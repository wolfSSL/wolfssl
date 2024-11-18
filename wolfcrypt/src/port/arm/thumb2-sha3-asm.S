/* thumb2-sha3-asm
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
 *   ruby ./sha3/sha3.rb thumb2 ../wolfssl/wolfcrypt/src/port/arm/thumb2-sha3-asm.S
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
#ifdef WOLFSSL_SHA3
	.text
	.type	L_sha3_thumb2_rt, %object
	.size	L_sha3_thumb2_rt, 192
	.align	8
L_sha3_thumb2_rt:
	.word	0x1
	.word	0x0
	.word	0x8082
	.word	0x0
	.word	0x808a
	.word	0x80000000
	.word	0x80008000
	.word	0x80000000
	.word	0x808b
	.word	0x0
	.word	0x80000001
	.word	0x0
	.word	0x80008081
	.word	0x80000000
	.word	0x8009
	.word	0x80000000
	.word	0x8a
	.word	0x0
	.word	0x88
	.word	0x0
	.word	0x80008009
	.word	0x0
	.word	0x8000000a
	.word	0x0
	.word	0x8000808b
	.word	0x0
	.word	0x8b
	.word	0x80000000
	.word	0x8089
	.word	0x80000000
	.word	0x8003
	.word	0x80000000
	.word	0x8002
	.word	0x80000000
	.word	0x80
	.word	0x80000000
	.word	0x800a
	.word	0x0
	.word	0x8000000a
	.word	0x80000000
	.word	0x80008081
	.word	0x80000000
	.word	0x8080
	.word	0x80000000
	.word	0x80000001
	.word	0x0
	.word	0x80008008
	.word	0x80000000
	.text
	.align	4
	.globl	BlockSha3
	.type	BlockSha3, %function
BlockSha3:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	SUB	sp, sp, #0xcc
	ADR	r1, L_sha3_thumb2_rt
	MOV	r2, #0xc
L_sha3_thumb2_begin:
	STR	r2, [sp, #200]
	/* Round even */
	/* Calc b[4] */
	LDRD	r4, r5, [r0, #32]
	LDRD	r6, r7, [r0, #72]
	LDRD	r8, r9, [r0, #112]
	LDRD	r10, r11, [r0, #152]
	LDR	r12, [r0, #192]
	LDR	lr, [r0, #196]
	EOR	r2, r4, r6
	EOR	r3, r5, r7
	EOR	r2, r2, r8
	EOR	r3, r3, r9
	EOR	r2, r2, r10
	EOR	r3, r3, r11
	EOR	r2, r2, r12
	EOR	r3, r3, lr
	STRD	r2, r3, [sp, #32]
	/* Calc b[1] */
	LDRD	r4, r5, [r0, #8]
	LDRD	r6, r7, [r0, #48]
	LDRD	r8, r9, [r0, #88]
	LDRD	r10, r11, [r0, #128]
	LDR	r12, [r0, #168]
	LDR	lr, [r0, #172]
	EOR	r4, r4, r6
	EOR	r5, r5, r7
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r4, r4, r10
	EOR	r5, r5, r11
	EOR	r4, r4, r12
	EOR	r5, r5, lr
	STRD	r4, r5, [sp, #8]
	/* Calc t[0] */
	EOR	r2, r2, r5, LSR #31
	EOR	r3, r3, r4, LSR #31
	EOR	r2, r2, r4, LSL #1
	EOR	r3, r3, r5, LSL #1
	/* Calc b[0] and XOR t[0] into s[x*5+0] */
	LDRD	r4, r5, [r0]
	LDRD	r6, r7, [r0, #40]
	LDRD	r8, r9, [r0, #80]
	LDRD	r10, r11, [r0, #120]
	EOR	r12, r4, r6
	EOR	lr, r5, r7
	EOR	r12, r12, r8
	EOR	lr, lr, r9
	EOR	r12, r12, r10
	EOR	lr, lr, r11
	EOR	r4, r4, r2
	EOR	r5, r5, r3
	EOR	r6, r6, r2
	EOR	r7, r7, r3
	EOR	r8, r8, r2
	EOR	r9, r9, r3
	EOR	r10, r10, r2
	EOR	r11, r11, r3
	STRD	r4, r5, [r0]
	STRD	r6, r7, [r0, #40]
	STRD	r8, r9, [r0, #80]
	STRD	r10, r11, [r0, #120]
	LDRD	r10, r11, [r0, #160]
	EOR	r12, r12, r10
	EOR	lr, lr, r11
	EOR	r10, r10, r2
	EOR	r11, r11, r3
	STRD	r10, r11, [r0, #160]
	STR	r12, [sp]
	STR	lr, [sp, #4]
	/* Calc b[3] */
	LDRD	r4, r5, [r0, #24]
	LDRD	r6, r7, [r0, #64]
	LDRD	r8, r9, [r0, #104]
	LDRD	r10, r11, [r0, #144]
	LDR	r12, [r0, #184]
	LDR	lr, [r0, #188]
	EOR	r4, r4, r6
	EOR	r5, r5, r7
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r4, r4, r10
	EOR	r5, r5, r11
	EOR	r4, r4, r12
	EOR	r5, r5, lr
	STRD	r4, r5, [sp, #24]
	/* Calc t[2] */
	LDRD	r2, r3, [sp, #8]
	EOR	r2, r2, r5, LSR #31
	EOR	r3, r3, r4, LSR #31
	EOR	r2, r2, r4, LSL #1
	EOR	r3, r3, r5, LSL #1
	/* Calc b[2] and XOR t[2] into s[x*5+2] */
	LDRD	r4, r5, [r0, #16]
	LDRD	r6, r7, [r0, #56]
	LDRD	r8, r9, [r0, #96]
	LDRD	r10, r11, [r0, #136]
	EOR	r12, r4, r6
	EOR	lr, r5, r7
	EOR	r12, r12, r8
	EOR	lr, lr, r9
	EOR	r12, r12, r10
	EOR	lr, lr, r11
	EOR	r4, r4, r2
	EOR	r5, r5, r3
	EOR	r6, r6, r2
	EOR	r7, r7, r3
	EOR	r8, r8, r2
	EOR	r9, r9, r3
	EOR	r10, r10, r2
	EOR	r11, r11, r3
	STRD	r4, r5, [r0, #16]
	STRD	r6, r7, [r0, #56]
	STRD	r8, r9, [r0, #96]
	STRD	r10, r11, [r0, #136]
	LDRD	r10, r11, [r0, #176]
	EOR	r12, r12, r10
	EOR	lr, lr, r11
	EOR	r10, r10, r2
	EOR	r11, r11, r3
	STRD	r10, r11, [r0, #176]
	STR	r12, [sp, #16]
	STR	lr, [sp, #20]
	/* Calc t[1] */
	LDRD	r2, r3, [sp]
	EOR	r2, r2, lr, LSR #31
	EOR	r3, r3, r12, LSR #31
	EOR	r2, r2, r12, LSL #1
	EOR	r3, r3, lr, LSL #1
	/* XOR t[1] into s[x*5+1] */
	LDRD	r4, r5, [r0, #8]
	LDRD	r6, r7, [r0, #48]
	LDRD	r8, r9, [r0, #88]
	LDRD	r10, r11, [r0, #128]
	LDR	r12, [r0, #168]
	LDR	lr, [r0, #172]
	EOR	r4, r4, r2
	EOR	r5, r5, r3
	EOR	r6, r6, r2
	EOR	r7, r7, r3
	EOR	r8, r8, r2
	EOR	r9, r9, r3
	EOR	r10, r10, r2
	EOR	r11, r11, r3
	EOR	r12, r12, r2
	EOR	lr, lr, r3
	STRD	r4, r5, [r0, #8]
	STRD	r6, r7, [r0, #48]
	STRD	r8, r9, [r0, #88]
	STRD	r10, r11, [r0, #128]
	STR	r12, [r0, #168]
	STR	lr, [r0, #172]
	/* Calc t[3] */
	LDRD	r2, r3, [sp, #16]
	LDRD	r4, r5, [sp, #32]
	EOR	r2, r2, r5, LSR #31
	EOR	r3, r3, r4, LSR #31
	EOR	r2, r2, r4, LSL #1
	EOR	r3, r3, r5, LSL #1
	/* XOR t[3] into s[x*5+3] */
	LDRD	r4, r5, [r0, #24]
	LDRD	r6, r7, [r0, #64]
	LDRD	r8, r9, [r0, #104]
	LDRD	r10, r11, [r0, #144]
	LDR	r12, [r0, #184]
	LDR	lr, [r0, #188]
	EOR	r4, r4, r2
	EOR	r5, r5, r3
	EOR	r6, r6, r2
	EOR	r7, r7, r3
	EOR	r8, r8, r2
	EOR	r9, r9, r3
	EOR	r10, r10, r2
	EOR	r11, r11, r3
	EOR	r12, r12, r2
	EOR	lr, lr, r3
	STRD	r4, r5, [r0, #24]
	STRD	r6, r7, [r0, #64]
	STRD	r8, r9, [r0, #104]
	STRD	r10, r11, [r0, #144]
	STR	r12, [r0, #184]
	STR	lr, [r0, #188]
	/* Calc t[4] */
	LDRD	r2, r3, [sp, #24]
	LDRD	r4, r5, [sp]
	EOR	r2, r2, r5, LSR #31
	EOR	r3, r3, r4, LSR #31
	EOR	r2, r2, r4, LSL #1
	EOR	r3, r3, r5, LSL #1
	/* XOR t[4] into s[x*5+4] */
	LDRD	r4, r5, [r0, #32]
	LDRD	r6, r7, [r0, #72]
	LDRD	r8, r9, [r0, #112]
	LDRD	r10, r11, [r0, #152]
	LDR	r12, [r0, #192]
	LDR	lr, [r0, #196]
	EOR	r4, r4, r2
	EOR	r5, r5, r3
	EOR	r6, r6, r2
	EOR	r7, r7, r3
	EOR	r8, r8, r2
	EOR	r9, r9, r3
	EOR	r10, r10, r2
	EOR	r11, r11, r3
	EOR	r12, r12, r2
	EOR	lr, lr, r3
	STRD	r4, r5, [r0, #32]
	STRD	r6, r7, [r0, #72]
	STRD	r8, r9, [r0, #112]
	STRD	r10, r11, [r0, #152]
	STR	r12, [r0, #192]
	STR	lr, [r0, #196]
	/* Row Mix */
	/* Row 0 */
	LDRD	r2, r3, [r0]
	LDRD	r4, r5, [r0, #48]
	LDRD	r6, r7, [r0, #96]
	LDRD	r8, r9, [r0, #144]
	LDRD	r10, r11, [r0, #192]
	/* s[1] <<< 44 */
	MOV	lr, r4
	LSR	r12, r5, #20
	LSR	r4, r4, #20
	ORR	r4, r4, r5, LSL #12
	ORR	r5, r12, lr, LSL #12
	/* s[2] <<< 43 */
	MOV	lr, r6
	LSR	r12, r7, #21
	LSR	r6, r6, #21
	ORR	r6, r6, r7, LSL #11
	ORR	r7, r12, lr, LSL #11
	/* s[3] <<< 21 */
	LSR	r12, r9, #11
	LSR	lr, r8, #11
	ORR	r8, r12, r8, LSL #21
	ORR	r9, lr, r9, LSL #21
	/* s[4] <<< 14 */
	LSR	r12, r11, #18
	LSR	lr, r10, #18
	ORR	r10, r12, r10, LSL #14
	ORR	r11, lr, r11, LSL #14
	BIC	r12, r8, r6
	BIC	lr, r9, r7
	EOR	r12, r12, r4
	EOR	lr, lr, r5
	STR	r12, [sp, #8]
	STR	lr, [sp, #12]
	BIC	r12, r10, r8
	BIC	lr, r11, r9
	EOR	r12, r12, r6
	EOR	lr, lr, r7
	STR	r12, [sp, #16]
	STR	lr, [sp, #20]
	BIC	r12, r2, r10
	BIC	lr, r3, r11
	EOR	r12, r12, r8
	EOR	lr, lr, r9
	STR	r12, [sp, #24]
	STR	lr, [sp, #28]
	BIC	r12, r4, r2
	BIC	lr, r5, r3
	EOR	r12, r12, r10
	EOR	lr, lr, r11
	STR	r12, [sp, #32]
	STR	lr, [sp, #36]
	/* Get constant */
	LDRD	r10, r11, [r1]
	ADD	r1, r1, #0x8
	BIC	r12, r6, r4
	BIC	lr, r7, r5
	EOR	r12, r12, r2
	EOR	lr, lr, r3
	/* XOR in constant */
	EOR	r12, r12, r10
	EOR	lr, lr, r11
	STR	r12, [sp]
	STR	lr, [sp, #4]
	/* Row 1 */
	LDRD	r2, r3, [r0, #24]
	LDRD	r4, r5, [r0, #72]
	LDRD	r6, r7, [r0, #80]
	LDRD	r8, r9, [r0, #128]
	LDRD	r10, r11, [r0, #176]
	/* s[0] <<< 28 */
	LSR	r12, r3, #4
	LSR	lr, r2, #4
	ORR	r2, r12, r2, LSL #28
	ORR	r3, lr, r3, LSL #28
	/* s[1] <<< 20 */
	LSR	r12, r5, #12
	LSR	lr, r4, #12
	ORR	r4, r12, r4, LSL #20
	ORR	r5, lr, r5, LSL #20
	/* s[2] <<< 3 */
	LSR	r12, r7, #29
	LSR	lr, r6, #29
	ORR	r6, r12, r6, LSL #3
	ORR	r7, lr, r7, LSL #3
	/* s[3] <<< 45 */
	MOV	lr, r8
	LSR	r12, r9, #19
	LSR	r8, r8, #19
	ORR	r8, r8, r9, LSL #13
	ORR	r9, r12, lr, LSL #13
	/* s[4] <<< 61 */
	MOV	lr, r10
	LSR	r12, r11, #3
	LSR	r10, r10, #3
	ORR	r10, r10, r11, LSL #29
	ORR	r11, r12, lr, LSL #29
	BIC	r12, r8, r6
	BIC	lr, r9, r7
	EOR	r12, r12, r4
	EOR	lr, lr, r5
	STR	r12, [sp, #48]
	STR	lr, [sp, #52]
	BIC	r12, r10, r8
	BIC	lr, r11, r9
	EOR	r12, r12, r6
	EOR	lr, lr, r7
	STR	r12, [sp, #56]
	STR	lr, [sp, #60]
	BIC	r12, r2, r10
	BIC	lr, r3, r11
	EOR	r12, r12, r8
	EOR	lr, lr, r9
	STR	r12, [sp, #64]
	STR	lr, [sp, #68]
	BIC	r12, r4, r2
	BIC	lr, r5, r3
	EOR	r12, r12, r10
	EOR	lr, lr, r11
	STR	r12, [sp, #72]
	STR	lr, [sp, #76]
	BIC	r12, r6, r4
	BIC	lr, r7, r5
	EOR	r12, r12, r2
	EOR	lr, lr, r3
	STR	r12, [sp, #40]
	STR	lr, [sp, #44]
	/* Row 2 */
	LDRD	r2, r3, [r0, #8]
	LDRD	r4, r5, [r0, #56]
	LDRD	r6, r7, [r0, #104]
	LDRD	r8, r9, [r0, #152]
	LDRD	r10, r11, [r0, #160]
	/* s[0] <<< 1 */
	LSR	r12, r3, #31
	LSR	lr, r2, #31
	ORR	r2, r12, r2, LSL #1
	ORR	r3, lr, r3, LSL #1
	/* s[1] <<< 6 */
	LSR	r12, r5, #26
	LSR	lr, r4, #26
	ORR	r4, r12, r4, LSL #6
	ORR	r5, lr, r5, LSL #6
	/* s[2] <<< 25 */
	LSR	r12, r7, #7
	LSR	lr, r6, #7
	ORR	r6, r12, r6, LSL #25
	ORR	r7, lr, r7, LSL #25
	/* s[3] <<< 8 */
	LSR	r12, r9, #24
	LSR	lr, r8, #24
	ORR	r8, r12, r8, LSL #8
	ORR	r9, lr, r9, LSL #8
	/* s[4] <<< 18 */
	LSR	r12, r11, #14
	LSR	lr, r10, #14
	ORR	r10, r12, r10, LSL #18
	ORR	r11, lr, r11, LSL #18
	BIC	r12, r8, r6
	BIC	lr, r9, r7
	EOR	r12, r12, r4
	EOR	lr, lr, r5
	STR	r12, [sp, #88]
	STR	lr, [sp, #92]
	BIC	r12, r10, r8
	BIC	lr, r11, r9
	EOR	r12, r12, r6
	EOR	lr, lr, r7
	STR	r12, [sp, #96]
	STR	lr, [sp, #100]
	BIC	r12, r2, r10
	BIC	lr, r3, r11
	EOR	r12, r12, r8
	EOR	lr, lr, r9
	STR	r12, [sp, #104]
	STR	lr, [sp, #108]
	BIC	r12, r4, r2
	BIC	lr, r5, r3
	EOR	r12, r12, r10
	EOR	lr, lr, r11
	STR	r12, [sp, #112]
	STR	lr, [sp, #116]
	BIC	r12, r6, r4
	BIC	lr, r7, r5
	EOR	r12, r12, r2
	EOR	lr, lr, r3
	STR	r12, [sp, #80]
	STR	lr, [sp, #84]
	/* Row 3 */
	LDRD	r2, r3, [r0, #32]
	LDRD	r4, r5, [r0, #40]
	LDRD	r6, r7, [r0, #88]
	LDRD	r8, r9, [r0, #136]
	LDRD	r10, r11, [r0, #184]
	/* s[0] <<< 27 */
	LSR	r12, r3, #5
	LSR	lr, r2, #5
	ORR	r2, r12, r2, LSL #27
	ORR	r3, lr, r3, LSL #27
	/* s[1] <<< 36 */
	MOV	lr, r4
	LSR	r12, r5, #28
	LSR	r4, r4, #28
	ORR	r4, r4, r5, LSL #4
	ORR	r5, r12, lr, LSL #4
	/* s[2] <<< 10 */
	LSR	r12, r7, #22
	LSR	lr, r6, #22
	ORR	r6, r12, r6, LSL #10
	ORR	r7, lr, r7, LSL #10
	/* s[3] <<< 15 */
	LSR	r12, r9, #17
	LSR	lr, r8, #17
	ORR	r8, r12, r8, LSL #15
	ORR	r9, lr, r9, LSL #15
	/* s[4] <<< 56 */
	MOV	lr, r10
	LSR	r12, r11, #8
	LSR	r10, r10, #8
	ORR	r10, r10, r11, LSL #24
	ORR	r11, r12, lr, LSL #24
	BIC	r12, r8, r6
	BIC	lr, r9, r7
	EOR	r12, r12, r4
	EOR	lr, lr, r5
	STR	r12, [sp, #128]
	STR	lr, [sp, #132]
	BIC	r12, r10, r8
	BIC	lr, r11, r9
	EOR	r12, r12, r6
	EOR	lr, lr, r7
	STR	r12, [sp, #136]
	STR	lr, [sp, #140]
	BIC	r12, r2, r10
	BIC	lr, r3, r11
	EOR	r12, r12, r8
	EOR	lr, lr, r9
	STR	r12, [sp, #144]
	STR	lr, [sp, #148]
	BIC	r12, r4, r2
	BIC	lr, r5, r3
	EOR	r12, r12, r10
	EOR	lr, lr, r11
	STR	r12, [sp, #152]
	STR	lr, [sp, #156]
	BIC	r12, r6, r4
	BIC	lr, r7, r5
	EOR	r12, r12, r2
	EOR	lr, lr, r3
	STR	r12, [sp, #120]
	STR	lr, [sp, #124]
	/* Row 4 */
	LDRD	r2, r3, [r0, #16]
	LDRD	r4, r5, [r0, #64]
	LDRD	r6, r7, [r0, #112]
	LDRD	r8, r9, [r0, #120]
	LDRD	r10, r11, [r0, #168]
	/* s[0] <<< 62 */
	MOV	lr, r2
	LSR	r12, r3, #2
	LSR	r2, r2, #2
	ORR	r2, r2, r3, LSL #30
	ORR	r3, r12, lr, LSL #30
	/* s[1] <<< 55 */
	MOV	lr, r4
	LSR	r12, r5, #9
	LSR	r4, r4, #9
	ORR	r4, r4, r5, LSL #23
	ORR	r5, r12, lr, LSL #23
	/* s[2] <<< 39 */
	MOV	lr, r6
	LSR	r12, r7, #25
	LSR	r6, r6, #25
	ORR	r6, r6, r7, LSL #7
	ORR	r7, r12, lr, LSL #7
	/* s[3] <<< 41 */
	MOV	lr, r8
	LSR	r12, r9, #23
	LSR	r8, r8, #23
	ORR	r8, r8, r9, LSL #9
	ORR	r9, r12, lr, LSL #9
	/* s[4] <<< 2 */
	LSR	r12, r11, #30
	LSR	lr, r10, #30
	ORR	r10, r12, r10, LSL #2
	ORR	r11, lr, r11, LSL #2
	BIC	r12, r8, r6
	BIC	lr, r9, r7
	EOR	r12, r12, r4
	EOR	lr, lr, r5
	STR	r12, [sp, #168]
	STR	lr, [sp, #172]
	BIC	r12, r10, r8
	BIC	lr, r11, r9
	EOR	r12, r12, r6
	EOR	lr, lr, r7
	STR	r12, [sp, #176]
	STR	lr, [sp, #180]
	BIC	r12, r2, r10
	BIC	lr, r3, r11
	EOR	r12, r12, r8
	EOR	lr, lr, r9
	STR	r12, [sp, #184]
	STR	lr, [sp, #188]
	BIC	r12, r4, r2
	BIC	lr, r5, r3
	EOR	r12, r12, r10
	EOR	lr, lr, r11
	STR	r12, [sp, #192]
	STR	lr, [sp, #196]
	BIC	r12, r6, r4
	BIC	lr, r7, r5
	EOR	r12, r12, r2
	EOR	lr, lr, r3
	STR	r12, [sp, #160]
	STR	lr, [sp, #164]
	/* Round odd */
	/* Calc b[4] */
	LDRD	r4, r5, [sp, #32]
	LDRD	r6, r7, [sp, #72]
	LDRD	r8, r9, [sp, #112]
	LDRD	r10, r11, [sp, #152]
	LDR	r12, [sp, #192]
	LDR	lr, [sp, #196]
	EOR	r2, r4, r6
	EOR	r3, r5, r7
	EOR	r2, r2, r8
	EOR	r3, r3, r9
	EOR	r2, r2, r10
	EOR	r3, r3, r11
	EOR	r2, r2, r12
	EOR	r3, r3, lr
	STRD	r2, r3, [r0, #32]
	/* Calc b[1] */
	LDRD	r4, r5, [sp, #8]
	LDRD	r6, r7, [sp, #48]
	LDRD	r8, r9, [sp, #88]
	LDRD	r10, r11, [sp, #128]
	LDR	r12, [sp, #168]
	LDR	lr, [sp, #172]
	EOR	r4, r4, r6
	EOR	r5, r5, r7
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r4, r4, r10
	EOR	r5, r5, r11
	EOR	r4, r4, r12
	EOR	r5, r5, lr
	STRD	r4, r5, [r0, #8]
	/* Calc t[0] */
	EOR	r2, r2, r5, LSR #31
	EOR	r3, r3, r4, LSR #31
	EOR	r2, r2, r4, LSL #1
	EOR	r3, r3, r5, LSL #1
	/* Calc b[0] and XOR t[0] into s[x*5+0] */
	LDRD	r4, r5, [sp]
	LDRD	r6, r7, [sp, #40]
	LDRD	r8, r9, [sp, #80]
	LDRD	r10, r11, [sp, #120]
	EOR	r12, r4, r6
	EOR	lr, r5, r7
	EOR	r12, r12, r8
	EOR	lr, lr, r9
	EOR	r12, r12, r10
	EOR	lr, lr, r11
	EOR	r4, r4, r2
	EOR	r5, r5, r3
	EOR	r6, r6, r2
	EOR	r7, r7, r3
	EOR	r8, r8, r2
	EOR	r9, r9, r3
	EOR	r10, r10, r2
	EOR	r11, r11, r3
	STRD	r4, r5, [sp]
	STRD	r6, r7, [sp, #40]
	STRD	r8, r9, [sp, #80]
	STRD	r10, r11, [sp, #120]
	LDRD	r10, r11, [sp, #160]
	EOR	r12, r12, r10
	EOR	lr, lr, r11
	EOR	r10, r10, r2
	EOR	r11, r11, r3
	STRD	r10, r11, [sp, #160]
	STR	r12, [r0]
	STR	lr, [r0, #4]
	/* Calc b[3] */
	LDRD	r4, r5, [sp, #24]
	LDRD	r6, r7, [sp, #64]
	LDRD	r8, r9, [sp, #104]
	LDRD	r10, r11, [sp, #144]
	LDR	r12, [sp, #184]
	LDR	lr, [sp, #188]
	EOR	r4, r4, r6
	EOR	r5, r5, r7
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r4, r4, r10
	EOR	r5, r5, r11
	EOR	r4, r4, r12
	EOR	r5, r5, lr
	STRD	r4, r5, [r0, #24]
	/* Calc t[2] */
	LDRD	r2, r3, [r0, #8]
	EOR	r2, r2, r5, LSR #31
	EOR	r3, r3, r4, LSR #31
	EOR	r2, r2, r4, LSL #1
	EOR	r3, r3, r5, LSL #1
	/* Calc b[2] and XOR t[2] into s[x*5+2] */
	LDRD	r4, r5, [sp, #16]
	LDRD	r6, r7, [sp, #56]
	LDRD	r8, r9, [sp, #96]
	LDRD	r10, r11, [sp, #136]
	EOR	r12, r4, r6
	EOR	lr, r5, r7
	EOR	r12, r12, r8
	EOR	lr, lr, r9
	EOR	r12, r12, r10
	EOR	lr, lr, r11
	EOR	r4, r4, r2
	EOR	r5, r5, r3
	EOR	r6, r6, r2
	EOR	r7, r7, r3
	EOR	r8, r8, r2
	EOR	r9, r9, r3
	EOR	r10, r10, r2
	EOR	r11, r11, r3
	STRD	r4, r5, [sp, #16]
	STRD	r6, r7, [sp, #56]
	STRD	r8, r9, [sp, #96]
	STRD	r10, r11, [sp, #136]
	LDRD	r10, r11, [sp, #176]
	EOR	r12, r12, r10
	EOR	lr, lr, r11
	EOR	r10, r10, r2
	EOR	r11, r11, r3
	STRD	r10, r11, [sp, #176]
	STR	r12, [r0, #16]
	STR	lr, [r0, #20]
	/* Calc t[1] */
	LDRD	r2, r3, [r0]
	EOR	r2, r2, lr, LSR #31
	EOR	r3, r3, r12, LSR #31
	EOR	r2, r2, r12, LSL #1
	EOR	r3, r3, lr, LSL #1
	/* XOR t[1] into s[x*5+1] */
	LDRD	r4, r5, [sp, #8]
	LDRD	r6, r7, [sp, #48]
	LDRD	r8, r9, [sp, #88]
	LDRD	r10, r11, [sp, #128]
	LDR	r12, [sp, #168]
	LDR	lr, [sp, #172]
	EOR	r4, r4, r2
	EOR	r5, r5, r3
	EOR	r6, r6, r2
	EOR	r7, r7, r3
	EOR	r8, r8, r2
	EOR	r9, r9, r3
	EOR	r10, r10, r2
	EOR	r11, r11, r3
	EOR	r12, r12, r2
	EOR	lr, lr, r3
	STRD	r4, r5, [sp, #8]
	STRD	r6, r7, [sp, #48]
	STRD	r8, r9, [sp, #88]
	STRD	r10, r11, [sp, #128]
	STR	r12, [sp, #168]
	STR	lr, [sp, #172]
	/* Calc t[3] */
	LDRD	r2, r3, [r0, #16]
	LDRD	r4, r5, [r0, #32]
	EOR	r2, r2, r5, LSR #31
	EOR	r3, r3, r4, LSR #31
	EOR	r2, r2, r4, LSL #1
	EOR	r3, r3, r5, LSL #1
	/* XOR t[3] into s[x*5+3] */
	LDRD	r4, r5, [sp, #24]
	LDRD	r6, r7, [sp, #64]
	LDRD	r8, r9, [sp, #104]
	LDRD	r10, r11, [sp, #144]
	LDR	r12, [sp, #184]
	LDR	lr, [sp, #188]
	EOR	r4, r4, r2
	EOR	r5, r5, r3
	EOR	r6, r6, r2
	EOR	r7, r7, r3
	EOR	r8, r8, r2
	EOR	r9, r9, r3
	EOR	r10, r10, r2
	EOR	r11, r11, r3
	EOR	r12, r12, r2
	EOR	lr, lr, r3
	STRD	r4, r5, [sp, #24]
	STRD	r6, r7, [sp, #64]
	STRD	r8, r9, [sp, #104]
	STRD	r10, r11, [sp, #144]
	STR	r12, [sp, #184]
	STR	lr, [sp, #188]
	/* Calc t[4] */
	LDRD	r2, r3, [r0, #24]
	LDRD	r4, r5, [r0]
	EOR	r2, r2, r5, LSR #31
	EOR	r3, r3, r4, LSR #31
	EOR	r2, r2, r4, LSL #1
	EOR	r3, r3, r5, LSL #1
	/* XOR t[4] into s[x*5+4] */
	LDRD	r4, r5, [sp, #32]
	LDRD	r6, r7, [sp, #72]
	LDRD	r8, r9, [sp, #112]
	LDRD	r10, r11, [sp, #152]
	LDR	r12, [sp, #192]
	LDR	lr, [sp, #196]
	EOR	r4, r4, r2
	EOR	r5, r5, r3
	EOR	r6, r6, r2
	EOR	r7, r7, r3
	EOR	r8, r8, r2
	EOR	r9, r9, r3
	EOR	r10, r10, r2
	EOR	r11, r11, r3
	EOR	r12, r12, r2
	EOR	lr, lr, r3
	STRD	r4, r5, [sp, #32]
	STRD	r6, r7, [sp, #72]
	STRD	r8, r9, [sp, #112]
	STRD	r10, r11, [sp, #152]
	STR	r12, [sp, #192]
	STR	lr, [sp, #196]
	/* Row Mix */
	/* Row 0 */
	LDRD	r2, r3, [sp]
	LDRD	r4, r5, [sp, #48]
	LDRD	r6, r7, [sp, #96]
	LDRD	r8, r9, [sp, #144]
	LDRD	r10, r11, [sp, #192]
	/* s[1] <<< 44 */
	MOV	lr, r4
	LSR	r12, r5, #20
	LSR	r4, r4, #20
	ORR	r4, r4, r5, LSL #12
	ORR	r5, r12, lr, LSL #12
	/* s[2] <<< 43 */
	MOV	lr, r6
	LSR	r12, r7, #21
	LSR	r6, r6, #21
	ORR	r6, r6, r7, LSL #11
	ORR	r7, r12, lr, LSL #11
	/* s[3] <<< 21 */
	LSR	r12, r9, #11
	LSR	lr, r8, #11
	ORR	r8, r12, r8, LSL #21
	ORR	r9, lr, r9, LSL #21
	/* s[4] <<< 14 */
	LSR	r12, r11, #18
	LSR	lr, r10, #18
	ORR	r10, r12, r10, LSL #14
	ORR	r11, lr, r11, LSL #14
	BIC	r12, r8, r6
	BIC	lr, r9, r7
	EOR	r12, r12, r4
	EOR	lr, lr, r5
	STR	r12, [r0, #8]
	STR	lr, [r0, #12]
	BIC	r12, r10, r8
	BIC	lr, r11, r9
	EOR	r12, r12, r6
	EOR	lr, lr, r7
	STR	r12, [r0, #16]
	STR	lr, [r0, #20]
	BIC	r12, r2, r10
	BIC	lr, r3, r11
	EOR	r12, r12, r8
	EOR	lr, lr, r9
	STR	r12, [r0, #24]
	STR	lr, [r0, #28]
	BIC	r12, r4, r2
	BIC	lr, r5, r3
	EOR	r12, r12, r10
	EOR	lr, lr, r11
	STR	r12, [r0, #32]
	STR	lr, [r0, #36]
	/* Get constant */
	LDRD	r10, r11, [r1]
	ADD	r1, r1, #0x8
	BIC	r12, r6, r4
	BIC	lr, r7, r5
	EOR	r12, r12, r2
	EOR	lr, lr, r3
	/* XOR in constant */
	EOR	r12, r12, r10
	EOR	lr, lr, r11
	STR	r12, [r0]
	STR	lr, [r0, #4]
	/* Row 1 */
	LDRD	r2, r3, [sp, #24]
	LDRD	r4, r5, [sp, #72]
	LDRD	r6, r7, [sp, #80]
	LDRD	r8, r9, [sp, #128]
	LDRD	r10, r11, [sp, #176]
	/* s[0] <<< 28 */
	LSR	r12, r3, #4
	LSR	lr, r2, #4
	ORR	r2, r12, r2, LSL #28
	ORR	r3, lr, r3, LSL #28
	/* s[1] <<< 20 */
	LSR	r12, r5, #12
	LSR	lr, r4, #12
	ORR	r4, r12, r4, LSL #20
	ORR	r5, lr, r5, LSL #20
	/* s[2] <<< 3 */
	LSR	r12, r7, #29
	LSR	lr, r6, #29
	ORR	r6, r12, r6, LSL #3
	ORR	r7, lr, r7, LSL #3
	/* s[3] <<< 45 */
	MOV	lr, r8
	LSR	r12, r9, #19
	LSR	r8, r8, #19
	ORR	r8, r8, r9, LSL #13
	ORR	r9, r12, lr, LSL #13
	/* s[4] <<< 61 */
	MOV	lr, r10
	LSR	r12, r11, #3
	LSR	r10, r10, #3
	ORR	r10, r10, r11, LSL #29
	ORR	r11, r12, lr, LSL #29
	BIC	r12, r8, r6
	BIC	lr, r9, r7
	EOR	r12, r12, r4
	EOR	lr, lr, r5
	STR	r12, [r0, #48]
	STR	lr, [r0, #52]
	BIC	r12, r10, r8
	BIC	lr, r11, r9
	EOR	r12, r12, r6
	EOR	lr, lr, r7
	STR	r12, [r0, #56]
	STR	lr, [r0, #60]
	BIC	r12, r2, r10
	BIC	lr, r3, r11
	EOR	r12, r12, r8
	EOR	lr, lr, r9
	STR	r12, [r0, #64]
	STR	lr, [r0, #68]
	BIC	r12, r4, r2
	BIC	lr, r5, r3
	EOR	r12, r12, r10
	EOR	lr, lr, r11
	STR	r12, [r0, #72]
	STR	lr, [r0, #76]
	BIC	r12, r6, r4
	BIC	lr, r7, r5
	EOR	r12, r12, r2
	EOR	lr, lr, r3
	STR	r12, [r0, #40]
	STR	lr, [r0, #44]
	/* Row 2 */
	LDRD	r2, r3, [sp, #8]
	LDRD	r4, r5, [sp, #56]
	LDRD	r6, r7, [sp, #104]
	LDRD	r8, r9, [sp, #152]
	LDRD	r10, r11, [sp, #160]
	/* s[0] <<< 1 */
	LSR	r12, r3, #31
	LSR	lr, r2, #31
	ORR	r2, r12, r2, LSL #1
	ORR	r3, lr, r3, LSL #1
	/* s[1] <<< 6 */
	LSR	r12, r5, #26
	LSR	lr, r4, #26
	ORR	r4, r12, r4, LSL #6
	ORR	r5, lr, r5, LSL #6
	/* s[2] <<< 25 */
	LSR	r12, r7, #7
	LSR	lr, r6, #7
	ORR	r6, r12, r6, LSL #25
	ORR	r7, lr, r7, LSL #25
	/* s[3] <<< 8 */
	LSR	r12, r9, #24
	LSR	lr, r8, #24
	ORR	r8, r12, r8, LSL #8
	ORR	r9, lr, r9, LSL #8
	/* s[4] <<< 18 */
	LSR	r12, r11, #14
	LSR	lr, r10, #14
	ORR	r10, r12, r10, LSL #18
	ORR	r11, lr, r11, LSL #18
	BIC	r12, r8, r6
	BIC	lr, r9, r7
	EOR	r12, r12, r4
	EOR	lr, lr, r5
	STR	r12, [r0, #88]
	STR	lr, [r0, #92]
	BIC	r12, r10, r8
	BIC	lr, r11, r9
	EOR	r12, r12, r6
	EOR	lr, lr, r7
	STR	r12, [r0, #96]
	STR	lr, [r0, #100]
	BIC	r12, r2, r10
	BIC	lr, r3, r11
	EOR	r12, r12, r8
	EOR	lr, lr, r9
	STR	r12, [r0, #104]
	STR	lr, [r0, #108]
	BIC	r12, r4, r2
	BIC	lr, r5, r3
	EOR	r12, r12, r10
	EOR	lr, lr, r11
	STR	r12, [r0, #112]
	STR	lr, [r0, #116]
	BIC	r12, r6, r4
	BIC	lr, r7, r5
	EOR	r12, r12, r2
	EOR	lr, lr, r3
	STR	r12, [r0, #80]
	STR	lr, [r0, #84]
	/* Row 3 */
	LDRD	r2, r3, [sp, #32]
	LDRD	r4, r5, [sp, #40]
	LDRD	r6, r7, [sp, #88]
	LDRD	r8, r9, [sp, #136]
	LDRD	r10, r11, [sp, #184]
	/* s[0] <<< 27 */
	LSR	r12, r3, #5
	LSR	lr, r2, #5
	ORR	r2, r12, r2, LSL #27
	ORR	r3, lr, r3, LSL #27
	/* s[1] <<< 36 */
	MOV	lr, r4
	LSR	r12, r5, #28
	LSR	r4, r4, #28
	ORR	r4, r4, r5, LSL #4
	ORR	r5, r12, lr, LSL #4
	/* s[2] <<< 10 */
	LSR	r12, r7, #22
	LSR	lr, r6, #22
	ORR	r6, r12, r6, LSL #10
	ORR	r7, lr, r7, LSL #10
	/* s[3] <<< 15 */
	LSR	r12, r9, #17
	LSR	lr, r8, #17
	ORR	r8, r12, r8, LSL #15
	ORR	r9, lr, r9, LSL #15
	/* s[4] <<< 56 */
	MOV	lr, r10
	LSR	r12, r11, #8
	LSR	r10, r10, #8
	ORR	r10, r10, r11, LSL #24
	ORR	r11, r12, lr, LSL #24
	BIC	r12, r8, r6
	BIC	lr, r9, r7
	EOR	r12, r12, r4
	EOR	lr, lr, r5
	STR	r12, [r0, #128]
	STR	lr, [r0, #132]
	BIC	r12, r10, r8
	BIC	lr, r11, r9
	EOR	r12, r12, r6
	EOR	lr, lr, r7
	STR	r12, [r0, #136]
	STR	lr, [r0, #140]
	BIC	r12, r2, r10
	BIC	lr, r3, r11
	EOR	r12, r12, r8
	EOR	lr, lr, r9
	STR	r12, [r0, #144]
	STR	lr, [r0, #148]
	BIC	r12, r4, r2
	BIC	lr, r5, r3
	EOR	r12, r12, r10
	EOR	lr, lr, r11
	STR	r12, [r0, #152]
	STR	lr, [r0, #156]
	BIC	r12, r6, r4
	BIC	lr, r7, r5
	EOR	r12, r12, r2
	EOR	lr, lr, r3
	STR	r12, [r0, #120]
	STR	lr, [r0, #124]
	/* Row 4 */
	LDRD	r2, r3, [sp, #16]
	LDRD	r4, r5, [sp, #64]
	LDRD	r6, r7, [sp, #112]
	LDRD	r8, r9, [sp, #120]
	LDRD	r10, r11, [sp, #168]
	/* s[0] <<< 62 */
	MOV	lr, r2
	LSR	r12, r3, #2
	LSR	r2, r2, #2
	ORR	r2, r2, r3, LSL #30
	ORR	r3, r12, lr, LSL #30
	/* s[1] <<< 55 */
	MOV	lr, r4
	LSR	r12, r5, #9
	LSR	r4, r4, #9
	ORR	r4, r4, r5, LSL #23
	ORR	r5, r12, lr, LSL #23
	/* s[2] <<< 39 */
	MOV	lr, r6
	LSR	r12, r7, #25
	LSR	r6, r6, #25
	ORR	r6, r6, r7, LSL #7
	ORR	r7, r12, lr, LSL #7
	/* s[3] <<< 41 */
	MOV	lr, r8
	LSR	r12, r9, #23
	LSR	r8, r8, #23
	ORR	r8, r8, r9, LSL #9
	ORR	r9, r12, lr, LSL #9
	/* s[4] <<< 2 */
	LSR	r12, r11, #30
	LSR	lr, r10, #30
	ORR	r10, r12, r10, LSL #2
	ORR	r11, lr, r11, LSL #2
	BIC	r12, r8, r6
	BIC	lr, r9, r7
	EOR	r12, r12, r4
	EOR	lr, lr, r5
	STR	r12, [r0, #168]
	STR	lr, [r0, #172]
	BIC	r12, r10, r8
	BIC	lr, r11, r9
	EOR	r12, r12, r6
	EOR	lr, lr, r7
	STR	r12, [r0, #176]
	STR	lr, [r0, #180]
	BIC	r12, r2, r10
	BIC	lr, r3, r11
	EOR	r12, r12, r8
	EOR	lr, lr, r9
	STR	r12, [r0, #184]
	STR	lr, [r0, #188]
	BIC	r12, r4, r2
	BIC	lr, r5, r3
	EOR	r12, r12, r10
	EOR	lr, lr, r11
	STR	r12, [r0, #192]
	STR	lr, [r0, #196]
	BIC	r12, r6, r4
	BIC	lr, r7, r5
	EOR	r12, r12, r2
	EOR	lr, lr, r3
	STR	r12, [r0, #160]
	STR	lr, [r0, #164]
	LDR	r2, [sp, #200]
	SUBS	r2, r2, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_sha3_thumb2_begin
#else
	BNE.W	L_sha3_thumb2_begin
#endif
	ADD	sp, sp, #0xcc
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 1505 */
	.size	BlockSha3,.-BlockSha3
#endif /* WOLFSSL_SHA3 */
#endif /* WOLFSSL_ARMASM_THUMB2 */
#endif /* WOLFSSL_ARMASM */

#if defined(__linux__) && defined(__ELF__)
.section        .note.GNU-stack,"",%progbits
#endif
#endif /* !WOLFSSL_ARMASM_INLINE */
