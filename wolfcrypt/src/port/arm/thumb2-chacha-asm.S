/* thumb2-chacha-asm
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
 *   ruby ./chacha/chacha.rb thumb2 ../wolfssl/wolfcrypt/src/port/arm/thumb2-chacha-asm.S
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
#ifdef HAVE_CHACHA
	.text
	.align	4
	.globl	wc_chacha_setiv
	.type	wc_chacha_setiv, %function
wc_chacha_setiv:
	PUSH	{r4, r5, r6, lr}
	ADD	r3, r0, #0x34
	LDR	r4, [r1]
	LDR	r5, [r1, #4]
	LDR	r6, [r1, #8]
	STR	r2, [r0, #48]
#ifdef BIG_ENDIAN_ORDER
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
#endif /* BIG_ENDIAN_ORDER */
	STM	r3, {r4, r5, r6}
	POP	{r4, r5, r6, pc}
	/* Cycle Count = 26 */
	.size	wc_chacha_setiv,.-wc_chacha_setiv
	.text
	.type	L_chacha_thumb2_constants, %object
	.size	L_chacha_thumb2_constants, 32
	.align	4
L_chacha_thumb2_constants:
	.word	0x61707865
	.word	0x3120646e
	.word	0x79622d36
	.word	0x6b206574
	.word	0x61707865
	.word	0x3320646e
	.word	0x79622d32
	.word	0x6b206574
	.text
	.align	4
	.globl	wc_chacha_setkey
	.type	wc_chacha_setkey, %function
wc_chacha_setkey:
	PUSH	{r4, r5, r6, r7, lr}
	ADR	r7, L_chacha_thumb2_constants
	SUBS	r2, r2, #0x10
	ADD	r7, r7, r2
	/* Start state with constants */
	LDM	r7, {r3, r4, r5, r6}
	STM	r0!, {r3, r4, r5, r6}
	/* Next is first 16 bytes of key. */
	LDR	r3, [r1]
	LDR	r4, [r1, #4]
	LDR	r5, [r1, #8]
	LDR	r6, [r1, #12]
#ifdef BIG_ENDIAN_ORDER
	REV	r3, r3
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
#endif /* BIG_ENDIAN_ORDER */
	STM	r0!, {r3, r4, r5, r6}
	/* Next 16 bytes of key. */
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BEQ	L_chacha_thumb2_setkey_same_keyb_ytes
#else
	BEQ.N	L_chacha_thumb2_setkey_same_keyb_ytes
#endif
	/* Update key pointer for next 16 bytes. */
	ADD	r1, r1, r2
	LDR	r3, [r1]
	LDR	r4, [r1, #4]
	LDR	r5, [r1, #8]
	LDR	r6, [r1, #12]
L_chacha_thumb2_setkey_same_keyb_ytes:
	STM	r0, {r3, r4, r5, r6}
	POP	{r4, r5, r6, r7, pc}
	/* Cycle Count = 60 */
	.size	wc_chacha_setkey,.-wc_chacha_setkey
	.text
	.align	4
	.globl	wc_chacha_crypt_bytes
	.type	wc_chacha_crypt_bytes, %function
wc_chacha_crypt_bytes:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	SUB	sp, sp, #0x34
	MOV	lr, r0
	STRD	r0, r1, [sp, #32]
	STRD	r2, r3, [sp, #40]
L_chacha_thumb2_crypt_block:
	/* Put x[12]..x[15] onto stack. */
	LDRD	r4, r5, [lr, #48]
	LDRD	r6, r7, [lr, #56]
	STRD	r4, r5, [sp, #16]
	STRD	r6, r7, [sp, #24]
	/* Load x[0]..x[12] into registers. */
	LDM	lr, {r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12}
	/* 10x 2 full rounds to perform. */
	MOV	lr, #0xa
	STR	lr, [sp, #48]
L_chacha_thumb2_crypt_loop:
	/* 0, 4,  8, 12 */
	/* 1, 5,  9, 13 */
	LDR	lr, [sp, #20]
	ADD	r0, r0, r4
	ADD	r1, r1, r5
	EOR	r12, r12, r0
	EOR	lr, lr, r1
	ROR	r12, r12, #16
	ROR	lr, lr, #16
	ADD	r8, r8, r12
	ADD	r9, r9, lr
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	ROR	r4, r4, #20
	ROR	r5, r5, #20
	ADD	r0, r0, r4
	ADD	r1, r1, r5
	EOR	r12, r12, r0
	EOR	lr, lr, r1
	ROR	r12, r12, #24
	ROR	lr, lr, #24
	ADD	r8, r8, r12
	ADD	r9, r9, lr
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	ROR	r4, r4, #25
	ROR	r5, r5, #25
	STR	r12, [sp, #16]
	STR	lr, [sp, #20]
	/* 2, 6, 10, 14 */
	/* 3, 7, 11, 15 */
	LDR	r12, [sp, #24]
	LDR	lr, [sp, #28]
	ADD	r2, r2, r6
	ADD	r3, r3, r7
	EOR	r12, r12, r2
	EOR	lr, lr, r3
	ROR	r12, r12, #16
	ROR	lr, lr, #16
	ADD	r10, r10, r12
	ADD	r11, r11, lr
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	ROR	r6, r6, #20
	ROR	r7, r7, #20
	ADD	r2, r2, r6
	ADD	r3, r3, r7
	EOR	r12, r12, r2
	EOR	lr, lr, r3
	ROR	r12, r12, #24
	ROR	lr, lr, #24
	ADD	r10, r10, r12
	ADD	r11, r11, lr
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	ROR	r6, r6, #25
	ROR	r7, r7, #25
	/* 3, 4,  9, 14 */
	/* 0, 5, 10, 15 */
	ADD	r3, r3, r4
	ADD	r0, r0, r5
	EOR	r12, r12, r3
	EOR	lr, lr, r0
	ROR	r12, r12, #16
	ROR	lr, lr, #16
	ADD	r9, r9, r12
	ADD	r10, r10, lr
	EOR	r4, r4, r9
	EOR	r5, r5, r10
	ROR	r4, r4, #20
	ROR	r5, r5, #20
	ADD	r3, r3, r4
	ADD	r0, r0, r5
	EOR	r12, r12, r3
	EOR	lr, lr, r0
	ROR	r12, r12, #24
	ROR	lr, lr, #24
	ADD	r9, r9, r12
	ADD	r10, r10, lr
	EOR	r4, r4, r9
	EOR	r5, r5, r10
	ROR	r4, r4, #25
	ROR	r5, r5, #25
	STR	r12, [sp, #24]
	STR	lr, [sp, #28]
	LDR	r12, [sp, #16]
	LDR	lr, [sp, #20]
	/* 1, 6, 11, 12 */
	/* 2, 7,  8, 13 */
	ADD	r1, r1, r6
	ADD	r2, r2, r7
	EOR	r12, r12, r1
	EOR	lr, lr, r2
	ROR	r12, r12, #16
	ROR	lr, lr, #16
	ADD	r11, r11, r12
	ADD	r8, r8, lr
	EOR	r6, r6, r11
	EOR	r7, r7, r8
	ROR	r6, r6, #20
	ROR	r7, r7, #20
	ADD	r1, r1, r6
	ADD	r2, r2, r7
	EOR	r12, r12, r1
	EOR	lr, lr, r2
	ROR	r12, r12, #24
	ROR	lr, lr, #24
	ADD	r11, r11, r12
	ADD	r8, r8, lr
	EOR	r6, r6, r11
	EOR	r7, r7, r8
	ROR	r6, r6, #25
	ROR	r7, r7, #25
	STR	lr, [sp, #20]
	/* Check if we have done enough rounds. */
	LDR	lr, [sp, #48]
	SUBS	lr, lr, #0x1
	STR	lr, [sp, #48]
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BGT	L_chacha_thumb2_crypt_loop
#else
	BGT.N	L_chacha_thumb2_crypt_loop
#endif
	STM	sp, {r8, r9, r10, r11, r12}
	LDR	lr, [sp, #32]
	MOV	r12, sp
	/* Add in original state */
	LDM	lr!, {r8, r9, r10, r11}
	ADD	r0, r0, r8
	ADD	r1, r1, r9
	ADD	r2, r2, r10
	ADD	r3, r3, r11
	LDM	lr!, {r8, r9, r10, r11}
	ADD	r4, r4, r8
	ADD	r5, r5, r9
	ADD	r6, r6, r10
	ADD	r7, r7, r11
	LDM	r12, {r8, r9}
	LDM	lr!, {r10, r11}
	ADD	r8, r8, r10
	ADD	r9, r9, r11
	STM	r12!, {r8, r9}
	LDM	r12, {r8, r9}
	LDM	lr!, {r10, r11}
	ADD	r8, r8, r10
	ADD	r9, r9, r11
	STM	r12!, {r8, r9}
	LDM	r12, {r8, r9}
	LDM	lr!, {r10, r11}
	ADD	r8, r8, r10
	ADD	r9, r9, r11
	ADD	r10, r10, #0x1
	STM	r12!, {r8, r9}
	STR	r10, [lr, #-8]
	LDM	r12, {r8, r9}
	LDM	lr, {r10, r11}
	ADD	r8, r8, r10
	ADD	r9, r9, r11
	STM	r12, {r8, r9}
	LDR	r12, [sp, #44]
	CMP	r12, #0x40
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BLT	L_chacha_thumb2_crypt_lt_block
#else
	BLT.N	L_chacha_thumb2_crypt_lt_block
#endif
	LDR	r12, [sp, #40]
	LDR	lr, [sp, #36]
	/* XOR state into 64 bytes. */
	LDR	r8, [r12]
	LDR	r9, [r12, #4]
	LDR	r10, [r12, #8]
	LDR	r11, [r12, #12]
	EOR	r0, r0, r8
	EOR	r1, r1, r9
	EOR	r2, r2, r10
	EOR	r3, r3, r11
	STR	r0, [lr]
	STR	r1, [lr, #4]
	STR	r2, [lr, #8]
	STR	r3, [lr, #12]
	LDR	r8, [r12, #16]
	LDR	r9, [r12, #20]
	LDR	r10, [r12, #24]
	LDR	r11, [r12, #28]
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	STR	r4, [lr, #16]
	STR	r5, [lr, #20]
	STR	r6, [lr, #24]
	STR	r7, [lr, #28]
	LDR	r4, [sp]
	LDR	r5, [sp, #4]
	LDR	r6, [sp, #8]
	LDR	r7, [sp, #12]
	LDR	r8, [r12, #32]
	LDR	r9, [r12, #36]
	LDR	r10, [r12, #40]
	LDR	r11, [r12, #44]
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	STR	r4, [lr, #32]
	STR	r5, [lr, #36]
	STR	r6, [lr, #40]
	STR	r7, [lr, #44]
	LDR	r4, [sp, #16]
	LDR	r5, [sp, #20]
	LDR	r6, [sp, #24]
	LDR	r7, [sp, #28]
	LDR	r8, [r12, #48]
	LDR	r9, [r12, #52]
	LDR	r10, [r12, #56]
	LDR	r11, [r12, #60]
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	STR	r4, [lr, #48]
	STR	r5, [lr, #52]
	STR	r6, [lr, #56]
	STR	r7, [lr, #60]
	LDR	r3, [sp, #44]
	ADD	r12, r12, #0x40
	ADD	lr, lr, #0x40
	STR	r12, [sp, #40]
	STR	lr, [sp, #36]
	SUBS	r3, r3, #0x40
	LDR	lr, [sp, #32]
	STR	r3, [sp, #44]
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_chacha_thumb2_crypt_block
#else
	BNE.N	L_chacha_thumb2_crypt_block
#endif
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	B	L_chacha_thumb2_crypt_done
#else
	B.N	L_chacha_thumb2_crypt_done
#endif
L_chacha_thumb2_crypt_lt_block:
	/* Store in over field of ChaCha. */
	LDR	lr, [sp, #32]
	ADD	r12, lr, #0x44
	STM	r12!, {r0, r1, r2, r3, r4, r5, r6, r7}
	LDM	sp, {r0, r1, r2, r3, r4, r5, r6, r7}
	STM	r12, {r0, r1, r2, r3, r4, r5, r6, r7}
	LDRD	r2, r3, [sp, #40]
	LDR	r1, [sp, #36]
	RSB	r12, r3, #0x40
	STR	r12, [lr, #64]
	ADD	lr, lr, #0x44
L_chacha_thumb2_crypt_16byte_loop:
	CMP	r3, #0x10
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BLT	L_chacha_thumb2_crypt_word_loop
#else
	BLT.N	L_chacha_thumb2_crypt_word_loop
#endif
	/* 16 bytes of state XORed into message. */
	LDM	lr!, {r4, r5, r6, r7}
	LDR	r8, [r2]
	LDR	r9, [r2, #4]
	LDR	r10, [r2, #8]
	LDR	r11, [r2, #12]
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	SUBS	r3, r3, #0x10
	STR	r8, [r1]
	STR	r9, [r1, #4]
	STR	r10, [r1, #8]
	STR	r11, [r1, #12]
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BEQ	L_chacha_thumb2_crypt_done
#else
	BEQ.N	L_chacha_thumb2_crypt_done
#endif
	ADD	r2, r2, #0x10
	ADD	r1, r1, #0x10
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	B	L_chacha_thumb2_crypt_16byte_loop
#else
	B.N	L_chacha_thumb2_crypt_16byte_loop
#endif
L_chacha_thumb2_crypt_word_loop:
	CMP	r3, #0x4
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BLT	L_chacha_thumb2_crypt_byte_start
#else
	BLT.N	L_chacha_thumb2_crypt_byte_start
#endif
	/* 4 bytes of state XORed into message. */
	LDR	r4, [lr]
	LDR	r8, [r2]
	EOR	r8, r8, r4
	SUBS	r3, r3, #0x4
	STR	r8, [r1]
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BEQ	L_chacha_thumb2_crypt_done
#else
	BEQ.N	L_chacha_thumb2_crypt_done
#endif
	ADD	lr, lr, #0x4
	ADD	r2, r2, #0x4
	ADD	r1, r1, #0x4
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	B	L_chacha_thumb2_crypt_word_loop
#else
	B.N	L_chacha_thumb2_crypt_word_loop
#endif
L_chacha_thumb2_crypt_byte_start:
	LDR	r4, [lr]
L_chacha_thumb2_crypt_byte_loop:
	LDRB	r8, [r2]
	EOR	r8, r8, r4
	SUBS	r3, r3, #0x1
	STRB	r8, [r1]
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BEQ	L_chacha_thumb2_crypt_done
#else
	BEQ.N	L_chacha_thumb2_crypt_done
#endif
	LSR	r4, r4, #8
	ADD	r2, r2, #0x1
	ADD	r1, r1, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	B	L_chacha_thumb2_crypt_byte_loop
#else
	B.N	L_chacha_thumb2_crypt_byte_loop
#endif
L_chacha_thumb2_crypt_done:
	ADD	sp, sp, #0x34
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 508 */
	.size	wc_chacha_crypt_bytes,.-wc_chacha_crypt_bytes
	.text
	.align	4
	.globl	wc_chacha_use_over
	.type	wc_chacha_use_over, %function
wc_chacha_use_over:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
L_chacha_thumb2_over_16byte_loop:
	CMP	r3, #0x10
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BLT	L_chacha_thumb2_over_word_loop
#else
	BLT.N	L_chacha_thumb2_over_word_loop
#endif
	/* 16 bytes of state XORed into message. */
	LDR	r4, [r0]
	LDR	r5, [r0, #4]
	LDR	r6, [r0, #8]
	LDR	r7, [r0, #12]
	LDR	r8, [r2]
	LDR	r9, [r2, #4]
	LDR	r10, [r2, #8]
	LDR	r11, [r2, #12]
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	SUBS	r3, r3, #0x10
	STR	r4, [r1]
	STR	r5, [r1, #4]
	STR	r6, [r1, #8]
	STR	r7, [r1, #12]
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BEQ	L_chacha_thumb2_over_done
#else
	BEQ.N	L_chacha_thumb2_over_done
#endif
	ADD	r0, r0, #0x10
	ADD	r2, r2, #0x10
	ADD	r1, r1, #0x10
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	B	L_chacha_thumb2_over_16byte_loop
#else
	B.N	L_chacha_thumb2_over_16byte_loop
#endif
L_chacha_thumb2_over_word_loop:
	CMP	r3, #0x4
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BLT	L_chacha_thumb2_over_byte_loop
#else
	BLT.N	L_chacha_thumb2_over_byte_loop
#endif
	/* 4 bytes of state XORed into message. */
	LDR	r4, [r0]
	LDR	r8, [r2]
	EOR	r4, r4, r8
	SUBS	r3, r3, #0x4
	STR	r4, [r1]
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BEQ	L_chacha_thumb2_over_done
#else
	BEQ.N	L_chacha_thumb2_over_done
#endif
	ADD	r0, r0, #0x4
	ADD	r2, r2, #0x4
	ADD	r1, r1, #0x4
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	B	L_chacha_thumb2_over_word_loop
#else
	B.N	L_chacha_thumb2_over_word_loop
#endif
L_chacha_thumb2_over_byte_loop:
	/* 4 bytes of state XORed into message. */
	LDRB	r4, [r0]
	LDRB	r8, [r2]
	EOR	r4, r4, r8
	SUBS	r3, r3, #0x1
	STRB	r4, [r1]
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BEQ	L_chacha_thumb2_over_done
#else
	BEQ.N	L_chacha_thumb2_over_done
#endif
	ADD	r0, r0, #0x1
	ADD	r2, r2, #0x1
	ADD	r1, r1, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	B	L_chacha_thumb2_over_byte_loop
#else
	B.N	L_chacha_thumb2_over_byte_loop
#endif
L_chacha_thumb2_over_done:
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 108 */
	.size	wc_chacha_use_over,.-wc_chacha_use_over
#endif /* HAVE_CHACHA */
#endif /* WOLFSSL_ARMASM_THUMB2 */
#endif /* WOLFSSL_ARMASM */

#if defined(__linux__) && defined(__ELF__)
.section        .note.GNU-stack,"",%progbits
#endif
#endif /* !WOLFSSL_ARMASM_INLINE */
