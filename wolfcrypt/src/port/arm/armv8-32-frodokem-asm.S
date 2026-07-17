/* armv8-32-frodokem-asm
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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
 *   ruby ./frodokem/frodokem.rb arm32 \
 *       ../wolfssl/wolfcrypt/src/port/arm/armv8-32-frodokem-asm.S
 */

#include <wolfssl/wolfcrypt/libwolfssl_sources_asm.h>

#ifdef WOLFSSL_ARMASM
#if !defined(__aarch64__) && !defined(WOLFSSL_ARMASM_THUMB2)
#ifndef WOLFSSL_ARMASM_INLINE
#ifdef WOLFSSL_HAVE_FRODOKEM
#ifndef WOLFSSL_ARMASM_NO_NEON
	.text
	.align	4
	.fpu	neon
	.globl	frodokem_add_neon
	.type	frodokem_add_neon, %function
frodokem_add_neon:
	vdup.16	q2, r2
	mov	r3, #8
L_frodokem_add_neon_blk:
	vld1.16	{d0-d1}, [r0]
	vld1.16	{d2-d3}, [r1]!
	vadd.i16	q0, q0, q1
	vand	q0, q0, q2
	vst1.16	{d0-d1}, [r0]!
	subs	r3, r3, #1
	bne	L_frodokem_add_neon_blk
	bx	lr
	.size	frodokem_add_neon,.-frodokem_add_neon
	.text
	.align	4
	.fpu	neon
	.globl	frodokem_sample_neon
	.type	frodokem_sample_neon, %function
frodokem_sample_neon:
	push	{r4, lr}
	vpush	{d8-d11}
L_frodokem_sample_neon_blk:
	vld1.16	{d0-d1}, [r0]
	vshr.u16	q1, q0, #1
	vmov.i16	q2, #1
	vand	q2, q2, q0
	vmov.i16	q3, #0
	mov	r12, r2
	mov	lr, r3
L_frodokem_sample_neon_cdf:
	ldrh	r4, [r12]
	add	r12, r12, #2
	vdup.16	q4, r4
	vsub.i16	q4, q4, q1
	vshr.u16	q4, q4, #15
	vadd.i16	q3, q3, q4
	subs	lr, lr, #1
	bne	L_frodokem_sample_neon_cdf
	vneg.s16	q5, q2
	veor	q3, q3, q5
	vadd.i16	q3, q3, q2
	vst1.16	{d6-d7}, [r0]!
	subs	r1, r1, #8
	bne	L_frodokem_sample_neon_blk
	vpop	{d8-d11}
	pop	{r4, pc}
	.size	frodokem_sample_neon,.-frodokem_sample_neon
	.text
	.align	4
	.fpu	neon
	.globl	frodokem_sa_accum_neon
	.type	frodokem_sa_accum_neon, %function
frodokem_sa_accum_neon:
	push	{r4, r5, r6, r7, r8, lr}
	ldr	r12, [sp, #24]
	lsl	lr, r12, #1
	add	r4, r1, r3, lsl #1
	mov	r7, #8
L_frodokem_sa_accum_neon_i:
	ldrh	r8, [r4]
	vdup.16	q0, r8
	add	r4, r4, lr
	mov	r5, r2
	lsr	r6, lr, #4
L_frodokem_sa_accum_neon_k:
	vld1.16	{d2-d3}, [r0]
	vld1.16	{d4-d5}, [r5]!
	vmla.i16	q1, q2, q0
	vst1.16	{d2-d3}, [r0]!
	subs	r6, r6, #1
	bne	L_frodokem_sa_accum_neon_k
	subs	r7, r7, #1
	bne	L_frodokem_sa_accum_neon_i
	pop	{r4, r5, r6, r7, r8, pc}
	.size	frodokem_sa_accum_neon,.-frodokem_sa_accum_neon
	.text
	.align	4
	.fpu	neon
	.globl	frodokem_as_accum_neon
	.type	frodokem_as_accum_neon, %function
frodokem_as_accum_neon:
	push	{r4, r5, r6, r7, r8, r9, lr}
	vpush	{d8-d15}
	ldr	r12, [sp, #92]
	lsl	lr, r12, #1
	add	r7, r0, r3, lsl #4
	mov	r6, r2
	mov	r4, r1
	veor	q0, q0, q0
	veor	q1, q1, q1
	veor	q2, q2, q2
	veor	q3, q3, q3
	veor	q4, q4, q4
	veor	q5, q5, q5
	veor	q6, q6, q6
	veor	q7, q7, q7
	lsr	r8, lr, #4
L_frodokem_as_accum_neon_k:
	vld1.16	{d16-d17}, [r6]!
	mov	r5, r4
	vld1.16	{d18-d19}, [r5]
	vmla.i16	q0, q8, q9
	add	r5, r5, lr
	vld1.16	{d18-d19}, [r5]
	vmla.i16	q1, q8, q9
	add	r5, r5, lr
	vld1.16	{d18-d19}, [r5]
	vmla.i16	q2, q8, q9
	add	r5, r5, lr
	vld1.16	{d18-d19}, [r5]
	vmla.i16	q3, q8, q9
	add	r5, r5, lr
	vld1.16	{d18-d19}, [r5]
	vmla.i16	q4, q8, q9
	add	r5, r5, lr
	vld1.16	{d18-d19}, [r5]
	vmla.i16	q5, q8, q9
	add	r5, r5, lr
	vld1.16	{d18-d19}, [r5]
	vmla.i16	q6, q8, q9
	add	r5, r5, lr
	vld1.16	{d18-d19}, [r5]
	vmla.i16	q7, q8, q9
	add	r5, r5, lr
	add	r4, r4, #16
	subs	r8, r8, #1
	bne	L_frodokem_as_accum_neon_k
	vadd.i16	d18, d0, d1
	vpadd.i16	d18, d18, d18
	vpadd.i16	d18, d18, d18
	vmov.u16	r9, d18[0]
	vmov.16	d20[0], r9
	vadd.i16	d18, d2, d3
	vpadd.i16	d18, d18, d18
	vpadd.i16	d18, d18, d18
	vmov.u16	r9, d18[0]
	vmov.16	d20[1], r9
	vadd.i16	d18, d4, d5
	vpadd.i16	d18, d18, d18
	vpadd.i16	d18, d18, d18
	vmov.u16	r9, d18[0]
	vmov.16	d20[2], r9
	vadd.i16	d18, d6, d7
	vpadd.i16	d18, d18, d18
	vpadd.i16	d18, d18, d18
	vmov.u16	r9, d18[0]
	vmov.16	d20[3], r9
	vadd.i16	d18, d8, d9
	vpadd.i16	d18, d18, d18
	vpadd.i16	d18, d18, d18
	vmov.u16	r9, d18[0]
	vmov.16	d21[0], r9
	vadd.i16	d18, d10, d11
	vpadd.i16	d18, d18, d18
	vpadd.i16	d18, d18, d18
	vmov.u16	r9, d18[0]
	vmov.16	d21[1], r9
	vadd.i16	d18, d12, d13
	vpadd.i16	d18, d18, d18
	vpadd.i16	d18, d18, d18
	vmov.u16	r9, d18[0]
	vmov.16	d21[2], r9
	vadd.i16	d18, d14, d15
	vpadd.i16	d18, d18, d18
	vpadd.i16	d18, d18, d18
	vmov.u16	r9, d18[0]
	vmov.16	d21[3], r9
	vld1.16	{d22-d23}, [r7]
	vadd.i16	q10, q10, q11
	vst1.16	{d20-d21}, [r7]
	vpop	{d8-d15}
	pop	{r4, r5, r6, r7, r8, r9, pc}
	.size	frodokem_as_accum_neon,.-frodokem_as_accum_neon
	.text
	.align	4
	.fpu	neon
	.globl	frodokem_mul_bs_neon
	.type	frodokem_mul_bs_neon, %function
frodokem_mul_bs_neon:
	push	{r4, r5, r6, r7, r8, r9, r10, lr}
	vpush	{d8-d15}
	ldr	lr, [sp, #96]
	lsl	r12, r3, #1
	vdup.16	q11, lr
	mov	r7, r0
	mov	r4, r1
	mov	r9, #8
L_frodokem_mul_bs_neon_r:
	mov	r5, r2
	veor	q0, q0, q0
	veor	q1, q1, q1
	veor	q2, q2, q2
	veor	q3, q3, q3
	veor	q4, q4, q4
	veor	q5, q5, q5
	veor	q6, q6, q6
	veor	q7, q7, q7
	lsr	r8, r12, #4
L_frodokem_mul_bs_neon_k:
	vld1.16	{d16-d17}, [r4]!
	mov	r6, r5
	vld1.16	{d18-d19}, [r6]
	vmla.i16	q0, q8, q9
	add	r6, r6, r12
	vld1.16	{d18-d19}, [r6]
	vmla.i16	q1, q8, q9
	add	r6, r6, r12
	vld1.16	{d18-d19}, [r6]
	vmla.i16	q2, q8, q9
	add	r6, r6, r12
	vld1.16	{d18-d19}, [r6]
	vmla.i16	q3, q8, q9
	add	r6, r6, r12
	vld1.16	{d18-d19}, [r6]
	vmla.i16	q4, q8, q9
	add	r6, r6, r12
	vld1.16	{d18-d19}, [r6]
	vmla.i16	q5, q8, q9
	add	r6, r6, r12
	vld1.16	{d18-d19}, [r6]
	vmla.i16	q6, q8, q9
	add	r6, r6, r12
	vld1.16	{d18-d19}, [r6]
	vmla.i16	q7, q8, q9
	add	r6, r6, r12
	add	r5, r5, #16
	subs	r8, r8, #1
	bne	L_frodokem_mul_bs_neon_k
	vadd.i16	d18, d0, d1
	vpadd.i16	d18, d18, d18
	vpadd.i16	d18, d18, d18
	vmov.u16	r10, d18[0]
	vmov.16	d20[0], r10
	vadd.i16	d18, d2, d3
	vpadd.i16	d18, d18, d18
	vpadd.i16	d18, d18, d18
	vmov.u16	r10, d18[0]
	vmov.16	d20[1], r10
	vadd.i16	d18, d4, d5
	vpadd.i16	d18, d18, d18
	vpadd.i16	d18, d18, d18
	vmov.u16	r10, d18[0]
	vmov.16	d20[2], r10
	vadd.i16	d18, d6, d7
	vpadd.i16	d18, d18, d18
	vpadd.i16	d18, d18, d18
	vmov.u16	r10, d18[0]
	vmov.16	d20[3], r10
	vadd.i16	d18, d8, d9
	vpadd.i16	d18, d18, d18
	vpadd.i16	d18, d18, d18
	vmov.u16	r10, d18[0]
	vmov.16	d21[0], r10
	vadd.i16	d18, d10, d11
	vpadd.i16	d18, d18, d18
	vpadd.i16	d18, d18, d18
	vmov.u16	r10, d18[0]
	vmov.16	d21[1], r10
	vadd.i16	d18, d12, d13
	vpadd.i16	d18, d18, d18
	vpadd.i16	d18, d18, d18
	vmov.u16	r10, d18[0]
	vmov.16	d21[2], r10
	vadd.i16	d18, d14, d15
	vpadd.i16	d18, d18, d18
	vpadd.i16	d18, d18, d18
	vmov.u16	r10, d18[0]
	vmov.16	d21[3], r10
	vand	q10, q10, q11
	vst1.16	{d20-d21}, [r7]!
	subs	r9, r9, #1
	bne	L_frodokem_mul_bs_neon_r
	vpop	{d8-d15}
	pop	{r4, r5, r6, r7, r8, r9, r10, pc}
	.size	frodokem_mul_bs_neon,.-frodokem_mul_bs_neon
	.text
	.align	4
	.fpu	neon
	.globl	frodokem_mul_add_sb_plus_e_neon
	.type	frodokem_mul_add_sb_plus_e_neon, %function
frodokem_mul_add_sb_plus_e_neon:
	push	{r4, r5, r6, r7, r8, r9, lr}
	vpush	{d8-d15}
	ldr	lr, [sp, #92]
	lsl	r12, r3, #1
	vdup.16	q10, lr
	mov	r4, r1
	mov	r5, r2
	mov	r7, r0
	vld1.16	{d0-d1}, [r7]!
	vld1.16	{d2-d3}, [r7]!
	vld1.16	{d4-d5}, [r7]!
	vld1.16	{d6-d7}, [r7]!
	vld1.16	{d8-d9}, [r7]!
	vld1.16	{d10-d11}, [r7]!
	vld1.16	{d12-d13}, [r7]!
	vld1.16	{d14-d15}, [r7]!
	mov	r8, r3
L_frodokem_mul_add_sb_plus_e_neon_j:
	vld1.16	{d16-d17}, [r4]!
	mov	r6, r5
	ldrh	r9, [r6]
	vdup.16	q9, r9
	vmla.i16	q0, q8, q9
	add	r6, r6, r12
	ldrh	r9, [r6]
	vdup.16	q9, r9
	vmla.i16	q1, q8, q9
	add	r6, r6, r12
	ldrh	r9, [r6]
	vdup.16	q9, r9
	vmla.i16	q2, q8, q9
	add	r6, r6, r12
	ldrh	r9, [r6]
	vdup.16	q9, r9
	vmla.i16	q3, q8, q9
	add	r6, r6, r12
	ldrh	r9, [r6]
	vdup.16	q9, r9
	vmla.i16	q4, q8, q9
	add	r6, r6, r12
	ldrh	r9, [r6]
	vdup.16	q9, r9
	vmla.i16	q5, q8, q9
	add	r6, r6, r12
	ldrh	r9, [r6]
	vdup.16	q9, r9
	vmla.i16	q6, q8, q9
	add	r6, r6, r12
	ldrh	r9, [r6]
	vdup.16	q9, r9
	vmla.i16	q7, q8, q9
	add	r6, r6, r12
	add	r5, r5, #2
	subs	r8, r8, #1
	bne	L_frodokem_mul_add_sb_plus_e_neon_j
	mov	r7, r0
	vand	q0, q0, q10
	vst1.16	{d0-d1}, [r7]!
	vand	q1, q1, q10
	vst1.16	{d2-d3}, [r7]!
	vand	q2, q2, q10
	vst1.16	{d4-d5}, [r7]!
	vand	q3, q3, q10
	vst1.16	{d6-d7}, [r7]!
	vand	q4, q4, q10
	vst1.16	{d8-d9}, [r7]!
	vand	q5, q5, q10
	vst1.16	{d10-d11}, [r7]!
	vand	q6, q6, q10
	vst1.16	{d12-d13}, [r7]!
	vand	q7, q7, q10
	vst1.16	{d14-d15}, [r7]!
	vpop	{d8-d15}
	pop	{r4, r5, r6, r7, r8, r9, pc}
	.size	frodokem_mul_add_sb_plus_e_neon,.-frodokem_mul_add_sb_plus_e_neon
#endif /* WOLFSSL_ARMASM_NO_NEON */
#endif /* WOLFSSL_HAVE_FRODOKEM */
#ifdef WOLFSSL_HAVE_FRODOKEM
#ifndef WOLFSSL_ARMASM_NO_NEON
	.fpu	crypto-neon-fp-armv8
	.text
	.align	4
	.globl	frodokem_gen_a_rows_aes_arm32
	.type	frodokem_gen_a_rows_aes_arm32, %function
frodokem_gen_a_rows_aes_arm32:
	push	{r4, r5, r6, r7, r8, r9, lr}
	vpush	{d8-d15}
	ldr	lr, [sp, #96]
	lsl	lr, lr, #1
	ldr	r4, [sp, #92]
	mul	r4, r4, lr
	ldr	r12, [sp, #100]
	vld1.8	{d0-d1}, [r2]!
	vld1.8	{d2-d3}, [r2]!
	vld1.8	{d4-d5}, [r2]!
	vld1.8	{d6-d7}, [r2]!
	vld1.8	{d8-d9}, [r2]!
	vld1.8	{d10-d11}, [r2]!
	vld1.8	{d12-d13}, [r2]!
	vld1.8	{d14-d15}, [r2]!
	vld1.8	{d16-d17}, [r2]!
	vld1.8	{d18-d19}, [r2]!
	vld1.8	{d20-d21}, [r2]!
	vdup.16	q13, r12
	movw	r8, #0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	orr	r8, r8, #0x80000
#else
	movt	r8, #0x8
#endif
	mov	r9, #0
	mov	r5, r0
L_frodokem_gen_a_rows_aes_arm32_row:
	mov	r7, r3
	add	r6, r5, lr
L_frodokem_gen_a_rows_aes_arm32_blk:
	str	r7, [r5], #4
	str	r9, [r5], #4
	str	r9, [r5], #4
	str	r9, [r5], #4
	add	r7, r7, r8
	cmp	r5, r6
	blt	L_frodokem_gen_a_rows_aes_arm32_blk
	add	r3, r3, #1
	add	r6, r0, r4
	cmp	r5, r6
	blt	L_frodokem_gen_a_rows_aes_arm32_row
L_frodokem_gen_a_rows_aes_arm32_aes:
	vld1.8	{d22-d23}, [r0]!
	vld1.8	{d24-d25}, [r0]!
	aese.8	q11, q0
	aese.8	q12, q0
	aesmc.8	q11, q11
	aesmc.8	q12, q12
	aese.8	q11, q1
	aese.8	q12, q1
	aesmc.8	q11, q11
	aesmc.8	q12, q12
	aese.8	q11, q2
	aese.8	q12, q2
	aesmc.8	q11, q11
	aesmc.8	q12, q12
	aese.8	q11, q3
	aese.8	q12, q3
	aesmc.8	q11, q11
	aesmc.8	q12, q12
	aese.8	q11, q4
	aese.8	q12, q4
	aesmc.8	q11, q11
	aesmc.8	q12, q12
	aese.8	q11, q5
	aese.8	q12, q5
	aesmc.8	q11, q11
	aesmc.8	q12, q12
	aese.8	q11, q6
	aese.8	q12, q6
	aesmc.8	q11, q11
	aesmc.8	q12, q12
	aese.8	q11, q7
	aese.8	q12, q7
	aesmc.8	q11, q11
	aesmc.8	q12, q12
	aese.8	q11, q8
	aese.8	q12, q8
	aesmc.8	q11, q11
	aesmc.8	q12, q12
	aese.8	q11, q9
	aese.8	q12, q9
	veor	q11, q11, q10
	veor	q12, q12, q10
	vand	q11, q11, q13
	vand	q12, q12, q13
	vst1.8	{d22-d23}, [r1]!
	vst1.8	{d24-d25}, [r1]!
	subs	r4, r4, #32
	bne	L_frodokem_gen_a_rows_aes_arm32_aes
	vpop	{d8-d15}
	pop	{r4, r5, r6, r7, r8, r9, pc}
	.size	frodokem_gen_a_rows_aes_arm32,.-frodokem_gen_a_rows_aes_arm32
#endif /* WOLFSSL_ARMASM_NO_NEON */
#endif /* WOLFSSL_HAVE_FRODOKEM */
#ifdef WOLFSSL_HAVE_FRODOKEM
#ifdef __ARM_FEATURE_SIMD32
#if (!defined(__ARM_NEON) && !defined(__ARM_NEON__)) || defined(WOLFSSL_ARMASM_NO_NEON)
	.text
	.align	4
	.globl	frodokem_add_simd32
	.type	frodokem_add_simd32, %function
frodokem_add_simd32:
	push	{lr}
	orr	r2, r2, r2, lsl #16
	mov	r3, #32
L_frodokem_add_simd32_blk:
	ldr	r12, [r0]
	ldr	lr, [r1], #4
	sadd16	r12, r12, lr
	and	r12, r12, r2
	str	r12, [r0], #4
	subs	r3, r3, #1
	bne	L_frodokem_add_simd32_blk
	pop	{pc}
	.size	frodokem_add_simd32,.-frodokem_add_simd32
	.text
	.align	4
	.globl	frodokem_sa_accum_simd32
	.type	frodokem_sa_accum_simd32, %function
frodokem_sa_accum_simd32:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	ldr	r12, [sp, #36]
	lsl	r12, r12, #1
	add	lr, r1, r3, lsl #1
	mov	r6, #8
L_frodokem_sa_accum_simd32_i:
	ldrh	r7, [lr]
	add	lr, lr, r12
	mov	r4, r2
	lsr	r5, r12, #2
L_frodokem_sa_accum_simd32_k:
	ldr	r9, [r0]
	ldr	r8, [r4], #4
	smulbb	r10, r7, r8
	smulbt	r11, r7, r8
	pkhbt	r10, r10, r11, LSL #16
	sadd16	r9, r9, r10
	str	r9, [r0], #4
	subs	r5, r5, #1
	bne	L_frodokem_sa_accum_simd32_k
	subs	r6, r6, #1
	bne	L_frodokem_sa_accum_simd32_i
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	frodokem_sa_accum_simd32,.-frodokem_sa_accum_simd32
	.text
	.align	4
	.globl	frodokem_as_accum_simd32
	.type	frodokem_as_accum_simd32, %function
frodokem_as_accum_simd32:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	ldr	r12, [sp, #36]
	lsl	r12, r12, #1
	add	lr, r0, r3, lsl #4
	mov	r4, r1
	mov	r7, #8
L_frodokem_as_accum_simd32_c:
	mov	r9, #0
	mov	r5, r2
	mov	r6, r4
	lsr	r8, r12, #2
L_frodokem_as_accum_simd32_j:
	ldr	r10, [r5], #4
	ldr	r11, [r6], #4
	smlad	r9, r10, r11, r9
	subs	r8, r8, #1
	bne	L_frodokem_as_accum_simd32_j
	ldrh	r10, [lr]
	add	r10, r10, r9
	strh	r10, [lr]
	add	lr, lr, #2
	add	r4, r4, r12
	subs	r7, r7, #1
	bne	L_frodokem_as_accum_simd32_c
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	frodokem_as_accum_simd32,.-frodokem_as_accum_simd32
	.text
	.align	4
	.globl	frodokem_mul_bs_simd32
	.type	frodokem_mul_bs_simd32, %function
frodokem_mul_bs_simd32:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	mov	r12, r1
	mov	r6, #8
L_frodokem_mul_bs_simd32_i:
	mov	lr, r2
	mov	r7, #8
L_frodokem_mul_bs_simd32_c:
	mov	r9, #0
	mov	r4, r12
	mov	r5, lr
	lsr	r8, r3, #1
L_frodokem_mul_bs_simd32_j:
	ldr	r10, [r4], #4
	ldr	r11, [r5], #4
	smlad	r9, r10, r11, r9
	subs	r8, r8, #1
	bne	L_frodokem_mul_bs_simd32_j
	ldr	r10, [sp, #36]
	orr	r10, r10, r10, lsl #16
	and	r9, r9, r10
	strh	r9, [r0]
	add	r0, r0, #2
	add	lr, lr, r3, lsl #1
	subs	r7, r7, #1
	bne	L_frodokem_mul_bs_simd32_c
	add	r12, r12, r3, lsl #1
	subs	r6, r6, #1
	bne	L_frodokem_mul_bs_simd32_i
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	frodokem_mul_bs_simd32,.-frodokem_mul_bs_simd32
	.text
	.align	4
	.globl	frodokem_mul_add_sb_plus_e_simd32
	.type	frodokem_mul_add_sb_plus_e_simd32, %function
frodokem_mul_add_sb_plus_e_simd32:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	sub	sp, sp, #8
	lsl	r9, r3, #1
	str	r9, [sp, #4]
	str	r1, [sp]
	mov	r12, #8
L_frodokem_mul_add_sb_plus_e_simd32_i:
	ldr	r9, [sp, #4]
	add	r3, r2, r9
	ldr	r1, [sp]
	mov	lr, r2
	ldr	r4, [r0]
	ldr	r5, [r0, #4]
	ldr	r6, [r0, #8]
	ldr	r7, [r0, #12]
L_frodokem_mul_add_sb_plus_e_simd32_j:
	ldrh	r8, [lr]
	add	lr, lr, #2
	ldr	r9, [r1]
	smulbb	r10, r8, r9
	smulbt	r11, r8, r9
	pkhbt	r10, r10, r11, LSL #16
	sadd16	r4, r4, r10
	ldr	r9, [r1, #4]
	smulbb	r10, r8, r9
	smulbt	r11, r8, r9
	pkhbt	r10, r10, r11, LSL #16
	sadd16	r5, r5, r10
	ldr	r9, [r1, #8]
	smulbb	r10, r8, r9
	smulbt	r11, r8, r9
	pkhbt	r10, r10, r11, LSL #16
	sadd16	r6, r6, r10
	ldr	r9, [r1, #12]
	smulbb	r10, r8, r9
	smulbt	r11, r8, r9
	pkhbt	r10, r10, r11, LSL #16
	sadd16	r7, r7, r10
	add	r1, r1, #16
	cmp	lr, r3
	bne	L_frodokem_mul_add_sb_plus_e_simd32_j
	ldr	r9, [sp, #44]
	orr	r9, r9, r9, lsl #16
	and	r4, r4, r9
	and	r5, r5, r9
	and	r6, r6, r9
	and	r7, r7, r9
	str	r4, [r0]
	str	r5, [r0, #4]
	str	r6, [r0, #8]
	str	r7, [r0, #12]
	add	r0, r0, #16
	mov	r2, r3
	subs	r12, r12, #1
	bne	L_frodokem_mul_add_sb_plus_e_simd32_i
	add	sp, sp, #8
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	frodokem_mul_add_sb_plus_e_simd32,.-frodokem_mul_add_sb_plus_e_simd32
#endif /* (!defined(__ARM_NEON) && !defined(__ARM_NEON__)) || defined(WOLFSSL_ARMASM_NO_NEON) */
#endif /* __ARM_FEATURE_SIMD32 */
#endif /* WOLFSSL_HAVE_FRODOKEM */

#if defined(__linux__) && defined(__ELF__)
.section	.note.GNU-stack,"",%progbits
#endif
#endif /* !WOLFSSL_ARMASM_INLINE */
#endif /* !__aarch64__ && !WOLFSSL_ARMASM_THUMB2 */
#endif /* WOLFSSL_ARMASM */
