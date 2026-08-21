/* armv8-32-mldsa-asm
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
 *   ruby ./mldsa/mldsa.rb arm32 \
 *       ../wolfssl/wolfcrypt/src/port/arm/armv8-32-mldsa-asm.S
 */

#define WC_FIPS_LL_CRYPTO
#define _WC_BUILDING_ARMV8_32_MLDSA_ASM_S

#include <wolfssl/wolfcrypt/libwolfssl_sources_asm.h>

#ifdef WOLFSSL_ARMASM
#if !defined(__aarch64__) && !defined(WOLFSSL_ARMASM_THUMB2)
#ifndef WOLFSSL_ARMASM_INLINE
#ifdef WOLFSSL_HAVE_MLDSA
#ifndef WOLFSSL_ARMASM_NO_NEON
#ifndef __APPLE__
	.text
	.type	L_mldsa_arm32_consts, %object
	.size	L_mldsa_arm32_consts, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_arm32_consts:
	.long	0x007fe001,0x03802001,0x00000000,0x00000000
	.text
	.align	4
	.globl	mldsa_mul_neon
	WC_ASM_ATT_HIDDEN(mldsa_mul_neon)
	.type	mldsa_mul_neon, %function
mldsa_mul_neon:
	vpush	{d8-d15}
	adr	r3, L_mldsa_arm32_consts
	vld1.8	{q0}, [r3]
	mov	r12, #32
L_mldsa_arm32_mul_loop:
	vld1.8	{q1-q2}, [r1]!
	vld1.8	{q3-q4}, [r2]!
	vmul.i32	q7, q3, d0[1]
	vmul.i32	q8, q4, d0[1]
	vmul.i32	q9, q1, q7
	vmul.i32	q10, q2, q8
	vqrdmulh.s32	q5, q1, q3
	vqrdmulh.s32	q6, q2, q4
	vqrdmulh.s32	q9, q9, d0[0]
	vqrdmulh.s32	q10, q10, d0[0]
	vsub.i32	q5, q5, q9
	vsub.i32	q6, q6, q10
	vshr.s32	q5, q5, #1
	vshr.s32	q6, q6, #1
	vst1.8	{q5-q6}, [r0]!
	subs	r12, r12, #1
	bne	L_mldsa_arm32_mul_loop
	vpop	{d8-d15}
	bx	lr
	.size	mldsa_mul_neon,.-mldsa_mul_neon
#ifndef __APPLE__
	.text
	.type	L_mldsa_arm32_ntt_zetas, %object
	.size	L_mldsa_arm32_ntt_zetas, 1024
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_arm32_ntt_zetas:
	.long	0xffff5c06,0x000064f7,0xffd83102,0xfff81503
	.long	0x00039e44,0xfff42118,0xfff2a128,0x00071e24
	.long	0x001bde2b,0x0023e92b,0xfffa84ad,0xffe0147f
	.long	0x002f9a75,0xffd3fb09,0x002f7a49,0x0028e527
	.long	0x00299658,0x000fa070,0xffef85a4,0x0036b788
	.long	0xfff79d90,0xffeeeaa0,0x0027f968,0xffdfd37b
	.long	0xffdfadd6,0xffc51ae7,0xffeaa4f7,0xffcdfc98
	.long	0x001ad035,0xffffb422,0x003d3201,0x000445c5
	.long	0x00294a67,0x00017620,0x002ef4cd,0x0035dec5
	.long	0xffe6a503,0xffc9302c,0xffd947d4,0x003bbeaf
	.long	0xffc51585,0xffd18e7c,0x00368a96,0xffd43e41
	.long	0x00360400,0xfffb6a4d,0x0023d69c,0xfff7c55d
	.long	0xffe6123d,0xffe6ead6,0x00357e1e,0xffc5af59
	.long	0x0035843f,0xffdf5617,0xffe7945c,0x0038738c
	.long	0x000c63a8,0x00081b9a,0x000e8f76,0x003b3853
	.long	0x003b8534,0xffd8fc30,0x001f9d54,0xffd54f2d
	.long	0xffc406e5,0xffe8ac81,0xffc7e1cf,0xffd19819
	.long	0xffe9d65d,0x003509ee,0x002135c7,0xffe7cfbb
	.long	0xffeccf75,0x001d9772,0xffc1b072,0xfff0bcf6
	.long	0xffcf5280,0xffcfd2ae,0xffc890e0,0x0001efca
	.long	0x003410f2,0xfff0fe85,0x0020c638,0x00296e9f
	.long	0xffd2b7a3,0xffc7a44b,0xfff9ba6d,0xffda3409
	.long	0xfff5c282,0xffed4113,0xffffa63b,0xffec09f7
	.long	0xfffa2bdd,0x001495d4,0x001c4563,0xffea2c62
	.long	0xffccfbe9,0x00040af0,0x0007c417,0x002f4588
	.long	0x0000ad00,0xffef36be,0x000dcd44,0x003c675a
	.long	0xffc72bca,0xffffde7e,0x00193948,0xffce69c0
	.long	0x0024756c,0xfffcc7df,0x000b98a1,0xffebe808
	.long	0x0002e46c,0xffc9c808,0x003036c2,0xffe3bff6
	.long	0xffdb3c93,0xfffd4ae0,0x00141305,0x00147792
	.long	0x00139e25,0xffe7d0e0,0xfff39944,0xffea0802
	.long	0xffd1eea2,0xffc4c79c,0xffc8a057,0x003a97d9
	.long	0x001fea93,0x0033ff5a,0x002358d4,0x003a41f8
	.long	0xffccff72,0x00223dfb,0xffdaab9f,0xffc9a422
	.long	0x000412f5,0x00252587,0xffed24f0,0x00359b5d
	.long	0xffca48a0,0xffc6a2fc,0xffedbb56,0xffcf45de
	.long	0x000dbe5e,0x001c5e1a,0x000de0e6,0x000c7f5a
	.long	0x00078f83,0xffe7628a,0xffff5704,0xfff806fc
	.long	0xfff60021,0xffd05af6,0x001f0084,0x0030ef86
	.long	0xffc9b97d,0xfff7fcd6,0xfff44592,0xffc921c2
	.long	0x00053919,0x0004610c,0xffdacd41,0x003eb01b
	.long	0x003472e7,0xffcd003b,0x001a7cc7,0x00031924
	.long	0x002b5ee5,0x00291199,0xffd87a3a,0x00134d71
	.long	0x003de11c,0x00130984,0x0025f051,0x00185a46
	.long	0xffc68518,0x001314be,0x00283891,0xffc9db90
	.long	0xffd25089,0x001c853f,0x001d0b4b,0xffeff6a6
	.long	0xffeba8be,0x0012e11b,0xffcd5e3e,0xffea2d2f
	.long	0xfff91de4,0x001406c7,0x00327283,0xffe20d6e
	.long	0xffec7953,0x001d4099,0xffd92578,0xffeb05ad
	.long	0x0016e405,0x000bdbe7,0x00221de8,0x0033f8cf
	.long	0xfff7b934,0xffd4ca0c,0xffe67ff8,0xffe3d157
	.long	0xffd8911b,0xffc72c12,0x000910d8,0xffc65e1f
	.long	0xffe14658,0x00251d8b,0x002573b7,0xfffd7c8f
	.long	0x001ddd98,0x00336898,0x0002d4bb,0xffed93a7
	.long	0xffcf6cbe,0x00027c1c,0x0018aa08,0x002dfd71
	.long	0x000c5ca5,0x0019379a,0xffc7a167,0xffe48c3d
	.long	0xffd1a13c,0x0035c539,0x003b0115,0x00041dc0
	.long	0x0021c4f7,0xfff11bf4,0x001a35e7,0x0007340e
	.long	0xfff97d45,0x001a4cd0,0xffe47cae,0x001d2668
	.long	0xffe68e98,0xffef2633,0xfffc05da,0xffc57fdb
	.long	0xffd32764,0xffdde1af,0xfff993dd,0xffdd1d09
	.long	0x0002cc93,0xfff11805,0x00189c2a,0xffc9e5a9
	.long	0xfff78a50,0x003bcf2c,0xffff434e,0xffeb36df
	.long	0x003c15ca,0x00155e68,0xfff316b6,0x001e29ce
#ifndef __APPLE__
	.text
	.type	L_mldsa_arm32_ntt_consts, %object
	.size	L_mldsa_arm32_ntt_consts, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_arm32_ntt_consts:
	.long	0x007fe001,0x03802001,0x00000000,0x00000000
#ifndef __APPLE__
	.text
	.type	L_mldsa_arm32_ntt_zetas_p, %object
	.size	L_mldsa_arm32_ntt_zetas_p, 12
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_arm32_ntt_zetas_p:
	.long	L_mldsa_arm32_ntt_zetas
	.text
	.align	4
	.globl	mldsa_ntt_neon
	WC_ASM_ATT_HIDDEN(mldsa_ntt_neon)
	.type	mldsa_ntt_neon, %function
mldsa_ntt_neon:
	vpush	{d8-d15}
	adr	r1, L_mldsa_arm32_ntt_consts
	vld1.8	{q0}, [r1]
	vdup.32	q1, d0[1]
	adr	r2, L_mldsa_arm32_ntt_zetas_p
	ldr	r2, [r2]
	add	r2, r2, #4
	# len = 128
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0
	add	r12, r3, #0x200
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	# len = 64
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0
	add	r12, r3, #0x100
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x200
	add	r12, r3, #0x100
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	# len = 32
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0
	add	r12, r3, #0x80
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x100
	add	r12, r3, #0x80
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x200
	add	r12, r3, #0x80
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x300
	add	r12, r3, #0x80
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	# len = 16
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0
	add	r12, r3, #0x40
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x80
	add	r12, r3, #0x40
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x100
	add	r12, r3, #0x40
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x180
	add	r12, r3, #0x40
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x200
	add	r12, r3, #0x40
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x280
	add	r12, r3, #0x40
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x300
	add	r12, r3, #0x40
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x380
	add	r12, r3, #0x40
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	# len = 8
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0
	add	r12, r3, #32
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x40
	add	r12, r3, #32
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x80
	add	r12, r3, #32
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0xc0
	add	r12, r3, #32
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x100
	add	r12, r3, #32
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x140
	add	r12, r3, #32
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x180
	add	r12, r3, #32
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x1c0
	add	r12, r3, #32
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x200
	add	r12, r3, #32
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x240
	add	r12, r3, #32
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x280
	add	r12, r3, #32
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x2c0
	add	r12, r3, #32
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x300
	add	r12, r3, #32
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x340
	add	r12, r3, #32
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x380
	add	r12, r3, #32
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x3c0
	add	r12, r3, #32
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	# len = 4
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #32
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x40
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x60
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x80
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0xa0
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0xc0
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0xe0
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x100
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x120
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x140
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x160
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x180
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x1a0
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x1c0
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x1e0
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x200
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x220
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x240
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x260
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x280
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x2a0
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x2c0
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x2e0
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x300
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x320
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x340
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x360
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x380
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x3a0
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x3c0
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x3e0
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	# len = 2
	add	r3, r0, #0
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vmul.i32	d14, d9, d6
	vqrdmulh.s32	d12, d9, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d12, d12, d14
	vshr.s32	d12, d12, #1
	vsub.i32	d9, d8, d12
	vadd.i32	d8, d8, d12
	vst1.8	{q4}, [r3]!
	# len = 1
	add	r3, r0, #0
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vmul.i32	q7, q5, q3
	vqrdmulh.s32	q6, q5, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q6, q6, q7
	vshr.s32	q6, q6, #1
	vsub.i32	q5, q4, q6
	vadd.i32	q4, q4, q6
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vpop	{d8-d15}
	bx	lr
	.size	mldsa_ntt_neon,.-mldsa_ntt_neon
#ifndef __APPLE__
	.text
	.type	L_mldsa_arm32_invntt_zetas, %object
	.size	L_mldsa_arm32_invntt_zetas, 1024
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_arm32_invntt_zetas:
	.long	0xffe1d632,0x000ce94a,0xffeaa198,0xffc3ea36
	.long	0x0014c921,0x0000bcb2,0xffc430d4,0x000875b0
	.long	0x00361a57,0xffe763d6,0x000ee7fb,0xfffd336d
	.long	0x0022e2f7,0x00066c23,0x00221e51,0x002cd89c
	.long	0x003a8025,0x0003fa26,0x0010d9cd,0x00197168
	.long	0xffe2d998,0x001b8352,0xffe5b330,0x000682bb
	.long	0xfff8cbf2,0xffe5ca19,0x000ee40c,0xffde3b09
	.long	0xfffbe240,0xffc4feeb,0xffca3ac7,0x002e5ec4
	.long	0x001b73c3,0x00385e99,0xffe6c866,0xfff3a35b
	.long	0xffd2028f,0xffe755f8,0xfffd83e4,0x00309342
	.long	0x00126c59,0xfffd2b45,0xffcc9768,0xffe22268
	.long	0x00028371,0xffda8c49,0xffdae275,0x001eb9a8
	.long	0x0039a1e1,0xfff6ef28,0x0038d3ee,0x00276ee5
	.long	0x001c2ea9,0x00198008,0x002b35f4,0x000846cc
	.long	0xffcc0731,0xffdde218,0xfff42419,0xffe91bfb
	.long	0x0014fa53,0x0026da88,0xffe2bf67,0x001386ad
	.long	0x001df292,0xffcd8d7d,0xffebf939,0x0006e21c
	.long	0x0015d2d1,0x0032a1c2,0xffed1ee5,0x00145742
	.long	0x0010095a,0xffe2f4b5,0xffe37ac1,0x002daf77
	.long	0x00362470,0xffd7c76f,0xffeceb42,0x00397ae8
	.long	0xffe7a5ba,0xffda0faf,0xffecf67c,0xffc21ee4
	.long	0xffecb28f,0x002785c6,0xffd6ee67,0xffd4a11b
	.long	0xfffce6dc,0xffe58339,0x0032ffc5,0xffcb8d19
	.long	0xffc14fe5,0x002532bf,0xfffb9ef4,0xfffac6e7
	.long	0x0036de3e,0x000bba6e,0x0008032a,0x00364683
	.long	0xffcf107a,0xffe0ff7c,0x002fa50a,0x0009ffdf
	.long	0x0007f904,0x0000a8fc,0x00189d76,0xfff8707d
	.long	0xfff380a6,0xfff21f1a,0xffe3a1e6,0xfff241a2
	.long	0x0030ba22,0x001244aa,0x00395d04,0x0035b760
	.long	0xffca64a3,0x0012db10,0xffdada79,0xfffbed0b
	.long	0x00365bde,0x00255461,0xffddc205,0x0033008e
	.long	0xffc5be08,0xffdca72c,0xffcc00a6,0xffe0156d
	.long	0xffc56827,0x00375fa9,0x003b3864,0x002e115e
	.long	0x0015f7fe,0x000c66bc,0x00182f20,0xffec61db
	.long	0xffeb886e,0xffebecfb,0x0002b520,0x0024c36d
	.long	0x001c400a,0xffcfc93e,0x003637f8,0xfffd1b94
	.long	0x001417f8,0xfff4675f,0x00033821,0xffdb8a94
	.long	0x00319640,0xffe6c6b8,0x00002182,0x0038d436
	.long	0xffc398a6,0xfff232bc,0x0010c942,0xffff5300
	.long	0xffd0ba78,0xfff83be9,0xfffbf510,0x00330417
	.long	0x0015d39e,0xffe3ba9d,0xffeb6a2c,0x0005d423
	.long	0x0013f609,0x000059c5,0x0012beed,0x000a3d7e
	.long	0x0025cbf7,0x00064593,0x00385bb5,0x002d485d
	.long	0xffd69161,0xffdf39c8,0x000f017b,0xffcbef0e
	.long	0xfffe1036,0x00376f20,0x00302d52,0x0030ad80
	.long	0x000f430a,0x003e4f8e,0xffe2688e,0x0013308b
	.long	0x00183045,0xffdeca39,0xffcaf612,0x001629a3
	.long	0x002e67e7,0x00381e31,0x0017537f,0x003bf91b
	.long	0x002ab0d3,0xffe062ac,0x002703d0,0xffc47acc
	.long	0xffc4c7ad,0xfff1708a,0xfff7e466,0xfff39c58
	.long	0xffc78c74,0x00186ba4,0x0020a9e9,0xffca7bc1
	.long	0x003a50a7,0xffca81e2,0x0019152a,0x0019edc3
	.long	0x00083aa3,0xffdc2964,0x000495b3,0xffc9fc00
	.long	0x002bc1bf,0xffc9756a,0x002e7184,0x003aea7b
	.long	0xffc44151,0x0026b82c,0x0036cfd4,0x00195afd
	.long	0xffca213b,0xffd10b33,0xfffe89e0,0xffd6b599
	.long	0xfffbba3b,0xffc2cdff,0x00004bde,0xffe52fcb
	.long	0x00320368,0x00155b09,0x003ae519,0x0020522a
	.long	0x00202c85,0xffd80698,0x00111560,0x00086270
	.long	0xffc94878,0x00107a5c,0xfff05f90,0xffd669a8
	.long	0xffd71ad9,0xffd085b7,0x002c04f7,0xffd0658b
	.long	0x001feb81,0x00057b53,0xffdc16d5,0xffe421d5
	.long	0xfff8e1dc,0x000d5ed8,0x000bdee8,0xfffc61bc
	.long	0x0007eafd,0x0027cefe,0xffff9b09,0x0000a3fa
#ifndef __APPLE__
	.text
	.type	L_mldsa_arm32_invntt_consts, %object
	.size	L_mldsa_arm32_invntt_consts, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_arm32_invntt_consts:
	.long	0x007fe001,0x03802001,0x00000000,0x00000000
#ifndef __APPLE__
	.text
	.type	L_mldsa_arm32_invntt_zetas_p, %object
	.size	L_mldsa_arm32_invntt_zetas_p, 12
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_arm32_invntt_zetas_p:
	.long	L_mldsa_arm32_invntt_zetas
	.text
	.align	4
	.globl	mldsa_invntt_neon
	WC_ASM_ATT_HIDDEN(mldsa_invntt_neon)
	.type	mldsa_invntt_neon, %function
mldsa_invntt_neon:
	vpush	{d8-d15}
	adr	r1, L_mldsa_arm32_invntt_consts
	vld1.8	{q0}, [r1]
	vdup.32	q1, d0[1]
	adr	r2, L_mldsa_arm32_invntt_zetas_p
	ldr	r2, [r2]
	# len = 1
	add	r3, r0, #0
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	add	r3, r3, #16
	vld1.8	{q5}, [r3]
	sub	r3, r3, #16
	vuzp.32	q4, q5
	vld1.8	{q2}, [r2]!
	vmul.i32	q3, q2, q1
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vzip.32	q4, q5
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r3]!
	# len = 2
	add	r3, r0, #0
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	ldr	r1, [r2], #4
	vdup.32	d4, r1
	vmul.i32	d6, d4, d2
	vld1.8	{q4}, [r3]
	vsub.i32	d12, d8, d9
	vadd.i32	d8, d8, d9
	vmul.i32	d14, d12, d6
	vqrdmulh.s32	d9, d12, d4
	vqrdmulh.s32	d14, d14, d0[0]
	vsub.i32	d9, d9, d14
	vshr.s32	d9, d9, #1
	vst1.8	{q4}, [r3]!
	# len = 4
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #32
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x40
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x60
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x80
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0xa0
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0xc0
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0xe0
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x100
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x120
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x140
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x160
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x180
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x1a0
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x1c0
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x1e0
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x200
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x220
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x240
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x260
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x280
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x2a0
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x2c0
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x2e0
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x300
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x320
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x340
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x360
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x380
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x3a0
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x3c0
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x3e0
	add	r12, r3, #16
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	# len = 8
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0
	add	r12, r3, #32
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x40
	add	r12, r3, #32
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x80
	add	r12, r3, #32
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0xc0
	add	r12, r3, #32
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x100
	add	r12, r3, #32
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x140
	add	r12, r3, #32
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x180
	add	r12, r3, #32
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x1c0
	add	r12, r3, #32
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x200
	add	r12, r3, #32
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x240
	add	r12, r3, #32
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x280
	add	r12, r3, #32
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x2c0
	add	r12, r3, #32
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x300
	add	r12, r3, #32
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x340
	add	r12, r3, #32
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x380
	add	r12, r3, #32
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x3c0
	add	r12, r3, #32
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	# len = 16
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0
	add	r12, r3, #0x40
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x80
	add	r12, r3, #0x40
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x100
	add	r12, r3, #0x40
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x180
	add	r12, r3, #0x40
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x200
	add	r12, r3, #0x40
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x280
	add	r12, r3, #0x40
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x300
	add	r12, r3, #0x40
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x380
	add	r12, r3, #0x40
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	# len = 32
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0
	add	r12, r3, #0x80
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x100
	add	r12, r3, #0x80
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x200
	add	r12, r3, #0x80
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x300
	add	r12, r3, #0x80
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	# len = 64
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0
	add	r12, r3, #0x100
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0x200
	add	r12, r3, #0x100
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	# len = 128
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0
	add	r12, r3, #0x200
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	vld1.8	{q4}, [r3]
	vld1.8	{q5}, [r12]
	vsub.i32	q6, q4, q5
	vadd.i32	q4, q4, q5
	vmul.i32	q7, q6, q3
	vqrdmulh.s32	q5, q6, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q4}, [r3]!
	vst1.8	{q5}, [r12]!
	# scale
	ldr	r1, [r2], #4
	vdup.32	q2, r1
	vmul.i32	q3, q2, q1
	add	r3, r0, #0
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vld1.8	{q4}, [r3]
	vmul.i32	q7, q4, q3
	vqrdmulh.s32	q5, q4, q2
	vqrdmulh.s32	q7, q7, d0[0]
	vsub.i32	q5, q5, q7
	vshr.s32	q5, q5, #1
	vst1.8	{q5}, [r3]!
	vpop	{d8-d15}
	bx	lr
	.size	mldsa_invntt_neon,.-mldsa_invntt_neon
#ifndef __APPLE__
	.text
	.type	L_mldsa_arm32_q88_consts_decompose, %object
	.size	L_mldsa_arm32_q88_consts_decompose, 96
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_arm32_q88_consts_decompose:
	.long	0x0000002c,0x0000002c,0x0000002c,0x0000002c
	.long	0x003fefd4,0x003fefd4,0x003fefd4,0x003fefd4
	.long	0x0002e800,0x0002e800,0x0002e800,0x0002e800
	.long	0x00017400,0x00017400,0x00017400,0x00017400
	.long	0x0000002b,0x0000002b,0x0000002b,0x0000002b
	.long	0x007fe001,0x007fe001,0x007fe001,0x007fe001
	.text
	.align	4
	.globl	mldsa_decompose_q88_neon
	WC_ASM_ATT_HIDDEN(mldsa_decompose_q88_neon)
	.type	mldsa_decompose_q88_neon, %function
mldsa_decompose_q88_neon:
	vpush	{d8-d15}
	adr	r3, L_mldsa_arm32_q88_consts_decompose
	vld1.8	{q0}, [r3]!
	vld1.8	{q1}, [r3]!
	vld1.8	{q2}, [r3]!
	vld1.8	{q3}, [r3]!
	vld1.8	{q4}, [r3]!
	mov	r12, #32
L_mldsa_decompose_q88_neon_loop:
	vld1.8	{q5}, [r0]!
	vld1.8	{q6}, [r0]!
	vmov	q9, q1
	vmla.i32	q9, q5, q0
	vshr.s32	q9, q9, #23
	vmov	q7, q5
	vmls.i32	q7, q9, q2
	vsub.i32	q11, q3, q7
	vsra.u32	q9, q11, #31
	vmov	q7, q5
	vmls.i32	q7, q9, q2
	vsub.i32	q11, q4, q9
	vshr.u32	q11, q11, #31
	vsub.i32	q7, q7, q11
	vsub.i32	q11, q9, q0
	vshr.u32	q11, q11, #31
	vneg.s32	q11, q11
	vand	q9, q9, q11
	vmov	q10, q1
	vmla.i32	q10, q6, q0
	vshr.s32	q10, q10, #23
	vmov	q8, q6
	vmls.i32	q8, q10, q2
	vsub.i32	q12, q3, q8
	vsra.u32	q10, q12, #31
	vmov	q8, q6
	vmls.i32	q8, q10, q2
	vsub.i32	q12, q4, q10
	vshr.u32	q12, q12, #31
	vsub.i32	q8, q8, q12
	vsub.i32	q12, q10, q0
	vshr.u32	q12, q12, #31
	vneg.s32	q12, q12
	vand	q10, q10, q12
	vst1.8	{q7}, [r1]!
	vst1.8	{q9}, [r2]!
	vst1.8	{q8}, [r1]!
	vst1.8	{q10}, [r2]!
	subs	r12, r12, #1
	bne	L_mldsa_decompose_q88_neon_loop
	vpop	{d8-d15}
	bx	lr
	.size	mldsa_decompose_q88_neon,.-mldsa_decompose_q88_neon
#ifndef __APPLE__
	.text
	.type	L_mldsa_arm32_q88_consts_high, %object
	.size	L_mldsa_arm32_q88_consts_high, 96
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_arm32_q88_consts_high:
	.long	0x0000002c,0x0000002c,0x0000002c,0x0000002c
	.long	0x003fefd4,0x003fefd4,0x003fefd4,0x003fefd4
	.long	0x0002e800,0x0002e800,0x0002e800,0x0002e800
	.long	0x00017400,0x00017400,0x00017400,0x00017400
	.long	0x0000002b,0x0000002b,0x0000002b,0x0000002b
	.long	0x007fe001,0x007fe001,0x007fe001,0x007fe001
	.text
	.align	4
	.globl	mldsa_use_hint_q88_neon
	WC_ASM_ATT_HIDDEN(mldsa_use_hint_q88_neon)
	.type	mldsa_use_hint_q88_neon, %function
mldsa_use_hint_q88_neon:
	vpush	{d8-d15}
	adr	r1, L_mldsa_arm32_q88_consts_high
	vld1.8	{q0}, [r1]!
	vld1.8	{q1}, [r1]!
	vld1.8	{q2}, [r1]!
	vld1.8	{q3}, [r1]!
	vld1.8	{q4}, [r1]!
	vld1.8	{q5}, [r1]!
	mov	r2, #32
L_mldsa_use_hint_q88_neon_loop:
	vld1.8	{q6}, [r0]!
	vld1.8	{q7}, [r0]!
	vshr.s32	q12, q6, #31
	vand	q12, q12, q5
	vadd.i32	q6, q6, q12
	vshr.s32	q13, q7, #31
	vand	q13, q13, q5
	vadd.i32	q7, q7, q13
	vmov	q10, q1
	vmla.i32	q10, q6, q0
	vshr.s32	q10, q10, #23
	vmov	q8, q6
	vmls.i32	q8, q10, q2
	vsub.i32	q12, q3, q8
	vsra.u32	q10, q12, #31
	vmov	q8, q6
	vmls.i32	q8, q10, q2
	vsub.i32	q12, q4, q10
	vshr.u32	q12, q12, #31
	vsub.i32	q8, q8, q12
	vsub.i32	q12, q10, q0
	vshr.u32	q12, q12, #31
	vneg.s32	q12, q12
	vand	q10, q10, q12
	vmov	q11, q1
	vmla.i32	q11, q7, q0
	vshr.s32	q11, q11, #23
	vmov	q9, q7
	vmls.i32	q9, q11, q2
	vsub.i32	q13, q3, q9
	vsra.u32	q11, q13, #31
	vmov	q9, q7
	vmls.i32	q9, q11, q2
	vsub.i32	q13, q4, q11
	vshr.u32	q13, q13, #31
	vsub.i32	q9, q9, q13
	vsub.i32	q13, q11, q0
	vshr.u32	q13, q13, #31
	vneg.s32	q13, q13
	vand	q11, q11, q13
	sub	r0, r0, #32
	vst1.8	{q10}, [r0]!
	vst1.8	{q11}, [r0]!
	subs	r2, r2, #1
	bne	L_mldsa_use_hint_q88_neon_loop
	vpop	{d8-d15}
	bx	lr
	.size	mldsa_use_hint_q88_neon,.-mldsa_use_hint_q88_neon
#ifndef __APPLE__
	.text
	.type	L_mldsa_arm32_q32_consts_decompose, %object
	.size	L_mldsa_arm32_q32_consts_decompose, 80
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_arm32_q32_consts_decompose:
	.long	0x0003feff,0x0003feff,0x0003feff,0x0003feff
	.long	0x0003ff00,0x0003ff00,0x0003ff00,0x0003ff00
	.long	0x0000000f,0x0000000f,0x0000000f,0x0000000f
	.long	0x0007fe00,0x0007fe00,0x0007fe00,0x0007fe00
	.long	0x007fe001,0x007fe001,0x007fe001,0x007fe001
	.text
	.align	4
	.globl	mldsa_decompose_q32_neon
	WC_ASM_ATT_HIDDEN(mldsa_decompose_q32_neon)
	.type	mldsa_decompose_q32_neon, %function
mldsa_decompose_q32_neon:
	vpush	{d8-d15}
	adr	r3, L_mldsa_arm32_q32_consts_decompose
	vld1.8	{q0}, [r3]!
	vld1.8	{q1}, [r3]!
	vld1.8	{q2}, [r3]!
	vld1.8	{q3}, [r3]!
	mov	r12, #32
L_mldsa_decompose_q32_neon_loop:
	vld1.8	{q4}, [r0]!
	vld1.8	{q5}, [r0]!
	vadd.i32	q8, q4, q0
	vshr.s32	q8, q8, #19
	vmov	q6, q4
	vmls.i32	q6, q8, q3
	vsub.i32	q10, q1, q6
	vsra.u32	q8, q10, #31
	vmov	q6, q4
	vmls.i32	q6, q8, q3
	vshr.s32	q10, q8, #4
	vsub.i32	q6, q6, q10
	vand	q8, q8, q2
	vadd.i32	q9, q5, q0
	vshr.s32	q9, q9, #19
	vmov	q7, q5
	vmls.i32	q7, q9, q3
	vsub.i32	q11, q1, q7
	vsra.u32	q9, q11, #31
	vmov	q7, q5
	vmls.i32	q7, q9, q3
	vshr.s32	q11, q9, #4
	vsub.i32	q7, q7, q11
	vand	q9, q9, q2
	vst1.8	{q6}, [r1]!
	vst1.8	{q8}, [r2]!
	vst1.8	{q7}, [r1]!
	vst1.8	{q9}, [r2]!
	subs	r12, r12, #1
	bne	L_mldsa_decompose_q32_neon_loop
	vpop	{d8-d15}
	bx	lr
	.size	mldsa_decompose_q32_neon,.-mldsa_decompose_q32_neon
#ifndef __APPLE__
	.text
	.type	L_mldsa_arm32_q32_consts_high, %object
	.size	L_mldsa_arm32_q32_consts_high, 80
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_arm32_q32_consts_high:
	.long	0x0003feff,0x0003feff,0x0003feff,0x0003feff
	.long	0x0003ff00,0x0003ff00,0x0003ff00,0x0003ff00
	.long	0x0000000f,0x0000000f,0x0000000f,0x0000000f
	.long	0x0007fe00,0x0007fe00,0x0007fe00,0x0007fe00
	.long	0x007fe001,0x007fe001,0x007fe001,0x007fe001
	.text
	.align	4
	.globl	mldsa_use_hint_q32_neon
	WC_ASM_ATT_HIDDEN(mldsa_use_hint_q32_neon)
	.type	mldsa_use_hint_q32_neon, %function
mldsa_use_hint_q32_neon:
	vpush	{d8-d15}
	adr	r1, L_mldsa_arm32_q32_consts_high
	vld1.8	{q0}, [r1]!
	vld1.8	{q1}, [r1]!
	vld1.8	{q2}, [r1]!
	vld1.8	{q3}, [r1]!
	vld1.8	{q4}, [r1]!
	mov	r2, #32
L_mldsa_use_hint_q32_neon_loop:
	vld1.8	{q5}, [r0]!
	vld1.8	{q6}, [r0]!
	vshr.s32	q11, q5, #31
	vand	q11, q11, q4
	vadd.i32	q5, q5, q11
	vshr.s32	q12, q6, #31
	vand	q12, q12, q4
	vadd.i32	q6, q6, q12
	vadd.i32	q9, q5, q0
	vshr.s32	q9, q9, #19
	vmov	q7, q5
	vmls.i32	q7, q9, q3
	vsub.i32	q11, q1, q7
	vsra.u32	q9, q11, #31
	vmov	q7, q5
	vmls.i32	q7, q9, q3
	vshr.s32	q11, q9, #4
	vsub.i32	q7, q7, q11
	vand	q9, q9, q2
	vadd.i32	q10, q6, q0
	vshr.s32	q10, q10, #19
	vmov	q8, q6
	vmls.i32	q8, q10, q3
	vsub.i32	q12, q1, q8
	vsra.u32	q10, q12, #31
	vmov	q8, q6
	vmls.i32	q8, q10, q3
	vshr.s32	q12, q10, #4
	vsub.i32	q8, q8, q12
	vand	q10, q10, q2
	sub	r0, r0, #32
	vst1.8	{q9}, [r0]!
	vst1.8	{q10}, [r0]!
	subs	r2, r2, #1
	bne	L_mldsa_use_hint_q32_neon_loop
	vpop	{d8-d15}
	bx	lr
	.size	mldsa_use_hint_q32_neon,.-mldsa_use_hint_q32_neon
	.text
	.align	4
	.globl	mldsa_poly_add_neon
	WC_ASM_ATT_HIDDEN(mldsa_poly_add_neon)
	.type	mldsa_poly_add_neon, %function
mldsa_poly_add_neon:
	vpush	{d8-d15}
	mov	r2, #16
L_mldsa_poly_add_neon_loop:
	vld1.8	{q0}, [r0]!
	vld1.8	{q4}, [r1]!
	vld1.8	{q1}, [r0]!
	vld1.8	{q5}, [r1]!
	vld1.8	{q2}, [r0]!
	vld1.8	{q6}, [r1]!
	vld1.8	{q3}, [r0]!
	vld1.8	{q7}, [r1]!
	sub	r0, r0, #0x40
	vadd.i32	q0, q0, q4
	vadd.i32	q1, q1, q5
	vadd.i32	q2, q2, q6
	vadd.i32	q3, q3, q7
	vst1.8	{q0}, [r0]!
	vst1.8	{q1}, [r0]!
	vst1.8	{q2}, [r0]!
	vst1.8	{q3}, [r0]!
	subs	r2, r2, #1
	bne	L_mldsa_poly_add_neon_loop
	vpop	{d8-d15}
	bx	lr
	.size	mldsa_poly_add_neon,.-mldsa_poly_add_neon
	.text
	.align	4
	.globl	mldsa_poly_sub_neon
	WC_ASM_ATT_HIDDEN(mldsa_poly_sub_neon)
	.type	mldsa_poly_sub_neon, %function
mldsa_poly_sub_neon:
	vpush	{d8-d15}
	mov	r2, #16
L_mldsa_poly_sub_neon_loop:
	vld1.8	{q0}, [r0]!
	vld1.8	{q4}, [r1]!
	vld1.8	{q1}, [r0]!
	vld1.8	{q5}, [r1]!
	vld1.8	{q2}, [r0]!
	vld1.8	{q6}, [r1]!
	vld1.8	{q3}, [r0]!
	vld1.8	{q7}, [r1]!
	sub	r0, r0, #0x40
	vsub.i32	q0, q0, q4
	vsub.i32	q1, q1, q5
	vsub.i32	q2, q2, q6
	vsub.i32	q3, q3, q7
	vst1.8	{q0}, [r0]!
	vst1.8	{q1}, [r0]!
	vst1.8	{q2}, [r0]!
	vst1.8	{q3}, [r0]!
	subs	r2, r2, #1
	bne	L_mldsa_poly_sub_neon_loop
	vpop	{d8-d15}
	bx	lr
	.size	mldsa_poly_sub_neon,.-mldsa_poly_sub_neon
#ifndef __APPLE__
	.text
	.type	L_mldsa_poly_make_pos_neon_q, %object
	.size	L_mldsa_poly_make_pos_neon_q, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_poly_make_pos_neon_q:
	.long	0x007fe001,0x007fe001,0x007fe001,0x007fe001
	.text
	.align	4
	.globl	mldsa_poly_make_pos_neon
	WC_ASM_ATT_HIDDEN(mldsa_poly_make_pos_neon)
	.type	mldsa_poly_make_pos_neon, %function
mldsa_poly_make_pos_neon:
	vpush	{d8-d15}
	adr	r1, L_mldsa_poly_make_pos_neon_q
	vld1.8	{q0}, [r1]!
	mov	r2, #16
L_mldsa_poly_make_pos_neon_loop:
	vld1.8	{q1}, [r0]!
	vld1.8	{q2}, [r0]!
	vld1.8	{q3}, [r0]!
	vld1.8	{q4}, [r0]!
	sub	r0, r0, #0x40
	vshr.s32	q5, q1, #31
	vmls.i32	q1, q5, q0
	vshr.s32	q6, q2, #31
	vmls.i32	q2, q6, q0
	vshr.s32	q7, q3, #31
	vmls.i32	q3, q7, q0
	vshr.s32	q8, q4, #31
	vmls.i32	q4, q8, q0
	vst1.8	{q1}, [r0]!
	vst1.8	{q2}, [r0]!
	vst1.8	{q3}, [r0]!
	vst1.8	{q4}, [r0]!
	subs	r2, r2, #1
	bne	L_mldsa_poly_make_pos_neon_loop
	vpop	{d8-d15}
	bx	lr
	.size	mldsa_poly_make_pos_neon,.-mldsa_poly_make_pos_neon
#ifndef __APPLE__
	.text
	.type	L_mldsa_poly_red_neon_q, %object
	.size	L_mldsa_poly_red_neon_q, 32
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_poly_red_neon_q:
	.long	0x007fe001,0x007fe001,0x007fe001,0x007fe001
	.long	0x00400000,0x00400000,0x00400000,0x00400000
	.text
	.align	4
	.globl	mldsa_poly_red_neon
	WC_ASM_ATT_HIDDEN(mldsa_poly_red_neon)
	.type	mldsa_poly_red_neon, %function
mldsa_poly_red_neon:
	vpush	{d8-d15}
	adr	r1, L_mldsa_poly_red_neon_q
	vld1.8	{q0}, [r1]!
	vld1.8	{q1}, [r1]
	mov	r2, #16
L_mldsa_poly_red_neon_loop:
	vld1.8	{q2}, [r0]!
	vld1.8	{q3}, [r0]!
	vld1.8	{q4}, [r0]!
	vld1.8	{q5}, [r0]!
	sub	r0, r0, #0x40
	vadd.i32	q6, q2, q1
	vshr.s32	q6, q6, #23
	vmls.i32	q2, q6, q0
	vadd.i32	q7, q3, q1
	vshr.s32	q7, q7, #23
	vmls.i32	q3, q7, q0
	vadd.i32	q8, q4, q1
	vshr.s32	q8, q8, #23
	vmls.i32	q4, q8, q0
	vadd.i32	q9, q5, q1
	vshr.s32	q9, q9, #23
	vmls.i32	q5, q9, q0
	vst1.8	{q2}, [r0]!
	vst1.8	{q3}, [r0]!
	vst1.8	{q4}, [r0]!
	vst1.8	{q5}, [r0]!
	subs	r2, r2, #1
	bne	L_mldsa_poly_red_neon_loop
	vpop	{d8-d15}
	bx	lr
	.size	mldsa_poly_red_neon,.-mldsa_poly_red_neon
	.text
	.align	4
	.globl	mldsa_vec_check_low_neon
	WC_ASM_ATT_HIDDEN(mldsa_vec_check_low_neon)
	.type	mldsa_vec_check_low_neon, %function
mldsa_vec_check_low_neon:
	vpush	{d8-d15}
	vdup.32	q0, r2
	veor	q1, q1, q1
	veor	q2, q2, q2
	veor	q3, q3, q3
	veor	q4, q4, q4
L_mldsa_arm32_check_low_outer:
	mov	r3, #16
L_mldsa_arm32_check_low_inner:
	vld1.8	{q5}, [r0]!
	vld1.8	{q6}, [r0]!
	vld1.8	{q7}, [r0]!
	vld1.8	{q8}, [r0]!
	vqabs.s32	q9, q5
	vcge.s32	q9, q9, q0
	vorr	q1, q1, q9
	vqabs.s32	q10, q6
	vcge.s32	q10, q10, q0
	vorr	q2, q2, q10
	vqabs.s32	q11, q7
	vcge.s32	q11, q11, q0
	vorr	q3, q3, q11
	vqabs.s32	q12, q8
	vcge.s32	q12, q12, q0
	vorr	q4, q4, q12
	subs	r3, r3, #1
	bne	L_mldsa_arm32_check_low_inner
	subs	r1, r1, #1
	bne	L_mldsa_arm32_check_low_outer
	vorr	q1, q1, q2
	vorr	q3, q3, q4
	vorr	q1, q1, q3
	vorr	d2, d2, d3
	vpmax.u32	d2, d2, d2
	vmov.32	r12, d2[0]
	cmp	r12, #0
	moveq	r12, #1
	movne	r12, #0
	mov	r0, r12
	vpop	{d8-d15}
	bx	lr
	.size	mldsa_vec_check_low_neon,.-mldsa_vec_check_low_neon
#ifndef __APPLE__
	.text
	.type	L_mldsa_decode_eta_2_neon_idx, %object
	.size	L_mldsa_decode_eta_2_neon_idx, 192
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 4-byte aligned, 32-bit aligned
#ifndef __APPLE__
	.align	2
#else
	.p2align	2
#endif /* __APPLE__ */
L_mldsa_decode_eta_2_neon_idx:
	.byte	0x00,0xff,0xff,0xff,0x00,0xff,0xff,0xff
	.byte	0x00,0x01,0xff,0xff,0x01,0xff,0xff,0xff
	.byte	0x01,0xff,0xff,0xff,0x01,0x02,0xff,0xff
	.byte	0x02,0xff,0xff,0xff,0x02,0xff,0xff,0xff
	.byte	0x01,0xff,0xff,0xff,0x01,0xff,0xff,0xff
	.byte	0x01,0x02,0xff,0xff,0x02,0xff,0xff,0xff
	.byte	0x02,0xff,0xff,0xff,0x02,0x03,0xff,0xff
	.byte	0x03,0xff,0xff,0xff,0x03,0xff,0xff,0xff
	.byte	0x04,0xff,0xff,0xff,0x04,0xff,0xff,0xff
	.byte	0x04,0x05,0xff,0xff,0x05,0xff,0xff,0xff
	.byte	0x05,0xff,0xff,0xff,0x05,0x06,0xff,0xff
	.byte	0x06,0xff,0xff,0xff,0x06,0xff,0xff,0xff
	.byte	0x07,0xff,0xff,0xff,0x07,0xff,0xff,0xff
	.byte	0x07,0x08,0xff,0xff,0x08,0xff,0xff,0xff
	.byte	0x08,0xff,0xff,0xff,0x08,0x09,0xff,0xff
	.byte	0x09,0xff,0xff,0xff,0x09,0xff,0xff,0xff
	.byte	0x0a,0xff,0xff,0xff,0x0a,0xff,0xff,0xff
	.byte	0x0a,0x0b,0xff,0xff,0x0b,0xff,0xff,0xff
	.byte	0x0b,0xff,0xff,0xff,0x0b,0x0c,0xff,0xff
	.byte	0x0c,0xff,0xff,0xff,0x0c,0xff,0xff,0xff
	.byte	0x0d,0xff,0xff,0xff,0x0d,0xff,0xff,0xff
	.byte	0x0d,0x0e,0xff,0xff,0x0e,0xff,0xff,0xff
	.byte	0x0e,0xff,0xff,0xff,0x0e,0x0f,0xff,0xff
	.byte	0x0f,0xff,0xff,0xff,0x0f,0xff,0xff,0xff
#ifndef __APPLE__
	.text
	.type	L_mldsa_decode_eta_2_neon_aux, %object
	.size	L_mldsa_decode_eta_2_neon_aux, 48
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_decode_eta_2_neon_aux:
	.long	0x00000000,0xfffffffd,0xfffffffa,0xffffffff
	.long	0xfffffffc,0xfffffff9,0xfffffffe,0xfffffffb
	.long	0x00000007,0x00000007,0x00000002,0x00000002
	.text
	.align	4
	.globl	mldsa_decode_eta_2_neon
	WC_ASM_ATT_HIDDEN(mldsa_decode_eta_2_neon)
	.type	mldsa_decode_eta_2_neon, %function
mldsa_decode_eta_2_neon:
	vpush	{d8-d15}
	adr	r2, L_mldsa_decode_eta_2_neon_idx
	vld1.8	{d2}, [r2]!
	vld1.8	{d3}, [r2]!
	vld1.8	{d4}, [r2]!
	vld1.8	{d5}, [r2]!
	adr	r3, L_mldsa_decode_eta_2_neon_aux
	vld1.8	{d6}, [r3]!
	vld1.8	{d7}, [r3]!
	vld1.8	{d8}, [r3]!
	vld1.8	{d9}, [r3]!
	vld1.8	{d14}, [r3]!
	vld1.8	{d15}, [r3]
	mov	r12, #27
L_mldsa_decode_eta_2_neon_loop:
	vld1.8	{d0-d1}, [r0]
	vtbl.8	d10, {d0-d1}, d2
	vshl.s32	d10, d10, d6
	vand	d10, d10, d14
	vsub.i32	d10, d15, d10
	vtbl.8	d11, {d0-d1}, d3
	vshl.s32	d11, d11, d7
	vand	d11, d11, d14
	vsub.i32	d11, d15, d11
	vtbl.8	d12, {d0-d1}, d4
	vshl.s32	d12, d12, d8
	vand	d12, d12, d14
	vsub.i32	d12, d15, d12
	vtbl.8	d13, {d0-d1}, d5
	vshl.s32	d13, d13, d9
	vand	d13, d13, d14
	vsub.i32	d13, d15, d13
	vst1.8	{d10-d11}, [r1]!
	vst1.8	{d12-d13}, [r1]!
	add	r0, r0, #3
	subs	r12, r12, #1
	bne	L_mldsa_decode_eta_2_neon_loop
	sub	r0, r0, #1
	vld1.8	{d0-d1}, [r0]
	vld1.8	{d2}, [r2]!
	vld1.8	{d3}, [r2]!
	vld1.8	{d4}, [r2]!
	vld1.8	{d5}, [r2]!
	vtbl.8	d10, {d0-d1}, d2
	vshl.s32	d10, d10, d6
	vand	d10, d10, d14
	vsub.i32	d10, d15, d10
	vtbl.8	d11, {d0-d1}, d3
	vshl.s32	d11, d11, d7
	vand	d11, d11, d14
	vsub.i32	d11, d15, d11
	vtbl.8	d12, {d0-d1}, d4
	vshl.s32	d12, d12, d8
	vand	d12, d12, d14
	vsub.i32	d12, d15, d12
	vtbl.8	d13, {d0-d1}, d5
	vshl.s32	d13, d13, d9
	vand	d13, d13, d14
	vsub.i32	d13, d15, d13
	vst1.8	{d10-d11}, [r1]!
	vst1.8	{d12-d13}, [r1]!
	vld1.8	{d2}, [r2]!
	vld1.8	{d3}, [r2]!
	vld1.8	{d4}, [r2]!
	vld1.8	{d5}, [r2]!
	vtbl.8	d10, {d0-d1}, d2
	vshl.s32	d10, d10, d6
	vand	d10, d10, d14
	vsub.i32	d10, d15, d10
	vtbl.8	d11, {d0-d1}, d3
	vshl.s32	d11, d11, d7
	vand	d11, d11, d14
	vsub.i32	d11, d15, d11
	vtbl.8	d12, {d0-d1}, d4
	vshl.s32	d12, d12, d8
	vand	d12, d12, d14
	vsub.i32	d12, d15, d12
	vtbl.8	d13, {d0-d1}, d5
	vshl.s32	d13, d13, d9
	vand	d13, d13, d14
	vsub.i32	d13, d15, d13
	vst1.8	{d10-d11}, [r1]!
	vst1.8	{d12-d13}, [r1]!
	vld1.8	{d2}, [r2]!
	vld1.8	{d3}, [r2]!
	vld1.8	{d4}, [r2]!
	vld1.8	{d5}, [r2]!
	vtbl.8	d10, {d0-d1}, d2
	vshl.s32	d10, d10, d6
	vand	d10, d10, d14
	vsub.i32	d10, d15, d10
	vtbl.8	d11, {d0-d1}, d3
	vshl.s32	d11, d11, d7
	vand	d11, d11, d14
	vsub.i32	d11, d15, d11
	vtbl.8	d12, {d0-d1}, d4
	vshl.s32	d12, d12, d8
	vand	d12, d12, d14
	vsub.i32	d12, d15, d12
	vtbl.8	d13, {d0-d1}, d5
	vshl.s32	d13, d13, d9
	vand	d13, d13, d14
	vsub.i32	d13, d15, d13
	vst1.8	{d10-d11}, [r1]!
	vst1.8	{d12-d13}, [r1]!
	vld1.8	{d2}, [r2]!
	vld1.8	{d3}, [r2]!
	vld1.8	{d4}, [r2]!
	vld1.8	{d5}, [r2]!
	vtbl.8	d10, {d0-d1}, d2
	vshl.s32	d10, d10, d6
	vand	d10, d10, d14
	vsub.i32	d10, d15, d10
	vtbl.8	d11, {d0-d1}, d3
	vshl.s32	d11, d11, d7
	vand	d11, d11, d14
	vsub.i32	d11, d15, d11
	vtbl.8	d12, {d0-d1}, d4
	vshl.s32	d12, d12, d8
	vand	d12, d12, d14
	vsub.i32	d12, d15, d12
	vtbl.8	d13, {d0-d1}, d5
	vshl.s32	d13, d13, d9
	vand	d13, d13, d14
	vsub.i32	d13, d15, d13
	vst1.8	{d10-d11}, [r1]!
	vst1.8	{d12-d13}, [r1]!
	vld1.8	{d2}, [r2]!
	vld1.8	{d3}, [r2]!
	vld1.8	{d4}, [r2]!
	vld1.8	{d5}, [r2]!
	vtbl.8	d10, {d0-d1}, d2
	vshl.s32	d10, d10, d6
	vand	d10, d10, d14
	vsub.i32	d10, d15, d10
	vtbl.8	d11, {d0-d1}, d3
	vshl.s32	d11, d11, d7
	vand	d11, d11, d14
	vsub.i32	d11, d15, d11
	vtbl.8	d12, {d0-d1}, d4
	vshl.s32	d12, d12, d8
	vand	d12, d12, d14
	vsub.i32	d12, d15, d12
	vtbl.8	d13, {d0-d1}, d5
	vshl.s32	d13, d13, d9
	vand	d13, d13, d14
	vsub.i32	d13, d15, d13
	vst1.8	{d10-d11}, [r1]!
	vst1.8	{d12-d13}, [r1]!
	vpop	{d8-d15}
	bx	lr
	.size	mldsa_decode_eta_2_neon,.-mldsa_decode_eta_2_neon
#ifndef __APPLE__
	.text
	.type	L_mldsa_decode_eta_4_neon_idx, %object
	.size	L_mldsa_decode_eta_4_neon_idx, 128
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 4-byte aligned, 32-bit aligned
#ifndef __APPLE__
	.align	2
#else
	.p2align	2
#endif /* __APPLE__ */
L_mldsa_decode_eta_4_neon_idx:
	.byte	0x00,0xff,0xff,0xff,0x00,0xff,0xff,0xff
	.byte	0x01,0xff,0xff,0xff,0x01,0xff,0xff,0xff
	.byte	0x02,0xff,0xff,0xff,0x02,0xff,0xff,0xff
	.byte	0x03,0xff,0xff,0xff,0x03,0xff,0xff,0xff
	.byte	0x04,0xff,0xff,0xff,0x04,0xff,0xff,0xff
	.byte	0x05,0xff,0xff,0xff,0x05,0xff,0xff,0xff
	.byte	0x06,0xff,0xff,0xff,0x06,0xff,0xff,0xff
	.byte	0x07,0xff,0xff,0xff,0x07,0xff,0xff,0xff
	.byte	0x08,0xff,0xff,0xff,0x08,0xff,0xff,0xff
	.byte	0x09,0xff,0xff,0xff,0x09,0xff,0xff,0xff
	.byte	0x0a,0xff,0xff,0xff,0x0a,0xff,0xff,0xff
	.byte	0x0b,0xff,0xff,0xff,0x0b,0xff,0xff,0xff
	.byte	0x0c,0xff,0xff,0xff,0x0c,0xff,0xff,0xff
	.byte	0x0d,0xff,0xff,0xff,0x0d,0xff,0xff,0xff
	.byte	0x0e,0xff,0xff,0xff,0x0e,0xff,0xff,0xff
	.byte	0x0f,0xff,0xff,0xff,0x0f,0xff,0xff,0xff
#ifndef __APPLE__
	.text
	.type	L_mldsa_decode_eta_4_neon_aux, %object
	.size	L_mldsa_decode_eta_4_neon_aux, 32
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_decode_eta_4_neon_aux:
	.long	0x00000000,0xfffffffc,0x00000000,0xfffffffc
	.long	0x0000000f,0x0000000f,0x00000004,0x00000004
	.text
	.align	4
	.globl	mldsa_decode_eta_4_neon
	WC_ASM_ATT_HIDDEN(mldsa_decode_eta_4_neon)
	.type	mldsa_decode_eta_4_neon, %function
mldsa_decode_eta_4_neon:
	vpush	{d8-d9}
	adr	r2, L_mldsa_decode_eta_4_neon_idx
	vld1.8	{d2}, [r2]!
	vld1.8	{d3}, [r2]!
	adr	r3, L_mldsa_decode_eta_4_neon_aux
	vld1.8	{d4}, [r3]!
	vld1.8	{d5}, [r3]!
	vld1.8	{d8}, [r3]!
	vld1.8	{d9}, [r3]
	mov	r12, #57
L_mldsa_decode_eta_4_neon_loop:
	vld1.8	{d0-d1}, [r0]
	vtbl.8	d6, {d0-d1}, d2
	vshl.s32	d6, d6, d4
	vand	d6, d6, d8
	vsub.i32	d6, d9, d6
	vtbl.8	d7, {d0-d1}, d3
	vshl.s32	d7, d7, d5
	vand	d7, d7, d8
	vsub.i32	d7, d9, d7
	vst1.8	{d6-d7}, [r1]!
	add	r0, r0, #2
	subs	r12, r12, #1
	bne	L_mldsa_decode_eta_4_neon_loop
	sub	r0, r0, #2
	vld1.8	{d0-d1}, [r0]
	vld1.8	{d2}, [r2]!
	vld1.8	{d3}, [r2]!
	vtbl.8	d6, {d0-d1}, d2
	vshl.s32	d6, d6, d4
	vand	d6, d6, d8
	vsub.i32	d6, d9, d6
	vtbl.8	d7, {d0-d1}, d3
	vshl.s32	d7, d7, d5
	vand	d7, d7, d8
	vsub.i32	d7, d9, d7
	vst1.8	{d6-d7}, [r1]!
	vld1.8	{d2}, [r2]!
	vld1.8	{d3}, [r2]!
	vtbl.8	d6, {d0-d1}, d2
	vshl.s32	d6, d6, d4
	vand	d6, d6, d8
	vsub.i32	d6, d9, d6
	vtbl.8	d7, {d0-d1}, d3
	vshl.s32	d7, d7, d5
	vand	d7, d7, d8
	vsub.i32	d7, d9, d7
	vst1.8	{d6-d7}, [r1]!
	vld1.8	{d2}, [r2]!
	vld1.8	{d3}, [r2]!
	vtbl.8	d6, {d0-d1}, d2
	vshl.s32	d6, d6, d4
	vand	d6, d6, d8
	vsub.i32	d6, d9, d6
	vtbl.8	d7, {d0-d1}, d3
	vshl.s32	d7, d7, d5
	vand	d7, d7, d8
	vsub.i32	d7, d9, d7
	vst1.8	{d6-d7}, [r1]!
	vld1.8	{d2}, [r2]!
	vld1.8	{d3}, [r2]!
	vtbl.8	d6, {d0-d1}, d2
	vshl.s32	d6, d6, d4
	vand	d6, d6, d8
	vsub.i32	d6, d9, d6
	vtbl.8	d7, {d0-d1}, d3
	vshl.s32	d7, d7, d5
	vand	d7, d7, d8
	vsub.i32	d7, d9, d7
	vst1.8	{d6-d7}, [r1]!
	vld1.8	{d2}, [r2]!
	vld1.8	{d3}, [r2]!
	vtbl.8	d6, {d0-d1}, d2
	vshl.s32	d6, d6, d4
	vand	d6, d6, d8
	vsub.i32	d6, d9, d6
	vtbl.8	d7, {d0-d1}, d3
	vshl.s32	d7, d7, d5
	vand	d7, d7, d8
	vsub.i32	d7, d9, d7
	vst1.8	{d6-d7}, [r1]!
	vld1.8	{d2}, [r2]!
	vld1.8	{d3}, [r2]!
	vtbl.8	d6, {d0-d1}, d2
	vshl.s32	d6, d6, d4
	vand	d6, d6, d8
	vsub.i32	d6, d9, d6
	vtbl.8	d7, {d0-d1}, d3
	vshl.s32	d7, d7, d5
	vand	d7, d7, d8
	vsub.i32	d7, d9, d7
	vst1.8	{d6-d7}, [r1]!
	vld1.8	{d2}, [r2]!
	vld1.8	{d3}, [r2]!
	vtbl.8	d6, {d0-d1}, d2
	vshl.s32	d6, d6, d4
	vand	d6, d6, d8
	vsub.i32	d6, d9, d6
	vtbl.8	d7, {d0-d1}, d3
	vshl.s32	d7, d7, d5
	vand	d7, d7, d8
	vsub.i32	d7, d9, d7
	vst1.8	{d6-d7}, [r1]!
	vpop	{d8-d9}
	bx	lr
	.size	mldsa_decode_eta_4_neon,.-mldsa_decode_eta_4_neon
#ifndef __APPLE__
	.text
	.type	L_mldsa_decode_t1_neon_idx, %object
	.size	L_mldsa_decode_t1_neon_idx, 64
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 4-byte aligned, 32-bit aligned
#ifndef __APPLE__
	.align	2
#else
	.p2align	2
#endif /* __APPLE__ */
L_mldsa_decode_t1_neon_idx:
	.byte	0x00,0x01,0xff,0xff,0x01,0x02,0xff,0xff
	.byte	0x02,0x03,0xff,0xff,0x03,0x04,0xff,0xff
	.byte	0x01,0x02,0xff,0xff,0x02,0x03,0xff,0xff
	.byte	0x03,0x04,0xff,0xff,0x04,0x05,0xff,0xff
	.byte	0x06,0x07,0xff,0xff,0x07,0x08,0xff,0xff
	.byte	0x08,0x09,0xff,0xff,0x09,0x0a,0xff,0xff
	.byte	0x0b,0x0c,0xff,0xff,0x0c,0x0d,0xff,0xff
	.byte	0x0d,0x0e,0xff,0xff,0x0e,0x0f,0xff,0xff
#ifndef __APPLE__
	.text
	.type	L_mldsa_decode_t1_neon_aux, %object
	.size	L_mldsa_decode_t1_neon_aux, 24
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_decode_t1_neon_aux:
	.long	0x00000000,0xfffffffe,0xfffffffc,0xfffffffa
	.long	0x000003ff,0x000003ff
	.text
	.align	4
	.globl	mldsa_decode_t1_neon
	WC_ASM_ATT_HIDDEN(mldsa_decode_t1_neon)
	.type	mldsa_decode_t1_neon, %function
mldsa_decode_t1_neon:
	vpush	{d8-d9}
	adr	r2, L_mldsa_decode_t1_neon_idx
	vld1.8	{d2}, [r2]!
	vld1.8	{d3}, [r2]!
	adr	r3, L_mldsa_decode_t1_neon_aux
	vld1.8	{d4}, [r3]!
	vld1.8	{d5}, [r3]!
	vld1.8	{d8}, [r3]!
	mov	r12, #61
L_mldsa_decode_t1_neon_loop:
	vld1.8	{d0-d1}, [r0]
	vtbl.8	d6, {d0-d1}, d2
	vshl.s32	d6, d6, d4
	vand	d6, d6, d8
	vshl.i32	d6, d6, #13
	vtbl.8	d7, {d0-d1}, d3
	vshl.s32	d7, d7, d5
	vand	d7, d7, d8
	vshl.i32	d7, d7, #13
	vst1.8	{d6-d7}, [r1]!
	add	r0, r0, #5
	subs	r12, r12, #1
	bne	L_mldsa_decode_t1_neon_loop
	sub	r0, r0, #1
	vld1.8	{d0-d1}, [r0]
	vld1.8	{d2}, [r2]!
	vld1.8	{d3}, [r2]!
	vtbl.8	d6, {d0-d1}, d2
	vshl.s32	d6, d6, d4
	vand	d6, d6, d8
	vshl.i32	d6, d6, #13
	vtbl.8	d7, {d0-d1}, d3
	vshl.s32	d7, d7, d5
	vand	d7, d7, d8
	vshl.i32	d7, d7, #13
	vst1.8	{d6-d7}, [r1]!
	vld1.8	{d2}, [r2]!
	vld1.8	{d3}, [r2]!
	vtbl.8	d6, {d0-d1}, d2
	vshl.s32	d6, d6, d4
	vand	d6, d6, d8
	vshl.i32	d6, d6, #13
	vtbl.8	d7, {d0-d1}, d3
	vshl.s32	d7, d7, d5
	vand	d7, d7, d8
	vshl.i32	d7, d7, #13
	vst1.8	{d6-d7}, [r1]!
	vld1.8	{d2}, [r2]!
	vld1.8	{d3}, [r2]!
	vtbl.8	d6, {d0-d1}, d2
	vshl.s32	d6, d6, d4
	vand	d6, d6, d8
	vshl.i32	d6, d6, #13
	vtbl.8	d7, {d0-d1}, d3
	vshl.s32	d7, d7, d5
	vand	d7, d7, d8
	vshl.i32	d7, d7, #13
	vst1.8	{d6-d7}, [r1]!
	vpop	{d8-d9}
	bx	lr
	.size	mldsa_decode_t1_neon,.-mldsa_decode_t1_neon
#ifndef __APPLE__
	.text
	.type	L_mldsa_decode_t0_neon_idx, %object
	.size	L_mldsa_decode_t0_neon_idx, 64
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 4-byte aligned, 32-bit aligned
#ifndef __APPLE__
	.align	2
#else
	.p2align	2
#endif /* __APPLE__ */
L_mldsa_decode_t0_neon_idx:
	.byte	0x00,0x01,0xff,0xff,0x01,0x02,0x03,0xff
	.byte	0x03,0x04,0xff,0xff,0x04,0x05,0x06,0xff
	.byte	0x06,0x07,0x08,0xff,0x08,0x09,0xff,0xff
	.byte	0x09,0x0a,0x0b,0xff,0x0b,0x0c,0xff,0xff
	.byte	0x03,0x04,0xff,0xff,0x04,0x05,0x06,0xff
	.byte	0x06,0x07,0xff,0xff,0x07,0x08,0x09,0xff
	.byte	0x09,0x0a,0x0b,0xff,0x0b,0x0c,0xff,0xff
	.byte	0x0c,0x0d,0x0e,0xff,0x0e,0x0f,0xff,0xff
#ifndef __APPLE__
	.text
	.type	L_mldsa_decode_t0_neon_aux, %object
	.size	L_mldsa_decode_t0_neon_aux, 48
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_decode_t0_neon_aux:
	.long	0x00000000,0xfffffffb,0xfffffffe,0xfffffff9
	.long	0xfffffffc,0xffffffff,0xfffffffa,0xfffffffd
	.long	0x00001fff,0x00001fff,0x00001000,0x00001000
	.text
	.align	4
	.globl	mldsa_decode_t0_neon
	WC_ASM_ATT_HIDDEN(mldsa_decode_t0_neon)
	.type	mldsa_decode_t0_neon, %function
mldsa_decode_t0_neon:
	vpush	{d8-d15}
	adr	r2, L_mldsa_decode_t0_neon_idx
	vld1.8	{d2}, [r2]!
	vld1.8	{d3}, [r2]!
	vld1.8	{d4}, [r2]!
	vld1.8	{d5}, [r2]!
	adr	r3, L_mldsa_decode_t0_neon_aux
	vld1.8	{d6}, [r3]!
	vld1.8	{d7}, [r3]!
	vld1.8	{d8}, [r3]!
	vld1.8	{d9}, [r3]!
	vld1.8	{d14}, [r3]!
	vld1.8	{d15}, [r3]
	mov	r12, #31
L_mldsa_decode_t0_neon_loop:
	vld1.8	{d0-d1}, [r0]
	vtbl.8	d10, {d0-d1}, d2
	vshl.s32	d10, d10, d6
	vand	d10, d10, d14
	vsub.i32	d10, d15, d10
	vtbl.8	d11, {d0-d1}, d3
	vshl.s32	d11, d11, d7
	vand	d11, d11, d14
	vsub.i32	d11, d15, d11
	vtbl.8	d12, {d0-d1}, d4
	vshl.s32	d12, d12, d8
	vand	d12, d12, d14
	vsub.i32	d12, d15, d12
	vtbl.8	d13, {d0-d1}, d5
	vshl.s32	d13, d13, d9
	vand	d13, d13, d14
	vsub.i32	d13, d15, d13
	vst1.8	{d10-d11}, [r1]!
	vst1.8	{d12-d13}, [r1]!
	add	r0, r0, #13
	subs	r12, r12, #1
	bne	L_mldsa_decode_t0_neon_loop
	sub	r0, r0, #3
	vld1.8	{d0-d1}, [r0]
	vld1.8	{d2}, [r2]!
	vld1.8	{d3}, [r2]!
	vld1.8	{d4}, [r2]!
	vld1.8	{d5}, [r2]!
	vtbl.8	d10, {d0-d1}, d2
	vshl.s32	d10, d10, d6
	vand	d10, d10, d14
	vsub.i32	d10, d15, d10
	vtbl.8	d11, {d0-d1}, d3
	vshl.s32	d11, d11, d7
	vand	d11, d11, d14
	vsub.i32	d11, d15, d11
	vtbl.8	d12, {d0-d1}, d4
	vshl.s32	d12, d12, d8
	vand	d12, d12, d14
	vsub.i32	d12, d15, d12
	vtbl.8	d13, {d0-d1}, d5
	vshl.s32	d13, d13, d9
	vand	d13, d13, d14
	vsub.i32	d13, d15, d13
	vst1.8	{d10-d11}, [r1]!
	vst1.8	{d12-d13}, [r1]!
	vpop	{d8-d15}
	bx	lr
	.size	mldsa_decode_t0_neon,.-mldsa_decode_t0_neon
#ifndef __APPLE__
	.text
	.type	L_mldsa_decode_gamma1_17_neon_idx, %object
	.size	L_mldsa_decode_gamma1_17_neon_idx, 32
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 4-byte aligned, 32-bit aligned
#ifndef __APPLE__
	.align	2
#else
	.p2align	2
#endif /* __APPLE__ */
L_mldsa_decode_gamma1_17_neon_idx:
	.byte	0x00,0x01,0x02,0xff,0x02,0x03,0x04,0xff
	.byte	0x04,0x05,0x06,0xff,0x06,0x07,0x08,0xff
	.byte	0x07,0x08,0x09,0xff,0x09,0x0a,0x0b,0xff
	.byte	0x0b,0x0c,0x0d,0xff,0x0d,0x0e,0x0f,0xff
#ifndef __APPLE__
	.text
	.type	L_mldsa_decode_gamma1_17_neon_aux, %object
	.size	L_mldsa_decode_gamma1_17_neon_aux, 32
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_decode_gamma1_17_neon_aux:
	.long	0x00000000,0xfffffffe,0xfffffffc,0xfffffffa
	.long	0x0003ffff,0x0003ffff,0x00020000,0x00020000
	.text
	.align	4
	.globl	mldsa_decode_gamma1_17_neon
	WC_ASM_ATT_HIDDEN(mldsa_decode_gamma1_17_neon)
	.type	mldsa_decode_gamma1_17_neon, %function
mldsa_decode_gamma1_17_neon:
	vpush	{d8-d9}
	adr	r2, L_mldsa_decode_gamma1_17_neon_idx
	vld1.8	{d2}, [r2]!
	vld1.8	{d3}, [r2]!
	adr	r3, L_mldsa_decode_gamma1_17_neon_aux
	vld1.8	{d4}, [r3]!
	vld1.8	{d5}, [r3]!
	vld1.8	{d8}, [r3]!
	vld1.8	{d9}, [r3]
	mov	r12, #63
L_mldsa_decode_gamma1_17_neon_loop:
	vld1.8	{d0-d1}, [r0]
	vtbl.8	d6, {d0-d1}, d2
	vshl.s32	d6, d6, d4
	vand	d6, d6, d8
	vsub.i32	d6, d9, d6
	vtbl.8	d7, {d0-d1}, d3
	vshl.s32	d7, d7, d5
	vand	d7, d7, d8
	vsub.i32	d7, d9, d7
	vst1.8	{d6-d7}, [r1]!
	add	r0, r0, #9
	subs	r12, r12, #1
	bne	L_mldsa_decode_gamma1_17_neon_loop
	sub	r0, r0, #7
	vld1.8	{d0-d1}, [r0]
	vld1.8	{d2}, [r2]!
	vld1.8	{d3}, [r2]!
	vtbl.8	d6, {d0-d1}, d2
	vshl.s32	d6, d6, d4
	vand	d6, d6, d8
	vsub.i32	d6, d9, d6
	vtbl.8	d7, {d0-d1}, d3
	vshl.s32	d7, d7, d5
	vand	d7, d7, d8
	vsub.i32	d7, d9, d7
	vst1.8	{d6-d7}, [r1]!
	vpop	{d8-d9}
	bx	lr
	.size	mldsa_decode_gamma1_17_neon,.-mldsa_decode_gamma1_17_neon
#ifndef __APPLE__
	.text
	.type	L_mldsa_decode_gamma1_19_neon_idx, %object
	.size	L_mldsa_decode_gamma1_19_neon_idx, 32
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 4-byte aligned, 32-bit aligned
#ifndef __APPLE__
	.align	2
#else
	.p2align	2
#endif /* __APPLE__ */
L_mldsa_decode_gamma1_19_neon_idx:
	.byte	0x00,0x01,0x02,0xff,0x02,0x03,0x04,0xff
	.byte	0x05,0x06,0x07,0xff,0x07,0x08,0x09,0xff
	.byte	0x06,0x07,0x08,0xff,0x08,0x09,0x0a,0xff
	.byte	0x0b,0x0c,0x0d,0xff,0x0d,0x0e,0x0f,0xff
#ifndef __APPLE__
	.text
	.type	L_mldsa_decode_gamma1_19_neon_aux, %object
	.size	L_mldsa_decode_gamma1_19_neon_aux, 32
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_decode_gamma1_19_neon_aux:
	.long	0x00000000,0xfffffffc,0x00000000,0xfffffffc
	.long	0x000fffff,0x000fffff,0x00080000,0x00080000
	.text
	.align	4
	.globl	mldsa_decode_gamma1_19_neon
	WC_ASM_ATT_HIDDEN(mldsa_decode_gamma1_19_neon)
	.type	mldsa_decode_gamma1_19_neon, %function
mldsa_decode_gamma1_19_neon:
	vpush	{d8-d9}
	adr	r2, L_mldsa_decode_gamma1_19_neon_idx
	vld1.8	{d2}, [r2]!
	vld1.8	{d3}, [r2]!
	adr	r3, L_mldsa_decode_gamma1_19_neon_aux
	vld1.8	{d4}, [r3]!
	vld1.8	{d5}, [r3]!
	vld1.8	{d8}, [r3]!
	vld1.8	{d9}, [r3]
	mov	r12, #63
L_mldsa_decode_gamma1_19_neon_loop:
	vld1.8	{d0-d1}, [r0]
	vtbl.8	d6, {d0-d1}, d2
	vshl.s32	d6, d6, d4
	vand	d6, d6, d8
	vsub.i32	d6, d9, d6
	vtbl.8	d7, {d0-d1}, d3
	vshl.s32	d7, d7, d5
	vand	d7, d7, d8
	vsub.i32	d7, d9, d7
	vst1.8	{d6-d7}, [r1]!
	add	r0, r0, #10
	subs	r12, r12, #1
	bne	L_mldsa_decode_gamma1_19_neon_loop
	sub	r0, r0, #6
	vld1.8	{d0-d1}, [r0]
	vld1.8	{d2}, [r2]!
	vld1.8	{d3}, [r2]!
	vtbl.8	d6, {d0-d1}, d2
	vshl.s32	d6, d6, d4
	vand	d6, d6, d8
	vsub.i32	d6, d9, d6
	vtbl.8	d7, {d0-d1}, d3
	vshl.s32	d7, d7, d5
	vand	d7, d7, d8
	vsub.i32	d7, d9, d7
	vst1.8	{d6-d7}, [r1]!
	vpop	{d8-d9}
	bx	lr
	.size	mldsa_decode_gamma1_19_neon,.-mldsa_decode_gamma1_19_neon
#ifndef __APPLE__
	.text
	.type	L_mldsa_encode_w1_88_neon_idx, %object
	.size	L_mldsa_encode_w1_88_neon_idx, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 4-byte aligned, 32-bit aligned
#ifndef __APPLE__
	.align	2
#else
	.p2align	2
#endif /* __APPLE__ */
L_mldsa_encode_w1_88_neon_idx:
	.byte	0x00,0x01,0x02,0x04,0x05,0x06,0x08,0x09
	.byte	0x0a,0x0c,0x0d,0x0e,0xff,0xff,0xff,0xff
	.text
	.align	4
	.globl	mldsa_encode_w1_88_neon
	WC_ASM_ATT_HIDDEN(mldsa_encode_w1_88_neon)
	.type	mldsa_encode_w1_88_neon, %function
mldsa_encode_w1_88_neon:
	vpush	{d8-d11}
	adr	r2, L_mldsa_encode_w1_88_neon_idx
	vld1.8	{d8}, [r2]!
	vld1.8	{d9}, [r2]
	mov	r3, #16
L_mldsa_encode_w1_88_neon_loop:
	vld1.8	{q0}, [r0]!
	vld1.8	{q1}, [r0]!
	vld1.8	{q2}, [r0]!
	vld1.8	{q3}, [r0]!
	vuzp.32	q0, q1
	vsli.32	q0, q1, #6
	vuzp.32	q2, q3
	vsli.32	q2, q3, #6
	vuzp.32	q0, q2
	vsli.32	q0, q2, #12
	vtbl.8	d10, {d0-d1}, d8
	vtbl.8	d11, {d0-d1}, d9
	vst1.8	{d10}, [r1]!
	vmov.32	r12, d11[0]
	str	r12, [r1], #4
	subs	r3, r3, #1
	bne	L_mldsa_encode_w1_88_neon_loop
	vpop	{d8-d11}
	bx	lr
	.size	mldsa_encode_w1_88_neon,.-mldsa_encode_w1_88_neon
#ifndef __APPLE__
	.text
	.type	L_mldsa_encode_w1_32_neon_idx, %object
	.size	L_mldsa_encode_w1_32_neon_idx, 8
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 4-byte aligned, 32-bit aligned
#ifndef __APPLE__
	.align	2
#else
	.p2align	2
#endif /* __APPLE__ */
L_mldsa_encode_w1_32_neon_idx:
	.byte	0x00,0x04,0x08,0x0c,0x10,0x14,0x18,0x1c
	.text
	.align	4
	.globl	mldsa_encode_w1_32_neon
	WC_ASM_ATT_HIDDEN(mldsa_encode_w1_32_neon)
	.type	mldsa_encode_w1_32_neon, %function
mldsa_encode_w1_32_neon:
	vpush	{d8-d11}
	adr	r2, L_mldsa_encode_w1_32_neon_idx
	vld1.8	{d8}, [r2]!
	mov	r3, #16
L_mldsa_encode_w1_32_neon_loop:
	vld1.8	{q0}, [r0]!
	vld1.8	{q1}, [r0]!
	vld1.8	{q2}, [r0]!
	vld1.8	{q3}, [r0]!
	vuzp.32	q0, q1
	vsli.32	q0, q1, #4
	vuzp.32	q2, q3
	vsli.32	q2, q3, #4
	vmov	q1, q2
	vtbl.8	d10, {d0-d3}, d8
	vst1.8	{d10}, [r1]!
	subs	r3, r3, #1
	bne	L_mldsa_encode_w1_32_neon_loop
	vpop	{d8-d11}
	bx	lr
	.size	mldsa_encode_w1_32_neon,.-mldsa_encode_w1_32_neon
#ifndef __APPLE__
	.text
	.type	L_mldsa_encode_gamma1_17_neon_idx, %object
	.size	L_mldsa_encode_gamma1_17_neon_idx, 32
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 4-byte aligned, 32-bit aligned
#ifndef __APPLE__
	.align	2
#else
	.p2align	2
#endif /* __APPLE__ */
L_mldsa_encode_gamma1_17_neon_idx:
	.byte	0x00,0x01,0x02,0xff,0x08,0x09,0x0a,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0x04,0x05,0x06,0xff,0x0c,0x0d
	.byte	0x0e,0xff,0xff,0xff,0xff,0xff,0xff,0xff
#ifndef __APPLE__
	.text
	.type	L_mldsa_encode_gamma1_17_neon_aux, %object
	.size	L_mldsa_encode_gamma1_17_neon_aux, 32
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_encode_gamma1_17_neon_aux:
	.long	0x00000000,0x00000002,0x00000004,0x00000006
	.long	0x00020000,0x00020000,0x00020000,0x00020000
	.text
	.align	4
	.globl	mldsa_encode_gamma1_17_neon
	WC_ASM_ATT_HIDDEN(mldsa_encode_gamma1_17_neon)
	.type	mldsa_encode_gamma1_17_neon, %function
mldsa_encode_gamma1_17_neon:
	vpush	{d8-d13}
	adr	r2, L_mldsa_encode_gamma1_17_neon_idx
	vld1.8	{d6}, [r2]!
	vld1.8	{d7}, [r2]!
	vld1.8	{d8}, [r2]!
	vld1.8	{d9}, [r2]!
	adr	r2, L_mldsa_encode_gamma1_17_neon_aux
	vld1.8	{q1}, [r2]!
	vld1.8	{q2}, [r2]
	mov	r3, #0x40
L_mldsa_encode_gamma1_17_neon_loop:
	vld1.8	{q0}, [r0]!
	vsub.i32	q0, q2, q0
	vshl.s32	q0, q0, q1
	vtbl.8	d10, {d0-d1}, d6
	vtbl.8	d11, {d0-d1}, d7
	vtbl.8	d12, {d0-d1}, d8
	vtbl.8	d13, {d0-d1}, d9
	vorr	d10, d10, d12
	vorr	d11, d11, d13
	vst1.8	{d10}, [r1]!
	vmov.32	r12, d11[0]
	strb	r12, [r1], #1
	subs	r3, r3, #1
	bne	L_mldsa_encode_gamma1_17_neon_loop
	vpop	{d8-d13}
	bx	lr
	.size	mldsa_encode_gamma1_17_neon,.-mldsa_encode_gamma1_17_neon
#ifndef __APPLE__
	.text
	.type	L_mldsa_encode_gamma1_19_neon_idx, %object
	.size	L_mldsa_encode_gamma1_19_neon_idx, 32
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 4-byte aligned, 32-bit aligned
#ifndef __APPLE__
	.align	2
#else
	.p2align	2
#endif /* __APPLE__ */
L_mldsa_encode_gamma1_19_neon_idx:
	.byte	0x00,0x01,0x02,0xff,0xff,0x08,0x09,0x0a
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0x04,0x05,0x06,0xff,0xff,0x0c
	.byte	0x0d,0x0e,0xff,0xff,0xff,0xff,0xff,0xff
#ifndef __APPLE__
	.text
	.type	L_mldsa_encode_gamma1_19_neon_aux, %object
	.size	L_mldsa_encode_gamma1_19_neon_aux, 32
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_encode_gamma1_19_neon_aux:
	.long	0x00000000,0x00000004,0x00000000,0x00000004
	.long	0x00080000,0x00080000,0x00080000,0x00080000
	.text
	.align	4
	.globl	mldsa_encode_gamma1_19_neon
	WC_ASM_ATT_HIDDEN(mldsa_encode_gamma1_19_neon)
	.type	mldsa_encode_gamma1_19_neon, %function
mldsa_encode_gamma1_19_neon:
	vpush	{d8-d13}
	adr	r2, L_mldsa_encode_gamma1_19_neon_idx
	vld1.8	{d6}, [r2]!
	vld1.8	{d7}, [r2]!
	vld1.8	{d8}, [r2]!
	vld1.8	{d9}, [r2]!
	adr	r2, L_mldsa_encode_gamma1_19_neon_aux
	vld1.8	{q1}, [r2]!
	vld1.8	{q2}, [r2]
	mov	r3, #0x40
L_mldsa_encode_gamma1_19_neon_loop:
	vld1.8	{q0}, [r0]!
	vsub.i32	q0, q2, q0
	vshl.s32	q0, q0, q1
	vtbl.8	d10, {d0-d1}, d6
	vtbl.8	d11, {d0-d1}, d7
	vtbl.8	d12, {d0-d1}, d8
	vtbl.8	d13, {d0-d1}, d9
	vorr	d10, d10, d12
	vorr	d11, d11, d13
	vst1.8	{d10}, [r1]!
	vmov.32	r12, d11[0]
	strh	r12, [r1], #2
	subs	r3, r3, #1
	bne	L_mldsa_encode_gamma1_19_neon_loop
	vpop	{d8-d13}
	bx	lr
	.size	mldsa_encode_gamma1_19_neon,.-mldsa_encode_gamma1_19_neon
#ifndef __APPLE__
	.text
	.type	L_mldsa_mul_vec_4_neon_q, %object
	.size	L_mldsa_mul_vec_4_neon_q, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_mul_vec_4_neon_q:
	.long	0x007fe001,0x007fe001,0x03802001,0x03802001
	.text
	.align	4
	.globl	mldsa_mul_vec_4_neon
	WC_ASM_ATT_HIDDEN(mldsa_mul_vec_4_neon)
	.type	mldsa_mul_vec_4_neon, %function
mldsa_mul_vec_4_neon:
	push	{lr}
	vpush	{d8-d13}
	adr	r3, L_mldsa_mul_vec_4_neon_q
	vld1.8	{q0}, [r3]
	vdup.32	q1, d1[0]
	mov	lr, #0x40
L_mldsa_mul_vec_4_neon_loop:
	vld1.8	{q2}, [r1]
	vld1.8	{q3}, [r2]
	vmull.s32	q4, d4, d6
	vmull.s32	q5, d5, d7
	add	r12, r1, #0x400
	vld1.8	{q2}, [r12]
	add	r12, r2, #0x400
	vld1.8	{q3}, [r12]
	vmlal.s32	q4, d4, d6
	vmlal.s32	q5, d5, d7
	add	r12, r1, #0x800
	vld1.8	{q2}, [r12]
	add	r12, r2, #0x800
	vld1.8	{q3}, [r12]
	vmlal.s32	q4, d4, d6
	vmlal.s32	q5, d5, d7
	add	r12, r1, #0xc00
	vld1.8	{q2}, [r12]
	add	r12, r2, #0xc00
	vld1.8	{q3}, [r12]
	vmlal.s32	q4, d4, d6
	vmlal.s32	q5, d5, d7
	vmovn.i64	d12, q4
	vmovn.i64	d13, q5
	vmul.i32	q6, q6, q1
	vmlsl.s32	q4, d12, d0
	vmlsl.s32	q5, d13, d0
	vshrn.i64	d12, q4, #32
	vshrn.i64	d13, q5, #32
	vst1.8	{q6}, [r0]!
	add	r1, r1, #16
	add	r2, r2, #16
	subs	lr, lr, #1
	bne	L_mldsa_mul_vec_4_neon_loop
	vpop	{d8-d13}
	pop	{pc}
	.size	mldsa_mul_vec_4_neon,.-mldsa_mul_vec_4_neon
#ifndef __APPLE__
	.text
	.type	L_mldsa_mul_vec_5_neon_q, %object
	.size	L_mldsa_mul_vec_5_neon_q, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_mul_vec_5_neon_q:
	.long	0x007fe001,0x007fe001,0x03802001,0x03802001
	.text
	.align	4
	.globl	mldsa_mul_vec_5_neon
	WC_ASM_ATT_HIDDEN(mldsa_mul_vec_5_neon)
	.type	mldsa_mul_vec_5_neon, %function
mldsa_mul_vec_5_neon:
	push	{lr}
	vpush	{d8-d13}
	adr	r3, L_mldsa_mul_vec_5_neon_q
	vld1.8	{q0}, [r3]
	vdup.32	q1, d1[0]
	mov	lr, #0x40
L_mldsa_mul_vec_5_neon_loop:
	vld1.8	{q2}, [r1]
	vld1.8	{q3}, [r2]
	vmull.s32	q4, d4, d6
	vmull.s32	q5, d5, d7
	add	r12, r1, #0x400
	vld1.8	{q2}, [r12]
	add	r12, r2, #0x400
	vld1.8	{q3}, [r12]
	vmlal.s32	q4, d4, d6
	vmlal.s32	q5, d5, d7
	add	r12, r1, #0x800
	vld1.8	{q2}, [r12]
	add	r12, r2, #0x800
	vld1.8	{q3}, [r12]
	vmlal.s32	q4, d4, d6
	vmlal.s32	q5, d5, d7
	add	r12, r1, #0xc00
	vld1.8	{q2}, [r12]
	add	r12, r2, #0xc00
	vld1.8	{q3}, [r12]
	vmlal.s32	q4, d4, d6
	vmlal.s32	q5, d5, d7
	add	r12, r1, #0x1000
	vld1.8	{q2}, [r12]
	add	r12, r2, #0x1000
	vld1.8	{q3}, [r12]
	vmlal.s32	q4, d4, d6
	vmlal.s32	q5, d5, d7
	vmovn.i64	d12, q4
	vmovn.i64	d13, q5
	vmul.i32	q6, q6, q1
	vmlsl.s32	q4, d12, d0
	vmlsl.s32	q5, d13, d0
	vshrn.i64	d12, q4, #32
	vshrn.i64	d13, q5, #32
	vst1.8	{q6}, [r0]!
	add	r1, r1, #16
	add	r2, r2, #16
	subs	lr, lr, #1
	bne	L_mldsa_mul_vec_5_neon_loop
	vpop	{d8-d13}
	pop	{pc}
	.size	mldsa_mul_vec_5_neon,.-mldsa_mul_vec_5_neon
#ifndef __APPLE__
	.text
	.type	L_mldsa_mul_vec_7_neon_q, %object
	.size	L_mldsa_mul_vec_7_neon_q, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_mul_vec_7_neon_q:
	.long	0x007fe001,0x007fe001,0x03802001,0x03802001
	.text
	.align	4
	.globl	mldsa_mul_vec_7_neon
	WC_ASM_ATT_HIDDEN(mldsa_mul_vec_7_neon)
	.type	mldsa_mul_vec_7_neon, %function
mldsa_mul_vec_7_neon:
	push	{lr}
	vpush	{d8-d13}
	adr	r3, L_mldsa_mul_vec_7_neon_q
	vld1.8	{q0}, [r3]
	vdup.32	q1, d1[0]
	mov	lr, #0x40
L_mldsa_mul_vec_7_neon_loop:
	vld1.8	{q2}, [r1]
	vld1.8	{q3}, [r2]
	vmull.s32	q4, d4, d6
	vmull.s32	q5, d5, d7
	add	r12, r1, #0x400
	vld1.8	{q2}, [r12]
	add	r12, r2, #0x400
	vld1.8	{q3}, [r12]
	vmlal.s32	q4, d4, d6
	vmlal.s32	q5, d5, d7
	add	r12, r1, #0x800
	vld1.8	{q2}, [r12]
	add	r12, r2, #0x800
	vld1.8	{q3}, [r12]
	vmlal.s32	q4, d4, d6
	vmlal.s32	q5, d5, d7
	add	r12, r1, #0xc00
	vld1.8	{q2}, [r12]
	add	r12, r2, #0xc00
	vld1.8	{q3}, [r12]
	vmlal.s32	q4, d4, d6
	vmlal.s32	q5, d5, d7
	add	r12, r1, #0x1000
	vld1.8	{q2}, [r12]
	add	r12, r2, #0x1000
	vld1.8	{q3}, [r12]
	vmlal.s32	q4, d4, d6
	vmlal.s32	q5, d5, d7
	add	r12, r1, #0x1400
	vld1.8	{q2}, [r12]
	add	r12, r2, #0x1400
	vld1.8	{q3}, [r12]
	vmlal.s32	q4, d4, d6
	vmlal.s32	q5, d5, d7
	add	r12, r1, #0x1800
	vld1.8	{q2}, [r12]
	add	r12, r2, #0x1800
	vld1.8	{q3}, [r12]
	vmlal.s32	q4, d4, d6
	vmlal.s32	q5, d5, d7
	vmovn.i64	d12, q4
	vmovn.i64	d13, q5
	vmul.i32	q6, q6, q1
	vmlsl.s32	q4, d12, d0
	vmlsl.s32	q5, d13, d0
	vshrn.i64	d12, q4, #32
	vshrn.i64	d13, q5, #32
	vst1.8	{q6}, [r0]!
	add	r1, r1, #16
	add	r2, r2, #16
	subs	lr, lr, #1
	bne	L_mldsa_mul_vec_7_neon_loop
	vpop	{d8-d13}
	pop	{pc}
	.size	mldsa_mul_vec_7_neon,.-mldsa_mul_vec_7_neon
#ifndef __APPLE__
	.text
	.type	L_mldsa_extract_coeffs_eta2_neon_map, %object
	.size	L_mldsa_extract_coeffs_eta2_neon_map, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 4-byte aligned, 32-bit aligned
#ifndef __APPLE__
	.align	2
#else
	.p2align	2
#endif /* __APPLE__ */
L_mldsa_extract_coeffs_eta2_neon_map:
	.byte	0x02,0x01,0x00,0xff,0xfe,0x02,0x01,0x00
	.byte	0xff,0xfe,0x02,0x01,0x00,0xff,0xfe,0x00
#ifndef __APPLE__
	.text
	.type	L_mldsa_extract_coeffs_eta2_neon_aux, %object
	.size	L_mldsa_extract_coeffs_eta2_neon_aux, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 4-byte aligned, 32-bit aligned
#ifndef __APPLE__
	.align	2
#else
	.p2align	2
#endif /* __APPLE__ */
L_mldsa_extract_coeffs_eta2_neon_aux:
	.byte	0x0f,0x0f,0x0f,0x0f,0x0f,0x0f,0x0f,0x0f
	.byte	0x0f,0x0f,0x0f,0x0f,0x0f,0x0f,0x0f,0x0f
#ifndef __APPLE__
	.text
	.type	L_mldsa_extract_coeffs_eta2_neon_bits, %object
	.size	L_mldsa_extract_coeffs_eta2_neon_bits, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_extract_coeffs_eta2_neon_bits:
	.long	0x00000001,0x00000002,0x00000004,0x00000008
#ifndef __APPLE__
	.text
	.type	L_mldsa_extract_coeffs_eta2_neon_idx, %object
	.size	L_mldsa_extract_coeffs_eta2_neon_idx, 256
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 4-byte aligned, 32-bit aligned
#ifndef __APPLE__
	.align	2
#else
	.p2align	2
#endif /* __APPLE__ */
L_mldsa_extract_coeffs_eta2_neon_idx:
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x04,0x05,0x06,0x07,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x08,0x09,0x0a,0x0b,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x08,0x09,0x0a,0x0b
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07
	.byte	0x08,0x09,0x0a,0x0b,0xff,0xff,0xff,0xff
	.byte	0x0c,0x0d,0x0e,0x0f,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x0c,0x0d,0x0e,0x0f
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x04,0x05,0x06,0x07,0x0c,0x0d,0x0e,0x0f
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07
	.byte	0x0c,0x0d,0x0e,0x0f,0xff,0xff,0xff,0xff
	.byte	0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x08,0x09,0x0a,0x0b
	.byte	0x0c,0x0d,0x0e,0x0f,0xff,0xff,0xff,0xff
	.byte	0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b
	.byte	0x0c,0x0d,0x0e,0x0f,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07
	.byte	0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
	.text
	.align	4
	.globl	mldsa_extract_coeffs_eta2_neon
	WC_ASM_ATT_HIDDEN(mldsa_extract_coeffs_eta2_neon)
	.type	mldsa_extract_coeffs_eta2_neon, %function
mldsa_extract_coeffs_eta2_neon:
	push	{r4, r5, r6, r7, r8, lr}
	vpush	{d8-d15}
	adr	r12, L_mldsa_extract_coeffs_eta2_neon_map
	vld1.8	{q0}, [r12]
	adr	lr, L_mldsa_extract_coeffs_eta2_neon_aux
	vld1.8	{q1}, [lr]
	adr	lr, L_mldsa_extract_coeffs_eta2_neon_bits
	vld1.8	{q2}, [lr]
	adr	r4, L_mldsa_extract_coeffs_eta2_neon_idx
	ldr	r5, [r3]
	add	r2, r2, r5, lsl #2
L_mldsa_extract_coeffs_eta2_neon_wide:
	cmp	r1, #8
	blt	L_mldsa_extract_coeffs_eta2_neon_tail
	cmp	r5, #0xf0
	bgt	L_mldsa_extract_coeffs_eta2_neon_tail
	vld1.8	{d6}, [r0]
	vshr.u8	d7, d6, #4
	vmov.i8	q12, #15
	vand	d6, d6, d24
	vzip.8	d6, d7
	vtbl.8	d8, {d0-d1}, d6
	vtbl.8	d9, {d0-d1}, d7
	vcgt.u8	q5, q1, q3
	vmovl.s8	q6, d8
	vmovl.s8	q7, d9
	vmovl.s8	q8, d10
	vmovl.s8	q9, d11
	vmovl.s16	q10, d12
	vmovl.s16	q11, d16
	vshr.u32	q12, q11, #31
	vpadd.u32	d24, d24, d25
	vpadd.u32	d24, d24, d24
	vmov.32	r6, d24[0]
	vand	q12, q11, q2
	vpadd.u32	d24, d24, d25
	vpadd.u32	d24, d24, d24
	vmov.32	r7, d24[0]
	lsl	r7, r7, #4
	add	r7, r7, r4
	vld1.8	{q13}, [r7]
	vtbl.8	d24, {d20-d21}, d26
	vtbl.8	d25, {d20-d21}, d27
	vst1.8	{q12}, [r2]
	add	r2, r2, r6, lsl #2
	add	r5, r5, r6
	vmovl.s16	q10, d13
	vmovl.s16	q11, d17
	vshr.u32	q12, q11, #31
	vpadd.u32	d24, d24, d25
	vpadd.u32	d24, d24, d24
	vmov.32	r6, d24[0]
	vand	q12, q11, q2
	vpadd.u32	d24, d24, d25
	vpadd.u32	d24, d24, d24
	vmov.32	r7, d24[0]
	lsl	r7, r7, #4
	add	r7, r7, r4
	vld1.8	{q13}, [r7]
	vtbl.8	d24, {d20-d21}, d26
	vtbl.8	d25, {d20-d21}, d27
	vst1.8	{q12}, [r2]
	add	r2, r2, r6, lsl #2
	add	r5, r5, r6
	vmovl.s16	q10, d14
	vmovl.s16	q11, d18
	vshr.u32	q12, q11, #31
	vpadd.u32	d24, d24, d25
	vpadd.u32	d24, d24, d24
	vmov.32	r6, d24[0]
	vand	q12, q11, q2
	vpadd.u32	d24, d24, d25
	vpadd.u32	d24, d24, d24
	vmov.32	r7, d24[0]
	lsl	r7, r7, #4
	add	r7, r7, r4
	vld1.8	{q13}, [r7]
	vtbl.8	d24, {d20-d21}, d26
	vtbl.8	d25, {d20-d21}, d27
	vst1.8	{q12}, [r2]
	add	r2, r2, r6, lsl #2
	add	r5, r5, r6
	vmovl.s16	q10, d15
	vmovl.s16	q11, d19
	vshr.u32	q12, q11, #31
	vpadd.u32	d24, d24, d25
	vpadd.u32	d24, d24, d24
	vmov.32	r6, d24[0]
	vand	q12, q11, q2
	vpadd.u32	d24, d24, d25
	vpadd.u32	d24, d24, d24
	vmov.32	r7, d24[0]
	lsl	r7, r7, #4
	add	r7, r7, r4
	vld1.8	{q13}, [r7]
	vtbl.8	d24, {d20-d21}, d26
	vtbl.8	d25, {d20-d21}, d27
	vst1.8	{q12}, [r2]
	add	r2, r2, r6, lsl #2
	add	r5, r5, r6
	add	r0, r0, #8
	sub	r1, r1, #8
	b	L_mldsa_extract_coeffs_eta2_neon_wide
L_mldsa_extract_coeffs_eta2_neon_tail:
	cmp	r1, #0
	beq	L_mldsa_extract_coeffs_eta2_neon_done
	cmp	r5, #0x100
	beq	L_mldsa_extract_coeffs_eta2_neon_done
	ldrb	r8, [r0], #1
	sub	r1, r1, #1
	and	r6, r8, #15
	cmp	r6, #15
	bcs	L_mldsa_extract_coeffs_eta2_neon_skip_lo
	add	lr, r12, r6
	ldrsb	r6, [lr]
	str	r6, [r2], #4
	add	r5, r5, #1
	cmp	r5, #0x100
	beq	L_mldsa_extract_coeffs_eta2_neon_done
L_mldsa_extract_coeffs_eta2_neon_skip_lo:
	lsr	r6, r8, #4
	cmp	r6, #15
	bcs	L_mldsa_extract_coeffs_eta2_neon_skip_hi
	add	lr, r12, r6
	ldrsb	r6, [lr]
	str	r6, [r2], #4
	add	r5, r5, #1
L_mldsa_extract_coeffs_eta2_neon_skip_hi:
	b	L_mldsa_extract_coeffs_eta2_neon_tail
L_mldsa_extract_coeffs_eta2_neon_done:
	str	r5, [r3]
	vpop	{d8-d15}
	pop	{r4, r5, r6, r7, r8, pc}
	.size	mldsa_extract_coeffs_eta2_neon,.-mldsa_extract_coeffs_eta2_neon
#ifndef __APPLE__
	.text
	.type	L_mldsa_extract_coeffs_eta4_neon_map, %object
	.size	L_mldsa_extract_coeffs_eta4_neon_map, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 4-byte aligned, 32-bit aligned
#ifndef __APPLE__
	.align	2
#else
	.p2align	2
#endif /* __APPLE__ */
L_mldsa_extract_coeffs_eta4_neon_map:
	.byte	0x04,0x03,0x02,0x01,0x00,0xff,0xfe,0xfd
	.byte	0xfc,0x00,0x00,0x00,0x00,0x00,0x00,0x00
#ifndef __APPLE__
	.text
	.type	L_mldsa_extract_coeffs_eta4_neon_aux, %object
	.size	L_mldsa_extract_coeffs_eta4_neon_aux, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 4-byte aligned, 32-bit aligned
#ifndef __APPLE__
	.align	2
#else
	.p2align	2
#endif /* __APPLE__ */
L_mldsa_extract_coeffs_eta4_neon_aux:
	.byte	0x09,0x09,0x09,0x09,0x09,0x09,0x09,0x09
	.byte	0x09,0x09,0x09,0x09,0x09,0x09,0x09,0x09
#ifndef __APPLE__
	.text
	.type	L_mldsa_extract_coeffs_eta4_neon_bits, %object
	.size	L_mldsa_extract_coeffs_eta4_neon_bits, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_extract_coeffs_eta4_neon_bits:
	.long	0x00000001,0x00000002,0x00000004,0x00000008
#ifndef __APPLE__
	.text
	.type	L_mldsa_extract_coeffs_eta4_neon_idx, %object
	.size	L_mldsa_extract_coeffs_eta4_neon_idx, 256
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 4-byte aligned, 32-bit aligned
#ifndef __APPLE__
	.align	2
#else
	.p2align	2
#endif /* __APPLE__ */
L_mldsa_extract_coeffs_eta4_neon_idx:
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x04,0x05,0x06,0x07,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x08,0x09,0x0a,0x0b,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x08,0x09,0x0a,0x0b
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07
	.byte	0x08,0x09,0x0a,0x0b,0xff,0xff,0xff,0xff
	.byte	0x0c,0x0d,0x0e,0x0f,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x0c,0x0d,0x0e,0x0f
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x04,0x05,0x06,0x07,0x0c,0x0d,0x0e,0x0f
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07
	.byte	0x0c,0x0d,0x0e,0x0f,0xff,0xff,0xff,0xff
	.byte	0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x08,0x09,0x0a,0x0b
	.byte	0x0c,0x0d,0x0e,0x0f,0xff,0xff,0xff,0xff
	.byte	0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b
	.byte	0x0c,0x0d,0x0e,0x0f,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07
	.byte	0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
	.text
	.align	4
	.globl	mldsa_extract_coeffs_eta4_neon
	WC_ASM_ATT_HIDDEN(mldsa_extract_coeffs_eta4_neon)
	.type	mldsa_extract_coeffs_eta4_neon, %function
mldsa_extract_coeffs_eta4_neon:
	push	{r4, r5, r6, r7, r8, lr}
	vpush	{d8-d15}
	adr	r12, L_mldsa_extract_coeffs_eta4_neon_map
	vld1.8	{q0}, [r12]
	adr	lr, L_mldsa_extract_coeffs_eta4_neon_aux
	vld1.8	{q1}, [lr]
	adr	lr, L_mldsa_extract_coeffs_eta4_neon_bits
	vld1.8	{q2}, [lr]
	adr	r4, L_mldsa_extract_coeffs_eta4_neon_idx
	ldr	r5, [r3]
	add	r2, r2, r5, lsl #2
L_mldsa_extract_coeffs_eta4_neon_wide:
	cmp	r1, #8
	blt	L_mldsa_extract_coeffs_eta4_neon_tail
	cmp	r5, #0xf0
	bgt	L_mldsa_extract_coeffs_eta4_neon_tail
	vld1.8	{d6}, [r0]
	vshr.u8	d7, d6, #4
	vmov.i8	q12, #15
	vand	d6, d6, d24
	vzip.8	d6, d7
	vtbl.8	d8, {d0-d1}, d6
	vtbl.8	d9, {d0-d1}, d7
	vcgt.u8	q5, q1, q3
	vmovl.s8	q6, d8
	vmovl.s8	q7, d9
	vmovl.s8	q8, d10
	vmovl.s8	q9, d11
	vmovl.s16	q10, d12
	vmovl.s16	q11, d16
	vshr.u32	q12, q11, #31
	vpadd.u32	d24, d24, d25
	vpadd.u32	d24, d24, d24
	vmov.32	r6, d24[0]
	vand	q12, q11, q2
	vpadd.u32	d24, d24, d25
	vpadd.u32	d24, d24, d24
	vmov.32	r7, d24[0]
	lsl	r7, r7, #4
	add	r7, r7, r4
	vld1.8	{q13}, [r7]
	vtbl.8	d24, {d20-d21}, d26
	vtbl.8	d25, {d20-d21}, d27
	vst1.8	{q12}, [r2]
	add	r2, r2, r6, lsl #2
	add	r5, r5, r6
	vmovl.s16	q10, d13
	vmovl.s16	q11, d17
	vshr.u32	q12, q11, #31
	vpadd.u32	d24, d24, d25
	vpadd.u32	d24, d24, d24
	vmov.32	r6, d24[0]
	vand	q12, q11, q2
	vpadd.u32	d24, d24, d25
	vpadd.u32	d24, d24, d24
	vmov.32	r7, d24[0]
	lsl	r7, r7, #4
	add	r7, r7, r4
	vld1.8	{q13}, [r7]
	vtbl.8	d24, {d20-d21}, d26
	vtbl.8	d25, {d20-d21}, d27
	vst1.8	{q12}, [r2]
	add	r2, r2, r6, lsl #2
	add	r5, r5, r6
	vmovl.s16	q10, d14
	vmovl.s16	q11, d18
	vshr.u32	q12, q11, #31
	vpadd.u32	d24, d24, d25
	vpadd.u32	d24, d24, d24
	vmov.32	r6, d24[0]
	vand	q12, q11, q2
	vpadd.u32	d24, d24, d25
	vpadd.u32	d24, d24, d24
	vmov.32	r7, d24[0]
	lsl	r7, r7, #4
	add	r7, r7, r4
	vld1.8	{q13}, [r7]
	vtbl.8	d24, {d20-d21}, d26
	vtbl.8	d25, {d20-d21}, d27
	vst1.8	{q12}, [r2]
	add	r2, r2, r6, lsl #2
	add	r5, r5, r6
	vmovl.s16	q10, d15
	vmovl.s16	q11, d19
	vshr.u32	q12, q11, #31
	vpadd.u32	d24, d24, d25
	vpadd.u32	d24, d24, d24
	vmov.32	r6, d24[0]
	vand	q12, q11, q2
	vpadd.u32	d24, d24, d25
	vpadd.u32	d24, d24, d24
	vmov.32	r7, d24[0]
	lsl	r7, r7, #4
	add	r7, r7, r4
	vld1.8	{q13}, [r7]
	vtbl.8	d24, {d20-d21}, d26
	vtbl.8	d25, {d20-d21}, d27
	vst1.8	{q12}, [r2]
	add	r2, r2, r6, lsl #2
	add	r5, r5, r6
	add	r0, r0, #8
	sub	r1, r1, #8
	b	L_mldsa_extract_coeffs_eta4_neon_wide
L_mldsa_extract_coeffs_eta4_neon_tail:
	cmp	r1, #0
	beq	L_mldsa_extract_coeffs_eta4_neon_done
	cmp	r5, #0x100
	beq	L_mldsa_extract_coeffs_eta4_neon_done
	ldrb	r8, [r0], #1
	sub	r1, r1, #1
	and	r6, r8, #15
	cmp	r6, #9
	bcs	L_mldsa_extract_coeffs_eta4_neon_skip_lo
	add	lr, r12, r6
	ldrsb	r6, [lr]
	str	r6, [r2], #4
	add	r5, r5, #1
	cmp	r5, #0x100
	beq	L_mldsa_extract_coeffs_eta4_neon_done
L_mldsa_extract_coeffs_eta4_neon_skip_lo:
	lsr	r6, r8, #4
	cmp	r6, #9
	bcs	L_mldsa_extract_coeffs_eta4_neon_skip_hi
	add	lr, r12, r6
	ldrsb	r6, [lr]
	str	r6, [r2], #4
	add	r5, r5, #1
L_mldsa_extract_coeffs_eta4_neon_skip_hi:
	b	L_mldsa_extract_coeffs_eta4_neon_tail
L_mldsa_extract_coeffs_eta4_neon_done:
	str	r5, [r3]
	vpop	{d8-d15}
	pop	{r4, r5, r6, r7, r8, pc}
	.size	mldsa_extract_coeffs_eta4_neon,.-mldsa_extract_coeffs_eta4_neon
#ifndef __APPLE__
	.text
	.type	L_mldsa_arm32_make_hint_bits, %object
	.size	L_mldsa_arm32_make_hint_bits, 64
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_arm32_make_hint_bits:
	.long	0x00000001,0x00000002,0x00000004,0x00000008
	.long	0x00000010,0x00000020,0x00000040,0x00000080
	.long	0x00000100,0x00000200,0x00000400,0x00000800
	.long	0x00001000,0x00002000,0x00004000,0x00008000
	.text
	.align	4
	.globl	mldsa_make_hint_neon
	WC_ASM_ATT_HIDDEN(mldsa_make_hint_neon)
	.type	mldsa_make_hint_neon, %function
mldsa_make_hint_neon:
	push	{r4, r5, r6, r7, lr}
	vpush	{d8-d15}
	ldr	r12, [sp, #84]
	ldr	lr, [sp, #88]
	vdup.32	q0, lr
	vneg.s32	q1, q0
	adr	r4, L_mldsa_arm32_make_hint_bits
	vld1.8	{q2}, [r4]!
	vld1.8	{q3}, [r4]!
	vld1.8	{q4}, [r4]!
	vld1.8	{q5}, [r4]!
	mov	r5, #0
L_mldsa_arm32_make_hint_loop:
	veor	q11, q11, q11
	vld1.8	{q6}, [r0]!
	vld1.8	{q7}, [r1]!
	vcgt.s32	q8, q6, q0
	vcgt.s32	q9, q1, q6
	vceq.i32	q10, q6, q1
	vceq.i32	q7, q7, #0
	vbic	q10, q10, q7
	vorr	q8, q8, q9
	vorr	q8, q8, q10
	vand	q8, q8, q2
	vorr	q11, q11, q8
	vld1.8	{q6}, [r0]!
	vld1.8	{q7}, [r1]!
	vcgt.s32	q8, q6, q0
	vcgt.s32	q9, q1, q6
	vceq.i32	q10, q6, q1
	vceq.i32	q7, q7, #0
	vbic	q10, q10, q7
	vorr	q8, q8, q9
	vorr	q8, q8, q10
	vand	q8, q8, q3
	vorr	q11, q11, q8
	vld1.8	{q6}, [r0]!
	vld1.8	{q7}, [r1]!
	vcgt.s32	q8, q6, q0
	vcgt.s32	q9, q1, q6
	vceq.i32	q10, q6, q1
	vceq.i32	q7, q7, #0
	vbic	q10, q10, q7
	vorr	q8, q8, q9
	vorr	q8, q8, q10
	vand	q8, q8, q4
	vorr	q11, q11, q8
	vld1.8	{q6}, [r0]!
	vld1.8	{q7}, [r1]!
	vcgt.s32	q8, q6, q0
	vcgt.s32	q9, q1, q6
	vceq.i32	q10, q6, q1
	vceq.i32	q7, q7, #0
	vbic	q10, q10, q7
	vorr	q8, q8, q9
	vorr	q8, q8, q10
	vand	q8, q8, q5
	vorr	q11, q11, q8
	vpadd.u32	d22, d22, d23
	vpadd.u32	d22, d22, d22
	vmov.32	r6, d22[0]
	cmp	r6, #0
	beq	L_mldsa_arm32_make_hint_next
L_mldsa_arm32_make_hint_bit:
	rbit	r7, r6
	clz	r7, r7
	add	r7, r7, r5
	strb	r7, [r2]
	add	r2, r2, #1
	add	r3, r3, #1
	cmp	r3, r12
	bgt	L_mldsa_arm32_make_hint_fail
	sub	r7, r6, #1
	and	r6, r6, r7
	cmp	r6, #0
	bne	L_mldsa_arm32_make_hint_bit
L_mldsa_arm32_make_hint_next:
	add	r5, r5, #16
	cmp	r5, #0x100
	blt	L_mldsa_arm32_make_hint_loop
	mov	r0, r3
	b	L_mldsa_arm32_make_hint_done
L_mldsa_arm32_make_hint_fail:
	mvn	r0, #0
L_mldsa_arm32_make_hint_done:
	vpop	{d8-d15}
	pop	{r4, r5, r6, r7, pc}
	.size	mldsa_make_hint_neon,.-mldsa_make_hint_neon
#ifndef __APPLE__
	.text
	.type	L_mldsa_rej_uniform_neon_aux, %object
	.size	L_mldsa_rej_uniform_neon_aux, 48
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_rej_uniform_neon_aux:
	.long	0x007fffff,0x007fffff,0x007fffff,0x007fffff
	.long	0x007fe001,0x007fe001,0x007fe001,0x007fe001
	.long	0x00000001,0x00000002,0x00000004,0x00000008
#ifndef __APPLE__
	.text
	.type	L_mldsa_rej_uniform_neon_shuffle, %object
	.size	L_mldsa_rej_uniform_neon_shuffle, 32
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 4-byte aligned, 32-bit aligned
#ifndef __APPLE__
	.align	2
#else
	.p2align	2
#endif /* __APPLE__ */
L_mldsa_rej_uniform_neon_shuffle:
	.byte	0x00,0x01,0x02,0xff,0x03,0x04,0x05,0xff
	.byte	0x06,0x07,0x08,0xff,0x09,0x0a,0x0b,0xff
	.byte	0x0c,0x0d,0x0e,0xff,0x0f,0x10,0x11,0xff
	.byte	0x12,0x13,0x14,0xff,0x15,0x16,0x17,0xff
#ifndef __APPLE__
	.text
	.type	L_mldsa_rej_uniform_neon_indices, %object
	.size	L_mldsa_rej_uniform_neon_indices, 256
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 4-byte aligned, 32-bit aligned
#ifndef __APPLE__
	.align	2
#else
	.p2align	2
#endif /* __APPLE__ */
L_mldsa_rej_uniform_neon_indices:
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x04,0x05,0x06,0x07,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x08,0x09,0x0a,0x0b,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x08,0x09,0x0a,0x0b
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07
	.byte	0x08,0x09,0x0a,0x0b,0xff,0xff,0xff,0xff
	.byte	0x0c,0x0d,0x0e,0x0f,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x0c,0x0d,0x0e,0x0f
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x04,0x05,0x06,0x07,0x0c,0x0d,0x0e,0x0f
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07
	.byte	0x0c,0x0d,0x0e,0x0f,0xff,0xff,0xff,0xff
	.byte	0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x08,0x09,0x0a,0x0b
	.byte	0x0c,0x0d,0x0e,0x0f,0xff,0xff,0xff,0xff
	.byte	0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b
	.byte	0x0c,0x0d,0x0e,0x0f,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07
	.byte	0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
	.text
	.align	4
	.globl	mldsa_rej_uniform_neon
	WC_ASM_ATT_HIDDEN(mldsa_rej_uniform_neon)
	.type	mldsa_rej_uniform_neon, %function
mldsa_rej_uniform_neon:
	push	{r4, r5, r6, r7, r8, lr}
	vpush	{d8-d15}
	adr	r12, L_mldsa_rej_uniform_neon_aux
	vld1.8	{q4}, [r12]!
	vld1.8	{q5}, [r12]!
	vld1.8	{q6}, [r12]
	adr	r12, L_mldsa_rej_uniform_neon_shuffle
	vld1.8	{d3-d6}, [r12]
	adr	lr, L_mldsa_rej_uniform_neon_indices
	vmov.32	r7, d10[0]
	mov	r4, #0
	cmp	r1, #0
	beq	L_mldsa_rej_uniform_neon_done
	cmp	r1, #16
	blt	L_mldsa_rej_uniform_neon_loop_2
L_mldsa_rej_uniform_neon_loop_8:
	vld1.8	{d0-d1}, [r2]!
	vld1.8	{d2}, [r2]!
	vtbl.8	d16, {d0-d2}, d3
	vtbl.8	d17, {d0-d2}, d4
	vand	q7, q8, q4
	vcgt.s32	q8, q5, q7
	vshr.u32	q9, q8, #31
	vpadd.u32	d18, d18, d19
	vpadd.u32	d18, d18, d18
	vmov.32	r5, d18[0]
	vand	q9, q8, q6
	vpadd.u32	d18, d18, d19
	vpadd.u32	d18, d18, d18
	vmov.32	r6, d18[0]
	lsl	r6, r6, #4
	add	r6, r6, lr
	vld1.8	{q10}, [r6]
	vtbl.8	d16, {d14-d15}, d20
	vtbl.8	d17, {d14-d15}, d21
	vst1.8	{q8}, [r0]
	add	r0, r0, r5, lsl #2
	add	r4, r4, r5
	vtbl.8	d16, {d0-d2}, d5
	vtbl.8	d17, {d0-d2}, d6
	vand	q7, q8, q4
	vcgt.s32	q8, q5, q7
	vshr.u32	q9, q8, #31
	vpadd.u32	d18, d18, d19
	vpadd.u32	d18, d18, d18
	vmov.32	r5, d18[0]
	vand	q9, q8, q6
	vpadd.u32	d18, d18, d19
	vpadd.u32	d18, d18, d18
	vmov.32	r6, d18[0]
	lsl	r6, r6, #4
	add	r6, r6, lr
	vld1.8	{q10}, [r6]
	vtbl.8	d16, {d14-d15}, d20
	vtbl.8	d17, {d14-d15}, d21
	vst1.8	{q8}, [r0]
	add	r0, r0, r5, lsl #2
	add	r4, r4, r5
	subs	r3, r3, #24
	beq	L_mldsa_rej_uniform_neon_done
	sub	r5, r1, r4
	subs	r5, r5, #8
	blt	L_mldsa_rej_uniform_neon_loop_2
	b	L_mldsa_rej_uniform_neon_loop_8
L_mldsa_rej_uniform_neon_loop_2:
	subs	r5, r1, r4
	beq	L_mldsa_rej_uniform_neon_done
	subs	r5, r5, #2
	blt	L_mldsa_rej_uniform_neon_loop_lt_2
	ldrb	r12, [r2], #1
	ldrb	r8, [r2], #1
	orr	r12, r12, r8, lsl #8
	ldrb	r8, [r2], #1
	orr	r12, r12, r8, lsl #16
	bic	r12, r12, #0x800000
	ldrb	r6, [r2], #1
	ldrb	r8, [r2], #1
	orr	r6, r6, r8, lsl #8
	ldrb	r8, [r2], #1
	orr	r6, r6, r8, lsl #16
	bic	r6, r6, #0x800000
	str	r12, [r0]
	add	r5, r0, #4
	cmp	r12, r7
	movlo	r0, r5
	addlo	r4, r4, #1
	str	r6, [r0]
	add	r5, r0, #4
	cmp	r6, r7
	movlo	r0, r5
	addlo	r4, r4, #1
	subs	r3, r3, #6
	beq	L_mldsa_rej_uniform_neon_done
	b	L_mldsa_rej_uniform_neon_loop_2
L_mldsa_rej_uniform_neon_loop_lt_2:
	ldrb	r12, [r2], #1
	ldrb	r8, [r2], #1
	orr	r12, r12, r8, lsl #8
	ldrb	r8, [r2], #1
	orr	r12, r12, r8, lsl #16
	bic	r12, r12, #0x800000
	ldrb	r6, [r2], #1
	ldrb	r8, [r2], #1
	orr	r6, r6, r8, lsl #8
	ldrb	r8, [r2], #1
	orr	r6, r6, r8, lsl #16
	bic	r6, r6, #0x800000
	str	r12, [r0]
	add	r5, r0, #4
	cmp	r12, r7
	movlo	r0, r5
	addlo	r4, r4, #1
	cmp	r1, r4
	beq	L_mldsa_rej_uniform_neon_done
	str	r6, [r0]
	add	r5, r0, #4
	cmp	r6, r7
	movlo	r0, r5
	addlo	r4, r4, #1
	cmp	r1, r4
	beq	L_mldsa_rej_uniform_neon_done
	subs	r3, r3, #6
	beq	L_mldsa_rej_uniform_neon_done
	b	L_mldsa_rej_uniform_neon_loop_lt_2
L_mldsa_rej_uniform_neon_done:
	mov	r0, r4
	vpop	{d8-d15}
	pop	{r4, r5, r6, r7, r8, pc}
	.size	mldsa_rej_uniform_neon,.-mldsa_rej_uniform_neon
#endif /* WOLFSSL_ARMASM_NO_NEON */
#endif /* WOLFSSL_HAVE_MLDSA */

#if defined(__linux__) && defined(__ELF__)
.section	.note.GNU-stack,"",%progbits
#endif
#endif /* !WOLFSSL_ARMASM_INLINE */
#endif /* !__aarch64__ && !WOLFSSL_ARMASM_THUMB2 */
#endif /* WOLFSSL_ARMASM */
