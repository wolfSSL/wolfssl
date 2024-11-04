/* armv8-kyber-asm
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif /* HAVE_CONFIG_H */
#include <wolfssl/wolfcrypt/settings.h>

/* Generated using (from wolfssl):
 *   cd ../scripts
 *   ruby ./kyber/kyber.rb arm64 ../wolfssl/wolfcrypt/src/port/arm/armv8-kyber-asm.S
 */
#ifdef WOLFSSL_ARMASM
#ifdef __aarch64__
#ifndef WOLFSSL_ARMASM_INLINE
#ifndef __APPLE__
	.text
	.type	L_kyber_aarch64_q, %object
	.section	.rodata
	.size	L_kyber_aarch64_q, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
#ifndef __APPLE__
	.align	2
#else
	.p2align	2
#endif /* __APPLE__ */
L_kyber_aarch64_q:
	.short	0x0d01,0x0d01,0x0d01,0x0d01,0x0d01,0x0d01,0x0d01,0x0d01
#ifndef __APPLE__
	.text
	.type	L_kyber_aarch64_consts, %object
	.section	.rodata
	.size	L_kyber_aarch64_consts, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
#ifndef __APPLE__
	.align	2
#else
	.p2align	2
#endif /* __APPLE__ */
L_kyber_aarch64_consts:
	.short	0x0d01,0xf301,0x4ebf,0x0549,0x5049,0x0000,0x0000,0x0000
#ifndef __APPLE__
	.text
	.type	L_sha3_aarch64_r, %object
	.section	.rodata
	.size	L_sha3_aarch64_r, 192
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_sha3_aarch64_r:
	.xword	0x0000000000000001
	.xword	0x0000000000008082
	.xword	0x800000000000808a
	.xword	0x8000000080008000
	.xword	0x000000000000808b
	.xword	0x0000000080000001
	.xword	0x8000000080008081
	.xword	0x8000000000008009
	.xword	0x000000000000008a
	.xword	0x0000000000000088
	.xword	0x0000000080008009
	.xword	0x000000008000000a
	.xword	0x000000008000808b
	.xword	0x800000000000008b
	.xword	0x8000000000008089
	.xword	0x8000000000008003
	.xword	0x8000000000008002
	.xword	0x8000000000000080
	.xword	0x000000000000800a
	.xword	0x800000008000000a
	.xword	0x8000000080008081
	.xword	0x8000000000008080
	.xword	0x0000000080000001
	.xword	0x8000000080008008
#ifdef WOLFSSL_WC_KYBER
#ifndef __APPLE__
	.text
	.type	L_kyber_aarch64_zetas, %object
	.section	.rodata
	.size	L_kyber_aarch64_zetas, 576
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
#ifndef __APPLE__
	.align	2
#else
	.p2align	2
#endif /* __APPLE__ */
L_kyber_aarch64_zetas:
	.short	0x08ed,0x0a0b,0x0b9a,0x0714,0x05d5,0x058e,0x011f,0x00ca
	.short	0x0c56,0x026e,0x0629,0x00b6,0x03c2,0x084f,0x073f,0x05bc
	.short	0x023d,0x07d4,0x0108,0x017f,0x09c4,0x05b2,0x06bf,0x0c7f
	.short	0x0a58,0x03f9,0x02dc,0x0260,0x06fb,0x019b,0x0c34,0x06de
	.short	0x04c7,0x04c7,0x04c7,0x04c7,0x028c,0x028c,0x028c,0x028c
	.short	0x0ad9,0x0ad9,0x0ad9,0x0ad9,0x03f7,0x03f7,0x03f7,0x03f7
	.short	0x07f4,0x07f4,0x07f4,0x07f4,0x05d3,0x05d3,0x05d3,0x05d3
	.short	0x0be7,0x0be7,0x0be7,0x0be7,0x06f9,0x06f9,0x06f9,0x06f9
	.short	0x0204,0x0204,0x0204,0x0204,0x0cf9,0x0cf9,0x0cf9,0x0cf9
	.short	0x0bc1,0x0bc1,0x0bc1,0x0bc1,0x0a67,0x0a67,0x0a67,0x0a67
	.short	0x06af,0x06af,0x06af,0x06af,0x0877,0x0877,0x0877,0x0877
	.short	0x007e,0x007e,0x007e,0x007e,0x05bd,0x05bd,0x05bd,0x05bd
	.short	0x09ac,0x09ac,0x09ac,0x09ac,0x0ca7,0x0ca7,0x0ca7,0x0ca7
	.short	0x0bf2,0x0bf2,0x0bf2,0x0bf2,0x033e,0x033e,0x033e,0x033e
	.short	0x006b,0x006b,0x006b,0x006b,0x0774,0x0774,0x0774,0x0774
	.short	0x0c0a,0x0c0a,0x0c0a,0x0c0a,0x094a,0x094a,0x094a,0x094a
	.short	0x0b73,0x0b73,0x0b73,0x0b73,0x03c1,0x03c1,0x03c1,0x03c1
	.short	0x071d,0x071d,0x071d,0x071d,0x0a2c,0x0a2c,0x0a2c,0x0a2c
	.short	0x01c0,0x01c0,0x01c0,0x01c0,0x08d8,0x08d8,0x08d8,0x08d8
	.short	0x02a5,0x02a5,0x02a5,0x02a5,0x0806,0x0806,0x0806,0x0806
	.short	0x08b2,0x08b2,0x01ae,0x01ae,0x022b,0x022b,0x034b,0x034b
	.short	0x081e,0x081e,0x0367,0x0367,0x060e,0x060e,0x0069,0x0069
	.short	0x01a6,0x01a6,0x024b,0x024b,0x00b1,0x00b1,0x0c16,0x0c16
	.short	0x0bde,0x0bde,0x0b35,0x0b35,0x0626,0x0626,0x0675,0x0675
	.short	0x0c0b,0x0c0b,0x030a,0x030a,0x0487,0x0487,0x0c6e,0x0c6e
	.short	0x09f8,0x09f8,0x05cb,0x05cb,0x0aa7,0x0aa7,0x045f,0x045f
	.short	0x06cb,0x06cb,0x0284,0x0284,0x0999,0x0999,0x015d,0x015d
	.short	0x01a2,0x01a2,0x0149,0x0149,0x0c65,0x0c65,0x0cb6,0x0cb6
	.short	0x0331,0x0331,0x0449,0x0449,0x025b,0x025b,0x0262,0x0262
	.short	0x052a,0x052a,0x07fc,0x07fc,0x0748,0x0748,0x0180,0x0180
	.short	0x0842,0x0842,0x0c79,0x0c79,0x04c2,0x04c2,0x07ca,0x07ca
	.short	0x0997,0x0997,0x00dc,0x00dc,0x085e,0x085e,0x0686,0x0686
	.short	0x0860,0x0860,0x0707,0x0707,0x0803,0x0803,0x031a,0x031a
	.short	0x071b,0x071b,0x09ab,0x09ab,0x099b,0x099b,0x01de,0x01de
	.short	0x0c95,0x0c95,0x0bcd,0x0bcd,0x03e4,0x03e4,0x03df,0x03df
	.short	0x03be,0x03be,0x074d,0x074d,0x05f2,0x05f2,0x065c,0x065c
#ifndef __APPLE__
	.text
	.type	L_kyber_aarch64_zetas_qinv, %object
	.section	.rodata
	.size	L_kyber_aarch64_zetas_qinv, 576
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
#ifndef __APPLE__
	.align	2
#else
	.p2align	2
#endif /* __APPLE__ */
L_kyber_aarch64_zetas_qinv:
	.short	0xffed,0x7b0b,0x399a,0x0314,0x34d5,0xcf8e,0x6e1f,0xbeca
	.short	0xae56,0x6c6e,0xf129,0xc2b6,0x29c2,0x054f,0xd43f,0x79bc
	.short	0xe93d,0x43d4,0x9908,0x8e7f,0x15c4,0xfbb2,0x53bf,0x997f
	.short	0x9258,0x5ef9,0xd6dc,0x2260,0x47fb,0x229b,0x6834,0xc0de
	.short	0xe9c7,0xe9c7,0xe9c7,0xe9c7,0xe68c,0xe68c,0xe68c,0xe68c
	.short	0x05d9,0x05d9,0x05d9,0x05d9,0x78f7,0x78f7,0x78f7,0x78f7
	.short	0xa3f4,0xa3f4,0xa3f4,0xa3f4,0x4ed3,0x4ed3,0x4ed3,0x4ed3
	.short	0x50e7,0x50e7,0x50e7,0x50e7,0x61f9,0x61f9,0x61f9,0x61f9
	.short	0xce04,0xce04,0xce04,0xce04,0x67f9,0x67f9,0x67f9,0x67f9
	.short	0x3ec1,0x3ec1,0x3ec1,0x3ec1,0xcf67,0xcf67,0xcf67,0xcf67
	.short	0x23af,0x23af,0x23af,0x23af,0xfd77,0xfd77,0xfd77,0xfd77
	.short	0x9a7e,0x9a7e,0x9a7e,0x9a7e,0x6cbd,0x6cbd,0x6cbd,0x6cbd
	.short	0x4dac,0x4dac,0x4dac,0x4dac,0x91a7,0x91a7,0x91a7,0x91a7
	.short	0xc1f2,0xc1f2,0xc1f2,0xc1f2,0xdd3e,0xdd3e,0xdd3e,0xdd3e
	.short	0x916b,0x916b,0x916b,0x916b,0x2374,0x2374,0x2374,0x2374
	.short	0x8a0a,0x8a0a,0x8a0a,0x8a0a,0x474a,0x474a,0x474a,0x474a
	.short	0x3473,0x3473,0x3473,0x3473,0x36c1,0x36c1,0x36c1,0x36c1
	.short	0x8e1d,0x8e1d,0x8e1d,0x8e1d,0xce2c,0xce2c,0xce2c,0xce2c
	.short	0x41c0,0x41c0,0x41c0,0x41c0,0x10d8,0x10d8,0x10d8,0x10d8
	.short	0xa1a5,0xa1a5,0xa1a5,0xa1a5,0xba06,0xba06,0xba06,0xba06
	.short	0xfeb2,0xfeb2,0x2bae,0x2bae,0xd32b,0xd32b,0x344b,0x344b
	.short	0x821e,0x821e,0xc867,0xc867,0x500e,0x500e,0xab69,0xab69
	.short	0x93a6,0x93a6,0x334b,0x334b,0x03b1,0x03b1,0xee16,0xee16
	.short	0xc5de,0xc5de,0x5a35,0x5a35,0x1826,0x1826,0x1575,0x1575
	.short	0x7d0b,0x7d0b,0x810a,0x810a,0x2987,0x2987,0x766e,0x766e
	.short	0x71f8,0x71f8,0xb6cb,0xb6cb,0x8fa7,0x8fa7,0x315f,0x315f
	.short	0xb7cb,0xb7cb,0x4e84,0x4e84,0x4499,0x4499,0x485d,0x485d
	.short	0xc7a2,0xc7a2,0x4c49,0x4c49,0xeb65,0xeb65,0xceb6,0xceb6
	.short	0x8631,0x8631,0x4f49,0x4f49,0x635b,0x635b,0x0862,0x0862
	.short	0xe32a,0xe32a,0x3bfc,0x3bfc,0x5f48,0x5f48,0x8180,0x8180
	.short	0xae42,0xae42,0xe779,0xe779,0x2ac2,0x2ac2,0xc5ca,0xc5ca
	.short	0x5e97,0x5e97,0xd4dc,0xd4dc,0x425e,0x425e,0x3886,0x3886
	.short	0x2860,0x2860,0xac07,0xac07,0xe103,0xe103,0xb11a,0xb11a
	.short	0xa81b,0xa81b,0x5aab,0x5aab,0x2a9b,0x2a9b,0xbbde,0xbbde
	.short	0x7b95,0x7b95,0xa2cd,0xa2cd,0x6fe4,0x6fe4,0xb0df,0xb0df
	.short	0x5dbe,0x5dbe,0x1e4d,0x1e4d,0xbbf2,0xbbf2,0x5a5c,0x5a5c
#ifndef __APPLE__
.text
.globl	kyber_ntt
.type	kyber_ntt,@function
.align	2
kyber_ntt:
#else
.section	__TEXT,__text
.globl	_kyber_ntt
.p2align	2
_kyber_ntt:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
	stp	d12, d13, [x29, #48]
	stp	d14, d15, [x29, #64]
#ifndef __APPLE__
	adrp x2, L_kyber_aarch64_zetas
	add  x2, x2, :lo12:L_kyber_aarch64_zetas
#else
	adrp x2, L_kyber_aarch64_zetas@PAGE
	add  x2, x2, :lo12:L_kyber_aarch64_zetas@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x3, L_kyber_aarch64_zetas_qinv
	add  x3, x3, :lo12:L_kyber_aarch64_zetas_qinv
#else
	adrp x3, L_kyber_aarch64_zetas_qinv@PAGE
	add  x3, x3, :lo12:L_kyber_aarch64_zetas_qinv@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x4, L_kyber_aarch64_consts
	add  x4, x4, :lo12:L_kyber_aarch64_consts
#else
	adrp x4, L_kyber_aarch64_consts@PAGE
	add  x4, x4, :lo12:L_kyber_aarch64_consts@PAGEOFF
#endif /* __APPLE__ */
	add	x1, x0, #0x100
	ldr	q4, [x4]
	ldr	q5, [x0]
	ldr	q6, [x0, #32]
	ldr	q7, [x0, #64]
	ldr	q8, [x0, #96]
	ldr	q9, [x0, #128]
	ldr	q10, [x0, #160]
	ldr	q11, [x0, #192]
	ldr	q12, [x0, #224]
	ldr	q13, [x1]
	ldr	q14, [x1, #32]
	ldr	q15, [x1, #64]
	ldr	q16, [x1, #96]
	ldr	q17, [x1, #128]
	ldr	q18, [x1, #160]
	ldr	q19, [x1, #192]
	ldr	q20, [x1, #224]
	ldr	q0, [x2]
	ldr	q1, [x3]
	mul	v29.8h, v13.8h, v1.h[1]
	mul	v30.8h, v14.8h, v1.h[1]
	sqrdmulh	v21.8h, v13.8h, v0.h[1]
	sqrdmulh	v22.8h, v14.8h, v0.h[1]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v21.8h, v29.8h, v4.h[0]
	sqrdmlsh	v22.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v21.8h, v21.8h, v29.8h
	sub	v22.8h, v22.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v21.8h, v21.8h, #1
	sshr	v22.8h, v22.8h, #1
	mul	v29.8h, v15.8h, v1.h[1]
	mul	v30.8h, v16.8h, v1.h[1]
	sqrdmulh	v23.8h, v15.8h, v0.h[1]
	sqrdmulh	v24.8h, v16.8h, v0.h[1]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v23.8h, v29.8h, v4.h[0]
	sqrdmlsh	v24.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v23.8h, v23.8h, v29.8h
	sub	v24.8h, v24.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v23.8h, v23.8h, #1
	sshr	v24.8h, v24.8h, #1
	mul	v29.8h, v17.8h, v1.h[1]
	mul	v30.8h, v18.8h, v1.h[1]
	sqrdmulh	v25.8h, v17.8h, v0.h[1]
	sqrdmulh	v26.8h, v18.8h, v0.h[1]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v25.8h, v29.8h, v4.h[0]
	sqrdmlsh	v26.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v25.8h, v25.8h, v29.8h
	sub	v26.8h, v26.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v25.8h, v25.8h, #1
	sshr	v26.8h, v26.8h, #1
	mul	v29.8h, v19.8h, v1.h[1]
	mul	v30.8h, v20.8h, v1.h[1]
	sqrdmulh	v27.8h, v19.8h, v0.h[1]
	sqrdmulh	v28.8h, v20.8h, v0.h[1]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v27.8h, v29.8h, v4.h[0]
	sqrdmlsh	v28.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v27.8h, v27.8h, v29.8h
	sub	v28.8h, v28.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v27.8h, v27.8h, #1
	sshr	v28.8h, v28.8h, #1
	sub	v13.8h, v5.8h, v21.8h
	add	v5.8h, v5.8h, v21.8h
	sub	v14.8h, v6.8h, v22.8h
	add	v6.8h, v6.8h, v22.8h
	sub	v15.8h, v7.8h, v23.8h
	add	v7.8h, v7.8h, v23.8h
	sub	v16.8h, v8.8h, v24.8h
	add	v8.8h, v8.8h, v24.8h
	sub	v17.8h, v9.8h, v25.8h
	add	v9.8h, v9.8h, v25.8h
	sub	v18.8h, v10.8h, v26.8h
	add	v10.8h, v10.8h, v26.8h
	sub	v19.8h, v11.8h, v27.8h
	add	v11.8h, v11.8h, v27.8h
	sub	v20.8h, v12.8h, v28.8h
	add	v12.8h, v12.8h, v28.8h
	mul	v29.8h, v9.8h, v1.h[2]
	mul	v30.8h, v10.8h, v1.h[2]
	sqrdmulh	v21.8h, v9.8h, v0.h[2]
	sqrdmulh	v22.8h, v10.8h, v0.h[2]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v21.8h, v29.8h, v4.h[0]
	sqrdmlsh	v22.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v21.8h, v21.8h, v29.8h
	sub	v22.8h, v22.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v21.8h, v21.8h, #1
	sshr	v22.8h, v22.8h, #1
	mul	v29.8h, v11.8h, v1.h[2]
	mul	v30.8h, v12.8h, v1.h[2]
	sqrdmulh	v23.8h, v11.8h, v0.h[2]
	sqrdmulh	v24.8h, v12.8h, v0.h[2]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v23.8h, v29.8h, v4.h[0]
	sqrdmlsh	v24.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v23.8h, v23.8h, v29.8h
	sub	v24.8h, v24.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v23.8h, v23.8h, #1
	sshr	v24.8h, v24.8h, #1
	mul	v29.8h, v17.8h, v1.h[3]
	mul	v30.8h, v18.8h, v1.h[3]
	sqrdmulh	v25.8h, v17.8h, v0.h[3]
	sqrdmulh	v26.8h, v18.8h, v0.h[3]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v25.8h, v29.8h, v4.h[0]
	sqrdmlsh	v26.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v25.8h, v25.8h, v29.8h
	sub	v26.8h, v26.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v25.8h, v25.8h, #1
	sshr	v26.8h, v26.8h, #1
	mul	v29.8h, v19.8h, v1.h[3]
	mul	v30.8h, v20.8h, v1.h[3]
	sqrdmulh	v27.8h, v19.8h, v0.h[3]
	sqrdmulh	v28.8h, v20.8h, v0.h[3]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v27.8h, v29.8h, v4.h[0]
	sqrdmlsh	v28.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v27.8h, v27.8h, v29.8h
	sub	v28.8h, v28.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v27.8h, v27.8h, #1
	sshr	v28.8h, v28.8h, #1
	sub	v9.8h, v5.8h, v21.8h
	add	v5.8h, v5.8h, v21.8h
	sub	v10.8h, v6.8h, v22.8h
	add	v6.8h, v6.8h, v22.8h
	sub	v11.8h, v7.8h, v23.8h
	add	v7.8h, v7.8h, v23.8h
	sub	v12.8h, v8.8h, v24.8h
	add	v8.8h, v8.8h, v24.8h
	sub	v17.8h, v13.8h, v25.8h
	add	v13.8h, v13.8h, v25.8h
	sub	v18.8h, v14.8h, v26.8h
	add	v14.8h, v14.8h, v26.8h
	sub	v19.8h, v15.8h, v27.8h
	add	v15.8h, v15.8h, v27.8h
	sub	v20.8h, v16.8h, v28.8h
	add	v16.8h, v16.8h, v28.8h
	mul	v29.8h, v7.8h, v1.h[4]
	mul	v30.8h, v8.8h, v1.h[4]
	sqrdmulh	v21.8h, v7.8h, v0.h[4]
	sqrdmulh	v22.8h, v8.8h, v0.h[4]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v21.8h, v29.8h, v4.h[0]
	sqrdmlsh	v22.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v21.8h, v21.8h, v29.8h
	sub	v22.8h, v22.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v21.8h, v21.8h, #1
	sshr	v22.8h, v22.8h, #1
	mul	v29.8h, v11.8h, v1.h[5]
	mul	v30.8h, v12.8h, v1.h[5]
	sqrdmulh	v23.8h, v11.8h, v0.h[5]
	sqrdmulh	v24.8h, v12.8h, v0.h[5]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v23.8h, v29.8h, v4.h[0]
	sqrdmlsh	v24.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v23.8h, v23.8h, v29.8h
	sub	v24.8h, v24.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v23.8h, v23.8h, #1
	sshr	v24.8h, v24.8h, #1
	mul	v29.8h, v15.8h, v1.h[6]
	mul	v30.8h, v16.8h, v1.h[6]
	sqrdmulh	v25.8h, v15.8h, v0.h[6]
	sqrdmulh	v26.8h, v16.8h, v0.h[6]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v25.8h, v29.8h, v4.h[0]
	sqrdmlsh	v26.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v25.8h, v25.8h, v29.8h
	sub	v26.8h, v26.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v25.8h, v25.8h, #1
	sshr	v26.8h, v26.8h, #1
	mul	v29.8h, v19.8h, v1.h[7]
	mul	v30.8h, v20.8h, v1.h[7]
	sqrdmulh	v27.8h, v19.8h, v0.h[7]
	sqrdmulh	v28.8h, v20.8h, v0.h[7]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v27.8h, v29.8h, v4.h[0]
	sqrdmlsh	v28.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v27.8h, v27.8h, v29.8h
	sub	v28.8h, v28.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v27.8h, v27.8h, #1
	sshr	v28.8h, v28.8h, #1
	sub	v7.8h, v5.8h, v21.8h
	add	v5.8h, v5.8h, v21.8h
	sub	v8.8h, v6.8h, v22.8h
	add	v6.8h, v6.8h, v22.8h
	sub	v11.8h, v9.8h, v23.8h
	add	v9.8h, v9.8h, v23.8h
	sub	v12.8h, v10.8h, v24.8h
	add	v10.8h, v10.8h, v24.8h
	sub	v15.8h, v13.8h, v25.8h
	add	v13.8h, v13.8h, v25.8h
	sub	v16.8h, v14.8h, v26.8h
	add	v14.8h, v14.8h, v26.8h
	sub	v19.8h, v17.8h, v27.8h
	add	v17.8h, v17.8h, v27.8h
	sub	v20.8h, v18.8h, v28.8h
	add	v18.8h, v18.8h, v28.8h
	ldr	q0, [x2, #16]
	ldr	q1, [x3, #16]
	mul	v29.8h, v6.8h, v1.h[0]
	mul	v30.8h, v8.8h, v1.h[1]
	sqrdmulh	v21.8h, v6.8h, v0.h[0]
	sqrdmulh	v22.8h, v8.8h, v0.h[1]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v21.8h, v29.8h, v4.h[0]
	sqrdmlsh	v22.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v21.8h, v21.8h, v29.8h
	sub	v22.8h, v22.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v21.8h, v21.8h, #1
	sshr	v22.8h, v22.8h, #1
	mul	v29.8h, v10.8h, v1.h[2]
	mul	v30.8h, v12.8h, v1.h[3]
	sqrdmulh	v23.8h, v10.8h, v0.h[2]
	sqrdmulh	v24.8h, v12.8h, v0.h[3]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v23.8h, v29.8h, v4.h[0]
	sqrdmlsh	v24.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v23.8h, v23.8h, v29.8h
	sub	v24.8h, v24.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v23.8h, v23.8h, #1
	sshr	v24.8h, v24.8h, #1
	mul	v29.8h, v14.8h, v1.h[4]
	mul	v30.8h, v16.8h, v1.h[5]
	sqrdmulh	v25.8h, v14.8h, v0.h[4]
	sqrdmulh	v26.8h, v16.8h, v0.h[5]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v25.8h, v29.8h, v4.h[0]
	sqrdmlsh	v26.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v25.8h, v25.8h, v29.8h
	sub	v26.8h, v26.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v25.8h, v25.8h, #1
	sshr	v26.8h, v26.8h, #1
	mul	v29.8h, v18.8h, v1.h[6]
	mul	v30.8h, v20.8h, v1.h[7]
	sqrdmulh	v27.8h, v18.8h, v0.h[6]
	sqrdmulh	v28.8h, v20.8h, v0.h[7]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v27.8h, v29.8h, v4.h[0]
	sqrdmlsh	v28.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v27.8h, v27.8h, v29.8h
	sub	v28.8h, v28.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v27.8h, v27.8h, #1
	sshr	v28.8h, v28.8h, #1
	sub	v6.8h, v5.8h, v21.8h
	add	v5.8h, v5.8h, v21.8h
	sub	v8.8h, v7.8h, v22.8h
	add	v7.8h, v7.8h, v22.8h
	sub	v10.8h, v9.8h, v23.8h
	add	v9.8h, v9.8h, v23.8h
	sub	v12.8h, v11.8h, v24.8h
	add	v11.8h, v11.8h, v24.8h
	sub	v14.8h, v13.8h, v25.8h
	add	v13.8h, v13.8h, v25.8h
	sub	v16.8h, v15.8h, v26.8h
	add	v15.8h, v15.8h, v26.8h
	sub	v18.8h, v17.8h, v27.8h
	add	v17.8h, v17.8h, v27.8h
	sub	v20.8h, v19.8h, v28.8h
	add	v19.8h, v19.8h, v28.8h
	str	q5, [x0]
	str	q6, [x0, #32]
	str	q7, [x0, #64]
	str	q8, [x0, #96]
	str	q9, [x0, #128]
	str	q10, [x0, #160]
	str	q11, [x0, #192]
	str	q12, [x0, #224]
	str	q13, [x1]
	str	q14, [x1, #32]
	str	q15, [x1, #64]
	str	q16, [x1, #96]
	str	q17, [x1, #128]
	str	q18, [x1, #160]
	str	q19, [x1, #192]
	str	q20, [x1, #224]
	ldr	q5, [x0, #16]
	ldr	q6, [x0, #48]
	ldr	q7, [x0, #80]
	ldr	q8, [x0, #112]
	ldr	q9, [x0, #144]
	ldr	q10, [x0, #176]
	ldr	q11, [x0, #208]
	ldr	q12, [x0, #240]
	ldr	q13, [x1, #16]
	ldr	q14, [x1, #48]
	ldr	q15, [x1, #80]
	ldr	q16, [x1, #112]
	ldr	q17, [x1, #144]
	ldr	q18, [x1, #176]
	ldr	q19, [x1, #208]
	ldr	q20, [x1, #240]
	ldr	q0, [x2]
	ldr	q1, [x3]
	mul	v29.8h, v13.8h, v1.h[1]
	mul	v30.8h, v14.8h, v1.h[1]
	sqrdmulh	v21.8h, v13.8h, v0.h[1]
	sqrdmulh	v22.8h, v14.8h, v0.h[1]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v21.8h, v29.8h, v4.h[0]
	sqrdmlsh	v22.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v21.8h, v21.8h, v29.8h
	sub	v22.8h, v22.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v21.8h, v21.8h, #1
	sshr	v22.8h, v22.8h, #1
	mul	v29.8h, v15.8h, v1.h[1]
	mul	v30.8h, v16.8h, v1.h[1]
	sqrdmulh	v23.8h, v15.8h, v0.h[1]
	sqrdmulh	v24.8h, v16.8h, v0.h[1]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v23.8h, v29.8h, v4.h[0]
	sqrdmlsh	v24.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v23.8h, v23.8h, v29.8h
	sub	v24.8h, v24.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v23.8h, v23.8h, #1
	sshr	v24.8h, v24.8h, #1
	mul	v29.8h, v17.8h, v1.h[1]
	mul	v30.8h, v18.8h, v1.h[1]
	sqrdmulh	v25.8h, v17.8h, v0.h[1]
	sqrdmulh	v26.8h, v18.8h, v0.h[1]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v25.8h, v29.8h, v4.h[0]
	sqrdmlsh	v26.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v25.8h, v25.8h, v29.8h
	sub	v26.8h, v26.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v25.8h, v25.8h, #1
	sshr	v26.8h, v26.8h, #1
	mul	v29.8h, v19.8h, v1.h[1]
	mul	v30.8h, v20.8h, v1.h[1]
	sqrdmulh	v27.8h, v19.8h, v0.h[1]
	sqrdmulh	v28.8h, v20.8h, v0.h[1]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v27.8h, v29.8h, v4.h[0]
	sqrdmlsh	v28.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v27.8h, v27.8h, v29.8h
	sub	v28.8h, v28.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v27.8h, v27.8h, #1
	sshr	v28.8h, v28.8h, #1
	sub	v13.8h, v5.8h, v21.8h
	add	v5.8h, v5.8h, v21.8h
	sub	v14.8h, v6.8h, v22.8h
	add	v6.8h, v6.8h, v22.8h
	sub	v15.8h, v7.8h, v23.8h
	add	v7.8h, v7.8h, v23.8h
	sub	v16.8h, v8.8h, v24.8h
	add	v8.8h, v8.8h, v24.8h
	sub	v17.8h, v9.8h, v25.8h
	add	v9.8h, v9.8h, v25.8h
	sub	v18.8h, v10.8h, v26.8h
	add	v10.8h, v10.8h, v26.8h
	sub	v19.8h, v11.8h, v27.8h
	add	v11.8h, v11.8h, v27.8h
	sub	v20.8h, v12.8h, v28.8h
	add	v12.8h, v12.8h, v28.8h
	mul	v29.8h, v9.8h, v1.h[2]
	mul	v30.8h, v10.8h, v1.h[2]
	sqrdmulh	v21.8h, v9.8h, v0.h[2]
	sqrdmulh	v22.8h, v10.8h, v0.h[2]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v21.8h, v29.8h, v4.h[0]
	sqrdmlsh	v22.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v21.8h, v21.8h, v29.8h
	sub	v22.8h, v22.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v21.8h, v21.8h, #1
	sshr	v22.8h, v22.8h, #1
	mul	v29.8h, v11.8h, v1.h[2]
	mul	v30.8h, v12.8h, v1.h[2]
	sqrdmulh	v23.8h, v11.8h, v0.h[2]
	sqrdmulh	v24.8h, v12.8h, v0.h[2]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v23.8h, v29.8h, v4.h[0]
	sqrdmlsh	v24.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v23.8h, v23.8h, v29.8h
	sub	v24.8h, v24.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v23.8h, v23.8h, #1
	sshr	v24.8h, v24.8h, #1
	mul	v29.8h, v17.8h, v1.h[3]
	mul	v30.8h, v18.8h, v1.h[3]
	sqrdmulh	v25.8h, v17.8h, v0.h[3]
	sqrdmulh	v26.8h, v18.8h, v0.h[3]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v25.8h, v29.8h, v4.h[0]
	sqrdmlsh	v26.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v25.8h, v25.8h, v29.8h
	sub	v26.8h, v26.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v25.8h, v25.8h, #1
	sshr	v26.8h, v26.8h, #1
	mul	v29.8h, v19.8h, v1.h[3]
	mul	v30.8h, v20.8h, v1.h[3]
	sqrdmulh	v27.8h, v19.8h, v0.h[3]
	sqrdmulh	v28.8h, v20.8h, v0.h[3]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v27.8h, v29.8h, v4.h[0]
	sqrdmlsh	v28.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v27.8h, v27.8h, v29.8h
	sub	v28.8h, v28.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v27.8h, v27.8h, #1
	sshr	v28.8h, v28.8h, #1
	sub	v9.8h, v5.8h, v21.8h
	add	v5.8h, v5.8h, v21.8h
	sub	v10.8h, v6.8h, v22.8h
	add	v6.8h, v6.8h, v22.8h
	sub	v11.8h, v7.8h, v23.8h
	add	v7.8h, v7.8h, v23.8h
	sub	v12.8h, v8.8h, v24.8h
	add	v8.8h, v8.8h, v24.8h
	sub	v17.8h, v13.8h, v25.8h
	add	v13.8h, v13.8h, v25.8h
	sub	v18.8h, v14.8h, v26.8h
	add	v14.8h, v14.8h, v26.8h
	sub	v19.8h, v15.8h, v27.8h
	add	v15.8h, v15.8h, v27.8h
	sub	v20.8h, v16.8h, v28.8h
	add	v16.8h, v16.8h, v28.8h
	mul	v29.8h, v7.8h, v1.h[4]
	mul	v30.8h, v8.8h, v1.h[4]
	sqrdmulh	v21.8h, v7.8h, v0.h[4]
	sqrdmulh	v22.8h, v8.8h, v0.h[4]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v21.8h, v29.8h, v4.h[0]
	sqrdmlsh	v22.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v21.8h, v21.8h, v29.8h
	sub	v22.8h, v22.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v21.8h, v21.8h, #1
	sshr	v22.8h, v22.8h, #1
	mul	v29.8h, v11.8h, v1.h[5]
	mul	v30.8h, v12.8h, v1.h[5]
	sqrdmulh	v23.8h, v11.8h, v0.h[5]
	sqrdmulh	v24.8h, v12.8h, v0.h[5]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v23.8h, v29.8h, v4.h[0]
	sqrdmlsh	v24.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v23.8h, v23.8h, v29.8h
	sub	v24.8h, v24.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v23.8h, v23.8h, #1
	sshr	v24.8h, v24.8h, #1
	mul	v29.8h, v15.8h, v1.h[6]
	mul	v30.8h, v16.8h, v1.h[6]
	sqrdmulh	v25.8h, v15.8h, v0.h[6]
	sqrdmulh	v26.8h, v16.8h, v0.h[6]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v25.8h, v29.8h, v4.h[0]
	sqrdmlsh	v26.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v25.8h, v25.8h, v29.8h
	sub	v26.8h, v26.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v25.8h, v25.8h, #1
	sshr	v26.8h, v26.8h, #1
	mul	v29.8h, v19.8h, v1.h[7]
	mul	v30.8h, v20.8h, v1.h[7]
	sqrdmulh	v27.8h, v19.8h, v0.h[7]
	sqrdmulh	v28.8h, v20.8h, v0.h[7]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v27.8h, v29.8h, v4.h[0]
	sqrdmlsh	v28.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v27.8h, v27.8h, v29.8h
	sub	v28.8h, v28.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v27.8h, v27.8h, #1
	sshr	v28.8h, v28.8h, #1
	sub	v7.8h, v5.8h, v21.8h
	add	v5.8h, v5.8h, v21.8h
	sub	v8.8h, v6.8h, v22.8h
	add	v6.8h, v6.8h, v22.8h
	sub	v11.8h, v9.8h, v23.8h
	add	v9.8h, v9.8h, v23.8h
	sub	v12.8h, v10.8h, v24.8h
	add	v10.8h, v10.8h, v24.8h
	sub	v15.8h, v13.8h, v25.8h
	add	v13.8h, v13.8h, v25.8h
	sub	v16.8h, v14.8h, v26.8h
	add	v14.8h, v14.8h, v26.8h
	sub	v19.8h, v17.8h, v27.8h
	add	v17.8h, v17.8h, v27.8h
	sub	v20.8h, v18.8h, v28.8h
	add	v18.8h, v18.8h, v28.8h
	ldr	q0, [x2, #16]
	ldr	q1, [x3, #16]
	mul	v29.8h, v6.8h, v1.h[0]
	mul	v30.8h, v8.8h, v1.h[1]
	sqrdmulh	v21.8h, v6.8h, v0.h[0]
	sqrdmulh	v22.8h, v8.8h, v0.h[1]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v21.8h, v29.8h, v4.h[0]
	sqrdmlsh	v22.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v21.8h, v21.8h, v29.8h
	sub	v22.8h, v22.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v21.8h, v21.8h, #1
	sshr	v22.8h, v22.8h, #1
	mul	v29.8h, v10.8h, v1.h[2]
	mul	v30.8h, v12.8h, v1.h[3]
	sqrdmulh	v23.8h, v10.8h, v0.h[2]
	sqrdmulh	v24.8h, v12.8h, v0.h[3]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v23.8h, v29.8h, v4.h[0]
	sqrdmlsh	v24.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v23.8h, v23.8h, v29.8h
	sub	v24.8h, v24.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v23.8h, v23.8h, #1
	sshr	v24.8h, v24.8h, #1
	mul	v29.8h, v14.8h, v1.h[4]
	mul	v30.8h, v16.8h, v1.h[5]
	sqrdmulh	v25.8h, v14.8h, v0.h[4]
	sqrdmulh	v26.8h, v16.8h, v0.h[5]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v25.8h, v29.8h, v4.h[0]
	sqrdmlsh	v26.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v25.8h, v25.8h, v29.8h
	sub	v26.8h, v26.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v25.8h, v25.8h, #1
	sshr	v26.8h, v26.8h, #1
	mul	v29.8h, v18.8h, v1.h[6]
	mul	v30.8h, v20.8h, v1.h[7]
	sqrdmulh	v27.8h, v18.8h, v0.h[6]
	sqrdmulh	v28.8h, v20.8h, v0.h[7]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v27.8h, v29.8h, v4.h[0]
	sqrdmlsh	v28.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v27.8h, v27.8h, v29.8h
	sub	v28.8h, v28.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v27.8h, v27.8h, #1
	sshr	v28.8h, v28.8h, #1
	sub	v6.8h, v5.8h, v21.8h
	add	v5.8h, v5.8h, v21.8h
	sub	v8.8h, v7.8h, v22.8h
	add	v7.8h, v7.8h, v22.8h
	sub	v10.8h, v9.8h, v23.8h
	add	v9.8h, v9.8h, v23.8h
	sub	v12.8h, v11.8h, v24.8h
	add	v11.8h, v11.8h, v24.8h
	sub	v14.8h, v13.8h, v25.8h
	add	v13.8h, v13.8h, v25.8h
	sub	v16.8h, v15.8h, v26.8h
	add	v15.8h, v15.8h, v26.8h
	sub	v18.8h, v17.8h, v27.8h
	add	v17.8h, v17.8h, v27.8h
	sub	v20.8h, v19.8h, v28.8h
	add	v19.8h, v19.8h, v28.8h
	str	q5, [x0, #16]
	str	q6, [x0, #48]
	str	q7, [x0, #80]
	str	q8, [x0, #112]
	str	q9, [x0, #144]
	str	q10, [x0, #176]
	str	q11, [x0, #208]
	str	q12, [x0, #240]
	str	q13, [x1, #16]
	str	q14, [x1, #48]
	str	q15, [x1, #80]
	str	q16, [x1, #112]
	str	q17, [x1, #144]
	str	q18, [x1, #176]
	str	q19, [x1, #208]
	str	q20, [x1, #240]
	ldp	q5, q6, [x0]
	ldp	q7, q8, [x0, #32]
	ldp	q9, q10, [x0, #64]
	ldp	q11, q12, [x0, #96]
	ldp	q13, q14, [x0, #128]
	ldp	q15, q16, [x0, #160]
	ldp	q17, q18, [x0, #192]
	ldp	q19, q20, [x0, #224]
	ldr	q0, [x2, #32]
	ldr	q1, [x3, #32]
	mul	v29.8h, v6.8h, v1.h[0]
	mul	v30.8h, v8.8h, v1.h[1]
	sqrdmulh	v21.8h, v6.8h, v0.h[0]
	sqrdmulh	v22.8h, v8.8h, v0.h[1]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v21.8h, v29.8h, v4.h[0]
	sqrdmlsh	v22.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v21.8h, v21.8h, v29.8h
	sub	v22.8h, v22.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v21.8h, v21.8h, #1
	sshr	v22.8h, v22.8h, #1
	mul	v29.8h, v10.8h, v1.h[2]
	mul	v30.8h, v12.8h, v1.h[3]
	sqrdmulh	v23.8h, v10.8h, v0.h[2]
	sqrdmulh	v24.8h, v12.8h, v0.h[3]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v23.8h, v29.8h, v4.h[0]
	sqrdmlsh	v24.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v23.8h, v23.8h, v29.8h
	sub	v24.8h, v24.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v23.8h, v23.8h, #1
	sshr	v24.8h, v24.8h, #1
	mul	v29.8h, v14.8h, v1.h[4]
	mul	v30.8h, v16.8h, v1.h[5]
	sqrdmulh	v25.8h, v14.8h, v0.h[4]
	sqrdmulh	v26.8h, v16.8h, v0.h[5]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v25.8h, v29.8h, v4.h[0]
	sqrdmlsh	v26.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v25.8h, v25.8h, v29.8h
	sub	v26.8h, v26.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v25.8h, v25.8h, #1
	sshr	v26.8h, v26.8h, #1
	mul	v29.8h, v18.8h, v1.h[6]
	mul	v30.8h, v20.8h, v1.h[7]
	sqrdmulh	v27.8h, v18.8h, v0.h[6]
	sqrdmulh	v28.8h, v20.8h, v0.h[7]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v27.8h, v29.8h, v4.h[0]
	sqrdmlsh	v28.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v27.8h, v27.8h, v29.8h
	sub	v28.8h, v28.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v27.8h, v27.8h, #1
	sshr	v28.8h, v28.8h, #1
	sub	v6.8h, v5.8h, v21.8h
	add	v5.8h, v5.8h, v21.8h
	sub	v8.8h, v7.8h, v22.8h
	add	v7.8h, v7.8h, v22.8h
	sub	v10.8h, v9.8h, v23.8h
	add	v9.8h, v9.8h, v23.8h
	sub	v12.8h, v11.8h, v24.8h
	add	v11.8h, v11.8h, v24.8h
	sub	v14.8h, v13.8h, v25.8h
	add	v13.8h, v13.8h, v25.8h
	sub	v16.8h, v15.8h, v26.8h
	add	v15.8h, v15.8h, v26.8h
	sub	v18.8h, v17.8h, v27.8h
	add	v17.8h, v17.8h, v27.8h
	sub	v20.8h, v19.8h, v28.8h
	add	v19.8h, v19.8h, v28.8h
	ldr	q0, [x2, #64]
	ldr	q2, [x2, #80]
	ldr	q1, [x3, #64]
	ldr	q3, [x3, #80]
	mov	v29.16b, v5.16b
	mov	v30.16b, v7.16b
	trn1	v5.2d, v5.2d, v6.2d
	trn1	v7.2d, v7.2d, v8.2d
	trn2	v6.2d, v29.2d, v6.2d
	trn2	v8.2d, v30.2d, v8.2d
	mul	v29.8h, v6.8h, v1.8h
	mul	v30.8h, v8.8h, v3.8h
	sqrdmulh	v21.8h, v6.8h, v0.8h
	sqrdmulh	v22.8h, v8.8h, v2.8h
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v21.8h, v29.8h, v4.h[0]
	sqrdmlsh	v22.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v21.8h, v21.8h, v29.8h
	sub	v22.8h, v22.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v21.8h, v21.8h, #1
	sshr	v22.8h, v22.8h, #1
	ldr	q0, [x2, #96]
	ldr	q2, [x2, #112]
	ldr	q1, [x3, #96]
	ldr	q3, [x3, #112]
	mov	v29.16b, v9.16b
	mov	v30.16b, v11.16b
	trn1	v9.2d, v9.2d, v10.2d
	trn1	v11.2d, v11.2d, v12.2d
	trn2	v10.2d, v29.2d, v10.2d
	trn2	v12.2d, v30.2d, v12.2d
	mul	v29.8h, v10.8h, v1.8h
	mul	v30.8h, v12.8h, v3.8h
	sqrdmulh	v23.8h, v10.8h, v0.8h
	sqrdmulh	v24.8h, v12.8h, v2.8h
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v23.8h, v29.8h, v4.h[0]
	sqrdmlsh	v24.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v23.8h, v23.8h, v29.8h
	sub	v24.8h, v24.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v23.8h, v23.8h, #1
	sshr	v24.8h, v24.8h, #1
	ldr	q0, [x2, #128]
	ldr	q2, [x2, #144]
	ldr	q1, [x3, #128]
	ldr	q3, [x3, #144]
	mov	v29.16b, v13.16b
	mov	v30.16b, v15.16b
	trn1	v13.2d, v13.2d, v14.2d
	trn1	v15.2d, v15.2d, v16.2d
	trn2	v14.2d, v29.2d, v14.2d
	trn2	v16.2d, v30.2d, v16.2d
	mul	v29.8h, v14.8h, v1.8h
	mul	v30.8h, v16.8h, v3.8h
	sqrdmulh	v25.8h, v14.8h, v0.8h
	sqrdmulh	v26.8h, v16.8h, v2.8h
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v25.8h, v29.8h, v4.h[0]
	sqrdmlsh	v26.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v25.8h, v25.8h, v29.8h
	sub	v26.8h, v26.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v25.8h, v25.8h, #1
	sshr	v26.8h, v26.8h, #1
	ldr	q0, [x2, #160]
	ldr	q2, [x2, #176]
	ldr	q1, [x3, #160]
	ldr	q3, [x3, #176]
	mov	v29.16b, v17.16b
	mov	v30.16b, v19.16b
	trn1	v17.2d, v17.2d, v18.2d
	trn1	v19.2d, v19.2d, v20.2d
	trn2	v18.2d, v29.2d, v18.2d
	trn2	v20.2d, v30.2d, v20.2d
	mul	v29.8h, v18.8h, v1.8h
	mul	v30.8h, v20.8h, v3.8h
	sqrdmulh	v27.8h, v18.8h, v0.8h
	sqrdmulh	v28.8h, v20.8h, v2.8h
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v27.8h, v29.8h, v4.h[0]
	sqrdmlsh	v28.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v27.8h, v27.8h, v29.8h
	sub	v28.8h, v28.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v27.8h, v27.8h, #1
	sshr	v28.8h, v28.8h, #1
	sub	v6.8h, v5.8h, v21.8h
	add	v5.8h, v5.8h, v21.8h
	sub	v8.8h, v7.8h, v22.8h
	add	v7.8h, v7.8h, v22.8h
	sub	v10.8h, v9.8h, v23.8h
	add	v9.8h, v9.8h, v23.8h
	sub	v12.8h, v11.8h, v24.8h
	add	v11.8h, v11.8h, v24.8h
	sub	v14.8h, v13.8h, v25.8h
	add	v13.8h, v13.8h, v25.8h
	sub	v16.8h, v15.8h, v26.8h
	add	v15.8h, v15.8h, v26.8h
	sub	v18.8h, v17.8h, v27.8h
	add	v17.8h, v17.8h, v27.8h
	sub	v20.8h, v19.8h, v28.8h
	add	v19.8h, v19.8h, v28.8h
	ldr	q0, [x2, #320]
	ldr	q2, [x2, #336]
	ldr	q1, [x3, #320]
	ldr	q3, [x3, #336]
	mov	v29.16b, v5.16b
	mov	v30.16b, v7.16b
	trn1	v5.4s, v5.4s, v6.4s
	trn1	v7.4s, v7.4s, v8.4s
	trn2	v6.4s, v29.4s, v6.4s
	trn2	v8.4s, v30.4s, v8.4s
	mul	v29.8h, v6.8h, v1.8h
	mul	v30.8h, v8.8h, v3.8h
	sqrdmulh	v21.8h, v6.8h, v0.8h
	sqrdmulh	v22.8h, v8.8h, v2.8h
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v21.8h, v29.8h, v4.h[0]
	sqrdmlsh	v22.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v21.8h, v21.8h, v29.8h
	sub	v22.8h, v22.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v21.8h, v21.8h, #1
	sshr	v22.8h, v22.8h, #1
	ldr	q0, [x2, #352]
	ldr	q2, [x2, #368]
	ldr	q1, [x3, #352]
	ldr	q3, [x3, #368]
	mov	v29.16b, v9.16b
	mov	v30.16b, v11.16b
	trn1	v9.4s, v9.4s, v10.4s
	trn1	v11.4s, v11.4s, v12.4s
	trn2	v10.4s, v29.4s, v10.4s
	trn2	v12.4s, v30.4s, v12.4s
	mul	v29.8h, v10.8h, v1.8h
	mul	v30.8h, v12.8h, v3.8h
	sqrdmulh	v23.8h, v10.8h, v0.8h
	sqrdmulh	v24.8h, v12.8h, v2.8h
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v23.8h, v29.8h, v4.h[0]
	sqrdmlsh	v24.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v23.8h, v23.8h, v29.8h
	sub	v24.8h, v24.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v23.8h, v23.8h, #1
	sshr	v24.8h, v24.8h, #1
	ldr	q0, [x2, #384]
	ldr	q2, [x2, #400]
	ldr	q1, [x3, #384]
	ldr	q3, [x3, #400]
	mov	v29.16b, v13.16b
	mov	v30.16b, v15.16b
	trn1	v13.4s, v13.4s, v14.4s
	trn1	v15.4s, v15.4s, v16.4s
	trn2	v14.4s, v29.4s, v14.4s
	trn2	v16.4s, v30.4s, v16.4s
	mul	v29.8h, v14.8h, v1.8h
	mul	v30.8h, v16.8h, v3.8h
	sqrdmulh	v25.8h, v14.8h, v0.8h
	sqrdmulh	v26.8h, v16.8h, v2.8h
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v25.8h, v29.8h, v4.h[0]
	sqrdmlsh	v26.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v25.8h, v25.8h, v29.8h
	sub	v26.8h, v26.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v25.8h, v25.8h, #1
	sshr	v26.8h, v26.8h, #1
	ldr	q0, [x2, #416]
	ldr	q2, [x2, #432]
	ldr	q1, [x3, #416]
	ldr	q3, [x3, #432]
	mov	v29.16b, v17.16b
	mov	v30.16b, v19.16b
	trn1	v17.4s, v17.4s, v18.4s
	trn1	v19.4s, v19.4s, v20.4s
	trn2	v18.4s, v29.4s, v18.4s
	trn2	v20.4s, v30.4s, v20.4s
	mul	v29.8h, v18.8h, v1.8h
	mul	v30.8h, v20.8h, v3.8h
	sqrdmulh	v27.8h, v18.8h, v0.8h
	sqrdmulh	v28.8h, v20.8h, v2.8h
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v27.8h, v29.8h, v4.h[0]
	sqrdmlsh	v28.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v27.8h, v27.8h, v29.8h
	sub	v28.8h, v28.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v27.8h, v27.8h, #1
	sshr	v28.8h, v28.8h, #1
	sub	v6.8h, v5.8h, v21.8h
	add	v5.8h, v5.8h, v21.8h
	sub	v8.8h, v7.8h, v22.8h
	add	v7.8h, v7.8h, v22.8h
	sub	v10.8h, v9.8h, v23.8h
	add	v9.8h, v9.8h, v23.8h
	sub	v12.8h, v11.8h, v24.8h
	add	v11.8h, v11.8h, v24.8h
	sub	v14.8h, v13.8h, v25.8h
	add	v13.8h, v13.8h, v25.8h
	sub	v16.8h, v15.8h, v26.8h
	add	v15.8h, v15.8h, v26.8h
	sub	v18.8h, v17.8h, v27.8h
	add	v17.8h, v17.8h, v27.8h
	sub	v20.8h, v19.8h, v28.8h
	add	v19.8h, v19.8h, v28.8h
	sqdmulh	v21.8h, v5.8h, v4.h[2]
	sqdmulh	v22.8h, v6.8h, v4.h[2]
	sshr	v21.8h, v21.8h, #11
	sshr	v22.8h, v22.8h, #11
	mls	v5.8h, v21.8h, v4.h[0]
	mls	v6.8h, v22.8h, v4.h[0]
	sqdmulh	v21.8h, v7.8h, v4.h[2]
	sqdmulh	v22.8h, v8.8h, v4.h[2]
	sshr	v21.8h, v21.8h, #11
	sshr	v22.8h, v22.8h, #11
	mls	v7.8h, v21.8h, v4.h[0]
	mls	v8.8h, v22.8h, v4.h[0]
	sqdmulh	v21.8h, v9.8h, v4.h[2]
	sqdmulh	v22.8h, v10.8h, v4.h[2]
	sshr	v21.8h, v21.8h, #11
	sshr	v22.8h, v22.8h, #11
	mls	v9.8h, v21.8h, v4.h[0]
	mls	v10.8h, v22.8h, v4.h[0]
	sqdmulh	v21.8h, v11.8h, v4.h[2]
	sqdmulh	v22.8h, v12.8h, v4.h[2]
	sshr	v21.8h, v21.8h, #11
	sshr	v22.8h, v22.8h, #11
	mls	v11.8h, v21.8h, v4.h[0]
	mls	v12.8h, v22.8h, v4.h[0]
	sqdmulh	v21.8h, v13.8h, v4.h[2]
	sqdmulh	v22.8h, v14.8h, v4.h[2]
	sshr	v21.8h, v21.8h, #11
	sshr	v22.8h, v22.8h, #11
	mls	v13.8h, v21.8h, v4.h[0]
	mls	v14.8h, v22.8h, v4.h[0]
	sqdmulh	v21.8h, v15.8h, v4.h[2]
	sqdmulh	v22.8h, v16.8h, v4.h[2]
	sshr	v21.8h, v21.8h, #11
	sshr	v22.8h, v22.8h, #11
	mls	v15.8h, v21.8h, v4.h[0]
	mls	v16.8h, v22.8h, v4.h[0]
	sqdmulh	v21.8h, v17.8h, v4.h[2]
	sqdmulh	v22.8h, v18.8h, v4.h[2]
	sshr	v21.8h, v21.8h, #11
	sshr	v22.8h, v22.8h, #11
	mls	v17.8h, v21.8h, v4.h[0]
	mls	v18.8h, v22.8h, v4.h[0]
	sqdmulh	v21.8h, v19.8h, v4.h[2]
	sqdmulh	v22.8h, v20.8h, v4.h[2]
	sshr	v21.8h, v21.8h, #11
	sshr	v22.8h, v22.8h, #11
	mls	v19.8h, v21.8h, v4.h[0]
	mls	v20.8h, v22.8h, v4.h[0]
	mov	v29.16b, v5.16b
	trn1	v5.4s, v5.4s, v6.4s
	trn2	v6.4s, v29.4s, v6.4s
	mov	v29.16b, v5.16b
	trn1	v5.2d, v5.2d, v6.2d
	trn2	v6.2d, v29.2d, v6.2d
	mov	v29.16b, v7.16b
	trn1	v7.4s, v7.4s, v8.4s
	trn2	v8.4s, v29.4s, v8.4s
	mov	v29.16b, v7.16b
	trn1	v7.2d, v7.2d, v8.2d
	trn2	v8.2d, v29.2d, v8.2d
	mov	v29.16b, v9.16b
	trn1	v9.4s, v9.4s, v10.4s
	trn2	v10.4s, v29.4s, v10.4s
	mov	v29.16b, v9.16b
	trn1	v9.2d, v9.2d, v10.2d
	trn2	v10.2d, v29.2d, v10.2d
	mov	v29.16b, v11.16b
	trn1	v11.4s, v11.4s, v12.4s
	trn2	v12.4s, v29.4s, v12.4s
	mov	v29.16b, v11.16b
	trn1	v11.2d, v11.2d, v12.2d
	trn2	v12.2d, v29.2d, v12.2d
	mov	v29.16b, v13.16b
	trn1	v13.4s, v13.4s, v14.4s
	trn2	v14.4s, v29.4s, v14.4s
	mov	v29.16b, v13.16b
	trn1	v13.2d, v13.2d, v14.2d
	trn2	v14.2d, v29.2d, v14.2d
	mov	v29.16b, v15.16b
	trn1	v15.4s, v15.4s, v16.4s
	trn2	v16.4s, v29.4s, v16.4s
	mov	v29.16b, v15.16b
	trn1	v15.2d, v15.2d, v16.2d
	trn2	v16.2d, v29.2d, v16.2d
	mov	v29.16b, v17.16b
	trn1	v17.4s, v17.4s, v18.4s
	trn2	v18.4s, v29.4s, v18.4s
	mov	v29.16b, v17.16b
	trn1	v17.2d, v17.2d, v18.2d
	trn2	v18.2d, v29.2d, v18.2d
	mov	v29.16b, v19.16b
	trn1	v19.4s, v19.4s, v20.4s
	trn2	v20.4s, v29.4s, v20.4s
	mov	v29.16b, v19.16b
	trn1	v19.2d, v19.2d, v20.2d
	trn2	v20.2d, v29.2d, v20.2d
	stp	q5, q6, [x0]
	stp	q7, q8, [x0, #32]
	stp	q9, q10, [x0, #64]
	stp	q11, q12, [x0, #96]
	stp	q13, q14, [x0, #128]
	stp	q15, q16, [x0, #160]
	stp	q17, q18, [x0, #192]
	stp	q19, q20, [x0, #224]
	ldp	q5, q6, [x1]
	ldp	q7, q8, [x1, #32]
	ldp	q9, q10, [x1, #64]
	ldp	q11, q12, [x1, #96]
	ldp	q13, q14, [x1, #128]
	ldp	q15, q16, [x1, #160]
	ldp	q17, q18, [x1, #192]
	ldp	q19, q20, [x1, #224]
	ldr	q0, [x2, #48]
	ldr	q1, [x3, #48]
	mul	v29.8h, v6.8h, v1.h[0]
	mul	v30.8h, v8.8h, v1.h[1]
	sqrdmulh	v21.8h, v6.8h, v0.h[0]
	sqrdmulh	v22.8h, v8.8h, v0.h[1]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v21.8h, v29.8h, v4.h[0]
	sqrdmlsh	v22.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v21.8h, v21.8h, v29.8h
	sub	v22.8h, v22.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v21.8h, v21.8h, #1
	sshr	v22.8h, v22.8h, #1
	mul	v29.8h, v10.8h, v1.h[2]
	mul	v30.8h, v12.8h, v1.h[3]
	sqrdmulh	v23.8h, v10.8h, v0.h[2]
	sqrdmulh	v24.8h, v12.8h, v0.h[3]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v23.8h, v29.8h, v4.h[0]
	sqrdmlsh	v24.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v23.8h, v23.8h, v29.8h
	sub	v24.8h, v24.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v23.8h, v23.8h, #1
	sshr	v24.8h, v24.8h, #1
	mul	v29.8h, v14.8h, v1.h[4]
	mul	v30.8h, v16.8h, v1.h[5]
	sqrdmulh	v25.8h, v14.8h, v0.h[4]
	sqrdmulh	v26.8h, v16.8h, v0.h[5]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v25.8h, v29.8h, v4.h[0]
	sqrdmlsh	v26.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v25.8h, v25.8h, v29.8h
	sub	v26.8h, v26.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v25.8h, v25.8h, #1
	sshr	v26.8h, v26.8h, #1
	mul	v29.8h, v18.8h, v1.h[6]
	mul	v30.8h, v20.8h, v1.h[7]
	sqrdmulh	v27.8h, v18.8h, v0.h[6]
	sqrdmulh	v28.8h, v20.8h, v0.h[7]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v27.8h, v29.8h, v4.h[0]
	sqrdmlsh	v28.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v27.8h, v27.8h, v29.8h
	sub	v28.8h, v28.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v27.8h, v27.8h, #1
	sshr	v28.8h, v28.8h, #1
	sub	v6.8h, v5.8h, v21.8h
	add	v5.8h, v5.8h, v21.8h
	sub	v8.8h, v7.8h, v22.8h
	add	v7.8h, v7.8h, v22.8h
	sub	v10.8h, v9.8h, v23.8h
	add	v9.8h, v9.8h, v23.8h
	sub	v12.8h, v11.8h, v24.8h
	add	v11.8h, v11.8h, v24.8h
	sub	v14.8h, v13.8h, v25.8h
	add	v13.8h, v13.8h, v25.8h
	sub	v16.8h, v15.8h, v26.8h
	add	v15.8h, v15.8h, v26.8h
	sub	v18.8h, v17.8h, v27.8h
	add	v17.8h, v17.8h, v27.8h
	sub	v20.8h, v19.8h, v28.8h
	add	v19.8h, v19.8h, v28.8h
	ldr	q0, [x2, #192]
	ldr	q2, [x2, #208]
	ldr	q1, [x3, #192]
	ldr	q3, [x3, #208]
	mov	v29.16b, v5.16b
	mov	v30.16b, v7.16b
	trn1	v5.2d, v5.2d, v6.2d
	trn1	v7.2d, v7.2d, v8.2d
	trn2	v6.2d, v29.2d, v6.2d
	trn2	v8.2d, v30.2d, v8.2d
	mul	v29.8h, v6.8h, v1.8h
	mul	v30.8h, v8.8h, v3.8h
	sqrdmulh	v21.8h, v6.8h, v0.8h
	sqrdmulh	v22.8h, v8.8h, v2.8h
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v21.8h, v29.8h, v4.h[0]
	sqrdmlsh	v22.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v21.8h, v21.8h, v29.8h
	sub	v22.8h, v22.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v21.8h, v21.8h, #1
	sshr	v22.8h, v22.8h, #1
	ldr	q0, [x2, #224]
	ldr	q2, [x2, #240]
	ldr	q1, [x3, #224]
	ldr	q3, [x3, #240]
	mov	v29.16b, v9.16b
	mov	v30.16b, v11.16b
	trn1	v9.2d, v9.2d, v10.2d
	trn1	v11.2d, v11.2d, v12.2d
	trn2	v10.2d, v29.2d, v10.2d
	trn2	v12.2d, v30.2d, v12.2d
	mul	v29.8h, v10.8h, v1.8h
	mul	v30.8h, v12.8h, v3.8h
	sqrdmulh	v23.8h, v10.8h, v0.8h
	sqrdmulh	v24.8h, v12.8h, v2.8h
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v23.8h, v29.8h, v4.h[0]
	sqrdmlsh	v24.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v23.8h, v23.8h, v29.8h
	sub	v24.8h, v24.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v23.8h, v23.8h, #1
	sshr	v24.8h, v24.8h, #1
	ldr	q0, [x2, #256]
	ldr	q2, [x2, #272]
	ldr	q1, [x3, #256]
	ldr	q3, [x3, #272]
	mov	v29.16b, v13.16b
	mov	v30.16b, v15.16b
	trn1	v13.2d, v13.2d, v14.2d
	trn1	v15.2d, v15.2d, v16.2d
	trn2	v14.2d, v29.2d, v14.2d
	trn2	v16.2d, v30.2d, v16.2d
	mul	v29.8h, v14.8h, v1.8h
	mul	v30.8h, v16.8h, v3.8h
	sqrdmulh	v25.8h, v14.8h, v0.8h
	sqrdmulh	v26.8h, v16.8h, v2.8h
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v25.8h, v29.8h, v4.h[0]
	sqrdmlsh	v26.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v25.8h, v25.8h, v29.8h
	sub	v26.8h, v26.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v25.8h, v25.8h, #1
	sshr	v26.8h, v26.8h, #1
	ldr	q0, [x2, #288]
	ldr	q2, [x2, #304]
	ldr	q1, [x3, #288]
	ldr	q3, [x3, #304]
	mov	v29.16b, v17.16b
	mov	v30.16b, v19.16b
	trn1	v17.2d, v17.2d, v18.2d
	trn1	v19.2d, v19.2d, v20.2d
	trn2	v18.2d, v29.2d, v18.2d
	trn2	v20.2d, v30.2d, v20.2d
	mul	v29.8h, v18.8h, v1.8h
	mul	v30.8h, v20.8h, v3.8h
	sqrdmulh	v27.8h, v18.8h, v0.8h
	sqrdmulh	v28.8h, v20.8h, v2.8h
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v27.8h, v29.8h, v4.h[0]
	sqrdmlsh	v28.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v27.8h, v27.8h, v29.8h
	sub	v28.8h, v28.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v27.8h, v27.8h, #1
	sshr	v28.8h, v28.8h, #1
	sub	v6.8h, v5.8h, v21.8h
	add	v5.8h, v5.8h, v21.8h
	sub	v8.8h, v7.8h, v22.8h
	add	v7.8h, v7.8h, v22.8h
	sub	v10.8h, v9.8h, v23.8h
	add	v9.8h, v9.8h, v23.8h
	sub	v12.8h, v11.8h, v24.8h
	add	v11.8h, v11.8h, v24.8h
	sub	v14.8h, v13.8h, v25.8h
	add	v13.8h, v13.8h, v25.8h
	sub	v16.8h, v15.8h, v26.8h
	add	v15.8h, v15.8h, v26.8h
	sub	v18.8h, v17.8h, v27.8h
	add	v17.8h, v17.8h, v27.8h
	sub	v20.8h, v19.8h, v28.8h
	add	v19.8h, v19.8h, v28.8h
	ldr	q0, [x2, #448]
	ldr	q2, [x2, #464]
	ldr	q1, [x3, #448]
	ldr	q3, [x3, #464]
	mov	v29.16b, v5.16b
	mov	v30.16b, v7.16b
	trn1	v5.4s, v5.4s, v6.4s
	trn1	v7.4s, v7.4s, v8.4s
	trn2	v6.4s, v29.4s, v6.4s
	trn2	v8.4s, v30.4s, v8.4s
	mul	v29.8h, v6.8h, v1.8h
	mul	v30.8h, v8.8h, v3.8h
	sqrdmulh	v21.8h, v6.8h, v0.8h
	sqrdmulh	v22.8h, v8.8h, v2.8h
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v21.8h, v29.8h, v4.h[0]
	sqrdmlsh	v22.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v21.8h, v21.8h, v29.8h
	sub	v22.8h, v22.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v21.8h, v21.8h, #1
	sshr	v22.8h, v22.8h, #1
	ldr	q0, [x2, #480]
	ldr	q2, [x2, #496]
	ldr	q1, [x3, #480]
	ldr	q3, [x3, #496]
	mov	v29.16b, v9.16b
	mov	v30.16b, v11.16b
	trn1	v9.4s, v9.4s, v10.4s
	trn1	v11.4s, v11.4s, v12.4s
	trn2	v10.4s, v29.4s, v10.4s
	trn2	v12.4s, v30.4s, v12.4s
	mul	v29.8h, v10.8h, v1.8h
	mul	v30.8h, v12.8h, v3.8h
	sqrdmulh	v23.8h, v10.8h, v0.8h
	sqrdmulh	v24.8h, v12.8h, v2.8h
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v23.8h, v29.8h, v4.h[0]
	sqrdmlsh	v24.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v23.8h, v23.8h, v29.8h
	sub	v24.8h, v24.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v23.8h, v23.8h, #1
	sshr	v24.8h, v24.8h, #1
	ldr	q0, [x2, #512]
	ldr	q2, [x2, #528]
	ldr	q1, [x3, #512]
	ldr	q3, [x3, #528]
	mov	v29.16b, v13.16b
	mov	v30.16b, v15.16b
	trn1	v13.4s, v13.4s, v14.4s
	trn1	v15.4s, v15.4s, v16.4s
	trn2	v14.4s, v29.4s, v14.4s
	trn2	v16.4s, v30.4s, v16.4s
	mul	v29.8h, v14.8h, v1.8h
	mul	v30.8h, v16.8h, v3.8h
	sqrdmulh	v25.8h, v14.8h, v0.8h
	sqrdmulh	v26.8h, v16.8h, v2.8h
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v25.8h, v29.8h, v4.h[0]
	sqrdmlsh	v26.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v25.8h, v25.8h, v29.8h
	sub	v26.8h, v26.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v25.8h, v25.8h, #1
	sshr	v26.8h, v26.8h, #1
	ldr	q0, [x2, #544]
	ldr	q2, [x2, #560]
	ldr	q1, [x3, #544]
	ldr	q3, [x3, #560]
	mov	v29.16b, v17.16b
	mov	v30.16b, v19.16b
	trn1	v17.4s, v17.4s, v18.4s
	trn1	v19.4s, v19.4s, v20.4s
	trn2	v18.4s, v29.4s, v18.4s
	trn2	v20.4s, v30.4s, v20.4s
	mul	v29.8h, v18.8h, v1.8h
	mul	v30.8h, v20.8h, v3.8h
	sqrdmulh	v27.8h, v18.8h, v0.8h
	sqrdmulh	v28.8h, v20.8h, v2.8h
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v27.8h, v29.8h, v4.h[0]
	sqrdmlsh	v28.8h, v30.8h, v4.h[0]
#else
	sqrdmulh	v29.8h, v29.8h, v4.h[0]
	sqrdmulh	v30.8h, v30.8h, v4.h[0]
	sub	v27.8h, v27.8h, v29.8h
	sub	v28.8h, v28.8h, v30.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v27.8h, v27.8h, #1
	sshr	v28.8h, v28.8h, #1
	sub	v6.8h, v5.8h, v21.8h
	add	v5.8h, v5.8h, v21.8h
	sub	v8.8h, v7.8h, v22.8h
	add	v7.8h, v7.8h, v22.8h
	sub	v10.8h, v9.8h, v23.8h
	add	v9.8h, v9.8h, v23.8h
	sub	v12.8h, v11.8h, v24.8h
	add	v11.8h, v11.8h, v24.8h
	sub	v14.8h, v13.8h, v25.8h
	add	v13.8h, v13.8h, v25.8h
	sub	v16.8h, v15.8h, v26.8h
	add	v15.8h, v15.8h, v26.8h
	sub	v18.8h, v17.8h, v27.8h
	add	v17.8h, v17.8h, v27.8h
	sub	v20.8h, v19.8h, v28.8h
	add	v19.8h, v19.8h, v28.8h
	sqdmulh	v21.8h, v5.8h, v4.h[2]
	sqdmulh	v22.8h, v6.8h, v4.h[2]
	sshr	v21.8h, v21.8h, #11
	sshr	v22.8h, v22.8h, #11
	mls	v5.8h, v21.8h, v4.h[0]
	mls	v6.8h, v22.8h, v4.h[0]
	sqdmulh	v21.8h, v7.8h, v4.h[2]
	sqdmulh	v22.8h, v8.8h, v4.h[2]
	sshr	v21.8h, v21.8h, #11
	sshr	v22.8h, v22.8h, #11
	mls	v7.8h, v21.8h, v4.h[0]
	mls	v8.8h, v22.8h, v4.h[0]
	sqdmulh	v21.8h, v9.8h, v4.h[2]
	sqdmulh	v22.8h, v10.8h, v4.h[2]
	sshr	v21.8h, v21.8h, #11
	sshr	v22.8h, v22.8h, #11
	mls	v9.8h, v21.8h, v4.h[0]
	mls	v10.8h, v22.8h, v4.h[0]
	sqdmulh	v21.8h, v11.8h, v4.h[2]
	sqdmulh	v22.8h, v12.8h, v4.h[2]
	sshr	v21.8h, v21.8h, #11
	sshr	v22.8h, v22.8h, #11
	mls	v11.8h, v21.8h, v4.h[0]
	mls	v12.8h, v22.8h, v4.h[0]
	sqdmulh	v21.8h, v13.8h, v4.h[2]
	sqdmulh	v22.8h, v14.8h, v4.h[2]
	sshr	v21.8h, v21.8h, #11
	sshr	v22.8h, v22.8h, #11
	mls	v13.8h, v21.8h, v4.h[0]
	mls	v14.8h, v22.8h, v4.h[0]
	sqdmulh	v21.8h, v15.8h, v4.h[2]
	sqdmulh	v22.8h, v16.8h, v4.h[2]
	sshr	v21.8h, v21.8h, #11
	sshr	v22.8h, v22.8h, #11
	mls	v15.8h, v21.8h, v4.h[0]
	mls	v16.8h, v22.8h, v4.h[0]
	sqdmulh	v21.8h, v17.8h, v4.h[2]
	sqdmulh	v22.8h, v18.8h, v4.h[2]
	sshr	v21.8h, v21.8h, #11
	sshr	v22.8h, v22.8h, #11
	mls	v17.8h, v21.8h, v4.h[0]
	mls	v18.8h, v22.8h, v4.h[0]
	sqdmulh	v21.8h, v19.8h, v4.h[2]
	sqdmulh	v22.8h, v20.8h, v4.h[2]
	sshr	v21.8h, v21.8h, #11
	sshr	v22.8h, v22.8h, #11
	mls	v19.8h, v21.8h, v4.h[0]
	mls	v20.8h, v22.8h, v4.h[0]
	mov	v29.16b, v5.16b
	trn1	v5.4s, v5.4s, v6.4s
	trn2	v6.4s, v29.4s, v6.4s
	mov	v29.16b, v5.16b
	trn1	v5.2d, v5.2d, v6.2d
	trn2	v6.2d, v29.2d, v6.2d
	mov	v29.16b, v7.16b
	trn1	v7.4s, v7.4s, v8.4s
	trn2	v8.4s, v29.4s, v8.4s
	mov	v29.16b, v7.16b
	trn1	v7.2d, v7.2d, v8.2d
	trn2	v8.2d, v29.2d, v8.2d
	mov	v29.16b, v9.16b
	trn1	v9.4s, v9.4s, v10.4s
	trn2	v10.4s, v29.4s, v10.4s
	mov	v29.16b, v9.16b
	trn1	v9.2d, v9.2d, v10.2d
	trn2	v10.2d, v29.2d, v10.2d
	mov	v29.16b, v11.16b
	trn1	v11.4s, v11.4s, v12.4s
	trn2	v12.4s, v29.4s, v12.4s
	mov	v29.16b, v11.16b
	trn1	v11.2d, v11.2d, v12.2d
	trn2	v12.2d, v29.2d, v12.2d
	mov	v29.16b, v13.16b
	trn1	v13.4s, v13.4s, v14.4s
	trn2	v14.4s, v29.4s, v14.4s
	mov	v29.16b, v13.16b
	trn1	v13.2d, v13.2d, v14.2d
	trn2	v14.2d, v29.2d, v14.2d
	mov	v29.16b, v15.16b
	trn1	v15.4s, v15.4s, v16.4s
	trn2	v16.4s, v29.4s, v16.4s
	mov	v29.16b, v15.16b
	trn1	v15.2d, v15.2d, v16.2d
	trn2	v16.2d, v29.2d, v16.2d
	mov	v29.16b, v17.16b
	trn1	v17.4s, v17.4s, v18.4s
	trn2	v18.4s, v29.4s, v18.4s
	mov	v29.16b, v17.16b
	trn1	v17.2d, v17.2d, v18.2d
	trn2	v18.2d, v29.2d, v18.2d
	mov	v29.16b, v19.16b
	trn1	v19.4s, v19.4s, v20.4s
	trn2	v20.4s, v29.4s, v20.4s
	mov	v29.16b, v19.16b
	trn1	v19.2d, v19.2d, v20.2d
	trn2	v20.2d, v29.2d, v20.2d
	stp	q5, q6, [x1]
	stp	q7, q8, [x1, #32]
	stp	q9, q10, [x1, #64]
	stp	q11, q12, [x1, #96]
	stp	q13, q14, [x1, #128]
	stp	q15, q16, [x1, #160]
	stp	q17, q18, [x1, #192]
	stp	q19, q20, [x1, #224]
	ldp	d8, d9, [x29, #16]
	ldp	d10, d11, [x29, #32]
	ldp	d12, d13, [x29, #48]
	ldp	d14, d15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
#ifndef __APPLE__
	.size	kyber_ntt,.-kyber_ntt
#endif /* __APPLE__ */
#ifndef __APPLE__
	.text
	.type	L_kyber_aarch64_zetas_inv, %object
	.section	.rodata
	.size	L_kyber_aarch64_zetas_inv, 576
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
#ifndef __APPLE__
	.align	2
#else
	.p2align	2
#endif /* __APPLE__ */
L_kyber_aarch64_zetas_inv:
	.short	0x06a5,0x06a5,0x070f,0x070f,0x05b4,0x05b4,0x0943,0x0943
	.short	0x0922,0x0922,0x091d,0x091d,0x0134,0x0134,0x006c,0x006c
	.short	0x0b23,0x0b23,0x0366,0x0366,0x0356,0x0356,0x05e6,0x05e6
	.short	0x09e7,0x09e7,0x04fe,0x04fe,0x05fa,0x05fa,0x04a1,0x04a1
	.short	0x067b,0x067b,0x04a3,0x04a3,0x0c25,0x0c25,0x036a,0x036a
	.short	0x0537,0x0537,0x083f,0x083f,0x0088,0x0088,0x04bf,0x04bf
	.short	0x0b81,0x0b81,0x05b9,0x05b9,0x0505,0x0505,0x07d7,0x07d7
	.short	0x0a9f,0x0a9f,0x0aa6,0x0aa6,0x08b8,0x08b8,0x09d0,0x09d0
	.short	0x004b,0x004b,0x009c,0x009c,0x0bb8,0x0bb8,0x0b5f,0x0b5f
	.short	0x0ba4,0x0ba4,0x0368,0x0368,0x0a7d,0x0a7d,0x0636,0x0636
	.short	0x08a2,0x08a2,0x025a,0x025a,0x0736,0x0736,0x0309,0x0309
	.short	0x0093,0x0093,0x087a,0x087a,0x09f7,0x09f7,0x00f6,0x00f6
	.short	0x068c,0x068c,0x06db,0x06db,0x01cc,0x01cc,0x0123,0x0123
	.short	0x00eb,0x00eb,0x0c50,0x0c50,0x0ab6,0x0ab6,0x0b5b,0x0b5b
	.short	0x0c98,0x0c98,0x06f3,0x06f3,0x099a,0x099a,0x04e3,0x04e3
	.short	0x09b6,0x09b6,0x0ad6,0x0ad6,0x0b53,0x0b53,0x044f,0x044f
	.short	0x04fb,0x04fb,0x04fb,0x04fb,0x0a5c,0x0a5c,0x0a5c,0x0a5c
	.short	0x0429,0x0429,0x0429,0x0429,0x0b41,0x0b41,0x0b41,0x0b41
	.short	0x02d5,0x02d5,0x02d5,0x02d5,0x05e4,0x05e4,0x05e4,0x05e4
	.short	0x0940,0x0940,0x0940,0x0940,0x018e,0x018e,0x018e,0x018e
	.short	0x03b7,0x03b7,0x03b7,0x03b7,0x00f7,0x00f7,0x00f7,0x00f7
	.short	0x058d,0x058d,0x058d,0x058d,0x0c96,0x0c96,0x0c96,0x0c96
	.short	0x09c3,0x09c3,0x09c3,0x09c3,0x010f,0x010f,0x010f,0x010f
	.short	0x005a,0x005a,0x005a,0x005a,0x0355,0x0355,0x0355,0x0355
	.short	0x0744,0x0744,0x0744,0x0744,0x0c83,0x0c83,0x0c83,0x0c83
	.short	0x048a,0x048a,0x048a,0x048a,0x0652,0x0652,0x0652,0x0652
	.short	0x029a,0x029a,0x029a,0x029a,0x0140,0x0140,0x0140,0x0140
	.short	0x0008,0x0008,0x0008,0x0008,0x0afd,0x0afd,0x0afd,0x0afd
	.short	0x0608,0x0608,0x0608,0x0608,0x011a,0x011a,0x011a,0x011a
	.short	0x072e,0x072e,0x072e,0x072e,0x050d,0x050d,0x050d,0x050d
	.short	0x090a,0x090a,0x090a,0x090a,0x0228,0x0228,0x0228,0x0228
	.short	0x0a75,0x0a75,0x0a75,0x0a75,0x083a,0x083a,0x083a,0x083a
	.short	0x0623,0x00cd,0x0b66,0x0606,0x0aa1,0x0a25,0x0908,0x02a9
	.short	0x0082,0x0642,0x074f,0x033d,0x0b82,0x0bf9,0x052d,0x0ac4
	.short	0x0745,0x05c2,0x04b2,0x093f,0x0c4b,0x06d8,0x0a93,0x00ab
	.short	0x0c37,0x0be2,0x0773,0x072c,0x05ed,0x0167,0x02f6,0x05a1
#ifndef __APPLE__
	.text
	.type	L_kyber_aarch64_zetas_inv_qinv, %object
	.section	.rodata
	.size	L_kyber_aarch64_zetas_inv_qinv, 576
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
#ifndef __APPLE__
	.align	2
#else
	.p2align	2
#endif /* __APPLE__ */
L_kyber_aarch64_zetas_inv_qinv:
	.short	0xa5a5,0xa5a5,0x440f,0x440f,0xe1b4,0xe1b4,0xa243,0xa243
	.short	0x4f22,0x4f22,0x901d,0x901d,0x5d34,0x5d34,0x846c,0x846c
	.short	0x4423,0x4423,0xd566,0xd566,0xa556,0xa556,0x57e6,0x57e6
	.short	0x4ee7,0x4ee7,0x1efe,0x1efe,0x53fa,0x53fa,0xd7a1,0xd7a1
	.short	0xc77b,0xc77b,0xbda3,0xbda3,0x2b25,0x2b25,0xa16a,0xa16a
	.short	0x3a37,0x3a37,0xd53f,0xd53f,0x1888,0x1888,0x51bf,0x51bf
	.short	0x7e81,0x7e81,0xa0b9,0xa0b9,0xc405,0xc405,0x1cd7,0x1cd7
	.short	0xf79f,0xf79f,0x9ca6,0x9ca6,0xb0b8,0xb0b8,0x79d0,0x79d0
	.short	0x314b,0x314b,0x149c,0x149c,0xb3b8,0xb3b8,0x385f,0x385f
	.short	0xb7a4,0xb7a4,0xbb68,0xbb68,0xb17d,0xb17d,0x4836,0x4836
	.short	0xcea2,0xcea2,0x705a,0x705a,0x4936,0x4936,0x8e09,0x8e09
	.short	0x8993,0x8993,0xd67a,0xd67a,0x7ef7,0x7ef7,0x82f6,0x82f6
	.short	0xea8c,0xea8c,0xe7db,0xe7db,0xa5cc,0xa5cc,0x3a23,0x3a23
	.short	0x11eb,0x11eb,0xfc50,0xfc50,0xccb6,0xccb6,0x6c5b,0x6c5b
	.short	0x5498,0x5498,0xaff3,0xaff3,0x379a,0x379a,0x7de3,0x7de3
	.short	0xcbb6,0xcbb6,0x2cd6,0x2cd6,0xd453,0xd453,0x014f,0x014f
	.short	0x45fb,0x45fb,0x45fb,0x45fb,0x5e5c,0x5e5c,0x5e5c,0x5e5c
	.short	0xef29,0xef29,0xef29,0xef29,0xbe41,0xbe41,0xbe41,0xbe41
	.short	0x31d5,0x31d5,0x31d5,0x31d5,0x71e4,0x71e4,0x71e4,0x71e4
	.short	0xc940,0xc940,0xc940,0xc940,0xcb8e,0xcb8e,0xcb8e,0xcb8e
	.short	0xb8b7,0xb8b7,0xb8b7,0xb8b7,0x75f7,0x75f7,0x75f7,0x75f7
	.short	0xdc8d,0xdc8d,0xdc8d,0xdc8d,0x6e96,0x6e96,0x6e96,0x6e96
	.short	0x22c3,0x22c3,0x22c3,0x22c3,0x3e0f,0x3e0f,0x3e0f,0x3e0f
	.short	0x6e5a,0x6e5a,0x6e5a,0x6e5a,0xb255,0xb255,0xb255,0xb255
	.short	0x9344,0x9344,0x9344,0x9344,0x6583,0x6583,0x6583,0x6583
	.short	0x028a,0x028a,0x028a,0x028a,0xdc52,0xdc52,0xdc52,0xdc52
	.short	0x309a,0x309a,0x309a,0x309a,0xc140,0xc140,0xc140,0xc140
	.short	0x9808,0x9808,0x9808,0x9808,0x31fd,0x31fd,0x31fd,0x31fd
	.short	0x9e08,0x9e08,0x9e08,0x9e08,0xaf1a,0xaf1a,0xaf1a,0xaf1a
	.short	0xb12e,0xb12e,0xb12e,0xb12e,0x5c0d,0x5c0d,0x5c0d,0x5c0d
	.short	0x870a,0x870a,0x870a,0x870a,0xfa28,0xfa28,0xfa28,0xfa28
	.short	0x1975,0x1975,0x1975,0x1975,0x163a,0x163a,0x163a,0x163a
	.short	0x3f23,0x97cd,0xdd66,0xb806,0xdda1,0x2925,0xa108,0x6da9
	.short	0x6682,0xac42,0x044f,0xea3d,0x7182,0x66f9,0xbc2d,0x16c4
	.short	0x8645,0x2bc2,0xfab2,0xd63f,0x3d4b,0x0ed8,0x9393,0x51ab
	.short	0x4137,0x91e2,0x3073,0xcb2c,0xfced,0xc667,0x84f6,0xd8a1
#ifndef __APPLE__
.text
.globl	kyber_invntt
.type	kyber_invntt,@function
.align	2
kyber_invntt:
#else
.section	__TEXT,__text
.globl	_kyber_invntt
.p2align	2
_kyber_invntt:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
	stp	d12, d13, [x29, #48]
	stp	d14, d15, [x29, #64]
#ifndef __APPLE__
	adrp x2, L_kyber_aarch64_zetas_inv
	add  x2, x2, :lo12:L_kyber_aarch64_zetas_inv
#else
	adrp x2, L_kyber_aarch64_zetas_inv@PAGE
	add  x2, x2, :lo12:L_kyber_aarch64_zetas_inv@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x3, L_kyber_aarch64_zetas_inv_qinv
	add  x3, x3, :lo12:L_kyber_aarch64_zetas_inv_qinv
#else
	adrp x3, L_kyber_aarch64_zetas_inv_qinv@PAGE
	add  x3, x3, :lo12:L_kyber_aarch64_zetas_inv_qinv@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x4, L_kyber_aarch64_consts
	add  x4, x4, :lo12:L_kyber_aarch64_consts
#else
	adrp x4, L_kyber_aarch64_consts@PAGE
	add  x4, x4, :lo12:L_kyber_aarch64_consts@PAGEOFF
#endif /* __APPLE__ */
	add	x1, x0, #0x100
	ldr	q8, [x4]
	ldp	q9, q10, [x0]
	ldp	q11, q12, [x0, #32]
	ldp	q13, q14, [x0, #64]
	ldp	q15, q16, [x0, #96]
	ldp	q17, q18, [x0, #128]
	ldp	q19, q20, [x0, #160]
	ldp	q21, q22, [x0, #192]
	ldp	q23, q24, [x0, #224]
	mov	v25.16b, v9.16b
	trn1	v9.2d, v9.2d, v10.2d
	trn2	v10.2d, v25.2d, v10.2d
	mov	v25.16b, v9.16b
	trn1	v9.4s, v9.4s, v10.4s
	trn2	v10.4s, v25.4s, v10.4s
	mov	v25.16b, v11.16b
	trn1	v11.2d, v11.2d, v12.2d
	trn2	v12.2d, v25.2d, v12.2d
	mov	v25.16b, v11.16b
	trn1	v11.4s, v11.4s, v12.4s
	trn2	v12.4s, v25.4s, v12.4s
	mov	v25.16b, v13.16b
	trn1	v13.2d, v13.2d, v14.2d
	trn2	v14.2d, v25.2d, v14.2d
	mov	v25.16b, v13.16b
	trn1	v13.4s, v13.4s, v14.4s
	trn2	v14.4s, v25.4s, v14.4s
	mov	v25.16b, v15.16b
	trn1	v15.2d, v15.2d, v16.2d
	trn2	v16.2d, v25.2d, v16.2d
	mov	v25.16b, v15.16b
	trn1	v15.4s, v15.4s, v16.4s
	trn2	v16.4s, v25.4s, v16.4s
	mov	v25.16b, v17.16b
	trn1	v17.2d, v17.2d, v18.2d
	trn2	v18.2d, v25.2d, v18.2d
	mov	v25.16b, v17.16b
	trn1	v17.4s, v17.4s, v18.4s
	trn2	v18.4s, v25.4s, v18.4s
	mov	v25.16b, v19.16b
	trn1	v19.2d, v19.2d, v20.2d
	trn2	v20.2d, v25.2d, v20.2d
	mov	v25.16b, v19.16b
	trn1	v19.4s, v19.4s, v20.4s
	trn2	v20.4s, v25.4s, v20.4s
	mov	v25.16b, v21.16b
	trn1	v21.2d, v21.2d, v22.2d
	trn2	v22.2d, v25.2d, v22.2d
	mov	v25.16b, v21.16b
	trn1	v21.4s, v21.4s, v22.4s
	trn2	v22.4s, v25.4s, v22.4s
	mov	v25.16b, v23.16b
	trn1	v23.2d, v23.2d, v24.2d
	trn2	v24.2d, v25.2d, v24.2d
	mov	v25.16b, v23.16b
	trn1	v23.4s, v23.4s, v24.4s
	trn2	v24.4s, v25.4s, v24.4s
	ldr	q0, [x2]
	ldr	q1, [x2, #16]
	ldr	q2, [x3]
	ldr	q3, [x3, #16]
	sub	v26.8h, v9.8h, v10.8h
	sub	v28.8h, v11.8h, v12.8h
	add	v9.8h, v9.8h, v10.8h
	add	v11.8h, v11.8h, v12.8h
	mul	v25.8h, v26.8h, v2.8h
	mul	v27.8h, v28.8h, v3.8h
	sqrdmulh	v10.8h, v26.8h, v0.8h
	sqrdmulh	v12.8h, v28.8h, v1.8h
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v10.8h, v25.8h, v8.h[0]
	sqrdmlsh	v12.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v10.8h, v10.8h, v25.8h
	sub	v12.8h, v12.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v10.8h, v10.8h, #1
	sshr	v12.8h, v12.8h, #1
	ldr	q0, [x2, #32]
	ldr	q1, [x2, #48]
	ldr	q2, [x3, #32]
	ldr	q3, [x3, #48]
	sub	v26.8h, v13.8h, v14.8h
	sub	v28.8h, v15.8h, v16.8h
	add	v13.8h, v13.8h, v14.8h
	add	v15.8h, v15.8h, v16.8h
	mul	v25.8h, v26.8h, v2.8h
	mul	v27.8h, v28.8h, v3.8h
	sqrdmulh	v14.8h, v26.8h, v0.8h
	sqrdmulh	v16.8h, v28.8h, v1.8h
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v14.8h, v25.8h, v8.h[0]
	sqrdmlsh	v16.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v14.8h, v14.8h, v25.8h
	sub	v16.8h, v16.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v14.8h, v14.8h, #1
	sshr	v16.8h, v16.8h, #1
	ldr	q0, [x2, #64]
	ldr	q1, [x2, #80]
	ldr	q2, [x3, #64]
	ldr	q3, [x3, #80]
	sub	v26.8h, v17.8h, v18.8h
	sub	v28.8h, v19.8h, v20.8h
	add	v17.8h, v17.8h, v18.8h
	add	v19.8h, v19.8h, v20.8h
	mul	v25.8h, v26.8h, v2.8h
	mul	v27.8h, v28.8h, v3.8h
	sqrdmulh	v18.8h, v26.8h, v0.8h
	sqrdmulh	v20.8h, v28.8h, v1.8h
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v18.8h, v25.8h, v8.h[0]
	sqrdmlsh	v20.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v18.8h, v18.8h, v25.8h
	sub	v20.8h, v20.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v18.8h, v18.8h, #1
	sshr	v20.8h, v20.8h, #1
	ldr	q0, [x2, #96]
	ldr	q1, [x2, #112]
	ldr	q2, [x3, #96]
	ldr	q3, [x3, #112]
	sub	v26.8h, v21.8h, v22.8h
	sub	v28.8h, v23.8h, v24.8h
	add	v21.8h, v21.8h, v22.8h
	add	v23.8h, v23.8h, v24.8h
	mul	v25.8h, v26.8h, v2.8h
	mul	v27.8h, v28.8h, v3.8h
	sqrdmulh	v22.8h, v26.8h, v0.8h
	sqrdmulh	v24.8h, v28.8h, v1.8h
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v22.8h, v25.8h, v8.h[0]
	sqrdmlsh	v24.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v22.8h, v22.8h, v25.8h
	sub	v24.8h, v24.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v22.8h, v22.8h, #1
	sshr	v24.8h, v24.8h, #1
	ldr	q0, [x2, #256]
	ldr	q1, [x2, #272]
	ldr	q2, [x3, #256]
	ldr	q3, [x3, #272]
	mov	v25.16b, v9.16b
	mov	v26.16b, v11.16b
	trn1	v9.4s, v9.4s, v10.4s
	trn1	v11.4s, v11.4s, v12.4s
	trn2	v10.4s, v25.4s, v10.4s
	trn2	v12.4s, v26.4s, v12.4s
	sub	v26.8h, v9.8h, v10.8h
	sub	v28.8h, v11.8h, v12.8h
	add	v9.8h, v9.8h, v10.8h
	add	v11.8h, v11.8h, v12.8h
	mul	v25.8h, v26.8h, v2.8h
	mul	v27.8h, v28.8h, v3.8h
	sqrdmulh	v10.8h, v26.8h, v0.8h
	sqrdmulh	v12.8h, v28.8h, v1.8h
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v10.8h, v25.8h, v8.h[0]
	sqrdmlsh	v12.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v10.8h, v10.8h, v25.8h
	sub	v12.8h, v12.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v10.8h, v10.8h, #1
	sshr	v12.8h, v12.8h, #1
	ldr	q0, [x2, #288]
	ldr	q1, [x2, #304]
	ldr	q2, [x3, #288]
	ldr	q3, [x3, #304]
	mov	v25.16b, v13.16b
	mov	v26.16b, v15.16b
	trn1	v13.4s, v13.4s, v14.4s
	trn1	v15.4s, v15.4s, v16.4s
	trn2	v14.4s, v25.4s, v14.4s
	trn2	v16.4s, v26.4s, v16.4s
	sub	v26.8h, v13.8h, v14.8h
	sub	v28.8h, v15.8h, v16.8h
	add	v13.8h, v13.8h, v14.8h
	add	v15.8h, v15.8h, v16.8h
	mul	v25.8h, v26.8h, v2.8h
	mul	v27.8h, v28.8h, v3.8h
	sqrdmulh	v14.8h, v26.8h, v0.8h
	sqrdmulh	v16.8h, v28.8h, v1.8h
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v14.8h, v25.8h, v8.h[0]
	sqrdmlsh	v16.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v14.8h, v14.8h, v25.8h
	sub	v16.8h, v16.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v14.8h, v14.8h, #1
	sshr	v16.8h, v16.8h, #1
	ldr	q0, [x2, #320]
	ldr	q1, [x2, #336]
	ldr	q2, [x3, #320]
	ldr	q3, [x3, #336]
	mov	v25.16b, v17.16b
	mov	v26.16b, v19.16b
	trn1	v17.4s, v17.4s, v18.4s
	trn1	v19.4s, v19.4s, v20.4s
	trn2	v18.4s, v25.4s, v18.4s
	trn2	v20.4s, v26.4s, v20.4s
	sub	v26.8h, v17.8h, v18.8h
	sub	v28.8h, v19.8h, v20.8h
	add	v17.8h, v17.8h, v18.8h
	add	v19.8h, v19.8h, v20.8h
	mul	v25.8h, v26.8h, v2.8h
	mul	v27.8h, v28.8h, v3.8h
	sqrdmulh	v18.8h, v26.8h, v0.8h
	sqrdmulh	v20.8h, v28.8h, v1.8h
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v18.8h, v25.8h, v8.h[0]
	sqrdmlsh	v20.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v18.8h, v18.8h, v25.8h
	sub	v20.8h, v20.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v18.8h, v18.8h, #1
	sshr	v20.8h, v20.8h, #1
	ldr	q0, [x2, #352]
	ldr	q1, [x2, #368]
	ldr	q2, [x3, #352]
	ldr	q3, [x3, #368]
	mov	v25.16b, v21.16b
	mov	v26.16b, v23.16b
	trn1	v21.4s, v21.4s, v22.4s
	trn1	v23.4s, v23.4s, v24.4s
	trn2	v22.4s, v25.4s, v22.4s
	trn2	v24.4s, v26.4s, v24.4s
	sub	v26.8h, v21.8h, v22.8h
	sub	v28.8h, v23.8h, v24.8h
	add	v21.8h, v21.8h, v22.8h
	add	v23.8h, v23.8h, v24.8h
	mul	v25.8h, v26.8h, v2.8h
	mul	v27.8h, v28.8h, v3.8h
	sqrdmulh	v22.8h, v26.8h, v0.8h
	sqrdmulh	v24.8h, v28.8h, v1.8h
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v22.8h, v25.8h, v8.h[0]
	sqrdmlsh	v24.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v22.8h, v22.8h, v25.8h
	sub	v24.8h, v24.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v22.8h, v22.8h, #1
	sshr	v24.8h, v24.8h, #1
	ldr	q0, [x2, #512]
	ldr	q2, [x3, #512]
	mov	v25.16b, v9.16b
	mov	v26.16b, v11.16b
	trn1	v9.2d, v9.2d, v10.2d
	trn1	v11.2d, v11.2d, v12.2d
	trn2	v10.2d, v25.2d, v10.2d
	trn2	v12.2d, v26.2d, v12.2d
	sub	v26.8h, v9.8h, v10.8h
	sub	v28.8h, v11.8h, v12.8h
	add	v9.8h, v9.8h, v10.8h
	add	v11.8h, v11.8h, v12.8h
	mul	v25.8h, v26.8h, v2.h[0]
	mul	v27.8h, v28.8h, v2.h[1]
	sqrdmulh	v10.8h, v26.8h, v0.h[0]
	sqrdmulh	v12.8h, v28.8h, v0.h[1]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v10.8h, v25.8h, v8.h[0]
	sqrdmlsh	v12.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v10.8h, v10.8h, v25.8h
	sub	v12.8h, v12.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v10.8h, v10.8h, #1
	sshr	v12.8h, v12.8h, #1
	mov	v25.16b, v13.16b
	mov	v26.16b, v15.16b
	trn1	v13.2d, v13.2d, v14.2d
	trn1	v15.2d, v15.2d, v16.2d
	trn2	v14.2d, v25.2d, v14.2d
	trn2	v16.2d, v26.2d, v16.2d
	sub	v26.8h, v13.8h, v14.8h
	sub	v28.8h, v15.8h, v16.8h
	add	v13.8h, v13.8h, v14.8h
	add	v15.8h, v15.8h, v16.8h
	mul	v25.8h, v26.8h, v2.h[2]
	mul	v27.8h, v28.8h, v2.h[3]
	sqrdmulh	v14.8h, v26.8h, v0.h[2]
	sqrdmulh	v16.8h, v28.8h, v0.h[3]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v14.8h, v25.8h, v8.h[0]
	sqrdmlsh	v16.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v14.8h, v14.8h, v25.8h
	sub	v16.8h, v16.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v14.8h, v14.8h, #1
	sshr	v16.8h, v16.8h, #1
	mov	v25.16b, v17.16b
	mov	v26.16b, v19.16b
	trn1	v17.2d, v17.2d, v18.2d
	trn1	v19.2d, v19.2d, v20.2d
	trn2	v18.2d, v25.2d, v18.2d
	trn2	v20.2d, v26.2d, v20.2d
	sub	v26.8h, v17.8h, v18.8h
	sub	v28.8h, v19.8h, v20.8h
	add	v17.8h, v17.8h, v18.8h
	add	v19.8h, v19.8h, v20.8h
	mul	v25.8h, v26.8h, v2.h[4]
	mul	v27.8h, v28.8h, v2.h[5]
	sqrdmulh	v18.8h, v26.8h, v0.h[4]
	sqrdmulh	v20.8h, v28.8h, v0.h[5]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v18.8h, v25.8h, v8.h[0]
	sqrdmlsh	v20.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v18.8h, v18.8h, v25.8h
	sub	v20.8h, v20.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v18.8h, v18.8h, #1
	sshr	v20.8h, v20.8h, #1
	mov	v25.16b, v21.16b
	mov	v26.16b, v23.16b
	trn1	v21.2d, v21.2d, v22.2d
	trn1	v23.2d, v23.2d, v24.2d
	trn2	v22.2d, v25.2d, v22.2d
	trn2	v24.2d, v26.2d, v24.2d
	sub	v26.8h, v21.8h, v22.8h
	sub	v28.8h, v23.8h, v24.8h
	add	v21.8h, v21.8h, v22.8h
	add	v23.8h, v23.8h, v24.8h
	mul	v25.8h, v26.8h, v2.h[6]
	mul	v27.8h, v28.8h, v2.h[7]
	sqrdmulh	v22.8h, v26.8h, v0.h[6]
	sqrdmulh	v24.8h, v28.8h, v0.h[7]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v22.8h, v25.8h, v8.h[0]
	sqrdmlsh	v24.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v22.8h, v22.8h, v25.8h
	sub	v24.8h, v24.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v22.8h, v22.8h, #1
	sshr	v24.8h, v24.8h, #1
	sqdmulh	v25.8h, v9.8h, v8.h[2]
	sqdmulh	v26.8h, v11.8h, v8.h[2]
	sshr	v25.8h, v25.8h, #11
	sshr	v26.8h, v26.8h, #11
	mls	v9.8h, v25.8h, v8.h[0]
	mls	v11.8h, v26.8h, v8.h[0]
	sqdmulh	v25.8h, v13.8h, v8.h[2]
	sqdmulh	v26.8h, v15.8h, v8.h[2]
	sshr	v25.8h, v25.8h, #11
	sshr	v26.8h, v26.8h, #11
	mls	v13.8h, v25.8h, v8.h[0]
	mls	v15.8h, v26.8h, v8.h[0]
	sqdmulh	v25.8h, v17.8h, v8.h[2]
	sqdmulh	v26.8h, v19.8h, v8.h[2]
	sshr	v25.8h, v25.8h, #11
	sshr	v26.8h, v26.8h, #11
	mls	v17.8h, v25.8h, v8.h[0]
	mls	v19.8h, v26.8h, v8.h[0]
	sqdmulh	v25.8h, v21.8h, v8.h[2]
	sqdmulh	v26.8h, v23.8h, v8.h[2]
	sshr	v25.8h, v25.8h, #11
	sshr	v26.8h, v26.8h, #11
	mls	v21.8h, v25.8h, v8.h[0]
	mls	v23.8h, v26.8h, v8.h[0]
	stp	q9, q10, [x0]
	stp	q11, q12, [x0, #32]
	stp	q13, q14, [x0, #64]
	stp	q15, q16, [x0, #96]
	stp	q17, q18, [x0, #128]
	stp	q19, q20, [x0, #160]
	stp	q21, q22, [x0, #192]
	stp	q23, q24, [x0, #224]
	ldp	q9, q10, [x1]
	ldp	q11, q12, [x1, #32]
	ldp	q13, q14, [x1, #64]
	ldp	q15, q16, [x1, #96]
	ldp	q17, q18, [x1, #128]
	ldp	q19, q20, [x1, #160]
	ldp	q21, q22, [x1, #192]
	ldp	q23, q24, [x1, #224]
	mov	v25.16b, v9.16b
	trn1	v9.2d, v9.2d, v10.2d
	trn2	v10.2d, v25.2d, v10.2d
	mov	v25.16b, v9.16b
	trn1	v9.4s, v9.4s, v10.4s
	trn2	v10.4s, v25.4s, v10.4s
	mov	v25.16b, v11.16b
	trn1	v11.2d, v11.2d, v12.2d
	trn2	v12.2d, v25.2d, v12.2d
	mov	v25.16b, v11.16b
	trn1	v11.4s, v11.4s, v12.4s
	trn2	v12.4s, v25.4s, v12.4s
	mov	v25.16b, v13.16b
	trn1	v13.2d, v13.2d, v14.2d
	trn2	v14.2d, v25.2d, v14.2d
	mov	v25.16b, v13.16b
	trn1	v13.4s, v13.4s, v14.4s
	trn2	v14.4s, v25.4s, v14.4s
	mov	v25.16b, v15.16b
	trn1	v15.2d, v15.2d, v16.2d
	trn2	v16.2d, v25.2d, v16.2d
	mov	v25.16b, v15.16b
	trn1	v15.4s, v15.4s, v16.4s
	trn2	v16.4s, v25.4s, v16.4s
	mov	v25.16b, v17.16b
	trn1	v17.2d, v17.2d, v18.2d
	trn2	v18.2d, v25.2d, v18.2d
	mov	v25.16b, v17.16b
	trn1	v17.4s, v17.4s, v18.4s
	trn2	v18.4s, v25.4s, v18.4s
	mov	v25.16b, v19.16b
	trn1	v19.2d, v19.2d, v20.2d
	trn2	v20.2d, v25.2d, v20.2d
	mov	v25.16b, v19.16b
	trn1	v19.4s, v19.4s, v20.4s
	trn2	v20.4s, v25.4s, v20.4s
	mov	v25.16b, v21.16b
	trn1	v21.2d, v21.2d, v22.2d
	trn2	v22.2d, v25.2d, v22.2d
	mov	v25.16b, v21.16b
	trn1	v21.4s, v21.4s, v22.4s
	trn2	v22.4s, v25.4s, v22.4s
	mov	v25.16b, v23.16b
	trn1	v23.2d, v23.2d, v24.2d
	trn2	v24.2d, v25.2d, v24.2d
	mov	v25.16b, v23.16b
	trn1	v23.4s, v23.4s, v24.4s
	trn2	v24.4s, v25.4s, v24.4s
	ldr	q0, [x2, #128]
	ldr	q1, [x2, #144]
	ldr	q2, [x3, #128]
	ldr	q3, [x3, #144]
	sub	v26.8h, v9.8h, v10.8h
	sub	v28.8h, v11.8h, v12.8h
	add	v9.8h, v9.8h, v10.8h
	add	v11.8h, v11.8h, v12.8h
	mul	v25.8h, v26.8h, v2.8h
	mul	v27.8h, v28.8h, v3.8h
	sqrdmulh	v10.8h, v26.8h, v0.8h
	sqrdmulh	v12.8h, v28.8h, v1.8h
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v10.8h, v25.8h, v8.h[0]
	sqrdmlsh	v12.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v10.8h, v10.8h, v25.8h
	sub	v12.8h, v12.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v10.8h, v10.8h, #1
	sshr	v12.8h, v12.8h, #1
	ldr	q0, [x2, #160]
	ldr	q1, [x2, #176]
	ldr	q2, [x3, #160]
	ldr	q3, [x3, #176]
	sub	v26.8h, v13.8h, v14.8h
	sub	v28.8h, v15.8h, v16.8h
	add	v13.8h, v13.8h, v14.8h
	add	v15.8h, v15.8h, v16.8h
	mul	v25.8h, v26.8h, v2.8h
	mul	v27.8h, v28.8h, v3.8h
	sqrdmulh	v14.8h, v26.8h, v0.8h
	sqrdmulh	v16.8h, v28.8h, v1.8h
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v14.8h, v25.8h, v8.h[0]
	sqrdmlsh	v16.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v14.8h, v14.8h, v25.8h
	sub	v16.8h, v16.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v14.8h, v14.8h, #1
	sshr	v16.8h, v16.8h, #1
	ldr	q0, [x2, #192]
	ldr	q1, [x2, #208]
	ldr	q2, [x3, #192]
	ldr	q3, [x3, #208]
	sub	v26.8h, v17.8h, v18.8h
	sub	v28.8h, v19.8h, v20.8h
	add	v17.8h, v17.8h, v18.8h
	add	v19.8h, v19.8h, v20.8h
	mul	v25.8h, v26.8h, v2.8h
	mul	v27.8h, v28.8h, v3.8h
	sqrdmulh	v18.8h, v26.8h, v0.8h
	sqrdmulh	v20.8h, v28.8h, v1.8h
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v18.8h, v25.8h, v8.h[0]
	sqrdmlsh	v20.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v18.8h, v18.8h, v25.8h
	sub	v20.8h, v20.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v18.8h, v18.8h, #1
	sshr	v20.8h, v20.8h, #1
	ldr	q0, [x2, #224]
	ldr	q1, [x2, #240]
	ldr	q2, [x3, #224]
	ldr	q3, [x3, #240]
	sub	v26.8h, v21.8h, v22.8h
	sub	v28.8h, v23.8h, v24.8h
	add	v21.8h, v21.8h, v22.8h
	add	v23.8h, v23.8h, v24.8h
	mul	v25.8h, v26.8h, v2.8h
	mul	v27.8h, v28.8h, v3.8h
	sqrdmulh	v22.8h, v26.8h, v0.8h
	sqrdmulh	v24.8h, v28.8h, v1.8h
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v22.8h, v25.8h, v8.h[0]
	sqrdmlsh	v24.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v22.8h, v22.8h, v25.8h
	sub	v24.8h, v24.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v22.8h, v22.8h, #1
	sshr	v24.8h, v24.8h, #1
	ldr	q0, [x2, #384]
	ldr	q1, [x2, #400]
	ldr	q2, [x3, #384]
	ldr	q3, [x3, #400]
	mov	v25.16b, v9.16b
	mov	v26.16b, v11.16b
	trn1	v9.4s, v9.4s, v10.4s
	trn1	v11.4s, v11.4s, v12.4s
	trn2	v10.4s, v25.4s, v10.4s
	trn2	v12.4s, v26.4s, v12.4s
	sub	v26.8h, v9.8h, v10.8h
	sub	v28.8h, v11.8h, v12.8h
	add	v9.8h, v9.8h, v10.8h
	add	v11.8h, v11.8h, v12.8h
	mul	v25.8h, v26.8h, v2.8h
	mul	v27.8h, v28.8h, v3.8h
	sqrdmulh	v10.8h, v26.8h, v0.8h
	sqrdmulh	v12.8h, v28.8h, v1.8h
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v10.8h, v25.8h, v8.h[0]
	sqrdmlsh	v12.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v10.8h, v10.8h, v25.8h
	sub	v12.8h, v12.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v10.8h, v10.8h, #1
	sshr	v12.8h, v12.8h, #1
	ldr	q0, [x2, #416]
	ldr	q1, [x2, #432]
	ldr	q2, [x3, #416]
	ldr	q3, [x3, #432]
	mov	v25.16b, v13.16b
	mov	v26.16b, v15.16b
	trn1	v13.4s, v13.4s, v14.4s
	trn1	v15.4s, v15.4s, v16.4s
	trn2	v14.4s, v25.4s, v14.4s
	trn2	v16.4s, v26.4s, v16.4s
	sub	v26.8h, v13.8h, v14.8h
	sub	v28.8h, v15.8h, v16.8h
	add	v13.8h, v13.8h, v14.8h
	add	v15.8h, v15.8h, v16.8h
	mul	v25.8h, v26.8h, v2.8h
	mul	v27.8h, v28.8h, v3.8h
	sqrdmulh	v14.8h, v26.8h, v0.8h
	sqrdmulh	v16.8h, v28.8h, v1.8h
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v14.8h, v25.8h, v8.h[0]
	sqrdmlsh	v16.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v14.8h, v14.8h, v25.8h
	sub	v16.8h, v16.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v14.8h, v14.8h, #1
	sshr	v16.8h, v16.8h, #1
	ldr	q0, [x2, #448]
	ldr	q1, [x2, #464]
	ldr	q2, [x3, #448]
	ldr	q3, [x3, #464]
	mov	v25.16b, v17.16b
	mov	v26.16b, v19.16b
	trn1	v17.4s, v17.4s, v18.4s
	trn1	v19.4s, v19.4s, v20.4s
	trn2	v18.4s, v25.4s, v18.4s
	trn2	v20.4s, v26.4s, v20.4s
	sub	v26.8h, v17.8h, v18.8h
	sub	v28.8h, v19.8h, v20.8h
	add	v17.8h, v17.8h, v18.8h
	add	v19.8h, v19.8h, v20.8h
	mul	v25.8h, v26.8h, v2.8h
	mul	v27.8h, v28.8h, v3.8h
	sqrdmulh	v18.8h, v26.8h, v0.8h
	sqrdmulh	v20.8h, v28.8h, v1.8h
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v18.8h, v25.8h, v8.h[0]
	sqrdmlsh	v20.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v18.8h, v18.8h, v25.8h
	sub	v20.8h, v20.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v18.8h, v18.8h, #1
	sshr	v20.8h, v20.8h, #1
	ldr	q0, [x2, #480]
	ldr	q1, [x2, #496]
	ldr	q2, [x3, #480]
	ldr	q3, [x3, #496]
	mov	v25.16b, v21.16b
	mov	v26.16b, v23.16b
	trn1	v21.4s, v21.4s, v22.4s
	trn1	v23.4s, v23.4s, v24.4s
	trn2	v22.4s, v25.4s, v22.4s
	trn2	v24.4s, v26.4s, v24.4s
	sub	v26.8h, v21.8h, v22.8h
	sub	v28.8h, v23.8h, v24.8h
	add	v21.8h, v21.8h, v22.8h
	add	v23.8h, v23.8h, v24.8h
	mul	v25.8h, v26.8h, v2.8h
	mul	v27.8h, v28.8h, v3.8h
	sqrdmulh	v22.8h, v26.8h, v0.8h
	sqrdmulh	v24.8h, v28.8h, v1.8h
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v22.8h, v25.8h, v8.h[0]
	sqrdmlsh	v24.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v22.8h, v22.8h, v25.8h
	sub	v24.8h, v24.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v22.8h, v22.8h, #1
	sshr	v24.8h, v24.8h, #1
	ldr	q0, [x2, #528]
	ldr	q2, [x3, #528]
	mov	v25.16b, v9.16b
	mov	v26.16b, v11.16b
	trn1	v9.2d, v9.2d, v10.2d
	trn1	v11.2d, v11.2d, v12.2d
	trn2	v10.2d, v25.2d, v10.2d
	trn2	v12.2d, v26.2d, v12.2d
	sub	v26.8h, v9.8h, v10.8h
	sub	v28.8h, v11.8h, v12.8h
	add	v9.8h, v9.8h, v10.8h
	add	v11.8h, v11.8h, v12.8h
	mul	v25.8h, v26.8h, v2.h[0]
	mul	v27.8h, v28.8h, v2.h[1]
	sqrdmulh	v10.8h, v26.8h, v0.h[0]
	sqrdmulh	v12.8h, v28.8h, v0.h[1]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v10.8h, v25.8h, v8.h[0]
	sqrdmlsh	v12.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v10.8h, v10.8h, v25.8h
	sub	v12.8h, v12.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v10.8h, v10.8h, #1
	sshr	v12.8h, v12.8h, #1
	mov	v25.16b, v13.16b
	mov	v26.16b, v15.16b
	trn1	v13.2d, v13.2d, v14.2d
	trn1	v15.2d, v15.2d, v16.2d
	trn2	v14.2d, v25.2d, v14.2d
	trn2	v16.2d, v26.2d, v16.2d
	sub	v26.8h, v13.8h, v14.8h
	sub	v28.8h, v15.8h, v16.8h
	add	v13.8h, v13.8h, v14.8h
	add	v15.8h, v15.8h, v16.8h
	mul	v25.8h, v26.8h, v2.h[2]
	mul	v27.8h, v28.8h, v2.h[3]
	sqrdmulh	v14.8h, v26.8h, v0.h[2]
	sqrdmulh	v16.8h, v28.8h, v0.h[3]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v14.8h, v25.8h, v8.h[0]
	sqrdmlsh	v16.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v14.8h, v14.8h, v25.8h
	sub	v16.8h, v16.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v14.8h, v14.8h, #1
	sshr	v16.8h, v16.8h, #1
	mov	v25.16b, v17.16b
	mov	v26.16b, v19.16b
	trn1	v17.2d, v17.2d, v18.2d
	trn1	v19.2d, v19.2d, v20.2d
	trn2	v18.2d, v25.2d, v18.2d
	trn2	v20.2d, v26.2d, v20.2d
	sub	v26.8h, v17.8h, v18.8h
	sub	v28.8h, v19.8h, v20.8h
	add	v17.8h, v17.8h, v18.8h
	add	v19.8h, v19.8h, v20.8h
	mul	v25.8h, v26.8h, v2.h[4]
	mul	v27.8h, v28.8h, v2.h[5]
	sqrdmulh	v18.8h, v26.8h, v0.h[4]
	sqrdmulh	v20.8h, v28.8h, v0.h[5]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v18.8h, v25.8h, v8.h[0]
	sqrdmlsh	v20.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v18.8h, v18.8h, v25.8h
	sub	v20.8h, v20.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v18.8h, v18.8h, #1
	sshr	v20.8h, v20.8h, #1
	mov	v25.16b, v21.16b
	mov	v26.16b, v23.16b
	trn1	v21.2d, v21.2d, v22.2d
	trn1	v23.2d, v23.2d, v24.2d
	trn2	v22.2d, v25.2d, v22.2d
	trn2	v24.2d, v26.2d, v24.2d
	sub	v26.8h, v21.8h, v22.8h
	sub	v28.8h, v23.8h, v24.8h
	add	v21.8h, v21.8h, v22.8h
	add	v23.8h, v23.8h, v24.8h
	mul	v25.8h, v26.8h, v2.h[6]
	mul	v27.8h, v28.8h, v2.h[7]
	sqrdmulh	v22.8h, v26.8h, v0.h[6]
	sqrdmulh	v24.8h, v28.8h, v0.h[7]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v22.8h, v25.8h, v8.h[0]
	sqrdmlsh	v24.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v22.8h, v22.8h, v25.8h
	sub	v24.8h, v24.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v22.8h, v22.8h, #1
	sshr	v24.8h, v24.8h, #1
	sqdmulh	v25.8h, v9.8h, v8.h[2]
	sqdmulh	v26.8h, v11.8h, v8.h[2]
	sshr	v25.8h, v25.8h, #11
	sshr	v26.8h, v26.8h, #11
	mls	v9.8h, v25.8h, v8.h[0]
	mls	v11.8h, v26.8h, v8.h[0]
	sqdmulh	v25.8h, v13.8h, v8.h[2]
	sqdmulh	v26.8h, v15.8h, v8.h[2]
	sshr	v25.8h, v25.8h, #11
	sshr	v26.8h, v26.8h, #11
	mls	v13.8h, v25.8h, v8.h[0]
	mls	v15.8h, v26.8h, v8.h[0]
	sqdmulh	v25.8h, v17.8h, v8.h[2]
	sqdmulh	v26.8h, v19.8h, v8.h[2]
	sshr	v25.8h, v25.8h, #11
	sshr	v26.8h, v26.8h, #11
	mls	v17.8h, v25.8h, v8.h[0]
	mls	v19.8h, v26.8h, v8.h[0]
	sqdmulh	v25.8h, v21.8h, v8.h[2]
	sqdmulh	v26.8h, v23.8h, v8.h[2]
	sshr	v25.8h, v25.8h, #11
	sshr	v26.8h, v26.8h, #11
	mls	v21.8h, v25.8h, v8.h[0]
	mls	v23.8h, v26.8h, v8.h[0]
	stp	q9, q10, [x1]
	stp	q11, q12, [x1, #32]
	stp	q13, q14, [x1, #64]
	stp	q15, q16, [x1, #96]
	stp	q17, q18, [x1, #128]
	stp	q19, q20, [x1, #160]
	stp	q21, q22, [x1, #192]
	stp	q23, q24, [x1, #224]
	ldr	q4, [x2, #544]
	ldr	q5, [x2, #560]
	ldr	q6, [x3, #544]
	ldr	q7, [x3, #560]
	ldr	q9, [x0]
	ldr	q10, [x0, #32]
	ldr	q11, [x0, #64]
	ldr	q12, [x0, #96]
	ldr	q13, [x0, #128]
	ldr	q14, [x0, #160]
	ldr	q15, [x0, #192]
	ldr	q16, [x0, #224]
	ldr	q17, [x1]
	ldr	q18, [x1, #32]
	ldr	q19, [x1, #64]
	ldr	q20, [x1, #96]
	ldr	q21, [x1, #128]
	ldr	q22, [x1, #160]
	ldr	q23, [x1, #192]
	ldr	q24, [x1, #224]
	sub	v26.8h, v9.8h, v10.8h
	sub	v28.8h, v11.8h, v12.8h
	add	v9.8h, v9.8h, v10.8h
	add	v11.8h, v11.8h, v12.8h
	mul	v25.8h, v26.8h, v6.h[0]
	mul	v27.8h, v28.8h, v6.h[1]
	sqrdmulh	v10.8h, v26.8h, v4.h[0]
	sqrdmulh	v12.8h, v28.8h, v4.h[1]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v10.8h, v25.8h, v8.h[0]
	sqrdmlsh	v12.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v10.8h, v10.8h, v25.8h
	sub	v12.8h, v12.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v10.8h, v10.8h, #1
	sshr	v12.8h, v12.8h, #1
	sub	v26.8h, v13.8h, v14.8h
	sub	v28.8h, v15.8h, v16.8h
	add	v13.8h, v13.8h, v14.8h
	add	v15.8h, v15.8h, v16.8h
	mul	v25.8h, v26.8h, v6.h[2]
	mul	v27.8h, v28.8h, v6.h[3]
	sqrdmulh	v14.8h, v26.8h, v4.h[2]
	sqrdmulh	v16.8h, v28.8h, v4.h[3]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v14.8h, v25.8h, v8.h[0]
	sqrdmlsh	v16.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v14.8h, v14.8h, v25.8h
	sub	v16.8h, v16.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v14.8h, v14.8h, #1
	sshr	v16.8h, v16.8h, #1
	sub	v26.8h, v17.8h, v18.8h
	sub	v28.8h, v19.8h, v20.8h
	add	v17.8h, v17.8h, v18.8h
	add	v19.8h, v19.8h, v20.8h
	mul	v25.8h, v26.8h, v6.h[4]
	mul	v27.8h, v28.8h, v6.h[5]
	sqrdmulh	v18.8h, v26.8h, v4.h[4]
	sqrdmulh	v20.8h, v28.8h, v4.h[5]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v18.8h, v25.8h, v8.h[0]
	sqrdmlsh	v20.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v18.8h, v18.8h, v25.8h
	sub	v20.8h, v20.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v18.8h, v18.8h, #1
	sshr	v20.8h, v20.8h, #1
	sub	v26.8h, v21.8h, v22.8h
	sub	v28.8h, v23.8h, v24.8h
	add	v21.8h, v21.8h, v22.8h
	add	v23.8h, v23.8h, v24.8h
	mul	v25.8h, v26.8h, v6.h[6]
	mul	v27.8h, v28.8h, v6.h[7]
	sqrdmulh	v22.8h, v26.8h, v4.h[6]
	sqrdmulh	v24.8h, v28.8h, v4.h[7]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v22.8h, v25.8h, v8.h[0]
	sqrdmlsh	v24.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v22.8h, v22.8h, v25.8h
	sub	v24.8h, v24.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v22.8h, v22.8h, #1
	sshr	v24.8h, v24.8h, #1
	sub	v26.8h, v9.8h, v11.8h
	sub	v28.8h, v10.8h, v12.8h
	add	v9.8h, v9.8h, v11.8h
	add	v10.8h, v10.8h, v12.8h
	mul	v25.8h, v26.8h, v7.h[0]
	mul	v27.8h, v28.8h, v7.h[0]
	sqrdmulh	v11.8h, v26.8h, v5.h[0]
	sqrdmulh	v12.8h, v28.8h, v5.h[0]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v11.8h, v25.8h, v8.h[0]
	sqrdmlsh	v12.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v11.8h, v11.8h, v25.8h
	sub	v12.8h, v12.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v11.8h, v11.8h, #1
	sshr	v12.8h, v12.8h, #1
	sub	v26.8h, v13.8h, v15.8h
	sub	v28.8h, v14.8h, v16.8h
	add	v13.8h, v13.8h, v15.8h
	add	v14.8h, v14.8h, v16.8h
	mul	v25.8h, v26.8h, v7.h[1]
	mul	v27.8h, v28.8h, v7.h[1]
	sqrdmulh	v15.8h, v26.8h, v5.h[1]
	sqrdmulh	v16.8h, v28.8h, v5.h[1]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v15.8h, v25.8h, v8.h[0]
	sqrdmlsh	v16.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v15.8h, v15.8h, v25.8h
	sub	v16.8h, v16.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v15.8h, v15.8h, #1
	sshr	v16.8h, v16.8h, #1
	sub	v26.8h, v17.8h, v19.8h
	sub	v28.8h, v18.8h, v20.8h
	add	v17.8h, v17.8h, v19.8h
	add	v18.8h, v18.8h, v20.8h
	mul	v25.8h, v26.8h, v7.h[2]
	mul	v27.8h, v28.8h, v7.h[2]
	sqrdmulh	v19.8h, v26.8h, v5.h[2]
	sqrdmulh	v20.8h, v28.8h, v5.h[2]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v19.8h, v25.8h, v8.h[0]
	sqrdmlsh	v20.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v19.8h, v19.8h, v25.8h
	sub	v20.8h, v20.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v19.8h, v19.8h, #1
	sshr	v20.8h, v20.8h, #1
	sub	v26.8h, v21.8h, v23.8h
	sub	v28.8h, v22.8h, v24.8h
	add	v21.8h, v21.8h, v23.8h
	add	v22.8h, v22.8h, v24.8h
	mul	v25.8h, v26.8h, v7.h[3]
	mul	v27.8h, v28.8h, v7.h[3]
	sqrdmulh	v23.8h, v26.8h, v5.h[3]
	sqrdmulh	v24.8h, v28.8h, v5.h[3]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v23.8h, v25.8h, v8.h[0]
	sqrdmlsh	v24.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v23.8h, v23.8h, v25.8h
	sub	v24.8h, v24.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v23.8h, v23.8h, #1
	sshr	v24.8h, v24.8h, #1
	sub	v26.8h, v9.8h, v13.8h
	sub	v28.8h, v10.8h, v14.8h
	add	v9.8h, v9.8h, v13.8h
	add	v10.8h, v10.8h, v14.8h
	mul	v25.8h, v26.8h, v7.h[4]
	mul	v27.8h, v28.8h, v7.h[4]
	sqrdmulh	v13.8h, v26.8h, v5.h[4]
	sqrdmulh	v14.8h, v28.8h, v5.h[4]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v13.8h, v25.8h, v8.h[0]
	sqrdmlsh	v14.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v13.8h, v13.8h, v25.8h
	sub	v14.8h, v14.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v13.8h, v13.8h, #1
	sshr	v14.8h, v14.8h, #1
	sub	v26.8h, v11.8h, v15.8h
	sub	v28.8h, v12.8h, v16.8h
	add	v11.8h, v11.8h, v15.8h
	add	v12.8h, v12.8h, v16.8h
	mul	v25.8h, v26.8h, v7.h[4]
	mul	v27.8h, v28.8h, v7.h[4]
	sqrdmulh	v15.8h, v26.8h, v5.h[4]
	sqrdmulh	v16.8h, v28.8h, v5.h[4]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v15.8h, v25.8h, v8.h[0]
	sqrdmlsh	v16.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v15.8h, v15.8h, v25.8h
	sub	v16.8h, v16.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v15.8h, v15.8h, #1
	sshr	v16.8h, v16.8h, #1
	sub	v26.8h, v17.8h, v21.8h
	sub	v28.8h, v18.8h, v22.8h
	add	v17.8h, v17.8h, v21.8h
	add	v18.8h, v18.8h, v22.8h
	mul	v25.8h, v26.8h, v7.h[5]
	mul	v27.8h, v28.8h, v7.h[5]
	sqrdmulh	v21.8h, v26.8h, v5.h[5]
	sqrdmulh	v22.8h, v28.8h, v5.h[5]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v21.8h, v25.8h, v8.h[0]
	sqrdmlsh	v22.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v21.8h, v21.8h, v25.8h
	sub	v22.8h, v22.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v21.8h, v21.8h, #1
	sshr	v22.8h, v22.8h, #1
	sub	v26.8h, v19.8h, v23.8h
	sub	v28.8h, v20.8h, v24.8h
	add	v19.8h, v19.8h, v23.8h
	add	v20.8h, v20.8h, v24.8h
	mul	v25.8h, v26.8h, v7.h[5]
	mul	v27.8h, v28.8h, v7.h[5]
	sqrdmulh	v23.8h, v26.8h, v5.h[5]
	sqrdmulh	v24.8h, v28.8h, v5.h[5]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v23.8h, v25.8h, v8.h[0]
	sqrdmlsh	v24.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v23.8h, v23.8h, v25.8h
	sub	v24.8h, v24.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v23.8h, v23.8h, #1
	sshr	v24.8h, v24.8h, #1
	sqdmulh	v25.8h, v9.8h, v8.h[2]
	sqdmulh	v26.8h, v10.8h, v8.h[2]
	sshr	v25.8h, v25.8h, #11
	sshr	v26.8h, v26.8h, #11
	mls	v9.8h, v25.8h, v8.h[0]
	mls	v10.8h, v26.8h, v8.h[0]
	sqdmulh	v25.8h, v11.8h, v8.h[2]
	sqdmulh	v26.8h, v12.8h, v8.h[2]
	sshr	v25.8h, v25.8h, #11
	sshr	v26.8h, v26.8h, #11
	mls	v11.8h, v25.8h, v8.h[0]
	mls	v12.8h, v26.8h, v8.h[0]
	sqdmulh	v25.8h, v17.8h, v8.h[2]
	sqdmulh	v26.8h, v18.8h, v8.h[2]
	sshr	v25.8h, v25.8h, #11
	sshr	v26.8h, v26.8h, #11
	mls	v17.8h, v25.8h, v8.h[0]
	mls	v18.8h, v26.8h, v8.h[0]
	sqdmulh	v25.8h, v19.8h, v8.h[2]
	sqdmulh	v26.8h, v20.8h, v8.h[2]
	sshr	v25.8h, v25.8h, #11
	sshr	v26.8h, v26.8h, #11
	mls	v19.8h, v25.8h, v8.h[0]
	mls	v20.8h, v26.8h, v8.h[0]
	sub	v26.8h, v9.8h, v17.8h
	sub	v28.8h, v10.8h, v18.8h
	add	v9.8h, v9.8h, v17.8h
	add	v10.8h, v10.8h, v18.8h
	mul	v25.8h, v26.8h, v7.h[6]
	mul	v27.8h, v28.8h, v7.h[6]
	sqrdmulh	v17.8h, v26.8h, v5.h[6]
	sqrdmulh	v18.8h, v28.8h, v5.h[6]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v17.8h, v25.8h, v8.h[0]
	sqrdmlsh	v18.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v17.8h, v17.8h, v25.8h
	sub	v18.8h, v18.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v17.8h, v17.8h, #1
	sshr	v18.8h, v18.8h, #1
	sub	v26.8h, v11.8h, v19.8h
	sub	v28.8h, v12.8h, v20.8h
	add	v11.8h, v11.8h, v19.8h
	add	v12.8h, v12.8h, v20.8h
	mul	v25.8h, v26.8h, v7.h[6]
	mul	v27.8h, v28.8h, v7.h[6]
	sqrdmulh	v19.8h, v26.8h, v5.h[6]
	sqrdmulh	v20.8h, v28.8h, v5.h[6]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v19.8h, v25.8h, v8.h[0]
	sqrdmlsh	v20.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v19.8h, v19.8h, v25.8h
	sub	v20.8h, v20.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v19.8h, v19.8h, #1
	sshr	v20.8h, v20.8h, #1
	sub	v26.8h, v13.8h, v21.8h
	sub	v28.8h, v14.8h, v22.8h
	add	v13.8h, v13.8h, v21.8h
	add	v14.8h, v14.8h, v22.8h
	mul	v25.8h, v26.8h, v7.h[6]
	mul	v27.8h, v28.8h, v7.h[6]
	sqrdmulh	v21.8h, v26.8h, v5.h[6]
	sqrdmulh	v22.8h, v28.8h, v5.h[6]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v21.8h, v25.8h, v8.h[0]
	sqrdmlsh	v22.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v21.8h, v21.8h, v25.8h
	sub	v22.8h, v22.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v21.8h, v21.8h, #1
	sshr	v22.8h, v22.8h, #1
	sub	v26.8h, v15.8h, v23.8h
	sub	v28.8h, v16.8h, v24.8h
	add	v15.8h, v15.8h, v23.8h
	add	v16.8h, v16.8h, v24.8h
	mul	v25.8h, v26.8h, v7.h[6]
	mul	v27.8h, v28.8h, v7.h[6]
	sqrdmulh	v23.8h, v26.8h, v5.h[6]
	sqrdmulh	v24.8h, v28.8h, v5.h[6]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v23.8h, v25.8h, v8.h[0]
	sqrdmlsh	v24.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v23.8h, v23.8h, v25.8h
	sub	v24.8h, v24.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v23.8h, v23.8h, #1
	sshr	v24.8h, v24.8h, #1
	mul	v25.8h, v9.8h, v7.h[7]
	mul	v26.8h, v10.8h, v7.h[7]
	sqrdmulh	v9.8h, v9.8h, v5.h[7]
	sqrdmulh	v10.8h, v10.8h, v5.h[7]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v9.8h, v25.8h, v8.h[0]
	sqrdmlsh	v10.8h, v26.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v26.8h, v26.8h, v8.h[0]
	sub	v9.8h, v9.8h, v25.8h
	sub	v10.8h, v10.8h, v26.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v9.8h, v9.8h, #1
	sshr	v10.8h, v10.8h, #1
	mul	v25.8h, v11.8h, v7.h[7]
	mul	v26.8h, v12.8h, v7.h[7]
	sqrdmulh	v11.8h, v11.8h, v5.h[7]
	sqrdmulh	v12.8h, v12.8h, v5.h[7]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v11.8h, v25.8h, v8.h[0]
	sqrdmlsh	v12.8h, v26.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v26.8h, v26.8h, v8.h[0]
	sub	v11.8h, v11.8h, v25.8h
	sub	v12.8h, v12.8h, v26.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v11.8h, v11.8h, #1
	sshr	v12.8h, v12.8h, #1
	mul	v25.8h, v13.8h, v7.h[7]
	mul	v26.8h, v14.8h, v7.h[7]
	sqrdmulh	v13.8h, v13.8h, v5.h[7]
	sqrdmulh	v14.8h, v14.8h, v5.h[7]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v13.8h, v25.8h, v8.h[0]
	sqrdmlsh	v14.8h, v26.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v26.8h, v26.8h, v8.h[0]
	sub	v13.8h, v13.8h, v25.8h
	sub	v14.8h, v14.8h, v26.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v13.8h, v13.8h, #1
	sshr	v14.8h, v14.8h, #1
	mul	v25.8h, v15.8h, v7.h[7]
	mul	v26.8h, v16.8h, v7.h[7]
	sqrdmulh	v15.8h, v15.8h, v5.h[7]
	sqrdmulh	v16.8h, v16.8h, v5.h[7]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v15.8h, v25.8h, v8.h[0]
	sqrdmlsh	v16.8h, v26.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v26.8h, v26.8h, v8.h[0]
	sub	v15.8h, v15.8h, v25.8h
	sub	v16.8h, v16.8h, v26.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v15.8h, v15.8h, #1
	sshr	v16.8h, v16.8h, #1
	mul	v25.8h, v17.8h, v7.h[7]
	mul	v26.8h, v18.8h, v7.h[7]
	sqrdmulh	v17.8h, v17.8h, v5.h[7]
	sqrdmulh	v18.8h, v18.8h, v5.h[7]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v17.8h, v25.8h, v8.h[0]
	sqrdmlsh	v18.8h, v26.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v26.8h, v26.8h, v8.h[0]
	sub	v17.8h, v17.8h, v25.8h
	sub	v18.8h, v18.8h, v26.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v17.8h, v17.8h, #1
	sshr	v18.8h, v18.8h, #1
	mul	v25.8h, v19.8h, v7.h[7]
	mul	v26.8h, v20.8h, v7.h[7]
	sqrdmulh	v19.8h, v19.8h, v5.h[7]
	sqrdmulh	v20.8h, v20.8h, v5.h[7]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v19.8h, v25.8h, v8.h[0]
	sqrdmlsh	v20.8h, v26.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v26.8h, v26.8h, v8.h[0]
	sub	v19.8h, v19.8h, v25.8h
	sub	v20.8h, v20.8h, v26.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v19.8h, v19.8h, #1
	sshr	v20.8h, v20.8h, #1
	mul	v25.8h, v21.8h, v7.h[7]
	mul	v26.8h, v22.8h, v7.h[7]
	sqrdmulh	v21.8h, v21.8h, v5.h[7]
	sqrdmulh	v22.8h, v22.8h, v5.h[7]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v21.8h, v25.8h, v8.h[0]
	sqrdmlsh	v22.8h, v26.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v26.8h, v26.8h, v8.h[0]
	sub	v21.8h, v21.8h, v25.8h
	sub	v22.8h, v22.8h, v26.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v21.8h, v21.8h, #1
	sshr	v22.8h, v22.8h, #1
	mul	v25.8h, v23.8h, v7.h[7]
	mul	v26.8h, v24.8h, v7.h[7]
	sqrdmulh	v23.8h, v23.8h, v5.h[7]
	sqrdmulh	v24.8h, v24.8h, v5.h[7]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v23.8h, v25.8h, v8.h[0]
	sqrdmlsh	v24.8h, v26.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v26.8h, v26.8h, v8.h[0]
	sub	v23.8h, v23.8h, v25.8h
	sub	v24.8h, v24.8h, v26.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v23.8h, v23.8h, #1
	sshr	v24.8h, v24.8h, #1
	str	q9, [x0]
	str	q10, [x0, #32]
	str	q11, [x0, #64]
	str	q12, [x0, #96]
	str	q13, [x0, #128]
	str	q14, [x0, #160]
	str	q15, [x0, #192]
	str	q16, [x0, #224]
	str	q17, [x1]
	str	q18, [x1, #32]
	str	q19, [x1, #64]
	str	q20, [x1, #96]
	str	q21, [x1, #128]
	str	q22, [x1, #160]
	str	q23, [x1, #192]
	str	q24, [x1, #224]
	ldr	q9, [x0, #16]
	ldr	q10, [x0, #48]
	ldr	q11, [x0, #80]
	ldr	q12, [x0, #112]
	ldr	q13, [x0, #144]
	ldr	q14, [x0, #176]
	ldr	q15, [x0, #208]
	ldr	q16, [x0, #240]
	ldr	q17, [x1, #16]
	ldr	q18, [x1, #48]
	ldr	q19, [x1, #80]
	ldr	q20, [x1, #112]
	ldr	q21, [x1, #144]
	ldr	q22, [x1, #176]
	ldr	q23, [x1, #208]
	ldr	q24, [x1, #240]
	sub	v26.8h, v9.8h, v10.8h
	sub	v28.8h, v11.8h, v12.8h
	add	v9.8h, v9.8h, v10.8h
	add	v11.8h, v11.8h, v12.8h
	mul	v25.8h, v26.8h, v6.h[0]
	mul	v27.8h, v28.8h, v6.h[1]
	sqrdmulh	v10.8h, v26.8h, v4.h[0]
	sqrdmulh	v12.8h, v28.8h, v4.h[1]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v10.8h, v25.8h, v8.h[0]
	sqrdmlsh	v12.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v10.8h, v10.8h, v25.8h
	sub	v12.8h, v12.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v10.8h, v10.8h, #1
	sshr	v12.8h, v12.8h, #1
	sub	v26.8h, v13.8h, v14.8h
	sub	v28.8h, v15.8h, v16.8h
	add	v13.8h, v13.8h, v14.8h
	add	v15.8h, v15.8h, v16.8h
	mul	v25.8h, v26.8h, v6.h[2]
	mul	v27.8h, v28.8h, v6.h[3]
	sqrdmulh	v14.8h, v26.8h, v4.h[2]
	sqrdmulh	v16.8h, v28.8h, v4.h[3]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v14.8h, v25.8h, v8.h[0]
	sqrdmlsh	v16.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v14.8h, v14.8h, v25.8h
	sub	v16.8h, v16.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v14.8h, v14.8h, #1
	sshr	v16.8h, v16.8h, #1
	sub	v26.8h, v17.8h, v18.8h
	sub	v28.8h, v19.8h, v20.8h
	add	v17.8h, v17.8h, v18.8h
	add	v19.8h, v19.8h, v20.8h
	mul	v25.8h, v26.8h, v6.h[4]
	mul	v27.8h, v28.8h, v6.h[5]
	sqrdmulh	v18.8h, v26.8h, v4.h[4]
	sqrdmulh	v20.8h, v28.8h, v4.h[5]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v18.8h, v25.8h, v8.h[0]
	sqrdmlsh	v20.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v18.8h, v18.8h, v25.8h
	sub	v20.8h, v20.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v18.8h, v18.8h, #1
	sshr	v20.8h, v20.8h, #1
	sub	v26.8h, v21.8h, v22.8h
	sub	v28.8h, v23.8h, v24.8h
	add	v21.8h, v21.8h, v22.8h
	add	v23.8h, v23.8h, v24.8h
	mul	v25.8h, v26.8h, v6.h[6]
	mul	v27.8h, v28.8h, v6.h[7]
	sqrdmulh	v22.8h, v26.8h, v4.h[6]
	sqrdmulh	v24.8h, v28.8h, v4.h[7]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v22.8h, v25.8h, v8.h[0]
	sqrdmlsh	v24.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v22.8h, v22.8h, v25.8h
	sub	v24.8h, v24.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v22.8h, v22.8h, #1
	sshr	v24.8h, v24.8h, #1
	sub	v26.8h, v9.8h, v11.8h
	sub	v28.8h, v10.8h, v12.8h
	add	v9.8h, v9.8h, v11.8h
	add	v10.8h, v10.8h, v12.8h
	mul	v25.8h, v26.8h, v7.h[0]
	mul	v27.8h, v28.8h, v7.h[0]
	sqrdmulh	v11.8h, v26.8h, v5.h[0]
	sqrdmulh	v12.8h, v28.8h, v5.h[0]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v11.8h, v25.8h, v8.h[0]
	sqrdmlsh	v12.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v11.8h, v11.8h, v25.8h
	sub	v12.8h, v12.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v11.8h, v11.8h, #1
	sshr	v12.8h, v12.8h, #1
	sub	v26.8h, v13.8h, v15.8h
	sub	v28.8h, v14.8h, v16.8h
	add	v13.8h, v13.8h, v15.8h
	add	v14.8h, v14.8h, v16.8h
	mul	v25.8h, v26.8h, v7.h[1]
	mul	v27.8h, v28.8h, v7.h[1]
	sqrdmulh	v15.8h, v26.8h, v5.h[1]
	sqrdmulh	v16.8h, v28.8h, v5.h[1]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v15.8h, v25.8h, v8.h[0]
	sqrdmlsh	v16.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v15.8h, v15.8h, v25.8h
	sub	v16.8h, v16.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v15.8h, v15.8h, #1
	sshr	v16.8h, v16.8h, #1
	sub	v26.8h, v17.8h, v19.8h
	sub	v28.8h, v18.8h, v20.8h
	add	v17.8h, v17.8h, v19.8h
	add	v18.8h, v18.8h, v20.8h
	mul	v25.8h, v26.8h, v7.h[2]
	mul	v27.8h, v28.8h, v7.h[2]
	sqrdmulh	v19.8h, v26.8h, v5.h[2]
	sqrdmulh	v20.8h, v28.8h, v5.h[2]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v19.8h, v25.8h, v8.h[0]
	sqrdmlsh	v20.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v19.8h, v19.8h, v25.8h
	sub	v20.8h, v20.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v19.8h, v19.8h, #1
	sshr	v20.8h, v20.8h, #1
	sub	v26.8h, v21.8h, v23.8h
	sub	v28.8h, v22.8h, v24.8h
	add	v21.8h, v21.8h, v23.8h
	add	v22.8h, v22.8h, v24.8h
	mul	v25.8h, v26.8h, v7.h[3]
	mul	v27.8h, v28.8h, v7.h[3]
	sqrdmulh	v23.8h, v26.8h, v5.h[3]
	sqrdmulh	v24.8h, v28.8h, v5.h[3]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v23.8h, v25.8h, v8.h[0]
	sqrdmlsh	v24.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v23.8h, v23.8h, v25.8h
	sub	v24.8h, v24.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v23.8h, v23.8h, #1
	sshr	v24.8h, v24.8h, #1
	sub	v26.8h, v9.8h, v13.8h
	sub	v28.8h, v10.8h, v14.8h
	add	v9.8h, v9.8h, v13.8h
	add	v10.8h, v10.8h, v14.8h
	mul	v25.8h, v26.8h, v7.h[4]
	mul	v27.8h, v28.8h, v7.h[4]
	sqrdmulh	v13.8h, v26.8h, v5.h[4]
	sqrdmulh	v14.8h, v28.8h, v5.h[4]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v13.8h, v25.8h, v8.h[0]
	sqrdmlsh	v14.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v13.8h, v13.8h, v25.8h
	sub	v14.8h, v14.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v13.8h, v13.8h, #1
	sshr	v14.8h, v14.8h, #1
	sub	v26.8h, v11.8h, v15.8h
	sub	v28.8h, v12.8h, v16.8h
	add	v11.8h, v11.8h, v15.8h
	add	v12.8h, v12.8h, v16.8h
	mul	v25.8h, v26.8h, v7.h[4]
	mul	v27.8h, v28.8h, v7.h[4]
	sqrdmulh	v15.8h, v26.8h, v5.h[4]
	sqrdmulh	v16.8h, v28.8h, v5.h[4]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v15.8h, v25.8h, v8.h[0]
	sqrdmlsh	v16.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v15.8h, v15.8h, v25.8h
	sub	v16.8h, v16.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v15.8h, v15.8h, #1
	sshr	v16.8h, v16.8h, #1
	sub	v26.8h, v17.8h, v21.8h
	sub	v28.8h, v18.8h, v22.8h
	add	v17.8h, v17.8h, v21.8h
	add	v18.8h, v18.8h, v22.8h
	mul	v25.8h, v26.8h, v7.h[5]
	mul	v27.8h, v28.8h, v7.h[5]
	sqrdmulh	v21.8h, v26.8h, v5.h[5]
	sqrdmulh	v22.8h, v28.8h, v5.h[5]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v21.8h, v25.8h, v8.h[0]
	sqrdmlsh	v22.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v21.8h, v21.8h, v25.8h
	sub	v22.8h, v22.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v21.8h, v21.8h, #1
	sshr	v22.8h, v22.8h, #1
	sub	v26.8h, v19.8h, v23.8h
	sub	v28.8h, v20.8h, v24.8h
	add	v19.8h, v19.8h, v23.8h
	add	v20.8h, v20.8h, v24.8h
	mul	v25.8h, v26.8h, v7.h[5]
	mul	v27.8h, v28.8h, v7.h[5]
	sqrdmulh	v23.8h, v26.8h, v5.h[5]
	sqrdmulh	v24.8h, v28.8h, v5.h[5]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v23.8h, v25.8h, v8.h[0]
	sqrdmlsh	v24.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v23.8h, v23.8h, v25.8h
	sub	v24.8h, v24.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v23.8h, v23.8h, #1
	sshr	v24.8h, v24.8h, #1
	sqdmulh	v25.8h, v9.8h, v8.h[2]
	sqdmulh	v26.8h, v10.8h, v8.h[2]
	sshr	v25.8h, v25.8h, #11
	sshr	v26.8h, v26.8h, #11
	mls	v9.8h, v25.8h, v8.h[0]
	mls	v10.8h, v26.8h, v8.h[0]
	sqdmulh	v25.8h, v11.8h, v8.h[2]
	sqdmulh	v26.8h, v12.8h, v8.h[2]
	sshr	v25.8h, v25.8h, #11
	sshr	v26.8h, v26.8h, #11
	mls	v11.8h, v25.8h, v8.h[0]
	mls	v12.8h, v26.8h, v8.h[0]
	sqdmulh	v25.8h, v17.8h, v8.h[2]
	sqdmulh	v26.8h, v18.8h, v8.h[2]
	sshr	v25.8h, v25.8h, #11
	sshr	v26.8h, v26.8h, #11
	mls	v17.8h, v25.8h, v8.h[0]
	mls	v18.8h, v26.8h, v8.h[0]
	sqdmulh	v25.8h, v19.8h, v8.h[2]
	sqdmulh	v26.8h, v20.8h, v8.h[2]
	sshr	v25.8h, v25.8h, #11
	sshr	v26.8h, v26.8h, #11
	mls	v19.8h, v25.8h, v8.h[0]
	mls	v20.8h, v26.8h, v8.h[0]
	sub	v26.8h, v9.8h, v17.8h
	sub	v28.8h, v10.8h, v18.8h
	add	v9.8h, v9.8h, v17.8h
	add	v10.8h, v10.8h, v18.8h
	mul	v25.8h, v26.8h, v7.h[6]
	mul	v27.8h, v28.8h, v7.h[6]
	sqrdmulh	v17.8h, v26.8h, v5.h[6]
	sqrdmulh	v18.8h, v28.8h, v5.h[6]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v17.8h, v25.8h, v8.h[0]
	sqrdmlsh	v18.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v17.8h, v17.8h, v25.8h
	sub	v18.8h, v18.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v17.8h, v17.8h, #1
	sshr	v18.8h, v18.8h, #1
	sub	v26.8h, v11.8h, v19.8h
	sub	v28.8h, v12.8h, v20.8h
	add	v11.8h, v11.8h, v19.8h
	add	v12.8h, v12.8h, v20.8h
	mul	v25.8h, v26.8h, v7.h[6]
	mul	v27.8h, v28.8h, v7.h[6]
	sqrdmulh	v19.8h, v26.8h, v5.h[6]
	sqrdmulh	v20.8h, v28.8h, v5.h[6]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v19.8h, v25.8h, v8.h[0]
	sqrdmlsh	v20.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v19.8h, v19.8h, v25.8h
	sub	v20.8h, v20.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v19.8h, v19.8h, #1
	sshr	v20.8h, v20.8h, #1
	sub	v26.8h, v13.8h, v21.8h
	sub	v28.8h, v14.8h, v22.8h
	add	v13.8h, v13.8h, v21.8h
	add	v14.8h, v14.8h, v22.8h
	mul	v25.8h, v26.8h, v7.h[6]
	mul	v27.8h, v28.8h, v7.h[6]
	sqrdmulh	v21.8h, v26.8h, v5.h[6]
	sqrdmulh	v22.8h, v28.8h, v5.h[6]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v21.8h, v25.8h, v8.h[0]
	sqrdmlsh	v22.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v21.8h, v21.8h, v25.8h
	sub	v22.8h, v22.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v21.8h, v21.8h, #1
	sshr	v22.8h, v22.8h, #1
	sub	v26.8h, v15.8h, v23.8h
	sub	v28.8h, v16.8h, v24.8h
	add	v15.8h, v15.8h, v23.8h
	add	v16.8h, v16.8h, v24.8h
	mul	v25.8h, v26.8h, v7.h[6]
	mul	v27.8h, v28.8h, v7.h[6]
	sqrdmulh	v23.8h, v26.8h, v5.h[6]
	sqrdmulh	v24.8h, v28.8h, v5.h[6]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v23.8h, v25.8h, v8.h[0]
	sqrdmlsh	v24.8h, v27.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v27.8h, v27.8h, v8.h[0]
	sub	v23.8h, v23.8h, v25.8h
	sub	v24.8h, v24.8h, v27.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v23.8h, v23.8h, #1
	sshr	v24.8h, v24.8h, #1
	mul	v25.8h, v9.8h, v7.h[7]
	mul	v26.8h, v10.8h, v7.h[7]
	sqrdmulh	v9.8h, v9.8h, v5.h[7]
	sqrdmulh	v10.8h, v10.8h, v5.h[7]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v9.8h, v25.8h, v8.h[0]
	sqrdmlsh	v10.8h, v26.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v26.8h, v26.8h, v8.h[0]
	sub	v9.8h, v9.8h, v25.8h
	sub	v10.8h, v10.8h, v26.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v9.8h, v9.8h, #1
	sshr	v10.8h, v10.8h, #1
	mul	v25.8h, v11.8h, v7.h[7]
	mul	v26.8h, v12.8h, v7.h[7]
	sqrdmulh	v11.8h, v11.8h, v5.h[7]
	sqrdmulh	v12.8h, v12.8h, v5.h[7]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v11.8h, v25.8h, v8.h[0]
	sqrdmlsh	v12.8h, v26.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v26.8h, v26.8h, v8.h[0]
	sub	v11.8h, v11.8h, v25.8h
	sub	v12.8h, v12.8h, v26.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v11.8h, v11.8h, #1
	sshr	v12.8h, v12.8h, #1
	mul	v25.8h, v13.8h, v7.h[7]
	mul	v26.8h, v14.8h, v7.h[7]
	sqrdmulh	v13.8h, v13.8h, v5.h[7]
	sqrdmulh	v14.8h, v14.8h, v5.h[7]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v13.8h, v25.8h, v8.h[0]
	sqrdmlsh	v14.8h, v26.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v26.8h, v26.8h, v8.h[0]
	sub	v13.8h, v13.8h, v25.8h
	sub	v14.8h, v14.8h, v26.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v13.8h, v13.8h, #1
	sshr	v14.8h, v14.8h, #1
	mul	v25.8h, v15.8h, v7.h[7]
	mul	v26.8h, v16.8h, v7.h[7]
	sqrdmulh	v15.8h, v15.8h, v5.h[7]
	sqrdmulh	v16.8h, v16.8h, v5.h[7]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v15.8h, v25.8h, v8.h[0]
	sqrdmlsh	v16.8h, v26.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v26.8h, v26.8h, v8.h[0]
	sub	v15.8h, v15.8h, v25.8h
	sub	v16.8h, v16.8h, v26.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v15.8h, v15.8h, #1
	sshr	v16.8h, v16.8h, #1
	mul	v25.8h, v17.8h, v7.h[7]
	mul	v26.8h, v18.8h, v7.h[7]
	sqrdmulh	v17.8h, v17.8h, v5.h[7]
	sqrdmulh	v18.8h, v18.8h, v5.h[7]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v17.8h, v25.8h, v8.h[0]
	sqrdmlsh	v18.8h, v26.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v26.8h, v26.8h, v8.h[0]
	sub	v17.8h, v17.8h, v25.8h
	sub	v18.8h, v18.8h, v26.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v17.8h, v17.8h, #1
	sshr	v18.8h, v18.8h, #1
	mul	v25.8h, v19.8h, v7.h[7]
	mul	v26.8h, v20.8h, v7.h[7]
	sqrdmulh	v19.8h, v19.8h, v5.h[7]
	sqrdmulh	v20.8h, v20.8h, v5.h[7]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v19.8h, v25.8h, v8.h[0]
	sqrdmlsh	v20.8h, v26.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v26.8h, v26.8h, v8.h[0]
	sub	v19.8h, v19.8h, v25.8h
	sub	v20.8h, v20.8h, v26.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v19.8h, v19.8h, #1
	sshr	v20.8h, v20.8h, #1
	mul	v25.8h, v21.8h, v7.h[7]
	mul	v26.8h, v22.8h, v7.h[7]
	sqrdmulh	v21.8h, v21.8h, v5.h[7]
	sqrdmulh	v22.8h, v22.8h, v5.h[7]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v21.8h, v25.8h, v8.h[0]
	sqrdmlsh	v22.8h, v26.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v26.8h, v26.8h, v8.h[0]
	sub	v21.8h, v21.8h, v25.8h
	sub	v22.8h, v22.8h, v26.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v21.8h, v21.8h, #1
	sshr	v22.8h, v22.8h, #1
	mul	v25.8h, v23.8h, v7.h[7]
	mul	v26.8h, v24.8h, v7.h[7]
	sqrdmulh	v23.8h, v23.8h, v5.h[7]
	sqrdmulh	v24.8h, v24.8h, v5.h[7]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v23.8h, v25.8h, v8.h[0]
	sqrdmlsh	v24.8h, v26.8h, v8.h[0]
#else
	sqrdmulh	v25.8h, v25.8h, v8.h[0]
	sqrdmulh	v26.8h, v26.8h, v8.h[0]
	sub	v23.8h, v23.8h, v25.8h
	sub	v24.8h, v24.8h, v26.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v23.8h, v23.8h, #1
	sshr	v24.8h, v24.8h, #1
	str	q9, [x0, #16]
	str	q10, [x0, #48]
	str	q11, [x0, #80]
	str	q12, [x0, #112]
	str	q13, [x0, #144]
	str	q14, [x0, #176]
	str	q15, [x0, #208]
	str	q16, [x0, #240]
	str	q17, [x1, #16]
	str	q18, [x1, #48]
	str	q19, [x1, #80]
	str	q20, [x1, #112]
	str	q21, [x1, #144]
	str	q22, [x1, #176]
	str	q23, [x1, #208]
	str	q24, [x1, #240]
	ldp	d8, d9, [x29, #16]
	ldp	d10, d11, [x29, #32]
	ldp	d12, d13, [x29, #48]
	ldp	d14, d15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
#ifndef __APPLE__
	.size	kyber_invntt,.-kyber_invntt
#endif /* __APPLE__ */
#ifndef __APPLE__
	.text
	.type	L_kyber_aarch64_zetas_mul, %object
	.section	.rodata
	.size	L_kyber_aarch64_zetas_mul, 256
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
#ifndef __APPLE__
	.align	2
#else
	.p2align	2
#endif /* __APPLE__ */
L_kyber_aarch64_zetas_mul:
	.short	0x08b2,0xf74e,0x01ae,0xfe52,0x022b,0xfdd5,0x034b,0xfcb5
	.short	0x081e,0xf7e2,0x0367,0xfc99,0x060e,0xf9f2,0x0069,0xff97
	.short	0x01a6,0xfe5a,0x024b,0xfdb5,0x00b1,0xff4f,0x0c16,0xf3ea
	.short	0x0bde,0xf422,0x0b35,0xf4cb,0x0626,0xf9da,0x0675,0xf98b
	.short	0x0c0b,0xf3f5,0x030a,0xfcf6,0x0487,0xfb79,0x0c6e,0xf392
	.short	0x09f8,0xf608,0x05cb,0xfa35,0x0aa7,0xf559,0x045f,0xfba1
	.short	0x06cb,0xf935,0x0284,0xfd7c,0x0999,0xf667,0x015d,0xfea3
	.short	0x01a2,0xfe5e,0x0149,0xfeb7,0x0c65,0xf39b,0x0cb6,0xf34a
	.short	0x0331,0xfccf,0x0449,0xfbb7,0x025b,0xfda5,0x0262,0xfd9e
	.short	0x052a,0xfad6,0x07fc,0xf804,0x0748,0xf8b8,0x0180,0xfe80
	.short	0x0842,0xf7be,0x0c79,0xf387,0x04c2,0xfb3e,0x07ca,0xf836
	.short	0x0997,0xf669,0x00dc,0xff24,0x085e,0xf7a2,0x0686,0xf97a
	.short	0x0860,0xf7a0,0x0707,0xf8f9,0x0803,0xf7fd,0x031a,0xfce6
	.short	0x071b,0xf8e5,0x09ab,0xf655,0x099b,0xf665,0x01de,0xfe22
	.short	0x0c95,0xf36b,0x0bcd,0xf433,0x03e4,0xfc1c,0x03df,0xfc21
	.short	0x03be,0xfc42,0x074d,0xf8b3,0x05f2,0xfa0e,0x065c,0xf9a4
#ifndef __APPLE__
.text
.globl	kyber_basemul_mont
.type	kyber_basemul_mont,@function
.align	2
kyber_basemul_mont:
#else
.section	__TEXT,__text
.globl	_kyber_basemul_mont
.p2align	2
_kyber_basemul_mont:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
	stp	d12, d13, [x29, #48]
	stp	d14, d15, [x29, #64]
#ifndef __APPLE__
	adrp x3, L_kyber_aarch64_zetas_mul
	add  x3, x3, :lo12:L_kyber_aarch64_zetas_mul
#else
	adrp x3, L_kyber_aarch64_zetas_mul@PAGE
	add  x3, x3, :lo12:L_kyber_aarch64_zetas_mul@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x4, L_kyber_aarch64_consts
	add  x4, x4, :lo12:L_kyber_aarch64_consts
#else
	adrp x4, L_kyber_aarch64_consts@PAGE
	add  x4, x4, :lo12:L_kyber_aarch64_consts@PAGEOFF
#endif /* __APPLE__ */
	ldr	q1, [x4]
	ldp	q2, q3, [x1]
	ldp	q4, q5, [x1, #32]
	ldp	q6, q7, [x1, #64]
	ldp	q8, q9, [x1, #96]
	ldp	q10, q11, [x2]
	ldp	q12, q13, [x2, #32]
	ldp	q14, q15, [x2, #64]
	ldp	q16, q17, [x2, #96]
	ldr	q0, [x3]
	uzp1	v18.8h, v2.8h, v3.8h
	uzp2	v19.8h, v2.8h, v3.8h
	uzp1	v20.8h, v10.8h, v11.8h
	uzp2	v21.8h, v10.8h, v11.8h
	smull	v26.4s, v18.4h, v20.4h
	smull2	v27.4s, v18.8h, v20.8h
	smull	v23.4s, v19.4h, v21.4h
	smull2	v24.4s, v19.8h, v21.8h
	xtn	v25.4h, v23.4s
	xtn2	v25.8h, v24.4s
	mul	v25.8h, v25.8h, v1.h[1]
	smlsl	v23.4s, v25.4h, v1.h[0]
	smlsl2	v24.4s, v25.8h, v1.h[0]
	shrn	v22.4h, v23.4s, #16
	shrn2	v22.8h, v24.4s, #16
	smlal	v26.4s, v22.4h, v0.4h
	smlal2	v27.4s, v22.8h, v0.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v22.4h, v26.4s, #16
	shrn2	v22.8h, v27.4s, #16
	smull	v26.4s, v18.4h, v21.4h
	smull2	v27.4s, v18.8h, v21.8h
	smlal	v26.4s, v19.4h, v20.4h
	smlal2	v27.4s, v19.8h, v20.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v23.4h, v26.4s, #16
	shrn2	v23.8h, v27.4s, #16
	zip1	v24.8h, v22.8h, v23.8h
	zip2	v25.8h, v22.8h, v23.8h
	stp	q24, q25, [x0]
	ldr	q0, [x3, #16]
	uzp1	v18.8h, v4.8h, v5.8h
	uzp2	v19.8h, v4.8h, v5.8h
	uzp1	v20.8h, v12.8h, v13.8h
	uzp2	v21.8h, v12.8h, v13.8h
	smull	v26.4s, v18.4h, v20.4h
	smull2	v27.4s, v18.8h, v20.8h
	smull	v23.4s, v19.4h, v21.4h
	smull2	v24.4s, v19.8h, v21.8h
	xtn	v25.4h, v23.4s
	xtn2	v25.8h, v24.4s
	mul	v25.8h, v25.8h, v1.h[1]
	smlsl	v23.4s, v25.4h, v1.h[0]
	smlsl2	v24.4s, v25.8h, v1.h[0]
	shrn	v22.4h, v23.4s, #16
	shrn2	v22.8h, v24.4s, #16
	smlal	v26.4s, v22.4h, v0.4h
	smlal2	v27.4s, v22.8h, v0.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v22.4h, v26.4s, #16
	shrn2	v22.8h, v27.4s, #16
	smull	v26.4s, v18.4h, v21.4h
	smull2	v27.4s, v18.8h, v21.8h
	smlal	v26.4s, v19.4h, v20.4h
	smlal2	v27.4s, v19.8h, v20.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v23.4h, v26.4s, #16
	shrn2	v23.8h, v27.4s, #16
	zip1	v24.8h, v22.8h, v23.8h
	zip2	v25.8h, v22.8h, v23.8h
	stp	q24, q25, [x0, #32]
	ldr	q0, [x3, #32]
	uzp1	v18.8h, v6.8h, v7.8h
	uzp2	v19.8h, v6.8h, v7.8h
	uzp1	v20.8h, v14.8h, v15.8h
	uzp2	v21.8h, v14.8h, v15.8h
	smull	v26.4s, v18.4h, v20.4h
	smull2	v27.4s, v18.8h, v20.8h
	smull	v23.4s, v19.4h, v21.4h
	smull2	v24.4s, v19.8h, v21.8h
	xtn	v25.4h, v23.4s
	xtn2	v25.8h, v24.4s
	mul	v25.8h, v25.8h, v1.h[1]
	smlsl	v23.4s, v25.4h, v1.h[0]
	smlsl2	v24.4s, v25.8h, v1.h[0]
	shrn	v22.4h, v23.4s, #16
	shrn2	v22.8h, v24.4s, #16
	smlal	v26.4s, v22.4h, v0.4h
	smlal2	v27.4s, v22.8h, v0.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v22.4h, v26.4s, #16
	shrn2	v22.8h, v27.4s, #16
	smull	v26.4s, v18.4h, v21.4h
	smull2	v27.4s, v18.8h, v21.8h
	smlal	v26.4s, v19.4h, v20.4h
	smlal2	v27.4s, v19.8h, v20.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v23.4h, v26.4s, #16
	shrn2	v23.8h, v27.4s, #16
	zip1	v24.8h, v22.8h, v23.8h
	zip2	v25.8h, v22.8h, v23.8h
	stp	q24, q25, [x0, #64]
	ldr	q0, [x3, #48]
	uzp1	v18.8h, v8.8h, v9.8h
	uzp2	v19.8h, v8.8h, v9.8h
	uzp1	v20.8h, v16.8h, v17.8h
	uzp2	v21.8h, v16.8h, v17.8h
	smull	v26.4s, v18.4h, v20.4h
	smull2	v27.4s, v18.8h, v20.8h
	smull	v23.4s, v19.4h, v21.4h
	smull2	v24.4s, v19.8h, v21.8h
	xtn	v25.4h, v23.4s
	xtn2	v25.8h, v24.4s
	mul	v25.8h, v25.8h, v1.h[1]
	smlsl	v23.4s, v25.4h, v1.h[0]
	smlsl2	v24.4s, v25.8h, v1.h[0]
	shrn	v22.4h, v23.4s, #16
	shrn2	v22.8h, v24.4s, #16
	smlal	v26.4s, v22.4h, v0.4h
	smlal2	v27.4s, v22.8h, v0.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v22.4h, v26.4s, #16
	shrn2	v22.8h, v27.4s, #16
	smull	v26.4s, v18.4h, v21.4h
	smull2	v27.4s, v18.8h, v21.8h
	smlal	v26.4s, v19.4h, v20.4h
	smlal2	v27.4s, v19.8h, v20.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v23.4h, v26.4s, #16
	shrn2	v23.8h, v27.4s, #16
	zip1	v24.8h, v22.8h, v23.8h
	zip2	v25.8h, v22.8h, v23.8h
	stp	q24, q25, [x0, #96]
	ldp	q2, q3, [x1, #128]
	ldp	q4, q5, [x1, #160]
	ldp	q6, q7, [x1, #192]
	ldp	q8, q9, [x1, #224]
	ldp	q10, q11, [x2, #128]
	ldp	q12, q13, [x2, #160]
	ldp	q14, q15, [x2, #192]
	ldp	q16, q17, [x2, #224]
	ldr	q0, [x3, #64]
	uzp1	v18.8h, v2.8h, v3.8h
	uzp2	v19.8h, v2.8h, v3.8h
	uzp1	v20.8h, v10.8h, v11.8h
	uzp2	v21.8h, v10.8h, v11.8h
	smull	v26.4s, v18.4h, v20.4h
	smull2	v27.4s, v18.8h, v20.8h
	smull	v23.4s, v19.4h, v21.4h
	smull2	v24.4s, v19.8h, v21.8h
	xtn	v25.4h, v23.4s
	xtn2	v25.8h, v24.4s
	mul	v25.8h, v25.8h, v1.h[1]
	smlsl	v23.4s, v25.4h, v1.h[0]
	smlsl2	v24.4s, v25.8h, v1.h[0]
	shrn	v22.4h, v23.4s, #16
	shrn2	v22.8h, v24.4s, #16
	smlal	v26.4s, v22.4h, v0.4h
	smlal2	v27.4s, v22.8h, v0.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v22.4h, v26.4s, #16
	shrn2	v22.8h, v27.4s, #16
	smull	v26.4s, v18.4h, v21.4h
	smull2	v27.4s, v18.8h, v21.8h
	smlal	v26.4s, v19.4h, v20.4h
	smlal2	v27.4s, v19.8h, v20.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v23.4h, v26.4s, #16
	shrn2	v23.8h, v27.4s, #16
	zip1	v24.8h, v22.8h, v23.8h
	zip2	v25.8h, v22.8h, v23.8h
	stp	q24, q25, [x0, #128]
	ldr	q0, [x3, #80]
	uzp1	v18.8h, v4.8h, v5.8h
	uzp2	v19.8h, v4.8h, v5.8h
	uzp1	v20.8h, v12.8h, v13.8h
	uzp2	v21.8h, v12.8h, v13.8h
	smull	v26.4s, v18.4h, v20.4h
	smull2	v27.4s, v18.8h, v20.8h
	smull	v23.4s, v19.4h, v21.4h
	smull2	v24.4s, v19.8h, v21.8h
	xtn	v25.4h, v23.4s
	xtn2	v25.8h, v24.4s
	mul	v25.8h, v25.8h, v1.h[1]
	smlsl	v23.4s, v25.4h, v1.h[0]
	smlsl2	v24.4s, v25.8h, v1.h[0]
	shrn	v22.4h, v23.4s, #16
	shrn2	v22.8h, v24.4s, #16
	smlal	v26.4s, v22.4h, v0.4h
	smlal2	v27.4s, v22.8h, v0.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v22.4h, v26.4s, #16
	shrn2	v22.8h, v27.4s, #16
	smull	v26.4s, v18.4h, v21.4h
	smull2	v27.4s, v18.8h, v21.8h
	smlal	v26.4s, v19.4h, v20.4h
	smlal2	v27.4s, v19.8h, v20.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v23.4h, v26.4s, #16
	shrn2	v23.8h, v27.4s, #16
	zip1	v24.8h, v22.8h, v23.8h
	zip2	v25.8h, v22.8h, v23.8h
	stp	q24, q25, [x0, #160]
	ldr	q0, [x3, #96]
	uzp1	v18.8h, v6.8h, v7.8h
	uzp2	v19.8h, v6.8h, v7.8h
	uzp1	v20.8h, v14.8h, v15.8h
	uzp2	v21.8h, v14.8h, v15.8h
	smull	v26.4s, v18.4h, v20.4h
	smull2	v27.4s, v18.8h, v20.8h
	smull	v23.4s, v19.4h, v21.4h
	smull2	v24.4s, v19.8h, v21.8h
	xtn	v25.4h, v23.4s
	xtn2	v25.8h, v24.4s
	mul	v25.8h, v25.8h, v1.h[1]
	smlsl	v23.4s, v25.4h, v1.h[0]
	smlsl2	v24.4s, v25.8h, v1.h[0]
	shrn	v22.4h, v23.4s, #16
	shrn2	v22.8h, v24.4s, #16
	smlal	v26.4s, v22.4h, v0.4h
	smlal2	v27.4s, v22.8h, v0.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v22.4h, v26.4s, #16
	shrn2	v22.8h, v27.4s, #16
	smull	v26.4s, v18.4h, v21.4h
	smull2	v27.4s, v18.8h, v21.8h
	smlal	v26.4s, v19.4h, v20.4h
	smlal2	v27.4s, v19.8h, v20.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v23.4h, v26.4s, #16
	shrn2	v23.8h, v27.4s, #16
	zip1	v24.8h, v22.8h, v23.8h
	zip2	v25.8h, v22.8h, v23.8h
	stp	q24, q25, [x0, #192]
	ldr	q0, [x3, #112]
	uzp1	v18.8h, v8.8h, v9.8h
	uzp2	v19.8h, v8.8h, v9.8h
	uzp1	v20.8h, v16.8h, v17.8h
	uzp2	v21.8h, v16.8h, v17.8h
	smull	v26.4s, v18.4h, v20.4h
	smull2	v27.4s, v18.8h, v20.8h
	smull	v23.4s, v19.4h, v21.4h
	smull2	v24.4s, v19.8h, v21.8h
	xtn	v25.4h, v23.4s
	xtn2	v25.8h, v24.4s
	mul	v25.8h, v25.8h, v1.h[1]
	smlsl	v23.4s, v25.4h, v1.h[0]
	smlsl2	v24.4s, v25.8h, v1.h[0]
	shrn	v22.4h, v23.4s, #16
	shrn2	v22.8h, v24.4s, #16
	smlal	v26.4s, v22.4h, v0.4h
	smlal2	v27.4s, v22.8h, v0.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v22.4h, v26.4s, #16
	shrn2	v22.8h, v27.4s, #16
	smull	v26.4s, v18.4h, v21.4h
	smull2	v27.4s, v18.8h, v21.8h
	smlal	v26.4s, v19.4h, v20.4h
	smlal2	v27.4s, v19.8h, v20.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v23.4h, v26.4s, #16
	shrn2	v23.8h, v27.4s, #16
	zip1	v24.8h, v22.8h, v23.8h
	zip2	v25.8h, v22.8h, v23.8h
	stp	q24, q25, [x0, #224]
	ldp	q2, q3, [x1, #256]
	ldp	q4, q5, [x1, #288]
	ldp	q6, q7, [x1, #320]
	ldp	q8, q9, [x1, #352]
	ldp	q10, q11, [x2, #256]
	ldp	q12, q13, [x2, #288]
	ldp	q14, q15, [x2, #320]
	ldp	q16, q17, [x2, #352]
	ldr	q0, [x3, #128]
	uzp1	v18.8h, v2.8h, v3.8h
	uzp2	v19.8h, v2.8h, v3.8h
	uzp1	v20.8h, v10.8h, v11.8h
	uzp2	v21.8h, v10.8h, v11.8h
	smull	v26.4s, v18.4h, v20.4h
	smull2	v27.4s, v18.8h, v20.8h
	smull	v23.4s, v19.4h, v21.4h
	smull2	v24.4s, v19.8h, v21.8h
	xtn	v25.4h, v23.4s
	xtn2	v25.8h, v24.4s
	mul	v25.8h, v25.8h, v1.h[1]
	smlsl	v23.4s, v25.4h, v1.h[0]
	smlsl2	v24.4s, v25.8h, v1.h[0]
	shrn	v22.4h, v23.4s, #16
	shrn2	v22.8h, v24.4s, #16
	smlal	v26.4s, v22.4h, v0.4h
	smlal2	v27.4s, v22.8h, v0.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v22.4h, v26.4s, #16
	shrn2	v22.8h, v27.4s, #16
	smull	v26.4s, v18.4h, v21.4h
	smull2	v27.4s, v18.8h, v21.8h
	smlal	v26.4s, v19.4h, v20.4h
	smlal2	v27.4s, v19.8h, v20.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v23.4h, v26.4s, #16
	shrn2	v23.8h, v27.4s, #16
	zip1	v24.8h, v22.8h, v23.8h
	zip2	v25.8h, v22.8h, v23.8h
	stp	q24, q25, [x0, #256]
	ldr	q0, [x3, #144]
	uzp1	v18.8h, v4.8h, v5.8h
	uzp2	v19.8h, v4.8h, v5.8h
	uzp1	v20.8h, v12.8h, v13.8h
	uzp2	v21.8h, v12.8h, v13.8h
	smull	v26.4s, v18.4h, v20.4h
	smull2	v27.4s, v18.8h, v20.8h
	smull	v23.4s, v19.4h, v21.4h
	smull2	v24.4s, v19.8h, v21.8h
	xtn	v25.4h, v23.4s
	xtn2	v25.8h, v24.4s
	mul	v25.8h, v25.8h, v1.h[1]
	smlsl	v23.4s, v25.4h, v1.h[0]
	smlsl2	v24.4s, v25.8h, v1.h[0]
	shrn	v22.4h, v23.4s, #16
	shrn2	v22.8h, v24.4s, #16
	smlal	v26.4s, v22.4h, v0.4h
	smlal2	v27.4s, v22.8h, v0.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v22.4h, v26.4s, #16
	shrn2	v22.8h, v27.4s, #16
	smull	v26.4s, v18.4h, v21.4h
	smull2	v27.4s, v18.8h, v21.8h
	smlal	v26.4s, v19.4h, v20.4h
	smlal2	v27.4s, v19.8h, v20.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v23.4h, v26.4s, #16
	shrn2	v23.8h, v27.4s, #16
	zip1	v24.8h, v22.8h, v23.8h
	zip2	v25.8h, v22.8h, v23.8h
	stp	q24, q25, [x0, #288]
	ldr	q0, [x3, #160]
	uzp1	v18.8h, v6.8h, v7.8h
	uzp2	v19.8h, v6.8h, v7.8h
	uzp1	v20.8h, v14.8h, v15.8h
	uzp2	v21.8h, v14.8h, v15.8h
	smull	v26.4s, v18.4h, v20.4h
	smull2	v27.4s, v18.8h, v20.8h
	smull	v23.4s, v19.4h, v21.4h
	smull2	v24.4s, v19.8h, v21.8h
	xtn	v25.4h, v23.4s
	xtn2	v25.8h, v24.4s
	mul	v25.8h, v25.8h, v1.h[1]
	smlsl	v23.4s, v25.4h, v1.h[0]
	smlsl2	v24.4s, v25.8h, v1.h[0]
	shrn	v22.4h, v23.4s, #16
	shrn2	v22.8h, v24.4s, #16
	smlal	v26.4s, v22.4h, v0.4h
	smlal2	v27.4s, v22.8h, v0.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v22.4h, v26.4s, #16
	shrn2	v22.8h, v27.4s, #16
	smull	v26.4s, v18.4h, v21.4h
	smull2	v27.4s, v18.8h, v21.8h
	smlal	v26.4s, v19.4h, v20.4h
	smlal2	v27.4s, v19.8h, v20.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v23.4h, v26.4s, #16
	shrn2	v23.8h, v27.4s, #16
	zip1	v24.8h, v22.8h, v23.8h
	zip2	v25.8h, v22.8h, v23.8h
	stp	q24, q25, [x0, #320]
	ldr	q0, [x3, #176]
	uzp1	v18.8h, v8.8h, v9.8h
	uzp2	v19.8h, v8.8h, v9.8h
	uzp1	v20.8h, v16.8h, v17.8h
	uzp2	v21.8h, v16.8h, v17.8h
	smull	v26.4s, v18.4h, v20.4h
	smull2	v27.4s, v18.8h, v20.8h
	smull	v23.4s, v19.4h, v21.4h
	smull2	v24.4s, v19.8h, v21.8h
	xtn	v25.4h, v23.4s
	xtn2	v25.8h, v24.4s
	mul	v25.8h, v25.8h, v1.h[1]
	smlsl	v23.4s, v25.4h, v1.h[0]
	smlsl2	v24.4s, v25.8h, v1.h[0]
	shrn	v22.4h, v23.4s, #16
	shrn2	v22.8h, v24.4s, #16
	smlal	v26.4s, v22.4h, v0.4h
	smlal2	v27.4s, v22.8h, v0.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v22.4h, v26.4s, #16
	shrn2	v22.8h, v27.4s, #16
	smull	v26.4s, v18.4h, v21.4h
	smull2	v27.4s, v18.8h, v21.8h
	smlal	v26.4s, v19.4h, v20.4h
	smlal2	v27.4s, v19.8h, v20.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v23.4h, v26.4s, #16
	shrn2	v23.8h, v27.4s, #16
	zip1	v24.8h, v22.8h, v23.8h
	zip2	v25.8h, v22.8h, v23.8h
	stp	q24, q25, [x0, #352]
	ldp	q2, q3, [x1, #384]
	ldp	q4, q5, [x1, #416]
	ldp	q6, q7, [x1, #448]
	ldp	q8, q9, [x1, #480]
	ldp	q10, q11, [x2, #384]
	ldp	q12, q13, [x2, #416]
	ldp	q14, q15, [x2, #448]
	ldp	q16, q17, [x2, #480]
	ldr	q0, [x3, #192]
	uzp1	v18.8h, v2.8h, v3.8h
	uzp2	v19.8h, v2.8h, v3.8h
	uzp1	v20.8h, v10.8h, v11.8h
	uzp2	v21.8h, v10.8h, v11.8h
	smull	v26.4s, v18.4h, v20.4h
	smull2	v27.4s, v18.8h, v20.8h
	smull	v23.4s, v19.4h, v21.4h
	smull2	v24.4s, v19.8h, v21.8h
	xtn	v25.4h, v23.4s
	xtn2	v25.8h, v24.4s
	mul	v25.8h, v25.8h, v1.h[1]
	smlsl	v23.4s, v25.4h, v1.h[0]
	smlsl2	v24.4s, v25.8h, v1.h[0]
	shrn	v22.4h, v23.4s, #16
	shrn2	v22.8h, v24.4s, #16
	smlal	v26.4s, v22.4h, v0.4h
	smlal2	v27.4s, v22.8h, v0.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v22.4h, v26.4s, #16
	shrn2	v22.8h, v27.4s, #16
	smull	v26.4s, v18.4h, v21.4h
	smull2	v27.4s, v18.8h, v21.8h
	smlal	v26.4s, v19.4h, v20.4h
	smlal2	v27.4s, v19.8h, v20.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v23.4h, v26.4s, #16
	shrn2	v23.8h, v27.4s, #16
	zip1	v24.8h, v22.8h, v23.8h
	zip2	v25.8h, v22.8h, v23.8h
	stp	q24, q25, [x0, #384]
	ldr	q0, [x3, #208]
	uzp1	v18.8h, v4.8h, v5.8h
	uzp2	v19.8h, v4.8h, v5.8h
	uzp1	v20.8h, v12.8h, v13.8h
	uzp2	v21.8h, v12.8h, v13.8h
	smull	v26.4s, v18.4h, v20.4h
	smull2	v27.4s, v18.8h, v20.8h
	smull	v23.4s, v19.4h, v21.4h
	smull2	v24.4s, v19.8h, v21.8h
	xtn	v25.4h, v23.4s
	xtn2	v25.8h, v24.4s
	mul	v25.8h, v25.8h, v1.h[1]
	smlsl	v23.4s, v25.4h, v1.h[0]
	smlsl2	v24.4s, v25.8h, v1.h[0]
	shrn	v22.4h, v23.4s, #16
	shrn2	v22.8h, v24.4s, #16
	smlal	v26.4s, v22.4h, v0.4h
	smlal2	v27.4s, v22.8h, v0.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v22.4h, v26.4s, #16
	shrn2	v22.8h, v27.4s, #16
	smull	v26.4s, v18.4h, v21.4h
	smull2	v27.4s, v18.8h, v21.8h
	smlal	v26.4s, v19.4h, v20.4h
	smlal2	v27.4s, v19.8h, v20.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v23.4h, v26.4s, #16
	shrn2	v23.8h, v27.4s, #16
	zip1	v24.8h, v22.8h, v23.8h
	zip2	v25.8h, v22.8h, v23.8h
	stp	q24, q25, [x0, #416]
	ldr	q0, [x3, #224]
	uzp1	v18.8h, v6.8h, v7.8h
	uzp2	v19.8h, v6.8h, v7.8h
	uzp1	v20.8h, v14.8h, v15.8h
	uzp2	v21.8h, v14.8h, v15.8h
	smull	v26.4s, v18.4h, v20.4h
	smull2	v27.4s, v18.8h, v20.8h
	smull	v23.4s, v19.4h, v21.4h
	smull2	v24.4s, v19.8h, v21.8h
	xtn	v25.4h, v23.4s
	xtn2	v25.8h, v24.4s
	mul	v25.8h, v25.8h, v1.h[1]
	smlsl	v23.4s, v25.4h, v1.h[0]
	smlsl2	v24.4s, v25.8h, v1.h[0]
	shrn	v22.4h, v23.4s, #16
	shrn2	v22.8h, v24.4s, #16
	smlal	v26.4s, v22.4h, v0.4h
	smlal2	v27.4s, v22.8h, v0.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v22.4h, v26.4s, #16
	shrn2	v22.8h, v27.4s, #16
	smull	v26.4s, v18.4h, v21.4h
	smull2	v27.4s, v18.8h, v21.8h
	smlal	v26.4s, v19.4h, v20.4h
	smlal2	v27.4s, v19.8h, v20.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v23.4h, v26.4s, #16
	shrn2	v23.8h, v27.4s, #16
	zip1	v24.8h, v22.8h, v23.8h
	zip2	v25.8h, v22.8h, v23.8h
	stp	q24, q25, [x0, #448]
	ldr	q0, [x3, #240]
	uzp1	v18.8h, v8.8h, v9.8h
	uzp2	v19.8h, v8.8h, v9.8h
	uzp1	v20.8h, v16.8h, v17.8h
	uzp2	v21.8h, v16.8h, v17.8h
	smull	v26.4s, v18.4h, v20.4h
	smull2	v27.4s, v18.8h, v20.8h
	smull	v23.4s, v19.4h, v21.4h
	smull2	v24.4s, v19.8h, v21.8h
	xtn	v25.4h, v23.4s
	xtn2	v25.8h, v24.4s
	mul	v25.8h, v25.8h, v1.h[1]
	smlsl	v23.4s, v25.4h, v1.h[0]
	smlsl2	v24.4s, v25.8h, v1.h[0]
	shrn	v22.4h, v23.4s, #16
	shrn2	v22.8h, v24.4s, #16
	smlal	v26.4s, v22.4h, v0.4h
	smlal2	v27.4s, v22.8h, v0.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v22.4h, v26.4s, #16
	shrn2	v22.8h, v27.4s, #16
	smull	v26.4s, v18.4h, v21.4h
	smull2	v27.4s, v18.8h, v21.8h
	smlal	v26.4s, v19.4h, v20.4h
	smlal2	v27.4s, v19.8h, v20.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v23.4h, v26.4s, #16
	shrn2	v23.8h, v27.4s, #16
	zip1	v24.8h, v22.8h, v23.8h
	zip2	v25.8h, v22.8h, v23.8h
	stp	q24, q25, [x0, #480]
	ldp	d8, d9, [x29, #16]
	ldp	d10, d11, [x29, #32]
	ldp	d12, d13, [x29, #48]
	ldp	d14, d15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
#ifndef __APPLE__
	.size	kyber_basemul_mont,.-kyber_basemul_mont
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	kyber_basemul_mont_add
.type	kyber_basemul_mont_add,@function
.align	2
kyber_basemul_mont_add:
#else
.section	__TEXT,__text
.globl	_kyber_basemul_mont_add
.p2align	2
_kyber_basemul_mont_add:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
	stp	d12, d13, [x29, #48]
	stp	d14, d15, [x29, #64]
#ifndef __APPLE__
	adrp x3, L_kyber_aarch64_zetas_mul
	add  x3, x3, :lo12:L_kyber_aarch64_zetas_mul
#else
	adrp x3, L_kyber_aarch64_zetas_mul@PAGE
	add  x3, x3, :lo12:L_kyber_aarch64_zetas_mul@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x4, L_kyber_aarch64_consts
	add  x4, x4, :lo12:L_kyber_aarch64_consts
#else
	adrp x4, L_kyber_aarch64_consts@PAGE
	add  x4, x4, :lo12:L_kyber_aarch64_consts@PAGEOFF
#endif /* __APPLE__ */
	ldr	q1, [x4]
	ldp	q2, q3, [x1]
	ldp	q4, q5, [x1, #32]
	ldp	q6, q7, [x1, #64]
	ldp	q8, q9, [x1, #96]
	ldp	q10, q11, [x2]
	ldp	q12, q13, [x2, #32]
	ldp	q14, q15, [x2, #64]
	ldp	q16, q17, [x2, #96]
	ldp	q28, q29, [x0]
	ldr	q0, [x3]
	uzp1	v18.8h, v2.8h, v3.8h
	uzp2	v19.8h, v2.8h, v3.8h
	uzp1	v20.8h, v10.8h, v11.8h
	uzp2	v21.8h, v10.8h, v11.8h
	smull	v26.4s, v18.4h, v20.4h
	smull2	v27.4s, v18.8h, v20.8h
	smull	v23.4s, v19.4h, v21.4h
	smull2	v24.4s, v19.8h, v21.8h
	xtn	v25.4h, v23.4s
	xtn2	v25.8h, v24.4s
	mul	v25.8h, v25.8h, v1.h[1]
	smlsl	v23.4s, v25.4h, v1.h[0]
	smlsl2	v24.4s, v25.8h, v1.h[0]
	shrn	v22.4h, v23.4s, #16
	shrn2	v22.8h, v24.4s, #16
	smlal	v26.4s, v22.4h, v0.4h
	smlal2	v27.4s, v22.8h, v0.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v22.4h, v26.4s, #16
	shrn2	v22.8h, v27.4s, #16
	smull	v26.4s, v18.4h, v21.4h
	smull2	v27.4s, v18.8h, v21.8h
	smlal	v26.4s, v19.4h, v20.4h
	smlal2	v27.4s, v19.8h, v20.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v23.4h, v26.4s, #16
	shrn2	v23.8h, v27.4s, #16
	zip1	v24.8h, v22.8h, v23.8h
	zip2	v25.8h, v22.8h, v23.8h
	add	v28.8h, v28.8h, v24.8h
	add	v29.8h, v29.8h, v25.8h
	stp	q28, q29, [x0]
	ldp	q28, q29, [x0, #32]
	ldr	q0, [x3, #16]
	uzp1	v18.8h, v4.8h, v5.8h
	uzp2	v19.8h, v4.8h, v5.8h
	uzp1	v20.8h, v12.8h, v13.8h
	uzp2	v21.8h, v12.8h, v13.8h
	smull	v26.4s, v18.4h, v20.4h
	smull2	v27.4s, v18.8h, v20.8h
	smull	v23.4s, v19.4h, v21.4h
	smull2	v24.4s, v19.8h, v21.8h
	xtn	v25.4h, v23.4s
	xtn2	v25.8h, v24.4s
	mul	v25.8h, v25.8h, v1.h[1]
	smlsl	v23.4s, v25.4h, v1.h[0]
	smlsl2	v24.4s, v25.8h, v1.h[0]
	shrn	v22.4h, v23.4s, #16
	shrn2	v22.8h, v24.4s, #16
	smlal	v26.4s, v22.4h, v0.4h
	smlal2	v27.4s, v22.8h, v0.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v22.4h, v26.4s, #16
	shrn2	v22.8h, v27.4s, #16
	smull	v26.4s, v18.4h, v21.4h
	smull2	v27.4s, v18.8h, v21.8h
	smlal	v26.4s, v19.4h, v20.4h
	smlal2	v27.4s, v19.8h, v20.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v23.4h, v26.4s, #16
	shrn2	v23.8h, v27.4s, #16
	zip1	v24.8h, v22.8h, v23.8h
	zip2	v25.8h, v22.8h, v23.8h
	add	v28.8h, v28.8h, v24.8h
	add	v29.8h, v29.8h, v25.8h
	stp	q28, q29, [x0, #32]
	ldp	q28, q29, [x0, #64]
	ldr	q0, [x3, #32]
	uzp1	v18.8h, v6.8h, v7.8h
	uzp2	v19.8h, v6.8h, v7.8h
	uzp1	v20.8h, v14.8h, v15.8h
	uzp2	v21.8h, v14.8h, v15.8h
	smull	v26.4s, v18.4h, v20.4h
	smull2	v27.4s, v18.8h, v20.8h
	smull	v23.4s, v19.4h, v21.4h
	smull2	v24.4s, v19.8h, v21.8h
	xtn	v25.4h, v23.4s
	xtn2	v25.8h, v24.4s
	mul	v25.8h, v25.8h, v1.h[1]
	smlsl	v23.4s, v25.4h, v1.h[0]
	smlsl2	v24.4s, v25.8h, v1.h[0]
	shrn	v22.4h, v23.4s, #16
	shrn2	v22.8h, v24.4s, #16
	smlal	v26.4s, v22.4h, v0.4h
	smlal2	v27.4s, v22.8h, v0.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v22.4h, v26.4s, #16
	shrn2	v22.8h, v27.4s, #16
	smull	v26.4s, v18.4h, v21.4h
	smull2	v27.4s, v18.8h, v21.8h
	smlal	v26.4s, v19.4h, v20.4h
	smlal2	v27.4s, v19.8h, v20.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v23.4h, v26.4s, #16
	shrn2	v23.8h, v27.4s, #16
	zip1	v24.8h, v22.8h, v23.8h
	zip2	v25.8h, v22.8h, v23.8h
	add	v28.8h, v28.8h, v24.8h
	add	v29.8h, v29.8h, v25.8h
	stp	q28, q29, [x0, #64]
	ldp	q28, q29, [x0, #96]
	ldr	q0, [x3, #48]
	uzp1	v18.8h, v8.8h, v9.8h
	uzp2	v19.8h, v8.8h, v9.8h
	uzp1	v20.8h, v16.8h, v17.8h
	uzp2	v21.8h, v16.8h, v17.8h
	smull	v26.4s, v18.4h, v20.4h
	smull2	v27.4s, v18.8h, v20.8h
	smull	v23.4s, v19.4h, v21.4h
	smull2	v24.4s, v19.8h, v21.8h
	xtn	v25.4h, v23.4s
	xtn2	v25.8h, v24.4s
	mul	v25.8h, v25.8h, v1.h[1]
	smlsl	v23.4s, v25.4h, v1.h[0]
	smlsl2	v24.4s, v25.8h, v1.h[0]
	shrn	v22.4h, v23.4s, #16
	shrn2	v22.8h, v24.4s, #16
	smlal	v26.4s, v22.4h, v0.4h
	smlal2	v27.4s, v22.8h, v0.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v22.4h, v26.4s, #16
	shrn2	v22.8h, v27.4s, #16
	smull	v26.4s, v18.4h, v21.4h
	smull2	v27.4s, v18.8h, v21.8h
	smlal	v26.4s, v19.4h, v20.4h
	smlal2	v27.4s, v19.8h, v20.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v23.4h, v26.4s, #16
	shrn2	v23.8h, v27.4s, #16
	zip1	v24.8h, v22.8h, v23.8h
	zip2	v25.8h, v22.8h, v23.8h
	add	v28.8h, v28.8h, v24.8h
	add	v29.8h, v29.8h, v25.8h
	stp	q28, q29, [x0, #96]
	ldp	q2, q3, [x1, #128]
	ldp	q4, q5, [x1, #160]
	ldp	q6, q7, [x1, #192]
	ldp	q8, q9, [x1, #224]
	ldp	q10, q11, [x2, #128]
	ldp	q12, q13, [x2, #160]
	ldp	q14, q15, [x2, #192]
	ldp	q16, q17, [x2, #224]
	ldp	q28, q29, [x0, #128]
	ldr	q0, [x3, #64]
	uzp1	v18.8h, v2.8h, v3.8h
	uzp2	v19.8h, v2.8h, v3.8h
	uzp1	v20.8h, v10.8h, v11.8h
	uzp2	v21.8h, v10.8h, v11.8h
	smull	v26.4s, v18.4h, v20.4h
	smull2	v27.4s, v18.8h, v20.8h
	smull	v23.4s, v19.4h, v21.4h
	smull2	v24.4s, v19.8h, v21.8h
	xtn	v25.4h, v23.4s
	xtn2	v25.8h, v24.4s
	mul	v25.8h, v25.8h, v1.h[1]
	smlsl	v23.4s, v25.4h, v1.h[0]
	smlsl2	v24.4s, v25.8h, v1.h[0]
	shrn	v22.4h, v23.4s, #16
	shrn2	v22.8h, v24.4s, #16
	smlal	v26.4s, v22.4h, v0.4h
	smlal2	v27.4s, v22.8h, v0.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v22.4h, v26.4s, #16
	shrn2	v22.8h, v27.4s, #16
	smull	v26.4s, v18.4h, v21.4h
	smull2	v27.4s, v18.8h, v21.8h
	smlal	v26.4s, v19.4h, v20.4h
	smlal2	v27.4s, v19.8h, v20.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v23.4h, v26.4s, #16
	shrn2	v23.8h, v27.4s, #16
	zip1	v24.8h, v22.8h, v23.8h
	zip2	v25.8h, v22.8h, v23.8h
	add	v28.8h, v28.8h, v24.8h
	add	v29.8h, v29.8h, v25.8h
	stp	q28, q29, [x0, #128]
	ldp	q28, q29, [x0, #160]
	ldr	q0, [x3, #80]
	uzp1	v18.8h, v4.8h, v5.8h
	uzp2	v19.8h, v4.8h, v5.8h
	uzp1	v20.8h, v12.8h, v13.8h
	uzp2	v21.8h, v12.8h, v13.8h
	smull	v26.4s, v18.4h, v20.4h
	smull2	v27.4s, v18.8h, v20.8h
	smull	v23.4s, v19.4h, v21.4h
	smull2	v24.4s, v19.8h, v21.8h
	xtn	v25.4h, v23.4s
	xtn2	v25.8h, v24.4s
	mul	v25.8h, v25.8h, v1.h[1]
	smlsl	v23.4s, v25.4h, v1.h[0]
	smlsl2	v24.4s, v25.8h, v1.h[0]
	shrn	v22.4h, v23.4s, #16
	shrn2	v22.8h, v24.4s, #16
	smlal	v26.4s, v22.4h, v0.4h
	smlal2	v27.4s, v22.8h, v0.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v22.4h, v26.4s, #16
	shrn2	v22.8h, v27.4s, #16
	smull	v26.4s, v18.4h, v21.4h
	smull2	v27.4s, v18.8h, v21.8h
	smlal	v26.4s, v19.4h, v20.4h
	smlal2	v27.4s, v19.8h, v20.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v23.4h, v26.4s, #16
	shrn2	v23.8h, v27.4s, #16
	zip1	v24.8h, v22.8h, v23.8h
	zip2	v25.8h, v22.8h, v23.8h
	add	v28.8h, v28.8h, v24.8h
	add	v29.8h, v29.8h, v25.8h
	stp	q28, q29, [x0, #160]
	ldp	q28, q29, [x0, #192]
	ldr	q0, [x3, #96]
	uzp1	v18.8h, v6.8h, v7.8h
	uzp2	v19.8h, v6.8h, v7.8h
	uzp1	v20.8h, v14.8h, v15.8h
	uzp2	v21.8h, v14.8h, v15.8h
	smull	v26.4s, v18.4h, v20.4h
	smull2	v27.4s, v18.8h, v20.8h
	smull	v23.4s, v19.4h, v21.4h
	smull2	v24.4s, v19.8h, v21.8h
	xtn	v25.4h, v23.4s
	xtn2	v25.8h, v24.4s
	mul	v25.8h, v25.8h, v1.h[1]
	smlsl	v23.4s, v25.4h, v1.h[0]
	smlsl2	v24.4s, v25.8h, v1.h[0]
	shrn	v22.4h, v23.4s, #16
	shrn2	v22.8h, v24.4s, #16
	smlal	v26.4s, v22.4h, v0.4h
	smlal2	v27.4s, v22.8h, v0.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v22.4h, v26.4s, #16
	shrn2	v22.8h, v27.4s, #16
	smull	v26.4s, v18.4h, v21.4h
	smull2	v27.4s, v18.8h, v21.8h
	smlal	v26.4s, v19.4h, v20.4h
	smlal2	v27.4s, v19.8h, v20.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v23.4h, v26.4s, #16
	shrn2	v23.8h, v27.4s, #16
	zip1	v24.8h, v22.8h, v23.8h
	zip2	v25.8h, v22.8h, v23.8h
	add	v28.8h, v28.8h, v24.8h
	add	v29.8h, v29.8h, v25.8h
	stp	q28, q29, [x0, #192]
	ldp	q28, q29, [x0, #224]
	ldr	q0, [x3, #112]
	uzp1	v18.8h, v8.8h, v9.8h
	uzp2	v19.8h, v8.8h, v9.8h
	uzp1	v20.8h, v16.8h, v17.8h
	uzp2	v21.8h, v16.8h, v17.8h
	smull	v26.4s, v18.4h, v20.4h
	smull2	v27.4s, v18.8h, v20.8h
	smull	v23.4s, v19.4h, v21.4h
	smull2	v24.4s, v19.8h, v21.8h
	xtn	v25.4h, v23.4s
	xtn2	v25.8h, v24.4s
	mul	v25.8h, v25.8h, v1.h[1]
	smlsl	v23.4s, v25.4h, v1.h[0]
	smlsl2	v24.4s, v25.8h, v1.h[0]
	shrn	v22.4h, v23.4s, #16
	shrn2	v22.8h, v24.4s, #16
	smlal	v26.4s, v22.4h, v0.4h
	smlal2	v27.4s, v22.8h, v0.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v22.4h, v26.4s, #16
	shrn2	v22.8h, v27.4s, #16
	smull	v26.4s, v18.4h, v21.4h
	smull2	v27.4s, v18.8h, v21.8h
	smlal	v26.4s, v19.4h, v20.4h
	smlal2	v27.4s, v19.8h, v20.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v23.4h, v26.4s, #16
	shrn2	v23.8h, v27.4s, #16
	zip1	v24.8h, v22.8h, v23.8h
	zip2	v25.8h, v22.8h, v23.8h
	add	v28.8h, v28.8h, v24.8h
	add	v29.8h, v29.8h, v25.8h
	stp	q28, q29, [x0, #224]
	ldp	q2, q3, [x1, #256]
	ldp	q4, q5, [x1, #288]
	ldp	q6, q7, [x1, #320]
	ldp	q8, q9, [x1, #352]
	ldp	q10, q11, [x2, #256]
	ldp	q12, q13, [x2, #288]
	ldp	q14, q15, [x2, #320]
	ldp	q16, q17, [x2, #352]
	ldp	q28, q29, [x0, #256]
	ldr	q0, [x3, #128]
	uzp1	v18.8h, v2.8h, v3.8h
	uzp2	v19.8h, v2.8h, v3.8h
	uzp1	v20.8h, v10.8h, v11.8h
	uzp2	v21.8h, v10.8h, v11.8h
	smull	v26.4s, v18.4h, v20.4h
	smull2	v27.4s, v18.8h, v20.8h
	smull	v23.4s, v19.4h, v21.4h
	smull2	v24.4s, v19.8h, v21.8h
	xtn	v25.4h, v23.4s
	xtn2	v25.8h, v24.4s
	mul	v25.8h, v25.8h, v1.h[1]
	smlsl	v23.4s, v25.4h, v1.h[0]
	smlsl2	v24.4s, v25.8h, v1.h[0]
	shrn	v22.4h, v23.4s, #16
	shrn2	v22.8h, v24.4s, #16
	smlal	v26.4s, v22.4h, v0.4h
	smlal2	v27.4s, v22.8h, v0.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v22.4h, v26.4s, #16
	shrn2	v22.8h, v27.4s, #16
	smull	v26.4s, v18.4h, v21.4h
	smull2	v27.4s, v18.8h, v21.8h
	smlal	v26.4s, v19.4h, v20.4h
	smlal2	v27.4s, v19.8h, v20.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v23.4h, v26.4s, #16
	shrn2	v23.8h, v27.4s, #16
	zip1	v24.8h, v22.8h, v23.8h
	zip2	v25.8h, v22.8h, v23.8h
	add	v28.8h, v28.8h, v24.8h
	add	v29.8h, v29.8h, v25.8h
	stp	q28, q29, [x0, #256]
	ldp	q28, q29, [x0, #288]
	ldr	q0, [x3, #144]
	uzp1	v18.8h, v4.8h, v5.8h
	uzp2	v19.8h, v4.8h, v5.8h
	uzp1	v20.8h, v12.8h, v13.8h
	uzp2	v21.8h, v12.8h, v13.8h
	smull	v26.4s, v18.4h, v20.4h
	smull2	v27.4s, v18.8h, v20.8h
	smull	v23.4s, v19.4h, v21.4h
	smull2	v24.4s, v19.8h, v21.8h
	xtn	v25.4h, v23.4s
	xtn2	v25.8h, v24.4s
	mul	v25.8h, v25.8h, v1.h[1]
	smlsl	v23.4s, v25.4h, v1.h[0]
	smlsl2	v24.4s, v25.8h, v1.h[0]
	shrn	v22.4h, v23.4s, #16
	shrn2	v22.8h, v24.4s, #16
	smlal	v26.4s, v22.4h, v0.4h
	smlal2	v27.4s, v22.8h, v0.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v22.4h, v26.4s, #16
	shrn2	v22.8h, v27.4s, #16
	smull	v26.4s, v18.4h, v21.4h
	smull2	v27.4s, v18.8h, v21.8h
	smlal	v26.4s, v19.4h, v20.4h
	smlal2	v27.4s, v19.8h, v20.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v23.4h, v26.4s, #16
	shrn2	v23.8h, v27.4s, #16
	zip1	v24.8h, v22.8h, v23.8h
	zip2	v25.8h, v22.8h, v23.8h
	add	v28.8h, v28.8h, v24.8h
	add	v29.8h, v29.8h, v25.8h
	stp	q28, q29, [x0, #288]
	ldp	q28, q29, [x0, #320]
	ldr	q0, [x3, #160]
	uzp1	v18.8h, v6.8h, v7.8h
	uzp2	v19.8h, v6.8h, v7.8h
	uzp1	v20.8h, v14.8h, v15.8h
	uzp2	v21.8h, v14.8h, v15.8h
	smull	v26.4s, v18.4h, v20.4h
	smull2	v27.4s, v18.8h, v20.8h
	smull	v23.4s, v19.4h, v21.4h
	smull2	v24.4s, v19.8h, v21.8h
	xtn	v25.4h, v23.4s
	xtn2	v25.8h, v24.4s
	mul	v25.8h, v25.8h, v1.h[1]
	smlsl	v23.4s, v25.4h, v1.h[0]
	smlsl2	v24.4s, v25.8h, v1.h[0]
	shrn	v22.4h, v23.4s, #16
	shrn2	v22.8h, v24.4s, #16
	smlal	v26.4s, v22.4h, v0.4h
	smlal2	v27.4s, v22.8h, v0.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v22.4h, v26.4s, #16
	shrn2	v22.8h, v27.4s, #16
	smull	v26.4s, v18.4h, v21.4h
	smull2	v27.4s, v18.8h, v21.8h
	smlal	v26.4s, v19.4h, v20.4h
	smlal2	v27.4s, v19.8h, v20.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v23.4h, v26.4s, #16
	shrn2	v23.8h, v27.4s, #16
	zip1	v24.8h, v22.8h, v23.8h
	zip2	v25.8h, v22.8h, v23.8h
	add	v28.8h, v28.8h, v24.8h
	add	v29.8h, v29.8h, v25.8h
	stp	q28, q29, [x0, #320]
	ldp	q28, q29, [x0, #352]
	ldr	q0, [x3, #176]
	uzp1	v18.8h, v8.8h, v9.8h
	uzp2	v19.8h, v8.8h, v9.8h
	uzp1	v20.8h, v16.8h, v17.8h
	uzp2	v21.8h, v16.8h, v17.8h
	smull	v26.4s, v18.4h, v20.4h
	smull2	v27.4s, v18.8h, v20.8h
	smull	v23.4s, v19.4h, v21.4h
	smull2	v24.4s, v19.8h, v21.8h
	xtn	v25.4h, v23.4s
	xtn2	v25.8h, v24.4s
	mul	v25.8h, v25.8h, v1.h[1]
	smlsl	v23.4s, v25.4h, v1.h[0]
	smlsl2	v24.4s, v25.8h, v1.h[0]
	shrn	v22.4h, v23.4s, #16
	shrn2	v22.8h, v24.4s, #16
	smlal	v26.4s, v22.4h, v0.4h
	smlal2	v27.4s, v22.8h, v0.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v22.4h, v26.4s, #16
	shrn2	v22.8h, v27.4s, #16
	smull	v26.4s, v18.4h, v21.4h
	smull2	v27.4s, v18.8h, v21.8h
	smlal	v26.4s, v19.4h, v20.4h
	smlal2	v27.4s, v19.8h, v20.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v23.4h, v26.4s, #16
	shrn2	v23.8h, v27.4s, #16
	zip1	v24.8h, v22.8h, v23.8h
	zip2	v25.8h, v22.8h, v23.8h
	add	v28.8h, v28.8h, v24.8h
	add	v29.8h, v29.8h, v25.8h
	stp	q28, q29, [x0, #352]
	ldp	q2, q3, [x1, #384]
	ldp	q4, q5, [x1, #416]
	ldp	q6, q7, [x1, #448]
	ldp	q8, q9, [x1, #480]
	ldp	q10, q11, [x2, #384]
	ldp	q12, q13, [x2, #416]
	ldp	q14, q15, [x2, #448]
	ldp	q16, q17, [x2, #480]
	ldp	q28, q29, [x0, #384]
	ldr	q0, [x3, #192]
	uzp1	v18.8h, v2.8h, v3.8h
	uzp2	v19.8h, v2.8h, v3.8h
	uzp1	v20.8h, v10.8h, v11.8h
	uzp2	v21.8h, v10.8h, v11.8h
	smull	v26.4s, v18.4h, v20.4h
	smull2	v27.4s, v18.8h, v20.8h
	smull	v23.4s, v19.4h, v21.4h
	smull2	v24.4s, v19.8h, v21.8h
	xtn	v25.4h, v23.4s
	xtn2	v25.8h, v24.4s
	mul	v25.8h, v25.8h, v1.h[1]
	smlsl	v23.4s, v25.4h, v1.h[0]
	smlsl2	v24.4s, v25.8h, v1.h[0]
	shrn	v22.4h, v23.4s, #16
	shrn2	v22.8h, v24.4s, #16
	smlal	v26.4s, v22.4h, v0.4h
	smlal2	v27.4s, v22.8h, v0.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v22.4h, v26.4s, #16
	shrn2	v22.8h, v27.4s, #16
	smull	v26.4s, v18.4h, v21.4h
	smull2	v27.4s, v18.8h, v21.8h
	smlal	v26.4s, v19.4h, v20.4h
	smlal2	v27.4s, v19.8h, v20.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v23.4h, v26.4s, #16
	shrn2	v23.8h, v27.4s, #16
	zip1	v24.8h, v22.8h, v23.8h
	zip2	v25.8h, v22.8h, v23.8h
	add	v28.8h, v28.8h, v24.8h
	add	v29.8h, v29.8h, v25.8h
	stp	q28, q29, [x0, #384]
	ldp	q28, q29, [x0, #416]
	ldr	q0, [x3, #208]
	uzp1	v18.8h, v4.8h, v5.8h
	uzp2	v19.8h, v4.8h, v5.8h
	uzp1	v20.8h, v12.8h, v13.8h
	uzp2	v21.8h, v12.8h, v13.8h
	smull	v26.4s, v18.4h, v20.4h
	smull2	v27.4s, v18.8h, v20.8h
	smull	v23.4s, v19.4h, v21.4h
	smull2	v24.4s, v19.8h, v21.8h
	xtn	v25.4h, v23.4s
	xtn2	v25.8h, v24.4s
	mul	v25.8h, v25.8h, v1.h[1]
	smlsl	v23.4s, v25.4h, v1.h[0]
	smlsl2	v24.4s, v25.8h, v1.h[0]
	shrn	v22.4h, v23.4s, #16
	shrn2	v22.8h, v24.4s, #16
	smlal	v26.4s, v22.4h, v0.4h
	smlal2	v27.4s, v22.8h, v0.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v22.4h, v26.4s, #16
	shrn2	v22.8h, v27.4s, #16
	smull	v26.4s, v18.4h, v21.4h
	smull2	v27.4s, v18.8h, v21.8h
	smlal	v26.4s, v19.4h, v20.4h
	smlal2	v27.4s, v19.8h, v20.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v23.4h, v26.4s, #16
	shrn2	v23.8h, v27.4s, #16
	zip1	v24.8h, v22.8h, v23.8h
	zip2	v25.8h, v22.8h, v23.8h
	add	v28.8h, v28.8h, v24.8h
	add	v29.8h, v29.8h, v25.8h
	stp	q28, q29, [x0, #416]
	ldp	q28, q29, [x0, #448]
	ldr	q0, [x3, #224]
	uzp1	v18.8h, v6.8h, v7.8h
	uzp2	v19.8h, v6.8h, v7.8h
	uzp1	v20.8h, v14.8h, v15.8h
	uzp2	v21.8h, v14.8h, v15.8h
	smull	v26.4s, v18.4h, v20.4h
	smull2	v27.4s, v18.8h, v20.8h
	smull	v23.4s, v19.4h, v21.4h
	smull2	v24.4s, v19.8h, v21.8h
	xtn	v25.4h, v23.4s
	xtn2	v25.8h, v24.4s
	mul	v25.8h, v25.8h, v1.h[1]
	smlsl	v23.4s, v25.4h, v1.h[0]
	smlsl2	v24.4s, v25.8h, v1.h[0]
	shrn	v22.4h, v23.4s, #16
	shrn2	v22.8h, v24.4s, #16
	smlal	v26.4s, v22.4h, v0.4h
	smlal2	v27.4s, v22.8h, v0.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v22.4h, v26.4s, #16
	shrn2	v22.8h, v27.4s, #16
	smull	v26.4s, v18.4h, v21.4h
	smull2	v27.4s, v18.8h, v21.8h
	smlal	v26.4s, v19.4h, v20.4h
	smlal2	v27.4s, v19.8h, v20.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v23.4h, v26.4s, #16
	shrn2	v23.8h, v27.4s, #16
	zip1	v24.8h, v22.8h, v23.8h
	zip2	v25.8h, v22.8h, v23.8h
	add	v28.8h, v28.8h, v24.8h
	add	v29.8h, v29.8h, v25.8h
	stp	q28, q29, [x0, #448]
	ldp	q28, q29, [x0, #480]
	ldr	q0, [x3, #240]
	uzp1	v18.8h, v8.8h, v9.8h
	uzp2	v19.8h, v8.8h, v9.8h
	uzp1	v20.8h, v16.8h, v17.8h
	uzp2	v21.8h, v16.8h, v17.8h
	smull	v26.4s, v18.4h, v20.4h
	smull2	v27.4s, v18.8h, v20.8h
	smull	v23.4s, v19.4h, v21.4h
	smull2	v24.4s, v19.8h, v21.8h
	xtn	v25.4h, v23.4s
	xtn2	v25.8h, v24.4s
	mul	v25.8h, v25.8h, v1.h[1]
	smlsl	v23.4s, v25.4h, v1.h[0]
	smlsl2	v24.4s, v25.8h, v1.h[0]
	shrn	v22.4h, v23.4s, #16
	shrn2	v22.8h, v24.4s, #16
	smlal	v26.4s, v22.4h, v0.4h
	smlal2	v27.4s, v22.8h, v0.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v22.4h, v26.4s, #16
	shrn2	v22.8h, v27.4s, #16
	smull	v26.4s, v18.4h, v21.4h
	smull2	v27.4s, v18.8h, v21.8h
	smlal	v26.4s, v19.4h, v20.4h
	smlal2	v27.4s, v19.8h, v20.8h
	xtn	v24.4h, v26.4s
	xtn2	v24.8h, v27.4s
	mul	v24.8h, v24.8h, v1.h[1]
	smlsl	v26.4s, v24.4h, v1.h[0]
	smlsl2	v27.4s, v24.8h, v1.h[0]
	shrn	v23.4h, v26.4s, #16
	shrn2	v23.8h, v27.4s, #16
	zip1	v24.8h, v22.8h, v23.8h
	zip2	v25.8h, v22.8h, v23.8h
	add	v28.8h, v28.8h, v24.8h
	add	v29.8h, v29.8h, v25.8h
	stp	q28, q29, [x0, #480]
	ldp	d8, d9, [x29, #16]
	ldp	d10, d11, [x29, #32]
	ldp	d12, d13, [x29, #48]
	ldp	d14, d15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
#ifndef __APPLE__
	.size	kyber_basemul_mont_add,.-kyber_basemul_mont_add
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	kyber_csubq_neon
.type	kyber_csubq_neon,@function
.align	2
kyber_csubq_neon:
#else
.section	__TEXT,__text
.globl	_kyber_csubq_neon
.p2align	2
_kyber_csubq_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
	stp	d12, d13, [x29, #48]
	stp	d14, d15, [x29, #64]
#ifndef __APPLE__
	adrp x1, L_kyber_aarch64_q
	add  x1, x1, :lo12:L_kyber_aarch64_q
#else
	adrp x1, L_kyber_aarch64_q@PAGE
	add  x1, x1, :lo12:L_kyber_aarch64_q@PAGEOFF
#endif /* __APPLE__ */
	ldr	q20, [x1]
	ld4	{v0.8h, v1.8h, v2.8h, v3.8h}, [x0], #0x40
	ld4	{v4.8h, v5.8h, v6.8h, v7.8h}, [x0], #0x40
	ld4	{v8.8h, v9.8h, v10.8h, v11.8h}, [x0], #0x40
	ld4	{v12.8h, v13.8h, v14.8h, v15.8h}, [x0], #0x40
	sub	x0, x0, #0x100
	sub	v0.8h, v0.8h, v20.8h
	sub	v1.8h, v1.8h, v20.8h
	sub	v2.8h, v2.8h, v20.8h
	sub	v3.8h, v3.8h, v20.8h
	sub	v4.8h, v4.8h, v20.8h
	sub	v5.8h, v5.8h, v20.8h
	sub	v6.8h, v6.8h, v20.8h
	sub	v7.8h, v7.8h, v20.8h
	sub	v8.8h, v8.8h, v20.8h
	sub	v9.8h, v9.8h, v20.8h
	sub	v10.8h, v10.8h, v20.8h
	sub	v11.8h, v11.8h, v20.8h
	sub	v12.8h, v12.8h, v20.8h
	sub	v13.8h, v13.8h, v20.8h
	sub	v14.8h, v14.8h, v20.8h
	sub	v15.8h, v15.8h, v20.8h
	sshr	v16.8h, v0.8h, #15
	sshr	v17.8h, v1.8h, #15
	sshr	v18.8h, v2.8h, #15
	sshr	v19.8h, v3.8h, #15
	and	v16.16b, v16.16b, v20.16b
	and	v17.16b, v17.16b, v20.16b
	and	v18.16b, v18.16b, v20.16b
	and	v19.16b, v19.16b, v20.16b
	add	v0.8h, v0.8h, v16.8h
	add	v1.8h, v1.8h, v17.8h
	add	v2.8h, v2.8h, v18.8h
	add	v3.8h, v3.8h, v19.8h
	sshr	v16.8h, v4.8h, #15
	sshr	v17.8h, v5.8h, #15
	sshr	v18.8h, v6.8h, #15
	sshr	v19.8h, v7.8h, #15
	and	v16.16b, v16.16b, v20.16b
	and	v17.16b, v17.16b, v20.16b
	and	v18.16b, v18.16b, v20.16b
	and	v19.16b, v19.16b, v20.16b
	add	v4.8h, v4.8h, v16.8h
	add	v5.8h, v5.8h, v17.8h
	add	v6.8h, v6.8h, v18.8h
	add	v7.8h, v7.8h, v19.8h
	sshr	v16.8h, v8.8h, #15
	sshr	v17.8h, v9.8h, #15
	sshr	v18.8h, v10.8h, #15
	sshr	v19.8h, v11.8h, #15
	and	v16.16b, v16.16b, v20.16b
	and	v17.16b, v17.16b, v20.16b
	and	v18.16b, v18.16b, v20.16b
	and	v19.16b, v19.16b, v20.16b
	add	v8.8h, v8.8h, v16.8h
	add	v9.8h, v9.8h, v17.8h
	add	v10.8h, v10.8h, v18.8h
	add	v11.8h, v11.8h, v19.8h
	sshr	v16.8h, v12.8h, #15
	sshr	v17.8h, v13.8h, #15
	sshr	v18.8h, v14.8h, #15
	sshr	v19.8h, v15.8h, #15
	and	v16.16b, v16.16b, v20.16b
	and	v17.16b, v17.16b, v20.16b
	and	v18.16b, v18.16b, v20.16b
	and	v19.16b, v19.16b, v20.16b
	add	v12.8h, v12.8h, v16.8h
	add	v13.8h, v13.8h, v17.8h
	add	v14.8h, v14.8h, v18.8h
	add	v15.8h, v15.8h, v19.8h
	st4	{v0.8h, v1.8h, v2.8h, v3.8h}, [x0], #0x40
	st4	{v4.8h, v5.8h, v6.8h, v7.8h}, [x0], #0x40
	st4	{v8.8h, v9.8h, v10.8h, v11.8h}, [x0], #0x40
	st4	{v12.8h, v13.8h, v14.8h, v15.8h}, [x0], #0x40
	ld4	{v0.8h, v1.8h, v2.8h, v3.8h}, [x0], #0x40
	ld4	{v4.8h, v5.8h, v6.8h, v7.8h}, [x0], #0x40
	ld4	{v8.8h, v9.8h, v10.8h, v11.8h}, [x0], #0x40
	ld4	{v12.8h, v13.8h, v14.8h, v15.8h}, [x0], #0x40
	sub	x0, x0, #0x100
	sub	v0.8h, v0.8h, v20.8h
	sub	v1.8h, v1.8h, v20.8h
	sub	v2.8h, v2.8h, v20.8h
	sub	v3.8h, v3.8h, v20.8h
	sub	v4.8h, v4.8h, v20.8h
	sub	v5.8h, v5.8h, v20.8h
	sub	v6.8h, v6.8h, v20.8h
	sub	v7.8h, v7.8h, v20.8h
	sub	v8.8h, v8.8h, v20.8h
	sub	v9.8h, v9.8h, v20.8h
	sub	v10.8h, v10.8h, v20.8h
	sub	v11.8h, v11.8h, v20.8h
	sub	v12.8h, v12.8h, v20.8h
	sub	v13.8h, v13.8h, v20.8h
	sub	v14.8h, v14.8h, v20.8h
	sub	v15.8h, v15.8h, v20.8h
	sshr	v16.8h, v0.8h, #15
	sshr	v17.8h, v1.8h, #15
	sshr	v18.8h, v2.8h, #15
	sshr	v19.8h, v3.8h, #15
	and	v16.16b, v16.16b, v20.16b
	and	v17.16b, v17.16b, v20.16b
	and	v18.16b, v18.16b, v20.16b
	and	v19.16b, v19.16b, v20.16b
	add	v0.8h, v0.8h, v16.8h
	add	v1.8h, v1.8h, v17.8h
	add	v2.8h, v2.8h, v18.8h
	add	v3.8h, v3.8h, v19.8h
	sshr	v16.8h, v4.8h, #15
	sshr	v17.8h, v5.8h, #15
	sshr	v18.8h, v6.8h, #15
	sshr	v19.8h, v7.8h, #15
	and	v16.16b, v16.16b, v20.16b
	and	v17.16b, v17.16b, v20.16b
	and	v18.16b, v18.16b, v20.16b
	and	v19.16b, v19.16b, v20.16b
	add	v4.8h, v4.8h, v16.8h
	add	v5.8h, v5.8h, v17.8h
	add	v6.8h, v6.8h, v18.8h
	add	v7.8h, v7.8h, v19.8h
	sshr	v16.8h, v8.8h, #15
	sshr	v17.8h, v9.8h, #15
	sshr	v18.8h, v10.8h, #15
	sshr	v19.8h, v11.8h, #15
	and	v16.16b, v16.16b, v20.16b
	and	v17.16b, v17.16b, v20.16b
	and	v18.16b, v18.16b, v20.16b
	and	v19.16b, v19.16b, v20.16b
	add	v8.8h, v8.8h, v16.8h
	add	v9.8h, v9.8h, v17.8h
	add	v10.8h, v10.8h, v18.8h
	add	v11.8h, v11.8h, v19.8h
	sshr	v16.8h, v12.8h, #15
	sshr	v17.8h, v13.8h, #15
	sshr	v18.8h, v14.8h, #15
	sshr	v19.8h, v15.8h, #15
	and	v16.16b, v16.16b, v20.16b
	and	v17.16b, v17.16b, v20.16b
	and	v18.16b, v18.16b, v20.16b
	and	v19.16b, v19.16b, v20.16b
	add	v12.8h, v12.8h, v16.8h
	add	v13.8h, v13.8h, v17.8h
	add	v14.8h, v14.8h, v18.8h
	add	v15.8h, v15.8h, v19.8h
	st4	{v0.8h, v1.8h, v2.8h, v3.8h}, [x0], #0x40
	st4	{v4.8h, v5.8h, v6.8h, v7.8h}, [x0], #0x40
	st4	{v8.8h, v9.8h, v10.8h, v11.8h}, [x0], #0x40
	st4	{v12.8h, v13.8h, v14.8h, v15.8h}, [x0], #0x40
	ldp	d8, d9, [x29, #16]
	ldp	d10, d11, [x29, #32]
	ldp	d12, d13, [x29, #48]
	ldp	d14, d15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
#ifndef __APPLE__
	.size	kyber_csubq_neon,.-kyber_csubq_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	kyber_add_reduce
.type	kyber_add_reduce,@function
.align	2
kyber_add_reduce:
#else
.section	__TEXT,__text
.globl	_kyber_add_reduce
.p2align	2
_kyber_add_reduce:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
	stp	d12, d13, [x29, #48]
	stp	d14, d15, [x29, #64]
#ifndef __APPLE__
	adrp x2, L_kyber_aarch64_consts
	add  x2, x2, :lo12:L_kyber_aarch64_consts
#else
	adrp x2, L_kyber_aarch64_consts@PAGE
	add  x2, x2, :lo12:L_kyber_aarch64_consts@PAGEOFF
#endif /* __APPLE__ */
	ldr	q0, [x2]
	ld4	{v1.8h, v2.8h, v3.8h, v4.8h}, [x0], #0x40
	ld4	{v5.8h, v6.8h, v7.8h, v8.8h}, [x0], #0x40
	ld4	{v9.8h, v10.8h, v11.8h, v12.8h}, [x1], #0x40
	ld4	{v13.8h, v14.8h, v15.8h, v16.8h}, [x1], #0x40
	sub	x0, x0, #0x80
	add	v1.8h, v1.8h, v9.8h
	add	v2.8h, v2.8h, v10.8h
	add	v3.8h, v3.8h, v11.8h
	add	v4.8h, v4.8h, v12.8h
	add	v5.8h, v5.8h, v13.8h
	add	v6.8h, v6.8h, v14.8h
	add	v7.8h, v7.8h, v15.8h
	add	v8.8h, v8.8h, v16.8h
	sqdmulh	v17.8h, v1.8h, v0.h[2]
	sqdmulh	v18.8h, v2.8h, v0.h[2]
	sshr	v17.8h, v17.8h, #11
	sshr	v18.8h, v18.8h, #11
	mls	v1.8h, v17.8h, v0.h[0]
	mls	v2.8h, v18.8h, v0.h[0]
	sqdmulh	v17.8h, v3.8h, v0.h[2]
	sqdmulh	v18.8h, v4.8h, v0.h[2]
	sshr	v17.8h, v17.8h, #11
	sshr	v18.8h, v18.8h, #11
	mls	v3.8h, v17.8h, v0.h[0]
	mls	v4.8h, v18.8h, v0.h[0]
	sqdmulh	v17.8h, v5.8h, v0.h[2]
	sqdmulh	v18.8h, v6.8h, v0.h[2]
	sshr	v17.8h, v17.8h, #11
	sshr	v18.8h, v18.8h, #11
	mls	v5.8h, v17.8h, v0.h[0]
	mls	v6.8h, v18.8h, v0.h[0]
	sqdmulh	v17.8h, v7.8h, v0.h[2]
	sqdmulh	v18.8h, v8.8h, v0.h[2]
	sshr	v17.8h, v17.8h, #11
	sshr	v18.8h, v18.8h, #11
	mls	v7.8h, v17.8h, v0.h[0]
	mls	v8.8h, v18.8h, v0.h[0]
	st4	{v1.8h, v2.8h, v3.8h, v4.8h}, [x0], #0x40
	st4	{v5.8h, v6.8h, v7.8h, v8.8h}, [x0], #0x40
	ld4	{v1.8h, v2.8h, v3.8h, v4.8h}, [x0], #0x40
	ld4	{v5.8h, v6.8h, v7.8h, v8.8h}, [x0], #0x40
	ld4	{v9.8h, v10.8h, v11.8h, v12.8h}, [x1], #0x40
	ld4	{v13.8h, v14.8h, v15.8h, v16.8h}, [x1], #0x40
	sub	x0, x0, #0x80
	add	v1.8h, v1.8h, v9.8h
	add	v2.8h, v2.8h, v10.8h
	add	v3.8h, v3.8h, v11.8h
	add	v4.8h, v4.8h, v12.8h
	add	v5.8h, v5.8h, v13.8h
	add	v6.8h, v6.8h, v14.8h
	add	v7.8h, v7.8h, v15.8h
	add	v8.8h, v8.8h, v16.8h
	sqdmulh	v17.8h, v1.8h, v0.h[2]
	sqdmulh	v18.8h, v2.8h, v0.h[2]
	sshr	v17.8h, v17.8h, #11
	sshr	v18.8h, v18.8h, #11
	mls	v1.8h, v17.8h, v0.h[0]
	mls	v2.8h, v18.8h, v0.h[0]
	sqdmulh	v17.8h, v3.8h, v0.h[2]
	sqdmulh	v18.8h, v4.8h, v0.h[2]
	sshr	v17.8h, v17.8h, #11
	sshr	v18.8h, v18.8h, #11
	mls	v3.8h, v17.8h, v0.h[0]
	mls	v4.8h, v18.8h, v0.h[0]
	sqdmulh	v17.8h, v5.8h, v0.h[2]
	sqdmulh	v18.8h, v6.8h, v0.h[2]
	sshr	v17.8h, v17.8h, #11
	sshr	v18.8h, v18.8h, #11
	mls	v5.8h, v17.8h, v0.h[0]
	mls	v6.8h, v18.8h, v0.h[0]
	sqdmulh	v17.8h, v7.8h, v0.h[2]
	sqdmulh	v18.8h, v8.8h, v0.h[2]
	sshr	v17.8h, v17.8h, #11
	sshr	v18.8h, v18.8h, #11
	mls	v7.8h, v17.8h, v0.h[0]
	mls	v8.8h, v18.8h, v0.h[0]
	st4	{v1.8h, v2.8h, v3.8h, v4.8h}, [x0], #0x40
	st4	{v5.8h, v6.8h, v7.8h, v8.8h}, [x0], #0x40
	ld4	{v1.8h, v2.8h, v3.8h, v4.8h}, [x0], #0x40
	ld4	{v5.8h, v6.8h, v7.8h, v8.8h}, [x0], #0x40
	ld4	{v9.8h, v10.8h, v11.8h, v12.8h}, [x1], #0x40
	ld4	{v13.8h, v14.8h, v15.8h, v16.8h}, [x1], #0x40
	sub	x0, x0, #0x80
	add	v1.8h, v1.8h, v9.8h
	add	v2.8h, v2.8h, v10.8h
	add	v3.8h, v3.8h, v11.8h
	add	v4.8h, v4.8h, v12.8h
	add	v5.8h, v5.8h, v13.8h
	add	v6.8h, v6.8h, v14.8h
	add	v7.8h, v7.8h, v15.8h
	add	v8.8h, v8.8h, v16.8h
	sqdmulh	v17.8h, v1.8h, v0.h[2]
	sqdmulh	v18.8h, v2.8h, v0.h[2]
	sshr	v17.8h, v17.8h, #11
	sshr	v18.8h, v18.8h, #11
	mls	v1.8h, v17.8h, v0.h[0]
	mls	v2.8h, v18.8h, v0.h[0]
	sqdmulh	v17.8h, v3.8h, v0.h[2]
	sqdmulh	v18.8h, v4.8h, v0.h[2]
	sshr	v17.8h, v17.8h, #11
	sshr	v18.8h, v18.8h, #11
	mls	v3.8h, v17.8h, v0.h[0]
	mls	v4.8h, v18.8h, v0.h[0]
	sqdmulh	v17.8h, v5.8h, v0.h[2]
	sqdmulh	v18.8h, v6.8h, v0.h[2]
	sshr	v17.8h, v17.8h, #11
	sshr	v18.8h, v18.8h, #11
	mls	v5.8h, v17.8h, v0.h[0]
	mls	v6.8h, v18.8h, v0.h[0]
	sqdmulh	v17.8h, v7.8h, v0.h[2]
	sqdmulh	v18.8h, v8.8h, v0.h[2]
	sshr	v17.8h, v17.8h, #11
	sshr	v18.8h, v18.8h, #11
	mls	v7.8h, v17.8h, v0.h[0]
	mls	v8.8h, v18.8h, v0.h[0]
	st4	{v1.8h, v2.8h, v3.8h, v4.8h}, [x0], #0x40
	st4	{v5.8h, v6.8h, v7.8h, v8.8h}, [x0], #0x40
	ld4	{v1.8h, v2.8h, v3.8h, v4.8h}, [x0], #0x40
	ld4	{v5.8h, v6.8h, v7.8h, v8.8h}, [x0], #0x40
	ld4	{v9.8h, v10.8h, v11.8h, v12.8h}, [x1], #0x40
	ld4	{v13.8h, v14.8h, v15.8h, v16.8h}, [x1], #0x40
	sub	x0, x0, #0x80
	add	v1.8h, v1.8h, v9.8h
	add	v2.8h, v2.8h, v10.8h
	add	v3.8h, v3.8h, v11.8h
	add	v4.8h, v4.8h, v12.8h
	add	v5.8h, v5.8h, v13.8h
	add	v6.8h, v6.8h, v14.8h
	add	v7.8h, v7.8h, v15.8h
	add	v8.8h, v8.8h, v16.8h
	sqdmulh	v17.8h, v1.8h, v0.h[2]
	sqdmulh	v18.8h, v2.8h, v0.h[2]
	sshr	v17.8h, v17.8h, #11
	sshr	v18.8h, v18.8h, #11
	mls	v1.8h, v17.8h, v0.h[0]
	mls	v2.8h, v18.8h, v0.h[0]
	sqdmulh	v17.8h, v3.8h, v0.h[2]
	sqdmulh	v18.8h, v4.8h, v0.h[2]
	sshr	v17.8h, v17.8h, #11
	sshr	v18.8h, v18.8h, #11
	mls	v3.8h, v17.8h, v0.h[0]
	mls	v4.8h, v18.8h, v0.h[0]
	sqdmulh	v17.8h, v5.8h, v0.h[2]
	sqdmulh	v18.8h, v6.8h, v0.h[2]
	sshr	v17.8h, v17.8h, #11
	sshr	v18.8h, v18.8h, #11
	mls	v5.8h, v17.8h, v0.h[0]
	mls	v6.8h, v18.8h, v0.h[0]
	sqdmulh	v17.8h, v7.8h, v0.h[2]
	sqdmulh	v18.8h, v8.8h, v0.h[2]
	sshr	v17.8h, v17.8h, #11
	sshr	v18.8h, v18.8h, #11
	mls	v7.8h, v17.8h, v0.h[0]
	mls	v8.8h, v18.8h, v0.h[0]
	st4	{v1.8h, v2.8h, v3.8h, v4.8h}, [x0], #0x40
	st4	{v5.8h, v6.8h, v7.8h, v8.8h}, [x0], #0x40
	ldp	d8, d9, [x29, #16]
	ldp	d10, d11, [x29, #32]
	ldp	d12, d13, [x29, #48]
	ldp	d14, d15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
#ifndef __APPLE__
	.size	kyber_add_reduce,.-kyber_add_reduce
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	kyber_add3_reduce
.type	kyber_add3_reduce,@function
.align	2
kyber_add3_reduce:
#else
.section	__TEXT,__text
.globl	_kyber_add3_reduce
.p2align	2
_kyber_add3_reduce:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
	stp	d12, d13, [x29, #48]
	stp	d14, d15, [x29, #64]
#ifndef __APPLE__
	adrp x3, L_kyber_aarch64_consts
	add  x3, x3, :lo12:L_kyber_aarch64_consts
#else
	adrp x3, L_kyber_aarch64_consts@PAGE
	add  x3, x3, :lo12:L_kyber_aarch64_consts@PAGEOFF
#endif /* __APPLE__ */
	ldr	q0, [x3]
	ld4	{v1.8h, v2.8h, v3.8h, v4.8h}, [x0], #0x40
	ld4	{v5.8h, v6.8h, v7.8h, v8.8h}, [x0], #0x40
	ld4	{v9.8h, v10.8h, v11.8h, v12.8h}, [x1], #0x40
	ld4	{v13.8h, v14.8h, v15.8h, v16.8h}, [x1], #0x40
	ld4	{v17.8h, v18.8h, v19.8h, v20.8h}, [x2], #0x40
	ld4	{v21.8h, v22.8h, v23.8h, v24.8h}, [x2], #0x40
	sub	x0, x0, #0x80
	add	v1.8h, v1.8h, v9.8h
	add	v2.8h, v2.8h, v10.8h
	add	v3.8h, v3.8h, v11.8h
	add	v4.8h, v4.8h, v12.8h
	add	v5.8h, v5.8h, v13.8h
	add	v6.8h, v6.8h, v14.8h
	add	v7.8h, v7.8h, v15.8h
	add	v8.8h, v8.8h, v16.8h
	add	v1.8h, v1.8h, v17.8h
	add	v2.8h, v2.8h, v18.8h
	add	v3.8h, v3.8h, v19.8h
	add	v4.8h, v4.8h, v20.8h
	add	v5.8h, v5.8h, v21.8h
	add	v6.8h, v6.8h, v22.8h
	add	v7.8h, v7.8h, v23.8h
	add	v8.8h, v8.8h, v24.8h
	sqdmulh	v25.8h, v1.8h, v0.h[2]
	sqdmulh	v26.8h, v2.8h, v0.h[2]
	sshr	v25.8h, v25.8h, #11
	sshr	v26.8h, v26.8h, #11
	mls	v1.8h, v25.8h, v0.h[0]
	mls	v2.8h, v26.8h, v0.h[0]
	sqdmulh	v25.8h, v3.8h, v0.h[2]
	sqdmulh	v26.8h, v4.8h, v0.h[2]
	sshr	v25.8h, v25.8h, #11
	sshr	v26.8h, v26.8h, #11
	mls	v3.8h, v25.8h, v0.h[0]
	mls	v4.8h, v26.8h, v0.h[0]
	sqdmulh	v25.8h, v5.8h, v0.h[2]
	sqdmulh	v26.8h, v6.8h, v0.h[2]
	sshr	v25.8h, v25.8h, #11
	sshr	v26.8h, v26.8h, #11
	mls	v5.8h, v25.8h, v0.h[0]
	mls	v6.8h, v26.8h, v0.h[0]
	sqdmulh	v25.8h, v7.8h, v0.h[2]
	sqdmulh	v26.8h, v8.8h, v0.h[2]
	sshr	v25.8h, v25.8h, #11
	sshr	v26.8h, v26.8h, #11
	mls	v7.8h, v25.8h, v0.h[0]
	mls	v8.8h, v26.8h, v0.h[0]
	st4	{v1.8h, v2.8h, v3.8h, v4.8h}, [x0], #0x40
	st4	{v5.8h, v6.8h, v7.8h, v8.8h}, [x0], #0x40
	ld4	{v1.8h, v2.8h, v3.8h, v4.8h}, [x0], #0x40
	ld4	{v5.8h, v6.8h, v7.8h, v8.8h}, [x0], #0x40
	ld4	{v9.8h, v10.8h, v11.8h, v12.8h}, [x1], #0x40
	ld4	{v13.8h, v14.8h, v15.8h, v16.8h}, [x1], #0x40
	ld4	{v17.8h, v18.8h, v19.8h, v20.8h}, [x2], #0x40
	ld4	{v21.8h, v22.8h, v23.8h, v24.8h}, [x2], #0x40
	sub	x0, x0, #0x80
	add	v1.8h, v1.8h, v9.8h
	add	v2.8h, v2.8h, v10.8h
	add	v3.8h, v3.8h, v11.8h
	add	v4.8h, v4.8h, v12.8h
	add	v5.8h, v5.8h, v13.8h
	add	v6.8h, v6.8h, v14.8h
	add	v7.8h, v7.8h, v15.8h
	add	v8.8h, v8.8h, v16.8h
	add	v1.8h, v1.8h, v17.8h
	add	v2.8h, v2.8h, v18.8h
	add	v3.8h, v3.8h, v19.8h
	add	v4.8h, v4.8h, v20.8h
	add	v5.8h, v5.8h, v21.8h
	add	v6.8h, v6.8h, v22.8h
	add	v7.8h, v7.8h, v23.8h
	add	v8.8h, v8.8h, v24.8h
	sqdmulh	v25.8h, v1.8h, v0.h[2]
	sqdmulh	v26.8h, v2.8h, v0.h[2]
	sshr	v25.8h, v25.8h, #11
	sshr	v26.8h, v26.8h, #11
	mls	v1.8h, v25.8h, v0.h[0]
	mls	v2.8h, v26.8h, v0.h[0]
	sqdmulh	v25.8h, v3.8h, v0.h[2]
	sqdmulh	v26.8h, v4.8h, v0.h[2]
	sshr	v25.8h, v25.8h, #11
	sshr	v26.8h, v26.8h, #11
	mls	v3.8h, v25.8h, v0.h[0]
	mls	v4.8h, v26.8h, v0.h[0]
	sqdmulh	v25.8h, v5.8h, v0.h[2]
	sqdmulh	v26.8h, v6.8h, v0.h[2]
	sshr	v25.8h, v25.8h, #11
	sshr	v26.8h, v26.8h, #11
	mls	v5.8h, v25.8h, v0.h[0]
	mls	v6.8h, v26.8h, v0.h[0]
	sqdmulh	v25.8h, v7.8h, v0.h[2]
	sqdmulh	v26.8h, v8.8h, v0.h[2]
	sshr	v25.8h, v25.8h, #11
	sshr	v26.8h, v26.8h, #11
	mls	v7.8h, v25.8h, v0.h[0]
	mls	v8.8h, v26.8h, v0.h[0]
	st4	{v1.8h, v2.8h, v3.8h, v4.8h}, [x0], #0x40
	st4	{v5.8h, v6.8h, v7.8h, v8.8h}, [x0], #0x40
	ld4	{v1.8h, v2.8h, v3.8h, v4.8h}, [x0], #0x40
	ld4	{v5.8h, v6.8h, v7.8h, v8.8h}, [x0], #0x40
	ld4	{v9.8h, v10.8h, v11.8h, v12.8h}, [x1], #0x40
	ld4	{v13.8h, v14.8h, v15.8h, v16.8h}, [x1], #0x40
	ld4	{v17.8h, v18.8h, v19.8h, v20.8h}, [x2], #0x40
	ld4	{v21.8h, v22.8h, v23.8h, v24.8h}, [x2], #0x40
	sub	x0, x0, #0x80
	add	v1.8h, v1.8h, v9.8h
	add	v2.8h, v2.8h, v10.8h
	add	v3.8h, v3.8h, v11.8h
	add	v4.8h, v4.8h, v12.8h
	add	v5.8h, v5.8h, v13.8h
	add	v6.8h, v6.8h, v14.8h
	add	v7.8h, v7.8h, v15.8h
	add	v8.8h, v8.8h, v16.8h
	add	v1.8h, v1.8h, v17.8h
	add	v2.8h, v2.8h, v18.8h
	add	v3.8h, v3.8h, v19.8h
	add	v4.8h, v4.8h, v20.8h
	add	v5.8h, v5.8h, v21.8h
	add	v6.8h, v6.8h, v22.8h
	add	v7.8h, v7.8h, v23.8h
	add	v8.8h, v8.8h, v24.8h
	sqdmulh	v25.8h, v1.8h, v0.h[2]
	sqdmulh	v26.8h, v2.8h, v0.h[2]
	sshr	v25.8h, v25.8h, #11
	sshr	v26.8h, v26.8h, #11
	mls	v1.8h, v25.8h, v0.h[0]
	mls	v2.8h, v26.8h, v0.h[0]
	sqdmulh	v25.8h, v3.8h, v0.h[2]
	sqdmulh	v26.8h, v4.8h, v0.h[2]
	sshr	v25.8h, v25.8h, #11
	sshr	v26.8h, v26.8h, #11
	mls	v3.8h, v25.8h, v0.h[0]
	mls	v4.8h, v26.8h, v0.h[0]
	sqdmulh	v25.8h, v5.8h, v0.h[2]
	sqdmulh	v26.8h, v6.8h, v0.h[2]
	sshr	v25.8h, v25.8h, #11
	sshr	v26.8h, v26.8h, #11
	mls	v5.8h, v25.8h, v0.h[0]
	mls	v6.8h, v26.8h, v0.h[0]
	sqdmulh	v25.8h, v7.8h, v0.h[2]
	sqdmulh	v26.8h, v8.8h, v0.h[2]
	sshr	v25.8h, v25.8h, #11
	sshr	v26.8h, v26.8h, #11
	mls	v7.8h, v25.8h, v0.h[0]
	mls	v8.8h, v26.8h, v0.h[0]
	st4	{v1.8h, v2.8h, v3.8h, v4.8h}, [x0], #0x40
	st4	{v5.8h, v6.8h, v7.8h, v8.8h}, [x0], #0x40
	ld4	{v1.8h, v2.8h, v3.8h, v4.8h}, [x0], #0x40
	ld4	{v5.8h, v6.8h, v7.8h, v8.8h}, [x0], #0x40
	ld4	{v9.8h, v10.8h, v11.8h, v12.8h}, [x1], #0x40
	ld4	{v13.8h, v14.8h, v15.8h, v16.8h}, [x1], #0x40
	ld4	{v17.8h, v18.8h, v19.8h, v20.8h}, [x2], #0x40
	ld4	{v21.8h, v22.8h, v23.8h, v24.8h}, [x2], #0x40
	sub	x0, x0, #0x80
	add	v1.8h, v1.8h, v9.8h
	add	v2.8h, v2.8h, v10.8h
	add	v3.8h, v3.8h, v11.8h
	add	v4.8h, v4.8h, v12.8h
	add	v5.8h, v5.8h, v13.8h
	add	v6.8h, v6.8h, v14.8h
	add	v7.8h, v7.8h, v15.8h
	add	v8.8h, v8.8h, v16.8h
	add	v1.8h, v1.8h, v17.8h
	add	v2.8h, v2.8h, v18.8h
	add	v3.8h, v3.8h, v19.8h
	add	v4.8h, v4.8h, v20.8h
	add	v5.8h, v5.8h, v21.8h
	add	v6.8h, v6.8h, v22.8h
	add	v7.8h, v7.8h, v23.8h
	add	v8.8h, v8.8h, v24.8h
	sqdmulh	v25.8h, v1.8h, v0.h[2]
	sqdmulh	v26.8h, v2.8h, v0.h[2]
	sshr	v25.8h, v25.8h, #11
	sshr	v26.8h, v26.8h, #11
	mls	v1.8h, v25.8h, v0.h[0]
	mls	v2.8h, v26.8h, v0.h[0]
	sqdmulh	v25.8h, v3.8h, v0.h[2]
	sqdmulh	v26.8h, v4.8h, v0.h[2]
	sshr	v25.8h, v25.8h, #11
	sshr	v26.8h, v26.8h, #11
	mls	v3.8h, v25.8h, v0.h[0]
	mls	v4.8h, v26.8h, v0.h[0]
	sqdmulh	v25.8h, v5.8h, v0.h[2]
	sqdmulh	v26.8h, v6.8h, v0.h[2]
	sshr	v25.8h, v25.8h, #11
	sshr	v26.8h, v26.8h, #11
	mls	v5.8h, v25.8h, v0.h[0]
	mls	v6.8h, v26.8h, v0.h[0]
	sqdmulh	v25.8h, v7.8h, v0.h[2]
	sqdmulh	v26.8h, v8.8h, v0.h[2]
	sshr	v25.8h, v25.8h, #11
	sshr	v26.8h, v26.8h, #11
	mls	v7.8h, v25.8h, v0.h[0]
	mls	v8.8h, v26.8h, v0.h[0]
	st4	{v1.8h, v2.8h, v3.8h, v4.8h}, [x0], #0x40
	st4	{v5.8h, v6.8h, v7.8h, v8.8h}, [x0], #0x40
	ldp	d8, d9, [x29, #16]
	ldp	d10, d11, [x29, #32]
	ldp	d12, d13, [x29, #48]
	ldp	d14, d15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
#ifndef __APPLE__
	.size	kyber_add3_reduce,.-kyber_add3_reduce
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	kyber_rsub_reduce
.type	kyber_rsub_reduce,@function
.align	2
kyber_rsub_reduce:
#else
.section	__TEXT,__text
.globl	_kyber_rsub_reduce
.p2align	2
_kyber_rsub_reduce:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
	stp	d12, d13, [x29, #48]
	stp	d14, d15, [x29, #64]
#ifndef __APPLE__
	adrp x2, L_kyber_aarch64_consts
	add  x2, x2, :lo12:L_kyber_aarch64_consts
#else
	adrp x2, L_kyber_aarch64_consts@PAGE
	add  x2, x2, :lo12:L_kyber_aarch64_consts@PAGEOFF
#endif /* __APPLE__ */
	ldr	q0, [x2]
	ld4	{v1.8h, v2.8h, v3.8h, v4.8h}, [x0], #0x40
	ld4	{v5.8h, v6.8h, v7.8h, v8.8h}, [x0], #0x40
	ld4	{v9.8h, v10.8h, v11.8h, v12.8h}, [x1], #0x40
	ld4	{v13.8h, v14.8h, v15.8h, v16.8h}, [x1], #0x40
	sub	x0, x0, #0x80
	sub	v1.8h, v9.8h, v1.8h
	sub	v2.8h, v10.8h, v2.8h
	sub	v3.8h, v11.8h, v3.8h
	sub	v4.8h, v12.8h, v4.8h
	sub	v5.8h, v13.8h, v5.8h
	sub	v6.8h, v14.8h, v6.8h
	sub	v7.8h, v15.8h, v7.8h
	sub	v8.8h, v16.8h, v8.8h
	sqdmulh	v17.8h, v1.8h, v0.h[2]
	sqdmulh	v18.8h, v2.8h, v0.h[2]
	sshr	v17.8h, v17.8h, #11
	sshr	v18.8h, v18.8h, #11
	mls	v1.8h, v17.8h, v0.h[0]
	mls	v2.8h, v18.8h, v0.h[0]
	sqdmulh	v17.8h, v3.8h, v0.h[2]
	sqdmulh	v18.8h, v4.8h, v0.h[2]
	sshr	v17.8h, v17.8h, #11
	sshr	v18.8h, v18.8h, #11
	mls	v3.8h, v17.8h, v0.h[0]
	mls	v4.8h, v18.8h, v0.h[0]
	sqdmulh	v17.8h, v5.8h, v0.h[2]
	sqdmulh	v18.8h, v6.8h, v0.h[2]
	sshr	v17.8h, v17.8h, #11
	sshr	v18.8h, v18.8h, #11
	mls	v5.8h, v17.8h, v0.h[0]
	mls	v6.8h, v18.8h, v0.h[0]
	sqdmulh	v17.8h, v7.8h, v0.h[2]
	sqdmulh	v18.8h, v8.8h, v0.h[2]
	sshr	v17.8h, v17.8h, #11
	sshr	v18.8h, v18.8h, #11
	mls	v7.8h, v17.8h, v0.h[0]
	mls	v8.8h, v18.8h, v0.h[0]
	st4	{v1.8h, v2.8h, v3.8h, v4.8h}, [x0], #0x40
	st4	{v5.8h, v6.8h, v7.8h, v8.8h}, [x0], #0x40
	ld4	{v1.8h, v2.8h, v3.8h, v4.8h}, [x0], #0x40
	ld4	{v5.8h, v6.8h, v7.8h, v8.8h}, [x0], #0x40
	ld4	{v9.8h, v10.8h, v11.8h, v12.8h}, [x1], #0x40
	ld4	{v13.8h, v14.8h, v15.8h, v16.8h}, [x1], #0x40
	sub	x0, x0, #0x80
	sub	v1.8h, v9.8h, v1.8h
	sub	v2.8h, v10.8h, v2.8h
	sub	v3.8h, v11.8h, v3.8h
	sub	v4.8h, v12.8h, v4.8h
	sub	v5.8h, v13.8h, v5.8h
	sub	v6.8h, v14.8h, v6.8h
	sub	v7.8h, v15.8h, v7.8h
	sub	v8.8h, v16.8h, v8.8h
	sqdmulh	v17.8h, v1.8h, v0.h[2]
	sqdmulh	v18.8h, v2.8h, v0.h[2]
	sshr	v17.8h, v17.8h, #11
	sshr	v18.8h, v18.8h, #11
	mls	v1.8h, v17.8h, v0.h[0]
	mls	v2.8h, v18.8h, v0.h[0]
	sqdmulh	v17.8h, v3.8h, v0.h[2]
	sqdmulh	v18.8h, v4.8h, v0.h[2]
	sshr	v17.8h, v17.8h, #11
	sshr	v18.8h, v18.8h, #11
	mls	v3.8h, v17.8h, v0.h[0]
	mls	v4.8h, v18.8h, v0.h[0]
	sqdmulh	v17.8h, v5.8h, v0.h[2]
	sqdmulh	v18.8h, v6.8h, v0.h[2]
	sshr	v17.8h, v17.8h, #11
	sshr	v18.8h, v18.8h, #11
	mls	v5.8h, v17.8h, v0.h[0]
	mls	v6.8h, v18.8h, v0.h[0]
	sqdmulh	v17.8h, v7.8h, v0.h[2]
	sqdmulh	v18.8h, v8.8h, v0.h[2]
	sshr	v17.8h, v17.8h, #11
	sshr	v18.8h, v18.8h, #11
	mls	v7.8h, v17.8h, v0.h[0]
	mls	v8.8h, v18.8h, v0.h[0]
	st4	{v1.8h, v2.8h, v3.8h, v4.8h}, [x0], #0x40
	st4	{v5.8h, v6.8h, v7.8h, v8.8h}, [x0], #0x40
	ld4	{v1.8h, v2.8h, v3.8h, v4.8h}, [x0], #0x40
	ld4	{v5.8h, v6.8h, v7.8h, v8.8h}, [x0], #0x40
	ld4	{v9.8h, v10.8h, v11.8h, v12.8h}, [x1], #0x40
	ld4	{v13.8h, v14.8h, v15.8h, v16.8h}, [x1], #0x40
	sub	x0, x0, #0x80
	sub	v1.8h, v9.8h, v1.8h
	sub	v2.8h, v10.8h, v2.8h
	sub	v3.8h, v11.8h, v3.8h
	sub	v4.8h, v12.8h, v4.8h
	sub	v5.8h, v13.8h, v5.8h
	sub	v6.8h, v14.8h, v6.8h
	sub	v7.8h, v15.8h, v7.8h
	sub	v8.8h, v16.8h, v8.8h
	sqdmulh	v17.8h, v1.8h, v0.h[2]
	sqdmulh	v18.8h, v2.8h, v0.h[2]
	sshr	v17.8h, v17.8h, #11
	sshr	v18.8h, v18.8h, #11
	mls	v1.8h, v17.8h, v0.h[0]
	mls	v2.8h, v18.8h, v0.h[0]
	sqdmulh	v17.8h, v3.8h, v0.h[2]
	sqdmulh	v18.8h, v4.8h, v0.h[2]
	sshr	v17.8h, v17.8h, #11
	sshr	v18.8h, v18.8h, #11
	mls	v3.8h, v17.8h, v0.h[0]
	mls	v4.8h, v18.8h, v0.h[0]
	sqdmulh	v17.8h, v5.8h, v0.h[2]
	sqdmulh	v18.8h, v6.8h, v0.h[2]
	sshr	v17.8h, v17.8h, #11
	sshr	v18.8h, v18.8h, #11
	mls	v5.8h, v17.8h, v0.h[0]
	mls	v6.8h, v18.8h, v0.h[0]
	sqdmulh	v17.8h, v7.8h, v0.h[2]
	sqdmulh	v18.8h, v8.8h, v0.h[2]
	sshr	v17.8h, v17.8h, #11
	sshr	v18.8h, v18.8h, #11
	mls	v7.8h, v17.8h, v0.h[0]
	mls	v8.8h, v18.8h, v0.h[0]
	st4	{v1.8h, v2.8h, v3.8h, v4.8h}, [x0], #0x40
	st4	{v5.8h, v6.8h, v7.8h, v8.8h}, [x0], #0x40
	ld4	{v1.8h, v2.8h, v3.8h, v4.8h}, [x0], #0x40
	ld4	{v5.8h, v6.8h, v7.8h, v8.8h}, [x0], #0x40
	ld4	{v9.8h, v10.8h, v11.8h, v12.8h}, [x1], #0x40
	ld4	{v13.8h, v14.8h, v15.8h, v16.8h}, [x1], #0x40
	sub	x0, x0, #0x80
	sub	v1.8h, v9.8h, v1.8h
	sub	v2.8h, v10.8h, v2.8h
	sub	v3.8h, v11.8h, v3.8h
	sub	v4.8h, v12.8h, v4.8h
	sub	v5.8h, v13.8h, v5.8h
	sub	v6.8h, v14.8h, v6.8h
	sub	v7.8h, v15.8h, v7.8h
	sub	v8.8h, v16.8h, v8.8h
	sqdmulh	v17.8h, v1.8h, v0.h[2]
	sqdmulh	v18.8h, v2.8h, v0.h[2]
	sshr	v17.8h, v17.8h, #11
	sshr	v18.8h, v18.8h, #11
	mls	v1.8h, v17.8h, v0.h[0]
	mls	v2.8h, v18.8h, v0.h[0]
	sqdmulh	v17.8h, v3.8h, v0.h[2]
	sqdmulh	v18.8h, v4.8h, v0.h[2]
	sshr	v17.8h, v17.8h, #11
	sshr	v18.8h, v18.8h, #11
	mls	v3.8h, v17.8h, v0.h[0]
	mls	v4.8h, v18.8h, v0.h[0]
	sqdmulh	v17.8h, v5.8h, v0.h[2]
	sqdmulh	v18.8h, v6.8h, v0.h[2]
	sshr	v17.8h, v17.8h, #11
	sshr	v18.8h, v18.8h, #11
	mls	v5.8h, v17.8h, v0.h[0]
	mls	v6.8h, v18.8h, v0.h[0]
	sqdmulh	v17.8h, v7.8h, v0.h[2]
	sqdmulh	v18.8h, v8.8h, v0.h[2]
	sshr	v17.8h, v17.8h, #11
	sshr	v18.8h, v18.8h, #11
	mls	v7.8h, v17.8h, v0.h[0]
	mls	v8.8h, v18.8h, v0.h[0]
	st4	{v1.8h, v2.8h, v3.8h, v4.8h}, [x0], #0x40
	st4	{v5.8h, v6.8h, v7.8h, v8.8h}, [x0], #0x40
	ldp	d8, d9, [x29, #16]
	ldp	d10, d11, [x29, #32]
	ldp	d12, d13, [x29, #48]
	ldp	d14, d15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
#ifndef __APPLE__
	.size	kyber_rsub_reduce,.-kyber_rsub_reduce
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	kyber_to_mont
.type	kyber_to_mont,@function
.align	2
kyber_to_mont:
#else
.section	__TEXT,__text
.globl	_kyber_to_mont
.p2align	2
_kyber_to_mont:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
	stp	d12, d13, [x29, #48]
	stp	d14, d15, [x29, #64]
#ifndef __APPLE__
	adrp x1, L_kyber_aarch64_consts
	add  x1, x1, :lo12:L_kyber_aarch64_consts
#else
	adrp x1, L_kyber_aarch64_consts@PAGE
	add  x1, x1, :lo12:L_kyber_aarch64_consts@PAGEOFF
#endif /* __APPLE__ */
	ldr	q0, [x1]
	ld4	{v1.8h, v2.8h, v3.8h, v4.8h}, [x0], #0x40
	ld4	{v5.8h, v6.8h, v7.8h, v8.8h}, [x0], #0x40
	ld4	{v9.8h, v10.8h, v11.8h, v12.8h}, [x0], #0x40
	ld4	{v13.8h, v14.8h, v15.8h, v16.8h}, [x0], #0x40
	sub	x0, x0, #0x100
	mul	v17.8h, v1.8h, v0.h[4]
	mul	v18.8h, v2.8h, v0.h[4]
	sqrdmulh	v1.8h, v1.8h, v0.h[3]
	sqrdmulh	v2.8h, v2.8h, v0.h[3]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v1.8h, v17.8h, v0.h[0]
	sqrdmlsh	v2.8h, v18.8h, v0.h[0]
#else
	sqrdmulh	v17.8h, v17.8h, v0.h[0]
	sqrdmulh	v18.8h, v18.8h, v0.h[0]
	sub	v1.8h, v1.8h, v17.8h
	sub	v2.8h, v2.8h, v18.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v1.8h, v1.8h, #1
	sshr	v2.8h, v2.8h, #1
	mul	v17.8h, v3.8h, v0.h[4]
	mul	v18.8h, v4.8h, v0.h[4]
	sqrdmulh	v3.8h, v3.8h, v0.h[3]
	sqrdmulh	v4.8h, v4.8h, v0.h[3]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v3.8h, v17.8h, v0.h[0]
	sqrdmlsh	v4.8h, v18.8h, v0.h[0]
#else
	sqrdmulh	v17.8h, v17.8h, v0.h[0]
	sqrdmulh	v18.8h, v18.8h, v0.h[0]
	sub	v3.8h, v3.8h, v17.8h
	sub	v4.8h, v4.8h, v18.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v3.8h, v3.8h, #1
	sshr	v4.8h, v4.8h, #1
	mul	v17.8h, v5.8h, v0.h[4]
	mul	v18.8h, v6.8h, v0.h[4]
	sqrdmulh	v5.8h, v5.8h, v0.h[3]
	sqrdmulh	v6.8h, v6.8h, v0.h[3]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v5.8h, v17.8h, v0.h[0]
	sqrdmlsh	v6.8h, v18.8h, v0.h[0]
#else
	sqrdmulh	v17.8h, v17.8h, v0.h[0]
	sqrdmulh	v18.8h, v18.8h, v0.h[0]
	sub	v5.8h, v5.8h, v17.8h
	sub	v6.8h, v6.8h, v18.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v5.8h, v5.8h, #1
	sshr	v6.8h, v6.8h, #1
	mul	v17.8h, v7.8h, v0.h[4]
	mul	v18.8h, v8.8h, v0.h[4]
	sqrdmulh	v7.8h, v7.8h, v0.h[3]
	sqrdmulh	v8.8h, v8.8h, v0.h[3]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v7.8h, v17.8h, v0.h[0]
	sqrdmlsh	v8.8h, v18.8h, v0.h[0]
#else
	sqrdmulh	v17.8h, v17.8h, v0.h[0]
	sqrdmulh	v18.8h, v18.8h, v0.h[0]
	sub	v7.8h, v7.8h, v17.8h
	sub	v8.8h, v8.8h, v18.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v7.8h, v7.8h, #1
	sshr	v8.8h, v8.8h, #1
	mul	v17.8h, v9.8h, v0.h[4]
	mul	v18.8h, v10.8h, v0.h[4]
	sqrdmulh	v9.8h, v9.8h, v0.h[3]
	sqrdmulh	v10.8h, v10.8h, v0.h[3]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v9.8h, v17.8h, v0.h[0]
	sqrdmlsh	v10.8h, v18.8h, v0.h[0]
#else
	sqrdmulh	v17.8h, v17.8h, v0.h[0]
	sqrdmulh	v18.8h, v18.8h, v0.h[0]
	sub	v9.8h, v9.8h, v17.8h
	sub	v10.8h, v10.8h, v18.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v9.8h, v9.8h, #1
	sshr	v10.8h, v10.8h, #1
	mul	v17.8h, v11.8h, v0.h[4]
	mul	v18.8h, v12.8h, v0.h[4]
	sqrdmulh	v11.8h, v11.8h, v0.h[3]
	sqrdmulh	v12.8h, v12.8h, v0.h[3]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v11.8h, v17.8h, v0.h[0]
	sqrdmlsh	v12.8h, v18.8h, v0.h[0]
#else
	sqrdmulh	v17.8h, v17.8h, v0.h[0]
	sqrdmulh	v18.8h, v18.8h, v0.h[0]
	sub	v11.8h, v11.8h, v17.8h
	sub	v12.8h, v12.8h, v18.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v11.8h, v11.8h, #1
	sshr	v12.8h, v12.8h, #1
	mul	v17.8h, v13.8h, v0.h[4]
	mul	v18.8h, v14.8h, v0.h[4]
	sqrdmulh	v13.8h, v13.8h, v0.h[3]
	sqrdmulh	v14.8h, v14.8h, v0.h[3]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v13.8h, v17.8h, v0.h[0]
	sqrdmlsh	v14.8h, v18.8h, v0.h[0]
#else
	sqrdmulh	v17.8h, v17.8h, v0.h[0]
	sqrdmulh	v18.8h, v18.8h, v0.h[0]
	sub	v13.8h, v13.8h, v17.8h
	sub	v14.8h, v14.8h, v18.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v13.8h, v13.8h, #1
	sshr	v14.8h, v14.8h, #1
	mul	v17.8h, v15.8h, v0.h[4]
	mul	v18.8h, v16.8h, v0.h[4]
	sqrdmulh	v15.8h, v15.8h, v0.h[3]
	sqrdmulh	v16.8h, v16.8h, v0.h[3]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v15.8h, v17.8h, v0.h[0]
	sqrdmlsh	v16.8h, v18.8h, v0.h[0]
#else
	sqrdmulh	v17.8h, v17.8h, v0.h[0]
	sqrdmulh	v18.8h, v18.8h, v0.h[0]
	sub	v15.8h, v15.8h, v17.8h
	sub	v16.8h, v16.8h, v18.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v15.8h, v15.8h, #1
	sshr	v16.8h, v16.8h, #1
	st4	{v1.8h, v2.8h, v3.8h, v4.8h}, [x0], #0x40
	st4	{v5.8h, v6.8h, v7.8h, v8.8h}, [x0], #0x40
	st4	{v9.8h, v10.8h, v11.8h, v12.8h}, [x0], #0x40
	st4	{v13.8h, v14.8h, v15.8h, v16.8h}, [x0], #0x40
	ld4	{v1.8h, v2.8h, v3.8h, v4.8h}, [x0], #0x40
	ld4	{v5.8h, v6.8h, v7.8h, v8.8h}, [x0], #0x40
	ld4	{v9.8h, v10.8h, v11.8h, v12.8h}, [x0], #0x40
	ld4	{v13.8h, v14.8h, v15.8h, v16.8h}, [x0], #0x40
	sub	x0, x0, #0x100
	mul	v17.8h, v1.8h, v0.h[4]
	mul	v18.8h, v2.8h, v0.h[4]
	sqrdmulh	v1.8h, v1.8h, v0.h[3]
	sqrdmulh	v2.8h, v2.8h, v0.h[3]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v1.8h, v17.8h, v0.h[0]
	sqrdmlsh	v2.8h, v18.8h, v0.h[0]
#else
	sqrdmulh	v17.8h, v17.8h, v0.h[0]
	sqrdmulh	v18.8h, v18.8h, v0.h[0]
	sub	v1.8h, v1.8h, v17.8h
	sub	v2.8h, v2.8h, v18.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v1.8h, v1.8h, #1
	sshr	v2.8h, v2.8h, #1
	mul	v17.8h, v3.8h, v0.h[4]
	mul	v18.8h, v4.8h, v0.h[4]
	sqrdmulh	v3.8h, v3.8h, v0.h[3]
	sqrdmulh	v4.8h, v4.8h, v0.h[3]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v3.8h, v17.8h, v0.h[0]
	sqrdmlsh	v4.8h, v18.8h, v0.h[0]
#else
	sqrdmulh	v17.8h, v17.8h, v0.h[0]
	sqrdmulh	v18.8h, v18.8h, v0.h[0]
	sub	v3.8h, v3.8h, v17.8h
	sub	v4.8h, v4.8h, v18.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v3.8h, v3.8h, #1
	sshr	v4.8h, v4.8h, #1
	mul	v17.8h, v5.8h, v0.h[4]
	mul	v18.8h, v6.8h, v0.h[4]
	sqrdmulh	v5.8h, v5.8h, v0.h[3]
	sqrdmulh	v6.8h, v6.8h, v0.h[3]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v5.8h, v17.8h, v0.h[0]
	sqrdmlsh	v6.8h, v18.8h, v0.h[0]
#else
	sqrdmulh	v17.8h, v17.8h, v0.h[0]
	sqrdmulh	v18.8h, v18.8h, v0.h[0]
	sub	v5.8h, v5.8h, v17.8h
	sub	v6.8h, v6.8h, v18.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v5.8h, v5.8h, #1
	sshr	v6.8h, v6.8h, #1
	mul	v17.8h, v7.8h, v0.h[4]
	mul	v18.8h, v8.8h, v0.h[4]
	sqrdmulh	v7.8h, v7.8h, v0.h[3]
	sqrdmulh	v8.8h, v8.8h, v0.h[3]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v7.8h, v17.8h, v0.h[0]
	sqrdmlsh	v8.8h, v18.8h, v0.h[0]
#else
	sqrdmulh	v17.8h, v17.8h, v0.h[0]
	sqrdmulh	v18.8h, v18.8h, v0.h[0]
	sub	v7.8h, v7.8h, v17.8h
	sub	v8.8h, v8.8h, v18.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v7.8h, v7.8h, #1
	sshr	v8.8h, v8.8h, #1
	mul	v17.8h, v9.8h, v0.h[4]
	mul	v18.8h, v10.8h, v0.h[4]
	sqrdmulh	v9.8h, v9.8h, v0.h[3]
	sqrdmulh	v10.8h, v10.8h, v0.h[3]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v9.8h, v17.8h, v0.h[0]
	sqrdmlsh	v10.8h, v18.8h, v0.h[0]
#else
	sqrdmulh	v17.8h, v17.8h, v0.h[0]
	sqrdmulh	v18.8h, v18.8h, v0.h[0]
	sub	v9.8h, v9.8h, v17.8h
	sub	v10.8h, v10.8h, v18.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v9.8h, v9.8h, #1
	sshr	v10.8h, v10.8h, #1
	mul	v17.8h, v11.8h, v0.h[4]
	mul	v18.8h, v12.8h, v0.h[4]
	sqrdmulh	v11.8h, v11.8h, v0.h[3]
	sqrdmulh	v12.8h, v12.8h, v0.h[3]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v11.8h, v17.8h, v0.h[0]
	sqrdmlsh	v12.8h, v18.8h, v0.h[0]
#else
	sqrdmulh	v17.8h, v17.8h, v0.h[0]
	sqrdmulh	v18.8h, v18.8h, v0.h[0]
	sub	v11.8h, v11.8h, v17.8h
	sub	v12.8h, v12.8h, v18.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v11.8h, v11.8h, #1
	sshr	v12.8h, v12.8h, #1
	mul	v17.8h, v13.8h, v0.h[4]
	mul	v18.8h, v14.8h, v0.h[4]
	sqrdmulh	v13.8h, v13.8h, v0.h[3]
	sqrdmulh	v14.8h, v14.8h, v0.h[3]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v13.8h, v17.8h, v0.h[0]
	sqrdmlsh	v14.8h, v18.8h, v0.h[0]
#else
	sqrdmulh	v17.8h, v17.8h, v0.h[0]
	sqrdmulh	v18.8h, v18.8h, v0.h[0]
	sub	v13.8h, v13.8h, v17.8h
	sub	v14.8h, v14.8h, v18.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v13.8h, v13.8h, #1
	sshr	v14.8h, v14.8h, #1
	mul	v17.8h, v15.8h, v0.h[4]
	mul	v18.8h, v16.8h, v0.h[4]
	sqrdmulh	v15.8h, v15.8h, v0.h[3]
	sqrdmulh	v16.8h, v16.8h, v0.h[3]
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
	sqrdmlsh	v15.8h, v17.8h, v0.h[0]
	sqrdmlsh	v16.8h, v18.8h, v0.h[0]
#else
	sqrdmulh	v17.8h, v17.8h, v0.h[0]
	sqrdmulh	v18.8h, v18.8h, v0.h[0]
	sub	v15.8h, v15.8h, v17.8h
	sub	v16.8h, v16.8h, v18.8h
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
	sshr	v15.8h, v15.8h, #1
	sshr	v16.8h, v16.8h, #1
	st4	{v1.8h, v2.8h, v3.8h, v4.8h}, [x0], #0x40
	st4	{v5.8h, v6.8h, v7.8h, v8.8h}, [x0], #0x40
	st4	{v9.8h, v10.8h, v11.8h, v12.8h}, [x0], #0x40
	st4	{v13.8h, v14.8h, v15.8h, v16.8h}, [x0], #0x40
	ldp	d8, d9, [x29, #16]
	ldp	d10, d11, [x29, #32]
	ldp	d12, d13, [x29, #48]
	ldp	d14, d15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
#ifndef __APPLE__
	.size	kyber_to_mont,.-kyber_to_mont
#endif /* __APPLE__ */
#ifndef __APPLE__
	.text
	.type	L_kyber_aarch64_to_msg_neon_low, %object
	.section	.rodata
	.size	L_kyber_aarch64_to_msg_neon_low, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
#ifndef __APPLE__
	.align	2
#else
	.p2align	2
#endif /* __APPLE__ */
L_kyber_aarch64_to_msg_neon_low:
	.short	0x0373,0x0373,0x0373,0x0373,0x0373,0x0373,0x0373,0x0373
#ifndef __APPLE__
	.text
	.type	L_kyber_aarch64_to_msg_neon_high, %object
	.section	.rodata
	.size	L_kyber_aarch64_to_msg_neon_high, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
#ifndef __APPLE__
	.align	2
#else
	.p2align	2
#endif /* __APPLE__ */
L_kyber_aarch64_to_msg_neon_high:
	.short	0x09c0,0x09c0,0x09c0,0x09c0,0x09c0,0x09c0,0x09c0,0x09c0
#ifndef __APPLE__
	.text
	.type	L_kyber_aarch64_to_msg_neon_bits, %object
	.section	.rodata
	.size	L_kyber_aarch64_to_msg_neon_bits, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
#ifndef __APPLE__
	.align	2
#else
	.p2align	2
#endif /* __APPLE__ */
L_kyber_aarch64_to_msg_neon_bits:
	.short	0x0001,0x0002,0x0004,0x0008,0x0010,0x0020,0x0040,0x0080
#ifndef __APPLE__
.text
.globl	kyber_to_msg_neon
.type	kyber_to_msg_neon,@function
.align	2
kyber_to_msg_neon:
#else
.section	__TEXT,__text
.globl	_kyber_to_msg_neon
.p2align	2
_kyber_to_msg_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
	stp	d12, d13, [x29, #48]
	stp	d14, d15, [x29, #64]
#ifndef __APPLE__
	adrp x2, L_kyber_aarch64_to_msg_neon_low
	add  x2, x2, :lo12:L_kyber_aarch64_to_msg_neon_low
#else
	adrp x2, L_kyber_aarch64_to_msg_neon_low@PAGE
	add  x2, x2, :lo12:L_kyber_aarch64_to_msg_neon_low@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x3, L_kyber_aarch64_to_msg_neon_high
	add  x3, x3, :lo12:L_kyber_aarch64_to_msg_neon_high
#else
	adrp x3, L_kyber_aarch64_to_msg_neon_high@PAGE
	add  x3, x3, :lo12:L_kyber_aarch64_to_msg_neon_high@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x4, L_kyber_aarch64_to_msg_neon_bits
	add  x4, x4, :lo12:L_kyber_aarch64_to_msg_neon_bits
#else
	adrp x4, L_kyber_aarch64_to_msg_neon_bits@PAGE
	add  x4, x4, :lo12:L_kyber_aarch64_to_msg_neon_bits@PAGEOFF
#endif /* __APPLE__ */
	ldr	q0, [x2]
	ldr	q1, [x3]
	ldr	q26, [x4]
	ld1	{v2.8h, v3.8h, v4.8h, v5.8h}, [x1], #0x40
	ld1	{v6.8h, v7.8h, v8.8h, v9.8h}, [x1], #0x40
	cmge	v10.8h, v2.8h, v0.8h
	cmge	v18.8h, v1.8h, v2.8h
	cmge	v11.8h, v3.8h, v0.8h
	cmge	v19.8h, v1.8h, v3.8h
	cmge	v12.8h, v4.8h, v0.8h
	cmge	v20.8h, v1.8h, v4.8h
	cmge	v13.8h, v5.8h, v0.8h
	cmge	v21.8h, v1.8h, v5.8h
	cmge	v14.8h, v6.8h, v0.8h
	cmge	v22.8h, v1.8h, v6.8h
	cmge	v15.8h, v7.8h, v0.8h
	cmge	v23.8h, v1.8h, v7.8h
	cmge	v16.8h, v8.8h, v0.8h
	cmge	v24.8h, v1.8h, v8.8h
	cmge	v17.8h, v9.8h, v0.8h
	cmge	v25.8h, v1.8h, v9.8h
	and	v18.16b, v18.16b, v10.16b
	and	v19.16b, v19.16b, v11.16b
	and	v20.16b, v20.16b, v12.16b
	and	v21.16b, v21.16b, v13.16b
	and	v22.16b, v22.16b, v14.16b
	and	v23.16b, v23.16b, v15.16b
	and	v24.16b, v24.16b, v16.16b
	and	v25.16b, v25.16b, v17.16b
	and	v18.16b, v18.16b, v26.16b
	and	v19.16b, v19.16b, v26.16b
	and	v20.16b, v20.16b, v26.16b
	and	v21.16b, v21.16b, v26.16b
	and	v22.16b, v22.16b, v26.16b
	and	v23.16b, v23.16b, v26.16b
	and	v24.16b, v24.16b, v26.16b
	and	v25.16b, v25.16b, v26.16b
	addv	h18, v18.8h
	addv	h19, v19.8h
	addv	h20, v20.8h
	addv	h21, v21.8h
	addv	h22, v22.8h
	addv	h23, v23.8h
	addv	h24, v24.8h
	addv	h25, v25.8h
	ins	v18.b[1], v19.b[0]
	ins	v18.b[2], v20.b[0]
	ins	v18.b[3], v21.b[0]
	ins	v18.b[4], v22.b[0]
	ins	v18.b[5], v23.b[0]
	ins	v18.b[6], v24.b[0]
	ins	v18.b[7], v25.b[0]
	st1	{v18.8b}, [x0], #8
	ld1	{v2.8h, v3.8h, v4.8h, v5.8h}, [x1], #0x40
	ld1	{v6.8h, v7.8h, v8.8h, v9.8h}, [x1], #0x40
	cmge	v10.8h, v2.8h, v0.8h
	cmge	v18.8h, v1.8h, v2.8h
	cmge	v11.8h, v3.8h, v0.8h
	cmge	v19.8h, v1.8h, v3.8h
	cmge	v12.8h, v4.8h, v0.8h
	cmge	v20.8h, v1.8h, v4.8h
	cmge	v13.8h, v5.8h, v0.8h
	cmge	v21.8h, v1.8h, v5.8h
	cmge	v14.8h, v6.8h, v0.8h
	cmge	v22.8h, v1.8h, v6.8h
	cmge	v15.8h, v7.8h, v0.8h
	cmge	v23.8h, v1.8h, v7.8h
	cmge	v16.8h, v8.8h, v0.8h
	cmge	v24.8h, v1.8h, v8.8h
	cmge	v17.8h, v9.8h, v0.8h
	cmge	v25.8h, v1.8h, v9.8h
	and	v18.16b, v18.16b, v10.16b
	and	v19.16b, v19.16b, v11.16b
	and	v20.16b, v20.16b, v12.16b
	and	v21.16b, v21.16b, v13.16b
	and	v22.16b, v22.16b, v14.16b
	and	v23.16b, v23.16b, v15.16b
	and	v24.16b, v24.16b, v16.16b
	and	v25.16b, v25.16b, v17.16b
	and	v18.16b, v18.16b, v26.16b
	and	v19.16b, v19.16b, v26.16b
	and	v20.16b, v20.16b, v26.16b
	and	v21.16b, v21.16b, v26.16b
	and	v22.16b, v22.16b, v26.16b
	and	v23.16b, v23.16b, v26.16b
	and	v24.16b, v24.16b, v26.16b
	and	v25.16b, v25.16b, v26.16b
	addv	h18, v18.8h
	addv	h19, v19.8h
	addv	h20, v20.8h
	addv	h21, v21.8h
	addv	h22, v22.8h
	addv	h23, v23.8h
	addv	h24, v24.8h
	addv	h25, v25.8h
	ins	v18.b[1], v19.b[0]
	ins	v18.b[2], v20.b[0]
	ins	v18.b[3], v21.b[0]
	ins	v18.b[4], v22.b[0]
	ins	v18.b[5], v23.b[0]
	ins	v18.b[6], v24.b[0]
	ins	v18.b[7], v25.b[0]
	st1	{v18.8b}, [x0], #8
	ld1	{v2.8h, v3.8h, v4.8h, v5.8h}, [x1], #0x40
	ld1	{v6.8h, v7.8h, v8.8h, v9.8h}, [x1], #0x40
	cmge	v10.8h, v2.8h, v0.8h
	cmge	v18.8h, v1.8h, v2.8h
	cmge	v11.8h, v3.8h, v0.8h
	cmge	v19.8h, v1.8h, v3.8h
	cmge	v12.8h, v4.8h, v0.8h
	cmge	v20.8h, v1.8h, v4.8h
	cmge	v13.8h, v5.8h, v0.8h
	cmge	v21.8h, v1.8h, v5.8h
	cmge	v14.8h, v6.8h, v0.8h
	cmge	v22.8h, v1.8h, v6.8h
	cmge	v15.8h, v7.8h, v0.8h
	cmge	v23.8h, v1.8h, v7.8h
	cmge	v16.8h, v8.8h, v0.8h
	cmge	v24.8h, v1.8h, v8.8h
	cmge	v17.8h, v9.8h, v0.8h
	cmge	v25.8h, v1.8h, v9.8h
	and	v18.16b, v18.16b, v10.16b
	and	v19.16b, v19.16b, v11.16b
	and	v20.16b, v20.16b, v12.16b
	and	v21.16b, v21.16b, v13.16b
	and	v22.16b, v22.16b, v14.16b
	and	v23.16b, v23.16b, v15.16b
	and	v24.16b, v24.16b, v16.16b
	and	v25.16b, v25.16b, v17.16b
	and	v18.16b, v18.16b, v26.16b
	and	v19.16b, v19.16b, v26.16b
	and	v20.16b, v20.16b, v26.16b
	and	v21.16b, v21.16b, v26.16b
	and	v22.16b, v22.16b, v26.16b
	and	v23.16b, v23.16b, v26.16b
	and	v24.16b, v24.16b, v26.16b
	and	v25.16b, v25.16b, v26.16b
	addv	h18, v18.8h
	addv	h19, v19.8h
	addv	h20, v20.8h
	addv	h21, v21.8h
	addv	h22, v22.8h
	addv	h23, v23.8h
	addv	h24, v24.8h
	addv	h25, v25.8h
	ins	v18.b[1], v19.b[0]
	ins	v18.b[2], v20.b[0]
	ins	v18.b[3], v21.b[0]
	ins	v18.b[4], v22.b[0]
	ins	v18.b[5], v23.b[0]
	ins	v18.b[6], v24.b[0]
	ins	v18.b[7], v25.b[0]
	st1	{v18.8b}, [x0], #8
	ld1	{v2.8h, v3.8h, v4.8h, v5.8h}, [x1], #0x40
	ld1	{v6.8h, v7.8h, v8.8h, v9.8h}, [x1], #0x40
	cmge	v10.8h, v2.8h, v0.8h
	cmge	v18.8h, v1.8h, v2.8h
	cmge	v11.8h, v3.8h, v0.8h
	cmge	v19.8h, v1.8h, v3.8h
	cmge	v12.8h, v4.8h, v0.8h
	cmge	v20.8h, v1.8h, v4.8h
	cmge	v13.8h, v5.8h, v0.8h
	cmge	v21.8h, v1.8h, v5.8h
	cmge	v14.8h, v6.8h, v0.8h
	cmge	v22.8h, v1.8h, v6.8h
	cmge	v15.8h, v7.8h, v0.8h
	cmge	v23.8h, v1.8h, v7.8h
	cmge	v16.8h, v8.8h, v0.8h
	cmge	v24.8h, v1.8h, v8.8h
	cmge	v17.8h, v9.8h, v0.8h
	cmge	v25.8h, v1.8h, v9.8h
	and	v18.16b, v18.16b, v10.16b
	and	v19.16b, v19.16b, v11.16b
	and	v20.16b, v20.16b, v12.16b
	and	v21.16b, v21.16b, v13.16b
	and	v22.16b, v22.16b, v14.16b
	and	v23.16b, v23.16b, v15.16b
	and	v24.16b, v24.16b, v16.16b
	and	v25.16b, v25.16b, v17.16b
	and	v18.16b, v18.16b, v26.16b
	and	v19.16b, v19.16b, v26.16b
	and	v20.16b, v20.16b, v26.16b
	and	v21.16b, v21.16b, v26.16b
	and	v22.16b, v22.16b, v26.16b
	and	v23.16b, v23.16b, v26.16b
	and	v24.16b, v24.16b, v26.16b
	and	v25.16b, v25.16b, v26.16b
	addv	h18, v18.8h
	addv	h19, v19.8h
	addv	h20, v20.8h
	addv	h21, v21.8h
	addv	h22, v22.8h
	addv	h23, v23.8h
	addv	h24, v24.8h
	addv	h25, v25.8h
	ins	v18.b[1], v19.b[0]
	ins	v18.b[2], v20.b[0]
	ins	v18.b[3], v21.b[0]
	ins	v18.b[4], v22.b[0]
	ins	v18.b[5], v23.b[0]
	ins	v18.b[6], v24.b[0]
	ins	v18.b[7], v25.b[0]
	st1	{v18.8b}, [x0], #8
	ldp	d8, d9, [x29, #16]
	ldp	d10, d11, [x29, #32]
	ldp	d12, d13, [x29, #48]
	ldp	d14, d15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
#ifndef __APPLE__
	.size	kyber_to_msg_neon,.-kyber_to_msg_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
	.text
	.type	L_kyber_aarch64_from_msg_neon_q1half, %object
	.section	.rodata
	.size	L_kyber_aarch64_from_msg_neon_q1half, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
#ifndef __APPLE__
	.align	2
#else
	.p2align	2
#endif /* __APPLE__ */
L_kyber_aarch64_from_msg_neon_q1half:
	.short	0x0681,0x0681,0x0681,0x0681,0x0681,0x0681,0x0681,0x0681
#ifndef __APPLE__
	.text
	.type	L_kyber_aarch64_from_msg_neon_bits, %object
	.section	.rodata
	.size	L_kyber_aarch64_from_msg_neon_bits, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
#ifndef __APPLE__
	.align	1
#else
	.p2align	1
#endif /* __APPLE__ */
L_kyber_aarch64_from_msg_neon_bits:
	.byte	0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80
	.byte	0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80
#ifndef __APPLE__
.text
.globl	kyber_from_msg_neon
.type	kyber_from_msg_neon,@function
.align	2
kyber_from_msg_neon:
#else
.section	__TEXT,__text
.globl	_kyber_from_msg_neon
.p2align	2
_kyber_from_msg_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-48]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
#ifndef __APPLE__
	adrp x2, L_kyber_aarch64_from_msg_neon_q1half
	add  x2, x2, :lo12:L_kyber_aarch64_from_msg_neon_q1half
#else
	adrp x2, L_kyber_aarch64_from_msg_neon_q1half@PAGE
	add  x2, x2, :lo12:L_kyber_aarch64_from_msg_neon_q1half@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x3, L_kyber_aarch64_from_msg_neon_bits
	add  x3, x3, :lo12:L_kyber_aarch64_from_msg_neon_bits
#else
	adrp x3, L_kyber_aarch64_from_msg_neon_bits@PAGE
	add  x3, x3, :lo12:L_kyber_aarch64_from_msg_neon_bits@PAGEOFF
#endif /* __APPLE__ */
	ld1	{v2.16b, v3.16b}, [x1]
	ldr	q1, [x2]
	ldr	q0, [x3]
	dup	v4.8b, v2.b[0]
	dup	v5.8b, v2.b[1]
	dup	v6.8b, v2.b[2]
	dup	v7.8b, v2.b[3]
	cmtst	v4.8b, v4.8b, v0.8b
	cmtst	v5.8b, v5.8b, v0.8b
	cmtst	v6.8b, v6.8b, v0.8b
	cmtst	v7.8b, v7.8b, v0.8b
	zip1	v4.16b, v4.16b, v4.16b
	zip1	v5.16b, v5.16b, v5.16b
	zip1	v6.16b, v6.16b, v6.16b
	zip1	v7.16b, v7.16b, v7.16b
	and	v4.16b, v4.16b, v1.16b
	and	v5.16b, v5.16b, v1.16b
	and	v6.16b, v6.16b, v1.16b
	and	v7.16b, v7.16b, v1.16b
	st1	{v4.8h, v5.8h, v6.8h, v7.8h}, [x0], #0x40
	dup	v4.8b, v2.b[4]
	dup	v5.8b, v2.b[5]
	dup	v6.8b, v2.b[6]
	dup	v7.8b, v2.b[7]
	cmtst	v4.8b, v4.8b, v0.8b
	cmtst	v5.8b, v5.8b, v0.8b
	cmtst	v6.8b, v6.8b, v0.8b
	cmtst	v7.8b, v7.8b, v0.8b
	zip1	v4.16b, v4.16b, v4.16b
	zip1	v5.16b, v5.16b, v5.16b
	zip1	v6.16b, v6.16b, v6.16b
	zip1	v7.16b, v7.16b, v7.16b
	and	v4.16b, v4.16b, v1.16b
	and	v5.16b, v5.16b, v1.16b
	and	v6.16b, v6.16b, v1.16b
	and	v7.16b, v7.16b, v1.16b
	st1	{v4.8h, v5.8h, v6.8h, v7.8h}, [x0], #0x40
	dup	v4.8b, v2.b[8]
	dup	v5.8b, v2.b[9]
	dup	v6.8b, v2.b[10]
	dup	v7.8b, v2.b[11]
	cmtst	v4.8b, v4.8b, v0.8b
	cmtst	v5.8b, v5.8b, v0.8b
	cmtst	v6.8b, v6.8b, v0.8b
	cmtst	v7.8b, v7.8b, v0.8b
	zip1	v4.16b, v4.16b, v4.16b
	zip1	v5.16b, v5.16b, v5.16b
	zip1	v6.16b, v6.16b, v6.16b
	zip1	v7.16b, v7.16b, v7.16b
	and	v4.16b, v4.16b, v1.16b
	and	v5.16b, v5.16b, v1.16b
	and	v6.16b, v6.16b, v1.16b
	and	v7.16b, v7.16b, v1.16b
	st1	{v4.8h, v5.8h, v6.8h, v7.8h}, [x0], #0x40
	dup	v4.8b, v2.b[12]
	dup	v5.8b, v2.b[13]
	dup	v6.8b, v2.b[14]
	dup	v7.8b, v2.b[15]
	cmtst	v4.8b, v4.8b, v0.8b
	cmtst	v5.8b, v5.8b, v0.8b
	cmtst	v6.8b, v6.8b, v0.8b
	cmtst	v7.8b, v7.8b, v0.8b
	zip1	v4.16b, v4.16b, v4.16b
	zip1	v5.16b, v5.16b, v5.16b
	zip1	v6.16b, v6.16b, v6.16b
	zip1	v7.16b, v7.16b, v7.16b
	and	v4.16b, v4.16b, v1.16b
	and	v5.16b, v5.16b, v1.16b
	and	v6.16b, v6.16b, v1.16b
	and	v7.16b, v7.16b, v1.16b
	st1	{v4.8h, v5.8h, v6.8h, v7.8h}, [x0], #0x40
	dup	v4.8b, v3.b[0]
	dup	v5.8b, v3.b[1]
	dup	v6.8b, v3.b[2]
	dup	v7.8b, v3.b[3]
	cmtst	v4.8b, v4.8b, v0.8b
	cmtst	v5.8b, v5.8b, v0.8b
	cmtst	v6.8b, v6.8b, v0.8b
	cmtst	v7.8b, v7.8b, v0.8b
	zip1	v4.16b, v4.16b, v4.16b
	zip1	v5.16b, v5.16b, v5.16b
	zip1	v6.16b, v6.16b, v6.16b
	zip1	v7.16b, v7.16b, v7.16b
	and	v4.16b, v4.16b, v1.16b
	and	v5.16b, v5.16b, v1.16b
	and	v6.16b, v6.16b, v1.16b
	and	v7.16b, v7.16b, v1.16b
	st1	{v4.8h, v5.8h, v6.8h, v7.8h}, [x0], #0x40
	dup	v4.8b, v3.b[4]
	dup	v5.8b, v3.b[5]
	dup	v6.8b, v3.b[6]
	dup	v7.8b, v3.b[7]
	cmtst	v4.8b, v4.8b, v0.8b
	cmtst	v5.8b, v5.8b, v0.8b
	cmtst	v6.8b, v6.8b, v0.8b
	cmtst	v7.8b, v7.8b, v0.8b
	zip1	v4.16b, v4.16b, v4.16b
	zip1	v5.16b, v5.16b, v5.16b
	zip1	v6.16b, v6.16b, v6.16b
	zip1	v7.16b, v7.16b, v7.16b
	and	v4.16b, v4.16b, v1.16b
	and	v5.16b, v5.16b, v1.16b
	and	v6.16b, v6.16b, v1.16b
	and	v7.16b, v7.16b, v1.16b
	st1	{v4.8h, v5.8h, v6.8h, v7.8h}, [x0], #0x40
	dup	v4.8b, v3.b[8]
	dup	v5.8b, v3.b[9]
	dup	v6.8b, v3.b[10]
	dup	v7.8b, v3.b[11]
	cmtst	v4.8b, v4.8b, v0.8b
	cmtst	v5.8b, v5.8b, v0.8b
	cmtst	v6.8b, v6.8b, v0.8b
	cmtst	v7.8b, v7.8b, v0.8b
	zip1	v4.16b, v4.16b, v4.16b
	zip1	v5.16b, v5.16b, v5.16b
	zip1	v6.16b, v6.16b, v6.16b
	zip1	v7.16b, v7.16b, v7.16b
	and	v4.16b, v4.16b, v1.16b
	and	v5.16b, v5.16b, v1.16b
	and	v6.16b, v6.16b, v1.16b
	and	v7.16b, v7.16b, v1.16b
	st1	{v4.8h, v5.8h, v6.8h, v7.8h}, [x0], #0x40
	dup	v4.8b, v3.b[12]
	dup	v5.8b, v3.b[13]
	dup	v6.8b, v3.b[14]
	dup	v7.8b, v3.b[15]
	cmtst	v4.8b, v4.8b, v0.8b
	cmtst	v5.8b, v5.8b, v0.8b
	cmtst	v6.8b, v6.8b, v0.8b
	cmtst	v7.8b, v7.8b, v0.8b
	zip1	v4.16b, v4.16b, v4.16b
	zip1	v5.16b, v5.16b, v5.16b
	zip1	v6.16b, v6.16b, v6.16b
	zip1	v7.16b, v7.16b, v7.16b
	and	v4.16b, v4.16b, v1.16b
	and	v5.16b, v5.16b, v1.16b
	and	v6.16b, v6.16b, v1.16b
	and	v7.16b, v7.16b, v1.16b
	st1	{v4.8h, v5.8h, v6.8h, v7.8h}, [x0], #0x40
	ldp	d8, d9, [x29, #16]
	ldp	d10, d11, [x29, #32]
	ldp	x29, x30, [sp], #48
	ret
#ifndef __APPLE__
	.size	kyber_from_msg_neon,.-kyber_from_msg_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	kyber_cmp_neon
.type	kyber_cmp_neon,@function
.align	2
kyber_cmp_neon:
#else
.section	__TEXT,__text
.globl	_kyber_cmp_neon
.p2align	2
_kyber_cmp_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-48]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
	ld4	{v0.16b, v1.16b, v2.16b, v3.16b}, [x0], #0x40
	ld4	{v4.16b, v5.16b, v6.16b, v7.16b}, [x1], #0x40
	eor	v8.16b, v0.16b, v4.16b
	eor	v9.16b, v1.16b, v5.16b
	eor	v10.16b, v2.16b, v6.16b
	eor	v11.16b, v3.16b, v7.16b
	ld4	{v0.16b, v1.16b, v2.16b, v3.16b}, [x0], #0x40
	ld4	{v4.16b, v5.16b, v6.16b, v7.16b}, [x1], #0x40
	eor	v0.16b, v0.16b, v4.16b
	eor	v1.16b, v1.16b, v5.16b
	eor	v2.16b, v2.16b, v6.16b
	eor	v3.16b, v3.16b, v7.16b
	orr	v8.16b, v8.16b, v0.16b
	orr	v9.16b, v9.16b, v1.16b
	orr	v10.16b, v10.16b, v2.16b
	orr	v11.16b, v11.16b, v3.16b
	ld4	{v0.16b, v1.16b, v2.16b, v3.16b}, [x0], #0x40
	ld4	{v4.16b, v5.16b, v6.16b, v7.16b}, [x1], #0x40
	eor	v0.16b, v0.16b, v4.16b
	eor	v1.16b, v1.16b, v5.16b
	eor	v2.16b, v2.16b, v6.16b
	eor	v3.16b, v3.16b, v7.16b
	orr	v8.16b, v8.16b, v0.16b
	orr	v9.16b, v9.16b, v1.16b
	orr	v10.16b, v10.16b, v2.16b
	orr	v11.16b, v11.16b, v3.16b
	ld4	{v0.16b, v1.16b, v2.16b, v3.16b}, [x0], #0x40
	ld4	{v4.16b, v5.16b, v6.16b, v7.16b}, [x1], #0x40
	eor	v0.16b, v0.16b, v4.16b
	eor	v1.16b, v1.16b, v5.16b
	eor	v2.16b, v2.16b, v6.16b
	eor	v3.16b, v3.16b, v7.16b
	orr	v8.16b, v8.16b, v0.16b
	orr	v9.16b, v9.16b, v1.16b
	orr	v10.16b, v10.16b, v2.16b
	orr	v11.16b, v11.16b, v3.16b
	ld4	{v0.16b, v1.16b, v2.16b, v3.16b}, [x0], #0x40
	ld4	{v4.16b, v5.16b, v6.16b, v7.16b}, [x1], #0x40
	eor	v0.16b, v0.16b, v4.16b
	eor	v1.16b, v1.16b, v5.16b
	eor	v2.16b, v2.16b, v6.16b
	eor	v3.16b, v3.16b, v7.16b
	orr	v8.16b, v8.16b, v0.16b
	orr	v9.16b, v9.16b, v1.16b
	orr	v10.16b, v10.16b, v2.16b
	orr	v11.16b, v11.16b, v3.16b
	ld4	{v0.16b, v1.16b, v2.16b, v3.16b}, [x0], #0x40
	ld4	{v4.16b, v5.16b, v6.16b, v7.16b}, [x1], #0x40
	eor	v0.16b, v0.16b, v4.16b
	eor	v1.16b, v1.16b, v5.16b
	eor	v2.16b, v2.16b, v6.16b
	eor	v3.16b, v3.16b, v7.16b
	orr	v8.16b, v8.16b, v0.16b
	orr	v9.16b, v9.16b, v1.16b
	orr	v10.16b, v10.16b, v2.16b
	orr	v11.16b, v11.16b, v3.16b
	ld4	{v0.16b, v1.16b, v2.16b, v3.16b}, [x0], #0x40
	ld4	{v4.16b, v5.16b, v6.16b, v7.16b}, [x1], #0x40
	eor	v0.16b, v0.16b, v4.16b
	eor	v1.16b, v1.16b, v5.16b
	eor	v2.16b, v2.16b, v6.16b
	eor	v3.16b, v3.16b, v7.16b
	orr	v8.16b, v8.16b, v0.16b
	orr	v9.16b, v9.16b, v1.16b
	orr	v10.16b, v10.16b, v2.16b
	orr	v11.16b, v11.16b, v3.16b
	ld4	{v0.16b, v1.16b, v2.16b, v3.16b}, [x0], #0x40
	ld4	{v4.16b, v5.16b, v6.16b, v7.16b}, [x1], #0x40
	eor	v0.16b, v0.16b, v4.16b
	eor	v1.16b, v1.16b, v5.16b
	eor	v2.16b, v2.16b, v6.16b
	eor	v3.16b, v3.16b, v7.16b
	orr	v8.16b, v8.16b, v0.16b
	orr	v9.16b, v9.16b, v1.16b
	orr	v10.16b, v10.16b, v2.16b
	orr	v11.16b, v11.16b, v3.16b
	ld4	{v0.16b, v1.16b, v2.16b, v3.16b}, [x0], #0x40
	ld4	{v4.16b, v5.16b, v6.16b, v7.16b}, [x1], #0x40
	eor	v0.16b, v0.16b, v4.16b
	eor	v1.16b, v1.16b, v5.16b
	eor	v2.16b, v2.16b, v6.16b
	eor	v3.16b, v3.16b, v7.16b
	orr	v8.16b, v8.16b, v0.16b
	orr	v9.16b, v9.16b, v1.16b
	orr	v10.16b, v10.16b, v2.16b
	orr	v11.16b, v11.16b, v3.16b
	ld4	{v0.16b, v1.16b, v2.16b, v3.16b}, [x0], #0x40
	ld4	{v4.16b, v5.16b, v6.16b, v7.16b}, [x1], #0x40
	eor	v0.16b, v0.16b, v4.16b
	eor	v1.16b, v1.16b, v5.16b
	eor	v2.16b, v2.16b, v6.16b
	eor	v3.16b, v3.16b, v7.16b
	orr	v8.16b, v8.16b, v0.16b
	orr	v9.16b, v9.16b, v1.16b
	orr	v10.16b, v10.16b, v2.16b
	orr	v11.16b, v11.16b, v3.16b
	ld4	{v0.16b, v1.16b, v2.16b, v3.16b}, [x0], #0x40
	ld4	{v4.16b, v5.16b, v6.16b, v7.16b}, [x1], #0x40
	eor	v0.16b, v0.16b, v4.16b
	eor	v1.16b, v1.16b, v5.16b
	eor	v2.16b, v2.16b, v6.16b
	eor	v3.16b, v3.16b, v7.16b
	orr	v8.16b, v8.16b, v0.16b
	orr	v9.16b, v9.16b, v1.16b
	orr	v10.16b, v10.16b, v2.16b
	orr	v11.16b, v11.16b, v3.16b
	ld4	{v0.16b, v1.16b, v2.16b, v3.16b}, [x0], #0x40
	ld4	{v4.16b, v5.16b, v6.16b, v7.16b}, [x1], #0x40
	eor	v0.16b, v0.16b, v4.16b
	eor	v1.16b, v1.16b, v5.16b
	eor	v2.16b, v2.16b, v6.16b
	eor	v3.16b, v3.16b, v7.16b
	orr	v8.16b, v8.16b, v0.16b
	orr	v9.16b, v9.16b, v1.16b
	orr	v10.16b, v10.16b, v2.16b
	orr	v11.16b, v11.16b, v3.16b
	subs	w2, w2, #0x300
	beq	L_kyber_aarch64_cmp_neon_done
	ld4	{v0.16b, v1.16b, v2.16b, v3.16b}, [x0], #0x40
	ld4	{v4.16b, v5.16b, v6.16b, v7.16b}, [x1], #0x40
	eor	v0.16b, v0.16b, v4.16b
	eor	v1.16b, v1.16b, v5.16b
	eor	v2.16b, v2.16b, v6.16b
	eor	v3.16b, v3.16b, v7.16b
	orr	v8.16b, v8.16b, v0.16b
	orr	v9.16b, v9.16b, v1.16b
	orr	v10.16b, v10.16b, v2.16b
	orr	v11.16b, v11.16b, v3.16b
	ld4	{v0.16b, v1.16b, v2.16b, v3.16b}, [x0], #0x40
	ld4	{v4.16b, v5.16b, v6.16b, v7.16b}, [x1], #0x40
	eor	v0.16b, v0.16b, v4.16b
	eor	v1.16b, v1.16b, v5.16b
	eor	v2.16b, v2.16b, v6.16b
	eor	v3.16b, v3.16b, v7.16b
	orr	v8.16b, v8.16b, v0.16b
	orr	v9.16b, v9.16b, v1.16b
	orr	v10.16b, v10.16b, v2.16b
	orr	v11.16b, v11.16b, v3.16b
	ld4	{v0.16b, v1.16b, v2.16b, v3.16b}, [x0], #0x40
	ld4	{v4.16b, v5.16b, v6.16b, v7.16b}, [x1], #0x40
	eor	v0.16b, v0.16b, v4.16b
	eor	v1.16b, v1.16b, v5.16b
	eor	v2.16b, v2.16b, v6.16b
	eor	v3.16b, v3.16b, v7.16b
	orr	v8.16b, v8.16b, v0.16b
	orr	v9.16b, v9.16b, v1.16b
	orr	v10.16b, v10.16b, v2.16b
	orr	v11.16b, v11.16b, v3.16b
	ld4	{v0.16b, v1.16b, v2.16b, v3.16b}, [x0], #0x40
	ld4	{v4.16b, v5.16b, v6.16b, v7.16b}, [x1], #0x40
	eor	v0.16b, v0.16b, v4.16b
	eor	v1.16b, v1.16b, v5.16b
	eor	v2.16b, v2.16b, v6.16b
	eor	v3.16b, v3.16b, v7.16b
	orr	v8.16b, v8.16b, v0.16b
	orr	v9.16b, v9.16b, v1.16b
	orr	v10.16b, v10.16b, v2.16b
	orr	v11.16b, v11.16b, v3.16b
	ld4	{v0.16b, v1.16b, v2.16b, v3.16b}, [x0], #0x40
	ld4	{v4.16b, v5.16b, v6.16b, v7.16b}, [x1], #0x40
	eor	v0.16b, v0.16b, v4.16b
	eor	v1.16b, v1.16b, v5.16b
	eor	v2.16b, v2.16b, v6.16b
	eor	v3.16b, v3.16b, v7.16b
	orr	v8.16b, v8.16b, v0.16b
	orr	v9.16b, v9.16b, v1.16b
	orr	v10.16b, v10.16b, v2.16b
	orr	v11.16b, v11.16b, v3.16b
	subs	w2, w2, #0x140
	beq	L_kyber_aarch64_cmp_neon_done
	ld4	{v0.16b, v1.16b, v2.16b, v3.16b}, [x0], #0x40
	ld4	{v4.16b, v5.16b, v6.16b, v7.16b}, [x1], #0x40
	eor	v0.16b, v0.16b, v4.16b
	eor	v1.16b, v1.16b, v5.16b
	eor	v2.16b, v2.16b, v6.16b
	eor	v3.16b, v3.16b, v7.16b
	orr	v8.16b, v8.16b, v0.16b
	orr	v9.16b, v9.16b, v1.16b
	orr	v10.16b, v10.16b, v2.16b
	orr	v11.16b, v11.16b, v3.16b
	ld4	{v0.16b, v1.16b, v2.16b, v3.16b}, [x0], #0x40
	ld4	{v4.16b, v5.16b, v6.16b, v7.16b}, [x1], #0x40
	eor	v0.16b, v0.16b, v4.16b
	eor	v1.16b, v1.16b, v5.16b
	eor	v2.16b, v2.16b, v6.16b
	eor	v3.16b, v3.16b, v7.16b
	orr	v8.16b, v8.16b, v0.16b
	orr	v9.16b, v9.16b, v1.16b
	orr	v10.16b, v10.16b, v2.16b
	orr	v11.16b, v11.16b, v3.16b
	ld4	{v0.16b, v1.16b, v2.16b, v3.16b}, [x0], #0x40
	ld4	{v4.16b, v5.16b, v6.16b, v7.16b}, [x1], #0x40
	eor	v0.16b, v0.16b, v4.16b
	eor	v1.16b, v1.16b, v5.16b
	eor	v2.16b, v2.16b, v6.16b
	eor	v3.16b, v3.16b, v7.16b
	orr	v8.16b, v8.16b, v0.16b
	orr	v9.16b, v9.16b, v1.16b
	orr	v10.16b, v10.16b, v2.16b
	orr	v11.16b, v11.16b, v3.16b
	ld4	{v0.16b, v1.16b, v2.16b, v3.16b}, [x0], #0x40
	ld4	{v4.16b, v5.16b, v6.16b, v7.16b}, [x1], #0x40
	eor	v0.16b, v0.16b, v4.16b
	eor	v1.16b, v1.16b, v5.16b
	eor	v2.16b, v2.16b, v6.16b
	eor	v3.16b, v3.16b, v7.16b
	orr	v8.16b, v8.16b, v0.16b
	orr	v9.16b, v9.16b, v1.16b
	orr	v10.16b, v10.16b, v2.16b
	orr	v11.16b, v11.16b, v3.16b
	ld4	{v0.16b, v1.16b, v2.16b, v3.16b}, [x0], #0x40
	ld4	{v4.16b, v5.16b, v6.16b, v7.16b}, [x1], #0x40
	eor	v0.16b, v0.16b, v4.16b
	eor	v1.16b, v1.16b, v5.16b
	eor	v2.16b, v2.16b, v6.16b
	eor	v3.16b, v3.16b, v7.16b
	orr	v8.16b, v8.16b, v0.16b
	orr	v9.16b, v9.16b, v1.16b
	orr	v10.16b, v10.16b, v2.16b
	orr	v11.16b, v11.16b, v3.16b
	ld4	{v0.16b, v1.16b, v2.16b, v3.16b}, [x0], #0x40
	ld4	{v4.16b, v5.16b, v6.16b, v7.16b}, [x1], #0x40
	eor	v0.16b, v0.16b, v4.16b
	eor	v1.16b, v1.16b, v5.16b
	eor	v2.16b, v2.16b, v6.16b
	eor	v3.16b, v3.16b, v7.16b
	orr	v8.16b, v8.16b, v0.16b
	orr	v9.16b, v9.16b, v1.16b
	orr	v10.16b, v10.16b, v2.16b
	orr	v11.16b, v11.16b, v3.16b
	ld4	{v0.16b, v1.16b, v2.16b, v3.16b}, [x0], #0x40
	ld4	{v4.16b, v5.16b, v6.16b, v7.16b}, [x1], #0x40
	eor	v0.16b, v0.16b, v4.16b
	eor	v1.16b, v1.16b, v5.16b
	eor	v2.16b, v2.16b, v6.16b
	eor	v3.16b, v3.16b, v7.16b
	orr	v8.16b, v8.16b, v0.16b
	orr	v9.16b, v9.16b, v1.16b
	orr	v10.16b, v10.16b, v2.16b
	orr	v11.16b, v11.16b, v3.16b
	ld2	{v0.16b, v1.16b}, [x0]
	ld2	{v4.16b, v5.16b}, [x1]
	eor	v0.16b, v0.16b, v4.16b
	eor	v1.16b, v1.16b, v5.16b
	orr	v8.16b, v8.16b, v0.16b
	orr	v9.16b, v9.16b, v1.16b
L_kyber_aarch64_cmp_neon_done:
	orr	v8.16b, v8.16b, v9.16b
	orr	v10.16b, v10.16b, v11.16b
	orr	v8.16b, v8.16b, v10.16b
	ins	v9.b[0], v8.b[1]
	orr	v8.16b, v8.16b, v9.16b
	mov	x0, v8.d[0]
	subs	x0, x0, xzr
	csetm	w0, ne
	ldp	d8, d9, [x29, #16]
	ldp	d10, d11, [x29, #32]
	ldp	x29, x30, [sp], #48
	ret
#ifndef __APPLE__
	.size	kyber_cmp_neon,.-kyber_cmp_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
	.text
	.type	L_kyber_aarch64_rej_uniform_neon_mask, %object
	.section	.rodata
	.size	L_kyber_aarch64_rej_uniform_neon_mask, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
#ifndef __APPLE__
	.align	2
#else
	.p2align	2
#endif /* __APPLE__ */
L_kyber_aarch64_rej_uniform_neon_mask:
	.short	0x0fff,0x0fff,0x0fff,0x0fff,0x0fff,0x0fff,0x0fff,0x0fff
#ifndef __APPLE__
	.text
	.type	L_kyber_aarch64_rej_uniform_neon_bits, %object
	.section	.rodata
	.size	L_kyber_aarch64_rej_uniform_neon_bits, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
#ifndef __APPLE__
	.align	2
#else
	.p2align	2
#endif /* __APPLE__ */
L_kyber_aarch64_rej_uniform_neon_bits:
	.short	0x0001,0x0002,0x0004,0x0008,0x0010,0x0020,0x0040,0x0080
#ifndef __APPLE__
	.text
	.type	L_kyber_aarch64_rej_uniform_neon_indices, %object
	.section	.rodata
	.size	L_kyber_aarch64_rej_uniform_neon_indices, 4096
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
#ifndef __APPLE__
	.align	1
#else
	.p2align	1
#endif /* __APPLE__ */
L_kyber_aarch64_rej_uniform_neon_indices:
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x04,0x05,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x04,0x05,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x04,0x05,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x04,0x05,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x06,0x07,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x06,0x07,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x06,0x07,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x06,0x07,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x04,0x05,0x06,0x07,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x04,0x05,0x06,0x07,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x04,0x05,0x06,0x07,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x08,0x09,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x08,0x09,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x08,0x09,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x08,0x09,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x04,0x05,0x08,0x09,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x04,0x05,0x08,0x09,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x04,0x05,0x08,0x09,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x04,0x05,0x08,0x09
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x06,0x07,0x08,0x09,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x06,0x07,0x08,0x09,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x06,0x07,0x08,0x09,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x06,0x07,0x08,0x09
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x04,0x05,0x06,0x07,0x08,0x09,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x04,0x05,0x06,0x07,0x08,0x09
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07
	.byte	0x08,0x09,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x0a,0x0b,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x0a,0x0b,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x0a,0x0b,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x0a,0x0b,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x04,0x05,0x0a,0x0b,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x04,0x05,0x0a,0x0b,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x04,0x05,0x0a,0x0b,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x04,0x05,0x0a,0x0b
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x06,0x07,0x0a,0x0b,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x06,0x07,0x0a,0x0b,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x06,0x07,0x0a,0x0b,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x06,0x07,0x0a,0x0b
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x04,0x05,0x06,0x07,0x0a,0x0b,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x04,0x05,0x06,0x07,0x0a,0x0b
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x04,0x05,0x06,0x07,0x0a,0x0b
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07
	.byte	0x0a,0x0b,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x08,0x09,0x0a,0x0b,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x08,0x09,0x0a,0x0b,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x08,0x09,0x0a,0x0b,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x08,0x09,0x0a,0x0b
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x04,0x05,0x08,0x09,0x0a,0x0b,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x04,0x05,0x08,0x09,0x0a,0x0b
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x04,0x05,0x08,0x09,0x0a,0x0b
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x04,0x05,0x08,0x09
	.byte	0x0a,0x0b,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x06,0x07,0x08,0x09,0x0a,0x0b,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x06,0x07,0x08,0x09,0x0a,0x0b
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x06,0x07,0x08,0x09,0x0a,0x0b
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x06,0x07,0x08,0x09
	.byte	0x0a,0x0b,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x04,0x05,0x06,0x07,0x08,0x09
	.byte	0x0a,0x0b,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09
	.byte	0x0a,0x0b,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07
	.byte	0x08,0x09,0x0a,0x0b,0xff,0xff,0xff,0xff
	.byte	0x0c,0x0d,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x0c,0x0d,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x0c,0x0d,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x0c,0x0d,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x04,0x05,0x0c,0x0d,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x04,0x05,0x0c,0x0d,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x04,0x05,0x0c,0x0d,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x04,0x05,0x0c,0x0d
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x06,0x07,0x0c,0x0d,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x06,0x07,0x0c,0x0d,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x06,0x07,0x0c,0x0d,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x06,0x07,0x0c,0x0d
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x04,0x05,0x06,0x07,0x0c,0x0d,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x04,0x05,0x06,0x07,0x0c,0x0d
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x04,0x05,0x06,0x07,0x0c,0x0d
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07
	.byte	0x0c,0x0d,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x08,0x09,0x0c,0x0d,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x08,0x09,0x0c,0x0d,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x08,0x09,0x0c,0x0d,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x08,0x09,0x0c,0x0d
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x04,0x05,0x08,0x09,0x0c,0x0d,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x04,0x05,0x08,0x09,0x0c,0x0d
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x04,0x05,0x08,0x09,0x0c,0x0d
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x04,0x05,0x08,0x09
	.byte	0x0c,0x0d,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x06,0x07,0x08,0x09,0x0c,0x0d,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x06,0x07,0x08,0x09,0x0c,0x0d
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x06,0x07,0x08,0x09,0x0c,0x0d
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x06,0x07,0x08,0x09
	.byte	0x0c,0x0d,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x04,0x05,0x06,0x07,0x08,0x09,0x0c,0x0d
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x04,0x05,0x06,0x07,0x08,0x09
	.byte	0x0c,0x0d,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09
	.byte	0x0c,0x0d,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07
	.byte	0x08,0x09,0x0c,0x0d,0xff,0xff,0xff,0xff
	.byte	0x0a,0x0b,0x0c,0x0d,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x0a,0x0b,0x0c,0x0d,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x0a,0x0b,0x0c,0x0d,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x0a,0x0b,0x0c,0x0d
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x04,0x05,0x0a,0x0b,0x0c,0x0d,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x04,0x05,0x0a,0x0b,0x0c,0x0d
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x04,0x05,0x0a,0x0b,0x0c,0x0d
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x04,0x05,0x0a,0x0b
	.byte	0x0c,0x0d,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x06,0x07,0x0a,0x0b,0x0c,0x0d,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x06,0x07,0x0a,0x0b,0x0c,0x0d
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x06,0x07,0x0a,0x0b,0x0c,0x0d
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x06,0x07,0x0a,0x0b
	.byte	0x0c,0x0d,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x04,0x05,0x06,0x07,0x0a,0x0b,0x0c,0x0d
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x04,0x05,0x06,0x07,0x0a,0x0b
	.byte	0x0c,0x0d,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x04,0x05,0x06,0x07,0x0a,0x0b
	.byte	0x0c,0x0d,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07
	.byte	0x0a,0x0b,0x0c,0x0d,0xff,0xff,0xff,0xff
	.byte	0x08,0x09,0x0a,0x0b,0x0c,0x0d,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x08,0x09,0x0a,0x0b,0x0c,0x0d
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x08,0x09,0x0a,0x0b,0x0c,0x0d
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x08,0x09,0x0a,0x0b
	.byte	0x0c,0x0d,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x04,0x05,0x08,0x09,0x0a,0x0b,0x0c,0x0d
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x04,0x05,0x08,0x09,0x0a,0x0b
	.byte	0x0c,0x0d,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x04,0x05,0x08,0x09,0x0a,0x0b
	.byte	0x0c,0x0d,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x04,0x05,0x08,0x09
	.byte	0x0a,0x0b,0x0c,0x0d,0xff,0xff,0xff,0xff
	.byte	0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x06,0x07,0x08,0x09,0x0a,0x0b
	.byte	0x0c,0x0d,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x06,0x07,0x08,0x09,0x0a,0x0b
	.byte	0x0c,0x0d,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x06,0x07,0x08,0x09
	.byte	0x0a,0x0b,0x0c,0x0d,0xff,0xff,0xff,0xff
	.byte	0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b
	.byte	0x0c,0x0d,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x04,0x05,0x06,0x07,0x08,0x09
	.byte	0x0a,0x0b,0x0c,0x0d,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09
	.byte	0x0a,0x0b,0x0c,0x0d,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07
	.byte	0x08,0x09,0x0a,0x0b,0x0c,0x0d,0xff,0xff
	.byte	0x0e,0x0f,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x0e,0x0f,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x0e,0x0f,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x0e,0x0f,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x04,0x05,0x0e,0x0f,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x04,0x05,0x0e,0x0f,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x04,0x05,0x0e,0x0f,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x04,0x05,0x0e,0x0f
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x06,0x07,0x0e,0x0f,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x06,0x07,0x0e,0x0f,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x06,0x07,0x0e,0x0f,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x06,0x07,0x0e,0x0f
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x04,0x05,0x06,0x07,0x0e,0x0f,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x04,0x05,0x06,0x07,0x0e,0x0f
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x04,0x05,0x06,0x07,0x0e,0x0f
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07
	.byte	0x0e,0x0f,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x08,0x09,0x0e,0x0f,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x08,0x09,0x0e,0x0f,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x08,0x09,0x0e,0x0f,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x08,0x09,0x0e,0x0f
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x04,0x05,0x08,0x09,0x0e,0x0f,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x04,0x05,0x08,0x09,0x0e,0x0f
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x04,0x05,0x08,0x09,0x0e,0x0f
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x04,0x05,0x08,0x09
	.byte	0x0e,0x0f,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x06,0x07,0x08,0x09,0x0e,0x0f,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x06,0x07,0x08,0x09,0x0e,0x0f
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x06,0x07,0x08,0x09,0x0e,0x0f
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x06,0x07,0x08,0x09
	.byte	0x0e,0x0f,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x04,0x05,0x06,0x07,0x08,0x09,0x0e,0x0f
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x04,0x05,0x06,0x07,0x08,0x09
	.byte	0x0e,0x0f,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09
	.byte	0x0e,0x0f,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07
	.byte	0x08,0x09,0x0e,0x0f,0xff,0xff,0xff,0xff
	.byte	0x0a,0x0b,0x0e,0x0f,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x0a,0x0b,0x0e,0x0f,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x0a,0x0b,0x0e,0x0f,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x0a,0x0b,0x0e,0x0f
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x04,0x05,0x0a,0x0b,0x0e,0x0f,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x04,0x05,0x0a,0x0b,0x0e,0x0f
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x04,0x05,0x0a,0x0b,0x0e,0x0f
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x04,0x05,0x0a,0x0b
	.byte	0x0e,0x0f,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x06,0x07,0x0a,0x0b,0x0e,0x0f,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x06,0x07,0x0a,0x0b,0x0e,0x0f
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x06,0x07,0x0a,0x0b,0x0e,0x0f
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x06,0x07,0x0a,0x0b
	.byte	0x0e,0x0f,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x04,0x05,0x06,0x07,0x0a,0x0b,0x0e,0x0f
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x04,0x05,0x06,0x07,0x0a,0x0b
	.byte	0x0e,0x0f,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x04,0x05,0x06,0x07,0x0a,0x0b
	.byte	0x0e,0x0f,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07
	.byte	0x0a,0x0b,0x0e,0x0f,0xff,0xff,0xff,0xff
	.byte	0x08,0x09,0x0a,0x0b,0x0e,0x0f,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x08,0x09,0x0a,0x0b,0x0e,0x0f
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x08,0x09,0x0a,0x0b,0x0e,0x0f
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x08,0x09,0x0a,0x0b
	.byte	0x0e,0x0f,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x04,0x05,0x08,0x09,0x0a,0x0b,0x0e,0x0f
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x04,0x05,0x08,0x09,0x0a,0x0b
	.byte	0x0e,0x0f,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x04,0x05,0x08,0x09,0x0a,0x0b
	.byte	0x0e,0x0f,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x04,0x05,0x08,0x09
	.byte	0x0a,0x0b,0x0e,0x0f,0xff,0xff,0xff,0xff
	.byte	0x06,0x07,0x08,0x09,0x0a,0x0b,0x0e,0x0f
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x06,0x07,0x08,0x09,0x0a,0x0b
	.byte	0x0e,0x0f,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x06,0x07,0x08,0x09,0x0a,0x0b
	.byte	0x0e,0x0f,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x06,0x07,0x08,0x09
	.byte	0x0a,0x0b,0x0e,0x0f,0xff,0xff,0xff,0xff
	.byte	0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b
	.byte	0x0e,0x0f,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x04,0x05,0x06,0x07,0x08,0x09
	.byte	0x0a,0x0b,0x0e,0x0f,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09
	.byte	0x0a,0x0b,0x0e,0x0f,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07
	.byte	0x08,0x09,0x0a,0x0b,0x0e,0x0f,0xff,0xff
	.byte	0x0c,0x0d,0x0e,0x0f,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x0c,0x0d,0x0e,0x0f,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x0c,0x0d,0x0e,0x0f,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x0c,0x0d,0x0e,0x0f
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x04,0x05,0x0c,0x0d,0x0e,0x0f,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x04,0x05,0x0c,0x0d,0x0e,0x0f
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x04,0x05,0x0c,0x0d,0x0e,0x0f
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x04,0x05,0x0c,0x0d
	.byte	0x0e,0x0f,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x06,0x07,0x0c,0x0d,0x0e,0x0f,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x06,0x07,0x0c,0x0d,0x0e,0x0f
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x06,0x07,0x0c,0x0d,0x0e,0x0f
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x06,0x07,0x0c,0x0d
	.byte	0x0e,0x0f,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x04,0x05,0x06,0x07,0x0c,0x0d,0x0e,0x0f
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x04,0x05,0x06,0x07,0x0c,0x0d
	.byte	0x0e,0x0f,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x04,0x05,0x06,0x07,0x0c,0x0d
	.byte	0x0e,0x0f,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07
	.byte	0x0c,0x0d,0x0e,0x0f,0xff,0xff,0xff,0xff
	.byte	0x08,0x09,0x0c,0x0d,0x0e,0x0f,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x08,0x09,0x0c,0x0d,0x0e,0x0f
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x08,0x09,0x0c,0x0d,0x0e,0x0f
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x08,0x09,0x0c,0x0d
	.byte	0x0e,0x0f,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x04,0x05,0x08,0x09,0x0c,0x0d,0x0e,0x0f
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x04,0x05,0x08,0x09,0x0c,0x0d
	.byte	0x0e,0x0f,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x04,0x05,0x08,0x09,0x0c,0x0d
	.byte	0x0e,0x0f,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x04,0x05,0x08,0x09
	.byte	0x0c,0x0d,0x0e,0x0f,0xff,0xff,0xff,0xff
	.byte	0x06,0x07,0x08,0x09,0x0c,0x0d,0x0e,0x0f
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x06,0x07,0x08,0x09,0x0c,0x0d
	.byte	0x0e,0x0f,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x06,0x07,0x08,0x09,0x0c,0x0d
	.byte	0x0e,0x0f,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x06,0x07,0x08,0x09
	.byte	0x0c,0x0d,0x0e,0x0f,0xff,0xff,0xff,0xff
	.byte	0x04,0x05,0x06,0x07,0x08,0x09,0x0c,0x0d
	.byte	0x0e,0x0f,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x04,0x05,0x06,0x07,0x08,0x09
	.byte	0x0c,0x0d,0x0e,0x0f,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09
	.byte	0x0c,0x0d,0x0e,0x0f,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07
	.byte	0x08,0x09,0x0c,0x0d,0x0e,0x0f,0xff,0xff
	.byte	0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0xff,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x0a,0x0b,0x0c,0x0d
	.byte	0x0e,0x0f,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x04,0x05,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x04,0x05,0x0a,0x0b,0x0c,0x0d
	.byte	0x0e,0x0f,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x04,0x05,0x0a,0x0b,0x0c,0x0d
	.byte	0x0e,0x0f,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x04,0x05,0x0a,0x0b
	.byte	0x0c,0x0d,0x0e,0x0f,0xff,0xff,0xff,0xff
	.byte	0x06,0x07,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x06,0x07,0x0a,0x0b,0x0c,0x0d
	.byte	0x0e,0x0f,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x06,0x07,0x0a,0x0b,0x0c,0x0d
	.byte	0x0e,0x0f,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x06,0x07,0x0a,0x0b
	.byte	0x0c,0x0d,0x0e,0x0f,0xff,0xff,0xff,0xff
	.byte	0x04,0x05,0x06,0x07,0x0a,0x0b,0x0c,0x0d
	.byte	0x0e,0x0f,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x04,0x05,0x06,0x07,0x0a,0x0b
	.byte	0x0c,0x0d,0x0e,0x0f,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x04,0x05,0x06,0x07,0x0a,0x0b
	.byte	0x0c,0x0d,0x0e,0x0f,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07
	.byte	0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0xff,0xff
	.byte	0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x08,0x09,0x0a,0x0b,0x0c,0x0d
	.byte	0x0e,0x0f,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x08,0x09,0x0a,0x0b,0x0c,0x0d
	.byte	0x0e,0x0f,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x08,0x09,0x0a,0x0b
	.byte	0x0c,0x0d,0x0e,0x0f,0xff,0xff,0xff,0xff
	.byte	0x04,0x05,0x08,0x09,0x0a,0x0b,0x0c,0x0d
	.byte	0x0e,0x0f,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x04,0x05,0x08,0x09,0x0a,0x0b
	.byte	0x0c,0x0d,0x0e,0x0f,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x04,0x05,0x08,0x09,0x0a,0x0b
	.byte	0x0c,0x0d,0x0e,0x0f,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x04,0x05,0x08,0x09
	.byte	0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0xff,0xff
	.byte	0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d
	.byte	0x0e,0x0f,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x06,0x07,0x08,0x09,0x0a,0x0b
	.byte	0x0c,0x0d,0x0e,0x0f,0xff,0xff,0xff,0xff
	.byte	0x02,0x03,0x06,0x07,0x08,0x09,0x0a,0x0b
	.byte	0x0c,0x0d,0x0e,0x0f,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x06,0x07,0x08,0x09
	.byte	0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0xff,0xff
	.byte	0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b
	.byte	0x0c,0x0d,0x0e,0x0f,0xff,0xff,0xff,0xff
	.byte	0x00,0x01,0x04,0x05,0x06,0x07,0x08,0x09
	.byte	0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0xff,0xff
	.byte	0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09
	.byte	0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0xff,0xff
	.byte	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07
	.byte	0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
#ifndef __APPLE__
.text
.globl	kyber_rej_uniform_neon
.type	kyber_rej_uniform_neon,@function
.align	2
kyber_rej_uniform_neon:
#else
.section	__TEXT,__text
.globl	_kyber_rej_uniform_neon
.p2align	2
_kyber_rej_uniform_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-64]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
	stp	d12, d13, [x29, #48]
#ifndef __APPLE__
	adrp x4, L_kyber_aarch64_rej_uniform_neon_mask
	add  x4, x4, :lo12:L_kyber_aarch64_rej_uniform_neon_mask
#else
	adrp x4, L_kyber_aarch64_rej_uniform_neon_mask@PAGE
	add  x4, x4, :lo12:L_kyber_aarch64_rej_uniform_neon_mask@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x5, L_kyber_aarch64_q
	add  x5, x5, :lo12:L_kyber_aarch64_q
#else
	adrp x5, L_kyber_aarch64_q@PAGE
	add  x5, x5, :lo12:L_kyber_aarch64_q@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x6, L_kyber_aarch64_rej_uniform_neon_bits
	add  x6, x6, :lo12:L_kyber_aarch64_rej_uniform_neon_bits
#else
	adrp x6, L_kyber_aarch64_rej_uniform_neon_bits@PAGE
	add  x6, x6, :lo12:L_kyber_aarch64_rej_uniform_neon_bits@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x7, L_kyber_aarch64_rej_uniform_neon_indices
	add  x7, x7, :lo12:L_kyber_aarch64_rej_uniform_neon_indices
#else
	adrp x7, L_kyber_aarch64_rej_uniform_neon_indices@PAGE
	add  x7, x7, :lo12:L_kyber_aarch64_rej_uniform_neon_indices@PAGEOFF
#endif /* __APPLE__ */
	eor	v1.16b, v1.16b, v1.16b
	eor	v12.16b, v12.16b, v12.16b
	eor	v13.16b, v13.16b, v13.16b
	eor	x12, x12, x12
	eor	v10.16b, v10.16b, v10.16b
	eor	v11.16b, v11.16b, v11.16b
	mov	x13, #0xd01
	ldr	q0, [x4]
	ldr	q3, [x5]
	ldr	q2, [x6]
	subs	wzr, w1, #0
	beq	L_kyber_aarch64_rej_uniform_neon_done
	subs	wzr, w1, #16
	blt	L_kyber_aarch64_rej_uniform_neon_loop_4
L_kyber_aarch64_rej_uniform_neon_loop_16:
	ld3	{v4.8b, v5.8b, v6.8b}, [x2], #24
	zip1	v4.16b, v4.16b, v1.16b
	zip1	v5.16b, v5.16b, v1.16b
	zip1	v6.16b, v6.16b, v1.16b
	shl	v7.8h, v5.8h, #8
	ushr	v8.8h, v5.8h, #4
	shl	v6.8h, v6.8h, #4
	orr	v4.16b, v4.16b, v7.16b
	orr	v5.16b, v8.16b, v6.16b
	and	v7.16b, v4.16b, v0.16b
	and	v8.16b, v5.16b, v0.16b
	zip1	v4.8h, v7.8h, v8.8h
	zip2	v5.8h, v7.8h, v8.8h
	cmgt	v7.8h, v3.8h, v4.8h
	cmgt	v8.8h, v3.8h, v5.8h
	ushr	v12.8h, v7.8h, #15
	ushr	v13.8h, v8.8h, #15
	addv	h12, v12.8h
	addv	h13, v13.8h
	mov	x10, v12.d[0]
	mov	x11, v13.d[0]
	and	v10.16b, v7.16b, v2.16b
	and	v11.16b, v8.16b, v2.16b
	addv	h10, v10.8h
	addv	h11, v11.8h
	mov	w8, v10.s[0]
	mov	w9, v11.s[0]
	lsl	w8, w8, #4
	lsl	w9, w9, #4
	ldr	q10, [x7, x8]
	ldr	q11, [x7, x9]
	tbl	v7.16b, {v4.16b}, v10.16b
	tbl	v8.16b, {v5.16b}, v11.16b
	str	q7, [x0]
	add	x0, x0, x10, lsl 1
	add	x12, x12, x10
	str	q8, [x0]
	add	x0, x0, x11, lsl 1
	add	x12, x12, x11
	subs	w3, w3, #24
	beq	L_kyber_aarch64_rej_uniform_neon_done
	sub	w10, w1, w12
	subs	x10, x10, #16
	blt	L_kyber_aarch64_rej_uniform_neon_loop_4
	b	L_kyber_aarch64_rej_uniform_neon_loop_16
L_kyber_aarch64_rej_uniform_neon_loop_4:
	subs	w10, w1, w12
	beq	L_kyber_aarch64_rej_uniform_neon_done
	subs	x10, x10, #4
	blt	L_kyber_aarch64_rej_uniform_neon_loop_lt_4
	ldr	x4, [x2], #6
	lsr	x5, x4, #12
	lsr	x6, x4, #24
	lsr	x7, x4, #36
	and	x4, x4, #0xfff
	and	x5, x5, #0xfff
	and	x6, x6, #0xfff
	and	x7, x7, #0xfff
	strh	w4, [x0]
	subs	xzr, x4, x13
	cinc	x0, x0, lt
	cinc	x0, x0, lt
	cinc	x12, x12, lt
	strh	w5, [x0]
	subs	xzr, x5, x13
	cinc	x0, x0, lt
	cinc	x0, x0, lt
	cinc	x12, x12, lt
	strh	w6, [x0]
	subs	xzr, x6, x13
	cinc	x0, x0, lt
	cinc	x0, x0, lt
	cinc	x12, x12, lt
	strh	w7, [x0]
	subs	xzr, x7, x13
	cinc	x0, x0, lt
	cinc	x0, x0, lt
	cinc	x12, x12, lt
	subs	w3, w3, #6
	beq	L_kyber_aarch64_rej_uniform_neon_done
	b	L_kyber_aarch64_rej_uniform_neon_loop_4
L_kyber_aarch64_rej_uniform_neon_loop_lt_4:
	ldr	x4, [x2], #6
	lsr	x5, x4, #12
	lsr	x6, x4, #24
	lsr	x7, x4, #36
	and	x4, x4, #0xfff
	and	x5, x5, #0xfff
	and	x6, x6, #0xfff
	and	x7, x7, #0xfff
	strh	w4, [x0]
	subs	xzr, x4, x13
	cinc	x0, x0, lt
	cinc	x0, x0, lt
	cinc	x12, x12, lt
	subs	wzr, w1, w12
	beq	L_kyber_aarch64_rej_uniform_neon_done
	strh	w5, [x0]
	subs	xzr, x5, x13
	cinc	x0, x0, lt
	cinc	x0, x0, lt
	cinc	x12, x12, lt
	subs	wzr, w1, w12
	beq	L_kyber_aarch64_rej_uniform_neon_done
	strh	w6, [x0]
	subs	xzr, x6, x13
	cinc	x0, x0, lt
	cinc	x0, x0, lt
	cinc	x12, x12, lt
	subs	wzr, w1, w12
	beq	L_kyber_aarch64_rej_uniform_neon_done
	strh	w7, [x0]
	subs	xzr, x7, x13
	cinc	x0, x0, lt
	cinc	x0, x0, lt
	cinc	x12, x12, lt
	subs	wzr, w1, w12
	beq	L_kyber_aarch64_rej_uniform_neon_done
	subs	w3, w3, #6
	beq	L_kyber_aarch64_rej_uniform_neon_done
	b	L_kyber_aarch64_rej_uniform_neon_loop_lt_4
L_kyber_aarch64_rej_uniform_neon_done:
	mov	x0, x12
	ldp	d8, d9, [x29, #16]
	ldp	d10, d11, [x29, #32]
	ldp	d12, d13, [x29, #48]
	ldp	x29, x30, [sp], #0x40
	ret
#ifndef __APPLE__
	.size	kyber_rej_uniform_neon,.-kyber_rej_uniform_neon
#endif /* __APPLE__ */
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
#ifndef __APPLE__
.text
.globl	kyber_sha3_blocksx3_neon
.type	kyber_sha3_blocksx3_neon,@function
.align	2
kyber_sha3_blocksx3_neon:
#else
.section	__TEXT,__text
.globl	_kyber_sha3_blocksx3_neon
.p2align	2
_kyber_sha3_blocksx3_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-224]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #72]
	stp	x20, x21, [x29, #88]
	stp	x22, x23, [x29, #104]
	stp	x24, x25, [x29, #120]
	stp	x26, x27, [x29, #136]
	str	x28, [x29, #152]
	stp	d8, d9, [x29, #160]
	stp	d10, d11, [x29, #176]
	stp	d12, d13, [x29, #192]
	stp	d14, d15, [x29, #208]
#ifndef __APPLE__
	adrp x27, L_sha3_aarch64_r
	add  x27, x27, :lo12:L_sha3_aarch64_r
#else
	adrp x27, L_sha3_aarch64_r@PAGE
	add  x27, x27, :lo12:L_sha3_aarch64_r@PAGEOFF
#endif /* __APPLE__ */
	str	x0, [x29, #40]
	ld4	{v0.d, v1.d, v2.d, v3.d}[0], [x0], #32
	ld4	{v4.d, v5.d, v6.d, v7.d}[0], [x0], #32
	ld4	{v8.d, v9.d, v10.d, v11.d}[0], [x0], #32
	ld4	{v12.d, v13.d, v14.d, v15.d}[0], [x0], #32
	ld4	{v16.d, v17.d, v18.d, v19.d}[0], [x0], #32
	ld4	{v20.d, v21.d, v22.d, v23.d}[0], [x0], #32
	ld1	{v24.d}[0], [x0]
	add	x0, x0, #8
	ld4	{v0.d, v1.d, v2.d, v3.d}[1], [x0], #32
	ld4	{v4.d, v5.d, v6.d, v7.d}[1], [x0], #32
	ld4	{v8.d, v9.d, v10.d, v11.d}[1], [x0], #32
	ld4	{v12.d, v13.d, v14.d, v15.d}[1], [x0], #32
	ld4	{v16.d, v17.d, v18.d, v19.d}[1], [x0], #32
	ld4	{v20.d, v21.d, v22.d, v23.d}[1], [x0], #32
	ld1	{v24.d}[1], [x0]
	add	x0, x0, #8
	ldp	x1, x2, [x0]
	ldp	x3, x4, [x0, #16]
	ldp	x5, x6, [x0, #32]
	ldp	x7, x8, [x0, #48]
	ldp	x9, x10, [x0, #64]
	ldp	x11, x12, [x0, #80]
	ldp	x13, x14, [x0, #96]
	ldp	x15, x16, [x0, #112]
	ldp	x17, x19, [x0, #128]
	ldp	x20, x21, [x0, #144]
	ldp	x22, x23, [x0, #160]
	ldp	x24, x25, [x0, #176]
	ldr	x26, [x0, #192]
	mov	x28, #24
	# Start of 24 rounds
L_SHA3_transform_blocksx3_neon_begin:
	stp	x27, x28, [x29, #48]
	# Col Mix
	eor3	v31.16b, v0.16b, v5.16b, v10.16b
	eor	x0, x5, x10
	eor3	v27.16b, v1.16b, v6.16b, v11.16b
	eor	x30, x1, x6
	eor3	v28.16b, v2.16b, v7.16b, v12.16b
	eor	x28, x3, x8
	eor3	v29.16b, v3.16b, v8.16b, v13.16b
	eor	x0, x0, x15
	eor3	v30.16b, v4.16b, v9.16b, v14.16b
	eor	x30, x30, x11
	eor3	v31.16b, v31.16b, v15.16b, v20.16b
	eor	x28, x28, x13
	eor3	v27.16b, v27.16b, v16.16b, v21.16b
	eor	x0, x0, x21
	eor3	v28.16b, v28.16b, v17.16b, v22.16b
	eor	x30, x30, x16
	eor3	v29.16b, v29.16b, v18.16b, v23.16b
	eor	x28, x28, x19
	eor3	v30.16b, v30.16b, v19.16b, v24.16b
	eor	x0, x0, x26
	rax1	v25.2d, v30.2d, v27.2d
	eor	x30, x30, x22
	rax1	v26.2d, v31.2d, v28.2d
	eor	x28, x28, x24
	rax1	v27.2d, v27.2d, v29.2d
	str	x0, [x29, #32]
	rax1	v28.2d, v28.2d, v30.2d
	str	x28, [x29, #24]
	rax1	v29.2d, v29.2d, v31.2d
	eor	x27, x2, x7
	eor	v0.16b, v0.16b, v25.16b
	xar	v30.2d, v1.2d, v26.2d, #63
	eor	x28, x4, x9
	xar	v1.2d, v6.2d, v26.2d, #20
	eor	x27, x27, x12
	xar	v6.2d, v9.2d, v29.2d, #44
	eor	x28, x28, x14
	xar	v9.2d, v22.2d, v27.2d, #3
	eor	x27, x27, x17
	xar	v22.2d, v14.2d, v29.2d, #25
	eor	x28, x28, x20
	xar	v14.2d, v20.2d, v25.2d, #46
	eor	x27, x27, x23
	xar	v20.2d, v2.2d, v27.2d, #2
	eor	x28, x28, x25
	xar	v2.2d, v12.2d, v27.2d, #21
	eor	x0, x0, x27, ror 63
	xar	v12.2d, v13.2d, v28.2d, #39
	eor	x27, x27, x28, ror 63
	xar	v13.2d, v19.2d, v29.2d, #56
	eor	x1, x1, x0
	xar	v19.2d, v23.2d, v28.2d, #8
	eor	x6, x6, x0
	xar	v23.2d, v15.2d, v25.2d, #23
	eor	x11, x11, x0
	xar	v15.2d, v4.2d, v29.2d, #37
	eor	x16, x16, x0
	xar	v4.2d, v24.2d, v29.2d, #50
	eor	x22, x22, x0
	xar	v24.2d, v21.2d, v26.2d, #62
	eor	x3, x3, x27
	xar	v21.2d, v8.2d, v28.2d, #9
	eor	x8, x8, x27
	xar	v8.2d, v16.2d, v26.2d, #19
	eor	x13, x13, x27
	xar	v16.2d, v5.2d, v25.2d, #28
	eor	x19, x19, x27
	xar	v5.2d, v3.2d, v28.2d, #36
	eor	x24, x24, x27
	xar	v3.2d, v18.2d, v28.2d, #43
	ldr	x0, [x29, #32]
	xar	v18.2d, v17.2d, v27.2d, #49
	ldr	x27, [x29, #24]
	xar	v17.2d, v11.2d, v26.2d, #54
	eor	x28, x28, x30, ror 63
	xar	v11.2d, v7.2d, v27.2d, #58
	eor	x30, x30, x27, ror 63
	xar	v7.2d, v10.2d, v25.2d, #61
	eor	x27, x27, x0, ror 63
	# Row Mix
	mov	v25.16b, v0.16b
	eor	x5, x5, x28
	mov	v26.16b, v1.16b
	eor	x10, x10, x28
	bcax	v0.16b, v25.16b, v2.16b, v26.16b
	eor	x15, x15, x28
	bcax	v1.16b, v26.16b, v3.16b, v2.16b
	eor	x21, x21, x28
	bcax	v2.16b, v2.16b, v4.16b, v3.16b
	eor	x26, x26, x28
	bcax	v3.16b, v3.16b, v25.16b, v4.16b
	eor	x2, x2, x30
	bcax	v4.16b, v4.16b, v26.16b, v25.16b
	eor	x7, x7, x30
	mov	v25.16b, v5.16b
	eor	x12, x12, x30
	mov	v26.16b, v6.16b
	eor	x17, x17, x30
	bcax	v5.16b, v25.16b, v7.16b, v26.16b
	eor	x23, x23, x30
	bcax	v6.16b, v26.16b, v8.16b, v7.16b
	eor	x4, x4, x27
	bcax	v7.16b, v7.16b, v9.16b, v8.16b
	eor	x9, x9, x27
	bcax	v8.16b, v8.16b, v25.16b, v9.16b
	eor	x14, x14, x27
	bcax	v9.16b, v9.16b, v26.16b, v25.16b
	eor	x20, x20, x27
	mov	v26.16b, v11.16b
	eor	x25, x25, x27
	# Swap Rotate Base
	bcax	v10.16b, v30.16b, v12.16b, v26.16b
	ror	x0, x2, #63
	bcax	v11.16b, v26.16b, v13.16b, v12.16b
	ror	x2, x7, #20
	bcax	v12.16b, v12.16b, v14.16b, v13.16b
	ror	x7, x10, #44
	bcax	v13.16b, v13.16b, v30.16b, v14.16b
	ror	x10, x24, #3
	bcax	v14.16b, v14.16b, v26.16b, v30.16b
	ror	x24, x15, #25
	mov	v25.16b, v15.16b
	ror	x15, x22, #46
	mov	v26.16b, v16.16b
	ror	x22, x3, #2
	bcax	v15.16b, v25.16b, v17.16b, v26.16b
	ror	x3, x13, #21
	bcax	v16.16b, v26.16b, v18.16b, v17.16b
	ror	x13, x14, #39
	bcax	v17.16b, v17.16b, v19.16b, v18.16b
	ror	x14, x21, #56
	bcax	v18.16b, v18.16b, v25.16b, v19.16b
	ror	x21, x25, #8
	bcax	v19.16b, v19.16b, v26.16b, v25.16b
	ror	x25, x16, #23
	mov	v25.16b, v20.16b
	ror	x16, x5, #37
	mov	v26.16b, v21.16b
	ror	x5, x26, #50
	bcax	v20.16b, v25.16b, v22.16b, v26.16b
	ror	x26, x23, #62
	bcax	v21.16b, v26.16b, v23.16b, v22.16b
	ror	x23, x9, #9
	bcax	v22.16b, v22.16b, v24.16b, v23.16b
	ror	x9, x17, #19
	bcax	v23.16b, v23.16b, v25.16b, v24.16b
	ror	x17, x6, #28
	bcax	v24.16b, v24.16b, v26.16b, v25.16b
	ror	x6, x4, #36
	ror	x4, x20, #43
	ror	x20, x19, #49
	ror	x19, x12, #54
	ror	x12, x8, #58
	ror	x8, x11, #61
	# Row Mix Base
	bic	x11, x3, x2
	bic	x27, x4, x3
	bic	x28, x1, x5
	bic	x30, x2, x1
	eor	x1, x1, x11
	eor	x2, x2, x27
	bic	x11, x5, x4
	eor	x4, x4, x28
	eor	x3, x3, x11
	eor	x5, x5, x30
	bic	x11, x8, x7
	bic	x27, x9, x8
	bic	x28, x6, x10
	bic	x30, x7, x6
	eor	x6, x6, x11
	eor	x7, x7, x27
	bic	x11, x10, x9
	eor	x9, x9, x28
	eor	x8, x8, x11
	eor	x10, x10, x30
	bic	x11, x13, x12
	bic	x27, x14, x13
	bic	x28, x0, x15
	bic	x30, x12, x0
	eor	x11, x0, x11
	eor	x12, x12, x27
	bic	x0, x15, x14
	eor	x14, x14, x28
	eor	x13, x13, x0
	eor	x15, x15, x30
	bic	x0, x19, x17
	bic	x27, x20, x19
	bic	x28, x16, x21
	bic	x30, x17, x16
	eor	x16, x16, x0
	eor	x17, x17, x27
	bic	x0, x21, x20
	eor	x20, x20, x28
	eor	x19, x19, x0
	eor	x21, x21, x30
	bic	x0, x24, x23
	bic	x27, x25, x24
	bic	x28, x22, x26
	bic	x30, x23, x22
	eor	x22, x22, x0
	eor	x23, x23, x27
	bic	x0, x26, x25
	eor	x25, x25, x28
	eor	x24, x24, x0
	eor	x26, x26, x30
	# Done transforming
	ldp	x27, x28, [x29, #48]
	ldr	x0, [x27], #8
	subs	x28, x28, #1
	mov	v30.d[0], x0
	mov	v30.d[1], x0
	eor	x1, x1, x0
	eor	v0.16b, v0.16b, v30.16b
	bne	L_SHA3_transform_blocksx3_neon_begin
	ldr	x0, [x29, #40]
	st4	{v0.d, v1.d, v2.d, v3.d}[0], [x0], #32
	st4	{v4.d, v5.d, v6.d, v7.d}[0], [x0], #32
	st4	{v8.d, v9.d, v10.d, v11.d}[0], [x0], #32
	st4	{v12.d, v13.d, v14.d, v15.d}[0], [x0], #32
	st4	{v16.d, v17.d, v18.d, v19.d}[0], [x0], #32
	st4	{v20.d, v21.d, v22.d, v23.d}[0], [x0], #32
	st1	{v24.d}[0], [x0]
	add	x0, x0, #8
	st4	{v0.d, v1.d, v2.d, v3.d}[1], [x0], #32
	st4	{v4.d, v5.d, v6.d, v7.d}[1], [x0], #32
	st4	{v8.d, v9.d, v10.d, v11.d}[1], [x0], #32
	st4	{v12.d, v13.d, v14.d, v15.d}[1], [x0], #32
	st4	{v16.d, v17.d, v18.d, v19.d}[1], [x0], #32
	st4	{v20.d, v21.d, v22.d, v23.d}[1], [x0], #32
	st1	{v24.d}[1], [x0]
	add	x0, x0, #8
	stp	x1, x2, [x0]
	stp	x3, x4, [x0, #16]
	stp	x5, x6, [x0, #32]
	stp	x7, x8, [x0, #48]
	stp	x9, x10, [x0, #64]
	stp	x11, x12, [x0, #80]
	stp	x13, x14, [x0, #96]
	stp	x15, x16, [x0, #112]
	stp	x17, x19, [x0, #128]
	stp	x20, x21, [x0, #144]
	stp	x22, x23, [x0, #160]
	stp	x24, x25, [x0, #176]
	str	x26, [x0, #192]
	ldp	x17, x19, [x29, #72]
	ldp	x20, x21, [x29, #88]
	ldp	x22, x23, [x29, #104]
	ldp	x24, x25, [x29, #120]
	ldp	x26, x27, [x29, #136]
	ldr	x28, [x29, #152]
	ldp	d8, d9, [x29, #160]
	ldp	d10, d11, [x29, #176]
	ldp	d12, d13, [x29, #192]
	ldp	d14, d15, [x29, #208]
	ldp	x29, x30, [sp], #0xe0
	ret
#ifndef __APPLE__
	.size	kyber_sha3_blocksx3_neon,.-kyber_sha3_blocksx3_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	kyber_shake128_blocksx3_seed_neon
.type	kyber_shake128_blocksx3_seed_neon,@function
.align	2
kyber_shake128_blocksx3_seed_neon:
#else
.section	__TEXT,__text
.globl	_kyber_shake128_blocksx3_seed_neon
.p2align	2
_kyber_shake128_blocksx3_seed_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-224]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #72]
	stp	x20, x21, [x29, #88]
	stp	x22, x23, [x29, #104]
	stp	x24, x25, [x29, #120]
	stp	x26, x27, [x29, #136]
	str	x28, [x29, #152]
	stp	d8, d9, [x29, #160]
	stp	d10, d11, [x29, #176]
	stp	d12, d13, [x29, #192]
	stp	d14, d15, [x29, #208]
#ifndef __APPLE__
	adrp x28, L_sha3_aarch64_r
	add  x28, x28, :lo12:L_sha3_aarch64_r
#else
	adrp x28, L_sha3_aarch64_r@PAGE
	add  x28, x28, :lo12:L_sha3_aarch64_r@PAGEOFF
#endif /* __APPLE__ */
	str	x0, [x29, #40]
	add	x0, x0, #32
	ld1	{v4.d}[0], [x0]
	ldp	x2, x3, [x1], #16
	add	x0, x0, #0xc8
	ld1	{v4.d}[1], [x0]
	ldp	x4, x5, [x1], #16
	ldr	x6, [x0, #200]
	eor	v5.16b, v5.16b, v5.16b
	eor	x7, x7, x7
	eor	v6.16b, v6.16b, v6.16b
	eor	x8, x8, x8
	eor	v7.16b, v7.16b, v7.16b
	eor	x9, x9, x9
	eor	v8.16b, v8.16b, v8.16b
	eor	x10, x10, x10
	eor	v9.16b, v9.16b, v9.16b
	eor	x11, x11, x11
	eor	v10.16b, v10.16b, v10.16b
	eor	x12, x12, x12
	eor	v11.16b, v11.16b, v11.16b
	eor	x13, x13, x13
	eor	v12.16b, v12.16b, v12.16b
	eor	x14, x14, x14
	eor	v13.16b, v13.16b, v13.16b
	eor	x15, x15, x15
	eor	v14.16b, v14.16b, v14.16b
	eor	x16, x16, x16
	eor	v15.16b, v15.16b, v15.16b
	eor	x17, x17, x17
	eor	v16.16b, v16.16b, v16.16b
	eor	x19, x19, x19
	eor	v17.16b, v17.16b, v17.16b
	eor	x20, x20, x20
	eor	v18.16b, v18.16b, v18.16b
	eor	x21, x21, x21
	eor	v19.16b, v19.16b, v19.16b
	eor	x22, x22, x22
	movz	x23, #0x8000, lsl 48
	eor	v21.16b, v21.16b, v21.16b
	eor	x24, x24, x24
	eor	v22.16b, v22.16b, v22.16b
	eor	x25, x25, x25
	eor	v23.16b, v23.16b, v23.16b
	eor	x26, x26, x26
	eor	v24.16b, v24.16b, v24.16b
	eor	x27, x27, x27
	dup	v0.2d, x2
	dup	v1.2d, x3
	dup	v2.2d, x4
	dup	v3.2d, x5
	dup	v20.2d, x23
	mov	x1, #24
	# Start of 24 rounds
L_SHA3_shake128_blocksx3_seed_neon_begin:
	stp	x28, x1, [x29, #48]
	# Col Mix
	eor3	v31.16b, v0.16b, v5.16b, v10.16b
	eor	x0, x6, x11
	eor3	v27.16b, v1.16b, v6.16b, v11.16b
	eor	x30, x2, x7
	eor3	v28.16b, v2.16b, v7.16b, v12.16b
	eor	x28, x4, x9
	eor3	v29.16b, v3.16b, v8.16b, v13.16b
	eor	x0, x0, x16
	eor3	v30.16b, v4.16b, v9.16b, v14.16b
	eor	x30, x30, x12
	eor3	v31.16b, v31.16b, v15.16b, v20.16b
	eor	x28, x28, x14
	eor3	v27.16b, v27.16b, v16.16b, v21.16b
	eor	x0, x0, x22
	eor3	v28.16b, v28.16b, v17.16b, v22.16b
	eor	x30, x30, x17
	eor3	v29.16b, v29.16b, v18.16b, v23.16b
	eor	x28, x28, x20
	eor3	v30.16b, v30.16b, v19.16b, v24.16b
	eor	x0, x0, x27
	rax1	v25.2d, v30.2d, v27.2d
	eor	x30, x30, x23
	rax1	v26.2d, v31.2d, v28.2d
	eor	x28, x28, x25
	rax1	v27.2d, v27.2d, v29.2d
	str	x0, [x29, #32]
	rax1	v28.2d, v28.2d, v30.2d
	str	x28, [x29, #24]
	rax1	v29.2d, v29.2d, v31.2d
	eor	x1, x3, x8
	eor	v0.16b, v0.16b, v25.16b
	xar	v30.2d, v1.2d, v26.2d, #63
	eor	x28, x5, x10
	xar	v1.2d, v6.2d, v26.2d, #20
	eor	x1, x1, x13
	xar	v6.2d, v9.2d, v29.2d, #44
	eor	x28, x28, x15
	xar	v9.2d, v22.2d, v27.2d, #3
	eor	x1, x1, x19
	xar	v22.2d, v14.2d, v29.2d, #25
	eor	x28, x28, x21
	xar	v14.2d, v20.2d, v25.2d, #46
	eor	x1, x1, x24
	xar	v20.2d, v2.2d, v27.2d, #2
	eor	x28, x28, x26
	xar	v2.2d, v12.2d, v27.2d, #21
	eor	x0, x0, x1, ror 63
	xar	v12.2d, v13.2d, v28.2d, #39
	eor	x1, x1, x28, ror 63
	xar	v13.2d, v19.2d, v29.2d, #56
	eor	x2, x2, x0
	xar	v19.2d, v23.2d, v28.2d, #8
	eor	x7, x7, x0
	xar	v23.2d, v15.2d, v25.2d, #23
	eor	x12, x12, x0
	xar	v15.2d, v4.2d, v29.2d, #37
	eor	x17, x17, x0
	xar	v4.2d, v24.2d, v29.2d, #50
	eor	x23, x23, x0
	xar	v24.2d, v21.2d, v26.2d, #62
	eor	x4, x4, x1
	xar	v21.2d, v8.2d, v28.2d, #9
	eor	x9, x9, x1
	xar	v8.2d, v16.2d, v26.2d, #19
	eor	x14, x14, x1
	xar	v16.2d, v5.2d, v25.2d, #28
	eor	x20, x20, x1
	xar	v5.2d, v3.2d, v28.2d, #36
	eor	x25, x25, x1
	xar	v3.2d, v18.2d, v28.2d, #43
	ldr	x0, [x29, #32]
	xar	v18.2d, v17.2d, v27.2d, #49
	ldr	x1, [x29, #24]
	xar	v17.2d, v11.2d, v26.2d, #54
	eor	x28, x28, x30, ror 63
	xar	v11.2d, v7.2d, v27.2d, #58
	eor	x30, x30, x1, ror 63
	xar	v7.2d, v10.2d, v25.2d, #61
	eor	x1, x1, x0, ror 63
	# Row Mix
	mov	v25.16b, v0.16b
	eor	x6, x6, x28
	mov	v26.16b, v1.16b
	eor	x11, x11, x28
	bcax	v0.16b, v25.16b, v2.16b, v26.16b
	eor	x16, x16, x28
	bcax	v1.16b, v26.16b, v3.16b, v2.16b
	eor	x22, x22, x28
	bcax	v2.16b, v2.16b, v4.16b, v3.16b
	eor	x27, x27, x28
	bcax	v3.16b, v3.16b, v25.16b, v4.16b
	eor	x3, x3, x30
	bcax	v4.16b, v4.16b, v26.16b, v25.16b
	eor	x8, x8, x30
	mov	v25.16b, v5.16b
	eor	x13, x13, x30
	mov	v26.16b, v6.16b
	eor	x19, x19, x30
	bcax	v5.16b, v25.16b, v7.16b, v26.16b
	eor	x24, x24, x30
	bcax	v6.16b, v26.16b, v8.16b, v7.16b
	eor	x5, x5, x1
	bcax	v7.16b, v7.16b, v9.16b, v8.16b
	eor	x10, x10, x1
	bcax	v8.16b, v8.16b, v25.16b, v9.16b
	eor	x15, x15, x1
	bcax	v9.16b, v9.16b, v26.16b, v25.16b
	eor	x21, x21, x1
	mov	v26.16b, v11.16b
	eor	x26, x26, x1
	# Swap Rotate Base
	bcax	v10.16b, v30.16b, v12.16b, v26.16b
	ror	x0, x3, #63
	bcax	v11.16b, v26.16b, v13.16b, v12.16b
	ror	x3, x8, #20
	bcax	v12.16b, v12.16b, v14.16b, v13.16b
	ror	x8, x11, #44
	bcax	v13.16b, v13.16b, v30.16b, v14.16b
	ror	x11, x25, #3
	bcax	v14.16b, v14.16b, v26.16b, v30.16b
	ror	x25, x16, #25
	mov	v25.16b, v15.16b
	ror	x16, x23, #46
	mov	v26.16b, v16.16b
	ror	x23, x4, #2
	bcax	v15.16b, v25.16b, v17.16b, v26.16b
	ror	x4, x14, #21
	bcax	v16.16b, v26.16b, v18.16b, v17.16b
	ror	x14, x15, #39
	bcax	v17.16b, v17.16b, v19.16b, v18.16b
	ror	x15, x22, #56
	bcax	v18.16b, v18.16b, v25.16b, v19.16b
	ror	x22, x26, #8
	bcax	v19.16b, v19.16b, v26.16b, v25.16b
	ror	x26, x17, #23
	mov	v25.16b, v20.16b
	ror	x17, x6, #37
	mov	v26.16b, v21.16b
	ror	x6, x27, #50
	bcax	v20.16b, v25.16b, v22.16b, v26.16b
	ror	x27, x24, #62
	bcax	v21.16b, v26.16b, v23.16b, v22.16b
	ror	x24, x10, #9
	bcax	v22.16b, v22.16b, v24.16b, v23.16b
	ror	x10, x19, #19
	bcax	v23.16b, v23.16b, v25.16b, v24.16b
	ror	x19, x7, #28
	bcax	v24.16b, v24.16b, v26.16b, v25.16b
	ror	x7, x5, #36
	ror	x5, x21, #43
	ror	x21, x20, #49
	ror	x20, x13, #54
	ror	x13, x9, #58
	ror	x9, x12, #61
	# Row Mix Base
	bic	x12, x4, x3
	bic	x1, x5, x4
	bic	x28, x2, x6
	bic	x30, x3, x2
	eor	x2, x2, x12
	eor	x3, x3, x1
	bic	x12, x6, x5
	eor	x5, x5, x28
	eor	x4, x4, x12
	eor	x6, x6, x30
	bic	x12, x9, x8
	bic	x1, x10, x9
	bic	x28, x7, x11
	bic	x30, x8, x7
	eor	x7, x7, x12
	eor	x8, x8, x1
	bic	x12, x11, x10
	eor	x10, x10, x28
	eor	x9, x9, x12
	eor	x11, x11, x30
	bic	x12, x14, x13
	bic	x1, x15, x14
	bic	x28, x0, x16
	bic	x30, x13, x0
	eor	x12, x0, x12
	eor	x13, x13, x1
	bic	x0, x16, x15
	eor	x15, x15, x28
	eor	x14, x14, x0
	eor	x16, x16, x30
	bic	x0, x20, x19
	bic	x1, x21, x20
	bic	x28, x17, x22
	bic	x30, x19, x17
	eor	x17, x17, x0
	eor	x19, x19, x1
	bic	x0, x22, x21
	eor	x21, x21, x28
	eor	x20, x20, x0
	eor	x22, x22, x30
	bic	x0, x25, x24
	bic	x1, x26, x25
	bic	x28, x23, x27
	bic	x30, x24, x23
	eor	x23, x23, x0
	eor	x24, x24, x1
	bic	x0, x27, x26
	eor	x26, x26, x28
	eor	x25, x25, x0
	eor	x27, x27, x30
	# Done transforming
	ldp	x28, x1, [x29, #48]
	ldr	x0, [x28], #8
	subs	x1, x1, #1
	mov	v30.d[0], x0
	mov	v30.d[1], x0
	eor	x2, x2, x0
	eor	v0.16b, v0.16b, v30.16b
	bne	L_SHA3_shake128_blocksx3_seed_neon_begin
	ldr	x0, [x29, #40]
	st4	{v0.d, v1.d, v2.d, v3.d}[0], [x0], #32
	st4	{v4.d, v5.d, v6.d, v7.d}[0], [x0], #32
	st4	{v8.d, v9.d, v10.d, v11.d}[0], [x0], #32
	st4	{v12.d, v13.d, v14.d, v15.d}[0], [x0], #32
	st4	{v16.d, v17.d, v18.d, v19.d}[0], [x0], #32
	st4	{v20.d, v21.d, v22.d, v23.d}[0], [x0], #32
	st1	{v24.d}[0], [x0]
	add	x0, x0, #8
	st4	{v0.d, v1.d, v2.d, v3.d}[1], [x0], #32
	st4	{v4.d, v5.d, v6.d, v7.d}[1], [x0], #32
	st4	{v8.d, v9.d, v10.d, v11.d}[1], [x0], #32
	st4	{v12.d, v13.d, v14.d, v15.d}[1], [x0], #32
	st4	{v16.d, v17.d, v18.d, v19.d}[1], [x0], #32
	st4	{v20.d, v21.d, v22.d, v23.d}[1], [x0], #32
	st1	{v24.d}[1], [x0]
	add	x0, x0, #8
	stp	x2, x3, [x0]
	stp	x4, x5, [x0, #16]
	stp	x6, x7, [x0, #32]
	stp	x8, x9, [x0, #48]
	stp	x10, x11, [x0, #64]
	stp	x12, x13, [x0, #80]
	stp	x14, x15, [x0, #96]
	stp	x16, x17, [x0, #112]
	stp	x19, x20, [x0, #128]
	stp	x21, x22, [x0, #144]
	stp	x23, x24, [x0, #160]
	stp	x25, x26, [x0, #176]
	str	x27, [x0, #192]
	ldp	x17, x19, [x29, #72]
	ldp	x20, x21, [x29, #88]
	ldp	x22, x23, [x29, #104]
	ldp	x24, x25, [x29, #120]
	ldp	x26, x27, [x29, #136]
	ldr	x28, [x29, #152]
	ldp	d8, d9, [x29, #160]
	ldp	d10, d11, [x29, #176]
	ldp	d12, d13, [x29, #192]
	ldp	d14, d15, [x29, #208]
	ldp	x29, x30, [sp], #0xe0
	ret
#ifndef __APPLE__
	.size	kyber_shake128_blocksx3_seed_neon,.-kyber_shake128_blocksx3_seed_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	kyber_shake256_blocksx3_seed_neon
.type	kyber_shake256_blocksx3_seed_neon,@function
.align	2
kyber_shake256_blocksx3_seed_neon:
#else
.section	__TEXT,__text
.globl	_kyber_shake256_blocksx3_seed_neon
.p2align	2
_kyber_shake256_blocksx3_seed_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-224]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #72]
	stp	x20, x21, [x29, #88]
	stp	x22, x23, [x29, #104]
	stp	x24, x25, [x29, #120]
	stp	x26, x27, [x29, #136]
	str	x28, [x29, #152]
	stp	d8, d9, [x29, #160]
	stp	d10, d11, [x29, #176]
	stp	d12, d13, [x29, #192]
	stp	d14, d15, [x29, #208]
#ifndef __APPLE__
	adrp x28, L_sha3_aarch64_r
	add  x28, x28, :lo12:L_sha3_aarch64_r
#else
	adrp x28, L_sha3_aarch64_r@PAGE
	add  x28, x28, :lo12:L_sha3_aarch64_r@PAGEOFF
#endif /* __APPLE__ */
	str	x0, [x29, #40]
	add	x0, x0, #32
	ld1	{v4.d}[0], [x0]
	ldp	x2, x3, [x1], #16
	add	x0, x0, #0xc8
	ld1	{v4.d}[1], [x0]
	ldp	x4, x5, [x1], #16
	ldr	x6, [x0, #200]
	eor	v5.16b, v5.16b, v5.16b
	eor	x7, x7, x7
	eor	v6.16b, v6.16b, v6.16b
	eor	x8, x8, x8
	eor	v7.16b, v7.16b, v7.16b
	eor	x9, x9, x9
	eor	v8.16b, v8.16b, v8.16b
	eor	x10, x10, x10
	eor	v9.16b, v9.16b, v9.16b
	eor	x11, x11, x11
	eor	v10.16b, v10.16b, v10.16b
	eor	x12, x12, x12
	eor	v11.16b, v11.16b, v11.16b
	eor	x13, x13, x13
	eor	v12.16b, v12.16b, v12.16b
	eor	x14, x14, x14
	eor	v13.16b, v13.16b, v13.16b
	eor	x15, x15, x15
	eor	v14.16b, v14.16b, v14.16b
	eor	x16, x16, x16
	eor	v15.16b, v15.16b, v15.16b
	eor	x17, x17, x17
	movz	x19, #0x8000, lsl 48
	eor	v17.16b, v17.16b, v17.16b
	eor	x20, x20, x20
	eor	v18.16b, v18.16b, v18.16b
	eor	x21, x21, x21
	eor	v19.16b, v19.16b, v19.16b
	eor	x22, x22, x22
	eor	v20.16b, v20.16b, v20.16b
	eor	x23, x23, x23
	eor	v21.16b, v21.16b, v21.16b
	eor	x24, x24, x24
	eor	v22.16b, v22.16b, v22.16b
	eor	x25, x25, x25
	eor	v23.16b, v23.16b, v23.16b
	eor	x26, x26, x26
	eor	v24.16b, v24.16b, v24.16b
	eor	x27, x27, x27
	dup	v0.2d, x2
	dup	v1.2d, x3
	dup	v2.2d, x4
	dup	v3.2d, x5
	dup	v16.2d, x19
	mov	x1, #24
	# Start of 24 rounds
L_SHA3_shake256_blocksx3_seed_neon_begin:
	stp	x28, x1, [x29, #48]
	# Col Mix
	eor3	v31.16b, v0.16b, v5.16b, v10.16b
	eor	x0, x6, x11
	eor3	v27.16b, v1.16b, v6.16b, v11.16b
	eor	x30, x2, x7
	eor3	v28.16b, v2.16b, v7.16b, v12.16b
	eor	x28, x4, x9
	eor3	v29.16b, v3.16b, v8.16b, v13.16b
	eor	x0, x0, x16
	eor3	v30.16b, v4.16b, v9.16b, v14.16b
	eor	x30, x30, x12
	eor3	v31.16b, v31.16b, v15.16b, v20.16b
	eor	x28, x28, x14
	eor3	v27.16b, v27.16b, v16.16b, v21.16b
	eor	x0, x0, x22
	eor3	v28.16b, v28.16b, v17.16b, v22.16b
	eor	x30, x30, x17
	eor3	v29.16b, v29.16b, v18.16b, v23.16b
	eor	x28, x28, x20
	eor3	v30.16b, v30.16b, v19.16b, v24.16b
	eor	x0, x0, x27
	rax1	v25.2d, v30.2d, v27.2d
	eor	x30, x30, x23
	rax1	v26.2d, v31.2d, v28.2d
	eor	x28, x28, x25
	rax1	v27.2d, v27.2d, v29.2d
	str	x0, [x29, #32]
	rax1	v28.2d, v28.2d, v30.2d
	str	x28, [x29, #24]
	rax1	v29.2d, v29.2d, v31.2d
	eor	x1, x3, x8
	eor	v0.16b, v0.16b, v25.16b
	xar	v30.2d, v1.2d, v26.2d, #63
	eor	x28, x5, x10
	xar	v1.2d, v6.2d, v26.2d, #20
	eor	x1, x1, x13
	xar	v6.2d, v9.2d, v29.2d, #44
	eor	x28, x28, x15
	xar	v9.2d, v22.2d, v27.2d, #3
	eor	x1, x1, x19
	xar	v22.2d, v14.2d, v29.2d, #25
	eor	x28, x28, x21
	xar	v14.2d, v20.2d, v25.2d, #46
	eor	x1, x1, x24
	xar	v20.2d, v2.2d, v27.2d, #2
	eor	x28, x28, x26
	xar	v2.2d, v12.2d, v27.2d, #21
	eor	x0, x0, x1, ror 63
	xar	v12.2d, v13.2d, v28.2d, #39
	eor	x1, x1, x28, ror 63
	xar	v13.2d, v19.2d, v29.2d, #56
	eor	x2, x2, x0
	xar	v19.2d, v23.2d, v28.2d, #8
	eor	x7, x7, x0
	xar	v23.2d, v15.2d, v25.2d, #23
	eor	x12, x12, x0
	xar	v15.2d, v4.2d, v29.2d, #37
	eor	x17, x17, x0
	xar	v4.2d, v24.2d, v29.2d, #50
	eor	x23, x23, x0
	xar	v24.2d, v21.2d, v26.2d, #62
	eor	x4, x4, x1
	xar	v21.2d, v8.2d, v28.2d, #9
	eor	x9, x9, x1
	xar	v8.2d, v16.2d, v26.2d, #19
	eor	x14, x14, x1
	xar	v16.2d, v5.2d, v25.2d, #28
	eor	x20, x20, x1
	xar	v5.2d, v3.2d, v28.2d, #36
	eor	x25, x25, x1
	xar	v3.2d, v18.2d, v28.2d, #43
	ldr	x0, [x29, #32]
	xar	v18.2d, v17.2d, v27.2d, #49
	ldr	x1, [x29, #24]
	xar	v17.2d, v11.2d, v26.2d, #54
	eor	x28, x28, x30, ror 63
	xar	v11.2d, v7.2d, v27.2d, #58
	eor	x30, x30, x1, ror 63
	xar	v7.2d, v10.2d, v25.2d, #61
	eor	x1, x1, x0, ror 63
	# Row Mix
	mov	v25.16b, v0.16b
	eor	x6, x6, x28
	mov	v26.16b, v1.16b
	eor	x11, x11, x28
	bcax	v0.16b, v25.16b, v2.16b, v26.16b
	eor	x16, x16, x28
	bcax	v1.16b, v26.16b, v3.16b, v2.16b
	eor	x22, x22, x28
	bcax	v2.16b, v2.16b, v4.16b, v3.16b
	eor	x27, x27, x28
	bcax	v3.16b, v3.16b, v25.16b, v4.16b
	eor	x3, x3, x30
	bcax	v4.16b, v4.16b, v26.16b, v25.16b
	eor	x8, x8, x30
	mov	v25.16b, v5.16b
	eor	x13, x13, x30
	mov	v26.16b, v6.16b
	eor	x19, x19, x30
	bcax	v5.16b, v25.16b, v7.16b, v26.16b
	eor	x24, x24, x30
	bcax	v6.16b, v26.16b, v8.16b, v7.16b
	eor	x5, x5, x1
	bcax	v7.16b, v7.16b, v9.16b, v8.16b
	eor	x10, x10, x1
	bcax	v8.16b, v8.16b, v25.16b, v9.16b
	eor	x15, x15, x1
	bcax	v9.16b, v9.16b, v26.16b, v25.16b
	eor	x21, x21, x1
	mov	v26.16b, v11.16b
	eor	x26, x26, x1
	# Swap Rotate Base
	bcax	v10.16b, v30.16b, v12.16b, v26.16b
	ror	x0, x3, #63
	bcax	v11.16b, v26.16b, v13.16b, v12.16b
	ror	x3, x8, #20
	bcax	v12.16b, v12.16b, v14.16b, v13.16b
	ror	x8, x11, #44
	bcax	v13.16b, v13.16b, v30.16b, v14.16b
	ror	x11, x25, #3
	bcax	v14.16b, v14.16b, v26.16b, v30.16b
	ror	x25, x16, #25
	mov	v25.16b, v15.16b
	ror	x16, x23, #46
	mov	v26.16b, v16.16b
	ror	x23, x4, #2
	bcax	v15.16b, v25.16b, v17.16b, v26.16b
	ror	x4, x14, #21
	bcax	v16.16b, v26.16b, v18.16b, v17.16b
	ror	x14, x15, #39
	bcax	v17.16b, v17.16b, v19.16b, v18.16b
	ror	x15, x22, #56
	bcax	v18.16b, v18.16b, v25.16b, v19.16b
	ror	x22, x26, #8
	bcax	v19.16b, v19.16b, v26.16b, v25.16b
	ror	x26, x17, #23
	mov	v25.16b, v20.16b
	ror	x17, x6, #37
	mov	v26.16b, v21.16b
	ror	x6, x27, #50
	bcax	v20.16b, v25.16b, v22.16b, v26.16b
	ror	x27, x24, #62
	bcax	v21.16b, v26.16b, v23.16b, v22.16b
	ror	x24, x10, #9
	bcax	v22.16b, v22.16b, v24.16b, v23.16b
	ror	x10, x19, #19
	bcax	v23.16b, v23.16b, v25.16b, v24.16b
	ror	x19, x7, #28
	bcax	v24.16b, v24.16b, v26.16b, v25.16b
	ror	x7, x5, #36
	ror	x5, x21, #43
	ror	x21, x20, #49
	ror	x20, x13, #54
	ror	x13, x9, #58
	ror	x9, x12, #61
	# Row Mix Base
	bic	x12, x4, x3
	bic	x1, x5, x4
	bic	x28, x2, x6
	bic	x30, x3, x2
	eor	x2, x2, x12
	eor	x3, x3, x1
	bic	x12, x6, x5
	eor	x5, x5, x28
	eor	x4, x4, x12
	eor	x6, x6, x30
	bic	x12, x9, x8
	bic	x1, x10, x9
	bic	x28, x7, x11
	bic	x30, x8, x7
	eor	x7, x7, x12
	eor	x8, x8, x1
	bic	x12, x11, x10
	eor	x10, x10, x28
	eor	x9, x9, x12
	eor	x11, x11, x30
	bic	x12, x14, x13
	bic	x1, x15, x14
	bic	x28, x0, x16
	bic	x30, x13, x0
	eor	x12, x0, x12
	eor	x13, x13, x1
	bic	x0, x16, x15
	eor	x15, x15, x28
	eor	x14, x14, x0
	eor	x16, x16, x30
	bic	x0, x20, x19
	bic	x1, x21, x20
	bic	x28, x17, x22
	bic	x30, x19, x17
	eor	x17, x17, x0
	eor	x19, x19, x1
	bic	x0, x22, x21
	eor	x21, x21, x28
	eor	x20, x20, x0
	eor	x22, x22, x30
	bic	x0, x25, x24
	bic	x1, x26, x25
	bic	x28, x23, x27
	bic	x30, x24, x23
	eor	x23, x23, x0
	eor	x24, x24, x1
	bic	x0, x27, x26
	eor	x26, x26, x28
	eor	x25, x25, x0
	eor	x27, x27, x30
	# Done transforming
	ldp	x28, x1, [x29, #48]
	ldr	x0, [x28], #8
	subs	x1, x1, #1
	mov	v30.d[0], x0
	mov	v30.d[1], x0
	eor	x2, x2, x0
	eor	v0.16b, v0.16b, v30.16b
	bne	L_SHA3_shake256_blocksx3_seed_neon_begin
	ldr	x0, [x29, #40]
	st4	{v0.d, v1.d, v2.d, v3.d}[0], [x0], #32
	st4	{v4.d, v5.d, v6.d, v7.d}[0], [x0], #32
	st4	{v8.d, v9.d, v10.d, v11.d}[0], [x0], #32
	st4	{v12.d, v13.d, v14.d, v15.d}[0], [x0], #32
	st4	{v16.d, v17.d, v18.d, v19.d}[0], [x0], #32
	st4	{v20.d, v21.d, v22.d, v23.d}[0], [x0], #32
	st1	{v24.d}[0], [x0]
	add	x0, x0, #8
	st4	{v0.d, v1.d, v2.d, v3.d}[1], [x0], #32
	st4	{v4.d, v5.d, v6.d, v7.d}[1], [x0], #32
	st4	{v8.d, v9.d, v10.d, v11.d}[1], [x0], #32
	st4	{v12.d, v13.d, v14.d, v15.d}[1], [x0], #32
	st4	{v16.d, v17.d, v18.d, v19.d}[1], [x0], #32
	st4	{v20.d, v21.d, v22.d, v23.d}[1], [x0], #32
	st1	{v24.d}[1], [x0]
	add	x0, x0, #8
	stp	x2, x3, [x0]
	stp	x4, x5, [x0, #16]
	stp	x6, x7, [x0, #32]
	stp	x8, x9, [x0, #48]
	stp	x10, x11, [x0, #64]
	stp	x12, x13, [x0, #80]
	stp	x14, x15, [x0, #96]
	stp	x16, x17, [x0, #112]
	stp	x19, x20, [x0, #128]
	stp	x21, x22, [x0, #144]
	stp	x23, x24, [x0, #160]
	stp	x25, x26, [x0, #176]
	str	x27, [x0, #192]
	ldp	x17, x19, [x29, #72]
	ldp	x20, x21, [x29, #88]
	ldp	x22, x23, [x29, #104]
	ldp	x24, x25, [x29, #120]
	ldp	x26, x27, [x29, #136]
	ldr	x28, [x29, #152]
	ldp	d8, d9, [x29, #160]
	ldp	d10, d11, [x29, #176]
	ldp	d12, d13, [x29, #192]
	ldp	d14, d15, [x29, #208]
	ldp	x29, x30, [sp], #0xe0
	ret
#ifndef __APPLE__
	.size	kyber_shake256_blocksx3_seed_neon,.-kyber_shake256_blocksx3_seed_neon
#endif /* __APPLE__ */
#else
#ifndef __APPLE__
.text
.globl	kyber_sha3_blocksx3_neon
.type	kyber_sha3_blocksx3_neon,@function
.align	2
kyber_sha3_blocksx3_neon:
#else
.section	__TEXT,__text
.globl	_kyber_sha3_blocksx3_neon
.p2align	2
_kyber_sha3_blocksx3_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-224]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #72]
	stp	x20, x21, [x29, #88]
	stp	x22, x23, [x29, #104]
	stp	x24, x25, [x29, #120]
	stp	x26, x27, [x29, #136]
	str	x28, [x29, #152]
	stp	d8, d9, [x29, #160]
	stp	d10, d11, [x29, #176]
	stp	d12, d13, [x29, #192]
	stp	d14, d15, [x29, #208]
#ifndef __APPLE__
	adrp x27, L_sha3_aarch64_r
	add  x27, x27, :lo12:L_sha3_aarch64_r
#else
	adrp x27, L_sha3_aarch64_r@PAGE
	add  x27, x27, :lo12:L_sha3_aarch64_r@PAGEOFF
#endif /* __APPLE__ */
	str	x0, [x29, #40]
	ld4	{v0.d, v1.d, v2.d, v3.d}[0], [x0], #32
	ld4	{v4.d, v5.d, v6.d, v7.d}[0], [x0], #32
	ld4	{v8.d, v9.d, v10.d, v11.d}[0], [x0], #32
	ld4	{v12.d, v13.d, v14.d, v15.d}[0], [x0], #32
	ld4	{v16.d, v17.d, v18.d, v19.d}[0], [x0], #32
	ld4	{v20.d, v21.d, v22.d, v23.d}[0], [x0], #32
	ld1	{v24.d}[0], [x0]
	add	x0, x0, #8
	ld4	{v0.d, v1.d, v2.d, v3.d}[1], [x0], #32
	ld4	{v4.d, v5.d, v6.d, v7.d}[1], [x0], #32
	ld4	{v8.d, v9.d, v10.d, v11.d}[1], [x0], #32
	ld4	{v12.d, v13.d, v14.d, v15.d}[1], [x0], #32
	ld4	{v16.d, v17.d, v18.d, v19.d}[1], [x0], #32
	ld4	{v20.d, v21.d, v22.d, v23.d}[1], [x0], #32
	ld1	{v24.d}[1], [x0]
	add	x0, x0, #8
	ldp	x1, x2, [x0]
	ldp	x3, x4, [x0, #16]
	ldp	x5, x6, [x0, #32]
	ldp	x7, x8, [x0, #48]
	ldp	x9, x10, [x0, #64]
	ldp	x11, x12, [x0, #80]
	ldp	x13, x14, [x0, #96]
	ldp	x15, x16, [x0, #112]
	ldp	x17, x19, [x0, #128]
	ldp	x20, x21, [x0, #144]
	ldp	x22, x23, [x0, #160]
	ldp	x24, x25, [x0, #176]
	ldr	x26, [x0, #192]
	mov	x28, #24
	# Start of 24 rounds
L_SHA3_transform_blocksx3_neon_begin:
	stp	x27, x28, [x29, #48]
	# Col Mix NEON
	eor	v30.16b, v4.16b, v9.16b
	eor	x0, x5, x10
	eor	v27.16b, v1.16b, v6.16b
	eor	x30, x1, x6
	eor	v30.16b, v30.16b, v14.16b
	eor	x28, x3, x8
	eor	v27.16b, v27.16b, v11.16b
	eor	x0, x0, x15
	eor	v30.16b, v30.16b, v19.16b
	eor	x30, x30, x11
	eor	v27.16b, v27.16b, v16.16b
	eor	x28, x28, x13
	eor	v30.16b, v30.16b, v24.16b
	eor	x0, x0, x21
	eor	v27.16b, v27.16b, v21.16b
	eor	x30, x30, x16
	ushr	v25.2d, v27.2d, #63
	eor	x28, x28, x19
	sli	v25.2d, v27.2d, #1
	eor	x0, x0, x26
	eor	v25.16b, v25.16b, v30.16b
	eor	x30, x30, x22
	eor	v31.16b, v0.16b, v5.16b
	eor	x28, x28, x24
	eor	v28.16b, v2.16b, v7.16b
	str	x0, [x29, #32]
	eor	v31.16b, v31.16b, v10.16b
	str	x28, [x29, #24]
	eor	v28.16b, v28.16b, v12.16b
	eor	x27, x2, x7
	eor	v31.16b, v31.16b, v15.16b
	eor	x28, x4, x9
	eor	v28.16b, v28.16b, v17.16b
	eor	x27, x27, x12
	eor	v31.16b, v31.16b, v20.16b
	eor	x28, x28, x14
	eor	v28.16b, v28.16b, v22.16b
	eor	x27, x27, x17
	ushr	v29.2d, v30.2d, #63
	eor	x28, x28, x20
	ushr	v26.2d, v28.2d, #63
	eor	x27, x27, x23
	sli	v29.2d, v30.2d, #1
	eor	x28, x28, x25
	sli	v26.2d, v28.2d, #1
	eor	x0, x0, x27, ror 63
	eor	v28.16b, v28.16b, v29.16b
	eor	x27, x27, x28, ror 63
	eor	v29.16b, v3.16b, v8.16b
	eor	x1, x1, x0
	eor	v26.16b, v26.16b, v31.16b
	eor	x6, x6, x0
	eor	v29.16b, v29.16b, v13.16b
	eor	x11, x11, x0
	eor	v29.16b, v29.16b, v18.16b
	eor	x16, x16, x0
	eor	v29.16b, v29.16b, v23.16b
	eor	x22, x22, x0
	ushr	v30.2d, v29.2d, #63
	eor	x3, x3, x27
	sli	v30.2d, v29.2d, #1
	eor	x8, x8, x27
	eor	v27.16b, v27.16b, v30.16b
	eor	x13, x13, x27
	ushr	v30.2d, v31.2d, #63
	eor	x19, x19, x27
	sli	v30.2d, v31.2d, #1
	eor	x24, x24, x27
	eor	v29.16b, v29.16b, v30.16b
	ldr	x0, [x29, #32]
	# Swap Rotate NEON
	eor	v0.16b, v0.16b, v25.16b
	eor	v31.16b, v1.16b, v26.16b
	ldr	x27, [x29, #24]
	eor	v6.16b, v6.16b, v26.16b
	eor	x28, x28, x30, ror 63
	ushr	v30.2d, v31.2d, #63
	eor	x30, x30, x27, ror 63
	ushr	v1.2d, v6.2d, #20
	eor	x27, x27, x0, ror 63
	sli	v30.2d, v31.2d, #1
	eor	x5, x5, x28
	sli	v1.2d, v6.2d, #44
	eor	x10, x10, x28
	eor	v31.16b, v9.16b, v29.16b
	eor	x15, x15, x28
	eor	v22.16b, v22.16b, v27.16b
	eor	x21, x21, x28
	ushr	v6.2d, v31.2d, #44
	eor	x26, x26, x28
	ushr	v9.2d, v22.2d, #3
	eor	x2, x2, x30
	sli	v6.2d, v31.2d, #20
	eor	x7, x7, x30
	sli	v9.2d, v22.2d, #61
	eor	x12, x12, x30
	eor	v31.16b, v14.16b, v29.16b
	eor	x17, x17, x30
	eor	v20.16b, v20.16b, v25.16b
	eor	x23, x23, x30
	ushr	v22.2d, v31.2d, #25
	eor	x4, x4, x27
	ushr	v14.2d, v20.2d, #46
	eor	x9, x9, x27
	sli	v22.2d, v31.2d, #39
	eor	x14, x14, x27
	sli	v14.2d, v20.2d, #18
	eor	x20, x20, x27
	eor	v31.16b, v2.16b, v27.16b
	eor	x25, x25, x27
	# Swap Rotate Base
	eor	v12.16b, v12.16b, v27.16b
	ror	x0, x2, #63
	ushr	v20.2d, v31.2d, #2
	ror	x2, x7, #20
	ushr	v2.2d, v12.2d, #21
	ror	x7, x10, #44
	sli	v20.2d, v31.2d, #62
	ror	x10, x24, #3
	sli	v2.2d, v12.2d, #43
	ror	x24, x15, #25
	eor	v31.16b, v13.16b, v28.16b
	ror	x15, x22, #46
	eor	v19.16b, v19.16b, v29.16b
	ror	x22, x3, #2
	ushr	v12.2d, v31.2d, #39
	ror	x3, x13, #21
	ushr	v13.2d, v19.2d, #56
	ror	x13, x14, #39
	sli	v12.2d, v31.2d, #25
	ror	x14, x21, #56
	sli	v13.2d, v19.2d, #8
	ror	x21, x25, #8
	eor	v31.16b, v23.16b, v28.16b
	ror	x25, x16, #23
	eor	v15.16b, v15.16b, v25.16b
	ror	x16, x5, #37
	ushr	v19.2d, v31.2d, #8
	ror	x5, x26, #50
	ushr	v23.2d, v15.2d, #23
	ror	x26, x23, #62
	sli	v19.2d, v31.2d, #56
	ror	x23, x9, #9
	sli	v23.2d, v15.2d, #41
	ror	x9, x17, #19
	eor	v31.16b, v4.16b, v29.16b
	ror	x17, x6, #28
	eor	v24.16b, v24.16b, v29.16b
	ror	x6, x4, #36
	ushr	v15.2d, v31.2d, #37
	ror	x4, x20, #43
	ushr	v4.2d, v24.2d, #50
	ror	x20, x19, #49
	sli	v15.2d, v31.2d, #27
	ror	x19, x12, #54
	sli	v4.2d, v24.2d, #14
	ror	x12, x8, #58
	eor	v31.16b, v21.16b, v26.16b
	ror	x8, x11, #61
	# Row Mix Base
	eor	v8.16b, v8.16b, v28.16b
	bic	x11, x3, x2
	ushr	v24.2d, v31.2d, #62
	bic	x27, x4, x3
	ushr	v21.2d, v8.2d, #9
	bic	x28, x1, x5
	sli	v24.2d, v31.2d, #2
	bic	x30, x2, x1
	sli	v21.2d, v8.2d, #55
	eor	x1, x1, x11
	eor	v31.16b, v16.16b, v26.16b
	eor	x2, x2, x27
	eor	v5.16b, v5.16b, v25.16b
	bic	x11, x5, x4
	ushr	v8.2d, v31.2d, #19
	eor	x4, x4, x28
	ushr	v16.2d, v5.2d, #28
	eor	x3, x3, x11
	sli	v8.2d, v31.2d, #45
	eor	x5, x5, x30
	sli	v16.2d, v5.2d, #36
	bic	x11, x8, x7
	eor	v31.16b, v3.16b, v28.16b
	bic	x27, x9, x8
	eor	v18.16b, v18.16b, v28.16b
	bic	x28, x6, x10
	ushr	v5.2d, v31.2d, #36
	bic	x30, x7, x6
	ushr	v3.2d, v18.2d, #43
	eor	x6, x6, x11
	sli	v5.2d, v31.2d, #28
	eor	x7, x7, x27
	sli	v3.2d, v18.2d, #21
	bic	x11, x10, x9
	eor	v31.16b, v17.16b, v27.16b
	eor	x9, x9, x28
	eor	v11.16b, v11.16b, v26.16b
	eor	x8, x8, x11
	ushr	v18.2d, v31.2d, #49
	eor	x10, x10, x30
	ushr	v17.2d, v11.2d, #54
	bic	x11, x13, x12
	sli	v18.2d, v31.2d, #15
	bic	x27, x14, x13
	sli	v17.2d, v11.2d, #10
	bic	x28, x0, x15
	eor	v31.16b, v7.16b, v27.16b
	bic	x30, x12, x0
	eor	v10.16b, v10.16b, v25.16b
	eor	x11, x0, x11
	ushr	v11.2d, v31.2d, #58
	eor	x12, x12, x27
	ushr	v7.2d, v10.2d, #61
	bic	x0, x15, x14
	sli	v11.2d, v31.2d, #6
	eor	x14, x14, x28
	sli	v7.2d, v10.2d, #3
	eor	x13, x13, x0
	# Row Mix NEON
	bic	v25.16b, v2.16b, v1.16b
	eor	x15, x15, x30
	bic	v26.16b, v3.16b, v2.16b
	bic	x0, x19, x17
	bic	v27.16b, v4.16b, v3.16b
	bic	x27, x20, x19
	bic	v28.16b, v0.16b, v4.16b
	bic	x28, x16, x21
	bic	v29.16b, v1.16b, v0.16b
	bic	x30, x17, x16
	eor	v0.16b, v0.16b, v25.16b
	eor	x16, x16, x0
	eor	v1.16b, v1.16b, v26.16b
	eor	x17, x17, x27
	eor	v2.16b, v2.16b, v27.16b
	bic	x0, x21, x20
	eor	v3.16b, v3.16b, v28.16b
	eor	x20, x20, x28
	eor	v4.16b, v4.16b, v29.16b
	eor	x19, x19, x0
	bic	v25.16b, v7.16b, v6.16b
	eor	x21, x21, x30
	bic	v26.16b, v8.16b, v7.16b
	bic	x0, x24, x23
	bic	v27.16b, v9.16b, v8.16b
	bic	x27, x25, x24
	bic	v28.16b, v5.16b, v9.16b
	bic	x28, x22, x26
	bic	v29.16b, v6.16b, v5.16b
	bic	x30, x23, x22
	eor	v5.16b, v5.16b, v25.16b
	eor	x22, x22, x0
	eor	v6.16b, v6.16b, v26.16b
	eor	x23, x23, x27
	eor	v7.16b, v7.16b, v27.16b
	bic	x0, x26, x25
	eor	v8.16b, v8.16b, v28.16b
	eor	x25, x25, x28
	eor	v9.16b, v9.16b, v29.16b
	eor	x24, x24, x0
	bic	v25.16b, v12.16b, v11.16b
	eor	x26, x26, x30
	bic	v26.16b, v13.16b, v12.16b
	bic	v27.16b, v14.16b, v13.16b
	bic	v28.16b, v30.16b, v14.16b
	bic	v29.16b, v11.16b, v30.16b
	eor	v10.16b, v30.16b, v25.16b
	eor	v11.16b, v11.16b, v26.16b
	eor	v12.16b, v12.16b, v27.16b
	eor	v13.16b, v13.16b, v28.16b
	eor	v14.16b, v14.16b, v29.16b
	bic	v25.16b, v17.16b, v16.16b
	bic	v26.16b, v18.16b, v17.16b
	bic	v27.16b, v19.16b, v18.16b
	bic	v28.16b, v15.16b, v19.16b
	bic	v29.16b, v16.16b, v15.16b
	eor	v15.16b, v15.16b, v25.16b
	eor	v16.16b, v16.16b, v26.16b
	eor	v17.16b, v17.16b, v27.16b
	eor	v18.16b, v18.16b, v28.16b
	eor	v19.16b, v19.16b, v29.16b
	bic	v25.16b, v22.16b, v21.16b
	bic	v26.16b, v23.16b, v22.16b
	bic	v27.16b, v24.16b, v23.16b
	bic	v28.16b, v20.16b, v24.16b
	bic	v29.16b, v21.16b, v20.16b
	eor	v20.16b, v20.16b, v25.16b
	eor	v21.16b, v21.16b, v26.16b
	eor	v22.16b, v22.16b, v27.16b
	eor	v23.16b, v23.16b, v28.16b
	eor	v24.16b, v24.16b, v29.16b
	# Done transforming
	ldp	x27, x28, [x29, #48]
	ldr	x0, [x27], #8
	subs	x28, x28, #1
	mov	v30.d[0], x0
	mov	v30.d[1], x0
	eor	x1, x1, x0
	eor	v0.16b, v0.16b, v30.16b
	bne	L_SHA3_transform_blocksx3_neon_begin
	ldr	x0, [x29, #40]
	st4	{v0.d, v1.d, v2.d, v3.d}[0], [x0], #32
	st4	{v4.d, v5.d, v6.d, v7.d}[0], [x0], #32
	st4	{v8.d, v9.d, v10.d, v11.d}[0], [x0], #32
	st4	{v12.d, v13.d, v14.d, v15.d}[0], [x0], #32
	st4	{v16.d, v17.d, v18.d, v19.d}[0], [x0], #32
	st4	{v20.d, v21.d, v22.d, v23.d}[0], [x0], #32
	st1	{v24.d}[0], [x0]
	add	x0, x0, #8
	st4	{v0.d, v1.d, v2.d, v3.d}[1], [x0], #32
	st4	{v4.d, v5.d, v6.d, v7.d}[1], [x0], #32
	st4	{v8.d, v9.d, v10.d, v11.d}[1], [x0], #32
	st4	{v12.d, v13.d, v14.d, v15.d}[1], [x0], #32
	st4	{v16.d, v17.d, v18.d, v19.d}[1], [x0], #32
	st4	{v20.d, v21.d, v22.d, v23.d}[1], [x0], #32
	st1	{v24.d}[1], [x0]
	add	x0, x0, #8
	stp	x1, x2, [x0]
	stp	x3, x4, [x0, #16]
	stp	x5, x6, [x0, #32]
	stp	x7, x8, [x0, #48]
	stp	x9, x10, [x0, #64]
	stp	x11, x12, [x0, #80]
	stp	x13, x14, [x0, #96]
	stp	x15, x16, [x0, #112]
	stp	x17, x19, [x0, #128]
	stp	x20, x21, [x0, #144]
	stp	x22, x23, [x0, #160]
	stp	x24, x25, [x0, #176]
	str	x26, [x0, #192]
	ldp	x17, x19, [x29, #72]
	ldp	x20, x21, [x29, #88]
	ldp	x22, x23, [x29, #104]
	ldp	x24, x25, [x29, #120]
	ldp	x26, x27, [x29, #136]
	ldr	x28, [x29, #152]
	ldp	d8, d9, [x29, #160]
	ldp	d10, d11, [x29, #176]
	ldp	d12, d13, [x29, #192]
	ldp	d14, d15, [x29, #208]
	ldp	x29, x30, [sp], #0xe0
	ret
#ifndef __APPLE__
	.size	kyber_sha3_blocksx3_neon,.-kyber_sha3_blocksx3_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	kyber_shake128_blocksx3_seed_neon
.type	kyber_shake128_blocksx3_seed_neon,@function
.align	2
kyber_shake128_blocksx3_seed_neon:
#else
.section	__TEXT,__text
.globl	_kyber_shake128_blocksx3_seed_neon
.p2align	2
_kyber_shake128_blocksx3_seed_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-224]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #72]
	stp	x20, x21, [x29, #88]
	stp	x22, x23, [x29, #104]
	stp	x24, x25, [x29, #120]
	stp	x26, x27, [x29, #136]
	str	x28, [x29, #152]
	stp	d8, d9, [x29, #160]
	stp	d10, d11, [x29, #176]
	stp	d12, d13, [x29, #192]
	stp	d14, d15, [x29, #208]
#ifndef __APPLE__
	adrp x28, L_sha3_aarch64_r
	add  x28, x28, :lo12:L_sha3_aarch64_r
#else
	adrp x28, L_sha3_aarch64_r@PAGE
	add  x28, x28, :lo12:L_sha3_aarch64_r@PAGEOFF
#endif /* __APPLE__ */
	str	x0, [x29, #40]
	add	x0, x0, #32
	ld1	{v4.d}[0], [x0]
	ldp	x2, x3, [x1], #16
	add	x0, x0, #0xc8
	ld1	{v4.d}[1], [x0]
	ldp	x4, x5, [x1], #16
	ldr	x6, [x0, #200]
	eor	v5.16b, v5.16b, v5.16b
	eor	x7, x7, x7
	eor	v6.16b, v6.16b, v6.16b
	eor	x8, x8, x8
	eor	v7.16b, v7.16b, v7.16b
	eor	x9, x9, x9
	eor	v8.16b, v8.16b, v8.16b
	eor	x10, x10, x10
	eor	v9.16b, v9.16b, v9.16b
	eor	x11, x11, x11
	eor	v10.16b, v10.16b, v10.16b
	eor	x12, x12, x12
	eor	v11.16b, v11.16b, v11.16b
	eor	x13, x13, x13
	eor	v12.16b, v12.16b, v12.16b
	eor	x14, x14, x14
	eor	v13.16b, v13.16b, v13.16b
	eor	x15, x15, x15
	eor	v14.16b, v14.16b, v14.16b
	eor	x16, x16, x16
	eor	v15.16b, v15.16b, v15.16b
	eor	x17, x17, x17
	eor	v16.16b, v16.16b, v16.16b
	eor	x19, x19, x19
	eor	v17.16b, v17.16b, v17.16b
	eor	x20, x20, x20
	eor	v18.16b, v18.16b, v18.16b
	eor	x21, x21, x21
	eor	v19.16b, v19.16b, v19.16b
	eor	x22, x22, x22
	movz	x23, #0x8000, lsl 48
	eor	v21.16b, v21.16b, v21.16b
	eor	x24, x24, x24
	eor	v22.16b, v22.16b, v22.16b
	eor	x25, x25, x25
	eor	v23.16b, v23.16b, v23.16b
	eor	x26, x26, x26
	eor	v24.16b, v24.16b, v24.16b
	eor	x27, x27, x27
	dup	v0.2d, x2
	dup	v1.2d, x3
	dup	v2.2d, x4
	dup	v3.2d, x5
	dup	v20.2d, x23
	mov	x1, #24
	# Start of 24 rounds
L_SHA3_shake128_blocksx3_seed_neon_begin:
	stp	x28, x1, [x29, #48]
	# Col Mix NEON
	eor	v30.16b, v4.16b, v9.16b
	eor	x0, x6, x11
	eor	v27.16b, v1.16b, v6.16b
	eor	x30, x2, x7
	eor	v30.16b, v30.16b, v14.16b
	eor	x28, x4, x9
	eor	v27.16b, v27.16b, v11.16b
	eor	x0, x0, x16
	eor	v30.16b, v30.16b, v19.16b
	eor	x30, x30, x12
	eor	v27.16b, v27.16b, v16.16b
	eor	x28, x28, x14
	eor	v30.16b, v30.16b, v24.16b
	eor	x0, x0, x22
	eor	v27.16b, v27.16b, v21.16b
	eor	x30, x30, x17
	ushr	v25.2d, v27.2d, #63
	eor	x28, x28, x20
	sli	v25.2d, v27.2d, #1
	eor	x0, x0, x27
	eor	v25.16b, v25.16b, v30.16b
	eor	x30, x30, x23
	eor	v31.16b, v0.16b, v5.16b
	eor	x28, x28, x25
	eor	v28.16b, v2.16b, v7.16b
	str	x0, [x29, #32]
	eor	v31.16b, v31.16b, v10.16b
	str	x28, [x29, #24]
	eor	v28.16b, v28.16b, v12.16b
	eor	x1, x3, x8
	eor	v31.16b, v31.16b, v15.16b
	eor	x28, x5, x10
	eor	v28.16b, v28.16b, v17.16b
	eor	x1, x1, x13
	eor	v31.16b, v31.16b, v20.16b
	eor	x28, x28, x15
	eor	v28.16b, v28.16b, v22.16b
	eor	x1, x1, x19
	ushr	v29.2d, v30.2d, #63
	eor	x28, x28, x21
	ushr	v26.2d, v28.2d, #63
	eor	x1, x1, x24
	sli	v29.2d, v30.2d, #1
	eor	x28, x28, x26
	sli	v26.2d, v28.2d, #1
	eor	x0, x0, x1, ror 63
	eor	v28.16b, v28.16b, v29.16b
	eor	x1, x1, x28, ror 63
	eor	v29.16b, v3.16b, v8.16b
	eor	x2, x2, x0
	eor	v26.16b, v26.16b, v31.16b
	eor	x7, x7, x0
	eor	v29.16b, v29.16b, v13.16b
	eor	x12, x12, x0
	eor	v29.16b, v29.16b, v18.16b
	eor	x17, x17, x0
	eor	v29.16b, v29.16b, v23.16b
	eor	x23, x23, x0
	ushr	v30.2d, v29.2d, #63
	eor	x4, x4, x1
	sli	v30.2d, v29.2d, #1
	eor	x9, x9, x1
	eor	v27.16b, v27.16b, v30.16b
	eor	x14, x14, x1
	ushr	v30.2d, v31.2d, #63
	eor	x20, x20, x1
	sli	v30.2d, v31.2d, #1
	eor	x25, x25, x1
	eor	v29.16b, v29.16b, v30.16b
	ldr	x0, [x29, #32]
	# Swap Rotate NEON
	eor	v0.16b, v0.16b, v25.16b
	eor	v31.16b, v1.16b, v26.16b
	ldr	x1, [x29, #24]
	eor	v6.16b, v6.16b, v26.16b
	eor	x28, x28, x30, ror 63
	ushr	v30.2d, v31.2d, #63
	eor	x30, x30, x1, ror 63
	ushr	v1.2d, v6.2d, #20
	eor	x1, x1, x0, ror 63
	sli	v30.2d, v31.2d, #1
	eor	x6, x6, x28
	sli	v1.2d, v6.2d, #44
	eor	x11, x11, x28
	eor	v31.16b, v9.16b, v29.16b
	eor	x16, x16, x28
	eor	v22.16b, v22.16b, v27.16b
	eor	x22, x22, x28
	ushr	v6.2d, v31.2d, #44
	eor	x27, x27, x28
	ushr	v9.2d, v22.2d, #3
	eor	x3, x3, x30
	sli	v6.2d, v31.2d, #20
	eor	x8, x8, x30
	sli	v9.2d, v22.2d, #61
	eor	x13, x13, x30
	eor	v31.16b, v14.16b, v29.16b
	eor	x19, x19, x30
	eor	v20.16b, v20.16b, v25.16b
	eor	x24, x24, x30
	ushr	v22.2d, v31.2d, #25
	eor	x5, x5, x1
	ushr	v14.2d, v20.2d, #46
	eor	x10, x10, x1
	sli	v22.2d, v31.2d, #39
	eor	x15, x15, x1
	sli	v14.2d, v20.2d, #18
	eor	x21, x21, x1
	eor	v31.16b, v2.16b, v27.16b
	eor	x26, x26, x1
	# Swap Rotate Base
	eor	v12.16b, v12.16b, v27.16b
	ror	x0, x3, #63
	ushr	v20.2d, v31.2d, #2
	ror	x3, x8, #20
	ushr	v2.2d, v12.2d, #21
	ror	x8, x11, #44
	sli	v20.2d, v31.2d, #62
	ror	x11, x25, #3
	sli	v2.2d, v12.2d, #43
	ror	x25, x16, #25
	eor	v31.16b, v13.16b, v28.16b
	ror	x16, x23, #46
	eor	v19.16b, v19.16b, v29.16b
	ror	x23, x4, #2
	ushr	v12.2d, v31.2d, #39
	ror	x4, x14, #21
	ushr	v13.2d, v19.2d, #56
	ror	x14, x15, #39
	sli	v12.2d, v31.2d, #25
	ror	x15, x22, #56
	sli	v13.2d, v19.2d, #8
	ror	x22, x26, #8
	eor	v31.16b, v23.16b, v28.16b
	ror	x26, x17, #23
	eor	v15.16b, v15.16b, v25.16b
	ror	x17, x6, #37
	ushr	v19.2d, v31.2d, #8
	ror	x6, x27, #50
	ushr	v23.2d, v15.2d, #23
	ror	x27, x24, #62
	sli	v19.2d, v31.2d, #56
	ror	x24, x10, #9
	sli	v23.2d, v15.2d, #41
	ror	x10, x19, #19
	eor	v31.16b, v4.16b, v29.16b
	ror	x19, x7, #28
	eor	v24.16b, v24.16b, v29.16b
	ror	x7, x5, #36
	ushr	v15.2d, v31.2d, #37
	ror	x5, x21, #43
	ushr	v4.2d, v24.2d, #50
	ror	x21, x20, #49
	sli	v15.2d, v31.2d, #27
	ror	x20, x13, #54
	sli	v4.2d, v24.2d, #14
	ror	x13, x9, #58
	eor	v31.16b, v21.16b, v26.16b
	ror	x9, x12, #61
	# Row Mix Base
	eor	v8.16b, v8.16b, v28.16b
	bic	x12, x4, x3
	ushr	v24.2d, v31.2d, #62
	bic	x1, x5, x4
	ushr	v21.2d, v8.2d, #9
	bic	x28, x2, x6
	sli	v24.2d, v31.2d, #2
	bic	x30, x3, x2
	sli	v21.2d, v8.2d, #55
	eor	x2, x2, x12
	eor	v31.16b, v16.16b, v26.16b
	eor	x3, x3, x1
	eor	v5.16b, v5.16b, v25.16b
	bic	x12, x6, x5
	ushr	v8.2d, v31.2d, #19
	eor	x5, x5, x28
	ushr	v16.2d, v5.2d, #28
	eor	x4, x4, x12
	sli	v8.2d, v31.2d, #45
	eor	x6, x6, x30
	sli	v16.2d, v5.2d, #36
	bic	x12, x9, x8
	eor	v31.16b, v3.16b, v28.16b
	bic	x1, x10, x9
	eor	v18.16b, v18.16b, v28.16b
	bic	x28, x7, x11
	ushr	v5.2d, v31.2d, #36
	bic	x30, x8, x7
	ushr	v3.2d, v18.2d, #43
	eor	x7, x7, x12
	sli	v5.2d, v31.2d, #28
	eor	x8, x8, x1
	sli	v3.2d, v18.2d, #21
	bic	x12, x11, x10
	eor	v31.16b, v17.16b, v27.16b
	eor	x10, x10, x28
	eor	v11.16b, v11.16b, v26.16b
	eor	x9, x9, x12
	ushr	v18.2d, v31.2d, #49
	eor	x11, x11, x30
	ushr	v17.2d, v11.2d, #54
	bic	x12, x14, x13
	sli	v18.2d, v31.2d, #15
	bic	x1, x15, x14
	sli	v17.2d, v11.2d, #10
	bic	x28, x0, x16
	eor	v31.16b, v7.16b, v27.16b
	bic	x30, x13, x0
	eor	v10.16b, v10.16b, v25.16b
	eor	x12, x0, x12
	ushr	v11.2d, v31.2d, #58
	eor	x13, x13, x1
	ushr	v7.2d, v10.2d, #61
	bic	x0, x16, x15
	sli	v11.2d, v31.2d, #6
	eor	x15, x15, x28
	sli	v7.2d, v10.2d, #3
	eor	x14, x14, x0
	# Row Mix NEON
	bic	v25.16b, v2.16b, v1.16b
	eor	x16, x16, x30
	bic	v26.16b, v3.16b, v2.16b
	bic	x0, x20, x19
	bic	v27.16b, v4.16b, v3.16b
	bic	x1, x21, x20
	bic	v28.16b, v0.16b, v4.16b
	bic	x28, x17, x22
	bic	v29.16b, v1.16b, v0.16b
	bic	x30, x19, x17
	eor	v0.16b, v0.16b, v25.16b
	eor	x17, x17, x0
	eor	v1.16b, v1.16b, v26.16b
	eor	x19, x19, x1
	eor	v2.16b, v2.16b, v27.16b
	bic	x0, x22, x21
	eor	v3.16b, v3.16b, v28.16b
	eor	x21, x21, x28
	eor	v4.16b, v4.16b, v29.16b
	eor	x20, x20, x0
	bic	v25.16b, v7.16b, v6.16b
	eor	x22, x22, x30
	bic	v26.16b, v8.16b, v7.16b
	bic	x0, x25, x24
	bic	v27.16b, v9.16b, v8.16b
	bic	x1, x26, x25
	bic	v28.16b, v5.16b, v9.16b
	bic	x28, x23, x27
	bic	v29.16b, v6.16b, v5.16b
	bic	x30, x24, x23
	eor	v5.16b, v5.16b, v25.16b
	eor	x23, x23, x0
	eor	v6.16b, v6.16b, v26.16b
	eor	x24, x24, x1
	eor	v7.16b, v7.16b, v27.16b
	bic	x0, x27, x26
	eor	v8.16b, v8.16b, v28.16b
	eor	x26, x26, x28
	eor	v9.16b, v9.16b, v29.16b
	eor	x25, x25, x0
	bic	v25.16b, v12.16b, v11.16b
	eor	x27, x27, x30
	bic	v26.16b, v13.16b, v12.16b
	bic	v27.16b, v14.16b, v13.16b
	bic	v28.16b, v30.16b, v14.16b
	bic	v29.16b, v11.16b, v30.16b
	eor	v10.16b, v30.16b, v25.16b
	eor	v11.16b, v11.16b, v26.16b
	eor	v12.16b, v12.16b, v27.16b
	eor	v13.16b, v13.16b, v28.16b
	eor	v14.16b, v14.16b, v29.16b
	bic	v25.16b, v17.16b, v16.16b
	bic	v26.16b, v18.16b, v17.16b
	bic	v27.16b, v19.16b, v18.16b
	bic	v28.16b, v15.16b, v19.16b
	bic	v29.16b, v16.16b, v15.16b
	eor	v15.16b, v15.16b, v25.16b
	eor	v16.16b, v16.16b, v26.16b
	eor	v17.16b, v17.16b, v27.16b
	eor	v18.16b, v18.16b, v28.16b
	eor	v19.16b, v19.16b, v29.16b
	bic	v25.16b, v22.16b, v21.16b
	bic	v26.16b, v23.16b, v22.16b
	bic	v27.16b, v24.16b, v23.16b
	bic	v28.16b, v20.16b, v24.16b
	bic	v29.16b, v21.16b, v20.16b
	eor	v20.16b, v20.16b, v25.16b
	eor	v21.16b, v21.16b, v26.16b
	eor	v22.16b, v22.16b, v27.16b
	eor	v23.16b, v23.16b, v28.16b
	eor	v24.16b, v24.16b, v29.16b
	# Done transforming
	ldp	x28, x1, [x29, #48]
	ldr	x0, [x28], #8
	subs	x1, x1, #1
	mov	v30.d[0], x0
	mov	v30.d[1], x0
	eor	x2, x2, x0
	eor	v0.16b, v0.16b, v30.16b
	bne	L_SHA3_shake128_blocksx3_seed_neon_begin
	ldr	x0, [x29, #40]
	st4	{v0.d, v1.d, v2.d, v3.d}[0], [x0], #32
	st4	{v4.d, v5.d, v6.d, v7.d}[0], [x0], #32
	st4	{v8.d, v9.d, v10.d, v11.d}[0], [x0], #32
	st4	{v12.d, v13.d, v14.d, v15.d}[0], [x0], #32
	st4	{v16.d, v17.d, v18.d, v19.d}[0], [x0], #32
	st4	{v20.d, v21.d, v22.d, v23.d}[0], [x0], #32
	st1	{v24.d}[0], [x0]
	add	x0, x0, #8
	st4	{v0.d, v1.d, v2.d, v3.d}[1], [x0], #32
	st4	{v4.d, v5.d, v6.d, v7.d}[1], [x0], #32
	st4	{v8.d, v9.d, v10.d, v11.d}[1], [x0], #32
	st4	{v12.d, v13.d, v14.d, v15.d}[1], [x0], #32
	st4	{v16.d, v17.d, v18.d, v19.d}[1], [x0], #32
	st4	{v20.d, v21.d, v22.d, v23.d}[1], [x0], #32
	st1	{v24.d}[1], [x0]
	add	x0, x0, #8
	stp	x2, x3, [x0]
	stp	x4, x5, [x0, #16]
	stp	x6, x7, [x0, #32]
	stp	x8, x9, [x0, #48]
	stp	x10, x11, [x0, #64]
	stp	x12, x13, [x0, #80]
	stp	x14, x15, [x0, #96]
	stp	x16, x17, [x0, #112]
	stp	x19, x20, [x0, #128]
	stp	x21, x22, [x0, #144]
	stp	x23, x24, [x0, #160]
	stp	x25, x26, [x0, #176]
	str	x27, [x0, #192]
	ldp	x17, x19, [x29, #72]
	ldp	x20, x21, [x29, #88]
	ldp	x22, x23, [x29, #104]
	ldp	x24, x25, [x29, #120]
	ldp	x26, x27, [x29, #136]
	ldr	x28, [x29, #152]
	ldp	d8, d9, [x29, #160]
	ldp	d10, d11, [x29, #176]
	ldp	d12, d13, [x29, #192]
	ldp	d14, d15, [x29, #208]
	ldp	x29, x30, [sp], #0xe0
	ret
#ifndef __APPLE__
	.size	kyber_shake128_blocksx3_seed_neon,.-kyber_shake128_blocksx3_seed_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	kyber_shake256_blocksx3_seed_neon
.type	kyber_shake256_blocksx3_seed_neon,@function
.align	2
kyber_shake256_blocksx3_seed_neon:
#else
.section	__TEXT,__text
.globl	_kyber_shake256_blocksx3_seed_neon
.p2align	2
_kyber_shake256_blocksx3_seed_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-224]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #72]
	stp	x20, x21, [x29, #88]
	stp	x22, x23, [x29, #104]
	stp	x24, x25, [x29, #120]
	stp	x26, x27, [x29, #136]
	str	x28, [x29, #152]
	stp	d8, d9, [x29, #160]
	stp	d10, d11, [x29, #176]
	stp	d12, d13, [x29, #192]
	stp	d14, d15, [x29, #208]
#ifndef __APPLE__
	adrp x28, L_sha3_aarch64_r
	add  x28, x28, :lo12:L_sha3_aarch64_r
#else
	adrp x28, L_sha3_aarch64_r@PAGE
	add  x28, x28, :lo12:L_sha3_aarch64_r@PAGEOFF
#endif /* __APPLE__ */
	str	x0, [x29, #40]
	add	x0, x0, #32
	ld1	{v4.d}[0], [x0]
	ldp	x2, x3, [x1], #16
	add	x0, x0, #0xc8
	ld1	{v4.d}[1], [x0]
	ldp	x4, x5, [x1], #16
	ldr	x6, [x0, #200]
	eor	v5.16b, v5.16b, v5.16b
	eor	x7, x7, x7
	eor	v6.16b, v6.16b, v6.16b
	eor	x8, x8, x8
	eor	v7.16b, v7.16b, v7.16b
	eor	x9, x9, x9
	eor	v8.16b, v8.16b, v8.16b
	eor	x10, x10, x10
	eor	v9.16b, v9.16b, v9.16b
	eor	x11, x11, x11
	eor	v10.16b, v10.16b, v10.16b
	eor	x12, x12, x12
	eor	v11.16b, v11.16b, v11.16b
	eor	x13, x13, x13
	eor	v12.16b, v12.16b, v12.16b
	eor	x14, x14, x14
	eor	v13.16b, v13.16b, v13.16b
	eor	x15, x15, x15
	eor	v14.16b, v14.16b, v14.16b
	eor	x16, x16, x16
	eor	v15.16b, v15.16b, v15.16b
	eor	x17, x17, x17
	movz	x19, #0x8000, lsl 48
	eor	v17.16b, v17.16b, v17.16b
	eor	x20, x20, x20
	eor	v18.16b, v18.16b, v18.16b
	eor	x21, x21, x21
	eor	v19.16b, v19.16b, v19.16b
	eor	x22, x22, x22
	eor	v20.16b, v20.16b, v20.16b
	eor	x23, x23, x23
	eor	v21.16b, v21.16b, v21.16b
	eor	x24, x24, x24
	eor	v22.16b, v22.16b, v22.16b
	eor	x25, x25, x25
	eor	v23.16b, v23.16b, v23.16b
	eor	x26, x26, x26
	eor	v24.16b, v24.16b, v24.16b
	eor	x27, x27, x27
	dup	v0.2d, x2
	dup	v1.2d, x3
	dup	v2.2d, x4
	dup	v3.2d, x5
	dup	v16.2d, x19
	mov	x1, #24
	# Start of 24 rounds
L_SHA3_shake256_blocksx3_seed_neon_begin:
	stp	x28, x1, [x29, #48]
	# Col Mix NEON
	eor	v30.16b, v4.16b, v9.16b
	eor	x0, x6, x11
	eor	v27.16b, v1.16b, v6.16b
	eor	x30, x2, x7
	eor	v30.16b, v30.16b, v14.16b
	eor	x28, x4, x9
	eor	v27.16b, v27.16b, v11.16b
	eor	x0, x0, x16
	eor	v30.16b, v30.16b, v19.16b
	eor	x30, x30, x12
	eor	v27.16b, v27.16b, v16.16b
	eor	x28, x28, x14
	eor	v30.16b, v30.16b, v24.16b
	eor	x0, x0, x22
	eor	v27.16b, v27.16b, v21.16b
	eor	x30, x30, x17
	ushr	v25.2d, v27.2d, #63
	eor	x28, x28, x20
	sli	v25.2d, v27.2d, #1
	eor	x0, x0, x27
	eor	v25.16b, v25.16b, v30.16b
	eor	x30, x30, x23
	eor	v31.16b, v0.16b, v5.16b
	eor	x28, x28, x25
	eor	v28.16b, v2.16b, v7.16b
	str	x0, [x29, #32]
	eor	v31.16b, v31.16b, v10.16b
	str	x28, [x29, #24]
	eor	v28.16b, v28.16b, v12.16b
	eor	x1, x3, x8
	eor	v31.16b, v31.16b, v15.16b
	eor	x28, x5, x10
	eor	v28.16b, v28.16b, v17.16b
	eor	x1, x1, x13
	eor	v31.16b, v31.16b, v20.16b
	eor	x28, x28, x15
	eor	v28.16b, v28.16b, v22.16b
	eor	x1, x1, x19
	ushr	v29.2d, v30.2d, #63
	eor	x28, x28, x21
	ushr	v26.2d, v28.2d, #63
	eor	x1, x1, x24
	sli	v29.2d, v30.2d, #1
	eor	x28, x28, x26
	sli	v26.2d, v28.2d, #1
	eor	x0, x0, x1, ror 63
	eor	v28.16b, v28.16b, v29.16b
	eor	x1, x1, x28, ror 63
	eor	v29.16b, v3.16b, v8.16b
	eor	x2, x2, x0
	eor	v26.16b, v26.16b, v31.16b
	eor	x7, x7, x0
	eor	v29.16b, v29.16b, v13.16b
	eor	x12, x12, x0
	eor	v29.16b, v29.16b, v18.16b
	eor	x17, x17, x0
	eor	v29.16b, v29.16b, v23.16b
	eor	x23, x23, x0
	ushr	v30.2d, v29.2d, #63
	eor	x4, x4, x1
	sli	v30.2d, v29.2d, #1
	eor	x9, x9, x1
	eor	v27.16b, v27.16b, v30.16b
	eor	x14, x14, x1
	ushr	v30.2d, v31.2d, #63
	eor	x20, x20, x1
	sli	v30.2d, v31.2d, #1
	eor	x25, x25, x1
	eor	v29.16b, v29.16b, v30.16b
	ldr	x0, [x29, #32]
	# Swap Rotate NEON
	eor	v0.16b, v0.16b, v25.16b
	eor	v31.16b, v1.16b, v26.16b
	ldr	x1, [x29, #24]
	eor	v6.16b, v6.16b, v26.16b
	eor	x28, x28, x30, ror 63
	ushr	v30.2d, v31.2d, #63
	eor	x30, x30, x1, ror 63
	ushr	v1.2d, v6.2d, #20
	eor	x1, x1, x0, ror 63
	sli	v30.2d, v31.2d, #1
	eor	x6, x6, x28
	sli	v1.2d, v6.2d, #44
	eor	x11, x11, x28
	eor	v31.16b, v9.16b, v29.16b
	eor	x16, x16, x28
	eor	v22.16b, v22.16b, v27.16b
	eor	x22, x22, x28
	ushr	v6.2d, v31.2d, #44
	eor	x27, x27, x28
	ushr	v9.2d, v22.2d, #3
	eor	x3, x3, x30
	sli	v6.2d, v31.2d, #20
	eor	x8, x8, x30
	sli	v9.2d, v22.2d, #61
	eor	x13, x13, x30
	eor	v31.16b, v14.16b, v29.16b
	eor	x19, x19, x30
	eor	v20.16b, v20.16b, v25.16b
	eor	x24, x24, x30
	ushr	v22.2d, v31.2d, #25
	eor	x5, x5, x1
	ushr	v14.2d, v20.2d, #46
	eor	x10, x10, x1
	sli	v22.2d, v31.2d, #39
	eor	x15, x15, x1
	sli	v14.2d, v20.2d, #18
	eor	x21, x21, x1
	eor	v31.16b, v2.16b, v27.16b
	eor	x26, x26, x1
	# Swap Rotate Base
	eor	v12.16b, v12.16b, v27.16b
	ror	x0, x3, #63
	ushr	v20.2d, v31.2d, #2
	ror	x3, x8, #20
	ushr	v2.2d, v12.2d, #21
	ror	x8, x11, #44
	sli	v20.2d, v31.2d, #62
	ror	x11, x25, #3
	sli	v2.2d, v12.2d, #43
	ror	x25, x16, #25
	eor	v31.16b, v13.16b, v28.16b
	ror	x16, x23, #46
	eor	v19.16b, v19.16b, v29.16b
	ror	x23, x4, #2
	ushr	v12.2d, v31.2d, #39
	ror	x4, x14, #21
	ushr	v13.2d, v19.2d, #56
	ror	x14, x15, #39
	sli	v12.2d, v31.2d, #25
	ror	x15, x22, #56
	sli	v13.2d, v19.2d, #8
	ror	x22, x26, #8
	eor	v31.16b, v23.16b, v28.16b
	ror	x26, x17, #23
	eor	v15.16b, v15.16b, v25.16b
	ror	x17, x6, #37
	ushr	v19.2d, v31.2d, #8
	ror	x6, x27, #50
	ushr	v23.2d, v15.2d, #23
	ror	x27, x24, #62
	sli	v19.2d, v31.2d, #56
	ror	x24, x10, #9
	sli	v23.2d, v15.2d, #41
	ror	x10, x19, #19
	eor	v31.16b, v4.16b, v29.16b
	ror	x19, x7, #28
	eor	v24.16b, v24.16b, v29.16b
	ror	x7, x5, #36
	ushr	v15.2d, v31.2d, #37
	ror	x5, x21, #43
	ushr	v4.2d, v24.2d, #50
	ror	x21, x20, #49
	sli	v15.2d, v31.2d, #27
	ror	x20, x13, #54
	sli	v4.2d, v24.2d, #14
	ror	x13, x9, #58
	eor	v31.16b, v21.16b, v26.16b
	ror	x9, x12, #61
	# Row Mix Base
	eor	v8.16b, v8.16b, v28.16b
	bic	x12, x4, x3
	ushr	v24.2d, v31.2d, #62
	bic	x1, x5, x4
	ushr	v21.2d, v8.2d, #9
	bic	x28, x2, x6
	sli	v24.2d, v31.2d, #2
	bic	x30, x3, x2
	sli	v21.2d, v8.2d, #55
	eor	x2, x2, x12
	eor	v31.16b, v16.16b, v26.16b
	eor	x3, x3, x1
	eor	v5.16b, v5.16b, v25.16b
	bic	x12, x6, x5
	ushr	v8.2d, v31.2d, #19
	eor	x5, x5, x28
	ushr	v16.2d, v5.2d, #28
	eor	x4, x4, x12
	sli	v8.2d, v31.2d, #45
	eor	x6, x6, x30
	sli	v16.2d, v5.2d, #36
	bic	x12, x9, x8
	eor	v31.16b, v3.16b, v28.16b
	bic	x1, x10, x9
	eor	v18.16b, v18.16b, v28.16b
	bic	x28, x7, x11
	ushr	v5.2d, v31.2d, #36
	bic	x30, x8, x7
	ushr	v3.2d, v18.2d, #43
	eor	x7, x7, x12
	sli	v5.2d, v31.2d, #28
	eor	x8, x8, x1
	sli	v3.2d, v18.2d, #21
	bic	x12, x11, x10
	eor	v31.16b, v17.16b, v27.16b
	eor	x10, x10, x28
	eor	v11.16b, v11.16b, v26.16b
	eor	x9, x9, x12
	ushr	v18.2d, v31.2d, #49
	eor	x11, x11, x30
	ushr	v17.2d, v11.2d, #54
	bic	x12, x14, x13
	sli	v18.2d, v31.2d, #15
	bic	x1, x15, x14
	sli	v17.2d, v11.2d, #10
	bic	x28, x0, x16
	eor	v31.16b, v7.16b, v27.16b
	bic	x30, x13, x0
	eor	v10.16b, v10.16b, v25.16b
	eor	x12, x0, x12
	ushr	v11.2d, v31.2d, #58
	eor	x13, x13, x1
	ushr	v7.2d, v10.2d, #61
	bic	x0, x16, x15
	sli	v11.2d, v31.2d, #6
	eor	x15, x15, x28
	sli	v7.2d, v10.2d, #3
	eor	x14, x14, x0
	# Row Mix NEON
	bic	v25.16b, v2.16b, v1.16b
	eor	x16, x16, x30
	bic	v26.16b, v3.16b, v2.16b
	bic	x0, x20, x19
	bic	v27.16b, v4.16b, v3.16b
	bic	x1, x21, x20
	bic	v28.16b, v0.16b, v4.16b
	bic	x28, x17, x22
	bic	v29.16b, v1.16b, v0.16b
	bic	x30, x19, x17
	eor	v0.16b, v0.16b, v25.16b
	eor	x17, x17, x0
	eor	v1.16b, v1.16b, v26.16b
	eor	x19, x19, x1
	eor	v2.16b, v2.16b, v27.16b
	bic	x0, x22, x21
	eor	v3.16b, v3.16b, v28.16b
	eor	x21, x21, x28
	eor	v4.16b, v4.16b, v29.16b
	eor	x20, x20, x0
	bic	v25.16b, v7.16b, v6.16b
	eor	x22, x22, x30
	bic	v26.16b, v8.16b, v7.16b
	bic	x0, x25, x24
	bic	v27.16b, v9.16b, v8.16b
	bic	x1, x26, x25
	bic	v28.16b, v5.16b, v9.16b
	bic	x28, x23, x27
	bic	v29.16b, v6.16b, v5.16b
	bic	x30, x24, x23
	eor	v5.16b, v5.16b, v25.16b
	eor	x23, x23, x0
	eor	v6.16b, v6.16b, v26.16b
	eor	x24, x24, x1
	eor	v7.16b, v7.16b, v27.16b
	bic	x0, x27, x26
	eor	v8.16b, v8.16b, v28.16b
	eor	x26, x26, x28
	eor	v9.16b, v9.16b, v29.16b
	eor	x25, x25, x0
	bic	v25.16b, v12.16b, v11.16b
	eor	x27, x27, x30
	bic	v26.16b, v13.16b, v12.16b
	bic	v27.16b, v14.16b, v13.16b
	bic	v28.16b, v30.16b, v14.16b
	bic	v29.16b, v11.16b, v30.16b
	eor	v10.16b, v30.16b, v25.16b
	eor	v11.16b, v11.16b, v26.16b
	eor	v12.16b, v12.16b, v27.16b
	eor	v13.16b, v13.16b, v28.16b
	eor	v14.16b, v14.16b, v29.16b
	bic	v25.16b, v17.16b, v16.16b
	bic	v26.16b, v18.16b, v17.16b
	bic	v27.16b, v19.16b, v18.16b
	bic	v28.16b, v15.16b, v19.16b
	bic	v29.16b, v16.16b, v15.16b
	eor	v15.16b, v15.16b, v25.16b
	eor	v16.16b, v16.16b, v26.16b
	eor	v17.16b, v17.16b, v27.16b
	eor	v18.16b, v18.16b, v28.16b
	eor	v19.16b, v19.16b, v29.16b
	bic	v25.16b, v22.16b, v21.16b
	bic	v26.16b, v23.16b, v22.16b
	bic	v27.16b, v24.16b, v23.16b
	bic	v28.16b, v20.16b, v24.16b
	bic	v29.16b, v21.16b, v20.16b
	eor	v20.16b, v20.16b, v25.16b
	eor	v21.16b, v21.16b, v26.16b
	eor	v22.16b, v22.16b, v27.16b
	eor	v23.16b, v23.16b, v28.16b
	eor	v24.16b, v24.16b, v29.16b
	# Done transforming
	ldp	x28, x1, [x29, #48]
	ldr	x0, [x28], #8
	subs	x1, x1, #1
	mov	v30.d[0], x0
	mov	v30.d[1], x0
	eor	x2, x2, x0
	eor	v0.16b, v0.16b, v30.16b
	bne	L_SHA3_shake256_blocksx3_seed_neon_begin
	ldr	x0, [x29, #40]
	st4	{v0.d, v1.d, v2.d, v3.d}[0], [x0], #32
	st4	{v4.d, v5.d, v6.d, v7.d}[0], [x0], #32
	st4	{v8.d, v9.d, v10.d, v11.d}[0], [x0], #32
	st4	{v12.d, v13.d, v14.d, v15.d}[0], [x0], #32
	st4	{v16.d, v17.d, v18.d, v19.d}[0], [x0], #32
	st4	{v20.d, v21.d, v22.d, v23.d}[0], [x0], #32
	st1	{v24.d}[0], [x0]
	add	x0, x0, #8
	st4	{v0.d, v1.d, v2.d, v3.d}[1], [x0], #32
	st4	{v4.d, v5.d, v6.d, v7.d}[1], [x0], #32
	st4	{v8.d, v9.d, v10.d, v11.d}[1], [x0], #32
	st4	{v12.d, v13.d, v14.d, v15.d}[1], [x0], #32
	st4	{v16.d, v17.d, v18.d, v19.d}[1], [x0], #32
	st4	{v20.d, v21.d, v22.d, v23.d}[1], [x0], #32
	st1	{v24.d}[1], [x0]
	add	x0, x0, #8
	stp	x2, x3, [x0]
	stp	x4, x5, [x0, #16]
	stp	x6, x7, [x0, #32]
	stp	x8, x9, [x0, #48]
	stp	x10, x11, [x0, #64]
	stp	x12, x13, [x0, #80]
	stp	x14, x15, [x0, #96]
	stp	x16, x17, [x0, #112]
	stp	x19, x20, [x0, #128]
	stp	x21, x22, [x0, #144]
	stp	x23, x24, [x0, #160]
	stp	x25, x26, [x0, #176]
	str	x27, [x0, #192]
	ldp	x17, x19, [x29, #72]
	ldp	x20, x21, [x29, #88]
	ldp	x22, x23, [x29, #104]
	ldp	x24, x25, [x29, #120]
	ldp	x26, x27, [x29, #136]
	ldr	x28, [x29, #152]
	ldp	d8, d9, [x29, #160]
	ldp	d10, d11, [x29, #176]
	ldp	d12, d13, [x29, #192]
	ldp	d14, d15, [x29, #208]
	ldp	x29, x30, [sp], #0xe0
	ret
#ifndef __APPLE__
	.size	kyber_shake256_blocksx3_seed_neon,.-kyber_shake256_blocksx3_seed_neon
#endif /* __APPLE__ */
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
#endif /* WOLFSSL_WC_KYBER */
#endif /* __aarch64__ */
#endif /* WOLFSSL_ARMASM */

#if defined(__linux__) && defined(__ELF__)
.section	.note.GNU-stack,"",%progbits
#endif
#endif /* !WOLFSSL_ARMASM_INLINE */
