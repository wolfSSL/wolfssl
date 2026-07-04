; /* armv8-mlkem-asm
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
;   ruby ./kyber/kyber.rb arm64 \
;       ../wolfssl/wolfcrypt/src/port/arm/armv8-mlkem-asm.asm
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mlkem_aarch64_consts
	DCW	0x0d01, 0xf301, 0x4ebf, 0x0549, 0x5049, 0x0000, 0x0000, 0x0000
	IF :DEF:WOLFSSL_HAVE_MLKEM
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mlkem_aarch64_zetas
	DCW	0x08ed, 0x0a0b, 0x0b9a, 0x0714, 0x05d5, 0x058e, 0x011f, 0x00ca
	DCW	0x0c56, 0x026e, 0x0629, 0x00b6, 0x03c2, 0x084f, 0x073f, 0x05bc
	DCW	0x023d, 0x07d4, 0x0108, 0x017f, 0x09c4, 0x05b2, 0x06bf, 0x0c7f
	DCW	0x0a58, 0x03f9, 0x02dc, 0x0260, 0x06fb, 0x019b, 0x0c34, 0x06de
	DCW	0x04c7, 0x04c7, 0x04c7, 0x04c7, 0x028c, 0x028c, 0x028c, 0x028c
	DCW	0x0ad9, 0x0ad9, 0x0ad9, 0x0ad9, 0x03f7, 0x03f7, 0x03f7, 0x03f7
	DCW	0x07f4, 0x07f4, 0x07f4, 0x07f4, 0x05d3, 0x05d3, 0x05d3, 0x05d3
	DCW	0x0be7, 0x0be7, 0x0be7, 0x0be7, 0x06f9, 0x06f9, 0x06f9, 0x06f9
	DCW	0x0204, 0x0204, 0x0204, 0x0204, 0x0cf9, 0x0cf9, 0x0cf9, 0x0cf9
	DCW	0x0bc1, 0x0bc1, 0x0bc1, 0x0bc1, 0x0a67, 0x0a67, 0x0a67, 0x0a67
	DCW	0x06af, 0x06af, 0x06af, 0x06af, 0x0877, 0x0877, 0x0877, 0x0877
	DCW	0x007e, 0x007e, 0x007e, 0x007e, 0x05bd, 0x05bd, 0x05bd, 0x05bd
	DCW	0x09ac, 0x09ac, 0x09ac, 0x09ac, 0x0ca7, 0x0ca7, 0x0ca7, 0x0ca7
	DCW	0x0bf2, 0x0bf2, 0x0bf2, 0x0bf2, 0x033e, 0x033e, 0x033e, 0x033e
	DCW	0x006b, 0x006b, 0x006b, 0x006b, 0x0774, 0x0774, 0x0774, 0x0774
	DCW	0x0c0a, 0x0c0a, 0x0c0a, 0x0c0a, 0x094a, 0x094a, 0x094a, 0x094a
	DCW	0x0b73, 0x0b73, 0x0b73, 0x0b73, 0x03c1, 0x03c1, 0x03c1, 0x03c1
	DCW	0x071d, 0x071d, 0x071d, 0x071d, 0x0a2c, 0x0a2c, 0x0a2c, 0x0a2c
	DCW	0x01c0, 0x01c0, 0x01c0, 0x01c0, 0x08d8, 0x08d8, 0x08d8, 0x08d8
	DCW	0x02a5, 0x02a5, 0x02a5, 0x02a5, 0x0806, 0x0806, 0x0806, 0x0806
	DCW	0x08b2, 0x08b2, 0x01ae, 0x01ae, 0x022b, 0x022b, 0x034b, 0x034b
	DCW	0x081e, 0x081e, 0x0367, 0x0367, 0x060e, 0x060e, 0x0069, 0x0069
	DCW	0x01a6, 0x01a6, 0x024b, 0x024b, 0x00b1, 0x00b1, 0x0c16, 0x0c16
	DCW	0x0bde, 0x0bde, 0x0b35, 0x0b35, 0x0626, 0x0626, 0x0675, 0x0675
	DCW	0x0c0b, 0x0c0b, 0x030a, 0x030a, 0x0487, 0x0487, 0x0c6e, 0x0c6e
	DCW	0x09f8, 0x09f8, 0x05cb, 0x05cb, 0x0aa7, 0x0aa7, 0x045f, 0x045f
	DCW	0x06cb, 0x06cb, 0x0284, 0x0284, 0x0999, 0x0999, 0x015d, 0x015d
	DCW	0x01a2, 0x01a2, 0x0149, 0x0149, 0x0c65, 0x0c65, 0x0cb6, 0x0cb6
	DCW	0x0331, 0x0331, 0x0449, 0x0449, 0x025b, 0x025b, 0x0262, 0x0262
	DCW	0x052a, 0x052a, 0x07fc, 0x07fc, 0x0748, 0x0748, 0x0180, 0x0180
	DCW	0x0842, 0x0842, 0x0c79, 0x0c79, 0x04c2, 0x04c2, 0x07ca, 0x07ca
	DCW	0x0997, 0x0997, 0x00dc, 0x00dc, 0x085e, 0x085e, 0x0686, 0x0686
	DCW	0x0860, 0x0860, 0x0707, 0x0707, 0x0803, 0x0803, 0x031a, 0x031a
	DCW	0x071b, 0x071b, 0x09ab, 0x09ab, 0x099b, 0x099b, 0x01de, 0x01de
	DCW	0x0c95, 0x0c95, 0x0bcd, 0x0bcd, 0x03e4, 0x03e4, 0x03df, 0x03df
	DCW	0x03be, 0x03be, 0x074d, 0x074d, 0x05f2, 0x05f2, 0x065c, 0x065c
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mlkem_aarch64_zetas_qinv
	DCW	0xffed, 0x7b0b, 0x399a, 0x0314, 0x34d5, 0xcf8e, 0x6e1f, 0xbeca
	DCW	0xae56, 0x6c6e, 0xf129, 0xc2b6, 0x29c2, 0x054f, 0xd43f, 0x79bc
	DCW	0xe93d, 0x43d4, 0x9908, 0x8e7f, 0x15c4, 0xfbb2, 0x53bf, 0x997f
	DCW	0x9258, 0x5ef9, 0xd6dc, 0x2260, 0x47fb, 0x229b, 0x6834, 0xc0de
	DCW	0xe9c7, 0xe9c7, 0xe9c7, 0xe9c7, 0xe68c, 0xe68c, 0xe68c, 0xe68c
	DCW	0x05d9, 0x05d9, 0x05d9, 0x05d9, 0x78f7, 0x78f7, 0x78f7, 0x78f7
	DCW	0xa3f4, 0xa3f4, 0xa3f4, 0xa3f4, 0x4ed3, 0x4ed3, 0x4ed3, 0x4ed3
	DCW	0x50e7, 0x50e7, 0x50e7, 0x50e7, 0x61f9, 0x61f9, 0x61f9, 0x61f9
	DCW	0xce04, 0xce04, 0xce04, 0xce04, 0x67f9, 0x67f9, 0x67f9, 0x67f9
	DCW	0x3ec1, 0x3ec1, 0x3ec1, 0x3ec1, 0xcf67, 0xcf67, 0xcf67, 0xcf67
	DCW	0x23af, 0x23af, 0x23af, 0x23af, 0xfd77, 0xfd77, 0xfd77, 0xfd77
	DCW	0x9a7e, 0x9a7e, 0x9a7e, 0x9a7e, 0x6cbd, 0x6cbd, 0x6cbd, 0x6cbd
	DCW	0x4dac, 0x4dac, 0x4dac, 0x4dac, 0x91a7, 0x91a7, 0x91a7, 0x91a7
	DCW	0xc1f2, 0xc1f2, 0xc1f2, 0xc1f2, 0xdd3e, 0xdd3e, 0xdd3e, 0xdd3e
	DCW	0x916b, 0x916b, 0x916b, 0x916b, 0x2374, 0x2374, 0x2374, 0x2374
	DCW	0x8a0a, 0x8a0a, 0x8a0a, 0x8a0a, 0x474a, 0x474a, 0x474a, 0x474a
	DCW	0x3473, 0x3473, 0x3473, 0x3473, 0x36c1, 0x36c1, 0x36c1, 0x36c1
	DCW	0x8e1d, 0x8e1d, 0x8e1d, 0x8e1d, 0xce2c, 0xce2c, 0xce2c, 0xce2c
	DCW	0x41c0, 0x41c0, 0x41c0, 0x41c0, 0x10d8, 0x10d8, 0x10d8, 0x10d8
	DCW	0xa1a5, 0xa1a5, 0xa1a5, 0xa1a5, 0xba06, 0xba06, 0xba06, 0xba06
	DCW	0xfeb2, 0xfeb2, 0x2bae, 0x2bae, 0xd32b, 0xd32b, 0x344b, 0x344b
	DCW	0x821e, 0x821e, 0xc867, 0xc867, 0x500e, 0x500e, 0xab69, 0xab69
	DCW	0x93a6, 0x93a6, 0x334b, 0x334b, 0x03b1, 0x03b1, 0xee16, 0xee16
	DCW	0xc5de, 0xc5de, 0x5a35, 0x5a35, 0x1826, 0x1826, 0x1575, 0x1575
	DCW	0x7d0b, 0x7d0b, 0x810a, 0x810a, 0x2987, 0x2987, 0x766e, 0x766e
	DCW	0x71f8, 0x71f8, 0xb6cb, 0xb6cb, 0x8fa7, 0x8fa7, 0x315f, 0x315f
	DCW	0xb7cb, 0xb7cb, 0x4e84, 0x4e84, 0x4499, 0x4499, 0x485d, 0x485d
	DCW	0xc7a2, 0xc7a2, 0x4c49, 0x4c49, 0xeb65, 0xeb65, 0xceb6, 0xceb6
	DCW	0x8631, 0x8631, 0x4f49, 0x4f49, 0x635b, 0x635b, 0x0862, 0x0862
	DCW	0xe32a, 0xe32a, 0x3bfc, 0x3bfc, 0x5f48, 0x5f48, 0x8180, 0x8180
	DCW	0xae42, 0xae42, 0xe779, 0xe779, 0x2ac2, 0x2ac2, 0xc5ca, 0xc5ca
	DCW	0x5e97, 0x5e97, 0xd4dc, 0xd4dc, 0x425e, 0x425e, 0x3886, 0x3886
	DCW	0x2860, 0x2860, 0xac07, 0xac07, 0xe103, 0xe103, 0xb11a, 0xb11a
	DCW	0xa81b, 0xa81b, 0x5aab, 0x5aab, 0x2a9b, 0x2a9b, 0xbbde, 0xbbde
	DCW	0x7b95, 0x7b95, 0xa2cd, 0xa2cd, 0x6fe4, 0x6fe4, 0xb0df, 0xb0df
	DCW	0x5dbe, 0x5dbe, 0x1e4d, 0x1e4d, 0xbbf2, 0xbbf2, 0x5a5c, 0x5a5c
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mlkem_ntt
mlkem_ntt PROC
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	stp	D10, D11, [x29, #32]
	stp	D12, D13, [x29, #48]
	stp	D14, D15, [x29, #64]
	adrp	x2, L_mlkem_aarch64_zetas
	add	x2, x2, L_mlkem_aarch64_zetas
	adrp	x3, L_mlkem_aarch64_zetas_qinv
	add	x3, x3, L_mlkem_aarch64_zetas_qinv
	adrp	x4, L_mlkem_aarch64_consts
	add	x4, x4, L_mlkem_aarch64_consts
	add	x1, x0, #0x100
	ldr	Q4, [x4]
	ldr	Q5, [x0]
	ldr	Q6, [x0, #32]
	ldr	Q7, [x0, #64]
	ldr	Q8, [x0, #96]
	ldr	Q9, [x0, #128]
	ldr	Q10, [x0, #160]
	ldr	Q11, [x0, #192]
	ldr	Q12, [x0, #224]
	ldr	Q13, [x1]
	ldr	Q14, [x1, #32]
	ldr	Q15, [x1, #64]
	ldr	Q16, [x1, #96]
	ldr	Q17, [x1, #128]
	ldr	Q18, [x1, #160]
	ldr	Q19, [x1, #192]
	ldr	Q20, [x1, #224]
	ldr	Q0, [x2]
	ldr	Q1, [x3]
	mul	V29.8H, V13.8H, V1.H[1]
	mul	V30.8H, V14.8H, V1.H[1]
	sqrdmulh	V21.8H, V13.8H, V0.H[1]
	sqrdmulh	V22.8H, V14.8H, V0.H[1]
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V21.8H, V21.8H, V29.8H
	sub	V22.8H, V22.8H, V30.8H
	sshr	V21.8H, V21.8H, #1
	sshr	V22.8H, V22.8H, #1
	mul	V29.8H, V15.8H, V1.H[1]
	mul	V30.8H, V16.8H, V1.H[1]
	sqrdmulh	V23.8H, V15.8H, V0.H[1]
	sqrdmulh	V24.8H, V16.8H, V0.H[1]
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V23.8H, V23.8H, V29.8H
	sub	V24.8H, V24.8H, V30.8H
	sshr	V23.8H, V23.8H, #1
	sshr	V24.8H, V24.8H, #1
	mul	V29.8H, V17.8H, V1.H[1]
	mul	V30.8H, V18.8H, V1.H[1]
	sqrdmulh	V25.8H, V17.8H, V0.H[1]
	sqrdmulh	V26.8H, V18.8H, V0.H[1]
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V25.8H, V25.8H, V29.8H
	sub	V26.8H, V26.8H, V30.8H
	sshr	V25.8H, V25.8H, #1
	sshr	V26.8H, V26.8H, #1
	mul	V29.8H, V19.8H, V1.H[1]
	mul	V30.8H, V20.8H, V1.H[1]
	sqrdmulh	V27.8H, V19.8H, V0.H[1]
	sqrdmulh	V28.8H, V20.8H, V0.H[1]
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V27.8H, V27.8H, V29.8H
	sub	V28.8H, V28.8H, V30.8H
	sshr	V27.8H, V27.8H, #1
	sshr	V28.8H, V28.8H, #1
	sub	V13.8H, V5.8H, V21.8H
	add	V5.8H, V5.8H, V21.8H
	sub	V14.8H, V6.8H, V22.8H
	add	V6.8H, V6.8H, V22.8H
	sub	V15.8H, V7.8H, V23.8H
	add	V7.8H, V7.8H, V23.8H
	sub	V16.8H, V8.8H, V24.8H
	add	V8.8H, V8.8H, V24.8H
	sub	V17.8H, V9.8H, V25.8H
	add	V9.8H, V9.8H, V25.8H
	sub	V18.8H, V10.8H, V26.8H
	add	V10.8H, V10.8H, V26.8H
	sub	V19.8H, V11.8H, V27.8H
	add	V11.8H, V11.8H, V27.8H
	sub	V20.8H, V12.8H, V28.8H
	add	V12.8H, V12.8H, V28.8H
	mul	V29.8H, V9.8H, V1.H[2]
	mul	V30.8H, V10.8H, V1.H[2]
	sqrdmulh	V21.8H, V9.8H, V0.H[2]
	sqrdmulh	V22.8H, V10.8H, V0.H[2]
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V21.8H, V21.8H, V29.8H
	sub	V22.8H, V22.8H, V30.8H
	sshr	V21.8H, V21.8H, #1
	sshr	V22.8H, V22.8H, #1
	mul	V29.8H, V11.8H, V1.H[2]
	mul	V30.8H, V12.8H, V1.H[2]
	sqrdmulh	V23.8H, V11.8H, V0.H[2]
	sqrdmulh	V24.8H, V12.8H, V0.H[2]
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V23.8H, V23.8H, V29.8H
	sub	V24.8H, V24.8H, V30.8H
	sshr	V23.8H, V23.8H, #1
	sshr	V24.8H, V24.8H, #1
	mul	V29.8H, V17.8H, V1.H[3]
	mul	V30.8H, V18.8H, V1.H[3]
	sqrdmulh	V25.8H, V17.8H, V0.H[3]
	sqrdmulh	V26.8H, V18.8H, V0.H[3]
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V25.8H, V25.8H, V29.8H
	sub	V26.8H, V26.8H, V30.8H
	sshr	V25.8H, V25.8H, #1
	sshr	V26.8H, V26.8H, #1
	mul	V29.8H, V19.8H, V1.H[3]
	mul	V30.8H, V20.8H, V1.H[3]
	sqrdmulh	V27.8H, V19.8H, V0.H[3]
	sqrdmulh	V28.8H, V20.8H, V0.H[3]
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V27.8H, V27.8H, V29.8H
	sub	V28.8H, V28.8H, V30.8H
	sshr	V27.8H, V27.8H, #1
	sshr	V28.8H, V28.8H, #1
	sub	V9.8H, V5.8H, V21.8H
	add	V5.8H, V5.8H, V21.8H
	sub	V10.8H, V6.8H, V22.8H
	add	V6.8H, V6.8H, V22.8H
	sub	V11.8H, V7.8H, V23.8H
	add	V7.8H, V7.8H, V23.8H
	sub	V12.8H, V8.8H, V24.8H
	add	V8.8H, V8.8H, V24.8H
	sub	V17.8H, V13.8H, V25.8H
	add	V13.8H, V13.8H, V25.8H
	sub	V18.8H, V14.8H, V26.8H
	add	V14.8H, V14.8H, V26.8H
	sub	V19.8H, V15.8H, V27.8H
	add	V15.8H, V15.8H, V27.8H
	sub	V20.8H, V16.8H, V28.8H
	add	V16.8H, V16.8H, V28.8H
	mul	V29.8H, V7.8H, V1.H[4]
	mul	V30.8H, V8.8H, V1.H[4]
	sqrdmulh	V21.8H, V7.8H, V0.H[4]
	sqrdmulh	V22.8H, V8.8H, V0.H[4]
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V21.8H, V21.8H, V29.8H
	sub	V22.8H, V22.8H, V30.8H
	sshr	V21.8H, V21.8H, #1
	sshr	V22.8H, V22.8H, #1
	mul	V29.8H, V11.8H, V1.H[5]
	mul	V30.8H, V12.8H, V1.H[5]
	sqrdmulh	V23.8H, V11.8H, V0.H[5]
	sqrdmulh	V24.8H, V12.8H, V0.H[5]
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V23.8H, V23.8H, V29.8H
	sub	V24.8H, V24.8H, V30.8H
	sshr	V23.8H, V23.8H, #1
	sshr	V24.8H, V24.8H, #1
	mul	V29.8H, V15.8H, V1.H[6]
	mul	V30.8H, V16.8H, V1.H[6]
	sqrdmulh	V25.8H, V15.8H, V0.H[6]
	sqrdmulh	V26.8H, V16.8H, V0.H[6]
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V25.8H, V25.8H, V29.8H
	sub	V26.8H, V26.8H, V30.8H
	sshr	V25.8H, V25.8H, #1
	sshr	V26.8H, V26.8H, #1
	mul	V29.8H, V19.8H, V1.H[7]
	mul	V30.8H, V20.8H, V1.H[7]
	sqrdmulh	V27.8H, V19.8H, V0.H[7]
	sqrdmulh	V28.8H, V20.8H, V0.H[7]
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V27.8H, V27.8H, V29.8H
	sub	V28.8H, V28.8H, V30.8H
	sshr	V27.8H, V27.8H, #1
	sshr	V28.8H, V28.8H, #1
	sub	V7.8H, V5.8H, V21.8H
	add	V5.8H, V5.8H, V21.8H
	sub	V8.8H, V6.8H, V22.8H
	add	V6.8H, V6.8H, V22.8H
	sub	V11.8H, V9.8H, V23.8H
	add	V9.8H, V9.8H, V23.8H
	sub	V12.8H, V10.8H, V24.8H
	add	V10.8H, V10.8H, V24.8H
	sub	V15.8H, V13.8H, V25.8H
	add	V13.8H, V13.8H, V25.8H
	sub	V16.8H, V14.8H, V26.8H
	add	V14.8H, V14.8H, V26.8H
	sub	V19.8H, V17.8H, V27.8H
	add	V17.8H, V17.8H, V27.8H
	sub	V20.8H, V18.8H, V28.8H
	add	V18.8H, V18.8H, V28.8H
	ldr	Q0, [x2, #16]
	ldr	Q1, [x3, #16]
	mul	V29.8H, V6.8H, V1.H[0]
	mul	V30.8H, V8.8H, V1.H[1]
	sqrdmulh	V21.8H, V6.8H, V0.H[0]
	sqrdmulh	V22.8H, V8.8H, V0.H[1]
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V21.8H, V21.8H, V29.8H
	sub	V22.8H, V22.8H, V30.8H
	sshr	V21.8H, V21.8H, #1
	sshr	V22.8H, V22.8H, #1
	mul	V29.8H, V10.8H, V1.H[2]
	mul	V30.8H, V12.8H, V1.H[3]
	sqrdmulh	V23.8H, V10.8H, V0.H[2]
	sqrdmulh	V24.8H, V12.8H, V0.H[3]
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V23.8H, V23.8H, V29.8H
	sub	V24.8H, V24.8H, V30.8H
	sshr	V23.8H, V23.8H, #1
	sshr	V24.8H, V24.8H, #1
	mul	V29.8H, V14.8H, V1.H[4]
	mul	V30.8H, V16.8H, V1.H[5]
	sqrdmulh	V25.8H, V14.8H, V0.H[4]
	sqrdmulh	V26.8H, V16.8H, V0.H[5]
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V25.8H, V25.8H, V29.8H
	sub	V26.8H, V26.8H, V30.8H
	sshr	V25.8H, V25.8H, #1
	sshr	V26.8H, V26.8H, #1
	mul	V29.8H, V18.8H, V1.H[6]
	mul	V30.8H, V20.8H, V1.H[7]
	sqrdmulh	V27.8H, V18.8H, V0.H[6]
	sqrdmulh	V28.8H, V20.8H, V0.H[7]
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V27.8H, V27.8H, V29.8H
	sub	V28.8H, V28.8H, V30.8H
	sshr	V27.8H, V27.8H, #1
	sshr	V28.8H, V28.8H, #1
	sub	V6.8H, V5.8H, V21.8H
	add	V5.8H, V5.8H, V21.8H
	sub	V8.8H, V7.8H, V22.8H
	add	V7.8H, V7.8H, V22.8H
	sub	V10.8H, V9.8H, V23.8H
	add	V9.8H, V9.8H, V23.8H
	sub	V12.8H, V11.8H, V24.8H
	add	V11.8H, V11.8H, V24.8H
	sub	V14.8H, V13.8H, V25.8H
	add	V13.8H, V13.8H, V25.8H
	sub	V16.8H, V15.8H, V26.8H
	add	V15.8H, V15.8H, V26.8H
	sub	V18.8H, V17.8H, V27.8H
	add	V17.8H, V17.8H, V27.8H
	sub	V20.8H, V19.8H, V28.8H
	add	V19.8H, V19.8H, V28.8H
	str	Q5, [x0]
	str	Q6, [x0, #32]
	str	Q7, [x0, #64]
	str	Q8, [x0, #96]
	str	Q9, [x0, #128]
	str	Q10, [x0, #160]
	str	Q11, [x0, #192]
	str	Q12, [x0, #224]
	str	Q13, [x1]
	str	Q14, [x1, #32]
	str	Q15, [x1, #64]
	str	Q16, [x1, #96]
	str	Q17, [x1, #128]
	str	Q18, [x1, #160]
	str	Q19, [x1, #192]
	str	Q20, [x1, #224]
	ldr	Q5, [x0, #16]
	ldr	Q6, [x0, #48]
	ldr	Q7, [x0, #80]
	ldr	Q8, [x0, #112]
	ldr	Q9, [x0, #144]
	ldr	Q10, [x0, #176]
	ldr	Q11, [x0, #208]
	ldr	Q12, [x0, #240]
	ldr	Q13, [x1, #16]
	ldr	Q14, [x1, #48]
	ldr	Q15, [x1, #80]
	ldr	Q16, [x1, #112]
	ldr	Q17, [x1, #144]
	ldr	Q18, [x1, #176]
	ldr	Q19, [x1, #208]
	ldr	Q20, [x1, #240]
	ldr	Q0, [x2]
	ldr	Q1, [x3]
	mul	V29.8H, V13.8H, V1.H[1]
	mul	V30.8H, V14.8H, V1.H[1]
	sqrdmulh	V21.8H, V13.8H, V0.H[1]
	sqrdmulh	V22.8H, V14.8H, V0.H[1]
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V21.8H, V21.8H, V29.8H
	sub	V22.8H, V22.8H, V30.8H
	sshr	V21.8H, V21.8H, #1
	sshr	V22.8H, V22.8H, #1
	mul	V29.8H, V15.8H, V1.H[1]
	mul	V30.8H, V16.8H, V1.H[1]
	sqrdmulh	V23.8H, V15.8H, V0.H[1]
	sqrdmulh	V24.8H, V16.8H, V0.H[1]
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V23.8H, V23.8H, V29.8H
	sub	V24.8H, V24.8H, V30.8H
	sshr	V23.8H, V23.8H, #1
	sshr	V24.8H, V24.8H, #1
	mul	V29.8H, V17.8H, V1.H[1]
	mul	V30.8H, V18.8H, V1.H[1]
	sqrdmulh	V25.8H, V17.8H, V0.H[1]
	sqrdmulh	V26.8H, V18.8H, V0.H[1]
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V25.8H, V25.8H, V29.8H
	sub	V26.8H, V26.8H, V30.8H
	sshr	V25.8H, V25.8H, #1
	sshr	V26.8H, V26.8H, #1
	mul	V29.8H, V19.8H, V1.H[1]
	mul	V30.8H, V20.8H, V1.H[1]
	sqrdmulh	V27.8H, V19.8H, V0.H[1]
	sqrdmulh	V28.8H, V20.8H, V0.H[1]
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V27.8H, V27.8H, V29.8H
	sub	V28.8H, V28.8H, V30.8H
	sshr	V27.8H, V27.8H, #1
	sshr	V28.8H, V28.8H, #1
	sub	V13.8H, V5.8H, V21.8H
	add	V5.8H, V5.8H, V21.8H
	sub	V14.8H, V6.8H, V22.8H
	add	V6.8H, V6.8H, V22.8H
	sub	V15.8H, V7.8H, V23.8H
	add	V7.8H, V7.8H, V23.8H
	sub	V16.8H, V8.8H, V24.8H
	add	V8.8H, V8.8H, V24.8H
	sub	V17.8H, V9.8H, V25.8H
	add	V9.8H, V9.8H, V25.8H
	sub	V18.8H, V10.8H, V26.8H
	add	V10.8H, V10.8H, V26.8H
	sub	V19.8H, V11.8H, V27.8H
	add	V11.8H, V11.8H, V27.8H
	sub	V20.8H, V12.8H, V28.8H
	add	V12.8H, V12.8H, V28.8H
	mul	V29.8H, V9.8H, V1.H[2]
	mul	V30.8H, V10.8H, V1.H[2]
	sqrdmulh	V21.8H, V9.8H, V0.H[2]
	sqrdmulh	V22.8H, V10.8H, V0.H[2]
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V21.8H, V21.8H, V29.8H
	sub	V22.8H, V22.8H, V30.8H
	sshr	V21.8H, V21.8H, #1
	sshr	V22.8H, V22.8H, #1
	mul	V29.8H, V11.8H, V1.H[2]
	mul	V30.8H, V12.8H, V1.H[2]
	sqrdmulh	V23.8H, V11.8H, V0.H[2]
	sqrdmulh	V24.8H, V12.8H, V0.H[2]
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V23.8H, V23.8H, V29.8H
	sub	V24.8H, V24.8H, V30.8H
	sshr	V23.8H, V23.8H, #1
	sshr	V24.8H, V24.8H, #1
	mul	V29.8H, V17.8H, V1.H[3]
	mul	V30.8H, V18.8H, V1.H[3]
	sqrdmulh	V25.8H, V17.8H, V0.H[3]
	sqrdmulh	V26.8H, V18.8H, V0.H[3]
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V25.8H, V25.8H, V29.8H
	sub	V26.8H, V26.8H, V30.8H
	sshr	V25.8H, V25.8H, #1
	sshr	V26.8H, V26.8H, #1
	mul	V29.8H, V19.8H, V1.H[3]
	mul	V30.8H, V20.8H, V1.H[3]
	sqrdmulh	V27.8H, V19.8H, V0.H[3]
	sqrdmulh	V28.8H, V20.8H, V0.H[3]
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V27.8H, V27.8H, V29.8H
	sub	V28.8H, V28.8H, V30.8H
	sshr	V27.8H, V27.8H, #1
	sshr	V28.8H, V28.8H, #1
	sub	V9.8H, V5.8H, V21.8H
	add	V5.8H, V5.8H, V21.8H
	sub	V10.8H, V6.8H, V22.8H
	add	V6.8H, V6.8H, V22.8H
	sub	V11.8H, V7.8H, V23.8H
	add	V7.8H, V7.8H, V23.8H
	sub	V12.8H, V8.8H, V24.8H
	add	V8.8H, V8.8H, V24.8H
	sub	V17.8H, V13.8H, V25.8H
	add	V13.8H, V13.8H, V25.8H
	sub	V18.8H, V14.8H, V26.8H
	add	V14.8H, V14.8H, V26.8H
	sub	V19.8H, V15.8H, V27.8H
	add	V15.8H, V15.8H, V27.8H
	sub	V20.8H, V16.8H, V28.8H
	add	V16.8H, V16.8H, V28.8H
	mul	V29.8H, V7.8H, V1.H[4]
	mul	V30.8H, V8.8H, V1.H[4]
	sqrdmulh	V21.8H, V7.8H, V0.H[4]
	sqrdmulh	V22.8H, V8.8H, V0.H[4]
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V21.8H, V21.8H, V29.8H
	sub	V22.8H, V22.8H, V30.8H
	sshr	V21.8H, V21.8H, #1
	sshr	V22.8H, V22.8H, #1
	mul	V29.8H, V11.8H, V1.H[5]
	mul	V30.8H, V12.8H, V1.H[5]
	sqrdmulh	V23.8H, V11.8H, V0.H[5]
	sqrdmulh	V24.8H, V12.8H, V0.H[5]
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V23.8H, V23.8H, V29.8H
	sub	V24.8H, V24.8H, V30.8H
	sshr	V23.8H, V23.8H, #1
	sshr	V24.8H, V24.8H, #1
	mul	V29.8H, V15.8H, V1.H[6]
	mul	V30.8H, V16.8H, V1.H[6]
	sqrdmulh	V25.8H, V15.8H, V0.H[6]
	sqrdmulh	V26.8H, V16.8H, V0.H[6]
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V25.8H, V25.8H, V29.8H
	sub	V26.8H, V26.8H, V30.8H
	sshr	V25.8H, V25.8H, #1
	sshr	V26.8H, V26.8H, #1
	mul	V29.8H, V19.8H, V1.H[7]
	mul	V30.8H, V20.8H, V1.H[7]
	sqrdmulh	V27.8H, V19.8H, V0.H[7]
	sqrdmulh	V28.8H, V20.8H, V0.H[7]
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V27.8H, V27.8H, V29.8H
	sub	V28.8H, V28.8H, V30.8H
	sshr	V27.8H, V27.8H, #1
	sshr	V28.8H, V28.8H, #1
	sub	V7.8H, V5.8H, V21.8H
	add	V5.8H, V5.8H, V21.8H
	sub	V8.8H, V6.8H, V22.8H
	add	V6.8H, V6.8H, V22.8H
	sub	V11.8H, V9.8H, V23.8H
	add	V9.8H, V9.8H, V23.8H
	sub	V12.8H, V10.8H, V24.8H
	add	V10.8H, V10.8H, V24.8H
	sub	V15.8H, V13.8H, V25.8H
	add	V13.8H, V13.8H, V25.8H
	sub	V16.8H, V14.8H, V26.8H
	add	V14.8H, V14.8H, V26.8H
	sub	V19.8H, V17.8H, V27.8H
	add	V17.8H, V17.8H, V27.8H
	sub	V20.8H, V18.8H, V28.8H
	add	V18.8H, V18.8H, V28.8H
	ldr	Q0, [x2, #16]
	ldr	Q1, [x3, #16]
	mul	V29.8H, V6.8H, V1.H[0]
	mul	V30.8H, V8.8H, V1.H[1]
	sqrdmulh	V21.8H, V6.8H, V0.H[0]
	sqrdmulh	V22.8H, V8.8H, V0.H[1]
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V21.8H, V21.8H, V29.8H
	sub	V22.8H, V22.8H, V30.8H
	sshr	V21.8H, V21.8H, #1
	sshr	V22.8H, V22.8H, #1
	mul	V29.8H, V10.8H, V1.H[2]
	mul	V30.8H, V12.8H, V1.H[3]
	sqrdmulh	V23.8H, V10.8H, V0.H[2]
	sqrdmulh	V24.8H, V12.8H, V0.H[3]
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V23.8H, V23.8H, V29.8H
	sub	V24.8H, V24.8H, V30.8H
	sshr	V23.8H, V23.8H, #1
	sshr	V24.8H, V24.8H, #1
	mul	V29.8H, V14.8H, V1.H[4]
	mul	V30.8H, V16.8H, V1.H[5]
	sqrdmulh	V25.8H, V14.8H, V0.H[4]
	sqrdmulh	V26.8H, V16.8H, V0.H[5]
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V25.8H, V25.8H, V29.8H
	sub	V26.8H, V26.8H, V30.8H
	sshr	V25.8H, V25.8H, #1
	sshr	V26.8H, V26.8H, #1
	mul	V29.8H, V18.8H, V1.H[6]
	mul	V30.8H, V20.8H, V1.H[7]
	sqrdmulh	V27.8H, V18.8H, V0.H[6]
	sqrdmulh	V28.8H, V20.8H, V0.H[7]
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V27.8H, V27.8H, V29.8H
	sub	V28.8H, V28.8H, V30.8H
	sshr	V27.8H, V27.8H, #1
	sshr	V28.8H, V28.8H, #1
	sub	V6.8H, V5.8H, V21.8H
	add	V5.8H, V5.8H, V21.8H
	sub	V8.8H, V7.8H, V22.8H
	add	V7.8H, V7.8H, V22.8H
	sub	V10.8H, V9.8H, V23.8H
	add	V9.8H, V9.8H, V23.8H
	sub	V12.8H, V11.8H, V24.8H
	add	V11.8H, V11.8H, V24.8H
	sub	V14.8H, V13.8H, V25.8H
	add	V13.8H, V13.8H, V25.8H
	sub	V16.8H, V15.8H, V26.8H
	add	V15.8H, V15.8H, V26.8H
	sub	V18.8H, V17.8H, V27.8H
	add	V17.8H, V17.8H, V27.8H
	sub	V20.8H, V19.8H, V28.8H
	add	V19.8H, V19.8H, V28.8H
	str	Q5, [x0, #16]
	str	Q6, [x0, #48]
	str	Q7, [x0, #80]
	str	Q8, [x0, #112]
	str	Q9, [x0, #144]
	str	Q10, [x0, #176]
	str	Q11, [x0, #208]
	str	Q12, [x0, #240]
	str	Q13, [x1, #16]
	str	Q14, [x1, #48]
	str	Q15, [x1, #80]
	str	Q16, [x1, #112]
	str	Q17, [x1, #144]
	str	Q18, [x1, #176]
	str	Q19, [x1, #208]
	str	Q20, [x1, #240]
	ldp	Q5, Q6, [x0]
	ldp	Q7, Q8, [x0, #32]
	ldp	Q9, Q10, [x0, #64]
	ldp	Q11, Q12, [x0, #96]
	ldp	Q13, Q14, [x0, #128]
	ldp	Q15, Q16, [x0, #160]
	ldp	Q17, Q18, [x0, #192]
	ldp	Q19, Q20, [x0, #224]
	ldr	Q0, [x2, #32]
	ldr	Q1, [x3, #32]
	mul	V29.8H, V6.8H, V1.H[0]
	mul	V30.8H, V8.8H, V1.H[1]
	sqrdmulh	V21.8H, V6.8H, V0.H[0]
	sqrdmulh	V22.8H, V8.8H, V0.H[1]
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V21.8H, V21.8H, V29.8H
	sub	V22.8H, V22.8H, V30.8H
	sshr	V21.8H, V21.8H, #1
	sshr	V22.8H, V22.8H, #1
	mul	V29.8H, V10.8H, V1.H[2]
	mul	V30.8H, V12.8H, V1.H[3]
	sqrdmulh	V23.8H, V10.8H, V0.H[2]
	sqrdmulh	V24.8H, V12.8H, V0.H[3]
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V23.8H, V23.8H, V29.8H
	sub	V24.8H, V24.8H, V30.8H
	sshr	V23.8H, V23.8H, #1
	sshr	V24.8H, V24.8H, #1
	mul	V29.8H, V14.8H, V1.H[4]
	mul	V30.8H, V16.8H, V1.H[5]
	sqrdmulh	V25.8H, V14.8H, V0.H[4]
	sqrdmulh	V26.8H, V16.8H, V0.H[5]
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V25.8H, V25.8H, V29.8H
	sub	V26.8H, V26.8H, V30.8H
	sshr	V25.8H, V25.8H, #1
	sshr	V26.8H, V26.8H, #1
	mul	V29.8H, V18.8H, V1.H[6]
	mul	V30.8H, V20.8H, V1.H[7]
	sqrdmulh	V27.8H, V18.8H, V0.H[6]
	sqrdmulh	V28.8H, V20.8H, V0.H[7]
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V27.8H, V27.8H, V29.8H
	sub	V28.8H, V28.8H, V30.8H
	sshr	V27.8H, V27.8H, #1
	sshr	V28.8H, V28.8H, #1
	sub	V6.8H, V5.8H, V21.8H
	add	V5.8H, V5.8H, V21.8H
	sub	V8.8H, V7.8H, V22.8H
	add	V7.8H, V7.8H, V22.8H
	sub	V10.8H, V9.8H, V23.8H
	add	V9.8H, V9.8H, V23.8H
	sub	V12.8H, V11.8H, V24.8H
	add	V11.8H, V11.8H, V24.8H
	sub	V14.8H, V13.8H, V25.8H
	add	V13.8H, V13.8H, V25.8H
	sub	V16.8H, V15.8H, V26.8H
	add	V15.8H, V15.8H, V26.8H
	sub	V18.8H, V17.8H, V27.8H
	add	V17.8H, V17.8H, V27.8H
	sub	V20.8H, V19.8H, V28.8H
	add	V19.8H, V19.8H, V28.8H
	ldr	Q0, [x2, #64]
	ldr	Q2, [x2, #80]
	ldr	Q1, [x3, #64]
	ldr	Q3, [x3, #80]
	mov	V29.16B, V5.16B
	mov	V30.16B, V7.16B
	trn1	V5.2D, V5.2D, V6.2D
	trn1	V7.2D, V7.2D, V8.2D
	trn2	V6.2D, V29.2D, V6.2D
	trn2	V8.2D, V30.2D, V8.2D
	mul	V29.8H, V6.8H, V1.8H
	mul	V30.8H, V8.8H, V3.8H
	sqrdmulh	V21.8H, V6.8H, V0.8H
	sqrdmulh	V22.8H, V8.8H, V2.8H
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V21.8H, V21.8H, V29.8H
	sub	V22.8H, V22.8H, V30.8H
	sshr	V21.8H, V21.8H, #1
	sshr	V22.8H, V22.8H, #1
	ldr	Q0, [x2, #96]
	ldr	Q2, [x2, #112]
	ldr	Q1, [x3, #96]
	ldr	Q3, [x3, #112]
	mov	V29.16B, V9.16B
	mov	V30.16B, V11.16B
	trn1	V9.2D, V9.2D, V10.2D
	trn1	V11.2D, V11.2D, V12.2D
	trn2	V10.2D, V29.2D, V10.2D
	trn2	V12.2D, V30.2D, V12.2D
	mul	V29.8H, V10.8H, V1.8H
	mul	V30.8H, V12.8H, V3.8H
	sqrdmulh	V23.8H, V10.8H, V0.8H
	sqrdmulh	V24.8H, V12.8H, V2.8H
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V23.8H, V23.8H, V29.8H
	sub	V24.8H, V24.8H, V30.8H
	sshr	V23.8H, V23.8H, #1
	sshr	V24.8H, V24.8H, #1
	ldr	Q0, [x2, #128]
	ldr	Q2, [x2, #144]
	ldr	Q1, [x3, #128]
	ldr	Q3, [x3, #144]
	mov	V29.16B, V13.16B
	mov	V30.16B, V15.16B
	trn1	V13.2D, V13.2D, V14.2D
	trn1	V15.2D, V15.2D, V16.2D
	trn2	V14.2D, V29.2D, V14.2D
	trn2	V16.2D, V30.2D, V16.2D
	mul	V29.8H, V14.8H, V1.8H
	mul	V30.8H, V16.8H, V3.8H
	sqrdmulh	V25.8H, V14.8H, V0.8H
	sqrdmulh	V26.8H, V16.8H, V2.8H
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V25.8H, V25.8H, V29.8H
	sub	V26.8H, V26.8H, V30.8H
	sshr	V25.8H, V25.8H, #1
	sshr	V26.8H, V26.8H, #1
	ldr	Q0, [x2, #160]
	ldr	Q2, [x2, #176]
	ldr	Q1, [x3, #160]
	ldr	Q3, [x3, #176]
	mov	V29.16B, V17.16B
	mov	V30.16B, V19.16B
	trn1	V17.2D, V17.2D, V18.2D
	trn1	V19.2D, V19.2D, V20.2D
	trn2	V18.2D, V29.2D, V18.2D
	trn2	V20.2D, V30.2D, V20.2D
	mul	V29.8H, V18.8H, V1.8H
	mul	V30.8H, V20.8H, V3.8H
	sqrdmulh	V27.8H, V18.8H, V0.8H
	sqrdmulh	V28.8H, V20.8H, V2.8H
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V27.8H, V27.8H, V29.8H
	sub	V28.8H, V28.8H, V30.8H
	sshr	V27.8H, V27.8H, #1
	sshr	V28.8H, V28.8H, #1
	sub	V6.8H, V5.8H, V21.8H
	add	V5.8H, V5.8H, V21.8H
	sub	V8.8H, V7.8H, V22.8H
	add	V7.8H, V7.8H, V22.8H
	sub	V10.8H, V9.8H, V23.8H
	add	V9.8H, V9.8H, V23.8H
	sub	V12.8H, V11.8H, V24.8H
	add	V11.8H, V11.8H, V24.8H
	sub	V14.8H, V13.8H, V25.8H
	add	V13.8H, V13.8H, V25.8H
	sub	V16.8H, V15.8H, V26.8H
	add	V15.8H, V15.8H, V26.8H
	sub	V18.8H, V17.8H, V27.8H
	add	V17.8H, V17.8H, V27.8H
	sub	V20.8H, V19.8H, V28.8H
	add	V19.8H, V19.8H, V28.8H
	ldr	Q0, [x2, #320]
	ldr	Q2, [x2, #336]
	ldr	Q1, [x3, #320]
	ldr	Q3, [x3, #336]
	mov	V29.16B, V5.16B
	mov	V30.16B, V7.16B
	trn1	V5.4S, V5.4S, V6.4S
	trn1	V7.4S, V7.4S, V8.4S
	trn2	V6.4S, V29.4S, V6.4S
	trn2	V8.4S, V30.4S, V8.4S
	mul	V29.8H, V6.8H, V1.8H
	mul	V30.8H, V8.8H, V3.8H
	sqrdmulh	V21.8H, V6.8H, V0.8H
	sqrdmulh	V22.8H, V8.8H, V2.8H
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V21.8H, V21.8H, V29.8H
	sub	V22.8H, V22.8H, V30.8H
	sshr	V21.8H, V21.8H, #1
	sshr	V22.8H, V22.8H, #1
	ldr	Q0, [x2, #352]
	ldr	Q2, [x2, #368]
	ldr	Q1, [x3, #352]
	ldr	Q3, [x3, #368]
	mov	V29.16B, V9.16B
	mov	V30.16B, V11.16B
	trn1	V9.4S, V9.4S, V10.4S
	trn1	V11.4S, V11.4S, V12.4S
	trn2	V10.4S, V29.4S, V10.4S
	trn2	V12.4S, V30.4S, V12.4S
	mul	V29.8H, V10.8H, V1.8H
	mul	V30.8H, V12.8H, V3.8H
	sqrdmulh	V23.8H, V10.8H, V0.8H
	sqrdmulh	V24.8H, V12.8H, V2.8H
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V23.8H, V23.8H, V29.8H
	sub	V24.8H, V24.8H, V30.8H
	sshr	V23.8H, V23.8H, #1
	sshr	V24.8H, V24.8H, #1
	ldr	Q0, [x2, #384]
	ldr	Q2, [x2, #400]
	ldr	Q1, [x3, #384]
	ldr	Q3, [x3, #400]
	mov	V29.16B, V13.16B
	mov	V30.16B, V15.16B
	trn1	V13.4S, V13.4S, V14.4S
	trn1	V15.4S, V15.4S, V16.4S
	trn2	V14.4S, V29.4S, V14.4S
	trn2	V16.4S, V30.4S, V16.4S
	mul	V29.8H, V14.8H, V1.8H
	mul	V30.8H, V16.8H, V3.8H
	sqrdmulh	V25.8H, V14.8H, V0.8H
	sqrdmulh	V26.8H, V16.8H, V2.8H
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V25.8H, V25.8H, V29.8H
	sub	V26.8H, V26.8H, V30.8H
	sshr	V25.8H, V25.8H, #1
	sshr	V26.8H, V26.8H, #1
	ldr	Q0, [x2, #416]
	ldr	Q2, [x2, #432]
	ldr	Q1, [x3, #416]
	ldr	Q3, [x3, #432]
	mov	V29.16B, V17.16B
	mov	V30.16B, V19.16B
	trn1	V17.4S, V17.4S, V18.4S
	trn1	V19.4S, V19.4S, V20.4S
	trn2	V18.4S, V29.4S, V18.4S
	trn2	V20.4S, V30.4S, V20.4S
	mul	V29.8H, V18.8H, V1.8H
	mul	V30.8H, V20.8H, V3.8H
	sqrdmulh	V27.8H, V18.8H, V0.8H
	sqrdmulh	V28.8H, V20.8H, V2.8H
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V27.8H, V27.8H, V29.8H
	sub	V28.8H, V28.8H, V30.8H
	sshr	V27.8H, V27.8H, #1
	sshr	V28.8H, V28.8H, #1
	sub	V6.8H, V5.8H, V21.8H
	add	V5.8H, V5.8H, V21.8H
	sub	V8.8H, V7.8H, V22.8H
	add	V7.8H, V7.8H, V22.8H
	sub	V10.8H, V9.8H, V23.8H
	add	V9.8H, V9.8H, V23.8H
	sub	V12.8H, V11.8H, V24.8H
	add	V11.8H, V11.8H, V24.8H
	sub	V14.8H, V13.8H, V25.8H
	add	V13.8H, V13.8H, V25.8H
	sub	V16.8H, V15.8H, V26.8H
	add	V15.8H, V15.8H, V26.8H
	sub	V18.8H, V17.8H, V27.8H
	add	V17.8H, V17.8H, V27.8H
	sub	V20.8H, V19.8H, V28.8H
	add	V19.8H, V19.8H, V28.8H
	sqdmulh	V21.8H, V5.8H, V4.H[2]
	sqdmulh	V22.8H, V6.8H, V4.H[2]
	sshr	V21.8H, V21.8H, #11
	sshr	V22.8H, V22.8H, #11
	mls	V5.8H, V21.8H, V4.H[0]
	mls	V6.8H, V22.8H, V4.H[0]
	sqdmulh	V21.8H, V7.8H, V4.H[2]
	sqdmulh	V22.8H, V8.8H, V4.H[2]
	sshr	V21.8H, V21.8H, #11
	sshr	V22.8H, V22.8H, #11
	mls	V7.8H, V21.8H, V4.H[0]
	mls	V8.8H, V22.8H, V4.H[0]
	sqdmulh	V21.8H, V9.8H, V4.H[2]
	sqdmulh	V22.8H, V10.8H, V4.H[2]
	sshr	V21.8H, V21.8H, #11
	sshr	V22.8H, V22.8H, #11
	mls	V9.8H, V21.8H, V4.H[0]
	mls	V10.8H, V22.8H, V4.H[0]
	sqdmulh	V21.8H, V11.8H, V4.H[2]
	sqdmulh	V22.8H, V12.8H, V4.H[2]
	sshr	V21.8H, V21.8H, #11
	sshr	V22.8H, V22.8H, #11
	mls	V11.8H, V21.8H, V4.H[0]
	mls	V12.8H, V22.8H, V4.H[0]
	sqdmulh	V21.8H, V13.8H, V4.H[2]
	sqdmulh	V22.8H, V14.8H, V4.H[2]
	sshr	V21.8H, V21.8H, #11
	sshr	V22.8H, V22.8H, #11
	mls	V13.8H, V21.8H, V4.H[0]
	mls	V14.8H, V22.8H, V4.H[0]
	sqdmulh	V21.8H, V15.8H, V4.H[2]
	sqdmulh	V22.8H, V16.8H, V4.H[2]
	sshr	V21.8H, V21.8H, #11
	sshr	V22.8H, V22.8H, #11
	mls	V15.8H, V21.8H, V4.H[0]
	mls	V16.8H, V22.8H, V4.H[0]
	sqdmulh	V21.8H, V17.8H, V4.H[2]
	sqdmulh	V22.8H, V18.8H, V4.H[2]
	sshr	V21.8H, V21.8H, #11
	sshr	V22.8H, V22.8H, #11
	mls	V17.8H, V21.8H, V4.H[0]
	mls	V18.8H, V22.8H, V4.H[0]
	sqdmulh	V21.8H, V19.8H, V4.H[2]
	sqdmulh	V22.8H, V20.8H, V4.H[2]
	sshr	V21.8H, V21.8H, #11
	sshr	V22.8H, V22.8H, #11
	mls	V19.8H, V21.8H, V4.H[0]
	mls	V20.8H, V22.8H, V4.H[0]
	mov	V29.16B, V5.16B
	trn1	V5.4S, V5.4S, V6.4S
	trn2	V6.4S, V29.4S, V6.4S
	mov	V29.16B, V5.16B
	trn1	V5.2D, V5.2D, V6.2D
	trn2	V6.2D, V29.2D, V6.2D
	mov	V29.16B, V7.16B
	trn1	V7.4S, V7.4S, V8.4S
	trn2	V8.4S, V29.4S, V8.4S
	mov	V29.16B, V7.16B
	trn1	V7.2D, V7.2D, V8.2D
	trn2	V8.2D, V29.2D, V8.2D
	mov	V29.16B, V9.16B
	trn1	V9.4S, V9.4S, V10.4S
	trn2	V10.4S, V29.4S, V10.4S
	mov	V29.16B, V9.16B
	trn1	V9.2D, V9.2D, V10.2D
	trn2	V10.2D, V29.2D, V10.2D
	mov	V29.16B, V11.16B
	trn1	V11.4S, V11.4S, V12.4S
	trn2	V12.4S, V29.4S, V12.4S
	mov	V29.16B, V11.16B
	trn1	V11.2D, V11.2D, V12.2D
	trn2	V12.2D, V29.2D, V12.2D
	mov	V29.16B, V13.16B
	trn1	V13.4S, V13.4S, V14.4S
	trn2	V14.4S, V29.4S, V14.4S
	mov	V29.16B, V13.16B
	trn1	V13.2D, V13.2D, V14.2D
	trn2	V14.2D, V29.2D, V14.2D
	mov	V29.16B, V15.16B
	trn1	V15.4S, V15.4S, V16.4S
	trn2	V16.4S, V29.4S, V16.4S
	mov	V29.16B, V15.16B
	trn1	V15.2D, V15.2D, V16.2D
	trn2	V16.2D, V29.2D, V16.2D
	mov	V29.16B, V17.16B
	trn1	V17.4S, V17.4S, V18.4S
	trn2	V18.4S, V29.4S, V18.4S
	mov	V29.16B, V17.16B
	trn1	V17.2D, V17.2D, V18.2D
	trn2	V18.2D, V29.2D, V18.2D
	mov	V29.16B, V19.16B
	trn1	V19.4S, V19.4S, V20.4S
	trn2	V20.4S, V29.4S, V20.4S
	mov	V29.16B, V19.16B
	trn1	V19.2D, V19.2D, V20.2D
	trn2	V20.2D, V29.2D, V20.2D
	stp	Q5, Q6, [x0]
	stp	Q7, Q8, [x0, #32]
	stp	Q9, Q10, [x0, #64]
	stp	Q11, Q12, [x0, #96]
	stp	Q13, Q14, [x0, #128]
	stp	Q15, Q16, [x0, #160]
	stp	Q17, Q18, [x0, #192]
	stp	Q19, Q20, [x0, #224]
	ldp	Q5, Q6, [x1]
	ldp	Q7, Q8, [x1, #32]
	ldp	Q9, Q10, [x1, #64]
	ldp	Q11, Q12, [x1, #96]
	ldp	Q13, Q14, [x1, #128]
	ldp	Q15, Q16, [x1, #160]
	ldp	Q17, Q18, [x1, #192]
	ldp	Q19, Q20, [x1, #224]
	ldr	Q0, [x2, #48]
	ldr	Q1, [x3, #48]
	mul	V29.8H, V6.8H, V1.H[0]
	mul	V30.8H, V8.8H, V1.H[1]
	sqrdmulh	V21.8H, V6.8H, V0.H[0]
	sqrdmulh	V22.8H, V8.8H, V0.H[1]
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V21.8H, V21.8H, V29.8H
	sub	V22.8H, V22.8H, V30.8H
	sshr	V21.8H, V21.8H, #1
	sshr	V22.8H, V22.8H, #1
	mul	V29.8H, V10.8H, V1.H[2]
	mul	V30.8H, V12.8H, V1.H[3]
	sqrdmulh	V23.8H, V10.8H, V0.H[2]
	sqrdmulh	V24.8H, V12.8H, V0.H[3]
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V23.8H, V23.8H, V29.8H
	sub	V24.8H, V24.8H, V30.8H
	sshr	V23.8H, V23.8H, #1
	sshr	V24.8H, V24.8H, #1
	mul	V29.8H, V14.8H, V1.H[4]
	mul	V30.8H, V16.8H, V1.H[5]
	sqrdmulh	V25.8H, V14.8H, V0.H[4]
	sqrdmulh	V26.8H, V16.8H, V0.H[5]
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V25.8H, V25.8H, V29.8H
	sub	V26.8H, V26.8H, V30.8H
	sshr	V25.8H, V25.8H, #1
	sshr	V26.8H, V26.8H, #1
	mul	V29.8H, V18.8H, V1.H[6]
	mul	V30.8H, V20.8H, V1.H[7]
	sqrdmulh	V27.8H, V18.8H, V0.H[6]
	sqrdmulh	V28.8H, V20.8H, V0.H[7]
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V27.8H, V27.8H, V29.8H
	sub	V28.8H, V28.8H, V30.8H
	sshr	V27.8H, V27.8H, #1
	sshr	V28.8H, V28.8H, #1
	sub	V6.8H, V5.8H, V21.8H
	add	V5.8H, V5.8H, V21.8H
	sub	V8.8H, V7.8H, V22.8H
	add	V7.8H, V7.8H, V22.8H
	sub	V10.8H, V9.8H, V23.8H
	add	V9.8H, V9.8H, V23.8H
	sub	V12.8H, V11.8H, V24.8H
	add	V11.8H, V11.8H, V24.8H
	sub	V14.8H, V13.8H, V25.8H
	add	V13.8H, V13.8H, V25.8H
	sub	V16.8H, V15.8H, V26.8H
	add	V15.8H, V15.8H, V26.8H
	sub	V18.8H, V17.8H, V27.8H
	add	V17.8H, V17.8H, V27.8H
	sub	V20.8H, V19.8H, V28.8H
	add	V19.8H, V19.8H, V28.8H
	ldr	Q0, [x2, #192]
	ldr	Q2, [x2, #208]
	ldr	Q1, [x3, #192]
	ldr	Q3, [x3, #208]
	mov	V29.16B, V5.16B
	mov	V30.16B, V7.16B
	trn1	V5.2D, V5.2D, V6.2D
	trn1	V7.2D, V7.2D, V8.2D
	trn2	V6.2D, V29.2D, V6.2D
	trn2	V8.2D, V30.2D, V8.2D
	mul	V29.8H, V6.8H, V1.8H
	mul	V30.8H, V8.8H, V3.8H
	sqrdmulh	V21.8H, V6.8H, V0.8H
	sqrdmulh	V22.8H, V8.8H, V2.8H
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V21.8H, V21.8H, V29.8H
	sub	V22.8H, V22.8H, V30.8H
	sshr	V21.8H, V21.8H, #1
	sshr	V22.8H, V22.8H, #1
	ldr	Q0, [x2, #224]
	ldr	Q2, [x2, #240]
	ldr	Q1, [x3, #224]
	ldr	Q3, [x3, #240]
	mov	V29.16B, V9.16B
	mov	V30.16B, V11.16B
	trn1	V9.2D, V9.2D, V10.2D
	trn1	V11.2D, V11.2D, V12.2D
	trn2	V10.2D, V29.2D, V10.2D
	trn2	V12.2D, V30.2D, V12.2D
	mul	V29.8H, V10.8H, V1.8H
	mul	V30.8H, V12.8H, V3.8H
	sqrdmulh	V23.8H, V10.8H, V0.8H
	sqrdmulh	V24.8H, V12.8H, V2.8H
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V23.8H, V23.8H, V29.8H
	sub	V24.8H, V24.8H, V30.8H
	sshr	V23.8H, V23.8H, #1
	sshr	V24.8H, V24.8H, #1
	ldr	Q0, [x2, #256]
	ldr	Q2, [x2, #272]
	ldr	Q1, [x3, #256]
	ldr	Q3, [x3, #272]
	mov	V29.16B, V13.16B
	mov	V30.16B, V15.16B
	trn1	V13.2D, V13.2D, V14.2D
	trn1	V15.2D, V15.2D, V16.2D
	trn2	V14.2D, V29.2D, V14.2D
	trn2	V16.2D, V30.2D, V16.2D
	mul	V29.8H, V14.8H, V1.8H
	mul	V30.8H, V16.8H, V3.8H
	sqrdmulh	V25.8H, V14.8H, V0.8H
	sqrdmulh	V26.8H, V16.8H, V2.8H
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V25.8H, V25.8H, V29.8H
	sub	V26.8H, V26.8H, V30.8H
	sshr	V25.8H, V25.8H, #1
	sshr	V26.8H, V26.8H, #1
	ldr	Q0, [x2, #288]
	ldr	Q2, [x2, #304]
	ldr	Q1, [x3, #288]
	ldr	Q3, [x3, #304]
	mov	V29.16B, V17.16B
	mov	V30.16B, V19.16B
	trn1	V17.2D, V17.2D, V18.2D
	trn1	V19.2D, V19.2D, V20.2D
	trn2	V18.2D, V29.2D, V18.2D
	trn2	V20.2D, V30.2D, V20.2D
	mul	V29.8H, V18.8H, V1.8H
	mul	V30.8H, V20.8H, V3.8H
	sqrdmulh	V27.8H, V18.8H, V0.8H
	sqrdmulh	V28.8H, V20.8H, V2.8H
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V27.8H, V27.8H, V29.8H
	sub	V28.8H, V28.8H, V30.8H
	sshr	V27.8H, V27.8H, #1
	sshr	V28.8H, V28.8H, #1
	sub	V6.8H, V5.8H, V21.8H
	add	V5.8H, V5.8H, V21.8H
	sub	V8.8H, V7.8H, V22.8H
	add	V7.8H, V7.8H, V22.8H
	sub	V10.8H, V9.8H, V23.8H
	add	V9.8H, V9.8H, V23.8H
	sub	V12.8H, V11.8H, V24.8H
	add	V11.8H, V11.8H, V24.8H
	sub	V14.8H, V13.8H, V25.8H
	add	V13.8H, V13.8H, V25.8H
	sub	V16.8H, V15.8H, V26.8H
	add	V15.8H, V15.8H, V26.8H
	sub	V18.8H, V17.8H, V27.8H
	add	V17.8H, V17.8H, V27.8H
	sub	V20.8H, V19.8H, V28.8H
	add	V19.8H, V19.8H, V28.8H
	ldr	Q0, [x2, #448]
	ldr	Q2, [x2, #464]
	ldr	Q1, [x3, #448]
	ldr	Q3, [x3, #464]
	mov	V29.16B, V5.16B
	mov	V30.16B, V7.16B
	trn1	V5.4S, V5.4S, V6.4S
	trn1	V7.4S, V7.4S, V8.4S
	trn2	V6.4S, V29.4S, V6.4S
	trn2	V8.4S, V30.4S, V8.4S
	mul	V29.8H, V6.8H, V1.8H
	mul	V30.8H, V8.8H, V3.8H
	sqrdmulh	V21.8H, V6.8H, V0.8H
	sqrdmulh	V22.8H, V8.8H, V2.8H
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V21.8H, V21.8H, V29.8H
	sub	V22.8H, V22.8H, V30.8H
	sshr	V21.8H, V21.8H, #1
	sshr	V22.8H, V22.8H, #1
	ldr	Q0, [x2, #480]
	ldr	Q2, [x2, #496]
	ldr	Q1, [x3, #480]
	ldr	Q3, [x3, #496]
	mov	V29.16B, V9.16B
	mov	V30.16B, V11.16B
	trn1	V9.4S, V9.4S, V10.4S
	trn1	V11.4S, V11.4S, V12.4S
	trn2	V10.4S, V29.4S, V10.4S
	trn2	V12.4S, V30.4S, V12.4S
	mul	V29.8H, V10.8H, V1.8H
	mul	V30.8H, V12.8H, V3.8H
	sqrdmulh	V23.8H, V10.8H, V0.8H
	sqrdmulh	V24.8H, V12.8H, V2.8H
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V23.8H, V23.8H, V29.8H
	sub	V24.8H, V24.8H, V30.8H
	sshr	V23.8H, V23.8H, #1
	sshr	V24.8H, V24.8H, #1
	ldr	Q0, [x2, #512]
	ldr	Q2, [x2, #528]
	ldr	Q1, [x3, #512]
	ldr	Q3, [x3, #528]
	mov	V29.16B, V13.16B
	mov	V30.16B, V15.16B
	trn1	V13.4S, V13.4S, V14.4S
	trn1	V15.4S, V15.4S, V16.4S
	trn2	V14.4S, V29.4S, V14.4S
	trn2	V16.4S, V30.4S, V16.4S
	mul	V29.8H, V14.8H, V1.8H
	mul	V30.8H, V16.8H, V3.8H
	sqrdmulh	V25.8H, V14.8H, V0.8H
	sqrdmulh	V26.8H, V16.8H, V2.8H
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V25.8H, V25.8H, V29.8H
	sub	V26.8H, V26.8H, V30.8H
	sshr	V25.8H, V25.8H, #1
	sshr	V26.8H, V26.8H, #1
	ldr	Q0, [x2, #544]
	ldr	Q2, [x2, #560]
	ldr	Q1, [x3, #544]
	ldr	Q3, [x3, #560]
	mov	V29.16B, V17.16B
	mov	V30.16B, V19.16B
	trn1	V17.4S, V17.4S, V18.4S
	trn1	V19.4S, V19.4S, V20.4S
	trn2	V18.4S, V29.4S, V18.4S
	trn2	V20.4S, V30.4S, V20.4S
	mul	V29.8H, V18.8H, V1.8H
	mul	V30.8H, V20.8H, V3.8H
	sqrdmulh	V27.8H, V18.8H, V0.8H
	sqrdmulh	V28.8H, V20.8H, V2.8H
	sqrdmulh	V29.8H, V29.8H, V4.H[0]
	sqrdmulh	V30.8H, V30.8H, V4.H[0]
	sub	V27.8H, V27.8H, V29.8H
	sub	V28.8H, V28.8H, V30.8H
	sshr	V27.8H, V27.8H, #1
	sshr	V28.8H, V28.8H, #1
	sub	V6.8H, V5.8H, V21.8H
	add	V5.8H, V5.8H, V21.8H
	sub	V8.8H, V7.8H, V22.8H
	add	V7.8H, V7.8H, V22.8H
	sub	V10.8H, V9.8H, V23.8H
	add	V9.8H, V9.8H, V23.8H
	sub	V12.8H, V11.8H, V24.8H
	add	V11.8H, V11.8H, V24.8H
	sub	V14.8H, V13.8H, V25.8H
	add	V13.8H, V13.8H, V25.8H
	sub	V16.8H, V15.8H, V26.8H
	add	V15.8H, V15.8H, V26.8H
	sub	V18.8H, V17.8H, V27.8H
	add	V17.8H, V17.8H, V27.8H
	sub	V20.8H, V19.8H, V28.8H
	add	V19.8H, V19.8H, V28.8H
	sqdmulh	V21.8H, V5.8H, V4.H[2]
	sqdmulh	V22.8H, V6.8H, V4.H[2]
	sshr	V21.8H, V21.8H, #11
	sshr	V22.8H, V22.8H, #11
	mls	V5.8H, V21.8H, V4.H[0]
	mls	V6.8H, V22.8H, V4.H[0]
	sqdmulh	V21.8H, V7.8H, V4.H[2]
	sqdmulh	V22.8H, V8.8H, V4.H[2]
	sshr	V21.8H, V21.8H, #11
	sshr	V22.8H, V22.8H, #11
	mls	V7.8H, V21.8H, V4.H[0]
	mls	V8.8H, V22.8H, V4.H[0]
	sqdmulh	V21.8H, V9.8H, V4.H[2]
	sqdmulh	V22.8H, V10.8H, V4.H[2]
	sshr	V21.8H, V21.8H, #11
	sshr	V22.8H, V22.8H, #11
	mls	V9.8H, V21.8H, V4.H[0]
	mls	V10.8H, V22.8H, V4.H[0]
	sqdmulh	V21.8H, V11.8H, V4.H[2]
	sqdmulh	V22.8H, V12.8H, V4.H[2]
	sshr	V21.8H, V21.8H, #11
	sshr	V22.8H, V22.8H, #11
	mls	V11.8H, V21.8H, V4.H[0]
	mls	V12.8H, V22.8H, V4.H[0]
	sqdmulh	V21.8H, V13.8H, V4.H[2]
	sqdmulh	V22.8H, V14.8H, V4.H[2]
	sshr	V21.8H, V21.8H, #11
	sshr	V22.8H, V22.8H, #11
	mls	V13.8H, V21.8H, V4.H[0]
	mls	V14.8H, V22.8H, V4.H[0]
	sqdmulh	V21.8H, V15.8H, V4.H[2]
	sqdmulh	V22.8H, V16.8H, V4.H[2]
	sshr	V21.8H, V21.8H, #11
	sshr	V22.8H, V22.8H, #11
	mls	V15.8H, V21.8H, V4.H[0]
	mls	V16.8H, V22.8H, V4.H[0]
	sqdmulh	V21.8H, V17.8H, V4.H[2]
	sqdmulh	V22.8H, V18.8H, V4.H[2]
	sshr	V21.8H, V21.8H, #11
	sshr	V22.8H, V22.8H, #11
	mls	V17.8H, V21.8H, V4.H[0]
	mls	V18.8H, V22.8H, V4.H[0]
	sqdmulh	V21.8H, V19.8H, V4.H[2]
	sqdmulh	V22.8H, V20.8H, V4.H[2]
	sshr	V21.8H, V21.8H, #11
	sshr	V22.8H, V22.8H, #11
	mls	V19.8H, V21.8H, V4.H[0]
	mls	V20.8H, V22.8H, V4.H[0]
	mov	V29.16B, V5.16B
	trn1	V5.4S, V5.4S, V6.4S
	trn2	V6.4S, V29.4S, V6.4S
	mov	V29.16B, V5.16B
	trn1	V5.2D, V5.2D, V6.2D
	trn2	V6.2D, V29.2D, V6.2D
	mov	V29.16B, V7.16B
	trn1	V7.4S, V7.4S, V8.4S
	trn2	V8.4S, V29.4S, V8.4S
	mov	V29.16B, V7.16B
	trn1	V7.2D, V7.2D, V8.2D
	trn2	V8.2D, V29.2D, V8.2D
	mov	V29.16B, V9.16B
	trn1	V9.4S, V9.4S, V10.4S
	trn2	V10.4S, V29.4S, V10.4S
	mov	V29.16B, V9.16B
	trn1	V9.2D, V9.2D, V10.2D
	trn2	V10.2D, V29.2D, V10.2D
	mov	V29.16B, V11.16B
	trn1	V11.4S, V11.4S, V12.4S
	trn2	V12.4S, V29.4S, V12.4S
	mov	V29.16B, V11.16B
	trn1	V11.2D, V11.2D, V12.2D
	trn2	V12.2D, V29.2D, V12.2D
	mov	V29.16B, V13.16B
	trn1	V13.4S, V13.4S, V14.4S
	trn2	V14.4S, V29.4S, V14.4S
	mov	V29.16B, V13.16B
	trn1	V13.2D, V13.2D, V14.2D
	trn2	V14.2D, V29.2D, V14.2D
	mov	V29.16B, V15.16B
	trn1	V15.4S, V15.4S, V16.4S
	trn2	V16.4S, V29.4S, V16.4S
	mov	V29.16B, V15.16B
	trn1	V15.2D, V15.2D, V16.2D
	trn2	V16.2D, V29.2D, V16.2D
	mov	V29.16B, V17.16B
	trn1	V17.4S, V17.4S, V18.4S
	trn2	V18.4S, V29.4S, V18.4S
	mov	V29.16B, V17.16B
	trn1	V17.2D, V17.2D, V18.2D
	trn2	V18.2D, V29.2D, V18.2D
	mov	V29.16B, V19.16B
	trn1	V19.4S, V19.4S, V20.4S
	trn2	V20.4S, V29.4S, V20.4S
	mov	V29.16B, V19.16B
	trn1	V19.2D, V19.2D, V20.2D
	trn2	V20.2D, V29.2D, V20.2D
	stp	Q5, Q6, [x1]
	stp	Q7, Q8, [x1, #32]
	stp	Q9, Q10, [x1, #64]
	stp	Q11, Q12, [x1, #96]
	stp	Q13, Q14, [x1, #128]
	stp	Q15, Q16, [x1, #160]
	stp	Q17, Q18, [x1, #192]
	stp	Q19, Q20, [x1, #224]
	ldp	D8, D9, [x29, #16]
	ldp	D10, D11, [x29, #32]
	ldp	D12, D13, [x29, #48]
	ldp	D14, D15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
	ENDP
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mlkem_aarch64_zetas_inv
	DCW	0x06a5, 0x06a5, 0x070f, 0x070f, 0x05b4, 0x05b4, 0x0943, 0x0943
	DCW	0x0922, 0x0922, 0x091d, 0x091d, 0x0134, 0x0134, 0x006c, 0x006c
	DCW	0x0b23, 0x0b23, 0x0366, 0x0366, 0x0356, 0x0356, 0x05e6, 0x05e6
	DCW	0x09e7, 0x09e7, 0x04fe, 0x04fe, 0x05fa, 0x05fa, 0x04a1, 0x04a1
	DCW	0x067b, 0x067b, 0x04a3, 0x04a3, 0x0c25, 0x0c25, 0x036a, 0x036a
	DCW	0x0537, 0x0537, 0x083f, 0x083f, 0x0088, 0x0088, 0x04bf, 0x04bf
	DCW	0x0b81, 0x0b81, 0x05b9, 0x05b9, 0x0505, 0x0505, 0x07d7, 0x07d7
	DCW	0x0a9f, 0x0a9f, 0x0aa6, 0x0aa6, 0x08b8, 0x08b8, 0x09d0, 0x09d0
	DCW	0x004b, 0x004b, 0x009c, 0x009c, 0x0bb8, 0x0bb8, 0x0b5f, 0x0b5f
	DCW	0x0ba4, 0x0ba4, 0x0368, 0x0368, 0x0a7d, 0x0a7d, 0x0636, 0x0636
	DCW	0x08a2, 0x08a2, 0x025a, 0x025a, 0x0736, 0x0736, 0x0309, 0x0309
	DCW	0x0093, 0x0093, 0x087a, 0x087a, 0x09f7, 0x09f7, 0x00f6, 0x00f6
	DCW	0x068c, 0x068c, 0x06db, 0x06db, 0x01cc, 0x01cc, 0x0123, 0x0123
	DCW	0x00eb, 0x00eb, 0x0c50, 0x0c50, 0x0ab6, 0x0ab6, 0x0b5b, 0x0b5b
	DCW	0x0c98, 0x0c98, 0x06f3, 0x06f3, 0x099a, 0x099a, 0x04e3, 0x04e3
	DCW	0x09b6, 0x09b6, 0x0ad6, 0x0ad6, 0x0b53, 0x0b53, 0x044f, 0x044f
	DCW	0x04fb, 0x04fb, 0x04fb, 0x04fb, 0x0a5c, 0x0a5c, 0x0a5c, 0x0a5c
	DCW	0x0429, 0x0429, 0x0429, 0x0429, 0x0b41, 0x0b41, 0x0b41, 0x0b41
	DCW	0x02d5, 0x02d5, 0x02d5, 0x02d5, 0x05e4, 0x05e4, 0x05e4, 0x05e4
	DCW	0x0940, 0x0940, 0x0940, 0x0940, 0x018e, 0x018e, 0x018e, 0x018e
	DCW	0x03b7, 0x03b7, 0x03b7, 0x03b7, 0x00f7, 0x00f7, 0x00f7, 0x00f7
	DCW	0x058d, 0x058d, 0x058d, 0x058d, 0x0c96, 0x0c96, 0x0c96, 0x0c96
	DCW	0x09c3, 0x09c3, 0x09c3, 0x09c3, 0x010f, 0x010f, 0x010f, 0x010f
	DCW	0x005a, 0x005a, 0x005a, 0x005a, 0x0355, 0x0355, 0x0355, 0x0355
	DCW	0x0744, 0x0744, 0x0744, 0x0744, 0x0c83, 0x0c83, 0x0c83, 0x0c83
	DCW	0x048a, 0x048a, 0x048a, 0x048a, 0x0652, 0x0652, 0x0652, 0x0652
	DCW	0x029a, 0x029a, 0x029a, 0x029a, 0x0140, 0x0140, 0x0140, 0x0140
	DCW	0x0008, 0x0008, 0x0008, 0x0008, 0x0afd, 0x0afd, 0x0afd, 0x0afd
	DCW	0x0608, 0x0608, 0x0608, 0x0608, 0x011a, 0x011a, 0x011a, 0x011a
	DCW	0x072e, 0x072e, 0x072e, 0x072e, 0x050d, 0x050d, 0x050d, 0x050d
	DCW	0x090a, 0x090a, 0x090a, 0x090a, 0x0228, 0x0228, 0x0228, 0x0228
	DCW	0x0a75, 0x0a75, 0x0a75, 0x0a75, 0x083a, 0x083a, 0x083a, 0x083a
	DCW	0x0623, 0x00cd, 0x0b66, 0x0606, 0x0aa1, 0x0a25, 0x0908, 0x02a9
	DCW	0x0082, 0x0642, 0x074f, 0x033d, 0x0b82, 0x0bf9, 0x052d, 0x0ac4
	DCW	0x0745, 0x05c2, 0x04b2, 0x093f, 0x0c4b, 0x06d8, 0x0a93, 0x00ab
	DCW	0x0c37, 0x0be2, 0x0773, 0x072c, 0x05ed, 0x0167, 0x02f6, 0x05a1
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mlkem_aarch64_zetas_inv_qinv
	DCW	0xa5a5, 0xa5a5, 0x440f, 0x440f, 0xe1b4, 0xe1b4, 0xa243, 0xa243
	DCW	0x4f22, 0x4f22, 0x901d, 0x901d, 0x5d34, 0x5d34, 0x846c, 0x846c
	DCW	0x4423, 0x4423, 0xd566, 0xd566, 0xa556, 0xa556, 0x57e6, 0x57e6
	DCW	0x4ee7, 0x4ee7, 0x1efe, 0x1efe, 0x53fa, 0x53fa, 0xd7a1, 0xd7a1
	DCW	0xc77b, 0xc77b, 0xbda3, 0xbda3, 0x2b25, 0x2b25, 0xa16a, 0xa16a
	DCW	0x3a37, 0x3a37, 0xd53f, 0xd53f, 0x1888, 0x1888, 0x51bf, 0x51bf
	DCW	0x7e81, 0x7e81, 0xa0b9, 0xa0b9, 0xc405, 0xc405, 0x1cd7, 0x1cd7
	DCW	0xf79f, 0xf79f, 0x9ca6, 0x9ca6, 0xb0b8, 0xb0b8, 0x79d0, 0x79d0
	DCW	0x314b, 0x314b, 0x149c, 0x149c, 0xb3b8, 0xb3b8, 0x385f, 0x385f
	DCW	0xb7a4, 0xb7a4, 0xbb68, 0xbb68, 0xb17d, 0xb17d, 0x4836, 0x4836
	DCW	0xcea2, 0xcea2, 0x705a, 0x705a, 0x4936, 0x4936, 0x8e09, 0x8e09
	DCW	0x8993, 0x8993, 0xd67a, 0xd67a, 0x7ef7, 0x7ef7, 0x82f6, 0x82f6
	DCW	0xea8c, 0xea8c, 0xe7db, 0xe7db, 0xa5cc, 0xa5cc, 0x3a23, 0x3a23
	DCW	0x11eb, 0x11eb, 0xfc50, 0xfc50, 0xccb6, 0xccb6, 0x6c5b, 0x6c5b
	DCW	0x5498, 0x5498, 0xaff3, 0xaff3, 0x379a, 0x379a, 0x7de3, 0x7de3
	DCW	0xcbb6, 0xcbb6, 0x2cd6, 0x2cd6, 0xd453, 0xd453, 0x014f, 0x014f
	DCW	0x45fb, 0x45fb, 0x45fb, 0x45fb, 0x5e5c, 0x5e5c, 0x5e5c, 0x5e5c
	DCW	0xef29, 0xef29, 0xef29, 0xef29, 0xbe41, 0xbe41, 0xbe41, 0xbe41
	DCW	0x31d5, 0x31d5, 0x31d5, 0x31d5, 0x71e4, 0x71e4, 0x71e4, 0x71e4
	DCW	0xc940, 0xc940, 0xc940, 0xc940, 0xcb8e, 0xcb8e, 0xcb8e, 0xcb8e
	DCW	0xb8b7, 0xb8b7, 0xb8b7, 0xb8b7, 0x75f7, 0x75f7, 0x75f7, 0x75f7
	DCW	0xdc8d, 0xdc8d, 0xdc8d, 0xdc8d, 0x6e96, 0x6e96, 0x6e96, 0x6e96
	DCW	0x22c3, 0x22c3, 0x22c3, 0x22c3, 0x3e0f, 0x3e0f, 0x3e0f, 0x3e0f
	DCW	0x6e5a, 0x6e5a, 0x6e5a, 0x6e5a, 0xb255, 0xb255, 0xb255, 0xb255
	DCW	0x9344, 0x9344, 0x9344, 0x9344, 0x6583, 0x6583, 0x6583, 0x6583
	DCW	0x028a, 0x028a, 0x028a, 0x028a, 0xdc52, 0xdc52, 0xdc52, 0xdc52
	DCW	0x309a, 0x309a, 0x309a, 0x309a, 0xc140, 0xc140, 0xc140, 0xc140
	DCW	0x9808, 0x9808, 0x9808, 0x9808, 0x31fd, 0x31fd, 0x31fd, 0x31fd
	DCW	0x9e08, 0x9e08, 0x9e08, 0x9e08, 0xaf1a, 0xaf1a, 0xaf1a, 0xaf1a
	DCW	0xb12e, 0xb12e, 0xb12e, 0xb12e, 0x5c0d, 0x5c0d, 0x5c0d, 0x5c0d
	DCW	0x870a, 0x870a, 0x870a, 0x870a, 0xfa28, 0xfa28, 0xfa28, 0xfa28
	DCW	0x1975, 0x1975, 0x1975, 0x1975, 0x163a, 0x163a, 0x163a, 0x163a
	DCW	0x3f23, 0x97cd, 0xdd66, 0xb806, 0xdda1, 0x2925, 0xa108, 0x6da9
	DCW	0x6682, 0xac42, 0x044f, 0xea3d, 0x7182, 0x66f9, 0xbc2d, 0x16c4
	DCW	0x8645, 0x2bc2, 0xfab2, 0xd63f, 0x3d4b, 0x0ed8, 0x9393, 0x51ab
	DCW	0x4137, 0x91e2, 0x3073, 0xcb2c, 0xfced, 0xc667, 0x84f6, 0xd8a1
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mlkem_invntt
mlkem_invntt PROC
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	stp	D10, D11, [x29, #32]
	stp	D12, D13, [x29, #48]
	stp	D14, D15, [x29, #64]
	adrp	x2, L_mlkem_aarch64_zetas_inv
	add	x2, x2, L_mlkem_aarch64_zetas_inv
	adrp	x3, L_mlkem_aarch64_zetas_inv_qinv
	add	x3, x3, L_mlkem_aarch64_zetas_inv_qinv
	adrp	x4, L_mlkem_aarch64_consts
	add	x4, x4, L_mlkem_aarch64_consts
	add	x1, x0, #0x100
	ldr	Q8, [x4]
	ldp	Q9, Q10, [x0]
	ldp	Q11, Q12, [x0, #32]
	ldp	Q13, Q14, [x0, #64]
	ldp	Q15, Q16, [x0, #96]
	ldp	Q17, Q18, [x0, #128]
	ldp	Q19, Q20, [x0, #160]
	ldp	Q21, Q22, [x0, #192]
	ldp	Q23, Q24, [x0, #224]
	mov	V25.16B, V9.16B
	trn1	V9.2D, V9.2D, V10.2D
	trn2	V10.2D, V25.2D, V10.2D
	mov	V25.16B, V9.16B
	trn1	V9.4S, V9.4S, V10.4S
	trn2	V10.4S, V25.4S, V10.4S
	mov	V25.16B, V11.16B
	trn1	V11.2D, V11.2D, V12.2D
	trn2	V12.2D, V25.2D, V12.2D
	mov	V25.16B, V11.16B
	trn1	V11.4S, V11.4S, V12.4S
	trn2	V12.4S, V25.4S, V12.4S
	mov	V25.16B, V13.16B
	trn1	V13.2D, V13.2D, V14.2D
	trn2	V14.2D, V25.2D, V14.2D
	mov	V25.16B, V13.16B
	trn1	V13.4S, V13.4S, V14.4S
	trn2	V14.4S, V25.4S, V14.4S
	mov	V25.16B, V15.16B
	trn1	V15.2D, V15.2D, V16.2D
	trn2	V16.2D, V25.2D, V16.2D
	mov	V25.16B, V15.16B
	trn1	V15.4S, V15.4S, V16.4S
	trn2	V16.4S, V25.4S, V16.4S
	mov	V25.16B, V17.16B
	trn1	V17.2D, V17.2D, V18.2D
	trn2	V18.2D, V25.2D, V18.2D
	mov	V25.16B, V17.16B
	trn1	V17.4S, V17.4S, V18.4S
	trn2	V18.4S, V25.4S, V18.4S
	mov	V25.16B, V19.16B
	trn1	V19.2D, V19.2D, V20.2D
	trn2	V20.2D, V25.2D, V20.2D
	mov	V25.16B, V19.16B
	trn1	V19.4S, V19.4S, V20.4S
	trn2	V20.4S, V25.4S, V20.4S
	mov	V25.16B, V21.16B
	trn1	V21.2D, V21.2D, V22.2D
	trn2	V22.2D, V25.2D, V22.2D
	mov	V25.16B, V21.16B
	trn1	V21.4S, V21.4S, V22.4S
	trn2	V22.4S, V25.4S, V22.4S
	mov	V25.16B, V23.16B
	trn1	V23.2D, V23.2D, V24.2D
	trn2	V24.2D, V25.2D, V24.2D
	mov	V25.16B, V23.16B
	trn1	V23.4S, V23.4S, V24.4S
	trn2	V24.4S, V25.4S, V24.4S
	ldr	Q0, [x2]
	ldr	Q1, [x2, #16]
	ldr	Q2, [x3]
	ldr	Q3, [x3, #16]
	sub	V26.8H, V9.8H, V10.8H
	sub	V28.8H, V11.8H, V12.8H
	add	V9.8H, V9.8H, V10.8H
	add	V11.8H, V11.8H, V12.8H
	mul	V25.8H, V26.8H, V2.8H
	mul	V27.8H, V28.8H, V3.8H
	sqrdmulh	V10.8H, V26.8H, V0.8H
	sqrdmulh	V12.8H, V28.8H, V1.8H
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V10.8H, V10.8H, V25.8H
	sub	V12.8H, V12.8H, V27.8H
	sshr	V10.8H, V10.8H, #1
	sshr	V12.8H, V12.8H, #1
	ldr	Q0, [x2, #32]
	ldr	Q1, [x2, #48]
	ldr	Q2, [x3, #32]
	ldr	Q3, [x3, #48]
	sub	V26.8H, V13.8H, V14.8H
	sub	V28.8H, V15.8H, V16.8H
	add	V13.8H, V13.8H, V14.8H
	add	V15.8H, V15.8H, V16.8H
	mul	V25.8H, V26.8H, V2.8H
	mul	V27.8H, V28.8H, V3.8H
	sqrdmulh	V14.8H, V26.8H, V0.8H
	sqrdmulh	V16.8H, V28.8H, V1.8H
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V14.8H, V14.8H, V25.8H
	sub	V16.8H, V16.8H, V27.8H
	sshr	V14.8H, V14.8H, #1
	sshr	V16.8H, V16.8H, #1
	ldr	Q0, [x2, #64]
	ldr	Q1, [x2, #80]
	ldr	Q2, [x3, #64]
	ldr	Q3, [x3, #80]
	sub	V26.8H, V17.8H, V18.8H
	sub	V28.8H, V19.8H, V20.8H
	add	V17.8H, V17.8H, V18.8H
	add	V19.8H, V19.8H, V20.8H
	mul	V25.8H, V26.8H, V2.8H
	mul	V27.8H, V28.8H, V3.8H
	sqrdmulh	V18.8H, V26.8H, V0.8H
	sqrdmulh	V20.8H, V28.8H, V1.8H
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V18.8H, V18.8H, V25.8H
	sub	V20.8H, V20.8H, V27.8H
	sshr	V18.8H, V18.8H, #1
	sshr	V20.8H, V20.8H, #1
	ldr	Q0, [x2, #96]
	ldr	Q1, [x2, #112]
	ldr	Q2, [x3, #96]
	ldr	Q3, [x3, #112]
	sub	V26.8H, V21.8H, V22.8H
	sub	V28.8H, V23.8H, V24.8H
	add	V21.8H, V21.8H, V22.8H
	add	V23.8H, V23.8H, V24.8H
	mul	V25.8H, V26.8H, V2.8H
	mul	V27.8H, V28.8H, V3.8H
	sqrdmulh	V22.8H, V26.8H, V0.8H
	sqrdmulh	V24.8H, V28.8H, V1.8H
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V22.8H, V22.8H, V25.8H
	sub	V24.8H, V24.8H, V27.8H
	sshr	V22.8H, V22.8H, #1
	sshr	V24.8H, V24.8H, #1
	ldr	Q0, [x2, #256]
	ldr	Q1, [x2, #272]
	ldr	Q2, [x3, #256]
	ldr	Q3, [x3, #272]
	mov	V25.16B, V9.16B
	mov	V26.16B, V11.16B
	trn1	V9.4S, V9.4S, V10.4S
	trn1	V11.4S, V11.4S, V12.4S
	trn2	V10.4S, V25.4S, V10.4S
	trn2	V12.4S, V26.4S, V12.4S
	sub	V26.8H, V9.8H, V10.8H
	sub	V28.8H, V11.8H, V12.8H
	add	V9.8H, V9.8H, V10.8H
	add	V11.8H, V11.8H, V12.8H
	mul	V25.8H, V26.8H, V2.8H
	mul	V27.8H, V28.8H, V3.8H
	sqrdmulh	V10.8H, V26.8H, V0.8H
	sqrdmulh	V12.8H, V28.8H, V1.8H
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V10.8H, V10.8H, V25.8H
	sub	V12.8H, V12.8H, V27.8H
	sshr	V10.8H, V10.8H, #1
	sshr	V12.8H, V12.8H, #1
	ldr	Q0, [x2, #288]
	ldr	Q1, [x2, #304]
	ldr	Q2, [x3, #288]
	ldr	Q3, [x3, #304]
	mov	V25.16B, V13.16B
	mov	V26.16B, V15.16B
	trn1	V13.4S, V13.4S, V14.4S
	trn1	V15.4S, V15.4S, V16.4S
	trn2	V14.4S, V25.4S, V14.4S
	trn2	V16.4S, V26.4S, V16.4S
	sub	V26.8H, V13.8H, V14.8H
	sub	V28.8H, V15.8H, V16.8H
	add	V13.8H, V13.8H, V14.8H
	add	V15.8H, V15.8H, V16.8H
	mul	V25.8H, V26.8H, V2.8H
	mul	V27.8H, V28.8H, V3.8H
	sqrdmulh	V14.8H, V26.8H, V0.8H
	sqrdmulh	V16.8H, V28.8H, V1.8H
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V14.8H, V14.8H, V25.8H
	sub	V16.8H, V16.8H, V27.8H
	sshr	V14.8H, V14.8H, #1
	sshr	V16.8H, V16.8H, #1
	ldr	Q0, [x2, #320]
	ldr	Q1, [x2, #336]
	ldr	Q2, [x3, #320]
	ldr	Q3, [x3, #336]
	mov	V25.16B, V17.16B
	mov	V26.16B, V19.16B
	trn1	V17.4S, V17.4S, V18.4S
	trn1	V19.4S, V19.4S, V20.4S
	trn2	V18.4S, V25.4S, V18.4S
	trn2	V20.4S, V26.4S, V20.4S
	sub	V26.8H, V17.8H, V18.8H
	sub	V28.8H, V19.8H, V20.8H
	add	V17.8H, V17.8H, V18.8H
	add	V19.8H, V19.8H, V20.8H
	mul	V25.8H, V26.8H, V2.8H
	mul	V27.8H, V28.8H, V3.8H
	sqrdmulh	V18.8H, V26.8H, V0.8H
	sqrdmulh	V20.8H, V28.8H, V1.8H
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V18.8H, V18.8H, V25.8H
	sub	V20.8H, V20.8H, V27.8H
	sshr	V18.8H, V18.8H, #1
	sshr	V20.8H, V20.8H, #1
	ldr	Q0, [x2, #352]
	ldr	Q1, [x2, #368]
	ldr	Q2, [x3, #352]
	ldr	Q3, [x3, #368]
	mov	V25.16B, V21.16B
	mov	V26.16B, V23.16B
	trn1	V21.4S, V21.4S, V22.4S
	trn1	V23.4S, V23.4S, V24.4S
	trn2	V22.4S, V25.4S, V22.4S
	trn2	V24.4S, V26.4S, V24.4S
	sub	V26.8H, V21.8H, V22.8H
	sub	V28.8H, V23.8H, V24.8H
	add	V21.8H, V21.8H, V22.8H
	add	V23.8H, V23.8H, V24.8H
	mul	V25.8H, V26.8H, V2.8H
	mul	V27.8H, V28.8H, V3.8H
	sqrdmulh	V22.8H, V26.8H, V0.8H
	sqrdmulh	V24.8H, V28.8H, V1.8H
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V22.8H, V22.8H, V25.8H
	sub	V24.8H, V24.8H, V27.8H
	sshr	V22.8H, V22.8H, #1
	sshr	V24.8H, V24.8H, #1
	ldr	Q0, [x2, #512]
	ldr	Q2, [x3, #512]
	mov	V25.16B, V9.16B
	mov	V26.16B, V11.16B
	trn1	V9.2D, V9.2D, V10.2D
	trn1	V11.2D, V11.2D, V12.2D
	trn2	V10.2D, V25.2D, V10.2D
	trn2	V12.2D, V26.2D, V12.2D
	sub	V26.8H, V9.8H, V10.8H
	sub	V28.8H, V11.8H, V12.8H
	add	V9.8H, V9.8H, V10.8H
	add	V11.8H, V11.8H, V12.8H
	mul	V25.8H, V26.8H, V2.H[0]
	mul	V27.8H, V28.8H, V2.H[1]
	sqrdmulh	V10.8H, V26.8H, V0.H[0]
	sqrdmulh	V12.8H, V28.8H, V0.H[1]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V10.8H, V10.8H, V25.8H
	sub	V12.8H, V12.8H, V27.8H
	sshr	V10.8H, V10.8H, #1
	sshr	V12.8H, V12.8H, #1
	mov	V25.16B, V13.16B
	mov	V26.16B, V15.16B
	trn1	V13.2D, V13.2D, V14.2D
	trn1	V15.2D, V15.2D, V16.2D
	trn2	V14.2D, V25.2D, V14.2D
	trn2	V16.2D, V26.2D, V16.2D
	sub	V26.8H, V13.8H, V14.8H
	sub	V28.8H, V15.8H, V16.8H
	add	V13.8H, V13.8H, V14.8H
	add	V15.8H, V15.8H, V16.8H
	mul	V25.8H, V26.8H, V2.H[2]
	mul	V27.8H, V28.8H, V2.H[3]
	sqrdmulh	V14.8H, V26.8H, V0.H[2]
	sqrdmulh	V16.8H, V28.8H, V0.H[3]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V14.8H, V14.8H, V25.8H
	sub	V16.8H, V16.8H, V27.8H
	sshr	V14.8H, V14.8H, #1
	sshr	V16.8H, V16.8H, #1
	mov	V25.16B, V17.16B
	mov	V26.16B, V19.16B
	trn1	V17.2D, V17.2D, V18.2D
	trn1	V19.2D, V19.2D, V20.2D
	trn2	V18.2D, V25.2D, V18.2D
	trn2	V20.2D, V26.2D, V20.2D
	sub	V26.8H, V17.8H, V18.8H
	sub	V28.8H, V19.8H, V20.8H
	add	V17.8H, V17.8H, V18.8H
	add	V19.8H, V19.8H, V20.8H
	mul	V25.8H, V26.8H, V2.H[4]
	mul	V27.8H, V28.8H, V2.H[5]
	sqrdmulh	V18.8H, V26.8H, V0.H[4]
	sqrdmulh	V20.8H, V28.8H, V0.H[5]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V18.8H, V18.8H, V25.8H
	sub	V20.8H, V20.8H, V27.8H
	sshr	V18.8H, V18.8H, #1
	sshr	V20.8H, V20.8H, #1
	mov	V25.16B, V21.16B
	mov	V26.16B, V23.16B
	trn1	V21.2D, V21.2D, V22.2D
	trn1	V23.2D, V23.2D, V24.2D
	trn2	V22.2D, V25.2D, V22.2D
	trn2	V24.2D, V26.2D, V24.2D
	sub	V26.8H, V21.8H, V22.8H
	sub	V28.8H, V23.8H, V24.8H
	add	V21.8H, V21.8H, V22.8H
	add	V23.8H, V23.8H, V24.8H
	mul	V25.8H, V26.8H, V2.H[6]
	mul	V27.8H, V28.8H, V2.H[7]
	sqrdmulh	V22.8H, V26.8H, V0.H[6]
	sqrdmulh	V24.8H, V28.8H, V0.H[7]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V22.8H, V22.8H, V25.8H
	sub	V24.8H, V24.8H, V27.8H
	sshr	V22.8H, V22.8H, #1
	sshr	V24.8H, V24.8H, #1
	sqdmulh	V25.8H, V9.8H, V8.H[2]
	sqdmulh	V26.8H, V11.8H, V8.H[2]
	sshr	V25.8H, V25.8H, #11
	sshr	V26.8H, V26.8H, #11
	mls	V9.8H, V25.8H, V8.H[0]
	mls	V11.8H, V26.8H, V8.H[0]
	sqdmulh	V25.8H, V13.8H, V8.H[2]
	sqdmulh	V26.8H, V15.8H, V8.H[2]
	sshr	V25.8H, V25.8H, #11
	sshr	V26.8H, V26.8H, #11
	mls	V13.8H, V25.8H, V8.H[0]
	mls	V15.8H, V26.8H, V8.H[0]
	sqdmulh	V25.8H, V17.8H, V8.H[2]
	sqdmulh	V26.8H, V19.8H, V8.H[2]
	sshr	V25.8H, V25.8H, #11
	sshr	V26.8H, V26.8H, #11
	mls	V17.8H, V25.8H, V8.H[0]
	mls	V19.8H, V26.8H, V8.H[0]
	sqdmulh	V25.8H, V21.8H, V8.H[2]
	sqdmulh	V26.8H, V23.8H, V8.H[2]
	sshr	V25.8H, V25.8H, #11
	sshr	V26.8H, V26.8H, #11
	mls	V21.8H, V25.8H, V8.H[0]
	mls	V23.8H, V26.8H, V8.H[0]
	stp	Q9, Q10, [x0]
	stp	Q11, Q12, [x0, #32]
	stp	Q13, Q14, [x0, #64]
	stp	Q15, Q16, [x0, #96]
	stp	Q17, Q18, [x0, #128]
	stp	Q19, Q20, [x0, #160]
	stp	Q21, Q22, [x0, #192]
	stp	Q23, Q24, [x0, #224]
	ldp	Q9, Q10, [x1]
	ldp	Q11, Q12, [x1, #32]
	ldp	Q13, Q14, [x1, #64]
	ldp	Q15, Q16, [x1, #96]
	ldp	Q17, Q18, [x1, #128]
	ldp	Q19, Q20, [x1, #160]
	ldp	Q21, Q22, [x1, #192]
	ldp	Q23, Q24, [x1, #224]
	mov	V25.16B, V9.16B
	trn1	V9.2D, V9.2D, V10.2D
	trn2	V10.2D, V25.2D, V10.2D
	mov	V25.16B, V9.16B
	trn1	V9.4S, V9.4S, V10.4S
	trn2	V10.4S, V25.4S, V10.4S
	mov	V25.16B, V11.16B
	trn1	V11.2D, V11.2D, V12.2D
	trn2	V12.2D, V25.2D, V12.2D
	mov	V25.16B, V11.16B
	trn1	V11.4S, V11.4S, V12.4S
	trn2	V12.4S, V25.4S, V12.4S
	mov	V25.16B, V13.16B
	trn1	V13.2D, V13.2D, V14.2D
	trn2	V14.2D, V25.2D, V14.2D
	mov	V25.16B, V13.16B
	trn1	V13.4S, V13.4S, V14.4S
	trn2	V14.4S, V25.4S, V14.4S
	mov	V25.16B, V15.16B
	trn1	V15.2D, V15.2D, V16.2D
	trn2	V16.2D, V25.2D, V16.2D
	mov	V25.16B, V15.16B
	trn1	V15.4S, V15.4S, V16.4S
	trn2	V16.4S, V25.4S, V16.4S
	mov	V25.16B, V17.16B
	trn1	V17.2D, V17.2D, V18.2D
	trn2	V18.2D, V25.2D, V18.2D
	mov	V25.16B, V17.16B
	trn1	V17.4S, V17.4S, V18.4S
	trn2	V18.4S, V25.4S, V18.4S
	mov	V25.16B, V19.16B
	trn1	V19.2D, V19.2D, V20.2D
	trn2	V20.2D, V25.2D, V20.2D
	mov	V25.16B, V19.16B
	trn1	V19.4S, V19.4S, V20.4S
	trn2	V20.4S, V25.4S, V20.4S
	mov	V25.16B, V21.16B
	trn1	V21.2D, V21.2D, V22.2D
	trn2	V22.2D, V25.2D, V22.2D
	mov	V25.16B, V21.16B
	trn1	V21.4S, V21.4S, V22.4S
	trn2	V22.4S, V25.4S, V22.4S
	mov	V25.16B, V23.16B
	trn1	V23.2D, V23.2D, V24.2D
	trn2	V24.2D, V25.2D, V24.2D
	mov	V25.16B, V23.16B
	trn1	V23.4S, V23.4S, V24.4S
	trn2	V24.4S, V25.4S, V24.4S
	ldr	Q0, [x2, #128]
	ldr	Q1, [x2, #144]
	ldr	Q2, [x3, #128]
	ldr	Q3, [x3, #144]
	sub	V26.8H, V9.8H, V10.8H
	sub	V28.8H, V11.8H, V12.8H
	add	V9.8H, V9.8H, V10.8H
	add	V11.8H, V11.8H, V12.8H
	mul	V25.8H, V26.8H, V2.8H
	mul	V27.8H, V28.8H, V3.8H
	sqrdmulh	V10.8H, V26.8H, V0.8H
	sqrdmulh	V12.8H, V28.8H, V1.8H
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V10.8H, V10.8H, V25.8H
	sub	V12.8H, V12.8H, V27.8H
	sshr	V10.8H, V10.8H, #1
	sshr	V12.8H, V12.8H, #1
	ldr	Q0, [x2, #160]
	ldr	Q1, [x2, #176]
	ldr	Q2, [x3, #160]
	ldr	Q3, [x3, #176]
	sub	V26.8H, V13.8H, V14.8H
	sub	V28.8H, V15.8H, V16.8H
	add	V13.8H, V13.8H, V14.8H
	add	V15.8H, V15.8H, V16.8H
	mul	V25.8H, V26.8H, V2.8H
	mul	V27.8H, V28.8H, V3.8H
	sqrdmulh	V14.8H, V26.8H, V0.8H
	sqrdmulh	V16.8H, V28.8H, V1.8H
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V14.8H, V14.8H, V25.8H
	sub	V16.8H, V16.8H, V27.8H
	sshr	V14.8H, V14.8H, #1
	sshr	V16.8H, V16.8H, #1
	ldr	Q0, [x2, #192]
	ldr	Q1, [x2, #208]
	ldr	Q2, [x3, #192]
	ldr	Q3, [x3, #208]
	sub	V26.8H, V17.8H, V18.8H
	sub	V28.8H, V19.8H, V20.8H
	add	V17.8H, V17.8H, V18.8H
	add	V19.8H, V19.8H, V20.8H
	mul	V25.8H, V26.8H, V2.8H
	mul	V27.8H, V28.8H, V3.8H
	sqrdmulh	V18.8H, V26.8H, V0.8H
	sqrdmulh	V20.8H, V28.8H, V1.8H
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V18.8H, V18.8H, V25.8H
	sub	V20.8H, V20.8H, V27.8H
	sshr	V18.8H, V18.8H, #1
	sshr	V20.8H, V20.8H, #1
	ldr	Q0, [x2, #224]
	ldr	Q1, [x2, #240]
	ldr	Q2, [x3, #224]
	ldr	Q3, [x3, #240]
	sub	V26.8H, V21.8H, V22.8H
	sub	V28.8H, V23.8H, V24.8H
	add	V21.8H, V21.8H, V22.8H
	add	V23.8H, V23.8H, V24.8H
	mul	V25.8H, V26.8H, V2.8H
	mul	V27.8H, V28.8H, V3.8H
	sqrdmulh	V22.8H, V26.8H, V0.8H
	sqrdmulh	V24.8H, V28.8H, V1.8H
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V22.8H, V22.8H, V25.8H
	sub	V24.8H, V24.8H, V27.8H
	sshr	V22.8H, V22.8H, #1
	sshr	V24.8H, V24.8H, #1
	ldr	Q0, [x2, #384]
	ldr	Q1, [x2, #400]
	ldr	Q2, [x3, #384]
	ldr	Q3, [x3, #400]
	mov	V25.16B, V9.16B
	mov	V26.16B, V11.16B
	trn1	V9.4S, V9.4S, V10.4S
	trn1	V11.4S, V11.4S, V12.4S
	trn2	V10.4S, V25.4S, V10.4S
	trn2	V12.4S, V26.4S, V12.4S
	sub	V26.8H, V9.8H, V10.8H
	sub	V28.8H, V11.8H, V12.8H
	add	V9.8H, V9.8H, V10.8H
	add	V11.8H, V11.8H, V12.8H
	mul	V25.8H, V26.8H, V2.8H
	mul	V27.8H, V28.8H, V3.8H
	sqrdmulh	V10.8H, V26.8H, V0.8H
	sqrdmulh	V12.8H, V28.8H, V1.8H
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V10.8H, V10.8H, V25.8H
	sub	V12.8H, V12.8H, V27.8H
	sshr	V10.8H, V10.8H, #1
	sshr	V12.8H, V12.8H, #1
	ldr	Q0, [x2, #416]
	ldr	Q1, [x2, #432]
	ldr	Q2, [x3, #416]
	ldr	Q3, [x3, #432]
	mov	V25.16B, V13.16B
	mov	V26.16B, V15.16B
	trn1	V13.4S, V13.4S, V14.4S
	trn1	V15.4S, V15.4S, V16.4S
	trn2	V14.4S, V25.4S, V14.4S
	trn2	V16.4S, V26.4S, V16.4S
	sub	V26.8H, V13.8H, V14.8H
	sub	V28.8H, V15.8H, V16.8H
	add	V13.8H, V13.8H, V14.8H
	add	V15.8H, V15.8H, V16.8H
	mul	V25.8H, V26.8H, V2.8H
	mul	V27.8H, V28.8H, V3.8H
	sqrdmulh	V14.8H, V26.8H, V0.8H
	sqrdmulh	V16.8H, V28.8H, V1.8H
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V14.8H, V14.8H, V25.8H
	sub	V16.8H, V16.8H, V27.8H
	sshr	V14.8H, V14.8H, #1
	sshr	V16.8H, V16.8H, #1
	ldr	Q0, [x2, #448]
	ldr	Q1, [x2, #464]
	ldr	Q2, [x3, #448]
	ldr	Q3, [x3, #464]
	mov	V25.16B, V17.16B
	mov	V26.16B, V19.16B
	trn1	V17.4S, V17.4S, V18.4S
	trn1	V19.4S, V19.4S, V20.4S
	trn2	V18.4S, V25.4S, V18.4S
	trn2	V20.4S, V26.4S, V20.4S
	sub	V26.8H, V17.8H, V18.8H
	sub	V28.8H, V19.8H, V20.8H
	add	V17.8H, V17.8H, V18.8H
	add	V19.8H, V19.8H, V20.8H
	mul	V25.8H, V26.8H, V2.8H
	mul	V27.8H, V28.8H, V3.8H
	sqrdmulh	V18.8H, V26.8H, V0.8H
	sqrdmulh	V20.8H, V28.8H, V1.8H
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V18.8H, V18.8H, V25.8H
	sub	V20.8H, V20.8H, V27.8H
	sshr	V18.8H, V18.8H, #1
	sshr	V20.8H, V20.8H, #1
	ldr	Q0, [x2, #480]
	ldr	Q1, [x2, #496]
	ldr	Q2, [x3, #480]
	ldr	Q3, [x3, #496]
	mov	V25.16B, V21.16B
	mov	V26.16B, V23.16B
	trn1	V21.4S, V21.4S, V22.4S
	trn1	V23.4S, V23.4S, V24.4S
	trn2	V22.4S, V25.4S, V22.4S
	trn2	V24.4S, V26.4S, V24.4S
	sub	V26.8H, V21.8H, V22.8H
	sub	V28.8H, V23.8H, V24.8H
	add	V21.8H, V21.8H, V22.8H
	add	V23.8H, V23.8H, V24.8H
	mul	V25.8H, V26.8H, V2.8H
	mul	V27.8H, V28.8H, V3.8H
	sqrdmulh	V22.8H, V26.8H, V0.8H
	sqrdmulh	V24.8H, V28.8H, V1.8H
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V22.8H, V22.8H, V25.8H
	sub	V24.8H, V24.8H, V27.8H
	sshr	V22.8H, V22.8H, #1
	sshr	V24.8H, V24.8H, #1
	ldr	Q0, [x2, #528]
	ldr	Q2, [x3, #528]
	mov	V25.16B, V9.16B
	mov	V26.16B, V11.16B
	trn1	V9.2D, V9.2D, V10.2D
	trn1	V11.2D, V11.2D, V12.2D
	trn2	V10.2D, V25.2D, V10.2D
	trn2	V12.2D, V26.2D, V12.2D
	sub	V26.8H, V9.8H, V10.8H
	sub	V28.8H, V11.8H, V12.8H
	add	V9.8H, V9.8H, V10.8H
	add	V11.8H, V11.8H, V12.8H
	mul	V25.8H, V26.8H, V2.H[0]
	mul	V27.8H, V28.8H, V2.H[1]
	sqrdmulh	V10.8H, V26.8H, V0.H[0]
	sqrdmulh	V12.8H, V28.8H, V0.H[1]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V10.8H, V10.8H, V25.8H
	sub	V12.8H, V12.8H, V27.8H
	sshr	V10.8H, V10.8H, #1
	sshr	V12.8H, V12.8H, #1
	mov	V25.16B, V13.16B
	mov	V26.16B, V15.16B
	trn1	V13.2D, V13.2D, V14.2D
	trn1	V15.2D, V15.2D, V16.2D
	trn2	V14.2D, V25.2D, V14.2D
	trn2	V16.2D, V26.2D, V16.2D
	sub	V26.8H, V13.8H, V14.8H
	sub	V28.8H, V15.8H, V16.8H
	add	V13.8H, V13.8H, V14.8H
	add	V15.8H, V15.8H, V16.8H
	mul	V25.8H, V26.8H, V2.H[2]
	mul	V27.8H, V28.8H, V2.H[3]
	sqrdmulh	V14.8H, V26.8H, V0.H[2]
	sqrdmulh	V16.8H, V28.8H, V0.H[3]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V14.8H, V14.8H, V25.8H
	sub	V16.8H, V16.8H, V27.8H
	sshr	V14.8H, V14.8H, #1
	sshr	V16.8H, V16.8H, #1
	mov	V25.16B, V17.16B
	mov	V26.16B, V19.16B
	trn1	V17.2D, V17.2D, V18.2D
	trn1	V19.2D, V19.2D, V20.2D
	trn2	V18.2D, V25.2D, V18.2D
	trn2	V20.2D, V26.2D, V20.2D
	sub	V26.8H, V17.8H, V18.8H
	sub	V28.8H, V19.8H, V20.8H
	add	V17.8H, V17.8H, V18.8H
	add	V19.8H, V19.8H, V20.8H
	mul	V25.8H, V26.8H, V2.H[4]
	mul	V27.8H, V28.8H, V2.H[5]
	sqrdmulh	V18.8H, V26.8H, V0.H[4]
	sqrdmulh	V20.8H, V28.8H, V0.H[5]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V18.8H, V18.8H, V25.8H
	sub	V20.8H, V20.8H, V27.8H
	sshr	V18.8H, V18.8H, #1
	sshr	V20.8H, V20.8H, #1
	mov	V25.16B, V21.16B
	mov	V26.16B, V23.16B
	trn1	V21.2D, V21.2D, V22.2D
	trn1	V23.2D, V23.2D, V24.2D
	trn2	V22.2D, V25.2D, V22.2D
	trn2	V24.2D, V26.2D, V24.2D
	sub	V26.8H, V21.8H, V22.8H
	sub	V28.8H, V23.8H, V24.8H
	add	V21.8H, V21.8H, V22.8H
	add	V23.8H, V23.8H, V24.8H
	mul	V25.8H, V26.8H, V2.H[6]
	mul	V27.8H, V28.8H, V2.H[7]
	sqrdmulh	V22.8H, V26.8H, V0.H[6]
	sqrdmulh	V24.8H, V28.8H, V0.H[7]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V22.8H, V22.8H, V25.8H
	sub	V24.8H, V24.8H, V27.8H
	sshr	V22.8H, V22.8H, #1
	sshr	V24.8H, V24.8H, #1
	sqdmulh	V25.8H, V9.8H, V8.H[2]
	sqdmulh	V26.8H, V11.8H, V8.H[2]
	sshr	V25.8H, V25.8H, #11
	sshr	V26.8H, V26.8H, #11
	mls	V9.8H, V25.8H, V8.H[0]
	mls	V11.8H, V26.8H, V8.H[0]
	sqdmulh	V25.8H, V13.8H, V8.H[2]
	sqdmulh	V26.8H, V15.8H, V8.H[2]
	sshr	V25.8H, V25.8H, #11
	sshr	V26.8H, V26.8H, #11
	mls	V13.8H, V25.8H, V8.H[0]
	mls	V15.8H, V26.8H, V8.H[0]
	sqdmulh	V25.8H, V17.8H, V8.H[2]
	sqdmulh	V26.8H, V19.8H, V8.H[2]
	sshr	V25.8H, V25.8H, #11
	sshr	V26.8H, V26.8H, #11
	mls	V17.8H, V25.8H, V8.H[0]
	mls	V19.8H, V26.8H, V8.H[0]
	sqdmulh	V25.8H, V21.8H, V8.H[2]
	sqdmulh	V26.8H, V23.8H, V8.H[2]
	sshr	V25.8H, V25.8H, #11
	sshr	V26.8H, V26.8H, #11
	mls	V21.8H, V25.8H, V8.H[0]
	mls	V23.8H, V26.8H, V8.H[0]
	stp	Q9, Q10, [x1]
	stp	Q11, Q12, [x1, #32]
	stp	Q13, Q14, [x1, #64]
	stp	Q15, Q16, [x1, #96]
	stp	Q17, Q18, [x1, #128]
	stp	Q19, Q20, [x1, #160]
	stp	Q21, Q22, [x1, #192]
	stp	Q23, Q24, [x1, #224]
	ldr	Q4, [x2, #544]
	ldr	Q5, [x2, #560]
	ldr	Q6, [x3, #544]
	ldr	Q7, [x3, #560]
	ldr	Q9, [x0]
	ldr	Q10, [x0, #32]
	ldr	Q11, [x0, #64]
	ldr	Q12, [x0, #96]
	ldr	Q13, [x0, #128]
	ldr	Q14, [x0, #160]
	ldr	Q15, [x0, #192]
	ldr	Q16, [x0, #224]
	ldr	Q17, [x1]
	ldr	Q18, [x1, #32]
	ldr	Q19, [x1, #64]
	ldr	Q20, [x1, #96]
	ldr	Q21, [x1, #128]
	ldr	Q22, [x1, #160]
	ldr	Q23, [x1, #192]
	ldr	Q24, [x1, #224]
	sub	V26.8H, V9.8H, V10.8H
	sub	V28.8H, V11.8H, V12.8H
	add	V9.8H, V9.8H, V10.8H
	add	V11.8H, V11.8H, V12.8H
	mul	V25.8H, V26.8H, V6.H[0]
	mul	V27.8H, V28.8H, V6.H[1]
	sqrdmulh	V10.8H, V26.8H, V4.H[0]
	sqrdmulh	V12.8H, V28.8H, V4.H[1]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V10.8H, V10.8H, V25.8H
	sub	V12.8H, V12.8H, V27.8H
	sshr	V10.8H, V10.8H, #1
	sshr	V12.8H, V12.8H, #1
	sub	V26.8H, V13.8H, V14.8H
	sub	V28.8H, V15.8H, V16.8H
	add	V13.8H, V13.8H, V14.8H
	add	V15.8H, V15.8H, V16.8H
	mul	V25.8H, V26.8H, V6.H[2]
	mul	V27.8H, V28.8H, V6.H[3]
	sqrdmulh	V14.8H, V26.8H, V4.H[2]
	sqrdmulh	V16.8H, V28.8H, V4.H[3]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V14.8H, V14.8H, V25.8H
	sub	V16.8H, V16.8H, V27.8H
	sshr	V14.8H, V14.8H, #1
	sshr	V16.8H, V16.8H, #1
	sub	V26.8H, V17.8H, V18.8H
	sub	V28.8H, V19.8H, V20.8H
	add	V17.8H, V17.8H, V18.8H
	add	V19.8H, V19.8H, V20.8H
	mul	V25.8H, V26.8H, V6.H[4]
	mul	V27.8H, V28.8H, V6.H[5]
	sqrdmulh	V18.8H, V26.8H, V4.H[4]
	sqrdmulh	V20.8H, V28.8H, V4.H[5]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V18.8H, V18.8H, V25.8H
	sub	V20.8H, V20.8H, V27.8H
	sshr	V18.8H, V18.8H, #1
	sshr	V20.8H, V20.8H, #1
	sub	V26.8H, V21.8H, V22.8H
	sub	V28.8H, V23.8H, V24.8H
	add	V21.8H, V21.8H, V22.8H
	add	V23.8H, V23.8H, V24.8H
	mul	V25.8H, V26.8H, V6.H[6]
	mul	V27.8H, V28.8H, V6.H[7]
	sqrdmulh	V22.8H, V26.8H, V4.H[6]
	sqrdmulh	V24.8H, V28.8H, V4.H[7]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V22.8H, V22.8H, V25.8H
	sub	V24.8H, V24.8H, V27.8H
	sshr	V22.8H, V22.8H, #1
	sshr	V24.8H, V24.8H, #1
	sub	V26.8H, V9.8H, V11.8H
	sub	V28.8H, V10.8H, V12.8H
	add	V9.8H, V9.8H, V11.8H
	add	V10.8H, V10.8H, V12.8H
	mul	V25.8H, V26.8H, V7.H[0]
	mul	V27.8H, V28.8H, V7.H[0]
	sqrdmulh	V11.8H, V26.8H, V5.H[0]
	sqrdmulh	V12.8H, V28.8H, V5.H[0]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V11.8H, V11.8H, V25.8H
	sub	V12.8H, V12.8H, V27.8H
	sshr	V11.8H, V11.8H, #1
	sshr	V12.8H, V12.8H, #1
	sub	V26.8H, V13.8H, V15.8H
	sub	V28.8H, V14.8H, V16.8H
	add	V13.8H, V13.8H, V15.8H
	add	V14.8H, V14.8H, V16.8H
	mul	V25.8H, V26.8H, V7.H[1]
	mul	V27.8H, V28.8H, V7.H[1]
	sqrdmulh	V15.8H, V26.8H, V5.H[1]
	sqrdmulh	V16.8H, V28.8H, V5.H[1]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V15.8H, V15.8H, V25.8H
	sub	V16.8H, V16.8H, V27.8H
	sshr	V15.8H, V15.8H, #1
	sshr	V16.8H, V16.8H, #1
	sub	V26.8H, V17.8H, V19.8H
	sub	V28.8H, V18.8H, V20.8H
	add	V17.8H, V17.8H, V19.8H
	add	V18.8H, V18.8H, V20.8H
	mul	V25.8H, V26.8H, V7.H[2]
	mul	V27.8H, V28.8H, V7.H[2]
	sqrdmulh	V19.8H, V26.8H, V5.H[2]
	sqrdmulh	V20.8H, V28.8H, V5.H[2]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V19.8H, V19.8H, V25.8H
	sub	V20.8H, V20.8H, V27.8H
	sshr	V19.8H, V19.8H, #1
	sshr	V20.8H, V20.8H, #1
	sub	V26.8H, V21.8H, V23.8H
	sub	V28.8H, V22.8H, V24.8H
	add	V21.8H, V21.8H, V23.8H
	add	V22.8H, V22.8H, V24.8H
	mul	V25.8H, V26.8H, V7.H[3]
	mul	V27.8H, V28.8H, V7.H[3]
	sqrdmulh	V23.8H, V26.8H, V5.H[3]
	sqrdmulh	V24.8H, V28.8H, V5.H[3]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V23.8H, V23.8H, V25.8H
	sub	V24.8H, V24.8H, V27.8H
	sshr	V23.8H, V23.8H, #1
	sshr	V24.8H, V24.8H, #1
	sub	V26.8H, V9.8H, V13.8H
	sub	V28.8H, V10.8H, V14.8H
	add	V9.8H, V9.8H, V13.8H
	add	V10.8H, V10.8H, V14.8H
	mul	V25.8H, V26.8H, V7.H[4]
	mul	V27.8H, V28.8H, V7.H[4]
	sqrdmulh	V13.8H, V26.8H, V5.H[4]
	sqrdmulh	V14.8H, V28.8H, V5.H[4]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V13.8H, V13.8H, V25.8H
	sub	V14.8H, V14.8H, V27.8H
	sshr	V13.8H, V13.8H, #1
	sshr	V14.8H, V14.8H, #1
	sub	V26.8H, V11.8H, V15.8H
	sub	V28.8H, V12.8H, V16.8H
	add	V11.8H, V11.8H, V15.8H
	add	V12.8H, V12.8H, V16.8H
	mul	V25.8H, V26.8H, V7.H[4]
	mul	V27.8H, V28.8H, V7.H[4]
	sqrdmulh	V15.8H, V26.8H, V5.H[4]
	sqrdmulh	V16.8H, V28.8H, V5.H[4]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V15.8H, V15.8H, V25.8H
	sub	V16.8H, V16.8H, V27.8H
	sshr	V15.8H, V15.8H, #1
	sshr	V16.8H, V16.8H, #1
	sub	V26.8H, V17.8H, V21.8H
	sub	V28.8H, V18.8H, V22.8H
	add	V17.8H, V17.8H, V21.8H
	add	V18.8H, V18.8H, V22.8H
	mul	V25.8H, V26.8H, V7.H[5]
	mul	V27.8H, V28.8H, V7.H[5]
	sqrdmulh	V21.8H, V26.8H, V5.H[5]
	sqrdmulh	V22.8H, V28.8H, V5.H[5]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V21.8H, V21.8H, V25.8H
	sub	V22.8H, V22.8H, V27.8H
	sshr	V21.8H, V21.8H, #1
	sshr	V22.8H, V22.8H, #1
	sub	V26.8H, V19.8H, V23.8H
	sub	V28.8H, V20.8H, V24.8H
	add	V19.8H, V19.8H, V23.8H
	add	V20.8H, V20.8H, V24.8H
	mul	V25.8H, V26.8H, V7.H[5]
	mul	V27.8H, V28.8H, V7.H[5]
	sqrdmulh	V23.8H, V26.8H, V5.H[5]
	sqrdmulh	V24.8H, V28.8H, V5.H[5]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V23.8H, V23.8H, V25.8H
	sub	V24.8H, V24.8H, V27.8H
	sshr	V23.8H, V23.8H, #1
	sshr	V24.8H, V24.8H, #1
	sqdmulh	V25.8H, V9.8H, V8.H[2]
	sqdmulh	V26.8H, V10.8H, V8.H[2]
	sshr	V25.8H, V25.8H, #11
	sshr	V26.8H, V26.8H, #11
	mls	V9.8H, V25.8H, V8.H[0]
	mls	V10.8H, V26.8H, V8.H[0]
	sqdmulh	V25.8H, V11.8H, V8.H[2]
	sqdmulh	V26.8H, V12.8H, V8.H[2]
	sshr	V25.8H, V25.8H, #11
	sshr	V26.8H, V26.8H, #11
	mls	V11.8H, V25.8H, V8.H[0]
	mls	V12.8H, V26.8H, V8.H[0]
	sqdmulh	V25.8H, V17.8H, V8.H[2]
	sqdmulh	V26.8H, V18.8H, V8.H[2]
	sshr	V25.8H, V25.8H, #11
	sshr	V26.8H, V26.8H, #11
	mls	V17.8H, V25.8H, V8.H[0]
	mls	V18.8H, V26.8H, V8.H[0]
	sqdmulh	V25.8H, V19.8H, V8.H[2]
	sqdmulh	V26.8H, V20.8H, V8.H[2]
	sshr	V25.8H, V25.8H, #11
	sshr	V26.8H, V26.8H, #11
	mls	V19.8H, V25.8H, V8.H[0]
	mls	V20.8H, V26.8H, V8.H[0]
	sub	V26.8H, V9.8H, V17.8H
	sub	V28.8H, V10.8H, V18.8H
	add	V9.8H, V9.8H, V17.8H
	add	V10.8H, V10.8H, V18.8H
	mul	V25.8H, V26.8H, V7.H[6]
	mul	V27.8H, V28.8H, V7.H[6]
	sqrdmulh	V17.8H, V26.8H, V5.H[6]
	sqrdmulh	V18.8H, V28.8H, V5.H[6]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V17.8H, V17.8H, V25.8H
	sub	V18.8H, V18.8H, V27.8H
	sshr	V17.8H, V17.8H, #1
	sshr	V18.8H, V18.8H, #1
	sub	V26.8H, V11.8H, V19.8H
	sub	V28.8H, V12.8H, V20.8H
	add	V11.8H, V11.8H, V19.8H
	add	V12.8H, V12.8H, V20.8H
	mul	V25.8H, V26.8H, V7.H[6]
	mul	V27.8H, V28.8H, V7.H[6]
	sqrdmulh	V19.8H, V26.8H, V5.H[6]
	sqrdmulh	V20.8H, V28.8H, V5.H[6]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V19.8H, V19.8H, V25.8H
	sub	V20.8H, V20.8H, V27.8H
	sshr	V19.8H, V19.8H, #1
	sshr	V20.8H, V20.8H, #1
	sub	V26.8H, V13.8H, V21.8H
	sub	V28.8H, V14.8H, V22.8H
	add	V13.8H, V13.8H, V21.8H
	add	V14.8H, V14.8H, V22.8H
	mul	V25.8H, V26.8H, V7.H[6]
	mul	V27.8H, V28.8H, V7.H[6]
	sqrdmulh	V21.8H, V26.8H, V5.H[6]
	sqrdmulh	V22.8H, V28.8H, V5.H[6]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V21.8H, V21.8H, V25.8H
	sub	V22.8H, V22.8H, V27.8H
	sshr	V21.8H, V21.8H, #1
	sshr	V22.8H, V22.8H, #1
	sub	V26.8H, V15.8H, V23.8H
	sub	V28.8H, V16.8H, V24.8H
	add	V15.8H, V15.8H, V23.8H
	add	V16.8H, V16.8H, V24.8H
	mul	V25.8H, V26.8H, V7.H[6]
	mul	V27.8H, V28.8H, V7.H[6]
	sqrdmulh	V23.8H, V26.8H, V5.H[6]
	sqrdmulh	V24.8H, V28.8H, V5.H[6]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V23.8H, V23.8H, V25.8H
	sub	V24.8H, V24.8H, V27.8H
	sshr	V23.8H, V23.8H, #1
	sshr	V24.8H, V24.8H, #1
	mul	V25.8H, V9.8H, V7.H[7]
	mul	V26.8H, V10.8H, V7.H[7]
	sqrdmulh	V9.8H, V9.8H, V5.H[7]
	sqrdmulh	V10.8H, V10.8H, V5.H[7]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V26.8H, V26.8H, V8.H[0]
	sub	V9.8H, V9.8H, V25.8H
	sub	V10.8H, V10.8H, V26.8H
	sshr	V9.8H, V9.8H, #1
	sshr	V10.8H, V10.8H, #1
	mul	V25.8H, V11.8H, V7.H[7]
	mul	V26.8H, V12.8H, V7.H[7]
	sqrdmulh	V11.8H, V11.8H, V5.H[7]
	sqrdmulh	V12.8H, V12.8H, V5.H[7]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V26.8H, V26.8H, V8.H[0]
	sub	V11.8H, V11.8H, V25.8H
	sub	V12.8H, V12.8H, V26.8H
	sshr	V11.8H, V11.8H, #1
	sshr	V12.8H, V12.8H, #1
	mul	V25.8H, V13.8H, V7.H[7]
	mul	V26.8H, V14.8H, V7.H[7]
	sqrdmulh	V13.8H, V13.8H, V5.H[7]
	sqrdmulh	V14.8H, V14.8H, V5.H[7]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V26.8H, V26.8H, V8.H[0]
	sub	V13.8H, V13.8H, V25.8H
	sub	V14.8H, V14.8H, V26.8H
	sshr	V13.8H, V13.8H, #1
	sshr	V14.8H, V14.8H, #1
	mul	V25.8H, V15.8H, V7.H[7]
	mul	V26.8H, V16.8H, V7.H[7]
	sqrdmulh	V15.8H, V15.8H, V5.H[7]
	sqrdmulh	V16.8H, V16.8H, V5.H[7]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V26.8H, V26.8H, V8.H[0]
	sub	V15.8H, V15.8H, V25.8H
	sub	V16.8H, V16.8H, V26.8H
	sshr	V15.8H, V15.8H, #1
	sshr	V16.8H, V16.8H, #1
	mul	V25.8H, V17.8H, V7.H[7]
	mul	V26.8H, V18.8H, V7.H[7]
	sqrdmulh	V17.8H, V17.8H, V5.H[7]
	sqrdmulh	V18.8H, V18.8H, V5.H[7]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V26.8H, V26.8H, V8.H[0]
	sub	V17.8H, V17.8H, V25.8H
	sub	V18.8H, V18.8H, V26.8H
	sshr	V17.8H, V17.8H, #1
	sshr	V18.8H, V18.8H, #1
	mul	V25.8H, V19.8H, V7.H[7]
	mul	V26.8H, V20.8H, V7.H[7]
	sqrdmulh	V19.8H, V19.8H, V5.H[7]
	sqrdmulh	V20.8H, V20.8H, V5.H[7]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V26.8H, V26.8H, V8.H[0]
	sub	V19.8H, V19.8H, V25.8H
	sub	V20.8H, V20.8H, V26.8H
	sshr	V19.8H, V19.8H, #1
	sshr	V20.8H, V20.8H, #1
	mul	V25.8H, V21.8H, V7.H[7]
	mul	V26.8H, V22.8H, V7.H[7]
	sqrdmulh	V21.8H, V21.8H, V5.H[7]
	sqrdmulh	V22.8H, V22.8H, V5.H[7]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V26.8H, V26.8H, V8.H[0]
	sub	V21.8H, V21.8H, V25.8H
	sub	V22.8H, V22.8H, V26.8H
	sshr	V21.8H, V21.8H, #1
	sshr	V22.8H, V22.8H, #1
	mul	V25.8H, V23.8H, V7.H[7]
	mul	V26.8H, V24.8H, V7.H[7]
	sqrdmulh	V23.8H, V23.8H, V5.H[7]
	sqrdmulh	V24.8H, V24.8H, V5.H[7]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V26.8H, V26.8H, V8.H[0]
	sub	V23.8H, V23.8H, V25.8H
	sub	V24.8H, V24.8H, V26.8H
	sshr	V23.8H, V23.8H, #1
	sshr	V24.8H, V24.8H, #1
	str	Q9, [x0]
	str	Q10, [x0, #32]
	str	Q11, [x0, #64]
	str	Q12, [x0, #96]
	str	Q13, [x0, #128]
	str	Q14, [x0, #160]
	str	Q15, [x0, #192]
	str	Q16, [x0, #224]
	str	Q17, [x1]
	str	Q18, [x1, #32]
	str	Q19, [x1, #64]
	str	Q20, [x1, #96]
	str	Q21, [x1, #128]
	str	Q22, [x1, #160]
	str	Q23, [x1, #192]
	str	Q24, [x1, #224]
	ldr	Q9, [x0, #16]
	ldr	Q10, [x0, #48]
	ldr	Q11, [x0, #80]
	ldr	Q12, [x0, #112]
	ldr	Q13, [x0, #144]
	ldr	Q14, [x0, #176]
	ldr	Q15, [x0, #208]
	ldr	Q16, [x0, #240]
	ldr	Q17, [x1, #16]
	ldr	Q18, [x1, #48]
	ldr	Q19, [x1, #80]
	ldr	Q20, [x1, #112]
	ldr	Q21, [x1, #144]
	ldr	Q22, [x1, #176]
	ldr	Q23, [x1, #208]
	ldr	Q24, [x1, #240]
	sub	V26.8H, V9.8H, V10.8H
	sub	V28.8H, V11.8H, V12.8H
	add	V9.8H, V9.8H, V10.8H
	add	V11.8H, V11.8H, V12.8H
	mul	V25.8H, V26.8H, V6.H[0]
	mul	V27.8H, V28.8H, V6.H[1]
	sqrdmulh	V10.8H, V26.8H, V4.H[0]
	sqrdmulh	V12.8H, V28.8H, V4.H[1]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V10.8H, V10.8H, V25.8H
	sub	V12.8H, V12.8H, V27.8H
	sshr	V10.8H, V10.8H, #1
	sshr	V12.8H, V12.8H, #1
	sub	V26.8H, V13.8H, V14.8H
	sub	V28.8H, V15.8H, V16.8H
	add	V13.8H, V13.8H, V14.8H
	add	V15.8H, V15.8H, V16.8H
	mul	V25.8H, V26.8H, V6.H[2]
	mul	V27.8H, V28.8H, V6.H[3]
	sqrdmulh	V14.8H, V26.8H, V4.H[2]
	sqrdmulh	V16.8H, V28.8H, V4.H[3]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V14.8H, V14.8H, V25.8H
	sub	V16.8H, V16.8H, V27.8H
	sshr	V14.8H, V14.8H, #1
	sshr	V16.8H, V16.8H, #1
	sub	V26.8H, V17.8H, V18.8H
	sub	V28.8H, V19.8H, V20.8H
	add	V17.8H, V17.8H, V18.8H
	add	V19.8H, V19.8H, V20.8H
	mul	V25.8H, V26.8H, V6.H[4]
	mul	V27.8H, V28.8H, V6.H[5]
	sqrdmulh	V18.8H, V26.8H, V4.H[4]
	sqrdmulh	V20.8H, V28.8H, V4.H[5]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V18.8H, V18.8H, V25.8H
	sub	V20.8H, V20.8H, V27.8H
	sshr	V18.8H, V18.8H, #1
	sshr	V20.8H, V20.8H, #1
	sub	V26.8H, V21.8H, V22.8H
	sub	V28.8H, V23.8H, V24.8H
	add	V21.8H, V21.8H, V22.8H
	add	V23.8H, V23.8H, V24.8H
	mul	V25.8H, V26.8H, V6.H[6]
	mul	V27.8H, V28.8H, V6.H[7]
	sqrdmulh	V22.8H, V26.8H, V4.H[6]
	sqrdmulh	V24.8H, V28.8H, V4.H[7]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V22.8H, V22.8H, V25.8H
	sub	V24.8H, V24.8H, V27.8H
	sshr	V22.8H, V22.8H, #1
	sshr	V24.8H, V24.8H, #1
	sub	V26.8H, V9.8H, V11.8H
	sub	V28.8H, V10.8H, V12.8H
	add	V9.8H, V9.8H, V11.8H
	add	V10.8H, V10.8H, V12.8H
	mul	V25.8H, V26.8H, V7.H[0]
	mul	V27.8H, V28.8H, V7.H[0]
	sqrdmulh	V11.8H, V26.8H, V5.H[0]
	sqrdmulh	V12.8H, V28.8H, V5.H[0]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V11.8H, V11.8H, V25.8H
	sub	V12.8H, V12.8H, V27.8H
	sshr	V11.8H, V11.8H, #1
	sshr	V12.8H, V12.8H, #1
	sub	V26.8H, V13.8H, V15.8H
	sub	V28.8H, V14.8H, V16.8H
	add	V13.8H, V13.8H, V15.8H
	add	V14.8H, V14.8H, V16.8H
	mul	V25.8H, V26.8H, V7.H[1]
	mul	V27.8H, V28.8H, V7.H[1]
	sqrdmulh	V15.8H, V26.8H, V5.H[1]
	sqrdmulh	V16.8H, V28.8H, V5.H[1]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V15.8H, V15.8H, V25.8H
	sub	V16.8H, V16.8H, V27.8H
	sshr	V15.8H, V15.8H, #1
	sshr	V16.8H, V16.8H, #1
	sub	V26.8H, V17.8H, V19.8H
	sub	V28.8H, V18.8H, V20.8H
	add	V17.8H, V17.8H, V19.8H
	add	V18.8H, V18.8H, V20.8H
	mul	V25.8H, V26.8H, V7.H[2]
	mul	V27.8H, V28.8H, V7.H[2]
	sqrdmulh	V19.8H, V26.8H, V5.H[2]
	sqrdmulh	V20.8H, V28.8H, V5.H[2]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V19.8H, V19.8H, V25.8H
	sub	V20.8H, V20.8H, V27.8H
	sshr	V19.8H, V19.8H, #1
	sshr	V20.8H, V20.8H, #1
	sub	V26.8H, V21.8H, V23.8H
	sub	V28.8H, V22.8H, V24.8H
	add	V21.8H, V21.8H, V23.8H
	add	V22.8H, V22.8H, V24.8H
	mul	V25.8H, V26.8H, V7.H[3]
	mul	V27.8H, V28.8H, V7.H[3]
	sqrdmulh	V23.8H, V26.8H, V5.H[3]
	sqrdmulh	V24.8H, V28.8H, V5.H[3]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V23.8H, V23.8H, V25.8H
	sub	V24.8H, V24.8H, V27.8H
	sshr	V23.8H, V23.8H, #1
	sshr	V24.8H, V24.8H, #1
	sub	V26.8H, V9.8H, V13.8H
	sub	V28.8H, V10.8H, V14.8H
	add	V9.8H, V9.8H, V13.8H
	add	V10.8H, V10.8H, V14.8H
	mul	V25.8H, V26.8H, V7.H[4]
	mul	V27.8H, V28.8H, V7.H[4]
	sqrdmulh	V13.8H, V26.8H, V5.H[4]
	sqrdmulh	V14.8H, V28.8H, V5.H[4]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V13.8H, V13.8H, V25.8H
	sub	V14.8H, V14.8H, V27.8H
	sshr	V13.8H, V13.8H, #1
	sshr	V14.8H, V14.8H, #1
	sub	V26.8H, V11.8H, V15.8H
	sub	V28.8H, V12.8H, V16.8H
	add	V11.8H, V11.8H, V15.8H
	add	V12.8H, V12.8H, V16.8H
	mul	V25.8H, V26.8H, V7.H[4]
	mul	V27.8H, V28.8H, V7.H[4]
	sqrdmulh	V15.8H, V26.8H, V5.H[4]
	sqrdmulh	V16.8H, V28.8H, V5.H[4]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V15.8H, V15.8H, V25.8H
	sub	V16.8H, V16.8H, V27.8H
	sshr	V15.8H, V15.8H, #1
	sshr	V16.8H, V16.8H, #1
	sub	V26.8H, V17.8H, V21.8H
	sub	V28.8H, V18.8H, V22.8H
	add	V17.8H, V17.8H, V21.8H
	add	V18.8H, V18.8H, V22.8H
	mul	V25.8H, V26.8H, V7.H[5]
	mul	V27.8H, V28.8H, V7.H[5]
	sqrdmulh	V21.8H, V26.8H, V5.H[5]
	sqrdmulh	V22.8H, V28.8H, V5.H[5]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V21.8H, V21.8H, V25.8H
	sub	V22.8H, V22.8H, V27.8H
	sshr	V21.8H, V21.8H, #1
	sshr	V22.8H, V22.8H, #1
	sub	V26.8H, V19.8H, V23.8H
	sub	V28.8H, V20.8H, V24.8H
	add	V19.8H, V19.8H, V23.8H
	add	V20.8H, V20.8H, V24.8H
	mul	V25.8H, V26.8H, V7.H[5]
	mul	V27.8H, V28.8H, V7.H[5]
	sqrdmulh	V23.8H, V26.8H, V5.H[5]
	sqrdmulh	V24.8H, V28.8H, V5.H[5]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V23.8H, V23.8H, V25.8H
	sub	V24.8H, V24.8H, V27.8H
	sshr	V23.8H, V23.8H, #1
	sshr	V24.8H, V24.8H, #1
	sqdmulh	V25.8H, V9.8H, V8.H[2]
	sqdmulh	V26.8H, V10.8H, V8.H[2]
	sshr	V25.8H, V25.8H, #11
	sshr	V26.8H, V26.8H, #11
	mls	V9.8H, V25.8H, V8.H[0]
	mls	V10.8H, V26.8H, V8.H[0]
	sqdmulh	V25.8H, V11.8H, V8.H[2]
	sqdmulh	V26.8H, V12.8H, V8.H[2]
	sshr	V25.8H, V25.8H, #11
	sshr	V26.8H, V26.8H, #11
	mls	V11.8H, V25.8H, V8.H[0]
	mls	V12.8H, V26.8H, V8.H[0]
	sqdmulh	V25.8H, V17.8H, V8.H[2]
	sqdmulh	V26.8H, V18.8H, V8.H[2]
	sshr	V25.8H, V25.8H, #11
	sshr	V26.8H, V26.8H, #11
	mls	V17.8H, V25.8H, V8.H[0]
	mls	V18.8H, V26.8H, V8.H[0]
	sqdmulh	V25.8H, V19.8H, V8.H[2]
	sqdmulh	V26.8H, V20.8H, V8.H[2]
	sshr	V25.8H, V25.8H, #11
	sshr	V26.8H, V26.8H, #11
	mls	V19.8H, V25.8H, V8.H[0]
	mls	V20.8H, V26.8H, V8.H[0]
	sub	V26.8H, V9.8H, V17.8H
	sub	V28.8H, V10.8H, V18.8H
	add	V9.8H, V9.8H, V17.8H
	add	V10.8H, V10.8H, V18.8H
	mul	V25.8H, V26.8H, V7.H[6]
	mul	V27.8H, V28.8H, V7.H[6]
	sqrdmulh	V17.8H, V26.8H, V5.H[6]
	sqrdmulh	V18.8H, V28.8H, V5.H[6]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V17.8H, V17.8H, V25.8H
	sub	V18.8H, V18.8H, V27.8H
	sshr	V17.8H, V17.8H, #1
	sshr	V18.8H, V18.8H, #1
	sub	V26.8H, V11.8H, V19.8H
	sub	V28.8H, V12.8H, V20.8H
	add	V11.8H, V11.8H, V19.8H
	add	V12.8H, V12.8H, V20.8H
	mul	V25.8H, V26.8H, V7.H[6]
	mul	V27.8H, V28.8H, V7.H[6]
	sqrdmulh	V19.8H, V26.8H, V5.H[6]
	sqrdmulh	V20.8H, V28.8H, V5.H[6]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V19.8H, V19.8H, V25.8H
	sub	V20.8H, V20.8H, V27.8H
	sshr	V19.8H, V19.8H, #1
	sshr	V20.8H, V20.8H, #1
	sub	V26.8H, V13.8H, V21.8H
	sub	V28.8H, V14.8H, V22.8H
	add	V13.8H, V13.8H, V21.8H
	add	V14.8H, V14.8H, V22.8H
	mul	V25.8H, V26.8H, V7.H[6]
	mul	V27.8H, V28.8H, V7.H[6]
	sqrdmulh	V21.8H, V26.8H, V5.H[6]
	sqrdmulh	V22.8H, V28.8H, V5.H[6]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V21.8H, V21.8H, V25.8H
	sub	V22.8H, V22.8H, V27.8H
	sshr	V21.8H, V21.8H, #1
	sshr	V22.8H, V22.8H, #1
	sub	V26.8H, V15.8H, V23.8H
	sub	V28.8H, V16.8H, V24.8H
	add	V15.8H, V15.8H, V23.8H
	add	V16.8H, V16.8H, V24.8H
	mul	V25.8H, V26.8H, V7.H[6]
	mul	V27.8H, V28.8H, V7.H[6]
	sqrdmulh	V23.8H, V26.8H, V5.H[6]
	sqrdmulh	V24.8H, V28.8H, V5.H[6]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V27.8H, V27.8H, V8.H[0]
	sub	V23.8H, V23.8H, V25.8H
	sub	V24.8H, V24.8H, V27.8H
	sshr	V23.8H, V23.8H, #1
	sshr	V24.8H, V24.8H, #1
	mul	V25.8H, V9.8H, V7.H[7]
	mul	V26.8H, V10.8H, V7.H[7]
	sqrdmulh	V9.8H, V9.8H, V5.H[7]
	sqrdmulh	V10.8H, V10.8H, V5.H[7]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V26.8H, V26.8H, V8.H[0]
	sub	V9.8H, V9.8H, V25.8H
	sub	V10.8H, V10.8H, V26.8H
	sshr	V9.8H, V9.8H, #1
	sshr	V10.8H, V10.8H, #1
	mul	V25.8H, V11.8H, V7.H[7]
	mul	V26.8H, V12.8H, V7.H[7]
	sqrdmulh	V11.8H, V11.8H, V5.H[7]
	sqrdmulh	V12.8H, V12.8H, V5.H[7]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V26.8H, V26.8H, V8.H[0]
	sub	V11.8H, V11.8H, V25.8H
	sub	V12.8H, V12.8H, V26.8H
	sshr	V11.8H, V11.8H, #1
	sshr	V12.8H, V12.8H, #1
	mul	V25.8H, V13.8H, V7.H[7]
	mul	V26.8H, V14.8H, V7.H[7]
	sqrdmulh	V13.8H, V13.8H, V5.H[7]
	sqrdmulh	V14.8H, V14.8H, V5.H[7]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V26.8H, V26.8H, V8.H[0]
	sub	V13.8H, V13.8H, V25.8H
	sub	V14.8H, V14.8H, V26.8H
	sshr	V13.8H, V13.8H, #1
	sshr	V14.8H, V14.8H, #1
	mul	V25.8H, V15.8H, V7.H[7]
	mul	V26.8H, V16.8H, V7.H[7]
	sqrdmulh	V15.8H, V15.8H, V5.H[7]
	sqrdmulh	V16.8H, V16.8H, V5.H[7]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V26.8H, V26.8H, V8.H[0]
	sub	V15.8H, V15.8H, V25.8H
	sub	V16.8H, V16.8H, V26.8H
	sshr	V15.8H, V15.8H, #1
	sshr	V16.8H, V16.8H, #1
	mul	V25.8H, V17.8H, V7.H[7]
	mul	V26.8H, V18.8H, V7.H[7]
	sqrdmulh	V17.8H, V17.8H, V5.H[7]
	sqrdmulh	V18.8H, V18.8H, V5.H[7]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V26.8H, V26.8H, V8.H[0]
	sub	V17.8H, V17.8H, V25.8H
	sub	V18.8H, V18.8H, V26.8H
	sshr	V17.8H, V17.8H, #1
	sshr	V18.8H, V18.8H, #1
	mul	V25.8H, V19.8H, V7.H[7]
	mul	V26.8H, V20.8H, V7.H[7]
	sqrdmulh	V19.8H, V19.8H, V5.H[7]
	sqrdmulh	V20.8H, V20.8H, V5.H[7]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V26.8H, V26.8H, V8.H[0]
	sub	V19.8H, V19.8H, V25.8H
	sub	V20.8H, V20.8H, V26.8H
	sshr	V19.8H, V19.8H, #1
	sshr	V20.8H, V20.8H, #1
	mul	V25.8H, V21.8H, V7.H[7]
	mul	V26.8H, V22.8H, V7.H[7]
	sqrdmulh	V21.8H, V21.8H, V5.H[7]
	sqrdmulh	V22.8H, V22.8H, V5.H[7]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V26.8H, V26.8H, V8.H[0]
	sub	V21.8H, V21.8H, V25.8H
	sub	V22.8H, V22.8H, V26.8H
	sshr	V21.8H, V21.8H, #1
	sshr	V22.8H, V22.8H, #1
	mul	V25.8H, V23.8H, V7.H[7]
	mul	V26.8H, V24.8H, V7.H[7]
	sqrdmulh	V23.8H, V23.8H, V5.H[7]
	sqrdmulh	V24.8H, V24.8H, V5.H[7]
	sqrdmulh	V25.8H, V25.8H, V8.H[0]
	sqrdmulh	V26.8H, V26.8H, V8.H[0]
	sub	V23.8H, V23.8H, V25.8H
	sub	V24.8H, V24.8H, V26.8H
	sshr	V23.8H, V23.8H, #1
	sshr	V24.8H, V24.8H, #1
	str	Q9, [x0, #16]
	str	Q10, [x0, #48]
	str	Q11, [x0, #80]
	str	Q12, [x0, #112]
	str	Q13, [x0, #144]
	str	Q14, [x0, #176]
	str	Q15, [x0, #208]
	str	Q16, [x0, #240]
	str	Q17, [x1, #16]
	str	Q18, [x1, #48]
	str	Q19, [x1, #80]
	str	Q20, [x1, #112]
	str	Q21, [x1, #144]
	str	Q22, [x1, #176]
	str	Q23, [x1, #208]
	str	Q24, [x1, #240]
	ldp	D8, D9, [x29, #16]
	ldp	D10, D11, [x29, #32]
	ldp	D12, D13, [x29, #48]
	ldp	D14, D15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
	ENDP
	IF :LNOT::DEF:WOLFSSL_AARCH64_NO_SQRDMLSH
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mlkem_ntt_sqrdmlsh
mlkem_ntt_sqrdmlsh PROC
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	stp	D10, D11, [x29, #32]
	stp	D12, D13, [x29, #48]
	stp	D14, D15, [x29, #64]
	adrp	x2, L_mlkem_aarch64_zetas
	add	x2, x2, L_mlkem_aarch64_zetas
	adrp	x3, L_mlkem_aarch64_zetas_qinv
	add	x3, x3, L_mlkem_aarch64_zetas_qinv
	adrp	x4, L_mlkem_aarch64_consts
	add	x4, x4, L_mlkem_aarch64_consts
	add	x1, x0, #0x100
	ldr	Q4, [x4]
	ldr	Q5, [x0]
	ldr	Q6, [x0, #32]
	ldr	Q7, [x0, #64]
	ldr	Q8, [x0, #96]
	ldr	Q9, [x0, #128]
	ldr	Q10, [x0, #160]
	ldr	Q11, [x0, #192]
	ldr	Q12, [x0, #224]
	ldr	Q13, [x1]
	ldr	Q14, [x1, #32]
	ldr	Q15, [x1, #64]
	ldr	Q16, [x1, #96]
	ldr	Q17, [x1, #128]
	ldr	Q18, [x1, #160]
	ldr	Q19, [x1, #192]
	ldr	Q20, [x1, #224]
	ldr	Q0, [x2]
	ldr	Q1, [x3]
	mul	V29.8H, V13.8H, V1.H[1]
	mul	V30.8H, V14.8H, V1.H[1]
	sqrdmulh	V21.8H, V13.8H, V0.H[1]
	sqrdmulh	V22.8H, V14.8H, V0.H[1]
	sqrdmlsh	V21.8H, V29.8H, V4.H[0]
	sqrdmlsh	V22.8H, V30.8H, V4.H[0]
	sshr	V21.8H, V21.8H, #1
	sshr	V22.8H, V22.8H, #1
	mul	V29.8H, V15.8H, V1.H[1]
	mul	V30.8H, V16.8H, V1.H[1]
	sqrdmulh	V23.8H, V15.8H, V0.H[1]
	sqrdmulh	V24.8H, V16.8H, V0.H[1]
	sqrdmlsh	V23.8H, V29.8H, V4.H[0]
	sqrdmlsh	V24.8H, V30.8H, V4.H[0]
	sshr	V23.8H, V23.8H, #1
	sshr	V24.8H, V24.8H, #1
	mul	V29.8H, V17.8H, V1.H[1]
	mul	V30.8H, V18.8H, V1.H[1]
	sqrdmulh	V25.8H, V17.8H, V0.H[1]
	sqrdmulh	V26.8H, V18.8H, V0.H[1]
	sqrdmlsh	V25.8H, V29.8H, V4.H[0]
	sqrdmlsh	V26.8H, V30.8H, V4.H[0]
	sshr	V25.8H, V25.8H, #1
	sshr	V26.8H, V26.8H, #1
	mul	V29.8H, V19.8H, V1.H[1]
	mul	V30.8H, V20.8H, V1.H[1]
	sqrdmulh	V27.8H, V19.8H, V0.H[1]
	sqrdmulh	V28.8H, V20.8H, V0.H[1]
	sqrdmlsh	V27.8H, V29.8H, V4.H[0]
	sqrdmlsh	V28.8H, V30.8H, V4.H[0]
	sshr	V27.8H, V27.8H, #1
	sshr	V28.8H, V28.8H, #1
	sub	V13.8H, V5.8H, V21.8H
	add	V5.8H, V5.8H, V21.8H
	sub	V14.8H, V6.8H, V22.8H
	add	V6.8H, V6.8H, V22.8H
	sub	V15.8H, V7.8H, V23.8H
	add	V7.8H, V7.8H, V23.8H
	sub	V16.8H, V8.8H, V24.8H
	add	V8.8H, V8.8H, V24.8H
	sub	V17.8H, V9.8H, V25.8H
	add	V9.8H, V9.8H, V25.8H
	sub	V18.8H, V10.8H, V26.8H
	add	V10.8H, V10.8H, V26.8H
	sub	V19.8H, V11.8H, V27.8H
	add	V11.8H, V11.8H, V27.8H
	sub	V20.8H, V12.8H, V28.8H
	add	V12.8H, V12.8H, V28.8H
	mul	V29.8H, V9.8H, V1.H[2]
	mul	V30.8H, V10.8H, V1.H[2]
	sqrdmulh	V21.8H, V9.8H, V0.H[2]
	sqrdmulh	V22.8H, V10.8H, V0.H[2]
	sqrdmlsh	V21.8H, V29.8H, V4.H[0]
	sqrdmlsh	V22.8H, V30.8H, V4.H[0]
	sshr	V21.8H, V21.8H, #1
	sshr	V22.8H, V22.8H, #1
	mul	V29.8H, V11.8H, V1.H[2]
	mul	V30.8H, V12.8H, V1.H[2]
	sqrdmulh	V23.8H, V11.8H, V0.H[2]
	sqrdmulh	V24.8H, V12.8H, V0.H[2]
	sqrdmlsh	V23.8H, V29.8H, V4.H[0]
	sqrdmlsh	V24.8H, V30.8H, V4.H[0]
	sshr	V23.8H, V23.8H, #1
	sshr	V24.8H, V24.8H, #1
	mul	V29.8H, V17.8H, V1.H[3]
	mul	V30.8H, V18.8H, V1.H[3]
	sqrdmulh	V25.8H, V17.8H, V0.H[3]
	sqrdmulh	V26.8H, V18.8H, V0.H[3]
	sqrdmlsh	V25.8H, V29.8H, V4.H[0]
	sqrdmlsh	V26.8H, V30.8H, V4.H[0]
	sshr	V25.8H, V25.8H, #1
	sshr	V26.8H, V26.8H, #1
	mul	V29.8H, V19.8H, V1.H[3]
	mul	V30.8H, V20.8H, V1.H[3]
	sqrdmulh	V27.8H, V19.8H, V0.H[3]
	sqrdmulh	V28.8H, V20.8H, V0.H[3]
	sqrdmlsh	V27.8H, V29.8H, V4.H[0]
	sqrdmlsh	V28.8H, V30.8H, V4.H[0]
	sshr	V27.8H, V27.8H, #1
	sshr	V28.8H, V28.8H, #1
	sub	V9.8H, V5.8H, V21.8H
	add	V5.8H, V5.8H, V21.8H
	sub	V10.8H, V6.8H, V22.8H
	add	V6.8H, V6.8H, V22.8H
	sub	V11.8H, V7.8H, V23.8H
	add	V7.8H, V7.8H, V23.8H
	sub	V12.8H, V8.8H, V24.8H
	add	V8.8H, V8.8H, V24.8H
	sub	V17.8H, V13.8H, V25.8H
	add	V13.8H, V13.8H, V25.8H
	sub	V18.8H, V14.8H, V26.8H
	add	V14.8H, V14.8H, V26.8H
	sub	V19.8H, V15.8H, V27.8H
	add	V15.8H, V15.8H, V27.8H
	sub	V20.8H, V16.8H, V28.8H
	add	V16.8H, V16.8H, V28.8H
	mul	V29.8H, V7.8H, V1.H[4]
	mul	V30.8H, V8.8H, V1.H[4]
	sqrdmulh	V21.8H, V7.8H, V0.H[4]
	sqrdmulh	V22.8H, V8.8H, V0.H[4]
	sqrdmlsh	V21.8H, V29.8H, V4.H[0]
	sqrdmlsh	V22.8H, V30.8H, V4.H[0]
	sshr	V21.8H, V21.8H, #1
	sshr	V22.8H, V22.8H, #1
	mul	V29.8H, V11.8H, V1.H[5]
	mul	V30.8H, V12.8H, V1.H[5]
	sqrdmulh	V23.8H, V11.8H, V0.H[5]
	sqrdmulh	V24.8H, V12.8H, V0.H[5]
	sqrdmlsh	V23.8H, V29.8H, V4.H[0]
	sqrdmlsh	V24.8H, V30.8H, V4.H[0]
	sshr	V23.8H, V23.8H, #1
	sshr	V24.8H, V24.8H, #1
	mul	V29.8H, V15.8H, V1.H[6]
	mul	V30.8H, V16.8H, V1.H[6]
	sqrdmulh	V25.8H, V15.8H, V0.H[6]
	sqrdmulh	V26.8H, V16.8H, V0.H[6]
	sqrdmlsh	V25.8H, V29.8H, V4.H[0]
	sqrdmlsh	V26.8H, V30.8H, V4.H[0]
	sshr	V25.8H, V25.8H, #1
	sshr	V26.8H, V26.8H, #1
	mul	V29.8H, V19.8H, V1.H[7]
	mul	V30.8H, V20.8H, V1.H[7]
	sqrdmulh	V27.8H, V19.8H, V0.H[7]
	sqrdmulh	V28.8H, V20.8H, V0.H[7]
	sqrdmlsh	V27.8H, V29.8H, V4.H[0]
	sqrdmlsh	V28.8H, V30.8H, V4.H[0]
	sshr	V27.8H, V27.8H, #1
	sshr	V28.8H, V28.8H, #1
	sub	V7.8H, V5.8H, V21.8H
	add	V5.8H, V5.8H, V21.8H
	sub	V8.8H, V6.8H, V22.8H
	add	V6.8H, V6.8H, V22.8H
	sub	V11.8H, V9.8H, V23.8H
	add	V9.8H, V9.8H, V23.8H
	sub	V12.8H, V10.8H, V24.8H
	add	V10.8H, V10.8H, V24.8H
	sub	V15.8H, V13.8H, V25.8H
	add	V13.8H, V13.8H, V25.8H
	sub	V16.8H, V14.8H, V26.8H
	add	V14.8H, V14.8H, V26.8H
	sub	V19.8H, V17.8H, V27.8H
	add	V17.8H, V17.8H, V27.8H
	sub	V20.8H, V18.8H, V28.8H
	add	V18.8H, V18.8H, V28.8H
	ldr	Q0, [x2, #16]
	ldr	Q1, [x3, #16]
	mul	V29.8H, V6.8H, V1.H[0]
	mul	V30.8H, V8.8H, V1.H[1]
	sqrdmulh	V21.8H, V6.8H, V0.H[0]
	sqrdmulh	V22.8H, V8.8H, V0.H[1]
	sqrdmlsh	V21.8H, V29.8H, V4.H[0]
	sqrdmlsh	V22.8H, V30.8H, V4.H[0]
	sshr	V21.8H, V21.8H, #1
	sshr	V22.8H, V22.8H, #1
	mul	V29.8H, V10.8H, V1.H[2]
	mul	V30.8H, V12.8H, V1.H[3]
	sqrdmulh	V23.8H, V10.8H, V0.H[2]
	sqrdmulh	V24.8H, V12.8H, V0.H[3]
	sqrdmlsh	V23.8H, V29.8H, V4.H[0]
	sqrdmlsh	V24.8H, V30.8H, V4.H[0]
	sshr	V23.8H, V23.8H, #1
	sshr	V24.8H, V24.8H, #1
	mul	V29.8H, V14.8H, V1.H[4]
	mul	V30.8H, V16.8H, V1.H[5]
	sqrdmulh	V25.8H, V14.8H, V0.H[4]
	sqrdmulh	V26.8H, V16.8H, V0.H[5]
	sqrdmlsh	V25.8H, V29.8H, V4.H[0]
	sqrdmlsh	V26.8H, V30.8H, V4.H[0]
	sshr	V25.8H, V25.8H, #1
	sshr	V26.8H, V26.8H, #1
	mul	V29.8H, V18.8H, V1.H[6]
	mul	V30.8H, V20.8H, V1.H[7]
	sqrdmulh	V27.8H, V18.8H, V0.H[6]
	sqrdmulh	V28.8H, V20.8H, V0.H[7]
	sqrdmlsh	V27.8H, V29.8H, V4.H[0]
	sqrdmlsh	V28.8H, V30.8H, V4.H[0]
	sshr	V27.8H, V27.8H, #1
	sshr	V28.8H, V28.8H, #1
	sub	V6.8H, V5.8H, V21.8H
	add	V5.8H, V5.8H, V21.8H
	sub	V8.8H, V7.8H, V22.8H
	add	V7.8H, V7.8H, V22.8H
	sub	V10.8H, V9.8H, V23.8H
	add	V9.8H, V9.8H, V23.8H
	sub	V12.8H, V11.8H, V24.8H
	add	V11.8H, V11.8H, V24.8H
	sub	V14.8H, V13.8H, V25.8H
	add	V13.8H, V13.8H, V25.8H
	sub	V16.8H, V15.8H, V26.8H
	add	V15.8H, V15.8H, V26.8H
	sub	V18.8H, V17.8H, V27.8H
	add	V17.8H, V17.8H, V27.8H
	sub	V20.8H, V19.8H, V28.8H
	add	V19.8H, V19.8H, V28.8H
	str	Q5, [x0]
	str	Q6, [x0, #32]
	str	Q7, [x0, #64]
	str	Q8, [x0, #96]
	str	Q9, [x0, #128]
	str	Q10, [x0, #160]
	str	Q11, [x0, #192]
	str	Q12, [x0, #224]
	str	Q13, [x1]
	str	Q14, [x1, #32]
	str	Q15, [x1, #64]
	str	Q16, [x1, #96]
	str	Q17, [x1, #128]
	str	Q18, [x1, #160]
	str	Q19, [x1, #192]
	str	Q20, [x1, #224]
	ldr	Q5, [x0, #16]
	ldr	Q6, [x0, #48]
	ldr	Q7, [x0, #80]
	ldr	Q8, [x0, #112]
	ldr	Q9, [x0, #144]
	ldr	Q10, [x0, #176]
	ldr	Q11, [x0, #208]
	ldr	Q12, [x0, #240]
	ldr	Q13, [x1, #16]
	ldr	Q14, [x1, #48]
	ldr	Q15, [x1, #80]
	ldr	Q16, [x1, #112]
	ldr	Q17, [x1, #144]
	ldr	Q18, [x1, #176]
	ldr	Q19, [x1, #208]
	ldr	Q20, [x1, #240]
	ldr	Q0, [x2]
	ldr	Q1, [x3]
	mul	V29.8H, V13.8H, V1.H[1]
	mul	V30.8H, V14.8H, V1.H[1]
	sqrdmulh	V21.8H, V13.8H, V0.H[1]
	sqrdmulh	V22.8H, V14.8H, V0.H[1]
	sqrdmlsh	V21.8H, V29.8H, V4.H[0]
	sqrdmlsh	V22.8H, V30.8H, V4.H[0]
	sshr	V21.8H, V21.8H, #1
	sshr	V22.8H, V22.8H, #1
	mul	V29.8H, V15.8H, V1.H[1]
	mul	V30.8H, V16.8H, V1.H[1]
	sqrdmulh	V23.8H, V15.8H, V0.H[1]
	sqrdmulh	V24.8H, V16.8H, V0.H[1]
	sqrdmlsh	V23.8H, V29.8H, V4.H[0]
	sqrdmlsh	V24.8H, V30.8H, V4.H[0]
	sshr	V23.8H, V23.8H, #1
	sshr	V24.8H, V24.8H, #1
	mul	V29.8H, V17.8H, V1.H[1]
	mul	V30.8H, V18.8H, V1.H[1]
	sqrdmulh	V25.8H, V17.8H, V0.H[1]
	sqrdmulh	V26.8H, V18.8H, V0.H[1]
	sqrdmlsh	V25.8H, V29.8H, V4.H[0]
	sqrdmlsh	V26.8H, V30.8H, V4.H[0]
	sshr	V25.8H, V25.8H, #1
	sshr	V26.8H, V26.8H, #1
	mul	V29.8H, V19.8H, V1.H[1]
	mul	V30.8H, V20.8H, V1.H[1]
	sqrdmulh	V27.8H, V19.8H, V0.H[1]
	sqrdmulh	V28.8H, V20.8H, V0.H[1]
	sqrdmlsh	V27.8H, V29.8H, V4.H[0]
	sqrdmlsh	V28.8H, V30.8H, V4.H[0]
	sshr	V27.8H, V27.8H, #1
	sshr	V28.8H, V28.8H, #1
	sub	V13.8H, V5.8H, V21.8H
	add	V5.8H, V5.8H, V21.8H
	sub	V14.8H, V6.8H, V22.8H
	add	V6.8H, V6.8H, V22.8H
	sub	V15.8H, V7.8H, V23.8H
	add	V7.8H, V7.8H, V23.8H
	sub	V16.8H, V8.8H, V24.8H
	add	V8.8H, V8.8H, V24.8H
	sub	V17.8H, V9.8H, V25.8H
	add	V9.8H, V9.8H, V25.8H
	sub	V18.8H, V10.8H, V26.8H
	add	V10.8H, V10.8H, V26.8H
	sub	V19.8H, V11.8H, V27.8H
	add	V11.8H, V11.8H, V27.8H
	sub	V20.8H, V12.8H, V28.8H
	add	V12.8H, V12.8H, V28.8H
	mul	V29.8H, V9.8H, V1.H[2]
	mul	V30.8H, V10.8H, V1.H[2]
	sqrdmulh	V21.8H, V9.8H, V0.H[2]
	sqrdmulh	V22.8H, V10.8H, V0.H[2]
	sqrdmlsh	V21.8H, V29.8H, V4.H[0]
	sqrdmlsh	V22.8H, V30.8H, V4.H[0]
	sshr	V21.8H, V21.8H, #1
	sshr	V22.8H, V22.8H, #1
	mul	V29.8H, V11.8H, V1.H[2]
	mul	V30.8H, V12.8H, V1.H[2]
	sqrdmulh	V23.8H, V11.8H, V0.H[2]
	sqrdmulh	V24.8H, V12.8H, V0.H[2]
	sqrdmlsh	V23.8H, V29.8H, V4.H[0]
	sqrdmlsh	V24.8H, V30.8H, V4.H[0]
	sshr	V23.8H, V23.8H, #1
	sshr	V24.8H, V24.8H, #1
	mul	V29.8H, V17.8H, V1.H[3]
	mul	V30.8H, V18.8H, V1.H[3]
	sqrdmulh	V25.8H, V17.8H, V0.H[3]
	sqrdmulh	V26.8H, V18.8H, V0.H[3]
	sqrdmlsh	V25.8H, V29.8H, V4.H[0]
	sqrdmlsh	V26.8H, V30.8H, V4.H[0]
	sshr	V25.8H, V25.8H, #1
	sshr	V26.8H, V26.8H, #1
	mul	V29.8H, V19.8H, V1.H[3]
	mul	V30.8H, V20.8H, V1.H[3]
	sqrdmulh	V27.8H, V19.8H, V0.H[3]
	sqrdmulh	V28.8H, V20.8H, V0.H[3]
	sqrdmlsh	V27.8H, V29.8H, V4.H[0]
	sqrdmlsh	V28.8H, V30.8H, V4.H[0]
	sshr	V27.8H, V27.8H, #1
	sshr	V28.8H, V28.8H, #1
	sub	V9.8H, V5.8H, V21.8H
	add	V5.8H, V5.8H, V21.8H
	sub	V10.8H, V6.8H, V22.8H
	add	V6.8H, V6.8H, V22.8H
	sub	V11.8H, V7.8H, V23.8H
	add	V7.8H, V7.8H, V23.8H
	sub	V12.8H, V8.8H, V24.8H
	add	V8.8H, V8.8H, V24.8H
	sub	V17.8H, V13.8H, V25.8H
	add	V13.8H, V13.8H, V25.8H
	sub	V18.8H, V14.8H, V26.8H
	add	V14.8H, V14.8H, V26.8H
	sub	V19.8H, V15.8H, V27.8H
	add	V15.8H, V15.8H, V27.8H
	sub	V20.8H, V16.8H, V28.8H
	add	V16.8H, V16.8H, V28.8H
	mul	V29.8H, V7.8H, V1.H[4]
	mul	V30.8H, V8.8H, V1.H[4]
	sqrdmulh	V21.8H, V7.8H, V0.H[4]
	sqrdmulh	V22.8H, V8.8H, V0.H[4]
	sqrdmlsh	V21.8H, V29.8H, V4.H[0]
	sqrdmlsh	V22.8H, V30.8H, V4.H[0]
	sshr	V21.8H, V21.8H, #1
	sshr	V22.8H, V22.8H, #1
	mul	V29.8H, V11.8H, V1.H[5]
	mul	V30.8H, V12.8H, V1.H[5]
	sqrdmulh	V23.8H, V11.8H, V0.H[5]
	sqrdmulh	V24.8H, V12.8H, V0.H[5]
	sqrdmlsh	V23.8H, V29.8H, V4.H[0]
	sqrdmlsh	V24.8H, V30.8H, V4.H[0]
	sshr	V23.8H, V23.8H, #1
	sshr	V24.8H, V24.8H, #1
	mul	V29.8H, V15.8H, V1.H[6]
	mul	V30.8H, V16.8H, V1.H[6]
	sqrdmulh	V25.8H, V15.8H, V0.H[6]
	sqrdmulh	V26.8H, V16.8H, V0.H[6]
	sqrdmlsh	V25.8H, V29.8H, V4.H[0]
	sqrdmlsh	V26.8H, V30.8H, V4.H[0]
	sshr	V25.8H, V25.8H, #1
	sshr	V26.8H, V26.8H, #1
	mul	V29.8H, V19.8H, V1.H[7]
	mul	V30.8H, V20.8H, V1.H[7]
	sqrdmulh	V27.8H, V19.8H, V0.H[7]
	sqrdmulh	V28.8H, V20.8H, V0.H[7]
	sqrdmlsh	V27.8H, V29.8H, V4.H[0]
	sqrdmlsh	V28.8H, V30.8H, V4.H[0]
	sshr	V27.8H, V27.8H, #1
	sshr	V28.8H, V28.8H, #1
	sub	V7.8H, V5.8H, V21.8H
	add	V5.8H, V5.8H, V21.8H
	sub	V8.8H, V6.8H, V22.8H
	add	V6.8H, V6.8H, V22.8H
	sub	V11.8H, V9.8H, V23.8H
	add	V9.8H, V9.8H, V23.8H
	sub	V12.8H, V10.8H, V24.8H
	add	V10.8H, V10.8H, V24.8H
	sub	V15.8H, V13.8H, V25.8H
	add	V13.8H, V13.8H, V25.8H
	sub	V16.8H, V14.8H, V26.8H
	add	V14.8H, V14.8H, V26.8H
	sub	V19.8H, V17.8H, V27.8H
	add	V17.8H, V17.8H, V27.8H
	sub	V20.8H, V18.8H, V28.8H
	add	V18.8H, V18.8H, V28.8H
	ldr	Q0, [x2, #16]
	ldr	Q1, [x3, #16]
	mul	V29.8H, V6.8H, V1.H[0]
	mul	V30.8H, V8.8H, V1.H[1]
	sqrdmulh	V21.8H, V6.8H, V0.H[0]
	sqrdmulh	V22.8H, V8.8H, V0.H[1]
	sqrdmlsh	V21.8H, V29.8H, V4.H[0]
	sqrdmlsh	V22.8H, V30.8H, V4.H[0]
	sshr	V21.8H, V21.8H, #1
	sshr	V22.8H, V22.8H, #1
	mul	V29.8H, V10.8H, V1.H[2]
	mul	V30.8H, V12.8H, V1.H[3]
	sqrdmulh	V23.8H, V10.8H, V0.H[2]
	sqrdmulh	V24.8H, V12.8H, V0.H[3]
	sqrdmlsh	V23.8H, V29.8H, V4.H[0]
	sqrdmlsh	V24.8H, V30.8H, V4.H[0]
	sshr	V23.8H, V23.8H, #1
	sshr	V24.8H, V24.8H, #1
	mul	V29.8H, V14.8H, V1.H[4]
	mul	V30.8H, V16.8H, V1.H[5]
	sqrdmulh	V25.8H, V14.8H, V0.H[4]
	sqrdmulh	V26.8H, V16.8H, V0.H[5]
	sqrdmlsh	V25.8H, V29.8H, V4.H[0]
	sqrdmlsh	V26.8H, V30.8H, V4.H[0]
	sshr	V25.8H, V25.8H, #1
	sshr	V26.8H, V26.8H, #1
	mul	V29.8H, V18.8H, V1.H[6]
	mul	V30.8H, V20.8H, V1.H[7]
	sqrdmulh	V27.8H, V18.8H, V0.H[6]
	sqrdmulh	V28.8H, V20.8H, V0.H[7]
	sqrdmlsh	V27.8H, V29.8H, V4.H[0]
	sqrdmlsh	V28.8H, V30.8H, V4.H[0]
	sshr	V27.8H, V27.8H, #1
	sshr	V28.8H, V28.8H, #1
	sub	V6.8H, V5.8H, V21.8H
	add	V5.8H, V5.8H, V21.8H
	sub	V8.8H, V7.8H, V22.8H
	add	V7.8H, V7.8H, V22.8H
	sub	V10.8H, V9.8H, V23.8H
	add	V9.8H, V9.8H, V23.8H
	sub	V12.8H, V11.8H, V24.8H
	add	V11.8H, V11.8H, V24.8H
	sub	V14.8H, V13.8H, V25.8H
	add	V13.8H, V13.8H, V25.8H
	sub	V16.8H, V15.8H, V26.8H
	add	V15.8H, V15.8H, V26.8H
	sub	V18.8H, V17.8H, V27.8H
	add	V17.8H, V17.8H, V27.8H
	sub	V20.8H, V19.8H, V28.8H
	add	V19.8H, V19.8H, V28.8H
	str	Q5, [x0, #16]
	str	Q6, [x0, #48]
	str	Q7, [x0, #80]
	str	Q8, [x0, #112]
	str	Q9, [x0, #144]
	str	Q10, [x0, #176]
	str	Q11, [x0, #208]
	str	Q12, [x0, #240]
	str	Q13, [x1, #16]
	str	Q14, [x1, #48]
	str	Q15, [x1, #80]
	str	Q16, [x1, #112]
	str	Q17, [x1, #144]
	str	Q18, [x1, #176]
	str	Q19, [x1, #208]
	str	Q20, [x1, #240]
	ldp	Q5, Q6, [x0]
	ldp	Q7, Q8, [x0, #32]
	ldp	Q9, Q10, [x0, #64]
	ldp	Q11, Q12, [x0, #96]
	ldp	Q13, Q14, [x0, #128]
	ldp	Q15, Q16, [x0, #160]
	ldp	Q17, Q18, [x0, #192]
	ldp	Q19, Q20, [x0, #224]
	ldr	Q0, [x2, #32]
	ldr	Q1, [x3, #32]
	mul	V29.8H, V6.8H, V1.H[0]
	mul	V30.8H, V8.8H, V1.H[1]
	sqrdmulh	V21.8H, V6.8H, V0.H[0]
	sqrdmulh	V22.8H, V8.8H, V0.H[1]
	sqrdmlsh	V21.8H, V29.8H, V4.H[0]
	sqrdmlsh	V22.8H, V30.8H, V4.H[0]
	sshr	V21.8H, V21.8H, #1
	sshr	V22.8H, V22.8H, #1
	mul	V29.8H, V10.8H, V1.H[2]
	mul	V30.8H, V12.8H, V1.H[3]
	sqrdmulh	V23.8H, V10.8H, V0.H[2]
	sqrdmulh	V24.8H, V12.8H, V0.H[3]
	sqrdmlsh	V23.8H, V29.8H, V4.H[0]
	sqrdmlsh	V24.8H, V30.8H, V4.H[0]
	sshr	V23.8H, V23.8H, #1
	sshr	V24.8H, V24.8H, #1
	mul	V29.8H, V14.8H, V1.H[4]
	mul	V30.8H, V16.8H, V1.H[5]
	sqrdmulh	V25.8H, V14.8H, V0.H[4]
	sqrdmulh	V26.8H, V16.8H, V0.H[5]
	sqrdmlsh	V25.8H, V29.8H, V4.H[0]
	sqrdmlsh	V26.8H, V30.8H, V4.H[0]
	sshr	V25.8H, V25.8H, #1
	sshr	V26.8H, V26.8H, #1
	mul	V29.8H, V18.8H, V1.H[6]
	mul	V30.8H, V20.8H, V1.H[7]
	sqrdmulh	V27.8H, V18.8H, V0.H[6]
	sqrdmulh	V28.8H, V20.8H, V0.H[7]
	sqrdmlsh	V27.8H, V29.8H, V4.H[0]
	sqrdmlsh	V28.8H, V30.8H, V4.H[0]
	sshr	V27.8H, V27.8H, #1
	sshr	V28.8H, V28.8H, #1
	sub	V6.8H, V5.8H, V21.8H
	add	V5.8H, V5.8H, V21.8H
	sub	V8.8H, V7.8H, V22.8H
	add	V7.8H, V7.8H, V22.8H
	sub	V10.8H, V9.8H, V23.8H
	add	V9.8H, V9.8H, V23.8H
	sub	V12.8H, V11.8H, V24.8H
	add	V11.8H, V11.8H, V24.8H
	sub	V14.8H, V13.8H, V25.8H
	add	V13.8H, V13.8H, V25.8H
	sub	V16.8H, V15.8H, V26.8H
	add	V15.8H, V15.8H, V26.8H
	sub	V18.8H, V17.8H, V27.8H
	add	V17.8H, V17.8H, V27.8H
	sub	V20.8H, V19.8H, V28.8H
	add	V19.8H, V19.8H, V28.8H
	ldr	Q0, [x2, #64]
	ldr	Q2, [x2, #80]
	ldr	Q1, [x3, #64]
	ldr	Q3, [x3, #80]
	mov	V29.16B, V5.16B
	mov	V30.16B, V7.16B
	trn1	V5.2D, V5.2D, V6.2D
	trn1	V7.2D, V7.2D, V8.2D
	trn2	V6.2D, V29.2D, V6.2D
	trn2	V8.2D, V30.2D, V8.2D
	mul	V29.8H, V6.8H, V1.8H
	mul	V30.8H, V8.8H, V3.8H
	sqrdmulh	V21.8H, V6.8H, V0.8H
	sqrdmulh	V22.8H, V8.8H, V2.8H
	sqrdmlsh	V21.8H, V29.8H, V4.H[0]
	sqrdmlsh	V22.8H, V30.8H, V4.H[0]
	sshr	V21.8H, V21.8H, #1
	sshr	V22.8H, V22.8H, #1
	ldr	Q0, [x2, #96]
	ldr	Q2, [x2, #112]
	ldr	Q1, [x3, #96]
	ldr	Q3, [x3, #112]
	mov	V29.16B, V9.16B
	mov	V30.16B, V11.16B
	trn1	V9.2D, V9.2D, V10.2D
	trn1	V11.2D, V11.2D, V12.2D
	trn2	V10.2D, V29.2D, V10.2D
	trn2	V12.2D, V30.2D, V12.2D
	mul	V29.8H, V10.8H, V1.8H
	mul	V30.8H, V12.8H, V3.8H
	sqrdmulh	V23.8H, V10.8H, V0.8H
	sqrdmulh	V24.8H, V12.8H, V2.8H
	sqrdmlsh	V23.8H, V29.8H, V4.H[0]
	sqrdmlsh	V24.8H, V30.8H, V4.H[0]
	sshr	V23.8H, V23.8H, #1
	sshr	V24.8H, V24.8H, #1
	ldr	Q0, [x2, #128]
	ldr	Q2, [x2, #144]
	ldr	Q1, [x3, #128]
	ldr	Q3, [x3, #144]
	mov	V29.16B, V13.16B
	mov	V30.16B, V15.16B
	trn1	V13.2D, V13.2D, V14.2D
	trn1	V15.2D, V15.2D, V16.2D
	trn2	V14.2D, V29.2D, V14.2D
	trn2	V16.2D, V30.2D, V16.2D
	mul	V29.8H, V14.8H, V1.8H
	mul	V30.8H, V16.8H, V3.8H
	sqrdmulh	V25.8H, V14.8H, V0.8H
	sqrdmulh	V26.8H, V16.8H, V2.8H
	sqrdmlsh	V25.8H, V29.8H, V4.H[0]
	sqrdmlsh	V26.8H, V30.8H, V4.H[0]
	sshr	V25.8H, V25.8H, #1
	sshr	V26.8H, V26.8H, #1
	ldr	Q0, [x2, #160]
	ldr	Q2, [x2, #176]
	ldr	Q1, [x3, #160]
	ldr	Q3, [x3, #176]
	mov	V29.16B, V17.16B
	mov	V30.16B, V19.16B
	trn1	V17.2D, V17.2D, V18.2D
	trn1	V19.2D, V19.2D, V20.2D
	trn2	V18.2D, V29.2D, V18.2D
	trn2	V20.2D, V30.2D, V20.2D
	mul	V29.8H, V18.8H, V1.8H
	mul	V30.8H, V20.8H, V3.8H
	sqrdmulh	V27.8H, V18.8H, V0.8H
	sqrdmulh	V28.8H, V20.8H, V2.8H
	sqrdmlsh	V27.8H, V29.8H, V4.H[0]
	sqrdmlsh	V28.8H, V30.8H, V4.H[0]
	sshr	V27.8H, V27.8H, #1
	sshr	V28.8H, V28.8H, #1
	sub	V6.8H, V5.8H, V21.8H
	add	V5.8H, V5.8H, V21.8H
	sub	V8.8H, V7.8H, V22.8H
	add	V7.8H, V7.8H, V22.8H
	sub	V10.8H, V9.8H, V23.8H
	add	V9.8H, V9.8H, V23.8H
	sub	V12.8H, V11.8H, V24.8H
	add	V11.8H, V11.8H, V24.8H
	sub	V14.8H, V13.8H, V25.8H
	add	V13.8H, V13.8H, V25.8H
	sub	V16.8H, V15.8H, V26.8H
	add	V15.8H, V15.8H, V26.8H
	sub	V18.8H, V17.8H, V27.8H
	add	V17.8H, V17.8H, V27.8H
	sub	V20.8H, V19.8H, V28.8H
	add	V19.8H, V19.8H, V28.8H
	ldr	Q0, [x2, #320]
	ldr	Q2, [x2, #336]
	ldr	Q1, [x3, #320]
	ldr	Q3, [x3, #336]
	mov	V29.16B, V5.16B
	mov	V30.16B, V7.16B
	trn1	V5.4S, V5.4S, V6.4S
	trn1	V7.4S, V7.4S, V8.4S
	trn2	V6.4S, V29.4S, V6.4S
	trn2	V8.4S, V30.4S, V8.4S
	mul	V29.8H, V6.8H, V1.8H
	mul	V30.8H, V8.8H, V3.8H
	sqrdmulh	V21.8H, V6.8H, V0.8H
	sqrdmulh	V22.8H, V8.8H, V2.8H
	sqrdmlsh	V21.8H, V29.8H, V4.H[0]
	sqrdmlsh	V22.8H, V30.8H, V4.H[0]
	sshr	V21.8H, V21.8H, #1
	sshr	V22.8H, V22.8H, #1
	ldr	Q0, [x2, #352]
	ldr	Q2, [x2, #368]
	ldr	Q1, [x3, #352]
	ldr	Q3, [x3, #368]
	mov	V29.16B, V9.16B
	mov	V30.16B, V11.16B
	trn1	V9.4S, V9.4S, V10.4S
	trn1	V11.4S, V11.4S, V12.4S
	trn2	V10.4S, V29.4S, V10.4S
	trn2	V12.4S, V30.4S, V12.4S
	mul	V29.8H, V10.8H, V1.8H
	mul	V30.8H, V12.8H, V3.8H
	sqrdmulh	V23.8H, V10.8H, V0.8H
	sqrdmulh	V24.8H, V12.8H, V2.8H
	sqrdmlsh	V23.8H, V29.8H, V4.H[0]
	sqrdmlsh	V24.8H, V30.8H, V4.H[0]
	sshr	V23.8H, V23.8H, #1
	sshr	V24.8H, V24.8H, #1
	ldr	Q0, [x2, #384]
	ldr	Q2, [x2, #400]
	ldr	Q1, [x3, #384]
	ldr	Q3, [x3, #400]
	mov	V29.16B, V13.16B
	mov	V30.16B, V15.16B
	trn1	V13.4S, V13.4S, V14.4S
	trn1	V15.4S, V15.4S, V16.4S
	trn2	V14.4S, V29.4S, V14.4S
	trn2	V16.4S, V30.4S, V16.4S
	mul	V29.8H, V14.8H, V1.8H
	mul	V30.8H, V16.8H, V3.8H
	sqrdmulh	V25.8H, V14.8H, V0.8H
	sqrdmulh	V26.8H, V16.8H, V2.8H
	sqrdmlsh	V25.8H, V29.8H, V4.H[0]
	sqrdmlsh	V26.8H, V30.8H, V4.H[0]
	sshr	V25.8H, V25.8H, #1
	sshr	V26.8H, V26.8H, #1
	ldr	Q0, [x2, #416]
	ldr	Q2, [x2, #432]
	ldr	Q1, [x3, #416]
	ldr	Q3, [x3, #432]
	mov	V29.16B, V17.16B
	mov	V30.16B, V19.16B
	trn1	V17.4S, V17.4S, V18.4S
	trn1	V19.4S, V19.4S, V20.4S
	trn2	V18.4S, V29.4S, V18.4S
	trn2	V20.4S, V30.4S, V20.4S
	mul	V29.8H, V18.8H, V1.8H
	mul	V30.8H, V20.8H, V3.8H
	sqrdmulh	V27.8H, V18.8H, V0.8H
	sqrdmulh	V28.8H, V20.8H, V2.8H
	sqrdmlsh	V27.8H, V29.8H, V4.H[0]
	sqrdmlsh	V28.8H, V30.8H, V4.H[0]
	sshr	V27.8H, V27.8H, #1
	sshr	V28.8H, V28.8H, #1
	sub	V6.8H, V5.8H, V21.8H
	add	V5.8H, V5.8H, V21.8H
	sub	V8.8H, V7.8H, V22.8H
	add	V7.8H, V7.8H, V22.8H
	sub	V10.8H, V9.8H, V23.8H
	add	V9.8H, V9.8H, V23.8H
	sub	V12.8H, V11.8H, V24.8H
	add	V11.8H, V11.8H, V24.8H
	sub	V14.8H, V13.8H, V25.8H
	add	V13.8H, V13.8H, V25.8H
	sub	V16.8H, V15.8H, V26.8H
	add	V15.8H, V15.8H, V26.8H
	sub	V18.8H, V17.8H, V27.8H
	add	V17.8H, V17.8H, V27.8H
	sub	V20.8H, V19.8H, V28.8H
	add	V19.8H, V19.8H, V28.8H
	sqdmulh	V21.8H, V5.8H, V4.H[2]
	sqdmulh	V22.8H, V6.8H, V4.H[2]
	sshr	V21.8H, V21.8H, #11
	sshr	V22.8H, V22.8H, #11
	mls	V5.8H, V21.8H, V4.H[0]
	mls	V6.8H, V22.8H, V4.H[0]
	sqdmulh	V21.8H, V7.8H, V4.H[2]
	sqdmulh	V22.8H, V8.8H, V4.H[2]
	sshr	V21.8H, V21.8H, #11
	sshr	V22.8H, V22.8H, #11
	mls	V7.8H, V21.8H, V4.H[0]
	mls	V8.8H, V22.8H, V4.H[0]
	sqdmulh	V21.8H, V9.8H, V4.H[2]
	sqdmulh	V22.8H, V10.8H, V4.H[2]
	sshr	V21.8H, V21.8H, #11
	sshr	V22.8H, V22.8H, #11
	mls	V9.8H, V21.8H, V4.H[0]
	mls	V10.8H, V22.8H, V4.H[0]
	sqdmulh	V21.8H, V11.8H, V4.H[2]
	sqdmulh	V22.8H, V12.8H, V4.H[2]
	sshr	V21.8H, V21.8H, #11
	sshr	V22.8H, V22.8H, #11
	mls	V11.8H, V21.8H, V4.H[0]
	mls	V12.8H, V22.8H, V4.H[0]
	sqdmulh	V21.8H, V13.8H, V4.H[2]
	sqdmulh	V22.8H, V14.8H, V4.H[2]
	sshr	V21.8H, V21.8H, #11
	sshr	V22.8H, V22.8H, #11
	mls	V13.8H, V21.8H, V4.H[0]
	mls	V14.8H, V22.8H, V4.H[0]
	sqdmulh	V21.8H, V15.8H, V4.H[2]
	sqdmulh	V22.8H, V16.8H, V4.H[2]
	sshr	V21.8H, V21.8H, #11
	sshr	V22.8H, V22.8H, #11
	mls	V15.8H, V21.8H, V4.H[0]
	mls	V16.8H, V22.8H, V4.H[0]
	sqdmulh	V21.8H, V17.8H, V4.H[2]
	sqdmulh	V22.8H, V18.8H, V4.H[2]
	sshr	V21.8H, V21.8H, #11
	sshr	V22.8H, V22.8H, #11
	mls	V17.8H, V21.8H, V4.H[0]
	mls	V18.8H, V22.8H, V4.H[0]
	sqdmulh	V21.8H, V19.8H, V4.H[2]
	sqdmulh	V22.8H, V20.8H, V4.H[2]
	sshr	V21.8H, V21.8H, #11
	sshr	V22.8H, V22.8H, #11
	mls	V19.8H, V21.8H, V4.H[0]
	mls	V20.8H, V22.8H, V4.H[0]
	mov	V29.16B, V5.16B
	trn1	V5.4S, V5.4S, V6.4S
	trn2	V6.4S, V29.4S, V6.4S
	mov	V29.16B, V5.16B
	trn1	V5.2D, V5.2D, V6.2D
	trn2	V6.2D, V29.2D, V6.2D
	mov	V29.16B, V7.16B
	trn1	V7.4S, V7.4S, V8.4S
	trn2	V8.4S, V29.4S, V8.4S
	mov	V29.16B, V7.16B
	trn1	V7.2D, V7.2D, V8.2D
	trn2	V8.2D, V29.2D, V8.2D
	mov	V29.16B, V9.16B
	trn1	V9.4S, V9.4S, V10.4S
	trn2	V10.4S, V29.4S, V10.4S
	mov	V29.16B, V9.16B
	trn1	V9.2D, V9.2D, V10.2D
	trn2	V10.2D, V29.2D, V10.2D
	mov	V29.16B, V11.16B
	trn1	V11.4S, V11.4S, V12.4S
	trn2	V12.4S, V29.4S, V12.4S
	mov	V29.16B, V11.16B
	trn1	V11.2D, V11.2D, V12.2D
	trn2	V12.2D, V29.2D, V12.2D
	mov	V29.16B, V13.16B
	trn1	V13.4S, V13.4S, V14.4S
	trn2	V14.4S, V29.4S, V14.4S
	mov	V29.16B, V13.16B
	trn1	V13.2D, V13.2D, V14.2D
	trn2	V14.2D, V29.2D, V14.2D
	mov	V29.16B, V15.16B
	trn1	V15.4S, V15.4S, V16.4S
	trn2	V16.4S, V29.4S, V16.4S
	mov	V29.16B, V15.16B
	trn1	V15.2D, V15.2D, V16.2D
	trn2	V16.2D, V29.2D, V16.2D
	mov	V29.16B, V17.16B
	trn1	V17.4S, V17.4S, V18.4S
	trn2	V18.4S, V29.4S, V18.4S
	mov	V29.16B, V17.16B
	trn1	V17.2D, V17.2D, V18.2D
	trn2	V18.2D, V29.2D, V18.2D
	mov	V29.16B, V19.16B
	trn1	V19.4S, V19.4S, V20.4S
	trn2	V20.4S, V29.4S, V20.4S
	mov	V29.16B, V19.16B
	trn1	V19.2D, V19.2D, V20.2D
	trn2	V20.2D, V29.2D, V20.2D
	stp	Q5, Q6, [x0]
	stp	Q7, Q8, [x0, #32]
	stp	Q9, Q10, [x0, #64]
	stp	Q11, Q12, [x0, #96]
	stp	Q13, Q14, [x0, #128]
	stp	Q15, Q16, [x0, #160]
	stp	Q17, Q18, [x0, #192]
	stp	Q19, Q20, [x0, #224]
	ldp	Q5, Q6, [x1]
	ldp	Q7, Q8, [x1, #32]
	ldp	Q9, Q10, [x1, #64]
	ldp	Q11, Q12, [x1, #96]
	ldp	Q13, Q14, [x1, #128]
	ldp	Q15, Q16, [x1, #160]
	ldp	Q17, Q18, [x1, #192]
	ldp	Q19, Q20, [x1, #224]
	ldr	Q0, [x2, #48]
	ldr	Q1, [x3, #48]
	mul	V29.8H, V6.8H, V1.H[0]
	mul	V30.8H, V8.8H, V1.H[1]
	sqrdmulh	V21.8H, V6.8H, V0.H[0]
	sqrdmulh	V22.8H, V8.8H, V0.H[1]
	sqrdmlsh	V21.8H, V29.8H, V4.H[0]
	sqrdmlsh	V22.8H, V30.8H, V4.H[0]
	sshr	V21.8H, V21.8H, #1
	sshr	V22.8H, V22.8H, #1
	mul	V29.8H, V10.8H, V1.H[2]
	mul	V30.8H, V12.8H, V1.H[3]
	sqrdmulh	V23.8H, V10.8H, V0.H[2]
	sqrdmulh	V24.8H, V12.8H, V0.H[3]
	sqrdmlsh	V23.8H, V29.8H, V4.H[0]
	sqrdmlsh	V24.8H, V30.8H, V4.H[0]
	sshr	V23.8H, V23.8H, #1
	sshr	V24.8H, V24.8H, #1
	mul	V29.8H, V14.8H, V1.H[4]
	mul	V30.8H, V16.8H, V1.H[5]
	sqrdmulh	V25.8H, V14.8H, V0.H[4]
	sqrdmulh	V26.8H, V16.8H, V0.H[5]
	sqrdmlsh	V25.8H, V29.8H, V4.H[0]
	sqrdmlsh	V26.8H, V30.8H, V4.H[0]
	sshr	V25.8H, V25.8H, #1
	sshr	V26.8H, V26.8H, #1
	mul	V29.8H, V18.8H, V1.H[6]
	mul	V30.8H, V20.8H, V1.H[7]
	sqrdmulh	V27.8H, V18.8H, V0.H[6]
	sqrdmulh	V28.8H, V20.8H, V0.H[7]
	sqrdmlsh	V27.8H, V29.8H, V4.H[0]
	sqrdmlsh	V28.8H, V30.8H, V4.H[0]
	sshr	V27.8H, V27.8H, #1
	sshr	V28.8H, V28.8H, #1
	sub	V6.8H, V5.8H, V21.8H
	add	V5.8H, V5.8H, V21.8H
	sub	V8.8H, V7.8H, V22.8H
	add	V7.8H, V7.8H, V22.8H
	sub	V10.8H, V9.8H, V23.8H
	add	V9.8H, V9.8H, V23.8H
	sub	V12.8H, V11.8H, V24.8H
	add	V11.8H, V11.8H, V24.8H
	sub	V14.8H, V13.8H, V25.8H
	add	V13.8H, V13.8H, V25.8H
	sub	V16.8H, V15.8H, V26.8H
	add	V15.8H, V15.8H, V26.8H
	sub	V18.8H, V17.8H, V27.8H
	add	V17.8H, V17.8H, V27.8H
	sub	V20.8H, V19.8H, V28.8H
	add	V19.8H, V19.8H, V28.8H
	ldr	Q0, [x2, #192]
	ldr	Q2, [x2, #208]
	ldr	Q1, [x3, #192]
	ldr	Q3, [x3, #208]
	mov	V29.16B, V5.16B
	mov	V30.16B, V7.16B
	trn1	V5.2D, V5.2D, V6.2D
	trn1	V7.2D, V7.2D, V8.2D
	trn2	V6.2D, V29.2D, V6.2D
	trn2	V8.2D, V30.2D, V8.2D
	mul	V29.8H, V6.8H, V1.8H
	mul	V30.8H, V8.8H, V3.8H
	sqrdmulh	V21.8H, V6.8H, V0.8H
	sqrdmulh	V22.8H, V8.8H, V2.8H
	sqrdmlsh	V21.8H, V29.8H, V4.H[0]
	sqrdmlsh	V22.8H, V30.8H, V4.H[0]
	sshr	V21.8H, V21.8H, #1
	sshr	V22.8H, V22.8H, #1
	ldr	Q0, [x2, #224]
	ldr	Q2, [x2, #240]
	ldr	Q1, [x3, #224]
	ldr	Q3, [x3, #240]
	mov	V29.16B, V9.16B
	mov	V30.16B, V11.16B
	trn1	V9.2D, V9.2D, V10.2D
	trn1	V11.2D, V11.2D, V12.2D
	trn2	V10.2D, V29.2D, V10.2D
	trn2	V12.2D, V30.2D, V12.2D
	mul	V29.8H, V10.8H, V1.8H
	mul	V30.8H, V12.8H, V3.8H
	sqrdmulh	V23.8H, V10.8H, V0.8H
	sqrdmulh	V24.8H, V12.8H, V2.8H
	sqrdmlsh	V23.8H, V29.8H, V4.H[0]
	sqrdmlsh	V24.8H, V30.8H, V4.H[0]
	sshr	V23.8H, V23.8H, #1
	sshr	V24.8H, V24.8H, #1
	ldr	Q0, [x2, #256]
	ldr	Q2, [x2, #272]
	ldr	Q1, [x3, #256]
	ldr	Q3, [x3, #272]
	mov	V29.16B, V13.16B
	mov	V30.16B, V15.16B
	trn1	V13.2D, V13.2D, V14.2D
	trn1	V15.2D, V15.2D, V16.2D
	trn2	V14.2D, V29.2D, V14.2D
	trn2	V16.2D, V30.2D, V16.2D
	mul	V29.8H, V14.8H, V1.8H
	mul	V30.8H, V16.8H, V3.8H
	sqrdmulh	V25.8H, V14.8H, V0.8H
	sqrdmulh	V26.8H, V16.8H, V2.8H
	sqrdmlsh	V25.8H, V29.8H, V4.H[0]
	sqrdmlsh	V26.8H, V30.8H, V4.H[0]
	sshr	V25.8H, V25.8H, #1
	sshr	V26.8H, V26.8H, #1
	ldr	Q0, [x2, #288]
	ldr	Q2, [x2, #304]
	ldr	Q1, [x3, #288]
	ldr	Q3, [x3, #304]
	mov	V29.16B, V17.16B
	mov	V30.16B, V19.16B
	trn1	V17.2D, V17.2D, V18.2D
	trn1	V19.2D, V19.2D, V20.2D
	trn2	V18.2D, V29.2D, V18.2D
	trn2	V20.2D, V30.2D, V20.2D
	mul	V29.8H, V18.8H, V1.8H
	mul	V30.8H, V20.8H, V3.8H
	sqrdmulh	V27.8H, V18.8H, V0.8H
	sqrdmulh	V28.8H, V20.8H, V2.8H
	sqrdmlsh	V27.8H, V29.8H, V4.H[0]
	sqrdmlsh	V28.8H, V30.8H, V4.H[0]
	sshr	V27.8H, V27.8H, #1
	sshr	V28.8H, V28.8H, #1
	sub	V6.8H, V5.8H, V21.8H
	add	V5.8H, V5.8H, V21.8H
	sub	V8.8H, V7.8H, V22.8H
	add	V7.8H, V7.8H, V22.8H
	sub	V10.8H, V9.8H, V23.8H
	add	V9.8H, V9.8H, V23.8H
	sub	V12.8H, V11.8H, V24.8H
	add	V11.8H, V11.8H, V24.8H
	sub	V14.8H, V13.8H, V25.8H
	add	V13.8H, V13.8H, V25.8H
	sub	V16.8H, V15.8H, V26.8H
	add	V15.8H, V15.8H, V26.8H
	sub	V18.8H, V17.8H, V27.8H
	add	V17.8H, V17.8H, V27.8H
	sub	V20.8H, V19.8H, V28.8H
	add	V19.8H, V19.8H, V28.8H
	ldr	Q0, [x2, #448]
	ldr	Q2, [x2, #464]
	ldr	Q1, [x3, #448]
	ldr	Q3, [x3, #464]
	mov	V29.16B, V5.16B
	mov	V30.16B, V7.16B
	trn1	V5.4S, V5.4S, V6.4S
	trn1	V7.4S, V7.4S, V8.4S
	trn2	V6.4S, V29.4S, V6.4S
	trn2	V8.4S, V30.4S, V8.4S
	mul	V29.8H, V6.8H, V1.8H
	mul	V30.8H, V8.8H, V3.8H
	sqrdmulh	V21.8H, V6.8H, V0.8H
	sqrdmulh	V22.8H, V8.8H, V2.8H
	sqrdmlsh	V21.8H, V29.8H, V4.H[0]
	sqrdmlsh	V22.8H, V30.8H, V4.H[0]
	sshr	V21.8H, V21.8H, #1
	sshr	V22.8H, V22.8H, #1
	ldr	Q0, [x2, #480]
	ldr	Q2, [x2, #496]
	ldr	Q1, [x3, #480]
	ldr	Q3, [x3, #496]
	mov	V29.16B, V9.16B
	mov	V30.16B, V11.16B
	trn1	V9.4S, V9.4S, V10.4S
	trn1	V11.4S, V11.4S, V12.4S
	trn2	V10.4S, V29.4S, V10.4S
	trn2	V12.4S, V30.4S, V12.4S
	mul	V29.8H, V10.8H, V1.8H
	mul	V30.8H, V12.8H, V3.8H
	sqrdmulh	V23.8H, V10.8H, V0.8H
	sqrdmulh	V24.8H, V12.8H, V2.8H
	sqrdmlsh	V23.8H, V29.8H, V4.H[0]
	sqrdmlsh	V24.8H, V30.8H, V4.H[0]
	sshr	V23.8H, V23.8H, #1
	sshr	V24.8H, V24.8H, #1
	ldr	Q0, [x2, #512]
	ldr	Q2, [x2, #528]
	ldr	Q1, [x3, #512]
	ldr	Q3, [x3, #528]
	mov	V29.16B, V13.16B
	mov	V30.16B, V15.16B
	trn1	V13.4S, V13.4S, V14.4S
	trn1	V15.4S, V15.4S, V16.4S
	trn2	V14.4S, V29.4S, V14.4S
	trn2	V16.4S, V30.4S, V16.4S
	mul	V29.8H, V14.8H, V1.8H
	mul	V30.8H, V16.8H, V3.8H
	sqrdmulh	V25.8H, V14.8H, V0.8H
	sqrdmulh	V26.8H, V16.8H, V2.8H
	sqrdmlsh	V25.8H, V29.8H, V4.H[0]
	sqrdmlsh	V26.8H, V30.8H, V4.H[0]
	sshr	V25.8H, V25.8H, #1
	sshr	V26.8H, V26.8H, #1
	ldr	Q0, [x2, #544]
	ldr	Q2, [x2, #560]
	ldr	Q1, [x3, #544]
	ldr	Q3, [x3, #560]
	mov	V29.16B, V17.16B
	mov	V30.16B, V19.16B
	trn1	V17.4S, V17.4S, V18.4S
	trn1	V19.4S, V19.4S, V20.4S
	trn2	V18.4S, V29.4S, V18.4S
	trn2	V20.4S, V30.4S, V20.4S
	mul	V29.8H, V18.8H, V1.8H
	mul	V30.8H, V20.8H, V3.8H
	sqrdmulh	V27.8H, V18.8H, V0.8H
	sqrdmulh	V28.8H, V20.8H, V2.8H
	sqrdmlsh	V27.8H, V29.8H, V4.H[0]
	sqrdmlsh	V28.8H, V30.8H, V4.H[0]
	sshr	V27.8H, V27.8H, #1
	sshr	V28.8H, V28.8H, #1
	sub	V6.8H, V5.8H, V21.8H
	add	V5.8H, V5.8H, V21.8H
	sub	V8.8H, V7.8H, V22.8H
	add	V7.8H, V7.8H, V22.8H
	sub	V10.8H, V9.8H, V23.8H
	add	V9.8H, V9.8H, V23.8H
	sub	V12.8H, V11.8H, V24.8H
	add	V11.8H, V11.8H, V24.8H
	sub	V14.8H, V13.8H, V25.8H
	add	V13.8H, V13.8H, V25.8H
	sub	V16.8H, V15.8H, V26.8H
	add	V15.8H, V15.8H, V26.8H
	sub	V18.8H, V17.8H, V27.8H
	add	V17.8H, V17.8H, V27.8H
	sub	V20.8H, V19.8H, V28.8H
	add	V19.8H, V19.8H, V28.8H
	sqdmulh	V21.8H, V5.8H, V4.H[2]
	sqdmulh	V22.8H, V6.8H, V4.H[2]
	sshr	V21.8H, V21.8H, #11
	sshr	V22.8H, V22.8H, #11
	mls	V5.8H, V21.8H, V4.H[0]
	mls	V6.8H, V22.8H, V4.H[0]
	sqdmulh	V21.8H, V7.8H, V4.H[2]
	sqdmulh	V22.8H, V8.8H, V4.H[2]
	sshr	V21.8H, V21.8H, #11
	sshr	V22.8H, V22.8H, #11
	mls	V7.8H, V21.8H, V4.H[0]
	mls	V8.8H, V22.8H, V4.H[0]
	sqdmulh	V21.8H, V9.8H, V4.H[2]
	sqdmulh	V22.8H, V10.8H, V4.H[2]
	sshr	V21.8H, V21.8H, #11
	sshr	V22.8H, V22.8H, #11
	mls	V9.8H, V21.8H, V4.H[0]
	mls	V10.8H, V22.8H, V4.H[0]
	sqdmulh	V21.8H, V11.8H, V4.H[2]
	sqdmulh	V22.8H, V12.8H, V4.H[2]
	sshr	V21.8H, V21.8H, #11
	sshr	V22.8H, V22.8H, #11
	mls	V11.8H, V21.8H, V4.H[0]
	mls	V12.8H, V22.8H, V4.H[0]
	sqdmulh	V21.8H, V13.8H, V4.H[2]
	sqdmulh	V22.8H, V14.8H, V4.H[2]
	sshr	V21.8H, V21.8H, #11
	sshr	V22.8H, V22.8H, #11
	mls	V13.8H, V21.8H, V4.H[0]
	mls	V14.8H, V22.8H, V4.H[0]
	sqdmulh	V21.8H, V15.8H, V4.H[2]
	sqdmulh	V22.8H, V16.8H, V4.H[2]
	sshr	V21.8H, V21.8H, #11
	sshr	V22.8H, V22.8H, #11
	mls	V15.8H, V21.8H, V4.H[0]
	mls	V16.8H, V22.8H, V4.H[0]
	sqdmulh	V21.8H, V17.8H, V4.H[2]
	sqdmulh	V22.8H, V18.8H, V4.H[2]
	sshr	V21.8H, V21.8H, #11
	sshr	V22.8H, V22.8H, #11
	mls	V17.8H, V21.8H, V4.H[0]
	mls	V18.8H, V22.8H, V4.H[0]
	sqdmulh	V21.8H, V19.8H, V4.H[2]
	sqdmulh	V22.8H, V20.8H, V4.H[2]
	sshr	V21.8H, V21.8H, #11
	sshr	V22.8H, V22.8H, #11
	mls	V19.8H, V21.8H, V4.H[0]
	mls	V20.8H, V22.8H, V4.H[0]
	mov	V29.16B, V5.16B
	trn1	V5.4S, V5.4S, V6.4S
	trn2	V6.4S, V29.4S, V6.4S
	mov	V29.16B, V5.16B
	trn1	V5.2D, V5.2D, V6.2D
	trn2	V6.2D, V29.2D, V6.2D
	mov	V29.16B, V7.16B
	trn1	V7.4S, V7.4S, V8.4S
	trn2	V8.4S, V29.4S, V8.4S
	mov	V29.16B, V7.16B
	trn1	V7.2D, V7.2D, V8.2D
	trn2	V8.2D, V29.2D, V8.2D
	mov	V29.16B, V9.16B
	trn1	V9.4S, V9.4S, V10.4S
	trn2	V10.4S, V29.4S, V10.4S
	mov	V29.16B, V9.16B
	trn1	V9.2D, V9.2D, V10.2D
	trn2	V10.2D, V29.2D, V10.2D
	mov	V29.16B, V11.16B
	trn1	V11.4S, V11.4S, V12.4S
	trn2	V12.4S, V29.4S, V12.4S
	mov	V29.16B, V11.16B
	trn1	V11.2D, V11.2D, V12.2D
	trn2	V12.2D, V29.2D, V12.2D
	mov	V29.16B, V13.16B
	trn1	V13.4S, V13.4S, V14.4S
	trn2	V14.4S, V29.4S, V14.4S
	mov	V29.16B, V13.16B
	trn1	V13.2D, V13.2D, V14.2D
	trn2	V14.2D, V29.2D, V14.2D
	mov	V29.16B, V15.16B
	trn1	V15.4S, V15.4S, V16.4S
	trn2	V16.4S, V29.4S, V16.4S
	mov	V29.16B, V15.16B
	trn1	V15.2D, V15.2D, V16.2D
	trn2	V16.2D, V29.2D, V16.2D
	mov	V29.16B, V17.16B
	trn1	V17.4S, V17.4S, V18.4S
	trn2	V18.4S, V29.4S, V18.4S
	mov	V29.16B, V17.16B
	trn1	V17.2D, V17.2D, V18.2D
	trn2	V18.2D, V29.2D, V18.2D
	mov	V29.16B, V19.16B
	trn1	V19.4S, V19.4S, V20.4S
	trn2	V20.4S, V29.4S, V20.4S
	mov	V29.16B, V19.16B
	trn1	V19.2D, V19.2D, V20.2D
	trn2	V20.2D, V29.2D, V20.2D
	stp	Q5, Q6, [x1]
	stp	Q7, Q8, [x1, #32]
	stp	Q9, Q10, [x1, #64]
	stp	Q11, Q12, [x1, #96]
	stp	Q13, Q14, [x1, #128]
	stp	Q15, Q16, [x1, #160]
	stp	Q17, Q18, [x1, #192]
	stp	Q19, Q20, [x1, #224]
	ldp	D8, D9, [x29, #16]
	ldp	D10, D11, [x29, #32]
	ldp	D12, D13, [x29, #48]
	ldp	D14, D15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
	ENDP
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mlkem_invntt_sqrdmlsh
mlkem_invntt_sqrdmlsh PROC
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	stp	D10, D11, [x29, #32]
	stp	D12, D13, [x29, #48]
	stp	D14, D15, [x29, #64]
	adrp	x2, L_mlkem_aarch64_zetas_inv
	add	x2, x2, L_mlkem_aarch64_zetas_inv
	adrp	x3, L_mlkem_aarch64_zetas_inv_qinv
	add	x3, x3, L_mlkem_aarch64_zetas_inv_qinv
	adrp	x4, L_mlkem_aarch64_consts
	add	x4, x4, L_mlkem_aarch64_consts
	add	x1, x0, #0x100
	ldr	Q8, [x4]
	ldp	Q9, Q10, [x0]
	ldp	Q11, Q12, [x0, #32]
	ldp	Q13, Q14, [x0, #64]
	ldp	Q15, Q16, [x0, #96]
	ldp	Q17, Q18, [x0, #128]
	ldp	Q19, Q20, [x0, #160]
	ldp	Q21, Q22, [x0, #192]
	ldp	Q23, Q24, [x0, #224]
	mov	V25.16B, V9.16B
	trn1	V9.2D, V9.2D, V10.2D
	trn2	V10.2D, V25.2D, V10.2D
	mov	V25.16B, V9.16B
	trn1	V9.4S, V9.4S, V10.4S
	trn2	V10.4S, V25.4S, V10.4S
	mov	V25.16B, V11.16B
	trn1	V11.2D, V11.2D, V12.2D
	trn2	V12.2D, V25.2D, V12.2D
	mov	V25.16B, V11.16B
	trn1	V11.4S, V11.4S, V12.4S
	trn2	V12.4S, V25.4S, V12.4S
	mov	V25.16B, V13.16B
	trn1	V13.2D, V13.2D, V14.2D
	trn2	V14.2D, V25.2D, V14.2D
	mov	V25.16B, V13.16B
	trn1	V13.4S, V13.4S, V14.4S
	trn2	V14.4S, V25.4S, V14.4S
	mov	V25.16B, V15.16B
	trn1	V15.2D, V15.2D, V16.2D
	trn2	V16.2D, V25.2D, V16.2D
	mov	V25.16B, V15.16B
	trn1	V15.4S, V15.4S, V16.4S
	trn2	V16.4S, V25.4S, V16.4S
	mov	V25.16B, V17.16B
	trn1	V17.2D, V17.2D, V18.2D
	trn2	V18.2D, V25.2D, V18.2D
	mov	V25.16B, V17.16B
	trn1	V17.4S, V17.4S, V18.4S
	trn2	V18.4S, V25.4S, V18.4S
	mov	V25.16B, V19.16B
	trn1	V19.2D, V19.2D, V20.2D
	trn2	V20.2D, V25.2D, V20.2D
	mov	V25.16B, V19.16B
	trn1	V19.4S, V19.4S, V20.4S
	trn2	V20.4S, V25.4S, V20.4S
	mov	V25.16B, V21.16B
	trn1	V21.2D, V21.2D, V22.2D
	trn2	V22.2D, V25.2D, V22.2D
	mov	V25.16B, V21.16B
	trn1	V21.4S, V21.4S, V22.4S
	trn2	V22.4S, V25.4S, V22.4S
	mov	V25.16B, V23.16B
	trn1	V23.2D, V23.2D, V24.2D
	trn2	V24.2D, V25.2D, V24.2D
	mov	V25.16B, V23.16B
	trn1	V23.4S, V23.4S, V24.4S
	trn2	V24.4S, V25.4S, V24.4S
	ldr	Q0, [x2]
	ldr	Q1, [x2, #16]
	ldr	Q2, [x3]
	ldr	Q3, [x3, #16]
	sub	V26.8H, V9.8H, V10.8H
	sub	V28.8H, V11.8H, V12.8H
	add	V9.8H, V9.8H, V10.8H
	add	V11.8H, V11.8H, V12.8H
	mul	V25.8H, V26.8H, V2.8H
	mul	V27.8H, V28.8H, V3.8H
	sqrdmulh	V10.8H, V26.8H, V0.8H
	sqrdmulh	V12.8H, V28.8H, V1.8H
	sqrdmlsh	V10.8H, V25.8H, V8.H[0]
	sqrdmlsh	V12.8H, V27.8H, V8.H[0]
	sshr	V10.8H, V10.8H, #1
	sshr	V12.8H, V12.8H, #1
	ldr	Q0, [x2, #32]
	ldr	Q1, [x2, #48]
	ldr	Q2, [x3, #32]
	ldr	Q3, [x3, #48]
	sub	V26.8H, V13.8H, V14.8H
	sub	V28.8H, V15.8H, V16.8H
	add	V13.8H, V13.8H, V14.8H
	add	V15.8H, V15.8H, V16.8H
	mul	V25.8H, V26.8H, V2.8H
	mul	V27.8H, V28.8H, V3.8H
	sqrdmulh	V14.8H, V26.8H, V0.8H
	sqrdmulh	V16.8H, V28.8H, V1.8H
	sqrdmlsh	V14.8H, V25.8H, V8.H[0]
	sqrdmlsh	V16.8H, V27.8H, V8.H[0]
	sshr	V14.8H, V14.8H, #1
	sshr	V16.8H, V16.8H, #1
	ldr	Q0, [x2, #64]
	ldr	Q1, [x2, #80]
	ldr	Q2, [x3, #64]
	ldr	Q3, [x3, #80]
	sub	V26.8H, V17.8H, V18.8H
	sub	V28.8H, V19.8H, V20.8H
	add	V17.8H, V17.8H, V18.8H
	add	V19.8H, V19.8H, V20.8H
	mul	V25.8H, V26.8H, V2.8H
	mul	V27.8H, V28.8H, V3.8H
	sqrdmulh	V18.8H, V26.8H, V0.8H
	sqrdmulh	V20.8H, V28.8H, V1.8H
	sqrdmlsh	V18.8H, V25.8H, V8.H[0]
	sqrdmlsh	V20.8H, V27.8H, V8.H[0]
	sshr	V18.8H, V18.8H, #1
	sshr	V20.8H, V20.8H, #1
	ldr	Q0, [x2, #96]
	ldr	Q1, [x2, #112]
	ldr	Q2, [x3, #96]
	ldr	Q3, [x3, #112]
	sub	V26.8H, V21.8H, V22.8H
	sub	V28.8H, V23.8H, V24.8H
	add	V21.8H, V21.8H, V22.8H
	add	V23.8H, V23.8H, V24.8H
	mul	V25.8H, V26.8H, V2.8H
	mul	V27.8H, V28.8H, V3.8H
	sqrdmulh	V22.8H, V26.8H, V0.8H
	sqrdmulh	V24.8H, V28.8H, V1.8H
	sqrdmlsh	V22.8H, V25.8H, V8.H[0]
	sqrdmlsh	V24.8H, V27.8H, V8.H[0]
	sshr	V22.8H, V22.8H, #1
	sshr	V24.8H, V24.8H, #1
	ldr	Q0, [x2, #256]
	ldr	Q1, [x2, #272]
	ldr	Q2, [x3, #256]
	ldr	Q3, [x3, #272]
	mov	V25.16B, V9.16B
	mov	V26.16B, V11.16B
	trn1	V9.4S, V9.4S, V10.4S
	trn1	V11.4S, V11.4S, V12.4S
	trn2	V10.4S, V25.4S, V10.4S
	trn2	V12.4S, V26.4S, V12.4S
	sub	V26.8H, V9.8H, V10.8H
	sub	V28.8H, V11.8H, V12.8H
	add	V9.8H, V9.8H, V10.8H
	add	V11.8H, V11.8H, V12.8H
	mul	V25.8H, V26.8H, V2.8H
	mul	V27.8H, V28.8H, V3.8H
	sqrdmulh	V10.8H, V26.8H, V0.8H
	sqrdmulh	V12.8H, V28.8H, V1.8H
	sqrdmlsh	V10.8H, V25.8H, V8.H[0]
	sqrdmlsh	V12.8H, V27.8H, V8.H[0]
	sshr	V10.8H, V10.8H, #1
	sshr	V12.8H, V12.8H, #1
	ldr	Q0, [x2, #288]
	ldr	Q1, [x2, #304]
	ldr	Q2, [x3, #288]
	ldr	Q3, [x3, #304]
	mov	V25.16B, V13.16B
	mov	V26.16B, V15.16B
	trn1	V13.4S, V13.4S, V14.4S
	trn1	V15.4S, V15.4S, V16.4S
	trn2	V14.4S, V25.4S, V14.4S
	trn2	V16.4S, V26.4S, V16.4S
	sub	V26.8H, V13.8H, V14.8H
	sub	V28.8H, V15.8H, V16.8H
	add	V13.8H, V13.8H, V14.8H
	add	V15.8H, V15.8H, V16.8H
	mul	V25.8H, V26.8H, V2.8H
	mul	V27.8H, V28.8H, V3.8H
	sqrdmulh	V14.8H, V26.8H, V0.8H
	sqrdmulh	V16.8H, V28.8H, V1.8H
	sqrdmlsh	V14.8H, V25.8H, V8.H[0]
	sqrdmlsh	V16.8H, V27.8H, V8.H[0]
	sshr	V14.8H, V14.8H, #1
	sshr	V16.8H, V16.8H, #1
	ldr	Q0, [x2, #320]
	ldr	Q1, [x2, #336]
	ldr	Q2, [x3, #320]
	ldr	Q3, [x3, #336]
	mov	V25.16B, V17.16B
	mov	V26.16B, V19.16B
	trn1	V17.4S, V17.4S, V18.4S
	trn1	V19.4S, V19.4S, V20.4S
	trn2	V18.4S, V25.4S, V18.4S
	trn2	V20.4S, V26.4S, V20.4S
	sub	V26.8H, V17.8H, V18.8H
	sub	V28.8H, V19.8H, V20.8H
	add	V17.8H, V17.8H, V18.8H
	add	V19.8H, V19.8H, V20.8H
	mul	V25.8H, V26.8H, V2.8H
	mul	V27.8H, V28.8H, V3.8H
	sqrdmulh	V18.8H, V26.8H, V0.8H
	sqrdmulh	V20.8H, V28.8H, V1.8H
	sqrdmlsh	V18.8H, V25.8H, V8.H[0]
	sqrdmlsh	V20.8H, V27.8H, V8.H[0]
	sshr	V18.8H, V18.8H, #1
	sshr	V20.8H, V20.8H, #1
	ldr	Q0, [x2, #352]
	ldr	Q1, [x2, #368]
	ldr	Q2, [x3, #352]
	ldr	Q3, [x3, #368]
	mov	V25.16B, V21.16B
	mov	V26.16B, V23.16B
	trn1	V21.4S, V21.4S, V22.4S
	trn1	V23.4S, V23.4S, V24.4S
	trn2	V22.4S, V25.4S, V22.4S
	trn2	V24.4S, V26.4S, V24.4S
	sub	V26.8H, V21.8H, V22.8H
	sub	V28.8H, V23.8H, V24.8H
	add	V21.8H, V21.8H, V22.8H
	add	V23.8H, V23.8H, V24.8H
	mul	V25.8H, V26.8H, V2.8H
	mul	V27.8H, V28.8H, V3.8H
	sqrdmulh	V22.8H, V26.8H, V0.8H
	sqrdmulh	V24.8H, V28.8H, V1.8H
	sqrdmlsh	V22.8H, V25.8H, V8.H[0]
	sqrdmlsh	V24.8H, V27.8H, V8.H[0]
	sshr	V22.8H, V22.8H, #1
	sshr	V24.8H, V24.8H, #1
	ldr	Q0, [x2, #512]
	ldr	Q2, [x3, #512]
	mov	V25.16B, V9.16B
	mov	V26.16B, V11.16B
	trn1	V9.2D, V9.2D, V10.2D
	trn1	V11.2D, V11.2D, V12.2D
	trn2	V10.2D, V25.2D, V10.2D
	trn2	V12.2D, V26.2D, V12.2D
	sub	V26.8H, V9.8H, V10.8H
	sub	V28.8H, V11.8H, V12.8H
	add	V9.8H, V9.8H, V10.8H
	add	V11.8H, V11.8H, V12.8H
	mul	V25.8H, V26.8H, V2.H[0]
	mul	V27.8H, V28.8H, V2.H[1]
	sqrdmulh	V10.8H, V26.8H, V0.H[0]
	sqrdmulh	V12.8H, V28.8H, V0.H[1]
	sqrdmlsh	V10.8H, V25.8H, V8.H[0]
	sqrdmlsh	V12.8H, V27.8H, V8.H[0]
	sshr	V10.8H, V10.8H, #1
	sshr	V12.8H, V12.8H, #1
	mov	V25.16B, V13.16B
	mov	V26.16B, V15.16B
	trn1	V13.2D, V13.2D, V14.2D
	trn1	V15.2D, V15.2D, V16.2D
	trn2	V14.2D, V25.2D, V14.2D
	trn2	V16.2D, V26.2D, V16.2D
	sub	V26.8H, V13.8H, V14.8H
	sub	V28.8H, V15.8H, V16.8H
	add	V13.8H, V13.8H, V14.8H
	add	V15.8H, V15.8H, V16.8H
	mul	V25.8H, V26.8H, V2.H[2]
	mul	V27.8H, V28.8H, V2.H[3]
	sqrdmulh	V14.8H, V26.8H, V0.H[2]
	sqrdmulh	V16.8H, V28.8H, V0.H[3]
	sqrdmlsh	V14.8H, V25.8H, V8.H[0]
	sqrdmlsh	V16.8H, V27.8H, V8.H[0]
	sshr	V14.8H, V14.8H, #1
	sshr	V16.8H, V16.8H, #1
	mov	V25.16B, V17.16B
	mov	V26.16B, V19.16B
	trn1	V17.2D, V17.2D, V18.2D
	trn1	V19.2D, V19.2D, V20.2D
	trn2	V18.2D, V25.2D, V18.2D
	trn2	V20.2D, V26.2D, V20.2D
	sub	V26.8H, V17.8H, V18.8H
	sub	V28.8H, V19.8H, V20.8H
	add	V17.8H, V17.8H, V18.8H
	add	V19.8H, V19.8H, V20.8H
	mul	V25.8H, V26.8H, V2.H[4]
	mul	V27.8H, V28.8H, V2.H[5]
	sqrdmulh	V18.8H, V26.8H, V0.H[4]
	sqrdmulh	V20.8H, V28.8H, V0.H[5]
	sqrdmlsh	V18.8H, V25.8H, V8.H[0]
	sqrdmlsh	V20.8H, V27.8H, V8.H[0]
	sshr	V18.8H, V18.8H, #1
	sshr	V20.8H, V20.8H, #1
	mov	V25.16B, V21.16B
	mov	V26.16B, V23.16B
	trn1	V21.2D, V21.2D, V22.2D
	trn1	V23.2D, V23.2D, V24.2D
	trn2	V22.2D, V25.2D, V22.2D
	trn2	V24.2D, V26.2D, V24.2D
	sub	V26.8H, V21.8H, V22.8H
	sub	V28.8H, V23.8H, V24.8H
	add	V21.8H, V21.8H, V22.8H
	add	V23.8H, V23.8H, V24.8H
	mul	V25.8H, V26.8H, V2.H[6]
	mul	V27.8H, V28.8H, V2.H[7]
	sqrdmulh	V22.8H, V26.8H, V0.H[6]
	sqrdmulh	V24.8H, V28.8H, V0.H[7]
	sqrdmlsh	V22.8H, V25.8H, V8.H[0]
	sqrdmlsh	V24.8H, V27.8H, V8.H[0]
	sshr	V22.8H, V22.8H, #1
	sshr	V24.8H, V24.8H, #1
	sqdmulh	V25.8H, V9.8H, V8.H[2]
	sqdmulh	V26.8H, V11.8H, V8.H[2]
	sshr	V25.8H, V25.8H, #11
	sshr	V26.8H, V26.8H, #11
	mls	V9.8H, V25.8H, V8.H[0]
	mls	V11.8H, V26.8H, V8.H[0]
	sqdmulh	V25.8H, V13.8H, V8.H[2]
	sqdmulh	V26.8H, V15.8H, V8.H[2]
	sshr	V25.8H, V25.8H, #11
	sshr	V26.8H, V26.8H, #11
	mls	V13.8H, V25.8H, V8.H[0]
	mls	V15.8H, V26.8H, V8.H[0]
	sqdmulh	V25.8H, V17.8H, V8.H[2]
	sqdmulh	V26.8H, V19.8H, V8.H[2]
	sshr	V25.8H, V25.8H, #11
	sshr	V26.8H, V26.8H, #11
	mls	V17.8H, V25.8H, V8.H[0]
	mls	V19.8H, V26.8H, V8.H[0]
	sqdmulh	V25.8H, V21.8H, V8.H[2]
	sqdmulh	V26.8H, V23.8H, V8.H[2]
	sshr	V25.8H, V25.8H, #11
	sshr	V26.8H, V26.8H, #11
	mls	V21.8H, V25.8H, V8.H[0]
	mls	V23.8H, V26.8H, V8.H[0]
	stp	Q9, Q10, [x0]
	stp	Q11, Q12, [x0, #32]
	stp	Q13, Q14, [x0, #64]
	stp	Q15, Q16, [x0, #96]
	stp	Q17, Q18, [x0, #128]
	stp	Q19, Q20, [x0, #160]
	stp	Q21, Q22, [x0, #192]
	stp	Q23, Q24, [x0, #224]
	ldp	Q9, Q10, [x1]
	ldp	Q11, Q12, [x1, #32]
	ldp	Q13, Q14, [x1, #64]
	ldp	Q15, Q16, [x1, #96]
	ldp	Q17, Q18, [x1, #128]
	ldp	Q19, Q20, [x1, #160]
	ldp	Q21, Q22, [x1, #192]
	ldp	Q23, Q24, [x1, #224]
	mov	V25.16B, V9.16B
	trn1	V9.2D, V9.2D, V10.2D
	trn2	V10.2D, V25.2D, V10.2D
	mov	V25.16B, V9.16B
	trn1	V9.4S, V9.4S, V10.4S
	trn2	V10.4S, V25.4S, V10.4S
	mov	V25.16B, V11.16B
	trn1	V11.2D, V11.2D, V12.2D
	trn2	V12.2D, V25.2D, V12.2D
	mov	V25.16B, V11.16B
	trn1	V11.4S, V11.4S, V12.4S
	trn2	V12.4S, V25.4S, V12.4S
	mov	V25.16B, V13.16B
	trn1	V13.2D, V13.2D, V14.2D
	trn2	V14.2D, V25.2D, V14.2D
	mov	V25.16B, V13.16B
	trn1	V13.4S, V13.4S, V14.4S
	trn2	V14.4S, V25.4S, V14.4S
	mov	V25.16B, V15.16B
	trn1	V15.2D, V15.2D, V16.2D
	trn2	V16.2D, V25.2D, V16.2D
	mov	V25.16B, V15.16B
	trn1	V15.4S, V15.4S, V16.4S
	trn2	V16.4S, V25.4S, V16.4S
	mov	V25.16B, V17.16B
	trn1	V17.2D, V17.2D, V18.2D
	trn2	V18.2D, V25.2D, V18.2D
	mov	V25.16B, V17.16B
	trn1	V17.4S, V17.4S, V18.4S
	trn2	V18.4S, V25.4S, V18.4S
	mov	V25.16B, V19.16B
	trn1	V19.2D, V19.2D, V20.2D
	trn2	V20.2D, V25.2D, V20.2D
	mov	V25.16B, V19.16B
	trn1	V19.4S, V19.4S, V20.4S
	trn2	V20.4S, V25.4S, V20.4S
	mov	V25.16B, V21.16B
	trn1	V21.2D, V21.2D, V22.2D
	trn2	V22.2D, V25.2D, V22.2D
	mov	V25.16B, V21.16B
	trn1	V21.4S, V21.4S, V22.4S
	trn2	V22.4S, V25.4S, V22.4S
	mov	V25.16B, V23.16B
	trn1	V23.2D, V23.2D, V24.2D
	trn2	V24.2D, V25.2D, V24.2D
	mov	V25.16B, V23.16B
	trn1	V23.4S, V23.4S, V24.4S
	trn2	V24.4S, V25.4S, V24.4S
	ldr	Q0, [x2, #128]
	ldr	Q1, [x2, #144]
	ldr	Q2, [x3, #128]
	ldr	Q3, [x3, #144]
	sub	V26.8H, V9.8H, V10.8H
	sub	V28.8H, V11.8H, V12.8H
	add	V9.8H, V9.8H, V10.8H
	add	V11.8H, V11.8H, V12.8H
	mul	V25.8H, V26.8H, V2.8H
	mul	V27.8H, V28.8H, V3.8H
	sqrdmulh	V10.8H, V26.8H, V0.8H
	sqrdmulh	V12.8H, V28.8H, V1.8H
	sqrdmlsh	V10.8H, V25.8H, V8.H[0]
	sqrdmlsh	V12.8H, V27.8H, V8.H[0]
	sshr	V10.8H, V10.8H, #1
	sshr	V12.8H, V12.8H, #1
	ldr	Q0, [x2, #160]
	ldr	Q1, [x2, #176]
	ldr	Q2, [x3, #160]
	ldr	Q3, [x3, #176]
	sub	V26.8H, V13.8H, V14.8H
	sub	V28.8H, V15.8H, V16.8H
	add	V13.8H, V13.8H, V14.8H
	add	V15.8H, V15.8H, V16.8H
	mul	V25.8H, V26.8H, V2.8H
	mul	V27.8H, V28.8H, V3.8H
	sqrdmulh	V14.8H, V26.8H, V0.8H
	sqrdmulh	V16.8H, V28.8H, V1.8H
	sqrdmlsh	V14.8H, V25.8H, V8.H[0]
	sqrdmlsh	V16.8H, V27.8H, V8.H[0]
	sshr	V14.8H, V14.8H, #1
	sshr	V16.8H, V16.8H, #1
	ldr	Q0, [x2, #192]
	ldr	Q1, [x2, #208]
	ldr	Q2, [x3, #192]
	ldr	Q3, [x3, #208]
	sub	V26.8H, V17.8H, V18.8H
	sub	V28.8H, V19.8H, V20.8H
	add	V17.8H, V17.8H, V18.8H
	add	V19.8H, V19.8H, V20.8H
	mul	V25.8H, V26.8H, V2.8H
	mul	V27.8H, V28.8H, V3.8H
	sqrdmulh	V18.8H, V26.8H, V0.8H
	sqrdmulh	V20.8H, V28.8H, V1.8H
	sqrdmlsh	V18.8H, V25.8H, V8.H[0]
	sqrdmlsh	V20.8H, V27.8H, V8.H[0]
	sshr	V18.8H, V18.8H, #1
	sshr	V20.8H, V20.8H, #1
	ldr	Q0, [x2, #224]
	ldr	Q1, [x2, #240]
	ldr	Q2, [x3, #224]
	ldr	Q3, [x3, #240]
	sub	V26.8H, V21.8H, V22.8H
	sub	V28.8H, V23.8H, V24.8H
	add	V21.8H, V21.8H, V22.8H
	add	V23.8H, V23.8H, V24.8H
	mul	V25.8H, V26.8H, V2.8H
	mul	V27.8H, V28.8H, V3.8H
	sqrdmulh	V22.8H, V26.8H, V0.8H
	sqrdmulh	V24.8H, V28.8H, V1.8H
	sqrdmlsh	V22.8H, V25.8H, V8.H[0]
	sqrdmlsh	V24.8H, V27.8H, V8.H[0]
	sshr	V22.8H, V22.8H, #1
	sshr	V24.8H, V24.8H, #1
	ldr	Q0, [x2, #384]
	ldr	Q1, [x2, #400]
	ldr	Q2, [x3, #384]
	ldr	Q3, [x3, #400]
	mov	V25.16B, V9.16B
	mov	V26.16B, V11.16B
	trn1	V9.4S, V9.4S, V10.4S
	trn1	V11.4S, V11.4S, V12.4S
	trn2	V10.4S, V25.4S, V10.4S
	trn2	V12.4S, V26.4S, V12.4S
	sub	V26.8H, V9.8H, V10.8H
	sub	V28.8H, V11.8H, V12.8H
	add	V9.8H, V9.8H, V10.8H
	add	V11.8H, V11.8H, V12.8H
	mul	V25.8H, V26.8H, V2.8H
	mul	V27.8H, V28.8H, V3.8H
	sqrdmulh	V10.8H, V26.8H, V0.8H
	sqrdmulh	V12.8H, V28.8H, V1.8H
	sqrdmlsh	V10.8H, V25.8H, V8.H[0]
	sqrdmlsh	V12.8H, V27.8H, V8.H[0]
	sshr	V10.8H, V10.8H, #1
	sshr	V12.8H, V12.8H, #1
	ldr	Q0, [x2, #416]
	ldr	Q1, [x2, #432]
	ldr	Q2, [x3, #416]
	ldr	Q3, [x3, #432]
	mov	V25.16B, V13.16B
	mov	V26.16B, V15.16B
	trn1	V13.4S, V13.4S, V14.4S
	trn1	V15.4S, V15.4S, V16.4S
	trn2	V14.4S, V25.4S, V14.4S
	trn2	V16.4S, V26.4S, V16.4S
	sub	V26.8H, V13.8H, V14.8H
	sub	V28.8H, V15.8H, V16.8H
	add	V13.8H, V13.8H, V14.8H
	add	V15.8H, V15.8H, V16.8H
	mul	V25.8H, V26.8H, V2.8H
	mul	V27.8H, V28.8H, V3.8H
	sqrdmulh	V14.8H, V26.8H, V0.8H
	sqrdmulh	V16.8H, V28.8H, V1.8H
	sqrdmlsh	V14.8H, V25.8H, V8.H[0]
	sqrdmlsh	V16.8H, V27.8H, V8.H[0]
	sshr	V14.8H, V14.8H, #1
	sshr	V16.8H, V16.8H, #1
	ldr	Q0, [x2, #448]
	ldr	Q1, [x2, #464]
	ldr	Q2, [x3, #448]
	ldr	Q3, [x3, #464]
	mov	V25.16B, V17.16B
	mov	V26.16B, V19.16B
	trn1	V17.4S, V17.4S, V18.4S
	trn1	V19.4S, V19.4S, V20.4S
	trn2	V18.4S, V25.4S, V18.4S
	trn2	V20.4S, V26.4S, V20.4S
	sub	V26.8H, V17.8H, V18.8H
	sub	V28.8H, V19.8H, V20.8H
	add	V17.8H, V17.8H, V18.8H
	add	V19.8H, V19.8H, V20.8H
	mul	V25.8H, V26.8H, V2.8H
	mul	V27.8H, V28.8H, V3.8H
	sqrdmulh	V18.8H, V26.8H, V0.8H
	sqrdmulh	V20.8H, V28.8H, V1.8H
	sqrdmlsh	V18.8H, V25.8H, V8.H[0]
	sqrdmlsh	V20.8H, V27.8H, V8.H[0]
	sshr	V18.8H, V18.8H, #1
	sshr	V20.8H, V20.8H, #1
	ldr	Q0, [x2, #480]
	ldr	Q1, [x2, #496]
	ldr	Q2, [x3, #480]
	ldr	Q3, [x3, #496]
	mov	V25.16B, V21.16B
	mov	V26.16B, V23.16B
	trn1	V21.4S, V21.4S, V22.4S
	trn1	V23.4S, V23.4S, V24.4S
	trn2	V22.4S, V25.4S, V22.4S
	trn2	V24.4S, V26.4S, V24.4S
	sub	V26.8H, V21.8H, V22.8H
	sub	V28.8H, V23.8H, V24.8H
	add	V21.8H, V21.8H, V22.8H
	add	V23.8H, V23.8H, V24.8H
	mul	V25.8H, V26.8H, V2.8H
	mul	V27.8H, V28.8H, V3.8H
	sqrdmulh	V22.8H, V26.8H, V0.8H
	sqrdmulh	V24.8H, V28.8H, V1.8H
	sqrdmlsh	V22.8H, V25.8H, V8.H[0]
	sqrdmlsh	V24.8H, V27.8H, V8.H[0]
	sshr	V22.8H, V22.8H, #1
	sshr	V24.8H, V24.8H, #1
	ldr	Q0, [x2, #528]
	ldr	Q2, [x3, #528]
	mov	V25.16B, V9.16B
	mov	V26.16B, V11.16B
	trn1	V9.2D, V9.2D, V10.2D
	trn1	V11.2D, V11.2D, V12.2D
	trn2	V10.2D, V25.2D, V10.2D
	trn2	V12.2D, V26.2D, V12.2D
	sub	V26.8H, V9.8H, V10.8H
	sub	V28.8H, V11.8H, V12.8H
	add	V9.8H, V9.8H, V10.8H
	add	V11.8H, V11.8H, V12.8H
	mul	V25.8H, V26.8H, V2.H[0]
	mul	V27.8H, V28.8H, V2.H[1]
	sqrdmulh	V10.8H, V26.8H, V0.H[0]
	sqrdmulh	V12.8H, V28.8H, V0.H[1]
	sqrdmlsh	V10.8H, V25.8H, V8.H[0]
	sqrdmlsh	V12.8H, V27.8H, V8.H[0]
	sshr	V10.8H, V10.8H, #1
	sshr	V12.8H, V12.8H, #1
	mov	V25.16B, V13.16B
	mov	V26.16B, V15.16B
	trn1	V13.2D, V13.2D, V14.2D
	trn1	V15.2D, V15.2D, V16.2D
	trn2	V14.2D, V25.2D, V14.2D
	trn2	V16.2D, V26.2D, V16.2D
	sub	V26.8H, V13.8H, V14.8H
	sub	V28.8H, V15.8H, V16.8H
	add	V13.8H, V13.8H, V14.8H
	add	V15.8H, V15.8H, V16.8H
	mul	V25.8H, V26.8H, V2.H[2]
	mul	V27.8H, V28.8H, V2.H[3]
	sqrdmulh	V14.8H, V26.8H, V0.H[2]
	sqrdmulh	V16.8H, V28.8H, V0.H[3]
	sqrdmlsh	V14.8H, V25.8H, V8.H[0]
	sqrdmlsh	V16.8H, V27.8H, V8.H[0]
	sshr	V14.8H, V14.8H, #1
	sshr	V16.8H, V16.8H, #1
	mov	V25.16B, V17.16B
	mov	V26.16B, V19.16B
	trn1	V17.2D, V17.2D, V18.2D
	trn1	V19.2D, V19.2D, V20.2D
	trn2	V18.2D, V25.2D, V18.2D
	trn2	V20.2D, V26.2D, V20.2D
	sub	V26.8H, V17.8H, V18.8H
	sub	V28.8H, V19.8H, V20.8H
	add	V17.8H, V17.8H, V18.8H
	add	V19.8H, V19.8H, V20.8H
	mul	V25.8H, V26.8H, V2.H[4]
	mul	V27.8H, V28.8H, V2.H[5]
	sqrdmulh	V18.8H, V26.8H, V0.H[4]
	sqrdmulh	V20.8H, V28.8H, V0.H[5]
	sqrdmlsh	V18.8H, V25.8H, V8.H[0]
	sqrdmlsh	V20.8H, V27.8H, V8.H[0]
	sshr	V18.8H, V18.8H, #1
	sshr	V20.8H, V20.8H, #1
	mov	V25.16B, V21.16B
	mov	V26.16B, V23.16B
	trn1	V21.2D, V21.2D, V22.2D
	trn1	V23.2D, V23.2D, V24.2D
	trn2	V22.2D, V25.2D, V22.2D
	trn2	V24.2D, V26.2D, V24.2D
	sub	V26.8H, V21.8H, V22.8H
	sub	V28.8H, V23.8H, V24.8H
	add	V21.8H, V21.8H, V22.8H
	add	V23.8H, V23.8H, V24.8H
	mul	V25.8H, V26.8H, V2.H[6]
	mul	V27.8H, V28.8H, V2.H[7]
	sqrdmulh	V22.8H, V26.8H, V0.H[6]
	sqrdmulh	V24.8H, V28.8H, V0.H[7]
	sqrdmlsh	V22.8H, V25.8H, V8.H[0]
	sqrdmlsh	V24.8H, V27.8H, V8.H[0]
	sshr	V22.8H, V22.8H, #1
	sshr	V24.8H, V24.8H, #1
	sqdmulh	V25.8H, V9.8H, V8.H[2]
	sqdmulh	V26.8H, V11.8H, V8.H[2]
	sshr	V25.8H, V25.8H, #11
	sshr	V26.8H, V26.8H, #11
	mls	V9.8H, V25.8H, V8.H[0]
	mls	V11.8H, V26.8H, V8.H[0]
	sqdmulh	V25.8H, V13.8H, V8.H[2]
	sqdmulh	V26.8H, V15.8H, V8.H[2]
	sshr	V25.8H, V25.8H, #11
	sshr	V26.8H, V26.8H, #11
	mls	V13.8H, V25.8H, V8.H[0]
	mls	V15.8H, V26.8H, V8.H[0]
	sqdmulh	V25.8H, V17.8H, V8.H[2]
	sqdmulh	V26.8H, V19.8H, V8.H[2]
	sshr	V25.8H, V25.8H, #11
	sshr	V26.8H, V26.8H, #11
	mls	V17.8H, V25.8H, V8.H[0]
	mls	V19.8H, V26.8H, V8.H[0]
	sqdmulh	V25.8H, V21.8H, V8.H[2]
	sqdmulh	V26.8H, V23.8H, V8.H[2]
	sshr	V25.8H, V25.8H, #11
	sshr	V26.8H, V26.8H, #11
	mls	V21.8H, V25.8H, V8.H[0]
	mls	V23.8H, V26.8H, V8.H[0]
	stp	Q9, Q10, [x1]
	stp	Q11, Q12, [x1, #32]
	stp	Q13, Q14, [x1, #64]
	stp	Q15, Q16, [x1, #96]
	stp	Q17, Q18, [x1, #128]
	stp	Q19, Q20, [x1, #160]
	stp	Q21, Q22, [x1, #192]
	stp	Q23, Q24, [x1, #224]
	ldr	Q4, [x2, #544]
	ldr	Q5, [x2, #560]
	ldr	Q6, [x3, #544]
	ldr	Q7, [x3, #560]
	ldr	Q9, [x0]
	ldr	Q10, [x0, #32]
	ldr	Q11, [x0, #64]
	ldr	Q12, [x0, #96]
	ldr	Q13, [x0, #128]
	ldr	Q14, [x0, #160]
	ldr	Q15, [x0, #192]
	ldr	Q16, [x0, #224]
	ldr	Q17, [x1]
	ldr	Q18, [x1, #32]
	ldr	Q19, [x1, #64]
	ldr	Q20, [x1, #96]
	ldr	Q21, [x1, #128]
	ldr	Q22, [x1, #160]
	ldr	Q23, [x1, #192]
	ldr	Q24, [x1, #224]
	sub	V26.8H, V9.8H, V10.8H
	sub	V28.8H, V11.8H, V12.8H
	add	V9.8H, V9.8H, V10.8H
	add	V11.8H, V11.8H, V12.8H
	mul	V25.8H, V26.8H, V6.H[0]
	mul	V27.8H, V28.8H, V6.H[1]
	sqrdmulh	V10.8H, V26.8H, V4.H[0]
	sqrdmulh	V12.8H, V28.8H, V4.H[1]
	sqrdmlsh	V10.8H, V25.8H, V8.H[0]
	sqrdmlsh	V12.8H, V27.8H, V8.H[0]
	sshr	V10.8H, V10.8H, #1
	sshr	V12.8H, V12.8H, #1
	sub	V26.8H, V13.8H, V14.8H
	sub	V28.8H, V15.8H, V16.8H
	add	V13.8H, V13.8H, V14.8H
	add	V15.8H, V15.8H, V16.8H
	mul	V25.8H, V26.8H, V6.H[2]
	mul	V27.8H, V28.8H, V6.H[3]
	sqrdmulh	V14.8H, V26.8H, V4.H[2]
	sqrdmulh	V16.8H, V28.8H, V4.H[3]
	sqrdmlsh	V14.8H, V25.8H, V8.H[0]
	sqrdmlsh	V16.8H, V27.8H, V8.H[0]
	sshr	V14.8H, V14.8H, #1
	sshr	V16.8H, V16.8H, #1
	sub	V26.8H, V17.8H, V18.8H
	sub	V28.8H, V19.8H, V20.8H
	add	V17.8H, V17.8H, V18.8H
	add	V19.8H, V19.8H, V20.8H
	mul	V25.8H, V26.8H, V6.H[4]
	mul	V27.8H, V28.8H, V6.H[5]
	sqrdmulh	V18.8H, V26.8H, V4.H[4]
	sqrdmulh	V20.8H, V28.8H, V4.H[5]
	sqrdmlsh	V18.8H, V25.8H, V8.H[0]
	sqrdmlsh	V20.8H, V27.8H, V8.H[0]
	sshr	V18.8H, V18.8H, #1
	sshr	V20.8H, V20.8H, #1
	sub	V26.8H, V21.8H, V22.8H
	sub	V28.8H, V23.8H, V24.8H
	add	V21.8H, V21.8H, V22.8H
	add	V23.8H, V23.8H, V24.8H
	mul	V25.8H, V26.8H, V6.H[6]
	mul	V27.8H, V28.8H, V6.H[7]
	sqrdmulh	V22.8H, V26.8H, V4.H[6]
	sqrdmulh	V24.8H, V28.8H, V4.H[7]
	sqrdmlsh	V22.8H, V25.8H, V8.H[0]
	sqrdmlsh	V24.8H, V27.8H, V8.H[0]
	sshr	V22.8H, V22.8H, #1
	sshr	V24.8H, V24.8H, #1
	sub	V26.8H, V9.8H, V11.8H
	sub	V28.8H, V10.8H, V12.8H
	add	V9.8H, V9.8H, V11.8H
	add	V10.8H, V10.8H, V12.8H
	mul	V25.8H, V26.8H, V7.H[0]
	mul	V27.8H, V28.8H, V7.H[0]
	sqrdmulh	V11.8H, V26.8H, V5.H[0]
	sqrdmulh	V12.8H, V28.8H, V5.H[0]
	sqrdmlsh	V11.8H, V25.8H, V8.H[0]
	sqrdmlsh	V12.8H, V27.8H, V8.H[0]
	sshr	V11.8H, V11.8H, #1
	sshr	V12.8H, V12.8H, #1
	sub	V26.8H, V13.8H, V15.8H
	sub	V28.8H, V14.8H, V16.8H
	add	V13.8H, V13.8H, V15.8H
	add	V14.8H, V14.8H, V16.8H
	mul	V25.8H, V26.8H, V7.H[1]
	mul	V27.8H, V28.8H, V7.H[1]
	sqrdmulh	V15.8H, V26.8H, V5.H[1]
	sqrdmulh	V16.8H, V28.8H, V5.H[1]
	sqrdmlsh	V15.8H, V25.8H, V8.H[0]
	sqrdmlsh	V16.8H, V27.8H, V8.H[0]
	sshr	V15.8H, V15.8H, #1
	sshr	V16.8H, V16.8H, #1
	sub	V26.8H, V17.8H, V19.8H
	sub	V28.8H, V18.8H, V20.8H
	add	V17.8H, V17.8H, V19.8H
	add	V18.8H, V18.8H, V20.8H
	mul	V25.8H, V26.8H, V7.H[2]
	mul	V27.8H, V28.8H, V7.H[2]
	sqrdmulh	V19.8H, V26.8H, V5.H[2]
	sqrdmulh	V20.8H, V28.8H, V5.H[2]
	sqrdmlsh	V19.8H, V25.8H, V8.H[0]
	sqrdmlsh	V20.8H, V27.8H, V8.H[0]
	sshr	V19.8H, V19.8H, #1
	sshr	V20.8H, V20.8H, #1
	sub	V26.8H, V21.8H, V23.8H
	sub	V28.8H, V22.8H, V24.8H
	add	V21.8H, V21.8H, V23.8H
	add	V22.8H, V22.8H, V24.8H
	mul	V25.8H, V26.8H, V7.H[3]
	mul	V27.8H, V28.8H, V7.H[3]
	sqrdmulh	V23.8H, V26.8H, V5.H[3]
	sqrdmulh	V24.8H, V28.8H, V5.H[3]
	sqrdmlsh	V23.8H, V25.8H, V8.H[0]
	sqrdmlsh	V24.8H, V27.8H, V8.H[0]
	sshr	V23.8H, V23.8H, #1
	sshr	V24.8H, V24.8H, #1
	sub	V26.8H, V9.8H, V13.8H
	sub	V28.8H, V10.8H, V14.8H
	add	V9.8H, V9.8H, V13.8H
	add	V10.8H, V10.8H, V14.8H
	mul	V25.8H, V26.8H, V7.H[4]
	mul	V27.8H, V28.8H, V7.H[4]
	sqrdmulh	V13.8H, V26.8H, V5.H[4]
	sqrdmulh	V14.8H, V28.8H, V5.H[4]
	sqrdmlsh	V13.8H, V25.8H, V8.H[0]
	sqrdmlsh	V14.8H, V27.8H, V8.H[0]
	sshr	V13.8H, V13.8H, #1
	sshr	V14.8H, V14.8H, #1
	sub	V26.8H, V11.8H, V15.8H
	sub	V28.8H, V12.8H, V16.8H
	add	V11.8H, V11.8H, V15.8H
	add	V12.8H, V12.8H, V16.8H
	mul	V25.8H, V26.8H, V7.H[4]
	mul	V27.8H, V28.8H, V7.H[4]
	sqrdmulh	V15.8H, V26.8H, V5.H[4]
	sqrdmulh	V16.8H, V28.8H, V5.H[4]
	sqrdmlsh	V15.8H, V25.8H, V8.H[0]
	sqrdmlsh	V16.8H, V27.8H, V8.H[0]
	sshr	V15.8H, V15.8H, #1
	sshr	V16.8H, V16.8H, #1
	sub	V26.8H, V17.8H, V21.8H
	sub	V28.8H, V18.8H, V22.8H
	add	V17.8H, V17.8H, V21.8H
	add	V18.8H, V18.8H, V22.8H
	mul	V25.8H, V26.8H, V7.H[5]
	mul	V27.8H, V28.8H, V7.H[5]
	sqrdmulh	V21.8H, V26.8H, V5.H[5]
	sqrdmulh	V22.8H, V28.8H, V5.H[5]
	sqrdmlsh	V21.8H, V25.8H, V8.H[0]
	sqrdmlsh	V22.8H, V27.8H, V8.H[0]
	sshr	V21.8H, V21.8H, #1
	sshr	V22.8H, V22.8H, #1
	sub	V26.8H, V19.8H, V23.8H
	sub	V28.8H, V20.8H, V24.8H
	add	V19.8H, V19.8H, V23.8H
	add	V20.8H, V20.8H, V24.8H
	mul	V25.8H, V26.8H, V7.H[5]
	mul	V27.8H, V28.8H, V7.H[5]
	sqrdmulh	V23.8H, V26.8H, V5.H[5]
	sqrdmulh	V24.8H, V28.8H, V5.H[5]
	sqrdmlsh	V23.8H, V25.8H, V8.H[0]
	sqrdmlsh	V24.8H, V27.8H, V8.H[0]
	sshr	V23.8H, V23.8H, #1
	sshr	V24.8H, V24.8H, #1
	sqdmulh	V25.8H, V9.8H, V8.H[2]
	sqdmulh	V26.8H, V10.8H, V8.H[2]
	sshr	V25.8H, V25.8H, #11
	sshr	V26.8H, V26.8H, #11
	mls	V9.8H, V25.8H, V8.H[0]
	mls	V10.8H, V26.8H, V8.H[0]
	sqdmulh	V25.8H, V11.8H, V8.H[2]
	sqdmulh	V26.8H, V12.8H, V8.H[2]
	sshr	V25.8H, V25.8H, #11
	sshr	V26.8H, V26.8H, #11
	mls	V11.8H, V25.8H, V8.H[0]
	mls	V12.8H, V26.8H, V8.H[0]
	sqdmulh	V25.8H, V17.8H, V8.H[2]
	sqdmulh	V26.8H, V18.8H, V8.H[2]
	sshr	V25.8H, V25.8H, #11
	sshr	V26.8H, V26.8H, #11
	mls	V17.8H, V25.8H, V8.H[0]
	mls	V18.8H, V26.8H, V8.H[0]
	sqdmulh	V25.8H, V19.8H, V8.H[2]
	sqdmulh	V26.8H, V20.8H, V8.H[2]
	sshr	V25.8H, V25.8H, #11
	sshr	V26.8H, V26.8H, #11
	mls	V19.8H, V25.8H, V8.H[0]
	mls	V20.8H, V26.8H, V8.H[0]
	sub	V26.8H, V9.8H, V17.8H
	sub	V28.8H, V10.8H, V18.8H
	add	V9.8H, V9.8H, V17.8H
	add	V10.8H, V10.8H, V18.8H
	mul	V25.8H, V26.8H, V7.H[6]
	mul	V27.8H, V28.8H, V7.H[6]
	sqrdmulh	V17.8H, V26.8H, V5.H[6]
	sqrdmulh	V18.8H, V28.8H, V5.H[6]
	sqrdmlsh	V17.8H, V25.8H, V8.H[0]
	sqrdmlsh	V18.8H, V27.8H, V8.H[0]
	sshr	V17.8H, V17.8H, #1
	sshr	V18.8H, V18.8H, #1
	sub	V26.8H, V11.8H, V19.8H
	sub	V28.8H, V12.8H, V20.8H
	add	V11.8H, V11.8H, V19.8H
	add	V12.8H, V12.8H, V20.8H
	mul	V25.8H, V26.8H, V7.H[6]
	mul	V27.8H, V28.8H, V7.H[6]
	sqrdmulh	V19.8H, V26.8H, V5.H[6]
	sqrdmulh	V20.8H, V28.8H, V5.H[6]
	sqrdmlsh	V19.8H, V25.8H, V8.H[0]
	sqrdmlsh	V20.8H, V27.8H, V8.H[0]
	sshr	V19.8H, V19.8H, #1
	sshr	V20.8H, V20.8H, #1
	sub	V26.8H, V13.8H, V21.8H
	sub	V28.8H, V14.8H, V22.8H
	add	V13.8H, V13.8H, V21.8H
	add	V14.8H, V14.8H, V22.8H
	mul	V25.8H, V26.8H, V7.H[6]
	mul	V27.8H, V28.8H, V7.H[6]
	sqrdmulh	V21.8H, V26.8H, V5.H[6]
	sqrdmulh	V22.8H, V28.8H, V5.H[6]
	sqrdmlsh	V21.8H, V25.8H, V8.H[0]
	sqrdmlsh	V22.8H, V27.8H, V8.H[0]
	sshr	V21.8H, V21.8H, #1
	sshr	V22.8H, V22.8H, #1
	sub	V26.8H, V15.8H, V23.8H
	sub	V28.8H, V16.8H, V24.8H
	add	V15.8H, V15.8H, V23.8H
	add	V16.8H, V16.8H, V24.8H
	mul	V25.8H, V26.8H, V7.H[6]
	mul	V27.8H, V28.8H, V7.H[6]
	sqrdmulh	V23.8H, V26.8H, V5.H[6]
	sqrdmulh	V24.8H, V28.8H, V5.H[6]
	sqrdmlsh	V23.8H, V25.8H, V8.H[0]
	sqrdmlsh	V24.8H, V27.8H, V8.H[0]
	sshr	V23.8H, V23.8H, #1
	sshr	V24.8H, V24.8H, #1
	mul	V25.8H, V9.8H, V7.H[7]
	mul	V26.8H, V10.8H, V7.H[7]
	sqrdmulh	V9.8H, V9.8H, V5.H[7]
	sqrdmulh	V10.8H, V10.8H, V5.H[7]
	sqrdmlsh	V9.8H, V25.8H, V8.H[0]
	sqrdmlsh	V10.8H, V26.8H, V8.H[0]
	sshr	V9.8H, V9.8H, #1
	sshr	V10.8H, V10.8H, #1
	mul	V25.8H, V11.8H, V7.H[7]
	mul	V26.8H, V12.8H, V7.H[7]
	sqrdmulh	V11.8H, V11.8H, V5.H[7]
	sqrdmulh	V12.8H, V12.8H, V5.H[7]
	sqrdmlsh	V11.8H, V25.8H, V8.H[0]
	sqrdmlsh	V12.8H, V26.8H, V8.H[0]
	sshr	V11.8H, V11.8H, #1
	sshr	V12.8H, V12.8H, #1
	mul	V25.8H, V13.8H, V7.H[7]
	mul	V26.8H, V14.8H, V7.H[7]
	sqrdmulh	V13.8H, V13.8H, V5.H[7]
	sqrdmulh	V14.8H, V14.8H, V5.H[7]
	sqrdmlsh	V13.8H, V25.8H, V8.H[0]
	sqrdmlsh	V14.8H, V26.8H, V8.H[0]
	sshr	V13.8H, V13.8H, #1
	sshr	V14.8H, V14.8H, #1
	mul	V25.8H, V15.8H, V7.H[7]
	mul	V26.8H, V16.8H, V7.H[7]
	sqrdmulh	V15.8H, V15.8H, V5.H[7]
	sqrdmulh	V16.8H, V16.8H, V5.H[7]
	sqrdmlsh	V15.8H, V25.8H, V8.H[0]
	sqrdmlsh	V16.8H, V26.8H, V8.H[0]
	sshr	V15.8H, V15.8H, #1
	sshr	V16.8H, V16.8H, #1
	mul	V25.8H, V17.8H, V7.H[7]
	mul	V26.8H, V18.8H, V7.H[7]
	sqrdmulh	V17.8H, V17.8H, V5.H[7]
	sqrdmulh	V18.8H, V18.8H, V5.H[7]
	sqrdmlsh	V17.8H, V25.8H, V8.H[0]
	sqrdmlsh	V18.8H, V26.8H, V8.H[0]
	sshr	V17.8H, V17.8H, #1
	sshr	V18.8H, V18.8H, #1
	mul	V25.8H, V19.8H, V7.H[7]
	mul	V26.8H, V20.8H, V7.H[7]
	sqrdmulh	V19.8H, V19.8H, V5.H[7]
	sqrdmulh	V20.8H, V20.8H, V5.H[7]
	sqrdmlsh	V19.8H, V25.8H, V8.H[0]
	sqrdmlsh	V20.8H, V26.8H, V8.H[0]
	sshr	V19.8H, V19.8H, #1
	sshr	V20.8H, V20.8H, #1
	mul	V25.8H, V21.8H, V7.H[7]
	mul	V26.8H, V22.8H, V7.H[7]
	sqrdmulh	V21.8H, V21.8H, V5.H[7]
	sqrdmulh	V22.8H, V22.8H, V5.H[7]
	sqrdmlsh	V21.8H, V25.8H, V8.H[0]
	sqrdmlsh	V22.8H, V26.8H, V8.H[0]
	sshr	V21.8H, V21.8H, #1
	sshr	V22.8H, V22.8H, #1
	mul	V25.8H, V23.8H, V7.H[7]
	mul	V26.8H, V24.8H, V7.H[7]
	sqrdmulh	V23.8H, V23.8H, V5.H[7]
	sqrdmulh	V24.8H, V24.8H, V5.H[7]
	sqrdmlsh	V23.8H, V25.8H, V8.H[0]
	sqrdmlsh	V24.8H, V26.8H, V8.H[0]
	sshr	V23.8H, V23.8H, #1
	sshr	V24.8H, V24.8H, #1
	str	Q9, [x0]
	str	Q10, [x0, #32]
	str	Q11, [x0, #64]
	str	Q12, [x0, #96]
	str	Q13, [x0, #128]
	str	Q14, [x0, #160]
	str	Q15, [x0, #192]
	str	Q16, [x0, #224]
	str	Q17, [x1]
	str	Q18, [x1, #32]
	str	Q19, [x1, #64]
	str	Q20, [x1, #96]
	str	Q21, [x1, #128]
	str	Q22, [x1, #160]
	str	Q23, [x1, #192]
	str	Q24, [x1, #224]
	ldr	Q9, [x0, #16]
	ldr	Q10, [x0, #48]
	ldr	Q11, [x0, #80]
	ldr	Q12, [x0, #112]
	ldr	Q13, [x0, #144]
	ldr	Q14, [x0, #176]
	ldr	Q15, [x0, #208]
	ldr	Q16, [x0, #240]
	ldr	Q17, [x1, #16]
	ldr	Q18, [x1, #48]
	ldr	Q19, [x1, #80]
	ldr	Q20, [x1, #112]
	ldr	Q21, [x1, #144]
	ldr	Q22, [x1, #176]
	ldr	Q23, [x1, #208]
	ldr	Q24, [x1, #240]
	sub	V26.8H, V9.8H, V10.8H
	sub	V28.8H, V11.8H, V12.8H
	add	V9.8H, V9.8H, V10.8H
	add	V11.8H, V11.8H, V12.8H
	mul	V25.8H, V26.8H, V6.H[0]
	mul	V27.8H, V28.8H, V6.H[1]
	sqrdmulh	V10.8H, V26.8H, V4.H[0]
	sqrdmulh	V12.8H, V28.8H, V4.H[1]
	sqrdmlsh	V10.8H, V25.8H, V8.H[0]
	sqrdmlsh	V12.8H, V27.8H, V8.H[0]
	sshr	V10.8H, V10.8H, #1
	sshr	V12.8H, V12.8H, #1
	sub	V26.8H, V13.8H, V14.8H
	sub	V28.8H, V15.8H, V16.8H
	add	V13.8H, V13.8H, V14.8H
	add	V15.8H, V15.8H, V16.8H
	mul	V25.8H, V26.8H, V6.H[2]
	mul	V27.8H, V28.8H, V6.H[3]
	sqrdmulh	V14.8H, V26.8H, V4.H[2]
	sqrdmulh	V16.8H, V28.8H, V4.H[3]
	sqrdmlsh	V14.8H, V25.8H, V8.H[0]
	sqrdmlsh	V16.8H, V27.8H, V8.H[0]
	sshr	V14.8H, V14.8H, #1
	sshr	V16.8H, V16.8H, #1
	sub	V26.8H, V17.8H, V18.8H
	sub	V28.8H, V19.8H, V20.8H
	add	V17.8H, V17.8H, V18.8H
	add	V19.8H, V19.8H, V20.8H
	mul	V25.8H, V26.8H, V6.H[4]
	mul	V27.8H, V28.8H, V6.H[5]
	sqrdmulh	V18.8H, V26.8H, V4.H[4]
	sqrdmulh	V20.8H, V28.8H, V4.H[5]
	sqrdmlsh	V18.8H, V25.8H, V8.H[0]
	sqrdmlsh	V20.8H, V27.8H, V8.H[0]
	sshr	V18.8H, V18.8H, #1
	sshr	V20.8H, V20.8H, #1
	sub	V26.8H, V21.8H, V22.8H
	sub	V28.8H, V23.8H, V24.8H
	add	V21.8H, V21.8H, V22.8H
	add	V23.8H, V23.8H, V24.8H
	mul	V25.8H, V26.8H, V6.H[6]
	mul	V27.8H, V28.8H, V6.H[7]
	sqrdmulh	V22.8H, V26.8H, V4.H[6]
	sqrdmulh	V24.8H, V28.8H, V4.H[7]
	sqrdmlsh	V22.8H, V25.8H, V8.H[0]
	sqrdmlsh	V24.8H, V27.8H, V8.H[0]
	sshr	V22.8H, V22.8H, #1
	sshr	V24.8H, V24.8H, #1
	sub	V26.8H, V9.8H, V11.8H
	sub	V28.8H, V10.8H, V12.8H
	add	V9.8H, V9.8H, V11.8H
	add	V10.8H, V10.8H, V12.8H
	mul	V25.8H, V26.8H, V7.H[0]
	mul	V27.8H, V28.8H, V7.H[0]
	sqrdmulh	V11.8H, V26.8H, V5.H[0]
	sqrdmulh	V12.8H, V28.8H, V5.H[0]
	sqrdmlsh	V11.8H, V25.8H, V8.H[0]
	sqrdmlsh	V12.8H, V27.8H, V8.H[0]
	sshr	V11.8H, V11.8H, #1
	sshr	V12.8H, V12.8H, #1
	sub	V26.8H, V13.8H, V15.8H
	sub	V28.8H, V14.8H, V16.8H
	add	V13.8H, V13.8H, V15.8H
	add	V14.8H, V14.8H, V16.8H
	mul	V25.8H, V26.8H, V7.H[1]
	mul	V27.8H, V28.8H, V7.H[1]
	sqrdmulh	V15.8H, V26.8H, V5.H[1]
	sqrdmulh	V16.8H, V28.8H, V5.H[1]
	sqrdmlsh	V15.8H, V25.8H, V8.H[0]
	sqrdmlsh	V16.8H, V27.8H, V8.H[0]
	sshr	V15.8H, V15.8H, #1
	sshr	V16.8H, V16.8H, #1
	sub	V26.8H, V17.8H, V19.8H
	sub	V28.8H, V18.8H, V20.8H
	add	V17.8H, V17.8H, V19.8H
	add	V18.8H, V18.8H, V20.8H
	mul	V25.8H, V26.8H, V7.H[2]
	mul	V27.8H, V28.8H, V7.H[2]
	sqrdmulh	V19.8H, V26.8H, V5.H[2]
	sqrdmulh	V20.8H, V28.8H, V5.H[2]
	sqrdmlsh	V19.8H, V25.8H, V8.H[0]
	sqrdmlsh	V20.8H, V27.8H, V8.H[0]
	sshr	V19.8H, V19.8H, #1
	sshr	V20.8H, V20.8H, #1
	sub	V26.8H, V21.8H, V23.8H
	sub	V28.8H, V22.8H, V24.8H
	add	V21.8H, V21.8H, V23.8H
	add	V22.8H, V22.8H, V24.8H
	mul	V25.8H, V26.8H, V7.H[3]
	mul	V27.8H, V28.8H, V7.H[3]
	sqrdmulh	V23.8H, V26.8H, V5.H[3]
	sqrdmulh	V24.8H, V28.8H, V5.H[3]
	sqrdmlsh	V23.8H, V25.8H, V8.H[0]
	sqrdmlsh	V24.8H, V27.8H, V8.H[0]
	sshr	V23.8H, V23.8H, #1
	sshr	V24.8H, V24.8H, #1
	sub	V26.8H, V9.8H, V13.8H
	sub	V28.8H, V10.8H, V14.8H
	add	V9.8H, V9.8H, V13.8H
	add	V10.8H, V10.8H, V14.8H
	mul	V25.8H, V26.8H, V7.H[4]
	mul	V27.8H, V28.8H, V7.H[4]
	sqrdmulh	V13.8H, V26.8H, V5.H[4]
	sqrdmulh	V14.8H, V28.8H, V5.H[4]
	sqrdmlsh	V13.8H, V25.8H, V8.H[0]
	sqrdmlsh	V14.8H, V27.8H, V8.H[0]
	sshr	V13.8H, V13.8H, #1
	sshr	V14.8H, V14.8H, #1
	sub	V26.8H, V11.8H, V15.8H
	sub	V28.8H, V12.8H, V16.8H
	add	V11.8H, V11.8H, V15.8H
	add	V12.8H, V12.8H, V16.8H
	mul	V25.8H, V26.8H, V7.H[4]
	mul	V27.8H, V28.8H, V7.H[4]
	sqrdmulh	V15.8H, V26.8H, V5.H[4]
	sqrdmulh	V16.8H, V28.8H, V5.H[4]
	sqrdmlsh	V15.8H, V25.8H, V8.H[0]
	sqrdmlsh	V16.8H, V27.8H, V8.H[0]
	sshr	V15.8H, V15.8H, #1
	sshr	V16.8H, V16.8H, #1
	sub	V26.8H, V17.8H, V21.8H
	sub	V28.8H, V18.8H, V22.8H
	add	V17.8H, V17.8H, V21.8H
	add	V18.8H, V18.8H, V22.8H
	mul	V25.8H, V26.8H, V7.H[5]
	mul	V27.8H, V28.8H, V7.H[5]
	sqrdmulh	V21.8H, V26.8H, V5.H[5]
	sqrdmulh	V22.8H, V28.8H, V5.H[5]
	sqrdmlsh	V21.8H, V25.8H, V8.H[0]
	sqrdmlsh	V22.8H, V27.8H, V8.H[0]
	sshr	V21.8H, V21.8H, #1
	sshr	V22.8H, V22.8H, #1
	sub	V26.8H, V19.8H, V23.8H
	sub	V28.8H, V20.8H, V24.8H
	add	V19.8H, V19.8H, V23.8H
	add	V20.8H, V20.8H, V24.8H
	mul	V25.8H, V26.8H, V7.H[5]
	mul	V27.8H, V28.8H, V7.H[5]
	sqrdmulh	V23.8H, V26.8H, V5.H[5]
	sqrdmulh	V24.8H, V28.8H, V5.H[5]
	sqrdmlsh	V23.8H, V25.8H, V8.H[0]
	sqrdmlsh	V24.8H, V27.8H, V8.H[0]
	sshr	V23.8H, V23.8H, #1
	sshr	V24.8H, V24.8H, #1
	sqdmulh	V25.8H, V9.8H, V8.H[2]
	sqdmulh	V26.8H, V10.8H, V8.H[2]
	sshr	V25.8H, V25.8H, #11
	sshr	V26.8H, V26.8H, #11
	mls	V9.8H, V25.8H, V8.H[0]
	mls	V10.8H, V26.8H, V8.H[0]
	sqdmulh	V25.8H, V11.8H, V8.H[2]
	sqdmulh	V26.8H, V12.8H, V8.H[2]
	sshr	V25.8H, V25.8H, #11
	sshr	V26.8H, V26.8H, #11
	mls	V11.8H, V25.8H, V8.H[0]
	mls	V12.8H, V26.8H, V8.H[0]
	sqdmulh	V25.8H, V17.8H, V8.H[2]
	sqdmulh	V26.8H, V18.8H, V8.H[2]
	sshr	V25.8H, V25.8H, #11
	sshr	V26.8H, V26.8H, #11
	mls	V17.8H, V25.8H, V8.H[0]
	mls	V18.8H, V26.8H, V8.H[0]
	sqdmulh	V25.8H, V19.8H, V8.H[2]
	sqdmulh	V26.8H, V20.8H, V8.H[2]
	sshr	V25.8H, V25.8H, #11
	sshr	V26.8H, V26.8H, #11
	mls	V19.8H, V25.8H, V8.H[0]
	mls	V20.8H, V26.8H, V8.H[0]
	sub	V26.8H, V9.8H, V17.8H
	sub	V28.8H, V10.8H, V18.8H
	add	V9.8H, V9.8H, V17.8H
	add	V10.8H, V10.8H, V18.8H
	mul	V25.8H, V26.8H, V7.H[6]
	mul	V27.8H, V28.8H, V7.H[6]
	sqrdmulh	V17.8H, V26.8H, V5.H[6]
	sqrdmulh	V18.8H, V28.8H, V5.H[6]
	sqrdmlsh	V17.8H, V25.8H, V8.H[0]
	sqrdmlsh	V18.8H, V27.8H, V8.H[0]
	sshr	V17.8H, V17.8H, #1
	sshr	V18.8H, V18.8H, #1
	sub	V26.8H, V11.8H, V19.8H
	sub	V28.8H, V12.8H, V20.8H
	add	V11.8H, V11.8H, V19.8H
	add	V12.8H, V12.8H, V20.8H
	mul	V25.8H, V26.8H, V7.H[6]
	mul	V27.8H, V28.8H, V7.H[6]
	sqrdmulh	V19.8H, V26.8H, V5.H[6]
	sqrdmulh	V20.8H, V28.8H, V5.H[6]
	sqrdmlsh	V19.8H, V25.8H, V8.H[0]
	sqrdmlsh	V20.8H, V27.8H, V8.H[0]
	sshr	V19.8H, V19.8H, #1
	sshr	V20.8H, V20.8H, #1
	sub	V26.8H, V13.8H, V21.8H
	sub	V28.8H, V14.8H, V22.8H
	add	V13.8H, V13.8H, V21.8H
	add	V14.8H, V14.8H, V22.8H
	mul	V25.8H, V26.8H, V7.H[6]
	mul	V27.8H, V28.8H, V7.H[6]
	sqrdmulh	V21.8H, V26.8H, V5.H[6]
	sqrdmulh	V22.8H, V28.8H, V5.H[6]
	sqrdmlsh	V21.8H, V25.8H, V8.H[0]
	sqrdmlsh	V22.8H, V27.8H, V8.H[0]
	sshr	V21.8H, V21.8H, #1
	sshr	V22.8H, V22.8H, #1
	sub	V26.8H, V15.8H, V23.8H
	sub	V28.8H, V16.8H, V24.8H
	add	V15.8H, V15.8H, V23.8H
	add	V16.8H, V16.8H, V24.8H
	mul	V25.8H, V26.8H, V7.H[6]
	mul	V27.8H, V28.8H, V7.H[6]
	sqrdmulh	V23.8H, V26.8H, V5.H[6]
	sqrdmulh	V24.8H, V28.8H, V5.H[6]
	sqrdmlsh	V23.8H, V25.8H, V8.H[0]
	sqrdmlsh	V24.8H, V27.8H, V8.H[0]
	sshr	V23.8H, V23.8H, #1
	sshr	V24.8H, V24.8H, #1
	mul	V25.8H, V9.8H, V7.H[7]
	mul	V26.8H, V10.8H, V7.H[7]
	sqrdmulh	V9.8H, V9.8H, V5.H[7]
	sqrdmulh	V10.8H, V10.8H, V5.H[7]
	sqrdmlsh	V9.8H, V25.8H, V8.H[0]
	sqrdmlsh	V10.8H, V26.8H, V8.H[0]
	sshr	V9.8H, V9.8H, #1
	sshr	V10.8H, V10.8H, #1
	mul	V25.8H, V11.8H, V7.H[7]
	mul	V26.8H, V12.8H, V7.H[7]
	sqrdmulh	V11.8H, V11.8H, V5.H[7]
	sqrdmulh	V12.8H, V12.8H, V5.H[7]
	sqrdmlsh	V11.8H, V25.8H, V8.H[0]
	sqrdmlsh	V12.8H, V26.8H, V8.H[0]
	sshr	V11.8H, V11.8H, #1
	sshr	V12.8H, V12.8H, #1
	mul	V25.8H, V13.8H, V7.H[7]
	mul	V26.8H, V14.8H, V7.H[7]
	sqrdmulh	V13.8H, V13.8H, V5.H[7]
	sqrdmulh	V14.8H, V14.8H, V5.H[7]
	sqrdmlsh	V13.8H, V25.8H, V8.H[0]
	sqrdmlsh	V14.8H, V26.8H, V8.H[0]
	sshr	V13.8H, V13.8H, #1
	sshr	V14.8H, V14.8H, #1
	mul	V25.8H, V15.8H, V7.H[7]
	mul	V26.8H, V16.8H, V7.H[7]
	sqrdmulh	V15.8H, V15.8H, V5.H[7]
	sqrdmulh	V16.8H, V16.8H, V5.H[7]
	sqrdmlsh	V15.8H, V25.8H, V8.H[0]
	sqrdmlsh	V16.8H, V26.8H, V8.H[0]
	sshr	V15.8H, V15.8H, #1
	sshr	V16.8H, V16.8H, #1
	mul	V25.8H, V17.8H, V7.H[7]
	mul	V26.8H, V18.8H, V7.H[7]
	sqrdmulh	V17.8H, V17.8H, V5.H[7]
	sqrdmulh	V18.8H, V18.8H, V5.H[7]
	sqrdmlsh	V17.8H, V25.8H, V8.H[0]
	sqrdmlsh	V18.8H, V26.8H, V8.H[0]
	sshr	V17.8H, V17.8H, #1
	sshr	V18.8H, V18.8H, #1
	mul	V25.8H, V19.8H, V7.H[7]
	mul	V26.8H, V20.8H, V7.H[7]
	sqrdmulh	V19.8H, V19.8H, V5.H[7]
	sqrdmulh	V20.8H, V20.8H, V5.H[7]
	sqrdmlsh	V19.8H, V25.8H, V8.H[0]
	sqrdmlsh	V20.8H, V26.8H, V8.H[0]
	sshr	V19.8H, V19.8H, #1
	sshr	V20.8H, V20.8H, #1
	mul	V25.8H, V21.8H, V7.H[7]
	mul	V26.8H, V22.8H, V7.H[7]
	sqrdmulh	V21.8H, V21.8H, V5.H[7]
	sqrdmulh	V22.8H, V22.8H, V5.H[7]
	sqrdmlsh	V21.8H, V25.8H, V8.H[0]
	sqrdmlsh	V22.8H, V26.8H, V8.H[0]
	sshr	V21.8H, V21.8H, #1
	sshr	V22.8H, V22.8H, #1
	mul	V25.8H, V23.8H, V7.H[7]
	mul	V26.8H, V24.8H, V7.H[7]
	sqrdmulh	V23.8H, V23.8H, V5.H[7]
	sqrdmulh	V24.8H, V24.8H, V5.H[7]
	sqrdmlsh	V23.8H, V25.8H, V8.H[0]
	sqrdmlsh	V24.8H, V26.8H, V8.H[0]
	sshr	V23.8H, V23.8H, #1
	sshr	V24.8H, V24.8H, #1
	str	Q9, [x0, #16]
	str	Q10, [x0, #48]
	str	Q11, [x0, #80]
	str	Q12, [x0, #112]
	str	Q13, [x0, #144]
	str	Q14, [x0, #176]
	str	Q15, [x0, #208]
	str	Q16, [x0, #240]
	str	Q17, [x1, #16]
	str	Q18, [x1, #48]
	str	Q19, [x1, #80]
	str	Q20, [x1, #112]
	str	Q21, [x1, #144]
	str	Q22, [x1, #176]
	str	Q23, [x1, #208]
	str	Q24, [x1, #240]
	ldp	D8, D9, [x29, #16]
	ldp	D10, D11, [x29, #32]
	ldp	D12, D13, [x29, #48]
	ldp	D14, D15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
	ENDP
	ENDIF
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mlkem_aarch64_zetas_mul
	DCW	0x08b2, 0xf74e, 0x01ae, 0xfe52, 0x022b, 0xfdd5, 0x034b, 0xfcb5
	DCW	0x081e, 0xf7e2, 0x0367, 0xfc99, 0x060e, 0xf9f2, 0x0069, 0xff97
	DCW	0x01a6, 0xfe5a, 0x024b, 0xfdb5, 0x00b1, 0xff4f, 0x0c16, 0xf3ea
	DCW	0x0bde, 0xf422, 0x0b35, 0xf4cb, 0x0626, 0xf9da, 0x0675, 0xf98b
	DCW	0x0c0b, 0xf3f5, 0x030a, 0xfcf6, 0x0487, 0xfb79, 0x0c6e, 0xf392
	DCW	0x09f8, 0xf608, 0x05cb, 0xfa35, 0x0aa7, 0xf559, 0x045f, 0xfba1
	DCW	0x06cb, 0xf935, 0x0284, 0xfd7c, 0x0999, 0xf667, 0x015d, 0xfea3
	DCW	0x01a2, 0xfe5e, 0x0149, 0xfeb7, 0x0c65, 0xf39b, 0x0cb6, 0xf34a
	DCW	0x0331, 0xfccf, 0x0449, 0xfbb7, 0x025b, 0xfda5, 0x0262, 0xfd9e
	DCW	0x052a, 0xfad6, 0x07fc, 0xf804, 0x0748, 0xf8b8, 0x0180, 0xfe80
	DCW	0x0842, 0xf7be, 0x0c79, 0xf387, 0x04c2, 0xfb3e, 0x07ca, 0xf836
	DCW	0x0997, 0xf669, 0x00dc, 0xff24, 0x085e, 0xf7a2, 0x0686, 0xf97a
	DCW	0x0860, 0xf7a0, 0x0707, 0xf8f9, 0x0803, 0xf7fd, 0x031a, 0xfce6
	DCW	0x071b, 0xf8e5, 0x09ab, 0xf655, 0x099b, 0xf665, 0x01de, 0xfe22
	DCW	0x0c95, 0xf36b, 0x0bcd, 0xf433, 0x03e4, 0xfc1c, 0x03df, 0xfc21
	DCW	0x03be, 0xfc42, 0x074d, 0xf8b3, 0x05f2, 0xfa0e, 0x065c, 0xf9a4
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mlkem_basemul_mont
mlkem_basemul_mont PROC
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	stp	D10, D11, [x29, #32]
	stp	D12, D13, [x29, #48]
	stp	D14, D15, [x29, #64]
	adrp	x3, L_mlkem_aarch64_zetas_mul
	add	x3, x3, L_mlkem_aarch64_zetas_mul
	adrp	x4, L_mlkem_aarch64_consts
	add	x4, x4, L_mlkem_aarch64_consts
	ldr	Q1, [x4]
	ldp	Q2, Q3, [x1]
	ldp	Q4, Q5, [x1, #32]
	ldp	Q6, Q7, [x1, #64]
	ldp	Q8, Q9, [x1, #96]
	ldp	Q10, Q11, [x2]
	ldp	Q12, Q13, [x2, #32]
	ldp	Q14, Q15, [x2, #64]
	ldp	Q16, Q17, [x2, #96]
	ldr	Q0, [x3]
	uzp1	V18.8H, V2.8H, V3.8H
	uzp2	V19.8H, V2.8H, V3.8H
	uzp1	V20.8H, V10.8H, V11.8H
	uzp2	V21.8H, V10.8H, V11.8H
	smull	V26.4S, V18.4H, V20.4H
	smull2	V27.4S, V18.8H, V20.8H
	smull	V23.4S, V19.4H, V21.4H
	smull2	V24.4S, V19.8H, V21.8H
	xtn	V25.4H, V23.4S
	xtn2	V25.8H, V24.4S
	mul	V25.8H, V25.8H, V1.H[1]
	smlsl	V23.4S, V25.4H, V1.H[0]
	smlsl2	V24.4S, V25.8H, V1.H[0]
	shrn	V22.4H, V23.4S, #16
	shrn2	V22.8H, V24.4S, #16
	smlal	V26.4S, V22.4H, V0.4H
	smlal2	V27.4S, V22.8H, V0.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V22.4H, V26.4S, #16
	shrn2	V22.8H, V27.4S, #16
	smull	V26.4S, V18.4H, V21.4H
	smull2	V27.4S, V18.8H, V21.8H
	smlal	V26.4S, V19.4H, V20.4H
	smlal2	V27.4S, V19.8H, V20.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V23.4H, V26.4S, #16
	shrn2	V23.8H, V27.4S, #16
	zip1	V24.8H, V22.8H, V23.8H
	zip2	V25.8H, V22.8H, V23.8H
	stp	Q24, Q25, [x0]
	ldr	Q0, [x3, #16]
	uzp1	V18.8H, V4.8H, V5.8H
	uzp2	V19.8H, V4.8H, V5.8H
	uzp1	V20.8H, V12.8H, V13.8H
	uzp2	V21.8H, V12.8H, V13.8H
	smull	V26.4S, V18.4H, V20.4H
	smull2	V27.4S, V18.8H, V20.8H
	smull	V23.4S, V19.4H, V21.4H
	smull2	V24.4S, V19.8H, V21.8H
	xtn	V25.4H, V23.4S
	xtn2	V25.8H, V24.4S
	mul	V25.8H, V25.8H, V1.H[1]
	smlsl	V23.4S, V25.4H, V1.H[0]
	smlsl2	V24.4S, V25.8H, V1.H[0]
	shrn	V22.4H, V23.4S, #16
	shrn2	V22.8H, V24.4S, #16
	smlal	V26.4S, V22.4H, V0.4H
	smlal2	V27.4S, V22.8H, V0.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V22.4H, V26.4S, #16
	shrn2	V22.8H, V27.4S, #16
	smull	V26.4S, V18.4H, V21.4H
	smull2	V27.4S, V18.8H, V21.8H
	smlal	V26.4S, V19.4H, V20.4H
	smlal2	V27.4S, V19.8H, V20.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V23.4H, V26.4S, #16
	shrn2	V23.8H, V27.4S, #16
	zip1	V24.8H, V22.8H, V23.8H
	zip2	V25.8H, V22.8H, V23.8H
	stp	Q24, Q25, [x0, #32]
	ldr	Q0, [x3, #32]
	uzp1	V18.8H, V6.8H, V7.8H
	uzp2	V19.8H, V6.8H, V7.8H
	uzp1	V20.8H, V14.8H, V15.8H
	uzp2	V21.8H, V14.8H, V15.8H
	smull	V26.4S, V18.4H, V20.4H
	smull2	V27.4S, V18.8H, V20.8H
	smull	V23.4S, V19.4H, V21.4H
	smull2	V24.4S, V19.8H, V21.8H
	xtn	V25.4H, V23.4S
	xtn2	V25.8H, V24.4S
	mul	V25.8H, V25.8H, V1.H[1]
	smlsl	V23.4S, V25.4H, V1.H[0]
	smlsl2	V24.4S, V25.8H, V1.H[0]
	shrn	V22.4H, V23.4S, #16
	shrn2	V22.8H, V24.4S, #16
	smlal	V26.4S, V22.4H, V0.4H
	smlal2	V27.4S, V22.8H, V0.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V22.4H, V26.4S, #16
	shrn2	V22.8H, V27.4S, #16
	smull	V26.4S, V18.4H, V21.4H
	smull2	V27.4S, V18.8H, V21.8H
	smlal	V26.4S, V19.4H, V20.4H
	smlal2	V27.4S, V19.8H, V20.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V23.4H, V26.4S, #16
	shrn2	V23.8H, V27.4S, #16
	zip1	V24.8H, V22.8H, V23.8H
	zip2	V25.8H, V22.8H, V23.8H
	stp	Q24, Q25, [x0, #64]
	ldr	Q0, [x3, #48]
	uzp1	V18.8H, V8.8H, V9.8H
	uzp2	V19.8H, V8.8H, V9.8H
	uzp1	V20.8H, V16.8H, V17.8H
	uzp2	V21.8H, V16.8H, V17.8H
	smull	V26.4S, V18.4H, V20.4H
	smull2	V27.4S, V18.8H, V20.8H
	smull	V23.4S, V19.4H, V21.4H
	smull2	V24.4S, V19.8H, V21.8H
	xtn	V25.4H, V23.4S
	xtn2	V25.8H, V24.4S
	mul	V25.8H, V25.8H, V1.H[1]
	smlsl	V23.4S, V25.4H, V1.H[0]
	smlsl2	V24.4S, V25.8H, V1.H[0]
	shrn	V22.4H, V23.4S, #16
	shrn2	V22.8H, V24.4S, #16
	smlal	V26.4S, V22.4H, V0.4H
	smlal2	V27.4S, V22.8H, V0.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V22.4H, V26.4S, #16
	shrn2	V22.8H, V27.4S, #16
	smull	V26.4S, V18.4H, V21.4H
	smull2	V27.4S, V18.8H, V21.8H
	smlal	V26.4S, V19.4H, V20.4H
	smlal2	V27.4S, V19.8H, V20.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V23.4H, V26.4S, #16
	shrn2	V23.8H, V27.4S, #16
	zip1	V24.8H, V22.8H, V23.8H
	zip2	V25.8H, V22.8H, V23.8H
	stp	Q24, Q25, [x0, #96]
	ldp	Q2, Q3, [x1, #128]
	ldp	Q4, Q5, [x1, #160]
	ldp	Q6, Q7, [x1, #192]
	ldp	Q8, Q9, [x1, #224]
	ldp	Q10, Q11, [x2, #128]
	ldp	Q12, Q13, [x2, #160]
	ldp	Q14, Q15, [x2, #192]
	ldp	Q16, Q17, [x2, #224]
	ldr	Q0, [x3, #64]
	uzp1	V18.8H, V2.8H, V3.8H
	uzp2	V19.8H, V2.8H, V3.8H
	uzp1	V20.8H, V10.8H, V11.8H
	uzp2	V21.8H, V10.8H, V11.8H
	smull	V26.4S, V18.4H, V20.4H
	smull2	V27.4S, V18.8H, V20.8H
	smull	V23.4S, V19.4H, V21.4H
	smull2	V24.4S, V19.8H, V21.8H
	xtn	V25.4H, V23.4S
	xtn2	V25.8H, V24.4S
	mul	V25.8H, V25.8H, V1.H[1]
	smlsl	V23.4S, V25.4H, V1.H[0]
	smlsl2	V24.4S, V25.8H, V1.H[0]
	shrn	V22.4H, V23.4S, #16
	shrn2	V22.8H, V24.4S, #16
	smlal	V26.4S, V22.4H, V0.4H
	smlal2	V27.4S, V22.8H, V0.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V22.4H, V26.4S, #16
	shrn2	V22.8H, V27.4S, #16
	smull	V26.4S, V18.4H, V21.4H
	smull2	V27.4S, V18.8H, V21.8H
	smlal	V26.4S, V19.4H, V20.4H
	smlal2	V27.4S, V19.8H, V20.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V23.4H, V26.4S, #16
	shrn2	V23.8H, V27.4S, #16
	zip1	V24.8H, V22.8H, V23.8H
	zip2	V25.8H, V22.8H, V23.8H
	stp	Q24, Q25, [x0, #128]
	ldr	Q0, [x3, #80]
	uzp1	V18.8H, V4.8H, V5.8H
	uzp2	V19.8H, V4.8H, V5.8H
	uzp1	V20.8H, V12.8H, V13.8H
	uzp2	V21.8H, V12.8H, V13.8H
	smull	V26.4S, V18.4H, V20.4H
	smull2	V27.4S, V18.8H, V20.8H
	smull	V23.4S, V19.4H, V21.4H
	smull2	V24.4S, V19.8H, V21.8H
	xtn	V25.4H, V23.4S
	xtn2	V25.8H, V24.4S
	mul	V25.8H, V25.8H, V1.H[1]
	smlsl	V23.4S, V25.4H, V1.H[0]
	smlsl2	V24.4S, V25.8H, V1.H[0]
	shrn	V22.4H, V23.4S, #16
	shrn2	V22.8H, V24.4S, #16
	smlal	V26.4S, V22.4H, V0.4H
	smlal2	V27.4S, V22.8H, V0.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V22.4H, V26.4S, #16
	shrn2	V22.8H, V27.4S, #16
	smull	V26.4S, V18.4H, V21.4H
	smull2	V27.4S, V18.8H, V21.8H
	smlal	V26.4S, V19.4H, V20.4H
	smlal2	V27.4S, V19.8H, V20.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V23.4H, V26.4S, #16
	shrn2	V23.8H, V27.4S, #16
	zip1	V24.8H, V22.8H, V23.8H
	zip2	V25.8H, V22.8H, V23.8H
	stp	Q24, Q25, [x0, #160]
	ldr	Q0, [x3, #96]
	uzp1	V18.8H, V6.8H, V7.8H
	uzp2	V19.8H, V6.8H, V7.8H
	uzp1	V20.8H, V14.8H, V15.8H
	uzp2	V21.8H, V14.8H, V15.8H
	smull	V26.4S, V18.4H, V20.4H
	smull2	V27.4S, V18.8H, V20.8H
	smull	V23.4S, V19.4H, V21.4H
	smull2	V24.4S, V19.8H, V21.8H
	xtn	V25.4H, V23.4S
	xtn2	V25.8H, V24.4S
	mul	V25.8H, V25.8H, V1.H[1]
	smlsl	V23.4S, V25.4H, V1.H[0]
	smlsl2	V24.4S, V25.8H, V1.H[0]
	shrn	V22.4H, V23.4S, #16
	shrn2	V22.8H, V24.4S, #16
	smlal	V26.4S, V22.4H, V0.4H
	smlal2	V27.4S, V22.8H, V0.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V22.4H, V26.4S, #16
	shrn2	V22.8H, V27.4S, #16
	smull	V26.4S, V18.4H, V21.4H
	smull2	V27.4S, V18.8H, V21.8H
	smlal	V26.4S, V19.4H, V20.4H
	smlal2	V27.4S, V19.8H, V20.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V23.4H, V26.4S, #16
	shrn2	V23.8H, V27.4S, #16
	zip1	V24.8H, V22.8H, V23.8H
	zip2	V25.8H, V22.8H, V23.8H
	stp	Q24, Q25, [x0, #192]
	ldr	Q0, [x3, #112]
	uzp1	V18.8H, V8.8H, V9.8H
	uzp2	V19.8H, V8.8H, V9.8H
	uzp1	V20.8H, V16.8H, V17.8H
	uzp2	V21.8H, V16.8H, V17.8H
	smull	V26.4S, V18.4H, V20.4H
	smull2	V27.4S, V18.8H, V20.8H
	smull	V23.4S, V19.4H, V21.4H
	smull2	V24.4S, V19.8H, V21.8H
	xtn	V25.4H, V23.4S
	xtn2	V25.8H, V24.4S
	mul	V25.8H, V25.8H, V1.H[1]
	smlsl	V23.4S, V25.4H, V1.H[0]
	smlsl2	V24.4S, V25.8H, V1.H[0]
	shrn	V22.4H, V23.4S, #16
	shrn2	V22.8H, V24.4S, #16
	smlal	V26.4S, V22.4H, V0.4H
	smlal2	V27.4S, V22.8H, V0.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V22.4H, V26.4S, #16
	shrn2	V22.8H, V27.4S, #16
	smull	V26.4S, V18.4H, V21.4H
	smull2	V27.4S, V18.8H, V21.8H
	smlal	V26.4S, V19.4H, V20.4H
	smlal2	V27.4S, V19.8H, V20.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V23.4H, V26.4S, #16
	shrn2	V23.8H, V27.4S, #16
	zip1	V24.8H, V22.8H, V23.8H
	zip2	V25.8H, V22.8H, V23.8H
	stp	Q24, Q25, [x0, #224]
	ldp	Q2, Q3, [x1, #256]
	ldp	Q4, Q5, [x1, #288]
	ldp	Q6, Q7, [x1, #320]
	ldp	Q8, Q9, [x1, #352]
	ldp	Q10, Q11, [x2, #256]
	ldp	Q12, Q13, [x2, #288]
	ldp	Q14, Q15, [x2, #320]
	ldp	Q16, Q17, [x2, #352]
	ldr	Q0, [x3, #128]
	uzp1	V18.8H, V2.8H, V3.8H
	uzp2	V19.8H, V2.8H, V3.8H
	uzp1	V20.8H, V10.8H, V11.8H
	uzp2	V21.8H, V10.8H, V11.8H
	smull	V26.4S, V18.4H, V20.4H
	smull2	V27.4S, V18.8H, V20.8H
	smull	V23.4S, V19.4H, V21.4H
	smull2	V24.4S, V19.8H, V21.8H
	xtn	V25.4H, V23.4S
	xtn2	V25.8H, V24.4S
	mul	V25.8H, V25.8H, V1.H[1]
	smlsl	V23.4S, V25.4H, V1.H[0]
	smlsl2	V24.4S, V25.8H, V1.H[0]
	shrn	V22.4H, V23.4S, #16
	shrn2	V22.8H, V24.4S, #16
	smlal	V26.4S, V22.4H, V0.4H
	smlal2	V27.4S, V22.8H, V0.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V22.4H, V26.4S, #16
	shrn2	V22.8H, V27.4S, #16
	smull	V26.4S, V18.4H, V21.4H
	smull2	V27.4S, V18.8H, V21.8H
	smlal	V26.4S, V19.4H, V20.4H
	smlal2	V27.4S, V19.8H, V20.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V23.4H, V26.4S, #16
	shrn2	V23.8H, V27.4S, #16
	zip1	V24.8H, V22.8H, V23.8H
	zip2	V25.8H, V22.8H, V23.8H
	stp	Q24, Q25, [x0, #256]
	ldr	Q0, [x3, #144]
	uzp1	V18.8H, V4.8H, V5.8H
	uzp2	V19.8H, V4.8H, V5.8H
	uzp1	V20.8H, V12.8H, V13.8H
	uzp2	V21.8H, V12.8H, V13.8H
	smull	V26.4S, V18.4H, V20.4H
	smull2	V27.4S, V18.8H, V20.8H
	smull	V23.4S, V19.4H, V21.4H
	smull2	V24.4S, V19.8H, V21.8H
	xtn	V25.4H, V23.4S
	xtn2	V25.8H, V24.4S
	mul	V25.8H, V25.8H, V1.H[1]
	smlsl	V23.4S, V25.4H, V1.H[0]
	smlsl2	V24.4S, V25.8H, V1.H[0]
	shrn	V22.4H, V23.4S, #16
	shrn2	V22.8H, V24.4S, #16
	smlal	V26.4S, V22.4H, V0.4H
	smlal2	V27.4S, V22.8H, V0.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V22.4H, V26.4S, #16
	shrn2	V22.8H, V27.4S, #16
	smull	V26.4S, V18.4H, V21.4H
	smull2	V27.4S, V18.8H, V21.8H
	smlal	V26.4S, V19.4H, V20.4H
	smlal2	V27.4S, V19.8H, V20.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V23.4H, V26.4S, #16
	shrn2	V23.8H, V27.4S, #16
	zip1	V24.8H, V22.8H, V23.8H
	zip2	V25.8H, V22.8H, V23.8H
	stp	Q24, Q25, [x0, #288]
	ldr	Q0, [x3, #160]
	uzp1	V18.8H, V6.8H, V7.8H
	uzp2	V19.8H, V6.8H, V7.8H
	uzp1	V20.8H, V14.8H, V15.8H
	uzp2	V21.8H, V14.8H, V15.8H
	smull	V26.4S, V18.4H, V20.4H
	smull2	V27.4S, V18.8H, V20.8H
	smull	V23.4S, V19.4H, V21.4H
	smull2	V24.4S, V19.8H, V21.8H
	xtn	V25.4H, V23.4S
	xtn2	V25.8H, V24.4S
	mul	V25.8H, V25.8H, V1.H[1]
	smlsl	V23.4S, V25.4H, V1.H[0]
	smlsl2	V24.4S, V25.8H, V1.H[0]
	shrn	V22.4H, V23.4S, #16
	shrn2	V22.8H, V24.4S, #16
	smlal	V26.4S, V22.4H, V0.4H
	smlal2	V27.4S, V22.8H, V0.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V22.4H, V26.4S, #16
	shrn2	V22.8H, V27.4S, #16
	smull	V26.4S, V18.4H, V21.4H
	smull2	V27.4S, V18.8H, V21.8H
	smlal	V26.4S, V19.4H, V20.4H
	smlal2	V27.4S, V19.8H, V20.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V23.4H, V26.4S, #16
	shrn2	V23.8H, V27.4S, #16
	zip1	V24.8H, V22.8H, V23.8H
	zip2	V25.8H, V22.8H, V23.8H
	stp	Q24, Q25, [x0, #320]
	ldr	Q0, [x3, #176]
	uzp1	V18.8H, V8.8H, V9.8H
	uzp2	V19.8H, V8.8H, V9.8H
	uzp1	V20.8H, V16.8H, V17.8H
	uzp2	V21.8H, V16.8H, V17.8H
	smull	V26.4S, V18.4H, V20.4H
	smull2	V27.4S, V18.8H, V20.8H
	smull	V23.4S, V19.4H, V21.4H
	smull2	V24.4S, V19.8H, V21.8H
	xtn	V25.4H, V23.4S
	xtn2	V25.8H, V24.4S
	mul	V25.8H, V25.8H, V1.H[1]
	smlsl	V23.4S, V25.4H, V1.H[0]
	smlsl2	V24.4S, V25.8H, V1.H[0]
	shrn	V22.4H, V23.4S, #16
	shrn2	V22.8H, V24.4S, #16
	smlal	V26.4S, V22.4H, V0.4H
	smlal2	V27.4S, V22.8H, V0.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V22.4H, V26.4S, #16
	shrn2	V22.8H, V27.4S, #16
	smull	V26.4S, V18.4H, V21.4H
	smull2	V27.4S, V18.8H, V21.8H
	smlal	V26.4S, V19.4H, V20.4H
	smlal2	V27.4S, V19.8H, V20.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V23.4H, V26.4S, #16
	shrn2	V23.8H, V27.4S, #16
	zip1	V24.8H, V22.8H, V23.8H
	zip2	V25.8H, V22.8H, V23.8H
	stp	Q24, Q25, [x0, #352]
	ldp	Q2, Q3, [x1, #384]
	ldp	Q4, Q5, [x1, #416]
	ldp	Q6, Q7, [x1, #448]
	ldp	Q8, Q9, [x1, #480]
	ldp	Q10, Q11, [x2, #384]
	ldp	Q12, Q13, [x2, #416]
	ldp	Q14, Q15, [x2, #448]
	ldp	Q16, Q17, [x2, #480]
	ldr	Q0, [x3, #192]
	uzp1	V18.8H, V2.8H, V3.8H
	uzp2	V19.8H, V2.8H, V3.8H
	uzp1	V20.8H, V10.8H, V11.8H
	uzp2	V21.8H, V10.8H, V11.8H
	smull	V26.4S, V18.4H, V20.4H
	smull2	V27.4S, V18.8H, V20.8H
	smull	V23.4S, V19.4H, V21.4H
	smull2	V24.4S, V19.8H, V21.8H
	xtn	V25.4H, V23.4S
	xtn2	V25.8H, V24.4S
	mul	V25.8H, V25.8H, V1.H[1]
	smlsl	V23.4S, V25.4H, V1.H[0]
	smlsl2	V24.4S, V25.8H, V1.H[0]
	shrn	V22.4H, V23.4S, #16
	shrn2	V22.8H, V24.4S, #16
	smlal	V26.4S, V22.4H, V0.4H
	smlal2	V27.4S, V22.8H, V0.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V22.4H, V26.4S, #16
	shrn2	V22.8H, V27.4S, #16
	smull	V26.4S, V18.4H, V21.4H
	smull2	V27.4S, V18.8H, V21.8H
	smlal	V26.4S, V19.4H, V20.4H
	smlal2	V27.4S, V19.8H, V20.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V23.4H, V26.4S, #16
	shrn2	V23.8H, V27.4S, #16
	zip1	V24.8H, V22.8H, V23.8H
	zip2	V25.8H, V22.8H, V23.8H
	stp	Q24, Q25, [x0, #384]
	ldr	Q0, [x3, #208]
	uzp1	V18.8H, V4.8H, V5.8H
	uzp2	V19.8H, V4.8H, V5.8H
	uzp1	V20.8H, V12.8H, V13.8H
	uzp2	V21.8H, V12.8H, V13.8H
	smull	V26.4S, V18.4H, V20.4H
	smull2	V27.4S, V18.8H, V20.8H
	smull	V23.4S, V19.4H, V21.4H
	smull2	V24.4S, V19.8H, V21.8H
	xtn	V25.4H, V23.4S
	xtn2	V25.8H, V24.4S
	mul	V25.8H, V25.8H, V1.H[1]
	smlsl	V23.4S, V25.4H, V1.H[0]
	smlsl2	V24.4S, V25.8H, V1.H[0]
	shrn	V22.4H, V23.4S, #16
	shrn2	V22.8H, V24.4S, #16
	smlal	V26.4S, V22.4H, V0.4H
	smlal2	V27.4S, V22.8H, V0.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V22.4H, V26.4S, #16
	shrn2	V22.8H, V27.4S, #16
	smull	V26.4S, V18.4H, V21.4H
	smull2	V27.4S, V18.8H, V21.8H
	smlal	V26.4S, V19.4H, V20.4H
	smlal2	V27.4S, V19.8H, V20.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V23.4H, V26.4S, #16
	shrn2	V23.8H, V27.4S, #16
	zip1	V24.8H, V22.8H, V23.8H
	zip2	V25.8H, V22.8H, V23.8H
	stp	Q24, Q25, [x0, #416]
	ldr	Q0, [x3, #224]
	uzp1	V18.8H, V6.8H, V7.8H
	uzp2	V19.8H, V6.8H, V7.8H
	uzp1	V20.8H, V14.8H, V15.8H
	uzp2	V21.8H, V14.8H, V15.8H
	smull	V26.4S, V18.4H, V20.4H
	smull2	V27.4S, V18.8H, V20.8H
	smull	V23.4S, V19.4H, V21.4H
	smull2	V24.4S, V19.8H, V21.8H
	xtn	V25.4H, V23.4S
	xtn2	V25.8H, V24.4S
	mul	V25.8H, V25.8H, V1.H[1]
	smlsl	V23.4S, V25.4H, V1.H[0]
	smlsl2	V24.4S, V25.8H, V1.H[0]
	shrn	V22.4H, V23.4S, #16
	shrn2	V22.8H, V24.4S, #16
	smlal	V26.4S, V22.4H, V0.4H
	smlal2	V27.4S, V22.8H, V0.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V22.4H, V26.4S, #16
	shrn2	V22.8H, V27.4S, #16
	smull	V26.4S, V18.4H, V21.4H
	smull2	V27.4S, V18.8H, V21.8H
	smlal	V26.4S, V19.4H, V20.4H
	smlal2	V27.4S, V19.8H, V20.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V23.4H, V26.4S, #16
	shrn2	V23.8H, V27.4S, #16
	zip1	V24.8H, V22.8H, V23.8H
	zip2	V25.8H, V22.8H, V23.8H
	stp	Q24, Q25, [x0, #448]
	ldr	Q0, [x3, #240]
	uzp1	V18.8H, V8.8H, V9.8H
	uzp2	V19.8H, V8.8H, V9.8H
	uzp1	V20.8H, V16.8H, V17.8H
	uzp2	V21.8H, V16.8H, V17.8H
	smull	V26.4S, V18.4H, V20.4H
	smull2	V27.4S, V18.8H, V20.8H
	smull	V23.4S, V19.4H, V21.4H
	smull2	V24.4S, V19.8H, V21.8H
	xtn	V25.4H, V23.4S
	xtn2	V25.8H, V24.4S
	mul	V25.8H, V25.8H, V1.H[1]
	smlsl	V23.4S, V25.4H, V1.H[0]
	smlsl2	V24.4S, V25.8H, V1.H[0]
	shrn	V22.4H, V23.4S, #16
	shrn2	V22.8H, V24.4S, #16
	smlal	V26.4S, V22.4H, V0.4H
	smlal2	V27.4S, V22.8H, V0.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V22.4H, V26.4S, #16
	shrn2	V22.8H, V27.4S, #16
	smull	V26.4S, V18.4H, V21.4H
	smull2	V27.4S, V18.8H, V21.8H
	smlal	V26.4S, V19.4H, V20.4H
	smlal2	V27.4S, V19.8H, V20.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V23.4H, V26.4S, #16
	shrn2	V23.8H, V27.4S, #16
	zip1	V24.8H, V22.8H, V23.8H
	zip2	V25.8H, V22.8H, V23.8H
	stp	Q24, Q25, [x0, #480]
	ldp	D8, D9, [x29, #16]
	ldp	D10, D11, [x29, #32]
	ldp	D12, D13, [x29, #48]
	ldp	D14, D15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
	ENDP
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mlkem_basemul_mont_add
mlkem_basemul_mont_add PROC
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	stp	D10, D11, [x29, #32]
	stp	D12, D13, [x29, #48]
	stp	D14, D15, [x29, #64]
	adrp	x3, L_mlkem_aarch64_zetas_mul
	add	x3, x3, L_mlkem_aarch64_zetas_mul
	adrp	x4, L_mlkem_aarch64_consts
	add	x4, x4, L_mlkem_aarch64_consts
	ldr	Q1, [x4]
	ldp	Q2, Q3, [x1]
	ldp	Q4, Q5, [x1, #32]
	ldp	Q6, Q7, [x1, #64]
	ldp	Q8, Q9, [x1, #96]
	ldp	Q10, Q11, [x2]
	ldp	Q12, Q13, [x2, #32]
	ldp	Q14, Q15, [x2, #64]
	ldp	Q16, Q17, [x2, #96]
	ldp	Q28, Q29, [x0]
	ldr	Q0, [x3]
	uzp1	V18.8H, V2.8H, V3.8H
	uzp2	V19.8H, V2.8H, V3.8H
	uzp1	V20.8H, V10.8H, V11.8H
	uzp2	V21.8H, V10.8H, V11.8H
	smull	V26.4S, V18.4H, V20.4H
	smull2	V27.4S, V18.8H, V20.8H
	smull	V23.4S, V19.4H, V21.4H
	smull2	V24.4S, V19.8H, V21.8H
	xtn	V25.4H, V23.4S
	xtn2	V25.8H, V24.4S
	mul	V25.8H, V25.8H, V1.H[1]
	smlsl	V23.4S, V25.4H, V1.H[0]
	smlsl2	V24.4S, V25.8H, V1.H[0]
	shrn	V22.4H, V23.4S, #16
	shrn2	V22.8H, V24.4S, #16
	smlal	V26.4S, V22.4H, V0.4H
	smlal2	V27.4S, V22.8H, V0.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V22.4H, V26.4S, #16
	shrn2	V22.8H, V27.4S, #16
	smull	V26.4S, V18.4H, V21.4H
	smull2	V27.4S, V18.8H, V21.8H
	smlal	V26.4S, V19.4H, V20.4H
	smlal2	V27.4S, V19.8H, V20.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V23.4H, V26.4S, #16
	shrn2	V23.8H, V27.4S, #16
	zip1	V24.8H, V22.8H, V23.8H
	zip2	V25.8H, V22.8H, V23.8H
	add	V28.8H, V28.8H, V24.8H
	add	V29.8H, V29.8H, V25.8H
	stp	Q28, Q29, [x0]
	ldp	Q28, Q29, [x0, #32]
	ldr	Q0, [x3, #16]
	uzp1	V18.8H, V4.8H, V5.8H
	uzp2	V19.8H, V4.8H, V5.8H
	uzp1	V20.8H, V12.8H, V13.8H
	uzp2	V21.8H, V12.8H, V13.8H
	smull	V26.4S, V18.4H, V20.4H
	smull2	V27.4S, V18.8H, V20.8H
	smull	V23.4S, V19.4H, V21.4H
	smull2	V24.4S, V19.8H, V21.8H
	xtn	V25.4H, V23.4S
	xtn2	V25.8H, V24.4S
	mul	V25.8H, V25.8H, V1.H[1]
	smlsl	V23.4S, V25.4H, V1.H[0]
	smlsl2	V24.4S, V25.8H, V1.H[0]
	shrn	V22.4H, V23.4S, #16
	shrn2	V22.8H, V24.4S, #16
	smlal	V26.4S, V22.4H, V0.4H
	smlal2	V27.4S, V22.8H, V0.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V22.4H, V26.4S, #16
	shrn2	V22.8H, V27.4S, #16
	smull	V26.4S, V18.4H, V21.4H
	smull2	V27.4S, V18.8H, V21.8H
	smlal	V26.4S, V19.4H, V20.4H
	smlal2	V27.4S, V19.8H, V20.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V23.4H, V26.4S, #16
	shrn2	V23.8H, V27.4S, #16
	zip1	V24.8H, V22.8H, V23.8H
	zip2	V25.8H, V22.8H, V23.8H
	add	V28.8H, V28.8H, V24.8H
	add	V29.8H, V29.8H, V25.8H
	stp	Q28, Q29, [x0, #32]
	ldp	Q28, Q29, [x0, #64]
	ldr	Q0, [x3, #32]
	uzp1	V18.8H, V6.8H, V7.8H
	uzp2	V19.8H, V6.8H, V7.8H
	uzp1	V20.8H, V14.8H, V15.8H
	uzp2	V21.8H, V14.8H, V15.8H
	smull	V26.4S, V18.4H, V20.4H
	smull2	V27.4S, V18.8H, V20.8H
	smull	V23.4S, V19.4H, V21.4H
	smull2	V24.4S, V19.8H, V21.8H
	xtn	V25.4H, V23.4S
	xtn2	V25.8H, V24.4S
	mul	V25.8H, V25.8H, V1.H[1]
	smlsl	V23.4S, V25.4H, V1.H[0]
	smlsl2	V24.4S, V25.8H, V1.H[0]
	shrn	V22.4H, V23.4S, #16
	shrn2	V22.8H, V24.4S, #16
	smlal	V26.4S, V22.4H, V0.4H
	smlal2	V27.4S, V22.8H, V0.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V22.4H, V26.4S, #16
	shrn2	V22.8H, V27.4S, #16
	smull	V26.4S, V18.4H, V21.4H
	smull2	V27.4S, V18.8H, V21.8H
	smlal	V26.4S, V19.4H, V20.4H
	smlal2	V27.4S, V19.8H, V20.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V23.4H, V26.4S, #16
	shrn2	V23.8H, V27.4S, #16
	zip1	V24.8H, V22.8H, V23.8H
	zip2	V25.8H, V22.8H, V23.8H
	add	V28.8H, V28.8H, V24.8H
	add	V29.8H, V29.8H, V25.8H
	stp	Q28, Q29, [x0, #64]
	ldp	Q28, Q29, [x0, #96]
	ldr	Q0, [x3, #48]
	uzp1	V18.8H, V8.8H, V9.8H
	uzp2	V19.8H, V8.8H, V9.8H
	uzp1	V20.8H, V16.8H, V17.8H
	uzp2	V21.8H, V16.8H, V17.8H
	smull	V26.4S, V18.4H, V20.4H
	smull2	V27.4S, V18.8H, V20.8H
	smull	V23.4S, V19.4H, V21.4H
	smull2	V24.4S, V19.8H, V21.8H
	xtn	V25.4H, V23.4S
	xtn2	V25.8H, V24.4S
	mul	V25.8H, V25.8H, V1.H[1]
	smlsl	V23.4S, V25.4H, V1.H[0]
	smlsl2	V24.4S, V25.8H, V1.H[0]
	shrn	V22.4H, V23.4S, #16
	shrn2	V22.8H, V24.4S, #16
	smlal	V26.4S, V22.4H, V0.4H
	smlal2	V27.4S, V22.8H, V0.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V22.4H, V26.4S, #16
	shrn2	V22.8H, V27.4S, #16
	smull	V26.4S, V18.4H, V21.4H
	smull2	V27.4S, V18.8H, V21.8H
	smlal	V26.4S, V19.4H, V20.4H
	smlal2	V27.4S, V19.8H, V20.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V23.4H, V26.4S, #16
	shrn2	V23.8H, V27.4S, #16
	zip1	V24.8H, V22.8H, V23.8H
	zip2	V25.8H, V22.8H, V23.8H
	add	V28.8H, V28.8H, V24.8H
	add	V29.8H, V29.8H, V25.8H
	stp	Q28, Q29, [x0, #96]
	ldp	Q2, Q3, [x1, #128]
	ldp	Q4, Q5, [x1, #160]
	ldp	Q6, Q7, [x1, #192]
	ldp	Q8, Q9, [x1, #224]
	ldp	Q10, Q11, [x2, #128]
	ldp	Q12, Q13, [x2, #160]
	ldp	Q14, Q15, [x2, #192]
	ldp	Q16, Q17, [x2, #224]
	ldp	Q28, Q29, [x0, #128]
	ldr	Q0, [x3, #64]
	uzp1	V18.8H, V2.8H, V3.8H
	uzp2	V19.8H, V2.8H, V3.8H
	uzp1	V20.8H, V10.8H, V11.8H
	uzp2	V21.8H, V10.8H, V11.8H
	smull	V26.4S, V18.4H, V20.4H
	smull2	V27.4S, V18.8H, V20.8H
	smull	V23.4S, V19.4H, V21.4H
	smull2	V24.4S, V19.8H, V21.8H
	xtn	V25.4H, V23.4S
	xtn2	V25.8H, V24.4S
	mul	V25.8H, V25.8H, V1.H[1]
	smlsl	V23.4S, V25.4H, V1.H[0]
	smlsl2	V24.4S, V25.8H, V1.H[0]
	shrn	V22.4H, V23.4S, #16
	shrn2	V22.8H, V24.4S, #16
	smlal	V26.4S, V22.4H, V0.4H
	smlal2	V27.4S, V22.8H, V0.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V22.4H, V26.4S, #16
	shrn2	V22.8H, V27.4S, #16
	smull	V26.4S, V18.4H, V21.4H
	smull2	V27.4S, V18.8H, V21.8H
	smlal	V26.4S, V19.4H, V20.4H
	smlal2	V27.4S, V19.8H, V20.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V23.4H, V26.4S, #16
	shrn2	V23.8H, V27.4S, #16
	zip1	V24.8H, V22.8H, V23.8H
	zip2	V25.8H, V22.8H, V23.8H
	add	V28.8H, V28.8H, V24.8H
	add	V29.8H, V29.8H, V25.8H
	stp	Q28, Q29, [x0, #128]
	ldp	Q28, Q29, [x0, #160]
	ldr	Q0, [x3, #80]
	uzp1	V18.8H, V4.8H, V5.8H
	uzp2	V19.8H, V4.8H, V5.8H
	uzp1	V20.8H, V12.8H, V13.8H
	uzp2	V21.8H, V12.8H, V13.8H
	smull	V26.4S, V18.4H, V20.4H
	smull2	V27.4S, V18.8H, V20.8H
	smull	V23.4S, V19.4H, V21.4H
	smull2	V24.4S, V19.8H, V21.8H
	xtn	V25.4H, V23.4S
	xtn2	V25.8H, V24.4S
	mul	V25.8H, V25.8H, V1.H[1]
	smlsl	V23.4S, V25.4H, V1.H[0]
	smlsl2	V24.4S, V25.8H, V1.H[0]
	shrn	V22.4H, V23.4S, #16
	shrn2	V22.8H, V24.4S, #16
	smlal	V26.4S, V22.4H, V0.4H
	smlal2	V27.4S, V22.8H, V0.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V22.4H, V26.4S, #16
	shrn2	V22.8H, V27.4S, #16
	smull	V26.4S, V18.4H, V21.4H
	smull2	V27.4S, V18.8H, V21.8H
	smlal	V26.4S, V19.4H, V20.4H
	smlal2	V27.4S, V19.8H, V20.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V23.4H, V26.4S, #16
	shrn2	V23.8H, V27.4S, #16
	zip1	V24.8H, V22.8H, V23.8H
	zip2	V25.8H, V22.8H, V23.8H
	add	V28.8H, V28.8H, V24.8H
	add	V29.8H, V29.8H, V25.8H
	stp	Q28, Q29, [x0, #160]
	ldp	Q28, Q29, [x0, #192]
	ldr	Q0, [x3, #96]
	uzp1	V18.8H, V6.8H, V7.8H
	uzp2	V19.8H, V6.8H, V7.8H
	uzp1	V20.8H, V14.8H, V15.8H
	uzp2	V21.8H, V14.8H, V15.8H
	smull	V26.4S, V18.4H, V20.4H
	smull2	V27.4S, V18.8H, V20.8H
	smull	V23.4S, V19.4H, V21.4H
	smull2	V24.4S, V19.8H, V21.8H
	xtn	V25.4H, V23.4S
	xtn2	V25.8H, V24.4S
	mul	V25.8H, V25.8H, V1.H[1]
	smlsl	V23.4S, V25.4H, V1.H[0]
	smlsl2	V24.4S, V25.8H, V1.H[0]
	shrn	V22.4H, V23.4S, #16
	shrn2	V22.8H, V24.4S, #16
	smlal	V26.4S, V22.4H, V0.4H
	smlal2	V27.4S, V22.8H, V0.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V22.4H, V26.4S, #16
	shrn2	V22.8H, V27.4S, #16
	smull	V26.4S, V18.4H, V21.4H
	smull2	V27.4S, V18.8H, V21.8H
	smlal	V26.4S, V19.4H, V20.4H
	smlal2	V27.4S, V19.8H, V20.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V23.4H, V26.4S, #16
	shrn2	V23.8H, V27.4S, #16
	zip1	V24.8H, V22.8H, V23.8H
	zip2	V25.8H, V22.8H, V23.8H
	add	V28.8H, V28.8H, V24.8H
	add	V29.8H, V29.8H, V25.8H
	stp	Q28, Q29, [x0, #192]
	ldp	Q28, Q29, [x0, #224]
	ldr	Q0, [x3, #112]
	uzp1	V18.8H, V8.8H, V9.8H
	uzp2	V19.8H, V8.8H, V9.8H
	uzp1	V20.8H, V16.8H, V17.8H
	uzp2	V21.8H, V16.8H, V17.8H
	smull	V26.4S, V18.4H, V20.4H
	smull2	V27.4S, V18.8H, V20.8H
	smull	V23.4S, V19.4H, V21.4H
	smull2	V24.4S, V19.8H, V21.8H
	xtn	V25.4H, V23.4S
	xtn2	V25.8H, V24.4S
	mul	V25.8H, V25.8H, V1.H[1]
	smlsl	V23.4S, V25.4H, V1.H[0]
	smlsl2	V24.4S, V25.8H, V1.H[0]
	shrn	V22.4H, V23.4S, #16
	shrn2	V22.8H, V24.4S, #16
	smlal	V26.4S, V22.4H, V0.4H
	smlal2	V27.4S, V22.8H, V0.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V22.4H, V26.4S, #16
	shrn2	V22.8H, V27.4S, #16
	smull	V26.4S, V18.4H, V21.4H
	smull2	V27.4S, V18.8H, V21.8H
	smlal	V26.4S, V19.4H, V20.4H
	smlal2	V27.4S, V19.8H, V20.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V23.4H, V26.4S, #16
	shrn2	V23.8H, V27.4S, #16
	zip1	V24.8H, V22.8H, V23.8H
	zip2	V25.8H, V22.8H, V23.8H
	add	V28.8H, V28.8H, V24.8H
	add	V29.8H, V29.8H, V25.8H
	stp	Q28, Q29, [x0, #224]
	ldp	Q2, Q3, [x1, #256]
	ldp	Q4, Q5, [x1, #288]
	ldp	Q6, Q7, [x1, #320]
	ldp	Q8, Q9, [x1, #352]
	ldp	Q10, Q11, [x2, #256]
	ldp	Q12, Q13, [x2, #288]
	ldp	Q14, Q15, [x2, #320]
	ldp	Q16, Q17, [x2, #352]
	ldp	Q28, Q29, [x0, #256]
	ldr	Q0, [x3, #128]
	uzp1	V18.8H, V2.8H, V3.8H
	uzp2	V19.8H, V2.8H, V3.8H
	uzp1	V20.8H, V10.8H, V11.8H
	uzp2	V21.8H, V10.8H, V11.8H
	smull	V26.4S, V18.4H, V20.4H
	smull2	V27.4S, V18.8H, V20.8H
	smull	V23.4S, V19.4H, V21.4H
	smull2	V24.4S, V19.8H, V21.8H
	xtn	V25.4H, V23.4S
	xtn2	V25.8H, V24.4S
	mul	V25.8H, V25.8H, V1.H[1]
	smlsl	V23.4S, V25.4H, V1.H[0]
	smlsl2	V24.4S, V25.8H, V1.H[0]
	shrn	V22.4H, V23.4S, #16
	shrn2	V22.8H, V24.4S, #16
	smlal	V26.4S, V22.4H, V0.4H
	smlal2	V27.4S, V22.8H, V0.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V22.4H, V26.4S, #16
	shrn2	V22.8H, V27.4S, #16
	smull	V26.4S, V18.4H, V21.4H
	smull2	V27.4S, V18.8H, V21.8H
	smlal	V26.4S, V19.4H, V20.4H
	smlal2	V27.4S, V19.8H, V20.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V23.4H, V26.4S, #16
	shrn2	V23.8H, V27.4S, #16
	zip1	V24.8H, V22.8H, V23.8H
	zip2	V25.8H, V22.8H, V23.8H
	add	V28.8H, V28.8H, V24.8H
	add	V29.8H, V29.8H, V25.8H
	stp	Q28, Q29, [x0, #256]
	ldp	Q28, Q29, [x0, #288]
	ldr	Q0, [x3, #144]
	uzp1	V18.8H, V4.8H, V5.8H
	uzp2	V19.8H, V4.8H, V5.8H
	uzp1	V20.8H, V12.8H, V13.8H
	uzp2	V21.8H, V12.8H, V13.8H
	smull	V26.4S, V18.4H, V20.4H
	smull2	V27.4S, V18.8H, V20.8H
	smull	V23.4S, V19.4H, V21.4H
	smull2	V24.4S, V19.8H, V21.8H
	xtn	V25.4H, V23.4S
	xtn2	V25.8H, V24.4S
	mul	V25.8H, V25.8H, V1.H[1]
	smlsl	V23.4S, V25.4H, V1.H[0]
	smlsl2	V24.4S, V25.8H, V1.H[0]
	shrn	V22.4H, V23.4S, #16
	shrn2	V22.8H, V24.4S, #16
	smlal	V26.4S, V22.4H, V0.4H
	smlal2	V27.4S, V22.8H, V0.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V22.4H, V26.4S, #16
	shrn2	V22.8H, V27.4S, #16
	smull	V26.4S, V18.4H, V21.4H
	smull2	V27.4S, V18.8H, V21.8H
	smlal	V26.4S, V19.4H, V20.4H
	smlal2	V27.4S, V19.8H, V20.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V23.4H, V26.4S, #16
	shrn2	V23.8H, V27.4S, #16
	zip1	V24.8H, V22.8H, V23.8H
	zip2	V25.8H, V22.8H, V23.8H
	add	V28.8H, V28.8H, V24.8H
	add	V29.8H, V29.8H, V25.8H
	stp	Q28, Q29, [x0, #288]
	ldp	Q28, Q29, [x0, #320]
	ldr	Q0, [x3, #160]
	uzp1	V18.8H, V6.8H, V7.8H
	uzp2	V19.8H, V6.8H, V7.8H
	uzp1	V20.8H, V14.8H, V15.8H
	uzp2	V21.8H, V14.8H, V15.8H
	smull	V26.4S, V18.4H, V20.4H
	smull2	V27.4S, V18.8H, V20.8H
	smull	V23.4S, V19.4H, V21.4H
	smull2	V24.4S, V19.8H, V21.8H
	xtn	V25.4H, V23.4S
	xtn2	V25.8H, V24.4S
	mul	V25.8H, V25.8H, V1.H[1]
	smlsl	V23.4S, V25.4H, V1.H[0]
	smlsl2	V24.4S, V25.8H, V1.H[0]
	shrn	V22.4H, V23.4S, #16
	shrn2	V22.8H, V24.4S, #16
	smlal	V26.4S, V22.4H, V0.4H
	smlal2	V27.4S, V22.8H, V0.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V22.4H, V26.4S, #16
	shrn2	V22.8H, V27.4S, #16
	smull	V26.4S, V18.4H, V21.4H
	smull2	V27.4S, V18.8H, V21.8H
	smlal	V26.4S, V19.4H, V20.4H
	smlal2	V27.4S, V19.8H, V20.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V23.4H, V26.4S, #16
	shrn2	V23.8H, V27.4S, #16
	zip1	V24.8H, V22.8H, V23.8H
	zip2	V25.8H, V22.8H, V23.8H
	add	V28.8H, V28.8H, V24.8H
	add	V29.8H, V29.8H, V25.8H
	stp	Q28, Q29, [x0, #320]
	ldp	Q28, Q29, [x0, #352]
	ldr	Q0, [x3, #176]
	uzp1	V18.8H, V8.8H, V9.8H
	uzp2	V19.8H, V8.8H, V9.8H
	uzp1	V20.8H, V16.8H, V17.8H
	uzp2	V21.8H, V16.8H, V17.8H
	smull	V26.4S, V18.4H, V20.4H
	smull2	V27.4S, V18.8H, V20.8H
	smull	V23.4S, V19.4H, V21.4H
	smull2	V24.4S, V19.8H, V21.8H
	xtn	V25.4H, V23.4S
	xtn2	V25.8H, V24.4S
	mul	V25.8H, V25.8H, V1.H[1]
	smlsl	V23.4S, V25.4H, V1.H[0]
	smlsl2	V24.4S, V25.8H, V1.H[0]
	shrn	V22.4H, V23.4S, #16
	shrn2	V22.8H, V24.4S, #16
	smlal	V26.4S, V22.4H, V0.4H
	smlal2	V27.4S, V22.8H, V0.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V22.4H, V26.4S, #16
	shrn2	V22.8H, V27.4S, #16
	smull	V26.4S, V18.4H, V21.4H
	smull2	V27.4S, V18.8H, V21.8H
	smlal	V26.4S, V19.4H, V20.4H
	smlal2	V27.4S, V19.8H, V20.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V23.4H, V26.4S, #16
	shrn2	V23.8H, V27.4S, #16
	zip1	V24.8H, V22.8H, V23.8H
	zip2	V25.8H, V22.8H, V23.8H
	add	V28.8H, V28.8H, V24.8H
	add	V29.8H, V29.8H, V25.8H
	stp	Q28, Q29, [x0, #352]
	ldp	Q2, Q3, [x1, #384]
	ldp	Q4, Q5, [x1, #416]
	ldp	Q6, Q7, [x1, #448]
	ldp	Q8, Q9, [x1, #480]
	ldp	Q10, Q11, [x2, #384]
	ldp	Q12, Q13, [x2, #416]
	ldp	Q14, Q15, [x2, #448]
	ldp	Q16, Q17, [x2, #480]
	ldp	Q28, Q29, [x0, #384]
	ldr	Q0, [x3, #192]
	uzp1	V18.8H, V2.8H, V3.8H
	uzp2	V19.8H, V2.8H, V3.8H
	uzp1	V20.8H, V10.8H, V11.8H
	uzp2	V21.8H, V10.8H, V11.8H
	smull	V26.4S, V18.4H, V20.4H
	smull2	V27.4S, V18.8H, V20.8H
	smull	V23.4S, V19.4H, V21.4H
	smull2	V24.4S, V19.8H, V21.8H
	xtn	V25.4H, V23.4S
	xtn2	V25.8H, V24.4S
	mul	V25.8H, V25.8H, V1.H[1]
	smlsl	V23.4S, V25.4H, V1.H[0]
	smlsl2	V24.4S, V25.8H, V1.H[0]
	shrn	V22.4H, V23.4S, #16
	shrn2	V22.8H, V24.4S, #16
	smlal	V26.4S, V22.4H, V0.4H
	smlal2	V27.4S, V22.8H, V0.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V22.4H, V26.4S, #16
	shrn2	V22.8H, V27.4S, #16
	smull	V26.4S, V18.4H, V21.4H
	smull2	V27.4S, V18.8H, V21.8H
	smlal	V26.4S, V19.4H, V20.4H
	smlal2	V27.4S, V19.8H, V20.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V23.4H, V26.4S, #16
	shrn2	V23.8H, V27.4S, #16
	zip1	V24.8H, V22.8H, V23.8H
	zip2	V25.8H, V22.8H, V23.8H
	add	V28.8H, V28.8H, V24.8H
	add	V29.8H, V29.8H, V25.8H
	stp	Q28, Q29, [x0, #384]
	ldp	Q28, Q29, [x0, #416]
	ldr	Q0, [x3, #208]
	uzp1	V18.8H, V4.8H, V5.8H
	uzp2	V19.8H, V4.8H, V5.8H
	uzp1	V20.8H, V12.8H, V13.8H
	uzp2	V21.8H, V12.8H, V13.8H
	smull	V26.4S, V18.4H, V20.4H
	smull2	V27.4S, V18.8H, V20.8H
	smull	V23.4S, V19.4H, V21.4H
	smull2	V24.4S, V19.8H, V21.8H
	xtn	V25.4H, V23.4S
	xtn2	V25.8H, V24.4S
	mul	V25.8H, V25.8H, V1.H[1]
	smlsl	V23.4S, V25.4H, V1.H[0]
	smlsl2	V24.4S, V25.8H, V1.H[0]
	shrn	V22.4H, V23.4S, #16
	shrn2	V22.8H, V24.4S, #16
	smlal	V26.4S, V22.4H, V0.4H
	smlal2	V27.4S, V22.8H, V0.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V22.4H, V26.4S, #16
	shrn2	V22.8H, V27.4S, #16
	smull	V26.4S, V18.4H, V21.4H
	smull2	V27.4S, V18.8H, V21.8H
	smlal	V26.4S, V19.4H, V20.4H
	smlal2	V27.4S, V19.8H, V20.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V23.4H, V26.4S, #16
	shrn2	V23.8H, V27.4S, #16
	zip1	V24.8H, V22.8H, V23.8H
	zip2	V25.8H, V22.8H, V23.8H
	add	V28.8H, V28.8H, V24.8H
	add	V29.8H, V29.8H, V25.8H
	stp	Q28, Q29, [x0, #416]
	ldp	Q28, Q29, [x0, #448]
	ldr	Q0, [x3, #224]
	uzp1	V18.8H, V6.8H, V7.8H
	uzp2	V19.8H, V6.8H, V7.8H
	uzp1	V20.8H, V14.8H, V15.8H
	uzp2	V21.8H, V14.8H, V15.8H
	smull	V26.4S, V18.4H, V20.4H
	smull2	V27.4S, V18.8H, V20.8H
	smull	V23.4S, V19.4H, V21.4H
	smull2	V24.4S, V19.8H, V21.8H
	xtn	V25.4H, V23.4S
	xtn2	V25.8H, V24.4S
	mul	V25.8H, V25.8H, V1.H[1]
	smlsl	V23.4S, V25.4H, V1.H[0]
	smlsl2	V24.4S, V25.8H, V1.H[0]
	shrn	V22.4H, V23.4S, #16
	shrn2	V22.8H, V24.4S, #16
	smlal	V26.4S, V22.4H, V0.4H
	smlal2	V27.4S, V22.8H, V0.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V22.4H, V26.4S, #16
	shrn2	V22.8H, V27.4S, #16
	smull	V26.4S, V18.4H, V21.4H
	smull2	V27.4S, V18.8H, V21.8H
	smlal	V26.4S, V19.4H, V20.4H
	smlal2	V27.4S, V19.8H, V20.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V23.4H, V26.4S, #16
	shrn2	V23.8H, V27.4S, #16
	zip1	V24.8H, V22.8H, V23.8H
	zip2	V25.8H, V22.8H, V23.8H
	add	V28.8H, V28.8H, V24.8H
	add	V29.8H, V29.8H, V25.8H
	stp	Q28, Q29, [x0, #448]
	ldp	Q28, Q29, [x0, #480]
	ldr	Q0, [x3, #240]
	uzp1	V18.8H, V8.8H, V9.8H
	uzp2	V19.8H, V8.8H, V9.8H
	uzp1	V20.8H, V16.8H, V17.8H
	uzp2	V21.8H, V16.8H, V17.8H
	smull	V26.4S, V18.4H, V20.4H
	smull2	V27.4S, V18.8H, V20.8H
	smull	V23.4S, V19.4H, V21.4H
	smull2	V24.4S, V19.8H, V21.8H
	xtn	V25.4H, V23.4S
	xtn2	V25.8H, V24.4S
	mul	V25.8H, V25.8H, V1.H[1]
	smlsl	V23.4S, V25.4H, V1.H[0]
	smlsl2	V24.4S, V25.8H, V1.H[0]
	shrn	V22.4H, V23.4S, #16
	shrn2	V22.8H, V24.4S, #16
	smlal	V26.4S, V22.4H, V0.4H
	smlal2	V27.4S, V22.8H, V0.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V22.4H, V26.4S, #16
	shrn2	V22.8H, V27.4S, #16
	smull	V26.4S, V18.4H, V21.4H
	smull2	V27.4S, V18.8H, V21.8H
	smlal	V26.4S, V19.4H, V20.4H
	smlal2	V27.4S, V19.8H, V20.8H
	xtn	V24.4H, V26.4S
	xtn2	V24.8H, V27.4S
	mul	V24.8H, V24.8H, V1.H[1]
	smlsl	V26.4S, V24.4H, V1.H[0]
	smlsl2	V27.4S, V24.8H, V1.H[0]
	shrn	V23.4H, V26.4S, #16
	shrn2	V23.8H, V27.4S, #16
	zip1	V24.8H, V22.8H, V23.8H
	zip2	V25.8H, V22.8H, V23.8H
	add	V28.8H, V28.8H, V24.8H
	add	V29.8H, V29.8H, V25.8H
	stp	Q28, Q29, [x0, #480]
	ldp	D8, D9, [x29, #16]
	ldp	D10, D11, [x29, #32]
	ldp	D12, D13, [x29, #48]
	ldp	D14, D15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
	ENDP
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mlkem_aarch64_q
	DCW	0x0d01, 0x0d01, 0x0d01, 0x0d01, 0x0d01, 0x0d01, 0x0d01, 0x0d01
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mlkem_csubq_neon
mlkem_csubq_neon PROC
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	stp	D10, D11, [x29, #32]
	stp	D12, D13, [x29, #48]
	stp	D14, D15, [x29, #64]
	adrp	x1, L_mlkem_aarch64_q
	add	x1, x1, L_mlkem_aarch64_q
	ldr	Q20, [x1]
	ld4	{V0.8H, V1.8H, V2.8H, V3.8H}, [x0], #0x40
	ld4	{V4.8H, V5.8H, V6.8H, V7.8H}, [x0], #0x40
	ld4	{V8.8H, V9.8H, V10.8H, V11.8H}, [x0], #0x40
	ld4	{V12.8H, V13.8H, V14.8H, V15.8H}, [x0], #0x40
	sub	x0, x0, #0x100
	sub	V0.8H, V0.8H, V20.8H
	sub	V1.8H, V1.8H, V20.8H
	sub	V2.8H, V2.8H, V20.8H
	sub	V3.8H, V3.8H, V20.8H
	sub	V4.8H, V4.8H, V20.8H
	sub	V5.8H, V5.8H, V20.8H
	sub	V6.8H, V6.8H, V20.8H
	sub	V7.8H, V7.8H, V20.8H
	sub	V8.8H, V8.8H, V20.8H
	sub	V9.8H, V9.8H, V20.8H
	sub	V10.8H, V10.8H, V20.8H
	sub	V11.8H, V11.8H, V20.8H
	sub	V12.8H, V12.8H, V20.8H
	sub	V13.8H, V13.8H, V20.8H
	sub	V14.8H, V14.8H, V20.8H
	sub	V15.8H, V15.8H, V20.8H
	sshr	V16.8H, V0.8H, #15
	sshr	V17.8H, V1.8H, #15
	sshr	V18.8H, V2.8H, #15
	sshr	V19.8H, V3.8H, #15
	and	V16.16B, V16.16B, V20.16B
	and	V17.16B, V17.16B, V20.16B
	and	V18.16B, V18.16B, V20.16B
	and	V19.16B, V19.16B, V20.16B
	add	V0.8H, V0.8H, V16.8H
	add	V1.8H, V1.8H, V17.8H
	add	V2.8H, V2.8H, V18.8H
	add	V3.8H, V3.8H, V19.8H
	sshr	V16.8H, V4.8H, #15
	sshr	V17.8H, V5.8H, #15
	sshr	V18.8H, V6.8H, #15
	sshr	V19.8H, V7.8H, #15
	and	V16.16B, V16.16B, V20.16B
	and	V17.16B, V17.16B, V20.16B
	and	V18.16B, V18.16B, V20.16B
	and	V19.16B, V19.16B, V20.16B
	add	V4.8H, V4.8H, V16.8H
	add	V5.8H, V5.8H, V17.8H
	add	V6.8H, V6.8H, V18.8H
	add	V7.8H, V7.8H, V19.8H
	sshr	V16.8H, V8.8H, #15
	sshr	V17.8H, V9.8H, #15
	sshr	V18.8H, V10.8H, #15
	sshr	V19.8H, V11.8H, #15
	and	V16.16B, V16.16B, V20.16B
	and	V17.16B, V17.16B, V20.16B
	and	V18.16B, V18.16B, V20.16B
	and	V19.16B, V19.16B, V20.16B
	add	V8.8H, V8.8H, V16.8H
	add	V9.8H, V9.8H, V17.8H
	add	V10.8H, V10.8H, V18.8H
	add	V11.8H, V11.8H, V19.8H
	sshr	V16.8H, V12.8H, #15
	sshr	V17.8H, V13.8H, #15
	sshr	V18.8H, V14.8H, #15
	sshr	V19.8H, V15.8H, #15
	and	V16.16B, V16.16B, V20.16B
	and	V17.16B, V17.16B, V20.16B
	and	V18.16B, V18.16B, V20.16B
	and	V19.16B, V19.16B, V20.16B
	add	V12.8H, V12.8H, V16.8H
	add	V13.8H, V13.8H, V17.8H
	add	V14.8H, V14.8H, V18.8H
	add	V15.8H, V15.8H, V19.8H
	st4	{V0.8H, V1.8H, V2.8H, V3.8H}, [x0], #0x40
	st4	{V4.8H, V5.8H, V6.8H, V7.8H}, [x0], #0x40
	st4	{V8.8H, V9.8H, V10.8H, V11.8H}, [x0], #0x40
	st4	{V12.8H, V13.8H, V14.8H, V15.8H}, [x0], #0x40
	ld4	{V0.8H, V1.8H, V2.8H, V3.8H}, [x0], #0x40
	ld4	{V4.8H, V5.8H, V6.8H, V7.8H}, [x0], #0x40
	ld4	{V8.8H, V9.8H, V10.8H, V11.8H}, [x0], #0x40
	ld4	{V12.8H, V13.8H, V14.8H, V15.8H}, [x0], #0x40
	sub	x0, x0, #0x100
	sub	V0.8H, V0.8H, V20.8H
	sub	V1.8H, V1.8H, V20.8H
	sub	V2.8H, V2.8H, V20.8H
	sub	V3.8H, V3.8H, V20.8H
	sub	V4.8H, V4.8H, V20.8H
	sub	V5.8H, V5.8H, V20.8H
	sub	V6.8H, V6.8H, V20.8H
	sub	V7.8H, V7.8H, V20.8H
	sub	V8.8H, V8.8H, V20.8H
	sub	V9.8H, V9.8H, V20.8H
	sub	V10.8H, V10.8H, V20.8H
	sub	V11.8H, V11.8H, V20.8H
	sub	V12.8H, V12.8H, V20.8H
	sub	V13.8H, V13.8H, V20.8H
	sub	V14.8H, V14.8H, V20.8H
	sub	V15.8H, V15.8H, V20.8H
	sshr	V16.8H, V0.8H, #15
	sshr	V17.8H, V1.8H, #15
	sshr	V18.8H, V2.8H, #15
	sshr	V19.8H, V3.8H, #15
	and	V16.16B, V16.16B, V20.16B
	and	V17.16B, V17.16B, V20.16B
	and	V18.16B, V18.16B, V20.16B
	and	V19.16B, V19.16B, V20.16B
	add	V0.8H, V0.8H, V16.8H
	add	V1.8H, V1.8H, V17.8H
	add	V2.8H, V2.8H, V18.8H
	add	V3.8H, V3.8H, V19.8H
	sshr	V16.8H, V4.8H, #15
	sshr	V17.8H, V5.8H, #15
	sshr	V18.8H, V6.8H, #15
	sshr	V19.8H, V7.8H, #15
	and	V16.16B, V16.16B, V20.16B
	and	V17.16B, V17.16B, V20.16B
	and	V18.16B, V18.16B, V20.16B
	and	V19.16B, V19.16B, V20.16B
	add	V4.8H, V4.8H, V16.8H
	add	V5.8H, V5.8H, V17.8H
	add	V6.8H, V6.8H, V18.8H
	add	V7.8H, V7.8H, V19.8H
	sshr	V16.8H, V8.8H, #15
	sshr	V17.8H, V9.8H, #15
	sshr	V18.8H, V10.8H, #15
	sshr	V19.8H, V11.8H, #15
	and	V16.16B, V16.16B, V20.16B
	and	V17.16B, V17.16B, V20.16B
	and	V18.16B, V18.16B, V20.16B
	and	V19.16B, V19.16B, V20.16B
	add	V8.8H, V8.8H, V16.8H
	add	V9.8H, V9.8H, V17.8H
	add	V10.8H, V10.8H, V18.8H
	add	V11.8H, V11.8H, V19.8H
	sshr	V16.8H, V12.8H, #15
	sshr	V17.8H, V13.8H, #15
	sshr	V18.8H, V14.8H, #15
	sshr	V19.8H, V15.8H, #15
	and	V16.16B, V16.16B, V20.16B
	and	V17.16B, V17.16B, V20.16B
	and	V18.16B, V18.16B, V20.16B
	and	V19.16B, V19.16B, V20.16B
	add	V12.8H, V12.8H, V16.8H
	add	V13.8H, V13.8H, V17.8H
	add	V14.8H, V14.8H, V18.8H
	add	V15.8H, V15.8H, V19.8H
	st4	{V0.8H, V1.8H, V2.8H, V3.8H}, [x0], #0x40
	st4	{V4.8H, V5.8H, V6.8H, V7.8H}, [x0], #0x40
	st4	{V8.8H, V9.8H, V10.8H, V11.8H}, [x0], #0x40
	st4	{V12.8H, V13.8H, V14.8H, V15.8H}, [x0], #0x40
	ldp	D8, D9, [x29, #16]
	ldp	D10, D11, [x29, #32]
	ldp	D12, D13, [x29, #48]
	ldp	D14, D15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
	ENDP
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mlkem_add_reduce
mlkem_add_reduce PROC
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	stp	D10, D11, [x29, #32]
	stp	D12, D13, [x29, #48]
	stp	D14, D15, [x29, #64]
	adrp	x2, L_mlkem_aarch64_consts
	add	x2, x2, L_mlkem_aarch64_consts
	ldr	Q0, [x2]
	ld4	{V1.8H, V2.8H, V3.8H, V4.8H}, [x0], #0x40
	ld4	{V5.8H, V6.8H, V7.8H, V8.8H}, [x0], #0x40
	ld4	{V9.8H, V10.8H, V11.8H, V12.8H}, [x1], #0x40
	ld4	{V13.8H, V14.8H, V15.8H, V16.8H}, [x1], #0x40
	sub	x0, x0, #0x80
	add	V1.8H, V1.8H, V9.8H
	add	V2.8H, V2.8H, V10.8H
	add	V3.8H, V3.8H, V11.8H
	add	V4.8H, V4.8H, V12.8H
	add	V5.8H, V5.8H, V13.8H
	add	V6.8H, V6.8H, V14.8H
	add	V7.8H, V7.8H, V15.8H
	add	V8.8H, V8.8H, V16.8H
	sqdmulh	V17.8H, V1.8H, V0.H[2]
	sqdmulh	V18.8H, V2.8H, V0.H[2]
	sshr	V17.8H, V17.8H, #11
	sshr	V18.8H, V18.8H, #11
	mls	V1.8H, V17.8H, V0.H[0]
	mls	V2.8H, V18.8H, V0.H[0]
	sqdmulh	V17.8H, V3.8H, V0.H[2]
	sqdmulh	V18.8H, V4.8H, V0.H[2]
	sshr	V17.8H, V17.8H, #11
	sshr	V18.8H, V18.8H, #11
	mls	V3.8H, V17.8H, V0.H[0]
	mls	V4.8H, V18.8H, V0.H[0]
	sqdmulh	V17.8H, V5.8H, V0.H[2]
	sqdmulh	V18.8H, V6.8H, V0.H[2]
	sshr	V17.8H, V17.8H, #11
	sshr	V18.8H, V18.8H, #11
	mls	V5.8H, V17.8H, V0.H[0]
	mls	V6.8H, V18.8H, V0.H[0]
	sqdmulh	V17.8H, V7.8H, V0.H[2]
	sqdmulh	V18.8H, V8.8H, V0.H[2]
	sshr	V17.8H, V17.8H, #11
	sshr	V18.8H, V18.8H, #11
	mls	V7.8H, V17.8H, V0.H[0]
	mls	V8.8H, V18.8H, V0.H[0]
	st4	{V1.8H, V2.8H, V3.8H, V4.8H}, [x0], #0x40
	st4	{V5.8H, V6.8H, V7.8H, V8.8H}, [x0], #0x40
	ld4	{V1.8H, V2.8H, V3.8H, V4.8H}, [x0], #0x40
	ld4	{V5.8H, V6.8H, V7.8H, V8.8H}, [x0], #0x40
	ld4	{V9.8H, V10.8H, V11.8H, V12.8H}, [x1], #0x40
	ld4	{V13.8H, V14.8H, V15.8H, V16.8H}, [x1], #0x40
	sub	x0, x0, #0x80
	add	V1.8H, V1.8H, V9.8H
	add	V2.8H, V2.8H, V10.8H
	add	V3.8H, V3.8H, V11.8H
	add	V4.8H, V4.8H, V12.8H
	add	V5.8H, V5.8H, V13.8H
	add	V6.8H, V6.8H, V14.8H
	add	V7.8H, V7.8H, V15.8H
	add	V8.8H, V8.8H, V16.8H
	sqdmulh	V17.8H, V1.8H, V0.H[2]
	sqdmulh	V18.8H, V2.8H, V0.H[2]
	sshr	V17.8H, V17.8H, #11
	sshr	V18.8H, V18.8H, #11
	mls	V1.8H, V17.8H, V0.H[0]
	mls	V2.8H, V18.8H, V0.H[0]
	sqdmulh	V17.8H, V3.8H, V0.H[2]
	sqdmulh	V18.8H, V4.8H, V0.H[2]
	sshr	V17.8H, V17.8H, #11
	sshr	V18.8H, V18.8H, #11
	mls	V3.8H, V17.8H, V0.H[0]
	mls	V4.8H, V18.8H, V0.H[0]
	sqdmulh	V17.8H, V5.8H, V0.H[2]
	sqdmulh	V18.8H, V6.8H, V0.H[2]
	sshr	V17.8H, V17.8H, #11
	sshr	V18.8H, V18.8H, #11
	mls	V5.8H, V17.8H, V0.H[0]
	mls	V6.8H, V18.8H, V0.H[0]
	sqdmulh	V17.8H, V7.8H, V0.H[2]
	sqdmulh	V18.8H, V8.8H, V0.H[2]
	sshr	V17.8H, V17.8H, #11
	sshr	V18.8H, V18.8H, #11
	mls	V7.8H, V17.8H, V0.H[0]
	mls	V8.8H, V18.8H, V0.H[0]
	st4	{V1.8H, V2.8H, V3.8H, V4.8H}, [x0], #0x40
	st4	{V5.8H, V6.8H, V7.8H, V8.8H}, [x0], #0x40
	ld4	{V1.8H, V2.8H, V3.8H, V4.8H}, [x0], #0x40
	ld4	{V5.8H, V6.8H, V7.8H, V8.8H}, [x0], #0x40
	ld4	{V9.8H, V10.8H, V11.8H, V12.8H}, [x1], #0x40
	ld4	{V13.8H, V14.8H, V15.8H, V16.8H}, [x1], #0x40
	sub	x0, x0, #0x80
	add	V1.8H, V1.8H, V9.8H
	add	V2.8H, V2.8H, V10.8H
	add	V3.8H, V3.8H, V11.8H
	add	V4.8H, V4.8H, V12.8H
	add	V5.8H, V5.8H, V13.8H
	add	V6.8H, V6.8H, V14.8H
	add	V7.8H, V7.8H, V15.8H
	add	V8.8H, V8.8H, V16.8H
	sqdmulh	V17.8H, V1.8H, V0.H[2]
	sqdmulh	V18.8H, V2.8H, V0.H[2]
	sshr	V17.8H, V17.8H, #11
	sshr	V18.8H, V18.8H, #11
	mls	V1.8H, V17.8H, V0.H[0]
	mls	V2.8H, V18.8H, V0.H[0]
	sqdmulh	V17.8H, V3.8H, V0.H[2]
	sqdmulh	V18.8H, V4.8H, V0.H[2]
	sshr	V17.8H, V17.8H, #11
	sshr	V18.8H, V18.8H, #11
	mls	V3.8H, V17.8H, V0.H[0]
	mls	V4.8H, V18.8H, V0.H[0]
	sqdmulh	V17.8H, V5.8H, V0.H[2]
	sqdmulh	V18.8H, V6.8H, V0.H[2]
	sshr	V17.8H, V17.8H, #11
	sshr	V18.8H, V18.8H, #11
	mls	V5.8H, V17.8H, V0.H[0]
	mls	V6.8H, V18.8H, V0.H[0]
	sqdmulh	V17.8H, V7.8H, V0.H[2]
	sqdmulh	V18.8H, V8.8H, V0.H[2]
	sshr	V17.8H, V17.8H, #11
	sshr	V18.8H, V18.8H, #11
	mls	V7.8H, V17.8H, V0.H[0]
	mls	V8.8H, V18.8H, V0.H[0]
	st4	{V1.8H, V2.8H, V3.8H, V4.8H}, [x0], #0x40
	st4	{V5.8H, V6.8H, V7.8H, V8.8H}, [x0], #0x40
	ld4	{V1.8H, V2.8H, V3.8H, V4.8H}, [x0], #0x40
	ld4	{V5.8H, V6.8H, V7.8H, V8.8H}, [x0], #0x40
	ld4	{V9.8H, V10.8H, V11.8H, V12.8H}, [x1], #0x40
	ld4	{V13.8H, V14.8H, V15.8H, V16.8H}, [x1], #0x40
	sub	x0, x0, #0x80
	add	V1.8H, V1.8H, V9.8H
	add	V2.8H, V2.8H, V10.8H
	add	V3.8H, V3.8H, V11.8H
	add	V4.8H, V4.8H, V12.8H
	add	V5.8H, V5.8H, V13.8H
	add	V6.8H, V6.8H, V14.8H
	add	V7.8H, V7.8H, V15.8H
	add	V8.8H, V8.8H, V16.8H
	sqdmulh	V17.8H, V1.8H, V0.H[2]
	sqdmulh	V18.8H, V2.8H, V0.H[2]
	sshr	V17.8H, V17.8H, #11
	sshr	V18.8H, V18.8H, #11
	mls	V1.8H, V17.8H, V0.H[0]
	mls	V2.8H, V18.8H, V0.H[0]
	sqdmulh	V17.8H, V3.8H, V0.H[2]
	sqdmulh	V18.8H, V4.8H, V0.H[2]
	sshr	V17.8H, V17.8H, #11
	sshr	V18.8H, V18.8H, #11
	mls	V3.8H, V17.8H, V0.H[0]
	mls	V4.8H, V18.8H, V0.H[0]
	sqdmulh	V17.8H, V5.8H, V0.H[2]
	sqdmulh	V18.8H, V6.8H, V0.H[2]
	sshr	V17.8H, V17.8H, #11
	sshr	V18.8H, V18.8H, #11
	mls	V5.8H, V17.8H, V0.H[0]
	mls	V6.8H, V18.8H, V0.H[0]
	sqdmulh	V17.8H, V7.8H, V0.H[2]
	sqdmulh	V18.8H, V8.8H, V0.H[2]
	sshr	V17.8H, V17.8H, #11
	sshr	V18.8H, V18.8H, #11
	mls	V7.8H, V17.8H, V0.H[0]
	mls	V8.8H, V18.8H, V0.H[0]
	st4	{V1.8H, V2.8H, V3.8H, V4.8H}, [x0], #0x40
	st4	{V5.8H, V6.8H, V7.8H, V8.8H}, [x0], #0x40
	ldp	D8, D9, [x29, #16]
	ldp	D10, D11, [x29, #32]
	ldp	D12, D13, [x29, #48]
	ldp	D14, D15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
	ENDP
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mlkem_add3_reduce
mlkem_add3_reduce PROC
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	stp	D10, D11, [x29, #32]
	stp	D12, D13, [x29, #48]
	stp	D14, D15, [x29, #64]
	adrp	x3, L_mlkem_aarch64_consts
	add	x3, x3, L_mlkem_aarch64_consts
	ldr	Q0, [x3]
	ld4	{V1.8H, V2.8H, V3.8H, V4.8H}, [x0], #0x40
	ld4	{V5.8H, V6.8H, V7.8H, V8.8H}, [x0], #0x40
	ld4	{V9.8H, V10.8H, V11.8H, V12.8H}, [x1], #0x40
	ld4	{V13.8H, V14.8H, V15.8H, V16.8H}, [x1], #0x40
	ld4	{V17.8H, V18.8H, V19.8H, V20.8H}, [x2], #0x40
	ld4	{V21.8H, V22.8H, V23.8H, V24.8H}, [x2], #0x40
	sub	x0, x0, #0x80
	add	V1.8H, V1.8H, V9.8H
	add	V2.8H, V2.8H, V10.8H
	add	V3.8H, V3.8H, V11.8H
	add	V4.8H, V4.8H, V12.8H
	add	V5.8H, V5.8H, V13.8H
	add	V6.8H, V6.8H, V14.8H
	add	V7.8H, V7.8H, V15.8H
	add	V8.8H, V8.8H, V16.8H
	add	V1.8H, V1.8H, V17.8H
	add	V2.8H, V2.8H, V18.8H
	add	V3.8H, V3.8H, V19.8H
	add	V4.8H, V4.8H, V20.8H
	add	V5.8H, V5.8H, V21.8H
	add	V6.8H, V6.8H, V22.8H
	add	V7.8H, V7.8H, V23.8H
	add	V8.8H, V8.8H, V24.8H
	sqdmulh	V25.8H, V1.8H, V0.H[2]
	sqdmulh	V26.8H, V2.8H, V0.H[2]
	sshr	V25.8H, V25.8H, #11
	sshr	V26.8H, V26.8H, #11
	mls	V1.8H, V25.8H, V0.H[0]
	mls	V2.8H, V26.8H, V0.H[0]
	sqdmulh	V25.8H, V3.8H, V0.H[2]
	sqdmulh	V26.8H, V4.8H, V0.H[2]
	sshr	V25.8H, V25.8H, #11
	sshr	V26.8H, V26.8H, #11
	mls	V3.8H, V25.8H, V0.H[0]
	mls	V4.8H, V26.8H, V0.H[0]
	sqdmulh	V25.8H, V5.8H, V0.H[2]
	sqdmulh	V26.8H, V6.8H, V0.H[2]
	sshr	V25.8H, V25.8H, #11
	sshr	V26.8H, V26.8H, #11
	mls	V5.8H, V25.8H, V0.H[0]
	mls	V6.8H, V26.8H, V0.H[0]
	sqdmulh	V25.8H, V7.8H, V0.H[2]
	sqdmulh	V26.8H, V8.8H, V0.H[2]
	sshr	V25.8H, V25.8H, #11
	sshr	V26.8H, V26.8H, #11
	mls	V7.8H, V25.8H, V0.H[0]
	mls	V8.8H, V26.8H, V0.H[0]
	st4	{V1.8H, V2.8H, V3.8H, V4.8H}, [x0], #0x40
	st4	{V5.8H, V6.8H, V7.8H, V8.8H}, [x0], #0x40
	ld4	{V1.8H, V2.8H, V3.8H, V4.8H}, [x0], #0x40
	ld4	{V5.8H, V6.8H, V7.8H, V8.8H}, [x0], #0x40
	ld4	{V9.8H, V10.8H, V11.8H, V12.8H}, [x1], #0x40
	ld4	{V13.8H, V14.8H, V15.8H, V16.8H}, [x1], #0x40
	ld4	{V17.8H, V18.8H, V19.8H, V20.8H}, [x2], #0x40
	ld4	{V21.8H, V22.8H, V23.8H, V24.8H}, [x2], #0x40
	sub	x0, x0, #0x80
	add	V1.8H, V1.8H, V9.8H
	add	V2.8H, V2.8H, V10.8H
	add	V3.8H, V3.8H, V11.8H
	add	V4.8H, V4.8H, V12.8H
	add	V5.8H, V5.8H, V13.8H
	add	V6.8H, V6.8H, V14.8H
	add	V7.8H, V7.8H, V15.8H
	add	V8.8H, V8.8H, V16.8H
	add	V1.8H, V1.8H, V17.8H
	add	V2.8H, V2.8H, V18.8H
	add	V3.8H, V3.8H, V19.8H
	add	V4.8H, V4.8H, V20.8H
	add	V5.8H, V5.8H, V21.8H
	add	V6.8H, V6.8H, V22.8H
	add	V7.8H, V7.8H, V23.8H
	add	V8.8H, V8.8H, V24.8H
	sqdmulh	V25.8H, V1.8H, V0.H[2]
	sqdmulh	V26.8H, V2.8H, V0.H[2]
	sshr	V25.8H, V25.8H, #11
	sshr	V26.8H, V26.8H, #11
	mls	V1.8H, V25.8H, V0.H[0]
	mls	V2.8H, V26.8H, V0.H[0]
	sqdmulh	V25.8H, V3.8H, V0.H[2]
	sqdmulh	V26.8H, V4.8H, V0.H[2]
	sshr	V25.8H, V25.8H, #11
	sshr	V26.8H, V26.8H, #11
	mls	V3.8H, V25.8H, V0.H[0]
	mls	V4.8H, V26.8H, V0.H[0]
	sqdmulh	V25.8H, V5.8H, V0.H[2]
	sqdmulh	V26.8H, V6.8H, V0.H[2]
	sshr	V25.8H, V25.8H, #11
	sshr	V26.8H, V26.8H, #11
	mls	V5.8H, V25.8H, V0.H[0]
	mls	V6.8H, V26.8H, V0.H[0]
	sqdmulh	V25.8H, V7.8H, V0.H[2]
	sqdmulh	V26.8H, V8.8H, V0.H[2]
	sshr	V25.8H, V25.8H, #11
	sshr	V26.8H, V26.8H, #11
	mls	V7.8H, V25.8H, V0.H[0]
	mls	V8.8H, V26.8H, V0.H[0]
	st4	{V1.8H, V2.8H, V3.8H, V4.8H}, [x0], #0x40
	st4	{V5.8H, V6.8H, V7.8H, V8.8H}, [x0], #0x40
	ld4	{V1.8H, V2.8H, V3.8H, V4.8H}, [x0], #0x40
	ld4	{V5.8H, V6.8H, V7.8H, V8.8H}, [x0], #0x40
	ld4	{V9.8H, V10.8H, V11.8H, V12.8H}, [x1], #0x40
	ld4	{V13.8H, V14.8H, V15.8H, V16.8H}, [x1], #0x40
	ld4	{V17.8H, V18.8H, V19.8H, V20.8H}, [x2], #0x40
	ld4	{V21.8H, V22.8H, V23.8H, V24.8H}, [x2], #0x40
	sub	x0, x0, #0x80
	add	V1.8H, V1.8H, V9.8H
	add	V2.8H, V2.8H, V10.8H
	add	V3.8H, V3.8H, V11.8H
	add	V4.8H, V4.8H, V12.8H
	add	V5.8H, V5.8H, V13.8H
	add	V6.8H, V6.8H, V14.8H
	add	V7.8H, V7.8H, V15.8H
	add	V8.8H, V8.8H, V16.8H
	add	V1.8H, V1.8H, V17.8H
	add	V2.8H, V2.8H, V18.8H
	add	V3.8H, V3.8H, V19.8H
	add	V4.8H, V4.8H, V20.8H
	add	V5.8H, V5.8H, V21.8H
	add	V6.8H, V6.8H, V22.8H
	add	V7.8H, V7.8H, V23.8H
	add	V8.8H, V8.8H, V24.8H
	sqdmulh	V25.8H, V1.8H, V0.H[2]
	sqdmulh	V26.8H, V2.8H, V0.H[2]
	sshr	V25.8H, V25.8H, #11
	sshr	V26.8H, V26.8H, #11
	mls	V1.8H, V25.8H, V0.H[0]
	mls	V2.8H, V26.8H, V0.H[0]
	sqdmulh	V25.8H, V3.8H, V0.H[2]
	sqdmulh	V26.8H, V4.8H, V0.H[2]
	sshr	V25.8H, V25.8H, #11
	sshr	V26.8H, V26.8H, #11
	mls	V3.8H, V25.8H, V0.H[0]
	mls	V4.8H, V26.8H, V0.H[0]
	sqdmulh	V25.8H, V5.8H, V0.H[2]
	sqdmulh	V26.8H, V6.8H, V0.H[2]
	sshr	V25.8H, V25.8H, #11
	sshr	V26.8H, V26.8H, #11
	mls	V5.8H, V25.8H, V0.H[0]
	mls	V6.8H, V26.8H, V0.H[0]
	sqdmulh	V25.8H, V7.8H, V0.H[2]
	sqdmulh	V26.8H, V8.8H, V0.H[2]
	sshr	V25.8H, V25.8H, #11
	sshr	V26.8H, V26.8H, #11
	mls	V7.8H, V25.8H, V0.H[0]
	mls	V8.8H, V26.8H, V0.H[0]
	st4	{V1.8H, V2.8H, V3.8H, V4.8H}, [x0], #0x40
	st4	{V5.8H, V6.8H, V7.8H, V8.8H}, [x0], #0x40
	ld4	{V1.8H, V2.8H, V3.8H, V4.8H}, [x0], #0x40
	ld4	{V5.8H, V6.8H, V7.8H, V8.8H}, [x0], #0x40
	ld4	{V9.8H, V10.8H, V11.8H, V12.8H}, [x1], #0x40
	ld4	{V13.8H, V14.8H, V15.8H, V16.8H}, [x1], #0x40
	ld4	{V17.8H, V18.8H, V19.8H, V20.8H}, [x2], #0x40
	ld4	{V21.8H, V22.8H, V23.8H, V24.8H}, [x2], #0x40
	sub	x0, x0, #0x80
	add	V1.8H, V1.8H, V9.8H
	add	V2.8H, V2.8H, V10.8H
	add	V3.8H, V3.8H, V11.8H
	add	V4.8H, V4.8H, V12.8H
	add	V5.8H, V5.8H, V13.8H
	add	V6.8H, V6.8H, V14.8H
	add	V7.8H, V7.8H, V15.8H
	add	V8.8H, V8.8H, V16.8H
	add	V1.8H, V1.8H, V17.8H
	add	V2.8H, V2.8H, V18.8H
	add	V3.8H, V3.8H, V19.8H
	add	V4.8H, V4.8H, V20.8H
	add	V5.8H, V5.8H, V21.8H
	add	V6.8H, V6.8H, V22.8H
	add	V7.8H, V7.8H, V23.8H
	add	V8.8H, V8.8H, V24.8H
	sqdmulh	V25.8H, V1.8H, V0.H[2]
	sqdmulh	V26.8H, V2.8H, V0.H[2]
	sshr	V25.8H, V25.8H, #11
	sshr	V26.8H, V26.8H, #11
	mls	V1.8H, V25.8H, V0.H[0]
	mls	V2.8H, V26.8H, V0.H[0]
	sqdmulh	V25.8H, V3.8H, V0.H[2]
	sqdmulh	V26.8H, V4.8H, V0.H[2]
	sshr	V25.8H, V25.8H, #11
	sshr	V26.8H, V26.8H, #11
	mls	V3.8H, V25.8H, V0.H[0]
	mls	V4.8H, V26.8H, V0.H[0]
	sqdmulh	V25.8H, V5.8H, V0.H[2]
	sqdmulh	V26.8H, V6.8H, V0.H[2]
	sshr	V25.8H, V25.8H, #11
	sshr	V26.8H, V26.8H, #11
	mls	V5.8H, V25.8H, V0.H[0]
	mls	V6.8H, V26.8H, V0.H[0]
	sqdmulh	V25.8H, V7.8H, V0.H[2]
	sqdmulh	V26.8H, V8.8H, V0.H[2]
	sshr	V25.8H, V25.8H, #11
	sshr	V26.8H, V26.8H, #11
	mls	V7.8H, V25.8H, V0.H[0]
	mls	V8.8H, V26.8H, V0.H[0]
	st4	{V1.8H, V2.8H, V3.8H, V4.8H}, [x0], #0x40
	st4	{V5.8H, V6.8H, V7.8H, V8.8H}, [x0], #0x40
	ldp	D8, D9, [x29, #16]
	ldp	D10, D11, [x29, #32]
	ldp	D12, D13, [x29, #48]
	ldp	D14, D15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
	ENDP
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mlkem_rsub_reduce
mlkem_rsub_reduce PROC
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	stp	D10, D11, [x29, #32]
	stp	D12, D13, [x29, #48]
	stp	D14, D15, [x29, #64]
	adrp	x2, L_mlkem_aarch64_consts
	add	x2, x2, L_mlkem_aarch64_consts
	ldr	Q0, [x2]
	ld4	{V1.8H, V2.8H, V3.8H, V4.8H}, [x0], #0x40
	ld4	{V5.8H, V6.8H, V7.8H, V8.8H}, [x0], #0x40
	ld4	{V9.8H, V10.8H, V11.8H, V12.8H}, [x1], #0x40
	ld4	{V13.8H, V14.8H, V15.8H, V16.8H}, [x1], #0x40
	sub	x0, x0, #0x80
	sub	V1.8H, V9.8H, V1.8H
	sub	V2.8H, V10.8H, V2.8H
	sub	V3.8H, V11.8H, V3.8H
	sub	V4.8H, V12.8H, V4.8H
	sub	V5.8H, V13.8H, V5.8H
	sub	V6.8H, V14.8H, V6.8H
	sub	V7.8H, V15.8H, V7.8H
	sub	V8.8H, V16.8H, V8.8H
	sqdmulh	V17.8H, V1.8H, V0.H[2]
	sqdmulh	V18.8H, V2.8H, V0.H[2]
	sshr	V17.8H, V17.8H, #11
	sshr	V18.8H, V18.8H, #11
	mls	V1.8H, V17.8H, V0.H[0]
	mls	V2.8H, V18.8H, V0.H[0]
	sqdmulh	V17.8H, V3.8H, V0.H[2]
	sqdmulh	V18.8H, V4.8H, V0.H[2]
	sshr	V17.8H, V17.8H, #11
	sshr	V18.8H, V18.8H, #11
	mls	V3.8H, V17.8H, V0.H[0]
	mls	V4.8H, V18.8H, V0.H[0]
	sqdmulh	V17.8H, V5.8H, V0.H[2]
	sqdmulh	V18.8H, V6.8H, V0.H[2]
	sshr	V17.8H, V17.8H, #11
	sshr	V18.8H, V18.8H, #11
	mls	V5.8H, V17.8H, V0.H[0]
	mls	V6.8H, V18.8H, V0.H[0]
	sqdmulh	V17.8H, V7.8H, V0.H[2]
	sqdmulh	V18.8H, V8.8H, V0.H[2]
	sshr	V17.8H, V17.8H, #11
	sshr	V18.8H, V18.8H, #11
	mls	V7.8H, V17.8H, V0.H[0]
	mls	V8.8H, V18.8H, V0.H[0]
	st4	{V1.8H, V2.8H, V3.8H, V4.8H}, [x0], #0x40
	st4	{V5.8H, V6.8H, V7.8H, V8.8H}, [x0], #0x40
	ld4	{V1.8H, V2.8H, V3.8H, V4.8H}, [x0], #0x40
	ld4	{V5.8H, V6.8H, V7.8H, V8.8H}, [x0], #0x40
	ld4	{V9.8H, V10.8H, V11.8H, V12.8H}, [x1], #0x40
	ld4	{V13.8H, V14.8H, V15.8H, V16.8H}, [x1], #0x40
	sub	x0, x0, #0x80
	sub	V1.8H, V9.8H, V1.8H
	sub	V2.8H, V10.8H, V2.8H
	sub	V3.8H, V11.8H, V3.8H
	sub	V4.8H, V12.8H, V4.8H
	sub	V5.8H, V13.8H, V5.8H
	sub	V6.8H, V14.8H, V6.8H
	sub	V7.8H, V15.8H, V7.8H
	sub	V8.8H, V16.8H, V8.8H
	sqdmulh	V17.8H, V1.8H, V0.H[2]
	sqdmulh	V18.8H, V2.8H, V0.H[2]
	sshr	V17.8H, V17.8H, #11
	sshr	V18.8H, V18.8H, #11
	mls	V1.8H, V17.8H, V0.H[0]
	mls	V2.8H, V18.8H, V0.H[0]
	sqdmulh	V17.8H, V3.8H, V0.H[2]
	sqdmulh	V18.8H, V4.8H, V0.H[2]
	sshr	V17.8H, V17.8H, #11
	sshr	V18.8H, V18.8H, #11
	mls	V3.8H, V17.8H, V0.H[0]
	mls	V4.8H, V18.8H, V0.H[0]
	sqdmulh	V17.8H, V5.8H, V0.H[2]
	sqdmulh	V18.8H, V6.8H, V0.H[2]
	sshr	V17.8H, V17.8H, #11
	sshr	V18.8H, V18.8H, #11
	mls	V5.8H, V17.8H, V0.H[0]
	mls	V6.8H, V18.8H, V0.H[0]
	sqdmulh	V17.8H, V7.8H, V0.H[2]
	sqdmulh	V18.8H, V8.8H, V0.H[2]
	sshr	V17.8H, V17.8H, #11
	sshr	V18.8H, V18.8H, #11
	mls	V7.8H, V17.8H, V0.H[0]
	mls	V8.8H, V18.8H, V0.H[0]
	st4	{V1.8H, V2.8H, V3.8H, V4.8H}, [x0], #0x40
	st4	{V5.8H, V6.8H, V7.8H, V8.8H}, [x0], #0x40
	ld4	{V1.8H, V2.8H, V3.8H, V4.8H}, [x0], #0x40
	ld4	{V5.8H, V6.8H, V7.8H, V8.8H}, [x0], #0x40
	ld4	{V9.8H, V10.8H, V11.8H, V12.8H}, [x1], #0x40
	ld4	{V13.8H, V14.8H, V15.8H, V16.8H}, [x1], #0x40
	sub	x0, x0, #0x80
	sub	V1.8H, V9.8H, V1.8H
	sub	V2.8H, V10.8H, V2.8H
	sub	V3.8H, V11.8H, V3.8H
	sub	V4.8H, V12.8H, V4.8H
	sub	V5.8H, V13.8H, V5.8H
	sub	V6.8H, V14.8H, V6.8H
	sub	V7.8H, V15.8H, V7.8H
	sub	V8.8H, V16.8H, V8.8H
	sqdmulh	V17.8H, V1.8H, V0.H[2]
	sqdmulh	V18.8H, V2.8H, V0.H[2]
	sshr	V17.8H, V17.8H, #11
	sshr	V18.8H, V18.8H, #11
	mls	V1.8H, V17.8H, V0.H[0]
	mls	V2.8H, V18.8H, V0.H[0]
	sqdmulh	V17.8H, V3.8H, V0.H[2]
	sqdmulh	V18.8H, V4.8H, V0.H[2]
	sshr	V17.8H, V17.8H, #11
	sshr	V18.8H, V18.8H, #11
	mls	V3.8H, V17.8H, V0.H[0]
	mls	V4.8H, V18.8H, V0.H[0]
	sqdmulh	V17.8H, V5.8H, V0.H[2]
	sqdmulh	V18.8H, V6.8H, V0.H[2]
	sshr	V17.8H, V17.8H, #11
	sshr	V18.8H, V18.8H, #11
	mls	V5.8H, V17.8H, V0.H[0]
	mls	V6.8H, V18.8H, V0.H[0]
	sqdmulh	V17.8H, V7.8H, V0.H[2]
	sqdmulh	V18.8H, V8.8H, V0.H[2]
	sshr	V17.8H, V17.8H, #11
	sshr	V18.8H, V18.8H, #11
	mls	V7.8H, V17.8H, V0.H[0]
	mls	V8.8H, V18.8H, V0.H[0]
	st4	{V1.8H, V2.8H, V3.8H, V4.8H}, [x0], #0x40
	st4	{V5.8H, V6.8H, V7.8H, V8.8H}, [x0], #0x40
	ld4	{V1.8H, V2.8H, V3.8H, V4.8H}, [x0], #0x40
	ld4	{V5.8H, V6.8H, V7.8H, V8.8H}, [x0], #0x40
	ld4	{V9.8H, V10.8H, V11.8H, V12.8H}, [x1], #0x40
	ld4	{V13.8H, V14.8H, V15.8H, V16.8H}, [x1], #0x40
	sub	x0, x0, #0x80
	sub	V1.8H, V9.8H, V1.8H
	sub	V2.8H, V10.8H, V2.8H
	sub	V3.8H, V11.8H, V3.8H
	sub	V4.8H, V12.8H, V4.8H
	sub	V5.8H, V13.8H, V5.8H
	sub	V6.8H, V14.8H, V6.8H
	sub	V7.8H, V15.8H, V7.8H
	sub	V8.8H, V16.8H, V8.8H
	sqdmulh	V17.8H, V1.8H, V0.H[2]
	sqdmulh	V18.8H, V2.8H, V0.H[2]
	sshr	V17.8H, V17.8H, #11
	sshr	V18.8H, V18.8H, #11
	mls	V1.8H, V17.8H, V0.H[0]
	mls	V2.8H, V18.8H, V0.H[0]
	sqdmulh	V17.8H, V3.8H, V0.H[2]
	sqdmulh	V18.8H, V4.8H, V0.H[2]
	sshr	V17.8H, V17.8H, #11
	sshr	V18.8H, V18.8H, #11
	mls	V3.8H, V17.8H, V0.H[0]
	mls	V4.8H, V18.8H, V0.H[0]
	sqdmulh	V17.8H, V5.8H, V0.H[2]
	sqdmulh	V18.8H, V6.8H, V0.H[2]
	sshr	V17.8H, V17.8H, #11
	sshr	V18.8H, V18.8H, #11
	mls	V5.8H, V17.8H, V0.H[0]
	mls	V6.8H, V18.8H, V0.H[0]
	sqdmulh	V17.8H, V7.8H, V0.H[2]
	sqdmulh	V18.8H, V8.8H, V0.H[2]
	sshr	V17.8H, V17.8H, #11
	sshr	V18.8H, V18.8H, #11
	mls	V7.8H, V17.8H, V0.H[0]
	mls	V8.8H, V18.8H, V0.H[0]
	st4	{V1.8H, V2.8H, V3.8H, V4.8H}, [x0], #0x40
	st4	{V5.8H, V6.8H, V7.8H, V8.8H}, [x0], #0x40
	ldp	D8, D9, [x29, #16]
	ldp	D10, D11, [x29, #32]
	ldp	D12, D13, [x29, #48]
	ldp	D14, D15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
	ENDP
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mlkem_to_mont
mlkem_to_mont PROC
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	stp	D10, D11, [x29, #32]
	stp	D12, D13, [x29, #48]
	stp	D14, D15, [x29, #64]
	adrp	x1, L_mlkem_aarch64_consts
	add	x1, x1, L_mlkem_aarch64_consts
	ldr	Q0, [x1]
	ld4	{V1.8H, V2.8H, V3.8H, V4.8H}, [x0], #0x40
	ld4	{V5.8H, V6.8H, V7.8H, V8.8H}, [x0], #0x40
	ld4	{V9.8H, V10.8H, V11.8H, V12.8H}, [x0], #0x40
	ld4	{V13.8H, V14.8H, V15.8H, V16.8H}, [x0], #0x40
	sub	x0, x0, #0x100
	mul	V17.8H, V1.8H, V0.H[4]
	mul	V18.8H, V2.8H, V0.H[4]
	sqrdmulh	V1.8H, V1.8H, V0.H[3]
	sqrdmulh	V2.8H, V2.8H, V0.H[3]
	sqrdmulh	V17.8H, V17.8H, V0.H[0]
	sqrdmulh	V18.8H, V18.8H, V0.H[0]
	sub	V1.8H, V1.8H, V17.8H
	sub	V2.8H, V2.8H, V18.8H
	sshr	V1.8H, V1.8H, #1
	sshr	V2.8H, V2.8H, #1
	mul	V17.8H, V3.8H, V0.H[4]
	mul	V18.8H, V4.8H, V0.H[4]
	sqrdmulh	V3.8H, V3.8H, V0.H[3]
	sqrdmulh	V4.8H, V4.8H, V0.H[3]
	sqrdmulh	V17.8H, V17.8H, V0.H[0]
	sqrdmulh	V18.8H, V18.8H, V0.H[0]
	sub	V3.8H, V3.8H, V17.8H
	sub	V4.8H, V4.8H, V18.8H
	sshr	V3.8H, V3.8H, #1
	sshr	V4.8H, V4.8H, #1
	mul	V17.8H, V5.8H, V0.H[4]
	mul	V18.8H, V6.8H, V0.H[4]
	sqrdmulh	V5.8H, V5.8H, V0.H[3]
	sqrdmulh	V6.8H, V6.8H, V0.H[3]
	sqrdmulh	V17.8H, V17.8H, V0.H[0]
	sqrdmulh	V18.8H, V18.8H, V0.H[0]
	sub	V5.8H, V5.8H, V17.8H
	sub	V6.8H, V6.8H, V18.8H
	sshr	V5.8H, V5.8H, #1
	sshr	V6.8H, V6.8H, #1
	mul	V17.8H, V7.8H, V0.H[4]
	mul	V18.8H, V8.8H, V0.H[4]
	sqrdmulh	V7.8H, V7.8H, V0.H[3]
	sqrdmulh	V8.8H, V8.8H, V0.H[3]
	sqrdmulh	V17.8H, V17.8H, V0.H[0]
	sqrdmulh	V18.8H, V18.8H, V0.H[0]
	sub	V7.8H, V7.8H, V17.8H
	sub	V8.8H, V8.8H, V18.8H
	sshr	V7.8H, V7.8H, #1
	sshr	V8.8H, V8.8H, #1
	mul	V17.8H, V9.8H, V0.H[4]
	mul	V18.8H, V10.8H, V0.H[4]
	sqrdmulh	V9.8H, V9.8H, V0.H[3]
	sqrdmulh	V10.8H, V10.8H, V0.H[3]
	sqrdmulh	V17.8H, V17.8H, V0.H[0]
	sqrdmulh	V18.8H, V18.8H, V0.H[0]
	sub	V9.8H, V9.8H, V17.8H
	sub	V10.8H, V10.8H, V18.8H
	sshr	V9.8H, V9.8H, #1
	sshr	V10.8H, V10.8H, #1
	mul	V17.8H, V11.8H, V0.H[4]
	mul	V18.8H, V12.8H, V0.H[4]
	sqrdmulh	V11.8H, V11.8H, V0.H[3]
	sqrdmulh	V12.8H, V12.8H, V0.H[3]
	sqrdmulh	V17.8H, V17.8H, V0.H[0]
	sqrdmulh	V18.8H, V18.8H, V0.H[0]
	sub	V11.8H, V11.8H, V17.8H
	sub	V12.8H, V12.8H, V18.8H
	sshr	V11.8H, V11.8H, #1
	sshr	V12.8H, V12.8H, #1
	mul	V17.8H, V13.8H, V0.H[4]
	mul	V18.8H, V14.8H, V0.H[4]
	sqrdmulh	V13.8H, V13.8H, V0.H[3]
	sqrdmulh	V14.8H, V14.8H, V0.H[3]
	sqrdmulh	V17.8H, V17.8H, V0.H[0]
	sqrdmulh	V18.8H, V18.8H, V0.H[0]
	sub	V13.8H, V13.8H, V17.8H
	sub	V14.8H, V14.8H, V18.8H
	sshr	V13.8H, V13.8H, #1
	sshr	V14.8H, V14.8H, #1
	mul	V17.8H, V15.8H, V0.H[4]
	mul	V18.8H, V16.8H, V0.H[4]
	sqrdmulh	V15.8H, V15.8H, V0.H[3]
	sqrdmulh	V16.8H, V16.8H, V0.H[3]
	sqrdmulh	V17.8H, V17.8H, V0.H[0]
	sqrdmulh	V18.8H, V18.8H, V0.H[0]
	sub	V15.8H, V15.8H, V17.8H
	sub	V16.8H, V16.8H, V18.8H
	sshr	V15.8H, V15.8H, #1
	sshr	V16.8H, V16.8H, #1
	st4	{V1.8H, V2.8H, V3.8H, V4.8H}, [x0], #0x40
	st4	{V5.8H, V6.8H, V7.8H, V8.8H}, [x0], #0x40
	st4	{V9.8H, V10.8H, V11.8H, V12.8H}, [x0], #0x40
	st4	{V13.8H, V14.8H, V15.8H, V16.8H}, [x0], #0x40
	ld4	{V1.8H, V2.8H, V3.8H, V4.8H}, [x0], #0x40
	ld4	{V5.8H, V6.8H, V7.8H, V8.8H}, [x0], #0x40
	ld4	{V9.8H, V10.8H, V11.8H, V12.8H}, [x0], #0x40
	ld4	{V13.8H, V14.8H, V15.8H, V16.8H}, [x0], #0x40
	sub	x0, x0, #0x100
	mul	V17.8H, V1.8H, V0.H[4]
	mul	V18.8H, V2.8H, V0.H[4]
	sqrdmulh	V1.8H, V1.8H, V0.H[3]
	sqrdmulh	V2.8H, V2.8H, V0.H[3]
	sqrdmulh	V17.8H, V17.8H, V0.H[0]
	sqrdmulh	V18.8H, V18.8H, V0.H[0]
	sub	V1.8H, V1.8H, V17.8H
	sub	V2.8H, V2.8H, V18.8H
	sshr	V1.8H, V1.8H, #1
	sshr	V2.8H, V2.8H, #1
	mul	V17.8H, V3.8H, V0.H[4]
	mul	V18.8H, V4.8H, V0.H[4]
	sqrdmulh	V3.8H, V3.8H, V0.H[3]
	sqrdmulh	V4.8H, V4.8H, V0.H[3]
	sqrdmulh	V17.8H, V17.8H, V0.H[0]
	sqrdmulh	V18.8H, V18.8H, V0.H[0]
	sub	V3.8H, V3.8H, V17.8H
	sub	V4.8H, V4.8H, V18.8H
	sshr	V3.8H, V3.8H, #1
	sshr	V4.8H, V4.8H, #1
	mul	V17.8H, V5.8H, V0.H[4]
	mul	V18.8H, V6.8H, V0.H[4]
	sqrdmulh	V5.8H, V5.8H, V0.H[3]
	sqrdmulh	V6.8H, V6.8H, V0.H[3]
	sqrdmulh	V17.8H, V17.8H, V0.H[0]
	sqrdmulh	V18.8H, V18.8H, V0.H[0]
	sub	V5.8H, V5.8H, V17.8H
	sub	V6.8H, V6.8H, V18.8H
	sshr	V5.8H, V5.8H, #1
	sshr	V6.8H, V6.8H, #1
	mul	V17.8H, V7.8H, V0.H[4]
	mul	V18.8H, V8.8H, V0.H[4]
	sqrdmulh	V7.8H, V7.8H, V0.H[3]
	sqrdmulh	V8.8H, V8.8H, V0.H[3]
	sqrdmulh	V17.8H, V17.8H, V0.H[0]
	sqrdmulh	V18.8H, V18.8H, V0.H[0]
	sub	V7.8H, V7.8H, V17.8H
	sub	V8.8H, V8.8H, V18.8H
	sshr	V7.8H, V7.8H, #1
	sshr	V8.8H, V8.8H, #1
	mul	V17.8H, V9.8H, V0.H[4]
	mul	V18.8H, V10.8H, V0.H[4]
	sqrdmulh	V9.8H, V9.8H, V0.H[3]
	sqrdmulh	V10.8H, V10.8H, V0.H[3]
	sqrdmulh	V17.8H, V17.8H, V0.H[0]
	sqrdmulh	V18.8H, V18.8H, V0.H[0]
	sub	V9.8H, V9.8H, V17.8H
	sub	V10.8H, V10.8H, V18.8H
	sshr	V9.8H, V9.8H, #1
	sshr	V10.8H, V10.8H, #1
	mul	V17.8H, V11.8H, V0.H[4]
	mul	V18.8H, V12.8H, V0.H[4]
	sqrdmulh	V11.8H, V11.8H, V0.H[3]
	sqrdmulh	V12.8H, V12.8H, V0.H[3]
	sqrdmulh	V17.8H, V17.8H, V0.H[0]
	sqrdmulh	V18.8H, V18.8H, V0.H[0]
	sub	V11.8H, V11.8H, V17.8H
	sub	V12.8H, V12.8H, V18.8H
	sshr	V11.8H, V11.8H, #1
	sshr	V12.8H, V12.8H, #1
	mul	V17.8H, V13.8H, V0.H[4]
	mul	V18.8H, V14.8H, V0.H[4]
	sqrdmulh	V13.8H, V13.8H, V0.H[3]
	sqrdmulh	V14.8H, V14.8H, V0.H[3]
	sqrdmulh	V17.8H, V17.8H, V0.H[0]
	sqrdmulh	V18.8H, V18.8H, V0.H[0]
	sub	V13.8H, V13.8H, V17.8H
	sub	V14.8H, V14.8H, V18.8H
	sshr	V13.8H, V13.8H, #1
	sshr	V14.8H, V14.8H, #1
	mul	V17.8H, V15.8H, V0.H[4]
	mul	V18.8H, V16.8H, V0.H[4]
	sqrdmulh	V15.8H, V15.8H, V0.H[3]
	sqrdmulh	V16.8H, V16.8H, V0.H[3]
	sqrdmulh	V17.8H, V17.8H, V0.H[0]
	sqrdmulh	V18.8H, V18.8H, V0.H[0]
	sub	V15.8H, V15.8H, V17.8H
	sub	V16.8H, V16.8H, V18.8H
	sshr	V15.8H, V15.8H, #1
	sshr	V16.8H, V16.8H, #1
	st4	{V1.8H, V2.8H, V3.8H, V4.8H}, [x0], #0x40
	st4	{V5.8H, V6.8H, V7.8H, V8.8H}, [x0], #0x40
	st4	{V9.8H, V10.8H, V11.8H, V12.8H}, [x0], #0x40
	st4	{V13.8H, V14.8H, V15.8H, V16.8H}, [x0], #0x40
	ldp	D8, D9, [x29, #16]
	ldp	D10, D11, [x29, #32]
	ldp	D12, D13, [x29, #48]
	ldp	D14, D15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
	ENDP
	IF :LNOT::DEF:WOLFSSL_AARCH64_NO_SQRDMLSH
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mlkem_to_mont_sqrdmlsh
mlkem_to_mont_sqrdmlsh PROC
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	stp	D10, D11, [x29, #32]
	stp	D12, D13, [x29, #48]
	stp	D14, D15, [x29, #64]
	adrp	x1, L_mlkem_aarch64_consts
	add	x1, x1, L_mlkem_aarch64_consts
	ldr	Q0, [x1]
	ld4	{V1.8H, V2.8H, V3.8H, V4.8H}, [x0], #0x40
	ld4	{V5.8H, V6.8H, V7.8H, V8.8H}, [x0], #0x40
	ld4	{V9.8H, V10.8H, V11.8H, V12.8H}, [x0], #0x40
	ld4	{V13.8H, V14.8H, V15.8H, V16.8H}, [x0], #0x40
	sub	x0, x0, #0x100
	mul	V17.8H, V1.8H, V0.H[4]
	mul	V18.8H, V2.8H, V0.H[4]
	sqrdmulh	V1.8H, V1.8H, V0.H[3]
	sqrdmulh	V2.8H, V2.8H, V0.H[3]
	sqrdmlsh	V1.8H, V17.8H, V0.H[0]
	sqrdmlsh	V2.8H, V18.8H, V0.H[0]
	sshr	V1.8H, V1.8H, #1
	sshr	V2.8H, V2.8H, #1
	mul	V17.8H, V3.8H, V0.H[4]
	mul	V18.8H, V4.8H, V0.H[4]
	sqrdmulh	V3.8H, V3.8H, V0.H[3]
	sqrdmulh	V4.8H, V4.8H, V0.H[3]
	sqrdmlsh	V3.8H, V17.8H, V0.H[0]
	sqrdmlsh	V4.8H, V18.8H, V0.H[0]
	sshr	V3.8H, V3.8H, #1
	sshr	V4.8H, V4.8H, #1
	mul	V17.8H, V5.8H, V0.H[4]
	mul	V18.8H, V6.8H, V0.H[4]
	sqrdmulh	V5.8H, V5.8H, V0.H[3]
	sqrdmulh	V6.8H, V6.8H, V0.H[3]
	sqrdmlsh	V5.8H, V17.8H, V0.H[0]
	sqrdmlsh	V6.8H, V18.8H, V0.H[0]
	sshr	V5.8H, V5.8H, #1
	sshr	V6.8H, V6.8H, #1
	mul	V17.8H, V7.8H, V0.H[4]
	mul	V18.8H, V8.8H, V0.H[4]
	sqrdmulh	V7.8H, V7.8H, V0.H[3]
	sqrdmulh	V8.8H, V8.8H, V0.H[3]
	sqrdmlsh	V7.8H, V17.8H, V0.H[0]
	sqrdmlsh	V8.8H, V18.8H, V0.H[0]
	sshr	V7.8H, V7.8H, #1
	sshr	V8.8H, V8.8H, #1
	mul	V17.8H, V9.8H, V0.H[4]
	mul	V18.8H, V10.8H, V0.H[4]
	sqrdmulh	V9.8H, V9.8H, V0.H[3]
	sqrdmulh	V10.8H, V10.8H, V0.H[3]
	sqrdmlsh	V9.8H, V17.8H, V0.H[0]
	sqrdmlsh	V10.8H, V18.8H, V0.H[0]
	sshr	V9.8H, V9.8H, #1
	sshr	V10.8H, V10.8H, #1
	mul	V17.8H, V11.8H, V0.H[4]
	mul	V18.8H, V12.8H, V0.H[4]
	sqrdmulh	V11.8H, V11.8H, V0.H[3]
	sqrdmulh	V12.8H, V12.8H, V0.H[3]
	sqrdmlsh	V11.8H, V17.8H, V0.H[0]
	sqrdmlsh	V12.8H, V18.8H, V0.H[0]
	sshr	V11.8H, V11.8H, #1
	sshr	V12.8H, V12.8H, #1
	mul	V17.8H, V13.8H, V0.H[4]
	mul	V18.8H, V14.8H, V0.H[4]
	sqrdmulh	V13.8H, V13.8H, V0.H[3]
	sqrdmulh	V14.8H, V14.8H, V0.H[3]
	sqrdmlsh	V13.8H, V17.8H, V0.H[0]
	sqrdmlsh	V14.8H, V18.8H, V0.H[0]
	sshr	V13.8H, V13.8H, #1
	sshr	V14.8H, V14.8H, #1
	mul	V17.8H, V15.8H, V0.H[4]
	mul	V18.8H, V16.8H, V0.H[4]
	sqrdmulh	V15.8H, V15.8H, V0.H[3]
	sqrdmulh	V16.8H, V16.8H, V0.H[3]
	sqrdmlsh	V15.8H, V17.8H, V0.H[0]
	sqrdmlsh	V16.8H, V18.8H, V0.H[0]
	sshr	V15.8H, V15.8H, #1
	sshr	V16.8H, V16.8H, #1
	st4	{V1.8H, V2.8H, V3.8H, V4.8H}, [x0], #0x40
	st4	{V5.8H, V6.8H, V7.8H, V8.8H}, [x0], #0x40
	st4	{V9.8H, V10.8H, V11.8H, V12.8H}, [x0], #0x40
	st4	{V13.8H, V14.8H, V15.8H, V16.8H}, [x0], #0x40
	ld4	{V1.8H, V2.8H, V3.8H, V4.8H}, [x0], #0x40
	ld4	{V5.8H, V6.8H, V7.8H, V8.8H}, [x0], #0x40
	ld4	{V9.8H, V10.8H, V11.8H, V12.8H}, [x0], #0x40
	ld4	{V13.8H, V14.8H, V15.8H, V16.8H}, [x0], #0x40
	sub	x0, x0, #0x100
	mul	V17.8H, V1.8H, V0.H[4]
	mul	V18.8H, V2.8H, V0.H[4]
	sqrdmulh	V1.8H, V1.8H, V0.H[3]
	sqrdmulh	V2.8H, V2.8H, V0.H[3]
	sqrdmlsh	V1.8H, V17.8H, V0.H[0]
	sqrdmlsh	V2.8H, V18.8H, V0.H[0]
	sshr	V1.8H, V1.8H, #1
	sshr	V2.8H, V2.8H, #1
	mul	V17.8H, V3.8H, V0.H[4]
	mul	V18.8H, V4.8H, V0.H[4]
	sqrdmulh	V3.8H, V3.8H, V0.H[3]
	sqrdmulh	V4.8H, V4.8H, V0.H[3]
	sqrdmlsh	V3.8H, V17.8H, V0.H[0]
	sqrdmlsh	V4.8H, V18.8H, V0.H[0]
	sshr	V3.8H, V3.8H, #1
	sshr	V4.8H, V4.8H, #1
	mul	V17.8H, V5.8H, V0.H[4]
	mul	V18.8H, V6.8H, V0.H[4]
	sqrdmulh	V5.8H, V5.8H, V0.H[3]
	sqrdmulh	V6.8H, V6.8H, V0.H[3]
	sqrdmlsh	V5.8H, V17.8H, V0.H[0]
	sqrdmlsh	V6.8H, V18.8H, V0.H[0]
	sshr	V5.8H, V5.8H, #1
	sshr	V6.8H, V6.8H, #1
	mul	V17.8H, V7.8H, V0.H[4]
	mul	V18.8H, V8.8H, V0.H[4]
	sqrdmulh	V7.8H, V7.8H, V0.H[3]
	sqrdmulh	V8.8H, V8.8H, V0.H[3]
	sqrdmlsh	V7.8H, V17.8H, V0.H[0]
	sqrdmlsh	V8.8H, V18.8H, V0.H[0]
	sshr	V7.8H, V7.8H, #1
	sshr	V8.8H, V8.8H, #1
	mul	V17.8H, V9.8H, V0.H[4]
	mul	V18.8H, V10.8H, V0.H[4]
	sqrdmulh	V9.8H, V9.8H, V0.H[3]
	sqrdmulh	V10.8H, V10.8H, V0.H[3]
	sqrdmlsh	V9.8H, V17.8H, V0.H[0]
	sqrdmlsh	V10.8H, V18.8H, V0.H[0]
	sshr	V9.8H, V9.8H, #1
	sshr	V10.8H, V10.8H, #1
	mul	V17.8H, V11.8H, V0.H[4]
	mul	V18.8H, V12.8H, V0.H[4]
	sqrdmulh	V11.8H, V11.8H, V0.H[3]
	sqrdmulh	V12.8H, V12.8H, V0.H[3]
	sqrdmlsh	V11.8H, V17.8H, V0.H[0]
	sqrdmlsh	V12.8H, V18.8H, V0.H[0]
	sshr	V11.8H, V11.8H, #1
	sshr	V12.8H, V12.8H, #1
	mul	V17.8H, V13.8H, V0.H[4]
	mul	V18.8H, V14.8H, V0.H[4]
	sqrdmulh	V13.8H, V13.8H, V0.H[3]
	sqrdmulh	V14.8H, V14.8H, V0.H[3]
	sqrdmlsh	V13.8H, V17.8H, V0.H[0]
	sqrdmlsh	V14.8H, V18.8H, V0.H[0]
	sshr	V13.8H, V13.8H, #1
	sshr	V14.8H, V14.8H, #1
	mul	V17.8H, V15.8H, V0.H[4]
	mul	V18.8H, V16.8H, V0.H[4]
	sqrdmulh	V15.8H, V15.8H, V0.H[3]
	sqrdmulh	V16.8H, V16.8H, V0.H[3]
	sqrdmlsh	V15.8H, V17.8H, V0.H[0]
	sqrdmlsh	V16.8H, V18.8H, V0.H[0]
	sshr	V15.8H, V15.8H, #1
	sshr	V16.8H, V16.8H, #1
	st4	{V1.8H, V2.8H, V3.8H, V4.8H}, [x0], #0x40
	st4	{V5.8H, V6.8H, V7.8H, V8.8H}, [x0], #0x40
	st4	{V9.8H, V10.8H, V11.8H, V12.8H}, [x0], #0x40
	st4	{V13.8H, V14.8H, V15.8H, V16.8H}, [x0], #0x40
	ldp	D8, D9, [x29, #16]
	ldp	D10, D11, [x29, #32]
	ldp	D12, D13, [x29, #48]
	ldp	D14, D15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
	ENDP
	ENDIF
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mlkem_to_msg_low
	DCW	0x0373, 0x0373, 0x0373, 0x0373, 0x0373, 0x0373, 0x0373, 0x0373
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mlkem_to_msg_high
	DCW	0x09c0, 0x09c0, 0x09c0, 0x09c0, 0x09c0, 0x09c0, 0x09c0, 0x09c0
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mlkem_to_msg_bits
	DCW	0x0001, 0x0002, 0x0004, 0x0008, 0x0010, 0x0020, 0x0040, 0x0080
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mlkem_to_msg_neon
mlkem_to_msg_neon PROC
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	stp	D10, D11, [x29, #32]
	stp	D12, D13, [x29, #48]
	stp	D14, D15, [x29, #64]
	adrp	x2, L_mlkem_to_msg_low
	add	x2, x2, L_mlkem_to_msg_low
	adrp	x3, L_mlkem_to_msg_high
	add	x3, x3, L_mlkem_to_msg_high
	adrp	x4, L_mlkem_to_msg_bits
	add	x4, x4, L_mlkem_to_msg_bits
	ldr	Q0, [x2]
	ldr	Q1, [x3]
	ldr	Q26, [x4]
	ld1	{V2.8H, V3.8H, V4.8H, V5.8H}, [x1], #0x40
	ld1	{V6.8H, V7.8H, V8.8H, V9.8H}, [x1], #0x40
	cmge	V10.8H, V2.8H, V0.8H
	cmge	V18.8H, V1.8H, V2.8H
	cmge	V11.8H, V3.8H, V0.8H
	cmge	V19.8H, V1.8H, V3.8H
	cmge	V12.8H, V4.8H, V0.8H
	cmge	V20.8H, V1.8H, V4.8H
	cmge	V13.8H, V5.8H, V0.8H
	cmge	V21.8H, V1.8H, V5.8H
	cmge	V14.8H, V6.8H, V0.8H
	cmge	V22.8H, V1.8H, V6.8H
	cmge	V15.8H, V7.8H, V0.8H
	cmge	V23.8H, V1.8H, V7.8H
	cmge	V16.8H, V8.8H, V0.8H
	cmge	V24.8H, V1.8H, V8.8H
	cmge	V17.8H, V9.8H, V0.8H
	cmge	V25.8H, V1.8H, V9.8H
	and	V18.16B, V18.16B, V10.16B
	and	V19.16B, V19.16B, V11.16B
	and	V20.16B, V20.16B, V12.16B
	and	V21.16B, V21.16B, V13.16B
	and	V22.16B, V22.16B, V14.16B
	and	V23.16B, V23.16B, V15.16B
	and	V24.16B, V24.16B, V16.16B
	and	V25.16B, V25.16B, V17.16B
	and	V18.16B, V18.16B, V26.16B
	and	V19.16B, V19.16B, V26.16B
	and	V20.16B, V20.16B, V26.16B
	and	V21.16B, V21.16B, V26.16B
	and	V22.16B, V22.16B, V26.16B
	and	V23.16B, V23.16B, V26.16B
	and	V24.16B, V24.16B, V26.16B
	and	V25.16B, V25.16B, V26.16B
	addv	H18, V18.8H
	addv	H19, V19.8H
	addv	H20, V20.8H
	addv	H21, V21.8H
	addv	H22, V22.8H
	addv	H23, V23.8H
	addv	H24, V24.8H
	addv	H25, V25.8H
	ins	V18.B[1], V19.B[0]
	ins	V18.B[2], V20.B[0]
	ins	V18.B[3], V21.B[0]
	ins	V18.B[4], V22.B[0]
	ins	V18.B[5], V23.B[0]
	ins	V18.B[6], V24.B[0]
	ins	V18.B[7], V25.B[0]
	st1	{V18.8B}, [x0], #8
	ld1	{V2.8H, V3.8H, V4.8H, V5.8H}, [x1], #0x40
	ld1	{V6.8H, V7.8H, V8.8H, V9.8H}, [x1], #0x40
	cmge	V10.8H, V2.8H, V0.8H
	cmge	V18.8H, V1.8H, V2.8H
	cmge	V11.8H, V3.8H, V0.8H
	cmge	V19.8H, V1.8H, V3.8H
	cmge	V12.8H, V4.8H, V0.8H
	cmge	V20.8H, V1.8H, V4.8H
	cmge	V13.8H, V5.8H, V0.8H
	cmge	V21.8H, V1.8H, V5.8H
	cmge	V14.8H, V6.8H, V0.8H
	cmge	V22.8H, V1.8H, V6.8H
	cmge	V15.8H, V7.8H, V0.8H
	cmge	V23.8H, V1.8H, V7.8H
	cmge	V16.8H, V8.8H, V0.8H
	cmge	V24.8H, V1.8H, V8.8H
	cmge	V17.8H, V9.8H, V0.8H
	cmge	V25.8H, V1.8H, V9.8H
	and	V18.16B, V18.16B, V10.16B
	and	V19.16B, V19.16B, V11.16B
	and	V20.16B, V20.16B, V12.16B
	and	V21.16B, V21.16B, V13.16B
	and	V22.16B, V22.16B, V14.16B
	and	V23.16B, V23.16B, V15.16B
	and	V24.16B, V24.16B, V16.16B
	and	V25.16B, V25.16B, V17.16B
	and	V18.16B, V18.16B, V26.16B
	and	V19.16B, V19.16B, V26.16B
	and	V20.16B, V20.16B, V26.16B
	and	V21.16B, V21.16B, V26.16B
	and	V22.16B, V22.16B, V26.16B
	and	V23.16B, V23.16B, V26.16B
	and	V24.16B, V24.16B, V26.16B
	and	V25.16B, V25.16B, V26.16B
	addv	H18, V18.8H
	addv	H19, V19.8H
	addv	H20, V20.8H
	addv	H21, V21.8H
	addv	H22, V22.8H
	addv	H23, V23.8H
	addv	H24, V24.8H
	addv	H25, V25.8H
	ins	V18.B[1], V19.B[0]
	ins	V18.B[2], V20.B[0]
	ins	V18.B[3], V21.B[0]
	ins	V18.B[4], V22.B[0]
	ins	V18.B[5], V23.B[0]
	ins	V18.B[6], V24.B[0]
	ins	V18.B[7], V25.B[0]
	st1	{V18.8B}, [x0], #8
	ld1	{V2.8H, V3.8H, V4.8H, V5.8H}, [x1], #0x40
	ld1	{V6.8H, V7.8H, V8.8H, V9.8H}, [x1], #0x40
	cmge	V10.8H, V2.8H, V0.8H
	cmge	V18.8H, V1.8H, V2.8H
	cmge	V11.8H, V3.8H, V0.8H
	cmge	V19.8H, V1.8H, V3.8H
	cmge	V12.8H, V4.8H, V0.8H
	cmge	V20.8H, V1.8H, V4.8H
	cmge	V13.8H, V5.8H, V0.8H
	cmge	V21.8H, V1.8H, V5.8H
	cmge	V14.8H, V6.8H, V0.8H
	cmge	V22.8H, V1.8H, V6.8H
	cmge	V15.8H, V7.8H, V0.8H
	cmge	V23.8H, V1.8H, V7.8H
	cmge	V16.8H, V8.8H, V0.8H
	cmge	V24.8H, V1.8H, V8.8H
	cmge	V17.8H, V9.8H, V0.8H
	cmge	V25.8H, V1.8H, V9.8H
	and	V18.16B, V18.16B, V10.16B
	and	V19.16B, V19.16B, V11.16B
	and	V20.16B, V20.16B, V12.16B
	and	V21.16B, V21.16B, V13.16B
	and	V22.16B, V22.16B, V14.16B
	and	V23.16B, V23.16B, V15.16B
	and	V24.16B, V24.16B, V16.16B
	and	V25.16B, V25.16B, V17.16B
	and	V18.16B, V18.16B, V26.16B
	and	V19.16B, V19.16B, V26.16B
	and	V20.16B, V20.16B, V26.16B
	and	V21.16B, V21.16B, V26.16B
	and	V22.16B, V22.16B, V26.16B
	and	V23.16B, V23.16B, V26.16B
	and	V24.16B, V24.16B, V26.16B
	and	V25.16B, V25.16B, V26.16B
	addv	H18, V18.8H
	addv	H19, V19.8H
	addv	H20, V20.8H
	addv	H21, V21.8H
	addv	H22, V22.8H
	addv	H23, V23.8H
	addv	H24, V24.8H
	addv	H25, V25.8H
	ins	V18.B[1], V19.B[0]
	ins	V18.B[2], V20.B[0]
	ins	V18.B[3], V21.B[0]
	ins	V18.B[4], V22.B[0]
	ins	V18.B[5], V23.B[0]
	ins	V18.B[6], V24.B[0]
	ins	V18.B[7], V25.B[0]
	st1	{V18.8B}, [x0], #8
	ld1	{V2.8H, V3.8H, V4.8H, V5.8H}, [x1], #0x40
	ld1	{V6.8H, V7.8H, V8.8H, V9.8H}, [x1], #0x40
	cmge	V10.8H, V2.8H, V0.8H
	cmge	V18.8H, V1.8H, V2.8H
	cmge	V11.8H, V3.8H, V0.8H
	cmge	V19.8H, V1.8H, V3.8H
	cmge	V12.8H, V4.8H, V0.8H
	cmge	V20.8H, V1.8H, V4.8H
	cmge	V13.8H, V5.8H, V0.8H
	cmge	V21.8H, V1.8H, V5.8H
	cmge	V14.8H, V6.8H, V0.8H
	cmge	V22.8H, V1.8H, V6.8H
	cmge	V15.8H, V7.8H, V0.8H
	cmge	V23.8H, V1.8H, V7.8H
	cmge	V16.8H, V8.8H, V0.8H
	cmge	V24.8H, V1.8H, V8.8H
	cmge	V17.8H, V9.8H, V0.8H
	cmge	V25.8H, V1.8H, V9.8H
	and	V18.16B, V18.16B, V10.16B
	and	V19.16B, V19.16B, V11.16B
	and	V20.16B, V20.16B, V12.16B
	and	V21.16B, V21.16B, V13.16B
	and	V22.16B, V22.16B, V14.16B
	and	V23.16B, V23.16B, V15.16B
	and	V24.16B, V24.16B, V16.16B
	and	V25.16B, V25.16B, V17.16B
	and	V18.16B, V18.16B, V26.16B
	and	V19.16B, V19.16B, V26.16B
	and	V20.16B, V20.16B, V26.16B
	and	V21.16B, V21.16B, V26.16B
	and	V22.16B, V22.16B, V26.16B
	and	V23.16B, V23.16B, V26.16B
	and	V24.16B, V24.16B, V26.16B
	and	V25.16B, V25.16B, V26.16B
	addv	H18, V18.8H
	addv	H19, V19.8H
	addv	H20, V20.8H
	addv	H21, V21.8H
	addv	H22, V22.8H
	addv	H23, V23.8H
	addv	H24, V24.8H
	addv	H25, V25.8H
	ins	V18.B[1], V19.B[0]
	ins	V18.B[2], V20.B[0]
	ins	V18.B[3], V21.B[0]
	ins	V18.B[4], V22.B[0]
	ins	V18.B[5], V23.B[0]
	ins	V18.B[6], V24.B[0]
	ins	V18.B[7], V25.B[0]
	st1	{V18.8B}, [x0], #8
	ldp	D8, D9, [x29, #16]
	ldp	D10, D11, [x29, #32]
	ldp	D12, D13, [x29, #48]
	ldp	D14, D15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
	ENDP
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mlkem_from_msg_q1half
	DCW	0x0681, 0x0681, 0x0681, 0x0681, 0x0681, 0x0681, 0x0681, 0x0681
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mlkem_from_msg_bits
	DCB	0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80
	DCB	0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mlkem_from_msg_neon
mlkem_from_msg_neon PROC
	stp	x29, x30, [sp, #-48]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	stp	D10, D11, [x29, #32]
	adrp	x2, L_mlkem_from_msg_q1half
	add	x2, x2, L_mlkem_from_msg_q1half
	adrp	x3, L_mlkem_from_msg_bits
	add	x3, x3, L_mlkem_from_msg_bits
	ld1	{V2.16B, V3.16B}, [x1]
	ldr	Q1, [x2]
	ldr	Q0, [x3]
	dup	V4.8B, V2.B[0]
	dup	V5.8B, V2.B[1]
	dup	V6.8B, V2.B[2]
	dup	V7.8B, V2.B[3]
	cmtst	V4.8B, V4.8B, V0.8B
	cmtst	V5.8B, V5.8B, V0.8B
	cmtst	V6.8B, V6.8B, V0.8B
	cmtst	V7.8B, V7.8B, V0.8B
	zip1	V4.16B, V4.16B, V4.16B
	zip1	V5.16B, V5.16B, V5.16B
	zip1	V6.16B, V6.16B, V6.16B
	zip1	V7.16B, V7.16B, V7.16B
	and	V4.16B, V4.16B, V1.16B
	and	V5.16B, V5.16B, V1.16B
	and	V6.16B, V6.16B, V1.16B
	and	V7.16B, V7.16B, V1.16B
	st1	{V4.8H, V5.8H, V6.8H, V7.8H}, [x0], #0x40
	dup	V4.8B, V2.B[4]
	dup	V5.8B, V2.B[5]
	dup	V6.8B, V2.B[6]
	dup	V7.8B, V2.B[7]
	cmtst	V4.8B, V4.8B, V0.8B
	cmtst	V5.8B, V5.8B, V0.8B
	cmtst	V6.8B, V6.8B, V0.8B
	cmtst	V7.8B, V7.8B, V0.8B
	zip1	V4.16B, V4.16B, V4.16B
	zip1	V5.16B, V5.16B, V5.16B
	zip1	V6.16B, V6.16B, V6.16B
	zip1	V7.16B, V7.16B, V7.16B
	and	V4.16B, V4.16B, V1.16B
	and	V5.16B, V5.16B, V1.16B
	and	V6.16B, V6.16B, V1.16B
	and	V7.16B, V7.16B, V1.16B
	st1	{V4.8H, V5.8H, V6.8H, V7.8H}, [x0], #0x40
	dup	V4.8B, V2.B[8]
	dup	V5.8B, V2.B[9]
	dup	V6.8B, V2.B[10]
	dup	V7.8B, V2.B[11]
	cmtst	V4.8B, V4.8B, V0.8B
	cmtst	V5.8B, V5.8B, V0.8B
	cmtst	V6.8B, V6.8B, V0.8B
	cmtst	V7.8B, V7.8B, V0.8B
	zip1	V4.16B, V4.16B, V4.16B
	zip1	V5.16B, V5.16B, V5.16B
	zip1	V6.16B, V6.16B, V6.16B
	zip1	V7.16B, V7.16B, V7.16B
	and	V4.16B, V4.16B, V1.16B
	and	V5.16B, V5.16B, V1.16B
	and	V6.16B, V6.16B, V1.16B
	and	V7.16B, V7.16B, V1.16B
	st1	{V4.8H, V5.8H, V6.8H, V7.8H}, [x0], #0x40
	dup	V4.8B, V2.B[12]
	dup	V5.8B, V2.B[13]
	dup	V6.8B, V2.B[14]
	dup	V7.8B, V2.B[15]
	cmtst	V4.8B, V4.8B, V0.8B
	cmtst	V5.8B, V5.8B, V0.8B
	cmtst	V6.8B, V6.8B, V0.8B
	cmtst	V7.8B, V7.8B, V0.8B
	zip1	V4.16B, V4.16B, V4.16B
	zip1	V5.16B, V5.16B, V5.16B
	zip1	V6.16B, V6.16B, V6.16B
	zip1	V7.16B, V7.16B, V7.16B
	and	V4.16B, V4.16B, V1.16B
	and	V5.16B, V5.16B, V1.16B
	and	V6.16B, V6.16B, V1.16B
	and	V7.16B, V7.16B, V1.16B
	st1	{V4.8H, V5.8H, V6.8H, V7.8H}, [x0], #0x40
	dup	V4.8B, V3.B[0]
	dup	V5.8B, V3.B[1]
	dup	V6.8B, V3.B[2]
	dup	V7.8B, V3.B[3]
	cmtst	V4.8B, V4.8B, V0.8B
	cmtst	V5.8B, V5.8B, V0.8B
	cmtst	V6.8B, V6.8B, V0.8B
	cmtst	V7.8B, V7.8B, V0.8B
	zip1	V4.16B, V4.16B, V4.16B
	zip1	V5.16B, V5.16B, V5.16B
	zip1	V6.16B, V6.16B, V6.16B
	zip1	V7.16B, V7.16B, V7.16B
	and	V4.16B, V4.16B, V1.16B
	and	V5.16B, V5.16B, V1.16B
	and	V6.16B, V6.16B, V1.16B
	and	V7.16B, V7.16B, V1.16B
	st1	{V4.8H, V5.8H, V6.8H, V7.8H}, [x0], #0x40
	dup	V4.8B, V3.B[4]
	dup	V5.8B, V3.B[5]
	dup	V6.8B, V3.B[6]
	dup	V7.8B, V3.B[7]
	cmtst	V4.8B, V4.8B, V0.8B
	cmtst	V5.8B, V5.8B, V0.8B
	cmtst	V6.8B, V6.8B, V0.8B
	cmtst	V7.8B, V7.8B, V0.8B
	zip1	V4.16B, V4.16B, V4.16B
	zip1	V5.16B, V5.16B, V5.16B
	zip1	V6.16B, V6.16B, V6.16B
	zip1	V7.16B, V7.16B, V7.16B
	and	V4.16B, V4.16B, V1.16B
	and	V5.16B, V5.16B, V1.16B
	and	V6.16B, V6.16B, V1.16B
	and	V7.16B, V7.16B, V1.16B
	st1	{V4.8H, V5.8H, V6.8H, V7.8H}, [x0], #0x40
	dup	V4.8B, V3.B[8]
	dup	V5.8B, V3.B[9]
	dup	V6.8B, V3.B[10]
	dup	V7.8B, V3.B[11]
	cmtst	V4.8B, V4.8B, V0.8B
	cmtst	V5.8B, V5.8B, V0.8B
	cmtst	V6.8B, V6.8B, V0.8B
	cmtst	V7.8B, V7.8B, V0.8B
	zip1	V4.16B, V4.16B, V4.16B
	zip1	V5.16B, V5.16B, V5.16B
	zip1	V6.16B, V6.16B, V6.16B
	zip1	V7.16B, V7.16B, V7.16B
	and	V4.16B, V4.16B, V1.16B
	and	V5.16B, V5.16B, V1.16B
	and	V6.16B, V6.16B, V1.16B
	and	V7.16B, V7.16B, V1.16B
	st1	{V4.8H, V5.8H, V6.8H, V7.8H}, [x0], #0x40
	dup	V4.8B, V3.B[12]
	dup	V5.8B, V3.B[13]
	dup	V6.8B, V3.B[14]
	dup	V7.8B, V3.B[15]
	cmtst	V4.8B, V4.8B, V0.8B
	cmtst	V5.8B, V5.8B, V0.8B
	cmtst	V6.8B, V6.8B, V0.8B
	cmtst	V7.8B, V7.8B, V0.8B
	zip1	V4.16B, V4.16B, V4.16B
	zip1	V5.16B, V5.16B, V5.16B
	zip1	V6.16B, V6.16B, V6.16B
	zip1	V7.16B, V7.16B, V7.16B
	and	V4.16B, V4.16B, V1.16B
	and	V5.16B, V5.16B, V1.16B
	and	V6.16B, V6.16B, V1.16B
	and	V7.16B, V7.16B, V1.16B
	st1	{V4.8H, V5.8H, V6.8H, V7.8H}, [x0], #0x40
	ldp	D8, D9, [x29, #16]
	ldp	D10, D11, [x29, #32]
	ldp	x29, x30, [sp], #48
	ret
	ENDP
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mlkem_cmp_neon
mlkem_cmp_neon PROC
	stp	x29, x30, [sp, #-48]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	stp	D10, D11, [x29, #32]
	ld4	{V0.16B, V1.16B, V2.16B, V3.16B}, [x0], #0x40
	ld4	{V4.16B, V5.16B, V6.16B, V7.16B}, [x1], #0x40
	eor	V8.16B, V0.16B, V4.16B
	eor	V9.16B, V1.16B, V5.16B
	eor	V10.16B, V2.16B, V6.16B
	eor	V11.16B, V3.16B, V7.16B
	ld4	{V0.16B, V1.16B, V2.16B, V3.16B}, [x0], #0x40
	ld4	{V4.16B, V5.16B, V6.16B, V7.16B}, [x1], #0x40
	eor	V0.16B, V0.16B, V4.16B
	eor	V1.16B, V1.16B, V5.16B
	eor	V2.16B, V2.16B, V6.16B
	eor	V3.16B, V3.16B, V7.16B
	orr	V8.16B, V8.16B, V0.16B
	orr	V9.16B, V9.16B, V1.16B
	orr	V10.16B, V10.16B, V2.16B
	orr	V11.16B, V11.16B, V3.16B
	ld4	{V0.16B, V1.16B, V2.16B, V3.16B}, [x0], #0x40
	ld4	{V4.16B, V5.16B, V6.16B, V7.16B}, [x1], #0x40
	eor	V0.16B, V0.16B, V4.16B
	eor	V1.16B, V1.16B, V5.16B
	eor	V2.16B, V2.16B, V6.16B
	eor	V3.16B, V3.16B, V7.16B
	orr	V8.16B, V8.16B, V0.16B
	orr	V9.16B, V9.16B, V1.16B
	orr	V10.16B, V10.16B, V2.16B
	orr	V11.16B, V11.16B, V3.16B
	ld4	{V0.16B, V1.16B, V2.16B, V3.16B}, [x0], #0x40
	ld4	{V4.16B, V5.16B, V6.16B, V7.16B}, [x1], #0x40
	eor	V0.16B, V0.16B, V4.16B
	eor	V1.16B, V1.16B, V5.16B
	eor	V2.16B, V2.16B, V6.16B
	eor	V3.16B, V3.16B, V7.16B
	orr	V8.16B, V8.16B, V0.16B
	orr	V9.16B, V9.16B, V1.16B
	orr	V10.16B, V10.16B, V2.16B
	orr	V11.16B, V11.16B, V3.16B
	ld4	{V0.16B, V1.16B, V2.16B, V3.16B}, [x0], #0x40
	ld4	{V4.16B, V5.16B, V6.16B, V7.16B}, [x1], #0x40
	eor	V0.16B, V0.16B, V4.16B
	eor	V1.16B, V1.16B, V5.16B
	eor	V2.16B, V2.16B, V6.16B
	eor	V3.16B, V3.16B, V7.16B
	orr	V8.16B, V8.16B, V0.16B
	orr	V9.16B, V9.16B, V1.16B
	orr	V10.16B, V10.16B, V2.16B
	orr	V11.16B, V11.16B, V3.16B
	ld4	{V0.16B, V1.16B, V2.16B, V3.16B}, [x0], #0x40
	ld4	{V4.16B, V5.16B, V6.16B, V7.16B}, [x1], #0x40
	eor	V0.16B, V0.16B, V4.16B
	eor	V1.16B, V1.16B, V5.16B
	eor	V2.16B, V2.16B, V6.16B
	eor	V3.16B, V3.16B, V7.16B
	orr	V8.16B, V8.16B, V0.16B
	orr	V9.16B, V9.16B, V1.16B
	orr	V10.16B, V10.16B, V2.16B
	orr	V11.16B, V11.16B, V3.16B
	ld4	{V0.16B, V1.16B, V2.16B, V3.16B}, [x0], #0x40
	ld4	{V4.16B, V5.16B, V6.16B, V7.16B}, [x1], #0x40
	eor	V0.16B, V0.16B, V4.16B
	eor	V1.16B, V1.16B, V5.16B
	eor	V2.16B, V2.16B, V6.16B
	eor	V3.16B, V3.16B, V7.16B
	orr	V8.16B, V8.16B, V0.16B
	orr	V9.16B, V9.16B, V1.16B
	orr	V10.16B, V10.16B, V2.16B
	orr	V11.16B, V11.16B, V3.16B
	ld4	{V0.16B, V1.16B, V2.16B, V3.16B}, [x0], #0x40
	ld4	{V4.16B, V5.16B, V6.16B, V7.16B}, [x1], #0x40
	eor	V0.16B, V0.16B, V4.16B
	eor	V1.16B, V1.16B, V5.16B
	eor	V2.16B, V2.16B, V6.16B
	eor	V3.16B, V3.16B, V7.16B
	orr	V8.16B, V8.16B, V0.16B
	orr	V9.16B, V9.16B, V1.16B
	orr	V10.16B, V10.16B, V2.16B
	orr	V11.16B, V11.16B, V3.16B
	ld4	{V0.16B, V1.16B, V2.16B, V3.16B}, [x0], #0x40
	ld4	{V4.16B, V5.16B, V6.16B, V7.16B}, [x1], #0x40
	eor	V0.16B, V0.16B, V4.16B
	eor	V1.16B, V1.16B, V5.16B
	eor	V2.16B, V2.16B, V6.16B
	eor	V3.16B, V3.16B, V7.16B
	orr	V8.16B, V8.16B, V0.16B
	orr	V9.16B, V9.16B, V1.16B
	orr	V10.16B, V10.16B, V2.16B
	orr	V11.16B, V11.16B, V3.16B
	ld4	{V0.16B, V1.16B, V2.16B, V3.16B}, [x0], #0x40
	ld4	{V4.16B, V5.16B, V6.16B, V7.16B}, [x1], #0x40
	eor	V0.16B, V0.16B, V4.16B
	eor	V1.16B, V1.16B, V5.16B
	eor	V2.16B, V2.16B, V6.16B
	eor	V3.16B, V3.16B, V7.16B
	orr	V8.16B, V8.16B, V0.16B
	orr	V9.16B, V9.16B, V1.16B
	orr	V10.16B, V10.16B, V2.16B
	orr	V11.16B, V11.16B, V3.16B
	ld4	{V0.16B, V1.16B, V2.16B, V3.16B}, [x0], #0x40
	ld4	{V4.16B, V5.16B, V6.16B, V7.16B}, [x1], #0x40
	eor	V0.16B, V0.16B, V4.16B
	eor	V1.16B, V1.16B, V5.16B
	eor	V2.16B, V2.16B, V6.16B
	eor	V3.16B, V3.16B, V7.16B
	orr	V8.16B, V8.16B, V0.16B
	orr	V9.16B, V9.16B, V1.16B
	orr	V10.16B, V10.16B, V2.16B
	orr	V11.16B, V11.16B, V3.16B
	ld4	{V0.16B, V1.16B, V2.16B, V3.16B}, [x0], #0x40
	ld4	{V4.16B, V5.16B, V6.16B, V7.16B}, [x1], #0x40
	eor	V0.16B, V0.16B, V4.16B
	eor	V1.16B, V1.16B, V5.16B
	eor	V2.16B, V2.16B, V6.16B
	eor	V3.16B, V3.16B, V7.16B
	orr	V8.16B, V8.16B, V0.16B
	orr	V9.16B, V9.16B, V1.16B
	orr	V10.16B, V10.16B, V2.16B
	orr	V11.16B, V11.16B, V3.16B
	subs	w2, w2, #0x300
	beq	L_mlkem_aarch64_cmp_neon_done
	ld4	{V0.16B, V1.16B, V2.16B, V3.16B}, [x0], #0x40
	ld4	{V4.16B, V5.16B, V6.16B, V7.16B}, [x1], #0x40
	eor	V0.16B, V0.16B, V4.16B
	eor	V1.16B, V1.16B, V5.16B
	eor	V2.16B, V2.16B, V6.16B
	eor	V3.16B, V3.16B, V7.16B
	orr	V8.16B, V8.16B, V0.16B
	orr	V9.16B, V9.16B, V1.16B
	orr	V10.16B, V10.16B, V2.16B
	orr	V11.16B, V11.16B, V3.16B
	ld4	{V0.16B, V1.16B, V2.16B, V3.16B}, [x0], #0x40
	ld4	{V4.16B, V5.16B, V6.16B, V7.16B}, [x1], #0x40
	eor	V0.16B, V0.16B, V4.16B
	eor	V1.16B, V1.16B, V5.16B
	eor	V2.16B, V2.16B, V6.16B
	eor	V3.16B, V3.16B, V7.16B
	orr	V8.16B, V8.16B, V0.16B
	orr	V9.16B, V9.16B, V1.16B
	orr	V10.16B, V10.16B, V2.16B
	orr	V11.16B, V11.16B, V3.16B
	ld4	{V0.16B, V1.16B, V2.16B, V3.16B}, [x0], #0x40
	ld4	{V4.16B, V5.16B, V6.16B, V7.16B}, [x1], #0x40
	eor	V0.16B, V0.16B, V4.16B
	eor	V1.16B, V1.16B, V5.16B
	eor	V2.16B, V2.16B, V6.16B
	eor	V3.16B, V3.16B, V7.16B
	orr	V8.16B, V8.16B, V0.16B
	orr	V9.16B, V9.16B, V1.16B
	orr	V10.16B, V10.16B, V2.16B
	orr	V11.16B, V11.16B, V3.16B
	ld4	{V0.16B, V1.16B, V2.16B, V3.16B}, [x0], #0x40
	ld4	{V4.16B, V5.16B, V6.16B, V7.16B}, [x1], #0x40
	eor	V0.16B, V0.16B, V4.16B
	eor	V1.16B, V1.16B, V5.16B
	eor	V2.16B, V2.16B, V6.16B
	eor	V3.16B, V3.16B, V7.16B
	orr	V8.16B, V8.16B, V0.16B
	orr	V9.16B, V9.16B, V1.16B
	orr	V10.16B, V10.16B, V2.16B
	orr	V11.16B, V11.16B, V3.16B
	ld4	{V0.16B, V1.16B, V2.16B, V3.16B}, [x0], #0x40
	ld4	{V4.16B, V5.16B, V6.16B, V7.16B}, [x1], #0x40
	eor	V0.16B, V0.16B, V4.16B
	eor	V1.16B, V1.16B, V5.16B
	eor	V2.16B, V2.16B, V6.16B
	eor	V3.16B, V3.16B, V7.16B
	orr	V8.16B, V8.16B, V0.16B
	orr	V9.16B, V9.16B, V1.16B
	orr	V10.16B, V10.16B, V2.16B
	orr	V11.16B, V11.16B, V3.16B
	subs	w2, w2, #0x140
	beq	L_mlkem_aarch64_cmp_neon_done
	ld4	{V0.16B, V1.16B, V2.16B, V3.16B}, [x0], #0x40
	ld4	{V4.16B, V5.16B, V6.16B, V7.16B}, [x1], #0x40
	eor	V0.16B, V0.16B, V4.16B
	eor	V1.16B, V1.16B, V5.16B
	eor	V2.16B, V2.16B, V6.16B
	eor	V3.16B, V3.16B, V7.16B
	orr	V8.16B, V8.16B, V0.16B
	orr	V9.16B, V9.16B, V1.16B
	orr	V10.16B, V10.16B, V2.16B
	orr	V11.16B, V11.16B, V3.16B
	ld4	{V0.16B, V1.16B, V2.16B, V3.16B}, [x0], #0x40
	ld4	{V4.16B, V5.16B, V6.16B, V7.16B}, [x1], #0x40
	eor	V0.16B, V0.16B, V4.16B
	eor	V1.16B, V1.16B, V5.16B
	eor	V2.16B, V2.16B, V6.16B
	eor	V3.16B, V3.16B, V7.16B
	orr	V8.16B, V8.16B, V0.16B
	orr	V9.16B, V9.16B, V1.16B
	orr	V10.16B, V10.16B, V2.16B
	orr	V11.16B, V11.16B, V3.16B
	ld4	{V0.16B, V1.16B, V2.16B, V3.16B}, [x0], #0x40
	ld4	{V4.16B, V5.16B, V6.16B, V7.16B}, [x1], #0x40
	eor	V0.16B, V0.16B, V4.16B
	eor	V1.16B, V1.16B, V5.16B
	eor	V2.16B, V2.16B, V6.16B
	eor	V3.16B, V3.16B, V7.16B
	orr	V8.16B, V8.16B, V0.16B
	orr	V9.16B, V9.16B, V1.16B
	orr	V10.16B, V10.16B, V2.16B
	orr	V11.16B, V11.16B, V3.16B
	ld4	{V0.16B, V1.16B, V2.16B, V3.16B}, [x0], #0x40
	ld4	{V4.16B, V5.16B, V6.16B, V7.16B}, [x1], #0x40
	eor	V0.16B, V0.16B, V4.16B
	eor	V1.16B, V1.16B, V5.16B
	eor	V2.16B, V2.16B, V6.16B
	eor	V3.16B, V3.16B, V7.16B
	orr	V8.16B, V8.16B, V0.16B
	orr	V9.16B, V9.16B, V1.16B
	orr	V10.16B, V10.16B, V2.16B
	orr	V11.16B, V11.16B, V3.16B
	ld4	{V0.16B, V1.16B, V2.16B, V3.16B}, [x0], #0x40
	ld4	{V4.16B, V5.16B, V6.16B, V7.16B}, [x1], #0x40
	eor	V0.16B, V0.16B, V4.16B
	eor	V1.16B, V1.16B, V5.16B
	eor	V2.16B, V2.16B, V6.16B
	eor	V3.16B, V3.16B, V7.16B
	orr	V8.16B, V8.16B, V0.16B
	orr	V9.16B, V9.16B, V1.16B
	orr	V10.16B, V10.16B, V2.16B
	orr	V11.16B, V11.16B, V3.16B
	ld4	{V0.16B, V1.16B, V2.16B, V3.16B}, [x0], #0x40
	ld4	{V4.16B, V5.16B, V6.16B, V7.16B}, [x1], #0x40
	eor	V0.16B, V0.16B, V4.16B
	eor	V1.16B, V1.16B, V5.16B
	eor	V2.16B, V2.16B, V6.16B
	eor	V3.16B, V3.16B, V7.16B
	orr	V8.16B, V8.16B, V0.16B
	orr	V9.16B, V9.16B, V1.16B
	orr	V10.16B, V10.16B, V2.16B
	orr	V11.16B, V11.16B, V3.16B
	ld4	{V0.16B, V1.16B, V2.16B, V3.16B}, [x0], #0x40
	ld4	{V4.16B, V5.16B, V6.16B, V7.16B}, [x1], #0x40
	eor	V0.16B, V0.16B, V4.16B
	eor	V1.16B, V1.16B, V5.16B
	eor	V2.16B, V2.16B, V6.16B
	eor	V3.16B, V3.16B, V7.16B
	orr	V8.16B, V8.16B, V0.16B
	orr	V9.16B, V9.16B, V1.16B
	orr	V10.16B, V10.16B, V2.16B
	orr	V11.16B, V11.16B, V3.16B
	ld2	{V0.16B, V1.16B}, [x0]
	ld2	{V4.16B, V5.16B}, [x1]
	eor	V0.16B, V0.16B, V4.16B
	eor	V1.16B, V1.16B, V5.16B
	orr	V8.16B, V8.16B, V0.16B
	orr	V9.16B, V9.16B, V1.16B
L_mlkem_aarch64_cmp_neon_done
	orr	V8.16B, V8.16B, V9.16B
	orr	V10.16B, V10.16B, V11.16B
	orr	V8.16B, V8.16B, V10.16B
	ext8	V9.16B, V8.16B, V8.16B, #8
	orr	V8.16B, V8.16B, V9.16B
	mov	x0, V8.D[0]
	subs	x0, x0, xzr
	csetm	w0, ne
	ldp	D8, D9, [x29, #16]
	ldp	D10, D11, [x29, #32]
	ldp	x29, x30, [sp], #48
	ret
	ENDP
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mlkem_rej_uniform_mask
	DCW	0x0fff, 0x0fff, 0x0fff, 0x0fff, 0x0fff, 0x0fff, 0x0fff, 0x0fff
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mlkem_rej_uniform_bits
	DCW	0x0001, 0x0002, 0x0004, 0x0008, 0x0010, 0x0020, 0x0040, 0x0080
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mlkem_rej_uniform_indices
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x04, 0x05, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x04, 0x05, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x04, 0x05, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x06, 0x07, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x06, 0x07, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x06, 0x07, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x06, 0x07, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x04, 0x05, 0x06, 0x07, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x08, 0x09, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x08, 0x09, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x08, 0x09, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x04, 0x05, 0x08, 0x09, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x04, 0x05, 0x08, 0x09, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x04, 0x05, 0x08, 0x09, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x08, 0x09
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x06, 0x07, 0x08, 0x09, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x06, 0x07, 0x08, 0x09, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x06, 0x07, 0x08, 0x09, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x06, 0x07, 0x08, 0x09
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
	DCB	0x08, 0x09, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x0a, 0x0b, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x04, 0x05, 0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x04, 0x05, 0x0a, 0x0b, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x04, 0x05, 0x0a, 0x0b, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x0a, 0x0b
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x06, 0x07, 0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x06, 0x07, 0x0a, 0x0b, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x06, 0x07, 0x0a, 0x0b, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x06, 0x07, 0x0a, 0x0b
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x04, 0x05, 0x06, 0x07, 0x0a, 0x0b, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0x0a, 0x0b
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x0a, 0x0b
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
	DCB	0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x08, 0x09, 0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x08, 0x09, 0x0a, 0x0b, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x04, 0x05, 0x08, 0x09, 0x0a, 0x0b, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x04, 0x05, 0x08, 0x09, 0x0a, 0x0b
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x04, 0x05, 0x08, 0x09, 0x0a, 0x0b
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x08, 0x09
	DCB	0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x06, 0x07, 0x08, 0x09
	DCB	0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09
	DCB	0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09
	DCB	0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
	DCB	0x08, 0x09, 0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff
	DCB	0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x0c, 0x0d, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x04, 0x05, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x04, 0x05, 0x0c, 0x0d, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x04, 0x05, 0x0c, 0x0d, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x0c, 0x0d
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x06, 0x07, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x06, 0x07, 0x0c, 0x0d, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x06, 0x07, 0x0c, 0x0d, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x06, 0x07, 0x0c, 0x0d
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x04, 0x05, 0x06, 0x07, 0x0c, 0x0d, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0x0c, 0x0d
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x0c, 0x0d
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
	DCB	0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x08, 0x09, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x08, 0x09, 0x0c, 0x0d, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x08, 0x09, 0x0c, 0x0d, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0c, 0x0d
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x04, 0x05, 0x08, 0x09, 0x0c, 0x0d, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x04, 0x05, 0x08, 0x09, 0x0c, 0x0d
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x04, 0x05, 0x08, 0x09, 0x0c, 0x0d
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x08, 0x09
	DCB	0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x06, 0x07, 0x08, 0x09, 0x0c, 0x0d, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x06, 0x07, 0x08, 0x09, 0x0c, 0x0d
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x06, 0x07, 0x08, 0x09, 0x0c, 0x0d
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x06, 0x07, 0x08, 0x09
	DCB	0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0c, 0x0d
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09
	DCB	0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09
	DCB	0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
	DCB	0x08, 0x09, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff
	DCB	0x0a, 0x0b, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x0a, 0x0b, 0x0c, 0x0d, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x0a, 0x0b, 0x0c, 0x0d, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x0a, 0x0b, 0x0c, 0x0d
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x04, 0x05, 0x0a, 0x0b, 0x0c, 0x0d, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x04, 0x05, 0x0a, 0x0b, 0x0c, 0x0d
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x04, 0x05, 0x0a, 0x0b, 0x0c, 0x0d
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x0a, 0x0b
	DCB	0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x06, 0x07, 0x0a, 0x0b, 0x0c, 0x0d, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x06, 0x07, 0x0a, 0x0b, 0x0c, 0x0d
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x06, 0x07, 0x0a, 0x0b, 0x0c, 0x0d
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x06, 0x07, 0x0a, 0x0b
	DCB	0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x04, 0x05, 0x06, 0x07, 0x0a, 0x0b, 0x0c, 0x0d
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0x0a, 0x0b
	DCB	0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x0a, 0x0b
	DCB	0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
	DCB	0x0a, 0x0b, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff
	DCB	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b
	DCB	0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x04, 0x05, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x04, 0x05, 0x08, 0x09, 0x0a, 0x0b
	DCB	0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x04, 0x05, 0x08, 0x09, 0x0a, 0x0b
	DCB	0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x08, 0x09
	DCB	0x0a, 0x0b, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff
	DCB	0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b
	DCB	0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b
	DCB	0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x06, 0x07, 0x08, 0x09
	DCB	0x0a, 0x0b, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff
	DCB	0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b
	DCB	0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09
	DCB	0x0a, 0x0b, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09
	DCB	0x0a, 0x0b, 0x0c, 0x0d, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
	DCB	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0xff, 0xff
	DCB	0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x0e, 0x0f, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x04, 0x05, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x04, 0x05, 0x0e, 0x0f, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x04, 0x05, 0x0e, 0x0f, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x0e, 0x0f
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x06, 0x07, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x06, 0x07, 0x0e, 0x0f, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x06, 0x07, 0x0e, 0x0f, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x06, 0x07, 0x0e, 0x0f
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x04, 0x05, 0x06, 0x07, 0x0e, 0x0f, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0x0e, 0x0f
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x0e, 0x0f
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
	DCB	0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x08, 0x09, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x08, 0x09, 0x0e, 0x0f, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x08, 0x09, 0x0e, 0x0f, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0e, 0x0f
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x04, 0x05, 0x08, 0x09, 0x0e, 0x0f, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x04, 0x05, 0x08, 0x09, 0x0e, 0x0f
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x04, 0x05, 0x08, 0x09, 0x0e, 0x0f
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x08, 0x09
	DCB	0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x06, 0x07, 0x08, 0x09, 0x0e, 0x0f, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x06, 0x07, 0x08, 0x09, 0x0e, 0x0f
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x06, 0x07, 0x08, 0x09, 0x0e, 0x0f
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x06, 0x07, 0x08, 0x09
	DCB	0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0e, 0x0f
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09
	DCB	0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09
	DCB	0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
	DCB	0x08, 0x09, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff
	DCB	0x0a, 0x0b, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x0a, 0x0b, 0x0e, 0x0f, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x0a, 0x0b, 0x0e, 0x0f, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x0a, 0x0b, 0x0e, 0x0f
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x04, 0x05, 0x0a, 0x0b, 0x0e, 0x0f, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x04, 0x05, 0x0a, 0x0b, 0x0e, 0x0f
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x04, 0x05, 0x0a, 0x0b, 0x0e, 0x0f
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x0a, 0x0b
	DCB	0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x06, 0x07, 0x0a, 0x0b, 0x0e, 0x0f, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x06, 0x07, 0x0a, 0x0b, 0x0e, 0x0f
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x06, 0x07, 0x0a, 0x0b, 0x0e, 0x0f
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x06, 0x07, 0x0a, 0x0b
	DCB	0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x04, 0x05, 0x06, 0x07, 0x0a, 0x0b, 0x0e, 0x0f
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0x0a, 0x0b
	DCB	0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x0a, 0x0b
	DCB	0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
	DCB	0x0a, 0x0b, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff
	DCB	0x08, 0x09, 0x0a, 0x0b, 0x0e, 0x0f, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x08, 0x09, 0x0a, 0x0b, 0x0e, 0x0f
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b, 0x0e, 0x0f
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b
	DCB	0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x04, 0x05, 0x08, 0x09, 0x0a, 0x0b, 0x0e, 0x0f
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x04, 0x05, 0x08, 0x09, 0x0a, 0x0b
	DCB	0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x04, 0x05, 0x08, 0x09, 0x0a, 0x0b
	DCB	0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x08, 0x09
	DCB	0x0a, 0x0b, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff
	DCB	0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0e, 0x0f
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b
	DCB	0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b
	DCB	0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x06, 0x07, 0x08, 0x09
	DCB	0x0a, 0x0b, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff
	DCB	0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b
	DCB	0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09
	DCB	0x0a, 0x0b, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09
	DCB	0x0a, 0x0b, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
	DCB	0x08, 0x09, 0x0a, 0x0b, 0x0e, 0x0f, 0xff, 0xff
	DCB	0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x0c, 0x0d, 0x0e, 0x0f
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x04, 0x05, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x04, 0x05, 0x0c, 0x0d, 0x0e, 0x0f
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x04, 0x05, 0x0c, 0x0d, 0x0e, 0x0f
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x0c, 0x0d
	DCB	0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x06, 0x07, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x06, 0x07, 0x0c, 0x0d, 0x0e, 0x0f
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x06, 0x07, 0x0c, 0x0d, 0x0e, 0x0f
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x06, 0x07, 0x0c, 0x0d
	DCB	0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x04, 0x05, 0x06, 0x07, 0x0c, 0x0d, 0x0e, 0x0f
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0x0c, 0x0d
	DCB	0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x0c, 0x0d
	DCB	0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
	DCB	0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff
	DCB	0x08, 0x09, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x08, 0x09, 0x0c, 0x0d, 0x0e, 0x0f
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x08, 0x09, 0x0c, 0x0d, 0x0e, 0x0f
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0c, 0x0d
	DCB	0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x04, 0x05, 0x08, 0x09, 0x0c, 0x0d, 0x0e, 0x0f
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x04, 0x05, 0x08, 0x09, 0x0c, 0x0d
	DCB	0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x04, 0x05, 0x08, 0x09, 0x0c, 0x0d
	DCB	0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x08, 0x09
	DCB	0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff
	DCB	0x06, 0x07, 0x08, 0x09, 0x0c, 0x0d, 0x0e, 0x0f
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x06, 0x07, 0x08, 0x09, 0x0c, 0x0d
	DCB	0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x06, 0x07, 0x08, 0x09, 0x0c, 0x0d
	DCB	0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x06, 0x07, 0x08, 0x09
	DCB	0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff
	DCB	0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0c, 0x0d
	DCB	0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09
	DCB	0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09
	DCB	0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
	DCB	0x08, 0x09, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff
	DCB	0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x0a, 0x0b, 0x0c, 0x0d
	DCB	0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x04, 0x05, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x04, 0x05, 0x0a, 0x0b, 0x0c, 0x0d
	DCB	0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x04, 0x05, 0x0a, 0x0b, 0x0c, 0x0d
	DCB	0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x0a, 0x0b
	DCB	0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff
	DCB	0x06, 0x07, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x06, 0x07, 0x0a, 0x0b, 0x0c, 0x0d
	DCB	0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x06, 0x07, 0x0a, 0x0b, 0x0c, 0x0d
	DCB	0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x06, 0x07, 0x0a, 0x0b
	DCB	0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff
	DCB	0x04, 0x05, 0x06, 0x07, 0x0a, 0x0b, 0x0c, 0x0d
	DCB	0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0x0a, 0x0b
	DCB	0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x0a, 0x0b
	DCB	0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
	DCB	0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff
	DCB	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d
	DCB	0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d
	DCB	0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b
	DCB	0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff
	DCB	0x04, 0x05, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d
	DCB	0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x04, 0x05, 0x08, 0x09, 0x0a, 0x0b
	DCB	0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x04, 0x05, 0x08, 0x09, 0x0a, 0x0b
	DCB	0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x08, 0x09
	DCB	0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff
	DCB	0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d
	DCB	0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b
	DCB	0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff
	DCB	0x02, 0x03, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b
	DCB	0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x06, 0x07, 0x08, 0x09
	DCB	0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff
	DCB	0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b
	DCB	0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09
	DCB	0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff
	DCB	0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09
	DCB	0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
	DCB	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mlkem_rej_uniform_neon
mlkem_rej_uniform_neon PROC
	stp	x29, x30, [sp, #-64]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	stp	D10, D11, [x29, #32]
	stp	D12, D13, [x29, #48]
	adrp	x4, L_mlkem_rej_uniform_mask
	add	x4, x4, L_mlkem_rej_uniform_mask
	adrp	x5, L_mlkem_aarch64_q
	add	x5, x5, L_mlkem_aarch64_q
	adrp	x6, L_mlkem_rej_uniform_bits
	add	x6, x6, L_mlkem_rej_uniform_bits
	adrp	x7, L_mlkem_rej_uniform_indices
	add	x7, x7, L_mlkem_rej_uniform_indices
	eor	V1.16B, V1.16B, V1.16B
	eor	V12.16B, V12.16B, V12.16B
	eor	V13.16B, V13.16B, V13.16B
	eor	x12, x12, x12
	eor	V10.16B, V10.16B, V10.16B
	eor	V11.16B, V11.16B, V11.16B
	mov	x13, #0xd01
	ldr	Q0, [x4]
	ldr	Q3, [x5]
	ldr	Q2, [x6]
	subs	wzr, w1, #0
	beq	L_mlkem_rej_uniform_done
	subs	wzr, w1, #16
	blt	L_mlkem_rej_uniform_loop_4
L_mlkem_rej_uniform_loop_16
	ld3	{V4.8B, V5.8B, V6.8B}, [x2], #24
	zip1	V4.16B, V4.16B, V1.16B
	zip1	V5.16B, V5.16B, V1.16B
	zip1	V6.16B, V6.16B, V1.16B
	shl	V7.8H, V5.8H, #8
	ushr	V8.8H, V5.8H, #4
	shl	V6.8H, V6.8H, #4
	orr	V4.16B, V4.16B, V7.16B
	orr	V5.16B, V8.16B, V6.16B
	and	V7.16B, V4.16B, V0.16B
	and	V8.16B, V5.16B, V0.16B
	zip1	V4.8H, V7.8H, V8.8H
	zip2	V5.8H, V7.8H, V8.8H
	cmgt	V7.8H, V3.8H, V4.8H
	cmgt	V8.8H, V3.8H, V5.8H
	ushr	V12.8H, V7.8H, #15
	ushr	V13.8H, V8.8H, #15
	addv	H12, V12.8H
	addv	H13, V13.8H
	mov	x10, V12.D[0]
	mov	x11, V13.D[0]
	and	V10.16B, V7.16B, V2.16B
	and	V11.16B, V8.16B, V2.16B
	addv	H10, V10.8H
	addv	H11, V11.8H
	mov	w8, V10.S[0]
	mov	w9, V11.S[0]
	lsl	w8, w8, #4
	lsl	w9, w9, #4
	ldr	Q10, [x7, x8]
	ldr	Q11, [x7, x9]
	tbl	V7.16B, {V4.16B}, V10.16B
	tbl	V8.16B, {V5.16B}, V11.16B
	str	Q7, [x0]
	add	x0, x0, x10, lsl 1
	add	x12, x12, x10
	str	Q8, [x0]
	add	x0, x0, x11, lsl 1
	add	x12, x12, x11
	subs	w3, w3, #24
	beq	L_mlkem_rej_uniform_done
	sub	w10, w1, w12
	subs	x10, x10, #16
	blt	L_mlkem_rej_uniform_loop_4
	b	L_mlkem_rej_uniform_loop_16
L_mlkem_rej_uniform_loop_4
	subs	w10, w1, w12
	beq	L_mlkem_rej_uniform_done
	subs	x10, x10, #4
	blt	L_mlkem_rej_uniform_loop_lt_4
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
	beq	L_mlkem_rej_uniform_done
	b	L_mlkem_rej_uniform_loop_4
L_mlkem_rej_uniform_loop_lt_4
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
	beq	L_mlkem_rej_uniform_done
	strh	w5, [x0]
	subs	xzr, x5, x13
	cinc	x0, x0, lt
	cinc	x0, x0, lt
	cinc	x12, x12, lt
	subs	wzr, w1, w12
	beq	L_mlkem_rej_uniform_done
	strh	w6, [x0]
	subs	xzr, x6, x13
	cinc	x0, x0, lt
	cinc	x0, x0, lt
	cinc	x12, x12, lt
	subs	wzr, w1, w12
	beq	L_mlkem_rej_uniform_done
	strh	w7, [x0]
	subs	xzr, x7, x13
	cinc	x0, x0, lt
	cinc	x0, x0, lt
	cinc	x12, x12, lt
	subs	wzr, w1, w12
	beq	L_mlkem_rej_uniform_done
	subs	w3, w3, #6
	beq	L_mlkem_rej_uniform_done
	b	L_mlkem_rej_uniform_loop_lt_4
L_mlkem_rej_uniform_done
	mov	x0, x12
	ldp	D8, D9, [x29, #16]
	ldp	D10, D11, [x29, #32]
	ldp	D12, D13, [x29, #48]
	ldp	x29, x30, [sp], #0x40
	ret
	ENDP
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	16
L_sha3_aarch64_r
	DCQ	0x0000000000000001, 0x0000000000008082
	DCQ	0x800000000000808a, 0x8000000080008000
	DCQ	0x000000000000808b, 0x0000000080000001
	DCQ	0x8000000080008081, 0x8000000000008009
	DCQ	0x000000000000008a, 0x0000000000000088
	DCQ	0x0000000080008009, 0x000000008000000a
	DCQ	0x000000008000808b, 0x800000000000008b
	DCQ	0x8000000000008089, 0x8000000000008003
	DCQ	0x8000000000008002, 0x8000000000000080
	DCQ	0x000000000000800a, 0x800000008000000a
	DCQ	0x8000000080008081, 0x8000000000008080
	DCQ	0x0000000080000001, 0x8000000080008008
	IF :DEF:WOLFSSL_ARMASM_CRYPTO_SHA3
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mlkem_sha3_blocksx3_neon
mlkem_sha3_blocksx3_neon PROC
	stp	x29, x30, [sp, #-224]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #72]
	stp	x20, x21, [x29, #88]
	stp	x22, x23, [x29, #104]
	stp	x24, x25, [x29, #120]
	stp	x26, x27, [x29, #136]
	str	x28, [x29, #152]
	stp	D8, D9, [x29, #160]
	stp	D10, D11, [x29, #176]
	stp	D12, D13, [x29, #192]
	stp	D14, D15, [x29, #208]
	adrp	x27, L_sha3_aarch64_r
	add	x27, x27, L_sha3_aarch64_r
	str	x0, [x29, #40]
	ld4	{V0.D, V1.D, V2.D, V3.D}[0], [x0], #32
	ld4	{V4.D, V5.D, V6.D, V7.D}[0], [x0], #32
	ld4	{V8.D, V9.D, V10.D, V11.D}[0], [x0], #32
	ld4	{V12.D, V13.D, V14.D, V15.D}[0], [x0], #32
	ld4	{V16.D, V17.D, V18.D, V19.D}[0], [x0], #32
	ld4	{V20.D, V21.D, V22.D, V23.D}[0], [x0], #32
	ld1	{V24.D}[0], [x0]
	add	x0, x0, #8
	ld4	{V0.D, V1.D, V2.D, V3.D}[1], [x0], #32
	ld4	{V4.D, V5.D, V6.D, V7.D}[1], [x0], #32
	ld4	{V8.D, V9.D, V10.D, V11.D}[1], [x0], #32
	ld4	{V12.D, V13.D, V14.D, V15.D}[1], [x0], #32
	ld4	{V16.D, V17.D, V18.D, V19.D}[1], [x0], #32
	ld4	{V20.D, V21.D, V22.D, V23.D}[1], [x0], #32
	ld1	{V24.D}[1], [x0]
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
	; Start of 24 rounds
L_SHA3_transform_blocksx3_neon_begin
	stp	x27, x28, [x29, #48]
	; Col Mix
	eor3	V31.16B, V0.16B, V5.16B, V10.16B
	eor	x0, x5, x10
	eor3	V27.16B, V1.16B, V6.16B, V11.16B
	eor	x30, x1, x6
	eor3	V28.16B, V2.16B, V7.16B, V12.16B
	eor	x28, x3, x8
	eor3	V29.16B, V3.16B, V8.16B, V13.16B
	eor	x0, x0, x15
	eor3	V30.16B, V4.16B, V9.16B, V14.16B
	eor	x30, x30, x11
	eor3	V31.16B, V31.16B, V15.16B, V20.16B
	eor	x28, x28, x13
	eor3	V27.16B, V27.16B, V16.16B, V21.16B
	eor	x0, x0, x21
	eor3	V28.16B, V28.16B, V17.16B, V22.16B
	eor	x30, x30, x16
	eor3	V29.16B, V29.16B, V18.16B, V23.16B
	eor	x28, x28, x19
	eor3	V30.16B, V30.16B, V19.16B, V24.16B
	eor	x0, x0, x26
	rax1	V25.2D, V30.2D, V27.2D
	eor	x30, x30, x22
	rax1	V26.2D, V31.2D, V28.2D
	eor	x28, x28, x24
	rax1	V27.2D, V27.2D, V29.2D
	str	x0, [x29, #32]
	rax1	V28.2D, V28.2D, V30.2D
	str	x28, [x29, #24]
	rax1	V29.2D, V29.2D, V31.2D
	eor	x27, x2, x7
	eor	V0.16B, V0.16B, V25.16B
	xar	V30.2D, V1.2D, V26.2D, #63
	eor	x28, x4, x9
	xar	V1.2D, V6.2D, V26.2D, #20
	eor	x27, x27, x12
	xar	V6.2D, V9.2D, V29.2D, #44
	eor	x28, x28, x14
	xar	V9.2D, V22.2D, V27.2D, #3
	eor	x27, x27, x17
	xar	V22.2D, V14.2D, V29.2D, #25
	eor	x28, x28, x20
	xar	V14.2D, V20.2D, V25.2D, #46
	eor	x27, x27, x23
	xar	V20.2D, V2.2D, V27.2D, #2
	eor	x28, x28, x25
	xar	V2.2D, V12.2D, V27.2D, #21
	eor	x0, x0, x27, ror 63
	xar	V12.2D, V13.2D, V28.2D, #39
	eor	x27, x27, x28, ror 63
	xar	V13.2D, V19.2D, V29.2D, #56
	eor	x1, x1, x0
	xar	V19.2D, V23.2D, V28.2D, #8
	eor	x6, x6, x0
	xar	V23.2D, V15.2D, V25.2D, #23
	eor	x11, x11, x0
	xar	V15.2D, V4.2D, V29.2D, #37
	eor	x16, x16, x0
	xar	V4.2D, V24.2D, V29.2D, #50
	eor	x22, x22, x0
	xar	V24.2D, V21.2D, V26.2D, #62
	eor	x3, x3, x27
	xar	V21.2D, V8.2D, V28.2D, #9
	eor	x8, x8, x27
	xar	V8.2D, V16.2D, V26.2D, #19
	eor	x13, x13, x27
	xar	V16.2D, V5.2D, V25.2D, #28
	eor	x19, x19, x27
	xar	V5.2D, V3.2D, V28.2D, #36
	eor	x24, x24, x27
	xar	V3.2D, V18.2D, V28.2D, #43
	ldr	x0, [x29, #32]
	xar	V18.2D, V17.2D, V27.2D, #49
	ldr	x27, [x29, #24]
	xar	V17.2D, V11.2D, V26.2D, #54
	eor	x28, x28, x30, ror 63
	xar	V11.2D, V7.2D, V27.2D, #58
	eor	x30, x30, x27, ror 63
	xar	V7.2D, V10.2D, V25.2D, #61
	eor	x27, x27, x0, ror 63
	; Row Mix
	mov	V25.16B, V0.16B
	eor	x5, x5, x28
	mov	V26.16B, V1.16B
	eor	x10, x10, x28
	bcax	V0.16B, V25.16B, V2.16B, V26.16B
	eor	x15, x15, x28
	bcax	V1.16B, V26.16B, V3.16B, V2.16B
	eor	x21, x21, x28
	bcax	V2.16B, V2.16B, V4.16B, V3.16B
	eor	x26, x26, x28
	bcax	V3.16B, V3.16B, V25.16B, V4.16B
	eor	x2, x2, x30
	bcax	V4.16B, V4.16B, V26.16B, V25.16B
	eor	x7, x7, x30
	mov	V25.16B, V5.16B
	eor	x12, x12, x30
	mov	V26.16B, V6.16B
	eor	x17, x17, x30
	bcax	V5.16B, V25.16B, V7.16B, V26.16B
	eor	x23, x23, x30
	bcax	V6.16B, V26.16B, V8.16B, V7.16B
	eor	x4, x4, x27
	bcax	V7.16B, V7.16B, V9.16B, V8.16B
	eor	x9, x9, x27
	bcax	V8.16B, V8.16B, V25.16B, V9.16B
	eor	x14, x14, x27
	bcax	V9.16B, V9.16B, V26.16B, V25.16B
	eor	x20, x20, x27
	mov	V26.16B, V11.16B
	eor	x25, x25, x27
	; Swap Rotate Base
	bcax	V10.16B, V30.16B, V12.16B, V26.16B
	ror	x0, x2, #63
	bcax	V11.16B, V26.16B, V13.16B, V12.16B
	ror	x2, x7, #20
	bcax	V12.16B, V12.16B, V14.16B, V13.16B
	ror	x7, x10, #44
	bcax	V13.16B, V13.16B, V30.16B, V14.16B
	ror	x10, x24, #3
	bcax	V14.16B, V14.16B, V26.16B, V30.16B
	ror	x24, x15, #25
	mov	V25.16B, V15.16B
	ror	x15, x22, #46
	mov	V26.16B, V16.16B
	ror	x22, x3, #2
	bcax	V15.16B, V25.16B, V17.16B, V26.16B
	ror	x3, x13, #21
	bcax	V16.16B, V26.16B, V18.16B, V17.16B
	ror	x13, x14, #39
	bcax	V17.16B, V17.16B, V19.16B, V18.16B
	ror	x14, x21, #56
	bcax	V18.16B, V18.16B, V25.16B, V19.16B
	ror	x21, x25, #8
	bcax	V19.16B, V19.16B, V26.16B, V25.16B
	ror	x25, x16, #23
	mov	V25.16B, V20.16B
	ror	x16, x5, #37
	mov	V26.16B, V21.16B
	ror	x5, x26, #50
	bcax	V20.16B, V25.16B, V22.16B, V26.16B
	ror	x26, x23, #62
	bcax	V21.16B, V26.16B, V23.16B, V22.16B
	ror	x23, x9, #9
	bcax	V22.16B, V22.16B, V24.16B, V23.16B
	ror	x9, x17, #19
	bcax	V23.16B, V23.16B, V25.16B, V24.16B
	ror	x17, x6, #28
	bcax	V24.16B, V24.16B, V26.16B, V25.16B
	ror	x6, x4, #36
	ror	x4, x20, #43
	ror	x20, x19, #49
	ror	x19, x12, #54
	ror	x12, x8, #58
	ror	x8, x11, #61
	; Row Mix Base
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
	; Done transforming
	ldp	x27, x28, [x29, #48]
	ldr	x0, [x27], #8
	subs	x28, x28, #1
	mov	V30.D[0], x0
	mov	V30.D[1], x0
	eor	x1, x1, x0
	eor	V0.16B, V0.16B, V30.16B
	bne	L_SHA3_transform_blocksx3_neon_begin
	ldr	x0, [x29, #40]
	st4	{V0.D, V1.D, V2.D, V3.D}[0], [x0], #32
	st4	{V4.D, V5.D, V6.D, V7.D}[0], [x0], #32
	st4	{V8.D, V9.D, V10.D, V11.D}[0], [x0], #32
	st4	{V12.D, V13.D, V14.D, V15.D}[0], [x0], #32
	st4	{V16.D, V17.D, V18.D, V19.D}[0], [x0], #32
	st4	{V20.D, V21.D, V22.D, V23.D}[0], [x0], #32
	st1	{V24.D}[0], [x0]
	add	x0, x0, #8
	st4	{V0.D, V1.D, V2.D, V3.D}[1], [x0], #32
	st4	{V4.D, V5.D, V6.D, V7.D}[1], [x0], #32
	st4	{V8.D, V9.D, V10.D, V11.D}[1], [x0], #32
	st4	{V12.D, V13.D, V14.D, V15.D}[1], [x0], #32
	st4	{V16.D, V17.D, V18.D, V19.D}[1], [x0], #32
	st4	{V20.D, V21.D, V22.D, V23.D}[1], [x0], #32
	st1	{V24.D}[1], [x0]
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
	ldp	D8, D9, [x29, #160]
	ldp	D10, D11, [x29, #176]
	ldp	D12, D13, [x29, #192]
	ldp	D14, D15, [x29, #208]
	ldp	x29, x30, [sp], #0xe0
	ret
	ENDP
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mlkem_shake128_blocksx3_seed_neon
mlkem_shake128_blocksx3_seed_neon PROC
	stp	x29, x30, [sp, #-224]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #72]
	stp	x20, x21, [x29, #88]
	stp	x22, x23, [x29, #104]
	stp	x24, x25, [x29, #120]
	stp	x26, x27, [x29, #136]
	str	x28, [x29, #152]
	stp	D8, D9, [x29, #160]
	stp	D10, D11, [x29, #176]
	stp	D12, D13, [x29, #192]
	stp	D14, D15, [x29, #208]
	adrp	x28, L_sha3_aarch64_r
	add	x28, x28, L_sha3_aarch64_r
	str	x0, [x29, #40]
	add	x0, x0, #32
	ld1	{V4.D}[0], [x0]
	ldp	x2, x3, [x1], #16
	add	x0, x0, #0xc8
	ld1	{V4.D}[1], [x0]
	ldp	x4, x5, [x1], #16
	ldr	x6, [x0, #200]
	eor	V5.16B, V5.16B, V5.16B
	eor	x7, x7, x7
	eor	V6.16B, V6.16B, V6.16B
	eor	x8, x8, x8
	eor	V7.16B, V7.16B, V7.16B
	eor	x9, x9, x9
	eor	V8.16B, V8.16B, V8.16B
	eor	x10, x10, x10
	eor	V9.16B, V9.16B, V9.16B
	eor	x11, x11, x11
	eor	V10.16B, V10.16B, V10.16B
	eor	x12, x12, x12
	eor	V11.16B, V11.16B, V11.16B
	eor	x13, x13, x13
	eor	V12.16B, V12.16B, V12.16B
	eor	x14, x14, x14
	eor	V13.16B, V13.16B, V13.16B
	eor	x15, x15, x15
	eor	V14.16B, V14.16B, V14.16B
	eor	x16, x16, x16
	eor	V15.16B, V15.16B, V15.16B
	eor	x17, x17, x17
	eor	V16.16B, V16.16B, V16.16B
	eor	x19, x19, x19
	eor	V17.16B, V17.16B, V17.16B
	eor	x20, x20, x20
	eor	V18.16B, V18.16B, V18.16B
	eor	x21, x21, x21
	eor	V19.16B, V19.16B, V19.16B
	eor	x22, x22, x22
	movz	x23, #0x8000, lsl 48
	eor	V21.16B, V21.16B, V21.16B
	eor	x24, x24, x24
	eor	V22.16B, V22.16B, V22.16B
	eor	x25, x25, x25
	eor	V23.16B, V23.16B, V23.16B
	eor	x26, x26, x26
	eor	V24.16B, V24.16B, V24.16B
	eor	x27, x27, x27
	dup	V0.2D, x2
	dup	V1.2D, x3
	dup	V2.2D, x4
	dup	V3.2D, x5
	dup	V20.2D, x23
	mov	x1, #24
	; Start of 24 rounds
L_SHA3_shake128_blocksx3_seed_neon_begin
	stp	x28, x1, [x29, #48]
	; Col Mix
	eor3	V31.16B, V0.16B, V5.16B, V10.16B
	eor	x0, x6, x11
	eor3	V27.16B, V1.16B, V6.16B, V11.16B
	eor	x30, x2, x7
	eor3	V28.16B, V2.16B, V7.16B, V12.16B
	eor	x28, x4, x9
	eor3	V29.16B, V3.16B, V8.16B, V13.16B
	eor	x0, x0, x16
	eor3	V30.16B, V4.16B, V9.16B, V14.16B
	eor	x30, x30, x12
	eor3	V31.16B, V31.16B, V15.16B, V20.16B
	eor	x28, x28, x14
	eor3	V27.16B, V27.16B, V16.16B, V21.16B
	eor	x0, x0, x22
	eor3	V28.16B, V28.16B, V17.16B, V22.16B
	eor	x30, x30, x17
	eor3	V29.16B, V29.16B, V18.16B, V23.16B
	eor	x28, x28, x20
	eor3	V30.16B, V30.16B, V19.16B, V24.16B
	eor	x0, x0, x27
	rax1	V25.2D, V30.2D, V27.2D
	eor	x30, x30, x23
	rax1	V26.2D, V31.2D, V28.2D
	eor	x28, x28, x25
	rax1	V27.2D, V27.2D, V29.2D
	str	x0, [x29, #32]
	rax1	V28.2D, V28.2D, V30.2D
	str	x28, [x29, #24]
	rax1	V29.2D, V29.2D, V31.2D
	eor	x1, x3, x8
	eor	V0.16B, V0.16B, V25.16B
	xar	V30.2D, V1.2D, V26.2D, #63
	eor	x28, x5, x10
	xar	V1.2D, V6.2D, V26.2D, #20
	eor	x1, x1, x13
	xar	V6.2D, V9.2D, V29.2D, #44
	eor	x28, x28, x15
	xar	V9.2D, V22.2D, V27.2D, #3
	eor	x1, x1, x19
	xar	V22.2D, V14.2D, V29.2D, #25
	eor	x28, x28, x21
	xar	V14.2D, V20.2D, V25.2D, #46
	eor	x1, x1, x24
	xar	V20.2D, V2.2D, V27.2D, #2
	eor	x28, x28, x26
	xar	V2.2D, V12.2D, V27.2D, #21
	eor	x0, x0, x1, ror 63
	xar	V12.2D, V13.2D, V28.2D, #39
	eor	x1, x1, x28, ror 63
	xar	V13.2D, V19.2D, V29.2D, #56
	eor	x2, x2, x0
	xar	V19.2D, V23.2D, V28.2D, #8
	eor	x7, x7, x0
	xar	V23.2D, V15.2D, V25.2D, #23
	eor	x12, x12, x0
	xar	V15.2D, V4.2D, V29.2D, #37
	eor	x17, x17, x0
	xar	V4.2D, V24.2D, V29.2D, #50
	eor	x23, x23, x0
	xar	V24.2D, V21.2D, V26.2D, #62
	eor	x4, x4, x1
	xar	V21.2D, V8.2D, V28.2D, #9
	eor	x9, x9, x1
	xar	V8.2D, V16.2D, V26.2D, #19
	eor	x14, x14, x1
	xar	V16.2D, V5.2D, V25.2D, #28
	eor	x20, x20, x1
	xar	V5.2D, V3.2D, V28.2D, #36
	eor	x25, x25, x1
	xar	V3.2D, V18.2D, V28.2D, #43
	ldr	x0, [x29, #32]
	xar	V18.2D, V17.2D, V27.2D, #49
	ldr	x1, [x29, #24]
	xar	V17.2D, V11.2D, V26.2D, #54
	eor	x28, x28, x30, ror 63
	xar	V11.2D, V7.2D, V27.2D, #58
	eor	x30, x30, x1, ror 63
	xar	V7.2D, V10.2D, V25.2D, #61
	eor	x1, x1, x0, ror 63
	; Row Mix
	mov	V25.16B, V0.16B
	eor	x6, x6, x28
	mov	V26.16B, V1.16B
	eor	x11, x11, x28
	bcax	V0.16B, V25.16B, V2.16B, V26.16B
	eor	x16, x16, x28
	bcax	V1.16B, V26.16B, V3.16B, V2.16B
	eor	x22, x22, x28
	bcax	V2.16B, V2.16B, V4.16B, V3.16B
	eor	x27, x27, x28
	bcax	V3.16B, V3.16B, V25.16B, V4.16B
	eor	x3, x3, x30
	bcax	V4.16B, V4.16B, V26.16B, V25.16B
	eor	x8, x8, x30
	mov	V25.16B, V5.16B
	eor	x13, x13, x30
	mov	V26.16B, V6.16B
	eor	x19, x19, x30
	bcax	V5.16B, V25.16B, V7.16B, V26.16B
	eor	x24, x24, x30
	bcax	V6.16B, V26.16B, V8.16B, V7.16B
	eor	x5, x5, x1
	bcax	V7.16B, V7.16B, V9.16B, V8.16B
	eor	x10, x10, x1
	bcax	V8.16B, V8.16B, V25.16B, V9.16B
	eor	x15, x15, x1
	bcax	V9.16B, V9.16B, V26.16B, V25.16B
	eor	x21, x21, x1
	mov	V26.16B, V11.16B
	eor	x26, x26, x1
	; Swap Rotate Base
	bcax	V10.16B, V30.16B, V12.16B, V26.16B
	ror	x0, x3, #63
	bcax	V11.16B, V26.16B, V13.16B, V12.16B
	ror	x3, x8, #20
	bcax	V12.16B, V12.16B, V14.16B, V13.16B
	ror	x8, x11, #44
	bcax	V13.16B, V13.16B, V30.16B, V14.16B
	ror	x11, x25, #3
	bcax	V14.16B, V14.16B, V26.16B, V30.16B
	ror	x25, x16, #25
	mov	V25.16B, V15.16B
	ror	x16, x23, #46
	mov	V26.16B, V16.16B
	ror	x23, x4, #2
	bcax	V15.16B, V25.16B, V17.16B, V26.16B
	ror	x4, x14, #21
	bcax	V16.16B, V26.16B, V18.16B, V17.16B
	ror	x14, x15, #39
	bcax	V17.16B, V17.16B, V19.16B, V18.16B
	ror	x15, x22, #56
	bcax	V18.16B, V18.16B, V25.16B, V19.16B
	ror	x22, x26, #8
	bcax	V19.16B, V19.16B, V26.16B, V25.16B
	ror	x26, x17, #23
	mov	V25.16B, V20.16B
	ror	x17, x6, #37
	mov	V26.16B, V21.16B
	ror	x6, x27, #50
	bcax	V20.16B, V25.16B, V22.16B, V26.16B
	ror	x27, x24, #62
	bcax	V21.16B, V26.16B, V23.16B, V22.16B
	ror	x24, x10, #9
	bcax	V22.16B, V22.16B, V24.16B, V23.16B
	ror	x10, x19, #19
	bcax	V23.16B, V23.16B, V25.16B, V24.16B
	ror	x19, x7, #28
	bcax	V24.16B, V24.16B, V26.16B, V25.16B
	ror	x7, x5, #36
	ror	x5, x21, #43
	ror	x21, x20, #49
	ror	x20, x13, #54
	ror	x13, x9, #58
	ror	x9, x12, #61
	; Row Mix Base
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
	; Done transforming
	ldp	x28, x1, [x29, #48]
	ldr	x0, [x28], #8
	subs	x1, x1, #1
	mov	V30.D[0], x0
	mov	V30.D[1], x0
	eor	x2, x2, x0
	eor	V0.16B, V0.16B, V30.16B
	bne	L_SHA3_shake128_blocksx3_seed_neon_begin
	ldr	x0, [x29, #40]
	st4	{V0.D, V1.D, V2.D, V3.D}[0], [x0], #32
	st4	{V4.D, V5.D, V6.D, V7.D}[0], [x0], #32
	st4	{V8.D, V9.D, V10.D, V11.D}[0], [x0], #32
	st4	{V12.D, V13.D, V14.D, V15.D}[0], [x0], #32
	st4	{V16.D, V17.D, V18.D, V19.D}[0], [x0], #32
	st4	{V20.D, V21.D, V22.D, V23.D}[0], [x0], #32
	st1	{V24.D}[0], [x0]
	add	x0, x0, #8
	st4	{V0.D, V1.D, V2.D, V3.D}[1], [x0], #32
	st4	{V4.D, V5.D, V6.D, V7.D}[1], [x0], #32
	st4	{V8.D, V9.D, V10.D, V11.D}[1], [x0], #32
	st4	{V12.D, V13.D, V14.D, V15.D}[1], [x0], #32
	st4	{V16.D, V17.D, V18.D, V19.D}[1], [x0], #32
	st4	{V20.D, V21.D, V22.D, V23.D}[1], [x0], #32
	st1	{V24.D}[1], [x0]
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
	ldp	D8, D9, [x29, #160]
	ldp	D10, D11, [x29, #176]
	ldp	D12, D13, [x29, #192]
	ldp	D14, D15, [x29, #208]
	ldp	x29, x30, [sp], #0xe0
	ret
	ENDP
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mlkem_shake256_blocksx3_seed_neon
mlkem_shake256_blocksx3_seed_neon PROC
	stp	x29, x30, [sp, #-224]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #72]
	stp	x20, x21, [x29, #88]
	stp	x22, x23, [x29, #104]
	stp	x24, x25, [x29, #120]
	stp	x26, x27, [x29, #136]
	str	x28, [x29, #152]
	stp	D8, D9, [x29, #160]
	stp	D10, D11, [x29, #176]
	stp	D12, D13, [x29, #192]
	stp	D14, D15, [x29, #208]
	adrp	x28, L_sha3_aarch64_r
	add	x28, x28, L_sha3_aarch64_r
	str	x0, [x29, #40]
	add	x0, x0, #32
	ld1	{V4.D}[0], [x0]
	ldp	x2, x3, [x1], #16
	add	x0, x0, #0xc8
	ld1	{V4.D}[1], [x0]
	ldp	x4, x5, [x1], #16
	ldr	x6, [x0, #200]
	eor	V5.16B, V5.16B, V5.16B
	eor	x7, x7, x7
	eor	V6.16B, V6.16B, V6.16B
	eor	x8, x8, x8
	eor	V7.16B, V7.16B, V7.16B
	eor	x9, x9, x9
	eor	V8.16B, V8.16B, V8.16B
	eor	x10, x10, x10
	eor	V9.16B, V9.16B, V9.16B
	eor	x11, x11, x11
	eor	V10.16B, V10.16B, V10.16B
	eor	x12, x12, x12
	eor	V11.16B, V11.16B, V11.16B
	eor	x13, x13, x13
	eor	V12.16B, V12.16B, V12.16B
	eor	x14, x14, x14
	eor	V13.16B, V13.16B, V13.16B
	eor	x15, x15, x15
	eor	V14.16B, V14.16B, V14.16B
	eor	x16, x16, x16
	eor	V15.16B, V15.16B, V15.16B
	eor	x17, x17, x17
	movz	x19, #0x8000, lsl 48
	eor	V17.16B, V17.16B, V17.16B
	eor	x20, x20, x20
	eor	V18.16B, V18.16B, V18.16B
	eor	x21, x21, x21
	eor	V19.16B, V19.16B, V19.16B
	eor	x22, x22, x22
	eor	V20.16B, V20.16B, V20.16B
	eor	x23, x23, x23
	eor	V21.16B, V21.16B, V21.16B
	eor	x24, x24, x24
	eor	V22.16B, V22.16B, V22.16B
	eor	x25, x25, x25
	eor	V23.16B, V23.16B, V23.16B
	eor	x26, x26, x26
	eor	V24.16B, V24.16B, V24.16B
	eor	x27, x27, x27
	dup	V0.2D, x2
	dup	V1.2D, x3
	dup	V2.2D, x4
	dup	V3.2D, x5
	dup	V16.2D, x19
	mov	x1, #24
	; Start of 24 rounds
L_SHA3_shake256_blocksx3_seed_neon_begin
	stp	x28, x1, [x29, #48]
	; Col Mix
	eor3	V31.16B, V0.16B, V5.16B, V10.16B
	eor	x0, x6, x11
	eor3	V27.16B, V1.16B, V6.16B, V11.16B
	eor	x30, x2, x7
	eor3	V28.16B, V2.16B, V7.16B, V12.16B
	eor	x28, x4, x9
	eor3	V29.16B, V3.16B, V8.16B, V13.16B
	eor	x0, x0, x16
	eor3	V30.16B, V4.16B, V9.16B, V14.16B
	eor	x30, x30, x12
	eor3	V31.16B, V31.16B, V15.16B, V20.16B
	eor	x28, x28, x14
	eor3	V27.16B, V27.16B, V16.16B, V21.16B
	eor	x0, x0, x22
	eor3	V28.16B, V28.16B, V17.16B, V22.16B
	eor	x30, x30, x17
	eor3	V29.16B, V29.16B, V18.16B, V23.16B
	eor	x28, x28, x20
	eor3	V30.16B, V30.16B, V19.16B, V24.16B
	eor	x0, x0, x27
	rax1	V25.2D, V30.2D, V27.2D
	eor	x30, x30, x23
	rax1	V26.2D, V31.2D, V28.2D
	eor	x28, x28, x25
	rax1	V27.2D, V27.2D, V29.2D
	str	x0, [x29, #32]
	rax1	V28.2D, V28.2D, V30.2D
	str	x28, [x29, #24]
	rax1	V29.2D, V29.2D, V31.2D
	eor	x1, x3, x8
	eor	V0.16B, V0.16B, V25.16B
	xar	V30.2D, V1.2D, V26.2D, #63
	eor	x28, x5, x10
	xar	V1.2D, V6.2D, V26.2D, #20
	eor	x1, x1, x13
	xar	V6.2D, V9.2D, V29.2D, #44
	eor	x28, x28, x15
	xar	V9.2D, V22.2D, V27.2D, #3
	eor	x1, x1, x19
	xar	V22.2D, V14.2D, V29.2D, #25
	eor	x28, x28, x21
	xar	V14.2D, V20.2D, V25.2D, #46
	eor	x1, x1, x24
	xar	V20.2D, V2.2D, V27.2D, #2
	eor	x28, x28, x26
	xar	V2.2D, V12.2D, V27.2D, #21
	eor	x0, x0, x1, ror 63
	xar	V12.2D, V13.2D, V28.2D, #39
	eor	x1, x1, x28, ror 63
	xar	V13.2D, V19.2D, V29.2D, #56
	eor	x2, x2, x0
	xar	V19.2D, V23.2D, V28.2D, #8
	eor	x7, x7, x0
	xar	V23.2D, V15.2D, V25.2D, #23
	eor	x12, x12, x0
	xar	V15.2D, V4.2D, V29.2D, #37
	eor	x17, x17, x0
	xar	V4.2D, V24.2D, V29.2D, #50
	eor	x23, x23, x0
	xar	V24.2D, V21.2D, V26.2D, #62
	eor	x4, x4, x1
	xar	V21.2D, V8.2D, V28.2D, #9
	eor	x9, x9, x1
	xar	V8.2D, V16.2D, V26.2D, #19
	eor	x14, x14, x1
	xar	V16.2D, V5.2D, V25.2D, #28
	eor	x20, x20, x1
	xar	V5.2D, V3.2D, V28.2D, #36
	eor	x25, x25, x1
	xar	V3.2D, V18.2D, V28.2D, #43
	ldr	x0, [x29, #32]
	xar	V18.2D, V17.2D, V27.2D, #49
	ldr	x1, [x29, #24]
	xar	V17.2D, V11.2D, V26.2D, #54
	eor	x28, x28, x30, ror 63
	xar	V11.2D, V7.2D, V27.2D, #58
	eor	x30, x30, x1, ror 63
	xar	V7.2D, V10.2D, V25.2D, #61
	eor	x1, x1, x0, ror 63
	; Row Mix
	mov	V25.16B, V0.16B
	eor	x6, x6, x28
	mov	V26.16B, V1.16B
	eor	x11, x11, x28
	bcax	V0.16B, V25.16B, V2.16B, V26.16B
	eor	x16, x16, x28
	bcax	V1.16B, V26.16B, V3.16B, V2.16B
	eor	x22, x22, x28
	bcax	V2.16B, V2.16B, V4.16B, V3.16B
	eor	x27, x27, x28
	bcax	V3.16B, V3.16B, V25.16B, V4.16B
	eor	x3, x3, x30
	bcax	V4.16B, V4.16B, V26.16B, V25.16B
	eor	x8, x8, x30
	mov	V25.16B, V5.16B
	eor	x13, x13, x30
	mov	V26.16B, V6.16B
	eor	x19, x19, x30
	bcax	V5.16B, V25.16B, V7.16B, V26.16B
	eor	x24, x24, x30
	bcax	V6.16B, V26.16B, V8.16B, V7.16B
	eor	x5, x5, x1
	bcax	V7.16B, V7.16B, V9.16B, V8.16B
	eor	x10, x10, x1
	bcax	V8.16B, V8.16B, V25.16B, V9.16B
	eor	x15, x15, x1
	bcax	V9.16B, V9.16B, V26.16B, V25.16B
	eor	x21, x21, x1
	mov	V26.16B, V11.16B
	eor	x26, x26, x1
	; Swap Rotate Base
	bcax	V10.16B, V30.16B, V12.16B, V26.16B
	ror	x0, x3, #63
	bcax	V11.16B, V26.16B, V13.16B, V12.16B
	ror	x3, x8, #20
	bcax	V12.16B, V12.16B, V14.16B, V13.16B
	ror	x8, x11, #44
	bcax	V13.16B, V13.16B, V30.16B, V14.16B
	ror	x11, x25, #3
	bcax	V14.16B, V14.16B, V26.16B, V30.16B
	ror	x25, x16, #25
	mov	V25.16B, V15.16B
	ror	x16, x23, #46
	mov	V26.16B, V16.16B
	ror	x23, x4, #2
	bcax	V15.16B, V25.16B, V17.16B, V26.16B
	ror	x4, x14, #21
	bcax	V16.16B, V26.16B, V18.16B, V17.16B
	ror	x14, x15, #39
	bcax	V17.16B, V17.16B, V19.16B, V18.16B
	ror	x15, x22, #56
	bcax	V18.16B, V18.16B, V25.16B, V19.16B
	ror	x22, x26, #8
	bcax	V19.16B, V19.16B, V26.16B, V25.16B
	ror	x26, x17, #23
	mov	V25.16B, V20.16B
	ror	x17, x6, #37
	mov	V26.16B, V21.16B
	ror	x6, x27, #50
	bcax	V20.16B, V25.16B, V22.16B, V26.16B
	ror	x27, x24, #62
	bcax	V21.16B, V26.16B, V23.16B, V22.16B
	ror	x24, x10, #9
	bcax	V22.16B, V22.16B, V24.16B, V23.16B
	ror	x10, x19, #19
	bcax	V23.16B, V23.16B, V25.16B, V24.16B
	ror	x19, x7, #28
	bcax	V24.16B, V24.16B, V26.16B, V25.16B
	ror	x7, x5, #36
	ror	x5, x21, #43
	ror	x21, x20, #49
	ror	x20, x13, #54
	ror	x13, x9, #58
	ror	x9, x12, #61
	; Row Mix Base
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
	; Done transforming
	ldp	x28, x1, [x29, #48]
	ldr	x0, [x28], #8
	subs	x1, x1, #1
	mov	V30.D[0], x0
	mov	V30.D[1], x0
	eor	x2, x2, x0
	eor	V0.16B, V0.16B, V30.16B
	bne	L_SHA3_shake256_blocksx3_seed_neon_begin
	ldr	x0, [x29, #40]
	st4	{V0.D, V1.D, V2.D, V3.D}[0], [x0], #32
	st4	{V4.D, V5.D, V6.D, V7.D}[0], [x0], #32
	st4	{V8.D, V9.D, V10.D, V11.D}[0], [x0], #32
	st4	{V12.D, V13.D, V14.D, V15.D}[0], [x0], #32
	st4	{V16.D, V17.D, V18.D, V19.D}[0], [x0], #32
	st4	{V20.D, V21.D, V22.D, V23.D}[0], [x0], #32
	st1	{V24.D}[0], [x0]
	add	x0, x0, #8
	st4	{V0.D, V1.D, V2.D, V3.D}[1], [x0], #32
	st4	{V4.D, V5.D, V6.D, V7.D}[1], [x0], #32
	st4	{V8.D, V9.D, V10.D, V11.D}[1], [x0], #32
	st4	{V12.D, V13.D, V14.D, V15.D}[1], [x0], #32
	st4	{V16.D, V17.D, V18.D, V19.D}[1], [x0], #32
	st4	{V20.D, V21.D, V22.D, V23.D}[1], [x0], #32
	st1	{V24.D}[1], [x0]
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
	ldp	D8, D9, [x29, #160]
	ldp	D10, D11, [x29, #176]
	ldp	D12, D13, [x29, #192]
	ldp	D14, D15, [x29, #208]
	ldp	x29, x30, [sp], #0xe0
	ret
	ENDP
	ELSE
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mlkem_sha3_blocksx3_neon
mlkem_sha3_blocksx3_neon PROC
	stp	x29, x30, [sp, #-224]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #72]
	stp	x20, x21, [x29, #88]
	stp	x22, x23, [x29, #104]
	stp	x24, x25, [x29, #120]
	stp	x26, x27, [x29, #136]
	str	x28, [x29, #152]
	stp	D8, D9, [x29, #160]
	stp	D10, D11, [x29, #176]
	stp	D12, D13, [x29, #192]
	stp	D14, D15, [x29, #208]
	adrp	x27, L_sha3_aarch64_r
	add	x27, x27, L_sha3_aarch64_r
	str	x0, [x29, #40]
	ld4	{V0.D, V1.D, V2.D, V3.D}[0], [x0], #32
	ld4	{V4.D, V5.D, V6.D, V7.D}[0], [x0], #32
	ld4	{V8.D, V9.D, V10.D, V11.D}[0], [x0], #32
	ld4	{V12.D, V13.D, V14.D, V15.D}[0], [x0], #32
	ld4	{V16.D, V17.D, V18.D, V19.D}[0], [x0], #32
	ld4	{V20.D, V21.D, V22.D, V23.D}[0], [x0], #32
	ld1	{V24.D}[0], [x0]
	add	x0, x0, #8
	ld4	{V0.D, V1.D, V2.D, V3.D}[1], [x0], #32
	ld4	{V4.D, V5.D, V6.D, V7.D}[1], [x0], #32
	ld4	{V8.D, V9.D, V10.D, V11.D}[1], [x0], #32
	ld4	{V12.D, V13.D, V14.D, V15.D}[1], [x0], #32
	ld4	{V16.D, V17.D, V18.D, V19.D}[1], [x0], #32
	ld4	{V20.D, V21.D, V22.D, V23.D}[1], [x0], #32
	ld1	{V24.D}[1], [x0]
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
	; Start of 24 rounds
L_SHA3_transform_blocksx3_neon_begin
	stp	x27, x28, [x29, #48]
	; Col Mix NEON
	eor	V30.16B, V4.16B, V9.16B
	eor	x0, x5, x10
	eor	V27.16B, V1.16B, V6.16B
	eor	x30, x1, x6
	eor	V30.16B, V30.16B, V14.16B
	eor	x28, x3, x8
	eor	V27.16B, V27.16B, V11.16B
	eor	x0, x0, x15
	eor	V30.16B, V30.16B, V19.16B
	eor	x30, x30, x11
	eor	V27.16B, V27.16B, V16.16B
	eor	x28, x28, x13
	eor	V30.16B, V30.16B, V24.16B
	eor	x0, x0, x21
	eor	V27.16B, V27.16B, V21.16B
	eor	x30, x30, x16
	ushr	V25.2D, V27.2D, #63
	eor	x28, x28, x19
	sli	V25.2D, V27.2D, #1
	eor	x0, x0, x26
	eor	V25.16B, V25.16B, V30.16B
	eor	x30, x30, x22
	eor	V31.16B, V0.16B, V5.16B
	eor	x28, x28, x24
	eor	V28.16B, V2.16B, V7.16B
	str	x0, [x29, #32]
	eor	V31.16B, V31.16B, V10.16B
	str	x28, [x29, #24]
	eor	V28.16B, V28.16B, V12.16B
	eor	x27, x2, x7
	eor	V31.16B, V31.16B, V15.16B
	eor	x28, x4, x9
	eor	V28.16B, V28.16B, V17.16B
	eor	x27, x27, x12
	eor	V31.16B, V31.16B, V20.16B
	eor	x28, x28, x14
	eor	V28.16B, V28.16B, V22.16B
	eor	x27, x27, x17
	ushr	V29.2D, V30.2D, #63
	eor	x28, x28, x20
	ushr	V26.2D, V28.2D, #63
	eor	x27, x27, x23
	sli	V29.2D, V30.2D, #1
	eor	x28, x28, x25
	sli	V26.2D, V28.2D, #1
	eor	x0, x0, x27, ror 63
	eor	V28.16B, V28.16B, V29.16B
	eor	x27, x27, x28, ror 63
	eor	V29.16B, V3.16B, V8.16B
	eor	x1, x1, x0
	eor	V26.16B, V26.16B, V31.16B
	eor	x6, x6, x0
	eor	V29.16B, V29.16B, V13.16B
	eor	x11, x11, x0
	eor	V29.16B, V29.16B, V18.16B
	eor	x16, x16, x0
	eor	V29.16B, V29.16B, V23.16B
	eor	x22, x22, x0
	ushr	V30.2D, V29.2D, #63
	eor	x3, x3, x27
	sli	V30.2D, V29.2D, #1
	eor	x8, x8, x27
	eor	V27.16B, V27.16B, V30.16B
	eor	x13, x13, x27
	ushr	V30.2D, V31.2D, #63
	eor	x19, x19, x27
	sli	V30.2D, V31.2D, #1
	eor	x24, x24, x27
	eor	V29.16B, V29.16B, V30.16B
	ldr	x0, [x29, #32]
	; Swap Rotate NEON
	eor	V0.16B, V0.16B, V25.16B
	eor	V31.16B, V1.16B, V26.16B
	ldr	x27, [x29, #24]
	eor	V6.16B, V6.16B, V26.16B
	eor	x28, x28, x30, ror 63
	ushr	V30.2D, V31.2D, #63
	eor	x30, x30, x27, ror 63
	ushr	V1.2D, V6.2D, #20
	eor	x27, x27, x0, ror 63
	sli	V30.2D, V31.2D, #1
	eor	x5, x5, x28
	sli	V1.2D, V6.2D, #44
	eor	x10, x10, x28
	eor	V31.16B, V9.16B, V29.16B
	eor	x15, x15, x28
	eor	V22.16B, V22.16B, V27.16B
	eor	x21, x21, x28
	ushr	V6.2D, V31.2D, #44
	eor	x26, x26, x28
	ushr	V9.2D, V22.2D, #3
	eor	x2, x2, x30
	sli	V6.2D, V31.2D, #20
	eor	x7, x7, x30
	sli	V9.2D, V22.2D, #61
	eor	x12, x12, x30
	eor	V31.16B, V14.16B, V29.16B
	eor	x17, x17, x30
	eor	V20.16B, V20.16B, V25.16B
	eor	x23, x23, x30
	ushr	V22.2D, V31.2D, #25
	eor	x4, x4, x27
	ushr	V14.2D, V20.2D, #46
	eor	x9, x9, x27
	sli	V22.2D, V31.2D, #39
	eor	x14, x14, x27
	sli	V14.2D, V20.2D, #18
	eor	x20, x20, x27
	eor	V31.16B, V2.16B, V27.16B
	eor	x25, x25, x27
	; Swap Rotate Base
	eor	V12.16B, V12.16B, V27.16B
	ror	x0, x2, #63
	ushr	V20.2D, V31.2D, #2
	ror	x2, x7, #20
	ushr	V2.2D, V12.2D, #21
	ror	x7, x10, #44
	sli	V20.2D, V31.2D, #62
	ror	x10, x24, #3
	sli	V2.2D, V12.2D, #43
	ror	x24, x15, #25
	eor	V31.16B, V13.16B, V28.16B
	ror	x15, x22, #46
	eor	V19.16B, V19.16B, V29.16B
	ror	x22, x3, #2
	ushr	V12.2D, V31.2D, #39
	ror	x3, x13, #21
	ushr	V13.2D, V19.2D, #56
	ror	x13, x14, #39
	sli	V12.2D, V31.2D, #25
	ror	x14, x21, #56
	sli	V13.2D, V19.2D, #8
	ror	x21, x25, #8
	eor	V31.16B, V23.16B, V28.16B
	ror	x25, x16, #23
	eor	V15.16B, V15.16B, V25.16B
	ror	x16, x5, #37
	ushr	V19.2D, V31.2D, #8
	ror	x5, x26, #50
	ushr	V23.2D, V15.2D, #23
	ror	x26, x23, #62
	sli	V19.2D, V31.2D, #56
	ror	x23, x9, #9
	sli	V23.2D, V15.2D, #41
	ror	x9, x17, #19
	eor	V31.16B, V4.16B, V29.16B
	ror	x17, x6, #28
	eor	V24.16B, V24.16B, V29.16B
	ror	x6, x4, #36
	ushr	V15.2D, V31.2D, #37
	ror	x4, x20, #43
	ushr	V4.2D, V24.2D, #50
	ror	x20, x19, #49
	sli	V15.2D, V31.2D, #27
	ror	x19, x12, #54
	sli	V4.2D, V24.2D, #14
	ror	x12, x8, #58
	eor	V31.16B, V21.16B, V26.16B
	ror	x8, x11, #61
	; Row Mix Base
	eor	V8.16B, V8.16B, V28.16B
	bic	x11, x3, x2
	ushr	V24.2D, V31.2D, #62
	bic	x27, x4, x3
	ushr	V21.2D, V8.2D, #9
	bic	x28, x1, x5
	sli	V24.2D, V31.2D, #2
	bic	x30, x2, x1
	sli	V21.2D, V8.2D, #55
	eor	x1, x1, x11
	eor	V31.16B, V16.16B, V26.16B
	eor	x2, x2, x27
	eor	V5.16B, V5.16B, V25.16B
	bic	x11, x5, x4
	ushr	V8.2D, V31.2D, #19
	eor	x4, x4, x28
	ushr	V16.2D, V5.2D, #28
	eor	x3, x3, x11
	sli	V8.2D, V31.2D, #45
	eor	x5, x5, x30
	sli	V16.2D, V5.2D, #36
	bic	x11, x8, x7
	eor	V31.16B, V3.16B, V28.16B
	bic	x27, x9, x8
	eor	V18.16B, V18.16B, V28.16B
	bic	x28, x6, x10
	ushr	V5.2D, V31.2D, #36
	bic	x30, x7, x6
	ushr	V3.2D, V18.2D, #43
	eor	x6, x6, x11
	sli	V5.2D, V31.2D, #28
	eor	x7, x7, x27
	sli	V3.2D, V18.2D, #21
	bic	x11, x10, x9
	eor	V31.16B, V17.16B, V27.16B
	eor	x9, x9, x28
	eor	V11.16B, V11.16B, V26.16B
	eor	x8, x8, x11
	ushr	V18.2D, V31.2D, #49
	eor	x10, x10, x30
	ushr	V17.2D, V11.2D, #54
	bic	x11, x13, x12
	sli	V18.2D, V31.2D, #15
	bic	x27, x14, x13
	sli	V17.2D, V11.2D, #10
	bic	x28, x0, x15
	eor	V31.16B, V7.16B, V27.16B
	bic	x30, x12, x0
	eor	V10.16B, V10.16B, V25.16B
	eor	x11, x0, x11
	ushr	V11.2D, V31.2D, #58
	eor	x12, x12, x27
	ushr	V7.2D, V10.2D, #61
	bic	x0, x15, x14
	sli	V11.2D, V31.2D, #6
	eor	x14, x14, x28
	sli	V7.2D, V10.2D, #3
	eor	x13, x13, x0
	; Row Mix NEON
	bic	V25.16B, V2.16B, V1.16B
	eor	x15, x15, x30
	bic	V26.16B, V3.16B, V2.16B
	bic	x0, x19, x17
	bic	V27.16B, V4.16B, V3.16B
	bic	x27, x20, x19
	bic	V28.16B, V0.16B, V4.16B
	bic	x28, x16, x21
	bic	V29.16B, V1.16B, V0.16B
	bic	x30, x17, x16
	eor	V0.16B, V0.16B, V25.16B
	eor	x16, x16, x0
	eor	V1.16B, V1.16B, V26.16B
	eor	x17, x17, x27
	eor	V2.16B, V2.16B, V27.16B
	bic	x0, x21, x20
	eor	V3.16B, V3.16B, V28.16B
	eor	x20, x20, x28
	eor	V4.16B, V4.16B, V29.16B
	eor	x19, x19, x0
	bic	V25.16B, V7.16B, V6.16B
	eor	x21, x21, x30
	bic	V26.16B, V8.16B, V7.16B
	bic	x0, x24, x23
	bic	V27.16B, V9.16B, V8.16B
	bic	x27, x25, x24
	bic	V28.16B, V5.16B, V9.16B
	bic	x28, x22, x26
	bic	V29.16B, V6.16B, V5.16B
	bic	x30, x23, x22
	eor	V5.16B, V5.16B, V25.16B
	eor	x22, x22, x0
	eor	V6.16B, V6.16B, V26.16B
	eor	x23, x23, x27
	eor	V7.16B, V7.16B, V27.16B
	bic	x0, x26, x25
	eor	V8.16B, V8.16B, V28.16B
	eor	x25, x25, x28
	eor	V9.16B, V9.16B, V29.16B
	eor	x24, x24, x0
	bic	V25.16B, V12.16B, V11.16B
	eor	x26, x26, x30
	bic	V26.16B, V13.16B, V12.16B
	bic	V27.16B, V14.16B, V13.16B
	bic	V28.16B, V30.16B, V14.16B
	bic	V29.16B, V11.16B, V30.16B
	eor	V10.16B, V30.16B, V25.16B
	eor	V11.16B, V11.16B, V26.16B
	eor	V12.16B, V12.16B, V27.16B
	eor	V13.16B, V13.16B, V28.16B
	eor	V14.16B, V14.16B, V29.16B
	bic	V25.16B, V17.16B, V16.16B
	bic	V26.16B, V18.16B, V17.16B
	bic	V27.16B, V19.16B, V18.16B
	bic	V28.16B, V15.16B, V19.16B
	bic	V29.16B, V16.16B, V15.16B
	eor	V15.16B, V15.16B, V25.16B
	eor	V16.16B, V16.16B, V26.16B
	eor	V17.16B, V17.16B, V27.16B
	eor	V18.16B, V18.16B, V28.16B
	eor	V19.16B, V19.16B, V29.16B
	bic	V25.16B, V22.16B, V21.16B
	bic	V26.16B, V23.16B, V22.16B
	bic	V27.16B, V24.16B, V23.16B
	bic	V28.16B, V20.16B, V24.16B
	bic	V29.16B, V21.16B, V20.16B
	eor	V20.16B, V20.16B, V25.16B
	eor	V21.16B, V21.16B, V26.16B
	eor	V22.16B, V22.16B, V27.16B
	eor	V23.16B, V23.16B, V28.16B
	eor	V24.16B, V24.16B, V29.16B
	; Done transforming
	ldp	x27, x28, [x29, #48]
	ldr	x0, [x27], #8
	subs	x28, x28, #1
	mov	V30.D[0], x0
	mov	V30.D[1], x0
	eor	x1, x1, x0
	eor	V0.16B, V0.16B, V30.16B
	bne	L_SHA3_transform_blocksx3_neon_begin
	ldr	x0, [x29, #40]
	st4	{V0.D, V1.D, V2.D, V3.D}[0], [x0], #32
	st4	{V4.D, V5.D, V6.D, V7.D}[0], [x0], #32
	st4	{V8.D, V9.D, V10.D, V11.D}[0], [x0], #32
	st4	{V12.D, V13.D, V14.D, V15.D}[0], [x0], #32
	st4	{V16.D, V17.D, V18.D, V19.D}[0], [x0], #32
	st4	{V20.D, V21.D, V22.D, V23.D}[0], [x0], #32
	st1	{V24.D}[0], [x0]
	add	x0, x0, #8
	st4	{V0.D, V1.D, V2.D, V3.D}[1], [x0], #32
	st4	{V4.D, V5.D, V6.D, V7.D}[1], [x0], #32
	st4	{V8.D, V9.D, V10.D, V11.D}[1], [x0], #32
	st4	{V12.D, V13.D, V14.D, V15.D}[1], [x0], #32
	st4	{V16.D, V17.D, V18.D, V19.D}[1], [x0], #32
	st4	{V20.D, V21.D, V22.D, V23.D}[1], [x0], #32
	st1	{V24.D}[1], [x0]
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
	ldp	D8, D9, [x29, #160]
	ldp	D10, D11, [x29, #176]
	ldp	D12, D13, [x29, #192]
	ldp	D14, D15, [x29, #208]
	ldp	x29, x30, [sp], #0xe0
	ret
	ENDP
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mlkem_shake128_blocksx3_seed_neon
mlkem_shake128_blocksx3_seed_neon PROC
	stp	x29, x30, [sp, #-224]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #72]
	stp	x20, x21, [x29, #88]
	stp	x22, x23, [x29, #104]
	stp	x24, x25, [x29, #120]
	stp	x26, x27, [x29, #136]
	str	x28, [x29, #152]
	stp	D8, D9, [x29, #160]
	stp	D10, D11, [x29, #176]
	stp	D12, D13, [x29, #192]
	stp	D14, D15, [x29, #208]
	adrp	x28, L_sha3_aarch64_r
	add	x28, x28, L_sha3_aarch64_r
	str	x0, [x29, #40]
	add	x0, x0, #32
	ld1	{V4.D}[0], [x0]
	ldp	x2, x3, [x1], #16
	add	x0, x0, #0xc8
	ld1	{V4.D}[1], [x0]
	ldp	x4, x5, [x1], #16
	ldr	x6, [x0, #200]
	eor	V5.16B, V5.16B, V5.16B
	eor	x7, x7, x7
	eor	V6.16B, V6.16B, V6.16B
	eor	x8, x8, x8
	eor	V7.16B, V7.16B, V7.16B
	eor	x9, x9, x9
	eor	V8.16B, V8.16B, V8.16B
	eor	x10, x10, x10
	eor	V9.16B, V9.16B, V9.16B
	eor	x11, x11, x11
	eor	V10.16B, V10.16B, V10.16B
	eor	x12, x12, x12
	eor	V11.16B, V11.16B, V11.16B
	eor	x13, x13, x13
	eor	V12.16B, V12.16B, V12.16B
	eor	x14, x14, x14
	eor	V13.16B, V13.16B, V13.16B
	eor	x15, x15, x15
	eor	V14.16B, V14.16B, V14.16B
	eor	x16, x16, x16
	eor	V15.16B, V15.16B, V15.16B
	eor	x17, x17, x17
	eor	V16.16B, V16.16B, V16.16B
	eor	x19, x19, x19
	eor	V17.16B, V17.16B, V17.16B
	eor	x20, x20, x20
	eor	V18.16B, V18.16B, V18.16B
	eor	x21, x21, x21
	eor	V19.16B, V19.16B, V19.16B
	eor	x22, x22, x22
	movz	x23, #0x8000, lsl 48
	eor	V21.16B, V21.16B, V21.16B
	eor	x24, x24, x24
	eor	V22.16B, V22.16B, V22.16B
	eor	x25, x25, x25
	eor	V23.16B, V23.16B, V23.16B
	eor	x26, x26, x26
	eor	V24.16B, V24.16B, V24.16B
	eor	x27, x27, x27
	dup	V0.2D, x2
	dup	V1.2D, x3
	dup	V2.2D, x4
	dup	V3.2D, x5
	dup	V20.2D, x23
	mov	x1, #24
	; Start of 24 rounds
L_SHA3_shake128_blocksx3_seed_neon_begin
	stp	x28, x1, [x29, #48]
	; Col Mix NEON
	eor	V30.16B, V4.16B, V9.16B
	eor	x0, x6, x11
	eor	V27.16B, V1.16B, V6.16B
	eor	x30, x2, x7
	eor	V30.16B, V30.16B, V14.16B
	eor	x28, x4, x9
	eor	V27.16B, V27.16B, V11.16B
	eor	x0, x0, x16
	eor	V30.16B, V30.16B, V19.16B
	eor	x30, x30, x12
	eor	V27.16B, V27.16B, V16.16B
	eor	x28, x28, x14
	eor	V30.16B, V30.16B, V24.16B
	eor	x0, x0, x22
	eor	V27.16B, V27.16B, V21.16B
	eor	x30, x30, x17
	ushr	V25.2D, V27.2D, #63
	eor	x28, x28, x20
	sli	V25.2D, V27.2D, #1
	eor	x0, x0, x27
	eor	V25.16B, V25.16B, V30.16B
	eor	x30, x30, x23
	eor	V31.16B, V0.16B, V5.16B
	eor	x28, x28, x25
	eor	V28.16B, V2.16B, V7.16B
	str	x0, [x29, #32]
	eor	V31.16B, V31.16B, V10.16B
	str	x28, [x29, #24]
	eor	V28.16B, V28.16B, V12.16B
	eor	x1, x3, x8
	eor	V31.16B, V31.16B, V15.16B
	eor	x28, x5, x10
	eor	V28.16B, V28.16B, V17.16B
	eor	x1, x1, x13
	eor	V31.16B, V31.16B, V20.16B
	eor	x28, x28, x15
	eor	V28.16B, V28.16B, V22.16B
	eor	x1, x1, x19
	ushr	V29.2D, V30.2D, #63
	eor	x28, x28, x21
	ushr	V26.2D, V28.2D, #63
	eor	x1, x1, x24
	sli	V29.2D, V30.2D, #1
	eor	x28, x28, x26
	sli	V26.2D, V28.2D, #1
	eor	x0, x0, x1, ror 63
	eor	V28.16B, V28.16B, V29.16B
	eor	x1, x1, x28, ror 63
	eor	V29.16B, V3.16B, V8.16B
	eor	x2, x2, x0
	eor	V26.16B, V26.16B, V31.16B
	eor	x7, x7, x0
	eor	V29.16B, V29.16B, V13.16B
	eor	x12, x12, x0
	eor	V29.16B, V29.16B, V18.16B
	eor	x17, x17, x0
	eor	V29.16B, V29.16B, V23.16B
	eor	x23, x23, x0
	ushr	V30.2D, V29.2D, #63
	eor	x4, x4, x1
	sli	V30.2D, V29.2D, #1
	eor	x9, x9, x1
	eor	V27.16B, V27.16B, V30.16B
	eor	x14, x14, x1
	ushr	V30.2D, V31.2D, #63
	eor	x20, x20, x1
	sli	V30.2D, V31.2D, #1
	eor	x25, x25, x1
	eor	V29.16B, V29.16B, V30.16B
	ldr	x0, [x29, #32]
	; Swap Rotate NEON
	eor	V0.16B, V0.16B, V25.16B
	eor	V31.16B, V1.16B, V26.16B
	ldr	x1, [x29, #24]
	eor	V6.16B, V6.16B, V26.16B
	eor	x28, x28, x30, ror 63
	ushr	V30.2D, V31.2D, #63
	eor	x30, x30, x1, ror 63
	ushr	V1.2D, V6.2D, #20
	eor	x1, x1, x0, ror 63
	sli	V30.2D, V31.2D, #1
	eor	x6, x6, x28
	sli	V1.2D, V6.2D, #44
	eor	x11, x11, x28
	eor	V31.16B, V9.16B, V29.16B
	eor	x16, x16, x28
	eor	V22.16B, V22.16B, V27.16B
	eor	x22, x22, x28
	ushr	V6.2D, V31.2D, #44
	eor	x27, x27, x28
	ushr	V9.2D, V22.2D, #3
	eor	x3, x3, x30
	sli	V6.2D, V31.2D, #20
	eor	x8, x8, x30
	sli	V9.2D, V22.2D, #61
	eor	x13, x13, x30
	eor	V31.16B, V14.16B, V29.16B
	eor	x19, x19, x30
	eor	V20.16B, V20.16B, V25.16B
	eor	x24, x24, x30
	ushr	V22.2D, V31.2D, #25
	eor	x5, x5, x1
	ushr	V14.2D, V20.2D, #46
	eor	x10, x10, x1
	sli	V22.2D, V31.2D, #39
	eor	x15, x15, x1
	sli	V14.2D, V20.2D, #18
	eor	x21, x21, x1
	eor	V31.16B, V2.16B, V27.16B
	eor	x26, x26, x1
	; Swap Rotate Base
	eor	V12.16B, V12.16B, V27.16B
	ror	x0, x3, #63
	ushr	V20.2D, V31.2D, #2
	ror	x3, x8, #20
	ushr	V2.2D, V12.2D, #21
	ror	x8, x11, #44
	sli	V20.2D, V31.2D, #62
	ror	x11, x25, #3
	sli	V2.2D, V12.2D, #43
	ror	x25, x16, #25
	eor	V31.16B, V13.16B, V28.16B
	ror	x16, x23, #46
	eor	V19.16B, V19.16B, V29.16B
	ror	x23, x4, #2
	ushr	V12.2D, V31.2D, #39
	ror	x4, x14, #21
	ushr	V13.2D, V19.2D, #56
	ror	x14, x15, #39
	sli	V12.2D, V31.2D, #25
	ror	x15, x22, #56
	sli	V13.2D, V19.2D, #8
	ror	x22, x26, #8
	eor	V31.16B, V23.16B, V28.16B
	ror	x26, x17, #23
	eor	V15.16B, V15.16B, V25.16B
	ror	x17, x6, #37
	ushr	V19.2D, V31.2D, #8
	ror	x6, x27, #50
	ushr	V23.2D, V15.2D, #23
	ror	x27, x24, #62
	sli	V19.2D, V31.2D, #56
	ror	x24, x10, #9
	sli	V23.2D, V15.2D, #41
	ror	x10, x19, #19
	eor	V31.16B, V4.16B, V29.16B
	ror	x19, x7, #28
	eor	V24.16B, V24.16B, V29.16B
	ror	x7, x5, #36
	ushr	V15.2D, V31.2D, #37
	ror	x5, x21, #43
	ushr	V4.2D, V24.2D, #50
	ror	x21, x20, #49
	sli	V15.2D, V31.2D, #27
	ror	x20, x13, #54
	sli	V4.2D, V24.2D, #14
	ror	x13, x9, #58
	eor	V31.16B, V21.16B, V26.16B
	ror	x9, x12, #61
	; Row Mix Base
	eor	V8.16B, V8.16B, V28.16B
	bic	x12, x4, x3
	ushr	V24.2D, V31.2D, #62
	bic	x1, x5, x4
	ushr	V21.2D, V8.2D, #9
	bic	x28, x2, x6
	sli	V24.2D, V31.2D, #2
	bic	x30, x3, x2
	sli	V21.2D, V8.2D, #55
	eor	x2, x2, x12
	eor	V31.16B, V16.16B, V26.16B
	eor	x3, x3, x1
	eor	V5.16B, V5.16B, V25.16B
	bic	x12, x6, x5
	ushr	V8.2D, V31.2D, #19
	eor	x5, x5, x28
	ushr	V16.2D, V5.2D, #28
	eor	x4, x4, x12
	sli	V8.2D, V31.2D, #45
	eor	x6, x6, x30
	sli	V16.2D, V5.2D, #36
	bic	x12, x9, x8
	eor	V31.16B, V3.16B, V28.16B
	bic	x1, x10, x9
	eor	V18.16B, V18.16B, V28.16B
	bic	x28, x7, x11
	ushr	V5.2D, V31.2D, #36
	bic	x30, x8, x7
	ushr	V3.2D, V18.2D, #43
	eor	x7, x7, x12
	sli	V5.2D, V31.2D, #28
	eor	x8, x8, x1
	sli	V3.2D, V18.2D, #21
	bic	x12, x11, x10
	eor	V31.16B, V17.16B, V27.16B
	eor	x10, x10, x28
	eor	V11.16B, V11.16B, V26.16B
	eor	x9, x9, x12
	ushr	V18.2D, V31.2D, #49
	eor	x11, x11, x30
	ushr	V17.2D, V11.2D, #54
	bic	x12, x14, x13
	sli	V18.2D, V31.2D, #15
	bic	x1, x15, x14
	sli	V17.2D, V11.2D, #10
	bic	x28, x0, x16
	eor	V31.16B, V7.16B, V27.16B
	bic	x30, x13, x0
	eor	V10.16B, V10.16B, V25.16B
	eor	x12, x0, x12
	ushr	V11.2D, V31.2D, #58
	eor	x13, x13, x1
	ushr	V7.2D, V10.2D, #61
	bic	x0, x16, x15
	sli	V11.2D, V31.2D, #6
	eor	x15, x15, x28
	sli	V7.2D, V10.2D, #3
	eor	x14, x14, x0
	; Row Mix NEON
	bic	V25.16B, V2.16B, V1.16B
	eor	x16, x16, x30
	bic	V26.16B, V3.16B, V2.16B
	bic	x0, x20, x19
	bic	V27.16B, V4.16B, V3.16B
	bic	x1, x21, x20
	bic	V28.16B, V0.16B, V4.16B
	bic	x28, x17, x22
	bic	V29.16B, V1.16B, V0.16B
	bic	x30, x19, x17
	eor	V0.16B, V0.16B, V25.16B
	eor	x17, x17, x0
	eor	V1.16B, V1.16B, V26.16B
	eor	x19, x19, x1
	eor	V2.16B, V2.16B, V27.16B
	bic	x0, x22, x21
	eor	V3.16B, V3.16B, V28.16B
	eor	x21, x21, x28
	eor	V4.16B, V4.16B, V29.16B
	eor	x20, x20, x0
	bic	V25.16B, V7.16B, V6.16B
	eor	x22, x22, x30
	bic	V26.16B, V8.16B, V7.16B
	bic	x0, x25, x24
	bic	V27.16B, V9.16B, V8.16B
	bic	x1, x26, x25
	bic	V28.16B, V5.16B, V9.16B
	bic	x28, x23, x27
	bic	V29.16B, V6.16B, V5.16B
	bic	x30, x24, x23
	eor	V5.16B, V5.16B, V25.16B
	eor	x23, x23, x0
	eor	V6.16B, V6.16B, V26.16B
	eor	x24, x24, x1
	eor	V7.16B, V7.16B, V27.16B
	bic	x0, x27, x26
	eor	V8.16B, V8.16B, V28.16B
	eor	x26, x26, x28
	eor	V9.16B, V9.16B, V29.16B
	eor	x25, x25, x0
	bic	V25.16B, V12.16B, V11.16B
	eor	x27, x27, x30
	bic	V26.16B, V13.16B, V12.16B
	bic	V27.16B, V14.16B, V13.16B
	bic	V28.16B, V30.16B, V14.16B
	bic	V29.16B, V11.16B, V30.16B
	eor	V10.16B, V30.16B, V25.16B
	eor	V11.16B, V11.16B, V26.16B
	eor	V12.16B, V12.16B, V27.16B
	eor	V13.16B, V13.16B, V28.16B
	eor	V14.16B, V14.16B, V29.16B
	bic	V25.16B, V17.16B, V16.16B
	bic	V26.16B, V18.16B, V17.16B
	bic	V27.16B, V19.16B, V18.16B
	bic	V28.16B, V15.16B, V19.16B
	bic	V29.16B, V16.16B, V15.16B
	eor	V15.16B, V15.16B, V25.16B
	eor	V16.16B, V16.16B, V26.16B
	eor	V17.16B, V17.16B, V27.16B
	eor	V18.16B, V18.16B, V28.16B
	eor	V19.16B, V19.16B, V29.16B
	bic	V25.16B, V22.16B, V21.16B
	bic	V26.16B, V23.16B, V22.16B
	bic	V27.16B, V24.16B, V23.16B
	bic	V28.16B, V20.16B, V24.16B
	bic	V29.16B, V21.16B, V20.16B
	eor	V20.16B, V20.16B, V25.16B
	eor	V21.16B, V21.16B, V26.16B
	eor	V22.16B, V22.16B, V27.16B
	eor	V23.16B, V23.16B, V28.16B
	eor	V24.16B, V24.16B, V29.16B
	; Done transforming
	ldp	x28, x1, [x29, #48]
	ldr	x0, [x28], #8
	subs	x1, x1, #1
	mov	V30.D[0], x0
	mov	V30.D[1], x0
	eor	x2, x2, x0
	eor	V0.16B, V0.16B, V30.16B
	bne	L_SHA3_shake128_blocksx3_seed_neon_begin
	ldr	x0, [x29, #40]
	st4	{V0.D, V1.D, V2.D, V3.D}[0], [x0], #32
	st4	{V4.D, V5.D, V6.D, V7.D}[0], [x0], #32
	st4	{V8.D, V9.D, V10.D, V11.D}[0], [x0], #32
	st4	{V12.D, V13.D, V14.D, V15.D}[0], [x0], #32
	st4	{V16.D, V17.D, V18.D, V19.D}[0], [x0], #32
	st4	{V20.D, V21.D, V22.D, V23.D}[0], [x0], #32
	st1	{V24.D}[0], [x0]
	add	x0, x0, #8
	st4	{V0.D, V1.D, V2.D, V3.D}[1], [x0], #32
	st4	{V4.D, V5.D, V6.D, V7.D}[1], [x0], #32
	st4	{V8.D, V9.D, V10.D, V11.D}[1], [x0], #32
	st4	{V12.D, V13.D, V14.D, V15.D}[1], [x0], #32
	st4	{V16.D, V17.D, V18.D, V19.D}[1], [x0], #32
	st4	{V20.D, V21.D, V22.D, V23.D}[1], [x0], #32
	st1	{V24.D}[1], [x0]
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
	ldp	D8, D9, [x29, #160]
	ldp	D10, D11, [x29, #176]
	ldp	D12, D13, [x29, #192]
	ldp	D14, D15, [x29, #208]
	ldp	x29, x30, [sp], #0xe0
	ret
	ENDP
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mlkem_shake256_blocksx3_seed_neon
mlkem_shake256_blocksx3_seed_neon PROC
	stp	x29, x30, [sp, #-224]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #72]
	stp	x20, x21, [x29, #88]
	stp	x22, x23, [x29, #104]
	stp	x24, x25, [x29, #120]
	stp	x26, x27, [x29, #136]
	str	x28, [x29, #152]
	stp	D8, D9, [x29, #160]
	stp	D10, D11, [x29, #176]
	stp	D12, D13, [x29, #192]
	stp	D14, D15, [x29, #208]
	adrp	x28, L_sha3_aarch64_r
	add	x28, x28, L_sha3_aarch64_r
	str	x0, [x29, #40]
	add	x0, x0, #32
	ld1	{V4.D}[0], [x0]
	ldp	x2, x3, [x1], #16
	add	x0, x0, #0xc8
	ld1	{V4.D}[1], [x0]
	ldp	x4, x5, [x1], #16
	ldr	x6, [x0, #200]
	eor	V5.16B, V5.16B, V5.16B
	eor	x7, x7, x7
	eor	V6.16B, V6.16B, V6.16B
	eor	x8, x8, x8
	eor	V7.16B, V7.16B, V7.16B
	eor	x9, x9, x9
	eor	V8.16B, V8.16B, V8.16B
	eor	x10, x10, x10
	eor	V9.16B, V9.16B, V9.16B
	eor	x11, x11, x11
	eor	V10.16B, V10.16B, V10.16B
	eor	x12, x12, x12
	eor	V11.16B, V11.16B, V11.16B
	eor	x13, x13, x13
	eor	V12.16B, V12.16B, V12.16B
	eor	x14, x14, x14
	eor	V13.16B, V13.16B, V13.16B
	eor	x15, x15, x15
	eor	V14.16B, V14.16B, V14.16B
	eor	x16, x16, x16
	eor	V15.16B, V15.16B, V15.16B
	eor	x17, x17, x17
	movz	x19, #0x8000, lsl 48
	eor	V17.16B, V17.16B, V17.16B
	eor	x20, x20, x20
	eor	V18.16B, V18.16B, V18.16B
	eor	x21, x21, x21
	eor	V19.16B, V19.16B, V19.16B
	eor	x22, x22, x22
	eor	V20.16B, V20.16B, V20.16B
	eor	x23, x23, x23
	eor	V21.16B, V21.16B, V21.16B
	eor	x24, x24, x24
	eor	V22.16B, V22.16B, V22.16B
	eor	x25, x25, x25
	eor	V23.16B, V23.16B, V23.16B
	eor	x26, x26, x26
	eor	V24.16B, V24.16B, V24.16B
	eor	x27, x27, x27
	dup	V0.2D, x2
	dup	V1.2D, x3
	dup	V2.2D, x4
	dup	V3.2D, x5
	dup	V16.2D, x19
	mov	x1, #24
	; Start of 24 rounds
L_SHA3_shake256_blocksx3_seed_neon_begin
	stp	x28, x1, [x29, #48]
	; Col Mix NEON
	eor	V30.16B, V4.16B, V9.16B
	eor	x0, x6, x11
	eor	V27.16B, V1.16B, V6.16B
	eor	x30, x2, x7
	eor	V30.16B, V30.16B, V14.16B
	eor	x28, x4, x9
	eor	V27.16B, V27.16B, V11.16B
	eor	x0, x0, x16
	eor	V30.16B, V30.16B, V19.16B
	eor	x30, x30, x12
	eor	V27.16B, V27.16B, V16.16B
	eor	x28, x28, x14
	eor	V30.16B, V30.16B, V24.16B
	eor	x0, x0, x22
	eor	V27.16B, V27.16B, V21.16B
	eor	x30, x30, x17
	ushr	V25.2D, V27.2D, #63
	eor	x28, x28, x20
	sli	V25.2D, V27.2D, #1
	eor	x0, x0, x27
	eor	V25.16B, V25.16B, V30.16B
	eor	x30, x30, x23
	eor	V31.16B, V0.16B, V5.16B
	eor	x28, x28, x25
	eor	V28.16B, V2.16B, V7.16B
	str	x0, [x29, #32]
	eor	V31.16B, V31.16B, V10.16B
	str	x28, [x29, #24]
	eor	V28.16B, V28.16B, V12.16B
	eor	x1, x3, x8
	eor	V31.16B, V31.16B, V15.16B
	eor	x28, x5, x10
	eor	V28.16B, V28.16B, V17.16B
	eor	x1, x1, x13
	eor	V31.16B, V31.16B, V20.16B
	eor	x28, x28, x15
	eor	V28.16B, V28.16B, V22.16B
	eor	x1, x1, x19
	ushr	V29.2D, V30.2D, #63
	eor	x28, x28, x21
	ushr	V26.2D, V28.2D, #63
	eor	x1, x1, x24
	sli	V29.2D, V30.2D, #1
	eor	x28, x28, x26
	sli	V26.2D, V28.2D, #1
	eor	x0, x0, x1, ror 63
	eor	V28.16B, V28.16B, V29.16B
	eor	x1, x1, x28, ror 63
	eor	V29.16B, V3.16B, V8.16B
	eor	x2, x2, x0
	eor	V26.16B, V26.16B, V31.16B
	eor	x7, x7, x0
	eor	V29.16B, V29.16B, V13.16B
	eor	x12, x12, x0
	eor	V29.16B, V29.16B, V18.16B
	eor	x17, x17, x0
	eor	V29.16B, V29.16B, V23.16B
	eor	x23, x23, x0
	ushr	V30.2D, V29.2D, #63
	eor	x4, x4, x1
	sli	V30.2D, V29.2D, #1
	eor	x9, x9, x1
	eor	V27.16B, V27.16B, V30.16B
	eor	x14, x14, x1
	ushr	V30.2D, V31.2D, #63
	eor	x20, x20, x1
	sli	V30.2D, V31.2D, #1
	eor	x25, x25, x1
	eor	V29.16B, V29.16B, V30.16B
	ldr	x0, [x29, #32]
	; Swap Rotate NEON
	eor	V0.16B, V0.16B, V25.16B
	eor	V31.16B, V1.16B, V26.16B
	ldr	x1, [x29, #24]
	eor	V6.16B, V6.16B, V26.16B
	eor	x28, x28, x30, ror 63
	ushr	V30.2D, V31.2D, #63
	eor	x30, x30, x1, ror 63
	ushr	V1.2D, V6.2D, #20
	eor	x1, x1, x0, ror 63
	sli	V30.2D, V31.2D, #1
	eor	x6, x6, x28
	sli	V1.2D, V6.2D, #44
	eor	x11, x11, x28
	eor	V31.16B, V9.16B, V29.16B
	eor	x16, x16, x28
	eor	V22.16B, V22.16B, V27.16B
	eor	x22, x22, x28
	ushr	V6.2D, V31.2D, #44
	eor	x27, x27, x28
	ushr	V9.2D, V22.2D, #3
	eor	x3, x3, x30
	sli	V6.2D, V31.2D, #20
	eor	x8, x8, x30
	sli	V9.2D, V22.2D, #61
	eor	x13, x13, x30
	eor	V31.16B, V14.16B, V29.16B
	eor	x19, x19, x30
	eor	V20.16B, V20.16B, V25.16B
	eor	x24, x24, x30
	ushr	V22.2D, V31.2D, #25
	eor	x5, x5, x1
	ushr	V14.2D, V20.2D, #46
	eor	x10, x10, x1
	sli	V22.2D, V31.2D, #39
	eor	x15, x15, x1
	sli	V14.2D, V20.2D, #18
	eor	x21, x21, x1
	eor	V31.16B, V2.16B, V27.16B
	eor	x26, x26, x1
	; Swap Rotate Base
	eor	V12.16B, V12.16B, V27.16B
	ror	x0, x3, #63
	ushr	V20.2D, V31.2D, #2
	ror	x3, x8, #20
	ushr	V2.2D, V12.2D, #21
	ror	x8, x11, #44
	sli	V20.2D, V31.2D, #62
	ror	x11, x25, #3
	sli	V2.2D, V12.2D, #43
	ror	x25, x16, #25
	eor	V31.16B, V13.16B, V28.16B
	ror	x16, x23, #46
	eor	V19.16B, V19.16B, V29.16B
	ror	x23, x4, #2
	ushr	V12.2D, V31.2D, #39
	ror	x4, x14, #21
	ushr	V13.2D, V19.2D, #56
	ror	x14, x15, #39
	sli	V12.2D, V31.2D, #25
	ror	x15, x22, #56
	sli	V13.2D, V19.2D, #8
	ror	x22, x26, #8
	eor	V31.16B, V23.16B, V28.16B
	ror	x26, x17, #23
	eor	V15.16B, V15.16B, V25.16B
	ror	x17, x6, #37
	ushr	V19.2D, V31.2D, #8
	ror	x6, x27, #50
	ushr	V23.2D, V15.2D, #23
	ror	x27, x24, #62
	sli	V19.2D, V31.2D, #56
	ror	x24, x10, #9
	sli	V23.2D, V15.2D, #41
	ror	x10, x19, #19
	eor	V31.16B, V4.16B, V29.16B
	ror	x19, x7, #28
	eor	V24.16B, V24.16B, V29.16B
	ror	x7, x5, #36
	ushr	V15.2D, V31.2D, #37
	ror	x5, x21, #43
	ushr	V4.2D, V24.2D, #50
	ror	x21, x20, #49
	sli	V15.2D, V31.2D, #27
	ror	x20, x13, #54
	sli	V4.2D, V24.2D, #14
	ror	x13, x9, #58
	eor	V31.16B, V21.16B, V26.16B
	ror	x9, x12, #61
	; Row Mix Base
	eor	V8.16B, V8.16B, V28.16B
	bic	x12, x4, x3
	ushr	V24.2D, V31.2D, #62
	bic	x1, x5, x4
	ushr	V21.2D, V8.2D, #9
	bic	x28, x2, x6
	sli	V24.2D, V31.2D, #2
	bic	x30, x3, x2
	sli	V21.2D, V8.2D, #55
	eor	x2, x2, x12
	eor	V31.16B, V16.16B, V26.16B
	eor	x3, x3, x1
	eor	V5.16B, V5.16B, V25.16B
	bic	x12, x6, x5
	ushr	V8.2D, V31.2D, #19
	eor	x5, x5, x28
	ushr	V16.2D, V5.2D, #28
	eor	x4, x4, x12
	sli	V8.2D, V31.2D, #45
	eor	x6, x6, x30
	sli	V16.2D, V5.2D, #36
	bic	x12, x9, x8
	eor	V31.16B, V3.16B, V28.16B
	bic	x1, x10, x9
	eor	V18.16B, V18.16B, V28.16B
	bic	x28, x7, x11
	ushr	V5.2D, V31.2D, #36
	bic	x30, x8, x7
	ushr	V3.2D, V18.2D, #43
	eor	x7, x7, x12
	sli	V5.2D, V31.2D, #28
	eor	x8, x8, x1
	sli	V3.2D, V18.2D, #21
	bic	x12, x11, x10
	eor	V31.16B, V17.16B, V27.16B
	eor	x10, x10, x28
	eor	V11.16B, V11.16B, V26.16B
	eor	x9, x9, x12
	ushr	V18.2D, V31.2D, #49
	eor	x11, x11, x30
	ushr	V17.2D, V11.2D, #54
	bic	x12, x14, x13
	sli	V18.2D, V31.2D, #15
	bic	x1, x15, x14
	sli	V17.2D, V11.2D, #10
	bic	x28, x0, x16
	eor	V31.16B, V7.16B, V27.16B
	bic	x30, x13, x0
	eor	V10.16B, V10.16B, V25.16B
	eor	x12, x0, x12
	ushr	V11.2D, V31.2D, #58
	eor	x13, x13, x1
	ushr	V7.2D, V10.2D, #61
	bic	x0, x16, x15
	sli	V11.2D, V31.2D, #6
	eor	x15, x15, x28
	sli	V7.2D, V10.2D, #3
	eor	x14, x14, x0
	; Row Mix NEON
	bic	V25.16B, V2.16B, V1.16B
	eor	x16, x16, x30
	bic	V26.16B, V3.16B, V2.16B
	bic	x0, x20, x19
	bic	V27.16B, V4.16B, V3.16B
	bic	x1, x21, x20
	bic	V28.16B, V0.16B, V4.16B
	bic	x28, x17, x22
	bic	V29.16B, V1.16B, V0.16B
	bic	x30, x19, x17
	eor	V0.16B, V0.16B, V25.16B
	eor	x17, x17, x0
	eor	V1.16B, V1.16B, V26.16B
	eor	x19, x19, x1
	eor	V2.16B, V2.16B, V27.16B
	bic	x0, x22, x21
	eor	V3.16B, V3.16B, V28.16B
	eor	x21, x21, x28
	eor	V4.16B, V4.16B, V29.16B
	eor	x20, x20, x0
	bic	V25.16B, V7.16B, V6.16B
	eor	x22, x22, x30
	bic	V26.16B, V8.16B, V7.16B
	bic	x0, x25, x24
	bic	V27.16B, V9.16B, V8.16B
	bic	x1, x26, x25
	bic	V28.16B, V5.16B, V9.16B
	bic	x28, x23, x27
	bic	V29.16B, V6.16B, V5.16B
	bic	x30, x24, x23
	eor	V5.16B, V5.16B, V25.16B
	eor	x23, x23, x0
	eor	V6.16B, V6.16B, V26.16B
	eor	x24, x24, x1
	eor	V7.16B, V7.16B, V27.16B
	bic	x0, x27, x26
	eor	V8.16B, V8.16B, V28.16B
	eor	x26, x26, x28
	eor	V9.16B, V9.16B, V29.16B
	eor	x25, x25, x0
	bic	V25.16B, V12.16B, V11.16B
	eor	x27, x27, x30
	bic	V26.16B, V13.16B, V12.16B
	bic	V27.16B, V14.16B, V13.16B
	bic	V28.16B, V30.16B, V14.16B
	bic	V29.16B, V11.16B, V30.16B
	eor	V10.16B, V30.16B, V25.16B
	eor	V11.16B, V11.16B, V26.16B
	eor	V12.16B, V12.16B, V27.16B
	eor	V13.16B, V13.16B, V28.16B
	eor	V14.16B, V14.16B, V29.16B
	bic	V25.16B, V17.16B, V16.16B
	bic	V26.16B, V18.16B, V17.16B
	bic	V27.16B, V19.16B, V18.16B
	bic	V28.16B, V15.16B, V19.16B
	bic	V29.16B, V16.16B, V15.16B
	eor	V15.16B, V15.16B, V25.16B
	eor	V16.16B, V16.16B, V26.16B
	eor	V17.16B, V17.16B, V27.16B
	eor	V18.16B, V18.16B, V28.16B
	eor	V19.16B, V19.16B, V29.16B
	bic	V25.16B, V22.16B, V21.16B
	bic	V26.16B, V23.16B, V22.16B
	bic	V27.16B, V24.16B, V23.16B
	bic	V28.16B, V20.16B, V24.16B
	bic	V29.16B, V21.16B, V20.16B
	eor	V20.16B, V20.16B, V25.16B
	eor	V21.16B, V21.16B, V26.16B
	eor	V22.16B, V22.16B, V27.16B
	eor	V23.16B, V23.16B, V28.16B
	eor	V24.16B, V24.16B, V29.16B
	; Done transforming
	ldp	x28, x1, [x29, #48]
	ldr	x0, [x28], #8
	subs	x1, x1, #1
	mov	V30.D[0], x0
	mov	V30.D[1], x0
	eor	x2, x2, x0
	eor	V0.16B, V0.16B, V30.16B
	bne	L_SHA3_shake256_blocksx3_seed_neon_begin
	ldr	x0, [x29, #40]
	st4	{V0.D, V1.D, V2.D, V3.D}[0], [x0], #32
	st4	{V4.D, V5.D, V6.D, V7.D}[0], [x0], #32
	st4	{V8.D, V9.D, V10.D, V11.D}[0], [x0], #32
	st4	{V12.D, V13.D, V14.D, V15.D}[0], [x0], #32
	st4	{V16.D, V17.D, V18.D, V19.D}[0], [x0], #32
	st4	{V20.D, V21.D, V22.D, V23.D}[0], [x0], #32
	st1	{V24.D}[0], [x0]
	add	x0, x0, #8
	st4	{V0.D, V1.D, V2.D, V3.D}[1], [x0], #32
	st4	{V4.D, V5.D, V6.D, V7.D}[1], [x0], #32
	st4	{V8.D, V9.D, V10.D, V11.D}[1], [x0], #32
	st4	{V12.D, V13.D, V14.D, V15.D}[1], [x0], #32
	st4	{V16.D, V17.D, V18.D, V19.D}[1], [x0], #32
	st4	{V20.D, V21.D, V22.D, V23.D}[1], [x0], #32
	st1	{V24.D}[1], [x0]
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
	ldp	D8, D9, [x29, #160]
	ldp	D10, D11, [x29, #176]
	ldp	D12, D13, [x29, #192]
	ldp	D14, D15, [x29, #208]
	ldp	x29, x30, [sp], #0xe0
	ret
	ENDP
	ENDIF
	ENDIF
	END
