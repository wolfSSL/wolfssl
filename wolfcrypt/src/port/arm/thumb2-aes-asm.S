/* thumb2-aes-asm
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
 *   ruby ./aes/aes.rb \
 *       thumb2 ../wolfssl/wolfcrypt/src/port/arm/thumb2-aes-asm.S
 */

#include <wolfssl/wolfcrypt/libwolfssl_sources_asm.h>

#ifdef WOLFSSL_ARMASM
#ifdef WOLFSSL_ARMASM_THUMB2
#ifndef WOLFSSL_ARMASM_INLINE
	.thumb
	.syntax unified
#ifndef NO_AES
#ifdef HAVE_AES_DECRYPT
#ifndef __APPLE__
	.text
	.type	L_AES_Thumb2_td_data, %object
	.size	L_AES_Thumb2_td_data, 1024
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	/* 8-byte aligned, 64-bit aligned */
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_AES_Thumb2_td_data:
	.long	0x5051f4a7,0x537e4165,0xc31a17a4,0x963a275e
	.long	0xcb3bab6b,0xf11f9d45,0xabacfa58,0x934be303
	.long	0x552030fa,0xf6ad766d,0x9188cc76,0x25f5024c
	.long	0xfc4fe5d7,0xd7c52acb,0x80263544,0x8fb562a3
	.long	0x49deb15a,0x6725ba1b,0x9845ea0e,0xe15dfec0
	.long	0x02c32f75,0x12814cf0,0xa38d4697,0xc66bd3f9
	.long	0xe7038f5f,0x9515929c,0xebbf6d7a,0xda955259
	.long	0x2dd4be83,0xd3587421,0x2949e069,0x448ec9c8
	.long	0x6a75c289,0x78f48e79,0x6b99583e,0xdd27b971
	.long	0xb6bee14f,0x17f088ad,0x66c920ac,0xb47dce3a
	.long	0x1863df4a,0x82e51a31,0x60975133,0x4562537f
	.long	0xe0b16477,0x84bb6bae,0x1cfe81a0,0x94f9082b
	.long	0x58704868,0x198f45fd,0x8794de6c,0xb7527bf8
	.long	0x23ab73d3,0xe2724b02,0x57e31f8f,0x2a6655ab
	.long	0x07b2eb28,0x032fb5c2,0x9a86c57b,0xa5d33708
	.long	0xf2302887,0xb223bfa5,0xba02036a,0x5ced1682
	.long	0x2b8acf1c,0x92a779b4,0xf0f307f2,0xa14e69e2
	.long	0xcd65daf4,0xd50605be,0x1fd13462,0x8ac4a6fe
	.long	0x9d342e53,0xa0a2f355,0x32058ae1,0x75a4f6eb
	.long	0x390b83ec,0xaa4060ef,0x065e719f,0x51bd6e10
	.long	0xf93e218a,0x3d96dd06,0xaedd3e05,0x464de6bd
	.long	0xb591548d,0x0571c45d,0x6f0406d4,0xff605015
	.long	0x241998fb,0x97d6bde9,0xcc894043,0x7767d99e
	.long	0xbdb0e842,0x8807898b,0x38e7195b,0xdb79c8ee
	.long	0x47a17c0a,0xe97c420f,0xc9f8841e,0x00000000
	.long	0x83098086,0x48322bed,0xac1e1170,0x4e6c5a72
	.long	0xfbfd0eff,0x560f8538,0x1e3daed5,0x27362d39
	.long	0x640a0fd9,0x21685ca6,0xd19b5b54,0x3a24362e
	.long	0xb10c0a67,0x0f9357e7,0xd2b4ee96,0x9e1b9b91
	.long	0x4f80c0c5,0xa261dc20,0x695a774b,0x161c121a
	.long	0x0ae293ba,0xe5c0a02a,0x433c22e0,0x1d121b17
	.long	0x0b0e090d,0xadf28bc7,0xb92db6a8,0xc8141ea9
	.long	0x8557f119,0x4caf7507,0xbbee99dd,0xfda37f60
	.long	0x9ff70126,0xbc5c72f5,0xc544663b,0x345bfb7e
	.long	0x768b4329,0xdccb23c6,0x68b6edfc,0x63b8e4f1
	.long	0xcad731dc,0x10426385,0x40139722,0x2084c611
	.long	0x7d854a24,0xf8d2bb3d,0x11aef932,0x6dc729a1
	.long	0x4b1d9e2f,0xf3dcb230,0xec0d8652,0xd077c1e3
	.long	0x6c2bb316,0x99a970b9,0xfa119448,0x2247e964
	.long	0xc4a8fc8c,0x1aa0f03f,0xd8567d2c,0xef223390
	.long	0xc787494e,0xc1d938d1,0xfe8ccaa2,0x3698d40b
	.long	0xcfa6f581,0x28a57ade,0x26dab78e,0xa43fadbf
	.long	0xe42c3a9d,0x0d507892,0x9b6a5fcc,0x62547e46
	.long	0xc2f68d13,0xe890d8b8,0x5e2e39f7,0xf582c3af
	.long	0xbe9f5d80,0x7c69d093,0xa96fd52d,0xb3cf2512
	.long	0x3bc8ac99,0xa710187d,0x6ee89c63,0x7bdb3bbb
	.long	0x09cd2678,0xf46e5918,0x01ec9ab7,0xa8834f9a
	.long	0x65e6956e,0x7eaaffe6,0x0821bccf,0xe6ef15e8
	.long	0xd9bae79b,0xce4a6f36,0xd4ea9f09,0xd629b07c
	.long	0xaf31a4b2,0x312a3f23,0x30c6a594,0xc035a266
	.long	0x37744ebc,0xa6fc82ca,0xb0e090d0,0x1533a7d8
	.long	0x4af10498,0xf741ecda,0x0e7fcd50,0x2f1791f6
	.long	0x8d764dd6,0x4d43efb0,0x54ccaa4d,0xdfe49604
	.long	0xe39ed1b5,0x1b4c6a88,0xb8c12c1f,0x7f466551
	.long	0x049d5eea,0x5d018c35,0x73fa8774,0x2efb0b41
	.long	0x5ab3671d,0x5292dbd2,0x33e91056,0x136dd647
	.long	0x8c9ad761,0x7a37a10c,0x8e59f814,0x89eb133c
	.long	0xeecea927,0x35b761c9,0xede11ce5,0x3c7a47b1
	.long	0x599cd2df,0x3f55f273,0x791814ce,0xbf73c737
	.long	0xea53f7cd,0x5b5ffdaa,0x14df3d6f,0x867844db
	.long	0x81caaff3,0x3eb968c4,0x2c382434,0x5fc2a340
	.long	0x72161dc3,0x0cbce225,0x8b283c49,0x41ff0d95
	.long	0x7139a801,0xde080cb3,0x9cd8b4e4,0x906456c1
	.long	0x617bcb84,0x70d532b6,0x74486c5c,0x42d0b857
#endif /* HAVE_AES_DECRYPT */
#if defined(HAVE_AES_DECRYPT) || defined(HAVE_AES_CBC) || \
    defined(HAVE_AESCCM) || defined(HAVE_AESGCM) || \
    defined(WOLFSSL_AES_DIRECT) || defined(WOLFSSL_AES_COUNTER)
#ifndef __APPLE__
	.text
	.type	L_AES_Thumb2_te_data, %object
	.size	L_AES_Thumb2_te_data, 1024
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	/* 8-byte aligned, 64-bit aligned */
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_AES_Thumb2_te_data:
	.long	0xa5c66363,0x84f87c7c,0x99ee7777,0x8df67b7b
	.long	0x0dfff2f2,0xbdd66b6b,0xb1de6f6f,0x5491c5c5
	.long	0x50603030,0x03020101,0xa9ce6767,0x7d562b2b
	.long	0x19e7fefe,0x62b5d7d7,0xe64dabab,0x9aec7676
	.long	0x458fcaca,0x9d1f8282,0x4089c9c9,0x87fa7d7d
	.long	0x15effafa,0xebb25959,0xc98e4747,0x0bfbf0f0
	.long	0xec41adad,0x67b3d4d4,0xfd5fa2a2,0xea45afaf
	.long	0xbf239c9c,0xf753a4a4,0x96e47272,0x5b9bc0c0
	.long	0xc275b7b7,0x1ce1fdfd,0xae3d9393,0x6a4c2626
	.long	0x5a6c3636,0x417e3f3f,0x02f5f7f7,0x4f83cccc
	.long	0x5c683434,0xf451a5a5,0x34d1e5e5,0x08f9f1f1
	.long	0x93e27171,0x73abd8d8,0x53623131,0x3f2a1515
	.long	0x0c080404,0x5295c7c7,0x65462323,0x5e9dc3c3
	.long	0x28301818,0xa1379696,0x0f0a0505,0xb52f9a9a
	.long	0x090e0707,0x36241212,0x9b1b8080,0x3ddfe2e2
	.long	0x26cdebeb,0x694e2727,0xcd7fb2b2,0x9fea7575
	.long	0x1b120909,0x9e1d8383,0x74582c2c,0x2e341a1a
	.long	0x2d361b1b,0xb2dc6e6e,0xeeb45a5a,0xfb5ba0a0
	.long	0xf6a45252,0x4d763b3b,0x61b7d6d6,0xce7db3b3
	.long	0x7b522929,0x3edde3e3,0x715e2f2f,0x97138484
	.long	0xf5a65353,0x68b9d1d1,0x00000000,0x2cc1eded
	.long	0x60402020,0x1fe3fcfc,0xc879b1b1,0xedb65b5b
	.long	0xbed46a6a,0x468dcbcb,0xd967bebe,0x4b723939
	.long	0xde944a4a,0xd4984c4c,0xe8b05858,0x4a85cfcf
	.long	0x6bbbd0d0,0x2ac5efef,0xe54faaaa,0x16edfbfb
	.long	0xc5864343,0xd79a4d4d,0x55663333,0x94118585
	.long	0xcf8a4545,0x10e9f9f9,0x06040202,0x81fe7f7f
	.long	0xf0a05050,0x44783c3c,0xba259f9f,0xe34ba8a8
	.long	0xf3a25151,0xfe5da3a3,0xc0804040,0x8a058f8f
	.long	0xad3f9292,0xbc219d9d,0x48703838,0x04f1f5f5
	.long	0xdf63bcbc,0xc177b6b6,0x75afdada,0x63422121
	.long	0x30201010,0x1ae5ffff,0x0efdf3f3,0x6dbfd2d2
	.long	0x4c81cdcd,0x14180c0c,0x35261313,0x2fc3ecec
	.long	0xe1be5f5f,0xa2359797,0xcc884444,0x392e1717
	.long	0x5793c4c4,0xf255a7a7,0x82fc7e7e,0x477a3d3d
	.long	0xacc86464,0xe7ba5d5d,0x2b321919,0x95e67373
	.long	0xa0c06060,0x98198181,0xd19e4f4f,0x7fa3dcdc
	.long	0x66442222,0x7e542a2a,0xab3b9090,0x830b8888
	.long	0xca8c4646,0x29c7eeee,0xd36bb8b8,0x3c281414
	.long	0x79a7dede,0xe2bc5e5e,0x1d160b0b,0x76addbdb
	.long	0x3bdbe0e0,0x56643232,0x4e743a3a,0x1e140a0a
	.long	0xdb924949,0x0a0c0606,0x6c482424,0xe4b85c5c
	.long	0x5d9fc2c2,0x6ebdd3d3,0xef43acac,0xa6c46262
	.long	0xa8399191,0xa4319595,0x37d3e4e4,0x8bf27979
	.long	0x32d5e7e7,0x438bc8c8,0x596e3737,0xb7da6d6d
	.long	0x8c018d8d,0x64b1d5d5,0xd29c4e4e,0xe049a9a9
	.long	0xb4d86c6c,0xfaac5656,0x07f3f4f4,0x25cfeaea
	.long	0xafca6565,0x8ef47a7a,0xe947aeae,0x18100808
	.long	0xd56fbaba,0x88f07878,0x6f4a2525,0x725c2e2e
	.long	0x24381c1c,0xf157a6a6,0xc773b4b4,0x5197c6c6
	.long	0x23cbe8e8,0x7ca1dddd,0x9ce87474,0x213e1f1f
	.long	0xdd964b4b,0xdc61bdbd,0x860d8b8b,0x850f8a8a
	.long	0x90e07070,0x427c3e3e,0xc471b5b5,0xaacc6666
	.long	0xd8904848,0x05060303,0x01f7f6f6,0x121c0e0e
	.long	0xa3c26161,0x5f6a3535,0xf9ae5757,0xd069b9b9
	.long	0x91178686,0x5899c1c1,0x273a1d1d,0xb9279e9e
	.long	0x38d9e1e1,0x13ebf8f8,0xb32b9898,0x33221111
	.long	0xbbd26969,0x70a9d9d9,0x89078e8e,0xa7339494
	.long	0xb62d9b9b,0x223c1e1e,0x92158787,0x20c9e9e9
	.long	0x4987cece,0xffaa5555,0x78502828,0x7aa5dfdf
	.long	0x8f038c8c,0xf859a1a1,0x80098989,0x171a0d0d
	.long	0xda65bfbf,0x31d7e6e6,0xc6844242,0xb8d06868
	.long	0xc3824141,0xb0299999,0x775a2d2d,0x111e0f0f
	.long	0xcb7bb0b0,0xfca85454,0xd66dbbbb,0x3a2c1616
#endif /* HAVE_AES_DECRYPT || HAVE_AES_CBC || HAVE_AESCCM || HAVE_AESGCM ||
        * WOLFSSL_AES_DIRECT || WOLFSSL_AES_COUNTER */
#ifdef HAVE_AES_DECRYPT
#ifndef __APPLE__
	.text
	.type	L_AES_Thumb2_td, %object
	.size	L_AES_Thumb2_td, 12
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	/* 8-byte aligned, 64-bit aligned */
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_AES_Thumb2_td:
	.long	L_AES_Thumb2_td_data
#endif /* HAVE_AES_DECRYPT */
#if defined(HAVE_AES_DECRYPT) || defined(HAVE_AES_CBC) || \
    defined(HAVE_AESCCM) || defined(HAVE_AESGCM) || \
    defined(WOLFSSL_AES_DIRECT) || defined(WOLFSSL_AES_COUNTER)
#ifndef __APPLE__
	.text
	.type	L_AES_Thumb2_te, %object
	.size	L_AES_Thumb2_te, 12
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	/* 8-byte aligned, 64-bit aligned */
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_AES_Thumb2_te:
	.long	L_AES_Thumb2_te_data
#endif /* HAVE_AES_DECRYPT || HAVE_AES_CBC || HAVE_AESCCM || HAVE_AESGCM ||
        * WOLFSSL_AES_DIRECT || WOLFSSL_AES_COUNTER */
#ifdef HAVE_AES_DECRYPT
	.text
	.align	4
	.globl	AES_invert_key
	.type	AES_invert_key, %function
AES_invert_key:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	LDR	r12, L_AES_Thumb2_te
	LDR	lr, L_AES_Thumb2_td
	ADD	r10, r0, r1, LSL #4
	MOV	r11, r1
L_AES_invert_key_loop:
	LDM	r0, {r2, r3, r4, r5}
	LDM	r10, {r6, r7, r8, r9}
	STM	r10, {r2, r3, r4, r5}
	STM	r0!, {r6, r7, r8, r9}
	SUBS	r11, r11, #0x2
	SUB	r10, r10, #0x10
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_AES_invert_key_loop
#else
	BNE.N	L_AES_invert_key_loop
#endif
	SUB	r0, r0, r1, LSL #3
	ADD	r0, r0, #0x10
	SUB	r11, r1, #0x1
L_AES_invert_key_mix_loop:
	LDM	r0, {r2, r3, r4, r5}
	UBFX	r6, r2, #0, #8
	UBFX	r7, r2, #8, #8
	UBFX	r8, r2, #16, #8
	LSR	r9, r2, #24
	LDRB	r6, [r12, r6, LSL #2]
	LDRB	r7, [r12, r7, LSL #2]
	LDRB	r8, [r12, r8, LSL #2]
	LDRB	r9, [r12, r9, LSL #2]
	LDR	r6, [lr, r6, LSL #2]
	LDR	r7, [lr, r7, LSL #2]
	LDR	r8, [lr, r8, LSL #2]
	LDR	r9, [lr, r9, LSL #2]
	EOR	r8, r8, r6, ROR #16
	EOR	r8, r8, r7, ROR #8
	EOR	r8, r8, r9, ROR #24
	STR	r8, [r0], #4
	UBFX	r6, r3, #0, #8
	UBFX	r7, r3, #8, #8
	UBFX	r8, r3, #16, #8
	LSR	r9, r3, #24
	LDRB	r6, [r12, r6, LSL #2]
	LDRB	r7, [r12, r7, LSL #2]
	LDRB	r8, [r12, r8, LSL #2]
	LDRB	r9, [r12, r9, LSL #2]
	LDR	r6, [lr, r6, LSL #2]
	LDR	r7, [lr, r7, LSL #2]
	LDR	r8, [lr, r8, LSL #2]
	LDR	r9, [lr, r9, LSL #2]
	EOR	r8, r8, r6, ROR #16
	EOR	r8, r8, r7, ROR #8
	EOR	r8, r8, r9, ROR #24
	STR	r8, [r0], #4
	UBFX	r6, r4, #0, #8
	UBFX	r7, r4, #8, #8
	UBFX	r8, r4, #16, #8
	LSR	r9, r4, #24
	LDRB	r6, [r12, r6, LSL #2]
	LDRB	r7, [r12, r7, LSL #2]
	LDRB	r8, [r12, r8, LSL #2]
	LDRB	r9, [r12, r9, LSL #2]
	LDR	r6, [lr, r6, LSL #2]
	LDR	r7, [lr, r7, LSL #2]
	LDR	r8, [lr, r8, LSL #2]
	LDR	r9, [lr, r9, LSL #2]
	EOR	r8, r8, r6, ROR #16
	EOR	r8, r8, r7, ROR #8
	EOR	r8, r8, r9, ROR #24
	STR	r8, [r0], #4
	UBFX	r6, r5, #0, #8
	UBFX	r7, r5, #8, #8
	UBFX	r8, r5, #16, #8
	LSR	r9, r5, #24
	LDRB	r6, [r12, r6, LSL #2]
	LDRB	r7, [r12, r7, LSL #2]
	LDRB	r8, [r12, r8, LSL #2]
	LDRB	r9, [r12, r9, LSL #2]
	LDR	r6, [lr, r6, LSL #2]
	LDR	r7, [lr, r7, LSL #2]
	LDR	r8, [lr, r8, LSL #2]
	LDR	r9, [lr, r9, LSL #2]
	EOR	r8, r8, r6, ROR #16
	EOR	r8, r8, r7, ROR #8
	EOR	r8, r8, r9, ROR #24
	STR	r8, [r0], #4
	SUBS	r11, r11, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_AES_invert_key_mix_loop
#else
	BNE.W	L_AES_invert_key_mix_loop
#endif
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 165 */
	.size	AES_invert_key,.-AES_invert_key
#endif /* HAVE_AES_DECRYPT */
#ifndef __APPLE__
	.text
	.type	L_AES_Thumb2_rcon, %object
	.size	L_AES_Thumb2_rcon, 40
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	/* 8-byte aligned, 64-bit aligned */
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_AES_Thumb2_rcon:
	.long	0x01000000,0x02000000,0x04000000,0x08000000
	.long	0x10000000,0x20000000,0x40000000,0x80000000
	.long	0x1b000000,0x36000000
	.text
	.align	4
	.globl	AES_set_encrypt_key
	.type	AES_set_encrypt_key, %function
AES_set_encrypt_key:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, lr}
	LDR	r10, L_AES_Thumb2_te
	ADR	lr, L_AES_Thumb2_rcon
	CMP	r1, #0x80
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BEQ	L_AES_set_encrypt_key_start_128
#else
	BEQ.W	L_AES_set_encrypt_key_start_128
#endif
	CMP	r1, #0xc0
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BEQ	L_AES_set_encrypt_key_start_192
#else
	BEQ.W	L_AES_set_encrypt_key_start_192
#endif
	LDR	r4, [r0]
	LDR	r5, [r0, #4]
	LDR	r6, [r0, #8]
	LDR	r7, [r0, #12]
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
	REV	r7, r7
	STM	r2!, {r4, r5, r6, r7}
	LDR	r4, [r0, #16]
	LDR	r5, [r0, #20]
	LDR	r6, [r0, #24]
	LDR	r7, [r0, #28]
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
	REV	r7, r7
	STM	r2, {r4, r5, r6, r7}
	SUB	r2, r2, #0x10
	MOV	r12, #0x6
L_AES_set_encrypt_key_loop_256:
	UBFX	r4, r7, #0, #8
	UBFX	r5, r7, #8, #8
	UBFX	r6, r7, #16, #8
	LSR	r7, r7, #24
	LDRB	r4, [r10, r4, LSL #2]
	LDRB	r5, [r10, r5, LSL #2]
	LDRB	r6, [r10, r6, LSL #2]
	LDRB	r7, [r10, r7, LSL #2]
	EOR	r3, r7, r4, LSL #8
	EOR	r3, r3, r5, LSL #16
	EOR	r3, r3, r6, LSL #24
	LDM	r2!, {r4, r5, r6, r7}
	EOR	r4, r4, r3
	LDM	lr!, {r3}
	EOR	r4, r4, r3
	EOR	r5, r5, r4
	EOR	r6, r6, r5
	EOR	r7, r7, r6
	ADD	r2, r2, #0x10
	STM	r2, {r4, r5, r6, r7}
	SUB	r2, r2, #0x10
	MOV	r3, r7
	UBFX	r4, r3, #8, #8
	UBFX	r5, r3, #16, #8
	LSR	r6, r3, #24
	UBFX	r3, r3, #0, #8
	LDRB	r4, [r10, r4, LSL #2]
	LDRB	r6, [r10, r6, LSL #2]
	LDRB	r5, [r10, r5, LSL #2]
	LDRB	r3, [r10, r3, LSL #2]
	EOR	r3, r3, r4, LSL #8
	EOR	r3, r3, r5, LSL #16
	EOR	r3, r3, r6, LSL #24
	LDM	r2!, {r4, r5, r6, r7}
	EOR	r4, r4, r3
	EOR	r5, r5, r4
	EOR	r6, r6, r5
	EOR	r7, r7, r6
	ADD	r2, r2, #0x10
	STM	r2, {r4, r5, r6, r7}
	SUB	r2, r2, #0x10
	SUBS	r12, r12, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_AES_set_encrypt_key_loop_256
#else
	BNE.N	L_AES_set_encrypt_key_loop_256
#endif
	UBFX	r4, r7, #0, #8
	UBFX	r5, r7, #8, #8
	UBFX	r6, r7, #16, #8
	LSR	r7, r7, #24
	LDRB	r4, [r10, r4, LSL #2]
	LDRB	r5, [r10, r5, LSL #2]
	LDRB	r6, [r10, r6, LSL #2]
	LDRB	r7, [r10, r7, LSL #2]
	EOR	r3, r7, r4, LSL #8
	EOR	r3, r3, r5, LSL #16
	EOR	r3, r3, r6, LSL #24
	LDM	r2!, {r4, r5, r6, r7}
	EOR	r4, r4, r3
	LDM	lr!, {r3}
	EOR	r4, r4, r3
	EOR	r5, r5, r4
	EOR	r6, r6, r5
	EOR	r7, r7, r6
	ADD	r2, r2, #0x10
	STM	r2, {r4, r5, r6, r7}
	SUB	r2, r2, #0x10
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	B	L_AES_set_encrypt_key_end
#else
	B.N	L_AES_set_encrypt_key_end
#endif
L_AES_set_encrypt_key_start_192:
	LDR	r4, [r0]
	LDR	r5, [r0, #4]
	LDR	r6, [r0, #8]
	LDR	r7, [r0, #12]
	LDR	r8, [r0, #16]
	LDR	r9, [r0, #20]
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
	REV	r7, r7
	REV	r8, r8
	REV	r9, r9
	STM	r2, {r4, r5, r6, r7}
	STRD	r8, r9, [r2, #16]
	MOV	r7, r9
	MOV	r12, #0x7
L_AES_set_encrypt_key_loop_192:
	UBFX	r4, r9, #0, #8
	UBFX	r5, r9, #8, #8
	UBFX	r6, r9, #16, #8
	LSR	r9, r9, #24
	LDRB	r4, [r10, r4, LSL #2]
	LDRB	r5, [r10, r5, LSL #2]
	LDRB	r6, [r10, r6, LSL #2]
	LDRB	r9, [r10, r9, LSL #2]
	EOR	r3, r9, r4, LSL #8
	EOR	r3, r3, r5, LSL #16
	EOR	r3, r3, r6, LSL #24
	LDM	r2!, {r4, r5, r6, r7, r8, r9}
	EOR	r4, r4, r3
	LDM	lr!, {r3}
	EOR	r4, r4, r3
	EOR	r5, r5, r4
	EOR	r6, r6, r5
	EOR	r7, r7, r6
	EOR	r8, r8, r7
	EOR	r9, r9, r8
	STM	r2, {r4, r5, r6, r7, r8, r9}
	SUBS	r12, r12, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_AES_set_encrypt_key_loop_192
#else
	BNE.N	L_AES_set_encrypt_key_loop_192
#endif
	UBFX	r4, r9, #0, #8
	UBFX	r5, r9, #8, #8
	UBFX	r6, r9, #16, #8
	LSR	r9, r9, #24
	LDRB	r4, [r10, r4, LSL #2]
	LDRB	r5, [r10, r5, LSL #2]
	LDRB	r6, [r10, r6, LSL #2]
	LDRB	r9, [r10, r9, LSL #2]
	EOR	r3, r9, r4, LSL #8
	EOR	r3, r3, r5, LSL #16
	EOR	r3, r3, r6, LSL #24
	LDM	r2!, {r4, r5, r6, r7, r8, r9}
	EOR	r4, r4, r3
	LDM	lr!, {r3}
	EOR	r4, r4, r3
	EOR	r5, r5, r4
	EOR	r6, r6, r5
	EOR	r7, r7, r6
	STM	r2, {r4, r5, r6, r7}
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	B	L_AES_set_encrypt_key_end
#else
	B.N	L_AES_set_encrypt_key_end
#endif
L_AES_set_encrypt_key_start_128:
	LDR	r4, [r0]
	LDR	r5, [r0, #4]
	LDR	r6, [r0, #8]
	LDR	r7, [r0, #12]
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
	REV	r7, r7
	STM	r2, {r4, r5, r6, r7}
	MOV	r12, #0xa
L_AES_set_encrypt_key_loop_128:
	UBFX	r4, r7, #0, #8
	UBFX	r5, r7, #8, #8
	UBFX	r6, r7, #16, #8
	LSR	r7, r7, #24
	LDRB	r4, [r10, r4, LSL #2]
	LDRB	r5, [r10, r5, LSL #2]
	LDRB	r6, [r10, r6, LSL #2]
	LDRB	r7, [r10, r7, LSL #2]
	EOR	r3, r7, r4, LSL #8
	EOR	r3, r3, r5, LSL #16
	EOR	r3, r3, r6, LSL #24
	LDM	r2!, {r4, r5, r6, r7}
	EOR	r4, r4, r3
	LDM	lr!, {r3}
	EOR	r4, r4, r3
	EOR	r5, r5, r4
	EOR	r6, r6, r5
	EOR	r7, r7, r6
	STM	r2, {r4, r5, r6, r7}
	SUBS	r12, r12, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_AES_set_encrypt_key_loop_128
#else
	BNE.N	L_AES_set_encrypt_key_loop_128
#endif
L_AES_set_encrypt_key_end:
	POP	{r4, r5, r6, r7, r8, r9, r10, pc}
	/* Cycle Count = 340 */
	.size	AES_set_encrypt_key,.-AES_set_encrypt_key
#ifndef WOLFSSL_ARMASM_AES_BLOCK_INLINE
	.text
	.align	4
	.globl	AES_encrypt_block
	.type	AES_encrypt_block, %function
AES_encrypt_block:
	PUSH	{lr}
L_AES_encrypt_block_nr:
	UBFX	r8, r5, #16, #8
	LSR	r11, r4, #24
	UBFX	lr, r6, #8, #8
	UBFX	r2, r7, #0, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r9, r6, #16, #8
	EOR	r8, r8, r11, ROR #24
	LSR	r11, r5, #24
	EOR	r8, r8, lr, ROR #8
	UBFX	lr, r7, #8, #8
	EOR	r8, r8, r2, ROR #16
	UBFX	r2, r4, #0, #8
	LDR	r9, [r0, r9, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r10, r7, #16, #8
	EOR	r9, r9, r11, ROR #24
	LSR	r11, r6, #24
	EOR	r9, r9, lr, ROR #8
	UBFX	lr, r4, #8, #8
	EOR	r9, r9, r2, ROR #16
	UBFX	r2, r5, #0, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r6, r6, #0, #8
	EOR	r10, r10, r11, ROR #24
	UBFX	r11, r4, #16, #8
	EOR	r10, r10, lr, ROR #8
	LSR	lr, r7, #24
	EOR	r10, r10, r2, ROR #16
	UBFX	r2, r5, #8, #8
	LDR	r6, [r0, r6, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r6, ROR #24
	LDM	r3!, {r4, r5, r6, r7}
	EOR	r11, r11, lr, ROR #24
	EOR	r11, r11, r2, ROR #8
	/*   XOR in Key Schedule */
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	UBFX	r4, r9, #16, #8
	LSR	r7, r8, #24
	UBFX	lr, r10, #8, #8
	UBFX	r2, r11, #0, #8
	LDR	r4, [r0, r4, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r5, r10, #16, #8
	EOR	r4, r4, r7, ROR #24
	LSR	r7, r9, #24
	EOR	r4, r4, lr, ROR #8
	UBFX	lr, r11, #8, #8
	EOR	r4, r4, r2, ROR #16
	UBFX	r2, r8, #0, #8
	LDR	r5, [r0, r5, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r6, r11, #16, #8
	EOR	r5, r5, r7, ROR #24
	LSR	r7, r10, #24
	EOR	r5, r5, lr, ROR #8
	UBFX	lr, r8, #8, #8
	EOR	r5, r5, r2, ROR #16
	UBFX	r2, r9, #0, #8
	LDR	r6, [r0, r6, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r10, r10, #0, #8
	EOR	r6, r6, r7, ROR #24
	UBFX	r7, r8, #16, #8
	EOR	r6, r6, lr, ROR #8
	LSR	lr, r11, #24
	EOR	r6, r6, r2, ROR #16
	UBFX	r2, r9, #8, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r10, ROR #24
	LDM	r3!, {r8, r9, r10, r11}
	EOR	r7, r7, lr, ROR #24
	EOR	r7, r7, r2, ROR #8
	/*   XOR in Key Schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	SUBS	r1, r1, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_AES_encrypt_block_nr
#else
	BNE.W	L_AES_encrypt_block_nr
#endif
	UBFX	r8, r5, #16, #8
	LSR	r11, r4, #24
	UBFX	lr, r6, #8, #8
	UBFX	r2, r7, #0, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r9, r6, #16, #8
	EOR	r8, r8, r11, ROR #24
	LSR	r11, r5, #24
	EOR	r8, r8, lr, ROR #8
	UBFX	lr, r7, #8, #8
	EOR	r8, r8, r2, ROR #16
	UBFX	r2, r4, #0, #8
	LDR	r9, [r0, r9, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r10, r7, #16, #8
	EOR	r9, r9, r11, ROR #24
	LSR	r11, r6, #24
	EOR	r9, r9, lr, ROR #8
	UBFX	lr, r4, #8, #8
	EOR	r9, r9, r2, ROR #16
	UBFX	r2, r5, #0, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r6, r6, #0, #8
	EOR	r10, r10, r11, ROR #24
	UBFX	r11, r4, #16, #8
	EOR	r10, r10, lr, ROR #8
	LSR	lr, r7, #24
	EOR	r10, r10, r2, ROR #16
	UBFX	r2, r5, #8, #8
	LDR	r6, [r0, r6, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r6, ROR #24
	LDM	r3!, {r4, r5, r6, r7}
	EOR	r11, r11, lr, ROR #24
	EOR	r11, r11, r2, ROR #8
	/*   XOR in Key Schedule */
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	UBFX	r4, r11, #0, #8
	UBFX	r7, r10, #8, #8
	UBFX	lr, r9, #16, #8
	LSR	r2, r8, #24
	LDRB	r4, [r0, r4, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	UBFX	r5, r8, #0, #8
	EOR	r4, r4, r7, LSL #8
	UBFX	r7, r11, #8, #8
	EOR	r4, r4, lr, LSL #16
	UBFX	lr, r10, #16, #8
	EOR	r4, r4, r2, LSL #24
	LSR	r2, r9, #24
	LDRB	r5, [r0, r5, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	UBFX	r6, r9, #0, #8
	EOR	r5, r5, r7, LSL #8
	UBFX	r7, r8, #8, #8
	EOR	r5, r5, lr, LSL #16
	UBFX	lr, r11, #16, #8
	EOR	r5, r5, r2, LSL #24
	LSR	r2, r10, #24
	LDRB	r6, [r0, r6, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	LSR	r11, r11, #24
	EOR	r6, r6, r7, LSL #8
	UBFX	r7, r10, #0, #8
	EOR	r6, r6, lr, LSL #16
	UBFX	lr, r9, #8, #8
	EOR	r6, r6, r2, LSL #24
	UBFX	r2, r8, #16, #8
	LDRB	r11, [r0, r11, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r11, LSL #16
	LDM	r3, {r8, r9, r10, r11}
	EOR	r7, r7, lr, LSL #8
	EOR	r7, r7, r2, LSL #16
	/*   XOR in Key Schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	POP	{pc}
	/* Cycle Count = 285 */
	.size	AES_encrypt_block,.-AES_encrypt_block
#endif /* !WOLFSSL_ARMASM_AES_BLOCK_INLINE */
#if defined(HAVE_AES_CBC) || defined(HAVE_AESCCM) || defined(HAVE_AESGCM) || \
    defined(WOLFSSL_AES_DIRECT) || defined(WOLFSSL_AES_COUNTER)
#ifndef __APPLE__
	.text
	.type	L_AES_Thumb2_te_ecb, %object
	.size	L_AES_Thumb2_te_ecb, 12
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	/* 8-byte aligned, 64-bit aligned */
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_AES_Thumb2_te_ecb:
	.long	L_AES_Thumb2_te_data
#endif /* HAVE_AES_CBC || HAVE_AESCCM || HAVE_AESGCM || WOLFSSL_AES_DIRECT ||
        * WOLFSSL_AES_COUNTER */
#if defined(HAVE_AESCCM) || defined(HAVE_AESGCM) || \
    defined(WOLFSSL_AES_DIRECT) || defined(WOLFSSL_AES_COUNTER) || \
    defined(HAVE_AES_ECB)
	.text
	.align	4
	.globl	AES_ECB_encrypt
	.type	AES_ECB_encrypt, %function
AES_ECB_encrypt:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	MOV	lr, r0
	LDR	r0, L_AES_Thumb2_te_ecb
	LDR	r12, [sp, #36]
	PUSH	{r3}
	CMP	r12, #0xa
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BEQ	L_AES_ECB_encrypt_start_block_128
#else
	BEQ.W	L_AES_ECB_encrypt_start_block_128
#endif
	CMP	r12, #0xc
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BEQ	L_AES_ECB_encrypt_start_block_192
#else
	BEQ.W	L_AES_ECB_encrypt_start_block_192
#endif
L_AES_ECB_encrypt_loop_block_256:
	LDR	r4, [lr]
	LDR	r5, [lr, #4]
	LDR	r6, [lr, #8]
	LDR	r7, [lr, #12]
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
	REV	r7, r7
	PUSH	{r1, r2, lr}
	LDM	r3!, {r8, r9, r10, r11}
	/* Round: 0 - XOR in key schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	MOV	r1, #0x6
#ifndef WOLFSSL_ARMASM_AES_BLOCK_INLINE
	BL	AES_encrypt_block
#else
L_AES_ECB_encrypt_block_nr_256:
	UBFX	r8, r5, #16, #8
	LSR	r11, r4, #24
	UBFX	lr, r6, #8, #8
	UBFX	r2, r7, #0, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r9, r6, #16, #8
	EOR	r8, r8, r11, ROR #24
	LSR	r11, r5, #24
	EOR	r8, r8, lr, ROR #8
	UBFX	lr, r7, #8, #8
	EOR	r8, r8, r2, ROR #16
	UBFX	r2, r4, #0, #8
	LDR	r9, [r0, r9, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r10, r7, #16, #8
	EOR	r9, r9, r11, ROR #24
	LSR	r11, r6, #24
	EOR	r9, r9, lr, ROR #8
	UBFX	lr, r4, #8, #8
	EOR	r9, r9, r2, ROR #16
	UBFX	r2, r5, #0, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r6, r6, #0, #8
	EOR	r10, r10, r11, ROR #24
	UBFX	r11, r4, #16, #8
	EOR	r10, r10, lr, ROR #8
	LSR	lr, r7, #24
	EOR	r10, r10, r2, ROR #16
	UBFX	r2, r5, #8, #8
	LDR	r6, [r0, r6, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r6, ROR #24
	LDM	r3!, {r4, r5, r6, r7}
	EOR	r11, r11, lr, ROR #24
	EOR	r11, r11, r2, ROR #8
	/*   XOR in Key Schedule */
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	UBFX	r4, r9, #16, #8
	LSR	r7, r8, #24
	UBFX	lr, r10, #8, #8
	UBFX	r2, r11, #0, #8
	LDR	r4, [r0, r4, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r5, r10, #16, #8
	EOR	r4, r4, r7, ROR #24
	LSR	r7, r9, #24
	EOR	r4, r4, lr, ROR #8
	UBFX	lr, r11, #8, #8
	EOR	r4, r4, r2, ROR #16
	UBFX	r2, r8, #0, #8
	LDR	r5, [r0, r5, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r6, r11, #16, #8
	EOR	r5, r5, r7, ROR #24
	LSR	r7, r10, #24
	EOR	r5, r5, lr, ROR #8
	UBFX	lr, r8, #8, #8
	EOR	r5, r5, r2, ROR #16
	UBFX	r2, r9, #0, #8
	LDR	r6, [r0, r6, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r10, r10, #0, #8
	EOR	r6, r6, r7, ROR #24
	UBFX	r7, r8, #16, #8
	EOR	r6, r6, lr, ROR #8
	LSR	lr, r11, #24
	EOR	r6, r6, r2, ROR #16
	UBFX	r2, r9, #8, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r10, ROR #24
	LDM	r3!, {r8, r9, r10, r11}
	EOR	r7, r7, lr, ROR #24
	EOR	r7, r7, r2, ROR #8
	/*   XOR in Key Schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	SUBS	r1, r1, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_AES_ECB_encrypt_block_nr_256
#else
	BNE.W	L_AES_ECB_encrypt_block_nr_256
#endif
	UBFX	r8, r5, #16, #8
	LSR	r11, r4, #24
	UBFX	lr, r6, #8, #8
	UBFX	r2, r7, #0, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r9, r6, #16, #8
	EOR	r8, r8, r11, ROR #24
	LSR	r11, r5, #24
	EOR	r8, r8, lr, ROR #8
	UBFX	lr, r7, #8, #8
	EOR	r8, r8, r2, ROR #16
	UBFX	r2, r4, #0, #8
	LDR	r9, [r0, r9, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r10, r7, #16, #8
	EOR	r9, r9, r11, ROR #24
	LSR	r11, r6, #24
	EOR	r9, r9, lr, ROR #8
	UBFX	lr, r4, #8, #8
	EOR	r9, r9, r2, ROR #16
	UBFX	r2, r5, #0, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r6, r6, #0, #8
	EOR	r10, r10, r11, ROR #24
	UBFX	r11, r4, #16, #8
	EOR	r10, r10, lr, ROR #8
	LSR	lr, r7, #24
	EOR	r10, r10, r2, ROR #16
	UBFX	r2, r5, #8, #8
	LDR	r6, [r0, r6, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r6, ROR #24
	LDM	r3!, {r4, r5, r6, r7}
	EOR	r11, r11, lr, ROR #24
	EOR	r11, r11, r2, ROR #8
	/*   XOR in Key Schedule */
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	UBFX	r4, r11, #0, #8
	UBFX	r7, r10, #8, #8
	UBFX	lr, r9, #16, #8
	LSR	r2, r8, #24
	LDRB	r4, [r0, r4, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	UBFX	r5, r8, #0, #8
	EOR	r4, r4, r7, LSL #8
	UBFX	r7, r11, #8, #8
	EOR	r4, r4, lr, LSL #16
	UBFX	lr, r10, #16, #8
	EOR	r4, r4, r2, LSL #24
	LSR	r2, r9, #24
	LDRB	r5, [r0, r5, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	UBFX	r6, r9, #0, #8
	EOR	r5, r5, r7, LSL #8
	UBFX	r7, r8, #8, #8
	EOR	r5, r5, lr, LSL #16
	UBFX	lr, r11, #16, #8
	EOR	r5, r5, r2, LSL #24
	LSR	r2, r10, #24
	LDRB	r6, [r0, r6, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	LSR	r11, r11, #24
	EOR	r6, r6, r7, LSL #8
	UBFX	r7, r10, #0, #8
	EOR	r6, r6, lr, LSL #16
	UBFX	lr, r9, #8, #8
	EOR	r6, r6, r2, LSL #24
	UBFX	r2, r8, #16, #8
	LDRB	r11, [r0, r11, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r11, LSL #16
	LDM	r3, {r8, r9, r10, r11}
	EOR	r7, r7, lr, LSL #8
	EOR	r7, r7, r2, LSL #16
	/*   XOR in Key Schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
#endif /* !WOLFSSL_ARMASM_AES_BLOCK_INLINE */
	POP	{r1, r2, lr}
	LDR	r3, [sp]
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
	REV	r7, r7
	STR	r4, [r1]
	STR	r5, [r1, #4]
	STR	r6, [r1, #8]
	STR	r7, [r1, #12]
	SUBS	r2, r2, #0x10
	ADD	lr, lr, #0x10
	ADD	r1, r1, #0x10
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_AES_ECB_encrypt_loop_block_256
#else
	BNE.W	L_AES_ECB_encrypt_loop_block_256
#endif
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	B	L_AES_ECB_encrypt_end
#else
	B.N	L_AES_ECB_encrypt_end
#endif
L_AES_ECB_encrypt_start_block_192:
L_AES_ECB_encrypt_loop_block_192:
	LDR	r4, [lr]
	LDR	r5, [lr, #4]
	LDR	r6, [lr, #8]
	LDR	r7, [lr, #12]
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
	REV	r7, r7
	PUSH	{r1, r2, lr}
	LDM	r3!, {r8, r9, r10, r11}
	/* Round: 0 - XOR in key schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	MOV	r1, #0x5
#ifndef WOLFSSL_ARMASM_AES_BLOCK_INLINE
	BL	AES_encrypt_block
#else
L_AES_ECB_encrypt_block_nr_192:
	UBFX	r8, r5, #16, #8
	LSR	r11, r4, #24
	UBFX	lr, r6, #8, #8
	UBFX	r2, r7, #0, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r9, r6, #16, #8
	EOR	r8, r8, r11, ROR #24
	LSR	r11, r5, #24
	EOR	r8, r8, lr, ROR #8
	UBFX	lr, r7, #8, #8
	EOR	r8, r8, r2, ROR #16
	UBFX	r2, r4, #0, #8
	LDR	r9, [r0, r9, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r10, r7, #16, #8
	EOR	r9, r9, r11, ROR #24
	LSR	r11, r6, #24
	EOR	r9, r9, lr, ROR #8
	UBFX	lr, r4, #8, #8
	EOR	r9, r9, r2, ROR #16
	UBFX	r2, r5, #0, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r6, r6, #0, #8
	EOR	r10, r10, r11, ROR #24
	UBFX	r11, r4, #16, #8
	EOR	r10, r10, lr, ROR #8
	LSR	lr, r7, #24
	EOR	r10, r10, r2, ROR #16
	UBFX	r2, r5, #8, #8
	LDR	r6, [r0, r6, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r6, ROR #24
	LDM	r3!, {r4, r5, r6, r7}
	EOR	r11, r11, lr, ROR #24
	EOR	r11, r11, r2, ROR #8
	/*   XOR in Key Schedule */
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	UBFX	r4, r9, #16, #8
	LSR	r7, r8, #24
	UBFX	lr, r10, #8, #8
	UBFX	r2, r11, #0, #8
	LDR	r4, [r0, r4, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r5, r10, #16, #8
	EOR	r4, r4, r7, ROR #24
	LSR	r7, r9, #24
	EOR	r4, r4, lr, ROR #8
	UBFX	lr, r11, #8, #8
	EOR	r4, r4, r2, ROR #16
	UBFX	r2, r8, #0, #8
	LDR	r5, [r0, r5, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r6, r11, #16, #8
	EOR	r5, r5, r7, ROR #24
	LSR	r7, r10, #24
	EOR	r5, r5, lr, ROR #8
	UBFX	lr, r8, #8, #8
	EOR	r5, r5, r2, ROR #16
	UBFX	r2, r9, #0, #8
	LDR	r6, [r0, r6, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r10, r10, #0, #8
	EOR	r6, r6, r7, ROR #24
	UBFX	r7, r8, #16, #8
	EOR	r6, r6, lr, ROR #8
	LSR	lr, r11, #24
	EOR	r6, r6, r2, ROR #16
	UBFX	r2, r9, #8, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r10, ROR #24
	LDM	r3!, {r8, r9, r10, r11}
	EOR	r7, r7, lr, ROR #24
	EOR	r7, r7, r2, ROR #8
	/*   XOR in Key Schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	SUBS	r1, r1, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_AES_ECB_encrypt_block_nr_192
#else
	BNE.W	L_AES_ECB_encrypt_block_nr_192
#endif
	UBFX	r8, r5, #16, #8
	LSR	r11, r4, #24
	UBFX	lr, r6, #8, #8
	UBFX	r2, r7, #0, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r9, r6, #16, #8
	EOR	r8, r8, r11, ROR #24
	LSR	r11, r5, #24
	EOR	r8, r8, lr, ROR #8
	UBFX	lr, r7, #8, #8
	EOR	r8, r8, r2, ROR #16
	UBFX	r2, r4, #0, #8
	LDR	r9, [r0, r9, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r10, r7, #16, #8
	EOR	r9, r9, r11, ROR #24
	LSR	r11, r6, #24
	EOR	r9, r9, lr, ROR #8
	UBFX	lr, r4, #8, #8
	EOR	r9, r9, r2, ROR #16
	UBFX	r2, r5, #0, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r6, r6, #0, #8
	EOR	r10, r10, r11, ROR #24
	UBFX	r11, r4, #16, #8
	EOR	r10, r10, lr, ROR #8
	LSR	lr, r7, #24
	EOR	r10, r10, r2, ROR #16
	UBFX	r2, r5, #8, #8
	LDR	r6, [r0, r6, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r6, ROR #24
	LDM	r3!, {r4, r5, r6, r7}
	EOR	r11, r11, lr, ROR #24
	EOR	r11, r11, r2, ROR #8
	/*   XOR in Key Schedule */
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	UBFX	r4, r11, #0, #8
	UBFX	r7, r10, #8, #8
	UBFX	lr, r9, #16, #8
	LSR	r2, r8, #24
	LDRB	r4, [r0, r4, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	UBFX	r5, r8, #0, #8
	EOR	r4, r4, r7, LSL #8
	UBFX	r7, r11, #8, #8
	EOR	r4, r4, lr, LSL #16
	UBFX	lr, r10, #16, #8
	EOR	r4, r4, r2, LSL #24
	LSR	r2, r9, #24
	LDRB	r5, [r0, r5, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	UBFX	r6, r9, #0, #8
	EOR	r5, r5, r7, LSL #8
	UBFX	r7, r8, #8, #8
	EOR	r5, r5, lr, LSL #16
	UBFX	lr, r11, #16, #8
	EOR	r5, r5, r2, LSL #24
	LSR	r2, r10, #24
	LDRB	r6, [r0, r6, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	LSR	r11, r11, #24
	EOR	r6, r6, r7, LSL #8
	UBFX	r7, r10, #0, #8
	EOR	r6, r6, lr, LSL #16
	UBFX	lr, r9, #8, #8
	EOR	r6, r6, r2, LSL #24
	UBFX	r2, r8, #16, #8
	LDRB	r11, [r0, r11, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r11, LSL #16
	LDM	r3, {r8, r9, r10, r11}
	EOR	r7, r7, lr, LSL #8
	EOR	r7, r7, r2, LSL #16
	/*   XOR in Key Schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
#endif /* !WOLFSSL_ARMASM_AES_BLOCK_INLINE */
	POP	{r1, r2, lr}
	LDR	r3, [sp]
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
	REV	r7, r7
	STR	r4, [r1]
	STR	r5, [r1, #4]
	STR	r6, [r1, #8]
	STR	r7, [r1, #12]
	SUBS	r2, r2, #0x10
	ADD	lr, lr, #0x10
	ADD	r1, r1, #0x10
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_AES_ECB_encrypt_loop_block_192
#else
	BNE.W	L_AES_ECB_encrypt_loop_block_192
#endif
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	B	L_AES_ECB_encrypt_end
#else
	B.N	L_AES_ECB_encrypt_end
#endif
L_AES_ECB_encrypt_start_block_128:
L_AES_ECB_encrypt_loop_block_128:
	LDR	r4, [lr]
	LDR	r5, [lr, #4]
	LDR	r6, [lr, #8]
	LDR	r7, [lr, #12]
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
	REV	r7, r7
	PUSH	{r1, r2, lr}
	LDM	r3!, {r8, r9, r10, r11}
	/* Round: 0 - XOR in key schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	MOV	r1, #0x4
#ifndef WOLFSSL_ARMASM_AES_BLOCK_INLINE
	BL	AES_encrypt_block
#else
L_AES_ECB_encrypt_block_nr_128:
	UBFX	r8, r5, #16, #8
	LSR	r11, r4, #24
	UBFX	lr, r6, #8, #8
	UBFX	r2, r7, #0, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r9, r6, #16, #8
	EOR	r8, r8, r11, ROR #24
	LSR	r11, r5, #24
	EOR	r8, r8, lr, ROR #8
	UBFX	lr, r7, #8, #8
	EOR	r8, r8, r2, ROR #16
	UBFX	r2, r4, #0, #8
	LDR	r9, [r0, r9, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r10, r7, #16, #8
	EOR	r9, r9, r11, ROR #24
	LSR	r11, r6, #24
	EOR	r9, r9, lr, ROR #8
	UBFX	lr, r4, #8, #8
	EOR	r9, r9, r2, ROR #16
	UBFX	r2, r5, #0, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r6, r6, #0, #8
	EOR	r10, r10, r11, ROR #24
	UBFX	r11, r4, #16, #8
	EOR	r10, r10, lr, ROR #8
	LSR	lr, r7, #24
	EOR	r10, r10, r2, ROR #16
	UBFX	r2, r5, #8, #8
	LDR	r6, [r0, r6, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r6, ROR #24
	LDM	r3!, {r4, r5, r6, r7}
	EOR	r11, r11, lr, ROR #24
	EOR	r11, r11, r2, ROR #8
	/*   XOR in Key Schedule */
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	UBFX	r4, r9, #16, #8
	LSR	r7, r8, #24
	UBFX	lr, r10, #8, #8
	UBFX	r2, r11, #0, #8
	LDR	r4, [r0, r4, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r5, r10, #16, #8
	EOR	r4, r4, r7, ROR #24
	LSR	r7, r9, #24
	EOR	r4, r4, lr, ROR #8
	UBFX	lr, r11, #8, #8
	EOR	r4, r4, r2, ROR #16
	UBFX	r2, r8, #0, #8
	LDR	r5, [r0, r5, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r6, r11, #16, #8
	EOR	r5, r5, r7, ROR #24
	LSR	r7, r10, #24
	EOR	r5, r5, lr, ROR #8
	UBFX	lr, r8, #8, #8
	EOR	r5, r5, r2, ROR #16
	UBFX	r2, r9, #0, #8
	LDR	r6, [r0, r6, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r10, r10, #0, #8
	EOR	r6, r6, r7, ROR #24
	UBFX	r7, r8, #16, #8
	EOR	r6, r6, lr, ROR #8
	LSR	lr, r11, #24
	EOR	r6, r6, r2, ROR #16
	UBFX	r2, r9, #8, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r10, ROR #24
	LDM	r3!, {r8, r9, r10, r11}
	EOR	r7, r7, lr, ROR #24
	EOR	r7, r7, r2, ROR #8
	/*   XOR in Key Schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	SUBS	r1, r1, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_AES_ECB_encrypt_block_nr_128
#else
	BNE.W	L_AES_ECB_encrypt_block_nr_128
#endif
	UBFX	r8, r5, #16, #8
	LSR	r11, r4, #24
	UBFX	lr, r6, #8, #8
	UBFX	r2, r7, #0, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r9, r6, #16, #8
	EOR	r8, r8, r11, ROR #24
	LSR	r11, r5, #24
	EOR	r8, r8, lr, ROR #8
	UBFX	lr, r7, #8, #8
	EOR	r8, r8, r2, ROR #16
	UBFX	r2, r4, #0, #8
	LDR	r9, [r0, r9, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r10, r7, #16, #8
	EOR	r9, r9, r11, ROR #24
	LSR	r11, r6, #24
	EOR	r9, r9, lr, ROR #8
	UBFX	lr, r4, #8, #8
	EOR	r9, r9, r2, ROR #16
	UBFX	r2, r5, #0, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r6, r6, #0, #8
	EOR	r10, r10, r11, ROR #24
	UBFX	r11, r4, #16, #8
	EOR	r10, r10, lr, ROR #8
	LSR	lr, r7, #24
	EOR	r10, r10, r2, ROR #16
	UBFX	r2, r5, #8, #8
	LDR	r6, [r0, r6, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r6, ROR #24
	LDM	r3!, {r4, r5, r6, r7}
	EOR	r11, r11, lr, ROR #24
	EOR	r11, r11, r2, ROR #8
	/*   XOR in Key Schedule */
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	UBFX	r4, r11, #0, #8
	UBFX	r7, r10, #8, #8
	UBFX	lr, r9, #16, #8
	LSR	r2, r8, #24
	LDRB	r4, [r0, r4, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	UBFX	r5, r8, #0, #8
	EOR	r4, r4, r7, LSL #8
	UBFX	r7, r11, #8, #8
	EOR	r4, r4, lr, LSL #16
	UBFX	lr, r10, #16, #8
	EOR	r4, r4, r2, LSL #24
	LSR	r2, r9, #24
	LDRB	r5, [r0, r5, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	UBFX	r6, r9, #0, #8
	EOR	r5, r5, r7, LSL #8
	UBFX	r7, r8, #8, #8
	EOR	r5, r5, lr, LSL #16
	UBFX	lr, r11, #16, #8
	EOR	r5, r5, r2, LSL #24
	LSR	r2, r10, #24
	LDRB	r6, [r0, r6, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	LSR	r11, r11, #24
	EOR	r6, r6, r7, LSL #8
	UBFX	r7, r10, #0, #8
	EOR	r6, r6, lr, LSL #16
	UBFX	lr, r9, #8, #8
	EOR	r6, r6, r2, LSL #24
	UBFX	r2, r8, #16, #8
	LDRB	r11, [r0, r11, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r11, LSL #16
	LDM	r3, {r8, r9, r10, r11}
	EOR	r7, r7, lr, LSL #8
	EOR	r7, r7, r2, LSL #16
	/*   XOR in Key Schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
#endif /* !WOLFSSL_ARMASM_AES_BLOCK_INLINE */
	POP	{r1, r2, lr}
	LDR	r3, [sp]
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
	REV	r7, r7
	STR	r4, [r1]
	STR	r5, [r1, #4]
	STR	r6, [r1, #8]
	STR	r7, [r1, #12]
	SUBS	r2, r2, #0x10
	ADD	lr, lr, #0x10
	ADD	r1, r1, #0x10
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_AES_ECB_encrypt_loop_block_128
#else
	BNE.W	L_AES_ECB_encrypt_loop_block_128
#endif
L_AES_ECB_encrypt_end:
	POP	{r3}
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 1055 */
	.size	AES_ECB_encrypt,.-AES_ECB_encrypt
#endif /* HAVE_AESCCM || HAVE_AESGCM || WOLFSSL_AES_DIRECT ||
        * WOLFSSL_AES_COUNTER || HAVE_AES_ECB */
#ifdef HAVE_AES_CBC
	.text
	.align	4
	.globl	AES_CBC_encrypt
	.type	AES_CBC_encrypt, %function
AES_CBC_encrypt:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	LDR	r8, [sp, #36]
	LDR	r9, [sp, #40]
	MOV	lr, r0
	LDR	r0, L_AES_Thumb2_te_ecb
	LDM	r9, {r4, r5, r6, r7}
	PUSH	{r3, r9}
	CMP	r8, #0xa
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BEQ	L_AES_CBC_encrypt_start_block_128
#else
	BEQ.W	L_AES_CBC_encrypt_start_block_128
#endif
	CMP	r8, #0xc
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BEQ	L_AES_CBC_encrypt_start_block_192
#else
	BEQ.W	L_AES_CBC_encrypt_start_block_192
#endif
L_AES_CBC_encrypt_loop_block_256:
	LDR	r8, [lr]
	LDR	r9, [lr, #4]
	LDR	r10, [lr, #8]
	LDR	r11, [lr, #12]
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	PUSH	{r1, r2, lr}
	LDM	r3!, {r8, r9, r10, r11}
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
	REV	r7, r7
	/* Round: 0 - XOR in key schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	MOV	r1, #0x6
#ifndef WOLFSSL_ARMASM_AES_BLOCK_INLINE
	BL	AES_encrypt_block
#else
L_AES_CBC_encrypt_block_nr_256:
	UBFX	r8, r5, #16, #8
	LSR	r11, r4, #24
	UBFX	lr, r6, #8, #8
	UBFX	r2, r7, #0, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r9, r6, #16, #8
	EOR	r8, r8, r11, ROR #24
	LSR	r11, r5, #24
	EOR	r8, r8, lr, ROR #8
	UBFX	lr, r7, #8, #8
	EOR	r8, r8, r2, ROR #16
	UBFX	r2, r4, #0, #8
	LDR	r9, [r0, r9, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r10, r7, #16, #8
	EOR	r9, r9, r11, ROR #24
	LSR	r11, r6, #24
	EOR	r9, r9, lr, ROR #8
	UBFX	lr, r4, #8, #8
	EOR	r9, r9, r2, ROR #16
	UBFX	r2, r5, #0, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r6, r6, #0, #8
	EOR	r10, r10, r11, ROR #24
	UBFX	r11, r4, #16, #8
	EOR	r10, r10, lr, ROR #8
	LSR	lr, r7, #24
	EOR	r10, r10, r2, ROR #16
	UBFX	r2, r5, #8, #8
	LDR	r6, [r0, r6, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r6, ROR #24
	LDM	r3!, {r4, r5, r6, r7}
	EOR	r11, r11, lr, ROR #24
	EOR	r11, r11, r2, ROR #8
	/*   XOR in Key Schedule */
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	UBFX	r4, r9, #16, #8
	LSR	r7, r8, #24
	UBFX	lr, r10, #8, #8
	UBFX	r2, r11, #0, #8
	LDR	r4, [r0, r4, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r5, r10, #16, #8
	EOR	r4, r4, r7, ROR #24
	LSR	r7, r9, #24
	EOR	r4, r4, lr, ROR #8
	UBFX	lr, r11, #8, #8
	EOR	r4, r4, r2, ROR #16
	UBFX	r2, r8, #0, #8
	LDR	r5, [r0, r5, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r6, r11, #16, #8
	EOR	r5, r5, r7, ROR #24
	LSR	r7, r10, #24
	EOR	r5, r5, lr, ROR #8
	UBFX	lr, r8, #8, #8
	EOR	r5, r5, r2, ROR #16
	UBFX	r2, r9, #0, #8
	LDR	r6, [r0, r6, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r10, r10, #0, #8
	EOR	r6, r6, r7, ROR #24
	UBFX	r7, r8, #16, #8
	EOR	r6, r6, lr, ROR #8
	LSR	lr, r11, #24
	EOR	r6, r6, r2, ROR #16
	UBFX	r2, r9, #8, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r10, ROR #24
	LDM	r3!, {r8, r9, r10, r11}
	EOR	r7, r7, lr, ROR #24
	EOR	r7, r7, r2, ROR #8
	/*   XOR in Key Schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	SUBS	r1, r1, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_AES_CBC_encrypt_block_nr_256
#else
	BNE.W	L_AES_CBC_encrypt_block_nr_256
#endif
	UBFX	r8, r5, #16, #8
	LSR	r11, r4, #24
	UBFX	lr, r6, #8, #8
	UBFX	r2, r7, #0, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r9, r6, #16, #8
	EOR	r8, r8, r11, ROR #24
	LSR	r11, r5, #24
	EOR	r8, r8, lr, ROR #8
	UBFX	lr, r7, #8, #8
	EOR	r8, r8, r2, ROR #16
	UBFX	r2, r4, #0, #8
	LDR	r9, [r0, r9, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r10, r7, #16, #8
	EOR	r9, r9, r11, ROR #24
	LSR	r11, r6, #24
	EOR	r9, r9, lr, ROR #8
	UBFX	lr, r4, #8, #8
	EOR	r9, r9, r2, ROR #16
	UBFX	r2, r5, #0, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r6, r6, #0, #8
	EOR	r10, r10, r11, ROR #24
	UBFX	r11, r4, #16, #8
	EOR	r10, r10, lr, ROR #8
	LSR	lr, r7, #24
	EOR	r10, r10, r2, ROR #16
	UBFX	r2, r5, #8, #8
	LDR	r6, [r0, r6, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r6, ROR #24
	LDM	r3!, {r4, r5, r6, r7}
	EOR	r11, r11, lr, ROR #24
	EOR	r11, r11, r2, ROR #8
	/*   XOR in Key Schedule */
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	UBFX	r4, r11, #0, #8
	UBFX	r7, r10, #8, #8
	UBFX	lr, r9, #16, #8
	LSR	r2, r8, #24
	LDRB	r4, [r0, r4, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	UBFX	r5, r8, #0, #8
	EOR	r4, r4, r7, LSL #8
	UBFX	r7, r11, #8, #8
	EOR	r4, r4, lr, LSL #16
	UBFX	lr, r10, #16, #8
	EOR	r4, r4, r2, LSL #24
	LSR	r2, r9, #24
	LDRB	r5, [r0, r5, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	UBFX	r6, r9, #0, #8
	EOR	r5, r5, r7, LSL #8
	UBFX	r7, r8, #8, #8
	EOR	r5, r5, lr, LSL #16
	UBFX	lr, r11, #16, #8
	EOR	r5, r5, r2, LSL #24
	LSR	r2, r10, #24
	LDRB	r6, [r0, r6, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	LSR	r11, r11, #24
	EOR	r6, r6, r7, LSL #8
	UBFX	r7, r10, #0, #8
	EOR	r6, r6, lr, LSL #16
	UBFX	lr, r9, #8, #8
	EOR	r6, r6, r2, LSL #24
	UBFX	r2, r8, #16, #8
	LDRB	r11, [r0, r11, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r11, LSL #16
	LDM	r3, {r8, r9, r10, r11}
	EOR	r7, r7, lr, LSL #8
	EOR	r7, r7, r2, LSL #16
	/*   XOR in Key Schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
#endif /* !WOLFSSL_ARMASM_AES_BLOCK_INLINE */
	POP	{r1, r2, lr}
	LDR	r3, [sp]
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
	REV	r7, r7
	STR	r4, [r1]
	STR	r5, [r1, #4]
	STR	r6, [r1, #8]
	STR	r7, [r1, #12]
	SUBS	r2, r2, #0x10
	ADD	lr, lr, #0x10
	ADD	r1, r1, #0x10
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_AES_CBC_encrypt_loop_block_256
#else
	BNE.W	L_AES_CBC_encrypt_loop_block_256
#endif
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	B	L_AES_CBC_encrypt_end
#else
	B.N	L_AES_CBC_encrypt_end
#endif
L_AES_CBC_encrypt_start_block_192:
L_AES_CBC_encrypt_loop_block_192:
	LDR	r8, [lr]
	LDR	r9, [lr, #4]
	LDR	r10, [lr, #8]
	LDR	r11, [lr, #12]
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	PUSH	{r1, r2, lr}
	LDM	r3!, {r8, r9, r10, r11}
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
	REV	r7, r7
	/* Round: 0 - XOR in key schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	MOV	r1, #0x5
#ifndef WOLFSSL_ARMASM_AES_BLOCK_INLINE
	BL	AES_encrypt_block
#else
L_AES_CBC_encrypt_block_nr_192:
	UBFX	r8, r5, #16, #8
	LSR	r11, r4, #24
	UBFX	lr, r6, #8, #8
	UBFX	r2, r7, #0, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r9, r6, #16, #8
	EOR	r8, r8, r11, ROR #24
	LSR	r11, r5, #24
	EOR	r8, r8, lr, ROR #8
	UBFX	lr, r7, #8, #8
	EOR	r8, r8, r2, ROR #16
	UBFX	r2, r4, #0, #8
	LDR	r9, [r0, r9, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r10, r7, #16, #8
	EOR	r9, r9, r11, ROR #24
	LSR	r11, r6, #24
	EOR	r9, r9, lr, ROR #8
	UBFX	lr, r4, #8, #8
	EOR	r9, r9, r2, ROR #16
	UBFX	r2, r5, #0, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r6, r6, #0, #8
	EOR	r10, r10, r11, ROR #24
	UBFX	r11, r4, #16, #8
	EOR	r10, r10, lr, ROR #8
	LSR	lr, r7, #24
	EOR	r10, r10, r2, ROR #16
	UBFX	r2, r5, #8, #8
	LDR	r6, [r0, r6, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r6, ROR #24
	LDM	r3!, {r4, r5, r6, r7}
	EOR	r11, r11, lr, ROR #24
	EOR	r11, r11, r2, ROR #8
	/*   XOR in Key Schedule */
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	UBFX	r4, r9, #16, #8
	LSR	r7, r8, #24
	UBFX	lr, r10, #8, #8
	UBFX	r2, r11, #0, #8
	LDR	r4, [r0, r4, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r5, r10, #16, #8
	EOR	r4, r4, r7, ROR #24
	LSR	r7, r9, #24
	EOR	r4, r4, lr, ROR #8
	UBFX	lr, r11, #8, #8
	EOR	r4, r4, r2, ROR #16
	UBFX	r2, r8, #0, #8
	LDR	r5, [r0, r5, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r6, r11, #16, #8
	EOR	r5, r5, r7, ROR #24
	LSR	r7, r10, #24
	EOR	r5, r5, lr, ROR #8
	UBFX	lr, r8, #8, #8
	EOR	r5, r5, r2, ROR #16
	UBFX	r2, r9, #0, #8
	LDR	r6, [r0, r6, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r10, r10, #0, #8
	EOR	r6, r6, r7, ROR #24
	UBFX	r7, r8, #16, #8
	EOR	r6, r6, lr, ROR #8
	LSR	lr, r11, #24
	EOR	r6, r6, r2, ROR #16
	UBFX	r2, r9, #8, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r10, ROR #24
	LDM	r3!, {r8, r9, r10, r11}
	EOR	r7, r7, lr, ROR #24
	EOR	r7, r7, r2, ROR #8
	/*   XOR in Key Schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	SUBS	r1, r1, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_AES_CBC_encrypt_block_nr_192
#else
	BNE.W	L_AES_CBC_encrypt_block_nr_192
#endif
	UBFX	r8, r5, #16, #8
	LSR	r11, r4, #24
	UBFX	lr, r6, #8, #8
	UBFX	r2, r7, #0, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r9, r6, #16, #8
	EOR	r8, r8, r11, ROR #24
	LSR	r11, r5, #24
	EOR	r8, r8, lr, ROR #8
	UBFX	lr, r7, #8, #8
	EOR	r8, r8, r2, ROR #16
	UBFX	r2, r4, #0, #8
	LDR	r9, [r0, r9, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r10, r7, #16, #8
	EOR	r9, r9, r11, ROR #24
	LSR	r11, r6, #24
	EOR	r9, r9, lr, ROR #8
	UBFX	lr, r4, #8, #8
	EOR	r9, r9, r2, ROR #16
	UBFX	r2, r5, #0, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r6, r6, #0, #8
	EOR	r10, r10, r11, ROR #24
	UBFX	r11, r4, #16, #8
	EOR	r10, r10, lr, ROR #8
	LSR	lr, r7, #24
	EOR	r10, r10, r2, ROR #16
	UBFX	r2, r5, #8, #8
	LDR	r6, [r0, r6, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r6, ROR #24
	LDM	r3!, {r4, r5, r6, r7}
	EOR	r11, r11, lr, ROR #24
	EOR	r11, r11, r2, ROR #8
	/*   XOR in Key Schedule */
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	UBFX	r4, r11, #0, #8
	UBFX	r7, r10, #8, #8
	UBFX	lr, r9, #16, #8
	LSR	r2, r8, #24
	LDRB	r4, [r0, r4, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	UBFX	r5, r8, #0, #8
	EOR	r4, r4, r7, LSL #8
	UBFX	r7, r11, #8, #8
	EOR	r4, r4, lr, LSL #16
	UBFX	lr, r10, #16, #8
	EOR	r4, r4, r2, LSL #24
	LSR	r2, r9, #24
	LDRB	r5, [r0, r5, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	UBFX	r6, r9, #0, #8
	EOR	r5, r5, r7, LSL #8
	UBFX	r7, r8, #8, #8
	EOR	r5, r5, lr, LSL #16
	UBFX	lr, r11, #16, #8
	EOR	r5, r5, r2, LSL #24
	LSR	r2, r10, #24
	LDRB	r6, [r0, r6, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	LSR	r11, r11, #24
	EOR	r6, r6, r7, LSL #8
	UBFX	r7, r10, #0, #8
	EOR	r6, r6, lr, LSL #16
	UBFX	lr, r9, #8, #8
	EOR	r6, r6, r2, LSL #24
	UBFX	r2, r8, #16, #8
	LDRB	r11, [r0, r11, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r11, LSL #16
	LDM	r3, {r8, r9, r10, r11}
	EOR	r7, r7, lr, LSL #8
	EOR	r7, r7, r2, LSL #16
	/*   XOR in Key Schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
#endif /* !WOLFSSL_ARMASM_AES_BLOCK_INLINE */
	POP	{r1, r2, lr}
	LDR	r3, [sp]
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
	REV	r7, r7
	STR	r4, [r1]
	STR	r5, [r1, #4]
	STR	r6, [r1, #8]
	STR	r7, [r1, #12]
	SUBS	r2, r2, #0x10
	ADD	lr, lr, #0x10
	ADD	r1, r1, #0x10
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_AES_CBC_encrypt_loop_block_192
#else
	BNE.W	L_AES_CBC_encrypt_loop_block_192
#endif
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	B	L_AES_CBC_encrypt_end
#else
	B.N	L_AES_CBC_encrypt_end
#endif
L_AES_CBC_encrypt_start_block_128:
L_AES_CBC_encrypt_loop_block_128:
	LDR	r8, [lr]
	LDR	r9, [lr, #4]
	LDR	r10, [lr, #8]
	LDR	r11, [lr, #12]
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	PUSH	{r1, r2, lr}
	LDM	r3!, {r8, r9, r10, r11}
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
	REV	r7, r7
	/* Round: 0 - XOR in key schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	MOV	r1, #0x4
#ifndef WOLFSSL_ARMASM_AES_BLOCK_INLINE
	BL	AES_encrypt_block
#else
L_AES_CBC_encrypt_block_nr_128:
	UBFX	r8, r5, #16, #8
	LSR	r11, r4, #24
	UBFX	lr, r6, #8, #8
	UBFX	r2, r7, #0, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r9, r6, #16, #8
	EOR	r8, r8, r11, ROR #24
	LSR	r11, r5, #24
	EOR	r8, r8, lr, ROR #8
	UBFX	lr, r7, #8, #8
	EOR	r8, r8, r2, ROR #16
	UBFX	r2, r4, #0, #8
	LDR	r9, [r0, r9, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r10, r7, #16, #8
	EOR	r9, r9, r11, ROR #24
	LSR	r11, r6, #24
	EOR	r9, r9, lr, ROR #8
	UBFX	lr, r4, #8, #8
	EOR	r9, r9, r2, ROR #16
	UBFX	r2, r5, #0, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r6, r6, #0, #8
	EOR	r10, r10, r11, ROR #24
	UBFX	r11, r4, #16, #8
	EOR	r10, r10, lr, ROR #8
	LSR	lr, r7, #24
	EOR	r10, r10, r2, ROR #16
	UBFX	r2, r5, #8, #8
	LDR	r6, [r0, r6, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r6, ROR #24
	LDM	r3!, {r4, r5, r6, r7}
	EOR	r11, r11, lr, ROR #24
	EOR	r11, r11, r2, ROR #8
	/*   XOR in Key Schedule */
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	UBFX	r4, r9, #16, #8
	LSR	r7, r8, #24
	UBFX	lr, r10, #8, #8
	UBFX	r2, r11, #0, #8
	LDR	r4, [r0, r4, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r5, r10, #16, #8
	EOR	r4, r4, r7, ROR #24
	LSR	r7, r9, #24
	EOR	r4, r4, lr, ROR #8
	UBFX	lr, r11, #8, #8
	EOR	r4, r4, r2, ROR #16
	UBFX	r2, r8, #0, #8
	LDR	r5, [r0, r5, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r6, r11, #16, #8
	EOR	r5, r5, r7, ROR #24
	LSR	r7, r10, #24
	EOR	r5, r5, lr, ROR #8
	UBFX	lr, r8, #8, #8
	EOR	r5, r5, r2, ROR #16
	UBFX	r2, r9, #0, #8
	LDR	r6, [r0, r6, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r10, r10, #0, #8
	EOR	r6, r6, r7, ROR #24
	UBFX	r7, r8, #16, #8
	EOR	r6, r6, lr, ROR #8
	LSR	lr, r11, #24
	EOR	r6, r6, r2, ROR #16
	UBFX	r2, r9, #8, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r10, ROR #24
	LDM	r3!, {r8, r9, r10, r11}
	EOR	r7, r7, lr, ROR #24
	EOR	r7, r7, r2, ROR #8
	/*   XOR in Key Schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	SUBS	r1, r1, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_AES_CBC_encrypt_block_nr_128
#else
	BNE.W	L_AES_CBC_encrypt_block_nr_128
#endif
	UBFX	r8, r5, #16, #8
	LSR	r11, r4, #24
	UBFX	lr, r6, #8, #8
	UBFX	r2, r7, #0, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r9, r6, #16, #8
	EOR	r8, r8, r11, ROR #24
	LSR	r11, r5, #24
	EOR	r8, r8, lr, ROR #8
	UBFX	lr, r7, #8, #8
	EOR	r8, r8, r2, ROR #16
	UBFX	r2, r4, #0, #8
	LDR	r9, [r0, r9, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r10, r7, #16, #8
	EOR	r9, r9, r11, ROR #24
	LSR	r11, r6, #24
	EOR	r9, r9, lr, ROR #8
	UBFX	lr, r4, #8, #8
	EOR	r9, r9, r2, ROR #16
	UBFX	r2, r5, #0, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r6, r6, #0, #8
	EOR	r10, r10, r11, ROR #24
	UBFX	r11, r4, #16, #8
	EOR	r10, r10, lr, ROR #8
	LSR	lr, r7, #24
	EOR	r10, r10, r2, ROR #16
	UBFX	r2, r5, #8, #8
	LDR	r6, [r0, r6, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r6, ROR #24
	LDM	r3!, {r4, r5, r6, r7}
	EOR	r11, r11, lr, ROR #24
	EOR	r11, r11, r2, ROR #8
	/*   XOR in Key Schedule */
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	UBFX	r4, r11, #0, #8
	UBFX	r7, r10, #8, #8
	UBFX	lr, r9, #16, #8
	LSR	r2, r8, #24
	LDRB	r4, [r0, r4, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	UBFX	r5, r8, #0, #8
	EOR	r4, r4, r7, LSL #8
	UBFX	r7, r11, #8, #8
	EOR	r4, r4, lr, LSL #16
	UBFX	lr, r10, #16, #8
	EOR	r4, r4, r2, LSL #24
	LSR	r2, r9, #24
	LDRB	r5, [r0, r5, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	UBFX	r6, r9, #0, #8
	EOR	r5, r5, r7, LSL #8
	UBFX	r7, r8, #8, #8
	EOR	r5, r5, lr, LSL #16
	UBFX	lr, r11, #16, #8
	EOR	r5, r5, r2, LSL #24
	LSR	r2, r10, #24
	LDRB	r6, [r0, r6, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	LSR	r11, r11, #24
	EOR	r6, r6, r7, LSL #8
	UBFX	r7, r10, #0, #8
	EOR	r6, r6, lr, LSL #16
	UBFX	lr, r9, #8, #8
	EOR	r6, r6, r2, LSL #24
	UBFX	r2, r8, #16, #8
	LDRB	r11, [r0, r11, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r11, LSL #16
	LDM	r3, {r8, r9, r10, r11}
	EOR	r7, r7, lr, LSL #8
	EOR	r7, r7, r2, LSL #16
	/*   XOR in Key Schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
#endif /* !WOLFSSL_ARMASM_AES_BLOCK_INLINE */
	POP	{r1, r2, lr}
	LDR	r3, [sp]
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
	REV	r7, r7
	STR	r4, [r1]
	STR	r5, [r1, #4]
	STR	r6, [r1, #8]
	STR	r7, [r1, #12]
	SUBS	r2, r2, #0x10
	ADD	lr, lr, #0x10
	ADD	r1, r1, #0x10
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_AES_CBC_encrypt_loop_block_128
#else
	BNE.W	L_AES_CBC_encrypt_loop_block_128
#endif
L_AES_CBC_encrypt_end:
	POP	{r3, r9}
	STM	r9, {r4, r5, r6, r7}
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 1081 */
	.size	AES_CBC_encrypt,.-AES_CBC_encrypt
#endif /* HAVE_AES_CBC */
#ifdef WOLFSSL_AES_COUNTER
#ifndef __APPLE__
	.text
	.type	L_AES_Thumb2_te_ctr, %object
	.size	L_AES_Thumb2_te_ctr, 12
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	/* 8-byte aligned, 64-bit aligned */
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_AES_Thumb2_te_ctr:
	.long	L_AES_Thumb2_te_data
	.text
	.align	4
	.globl	AES_CTR_encrypt
	.type	AES_CTR_encrypt, %function
AES_CTR_encrypt:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	LDR	r12, [sp, #36]
	LDR	r8, [sp, #40]
	MOV	lr, r0
	LDR	r0, L_AES_Thumb2_te_ctr
	LDM	r8, {r4, r5, r6, r7}
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
	REV	r7, r7
	STM	r8, {r4, r5, r6, r7}
	PUSH	{r3, r8}
	CMP	r12, #0xa
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BEQ	L_AES_CTR_encrypt_start_block_128
#else
	BEQ.W	L_AES_CTR_encrypt_start_block_128
#endif
	CMP	r12, #0xc
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BEQ	L_AES_CTR_encrypt_start_block_192
#else
	BEQ.W	L_AES_CTR_encrypt_start_block_192
#endif
L_AES_CTR_encrypt_loop_block_256:
	PUSH	{r1, r2, lr}
	LDR	lr, [sp, #16]
	ADDS	r11, r7, #0x1
	ADCS	r10, r6, #0x0
	ADCS	r9, r5, #0x0
	ADC	r8, r4, #0x0
	STM	lr, {r8, r9, r10, r11}
	LDM	r3!, {r8, r9, r10, r11}
	/* Round: 0 - XOR in key schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	MOV	r1, #0x6
#ifndef WOLFSSL_ARMASM_AES_BLOCK_INLINE
	BL	AES_encrypt_block
#else
L_AES_CTR_encrypt_block_nr_256:
	UBFX	r8, r5, #16, #8
	LSR	r11, r4, #24
	UBFX	lr, r6, #8, #8
	UBFX	r2, r7, #0, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r9, r6, #16, #8
	EOR	r8, r8, r11, ROR #24
	LSR	r11, r5, #24
	EOR	r8, r8, lr, ROR #8
	UBFX	lr, r7, #8, #8
	EOR	r8, r8, r2, ROR #16
	UBFX	r2, r4, #0, #8
	LDR	r9, [r0, r9, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r10, r7, #16, #8
	EOR	r9, r9, r11, ROR #24
	LSR	r11, r6, #24
	EOR	r9, r9, lr, ROR #8
	UBFX	lr, r4, #8, #8
	EOR	r9, r9, r2, ROR #16
	UBFX	r2, r5, #0, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r6, r6, #0, #8
	EOR	r10, r10, r11, ROR #24
	UBFX	r11, r4, #16, #8
	EOR	r10, r10, lr, ROR #8
	LSR	lr, r7, #24
	EOR	r10, r10, r2, ROR #16
	UBFX	r2, r5, #8, #8
	LDR	r6, [r0, r6, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r6, ROR #24
	LDM	r3!, {r4, r5, r6, r7}
	EOR	r11, r11, lr, ROR #24
	EOR	r11, r11, r2, ROR #8
	/*   XOR in Key Schedule */
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	UBFX	r4, r9, #16, #8
	LSR	r7, r8, #24
	UBFX	lr, r10, #8, #8
	UBFX	r2, r11, #0, #8
	LDR	r4, [r0, r4, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r5, r10, #16, #8
	EOR	r4, r4, r7, ROR #24
	LSR	r7, r9, #24
	EOR	r4, r4, lr, ROR #8
	UBFX	lr, r11, #8, #8
	EOR	r4, r4, r2, ROR #16
	UBFX	r2, r8, #0, #8
	LDR	r5, [r0, r5, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r6, r11, #16, #8
	EOR	r5, r5, r7, ROR #24
	LSR	r7, r10, #24
	EOR	r5, r5, lr, ROR #8
	UBFX	lr, r8, #8, #8
	EOR	r5, r5, r2, ROR #16
	UBFX	r2, r9, #0, #8
	LDR	r6, [r0, r6, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r10, r10, #0, #8
	EOR	r6, r6, r7, ROR #24
	UBFX	r7, r8, #16, #8
	EOR	r6, r6, lr, ROR #8
	LSR	lr, r11, #24
	EOR	r6, r6, r2, ROR #16
	UBFX	r2, r9, #8, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r10, ROR #24
	LDM	r3!, {r8, r9, r10, r11}
	EOR	r7, r7, lr, ROR #24
	EOR	r7, r7, r2, ROR #8
	/*   XOR in Key Schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	SUBS	r1, r1, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_AES_CTR_encrypt_block_nr_256
#else
	BNE.W	L_AES_CTR_encrypt_block_nr_256
#endif
	UBFX	r8, r5, #16, #8
	LSR	r11, r4, #24
	UBFX	lr, r6, #8, #8
	UBFX	r2, r7, #0, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r9, r6, #16, #8
	EOR	r8, r8, r11, ROR #24
	LSR	r11, r5, #24
	EOR	r8, r8, lr, ROR #8
	UBFX	lr, r7, #8, #8
	EOR	r8, r8, r2, ROR #16
	UBFX	r2, r4, #0, #8
	LDR	r9, [r0, r9, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r10, r7, #16, #8
	EOR	r9, r9, r11, ROR #24
	LSR	r11, r6, #24
	EOR	r9, r9, lr, ROR #8
	UBFX	lr, r4, #8, #8
	EOR	r9, r9, r2, ROR #16
	UBFX	r2, r5, #0, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r6, r6, #0, #8
	EOR	r10, r10, r11, ROR #24
	UBFX	r11, r4, #16, #8
	EOR	r10, r10, lr, ROR #8
	LSR	lr, r7, #24
	EOR	r10, r10, r2, ROR #16
	UBFX	r2, r5, #8, #8
	LDR	r6, [r0, r6, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r6, ROR #24
	LDM	r3!, {r4, r5, r6, r7}
	EOR	r11, r11, lr, ROR #24
	EOR	r11, r11, r2, ROR #8
	/*   XOR in Key Schedule */
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	UBFX	r4, r11, #0, #8
	UBFX	r7, r10, #8, #8
	UBFX	lr, r9, #16, #8
	LSR	r2, r8, #24
	LDRB	r4, [r0, r4, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	UBFX	r5, r8, #0, #8
	EOR	r4, r4, r7, LSL #8
	UBFX	r7, r11, #8, #8
	EOR	r4, r4, lr, LSL #16
	UBFX	lr, r10, #16, #8
	EOR	r4, r4, r2, LSL #24
	LSR	r2, r9, #24
	LDRB	r5, [r0, r5, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	UBFX	r6, r9, #0, #8
	EOR	r5, r5, r7, LSL #8
	UBFX	r7, r8, #8, #8
	EOR	r5, r5, lr, LSL #16
	UBFX	lr, r11, #16, #8
	EOR	r5, r5, r2, LSL #24
	LSR	r2, r10, #24
	LDRB	r6, [r0, r6, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	LSR	r11, r11, #24
	EOR	r6, r6, r7, LSL #8
	UBFX	r7, r10, #0, #8
	EOR	r6, r6, lr, LSL #16
	UBFX	lr, r9, #8, #8
	EOR	r6, r6, r2, LSL #24
	UBFX	r2, r8, #16, #8
	LDRB	r11, [r0, r11, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r11, LSL #16
	LDM	r3, {r8, r9, r10, r11}
	EOR	r7, r7, lr, LSL #8
	EOR	r7, r7, r2, LSL #16
	/*   XOR in Key Schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
#endif /* !WOLFSSL_ARMASM_AES_BLOCK_INLINE */
	POP	{r1, r2, lr}
	LDR	r3, [sp]
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
	REV	r7, r7
	LDR	r8, [lr]
	LDR	r9, [lr, #4]
	LDR	r10, [lr, #8]
	LDR	r11, [lr, #12]
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	LDR	r8, [sp, #4]
	STR	r4, [r1]
	STR	r5, [r1, #4]
	STR	r6, [r1, #8]
	STR	r7, [r1, #12]
	LDM	r8, {r4, r5, r6, r7}
	SUBS	r2, r2, #0x10
	ADD	lr, lr, #0x10
	ADD	r1, r1, #0x10
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_AES_CTR_encrypt_loop_block_256
#else
	BNE.W	L_AES_CTR_encrypt_loop_block_256
#endif
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	B	L_AES_CTR_encrypt_end
#else
	B.W	L_AES_CTR_encrypt_end
#endif
L_AES_CTR_encrypt_start_block_192:
L_AES_CTR_encrypt_loop_block_192:
	PUSH	{r1, r2, lr}
	LDR	lr, [sp, #16]
	ADDS	r11, r7, #0x1
	ADCS	r10, r6, #0x0
	ADCS	r9, r5, #0x0
	ADC	r8, r4, #0x0
	STM	lr, {r8, r9, r10, r11}
	LDM	r3!, {r8, r9, r10, r11}
	/* Round: 0 - XOR in key schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	MOV	r1, #0x5
#ifndef WOLFSSL_ARMASM_AES_BLOCK_INLINE
	BL	AES_encrypt_block
#else
L_AES_CTR_encrypt_block_nr_192:
	UBFX	r8, r5, #16, #8
	LSR	r11, r4, #24
	UBFX	lr, r6, #8, #8
	UBFX	r2, r7, #0, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r9, r6, #16, #8
	EOR	r8, r8, r11, ROR #24
	LSR	r11, r5, #24
	EOR	r8, r8, lr, ROR #8
	UBFX	lr, r7, #8, #8
	EOR	r8, r8, r2, ROR #16
	UBFX	r2, r4, #0, #8
	LDR	r9, [r0, r9, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r10, r7, #16, #8
	EOR	r9, r9, r11, ROR #24
	LSR	r11, r6, #24
	EOR	r9, r9, lr, ROR #8
	UBFX	lr, r4, #8, #8
	EOR	r9, r9, r2, ROR #16
	UBFX	r2, r5, #0, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r6, r6, #0, #8
	EOR	r10, r10, r11, ROR #24
	UBFX	r11, r4, #16, #8
	EOR	r10, r10, lr, ROR #8
	LSR	lr, r7, #24
	EOR	r10, r10, r2, ROR #16
	UBFX	r2, r5, #8, #8
	LDR	r6, [r0, r6, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r6, ROR #24
	LDM	r3!, {r4, r5, r6, r7}
	EOR	r11, r11, lr, ROR #24
	EOR	r11, r11, r2, ROR #8
	/*   XOR in Key Schedule */
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	UBFX	r4, r9, #16, #8
	LSR	r7, r8, #24
	UBFX	lr, r10, #8, #8
	UBFX	r2, r11, #0, #8
	LDR	r4, [r0, r4, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r5, r10, #16, #8
	EOR	r4, r4, r7, ROR #24
	LSR	r7, r9, #24
	EOR	r4, r4, lr, ROR #8
	UBFX	lr, r11, #8, #8
	EOR	r4, r4, r2, ROR #16
	UBFX	r2, r8, #0, #8
	LDR	r5, [r0, r5, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r6, r11, #16, #8
	EOR	r5, r5, r7, ROR #24
	LSR	r7, r10, #24
	EOR	r5, r5, lr, ROR #8
	UBFX	lr, r8, #8, #8
	EOR	r5, r5, r2, ROR #16
	UBFX	r2, r9, #0, #8
	LDR	r6, [r0, r6, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r10, r10, #0, #8
	EOR	r6, r6, r7, ROR #24
	UBFX	r7, r8, #16, #8
	EOR	r6, r6, lr, ROR #8
	LSR	lr, r11, #24
	EOR	r6, r6, r2, ROR #16
	UBFX	r2, r9, #8, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r10, ROR #24
	LDM	r3!, {r8, r9, r10, r11}
	EOR	r7, r7, lr, ROR #24
	EOR	r7, r7, r2, ROR #8
	/*   XOR in Key Schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	SUBS	r1, r1, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_AES_CTR_encrypt_block_nr_192
#else
	BNE.W	L_AES_CTR_encrypt_block_nr_192
#endif
	UBFX	r8, r5, #16, #8
	LSR	r11, r4, #24
	UBFX	lr, r6, #8, #8
	UBFX	r2, r7, #0, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r9, r6, #16, #8
	EOR	r8, r8, r11, ROR #24
	LSR	r11, r5, #24
	EOR	r8, r8, lr, ROR #8
	UBFX	lr, r7, #8, #8
	EOR	r8, r8, r2, ROR #16
	UBFX	r2, r4, #0, #8
	LDR	r9, [r0, r9, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r10, r7, #16, #8
	EOR	r9, r9, r11, ROR #24
	LSR	r11, r6, #24
	EOR	r9, r9, lr, ROR #8
	UBFX	lr, r4, #8, #8
	EOR	r9, r9, r2, ROR #16
	UBFX	r2, r5, #0, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r6, r6, #0, #8
	EOR	r10, r10, r11, ROR #24
	UBFX	r11, r4, #16, #8
	EOR	r10, r10, lr, ROR #8
	LSR	lr, r7, #24
	EOR	r10, r10, r2, ROR #16
	UBFX	r2, r5, #8, #8
	LDR	r6, [r0, r6, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r6, ROR #24
	LDM	r3!, {r4, r5, r6, r7}
	EOR	r11, r11, lr, ROR #24
	EOR	r11, r11, r2, ROR #8
	/*   XOR in Key Schedule */
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	UBFX	r4, r11, #0, #8
	UBFX	r7, r10, #8, #8
	UBFX	lr, r9, #16, #8
	LSR	r2, r8, #24
	LDRB	r4, [r0, r4, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	UBFX	r5, r8, #0, #8
	EOR	r4, r4, r7, LSL #8
	UBFX	r7, r11, #8, #8
	EOR	r4, r4, lr, LSL #16
	UBFX	lr, r10, #16, #8
	EOR	r4, r4, r2, LSL #24
	LSR	r2, r9, #24
	LDRB	r5, [r0, r5, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	UBFX	r6, r9, #0, #8
	EOR	r5, r5, r7, LSL #8
	UBFX	r7, r8, #8, #8
	EOR	r5, r5, lr, LSL #16
	UBFX	lr, r11, #16, #8
	EOR	r5, r5, r2, LSL #24
	LSR	r2, r10, #24
	LDRB	r6, [r0, r6, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	LSR	r11, r11, #24
	EOR	r6, r6, r7, LSL #8
	UBFX	r7, r10, #0, #8
	EOR	r6, r6, lr, LSL #16
	UBFX	lr, r9, #8, #8
	EOR	r6, r6, r2, LSL #24
	UBFX	r2, r8, #16, #8
	LDRB	r11, [r0, r11, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r11, LSL #16
	LDM	r3, {r8, r9, r10, r11}
	EOR	r7, r7, lr, LSL #8
	EOR	r7, r7, r2, LSL #16
	/*   XOR in Key Schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
#endif /* !WOLFSSL_ARMASM_AES_BLOCK_INLINE */
	POP	{r1, r2, lr}
	LDR	r3, [sp]
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
	REV	r7, r7
	LDR	r8, [lr]
	LDR	r9, [lr, #4]
	LDR	r10, [lr, #8]
	LDR	r11, [lr, #12]
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	LDR	r8, [sp, #4]
	STR	r4, [r1]
	STR	r5, [r1, #4]
	STR	r6, [r1, #8]
	STR	r7, [r1, #12]
	LDM	r8, {r4, r5, r6, r7}
	SUBS	r2, r2, #0x10
	ADD	lr, lr, #0x10
	ADD	r1, r1, #0x10
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_AES_CTR_encrypt_loop_block_192
#else
	BNE.W	L_AES_CTR_encrypt_loop_block_192
#endif
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	B	L_AES_CTR_encrypt_end
#else
	B.W	L_AES_CTR_encrypt_end
#endif
L_AES_CTR_encrypt_start_block_128:
L_AES_CTR_encrypt_loop_block_128:
	PUSH	{r1, r2, lr}
	LDR	lr, [sp, #16]
	ADDS	r11, r7, #0x1
	ADCS	r10, r6, #0x0
	ADCS	r9, r5, #0x0
	ADC	r8, r4, #0x0
	STM	lr, {r8, r9, r10, r11}
	LDM	r3!, {r8, r9, r10, r11}
	/* Round: 0 - XOR in key schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	MOV	r1, #0x4
#ifndef WOLFSSL_ARMASM_AES_BLOCK_INLINE
	BL	AES_encrypt_block
#else
L_AES_CTR_encrypt_block_nr_128:
	UBFX	r8, r5, #16, #8
	LSR	r11, r4, #24
	UBFX	lr, r6, #8, #8
	UBFX	r2, r7, #0, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r9, r6, #16, #8
	EOR	r8, r8, r11, ROR #24
	LSR	r11, r5, #24
	EOR	r8, r8, lr, ROR #8
	UBFX	lr, r7, #8, #8
	EOR	r8, r8, r2, ROR #16
	UBFX	r2, r4, #0, #8
	LDR	r9, [r0, r9, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r10, r7, #16, #8
	EOR	r9, r9, r11, ROR #24
	LSR	r11, r6, #24
	EOR	r9, r9, lr, ROR #8
	UBFX	lr, r4, #8, #8
	EOR	r9, r9, r2, ROR #16
	UBFX	r2, r5, #0, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r6, r6, #0, #8
	EOR	r10, r10, r11, ROR #24
	UBFX	r11, r4, #16, #8
	EOR	r10, r10, lr, ROR #8
	LSR	lr, r7, #24
	EOR	r10, r10, r2, ROR #16
	UBFX	r2, r5, #8, #8
	LDR	r6, [r0, r6, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r6, ROR #24
	LDM	r3!, {r4, r5, r6, r7}
	EOR	r11, r11, lr, ROR #24
	EOR	r11, r11, r2, ROR #8
	/*   XOR in Key Schedule */
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	UBFX	r4, r9, #16, #8
	LSR	r7, r8, #24
	UBFX	lr, r10, #8, #8
	UBFX	r2, r11, #0, #8
	LDR	r4, [r0, r4, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r5, r10, #16, #8
	EOR	r4, r4, r7, ROR #24
	LSR	r7, r9, #24
	EOR	r4, r4, lr, ROR #8
	UBFX	lr, r11, #8, #8
	EOR	r4, r4, r2, ROR #16
	UBFX	r2, r8, #0, #8
	LDR	r5, [r0, r5, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r6, r11, #16, #8
	EOR	r5, r5, r7, ROR #24
	LSR	r7, r10, #24
	EOR	r5, r5, lr, ROR #8
	UBFX	lr, r8, #8, #8
	EOR	r5, r5, r2, ROR #16
	UBFX	r2, r9, #0, #8
	LDR	r6, [r0, r6, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r10, r10, #0, #8
	EOR	r6, r6, r7, ROR #24
	UBFX	r7, r8, #16, #8
	EOR	r6, r6, lr, ROR #8
	LSR	lr, r11, #24
	EOR	r6, r6, r2, ROR #16
	UBFX	r2, r9, #8, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r10, ROR #24
	LDM	r3!, {r8, r9, r10, r11}
	EOR	r7, r7, lr, ROR #24
	EOR	r7, r7, r2, ROR #8
	/*   XOR in Key Schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	SUBS	r1, r1, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_AES_CTR_encrypt_block_nr_128
#else
	BNE.W	L_AES_CTR_encrypt_block_nr_128
#endif
	UBFX	r8, r5, #16, #8
	LSR	r11, r4, #24
	UBFX	lr, r6, #8, #8
	UBFX	r2, r7, #0, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r9, r6, #16, #8
	EOR	r8, r8, r11, ROR #24
	LSR	r11, r5, #24
	EOR	r8, r8, lr, ROR #8
	UBFX	lr, r7, #8, #8
	EOR	r8, r8, r2, ROR #16
	UBFX	r2, r4, #0, #8
	LDR	r9, [r0, r9, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r10, r7, #16, #8
	EOR	r9, r9, r11, ROR #24
	LSR	r11, r6, #24
	EOR	r9, r9, lr, ROR #8
	UBFX	lr, r4, #8, #8
	EOR	r9, r9, r2, ROR #16
	UBFX	r2, r5, #0, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r6, r6, #0, #8
	EOR	r10, r10, r11, ROR #24
	UBFX	r11, r4, #16, #8
	EOR	r10, r10, lr, ROR #8
	LSR	lr, r7, #24
	EOR	r10, r10, r2, ROR #16
	UBFX	r2, r5, #8, #8
	LDR	r6, [r0, r6, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r6, ROR #24
	LDM	r3!, {r4, r5, r6, r7}
	EOR	r11, r11, lr, ROR #24
	EOR	r11, r11, r2, ROR #8
	/*   XOR in Key Schedule */
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	UBFX	r4, r11, #0, #8
	UBFX	r7, r10, #8, #8
	UBFX	lr, r9, #16, #8
	LSR	r2, r8, #24
	LDRB	r4, [r0, r4, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	UBFX	r5, r8, #0, #8
	EOR	r4, r4, r7, LSL #8
	UBFX	r7, r11, #8, #8
	EOR	r4, r4, lr, LSL #16
	UBFX	lr, r10, #16, #8
	EOR	r4, r4, r2, LSL #24
	LSR	r2, r9, #24
	LDRB	r5, [r0, r5, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	UBFX	r6, r9, #0, #8
	EOR	r5, r5, r7, LSL #8
	UBFX	r7, r8, #8, #8
	EOR	r5, r5, lr, LSL #16
	UBFX	lr, r11, #16, #8
	EOR	r5, r5, r2, LSL #24
	LSR	r2, r10, #24
	LDRB	r6, [r0, r6, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	LSR	r11, r11, #24
	EOR	r6, r6, r7, LSL #8
	UBFX	r7, r10, #0, #8
	EOR	r6, r6, lr, LSL #16
	UBFX	lr, r9, #8, #8
	EOR	r6, r6, r2, LSL #24
	UBFX	r2, r8, #16, #8
	LDRB	r11, [r0, r11, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r11, LSL #16
	LDM	r3, {r8, r9, r10, r11}
	EOR	r7, r7, lr, LSL #8
	EOR	r7, r7, r2, LSL #16
	/*   XOR in Key Schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
#endif /* !WOLFSSL_ARMASM_AES_BLOCK_INLINE */
	POP	{r1, r2, lr}
	LDR	r3, [sp]
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
	REV	r7, r7
	LDR	r8, [lr]
	LDR	r9, [lr, #4]
	LDR	r10, [lr, #8]
	LDR	r11, [lr, #12]
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	LDR	r8, [sp, #4]
	STR	r4, [r1]
	STR	r5, [r1, #4]
	STR	r6, [r1, #8]
	STR	r7, [r1, #12]
	LDM	r8, {r4, r5, r6, r7}
	SUBS	r2, r2, #0x10
	ADD	lr, lr, #0x10
	ADD	r1, r1, #0x10
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_AES_CTR_encrypt_loop_block_128
#else
	BNE.W	L_AES_CTR_encrypt_loop_block_128
#endif
L_AES_CTR_encrypt_end:
	POP	{r3, r8}
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
	REV	r7, r7
	STM	r8, {r4, r5, r6, r7}
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 1136 */
	.size	AES_CTR_encrypt,.-AES_CTR_encrypt
#endif /* WOLFSSL_AES_COUNTER */
#ifdef HAVE_AES_DECRYPT
#if defined(WOLFSSL_AES_DIRECT) || defined(WOLFSSL_AES_COUNTER) || \
    defined(HAVE_AES_CBC) || defined(HAVE_AES_ECB)
#ifndef WOLFSSL_ARMASM_AES_BLOCK_INLINE
	.text
	.align	4
	.globl	AES_decrypt_block
	.type	AES_decrypt_block, %function
AES_decrypt_block:
	PUSH	{lr}
L_AES_decrypt_block_nr:
	UBFX	r8, r7, #16, #8
	LSR	r11, r4, #24
	UBFX	r12, r6, #8, #8
	UBFX	lr, r5, #0, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r9, r4, #16, #8
	EOR	r8, r8, r11, ROR #24
	LSR	r11, r5, #24
	EOR	r8, r8, r12, ROR #8
	UBFX	r12, r7, #8, #8
	EOR	r8, r8, lr, ROR #16
	UBFX	lr, r6, #0, #8
	LDR	r9, [r0, r9, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r10, r5, #16, #8
	EOR	r9, r9, r11, ROR #24
	LSR	r11, r6, #24
	EOR	r9, r9, r12, ROR #8
	UBFX	r12, r4, #8, #8
	EOR	r9, r9, lr, ROR #16
	UBFX	lr, r7, #0, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r4, r4, #0, #8
	EOR	r10, r10, r11, ROR #24
	UBFX	r11, r6, #16, #8
	EOR	r10, r10, r12, ROR #8
	LSR	r12, r7, #24
	EOR	r10, r10, lr, ROR #16
	UBFX	lr, r5, #8, #8
	LDR	r4, [r0, r4, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	EOR	r12, r12, r4, ROR #24
	LDM	r3!, {r4, r5, r6, r7}
	EOR	r11, r11, lr, ROR #8
	EOR	r11, r11, r12, ROR #24
	/*   XOR in Key Schedule */
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	UBFX	r4, r11, #16, #8
	LSR	r7, r8, #24
	UBFX	r12, r10, #8, #8
	UBFX	lr, r9, #0, #8
	LDR	r4, [r0, r4, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r5, r8, #16, #8
	EOR	r4, r4, r7, ROR #24
	LSR	r7, r9, #24
	EOR	r4, r4, r12, ROR #8
	UBFX	r12, r11, #8, #8
	EOR	r4, r4, lr, ROR #16
	UBFX	lr, r10, #0, #8
	LDR	r5, [r0, r5, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r6, r9, #16, #8
	EOR	r5, r5, r7, ROR #24
	LSR	r7, r10, #24
	EOR	r5, r5, r12, ROR #8
	UBFX	r12, r8, #8, #8
	EOR	r5, r5, lr, ROR #16
	UBFX	lr, r11, #0, #8
	LDR	r6, [r0, r6, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r8, r8, #0, #8
	EOR	r6, r6, r7, ROR #24
	UBFX	r7, r10, #16, #8
	EOR	r6, r6, r12, ROR #8
	LSR	r12, r11, #24
	EOR	r6, r6, lr, ROR #16
	UBFX	lr, r9, #8, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	EOR	r12, r12, r8, ROR #24
	LDM	r3!, {r8, r9, r10, r11}
	EOR	r7, r7, lr, ROR #8
	EOR	r7, r7, r12, ROR #24
	/*   XOR in Key Schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	SUBS	r1, r1, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_AES_decrypt_block_nr
#else
	BNE.W	L_AES_decrypt_block_nr
#endif
	UBFX	r8, r7, #16, #8
	LSR	r11, r4, #24
	UBFX	r12, r6, #8, #8
	UBFX	lr, r5, #0, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r9, r4, #16, #8
	EOR	r8, r8, r11, ROR #24
	LSR	r11, r5, #24
	EOR	r8, r8, r12, ROR #8
	UBFX	r12, r7, #8, #8
	EOR	r8, r8, lr, ROR #16
	UBFX	lr, r6, #0, #8
	LDR	r9, [r0, r9, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r10, r5, #16, #8
	EOR	r9, r9, r11, ROR #24
	LSR	r11, r6, #24
	EOR	r9, r9, r12, ROR #8
	UBFX	r12, r4, #8, #8
	EOR	r9, r9, lr, ROR #16
	UBFX	lr, r7, #0, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r4, r4, #0, #8
	EOR	r10, r10, r11, ROR #24
	UBFX	r11, r6, #16, #8
	EOR	r10, r10, r12, ROR #8
	LSR	r12, r7, #24
	EOR	r10, r10, lr, ROR #16
	UBFX	lr, r5, #8, #8
	LDR	r4, [r0, r4, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	EOR	r12, r12, r4, ROR #24
	LDM	r3!, {r4, r5, r6, r7}
	EOR	r11, r11, lr, ROR #8
	EOR	r11, r11, r12, ROR #24
	/*   XOR in Key Schedule */
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	UBFX	r4, r9, #0, #8
	UBFX	r7, r10, #8, #8
	UBFX	r12, r11, #16, #8
	LSR	lr, r8, #24
	LDRB	r4, [r2, r4]
	LDRB	r7, [r2, r7]
	LDRB	r12, [r2, r12]
	LDRB	lr, [r2, lr]
	UBFX	r5, r10, #0, #8
	EOR	r4, r4, r7, LSL #8
	UBFX	r7, r11, #8, #8
	EOR	r4, r4, r12, LSL #16
	UBFX	r12, r8, #16, #8
	EOR	r4, r4, lr, LSL #24
	LSR	lr, r9, #24
	LDRB	r7, [r2, r7]
	LDRB	lr, [r2, lr]
	LDRB	r5, [r2, r5]
	LDRB	r12, [r2, r12]
	UBFX	r6, r11, #0, #8
	EOR	r5, r5, r7, LSL #8
	UBFX	r7, r8, #8, #8
	EOR	r5, r5, r12, LSL #16
	UBFX	r12, r9, #16, #8
	EOR	r5, r5, lr, LSL #24
	LSR	lr, r10, #24
	LDRB	r7, [r2, r7]
	LDRB	lr, [r2, lr]
	LDRB	r6, [r2, r6]
	LDRB	r12, [r2, r12]
	LSR	r11, r11, #24
	EOR	r6, r6, r7, LSL #8
	UBFX	r7, r8, #0, #8
	EOR	r6, r6, r12, LSL #16
	UBFX	r12, r9, #8, #8
	EOR	r6, r6, lr, LSL #24
	UBFX	lr, r10, #16, #8
	LDRB	r11, [r2, r11]
	LDRB	r12, [r2, r12]
	LDRB	r7, [r2, r7]
	LDRB	lr, [r2, lr]
	EOR	r12, r12, r11, LSL #16
	LDM	r3, {r8, r9, r10, r11}
	EOR	r7, r7, r12, LSL #8
	EOR	r7, r7, lr, LSL #16
	/*   XOR in Key Schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	POP	{pc}
	/* Cycle Count = 285 */
	.size	AES_decrypt_block,.-AES_decrypt_block
#endif /* !WOLFSSL_ARMASM_AES_BLOCK_INLINE */
#ifndef __APPLE__
	.text
	.type	L_AES_Thumb2_td_ecb, %object
	.size	L_AES_Thumb2_td_ecb, 12
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	/* 8-byte aligned, 64-bit aligned */
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_AES_Thumb2_td_ecb:
	.long	L_AES_Thumb2_td_data
#ifndef __APPLE__
	.text
	.type	L_AES_Thumb2_td4, %object
	.size	L_AES_Thumb2_td4, 256
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	/* 4-byte aligned, 32-bit aligned */
#ifndef __APPLE__
	.align	2
#else
	.p2align	2
#endif /* __APPLE__ */
L_AES_Thumb2_td4:
	.byte	0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38
	.byte	0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb
	.byte	0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87
	.byte	0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb
	.byte	0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d
	.byte	0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e
	.byte	0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2
	.byte	0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25
	.byte	0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16
	.byte	0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92
	.byte	0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda
	.byte	0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84
	.byte	0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a
	.byte	0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06
	.byte	0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02
	.byte	0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b
	.byte	0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea
	.byte	0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73
	.byte	0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85
	.byte	0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e
	.byte	0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89
	.byte	0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b
	.byte	0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20
	.byte	0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4
	.byte	0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31
	.byte	0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f
	.byte	0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d
	.byte	0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef
	.byte	0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0
	.byte	0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61
	.byte	0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26
	.byte	0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
#if defined(WOLFSSL_AES_DIRECT) || defined(WOLFSSL_AES_COUNTER) || defined(HAVE_AES_ECB)
	.text
	.align	4
	.globl	AES_ECB_decrypt
	.type	AES_ECB_decrypt, %function
AES_ECB_decrypt:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	LDR	r8, [sp, #36]
	MOV	lr, r0
	LDR	r0, L_AES_Thumb2_td_ecb
	MOV	r12, r2
	ADR	r2, L_AES_Thumb2_td4
	CMP	r8, #0xa
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BEQ	L_AES_ECB_decrypt_start_block_128
#else
	BEQ.W	L_AES_ECB_decrypt_start_block_128
#endif
	CMP	r8, #0xc
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BEQ	L_AES_ECB_decrypt_start_block_192
#else
	BEQ.W	L_AES_ECB_decrypt_start_block_192
#endif
L_AES_ECB_decrypt_loop_block_256:
	LDR	r4, [lr]
	LDR	r5, [lr, #4]
	LDR	r6, [lr, #8]
	LDR	r7, [lr, #12]
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
	REV	r7, r7
	PUSH	{r1, r3, r12, lr}
	LDM	r3!, {r8, r9, r10, r11}
	/* Round: 0 - XOR in key schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	MOV	r1, #0x6
#ifndef WOLFSSL_ARMASM_AES_BLOCK_INLINE
	BL	AES_decrypt_block
#else
L_AES_ECB_decrypt_block_nr_256:
	UBFX	r8, r7, #16, #8
	LSR	r11, r4, #24
	UBFX	r12, r6, #8, #8
	UBFX	lr, r5, #0, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r9, r4, #16, #8
	EOR	r8, r8, r11, ROR #24
	LSR	r11, r5, #24
	EOR	r8, r8, r12, ROR #8
	UBFX	r12, r7, #8, #8
	EOR	r8, r8, lr, ROR #16
	UBFX	lr, r6, #0, #8
	LDR	r9, [r0, r9, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r10, r5, #16, #8
	EOR	r9, r9, r11, ROR #24
	LSR	r11, r6, #24
	EOR	r9, r9, r12, ROR #8
	UBFX	r12, r4, #8, #8
	EOR	r9, r9, lr, ROR #16
	UBFX	lr, r7, #0, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r4, r4, #0, #8
	EOR	r10, r10, r11, ROR #24
	UBFX	r11, r6, #16, #8
	EOR	r10, r10, r12, ROR #8
	LSR	r12, r7, #24
	EOR	r10, r10, lr, ROR #16
	UBFX	lr, r5, #8, #8
	LDR	r4, [r0, r4, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	EOR	r12, r12, r4, ROR #24
	LDM	r3!, {r4, r5, r6, r7}
	EOR	r11, r11, lr, ROR #8
	EOR	r11, r11, r12, ROR #24
	/*   XOR in Key Schedule */
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	UBFX	r4, r11, #16, #8
	LSR	r7, r8, #24
	UBFX	r12, r10, #8, #8
	UBFX	lr, r9, #0, #8
	LDR	r4, [r0, r4, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r5, r8, #16, #8
	EOR	r4, r4, r7, ROR #24
	LSR	r7, r9, #24
	EOR	r4, r4, r12, ROR #8
	UBFX	r12, r11, #8, #8
	EOR	r4, r4, lr, ROR #16
	UBFX	lr, r10, #0, #8
	LDR	r5, [r0, r5, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r6, r9, #16, #8
	EOR	r5, r5, r7, ROR #24
	LSR	r7, r10, #24
	EOR	r5, r5, r12, ROR #8
	UBFX	r12, r8, #8, #8
	EOR	r5, r5, lr, ROR #16
	UBFX	lr, r11, #0, #8
	LDR	r6, [r0, r6, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r8, r8, #0, #8
	EOR	r6, r6, r7, ROR #24
	UBFX	r7, r10, #16, #8
	EOR	r6, r6, r12, ROR #8
	LSR	r12, r11, #24
	EOR	r6, r6, lr, ROR #16
	UBFX	lr, r9, #8, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	EOR	r12, r12, r8, ROR #24
	LDM	r3!, {r8, r9, r10, r11}
	EOR	r7, r7, lr, ROR #8
	EOR	r7, r7, r12, ROR #24
	/*   XOR in Key Schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	SUBS	r1, r1, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_AES_ECB_decrypt_block_nr_256
#else
	BNE.W	L_AES_ECB_decrypt_block_nr_256
#endif
	UBFX	r8, r7, #16, #8
	LSR	r11, r4, #24
	UBFX	r12, r6, #8, #8
	UBFX	lr, r5, #0, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r9, r4, #16, #8
	EOR	r8, r8, r11, ROR #24
	LSR	r11, r5, #24
	EOR	r8, r8, r12, ROR #8
	UBFX	r12, r7, #8, #8
	EOR	r8, r8, lr, ROR #16
	UBFX	lr, r6, #0, #8
	LDR	r9, [r0, r9, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r10, r5, #16, #8
	EOR	r9, r9, r11, ROR #24
	LSR	r11, r6, #24
	EOR	r9, r9, r12, ROR #8
	UBFX	r12, r4, #8, #8
	EOR	r9, r9, lr, ROR #16
	UBFX	lr, r7, #0, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r4, r4, #0, #8
	EOR	r10, r10, r11, ROR #24
	UBFX	r11, r6, #16, #8
	EOR	r10, r10, r12, ROR #8
	LSR	r12, r7, #24
	EOR	r10, r10, lr, ROR #16
	UBFX	lr, r5, #8, #8
	LDR	r4, [r0, r4, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	EOR	r12, r12, r4, ROR #24
	LDM	r3!, {r4, r5, r6, r7}
	EOR	r11, r11, lr, ROR #8
	EOR	r11, r11, r12, ROR #24
	/*   XOR in Key Schedule */
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	UBFX	r4, r9, #0, #8
	UBFX	r7, r10, #8, #8
	UBFX	r12, r11, #16, #8
	LSR	lr, r8, #24
	LDRB	r4, [r2, r4]
	LDRB	r7, [r2, r7]
	LDRB	r12, [r2, r12]
	LDRB	lr, [r2, lr]
	UBFX	r5, r10, #0, #8
	EOR	r4, r4, r7, LSL #8
	UBFX	r7, r11, #8, #8
	EOR	r4, r4, r12, LSL #16
	UBFX	r12, r8, #16, #8
	EOR	r4, r4, lr, LSL #24
	LSR	lr, r9, #24
	LDRB	r7, [r2, r7]
	LDRB	lr, [r2, lr]
	LDRB	r5, [r2, r5]
	LDRB	r12, [r2, r12]
	UBFX	r6, r11, #0, #8
	EOR	r5, r5, r7, LSL #8
	UBFX	r7, r8, #8, #8
	EOR	r5, r5, r12, LSL #16
	UBFX	r12, r9, #16, #8
	EOR	r5, r5, lr, LSL #24
	LSR	lr, r10, #24
	LDRB	r7, [r2, r7]
	LDRB	lr, [r2, lr]
	LDRB	r6, [r2, r6]
	LDRB	r12, [r2, r12]
	LSR	r11, r11, #24
	EOR	r6, r6, r7, LSL #8
	UBFX	r7, r8, #0, #8
	EOR	r6, r6, r12, LSL #16
	UBFX	r12, r9, #8, #8
	EOR	r6, r6, lr, LSL #24
	UBFX	lr, r10, #16, #8
	LDRB	r11, [r2, r11]
	LDRB	r12, [r2, r12]
	LDRB	r7, [r2, r7]
	LDRB	lr, [r2, lr]
	EOR	r12, r12, r11, LSL #16
	LDM	r3, {r8, r9, r10, r11}
	EOR	r7, r7, r12, LSL #8
	EOR	r7, r7, lr, LSL #16
	/*   XOR in Key Schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
#endif /* !WOLFSSL_ARMASM_AES_BLOCK_INLINE */
	POP	{r1, r3, r12, lr}
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
	REV	r7, r7
	STR	r4, [r1]
	STR	r5, [r1, #4]
	STR	r6, [r1, #8]
	STR	r7, [r1, #12]
	SUBS	r12, r12, #0x10
	ADD	lr, lr, #0x10
	ADD	r1, r1, #0x10
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_AES_ECB_decrypt_loop_block_256
#else
	BNE.W	L_AES_ECB_decrypt_loop_block_256
#endif
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	B	L_AES_ECB_decrypt_end
#else
	B.N	L_AES_ECB_decrypt_end
#endif
L_AES_ECB_decrypt_start_block_192:
L_AES_ECB_decrypt_loop_block_192:
	LDR	r4, [lr]
	LDR	r5, [lr, #4]
	LDR	r6, [lr, #8]
	LDR	r7, [lr, #12]
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
	REV	r7, r7
	PUSH	{r1, r3, r12, lr}
	LDM	r3!, {r8, r9, r10, r11}
	/* Round: 0 - XOR in key schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	MOV	r1, #0x5
#ifndef WOLFSSL_ARMASM_AES_BLOCK_INLINE
	BL	AES_decrypt_block
#else
L_AES_ECB_decrypt_block_nr_192:
	UBFX	r8, r7, #16, #8
	LSR	r11, r4, #24
	UBFX	r12, r6, #8, #8
	UBFX	lr, r5, #0, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r9, r4, #16, #8
	EOR	r8, r8, r11, ROR #24
	LSR	r11, r5, #24
	EOR	r8, r8, r12, ROR #8
	UBFX	r12, r7, #8, #8
	EOR	r8, r8, lr, ROR #16
	UBFX	lr, r6, #0, #8
	LDR	r9, [r0, r9, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r10, r5, #16, #8
	EOR	r9, r9, r11, ROR #24
	LSR	r11, r6, #24
	EOR	r9, r9, r12, ROR #8
	UBFX	r12, r4, #8, #8
	EOR	r9, r9, lr, ROR #16
	UBFX	lr, r7, #0, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r4, r4, #0, #8
	EOR	r10, r10, r11, ROR #24
	UBFX	r11, r6, #16, #8
	EOR	r10, r10, r12, ROR #8
	LSR	r12, r7, #24
	EOR	r10, r10, lr, ROR #16
	UBFX	lr, r5, #8, #8
	LDR	r4, [r0, r4, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	EOR	r12, r12, r4, ROR #24
	LDM	r3!, {r4, r5, r6, r7}
	EOR	r11, r11, lr, ROR #8
	EOR	r11, r11, r12, ROR #24
	/*   XOR in Key Schedule */
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	UBFX	r4, r11, #16, #8
	LSR	r7, r8, #24
	UBFX	r12, r10, #8, #8
	UBFX	lr, r9, #0, #8
	LDR	r4, [r0, r4, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r5, r8, #16, #8
	EOR	r4, r4, r7, ROR #24
	LSR	r7, r9, #24
	EOR	r4, r4, r12, ROR #8
	UBFX	r12, r11, #8, #8
	EOR	r4, r4, lr, ROR #16
	UBFX	lr, r10, #0, #8
	LDR	r5, [r0, r5, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r6, r9, #16, #8
	EOR	r5, r5, r7, ROR #24
	LSR	r7, r10, #24
	EOR	r5, r5, r12, ROR #8
	UBFX	r12, r8, #8, #8
	EOR	r5, r5, lr, ROR #16
	UBFX	lr, r11, #0, #8
	LDR	r6, [r0, r6, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r8, r8, #0, #8
	EOR	r6, r6, r7, ROR #24
	UBFX	r7, r10, #16, #8
	EOR	r6, r6, r12, ROR #8
	LSR	r12, r11, #24
	EOR	r6, r6, lr, ROR #16
	UBFX	lr, r9, #8, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	EOR	r12, r12, r8, ROR #24
	LDM	r3!, {r8, r9, r10, r11}
	EOR	r7, r7, lr, ROR #8
	EOR	r7, r7, r12, ROR #24
	/*   XOR in Key Schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	SUBS	r1, r1, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_AES_ECB_decrypt_block_nr_192
#else
	BNE.W	L_AES_ECB_decrypt_block_nr_192
#endif
	UBFX	r8, r7, #16, #8
	LSR	r11, r4, #24
	UBFX	r12, r6, #8, #8
	UBFX	lr, r5, #0, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r9, r4, #16, #8
	EOR	r8, r8, r11, ROR #24
	LSR	r11, r5, #24
	EOR	r8, r8, r12, ROR #8
	UBFX	r12, r7, #8, #8
	EOR	r8, r8, lr, ROR #16
	UBFX	lr, r6, #0, #8
	LDR	r9, [r0, r9, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r10, r5, #16, #8
	EOR	r9, r9, r11, ROR #24
	LSR	r11, r6, #24
	EOR	r9, r9, r12, ROR #8
	UBFX	r12, r4, #8, #8
	EOR	r9, r9, lr, ROR #16
	UBFX	lr, r7, #0, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r4, r4, #0, #8
	EOR	r10, r10, r11, ROR #24
	UBFX	r11, r6, #16, #8
	EOR	r10, r10, r12, ROR #8
	LSR	r12, r7, #24
	EOR	r10, r10, lr, ROR #16
	UBFX	lr, r5, #8, #8
	LDR	r4, [r0, r4, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	EOR	r12, r12, r4, ROR #24
	LDM	r3!, {r4, r5, r6, r7}
	EOR	r11, r11, lr, ROR #8
	EOR	r11, r11, r12, ROR #24
	/*   XOR in Key Schedule */
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	UBFX	r4, r9, #0, #8
	UBFX	r7, r10, #8, #8
	UBFX	r12, r11, #16, #8
	LSR	lr, r8, #24
	LDRB	r4, [r2, r4]
	LDRB	r7, [r2, r7]
	LDRB	r12, [r2, r12]
	LDRB	lr, [r2, lr]
	UBFX	r5, r10, #0, #8
	EOR	r4, r4, r7, LSL #8
	UBFX	r7, r11, #8, #8
	EOR	r4, r4, r12, LSL #16
	UBFX	r12, r8, #16, #8
	EOR	r4, r4, lr, LSL #24
	LSR	lr, r9, #24
	LDRB	r7, [r2, r7]
	LDRB	lr, [r2, lr]
	LDRB	r5, [r2, r5]
	LDRB	r12, [r2, r12]
	UBFX	r6, r11, #0, #8
	EOR	r5, r5, r7, LSL #8
	UBFX	r7, r8, #8, #8
	EOR	r5, r5, r12, LSL #16
	UBFX	r12, r9, #16, #8
	EOR	r5, r5, lr, LSL #24
	LSR	lr, r10, #24
	LDRB	r7, [r2, r7]
	LDRB	lr, [r2, lr]
	LDRB	r6, [r2, r6]
	LDRB	r12, [r2, r12]
	LSR	r11, r11, #24
	EOR	r6, r6, r7, LSL #8
	UBFX	r7, r8, #0, #8
	EOR	r6, r6, r12, LSL #16
	UBFX	r12, r9, #8, #8
	EOR	r6, r6, lr, LSL #24
	UBFX	lr, r10, #16, #8
	LDRB	r11, [r2, r11]
	LDRB	r12, [r2, r12]
	LDRB	r7, [r2, r7]
	LDRB	lr, [r2, lr]
	EOR	r12, r12, r11, LSL #16
	LDM	r3, {r8, r9, r10, r11}
	EOR	r7, r7, r12, LSL #8
	EOR	r7, r7, lr, LSL #16
	/*   XOR in Key Schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
#endif /* !WOLFSSL_ARMASM_AES_BLOCK_INLINE */
	POP	{r1, r3, r12, lr}
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
	REV	r7, r7
	STR	r4, [r1]
	STR	r5, [r1, #4]
	STR	r6, [r1, #8]
	STR	r7, [r1, #12]
	SUBS	r12, r12, #0x10
	ADD	lr, lr, #0x10
	ADD	r1, r1, #0x10
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_AES_ECB_decrypt_loop_block_192
#else
	BNE.W	L_AES_ECB_decrypt_loop_block_192
#endif
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	B	L_AES_ECB_decrypt_end
#else
	B.N	L_AES_ECB_decrypt_end
#endif
L_AES_ECB_decrypt_start_block_128:
L_AES_ECB_decrypt_loop_block_128:
	LDR	r4, [lr]
	LDR	r5, [lr, #4]
	LDR	r6, [lr, #8]
	LDR	r7, [lr, #12]
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
	REV	r7, r7
	PUSH	{r1, r3, r12, lr}
	LDM	r3!, {r8, r9, r10, r11}
	/* Round: 0 - XOR in key schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	MOV	r1, #0x4
#ifndef WOLFSSL_ARMASM_AES_BLOCK_INLINE
	BL	AES_decrypt_block
#else
L_AES_ECB_decrypt_block_nr_128:
	UBFX	r8, r7, #16, #8
	LSR	r11, r4, #24
	UBFX	r12, r6, #8, #8
	UBFX	lr, r5, #0, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r9, r4, #16, #8
	EOR	r8, r8, r11, ROR #24
	LSR	r11, r5, #24
	EOR	r8, r8, r12, ROR #8
	UBFX	r12, r7, #8, #8
	EOR	r8, r8, lr, ROR #16
	UBFX	lr, r6, #0, #8
	LDR	r9, [r0, r9, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r10, r5, #16, #8
	EOR	r9, r9, r11, ROR #24
	LSR	r11, r6, #24
	EOR	r9, r9, r12, ROR #8
	UBFX	r12, r4, #8, #8
	EOR	r9, r9, lr, ROR #16
	UBFX	lr, r7, #0, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r4, r4, #0, #8
	EOR	r10, r10, r11, ROR #24
	UBFX	r11, r6, #16, #8
	EOR	r10, r10, r12, ROR #8
	LSR	r12, r7, #24
	EOR	r10, r10, lr, ROR #16
	UBFX	lr, r5, #8, #8
	LDR	r4, [r0, r4, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	EOR	r12, r12, r4, ROR #24
	LDM	r3!, {r4, r5, r6, r7}
	EOR	r11, r11, lr, ROR #8
	EOR	r11, r11, r12, ROR #24
	/*   XOR in Key Schedule */
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	UBFX	r4, r11, #16, #8
	LSR	r7, r8, #24
	UBFX	r12, r10, #8, #8
	UBFX	lr, r9, #0, #8
	LDR	r4, [r0, r4, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r5, r8, #16, #8
	EOR	r4, r4, r7, ROR #24
	LSR	r7, r9, #24
	EOR	r4, r4, r12, ROR #8
	UBFX	r12, r11, #8, #8
	EOR	r4, r4, lr, ROR #16
	UBFX	lr, r10, #0, #8
	LDR	r5, [r0, r5, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r6, r9, #16, #8
	EOR	r5, r5, r7, ROR #24
	LSR	r7, r10, #24
	EOR	r5, r5, r12, ROR #8
	UBFX	r12, r8, #8, #8
	EOR	r5, r5, lr, ROR #16
	UBFX	lr, r11, #0, #8
	LDR	r6, [r0, r6, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r8, r8, #0, #8
	EOR	r6, r6, r7, ROR #24
	UBFX	r7, r10, #16, #8
	EOR	r6, r6, r12, ROR #8
	LSR	r12, r11, #24
	EOR	r6, r6, lr, ROR #16
	UBFX	lr, r9, #8, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	EOR	r12, r12, r8, ROR #24
	LDM	r3!, {r8, r9, r10, r11}
	EOR	r7, r7, lr, ROR #8
	EOR	r7, r7, r12, ROR #24
	/*   XOR in Key Schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	SUBS	r1, r1, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_AES_ECB_decrypt_block_nr_128
#else
	BNE.W	L_AES_ECB_decrypt_block_nr_128
#endif
	UBFX	r8, r7, #16, #8
	LSR	r11, r4, #24
	UBFX	r12, r6, #8, #8
	UBFX	lr, r5, #0, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r9, r4, #16, #8
	EOR	r8, r8, r11, ROR #24
	LSR	r11, r5, #24
	EOR	r8, r8, r12, ROR #8
	UBFX	r12, r7, #8, #8
	EOR	r8, r8, lr, ROR #16
	UBFX	lr, r6, #0, #8
	LDR	r9, [r0, r9, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r10, r5, #16, #8
	EOR	r9, r9, r11, ROR #24
	LSR	r11, r6, #24
	EOR	r9, r9, r12, ROR #8
	UBFX	r12, r4, #8, #8
	EOR	r9, r9, lr, ROR #16
	UBFX	lr, r7, #0, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r4, r4, #0, #8
	EOR	r10, r10, r11, ROR #24
	UBFX	r11, r6, #16, #8
	EOR	r10, r10, r12, ROR #8
	LSR	r12, r7, #24
	EOR	r10, r10, lr, ROR #16
	UBFX	lr, r5, #8, #8
	LDR	r4, [r0, r4, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	EOR	r12, r12, r4, ROR #24
	LDM	r3!, {r4, r5, r6, r7}
	EOR	r11, r11, lr, ROR #8
	EOR	r11, r11, r12, ROR #24
	/*   XOR in Key Schedule */
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	UBFX	r4, r9, #0, #8
	UBFX	r7, r10, #8, #8
	UBFX	r12, r11, #16, #8
	LSR	lr, r8, #24
	LDRB	r4, [r2, r4]
	LDRB	r7, [r2, r7]
	LDRB	r12, [r2, r12]
	LDRB	lr, [r2, lr]
	UBFX	r5, r10, #0, #8
	EOR	r4, r4, r7, LSL #8
	UBFX	r7, r11, #8, #8
	EOR	r4, r4, r12, LSL #16
	UBFX	r12, r8, #16, #8
	EOR	r4, r4, lr, LSL #24
	LSR	lr, r9, #24
	LDRB	r7, [r2, r7]
	LDRB	lr, [r2, lr]
	LDRB	r5, [r2, r5]
	LDRB	r12, [r2, r12]
	UBFX	r6, r11, #0, #8
	EOR	r5, r5, r7, LSL #8
	UBFX	r7, r8, #8, #8
	EOR	r5, r5, r12, LSL #16
	UBFX	r12, r9, #16, #8
	EOR	r5, r5, lr, LSL #24
	LSR	lr, r10, #24
	LDRB	r7, [r2, r7]
	LDRB	lr, [r2, lr]
	LDRB	r6, [r2, r6]
	LDRB	r12, [r2, r12]
	LSR	r11, r11, #24
	EOR	r6, r6, r7, LSL #8
	UBFX	r7, r8, #0, #8
	EOR	r6, r6, r12, LSL #16
	UBFX	r12, r9, #8, #8
	EOR	r6, r6, lr, LSL #24
	UBFX	lr, r10, #16, #8
	LDRB	r11, [r2, r11]
	LDRB	r12, [r2, r12]
	LDRB	r7, [r2, r7]
	LDRB	lr, [r2, lr]
	EOR	r12, r12, r11, LSL #16
	LDM	r3, {r8, r9, r10, r11}
	EOR	r7, r7, r12, LSL #8
	EOR	r7, r7, lr, LSL #16
	/*   XOR in Key Schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
#endif /* !WOLFSSL_ARMASM_AES_BLOCK_INLINE */
	POP	{r1, r3, r12, lr}
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
	REV	r7, r7
	STR	r4, [r1]
	STR	r5, [r1, #4]
	STR	r6, [r1, #8]
	STR	r7, [r1, #12]
	SUBS	r12, r12, #0x10
	ADD	lr, lr, #0x10
	ADD	r1, r1, #0x10
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_AES_ECB_decrypt_loop_block_128
#else
	BNE.W	L_AES_ECB_decrypt_loop_block_128
#endif
L_AES_ECB_decrypt_end:
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 1053 */
	.size	AES_ECB_decrypt,.-AES_ECB_decrypt
#endif /* WOLFSSL_AES_DIRECT || WOLFSSL_AES_COUNTER || defined(HAVE_AES_ECB) */
#ifdef HAVE_AES_CBC
	.text
	.align	4
	.globl	AES_CBC_decrypt
	.type	AES_CBC_decrypt, %function
AES_CBC_decrypt:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	MOV	lr, r0
	LDR	r0, L_AES_Thumb2_td_ecb
	MOV	r12, r2
	ADR	r2, L_AES_Thumb2_td4
	LDR	r8, [sp, #36]
	LDR	r4, [sp, #40]
	PUSH	{r3, r4}
	CMP	r8, #0xa
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BEQ	L_AES_CBC_decrypt_loop_block_128
#else
	BEQ.W	L_AES_CBC_decrypt_loop_block_128
#endif
	CMP	r8, #0xc
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BEQ	L_AES_CBC_decrypt_loop_block_192
#else
	BEQ.W	L_AES_CBC_decrypt_loop_block_192
#endif
L_AES_CBC_decrypt_loop_block_256:
	PUSH	{r1, r12, lr}
	LDR	r4, [lr]
	LDR	r5, [lr, #4]
	LDR	r6, [lr, #8]
	LDR	r7, [lr, #12]
	LDR	lr, [sp, #16]
	STRD	r4, r5, [lr, #16]
	STRD	r6, r7, [lr, #24]
	LDM	r3!, {r8, r9, r10, r11}
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
	REV	r7, r7
	/* Round: 0 - XOR in key schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	MOV	r1, #0x6
#ifndef WOLFSSL_ARMASM_AES_BLOCK_INLINE
	BL	AES_decrypt_block
#else
L_AES_CBC_decrypt_block_nr_256_odd:
	UBFX	r8, r7, #16, #8
	LSR	r11, r4, #24
	UBFX	r12, r6, #8, #8
	UBFX	lr, r5, #0, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r9, r4, #16, #8
	EOR	r8, r8, r11, ROR #24
	LSR	r11, r5, #24
	EOR	r8, r8, r12, ROR #8
	UBFX	r12, r7, #8, #8
	EOR	r8, r8, lr, ROR #16
	UBFX	lr, r6, #0, #8
	LDR	r9, [r0, r9, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r10, r5, #16, #8
	EOR	r9, r9, r11, ROR #24
	LSR	r11, r6, #24
	EOR	r9, r9, r12, ROR #8
	UBFX	r12, r4, #8, #8
	EOR	r9, r9, lr, ROR #16
	UBFX	lr, r7, #0, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r4, r4, #0, #8
	EOR	r10, r10, r11, ROR #24
	UBFX	r11, r6, #16, #8
	EOR	r10, r10, r12, ROR #8
	LSR	r12, r7, #24
	EOR	r10, r10, lr, ROR #16
	UBFX	lr, r5, #8, #8
	LDR	r4, [r0, r4, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	EOR	r12, r12, r4, ROR #24
	LDM	r3!, {r4, r5, r6, r7}
	EOR	r11, r11, lr, ROR #8
	EOR	r11, r11, r12, ROR #24
	/*   XOR in Key Schedule */
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	UBFX	r4, r11, #16, #8
	LSR	r7, r8, #24
	UBFX	r12, r10, #8, #8
	UBFX	lr, r9, #0, #8
	LDR	r4, [r0, r4, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r5, r8, #16, #8
	EOR	r4, r4, r7, ROR #24
	LSR	r7, r9, #24
	EOR	r4, r4, r12, ROR #8
	UBFX	r12, r11, #8, #8
	EOR	r4, r4, lr, ROR #16
	UBFX	lr, r10, #0, #8
	LDR	r5, [r0, r5, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r6, r9, #16, #8
	EOR	r5, r5, r7, ROR #24
	LSR	r7, r10, #24
	EOR	r5, r5, r12, ROR #8
	UBFX	r12, r8, #8, #8
	EOR	r5, r5, lr, ROR #16
	UBFX	lr, r11, #0, #8
	LDR	r6, [r0, r6, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r8, r8, #0, #8
	EOR	r6, r6, r7, ROR #24
	UBFX	r7, r10, #16, #8
	EOR	r6, r6, r12, ROR #8
	LSR	r12, r11, #24
	EOR	r6, r6, lr, ROR #16
	UBFX	lr, r9, #8, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	EOR	r12, r12, r8, ROR #24
	LDM	r3!, {r8, r9, r10, r11}
	EOR	r7, r7, lr, ROR #8
	EOR	r7, r7, r12, ROR #24
	/*   XOR in Key Schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	SUBS	r1, r1, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_AES_CBC_decrypt_block_nr_256_odd
#else
	BNE.W	L_AES_CBC_decrypt_block_nr_256_odd
#endif
	UBFX	r8, r7, #16, #8
	LSR	r11, r4, #24
	UBFX	r12, r6, #8, #8
	UBFX	lr, r5, #0, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r9, r4, #16, #8
	EOR	r8, r8, r11, ROR #24
	LSR	r11, r5, #24
	EOR	r8, r8, r12, ROR #8
	UBFX	r12, r7, #8, #8
	EOR	r8, r8, lr, ROR #16
	UBFX	lr, r6, #0, #8
	LDR	r9, [r0, r9, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r10, r5, #16, #8
	EOR	r9, r9, r11, ROR #24
	LSR	r11, r6, #24
	EOR	r9, r9, r12, ROR #8
	UBFX	r12, r4, #8, #8
	EOR	r9, r9, lr, ROR #16
	UBFX	lr, r7, #0, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r4, r4, #0, #8
	EOR	r10, r10, r11, ROR #24
	UBFX	r11, r6, #16, #8
	EOR	r10, r10, r12, ROR #8
	LSR	r12, r7, #24
	EOR	r10, r10, lr, ROR #16
	UBFX	lr, r5, #8, #8
	LDR	r4, [r0, r4, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	EOR	r12, r12, r4, ROR #24
	LDM	r3!, {r4, r5, r6, r7}
	EOR	r11, r11, lr, ROR #8
	EOR	r11, r11, r12, ROR #24
	/*   XOR in Key Schedule */
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	UBFX	r4, r9, #0, #8
	UBFX	r7, r10, #8, #8
	UBFX	r12, r11, #16, #8
	LSR	lr, r8, #24
	LDRB	r4, [r2, r4]
	LDRB	r7, [r2, r7]
	LDRB	r12, [r2, r12]
	LDRB	lr, [r2, lr]
	UBFX	r5, r10, #0, #8
	EOR	r4, r4, r7, LSL #8
	UBFX	r7, r11, #8, #8
	EOR	r4, r4, r12, LSL #16
	UBFX	r12, r8, #16, #8
	EOR	r4, r4, lr, LSL #24
	LSR	lr, r9, #24
	LDRB	r7, [r2, r7]
	LDRB	lr, [r2, lr]
	LDRB	r5, [r2, r5]
	LDRB	r12, [r2, r12]
	UBFX	r6, r11, #0, #8
	EOR	r5, r5, r7, LSL #8
	UBFX	r7, r8, #8, #8
	EOR	r5, r5, r12, LSL #16
	UBFX	r12, r9, #16, #8
	EOR	r5, r5, lr, LSL #24
	LSR	lr, r10, #24
	LDRB	r7, [r2, r7]
	LDRB	lr, [r2, lr]
	LDRB	r6, [r2, r6]
	LDRB	r12, [r2, r12]
	LSR	r11, r11, #24
	EOR	r6, r6, r7, LSL #8
	UBFX	r7, r8, #0, #8
	EOR	r6, r6, r12, LSL #16
	UBFX	r12, r9, #8, #8
	EOR	r6, r6, lr, LSL #24
	UBFX	lr, r10, #16, #8
	LDRB	r11, [r2, r11]
	LDRB	r12, [r2, r12]
	LDRB	r7, [r2, r7]
	LDRB	lr, [r2, lr]
	EOR	r12, r12, r11, LSL #16
	LDM	r3, {r8, r9, r10, r11}
	EOR	r7, r7, r12, LSL #8
	EOR	r7, r7, lr, LSL #16
	/*   XOR in Key Schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
#endif /* !WOLFSSL_ARMASM_AES_BLOCK_INLINE */
	LDR	lr, [sp, #16]
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
	REV	r7, r7
	LDM	lr, {r8, r9, r10, r11}
	POP	{r1, r12, lr}
	LDR	r3, [sp]
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	STR	r4, [r1]
	STR	r5, [r1, #4]
	STR	r6, [r1, #8]
	STR	r7, [r1, #12]
	SUBS	r12, r12, #0x10
	ADD	lr, lr, #0x10
	ADD	r1, r1, #0x10
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BEQ	L_AES_CBC_decrypt_end_odd
#else
	BEQ.W	L_AES_CBC_decrypt_end_odd
#endif
	PUSH	{r1, r12, lr}
	LDR	r4, [lr]
	LDR	r5, [lr, #4]
	LDR	r6, [lr, #8]
	LDR	r7, [lr, #12]
	LDR	lr, [sp, #16]
	STRD	r4, r5, [lr]
	STRD	r6, r7, [lr, #8]
	LDM	r3!, {r8, r9, r10, r11}
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
	REV	r7, r7
	/* Round: 0 - XOR in key schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	MOV	r1, #0x6
#ifndef WOLFSSL_ARMASM_AES_BLOCK_INLINE
	BL	AES_decrypt_block
#else
L_AES_CBC_decrypt_block_nr_256_even:
	UBFX	r8, r7, #16, #8
	LSR	r11, r4, #24
	UBFX	r12, r6, #8, #8
	UBFX	lr, r5, #0, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r9, r4, #16, #8
	EOR	r8, r8, r11, ROR #24
	LSR	r11, r5, #24
	EOR	r8, r8, r12, ROR #8
	UBFX	r12, r7, #8, #8
	EOR	r8, r8, lr, ROR #16
	UBFX	lr, r6, #0, #8
	LDR	r9, [r0, r9, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r10, r5, #16, #8
	EOR	r9, r9, r11, ROR #24
	LSR	r11, r6, #24
	EOR	r9, r9, r12, ROR #8
	UBFX	r12, r4, #8, #8
	EOR	r9, r9, lr, ROR #16
	UBFX	lr, r7, #0, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r4, r4, #0, #8
	EOR	r10, r10, r11, ROR #24
	UBFX	r11, r6, #16, #8
	EOR	r10, r10, r12, ROR #8
	LSR	r12, r7, #24
	EOR	r10, r10, lr, ROR #16
	UBFX	lr, r5, #8, #8
	LDR	r4, [r0, r4, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	EOR	r12, r12, r4, ROR #24
	LDM	r3!, {r4, r5, r6, r7}
	EOR	r11, r11, lr, ROR #8
	EOR	r11, r11, r12, ROR #24
	/*   XOR in Key Schedule */
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	UBFX	r4, r11, #16, #8
	LSR	r7, r8, #24
	UBFX	r12, r10, #8, #8
	UBFX	lr, r9, #0, #8
	LDR	r4, [r0, r4, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r5, r8, #16, #8
	EOR	r4, r4, r7, ROR #24
	LSR	r7, r9, #24
	EOR	r4, r4, r12, ROR #8
	UBFX	r12, r11, #8, #8
	EOR	r4, r4, lr, ROR #16
	UBFX	lr, r10, #0, #8
	LDR	r5, [r0, r5, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r6, r9, #16, #8
	EOR	r5, r5, r7, ROR #24
	LSR	r7, r10, #24
	EOR	r5, r5, r12, ROR #8
	UBFX	r12, r8, #8, #8
	EOR	r5, r5, lr, ROR #16
	UBFX	lr, r11, #0, #8
	LDR	r6, [r0, r6, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r8, r8, #0, #8
	EOR	r6, r6, r7, ROR #24
	UBFX	r7, r10, #16, #8
	EOR	r6, r6, r12, ROR #8
	LSR	r12, r11, #24
	EOR	r6, r6, lr, ROR #16
	UBFX	lr, r9, #8, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	EOR	r12, r12, r8, ROR #24
	LDM	r3!, {r8, r9, r10, r11}
	EOR	r7, r7, lr, ROR #8
	EOR	r7, r7, r12, ROR #24
	/*   XOR in Key Schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	SUBS	r1, r1, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_AES_CBC_decrypt_block_nr_256_even
#else
	BNE.W	L_AES_CBC_decrypt_block_nr_256_even
#endif
	UBFX	r8, r7, #16, #8
	LSR	r11, r4, #24
	UBFX	r12, r6, #8, #8
	UBFX	lr, r5, #0, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r9, r4, #16, #8
	EOR	r8, r8, r11, ROR #24
	LSR	r11, r5, #24
	EOR	r8, r8, r12, ROR #8
	UBFX	r12, r7, #8, #8
	EOR	r8, r8, lr, ROR #16
	UBFX	lr, r6, #0, #8
	LDR	r9, [r0, r9, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r10, r5, #16, #8
	EOR	r9, r9, r11, ROR #24
	LSR	r11, r6, #24
	EOR	r9, r9, r12, ROR #8
	UBFX	r12, r4, #8, #8
	EOR	r9, r9, lr, ROR #16
	UBFX	lr, r7, #0, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r4, r4, #0, #8
	EOR	r10, r10, r11, ROR #24
	UBFX	r11, r6, #16, #8
	EOR	r10, r10, r12, ROR #8
	LSR	r12, r7, #24
	EOR	r10, r10, lr, ROR #16
	UBFX	lr, r5, #8, #8
	LDR	r4, [r0, r4, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	EOR	r12, r12, r4, ROR #24
	LDM	r3!, {r4, r5, r6, r7}
	EOR	r11, r11, lr, ROR #8
	EOR	r11, r11, r12, ROR #24
	/*   XOR in Key Schedule */
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	UBFX	r4, r9, #0, #8
	UBFX	r7, r10, #8, #8
	UBFX	r12, r11, #16, #8
	LSR	lr, r8, #24
	LDRB	r4, [r2, r4]
	LDRB	r7, [r2, r7]
	LDRB	r12, [r2, r12]
	LDRB	lr, [r2, lr]
	UBFX	r5, r10, #0, #8
	EOR	r4, r4, r7, LSL #8
	UBFX	r7, r11, #8, #8
	EOR	r4, r4, r12, LSL #16
	UBFX	r12, r8, #16, #8
	EOR	r4, r4, lr, LSL #24
	LSR	lr, r9, #24
	LDRB	r7, [r2, r7]
	LDRB	lr, [r2, lr]
	LDRB	r5, [r2, r5]
	LDRB	r12, [r2, r12]
	UBFX	r6, r11, #0, #8
	EOR	r5, r5, r7, LSL #8
	UBFX	r7, r8, #8, #8
	EOR	r5, r5, r12, LSL #16
	UBFX	r12, r9, #16, #8
	EOR	r5, r5, lr, LSL #24
	LSR	lr, r10, #24
	LDRB	r7, [r2, r7]
	LDRB	lr, [r2, lr]
	LDRB	r6, [r2, r6]
	LDRB	r12, [r2, r12]
	LSR	r11, r11, #24
	EOR	r6, r6, r7, LSL #8
	UBFX	r7, r8, #0, #8
	EOR	r6, r6, r12, LSL #16
	UBFX	r12, r9, #8, #8
	EOR	r6, r6, lr, LSL #24
	UBFX	lr, r10, #16, #8
	LDRB	r11, [r2, r11]
	LDRB	r12, [r2, r12]
	LDRB	r7, [r2, r7]
	LDRB	lr, [r2, lr]
	EOR	r12, r12, r11, LSL #16
	LDM	r3, {r8, r9, r10, r11}
	EOR	r7, r7, r12, LSL #8
	EOR	r7, r7, lr, LSL #16
	/*   XOR in Key Schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
#endif /* !WOLFSSL_ARMASM_AES_BLOCK_INLINE */
	LDR	lr, [sp, #16]
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
	REV	r7, r7
	LDRD	r8, r9, [lr, #16]
	LDRD	r10, r11, [lr, #24]
	POP	{r1, r12, lr}
	LDR	r3, [sp]
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	STR	r4, [r1]
	STR	r5, [r1, #4]
	STR	r6, [r1, #8]
	STR	r7, [r1, #12]
	SUBS	r12, r12, #0x10
	ADD	lr, lr, #0x10
	ADD	r1, r1, #0x10
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_AES_CBC_decrypt_loop_block_256
#else
	BNE.W	L_AES_CBC_decrypt_loop_block_256
#endif
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	B	L_AES_CBC_decrypt_end
#else
	B.W	L_AES_CBC_decrypt_end
#endif
L_AES_CBC_decrypt_loop_block_192:
	PUSH	{r1, r12, lr}
	LDR	r4, [lr]
	LDR	r5, [lr, #4]
	LDR	r6, [lr, #8]
	LDR	r7, [lr, #12]
	LDR	lr, [sp, #16]
	STRD	r4, r5, [lr, #16]
	STRD	r6, r7, [lr, #24]
	LDM	r3!, {r8, r9, r10, r11}
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
	REV	r7, r7
	/* Round: 0 - XOR in key schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	MOV	r1, #0x5
#ifndef WOLFSSL_ARMASM_AES_BLOCK_INLINE
	BL	AES_decrypt_block
#else
L_AES_CBC_decrypt_block_nr_192_odd:
	UBFX	r8, r7, #16, #8
	LSR	r11, r4, #24
	UBFX	r12, r6, #8, #8
	UBFX	lr, r5, #0, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r9, r4, #16, #8
	EOR	r8, r8, r11, ROR #24
	LSR	r11, r5, #24
	EOR	r8, r8, r12, ROR #8
	UBFX	r12, r7, #8, #8
	EOR	r8, r8, lr, ROR #16
	UBFX	lr, r6, #0, #8
	LDR	r9, [r0, r9, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r10, r5, #16, #8
	EOR	r9, r9, r11, ROR #24
	LSR	r11, r6, #24
	EOR	r9, r9, r12, ROR #8
	UBFX	r12, r4, #8, #8
	EOR	r9, r9, lr, ROR #16
	UBFX	lr, r7, #0, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r4, r4, #0, #8
	EOR	r10, r10, r11, ROR #24
	UBFX	r11, r6, #16, #8
	EOR	r10, r10, r12, ROR #8
	LSR	r12, r7, #24
	EOR	r10, r10, lr, ROR #16
	UBFX	lr, r5, #8, #8
	LDR	r4, [r0, r4, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	EOR	r12, r12, r4, ROR #24
	LDM	r3!, {r4, r5, r6, r7}
	EOR	r11, r11, lr, ROR #8
	EOR	r11, r11, r12, ROR #24
	/*   XOR in Key Schedule */
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	UBFX	r4, r11, #16, #8
	LSR	r7, r8, #24
	UBFX	r12, r10, #8, #8
	UBFX	lr, r9, #0, #8
	LDR	r4, [r0, r4, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r5, r8, #16, #8
	EOR	r4, r4, r7, ROR #24
	LSR	r7, r9, #24
	EOR	r4, r4, r12, ROR #8
	UBFX	r12, r11, #8, #8
	EOR	r4, r4, lr, ROR #16
	UBFX	lr, r10, #0, #8
	LDR	r5, [r0, r5, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r6, r9, #16, #8
	EOR	r5, r5, r7, ROR #24
	LSR	r7, r10, #24
	EOR	r5, r5, r12, ROR #8
	UBFX	r12, r8, #8, #8
	EOR	r5, r5, lr, ROR #16
	UBFX	lr, r11, #0, #8
	LDR	r6, [r0, r6, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r8, r8, #0, #8
	EOR	r6, r6, r7, ROR #24
	UBFX	r7, r10, #16, #8
	EOR	r6, r6, r12, ROR #8
	LSR	r12, r11, #24
	EOR	r6, r6, lr, ROR #16
	UBFX	lr, r9, #8, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	EOR	r12, r12, r8, ROR #24
	LDM	r3!, {r8, r9, r10, r11}
	EOR	r7, r7, lr, ROR #8
	EOR	r7, r7, r12, ROR #24
	/*   XOR in Key Schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	SUBS	r1, r1, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_AES_CBC_decrypt_block_nr_192_odd
#else
	BNE.W	L_AES_CBC_decrypt_block_nr_192_odd
#endif
	UBFX	r8, r7, #16, #8
	LSR	r11, r4, #24
	UBFX	r12, r6, #8, #8
	UBFX	lr, r5, #0, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r9, r4, #16, #8
	EOR	r8, r8, r11, ROR #24
	LSR	r11, r5, #24
	EOR	r8, r8, r12, ROR #8
	UBFX	r12, r7, #8, #8
	EOR	r8, r8, lr, ROR #16
	UBFX	lr, r6, #0, #8
	LDR	r9, [r0, r9, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r10, r5, #16, #8
	EOR	r9, r9, r11, ROR #24
	LSR	r11, r6, #24
	EOR	r9, r9, r12, ROR #8
	UBFX	r12, r4, #8, #8
	EOR	r9, r9, lr, ROR #16
	UBFX	lr, r7, #0, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r4, r4, #0, #8
	EOR	r10, r10, r11, ROR #24
	UBFX	r11, r6, #16, #8
	EOR	r10, r10, r12, ROR #8
	LSR	r12, r7, #24
	EOR	r10, r10, lr, ROR #16
	UBFX	lr, r5, #8, #8
	LDR	r4, [r0, r4, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	EOR	r12, r12, r4, ROR #24
	LDM	r3!, {r4, r5, r6, r7}
	EOR	r11, r11, lr, ROR #8
	EOR	r11, r11, r12, ROR #24
	/*   XOR in Key Schedule */
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	UBFX	r4, r9, #0, #8
	UBFX	r7, r10, #8, #8
	UBFX	r12, r11, #16, #8
	LSR	lr, r8, #24
	LDRB	r4, [r2, r4]
	LDRB	r7, [r2, r7]
	LDRB	r12, [r2, r12]
	LDRB	lr, [r2, lr]
	UBFX	r5, r10, #0, #8
	EOR	r4, r4, r7, LSL #8
	UBFX	r7, r11, #8, #8
	EOR	r4, r4, r12, LSL #16
	UBFX	r12, r8, #16, #8
	EOR	r4, r4, lr, LSL #24
	LSR	lr, r9, #24
	LDRB	r7, [r2, r7]
	LDRB	lr, [r2, lr]
	LDRB	r5, [r2, r5]
	LDRB	r12, [r2, r12]
	UBFX	r6, r11, #0, #8
	EOR	r5, r5, r7, LSL #8
	UBFX	r7, r8, #8, #8
	EOR	r5, r5, r12, LSL #16
	UBFX	r12, r9, #16, #8
	EOR	r5, r5, lr, LSL #24
	LSR	lr, r10, #24
	LDRB	r7, [r2, r7]
	LDRB	lr, [r2, lr]
	LDRB	r6, [r2, r6]
	LDRB	r12, [r2, r12]
	LSR	r11, r11, #24
	EOR	r6, r6, r7, LSL #8
	UBFX	r7, r8, #0, #8
	EOR	r6, r6, r12, LSL #16
	UBFX	r12, r9, #8, #8
	EOR	r6, r6, lr, LSL #24
	UBFX	lr, r10, #16, #8
	LDRB	r11, [r2, r11]
	LDRB	r12, [r2, r12]
	LDRB	r7, [r2, r7]
	LDRB	lr, [r2, lr]
	EOR	r12, r12, r11, LSL #16
	LDM	r3, {r8, r9, r10, r11}
	EOR	r7, r7, r12, LSL #8
	EOR	r7, r7, lr, LSL #16
	/*   XOR in Key Schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
#endif /* !WOLFSSL_ARMASM_AES_BLOCK_INLINE */
	LDR	lr, [sp, #16]
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
	REV	r7, r7
	LDM	lr, {r8, r9, r10, r11}
	POP	{r1, r12, lr}
	LDR	r3, [sp]
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	STR	r4, [r1]
	STR	r5, [r1, #4]
	STR	r6, [r1, #8]
	STR	r7, [r1, #12]
	SUBS	r12, r12, #0x10
	ADD	lr, lr, #0x10
	ADD	r1, r1, #0x10
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BEQ	L_AES_CBC_decrypt_end_odd
#else
	BEQ.W	L_AES_CBC_decrypt_end_odd
#endif
	PUSH	{r1, r12, lr}
	LDR	r4, [lr]
	LDR	r5, [lr, #4]
	LDR	r6, [lr, #8]
	LDR	r7, [lr, #12]
	LDR	lr, [sp, #16]
	STRD	r4, r5, [lr]
	STRD	r6, r7, [lr, #8]
	LDM	r3!, {r8, r9, r10, r11}
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
	REV	r7, r7
	/* Round: 0 - XOR in key schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	MOV	r1, #0x5
#ifndef WOLFSSL_ARMASM_AES_BLOCK_INLINE
	BL	AES_decrypt_block
#else
L_AES_CBC_decrypt_block_nr_192_even:
	UBFX	r8, r7, #16, #8
	LSR	r11, r4, #24
	UBFX	r12, r6, #8, #8
	UBFX	lr, r5, #0, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r9, r4, #16, #8
	EOR	r8, r8, r11, ROR #24
	LSR	r11, r5, #24
	EOR	r8, r8, r12, ROR #8
	UBFX	r12, r7, #8, #8
	EOR	r8, r8, lr, ROR #16
	UBFX	lr, r6, #0, #8
	LDR	r9, [r0, r9, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r10, r5, #16, #8
	EOR	r9, r9, r11, ROR #24
	LSR	r11, r6, #24
	EOR	r9, r9, r12, ROR #8
	UBFX	r12, r4, #8, #8
	EOR	r9, r9, lr, ROR #16
	UBFX	lr, r7, #0, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r4, r4, #0, #8
	EOR	r10, r10, r11, ROR #24
	UBFX	r11, r6, #16, #8
	EOR	r10, r10, r12, ROR #8
	LSR	r12, r7, #24
	EOR	r10, r10, lr, ROR #16
	UBFX	lr, r5, #8, #8
	LDR	r4, [r0, r4, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	EOR	r12, r12, r4, ROR #24
	LDM	r3!, {r4, r5, r6, r7}
	EOR	r11, r11, lr, ROR #8
	EOR	r11, r11, r12, ROR #24
	/*   XOR in Key Schedule */
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	UBFX	r4, r11, #16, #8
	LSR	r7, r8, #24
	UBFX	r12, r10, #8, #8
	UBFX	lr, r9, #0, #8
	LDR	r4, [r0, r4, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r5, r8, #16, #8
	EOR	r4, r4, r7, ROR #24
	LSR	r7, r9, #24
	EOR	r4, r4, r12, ROR #8
	UBFX	r12, r11, #8, #8
	EOR	r4, r4, lr, ROR #16
	UBFX	lr, r10, #0, #8
	LDR	r5, [r0, r5, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r6, r9, #16, #8
	EOR	r5, r5, r7, ROR #24
	LSR	r7, r10, #24
	EOR	r5, r5, r12, ROR #8
	UBFX	r12, r8, #8, #8
	EOR	r5, r5, lr, ROR #16
	UBFX	lr, r11, #0, #8
	LDR	r6, [r0, r6, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r8, r8, #0, #8
	EOR	r6, r6, r7, ROR #24
	UBFX	r7, r10, #16, #8
	EOR	r6, r6, r12, ROR #8
	LSR	r12, r11, #24
	EOR	r6, r6, lr, ROR #16
	UBFX	lr, r9, #8, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	EOR	r12, r12, r8, ROR #24
	LDM	r3!, {r8, r9, r10, r11}
	EOR	r7, r7, lr, ROR #8
	EOR	r7, r7, r12, ROR #24
	/*   XOR in Key Schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	SUBS	r1, r1, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_AES_CBC_decrypt_block_nr_192_even
#else
	BNE.W	L_AES_CBC_decrypt_block_nr_192_even
#endif
	UBFX	r8, r7, #16, #8
	LSR	r11, r4, #24
	UBFX	r12, r6, #8, #8
	UBFX	lr, r5, #0, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r9, r4, #16, #8
	EOR	r8, r8, r11, ROR #24
	LSR	r11, r5, #24
	EOR	r8, r8, r12, ROR #8
	UBFX	r12, r7, #8, #8
	EOR	r8, r8, lr, ROR #16
	UBFX	lr, r6, #0, #8
	LDR	r9, [r0, r9, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r10, r5, #16, #8
	EOR	r9, r9, r11, ROR #24
	LSR	r11, r6, #24
	EOR	r9, r9, r12, ROR #8
	UBFX	r12, r4, #8, #8
	EOR	r9, r9, lr, ROR #16
	UBFX	lr, r7, #0, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r4, r4, #0, #8
	EOR	r10, r10, r11, ROR #24
	UBFX	r11, r6, #16, #8
	EOR	r10, r10, r12, ROR #8
	LSR	r12, r7, #24
	EOR	r10, r10, lr, ROR #16
	UBFX	lr, r5, #8, #8
	LDR	r4, [r0, r4, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	EOR	r12, r12, r4, ROR #24
	LDM	r3!, {r4, r5, r6, r7}
	EOR	r11, r11, lr, ROR #8
	EOR	r11, r11, r12, ROR #24
	/*   XOR in Key Schedule */
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	UBFX	r4, r9, #0, #8
	UBFX	r7, r10, #8, #8
	UBFX	r12, r11, #16, #8
	LSR	lr, r8, #24
	LDRB	r4, [r2, r4]
	LDRB	r7, [r2, r7]
	LDRB	r12, [r2, r12]
	LDRB	lr, [r2, lr]
	UBFX	r5, r10, #0, #8
	EOR	r4, r4, r7, LSL #8
	UBFX	r7, r11, #8, #8
	EOR	r4, r4, r12, LSL #16
	UBFX	r12, r8, #16, #8
	EOR	r4, r4, lr, LSL #24
	LSR	lr, r9, #24
	LDRB	r7, [r2, r7]
	LDRB	lr, [r2, lr]
	LDRB	r5, [r2, r5]
	LDRB	r12, [r2, r12]
	UBFX	r6, r11, #0, #8
	EOR	r5, r5, r7, LSL #8
	UBFX	r7, r8, #8, #8
	EOR	r5, r5, r12, LSL #16
	UBFX	r12, r9, #16, #8
	EOR	r5, r5, lr, LSL #24
	LSR	lr, r10, #24
	LDRB	r7, [r2, r7]
	LDRB	lr, [r2, lr]
	LDRB	r6, [r2, r6]
	LDRB	r12, [r2, r12]
	LSR	r11, r11, #24
	EOR	r6, r6, r7, LSL #8
	UBFX	r7, r8, #0, #8
	EOR	r6, r6, r12, LSL #16
	UBFX	r12, r9, #8, #8
	EOR	r6, r6, lr, LSL #24
	UBFX	lr, r10, #16, #8
	LDRB	r11, [r2, r11]
	LDRB	r12, [r2, r12]
	LDRB	r7, [r2, r7]
	LDRB	lr, [r2, lr]
	EOR	r12, r12, r11, LSL #16
	LDM	r3, {r8, r9, r10, r11}
	EOR	r7, r7, r12, LSL #8
	EOR	r7, r7, lr, LSL #16
	/*   XOR in Key Schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
#endif /* !WOLFSSL_ARMASM_AES_BLOCK_INLINE */
	LDR	lr, [sp, #16]
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
	REV	r7, r7
	LDRD	r8, r9, [lr, #16]
	LDRD	r10, r11, [lr, #24]
	POP	{r1, r12, lr}
	LDR	r3, [sp]
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	STR	r4, [r1]
	STR	r5, [r1, #4]
	STR	r6, [r1, #8]
	STR	r7, [r1, #12]
	SUBS	r12, r12, #0x10
	ADD	lr, lr, #0x10
	ADD	r1, r1, #0x10
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_AES_CBC_decrypt_loop_block_192
#else
	BNE.W	L_AES_CBC_decrypt_loop_block_192
#endif
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	B	L_AES_CBC_decrypt_end
#else
	B.W	L_AES_CBC_decrypt_end
#endif
L_AES_CBC_decrypt_loop_block_128:
	PUSH	{r1, r12, lr}
	LDR	r4, [lr]
	LDR	r5, [lr, #4]
	LDR	r6, [lr, #8]
	LDR	r7, [lr, #12]
	LDR	lr, [sp, #16]
	STRD	r4, r5, [lr, #16]
	STRD	r6, r7, [lr, #24]
	LDM	r3!, {r8, r9, r10, r11}
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
	REV	r7, r7
	/* Round: 0 - XOR in key schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	MOV	r1, #0x4
#ifndef WOLFSSL_ARMASM_AES_BLOCK_INLINE
	BL	AES_decrypt_block
#else
L_AES_CBC_decrypt_block_nr_128_odd:
	UBFX	r8, r7, #16, #8
	LSR	r11, r4, #24
	UBFX	r12, r6, #8, #8
	UBFX	lr, r5, #0, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r9, r4, #16, #8
	EOR	r8, r8, r11, ROR #24
	LSR	r11, r5, #24
	EOR	r8, r8, r12, ROR #8
	UBFX	r12, r7, #8, #8
	EOR	r8, r8, lr, ROR #16
	UBFX	lr, r6, #0, #8
	LDR	r9, [r0, r9, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r10, r5, #16, #8
	EOR	r9, r9, r11, ROR #24
	LSR	r11, r6, #24
	EOR	r9, r9, r12, ROR #8
	UBFX	r12, r4, #8, #8
	EOR	r9, r9, lr, ROR #16
	UBFX	lr, r7, #0, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r4, r4, #0, #8
	EOR	r10, r10, r11, ROR #24
	UBFX	r11, r6, #16, #8
	EOR	r10, r10, r12, ROR #8
	LSR	r12, r7, #24
	EOR	r10, r10, lr, ROR #16
	UBFX	lr, r5, #8, #8
	LDR	r4, [r0, r4, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	EOR	r12, r12, r4, ROR #24
	LDM	r3!, {r4, r5, r6, r7}
	EOR	r11, r11, lr, ROR #8
	EOR	r11, r11, r12, ROR #24
	/*   XOR in Key Schedule */
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	UBFX	r4, r11, #16, #8
	LSR	r7, r8, #24
	UBFX	r12, r10, #8, #8
	UBFX	lr, r9, #0, #8
	LDR	r4, [r0, r4, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r5, r8, #16, #8
	EOR	r4, r4, r7, ROR #24
	LSR	r7, r9, #24
	EOR	r4, r4, r12, ROR #8
	UBFX	r12, r11, #8, #8
	EOR	r4, r4, lr, ROR #16
	UBFX	lr, r10, #0, #8
	LDR	r5, [r0, r5, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r6, r9, #16, #8
	EOR	r5, r5, r7, ROR #24
	LSR	r7, r10, #24
	EOR	r5, r5, r12, ROR #8
	UBFX	r12, r8, #8, #8
	EOR	r5, r5, lr, ROR #16
	UBFX	lr, r11, #0, #8
	LDR	r6, [r0, r6, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r8, r8, #0, #8
	EOR	r6, r6, r7, ROR #24
	UBFX	r7, r10, #16, #8
	EOR	r6, r6, r12, ROR #8
	LSR	r12, r11, #24
	EOR	r6, r6, lr, ROR #16
	UBFX	lr, r9, #8, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	EOR	r12, r12, r8, ROR #24
	LDM	r3!, {r8, r9, r10, r11}
	EOR	r7, r7, lr, ROR #8
	EOR	r7, r7, r12, ROR #24
	/*   XOR in Key Schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	SUBS	r1, r1, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_AES_CBC_decrypt_block_nr_128_odd
#else
	BNE.W	L_AES_CBC_decrypt_block_nr_128_odd
#endif
	UBFX	r8, r7, #16, #8
	LSR	r11, r4, #24
	UBFX	r12, r6, #8, #8
	UBFX	lr, r5, #0, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r9, r4, #16, #8
	EOR	r8, r8, r11, ROR #24
	LSR	r11, r5, #24
	EOR	r8, r8, r12, ROR #8
	UBFX	r12, r7, #8, #8
	EOR	r8, r8, lr, ROR #16
	UBFX	lr, r6, #0, #8
	LDR	r9, [r0, r9, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r10, r5, #16, #8
	EOR	r9, r9, r11, ROR #24
	LSR	r11, r6, #24
	EOR	r9, r9, r12, ROR #8
	UBFX	r12, r4, #8, #8
	EOR	r9, r9, lr, ROR #16
	UBFX	lr, r7, #0, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r4, r4, #0, #8
	EOR	r10, r10, r11, ROR #24
	UBFX	r11, r6, #16, #8
	EOR	r10, r10, r12, ROR #8
	LSR	r12, r7, #24
	EOR	r10, r10, lr, ROR #16
	UBFX	lr, r5, #8, #8
	LDR	r4, [r0, r4, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	EOR	r12, r12, r4, ROR #24
	LDM	r3!, {r4, r5, r6, r7}
	EOR	r11, r11, lr, ROR #8
	EOR	r11, r11, r12, ROR #24
	/*   XOR in Key Schedule */
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	UBFX	r4, r9, #0, #8
	UBFX	r7, r10, #8, #8
	UBFX	r12, r11, #16, #8
	LSR	lr, r8, #24
	LDRB	r4, [r2, r4]
	LDRB	r7, [r2, r7]
	LDRB	r12, [r2, r12]
	LDRB	lr, [r2, lr]
	UBFX	r5, r10, #0, #8
	EOR	r4, r4, r7, LSL #8
	UBFX	r7, r11, #8, #8
	EOR	r4, r4, r12, LSL #16
	UBFX	r12, r8, #16, #8
	EOR	r4, r4, lr, LSL #24
	LSR	lr, r9, #24
	LDRB	r7, [r2, r7]
	LDRB	lr, [r2, lr]
	LDRB	r5, [r2, r5]
	LDRB	r12, [r2, r12]
	UBFX	r6, r11, #0, #8
	EOR	r5, r5, r7, LSL #8
	UBFX	r7, r8, #8, #8
	EOR	r5, r5, r12, LSL #16
	UBFX	r12, r9, #16, #8
	EOR	r5, r5, lr, LSL #24
	LSR	lr, r10, #24
	LDRB	r7, [r2, r7]
	LDRB	lr, [r2, lr]
	LDRB	r6, [r2, r6]
	LDRB	r12, [r2, r12]
	LSR	r11, r11, #24
	EOR	r6, r6, r7, LSL #8
	UBFX	r7, r8, #0, #8
	EOR	r6, r6, r12, LSL #16
	UBFX	r12, r9, #8, #8
	EOR	r6, r6, lr, LSL #24
	UBFX	lr, r10, #16, #8
	LDRB	r11, [r2, r11]
	LDRB	r12, [r2, r12]
	LDRB	r7, [r2, r7]
	LDRB	lr, [r2, lr]
	EOR	r12, r12, r11, LSL #16
	LDM	r3, {r8, r9, r10, r11}
	EOR	r7, r7, r12, LSL #8
	EOR	r7, r7, lr, LSL #16
	/*   XOR in Key Schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
#endif /* !WOLFSSL_ARMASM_AES_BLOCK_INLINE */
	LDR	lr, [sp, #16]
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
	REV	r7, r7
	LDM	lr, {r8, r9, r10, r11}
	POP	{r1, r12, lr}
	LDR	r3, [sp]
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	STR	r4, [r1]
	STR	r5, [r1, #4]
	STR	r6, [r1, #8]
	STR	r7, [r1, #12]
	SUBS	r12, r12, #0x10
	ADD	lr, lr, #0x10
	ADD	r1, r1, #0x10
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BEQ	L_AES_CBC_decrypt_end_odd
#else
	BEQ.W	L_AES_CBC_decrypt_end_odd
#endif
	PUSH	{r1, r12, lr}
	LDR	r4, [lr]
	LDR	r5, [lr, #4]
	LDR	r6, [lr, #8]
	LDR	r7, [lr, #12]
	LDR	lr, [sp, #16]
	STRD	r4, r5, [lr]
	STRD	r6, r7, [lr, #8]
	LDM	r3!, {r8, r9, r10, r11}
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
	REV	r7, r7
	/* Round: 0 - XOR in key schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	MOV	r1, #0x4
#ifndef WOLFSSL_ARMASM_AES_BLOCK_INLINE
	BL	AES_decrypt_block
#else
L_AES_CBC_decrypt_block_nr_128_even:
	UBFX	r8, r7, #16, #8
	LSR	r11, r4, #24
	UBFX	r12, r6, #8, #8
	UBFX	lr, r5, #0, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r9, r4, #16, #8
	EOR	r8, r8, r11, ROR #24
	LSR	r11, r5, #24
	EOR	r8, r8, r12, ROR #8
	UBFX	r12, r7, #8, #8
	EOR	r8, r8, lr, ROR #16
	UBFX	lr, r6, #0, #8
	LDR	r9, [r0, r9, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r10, r5, #16, #8
	EOR	r9, r9, r11, ROR #24
	LSR	r11, r6, #24
	EOR	r9, r9, r12, ROR #8
	UBFX	r12, r4, #8, #8
	EOR	r9, r9, lr, ROR #16
	UBFX	lr, r7, #0, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r4, r4, #0, #8
	EOR	r10, r10, r11, ROR #24
	UBFX	r11, r6, #16, #8
	EOR	r10, r10, r12, ROR #8
	LSR	r12, r7, #24
	EOR	r10, r10, lr, ROR #16
	UBFX	lr, r5, #8, #8
	LDR	r4, [r0, r4, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	EOR	r12, r12, r4, ROR #24
	LDM	r3!, {r4, r5, r6, r7}
	EOR	r11, r11, lr, ROR #8
	EOR	r11, r11, r12, ROR #24
	/*   XOR in Key Schedule */
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	UBFX	r4, r11, #16, #8
	LSR	r7, r8, #24
	UBFX	r12, r10, #8, #8
	UBFX	lr, r9, #0, #8
	LDR	r4, [r0, r4, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r5, r8, #16, #8
	EOR	r4, r4, r7, ROR #24
	LSR	r7, r9, #24
	EOR	r4, r4, r12, ROR #8
	UBFX	r12, r11, #8, #8
	EOR	r4, r4, lr, ROR #16
	UBFX	lr, r10, #0, #8
	LDR	r5, [r0, r5, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r6, r9, #16, #8
	EOR	r5, r5, r7, ROR #24
	LSR	r7, r10, #24
	EOR	r5, r5, r12, ROR #8
	UBFX	r12, r8, #8, #8
	EOR	r5, r5, lr, ROR #16
	UBFX	lr, r11, #0, #8
	LDR	r6, [r0, r6, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r8, r8, #0, #8
	EOR	r6, r6, r7, ROR #24
	UBFX	r7, r10, #16, #8
	EOR	r6, r6, r12, ROR #8
	LSR	r12, r11, #24
	EOR	r6, r6, lr, ROR #16
	UBFX	lr, r9, #8, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	EOR	r12, r12, r8, ROR #24
	LDM	r3!, {r8, r9, r10, r11}
	EOR	r7, r7, lr, ROR #8
	EOR	r7, r7, r12, ROR #24
	/*   XOR in Key Schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	SUBS	r1, r1, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_AES_CBC_decrypt_block_nr_128_even
#else
	BNE.W	L_AES_CBC_decrypt_block_nr_128_even
#endif
	UBFX	r8, r7, #16, #8
	LSR	r11, r4, #24
	UBFX	r12, r6, #8, #8
	UBFX	lr, r5, #0, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r9, r4, #16, #8
	EOR	r8, r8, r11, ROR #24
	LSR	r11, r5, #24
	EOR	r8, r8, r12, ROR #8
	UBFX	r12, r7, #8, #8
	EOR	r8, r8, lr, ROR #16
	UBFX	lr, r6, #0, #8
	LDR	r9, [r0, r9, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r10, r5, #16, #8
	EOR	r9, r9, r11, ROR #24
	LSR	r11, r6, #24
	EOR	r9, r9, r12, ROR #8
	UBFX	r12, r4, #8, #8
	EOR	r9, r9, lr, ROR #16
	UBFX	lr, r7, #0, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	UBFX	r4, r4, #0, #8
	EOR	r10, r10, r11, ROR #24
	UBFX	r11, r6, #16, #8
	EOR	r10, r10, r12, ROR #8
	LSR	r12, r7, #24
	EOR	r10, r10, lr, ROR #16
	UBFX	lr, r5, #8, #8
	LDR	r4, [r0, r4, LSL #2]
	LDR	r12, [r0, r12, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	EOR	r12, r12, r4, ROR #24
	LDM	r3!, {r4, r5, r6, r7}
	EOR	r11, r11, lr, ROR #8
	EOR	r11, r11, r12, ROR #24
	/*   XOR in Key Schedule */
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	UBFX	r4, r9, #0, #8
	UBFX	r7, r10, #8, #8
	UBFX	r12, r11, #16, #8
	LSR	lr, r8, #24
	LDRB	r4, [r2, r4]
	LDRB	r7, [r2, r7]
	LDRB	r12, [r2, r12]
	LDRB	lr, [r2, lr]
	UBFX	r5, r10, #0, #8
	EOR	r4, r4, r7, LSL #8
	UBFX	r7, r11, #8, #8
	EOR	r4, r4, r12, LSL #16
	UBFX	r12, r8, #16, #8
	EOR	r4, r4, lr, LSL #24
	LSR	lr, r9, #24
	LDRB	r7, [r2, r7]
	LDRB	lr, [r2, lr]
	LDRB	r5, [r2, r5]
	LDRB	r12, [r2, r12]
	UBFX	r6, r11, #0, #8
	EOR	r5, r5, r7, LSL #8
	UBFX	r7, r8, #8, #8
	EOR	r5, r5, r12, LSL #16
	UBFX	r12, r9, #16, #8
	EOR	r5, r5, lr, LSL #24
	LSR	lr, r10, #24
	LDRB	r7, [r2, r7]
	LDRB	lr, [r2, lr]
	LDRB	r6, [r2, r6]
	LDRB	r12, [r2, r12]
	LSR	r11, r11, #24
	EOR	r6, r6, r7, LSL #8
	UBFX	r7, r8, #0, #8
	EOR	r6, r6, r12, LSL #16
	UBFX	r12, r9, #8, #8
	EOR	r6, r6, lr, LSL #24
	UBFX	lr, r10, #16, #8
	LDRB	r11, [r2, r11]
	LDRB	r12, [r2, r12]
	LDRB	r7, [r2, r7]
	LDRB	lr, [r2, lr]
	EOR	r12, r12, r11, LSL #16
	LDM	r3, {r8, r9, r10, r11}
	EOR	r7, r7, r12, LSL #8
	EOR	r7, r7, lr, LSL #16
	/*   XOR in Key Schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
#endif /* !WOLFSSL_ARMASM_AES_BLOCK_INLINE */
	LDR	lr, [sp, #16]
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
	REV	r7, r7
	LDRD	r8, r9, [lr, #16]
	LDRD	r10, r11, [lr, #24]
	POP	{r1, r12, lr}
	LDR	r3, [sp]
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	STR	r4, [r1]
	STR	r5, [r1, #4]
	STR	r6, [r1, #8]
	STR	r7, [r1, #12]
	SUBS	r12, r12, #0x10
	ADD	lr, lr, #0x10
	ADD	r1, r1, #0x10
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_AES_CBC_decrypt_loop_block_128
#else
	BNE.W	L_AES_CBC_decrypt_loop_block_128
#endif
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	B	L_AES_CBC_decrypt_end
#else
	B.N	L_AES_CBC_decrypt_end
#endif
L_AES_CBC_decrypt_end_odd:
	LDR	r4, [sp, #4]
	LDRD	r8, r9, [r4, #16]
	LDRD	r10, r11, [r4, #24]
	STRD	r8, r9, [r4]
	STRD	r10, r11, [r4, #8]
L_AES_CBC_decrypt_end:
	POP	{r3, r4}
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 2204 */
	.size	AES_CBC_decrypt,.-AES_CBC_decrypt
#endif /* HAVE_AES_CBC */
#endif /* WOLFSSL_AES_DIRECT || WOLFSSL_AES_COUNTER || HAVE_AES_CBC
        * HAVE_AES_ECB */
#endif /* HAVE_AES_DECRYPT */
#ifdef HAVE_AESGCM
#ifndef __APPLE__
	.text
	.type	L_GCM_gmult_len_r, %object
	.size	L_GCM_gmult_len_r, 64
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	/* 8-byte aligned, 64-bit aligned */
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_GCM_gmult_len_r:
	.long	0x00000000,0x1c200000,0x38400000,0x24600000
	.long	0x70800000,0x6ca00000,0x48c00000,0x54e00000
	.long	0xe1000000,0xfd200000,0xd9400000,0xc5600000
	.long	0x91800000,0x8da00000,0xa9c00000,0xb5e00000
	.text
	.align	4
	.globl	GCM_gmult_len
	.type	GCM_gmult_len, %function
GCM_gmult_len:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	ADR	lr, L_GCM_gmult_len_r
L_GCM_gmult_len_start_block:
	PUSH	{r3}
	LDR	r12, [r0, #12]
	LDR	r3, [r2, #12]
	EOR	r12, r12, r3
	LSR	r3, r12, #24
	AND	r3, r3, #0xf
	ADD	r3, r1, r3, LSL #4
	LDM	r3, {r8, r9, r10, r11}
	LSR	r6, r10, #4
	AND	r3, r11, #0xf
	LSR	r11, r11, #4
	LSR	r4, r12, #28
	EOR	r11, r11, r10, LSL #28
	LDR	r3, [lr, r3, LSL #2]
	ADD	r4, r1, r4, LSL #4
	EOR	r10, r6, r9, LSL #28
	LSR	r9, r9, #4
	LDM	r4, {r4, r5, r6, r7}
	EOR	r9, r9, r8, LSL #28
	EOR	r8, r3, r8, LSR #4
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LSR	r6, r10, #4
	AND	r3, r11, #0xf
	LSR	r11, r11, #4
	LSR	r4, r12, #16
	EOR	r11, r11, r10, LSL #28
	AND	r4, r4, #0xf
	LDR	r3, [lr, r3, LSL #2]
	ADD	r4, r1, r4, LSL #4
	EOR	r10, r6, r9, LSL #28
	LSR	r9, r9, #4
	LDM	r4, {r4, r5, r6, r7}
	EOR	r9, r9, r8, LSL #28
	EOR	r8, r3, r8, LSR #4
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LSR	r6, r10, #4
	AND	r3, r11, #0xf
	LSR	r11, r11, #4
	LSR	r4, r12, #20
	EOR	r11, r11, r10, LSL #28
	AND	r4, r4, #0xf
	LDR	r3, [lr, r3, LSL #2]
	ADD	r4, r1, r4, LSL #4
	EOR	r10, r6, r9, LSL #28
	LSR	r9, r9, #4
	LDM	r4, {r4, r5, r6, r7}
	EOR	r9, r9, r8, LSL #28
	EOR	r8, r3, r8, LSR #4
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LSR	r6, r10, #4
	AND	r3, r11, #0xf
	LSR	r11, r11, #4
	LSR	r4, r12, #8
	EOR	r11, r11, r10, LSL #28
	AND	r4, r4, #0xf
	LDR	r3, [lr, r3, LSL #2]
	ADD	r4, r1, r4, LSL #4
	EOR	r10, r6, r9, LSL #28
	LSR	r9, r9, #4
	LDM	r4, {r4, r5, r6, r7}
	EOR	r9, r9, r8, LSL #28
	EOR	r8, r3, r8, LSR #4
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LSR	r6, r10, #4
	AND	r3, r11, #0xf
	LSR	r11, r11, #4
	LSR	r4, r12, #12
	EOR	r11, r11, r10, LSL #28
	AND	r4, r4, #0xf
	LDR	r3, [lr, r3, LSL #2]
	ADD	r4, r1, r4, LSL #4
	EOR	r10, r6, r9, LSL #28
	LSR	r9, r9, #4
	LDM	r4, {r4, r5, r6, r7}
	EOR	r9, r9, r8, LSL #28
	EOR	r8, r3, r8, LSR #4
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LSR	r6, r10, #4
	AND	r3, r11, #0xf
	LSR	r11, r11, #4
	AND	r4, r12, #0xf
	EOR	r11, r11, r10, LSL #28
	LDR	r3, [lr, r3, LSL #2]
	ADD	r4, r1, r4, LSL #4
	EOR	r10, r6, r9, LSL #28
	LSR	r9, r9, #4
	LDM	r4, {r4, r5, r6, r7}
	EOR	r9, r9, r8, LSL #28
	EOR	r8, r3, r8, LSR #4
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LSR	r6, r10, #4
	AND	r3, r11, #0xf
	LSR	r11, r11, #4
	LSR	r4, r12, #4
	EOR	r11, r11, r10, LSL #28
	AND	r4, r4, #0xf
	LDR	r3, [lr, r3, LSL #2]
	ADD	r4, r1, r4, LSL #4
	EOR	r10, r6, r9, LSL #28
	LSR	r9, r9, #4
	LDM	r4, {r4, r5, r6, r7}
	EOR	r9, r9, r8, LSL #28
	EOR	r8, r3, r8, LSR #4
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LSR	r6, r10, #4
	AND	r3, r11, #0xf
	LSR	r11, r11, #4
	EOR	r11, r11, r10, LSL #28
	LDR	r3, [lr, r3, LSL #2]
	EOR	r10, r6, r9, LSL #28
	LSR	r9, r9, #4
	EOR	r9, r9, r8, LSL #28
	EOR	r8, r3, r8, LSR #4
	LDR	r12, [r0, #8]
	LDR	r3, [r2, #8]
	EOR	r12, r12, r3
	LSR	r3, r12, #24
	AND	r3, r3, #0xf
	ADD	r3, r1, r3, LSL #4
	LDM	r3, {r4, r5, r6, r7}
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LSR	r6, r10, #4
	AND	r3, r11, #0xf
	LSR	r11, r11, #4
	LSR	r4, r12, #28
	EOR	r11, r11, r10, LSL #28
	LDR	r3, [lr, r3, LSL #2]
	ADD	r4, r1, r4, LSL #4
	EOR	r10, r6, r9, LSL #28
	LSR	r9, r9, #4
	LDM	r4, {r4, r5, r6, r7}
	EOR	r9, r9, r8, LSL #28
	EOR	r8, r3, r8, LSR #4
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LSR	r6, r10, #4
	AND	r3, r11, #0xf
	LSR	r11, r11, #4
	LSR	r4, r12, #16
	EOR	r11, r11, r10, LSL #28
	AND	r4, r4, #0xf
	LDR	r3, [lr, r3, LSL #2]
	ADD	r4, r1, r4, LSL #4
	EOR	r10, r6, r9, LSL #28
	LSR	r9, r9, #4
	LDM	r4, {r4, r5, r6, r7}
	EOR	r9, r9, r8, LSL #28
	EOR	r8, r3, r8, LSR #4
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LSR	r6, r10, #4
	AND	r3, r11, #0xf
	LSR	r11, r11, #4
	LSR	r4, r12, #20
	EOR	r11, r11, r10, LSL #28
	AND	r4, r4, #0xf
	LDR	r3, [lr, r3, LSL #2]
	ADD	r4, r1, r4, LSL #4
	EOR	r10, r6, r9, LSL #28
	LSR	r9, r9, #4
	LDM	r4, {r4, r5, r6, r7}
	EOR	r9, r9, r8, LSL #28
	EOR	r8, r3, r8, LSR #4
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LSR	r6, r10, #4
	AND	r3, r11, #0xf
	LSR	r11, r11, #4
	LSR	r4, r12, #8
	EOR	r11, r11, r10, LSL #28
	AND	r4, r4, #0xf
	LDR	r3, [lr, r3, LSL #2]
	ADD	r4, r1, r4, LSL #4
	EOR	r10, r6, r9, LSL #28
	LSR	r9, r9, #4
	LDM	r4, {r4, r5, r6, r7}
	EOR	r9, r9, r8, LSL #28
	EOR	r8, r3, r8, LSR #4
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LSR	r6, r10, #4
	AND	r3, r11, #0xf
	LSR	r11, r11, #4
	LSR	r4, r12, #12
	EOR	r11, r11, r10, LSL #28
	AND	r4, r4, #0xf
	LDR	r3, [lr, r3, LSL #2]
	ADD	r4, r1, r4, LSL #4
	EOR	r10, r6, r9, LSL #28
	LSR	r9, r9, #4
	LDM	r4, {r4, r5, r6, r7}
	EOR	r9, r9, r8, LSL #28
	EOR	r8, r3, r8, LSR #4
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LSR	r6, r10, #4
	AND	r3, r11, #0xf
	LSR	r11, r11, #4
	AND	r4, r12, #0xf
	EOR	r11, r11, r10, LSL #28
	LDR	r3, [lr, r3, LSL #2]
	ADD	r4, r1, r4, LSL #4
	EOR	r10, r6, r9, LSL #28
	LSR	r9, r9, #4
	LDM	r4, {r4, r5, r6, r7}
	EOR	r9, r9, r8, LSL #28
	EOR	r8, r3, r8, LSR #4
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LSR	r6, r10, #4
	AND	r3, r11, #0xf
	LSR	r11, r11, #4
	LSR	r4, r12, #4
	EOR	r11, r11, r10, LSL #28
	AND	r4, r4, #0xf
	LDR	r3, [lr, r3, LSL #2]
	ADD	r4, r1, r4, LSL #4
	EOR	r10, r6, r9, LSL #28
	LSR	r9, r9, #4
	LDM	r4, {r4, r5, r6, r7}
	EOR	r9, r9, r8, LSL #28
	EOR	r8, r3, r8, LSR #4
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LSR	r6, r10, #4
	AND	r3, r11, #0xf
	LSR	r11, r11, #4
	EOR	r11, r11, r10, LSL #28
	LDR	r3, [lr, r3, LSL #2]
	EOR	r10, r6, r9, LSL #28
	LSR	r9, r9, #4
	EOR	r9, r9, r8, LSL #28
	EOR	r8, r3, r8, LSR #4
	LDR	r12, [r0, #4]
	LDR	r3, [r2, #4]
	EOR	r12, r12, r3
	LSR	r3, r12, #24
	AND	r3, r3, #0xf
	ADD	r3, r1, r3, LSL #4
	LDM	r3, {r4, r5, r6, r7}
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LSR	r6, r10, #4
	AND	r3, r11, #0xf
	LSR	r11, r11, #4
	LSR	r4, r12, #28
	EOR	r11, r11, r10, LSL #28
	LDR	r3, [lr, r3, LSL #2]
	ADD	r4, r1, r4, LSL #4
	EOR	r10, r6, r9, LSL #28
	LSR	r9, r9, #4
	LDM	r4, {r4, r5, r6, r7}
	EOR	r9, r9, r8, LSL #28
	EOR	r8, r3, r8, LSR #4
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LSR	r6, r10, #4
	AND	r3, r11, #0xf
	LSR	r11, r11, #4
	LSR	r4, r12, #16
	EOR	r11, r11, r10, LSL #28
	AND	r4, r4, #0xf
	LDR	r3, [lr, r3, LSL #2]
	ADD	r4, r1, r4, LSL #4
	EOR	r10, r6, r9, LSL #28
	LSR	r9, r9, #4
	LDM	r4, {r4, r5, r6, r7}
	EOR	r9, r9, r8, LSL #28
	EOR	r8, r3, r8, LSR #4
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LSR	r6, r10, #4
	AND	r3, r11, #0xf
	LSR	r11, r11, #4
	LSR	r4, r12, #20
	EOR	r11, r11, r10, LSL #28
	AND	r4, r4, #0xf
	LDR	r3, [lr, r3, LSL #2]
	ADD	r4, r1, r4, LSL #4
	EOR	r10, r6, r9, LSL #28
	LSR	r9, r9, #4
	LDM	r4, {r4, r5, r6, r7}
	EOR	r9, r9, r8, LSL #28
	EOR	r8, r3, r8, LSR #4
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LSR	r6, r10, #4
	AND	r3, r11, #0xf
	LSR	r11, r11, #4
	LSR	r4, r12, #8
	EOR	r11, r11, r10, LSL #28
	AND	r4, r4, #0xf
	LDR	r3, [lr, r3, LSL #2]
	ADD	r4, r1, r4, LSL #4
	EOR	r10, r6, r9, LSL #28
	LSR	r9, r9, #4
	LDM	r4, {r4, r5, r6, r7}
	EOR	r9, r9, r8, LSL #28
	EOR	r8, r3, r8, LSR #4
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LSR	r6, r10, #4
	AND	r3, r11, #0xf
	LSR	r11, r11, #4
	LSR	r4, r12, #12
	EOR	r11, r11, r10, LSL #28
	AND	r4, r4, #0xf
	LDR	r3, [lr, r3, LSL #2]
	ADD	r4, r1, r4, LSL #4
	EOR	r10, r6, r9, LSL #28
	LSR	r9, r9, #4
	LDM	r4, {r4, r5, r6, r7}
	EOR	r9, r9, r8, LSL #28
	EOR	r8, r3, r8, LSR #4
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LSR	r6, r10, #4
	AND	r3, r11, #0xf
	LSR	r11, r11, #4
	AND	r4, r12, #0xf
	EOR	r11, r11, r10, LSL #28
	LDR	r3, [lr, r3, LSL #2]
	ADD	r4, r1, r4, LSL #4
	EOR	r10, r6, r9, LSL #28
	LSR	r9, r9, #4
	LDM	r4, {r4, r5, r6, r7}
	EOR	r9, r9, r8, LSL #28
	EOR	r8, r3, r8, LSR #4
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LSR	r6, r10, #4
	AND	r3, r11, #0xf
	LSR	r11, r11, #4
	LSR	r4, r12, #4
	EOR	r11, r11, r10, LSL #28
	AND	r4, r4, #0xf
	LDR	r3, [lr, r3, LSL #2]
	ADD	r4, r1, r4, LSL #4
	EOR	r10, r6, r9, LSL #28
	LSR	r9, r9, #4
	LDM	r4, {r4, r5, r6, r7}
	EOR	r9, r9, r8, LSL #28
	EOR	r8, r3, r8, LSR #4
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LSR	r6, r10, #4
	AND	r3, r11, #0xf
	LSR	r11, r11, #4
	EOR	r11, r11, r10, LSL #28
	LDR	r3, [lr, r3, LSL #2]
	EOR	r10, r6, r9, LSL #28
	LSR	r9, r9, #4
	EOR	r9, r9, r8, LSL #28
	EOR	r8, r3, r8, LSR #4
	LDR	r12, [r0]
	LDR	r3, [r2]
	EOR	r12, r12, r3
	LSR	r3, r12, #24
	AND	r3, r3, #0xf
	ADD	r3, r1, r3, LSL #4
	LDM	r3, {r4, r5, r6, r7}
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LSR	r6, r10, #4
	AND	r3, r11, #0xf
	LSR	r11, r11, #4
	LSR	r4, r12, #28
	EOR	r11, r11, r10, LSL #28
	LDR	r3, [lr, r3, LSL #2]
	ADD	r4, r1, r4, LSL #4
	EOR	r10, r6, r9, LSL #28
	LSR	r9, r9, #4
	LDM	r4, {r4, r5, r6, r7}
	EOR	r9, r9, r8, LSL #28
	EOR	r8, r3, r8, LSR #4
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LSR	r6, r10, #4
	AND	r3, r11, #0xf
	LSR	r11, r11, #4
	LSR	r4, r12, #16
	EOR	r11, r11, r10, LSL #28
	AND	r4, r4, #0xf
	LDR	r3, [lr, r3, LSL #2]
	ADD	r4, r1, r4, LSL #4
	EOR	r10, r6, r9, LSL #28
	LSR	r9, r9, #4
	LDM	r4, {r4, r5, r6, r7}
	EOR	r9, r9, r8, LSL #28
	EOR	r8, r3, r8, LSR #4
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LSR	r6, r10, #4
	AND	r3, r11, #0xf
	LSR	r11, r11, #4
	LSR	r4, r12, #20
	EOR	r11, r11, r10, LSL #28
	AND	r4, r4, #0xf
	LDR	r3, [lr, r3, LSL #2]
	ADD	r4, r1, r4, LSL #4
	EOR	r10, r6, r9, LSL #28
	LSR	r9, r9, #4
	LDM	r4, {r4, r5, r6, r7}
	EOR	r9, r9, r8, LSL #28
	EOR	r8, r3, r8, LSR #4
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LSR	r6, r10, #4
	AND	r3, r11, #0xf
	LSR	r11, r11, #4
	LSR	r4, r12, #8
	EOR	r11, r11, r10, LSL #28
	AND	r4, r4, #0xf
	LDR	r3, [lr, r3, LSL #2]
	ADD	r4, r1, r4, LSL #4
	EOR	r10, r6, r9, LSL #28
	LSR	r9, r9, #4
	LDM	r4, {r4, r5, r6, r7}
	EOR	r9, r9, r8, LSL #28
	EOR	r8, r3, r8, LSR #4
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LSR	r6, r10, #4
	AND	r3, r11, #0xf
	LSR	r11, r11, #4
	LSR	r4, r12, #12
	EOR	r11, r11, r10, LSL #28
	AND	r4, r4, #0xf
	LDR	r3, [lr, r3, LSL #2]
	ADD	r4, r1, r4, LSL #4
	EOR	r10, r6, r9, LSL #28
	LSR	r9, r9, #4
	LDM	r4, {r4, r5, r6, r7}
	EOR	r9, r9, r8, LSL #28
	EOR	r8, r3, r8, LSR #4
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LSR	r6, r10, #4
	AND	r3, r11, #0xf
	LSR	r11, r11, #4
	AND	r4, r12, #0xf
	EOR	r11, r11, r10, LSL #28
	LDR	r3, [lr, r3, LSL #2]
	ADD	r4, r1, r4, LSL #4
	EOR	r10, r6, r9, LSL #28
	LSR	r9, r9, #4
	LDM	r4, {r4, r5, r6, r7}
	EOR	r9, r9, r8, LSL #28
	EOR	r8, r3, r8, LSR #4
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LSR	r6, r10, #4
	AND	r3, r11, #0xf
	LSR	r11, r11, #4
	LSR	r4, r12, #4
	EOR	r11, r11, r10, LSL #28
	AND	r4, r4, #0xf
	LDR	r3, [lr, r3, LSL #2]
	ADD	r4, r1, r4, LSL #4
	EOR	r10, r6, r9, LSL #28
	LSR	r9, r9, #4
	LDM	r4, {r4, r5, r6, r7}
	EOR	r9, r9, r8, LSL #28
	EOR	r8, r3, r8, LSR #4
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	REV	r8, r8
	REV	r9, r9
	REV	r10, r10
	REV	r11, r11
	STM	r0, {r8, r9, r10, r11}
	POP	{r3}
	SUBS	r3, r3, #0x10
	ADD	r2, r2, #0x10
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_GCM_gmult_len_start_block
#else
	BNE.W	L_GCM_gmult_len_start_block
#endif
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 742 */
	.size	GCM_gmult_len,.-GCM_gmult_len
#ifndef __APPLE__
	.text
	.type	L_AES_Thumb2_te_gcm, %object
	.size	L_AES_Thumb2_te_gcm, 12
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	/* 8-byte aligned, 64-bit aligned */
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_AES_Thumb2_te_gcm:
	.long	L_AES_Thumb2_te_data
	.text
	.align	4
	.globl	AES_GCM_encrypt
	.type	AES_GCM_encrypt, %function
AES_GCM_encrypt:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	LDR	r12, [sp, #36]
	LDR	r8, [sp, #40]
	MOV	lr, r0
	LDR	r0, L_AES_Thumb2_te_gcm
	LDM	r8, {r4, r5, r6, r7}
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
	REV	r7, r7
	STM	r8, {r4, r5, r6, r7}
	PUSH	{r3, r8}
	CMP	r12, #0xa
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BEQ	L_AES_GCM_encrypt_start_block_128
#else
	BEQ.W	L_AES_GCM_encrypt_start_block_128
#endif
	CMP	r12, #0xc
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BEQ	L_AES_GCM_encrypt_start_block_192
#else
	BEQ.W	L_AES_GCM_encrypt_start_block_192
#endif
L_AES_GCM_encrypt_loop_block_256:
	PUSH	{r1, r2, lr}
	LDR	lr, [sp, #16]
	ADD	r7, r7, #0x1
	LDM	r3!, {r8, r9, r10, r11}
	STR	r7, [lr, #12]
	/* Round: 0 - XOR in key schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	MOV	r1, #0x6
#ifndef WOLFSSL_ARMASM_AES_BLOCK_INLINE
	BL	AES_encrypt_block
#else
L_AES_GCM_encrypt_block_nr_256:
	UBFX	r8, r5, #16, #8
	LSR	r11, r4, #24
	UBFX	lr, r6, #8, #8
	UBFX	r2, r7, #0, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r9, r6, #16, #8
	EOR	r8, r8, r11, ROR #24
	LSR	r11, r5, #24
	EOR	r8, r8, lr, ROR #8
	UBFX	lr, r7, #8, #8
	EOR	r8, r8, r2, ROR #16
	UBFX	r2, r4, #0, #8
	LDR	r9, [r0, r9, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r10, r7, #16, #8
	EOR	r9, r9, r11, ROR #24
	LSR	r11, r6, #24
	EOR	r9, r9, lr, ROR #8
	UBFX	lr, r4, #8, #8
	EOR	r9, r9, r2, ROR #16
	UBFX	r2, r5, #0, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r6, r6, #0, #8
	EOR	r10, r10, r11, ROR #24
	UBFX	r11, r4, #16, #8
	EOR	r10, r10, lr, ROR #8
	LSR	lr, r7, #24
	EOR	r10, r10, r2, ROR #16
	UBFX	r2, r5, #8, #8
	LDR	r6, [r0, r6, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r6, ROR #24
	LDM	r3!, {r4, r5, r6, r7}
	EOR	r11, r11, lr, ROR #24
	EOR	r11, r11, r2, ROR #8
	/*   XOR in Key Schedule */
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	UBFX	r4, r9, #16, #8
	LSR	r7, r8, #24
	UBFX	lr, r10, #8, #8
	UBFX	r2, r11, #0, #8
	LDR	r4, [r0, r4, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r5, r10, #16, #8
	EOR	r4, r4, r7, ROR #24
	LSR	r7, r9, #24
	EOR	r4, r4, lr, ROR #8
	UBFX	lr, r11, #8, #8
	EOR	r4, r4, r2, ROR #16
	UBFX	r2, r8, #0, #8
	LDR	r5, [r0, r5, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r6, r11, #16, #8
	EOR	r5, r5, r7, ROR #24
	LSR	r7, r10, #24
	EOR	r5, r5, lr, ROR #8
	UBFX	lr, r8, #8, #8
	EOR	r5, r5, r2, ROR #16
	UBFX	r2, r9, #0, #8
	LDR	r6, [r0, r6, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r10, r10, #0, #8
	EOR	r6, r6, r7, ROR #24
	UBFX	r7, r8, #16, #8
	EOR	r6, r6, lr, ROR #8
	LSR	lr, r11, #24
	EOR	r6, r6, r2, ROR #16
	UBFX	r2, r9, #8, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r10, ROR #24
	LDM	r3!, {r8, r9, r10, r11}
	EOR	r7, r7, lr, ROR #24
	EOR	r7, r7, r2, ROR #8
	/*   XOR in Key Schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	SUBS	r1, r1, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_AES_GCM_encrypt_block_nr_256
#else
	BNE.W	L_AES_GCM_encrypt_block_nr_256
#endif
	UBFX	r8, r5, #16, #8
	LSR	r11, r4, #24
	UBFX	lr, r6, #8, #8
	UBFX	r2, r7, #0, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r9, r6, #16, #8
	EOR	r8, r8, r11, ROR #24
	LSR	r11, r5, #24
	EOR	r8, r8, lr, ROR #8
	UBFX	lr, r7, #8, #8
	EOR	r8, r8, r2, ROR #16
	UBFX	r2, r4, #0, #8
	LDR	r9, [r0, r9, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r10, r7, #16, #8
	EOR	r9, r9, r11, ROR #24
	LSR	r11, r6, #24
	EOR	r9, r9, lr, ROR #8
	UBFX	lr, r4, #8, #8
	EOR	r9, r9, r2, ROR #16
	UBFX	r2, r5, #0, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r6, r6, #0, #8
	EOR	r10, r10, r11, ROR #24
	UBFX	r11, r4, #16, #8
	EOR	r10, r10, lr, ROR #8
	LSR	lr, r7, #24
	EOR	r10, r10, r2, ROR #16
	UBFX	r2, r5, #8, #8
	LDR	r6, [r0, r6, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r6, ROR #24
	LDM	r3!, {r4, r5, r6, r7}
	EOR	r11, r11, lr, ROR #24
	EOR	r11, r11, r2, ROR #8
	/*   XOR in Key Schedule */
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	UBFX	r4, r11, #0, #8
	UBFX	r7, r10, #8, #8
	UBFX	lr, r9, #16, #8
	LSR	r2, r8, #24
	LDRB	r4, [r0, r4, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	UBFX	r5, r8, #0, #8
	EOR	r4, r4, r7, LSL #8
	UBFX	r7, r11, #8, #8
	EOR	r4, r4, lr, LSL #16
	UBFX	lr, r10, #16, #8
	EOR	r4, r4, r2, LSL #24
	LSR	r2, r9, #24
	LDRB	r5, [r0, r5, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	UBFX	r6, r9, #0, #8
	EOR	r5, r5, r7, LSL #8
	UBFX	r7, r8, #8, #8
	EOR	r5, r5, lr, LSL #16
	UBFX	lr, r11, #16, #8
	EOR	r5, r5, r2, LSL #24
	LSR	r2, r10, #24
	LDRB	r6, [r0, r6, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	LSR	r11, r11, #24
	EOR	r6, r6, r7, LSL #8
	UBFX	r7, r10, #0, #8
	EOR	r6, r6, lr, LSL #16
	UBFX	lr, r9, #8, #8
	EOR	r6, r6, r2, LSL #24
	UBFX	r2, r8, #16, #8
	LDRB	r11, [r0, r11, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r11, LSL #16
	LDM	r3, {r8, r9, r10, r11}
	EOR	r7, r7, lr, LSL #8
	EOR	r7, r7, r2, LSL #16
	/*   XOR in Key Schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
#endif /* !WOLFSSL_ARMASM_AES_BLOCK_INLINE */
	POP	{r1, r2, lr}
	LDR	r3, [sp]
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
	REV	r7, r7
	LDR	r8, [lr]
	LDR	r9, [lr, #4]
	LDR	r10, [lr, #8]
	LDR	r11, [lr, #12]
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	LDR	r8, [sp, #4]
	STR	r4, [r1]
	STR	r5, [r1, #4]
	STR	r6, [r1, #8]
	STR	r7, [r1, #12]
	LDM	r8, {r4, r5, r6, r7}
	SUBS	r2, r2, #0x10
	ADD	lr, lr, #0x10
	ADD	r1, r1, #0x10
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_AES_GCM_encrypt_loop_block_256
#else
	BNE.W	L_AES_GCM_encrypt_loop_block_256
#endif
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	B	L_AES_GCM_encrypt_end
#else
	B.W	L_AES_GCM_encrypt_end
#endif
L_AES_GCM_encrypt_start_block_192:
L_AES_GCM_encrypt_loop_block_192:
	PUSH	{r1, r2, lr}
	LDR	lr, [sp, #16]
	ADD	r7, r7, #0x1
	LDM	r3!, {r8, r9, r10, r11}
	STR	r7, [lr, #12]
	/* Round: 0 - XOR in key schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	MOV	r1, #0x5
#ifndef WOLFSSL_ARMASM_AES_BLOCK_INLINE
	BL	AES_encrypt_block
#else
L_AES_GCM_encrypt_block_nr_192:
	UBFX	r8, r5, #16, #8
	LSR	r11, r4, #24
	UBFX	lr, r6, #8, #8
	UBFX	r2, r7, #0, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r9, r6, #16, #8
	EOR	r8, r8, r11, ROR #24
	LSR	r11, r5, #24
	EOR	r8, r8, lr, ROR #8
	UBFX	lr, r7, #8, #8
	EOR	r8, r8, r2, ROR #16
	UBFX	r2, r4, #0, #8
	LDR	r9, [r0, r9, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r10, r7, #16, #8
	EOR	r9, r9, r11, ROR #24
	LSR	r11, r6, #24
	EOR	r9, r9, lr, ROR #8
	UBFX	lr, r4, #8, #8
	EOR	r9, r9, r2, ROR #16
	UBFX	r2, r5, #0, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r6, r6, #0, #8
	EOR	r10, r10, r11, ROR #24
	UBFX	r11, r4, #16, #8
	EOR	r10, r10, lr, ROR #8
	LSR	lr, r7, #24
	EOR	r10, r10, r2, ROR #16
	UBFX	r2, r5, #8, #8
	LDR	r6, [r0, r6, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r6, ROR #24
	LDM	r3!, {r4, r5, r6, r7}
	EOR	r11, r11, lr, ROR #24
	EOR	r11, r11, r2, ROR #8
	/*   XOR in Key Schedule */
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	UBFX	r4, r9, #16, #8
	LSR	r7, r8, #24
	UBFX	lr, r10, #8, #8
	UBFX	r2, r11, #0, #8
	LDR	r4, [r0, r4, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r5, r10, #16, #8
	EOR	r4, r4, r7, ROR #24
	LSR	r7, r9, #24
	EOR	r4, r4, lr, ROR #8
	UBFX	lr, r11, #8, #8
	EOR	r4, r4, r2, ROR #16
	UBFX	r2, r8, #0, #8
	LDR	r5, [r0, r5, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r6, r11, #16, #8
	EOR	r5, r5, r7, ROR #24
	LSR	r7, r10, #24
	EOR	r5, r5, lr, ROR #8
	UBFX	lr, r8, #8, #8
	EOR	r5, r5, r2, ROR #16
	UBFX	r2, r9, #0, #8
	LDR	r6, [r0, r6, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r10, r10, #0, #8
	EOR	r6, r6, r7, ROR #24
	UBFX	r7, r8, #16, #8
	EOR	r6, r6, lr, ROR #8
	LSR	lr, r11, #24
	EOR	r6, r6, r2, ROR #16
	UBFX	r2, r9, #8, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r10, ROR #24
	LDM	r3!, {r8, r9, r10, r11}
	EOR	r7, r7, lr, ROR #24
	EOR	r7, r7, r2, ROR #8
	/*   XOR in Key Schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	SUBS	r1, r1, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_AES_GCM_encrypt_block_nr_192
#else
	BNE.W	L_AES_GCM_encrypt_block_nr_192
#endif
	UBFX	r8, r5, #16, #8
	LSR	r11, r4, #24
	UBFX	lr, r6, #8, #8
	UBFX	r2, r7, #0, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r9, r6, #16, #8
	EOR	r8, r8, r11, ROR #24
	LSR	r11, r5, #24
	EOR	r8, r8, lr, ROR #8
	UBFX	lr, r7, #8, #8
	EOR	r8, r8, r2, ROR #16
	UBFX	r2, r4, #0, #8
	LDR	r9, [r0, r9, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r10, r7, #16, #8
	EOR	r9, r9, r11, ROR #24
	LSR	r11, r6, #24
	EOR	r9, r9, lr, ROR #8
	UBFX	lr, r4, #8, #8
	EOR	r9, r9, r2, ROR #16
	UBFX	r2, r5, #0, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r6, r6, #0, #8
	EOR	r10, r10, r11, ROR #24
	UBFX	r11, r4, #16, #8
	EOR	r10, r10, lr, ROR #8
	LSR	lr, r7, #24
	EOR	r10, r10, r2, ROR #16
	UBFX	r2, r5, #8, #8
	LDR	r6, [r0, r6, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r6, ROR #24
	LDM	r3!, {r4, r5, r6, r7}
	EOR	r11, r11, lr, ROR #24
	EOR	r11, r11, r2, ROR #8
	/*   XOR in Key Schedule */
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	UBFX	r4, r11, #0, #8
	UBFX	r7, r10, #8, #8
	UBFX	lr, r9, #16, #8
	LSR	r2, r8, #24
	LDRB	r4, [r0, r4, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	UBFX	r5, r8, #0, #8
	EOR	r4, r4, r7, LSL #8
	UBFX	r7, r11, #8, #8
	EOR	r4, r4, lr, LSL #16
	UBFX	lr, r10, #16, #8
	EOR	r4, r4, r2, LSL #24
	LSR	r2, r9, #24
	LDRB	r5, [r0, r5, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	UBFX	r6, r9, #0, #8
	EOR	r5, r5, r7, LSL #8
	UBFX	r7, r8, #8, #8
	EOR	r5, r5, lr, LSL #16
	UBFX	lr, r11, #16, #8
	EOR	r5, r5, r2, LSL #24
	LSR	r2, r10, #24
	LDRB	r6, [r0, r6, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	LSR	r11, r11, #24
	EOR	r6, r6, r7, LSL #8
	UBFX	r7, r10, #0, #8
	EOR	r6, r6, lr, LSL #16
	UBFX	lr, r9, #8, #8
	EOR	r6, r6, r2, LSL #24
	UBFX	r2, r8, #16, #8
	LDRB	r11, [r0, r11, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r11, LSL #16
	LDM	r3, {r8, r9, r10, r11}
	EOR	r7, r7, lr, LSL #8
	EOR	r7, r7, r2, LSL #16
	/*   XOR in Key Schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
#endif /* !WOLFSSL_ARMASM_AES_BLOCK_INLINE */
	POP	{r1, r2, lr}
	LDR	r3, [sp]
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
	REV	r7, r7
	LDR	r8, [lr]
	LDR	r9, [lr, #4]
	LDR	r10, [lr, #8]
	LDR	r11, [lr, #12]
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	LDR	r8, [sp, #4]
	STR	r4, [r1]
	STR	r5, [r1, #4]
	STR	r6, [r1, #8]
	STR	r7, [r1, #12]
	LDM	r8, {r4, r5, r6, r7}
	SUBS	r2, r2, #0x10
	ADD	lr, lr, #0x10
	ADD	r1, r1, #0x10
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_AES_GCM_encrypt_loop_block_192
#else
	BNE.W	L_AES_GCM_encrypt_loop_block_192
#endif
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	B	L_AES_GCM_encrypt_end
#else
	B.W	L_AES_GCM_encrypt_end
#endif
L_AES_GCM_encrypt_start_block_128:
L_AES_GCM_encrypt_loop_block_128:
	PUSH	{r1, r2, lr}
	LDR	lr, [sp, #16]
	ADD	r7, r7, #0x1
	LDM	r3!, {r8, r9, r10, r11}
	STR	r7, [lr, #12]
	/* Round: 0 - XOR in key schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	MOV	r1, #0x4
#ifndef WOLFSSL_ARMASM_AES_BLOCK_INLINE
	BL	AES_encrypt_block
#else
L_AES_GCM_encrypt_block_nr_128:
	UBFX	r8, r5, #16, #8
	LSR	r11, r4, #24
	UBFX	lr, r6, #8, #8
	UBFX	r2, r7, #0, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r9, r6, #16, #8
	EOR	r8, r8, r11, ROR #24
	LSR	r11, r5, #24
	EOR	r8, r8, lr, ROR #8
	UBFX	lr, r7, #8, #8
	EOR	r8, r8, r2, ROR #16
	UBFX	r2, r4, #0, #8
	LDR	r9, [r0, r9, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r10, r7, #16, #8
	EOR	r9, r9, r11, ROR #24
	LSR	r11, r6, #24
	EOR	r9, r9, lr, ROR #8
	UBFX	lr, r4, #8, #8
	EOR	r9, r9, r2, ROR #16
	UBFX	r2, r5, #0, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r6, r6, #0, #8
	EOR	r10, r10, r11, ROR #24
	UBFX	r11, r4, #16, #8
	EOR	r10, r10, lr, ROR #8
	LSR	lr, r7, #24
	EOR	r10, r10, r2, ROR #16
	UBFX	r2, r5, #8, #8
	LDR	r6, [r0, r6, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r6, ROR #24
	LDM	r3!, {r4, r5, r6, r7}
	EOR	r11, r11, lr, ROR #24
	EOR	r11, r11, r2, ROR #8
	/*   XOR in Key Schedule */
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	UBFX	r4, r9, #16, #8
	LSR	r7, r8, #24
	UBFX	lr, r10, #8, #8
	UBFX	r2, r11, #0, #8
	LDR	r4, [r0, r4, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r5, r10, #16, #8
	EOR	r4, r4, r7, ROR #24
	LSR	r7, r9, #24
	EOR	r4, r4, lr, ROR #8
	UBFX	lr, r11, #8, #8
	EOR	r4, r4, r2, ROR #16
	UBFX	r2, r8, #0, #8
	LDR	r5, [r0, r5, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r6, r11, #16, #8
	EOR	r5, r5, r7, ROR #24
	LSR	r7, r10, #24
	EOR	r5, r5, lr, ROR #8
	UBFX	lr, r8, #8, #8
	EOR	r5, r5, r2, ROR #16
	UBFX	r2, r9, #0, #8
	LDR	r6, [r0, r6, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r10, r10, #0, #8
	EOR	r6, r6, r7, ROR #24
	UBFX	r7, r8, #16, #8
	EOR	r6, r6, lr, ROR #8
	LSR	lr, r11, #24
	EOR	r6, r6, r2, ROR #16
	UBFX	r2, r9, #8, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r7, [r0, r7, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r10, ROR #24
	LDM	r3!, {r8, r9, r10, r11}
	EOR	r7, r7, lr, ROR #24
	EOR	r7, r7, r2, ROR #8
	/*   XOR in Key Schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	SUBS	r1, r1, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_AES_GCM_encrypt_block_nr_128
#else
	BNE.W	L_AES_GCM_encrypt_block_nr_128
#endif
	UBFX	r8, r5, #16, #8
	LSR	r11, r4, #24
	UBFX	lr, r6, #8, #8
	UBFX	r2, r7, #0, #8
	LDR	r8, [r0, r8, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r9, r6, #16, #8
	EOR	r8, r8, r11, ROR #24
	LSR	r11, r5, #24
	EOR	r8, r8, lr, ROR #8
	UBFX	lr, r7, #8, #8
	EOR	r8, r8, r2, ROR #16
	UBFX	r2, r4, #0, #8
	LDR	r9, [r0, r9, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r10, r7, #16, #8
	EOR	r9, r9, r11, ROR #24
	LSR	r11, r6, #24
	EOR	r9, r9, lr, ROR #8
	UBFX	lr, r4, #8, #8
	EOR	r9, r9, r2, ROR #16
	UBFX	r2, r5, #0, #8
	LDR	r10, [r0, r10, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	UBFX	r6, r6, #0, #8
	EOR	r10, r10, r11, ROR #24
	UBFX	r11, r4, #16, #8
	EOR	r10, r10, lr, ROR #8
	LSR	lr, r7, #24
	EOR	r10, r10, r2, ROR #16
	UBFX	r2, r5, #8, #8
	LDR	r6, [r0, r6, LSL #2]
	LDR	lr, [r0, lr, LSL #2]
	LDR	r11, [r0, r11, LSL #2]
	LDR	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r6, ROR #24
	LDM	r3!, {r4, r5, r6, r7}
	EOR	r11, r11, lr, ROR #24
	EOR	r11, r11, r2, ROR #8
	/*   XOR in Key Schedule */
	EOR	r8, r8, r4
	EOR	r9, r9, r5
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	UBFX	r4, r11, #0, #8
	UBFX	r7, r10, #8, #8
	UBFX	lr, r9, #16, #8
	LSR	r2, r8, #24
	LDRB	r4, [r0, r4, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	UBFX	r5, r8, #0, #8
	EOR	r4, r4, r7, LSL #8
	UBFX	r7, r11, #8, #8
	EOR	r4, r4, lr, LSL #16
	UBFX	lr, r10, #16, #8
	EOR	r4, r4, r2, LSL #24
	LSR	r2, r9, #24
	LDRB	r5, [r0, r5, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	UBFX	r6, r9, #0, #8
	EOR	r5, r5, r7, LSL #8
	UBFX	r7, r8, #8, #8
	EOR	r5, r5, lr, LSL #16
	UBFX	lr, r11, #16, #8
	EOR	r5, r5, r2, LSL #24
	LSR	r2, r10, #24
	LDRB	r6, [r0, r6, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	LSR	r11, r11, #24
	EOR	r6, r6, r7, LSL #8
	UBFX	r7, r10, #0, #8
	EOR	r6, r6, lr, LSL #16
	UBFX	lr, r9, #8, #8
	EOR	r6, r6, r2, LSL #24
	UBFX	r2, r8, #16, #8
	LDRB	r11, [r0, r11, LSL #2]
	LDRB	r7, [r0, r7, LSL #2]
	LDRB	lr, [r0, lr, LSL #2]
	LDRB	r2, [r0, r2, LSL #2]
	EOR	lr, lr, r11, LSL #16
	LDM	r3, {r8, r9, r10, r11}
	EOR	r7, r7, lr, LSL #8
	EOR	r7, r7, r2, LSL #16
	/*   XOR in Key Schedule */
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
#endif /* !WOLFSSL_ARMASM_AES_BLOCK_INLINE */
	POP	{r1, r2, lr}
	LDR	r3, [sp]
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
	REV	r7, r7
	LDR	r8, [lr]
	LDR	r9, [lr, #4]
	LDR	r10, [lr, #8]
	LDR	r11, [lr, #12]
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	LDR	r8, [sp, #4]
	STR	r4, [r1]
	STR	r5, [r1, #4]
	STR	r6, [r1, #8]
	STR	r7, [r1, #12]
	LDM	r8, {r4, r5, r6, r7}
	SUBS	r2, r2, #0x10
	ADD	lr, lr, #0x10
	ADD	r1, r1, #0x10
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_AES_GCM_encrypt_loop_block_128
#else
	BNE.W	L_AES_GCM_encrypt_loop_block_128
#endif
L_AES_GCM_encrypt_end:
	POP	{r3, r8}
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
	REV	r7, r7
	STM	r8, {r4, r5, r6, r7}
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 1118 */
	.size	AES_GCM_encrypt,.-AES_GCM_encrypt
#endif /* HAVE_AESGCM */
#endif /* !NO_AES */
#endif /* WOLFSSL_ARMASM_THUMB2 */
#endif /* WOLFSSL_ARMASM */

#if defined(__linux__) && defined(__ELF__)
.section	.note.GNU-stack,"",%progbits
#endif
#endif /* !WOLFSSL_ARMASM_INLINE */
