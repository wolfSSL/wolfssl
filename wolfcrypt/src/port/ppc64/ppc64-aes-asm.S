/* ppc64-aes-asm
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

#include <wolfssl/wolfcrypt/libwolfssl_sources_asm.h>

/* Generated using (from wolfssl):
 *   cd ../scripts
 *   ruby ./aes/aes.rb ppc64 \
 *       ../wolfssl/wolfcrypt/src/port/ppc64/ppc64-aes-asm.S
 */
#ifdef WOLFSSL_PPC64_ASM
#ifndef WOLFSSL_PPC64_ASM_INLINE
#if !defined(NO_AES) && defined(WOLFSSL_PPC64_ASM)
#ifdef HAVE_AES_DECRYPT
#ifndef __APPLE__
	.text
	.type	L_AES_PPC64_td, %object
	.size	L_AES_PPC64_td, 1024
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_AES_PPC64_td:
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
	.type	L_AES_PPC64_te, %object
	.size	L_AES_PPC64_te, 1024
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_AES_PPC64_te:
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
.globl	AES_invert_key
.type	AES_invert_key,@function
.align	16
AES_invert_key:
#if defined(_CALL_ELF) && _CALL_ELF == 2
0:	addis	2, 12, .TOC.-0b@ha
	addi	2, 2, .TOC.-0b@l
	.localentry	AES_invert_key, .-AES_invert_key
#endif
#else
.section	__TEXT,__text
.globl	_AES_invert_key
.p2align	4
_AES_invert_key:
#endif /* __APPLE__ */
	stdu	1, -32(1)
	mflr	0
	std	0, 24(1)
	std	14, 0(1)
	std	15, 8(1)
	std	16, 16(1)
	addis	5, 2, L_AES_PPC64_te@toc@ha
	addi	5, 5, L_AES_PPC64_te@toc@l
	addis	6, 2, L_AES_PPC64_td@toc@ha
	addi	6, 6, L_AES_PPC64_td@toc@l
	addi	5, 5, 3
	sldi	16, 4, 4
	add	16, 16, 3
	ld	7, 0(3)
	ld	8, 8(3)
	ld	11, 0(16)
	ld	12, 8(16)
	rldicr	7, 7, 32, 63
	rldicr	8, 8, 32, 63
	rldicr	11, 11, 32, 63
	rldicr	12, 12, 32, 63
	std	7, 0(16)
	std	8, 8(16)
	std	11, 0(3)
	std	12, 8(3)
	addi	3, 3, 16
	addi	16, 16, -16
	addi	0, 4, -2
	srdi	0, 0, 1
	mtctr	0
L_AES_invert_key_loop:
	ld	7, 0(3)
	ld	8, 8(3)
	ld	11, 0(16)
	ld	12, 8(16)
	std	7, 0(16)
	std	8, 8(16)
	std	11, 0(3)
	std	12, 8(3)
	addi	3, 3, 16
	addi	16, 16, -16
	bdnz	L_AES_invert_key_loop
	sldi	16, 4, 3
	subf	3, 16, 3
	addi	3, 3, 16
	addi	0, 4, -1
	mtctr	0
L_AES_invert_key_mix_loop:
	lwz	8, 0(3)
	lwz	7, 4(3)
	lwz	10, 8(3)
	lwz	9, 12(3)
	rlwinm	11, 7, 2, 22, 29
	rlwinm	12, 7, 26, 22, 29
	rlwinm	14, 7, 18, 22, 29
	rlwinm	15, 7, 10, 22, 29
	lbzx	11, 5, 11
	lbzx	12, 5, 12
	lbzx	14, 5, 14
	lbzx	15, 5, 15
	slwi	11, 11, 2
	slwi	12, 12, 2
	slwi	14, 14, 2
	slwi	15, 15, 2
	lwzx	11, 6, 11
	lwzx	12, 6, 12
	lwzx	14, 6, 14
	lwzx	15, 6, 15
	rlwimi	11, 11, 16, 0, 31
	rlwimi	12, 12, 24, 0, 31
	rlwimi	15, 15, 8, 0, 31
	xor	14, 14, 11
	xor	14, 14, 12
	xor	14, 14, 15
	stw	14, 4(3)
	rlwinm	11, 8, 2, 22, 29
	rlwinm	12, 8, 26, 22, 29
	rlwinm	14, 8, 18, 22, 29
	rlwinm	15, 8, 10, 22, 29
	lbzx	11, 5, 11
	lbzx	12, 5, 12
	lbzx	14, 5, 14
	lbzx	15, 5, 15
	slwi	11, 11, 2
	slwi	12, 12, 2
	slwi	14, 14, 2
	slwi	15, 15, 2
	lwzx	11, 6, 11
	lwzx	12, 6, 12
	lwzx	14, 6, 14
	lwzx	15, 6, 15
	rlwimi	11, 11, 16, 0, 31
	rlwimi	12, 12, 24, 0, 31
	rlwimi	15, 15, 8, 0, 31
	xor	14, 14, 11
	xor	14, 14, 12
	xor	14, 14, 15
	stw	14, 0(3)
	addi	3, 3, 8
	rlwinm	11, 9, 2, 22, 29
	rlwinm	12, 9, 26, 22, 29
	rlwinm	14, 9, 18, 22, 29
	rlwinm	15, 9, 10, 22, 29
	lbzx	11, 5, 11
	lbzx	12, 5, 12
	lbzx	14, 5, 14
	lbzx	15, 5, 15
	slwi	11, 11, 2
	slwi	12, 12, 2
	slwi	14, 14, 2
	slwi	15, 15, 2
	lwzx	11, 6, 11
	lwzx	12, 6, 12
	lwzx	14, 6, 14
	lwzx	15, 6, 15
	rlwimi	11, 11, 16, 0, 31
	rlwimi	12, 12, 24, 0, 31
	rlwimi	15, 15, 8, 0, 31
	xor	14, 14, 11
	xor	14, 14, 12
	xor	14, 14, 15
	stw	14, 4(3)
	rlwinm	11, 10, 2, 22, 29
	rlwinm	12, 10, 26, 22, 29
	rlwinm	14, 10, 18, 22, 29
	rlwinm	15, 10, 10, 22, 29
	lbzx	11, 5, 11
	lbzx	12, 5, 12
	lbzx	14, 5, 14
	lbzx	15, 5, 15
	slwi	11, 11, 2
	slwi	12, 12, 2
	slwi	14, 14, 2
	slwi	15, 15, 2
	lwzx	11, 6, 11
	lwzx	12, 6, 12
	lwzx	14, 6, 14
	lwzx	15, 6, 15
	rlwimi	11, 11, 16, 0, 31
	rlwimi	12, 12, 24, 0, 31
	rlwimi	15, 15, 8, 0, 31
	xor	14, 14, 11
	xor	14, 14, 12
	xor	14, 14, 15
	stw	14, 0(3)
	addi	3, 3, 8
	bdnz	L_AES_invert_key_mix_loop
	ld	0, 24(1)
	mtlr	0
	ld	14, 0(1)
	ld	15, 8(1)
	ld	16, 16(1)
	addi	1, 1, 32
	blr
#ifndef __APPLE__
	.size	AES_invert_key,.-AES_invert_key
#endif /* __APPLE__ */
#endif /* HAVE_AES_DECRYPT */
#ifndef __APPLE__
	.text
	.type	L_AES_PPC64_rcon, %object
	.size	L_AES_PPC64_rcon, 40
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_AES_PPC64_rcon:
	.long	0x01000000,0x02000000,0x04000000,0x08000000
	.long	0x10000000,0x20000000,0x40000000,0x80000000
	.long	0x1b000000,0x36000000
#ifndef __APPLE__
.text
.globl	AES_set_encrypt_key
.type	AES_set_encrypt_key,@function
.align	16
AES_set_encrypt_key:
#if defined(_CALL_ELF) && _CALL_ELF == 2
0:	addis	2, 12, .TOC.-0b@ha
	addi	2, 2, .TOC.-0b@l
	.localentry	AES_set_encrypt_key, .-AES_set_encrypt_key
#endif
#else
.section	__TEXT,__text
.globl	_AES_set_encrypt_key
.p2align	4
_AES_set_encrypt_key:
#endif /* __APPLE__ */
	stdu	1, -24(1)
	mflr	0
	std	0, 16(1)
	std	14, 0(1)
	std	15, 8(1)
	addis	6, 2, L_AES_PPC64_te@toc@ha
	addi	6, 6, L_AES_PPC64_te@toc@l
	addis	7, 2, L_AES_PPC64_rcon@toc@ha
	addi	7, 7, L_AES_PPC64_rcon@toc@l
	addi	6, 6, 3
	cmplwi	4, 0x80
	beq	L_AES_set_encrypt_key_start_128
	cmplwi	4, 0xc0
	beq	L_AES_set_encrypt_key_start_192
	ld	9, 0(3)
	ld	10, 8(3)
	ld	11, 16(3)
	ld	12, 24(3)
	rldicr	9, 9, 32, 63
	rldicr	10, 10, 32, 63
	rldicr	11, 11, 32, 63
	rldicr	12, 12, 32, 63
	std	9, 0(5)
	std	10, 8(5)
	std	11, 16(5)
	std	12, 24(5)
	rldicr	12, 12, 32, 63
	li	8, 6
	mtctr	8
L_AES_set_encrypt_key_loop_256:
	rlwinm	9, 12, 2, 22, 29
	rlwinm	10, 12, 26, 22, 29
	rlwinm	11, 12, 18, 22, 29
	rlwinm	12, 12, 10, 22, 29
	lbzx	9, 6, 9
	lbzx	10, 6, 10
	lbzx	11, 6, 11
	lbzx	0, 6, 12
	rlwimi	0, 9, 8, 16, 23
	rlwimi	0, 10, 16, 8, 15
	rlwimi	0, 11, 24, 0, 7
	lwz	10, 0(5)
	lwz	9, 4(5)
	lwz	12, 8(5)
	lwz	11, 12(5)
	addi	5, 5, 16
	xor	9, 9, 0
	lwz	0, 0(7)
	addi	7, 7, 4
	xor	9, 9, 0
	xor	10, 10, 9
	xor	11, 11, 10
	xor	12, 12, 11
	stw	10, 16(5)
	stw	9, 20(5)
	stw	12, 24(5)
	stw	11, 28(5)
	rlwinm	9, 12, 26, 22, 29
	rlwinm	10, 12, 18, 22, 29
	rlwinm	11, 12, 10, 22, 29
	rlwinm	12, 12, 2, 22, 29
	lbzx	9, 6, 9
	lbzx	10, 6, 10
	lbzx	11, 6, 11
	lbzx	0, 6, 12
	rlwimi	0, 9, 8, 16, 23
	rlwimi	0, 10, 16, 8, 15
	rlwimi	0, 11, 24, 0, 7
	lwz	10, 0(5)
	lwz	9, 4(5)
	lwz	12, 8(5)
	lwz	11, 12(5)
	addi	5, 5, 16
	xor	9, 9, 0
	xor	10, 10, 9
	xor	11, 11, 10
	xor	12, 12, 11
	stw	10, 16(5)
	stw	9, 20(5)
	stw	12, 24(5)
	stw	11, 28(5)
	bdnz	L_AES_set_encrypt_key_loop_256
	rlwinm	9, 12, 2, 22, 29
	rlwinm	10, 12, 26, 22, 29
	rlwinm	11, 12, 18, 22, 29
	rlwinm	12, 12, 10, 22, 29
	lbzx	9, 6, 9
	lbzx	10, 6, 10
	lbzx	11, 6, 11
	lbzx	0, 6, 12
	rlwimi	0, 9, 8, 16, 23
	rlwimi	0, 10, 16, 8, 15
	rlwimi	0, 11, 24, 0, 7
	lwz	10, 0(5)
	lwz	9, 4(5)
	lwz	12, 8(5)
	lwz	11, 12(5)
	addi	5, 5, 16
	xor	9, 9, 0
	lwz	0, 0(7)
	addi	7, 7, 4
	xor	9, 9, 0
	xor	10, 10, 9
	xor	11, 11, 10
	xor	12, 12, 11
	stw	9, 16(5)
	stw	10, 20(5)
	stw	11, 24(5)
	stw	12, 28(5)
	b	L_AES_set_encrypt_key_end
L_AES_set_encrypt_key_start_192:
	ld	12, 0(3)
	ld	14, 8(3)
	ld	15, 16(3)
	rldicr	12, 12, 32, 63
	rldicr	14, 14, 32, 63
	rldicr	15, 15, 32, 63
	std	12, 0(5)
	std	14, 8(5)
	std	15, 16(5)
	rldicr	15, 15, 32, 63
	li	8, 7
	mtctr	8
L_AES_set_encrypt_key_loop_192:
	rlwinm	9, 15, 2, 22, 29
	rlwinm	10, 15, 26, 22, 29
	rlwinm	11, 15, 18, 22, 29
	rlwinm	15, 15, 10, 22, 29
	lbzx	9, 6, 9
	lbzx	10, 6, 10
	lbzx	11, 6, 11
	lbzx	0, 6, 15
	rlwimi	0, 9, 8, 16, 23
	rlwimi	0, 10, 16, 8, 15
	rlwimi	0, 11, 24, 0, 7
	lwz	10, 0(5)
	lwz	9, 4(5)
	lwz	12, 8(5)
	lwz	11, 12(5)
	lwz	15, 16(5)
	lwz	14, 20(5)
	addi	5, 5, 24
	xor	9, 9, 0
	lwz	0, 0(7)
	addi	7, 7, 4
	xor	9, 9, 0
	xor	10, 10, 9
	xor	11, 11, 10
	xor	12, 12, 11
	xor	14, 14, 12
	xor	15, 15, 14
	stw	10, 0(5)
	stw	9, 4(5)
	stw	12, 8(5)
	stw	11, 12(5)
	stw	15, 16(5)
	stw	14, 20(5)
	bdnz	L_AES_set_encrypt_key_loop_192
	rlwinm	9, 15, 2, 22, 29
	rlwinm	10, 15, 26, 22, 29
	rlwinm	11, 15, 18, 22, 29
	rlwinm	15, 15, 10, 22, 29
	lbzx	9, 6, 9
	lbzx	10, 6, 10
	lbzx	11, 6, 11
	lbzx	0, 6, 15
	rlwimi	0, 9, 8, 16, 23
	rlwimi	0, 10, 16, 8, 15
	rlwimi	0, 11, 24, 0, 7
	lwz	10, 0(5)
	lwz	9, 4(5)
	lwz	12, 8(5)
	lwz	11, 12(5)
	lwz	15, 16(5)
	lwz	14, 20(5)
	addi	5, 5, 24
	xor	9, 9, 0
	lwz	0, 0(7)
	addi	7, 7, 4
	xor	9, 9, 0
	xor	10, 10, 9
	xor	11, 11, 10
	xor	12, 12, 11
	stw	9, 0(5)
	stw	10, 4(5)
	stw	11, 8(5)
	stw	12, 12(5)
	b	L_AES_set_encrypt_key_end
L_AES_set_encrypt_key_start_128:
	li	8, 0
	ld	11, 0(3)
	ld	12, 8(3)
	rldicr	11, 11, 32, 63
	rldicr	12, 12, 32, 63
	std	11, 0(5)
	std	12, 8(5)
	rldicr	12, 12, 32, 63
	li	8, 9
	mtctr	8
L_AES_set_encrypt_key_loop_128:
	rlwinm	9, 12, 2, 22, 29
	rlwinm	10, 12, 26, 22, 29
	rlwinm	11, 12, 18, 22, 29
	rlwinm	12, 12, 10, 22, 29
	lbzx	9, 6, 9
	lbzx	10, 6, 10
	lbzx	11, 6, 11
	lbzx	0, 6, 12
	rlwimi	0, 9, 8, 16, 23
	rlwimi	0, 10, 16, 8, 15
	rlwimi	0, 11, 24, 0, 7
	lwz	10, 0(5)
	lwz	9, 4(5)
	lwz	12, 8(5)
	lwz	11, 12(5)
	addi	5, 5, 16
	xor	9, 9, 0
	lwz	0, 0(7)
	addi	7, 7, 4
	xor	9, 9, 0
	xor	10, 10, 9
	xor	11, 11, 10
	xor	12, 12, 11
	stw	10, 0(5)
	stw	9, 4(5)
	stw	12, 8(5)
	stw	11, 12(5)
	bdnz	L_AES_set_encrypt_key_loop_128
	rlwinm	9, 12, 2, 22, 29
	rlwinm	10, 12, 26, 22, 29
	rlwinm	11, 12, 18, 22, 29
	rlwinm	12, 12, 10, 22, 29
	lbzx	9, 6, 9
	lbzx	10, 6, 10
	lbzx	11, 6, 11
	lbzx	0, 6, 12
	rlwimi	0, 9, 8, 16, 23
	rlwimi	0, 10, 16, 8, 15
	rlwimi	0, 11, 24, 0, 7
	lwz	10, 0(5)
	lwz	9, 4(5)
	lwz	12, 8(5)
	lwz	11, 12(5)
	addi	5, 5, 16
	xor	9, 9, 0
	lwz	0, 0(7)
	addi	7, 7, 4
	xor	9, 9, 0
	xor	10, 10, 9
	xor	11, 11, 10
	xor	12, 12, 11
	stw	9, 0(5)
	stw	10, 4(5)
	stw	11, 8(5)
	stw	12, 12(5)
L_AES_set_encrypt_key_end:
	ld	0, 16(1)
	mtlr	0
	ld	14, 0(1)
	ld	15, 8(1)
	addi	1, 1, 24
	blr
#ifndef __APPLE__
	.size	AES_set_encrypt_key,.-AES_set_encrypt_key
#endif /* __APPLE__ */
#ifndef __APPLE__
	.text
	.type	L_AES_PPC64_te4_0, %object
	.size	L_AES_PPC64_te4_0, 4096
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_AES_PPC64_te4_0:
	.long	0xc66363a5,0xf87c7c84,0xee777799,0xf67b7b8d
	.long	0xfff2f20d,0xd66b6bbd,0xde6f6fb1,0x91c5c554
	.long	0x60303050,0x02010103,0xce6767a9,0x562b2b7d
	.long	0xe7fefe19,0xb5d7d762,0x4dababe6,0xec76769a
	.long	0x8fcaca45,0x1f82829d,0x89c9c940,0xfa7d7d87
	.long	0xeffafa15,0xb25959eb,0x8e4747c9,0xfbf0f00b
	.long	0x41adadec,0xb3d4d467,0x5fa2a2fd,0x45afafea
	.long	0x239c9cbf,0x53a4a4f7,0xe4727296,0x9bc0c05b
	.long	0x75b7b7c2,0xe1fdfd1c,0x3d9393ae,0x4c26266a
	.long	0x6c36365a,0x7e3f3f41,0xf5f7f702,0x83cccc4f
	.long	0x6834345c,0x51a5a5f4,0xd1e5e534,0xf9f1f108
	.long	0xe2717193,0xabd8d873,0x62313153,0x2a15153f
	.long	0x0804040c,0x95c7c752,0x46232365,0x9dc3c35e
	.long	0x30181828,0x379696a1,0x0a05050f,0x2f9a9ab5
	.long	0x0e070709,0x24121236,0x1b80809b,0xdfe2e23d
	.long	0xcdebeb26,0x4e272769,0x7fb2b2cd,0xea75759f
	.long	0x1209091b,0x1d83839e,0x582c2c74,0x341a1a2e
	.long	0x361b1b2d,0xdc6e6eb2,0xb45a5aee,0x5ba0a0fb
	.long	0xa45252f6,0x763b3b4d,0xb7d6d661,0x7db3b3ce
	.long	0x5229297b,0xdde3e33e,0x5e2f2f71,0x13848497
	.long	0xa65353f5,0xb9d1d168,0x00000000,0xc1eded2c
	.long	0x40202060,0xe3fcfc1f,0x79b1b1c8,0xb65b5bed
	.long	0xd46a6abe,0x8dcbcb46,0x67bebed9,0x7239394b
	.long	0x944a4ade,0x984c4cd4,0xb05858e8,0x85cfcf4a
	.long	0xbbd0d06b,0xc5efef2a,0x4faaaae5,0xedfbfb16
	.long	0x864343c5,0x9a4d4dd7,0x66333355,0x11858594
	.long	0x8a4545cf,0xe9f9f910,0x04020206,0xfe7f7f81
	.long	0xa05050f0,0x783c3c44,0x259f9fba,0x4ba8a8e3
	.long	0xa25151f3,0x5da3a3fe,0x804040c0,0x058f8f8a
	.long	0x3f9292ad,0x219d9dbc,0x70383848,0xf1f5f504
	.long	0x63bcbcdf,0x77b6b6c1,0xafdada75,0x42212163
	.long	0x20101030,0xe5ffff1a,0xfdf3f30e,0xbfd2d26d
	.long	0x81cdcd4c,0x180c0c14,0x26131335,0xc3ecec2f
	.long	0xbe5f5fe1,0x359797a2,0x884444cc,0x2e171739
	.long	0x93c4c457,0x55a7a7f2,0xfc7e7e82,0x7a3d3d47
	.long	0xc86464ac,0xba5d5de7,0x3219192b,0xe6737395
	.long	0xc06060a0,0x19818198,0x9e4f4fd1,0xa3dcdc7f
	.long	0x44222266,0x542a2a7e,0x3b9090ab,0x0b888883
	.long	0x8c4646ca,0xc7eeee29,0x6bb8b8d3,0x2814143c
	.long	0xa7dede79,0xbc5e5ee2,0x160b0b1d,0xaddbdb76
	.long	0xdbe0e03b,0x64323256,0x743a3a4e,0x140a0a1e
	.long	0x924949db,0x0c06060a,0x4824246c,0xb85c5ce4
	.long	0x9fc2c25d,0xbdd3d36e,0x43acacef,0xc46262a6
	.long	0x399191a8,0x319595a4,0xd3e4e437,0xf279798b
	.long	0xd5e7e732,0x8bc8c843,0x6e373759,0xda6d6db7
	.long	0x018d8d8c,0xb1d5d564,0x9c4e4ed2,0x49a9a9e0
	.long	0xd86c6cb4,0xac5656fa,0xf3f4f407,0xcfeaea25
	.long	0xca6565af,0xf47a7a8e,0x47aeaee9,0x10080818
	.long	0x6fbabad5,0xf0787888,0x4a25256f,0x5c2e2e72
	.long	0x381c1c24,0x57a6a6f1,0x73b4b4c7,0x97c6c651
	.long	0xcbe8e823,0xa1dddd7c,0xe874749c,0x3e1f1f21
	.long	0x964b4bdd,0x61bdbddc,0x0d8b8b86,0x0f8a8a85
	.long	0xe0707090,0x7c3e3e42,0x71b5b5c4,0xcc6666aa
	.long	0x904848d8,0x06030305,0xf7f6f601,0x1c0e0e12
	.long	0xc26161a3,0x6a35355f,0xae5757f9,0x69b9b9d0
	.long	0x17868691,0x99c1c158,0x3a1d1d27,0x279e9eb9
	.long	0xd9e1e138,0xebf8f813,0x2b9898b3,0x22111133
	.long	0xd26969bb,0xa9d9d970,0x078e8e89,0x339494a7
	.long	0x2d9b9bb6,0x3c1e1e22,0x15878792,0xc9e9e920
	.long	0x87cece49,0xaa5555ff,0x50282878,0xa5dfdf7a
	.long	0x038c8c8f,0x59a1a1f8,0x09898980,0x1a0d0d17
	.long	0x65bfbfda,0xd7e6e631,0x844242c6,0xd06868b8
	.long	0x824141c3,0x299999b0,0x5a2d2d77,0x1e0f0f11
	.long	0x7bb0b0cb,0xa85454fc,0x6dbbbbd6,0x2c16163a
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
	.long	0x63a5c663,0x7c84f87c,0x7799ee77,0x7b8df67b
	.long	0xf20dfff2,0x6bbdd66b,0x6fb1de6f,0xc55491c5
	.long	0x30506030,0x01030201,0x67a9ce67,0x2b7d562b
	.long	0xfe19e7fe,0xd762b5d7,0xabe64dab,0x769aec76
	.long	0xca458fca,0x829d1f82,0xc94089c9,0x7d87fa7d
	.long	0xfa15effa,0x59ebb259,0x47c98e47,0xf00bfbf0
	.long	0xadec41ad,0xd467b3d4,0xa2fd5fa2,0xafea45af
	.long	0x9cbf239c,0xa4f753a4,0x7296e472,0xc05b9bc0
	.long	0xb7c275b7,0xfd1ce1fd,0x93ae3d93,0x266a4c26
	.long	0x365a6c36,0x3f417e3f,0xf702f5f7,0xcc4f83cc
	.long	0x345c6834,0xa5f451a5,0xe534d1e5,0xf108f9f1
	.long	0x7193e271,0xd873abd8,0x31536231,0x153f2a15
	.long	0x040c0804,0xc75295c7,0x23654623,0xc35e9dc3
	.long	0x18283018,0x96a13796,0x050f0a05,0x9ab52f9a
	.long	0x07090e07,0x12362412,0x809b1b80,0xe23ddfe2
	.long	0xeb26cdeb,0x27694e27,0xb2cd7fb2,0x759fea75
	.long	0x091b1209,0x839e1d83,0x2c74582c,0x1a2e341a
	.long	0x1b2d361b,0x6eb2dc6e,0x5aeeb45a,0xa0fb5ba0
	.long	0x52f6a452,0x3b4d763b,0xd661b7d6,0xb3ce7db3
	.long	0x297b5229,0xe33edde3,0x2f715e2f,0x84971384
	.long	0x53f5a653,0xd168b9d1,0x00000000,0xed2cc1ed
	.long	0x20604020,0xfc1fe3fc,0xb1c879b1,0x5bedb65b
	.long	0x6abed46a,0xcb468dcb,0xbed967be,0x394b7239
	.long	0x4ade944a,0x4cd4984c,0x58e8b058,0xcf4a85cf
	.long	0xd06bbbd0,0xef2ac5ef,0xaae54faa,0xfb16edfb
	.long	0x43c58643,0x4dd79a4d,0x33556633,0x85941185
	.long	0x45cf8a45,0xf910e9f9,0x02060402,0x7f81fe7f
	.long	0x50f0a050,0x3c44783c,0x9fba259f,0xa8e34ba8
	.long	0x51f3a251,0xa3fe5da3,0x40c08040,0x8f8a058f
	.long	0x92ad3f92,0x9dbc219d,0x38487038,0xf504f1f5
	.long	0xbcdf63bc,0xb6c177b6,0xda75afda,0x21634221
	.long	0x10302010,0xff1ae5ff,0xf30efdf3,0xd26dbfd2
	.long	0xcd4c81cd,0x0c14180c,0x13352613,0xec2fc3ec
	.long	0x5fe1be5f,0x97a23597,0x44cc8844,0x17392e17
	.long	0xc45793c4,0xa7f255a7,0x7e82fc7e,0x3d477a3d
	.long	0x64acc864,0x5de7ba5d,0x192b3219,0x7395e673
	.long	0x60a0c060,0x81981981,0x4fd19e4f,0xdc7fa3dc
	.long	0x22664422,0x2a7e542a,0x90ab3b90,0x88830b88
	.long	0x46ca8c46,0xee29c7ee,0xb8d36bb8,0x143c2814
	.long	0xde79a7de,0x5ee2bc5e,0x0b1d160b,0xdb76addb
	.long	0xe03bdbe0,0x32566432,0x3a4e743a,0x0a1e140a
	.long	0x49db9249,0x060a0c06,0x246c4824,0x5ce4b85c
	.long	0xc25d9fc2,0xd36ebdd3,0xacef43ac,0x62a6c462
	.long	0x91a83991,0x95a43195,0xe437d3e4,0x798bf279
	.long	0xe732d5e7,0xc8438bc8,0x37596e37,0x6db7da6d
	.long	0x8d8c018d,0xd564b1d5,0x4ed29c4e,0xa9e049a9
	.long	0x6cb4d86c,0x56faac56,0xf407f3f4,0xea25cfea
	.long	0x65afca65,0x7a8ef47a,0xaee947ae,0x08181008
	.long	0xbad56fba,0x7888f078,0x256f4a25,0x2e725c2e
	.long	0x1c24381c,0xa6f157a6,0xb4c773b4,0xc65197c6
	.long	0xe823cbe8,0xdd7ca1dd,0x749ce874,0x1f213e1f
	.long	0x4bdd964b,0xbddc61bd,0x8b860d8b,0x8a850f8a
	.long	0x7090e070,0x3e427c3e,0xb5c471b5,0x66aacc66
	.long	0x48d89048,0x03050603,0xf601f7f6,0x0e121c0e
	.long	0x61a3c261,0x355f6a35,0x57f9ae57,0xb9d069b9
	.long	0x86911786,0xc15899c1,0x1d273a1d,0x9eb9279e
	.long	0xe138d9e1,0xf813ebf8,0x98b32b98,0x11332211
	.long	0x69bbd269,0xd970a9d9,0x8e89078e,0x94a73394
	.long	0x9bb62d9b,0x1e223c1e,0x87921587,0xe920c9e9
	.long	0xce4987ce,0x55ffaa55,0x28785028,0xdf7aa5df
	.long	0x8c8f038c,0xa1f859a1,0x89800989,0x0d171a0d
	.long	0xbfda65bf,0xe631d7e6,0x42c68442,0x68b8d068
	.long	0x41c38241,0x99b02999,0x2d775a2d,0x0f111e0f
	.long	0xb0cb7bb0,0x54fca854,0xbbd66dbb,0x163a2c16
	.long	0x6363a5c6,0x7c7c84f8,0x777799ee,0x7b7b8df6
	.long	0xf2f20dff,0x6b6bbdd6,0x6f6fb1de,0xc5c55491
	.long	0x30305060,0x01010302,0x6767a9ce,0x2b2b7d56
	.long	0xfefe19e7,0xd7d762b5,0xababe64d,0x76769aec
	.long	0xcaca458f,0x82829d1f,0xc9c94089,0x7d7d87fa
	.long	0xfafa15ef,0x5959ebb2,0x4747c98e,0xf0f00bfb
	.long	0xadadec41,0xd4d467b3,0xa2a2fd5f,0xafafea45
	.long	0x9c9cbf23,0xa4a4f753,0x727296e4,0xc0c05b9b
	.long	0xb7b7c275,0xfdfd1ce1,0x9393ae3d,0x26266a4c
	.long	0x36365a6c,0x3f3f417e,0xf7f702f5,0xcccc4f83
	.long	0x34345c68,0xa5a5f451,0xe5e534d1,0xf1f108f9
	.long	0x717193e2,0xd8d873ab,0x31315362,0x15153f2a
	.long	0x04040c08,0xc7c75295,0x23236546,0xc3c35e9d
	.long	0x18182830,0x9696a137,0x05050f0a,0x9a9ab52f
	.long	0x0707090e,0x12123624,0x80809b1b,0xe2e23ddf
	.long	0xebeb26cd,0x2727694e,0xb2b2cd7f,0x75759fea
	.long	0x09091b12,0x83839e1d,0x2c2c7458,0x1a1a2e34
	.long	0x1b1b2d36,0x6e6eb2dc,0x5a5aeeb4,0xa0a0fb5b
	.long	0x5252f6a4,0x3b3b4d76,0xd6d661b7,0xb3b3ce7d
	.long	0x29297b52,0xe3e33edd,0x2f2f715e,0x84849713
	.long	0x5353f5a6,0xd1d168b9,0x00000000,0xeded2cc1
	.long	0x20206040,0xfcfc1fe3,0xb1b1c879,0x5b5bedb6
	.long	0x6a6abed4,0xcbcb468d,0xbebed967,0x39394b72
	.long	0x4a4ade94,0x4c4cd498,0x5858e8b0,0xcfcf4a85
	.long	0xd0d06bbb,0xefef2ac5,0xaaaae54f,0xfbfb16ed
	.long	0x4343c586,0x4d4dd79a,0x33335566,0x85859411
	.long	0x4545cf8a,0xf9f910e9,0x02020604,0x7f7f81fe
	.long	0x5050f0a0,0x3c3c4478,0x9f9fba25,0xa8a8e34b
	.long	0x5151f3a2,0xa3a3fe5d,0x4040c080,0x8f8f8a05
	.long	0x9292ad3f,0x9d9dbc21,0x38384870,0xf5f504f1
	.long	0xbcbcdf63,0xb6b6c177,0xdada75af,0x21216342
	.long	0x10103020,0xffff1ae5,0xf3f30efd,0xd2d26dbf
	.long	0xcdcd4c81,0x0c0c1418,0x13133526,0xecec2fc3
	.long	0x5f5fe1be,0x9797a235,0x4444cc88,0x1717392e
	.long	0xc4c45793,0xa7a7f255,0x7e7e82fc,0x3d3d477a
	.long	0x6464acc8,0x5d5de7ba,0x19192b32,0x737395e6
	.long	0x6060a0c0,0x81819819,0x4f4fd19e,0xdcdc7fa3
	.long	0x22226644,0x2a2a7e54,0x9090ab3b,0x8888830b
	.long	0x4646ca8c,0xeeee29c7,0xb8b8d36b,0x14143c28
	.long	0xdede79a7,0x5e5ee2bc,0x0b0b1d16,0xdbdb76ad
	.long	0xe0e03bdb,0x32325664,0x3a3a4e74,0x0a0a1e14
	.long	0x4949db92,0x06060a0c,0x24246c48,0x5c5ce4b8
	.long	0xc2c25d9f,0xd3d36ebd,0xacacef43,0x6262a6c4
	.long	0x9191a839,0x9595a431,0xe4e437d3,0x79798bf2
	.long	0xe7e732d5,0xc8c8438b,0x3737596e,0x6d6db7da
	.long	0x8d8d8c01,0xd5d564b1,0x4e4ed29c,0xa9a9e049
	.long	0x6c6cb4d8,0x5656faac,0xf4f407f3,0xeaea25cf
	.long	0x6565afca,0x7a7a8ef4,0xaeaee947,0x08081810
	.long	0xbabad56f,0x787888f0,0x25256f4a,0x2e2e725c
	.long	0x1c1c2438,0xa6a6f157,0xb4b4c773,0xc6c65197
	.long	0xe8e823cb,0xdddd7ca1,0x74749ce8,0x1f1f213e
	.long	0x4b4bdd96,0xbdbddc61,0x8b8b860d,0x8a8a850f
	.long	0x707090e0,0x3e3e427c,0xb5b5c471,0x6666aacc
	.long	0x4848d890,0x03030506,0xf6f601f7,0x0e0e121c
	.long	0x6161a3c2,0x35355f6a,0x5757f9ae,0xb9b9d069
	.long	0x86869117,0xc1c15899,0x1d1d273a,0x9e9eb927
	.long	0xe1e138d9,0xf8f813eb,0x9898b32b,0x11113322
	.long	0x6969bbd2,0xd9d970a9,0x8e8e8907,0x9494a733
	.long	0x9b9bb62d,0x1e1e223c,0x87879215,0xe9e920c9
	.long	0xcece4987,0x5555ffaa,0x28287850,0xdfdf7aa5
	.long	0x8c8c8f03,0xa1a1f859,0x89898009,0x0d0d171a
	.long	0xbfbfda65,0xe6e631d7,0x4242c684,0x6868b8d0
	.long	0x4141c382,0x9999b029,0x2d2d775a,0x0f0f111e
	.long	0xb0b0cb7b,0x5454fca8,0xbbbbd66d,0x16163a2c
#if defined(HAVE_AESCCM) || defined(HAVE_AESGCM) || \
    defined(WOLFSSL_AES_DIRECT) || defined(WOLFSSL_AES_COUNTER) || \
    defined(HAVE_AES_ECB)
#ifndef __APPLE__
.text
.globl	AES_ECB_encrypt
.type	AES_ECB_encrypt,@function
.align	16
AES_ECB_encrypt:
#if defined(_CALL_ELF) && _CALL_ELF == 2
0:	addis	2, 12, .TOC.-0b@ha
	addi	2, 2, .TOC.-0b@l
	.localentry	AES_ECB_encrypt, .-AES_ECB_encrypt
#endif
#else
.section	__TEXT,__text
.globl	_AES_ECB_encrypt
.p2align	4
_AES_ECB_encrypt:
#endif /* __APPLE__ */
	stdu	1, -104(1)
	mflr	0
	std	0, 96(1)
	std	14, 0(1)
	std	15, 8(1)
	std	16, 16(1)
	std	17, 24(1)
	std	18, 32(1)
	std	19, 40(1)
	std	20, 48(1)
	std	21, 56(1)
	std	22, 64(1)
	std	23, 72(1)
	std	24, 80(1)
	std	25, 88(1)
	addis	8, 2, L_AES_PPC64_te4_0@toc@ha
	addi	8, 8, L_AES_PPC64_te4_0@toc@l
	addi	9, 8, 0x400
	addi	10, 8, 0x800
	addi	11, 8, 0xc00
L_AES_ECB_encrypt_loop_block_128:
	addi	25, 6, 0
	ld	12, 0(3)
	ld	14, 8(3)
	ld	17, 0(25)
	ld	18, 8(25)
	addi	25, 25, 16
	rldicr	12, 12, 32, 63
	rldicr	14, 14, 32, 63
	# Round: 0 - XOR in key schedule
	xor	12, 12, 17
	xor	14, 14, 18
	addi	0, 7, -2
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
	ld	20, 0(8)
	ld	20, 64(8)
	ld	20, 128(8)
	ld	20, 192(8)
	ld	20, 256(8)
	ld	20, 320(8)
	ld	20, 384(8)
	ld	20, 448(8)
	ld	20, 512(8)
	ld	20, 576(8)
	ld	20, 640(8)
	ld	20, 704(8)
	ld	20, 768(8)
	ld	20, 832(8)
	ld	20, 896(8)
	ld	20, 960(8)
	ld	20, 1024(8)
	ld	20, 1088(8)
	ld	20, 1152(8)
	ld	20, 1216(8)
	ld	20, 1280(8)
	ld	20, 1344(8)
	ld	20, 1408(8)
	ld	20, 1472(8)
	ld	20, 1536(8)
	ld	20, 1600(8)
	ld	20, 1664(8)
	ld	20, 1728(8)
	ld	20, 1792(8)
	ld	20, 1856(8)
	ld	20, 1920(8)
	ld	20, 1984(8)
	ld	20, 2048(8)
	ld	20, 2112(8)
	ld	20, 2176(8)
	ld	20, 2240(8)
	ld	20, 2304(8)
	ld	20, 2368(8)
	ld	20, 2432(8)
	ld	20, 2496(8)
	ld	20, 2560(8)
	ld	20, 2624(8)
	ld	20, 2688(8)
	ld	20, 2752(8)
	ld	20, 2816(8)
	ld	20, 2880(8)
	ld	20, 2944(8)
	ld	20, 3008(8)
	ld	20, 3072(8)
	ld	20, 3136(8)
	ld	20, 3200(8)
	ld	20, 3264(8)
	ld	20, 3328(8)
	ld	20, 3392(8)
	ld	20, 3456(8)
	ld	20, 3520(8)
	ld	20, 3584(8)
	ld	20, 3648(8)
	ld	20, 3712(8)
	ld	20, 3776(8)
	ld	20, 3840(8)
	ld	20, 3904(8)
	ld	20, 3968(8)
	ld	20, 4032(8)
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
	srwi	0, 0, 1
	mtctr	0
L_AES_ECB_encrypt_loop_nr:
	srdi	15, 12, 32
	srdi	16, 14, 32
	rlwinm	17, 12, 10, 22, 29
	rlwinm	18, 14, 10, 22, 29
	rlwinm	19, 15, 10, 22, 29
	rlwinm	20, 16, 10, 22, 29
	lwzx	17, 8, 17
	lwzx	18, 8, 18
	lwzx	19, 8, 19
	lwzx	20, 8, 20
	rlwinm	21, 15, 18, 22, 29
	rlwinm	22, 14, 18, 22, 29
	rlwinm	23, 16, 18, 22, 29
	rlwinm	24, 12, 18, 22, 29
	lwzx	21, 9, 21
	lwzx	22, 9, 22
	lwzx	23, 9, 23
	lwzx	24, 9, 24
	xor	17, 17, 21
	xor	19, 19, 22
	xor	18, 18, 23
	xor	20, 20, 24
	rlwinm	21, 14, 26, 22, 29
	rlwinm	22, 16, 26, 22, 29
	rlwinm	23, 12, 26, 22, 29
	rlwinm	24, 15, 26, 22, 29
	lwzx	21, 10, 21
	lwzx	22, 10, 22
	lwzx	23, 10, 23
	lwzx	24, 10, 24
	xor	17, 17, 21
	xor	19, 19, 22
	xor	18, 18, 23
	xor	20, 20, 24
	rlwinm	21, 16, 2, 22, 29
	rlwinm	22, 12, 2, 22, 29
	rlwinm	23, 15, 2, 22, 29
	rlwinm	24, 14, 2, 22, 29
	lwzx	21, 11, 21
	lwzx	22, 11, 22
	lwzx	23, 11, 23
	lwzx	24, 11, 24
	xor	17, 17, 21
	xor	19, 19, 22
	xor	18, 18, 23
	xor	20, 20, 24
	ld	12, 0(25)
	ld	14, 8(25)
	rldimi	17, 19, 32, 0
	rldimi	18, 20, 32, 0
	addi	25, 25, 16
	#   XOR in Key Schedule
	xor	17, 17, 12
	xor	18, 18, 14
	srdi	19, 17, 32
	srdi	20, 18, 32
	rlwinm	12, 17, 10, 22, 29
	rlwinm	14, 18, 10, 22, 29
	rlwinm	15, 19, 10, 22, 29
	rlwinm	16, 20, 10, 22, 29
	lwzx	12, 8, 12
	lwzx	14, 8, 14
	lwzx	15, 8, 15
	lwzx	16, 8, 16
	rlwinm	21, 19, 18, 22, 29
	rlwinm	22, 18, 18, 22, 29
	rlwinm	23, 20, 18, 22, 29
	rlwinm	24, 17, 18, 22, 29
	lwzx	21, 9, 21
	lwzx	22, 9, 22
	lwzx	23, 9, 23
	lwzx	24, 9, 24
	xor	12, 12, 21
	xor	15, 15, 22
	xor	14, 14, 23
	xor	16, 16, 24
	rlwinm	21, 18, 26, 22, 29
	rlwinm	22, 20, 26, 22, 29
	rlwinm	23, 17, 26, 22, 29
	rlwinm	24, 19, 26, 22, 29
	lwzx	21, 10, 21
	lwzx	22, 10, 22
	lwzx	23, 10, 23
	lwzx	24, 10, 24
	xor	12, 12, 21
	xor	15, 15, 22
	xor	14, 14, 23
	xor	16, 16, 24
	rlwinm	21, 20, 2, 22, 29
	rlwinm	22, 17, 2, 22, 29
	rlwinm	23, 19, 2, 22, 29
	rlwinm	24, 18, 2, 22, 29
	lwzx	21, 11, 21
	lwzx	22, 11, 22
	lwzx	23, 11, 23
	lwzx	24, 11, 24
	xor	12, 12, 21
	xor	15, 15, 22
	xor	14, 14, 23
	xor	16, 16, 24
	ld	17, 0(25)
	ld	18, 8(25)
	rldimi	12, 15, 32, 0
	rldimi	14, 16, 32, 0
	addi	25, 25, 16
	#   XOR in Key Schedule
	xor	12, 12, 17
	xor	14, 14, 18
	bdnz	L_AES_ECB_encrypt_loop_nr
	srdi	15, 12, 32
	srdi	16, 14, 32
	rlwinm	17, 12, 10, 22, 29
	rlwinm	18, 14, 10, 22, 29
	rlwinm	19, 15, 10, 22, 29
	rlwinm	20, 16, 10, 22, 29
	lwzx	17, 8, 17
	lwzx	18, 8, 18
	lwzx	19, 8, 19
	lwzx	20, 8, 20
	rlwinm	21, 15, 18, 22, 29
	rlwinm	22, 14, 18, 22, 29
	rlwinm	23, 16, 18, 22, 29
	rlwinm	24, 12, 18, 22, 29
	lwzx	21, 9, 21
	lwzx	22, 9, 22
	lwzx	23, 9, 23
	lwzx	24, 9, 24
	xor	17, 17, 21
	xor	19, 19, 22
	xor	18, 18, 23
	xor	20, 20, 24
	rlwinm	21, 14, 26, 22, 29
	rlwinm	22, 16, 26, 22, 29
	rlwinm	23, 12, 26, 22, 29
	rlwinm	24, 15, 26, 22, 29
	lwzx	21, 10, 21
	lwzx	22, 10, 22
	lwzx	23, 10, 23
	lwzx	24, 10, 24
	xor	17, 17, 21
	xor	19, 19, 22
	xor	18, 18, 23
	xor	20, 20, 24
	rlwinm	21, 16, 2, 22, 29
	rlwinm	22, 12, 2, 22, 29
	rlwinm	23, 15, 2, 22, 29
	rlwinm	24, 14, 2, 22, 29
	lwzx	21, 11, 21
	lwzx	22, 11, 22
	lwzx	23, 11, 23
	lwzx	24, 11, 24
	xor	17, 17, 21
	xor	19, 19, 22
	xor	18, 18, 23
	xor	20, 20, 24
	ld	12, 0(25)
	ld	14, 8(25)
	rldimi	17, 19, 32, 0
	rldimi	18, 20, 32, 0
	addi	25, 25, 16
	#   XOR in Key Schedule
	xor	17, 17, 12
	xor	18, 18, 14
	srdi	19, 17, 32
	srdi	20, 18, 32
	rlwinm	12, 17, 2, 22, 29
	rlwinm	14, 18, 2, 22, 29
	rlwinm	16, 19, 2, 22, 29
	rlwinm	15, 20, 2, 22, 29
	lwzx	12, 9, 12
	lwzx	14, 9, 14
	lwzx	16, 9, 16
	lwzx	15, 9, 15
	rlwinm	21, 18, 26, 22, 29
	rlwinm	22, 20, 26, 22, 29
	rldimi	14, 16, 32, 24
	rldimi	12, 15, 32, 24
	rlwinm	23, 17, 26, 22, 29
	rlwinm	24, 19, 26, 22, 29
	lwzx	21, 9, 21
	lwzx	22, 9, 22
	lwzx	23, 9, 23
	lwzx	24, 9, 24
	rldimi	12, 21, 40, 16
	rlwimi	12, 22, 8, 16, 23
	rldimi	14, 23, 40, 16
	rlwimi	14, 24, 8, 16, 23
	rlwinm	21, 19, 18, 22, 29
	rlwinm	22, 18, 18, 22, 29
	rlwinm	23, 20, 18, 22, 29
	rlwinm	24, 17, 18, 22, 29
	lwzx	21, 9, 21
	lwzx	22, 9, 22
	lwzx	23, 9, 23
	lwzx	24, 9, 24
	rldimi	12, 21, 48, 8
	rlwimi	12, 22, 16, 8, 15
	rldimi	14, 23, 48, 8
	rlwimi	14, 24, 16, 8, 15
	rlwinm	21, 17, 10, 22, 29
	rlwinm	22, 19, 10, 22, 29
	rlwinm	23, 18, 10, 22, 29
	rlwinm	24, 20, 10, 22, 29
	lwzx	21, 9, 21
	lwzx	22, 9, 22
	lwzx	23, 9, 23
	lwzx	24, 9, 24
	ld	17, 0(25)
	ld	18, 8(25)
	rldimi	12, 21, 56, 0
	rlwimi	12, 22, 24, 0, 7
	rldimi	14, 23, 56, 0
	rlwimi	14, 24, 24, 0, 7
	addi	25, 25, 16
	#   XOR in Key Schedule
	xor	12, 12, 17
	xor	14, 14, 18
	std	12, 0(4)
	std	14, 8(4)
	addi	3, 3, 16
	addi	4, 4, 16
	addic.	5, 5, -16
	bne	L_AES_ECB_encrypt_loop_block_128
	ld	0, 96(1)
	mtlr	0
	ld	14, 0(1)
	ld	15, 8(1)
	ld	16, 16(1)
	ld	17, 24(1)
	ld	18, 32(1)
	ld	19, 40(1)
	ld	20, 48(1)
	ld	21, 56(1)
	ld	22, 64(1)
	ld	23, 72(1)
	ld	24, 80(1)
	ld	25, 88(1)
	addi	1, 1, 0x68
	blr
#ifndef __APPLE__
	.size	AES_ECB_encrypt,.-AES_ECB_encrypt
#endif /* __APPLE__ */
#endif /* HAVE_AESCCM || HAVE_AESGCM || WOLFSSL_AES_DIRECT ||
        * WOLFSSL_AES_COUNTER || HAVE_AES_ECB */
#ifdef HAVE_AES_CBC
#ifndef __APPLE__
.text
.globl	AES_CBC_encrypt
.type	AES_CBC_encrypt,@function
.align	16
AES_CBC_encrypt:
#if defined(_CALL_ELF) && _CALL_ELF == 2
0:	addis	2, 12, .TOC.-0b@ha
	addi	2, 2, .TOC.-0b@l
	.localentry	AES_CBC_encrypt, .-AES_CBC_encrypt
#endif
#else
.section	__TEXT,__text
.globl	_AES_CBC_encrypt
.p2align	4
_AES_CBC_encrypt:
#endif /* __APPLE__ */
	stdu	1, -112(1)
	mflr	0
	std	0, 104(1)
	std	14, 0(1)
	std	15, 8(1)
	std	16, 16(1)
	std	17, 24(1)
	std	18, 32(1)
	std	19, 40(1)
	std	20, 48(1)
	std	21, 56(1)
	std	22, 64(1)
	std	23, 72(1)
	std	24, 80(1)
	std	25, 88(1)
	std	26, 96(1)
	addis	9, 2, L_AES_PPC64_te4_0@toc@ha
	addi	9, 9, L_AES_PPC64_te4_0@toc@l
	ld	14, 0(8)
	ld	15, 8(8)
	addi	10, 9, 0x400
	addi	11, 9, 0x800
	addi	12, 9, 0xc00
L_AES_CBC_encrypt_loop_block:
	addi	26, 6, 0
	ld	18, 0(3)
	ld	19, 8(3)
	xor	14, 14, 18
	xor	15, 15, 19
	ld	18, 0(26)
	ld	19, 8(26)
	addi	26, 26, 16
	rldicr	14, 14, 32, 63
	rldicr	15, 15, 32, 63
	# Round: 0 - XOR in key schedule
	xor	14, 14, 18
	xor	15, 15, 19
	addi	0, 7, -2
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
	ld	21, 0(9)
	ld	21, 64(9)
	ld	21, 128(9)
	ld	21, 192(9)
	ld	21, 256(9)
	ld	21, 320(9)
	ld	21, 384(9)
	ld	21, 448(9)
	ld	21, 512(9)
	ld	21, 576(9)
	ld	21, 640(9)
	ld	21, 704(9)
	ld	21, 768(9)
	ld	21, 832(9)
	ld	21, 896(9)
	ld	21, 960(9)
	ld	21, 1024(9)
	ld	21, 1088(9)
	ld	21, 1152(9)
	ld	21, 1216(9)
	ld	21, 1280(9)
	ld	21, 1344(9)
	ld	21, 1408(9)
	ld	21, 1472(9)
	ld	21, 1536(9)
	ld	21, 1600(9)
	ld	21, 1664(9)
	ld	21, 1728(9)
	ld	21, 1792(9)
	ld	21, 1856(9)
	ld	21, 1920(9)
	ld	21, 1984(9)
	ld	21, 2048(9)
	ld	21, 2112(9)
	ld	21, 2176(9)
	ld	21, 2240(9)
	ld	21, 2304(9)
	ld	21, 2368(9)
	ld	21, 2432(9)
	ld	21, 2496(9)
	ld	21, 2560(9)
	ld	21, 2624(9)
	ld	21, 2688(9)
	ld	21, 2752(9)
	ld	21, 2816(9)
	ld	21, 2880(9)
	ld	21, 2944(9)
	ld	21, 3008(9)
	ld	21, 3072(9)
	ld	21, 3136(9)
	ld	21, 3200(9)
	ld	21, 3264(9)
	ld	21, 3328(9)
	ld	21, 3392(9)
	ld	21, 3456(9)
	ld	21, 3520(9)
	ld	21, 3584(9)
	ld	21, 3648(9)
	ld	21, 3712(9)
	ld	21, 3776(9)
	ld	21, 3840(9)
	ld	21, 3904(9)
	ld	21, 3968(9)
	ld	21, 4032(9)
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
	srwi	0, 0, 1
	mtctr	0
L_AES_CBC_encrypt_loop_nr:
	srdi	16, 14, 32
	srdi	17, 15, 32
	rlwinm	18, 14, 10, 22, 29
	rlwinm	19, 15, 10, 22, 29
	rlwinm	20, 16, 10, 22, 29
	rlwinm	21, 17, 10, 22, 29
	lwzx	18, 9, 18
	lwzx	19, 9, 19
	lwzx	20, 9, 20
	lwzx	21, 9, 21
	rlwinm	22, 16, 18, 22, 29
	rlwinm	23, 15, 18, 22, 29
	rlwinm	24, 17, 18, 22, 29
	rlwinm	25, 14, 18, 22, 29
	lwzx	22, 10, 22
	lwzx	23, 10, 23
	lwzx	24, 10, 24
	lwzx	25, 10, 25
	xor	18, 18, 22
	xor	20, 20, 23
	xor	19, 19, 24
	xor	21, 21, 25
	rlwinm	22, 15, 26, 22, 29
	rlwinm	23, 17, 26, 22, 29
	rlwinm	24, 14, 26, 22, 29
	rlwinm	25, 16, 26, 22, 29
	lwzx	22, 11, 22
	lwzx	23, 11, 23
	lwzx	24, 11, 24
	lwzx	25, 11, 25
	xor	18, 18, 22
	xor	20, 20, 23
	xor	19, 19, 24
	xor	21, 21, 25
	rlwinm	22, 17, 2, 22, 29
	rlwinm	23, 14, 2, 22, 29
	rlwinm	24, 16, 2, 22, 29
	rlwinm	25, 15, 2, 22, 29
	lwzx	22, 12, 22
	lwzx	23, 12, 23
	lwzx	24, 12, 24
	lwzx	25, 12, 25
	xor	18, 18, 22
	xor	20, 20, 23
	xor	19, 19, 24
	xor	21, 21, 25
	ld	14, 0(26)
	ld	15, 8(26)
	rldimi	18, 20, 32, 0
	rldimi	19, 21, 32, 0
	addi	26, 26, 16
	#   XOR in Key Schedule
	xor	18, 18, 14
	xor	19, 19, 15
	srdi	20, 18, 32
	srdi	21, 19, 32
	rlwinm	14, 18, 10, 22, 29
	rlwinm	15, 19, 10, 22, 29
	rlwinm	16, 20, 10, 22, 29
	rlwinm	17, 21, 10, 22, 29
	lwzx	14, 9, 14
	lwzx	15, 9, 15
	lwzx	16, 9, 16
	lwzx	17, 9, 17
	rlwinm	22, 20, 18, 22, 29
	rlwinm	23, 19, 18, 22, 29
	rlwinm	24, 21, 18, 22, 29
	rlwinm	25, 18, 18, 22, 29
	lwzx	22, 10, 22
	lwzx	23, 10, 23
	lwzx	24, 10, 24
	lwzx	25, 10, 25
	xor	14, 14, 22
	xor	16, 16, 23
	xor	15, 15, 24
	xor	17, 17, 25
	rlwinm	22, 19, 26, 22, 29
	rlwinm	23, 21, 26, 22, 29
	rlwinm	24, 18, 26, 22, 29
	rlwinm	25, 20, 26, 22, 29
	lwzx	22, 11, 22
	lwzx	23, 11, 23
	lwzx	24, 11, 24
	lwzx	25, 11, 25
	xor	14, 14, 22
	xor	16, 16, 23
	xor	15, 15, 24
	xor	17, 17, 25
	rlwinm	22, 21, 2, 22, 29
	rlwinm	23, 18, 2, 22, 29
	rlwinm	24, 20, 2, 22, 29
	rlwinm	25, 19, 2, 22, 29
	lwzx	22, 12, 22
	lwzx	23, 12, 23
	lwzx	24, 12, 24
	lwzx	25, 12, 25
	xor	14, 14, 22
	xor	16, 16, 23
	xor	15, 15, 24
	xor	17, 17, 25
	ld	18, 0(26)
	ld	19, 8(26)
	rldimi	14, 16, 32, 0
	rldimi	15, 17, 32, 0
	addi	26, 26, 16
	#   XOR in Key Schedule
	xor	14, 14, 18
	xor	15, 15, 19
	bdnz	L_AES_CBC_encrypt_loop_nr
	srdi	16, 14, 32
	srdi	17, 15, 32
	rlwinm	18, 14, 10, 22, 29
	rlwinm	19, 15, 10, 22, 29
	rlwinm	20, 16, 10, 22, 29
	rlwinm	21, 17, 10, 22, 29
	lwzx	18, 9, 18
	lwzx	19, 9, 19
	lwzx	20, 9, 20
	lwzx	21, 9, 21
	rlwinm	22, 16, 18, 22, 29
	rlwinm	23, 15, 18, 22, 29
	rlwinm	24, 17, 18, 22, 29
	rlwinm	25, 14, 18, 22, 29
	lwzx	22, 10, 22
	lwzx	23, 10, 23
	lwzx	24, 10, 24
	lwzx	25, 10, 25
	xor	18, 18, 22
	xor	20, 20, 23
	xor	19, 19, 24
	xor	21, 21, 25
	rlwinm	22, 15, 26, 22, 29
	rlwinm	23, 17, 26, 22, 29
	rlwinm	24, 14, 26, 22, 29
	rlwinm	25, 16, 26, 22, 29
	lwzx	22, 11, 22
	lwzx	23, 11, 23
	lwzx	24, 11, 24
	lwzx	25, 11, 25
	xor	18, 18, 22
	xor	20, 20, 23
	xor	19, 19, 24
	xor	21, 21, 25
	rlwinm	22, 17, 2, 22, 29
	rlwinm	23, 14, 2, 22, 29
	rlwinm	24, 16, 2, 22, 29
	rlwinm	25, 15, 2, 22, 29
	lwzx	22, 12, 22
	lwzx	23, 12, 23
	lwzx	24, 12, 24
	lwzx	25, 12, 25
	xor	18, 18, 22
	xor	20, 20, 23
	xor	19, 19, 24
	xor	21, 21, 25
	ld	14, 0(26)
	ld	15, 8(26)
	rldimi	18, 20, 32, 0
	rldimi	19, 21, 32, 0
	addi	26, 26, 16
	#   XOR in Key Schedule
	xor	18, 18, 14
	xor	19, 19, 15
	srdi	20, 18, 32
	srdi	21, 19, 32
	rlwinm	14, 18, 2, 22, 29
	rlwinm	15, 19, 2, 22, 29
	rlwinm	17, 20, 2, 22, 29
	rlwinm	16, 21, 2, 22, 29
	lwzx	14, 10, 14
	lwzx	15, 10, 15
	lwzx	17, 10, 17
	lwzx	16, 10, 16
	rlwinm	22, 19, 26, 22, 29
	rlwinm	23, 21, 26, 22, 29
	rldimi	15, 17, 32, 24
	rldimi	14, 16, 32, 24
	rlwinm	24, 18, 26, 22, 29
	rlwinm	25, 20, 26, 22, 29
	lwzx	22, 10, 22
	lwzx	23, 10, 23
	lwzx	24, 10, 24
	lwzx	25, 10, 25
	rldimi	14, 22, 40, 16
	rlwimi	14, 23, 8, 16, 23
	rldimi	15, 24, 40, 16
	rlwimi	15, 25, 8, 16, 23
	rlwinm	22, 20, 18, 22, 29
	rlwinm	23, 19, 18, 22, 29
	rlwinm	24, 21, 18, 22, 29
	rlwinm	25, 18, 18, 22, 29
	lwzx	22, 10, 22
	lwzx	23, 10, 23
	lwzx	24, 10, 24
	lwzx	25, 10, 25
	rldimi	14, 22, 48, 8
	rlwimi	14, 23, 16, 8, 15
	rldimi	15, 24, 48, 8
	rlwimi	15, 25, 16, 8, 15
	rlwinm	22, 18, 10, 22, 29
	rlwinm	23, 20, 10, 22, 29
	rlwinm	24, 19, 10, 22, 29
	rlwinm	25, 21, 10, 22, 29
	lwzx	22, 10, 22
	lwzx	23, 10, 23
	lwzx	24, 10, 24
	lwzx	25, 10, 25
	ld	18, 0(26)
	ld	19, 8(26)
	rldimi	14, 22, 56, 0
	rlwimi	14, 23, 24, 0, 7
	rldimi	15, 24, 56, 0
	rlwimi	15, 25, 24, 0, 7
	addi	26, 26, 16
	#   XOR in Key Schedule
	xor	14, 14, 18
	xor	15, 15, 19
	std	14, 0(4)
	std	15, 8(4)
	addi	3, 3, 16
	addi	4, 4, 16
	addic.	5, 5, -16
	bne	L_AES_CBC_encrypt_loop_block
	std	14, 0(8)
	std	15, 8(8)
	ld	0, 104(1)
	mtlr	0
	ld	14, 0(1)
	ld	15, 8(1)
	ld	16, 16(1)
	ld	17, 24(1)
	ld	18, 32(1)
	ld	19, 40(1)
	ld	20, 48(1)
	ld	21, 56(1)
	ld	22, 64(1)
	ld	23, 72(1)
	ld	24, 80(1)
	ld	25, 88(1)
	ld	26, 96(1)
	addi	1, 1, 0x70
	blr
#ifndef __APPLE__
	.size	AES_CBC_encrypt,.-AES_CBC_encrypt
#endif /* __APPLE__ */
#endif /* HAVE_AES_CBC */
#ifdef WOLFSSL_AES_COUNTER
#ifndef __APPLE__
.text
.globl	AES_CTR_encrypt
.type	AES_CTR_encrypt,@function
.align	16
AES_CTR_encrypt:
#if defined(_CALL_ELF) && _CALL_ELF == 2
0:	addis	2, 12, .TOC.-0b@ha
	addi	2, 2, .TOC.-0b@l
	.localentry	AES_CTR_encrypt, .-AES_CTR_encrypt
#endif
#else
.section	__TEXT,__text
.globl	_AES_CTR_encrypt
.p2align	4
_AES_CTR_encrypt:
#endif /* __APPLE__ */
	stdu	1, -128(1)
	mflr	0
	std	0, 120(1)
	std	14, 0(1)
	std	15, 8(1)
	std	16, 16(1)
	std	17, 24(1)
	std	18, 32(1)
	std	19, 40(1)
	std	20, 48(1)
	std	21, 56(1)
	std	22, 64(1)
	std	23, 72(1)
	std	24, 80(1)
	std	25, 88(1)
	std	26, 96(1)
	std	27, 104(1)
	std	28, 112(1)
	addis	9, 2, L_AES_PPC64_te4_0@toc@ha
	addi	9, 9, L_AES_PPC64_te4_0@toc@l
	ld	22, 0(8)
	ld	23, 8(8)
	addi	10, 9, 0x400
	addi	11, 9, 0x800
	addi	12, 9, 0xc00
L_AES_CTR_encrypt_loop_block_128:
	addi	28, 6, 0
	ld	18, 0(28)
	ld	19, 8(28)
	addi	28, 28, 16
	rldicr	14, 22, 32, 63
	rldicr	15, 23, 32, 63
	# Round: 0 - XOR in key schedule
	xor	14, 14, 18
	xor	15, 15, 19
	addi	0, 7, -2
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
	ld	21, 0(9)
	ld	21, 64(9)
	ld	21, 128(9)
	ld	21, 192(9)
	ld	21, 256(9)
	ld	21, 320(9)
	ld	21, 384(9)
	ld	21, 448(9)
	ld	21, 512(9)
	ld	21, 576(9)
	ld	21, 640(9)
	ld	21, 704(9)
	ld	21, 768(9)
	ld	21, 832(9)
	ld	21, 896(9)
	ld	21, 960(9)
	ld	21, 1024(9)
	ld	21, 1088(9)
	ld	21, 1152(9)
	ld	21, 1216(9)
	ld	21, 1280(9)
	ld	21, 1344(9)
	ld	21, 1408(9)
	ld	21, 1472(9)
	ld	21, 1536(9)
	ld	21, 1600(9)
	ld	21, 1664(9)
	ld	21, 1728(9)
	ld	21, 1792(9)
	ld	21, 1856(9)
	ld	21, 1920(9)
	ld	21, 1984(9)
	ld	21, 2048(9)
	ld	21, 2112(9)
	ld	21, 2176(9)
	ld	21, 2240(9)
	ld	21, 2304(9)
	ld	21, 2368(9)
	ld	21, 2432(9)
	ld	21, 2496(9)
	ld	21, 2560(9)
	ld	21, 2624(9)
	ld	21, 2688(9)
	ld	21, 2752(9)
	ld	21, 2816(9)
	ld	21, 2880(9)
	ld	21, 2944(9)
	ld	21, 3008(9)
	ld	21, 3072(9)
	ld	21, 3136(9)
	ld	21, 3200(9)
	ld	21, 3264(9)
	ld	21, 3328(9)
	ld	21, 3392(9)
	ld	21, 3456(9)
	ld	21, 3520(9)
	ld	21, 3584(9)
	ld	21, 3648(9)
	ld	21, 3712(9)
	ld	21, 3776(9)
	ld	21, 3840(9)
	ld	21, 3904(9)
	ld	21, 3968(9)
	ld	21, 4032(9)
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
	srwi	0, 0, 1
	mtctr	0
L_AES_CTR_encrypt_loop_nr:
	srdi	16, 14, 32
	srdi	17, 15, 32
	rlwinm	18, 14, 10, 22, 29
	rlwinm	19, 15, 10, 22, 29
	rlwinm	20, 16, 10, 22, 29
	rlwinm	21, 17, 10, 22, 29
	lwzx	18, 9, 18
	lwzx	19, 9, 19
	lwzx	20, 9, 20
	lwzx	21, 9, 21
	rlwinm	24, 16, 18, 22, 29
	rlwinm	25, 15, 18, 22, 29
	rlwinm	26, 17, 18, 22, 29
	rlwinm	27, 14, 18, 22, 29
	lwzx	24, 10, 24
	lwzx	25, 10, 25
	lwzx	26, 10, 26
	lwzx	27, 10, 27
	xor	18, 18, 24
	xor	20, 20, 25
	xor	19, 19, 26
	xor	21, 21, 27
	rlwinm	24, 15, 26, 22, 29
	rlwinm	25, 17, 26, 22, 29
	rlwinm	26, 14, 26, 22, 29
	rlwinm	27, 16, 26, 22, 29
	lwzx	24, 11, 24
	lwzx	25, 11, 25
	lwzx	26, 11, 26
	lwzx	27, 11, 27
	xor	18, 18, 24
	xor	20, 20, 25
	xor	19, 19, 26
	xor	21, 21, 27
	rlwinm	24, 17, 2, 22, 29
	rlwinm	25, 14, 2, 22, 29
	rlwinm	26, 16, 2, 22, 29
	rlwinm	27, 15, 2, 22, 29
	lwzx	24, 12, 24
	lwzx	25, 12, 25
	lwzx	26, 12, 26
	lwzx	27, 12, 27
	xor	18, 18, 24
	xor	20, 20, 25
	xor	19, 19, 26
	xor	21, 21, 27
	ld	14, 0(28)
	ld	15, 8(28)
	rldimi	18, 20, 32, 0
	rldimi	19, 21, 32, 0
	addi	28, 28, 16
	#   XOR in Key Schedule
	xor	18, 18, 14
	xor	19, 19, 15
	srdi	20, 18, 32
	srdi	21, 19, 32
	rlwinm	14, 18, 10, 22, 29
	rlwinm	15, 19, 10, 22, 29
	rlwinm	16, 20, 10, 22, 29
	rlwinm	17, 21, 10, 22, 29
	lwzx	14, 9, 14
	lwzx	15, 9, 15
	lwzx	16, 9, 16
	lwzx	17, 9, 17
	rlwinm	24, 20, 18, 22, 29
	rlwinm	25, 19, 18, 22, 29
	rlwinm	26, 21, 18, 22, 29
	rlwinm	27, 18, 18, 22, 29
	lwzx	24, 10, 24
	lwzx	25, 10, 25
	lwzx	26, 10, 26
	lwzx	27, 10, 27
	xor	14, 14, 24
	xor	16, 16, 25
	xor	15, 15, 26
	xor	17, 17, 27
	rlwinm	24, 19, 26, 22, 29
	rlwinm	25, 21, 26, 22, 29
	rlwinm	26, 18, 26, 22, 29
	rlwinm	27, 20, 26, 22, 29
	lwzx	24, 11, 24
	lwzx	25, 11, 25
	lwzx	26, 11, 26
	lwzx	27, 11, 27
	xor	14, 14, 24
	xor	16, 16, 25
	xor	15, 15, 26
	xor	17, 17, 27
	rlwinm	24, 21, 2, 22, 29
	rlwinm	25, 18, 2, 22, 29
	rlwinm	26, 20, 2, 22, 29
	rlwinm	27, 19, 2, 22, 29
	lwzx	24, 12, 24
	lwzx	25, 12, 25
	lwzx	26, 12, 26
	lwzx	27, 12, 27
	xor	14, 14, 24
	xor	16, 16, 25
	xor	15, 15, 26
	xor	17, 17, 27
	ld	18, 0(28)
	ld	19, 8(28)
	rldimi	14, 16, 32, 0
	rldimi	15, 17, 32, 0
	addi	28, 28, 16
	#   XOR in Key Schedule
	xor	14, 14, 18
	xor	15, 15, 19
	bdnz	L_AES_CTR_encrypt_loop_nr
	srdi	16, 14, 32
	srdi	17, 15, 32
	rlwinm	18, 14, 10, 22, 29
	rlwinm	19, 15, 10, 22, 29
	rlwinm	20, 16, 10, 22, 29
	rlwinm	21, 17, 10, 22, 29
	lwzx	18, 9, 18
	lwzx	19, 9, 19
	lwzx	20, 9, 20
	lwzx	21, 9, 21
	rlwinm	24, 16, 18, 22, 29
	rlwinm	25, 15, 18, 22, 29
	rlwinm	26, 17, 18, 22, 29
	rlwinm	27, 14, 18, 22, 29
	lwzx	24, 10, 24
	lwzx	25, 10, 25
	lwzx	26, 10, 26
	lwzx	27, 10, 27
	xor	18, 18, 24
	xor	20, 20, 25
	xor	19, 19, 26
	xor	21, 21, 27
	rlwinm	24, 15, 26, 22, 29
	rlwinm	25, 17, 26, 22, 29
	rlwinm	26, 14, 26, 22, 29
	rlwinm	27, 16, 26, 22, 29
	lwzx	24, 11, 24
	lwzx	25, 11, 25
	lwzx	26, 11, 26
	lwzx	27, 11, 27
	xor	18, 18, 24
	xor	20, 20, 25
	xor	19, 19, 26
	xor	21, 21, 27
	rlwinm	24, 17, 2, 22, 29
	rlwinm	25, 14, 2, 22, 29
	rlwinm	26, 16, 2, 22, 29
	rlwinm	27, 15, 2, 22, 29
	lwzx	24, 12, 24
	lwzx	25, 12, 25
	lwzx	26, 12, 26
	lwzx	27, 12, 27
	xor	18, 18, 24
	xor	20, 20, 25
	xor	19, 19, 26
	xor	21, 21, 27
	ld	14, 0(28)
	ld	15, 8(28)
	rldimi	18, 20, 32, 0
	rldimi	19, 21, 32, 0
	addi	28, 28, 16
	#   XOR in Key Schedule
	xor	18, 18, 14
	xor	19, 19, 15
	srdi	20, 18, 32
	srdi	21, 19, 32
	rlwinm	14, 18, 2, 22, 29
	rlwinm	15, 19, 2, 22, 29
	rlwinm	17, 20, 2, 22, 29
	rlwinm	16, 21, 2, 22, 29
	lwzx	14, 10, 14
	lwzx	15, 10, 15
	lwzx	17, 10, 17
	lwzx	16, 10, 16
	rlwinm	24, 19, 26, 22, 29
	rlwinm	25, 21, 26, 22, 29
	rldimi	15, 17, 32, 24
	rldimi	14, 16, 32, 24
	rlwinm	26, 18, 26, 22, 29
	rlwinm	27, 20, 26, 22, 29
	lwzx	24, 10, 24
	lwzx	25, 10, 25
	lwzx	26, 10, 26
	lwzx	27, 10, 27
	rldimi	14, 24, 40, 16
	rlwimi	14, 25, 8, 16, 23
	rldimi	15, 26, 40, 16
	rlwimi	15, 27, 8, 16, 23
	rlwinm	24, 20, 18, 22, 29
	rlwinm	25, 19, 18, 22, 29
	rlwinm	26, 21, 18, 22, 29
	rlwinm	27, 18, 18, 22, 29
	lwzx	24, 10, 24
	lwzx	25, 10, 25
	lwzx	26, 10, 26
	lwzx	27, 10, 27
	rldimi	14, 24, 48, 8
	rlwimi	14, 25, 16, 8, 15
	rldimi	15, 26, 48, 8
	rlwimi	15, 27, 16, 8, 15
	rlwinm	24, 18, 10, 22, 29
	rlwinm	25, 20, 10, 22, 29
	rlwinm	26, 19, 10, 22, 29
	rlwinm	27, 21, 10, 22, 29
	lwzx	24, 10, 24
	lwzx	25, 10, 25
	lwzx	26, 10, 26
	lwzx	27, 10, 27
	ld	18, 0(28)
	ld	19, 8(28)
	rldimi	14, 24, 56, 0
	rlwimi	14, 25, 24, 0, 7
	rldimi	15, 26, 56, 0
	rlwimi	15, 27, 24, 0, 7
	addi	28, 28, 16
	#   XOR in Key Schedule
	xor	14, 14, 18
	xor	15, 15, 19
	ld	18, 0(3)
	ld	19, 8(3)
	xor	14, 14, 18
	xor	15, 15, 19
	std	14, 0(4)
	std	15, 8(4)
	addic	23, 23, 1
	addze	22, 22
	addi	3, 3, 16
	addi	4, 4, 16
	addic.	5, 5, -16
	bne	L_AES_CTR_encrypt_loop_block_128
	std	22, 0(8)
	std	23, 8(8)
	ld	0, 120(1)
	mtlr	0
	ld	14, 0(1)
	ld	15, 8(1)
	ld	16, 16(1)
	ld	17, 24(1)
	ld	18, 32(1)
	ld	19, 40(1)
	ld	20, 48(1)
	ld	21, 56(1)
	ld	22, 64(1)
	ld	23, 72(1)
	ld	24, 80(1)
	ld	25, 88(1)
	ld	26, 96(1)
	ld	27, 104(1)
	ld	28, 112(1)
	addi	1, 1, 0x80
	blr
#ifndef __APPLE__
	.size	AES_CTR_encrypt,.-AES_CTR_encrypt
#endif /* __APPLE__ */
#endif /* WOLFSSL_AES_COUNTER */
#ifdef HAVE_AESGCM
#ifndef __APPLE__
.text
.globl	AES_GCM_encrypt
.type	AES_GCM_encrypt,@function
.align	16
AES_GCM_encrypt:
#if defined(_CALL_ELF) && _CALL_ELF == 2
0:	addis	2, 12, .TOC.-0b@ha
	addi	2, 2, .TOC.-0b@l
	.localentry	AES_GCM_encrypt, .-AES_GCM_encrypt
#endif
#else
.section	__TEXT,__text
.globl	_AES_GCM_encrypt
.p2align	4
_AES_GCM_encrypt:
#endif /* __APPLE__ */
	stdu	1, -128(1)
	mflr	0
	std	0, 120(1)
	std	14, 0(1)
	std	15, 8(1)
	std	16, 16(1)
	std	17, 24(1)
	std	18, 32(1)
	std	19, 40(1)
	std	20, 48(1)
	std	21, 56(1)
	std	22, 64(1)
	std	23, 72(1)
	std	24, 80(1)
	std	25, 88(1)
	std	26, 96(1)
	std	27, 104(1)
	std	28, 112(1)
	addis	9, 2, L_AES_PPC64_te4_0@toc@ha
	addi	9, 9, L_AES_PPC64_te4_0@toc@l
	ld	26, 0(8)
	ld	27, 8(8)
	addi	10, 9, 0x400
	addi	11, 9, 0x800
	addi	12, 9, 0xc00
L_AES_GCM_encrypt_loop_block:
	addi	28, 6, 0
	addi	17, 27, 1
	ld	18, 0(28)
	ld	19, 8(28)
	addi	28, 28, 16
	rldimi	27, 17, 0, 32
	rldicr	14, 26, 32, 63
	rldicr	15, 27, 32, 63
	# Round: 0 - XOR in key schedule
	xor	14, 14, 18
	xor	15, 15, 19
	addi	0, 7, -2
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
	ld	21, 0(9)
	ld	21, 64(9)
	ld	21, 128(9)
	ld	21, 192(9)
	ld	21, 256(9)
	ld	21, 320(9)
	ld	21, 384(9)
	ld	21, 448(9)
	ld	21, 512(9)
	ld	21, 576(9)
	ld	21, 640(9)
	ld	21, 704(9)
	ld	21, 768(9)
	ld	21, 832(9)
	ld	21, 896(9)
	ld	21, 960(9)
	ld	21, 1024(9)
	ld	21, 1088(9)
	ld	21, 1152(9)
	ld	21, 1216(9)
	ld	21, 1280(9)
	ld	21, 1344(9)
	ld	21, 1408(9)
	ld	21, 1472(9)
	ld	21, 1536(9)
	ld	21, 1600(9)
	ld	21, 1664(9)
	ld	21, 1728(9)
	ld	21, 1792(9)
	ld	21, 1856(9)
	ld	21, 1920(9)
	ld	21, 1984(9)
	ld	21, 2048(9)
	ld	21, 2112(9)
	ld	21, 2176(9)
	ld	21, 2240(9)
	ld	21, 2304(9)
	ld	21, 2368(9)
	ld	21, 2432(9)
	ld	21, 2496(9)
	ld	21, 2560(9)
	ld	21, 2624(9)
	ld	21, 2688(9)
	ld	21, 2752(9)
	ld	21, 2816(9)
	ld	21, 2880(9)
	ld	21, 2944(9)
	ld	21, 3008(9)
	ld	21, 3072(9)
	ld	21, 3136(9)
	ld	21, 3200(9)
	ld	21, 3264(9)
	ld	21, 3328(9)
	ld	21, 3392(9)
	ld	21, 3456(9)
	ld	21, 3520(9)
	ld	21, 3584(9)
	ld	21, 3648(9)
	ld	21, 3712(9)
	ld	21, 3776(9)
	ld	21, 3840(9)
	ld	21, 3904(9)
	ld	21, 3968(9)
	ld	21, 4032(9)
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
	srwi	0, 0, 1
	mtctr	0
L_AES_GCM_encrypt_loop_nr:
	srdi	16, 14, 32
	srdi	17, 15, 32
	rlwinm	18, 14, 10, 22, 29
	rlwinm	19, 15, 10, 22, 29
	rlwinm	20, 16, 10, 22, 29
	rlwinm	21, 17, 10, 22, 29
	lwzx	18, 9, 18
	lwzx	19, 9, 19
	lwzx	20, 9, 20
	lwzx	21, 9, 21
	rlwinm	22, 16, 18, 22, 29
	rlwinm	23, 15, 18, 22, 29
	rlwinm	24, 17, 18, 22, 29
	rlwinm	25, 14, 18, 22, 29
	lwzx	22, 10, 22
	lwzx	23, 10, 23
	lwzx	24, 10, 24
	lwzx	25, 10, 25
	xor	18, 18, 22
	xor	20, 20, 23
	xor	19, 19, 24
	xor	21, 21, 25
	rlwinm	22, 15, 26, 22, 29
	rlwinm	23, 17, 26, 22, 29
	rlwinm	24, 14, 26, 22, 29
	rlwinm	25, 16, 26, 22, 29
	lwzx	22, 11, 22
	lwzx	23, 11, 23
	lwzx	24, 11, 24
	lwzx	25, 11, 25
	xor	18, 18, 22
	xor	20, 20, 23
	xor	19, 19, 24
	xor	21, 21, 25
	rlwinm	22, 17, 2, 22, 29
	rlwinm	23, 14, 2, 22, 29
	rlwinm	24, 16, 2, 22, 29
	rlwinm	25, 15, 2, 22, 29
	lwzx	22, 12, 22
	lwzx	23, 12, 23
	lwzx	24, 12, 24
	lwzx	25, 12, 25
	xor	18, 18, 22
	xor	20, 20, 23
	xor	19, 19, 24
	xor	21, 21, 25
	ld	14, 0(28)
	ld	15, 8(28)
	rldimi	18, 20, 32, 0
	rldimi	19, 21, 32, 0
	addi	28, 28, 16
	#   XOR in Key Schedule
	xor	18, 18, 14
	xor	19, 19, 15
	srdi	20, 18, 32
	srdi	21, 19, 32
	rlwinm	14, 18, 10, 22, 29
	rlwinm	15, 19, 10, 22, 29
	rlwinm	16, 20, 10, 22, 29
	rlwinm	17, 21, 10, 22, 29
	lwzx	14, 9, 14
	lwzx	15, 9, 15
	lwzx	16, 9, 16
	lwzx	17, 9, 17
	rlwinm	22, 20, 18, 22, 29
	rlwinm	23, 19, 18, 22, 29
	rlwinm	24, 21, 18, 22, 29
	rlwinm	25, 18, 18, 22, 29
	lwzx	22, 10, 22
	lwzx	23, 10, 23
	lwzx	24, 10, 24
	lwzx	25, 10, 25
	xor	14, 14, 22
	xor	16, 16, 23
	xor	15, 15, 24
	xor	17, 17, 25
	rlwinm	22, 19, 26, 22, 29
	rlwinm	23, 21, 26, 22, 29
	rlwinm	24, 18, 26, 22, 29
	rlwinm	25, 20, 26, 22, 29
	lwzx	22, 11, 22
	lwzx	23, 11, 23
	lwzx	24, 11, 24
	lwzx	25, 11, 25
	xor	14, 14, 22
	xor	16, 16, 23
	xor	15, 15, 24
	xor	17, 17, 25
	rlwinm	22, 21, 2, 22, 29
	rlwinm	23, 18, 2, 22, 29
	rlwinm	24, 20, 2, 22, 29
	rlwinm	25, 19, 2, 22, 29
	lwzx	22, 12, 22
	lwzx	23, 12, 23
	lwzx	24, 12, 24
	lwzx	25, 12, 25
	xor	14, 14, 22
	xor	16, 16, 23
	xor	15, 15, 24
	xor	17, 17, 25
	ld	18, 0(28)
	ld	19, 8(28)
	rldimi	14, 16, 32, 0
	rldimi	15, 17, 32, 0
	addi	28, 28, 16
	#   XOR in Key Schedule
	xor	14, 14, 18
	xor	15, 15, 19
	bdnz	L_AES_GCM_encrypt_loop_nr
	srdi	16, 14, 32
	srdi	17, 15, 32
	rlwinm	18, 14, 10, 22, 29
	rlwinm	19, 15, 10, 22, 29
	rlwinm	20, 16, 10, 22, 29
	rlwinm	21, 17, 10, 22, 29
	lwzx	18, 9, 18
	lwzx	19, 9, 19
	lwzx	20, 9, 20
	lwzx	21, 9, 21
	rlwinm	22, 16, 18, 22, 29
	rlwinm	23, 15, 18, 22, 29
	rlwinm	24, 17, 18, 22, 29
	rlwinm	25, 14, 18, 22, 29
	lwzx	22, 10, 22
	lwzx	23, 10, 23
	lwzx	24, 10, 24
	lwzx	25, 10, 25
	xor	18, 18, 22
	xor	20, 20, 23
	xor	19, 19, 24
	xor	21, 21, 25
	rlwinm	22, 15, 26, 22, 29
	rlwinm	23, 17, 26, 22, 29
	rlwinm	24, 14, 26, 22, 29
	rlwinm	25, 16, 26, 22, 29
	lwzx	22, 11, 22
	lwzx	23, 11, 23
	lwzx	24, 11, 24
	lwzx	25, 11, 25
	xor	18, 18, 22
	xor	20, 20, 23
	xor	19, 19, 24
	xor	21, 21, 25
	rlwinm	22, 17, 2, 22, 29
	rlwinm	23, 14, 2, 22, 29
	rlwinm	24, 16, 2, 22, 29
	rlwinm	25, 15, 2, 22, 29
	lwzx	22, 12, 22
	lwzx	23, 12, 23
	lwzx	24, 12, 24
	lwzx	25, 12, 25
	xor	18, 18, 22
	xor	20, 20, 23
	xor	19, 19, 24
	xor	21, 21, 25
	ld	14, 0(28)
	ld	15, 8(28)
	rldimi	18, 20, 32, 0
	rldimi	19, 21, 32, 0
	addi	28, 28, 16
	#   XOR in Key Schedule
	xor	18, 18, 14
	xor	19, 19, 15
	srdi	20, 18, 32
	srdi	21, 19, 32
	rlwinm	14, 18, 2, 22, 29
	rlwinm	15, 19, 2, 22, 29
	rlwinm	17, 20, 2, 22, 29
	rlwinm	16, 21, 2, 22, 29
	lwzx	14, 10, 14
	lwzx	15, 10, 15
	lwzx	17, 10, 17
	lwzx	16, 10, 16
	rlwinm	22, 19, 26, 22, 29
	rlwinm	23, 21, 26, 22, 29
	rldimi	15, 17, 32, 24
	rldimi	14, 16, 32, 24
	rlwinm	24, 18, 26, 22, 29
	rlwinm	25, 20, 26, 22, 29
	lwzx	22, 10, 22
	lwzx	23, 10, 23
	lwzx	24, 10, 24
	lwzx	25, 10, 25
	rldimi	14, 22, 40, 16
	rlwimi	14, 23, 8, 16, 23
	rldimi	15, 24, 40, 16
	rlwimi	15, 25, 8, 16, 23
	rlwinm	22, 20, 18, 22, 29
	rlwinm	23, 19, 18, 22, 29
	rlwinm	24, 21, 18, 22, 29
	rlwinm	25, 18, 18, 22, 29
	lwzx	22, 10, 22
	lwzx	23, 10, 23
	lwzx	24, 10, 24
	lwzx	25, 10, 25
	rldimi	14, 22, 48, 8
	rlwimi	14, 23, 16, 8, 15
	rldimi	15, 24, 48, 8
	rlwimi	15, 25, 16, 8, 15
	rlwinm	22, 18, 10, 22, 29
	rlwinm	23, 20, 10, 22, 29
	rlwinm	24, 19, 10, 22, 29
	rlwinm	25, 21, 10, 22, 29
	lwzx	22, 10, 22
	lwzx	23, 10, 23
	lwzx	24, 10, 24
	lwzx	25, 10, 25
	ld	18, 0(28)
	ld	19, 8(28)
	rldimi	14, 22, 56, 0
	rlwimi	14, 23, 24, 0, 7
	rldimi	15, 24, 56, 0
	rlwimi	15, 25, 24, 0, 7
	addi	28, 28, 16
	#   XOR in Key Schedule
	xor	14, 14, 18
	xor	15, 15, 19
	ld	18, 0(3)
	ld	19, 8(3)
	addi	3, 3, 16
	addic.	5, 5, -16
	xor	14, 14, 18
	xor	15, 15, 19
	std	14, 0(4)
	std	15, 8(4)
	addi	4, 4, 16
	bne	L_AES_GCM_encrypt_loop_block
	std	26, 0(8)
	std	27, 8(8)
	ld	0, 120(1)
	mtlr	0
	ld	14, 0(1)
	ld	15, 8(1)
	ld	16, 16(1)
	ld	17, 24(1)
	ld	18, 32(1)
	ld	19, 40(1)
	ld	20, 48(1)
	ld	21, 56(1)
	ld	22, 64(1)
	ld	23, 72(1)
	ld	24, 80(1)
	ld	25, 88(1)
	ld	26, 96(1)
	ld	27, 104(1)
	ld	28, 112(1)
	addi	1, 1, 0x80
	blr
#ifndef __APPLE__
	.size	AES_GCM_encrypt,.-AES_GCM_encrypt
#endif /* __APPLE__ */
#endif /* HAVE_AESGCM */
#ifdef WOLFSSL_AES_XTS
#ifndef __APPLE__
.text
.globl	AES_XTS_encrypt
.type	AES_XTS_encrypt,@function
.align	16
AES_XTS_encrypt:
#if defined(_CALL_ELF) && _CALL_ELF == 2
0:	addis	2, 12, .TOC.-0b@ha
	addi	2, 2, .TOC.-0b@l
	.localentry	AES_XTS_encrypt, .-AES_XTS_encrypt
#endif
#else
.section	__TEXT,__text
.globl	_AES_XTS_encrypt
.p2align	4
_AES_XTS_encrypt:
#endif /* __APPLE__ */
	stdu	1, -136(1)
	mflr	0
	std	0, 128(1)
	std	14, 0(1)
	std	15, 8(1)
	std	16, 16(1)
	std	17, 24(1)
	std	18, 32(1)
	std	19, 40(1)
	std	20, 48(1)
	std	21, 56(1)
	std	22, 64(1)
	std	23, 72(1)
	std	24, 80(1)
	std	25, 88(1)
	std	26, 96(1)
	std	27, 104(1)
	std	28, 112(1)
	std	29, 120(1)
	addis	11, 2, L_AES_PPC64_te4_0@toc@ha
	addi	11, 11, L_AES_PPC64_te4_0@toc@l
	addi	12, 11, 0x400
	addi	14, 11, 0x800
	addi	15, 11, 0xc00
	ld	28, 0(6)
	ld	29, 8(6)
	ld	20, 0(8)
	ld	21, 8(8)
	addi	8, 8, 16
	rldicr	28, 28, 32, 63
	rldicr	29, 29, 32, 63
	# Round: 0 - XOR in key schedule
	xor	28, 28, 20
	xor	29, 29, 21
	addi	0, 10, -2
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
	ld	23, 0(11)
	ld	23, 64(11)
	ld	23, 128(11)
	ld	23, 192(11)
	ld	23, 256(11)
	ld	23, 320(11)
	ld	23, 384(11)
	ld	23, 448(11)
	ld	23, 512(11)
	ld	23, 576(11)
	ld	23, 640(11)
	ld	23, 704(11)
	ld	23, 768(11)
	ld	23, 832(11)
	ld	23, 896(11)
	ld	23, 960(11)
	ld	23, 1024(11)
	ld	23, 1088(11)
	ld	23, 1152(11)
	ld	23, 1216(11)
	ld	23, 1280(11)
	ld	23, 1344(11)
	ld	23, 1408(11)
	ld	23, 1472(11)
	ld	23, 1536(11)
	ld	23, 1600(11)
	ld	23, 1664(11)
	ld	23, 1728(11)
	ld	23, 1792(11)
	ld	23, 1856(11)
	ld	23, 1920(11)
	ld	23, 1984(11)
	ld	23, 2048(11)
	ld	23, 2112(11)
	ld	23, 2176(11)
	ld	23, 2240(11)
	ld	23, 2304(11)
	ld	23, 2368(11)
	ld	23, 2432(11)
	ld	23, 2496(11)
	ld	23, 2560(11)
	ld	23, 2624(11)
	ld	23, 2688(11)
	ld	23, 2752(11)
	ld	23, 2816(11)
	ld	23, 2880(11)
	ld	23, 2944(11)
	ld	23, 3008(11)
	ld	23, 3072(11)
	ld	23, 3136(11)
	ld	23, 3200(11)
	ld	23, 3264(11)
	ld	23, 3328(11)
	ld	23, 3392(11)
	ld	23, 3456(11)
	ld	23, 3520(11)
	ld	23, 3584(11)
	ld	23, 3648(11)
	ld	23, 3712(11)
	ld	23, 3776(11)
	ld	23, 3840(11)
	ld	23, 3904(11)
	ld	23, 3968(11)
	ld	23, 4032(11)
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
	srwi	0, 0, 1
	mtctr	0
L_AES_XTS_encrypt_loop_nr_tweak:
	srdi	18, 28, 32
	srdi	19, 29, 32
	rlwinm	20, 28, 10, 22, 29
	rlwinm	21, 29, 10, 22, 29
	rlwinm	22, 18, 10, 22, 29
	rlwinm	23, 19, 10, 22, 29
	lwzx	20, 11, 20
	lwzx	21, 11, 21
	lwzx	22, 11, 22
	lwzx	23, 11, 23
	rlwinm	24, 18, 18, 22, 29
	rlwinm	25, 29, 18, 22, 29
	rlwinm	26, 19, 18, 22, 29
	rlwinm	27, 28, 18, 22, 29
	lwzx	24, 12, 24
	lwzx	25, 12, 25
	lwzx	26, 12, 26
	lwzx	27, 12, 27
	xor	20, 20, 24
	xor	22, 22, 25
	xor	21, 21, 26
	xor	23, 23, 27
	rlwinm	24, 29, 26, 22, 29
	rlwinm	25, 19, 26, 22, 29
	rlwinm	26, 28, 26, 22, 29
	rlwinm	27, 18, 26, 22, 29
	lwzx	24, 14, 24
	lwzx	25, 14, 25
	lwzx	26, 14, 26
	lwzx	27, 14, 27
	xor	20, 20, 24
	xor	22, 22, 25
	xor	21, 21, 26
	xor	23, 23, 27
	rlwinm	24, 19, 2, 22, 29
	rlwinm	25, 28, 2, 22, 29
	rlwinm	26, 18, 2, 22, 29
	rlwinm	27, 29, 2, 22, 29
	lwzx	24, 15, 24
	lwzx	25, 15, 25
	lwzx	26, 15, 26
	lwzx	27, 15, 27
	xor	20, 20, 24
	xor	22, 22, 25
	xor	21, 21, 26
	xor	23, 23, 27
	ld	28, 0(8)
	ld	29, 8(8)
	rldimi	20, 22, 32, 0
	rldimi	21, 23, 32, 0
	addi	8, 8, 16
	#   XOR in Key Schedule
	xor	20, 20, 28
	xor	21, 21, 29
	srdi	22, 20, 32
	srdi	23, 21, 32
	rlwinm	28, 20, 10, 22, 29
	rlwinm	29, 21, 10, 22, 29
	rlwinm	18, 22, 10, 22, 29
	rlwinm	19, 23, 10, 22, 29
	lwzx	28, 11, 28
	lwzx	29, 11, 29
	lwzx	18, 11, 18
	lwzx	19, 11, 19
	rlwinm	24, 22, 18, 22, 29
	rlwinm	25, 21, 18, 22, 29
	rlwinm	26, 23, 18, 22, 29
	rlwinm	27, 20, 18, 22, 29
	lwzx	24, 12, 24
	lwzx	25, 12, 25
	lwzx	26, 12, 26
	lwzx	27, 12, 27
	xor	28, 28, 24
	xor	18, 18, 25
	xor	29, 29, 26
	xor	19, 19, 27
	rlwinm	24, 21, 26, 22, 29
	rlwinm	25, 23, 26, 22, 29
	rlwinm	26, 20, 26, 22, 29
	rlwinm	27, 22, 26, 22, 29
	lwzx	24, 14, 24
	lwzx	25, 14, 25
	lwzx	26, 14, 26
	lwzx	27, 14, 27
	xor	28, 28, 24
	xor	18, 18, 25
	xor	29, 29, 26
	xor	19, 19, 27
	rlwinm	24, 23, 2, 22, 29
	rlwinm	25, 20, 2, 22, 29
	rlwinm	26, 22, 2, 22, 29
	rlwinm	27, 21, 2, 22, 29
	lwzx	24, 15, 24
	lwzx	25, 15, 25
	lwzx	26, 15, 26
	lwzx	27, 15, 27
	xor	28, 28, 24
	xor	18, 18, 25
	xor	29, 29, 26
	xor	19, 19, 27
	ld	20, 0(8)
	ld	21, 8(8)
	rldimi	28, 18, 32, 0
	rldimi	29, 19, 32, 0
	addi	8, 8, 16
	#   XOR in Key Schedule
	xor	28, 28, 20
	xor	29, 29, 21
	bdnz	L_AES_XTS_encrypt_loop_nr_tweak
	srdi	18, 28, 32
	srdi	19, 29, 32
	rlwinm	20, 28, 10, 22, 29
	rlwinm	21, 29, 10, 22, 29
	rlwinm	22, 18, 10, 22, 29
	rlwinm	23, 19, 10, 22, 29
	lwzx	20, 11, 20
	lwzx	21, 11, 21
	lwzx	22, 11, 22
	lwzx	23, 11, 23
	rlwinm	24, 18, 18, 22, 29
	rlwinm	25, 29, 18, 22, 29
	rlwinm	26, 19, 18, 22, 29
	rlwinm	27, 28, 18, 22, 29
	lwzx	24, 12, 24
	lwzx	25, 12, 25
	lwzx	26, 12, 26
	lwzx	27, 12, 27
	xor	20, 20, 24
	xor	22, 22, 25
	xor	21, 21, 26
	xor	23, 23, 27
	rlwinm	24, 29, 26, 22, 29
	rlwinm	25, 19, 26, 22, 29
	rlwinm	26, 28, 26, 22, 29
	rlwinm	27, 18, 26, 22, 29
	lwzx	24, 14, 24
	lwzx	25, 14, 25
	lwzx	26, 14, 26
	lwzx	27, 14, 27
	xor	20, 20, 24
	xor	22, 22, 25
	xor	21, 21, 26
	xor	23, 23, 27
	rlwinm	24, 19, 2, 22, 29
	rlwinm	25, 28, 2, 22, 29
	rlwinm	26, 18, 2, 22, 29
	rlwinm	27, 29, 2, 22, 29
	lwzx	24, 15, 24
	lwzx	25, 15, 25
	lwzx	26, 15, 26
	lwzx	27, 15, 27
	xor	20, 20, 24
	xor	22, 22, 25
	xor	21, 21, 26
	xor	23, 23, 27
	ld	28, 0(8)
	ld	29, 8(8)
	rldimi	20, 22, 32, 0
	rldimi	21, 23, 32, 0
	addi	8, 8, 16
	#   XOR in Key Schedule
	xor	20, 20, 28
	xor	21, 21, 29
	srdi	22, 20, 32
	srdi	23, 21, 32
	rlwinm	28, 20, 2, 22, 29
	rlwinm	29, 21, 2, 22, 29
	rlwinm	19, 22, 2, 22, 29
	rlwinm	18, 23, 2, 22, 29
	lwzx	28, 12, 28
	lwzx	29, 12, 29
	lwzx	19, 12, 19
	lwzx	18, 12, 18
	rlwinm	24, 21, 26, 22, 29
	rlwinm	25, 23, 26, 22, 29
	rldimi	29, 19, 32, 24
	rldimi	28, 18, 32, 24
	rlwinm	26, 20, 26, 22, 29
	rlwinm	27, 22, 26, 22, 29
	lwzx	24, 12, 24
	lwzx	25, 12, 25
	lwzx	26, 12, 26
	lwzx	27, 12, 27
	rldimi	28, 24, 40, 16
	rlwimi	28, 25, 8, 16, 23
	rldimi	29, 26, 40, 16
	rlwimi	29, 27, 8, 16, 23
	rlwinm	24, 22, 18, 22, 29
	rlwinm	25, 21, 18, 22, 29
	rlwinm	26, 23, 18, 22, 29
	rlwinm	27, 20, 18, 22, 29
	lwzx	24, 12, 24
	lwzx	25, 12, 25
	lwzx	26, 12, 26
	lwzx	27, 12, 27
	rldimi	28, 24, 48, 8
	rlwimi	28, 25, 16, 8, 15
	rldimi	29, 26, 48, 8
	rlwimi	29, 27, 16, 8, 15
	rlwinm	24, 20, 10, 22, 29
	rlwinm	25, 22, 10, 22, 29
	rlwinm	26, 21, 10, 22, 29
	rlwinm	27, 23, 10, 22, 29
	lwzx	24, 12, 24
	lwzx	25, 12, 25
	lwzx	26, 12, 26
	lwzx	27, 12, 27
	ld	20, 0(8)
	ld	21, 8(8)
	rldimi	28, 24, 56, 0
	rlwimi	28, 25, 24, 0, 7
	rldimi	29, 26, 56, 0
	rlwimi	29, 27, 24, 0, 7
	addi	8, 8, 16
	#   XOR in Key Schedule
	xor	28, 28, 20
	xor	29, 29, 21
	std	28, 0(9)
	std	29, 8(9)
L_AES_XTS_encrypt_loop_block:
	addi	8, 7, 0
	ld	16, 0(3)
	ld	17, 8(3)
	ld	20, 0(8)
	ld	21, 8(8)
	addi	8, 8, 16
	xor	16, 16, 28
	xor	17, 17, 29
	rldicr	16, 16, 32, 63
	rldicr	17, 17, 32, 63
	# Round: 0 - XOR in key schedule
	xor	16, 16, 20
	xor	17, 17, 21
	addi	0, 10, -2
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
	ld	23, 0(11)
	ld	23, 64(11)
	ld	23, 128(11)
	ld	23, 192(11)
	ld	23, 256(11)
	ld	23, 320(11)
	ld	23, 384(11)
	ld	23, 448(11)
	ld	23, 512(11)
	ld	23, 576(11)
	ld	23, 640(11)
	ld	23, 704(11)
	ld	23, 768(11)
	ld	23, 832(11)
	ld	23, 896(11)
	ld	23, 960(11)
	ld	23, 1024(11)
	ld	23, 1088(11)
	ld	23, 1152(11)
	ld	23, 1216(11)
	ld	23, 1280(11)
	ld	23, 1344(11)
	ld	23, 1408(11)
	ld	23, 1472(11)
	ld	23, 1536(11)
	ld	23, 1600(11)
	ld	23, 1664(11)
	ld	23, 1728(11)
	ld	23, 1792(11)
	ld	23, 1856(11)
	ld	23, 1920(11)
	ld	23, 1984(11)
	ld	23, 2048(11)
	ld	23, 2112(11)
	ld	23, 2176(11)
	ld	23, 2240(11)
	ld	23, 2304(11)
	ld	23, 2368(11)
	ld	23, 2432(11)
	ld	23, 2496(11)
	ld	23, 2560(11)
	ld	23, 2624(11)
	ld	23, 2688(11)
	ld	23, 2752(11)
	ld	23, 2816(11)
	ld	23, 2880(11)
	ld	23, 2944(11)
	ld	23, 3008(11)
	ld	23, 3072(11)
	ld	23, 3136(11)
	ld	23, 3200(11)
	ld	23, 3264(11)
	ld	23, 3328(11)
	ld	23, 3392(11)
	ld	23, 3456(11)
	ld	23, 3520(11)
	ld	23, 3584(11)
	ld	23, 3648(11)
	ld	23, 3712(11)
	ld	23, 3776(11)
	ld	23, 3840(11)
	ld	23, 3904(11)
	ld	23, 3968(11)
	ld	23, 4032(11)
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
	srwi	0, 0, 1
	mtctr	0
L_AES_XTS_encrypt_loop_nr:
	srdi	18, 16, 32
	srdi	19, 17, 32
	rlwinm	20, 16, 10, 22, 29
	rlwinm	21, 17, 10, 22, 29
	rlwinm	22, 18, 10, 22, 29
	rlwinm	23, 19, 10, 22, 29
	lwzx	20, 11, 20
	lwzx	21, 11, 21
	lwzx	22, 11, 22
	lwzx	23, 11, 23
	rlwinm	24, 18, 18, 22, 29
	rlwinm	25, 17, 18, 22, 29
	rlwinm	26, 19, 18, 22, 29
	rlwinm	27, 16, 18, 22, 29
	lwzx	24, 12, 24
	lwzx	25, 12, 25
	lwzx	26, 12, 26
	lwzx	27, 12, 27
	xor	20, 20, 24
	xor	22, 22, 25
	xor	21, 21, 26
	xor	23, 23, 27
	rlwinm	24, 17, 26, 22, 29
	rlwinm	25, 19, 26, 22, 29
	rlwinm	26, 16, 26, 22, 29
	rlwinm	27, 18, 26, 22, 29
	lwzx	24, 14, 24
	lwzx	25, 14, 25
	lwzx	26, 14, 26
	lwzx	27, 14, 27
	xor	20, 20, 24
	xor	22, 22, 25
	xor	21, 21, 26
	xor	23, 23, 27
	rlwinm	24, 19, 2, 22, 29
	rlwinm	25, 16, 2, 22, 29
	rlwinm	26, 18, 2, 22, 29
	rlwinm	27, 17, 2, 22, 29
	lwzx	24, 15, 24
	lwzx	25, 15, 25
	lwzx	26, 15, 26
	lwzx	27, 15, 27
	xor	20, 20, 24
	xor	22, 22, 25
	xor	21, 21, 26
	xor	23, 23, 27
	ld	16, 0(8)
	ld	17, 8(8)
	rldimi	20, 22, 32, 0
	rldimi	21, 23, 32, 0
	addi	8, 8, 16
	#   XOR in Key Schedule
	xor	20, 20, 16
	xor	21, 21, 17
	srdi	22, 20, 32
	srdi	23, 21, 32
	rlwinm	16, 20, 10, 22, 29
	rlwinm	17, 21, 10, 22, 29
	rlwinm	18, 22, 10, 22, 29
	rlwinm	19, 23, 10, 22, 29
	lwzx	16, 11, 16
	lwzx	17, 11, 17
	lwzx	18, 11, 18
	lwzx	19, 11, 19
	rlwinm	24, 22, 18, 22, 29
	rlwinm	25, 21, 18, 22, 29
	rlwinm	26, 23, 18, 22, 29
	rlwinm	27, 20, 18, 22, 29
	lwzx	24, 12, 24
	lwzx	25, 12, 25
	lwzx	26, 12, 26
	lwzx	27, 12, 27
	xor	16, 16, 24
	xor	18, 18, 25
	xor	17, 17, 26
	xor	19, 19, 27
	rlwinm	24, 21, 26, 22, 29
	rlwinm	25, 23, 26, 22, 29
	rlwinm	26, 20, 26, 22, 29
	rlwinm	27, 22, 26, 22, 29
	lwzx	24, 14, 24
	lwzx	25, 14, 25
	lwzx	26, 14, 26
	lwzx	27, 14, 27
	xor	16, 16, 24
	xor	18, 18, 25
	xor	17, 17, 26
	xor	19, 19, 27
	rlwinm	24, 23, 2, 22, 29
	rlwinm	25, 20, 2, 22, 29
	rlwinm	26, 22, 2, 22, 29
	rlwinm	27, 21, 2, 22, 29
	lwzx	24, 15, 24
	lwzx	25, 15, 25
	lwzx	26, 15, 26
	lwzx	27, 15, 27
	xor	16, 16, 24
	xor	18, 18, 25
	xor	17, 17, 26
	xor	19, 19, 27
	ld	20, 0(8)
	ld	21, 8(8)
	rldimi	16, 18, 32, 0
	rldimi	17, 19, 32, 0
	addi	8, 8, 16
	#   XOR in Key Schedule
	xor	16, 16, 20
	xor	17, 17, 21
	bdnz	L_AES_XTS_encrypt_loop_nr
	srdi	18, 16, 32
	srdi	19, 17, 32
	rlwinm	20, 16, 10, 22, 29
	rlwinm	21, 17, 10, 22, 29
	rlwinm	22, 18, 10, 22, 29
	rlwinm	23, 19, 10, 22, 29
	lwzx	20, 11, 20
	lwzx	21, 11, 21
	lwzx	22, 11, 22
	lwzx	23, 11, 23
	rlwinm	24, 18, 18, 22, 29
	rlwinm	25, 17, 18, 22, 29
	rlwinm	26, 19, 18, 22, 29
	rlwinm	27, 16, 18, 22, 29
	lwzx	24, 12, 24
	lwzx	25, 12, 25
	lwzx	26, 12, 26
	lwzx	27, 12, 27
	xor	20, 20, 24
	xor	22, 22, 25
	xor	21, 21, 26
	xor	23, 23, 27
	rlwinm	24, 17, 26, 22, 29
	rlwinm	25, 19, 26, 22, 29
	rlwinm	26, 16, 26, 22, 29
	rlwinm	27, 18, 26, 22, 29
	lwzx	24, 14, 24
	lwzx	25, 14, 25
	lwzx	26, 14, 26
	lwzx	27, 14, 27
	xor	20, 20, 24
	xor	22, 22, 25
	xor	21, 21, 26
	xor	23, 23, 27
	rlwinm	24, 19, 2, 22, 29
	rlwinm	25, 16, 2, 22, 29
	rlwinm	26, 18, 2, 22, 29
	rlwinm	27, 17, 2, 22, 29
	lwzx	24, 15, 24
	lwzx	25, 15, 25
	lwzx	26, 15, 26
	lwzx	27, 15, 27
	xor	20, 20, 24
	xor	22, 22, 25
	xor	21, 21, 26
	xor	23, 23, 27
	ld	16, 0(8)
	ld	17, 8(8)
	rldimi	20, 22, 32, 0
	rldimi	21, 23, 32, 0
	addi	8, 8, 16
	#   XOR in Key Schedule
	xor	20, 20, 16
	xor	21, 21, 17
	srdi	22, 20, 32
	srdi	23, 21, 32
	rlwinm	16, 20, 2, 22, 29
	rlwinm	17, 21, 2, 22, 29
	rlwinm	19, 22, 2, 22, 29
	rlwinm	18, 23, 2, 22, 29
	lwzx	16, 12, 16
	lwzx	17, 12, 17
	lwzx	19, 12, 19
	lwzx	18, 12, 18
	rlwinm	24, 21, 26, 22, 29
	rlwinm	25, 23, 26, 22, 29
	rldimi	17, 19, 32, 24
	rldimi	16, 18, 32, 24
	rlwinm	26, 20, 26, 22, 29
	rlwinm	27, 22, 26, 22, 29
	lwzx	24, 12, 24
	lwzx	25, 12, 25
	lwzx	26, 12, 26
	lwzx	27, 12, 27
	rldimi	16, 24, 40, 16
	rlwimi	16, 25, 8, 16, 23
	rldimi	17, 26, 40, 16
	rlwimi	17, 27, 8, 16, 23
	rlwinm	24, 22, 18, 22, 29
	rlwinm	25, 21, 18, 22, 29
	rlwinm	26, 23, 18, 22, 29
	rlwinm	27, 20, 18, 22, 29
	lwzx	24, 12, 24
	lwzx	25, 12, 25
	lwzx	26, 12, 26
	lwzx	27, 12, 27
	rldimi	16, 24, 48, 8
	rlwimi	16, 25, 16, 8, 15
	rldimi	17, 26, 48, 8
	rlwimi	17, 27, 16, 8, 15
	rlwinm	24, 20, 10, 22, 29
	rlwinm	25, 22, 10, 22, 29
	rlwinm	26, 21, 10, 22, 29
	rlwinm	27, 23, 10, 22, 29
	lwzx	24, 12, 24
	lwzx	25, 12, 25
	lwzx	26, 12, 26
	lwzx	27, 12, 27
	ld	20, 0(8)
	ld	21, 8(8)
	rldimi	16, 24, 56, 0
	rlwimi	16, 25, 24, 0, 7
	rldimi	17, 26, 56, 0
	rlwimi	17, 27, 24, 0, 7
	addi	8, 8, 16
	#   XOR in Key Schedule
	xor	16, 16, 20
	xor	17, 17, 21
	xor	16, 16, 28
	xor	17, 17, 29
	li	19, 8
	ldbrx	28, 0, 9
	ldbrx	29, 9, 19
	std	16, 0(4)
	std	17, 8(4)
	sradi	24, 29, 63
	srdi	25, 28, 63
	sldi	29, 29, 1
	andi.	24, 24, 0x87
	sldi	28, 28, 1
	xor	29, 29, 25
	xor	28, 28, 24
	stdbrx	28, 0, 9
	stdbrx	29, 9, 19
	ld	28, 0(9)
	ld	29, 8(9)
	addi	5, 5, -16
	addi	3, 3, 16
	addi	4, 4, 16
	cmpdi	5, 16
	bge	L_AES_XTS_encrypt_loop_block
	cmpdi	5, 0
	beq	L_AES_XTS_encrypt_done_data
	addi	8, 7, 0
	addi	4, 4, -16
	ld	16, 0(4)
	ld	17, 8(4)
	addi	4, 4, 16
	std	16, 0(9)
	std	17, 8(9)
	addi	20, 5, 0
L_AES_XTS_encrypt_start_byte:
	lbz	24, 0(9)
	lbz	25, 0(3)
	addi	3, 3, 1
	stb	24, 0(4)
	addi	4, 4, 1
	stb	25, 0(9)
	addi	9, 9, 1
	addic.	20, 20, -1
	bne	L_AES_XTS_encrypt_start_byte
	subf	4, 5, 4
	subf	9, 5, 9
	addi	4, 4, -16
	ld	16, 0(9)
	ld	17, 8(9)
	ld	20, 0(8)
	ld	21, 8(8)
	addi	8, 8, 16
	xor	16, 16, 28
	xor	17, 17, 29
	rldicr	16, 16, 32, 63
	rldicr	17, 17, 32, 63
	# Round: 0 - XOR in key schedule
	xor	16, 16, 20
	xor	17, 17, 21
	addi	0, 10, -2
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
	ld	23, 0(11)
	ld	23, 64(11)
	ld	23, 128(11)
	ld	23, 192(11)
	ld	23, 256(11)
	ld	23, 320(11)
	ld	23, 384(11)
	ld	23, 448(11)
	ld	23, 512(11)
	ld	23, 576(11)
	ld	23, 640(11)
	ld	23, 704(11)
	ld	23, 768(11)
	ld	23, 832(11)
	ld	23, 896(11)
	ld	23, 960(11)
	ld	23, 1024(11)
	ld	23, 1088(11)
	ld	23, 1152(11)
	ld	23, 1216(11)
	ld	23, 1280(11)
	ld	23, 1344(11)
	ld	23, 1408(11)
	ld	23, 1472(11)
	ld	23, 1536(11)
	ld	23, 1600(11)
	ld	23, 1664(11)
	ld	23, 1728(11)
	ld	23, 1792(11)
	ld	23, 1856(11)
	ld	23, 1920(11)
	ld	23, 1984(11)
	ld	23, 2048(11)
	ld	23, 2112(11)
	ld	23, 2176(11)
	ld	23, 2240(11)
	ld	23, 2304(11)
	ld	23, 2368(11)
	ld	23, 2432(11)
	ld	23, 2496(11)
	ld	23, 2560(11)
	ld	23, 2624(11)
	ld	23, 2688(11)
	ld	23, 2752(11)
	ld	23, 2816(11)
	ld	23, 2880(11)
	ld	23, 2944(11)
	ld	23, 3008(11)
	ld	23, 3072(11)
	ld	23, 3136(11)
	ld	23, 3200(11)
	ld	23, 3264(11)
	ld	23, 3328(11)
	ld	23, 3392(11)
	ld	23, 3456(11)
	ld	23, 3520(11)
	ld	23, 3584(11)
	ld	23, 3648(11)
	ld	23, 3712(11)
	ld	23, 3776(11)
	ld	23, 3840(11)
	ld	23, 3904(11)
	ld	23, 3968(11)
	ld	23, 4032(11)
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
	srwi	0, 0, 1
	mtctr	0
L_AES_XTS_encrypt_loop_nr_partial:
	srdi	18, 16, 32
	srdi	19, 17, 32
	rlwinm	20, 16, 10, 22, 29
	rlwinm	21, 17, 10, 22, 29
	rlwinm	22, 18, 10, 22, 29
	rlwinm	23, 19, 10, 22, 29
	lwzx	20, 11, 20
	lwzx	21, 11, 21
	lwzx	22, 11, 22
	lwzx	23, 11, 23
	rlwinm	24, 18, 18, 22, 29
	rlwinm	25, 17, 18, 22, 29
	rlwinm	26, 19, 18, 22, 29
	rlwinm	27, 16, 18, 22, 29
	lwzx	24, 12, 24
	lwzx	25, 12, 25
	lwzx	26, 12, 26
	lwzx	27, 12, 27
	xor	20, 20, 24
	xor	22, 22, 25
	xor	21, 21, 26
	xor	23, 23, 27
	rlwinm	24, 17, 26, 22, 29
	rlwinm	25, 19, 26, 22, 29
	rlwinm	26, 16, 26, 22, 29
	rlwinm	27, 18, 26, 22, 29
	lwzx	24, 14, 24
	lwzx	25, 14, 25
	lwzx	26, 14, 26
	lwzx	27, 14, 27
	xor	20, 20, 24
	xor	22, 22, 25
	xor	21, 21, 26
	xor	23, 23, 27
	rlwinm	24, 19, 2, 22, 29
	rlwinm	25, 16, 2, 22, 29
	rlwinm	26, 18, 2, 22, 29
	rlwinm	27, 17, 2, 22, 29
	lwzx	24, 15, 24
	lwzx	25, 15, 25
	lwzx	26, 15, 26
	lwzx	27, 15, 27
	xor	20, 20, 24
	xor	22, 22, 25
	xor	21, 21, 26
	xor	23, 23, 27
	ld	16, 0(8)
	ld	17, 8(8)
	rldimi	20, 22, 32, 0
	rldimi	21, 23, 32, 0
	addi	8, 8, 16
	#   XOR in Key Schedule
	xor	20, 20, 16
	xor	21, 21, 17
	srdi	22, 20, 32
	srdi	23, 21, 32
	rlwinm	16, 20, 10, 22, 29
	rlwinm	17, 21, 10, 22, 29
	rlwinm	18, 22, 10, 22, 29
	rlwinm	19, 23, 10, 22, 29
	lwzx	16, 11, 16
	lwzx	17, 11, 17
	lwzx	18, 11, 18
	lwzx	19, 11, 19
	rlwinm	24, 22, 18, 22, 29
	rlwinm	25, 21, 18, 22, 29
	rlwinm	26, 23, 18, 22, 29
	rlwinm	27, 20, 18, 22, 29
	lwzx	24, 12, 24
	lwzx	25, 12, 25
	lwzx	26, 12, 26
	lwzx	27, 12, 27
	xor	16, 16, 24
	xor	18, 18, 25
	xor	17, 17, 26
	xor	19, 19, 27
	rlwinm	24, 21, 26, 22, 29
	rlwinm	25, 23, 26, 22, 29
	rlwinm	26, 20, 26, 22, 29
	rlwinm	27, 22, 26, 22, 29
	lwzx	24, 14, 24
	lwzx	25, 14, 25
	lwzx	26, 14, 26
	lwzx	27, 14, 27
	xor	16, 16, 24
	xor	18, 18, 25
	xor	17, 17, 26
	xor	19, 19, 27
	rlwinm	24, 23, 2, 22, 29
	rlwinm	25, 20, 2, 22, 29
	rlwinm	26, 22, 2, 22, 29
	rlwinm	27, 21, 2, 22, 29
	lwzx	24, 15, 24
	lwzx	25, 15, 25
	lwzx	26, 15, 26
	lwzx	27, 15, 27
	xor	16, 16, 24
	xor	18, 18, 25
	xor	17, 17, 26
	xor	19, 19, 27
	ld	20, 0(8)
	ld	21, 8(8)
	rldimi	16, 18, 32, 0
	rldimi	17, 19, 32, 0
	addi	8, 8, 16
	#   XOR in Key Schedule
	xor	16, 16, 20
	xor	17, 17, 21
	bdnz	L_AES_XTS_encrypt_loop_nr_partial
	srdi	18, 16, 32
	srdi	19, 17, 32
	rlwinm	20, 16, 10, 22, 29
	rlwinm	21, 17, 10, 22, 29
	rlwinm	22, 18, 10, 22, 29
	rlwinm	23, 19, 10, 22, 29
	lwzx	20, 11, 20
	lwzx	21, 11, 21
	lwzx	22, 11, 22
	lwzx	23, 11, 23
	rlwinm	24, 18, 18, 22, 29
	rlwinm	25, 17, 18, 22, 29
	rlwinm	26, 19, 18, 22, 29
	rlwinm	27, 16, 18, 22, 29
	lwzx	24, 12, 24
	lwzx	25, 12, 25
	lwzx	26, 12, 26
	lwzx	27, 12, 27
	xor	20, 20, 24
	xor	22, 22, 25
	xor	21, 21, 26
	xor	23, 23, 27
	rlwinm	24, 17, 26, 22, 29
	rlwinm	25, 19, 26, 22, 29
	rlwinm	26, 16, 26, 22, 29
	rlwinm	27, 18, 26, 22, 29
	lwzx	24, 14, 24
	lwzx	25, 14, 25
	lwzx	26, 14, 26
	lwzx	27, 14, 27
	xor	20, 20, 24
	xor	22, 22, 25
	xor	21, 21, 26
	xor	23, 23, 27
	rlwinm	24, 19, 2, 22, 29
	rlwinm	25, 16, 2, 22, 29
	rlwinm	26, 18, 2, 22, 29
	rlwinm	27, 17, 2, 22, 29
	lwzx	24, 15, 24
	lwzx	25, 15, 25
	lwzx	26, 15, 26
	lwzx	27, 15, 27
	xor	20, 20, 24
	xor	22, 22, 25
	xor	21, 21, 26
	xor	23, 23, 27
	ld	16, 0(8)
	ld	17, 8(8)
	rldimi	20, 22, 32, 0
	rldimi	21, 23, 32, 0
	addi	8, 8, 16
	#   XOR in Key Schedule
	xor	20, 20, 16
	xor	21, 21, 17
	srdi	22, 20, 32
	srdi	23, 21, 32
	rlwinm	16, 20, 2, 22, 29
	rlwinm	17, 21, 2, 22, 29
	rlwinm	19, 22, 2, 22, 29
	rlwinm	18, 23, 2, 22, 29
	lwzx	16, 12, 16
	lwzx	17, 12, 17
	lwzx	19, 12, 19
	lwzx	18, 12, 18
	rlwinm	24, 21, 26, 22, 29
	rlwinm	25, 23, 26, 22, 29
	rldimi	17, 19, 32, 24
	rldimi	16, 18, 32, 24
	rlwinm	26, 20, 26, 22, 29
	rlwinm	27, 22, 26, 22, 29
	lwzx	24, 12, 24
	lwzx	25, 12, 25
	lwzx	26, 12, 26
	lwzx	27, 12, 27
	rldimi	16, 24, 40, 16
	rlwimi	16, 25, 8, 16, 23
	rldimi	17, 26, 40, 16
	rlwimi	17, 27, 8, 16, 23
	rlwinm	24, 22, 18, 22, 29
	rlwinm	25, 21, 18, 22, 29
	rlwinm	26, 23, 18, 22, 29
	rlwinm	27, 20, 18, 22, 29
	lwzx	24, 12, 24
	lwzx	25, 12, 25
	lwzx	26, 12, 26
	lwzx	27, 12, 27
	rldimi	16, 24, 48, 8
	rlwimi	16, 25, 16, 8, 15
	rldimi	17, 26, 48, 8
	rlwimi	17, 27, 16, 8, 15
	rlwinm	24, 20, 10, 22, 29
	rlwinm	25, 22, 10, 22, 29
	rlwinm	26, 21, 10, 22, 29
	rlwinm	27, 23, 10, 22, 29
	lwzx	24, 12, 24
	lwzx	25, 12, 25
	lwzx	26, 12, 26
	lwzx	27, 12, 27
	ld	20, 0(8)
	ld	21, 8(8)
	rldimi	16, 24, 56, 0
	rlwimi	16, 25, 24, 0, 7
	rldimi	17, 26, 56, 0
	rlwimi	17, 27, 24, 0, 7
	addi	8, 8, 16
	#   XOR in Key Schedule
	xor	16, 16, 20
	xor	17, 17, 21
	xor	16, 16, 28
	xor	17, 17, 29
	std	16, 0(4)
	std	17, 8(4)
L_AES_XTS_encrypt_done_data:
	ld	0, 128(1)
	mtlr	0
	ld	14, 0(1)
	ld	15, 8(1)
	ld	16, 16(1)
	ld	17, 24(1)
	ld	18, 32(1)
	ld	19, 40(1)
	ld	20, 48(1)
	ld	21, 56(1)
	ld	22, 64(1)
	ld	23, 72(1)
	ld	24, 80(1)
	ld	25, 88(1)
	ld	26, 96(1)
	ld	27, 104(1)
	ld	28, 112(1)
	ld	29, 120(1)
	addi	1, 1, 0x88
	blr
#ifndef __APPLE__
	.size	AES_XTS_encrypt,.-AES_XTS_encrypt
#endif /* __APPLE__ */
#endif /* WOLFSSL_AES_XTS */
#ifdef HAVE_AES_DECRYPT
#if defined(WOLFSSL_AES_DIRECT) || defined(WOLFSSL_AES_COUNTER) || \
    defined(HAVE_AES_CBC) || defined(HAVE_AES_ECB)
#ifndef __APPLE__
	.text
	.type	L_AES_PPC64_td4, %object
	.size	L_AES_PPC64_td4, 256
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_AES_PPC64_td4:
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
#ifndef __APPLE__
.text
.globl	AES_ECB_decrypt
.type	AES_ECB_decrypt,@function
.align	16
AES_ECB_decrypt:
#if defined(_CALL_ELF) && _CALL_ELF == 2
0:	addis	2, 12, .TOC.-0b@ha
	addi	2, 2, .TOC.-0b@l
	.localentry	AES_ECB_decrypt, .-AES_ECB_decrypt
#endif
#else
.section	__TEXT,__text
.globl	_AES_ECB_decrypt
.p2align	4
_AES_ECB_decrypt:
#endif /* __APPLE__ */
	stdu	1, -88(1)
	mflr	0
	std	0, 80(1)
	std	14, 0(1)
	std	15, 8(1)
	std	16, 16(1)
	std	17, 24(1)
	std	18, 32(1)
	std	19, 40(1)
	std	20, 48(1)
	std	21, 56(1)
	std	22, 64(1)
	std	23, 72(1)
	addis	8, 2, L_AES_PPC64_td@toc@ha
	addi	8, 8, L_AES_PPC64_td@toc@l
	addis	9, 2, L_AES_PPC64_td4@toc@ha
	addi	9, 9, L_AES_PPC64_td4@toc@l
L_AES_ECB_decrypt_loop_block:
	addi	23, 6, 0
	ld	10, 0(3)
	ld	11, 8(3)
	ld	15, 0(23)
	ld	16, 8(23)
	addi	23, 23, 16
	rldicr	10, 10, 32, 63
	rldicr	11, 11, 32, 63
	# Round: 0 - XOR in key schedule
	xor	10, 10, 15
	xor	11, 11, 16
	addi	0, 7, -2
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
	ld	18, 0(8)
	ld	18, 64(8)
	ld	18, 128(8)
	ld	18, 192(8)
	ld	18, 256(8)
	ld	18, 320(8)
	ld	18, 384(8)
	ld	18, 448(8)
	ld	18, 512(8)
	ld	18, 576(8)
	ld	18, 640(8)
	ld	18, 704(8)
	ld	18, 768(8)
	ld	18, 832(8)
	ld	18, 896(8)
	ld	18, 960(8)
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
	srwi	0, 0, 1
	mtctr	0
L_AES_ECB_decrypt_loop_nr:
	srdi	12, 10, 32
	srdi	14, 11, 32
	rlwinm	15, 14, 18, 22, 29
	rlwinm	17, 10, 18, 22, 29
	rlwinm	16, 12, 18, 22, 29
	rlwinm	18, 11, 18, 22, 29
	lwzx	15, 8, 15
	lwzx	17, 8, 17
	lwzx	16, 8, 16
	lwzx	18, 8, 18
	rlwinm	19, 10, 10, 22, 29
	rlwinm	20, 12, 10, 22, 29
	rlwinm	21, 11, 10, 22, 29
	rlwinm	22, 14, 10, 22, 29
	lwzx	19, 8, 19
	lwzx	20, 8, 20
	lwzx	21, 8, 21
	lwzx	22, 8, 22
	rlwimi	19, 19, 8, 0, 31
	rlwimi	20, 20, 8, 0, 31
	rlwimi	21, 21, 8, 0, 31
	rlwimi	22, 22, 8, 0, 31
	xor	15, 15, 19
	xor	17, 17, 20
	xor	16, 16, 21
	xor	18, 18, 22
	rlwinm	19, 11, 26, 22, 29
	rlwinm	20, 14, 26, 22, 29
	rlwinm	21, 10, 26, 22, 29
	rlwinm	22, 12, 26, 22, 29
	lwzx	19, 8, 19
	lwzx	20, 8, 20
	lwzx	21, 8, 21
	lwzx	22, 8, 22
	rlwimi	19, 19, 24, 0, 31
	rlwimi	20, 20, 24, 0, 31
	rlwimi	21, 21, 24, 0, 31
	rlwimi	22, 22, 24, 0, 31
	xor	15, 15, 19
	xor	17, 17, 20
	xor	16, 16, 21
	xor	18, 18, 22
	rlwinm	19, 12, 2, 22, 29
	rlwinm	20, 11, 2, 22, 29
	rlwinm	21, 14, 2, 22, 29
	rlwinm	22, 10, 2, 22, 29
	lwzx	19, 8, 19
	lwzx	20, 8, 20
	lwzx	21, 8, 21
	lwzx	22, 8, 22
	rlwimi	19, 19, 16, 0, 31
	rlwimi	20, 20, 16, 0, 31
	rlwimi	21, 21, 16, 0, 31
	rlwimi	22, 22, 16, 0, 31
	ld	10, 0(23)
	ld	11, 8(23)
	xor	15, 15, 19
	xor	17, 17, 20
	xor	16, 16, 21
	xor	18, 18, 22
	addi	23, 23, 16
	rldimi	15, 17, 32, 0
	rldimi	16, 18, 32, 0
	#   XOR in Key Schedule
	xor	15, 15, 10
	xor	16, 16, 11
	srdi	17, 15, 32
	srdi	18, 16, 32
	rlwinm	10, 18, 18, 22, 29
	rlwinm	12, 15, 18, 22, 29
	rlwinm	11, 17, 18, 22, 29
	rlwinm	14, 16, 18, 22, 29
	lwzx	10, 8, 10
	lwzx	12, 8, 12
	lwzx	11, 8, 11
	lwzx	14, 8, 14
	rlwinm	19, 15, 10, 22, 29
	rlwinm	20, 17, 10, 22, 29
	rlwinm	21, 16, 10, 22, 29
	rlwinm	22, 18, 10, 22, 29
	lwzx	19, 8, 19
	lwzx	20, 8, 20
	lwzx	21, 8, 21
	lwzx	22, 8, 22
	rlwimi	19, 19, 8, 0, 31
	rlwimi	20, 20, 8, 0, 31
	rlwimi	21, 21, 8, 0, 31
	rlwimi	22, 22, 8, 0, 31
	xor	10, 10, 19
	xor	12, 12, 20
	xor	11, 11, 21
	xor	14, 14, 22
	rlwinm	19, 16, 26, 22, 29
	rlwinm	20, 18, 26, 22, 29
	rlwinm	21, 15, 26, 22, 29
	rlwinm	22, 17, 26, 22, 29
	lwzx	19, 8, 19
	lwzx	20, 8, 20
	lwzx	21, 8, 21
	lwzx	22, 8, 22
	rlwimi	19, 19, 24, 0, 31
	rlwimi	20, 20, 24, 0, 31
	rlwimi	21, 21, 24, 0, 31
	rlwimi	22, 22, 24, 0, 31
	xor	10, 10, 19
	xor	12, 12, 20
	xor	11, 11, 21
	xor	14, 14, 22
	rlwinm	19, 17, 2, 22, 29
	rlwinm	20, 16, 2, 22, 29
	rlwinm	21, 18, 2, 22, 29
	rlwinm	22, 15, 2, 22, 29
	lwzx	19, 8, 19
	lwzx	20, 8, 20
	lwzx	21, 8, 21
	lwzx	22, 8, 22
	rlwimi	19, 19, 16, 0, 31
	rlwimi	20, 20, 16, 0, 31
	rlwimi	21, 21, 16, 0, 31
	rlwimi	22, 22, 16, 0, 31
	ld	15, 0(23)
	ld	16, 8(23)
	xor	10, 10, 19
	xor	12, 12, 20
	xor	11, 11, 21
	xor	14, 14, 22
	addi	23, 23, 16
	rldimi	10, 12, 32, 0
	rldimi	11, 14, 32, 0
	#   XOR in Key Schedule
	xor	10, 10, 15
	xor	11, 11, 16
	bdnz	L_AES_ECB_decrypt_loop_nr
	srdi	12, 10, 32
	srdi	14, 11, 32
	rlwinm	15, 14, 18, 22, 29
	rlwinm	17, 10, 18, 22, 29
	rlwinm	16, 12, 18, 22, 29
	rlwinm	18, 11, 18, 22, 29
	lwzx	15, 8, 15
	lwzx	17, 8, 17
	lwzx	16, 8, 16
	lwzx	18, 8, 18
	rlwinm	19, 10, 10, 22, 29
	rlwinm	20, 12, 10, 22, 29
	rlwinm	21, 11, 10, 22, 29
	rlwinm	22, 14, 10, 22, 29
	lwzx	19, 8, 19
	lwzx	20, 8, 20
	lwzx	21, 8, 21
	lwzx	22, 8, 22
	rlwimi	19, 19, 8, 0, 31
	rlwimi	20, 20, 8, 0, 31
	rlwimi	21, 21, 8, 0, 31
	rlwimi	22, 22, 8, 0, 31
	xor	15, 15, 19
	xor	17, 17, 20
	xor	16, 16, 21
	xor	18, 18, 22
	rlwinm	19, 11, 26, 22, 29
	rlwinm	20, 14, 26, 22, 29
	rlwinm	21, 10, 26, 22, 29
	rlwinm	22, 12, 26, 22, 29
	lwzx	19, 8, 19
	lwzx	20, 8, 20
	lwzx	21, 8, 21
	lwzx	22, 8, 22
	rlwimi	19, 19, 24, 0, 31
	rlwimi	20, 20, 24, 0, 31
	rlwimi	21, 21, 24, 0, 31
	rlwimi	22, 22, 24, 0, 31
	xor	15, 15, 19
	xor	17, 17, 20
	xor	16, 16, 21
	xor	18, 18, 22
	rlwinm	19, 12, 2, 22, 29
	rlwinm	20, 11, 2, 22, 29
	rlwinm	21, 14, 2, 22, 29
	rlwinm	22, 10, 2, 22, 29
	lwzx	19, 8, 19
	lwzx	20, 8, 20
	lwzx	21, 8, 21
	lwzx	22, 8, 22
	rlwimi	19, 19, 16, 0, 31
	rlwimi	20, 20, 16, 0, 31
	rlwimi	21, 21, 16, 0, 31
	rlwimi	22, 22, 16, 0, 31
	ld	10, 0(23)
	ld	11, 8(23)
	xor	15, 15, 19
	xor	17, 17, 20
	xor	16, 16, 21
	xor	18, 18, 22
	addi	23, 23, 16
	rldimi	15, 17, 32, 0
	rldimi	16, 18, 32, 0
	#   XOR in Key Schedule
	xor	15, 15, 10
	xor	16, 16, 11
	ld	18, 0(9)
	ld	18, 64(9)
	ld	18, 128(9)
	ld	18, 192(9)
	ld	18, 256(9)
	ld	18, 320(9)
	ld	18, 384(9)
	ld	18, 448(9)
	ld	18, 512(9)
	ld	18, 576(9)
	ld	18, 640(9)
	ld	18, 704(9)
	ld	18, 768(9)
	ld	18, 832(9)
	ld	18, 896(9)
	ld	18, 960(9)
	rldicl	12, 15, 32, 56
	andi.   10, 16, 255
	rldicl	14, 16, 32, 56
	andi.   11, 15, 255
	lbzx	12, 9, 12
	lbzx	10, 9, 10
	lbzx	14, 9, 14
	lbzx	11, 9, 11
	rldimi	10, 12, 32, 24
	rldimi	11, 14, 32, 24
	rldicl	19, 16, 56, 56
	rldicl	20, 16, 24, 56
	rldicl	21, 15, 56, 56
	rldicl	22, 15, 24, 56
	lbzx	19, 9, 19
	lbzx	20, 9, 20
	lbzx	21, 9, 21
	lbzx	22, 9, 22
	rldimi	10, 19, 40, 16
	rlwimi	10, 20, 8, 16, 23
	rldimi	11, 21, 40, 16
	rlwimi	11, 22, 8, 16, 23
	rldicl	19, 16, 16, 56
	rldicl	20, 15, 48, 56
	rldicl	21, 15, 16, 56
	rldicl	22, 16, 48, 56
	lbzx	19, 9, 19
	lbzx	20, 9, 20
	lbzx	21, 9, 21
	lbzx	22, 9, 22
	rldimi	10, 19, 48, 8
	rlwimi	10, 20, 16, 8, 15
	rldimi	11, 21, 48, 8
	rlwimi	11, 22, 16, 8, 15
	rldicl	19, 15, 40, 56
	rldicl	20, 15, 8, 56
	rldicl	21, 16, 40, 56
	rldicl	22, 16, 8, 56
	lbzx	19, 9, 19
	lbzx	20, 9, 20
	lbzx	21, 9, 21
	lbzx	22, 9, 22
	ld	15, 0(23)
	ld	16, 8(23)
	rldimi	10, 19, 56, 0
	rlwimi	10, 20, 24, 0, 7
	rldimi	11, 21, 56, 0
	rlwimi	11, 22, 24, 0, 7
	addi	23, 23, 16
	#   XOR in Key Schedule
	xor	10, 10, 15
	xor	11, 11, 16
	std	10, 0(4)
	std	11, 8(4)
	addic.	5, 5, -16
	addi	3, 3, 16
	addi	4, 4, 16
	bne	L_AES_ECB_decrypt_loop_block
	ld	0, 80(1)
	mtlr	0
	ld	14, 0(1)
	ld	15, 8(1)
	ld	16, 16(1)
	ld	17, 24(1)
	ld	18, 32(1)
	ld	19, 40(1)
	ld	20, 48(1)
	ld	21, 56(1)
	ld	22, 64(1)
	ld	23, 72(1)
	addi	1, 1, 0x58
	blr
#ifndef __APPLE__
	.size	AES_ECB_decrypt,.-AES_ECB_decrypt
#endif /* __APPLE__ */
#endif /* WOLFSSL_AES_DIRECT || WOLFSSL_AES_COUNTER || defined(HAVE_AES_ECB) */
#ifdef HAVE_AES_CBC
#ifndef __APPLE__
.text
.globl	AES_CBC_decrypt
.type	AES_CBC_decrypt,@function
.align	16
AES_CBC_decrypt:
#if defined(_CALL_ELF) && _CALL_ELF == 2
0:	addis	2, 12, .TOC.-0b@ha
	addi	2, 2, .TOC.-0b@l
	.localentry	AES_CBC_decrypt, .-AES_CBC_decrypt
#endif
#else
.section	__TEXT,__text
.globl	_AES_CBC_decrypt
.p2align	4
_AES_CBC_decrypt:
#endif /* __APPLE__ */
	stdu	1, -128(1)
	mflr	0
	std	0, 120(1)
	std	14, 0(1)
	std	15, 8(1)
	std	16, 16(1)
	std	17, 24(1)
	std	18, 32(1)
	std	19, 40(1)
	std	20, 48(1)
	std	21, 56(1)
	std	22, 64(1)
	std	23, 72(1)
	std	24, 80(1)
	std	25, 88(1)
	std	26, 96(1)
	std	27, 104(1)
	std	28, 112(1)
	addis	10, 2, L_AES_PPC64_td4@toc@ha
	addi	10, 10, L_AES_PPC64_td4@toc@l
	addis	9, 2, L_AES_PPC64_td@toc@ha
	addi	9, 9, L_AES_PPC64_td@toc@l
	ld	24, 0(8)
	ld	25, 8(8)
L_AES_CBC_decrypt_loop_block:
	addi	28, 6, 0
	ld	26, 0(3)
	ld	27, 8(3)
	ld	16, 0(28)
	ld	17, 8(28)
	addi	28, 28, 16
	rldicr	11, 26, 32, 63
	rldicr	12, 27, 32, 63
	# Round: 0 - XOR in key schedule
	xor	11, 11, 16
	xor	12, 12, 17
	addi	0, 7, -2
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
	ld	19, 0(9)
	ld	19, 64(9)
	ld	19, 128(9)
	ld	19, 192(9)
	ld	19, 256(9)
	ld	19, 320(9)
	ld	19, 384(9)
	ld	19, 448(9)
	ld	19, 512(9)
	ld	19, 576(9)
	ld	19, 640(9)
	ld	19, 704(9)
	ld	19, 768(9)
	ld	19, 832(9)
	ld	19, 896(9)
	ld	19, 960(9)
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
	srwi	0, 0, 1
	mtctr	0
L_AES_CBC_decrypt_loop_nr_even:
	srdi	14, 11, 32
	srdi	15, 12, 32
	rlwinm	16, 15, 18, 22, 29
	rlwinm	18, 11, 18, 22, 29
	rlwinm	17, 14, 18, 22, 29
	rlwinm	19, 12, 18, 22, 29
	lwzx	16, 9, 16
	lwzx	18, 9, 18
	lwzx	17, 9, 17
	lwzx	19, 9, 19
	rlwinm	20, 11, 10, 22, 29
	rlwinm	21, 14, 10, 22, 29
	rlwinm	22, 12, 10, 22, 29
	rlwinm	23, 15, 10, 22, 29
	lwzx	20, 9, 20
	lwzx	21, 9, 21
	lwzx	22, 9, 22
	lwzx	23, 9, 23
	rlwimi	20, 20, 8, 0, 31
	rlwimi	21, 21, 8, 0, 31
	rlwimi	22, 22, 8, 0, 31
	rlwimi	23, 23, 8, 0, 31
	xor	16, 16, 20
	xor	18, 18, 21
	xor	17, 17, 22
	xor	19, 19, 23
	rlwinm	20, 12, 26, 22, 29
	rlwinm	21, 15, 26, 22, 29
	rlwinm	22, 11, 26, 22, 29
	rlwinm	23, 14, 26, 22, 29
	lwzx	20, 9, 20
	lwzx	21, 9, 21
	lwzx	22, 9, 22
	lwzx	23, 9, 23
	rlwimi	20, 20, 24, 0, 31
	rlwimi	21, 21, 24, 0, 31
	rlwimi	22, 22, 24, 0, 31
	rlwimi	23, 23, 24, 0, 31
	xor	16, 16, 20
	xor	18, 18, 21
	xor	17, 17, 22
	xor	19, 19, 23
	rlwinm	20, 14, 2, 22, 29
	rlwinm	21, 12, 2, 22, 29
	rlwinm	22, 15, 2, 22, 29
	rlwinm	23, 11, 2, 22, 29
	lwzx	20, 9, 20
	lwzx	21, 9, 21
	lwzx	22, 9, 22
	lwzx	23, 9, 23
	rlwimi	20, 20, 16, 0, 31
	rlwimi	21, 21, 16, 0, 31
	rlwimi	22, 22, 16, 0, 31
	rlwimi	23, 23, 16, 0, 31
	ld	11, 0(28)
	ld	12, 8(28)
	xor	16, 16, 20
	xor	18, 18, 21
	xor	17, 17, 22
	xor	19, 19, 23
	addi	28, 28, 16
	rldimi	16, 18, 32, 0
	rldimi	17, 19, 32, 0
	#   XOR in Key Schedule
	xor	16, 16, 11
	xor	17, 17, 12
	srdi	18, 16, 32
	srdi	19, 17, 32
	rlwinm	11, 19, 18, 22, 29
	rlwinm	14, 16, 18, 22, 29
	rlwinm	12, 18, 18, 22, 29
	rlwinm	15, 17, 18, 22, 29
	lwzx	11, 9, 11
	lwzx	14, 9, 14
	lwzx	12, 9, 12
	lwzx	15, 9, 15
	rlwinm	20, 16, 10, 22, 29
	rlwinm	21, 18, 10, 22, 29
	rlwinm	22, 17, 10, 22, 29
	rlwinm	23, 19, 10, 22, 29
	lwzx	20, 9, 20
	lwzx	21, 9, 21
	lwzx	22, 9, 22
	lwzx	23, 9, 23
	rlwimi	20, 20, 8, 0, 31
	rlwimi	21, 21, 8, 0, 31
	rlwimi	22, 22, 8, 0, 31
	rlwimi	23, 23, 8, 0, 31
	xor	11, 11, 20
	xor	14, 14, 21
	xor	12, 12, 22
	xor	15, 15, 23
	rlwinm	20, 17, 26, 22, 29
	rlwinm	21, 19, 26, 22, 29
	rlwinm	22, 16, 26, 22, 29
	rlwinm	23, 18, 26, 22, 29
	lwzx	20, 9, 20
	lwzx	21, 9, 21
	lwzx	22, 9, 22
	lwzx	23, 9, 23
	rlwimi	20, 20, 24, 0, 31
	rlwimi	21, 21, 24, 0, 31
	rlwimi	22, 22, 24, 0, 31
	rlwimi	23, 23, 24, 0, 31
	xor	11, 11, 20
	xor	14, 14, 21
	xor	12, 12, 22
	xor	15, 15, 23
	rlwinm	20, 18, 2, 22, 29
	rlwinm	21, 17, 2, 22, 29
	rlwinm	22, 19, 2, 22, 29
	rlwinm	23, 16, 2, 22, 29
	lwzx	20, 9, 20
	lwzx	21, 9, 21
	lwzx	22, 9, 22
	lwzx	23, 9, 23
	rlwimi	20, 20, 16, 0, 31
	rlwimi	21, 21, 16, 0, 31
	rlwimi	22, 22, 16, 0, 31
	rlwimi	23, 23, 16, 0, 31
	ld	16, 0(28)
	ld	17, 8(28)
	xor	11, 11, 20
	xor	14, 14, 21
	xor	12, 12, 22
	xor	15, 15, 23
	addi	28, 28, 16
	rldimi	11, 14, 32, 0
	rldimi	12, 15, 32, 0
	#   XOR in Key Schedule
	xor	11, 11, 16
	xor	12, 12, 17
	bdnz	L_AES_CBC_decrypt_loop_nr_even
	srdi	14, 11, 32
	srdi	15, 12, 32
	rlwinm	16, 15, 18, 22, 29
	rlwinm	18, 11, 18, 22, 29
	rlwinm	17, 14, 18, 22, 29
	rlwinm	19, 12, 18, 22, 29
	lwzx	16, 9, 16
	lwzx	18, 9, 18
	lwzx	17, 9, 17
	lwzx	19, 9, 19
	rlwinm	20, 11, 10, 22, 29
	rlwinm	21, 14, 10, 22, 29
	rlwinm	22, 12, 10, 22, 29
	rlwinm	23, 15, 10, 22, 29
	lwzx	20, 9, 20
	lwzx	21, 9, 21
	lwzx	22, 9, 22
	lwzx	23, 9, 23
	rlwimi	20, 20, 8, 0, 31
	rlwimi	21, 21, 8, 0, 31
	rlwimi	22, 22, 8, 0, 31
	rlwimi	23, 23, 8, 0, 31
	xor	16, 16, 20
	xor	18, 18, 21
	xor	17, 17, 22
	xor	19, 19, 23
	rlwinm	20, 12, 26, 22, 29
	rlwinm	21, 15, 26, 22, 29
	rlwinm	22, 11, 26, 22, 29
	rlwinm	23, 14, 26, 22, 29
	lwzx	20, 9, 20
	lwzx	21, 9, 21
	lwzx	22, 9, 22
	lwzx	23, 9, 23
	rlwimi	20, 20, 24, 0, 31
	rlwimi	21, 21, 24, 0, 31
	rlwimi	22, 22, 24, 0, 31
	rlwimi	23, 23, 24, 0, 31
	xor	16, 16, 20
	xor	18, 18, 21
	xor	17, 17, 22
	xor	19, 19, 23
	rlwinm	20, 14, 2, 22, 29
	rlwinm	21, 12, 2, 22, 29
	rlwinm	22, 15, 2, 22, 29
	rlwinm	23, 11, 2, 22, 29
	lwzx	20, 9, 20
	lwzx	21, 9, 21
	lwzx	22, 9, 22
	lwzx	23, 9, 23
	rlwimi	20, 20, 16, 0, 31
	rlwimi	21, 21, 16, 0, 31
	rlwimi	22, 22, 16, 0, 31
	rlwimi	23, 23, 16, 0, 31
	ld	11, 0(28)
	ld	12, 8(28)
	xor	16, 16, 20
	xor	18, 18, 21
	xor	17, 17, 22
	xor	19, 19, 23
	addi	28, 28, 16
	rldimi	16, 18, 32, 0
	rldimi	17, 19, 32, 0
	#   XOR in Key Schedule
	xor	16, 16, 11
	xor	17, 17, 12
	ld	19, 0(10)
	ld	19, 64(10)
	ld	19, 128(10)
	ld	19, 192(10)
	ld	19, 256(10)
	ld	19, 320(10)
	ld	19, 384(10)
	ld	19, 448(10)
	ld	19, 512(10)
	ld	19, 576(10)
	ld	19, 640(10)
	ld	19, 704(10)
	ld	19, 768(10)
	ld	19, 832(10)
	ld	19, 896(10)
	ld	19, 960(10)
	rldicl	14, 16, 32, 56
	andi.   11, 17, 255
	rldicl	15, 17, 32, 56
	andi.   12, 16, 255
	lbzx	14, 10, 14
	lbzx	11, 10, 11
	lbzx	15, 10, 15
	lbzx	12, 10, 12
	rldimi	11, 14, 32, 24
	rldimi	12, 15, 32, 24
	rldicl	20, 17, 56, 56
	rldicl	21, 17, 24, 56
	rldicl	22, 16, 56, 56
	rldicl	23, 16, 24, 56
	lbzx	20, 10, 20
	lbzx	21, 10, 21
	lbzx	22, 10, 22
	lbzx	23, 10, 23
	rldimi	11, 20, 40, 16
	rlwimi	11, 21, 8, 16, 23
	rldimi	12, 22, 40, 16
	rlwimi	12, 23, 8, 16, 23
	rldicl	20, 17, 16, 56
	rldicl	21, 16, 48, 56
	rldicl	22, 16, 16, 56
	rldicl	23, 17, 48, 56
	lbzx	20, 10, 20
	lbzx	21, 10, 21
	lbzx	22, 10, 22
	lbzx	23, 10, 23
	rldimi	11, 20, 48, 8
	rlwimi	11, 21, 16, 8, 15
	rldimi	12, 22, 48, 8
	rlwimi	12, 23, 16, 8, 15
	rldicl	20, 16, 40, 56
	rldicl	21, 16, 8, 56
	rldicl	22, 17, 40, 56
	rldicl	23, 17, 8, 56
	lbzx	20, 10, 20
	lbzx	21, 10, 21
	lbzx	22, 10, 22
	lbzx	23, 10, 23
	ld	16, 0(28)
	ld	17, 8(28)
	rldimi	11, 20, 56, 0
	rlwimi	11, 21, 24, 0, 7
	rldimi	12, 22, 56, 0
	rlwimi	12, 23, 24, 0, 7
	addi	28, 28, 16
	#   XOR in Key Schedule
	xor	11, 11, 16
	xor	12, 12, 17
	xor	11, 11, 24
	xor	12, 12, 25
	std	11, 0(4)
	std	12, 8(4)
	addic.	5, 5, -16
	addi	3, 3, 16
	addi	4, 4, 16
	beq	L_AES_CBC_decrypt_end_dec_odd
	addi	28, 6, 0
	ld	24, 0(3)
	ld	25, 8(3)
	ld	16, 0(28)
	ld	17, 8(28)
	addi	28, 28, 16
	rldicr	11, 24, 32, 63
	rldicr	12, 25, 32, 63
	# Round: 0 - XOR in key schedule
	xor	11, 11, 16
	xor	12, 12, 17
	addi	0, 7, -2
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
	ld	19, 0(9)
	ld	19, 64(9)
	ld	19, 128(9)
	ld	19, 192(9)
	ld	19, 256(9)
	ld	19, 320(9)
	ld	19, 384(9)
	ld	19, 448(9)
	ld	19, 512(9)
	ld	19, 576(9)
	ld	19, 640(9)
	ld	19, 704(9)
	ld	19, 768(9)
	ld	19, 832(9)
	ld	19, 896(9)
	ld	19, 960(9)
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
	srwi	0, 0, 1
	mtctr	0
L_AES_CBC_decrypt_loop_nr_odd:
	srdi	14, 11, 32
	srdi	15, 12, 32
	rlwinm	16, 15, 18, 22, 29
	rlwinm	18, 11, 18, 22, 29
	rlwinm	17, 14, 18, 22, 29
	rlwinm	19, 12, 18, 22, 29
	lwzx	16, 9, 16
	lwzx	18, 9, 18
	lwzx	17, 9, 17
	lwzx	19, 9, 19
	rlwinm	20, 11, 10, 22, 29
	rlwinm	21, 14, 10, 22, 29
	rlwinm	22, 12, 10, 22, 29
	rlwinm	23, 15, 10, 22, 29
	lwzx	20, 9, 20
	lwzx	21, 9, 21
	lwzx	22, 9, 22
	lwzx	23, 9, 23
	rlwimi	20, 20, 8, 0, 31
	rlwimi	21, 21, 8, 0, 31
	rlwimi	22, 22, 8, 0, 31
	rlwimi	23, 23, 8, 0, 31
	xor	16, 16, 20
	xor	18, 18, 21
	xor	17, 17, 22
	xor	19, 19, 23
	rlwinm	20, 12, 26, 22, 29
	rlwinm	21, 15, 26, 22, 29
	rlwinm	22, 11, 26, 22, 29
	rlwinm	23, 14, 26, 22, 29
	lwzx	20, 9, 20
	lwzx	21, 9, 21
	lwzx	22, 9, 22
	lwzx	23, 9, 23
	rlwimi	20, 20, 24, 0, 31
	rlwimi	21, 21, 24, 0, 31
	rlwimi	22, 22, 24, 0, 31
	rlwimi	23, 23, 24, 0, 31
	xor	16, 16, 20
	xor	18, 18, 21
	xor	17, 17, 22
	xor	19, 19, 23
	rlwinm	20, 14, 2, 22, 29
	rlwinm	21, 12, 2, 22, 29
	rlwinm	22, 15, 2, 22, 29
	rlwinm	23, 11, 2, 22, 29
	lwzx	20, 9, 20
	lwzx	21, 9, 21
	lwzx	22, 9, 22
	lwzx	23, 9, 23
	rlwimi	20, 20, 16, 0, 31
	rlwimi	21, 21, 16, 0, 31
	rlwimi	22, 22, 16, 0, 31
	rlwimi	23, 23, 16, 0, 31
	ld	11, 0(28)
	ld	12, 8(28)
	xor	16, 16, 20
	xor	18, 18, 21
	xor	17, 17, 22
	xor	19, 19, 23
	addi	28, 28, 16
	rldimi	16, 18, 32, 0
	rldimi	17, 19, 32, 0
	#   XOR in Key Schedule
	xor	16, 16, 11
	xor	17, 17, 12
	srdi	18, 16, 32
	srdi	19, 17, 32
	rlwinm	11, 19, 18, 22, 29
	rlwinm	14, 16, 18, 22, 29
	rlwinm	12, 18, 18, 22, 29
	rlwinm	15, 17, 18, 22, 29
	lwzx	11, 9, 11
	lwzx	14, 9, 14
	lwzx	12, 9, 12
	lwzx	15, 9, 15
	rlwinm	20, 16, 10, 22, 29
	rlwinm	21, 18, 10, 22, 29
	rlwinm	22, 17, 10, 22, 29
	rlwinm	23, 19, 10, 22, 29
	lwzx	20, 9, 20
	lwzx	21, 9, 21
	lwzx	22, 9, 22
	lwzx	23, 9, 23
	rlwimi	20, 20, 8, 0, 31
	rlwimi	21, 21, 8, 0, 31
	rlwimi	22, 22, 8, 0, 31
	rlwimi	23, 23, 8, 0, 31
	xor	11, 11, 20
	xor	14, 14, 21
	xor	12, 12, 22
	xor	15, 15, 23
	rlwinm	20, 17, 26, 22, 29
	rlwinm	21, 19, 26, 22, 29
	rlwinm	22, 16, 26, 22, 29
	rlwinm	23, 18, 26, 22, 29
	lwzx	20, 9, 20
	lwzx	21, 9, 21
	lwzx	22, 9, 22
	lwzx	23, 9, 23
	rlwimi	20, 20, 24, 0, 31
	rlwimi	21, 21, 24, 0, 31
	rlwimi	22, 22, 24, 0, 31
	rlwimi	23, 23, 24, 0, 31
	xor	11, 11, 20
	xor	14, 14, 21
	xor	12, 12, 22
	xor	15, 15, 23
	rlwinm	20, 18, 2, 22, 29
	rlwinm	21, 17, 2, 22, 29
	rlwinm	22, 19, 2, 22, 29
	rlwinm	23, 16, 2, 22, 29
	lwzx	20, 9, 20
	lwzx	21, 9, 21
	lwzx	22, 9, 22
	lwzx	23, 9, 23
	rlwimi	20, 20, 16, 0, 31
	rlwimi	21, 21, 16, 0, 31
	rlwimi	22, 22, 16, 0, 31
	rlwimi	23, 23, 16, 0, 31
	ld	16, 0(28)
	ld	17, 8(28)
	xor	11, 11, 20
	xor	14, 14, 21
	xor	12, 12, 22
	xor	15, 15, 23
	addi	28, 28, 16
	rldimi	11, 14, 32, 0
	rldimi	12, 15, 32, 0
	#   XOR in Key Schedule
	xor	11, 11, 16
	xor	12, 12, 17
	bdnz	L_AES_CBC_decrypt_loop_nr_odd
	srdi	14, 11, 32
	srdi	15, 12, 32
	rlwinm	16, 15, 18, 22, 29
	rlwinm	18, 11, 18, 22, 29
	rlwinm	17, 14, 18, 22, 29
	rlwinm	19, 12, 18, 22, 29
	lwzx	16, 9, 16
	lwzx	18, 9, 18
	lwzx	17, 9, 17
	lwzx	19, 9, 19
	rlwinm	20, 11, 10, 22, 29
	rlwinm	21, 14, 10, 22, 29
	rlwinm	22, 12, 10, 22, 29
	rlwinm	23, 15, 10, 22, 29
	lwzx	20, 9, 20
	lwzx	21, 9, 21
	lwzx	22, 9, 22
	lwzx	23, 9, 23
	rlwimi	20, 20, 8, 0, 31
	rlwimi	21, 21, 8, 0, 31
	rlwimi	22, 22, 8, 0, 31
	rlwimi	23, 23, 8, 0, 31
	xor	16, 16, 20
	xor	18, 18, 21
	xor	17, 17, 22
	xor	19, 19, 23
	rlwinm	20, 12, 26, 22, 29
	rlwinm	21, 15, 26, 22, 29
	rlwinm	22, 11, 26, 22, 29
	rlwinm	23, 14, 26, 22, 29
	lwzx	20, 9, 20
	lwzx	21, 9, 21
	lwzx	22, 9, 22
	lwzx	23, 9, 23
	rlwimi	20, 20, 24, 0, 31
	rlwimi	21, 21, 24, 0, 31
	rlwimi	22, 22, 24, 0, 31
	rlwimi	23, 23, 24, 0, 31
	xor	16, 16, 20
	xor	18, 18, 21
	xor	17, 17, 22
	xor	19, 19, 23
	rlwinm	20, 14, 2, 22, 29
	rlwinm	21, 12, 2, 22, 29
	rlwinm	22, 15, 2, 22, 29
	rlwinm	23, 11, 2, 22, 29
	lwzx	20, 9, 20
	lwzx	21, 9, 21
	lwzx	22, 9, 22
	lwzx	23, 9, 23
	rlwimi	20, 20, 16, 0, 31
	rlwimi	21, 21, 16, 0, 31
	rlwimi	22, 22, 16, 0, 31
	rlwimi	23, 23, 16, 0, 31
	ld	11, 0(28)
	ld	12, 8(28)
	xor	16, 16, 20
	xor	18, 18, 21
	xor	17, 17, 22
	xor	19, 19, 23
	addi	28, 28, 16
	rldimi	16, 18, 32, 0
	rldimi	17, 19, 32, 0
	#   XOR in Key Schedule
	xor	16, 16, 11
	xor	17, 17, 12
	ld	19, 0(10)
	ld	19, 64(10)
	ld	19, 128(10)
	ld	19, 192(10)
	ld	19, 256(10)
	ld	19, 320(10)
	ld	19, 384(10)
	ld	19, 448(10)
	ld	19, 512(10)
	ld	19, 576(10)
	ld	19, 640(10)
	ld	19, 704(10)
	ld	19, 768(10)
	ld	19, 832(10)
	ld	19, 896(10)
	ld	19, 960(10)
	rldicl	14, 16, 32, 56
	andi.   11, 17, 255
	rldicl	15, 17, 32, 56
	andi.   12, 16, 255
	lbzx	14, 10, 14
	lbzx	11, 10, 11
	lbzx	15, 10, 15
	lbzx	12, 10, 12
	rldimi	11, 14, 32, 24
	rldimi	12, 15, 32, 24
	rldicl	20, 17, 56, 56
	rldicl	21, 17, 24, 56
	rldicl	22, 16, 56, 56
	rldicl	23, 16, 24, 56
	lbzx	20, 10, 20
	lbzx	21, 10, 21
	lbzx	22, 10, 22
	lbzx	23, 10, 23
	rldimi	11, 20, 40, 16
	rlwimi	11, 21, 8, 16, 23
	rldimi	12, 22, 40, 16
	rlwimi	12, 23, 8, 16, 23
	rldicl	20, 17, 16, 56
	rldicl	21, 16, 48, 56
	rldicl	22, 16, 16, 56
	rldicl	23, 17, 48, 56
	lbzx	20, 10, 20
	lbzx	21, 10, 21
	lbzx	22, 10, 22
	lbzx	23, 10, 23
	rldimi	11, 20, 48, 8
	rlwimi	11, 21, 16, 8, 15
	rldimi	12, 22, 48, 8
	rlwimi	12, 23, 16, 8, 15
	rldicl	20, 16, 40, 56
	rldicl	21, 16, 8, 56
	rldicl	22, 17, 40, 56
	rldicl	23, 17, 8, 56
	lbzx	20, 10, 20
	lbzx	21, 10, 21
	lbzx	22, 10, 22
	lbzx	23, 10, 23
	ld	16, 0(28)
	ld	17, 8(28)
	rldimi	11, 20, 56, 0
	rlwimi	11, 21, 24, 0, 7
	rldimi	12, 22, 56, 0
	rlwimi	12, 23, 24, 0, 7
	addi	28, 28, 16
	#   XOR in Key Schedule
	xor	11, 11, 16
	xor	12, 12, 17
	xor	11, 11, 26
	xor	12, 12, 27
	std	11, 0(4)
	std	12, 8(4)
	addic.	5, 5, -16
	addi	3, 3, 16
	addi	4, 4, 16
	bne	L_AES_CBC_decrypt_loop_block
	std	24, 0(8)
	std	25, 8(8)
	b	L_AES_CBC_decrypt_end_dec
L_AES_CBC_decrypt_end_dec_odd:
	std	26, 0(8)
	std	27, 8(8)
L_AES_CBC_decrypt_end_dec:
	ld	0, 120(1)
	mtlr	0
	ld	14, 0(1)
	ld	15, 8(1)
	ld	16, 16(1)
	ld	17, 24(1)
	ld	18, 32(1)
	ld	19, 40(1)
	ld	20, 48(1)
	ld	21, 56(1)
	ld	22, 64(1)
	ld	23, 72(1)
	ld	24, 80(1)
	ld	25, 88(1)
	ld	26, 96(1)
	ld	27, 104(1)
	ld	28, 112(1)
	addi	1, 1, 0x80
	blr
#ifndef __APPLE__
	.size	AES_CBC_decrypt,.-AES_CBC_decrypt
#endif /* __APPLE__ */
#endif /* HAVE_AES_CBC */
#endif /* WOLFSSL_AES_DIRECT || WOLFSSL_AES_COUNTER || HAVE_AES_CBC
        * HAVE_AES_ECB */
#ifdef WOLFSSL_AES_XTS
#ifndef __APPLE__
.text
.globl	AES_XTS_decrypt
.type	AES_XTS_decrypt,@function
.align	16
AES_XTS_decrypt:
#if defined(_CALL_ELF) && _CALL_ELF == 2
0:	addis	2, 12, .TOC.-0b@ha
	addi	2, 2, .TOC.-0b@l
	.localentry	AES_XTS_decrypt, .-AES_XTS_decrypt
#endif
#else
.section	__TEXT,__text
.globl	_AES_XTS_decrypt
.p2align	4
_AES_XTS_decrypt:
#endif /* __APPLE__ */
	stdu	1, -136(1)
	mflr	0
	std	0, 128(1)
	std	14, 0(1)
	std	15, 8(1)
	std	16, 16(1)
	std	17, 24(1)
	std	18, 32(1)
	std	19, 40(1)
	std	20, 48(1)
	std	21, 56(1)
	std	22, 64(1)
	std	23, 72(1)
	std	24, 80(1)
	std	25, 88(1)
	std	26, 96(1)
	std	27, 104(1)
	std	28, 112(1)
	std	29, 120(1)
	addis	14, 2, L_AES_PPC64_te4_0@toc@ha
	addi	14, 14, L_AES_PPC64_te4_0@toc@l
	addi	15, 14, 0x400
	addi	16, 14, 0x800
	addi	17, 14, 0xc00
	andi.   18, 5, 15
	addi	18, 18, 15
	andi.   18, 18, 16
	subf	5, 18, 5
	ld	26, 0(6)
	ld	27, 8(6)
	ld	18, 0(8)
	ld	19, 8(8)
	addi	8, 8, 16
	rldicr	26, 26, 32, 63
	rldicr	27, 27, 32, 63
	# Round: 0 - XOR in key schedule
	xor	26, 26, 18
	xor	27, 27, 19
	addi	0, 10, -2
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
	ld	21, 0(14)
	ld	21, 32(14)
	ld	21, 64(14)
	ld	21, 96(14)
	ld	21, 128(14)
	ld	21, 160(14)
	ld	21, 192(14)
	ld	21, 224(14)
	ld	21, 256(14)
	ld	21, 288(14)
	ld	21, 320(14)
	ld	21, 352(14)
	ld	21, 384(14)
	ld	21, 416(14)
	ld	21, 448(14)
	ld	21, 480(14)
	ld	21, 512(14)
	ld	21, 544(14)
	ld	21, 576(14)
	ld	21, 608(14)
	ld	21, 640(14)
	ld	21, 672(14)
	ld	21, 704(14)
	ld	21, 736(14)
	ld	21, 768(14)
	ld	21, 800(14)
	ld	21, 832(14)
	ld	21, 864(14)
	ld	21, 896(14)
	ld	21, 928(14)
	ld	21, 960(14)
	ld	21, 992(14)
	ld	21, 1024(14)
	ld	21, 1056(14)
	ld	21, 1088(14)
	ld	21, 1120(14)
	ld	21, 1152(14)
	ld	21, 1184(14)
	ld	21, 1216(14)
	ld	21, 1248(14)
	ld	21, 1280(14)
	ld	21, 1312(14)
	ld	21, 1344(14)
	ld	21, 1376(14)
	ld	21, 1408(14)
	ld	21, 1440(14)
	ld	21, 1472(14)
	ld	21, 1504(14)
	ld	21, 1536(14)
	ld	21, 1568(14)
	ld	21, 1600(14)
	ld	21, 1632(14)
	ld	21, 1664(14)
	ld	21, 1696(14)
	ld	21, 1728(14)
	ld	21, 1760(14)
	ld	21, 1792(14)
	ld	21, 1824(14)
	ld	21, 1856(14)
	ld	21, 1888(14)
	ld	21, 1920(14)
	ld	21, 1952(14)
	ld	21, 1984(14)
	ld	21, 2016(14)
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
	srwi	0, 0, 1
	mtctr	0
L_AES_XTS_decrypt_loop_nr_tweak:
	srdi	28, 26, 32
	srdi	29, 27, 32
	rlwinm	18, 26, 10, 22, 29
	rlwinm	19, 27, 10, 22, 29
	rlwinm	20, 28, 10, 22, 29
	rlwinm	21, 29, 10, 22, 29
	lwzx	18, 14, 18
	lwzx	19, 14, 19
	lwzx	20, 14, 20
	lwzx	21, 14, 21
	rlwinm	22, 28, 18, 22, 29
	rlwinm	23, 27, 18, 22, 29
	rlwinm	24, 29, 18, 22, 29
	rlwinm	25, 26, 18, 22, 29
	lwzx	22, 15, 22
	lwzx	23, 15, 23
	lwzx	24, 15, 24
	lwzx	25, 15, 25
	xor	18, 18, 22
	xor	20, 20, 23
	xor	19, 19, 24
	xor	21, 21, 25
	rlwinm	22, 27, 26, 22, 29
	rlwinm	23, 29, 26, 22, 29
	rlwinm	24, 26, 26, 22, 29
	rlwinm	25, 28, 26, 22, 29
	lwzx	22, 16, 22
	lwzx	23, 16, 23
	lwzx	24, 16, 24
	lwzx	25, 16, 25
	xor	18, 18, 22
	xor	20, 20, 23
	xor	19, 19, 24
	xor	21, 21, 25
	rlwinm	22, 29, 2, 22, 29
	rlwinm	23, 26, 2, 22, 29
	rlwinm	24, 28, 2, 22, 29
	rlwinm	25, 27, 2, 22, 29
	lwzx	22, 17, 22
	lwzx	23, 17, 23
	lwzx	24, 17, 24
	lwzx	25, 17, 25
	xor	18, 18, 22
	xor	20, 20, 23
	xor	19, 19, 24
	xor	21, 21, 25
	ld	26, 0(8)
	ld	27, 8(8)
	rldimi	18, 20, 32, 0
	rldimi	19, 21, 32, 0
	addi	8, 8, 16
	#   XOR in Key Schedule
	xor	18, 18, 26
	xor	19, 19, 27
	srdi	20, 18, 32
	srdi	21, 19, 32
	rlwinm	26, 18, 10, 22, 29
	rlwinm	27, 19, 10, 22, 29
	rlwinm	28, 20, 10, 22, 29
	rlwinm	29, 21, 10, 22, 29
	lwzx	26, 14, 26
	lwzx	27, 14, 27
	lwzx	28, 14, 28
	lwzx	29, 14, 29
	rlwinm	22, 20, 18, 22, 29
	rlwinm	23, 19, 18, 22, 29
	rlwinm	24, 21, 18, 22, 29
	rlwinm	25, 18, 18, 22, 29
	lwzx	22, 15, 22
	lwzx	23, 15, 23
	lwzx	24, 15, 24
	lwzx	25, 15, 25
	xor	26, 26, 22
	xor	28, 28, 23
	xor	27, 27, 24
	xor	29, 29, 25
	rlwinm	22, 19, 26, 22, 29
	rlwinm	23, 21, 26, 22, 29
	rlwinm	24, 18, 26, 22, 29
	rlwinm	25, 20, 26, 22, 29
	lwzx	22, 16, 22
	lwzx	23, 16, 23
	lwzx	24, 16, 24
	lwzx	25, 16, 25
	xor	26, 26, 22
	xor	28, 28, 23
	xor	27, 27, 24
	xor	29, 29, 25
	rlwinm	22, 21, 2, 22, 29
	rlwinm	23, 18, 2, 22, 29
	rlwinm	24, 20, 2, 22, 29
	rlwinm	25, 19, 2, 22, 29
	lwzx	22, 17, 22
	lwzx	23, 17, 23
	lwzx	24, 17, 24
	lwzx	25, 17, 25
	xor	26, 26, 22
	xor	28, 28, 23
	xor	27, 27, 24
	xor	29, 29, 25
	ld	18, 0(8)
	ld	19, 8(8)
	rldimi	26, 28, 32, 0
	rldimi	27, 29, 32, 0
	addi	8, 8, 16
	#   XOR in Key Schedule
	xor	26, 26, 18
	xor	27, 27, 19
	bdnz	L_AES_XTS_decrypt_loop_nr_tweak
	srdi	28, 26, 32
	srdi	29, 27, 32
	rlwinm	18, 26, 10, 22, 29
	rlwinm	19, 27, 10, 22, 29
	rlwinm	20, 28, 10, 22, 29
	rlwinm	21, 29, 10, 22, 29
	lwzx	18, 14, 18
	lwzx	19, 14, 19
	lwzx	20, 14, 20
	lwzx	21, 14, 21
	rlwinm	22, 28, 18, 22, 29
	rlwinm	23, 27, 18, 22, 29
	rlwinm	24, 29, 18, 22, 29
	rlwinm	25, 26, 18, 22, 29
	lwzx	22, 15, 22
	lwzx	23, 15, 23
	lwzx	24, 15, 24
	lwzx	25, 15, 25
	xor	18, 18, 22
	xor	20, 20, 23
	xor	19, 19, 24
	xor	21, 21, 25
	rlwinm	22, 27, 26, 22, 29
	rlwinm	23, 29, 26, 22, 29
	rlwinm	24, 26, 26, 22, 29
	rlwinm	25, 28, 26, 22, 29
	lwzx	22, 16, 22
	lwzx	23, 16, 23
	lwzx	24, 16, 24
	lwzx	25, 16, 25
	xor	18, 18, 22
	xor	20, 20, 23
	xor	19, 19, 24
	xor	21, 21, 25
	rlwinm	22, 29, 2, 22, 29
	rlwinm	23, 26, 2, 22, 29
	rlwinm	24, 28, 2, 22, 29
	rlwinm	25, 27, 2, 22, 29
	lwzx	22, 17, 22
	lwzx	23, 17, 23
	lwzx	24, 17, 24
	lwzx	25, 17, 25
	xor	18, 18, 22
	xor	20, 20, 23
	xor	19, 19, 24
	xor	21, 21, 25
	ld	26, 0(8)
	ld	27, 8(8)
	rldimi	18, 20, 32, 0
	rldimi	19, 21, 32, 0
	addi	8, 8, 16
	#   XOR in Key Schedule
	xor	18, 18, 26
	xor	19, 19, 27
	srdi	20, 18, 32
	srdi	21, 19, 32
	rlwinm	26, 18, 2, 22, 29
	rlwinm	27, 19, 2, 22, 29
	rlwinm	29, 20, 2, 22, 29
	rlwinm	28, 21, 2, 22, 29
	lwzx	26, 15, 26
	lwzx	27, 15, 27
	lwzx	29, 15, 29
	lwzx	28, 15, 28
	rlwinm	22, 19, 26, 22, 29
	rlwinm	23, 21, 26, 22, 29
	rldimi	27, 29, 32, 24
	rldimi	26, 28, 32, 24
	rlwinm	24, 18, 26, 22, 29
	rlwinm	25, 20, 26, 22, 29
	lwzx	22, 15, 22
	lwzx	23, 15, 23
	lwzx	24, 15, 24
	lwzx	25, 15, 25
	rldimi	26, 22, 40, 16
	rlwimi	26, 23, 8, 16, 23
	rldimi	27, 24, 40, 16
	rlwimi	27, 25, 8, 16, 23
	rlwinm	22, 20, 18, 22, 29
	rlwinm	23, 19, 18, 22, 29
	rlwinm	24, 21, 18, 22, 29
	rlwinm	25, 18, 18, 22, 29
	lwzx	22, 15, 22
	lwzx	23, 15, 23
	lwzx	24, 15, 24
	lwzx	25, 15, 25
	rldimi	26, 22, 48, 8
	rlwimi	26, 23, 16, 8, 15
	rldimi	27, 24, 48, 8
	rlwimi	27, 25, 16, 8, 15
	rlwinm	22, 18, 10, 22, 29
	rlwinm	23, 20, 10, 22, 29
	rlwinm	24, 19, 10, 22, 29
	rlwinm	25, 21, 10, 22, 29
	lwzx	22, 15, 22
	lwzx	23, 15, 23
	lwzx	24, 15, 24
	lwzx	25, 15, 25
	ld	18, 0(8)
	ld	19, 8(8)
	rldimi	26, 22, 56, 0
	rlwimi	26, 23, 24, 0, 7
	rldimi	27, 24, 56, 0
	rlwimi	27, 25, 24, 0, 7
	addi	8, 8, 16
	#   XOR in Key Schedule
	xor	26, 26, 18
	xor	27, 27, 19
	std	26, 0(9)
	std	27, 8(9)
	addis	11, 2, L_AES_PPC64_td@toc@ha
	addi	11, 11, L_AES_PPC64_td@toc@l
	addis	12, 2, L_AES_PPC64_td4@toc@ha
	addi	12, 12, L_AES_PPC64_td4@toc@l
	cmpdi	5, 16
	blt	L_AES_XTS_decrypt_start_partail
L_AES_XTS_decrypt_loop_block:
	addi	8, 7, 0
	ld	14, 0(3)
	ld	15, 8(3)
	ld	18, 0(8)
	ld	19, 8(8)
	addi	8, 8, 16
	xor	14, 14, 26
	xor	15, 15, 27
	rldicr	14, 14, 32, 63
	rldicr	15, 15, 32, 63
	# Round: 0 - XOR in key schedule
	xor	14, 14, 18
	xor	15, 15, 19
	addi	0, 10, -2
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
	ld	21, 0(11)
	ld	21, 64(11)
	ld	21, 128(11)
	ld	21, 192(11)
	ld	21, 256(11)
	ld	21, 320(11)
	ld	21, 384(11)
	ld	21, 448(11)
	ld	21, 512(11)
	ld	21, 576(11)
	ld	21, 640(11)
	ld	21, 704(11)
	ld	21, 768(11)
	ld	21, 832(11)
	ld	21, 896(11)
	ld	21, 960(11)
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
	srwi	0, 0, 1
	mtctr	0
L_AES_XTS_decrypt_loop_nr:
	srdi	16, 14, 32
	srdi	17, 15, 32
	rlwinm	18, 17, 18, 22, 29
	rlwinm	20, 14, 18, 22, 29
	rlwinm	19, 16, 18, 22, 29
	rlwinm	21, 15, 18, 22, 29
	lwzx	18, 11, 18
	lwzx	20, 11, 20
	lwzx	19, 11, 19
	lwzx	21, 11, 21
	rlwinm	22, 14, 10, 22, 29
	rlwinm	23, 16, 10, 22, 29
	rlwinm	24, 15, 10, 22, 29
	rlwinm	25, 17, 10, 22, 29
	lwzx	22, 11, 22
	lwzx	23, 11, 23
	lwzx	24, 11, 24
	lwzx	25, 11, 25
	rlwimi	22, 22, 8, 0, 31
	rlwimi	23, 23, 8, 0, 31
	rlwimi	24, 24, 8, 0, 31
	rlwimi	25, 25, 8, 0, 31
	xor	18, 18, 22
	xor	20, 20, 23
	xor	19, 19, 24
	xor	21, 21, 25
	rlwinm	22, 15, 26, 22, 29
	rlwinm	23, 17, 26, 22, 29
	rlwinm	24, 14, 26, 22, 29
	rlwinm	25, 16, 26, 22, 29
	lwzx	22, 11, 22
	lwzx	23, 11, 23
	lwzx	24, 11, 24
	lwzx	25, 11, 25
	rlwimi	22, 22, 24, 0, 31
	rlwimi	23, 23, 24, 0, 31
	rlwimi	24, 24, 24, 0, 31
	rlwimi	25, 25, 24, 0, 31
	xor	18, 18, 22
	xor	20, 20, 23
	xor	19, 19, 24
	xor	21, 21, 25
	rlwinm	22, 16, 2, 22, 29
	rlwinm	23, 15, 2, 22, 29
	rlwinm	24, 17, 2, 22, 29
	rlwinm	25, 14, 2, 22, 29
	lwzx	22, 11, 22
	lwzx	23, 11, 23
	lwzx	24, 11, 24
	lwzx	25, 11, 25
	rlwimi	22, 22, 16, 0, 31
	rlwimi	23, 23, 16, 0, 31
	rlwimi	24, 24, 16, 0, 31
	rlwimi	25, 25, 16, 0, 31
	ld	14, 0(8)
	ld	15, 8(8)
	xor	18, 18, 22
	xor	20, 20, 23
	xor	19, 19, 24
	xor	21, 21, 25
	addi	8, 8, 16
	rldimi	18, 20, 32, 0
	rldimi	19, 21, 32, 0
	#   XOR in Key Schedule
	xor	18, 18, 14
	xor	19, 19, 15
	srdi	20, 18, 32
	srdi	21, 19, 32
	rlwinm	14, 21, 18, 22, 29
	rlwinm	16, 18, 18, 22, 29
	rlwinm	15, 20, 18, 22, 29
	rlwinm	17, 19, 18, 22, 29
	lwzx	14, 11, 14
	lwzx	16, 11, 16
	lwzx	15, 11, 15
	lwzx	17, 11, 17
	rlwinm	22, 18, 10, 22, 29
	rlwinm	23, 20, 10, 22, 29
	rlwinm	24, 19, 10, 22, 29
	rlwinm	25, 21, 10, 22, 29
	lwzx	22, 11, 22
	lwzx	23, 11, 23
	lwzx	24, 11, 24
	lwzx	25, 11, 25
	rlwimi	22, 22, 8, 0, 31
	rlwimi	23, 23, 8, 0, 31
	rlwimi	24, 24, 8, 0, 31
	rlwimi	25, 25, 8, 0, 31
	xor	14, 14, 22
	xor	16, 16, 23
	xor	15, 15, 24
	xor	17, 17, 25
	rlwinm	22, 19, 26, 22, 29
	rlwinm	23, 21, 26, 22, 29
	rlwinm	24, 18, 26, 22, 29
	rlwinm	25, 20, 26, 22, 29
	lwzx	22, 11, 22
	lwzx	23, 11, 23
	lwzx	24, 11, 24
	lwzx	25, 11, 25
	rlwimi	22, 22, 24, 0, 31
	rlwimi	23, 23, 24, 0, 31
	rlwimi	24, 24, 24, 0, 31
	rlwimi	25, 25, 24, 0, 31
	xor	14, 14, 22
	xor	16, 16, 23
	xor	15, 15, 24
	xor	17, 17, 25
	rlwinm	22, 20, 2, 22, 29
	rlwinm	23, 19, 2, 22, 29
	rlwinm	24, 21, 2, 22, 29
	rlwinm	25, 18, 2, 22, 29
	lwzx	22, 11, 22
	lwzx	23, 11, 23
	lwzx	24, 11, 24
	lwzx	25, 11, 25
	rlwimi	22, 22, 16, 0, 31
	rlwimi	23, 23, 16, 0, 31
	rlwimi	24, 24, 16, 0, 31
	rlwimi	25, 25, 16, 0, 31
	ld	18, 0(8)
	ld	19, 8(8)
	xor	14, 14, 22
	xor	16, 16, 23
	xor	15, 15, 24
	xor	17, 17, 25
	addi	8, 8, 16
	rldimi	14, 16, 32, 0
	rldimi	15, 17, 32, 0
	#   XOR in Key Schedule
	xor	14, 14, 18
	xor	15, 15, 19
	bdnz	L_AES_XTS_decrypt_loop_nr
	srdi	16, 14, 32
	srdi	17, 15, 32
	rlwinm	18, 17, 18, 22, 29
	rlwinm	20, 14, 18, 22, 29
	rlwinm	19, 16, 18, 22, 29
	rlwinm	21, 15, 18, 22, 29
	lwzx	18, 11, 18
	lwzx	20, 11, 20
	lwzx	19, 11, 19
	lwzx	21, 11, 21
	rlwinm	22, 14, 10, 22, 29
	rlwinm	23, 16, 10, 22, 29
	rlwinm	24, 15, 10, 22, 29
	rlwinm	25, 17, 10, 22, 29
	lwzx	22, 11, 22
	lwzx	23, 11, 23
	lwzx	24, 11, 24
	lwzx	25, 11, 25
	rlwimi	22, 22, 8, 0, 31
	rlwimi	23, 23, 8, 0, 31
	rlwimi	24, 24, 8, 0, 31
	rlwimi	25, 25, 8, 0, 31
	xor	18, 18, 22
	xor	20, 20, 23
	xor	19, 19, 24
	xor	21, 21, 25
	rlwinm	22, 15, 26, 22, 29
	rlwinm	23, 17, 26, 22, 29
	rlwinm	24, 14, 26, 22, 29
	rlwinm	25, 16, 26, 22, 29
	lwzx	22, 11, 22
	lwzx	23, 11, 23
	lwzx	24, 11, 24
	lwzx	25, 11, 25
	rlwimi	22, 22, 24, 0, 31
	rlwimi	23, 23, 24, 0, 31
	rlwimi	24, 24, 24, 0, 31
	rlwimi	25, 25, 24, 0, 31
	xor	18, 18, 22
	xor	20, 20, 23
	xor	19, 19, 24
	xor	21, 21, 25
	rlwinm	22, 16, 2, 22, 29
	rlwinm	23, 15, 2, 22, 29
	rlwinm	24, 17, 2, 22, 29
	rlwinm	25, 14, 2, 22, 29
	lwzx	22, 11, 22
	lwzx	23, 11, 23
	lwzx	24, 11, 24
	lwzx	25, 11, 25
	rlwimi	22, 22, 16, 0, 31
	rlwimi	23, 23, 16, 0, 31
	rlwimi	24, 24, 16, 0, 31
	rlwimi	25, 25, 16, 0, 31
	ld	14, 0(8)
	ld	15, 8(8)
	xor	18, 18, 22
	xor	20, 20, 23
	xor	19, 19, 24
	xor	21, 21, 25
	addi	8, 8, 16
	rldimi	18, 20, 32, 0
	rldimi	19, 21, 32, 0
	#   XOR in Key Schedule
	xor	18, 18, 14
	xor	19, 19, 15
	ld	21, 0(12)
	ld	21, 64(12)
	ld	21, 128(12)
	ld	21, 192(12)
	ld	21, 256(12)
	ld	21, 320(12)
	ld	21, 384(12)
	ld	21, 448(12)
	ld	21, 512(12)
	ld	21, 576(12)
	ld	21, 640(12)
	ld	21, 704(12)
	ld	21, 768(12)
	ld	21, 832(12)
	ld	21, 896(12)
	ld	21, 960(12)
	rldicl	16, 18, 32, 56
	andi.   14, 19, 255
	rldicl	17, 19, 32, 56
	andi.   15, 18, 255
	lbzx	16, 12, 16
	lbzx	14, 12, 14
	lbzx	17, 12, 17
	lbzx	15, 12, 15
	rldimi	14, 16, 32, 24
	rldimi	15, 17, 32, 24
	rldicl	22, 19, 56, 56
	rldicl	23, 19, 24, 56
	rldicl	24, 18, 56, 56
	rldicl	25, 18, 24, 56
	lbzx	22, 12, 22
	lbzx	23, 12, 23
	lbzx	24, 12, 24
	lbzx	25, 12, 25
	rldimi	14, 22, 40, 16
	rlwimi	14, 23, 8, 16, 23
	rldimi	15, 24, 40, 16
	rlwimi	15, 25, 8, 16, 23
	rldicl	22, 19, 16, 56
	rldicl	23, 18, 48, 56
	rldicl	24, 18, 16, 56
	rldicl	25, 19, 48, 56
	lbzx	22, 12, 22
	lbzx	23, 12, 23
	lbzx	24, 12, 24
	lbzx	25, 12, 25
	rldimi	14, 22, 48, 8
	rlwimi	14, 23, 16, 8, 15
	rldimi	15, 24, 48, 8
	rlwimi	15, 25, 16, 8, 15
	rldicl	22, 18, 40, 56
	rldicl	23, 18, 8, 56
	rldicl	24, 19, 40, 56
	rldicl	25, 19, 8, 56
	lbzx	22, 12, 22
	lbzx	23, 12, 23
	lbzx	24, 12, 24
	lbzx	25, 12, 25
	ld	18, 0(8)
	ld	19, 8(8)
	rldimi	14, 22, 56, 0
	rlwimi	14, 23, 24, 0, 7
	rldimi	15, 24, 56, 0
	rlwimi	15, 25, 24, 0, 7
	addi	8, 8, 16
	#   XOR in Key Schedule
	xor	14, 14, 18
	xor	15, 15, 19
	xor	14, 14, 26
	xor	15, 15, 27
	li	17, 8
	ldbrx	26, 0, 9
	ldbrx	27, 9, 17
	std	14, 0(4)
	std	15, 8(4)
	sradi	22, 27, 63
	srdi	23, 26, 63
	sldi	27, 27, 1
	andi.	22, 22, 0x87
	sldi	26, 26, 1
	xor	27, 27, 23
	xor	26, 26, 22
	stdbrx	26, 0, 9
	stdbrx	27, 9, 17
	ld	26, 0(9)
	ld	27, 8(9)
	addi	5, 5, -16
	addi	3, 3, 16
	addi	4, 4, 16
	cmpdi	5, 16
	bge	L_AES_XTS_decrypt_loop_block
	cmpdi	5, 0
	beq	L_AES_XTS_decrypt_done_data
L_AES_XTS_decrypt_start_partail:
	li	17, 8
	ldbrx	28, 0, 9
	ldbrx	29, 9, 17
	sradi	22, 29, 63
	srdi	23, 28, 63
	sldi	29, 29, 1
	andi.	22, 22, 0x87
	sldi	28, 28, 1
	xor	29, 29, 23
	xor	28, 28, 22
	stdbrx	28, 0, 9
	stdbrx	29, 9, 17
	ld	28, 0(9)
	ld	29, 8(9)
	addi	8, 7, 0
	ld	14, 0(3)
	ld	15, 8(3)
	addi	3, 3, 16
	ld	18, 0(8)
	ld	19, 8(8)
	addi	8, 8, 16
	xor	14, 14, 28
	xor	15, 15, 29
	rldicr	14, 14, 32, 63
	rldicr	15, 15, 32, 63
	# Round: 0 - XOR in key schedule
	xor	14, 14, 18
	xor	15, 15, 19
	addi	0, 10, -2
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
	ld	21, 0(11)
	ld	21, 64(11)
	ld	21, 128(11)
	ld	21, 192(11)
	ld	21, 256(11)
	ld	21, 320(11)
	ld	21, 384(11)
	ld	21, 448(11)
	ld	21, 512(11)
	ld	21, 576(11)
	ld	21, 640(11)
	ld	21, 704(11)
	ld	21, 768(11)
	ld	21, 832(11)
	ld	21, 896(11)
	ld	21, 960(11)
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
	srwi	0, 0, 1
	mtctr	0
L_AES_XTS_decrypt_loop_nr_partial_1:
	srdi	16, 14, 32
	srdi	17, 15, 32
	rlwinm	18, 17, 18, 22, 29
	rlwinm	20, 14, 18, 22, 29
	rlwinm	19, 16, 18, 22, 29
	rlwinm	21, 15, 18, 22, 29
	lwzx	18, 11, 18
	lwzx	20, 11, 20
	lwzx	19, 11, 19
	lwzx	21, 11, 21
	rlwinm	22, 14, 10, 22, 29
	rlwinm	23, 16, 10, 22, 29
	rlwinm	24, 15, 10, 22, 29
	rlwinm	25, 17, 10, 22, 29
	lwzx	22, 11, 22
	lwzx	23, 11, 23
	lwzx	24, 11, 24
	lwzx	25, 11, 25
	rlwimi	22, 22, 8, 0, 31
	rlwimi	23, 23, 8, 0, 31
	rlwimi	24, 24, 8, 0, 31
	rlwimi	25, 25, 8, 0, 31
	xor	18, 18, 22
	xor	20, 20, 23
	xor	19, 19, 24
	xor	21, 21, 25
	rlwinm	22, 15, 26, 22, 29
	rlwinm	23, 17, 26, 22, 29
	rlwinm	24, 14, 26, 22, 29
	rlwinm	25, 16, 26, 22, 29
	lwzx	22, 11, 22
	lwzx	23, 11, 23
	lwzx	24, 11, 24
	lwzx	25, 11, 25
	rlwimi	22, 22, 24, 0, 31
	rlwimi	23, 23, 24, 0, 31
	rlwimi	24, 24, 24, 0, 31
	rlwimi	25, 25, 24, 0, 31
	xor	18, 18, 22
	xor	20, 20, 23
	xor	19, 19, 24
	xor	21, 21, 25
	rlwinm	22, 16, 2, 22, 29
	rlwinm	23, 15, 2, 22, 29
	rlwinm	24, 17, 2, 22, 29
	rlwinm	25, 14, 2, 22, 29
	lwzx	22, 11, 22
	lwzx	23, 11, 23
	lwzx	24, 11, 24
	lwzx	25, 11, 25
	rlwimi	22, 22, 16, 0, 31
	rlwimi	23, 23, 16, 0, 31
	rlwimi	24, 24, 16, 0, 31
	rlwimi	25, 25, 16, 0, 31
	ld	14, 0(8)
	ld	15, 8(8)
	xor	18, 18, 22
	xor	20, 20, 23
	xor	19, 19, 24
	xor	21, 21, 25
	addi	8, 8, 16
	rldimi	18, 20, 32, 0
	rldimi	19, 21, 32, 0
	#   XOR in Key Schedule
	xor	18, 18, 14
	xor	19, 19, 15
	srdi	20, 18, 32
	srdi	21, 19, 32
	rlwinm	14, 21, 18, 22, 29
	rlwinm	16, 18, 18, 22, 29
	rlwinm	15, 20, 18, 22, 29
	rlwinm	17, 19, 18, 22, 29
	lwzx	14, 11, 14
	lwzx	16, 11, 16
	lwzx	15, 11, 15
	lwzx	17, 11, 17
	rlwinm	22, 18, 10, 22, 29
	rlwinm	23, 20, 10, 22, 29
	rlwinm	24, 19, 10, 22, 29
	rlwinm	25, 21, 10, 22, 29
	lwzx	22, 11, 22
	lwzx	23, 11, 23
	lwzx	24, 11, 24
	lwzx	25, 11, 25
	rlwimi	22, 22, 8, 0, 31
	rlwimi	23, 23, 8, 0, 31
	rlwimi	24, 24, 8, 0, 31
	rlwimi	25, 25, 8, 0, 31
	xor	14, 14, 22
	xor	16, 16, 23
	xor	15, 15, 24
	xor	17, 17, 25
	rlwinm	22, 19, 26, 22, 29
	rlwinm	23, 21, 26, 22, 29
	rlwinm	24, 18, 26, 22, 29
	rlwinm	25, 20, 26, 22, 29
	lwzx	22, 11, 22
	lwzx	23, 11, 23
	lwzx	24, 11, 24
	lwzx	25, 11, 25
	rlwimi	22, 22, 24, 0, 31
	rlwimi	23, 23, 24, 0, 31
	rlwimi	24, 24, 24, 0, 31
	rlwimi	25, 25, 24, 0, 31
	xor	14, 14, 22
	xor	16, 16, 23
	xor	15, 15, 24
	xor	17, 17, 25
	rlwinm	22, 20, 2, 22, 29
	rlwinm	23, 19, 2, 22, 29
	rlwinm	24, 21, 2, 22, 29
	rlwinm	25, 18, 2, 22, 29
	lwzx	22, 11, 22
	lwzx	23, 11, 23
	lwzx	24, 11, 24
	lwzx	25, 11, 25
	rlwimi	22, 22, 16, 0, 31
	rlwimi	23, 23, 16, 0, 31
	rlwimi	24, 24, 16, 0, 31
	rlwimi	25, 25, 16, 0, 31
	ld	18, 0(8)
	ld	19, 8(8)
	xor	14, 14, 22
	xor	16, 16, 23
	xor	15, 15, 24
	xor	17, 17, 25
	addi	8, 8, 16
	rldimi	14, 16, 32, 0
	rldimi	15, 17, 32, 0
	#   XOR in Key Schedule
	xor	14, 14, 18
	xor	15, 15, 19
	bdnz	L_AES_XTS_decrypt_loop_nr_partial_1
	srdi	16, 14, 32
	srdi	17, 15, 32
	rlwinm	18, 17, 18, 22, 29
	rlwinm	20, 14, 18, 22, 29
	rlwinm	19, 16, 18, 22, 29
	rlwinm	21, 15, 18, 22, 29
	lwzx	18, 11, 18
	lwzx	20, 11, 20
	lwzx	19, 11, 19
	lwzx	21, 11, 21
	rlwinm	22, 14, 10, 22, 29
	rlwinm	23, 16, 10, 22, 29
	rlwinm	24, 15, 10, 22, 29
	rlwinm	25, 17, 10, 22, 29
	lwzx	22, 11, 22
	lwzx	23, 11, 23
	lwzx	24, 11, 24
	lwzx	25, 11, 25
	rlwimi	22, 22, 8, 0, 31
	rlwimi	23, 23, 8, 0, 31
	rlwimi	24, 24, 8, 0, 31
	rlwimi	25, 25, 8, 0, 31
	xor	18, 18, 22
	xor	20, 20, 23
	xor	19, 19, 24
	xor	21, 21, 25
	rlwinm	22, 15, 26, 22, 29
	rlwinm	23, 17, 26, 22, 29
	rlwinm	24, 14, 26, 22, 29
	rlwinm	25, 16, 26, 22, 29
	lwzx	22, 11, 22
	lwzx	23, 11, 23
	lwzx	24, 11, 24
	lwzx	25, 11, 25
	rlwimi	22, 22, 24, 0, 31
	rlwimi	23, 23, 24, 0, 31
	rlwimi	24, 24, 24, 0, 31
	rlwimi	25, 25, 24, 0, 31
	xor	18, 18, 22
	xor	20, 20, 23
	xor	19, 19, 24
	xor	21, 21, 25
	rlwinm	22, 16, 2, 22, 29
	rlwinm	23, 15, 2, 22, 29
	rlwinm	24, 17, 2, 22, 29
	rlwinm	25, 14, 2, 22, 29
	lwzx	22, 11, 22
	lwzx	23, 11, 23
	lwzx	24, 11, 24
	lwzx	25, 11, 25
	rlwimi	22, 22, 16, 0, 31
	rlwimi	23, 23, 16, 0, 31
	rlwimi	24, 24, 16, 0, 31
	rlwimi	25, 25, 16, 0, 31
	ld	14, 0(8)
	ld	15, 8(8)
	xor	18, 18, 22
	xor	20, 20, 23
	xor	19, 19, 24
	xor	21, 21, 25
	addi	8, 8, 16
	rldimi	18, 20, 32, 0
	rldimi	19, 21, 32, 0
	#   XOR in Key Schedule
	xor	18, 18, 14
	xor	19, 19, 15
	ld	21, 0(12)
	ld	21, 64(12)
	ld	21, 128(12)
	ld	21, 192(12)
	ld	21, 256(12)
	ld	21, 320(12)
	ld	21, 384(12)
	ld	21, 448(12)
	ld	21, 512(12)
	ld	21, 576(12)
	ld	21, 640(12)
	ld	21, 704(12)
	ld	21, 768(12)
	ld	21, 832(12)
	ld	21, 896(12)
	ld	21, 960(12)
	rldicl	16, 18, 32, 56
	andi.   14, 19, 255
	rldicl	17, 19, 32, 56
	andi.   15, 18, 255
	lbzx	16, 12, 16
	lbzx	14, 12, 14
	lbzx	17, 12, 17
	lbzx	15, 12, 15
	rldimi	14, 16, 32, 24
	rldimi	15, 17, 32, 24
	rldicl	22, 19, 56, 56
	rldicl	23, 19, 24, 56
	rldicl	24, 18, 56, 56
	rldicl	25, 18, 24, 56
	lbzx	22, 12, 22
	lbzx	23, 12, 23
	lbzx	24, 12, 24
	lbzx	25, 12, 25
	rldimi	14, 22, 40, 16
	rlwimi	14, 23, 8, 16, 23
	rldimi	15, 24, 40, 16
	rlwimi	15, 25, 8, 16, 23
	rldicl	22, 19, 16, 56
	rldicl	23, 18, 48, 56
	rldicl	24, 18, 16, 56
	rldicl	25, 19, 48, 56
	lbzx	22, 12, 22
	lbzx	23, 12, 23
	lbzx	24, 12, 24
	lbzx	25, 12, 25
	rldimi	14, 22, 48, 8
	rlwimi	14, 23, 16, 8, 15
	rldimi	15, 24, 48, 8
	rlwimi	15, 25, 16, 8, 15
	rldicl	22, 18, 40, 56
	rldicl	23, 18, 8, 56
	rldicl	24, 19, 40, 56
	rldicl	25, 19, 8, 56
	lbzx	22, 12, 22
	lbzx	23, 12, 23
	lbzx	24, 12, 24
	lbzx	25, 12, 25
	ld	18, 0(8)
	ld	19, 8(8)
	rldimi	14, 22, 56, 0
	rlwimi	14, 23, 24, 0, 7
	rldimi	15, 24, 56, 0
	rlwimi	15, 25, 24, 0, 7
	addi	8, 8, 16
	#   XOR in Key Schedule
	xor	14, 14, 18
	xor	15, 15, 19
	xor	14, 14, 28
	xor	15, 15, 29
	std	14, 0(9)
	std	15, 8(9)
	addi	4, 4, 16
	addi	18, 5, 0
L_AES_XTS_decrypt_start_byte:
	lbz	22, 0(9)
	lbz	23, 0(3)
	addi	3, 3, 1
	stb	22, 0(4)
	addi	4, 4, 1
	stb	23, 0(9)
	addi	9, 9, 1
	addic.	18, 18, -1
	bne	L_AES_XTS_decrypt_start_byte
	subf	4, 5, 4
	subf	9, 5, 9
	addi	4, 4, -16
	addi	8, 7, 0
	ld	14, 0(9)
	ld	15, 8(9)
	ld	18, 0(8)
	ld	19, 8(8)
	addi	8, 8, 16
	xor	14, 14, 26
	xor	15, 15, 27
	rldicr	14, 14, 32, 63
	rldicr	15, 15, 32, 63
	# Round: 0 - XOR in key schedule
	xor	14, 14, 18
	xor	15, 15, 19
	addi	0, 10, -2
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
	ld	21, 0(11)
	ld	21, 64(11)
	ld	21, 128(11)
	ld	21, 192(11)
	ld	21, 256(11)
	ld	21, 320(11)
	ld	21, 384(11)
	ld	21, 448(11)
	ld	21, 512(11)
	ld	21, 576(11)
	ld	21, 640(11)
	ld	21, 704(11)
	ld	21, 768(11)
	ld	21, 832(11)
	ld	21, 896(11)
	ld	21, 960(11)
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
	srwi	0, 0, 1
	mtctr	0
L_AES_XTS_decrypt_loop_nr_partial_2:
	srdi	16, 14, 32
	srdi	17, 15, 32
	rlwinm	18, 17, 18, 22, 29
	rlwinm	20, 14, 18, 22, 29
	rlwinm	19, 16, 18, 22, 29
	rlwinm	21, 15, 18, 22, 29
	lwzx	18, 11, 18
	lwzx	20, 11, 20
	lwzx	19, 11, 19
	lwzx	21, 11, 21
	rlwinm	22, 14, 10, 22, 29
	rlwinm	23, 16, 10, 22, 29
	rlwinm	24, 15, 10, 22, 29
	rlwinm	25, 17, 10, 22, 29
	lwzx	22, 11, 22
	lwzx	23, 11, 23
	lwzx	24, 11, 24
	lwzx	25, 11, 25
	rlwimi	22, 22, 8, 0, 31
	rlwimi	23, 23, 8, 0, 31
	rlwimi	24, 24, 8, 0, 31
	rlwimi	25, 25, 8, 0, 31
	xor	18, 18, 22
	xor	20, 20, 23
	xor	19, 19, 24
	xor	21, 21, 25
	rlwinm	22, 15, 26, 22, 29
	rlwinm	23, 17, 26, 22, 29
	rlwinm	24, 14, 26, 22, 29
	rlwinm	25, 16, 26, 22, 29
	lwzx	22, 11, 22
	lwzx	23, 11, 23
	lwzx	24, 11, 24
	lwzx	25, 11, 25
	rlwimi	22, 22, 24, 0, 31
	rlwimi	23, 23, 24, 0, 31
	rlwimi	24, 24, 24, 0, 31
	rlwimi	25, 25, 24, 0, 31
	xor	18, 18, 22
	xor	20, 20, 23
	xor	19, 19, 24
	xor	21, 21, 25
	rlwinm	22, 16, 2, 22, 29
	rlwinm	23, 15, 2, 22, 29
	rlwinm	24, 17, 2, 22, 29
	rlwinm	25, 14, 2, 22, 29
	lwzx	22, 11, 22
	lwzx	23, 11, 23
	lwzx	24, 11, 24
	lwzx	25, 11, 25
	rlwimi	22, 22, 16, 0, 31
	rlwimi	23, 23, 16, 0, 31
	rlwimi	24, 24, 16, 0, 31
	rlwimi	25, 25, 16, 0, 31
	ld	14, 0(8)
	ld	15, 8(8)
	xor	18, 18, 22
	xor	20, 20, 23
	xor	19, 19, 24
	xor	21, 21, 25
	addi	8, 8, 16
	rldimi	18, 20, 32, 0
	rldimi	19, 21, 32, 0
	#   XOR in Key Schedule
	xor	18, 18, 14
	xor	19, 19, 15
	srdi	20, 18, 32
	srdi	21, 19, 32
	rlwinm	14, 21, 18, 22, 29
	rlwinm	16, 18, 18, 22, 29
	rlwinm	15, 20, 18, 22, 29
	rlwinm	17, 19, 18, 22, 29
	lwzx	14, 11, 14
	lwzx	16, 11, 16
	lwzx	15, 11, 15
	lwzx	17, 11, 17
	rlwinm	22, 18, 10, 22, 29
	rlwinm	23, 20, 10, 22, 29
	rlwinm	24, 19, 10, 22, 29
	rlwinm	25, 21, 10, 22, 29
	lwzx	22, 11, 22
	lwzx	23, 11, 23
	lwzx	24, 11, 24
	lwzx	25, 11, 25
	rlwimi	22, 22, 8, 0, 31
	rlwimi	23, 23, 8, 0, 31
	rlwimi	24, 24, 8, 0, 31
	rlwimi	25, 25, 8, 0, 31
	xor	14, 14, 22
	xor	16, 16, 23
	xor	15, 15, 24
	xor	17, 17, 25
	rlwinm	22, 19, 26, 22, 29
	rlwinm	23, 21, 26, 22, 29
	rlwinm	24, 18, 26, 22, 29
	rlwinm	25, 20, 26, 22, 29
	lwzx	22, 11, 22
	lwzx	23, 11, 23
	lwzx	24, 11, 24
	lwzx	25, 11, 25
	rlwimi	22, 22, 24, 0, 31
	rlwimi	23, 23, 24, 0, 31
	rlwimi	24, 24, 24, 0, 31
	rlwimi	25, 25, 24, 0, 31
	xor	14, 14, 22
	xor	16, 16, 23
	xor	15, 15, 24
	xor	17, 17, 25
	rlwinm	22, 20, 2, 22, 29
	rlwinm	23, 19, 2, 22, 29
	rlwinm	24, 21, 2, 22, 29
	rlwinm	25, 18, 2, 22, 29
	lwzx	22, 11, 22
	lwzx	23, 11, 23
	lwzx	24, 11, 24
	lwzx	25, 11, 25
	rlwimi	22, 22, 16, 0, 31
	rlwimi	23, 23, 16, 0, 31
	rlwimi	24, 24, 16, 0, 31
	rlwimi	25, 25, 16, 0, 31
	ld	18, 0(8)
	ld	19, 8(8)
	xor	14, 14, 22
	xor	16, 16, 23
	xor	15, 15, 24
	xor	17, 17, 25
	addi	8, 8, 16
	rldimi	14, 16, 32, 0
	rldimi	15, 17, 32, 0
	#   XOR in Key Schedule
	xor	14, 14, 18
	xor	15, 15, 19
	bdnz	L_AES_XTS_decrypt_loop_nr_partial_2
	srdi	16, 14, 32
	srdi	17, 15, 32
	rlwinm	18, 17, 18, 22, 29
	rlwinm	20, 14, 18, 22, 29
	rlwinm	19, 16, 18, 22, 29
	rlwinm	21, 15, 18, 22, 29
	lwzx	18, 11, 18
	lwzx	20, 11, 20
	lwzx	19, 11, 19
	lwzx	21, 11, 21
	rlwinm	22, 14, 10, 22, 29
	rlwinm	23, 16, 10, 22, 29
	rlwinm	24, 15, 10, 22, 29
	rlwinm	25, 17, 10, 22, 29
	lwzx	22, 11, 22
	lwzx	23, 11, 23
	lwzx	24, 11, 24
	lwzx	25, 11, 25
	rlwimi	22, 22, 8, 0, 31
	rlwimi	23, 23, 8, 0, 31
	rlwimi	24, 24, 8, 0, 31
	rlwimi	25, 25, 8, 0, 31
	xor	18, 18, 22
	xor	20, 20, 23
	xor	19, 19, 24
	xor	21, 21, 25
	rlwinm	22, 15, 26, 22, 29
	rlwinm	23, 17, 26, 22, 29
	rlwinm	24, 14, 26, 22, 29
	rlwinm	25, 16, 26, 22, 29
	lwzx	22, 11, 22
	lwzx	23, 11, 23
	lwzx	24, 11, 24
	lwzx	25, 11, 25
	rlwimi	22, 22, 24, 0, 31
	rlwimi	23, 23, 24, 0, 31
	rlwimi	24, 24, 24, 0, 31
	rlwimi	25, 25, 24, 0, 31
	xor	18, 18, 22
	xor	20, 20, 23
	xor	19, 19, 24
	xor	21, 21, 25
	rlwinm	22, 16, 2, 22, 29
	rlwinm	23, 15, 2, 22, 29
	rlwinm	24, 17, 2, 22, 29
	rlwinm	25, 14, 2, 22, 29
	lwzx	22, 11, 22
	lwzx	23, 11, 23
	lwzx	24, 11, 24
	lwzx	25, 11, 25
	rlwimi	22, 22, 16, 0, 31
	rlwimi	23, 23, 16, 0, 31
	rlwimi	24, 24, 16, 0, 31
	rlwimi	25, 25, 16, 0, 31
	ld	14, 0(8)
	ld	15, 8(8)
	xor	18, 18, 22
	xor	20, 20, 23
	xor	19, 19, 24
	xor	21, 21, 25
	addi	8, 8, 16
	rldimi	18, 20, 32, 0
	rldimi	19, 21, 32, 0
	#   XOR in Key Schedule
	xor	18, 18, 14
	xor	19, 19, 15
	ld	21, 0(12)
	ld	21, 64(12)
	ld	21, 128(12)
	ld	21, 192(12)
	ld	21, 256(12)
	ld	21, 320(12)
	ld	21, 384(12)
	ld	21, 448(12)
	ld	21, 512(12)
	ld	21, 576(12)
	ld	21, 640(12)
	ld	21, 704(12)
	ld	21, 768(12)
	ld	21, 832(12)
	ld	21, 896(12)
	ld	21, 960(12)
	rldicl	16, 18, 32, 56
	andi.   14, 19, 255
	rldicl	17, 19, 32, 56
	andi.   15, 18, 255
	lbzx	16, 12, 16
	lbzx	14, 12, 14
	lbzx	17, 12, 17
	lbzx	15, 12, 15
	rldimi	14, 16, 32, 24
	rldimi	15, 17, 32, 24
	rldicl	22, 19, 56, 56
	rldicl	23, 19, 24, 56
	rldicl	24, 18, 56, 56
	rldicl	25, 18, 24, 56
	lbzx	22, 12, 22
	lbzx	23, 12, 23
	lbzx	24, 12, 24
	lbzx	25, 12, 25
	rldimi	14, 22, 40, 16
	rlwimi	14, 23, 8, 16, 23
	rldimi	15, 24, 40, 16
	rlwimi	15, 25, 8, 16, 23
	rldicl	22, 19, 16, 56
	rldicl	23, 18, 48, 56
	rldicl	24, 18, 16, 56
	rldicl	25, 19, 48, 56
	lbzx	22, 12, 22
	lbzx	23, 12, 23
	lbzx	24, 12, 24
	lbzx	25, 12, 25
	rldimi	14, 22, 48, 8
	rlwimi	14, 23, 16, 8, 15
	rldimi	15, 24, 48, 8
	rlwimi	15, 25, 16, 8, 15
	rldicl	22, 18, 40, 56
	rldicl	23, 18, 8, 56
	rldicl	24, 19, 40, 56
	rldicl	25, 19, 8, 56
	lbzx	22, 12, 22
	lbzx	23, 12, 23
	lbzx	24, 12, 24
	lbzx	25, 12, 25
	ld	18, 0(8)
	ld	19, 8(8)
	rldimi	14, 22, 56, 0
	rlwimi	14, 23, 24, 0, 7
	rldimi	15, 24, 56, 0
	rlwimi	15, 25, 24, 0, 7
	addi	8, 8, 16
	#   XOR in Key Schedule
	xor	14, 14, 18
	xor	15, 15, 19
	xor	14, 14, 26
	xor	15, 15, 27
	std	14, 0(4)
	std	15, 8(4)
L_AES_XTS_decrypt_done_data:
	ld	0, 128(1)
	mtlr	0
	ld	14, 0(1)
	ld	15, 8(1)
	ld	16, 16(1)
	ld	17, 24(1)
	ld	18, 32(1)
	ld	19, 40(1)
	ld	20, 48(1)
	ld	21, 56(1)
	ld	22, 64(1)
	ld	23, 72(1)
	ld	24, 80(1)
	ld	25, 88(1)
	ld	26, 96(1)
	ld	27, 104(1)
	ld	28, 112(1)
	ld	29, 120(1)
	addi	1, 1, 0x88
	blr
#ifndef __APPLE__
	.size	AES_XTS_decrypt,.-AES_XTS_decrypt
#endif /* __APPLE__ */
#endif /* WOLFSSL_AES_XTS */
#endif /* HAVE_AES_DECRYPT */
#ifdef HAVE_AESGCM
#ifdef GCM_TABLE_4BIT
#ifndef __APPLE__
	.text
	.type	L_GCM_gmult_len_r, %object
	.size	L_GCM_gmult_len_r, 128
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
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
	.long	0x00000000,0x01c20000,0x03840000,0x02460000
	.long	0x07080000,0x06ca0000,0x048c0000,0x054e0000
	.long	0x0e100000,0x0fd20000,0x0d940000,0x0c560000
	.long	0x09180000,0x08da0000,0x0a9c0000,0x0b5e0000
#ifndef __APPLE__
.text
.globl	GCM_gmult_len
.type	GCM_gmult_len,@function
.align	16
GCM_gmult_len:
#if defined(_CALL_ELF) && _CALL_ELF == 2
0:	addis	2, 12, .TOC.-0b@ha
	addi	2, 2, .TOC.-0b@l
	.localentry	GCM_gmult_len, .-GCM_gmult_len
#endif
#else
.section	__TEXT,__text
.globl	_GCM_gmult_len
.p2align	4
_GCM_gmult_len:
#endif /* __APPLE__ */
	stdu	1, -104(1)
	mflr	0
	std	0, 96(1)
	std	14, 0(1)
	std	15, 8(1)
	std	16, 16(1)
	std	17, 24(1)
	std	18, 32(1)
	std	19, 40(1)
	std	20, 48(1)
	std	21, 56(1)
	std	22, 64(1)
	std	23, 72(1)
	std	24, 80(1)
	std	25, 88(1)
	li	21, 0x100
	li	25, 8
	addis	7, 2, L_GCM_gmult_len_r@toc@ha
	addi	7, 7, L_GCM_gmult_len_r@toc@l
	add	21, 21, 4
	addi	20, 4, 8
	addi	22, 21, 8
	addi	8, 7, 0x40
L_GCM_gmult_len_start_block:
	ldbrx	18, 0, 3
	ldbrx	19, 25, 3
	ldbrx	9, 0, 5
	ldbrx	10, 25, 5
	xor	18, 18, 9
	xor	19, 19, 10
	rldicr	0, 19, 32, 63
	# Byte 15
	rlwinm	23, 0, 12, 24, 27
	rlwinm	24, 0, 8, 24, 27
	ldx	14, 23, 4
	ldx	15, 23, 20
	ldx	11, 24, 21
	ldx	12, 24, 22
	ldx	10, 24, 20
	rldicl	16, 15, 60, 60
	rldic	17, 15, 2, 58
	srdi	15, 15, 8
	rldimi	15, 14, 56, 0
	srdi	14, 14, 8
	lwzx	9, 17, 8
	xor	16, 16, 10
	xor	14, 14, 11
	rlwinm	16, 16, 2, 26, 29
	lwzx	10, 16, 7
	xor	15, 15, 12
	sldi	9, 9, 32
	xor	14, 14, 9
	sldi	10, 10, 32
	xor	14, 14, 10
	# Byte 14
	rlwinm	23, 0, 20, 24, 27
	rlwinm	24, 0, 16, 24, 27
	ldx	9, 23, 4
	ldx	10, 23, 20
	ldx	11, 24, 21
	ldx	12, 24, 22
	xor	14, 14, 9
	xor	15, 15, 10
	ldx	10, 24, 20
	rldicl	16, 15, 60, 60
	rldic	17, 15, 2, 58
	srdi	15, 15, 8
	rldimi	15, 14, 56, 0
	srdi	14, 14, 8
	lwzx	9, 17, 8
	xor	16, 16, 10
	xor	14, 14, 11
	rlwinm	16, 16, 2, 26, 29
	lwzx	10, 16, 7
	xor	15, 15, 12
	sldi	9, 9, 32
	xor	14, 14, 9
	sldi	10, 10, 32
	xor	14, 14, 10
	# Byte 13
	rlwinm	23, 0, 28, 24, 27
	rlwinm	24, 0, 24, 24, 27
	ldx	9, 23, 4
	ldx	10, 23, 20
	ldx	11, 24, 21
	ldx	12, 24, 22
	xor	14, 14, 9
	xor	15, 15, 10
	ldx	10, 24, 20
	rldicl	16, 15, 60, 60
	rldic	17, 15, 2, 58
	srdi	15, 15, 8
	rldimi	15, 14, 56, 0
	srdi	14, 14, 8
	lwzx	9, 17, 8
	xor	16, 16, 10
	xor	14, 14, 11
	rlwinm	16, 16, 2, 26, 29
	lwzx	10, 16, 7
	xor	15, 15, 12
	sldi	9, 9, 32
	xor	14, 14, 9
	sldi	10, 10, 32
	xor	14, 14, 10
	# Byte 12
	rlwinm	23, 0, 4, 24, 27
	rlwinm	24, 0, 0, 24, 27
	ldx	9, 23, 4
	ldx	10, 23, 20
	ldx	11, 24, 21
	ldx	12, 24, 22
	xor	14, 14, 9
	xor	15, 15, 10
	ldx	10, 24, 20
	rldicl	16, 15, 60, 60
	rldic	17, 15, 2, 58
	srdi	15, 15, 8
	rldimi	15, 14, 56, 0
	srdi	14, 14, 8
	lwzx	9, 17, 8
	xor	16, 16, 10
	xor	14, 14, 11
	rlwinm	16, 16, 2, 26, 29
	lwzx	10, 16, 7
	xor	15, 15, 12
	sldi	9, 9, 32
	xor	14, 14, 9
	sldi	10, 10, 32
	xor	14, 14, 10
	# Byte 11
	rlwinm	23, 19, 12, 24, 27
	rlwinm	24, 19, 8, 24, 27
	ldx	9, 23, 4
	ldx	10, 23, 20
	ldx	11, 24, 21
	ldx	12, 24, 22
	xor	14, 14, 9
	xor	15, 15, 10
	ldx	10, 24, 20
	rldicl	16, 15, 60, 60
	rldic	17, 15, 2, 58
	srdi	15, 15, 8
	rldimi	15, 14, 56, 0
	srdi	14, 14, 8
	lwzx	9, 17, 8
	xor	16, 16, 10
	xor	14, 14, 11
	rlwinm	16, 16, 2, 26, 29
	lwzx	10, 16, 7
	xor	15, 15, 12
	sldi	9, 9, 32
	xor	14, 14, 9
	sldi	10, 10, 32
	xor	14, 14, 10
	# Byte 10
	rlwinm	23, 19, 20, 24, 27
	rlwinm	24, 19, 16, 24, 27
	ldx	9, 23, 4
	ldx	10, 23, 20
	ldx	11, 24, 21
	ldx	12, 24, 22
	xor	14, 14, 9
	xor	15, 15, 10
	ldx	10, 24, 20
	rldicl	16, 15, 60, 60
	rldic	17, 15, 2, 58
	srdi	15, 15, 8
	rldimi	15, 14, 56, 0
	srdi	14, 14, 8
	lwzx	9, 17, 8
	xor	16, 16, 10
	xor	14, 14, 11
	rlwinm	16, 16, 2, 26, 29
	lwzx	10, 16, 7
	xor	15, 15, 12
	sldi	9, 9, 32
	xor	14, 14, 9
	sldi	10, 10, 32
	xor	14, 14, 10
	# Byte 9
	rlwinm	23, 19, 28, 24, 27
	rlwinm	24, 19, 24, 24, 27
	ldx	9, 23, 4
	ldx	10, 23, 20
	ldx	11, 24, 21
	ldx	12, 24, 22
	xor	14, 14, 9
	xor	15, 15, 10
	ldx	10, 24, 20
	rldicl	16, 15, 60, 60
	rldic	17, 15, 2, 58
	srdi	15, 15, 8
	rldimi	15, 14, 56, 0
	srdi	14, 14, 8
	lwzx	9, 17, 8
	xor	16, 16, 10
	xor	14, 14, 11
	rlwinm	16, 16, 2, 26, 29
	lwzx	10, 16, 7
	xor	15, 15, 12
	sldi	9, 9, 32
	xor	14, 14, 9
	sldi	10, 10, 32
	xor	14, 14, 10
	# Byte 8
	rlwinm	23, 19, 4, 24, 27
	rlwinm	24, 19, 0, 24, 27
	ldx	9, 23, 4
	ldx	10, 23, 20
	ldx	11, 24, 21
	ldx	12, 24, 22
	xor	14, 14, 9
	xor	15, 15, 10
	ldx	10, 24, 20
	rldicl	16, 15, 60, 60
	rldic	17, 15, 2, 58
	srdi	15, 15, 8
	rldimi	15, 14, 56, 0
	srdi	14, 14, 8
	lwzx	9, 17, 8
	xor	16, 16, 10
	xor	14, 14, 11
	rlwinm	16, 16, 2, 26, 29
	lwzx	10, 16, 7
	xor	15, 15, 12
	sldi	9, 9, 32
	xor	14, 14, 9
	sldi	10, 10, 32
	xor	14, 14, 10
	rldicr	0, 18, 32, 63
	# Byte 7
	rlwinm	23, 0, 12, 24, 27
	rlwinm	24, 0, 8, 24, 27
	ldx	9, 23, 4
	ldx	10, 23, 20
	ldx	11, 24, 21
	ldx	12, 24, 22
	xor	14, 14, 9
	xor	15, 15, 10
	ldx	10, 24, 20
	rldicl	16, 15, 60, 60
	rldic	17, 15, 2, 58
	srdi	15, 15, 8
	rldimi	15, 14, 56, 0
	srdi	14, 14, 8
	lwzx	9, 17, 8
	xor	16, 16, 10
	xor	14, 14, 11
	rlwinm	16, 16, 2, 26, 29
	lwzx	10, 16, 7
	xor	15, 15, 12
	sldi	9, 9, 32
	xor	14, 14, 9
	sldi	10, 10, 32
	xor	14, 14, 10
	# Byte 6
	rlwinm	23, 0, 20, 24, 27
	rlwinm	24, 0, 16, 24, 27
	ldx	9, 23, 4
	ldx	10, 23, 20
	ldx	11, 24, 21
	ldx	12, 24, 22
	xor	14, 14, 9
	xor	15, 15, 10
	ldx	10, 24, 20
	rldicl	16, 15, 60, 60
	rldic	17, 15, 2, 58
	srdi	15, 15, 8
	rldimi	15, 14, 56, 0
	srdi	14, 14, 8
	lwzx	9, 17, 8
	xor	16, 16, 10
	xor	14, 14, 11
	rlwinm	16, 16, 2, 26, 29
	lwzx	10, 16, 7
	xor	15, 15, 12
	sldi	9, 9, 32
	xor	14, 14, 9
	sldi	10, 10, 32
	xor	14, 14, 10
	# Byte 5
	rlwinm	23, 0, 28, 24, 27
	rlwinm	24, 0, 24, 24, 27
	ldx	9, 23, 4
	ldx	10, 23, 20
	ldx	11, 24, 21
	ldx	12, 24, 22
	xor	14, 14, 9
	xor	15, 15, 10
	ldx	10, 24, 20
	rldicl	16, 15, 60, 60
	rldic	17, 15, 2, 58
	srdi	15, 15, 8
	rldimi	15, 14, 56, 0
	srdi	14, 14, 8
	lwzx	9, 17, 8
	xor	16, 16, 10
	xor	14, 14, 11
	rlwinm	16, 16, 2, 26, 29
	lwzx	10, 16, 7
	xor	15, 15, 12
	sldi	9, 9, 32
	xor	14, 14, 9
	sldi	10, 10, 32
	xor	14, 14, 10
	# Byte 4
	rlwinm	23, 0, 4, 24, 27
	rlwinm	24, 0, 0, 24, 27
	ldx	9, 23, 4
	ldx	10, 23, 20
	ldx	11, 24, 21
	ldx	12, 24, 22
	xor	14, 14, 9
	xor	15, 15, 10
	ldx	10, 24, 20
	rldicl	16, 15, 60, 60
	rldic	17, 15, 2, 58
	srdi	15, 15, 8
	rldimi	15, 14, 56, 0
	srdi	14, 14, 8
	lwzx	9, 17, 8
	xor	16, 16, 10
	xor	14, 14, 11
	rlwinm	16, 16, 2, 26, 29
	lwzx	10, 16, 7
	xor	15, 15, 12
	sldi	9, 9, 32
	xor	14, 14, 9
	sldi	10, 10, 32
	xor	14, 14, 10
	# Byte 3
	rlwinm	23, 18, 12, 24, 27
	rlwinm	24, 18, 8, 24, 27
	ldx	9, 23, 4
	ldx	10, 23, 20
	ldx	11, 24, 21
	ldx	12, 24, 22
	xor	14, 14, 9
	xor	15, 15, 10
	ldx	10, 24, 20
	rldicl	16, 15, 60, 60
	rldic	17, 15, 2, 58
	srdi	15, 15, 8
	rldimi	15, 14, 56, 0
	srdi	14, 14, 8
	lwzx	9, 17, 8
	xor	16, 16, 10
	xor	14, 14, 11
	rlwinm	16, 16, 2, 26, 29
	lwzx	10, 16, 7
	xor	15, 15, 12
	sldi	9, 9, 32
	xor	14, 14, 9
	sldi	10, 10, 32
	xor	14, 14, 10
	# Byte 2
	rlwinm	23, 18, 20, 24, 27
	rlwinm	24, 18, 16, 24, 27
	ldx	9, 23, 4
	ldx	10, 23, 20
	ldx	11, 24, 21
	ldx	12, 24, 22
	xor	14, 14, 9
	xor	15, 15, 10
	ldx	10, 24, 20
	rldicl	16, 15, 60, 60
	rldic	17, 15, 2, 58
	srdi	15, 15, 8
	rldimi	15, 14, 56, 0
	srdi	14, 14, 8
	lwzx	9, 17, 8
	xor	16, 16, 10
	xor	14, 14, 11
	rlwinm	16, 16, 2, 26, 29
	lwzx	10, 16, 7
	xor	15, 15, 12
	sldi	9, 9, 32
	xor	14, 14, 9
	sldi	10, 10, 32
	xor	14, 14, 10
	# Byte 1
	rlwinm	23, 18, 28, 24, 27
	rlwinm	24, 18, 24, 24, 27
	ldx	9, 23, 4
	ldx	10, 23, 20
	ldx	11, 24, 21
	ldx	12, 24, 22
	xor	14, 14, 9
	xor	15, 15, 10
	ldx	10, 24, 20
	rldicl	16, 15, 60, 60
	rldic	17, 15, 2, 58
	srdi	15, 15, 8
	rldimi	15, 14, 56, 0
	srdi	14, 14, 8
	lwzx	9, 17, 8
	xor	16, 16, 10
	xor	14, 14, 11
	rlwinm	16, 16, 2, 26, 29
	lwzx	10, 16, 7
	xor	15, 15, 12
	sldi	9, 9, 32
	xor	14, 14, 9
	sldi	10, 10, 32
	xor	14, 14, 10
	# Byte 0
	rlwinm	23, 18, 4, 24, 27
	rlwinm	24, 18, 0, 24, 27
	ldx	9, 23, 4
	ldx	10, 23, 20
	ldx	11, 24, 4
	ldx	12, 24, 20
	xor	14, 14, 9
	xor	15, 15, 10
	rldic	16, 15, 2, 58
	srdi	15, 15, 4
	lwzx	9, 16, 7
	rldimi	15, 14, 60, 0
	srdi	14, 14, 4
	xor	19, 15, 12
	xor	14, 14, 11
	sldi	9, 9, 32
	xor	18, 14, 9
	addi	5, 5, 16
	addic.	6, 6, -16
	std	18, 0(3)
	std	19, 8(3)
	bne	L_GCM_gmult_len_start_block
	ld	0, 96(1)
	mtlr	0
	ld	14, 0(1)
	ld	15, 8(1)
	ld	16, 16(1)
	ld	17, 24(1)
	ld	18, 32(1)
	ld	19, 40(1)
	ld	20, 48(1)
	ld	21, 56(1)
	ld	22, 64(1)
	ld	23, 72(1)
	ld	24, 80(1)
	ld	25, 88(1)
	addi	1, 1, 0x68
	blr
#ifndef __APPLE__
	.size	GCM_gmult_len,.-GCM_gmult_len
#endif /* __APPLE__ */
#endif /* GCM_TABLE_4BIT */
#ifdef GCM_TABLE
#ifndef __APPLE__
	.text
	.type	L_GCM_gmult_len_r, %object
	.size	L_GCM_gmult_len_r, 512
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_GCM_gmult_len_r:
	.byte	0x00,0x00,0xc2,0x01,0x84,0x03,0x46,0x02
	.byte	0x08,0x07,0xca,0x06,0x8c,0x04,0x4e,0x05
	.byte	0x10,0x0e,0xd2,0x0f,0x94,0x0d,0x56,0x0c
	.byte	0x18,0x09,0xda,0x08,0x9c,0x0a,0x5e,0x0b
	.byte	0x20,0x1c,0xe2,0x1d,0xa4,0x1f,0x66,0x1e
	.byte	0x28,0x1b,0xea,0x1a,0xac,0x18,0x6e,0x19
	.byte	0x30,0x12,0xf2,0x13,0xb4,0x11,0x76,0x10
	.byte	0x38,0x15,0xfa,0x14,0xbc,0x16,0x7e,0x17
	.byte	0x40,0x38,0x82,0x39,0xc4,0x3b,0x06,0x3a
	.byte	0x48,0x3f,0x8a,0x3e,0xcc,0x3c,0x0e,0x3d
	.byte	0x50,0x36,0x92,0x37,0xd4,0x35,0x16,0x34
	.byte	0x58,0x31,0x9a,0x30,0xdc,0x32,0x1e,0x33
	.byte	0x60,0x24,0xa2,0x25,0xe4,0x27,0x26,0x26
	.byte	0x68,0x23,0xaa,0x22,0xec,0x20,0x2e,0x21
	.byte	0x70,0x2a,0xb2,0x2b,0xf4,0x29,0x36,0x28
	.byte	0x78,0x2d,0xba,0x2c,0xfc,0x2e,0x3e,0x2f
	.byte	0x80,0x70,0x42,0x71,0x04,0x73,0xc6,0x72
	.byte	0x88,0x77,0x4a,0x76,0x0c,0x74,0xce,0x75
	.byte	0x90,0x7e,0x52,0x7f,0x14,0x7d,0xd6,0x7c
	.byte	0x98,0x79,0x5a,0x78,0x1c,0x7a,0xde,0x7b
	.byte	0xa0,0x6c,0x62,0x6d,0x24,0x6f,0xe6,0x6e
	.byte	0xa8,0x6b,0x6a,0x6a,0x2c,0x68,0xee,0x69
	.byte	0xb0,0x62,0x72,0x63,0x34,0x61,0xf6,0x60
	.byte	0xb8,0x65,0x7a,0x64,0x3c,0x66,0xfe,0x67
	.byte	0xc0,0x48,0x02,0x49,0x44,0x4b,0x86,0x4a
	.byte	0xc8,0x4f,0x0a,0x4e,0x4c,0x4c,0x8e,0x4d
	.byte	0xd0,0x46,0x12,0x47,0x54,0x45,0x96,0x44
	.byte	0xd8,0x41,0x1a,0x40,0x5c,0x42,0x9e,0x43
	.byte	0xe0,0x54,0x22,0x55,0x64,0x57,0xa6,0x56
	.byte	0xe8,0x53,0x2a,0x52,0x6c,0x50,0xae,0x51
	.byte	0xf0,0x5a,0x32,0x5b,0x74,0x59,0xb6,0x58
	.byte	0xf8,0x5d,0x3a,0x5c,0x7c,0x5e,0xbe,0x5f
	.byte	0x00,0xe1,0xc2,0xe0,0x84,0xe2,0x46,0xe3
	.byte	0x08,0xe6,0xca,0xe7,0x8c,0xe5,0x4e,0xe4
	.byte	0x10,0xef,0xd2,0xee,0x94,0xec,0x56,0xed
	.byte	0x18,0xe8,0xda,0xe9,0x9c,0xeb,0x5e,0xea
	.byte	0x20,0xfd,0xe2,0xfc,0xa4,0xfe,0x66,0xff
	.byte	0x28,0xfa,0xea,0xfb,0xac,0xf9,0x6e,0xf8
	.byte	0x30,0xf3,0xf2,0xf2,0xb4,0xf0,0x76,0xf1
	.byte	0x38,0xf4,0xfa,0xf5,0xbc,0xf7,0x7e,0xf6
	.byte	0x40,0xd9,0x82,0xd8,0xc4,0xda,0x06,0xdb
	.byte	0x48,0xde,0x8a,0xdf,0xcc,0xdd,0x0e,0xdc
	.byte	0x50,0xd7,0x92,0xd6,0xd4,0xd4,0x16,0xd5
	.byte	0x58,0xd0,0x9a,0xd1,0xdc,0xd3,0x1e,0xd2
	.byte	0x60,0xc5,0xa2,0xc4,0xe4,0xc6,0x26,0xc7
	.byte	0x68,0xc2,0xaa,0xc3,0xec,0xc1,0x2e,0xc0
	.byte	0x70,0xcb,0xb2,0xca,0xf4,0xc8,0x36,0xc9
	.byte	0x78,0xcc,0xba,0xcd,0xfc,0xcf,0x3e,0xce
	.byte	0x80,0x91,0x42,0x90,0x04,0x92,0xc6,0x93
	.byte	0x88,0x96,0x4a,0x97,0x0c,0x95,0xce,0x94
	.byte	0x90,0x9f,0x52,0x9e,0x14,0x9c,0xd6,0x9d
	.byte	0x98,0x98,0x5a,0x99,0x1c,0x9b,0xde,0x9a
	.byte	0xa0,0x8d,0x62,0x8c,0x24,0x8e,0xe6,0x8f
	.byte	0xa8,0x8a,0x6a,0x8b,0x2c,0x89,0xee,0x88
	.byte	0xb0,0x83,0x72,0x82,0x34,0x80,0xf6,0x81
	.byte	0xb8,0x84,0x7a,0x85,0x3c,0x87,0xfe,0x86
	.byte	0xc0,0xa9,0x02,0xa8,0x44,0xaa,0x86,0xab
	.byte	0xc8,0xae,0x0a,0xaf,0x4c,0xad,0x8e,0xac
	.byte	0xd0,0xa7,0x12,0xa6,0x54,0xa4,0x96,0xa5
	.byte	0xd8,0xa0,0x1a,0xa1,0x5c,0xa3,0x9e,0xa2
	.byte	0xe0,0xb5,0x22,0xb4,0x64,0xb6,0xa6,0xb7
	.byte	0xe8,0xb2,0x2a,0xb3,0x6c,0xb1,0xae,0xb0
	.byte	0xf0,0xbb,0x32,0xba,0x74,0xb8,0xb6,0xb9
	.byte	0xf8,0xbc,0x3a,0xbd,0x7c,0xbf,0xbe,0xbe
#ifndef __APPLE__
.text
.globl	GCM_gmult_len
.type	GCM_gmult_len,@function
.align	16
GCM_gmult_len:
#if defined(_CALL_ELF) && _CALL_ELF == 2
0:	addis	2, 12, .TOC.-0b@ha
	addi	2, 2, .TOC.-0b@l
	.localentry	GCM_gmult_len, .-GCM_gmult_len
#endif
#else
.section	__TEXT,__text
.globl	_GCM_gmult_len
.p2align	4
_GCM_gmult_len:
#endif /* __APPLE__ */
	stdu	1, -56(1)
	mflr	0
	std	0, 48(1)
	std	14, 0(1)
	std	15, 8(1)
	std	16, 16(1)
	std	17, 24(1)
	std	18, 32(1)
	std	19, 40(1)
	addis	7, 2, L_GCM_gmult_len_r@toc@ha
	addi	7, 7, L_GCM_gmult_len_r@toc@l
	addi	0, 4, 8
	li	17, 8
L_GCM_gmult_len_start_block:
	ldbrx	8, 0, 3
	ldbrx	9, 17, 3
	ldbrx	10, 0, 5
	ldbrx	11, 17, 5
	xor	8, 8, 10
	xor	9, 9, 11
	rldicr	19, 9, 32, 63
	rldicr	18, 8, 32, 63
	rlwinm	16, 19, 12, 20, 27
	# Byte 15
	ldx	12, 16, 4
	ldx	14, 16, 0
	rldicl	11, 12, 8, 56
	rldicl	15, 14, 9, 55
	sldi	14, 14, 8
	andi.   15, 15, 510
	sldi	12, 12, 8
	lhzx	10, 15, 7
	xor	14, 14, 11
	rlwinm	16, 19, 20, 20, 27
	xor	12, 12, 10
	# Byte 14
	ldx	10, 16, 4
	ldx	11, 16, 0
	xor	12, 12, 10
	xor	14, 14, 11
	rldicl	11, 12, 8, 56
	rldicl	15, 14, 9, 55
	sldi	14, 14, 8
	andi.   15, 15, 510
	sldi	12, 12, 8
	lhzx	10, 15, 7
	xor	14, 14, 11
	rlwinm	16, 19, 28, 20, 27
	xor	12, 12, 10
	# Byte 13
	ldx	10, 16, 4
	ldx	11, 16, 0
	xor	12, 12, 10
	xor	14, 14, 11
	rldicl	11, 12, 8, 56
	rldicl	15, 14, 9, 55
	sldi	14, 14, 8
	andi.   15, 15, 510
	sldi	12, 12, 8
	lhzx	10, 15, 7
	xor	14, 14, 11
	rlwinm	16, 19, 4, 20, 27
	xor	12, 12, 10
	# Byte 12
	ldx	10, 16, 4
	ldx	11, 16, 0
	xor	12, 12, 10
	xor	14, 14, 11
	rldicl	11, 12, 8, 56
	rldicl	15, 14, 9, 55
	sldi	14, 14, 8
	andi.   15, 15, 510
	sldi	12, 12, 8
	lhzx	10, 15, 7
	xor	14, 14, 11
	rlwinm	16, 9, 12, 20, 27
	xor	12, 12, 10
	# Byte 11
	ldx	10, 16, 4
	ldx	11, 16, 0
	xor	12, 12, 10
	xor	14, 14, 11
	rldicl	11, 12, 8, 56
	rldicl	15, 14, 9, 55
	sldi	14, 14, 8
	andi.   15, 15, 510
	sldi	12, 12, 8
	lhzx	10, 15, 7
	xor	14, 14, 11
	rlwinm	16, 9, 20, 20, 27
	xor	12, 12, 10
	# Byte 10
	ldx	10, 16, 4
	ldx	11, 16, 0
	xor	12, 12, 10
	xor	14, 14, 11
	rldicl	11, 12, 8, 56
	rldicl	15, 14, 9, 55
	sldi	14, 14, 8
	andi.   15, 15, 510
	sldi	12, 12, 8
	lhzx	10, 15, 7
	xor	14, 14, 11
	rlwinm	16, 9, 28, 20, 27
	xor	12, 12, 10
	# Byte 9
	ldx	10, 16, 4
	ldx	11, 16, 0
	xor	12, 12, 10
	xor	14, 14, 11
	rldicl	11, 12, 8, 56
	rldicl	15, 14, 9, 55
	sldi	14, 14, 8
	andi.   15, 15, 510
	sldi	12, 12, 8
	lhzx	10, 15, 7
	xor	14, 14, 11
	rlwinm	16, 9, 4, 20, 27
	xor	12, 12, 10
	# Byte 8
	ldx	10, 16, 4
	ldx	11, 16, 0
	xor	12, 12, 10
	xor	14, 14, 11
	rldicl	11, 12, 8, 56
	rldicl	15, 14, 9, 55
	sldi	14, 14, 8
	andi.   15, 15, 510
	sldi	12, 12, 8
	lhzx	10, 15, 7
	xor	14, 14, 11
	rlwinm	16, 18, 12, 20, 27
	xor	12, 12, 10
	# Byte 7
	ldx	10, 16, 4
	ldx	11, 16, 0
	xor	12, 12, 10
	xor	14, 14, 11
	rldicl	11, 12, 8, 56
	rldicl	15, 14, 9, 55
	sldi	14, 14, 8
	andi.   15, 15, 510
	sldi	12, 12, 8
	lhzx	10, 15, 7
	xor	14, 14, 11
	rlwinm	16, 18, 20, 20, 27
	xor	12, 12, 10
	# Byte 6
	ldx	10, 16, 4
	ldx	11, 16, 0
	xor	12, 12, 10
	xor	14, 14, 11
	rldicl	11, 12, 8, 56
	rldicl	15, 14, 9, 55
	sldi	14, 14, 8
	andi.   15, 15, 510
	sldi	12, 12, 8
	lhzx	10, 15, 7
	xor	14, 14, 11
	rlwinm	16, 18, 28, 20, 27
	xor	12, 12, 10
	# Byte 5
	ldx	10, 16, 4
	ldx	11, 16, 0
	xor	12, 12, 10
	xor	14, 14, 11
	rldicl	11, 12, 8, 56
	rldicl	15, 14, 9, 55
	sldi	14, 14, 8
	andi.   15, 15, 510
	sldi	12, 12, 8
	lhzx	10, 15, 7
	xor	14, 14, 11
	rlwinm	16, 18, 4, 20, 27
	xor	12, 12, 10
	# Byte 4
	ldx	10, 16, 4
	ldx	11, 16, 0
	xor	12, 12, 10
	xor	14, 14, 11
	rldicl	11, 12, 8, 56
	rldicl	15, 14, 9, 55
	sldi	14, 14, 8
	andi.   15, 15, 510
	sldi	12, 12, 8
	lhzx	10, 15, 7
	xor	14, 14, 11
	rlwinm	16, 8, 12, 20, 27
	xor	12, 12, 10
	# Byte 3
	ldx	10, 16, 4
	ldx	11, 16, 0
	xor	12, 12, 10
	xor	14, 14, 11
	rldicl	11, 12, 8, 56
	rldicl	15, 14, 9, 55
	sldi	14, 14, 8
	andi.   15, 15, 510
	sldi	12, 12, 8
	lhzx	10, 15, 7
	xor	14, 14, 11
	rlwinm	16, 8, 20, 20, 27
	xor	12, 12, 10
	# Byte 2
	ldx	10, 16, 4
	ldx	11, 16, 0
	xor	12, 12, 10
	xor	14, 14, 11
	rldicl	11, 12, 8, 56
	rldicl	15, 14, 9, 55
	sldi	14, 14, 8
	andi.   15, 15, 510
	sldi	12, 12, 8
	lhzx	10, 15, 7
	xor	14, 14, 11
	rlwinm	16, 8, 28, 20, 27
	xor	12, 12, 10
	# Byte 1
	ldx	10, 16, 4
	ldx	11, 16, 0
	xor	12, 12, 10
	xor	14, 14, 11
	rldicl	11, 12, 8, 56
	rldicl	15, 14, 9, 55
	sldi	14, 14, 8
	andi.   15, 15, 510
	sldi	12, 12, 8
	lhzx	10, 15, 7
	xor	14, 14, 11
	rlwinm	16, 8, 4, 20, 27
	xor	12, 12, 10
	# Byte 0
	ldx	10, 16, 4
	ldx	11, 16, 0
	addi	5, 5, 16
	addic.	6, 6, -16
	xor	8, 12, 10
	xor	9, 14, 11
	stdbrx	8, 0, 3
	stdbrx	9, 17, 3
	bne	L_GCM_gmult_len_start_block
	ld	0, 48(1)
	mtlr	0
	ld	14, 0(1)
	ld	15, 8(1)
	ld	16, 16(1)
	ld	17, 24(1)
	ld	18, 32(1)
	ld	19, 40(1)
	addi	1, 1, 56
	blr
#ifndef __APPLE__
	.size	GCM_gmult_len,.-GCM_gmult_len
#endif /* __APPLE__ */
#endif /* GCM_TABLE */
#endif /* HAVE_AESGCM */
#ifdef WOLFSSL_PPC64_ASM_CRYPTO
#ifndef __APPLE__
	.text
	.type	L_AES_PPC64_crypto_sbox, %object
	.size	L_AES_PPC64_crypto_sbox, 256
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_AES_PPC64_crypto_sbox:
	.byte	0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5
	.byte	0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76
	.byte	0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0
	.byte	0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0
	.byte	0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc
	.byte	0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15
	.byte	0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a
	.byte	0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75
	.byte	0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0
	.byte	0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84
	.byte	0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b
	.byte	0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf
	.byte	0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85
	.byte	0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8
	.byte	0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5
	.byte	0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2
	.byte	0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17
	.byte	0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73
	.byte	0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88
	.byte	0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb
	.byte	0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c
	.byte	0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79
	.byte	0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9
	.byte	0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08
	.byte	0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6
	.byte	0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a
	.byte	0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e
	.byte	0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e
	.byte	0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94
	.byte	0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf
	.byte	0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68
	.byte	0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
#ifndef __APPLE__
	.text
	.type	L_AES_PPC64_crypto_rcon, %object
	.size	L_AES_PPC64_crypto_rcon, 40
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_AES_PPC64_crypto_rcon:
	.long	0x01000000,0x02000000,0x04000000,0x08000000
	.long	0x10000000,0x20000000,0x40000000,0x80000000
	.long	0x1b000000,0x36000000
#if defined(WOLFSSL_AES_COUNTER) && defined(HAVE_AESGCM)
#ifndef __APPLE__
	.text
	.type	L_AES_PPC64_crypto_one, %object
	.size	L_AES_PPC64_crypto_one, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_AES_PPC64_crypto_one:
	.long	0x00000000,0x00000000,0x00000000,0x00000001
#endif /* defined(WOLFSSL_AES_COUNTER) && defined(HAVE_AESGCM) */
	.machine	"push"
	.machine	"power8"
#ifndef __APPLE__
.text
.globl	AES_set_encrypt_key_crypto
.type	AES_set_encrypt_key_crypto,@function
.align	16
AES_set_encrypt_key_crypto:
#if defined(_CALL_ELF) && _CALL_ELF == 2
0:	addis	2, 12, .TOC.-0b@ha
	addi	2, 2, .TOC.-0b@l
	.localentry	AES_set_encrypt_key_crypto, .-AES_set_encrypt_key_crypto
#endif
#else
.section	__TEXT,__text
.globl	_AES_set_encrypt_key_crypto
.p2align	4
_AES_set_encrypt_key_crypto:
#endif /* __APPLE__ */
	stdu	1, -40(1)
	mflr	0
	std	0, 32(1)
	std	14, 0(1)
	std	15, 8(1)
	std	16, 16(1)
	std	17, 24(1)
	addis	14, 2, L_AES_PPC64_crypto_sbox@toc@ha
	addi	14, 14, L_AES_PPC64_crypto_sbox@toc@l
	addis	15, 2, L_AES_PPC64_crypto_rcon@toc@ha
	addi	15, 15, L_AES_PPC64_crypto_rcon@toc@l
	cmplwi	4, 0x80
	beq	L_AES_set_encrypt_key_crypto_128
	cmplwi	4, 0xc0
	beq	L_AES_set_encrypt_key_crypto_192
	lwz	0, 0(3)
	lwz	6, 4(3)
	lwz	7, 8(3)
	lwz	8, 12(3)
	lwz	9, 16(3)
	lwz	10, 20(3)
	lwz	11, 24(3)
	lwz	12, 28(3)
	stw	0, 0(5)
	stw	6, 4(5)
	stw	7, 8(5)
	stw	8, 12(5)
	stw	9, 16(5)
	stw	10, 20(5)
	stw	11, 24(5)
	stw	12, 28(5)
	addi	5, 5, 32
	li	17, 6
	mtctr	17
L_AES_set_encrypt_key_crypto_loop_256:
	rlwinm	17, 12, 16, 24, 31
	lbzx	17, 14, 17
	slwi	16, 17, 24
	rlwinm	17, 12, 24, 24, 31
	lbzx	17, 14, 17
	rlwimi	16, 17, 16, 8, 15
	rlwinm	17, 12, 0, 24, 31
	lbzx	17, 14, 17
	rlwimi	16, 17, 8, 16, 23
	rlwinm	17, 12, 8, 24, 31
	lbzx	17, 14, 17
	rlwimi	16, 17, 0, 24, 31
	lwz	17, 0(15)
	addi	15, 15, 4
	xor	0, 0, 16
	xor	0, 0, 17
	xor	6, 6, 0
	xor	7, 7, 6
	xor	8, 8, 7
	stw	0, 0(5)
	stw	6, 4(5)
	stw	7, 8(5)
	stw	8, 12(5)
	addi	5, 5, 16
	rlwinm	17, 8, 8, 24, 31
	lbzx	17, 14, 17
	slwi	16, 17, 24
	rlwinm	17, 8, 16, 24, 31
	lbzx	17, 14, 17
	rlwimi	16, 17, 16, 8, 15
	rlwinm	17, 8, 24, 24, 31
	lbzx	17, 14, 17
	rlwimi	16, 17, 8, 16, 23
	rlwinm	17, 8, 0, 24, 31
	lbzx	17, 14, 17
	rlwimi	16, 17, 0, 24, 31
	xor	9, 9, 16
	xor	10, 10, 9
	xor	11, 11, 10
	xor	12, 12, 11
	stw	9, 0(5)
	stw	10, 4(5)
	stw	11, 8(5)
	stw	12, 12(5)
	addi	5, 5, 16
	bdnz	L_AES_set_encrypt_key_crypto_loop_256
	rlwinm	17, 12, 16, 24, 31
	lbzx	17, 14, 17
	slwi	16, 17, 24
	rlwinm	17, 12, 24, 24, 31
	lbzx	17, 14, 17
	rlwimi	16, 17, 16, 8, 15
	rlwinm	17, 12, 0, 24, 31
	lbzx	17, 14, 17
	rlwimi	16, 17, 8, 16, 23
	rlwinm	17, 12, 8, 24, 31
	lbzx	17, 14, 17
	rlwimi	16, 17, 0, 24, 31
	lwz	17, 0(15)
	addi	15, 15, 4
	xor	0, 0, 16
	xor	0, 0, 17
	xor	6, 6, 0
	xor	7, 7, 6
	xor	8, 8, 7
	stw	0, 0(5)
	stw	6, 4(5)
	stw	7, 8(5)
	stw	8, 12(5)
	addi	5, 5, 16
	b	L_AES_set_encrypt_key_crypto_end
L_AES_set_encrypt_key_crypto_192:
	lwz	0, 0(3)
	lwz	6, 4(3)
	lwz	7, 8(3)
	lwz	8, 12(3)
	lwz	9, 16(3)
	lwz	10, 20(3)
	stw	0, 0(5)
	stw	6, 4(5)
	stw	7, 8(5)
	stw	8, 12(5)
	stw	9, 16(5)
	stw	10, 20(5)
	addi	5, 5, 24
	li	17, 7
	mtctr	17
L_AES_set_encrypt_key_crypto_loop_192:
	rlwinm	17, 10, 16, 24, 31
	lbzx	17, 14, 17
	slwi	16, 17, 24
	rlwinm	17, 10, 24, 24, 31
	lbzx	17, 14, 17
	rlwimi	16, 17, 16, 8, 15
	rlwinm	17, 10, 0, 24, 31
	lbzx	17, 14, 17
	rlwimi	16, 17, 8, 16, 23
	rlwinm	17, 10, 8, 24, 31
	lbzx	17, 14, 17
	rlwimi	16, 17, 0, 24, 31
	lwz	17, 0(15)
	addi	15, 15, 4
	xor	0, 0, 16
	xor	0, 0, 17
	xor	6, 6, 0
	xor	7, 7, 6
	xor	8, 8, 7
	stw	0, 0(5)
	stw	6, 4(5)
	stw	7, 8(5)
	stw	8, 12(5)
	xor	9, 9, 8
	xor	10, 10, 9
	stw	9, 16(5)
	stw	10, 20(5)
	addi	5, 5, 24
	bdnz	L_AES_set_encrypt_key_crypto_loop_192
	rlwinm	17, 10, 16, 24, 31
	lbzx	17, 14, 17
	slwi	16, 17, 24
	rlwinm	17, 10, 24, 24, 31
	lbzx	17, 14, 17
	rlwimi	16, 17, 16, 8, 15
	rlwinm	17, 10, 0, 24, 31
	lbzx	17, 14, 17
	rlwimi	16, 17, 8, 16, 23
	rlwinm	17, 10, 8, 24, 31
	lbzx	17, 14, 17
	rlwimi	16, 17, 0, 24, 31
	lwz	17, 0(15)
	addi	15, 15, 4
	xor	0, 0, 16
	xor	0, 0, 17
	xor	6, 6, 0
	xor	7, 7, 6
	xor	8, 8, 7
	stw	0, 0(5)
	stw	6, 4(5)
	stw	7, 8(5)
	stw	8, 12(5)
	b	L_AES_set_encrypt_key_crypto_end
L_AES_set_encrypt_key_crypto_128:
	lwz	0, 0(3)
	lwz	6, 4(3)
	lwz	7, 8(3)
	lwz	8, 12(3)
	stw	0, 0(5)
	stw	6, 4(5)
	stw	7, 8(5)
	stw	8, 12(5)
	addi	5, 5, 16
	li	17, 10
	mtctr	17
L_AES_set_encrypt_key_crypto_loop_128:
	rlwinm	17, 8, 16, 24, 31
	lbzx	17, 14, 17
	slwi	16, 17, 24
	rlwinm	17, 8, 24, 24, 31
	lbzx	17, 14, 17
	rlwimi	16, 17, 16, 8, 15
	rlwinm	17, 8, 0, 24, 31
	lbzx	17, 14, 17
	rlwimi	16, 17, 8, 16, 23
	rlwinm	17, 8, 8, 24, 31
	lbzx	17, 14, 17
	rlwimi	16, 17, 0, 24, 31
	lwz	17, 0(15)
	addi	15, 15, 4
	xor	0, 0, 16
	xor	0, 0, 17
	xor	6, 6, 0
	xor	7, 7, 6
	xor	8, 8, 7
	stw	0, 0(5)
	stw	6, 4(5)
	stw	7, 8(5)
	stw	8, 12(5)
	addi	5, 5, 16
	bdnz	L_AES_set_encrypt_key_crypto_loop_128
L_AES_set_encrypt_key_crypto_end:
	ld	0, 32(1)
	mtlr	0
	ld	14, 0(1)
	ld	15, 8(1)
	ld	16, 16(1)
	ld	17, 24(1)
	addi	1, 1, 40
	blr
#ifndef __APPLE__
	.size	AES_set_encrypt_key_crypto,.-AES_set_encrypt_key_crypto
#endif /* __APPLE__ */
	.machine	"pop"
	.machine	"push"
	.machine	"power8"
#ifndef __APPLE__
.text
.globl	AES_invert_key_crypto
.type	AES_invert_key_crypto,@function
.align	16
AES_invert_key_crypto:
#if defined(_CALL_ELF) && _CALL_ELF == 2
0:	addis	2, 12, .TOC.-0b@ha
	addi	2, 2, .TOC.-0b@l
	.localentry	AES_invert_key_crypto, .-AES_invert_key_crypto
#endif
#else
.section	__TEXT,__text
.globl	_AES_invert_key_crypto
.p2align	4
_AES_invert_key_crypto:
#endif /* __APPLE__ */
	stdu	1, -8(1)
	mflr	0
	std	0, 0(1)
	addi	5, 3, 0
	slwi	6, 4, 4
	add	6, 3, 6
	srwi	11, 4, 1
	mtctr	11
L_AES_invert_key_crypto_loop:
	ld	7, 0(5)
	ld	8, 8(5)
	ld	9, 0(6)
	ld	10, 8(6)
	std	9, 0(5)
	std	10, 8(5)
	std	7, 0(6)
	std	8, 8(6)
	addi	5, 5, 16
	addi	6, 6, -16
	bdnz	L_AES_invert_key_crypto_loop
	ld	0, 0(1)
	mtlr	0
	addi	1, 1, 8
	blr
#ifndef __APPLE__
	.size	AES_invert_key_crypto,.-AES_invert_key_crypto
#endif /* __APPLE__ */
	.machine	"pop"
	.machine	"push"
	.machine	"power8"
#ifndef __APPLE__
.text
.globl	AES_ECB_encrypt_crypto
.type	AES_ECB_encrypt_crypto,@function
.align	16
AES_ECB_encrypt_crypto:
#if defined(_CALL_ELF) && _CALL_ELF == 2
0:	addis	2, 12, .TOC.-0b@ha
	addi	2, 2, .TOC.-0b@l
	.localentry	AES_ECB_encrypt_crypto, .-AES_ECB_encrypt_crypto
#endif
#else
.section	__TEXT,__text
.globl	_AES_ECB_encrypt_crypto
.p2align	4
_AES_ECB_encrypt_crypto:
#endif /* __APPLE__ */
	subi	1, 1, 48
	li	0, 0
	stxvd2x	52, 1, 0
	li	0, 16
	stxvd2x	53, 1, 0
	li	0, 32
	stxvd2x	54, 1, 0
	stdu	1, -8(1)
	mflr	0
	std	0, 0(1)
	cmplwi	7, 10
	beq	L_AES_ECB_encrypt_crypto_128
	cmplwi	7, 12
	beq	L_AES_ECB_encrypt_crypto_192
	addi	8, 6, 0
	lxvd2x	32, 0, 8
	addi	8, 8, 16
	lxvd2x	33, 0, 8
	addi	8, 8, 16
	lxvd2x	34, 0, 8
	addi	8, 8, 16
	lxvd2x	35, 0, 8
	addi	8, 8, 16
	lxvd2x	36, 0, 8
	addi	8, 8, 16
	lxvd2x	37, 0, 8
	addi	8, 8, 16
	lxvd2x	38, 0, 8
	addi	8, 8, 16
	lxvd2x	39, 0, 8
	addi	8, 8, 16
	lxvd2x	40, 0, 8
	addi	8, 8, 16
	lxvd2x	41, 0, 8
	addi	8, 8, 16
	lxvd2x	42, 0, 8
	addi	8, 8, 16
	lxvd2x	43, 0, 8
	addi	8, 8, 16
	lxvd2x	44, 0, 8
	addi	8, 8, 16
	lxvd2x	45, 0, 8
	addi	8, 8, 16
	lxvd2x	46, 0, 8
	addi	8, 8, 16
	cmpdi	5, 0x80
	blt	L_AES_ECB_encrypt_crypto_256_blk4
L_AES_ECB_encrypt_crypto_256_blk8:
	lxvd2x	47, 0, 3
	addi	3, 3, 16
	lxvd2x	48, 0, 3
	addi	3, 3, 16
	lxvd2x	49, 0, 3
	addi	3, 3, 16
	lxvd2x	50, 0, 3
	addi	3, 3, 16
	lxvd2x	51, 0, 3
	addi	3, 3, 16
	lxvd2x	52, 0, 3
	addi	3, 3, 16
	lxvd2x	53, 0, 3
	addi	3, 3, 16
	lxvd2x	54, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 0
	vxor	16, 16, 0
	vxor	17, 17, 0
	vxor	18, 18, 0
	vxor	19, 19, 0
	vxor	20, 20, 0
	vxor	21, 21, 0
	vxor	22, 22, 0
	vcipher	15, 15, 1
	vcipher	16, 16, 1
	vcipher	17, 17, 1
	vcipher	18, 18, 1
	vcipher	19, 19, 1
	vcipher	20, 20, 1
	vcipher	21, 21, 1
	vcipher	22, 22, 1
	vcipher	15, 15, 2
	vcipher	16, 16, 2
	vcipher	17, 17, 2
	vcipher	18, 18, 2
	vcipher	19, 19, 2
	vcipher	20, 20, 2
	vcipher	21, 21, 2
	vcipher	22, 22, 2
	vcipher	15, 15, 3
	vcipher	16, 16, 3
	vcipher	17, 17, 3
	vcipher	18, 18, 3
	vcipher	19, 19, 3
	vcipher	20, 20, 3
	vcipher	21, 21, 3
	vcipher	22, 22, 3
	vcipher	15, 15, 4
	vcipher	16, 16, 4
	vcipher	17, 17, 4
	vcipher	18, 18, 4
	vcipher	19, 19, 4
	vcipher	20, 20, 4
	vcipher	21, 21, 4
	vcipher	22, 22, 4
	vcipher	15, 15, 5
	vcipher	16, 16, 5
	vcipher	17, 17, 5
	vcipher	18, 18, 5
	vcipher	19, 19, 5
	vcipher	20, 20, 5
	vcipher	21, 21, 5
	vcipher	22, 22, 5
	vcipher	15, 15, 6
	vcipher	16, 16, 6
	vcipher	17, 17, 6
	vcipher	18, 18, 6
	vcipher	19, 19, 6
	vcipher	20, 20, 6
	vcipher	21, 21, 6
	vcipher	22, 22, 6
	vcipher	15, 15, 7
	vcipher	16, 16, 7
	vcipher	17, 17, 7
	vcipher	18, 18, 7
	vcipher	19, 19, 7
	vcipher	20, 20, 7
	vcipher	21, 21, 7
	vcipher	22, 22, 7
	vcipher	15, 15, 8
	vcipher	16, 16, 8
	vcipher	17, 17, 8
	vcipher	18, 18, 8
	vcipher	19, 19, 8
	vcipher	20, 20, 8
	vcipher	21, 21, 8
	vcipher	22, 22, 8
	vcipher	15, 15, 9
	vcipher	16, 16, 9
	vcipher	17, 17, 9
	vcipher	18, 18, 9
	vcipher	19, 19, 9
	vcipher	20, 20, 9
	vcipher	21, 21, 9
	vcipher	22, 22, 9
	vcipher	15, 15, 10
	vcipher	16, 16, 10
	vcipher	17, 17, 10
	vcipher	18, 18, 10
	vcipher	19, 19, 10
	vcipher	20, 20, 10
	vcipher	21, 21, 10
	vcipher	22, 22, 10
	vcipher	15, 15, 11
	vcipher	16, 16, 11
	vcipher	17, 17, 11
	vcipher	18, 18, 11
	vcipher	19, 19, 11
	vcipher	20, 20, 11
	vcipher	21, 21, 11
	vcipher	22, 22, 11
	vcipher	15, 15, 12
	vcipher	16, 16, 12
	vcipher	17, 17, 12
	vcipher	18, 18, 12
	vcipher	19, 19, 12
	vcipher	20, 20, 12
	vcipher	21, 21, 12
	vcipher	22, 22, 12
	vcipher	15, 15, 13
	vcipher	16, 16, 13
	vcipher	17, 17, 13
	vcipher	18, 18, 13
	vcipher	19, 19, 13
	vcipher	20, 20, 13
	vcipher	21, 21, 13
	vcipher	22, 22, 13
	vcipherlast	15, 15, 14
	vcipherlast	16, 16, 14
	vcipherlast	17, 17, 14
	vcipherlast	18, 18, 14
	vcipherlast	19, 19, 14
	vcipherlast	20, 20, 14
	vcipherlast	21, 21, 14
	vcipherlast	22, 22, 14
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	stxvd2x	49, 0, 4
	addi	4, 4, 16
	stxvd2x	50, 0, 4
	addi	4, 4, 16
	stxvd2x	51, 0, 4
	addi	4, 4, 16
	stxvd2x	52, 0, 4
	addi	4, 4, 16
	stxvd2x	53, 0, 4
	addi	4, 4, 16
	stxvd2x	54, 0, 4
	addi	4, 4, 16
	addi	5, 5, -128
	cmpdi	5, 0x80
	bge	L_AES_ECB_encrypt_crypto_256_blk8
L_AES_ECB_encrypt_crypto_256_blk4:
	cmpdi	5, 0x40
	blt	L_AES_ECB_encrypt_crypto_256_blk2
	lxvd2x	47, 0, 3
	addi	3, 3, 16
	lxvd2x	48, 0, 3
	addi	3, 3, 16
	lxvd2x	49, 0, 3
	addi	3, 3, 16
	lxvd2x	50, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 0
	vxor	16, 16, 0
	vxor	17, 17, 0
	vxor	18, 18, 0
	vcipher	15, 15, 1
	vcipher	16, 16, 1
	vcipher	17, 17, 1
	vcipher	18, 18, 1
	vcipher	15, 15, 2
	vcipher	16, 16, 2
	vcipher	17, 17, 2
	vcipher	18, 18, 2
	vcipher	15, 15, 3
	vcipher	16, 16, 3
	vcipher	17, 17, 3
	vcipher	18, 18, 3
	vcipher	15, 15, 4
	vcipher	16, 16, 4
	vcipher	17, 17, 4
	vcipher	18, 18, 4
	vcipher	15, 15, 5
	vcipher	16, 16, 5
	vcipher	17, 17, 5
	vcipher	18, 18, 5
	vcipher	15, 15, 6
	vcipher	16, 16, 6
	vcipher	17, 17, 6
	vcipher	18, 18, 6
	vcipher	15, 15, 7
	vcipher	16, 16, 7
	vcipher	17, 17, 7
	vcipher	18, 18, 7
	vcipher	15, 15, 8
	vcipher	16, 16, 8
	vcipher	17, 17, 8
	vcipher	18, 18, 8
	vcipher	15, 15, 9
	vcipher	16, 16, 9
	vcipher	17, 17, 9
	vcipher	18, 18, 9
	vcipher	15, 15, 10
	vcipher	16, 16, 10
	vcipher	17, 17, 10
	vcipher	18, 18, 10
	vcipher	15, 15, 11
	vcipher	16, 16, 11
	vcipher	17, 17, 11
	vcipher	18, 18, 11
	vcipher	15, 15, 12
	vcipher	16, 16, 12
	vcipher	17, 17, 12
	vcipher	18, 18, 12
	vcipher	15, 15, 13
	vcipher	16, 16, 13
	vcipher	17, 17, 13
	vcipher	18, 18, 13
	vcipherlast	15, 15, 14
	vcipherlast	16, 16, 14
	vcipherlast	17, 17, 14
	vcipherlast	18, 18, 14
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	stxvd2x	49, 0, 4
	addi	4, 4, 16
	stxvd2x	50, 0, 4
	addi	4, 4, 16
	addi	5, 5, -64
L_AES_ECB_encrypt_crypto_256_blk2:
	cmpdi	5, 32
	blt	L_AES_ECB_encrypt_crypto_256_blk1
	lxvd2x	47, 0, 3
	addi	3, 3, 16
	lxvd2x	48, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 0
	vxor	16, 16, 0
	vcipher	15, 15, 1
	vcipher	16, 16, 1
	vcipher	15, 15, 2
	vcipher	16, 16, 2
	vcipher	15, 15, 3
	vcipher	16, 16, 3
	vcipher	15, 15, 4
	vcipher	16, 16, 4
	vcipher	15, 15, 5
	vcipher	16, 16, 5
	vcipher	15, 15, 6
	vcipher	16, 16, 6
	vcipher	15, 15, 7
	vcipher	16, 16, 7
	vcipher	15, 15, 8
	vcipher	16, 16, 8
	vcipher	15, 15, 9
	vcipher	16, 16, 9
	vcipher	15, 15, 10
	vcipher	16, 16, 10
	vcipher	15, 15, 11
	vcipher	16, 16, 11
	vcipher	15, 15, 12
	vcipher	16, 16, 12
	vcipher	15, 15, 13
	vcipher	16, 16, 13
	vcipherlast	15, 15, 14
	vcipherlast	16, 16, 14
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	addi	5, 5, -32
L_AES_ECB_encrypt_crypto_256_blk1:
	cmpdi	5, 16
	blt	L_AES_ECB_encrypt_crypto_256_done
	lxvd2x	47, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 0
	vcipher	15, 15, 1
	vcipher	15, 15, 2
	vcipher	15, 15, 3
	vcipher	15, 15, 4
	vcipher	15, 15, 5
	vcipher	15, 15, 6
	vcipher	15, 15, 7
	vcipher	15, 15, 8
	vcipher	15, 15, 9
	vcipher	15, 15, 10
	vcipher	15, 15, 11
	vcipher	15, 15, 12
	vcipher	15, 15, 13
	vcipherlast	15, 15, 14
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	addi	5, 5, -16
L_AES_ECB_encrypt_crypto_256_done:
	b	L_AES_ECB_encrypt_crypto_alldone
L_AES_ECB_encrypt_crypto_192:
	addi	8, 6, 0
	lxvd2x	32, 0, 8
	addi	8, 8, 16
	lxvd2x	33, 0, 8
	addi	8, 8, 16
	lxvd2x	34, 0, 8
	addi	8, 8, 16
	lxvd2x	35, 0, 8
	addi	8, 8, 16
	lxvd2x	36, 0, 8
	addi	8, 8, 16
	lxvd2x	37, 0, 8
	addi	8, 8, 16
	lxvd2x	38, 0, 8
	addi	8, 8, 16
	lxvd2x	39, 0, 8
	addi	8, 8, 16
	lxvd2x	40, 0, 8
	addi	8, 8, 16
	lxvd2x	41, 0, 8
	addi	8, 8, 16
	lxvd2x	42, 0, 8
	addi	8, 8, 16
	lxvd2x	43, 0, 8
	addi	8, 8, 16
	lxvd2x	44, 0, 8
	addi	8, 8, 16
	cmpdi	5, 0x80
	blt	L_AES_ECB_encrypt_crypto_192_blk4
L_AES_ECB_encrypt_crypto_192_blk8:
	lxvd2x	47, 0, 3
	addi	3, 3, 16
	lxvd2x	48, 0, 3
	addi	3, 3, 16
	lxvd2x	49, 0, 3
	addi	3, 3, 16
	lxvd2x	50, 0, 3
	addi	3, 3, 16
	lxvd2x	51, 0, 3
	addi	3, 3, 16
	lxvd2x	52, 0, 3
	addi	3, 3, 16
	lxvd2x	53, 0, 3
	addi	3, 3, 16
	lxvd2x	54, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 0
	vxor	16, 16, 0
	vxor	17, 17, 0
	vxor	18, 18, 0
	vxor	19, 19, 0
	vxor	20, 20, 0
	vxor	21, 21, 0
	vxor	22, 22, 0
	vcipher	15, 15, 1
	vcipher	16, 16, 1
	vcipher	17, 17, 1
	vcipher	18, 18, 1
	vcipher	19, 19, 1
	vcipher	20, 20, 1
	vcipher	21, 21, 1
	vcipher	22, 22, 1
	vcipher	15, 15, 2
	vcipher	16, 16, 2
	vcipher	17, 17, 2
	vcipher	18, 18, 2
	vcipher	19, 19, 2
	vcipher	20, 20, 2
	vcipher	21, 21, 2
	vcipher	22, 22, 2
	vcipher	15, 15, 3
	vcipher	16, 16, 3
	vcipher	17, 17, 3
	vcipher	18, 18, 3
	vcipher	19, 19, 3
	vcipher	20, 20, 3
	vcipher	21, 21, 3
	vcipher	22, 22, 3
	vcipher	15, 15, 4
	vcipher	16, 16, 4
	vcipher	17, 17, 4
	vcipher	18, 18, 4
	vcipher	19, 19, 4
	vcipher	20, 20, 4
	vcipher	21, 21, 4
	vcipher	22, 22, 4
	vcipher	15, 15, 5
	vcipher	16, 16, 5
	vcipher	17, 17, 5
	vcipher	18, 18, 5
	vcipher	19, 19, 5
	vcipher	20, 20, 5
	vcipher	21, 21, 5
	vcipher	22, 22, 5
	vcipher	15, 15, 6
	vcipher	16, 16, 6
	vcipher	17, 17, 6
	vcipher	18, 18, 6
	vcipher	19, 19, 6
	vcipher	20, 20, 6
	vcipher	21, 21, 6
	vcipher	22, 22, 6
	vcipher	15, 15, 7
	vcipher	16, 16, 7
	vcipher	17, 17, 7
	vcipher	18, 18, 7
	vcipher	19, 19, 7
	vcipher	20, 20, 7
	vcipher	21, 21, 7
	vcipher	22, 22, 7
	vcipher	15, 15, 8
	vcipher	16, 16, 8
	vcipher	17, 17, 8
	vcipher	18, 18, 8
	vcipher	19, 19, 8
	vcipher	20, 20, 8
	vcipher	21, 21, 8
	vcipher	22, 22, 8
	vcipher	15, 15, 9
	vcipher	16, 16, 9
	vcipher	17, 17, 9
	vcipher	18, 18, 9
	vcipher	19, 19, 9
	vcipher	20, 20, 9
	vcipher	21, 21, 9
	vcipher	22, 22, 9
	vcipher	15, 15, 10
	vcipher	16, 16, 10
	vcipher	17, 17, 10
	vcipher	18, 18, 10
	vcipher	19, 19, 10
	vcipher	20, 20, 10
	vcipher	21, 21, 10
	vcipher	22, 22, 10
	vcipher	15, 15, 11
	vcipher	16, 16, 11
	vcipher	17, 17, 11
	vcipher	18, 18, 11
	vcipher	19, 19, 11
	vcipher	20, 20, 11
	vcipher	21, 21, 11
	vcipher	22, 22, 11
	vcipherlast	15, 15, 12
	vcipherlast	16, 16, 12
	vcipherlast	17, 17, 12
	vcipherlast	18, 18, 12
	vcipherlast	19, 19, 12
	vcipherlast	20, 20, 12
	vcipherlast	21, 21, 12
	vcipherlast	22, 22, 12
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	stxvd2x	49, 0, 4
	addi	4, 4, 16
	stxvd2x	50, 0, 4
	addi	4, 4, 16
	stxvd2x	51, 0, 4
	addi	4, 4, 16
	stxvd2x	52, 0, 4
	addi	4, 4, 16
	stxvd2x	53, 0, 4
	addi	4, 4, 16
	stxvd2x	54, 0, 4
	addi	4, 4, 16
	addi	5, 5, -128
	cmpdi	5, 0x80
	bge	L_AES_ECB_encrypt_crypto_192_blk8
L_AES_ECB_encrypt_crypto_192_blk4:
	cmpdi	5, 0x40
	blt	L_AES_ECB_encrypt_crypto_192_blk2
	lxvd2x	47, 0, 3
	addi	3, 3, 16
	lxvd2x	48, 0, 3
	addi	3, 3, 16
	lxvd2x	49, 0, 3
	addi	3, 3, 16
	lxvd2x	50, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 0
	vxor	16, 16, 0
	vxor	17, 17, 0
	vxor	18, 18, 0
	vcipher	15, 15, 1
	vcipher	16, 16, 1
	vcipher	17, 17, 1
	vcipher	18, 18, 1
	vcipher	15, 15, 2
	vcipher	16, 16, 2
	vcipher	17, 17, 2
	vcipher	18, 18, 2
	vcipher	15, 15, 3
	vcipher	16, 16, 3
	vcipher	17, 17, 3
	vcipher	18, 18, 3
	vcipher	15, 15, 4
	vcipher	16, 16, 4
	vcipher	17, 17, 4
	vcipher	18, 18, 4
	vcipher	15, 15, 5
	vcipher	16, 16, 5
	vcipher	17, 17, 5
	vcipher	18, 18, 5
	vcipher	15, 15, 6
	vcipher	16, 16, 6
	vcipher	17, 17, 6
	vcipher	18, 18, 6
	vcipher	15, 15, 7
	vcipher	16, 16, 7
	vcipher	17, 17, 7
	vcipher	18, 18, 7
	vcipher	15, 15, 8
	vcipher	16, 16, 8
	vcipher	17, 17, 8
	vcipher	18, 18, 8
	vcipher	15, 15, 9
	vcipher	16, 16, 9
	vcipher	17, 17, 9
	vcipher	18, 18, 9
	vcipher	15, 15, 10
	vcipher	16, 16, 10
	vcipher	17, 17, 10
	vcipher	18, 18, 10
	vcipher	15, 15, 11
	vcipher	16, 16, 11
	vcipher	17, 17, 11
	vcipher	18, 18, 11
	vcipherlast	15, 15, 12
	vcipherlast	16, 16, 12
	vcipherlast	17, 17, 12
	vcipherlast	18, 18, 12
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	stxvd2x	49, 0, 4
	addi	4, 4, 16
	stxvd2x	50, 0, 4
	addi	4, 4, 16
	addi	5, 5, -64
L_AES_ECB_encrypt_crypto_192_blk2:
	cmpdi	5, 32
	blt	L_AES_ECB_encrypt_crypto_192_blk1
	lxvd2x	47, 0, 3
	addi	3, 3, 16
	lxvd2x	48, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 0
	vxor	16, 16, 0
	vcipher	15, 15, 1
	vcipher	16, 16, 1
	vcipher	15, 15, 2
	vcipher	16, 16, 2
	vcipher	15, 15, 3
	vcipher	16, 16, 3
	vcipher	15, 15, 4
	vcipher	16, 16, 4
	vcipher	15, 15, 5
	vcipher	16, 16, 5
	vcipher	15, 15, 6
	vcipher	16, 16, 6
	vcipher	15, 15, 7
	vcipher	16, 16, 7
	vcipher	15, 15, 8
	vcipher	16, 16, 8
	vcipher	15, 15, 9
	vcipher	16, 16, 9
	vcipher	15, 15, 10
	vcipher	16, 16, 10
	vcipher	15, 15, 11
	vcipher	16, 16, 11
	vcipherlast	15, 15, 12
	vcipherlast	16, 16, 12
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	addi	5, 5, -32
L_AES_ECB_encrypt_crypto_192_blk1:
	cmpdi	5, 16
	blt	L_AES_ECB_encrypt_crypto_192_done
	lxvd2x	47, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 0
	vcipher	15, 15, 1
	vcipher	15, 15, 2
	vcipher	15, 15, 3
	vcipher	15, 15, 4
	vcipher	15, 15, 5
	vcipher	15, 15, 6
	vcipher	15, 15, 7
	vcipher	15, 15, 8
	vcipher	15, 15, 9
	vcipher	15, 15, 10
	vcipher	15, 15, 11
	vcipherlast	15, 15, 12
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	addi	5, 5, -16
L_AES_ECB_encrypt_crypto_192_done:
	b	L_AES_ECB_encrypt_crypto_alldone
L_AES_ECB_encrypt_crypto_128:
	addi	8, 6, 0
	lxvd2x	32, 0, 8
	addi	8, 8, 16
	lxvd2x	33, 0, 8
	addi	8, 8, 16
	lxvd2x	34, 0, 8
	addi	8, 8, 16
	lxvd2x	35, 0, 8
	addi	8, 8, 16
	lxvd2x	36, 0, 8
	addi	8, 8, 16
	lxvd2x	37, 0, 8
	addi	8, 8, 16
	lxvd2x	38, 0, 8
	addi	8, 8, 16
	lxvd2x	39, 0, 8
	addi	8, 8, 16
	lxvd2x	40, 0, 8
	addi	8, 8, 16
	lxvd2x	41, 0, 8
	addi	8, 8, 16
	lxvd2x	42, 0, 8
	addi	8, 8, 16
	cmpdi	5, 0x80
	blt	L_AES_ECB_encrypt_crypto_128_blk4
L_AES_ECB_encrypt_crypto_128_blk8:
	lxvd2x	47, 0, 3
	addi	3, 3, 16
	lxvd2x	48, 0, 3
	addi	3, 3, 16
	lxvd2x	49, 0, 3
	addi	3, 3, 16
	lxvd2x	50, 0, 3
	addi	3, 3, 16
	lxvd2x	51, 0, 3
	addi	3, 3, 16
	lxvd2x	52, 0, 3
	addi	3, 3, 16
	lxvd2x	53, 0, 3
	addi	3, 3, 16
	lxvd2x	54, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 0
	vxor	16, 16, 0
	vxor	17, 17, 0
	vxor	18, 18, 0
	vxor	19, 19, 0
	vxor	20, 20, 0
	vxor	21, 21, 0
	vxor	22, 22, 0
	vcipher	15, 15, 1
	vcipher	16, 16, 1
	vcipher	17, 17, 1
	vcipher	18, 18, 1
	vcipher	19, 19, 1
	vcipher	20, 20, 1
	vcipher	21, 21, 1
	vcipher	22, 22, 1
	vcipher	15, 15, 2
	vcipher	16, 16, 2
	vcipher	17, 17, 2
	vcipher	18, 18, 2
	vcipher	19, 19, 2
	vcipher	20, 20, 2
	vcipher	21, 21, 2
	vcipher	22, 22, 2
	vcipher	15, 15, 3
	vcipher	16, 16, 3
	vcipher	17, 17, 3
	vcipher	18, 18, 3
	vcipher	19, 19, 3
	vcipher	20, 20, 3
	vcipher	21, 21, 3
	vcipher	22, 22, 3
	vcipher	15, 15, 4
	vcipher	16, 16, 4
	vcipher	17, 17, 4
	vcipher	18, 18, 4
	vcipher	19, 19, 4
	vcipher	20, 20, 4
	vcipher	21, 21, 4
	vcipher	22, 22, 4
	vcipher	15, 15, 5
	vcipher	16, 16, 5
	vcipher	17, 17, 5
	vcipher	18, 18, 5
	vcipher	19, 19, 5
	vcipher	20, 20, 5
	vcipher	21, 21, 5
	vcipher	22, 22, 5
	vcipher	15, 15, 6
	vcipher	16, 16, 6
	vcipher	17, 17, 6
	vcipher	18, 18, 6
	vcipher	19, 19, 6
	vcipher	20, 20, 6
	vcipher	21, 21, 6
	vcipher	22, 22, 6
	vcipher	15, 15, 7
	vcipher	16, 16, 7
	vcipher	17, 17, 7
	vcipher	18, 18, 7
	vcipher	19, 19, 7
	vcipher	20, 20, 7
	vcipher	21, 21, 7
	vcipher	22, 22, 7
	vcipher	15, 15, 8
	vcipher	16, 16, 8
	vcipher	17, 17, 8
	vcipher	18, 18, 8
	vcipher	19, 19, 8
	vcipher	20, 20, 8
	vcipher	21, 21, 8
	vcipher	22, 22, 8
	vcipher	15, 15, 9
	vcipher	16, 16, 9
	vcipher	17, 17, 9
	vcipher	18, 18, 9
	vcipher	19, 19, 9
	vcipher	20, 20, 9
	vcipher	21, 21, 9
	vcipher	22, 22, 9
	vcipherlast	15, 15, 10
	vcipherlast	16, 16, 10
	vcipherlast	17, 17, 10
	vcipherlast	18, 18, 10
	vcipherlast	19, 19, 10
	vcipherlast	20, 20, 10
	vcipherlast	21, 21, 10
	vcipherlast	22, 22, 10
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	stxvd2x	49, 0, 4
	addi	4, 4, 16
	stxvd2x	50, 0, 4
	addi	4, 4, 16
	stxvd2x	51, 0, 4
	addi	4, 4, 16
	stxvd2x	52, 0, 4
	addi	4, 4, 16
	stxvd2x	53, 0, 4
	addi	4, 4, 16
	stxvd2x	54, 0, 4
	addi	4, 4, 16
	addi	5, 5, -128
	cmpdi	5, 0x80
	bge	L_AES_ECB_encrypt_crypto_128_blk8
L_AES_ECB_encrypt_crypto_128_blk4:
	cmpdi	5, 0x40
	blt	L_AES_ECB_encrypt_crypto_128_blk2
	lxvd2x	47, 0, 3
	addi	3, 3, 16
	lxvd2x	48, 0, 3
	addi	3, 3, 16
	lxvd2x	49, 0, 3
	addi	3, 3, 16
	lxvd2x	50, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 0
	vxor	16, 16, 0
	vxor	17, 17, 0
	vxor	18, 18, 0
	vcipher	15, 15, 1
	vcipher	16, 16, 1
	vcipher	17, 17, 1
	vcipher	18, 18, 1
	vcipher	15, 15, 2
	vcipher	16, 16, 2
	vcipher	17, 17, 2
	vcipher	18, 18, 2
	vcipher	15, 15, 3
	vcipher	16, 16, 3
	vcipher	17, 17, 3
	vcipher	18, 18, 3
	vcipher	15, 15, 4
	vcipher	16, 16, 4
	vcipher	17, 17, 4
	vcipher	18, 18, 4
	vcipher	15, 15, 5
	vcipher	16, 16, 5
	vcipher	17, 17, 5
	vcipher	18, 18, 5
	vcipher	15, 15, 6
	vcipher	16, 16, 6
	vcipher	17, 17, 6
	vcipher	18, 18, 6
	vcipher	15, 15, 7
	vcipher	16, 16, 7
	vcipher	17, 17, 7
	vcipher	18, 18, 7
	vcipher	15, 15, 8
	vcipher	16, 16, 8
	vcipher	17, 17, 8
	vcipher	18, 18, 8
	vcipher	15, 15, 9
	vcipher	16, 16, 9
	vcipher	17, 17, 9
	vcipher	18, 18, 9
	vcipherlast	15, 15, 10
	vcipherlast	16, 16, 10
	vcipherlast	17, 17, 10
	vcipherlast	18, 18, 10
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	stxvd2x	49, 0, 4
	addi	4, 4, 16
	stxvd2x	50, 0, 4
	addi	4, 4, 16
	addi	5, 5, -64
L_AES_ECB_encrypt_crypto_128_blk2:
	cmpdi	5, 32
	blt	L_AES_ECB_encrypt_crypto_128_blk1
	lxvd2x	47, 0, 3
	addi	3, 3, 16
	lxvd2x	48, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 0
	vxor	16, 16, 0
	vcipher	15, 15, 1
	vcipher	16, 16, 1
	vcipher	15, 15, 2
	vcipher	16, 16, 2
	vcipher	15, 15, 3
	vcipher	16, 16, 3
	vcipher	15, 15, 4
	vcipher	16, 16, 4
	vcipher	15, 15, 5
	vcipher	16, 16, 5
	vcipher	15, 15, 6
	vcipher	16, 16, 6
	vcipher	15, 15, 7
	vcipher	16, 16, 7
	vcipher	15, 15, 8
	vcipher	16, 16, 8
	vcipher	15, 15, 9
	vcipher	16, 16, 9
	vcipherlast	15, 15, 10
	vcipherlast	16, 16, 10
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	addi	5, 5, -32
L_AES_ECB_encrypt_crypto_128_blk1:
	cmpdi	5, 16
	blt	L_AES_ECB_encrypt_crypto_128_done
	lxvd2x	47, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 0
	vcipher	15, 15, 1
	vcipher	15, 15, 2
	vcipher	15, 15, 3
	vcipher	15, 15, 4
	vcipher	15, 15, 5
	vcipher	15, 15, 6
	vcipher	15, 15, 7
	vcipher	15, 15, 8
	vcipher	15, 15, 9
	vcipherlast	15, 15, 10
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	addi	5, 5, -16
L_AES_ECB_encrypt_crypto_128_done:
L_AES_ECB_encrypt_crypto_alldone:
	ld	0, 0(1)
	mtlr	0
	addi	1, 1, 8
	li	0, 0
	lxvd2x	52, 1, 0
	li	0, 16
	lxvd2x	53, 1, 0
	li	0, 32
	lxvd2x	54, 1, 0
	addi	1, 1, 48
	blr
#ifndef __APPLE__
	.size	AES_ECB_encrypt_crypto,.-AES_ECB_encrypt_crypto
#endif /* __APPLE__ */
	.machine	"pop"
#ifdef HAVE_AES_DECRYPT
	.machine	"push"
	.machine	"power8"
#ifndef __APPLE__
.text
.globl	AES_ECB_decrypt_crypto
.type	AES_ECB_decrypt_crypto,@function
.align	16
AES_ECB_decrypt_crypto:
#if defined(_CALL_ELF) && _CALL_ELF == 2
0:	addis	2, 12, .TOC.-0b@ha
	addi	2, 2, .TOC.-0b@l
	.localentry	AES_ECB_decrypt_crypto, .-AES_ECB_decrypt_crypto
#endif
#else
.section	__TEXT,__text
.globl	_AES_ECB_decrypt_crypto
.p2align	4
_AES_ECB_decrypt_crypto:
#endif /* __APPLE__ */
	subi	1, 1, 48
	li	0, 0
	stxvd2x	52, 1, 0
	li	0, 16
	stxvd2x	53, 1, 0
	li	0, 32
	stxvd2x	54, 1, 0
	stdu	1, -8(1)
	mflr	0
	std	0, 0(1)
	cmplwi	7, 10
	beq	L_AES_ECB_decrypt_crypto_128
	cmplwi	7, 12
	beq	L_AES_ECB_decrypt_crypto_192
	addi	8, 6, 0
	lxvd2x	32, 0, 8
	addi	8, 8, 16
	lxvd2x	33, 0, 8
	addi	8, 8, 16
	lxvd2x	34, 0, 8
	addi	8, 8, 16
	lxvd2x	35, 0, 8
	addi	8, 8, 16
	lxvd2x	36, 0, 8
	addi	8, 8, 16
	lxvd2x	37, 0, 8
	addi	8, 8, 16
	lxvd2x	38, 0, 8
	addi	8, 8, 16
	lxvd2x	39, 0, 8
	addi	8, 8, 16
	lxvd2x	40, 0, 8
	addi	8, 8, 16
	lxvd2x	41, 0, 8
	addi	8, 8, 16
	lxvd2x	42, 0, 8
	addi	8, 8, 16
	lxvd2x	43, 0, 8
	addi	8, 8, 16
	lxvd2x	44, 0, 8
	addi	8, 8, 16
	lxvd2x	45, 0, 8
	addi	8, 8, 16
	lxvd2x	46, 0, 8
	addi	8, 8, 16
	cmpdi	5, 0x80
	blt	L_AES_ECB_decrypt_crypto_256_blk4
L_AES_ECB_decrypt_crypto_256_blk8:
	lxvd2x	47, 0, 3
	addi	3, 3, 16
	lxvd2x	48, 0, 3
	addi	3, 3, 16
	lxvd2x	49, 0, 3
	addi	3, 3, 16
	lxvd2x	50, 0, 3
	addi	3, 3, 16
	lxvd2x	51, 0, 3
	addi	3, 3, 16
	lxvd2x	52, 0, 3
	addi	3, 3, 16
	lxvd2x	53, 0, 3
	addi	3, 3, 16
	lxvd2x	54, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 0
	vxor	16, 16, 0
	vxor	17, 17, 0
	vxor	18, 18, 0
	vxor	19, 19, 0
	vxor	20, 20, 0
	vxor	21, 21, 0
	vxor	22, 22, 0
	vncipher	15, 15, 1
	vncipher	16, 16, 1
	vncipher	17, 17, 1
	vncipher	18, 18, 1
	vncipher	19, 19, 1
	vncipher	20, 20, 1
	vncipher	21, 21, 1
	vncipher	22, 22, 1
	vncipher	15, 15, 2
	vncipher	16, 16, 2
	vncipher	17, 17, 2
	vncipher	18, 18, 2
	vncipher	19, 19, 2
	vncipher	20, 20, 2
	vncipher	21, 21, 2
	vncipher	22, 22, 2
	vncipher	15, 15, 3
	vncipher	16, 16, 3
	vncipher	17, 17, 3
	vncipher	18, 18, 3
	vncipher	19, 19, 3
	vncipher	20, 20, 3
	vncipher	21, 21, 3
	vncipher	22, 22, 3
	vncipher	15, 15, 4
	vncipher	16, 16, 4
	vncipher	17, 17, 4
	vncipher	18, 18, 4
	vncipher	19, 19, 4
	vncipher	20, 20, 4
	vncipher	21, 21, 4
	vncipher	22, 22, 4
	vncipher	15, 15, 5
	vncipher	16, 16, 5
	vncipher	17, 17, 5
	vncipher	18, 18, 5
	vncipher	19, 19, 5
	vncipher	20, 20, 5
	vncipher	21, 21, 5
	vncipher	22, 22, 5
	vncipher	15, 15, 6
	vncipher	16, 16, 6
	vncipher	17, 17, 6
	vncipher	18, 18, 6
	vncipher	19, 19, 6
	vncipher	20, 20, 6
	vncipher	21, 21, 6
	vncipher	22, 22, 6
	vncipher	15, 15, 7
	vncipher	16, 16, 7
	vncipher	17, 17, 7
	vncipher	18, 18, 7
	vncipher	19, 19, 7
	vncipher	20, 20, 7
	vncipher	21, 21, 7
	vncipher	22, 22, 7
	vncipher	15, 15, 8
	vncipher	16, 16, 8
	vncipher	17, 17, 8
	vncipher	18, 18, 8
	vncipher	19, 19, 8
	vncipher	20, 20, 8
	vncipher	21, 21, 8
	vncipher	22, 22, 8
	vncipher	15, 15, 9
	vncipher	16, 16, 9
	vncipher	17, 17, 9
	vncipher	18, 18, 9
	vncipher	19, 19, 9
	vncipher	20, 20, 9
	vncipher	21, 21, 9
	vncipher	22, 22, 9
	vncipher	15, 15, 10
	vncipher	16, 16, 10
	vncipher	17, 17, 10
	vncipher	18, 18, 10
	vncipher	19, 19, 10
	vncipher	20, 20, 10
	vncipher	21, 21, 10
	vncipher	22, 22, 10
	vncipher	15, 15, 11
	vncipher	16, 16, 11
	vncipher	17, 17, 11
	vncipher	18, 18, 11
	vncipher	19, 19, 11
	vncipher	20, 20, 11
	vncipher	21, 21, 11
	vncipher	22, 22, 11
	vncipher	15, 15, 12
	vncipher	16, 16, 12
	vncipher	17, 17, 12
	vncipher	18, 18, 12
	vncipher	19, 19, 12
	vncipher	20, 20, 12
	vncipher	21, 21, 12
	vncipher	22, 22, 12
	vncipher	15, 15, 13
	vncipher	16, 16, 13
	vncipher	17, 17, 13
	vncipher	18, 18, 13
	vncipher	19, 19, 13
	vncipher	20, 20, 13
	vncipher	21, 21, 13
	vncipher	22, 22, 13
	vncipherlast	15, 15, 14
	vncipherlast	16, 16, 14
	vncipherlast	17, 17, 14
	vncipherlast	18, 18, 14
	vncipherlast	19, 19, 14
	vncipherlast	20, 20, 14
	vncipherlast	21, 21, 14
	vncipherlast	22, 22, 14
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	stxvd2x	49, 0, 4
	addi	4, 4, 16
	stxvd2x	50, 0, 4
	addi	4, 4, 16
	stxvd2x	51, 0, 4
	addi	4, 4, 16
	stxvd2x	52, 0, 4
	addi	4, 4, 16
	stxvd2x	53, 0, 4
	addi	4, 4, 16
	stxvd2x	54, 0, 4
	addi	4, 4, 16
	addi	5, 5, -128
	cmpdi	5, 0x80
	bge	L_AES_ECB_decrypt_crypto_256_blk8
L_AES_ECB_decrypt_crypto_256_blk4:
	cmpdi	5, 0x40
	blt	L_AES_ECB_decrypt_crypto_256_blk2
	lxvd2x	47, 0, 3
	addi	3, 3, 16
	lxvd2x	48, 0, 3
	addi	3, 3, 16
	lxvd2x	49, 0, 3
	addi	3, 3, 16
	lxvd2x	50, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 0
	vxor	16, 16, 0
	vxor	17, 17, 0
	vxor	18, 18, 0
	vncipher	15, 15, 1
	vncipher	16, 16, 1
	vncipher	17, 17, 1
	vncipher	18, 18, 1
	vncipher	15, 15, 2
	vncipher	16, 16, 2
	vncipher	17, 17, 2
	vncipher	18, 18, 2
	vncipher	15, 15, 3
	vncipher	16, 16, 3
	vncipher	17, 17, 3
	vncipher	18, 18, 3
	vncipher	15, 15, 4
	vncipher	16, 16, 4
	vncipher	17, 17, 4
	vncipher	18, 18, 4
	vncipher	15, 15, 5
	vncipher	16, 16, 5
	vncipher	17, 17, 5
	vncipher	18, 18, 5
	vncipher	15, 15, 6
	vncipher	16, 16, 6
	vncipher	17, 17, 6
	vncipher	18, 18, 6
	vncipher	15, 15, 7
	vncipher	16, 16, 7
	vncipher	17, 17, 7
	vncipher	18, 18, 7
	vncipher	15, 15, 8
	vncipher	16, 16, 8
	vncipher	17, 17, 8
	vncipher	18, 18, 8
	vncipher	15, 15, 9
	vncipher	16, 16, 9
	vncipher	17, 17, 9
	vncipher	18, 18, 9
	vncipher	15, 15, 10
	vncipher	16, 16, 10
	vncipher	17, 17, 10
	vncipher	18, 18, 10
	vncipher	15, 15, 11
	vncipher	16, 16, 11
	vncipher	17, 17, 11
	vncipher	18, 18, 11
	vncipher	15, 15, 12
	vncipher	16, 16, 12
	vncipher	17, 17, 12
	vncipher	18, 18, 12
	vncipher	15, 15, 13
	vncipher	16, 16, 13
	vncipher	17, 17, 13
	vncipher	18, 18, 13
	vncipherlast	15, 15, 14
	vncipherlast	16, 16, 14
	vncipherlast	17, 17, 14
	vncipherlast	18, 18, 14
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	stxvd2x	49, 0, 4
	addi	4, 4, 16
	stxvd2x	50, 0, 4
	addi	4, 4, 16
	addi	5, 5, -64
L_AES_ECB_decrypt_crypto_256_blk2:
	cmpdi	5, 32
	blt	L_AES_ECB_decrypt_crypto_256_blk1
	lxvd2x	47, 0, 3
	addi	3, 3, 16
	lxvd2x	48, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 0
	vxor	16, 16, 0
	vncipher	15, 15, 1
	vncipher	16, 16, 1
	vncipher	15, 15, 2
	vncipher	16, 16, 2
	vncipher	15, 15, 3
	vncipher	16, 16, 3
	vncipher	15, 15, 4
	vncipher	16, 16, 4
	vncipher	15, 15, 5
	vncipher	16, 16, 5
	vncipher	15, 15, 6
	vncipher	16, 16, 6
	vncipher	15, 15, 7
	vncipher	16, 16, 7
	vncipher	15, 15, 8
	vncipher	16, 16, 8
	vncipher	15, 15, 9
	vncipher	16, 16, 9
	vncipher	15, 15, 10
	vncipher	16, 16, 10
	vncipher	15, 15, 11
	vncipher	16, 16, 11
	vncipher	15, 15, 12
	vncipher	16, 16, 12
	vncipher	15, 15, 13
	vncipher	16, 16, 13
	vncipherlast	15, 15, 14
	vncipherlast	16, 16, 14
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	addi	5, 5, -32
L_AES_ECB_decrypt_crypto_256_blk1:
	cmpdi	5, 16
	blt	L_AES_ECB_decrypt_crypto_256_done
	lxvd2x	47, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 0
	vncipher	15, 15, 1
	vncipher	15, 15, 2
	vncipher	15, 15, 3
	vncipher	15, 15, 4
	vncipher	15, 15, 5
	vncipher	15, 15, 6
	vncipher	15, 15, 7
	vncipher	15, 15, 8
	vncipher	15, 15, 9
	vncipher	15, 15, 10
	vncipher	15, 15, 11
	vncipher	15, 15, 12
	vncipher	15, 15, 13
	vncipherlast	15, 15, 14
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	addi	5, 5, -16
L_AES_ECB_decrypt_crypto_256_done:
	b	L_AES_ECB_decrypt_crypto_alldone
L_AES_ECB_decrypt_crypto_192:
	addi	8, 6, 0
	lxvd2x	32, 0, 8
	addi	8, 8, 16
	lxvd2x	33, 0, 8
	addi	8, 8, 16
	lxvd2x	34, 0, 8
	addi	8, 8, 16
	lxvd2x	35, 0, 8
	addi	8, 8, 16
	lxvd2x	36, 0, 8
	addi	8, 8, 16
	lxvd2x	37, 0, 8
	addi	8, 8, 16
	lxvd2x	38, 0, 8
	addi	8, 8, 16
	lxvd2x	39, 0, 8
	addi	8, 8, 16
	lxvd2x	40, 0, 8
	addi	8, 8, 16
	lxvd2x	41, 0, 8
	addi	8, 8, 16
	lxvd2x	42, 0, 8
	addi	8, 8, 16
	lxvd2x	43, 0, 8
	addi	8, 8, 16
	lxvd2x	44, 0, 8
	addi	8, 8, 16
	cmpdi	5, 0x80
	blt	L_AES_ECB_decrypt_crypto_192_blk4
L_AES_ECB_decrypt_crypto_192_blk8:
	lxvd2x	47, 0, 3
	addi	3, 3, 16
	lxvd2x	48, 0, 3
	addi	3, 3, 16
	lxvd2x	49, 0, 3
	addi	3, 3, 16
	lxvd2x	50, 0, 3
	addi	3, 3, 16
	lxvd2x	51, 0, 3
	addi	3, 3, 16
	lxvd2x	52, 0, 3
	addi	3, 3, 16
	lxvd2x	53, 0, 3
	addi	3, 3, 16
	lxvd2x	54, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 0
	vxor	16, 16, 0
	vxor	17, 17, 0
	vxor	18, 18, 0
	vxor	19, 19, 0
	vxor	20, 20, 0
	vxor	21, 21, 0
	vxor	22, 22, 0
	vncipher	15, 15, 1
	vncipher	16, 16, 1
	vncipher	17, 17, 1
	vncipher	18, 18, 1
	vncipher	19, 19, 1
	vncipher	20, 20, 1
	vncipher	21, 21, 1
	vncipher	22, 22, 1
	vncipher	15, 15, 2
	vncipher	16, 16, 2
	vncipher	17, 17, 2
	vncipher	18, 18, 2
	vncipher	19, 19, 2
	vncipher	20, 20, 2
	vncipher	21, 21, 2
	vncipher	22, 22, 2
	vncipher	15, 15, 3
	vncipher	16, 16, 3
	vncipher	17, 17, 3
	vncipher	18, 18, 3
	vncipher	19, 19, 3
	vncipher	20, 20, 3
	vncipher	21, 21, 3
	vncipher	22, 22, 3
	vncipher	15, 15, 4
	vncipher	16, 16, 4
	vncipher	17, 17, 4
	vncipher	18, 18, 4
	vncipher	19, 19, 4
	vncipher	20, 20, 4
	vncipher	21, 21, 4
	vncipher	22, 22, 4
	vncipher	15, 15, 5
	vncipher	16, 16, 5
	vncipher	17, 17, 5
	vncipher	18, 18, 5
	vncipher	19, 19, 5
	vncipher	20, 20, 5
	vncipher	21, 21, 5
	vncipher	22, 22, 5
	vncipher	15, 15, 6
	vncipher	16, 16, 6
	vncipher	17, 17, 6
	vncipher	18, 18, 6
	vncipher	19, 19, 6
	vncipher	20, 20, 6
	vncipher	21, 21, 6
	vncipher	22, 22, 6
	vncipher	15, 15, 7
	vncipher	16, 16, 7
	vncipher	17, 17, 7
	vncipher	18, 18, 7
	vncipher	19, 19, 7
	vncipher	20, 20, 7
	vncipher	21, 21, 7
	vncipher	22, 22, 7
	vncipher	15, 15, 8
	vncipher	16, 16, 8
	vncipher	17, 17, 8
	vncipher	18, 18, 8
	vncipher	19, 19, 8
	vncipher	20, 20, 8
	vncipher	21, 21, 8
	vncipher	22, 22, 8
	vncipher	15, 15, 9
	vncipher	16, 16, 9
	vncipher	17, 17, 9
	vncipher	18, 18, 9
	vncipher	19, 19, 9
	vncipher	20, 20, 9
	vncipher	21, 21, 9
	vncipher	22, 22, 9
	vncipher	15, 15, 10
	vncipher	16, 16, 10
	vncipher	17, 17, 10
	vncipher	18, 18, 10
	vncipher	19, 19, 10
	vncipher	20, 20, 10
	vncipher	21, 21, 10
	vncipher	22, 22, 10
	vncipher	15, 15, 11
	vncipher	16, 16, 11
	vncipher	17, 17, 11
	vncipher	18, 18, 11
	vncipher	19, 19, 11
	vncipher	20, 20, 11
	vncipher	21, 21, 11
	vncipher	22, 22, 11
	vncipherlast	15, 15, 12
	vncipherlast	16, 16, 12
	vncipherlast	17, 17, 12
	vncipherlast	18, 18, 12
	vncipherlast	19, 19, 12
	vncipherlast	20, 20, 12
	vncipherlast	21, 21, 12
	vncipherlast	22, 22, 12
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	stxvd2x	49, 0, 4
	addi	4, 4, 16
	stxvd2x	50, 0, 4
	addi	4, 4, 16
	stxvd2x	51, 0, 4
	addi	4, 4, 16
	stxvd2x	52, 0, 4
	addi	4, 4, 16
	stxvd2x	53, 0, 4
	addi	4, 4, 16
	stxvd2x	54, 0, 4
	addi	4, 4, 16
	addi	5, 5, -128
	cmpdi	5, 0x80
	bge	L_AES_ECB_decrypt_crypto_192_blk8
L_AES_ECB_decrypt_crypto_192_blk4:
	cmpdi	5, 0x40
	blt	L_AES_ECB_decrypt_crypto_192_blk2
	lxvd2x	47, 0, 3
	addi	3, 3, 16
	lxvd2x	48, 0, 3
	addi	3, 3, 16
	lxvd2x	49, 0, 3
	addi	3, 3, 16
	lxvd2x	50, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 0
	vxor	16, 16, 0
	vxor	17, 17, 0
	vxor	18, 18, 0
	vncipher	15, 15, 1
	vncipher	16, 16, 1
	vncipher	17, 17, 1
	vncipher	18, 18, 1
	vncipher	15, 15, 2
	vncipher	16, 16, 2
	vncipher	17, 17, 2
	vncipher	18, 18, 2
	vncipher	15, 15, 3
	vncipher	16, 16, 3
	vncipher	17, 17, 3
	vncipher	18, 18, 3
	vncipher	15, 15, 4
	vncipher	16, 16, 4
	vncipher	17, 17, 4
	vncipher	18, 18, 4
	vncipher	15, 15, 5
	vncipher	16, 16, 5
	vncipher	17, 17, 5
	vncipher	18, 18, 5
	vncipher	15, 15, 6
	vncipher	16, 16, 6
	vncipher	17, 17, 6
	vncipher	18, 18, 6
	vncipher	15, 15, 7
	vncipher	16, 16, 7
	vncipher	17, 17, 7
	vncipher	18, 18, 7
	vncipher	15, 15, 8
	vncipher	16, 16, 8
	vncipher	17, 17, 8
	vncipher	18, 18, 8
	vncipher	15, 15, 9
	vncipher	16, 16, 9
	vncipher	17, 17, 9
	vncipher	18, 18, 9
	vncipher	15, 15, 10
	vncipher	16, 16, 10
	vncipher	17, 17, 10
	vncipher	18, 18, 10
	vncipher	15, 15, 11
	vncipher	16, 16, 11
	vncipher	17, 17, 11
	vncipher	18, 18, 11
	vncipherlast	15, 15, 12
	vncipherlast	16, 16, 12
	vncipherlast	17, 17, 12
	vncipherlast	18, 18, 12
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	stxvd2x	49, 0, 4
	addi	4, 4, 16
	stxvd2x	50, 0, 4
	addi	4, 4, 16
	addi	5, 5, -64
L_AES_ECB_decrypt_crypto_192_blk2:
	cmpdi	5, 32
	blt	L_AES_ECB_decrypt_crypto_192_blk1
	lxvd2x	47, 0, 3
	addi	3, 3, 16
	lxvd2x	48, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 0
	vxor	16, 16, 0
	vncipher	15, 15, 1
	vncipher	16, 16, 1
	vncipher	15, 15, 2
	vncipher	16, 16, 2
	vncipher	15, 15, 3
	vncipher	16, 16, 3
	vncipher	15, 15, 4
	vncipher	16, 16, 4
	vncipher	15, 15, 5
	vncipher	16, 16, 5
	vncipher	15, 15, 6
	vncipher	16, 16, 6
	vncipher	15, 15, 7
	vncipher	16, 16, 7
	vncipher	15, 15, 8
	vncipher	16, 16, 8
	vncipher	15, 15, 9
	vncipher	16, 16, 9
	vncipher	15, 15, 10
	vncipher	16, 16, 10
	vncipher	15, 15, 11
	vncipher	16, 16, 11
	vncipherlast	15, 15, 12
	vncipherlast	16, 16, 12
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	addi	5, 5, -32
L_AES_ECB_decrypt_crypto_192_blk1:
	cmpdi	5, 16
	blt	L_AES_ECB_decrypt_crypto_192_done
	lxvd2x	47, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 0
	vncipher	15, 15, 1
	vncipher	15, 15, 2
	vncipher	15, 15, 3
	vncipher	15, 15, 4
	vncipher	15, 15, 5
	vncipher	15, 15, 6
	vncipher	15, 15, 7
	vncipher	15, 15, 8
	vncipher	15, 15, 9
	vncipher	15, 15, 10
	vncipher	15, 15, 11
	vncipherlast	15, 15, 12
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	addi	5, 5, -16
L_AES_ECB_decrypt_crypto_192_done:
	b	L_AES_ECB_decrypt_crypto_alldone
L_AES_ECB_decrypt_crypto_128:
	addi	8, 6, 0
	lxvd2x	32, 0, 8
	addi	8, 8, 16
	lxvd2x	33, 0, 8
	addi	8, 8, 16
	lxvd2x	34, 0, 8
	addi	8, 8, 16
	lxvd2x	35, 0, 8
	addi	8, 8, 16
	lxvd2x	36, 0, 8
	addi	8, 8, 16
	lxvd2x	37, 0, 8
	addi	8, 8, 16
	lxvd2x	38, 0, 8
	addi	8, 8, 16
	lxvd2x	39, 0, 8
	addi	8, 8, 16
	lxvd2x	40, 0, 8
	addi	8, 8, 16
	lxvd2x	41, 0, 8
	addi	8, 8, 16
	lxvd2x	42, 0, 8
	addi	8, 8, 16
	cmpdi	5, 0x80
	blt	L_AES_ECB_decrypt_crypto_128_blk4
L_AES_ECB_decrypt_crypto_128_blk8:
	lxvd2x	47, 0, 3
	addi	3, 3, 16
	lxvd2x	48, 0, 3
	addi	3, 3, 16
	lxvd2x	49, 0, 3
	addi	3, 3, 16
	lxvd2x	50, 0, 3
	addi	3, 3, 16
	lxvd2x	51, 0, 3
	addi	3, 3, 16
	lxvd2x	52, 0, 3
	addi	3, 3, 16
	lxvd2x	53, 0, 3
	addi	3, 3, 16
	lxvd2x	54, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 0
	vxor	16, 16, 0
	vxor	17, 17, 0
	vxor	18, 18, 0
	vxor	19, 19, 0
	vxor	20, 20, 0
	vxor	21, 21, 0
	vxor	22, 22, 0
	vncipher	15, 15, 1
	vncipher	16, 16, 1
	vncipher	17, 17, 1
	vncipher	18, 18, 1
	vncipher	19, 19, 1
	vncipher	20, 20, 1
	vncipher	21, 21, 1
	vncipher	22, 22, 1
	vncipher	15, 15, 2
	vncipher	16, 16, 2
	vncipher	17, 17, 2
	vncipher	18, 18, 2
	vncipher	19, 19, 2
	vncipher	20, 20, 2
	vncipher	21, 21, 2
	vncipher	22, 22, 2
	vncipher	15, 15, 3
	vncipher	16, 16, 3
	vncipher	17, 17, 3
	vncipher	18, 18, 3
	vncipher	19, 19, 3
	vncipher	20, 20, 3
	vncipher	21, 21, 3
	vncipher	22, 22, 3
	vncipher	15, 15, 4
	vncipher	16, 16, 4
	vncipher	17, 17, 4
	vncipher	18, 18, 4
	vncipher	19, 19, 4
	vncipher	20, 20, 4
	vncipher	21, 21, 4
	vncipher	22, 22, 4
	vncipher	15, 15, 5
	vncipher	16, 16, 5
	vncipher	17, 17, 5
	vncipher	18, 18, 5
	vncipher	19, 19, 5
	vncipher	20, 20, 5
	vncipher	21, 21, 5
	vncipher	22, 22, 5
	vncipher	15, 15, 6
	vncipher	16, 16, 6
	vncipher	17, 17, 6
	vncipher	18, 18, 6
	vncipher	19, 19, 6
	vncipher	20, 20, 6
	vncipher	21, 21, 6
	vncipher	22, 22, 6
	vncipher	15, 15, 7
	vncipher	16, 16, 7
	vncipher	17, 17, 7
	vncipher	18, 18, 7
	vncipher	19, 19, 7
	vncipher	20, 20, 7
	vncipher	21, 21, 7
	vncipher	22, 22, 7
	vncipher	15, 15, 8
	vncipher	16, 16, 8
	vncipher	17, 17, 8
	vncipher	18, 18, 8
	vncipher	19, 19, 8
	vncipher	20, 20, 8
	vncipher	21, 21, 8
	vncipher	22, 22, 8
	vncipher	15, 15, 9
	vncipher	16, 16, 9
	vncipher	17, 17, 9
	vncipher	18, 18, 9
	vncipher	19, 19, 9
	vncipher	20, 20, 9
	vncipher	21, 21, 9
	vncipher	22, 22, 9
	vncipherlast	15, 15, 10
	vncipherlast	16, 16, 10
	vncipherlast	17, 17, 10
	vncipherlast	18, 18, 10
	vncipherlast	19, 19, 10
	vncipherlast	20, 20, 10
	vncipherlast	21, 21, 10
	vncipherlast	22, 22, 10
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	stxvd2x	49, 0, 4
	addi	4, 4, 16
	stxvd2x	50, 0, 4
	addi	4, 4, 16
	stxvd2x	51, 0, 4
	addi	4, 4, 16
	stxvd2x	52, 0, 4
	addi	4, 4, 16
	stxvd2x	53, 0, 4
	addi	4, 4, 16
	stxvd2x	54, 0, 4
	addi	4, 4, 16
	addi	5, 5, -128
	cmpdi	5, 0x80
	bge	L_AES_ECB_decrypt_crypto_128_blk8
L_AES_ECB_decrypt_crypto_128_blk4:
	cmpdi	5, 0x40
	blt	L_AES_ECB_decrypt_crypto_128_blk2
	lxvd2x	47, 0, 3
	addi	3, 3, 16
	lxvd2x	48, 0, 3
	addi	3, 3, 16
	lxvd2x	49, 0, 3
	addi	3, 3, 16
	lxvd2x	50, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 0
	vxor	16, 16, 0
	vxor	17, 17, 0
	vxor	18, 18, 0
	vncipher	15, 15, 1
	vncipher	16, 16, 1
	vncipher	17, 17, 1
	vncipher	18, 18, 1
	vncipher	15, 15, 2
	vncipher	16, 16, 2
	vncipher	17, 17, 2
	vncipher	18, 18, 2
	vncipher	15, 15, 3
	vncipher	16, 16, 3
	vncipher	17, 17, 3
	vncipher	18, 18, 3
	vncipher	15, 15, 4
	vncipher	16, 16, 4
	vncipher	17, 17, 4
	vncipher	18, 18, 4
	vncipher	15, 15, 5
	vncipher	16, 16, 5
	vncipher	17, 17, 5
	vncipher	18, 18, 5
	vncipher	15, 15, 6
	vncipher	16, 16, 6
	vncipher	17, 17, 6
	vncipher	18, 18, 6
	vncipher	15, 15, 7
	vncipher	16, 16, 7
	vncipher	17, 17, 7
	vncipher	18, 18, 7
	vncipher	15, 15, 8
	vncipher	16, 16, 8
	vncipher	17, 17, 8
	vncipher	18, 18, 8
	vncipher	15, 15, 9
	vncipher	16, 16, 9
	vncipher	17, 17, 9
	vncipher	18, 18, 9
	vncipherlast	15, 15, 10
	vncipherlast	16, 16, 10
	vncipherlast	17, 17, 10
	vncipherlast	18, 18, 10
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	stxvd2x	49, 0, 4
	addi	4, 4, 16
	stxvd2x	50, 0, 4
	addi	4, 4, 16
	addi	5, 5, -64
L_AES_ECB_decrypt_crypto_128_blk2:
	cmpdi	5, 32
	blt	L_AES_ECB_decrypt_crypto_128_blk1
	lxvd2x	47, 0, 3
	addi	3, 3, 16
	lxvd2x	48, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 0
	vxor	16, 16, 0
	vncipher	15, 15, 1
	vncipher	16, 16, 1
	vncipher	15, 15, 2
	vncipher	16, 16, 2
	vncipher	15, 15, 3
	vncipher	16, 16, 3
	vncipher	15, 15, 4
	vncipher	16, 16, 4
	vncipher	15, 15, 5
	vncipher	16, 16, 5
	vncipher	15, 15, 6
	vncipher	16, 16, 6
	vncipher	15, 15, 7
	vncipher	16, 16, 7
	vncipher	15, 15, 8
	vncipher	16, 16, 8
	vncipher	15, 15, 9
	vncipher	16, 16, 9
	vncipherlast	15, 15, 10
	vncipherlast	16, 16, 10
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	addi	5, 5, -32
L_AES_ECB_decrypt_crypto_128_blk1:
	cmpdi	5, 16
	blt	L_AES_ECB_decrypt_crypto_128_done
	lxvd2x	47, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 0
	vncipher	15, 15, 1
	vncipher	15, 15, 2
	vncipher	15, 15, 3
	vncipher	15, 15, 4
	vncipher	15, 15, 5
	vncipher	15, 15, 6
	vncipher	15, 15, 7
	vncipher	15, 15, 8
	vncipher	15, 15, 9
	vncipherlast	15, 15, 10
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	addi	5, 5, -16
L_AES_ECB_decrypt_crypto_128_done:
L_AES_ECB_decrypt_crypto_alldone:
	ld	0, 0(1)
	mtlr	0
	addi	1, 1, 8
	li	0, 0
	lxvd2x	52, 1, 0
	li	0, 16
	lxvd2x	53, 1, 0
	li	0, 32
	lxvd2x	54, 1, 0
	addi	1, 1, 48
	blr
#ifndef __APPLE__
	.size	AES_ECB_decrypt_crypto,.-AES_ECB_decrypt_crypto
#endif /* __APPLE__ */
	.machine	"pop"
#endif /* HAVE_AES_DECRYPT */
#ifdef HAVE_AES_CBC
	.machine	"push"
	.machine	"power8"
#ifndef __APPLE__
.text
.globl	AES_CBC_encrypt_crypto
.type	AES_CBC_encrypt_crypto,@function
.align	16
AES_CBC_encrypt_crypto:
#if defined(_CALL_ELF) && _CALL_ELF == 2
0:	addis	2, 12, .TOC.-0b@ha
	addi	2, 2, .TOC.-0b@l
	.localentry	AES_CBC_encrypt_crypto, .-AES_CBC_encrypt_crypto
#endif
#else
.section	__TEXT,__text
.globl	_AES_CBC_encrypt_crypto
.p2align	4
_AES_CBC_encrypt_crypto:
#endif /* __APPLE__ */
	stdu	1, -8(1)
	mflr	0
	std	0, 0(1)
	lxvd2x	47, 0, 8
	cmplwi	7, 10
	beq	L_AES_CBC_encrypt_crypto_128
	cmplwi	7, 12
	beq	L_AES_CBC_encrypt_crypto_192
	addi	9, 6, 0
	lxvd2x	32, 0, 9
	addi	9, 9, 16
	lxvd2x	33, 0, 9
	addi	9, 9, 16
	lxvd2x	34, 0, 9
	addi	9, 9, 16
	lxvd2x	35, 0, 9
	addi	9, 9, 16
	lxvd2x	36, 0, 9
	addi	9, 9, 16
	lxvd2x	37, 0, 9
	addi	9, 9, 16
	lxvd2x	38, 0, 9
	addi	9, 9, 16
	lxvd2x	39, 0, 9
	addi	9, 9, 16
	lxvd2x	40, 0, 9
	addi	9, 9, 16
	lxvd2x	41, 0, 9
	addi	9, 9, 16
	lxvd2x	42, 0, 9
	addi	9, 9, 16
	lxvd2x	43, 0, 9
	addi	9, 9, 16
	lxvd2x	44, 0, 9
	addi	9, 9, 16
	lxvd2x	45, 0, 9
	addi	9, 9, 16
	lxvd2x	46, 0, 9
	addi	9, 9, 16
L_AES_CBC_encrypt_crypto_256_block:
	lxvd2x	48, 0, 3
	vxor	15, 15, 16
	vxor	15, 15, 0
	vcipher	15, 15, 1
	vcipher	15, 15, 2
	vcipher	15, 15, 3
	vcipher	15, 15, 4
	vcipher	15, 15, 5
	vcipher	15, 15, 6
	vcipher	15, 15, 7
	vcipher	15, 15, 8
	vcipher	15, 15, 9
	vcipher	15, 15, 10
	vcipher	15, 15, 11
	vcipher	15, 15, 12
	vcipher	15, 15, 13
	vcipherlast	15, 15, 14
	stxvd2x	47, 0, 4
	addi	3, 3, 16
	addi	4, 4, 16
	addic.	5, 5, -16
	bne	L_AES_CBC_encrypt_crypto_256_block
	b	L_AES_CBC_encrypt_crypto_alldone
L_AES_CBC_encrypt_crypto_192:
	addi	9, 6, 0
	lxvd2x	32, 0, 9
	addi	9, 9, 16
	lxvd2x	33, 0, 9
	addi	9, 9, 16
	lxvd2x	34, 0, 9
	addi	9, 9, 16
	lxvd2x	35, 0, 9
	addi	9, 9, 16
	lxvd2x	36, 0, 9
	addi	9, 9, 16
	lxvd2x	37, 0, 9
	addi	9, 9, 16
	lxvd2x	38, 0, 9
	addi	9, 9, 16
	lxvd2x	39, 0, 9
	addi	9, 9, 16
	lxvd2x	40, 0, 9
	addi	9, 9, 16
	lxvd2x	41, 0, 9
	addi	9, 9, 16
	lxvd2x	42, 0, 9
	addi	9, 9, 16
	lxvd2x	43, 0, 9
	addi	9, 9, 16
	lxvd2x	44, 0, 9
	addi	9, 9, 16
L_AES_CBC_encrypt_crypto_192_block:
	lxvd2x	48, 0, 3
	vxor	15, 15, 16
	vxor	15, 15, 0
	vcipher	15, 15, 1
	vcipher	15, 15, 2
	vcipher	15, 15, 3
	vcipher	15, 15, 4
	vcipher	15, 15, 5
	vcipher	15, 15, 6
	vcipher	15, 15, 7
	vcipher	15, 15, 8
	vcipher	15, 15, 9
	vcipher	15, 15, 10
	vcipher	15, 15, 11
	vcipherlast	15, 15, 12
	stxvd2x	47, 0, 4
	addi	3, 3, 16
	addi	4, 4, 16
	addic.	5, 5, -16
	bne	L_AES_CBC_encrypt_crypto_192_block
	b	L_AES_CBC_encrypt_crypto_alldone
L_AES_CBC_encrypt_crypto_128:
	addi	9, 6, 0
	lxvd2x	32, 0, 9
	addi	9, 9, 16
	lxvd2x	33, 0, 9
	addi	9, 9, 16
	lxvd2x	34, 0, 9
	addi	9, 9, 16
	lxvd2x	35, 0, 9
	addi	9, 9, 16
	lxvd2x	36, 0, 9
	addi	9, 9, 16
	lxvd2x	37, 0, 9
	addi	9, 9, 16
	lxvd2x	38, 0, 9
	addi	9, 9, 16
	lxvd2x	39, 0, 9
	addi	9, 9, 16
	lxvd2x	40, 0, 9
	addi	9, 9, 16
	lxvd2x	41, 0, 9
	addi	9, 9, 16
	lxvd2x	42, 0, 9
	addi	9, 9, 16
L_AES_CBC_encrypt_crypto_128_block:
	lxvd2x	48, 0, 3
	vxor	15, 15, 16
	vxor	15, 15, 0
	vcipher	15, 15, 1
	vcipher	15, 15, 2
	vcipher	15, 15, 3
	vcipher	15, 15, 4
	vcipher	15, 15, 5
	vcipher	15, 15, 6
	vcipher	15, 15, 7
	vcipher	15, 15, 8
	vcipher	15, 15, 9
	vcipherlast	15, 15, 10
	stxvd2x	47, 0, 4
	addi	3, 3, 16
	addi	4, 4, 16
	addic.	5, 5, -16
	bne	L_AES_CBC_encrypt_crypto_128_block
L_AES_CBC_encrypt_crypto_alldone:
	stxvd2x	47, 0, 8
	ld	0, 0(1)
	mtlr	0
	addi	1, 1, 8
	blr
#ifndef __APPLE__
	.size	AES_CBC_encrypt_crypto,.-AES_CBC_encrypt_crypto
#endif /* __APPLE__ */
	.machine	"pop"
#ifdef HAVE_AES_DECRYPT
	.machine	"push"
	.machine	"power8"
#ifndef __APPLE__
.text
.globl	AES_CBC_decrypt_crypto
.type	AES_CBC_decrypt_crypto,@function
.align	16
AES_CBC_decrypt_crypto:
#if defined(_CALL_ELF) && _CALL_ELF == 2
0:	addis	2, 12, .TOC.-0b@ha
	addi	2, 2, .TOC.-0b@l
	.localentry	AES_CBC_decrypt_crypto, .-AES_CBC_decrypt_crypto
#endif
#else
.section	__TEXT,__text
.globl	_AES_CBC_decrypt_crypto
.p2align	4
_AES_CBC_decrypt_crypto:
#endif /* __APPLE__ */
	subi	1, 1, 0xc0
	li	0, 0
	stxvd2x	52, 1, 0
	li	0, 16
	stxvd2x	53, 1, 0
	li	0, 32
	stxvd2x	54, 1, 0
	li	0, 48
	stxvd2x	55, 1, 0
	li	0, 0x40
	stxvd2x	56, 1, 0
	li	0, 0x50
	stxvd2x	57, 1, 0
	li	0, 0x60
	stxvd2x	58, 1, 0
	li	0, 0x70
	stxvd2x	59, 1, 0
	li	0, 0x80
	stxvd2x	60, 1, 0
	li	0, 0x90
	stxvd2x	61, 1, 0
	li	0, 0xa0
	stxvd2x	62, 1, 0
	li	0, 0xb0
	stxvd2x	63, 1, 0
	stdu	1, -8(1)
	mflr	0
	std	0, 0(1)
	lxvd2x	63, 0, 8
	cmplwi	7, 10
	beq	L_AES_CBC_decrypt_crypto_128
	cmplwi	7, 12
	beq	L_AES_CBC_decrypt_crypto_192
	addi	9, 6, 0
	lxvd2x	32, 0, 9
	addi	9, 9, 16
	lxvd2x	33, 0, 9
	addi	9, 9, 16
	lxvd2x	34, 0, 9
	addi	9, 9, 16
	lxvd2x	35, 0, 9
	addi	9, 9, 16
	lxvd2x	36, 0, 9
	addi	9, 9, 16
	lxvd2x	37, 0, 9
	addi	9, 9, 16
	lxvd2x	38, 0, 9
	addi	9, 9, 16
	lxvd2x	39, 0, 9
	addi	9, 9, 16
	lxvd2x	40, 0, 9
	addi	9, 9, 16
	lxvd2x	41, 0, 9
	addi	9, 9, 16
	lxvd2x	42, 0, 9
	addi	9, 9, 16
	lxvd2x	43, 0, 9
	addi	9, 9, 16
	lxvd2x	44, 0, 9
	addi	9, 9, 16
	lxvd2x	45, 0, 9
	addi	9, 9, 16
	lxvd2x	46, 0, 9
	addi	9, 9, 16
	cmpdi	5, 0x80
	blt	L_AES_CBC_decrypt_crypto_256_blk4
L_AES_CBC_decrypt_crypto_256_blk8:
	lxvd2x	47, 0, 3
	vor	23, 15, 15 /* codespell:ignore vor */
	addi	3, 3, 16
	lxvd2x	48, 0, 3
	vor	24, 16, 16 /* codespell:ignore vor */
	addi	3, 3, 16
	lxvd2x	49, 0, 3
	vor	25, 17, 17 /* codespell:ignore vor */
	addi	3, 3, 16
	lxvd2x	50, 0, 3
	vor	26, 18, 18 /* codespell:ignore vor */
	addi	3, 3, 16
	lxvd2x	51, 0, 3
	vor	27, 19, 19 /* codespell:ignore vor */
	addi	3, 3, 16
	lxvd2x	52, 0, 3
	vor	28, 20, 20 /* codespell:ignore vor */
	addi	3, 3, 16
	lxvd2x	53, 0, 3
	vor	29, 21, 21 /* codespell:ignore vor */
	addi	3, 3, 16
	lxvd2x	54, 0, 3
	vor	30, 22, 22 /* codespell:ignore vor */
	addi	3, 3, 16
	vxor	15, 15, 0
	vxor	16, 16, 0
	vxor	17, 17, 0
	vxor	18, 18, 0
	vxor	19, 19, 0
	vxor	20, 20, 0
	vxor	21, 21, 0
	vxor	22, 22, 0
	vncipher	15, 15, 1
	vncipher	16, 16, 1
	vncipher	17, 17, 1
	vncipher	18, 18, 1
	vncipher	19, 19, 1
	vncipher	20, 20, 1
	vncipher	21, 21, 1
	vncipher	22, 22, 1
	vncipher	15, 15, 2
	vncipher	16, 16, 2
	vncipher	17, 17, 2
	vncipher	18, 18, 2
	vncipher	19, 19, 2
	vncipher	20, 20, 2
	vncipher	21, 21, 2
	vncipher	22, 22, 2
	vncipher	15, 15, 3
	vncipher	16, 16, 3
	vncipher	17, 17, 3
	vncipher	18, 18, 3
	vncipher	19, 19, 3
	vncipher	20, 20, 3
	vncipher	21, 21, 3
	vncipher	22, 22, 3
	vncipher	15, 15, 4
	vncipher	16, 16, 4
	vncipher	17, 17, 4
	vncipher	18, 18, 4
	vncipher	19, 19, 4
	vncipher	20, 20, 4
	vncipher	21, 21, 4
	vncipher	22, 22, 4
	vncipher	15, 15, 5
	vncipher	16, 16, 5
	vncipher	17, 17, 5
	vncipher	18, 18, 5
	vncipher	19, 19, 5
	vncipher	20, 20, 5
	vncipher	21, 21, 5
	vncipher	22, 22, 5
	vncipher	15, 15, 6
	vncipher	16, 16, 6
	vncipher	17, 17, 6
	vncipher	18, 18, 6
	vncipher	19, 19, 6
	vncipher	20, 20, 6
	vncipher	21, 21, 6
	vncipher	22, 22, 6
	vncipher	15, 15, 7
	vncipher	16, 16, 7
	vncipher	17, 17, 7
	vncipher	18, 18, 7
	vncipher	19, 19, 7
	vncipher	20, 20, 7
	vncipher	21, 21, 7
	vncipher	22, 22, 7
	vncipher	15, 15, 8
	vncipher	16, 16, 8
	vncipher	17, 17, 8
	vncipher	18, 18, 8
	vncipher	19, 19, 8
	vncipher	20, 20, 8
	vncipher	21, 21, 8
	vncipher	22, 22, 8
	vncipher	15, 15, 9
	vncipher	16, 16, 9
	vncipher	17, 17, 9
	vncipher	18, 18, 9
	vncipher	19, 19, 9
	vncipher	20, 20, 9
	vncipher	21, 21, 9
	vncipher	22, 22, 9
	vncipher	15, 15, 10
	vncipher	16, 16, 10
	vncipher	17, 17, 10
	vncipher	18, 18, 10
	vncipher	19, 19, 10
	vncipher	20, 20, 10
	vncipher	21, 21, 10
	vncipher	22, 22, 10
	vncipher	15, 15, 11
	vncipher	16, 16, 11
	vncipher	17, 17, 11
	vncipher	18, 18, 11
	vncipher	19, 19, 11
	vncipher	20, 20, 11
	vncipher	21, 21, 11
	vncipher	22, 22, 11
	vncipher	15, 15, 12
	vncipher	16, 16, 12
	vncipher	17, 17, 12
	vncipher	18, 18, 12
	vncipher	19, 19, 12
	vncipher	20, 20, 12
	vncipher	21, 21, 12
	vncipher	22, 22, 12
	vncipher	15, 15, 13
	vncipher	16, 16, 13
	vncipher	17, 17, 13
	vncipher	18, 18, 13
	vncipher	19, 19, 13
	vncipher	20, 20, 13
	vncipher	21, 21, 13
	vncipher	22, 22, 13
	vncipherlast	15, 15, 14
	vncipherlast	16, 16, 14
	vncipherlast	17, 17, 14
	vncipherlast	18, 18, 14
	vncipherlast	19, 19, 14
	vncipherlast	20, 20, 14
	vncipherlast	21, 21, 14
	vncipherlast	22, 22, 14
	vxor	15, 15, 31
	vxor	16, 16, 23
	vxor	17, 17, 24
	vxor	18, 18, 25
	vxor	19, 19, 26
	vxor	20, 20, 27
	vxor	21, 21, 28
	vxor	22, 22, 29
	vor	31, 30, 30 /* codespell:ignore vor */
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	stxvd2x	49, 0, 4
	addi	4, 4, 16
	stxvd2x	50, 0, 4
	addi	4, 4, 16
	stxvd2x	51, 0, 4
	addi	4, 4, 16
	stxvd2x	52, 0, 4
	addi	4, 4, 16
	stxvd2x	53, 0, 4
	addi	4, 4, 16
	stxvd2x	54, 0, 4
	addi	4, 4, 16
	addi	5, 5, -128
	cmpdi	5, 0x80
	bge	L_AES_CBC_decrypt_crypto_256_blk8
L_AES_CBC_decrypt_crypto_256_blk4:
	cmpdi	5, 0x40
	blt	L_AES_CBC_decrypt_crypto_256_blk2
	lxvd2x	47, 0, 3
	vor	23, 15, 15 /* codespell:ignore vor */
	addi	3, 3, 16
	lxvd2x	48, 0, 3
	vor	24, 16, 16 /* codespell:ignore vor */
	addi	3, 3, 16
	lxvd2x	49, 0, 3
	vor	25, 17, 17 /* codespell:ignore vor */
	addi	3, 3, 16
	lxvd2x	50, 0, 3
	vor	26, 18, 18 /* codespell:ignore vor */
	addi	3, 3, 16
	vxor	15, 15, 0
	vxor	16, 16, 0
	vxor	17, 17, 0
	vxor	18, 18, 0
	vncipher	15, 15, 1
	vncipher	16, 16, 1
	vncipher	17, 17, 1
	vncipher	18, 18, 1
	vncipher	15, 15, 2
	vncipher	16, 16, 2
	vncipher	17, 17, 2
	vncipher	18, 18, 2
	vncipher	15, 15, 3
	vncipher	16, 16, 3
	vncipher	17, 17, 3
	vncipher	18, 18, 3
	vncipher	15, 15, 4
	vncipher	16, 16, 4
	vncipher	17, 17, 4
	vncipher	18, 18, 4
	vncipher	15, 15, 5
	vncipher	16, 16, 5
	vncipher	17, 17, 5
	vncipher	18, 18, 5
	vncipher	15, 15, 6
	vncipher	16, 16, 6
	vncipher	17, 17, 6
	vncipher	18, 18, 6
	vncipher	15, 15, 7
	vncipher	16, 16, 7
	vncipher	17, 17, 7
	vncipher	18, 18, 7
	vncipher	15, 15, 8
	vncipher	16, 16, 8
	vncipher	17, 17, 8
	vncipher	18, 18, 8
	vncipher	15, 15, 9
	vncipher	16, 16, 9
	vncipher	17, 17, 9
	vncipher	18, 18, 9
	vncipher	15, 15, 10
	vncipher	16, 16, 10
	vncipher	17, 17, 10
	vncipher	18, 18, 10
	vncipher	15, 15, 11
	vncipher	16, 16, 11
	vncipher	17, 17, 11
	vncipher	18, 18, 11
	vncipher	15, 15, 12
	vncipher	16, 16, 12
	vncipher	17, 17, 12
	vncipher	18, 18, 12
	vncipher	15, 15, 13
	vncipher	16, 16, 13
	vncipher	17, 17, 13
	vncipher	18, 18, 13
	vncipherlast	15, 15, 14
	vncipherlast	16, 16, 14
	vncipherlast	17, 17, 14
	vncipherlast	18, 18, 14
	vxor	15, 15, 31
	vxor	16, 16, 23
	vxor	17, 17, 24
	vxor	18, 18, 25
	vor	31, 26, 26 /* codespell:ignore vor */
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	stxvd2x	49, 0, 4
	addi	4, 4, 16
	stxvd2x	50, 0, 4
	addi	4, 4, 16
	addi	5, 5, -64
L_AES_CBC_decrypt_crypto_256_blk2:
	cmpdi	5, 32
	blt	L_AES_CBC_decrypt_crypto_256_blk1
	lxvd2x	47, 0, 3
	vor	23, 15, 15 /* codespell:ignore vor */
	addi	3, 3, 16
	lxvd2x	48, 0, 3
	vor	24, 16, 16 /* codespell:ignore vor */
	addi	3, 3, 16
	vxor	15, 15, 0
	vxor	16, 16, 0
	vncipher	15, 15, 1
	vncipher	16, 16, 1
	vncipher	15, 15, 2
	vncipher	16, 16, 2
	vncipher	15, 15, 3
	vncipher	16, 16, 3
	vncipher	15, 15, 4
	vncipher	16, 16, 4
	vncipher	15, 15, 5
	vncipher	16, 16, 5
	vncipher	15, 15, 6
	vncipher	16, 16, 6
	vncipher	15, 15, 7
	vncipher	16, 16, 7
	vncipher	15, 15, 8
	vncipher	16, 16, 8
	vncipher	15, 15, 9
	vncipher	16, 16, 9
	vncipher	15, 15, 10
	vncipher	16, 16, 10
	vncipher	15, 15, 11
	vncipher	16, 16, 11
	vncipher	15, 15, 12
	vncipher	16, 16, 12
	vncipher	15, 15, 13
	vncipher	16, 16, 13
	vncipherlast	15, 15, 14
	vncipherlast	16, 16, 14
	vxor	15, 15, 31
	vxor	16, 16, 23
	vor	31, 24, 24 /* codespell:ignore vor */
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	addi	5, 5, -32
L_AES_CBC_decrypt_crypto_256_blk1:
	cmpdi	5, 16
	blt	L_AES_CBC_decrypt_crypto_256_done
	lxvd2x	47, 0, 3
	vor	23, 15, 15 /* codespell:ignore vor */
	addi	3, 3, 16
	vxor	15, 15, 0
	vncipher	15, 15, 1
	vncipher	15, 15, 2
	vncipher	15, 15, 3
	vncipher	15, 15, 4
	vncipher	15, 15, 5
	vncipher	15, 15, 6
	vncipher	15, 15, 7
	vncipher	15, 15, 8
	vncipher	15, 15, 9
	vncipher	15, 15, 10
	vncipher	15, 15, 11
	vncipher	15, 15, 12
	vncipher	15, 15, 13
	vncipherlast	15, 15, 14
	vxor	15, 15, 31
	vor	31, 23, 23 /* codespell:ignore vor */
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	addi	5, 5, -16
L_AES_CBC_decrypt_crypto_256_done:
	b	L_AES_CBC_decrypt_crypto_alldone
L_AES_CBC_decrypt_crypto_192:
	addi	9, 6, 0
	lxvd2x	32, 0, 9
	addi	9, 9, 16
	lxvd2x	33, 0, 9
	addi	9, 9, 16
	lxvd2x	34, 0, 9
	addi	9, 9, 16
	lxvd2x	35, 0, 9
	addi	9, 9, 16
	lxvd2x	36, 0, 9
	addi	9, 9, 16
	lxvd2x	37, 0, 9
	addi	9, 9, 16
	lxvd2x	38, 0, 9
	addi	9, 9, 16
	lxvd2x	39, 0, 9
	addi	9, 9, 16
	lxvd2x	40, 0, 9
	addi	9, 9, 16
	lxvd2x	41, 0, 9
	addi	9, 9, 16
	lxvd2x	42, 0, 9
	addi	9, 9, 16
	lxvd2x	43, 0, 9
	addi	9, 9, 16
	lxvd2x	44, 0, 9
	addi	9, 9, 16
	cmpdi	5, 0x80
	blt	L_AES_CBC_decrypt_crypto_192_blk4
L_AES_CBC_decrypt_crypto_192_blk8:
	lxvd2x	47, 0, 3
	vor	23, 15, 15 /* codespell:ignore vor */
	addi	3, 3, 16
	lxvd2x	48, 0, 3
	vor	24, 16, 16 /* codespell:ignore vor */
	addi	3, 3, 16
	lxvd2x	49, 0, 3
	vor	25, 17, 17 /* codespell:ignore vor */
	addi	3, 3, 16
	lxvd2x	50, 0, 3
	vor	26, 18, 18 /* codespell:ignore vor */
	addi	3, 3, 16
	lxvd2x	51, 0, 3
	vor	27, 19, 19 /* codespell:ignore vor */
	addi	3, 3, 16
	lxvd2x	52, 0, 3
	vor	28, 20, 20 /* codespell:ignore vor */
	addi	3, 3, 16
	lxvd2x	53, 0, 3
	vor	29, 21, 21 /* codespell:ignore vor */
	addi	3, 3, 16
	lxvd2x	54, 0, 3
	vor	30, 22, 22 /* codespell:ignore vor */
	addi	3, 3, 16
	vxor	15, 15, 0
	vxor	16, 16, 0
	vxor	17, 17, 0
	vxor	18, 18, 0
	vxor	19, 19, 0
	vxor	20, 20, 0
	vxor	21, 21, 0
	vxor	22, 22, 0
	vncipher	15, 15, 1
	vncipher	16, 16, 1
	vncipher	17, 17, 1
	vncipher	18, 18, 1
	vncipher	19, 19, 1
	vncipher	20, 20, 1
	vncipher	21, 21, 1
	vncipher	22, 22, 1
	vncipher	15, 15, 2
	vncipher	16, 16, 2
	vncipher	17, 17, 2
	vncipher	18, 18, 2
	vncipher	19, 19, 2
	vncipher	20, 20, 2
	vncipher	21, 21, 2
	vncipher	22, 22, 2
	vncipher	15, 15, 3
	vncipher	16, 16, 3
	vncipher	17, 17, 3
	vncipher	18, 18, 3
	vncipher	19, 19, 3
	vncipher	20, 20, 3
	vncipher	21, 21, 3
	vncipher	22, 22, 3
	vncipher	15, 15, 4
	vncipher	16, 16, 4
	vncipher	17, 17, 4
	vncipher	18, 18, 4
	vncipher	19, 19, 4
	vncipher	20, 20, 4
	vncipher	21, 21, 4
	vncipher	22, 22, 4
	vncipher	15, 15, 5
	vncipher	16, 16, 5
	vncipher	17, 17, 5
	vncipher	18, 18, 5
	vncipher	19, 19, 5
	vncipher	20, 20, 5
	vncipher	21, 21, 5
	vncipher	22, 22, 5
	vncipher	15, 15, 6
	vncipher	16, 16, 6
	vncipher	17, 17, 6
	vncipher	18, 18, 6
	vncipher	19, 19, 6
	vncipher	20, 20, 6
	vncipher	21, 21, 6
	vncipher	22, 22, 6
	vncipher	15, 15, 7
	vncipher	16, 16, 7
	vncipher	17, 17, 7
	vncipher	18, 18, 7
	vncipher	19, 19, 7
	vncipher	20, 20, 7
	vncipher	21, 21, 7
	vncipher	22, 22, 7
	vncipher	15, 15, 8
	vncipher	16, 16, 8
	vncipher	17, 17, 8
	vncipher	18, 18, 8
	vncipher	19, 19, 8
	vncipher	20, 20, 8
	vncipher	21, 21, 8
	vncipher	22, 22, 8
	vncipher	15, 15, 9
	vncipher	16, 16, 9
	vncipher	17, 17, 9
	vncipher	18, 18, 9
	vncipher	19, 19, 9
	vncipher	20, 20, 9
	vncipher	21, 21, 9
	vncipher	22, 22, 9
	vncipher	15, 15, 10
	vncipher	16, 16, 10
	vncipher	17, 17, 10
	vncipher	18, 18, 10
	vncipher	19, 19, 10
	vncipher	20, 20, 10
	vncipher	21, 21, 10
	vncipher	22, 22, 10
	vncipher	15, 15, 11
	vncipher	16, 16, 11
	vncipher	17, 17, 11
	vncipher	18, 18, 11
	vncipher	19, 19, 11
	vncipher	20, 20, 11
	vncipher	21, 21, 11
	vncipher	22, 22, 11
	vncipherlast	15, 15, 12
	vncipherlast	16, 16, 12
	vncipherlast	17, 17, 12
	vncipherlast	18, 18, 12
	vncipherlast	19, 19, 12
	vncipherlast	20, 20, 12
	vncipherlast	21, 21, 12
	vncipherlast	22, 22, 12
	vxor	15, 15, 31
	vxor	16, 16, 23
	vxor	17, 17, 24
	vxor	18, 18, 25
	vxor	19, 19, 26
	vxor	20, 20, 27
	vxor	21, 21, 28
	vxor	22, 22, 29
	vor	31, 30, 30 /* codespell:ignore vor */
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	stxvd2x	49, 0, 4
	addi	4, 4, 16
	stxvd2x	50, 0, 4
	addi	4, 4, 16
	stxvd2x	51, 0, 4
	addi	4, 4, 16
	stxvd2x	52, 0, 4
	addi	4, 4, 16
	stxvd2x	53, 0, 4
	addi	4, 4, 16
	stxvd2x	54, 0, 4
	addi	4, 4, 16
	addi	5, 5, -128
	cmpdi	5, 0x80
	bge	L_AES_CBC_decrypt_crypto_192_blk8
L_AES_CBC_decrypt_crypto_192_blk4:
	cmpdi	5, 0x40
	blt	L_AES_CBC_decrypt_crypto_192_blk2
	lxvd2x	47, 0, 3
	vor	23, 15, 15 /* codespell:ignore vor */
	addi	3, 3, 16
	lxvd2x	48, 0, 3
	vor	24, 16, 16 /* codespell:ignore vor */
	addi	3, 3, 16
	lxvd2x	49, 0, 3
	vor	25, 17, 17 /* codespell:ignore vor */
	addi	3, 3, 16
	lxvd2x	50, 0, 3
	vor	26, 18, 18 /* codespell:ignore vor */
	addi	3, 3, 16
	vxor	15, 15, 0
	vxor	16, 16, 0
	vxor	17, 17, 0
	vxor	18, 18, 0
	vncipher	15, 15, 1
	vncipher	16, 16, 1
	vncipher	17, 17, 1
	vncipher	18, 18, 1
	vncipher	15, 15, 2
	vncipher	16, 16, 2
	vncipher	17, 17, 2
	vncipher	18, 18, 2
	vncipher	15, 15, 3
	vncipher	16, 16, 3
	vncipher	17, 17, 3
	vncipher	18, 18, 3
	vncipher	15, 15, 4
	vncipher	16, 16, 4
	vncipher	17, 17, 4
	vncipher	18, 18, 4
	vncipher	15, 15, 5
	vncipher	16, 16, 5
	vncipher	17, 17, 5
	vncipher	18, 18, 5
	vncipher	15, 15, 6
	vncipher	16, 16, 6
	vncipher	17, 17, 6
	vncipher	18, 18, 6
	vncipher	15, 15, 7
	vncipher	16, 16, 7
	vncipher	17, 17, 7
	vncipher	18, 18, 7
	vncipher	15, 15, 8
	vncipher	16, 16, 8
	vncipher	17, 17, 8
	vncipher	18, 18, 8
	vncipher	15, 15, 9
	vncipher	16, 16, 9
	vncipher	17, 17, 9
	vncipher	18, 18, 9
	vncipher	15, 15, 10
	vncipher	16, 16, 10
	vncipher	17, 17, 10
	vncipher	18, 18, 10
	vncipher	15, 15, 11
	vncipher	16, 16, 11
	vncipher	17, 17, 11
	vncipher	18, 18, 11
	vncipherlast	15, 15, 12
	vncipherlast	16, 16, 12
	vncipherlast	17, 17, 12
	vncipherlast	18, 18, 12
	vxor	15, 15, 31
	vxor	16, 16, 23
	vxor	17, 17, 24
	vxor	18, 18, 25
	vor	31, 26, 26 /* codespell:ignore vor */
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	stxvd2x	49, 0, 4
	addi	4, 4, 16
	stxvd2x	50, 0, 4
	addi	4, 4, 16
	addi	5, 5, -64
L_AES_CBC_decrypt_crypto_192_blk2:
	cmpdi	5, 32
	blt	L_AES_CBC_decrypt_crypto_192_blk1
	lxvd2x	47, 0, 3
	vor	23, 15, 15 /* codespell:ignore vor */
	addi	3, 3, 16
	lxvd2x	48, 0, 3
	vor	24, 16, 16 /* codespell:ignore vor */
	addi	3, 3, 16
	vxor	15, 15, 0
	vxor	16, 16, 0
	vncipher	15, 15, 1
	vncipher	16, 16, 1
	vncipher	15, 15, 2
	vncipher	16, 16, 2
	vncipher	15, 15, 3
	vncipher	16, 16, 3
	vncipher	15, 15, 4
	vncipher	16, 16, 4
	vncipher	15, 15, 5
	vncipher	16, 16, 5
	vncipher	15, 15, 6
	vncipher	16, 16, 6
	vncipher	15, 15, 7
	vncipher	16, 16, 7
	vncipher	15, 15, 8
	vncipher	16, 16, 8
	vncipher	15, 15, 9
	vncipher	16, 16, 9
	vncipher	15, 15, 10
	vncipher	16, 16, 10
	vncipher	15, 15, 11
	vncipher	16, 16, 11
	vncipherlast	15, 15, 12
	vncipherlast	16, 16, 12
	vxor	15, 15, 31
	vxor	16, 16, 23
	vor	31, 24, 24 /* codespell:ignore vor */
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	addi	5, 5, -32
L_AES_CBC_decrypt_crypto_192_blk1:
	cmpdi	5, 16
	blt	L_AES_CBC_decrypt_crypto_192_done
	lxvd2x	47, 0, 3
	vor	23, 15, 15 /* codespell:ignore vor */
	addi	3, 3, 16
	vxor	15, 15, 0
	vncipher	15, 15, 1
	vncipher	15, 15, 2
	vncipher	15, 15, 3
	vncipher	15, 15, 4
	vncipher	15, 15, 5
	vncipher	15, 15, 6
	vncipher	15, 15, 7
	vncipher	15, 15, 8
	vncipher	15, 15, 9
	vncipher	15, 15, 10
	vncipher	15, 15, 11
	vncipherlast	15, 15, 12
	vxor	15, 15, 31
	vor	31, 23, 23 /* codespell:ignore vor */
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	addi	5, 5, -16
L_AES_CBC_decrypt_crypto_192_done:
	b	L_AES_CBC_decrypt_crypto_alldone
L_AES_CBC_decrypt_crypto_128:
	addi	9, 6, 0
	lxvd2x	32, 0, 9
	addi	9, 9, 16
	lxvd2x	33, 0, 9
	addi	9, 9, 16
	lxvd2x	34, 0, 9
	addi	9, 9, 16
	lxvd2x	35, 0, 9
	addi	9, 9, 16
	lxvd2x	36, 0, 9
	addi	9, 9, 16
	lxvd2x	37, 0, 9
	addi	9, 9, 16
	lxvd2x	38, 0, 9
	addi	9, 9, 16
	lxvd2x	39, 0, 9
	addi	9, 9, 16
	lxvd2x	40, 0, 9
	addi	9, 9, 16
	lxvd2x	41, 0, 9
	addi	9, 9, 16
	lxvd2x	42, 0, 9
	addi	9, 9, 16
	cmpdi	5, 0x80
	blt	L_AES_CBC_decrypt_crypto_128_blk4
L_AES_CBC_decrypt_crypto_128_blk8:
	lxvd2x	47, 0, 3
	vor	23, 15, 15 /* codespell:ignore vor */
	addi	3, 3, 16
	lxvd2x	48, 0, 3
	vor	24, 16, 16 /* codespell:ignore vor */
	addi	3, 3, 16
	lxvd2x	49, 0, 3
	vor	25, 17, 17 /* codespell:ignore vor */
	addi	3, 3, 16
	lxvd2x	50, 0, 3
	vor	26, 18, 18 /* codespell:ignore vor */
	addi	3, 3, 16
	lxvd2x	51, 0, 3
	vor	27, 19, 19 /* codespell:ignore vor */
	addi	3, 3, 16
	lxvd2x	52, 0, 3
	vor	28, 20, 20 /* codespell:ignore vor */
	addi	3, 3, 16
	lxvd2x	53, 0, 3
	vor	29, 21, 21 /* codespell:ignore vor */
	addi	3, 3, 16
	lxvd2x	54, 0, 3
	vor	30, 22, 22 /* codespell:ignore vor */
	addi	3, 3, 16
	vxor	15, 15, 0
	vxor	16, 16, 0
	vxor	17, 17, 0
	vxor	18, 18, 0
	vxor	19, 19, 0
	vxor	20, 20, 0
	vxor	21, 21, 0
	vxor	22, 22, 0
	vncipher	15, 15, 1
	vncipher	16, 16, 1
	vncipher	17, 17, 1
	vncipher	18, 18, 1
	vncipher	19, 19, 1
	vncipher	20, 20, 1
	vncipher	21, 21, 1
	vncipher	22, 22, 1
	vncipher	15, 15, 2
	vncipher	16, 16, 2
	vncipher	17, 17, 2
	vncipher	18, 18, 2
	vncipher	19, 19, 2
	vncipher	20, 20, 2
	vncipher	21, 21, 2
	vncipher	22, 22, 2
	vncipher	15, 15, 3
	vncipher	16, 16, 3
	vncipher	17, 17, 3
	vncipher	18, 18, 3
	vncipher	19, 19, 3
	vncipher	20, 20, 3
	vncipher	21, 21, 3
	vncipher	22, 22, 3
	vncipher	15, 15, 4
	vncipher	16, 16, 4
	vncipher	17, 17, 4
	vncipher	18, 18, 4
	vncipher	19, 19, 4
	vncipher	20, 20, 4
	vncipher	21, 21, 4
	vncipher	22, 22, 4
	vncipher	15, 15, 5
	vncipher	16, 16, 5
	vncipher	17, 17, 5
	vncipher	18, 18, 5
	vncipher	19, 19, 5
	vncipher	20, 20, 5
	vncipher	21, 21, 5
	vncipher	22, 22, 5
	vncipher	15, 15, 6
	vncipher	16, 16, 6
	vncipher	17, 17, 6
	vncipher	18, 18, 6
	vncipher	19, 19, 6
	vncipher	20, 20, 6
	vncipher	21, 21, 6
	vncipher	22, 22, 6
	vncipher	15, 15, 7
	vncipher	16, 16, 7
	vncipher	17, 17, 7
	vncipher	18, 18, 7
	vncipher	19, 19, 7
	vncipher	20, 20, 7
	vncipher	21, 21, 7
	vncipher	22, 22, 7
	vncipher	15, 15, 8
	vncipher	16, 16, 8
	vncipher	17, 17, 8
	vncipher	18, 18, 8
	vncipher	19, 19, 8
	vncipher	20, 20, 8
	vncipher	21, 21, 8
	vncipher	22, 22, 8
	vncipher	15, 15, 9
	vncipher	16, 16, 9
	vncipher	17, 17, 9
	vncipher	18, 18, 9
	vncipher	19, 19, 9
	vncipher	20, 20, 9
	vncipher	21, 21, 9
	vncipher	22, 22, 9
	vncipherlast	15, 15, 10
	vncipherlast	16, 16, 10
	vncipherlast	17, 17, 10
	vncipherlast	18, 18, 10
	vncipherlast	19, 19, 10
	vncipherlast	20, 20, 10
	vncipherlast	21, 21, 10
	vncipherlast	22, 22, 10
	vxor	15, 15, 31
	vxor	16, 16, 23
	vxor	17, 17, 24
	vxor	18, 18, 25
	vxor	19, 19, 26
	vxor	20, 20, 27
	vxor	21, 21, 28
	vxor	22, 22, 29
	vor	31, 30, 30 /* codespell:ignore vor */
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	stxvd2x	49, 0, 4
	addi	4, 4, 16
	stxvd2x	50, 0, 4
	addi	4, 4, 16
	stxvd2x	51, 0, 4
	addi	4, 4, 16
	stxvd2x	52, 0, 4
	addi	4, 4, 16
	stxvd2x	53, 0, 4
	addi	4, 4, 16
	stxvd2x	54, 0, 4
	addi	4, 4, 16
	addi	5, 5, -128
	cmpdi	5, 0x80
	bge	L_AES_CBC_decrypt_crypto_128_blk8
L_AES_CBC_decrypt_crypto_128_blk4:
	cmpdi	5, 0x40
	blt	L_AES_CBC_decrypt_crypto_128_blk2
	lxvd2x	47, 0, 3
	vor	23, 15, 15 /* codespell:ignore vor */
	addi	3, 3, 16
	lxvd2x	48, 0, 3
	vor	24, 16, 16 /* codespell:ignore vor */
	addi	3, 3, 16
	lxvd2x	49, 0, 3
	vor	25, 17, 17 /* codespell:ignore vor */
	addi	3, 3, 16
	lxvd2x	50, 0, 3
	vor	26, 18, 18 /* codespell:ignore vor */
	addi	3, 3, 16
	vxor	15, 15, 0
	vxor	16, 16, 0
	vxor	17, 17, 0
	vxor	18, 18, 0
	vncipher	15, 15, 1
	vncipher	16, 16, 1
	vncipher	17, 17, 1
	vncipher	18, 18, 1
	vncipher	15, 15, 2
	vncipher	16, 16, 2
	vncipher	17, 17, 2
	vncipher	18, 18, 2
	vncipher	15, 15, 3
	vncipher	16, 16, 3
	vncipher	17, 17, 3
	vncipher	18, 18, 3
	vncipher	15, 15, 4
	vncipher	16, 16, 4
	vncipher	17, 17, 4
	vncipher	18, 18, 4
	vncipher	15, 15, 5
	vncipher	16, 16, 5
	vncipher	17, 17, 5
	vncipher	18, 18, 5
	vncipher	15, 15, 6
	vncipher	16, 16, 6
	vncipher	17, 17, 6
	vncipher	18, 18, 6
	vncipher	15, 15, 7
	vncipher	16, 16, 7
	vncipher	17, 17, 7
	vncipher	18, 18, 7
	vncipher	15, 15, 8
	vncipher	16, 16, 8
	vncipher	17, 17, 8
	vncipher	18, 18, 8
	vncipher	15, 15, 9
	vncipher	16, 16, 9
	vncipher	17, 17, 9
	vncipher	18, 18, 9
	vncipherlast	15, 15, 10
	vncipherlast	16, 16, 10
	vncipherlast	17, 17, 10
	vncipherlast	18, 18, 10
	vxor	15, 15, 31
	vxor	16, 16, 23
	vxor	17, 17, 24
	vxor	18, 18, 25
	vor	31, 26, 26 /* codespell:ignore vor */
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	stxvd2x	49, 0, 4
	addi	4, 4, 16
	stxvd2x	50, 0, 4
	addi	4, 4, 16
	addi	5, 5, -64
L_AES_CBC_decrypt_crypto_128_blk2:
	cmpdi	5, 32
	blt	L_AES_CBC_decrypt_crypto_128_blk1
	lxvd2x	47, 0, 3
	vor	23, 15, 15 /* codespell:ignore vor */
	addi	3, 3, 16
	lxvd2x	48, 0, 3
	vor	24, 16, 16 /* codespell:ignore vor */
	addi	3, 3, 16
	vxor	15, 15, 0
	vxor	16, 16, 0
	vncipher	15, 15, 1
	vncipher	16, 16, 1
	vncipher	15, 15, 2
	vncipher	16, 16, 2
	vncipher	15, 15, 3
	vncipher	16, 16, 3
	vncipher	15, 15, 4
	vncipher	16, 16, 4
	vncipher	15, 15, 5
	vncipher	16, 16, 5
	vncipher	15, 15, 6
	vncipher	16, 16, 6
	vncipher	15, 15, 7
	vncipher	16, 16, 7
	vncipher	15, 15, 8
	vncipher	16, 16, 8
	vncipher	15, 15, 9
	vncipher	16, 16, 9
	vncipherlast	15, 15, 10
	vncipherlast	16, 16, 10
	vxor	15, 15, 31
	vxor	16, 16, 23
	vor	31, 24, 24 /* codespell:ignore vor */
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	addi	5, 5, -32
L_AES_CBC_decrypt_crypto_128_blk1:
	cmpdi	5, 16
	blt	L_AES_CBC_decrypt_crypto_128_done
	lxvd2x	47, 0, 3
	vor	23, 15, 15 /* codespell:ignore vor */
	addi	3, 3, 16
	vxor	15, 15, 0
	vncipher	15, 15, 1
	vncipher	15, 15, 2
	vncipher	15, 15, 3
	vncipher	15, 15, 4
	vncipher	15, 15, 5
	vncipher	15, 15, 6
	vncipher	15, 15, 7
	vncipher	15, 15, 8
	vncipher	15, 15, 9
	vncipherlast	15, 15, 10
	vxor	15, 15, 31
	vor	31, 23, 23 /* codespell:ignore vor */
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	addi	5, 5, -16
L_AES_CBC_decrypt_crypto_128_done:
L_AES_CBC_decrypt_crypto_alldone:
	stxvd2x	63, 0, 8
	ld	0, 0(1)
	mtlr	0
	addi	1, 1, 8
	li	0, 0
	lxvd2x	52, 1, 0
	li	0, 16
	lxvd2x	53, 1, 0
	li	0, 32
	lxvd2x	54, 1, 0
	li	0, 48
	lxvd2x	55, 1, 0
	li	0, 0x40
	lxvd2x	56, 1, 0
	li	0, 0x50
	lxvd2x	57, 1, 0
	li	0, 0x60
	lxvd2x	58, 1, 0
	li	0, 0x70
	lxvd2x	59, 1, 0
	li	0, 0x80
	lxvd2x	60, 1, 0
	li	0, 0x90
	lxvd2x	61, 1, 0
	li	0, 0xa0
	lxvd2x	62, 1, 0
	li	0, 0xb0
	lxvd2x	63, 1, 0
	addi	1, 1, 0xc0
	blr
#ifndef __APPLE__
	.size	AES_CBC_decrypt_crypto,.-AES_CBC_decrypt_crypto
#endif /* __APPLE__ */
	.machine	"pop"
#endif /* HAVE_AES_DECRYPT */
#endif /* HAVE_AES_CBC */
#ifdef WOLFSSL_AES_COUNTER
	.machine	"push"
	.machine	"power8"
#ifndef __APPLE__
.text
.globl	AES_CTR_encrypt_crypto
.type	AES_CTR_encrypt_crypto,@function
.align	16
AES_CTR_encrypt_crypto:
#if defined(_CALL_ELF) && _CALL_ELF == 2
0:	addis	2, 12, .TOC.-0b@ha
	addi	2, 2, .TOC.-0b@l
	.localentry	AES_CTR_encrypt_crypto, .-AES_CTR_encrypt_crypto
#endif
#else
.section	__TEXT,__text
.globl	_AES_CTR_encrypt_crypto
.p2align	4
_AES_CTR_encrypt_crypto:
#endif /* __APPLE__ */
	subi	1, 1, 0xc0
	li	0, 0
	stxvd2x	52, 1, 0
	li	0, 16
	stxvd2x	53, 1, 0
	li	0, 32
	stxvd2x	54, 1, 0
	li	0, 48
	stxvd2x	55, 1, 0
	li	0, 0x40
	stxvd2x	56, 1, 0
	li	0, 0x50
	stxvd2x	57, 1, 0
	li	0, 0x60
	stxvd2x	58, 1, 0
	li	0, 0x70
	stxvd2x	59, 1, 0
	li	0, 0x80
	stxvd2x	60, 1, 0
	li	0, 0x90
	stxvd2x	61, 1, 0
	li	0, 0xa0
	stxvd2x	62, 1, 0
	li	0, 0xb0
	stxvd2x	63, 1, 0
	stdu	1, -8(1)
	mflr	0
	std	0, 0(1)
	addis	9, 2, L_AES_PPC64_crypto_one@toc@ha
	addi	9, 9, L_AES_PPC64_crypto_one@toc@l
	lxvd2x	63, 0, 9
	cmplwi	7, 10
	beq	L_AES_CTR_encrypt_crypto_128
	cmplwi	7, 12
	beq	L_AES_CTR_encrypt_crypto_192
	addi	10, 6, 0
	lxvd2x	32, 0, 10
	addi	10, 10, 16
	lxvd2x	33, 0, 10
	addi	10, 10, 16
	lxvd2x	34, 0, 10
	addi	10, 10, 16
	lxvd2x	35, 0, 10
	addi	10, 10, 16
	lxvd2x	36, 0, 10
	addi	10, 10, 16
	lxvd2x	37, 0, 10
	addi	10, 10, 16
	lxvd2x	38, 0, 10
	addi	10, 10, 16
	lxvd2x	39, 0, 10
	addi	10, 10, 16
	lxvd2x	40, 0, 10
	addi	10, 10, 16
	lxvd2x	41, 0, 10
	addi	10, 10, 16
	lxvd2x	42, 0, 10
	addi	10, 10, 16
	lxvd2x	43, 0, 10
	addi	10, 10, 16
	lxvd2x	44, 0, 10
	addi	10, 10, 16
	lxvd2x	45, 0, 10
	addi	10, 10, 16
	lxvd2x	46, 0, 10
	addi	10, 10, 16
	cmpdi	5, 0x80
	blt	L_AES_CTR_encrypt_crypto_256_blk4
L_AES_CTR_encrypt_crypto_256_blk8:
	lxvd2x	55, 0, 8
	vor	15, 23, 23 /* codespell:ignore vor */
	vadduqm	16, 15, 31
	vadduqm	17, 16, 31
	vadduqm	18, 17, 31
	vadduqm	19, 18, 31
	vadduqm	20, 19, 31
	vadduqm	21, 20, 31
	vadduqm	22, 21, 31
	vadduqm	23, 22, 31
	stxvd2x	55, 0, 8
	lxvd2x	55, 0, 3
	addi	3, 3, 16
	lxvd2x	56, 0, 3
	addi	3, 3, 16
	lxvd2x	57, 0, 3
	addi	3, 3, 16
	lxvd2x	58, 0, 3
	addi	3, 3, 16
	lxvd2x	59, 0, 3
	addi	3, 3, 16
	lxvd2x	60, 0, 3
	addi	3, 3, 16
	lxvd2x	61, 0, 3
	addi	3, 3, 16
	lxvd2x	62, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 0
	vxor	16, 16, 0
	vxor	17, 17, 0
	vxor	18, 18, 0
	vxor	19, 19, 0
	vxor	20, 20, 0
	vxor	21, 21, 0
	vxor	22, 22, 0
	vcipher	15, 15, 1
	vcipher	16, 16, 1
	vcipher	17, 17, 1
	vcipher	18, 18, 1
	vcipher	19, 19, 1
	vcipher	20, 20, 1
	vcipher	21, 21, 1
	vcipher	22, 22, 1
	vcipher	15, 15, 2
	vcipher	16, 16, 2
	vcipher	17, 17, 2
	vcipher	18, 18, 2
	vcipher	19, 19, 2
	vcipher	20, 20, 2
	vcipher	21, 21, 2
	vcipher	22, 22, 2
	vcipher	15, 15, 3
	vcipher	16, 16, 3
	vcipher	17, 17, 3
	vcipher	18, 18, 3
	vcipher	19, 19, 3
	vcipher	20, 20, 3
	vcipher	21, 21, 3
	vcipher	22, 22, 3
	vcipher	15, 15, 4
	vcipher	16, 16, 4
	vcipher	17, 17, 4
	vcipher	18, 18, 4
	vcipher	19, 19, 4
	vcipher	20, 20, 4
	vcipher	21, 21, 4
	vcipher	22, 22, 4
	vcipher	15, 15, 5
	vcipher	16, 16, 5
	vcipher	17, 17, 5
	vcipher	18, 18, 5
	vcipher	19, 19, 5
	vcipher	20, 20, 5
	vcipher	21, 21, 5
	vcipher	22, 22, 5
	vcipher	15, 15, 6
	vcipher	16, 16, 6
	vcipher	17, 17, 6
	vcipher	18, 18, 6
	vcipher	19, 19, 6
	vcipher	20, 20, 6
	vcipher	21, 21, 6
	vcipher	22, 22, 6
	vcipher	15, 15, 7
	vcipher	16, 16, 7
	vcipher	17, 17, 7
	vcipher	18, 18, 7
	vcipher	19, 19, 7
	vcipher	20, 20, 7
	vcipher	21, 21, 7
	vcipher	22, 22, 7
	vcipher	15, 15, 8
	vcipher	16, 16, 8
	vcipher	17, 17, 8
	vcipher	18, 18, 8
	vcipher	19, 19, 8
	vcipher	20, 20, 8
	vcipher	21, 21, 8
	vcipher	22, 22, 8
	vcipher	15, 15, 9
	vcipher	16, 16, 9
	vcipher	17, 17, 9
	vcipher	18, 18, 9
	vcipher	19, 19, 9
	vcipher	20, 20, 9
	vcipher	21, 21, 9
	vcipher	22, 22, 9
	vcipher	15, 15, 10
	vcipher	16, 16, 10
	vcipher	17, 17, 10
	vcipher	18, 18, 10
	vcipher	19, 19, 10
	vcipher	20, 20, 10
	vcipher	21, 21, 10
	vcipher	22, 22, 10
	vcipher	15, 15, 11
	vcipher	16, 16, 11
	vcipher	17, 17, 11
	vcipher	18, 18, 11
	vcipher	19, 19, 11
	vcipher	20, 20, 11
	vcipher	21, 21, 11
	vcipher	22, 22, 11
	vcipher	15, 15, 12
	vcipher	16, 16, 12
	vcipher	17, 17, 12
	vcipher	18, 18, 12
	vcipher	19, 19, 12
	vcipher	20, 20, 12
	vcipher	21, 21, 12
	vcipher	22, 22, 12
	vcipher	15, 15, 13
	vcipher	16, 16, 13
	vcipher	17, 17, 13
	vcipher	18, 18, 13
	vcipher	19, 19, 13
	vcipher	20, 20, 13
	vcipher	21, 21, 13
	vcipher	22, 22, 13
	vcipherlast	15, 15, 14
	vcipherlast	16, 16, 14
	vcipherlast	17, 17, 14
	vcipherlast	18, 18, 14
	vcipherlast	19, 19, 14
	vcipherlast	20, 20, 14
	vcipherlast	21, 21, 14
	vcipherlast	22, 22, 14
	vxor	15, 15, 23
	vxor	16, 16, 24
	vxor	17, 17, 25
	vxor	18, 18, 26
	vxor	19, 19, 27
	vxor	20, 20, 28
	vxor	21, 21, 29
	vxor	22, 22, 30
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	stxvd2x	49, 0, 4
	addi	4, 4, 16
	stxvd2x	50, 0, 4
	addi	4, 4, 16
	stxvd2x	51, 0, 4
	addi	4, 4, 16
	stxvd2x	52, 0, 4
	addi	4, 4, 16
	stxvd2x	53, 0, 4
	addi	4, 4, 16
	stxvd2x	54, 0, 4
	addi	4, 4, 16
	addi	5, 5, -128
	cmpdi	5, 0x80
	bge	L_AES_CTR_encrypt_crypto_256_blk8
L_AES_CTR_encrypt_crypto_256_blk4:
	cmpdi	5, 0x40
	blt	L_AES_CTR_encrypt_crypto_256_blk2
	lxvd2x	55, 0, 8
	vor	15, 23, 23 /* codespell:ignore vor */
	vadduqm	16, 15, 31
	vadduqm	17, 16, 31
	vadduqm	18, 17, 31
	vadduqm	23, 18, 31
	stxvd2x	55, 0, 8
	lxvd2x	55, 0, 3
	addi	3, 3, 16
	lxvd2x	56, 0, 3
	addi	3, 3, 16
	lxvd2x	57, 0, 3
	addi	3, 3, 16
	lxvd2x	58, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 0
	vxor	16, 16, 0
	vxor	17, 17, 0
	vxor	18, 18, 0
	vcipher	15, 15, 1
	vcipher	16, 16, 1
	vcipher	17, 17, 1
	vcipher	18, 18, 1
	vcipher	15, 15, 2
	vcipher	16, 16, 2
	vcipher	17, 17, 2
	vcipher	18, 18, 2
	vcipher	15, 15, 3
	vcipher	16, 16, 3
	vcipher	17, 17, 3
	vcipher	18, 18, 3
	vcipher	15, 15, 4
	vcipher	16, 16, 4
	vcipher	17, 17, 4
	vcipher	18, 18, 4
	vcipher	15, 15, 5
	vcipher	16, 16, 5
	vcipher	17, 17, 5
	vcipher	18, 18, 5
	vcipher	15, 15, 6
	vcipher	16, 16, 6
	vcipher	17, 17, 6
	vcipher	18, 18, 6
	vcipher	15, 15, 7
	vcipher	16, 16, 7
	vcipher	17, 17, 7
	vcipher	18, 18, 7
	vcipher	15, 15, 8
	vcipher	16, 16, 8
	vcipher	17, 17, 8
	vcipher	18, 18, 8
	vcipher	15, 15, 9
	vcipher	16, 16, 9
	vcipher	17, 17, 9
	vcipher	18, 18, 9
	vcipher	15, 15, 10
	vcipher	16, 16, 10
	vcipher	17, 17, 10
	vcipher	18, 18, 10
	vcipher	15, 15, 11
	vcipher	16, 16, 11
	vcipher	17, 17, 11
	vcipher	18, 18, 11
	vcipher	15, 15, 12
	vcipher	16, 16, 12
	vcipher	17, 17, 12
	vcipher	18, 18, 12
	vcipher	15, 15, 13
	vcipher	16, 16, 13
	vcipher	17, 17, 13
	vcipher	18, 18, 13
	vcipherlast	15, 15, 14
	vcipherlast	16, 16, 14
	vcipherlast	17, 17, 14
	vcipherlast	18, 18, 14
	vxor	15, 15, 23
	vxor	16, 16, 24
	vxor	17, 17, 25
	vxor	18, 18, 26
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	stxvd2x	49, 0, 4
	addi	4, 4, 16
	stxvd2x	50, 0, 4
	addi	4, 4, 16
	addi	5, 5, -64
L_AES_CTR_encrypt_crypto_256_blk2:
	cmpdi	5, 32
	blt	L_AES_CTR_encrypt_crypto_256_blk1
	lxvd2x	55, 0, 8
	vor	15, 23, 23 /* codespell:ignore vor */
	vadduqm	16, 15, 31
	vadduqm	23, 16, 31
	stxvd2x	55, 0, 8
	lxvd2x	55, 0, 3
	addi	3, 3, 16
	lxvd2x	56, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 0
	vxor	16, 16, 0
	vcipher	15, 15, 1
	vcipher	16, 16, 1
	vcipher	15, 15, 2
	vcipher	16, 16, 2
	vcipher	15, 15, 3
	vcipher	16, 16, 3
	vcipher	15, 15, 4
	vcipher	16, 16, 4
	vcipher	15, 15, 5
	vcipher	16, 16, 5
	vcipher	15, 15, 6
	vcipher	16, 16, 6
	vcipher	15, 15, 7
	vcipher	16, 16, 7
	vcipher	15, 15, 8
	vcipher	16, 16, 8
	vcipher	15, 15, 9
	vcipher	16, 16, 9
	vcipher	15, 15, 10
	vcipher	16, 16, 10
	vcipher	15, 15, 11
	vcipher	16, 16, 11
	vcipher	15, 15, 12
	vcipher	16, 16, 12
	vcipher	15, 15, 13
	vcipher	16, 16, 13
	vcipherlast	15, 15, 14
	vcipherlast	16, 16, 14
	vxor	15, 15, 23
	vxor	16, 16, 24
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	addi	5, 5, -32
L_AES_CTR_encrypt_crypto_256_blk1:
	cmpdi	5, 16
	blt	L_AES_CTR_encrypt_crypto_256_done
	lxvd2x	55, 0, 8
	vor	15, 23, 23 /* codespell:ignore vor */
	vadduqm	23, 15, 31
	stxvd2x	55, 0, 8
	lxvd2x	55, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 0
	vcipher	15, 15, 1
	vcipher	15, 15, 2
	vcipher	15, 15, 3
	vcipher	15, 15, 4
	vcipher	15, 15, 5
	vcipher	15, 15, 6
	vcipher	15, 15, 7
	vcipher	15, 15, 8
	vcipher	15, 15, 9
	vcipher	15, 15, 10
	vcipher	15, 15, 11
	vcipher	15, 15, 12
	vcipher	15, 15, 13
	vcipherlast	15, 15, 14
	vxor	15, 15, 23
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	addi	5, 5, -16
L_AES_CTR_encrypt_crypto_256_done:
	b	L_AES_CTR_encrypt_crypto_alldone
L_AES_CTR_encrypt_crypto_192:
	addi	10, 6, 0
	lxvd2x	32, 0, 10
	addi	10, 10, 16
	lxvd2x	33, 0, 10
	addi	10, 10, 16
	lxvd2x	34, 0, 10
	addi	10, 10, 16
	lxvd2x	35, 0, 10
	addi	10, 10, 16
	lxvd2x	36, 0, 10
	addi	10, 10, 16
	lxvd2x	37, 0, 10
	addi	10, 10, 16
	lxvd2x	38, 0, 10
	addi	10, 10, 16
	lxvd2x	39, 0, 10
	addi	10, 10, 16
	lxvd2x	40, 0, 10
	addi	10, 10, 16
	lxvd2x	41, 0, 10
	addi	10, 10, 16
	lxvd2x	42, 0, 10
	addi	10, 10, 16
	lxvd2x	43, 0, 10
	addi	10, 10, 16
	lxvd2x	44, 0, 10
	addi	10, 10, 16
	cmpdi	5, 0x80
	blt	L_AES_CTR_encrypt_crypto_192_blk4
L_AES_CTR_encrypt_crypto_192_blk8:
	lxvd2x	55, 0, 8
	vor	15, 23, 23 /* codespell:ignore vor */
	vadduqm	16, 15, 31
	vadduqm	17, 16, 31
	vadduqm	18, 17, 31
	vadduqm	19, 18, 31
	vadduqm	20, 19, 31
	vadduqm	21, 20, 31
	vadduqm	22, 21, 31
	vadduqm	23, 22, 31
	stxvd2x	55, 0, 8
	lxvd2x	55, 0, 3
	addi	3, 3, 16
	lxvd2x	56, 0, 3
	addi	3, 3, 16
	lxvd2x	57, 0, 3
	addi	3, 3, 16
	lxvd2x	58, 0, 3
	addi	3, 3, 16
	lxvd2x	59, 0, 3
	addi	3, 3, 16
	lxvd2x	60, 0, 3
	addi	3, 3, 16
	lxvd2x	61, 0, 3
	addi	3, 3, 16
	lxvd2x	62, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 0
	vxor	16, 16, 0
	vxor	17, 17, 0
	vxor	18, 18, 0
	vxor	19, 19, 0
	vxor	20, 20, 0
	vxor	21, 21, 0
	vxor	22, 22, 0
	vcipher	15, 15, 1
	vcipher	16, 16, 1
	vcipher	17, 17, 1
	vcipher	18, 18, 1
	vcipher	19, 19, 1
	vcipher	20, 20, 1
	vcipher	21, 21, 1
	vcipher	22, 22, 1
	vcipher	15, 15, 2
	vcipher	16, 16, 2
	vcipher	17, 17, 2
	vcipher	18, 18, 2
	vcipher	19, 19, 2
	vcipher	20, 20, 2
	vcipher	21, 21, 2
	vcipher	22, 22, 2
	vcipher	15, 15, 3
	vcipher	16, 16, 3
	vcipher	17, 17, 3
	vcipher	18, 18, 3
	vcipher	19, 19, 3
	vcipher	20, 20, 3
	vcipher	21, 21, 3
	vcipher	22, 22, 3
	vcipher	15, 15, 4
	vcipher	16, 16, 4
	vcipher	17, 17, 4
	vcipher	18, 18, 4
	vcipher	19, 19, 4
	vcipher	20, 20, 4
	vcipher	21, 21, 4
	vcipher	22, 22, 4
	vcipher	15, 15, 5
	vcipher	16, 16, 5
	vcipher	17, 17, 5
	vcipher	18, 18, 5
	vcipher	19, 19, 5
	vcipher	20, 20, 5
	vcipher	21, 21, 5
	vcipher	22, 22, 5
	vcipher	15, 15, 6
	vcipher	16, 16, 6
	vcipher	17, 17, 6
	vcipher	18, 18, 6
	vcipher	19, 19, 6
	vcipher	20, 20, 6
	vcipher	21, 21, 6
	vcipher	22, 22, 6
	vcipher	15, 15, 7
	vcipher	16, 16, 7
	vcipher	17, 17, 7
	vcipher	18, 18, 7
	vcipher	19, 19, 7
	vcipher	20, 20, 7
	vcipher	21, 21, 7
	vcipher	22, 22, 7
	vcipher	15, 15, 8
	vcipher	16, 16, 8
	vcipher	17, 17, 8
	vcipher	18, 18, 8
	vcipher	19, 19, 8
	vcipher	20, 20, 8
	vcipher	21, 21, 8
	vcipher	22, 22, 8
	vcipher	15, 15, 9
	vcipher	16, 16, 9
	vcipher	17, 17, 9
	vcipher	18, 18, 9
	vcipher	19, 19, 9
	vcipher	20, 20, 9
	vcipher	21, 21, 9
	vcipher	22, 22, 9
	vcipher	15, 15, 10
	vcipher	16, 16, 10
	vcipher	17, 17, 10
	vcipher	18, 18, 10
	vcipher	19, 19, 10
	vcipher	20, 20, 10
	vcipher	21, 21, 10
	vcipher	22, 22, 10
	vcipher	15, 15, 11
	vcipher	16, 16, 11
	vcipher	17, 17, 11
	vcipher	18, 18, 11
	vcipher	19, 19, 11
	vcipher	20, 20, 11
	vcipher	21, 21, 11
	vcipher	22, 22, 11
	vcipherlast	15, 15, 12
	vcipherlast	16, 16, 12
	vcipherlast	17, 17, 12
	vcipherlast	18, 18, 12
	vcipherlast	19, 19, 12
	vcipherlast	20, 20, 12
	vcipherlast	21, 21, 12
	vcipherlast	22, 22, 12
	vxor	15, 15, 23
	vxor	16, 16, 24
	vxor	17, 17, 25
	vxor	18, 18, 26
	vxor	19, 19, 27
	vxor	20, 20, 28
	vxor	21, 21, 29
	vxor	22, 22, 30
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	stxvd2x	49, 0, 4
	addi	4, 4, 16
	stxvd2x	50, 0, 4
	addi	4, 4, 16
	stxvd2x	51, 0, 4
	addi	4, 4, 16
	stxvd2x	52, 0, 4
	addi	4, 4, 16
	stxvd2x	53, 0, 4
	addi	4, 4, 16
	stxvd2x	54, 0, 4
	addi	4, 4, 16
	addi	5, 5, -128
	cmpdi	5, 0x80
	bge	L_AES_CTR_encrypt_crypto_192_blk8
L_AES_CTR_encrypt_crypto_192_blk4:
	cmpdi	5, 0x40
	blt	L_AES_CTR_encrypt_crypto_192_blk2
	lxvd2x	55, 0, 8
	vor	15, 23, 23 /* codespell:ignore vor */
	vadduqm	16, 15, 31
	vadduqm	17, 16, 31
	vadduqm	18, 17, 31
	vadduqm	23, 18, 31
	stxvd2x	55, 0, 8
	lxvd2x	55, 0, 3
	addi	3, 3, 16
	lxvd2x	56, 0, 3
	addi	3, 3, 16
	lxvd2x	57, 0, 3
	addi	3, 3, 16
	lxvd2x	58, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 0
	vxor	16, 16, 0
	vxor	17, 17, 0
	vxor	18, 18, 0
	vcipher	15, 15, 1
	vcipher	16, 16, 1
	vcipher	17, 17, 1
	vcipher	18, 18, 1
	vcipher	15, 15, 2
	vcipher	16, 16, 2
	vcipher	17, 17, 2
	vcipher	18, 18, 2
	vcipher	15, 15, 3
	vcipher	16, 16, 3
	vcipher	17, 17, 3
	vcipher	18, 18, 3
	vcipher	15, 15, 4
	vcipher	16, 16, 4
	vcipher	17, 17, 4
	vcipher	18, 18, 4
	vcipher	15, 15, 5
	vcipher	16, 16, 5
	vcipher	17, 17, 5
	vcipher	18, 18, 5
	vcipher	15, 15, 6
	vcipher	16, 16, 6
	vcipher	17, 17, 6
	vcipher	18, 18, 6
	vcipher	15, 15, 7
	vcipher	16, 16, 7
	vcipher	17, 17, 7
	vcipher	18, 18, 7
	vcipher	15, 15, 8
	vcipher	16, 16, 8
	vcipher	17, 17, 8
	vcipher	18, 18, 8
	vcipher	15, 15, 9
	vcipher	16, 16, 9
	vcipher	17, 17, 9
	vcipher	18, 18, 9
	vcipher	15, 15, 10
	vcipher	16, 16, 10
	vcipher	17, 17, 10
	vcipher	18, 18, 10
	vcipher	15, 15, 11
	vcipher	16, 16, 11
	vcipher	17, 17, 11
	vcipher	18, 18, 11
	vcipherlast	15, 15, 12
	vcipherlast	16, 16, 12
	vcipherlast	17, 17, 12
	vcipherlast	18, 18, 12
	vxor	15, 15, 23
	vxor	16, 16, 24
	vxor	17, 17, 25
	vxor	18, 18, 26
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	stxvd2x	49, 0, 4
	addi	4, 4, 16
	stxvd2x	50, 0, 4
	addi	4, 4, 16
	addi	5, 5, -64
L_AES_CTR_encrypt_crypto_192_blk2:
	cmpdi	5, 32
	blt	L_AES_CTR_encrypt_crypto_192_blk1
	lxvd2x	55, 0, 8
	vor	15, 23, 23 /* codespell:ignore vor */
	vadduqm	16, 15, 31
	vadduqm	23, 16, 31
	stxvd2x	55, 0, 8
	lxvd2x	55, 0, 3
	addi	3, 3, 16
	lxvd2x	56, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 0
	vxor	16, 16, 0
	vcipher	15, 15, 1
	vcipher	16, 16, 1
	vcipher	15, 15, 2
	vcipher	16, 16, 2
	vcipher	15, 15, 3
	vcipher	16, 16, 3
	vcipher	15, 15, 4
	vcipher	16, 16, 4
	vcipher	15, 15, 5
	vcipher	16, 16, 5
	vcipher	15, 15, 6
	vcipher	16, 16, 6
	vcipher	15, 15, 7
	vcipher	16, 16, 7
	vcipher	15, 15, 8
	vcipher	16, 16, 8
	vcipher	15, 15, 9
	vcipher	16, 16, 9
	vcipher	15, 15, 10
	vcipher	16, 16, 10
	vcipher	15, 15, 11
	vcipher	16, 16, 11
	vcipherlast	15, 15, 12
	vcipherlast	16, 16, 12
	vxor	15, 15, 23
	vxor	16, 16, 24
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	addi	5, 5, -32
L_AES_CTR_encrypt_crypto_192_blk1:
	cmpdi	5, 16
	blt	L_AES_CTR_encrypt_crypto_192_done
	lxvd2x	55, 0, 8
	vor	15, 23, 23 /* codespell:ignore vor */
	vadduqm	23, 15, 31
	stxvd2x	55, 0, 8
	lxvd2x	55, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 0
	vcipher	15, 15, 1
	vcipher	15, 15, 2
	vcipher	15, 15, 3
	vcipher	15, 15, 4
	vcipher	15, 15, 5
	vcipher	15, 15, 6
	vcipher	15, 15, 7
	vcipher	15, 15, 8
	vcipher	15, 15, 9
	vcipher	15, 15, 10
	vcipher	15, 15, 11
	vcipherlast	15, 15, 12
	vxor	15, 15, 23
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	addi	5, 5, -16
L_AES_CTR_encrypt_crypto_192_done:
	b	L_AES_CTR_encrypt_crypto_alldone
L_AES_CTR_encrypt_crypto_128:
	addi	10, 6, 0
	lxvd2x	32, 0, 10
	addi	10, 10, 16
	lxvd2x	33, 0, 10
	addi	10, 10, 16
	lxvd2x	34, 0, 10
	addi	10, 10, 16
	lxvd2x	35, 0, 10
	addi	10, 10, 16
	lxvd2x	36, 0, 10
	addi	10, 10, 16
	lxvd2x	37, 0, 10
	addi	10, 10, 16
	lxvd2x	38, 0, 10
	addi	10, 10, 16
	lxvd2x	39, 0, 10
	addi	10, 10, 16
	lxvd2x	40, 0, 10
	addi	10, 10, 16
	lxvd2x	41, 0, 10
	addi	10, 10, 16
	lxvd2x	42, 0, 10
	addi	10, 10, 16
	cmpdi	5, 0x80
	blt	L_AES_CTR_encrypt_crypto_128_blk4
L_AES_CTR_encrypt_crypto_128_blk8:
	lxvd2x	55, 0, 8
	vor	15, 23, 23 /* codespell:ignore vor */
	vadduqm	16, 15, 31
	vadduqm	17, 16, 31
	vadduqm	18, 17, 31
	vadduqm	19, 18, 31
	vadduqm	20, 19, 31
	vadduqm	21, 20, 31
	vadduqm	22, 21, 31
	vadduqm	23, 22, 31
	stxvd2x	55, 0, 8
	lxvd2x	55, 0, 3
	addi	3, 3, 16
	lxvd2x	56, 0, 3
	addi	3, 3, 16
	lxvd2x	57, 0, 3
	addi	3, 3, 16
	lxvd2x	58, 0, 3
	addi	3, 3, 16
	lxvd2x	59, 0, 3
	addi	3, 3, 16
	lxvd2x	60, 0, 3
	addi	3, 3, 16
	lxvd2x	61, 0, 3
	addi	3, 3, 16
	lxvd2x	62, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 0
	vxor	16, 16, 0
	vxor	17, 17, 0
	vxor	18, 18, 0
	vxor	19, 19, 0
	vxor	20, 20, 0
	vxor	21, 21, 0
	vxor	22, 22, 0
	vcipher	15, 15, 1
	vcipher	16, 16, 1
	vcipher	17, 17, 1
	vcipher	18, 18, 1
	vcipher	19, 19, 1
	vcipher	20, 20, 1
	vcipher	21, 21, 1
	vcipher	22, 22, 1
	vcipher	15, 15, 2
	vcipher	16, 16, 2
	vcipher	17, 17, 2
	vcipher	18, 18, 2
	vcipher	19, 19, 2
	vcipher	20, 20, 2
	vcipher	21, 21, 2
	vcipher	22, 22, 2
	vcipher	15, 15, 3
	vcipher	16, 16, 3
	vcipher	17, 17, 3
	vcipher	18, 18, 3
	vcipher	19, 19, 3
	vcipher	20, 20, 3
	vcipher	21, 21, 3
	vcipher	22, 22, 3
	vcipher	15, 15, 4
	vcipher	16, 16, 4
	vcipher	17, 17, 4
	vcipher	18, 18, 4
	vcipher	19, 19, 4
	vcipher	20, 20, 4
	vcipher	21, 21, 4
	vcipher	22, 22, 4
	vcipher	15, 15, 5
	vcipher	16, 16, 5
	vcipher	17, 17, 5
	vcipher	18, 18, 5
	vcipher	19, 19, 5
	vcipher	20, 20, 5
	vcipher	21, 21, 5
	vcipher	22, 22, 5
	vcipher	15, 15, 6
	vcipher	16, 16, 6
	vcipher	17, 17, 6
	vcipher	18, 18, 6
	vcipher	19, 19, 6
	vcipher	20, 20, 6
	vcipher	21, 21, 6
	vcipher	22, 22, 6
	vcipher	15, 15, 7
	vcipher	16, 16, 7
	vcipher	17, 17, 7
	vcipher	18, 18, 7
	vcipher	19, 19, 7
	vcipher	20, 20, 7
	vcipher	21, 21, 7
	vcipher	22, 22, 7
	vcipher	15, 15, 8
	vcipher	16, 16, 8
	vcipher	17, 17, 8
	vcipher	18, 18, 8
	vcipher	19, 19, 8
	vcipher	20, 20, 8
	vcipher	21, 21, 8
	vcipher	22, 22, 8
	vcipher	15, 15, 9
	vcipher	16, 16, 9
	vcipher	17, 17, 9
	vcipher	18, 18, 9
	vcipher	19, 19, 9
	vcipher	20, 20, 9
	vcipher	21, 21, 9
	vcipher	22, 22, 9
	vcipherlast	15, 15, 10
	vcipherlast	16, 16, 10
	vcipherlast	17, 17, 10
	vcipherlast	18, 18, 10
	vcipherlast	19, 19, 10
	vcipherlast	20, 20, 10
	vcipherlast	21, 21, 10
	vcipherlast	22, 22, 10
	vxor	15, 15, 23
	vxor	16, 16, 24
	vxor	17, 17, 25
	vxor	18, 18, 26
	vxor	19, 19, 27
	vxor	20, 20, 28
	vxor	21, 21, 29
	vxor	22, 22, 30
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	stxvd2x	49, 0, 4
	addi	4, 4, 16
	stxvd2x	50, 0, 4
	addi	4, 4, 16
	stxvd2x	51, 0, 4
	addi	4, 4, 16
	stxvd2x	52, 0, 4
	addi	4, 4, 16
	stxvd2x	53, 0, 4
	addi	4, 4, 16
	stxvd2x	54, 0, 4
	addi	4, 4, 16
	addi	5, 5, -128
	cmpdi	5, 0x80
	bge	L_AES_CTR_encrypt_crypto_128_blk8
L_AES_CTR_encrypt_crypto_128_blk4:
	cmpdi	5, 0x40
	blt	L_AES_CTR_encrypt_crypto_128_blk2
	lxvd2x	55, 0, 8
	vor	15, 23, 23 /* codespell:ignore vor */
	vadduqm	16, 15, 31
	vadduqm	17, 16, 31
	vadduqm	18, 17, 31
	vadduqm	23, 18, 31
	stxvd2x	55, 0, 8
	lxvd2x	55, 0, 3
	addi	3, 3, 16
	lxvd2x	56, 0, 3
	addi	3, 3, 16
	lxvd2x	57, 0, 3
	addi	3, 3, 16
	lxvd2x	58, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 0
	vxor	16, 16, 0
	vxor	17, 17, 0
	vxor	18, 18, 0
	vcipher	15, 15, 1
	vcipher	16, 16, 1
	vcipher	17, 17, 1
	vcipher	18, 18, 1
	vcipher	15, 15, 2
	vcipher	16, 16, 2
	vcipher	17, 17, 2
	vcipher	18, 18, 2
	vcipher	15, 15, 3
	vcipher	16, 16, 3
	vcipher	17, 17, 3
	vcipher	18, 18, 3
	vcipher	15, 15, 4
	vcipher	16, 16, 4
	vcipher	17, 17, 4
	vcipher	18, 18, 4
	vcipher	15, 15, 5
	vcipher	16, 16, 5
	vcipher	17, 17, 5
	vcipher	18, 18, 5
	vcipher	15, 15, 6
	vcipher	16, 16, 6
	vcipher	17, 17, 6
	vcipher	18, 18, 6
	vcipher	15, 15, 7
	vcipher	16, 16, 7
	vcipher	17, 17, 7
	vcipher	18, 18, 7
	vcipher	15, 15, 8
	vcipher	16, 16, 8
	vcipher	17, 17, 8
	vcipher	18, 18, 8
	vcipher	15, 15, 9
	vcipher	16, 16, 9
	vcipher	17, 17, 9
	vcipher	18, 18, 9
	vcipherlast	15, 15, 10
	vcipherlast	16, 16, 10
	vcipherlast	17, 17, 10
	vcipherlast	18, 18, 10
	vxor	15, 15, 23
	vxor	16, 16, 24
	vxor	17, 17, 25
	vxor	18, 18, 26
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	stxvd2x	49, 0, 4
	addi	4, 4, 16
	stxvd2x	50, 0, 4
	addi	4, 4, 16
	addi	5, 5, -64
L_AES_CTR_encrypt_crypto_128_blk2:
	cmpdi	5, 32
	blt	L_AES_CTR_encrypt_crypto_128_blk1
	lxvd2x	55, 0, 8
	vor	15, 23, 23 /* codespell:ignore vor */
	vadduqm	16, 15, 31
	vadduqm	23, 16, 31
	stxvd2x	55, 0, 8
	lxvd2x	55, 0, 3
	addi	3, 3, 16
	lxvd2x	56, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 0
	vxor	16, 16, 0
	vcipher	15, 15, 1
	vcipher	16, 16, 1
	vcipher	15, 15, 2
	vcipher	16, 16, 2
	vcipher	15, 15, 3
	vcipher	16, 16, 3
	vcipher	15, 15, 4
	vcipher	16, 16, 4
	vcipher	15, 15, 5
	vcipher	16, 16, 5
	vcipher	15, 15, 6
	vcipher	16, 16, 6
	vcipher	15, 15, 7
	vcipher	16, 16, 7
	vcipher	15, 15, 8
	vcipher	16, 16, 8
	vcipher	15, 15, 9
	vcipher	16, 16, 9
	vcipherlast	15, 15, 10
	vcipherlast	16, 16, 10
	vxor	15, 15, 23
	vxor	16, 16, 24
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	addi	5, 5, -32
L_AES_CTR_encrypt_crypto_128_blk1:
	cmpdi	5, 16
	blt	L_AES_CTR_encrypt_crypto_128_done
	lxvd2x	55, 0, 8
	vor	15, 23, 23 /* codespell:ignore vor */
	vadduqm	23, 15, 31
	stxvd2x	55, 0, 8
	lxvd2x	55, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 0
	vcipher	15, 15, 1
	vcipher	15, 15, 2
	vcipher	15, 15, 3
	vcipher	15, 15, 4
	vcipher	15, 15, 5
	vcipher	15, 15, 6
	vcipher	15, 15, 7
	vcipher	15, 15, 8
	vcipher	15, 15, 9
	vcipherlast	15, 15, 10
	vxor	15, 15, 23
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	addi	5, 5, -16
L_AES_CTR_encrypt_crypto_128_done:
L_AES_CTR_encrypt_crypto_alldone:
	ld	0, 0(1)
	mtlr	0
	addi	1, 1, 8
	li	0, 0
	lxvd2x	52, 1, 0
	li	0, 16
	lxvd2x	53, 1, 0
	li	0, 32
	lxvd2x	54, 1, 0
	li	0, 48
	lxvd2x	55, 1, 0
	li	0, 0x40
	lxvd2x	56, 1, 0
	li	0, 0x50
	lxvd2x	57, 1, 0
	li	0, 0x60
	lxvd2x	58, 1, 0
	li	0, 0x70
	lxvd2x	59, 1, 0
	li	0, 0x80
	lxvd2x	60, 1, 0
	li	0, 0x90
	lxvd2x	61, 1, 0
	li	0, 0xa0
	lxvd2x	62, 1, 0
	li	0, 0xb0
	lxvd2x	63, 1, 0
	addi	1, 1, 0xc0
	blr
#ifndef __APPLE__
	.size	AES_CTR_encrypt_crypto,.-AES_CTR_encrypt_crypto
#endif /* __APPLE__ */
	.machine	"pop"
#endif /* WOLFSSL_AES_COUNTER */
#ifdef HAVE_AESGCM
	.machine	"push"
	.machine	"power8"
#ifndef __APPLE__
.text
.globl	AES_GCM_encrypt_crypto
.type	AES_GCM_encrypt_crypto,@function
.align	16
AES_GCM_encrypt_crypto:
#if defined(_CALL_ELF) && _CALL_ELF == 2
0:	addis	2, 12, .TOC.-0b@ha
	addi	2, 2, .TOC.-0b@l
	.localentry	AES_GCM_encrypt_crypto, .-AES_GCM_encrypt_crypto
#endif
#else
.section	__TEXT,__text
.globl	_AES_GCM_encrypt_crypto
.p2align	4
_AES_GCM_encrypt_crypto:
#endif /* __APPLE__ */
	subi	1, 1, 0xc0
	li	0, 0
	stxvd2x	52, 1, 0
	li	0, 16
	stxvd2x	53, 1, 0
	li	0, 32
	stxvd2x	54, 1, 0
	li	0, 48
	stxvd2x	55, 1, 0
	li	0, 0x40
	stxvd2x	56, 1, 0
	li	0, 0x50
	stxvd2x	57, 1, 0
	li	0, 0x60
	stxvd2x	58, 1, 0
	li	0, 0x70
	stxvd2x	59, 1, 0
	li	0, 0x80
	stxvd2x	60, 1, 0
	li	0, 0x90
	stxvd2x	61, 1, 0
	li	0, 0xa0
	stxvd2x	62, 1, 0
	li	0, 0xb0
	stxvd2x	63, 1, 0
	stdu	1, -8(1)
	mflr	0
	std	0, 0(1)
	addis	9, 2, L_AES_PPC64_crypto_one@toc@ha
	addi	9, 9, L_AES_PPC64_crypto_one@toc@l
	lxvd2x	63, 0, 9
	cmplwi	7, 10
	beq	L_AES_GCM_encrypt_crypto_128
	cmplwi	7, 12
	beq	L_AES_GCM_encrypt_crypto_192
	addi	10, 6, 0
	lxvd2x	32, 0, 10
	addi	10, 10, 16
	lxvd2x	33, 0, 10
	addi	10, 10, 16
	lxvd2x	34, 0, 10
	addi	10, 10, 16
	lxvd2x	35, 0, 10
	addi	10, 10, 16
	lxvd2x	36, 0, 10
	addi	10, 10, 16
	lxvd2x	37, 0, 10
	addi	10, 10, 16
	lxvd2x	38, 0, 10
	addi	10, 10, 16
	lxvd2x	39, 0, 10
	addi	10, 10, 16
	lxvd2x	40, 0, 10
	addi	10, 10, 16
	lxvd2x	41, 0, 10
	addi	10, 10, 16
	lxvd2x	42, 0, 10
	addi	10, 10, 16
	lxvd2x	43, 0, 10
	addi	10, 10, 16
	lxvd2x	44, 0, 10
	addi	10, 10, 16
	lxvd2x	45, 0, 10
	addi	10, 10, 16
	lxvd2x	46, 0, 10
	addi	10, 10, 16
	cmpdi	5, 0x80
	blt	L_AES_GCM_encrypt_crypto_256_blk4
L_AES_GCM_encrypt_crypto_256_blk8:
	lxvd2x	55, 0, 8
	vadduwm	15, 23, 31
	vadduwm	16, 15, 31
	vadduwm	17, 16, 31
	vadduwm	18, 17, 31
	vadduwm	19, 18, 31
	vadduwm	20, 19, 31
	vadduwm	21, 20, 31
	vadduwm	22, 21, 31
	vor	23, 22, 22 /* codespell:ignore vor */
	stxvd2x	55, 0, 8
	lxvd2x	55, 0, 3
	addi	3, 3, 16
	lxvd2x	56, 0, 3
	addi	3, 3, 16
	lxvd2x	57, 0, 3
	addi	3, 3, 16
	lxvd2x	58, 0, 3
	addi	3, 3, 16
	lxvd2x	59, 0, 3
	addi	3, 3, 16
	lxvd2x	60, 0, 3
	addi	3, 3, 16
	lxvd2x	61, 0, 3
	addi	3, 3, 16
	lxvd2x	62, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 0
	vxor	16, 16, 0
	vxor	17, 17, 0
	vxor	18, 18, 0
	vxor	19, 19, 0
	vxor	20, 20, 0
	vxor	21, 21, 0
	vxor	22, 22, 0
	vcipher	15, 15, 1
	vcipher	16, 16, 1
	vcipher	17, 17, 1
	vcipher	18, 18, 1
	vcipher	19, 19, 1
	vcipher	20, 20, 1
	vcipher	21, 21, 1
	vcipher	22, 22, 1
	vcipher	15, 15, 2
	vcipher	16, 16, 2
	vcipher	17, 17, 2
	vcipher	18, 18, 2
	vcipher	19, 19, 2
	vcipher	20, 20, 2
	vcipher	21, 21, 2
	vcipher	22, 22, 2
	vcipher	15, 15, 3
	vcipher	16, 16, 3
	vcipher	17, 17, 3
	vcipher	18, 18, 3
	vcipher	19, 19, 3
	vcipher	20, 20, 3
	vcipher	21, 21, 3
	vcipher	22, 22, 3
	vcipher	15, 15, 4
	vcipher	16, 16, 4
	vcipher	17, 17, 4
	vcipher	18, 18, 4
	vcipher	19, 19, 4
	vcipher	20, 20, 4
	vcipher	21, 21, 4
	vcipher	22, 22, 4
	vcipher	15, 15, 5
	vcipher	16, 16, 5
	vcipher	17, 17, 5
	vcipher	18, 18, 5
	vcipher	19, 19, 5
	vcipher	20, 20, 5
	vcipher	21, 21, 5
	vcipher	22, 22, 5
	vcipher	15, 15, 6
	vcipher	16, 16, 6
	vcipher	17, 17, 6
	vcipher	18, 18, 6
	vcipher	19, 19, 6
	vcipher	20, 20, 6
	vcipher	21, 21, 6
	vcipher	22, 22, 6
	vcipher	15, 15, 7
	vcipher	16, 16, 7
	vcipher	17, 17, 7
	vcipher	18, 18, 7
	vcipher	19, 19, 7
	vcipher	20, 20, 7
	vcipher	21, 21, 7
	vcipher	22, 22, 7
	vcipher	15, 15, 8
	vcipher	16, 16, 8
	vcipher	17, 17, 8
	vcipher	18, 18, 8
	vcipher	19, 19, 8
	vcipher	20, 20, 8
	vcipher	21, 21, 8
	vcipher	22, 22, 8
	vcipher	15, 15, 9
	vcipher	16, 16, 9
	vcipher	17, 17, 9
	vcipher	18, 18, 9
	vcipher	19, 19, 9
	vcipher	20, 20, 9
	vcipher	21, 21, 9
	vcipher	22, 22, 9
	vcipher	15, 15, 10
	vcipher	16, 16, 10
	vcipher	17, 17, 10
	vcipher	18, 18, 10
	vcipher	19, 19, 10
	vcipher	20, 20, 10
	vcipher	21, 21, 10
	vcipher	22, 22, 10
	vcipher	15, 15, 11
	vcipher	16, 16, 11
	vcipher	17, 17, 11
	vcipher	18, 18, 11
	vcipher	19, 19, 11
	vcipher	20, 20, 11
	vcipher	21, 21, 11
	vcipher	22, 22, 11
	vcipher	15, 15, 12
	vcipher	16, 16, 12
	vcipher	17, 17, 12
	vcipher	18, 18, 12
	vcipher	19, 19, 12
	vcipher	20, 20, 12
	vcipher	21, 21, 12
	vcipher	22, 22, 12
	vcipher	15, 15, 13
	vcipher	16, 16, 13
	vcipher	17, 17, 13
	vcipher	18, 18, 13
	vcipher	19, 19, 13
	vcipher	20, 20, 13
	vcipher	21, 21, 13
	vcipher	22, 22, 13
	vcipherlast	15, 15, 14
	vcipherlast	16, 16, 14
	vcipherlast	17, 17, 14
	vcipherlast	18, 18, 14
	vcipherlast	19, 19, 14
	vcipherlast	20, 20, 14
	vcipherlast	21, 21, 14
	vcipherlast	22, 22, 14
	vxor	15, 15, 23
	vxor	16, 16, 24
	vxor	17, 17, 25
	vxor	18, 18, 26
	vxor	19, 19, 27
	vxor	20, 20, 28
	vxor	21, 21, 29
	vxor	22, 22, 30
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	stxvd2x	49, 0, 4
	addi	4, 4, 16
	stxvd2x	50, 0, 4
	addi	4, 4, 16
	stxvd2x	51, 0, 4
	addi	4, 4, 16
	stxvd2x	52, 0, 4
	addi	4, 4, 16
	stxvd2x	53, 0, 4
	addi	4, 4, 16
	stxvd2x	54, 0, 4
	addi	4, 4, 16
	addi	5, 5, -128
	cmpdi	5, 0x80
	bge	L_AES_GCM_encrypt_crypto_256_blk8
L_AES_GCM_encrypt_crypto_256_blk4:
	cmpdi	5, 0x40
	blt	L_AES_GCM_encrypt_crypto_256_blk2
	lxvd2x	55, 0, 8
	vadduwm	15, 23, 31
	vadduwm	16, 15, 31
	vadduwm	17, 16, 31
	vadduwm	18, 17, 31
	vor	23, 18, 18 /* codespell:ignore vor */
	stxvd2x	55, 0, 8
	lxvd2x	55, 0, 3
	addi	3, 3, 16
	lxvd2x	56, 0, 3
	addi	3, 3, 16
	lxvd2x	57, 0, 3
	addi	3, 3, 16
	lxvd2x	58, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 0
	vxor	16, 16, 0
	vxor	17, 17, 0
	vxor	18, 18, 0
	vcipher	15, 15, 1
	vcipher	16, 16, 1
	vcipher	17, 17, 1
	vcipher	18, 18, 1
	vcipher	15, 15, 2
	vcipher	16, 16, 2
	vcipher	17, 17, 2
	vcipher	18, 18, 2
	vcipher	15, 15, 3
	vcipher	16, 16, 3
	vcipher	17, 17, 3
	vcipher	18, 18, 3
	vcipher	15, 15, 4
	vcipher	16, 16, 4
	vcipher	17, 17, 4
	vcipher	18, 18, 4
	vcipher	15, 15, 5
	vcipher	16, 16, 5
	vcipher	17, 17, 5
	vcipher	18, 18, 5
	vcipher	15, 15, 6
	vcipher	16, 16, 6
	vcipher	17, 17, 6
	vcipher	18, 18, 6
	vcipher	15, 15, 7
	vcipher	16, 16, 7
	vcipher	17, 17, 7
	vcipher	18, 18, 7
	vcipher	15, 15, 8
	vcipher	16, 16, 8
	vcipher	17, 17, 8
	vcipher	18, 18, 8
	vcipher	15, 15, 9
	vcipher	16, 16, 9
	vcipher	17, 17, 9
	vcipher	18, 18, 9
	vcipher	15, 15, 10
	vcipher	16, 16, 10
	vcipher	17, 17, 10
	vcipher	18, 18, 10
	vcipher	15, 15, 11
	vcipher	16, 16, 11
	vcipher	17, 17, 11
	vcipher	18, 18, 11
	vcipher	15, 15, 12
	vcipher	16, 16, 12
	vcipher	17, 17, 12
	vcipher	18, 18, 12
	vcipher	15, 15, 13
	vcipher	16, 16, 13
	vcipher	17, 17, 13
	vcipher	18, 18, 13
	vcipherlast	15, 15, 14
	vcipherlast	16, 16, 14
	vcipherlast	17, 17, 14
	vcipherlast	18, 18, 14
	vxor	15, 15, 23
	vxor	16, 16, 24
	vxor	17, 17, 25
	vxor	18, 18, 26
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	stxvd2x	49, 0, 4
	addi	4, 4, 16
	stxvd2x	50, 0, 4
	addi	4, 4, 16
	addi	5, 5, -64
L_AES_GCM_encrypt_crypto_256_blk2:
	cmpdi	5, 32
	blt	L_AES_GCM_encrypt_crypto_256_blk1
	lxvd2x	55, 0, 8
	vadduwm	15, 23, 31
	vadduwm	16, 15, 31
	vor	23, 16, 16 /* codespell:ignore vor */
	stxvd2x	55, 0, 8
	lxvd2x	55, 0, 3
	addi	3, 3, 16
	lxvd2x	56, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 0
	vxor	16, 16, 0
	vcipher	15, 15, 1
	vcipher	16, 16, 1
	vcipher	15, 15, 2
	vcipher	16, 16, 2
	vcipher	15, 15, 3
	vcipher	16, 16, 3
	vcipher	15, 15, 4
	vcipher	16, 16, 4
	vcipher	15, 15, 5
	vcipher	16, 16, 5
	vcipher	15, 15, 6
	vcipher	16, 16, 6
	vcipher	15, 15, 7
	vcipher	16, 16, 7
	vcipher	15, 15, 8
	vcipher	16, 16, 8
	vcipher	15, 15, 9
	vcipher	16, 16, 9
	vcipher	15, 15, 10
	vcipher	16, 16, 10
	vcipher	15, 15, 11
	vcipher	16, 16, 11
	vcipher	15, 15, 12
	vcipher	16, 16, 12
	vcipher	15, 15, 13
	vcipher	16, 16, 13
	vcipherlast	15, 15, 14
	vcipherlast	16, 16, 14
	vxor	15, 15, 23
	vxor	16, 16, 24
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	addi	5, 5, -32
L_AES_GCM_encrypt_crypto_256_blk1:
	cmpdi	5, 16
	blt	L_AES_GCM_encrypt_crypto_256_done
	lxvd2x	55, 0, 8
	vadduwm	15, 23, 31
	vor	23, 15, 15 /* codespell:ignore vor */
	stxvd2x	55, 0, 8
	lxvd2x	55, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 0
	vcipher	15, 15, 1
	vcipher	15, 15, 2
	vcipher	15, 15, 3
	vcipher	15, 15, 4
	vcipher	15, 15, 5
	vcipher	15, 15, 6
	vcipher	15, 15, 7
	vcipher	15, 15, 8
	vcipher	15, 15, 9
	vcipher	15, 15, 10
	vcipher	15, 15, 11
	vcipher	15, 15, 12
	vcipher	15, 15, 13
	vcipherlast	15, 15, 14
	vxor	15, 15, 23
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	addi	5, 5, -16
L_AES_GCM_encrypt_crypto_256_done:
	b	L_AES_GCM_encrypt_crypto_alldone
L_AES_GCM_encrypt_crypto_192:
	addi	10, 6, 0
	lxvd2x	32, 0, 10
	addi	10, 10, 16
	lxvd2x	33, 0, 10
	addi	10, 10, 16
	lxvd2x	34, 0, 10
	addi	10, 10, 16
	lxvd2x	35, 0, 10
	addi	10, 10, 16
	lxvd2x	36, 0, 10
	addi	10, 10, 16
	lxvd2x	37, 0, 10
	addi	10, 10, 16
	lxvd2x	38, 0, 10
	addi	10, 10, 16
	lxvd2x	39, 0, 10
	addi	10, 10, 16
	lxvd2x	40, 0, 10
	addi	10, 10, 16
	lxvd2x	41, 0, 10
	addi	10, 10, 16
	lxvd2x	42, 0, 10
	addi	10, 10, 16
	lxvd2x	43, 0, 10
	addi	10, 10, 16
	lxvd2x	44, 0, 10
	addi	10, 10, 16
	cmpdi	5, 0x80
	blt	L_AES_GCM_encrypt_crypto_192_blk4
L_AES_GCM_encrypt_crypto_192_blk8:
	lxvd2x	55, 0, 8
	vadduwm	15, 23, 31
	vadduwm	16, 15, 31
	vadduwm	17, 16, 31
	vadduwm	18, 17, 31
	vadduwm	19, 18, 31
	vadduwm	20, 19, 31
	vadduwm	21, 20, 31
	vadduwm	22, 21, 31
	vor	23, 22, 22 /* codespell:ignore vor */
	stxvd2x	55, 0, 8
	lxvd2x	55, 0, 3
	addi	3, 3, 16
	lxvd2x	56, 0, 3
	addi	3, 3, 16
	lxvd2x	57, 0, 3
	addi	3, 3, 16
	lxvd2x	58, 0, 3
	addi	3, 3, 16
	lxvd2x	59, 0, 3
	addi	3, 3, 16
	lxvd2x	60, 0, 3
	addi	3, 3, 16
	lxvd2x	61, 0, 3
	addi	3, 3, 16
	lxvd2x	62, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 0
	vxor	16, 16, 0
	vxor	17, 17, 0
	vxor	18, 18, 0
	vxor	19, 19, 0
	vxor	20, 20, 0
	vxor	21, 21, 0
	vxor	22, 22, 0
	vcipher	15, 15, 1
	vcipher	16, 16, 1
	vcipher	17, 17, 1
	vcipher	18, 18, 1
	vcipher	19, 19, 1
	vcipher	20, 20, 1
	vcipher	21, 21, 1
	vcipher	22, 22, 1
	vcipher	15, 15, 2
	vcipher	16, 16, 2
	vcipher	17, 17, 2
	vcipher	18, 18, 2
	vcipher	19, 19, 2
	vcipher	20, 20, 2
	vcipher	21, 21, 2
	vcipher	22, 22, 2
	vcipher	15, 15, 3
	vcipher	16, 16, 3
	vcipher	17, 17, 3
	vcipher	18, 18, 3
	vcipher	19, 19, 3
	vcipher	20, 20, 3
	vcipher	21, 21, 3
	vcipher	22, 22, 3
	vcipher	15, 15, 4
	vcipher	16, 16, 4
	vcipher	17, 17, 4
	vcipher	18, 18, 4
	vcipher	19, 19, 4
	vcipher	20, 20, 4
	vcipher	21, 21, 4
	vcipher	22, 22, 4
	vcipher	15, 15, 5
	vcipher	16, 16, 5
	vcipher	17, 17, 5
	vcipher	18, 18, 5
	vcipher	19, 19, 5
	vcipher	20, 20, 5
	vcipher	21, 21, 5
	vcipher	22, 22, 5
	vcipher	15, 15, 6
	vcipher	16, 16, 6
	vcipher	17, 17, 6
	vcipher	18, 18, 6
	vcipher	19, 19, 6
	vcipher	20, 20, 6
	vcipher	21, 21, 6
	vcipher	22, 22, 6
	vcipher	15, 15, 7
	vcipher	16, 16, 7
	vcipher	17, 17, 7
	vcipher	18, 18, 7
	vcipher	19, 19, 7
	vcipher	20, 20, 7
	vcipher	21, 21, 7
	vcipher	22, 22, 7
	vcipher	15, 15, 8
	vcipher	16, 16, 8
	vcipher	17, 17, 8
	vcipher	18, 18, 8
	vcipher	19, 19, 8
	vcipher	20, 20, 8
	vcipher	21, 21, 8
	vcipher	22, 22, 8
	vcipher	15, 15, 9
	vcipher	16, 16, 9
	vcipher	17, 17, 9
	vcipher	18, 18, 9
	vcipher	19, 19, 9
	vcipher	20, 20, 9
	vcipher	21, 21, 9
	vcipher	22, 22, 9
	vcipher	15, 15, 10
	vcipher	16, 16, 10
	vcipher	17, 17, 10
	vcipher	18, 18, 10
	vcipher	19, 19, 10
	vcipher	20, 20, 10
	vcipher	21, 21, 10
	vcipher	22, 22, 10
	vcipher	15, 15, 11
	vcipher	16, 16, 11
	vcipher	17, 17, 11
	vcipher	18, 18, 11
	vcipher	19, 19, 11
	vcipher	20, 20, 11
	vcipher	21, 21, 11
	vcipher	22, 22, 11
	vcipherlast	15, 15, 12
	vcipherlast	16, 16, 12
	vcipherlast	17, 17, 12
	vcipherlast	18, 18, 12
	vcipherlast	19, 19, 12
	vcipherlast	20, 20, 12
	vcipherlast	21, 21, 12
	vcipherlast	22, 22, 12
	vxor	15, 15, 23
	vxor	16, 16, 24
	vxor	17, 17, 25
	vxor	18, 18, 26
	vxor	19, 19, 27
	vxor	20, 20, 28
	vxor	21, 21, 29
	vxor	22, 22, 30
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	stxvd2x	49, 0, 4
	addi	4, 4, 16
	stxvd2x	50, 0, 4
	addi	4, 4, 16
	stxvd2x	51, 0, 4
	addi	4, 4, 16
	stxvd2x	52, 0, 4
	addi	4, 4, 16
	stxvd2x	53, 0, 4
	addi	4, 4, 16
	stxvd2x	54, 0, 4
	addi	4, 4, 16
	addi	5, 5, -128
	cmpdi	5, 0x80
	bge	L_AES_GCM_encrypt_crypto_192_blk8
L_AES_GCM_encrypt_crypto_192_blk4:
	cmpdi	5, 0x40
	blt	L_AES_GCM_encrypt_crypto_192_blk2
	lxvd2x	55, 0, 8
	vadduwm	15, 23, 31
	vadduwm	16, 15, 31
	vadduwm	17, 16, 31
	vadduwm	18, 17, 31
	vor	23, 18, 18 /* codespell:ignore vor */
	stxvd2x	55, 0, 8
	lxvd2x	55, 0, 3
	addi	3, 3, 16
	lxvd2x	56, 0, 3
	addi	3, 3, 16
	lxvd2x	57, 0, 3
	addi	3, 3, 16
	lxvd2x	58, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 0
	vxor	16, 16, 0
	vxor	17, 17, 0
	vxor	18, 18, 0
	vcipher	15, 15, 1
	vcipher	16, 16, 1
	vcipher	17, 17, 1
	vcipher	18, 18, 1
	vcipher	15, 15, 2
	vcipher	16, 16, 2
	vcipher	17, 17, 2
	vcipher	18, 18, 2
	vcipher	15, 15, 3
	vcipher	16, 16, 3
	vcipher	17, 17, 3
	vcipher	18, 18, 3
	vcipher	15, 15, 4
	vcipher	16, 16, 4
	vcipher	17, 17, 4
	vcipher	18, 18, 4
	vcipher	15, 15, 5
	vcipher	16, 16, 5
	vcipher	17, 17, 5
	vcipher	18, 18, 5
	vcipher	15, 15, 6
	vcipher	16, 16, 6
	vcipher	17, 17, 6
	vcipher	18, 18, 6
	vcipher	15, 15, 7
	vcipher	16, 16, 7
	vcipher	17, 17, 7
	vcipher	18, 18, 7
	vcipher	15, 15, 8
	vcipher	16, 16, 8
	vcipher	17, 17, 8
	vcipher	18, 18, 8
	vcipher	15, 15, 9
	vcipher	16, 16, 9
	vcipher	17, 17, 9
	vcipher	18, 18, 9
	vcipher	15, 15, 10
	vcipher	16, 16, 10
	vcipher	17, 17, 10
	vcipher	18, 18, 10
	vcipher	15, 15, 11
	vcipher	16, 16, 11
	vcipher	17, 17, 11
	vcipher	18, 18, 11
	vcipherlast	15, 15, 12
	vcipherlast	16, 16, 12
	vcipherlast	17, 17, 12
	vcipherlast	18, 18, 12
	vxor	15, 15, 23
	vxor	16, 16, 24
	vxor	17, 17, 25
	vxor	18, 18, 26
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	stxvd2x	49, 0, 4
	addi	4, 4, 16
	stxvd2x	50, 0, 4
	addi	4, 4, 16
	addi	5, 5, -64
L_AES_GCM_encrypt_crypto_192_blk2:
	cmpdi	5, 32
	blt	L_AES_GCM_encrypt_crypto_192_blk1
	lxvd2x	55, 0, 8
	vadduwm	15, 23, 31
	vadduwm	16, 15, 31
	vor	23, 16, 16 /* codespell:ignore vor */
	stxvd2x	55, 0, 8
	lxvd2x	55, 0, 3
	addi	3, 3, 16
	lxvd2x	56, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 0
	vxor	16, 16, 0
	vcipher	15, 15, 1
	vcipher	16, 16, 1
	vcipher	15, 15, 2
	vcipher	16, 16, 2
	vcipher	15, 15, 3
	vcipher	16, 16, 3
	vcipher	15, 15, 4
	vcipher	16, 16, 4
	vcipher	15, 15, 5
	vcipher	16, 16, 5
	vcipher	15, 15, 6
	vcipher	16, 16, 6
	vcipher	15, 15, 7
	vcipher	16, 16, 7
	vcipher	15, 15, 8
	vcipher	16, 16, 8
	vcipher	15, 15, 9
	vcipher	16, 16, 9
	vcipher	15, 15, 10
	vcipher	16, 16, 10
	vcipher	15, 15, 11
	vcipher	16, 16, 11
	vcipherlast	15, 15, 12
	vcipherlast	16, 16, 12
	vxor	15, 15, 23
	vxor	16, 16, 24
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	addi	5, 5, -32
L_AES_GCM_encrypt_crypto_192_blk1:
	cmpdi	5, 16
	blt	L_AES_GCM_encrypt_crypto_192_done
	lxvd2x	55, 0, 8
	vadduwm	15, 23, 31
	vor	23, 15, 15 /* codespell:ignore vor */
	stxvd2x	55, 0, 8
	lxvd2x	55, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 0
	vcipher	15, 15, 1
	vcipher	15, 15, 2
	vcipher	15, 15, 3
	vcipher	15, 15, 4
	vcipher	15, 15, 5
	vcipher	15, 15, 6
	vcipher	15, 15, 7
	vcipher	15, 15, 8
	vcipher	15, 15, 9
	vcipher	15, 15, 10
	vcipher	15, 15, 11
	vcipherlast	15, 15, 12
	vxor	15, 15, 23
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	addi	5, 5, -16
L_AES_GCM_encrypt_crypto_192_done:
	b	L_AES_GCM_encrypt_crypto_alldone
L_AES_GCM_encrypt_crypto_128:
	addi	10, 6, 0
	lxvd2x	32, 0, 10
	addi	10, 10, 16
	lxvd2x	33, 0, 10
	addi	10, 10, 16
	lxvd2x	34, 0, 10
	addi	10, 10, 16
	lxvd2x	35, 0, 10
	addi	10, 10, 16
	lxvd2x	36, 0, 10
	addi	10, 10, 16
	lxvd2x	37, 0, 10
	addi	10, 10, 16
	lxvd2x	38, 0, 10
	addi	10, 10, 16
	lxvd2x	39, 0, 10
	addi	10, 10, 16
	lxvd2x	40, 0, 10
	addi	10, 10, 16
	lxvd2x	41, 0, 10
	addi	10, 10, 16
	lxvd2x	42, 0, 10
	addi	10, 10, 16
	cmpdi	5, 0x80
	blt	L_AES_GCM_encrypt_crypto_128_blk4
L_AES_GCM_encrypt_crypto_128_blk8:
	lxvd2x	55, 0, 8
	vadduwm	15, 23, 31
	vadduwm	16, 15, 31
	vadduwm	17, 16, 31
	vadduwm	18, 17, 31
	vadduwm	19, 18, 31
	vadduwm	20, 19, 31
	vadduwm	21, 20, 31
	vadduwm	22, 21, 31
	vor	23, 22, 22 /* codespell:ignore vor */
	stxvd2x	55, 0, 8
	lxvd2x	55, 0, 3
	addi	3, 3, 16
	lxvd2x	56, 0, 3
	addi	3, 3, 16
	lxvd2x	57, 0, 3
	addi	3, 3, 16
	lxvd2x	58, 0, 3
	addi	3, 3, 16
	lxvd2x	59, 0, 3
	addi	3, 3, 16
	lxvd2x	60, 0, 3
	addi	3, 3, 16
	lxvd2x	61, 0, 3
	addi	3, 3, 16
	lxvd2x	62, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 0
	vxor	16, 16, 0
	vxor	17, 17, 0
	vxor	18, 18, 0
	vxor	19, 19, 0
	vxor	20, 20, 0
	vxor	21, 21, 0
	vxor	22, 22, 0
	vcipher	15, 15, 1
	vcipher	16, 16, 1
	vcipher	17, 17, 1
	vcipher	18, 18, 1
	vcipher	19, 19, 1
	vcipher	20, 20, 1
	vcipher	21, 21, 1
	vcipher	22, 22, 1
	vcipher	15, 15, 2
	vcipher	16, 16, 2
	vcipher	17, 17, 2
	vcipher	18, 18, 2
	vcipher	19, 19, 2
	vcipher	20, 20, 2
	vcipher	21, 21, 2
	vcipher	22, 22, 2
	vcipher	15, 15, 3
	vcipher	16, 16, 3
	vcipher	17, 17, 3
	vcipher	18, 18, 3
	vcipher	19, 19, 3
	vcipher	20, 20, 3
	vcipher	21, 21, 3
	vcipher	22, 22, 3
	vcipher	15, 15, 4
	vcipher	16, 16, 4
	vcipher	17, 17, 4
	vcipher	18, 18, 4
	vcipher	19, 19, 4
	vcipher	20, 20, 4
	vcipher	21, 21, 4
	vcipher	22, 22, 4
	vcipher	15, 15, 5
	vcipher	16, 16, 5
	vcipher	17, 17, 5
	vcipher	18, 18, 5
	vcipher	19, 19, 5
	vcipher	20, 20, 5
	vcipher	21, 21, 5
	vcipher	22, 22, 5
	vcipher	15, 15, 6
	vcipher	16, 16, 6
	vcipher	17, 17, 6
	vcipher	18, 18, 6
	vcipher	19, 19, 6
	vcipher	20, 20, 6
	vcipher	21, 21, 6
	vcipher	22, 22, 6
	vcipher	15, 15, 7
	vcipher	16, 16, 7
	vcipher	17, 17, 7
	vcipher	18, 18, 7
	vcipher	19, 19, 7
	vcipher	20, 20, 7
	vcipher	21, 21, 7
	vcipher	22, 22, 7
	vcipher	15, 15, 8
	vcipher	16, 16, 8
	vcipher	17, 17, 8
	vcipher	18, 18, 8
	vcipher	19, 19, 8
	vcipher	20, 20, 8
	vcipher	21, 21, 8
	vcipher	22, 22, 8
	vcipher	15, 15, 9
	vcipher	16, 16, 9
	vcipher	17, 17, 9
	vcipher	18, 18, 9
	vcipher	19, 19, 9
	vcipher	20, 20, 9
	vcipher	21, 21, 9
	vcipher	22, 22, 9
	vcipherlast	15, 15, 10
	vcipherlast	16, 16, 10
	vcipherlast	17, 17, 10
	vcipherlast	18, 18, 10
	vcipherlast	19, 19, 10
	vcipherlast	20, 20, 10
	vcipherlast	21, 21, 10
	vcipherlast	22, 22, 10
	vxor	15, 15, 23
	vxor	16, 16, 24
	vxor	17, 17, 25
	vxor	18, 18, 26
	vxor	19, 19, 27
	vxor	20, 20, 28
	vxor	21, 21, 29
	vxor	22, 22, 30
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	stxvd2x	49, 0, 4
	addi	4, 4, 16
	stxvd2x	50, 0, 4
	addi	4, 4, 16
	stxvd2x	51, 0, 4
	addi	4, 4, 16
	stxvd2x	52, 0, 4
	addi	4, 4, 16
	stxvd2x	53, 0, 4
	addi	4, 4, 16
	stxvd2x	54, 0, 4
	addi	4, 4, 16
	addi	5, 5, -128
	cmpdi	5, 0x80
	bge	L_AES_GCM_encrypt_crypto_128_blk8
L_AES_GCM_encrypt_crypto_128_blk4:
	cmpdi	5, 0x40
	blt	L_AES_GCM_encrypt_crypto_128_blk2
	lxvd2x	55, 0, 8
	vadduwm	15, 23, 31
	vadduwm	16, 15, 31
	vadduwm	17, 16, 31
	vadduwm	18, 17, 31
	vor	23, 18, 18 /* codespell:ignore vor */
	stxvd2x	55, 0, 8
	lxvd2x	55, 0, 3
	addi	3, 3, 16
	lxvd2x	56, 0, 3
	addi	3, 3, 16
	lxvd2x	57, 0, 3
	addi	3, 3, 16
	lxvd2x	58, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 0
	vxor	16, 16, 0
	vxor	17, 17, 0
	vxor	18, 18, 0
	vcipher	15, 15, 1
	vcipher	16, 16, 1
	vcipher	17, 17, 1
	vcipher	18, 18, 1
	vcipher	15, 15, 2
	vcipher	16, 16, 2
	vcipher	17, 17, 2
	vcipher	18, 18, 2
	vcipher	15, 15, 3
	vcipher	16, 16, 3
	vcipher	17, 17, 3
	vcipher	18, 18, 3
	vcipher	15, 15, 4
	vcipher	16, 16, 4
	vcipher	17, 17, 4
	vcipher	18, 18, 4
	vcipher	15, 15, 5
	vcipher	16, 16, 5
	vcipher	17, 17, 5
	vcipher	18, 18, 5
	vcipher	15, 15, 6
	vcipher	16, 16, 6
	vcipher	17, 17, 6
	vcipher	18, 18, 6
	vcipher	15, 15, 7
	vcipher	16, 16, 7
	vcipher	17, 17, 7
	vcipher	18, 18, 7
	vcipher	15, 15, 8
	vcipher	16, 16, 8
	vcipher	17, 17, 8
	vcipher	18, 18, 8
	vcipher	15, 15, 9
	vcipher	16, 16, 9
	vcipher	17, 17, 9
	vcipher	18, 18, 9
	vcipherlast	15, 15, 10
	vcipherlast	16, 16, 10
	vcipherlast	17, 17, 10
	vcipherlast	18, 18, 10
	vxor	15, 15, 23
	vxor	16, 16, 24
	vxor	17, 17, 25
	vxor	18, 18, 26
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	stxvd2x	49, 0, 4
	addi	4, 4, 16
	stxvd2x	50, 0, 4
	addi	4, 4, 16
	addi	5, 5, -64
L_AES_GCM_encrypt_crypto_128_blk2:
	cmpdi	5, 32
	blt	L_AES_GCM_encrypt_crypto_128_blk1
	lxvd2x	55, 0, 8
	vadduwm	15, 23, 31
	vadduwm	16, 15, 31
	vor	23, 16, 16 /* codespell:ignore vor */
	stxvd2x	55, 0, 8
	lxvd2x	55, 0, 3
	addi	3, 3, 16
	lxvd2x	56, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 0
	vxor	16, 16, 0
	vcipher	15, 15, 1
	vcipher	16, 16, 1
	vcipher	15, 15, 2
	vcipher	16, 16, 2
	vcipher	15, 15, 3
	vcipher	16, 16, 3
	vcipher	15, 15, 4
	vcipher	16, 16, 4
	vcipher	15, 15, 5
	vcipher	16, 16, 5
	vcipher	15, 15, 6
	vcipher	16, 16, 6
	vcipher	15, 15, 7
	vcipher	16, 16, 7
	vcipher	15, 15, 8
	vcipher	16, 16, 8
	vcipher	15, 15, 9
	vcipher	16, 16, 9
	vcipherlast	15, 15, 10
	vcipherlast	16, 16, 10
	vxor	15, 15, 23
	vxor	16, 16, 24
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	addi	5, 5, -32
L_AES_GCM_encrypt_crypto_128_blk1:
	cmpdi	5, 16
	blt	L_AES_GCM_encrypt_crypto_128_done
	lxvd2x	55, 0, 8
	vadduwm	15, 23, 31
	vor	23, 15, 15 /* codespell:ignore vor */
	stxvd2x	55, 0, 8
	lxvd2x	55, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 0
	vcipher	15, 15, 1
	vcipher	15, 15, 2
	vcipher	15, 15, 3
	vcipher	15, 15, 4
	vcipher	15, 15, 5
	vcipher	15, 15, 6
	vcipher	15, 15, 7
	vcipher	15, 15, 8
	vcipher	15, 15, 9
	vcipherlast	15, 15, 10
	vxor	15, 15, 23
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	addi	5, 5, -16
L_AES_GCM_encrypt_crypto_128_done:
L_AES_GCM_encrypt_crypto_alldone:
	ld	0, 0(1)
	mtlr	0
	addi	1, 1, 8
	li	0, 0
	lxvd2x	52, 1, 0
	li	0, 16
	lxvd2x	53, 1, 0
	li	0, 32
	lxvd2x	54, 1, 0
	li	0, 48
	lxvd2x	55, 1, 0
	li	0, 0x40
	lxvd2x	56, 1, 0
	li	0, 0x50
	lxvd2x	57, 1, 0
	li	0, 0x60
	lxvd2x	58, 1, 0
	li	0, 0x70
	lxvd2x	59, 1, 0
	li	0, 0x80
	lxvd2x	60, 1, 0
	li	0, 0x90
	lxvd2x	61, 1, 0
	li	0, 0xa0
	lxvd2x	62, 1, 0
	li	0, 0xb0
	lxvd2x	63, 1, 0
	addi	1, 1, 0xc0
	blr
#ifndef __APPLE__
	.size	AES_GCM_encrypt_crypto,.-AES_GCM_encrypt_crypto
#endif /* __APPLE__ */
	.machine	"pop"
#endif /* HAVE_AESGCM */
#ifdef WOLFSSL_AES_XTS
	.machine	"push"
	.machine	"power8"
#ifndef __APPLE__
.text
.globl	AES_XTS_encrypt_crypto
.type	AES_XTS_encrypt_crypto,@function
.align	16
AES_XTS_encrypt_crypto:
#if defined(_CALL_ELF) && _CALL_ELF == 2
0:	addis	2, 12, .TOC.-0b@ha
	addi	2, 2, .TOC.-0b@l
	.localentry	AES_XTS_encrypt_crypto, .-AES_XTS_encrypt_crypto
#endif
#else
.section	__TEXT,__text
.globl	_AES_XTS_encrypt_crypto
.p2align	4
_AES_XTS_encrypt_crypto:
#endif /* __APPLE__ */
	subi	1, 1, 0xc0
	li	0, 0
	stxvd2x	52, 1, 0
	li	0, 16
	stxvd2x	53, 1, 0
	li	0, 32
	stxvd2x	54, 1, 0
	li	0, 48
	stxvd2x	55, 1, 0
	li	0, 0x40
	stxvd2x	56, 1, 0
	li	0, 0x50
	stxvd2x	57, 1, 0
	li	0, 0x60
	stxvd2x	58, 1, 0
	li	0, 0x70
	stxvd2x	59, 1, 0
	li	0, 0x80
	stxvd2x	60, 1, 0
	li	0, 0x90
	stxvd2x	61, 1, 0
	li	0, 0xa0
	stxvd2x	62, 1, 0
	li	0, 0xb0
	stxvd2x	63, 1, 0
	stdu	1, -40(1)
	mflr	0
	std	0, 32(1)
	std	14, 0(1)
	std	15, 8(1)
	std	16, 16(1)
	std	17, 24(1)
	li	12, 8
	lxvd2x	63, 0, 6
	cmplwi	10, 10
	beq	L_AES_XTS_encrypt_crypto_128
	cmplwi	10, 12
	beq	L_AES_XTS_encrypt_crypto_192
	addi	11, 8, 0
	lxvd2x	32, 0, 11
	addi	11, 11, 16
	lxvd2x	33, 0, 11
	addi	11, 11, 16
	lxvd2x	34, 0, 11
	addi	11, 11, 16
	lxvd2x	35, 0, 11
	addi	11, 11, 16
	lxvd2x	36, 0, 11
	addi	11, 11, 16
	lxvd2x	37, 0, 11
	addi	11, 11, 16
	lxvd2x	38, 0, 11
	addi	11, 11, 16
	lxvd2x	39, 0, 11
	addi	11, 11, 16
	lxvd2x	40, 0, 11
	addi	11, 11, 16
	lxvd2x	41, 0, 11
	addi	11, 11, 16
	lxvd2x	42, 0, 11
	addi	11, 11, 16
	lxvd2x	43, 0, 11
	addi	11, 11, 16
	lxvd2x	44, 0, 11
	addi	11, 11, 16
	lxvd2x	45, 0, 11
	addi	11, 11, 16
	lxvd2x	46, 0, 11
	addi	11, 11, 16
	vxor	31, 31, 0
	vcipher	31, 31, 1
	vcipher	31, 31, 2
	vcipher	31, 31, 3
	vcipher	31, 31, 4
	vcipher	31, 31, 5
	vcipher	31, 31, 6
	vcipher	31, 31, 7
	vcipher	31, 31, 8
	vcipher	31, 31, 9
	vcipher	31, 31, 10
	vcipher	31, 31, 11
	vcipher	31, 31, 12
	vcipher	31, 31, 13
	vcipherlast	31, 31, 14
	addi	11, 7, 0
	lxvd2x	32, 0, 11
	addi	11, 11, 16
	lxvd2x	33, 0, 11
	addi	11, 11, 16
	lxvd2x	34, 0, 11
	addi	11, 11, 16
	lxvd2x	35, 0, 11
	addi	11, 11, 16
	lxvd2x	36, 0, 11
	addi	11, 11, 16
	lxvd2x	37, 0, 11
	addi	11, 11, 16
	lxvd2x	38, 0, 11
	addi	11, 11, 16
	lxvd2x	39, 0, 11
	addi	11, 11, 16
	lxvd2x	40, 0, 11
	addi	11, 11, 16
	lxvd2x	41, 0, 11
	addi	11, 11, 16
	lxvd2x	42, 0, 11
	addi	11, 11, 16
	lxvd2x	43, 0, 11
	addi	11, 11, 16
	lxvd2x	44, 0, 11
	addi	11, 11, 16
	lxvd2x	45, 0, 11
	addi	11, 11, 16
	lxvd2x	46, 0, 11
	addi	11, 11, 16
	cmpdi	5, 0x80
	blt	L_AES_XTS_encrypt_crypto_256_blk4
L_AES_XTS_encrypt_crypto_256_blk8:
	vor	23, 31, 31 /* codespell:ignore vor */
	stxvd2x	55, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	56, 0, 9
	stxvd2x	56, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	57, 0, 9
	stxvd2x	57, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	58, 0, 9
	stxvd2x	58, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	59, 0, 9
	stxvd2x	59, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	60, 0, 9
	stxvd2x	60, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	61, 0, 9
	stxvd2x	61, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	62, 0, 9
	stxvd2x	62, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	63, 0, 9
	lxvd2x	47, 0, 3
	addi	3, 3, 16
	lxvd2x	48, 0, 3
	addi	3, 3, 16
	lxvd2x	49, 0, 3
	addi	3, 3, 16
	lxvd2x	50, 0, 3
	addi	3, 3, 16
	lxvd2x	51, 0, 3
	addi	3, 3, 16
	lxvd2x	52, 0, 3
	addi	3, 3, 16
	lxvd2x	53, 0, 3
	addi	3, 3, 16
	lxvd2x	54, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 23
	vxor	16, 16, 24
	vxor	17, 17, 25
	vxor	18, 18, 26
	vxor	19, 19, 27
	vxor	20, 20, 28
	vxor	21, 21, 29
	vxor	22, 22, 30
	vxor	15, 15, 0
	vxor	16, 16, 0
	vxor	17, 17, 0
	vxor	18, 18, 0
	vxor	19, 19, 0
	vxor	20, 20, 0
	vxor	21, 21, 0
	vxor	22, 22, 0
	vcipher	15, 15, 1
	vcipher	16, 16, 1
	vcipher	17, 17, 1
	vcipher	18, 18, 1
	vcipher	19, 19, 1
	vcipher	20, 20, 1
	vcipher	21, 21, 1
	vcipher	22, 22, 1
	vcipher	15, 15, 2
	vcipher	16, 16, 2
	vcipher	17, 17, 2
	vcipher	18, 18, 2
	vcipher	19, 19, 2
	vcipher	20, 20, 2
	vcipher	21, 21, 2
	vcipher	22, 22, 2
	vcipher	15, 15, 3
	vcipher	16, 16, 3
	vcipher	17, 17, 3
	vcipher	18, 18, 3
	vcipher	19, 19, 3
	vcipher	20, 20, 3
	vcipher	21, 21, 3
	vcipher	22, 22, 3
	vcipher	15, 15, 4
	vcipher	16, 16, 4
	vcipher	17, 17, 4
	vcipher	18, 18, 4
	vcipher	19, 19, 4
	vcipher	20, 20, 4
	vcipher	21, 21, 4
	vcipher	22, 22, 4
	vcipher	15, 15, 5
	vcipher	16, 16, 5
	vcipher	17, 17, 5
	vcipher	18, 18, 5
	vcipher	19, 19, 5
	vcipher	20, 20, 5
	vcipher	21, 21, 5
	vcipher	22, 22, 5
	vcipher	15, 15, 6
	vcipher	16, 16, 6
	vcipher	17, 17, 6
	vcipher	18, 18, 6
	vcipher	19, 19, 6
	vcipher	20, 20, 6
	vcipher	21, 21, 6
	vcipher	22, 22, 6
	vcipher	15, 15, 7
	vcipher	16, 16, 7
	vcipher	17, 17, 7
	vcipher	18, 18, 7
	vcipher	19, 19, 7
	vcipher	20, 20, 7
	vcipher	21, 21, 7
	vcipher	22, 22, 7
	vcipher	15, 15, 8
	vcipher	16, 16, 8
	vcipher	17, 17, 8
	vcipher	18, 18, 8
	vcipher	19, 19, 8
	vcipher	20, 20, 8
	vcipher	21, 21, 8
	vcipher	22, 22, 8
	vcipher	15, 15, 9
	vcipher	16, 16, 9
	vcipher	17, 17, 9
	vcipher	18, 18, 9
	vcipher	19, 19, 9
	vcipher	20, 20, 9
	vcipher	21, 21, 9
	vcipher	22, 22, 9
	vcipher	15, 15, 10
	vcipher	16, 16, 10
	vcipher	17, 17, 10
	vcipher	18, 18, 10
	vcipher	19, 19, 10
	vcipher	20, 20, 10
	vcipher	21, 21, 10
	vcipher	22, 22, 10
	vcipher	15, 15, 11
	vcipher	16, 16, 11
	vcipher	17, 17, 11
	vcipher	18, 18, 11
	vcipher	19, 19, 11
	vcipher	20, 20, 11
	vcipher	21, 21, 11
	vcipher	22, 22, 11
	vcipher	15, 15, 12
	vcipher	16, 16, 12
	vcipher	17, 17, 12
	vcipher	18, 18, 12
	vcipher	19, 19, 12
	vcipher	20, 20, 12
	vcipher	21, 21, 12
	vcipher	22, 22, 12
	vcipher	15, 15, 13
	vcipher	16, 16, 13
	vcipher	17, 17, 13
	vcipher	18, 18, 13
	vcipher	19, 19, 13
	vcipher	20, 20, 13
	vcipher	21, 21, 13
	vcipher	22, 22, 13
	vcipherlast	15, 15, 14
	vcipherlast	16, 16, 14
	vcipherlast	17, 17, 14
	vcipherlast	18, 18, 14
	vcipherlast	19, 19, 14
	vcipherlast	20, 20, 14
	vcipherlast	21, 21, 14
	vcipherlast	22, 22, 14
	vxor	15, 15, 23
	vxor	16, 16, 24
	vxor	17, 17, 25
	vxor	18, 18, 26
	vxor	19, 19, 27
	vxor	20, 20, 28
	vxor	21, 21, 29
	vxor	22, 22, 30
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	stxvd2x	49, 0, 4
	addi	4, 4, 16
	stxvd2x	50, 0, 4
	addi	4, 4, 16
	stxvd2x	51, 0, 4
	addi	4, 4, 16
	stxvd2x	52, 0, 4
	addi	4, 4, 16
	stxvd2x	53, 0, 4
	addi	4, 4, 16
	stxvd2x	54, 0, 4
	addi	4, 4, 16
	addi	5, 5, -128
	cmpdi	5, 0x80
	bge	L_AES_XTS_encrypt_crypto_256_blk8
L_AES_XTS_encrypt_crypto_256_blk4:
	cmpdi	5, 0x40
	blt	L_AES_XTS_encrypt_crypto_256_blk2
	vor	23, 31, 31 /* codespell:ignore vor */
	stxvd2x	55, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	56, 0, 9
	stxvd2x	56, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	57, 0, 9
	stxvd2x	57, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	58, 0, 9
	stxvd2x	58, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	63, 0, 9
	lxvd2x	47, 0, 3
	addi	3, 3, 16
	lxvd2x	48, 0, 3
	addi	3, 3, 16
	lxvd2x	49, 0, 3
	addi	3, 3, 16
	lxvd2x	50, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 23
	vxor	16, 16, 24
	vxor	17, 17, 25
	vxor	18, 18, 26
	vxor	15, 15, 0
	vxor	16, 16, 0
	vxor	17, 17, 0
	vxor	18, 18, 0
	vcipher	15, 15, 1
	vcipher	16, 16, 1
	vcipher	17, 17, 1
	vcipher	18, 18, 1
	vcipher	15, 15, 2
	vcipher	16, 16, 2
	vcipher	17, 17, 2
	vcipher	18, 18, 2
	vcipher	15, 15, 3
	vcipher	16, 16, 3
	vcipher	17, 17, 3
	vcipher	18, 18, 3
	vcipher	15, 15, 4
	vcipher	16, 16, 4
	vcipher	17, 17, 4
	vcipher	18, 18, 4
	vcipher	15, 15, 5
	vcipher	16, 16, 5
	vcipher	17, 17, 5
	vcipher	18, 18, 5
	vcipher	15, 15, 6
	vcipher	16, 16, 6
	vcipher	17, 17, 6
	vcipher	18, 18, 6
	vcipher	15, 15, 7
	vcipher	16, 16, 7
	vcipher	17, 17, 7
	vcipher	18, 18, 7
	vcipher	15, 15, 8
	vcipher	16, 16, 8
	vcipher	17, 17, 8
	vcipher	18, 18, 8
	vcipher	15, 15, 9
	vcipher	16, 16, 9
	vcipher	17, 17, 9
	vcipher	18, 18, 9
	vcipher	15, 15, 10
	vcipher	16, 16, 10
	vcipher	17, 17, 10
	vcipher	18, 18, 10
	vcipher	15, 15, 11
	vcipher	16, 16, 11
	vcipher	17, 17, 11
	vcipher	18, 18, 11
	vcipher	15, 15, 12
	vcipher	16, 16, 12
	vcipher	17, 17, 12
	vcipher	18, 18, 12
	vcipher	15, 15, 13
	vcipher	16, 16, 13
	vcipher	17, 17, 13
	vcipher	18, 18, 13
	vcipherlast	15, 15, 14
	vcipherlast	16, 16, 14
	vcipherlast	17, 17, 14
	vcipherlast	18, 18, 14
	vxor	15, 15, 23
	vxor	16, 16, 24
	vxor	17, 17, 25
	vxor	18, 18, 26
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	stxvd2x	49, 0, 4
	addi	4, 4, 16
	stxvd2x	50, 0, 4
	addi	4, 4, 16
	addi	5, 5, -64
L_AES_XTS_encrypt_crypto_256_blk2:
	cmpdi	5, 32
	blt	L_AES_XTS_encrypt_crypto_256_blk1
	vor	23, 31, 31 /* codespell:ignore vor */
	stxvd2x	55, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	56, 0, 9
	stxvd2x	56, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	63, 0, 9
	lxvd2x	47, 0, 3
	addi	3, 3, 16
	lxvd2x	48, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 23
	vxor	16, 16, 24
	vxor	15, 15, 0
	vxor	16, 16, 0
	vcipher	15, 15, 1
	vcipher	16, 16, 1
	vcipher	15, 15, 2
	vcipher	16, 16, 2
	vcipher	15, 15, 3
	vcipher	16, 16, 3
	vcipher	15, 15, 4
	vcipher	16, 16, 4
	vcipher	15, 15, 5
	vcipher	16, 16, 5
	vcipher	15, 15, 6
	vcipher	16, 16, 6
	vcipher	15, 15, 7
	vcipher	16, 16, 7
	vcipher	15, 15, 8
	vcipher	16, 16, 8
	vcipher	15, 15, 9
	vcipher	16, 16, 9
	vcipher	15, 15, 10
	vcipher	16, 16, 10
	vcipher	15, 15, 11
	vcipher	16, 16, 11
	vcipher	15, 15, 12
	vcipher	16, 16, 12
	vcipher	15, 15, 13
	vcipher	16, 16, 13
	vcipherlast	15, 15, 14
	vcipherlast	16, 16, 14
	vxor	15, 15, 23
	vxor	16, 16, 24
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	addi	5, 5, -32
L_AES_XTS_encrypt_crypto_256_blk1:
	cmpdi	5, 16
	blt	L_AES_XTS_encrypt_crypto_256_done
	vor	23, 31, 31 /* codespell:ignore vor */
	stxvd2x	55, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	63, 0, 9
	lxvd2x	47, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 23
	vxor	15, 15, 0
	vcipher	15, 15, 1
	vcipher	15, 15, 2
	vcipher	15, 15, 3
	vcipher	15, 15, 4
	vcipher	15, 15, 5
	vcipher	15, 15, 6
	vcipher	15, 15, 7
	vcipher	15, 15, 8
	vcipher	15, 15, 9
	vcipher	15, 15, 10
	vcipher	15, 15, 11
	vcipher	15, 15, 12
	vcipher	15, 15, 13
	vcipherlast	15, 15, 14
	vxor	15, 15, 23
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	addi	5, 5, -16
L_AES_XTS_encrypt_crypto_256_done:
	b	L_AES_XTS_encrypt_crypto_alldone
L_AES_XTS_encrypt_crypto_192:
	addi	11, 8, 0
	lxvd2x	32, 0, 11
	addi	11, 11, 16
	lxvd2x	33, 0, 11
	addi	11, 11, 16
	lxvd2x	34, 0, 11
	addi	11, 11, 16
	lxvd2x	35, 0, 11
	addi	11, 11, 16
	lxvd2x	36, 0, 11
	addi	11, 11, 16
	lxvd2x	37, 0, 11
	addi	11, 11, 16
	lxvd2x	38, 0, 11
	addi	11, 11, 16
	lxvd2x	39, 0, 11
	addi	11, 11, 16
	lxvd2x	40, 0, 11
	addi	11, 11, 16
	lxvd2x	41, 0, 11
	addi	11, 11, 16
	lxvd2x	42, 0, 11
	addi	11, 11, 16
	lxvd2x	43, 0, 11
	addi	11, 11, 16
	lxvd2x	44, 0, 11
	addi	11, 11, 16
	vxor	31, 31, 0
	vcipher	31, 31, 1
	vcipher	31, 31, 2
	vcipher	31, 31, 3
	vcipher	31, 31, 4
	vcipher	31, 31, 5
	vcipher	31, 31, 6
	vcipher	31, 31, 7
	vcipher	31, 31, 8
	vcipher	31, 31, 9
	vcipher	31, 31, 10
	vcipher	31, 31, 11
	vcipherlast	31, 31, 12
	addi	11, 7, 0
	lxvd2x	32, 0, 11
	addi	11, 11, 16
	lxvd2x	33, 0, 11
	addi	11, 11, 16
	lxvd2x	34, 0, 11
	addi	11, 11, 16
	lxvd2x	35, 0, 11
	addi	11, 11, 16
	lxvd2x	36, 0, 11
	addi	11, 11, 16
	lxvd2x	37, 0, 11
	addi	11, 11, 16
	lxvd2x	38, 0, 11
	addi	11, 11, 16
	lxvd2x	39, 0, 11
	addi	11, 11, 16
	lxvd2x	40, 0, 11
	addi	11, 11, 16
	lxvd2x	41, 0, 11
	addi	11, 11, 16
	lxvd2x	42, 0, 11
	addi	11, 11, 16
	lxvd2x	43, 0, 11
	addi	11, 11, 16
	lxvd2x	44, 0, 11
	addi	11, 11, 16
	cmpdi	5, 0x80
	blt	L_AES_XTS_encrypt_crypto_192_blk4
L_AES_XTS_encrypt_crypto_192_blk8:
	vor	23, 31, 31 /* codespell:ignore vor */
	stxvd2x	55, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	56, 0, 9
	stxvd2x	56, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	57, 0, 9
	stxvd2x	57, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	58, 0, 9
	stxvd2x	58, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	59, 0, 9
	stxvd2x	59, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	60, 0, 9
	stxvd2x	60, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	61, 0, 9
	stxvd2x	61, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	62, 0, 9
	stxvd2x	62, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	63, 0, 9
	lxvd2x	47, 0, 3
	addi	3, 3, 16
	lxvd2x	48, 0, 3
	addi	3, 3, 16
	lxvd2x	49, 0, 3
	addi	3, 3, 16
	lxvd2x	50, 0, 3
	addi	3, 3, 16
	lxvd2x	51, 0, 3
	addi	3, 3, 16
	lxvd2x	52, 0, 3
	addi	3, 3, 16
	lxvd2x	53, 0, 3
	addi	3, 3, 16
	lxvd2x	54, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 23
	vxor	16, 16, 24
	vxor	17, 17, 25
	vxor	18, 18, 26
	vxor	19, 19, 27
	vxor	20, 20, 28
	vxor	21, 21, 29
	vxor	22, 22, 30
	vxor	15, 15, 0
	vxor	16, 16, 0
	vxor	17, 17, 0
	vxor	18, 18, 0
	vxor	19, 19, 0
	vxor	20, 20, 0
	vxor	21, 21, 0
	vxor	22, 22, 0
	vcipher	15, 15, 1
	vcipher	16, 16, 1
	vcipher	17, 17, 1
	vcipher	18, 18, 1
	vcipher	19, 19, 1
	vcipher	20, 20, 1
	vcipher	21, 21, 1
	vcipher	22, 22, 1
	vcipher	15, 15, 2
	vcipher	16, 16, 2
	vcipher	17, 17, 2
	vcipher	18, 18, 2
	vcipher	19, 19, 2
	vcipher	20, 20, 2
	vcipher	21, 21, 2
	vcipher	22, 22, 2
	vcipher	15, 15, 3
	vcipher	16, 16, 3
	vcipher	17, 17, 3
	vcipher	18, 18, 3
	vcipher	19, 19, 3
	vcipher	20, 20, 3
	vcipher	21, 21, 3
	vcipher	22, 22, 3
	vcipher	15, 15, 4
	vcipher	16, 16, 4
	vcipher	17, 17, 4
	vcipher	18, 18, 4
	vcipher	19, 19, 4
	vcipher	20, 20, 4
	vcipher	21, 21, 4
	vcipher	22, 22, 4
	vcipher	15, 15, 5
	vcipher	16, 16, 5
	vcipher	17, 17, 5
	vcipher	18, 18, 5
	vcipher	19, 19, 5
	vcipher	20, 20, 5
	vcipher	21, 21, 5
	vcipher	22, 22, 5
	vcipher	15, 15, 6
	vcipher	16, 16, 6
	vcipher	17, 17, 6
	vcipher	18, 18, 6
	vcipher	19, 19, 6
	vcipher	20, 20, 6
	vcipher	21, 21, 6
	vcipher	22, 22, 6
	vcipher	15, 15, 7
	vcipher	16, 16, 7
	vcipher	17, 17, 7
	vcipher	18, 18, 7
	vcipher	19, 19, 7
	vcipher	20, 20, 7
	vcipher	21, 21, 7
	vcipher	22, 22, 7
	vcipher	15, 15, 8
	vcipher	16, 16, 8
	vcipher	17, 17, 8
	vcipher	18, 18, 8
	vcipher	19, 19, 8
	vcipher	20, 20, 8
	vcipher	21, 21, 8
	vcipher	22, 22, 8
	vcipher	15, 15, 9
	vcipher	16, 16, 9
	vcipher	17, 17, 9
	vcipher	18, 18, 9
	vcipher	19, 19, 9
	vcipher	20, 20, 9
	vcipher	21, 21, 9
	vcipher	22, 22, 9
	vcipher	15, 15, 10
	vcipher	16, 16, 10
	vcipher	17, 17, 10
	vcipher	18, 18, 10
	vcipher	19, 19, 10
	vcipher	20, 20, 10
	vcipher	21, 21, 10
	vcipher	22, 22, 10
	vcipher	15, 15, 11
	vcipher	16, 16, 11
	vcipher	17, 17, 11
	vcipher	18, 18, 11
	vcipher	19, 19, 11
	vcipher	20, 20, 11
	vcipher	21, 21, 11
	vcipher	22, 22, 11
	vcipherlast	15, 15, 12
	vcipherlast	16, 16, 12
	vcipherlast	17, 17, 12
	vcipherlast	18, 18, 12
	vcipherlast	19, 19, 12
	vcipherlast	20, 20, 12
	vcipherlast	21, 21, 12
	vcipherlast	22, 22, 12
	vxor	15, 15, 23
	vxor	16, 16, 24
	vxor	17, 17, 25
	vxor	18, 18, 26
	vxor	19, 19, 27
	vxor	20, 20, 28
	vxor	21, 21, 29
	vxor	22, 22, 30
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	stxvd2x	49, 0, 4
	addi	4, 4, 16
	stxvd2x	50, 0, 4
	addi	4, 4, 16
	stxvd2x	51, 0, 4
	addi	4, 4, 16
	stxvd2x	52, 0, 4
	addi	4, 4, 16
	stxvd2x	53, 0, 4
	addi	4, 4, 16
	stxvd2x	54, 0, 4
	addi	4, 4, 16
	addi	5, 5, -128
	cmpdi	5, 0x80
	bge	L_AES_XTS_encrypt_crypto_192_blk8
L_AES_XTS_encrypt_crypto_192_blk4:
	cmpdi	5, 0x40
	blt	L_AES_XTS_encrypt_crypto_192_blk2
	vor	23, 31, 31 /* codespell:ignore vor */
	stxvd2x	55, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	56, 0, 9
	stxvd2x	56, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	57, 0, 9
	stxvd2x	57, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	58, 0, 9
	stxvd2x	58, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	63, 0, 9
	lxvd2x	47, 0, 3
	addi	3, 3, 16
	lxvd2x	48, 0, 3
	addi	3, 3, 16
	lxvd2x	49, 0, 3
	addi	3, 3, 16
	lxvd2x	50, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 23
	vxor	16, 16, 24
	vxor	17, 17, 25
	vxor	18, 18, 26
	vxor	15, 15, 0
	vxor	16, 16, 0
	vxor	17, 17, 0
	vxor	18, 18, 0
	vcipher	15, 15, 1
	vcipher	16, 16, 1
	vcipher	17, 17, 1
	vcipher	18, 18, 1
	vcipher	15, 15, 2
	vcipher	16, 16, 2
	vcipher	17, 17, 2
	vcipher	18, 18, 2
	vcipher	15, 15, 3
	vcipher	16, 16, 3
	vcipher	17, 17, 3
	vcipher	18, 18, 3
	vcipher	15, 15, 4
	vcipher	16, 16, 4
	vcipher	17, 17, 4
	vcipher	18, 18, 4
	vcipher	15, 15, 5
	vcipher	16, 16, 5
	vcipher	17, 17, 5
	vcipher	18, 18, 5
	vcipher	15, 15, 6
	vcipher	16, 16, 6
	vcipher	17, 17, 6
	vcipher	18, 18, 6
	vcipher	15, 15, 7
	vcipher	16, 16, 7
	vcipher	17, 17, 7
	vcipher	18, 18, 7
	vcipher	15, 15, 8
	vcipher	16, 16, 8
	vcipher	17, 17, 8
	vcipher	18, 18, 8
	vcipher	15, 15, 9
	vcipher	16, 16, 9
	vcipher	17, 17, 9
	vcipher	18, 18, 9
	vcipher	15, 15, 10
	vcipher	16, 16, 10
	vcipher	17, 17, 10
	vcipher	18, 18, 10
	vcipher	15, 15, 11
	vcipher	16, 16, 11
	vcipher	17, 17, 11
	vcipher	18, 18, 11
	vcipherlast	15, 15, 12
	vcipherlast	16, 16, 12
	vcipherlast	17, 17, 12
	vcipherlast	18, 18, 12
	vxor	15, 15, 23
	vxor	16, 16, 24
	vxor	17, 17, 25
	vxor	18, 18, 26
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	stxvd2x	49, 0, 4
	addi	4, 4, 16
	stxvd2x	50, 0, 4
	addi	4, 4, 16
	addi	5, 5, -64
L_AES_XTS_encrypt_crypto_192_blk2:
	cmpdi	5, 32
	blt	L_AES_XTS_encrypt_crypto_192_blk1
	vor	23, 31, 31 /* codespell:ignore vor */
	stxvd2x	55, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	56, 0, 9
	stxvd2x	56, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	63, 0, 9
	lxvd2x	47, 0, 3
	addi	3, 3, 16
	lxvd2x	48, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 23
	vxor	16, 16, 24
	vxor	15, 15, 0
	vxor	16, 16, 0
	vcipher	15, 15, 1
	vcipher	16, 16, 1
	vcipher	15, 15, 2
	vcipher	16, 16, 2
	vcipher	15, 15, 3
	vcipher	16, 16, 3
	vcipher	15, 15, 4
	vcipher	16, 16, 4
	vcipher	15, 15, 5
	vcipher	16, 16, 5
	vcipher	15, 15, 6
	vcipher	16, 16, 6
	vcipher	15, 15, 7
	vcipher	16, 16, 7
	vcipher	15, 15, 8
	vcipher	16, 16, 8
	vcipher	15, 15, 9
	vcipher	16, 16, 9
	vcipher	15, 15, 10
	vcipher	16, 16, 10
	vcipher	15, 15, 11
	vcipher	16, 16, 11
	vcipherlast	15, 15, 12
	vcipherlast	16, 16, 12
	vxor	15, 15, 23
	vxor	16, 16, 24
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	addi	5, 5, -32
L_AES_XTS_encrypt_crypto_192_blk1:
	cmpdi	5, 16
	blt	L_AES_XTS_encrypt_crypto_192_done
	vor	23, 31, 31 /* codespell:ignore vor */
	stxvd2x	55, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	63, 0, 9
	lxvd2x	47, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 23
	vxor	15, 15, 0
	vcipher	15, 15, 1
	vcipher	15, 15, 2
	vcipher	15, 15, 3
	vcipher	15, 15, 4
	vcipher	15, 15, 5
	vcipher	15, 15, 6
	vcipher	15, 15, 7
	vcipher	15, 15, 8
	vcipher	15, 15, 9
	vcipher	15, 15, 10
	vcipher	15, 15, 11
	vcipherlast	15, 15, 12
	vxor	15, 15, 23
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	addi	5, 5, -16
L_AES_XTS_encrypt_crypto_192_done:
	b	L_AES_XTS_encrypt_crypto_alldone
L_AES_XTS_encrypt_crypto_128:
	addi	11, 8, 0
	lxvd2x	32, 0, 11
	addi	11, 11, 16
	lxvd2x	33, 0, 11
	addi	11, 11, 16
	lxvd2x	34, 0, 11
	addi	11, 11, 16
	lxvd2x	35, 0, 11
	addi	11, 11, 16
	lxvd2x	36, 0, 11
	addi	11, 11, 16
	lxvd2x	37, 0, 11
	addi	11, 11, 16
	lxvd2x	38, 0, 11
	addi	11, 11, 16
	lxvd2x	39, 0, 11
	addi	11, 11, 16
	lxvd2x	40, 0, 11
	addi	11, 11, 16
	lxvd2x	41, 0, 11
	addi	11, 11, 16
	lxvd2x	42, 0, 11
	addi	11, 11, 16
	vxor	31, 31, 0
	vcipher	31, 31, 1
	vcipher	31, 31, 2
	vcipher	31, 31, 3
	vcipher	31, 31, 4
	vcipher	31, 31, 5
	vcipher	31, 31, 6
	vcipher	31, 31, 7
	vcipher	31, 31, 8
	vcipher	31, 31, 9
	vcipherlast	31, 31, 10
	addi	11, 7, 0
	lxvd2x	32, 0, 11
	addi	11, 11, 16
	lxvd2x	33, 0, 11
	addi	11, 11, 16
	lxvd2x	34, 0, 11
	addi	11, 11, 16
	lxvd2x	35, 0, 11
	addi	11, 11, 16
	lxvd2x	36, 0, 11
	addi	11, 11, 16
	lxvd2x	37, 0, 11
	addi	11, 11, 16
	lxvd2x	38, 0, 11
	addi	11, 11, 16
	lxvd2x	39, 0, 11
	addi	11, 11, 16
	lxvd2x	40, 0, 11
	addi	11, 11, 16
	lxvd2x	41, 0, 11
	addi	11, 11, 16
	lxvd2x	42, 0, 11
	addi	11, 11, 16
	cmpdi	5, 0x80
	blt	L_AES_XTS_encrypt_crypto_128_blk4
L_AES_XTS_encrypt_crypto_128_blk8:
	vor	23, 31, 31 /* codespell:ignore vor */
	stxvd2x	55, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	56, 0, 9
	stxvd2x	56, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	57, 0, 9
	stxvd2x	57, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	58, 0, 9
	stxvd2x	58, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	59, 0, 9
	stxvd2x	59, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	60, 0, 9
	stxvd2x	60, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	61, 0, 9
	stxvd2x	61, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	62, 0, 9
	stxvd2x	62, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	63, 0, 9
	lxvd2x	47, 0, 3
	addi	3, 3, 16
	lxvd2x	48, 0, 3
	addi	3, 3, 16
	lxvd2x	49, 0, 3
	addi	3, 3, 16
	lxvd2x	50, 0, 3
	addi	3, 3, 16
	lxvd2x	51, 0, 3
	addi	3, 3, 16
	lxvd2x	52, 0, 3
	addi	3, 3, 16
	lxvd2x	53, 0, 3
	addi	3, 3, 16
	lxvd2x	54, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 23
	vxor	16, 16, 24
	vxor	17, 17, 25
	vxor	18, 18, 26
	vxor	19, 19, 27
	vxor	20, 20, 28
	vxor	21, 21, 29
	vxor	22, 22, 30
	vxor	15, 15, 0
	vxor	16, 16, 0
	vxor	17, 17, 0
	vxor	18, 18, 0
	vxor	19, 19, 0
	vxor	20, 20, 0
	vxor	21, 21, 0
	vxor	22, 22, 0
	vcipher	15, 15, 1
	vcipher	16, 16, 1
	vcipher	17, 17, 1
	vcipher	18, 18, 1
	vcipher	19, 19, 1
	vcipher	20, 20, 1
	vcipher	21, 21, 1
	vcipher	22, 22, 1
	vcipher	15, 15, 2
	vcipher	16, 16, 2
	vcipher	17, 17, 2
	vcipher	18, 18, 2
	vcipher	19, 19, 2
	vcipher	20, 20, 2
	vcipher	21, 21, 2
	vcipher	22, 22, 2
	vcipher	15, 15, 3
	vcipher	16, 16, 3
	vcipher	17, 17, 3
	vcipher	18, 18, 3
	vcipher	19, 19, 3
	vcipher	20, 20, 3
	vcipher	21, 21, 3
	vcipher	22, 22, 3
	vcipher	15, 15, 4
	vcipher	16, 16, 4
	vcipher	17, 17, 4
	vcipher	18, 18, 4
	vcipher	19, 19, 4
	vcipher	20, 20, 4
	vcipher	21, 21, 4
	vcipher	22, 22, 4
	vcipher	15, 15, 5
	vcipher	16, 16, 5
	vcipher	17, 17, 5
	vcipher	18, 18, 5
	vcipher	19, 19, 5
	vcipher	20, 20, 5
	vcipher	21, 21, 5
	vcipher	22, 22, 5
	vcipher	15, 15, 6
	vcipher	16, 16, 6
	vcipher	17, 17, 6
	vcipher	18, 18, 6
	vcipher	19, 19, 6
	vcipher	20, 20, 6
	vcipher	21, 21, 6
	vcipher	22, 22, 6
	vcipher	15, 15, 7
	vcipher	16, 16, 7
	vcipher	17, 17, 7
	vcipher	18, 18, 7
	vcipher	19, 19, 7
	vcipher	20, 20, 7
	vcipher	21, 21, 7
	vcipher	22, 22, 7
	vcipher	15, 15, 8
	vcipher	16, 16, 8
	vcipher	17, 17, 8
	vcipher	18, 18, 8
	vcipher	19, 19, 8
	vcipher	20, 20, 8
	vcipher	21, 21, 8
	vcipher	22, 22, 8
	vcipher	15, 15, 9
	vcipher	16, 16, 9
	vcipher	17, 17, 9
	vcipher	18, 18, 9
	vcipher	19, 19, 9
	vcipher	20, 20, 9
	vcipher	21, 21, 9
	vcipher	22, 22, 9
	vcipherlast	15, 15, 10
	vcipherlast	16, 16, 10
	vcipherlast	17, 17, 10
	vcipherlast	18, 18, 10
	vcipherlast	19, 19, 10
	vcipherlast	20, 20, 10
	vcipherlast	21, 21, 10
	vcipherlast	22, 22, 10
	vxor	15, 15, 23
	vxor	16, 16, 24
	vxor	17, 17, 25
	vxor	18, 18, 26
	vxor	19, 19, 27
	vxor	20, 20, 28
	vxor	21, 21, 29
	vxor	22, 22, 30
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	stxvd2x	49, 0, 4
	addi	4, 4, 16
	stxvd2x	50, 0, 4
	addi	4, 4, 16
	stxvd2x	51, 0, 4
	addi	4, 4, 16
	stxvd2x	52, 0, 4
	addi	4, 4, 16
	stxvd2x	53, 0, 4
	addi	4, 4, 16
	stxvd2x	54, 0, 4
	addi	4, 4, 16
	addi	5, 5, -128
	cmpdi	5, 0x80
	bge	L_AES_XTS_encrypt_crypto_128_blk8
L_AES_XTS_encrypt_crypto_128_blk4:
	cmpdi	5, 0x40
	blt	L_AES_XTS_encrypt_crypto_128_blk2
	vor	23, 31, 31 /* codespell:ignore vor */
	stxvd2x	55, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	56, 0, 9
	stxvd2x	56, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	57, 0, 9
	stxvd2x	57, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	58, 0, 9
	stxvd2x	58, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	63, 0, 9
	lxvd2x	47, 0, 3
	addi	3, 3, 16
	lxvd2x	48, 0, 3
	addi	3, 3, 16
	lxvd2x	49, 0, 3
	addi	3, 3, 16
	lxvd2x	50, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 23
	vxor	16, 16, 24
	vxor	17, 17, 25
	vxor	18, 18, 26
	vxor	15, 15, 0
	vxor	16, 16, 0
	vxor	17, 17, 0
	vxor	18, 18, 0
	vcipher	15, 15, 1
	vcipher	16, 16, 1
	vcipher	17, 17, 1
	vcipher	18, 18, 1
	vcipher	15, 15, 2
	vcipher	16, 16, 2
	vcipher	17, 17, 2
	vcipher	18, 18, 2
	vcipher	15, 15, 3
	vcipher	16, 16, 3
	vcipher	17, 17, 3
	vcipher	18, 18, 3
	vcipher	15, 15, 4
	vcipher	16, 16, 4
	vcipher	17, 17, 4
	vcipher	18, 18, 4
	vcipher	15, 15, 5
	vcipher	16, 16, 5
	vcipher	17, 17, 5
	vcipher	18, 18, 5
	vcipher	15, 15, 6
	vcipher	16, 16, 6
	vcipher	17, 17, 6
	vcipher	18, 18, 6
	vcipher	15, 15, 7
	vcipher	16, 16, 7
	vcipher	17, 17, 7
	vcipher	18, 18, 7
	vcipher	15, 15, 8
	vcipher	16, 16, 8
	vcipher	17, 17, 8
	vcipher	18, 18, 8
	vcipher	15, 15, 9
	vcipher	16, 16, 9
	vcipher	17, 17, 9
	vcipher	18, 18, 9
	vcipherlast	15, 15, 10
	vcipherlast	16, 16, 10
	vcipherlast	17, 17, 10
	vcipherlast	18, 18, 10
	vxor	15, 15, 23
	vxor	16, 16, 24
	vxor	17, 17, 25
	vxor	18, 18, 26
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	stxvd2x	49, 0, 4
	addi	4, 4, 16
	stxvd2x	50, 0, 4
	addi	4, 4, 16
	addi	5, 5, -64
L_AES_XTS_encrypt_crypto_128_blk2:
	cmpdi	5, 32
	blt	L_AES_XTS_encrypt_crypto_128_blk1
	vor	23, 31, 31 /* codespell:ignore vor */
	stxvd2x	55, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	56, 0, 9
	stxvd2x	56, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	63, 0, 9
	lxvd2x	47, 0, 3
	addi	3, 3, 16
	lxvd2x	48, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 23
	vxor	16, 16, 24
	vxor	15, 15, 0
	vxor	16, 16, 0
	vcipher	15, 15, 1
	vcipher	16, 16, 1
	vcipher	15, 15, 2
	vcipher	16, 16, 2
	vcipher	15, 15, 3
	vcipher	16, 16, 3
	vcipher	15, 15, 4
	vcipher	16, 16, 4
	vcipher	15, 15, 5
	vcipher	16, 16, 5
	vcipher	15, 15, 6
	vcipher	16, 16, 6
	vcipher	15, 15, 7
	vcipher	16, 16, 7
	vcipher	15, 15, 8
	vcipher	16, 16, 8
	vcipher	15, 15, 9
	vcipher	16, 16, 9
	vcipherlast	15, 15, 10
	vcipherlast	16, 16, 10
	vxor	15, 15, 23
	vxor	16, 16, 24
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	addi	5, 5, -32
L_AES_XTS_encrypt_crypto_128_blk1:
	cmpdi	5, 16
	blt	L_AES_XTS_encrypt_crypto_128_done
	vor	23, 31, 31 /* codespell:ignore vor */
	stxvd2x	55, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	63, 0, 9
	lxvd2x	47, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 23
	vxor	15, 15, 0
	vcipher	15, 15, 1
	vcipher	15, 15, 2
	vcipher	15, 15, 3
	vcipher	15, 15, 4
	vcipher	15, 15, 5
	vcipher	15, 15, 6
	vcipher	15, 15, 7
	vcipher	15, 15, 8
	vcipher	15, 15, 9
	vcipherlast	15, 15, 10
	vxor	15, 15, 23
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	addi	5, 5, -16
L_AES_XTS_encrypt_crypto_128_done:
L_AES_XTS_encrypt_crypto_alldone:
	ld	0, 32(1)
	mtlr	0
	ld	14, 0(1)
	ld	15, 8(1)
	ld	16, 16(1)
	ld	17, 24(1)
	addi	1, 1, 40
	li	0, 0
	lxvd2x	52, 1, 0
	li	0, 16
	lxvd2x	53, 1, 0
	li	0, 32
	lxvd2x	54, 1, 0
	li	0, 48
	lxvd2x	55, 1, 0
	li	0, 0x40
	lxvd2x	56, 1, 0
	li	0, 0x50
	lxvd2x	57, 1, 0
	li	0, 0x60
	lxvd2x	58, 1, 0
	li	0, 0x70
	lxvd2x	59, 1, 0
	li	0, 0x80
	lxvd2x	60, 1, 0
	li	0, 0x90
	lxvd2x	61, 1, 0
	li	0, 0xa0
	lxvd2x	62, 1, 0
	li	0, 0xb0
	lxvd2x	63, 1, 0
	addi	1, 1, 0xc0
	blr
#ifndef __APPLE__
	.size	AES_XTS_encrypt_crypto,.-AES_XTS_encrypt_crypto
#endif /* __APPLE__ */
	.machine	"pop"
#ifdef HAVE_AES_DECRYPT
	.machine	"push"
	.machine	"power8"
#ifndef __APPLE__
.text
.globl	AES_XTS_decrypt_crypto
.type	AES_XTS_decrypt_crypto,@function
.align	16
AES_XTS_decrypt_crypto:
#if defined(_CALL_ELF) && _CALL_ELF == 2
0:	addis	2, 12, .TOC.-0b@ha
	addi	2, 2, .TOC.-0b@l
	.localentry	AES_XTS_decrypt_crypto, .-AES_XTS_decrypt_crypto
#endif
#else
.section	__TEXT,__text
.globl	_AES_XTS_decrypt_crypto
.p2align	4
_AES_XTS_decrypt_crypto:
#endif /* __APPLE__ */
	subi	1, 1, 0xc0
	li	0, 0
	stxvd2x	52, 1, 0
	li	0, 16
	stxvd2x	53, 1, 0
	li	0, 32
	stxvd2x	54, 1, 0
	li	0, 48
	stxvd2x	55, 1, 0
	li	0, 0x40
	stxvd2x	56, 1, 0
	li	0, 0x50
	stxvd2x	57, 1, 0
	li	0, 0x60
	stxvd2x	58, 1, 0
	li	0, 0x70
	stxvd2x	59, 1, 0
	li	0, 0x80
	stxvd2x	60, 1, 0
	li	0, 0x90
	stxvd2x	61, 1, 0
	li	0, 0xa0
	stxvd2x	62, 1, 0
	li	0, 0xb0
	stxvd2x	63, 1, 0
	stdu	1, -40(1)
	mflr	0
	std	0, 32(1)
	std	14, 0(1)
	std	15, 8(1)
	std	16, 16(1)
	std	17, 24(1)
	li	12, 8
	lxvd2x	63, 0, 6
	cmplwi	10, 10
	beq	L_AES_XTS_decrypt_crypto_128
	cmplwi	10, 12
	beq	L_AES_XTS_decrypt_crypto_192
	addi	11, 8, 0
	lxvd2x	32, 0, 11
	addi	11, 11, 16
	lxvd2x	33, 0, 11
	addi	11, 11, 16
	lxvd2x	34, 0, 11
	addi	11, 11, 16
	lxvd2x	35, 0, 11
	addi	11, 11, 16
	lxvd2x	36, 0, 11
	addi	11, 11, 16
	lxvd2x	37, 0, 11
	addi	11, 11, 16
	lxvd2x	38, 0, 11
	addi	11, 11, 16
	lxvd2x	39, 0, 11
	addi	11, 11, 16
	lxvd2x	40, 0, 11
	addi	11, 11, 16
	lxvd2x	41, 0, 11
	addi	11, 11, 16
	lxvd2x	42, 0, 11
	addi	11, 11, 16
	lxvd2x	43, 0, 11
	addi	11, 11, 16
	lxvd2x	44, 0, 11
	addi	11, 11, 16
	lxvd2x	45, 0, 11
	addi	11, 11, 16
	lxvd2x	46, 0, 11
	addi	11, 11, 16
	vxor	31, 31, 0
	vcipher	31, 31, 1
	vcipher	31, 31, 2
	vcipher	31, 31, 3
	vcipher	31, 31, 4
	vcipher	31, 31, 5
	vcipher	31, 31, 6
	vcipher	31, 31, 7
	vcipher	31, 31, 8
	vcipher	31, 31, 9
	vcipher	31, 31, 10
	vcipher	31, 31, 11
	vcipher	31, 31, 12
	vcipher	31, 31, 13
	vcipherlast	31, 31, 14
	addi	11, 7, 0
	lxvd2x	32, 0, 11
	addi	11, 11, 16
	lxvd2x	33, 0, 11
	addi	11, 11, 16
	lxvd2x	34, 0, 11
	addi	11, 11, 16
	lxvd2x	35, 0, 11
	addi	11, 11, 16
	lxvd2x	36, 0, 11
	addi	11, 11, 16
	lxvd2x	37, 0, 11
	addi	11, 11, 16
	lxvd2x	38, 0, 11
	addi	11, 11, 16
	lxvd2x	39, 0, 11
	addi	11, 11, 16
	lxvd2x	40, 0, 11
	addi	11, 11, 16
	lxvd2x	41, 0, 11
	addi	11, 11, 16
	lxvd2x	42, 0, 11
	addi	11, 11, 16
	lxvd2x	43, 0, 11
	addi	11, 11, 16
	lxvd2x	44, 0, 11
	addi	11, 11, 16
	lxvd2x	45, 0, 11
	addi	11, 11, 16
	lxvd2x	46, 0, 11
	addi	11, 11, 16
	cmpdi	5, 0x80
	blt	L_AES_XTS_decrypt_crypto_256_blk4
L_AES_XTS_decrypt_crypto_256_blk8:
	vor	23, 31, 31 /* codespell:ignore vor */
	stxvd2x	55, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	56, 0, 9
	stxvd2x	56, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	57, 0, 9
	stxvd2x	57, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	58, 0, 9
	stxvd2x	58, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	59, 0, 9
	stxvd2x	59, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	60, 0, 9
	stxvd2x	60, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	61, 0, 9
	stxvd2x	61, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	62, 0, 9
	stxvd2x	62, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	63, 0, 9
	lxvd2x	47, 0, 3
	addi	3, 3, 16
	lxvd2x	48, 0, 3
	addi	3, 3, 16
	lxvd2x	49, 0, 3
	addi	3, 3, 16
	lxvd2x	50, 0, 3
	addi	3, 3, 16
	lxvd2x	51, 0, 3
	addi	3, 3, 16
	lxvd2x	52, 0, 3
	addi	3, 3, 16
	lxvd2x	53, 0, 3
	addi	3, 3, 16
	lxvd2x	54, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 23
	vxor	16, 16, 24
	vxor	17, 17, 25
	vxor	18, 18, 26
	vxor	19, 19, 27
	vxor	20, 20, 28
	vxor	21, 21, 29
	vxor	22, 22, 30
	vxor	15, 15, 0
	vxor	16, 16, 0
	vxor	17, 17, 0
	vxor	18, 18, 0
	vxor	19, 19, 0
	vxor	20, 20, 0
	vxor	21, 21, 0
	vxor	22, 22, 0
	vncipher	15, 15, 1
	vncipher	16, 16, 1
	vncipher	17, 17, 1
	vncipher	18, 18, 1
	vncipher	19, 19, 1
	vncipher	20, 20, 1
	vncipher	21, 21, 1
	vncipher	22, 22, 1
	vncipher	15, 15, 2
	vncipher	16, 16, 2
	vncipher	17, 17, 2
	vncipher	18, 18, 2
	vncipher	19, 19, 2
	vncipher	20, 20, 2
	vncipher	21, 21, 2
	vncipher	22, 22, 2
	vncipher	15, 15, 3
	vncipher	16, 16, 3
	vncipher	17, 17, 3
	vncipher	18, 18, 3
	vncipher	19, 19, 3
	vncipher	20, 20, 3
	vncipher	21, 21, 3
	vncipher	22, 22, 3
	vncipher	15, 15, 4
	vncipher	16, 16, 4
	vncipher	17, 17, 4
	vncipher	18, 18, 4
	vncipher	19, 19, 4
	vncipher	20, 20, 4
	vncipher	21, 21, 4
	vncipher	22, 22, 4
	vncipher	15, 15, 5
	vncipher	16, 16, 5
	vncipher	17, 17, 5
	vncipher	18, 18, 5
	vncipher	19, 19, 5
	vncipher	20, 20, 5
	vncipher	21, 21, 5
	vncipher	22, 22, 5
	vncipher	15, 15, 6
	vncipher	16, 16, 6
	vncipher	17, 17, 6
	vncipher	18, 18, 6
	vncipher	19, 19, 6
	vncipher	20, 20, 6
	vncipher	21, 21, 6
	vncipher	22, 22, 6
	vncipher	15, 15, 7
	vncipher	16, 16, 7
	vncipher	17, 17, 7
	vncipher	18, 18, 7
	vncipher	19, 19, 7
	vncipher	20, 20, 7
	vncipher	21, 21, 7
	vncipher	22, 22, 7
	vncipher	15, 15, 8
	vncipher	16, 16, 8
	vncipher	17, 17, 8
	vncipher	18, 18, 8
	vncipher	19, 19, 8
	vncipher	20, 20, 8
	vncipher	21, 21, 8
	vncipher	22, 22, 8
	vncipher	15, 15, 9
	vncipher	16, 16, 9
	vncipher	17, 17, 9
	vncipher	18, 18, 9
	vncipher	19, 19, 9
	vncipher	20, 20, 9
	vncipher	21, 21, 9
	vncipher	22, 22, 9
	vncipher	15, 15, 10
	vncipher	16, 16, 10
	vncipher	17, 17, 10
	vncipher	18, 18, 10
	vncipher	19, 19, 10
	vncipher	20, 20, 10
	vncipher	21, 21, 10
	vncipher	22, 22, 10
	vncipher	15, 15, 11
	vncipher	16, 16, 11
	vncipher	17, 17, 11
	vncipher	18, 18, 11
	vncipher	19, 19, 11
	vncipher	20, 20, 11
	vncipher	21, 21, 11
	vncipher	22, 22, 11
	vncipher	15, 15, 12
	vncipher	16, 16, 12
	vncipher	17, 17, 12
	vncipher	18, 18, 12
	vncipher	19, 19, 12
	vncipher	20, 20, 12
	vncipher	21, 21, 12
	vncipher	22, 22, 12
	vncipher	15, 15, 13
	vncipher	16, 16, 13
	vncipher	17, 17, 13
	vncipher	18, 18, 13
	vncipher	19, 19, 13
	vncipher	20, 20, 13
	vncipher	21, 21, 13
	vncipher	22, 22, 13
	vncipherlast	15, 15, 14
	vncipherlast	16, 16, 14
	vncipherlast	17, 17, 14
	vncipherlast	18, 18, 14
	vncipherlast	19, 19, 14
	vncipherlast	20, 20, 14
	vncipherlast	21, 21, 14
	vncipherlast	22, 22, 14
	vxor	15, 15, 23
	vxor	16, 16, 24
	vxor	17, 17, 25
	vxor	18, 18, 26
	vxor	19, 19, 27
	vxor	20, 20, 28
	vxor	21, 21, 29
	vxor	22, 22, 30
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	stxvd2x	49, 0, 4
	addi	4, 4, 16
	stxvd2x	50, 0, 4
	addi	4, 4, 16
	stxvd2x	51, 0, 4
	addi	4, 4, 16
	stxvd2x	52, 0, 4
	addi	4, 4, 16
	stxvd2x	53, 0, 4
	addi	4, 4, 16
	stxvd2x	54, 0, 4
	addi	4, 4, 16
	addi	5, 5, -128
	cmpdi	5, 0x80
	bge	L_AES_XTS_decrypt_crypto_256_blk8
L_AES_XTS_decrypt_crypto_256_blk4:
	cmpdi	5, 0x40
	blt	L_AES_XTS_decrypt_crypto_256_blk2
	vor	23, 31, 31 /* codespell:ignore vor */
	stxvd2x	55, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	56, 0, 9
	stxvd2x	56, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	57, 0, 9
	stxvd2x	57, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	58, 0, 9
	stxvd2x	58, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	63, 0, 9
	lxvd2x	47, 0, 3
	addi	3, 3, 16
	lxvd2x	48, 0, 3
	addi	3, 3, 16
	lxvd2x	49, 0, 3
	addi	3, 3, 16
	lxvd2x	50, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 23
	vxor	16, 16, 24
	vxor	17, 17, 25
	vxor	18, 18, 26
	vxor	15, 15, 0
	vxor	16, 16, 0
	vxor	17, 17, 0
	vxor	18, 18, 0
	vncipher	15, 15, 1
	vncipher	16, 16, 1
	vncipher	17, 17, 1
	vncipher	18, 18, 1
	vncipher	15, 15, 2
	vncipher	16, 16, 2
	vncipher	17, 17, 2
	vncipher	18, 18, 2
	vncipher	15, 15, 3
	vncipher	16, 16, 3
	vncipher	17, 17, 3
	vncipher	18, 18, 3
	vncipher	15, 15, 4
	vncipher	16, 16, 4
	vncipher	17, 17, 4
	vncipher	18, 18, 4
	vncipher	15, 15, 5
	vncipher	16, 16, 5
	vncipher	17, 17, 5
	vncipher	18, 18, 5
	vncipher	15, 15, 6
	vncipher	16, 16, 6
	vncipher	17, 17, 6
	vncipher	18, 18, 6
	vncipher	15, 15, 7
	vncipher	16, 16, 7
	vncipher	17, 17, 7
	vncipher	18, 18, 7
	vncipher	15, 15, 8
	vncipher	16, 16, 8
	vncipher	17, 17, 8
	vncipher	18, 18, 8
	vncipher	15, 15, 9
	vncipher	16, 16, 9
	vncipher	17, 17, 9
	vncipher	18, 18, 9
	vncipher	15, 15, 10
	vncipher	16, 16, 10
	vncipher	17, 17, 10
	vncipher	18, 18, 10
	vncipher	15, 15, 11
	vncipher	16, 16, 11
	vncipher	17, 17, 11
	vncipher	18, 18, 11
	vncipher	15, 15, 12
	vncipher	16, 16, 12
	vncipher	17, 17, 12
	vncipher	18, 18, 12
	vncipher	15, 15, 13
	vncipher	16, 16, 13
	vncipher	17, 17, 13
	vncipher	18, 18, 13
	vncipherlast	15, 15, 14
	vncipherlast	16, 16, 14
	vncipherlast	17, 17, 14
	vncipherlast	18, 18, 14
	vxor	15, 15, 23
	vxor	16, 16, 24
	vxor	17, 17, 25
	vxor	18, 18, 26
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	stxvd2x	49, 0, 4
	addi	4, 4, 16
	stxvd2x	50, 0, 4
	addi	4, 4, 16
	addi	5, 5, -64
L_AES_XTS_decrypt_crypto_256_blk2:
	cmpdi	5, 32
	blt	L_AES_XTS_decrypt_crypto_256_blk1
	vor	23, 31, 31 /* codespell:ignore vor */
	stxvd2x	55, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	56, 0, 9
	stxvd2x	56, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	63, 0, 9
	lxvd2x	47, 0, 3
	addi	3, 3, 16
	lxvd2x	48, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 23
	vxor	16, 16, 24
	vxor	15, 15, 0
	vxor	16, 16, 0
	vncipher	15, 15, 1
	vncipher	16, 16, 1
	vncipher	15, 15, 2
	vncipher	16, 16, 2
	vncipher	15, 15, 3
	vncipher	16, 16, 3
	vncipher	15, 15, 4
	vncipher	16, 16, 4
	vncipher	15, 15, 5
	vncipher	16, 16, 5
	vncipher	15, 15, 6
	vncipher	16, 16, 6
	vncipher	15, 15, 7
	vncipher	16, 16, 7
	vncipher	15, 15, 8
	vncipher	16, 16, 8
	vncipher	15, 15, 9
	vncipher	16, 16, 9
	vncipher	15, 15, 10
	vncipher	16, 16, 10
	vncipher	15, 15, 11
	vncipher	16, 16, 11
	vncipher	15, 15, 12
	vncipher	16, 16, 12
	vncipher	15, 15, 13
	vncipher	16, 16, 13
	vncipherlast	15, 15, 14
	vncipherlast	16, 16, 14
	vxor	15, 15, 23
	vxor	16, 16, 24
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	addi	5, 5, -32
L_AES_XTS_decrypt_crypto_256_blk1:
	cmpdi	5, 16
	blt	L_AES_XTS_decrypt_crypto_256_done
	vor	23, 31, 31 /* codespell:ignore vor */
	stxvd2x	55, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	63, 0, 9
	lxvd2x	47, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 23
	vxor	15, 15, 0
	vncipher	15, 15, 1
	vncipher	15, 15, 2
	vncipher	15, 15, 3
	vncipher	15, 15, 4
	vncipher	15, 15, 5
	vncipher	15, 15, 6
	vncipher	15, 15, 7
	vncipher	15, 15, 8
	vncipher	15, 15, 9
	vncipher	15, 15, 10
	vncipher	15, 15, 11
	vncipher	15, 15, 12
	vncipher	15, 15, 13
	vncipherlast	15, 15, 14
	vxor	15, 15, 23
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	addi	5, 5, -16
L_AES_XTS_decrypt_crypto_256_done:
	b	L_AES_XTS_decrypt_crypto_alldone
L_AES_XTS_decrypt_crypto_192:
	addi	11, 8, 0
	lxvd2x	32, 0, 11
	addi	11, 11, 16
	lxvd2x	33, 0, 11
	addi	11, 11, 16
	lxvd2x	34, 0, 11
	addi	11, 11, 16
	lxvd2x	35, 0, 11
	addi	11, 11, 16
	lxvd2x	36, 0, 11
	addi	11, 11, 16
	lxvd2x	37, 0, 11
	addi	11, 11, 16
	lxvd2x	38, 0, 11
	addi	11, 11, 16
	lxvd2x	39, 0, 11
	addi	11, 11, 16
	lxvd2x	40, 0, 11
	addi	11, 11, 16
	lxvd2x	41, 0, 11
	addi	11, 11, 16
	lxvd2x	42, 0, 11
	addi	11, 11, 16
	lxvd2x	43, 0, 11
	addi	11, 11, 16
	lxvd2x	44, 0, 11
	addi	11, 11, 16
	vxor	31, 31, 0
	vcipher	31, 31, 1
	vcipher	31, 31, 2
	vcipher	31, 31, 3
	vcipher	31, 31, 4
	vcipher	31, 31, 5
	vcipher	31, 31, 6
	vcipher	31, 31, 7
	vcipher	31, 31, 8
	vcipher	31, 31, 9
	vcipher	31, 31, 10
	vcipher	31, 31, 11
	vcipherlast	31, 31, 12
	addi	11, 7, 0
	lxvd2x	32, 0, 11
	addi	11, 11, 16
	lxvd2x	33, 0, 11
	addi	11, 11, 16
	lxvd2x	34, 0, 11
	addi	11, 11, 16
	lxvd2x	35, 0, 11
	addi	11, 11, 16
	lxvd2x	36, 0, 11
	addi	11, 11, 16
	lxvd2x	37, 0, 11
	addi	11, 11, 16
	lxvd2x	38, 0, 11
	addi	11, 11, 16
	lxvd2x	39, 0, 11
	addi	11, 11, 16
	lxvd2x	40, 0, 11
	addi	11, 11, 16
	lxvd2x	41, 0, 11
	addi	11, 11, 16
	lxvd2x	42, 0, 11
	addi	11, 11, 16
	lxvd2x	43, 0, 11
	addi	11, 11, 16
	lxvd2x	44, 0, 11
	addi	11, 11, 16
	cmpdi	5, 0x80
	blt	L_AES_XTS_decrypt_crypto_192_blk4
L_AES_XTS_decrypt_crypto_192_blk8:
	vor	23, 31, 31 /* codespell:ignore vor */
	stxvd2x	55, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	56, 0, 9
	stxvd2x	56, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	57, 0, 9
	stxvd2x	57, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	58, 0, 9
	stxvd2x	58, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	59, 0, 9
	stxvd2x	59, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	60, 0, 9
	stxvd2x	60, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	61, 0, 9
	stxvd2x	61, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	62, 0, 9
	stxvd2x	62, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	63, 0, 9
	lxvd2x	47, 0, 3
	addi	3, 3, 16
	lxvd2x	48, 0, 3
	addi	3, 3, 16
	lxvd2x	49, 0, 3
	addi	3, 3, 16
	lxvd2x	50, 0, 3
	addi	3, 3, 16
	lxvd2x	51, 0, 3
	addi	3, 3, 16
	lxvd2x	52, 0, 3
	addi	3, 3, 16
	lxvd2x	53, 0, 3
	addi	3, 3, 16
	lxvd2x	54, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 23
	vxor	16, 16, 24
	vxor	17, 17, 25
	vxor	18, 18, 26
	vxor	19, 19, 27
	vxor	20, 20, 28
	vxor	21, 21, 29
	vxor	22, 22, 30
	vxor	15, 15, 0
	vxor	16, 16, 0
	vxor	17, 17, 0
	vxor	18, 18, 0
	vxor	19, 19, 0
	vxor	20, 20, 0
	vxor	21, 21, 0
	vxor	22, 22, 0
	vncipher	15, 15, 1
	vncipher	16, 16, 1
	vncipher	17, 17, 1
	vncipher	18, 18, 1
	vncipher	19, 19, 1
	vncipher	20, 20, 1
	vncipher	21, 21, 1
	vncipher	22, 22, 1
	vncipher	15, 15, 2
	vncipher	16, 16, 2
	vncipher	17, 17, 2
	vncipher	18, 18, 2
	vncipher	19, 19, 2
	vncipher	20, 20, 2
	vncipher	21, 21, 2
	vncipher	22, 22, 2
	vncipher	15, 15, 3
	vncipher	16, 16, 3
	vncipher	17, 17, 3
	vncipher	18, 18, 3
	vncipher	19, 19, 3
	vncipher	20, 20, 3
	vncipher	21, 21, 3
	vncipher	22, 22, 3
	vncipher	15, 15, 4
	vncipher	16, 16, 4
	vncipher	17, 17, 4
	vncipher	18, 18, 4
	vncipher	19, 19, 4
	vncipher	20, 20, 4
	vncipher	21, 21, 4
	vncipher	22, 22, 4
	vncipher	15, 15, 5
	vncipher	16, 16, 5
	vncipher	17, 17, 5
	vncipher	18, 18, 5
	vncipher	19, 19, 5
	vncipher	20, 20, 5
	vncipher	21, 21, 5
	vncipher	22, 22, 5
	vncipher	15, 15, 6
	vncipher	16, 16, 6
	vncipher	17, 17, 6
	vncipher	18, 18, 6
	vncipher	19, 19, 6
	vncipher	20, 20, 6
	vncipher	21, 21, 6
	vncipher	22, 22, 6
	vncipher	15, 15, 7
	vncipher	16, 16, 7
	vncipher	17, 17, 7
	vncipher	18, 18, 7
	vncipher	19, 19, 7
	vncipher	20, 20, 7
	vncipher	21, 21, 7
	vncipher	22, 22, 7
	vncipher	15, 15, 8
	vncipher	16, 16, 8
	vncipher	17, 17, 8
	vncipher	18, 18, 8
	vncipher	19, 19, 8
	vncipher	20, 20, 8
	vncipher	21, 21, 8
	vncipher	22, 22, 8
	vncipher	15, 15, 9
	vncipher	16, 16, 9
	vncipher	17, 17, 9
	vncipher	18, 18, 9
	vncipher	19, 19, 9
	vncipher	20, 20, 9
	vncipher	21, 21, 9
	vncipher	22, 22, 9
	vncipher	15, 15, 10
	vncipher	16, 16, 10
	vncipher	17, 17, 10
	vncipher	18, 18, 10
	vncipher	19, 19, 10
	vncipher	20, 20, 10
	vncipher	21, 21, 10
	vncipher	22, 22, 10
	vncipher	15, 15, 11
	vncipher	16, 16, 11
	vncipher	17, 17, 11
	vncipher	18, 18, 11
	vncipher	19, 19, 11
	vncipher	20, 20, 11
	vncipher	21, 21, 11
	vncipher	22, 22, 11
	vncipherlast	15, 15, 12
	vncipherlast	16, 16, 12
	vncipherlast	17, 17, 12
	vncipherlast	18, 18, 12
	vncipherlast	19, 19, 12
	vncipherlast	20, 20, 12
	vncipherlast	21, 21, 12
	vncipherlast	22, 22, 12
	vxor	15, 15, 23
	vxor	16, 16, 24
	vxor	17, 17, 25
	vxor	18, 18, 26
	vxor	19, 19, 27
	vxor	20, 20, 28
	vxor	21, 21, 29
	vxor	22, 22, 30
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	stxvd2x	49, 0, 4
	addi	4, 4, 16
	stxvd2x	50, 0, 4
	addi	4, 4, 16
	stxvd2x	51, 0, 4
	addi	4, 4, 16
	stxvd2x	52, 0, 4
	addi	4, 4, 16
	stxvd2x	53, 0, 4
	addi	4, 4, 16
	stxvd2x	54, 0, 4
	addi	4, 4, 16
	addi	5, 5, -128
	cmpdi	5, 0x80
	bge	L_AES_XTS_decrypt_crypto_192_blk8
L_AES_XTS_decrypt_crypto_192_blk4:
	cmpdi	5, 0x40
	blt	L_AES_XTS_decrypt_crypto_192_blk2
	vor	23, 31, 31 /* codespell:ignore vor */
	stxvd2x	55, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	56, 0, 9
	stxvd2x	56, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	57, 0, 9
	stxvd2x	57, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	58, 0, 9
	stxvd2x	58, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	63, 0, 9
	lxvd2x	47, 0, 3
	addi	3, 3, 16
	lxvd2x	48, 0, 3
	addi	3, 3, 16
	lxvd2x	49, 0, 3
	addi	3, 3, 16
	lxvd2x	50, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 23
	vxor	16, 16, 24
	vxor	17, 17, 25
	vxor	18, 18, 26
	vxor	15, 15, 0
	vxor	16, 16, 0
	vxor	17, 17, 0
	vxor	18, 18, 0
	vncipher	15, 15, 1
	vncipher	16, 16, 1
	vncipher	17, 17, 1
	vncipher	18, 18, 1
	vncipher	15, 15, 2
	vncipher	16, 16, 2
	vncipher	17, 17, 2
	vncipher	18, 18, 2
	vncipher	15, 15, 3
	vncipher	16, 16, 3
	vncipher	17, 17, 3
	vncipher	18, 18, 3
	vncipher	15, 15, 4
	vncipher	16, 16, 4
	vncipher	17, 17, 4
	vncipher	18, 18, 4
	vncipher	15, 15, 5
	vncipher	16, 16, 5
	vncipher	17, 17, 5
	vncipher	18, 18, 5
	vncipher	15, 15, 6
	vncipher	16, 16, 6
	vncipher	17, 17, 6
	vncipher	18, 18, 6
	vncipher	15, 15, 7
	vncipher	16, 16, 7
	vncipher	17, 17, 7
	vncipher	18, 18, 7
	vncipher	15, 15, 8
	vncipher	16, 16, 8
	vncipher	17, 17, 8
	vncipher	18, 18, 8
	vncipher	15, 15, 9
	vncipher	16, 16, 9
	vncipher	17, 17, 9
	vncipher	18, 18, 9
	vncipher	15, 15, 10
	vncipher	16, 16, 10
	vncipher	17, 17, 10
	vncipher	18, 18, 10
	vncipher	15, 15, 11
	vncipher	16, 16, 11
	vncipher	17, 17, 11
	vncipher	18, 18, 11
	vncipherlast	15, 15, 12
	vncipherlast	16, 16, 12
	vncipherlast	17, 17, 12
	vncipherlast	18, 18, 12
	vxor	15, 15, 23
	vxor	16, 16, 24
	vxor	17, 17, 25
	vxor	18, 18, 26
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	stxvd2x	49, 0, 4
	addi	4, 4, 16
	stxvd2x	50, 0, 4
	addi	4, 4, 16
	addi	5, 5, -64
L_AES_XTS_decrypt_crypto_192_blk2:
	cmpdi	5, 32
	blt	L_AES_XTS_decrypt_crypto_192_blk1
	vor	23, 31, 31 /* codespell:ignore vor */
	stxvd2x	55, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	56, 0, 9
	stxvd2x	56, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	63, 0, 9
	lxvd2x	47, 0, 3
	addi	3, 3, 16
	lxvd2x	48, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 23
	vxor	16, 16, 24
	vxor	15, 15, 0
	vxor	16, 16, 0
	vncipher	15, 15, 1
	vncipher	16, 16, 1
	vncipher	15, 15, 2
	vncipher	16, 16, 2
	vncipher	15, 15, 3
	vncipher	16, 16, 3
	vncipher	15, 15, 4
	vncipher	16, 16, 4
	vncipher	15, 15, 5
	vncipher	16, 16, 5
	vncipher	15, 15, 6
	vncipher	16, 16, 6
	vncipher	15, 15, 7
	vncipher	16, 16, 7
	vncipher	15, 15, 8
	vncipher	16, 16, 8
	vncipher	15, 15, 9
	vncipher	16, 16, 9
	vncipher	15, 15, 10
	vncipher	16, 16, 10
	vncipher	15, 15, 11
	vncipher	16, 16, 11
	vncipherlast	15, 15, 12
	vncipherlast	16, 16, 12
	vxor	15, 15, 23
	vxor	16, 16, 24
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	addi	5, 5, -32
L_AES_XTS_decrypt_crypto_192_blk1:
	cmpdi	5, 16
	blt	L_AES_XTS_decrypt_crypto_192_done
	vor	23, 31, 31 /* codespell:ignore vor */
	stxvd2x	55, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	63, 0, 9
	lxvd2x	47, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 23
	vxor	15, 15, 0
	vncipher	15, 15, 1
	vncipher	15, 15, 2
	vncipher	15, 15, 3
	vncipher	15, 15, 4
	vncipher	15, 15, 5
	vncipher	15, 15, 6
	vncipher	15, 15, 7
	vncipher	15, 15, 8
	vncipher	15, 15, 9
	vncipher	15, 15, 10
	vncipher	15, 15, 11
	vncipherlast	15, 15, 12
	vxor	15, 15, 23
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	addi	5, 5, -16
L_AES_XTS_decrypt_crypto_192_done:
	b	L_AES_XTS_decrypt_crypto_alldone
L_AES_XTS_decrypt_crypto_128:
	addi	11, 8, 0
	lxvd2x	32, 0, 11
	addi	11, 11, 16
	lxvd2x	33, 0, 11
	addi	11, 11, 16
	lxvd2x	34, 0, 11
	addi	11, 11, 16
	lxvd2x	35, 0, 11
	addi	11, 11, 16
	lxvd2x	36, 0, 11
	addi	11, 11, 16
	lxvd2x	37, 0, 11
	addi	11, 11, 16
	lxvd2x	38, 0, 11
	addi	11, 11, 16
	lxvd2x	39, 0, 11
	addi	11, 11, 16
	lxvd2x	40, 0, 11
	addi	11, 11, 16
	lxvd2x	41, 0, 11
	addi	11, 11, 16
	lxvd2x	42, 0, 11
	addi	11, 11, 16
	vxor	31, 31, 0
	vcipher	31, 31, 1
	vcipher	31, 31, 2
	vcipher	31, 31, 3
	vcipher	31, 31, 4
	vcipher	31, 31, 5
	vcipher	31, 31, 6
	vcipher	31, 31, 7
	vcipher	31, 31, 8
	vcipher	31, 31, 9
	vcipherlast	31, 31, 10
	addi	11, 7, 0
	lxvd2x	32, 0, 11
	addi	11, 11, 16
	lxvd2x	33, 0, 11
	addi	11, 11, 16
	lxvd2x	34, 0, 11
	addi	11, 11, 16
	lxvd2x	35, 0, 11
	addi	11, 11, 16
	lxvd2x	36, 0, 11
	addi	11, 11, 16
	lxvd2x	37, 0, 11
	addi	11, 11, 16
	lxvd2x	38, 0, 11
	addi	11, 11, 16
	lxvd2x	39, 0, 11
	addi	11, 11, 16
	lxvd2x	40, 0, 11
	addi	11, 11, 16
	lxvd2x	41, 0, 11
	addi	11, 11, 16
	lxvd2x	42, 0, 11
	addi	11, 11, 16
	cmpdi	5, 0x80
	blt	L_AES_XTS_decrypt_crypto_128_blk4
L_AES_XTS_decrypt_crypto_128_blk8:
	vor	23, 31, 31 /* codespell:ignore vor */
	stxvd2x	55, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	56, 0, 9
	stxvd2x	56, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	57, 0, 9
	stxvd2x	57, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	58, 0, 9
	stxvd2x	58, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	59, 0, 9
	stxvd2x	59, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	60, 0, 9
	stxvd2x	60, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	61, 0, 9
	stxvd2x	61, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	62, 0, 9
	stxvd2x	62, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	63, 0, 9
	lxvd2x	47, 0, 3
	addi	3, 3, 16
	lxvd2x	48, 0, 3
	addi	3, 3, 16
	lxvd2x	49, 0, 3
	addi	3, 3, 16
	lxvd2x	50, 0, 3
	addi	3, 3, 16
	lxvd2x	51, 0, 3
	addi	3, 3, 16
	lxvd2x	52, 0, 3
	addi	3, 3, 16
	lxvd2x	53, 0, 3
	addi	3, 3, 16
	lxvd2x	54, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 23
	vxor	16, 16, 24
	vxor	17, 17, 25
	vxor	18, 18, 26
	vxor	19, 19, 27
	vxor	20, 20, 28
	vxor	21, 21, 29
	vxor	22, 22, 30
	vxor	15, 15, 0
	vxor	16, 16, 0
	vxor	17, 17, 0
	vxor	18, 18, 0
	vxor	19, 19, 0
	vxor	20, 20, 0
	vxor	21, 21, 0
	vxor	22, 22, 0
	vncipher	15, 15, 1
	vncipher	16, 16, 1
	vncipher	17, 17, 1
	vncipher	18, 18, 1
	vncipher	19, 19, 1
	vncipher	20, 20, 1
	vncipher	21, 21, 1
	vncipher	22, 22, 1
	vncipher	15, 15, 2
	vncipher	16, 16, 2
	vncipher	17, 17, 2
	vncipher	18, 18, 2
	vncipher	19, 19, 2
	vncipher	20, 20, 2
	vncipher	21, 21, 2
	vncipher	22, 22, 2
	vncipher	15, 15, 3
	vncipher	16, 16, 3
	vncipher	17, 17, 3
	vncipher	18, 18, 3
	vncipher	19, 19, 3
	vncipher	20, 20, 3
	vncipher	21, 21, 3
	vncipher	22, 22, 3
	vncipher	15, 15, 4
	vncipher	16, 16, 4
	vncipher	17, 17, 4
	vncipher	18, 18, 4
	vncipher	19, 19, 4
	vncipher	20, 20, 4
	vncipher	21, 21, 4
	vncipher	22, 22, 4
	vncipher	15, 15, 5
	vncipher	16, 16, 5
	vncipher	17, 17, 5
	vncipher	18, 18, 5
	vncipher	19, 19, 5
	vncipher	20, 20, 5
	vncipher	21, 21, 5
	vncipher	22, 22, 5
	vncipher	15, 15, 6
	vncipher	16, 16, 6
	vncipher	17, 17, 6
	vncipher	18, 18, 6
	vncipher	19, 19, 6
	vncipher	20, 20, 6
	vncipher	21, 21, 6
	vncipher	22, 22, 6
	vncipher	15, 15, 7
	vncipher	16, 16, 7
	vncipher	17, 17, 7
	vncipher	18, 18, 7
	vncipher	19, 19, 7
	vncipher	20, 20, 7
	vncipher	21, 21, 7
	vncipher	22, 22, 7
	vncipher	15, 15, 8
	vncipher	16, 16, 8
	vncipher	17, 17, 8
	vncipher	18, 18, 8
	vncipher	19, 19, 8
	vncipher	20, 20, 8
	vncipher	21, 21, 8
	vncipher	22, 22, 8
	vncipher	15, 15, 9
	vncipher	16, 16, 9
	vncipher	17, 17, 9
	vncipher	18, 18, 9
	vncipher	19, 19, 9
	vncipher	20, 20, 9
	vncipher	21, 21, 9
	vncipher	22, 22, 9
	vncipherlast	15, 15, 10
	vncipherlast	16, 16, 10
	vncipherlast	17, 17, 10
	vncipherlast	18, 18, 10
	vncipherlast	19, 19, 10
	vncipherlast	20, 20, 10
	vncipherlast	21, 21, 10
	vncipherlast	22, 22, 10
	vxor	15, 15, 23
	vxor	16, 16, 24
	vxor	17, 17, 25
	vxor	18, 18, 26
	vxor	19, 19, 27
	vxor	20, 20, 28
	vxor	21, 21, 29
	vxor	22, 22, 30
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	stxvd2x	49, 0, 4
	addi	4, 4, 16
	stxvd2x	50, 0, 4
	addi	4, 4, 16
	stxvd2x	51, 0, 4
	addi	4, 4, 16
	stxvd2x	52, 0, 4
	addi	4, 4, 16
	stxvd2x	53, 0, 4
	addi	4, 4, 16
	stxvd2x	54, 0, 4
	addi	4, 4, 16
	addi	5, 5, -128
	cmpdi	5, 0x80
	bge	L_AES_XTS_decrypt_crypto_128_blk8
L_AES_XTS_decrypt_crypto_128_blk4:
	cmpdi	5, 0x40
	blt	L_AES_XTS_decrypt_crypto_128_blk2
	vor	23, 31, 31 /* codespell:ignore vor */
	stxvd2x	55, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	56, 0, 9
	stxvd2x	56, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	57, 0, 9
	stxvd2x	57, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	58, 0, 9
	stxvd2x	58, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	63, 0, 9
	lxvd2x	47, 0, 3
	addi	3, 3, 16
	lxvd2x	48, 0, 3
	addi	3, 3, 16
	lxvd2x	49, 0, 3
	addi	3, 3, 16
	lxvd2x	50, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 23
	vxor	16, 16, 24
	vxor	17, 17, 25
	vxor	18, 18, 26
	vxor	15, 15, 0
	vxor	16, 16, 0
	vxor	17, 17, 0
	vxor	18, 18, 0
	vncipher	15, 15, 1
	vncipher	16, 16, 1
	vncipher	17, 17, 1
	vncipher	18, 18, 1
	vncipher	15, 15, 2
	vncipher	16, 16, 2
	vncipher	17, 17, 2
	vncipher	18, 18, 2
	vncipher	15, 15, 3
	vncipher	16, 16, 3
	vncipher	17, 17, 3
	vncipher	18, 18, 3
	vncipher	15, 15, 4
	vncipher	16, 16, 4
	vncipher	17, 17, 4
	vncipher	18, 18, 4
	vncipher	15, 15, 5
	vncipher	16, 16, 5
	vncipher	17, 17, 5
	vncipher	18, 18, 5
	vncipher	15, 15, 6
	vncipher	16, 16, 6
	vncipher	17, 17, 6
	vncipher	18, 18, 6
	vncipher	15, 15, 7
	vncipher	16, 16, 7
	vncipher	17, 17, 7
	vncipher	18, 18, 7
	vncipher	15, 15, 8
	vncipher	16, 16, 8
	vncipher	17, 17, 8
	vncipher	18, 18, 8
	vncipher	15, 15, 9
	vncipher	16, 16, 9
	vncipher	17, 17, 9
	vncipher	18, 18, 9
	vncipherlast	15, 15, 10
	vncipherlast	16, 16, 10
	vncipherlast	17, 17, 10
	vncipherlast	18, 18, 10
	vxor	15, 15, 23
	vxor	16, 16, 24
	vxor	17, 17, 25
	vxor	18, 18, 26
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	stxvd2x	49, 0, 4
	addi	4, 4, 16
	stxvd2x	50, 0, 4
	addi	4, 4, 16
	addi	5, 5, -64
L_AES_XTS_decrypt_crypto_128_blk2:
	cmpdi	5, 32
	blt	L_AES_XTS_decrypt_crypto_128_blk1
	vor	23, 31, 31 /* codespell:ignore vor */
	stxvd2x	55, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	56, 0, 9
	stxvd2x	56, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	63, 0, 9
	lxvd2x	47, 0, 3
	addi	3, 3, 16
	lxvd2x	48, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 23
	vxor	16, 16, 24
	vxor	15, 15, 0
	vxor	16, 16, 0
	vncipher	15, 15, 1
	vncipher	16, 16, 1
	vncipher	15, 15, 2
	vncipher	16, 16, 2
	vncipher	15, 15, 3
	vncipher	16, 16, 3
	vncipher	15, 15, 4
	vncipher	16, 16, 4
	vncipher	15, 15, 5
	vncipher	16, 16, 5
	vncipher	15, 15, 6
	vncipher	16, 16, 6
	vncipher	15, 15, 7
	vncipher	16, 16, 7
	vncipher	15, 15, 8
	vncipher	16, 16, 8
	vncipher	15, 15, 9
	vncipher	16, 16, 9
	vncipherlast	15, 15, 10
	vncipherlast	16, 16, 10
	vxor	15, 15, 23
	vxor	16, 16, 24
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	stxvd2x	48, 0, 4
	addi	4, 4, 16
	addi	5, 5, -32
L_AES_XTS_decrypt_crypto_128_blk1:
	cmpdi	5, 16
	blt	L_AES_XTS_decrypt_crypto_128_done
	vor	23, 31, 31 /* codespell:ignore vor */
	stxvd2x	55, 0, 9
	ldbrx	14, 0, 9
	ldbrx	15, 9, 12
	sradi	16, 15, 63
	srdi	17, 14, 63
	andi.	16, 16, 0x87
	sldi	15, 15, 1
	sldi	14, 14, 1
	xor	15, 15, 17
	xor	14, 14, 16
	stdbrx	14, 0, 9
	stdbrx	15, 9, 12
	lxvd2x	63, 0, 9
	lxvd2x	47, 0, 3
	addi	3, 3, 16
	vxor	15, 15, 23
	vxor	15, 15, 0
	vncipher	15, 15, 1
	vncipher	15, 15, 2
	vncipher	15, 15, 3
	vncipher	15, 15, 4
	vncipher	15, 15, 5
	vncipher	15, 15, 6
	vncipher	15, 15, 7
	vncipher	15, 15, 8
	vncipher	15, 15, 9
	vncipherlast	15, 15, 10
	vxor	15, 15, 23
	stxvd2x	47, 0, 4
	addi	4, 4, 16
	addi	5, 5, -16
L_AES_XTS_decrypt_crypto_128_done:
L_AES_XTS_decrypt_crypto_alldone:
	ld	0, 32(1)
	mtlr	0
	ld	14, 0(1)
	ld	15, 8(1)
	ld	16, 16(1)
	ld	17, 24(1)
	addi	1, 1, 40
	li	0, 0
	lxvd2x	52, 1, 0
	li	0, 16
	lxvd2x	53, 1, 0
	li	0, 32
	lxvd2x	54, 1, 0
	li	0, 48
	lxvd2x	55, 1, 0
	li	0, 0x40
	lxvd2x	56, 1, 0
	li	0, 0x50
	lxvd2x	57, 1, 0
	li	0, 0x60
	lxvd2x	58, 1, 0
	li	0, 0x70
	lxvd2x	59, 1, 0
	li	0, 0x80
	lxvd2x	60, 1, 0
	li	0, 0x90
	lxvd2x	61, 1, 0
	li	0, 0xa0
	lxvd2x	62, 1, 0
	li	0, 0xb0
	lxvd2x	63, 1, 0
	addi	1, 1, 0xc0
	blr
#ifndef __APPLE__
	.size	AES_XTS_decrypt_crypto,.-AES_XTS_decrypt_crypto
#endif /* __APPLE__ */
	.machine	"pop"
#endif /* HAVE_AES_DECRYPT */
#endif /* WOLFSSL_AES_XTS */
#endif /* WOLFSSL_PPC64_ASM_CRYPTO */
#endif /* !defined(NO_AES) && defined(WOLFSSL_PPC64_ASM) */
#endif /* WOLFSSL_PPC64_ASM */

#if defined(__linux__) && defined(__ELF__)
.section	.note.GNU-stack,"",%progbits
#endif
#endif /* !WOLFSSL_PPC64_ASM_INLINE */
