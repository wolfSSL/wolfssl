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
	.section	".text"
	.section	.rodata
	.type	L_AES_PPC64_td, @object
	.size	L_AES_PPC64_td, 1024
	.align	4
L_AES_PPC64_td:
	.long	0x5051f4a7
	.long	0x537e4165
	.long	0xc31a17a4
	.long	0x963a275e
	.long	0xcb3bab6b
	.long	0xf11f9d45
	.long	0xabacfa58
	.long	0x934be303
	.long	0x552030fa
	.long	0xf6ad766d
	.long	0x9188cc76
	.long	0x25f5024c
	.long	0xfc4fe5d7
	.long	0xd7c52acb
	.long	0x80263544
	.long	0x8fb562a3
	.long	0x49deb15a
	.long	0x6725ba1b
	.long	0x9845ea0e
	.long	0xe15dfec0
	.long	0x2c32f75
	.long	0x12814cf0
	.long	0xa38d4697
	.long	0xc66bd3f9
	.long	0xe7038f5f
	.long	0x9515929c
	.long	0xebbf6d7a
	.long	0xda955259
	.long	0x2dd4be83
	.long	0xd3587421
	.long	0x2949e069
	.long	0x448ec9c8
	.long	0x6a75c289
	.long	0x78f48e79
	.long	0x6b99583e
	.long	0xdd27b971
	.long	0xb6bee14f
	.long	0x17f088ad
	.long	0x66c920ac
	.long	0xb47dce3a
	.long	0x1863df4a
	.long	0x82e51a31
	.long	0x60975133
	.long	0x4562537f
	.long	0xe0b16477
	.long	0x84bb6bae
	.long	0x1cfe81a0
	.long	0x94f9082b
	.long	0x58704868
	.long	0x198f45fd
	.long	0x8794de6c
	.long	0xb7527bf8
	.long	0x23ab73d3
	.long	0xe2724b02
	.long	0x57e31f8f
	.long	0x2a6655ab
	.long	0x7b2eb28
	.long	0x32fb5c2
	.long	0x9a86c57b
	.long	0xa5d33708
	.long	0xf2302887
	.long	0xb223bfa5
	.long	0xba02036a
	.long	0x5ced1682
	.long	0x2b8acf1c
	.long	0x92a779b4
	.long	0xf0f307f2
	.long	0xa14e69e2
	.long	0xcd65daf4
	.long	0xd50605be
	.long	0x1fd13462
	.long	0x8ac4a6fe
	.long	0x9d342e53
	.long	0xa0a2f355
	.long	0x32058ae1
	.long	0x75a4f6eb
	.long	0x390b83ec
	.long	0xaa4060ef
	.long	0x65e719f
	.long	0x51bd6e10
	.long	0xf93e218a
	.long	0x3d96dd06
	.long	0xaedd3e05
	.long	0x464de6bd
	.long	0xb591548d
	.long	0x571c45d
	.long	0x6f0406d4
	.long	0xff605015
	.long	0x241998fb
	.long	0x97d6bde9
	.long	0xcc894043
	.long	0x7767d99e
	.long	0xbdb0e842
	.long	0x8807898b
	.long	0x38e7195b
	.long	0xdb79c8ee
	.long	0x47a17c0a
	.long	0xe97c420f
	.long	0xc9f8841e
	.long	0x0
	.long	0x83098086
	.long	0x48322bed
	.long	0xac1e1170
	.long	0x4e6c5a72
	.long	0xfbfd0eff
	.long	0x560f8538
	.long	0x1e3daed5
	.long	0x27362d39
	.long	0x640a0fd9
	.long	0x21685ca6
	.long	0xd19b5b54
	.long	0x3a24362e
	.long	0xb10c0a67
	.long	0xf9357e7
	.long	0xd2b4ee96
	.long	0x9e1b9b91
	.long	0x4f80c0c5
	.long	0xa261dc20
	.long	0x695a774b
	.long	0x161c121a
	.long	0xae293ba
	.long	0xe5c0a02a
	.long	0x433c22e0
	.long	0x1d121b17
	.long	0xb0e090d
	.long	0xadf28bc7
	.long	0xb92db6a8
	.long	0xc8141ea9
	.long	0x8557f119
	.long	0x4caf7507
	.long	0xbbee99dd
	.long	0xfda37f60
	.long	0x9ff70126
	.long	0xbc5c72f5
	.long	0xc544663b
	.long	0x345bfb7e
	.long	0x768b4329
	.long	0xdccb23c6
	.long	0x68b6edfc
	.long	0x63b8e4f1
	.long	0xcad731dc
	.long	0x10426385
	.long	0x40139722
	.long	0x2084c611
	.long	0x7d854a24
	.long	0xf8d2bb3d
	.long	0x11aef932
	.long	0x6dc729a1
	.long	0x4b1d9e2f
	.long	0xf3dcb230
	.long	0xec0d8652
	.long	0xd077c1e3
	.long	0x6c2bb316
	.long	0x99a970b9
	.long	0xfa119448
	.long	0x2247e964
	.long	0xc4a8fc8c
	.long	0x1aa0f03f
	.long	0xd8567d2c
	.long	0xef223390
	.long	0xc787494e
	.long	0xc1d938d1
	.long	0xfe8ccaa2
	.long	0x3698d40b
	.long	0xcfa6f581
	.long	0x28a57ade
	.long	0x26dab78e
	.long	0xa43fadbf
	.long	0xe42c3a9d
	.long	0xd507892
	.long	0x9b6a5fcc
	.long	0x62547e46
	.long	0xc2f68d13
	.long	0xe890d8b8
	.long	0x5e2e39f7
	.long	0xf582c3af
	.long	0xbe9f5d80
	.long	0x7c69d093
	.long	0xa96fd52d
	.long	0xb3cf2512
	.long	0x3bc8ac99
	.long	0xa710187d
	.long	0x6ee89c63
	.long	0x7bdb3bbb
	.long	0x9cd2678
	.long	0xf46e5918
	.long	0x1ec9ab7
	.long	0xa8834f9a
	.long	0x65e6956e
	.long	0x7eaaffe6
	.long	0x821bccf
	.long	0xe6ef15e8
	.long	0xd9bae79b
	.long	0xce4a6f36
	.long	0xd4ea9f09
	.long	0xd629b07c
	.long	0xaf31a4b2
	.long	0x312a3f23
	.long	0x30c6a594
	.long	0xc035a266
	.long	0x37744ebc
	.long	0xa6fc82ca
	.long	0xb0e090d0
	.long	0x1533a7d8
	.long	0x4af10498
	.long	0xf741ecda
	.long	0xe7fcd50
	.long	0x2f1791f6
	.long	0x8d764dd6
	.long	0x4d43efb0
	.long	0x54ccaa4d
	.long	0xdfe49604
	.long	0xe39ed1b5
	.long	0x1b4c6a88
	.long	0xb8c12c1f
	.long	0x7f466551
	.long	0x49d5eea
	.long	0x5d018c35
	.long	0x73fa8774
	.long	0x2efb0b41
	.long	0x5ab3671d
	.long	0x5292dbd2
	.long	0x33e91056
	.long	0x136dd647
	.long	0x8c9ad761
	.long	0x7a37a10c
	.long	0x8e59f814
	.long	0x89eb133c
	.long	0xeecea927
	.long	0x35b761c9
	.long	0xede11ce5
	.long	0x3c7a47b1
	.long	0x599cd2df
	.long	0x3f55f273
	.long	0x791814ce
	.long	0xbf73c737
	.long	0xea53f7cd
	.long	0x5b5ffdaa
	.long	0x14df3d6f
	.long	0x867844db
	.long	0x81caaff3
	.long	0x3eb968c4
	.long	0x2c382434
	.long	0x5fc2a340
	.long	0x72161dc3
	.long	0xcbce225
	.long	0x8b283c49
	.long	0x41ff0d95
	.long	0x7139a801
	.long	0xde080cb3
	.long	0x9cd8b4e4
	.long	0x906456c1
	.long	0x617bcb84
	.long	0x70d532b6
	.long	0x74486c5c
	.long	0x42d0b857
#endif /* HAVE_AES_DECRYPT */
#if defined(HAVE_AES_DECRYPT) || defined(HAVE_AES_CBC) || \
    defined(HAVE_AESCCM) || defined(HAVE_AESGCM) || \
    defined(WOLFSSL_AES_DIRECT) || defined(WOLFSSL_AES_COUNTER)
	.section	".text"
	.section	.rodata
	.type	L_AES_PPC64_te, @object
	.size	L_AES_PPC64_te, 1024
	.align	4
L_AES_PPC64_te:
	.long	0xa5c66363
	.long	0x84f87c7c
	.long	0x99ee7777
	.long	0x8df67b7b
	.long	0xdfff2f2
	.long	0xbdd66b6b
	.long	0xb1de6f6f
	.long	0x5491c5c5
	.long	0x50603030
	.long	0x3020101
	.long	0xa9ce6767
	.long	0x7d562b2b
	.long	0x19e7fefe
	.long	0x62b5d7d7
	.long	0xe64dabab
	.long	0x9aec7676
	.long	0x458fcaca
	.long	0x9d1f8282
	.long	0x4089c9c9
	.long	0x87fa7d7d
	.long	0x15effafa
	.long	0xebb25959
	.long	0xc98e4747
	.long	0xbfbf0f0
	.long	0xec41adad
	.long	0x67b3d4d4
	.long	0xfd5fa2a2
	.long	0xea45afaf
	.long	0xbf239c9c
	.long	0xf753a4a4
	.long	0x96e47272
	.long	0x5b9bc0c0
	.long	0xc275b7b7
	.long	0x1ce1fdfd
	.long	0xae3d9393
	.long	0x6a4c2626
	.long	0x5a6c3636
	.long	0x417e3f3f
	.long	0x2f5f7f7
	.long	0x4f83cccc
	.long	0x5c683434
	.long	0xf451a5a5
	.long	0x34d1e5e5
	.long	0x8f9f1f1
	.long	0x93e27171
	.long	0x73abd8d8
	.long	0x53623131
	.long	0x3f2a1515
	.long	0xc080404
	.long	0x5295c7c7
	.long	0x65462323
	.long	0x5e9dc3c3
	.long	0x28301818
	.long	0xa1379696
	.long	0xf0a0505
	.long	0xb52f9a9a
	.long	0x90e0707
	.long	0x36241212
	.long	0x9b1b8080
	.long	0x3ddfe2e2
	.long	0x26cdebeb
	.long	0x694e2727
	.long	0xcd7fb2b2
	.long	0x9fea7575
	.long	0x1b120909
	.long	0x9e1d8383
	.long	0x74582c2c
	.long	0x2e341a1a
	.long	0x2d361b1b
	.long	0xb2dc6e6e
	.long	0xeeb45a5a
	.long	0xfb5ba0a0
	.long	0xf6a45252
	.long	0x4d763b3b
	.long	0x61b7d6d6
	.long	0xce7db3b3
	.long	0x7b522929
	.long	0x3edde3e3
	.long	0x715e2f2f
	.long	0x97138484
	.long	0xf5a65353
	.long	0x68b9d1d1
	.long	0x0
	.long	0x2cc1eded
	.long	0x60402020
	.long	0x1fe3fcfc
	.long	0xc879b1b1
	.long	0xedb65b5b
	.long	0xbed46a6a
	.long	0x468dcbcb
	.long	0xd967bebe
	.long	0x4b723939
	.long	0xde944a4a
	.long	0xd4984c4c
	.long	0xe8b05858
	.long	0x4a85cfcf
	.long	0x6bbbd0d0
	.long	0x2ac5efef
	.long	0xe54faaaa
	.long	0x16edfbfb
	.long	0xc5864343
	.long	0xd79a4d4d
	.long	0x55663333
	.long	0x94118585
	.long	0xcf8a4545
	.long	0x10e9f9f9
	.long	0x6040202
	.long	0x81fe7f7f
	.long	0xf0a05050
	.long	0x44783c3c
	.long	0xba259f9f
	.long	0xe34ba8a8
	.long	0xf3a25151
	.long	0xfe5da3a3
	.long	0xc0804040
	.long	0x8a058f8f
	.long	0xad3f9292
	.long	0xbc219d9d
	.long	0x48703838
	.long	0x4f1f5f5
	.long	0xdf63bcbc
	.long	0xc177b6b6
	.long	0x75afdada
	.long	0x63422121
	.long	0x30201010
	.long	0x1ae5ffff
	.long	0xefdf3f3
	.long	0x6dbfd2d2
	.long	0x4c81cdcd
	.long	0x14180c0c
	.long	0x35261313
	.long	0x2fc3ecec
	.long	0xe1be5f5f
	.long	0xa2359797
	.long	0xcc884444
	.long	0x392e1717
	.long	0x5793c4c4
	.long	0xf255a7a7
	.long	0x82fc7e7e
	.long	0x477a3d3d
	.long	0xacc86464
	.long	0xe7ba5d5d
	.long	0x2b321919
	.long	0x95e67373
	.long	0xa0c06060
	.long	0x98198181
	.long	0xd19e4f4f
	.long	0x7fa3dcdc
	.long	0x66442222
	.long	0x7e542a2a
	.long	0xab3b9090
	.long	0x830b8888
	.long	0xca8c4646
	.long	0x29c7eeee
	.long	0xd36bb8b8
	.long	0x3c281414
	.long	0x79a7dede
	.long	0xe2bc5e5e
	.long	0x1d160b0b
	.long	0x76addbdb
	.long	0x3bdbe0e0
	.long	0x56643232
	.long	0x4e743a3a
	.long	0x1e140a0a
	.long	0xdb924949
	.long	0xa0c0606
	.long	0x6c482424
	.long	0xe4b85c5c
	.long	0x5d9fc2c2
	.long	0x6ebdd3d3
	.long	0xef43acac
	.long	0xa6c46262
	.long	0xa8399191
	.long	0xa4319595
	.long	0x37d3e4e4
	.long	0x8bf27979
	.long	0x32d5e7e7
	.long	0x438bc8c8
	.long	0x596e3737
	.long	0xb7da6d6d
	.long	0x8c018d8d
	.long	0x64b1d5d5
	.long	0xd29c4e4e
	.long	0xe049a9a9
	.long	0xb4d86c6c
	.long	0xfaac5656
	.long	0x7f3f4f4
	.long	0x25cfeaea
	.long	0xafca6565
	.long	0x8ef47a7a
	.long	0xe947aeae
	.long	0x18100808
	.long	0xd56fbaba
	.long	0x88f07878
	.long	0x6f4a2525
	.long	0x725c2e2e
	.long	0x24381c1c
	.long	0xf157a6a6
	.long	0xc773b4b4
	.long	0x5197c6c6
	.long	0x23cbe8e8
	.long	0x7ca1dddd
	.long	0x9ce87474
	.long	0x213e1f1f
	.long	0xdd964b4b
	.long	0xdc61bdbd
	.long	0x860d8b8b
	.long	0x850f8a8a
	.long	0x90e07070
	.long	0x427c3e3e
	.long	0xc471b5b5
	.long	0xaacc6666
	.long	0xd8904848
	.long	0x5060303
	.long	0x1f7f6f6
	.long	0x121c0e0e
	.long	0xa3c26161
	.long	0x5f6a3535
	.long	0xf9ae5757
	.long	0xd069b9b9
	.long	0x91178686
	.long	0x5899c1c1
	.long	0x273a1d1d
	.long	0xb9279e9e
	.long	0x38d9e1e1
	.long	0x13ebf8f8
	.long	0xb32b9898
	.long	0x33221111
	.long	0xbbd26969
	.long	0x70a9d9d9
	.long	0x89078e8e
	.long	0xa7339494
	.long	0xb62d9b9b
	.long	0x223c1e1e
	.long	0x92158787
	.long	0x20c9e9e9
	.long	0x4987cece
	.long	0xffaa5555
	.long	0x78502828
	.long	0x7aa5dfdf
	.long	0x8f038c8c
	.long	0xf859a1a1
	.long	0x80098989
	.long	0x171a0d0d
	.long	0xda65bfbf
	.long	0x31d7e6e6
	.long	0xc6844242
	.long	0xb8d06868
	.long	0xc3824141
	.long	0xb0299999
	.long	0x775a2d2d
	.long	0x111e0f0f
	.long	0xcb7bb0b0
	.long	0xfca85454
	.long	0xd66dbbbb
	.long	0x3a2c1616
#endif /* HAVE_AES_DECRYPT || HAVE_AES_CBC || HAVE_AESCCM || HAVE_AESGCM ||
        * WOLFSSL_AES_DIRECT || WOLFSSL_AES_COUNTER */
#ifdef HAVE_AES_DECRYPT
	.section	".text"
	.align	4
	.globl	AES_invert_key
	.type	AES_invert_key, @function
AES_invert_key:
	stdu	1, -32(1)
	mflr	0
	std	0, 24(1)
	std	14, 0(1)
	std	15, 8(1)
	std	16, 16(1)
	lis	5, L_AES_PPC64_te@ha
	la	5, L_AES_PPC64_te@l(5)
	lis	6, L_AES_PPC64_td@ha
	la	6, L_AES_PPC64_td@l(6)
	addi	5, 5, 3
	sldi	16, 4, 4
	add	16, 16, 3
	srdi	0, 4, 1
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
	lwz	7, 0(3)
	lwz	8, 4(3)
	lwz	9, 8(3)
	lwz	10, 12(3)
	andi.   11, 7, 255
	rlwinm	12, 7, 24, 24, 31
	rlwinm	14, 7, 16, 24, 31
	rlwinm	15, 7, 8, 24, 31
	slwi	11, 11, 2
	slwi	12, 12, 2
	slwi	14, 14, 2
	slwi	15, 15, 2
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
	addi	3, 3, 4
	andi.   11, 8, 255
	rlwinm	12, 8, 24, 24, 31
	rlwinm	14, 8, 16, 24, 31
	rlwinm	15, 8, 8, 24, 31
	slwi	11, 11, 2
	slwi	12, 12, 2
	slwi	14, 14, 2
	slwi	15, 15, 2
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
	addi	3, 3, 4
	andi.   11, 9, 255
	rlwinm	12, 9, 24, 24, 31
	rlwinm	14, 9, 16, 24, 31
	rlwinm	15, 9, 8, 24, 31
	slwi	11, 11, 2
	slwi	12, 12, 2
	slwi	14, 14, 2
	slwi	15, 15, 2
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
	addi	3, 3, 4
	andi.   11, 10, 255
	rlwinm	12, 10, 24, 24, 31
	rlwinm	14, 10, 16, 24, 31
	rlwinm	15, 10, 8, 24, 31
	slwi	11, 11, 2
	slwi	12, 12, 2
	slwi	14, 14, 2
	slwi	15, 15, 2
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
	addi	3, 3, 4
	bdnz	L_AES_invert_key_mix_loop
	ld	0, 24(1)
	mtlr	0
	ld	14, 0(1)
	ld	15, 8(1)
	ld	16, 16(1)
	addi	1, 1, 32
	blr
	.size	AES_invert_key,.-AES_invert_key
#endif /* HAVE_AES_DECRYPT */
	.section	".text"
	.section	.rodata
	.type	L_AES_PPC64_rcon, @object
	.size	L_AES_PPC64_rcon, 40
	.align	4
L_AES_PPC64_rcon:
	.long	0x1000000
	.long	0x2000000
	.long	0x4000000
	.long	0x8000000
	.long	0x10000000
	.long	0x20000000
	.long	0x40000000
	.long	0x80000000
	.long	0x1b000000
	.long	0x36000000
	.section	".text"
	.align	4
	.globl	AES_set_encrypt_key
	.type	AES_set_encrypt_key, @function
AES_set_encrypt_key:
	stdu	1, -24(1)
	mflr	0
	std	0, 16(1)
	std	14, 0(1)
	std	15, 8(1)
	lis	6, L_AES_PPC64_te@ha
	la	6, L_AES_PPC64_te@l(6)
	lis	7, L_AES_PPC64_rcon@ha
	la	7, L_AES_PPC64_rcon@l(7)
	addi	6, 6, 3
	cmplwi	4, 0x80
	beq	L_AES_set_encrypt_key_start_128
	cmplwi	4, 0xc0
	beq	L_AES_set_encrypt_key_start_192
	ld	9, 0(3)
	ld	10, 8(3)
	ld	11, 16(3)
	ld	12, 24(3)
	std	9, 0(5)
	std	10, 8(5)
	std	11, 16(5)
	std	12, 24(5)
	li	8, 6
	mtctr	8
L_AES_set_encrypt_key_loop_256:
	andi.   9, 12, 255
	rlwinm	10, 12, 24, 24, 31
	rlwinm	11, 12, 16, 24, 31
	rlwinm	12, 12, 8, 24, 31
	slwi	9, 9, 2
	slwi	10, 10, 2
	slwi	11, 11, 2
	slwi	12, 12, 2
	lbzx	9, 6, 9
	lbzx	10, 6, 10
	lbzx	11, 6, 11
	lbzx	0, 6, 12
	rlwimi	0, 9, 8, 16, 23
	rlwimi	0, 10, 16, 8, 15
	rlwimi	0, 11, 24, 0, 7
	lwz	9, 0(5)
	lwz	10, 4(5)
	lwz	11, 8(5)
	lwz	12, 12(5)
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
	rlwinm	9, 12, 24, 24, 31
	rlwinm	10, 12, 16, 24, 31
	rlwinm	11, 12, 8, 24, 31
	andi.   12, 12, 255
	slwi	9, 9, 2
	slwi	10, 10, 2
	slwi	11, 11, 2
	slwi	12, 12, 2
	lbzx	9, 6, 9
	lbzx	10, 6, 10
	lbzx	11, 6, 11
	lbzx	0, 6, 12
	rlwimi	0, 9, 8, 16, 23
	rlwimi	0, 10, 16, 8, 15
	rlwimi	0, 11, 24, 0, 7
	lwz	9, 0(5)
	lwz	10, 4(5)
	lwz	11, 8(5)
	lwz	12, 12(5)
	addi	5, 5, 16
	xor	9, 9, 0
	xor	10, 10, 9
	xor	11, 11, 10
	xor	12, 12, 11
	stw	9, 16(5)
	stw	10, 20(5)
	stw	11, 24(5)
	stw	12, 28(5)
	bdnz	L_AES_set_encrypt_key_loop_256
	andi.   9, 12, 255
	rlwinm	10, 12, 24, 24, 31
	rlwinm	11, 12, 16, 24, 31
	rlwinm	12, 12, 8, 24, 31
	slwi	9, 9, 2
	slwi	10, 10, 2
	slwi	11, 11, 2
	slwi	12, 12, 2
	lbzx	9, 6, 9
	lbzx	10, 6, 10
	lbzx	11, 6, 11
	lbzx	0, 6, 12
	rlwimi	0, 9, 8, 16, 23
	rlwimi	0, 10, 16, 8, 15
	rlwimi	0, 11, 24, 0, 7
	lwz	9, 0(5)
	lwz	10, 4(5)
	lwz	11, 8(5)
	lwz	12, 12(5)
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
	std	12, 0(5)
	std	14, 8(5)
	std	15, 16(5)
	li	8, 7
	mtctr	8
L_AES_set_encrypt_key_loop_192:
	andi.   9, 15, 255
	rlwinm	10, 15, 24, 24, 31
	rlwinm	11, 15, 16, 24, 31
	rlwinm	15, 15, 8, 24, 31
	slwi	9, 9, 2
	slwi	10, 10, 2
	slwi	11, 11, 2
	slwi	15, 15, 2
	lbzx	9, 6, 9
	lbzx	10, 6, 10
	lbzx	11, 6, 11
	lbzx	0, 6, 15
	rlwimi	0, 9, 8, 16, 23
	rlwimi	0, 10, 16, 8, 15
	rlwimi	0, 11, 24, 0, 7
	lwz	9, 0(5)
	lwz	10, 4(5)
	lwz	11, 8(5)
	lwz	12, 12(5)
	lwz	14, 16(5)
	lwz	15, 20(5)
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
	stw	9, 0(5)
	stw	10, 4(5)
	stw	11, 8(5)
	stw	12, 12(5)
	stw	14, 16(5)
	stw	15, 20(5)
	bdnz	L_AES_set_encrypt_key_loop_192
	andi.   9, 15, 255
	rlwinm	10, 15, 24, 24, 31
	rlwinm	11, 15, 16, 24, 31
	rlwinm	15, 15, 8, 24, 31
	slwi	9, 9, 2
	slwi	10, 10, 2
	slwi	11, 11, 2
	slwi	15, 15, 2
	lbzx	9, 6, 9
	lbzx	10, 6, 10
	lbzx	11, 6, 11
	lbzx	0, 6, 15
	rlwimi	0, 9, 8, 16, 23
	rlwimi	0, 10, 16, 8, 15
	rlwimi	0, 11, 24, 0, 7
	lwz	9, 0(5)
	lwz	10, 4(5)
	lwz	11, 8(5)
	lwz	12, 12(5)
	lwz	14, 16(5)
	lwz	15, 20(5)
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
	std	11, 0(5)
	std	12, 8(5)
	li	8, 10
	mtctr	8
L_AES_set_encrypt_key_loop_128:
	andi.   9, 12, 255
	rlwinm	10, 12, 24, 24, 31
	rlwinm	11, 12, 16, 24, 31
	rlwinm	12, 12, 8, 24, 31
	slwi	9, 9, 2
	slwi	10, 10, 2
	slwi	11, 11, 2
	slwi	12, 12, 2
	lbzx	9, 6, 9
	lbzx	10, 6, 10
	lbzx	11, 6, 11
	lbzx	0, 6, 12
	rlwimi	0, 9, 8, 16, 23
	rlwimi	0, 10, 16, 8, 15
	rlwimi	0, 11, 24, 0, 7
	lwz	9, 0(5)
	lwz	10, 4(5)
	lwz	11, 8(5)
	lwz	12, 12(5)
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
	bdnz	L_AES_set_encrypt_key_loop_128
L_AES_set_encrypt_key_end:
	ld	0, 16(1)
	mtlr	0
	ld	14, 0(1)
	ld	15, 8(1)
	addi	1, 1, 24
	blr
	.size	AES_set_encrypt_key,.-AES_set_encrypt_key
	.section	".text"
	.section	.rodata
	.type	L_AES_PPC64_te4_0, @object
	.size	L_AES_PPC64_te4_0, 4096
	.align	4
L_AES_PPC64_te4_0:
	.long	0xc66363a5
	.long	0xf87c7c84
	.long	0xee777799
	.long	0xf67b7b8d
	.long	0xfff2f20d
	.long	0xd66b6bbd
	.long	0xde6f6fb1
	.long	0x91c5c554
	.long	0x60303050
	.long	0x2010103
	.long	0xce6767a9
	.long	0x562b2b7d
	.long	0xe7fefe19
	.long	0xb5d7d762
	.long	0x4dababe6
	.long	0xec76769a
	.long	0x8fcaca45
	.long	0x1f82829d
	.long	0x89c9c940
	.long	0xfa7d7d87
	.long	0xeffafa15
	.long	0xb25959eb
	.long	0x8e4747c9
	.long	0xfbf0f00b
	.long	0x41adadec
	.long	0xb3d4d467
	.long	0x5fa2a2fd
	.long	0x45afafea
	.long	0x239c9cbf
	.long	0x53a4a4f7
	.long	0xe4727296
	.long	0x9bc0c05b
	.long	0x75b7b7c2
	.long	0xe1fdfd1c
	.long	0x3d9393ae
	.long	0x4c26266a
	.long	0x6c36365a
	.long	0x7e3f3f41
	.long	0xf5f7f702
	.long	0x83cccc4f
	.long	0x6834345c
	.long	0x51a5a5f4
	.long	0xd1e5e534
	.long	0xf9f1f108
	.long	0xe2717193
	.long	0xabd8d873
	.long	0x62313153
	.long	0x2a15153f
	.long	0x804040c
	.long	0x95c7c752
	.long	0x46232365
	.long	0x9dc3c35e
	.long	0x30181828
	.long	0x379696a1
	.long	0xa05050f
	.long	0x2f9a9ab5
	.long	0xe070709
	.long	0x24121236
	.long	0x1b80809b
	.long	0xdfe2e23d
	.long	0xcdebeb26
	.long	0x4e272769
	.long	0x7fb2b2cd
	.long	0xea75759f
	.long	0x1209091b
	.long	0x1d83839e
	.long	0x582c2c74
	.long	0x341a1a2e
	.long	0x361b1b2d
	.long	0xdc6e6eb2
	.long	0xb45a5aee
	.long	0x5ba0a0fb
	.long	0xa45252f6
	.long	0x763b3b4d
	.long	0xb7d6d661
	.long	0x7db3b3ce
	.long	0x5229297b
	.long	0xdde3e33e
	.long	0x5e2f2f71
	.long	0x13848497
	.long	0xa65353f5
	.long	0xb9d1d168
	.long	0x0
	.long	0xc1eded2c
	.long	0x40202060
	.long	0xe3fcfc1f
	.long	0x79b1b1c8
	.long	0xb65b5bed
	.long	0xd46a6abe
	.long	0x8dcbcb46
	.long	0x67bebed9
	.long	0x7239394b
	.long	0x944a4ade
	.long	0x984c4cd4
	.long	0xb05858e8
	.long	0x85cfcf4a
	.long	0xbbd0d06b
	.long	0xc5efef2a
	.long	0x4faaaae5
	.long	0xedfbfb16
	.long	0x864343c5
	.long	0x9a4d4dd7
	.long	0x66333355
	.long	0x11858594
	.long	0x8a4545cf
	.long	0xe9f9f910
	.long	0x4020206
	.long	0xfe7f7f81
	.long	0xa05050f0
	.long	0x783c3c44
	.long	0x259f9fba
	.long	0x4ba8a8e3
	.long	0xa25151f3
	.long	0x5da3a3fe
	.long	0x804040c0
	.long	0x58f8f8a
	.long	0x3f9292ad
	.long	0x219d9dbc
	.long	0x70383848
	.long	0xf1f5f504
	.long	0x63bcbcdf
	.long	0x77b6b6c1
	.long	0xafdada75
	.long	0x42212163
	.long	0x20101030
	.long	0xe5ffff1a
	.long	0xfdf3f30e
	.long	0xbfd2d26d
	.long	0x81cdcd4c
	.long	0x180c0c14
	.long	0x26131335
	.long	0xc3ecec2f
	.long	0xbe5f5fe1
	.long	0x359797a2
	.long	0x884444cc
	.long	0x2e171739
	.long	0x93c4c457
	.long	0x55a7a7f2
	.long	0xfc7e7e82
	.long	0x7a3d3d47
	.long	0xc86464ac
	.long	0xba5d5de7
	.long	0x3219192b
	.long	0xe6737395
	.long	0xc06060a0
	.long	0x19818198
	.long	0x9e4f4fd1
	.long	0xa3dcdc7f
	.long	0x44222266
	.long	0x542a2a7e
	.long	0x3b9090ab
	.long	0xb888883
	.long	0x8c4646ca
	.long	0xc7eeee29
	.long	0x6bb8b8d3
	.long	0x2814143c
	.long	0xa7dede79
	.long	0xbc5e5ee2
	.long	0x160b0b1d
	.long	0xaddbdb76
	.long	0xdbe0e03b
	.long	0x64323256
	.long	0x743a3a4e
	.long	0x140a0a1e
	.long	0x924949db
	.long	0xc06060a
	.long	0x4824246c
	.long	0xb85c5ce4
	.long	0x9fc2c25d
	.long	0xbdd3d36e
	.long	0x43acacef
	.long	0xc46262a6
	.long	0x399191a8
	.long	0x319595a4
	.long	0xd3e4e437
	.long	0xf279798b
	.long	0xd5e7e732
	.long	0x8bc8c843
	.long	0x6e373759
	.long	0xda6d6db7
	.long	0x18d8d8c
	.long	0xb1d5d564
	.long	0x9c4e4ed2
	.long	0x49a9a9e0
	.long	0xd86c6cb4
	.long	0xac5656fa
	.long	0xf3f4f407
	.long	0xcfeaea25
	.long	0xca6565af
	.long	0xf47a7a8e
	.long	0x47aeaee9
	.long	0x10080818
	.long	0x6fbabad5
	.long	0xf0787888
	.long	0x4a25256f
	.long	0x5c2e2e72
	.long	0x381c1c24
	.long	0x57a6a6f1
	.long	0x73b4b4c7
	.long	0x97c6c651
	.long	0xcbe8e823
	.long	0xa1dddd7c
	.long	0xe874749c
	.long	0x3e1f1f21
	.long	0x964b4bdd
	.long	0x61bdbddc
	.long	0xd8b8b86
	.long	0xf8a8a85
	.long	0xe0707090
	.long	0x7c3e3e42
	.long	0x71b5b5c4
	.long	0xcc6666aa
	.long	0x904848d8
	.long	0x6030305
	.long	0xf7f6f601
	.long	0x1c0e0e12
	.long	0xc26161a3
	.long	0x6a35355f
	.long	0xae5757f9
	.long	0x69b9b9d0
	.long	0x17868691
	.long	0x99c1c158
	.long	0x3a1d1d27
	.long	0x279e9eb9
	.long	0xd9e1e138
	.long	0xebf8f813
	.long	0x2b9898b3
	.long	0x22111133
	.long	0xd26969bb
	.long	0xa9d9d970
	.long	0x78e8e89
	.long	0x339494a7
	.long	0x2d9b9bb6
	.long	0x3c1e1e22
	.long	0x15878792
	.long	0xc9e9e920
	.long	0x87cece49
	.long	0xaa5555ff
	.long	0x50282878
	.long	0xa5dfdf7a
	.long	0x38c8c8f
	.long	0x59a1a1f8
	.long	0x9898980
	.long	0x1a0d0d17
	.long	0x65bfbfda
	.long	0xd7e6e631
	.long	0x844242c6
	.long	0xd06868b8
	.long	0x824141c3
	.long	0x299999b0
	.long	0x5a2d2d77
	.long	0x1e0f0f11
	.long	0x7bb0b0cb
	.long	0xa85454fc
	.long	0x6dbbbbd6
	.long	0x2c16163a
	.long	0xa5c66363
	.long	0x84f87c7c
	.long	0x99ee7777
	.long	0x8df67b7b
	.long	0xdfff2f2
	.long	0xbdd66b6b
	.long	0xb1de6f6f
	.long	0x5491c5c5
	.long	0x50603030
	.long	0x3020101
	.long	0xa9ce6767
	.long	0x7d562b2b
	.long	0x19e7fefe
	.long	0x62b5d7d7
	.long	0xe64dabab
	.long	0x9aec7676
	.long	0x458fcaca
	.long	0x9d1f8282
	.long	0x4089c9c9
	.long	0x87fa7d7d
	.long	0x15effafa
	.long	0xebb25959
	.long	0xc98e4747
	.long	0xbfbf0f0
	.long	0xec41adad
	.long	0x67b3d4d4
	.long	0xfd5fa2a2
	.long	0xea45afaf
	.long	0xbf239c9c
	.long	0xf753a4a4
	.long	0x96e47272
	.long	0x5b9bc0c0
	.long	0xc275b7b7
	.long	0x1ce1fdfd
	.long	0xae3d9393
	.long	0x6a4c2626
	.long	0x5a6c3636
	.long	0x417e3f3f
	.long	0x2f5f7f7
	.long	0x4f83cccc
	.long	0x5c683434
	.long	0xf451a5a5
	.long	0x34d1e5e5
	.long	0x8f9f1f1
	.long	0x93e27171
	.long	0x73abd8d8
	.long	0x53623131
	.long	0x3f2a1515
	.long	0xc080404
	.long	0x5295c7c7
	.long	0x65462323
	.long	0x5e9dc3c3
	.long	0x28301818
	.long	0xa1379696
	.long	0xf0a0505
	.long	0xb52f9a9a
	.long	0x90e0707
	.long	0x36241212
	.long	0x9b1b8080
	.long	0x3ddfe2e2
	.long	0x26cdebeb
	.long	0x694e2727
	.long	0xcd7fb2b2
	.long	0x9fea7575
	.long	0x1b120909
	.long	0x9e1d8383
	.long	0x74582c2c
	.long	0x2e341a1a
	.long	0x2d361b1b
	.long	0xb2dc6e6e
	.long	0xeeb45a5a
	.long	0xfb5ba0a0
	.long	0xf6a45252
	.long	0x4d763b3b
	.long	0x61b7d6d6
	.long	0xce7db3b3
	.long	0x7b522929
	.long	0x3edde3e3
	.long	0x715e2f2f
	.long	0x97138484
	.long	0xf5a65353
	.long	0x68b9d1d1
	.long	0x0
	.long	0x2cc1eded
	.long	0x60402020
	.long	0x1fe3fcfc
	.long	0xc879b1b1
	.long	0xedb65b5b
	.long	0xbed46a6a
	.long	0x468dcbcb
	.long	0xd967bebe
	.long	0x4b723939
	.long	0xde944a4a
	.long	0xd4984c4c
	.long	0xe8b05858
	.long	0x4a85cfcf
	.long	0x6bbbd0d0
	.long	0x2ac5efef
	.long	0xe54faaaa
	.long	0x16edfbfb
	.long	0xc5864343
	.long	0xd79a4d4d
	.long	0x55663333
	.long	0x94118585
	.long	0xcf8a4545
	.long	0x10e9f9f9
	.long	0x6040202
	.long	0x81fe7f7f
	.long	0xf0a05050
	.long	0x44783c3c
	.long	0xba259f9f
	.long	0xe34ba8a8
	.long	0xf3a25151
	.long	0xfe5da3a3
	.long	0xc0804040
	.long	0x8a058f8f
	.long	0xad3f9292
	.long	0xbc219d9d
	.long	0x48703838
	.long	0x4f1f5f5
	.long	0xdf63bcbc
	.long	0xc177b6b6
	.long	0x75afdada
	.long	0x63422121
	.long	0x30201010
	.long	0x1ae5ffff
	.long	0xefdf3f3
	.long	0x6dbfd2d2
	.long	0x4c81cdcd
	.long	0x14180c0c
	.long	0x35261313
	.long	0x2fc3ecec
	.long	0xe1be5f5f
	.long	0xa2359797
	.long	0xcc884444
	.long	0x392e1717
	.long	0x5793c4c4
	.long	0xf255a7a7
	.long	0x82fc7e7e
	.long	0x477a3d3d
	.long	0xacc86464
	.long	0xe7ba5d5d
	.long	0x2b321919
	.long	0x95e67373
	.long	0xa0c06060
	.long	0x98198181
	.long	0xd19e4f4f
	.long	0x7fa3dcdc
	.long	0x66442222
	.long	0x7e542a2a
	.long	0xab3b9090
	.long	0x830b8888
	.long	0xca8c4646
	.long	0x29c7eeee
	.long	0xd36bb8b8
	.long	0x3c281414
	.long	0x79a7dede
	.long	0xe2bc5e5e
	.long	0x1d160b0b
	.long	0x76addbdb
	.long	0x3bdbe0e0
	.long	0x56643232
	.long	0x4e743a3a
	.long	0x1e140a0a
	.long	0xdb924949
	.long	0xa0c0606
	.long	0x6c482424
	.long	0xe4b85c5c
	.long	0x5d9fc2c2
	.long	0x6ebdd3d3
	.long	0xef43acac
	.long	0xa6c46262
	.long	0xa8399191
	.long	0xa4319595
	.long	0x37d3e4e4
	.long	0x8bf27979
	.long	0x32d5e7e7
	.long	0x438bc8c8
	.long	0x596e3737
	.long	0xb7da6d6d
	.long	0x8c018d8d
	.long	0x64b1d5d5
	.long	0xd29c4e4e
	.long	0xe049a9a9
	.long	0xb4d86c6c
	.long	0xfaac5656
	.long	0x7f3f4f4
	.long	0x25cfeaea
	.long	0xafca6565
	.long	0x8ef47a7a
	.long	0xe947aeae
	.long	0x18100808
	.long	0xd56fbaba
	.long	0x88f07878
	.long	0x6f4a2525
	.long	0x725c2e2e
	.long	0x24381c1c
	.long	0xf157a6a6
	.long	0xc773b4b4
	.long	0x5197c6c6
	.long	0x23cbe8e8
	.long	0x7ca1dddd
	.long	0x9ce87474
	.long	0x213e1f1f
	.long	0xdd964b4b
	.long	0xdc61bdbd
	.long	0x860d8b8b
	.long	0x850f8a8a
	.long	0x90e07070
	.long	0x427c3e3e
	.long	0xc471b5b5
	.long	0xaacc6666
	.long	0xd8904848
	.long	0x5060303
	.long	0x1f7f6f6
	.long	0x121c0e0e
	.long	0xa3c26161
	.long	0x5f6a3535
	.long	0xf9ae5757
	.long	0xd069b9b9
	.long	0x91178686
	.long	0x5899c1c1
	.long	0x273a1d1d
	.long	0xb9279e9e
	.long	0x38d9e1e1
	.long	0x13ebf8f8
	.long	0xb32b9898
	.long	0x33221111
	.long	0xbbd26969
	.long	0x70a9d9d9
	.long	0x89078e8e
	.long	0xa7339494
	.long	0xb62d9b9b
	.long	0x223c1e1e
	.long	0x92158787
	.long	0x20c9e9e9
	.long	0x4987cece
	.long	0xffaa5555
	.long	0x78502828
	.long	0x7aa5dfdf
	.long	0x8f038c8c
	.long	0xf859a1a1
	.long	0x80098989
	.long	0x171a0d0d
	.long	0xda65bfbf
	.long	0x31d7e6e6
	.long	0xc6844242
	.long	0xb8d06868
	.long	0xc3824141
	.long	0xb0299999
	.long	0x775a2d2d
	.long	0x111e0f0f
	.long	0xcb7bb0b0
	.long	0xfca85454
	.long	0xd66dbbbb
	.long	0x3a2c1616
	.long	0x63a5c663
	.long	0x7c84f87c
	.long	0x7799ee77
	.long	0x7b8df67b
	.long	0xf20dfff2
	.long	0x6bbdd66b
	.long	0x6fb1de6f
	.long	0xc55491c5
	.long	0x30506030
	.long	0x1030201
	.long	0x67a9ce67
	.long	0x2b7d562b
	.long	0xfe19e7fe
	.long	0xd762b5d7
	.long	0xabe64dab
	.long	0x769aec76
	.long	0xca458fca
	.long	0x829d1f82
	.long	0xc94089c9
	.long	0x7d87fa7d
	.long	0xfa15effa
	.long	0x59ebb259
	.long	0x47c98e47
	.long	0xf00bfbf0
	.long	0xadec41ad
	.long	0xd467b3d4
	.long	0xa2fd5fa2
	.long	0xafea45af
	.long	0x9cbf239c
	.long	0xa4f753a4
	.long	0x7296e472
	.long	0xc05b9bc0
	.long	0xb7c275b7
	.long	0xfd1ce1fd
	.long	0x93ae3d93
	.long	0x266a4c26
	.long	0x365a6c36
	.long	0x3f417e3f
	.long	0xf702f5f7
	.long	0xcc4f83cc
	.long	0x345c6834
	.long	0xa5f451a5
	.long	0xe534d1e5
	.long	0xf108f9f1
	.long	0x7193e271
	.long	0xd873abd8
	.long	0x31536231
	.long	0x153f2a15
	.long	0x40c0804
	.long	0xc75295c7
	.long	0x23654623
	.long	0xc35e9dc3
	.long	0x18283018
	.long	0x96a13796
	.long	0x50f0a05
	.long	0x9ab52f9a
	.long	0x7090e07
	.long	0x12362412
	.long	0x809b1b80
	.long	0xe23ddfe2
	.long	0xeb26cdeb
	.long	0x27694e27
	.long	0xb2cd7fb2
	.long	0x759fea75
	.long	0x91b1209
	.long	0x839e1d83
	.long	0x2c74582c
	.long	0x1a2e341a
	.long	0x1b2d361b
	.long	0x6eb2dc6e
	.long	0x5aeeb45a
	.long	0xa0fb5ba0
	.long	0x52f6a452
	.long	0x3b4d763b
	.long	0xd661b7d6
	.long	0xb3ce7db3
	.long	0x297b5229
	.long	0xe33edde3
	.long	0x2f715e2f
	.long	0x84971384
	.long	0x53f5a653
	.long	0xd168b9d1
	.long	0x0
	.long	0xed2cc1ed
	.long	0x20604020
	.long	0xfc1fe3fc
	.long	0xb1c879b1
	.long	0x5bedb65b
	.long	0x6abed46a
	.long	0xcb468dcb
	.long	0xbed967be
	.long	0x394b7239
	.long	0x4ade944a
	.long	0x4cd4984c
	.long	0x58e8b058
	.long	0xcf4a85cf
	.long	0xd06bbbd0
	.long	0xef2ac5ef
	.long	0xaae54faa
	.long	0xfb16edfb
	.long	0x43c58643
	.long	0x4dd79a4d
	.long	0x33556633
	.long	0x85941185
	.long	0x45cf8a45
	.long	0xf910e9f9
	.long	0x2060402
	.long	0x7f81fe7f
	.long	0x50f0a050
	.long	0x3c44783c
	.long	0x9fba259f
	.long	0xa8e34ba8
	.long	0x51f3a251
	.long	0xa3fe5da3
	.long	0x40c08040
	.long	0x8f8a058f
	.long	0x92ad3f92
	.long	0x9dbc219d
	.long	0x38487038
	.long	0xf504f1f5
	.long	0xbcdf63bc
	.long	0xb6c177b6
	.long	0xda75afda
	.long	0x21634221
	.long	0x10302010
	.long	0xff1ae5ff
	.long	0xf30efdf3
	.long	0xd26dbfd2
	.long	0xcd4c81cd
	.long	0xc14180c
	.long	0x13352613
	.long	0xec2fc3ec
	.long	0x5fe1be5f
	.long	0x97a23597
	.long	0x44cc8844
	.long	0x17392e17
	.long	0xc45793c4
	.long	0xa7f255a7
	.long	0x7e82fc7e
	.long	0x3d477a3d
	.long	0x64acc864
	.long	0x5de7ba5d
	.long	0x192b3219
	.long	0x7395e673
	.long	0x60a0c060
	.long	0x81981981
	.long	0x4fd19e4f
	.long	0xdc7fa3dc
	.long	0x22664422
	.long	0x2a7e542a
	.long	0x90ab3b90
	.long	0x88830b88
	.long	0x46ca8c46
	.long	0xee29c7ee
	.long	0xb8d36bb8
	.long	0x143c2814
	.long	0xde79a7de
	.long	0x5ee2bc5e
	.long	0xb1d160b
	.long	0xdb76addb
	.long	0xe03bdbe0
	.long	0x32566432
	.long	0x3a4e743a
	.long	0xa1e140a
	.long	0x49db9249
	.long	0x60a0c06
	.long	0x246c4824
	.long	0x5ce4b85c
	.long	0xc25d9fc2
	.long	0xd36ebdd3
	.long	0xacef43ac
	.long	0x62a6c462
	.long	0x91a83991
	.long	0x95a43195
	.long	0xe437d3e4
	.long	0x798bf279
	.long	0xe732d5e7
	.long	0xc8438bc8
	.long	0x37596e37
	.long	0x6db7da6d
	.long	0x8d8c018d
	.long	0xd564b1d5
	.long	0x4ed29c4e
	.long	0xa9e049a9
	.long	0x6cb4d86c
	.long	0x56faac56
	.long	0xf407f3f4
	.long	0xea25cfea
	.long	0x65afca65
	.long	0x7a8ef47a
	.long	0xaee947ae
	.long	0x8181008
	.long	0xbad56fba
	.long	0x7888f078
	.long	0x256f4a25
	.long	0x2e725c2e
	.long	0x1c24381c
	.long	0xa6f157a6
	.long	0xb4c773b4
	.long	0xc65197c6
	.long	0xe823cbe8
	.long	0xdd7ca1dd
	.long	0x749ce874
	.long	0x1f213e1f
	.long	0x4bdd964b
	.long	0xbddc61bd
	.long	0x8b860d8b
	.long	0x8a850f8a
	.long	0x7090e070
	.long	0x3e427c3e
	.long	0xb5c471b5
	.long	0x66aacc66
	.long	0x48d89048
	.long	0x3050603
	.long	0xf601f7f6
	.long	0xe121c0e
	.long	0x61a3c261
	.long	0x355f6a35
	.long	0x57f9ae57
	.long	0xb9d069b9
	.long	0x86911786
	.long	0xc15899c1
	.long	0x1d273a1d
	.long	0x9eb9279e
	.long	0xe138d9e1
	.long	0xf813ebf8
	.long	0x98b32b98
	.long	0x11332211
	.long	0x69bbd269
	.long	0xd970a9d9
	.long	0x8e89078e
	.long	0x94a73394
	.long	0x9bb62d9b
	.long	0x1e223c1e
	.long	0x87921587
	.long	0xe920c9e9
	.long	0xce4987ce
	.long	0x55ffaa55
	.long	0x28785028
	.long	0xdf7aa5df
	.long	0x8c8f038c
	.long	0xa1f859a1
	.long	0x89800989
	.long	0xd171a0d
	.long	0xbfda65bf
	.long	0xe631d7e6
	.long	0x42c68442
	.long	0x68b8d068
	.long	0x41c38241
	.long	0x99b02999
	.long	0x2d775a2d
	.long	0xf111e0f
	.long	0xb0cb7bb0
	.long	0x54fca854
	.long	0xbbd66dbb
	.long	0x163a2c16
	.long	0x6363a5c6
	.long	0x7c7c84f8
	.long	0x777799ee
	.long	0x7b7b8df6
	.long	0xf2f20dff
	.long	0x6b6bbdd6
	.long	0x6f6fb1de
	.long	0xc5c55491
	.long	0x30305060
	.long	0x1010302
	.long	0x6767a9ce
	.long	0x2b2b7d56
	.long	0xfefe19e7
	.long	0xd7d762b5
	.long	0xababe64d
	.long	0x76769aec
	.long	0xcaca458f
	.long	0x82829d1f
	.long	0xc9c94089
	.long	0x7d7d87fa
	.long	0xfafa15ef
	.long	0x5959ebb2
	.long	0x4747c98e
	.long	0xf0f00bfb
	.long	0xadadec41
	.long	0xd4d467b3
	.long	0xa2a2fd5f
	.long	0xafafea45
	.long	0x9c9cbf23
	.long	0xa4a4f753
	.long	0x727296e4
	.long	0xc0c05b9b
	.long	0xb7b7c275
	.long	0xfdfd1ce1
	.long	0x9393ae3d
	.long	0x26266a4c
	.long	0x36365a6c
	.long	0x3f3f417e
	.long	0xf7f702f5
	.long	0xcccc4f83
	.long	0x34345c68
	.long	0xa5a5f451
	.long	0xe5e534d1
	.long	0xf1f108f9
	.long	0x717193e2
	.long	0xd8d873ab
	.long	0x31315362
	.long	0x15153f2a
	.long	0x4040c08
	.long	0xc7c75295
	.long	0x23236546
	.long	0xc3c35e9d
	.long	0x18182830
	.long	0x9696a137
	.long	0x5050f0a
	.long	0x9a9ab52f
	.long	0x707090e
	.long	0x12123624
	.long	0x80809b1b
	.long	0xe2e23ddf
	.long	0xebeb26cd
	.long	0x2727694e
	.long	0xb2b2cd7f
	.long	0x75759fea
	.long	0x9091b12
	.long	0x83839e1d
	.long	0x2c2c7458
	.long	0x1a1a2e34
	.long	0x1b1b2d36
	.long	0x6e6eb2dc
	.long	0x5a5aeeb4
	.long	0xa0a0fb5b
	.long	0x5252f6a4
	.long	0x3b3b4d76
	.long	0xd6d661b7
	.long	0xb3b3ce7d
	.long	0x29297b52
	.long	0xe3e33edd
	.long	0x2f2f715e
	.long	0x84849713
	.long	0x5353f5a6
	.long	0xd1d168b9
	.long	0x0
	.long	0xeded2cc1
	.long	0x20206040
	.long	0xfcfc1fe3
	.long	0xb1b1c879
	.long	0x5b5bedb6
	.long	0x6a6abed4
	.long	0xcbcb468d
	.long	0xbebed967
	.long	0x39394b72
	.long	0x4a4ade94
	.long	0x4c4cd498
	.long	0x5858e8b0
	.long	0xcfcf4a85
	.long	0xd0d06bbb
	.long	0xefef2ac5
	.long	0xaaaae54f
	.long	0xfbfb16ed
	.long	0x4343c586
	.long	0x4d4dd79a
	.long	0x33335566
	.long	0x85859411
	.long	0x4545cf8a
	.long	0xf9f910e9
	.long	0x2020604
	.long	0x7f7f81fe
	.long	0x5050f0a0
	.long	0x3c3c4478
	.long	0x9f9fba25
	.long	0xa8a8e34b
	.long	0x5151f3a2
	.long	0xa3a3fe5d
	.long	0x4040c080
	.long	0x8f8f8a05
	.long	0x9292ad3f
	.long	0x9d9dbc21
	.long	0x38384870
	.long	0xf5f504f1
	.long	0xbcbcdf63
	.long	0xb6b6c177
	.long	0xdada75af
	.long	0x21216342
	.long	0x10103020
	.long	0xffff1ae5
	.long	0xf3f30efd
	.long	0xd2d26dbf
	.long	0xcdcd4c81
	.long	0xc0c1418
	.long	0x13133526
	.long	0xecec2fc3
	.long	0x5f5fe1be
	.long	0x9797a235
	.long	0x4444cc88
	.long	0x1717392e
	.long	0xc4c45793
	.long	0xa7a7f255
	.long	0x7e7e82fc
	.long	0x3d3d477a
	.long	0x6464acc8
	.long	0x5d5de7ba
	.long	0x19192b32
	.long	0x737395e6
	.long	0x6060a0c0
	.long	0x81819819
	.long	0x4f4fd19e
	.long	0xdcdc7fa3
	.long	0x22226644
	.long	0x2a2a7e54
	.long	0x9090ab3b
	.long	0x8888830b
	.long	0x4646ca8c
	.long	0xeeee29c7
	.long	0xb8b8d36b
	.long	0x14143c28
	.long	0xdede79a7
	.long	0x5e5ee2bc
	.long	0xb0b1d16
	.long	0xdbdb76ad
	.long	0xe0e03bdb
	.long	0x32325664
	.long	0x3a3a4e74
	.long	0xa0a1e14
	.long	0x4949db92
	.long	0x6060a0c
	.long	0x24246c48
	.long	0x5c5ce4b8
	.long	0xc2c25d9f
	.long	0xd3d36ebd
	.long	0xacacef43
	.long	0x6262a6c4
	.long	0x9191a839
	.long	0x9595a431
	.long	0xe4e437d3
	.long	0x79798bf2
	.long	0xe7e732d5
	.long	0xc8c8438b
	.long	0x3737596e
	.long	0x6d6db7da
	.long	0x8d8d8c01
	.long	0xd5d564b1
	.long	0x4e4ed29c
	.long	0xa9a9e049
	.long	0x6c6cb4d8
	.long	0x5656faac
	.long	0xf4f407f3
	.long	0xeaea25cf
	.long	0x6565afca
	.long	0x7a7a8ef4
	.long	0xaeaee947
	.long	0x8081810
	.long	0xbabad56f
	.long	0x787888f0
	.long	0x25256f4a
	.long	0x2e2e725c
	.long	0x1c1c2438
	.long	0xa6a6f157
	.long	0xb4b4c773
	.long	0xc6c65197
	.long	0xe8e823cb
	.long	0xdddd7ca1
	.long	0x74749ce8
	.long	0x1f1f213e
	.long	0x4b4bdd96
	.long	0xbdbddc61
	.long	0x8b8b860d
	.long	0x8a8a850f
	.long	0x707090e0
	.long	0x3e3e427c
	.long	0xb5b5c471
	.long	0x6666aacc
	.long	0x4848d890
	.long	0x3030506
	.long	0xf6f601f7
	.long	0xe0e121c
	.long	0x6161a3c2
	.long	0x35355f6a
	.long	0x5757f9ae
	.long	0xb9b9d069
	.long	0x86869117
	.long	0xc1c15899
	.long	0x1d1d273a
	.long	0x9e9eb927
	.long	0xe1e138d9
	.long	0xf8f813eb
	.long	0x9898b32b
	.long	0x11113322
	.long	0x6969bbd2
	.long	0xd9d970a9
	.long	0x8e8e8907
	.long	0x9494a733
	.long	0x9b9bb62d
	.long	0x1e1e223c
	.long	0x87879215
	.long	0xe9e920c9
	.long	0xcece4987
	.long	0x5555ffaa
	.long	0x28287850
	.long	0xdfdf7aa5
	.long	0x8c8c8f03
	.long	0xa1a1f859
	.long	0x89898009
	.long	0xd0d171a
	.long	0xbfbfda65
	.long	0xe6e631d7
	.long	0x4242c684
	.long	0x6868b8d0
	.long	0x4141c382
	.long	0x9999b029
	.long	0x2d2d775a
	.long	0xf0f111e
	.long	0xb0b0cb7b
	.long	0x5454fca8
	.long	0xbbbbd66d
	.long	0x16163a2c
#if defined(HAVE_AESCCM) || defined(HAVE_AESGCM) || \
    defined(WOLFSSL_AES_DIRECT) || defined(WOLFSSL_AES_COUNTER) || \
    defined(HAVE_AES_ECB)
	.section	".text"
	.align	4
	.globl	AES_ECB_encrypt
	.type	AES_ECB_encrypt, @function
AES_ECB_encrypt:
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
	lis	8, L_AES_PPC64_te4_0@ha
	la	8, L_AES_PPC64_te4_0@l(8)
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
	# Round: 0 - XOR in key schedule
	xor	12, 12, 17
	xor	14, 14, 18
	rldicr	12, 12, 32, 63
	rldicr	14, 14, 32, 63
	addi	0, 7, -2
	srwi	0, 0, 1
	mtctr	0
L_AES_ECB_encrypt_loop_nr:
	rldicl	17, 12, 40, 56
	rldicl	19, 12, 8, 56
	rldicl	18, 14, 40, 56
	rldicl	20, 14, 8, 56
	slwi	17, 17, 2
	slwi	19, 19, 2
	slwi	18, 18, 2
	slwi	20, 20, 2
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
	lwzx	17, 8, 17
	lwzx	19, 8, 19
	lwzx	18, 8, 18
	lwzx	20, 8, 20
	rldicl	21, 12, 16, 56
	rldicl	22, 14, 48, 56
	rldicl	23, 14, 16, 56
	rldicl	24, 12, 48, 56
	slwi	21, 21, 2
	slwi	22, 22, 2
	slwi	23, 23, 2
	slwi	24, 24, 2
	lwzx	21, 9, 21
	lwzx	22, 9, 22
	lwzx	23, 9, 23
	lwzx	24, 9, 24
	xor	17, 17, 21
	xor	19, 19, 22
	xor	18, 18, 23
	xor	20, 20, 24
	rldicl	21, 14, 56, 56
	rldicl	22, 14, 24, 56
	rldicl	23, 12, 56, 56
	rldicl	24, 12, 24, 56
	slwi	21, 21, 2
	slwi	22, 22, 2
	slwi	23, 23, 2
	slwi	24, 24, 2
	lwzx	21, 10, 21
	lwzx	22, 10, 22
	lwzx	23, 10, 23
	lwzx	24, 10, 24
	xor	17, 17, 21
	xor	19, 19, 22
	xor	18, 18, 23
	xor	20, 20, 24
	rldicl	21, 14, 32, 56
	rldic	22, 12, 2, 54
	rldicl	23, 12, 32, 56
	rldic	24, 14, 2, 54
	slwi	21, 21, 2
	slwi	23, 23, 2
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
	rldicr	12, 12, 32, 63
	rldicr	14, 14, 32, 63
	#   XOR in Key Schedule
	xor	17, 17, 12
	xor	18, 18, 14
	rldicl	12, 17, 40, 56
	rldicl	15, 17, 8, 56
	rldicl	14, 18, 40, 56
	rldicl	16, 18, 8, 56
	slwi	12, 12, 2
	slwi	15, 15, 2
	slwi	14, 14, 2
	slwi	16, 16, 2
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
	lwzx	12, 8, 12
	lwzx	15, 8, 15
	lwzx	14, 8, 14
	lwzx	16, 8, 16
	rldicl	21, 17, 16, 56
	rldicl	22, 18, 48, 56
	rldicl	23, 18, 16, 56
	rldicl	24, 17, 48, 56
	slwi	21, 21, 2
	slwi	22, 22, 2
	slwi	23, 23, 2
	slwi	24, 24, 2
	lwzx	21, 9, 21
	lwzx	22, 9, 22
	lwzx	23, 9, 23
	lwzx	24, 9, 24
	xor	12, 12, 21
	xor	15, 15, 22
	xor	14, 14, 23
	xor	16, 16, 24
	rldicl	21, 18, 56, 56
	rldicl	22, 18, 24, 56
	rldicl	23, 17, 56, 56
	rldicl	24, 17, 24, 56
	slwi	21, 21, 2
	slwi	22, 22, 2
	slwi	23, 23, 2
	slwi	24, 24, 2
	lwzx	21, 10, 21
	lwzx	22, 10, 22
	lwzx	23, 10, 23
	lwzx	24, 10, 24
	xor	12, 12, 21
	xor	15, 15, 22
	xor	14, 14, 23
	xor	16, 16, 24
	rldicl	21, 18, 32, 56
	rldic	22, 17, 2, 54
	rldicl	23, 17, 32, 56
	rldic	24, 18, 2, 54
	slwi	21, 21, 2
	slwi	23, 23, 2
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
	rldicr	17, 17, 32, 63
	rldicr	18, 18, 32, 63
	#   XOR in Key Schedule
	xor	12, 12, 17
	xor	14, 14, 18
	bdnz	L_AES_ECB_encrypt_loop_nr
	rldicl	17, 12, 40, 56
	rldicl	19, 12, 8, 56
	rldicl	18, 14, 40, 56
	rldicl	20, 14, 8, 56
	slwi	17, 17, 2
	slwi	19, 19, 2
	slwi	18, 18, 2
	slwi	20, 20, 2
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
	ld	24, 0(8)
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
	lwzx	17, 8, 17
	lwzx	19, 8, 19
	lwzx	18, 8, 18
	lwzx	20, 8, 20
	rldicl	21, 12, 16, 56
	rldicl	22, 14, 48, 56
	rldicl	23, 14, 16, 56
	rldicl	24, 12, 48, 56
	slwi	21, 21, 2
	slwi	22, 22, 2
	slwi	23, 23, 2
	slwi	24, 24, 2
	lwzx	21, 9, 21
	lwzx	22, 9, 22
	lwzx	23, 9, 23
	lwzx	24, 9, 24
	xor	17, 17, 21
	xor	19, 19, 22
	xor	18, 18, 23
	xor	20, 20, 24
	rldicl	21, 14, 56, 56
	rldicl	22, 14, 24, 56
	rldicl	23, 12, 56, 56
	rldicl	24, 12, 24, 56
	slwi	21, 21, 2
	slwi	22, 22, 2
	slwi	23, 23, 2
	slwi	24, 24, 2
	lwzx	21, 10, 21
	lwzx	22, 10, 22
	lwzx	23, 10, 23
	lwzx	24, 10, 24
	xor	17, 17, 21
	xor	19, 19, 22
	xor	18, 18, 23
	xor	20, 20, 24
	rldicl	21, 14, 32, 56
	rldic	22, 12, 2, 54
	rldicl	23, 12, 32, 56
	rldic	24, 14, 2, 54
	slwi	21, 21, 2
	slwi	23, 23, 2
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
	rldicr	12, 12, 32, 63
	rldicr	14, 14, 32, 63
	#   XOR in Key Schedule
	xor	17, 17, 12
	xor	18, 18, 14
	rldicl	12, 18, 32, 56
	rldic	15, 17, 2, 54
	rldicl	14, 17, 32, 56
	rldic	16, 18, 2, 54
	slwi	12, 12, 2
	slwi	14, 14, 2
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
	ld	24, 0(9)
	ld	24, 0(9)
	ld	24, 0(9)
	ld	24, 0(9)
	ld	24, 0(9)
	ld	24, 0(9)
	ld	24, 0(9)
	ld	24, 0(9)
	ld	24, 0(9)
	ld	24, 0(9)
	ld	24, 0(9)
	ld	24, 0(9)
	ld	24, 0(9)
	ld	24, 0(9)
	ld	24, 0(9)
	ld	24, 0(9)
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
	lwzx	12, 9, 12
	lwzx	15, 9, 15
	lwzx	14, 9, 14
	lwzx	16, 9, 16
	rldicl	21, 18, 56, 56
	rldicl	22, 18, 24, 56
	rldicl	23, 17, 56, 56
	rldicl	24, 17, 24, 56
	slwi	21, 21, 2
	slwi	22, 22, 2
	slwi	23, 23, 2
	slwi	24, 24, 2
	lwzx	21, 9, 21
	lwzx	22, 9, 22
	lwzx	23, 9, 23
	lwzx	24, 9, 24
	rlwimi	12, 21, 8, 16, 23
	rlwimi	15, 22, 8, 16, 23
	rlwimi	14, 23, 8, 16, 23
	rlwimi	16, 24, 8, 16, 23
	rldicl	21, 17, 16, 56
	rldicl	22, 18, 48, 56
	rldicl	23, 18, 16, 56
	rldicl	24, 17, 48, 56
	slwi	21, 21, 2
	slwi	22, 22, 2
	slwi	23, 23, 2
	slwi	24, 24, 2
	lwzx	21, 9, 21
	lwzx	22, 9, 22
	lwzx	23, 9, 23
	lwzx	24, 9, 24
	rlwimi	12, 21, 16, 8, 15
	rlwimi	15, 22, 16, 8, 15
	rlwimi	14, 23, 16, 8, 15
	rlwimi	16, 24, 16, 8, 15
	rldicl	21, 17, 40, 56
	rldicl	22, 17, 8, 56
	rldicl	23, 18, 40, 56
	rldicl	24, 18, 8, 56
	slwi	21, 21, 2
	slwi	22, 22, 2
	slwi	23, 23, 2
	slwi	24, 24, 2
	lwzx	21, 9, 21
	lwzx	22, 9, 22
	lwzx	23, 9, 23
	lwzx	24, 9, 24
	rlwimi	12, 21, 24, 0, 7
	rlwimi	15, 22, 24, 0, 7
	rlwimi	14, 23, 24, 0, 7
	rlwimi	16, 24, 24, 0, 7
	ld	17, 0(25)
	ld	18, 8(25)
	rldimi	12, 15, 32, 0
	rldimi	14, 16, 32, 0
	addi	25, 25, 16
	rldicr	17, 17, 32, 63
	rldicr	18, 18, 32, 63
	#   XOR in Key Schedule
	xor	12, 12, 17
	xor	14, 14, 18
	rldicr	12, 12, 32, 63
	rldicr	14, 14, 32, 63
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
	.size	AES_ECB_encrypt,.-AES_ECB_encrypt
#endif /* HAVE_AESCCM || HAVE_AESGCM || WOLFSSL_AES_DIRECT ||
        * WOLFSSL_AES_COUNTER || HAVE_AES_ECB */
#ifdef HAVE_AES_CBC
	.section	".text"
	.align	4
	.globl	AES_CBC_encrypt
	.type	AES_CBC_encrypt, @function
AES_CBC_encrypt:
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
	lis	9, L_AES_PPC64_te4_0@ha
	la	9, L_AES_PPC64_te4_0@l(9)
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
	# Round: 0 - XOR in key schedule
	xor	14, 14, 18
	xor	15, 15, 19
	rldicr	14, 14, 32, 63
	rldicr	15, 15, 32, 63
	addi	0, 7, -2
	srwi	0, 0, 1
	mtctr	0
L_AES_CBC_encrypt_loop_nr:
	rldicl	18, 14, 40, 56
	rldicl	20, 14, 8, 56
	rldicl	19, 15, 40, 56
	rldicl	21, 15, 8, 56
	slwi	18, 18, 2
	slwi	20, 20, 2
	slwi	19, 19, 2
	slwi	21, 21, 2
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
	lwzx	18, 9, 18
	lwzx	20, 9, 20
	lwzx	19, 9, 19
	lwzx	21, 9, 21
	rldicl	22, 14, 16, 56
	rldicl	23, 15, 48, 56
	rldicl	24, 15, 16, 56
	rldicl	25, 14, 48, 56
	slwi	22, 22, 2
	slwi	23, 23, 2
	slwi	24, 24, 2
	slwi	25, 25, 2
	lwzx	22, 10, 22
	lwzx	23, 10, 23
	lwzx	24, 10, 24
	lwzx	25, 10, 25
	xor	18, 18, 22
	xor	20, 20, 23
	xor	19, 19, 24
	xor	21, 21, 25
	rldicl	22, 15, 56, 56
	rldicl	23, 15, 24, 56
	rldicl	24, 14, 56, 56
	rldicl	25, 14, 24, 56
	slwi	22, 22, 2
	slwi	23, 23, 2
	slwi	24, 24, 2
	slwi	25, 25, 2
	lwzx	22, 11, 22
	lwzx	23, 11, 23
	lwzx	24, 11, 24
	lwzx	25, 11, 25
	xor	18, 18, 22
	xor	20, 20, 23
	xor	19, 19, 24
	xor	21, 21, 25
	rldicl	22, 15, 32, 56
	rldic	23, 14, 2, 54
	rldicl	24, 14, 32, 56
	rldic	25, 15, 2, 54
	slwi	22, 22, 2
	slwi	24, 24, 2
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
	rldicr	14, 14, 32, 63
	rldicr	15, 15, 32, 63
	#   XOR in Key Schedule
	xor	18, 18, 14
	xor	19, 19, 15
	rldicl	14, 18, 40, 56
	rldicl	16, 18, 8, 56
	rldicl	15, 19, 40, 56
	rldicl	17, 19, 8, 56
	slwi	14, 14, 2
	slwi	16, 16, 2
	slwi	15, 15, 2
	slwi	17, 17, 2
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
	lwzx	14, 9, 14
	lwzx	16, 9, 16
	lwzx	15, 9, 15
	lwzx	17, 9, 17
	rldicl	22, 18, 16, 56
	rldicl	23, 19, 48, 56
	rldicl	24, 19, 16, 56
	rldicl	25, 18, 48, 56
	slwi	22, 22, 2
	slwi	23, 23, 2
	slwi	24, 24, 2
	slwi	25, 25, 2
	lwzx	22, 10, 22
	lwzx	23, 10, 23
	lwzx	24, 10, 24
	lwzx	25, 10, 25
	xor	14, 14, 22
	xor	16, 16, 23
	xor	15, 15, 24
	xor	17, 17, 25
	rldicl	22, 19, 56, 56
	rldicl	23, 19, 24, 56
	rldicl	24, 18, 56, 56
	rldicl	25, 18, 24, 56
	slwi	22, 22, 2
	slwi	23, 23, 2
	slwi	24, 24, 2
	slwi	25, 25, 2
	lwzx	22, 11, 22
	lwzx	23, 11, 23
	lwzx	24, 11, 24
	lwzx	25, 11, 25
	xor	14, 14, 22
	xor	16, 16, 23
	xor	15, 15, 24
	xor	17, 17, 25
	rldicl	22, 19, 32, 56
	rldic	23, 18, 2, 54
	rldicl	24, 18, 32, 56
	rldic	25, 19, 2, 54
	slwi	22, 22, 2
	slwi	24, 24, 2
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
	rldicr	18, 18, 32, 63
	rldicr	19, 19, 32, 63
	#   XOR in Key Schedule
	xor	14, 14, 18
	xor	15, 15, 19
	bdnz	L_AES_CBC_encrypt_loop_nr
	rldicl	18, 14, 40, 56
	rldicl	20, 14, 8, 56
	rldicl	19, 15, 40, 56
	rldicl	21, 15, 8, 56
	slwi	18, 18, 2
	slwi	20, 20, 2
	slwi	19, 19, 2
	slwi	21, 21, 2
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
	lwzx	18, 9, 18
	lwzx	20, 9, 20
	lwzx	19, 9, 19
	lwzx	21, 9, 21
	rldicl	22, 14, 16, 56
	rldicl	23, 15, 48, 56
	rldicl	24, 15, 16, 56
	rldicl	25, 14, 48, 56
	slwi	22, 22, 2
	slwi	23, 23, 2
	slwi	24, 24, 2
	slwi	25, 25, 2
	lwzx	22, 10, 22
	lwzx	23, 10, 23
	lwzx	24, 10, 24
	lwzx	25, 10, 25
	xor	18, 18, 22
	xor	20, 20, 23
	xor	19, 19, 24
	xor	21, 21, 25
	rldicl	22, 15, 56, 56
	rldicl	23, 15, 24, 56
	rldicl	24, 14, 56, 56
	rldicl	25, 14, 24, 56
	slwi	22, 22, 2
	slwi	23, 23, 2
	slwi	24, 24, 2
	slwi	25, 25, 2
	lwzx	22, 11, 22
	lwzx	23, 11, 23
	lwzx	24, 11, 24
	lwzx	25, 11, 25
	xor	18, 18, 22
	xor	20, 20, 23
	xor	19, 19, 24
	xor	21, 21, 25
	rldicl	22, 15, 32, 56
	rldic	23, 14, 2, 54
	rldicl	24, 14, 32, 56
	rldic	25, 15, 2, 54
	slwi	22, 22, 2
	slwi	24, 24, 2
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
	rldicr	14, 14, 32, 63
	rldicr	15, 15, 32, 63
	#   XOR in Key Schedule
	xor	18, 18, 14
	xor	19, 19, 15
	rldicl	14, 19, 32, 56
	rldic	16, 18, 2, 54
	rldicl	15, 18, 32, 56
	rldic	17, 19, 2, 54
	slwi	14, 14, 2
	slwi	15, 15, 2
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
	ld	25, 0(10)
	ld	25, 0(10)
	ld	25, 0(10)
	ld	25, 0(10)
	ld	25, 0(10)
	ld	25, 0(10)
	ld	25, 0(10)
	ld	25, 0(10)
	ld	25, 0(10)
	ld	25, 0(10)
	ld	25, 0(10)
	ld	25, 0(10)
	ld	25, 0(10)
	ld	25, 0(10)
	ld	25, 0(10)
	ld	25, 0(10)
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
	lwzx	14, 10, 14
	lwzx	16, 10, 16
	lwzx	15, 10, 15
	lwzx	17, 10, 17
	rldicl	22, 19, 56, 56
	rldicl	23, 19, 24, 56
	rldicl	24, 18, 56, 56
	rldicl	25, 18, 24, 56
	slwi	22, 22, 2
	slwi	23, 23, 2
	slwi	24, 24, 2
	slwi	25, 25, 2
	lwzx	22, 10, 22
	lwzx	23, 10, 23
	lwzx	24, 10, 24
	lwzx	25, 10, 25
	rlwimi	14, 22, 8, 16, 23
	rlwimi	16, 23, 8, 16, 23
	rlwimi	15, 24, 8, 16, 23
	rlwimi	17, 25, 8, 16, 23
	rldicl	22, 18, 16, 56
	rldicl	23, 19, 48, 56
	rldicl	24, 19, 16, 56
	rldicl	25, 18, 48, 56
	slwi	22, 22, 2
	slwi	23, 23, 2
	slwi	24, 24, 2
	slwi	25, 25, 2
	lwzx	22, 10, 22
	lwzx	23, 10, 23
	lwzx	24, 10, 24
	lwzx	25, 10, 25
	rlwimi	14, 22, 16, 8, 15
	rlwimi	16, 23, 16, 8, 15
	rlwimi	15, 24, 16, 8, 15
	rlwimi	17, 25, 16, 8, 15
	rldicl	22, 18, 40, 56
	rldicl	23, 18, 8, 56
	rldicl	24, 19, 40, 56
	rldicl	25, 19, 8, 56
	slwi	22, 22, 2
	slwi	23, 23, 2
	slwi	24, 24, 2
	slwi	25, 25, 2
	lwzx	22, 10, 22
	lwzx	23, 10, 23
	lwzx	24, 10, 24
	lwzx	25, 10, 25
	rlwimi	14, 22, 24, 0, 7
	rlwimi	16, 23, 24, 0, 7
	rlwimi	15, 24, 24, 0, 7
	rlwimi	17, 25, 24, 0, 7
	ld	18, 0(26)
	ld	19, 8(26)
	rldimi	14, 16, 32, 0
	rldimi	15, 17, 32, 0
	addi	26, 26, 16
	rldicr	18, 18, 32, 63
	rldicr	19, 19, 32, 63
	#   XOR in Key Schedule
	xor	14, 14, 18
	xor	15, 15, 19
	rldicr	14, 14, 32, 63
	rldicr	15, 15, 32, 63
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
	.size	AES_CBC_encrypt,.-AES_CBC_encrypt
#endif /* HAVE_AES_CBC */
#ifdef WOLFSSL_AES_COUNTER
	.section	".text"
	.align	4
	.globl	AES_CTR_encrypt
	.type	AES_CTR_encrypt, @function
AES_CTR_encrypt:
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
	lis	9, L_AES_PPC64_te4_0@ha
	la	9, L_AES_PPC64_te4_0@l(9)
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
	# Round: 0 - XOR in key schedule
	xor	14, 22, 18
	xor	15, 23, 19
	rldicr	14, 14, 32, 63
	rldicr	15, 15, 32, 63
	addi	0, 7, -2
	srwi	0, 0, 1
	mtctr	0
L_AES_CTR_encrypt_loop_nr:
	rldicl	18, 14, 40, 56
	rldicl	20, 14, 8, 56
	rldicl	19, 15, 40, 56
	rldicl	21, 15, 8, 56
	slwi	18, 18, 2
	slwi	20, 20, 2
	slwi	19, 19, 2
	slwi	21, 21, 2
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
	lwzx	18, 9, 18
	lwzx	20, 9, 20
	lwzx	19, 9, 19
	lwzx	21, 9, 21
	rldicl	24, 14, 16, 56
	rldicl	25, 15, 48, 56
	rldicl	26, 15, 16, 56
	rldicl	27, 14, 48, 56
	slwi	24, 24, 2
	slwi	25, 25, 2
	slwi	26, 26, 2
	slwi	27, 27, 2
	lwzx	24, 10, 24
	lwzx	25, 10, 25
	lwzx	26, 10, 26
	lwzx	27, 10, 27
	xor	18, 18, 24
	xor	20, 20, 25
	xor	19, 19, 26
	xor	21, 21, 27
	rldicl	24, 15, 56, 56
	rldicl	25, 15, 24, 56
	rldicl	26, 14, 56, 56
	rldicl	27, 14, 24, 56
	slwi	24, 24, 2
	slwi	25, 25, 2
	slwi	26, 26, 2
	slwi	27, 27, 2
	lwzx	24, 11, 24
	lwzx	25, 11, 25
	lwzx	26, 11, 26
	lwzx	27, 11, 27
	xor	18, 18, 24
	xor	20, 20, 25
	xor	19, 19, 26
	xor	21, 21, 27
	rldicl	24, 15, 32, 56
	rldic	25, 14, 2, 54
	rldicl	26, 14, 32, 56
	rldic	27, 15, 2, 54
	slwi	24, 24, 2
	slwi	26, 26, 2
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
	rldicr	14, 14, 32, 63
	rldicr	15, 15, 32, 63
	#   XOR in Key Schedule
	xor	18, 18, 14
	xor	19, 19, 15
	rldicl	14, 18, 40, 56
	rldicl	16, 18, 8, 56
	rldicl	15, 19, 40, 56
	rldicl	17, 19, 8, 56
	slwi	14, 14, 2
	slwi	16, 16, 2
	slwi	15, 15, 2
	slwi	17, 17, 2
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
	lwzx	14, 9, 14
	lwzx	16, 9, 16
	lwzx	15, 9, 15
	lwzx	17, 9, 17
	rldicl	24, 18, 16, 56
	rldicl	25, 19, 48, 56
	rldicl	26, 19, 16, 56
	rldicl	27, 18, 48, 56
	slwi	24, 24, 2
	slwi	25, 25, 2
	slwi	26, 26, 2
	slwi	27, 27, 2
	lwzx	24, 10, 24
	lwzx	25, 10, 25
	lwzx	26, 10, 26
	lwzx	27, 10, 27
	xor	14, 14, 24
	xor	16, 16, 25
	xor	15, 15, 26
	xor	17, 17, 27
	rldicl	24, 19, 56, 56
	rldicl	25, 19, 24, 56
	rldicl	26, 18, 56, 56
	rldicl	27, 18, 24, 56
	slwi	24, 24, 2
	slwi	25, 25, 2
	slwi	26, 26, 2
	slwi	27, 27, 2
	lwzx	24, 11, 24
	lwzx	25, 11, 25
	lwzx	26, 11, 26
	lwzx	27, 11, 27
	xor	14, 14, 24
	xor	16, 16, 25
	xor	15, 15, 26
	xor	17, 17, 27
	rldicl	24, 19, 32, 56
	rldic	25, 18, 2, 54
	rldicl	26, 18, 32, 56
	rldic	27, 19, 2, 54
	slwi	24, 24, 2
	slwi	26, 26, 2
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
	rldicr	18, 18, 32, 63
	rldicr	19, 19, 32, 63
	#   XOR in Key Schedule
	xor	14, 14, 18
	xor	15, 15, 19
	bdnz	L_AES_CTR_encrypt_loop_nr
	rldicl	18, 14, 40, 56
	rldicl	20, 14, 8, 56
	rldicl	19, 15, 40, 56
	rldicl	21, 15, 8, 56
	slwi	18, 18, 2
	slwi	20, 20, 2
	slwi	19, 19, 2
	slwi	21, 21, 2
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
	ld	27, 0(9)
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
	lwzx	18, 9, 18
	lwzx	20, 9, 20
	lwzx	19, 9, 19
	lwzx	21, 9, 21
	rldicl	24, 14, 16, 56
	rldicl	25, 15, 48, 56
	rldicl	26, 15, 16, 56
	rldicl	27, 14, 48, 56
	slwi	24, 24, 2
	slwi	25, 25, 2
	slwi	26, 26, 2
	slwi	27, 27, 2
	lwzx	24, 10, 24
	lwzx	25, 10, 25
	lwzx	26, 10, 26
	lwzx	27, 10, 27
	xor	18, 18, 24
	xor	20, 20, 25
	xor	19, 19, 26
	xor	21, 21, 27
	rldicl	24, 15, 56, 56
	rldicl	25, 15, 24, 56
	rldicl	26, 14, 56, 56
	rldicl	27, 14, 24, 56
	slwi	24, 24, 2
	slwi	25, 25, 2
	slwi	26, 26, 2
	slwi	27, 27, 2
	lwzx	24, 11, 24
	lwzx	25, 11, 25
	lwzx	26, 11, 26
	lwzx	27, 11, 27
	xor	18, 18, 24
	xor	20, 20, 25
	xor	19, 19, 26
	xor	21, 21, 27
	rldicl	24, 15, 32, 56
	rldic	25, 14, 2, 54
	rldicl	26, 14, 32, 56
	rldic	27, 15, 2, 54
	slwi	24, 24, 2
	slwi	26, 26, 2
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
	rldicr	14, 14, 32, 63
	rldicr	15, 15, 32, 63
	#   XOR in Key Schedule
	xor	18, 18, 14
	xor	19, 19, 15
	rldicl	14, 19, 32, 56
	rldic	16, 18, 2, 54
	rldicl	15, 18, 32, 56
	rldic	17, 19, 2, 54
	slwi	14, 14, 2
	slwi	15, 15, 2
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
	ld	27, 0(10)
	ld	27, 0(10)
	ld	27, 0(10)
	ld	27, 0(10)
	ld	27, 0(10)
	ld	27, 0(10)
	ld	27, 0(10)
	ld	27, 0(10)
	ld	27, 0(10)
	ld	27, 0(10)
	ld	27, 0(10)
	ld	27, 0(10)
	ld	27, 0(10)
	ld	27, 0(10)
	ld	27, 0(10)
	ld	27, 0(10)
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
	lwzx	14, 10, 14
	lwzx	16, 10, 16
	lwzx	15, 10, 15
	lwzx	17, 10, 17
	rldicl	24, 19, 56, 56
	rldicl	25, 19, 24, 56
	rldicl	26, 18, 56, 56
	rldicl	27, 18, 24, 56
	slwi	24, 24, 2
	slwi	25, 25, 2
	slwi	26, 26, 2
	slwi	27, 27, 2
	lwzx	24, 10, 24
	lwzx	25, 10, 25
	lwzx	26, 10, 26
	lwzx	27, 10, 27
	rlwimi	14, 24, 8, 16, 23
	rlwimi	16, 25, 8, 16, 23
	rlwimi	15, 26, 8, 16, 23
	rlwimi	17, 27, 8, 16, 23
	rldicl	24, 18, 16, 56
	rldicl	25, 19, 48, 56
	rldicl	26, 19, 16, 56
	rldicl	27, 18, 48, 56
	slwi	24, 24, 2
	slwi	25, 25, 2
	slwi	26, 26, 2
	slwi	27, 27, 2
	lwzx	24, 10, 24
	lwzx	25, 10, 25
	lwzx	26, 10, 26
	lwzx	27, 10, 27
	rlwimi	14, 24, 16, 8, 15
	rlwimi	16, 25, 16, 8, 15
	rlwimi	15, 26, 16, 8, 15
	rlwimi	17, 27, 16, 8, 15
	rldicl	24, 18, 40, 56
	rldicl	25, 18, 8, 56
	rldicl	26, 19, 40, 56
	rldicl	27, 19, 8, 56
	slwi	24, 24, 2
	slwi	25, 25, 2
	slwi	26, 26, 2
	slwi	27, 27, 2
	lwzx	24, 10, 24
	lwzx	25, 10, 25
	lwzx	26, 10, 26
	lwzx	27, 10, 27
	rlwimi	14, 24, 24, 0, 7
	rlwimi	16, 25, 24, 0, 7
	rlwimi	15, 26, 24, 0, 7
	rlwimi	17, 27, 24, 0, 7
	ld	18, 0(28)
	ld	19, 8(28)
	rldimi	14, 16, 32, 0
	rldimi	15, 17, 32, 0
	addi	28, 28, 16
	rldicr	18, 18, 32, 63
	rldicr	19, 19, 32, 63
	#   XOR in Key Schedule
	xor	14, 14, 18
	xor	15, 15, 19
	rldicr	14, 14, 32, 63
	rldicr	15, 15, 32, 63
	ld	18, 0(3)
	ld	19, 8(3)
	xor	14, 14, 18
	xor	15, 15, 19
	std	14, 0(4)
	std	15, 8(4)
	rldicr	15, 15, 32, 63
	rldicr	14, 14, 32, 63
	addic	23, 23, 1
	addze	22, 22
	rldicr	15, 15, 32, 63
	rldicr	14, 14, 32, 63
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
	.size	AES_CTR_encrypt,.-AES_CTR_encrypt
#endif /* WOLFSSL_AES_COUNTER */
#ifdef HAVE_AESGCM
	.section	".text"
	.align	4
	.globl	AES_GCM_encrypt
	.type	AES_GCM_encrypt, @function
AES_GCM_encrypt:
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
	lis	9, L_AES_PPC64_te4_0@ha
	la	9, L_AES_PPC64_te4_0@l(9)
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
	# Round: 0 - XOR in key schedule
	xor	14, 26, 18
	xor	15, 27, 19
	rldicr	14, 14, 32, 63
	rldicr	15, 15, 32, 63
	addi	0, 7, -2
	srwi	0, 0, 1
	mtctr	0
L_AES_GCM_encrypt_loop_nr:
	rldicl	18, 14, 40, 56
	rldicl	20, 14, 8, 56
	rldicl	19, 15, 40, 56
	rldicl	21, 15, 8, 56
	slwi	18, 18, 2
	slwi	20, 20, 2
	slwi	19, 19, 2
	slwi	21, 21, 2
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
	lwzx	18, 9, 18
	lwzx	20, 9, 20
	lwzx	19, 9, 19
	lwzx	21, 9, 21
	rldicl	22, 14, 16, 56
	rldicl	23, 15, 48, 56
	rldicl	24, 15, 16, 56
	rldicl	25, 14, 48, 56
	slwi	22, 22, 2
	slwi	23, 23, 2
	slwi	24, 24, 2
	slwi	25, 25, 2
	lwzx	22, 10, 22
	lwzx	23, 10, 23
	lwzx	24, 10, 24
	lwzx	25, 10, 25
	xor	18, 18, 22
	xor	20, 20, 23
	xor	19, 19, 24
	xor	21, 21, 25
	rldicl	22, 15, 56, 56
	rldicl	23, 15, 24, 56
	rldicl	24, 14, 56, 56
	rldicl	25, 14, 24, 56
	slwi	22, 22, 2
	slwi	23, 23, 2
	slwi	24, 24, 2
	slwi	25, 25, 2
	lwzx	22, 11, 22
	lwzx	23, 11, 23
	lwzx	24, 11, 24
	lwzx	25, 11, 25
	xor	18, 18, 22
	xor	20, 20, 23
	xor	19, 19, 24
	xor	21, 21, 25
	rldicl	22, 15, 32, 56
	rldic	23, 14, 2, 54
	rldicl	24, 14, 32, 56
	rldic	25, 15, 2, 54
	slwi	22, 22, 2
	slwi	24, 24, 2
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
	rldicr	14, 14, 32, 63
	rldicr	15, 15, 32, 63
	#   XOR in Key Schedule
	xor	18, 18, 14
	xor	19, 19, 15
	rldicl	14, 18, 40, 56
	rldicl	16, 18, 8, 56
	rldicl	15, 19, 40, 56
	rldicl	17, 19, 8, 56
	slwi	14, 14, 2
	slwi	16, 16, 2
	slwi	15, 15, 2
	slwi	17, 17, 2
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
	lwzx	14, 9, 14
	lwzx	16, 9, 16
	lwzx	15, 9, 15
	lwzx	17, 9, 17
	rldicl	22, 18, 16, 56
	rldicl	23, 19, 48, 56
	rldicl	24, 19, 16, 56
	rldicl	25, 18, 48, 56
	slwi	22, 22, 2
	slwi	23, 23, 2
	slwi	24, 24, 2
	slwi	25, 25, 2
	lwzx	22, 10, 22
	lwzx	23, 10, 23
	lwzx	24, 10, 24
	lwzx	25, 10, 25
	xor	14, 14, 22
	xor	16, 16, 23
	xor	15, 15, 24
	xor	17, 17, 25
	rldicl	22, 19, 56, 56
	rldicl	23, 19, 24, 56
	rldicl	24, 18, 56, 56
	rldicl	25, 18, 24, 56
	slwi	22, 22, 2
	slwi	23, 23, 2
	slwi	24, 24, 2
	slwi	25, 25, 2
	lwzx	22, 11, 22
	lwzx	23, 11, 23
	lwzx	24, 11, 24
	lwzx	25, 11, 25
	xor	14, 14, 22
	xor	16, 16, 23
	xor	15, 15, 24
	xor	17, 17, 25
	rldicl	22, 19, 32, 56
	rldic	23, 18, 2, 54
	rldicl	24, 18, 32, 56
	rldic	25, 19, 2, 54
	slwi	22, 22, 2
	slwi	24, 24, 2
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
	rldicr	18, 18, 32, 63
	rldicr	19, 19, 32, 63
	#   XOR in Key Schedule
	xor	14, 14, 18
	xor	15, 15, 19
	bdnz	L_AES_GCM_encrypt_loop_nr
	rldicl	18, 14, 40, 56
	rldicl	20, 14, 8, 56
	rldicl	19, 15, 40, 56
	rldicl	21, 15, 8, 56
	slwi	18, 18, 2
	slwi	20, 20, 2
	slwi	19, 19, 2
	slwi	21, 21, 2
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
	ld	25, 0(9)
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
	lwzx	18, 9, 18
	lwzx	20, 9, 20
	lwzx	19, 9, 19
	lwzx	21, 9, 21
	rldicl	22, 14, 16, 56
	rldicl	23, 15, 48, 56
	rldicl	24, 15, 16, 56
	rldicl	25, 14, 48, 56
	slwi	22, 22, 2
	slwi	23, 23, 2
	slwi	24, 24, 2
	slwi	25, 25, 2
	lwzx	22, 10, 22
	lwzx	23, 10, 23
	lwzx	24, 10, 24
	lwzx	25, 10, 25
	xor	18, 18, 22
	xor	20, 20, 23
	xor	19, 19, 24
	xor	21, 21, 25
	rldicl	22, 15, 56, 56
	rldicl	23, 15, 24, 56
	rldicl	24, 14, 56, 56
	rldicl	25, 14, 24, 56
	slwi	22, 22, 2
	slwi	23, 23, 2
	slwi	24, 24, 2
	slwi	25, 25, 2
	lwzx	22, 11, 22
	lwzx	23, 11, 23
	lwzx	24, 11, 24
	lwzx	25, 11, 25
	xor	18, 18, 22
	xor	20, 20, 23
	xor	19, 19, 24
	xor	21, 21, 25
	rldicl	22, 15, 32, 56
	rldic	23, 14, 2, 54
	rldicl	24, 14, 32, 56
	rldic	25, 15, 2, 54
	slwi	22, 22, 2
	slwi	24, 24, 2
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
	rldicr	14, 14, 32, 63
	rldicr	15, 15, 32, 63
	#   XOR in Key Schedule
	xor	18, 18, 14
	xor	19, 19, 15
	rldicl	14, 19, 32, 56
	rldic	16, 18, 2, 54
	rldicl	15, 18, 32, 56
	rldic	17, 19, 2, 54
	slwi	14, 14, 2
	slwi	15, 15, 2
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
	ld	25, 0(10)
	ld	25, 0(10)
	ld	25, 0(10)
	ld	25, 0(10)
	ld	25, 0(10)
	ld	25, 0(10)
	ld	25, 0(10)
	ld	25, 0(10)
	ld	25, 0(10)
	ld	25, 0(10)
	ld	25, 0(10)
	ld	25, 0(10)
	ld	25, 0(10)
	ld	25, 0(10)
	ld	25, 0(10)
	ld	25, 0(10)
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
	lwzx	14, 10, 14
	lwzx	16, 10, 16
	lwzx	15, 10, 15
	lwzx	17, 10, 17
	rldicl	22, 19, 56, 56
	rldicl	23, 19, 24, 56
	rldicl	24, 18, 56, 56
	rldicl	25, 18, 24, 56
	slwi	22, 22, 2
	slwi	23, 23, 2
	slwi	24, 24, 2
	slwi	25, 25, 2
	lwzx	22, 10, 22
	lwzx	23, 10, 23
	lwzx	24, 10, 24
	lwzx	25, 10, 25
	rlwimi	14, 22, 8, 16, 23
	rlwimi	16, 23, 8, 16, 23
	rlwimi	15, 24, 8, 16, 23
	rlwimi	17, 25, 8, 16, 23
	rldicl	22, 18, 16, 56
	rldicl	23, 19, 48, 56
	rldicl	24, 19, 16, 56
	rldicl	25, 18, 48, 56
	slwi	22, 22, 2
	slwi	23, 23, 2
	slwi	24, 24, 2
	slwi	25, 25, 2
	lwzx	22, 10, 22
	lwzx	23, 10, 23
	lwzx	24, 10, 24
	lwzx	25, 10, 25
	rlwimi	14, 22, 16, 8, 15
	rlwimi	16, 23, 16, 8, 15
	rlwimi	15, 24, 16, 8, 15
	rlwimi	17, 25, 16, 8, 15
	rldicl	22, 18, 40, 56
	rldicl	23, 18, 8, 56
	rldicl	24, 19, 40, 56
	rldicl	25, 19, 8, 56
	slwi	22, 22, 2
	slwi	23, 23, 2
	slwi	24, 24, 2
	slwi	25, 25, 2
	lwzx	22, 10, 22
	lwzx	23, 10, 23
	lwzx	24, 10, 24
	lwzx	25, 10, 25
	rlwimi	14, 22, 24, 0, 7
	rlwimi	16, 23, 24, 0, 7
	rlwimi	15, 24, 24, 0, 7
	rlwimi	17, 25, 24, 0, 7
	ld	18, 0(28)
	ld	19, 8(28)
	rldimi	14, 16, 32, 0
	rldimi	15, 17, 32, 0
	addi	28, 28, 16
	rldicr	18, 18, 32, 63
	rldicr	19, 19, 32, 63
	#   XOR in Key Schedule
	xor	14, 14, 18
	xor	15, 15, 19
	rldicr	14, 14, 32, 63
	rldicr	15, 15, 32, 63
	ld	18, 0(3)
	ld	19, 8(3)
	xor	14, 14, 18
	xor	15, 15, 19
	std	14, 0(4)
	std	15, 8(4)
	addi	3, 3, 16
	addi	4, 4, 16
	addic.	5, 5, -16
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
	.size	AES_GCM_encrypt,.-AES_GCM_encrypt
#endif /* HAVE_AESGCM */
#ifdef WOLFSSL_AES_XTS
#endif /* WOLFSSL_AES_XTS */
#ifdef HAVE_AES_DECRYPT
#if defined(WOLFSSL_AES_DIRECT) || defined(WOLFSSL_AES_COUNTER) || \
    defined(HAVE_AES_CBC) || defined(HAVE_AES_ECB)
	.section	".text"
	.section	.rodata
	.type	L_AES_PPC64_td4, @object
	.size	L_AES_PPC64_td4, 256
	.align	4
L_AES_PPC64_td4:
	.byte	0x52
	.byte	0x9
	.byte	0x6a
	.byte	0xd5
	.byte	0x30
	.byte	0x36
	.byte	0xa5
	.byte	0x38
	.byte	0xbf
	.byte	0x40
	.byte	0xa3
	.byte	0x9e
	.byte	0x81
	.byte	0xf3
	.byte	0xd7
	.byte	0xfb
	.byte	0x7c
	.byte	0xe3
	.byte	0x39
	.byte	0x82
	.byte	0x9b
	.byte	0x2f
	.byte	0xff
	.byte	0x87
	.byte	0x34
	.byte	0x8e
	.byte	0x43
	.byte	0x44
	.byte	0xc4
	.byte	0xde
	.byte	0xe9
	.byte	0xcb
	.byte	0x54
	.byte	0x7b
	.byte	0x94
	.byte	0x32
	.byte	0xa6
	.byte	0xc2
	.byte	0x23
	.byte	0x3d
	.byte	0xee
	.byte	0x4c
	.byte	0x95
	.byte	0xb
	.byte	0x42
	.byte	0xfa
	.byte	0xc3
	.byte	0x4e
	.byte	0x8
	.byte	0x2e
	.byte	0xa1
	.byte	0x66
	.byte	0x28
	.byte	0xd9
	.byte	0x24
	.byte	0xb2
	.byte	0x76
	.byte	0x5b
	.byte	0xa2
	.byte	0x49
	.byte	0x6d
	.byte	0x8b
	.byte	0xd1
	.byte	0x25
	.byte	0x72
	.byte	0xf8
	.byte	0xf6
	.byte	0x64
	.byte	0x86
	.byte	0x68
	.byte	0x98
	.byte	0x16
	.byte	0xd4
	.byte	0xa4
	.byte	0x5c
	.byte	0xcc
	.byte	0x5d
	.byte	0x65
	.byte	0xb6
	.byte	0x92
	.byte	0x6c
	.byte	0x70
	.byte	0x48
	.byte	0x50
	.byte	0xfd
	.byte	0xed
	.byte	0xb9
	.byte	0xda
	.byte	0x5e
	.byte	0x15
	.byte	0x46
	.byte	0x57
	.byte	0xa7
	.byte	0x8d
	.byte	0x9d
	.byte	0x84
	.byte	0x90
	.byte	0xd8
	.byte	0xab
	.byte	0x0
	.byte	0x8c
	.byte	0xbc
	.byte	0xd3
	.byte	0xa
	.byte	0xf7
	.byte	0xe4
	.byte	0x58
	.byte	0x5
	.byte	0xb8
	.byte	0xb3
	.byte	0x45
	.byte	0x6
	.byte	0xd0
	.byte	0x2c
	.byte	0x1e
	.byte	0x8f
	.byte	0xca
	.byte	0x3f
	.byte	0xf
	.byte	0x2
	.byte	0xc1
	.byte	0xaf
	.byte	0xbd
	.byte	0x3
	.byte	0x1
	.byte	0x13
	.byte	0x8a
	.byte	0x6b
	.byte	0x3a
	.byte	0x91
	.byte	0x11
	.byte	0x41
	.byte	0x4f
	.byte	0x67
	.byte	0xdc
	.byte	0xea
	.byte	0x97
	.byte	0xf2
	.byte	0xcf
	.byte	0xce
	.byte	0xf0
	.byte	0xb4
	.byte	0xe6
	.byte	0x73
	.byte	0x96
	.byte	0xac
	.byte	0x74
	.byte	0x22
	.byte	0xe7
	.byte	0xad
	.byte	0x35
	.byte	0x85
	.byte	0xe2
	.byte	0xf9
	.byte	0x37
	.byte	0xe8
	.byte	0x1c
	.byte	0x75
	.byte	0xdf
	.byte	0x6e
	.byte	0x47
	.byte	0xf1
	.byte	0x1a
	.byte	0x71
	.byte	0x1d
	.byte	0x29
	.byte	0xc5
	.byte	0x89
	.byte	0x6f
	.byte	0xb7
	.byte	0x62
	.byte	0xe
	.byte	0xaa
	.byte	0x18
	.byte	0xbe
	.byte	0x1b
	.byte	0xfc
	.byte	0x56
	.byte	0x3e
	.byte	0x4b
	.byte	0xc6
	.byte	0xd2
	.byte	0x79
	.byte	0x20
	.byte	0x9a
	.byte	0xdb
	.byte	0xc0
	.byte	0xfe
	.byte	0x78
	.byte	0xcd
	.byte	0x5a
	.byte	0xf4
	.byte	0x1f
	.byte	0xdd
	.byte	0xa8
	.byte	0x33
	.byte	0x88
	.byte	0x7
	.byte	0xc7
	.byte	0x31
	.byte	0xb1
	.byte	0x12
	.byte	0x10
	.byte	0x59
	.byte	0x27
	.byte	0x80
	.byte	0xec
	.byte	0x5f
	.byte	0x60
	.byte	0x51
	.byte	0x7f
	.byte	0xa9
	.byte	0x19
	.byte	0xb5
	.byte	0x4a
	.byte	0xd
	.byte	0x2d
	.byte	0xe5
	.byte	0x7a
	.byte	0x9f
	.byte	0x93
	.byte	0xc9
	.byte	0x9c
	.byte	0xef
	.byte	0xa0
	.byte	0xe0
	.byte	0x3b
	.byte	0x4d
	.byte	0xae
	.byte	0x2a
	.byte	0xf5
	.byte	0xb0
	.byte	0xc8
	.byte	0xeb
	.byte	0xbb
	.byte	0x3c
	.byte	0x83
	.byte	0x53
	.byte	0x99
	.byte	0x61
	.byte	0x17
	.byte	0x2b
	.byte	0x4
	.byte	0x7e
	.byte	0xba
	.byte	0x77
	.byte	0xd6
	.byte	0x26
	.byte	0xe1
	.byte	0x69
	.byte	0x14
	.byte	0x63
	.byte	0x55
	.byte	0x21
	.byte	0xc
	.byte	0x7d
#if defined(WOLFSSL_AES_DIRECT) || defined(WOLFSSL_AES_COUNTER) || defined(HAVE_AES_ECB)
	.section	".text"
	.align	4
	.globl	AES_ECB_decrypt
	.type	AES_ECB_decrypt, @function
AES_ECB_decrypt:
	stdu	1, -72(1)
	mflr	0
	std	0, 64(1)
	std	14, 0(1)
	std	15, 8(1)
	std	16, 16(1)
	std	17, 24(1)
	std	18, 32(1)
	std	19, 40(1)
	std	20, 48(1)
	std	21, 56(1)
	lis	8, L_AES_PPC64_td@ha
	la	8, L_AES_PPC64_td@l(8)
	lis	9, L_AES_PPC64_td4@ha
	la	9, L_AES_PPC64_td4@l(9)
L_AES_ECB_decrypt_loop_block:
	addi	21, 6, 0
	ld	10, 0(3)
	ld	11, 8(3)
	ld	15, 0(21)
	ld	16, 8(21)
	addi	21, 21, 16
	# Round: 0 - XOR in key schedule
	xor	10, 10, 15
	xor	11, 11, 16
	rldicr	10, 10, 32, 63
	rldicr	11, 11, 32, 63
	addi	0, 7, -2
	srwi	0, 0, 1
	mtctr	0
L_AES_ECB_decrypt_loop_nr:
	rldicl	15, 11, 16, 56
	rldicl	18, 10, 40, 56
	rldicl	19, 11, 56, 56
	rldicl	20, 10, 32, 56
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
	ld	12, 0(8)
	ld	12, 64(8)
	ld	12, 128(8)
	ld	12, 192(8)
	ld	12, 256(8)
	ld	12, 320(8)
	ld	12, 384(8)
	ld	12, 448(8)
	ld	12, 512(8)
	ld	12, 576(8)
	ld	12, 640(8)
	ld	12, 704(8)
	ld	12, 768(8)
	ld	12, 832(8)
	ld	12, 896(8)
	ld	12, 960(8)
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
	slwi	15, 15, 2
	slwi	18, 18, 2
	slwi	19, 19, 2
	slwi	20, 20, 2
	lwzx	15, 8, 15
	lwzx	18, 8, 18
	lwzx	19, 8, 19
	lwzx	20, 8, 20
	rldicl	16, 10, 48, 56
	rlwimi	18, 18, 8, 0, 31
	xor	15, 15, 18
	rldicl	18, 10, 8, 56
	rlwimi	19, 19, 24, 0, 31
	xor	15, 15, 19
	rldicl	19, 11, 24, 56
	rlwimi	20, 20, 16, 0, 31
	xor	15, 15, 20
	andi.   20, 11, 255
	slwi	16, 16, 2
	slwi	18, 18, 2
	slwi	19, 19, 2
	slwi	20, 20, 2
	lwzx	16, 8, 16
	lwzx	18, 8, 18
	lwzx	19, 8, 19
	lwzx	20, 8, 20
	rldicl	17, 10, 16, 56
	rlwimi	18, 18, 8, 0, 31
	xor	16, 16, 18
	rldicl	18, 11, 40, 56
	rlwimi	19, 19, 24, 0, 31
	xor	16, 16, 19
	rldicl	19, 10, 56, 56
	rlwimi	20, 20, 16, 0, 31
	xor	16, 16, 20
	rldicl	20, 11, 32, 56
	rldimi	15, 16, 32, 0
	slwi	17, 17, 2
	slwi	18, 18, 2
	slwi	19, 19, 2
	slwi	20, 20, 2
	lwzx	17, 8, 17
	lwzx	18, 8, 18
	lwzx	19, 8, 19
	lwzx	20, 8, 20
	andi.   12, 10, 255
	rlwimi	18, 18, 8, 0, 31
	xor	17, 17, 18
	rldicl	18, 11, 48, 56
	rlwimi	19, 19, 24, 0, 31
	xor	17, 17, 19
	rldicl	19, 11, 8, 56
	rlwimi	20, 20, 16, 0, 31
	xor	16, 17, 20
	rldicl	20, 10, 24, 56
	slwi	12, 12, 2
	slwi	19, 19, 2
	slwi	18, 18, 2
	slwi	20, 20, 2
	lwzx	12, 8, 12
	lwzx	19, 8, 19
	lwzx	18, 8, 18
	lwzx	20, 8, 20
	rlwimi	12, 12, 8, 0, 31
	xor	19, 19, 12
	ld	10, 0(21)
	rlwimi	20, 20, 24, 0, 31
	rldicr	10, 10, 32, 63
	xor	18, 18, 20
	ld	11, 8(21)
	rlwimi	19, 19, 8, 0, 31
	rldicr	11, 11, 32, 63
	xor	18, 18, 19
	addi	21, 21, 16
	rldimi	16, 18, 32, 0
	#   XOR in Key Schedule
	xor	15, 15, 10
	xor	16, 16, 11
	rldicl	10, 16, 16, 56
	rldicl	14, 15, 40, 56
	rldicl	19, 16, 56, 56
	rldicl	20, 15, 32, 56
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
	ld	17, 0(8)
	ld	17, 64(8)
	ld	17, 128(8)
	ld	17, 192(8)
	ld	17, 256(8)
	ld	17, 320(8)
	ld	17, 384(8)
	ld	17, 448(8)
	ld	17, 512(8)
	ld	17, 576(8)
	ld	17, 640(8)
	ld	17, 704(8)
	ld	17, 768(8)
	ld	17, 832(8)
	ld	17, 896(8)
	ld	17, 960(8)
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
	slwi	10, 10, 2
	slwi	14, 14, 2
	slwi	19, 19, 2
	slwi	20, 20, 2
	lwzx	10, 8, 10
	lwzx	14, 8, 14
	lwzx	19, 8, 19
	lwzx	20, 8, 20
	rldicl	11, 15, 48, 56
	rlwimi	14, 14, 8, 0, 31
	xor	10, 10, 14
	rldicl	14, 15, 8, 56
	rlwimi	19, 19, 24, 0, 31
	xor	10, 10, 19
	rldicl	19, 16, 24, 56
	rlwimi	20, 20, 16, 0, 31
	xor	10, 10, 20
	andi.   20, 16, 255
	slwi	11, 11, 2
	slwi	14, 14, 2
	slwi	19, 19, 2
	slwi	20, 20, 2
	lwzx	11, 8, 11
	lwzx	14, 8, 14
	lwzx	19, 8, 19
	lwzx	20, 8, 20
	rldicl	12, 15, 16, 56
	rlwimi	14, 14, 8, 0, 31
	xor	11, 11, 14
	rldicl	14, 16, 40, 56
	rlwimi	19, 19, 24, 0, 31
	xor	11, 11, 19
	rldicl	19, 15, 56, 56
	rlwimi	20, 20, 16, 0, 31
	xor	11, 11, 20
	rldicl	20, 16, 32, 56
	rldimi	10, 11, 32, 0
	slwi	12, 12, 2
	slwi	14, 14, 2
	slwi	19, 19, 2
	slwi	20, 20, 2
	lwzx	12, 8, 12
	lwzx	14, 8, 14
	lwzx	19, 8, 19
	lwzx	20, 8, 20
	andi.   17, 15, 255
	rlwimi	14, 14, 8, 0, 31
	xor	12, 12, 14
	rldicl	14, 16, 48, 56
	rlwimi	19, 19, 24, 0, 31
	xor	12, 12, 19
	rldicl	19, 16, 8, 56
	rlwimi	20, 20, 16, 0, 31
	xor	11, 12, 20
	rldicl	20, 15, 24, 56
	slwi	17, 17, 2
	slwi	19, 19, 2
	slwi	14, 14, 2
	slwi	20, 20, 2
	lwzx	17, 8, 17
	lwzx	19, 8, 19
	lwzx	14, 8, 14
	lwzx	20, 8, 20
	rlwimi	17, 17, 8, 0, 31
	xor	19, 19, 17
	ld	15, 0(21)
	rlwimi	20, 20, 24, 0, 31
	rldicr	15, 15, 32, 63
	xor	14, 14, 20
	ld	16, 8(21)
	rlwimi	19, 19, 8, 0, 31
	rldicr	16, 16, 32, 63
	xor	14, 14, 19
	addi	21, 21, 16
	rldimi	11, 14, 32, 0
	#   XOR in Key Schedule
	xor	10, 10, 15
	xor	11, 11, 16
	bdnz	L_AES_ECB_decrypt_loop_nr
	rldicl	15, 11, 16, 56
	rldicl	18, 10, 40, 56
	rldicl	19, 11, 56, 56
	rldicl	20, 10, 32, 56
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
	ld	12, 0(8)
	ld	12, 64(8)
	ld	12, 128(8)
	ld	12, 192(8)
	ld	12, 256(8)
	ld	12, 320(8)
	ld	12, 384(8)
	ld	12, 448(8)
	ld	12, 512(8)
	ld	12, 576(8)
	ld	12, 640(8)
	ld	12, 704(8)
	ld	12, 768(8)
	ld	12, 832(8)
	ld	12, 896(8)
	ld	12, 960(8)
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
	slwi	15, 15, 2
	slwi	18, 18, 2
	slwi	19, 19, 2
	slwi	20, 20, 2
	lwzx	15, 8, 15
	lwzx	18, 8, 18
	lwzx	19, 8, 19
	lwzx	20, 8, 20
	rldicl	16, 10, 48, 56
	rlwimi	18, 18, 8, 0, 31
	xor	15, 15, 18
	rldicl	18, 10, 8, 56
	rlwimi	19, 19, 24, 0, 31
	xor	15, 15, 19
	rldicl	19, 11, 24, 56
	rlwimi	20, 20, 16, 0, 31
	xor	15, 15, 20
	andi.   20, 11, 255
	slwi	16, 16, 2
	slwi	18, 18, 2
	slwi	19, 19, 2
	slwi	20, 20, 2
	lwzx	16, 8, 16
	lwzx	18, 8, 18
	lwzx	19, 8, 19
	lwzx	20, 8, 20
	rldicl	17, 10, 16, 56
	rlwimi	18, 18, 8, 0, 31
	xor	16, 16, 18
	rldicl	18, 11, 40, 56
	rlwimi	19, 19, 24, 0, 31
	xor	16, 16, 19
	rldicl	19, 10, 56, 56
	rlwimi	20, 20, 16, 0, 31
	xor	16, 16, 20
	rldicl	20, 11, 32, 56
	rldimi	15, 16, 32, 0
	slwi	17, 17, 2
	slwi	18, 18, 2
	slwi	19, 19, 2
	slwi	20, 20, 2
	lwzx	17, 8, 17
	lwzx	18, 8, 18
	lwzx	19, 8, 19
	lwzx	20, 8, 20
	andi.   12, 10, 255
	rlwimi	18, 18, 8, 0, 31
	xor	17, 17, 18
	rldicl	18, 11, 48, 56
	rlwimi	19, 19, 24, 0, 31
	xor	17, 17, 19
	rldicl	19, 11, 8, 56
	rlwimi	20, 20, 16, 0, 31
	xor	16, 17, 20
	rldicl	20, 10, 24, 56
	slwi	12, 12, 2
	slwi	19, 19, 2
	slwi	18, 18, 2
	slwi	20, 20, 2
	lwzx	12, 8, 12
	lwzx	19, 8, 19
	lwzx	18, 8, 18
	lwzx	20, 8, 20
	rlwimi	12, 12, 8, 0, 31
	xor	19, 19, 12
	ld	10, 0(21)
	rlwimi	20, 20, 24, 0, 31
	rldicr	10, 10, 32, 63
	xor	18, 18, 20
	ld	11, 8(21)
	rlwimi	19, 19, 8, 0, 31
	rldicr	11, 11, 32, 63
	xor	18, 18, 19
	addi	21, 21, 16
	rldimi	16, 18, 32, 0
	#   XOR in Key Schedule
	xor	15, 15, 10
	xor	16, 16, 11
	rldicl	10, 15, 32, 56
	rldicl	14, 16, 56, 56
	rldicl	19, 16, 16, 56
	rldicl	20, 15, 40, 56
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
	ld	18, 0(9)
	ld	18, 64(9)
	ld	18, 128(9)
	ld	18, 192(9)
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
	lbzx	10, 9, 10
	lbzx	14, 9, 14
	lbzx	19, 9, 19
	lbzx	20, 9, 20
	andi.   11, 16, 255
	rlwimi	10, 14, 8, 16, 23
	rldicl	14, 16, 24, 56
	rlwimi	10, 19, 16, 8, 15
	rldicl	19, 15, 48, 56
	rlwimi	10, 20, 24, 0, 7
	rldicl	20, 15, 8, 56
	lbzx	14, 9, 14
	lbzx	20, 9, 20
	lbzx	11, 9, 11
	lbzx	19, 9, 19
	rldicl	12, 16, 32, 56
	rlwimi	11, 14, 8, 16, 23
	rldicl	14, 15, 56, 56
	rlwimi	11, 19, 16, 8, 15
	rldicl	19, 15, 16, 56
	rlwimi	11, 20, 24, 0, 7
	rldicl	20, 16, 40, 56
	rldimi	10, 11, 32, 0
	lbzx	14, 9, 14
	lbzx	19, 9, 19
	lbzx	11, 9, 12
	lbzx	20, 9, 20
	rldicl	18, 16, 8, 56
	rlwimi	11, 14, 8, 16, 23
	andi.   14, 15, 255
	rlwimi	11, 19, 16, 8, 15
	rldicl	19, 15, 24, 56
	rlwimi	11, 20, 24, 0, 7
	rldicl	20, 16, 48, 56
	lbzx	18, 9, 18
	lbzx	19, 9, 19
	lbzx	14, 9, 14
	lbzx	20, 9, 20
	ld	15, 0(21)
	rlwimi	14, 18, 24, 0, 7
	rldicr	15, 15, 32, 63
	rlwimi	14, 20, 16, 8, 15
	ld	16, 8(21)
	rlwimi	14, 19, 8, 16, 23
	rldicr	16, 16, 32, 63
	rldimi	11, 14, 32, 0
	#   XOR in Key Schedule
	xor	10, 10, 15
	xor	11, 11, 16
	rldicr	10, 10, 32, 63
	rldicr	11, 11, 32, 63
	std	10, 0(4)
	std	11, 8(4)
	addi	3, 3, 16
	addi	4, 4, 16
	addic.	5, 5, -16
	bne	L_AES_ECB_decrypt_loop_block
	ld	0, 64(1)
	mtlr	0
	ld	14, 0(1)
	ld	15, 8(1)
	ld	16, 16(1)
	ld	17, 24(1)
	ld	18, 32(1)
	ld	19, 40(1)
	ld	20, 48(1)
	ld	21, 56(1)
	addi	1, 1, 0x48
	blr
	.size	AES_ECB_decrypt,.-AES_ECB_decrypt
#endif /* WOLFSSL_AES_DIRECT || WOLFSSL_AES_COUNTER || defined(HAVE_AES_ECB) */
#ifdef HAVE_AES_CBC
	.section	".text"
	.align	4
	.globl	AES_CBC_decrypt
	.type	AES_CBC_decrypt, @function
AES_CBC_decrypt:
	stdu	1, -80(1)
	mflr	0
	std	0, 72(1)
	std	14, 0(1)
	std	15, 8(1)
	std	16, 16(1)
	std	17, 24(1)
	std	18, 32(1)
	std	19, 40(1)
	std	20, 48(1)
	std	21, 56(1)
	std	22, 64(1)
	lis	10, L_AES_PPC64_td4@ha
	la	10, L_AES_PPC64_td4@l(10)
	lis	9, L_AES_PPC64_td@ha
	la	9, L_AES_PPC64_td@l(9)
L_AES_CBC_decrypt_loop_block:
	addi	22, 6, 0
	ld	11, 0(3)
	ld	12, 8(3)
	std	11, 16(8)
	std	12, 24(8)
	ld	16, 0(22)
	ld	17, 8(22)
	addi	22, 22, 16
	# Round: 0 - XOR in key schedule
	xor	11, 11, 16
	xor	12, 12, 17
	rldicr	11, 11, 32, 63
	rldicr	12, 12, 32, 63
	addi	0, 7, -2
	srwi	0, 0, 1
	mtctr	0
L_AES_CBC_decrypt_loop_nr_even:
	rldicl	16, 12, 16, 56
	rldicl	19, 11, 40, 56
	rldicl	20, 12, 56, 56
	rldicl	21, 11, 32, 56
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
	ld	14, 0(9)
	ld	14, 64(9)
	ld	14, 128(9)
	ld	14, 192(9)
	ld	14, 256(9)
	ld	14, 320(9)
	ld	14, 384(9)
	ld	14, 448(9)
	ld	14, 512(9)
	ld	14, 576(9)
	ld	14, 640(9)
	ld	14, 704(9)
	ld	14, 768(9)
	ld	14, 832(9)
	ld	14, 896(9)
	ld	14, 960(9)
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
	slwi	16, 16, 2
	slwi	19, 19, 2
	slwi	20, 20, 2
	slwi	21, 21, 2
	lwzx	16, 9, 16
	lwzx	19, 9, 19
	lwzx	20, 9, 20
	lwzx	21, 9, 21
	rldicl	17, 11, 48, 56
	rlwimi	19, 19, 8, 0, 31
	xor	16, 16, 19
	rldicl	19, 11, 8, 56
	rlwimi	20, 20, 24, 0, 31
	xor	16, 16, 20
	rldicl	20, 12, 24, 56
	rlwimi	21, 21, 16, 0, 31
	xor	16, 16, 21
	andi.   21, 12, 255
	slwi	17, 17, 2
	slwi	19, 19, 2
	slwi	20, 20, 2
	slwi	21, 21, 2
	lwzx	17, 9, 17
	lwzx	19, 9, 19
	lwzx	20, 9, 20
	lwzx	21, 9, 21
	rldicl	18, 11, 16, 56
	rlwimi	19, 19, 8, 0, 31
	xor	17, 17, 19
	rldicl	19, 12, 40, 56
	rlwimi	20, 20, 24, 0, 31
	xor	17, 17, 20
	rldicl	20, 11, 56, 56
	rlwimi	21, 21, 16, 0, 31
	xor	17, 17, 21
	rldicl	21, 12, 32, 56
	rldimi	16, 17, 32, 0
	slwi	18, 18, 2
	slwi	19, 19, 2
	slwi	20, 20, 2
	slwi	21, 21, 2
	lwzx	18, 9, 18
	lwzx	19, 9, 19
	lwzx	20, 9, 20
	lwzx	21, 9, 21
	andi.   14, 11, 255
	rlwimi	19, 19, 8, 0, 31
	xor	18, 18, 19
	rldicl	19, 12, 48, 56
	rlwimi	20, 20, 24, 0, 31
	xor	18, 18, 20
	rldicl	20, 12, 8, 56
	rlwimi	21, 21, 16, 0, 31
	xor	17, 18, 21
	rldicl	21, 11, 24, 56
	slwi	14, 14, 2
	slwi	20, 20, 2
	slwi	19, 19, 2
	slwi	21, 21, 2
	lwzx	14, 9, 14
	lwzx	20, 9, 20
	lwzx	19, 9, 19
	lwzx	21, 9, 21
	rlwimi	14, 14, 8, 0, 31
	xor	20, 20, 14
	ld	11, 0(22)
	rlwimi	21, 21, 24, 0, 31
	rldicr	11, 11, 32, 63
	xor	19, 19, 21
	ld	12, 8(22)
	rlwimi	20, 20, 8, 0, 31
	rldicr	12, 12, 32, 63
	xor	19, 19, 20
	addi	22, 22, 16
	rldimi	17, 19, 32, 0
	#   XOR in Key Schedule
	xor	16, 16, 11
	xor	17, 17, 12
	rldicl	11, 17, 16, 56
	rldicl	15, 16, 40, 56
	rldicl	20, 17, 56, 56
	rldicl	21, 16, 32, 56
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
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
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
	slwi	11, 11, 2
	slwi	15, 15, 2
	slwi	20, 20, 2
	slwi	21, 21, 2
	lwzx	11, 9, 11
	lwzx	15, 9, 15
	lwzx	20, 9, 20
	lwzx	21, 9, 21
	rldicl	12, 16, 48, 56
	rlwimi	15, 15, 8, 0, 31
	xor	11, 11, 15
	rldicl	15, 16, 8, 56
	rlwimi	20, 20, 24, 0, 31
	xor	11, 11, 20
	rldicl	20, 17, 24, 56
	rlwimi	21, 21, 16, 0, 31
	xor	11, 11, 21
	andi.   21, 17, 255
	slwi	12, 12, 2
	slwi	15, 15, 2
	slwi	20, 20, 2
	slwi	21, 21, 2
	lwzx	12, 9, 12
	lwzx	15, 9, 15
	lwzx	20, 9, 20
	lwzx	21, 9, 21
	rldicl	14, 16, 16, 56
	rlwimi	15, 15, 8, 0, 31
	xor	12, 12, 15
	rldicl	15, 17, 40, 56
	rlwimi	20, 20, 24, 0, 31
	xor	12, 12, 20
	rldicl	20, 16, 56, 56
	rlwimi	21, 21, 16, 0, 31
	xor	12, 12, 21
	rldicl	21, 17, 32, 56
	rldimi	11, 12, 32, 0
	slwi	14, 14, 2
	slwi	15, 15, 2
	slwi	20, 20, 2
	slwi	21, 21, 2
	lwzx	14, 9, 14
	lwzx	15, 9, 15
	lwzx	20, 9, 20
	lwzx	21, 9, 21
	andi.   18, 16, 255
	rlwimi	15, 15, 8, 0, 31
	xor	14, 14, 15
	rldicl	15, 17, 48, 56
	rlwimi	20, 20, 24, 0, 31
	xor	14, 14, 20
	rldicl	20, 17, 8, 56
	rlwimi	21, 21, 16, 0, 31
	xor	12, 14, 21
	rldicl	21, 16, 24, 56
	slwi	18, 18, 2
	slwi	20, 20, 2
	slwi	15, 15, 2
	slwi	21, 21, 2
	lwzx	18, 9, 18
	lwzx	20, 9, 20
	lwzx	15, 9, 15
	lwzx	21, 9, 21
	rlwimi	18, 18, 8, 0, 31
	xor	20, 20, 18
	ld	16, 0(22)
	rlwimi	21, 21, 24, 0, 31
	rldicr	16, 16, 32, 63
	xor	15, 15, 21
	ld	17, 8(22)
	rlwimi	20, 20, 8, 0, 31
	rldicr	17, 17, 32, 63
	xor	15, 15, 20
	addi	22, 22, 16
	rldimi	12, 15, 32, 0
	#   XOR in Key Schedule
	xor	11, 11, 16
	xor	12, 12, 17
	bdnz	L_AES_CBC_decrypt_loop_nr_even
	rldicl	16, 12, 16, 56
	rldicl	19, 11, 40, 56
	rldicl	20, 12, 56, 56
	rldicl	21, 11, 32, 56
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
	ld	14, 0(9)
	ld	14, 64(9)
	ld	14, 128(9)
	ld	14, 192(9)
	ld	14, 256(9)
	ld	14, 320(9)
	ld	14, 384(9)
	ld	14, 448(9)
	ld	14, 512(9)
	ld	14, 576(9)
	ld	14, 640(9)
	ld	14, 704(9)
	ld	14, 768(9)
	ld	14, 832(9)
	ld	14, 896(9)
	ld	14, 960(9)
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
	slwi	16, 16, 2
	slwi	19, 19, 2
	slwi	20, 20, 2
	slwi	21, 21, 2
	lwzx	16, 9, 16
	lwzx	19, 9, 19
	lwzx	20, 9, 20
	lwzx	21, 9, 21
	rldicl	17, 11, 48, 56
	rlwimi	19, 19, 8, 0, 31
	xor	16, 16, 19
	rldicl	19, 11, 8, 56
	rlwimi	20, 20, 24, 0, 31
	xor	16, 16, 20
	rldicl	20, 12, 24, 56
	rlwimi	21, 21, 16, 0, 31
	xor	16, 16, 21
	andi.   21, 12, 255
	slwi	17, 17, 2
	slwi	19, 19, 2
	slwi	20, 20, 2
	slwi	21, 21, 2
	lwzx	17, 9, 17
	lwzx	19, 9, 19
	lwzx	20, 9, 20
	lwzx	21, 9, 21
	rldicl	18, 11, 16, 56
	rlwimi	19, 19, 8, 0, 31
	xor	17, 17, 19
	rldicl	19, 12, 40, 56
	rlwimi	20, 20, 24, 0, 31
	xor	17, 17, 20
	rldicl	20, 11, 56, 56
	rlwimi	21, 21, 16, 0, 31
	xor	17, 17, 21
	rldicl	21, 12, 32, 56
	rldimi	16, 17, 32, 0
	slwi	18, 18, 2
	slwi	19, 19, 2
	slwi	20, 20, 2
	slwi	21, 21, 2
	lwzx	18, 9, 18
	lwzx	19, 9, 19
	lwzx	20, 9, 20
	lwzx	21, 9, 21
	andi.   14, 11, 255
	rlwimi	19, 19, 8, 0, 31
	xor	18, 18, 19
	rldicl	19, 12, 48, 56
	rlwimi	20, 20, 24, 0, 31
	xor	18, 18, 20
	rldicl	20, 12, 8, 56
	rlwimi	21, 21, 16, 0, 31
	xor	17, 18, 21
	rldicl	21, 11, 24, 56
	slwi	14, 14, 2
	slwi	20, 20, 2
	slwi	19, 19, 2
	slwi	21, 21, 2
	lwzx	14, 9, 14
	lwzx	20, 9, 20
	lwzx	19, 9, 19
	lwzx	21, 9, 21
	rlwimi	14, 14, 8, 0, 31
	xor	20, 20, 14
	ld	11, 0(22)
	rlwimi	21, 21, 24, 0, 31
	rldicr	11, 11, 32, 63
	xor	19, 19, 21
	ld	12, 8(22)
	rlwimi	20, 20, 8, 0, 31
	rldicr	12, 12, 32, 63
	xor	19, 19, 20
	addi	22, 22, 16
	rldimi	17, 19, 32, 0
	#   XOR in Key Schedule
	xor	16, 16, 11
	xor	17, 17, 12
	rldicl	11, 16, 32, 56
	rldicl	15, 17, 56, 56
	rldicl	20, 17, 16, 56
	rldicl	21, 16, 40, 56
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
	ld	19, 0(10)
	ld	19, 64(10)
	ld	19, 128(10)
	ld	19, 192(10)
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
	lbzx	11, 10, 11
	lbzx	15, 10, 15
	lbzx	20, 10, 20
	lbzx	21, 10, 21
	andi.   12, 17, 255
	rlwimi	11, 15, 8, 16, 23
	rldicl	15, 17, 24, 56
	rlwimi	11, 20, 16, 8, 15
	rldicl	20, 16, 48, 56
	rlwimi	11, 21, 24, 0, 7
	rldicl	21, 16, 8, 56
	lbzx	15, 10, 15
	lbzx	21, 10, 21
	lbzx	12, 10, 12
	lbzx	20, 10, 20
	rldicl	14, 17, 32, 56
	rlwimi	12, 15, 8, 16, 23
	rldicl	15, 16, 56, 56
	rlwimi	12, 20, 16, 8, 15
	rldicl	20, 16, 16, 56
	rlwimi	12, 21, 24, 0, 7
	rldicl	21, 17, 40, 56
	rldimi	11, 12, 32, 0
	lbzx	15, 10, 15
	lbzx	20, 10, 20
	lbzx	12, 10, 14
	lbzx	21, 10, 21
	rldicl	19, 17, 8, 56
	rlwimi	12, 15, 8, 16, 23
	andi.   15, 16, 255
	rlwimi	12, 20, 16, 8, 15
	rldicl	20, 16, 24, 56
	rlwimi	12, 21, 24, 0, 7
	rldicl	21, 17, 48, 56
	lbzx	19, 10, 19
	lbzx	20, 10, 20
	lbzx	15, 10, 15
	lbzx	21, 10, 21
	ld	16, 0(22)
	rlwimi	15, 19, 24, 0, 7
	rldicr	16, 16, 32, 63
	rlwimi	15, 21, 16, 8, 15
	ld	17, 8(22)
	rlwimi	15, 20, 8, 16, 23
	rldicr	17, 17, 32, 63
	rldimi	12, 15, 32, 0
	#   XOR in Key Schedule
	xor	11, 11, 16
	xor	12, 12, 17
	rldicr	11, 11, 32, 63
	rldicr	12, 12, 32, 63
	ld	16, 0(8)
	ld	17, 8(8)
	xor	11, 11, 16
	xor	12, 12, 17
	std	11, 0(4)
	std	12, 8(4)
	addi	3, 3, 16
	addi	4, 4, 16
	addic.	5, 5, -16
	beq	L_AES_CBC_decrypt_end_dec_odd
	addi	22, 6, 0
	ld	11, 0(3)
	ld	12, 8(3)
	std	11, 0(8)
	std	12, 8(8)
	ld	16, 0(22)
	ld	17, 8(22)
	addi	22, 22, 16
	# Round: 0 - XOR in key schedule
	xor	11, 11, 16
	xor	12, 12, 17
	rldicr	11, 11, 32, 63
	rldicr	12, 12, 32, 63
	addi	0, 7, -2
	srwi	0, 0, 1
	mtctr	0
L_AES_CBC_decrypt_loop_nr_odd:
	rldicl	16, 12, 16, 56
	rldicl	19, 11, 40, 56
	rldicl	20, 12, 56, 56
	rldicl	21, 11, 32, 56
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
	ld	14, 0(9)
	ld	14, 64(9)
	ld	14, 128(9)
	ld	14, 192(9)
	ld	14, 256(9)
	ld	14, 320(9)
	ld	14, 384(9)
	ld	14, 448(9)
	ld	14, 512(9)
	ld	14, 576(9)
	ld	14, 640(9)
	ld	14, 704(9)
	ld	14, 768(9)
	ld	14, 832(9)
	ld	14, 896(9)
	ld	14, 960(9)
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
	slwi	16, 16, 2
	slwi	19, 19, 2
	slwi	20, 20, 2
	slwi	21, 21, 2
	lwzx	16, 9, 16
	lwzx	19, 9, 19
	lwzx	20, 9, 20
	lwzx	21, 9, 21
	rldicl	17, 11, 48, 56
	rlwimi	19, 19, 8, 0, 31
	xor	16, 16, 19
	rldicl	19, 11, 8, 56
	rlwimi	20, 20, 24, 0, 31
	xor	16, 16, 20
	rldicl	20, 12, 24, 56
	rlwimi	21, 21, 16, 0, 31
	xor	16, 16, 21
	andi.   21, 12, 255
	slwi	17, 17, 2
	slwi	19, 19, 2
	slwi	20, 20, 2
	slwi	21, 21, 2
	lwzx	17, 9, 17
	lwzx	19, 9, 19
	lwzx	20, 9, 20
	lwzx	21, 9, 21
	rldicl	18, 11, 16, 56
	rlwimi	19, 19, 8, 0, 31
	xor	17, 17, 19
	rldicl	19, 12, 40, 56
	rlwimi	20, 20, 24, 0, 31
	xor	17, 17, 20
	rldicl	20, 11, 56, 56
	rlwimi	21, 21, 16, 0, 31
	xor	17, 17, 21
	rldicl	21, 12, 32, 56
	rldimi	16, 17, 32, 0
	slwi	18, 18, 2
	slwi	19, 19, 2
	slwi	20, 20, 2
	slwi	21, 21, 2
	lwzx	18, 9, 18
	lwzx	19, 9, 19
	lwzx	20, 9, 20
	lwzx	21, 9, 21
	andi.   14, 11, 255
	rlwimi	19, 19, 8, 0, 31
	xor	18, 18, 19
	rldicl	19, 12, 48, 56
	rlwimi	20, 20, 24, 0, 31
	xor	18, 18, 20
	rldicl	20, 12, 8, 56
	rlwimi	21, 21, 16, 0, 31
	xor	17, 18, 21
	rldicl	21, 11, 24, 56
	slwi	14, 14, 2
	slwi	20, 20, 2
	slwi	19, 19, 2
	slwi	21, 21, 2
	lwzx	14, 9, 14
	lwzx	20, 9, 20
	lwzx	19, 9, 19
	lwzx	21, 9, 21
	rlwimi	14, 14, 8, 0, 31
	xor	20, 20, 14
	ld	11, 0(22)
	rlwimi	21, 21, 24, 0, 31
	rldicr	11, 11, 32, 63
	xor	19, 19, 21
	ld	12, 8(22)
	rlwimi	20, 20, 8, 0, 31
	rldicr	12, 12, 32, 63
	xor	19, 19, 20
	addi	22, 22, 16
	rldimi	17, 19, 32, 0
	#   XOR in Key Schedule
	xor	16, 16, 11
	xor	17, 17, 12
	rldicl	11, 17, 16, 56
	rldicl	15, 16, 40, 56
	rldicl	20, 17, 56, 56
	rldicl	21, 16, 32, 56
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
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
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
	slwi	11, 11, 2
	slwi	15, 15, 2
	slwi	20, 20, 2
	slwi	21, 21, 2
	lwzx	11, 9, 11
	lwzx	15, 9, 15
	lwzx	20, 9, 20
	lwzx	21, 9, 21
	rldicl	12, 16, 48, 56
	rlwimi	15, 15, 8, 0, 31
	xor	11, 11, 15
	rldicl	15, 16, 8, 56
	rlwimi	20, 20, 24, 0, 31
	xor	11, 11, 20
	rldicl	20, 17, 24, 56
	rlwimi	21, 21, 16, 0, 31
	xor	11, 11, 21
	andi.   21, 17, 255
	slwi	12, 12, 2
	slwi	15, 15, 2
	slwi	20, 20, 2
	slwi	21, 21, 2
	lwzx	12, 9, 12
	lwzx	15, 9, 15
	lwzx	20, 9, 20
	lwzx	21, 9, 21
	rldicl	14, 16, 16, 56
	rlwimi	15, 15, 8, 0, 31
	xor	12, 12, 15
	rldicl	15, 17, 40, 56
	rlwimi	20, 20, 24, 0, 31
	xor	12, 12, 20
	rldicl	20, 16, 56, 56
	rlwimi	21, 21, 16, 0, 31
	xor	12, 12, 21
	rldicl	21, 17, 32, 56
	rldimi	11, 12, 32, 0
	slwi	14, 14, 2
	slwi	15, 15, 2
	slwi	20, 20, 2
	slwi	21, 21, 2
	lwzx	14, 9, 14
	lwzx	15, 9, 15
	lwzx	20, 9, 20
	lwzx	21, 9, 21
	andi.   18, 16, 255
	rlwimi	15, 15, 8, 0, 31
	xor	14, 14, 15
	rldicl	15, 17, 48, 56
	rlwimi	20, 20, 24, 0, 31
	xor	14, 14, 20
	rldicl	20, 17, 8, 56
	rlwimi	21, 21, 16, 0, 31
	xor	12, 14, 21
	rldicl	21, 16, 24, 56
	slwi	18, 18, 2
	slwi	20, 20, 2
	slwi	15, 15, 2
	slwi	21, 21, 2
	lwzx	18, 9, 18
	lwzx	20, 9, 20
	lwzx	15, 9, 15
	lwzx	21, 9, 21
	rlwimi	18, 18, 8, 0, 31
	xor	20, 20, 18
	ld	16, 0(22)
	rlwimi	21, 21, 24, 0, 31
	rldicr	16, 16, 32, 63
	xor	15, 15, 21
	ld	17, 8(22)
	rlwimi	20, 20, 8, 0, 31
	rldicr	17, 17, 32, 63
	xor	15, 15, 20
	addi	22, 22, 16
	rldimi	12, 15, 32, 0
	#   XOR in Key Schedule
	xor	11, 11, 16
	xor	12, 12, 17
	bdnz	L_AES_CBC_decrypt_loop_nr_odd
	rldicl	16, 12, 16, 56
	rldicl	19, 11, 40, 56
	rldicl	20, 12, 56, 56
	rldicl	21, 11, 32, 56
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
	ld	14, 0(9)
	ld	14, 64(9)
	ld	14, 128(9)
	ld	14, 192(9)
	ld	14, 256(9)
	ld	14, 320(9)
	ld	14, 384(9)
	ld	14, 448(9)
	ld	14, 512(9)
	ld	14, 576(9)
	ld	14, 640(9)
	ld	14, 704(9)
	ld	14, 768(9)
	ld	14, 832(9)
	ld	14, 896(9)
	ld	14, 960(9)
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
	slwi	16, 16, 2
	slwi	19, 19, 2
	slwi	20, 20, 2
	slwi	21, 21, 2
	lwzx	16, 9, 16
	lwzx	19, 9, 19
	lwzx	20, 9, 20
	lwzx	21, 9, 21
	rldicl	17, 11, 48, 56
	rlwimi	19, 19, 8, 0, 31
	xor	16, 16, 19
	rldicl	19, 11, 8, 56
	rlwimi	20, 20, 24, 0, 31
	xor	16, 16, 20
	rldicl	20, 12, 24, 56
	rlwimi	21, 21, 16, 0, 31
	xor	16, 16, 21
	andi.   21, 12, 255
	slwi	17, 17, 2
	slwi	19, 19, 2
	slwi	20, 20, 2
	slwi	21, 21, 2
	lwzx	17, 9, 17
	lwzx	19, 9, 19
	lwzx	20, 9, 20
	lwzx	21, 9, 21
	rldicl	18, 11, 16, 56
	rlwimi	19, 19, 8, 0, 31
	xor	17, 17, 19
	rldicl	19, 12, 40, 56
	rlwimi	20, 20, 24, 0, 31
	xor	17, 17, 20
	rldicl	20, 11, 56, 56
	rlwimi	21, 21, 16, 0, 31
	xor	17, 17, 21
	rldicl	21, 12, 32, 56
	rldimi	16, 17, 32, 0
	slwi	18, 18, 2
	slwi	19, 19, 2
	slwi	20, 20, 2
	slwi	21, 21, 2
	lwzx	18, 9, 18
	lwzx	19, 9, 19
	lwzx	20, 9, 20
	lwzx	21, 9, 21
	andi.   14, 11, 255
	rlwimi	19, 19, 8, 0, 31
	xor	18, 18, 19
	rldicl	19, 12, 48, 56
	rlwimi	20, 20, 24, 0, 31
	xor	18, 18, 20
	rldicl	20, 12, 8, 56
	rlwimi	21, 21, 16, 0, 31
	xor	17, 18, 21
	rldicl	21, 11, 24, 56
	slwi	14, 14, 2
	slwi	20, 20, 2
	slwi	19, 19, 2
	slwi	21, 21, 2
	lwzx	14, 9, 14
	lwzx	20, 9, 20
	lwzx	19, 9, 19
	lwzx	21, 9, 21
	rlwimi	14, 14, 8, 0, 31
	xor	20, 20, 14
	ld	11, 0(22)
	rlwimi	21, 21, 24, 0, 31
	rldicr	11, 11, 32, 63
	xor	19, 19, 21
	ld	12, 8(22)
	rlwimi	20, 20, 8, 0, 31
	rldicr	12, 12, 32, 63
	xor	19, 19, 20
	addi	22, 22, 16
	rldimi	17, 19, 32, 0
	#   XOR in Key Schedule
	xor	16, 16, 11
	xor	17, 17, 12
	rldicl	11, 16, 32, 56
	rldicl	15, 17, 56, 56
	rldicl	20, 17, 16, 56
	rldicl	21, 16, 40, 56
#ifndef WOLFSSL_PPC64_ASM_AES_NO_HARDEN
	ld	19, 0(10)
	ld	19, 64(10)
	ld	19, 128(10)
	ld	19, 192(10)
#endif /* !WOLFSSL_PPC64_ASM_AES_NO_HARDEN */
	lbzx	11, 10, 11
	lbzx	15, 10, 15
	lbzx	20, 10, 20
	lbzx	21, 10, 21
	andi.   12, 17, 255
	rlwimi	11, 15, 8, 16, 23
	rldicl	15, 17, 24, 56
	rlwimi	11, 20, 16, 8, 15
	rldicl	20, 16, 48, 56
	rlwimi	11, 21, 24, 0, 7
	rldicl	21, 16, 8, 56
	lbzx	15, 10, 15
	lbzx	21, 10, 21
	lbzx	12, 10, 12
	lbzx	20, 10, 20
	rldicl	14, 17, 32, 56
	rlwimi	12, 15, 8, 16, 23
	rldicl	15, 16, 56, 56
	rlwimi	12, 20, 16, 8, 15
	rldicl	20, 16, 16, 56
	rlwimi	12, 21, 24, 0, 7
	rldicl	21, 17, 40, 56
	rldimi	11, 12, 32, 0
	lbzx	15, 10, 15
	lbzx	20, 10, 20
	lbzx	12, 10, 14
	lbzx	21, 10, 21
	rldicl	19, 17, 8, 56
	rlwimi	12, 15, 8, 16, 23
	andi.   15, 16, 255
	rlwimi	12, 20, 16, 8, 15
	rldicl	20, 16, 24, 56
	rlwimi	12, 21, 24, 0, 7
	rldicl	21, 17, 48, 56
	lbzx	19, 10, 19
	lbzx	20, 10, 20
	lbzx	15, 10, 15
	lbzx	21, 10, 21
	ld	16, 0(22)
	rlwimi	15, 19, 24, 0, 7
	rldicr	16, 16, 32, 63
	rlwimi	15, 21, 16, 8, 15
	ld	17, 8(22)
	rlwimi	15, 20, 8, 16, 23
	rldicr	17, 17, 32, 63
	rldimi	12, 15, 32, 0
	#   XOR in Key Schedule
	xor	11, 11, 16
	xor	12, 12, 17
	rldicr	11, 11, 32, 63
	rldicr	12, 12, 32, 63
	ld	16, 16(8)
	ld	17, 24(8)
	xor	11, 11, 16
	xor	12, 12, 17
	std	11, 0(4)
	std	12, 8(4)
	addi	3, 3, 16
	addi	4, 4, 16
	addic.	5, 5, -16
	bne	L_AES_CBC_decrypt_loop_block
	b	L_AES_CBC_decrypt_end_dec
L_AES_CBC_decrypt_end_dec_odd:
	ld	16, 16(8)
	ld	17, 24(8)
	std	16, 0(8)
	std	17, 8(8)
L_AES_CBC_decrypt_end_dec:
	ld	0, 72(1)
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
	addi	1, 1, 0x50
	blr
	.size	AES_CBC_decrypt,.-AES_CBC_decrypt
#endif /* HAVE_AES_CBC */
#endif /* WOLFSSL_AES_DIRECT || WOLFSSL_AES_COUNTER || HAVE_AES_CBC
        * HAVE_AES_ECB */
#ifdef WOLFSSL_AES_XTS
#endif /* WOLFSSL_AES_XTS */
#endif /* HAVE_AES_DECRYPT */
#ifdef HAVE_AESGCM
#ifdef GCM_TABLE_4BIT
	.section	".text"
	.section	.rodata
	.type	L_GCM_gmult_len_r, @object
	.size	L_GCM_gmult_len_r, 128
	.align	4
L_GCM_gmult_len_r:
	.long	0x0
	.long	0x1c200000
	.long	0x38400000
	.long	0x24600000
	.long	0x70800000
	.long	0x6ca00000
	.long	0x48c00000
	.long	0x54e00000
	.long	0xe1000000
	.long	0xfd200000
	.long	0xd9400000
	.long	0xc5600000
	.long	0x91800000
	.long	0x8da00000
	.long	0xa9c00000
	.long	0xb5e00000
	.long	0x0
	.long	0x1c20000
	.long	0x3840000
	.long	0x2460000
	.long	0x7080000
	.long	0x6ca0000
	.long	0x48c0000
	.long	0x54e0000
	.long	0xe100000
	.long	0xfd20000
	.long	0xd940000
	.long	0xc560000
	.long	0x9180000
	.long	0x8da0000
	.long	0xa9c0000
	.long	0xb5e0000
	.section	".text"
	.align	4
	.globl	GCM_gmult_len
	.type	GCM_gmult_len, @function
GCM_gmult_len:
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
	lis	18, L_GCM_gmult_len_r@ha
	la	18, L_GCM_gmult_len_r@l(18)
	add	21, 21, 4
	addi	20, 4, 8
	addi	22, 21, 8
	addi	19, 18, 0x40
L_GCM_gmult_len_start_block:
	li	16, 8
	ldbrx	7, 0, 3
	ldbrx	8, 16, 3
	ldbrx	9, 0, 5
	ldbrx	10, 16, 5
	xor	7, 7, 9
	xor	8, 8, 10
	rldicr	25, 8, 32, 63
	# Byte 15
	rlwinm	23, 25, 12, 24, 27
	rlwinm	24, 25, 8, 24, 27
	ldx	14, 23, 4
	ldx	15, 23, 20
	ldx	11, 24, 21
	ldx	12, 24, 22
	rldicl	16, 15, 60, 60
	rldic	17, 15, 2, 58
	srdi	15, 15, 8
	addi	24, 24, -248
	rldimi	15, 14, 56, 0
	srdi	14, 14, 8
	lwzx	9, 17, 19
	ldx	10, 24, 21
	xor	16, 16, 10
	xor	14, 14, 11
	rlwinm	16, 16, 2, 26, 29
	xor	15, 15, 12
	sldi	9, 9, 32
	lwzx	10, 16, 18
	xor	14, 14, 9
	sldi	10, 10, 32
	xor	14, 14, 10
	# Byte 14
	rlwinm	23, 25, 20, 24, 27
	rlwinm	24, 25, 16, 24, 27
	ldx	9, 23, 4
	ldx	10, 23, 20
	ldx	11, 24, 21
	ldx	12, 24, 22
	xor	14, 14, 9
	xor	15, 15, 10
	rldicl	16, 15, 60, 60
	rldic	17, 15, 2, 58
	srdi	15, 15, 8
	addi	24, 24, -248
	rldimi	15, 14, 56, 0
	srdi	14, 14, 8
	lwzx	9, 17, 19
	ldx	10, 24, 21
	xor	16, 16, 10
	xor	14, 14, 11
	rlwinm	16, 16, 2, 26, 29
	xor	15, 15, 12
	sldi	9, 9, 32
	lwzx	10, 16, 18
	xor	14, 14, 9
	sldi	10, 10, 32
	xor	14, 14, 10
	# Byte 13
	rlwinm	23, 25, 28, 24, 27
	rlwinm	24, 25, 24, 24, 27
	ldx	9, 23, 4
	ldx	10, 23, 20
	ldx	11, 24, 21
	ldx	12, 24, 22
	xor	14, 14, 9
	xor	15, 15, 10
	rldicl	16, 15, 60, 60
	rldic	17, 15, 2, 58
	srdi	15, 15, 8
	addi	24, 24, -248
	rldimi	15, 14, 56, 0
	srdi	14, 14, 8
	lwzx	9, 17, 19
	ldx	10, 24, 21
	xor	16, 16, 10
	xor	14, 14, 11
	rlwinm	16, 16, 2, 26, 29
	xor	15, 15, 12
	sldi	9, 9, 32
	lwzx	10, 16, 18
	xor	14, 14, 9
	sldi	10, 10, 32
	xor	14, 14, 10
	# Byte 12
	rlwinm	23, 25, 4, 24, 27
	rlwinm	24, 25, 0, 24, 27
	ldx	9, 23, 4
	ldx	10, 23, 20
	ldx	11, 24, 21
	ldx	12, 24, 22
	xor	14, 14, 9
	xor	15, 15, 10
	rldicl	16, 15, 60, 60
	rldic	17, 15, 2, 58
	srdi	15, 15, 8
	addi	24, 24, -248
	rldimi	15, 14, 56, 0
	srdi	14, 14, 8
	lwzx	9, 17, 19
	ldx	10, 24, 21
	xor	16, 16, 10
	xor	14, 14, 11
	rlwinm	16, 16, 2, 26, 29
	xor	15, 15, 12
	sldi	9, 9, 32
	lwzx	10, 16, 18
	xor	14, 14, 9
	sldi	10, 10, 32
	xor	14, 14, 10
	# Byte 11
	rlwinm	23, 8, 12, 24, 27
	rlwinm	24, 8, 8, 24, 27
	ldx	9, 23, 4
	ldx	10, 23, 20
	ldx	11, 24, 21
	ldx	12, 24, 22
	xor	14, 14, 9
	xor	15, 15, 10
	rldicl	16, 15, 60, 60
	rldic	17, 15, 2, 58
	srdi	15, 15, 8
	addi	24, 24, -248
	rldimi	15, 14, 56, 0
	srdi	14, 14, 8
	lwzx	9, 17, 19
	ldx	10, 24, 21
	xor	16, 16, 10
	xor	14, 14, 11
	rlwinm	16, 16, 2, 26, 29
	xor	15, 15, 12
	sldi	9, 9, 32
	lwzx	10, 16, 18
	xor	14, 14, 9
	sldi	10, 10, 32
	xor	14, 14, 10
	# Byte 10
	rlwinm	23, 8, 20, 24, 27
	rlwinm	24, 8, 16, 24, 27
	ldx	9, 23, 4
	ldx	10, 23, 20
	ldx	11, 24, 21
	ldx	12, 24, 22
	xor	14, 14, 9
	xor	15, 15, 10
	rldicl	16, 15, 60, 60
	rldic	17, 15, 2, 58
	srdi	15, 15, 8
	addi	24, 24, -248
	rldimi	15, 14, 56, 0
	srdi	14, 14, 8
	lwzx	9, 17, 19
	ldx	10, 24, 21
	xor	16, 16, 10
	xor	14, 14, 11
	rlwinm	16, 16, 2, 26, 29
	xor	15, 15, 12
	sldi	9, 9, 32
	lwzx	10, 16, 18
	xor	14, 14, 9
	sldi	10, 10, 32
	xor	14, 14, 10
	# Byte 9
	rlwinm	23, 8, 28, 24, 27
	rlwinm	24, 8, 24, 24, 27
	ldx	9, 23, 4
	ldx	10, 23, 20
	ldx	11, 24, 21
	ldx	12, 24, 22
	xor	14, 14, 9
	xor	15, 15, 10
	rldicl	16, 15, 60, 60
	rldic	17, 15, 2, 58
	srdi	15, 15, 8
	addi	24, 24, -248
	rldimi	15, 14, 56, 0
	srdi	14, 14, 8
	lwzx	9, 17, 19
	ldx	10, 24, 21
	xor	16, 16, 10
	xor	14, 14, 11
	rlwinm	16, 16, 2, 26, 29
	xor	15, 15, 12
	sldi	9, 9, 32
	lwzx	10, 16, 18
	xor	14, 14, 9
	sldi	10, 10, 32
	xor	14, 14, 10
	# Byte 8
	rlwinm	23, 8, 4, 24, 27
	rlwinm	24, 8, 0, 24, 27
	ldx	9, 23, 4
	ldx	10, 23, 20
	ldx	11, 24, 21
	ldx	12, 24, 22
	xor	14, 14, 9
	xor	15, 15, 10
	rldicl	16, 15, 60, 60
	rldic	17, 15, 2, 58
	srdi	15, 15, 8
	addi	24, 24, -248
	rldimi	15, 14, 56, 0
	srdi	14, 14, 8
	lwzx	9, 17, 19
	ldx	10, 24, 21
	xor	16, 16, 10
	xor	14, 14, 11
	rlwinm	16, 16, 2, 26, 29
	xor	15, 15, 12
	sldi	9, 9, 32
	lwzx	10, 16, 18
	xor	14, 14, 9
	sldi	10, 10, 32
	xor	14, 14, 10
	rldicr	25, 7, 32, 63
	# Byte 7
	rlwinm	23, 25, 12, 24, 27
	rlwinm	24, 25, 8, 24, 27
	ldx	9, 23, 4
	ldx	10, 23, 20
	ldx	11, 24, 21
	ldx	12, 24, 22
	xor	14, 14, 9
	xor	15, 15, 10
	rldicl	16, 15, 60, 60
	rldic	17, 15, 2, 58
	srdi	15, 15, 8
	addi	24, 24, -248
	rldimi	15, 14, 56, 0
	srdi	14, 14, 8
	lwzx	9, 17, 19
	ldx	10, 24, 21
	xor	16, 16, 10
	xor	14, 14, 11
	rlwinm	16, 16, 2, 26, 29
	xor	15, 15, 12
	sldi	9, 9, 32
	lwzx	10, 16, 18
	xor	14, 14, 9
	sldi	10, 10, 32
	xor	14, 14, 10
	# Byte 6
	rlwinm	23, 25, 20, 24, 27
	rlwinm	24, 25, 16, 24, 27
	ldx	9, 23, 4
	ldx	10, 23, 20
	ldx	11, 24, 21
	ldx	12, 24, 22
	xor	14, 14, 9
	xor	15, 15, 10
	rldicl	16, 15, 60, 60
	rldic	17, 15, 2, 58
	srdi	15, 15, 8
	addi	24, 24, -248
	rldimi	15, 14, 56, 0
	srdi	14, 14, 8
	lwzx	9, 17, 19
	ldx	10, 24, 21
	xor	16, 16, 10
	xor	14, 14, 11
	rlwinm	16, 16, 2, 26, 29
	xor	15, 15, 12
	sldi	9, 9, 32
	lwzx	10, 16, 18
	xor	14, 14, 9
	sldi	10, 10, 32
	xor	14, 14, 10
	# Byte 5
	rlwinm	23, 25, 28, 24, 27
	rlwinm	24, 25, 24, 24, 27
	ldx	9, 23, 4
	ldx	10, 23, 20
	ldx	11, 24, 21
	ldx	12, 24, 22
	xor	14, 14, 9
	xor	15, 15, 10
	rldicl	16, 15, 60, 60
	rldic	17, 15, 2, 58
	srdi	15, 15, 8
	addi	24, 24, -248
	rldimi	15, 14, 56, 0
	srdi	14, 14, 8
	lwzx	9, 17, 19
	ldx	10, 24, 21
	xor	16, 16, 10
	xor	14, 14, 11
	rlwinm	16, 16, 2, 26, 29
	xor	15, 15, 12
	sldi	9, 9, 32
	lwzx	10, 16, 18
	xor	14, 14, 9
	sldi	10, 10, 32
	xor	14, 14, 10
	# Byte 4
	rlwinm	23, 25, 4, 24, 27
	rlwinm	24, 25, 0, 24, 27
	ldx	9, 23, 4
	ldx	10, 23, 20
	ldx	11, 24, 21
	ldx	12, 24, 22
	xor	14, 14, 9
	xor	15, 15, 10
	rldicl	16, 15, 60, 60
	rldic	17, 15, 2, 58
	srdi	15, 15, 8
	addi	24, 24, -248
	rldimi	15, 14, 56, 0
	srdi	14, 14, 8
	lwzx	9, 17, 19
	ldx	10, 24, 21
	xor	16, 16, 10
	xor	14, 14, 11
	rlwinm	16, 16, 2, 26, 29
	xor	15, 15, 12
	sldi	9, 9, 32
	lwzx	10, 16, 18
	xor	14, 14, 9
	sldi	10, 10, 32
	xor	14, 14, 10
	# Byte 3
	rlwinm	23, 7, 12, 24, 27
	rlwinm	24, 7, 8, 24, 27
	ldx	9, 23, 4
	ldx	10, 23, 20
	ldx	11, 24, 21
	ldx	12, 24, 22
	xor	14, 14, 9
	xor	15, 15, 10
	rldicl	16, 15, 60, 60
	rldic	17, 15, 2, 58
	srdi	15, 15, 8
	addi	24, 24, -248
	rldimi	15, 14, 56, 0
	srdi	14, 14, 8
	lwzx	9, 17, 19
	ldx	10, 24, 21
	xor	16, 16, 10
	xor	14, 14, 11
	rlwinm	16, 16, 2, 26, 29
	xor	15, 15, 12
	sldi	9, 9, 32
	lwzx	10, 16, 18
	xor	14, 14, 9
	sldi	10, 10, 32
	xor	14, 14, 10
	# Byte 2
	rlwinm	23, 7, 20, 24, 27
	rlwinm	24, 7, 16, 24, 27
	ldx	9, 23, 4
	ldx	10, 23, 20
	ldx	11, 24, 21
	ldx	12, 24, 22
	xor	14, 14, 9
	xor	15, 15, 10
	rldicl	16, 15, 60, 60
	rldic	17, 15, 2, 58
	srdi	15, 15, 8
	addi	24, 24, -248
	rldimi	15, 14, 56, 0
	srdi	14, 14, 8
	lwzx	9, 17, 19
	ldx	10, 24, 21
	xor	16, 16, 10
	xor	14, 14, 11
	rlwinm	16, 16, 2, 26, 29
	xor	15, 15, 12
	sldi	9, 9, 32
	lwzx	10, 16, 18
	xor	14, 14, 9
	sldi	10, 10, 32
	xor	14, 14, 10
	# Byte 1
	rlwinm	23, 7, 28, 24, 27
	rlwinm	24, 7, 24, 24, 27
	ldx	9, 23, 4
	ldx	10, 23, 20
	ldx	11, 24, 21
	ldx	12, 24, 22
	xor	14, 14, 9
	xor	15, 15, 10
	rldicl	16, 15, 60, 60
	rldic	17, 15, 2, 58
	srdi	15, 15, 8
	addi	24, 24, -248
	rldimi	15, 14, 56, 0
	srdi	14, 14, 8
	lwzx	9, 17, 19
	ldx	10, 24, 21
	xor	16, 16, 10
	xor	14, 14, 11
	rlwinm	16, 16, 2, 26, 29
	xor	15, 15, 12
	sldi	9, 9, 32
	lwzx	10, 16, 18
	xor	14, 14, 9
	sldi	10, 10, 32
	xor	14, 14, 10
	# Byte 0
	rlwinm	23, 7, 4, 24, 27
	rlwinm	24, 7, 0, 24, 27
	ldx	9, 23, 4
	ldx	10, 23, 20
	ldx	11, 24, 4
	ldx	12, 24, 20
	xor	14, 14, 9
	xor	15, 15, 10
	rldic	16, 15, 2, 58
	srdi	15, 15, 4
	lwzx	9, 16, 18
	rldimi	15, 14, 60, 0
	srdi	14, 14, 4
	xor	8, 15, 12
	xor	14, 14, 11
	sldi	9, 9, 32
	xor	7, 14, 9
	addi	5, 5, 16
	addic.	6, 6, -16
	std	7, 0(3)
	std	8, 8(3)
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
	.size	GCM_gmult_len,.-GCM_gmult_len
#endif /* GCM_TABLE_4BIT */
#ifdef GCM_TABLE
	.section	".text"
	.section	.rodata
	.type	L_GCM_gmult_len_r, @object
	.size	L_GCM_gmult_len_r, 512
	.align	4
L_GCM_gmult_len_r:
	.byte	0x0
	.byte	0x0
	.byte	0xc2
	.byte	0x1
	.byte	0x84
	.byte	0x3
	.byte	0x46
	.byte	0x2
	.byte	0x8
	.byte	0x7
	.byte	0xca
	.byte	0x6
	.byte	0x8c
	.byte	0x4
	.byte	0x4e
	.byte	0x5
	.byte	0x10
	.byte	0xe
	.byte	0xd2
	.byte	0xf
	.byte	0x94
	.byte	0xd
	.byte	0x56
	.byte	0xc
	.byte	0x18
	.byte	0x9
	.byte	0xda
	.byte	0x8
	.byte	0x9c
	.byte	0xa
	.byte	0x5e
	.byte	0xb
	.byte	0x20
	.byte	0x1c
	.byte	0xe2
	.byte	0x1d
	.byte	0xa4
	.byte	0x1f
	.byte	0x66
	.byte	0x1e
	.byte	0x28
	.byte	0x1b
	.byte	0xea
	.byte	0x1a
	.byte	0xac
	.byte	0x18
	.byte	0x6e
	.byte	0x19
	.byte	0x30
	.byte	0x12
	.byte	0xf2
	.byte	0x13
	.byte	0xb4
	.byte	0x11
	.byte	0x76
	.byte	0x10
	.byte	0x38
	.byte	0x15
	.byte	0xfa
	.byte	0x14
	.byte	0xbc
	.byte	0x16
	.byte	0x7e
	.byte	0x17
	.byte	0x40
	.byte	0x38
	.byte	0x82
	.byte	0x39
	.byte	0xc4
	.byte	0x3b
	.byte	0x6
	.byte	0x3a
	.byte	0x48
	.byte	0x3f
	.byte	0x8a
	.byte	0x3e
	.byte	0xcc
	.byte	0x3c
	.byte	0xe
	.byte	0x3d
	.byte	0x50
	.byte	0x36
	.byte	0x92
	.byte	0x37
	.byte	0xd4
	.byte	0x35
	.byte	0x16
	.byte	0x34
	.byte	0x58
	.byte	0x31
	.byte	0x9a
	.byte	0x30
	.byte	0xdc
	.byte	0x32
	.byte	0x1e
	.byte	0x33
	.byte	0x60
	.byte	0x24
	.byte	0xa2
	.byte	0x25
	.byte	0xe4
	.byte	0x27
	.byte	0x26
	.byte	0x26
	.byte	0x68
	.byte	0x23
	.byte	0xaa
	.byte	0x22
	.byte	0xec
	.byte	0x20
	.byte	0x2e
	.byte	0x21
	.byte	0x70
	.byte	0x2a
	.byte	0xb2
	.byte	0x2b
	.byte	0xf4
	.byte	0x29
	.byte	0x36
	.byte	0x28
	.byte	0x78
	.byte	0x2d
	.byte	0xba
	.byte	0x2c
	.byte	0xfc
	.byte	0x2e
	.byte	0x3e
	.byte	0x2f
	.byte	0x80
	.byte	0x70
	.byte	0x42
	.byte	0x71
	.byte	0x4
	.byte	0x73
	.byte	0xc6
	.byte	0x72
	.byte	0x88
	.byte	0x77
	.byte	0x4a
	.byte	0x76
	.byte	0xc
	.byte	0x74
	.byte	0xce
	.byte	0x75
	.byte	0x90
	.byte	0x7e
	.byte	0x52
	.byte	0x7f
	.byte	0x14
	.byte	0x7d
	.byte	0xd6
	.byte	0x7c
	.byte	0x98
	.byte	0x79
	.byte	0x5a
	.byte	0x78
	.byte	0x1c
	.byte	0x7a
	.byte	0xde
	.byte	0x7b
	.byte	0xa0
	.byte	0x6c
	.byte	0x62
	.byte	0x6d
	.byte	0x24
	.byte	0x6f
	.byte	0xe6
	.byte	0x6e
	.byte	0xa8
	.byte	0x6b
	.byte	0x6a
	.byte	0x6a
	.byte	0x2c
	.byte	0x68
	.byte	0xee
	.byte	0x69
	.byte	0xb0
	.byte	0x62
	.byte	0x72
	.byte	0x63
	.byte	0x34
	.byte	0x61
	.byte	0xf6
	.byte	0x60
	.byte	0xb8
	.byte	0x65
	.byte	0x7a
	.byte	0x64
	.byte	0x3c
	.byte	0x66
	.byte	0xfe
	.byte	0x67
	.byte	0xc0
	.byte	0x48
	.byte	0x2
	.byte	0x49
	.byte	0x44
	.byte	0x4b
	.byte	0x86
	.byte	0x4a
	.byte	0xc8
	.byte	0x4f
	.byte	0xa
	.byte	0x4e
	.byte	0x4c
	.byte	0x4c
	.byte	0x8e
	.byte	0x4d
	.byte	0xd0
	.byte	0x46
	.byte	0x12
	.byte	0x47
	.byte	0x54
	.byte	0x45
	.byte	0x96
	.byte	0x44
	.byte	0xd8
	.byte	0x41
	.byte	0x1a
	.byte	0x40
	.byte	0x5c
	.byte	0x42
	.byte	0x9e
	.byte	0x43
	.byte	0xe0
	.byte	0x54
	.byte	0x22
	.byte	0x55
	.byte	0x64
	.byte	0x57
	.byte	0xa6
	.byte	0x56
	.byte	0xe8
	.byte	0x53
	.byte	0x2a
	.byte	0x52
	.byte	0x6c
	.byte	0x50
	.byte	0xae
	.byte	0x51
	.byte	0xf0
	.byte	0x5a
	.byte	0x32
	.byte	0x5b
	.byte	0x74
	.byte	0x59
	.byte	0xb6
	.byte	0x58
	.byte	0xf8
	.byte	0x5d
	.byte	0x3a
	.byte	0x5c
	.byte	0x7c
	.byte	0x5e
	.byte	0xbe
	.byte	0x5f
	.byte	0x0
	.byte	0xe1
	.byte	0xc2
	.byte	0xe0
	.byte	0x84
	.byte	0xe2
	.byte	0x46
	.byte	0xe3
	.byte	0x8
	.byte	0xe6
	.byte	0xca
	.byte	0xe7
	.byte	0x8c
	.byte	0xe5
	.byte	0x4e
	.byte	0xe4
	.byte	0x10
	.byte	0xef
	.byte	0xd2
	.byte	0xee
	.byte	0x94
	.byte	0xec
	.byte	0x56
	.byte	0xed
	.byte	0x18
	.byte	0xe8
	.byte	0xda
	.byte	0xe9
	.byte	0x9c
	.byte	0xeb
	.byte	0x5e
	.byte	0xea
	.byte	0x20
	.byte	0xfd
	.byte	0xe2
	.byte	0xfc
	.byte	0xa4
	.byte	0xfe
	.byte	0x66
	.byte	0xff
	.byte	0x28
	.byte	0xfa
	.byte	0xea
	.byte	0xfb
	.byte	0xac
	.byte	0xf9
	.byte	0x6e
	.byte	0xf8
	.byte	0x30
	.byte	0xf3
	.byte	0xf2
	.byte	0xf2
	.byte	0xb4
	.byte	0xf0
	.byte	0x76
	.byte	0xf1
	.byte	0x38
	.byte	0xf4
	.byte	0xfa
	.byte	0xf5
	.byte	0xbc
	.byte	0xf7
	.byte	0x7e
	.byte	0xf6
	.byte	0x40
	.byte	0xd9
	.byte	0x82
	.byte	0xd8
	.byte	0xc4
	.byte	0xda
	.byte	0x6
	.byte	0xdb
	.byte	0x48
	.byte	0xde
	.byte	0x8a
	.byte	0xdf
	.byte	0xcc
	.byte	0xdd
	.byte	0xe
	.byte	0xdc
	.byte	0x50
	.byte	0xd7
	.byte	0x92
	.byte	0xd6
	.byte	0xd4
	.byte	0xd4
	.byte	0x16
	.byte	0xd5
	.byte	0x58
	.byte	0xd0
	.byte	0x9a
	.byte	0xd1
	.byte	0xdc
	.byte	0xd3
	.byte	0x1e
	.byte	0xd2
	.byte	0x60
	.byte	0xc5
	.byte	0xa2
	.byte	0xc4
	.byte	0xe4
	.byte	0xc6
	.byte	0x26
	.byte	0xc7
	.byte	0x68
	.byte	0xc2
	.byte	0xaa
	.byte	0xc3
	.byte	0xec
	.byte	0xc1
	.byte	0x2e
	.byte	0xc0
	.byte	0x70
	.byte	0xcb
	.byte	0xb2
	.byte	0xca
	.byte	0xf4
	.byte	0xc8
	.byte	0x36
	.byte	0xc9
	.byte	0x78
	.byte	0xcc
	.byte	0xba
	.byte	0xcd
	.byte	0xfc
	.byte	0xcf
	.byte	0x3e
	.byte	0xce
	.byte	0x80
	.byte	0x91
	.byte	0x42
	.byte	0x90
	.byte	0x4
	.byte	0x92
	.byte	0xc6
	.byte	0x93
	.byte	0x88
	.byte	0x96
	.byte	0x4a
	.byte	0x97
	.byte	0xc
	.byte	0x95
	.byte	0xce
	.byte	0x94
	.byte	0x90
	.byte	0x9f
	.byte	0x52
	.byte	0x9e
	.byte	0x14
	.byte	0x9c
	.byte	0xd6
	.byte	0x9d
	.byte	0x98
	.byte	0x98
	.byte	0x5a
	.byte	0x99
	.byte	0x1c
	.byte	0x9b
	.byte	0xde
	.byte	0x9a
	.byte	0xa0
	.byte	0x8d
	.byte	0x62
	.byte	0x8c
	.byte	0x24
	.byte	0x8e
	.byte	0xe6
	.byte	0x8f
	.byte	0xa8
	.byte	0x8a
	.byte	0x6a
	.byte	0x8b
	.byte	0x2c
	.byte	0x89
	.byte	0xee
	.byte	0x88
	.byte	0xb0
	.byte	0x83
	.byte	0x72
	.byte	0x82
	.byte	0x34
	.byte	0x80
	.byte	0xf6
	.byte	0x81
	.byte	0xb8
	.byte	0x84
	.byte	0x7a
	.byte	0x85
	.byte	0x3c
	.byte	0x87
	.byte	0xfe
	.byte	0x86
	.byte	0xc0
	.byte	0xa9
	.byte	0x2
	.byte	0xa8
	.byte	0x44
	.byte	0xaa
	.byte	0x86
	.byte	0xab
	.byte	0xc8
	.byte	0xae
	.byte	0xa
	.byte	0xaf
	.byte	0x4c
	.byte	0xad
	.byte	0x8e
	.byte	0xac
	.byte	0xd0
	.byte	0xa7
	.byte	0x12
	.byte	0xa6
	.byte	0x54
	.byte	0xa4
	.byte	0x96
	.byte	0xa5
	.byte	0xd8
	.byte	0xa0
	.byte	0x1a
	.byte	0xa1
	.byte	0x5c
	.byte	0xa3
	.byte	0x9e
	.byte	0xa2
	.byte	0xe0
	.byte	0xb5
	.byte	0x22
	.byte	0xb4
	.byte	0x64
	.byte	0xb6
	.byte	0xa6
	.byte	0xb7
	.byte	0xe8
	.byte	0xb2
	.byte	0x2a
	.byte	0xb3
	.byte	0x6c
	.byte	0xb1
	.byte	0xae
	.byte	0xb0
	.byte	0xf0
	.byte	0xbb
	.byte	0x32
	.byte	0xba
	.byte	0x74
	.byte	0xb8
	.byte	0xb6
	.byte	0xb9
	.byte	0xf8
	.byte	0xbc
	.byte	0x3a
	.byte	0xbd
	.byte	0x7c
	.byte	0xbf
	.byte	0xbe
	.byte	0xbe
	.section	".text"
	.align	4
	.globl	GCM_gmult_len
	.type	GCM_gmult_len, @function
GCM_gmult_len:
	stdu	1, -64(1)
	mflr	0
	std	0, 56(1)
	std	14, 0(1)
	std	15, 8(1)
	std	16, 16(1)
	std	17, 24(1)
	std	18, 32(1)
	std	19, 40(1)
	std	20, 48(1)
	lis	17, L_GCM_gmult_len_r@ha
	la	17, L_GCM_gmult_len_r@l(17)
L_GCM_gmult_len_start_block:
	li	16, 8
	ldbrx	7, 0, 3
	ldbrx	8, 16, 3
	ldbrx	9, 0, 5
	ldbrx	10, 16, 5
	xor	7, 7, 9
	xor	8, 8, 10
	rldicr	20, 8, 32, 63
	# Byte 15
	rlwinm	18, 20, 12, 20, 27
	addi	19, 18, 8
	ldx	14, 18, 4
	ldx	15, 19, 4
	rldicl	16, 15, 9, 55
	andi.   16, 16, 510
	lhzx	9, 16, 17
	rldicl	10, 14, 8, 56
	sldi	15, 15, 8
	sldi	14, 14, 8
	xor	15, 15, 10
	xor	14, 14, 9
	# Byte 14
	rlwinm	18, 20, 20, 20, 27
	addi	19, 18, 8
	ldx	9, 18, 4
	ldx	10, 19, 4
	xor	14, 14, 9
	xor	15, 15, 10
	rldicl	16, 15, 9, 55
	andi.   16, 16, 510
	lhzx	9, 16, 17
	rldicl	10, 14, 8, 56
	sldi	15, 15, 8
	sldi	14, 14, 8
	xor	15, 15, 10
	xor	14, 14, 9
	# Byte 13
	rlwinm	18, 20, 28, 20, 27
	addi	19, 18, 8
	ldx	9, 18, 4
	ldx	10, 19, 4
	xor	14, 14, 9
	xor	15, 15, 10
	rldicl	16, 15, 9, 55
	andi.   16, 16, 510
	lhzx	9, 16, 17
	rldicl	10, 14, 8, 56
	sldi	15, 15, 8
	sldi	14, 14, 8
	xor	15, 15, 10
	xor	14, 14, 9
	# Byte 12
	rlwinm	18, 20, 4, 20, 27
	addi	19, 18, 8
	ldx	9, 18, 4
	ldx	10, 19, 4
	xor	14, 14, 9
	xor	15, 15, 10
	rldicl	16, 15, 9, 55
	andi.   16, 16, 510
	lhzx	9, 16, 17
	rldicl	10, 14, 8, 56
	sldi	15, 15, 8
	sldi	14, 14, 8
	xor	15, 15, 10
	xor	14, 14, 9
	# Byte 11
	rlwinm	18, 8, 12, 20, 27
	addi	19, 18, 8
	ldx	9, 18, 4
	ldx	10, 19, 4
	xor	14, 14, 9
	xor	15, 15, 10
	rldicl	16, 15, 9, 55
	andi.   16, 16, 510
	lhzx	9, 16, 17
	rldicl	10, 14, 8, 56
	sldi	15, 15, 8
	sldi	14, 14, 8
	xor	15, 15, 10
	xor	14, 14, 9
	# Byte 10
	rlwinm	18, 8, 20, 20, 27
	addi	19, 18, 8
	ldx	9, 18, 4
	ldx	10, 19, 4
	xor	14, 14, 9
	xor	15, 15, 10
	rldicl	16, 15, 9, 55
	andi.   16, 16, 510
	lhzx	9, 16, 17
	rldicl	10, 14, 8, 56
	sldi	15, 15, 8
	sldi	14, 14, 8
	xor	15, 15, 10
	xor	14, 14, 9
	# Byte 9
	rlwinm	18, 8, 28, 20, 27
	addi	19, 18, 8
	ldx	9, 18, 4
	ldx	10, 19, 4
	xor	14, 14, 9
	xor	15, 15, 10
	rldicl	16, 15, 9, 55
	andi.   16, 16, 510
	lhzx	9, 16, 17
	rldicl	10, 14, 8, 56
	sldi	15, 15, 8
	sldi	14, 14, 8
	xor	15, 15, 10
	xor	14, 14, 9
	# Byte 8
	rlwinm	18, 8, 4, 20, 27
	addi	19, 18, 8
	ldx	9, 18, 4
	ldx	10, 19, 4
	xor	14, 14, 9
	xor	15, 15, 10
	rldicl	16, 15, 9, 55
	andi.   16, 16, 510
	lhzx	9, 16, 17
	rldicl	10, 14, 8, 56
	sldi	15, 15, 8
	sldi	14, 14, 8
	xor	15, 15, 10
	xor	14, 14, 9
	rldicr	20, 7, 32, 63
	# Byte 7
	rlwinm	18, 20, 12, 20, 27
	addi	19, 18, 8
	ldx	9, 18, 4
	ldx	10, 19, 4
	xor	14, 14, 9
	xor	15, 15, 10
	rldicl	16, 15, 9, 55
	andi.   16, 16, 510
	lhzx	9, 16, 17
	rldicl	10, 14, 8, 56
	sldi	15, 15, 8
	sldi	14, 14, 8
	xor	15, 15, 10
	xor	14, 14, 9
	# Byte 6
	rlwinm	18, 20, 20, 20, 27
	addi	19, 18, 8
	ldx	9, 18, 4
	ldx	10, 19, 4
	xor	14, 14, 9
	xor	15, 15, 10
	rldicl	16, 15, 9, 55
	andi.   16, 16, 510
	lhzx	9, 16, 17
	rldicl	10, 14, 8, 56
	sldi	15, 15, 8
	sldi	14, 14, 8
	xor	15, 15, 10
	xor	14, 14, 9
	# Byte 5
	rlwinm	18, 20, 28, 20, 27
	addi	19, 18, 8
	ldx	9, 18, 4
	ldx	10, 19, 4
	xor	14, 14, 9
	xor	15, 15, 10
	rldicl	16, 15, 9, 55
	andi.   16, 16, 510
	lhzx	9, 16, 17
	rldicl	10, 14, 8, 56
	sldi	15, 15, 8
	sldi	14, 14, 8
	xor	15, 15, 10
	xor	14, 14, 9
	# Byte 4
	rlwinm	18, 20, 4, 20, 27
	addi	19, 18, 8
	ldx	9, 18, 4
	ldx	10, 19, 4
	xor	14, 14, 9
	xor	15, 15, 10
	rldicl	16, 15, 9, 55
	andi.   16, 16, 510
	lhzx	9, 16, 17
	rldicl	10, 14, 8, 56
	sldi	15, 15, 8
	sldi	14, 14, 8
	xor	15, 15, 10
	xor	14, 14, 9
	# Byte 3
	rlwinm	18, 7, 12, 20, 27
	addi	19, 18, 8
	ldx	9, 18, 4
	ldx	10, 19, 4
	xor	14, 14, 9
	xor	15, 15, 10
	rldicl	16, 15, 9, 55
	andi.   16, 16, 510
	lhzx	9, 16, 17
	rldicl	10, 14, 8, 56
	sldi	15, 15, 8
	sldi	14, 14, 8
	xor	15, 15, 10
	xor	14, 14, 9
	# Byte 2
	rlwinm	18, 7, 20, 20, 27
	addi	19, 18, 8
	ldx	9, 18, 4
	ldx	10, 19, 4
	xor	14, 14, 9
	xor	15, 15, 10
	rldicl	16, 15, 9, 55
	andi.   16, 16, 510
	lhzx	9, 16, 17
	rldicl	10, 14, 8, 56
	sldi	15, 15, 8
	sldi	14, 14, 8
	xor	15, 15, 10
	xor	14, 14, 9
	# Byte 1
	rlwinm	18, 7, 28, 20, 27
	addi	19, 18, 8
	ldx	9, 18, 4
	ldx	10, 19, 4
	xor	14, 14, 9
	xor	15, 15, 10
	rldicl	16, 15, 9, 55
	andi.   16, 16, 510
	lhzx	9, 16, 17
	rldicl	10, 14, 8, 56
	sldi	15, 15, 8
	sldi	14, 14, 8
	xor	15, 15, 10
	xor	14, 14, 9
	# Byte 0
	rlwinm	18, 7, 4, 20, 27
	addi	19, 18, 8
	ldx	9, 18, 4
	ldx	10, 19, 4
	xor	7, 14, 9
	xor	8, 15, 10
	addi	5, 5, 16
	addic.	6, 6, -16
	li	16, 8
	stdbrx	7, 0, 3
	stdbrx	8, 16, 3
	bne	L_GCM_gmult_len_start_block
	ld	0, 56(1)
	mtlr	0
	ld	14, 0(1)
	ld	15, 8(1)
	ld	16, 16(1)
	ld	17, 24(1)
	ld	18, 32(1)
	ld	19, 40(1)
	ld	20, 48(1)
	addi	1, 1, 0x40
	blr
	.size	GCM_gmult_len,.-GCM_gmult_len
#endif /* GCM_TABLE */
#endif /* HAVE_AESGCM */
#endif /* !defined(NO_AES) && defined(WOLFSSL_PPC64_ASM) */
#endif /* WOLFSSL_PPC64_ASM */

#if defined(__linux__) && defined(__ELF__)
.section	.note.GNU-stack,"",%progbits
#endif
#endif /* !WOLFSSL_PPC64_ASM_INLINE */
