/* armv8-mldsa-asm
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
 *   ruby ./mldsa/mldsa.rb arm64 \
 *       ../wolfssl/wolfcrypt/src/port/arm/armv8-mldsa-asm.S
 */

#define WC_FIPS_LL_CRYPTO
#define _WC_BUILDING_ARMV8_MLDSA_ASM_S

#include <wolfssl/wolfcrypt/libwolfssl_sources_asm.h>

#ifdef WOLFSSL_ARMASM
#ifdef __aarch64__
#ifndef WOLFSSL_ARMASM_INLINE
#ifdef WOLFSSL_HAVE_MLDSA
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mldsa_aarch64_consts, %object
	.size	L_mldsa_aarch64_consts, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_aarch64_consts:
	.long	0x007fe001,0x03802001,0x00400000,0x00000000
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mldsa_aarch64_zetas, %object
	.size	L_mldsa_aarch64_zetas, 1280
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_aarch64_zetas:
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
	.long	0xffc406e5,0xffc406e5,0xffe8ac81,0xffe8ac81
	.long	0xffc7e1cf,0xffc7e1cf,0xffd19819,0xffd19819
	.long	0xffe9d65d,0xffe9d65d,0x003509ee,0x003509ee
	.long	0x002135c7,0x002135c7,0xffe7cfbb,0xffe7cfbb
	.long	0xffeccf75,0xffeccf75,0x001d9772,0x001d9772
	.long	0xffc1b072,0xffc1b072,0xfff0bcf6,0xfff0bcf6
	.long	0xffcf5280,0xffcf5280,0xffcfd2ae,0xffcfd2ae
	.long	0xffc890e0,0xffc890e0,0x0001efca,0x0001efca
	.long	0x003410f2,0x003410f2,0xfff0fe85,0xfff0fe85
	.long	0x0020c638,0x0020c638,0x00296e9f,0x00296e9f
	.long	0xffd2b7a3,0xffd2b7a3,0xffc7a44b,0xffc7a44b
	.long	0xfff9ba6d,0xfff9ba6d,0xffda3409,0xffda3409
	.long	0xfff5c282,0xfff5c282,0xffed4113,0xffed4113
	.long	0xffffa63b,0xffffa63b,0xffec09f7,0xffec09f7
	.long	0xfffa2bdd,0xfffa2bdd,0x001495d4,0x001495d4
	.long	0x001c4563,0x001c4563,0xffea2c62,0xffea2c62
	.long	0xffccfbe9,0xffccfbe9,0x00040af0,0x00040af0
	.long	0x0007c417,0x0007c417,0x002f4588,0x002f4588
	.long	0x0000ad00,0x0000ad00,0xffef36be,0xffef36be
	.long	0x000dcd44,0x000dcd44,0x003c675a,0x003c675a
	.long	0xffc72bca,0xffc72bca,0xffffde7e,0xffffde7e
	.long	0x00193948,0x00193948,0xffce69c0,0xffce69c0
	.long	0x0024756c,0x0024756c,0xfffcc7df,0xfffcc7df
	.long	0x000b98a1,0x000b98a1,0xffebe808,0xffebe808
	.long	0x0002e46c,0x0002e46c,0xffc9c808,0xffc9c808
	.long	0x003036c2,0x003036c2,0xffe3bff6,0xffe3bff6
	.long	0xffdb3c93,0xffdb3c93,0xfffd4ae0,0xfffd4ae0
	.long	0x00141305,0x00141305,0x00147792,0x00147792
	.long	0x00139e25,0x00139e25,0xffe7d0e0,0xffe7d0e0
	.long	0xfff39944,0xfff39944,0xffea0802,0xffea0802
	.long	0xffd1eea2,0xffd1eea2,0xffc4c79c,0xffc4c79c
	.long	0xffc8a057,0xffc8a057,0x003a97d9,0x003a97d9
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
	.section	.rodata
	.type	L_mldsa_aarch64_zetas_qinv, %object
	.size	L_mldsa_aarch64_zetas_qinv, 1280
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_aarch64_zetas_qinv:
	.long	0x00801c06,0x6d1f44f7,0x8cf87102,0x8d187503
	.long	0x61cc1e44,0x58172118,0x6017a128,0x61cb9e24
	.long	0x12613e2b,0x93c9492b,0xae1024ad,0xbeeff47f
	.long	0x8cfe3a75,0x1eb51b09,0xeef89a49,0x254dc527
	.long	0x66f49658,0x7c1da070,0xaea405a4,0x3327b788
	.long	0x6ba99d90,0x0d42eaa0,0xeb54f968,0x28cf337b
	.long	0x629a6dd6,0xcba1fae7,0xb50984f7,0xd360fc98
	.long	0x13a17035,0x6d83f422,0xa9fd5201,0xba3ce5c5
	.long	0x91f62a67,0x9ec57620,0xac4894cd,0x6d8e7ec5
	.long	0x5f070503,0xbfceb02c,0x8ed3c7d4,0xdc919eaf
	.long	0xf3f5b585,0xe3a10e7c,0xde894a96,0x6b1c5e41
	.long	0xc0b60400,0x7ac50a4d,0x9cf7569c,0xbe23655d
	.long	0x97adb23d,0xca41aad6,0x18f93e1e,0x6d30cf59
	.long	0x8d3d643f,0x3b223617,0x3473145c,0x78a9f38c
	.long	0x588163a8,0x9e7b5b9a,0xeefd4f76,0x89c59853
	.long	0xa6e20534,0xc75efc30,0x99ca1d54,0xc73aef2d
	.long	0xa220a6e5,0xa220a6e5,0xd8f8cc81,0xd8f8cc81
	.long	0x5081c1cf,0x5081c1cf,0x8a54b819,0x8a54b819
	.long	0x8035765d,0x8035765d,0x6272c9ee,0x6272c9ee
	.long	0x5f5a15c7,0x5f5a15c7,0x085f2fbb,0x085f2fbb
	.long	0xb35b6f75,0xb35b6f75,0xc20bd772,0xc20bd772
	.long	0xc4cff072,0xc4cff072,0x748f7cf6,0x748f7cf6
	.long	0xaa1f5280,0xaa1f5280,0x5b2592ae,0x5b2592ae
	.long	0x21e490e0,0x21e490e0,0x80fb2fca,0x80fb2fca
	.long	0xd15250f2,0xd15250f2,0xf1419e85,0xf1419e85
	.long	0xdce7c638,0xdce7c638,0x5a7d4e9f,0x5a7d4e9f
	.long	0x114717a3,0x114717a3,0xfad1044b,0xfad1044b
	.long	0xb4c75a6d,0xb4c75a6d,0x65db5409,0x65db5409
	.long	0x7f460282,0x7f460282,0x6a8fa113,0x6a8fa113
	.long	0xc347063b,0xc347063b,0x61aae9f7,0x61aae9f7
	.long	0xcaf5cbdd,0xcaf5cbdd,0xf8cf15d4,0xf8cf15d4
	.long	0x6348a563,0x6348a563,0x9c766c62,0x9c766c62
	.long	0x4eca1be9,0x4eca1be9,0xc9620af0,0xc9620af0
	.long	0x490aa417,0x490aa417,0x44e04588,0x44e04588
	.long	0x95a0ad00,0x95a0ad00,0x7fc6f6be,0x7fc6f6be
	.long	0x27b64d44,0x27b64d44,0x4827a75a,0x4827a75a
	.long	0x28406bca,0x28406bca,0xb4cf9e7e,0xb4cf9e7e
	.long	0xa3423948,0xa3423948,0xed0669c0,0xed0669c0
	.long	0x88d1f56c,0x88d1f56c,0x2578a7df,0x2578a7df
	.long	0xa69fb8a1,0xa69fb8a1,0x98ece808,0x98ece808
	.long	0xd690646c,0xd690646c,0x54cac808,0x54cac808
	.long	0xae0876c2,0xae0876c2,0x54e27ff6,0x54e27ff6
	.long	0x69ed9c93,0x69ed9c93,0xb9594ae0,0xb9594ae0
	.long	0x13f4b305,0x13f4b305,0x0e06b792,0x0e06b792
	.long	0xf5583e25,0xf5583e25,0x0a03d0e0,0x0a03d0e0
	.long	0xe11c1944,0xe11c1944,0x47ea4802,0x47ea4802
	.long	0x74a62ea2,0x74a62ea2,0x3ab8479c,0x3ab8479c
	.long	0x44538057,0x44538057,0xcab5b7d9,0xcab5b7d9
	.long	0xfff24a93,0x3b1f3f5a,0x513dd8d4,0x2c7941f8
	.long	0xaebb3f72,0x36619dfb,0x01ce8b9f,0xab4de422
	.long	0xdbe2b2f5,0xfd560587,0xec8b24f0,0x79213b5d
	.long	0x78de48a0,0x462622fc,0x64587b56,0x718b05de
	.long	0x00d97e5e,0xe6df9e1a,0xe12aa0e6,0x4af7bf5a
	.long	0x3c77ef83,0xcf38a28a,0x78dfd704,0x72d786fc
	.long	0x337a2021,0x682f1af6,0xae2f8084,0x7321af86
	.long	0x6c79597d,0xec92bcd6,0x07a68592,0x4b0161c2
	.long	0x7ea85919,0x3625e10c,0xbd02ed41,0x34c2101b
	.long	0xb71152e7,0x6e54603b,0x08335cc7,0x61279924
	.long	0x8d87fee5,0xb9dc3199,0xda1fba3a,0x75416d71
	.long	0x9e61611c,0xaf438984,0xd9b01051,0x00611a46
	.long	0xa4698518,0xfbaad4be,0x02ba5891,0xb33bdb90
	.long	0x29637089,0xed44653f,0x28066b4b,0x43c4b6a6
	.long	0x0e0368be,0x3ab6411b,0x84951e3e,0x6a100d2f
	.long	0xc1b59de4,0x396ce6c7,0x1902d283,0x428fcd6e
	.long	0x3196d953,0xbfb06099,0x48882578,0x3e20a5ad
	.long	0xee178405,0x2408bbe7,0xefdf1de8,0x53cdd8cf
	.long	0x2d1e3934,0xc3164a0c,0xb3e57ff8,0x2a8eb157
	.long	0xf07bf11b,0x24496c12,0x162410d8,0x380a3e1f
	.long	0x5cac4658,0x0a567d8b,0xaf1c53b7,0xa40f5c8f
	.long	0x4fd0dd98,0x81466898,0xe91a34bb,0x7ae273a7
	.long	0x86672cbe,0xb185fc1c,0x3159aa08,0xcb5c1d71
	.long	0xcd20fca5,0xc20c779a,0xdc748167,0x66ec2c3d
	.long	0x85f9213c,0x005ce539,0x29dda115,0xa3bc1dc0
	.long	0x9940a4f7,0xf96f9bf4,0xef5715e7,0x1788f40e
	.long	0xa1221d45,0x21b44cd0,0xf07a3cae,0x10ea2668
	.long	0xe5b98e98,0x97358633,0xfbb745da,0x2e40dfdb
	.long	0x42bfa764,0xa093c1af,0xb7f533dd,0x42fe3d09
	.long	0x5c152c93,0x3471b805,0xa69ddc2a,0x0bff05a9
	.long	0x09418a50,0x94214f2c,0x7969034e,0x734716df
	.long	0xc5f555ca,0x17e25e68,0xdfc9d6b6,0x1657e9ce
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mldsa_aarch64_zetas_inv, %object
	.size	L_mldsa_aarch64_zetas_inv, 1280
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_aarch64_zetas_inv:
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
	.long	0xffc56827,0xffc56827,0x00375fa9,0x00375fa9
	.long	0x003b3864,0x003b3864,0x002e115e,0x002e115e
	.long	0x0015f7fe,0x0015f7fe,0x000c66bc,0x000c66bc
	.long	0x00182f20,0x00182f20,0xffec61db,0xffec61db
	.long	0xffeb886e,0xffeb886e,0xffebecfb,0xffebecfb
	.long	0x0002b520,0x0002b520,0x0024c36d,0x0024c36d
	.long	0x001c400a,0x001c400a,0xffcfc93e,0xffcfc93e
	.long	0x003637f8,0x003637f8,0xfffd1b94,0xfffd1b94
	.long	0x001417f8,0x001417f8,0xfff4675f,0xfff4675f
	.long	0x00033821,0x00033821,0xffdb8a94,0xffdb8a94
	.long	0x00319640,0x00319640,0xffe6c6b8,0xffe6c6b8
	.long	0x00002182,0x00002182,0x0038d436,0x0038d436
	.long	0xffc398a6,0xffc398a6,0xfff232bc,0xfff232bc
	.long	0x0010c942,0x0010c942,0xffff5300,0xffff5300
	.long	0xffd0ba78,0xffd0ba78,0xfff83be9,0xfff83be9
	.long	0xfffbf510,0xfffbf510,0x00330417,0x00330417
	.long	0x0015d39e,0x0015d39e,0xffe3ba9d,0xffe3ba9d
	.long	0xffeb6a2c,0xffeb6a2c,0x0005d423,0x0005d423
	.long	0x0013f609,0x0013f609,0x000059c5,0x000059c5
	.long	0x0012beed,0x0012beed,0x000a3d7e,0x000a3d7e
	.long	0x0025cbf7,0x0025cbf7,0x00064593,0x00064593
	.long	0x00385bb5,0x00385bb5,0x002d485d,0x002d485d
	.long	0xffd69161,0xffd69161,0xffdf39c8,0xffdf39c8
	.long	0x000f017b,0x000f017b,0xffcbef0e,0xffcbef0e
	.long	0xfffe1036,0xfffe1036,0x00376f20,0x00376f20
	.long	0x00302d52,0x00302d52,0x0030ad80,0x0030ad80
	.long	0x000f430a,0x000f430a,0x003e4f8e,0x003e4f8e
	.long	0xffe2688e,0xffe2688e,0x0013308b,0x0013308b
	.long	0x00183045,0x00183045,0xffdeca39,0xffdeca39
	.long	0xffcaf612,0xffcaf612,0x001629a3,0x001629a3
	.long	0x002e67e7,0x002e67e7,0x00381e31,0x00381e31
	.long	0x0017537f,0x0017537f,0x003bf91b,0x003bf91b
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
	.long	0x0007eafd,0x0027cefe,0x003caa21,0x0000a3fa
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mldsa_aarch64_zetas_inv_qinv, %object
	.size	L_mldsa_aarch64_zetas_inv_qinv, 1280
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_aarch64_zetas_inv_qinv:
	.long	0xe9a81632,0x2036294a,0xe81da198,0x3a0aaa36
	.long	0x8cb8e921,0x8696fcb2,0x6bdeb0d4,0xf6be75b0
	.long	0xf400fa57,0x596223d6,0xcb8e47fb,0xa3ead36d
	.long	0xbd01c2f7,0x480acc23,0x5f6c3e51,0xbd40589c
	.long	0xd1bf2025,0x0448ba26,0x68ca79cd,0x1a467168
	.long	0xef15d998,0x0f85c352,0xde4bb330,0x5edde2bb
	.long	0xe8770bf2,0x10a8ea19,0x0690640c,0x66bf5b09
	.long	0x5c43e240,0xd6225eeb,0xffa31ac7,0x7a06dec4
	.long	0x9913d3c3,0x238b7e99,0x3df38866,0x32df035b
	.long	0x34a3e28f,0xcea655f8,0x4e7a03e4,0x7998d342
	.long	0x851d8c59,0x16e5cb45,0x7eb99768,0xb02f2268
	.long	0x5bf0a371,0x50e3ac49,0xf5a98275,0xa353b9a8
	.long	0xc7f5c1e1,0xe9dbef28,0xdbb693ee,0x0f840ee5
	.long	0xd5714ea9,0x4c1a8008,0x3ce9b5f4,0xd2e1c6cc
	.long	0xac322731,0x1020e218,0xdbf74419,0x11e87bfb
	.long	0xc1df5a53,0xb777da88,0x404f9f67,0xce6926ad
	.long	0xbd703292,0xe6fd2d7d,0xc6931939,0x3e4a621c
	.long	0x95eff2d1,0x7b6ae1c2,0xc549bee5,0xf1fc9742
	.long	0xbc3b495a,0xd7f994b5,0x12bb9ac1,0xd69c8f77
	.long	0x4cc42470,0xfd45a76f,0x04552b42,0x5b967ae8
	.long	0xff9ee5ba,0x264fefaf,0x50bc767c,0x619e9ee4
	.long	0x8abe928f,0x25e045c6,0x4623ce67,0x7278011b
	.long	0x9ed866dc,0xf7cca339,0x91ab9fc5,0x48eead19
	.long	0xcb3defe5,0x42fd12bf,0xc9da1ef4,0x8157a6e7
	.long	0xb4fe9e3e,0xf8597a6e,0x136d432a,0x9386a683
	.long	0x8cde507a,0x51d07f7c,0x97d0e50a,0xcc85dfdf
	.long	0x8d287904,0x872028fc,0x30c75d76,0xc388107d
	.long	0xb50840a6,0x1ed55f1a,0x192061e6,0xff2681a2
	.long	0x8e74fa22,0x9ba784aa,0xb9d9dd04,0x8721b760
	.long	0x86dec4a3,0x1374db10,0x02a9fa79,0x241d4d0b
	.long	0x54b21bde,0xfe317461,0xc99e6205,0x5144c08e
	.long	0xd386be08,0xaec2272c,0xc4e0c0a6,0x000db56d
	.long	0x354a4827,0x354a4827,0xbbac7fa9,0xbbac7fa9
	.long	0xc547b864,0xc547b864,0x8b59d15e,0x8b59d15e
	.long	0xb815b7fe,0xb815b7fe,0x1ee3e6bc,0x1ee3e6bc
	.long	0xf5fc2f20,0xf5fc2f20,0x0aa7c1db,0x0aa7c1db
	.long	0xf1f9486e,0xf1f9486e,0xec0b4cfb,0xec0b4cfb
	.long	0x46a6b520,0x46a6b520,0x9612636d,0x9612636d
	.long	0xab1d800a,0xab1d800a,0x51f7893e,0x51f7893e
	.long	0xab3537f8,0xab3537f8,0x296f9b94,0x296f9b94
	.long	0x671317f8,0x671317f8,0x5960475f,0x5960475f
	.long	0xda875821,0xda875821,0x772e0a94,0x772e0a94
	.long	0x12f99640,0x12f99640,0x5cbdc6b8,0x5cbdc6b8
	.long	0x4b306182,0x4b306182,0xd7bf9436,0xd7bf9436
	.long	0xb7d858a6,0xb7d858a6,0xd849b2bc,0xd849b2bc
	.long	0x80390942,0x80390942,0x6a5f5300,0x6a5f5300
	.long	0xbb1fba78,0xbb1fba78,0xb6f55be9,0xb6f55be9
	.long	0x369df510,0x369df510,0xb135e417,0xb135e417
	.long	0x6389939e,0x6389939e,0x9cb75a9d,0x9cb75a9d
	.long	0x0730ea2c,0x0730ea2c,0x350a3423,0x350a3423
	.long	0x9e551609,0x9e551609,0x3cb8f9c5,0x3cb8f9c5
	.long	0x95705eed,0x95705eed,0x80b9fd7e,0x80b9fd7e
	.long	0x9a24abf7,0x9a24abf7,0x4b38a593,0x4b38a593
	.long	0x052efbb5,0x052efbb5,0xeeb8e85d,0xeeb8e85d
	.long	0xa582b161,0xa582b161,0x231839c8,0x231839c8
	.long	0x0ebe617b,0x0ebe617b,0x2eadaf0e,0x2eadaf0e
	.long	0x7f04d036,0x7f04d036,0xde1b6f20,0xde1b6f20
	.long	0xa4da6d52,0xa4da6d52,0x55e0ad80,0x55e0ad80
	.long	0x8b70830a,0x8b70830a,0x3b300f8e,0x3b300f8e
	.long	0x3df4288e,0x3df4288e,0x4ca4908b,0x4ca4908b
	.long	0xf7a0d045,0xf7a0d045,0xa0a5ea39,0xa0a5ea39
	.long	0x9d8d3612,0x9d8d3612,0x7fca89a3,0x7fca89a3
	.long	0x75ab47e7,0x75ab47e7,0xaf7e3e31,0xaf7e3e31
	.long	0x2707337f,0x2707337f,0x5ddf591b,0x5ddf591b
	.long	0x38c510d3,0x6635e2ac,0x38a103d0,0x591dfacc
	.long	0x763a67ad,0x1102b08a,0x6184a466,0xa77e9c58
	.long	0x87560c74,0xcb8ceba4,0xc4ddc9e9,0x72c29bc1
	.long	0x92cf30a7,0xe706c1e2,0x35be552a,0x68524dc3
	.long	0x41dc9aa3,0x6308a964,0x853af5b3,0x3f49fc00
	.long	0x94e3a1bf,0x2176b56a,0x1c5ef184,0x0c0a4a7b
	.long	0x236e6151,0x712c382c,0x40314fd4,0xa0f8fafd
	.long	0x9271813b,0x53b76b33,0x613a89e0,0x6e09d599
	.long	0x45c31a3b,0x5602adff,0x927c0bde,0xec5e8fcb
	.long	0x2c9f0368,0x4af67b09,0x345e0519,0x9d65922a
	.long	0xd730cc85,0x14ab0698,0xf2bd1560,0x94566270
	.long	0xccd84878,0x515bfa5c,0x83e25f90,0x990b69a8
	.long	0xdab23ad9,0x110765b7,0xe14ae4f7,0x7301c58b
	.long	0x41100b81,0x51efdb53,0x6c36b6d5,0xed9ec1d5
	.long	0x9e3461dc,0x9fe85ed8,0xa7e8dee8,0x9e33e1bc
	.long	0x72e78afd,0x73078efe,0x0900ca21,0xff7fe3fa
#ifndef __APPLE__
.text
.globl	mldsa_ntt_neon
WC_ASM_ATT_HIDDEN(mldsa_ntt_neon)
.type	mldsa_ntt_neon,@function
.align	2
mldsa_ntt_neon:
#else
.section	__TEXT,__text
.globl	_mldsa_ntt_neon
WC_ASM_ATT_HIDDEN(_mldsa_ntt_neon)
.p2align	2
_mldsa_ntt_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
	stp	d12, d13, [x29, #48]
	stp	d14, d15, [x29, #64]
#ifndef __APPLE__
	adrp x1, L_mldsa_aarch64_zetas
	add  x1, x1, :lo12:L_mldsa_aarch64_zetas
#else
	adrp x1, L_mldsa_aarch64_zetas@PAGE
	add  x1, x1, L_mldsa_aarch64_zetas@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x2, L_mldsa_aarch64_zetas_qinv
	add  x2, x2, :lo12:L_mldsa_aarch64_zetas_qinv
#else
	adrp x2, L_mldsa_aarch64_zetas_qinv@PAGE
	add  x2, x2, L_mldsa_aarch64_zetas_qinv@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x3, L_mldsa_aarch64_consts
	add  x3, x3, :lo12:L_mldsa_aarch64_consts
#else
	adrp x3, L_mldsa_aarch64_consts@PAGE
	add  x3, x3, L_mldsa_aarch64_consts@PAGEOFF
#endif /* __APPLE__ */
	ldr	q4, [x3]
	ldr	q5, [x0]
	ldr	q6, [x0, #64]
	ldr	q7, [x0, #128]
	ldr	q8, [x0, #192]
	ldr	q9, [x0, #256]
	ldr	q10, [x0, #320]
	ldr	q11, [x0, #384]
	ldr	q12, [x0, #448]
	ldr	q13, [x0, #512]
	ldr	q14, [x0, #576]
	ldr	q15, [x0, #640]
	ldr	q16, [x0, #704]
	ldr	q17, [x0, #768]
	ldr	q18, [x0, #832]
	ldr	q19, [x0, #896]
	ldr	q20, [x0, #960]
	ldr	q0, [x1]
	ldr	q1, [x2]
	mul	v29.4s, v13.4s, v1.s[1]
	mul	v30.4s, v14.4s, v1.s[1]
	sqrdmulh	v21.4s, v13.4s, v0.s[1]
	sqrdmulh	v22.4s, v14.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v15.4s, v1.s[1]
	mul	v30.4s, v16.4s, v1.s[1]
	sqrdmulh	v23.4s, v15.4s, v0.s[1]
	sqrdmulh	v24.4s, v16.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v17.4s, v1.s[1]
	mul	v30.4s, v18.4s, v1.s[1]
	sqrdmulh	v25.4s, v17.4s, v0.s[1]
	sqrdmulh	v26.4s, v18.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[1]
	mul	v30.4s, v20.4s, v1.s[1]
	sqrdmulh	v27.4s, v19.4s, v0.s[1]
	sqrdmulh	v28.4s, v20.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v13.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v14.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v15.4s, v7.4s, v23.4s
	add	v7.4s, v7.4s, v23.4s
	sub	v16.4s, v8.4s, v24.4s
	add	v8.4s, v8.4s, v24.4s
	sub	v17.4s, v9.4s, v25.4s
	add	v9.4s, v9.4s, v25.4s
	sub	v18.4s, v10.4s, v26.4s
	add	v10.4s, v10.4s, v26.4s
	sub	v19.4s, v11.4s, v27.4s
	add	v11.4s, v11.4s, v27.4s
	sub	v20.4s, v12.4s, v28.4s
	add	v12.4s, v12.4s, v28.4s
	mul	v29.4s, v9.4s, v1.s[2]
	mul	v30.4s, v10.4s, v1.s[2]
	sqrdmulh	v21.4s, v9.4s, v0.s[2]
	sqrdmulh	v22.4s, v10.4s, v0.s[2]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v11.4s, v1.s[2]
	mul	v30.4s, v12.4s, v1.s[2]
	sqrdmulh	v23.4s, v11.4s, v0.s[2]
	sqrdmulh	v24.4s, v12.4s, v0.s[2]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v17.4s, v1.s[3]
	mul	v30.4s, v18.4s, v1.s[3]
	sqrdmulh	v25.4s, v17.4s, v0.s[3]
	sqrdmulh	v26.4s, v18.4s, v0.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[3]
	mul	v30.4s, v20.4s, v1.s[3]
	sqrdmulh	v27.4s, v19.4s, v0.s[3]
	sqrdmulh	v28.4s, v20.4s, v0.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v9.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v10.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v11.4s, v7.4s, v23.4s
	add	v7.4s, v7.4s, v23.4s
	sub	v12.4s, v8.4s, v24.4s
	add	v8.4s, v8.4s, v24.4s
	sub	v17.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v18.4s, v14.4s, v26.4s
	add	v14.4s, v14.4s, v26.4s
	sub	v19.4s, v15.4s, v27.4s
	add	v15.4s, v15.4s, v27.4s
	sub	v20.4s, v16.4s, v28.4s
	add	v16.4s, v16.4s, v28.4s
	ldr	q0, [x1, #16]
	ldr	q1, [x2, #16]
	mul	v29.4s, v7.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[0]
	sqrdmulh	v21.4s, v7.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[0]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v11.4s, v1.s[1]
	mul	v30.4s, v12.4s, v1.s[1]
	sqrdmulh	v23.4s, v11.4s, v0.s[1]
	sqrdmulh	v24.4s, v12.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v15.4s, v1.s[2]
	mul	v30.4s, v16.4s, v1.s[2]
	sqrdmulh	v25.4s, v15.4s, v0.s[2]
	sqrdmulh	v26.4s, v16.4s, v0.s[2]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[3]
	mul	v30.4s, v20.4s, v1.s[3]
	sqrdmulh	v27.4s, v19.4s, v0.s[3]
	sqrdmulh	v28.4s, v20.4s, v0.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v7.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v11.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v10.4s, v24.4s
	add	v10.4s, v10.4s, v24.4s
	sub	v15.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v14.4s, v26.4s
	add	v14.4s, v14.4s, v26.4s
	sub	v19.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v18.4s, v28.4s
	add	v18.4s, v18.4s, v28.4s
	ldp	q0, q2, [x1, #32]
	ldp	q1, q3, [x2, #32]
	mul	v29.4s, v6.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[1]
	sqrdmulh	v21.4s, v6.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v10.4s, v1.s[2]
	mul	v30.4s, v12.4s, v1.s[3]
	sqrdmulh	v23.4s, v10.4s, v0.s[2]
	sqrdmulh	v24.4s, v12.4s, v0.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v14.4s, v3.s[0]
	mul	v30.4s, v16.4s, v3.s[1]
	sqrdmulh	v25.4s, v14.4s, v2.s[0]
	sqrdmulh	v26.4s, v16.4s, v2.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v18.4s, v3.s[2]
	mul	v30.4s, v20.4s, v3.s[3]
	sqrdmulh	v27.4s, v18.4s, v2.s[2]
	sqrdmulh	v28.4s, v20.4s, v2.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	str	q5, [x0]
	str	q6, [x0, #64]
	str	q7, [x0, #128]
	str	q8, [x0, #192]
	str	q9, [x0, #256]
	str	q10, [x0, #320]
	str	q11, [x0, #384]
	str	q12, [x0, #448]
	str	q13, [x0, #512]
	str	q14, [x0, #576]
	str	q15, [x0, #640]
	str	q16, [x0, #704]
	str	q17, [x0, #768]
	str	q18, [x0, #832]
	str	q19, [x0, #896]
	str	q20, [x0, #960]
	ldr	q5, [x0, #16]
	ldr	q6, [x0, #80]
	ldr	q7, [x0, #144]
	ldr	q8, [x0, #208]
	ldr	q9, [x0, #272]
	ldr	q10, [x0, #336]
	ldr	q11, [x0, #400]
	ldr	q12, [x0, #464]
	ldr	q13, [x0, #528]
	ldr	q14, [x0, #592]
	ldr	q15, [x0, #656]
	ldr	q16, [x0, #720]
	ldr	q17, [x0, #784]
	ldr	q18, [x0, #848]
	ldr	q19, [x0, #912]
	ldr	q20, [x0, #976]
	ldr	q0, [x1]
	ldr	q1, [x2]
	mul	v29.4s, v13.4s, v1.s[1]
	mul	v30.4s, v14.4s, v1.s[1]
	sqrdmulh	v21.4s, v13.4s, v0.s[1]
	sqrdmulh	v22.4s, v14.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v15.4s, v1.s[1]
	mul	v30.4s, v16.4s, v1.s[1]
	sqrdmulh	v23.4s, v15.4s, v0.s[1]
	sqrdmulh	v24.4s, v16.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v17.4s, v1.s[1]
	mul	v30.4s, v18.4s, v1.s[1]
	sqrdmulh	v25.4s, v17.4s, v0.s[1]
	sqrdmulh	v26.4s, v18.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[1]
	mul	v30.4s, v20.4s, v1.s[1]
	sqrdmulh	v27.4s, v19.4s, v0.s[1]
	sqrdmulh	v28.4s, v20.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v13.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v14.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v15.4s, v7.4s, v23.4s
	add	v7.4s, v7.4s, v23.4s
	sub	v16.4s, v8.4s, v24.4s
	add	v8.4s, v8.4s, v24.4s
	sub	v17.4s, v9.4s, v25.4s
	add	v9.4s, v9.4s, v25.4s
	sub	v18.4s, v10.4s, v26.4s
	add	v10.4s, v10.4s, v26.4s
	sub	v19.4s, v11.4s, v27.4s
	add	v11.4s, v11.4s, v27.4s
	sub	v20.4s, v12.4s, v28.4s
	add	v12.4s, v12.4s, v28.4s
	mul	v29.4s, v9.4s, v1.s[2]
	mul	v30.4s, v10.4s, v1.s[2]
	sqrdmulh	v21.4s, v9.4s, v0.s[2]
	sqrdmulh	v22.4s, v10.4s, v0.s[2]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v11.4s, v1.s[2]
	mul	v30.4s, v12.4s, v1.s[2]
	sqrdmulh	v23.4s, v11.4s, v0.s[2]
	sqrdmulh	v24.4s, v12.4s, v0.s[2]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v17.4s, v1.s[3]
	mul	v30.4s, v18.4s, v1.s[3]
	sqrdmulh	v25.4s, v17.4s, v0.s[3]
	sqrdmulh	v26.4s, v18.4s, v0.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[3]
	mul	v30.4s, v20.4s, v1.s[3]
	sqrdmulh	v27.4s, v19.4s, v0.s[3]
	sqrdmulh	v28.4s, v20.4s, v0.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v9.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v10.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v11.4s, v7.4s, v23.4s
	add	v7.4s, v7.4s, v23.4s
	sub	v12.4s, v8.4s, v24.4s
	add	v8.4s, v8.4s, v24.4s
	sub	v17.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v18.4s, v14.4s, v26.4s
	add	v14.4s, v14.4s, v26.4s
	sub	v19.4s, v15.4s, v27.4s
	add	v15.4s, v15.4s, v27.4s
	sub	v20.4s, v16.4s, v28.4s
	add	v16.4s, v16.4s, v28.4s
	ldr	q0, [x1, #16]
	ldr	q1, [x2, #16]
	mul	v29.4s, v7.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[0]
	sqrdmulh	v21.4s, v7.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[0]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v11.4s, v1.s[1]
	mul	v30.4s, v12.4s, v1.s[1]
	sqrdmulh	v23.4s, v11.4s, v0.s[1]
	sqrdmulh	v24.4s, v12.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v15.4s, v1.s[2]
	mul	v30.4s, v16.4s, v1.s[2]
	sqrdmulh	v25.4s, v15.4s, v0.s[2]
	sqrdmulh	v26.4s, v16.4s, v0.s[2]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[3]
	mul	v30.4s, v20.4s, v1.s[3]
	sqrdmulh	v27.4s, v19.4s, v0.s[3]
	sqrdmulh	v28.4s, v20.4s, v0.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v7.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v11.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v10.4s, v24.4s
	add	v10.4s, v10.4s, v24.4s
	sub	v15.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v14.4s, v26.4s
	add	v14.4s, v14.4s, v26.4s
	sub	v19.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v18.4s, v28.4s
	add	v18.4s, v18.4s, v28.4s
	ldp	q0, q2, [x1, #32]
	ldp	q1, q3, [x2, #32]
	mul	v29.4s, v6.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[1]
	sqrdmulh	v21.4s, v6.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v10.4s, v1.s[2]
	mul	v30.4s, v12.4s, v1.s[3]
	sqrdmulh	v23.4s, v10.4s, v0.s[2]
	sqrdmulh	v24.4s, v12.4s, v0.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v14.4s, v3.s[0]
	mul	v30.4s, v16.4s, v3.s[1]
	sqrdmulh	v25.4s, v14.4s, v2.s[0]
	sqrdmulh	v26.4s, v16.4s, v2.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v18.4s, v3.s[2]
	mul	v30.4s, v20.4s, v3.s[3]
	sqrdmulh	v27.4s, v18.4s, v2.s[2]
	sqrdmulh	v28.4s, v20.4s, v2.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	str	q5, [x0, #16]
	str	q6, [x0, #80]
	str	q7, [x0, #144]
	str	q8, [x0, #208]
	str	q9, [x0, #272]
	str	q10, [x0, #336]
	str	q11, [x0, #400]
	str	q12, [x0, #464]
	str	q13, [x0, #528]
	str	q14, [x0, #592]
	str	q15, [x0, #656]
	str	q16, [x0, #720]
	str	q17, [x0, #784]
	str	q18, [x0, #848]
	str	q19, [x0, #912]
	str	q20, [x0, #976]
	ldr	q5, [x0, #32]
	ldr	q6, [x0, #96]
	ldr	q7, [x0, #160]
	ldr	q8, [x0, #224]
	ldr	q9, [x0, #288]
	ldr	q10, [x0, #352]
	ldr	q11, [x0, #416]
	ldr	q12, [x0, #480]
	ldr	q13, [x0, #544]
	ldr	q14, [x0, #608]
	ldr	q15, [x0, #672]
	ldr	q16, [x0, #736]
	ldr	q17, [x0, #800]
	ldr	q18, [x0, #864]
	ldr	q19, [x0, #928]
	ldr	q20, [x0, #992]
	ldr	q0, [x1]
	ldr	q1, [x2]
	mul	v29.4s, v13.4s, v1.s[1]
	mul	v30.4s, v14.4s, v1.s[1]
	sqrdmulh	v21.4s, v13.4s, v0.s[1]
	sqrdmulh	v22.4s, v14.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v15.4s, v1.s[1]
	mul	v30.4s, v16.4s, v1.s[1]
	sqrdmulh	v23.4s, v15.4s, v0.s[1]
	sqrdmulh	v24.4s, v16.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v17.4s, v1.s[1]
	mul	v30.4s, v18.4s, v1.s[1]
	sqrdmulh	v25.4s, v17.4s, v0.s[1]
	sqrdmulh	v26.4s, v18.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[1]
	mul	v30.4s, v20.4s, v1.s[1]
	sqrdmulh	v27.4s, v19.4s, v0.s[1]
	sqrdmulh	v28.4s, v20.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v13.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v14.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v15.4s, v7.4s, v23.4s
	add	v7.4s, v7.4s, v23.4s
	sub	v16.4s, v8.4s, v24.4s
	add	v8.4s, v8.4s, v24.4s
	sub	v17.4s, v9.4s, v25.4s
	add	v9.4s, v9.4s, v25.4s
	sub	v18.4s, v10.4s, v26.4s
	add	v10.4s, v10.4s, v26.4s
	sub	v19.4s, v11.4s, v27.4s
	add	v11.4s, v11.4s, v27.4s
	sub	v20.4s, v12.4s, v28.4s
	add	v12.4s, v12.4s, v28.4s
	mul	v29.4s, v9.4s, v1.s[2]
	mul	v30.4s, v10.4s, v1.s[2]
	sqrdmulh	v21.4s, v9.4s, v0.s[2]
	sqrdmulh	v22.4s, v10.4s, v0.s[2]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v11.4s, v1.s[2]
	mul	v30.4s, v12.4s, v1.s[2]
	sqrdmulh	v23.4s, v11.4s, v0.s[2]
	sqrdmulh	v24.4s, v12.4s, v0.s[2]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v17.4s, v1.s[3]
	mul	v30.4s, v18.4s, v1.s[3]
	sqrdmulh	v25.4s, v17.4s, v0.s[3]
	sqrdmulh	v26.4s, v18.4s, v0.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[3]
	mul	v30.4s, v20.4s, v1.s[3]
	sqrdmulh	v27.4s, v19.4s, v0.s[3]
	sqrdmulh	v28.4s, v20.4s, v0.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v9.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v10.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v11.4s, v7.4s, v23.4s
	add	v7.4s, v7.4s, v23.4s
	sub	v12.4s, v8.4s, v24.4s
	add	v8.4s, v8.4s, v24.4s
	sub	v17.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v18.4s, v14.4s, v26.4s
	add	v14.4s, v14.4s, v26.4s
	sub	v19.4s, v15.4s, v27.4s
	add	v15.4s, v15.4s, v27.4s
	sub	v20.4s, v16.4s, v28.4s
	add	v16.4s, v16.4s, v28.4s
	ldr	q0, [x1, #16]
	ldr	q1, [x2, #16]
	mul	v29.4s, v7.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[0]
	sqrdmulh	v21.4s, v7.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[0]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v11.4s, v1.s[1]
	mul	v30.4s, v12.4s, v1.s[1]
	sqrdmulh	v23.4s, v11.4s, v0.s[1]
	sqrdmulh	v24.4s, v12.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v15.4s, v1.s[2]
	mul	v30.4s, v16.4s, v1.s[2]
	sqrdmulh	v25.4s, v15.4s, v0.s[2]
	sqrdmulh	v26.4s, v16.4s, v0.s[2]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[3]
	mul	v30.4s, v20.4s, v1.s[3]
	sqrdmulh	v27.4s, v19.4s, v0.s[3]
	sqrdmulh	v28.4s, v20.4s, v0.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v7.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v11.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v10.4s, v24.4s
	add	v10.4s, v10.4s, v24.4s
	sub	v15.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v14.4s, v26.4s
	add	v14.4s, v14.4s, v26.4s
	sub	v19.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v18.4s, v28.4s
	add	v18.4s, v18.4s, v28.4s
	ldp	q0, q2, [x1, #32]
	ldp	q1, q3, [x2, #32]
	mul	v29.4s, v6.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[1]
	sqrdmulh	v21.4s, v6.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v10.4s, v1.s[2]
	mul	v30.4s, v12.4s, v1.s[3]
	sqrdmulh	v23.4s, v10.4s, v0.s[2]
	sqrdmulh	v24.4s, v12.4s, v0.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v14.4s, v3.s[0]
	mul	v30.4s, v16.4s, v3.s[1]
	sqrdmulh	v25.4s, v14.4s, v2.s[0]
	sqrdmulh	v26.4s, v16.4s, v2.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v18.4s, v3.s[2]
	mul	v30.4s, v20.4s, v3.s[3]
	sqrdmulh	v27.4s, v18.4s, v2.s[2]
	sqrdmulh	v28.4s, v20.4s, v2.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	str	q5, [x0, #32]
	str	q6, [x0, #96]
	str	q7, [x0, #160]
	str	q8, [x0, #224]
	str	q9, [x0, #288]
	str	q10, [x0, #352]
	str	q11, [x0, #416]
	str	q12, [x0, #480]
	str	q13, [x0, #544]
	str	q14, [x0, #608]
	str	q15, [x0, #672]
	str	q16, [x0, #736]
	str	q17, [x0, #800]
	str	q18, [x0, #864]
	str	q19, [x0, #928]
	str	q20, [x0, #992]
	ldr	q5, [x0, #48]
	ldr	q6, [x0, #112]
	ldr	q7, [x0, #176]
	ldr	q8, [x0, #240]
	ldr	q9, [x0, #304]
	ldr	q10, [x0, #368]
	ldr	q11, [x0, #432]
	ldr	q12, [x0, #496]
	ldr	q13, [x0, #560]
	ldr	q14, [x0, #624]
	ldr	q15, [x0, #688]
	ldr	q16, [x0, #752]
	ldr	q17, [x0, #816]
	ldr	q18, [x0, #880]
	ldr	q19, [x0, #944]
	ldr	q20, [x0, #1008]
	ldr	q0, [x1]
	ldr	q1, [x2]
	mul	v29.4s, v13.4s, v1.s[1]
	mul	v30.4s, v14.4s, v1.s[1]
	sqrdmulh	v21.4s, v13.4s, v0.s[1]
	sqrdmulh	v22.4s, v14.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v15.4s, v1.s[1]
	mul	v30.4s, v16.4s, v1.s[1]
	sqrdmulh	v23.4s, v15.4s, v0.s[1]
	sqrdmulh	v24.4s, v16.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v17.4s, v1.s[1]
	mul	v30.4s, v18.4s, v1.s[1]
	sqrdmulh	v25.4s, v17.4s, v0.s[1]
	sqrdmulh	v26.4s, v18.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[1]
	mul	v30.4s, v20.4s, v1.s[1]
	sqrdmulh	v27.4s, v19.4s, v0.s[1]
	sqrdmulh	v28.4s, v20.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v13.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v14.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v15.4s, v7.4s, v23.4s
	add	v7.4s, v7.4s, v23.4s
	sub	v16.4s, v8.4s, v24.4s
	add	v8.4s, v8.4s, v24.4s
	sub	v17.4s, v9.4s, v25.4s
	add	v9.4s, v9.4s, v25.4s
	sub	v18.4s, v10.4s, v26.4s
	add	v10.4s, v10.4s, v26.4s
	sub	v19.4s, v11.4s, v27.4s
	add	v11.4s, v11.4s, v27.4s
	sub	v20.4s, v12.4s, v28.4s
	add	v12.4s, v12.4s, v28.4s
	mul	v29.4s, v9.4s, v1.s[2]
	mul	v30.4s, v10.4s, v1.s[2]
	sqrdmulh	v21.4s, v9.4s, v0.s[2]
	sqrdmulh	v22.4s, v10.4s, v0.s[2]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v11.4s, v1.s[2]
	mul	v30.4s, v12.4s, v1.s[2]
	sqrdmulh	v23.4s, v11.4s, v0.s[2]
	sqrdmulh	v24.4s, v12.4s, v0.s[2]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v17.4s, v1.s[3]
	mul	v30.4s, v18.4s, v1.s[3]
	sqrdmulh	v25.4s, v17.4s, v0.s[3]
	sqrdmulh	v26.4s, v18.4s, v0.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[3]
	mul	v30.4s, v20.4s, v1.s[3]
	sqrdmulh	v27.4s, v19.4s, v0.s[3]
	sqrdmulh	v28.4s, v20.4s, v0.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v9.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v10.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v11.4s, v7.4s, v23.4s
	add	v7.4s, v7.4s, v23.4s
	sub	v12.4s, v8.4s, v24.4s
	add	v8.4s, v8.4s, v24.4s
	sub	v17.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v18.4s, v14.4s, v26.4s
	add	v14.4s, v14.4s, v26.4s
	sub	v19.4s, v15.4s, v27.4s
	add	v15.4s, v15.4s, v27.4s
	sub	v20.4s, v16.4s, v28.4s
	add	v16.4s, v16.4s, v28.4s
	ldr	q0, [x1, #16]
	ldr	q1, [x2, #16]
	mul	v29.4s, v7.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[0]
	sqrdmulh	v21.4s, v7.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[0]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v11.4s, v1.s[1]
	mul	v30.4s, v12.4s, v1.s[1]
	sqrdmulh	v23.4s, v11.4s, v0.s[1]
	sqrdmulh	v24.4s, v12.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v15.4s, v1.s[2]
	mul	v30.4s, v16.4s, v1.s[2]
	sqrdmulh	v25.4s, v15.4s, v0.s[2]
	sqrdmulh	v26.4s, v16.4s, v0.s[2]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[3]
	mul	v30.4s, v20.4s, v1.s[3]
	sqrdmulh	v27.4s, v19.4s, v0.s[3]
	sqrdmulh	v28.4s, v20.4s, v0.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v7.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v11.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v10.4s, v24.4s
	add	v10.4s, v10.4s, v24.4s
	sub	v15.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v14.4s, v26.4s
	add	v14.4s, v14.4s, v26.4s
	sub	v19.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v18.4s, v28.4s
	add	v18.4s, v18.4s, v28.4s
	ldp	q0, q2, [x1, #32]
	ldp	q1, q3, [x2, #32]
	mul	v29.4s, v6.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[1]
	sqrdmulh	v21.4s, v6.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v10.4s, v1.s[2]
	mul	v30.4s, v12.4s, v1.s[3]
	sqrdmulh	v23.4s, v10.4s, v0.s[2]
	sqrdmulh	v24.4s, v12.4s, v0.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v14.4s, v3.s[0]
	mul	v30.4s, v16.4s, v3.s[1]
	sqrdmulh	v25.4s, v14.4s, v2.s[0]
	sqrdmulh	v26.4s, v16.4s, v2.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v18.4s, v3.s[2]
	mul	v30.4s, v20.4s, v3.s[3]
	sqrdmulh	v27.4s, v18.4s, v2.s[2]
	sqrdmulh	v28.4s, v20.4s, v2.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	str	q5, [x0, #48]
	str	q6, [x0, #112]
	str	q7, [x0, #176]
	str	q8, [x0, #240]
	str	q9, [x0, #304]
	str	q10, [x0, #368]
	str	q11, [x0, #432]
	str	q12, [x0, #496]
	str	q13, [x0, #560]
	str	q14, [x0, #624]
	str	q15, [x0, #688]
	str	q16, [x0, #752]
	str	q17, [x0, #816]
	str	q18, [x0, #880]
	str	q19, [x0, #944]
	str	q20, [x0, #1008]
	ldp	q5, q6, [x0]
	ldp	q7, q8, [x0, #32]
	ldp	q9, q10, [x0, #64]
	ldp	q11, q12, [x0, #96]
	ldp	q13, q14, [x0, #128]
	ldp	q15, q16, [x0, #160]
	ldp	q17, q18, [x0, #192]
	ldp	q19, q20, [x0, #224]
	ldr	q0, [x1, #64]
	ldr	q1, [x2, #64]
	mul	v29.4s, v7.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[0]
	sqrdmulh	v21.4s, v7.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[0]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v11.4s, v1.s[1]
	mul	v30.4s, v12.4s, v1.s[1]
	sqrdmulh	v23.4s, v11.4s, v0.s[1]
	sqrdmulh	v24.4s, v12.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v15.4s, v1.s[2]
	mul	v30.4s, v16.4s, v1.s[2]
	sqrdmulh	v25.4s, v15.4s, v0.s[2]
	sqrdmulh	v26.4s, v16.4s, v0.s[2]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[3]
	mul	v30.4s, v20.4s, v1.s[3]
	sqrdmulh	v27.4s, v19.4s, v0.s[3]
	sqrdmulh	v28.4s, v20.4s, v0.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v7.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v11.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v10.4s, v24.4s
	add	v10.4s, v10.4s, v24.4s
	sub	v15.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v14.4s, v26.4s
	add	v14.4s, v14.4s, v26.4s
	sub	v19.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v18.4s, v28.4s
	add	v18.4s, v18.4s, v28.4s
	ldp	q0, q2, [x1, #128]
	ldp	q1, q3, [x2, #128]
	mul	v29.4s, v6.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[1]
	sqrdmulh	v21.4s, v6.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v10.4s, v1.s[2]
	mul	v30.4s, v12.4s, v1.s[3]
	sqrdmulh	v23.4s, v10.4s, v0.s[2]
	sqrdmulh	v24.4s, v12.4s, v0.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v14.4s, v3.s[0]
	mul	v30.4s, v16.4s, v3.s[1]
	sqrdmulh	v25.4s, v14.4s, v2.s[0]
	sqrdmulh	v26.4s, v16.4s, v2.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v18.4s, v3.s[2]
	mul	v30.4s, v20.4s, v3.s[3]
	sqrdmulh	v27.4s, v18.4s, v2.s[2]
	sqrdmulh	v28.4s, v20.4s, v2.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	ldp	q0, q2, [x1, #256]
	ldp	q1, q3, [x2, #256]
	mov	v29.16b, v5.16b
	mov	v30.16b, v7.16b
	trn1	v5.2d, v5.2d, v6.2d
	trn1	v7.2d, v7.2d, v8.2d
	trn2	v6.2d, v29.2d, v6.2d
	trn2	v8.2d, v30.2d, v8.2d
	mul	v29.4s, v6.4s, v1.4s
	mul	v30.4s, v8.4s, v3.4s
	sqrdmulh	v21.4s, v6.4s, v0.4s
	sqrdmulh	v22.4s, v8.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	ldp	q0, q2, [x1, #288]
	ldp	q1, q3, [x2, #288]
	mov	v29.16b, v9.16b
	mov	v30.16b, v11.16b
	trn1	v9.2d, v9.2d, v10.2d
	trn1	v11.2d, v11.2d, v12.2d
	trn2	v10.2d, v29.2d, v10.2d
	trn2	v12.2d, v30.2d, v12.2d
	mul	v29.4s, v10.4s, v1.4s
	mul	v30.4s, v12.4s, v3.4s
	sqrdmulh	v23.4s, v10.4s, v0.4s
	sqrdmulh	v24.4s, v12.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	ldp	q0, q2, [x1, #320]
	ldp	q1, q3, [x2, #320]
	mov	v29.16b, v13.16b
	mov	v30.16b, v15.16b
	trn1	v13.2d, v13.2d, v14.2d
	trn1	v15.2d, v15.2d, v16.2d
	trn2	v14.2d, v29.2d, v14.2d
	trn2	v16.2d, v30.2d, v16.2d
	mul	v29.4s, v14.4s, v1.4s
	mul	v30.4s, v16.4s, v3.4s
	sqrdmulh	v25.4s, v14.4s, v0.4s
	sqrdmulh	v26.4s, v16.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	ldp	q0, q2, [x1, #352]
	ldp	q1, q3, [x2, #352]
	mov	v29.16b, v17.16b
	mov	v30.16b, v19.16b
	trn1	v17.2d, v17.2d, v18.2d
	trn1	v19.2d, v19.2d, v20.2d
	trn2	v18.2d, v29.2d, v18.2d
	trn2	v20.2d, v30.2d, v20.2d
	mul	v29.4s, v18.4s, v1.4s
	mul	v30.4s, v20.4s, v3.4s
	sqrdmulh	v27.4s, v18.4s, v0.4s
	sqrdmulh	v28.4s, v20.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	ldp	q0, q2, [x1, #768]
	ldp	q1, q3, [x2, #768]
	mov	v29.16b, v5.16b
	mov	v30.16b, v7.16b
	trn1	v5.4s, v5.4s, v6.4s
	trn1	v7.4s, v7.4s, v8.4s
	trn2	v6.4s, v29.4s, v6.4s
	trn2	v8.4s, v30.4s, v8.4s
	mul	v29.4s, v6.4s, v1.4s
	mul	v30.4s, v8.4s, v3.4s
	sqrdmulh	v21.4s, v6.4s, v0.4s
	sqrdmulh	v22.4s, v8.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	ldp	q0, q2, [x1, #800]
	ldp	q1, q3, [x2, #800]
	mov	v29.16b, v9.16b
	mov	v30.16b, v11.16b
	trn1	v9.4s, v9.4s, v10.4s
	trn1	v11.4s, v11.4s, v12.4s
	trn2	v10.4s, v29.4s, v10.4s
	trn2	v12.4s, v30.4s, v12.4s
	mul	v29.4s, v10.4s, v1.4s
	mul	v30.4s, v12.4s, v3.4s
	sqrdmulh	v23.4s, v10.4s, v0.4s
	sqrdmulh	v24.4s, v12.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	ldp	q0, q2, [x1, #832]
	ldp	q1, q3, [x2, #832]
	mov	v29.16b, v13.16b
	mov	v30.16b, v15.16b
	trn1	v13.4s, v13.4s, v14.4s
	trn1	v15.4s, v15.4s, v16.4s
	trn2	v14.4s, v29.4s, v14.4s
	trn2	v16.4s, v30.4s, v16.4s
	mul	v29.4s, v14.4s, v1.4s
	mul	v30.4s, v16.4s, v3.4s
	sqrdmulh	v25.4s, v14.4s, v0.4s
	sqrdmulh	v26.4s, v16.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	ldp	q0, q2, [x1, #864]
	ldp	q1, q3, [x2, #864]
	mov	v29.16b, v17.16b
	mov	v30.16b, v19.16b
	trn1	v17.4s, v17.4s, v18.4s
	trn1	v19.4s, v19.4s, v20.4s
	trn2	v18.4s, v29.4s, v18.4s
	trn2	v20.4s, v30.4s, v20.4s
	mul	v29.4s, v18.4s, v1.4s
	mul	v30.4s, v20.4s, v3.4s
	sqrdmulh	v27.4s, v18.4s, v0.4s
	sqrdmulh	v28.4s, v20.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	stp	q5, q6, [x0]
	stp	q7, q8, [x0, #32]
	stp	q9, q10, [x0, #64]
	stp	q11, q12, [x0, #96]
	stp	q13, q14, [x0, #128]
	stp	q15, q16, [x0, #160]
	stp	q17, q18, [x0, #192]
	stp	q19, q20, [x0, #224]
	ldp	q5, q6, [x0, #256]
	ldp	q7, q8, [x0, #288]
	ldp	q9, q10, [x0, #320]
	ldp	q11, q12, [x0, #352]
	ldp	q13, q14, [x0, #384]
	ldp	q15, q16, [x0, #416]
	ldp	q17, q18, [x0, #448]
	ldp	q19, q20, [x0, #480]
	ldr	q0, [x1, #80]
	ldr	q1, [x2, #80]
	mul	v29.4s, v7.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[0]
	sqrdmulh	v21.4s, v7.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[0]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v11.4s, v1.s[1]
	mul	v30.4s, v12.4s, v1.s[1]
	sqrdmulh	v23.4s, v11.4s, v0.s[1]
	sqrdmulh	v24.4s, v12.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v15.4s, v1.s[2]
	mul	v30.4s, v16.4s, v1.s[2]
	sqrdmulh	v25.4s, v15.4s, v0.s[2]
	sqrdmulh	v26.4s, v16.4s, v0.s[2]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[3]
	mul	v30.4s, v20.4s, v1.s[3]
	sqrdmulh	v27.4s, v19.4s, v0.s[3]
	sqrdmulh	v28.4s, v20.4s, v0.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v7.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v11.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v10.4s, v24.4s
	add	v10.4s, v10.4s, v24.4s
	sub	v15.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v14.4s, v26.4s
	add	v14.4s, v14.4s, v26.4s
	sub	v19.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v18.4s, v28.4s
	add	v18.4s, v18.4s, v28.4s
	ldp	q0, q2, [x1, #160]
	ldp	q1, q3, [x2, #160]
	mul	v29.4s, v6.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[1]
	sqrdmulh	v21.4s, v6.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v10.4s, v1.s[2]
	mul	v30.4s, v12.4s, v1.s[3]
	sqrdmulh	v23.4s, v10.4s, v0.s[2]
	sqrdmulh	v24.4s, v12.4s, v0.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v14.4s, v3.s[0]
	mul	v30.4s, v16.4s, v3.s[1]
	sqrdmulh	v25.4s, v14.4s, v2.s[0]
	sqrdmulh	v26.4s, v16.4s, v2.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v18.4s, v3.s[2]
	mul	v30.4s, v20.4s, v3.s[3]
	sqrdmulh	v27.4s, v18.4s, v2.s[2]
	sqrdmulh	v28.4s, v20.4s, v2.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	ldp	q0, q2, [x1, #384]
	ldp	q1, q3, [x2, #384]
	mov	v29.16b, v5.16b
	mov	v30.16b, v7.16b
	trn1	v5.2d, v5.2d, v6.2d
	trn1	v7.2d, v7.2d, v8.2d
	trn2	v6.2d, v29.2d, v6.2d
	trn2	v8.2d, v30.2d, v8.2d
	mul	v29.4s, v6.4s, v1.4s
	mul	v30.4s, v8.4s, v3.4s
	sqrdmulh	v21.4s, v6.4s, v0.4s
	sqrdmulh	v22.4s, v8.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	ldp	q0, q2, [x1, #416]
	ldp	q1, q3, [x2, #416]
	mov	v29.16b, v9.16b
	mov	v30.16b, v11.16b
	trn1	v9.2d, v9.2d, v10.2d
	trn1	v11.2d, v11.2d, v12.2d
	trn2	v10.2d, v29.2d, v10.2d
	trn2	v12.2d, v30.2d, v12.2d
	mul	v29.4s, v10.4s, v1.4s
	mul	v30.4s, v12.4s, v3.4s
	sqrdmulh	v23.4s, v10.4s, v0.4s
	sqrdmulh	v24.4s, v12.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	ldp	q0, q2, [x1, #448]
	ldp	q1, q3, [x2, #448]
	mov	v29.16b, v13.16b
	mov	v30.16b, v15.16b
	trn1	v13.2d, v13.2d, v14.2d
	trn1	v15.2d, v15.2d, v16.2d
	trn2	v14.2d, v29.2d, v14.2d
	trn2	v16.2d, v30.2d, v16.2d
	mul	v29.4s, v14.4s, v1.4s
	mul	v30.4s, v16.4s, v3.4s
	sqrdmulh	v25.4s, v14.4s, v0.4s
	sqrdmulh	v26.4s, v16.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	ldp	q0, q2, [x1, #480]
	ldp	q1, q3, [x2, #480]
	mov	v29.16b, v17.16b
	mov	v30.16b, v19.16b
	trn1	v17.2d, v17.2d, v18.2d
	trn1	v19.2d, v19.2d, v20.2d
	trn2	v18.2d, v29.2d, v18.2d
	trn2	v20.2d, v30.2d, v20.2d
	mul	v29.4s, v18.4s, v1.4s
	mul	v30.4s, v20.4s, v3.4s
	sqrdmulh	v27.4s, v18.4s, v0.4s
	sqrdmulh	v28.4s, v20.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	ldp	q0, q2, [x1, #896]
	ldp	q1, q3, [x2, #896]
	mov	v29.16b, v5.16b
	mov	v30.16b, v7.16b
	trn1	v5.4s, v5.4s, v6.4s
	trn1	v7.4s, v7.4s, v8.4s
	trn2	v6.4s, v29.4s, v6.4s
	trn2	v8.4s, v30.4s, v8.4s
	mul	v29.4s, v6.4s, v1.4s
	mul	v30.4s, v8.4s, v3.4s
	sqrdmulh	v21.4s, v6.4s, v0.4s
	sqrdmulh	v22.4s, v8.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	ldp	q0, q2, [x1, #928]
	ldp	q1, q3, [x2, #928]
	mov	v29.16b, v9.16b
	mov	v30.16b, v11.16b
	trn1	v9.4s, v9.4s, v10.4s
	trn1	v11.4s, v11.4s, v12.4s
	trn2	v10.4s, v29.4s, v10.4s
	trn2	v12.4s, v30.4s, v12.4s
	mul	v29.4s, v10.4s, v1.4s
	mul	v30.4s, v12.4s, v3.4s
	sqrdmulh	v23.4s, v10.4s, v0.4s
	sqrdmulh	v24.4s, v12.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	ldp	q0, q2, [x1, #960]
	ldp	q1, q3, [x2, #960]
	mov	v29.16b, v13.16b
	mov	v30.16b, v15.16b
	trn1	v13.4s, v13.4s, v14.4s
	trn1	v15.4s, v15.4s, v16.4s
	trn2	v14.4s, v29.4s, v14.4s
	trn2	v16.4s, v30.4s, v16.4s
	mul	v29.4s, v14.4s, v1.4s
	mul	v30.4s, v16.4s, v3.4s
	sqrdmulh	v25.4s, v14.4s, v0.4s
	sqrdmulh	v26.4s, v16.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	ldp	q0, q2, [x1, #992]
	ldp	q1, q3, [x2, #992]
	mov	v29.16b, v17.16b
	mov	v30.16b, v19.16b
	trn1	v17.4s, v17.4s, v18.4s
	trn1	v19.4s, v19.4s, v20.4s
	trn2	v18.4s, v29.4s, v18.4s
	trn2	v20.4s, v30.4s, v20.4s
	mul	v29.4s, v18.4s, v1.4s
	mul	v30.4s, v20.4s, v3.4s
	sqrdmulh	v27.4s, v18.4s, v0.4s
	sqrdmulh	v28.4s, v20.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	stp	q5, q6, [x0, #256]
	stp	q7, q8, [x0, #288]
	stp	q9, q10, [x0, #320]
	stp	q11, q12, [x0, #352]
	stp	q13, q14, [x0, #384]
	stp	q15, q16, [x0, #416]
	stp	q17, q18, [x0, #448]
	stp	q19, q20, [x0, #480]
	ldp	q5, q6, [x0, #512]
	ldp	q7, q8, [x0, #544]
	ldp	q9, q10, [x0, #576]
	ldp	q11, q12, [x0, #608]
	ldp	q13, q14, [x0, #640]
	ldp	q15, q16, [x0, #672]
	ldp	q17, q18, [x0, #704]
	ldp	q19, q20, [x0, #736]
	ldr	q0, [x1, #96]
	ldr	q1, [x2, #96]
	mul	v29.4s, v7.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[0]
	sqrdmulh	v21.4s, v7.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[0]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v11.4s, v1.s[1]
	mul	v30.4s, v12.4s, v1.s[1]
	sqrdmulh	v23.4s, v11.4s, v0.s[1]
	sqrdmulh	v24.4s, v12.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v15.4s, v1.s[2]
	mul	v30.4s, v16.4s, v1.s[2]
	sqrdmulh	v25.4s, v15.4s, v0.s[2]
	sqrdmulh	v26.4s, v16.4s, v0.s[2]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[3]
	mul	v30.4s, v20.4s, v1.s[3]
	sqrdmulh	v27.4s, v19.4s, v0.s[3]
	sqrdmulh	v28.4s, v20.4s, v0.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v7.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v11.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v10.4s, v24.4s
	add	v10.4s, v10.4s, v24.4s
	sub	v15.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v14.4s, v26.4s
	add	v14.4s, v14.4s, v26.4s
	sub	v19.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v18.4s, v28.4s
	add	v18.4s, v18.4s, v28.4s
	ldp	q0, q2, [x1, #192]
	ldp	q1, q3, [x2, #192]
	mul	v29.4s, v6.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[1]
	sqrdmulh	v21.4s, v6.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v10.4s, v1.s[2]
	mul	v30.4s, v12.4s, v1.s[3]
	sqrdmulh	v23.4s, v10.4s, v0.s[2]
	sqrdmulh	v24.4s, v12.4s, v0.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v14.4s, v3.s[0]
	mul	v30.4s, v16.4s, v3.s[1]
	sqrdmulh	v25.4s, v14.4s, v2.s[0]
	sqrdmulh	v26.4s, v16.4s, v2.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v18.4s, v3.s[2]
	mul	v30.4s, v20.4s, v3.s[3]
	sqrdmulh	v27.4s, v18.4s, v2.s[2]
	sqrdmulh	v28.4s, v20.4s, v2.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	ldp	q0, q2, [x1, #512]
	ldp	q1, q3, [x2, #512]
	mov	v29.16b, v5.16b
	mov	v30.16b, v7.16b
	trn1	v5.2d, v5.2d, v6.2d
	trn1	v7.2d, v7.2d, v8.2d
	trn2	v6.2d, v29.2d, v6.2d
	trn2	v8.2d, v30.2d, v8.2d
	mul	v29.4s, v6.4s, v1.4s
	mul	v30.4s, v8.4s, v3.4s
	sqrdmulh	v21.4s, v6.4s, v0.4s
	sqrdmulh	v22.4s, v8.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	ldp	q0, q2, [x1, #544]
	ldp	q1, q3, [x2, #544]
	mov	v29.16b, v9.16b
	mov	v30.16b, v11.16b
	trn1	v9.2d, v9.2d, v10.2d
	trn1	v11.2d, v11.2d, v12.2d
	trn2	v10.2d, v29.2d, v10.2d
	trn2	v12.2d, v30.2d, v12.2d
	mul	v29.4s, v10.4s, v1.4s
	mul	v30.4s, v12.4s, v3.4s
	sqrdmulh	v23.4s, v10.4s, v0.4s
	sqrdmulh	v24.4s, v12.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	ldp	q0, q2, [x1, #576]
	ldp	q1, q3, [x2, #576]
	mov	v29.16b, v13.16b
	mov	v30.16b, v15.16b
	trn1	v13.2d, v13.2d, v14.2d
	trn1	v15.2d, v15.2d, v16.2d
	trn2	v14.2d, v29.2d, v14.2d
	trn2	v16.2d, v30.2d, v16.2d
	mul	v29.4s, v14.4s, v1.4s
	mul	v30.4s, v16.4s, v3.4s
	sqrdmulh	v25.4s, v14.4s, v0.4s
	sqrdmulh	v26.4s, v16.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	ldp	q0, q2, [x1, #608]
	ldp	q1, q3, [x2, #608]
	mov	v29.16b, v17.16b
	mov	v30.16b, v19.16b
	trn1	v17.2d, v17.2d, v18.2d
	trn1	v19.2d, v19.2d, v20.2d
	trn2	v18.2d, v29.2d, v18.2d
	trn2	v20.2d, v30.2d, v20.2d
	mul	v29.4s, v18.4s, v1.4s
	mul	v30.4s, v20.4s, v3.4s
	sqrdmulh	v27.4s, v18.4s, v0.4s
	sqrdmulh	v28.4s, v20.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	ldr	q0, [x1, #1024]
	ldr	q2, [x1, #1040]
	ldr	q1, [x2, #1024]
	ldr	q3, [x2, #1040]
	mov	v29.16b, v5.16b
	mov	v30.16b, v7.16b
	trn1	v5.4s, v5.4s, v6.4s
	trn1	v7.4s, v7.4s, v8.4s
	trn2	v6.4s, v29.4s, v6.4s
	trn2	v8.4s, v30.4s, v8.4s
	mul	v29.4s, v6.4s, v1.4s
	mul	v30.4s, v8.4s, v3.4s
	sqrdmulh	v21.4s, v6.4s, v0.4s
	sqrdmulh	v22.4s, v8.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	ldr	q0, [x1, #1056]
	ldr	q2, [x1, #1072]
	ldr	q1, [x2, #1056]
	ldr	q3, [x2, #1072]
	mov	v29.16b, v9.16b
	mov	v30.16b, v11.16b
	trn1	v9.4s, v9.4s, v10.4s
	trn1	v11.4s, v11.4s, v12.4s
	trn2	v10.4s, v29.4s, v10.4s
	trn2	v12.4s, v30.4s, v12.4s
	mul	v29.4s, v10.4s, v1.4s
	mul	v30.4s, v12.4s, v3.4s
	sqrdmulh	v23.4s, v10.4s, v0.4s
	sqrdmulh	v24.4s, v12.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	ldr	q0, [x1, #1088]
	ldr	q2, [x1, #1104]
	ldr	q1, [x2, #1088]
	ldr	q3, [x2, #1104]
	mov	v29.16b, v13.16b
	mov	v30.16b, v15.16b
	trn1	v13.4s, v13.4s, v14.4s
	trn1	v15.4s, v15.4s, v16.4s
	trn2	v14.4s, v29.4s, v14.4s
	trn2	v16.4s, v30.4s, v16.4s
	mul	v29.4s, v14.4s, v1.4s
	mul	v30.4s, v16.4s, v3.4s
	sqrdmulh	v25.4s, v14.4s, v0.4s
	sqrdmulh	v26.4s, v16.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	ldr	q0, [x1, #1120]
	ldr	q2, [x1, #1136]
	ldr	q1, [x2, #1120]
	ldr	q3, [x2, #1136]
	mov	v29.16b, v17.16b
	mov	v30.16b, v19.16b
	trn1	v17.4s, v17.4s, v18.4s
	trn1	v19.4s, v19.4s, v20.4s
	trn2	v18.4s, v29.4s, v18.4s
	trn2	v20.4s, v30.4s, v20.4s
	mul	v29.4s, v18.4s, v1.4s
	mul	v30.4s, v20.4s, v3.4s
	sqrdmulh	v27.4s, v18.4s, v0.4s
	sqrdmulh	v28.4s, v20.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	stp	q5, q6, [x0, #512]
	stp	q7, q8, [x0, #544]
	stp	q9, q10, [x0, #576]
	stp	q11, q12, [x0, #608]
	stp	q13, q14, [x0, #640]
	stp	q15, q16, [x0, #672]
	stp	q17, q18, [x0, #704]
	stp	q19, q20, [x0, #736]
	ldp	q5, q6, [x0, #768]
	ldp	q7, q8, [x0, #800]
	ldp	q9, q10, [x0, #832]
	ldp	q11, q12, [x0, #864]
	ldp	q13, q14, [x0, #896]
	ldp	q15, q16, [x0, #928]
	ldp	q17, q18, [x0, #960]
	ldp	q19, q20, [x0, #992]
	ldr	q0, [x1, #112]
	ldr	q1, [x2, #112]
	mul	v29.4s, v7.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[0]
	sqrdmulh	v21.4s, v7.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[0]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v11.4s, v1.s[1]
	mul	v30.4s, v12.4s, v1.s[1]
	sqrdmulh	v23.4s, v11.4s, v0.s[1]
	sqrdmulh	v24.4s, v12.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v15.4s, v1.s[2]
	mul	v30.4s, v16.4s, v1.s[2]
	sqrdmulh	v25.4s, v15.4s, v0.s[2]
	sqrdmulh	v26.4s, v16.4s, v0.s[2]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[3]
	mul	v30.4s, v20.4s, v1.s[3]
	sqrdmulh	v27.4s, v19.4s, v0.s[3]
	sqrdmulh	v28.4s, v20.4s, v0.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v7.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v11.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v10.4s, v24.4s
	add	v10.4s, v10.4s, v24.4s
	sub	v15.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v14.4s, v26.4s
	add	v14.4s, v14.4s, v26.4s
	sub	v19.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v18.4s, v28.4s
	add	v18.4s, v18.4s, v28.4s
	ldp	q0, q2, [x1, #224]
	ldp	q1, q3, [x2, #224]
	mul	v29.4s, v6.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[1]
	sqrdmulh	v21.4s, v6.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v10.4s, v1.s[2]
	mul	v30.4s, v12.4s, v1.s[3]
	sqrdmulh	v23.4s, v10.4s, v0.s[2]
	sqrdmulh	v24.4s, v12.4s, v0.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v14.4s, v3.s[0]
	mul	v30.4s, v16.4s, v3.s[1]
	sqrdmulh	v25.4s, v14.4s, v2.s[0]
	sqrdmulh	v26.4s, v16.4s, v2.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v18.4s, v3.s[2]
	mul	v30.4s, v20.4s, v3.s[3]
	sqrdmulh	v27.4s, v18.4s, v2.s[2]
	sqrdmulh	v28.4s, v20.4s, v2.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	ldp	q0, q2, [x1, #640]
	ldp	q1, q3, [x2, #640]
	mov	v29.16b, v5.16b
	mov	v30.16b, v7.16b
	trn1	v5.2d, v5.2d, v6.2d
	trn1	v7.2d, v7.2d, v8.2d
	trn2	v6.2d, v29.2d, v6.2d
	trn2	v8.2d, v30.2d, v8.2d
	mul	v29.4s, v6.4s, v1.4s
	mul	v30.4s, v8.4s, v3.4s
	sqrdmulh	v21.4s, v6.4s, v0.4s
	sqrdmulh	v22.4s, v8.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	ldp	q0, q2, [x1, #672]
	ldp	q1, q3, [x2, #672]
	mov	v29.16b, v9.16b
	mov	v30.16b, v11.16b
	trn1	v9.2d, v9.2d, v10.2d
	trn1	v11.2d, v11.2d, v12.2d
	trn2	v10.2d, v29.2d, v10.2d
	trn2	v12.2d, v30.2d, v12.2d
	mul	v29.4s, v10.4s, v1.4s
	mul	v30.4s, v12.4s, v3.4s
	sqrdmulh	v23.4s, v10.4s, v0.4s
	sqrdmulh	v24.4s, v12.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	ldp	q0, q2, [x1, #704]
	ldp	q1, q3, [x2, #704]
	mov	v29.16b, v13.16b
	mov	v30.16b, v15.16b
	trn1	v13.2d, v13.2d, v14.2d
	trn1	v15.2d, v15.2d, v16.2d
	trn2	v14.2d, v29.2d, v14.2d
	trn2	v16.2d, v30.2d, v16.2d
	mul	v29.4s, v14.4s, v1.4s
	mul	v30.4s, v16.4s, v3.4s
	sqrdmulh	v25.4s, v14.4s, v0.4s
	sqrdmulh	v26.4s, v16.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	ldp	q0, q2, [x1, #736]
	ldp	q1, q3, [x2, #736]
	mov	v29.16b, v17.16b
	mov	v30.16b, v19.16b
	trn1	v17.2d, v17.2d, v18.2d
	trn1	v19.2d, v19.2d, v20.2d
	trn2	v18.2d, v29.2d, v18.2d
	trn2	v20.2d, v30.2d, v20.2d
	mul	v29.4s, v18.4s, v1.4s
	mul	v30.4s, v20.4s, v3.4s
	sqrdmulh	v27.4s, v18.4s, v0.4s
	sqrdmulh	v28.4s, v20.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	ldr	q0, [x1, #1152]
	ldr	q2, [x1, #1168]
	ldr	q1, [x2, #1152]
	ldr	q3, [x2, #1168]
	mov	v29.16b, v5.16b
	mov	v30.16b, v7.16b
	trn1	v5.4s, v5.4s, v6.4s
	trn1	v7.4s, v7.4s, v8.4s
	trn2	v6.4s, v29.4s, v6.4s
	trn2	v8.4s, v30.4s, v8.4s
	mul	v29.4s, v6.4s, v1.4s
	mul	v30.4s, v8.4s, v3.4s
	sqrdmulh	v21.4s, v6.4s, v0.4s
	sqrdmulh	v22.4s, v8.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	ldr	q0, [x1, #1184]
	ldr	q2, [x1, #1200]
	ldr	q1, [x2, #1184]
	ldr	q3, [x2, #1200]
	mov	v29.16b, v9.16b
	mov	v30.16b, v11.16b
	trn1	v9.4s, v9.4s, v10.4s
	trn1	v11.4s, v11.4s, v12.4s
	trn2	v10.4s, v29.4s, v10.4s
	trn2	v12.4s, v30.4s, v12.4s
	mul	v29.4s, v10.4s, v1.4s
	mul	v30.4s, v12.4s, v3.4s
	sqrdmulh	v23.4s, v10.4s, v0.4s
	sqrdmulh	v24.4s, v12.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	ldr	q0, [x1, #1216]
	ldr	q2, [x1, #1232]
	ldr	q1, [x2, #1216]
	ldr	q3, [x2, #1232]
	mov	v29.16b, v13.16b
	mov	v30.16b, v15.16b
	trn1	v13.4s, v13.4s, v14.4s
	trn1	v15.4s, v15.4s, v16.4s
	trn2	v14.4s, v29.4s, v14.4s
	trn2	v16.4s, v30.4s, v16.4s
	mul	v29.4s, v14.4s, v1.4s
	mul	v30.4s, v16.4s, v3.4s
	sqrdmulh	v25.4s, v14.4s, v0.4s
	sqrdmulh	v26.4s, v16.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	ldr	q0, [x1, #1248]
	ldr	q2, [x1, #1264]
	ldr	q1, [x2, #1248]
	ldr	q3, [x2, #1264]
	mov	v29.16b, v17.16b
	mov	v30.16b, v19.16b
	trn1	v17.4s, v17.4s, v18.4s
	trn1	v19.4s, v19.4s, v20.4s
	trn2	v18.4s, v29.4s, v18.4s
	trn2	v20.4s, v30.4s, v20.4s
	mul	v29.4s, v18.4s, v1.4s
	mul	v30.4s, v20.4s, v3.4s
	sqrdmulh	v27.4s, v18.4s, v0.4s
	sqrdmulh	v28.4s, v20.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	stp	q5, q6, [x0, #768]
	stp	q7, q8, [x0, #800]
	stp	q9, q10, [x0, #832]
	stp	q11, q12, [x0, #864]
	stp	q13, q14, [x0, #896]
	stp	q15, q16, [x0, #928]
	stp	q17, q18, [x0, #960]
	stp	q19, q20, [x0, #992]
	ldp	d8, d9, [x29, #16]
	ldp	d10, d11, [x29, #32]
	ldp	d12, d13, [x29, #48]
	ldp	d14, d15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
#ifndef __APPLE__
	.size	mldsa_ntt_neon,.-mldsa_ntt_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	mldsa_ntt_full_neon
WC_ASM_ATT_HIDDEN(mldsa_ntt_full_neon)
.type	mldsa_ntt_full_neon,@function
.align	2
mldsa_ntt_full_neon:
#else
.section	__TEXT,__text
.globl	_mldsa_ntt_full_neon
WC_ASM_ATT_HIDDEN(_mldsa_ntt_full_neon)
.p2align	2
_mldsa_ntt_full_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
	stp	d12, d13, [x29, #48]
	stp	d14, d15, [x29, #64]
#ifndef __APPLE__
	adrp x1, L_mldsa_aarch64_zetas
	add  x1, x1, :lo12:L_mldsa_aarch64_zetas
#else
	adrp x1, L_mldsa_aarch64_zetas@PAGE
	add  x1, x1, L_mldsa_aarch64_zetas@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x2, L_mldsa_aarch64_zetas_qinv
	add  x2, x2, :lo12:L_mldsa_aarch64_zetas_qinv
#else
	adrp x2, L_mldsa_aarch64_zetas_qinv@PAGE
	add  x2, x2, L_mldsa_aarch64_zetas_qinv@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x3, L_mldsa_aarch64_consts
	add  x3, x3, :lo12:L_mldsa_aarch64_consts
#else
	adrp x3, L_mldsa_aarch64_consts@PAGE
	add  x3, x3, L_mldsa_aarch64_consts@PAGEOFF
#endif /* __APPLE__ */
	ldr	q4, [x3]
	ldr	q5, [x0]
	ldr	q6, [x0, #64]
	ldr	q7, [x0, #128]
	ldr	q8, [x0, #192]
	ldr	q9, [x0, #256]
	ldr	q10, [x0, #320]
	ldr	q11, [x0, #384]
	ldr	q12, [x0, #448]
	ldr	q13, [x0, #512]
	ldr	q14, [x0, #576]
	ldr	q15, [x0, #640]
	ldr	q16, [x0, #704]
	ldr	q17, [x0, #768]
	ldr	q18, [x0, #832]
	ldr	q19, [x0, #896]
	ldr	q20, [x0, #960]
	ldr	q0, [x1]
	ldr	q1, [x2]
	mul	v29.4s, v13.4s, v1.s[1]
	mul	v30.4s, v14.4s, v1.s[1]
	sqrdmulh	v21.4s, v13.4s, v0.s[1]
	sqrdmulh	v22.4s, v14.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v15.4s, v1.s[1]
	mul	v30.4s, v16.4s, v1.s[1]
	sqrdmulh	v23.4s, v15.4s, v0.s[1]
	sqrdmulh	v24.4s, v16.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v17.4s, v1.s[1]
	mul	v30.4s, v18.4s, v1.s[1]
	sqrdmulh	v25.4s, v17.4s, v0.s[1]
	sqrdmulh	v26.4s, v18.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[1]
	mul	v30.4s, v20.4s, v1.s[1]
	sqrdmulh	v27.4s, v19.4s, v0.s[1]
	sqrdmulh	v28.4s, v20.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v13.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v14.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v15.4s, v7.4s, v23.4s
	add	v7.4s, v7.4s, v23.4s
	sub	v16.4s, v8.4s, v24.4s
	add	v8.4s, v8.4s, v24.4s
	sub	v17.4s, v9.4s, v25.4s
	add	v9.4s, v9.4s, v25.4s
	sub	v18.4s, v10.4s, v26.4s
	add	v10.4s, v10.4s, v26.4s
	sub	v19.4s, v11.4s, v27.4s
	add	v11.4s, v11.4s, v27.4s
	sub	v20.4s, v12.4s, v28.4s
	add	v12.4s, v12.4s, v28.4s
	mul	v29.4s, v9.4s, v1.s[2]
	mul	v30.4s, v10.4s, v1.s[2]
	sqrdmulh	v21.4s, v9.4s, v0.s[2]
	sqrdmulh	v22.4s, v10.4s, v0.s[2]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v11.4s, v1.s[2]
	mul	v30.4s, v12.4s, v1.s[2]
	sqrdmulh	v23.4s, v11.4s, v0.s[2]
	sqrdmulh	v24.4s, v12.4s, v0.s[2]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v17.4s, v1.s[3]
	mul	v30.4s, v18.4s, v1.s[3]
	sqrdmulh	v25.4s, v17.4s, v0.s[3]
	sqrdmulh	v26.4s, v18.4s, v0.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[3]
	mul	v30.4s, v20.4s, v1.s[3]
	sqrdmulh	v27.4s, v19.4s, v0.s[3]
	sqrdmulh	v28.4s, v20.4s, v0.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v9.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v10.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v11.4s, v7.4s, v23.4s
	add	v7.4s, v7.4s, v23.4s
	sub	v12.4s, v8.4s, v24.4s
	add	v8.4s, v8.4s, v24.4s
	sub	v17.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v18.4s, v14.4s, v26.4s
	add	v14.4s, v14.4s, v26.4s
	sub	v19.4s, v15.4s, v27.4s
	add	v15.4s, v15.4s, v27.4s
	sub	v20.4s, v16.4s, v28.4s
	add	v16.4s, v16.4s, v28.4s
	ldr	q0, [x1, #16]
	ldr	q1, [x2, #16]
	mul	v29.4s, v7.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[0]
	sqrdmulh	v21.4s, v7.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[0]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v11.4s, v1.s[1]
	mul	v30.4s, v12.4s, v1.s[1]
	sqrdmulh	v23.4s, v11.4s, v0.s[1]
	sqrdmulh	v24.4s, v12.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v15.4s, v1.s[2]
	mul	v30.4s, v16.4s, v1.s[2]
	sqrdmulh	v25.4s, v15.4s, v0.s[2]
	sqrdmulh	v26.4s, v16.4s, v0.s[2]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[3]
	mul	v30.4s, v20.4s, v1.s[3]
	sqrdmulh	v27.4s, v19.4s, v0.s[3]
	sqrdmulh	v28.4s, v20.4s, v0.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v7.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v11.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v10.4s, v24.4s
	add	v10.4s, v10.4s, v24.4s
	sub	v15.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v14.4s, v26.4s
	add	v14.4s, v14.4s, v26.4s
	sub	v19.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v18.4s, v28.4s
	add	v18.4s, v18.4s, v28.4s
	ldp	q0, q2, [x1, #32]
	ldp	q1, q3, [x2, #32]
	mul	v29.4s, v6.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[1]
	sqrdmulh	v21.4s, v6.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v10.4s, v1.s[2]
	mul	v30.4s, v12.4s, v1.s[3]
	sqrdmulh	v23.4s, v10.4s, v0.s[2]
	sqrdmulh	v24.4s, v12.4s, v0.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v14.4s, v3.s[0]
	mul	v30.4s, v16.4s, v3.s[1]
	sqrdmulh	v25.4s, v14.4s, v2.s[0]
	sqrdmulh	v26.4s, v16.4s, v2.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v18.4s, v3.s[2]
	mul	v30.4s, v20.4s, v3.s[3]
	sqrdmulh	v27.4s, v18.4s, v2.s[2]
	sqrdmulh	v28.4s, v20.4s, v2.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	str	q5, [x0]
	str	q6, [x0, #64]
	str	q7, [x0, #128]
	str	q8, [x0, #192]
	str	q9, [x0, #256]
	str	q10, [x0, #320]
	str	q11, [x0, #384]
	str	q12, [x0, #448]
	str	q13, [x0, #512]
	str	q14, [x0, #576]
	str	q15, [x0, #640]
	str	q16, [x0, #704]
	str	q17, [x0, #768]
	str	q18, [x0, #832]
	str	q19, [x0, #896]
	str	q20, [x0, #960]
	ldr	q5, [x0, #16]
	ldr	q6, [x0, #80]
	ldr	q7, [x0, #144]
	ldr	q8, [x0, #208]
	ldr	q9, [x0, #272]
	ldr	q10, [x0, #336]
	ldr	q11, [x0, #400]
	ldr	q12, [x0, #464]
	ldr	q13, [x0, #528]
	ldr	q14, [x0, #592]
	ldr	q15, [x0, #656]
	ldr	q16, [x0, #720]
	ldr	q17, [x0, #784]
	ldr	q18, [x0, #848]
	ldr	q19, [x0, #912]
	ldr	q20, [x0, #976]
	ldr	q0, [x1]
	ldr	q1, [x2]
	mul	v29.4s, v13.4s, v1.s[1]
	mul	v30.4s, v14.4s, v1.s[1]
	sqrdmulh	v21.4s, v13.4s, v0.s[1]
	sqrdmulh	v22.4s, v14.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v15.4s, v1.s[1]
	mul	v30.4s, v16.4s, v1.s[1]
	sqrdmulh	v23.4s, v15.4s, v0.s[1]
	sqrdmulh	v24.4s, v16.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v17.4s, v1.s[1]
	mul	v30.4s, v18.4s, v1.s[1]
	sqrdmulh	v25.4s, v17.4s, v0.s[1]
	sqrdmulh	v26.4s, v18.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[1]
	mul	v30.4s, v20.4s, v1.s[1]
	sqrdmulh	v27.4s, v19.4s, v0.s[1]
	sqrdmulh	v28.4s, v20.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v13.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v14.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v15.4s, v7.4s, v23.4s
	add	v7.4s, v7.4s, v23.4s
	sub	v16.4s, v8.4s, v24.4s
	add	v8.4s, v8.4s, v24.4s
	sub	v17.4s, v9.4s, v25.4s
	add	v9.4s, v9.4s, v25.4s
	sub	v18.4s, v10.4s, v26.4s
	add	v10.4s, v10.4s, v26.4s
	sub	v19.4s, v11.4s, v27.4s
	add	v11.4s, v11.4s, v27.4s
	sub	v20.4s, v12.4s, v28.4s
	add	v12.4s, v12.4s, v28.4s
	mul	v29.4s, v9.4s, v1.s[2]
	mul	v30.4s, v10.4s, v1.s[2]
	sqrdmulh	v21.4s, v9.4s, v0.s[2]
	sqrdmulh	v22.4s, v10.4s, v0.s[2]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v11.4s, v1.s[2]
	mul	v30.4s, v12.4s, v1.s[2]
	sqrdmulh	v23.4s, v11.4s, v0.s[2]
	sqrdmulh	v24.4s, v12.4s, v0.s[2]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v17.4s, v1.s[3]
	mul	v30.4s, v18.4s, v1.s[3]
	sqrdmulh	v25.4s, v17.4s, v0.s[3]
	sqrdmulh	v26.4s, v18.4s, v0.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[3]
	mul	v30.4s, v20.4s, v1.s[3]
	sqrdmulh	v27.4s, v19.4s, v0.s[3]
	sqrdmulh	v28.4s, v20.4s, v0.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v9.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v10.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v11.4s, v7.4s, v23.4s
	add	v7.4s, v7.4s, v23.4s
	sub	v12.4s, v8.4s, v24.4s
	add	v8.4s, v8.4s, v24.4s
	sub	v17.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v18.4s, v14.4s, v26.4s
	add	v14.4s, v14.4s, v26.4s
	sub	v19.4s, v15.4s, v27.4s
	add	v15.4s, v15.4s, v27.4s
	sub	v20.4s, v16.4s, v28.4s
	add	v16.4s, v16.4s, v28.4s
	ldr	q0, [x1, #16]
	ldr	q1, [x2, #16]
	mul	v29.4s, v7.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[0]
	sqrdmulh	v21.4s, v7.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[0]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v11.4s, v1.s[1]
	mul	v30.4s, v12.4s, v1.s[1]
	sqrdmulh	v23.4s, v11.4s, v0.s[1]
	sqrdmulh	v24.4s, v12.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v15.4s, v1.s[2]
	mul	v30.4s, v16.4s, v1.s[2]
	sqrdmulh	v25.4s, v15.4s, v0.s[2]
	sqrdmulh	v26.4s, v16.4s, v0.s[2]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[3]
	mul	v30.4s, v20.4s, v1.s[3]
	sqrdmulh	v27.4s, v19.4s, v0.s[3]
	sqrdmulh	v28.4s, v20.4s, v0.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v7.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v11.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v10.4s, v24.4s
	add	v10.4s, v10.4s, v24.4s
	sub	v15.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v14.4s, v26.4s
	add	v14.4s, v14.4s, v26.4s
	sub	v19.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v18.4s, v28.4s
	add	v18.4s, v18.4s, v28.4s
	ldp	q0, q2, [x1, #32]
	ldp	q1, q3, [x2, #32]
	mul	v29.4s, v6.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[1]
	sqrdmulh	v21.4s, v6.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v10.4s, v1.s[2]
	mul	v30.4s, v12.4s, v1.s[3]
	sqrdmulh	v23.4s, v10.4s, v0.s[2]
	sqrdmulh	v24.4s, v12.4s, v0.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v14.4s, v3.s[0]
	mul	v30.4s, v16.4s, v3.s[1]
	sqrdmulh	v25.4s, v14.4s, v2.s[0]
	sqrdmulh	v26.4s, v16.4s, v2.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v18.4s, v3.s[2]
	mul	v30.4s, v20.4s, v3.s[3]
	sqrdmulh	v27.4s, v18.4s, v2.s[2]
	sqrdmulh	v28.4s, v20.4s, v2.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	str	q5, [x0, #16]
	str	q6, [x0, #80]
	str	q7, [x0, #144]
	str	q8, [x0, #208]
	str	q9, [x0, #272]
	str	q10, [x0, #336]
	str	q11, [x0, #400]
	str	q12, [x0, #464]
	str	q13, [x0, #528]
	str	q14, [x0, #592]
	str	q15, [x0, #656]
	str	q16, [x0, #720]
	str	q17, [x0, #784]
	str	q18, [x0, #848]
	str	q19, [x0, #912]
	str	q20, [x0, #976]
	ldr	q5, [x0, #32]
	ldr	q6, [x0, #96]
	ldr	q7, [x0, #160]
	ldr	q8, [x0, #224]
	ldr	q9, [x0, #288]
	ldr	q10, [x0, #352]
	ldr	q11, [x0, #416]
	ldr	q12, [x0, #480]
	ldr	q13, [x0, #544]
	ldr	q14, [x0, #608]
	ldr	q15, [x0, #672]
	ldr	q16, [x0, #736]
	ldr	q17, [x0, #800]
	ldr	q18, [x0, #864]
	ldr	q19, [x0, #928]
	ldr	q20, [x0, #992]
	ldr	q0, [x1]
	ldr	q1, [x2]
	mul	v29.4s, v13.4s, v1.s[1]
	mul	v30.4s, v14.4s, v1.s[1]
	sqrdmulh	v21.4s, v13.4s, v0.s[1]
	sqrdmulh	v22.4s, v14.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v15.4s, v1.s[1]
	mul	v30.4s, v16.4s, v1.s[1]
	sqrdmulh	v23.4s, v15.4s, v0.s[1]
	sqrdmulh	v24.4s, v16.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v17.4s, v1.s[1]
	mul	v30.4s, v18.4s, v1.s[1]
	sqrdmulh	v25.4s, v17.4s, v0.s[1]
	sqrdmulh	v26.4s, v18.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[1]
	mul	v30.4s, v20.4s, v1.s[1]
	sqrdmulh	v27.4s, v19.4s, v0.s[1]
	sqrdmulh	v28.4s, v20.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v13.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v14.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v15.4s, v7.4s, v23.4s
	add	v7.4s, v7.4s, v23.4s
	sub	v16.4s, v8.4s, v24.4s
	add	v8.4s, v8.4s, v24.4s
	sub	v17.4s, v9.4s, v25.4s
	add	v9.4s, v9.4s, v25.4s
	sub	v18.4s, v10.4s, v26.4s
	add	v10.4s, v10.4s, v26.4s
	sub	v19.4s, v11.4s, v27.4s
	add	v11.4s, v11.4s, v27.4s
	sub	v20.4s, v12.4s, v28.4s
	add	v12.4s, v12.4s, v28.4s
	mul	v29.4s, v9.4s, v1.s[2]
	mul	v30.4s, v10.4s, v1.s[2]
	sqrdmulh	v21.4s, v9.4s, v0.s[2]
	sqrdmulh	v22.4s, v10.4s, v0.s[2]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v11.4s, v1.s[2]
	mul	v30.4s, v12.4s, v1.s[2]
	sqrdmulh	v23.4s, v11.4s, v0.s[2]
	sqrdmulh	v24.4s, v12.4s, v0.s[2]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v17.4s, v1.s[3]
	mul	v30.4s, v18.4s, v1.s[3]
	sqrdmulh	v25.4s, v17.4s, v0.s[3]
	sqrdmulh	v26.4s, v18.4s, v0.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[3]
	mul	v30.4s, v20.4s, v1.s[3]
	sqrdmulh	v27.4s, v19.4s, v0.s[3]
	sqrdmulh	v28.4s, v20.4s, v0.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v9.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v10.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v11.4s, v7.4s, v23.4s
	add	v7.4s, v7.4s, v23.4s
	sub	v12.4s, v8.4s, v24.4s
	add	v8.4s, v8.4s, v24.4s
	sub	v17.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v18.4s, v14.4s, v26.4s
	add	v14.4s, v14.4s, v26.4s
	sub	v19.4s, v15.4s, v27.4s
	add	v15.4s, v15.4s, v27.4s
	sub	v20.4s, v16.4s, v28.4s
	add	v16.4s, v16.4s, v28.4s
	ldr	q0, [x1, #16]
	ldr	q1, [x2, #16]
	mul	v29.4s, v7.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[0]
	sqrdmulh	v21.4s, v7.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[0]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v11.4s, v1.s[1]
	mul	v30.4s, v12.4s, v1.s[1]
	sqrdmulh	v23.4s, v11.4s, v0.s[1]
	sqrdmulh	v24.4s, v12.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v15.4s, v1.s[2]
	mul	v30.4s, v16.4s, v1.s[2]
	sqrdmulh	v25.4s, v15.4s, v0.s[2]
	sqrdmulh	v26.4s, v16.4s, v0.s[2]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[3]
	mul	v30.4s, v20.4s, v1.s[3]
	sqrdmulh	v27.4s, v19.4s, v0.s[3]
	sqrdmulh	v28.4s, v20.4s, v0.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v7.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v11.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v10.4s, v24.4s
	add	v10.4s, v10.4s, v24.4s
	sub	v15.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v14.4s, v26.4s
	add	v14.4s, v14.4s, v26.4s
	sub	v19.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v18.4s, v28.4s
	add	v18.4s, v18.4s, v28.4s
	ldp	q0, q2, [x1, #32]
	ldp	q1, q3, [x2, #32]
	mul	v29.4s, v6.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[1]
	sqrdmulh	v21.4s, v6.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v10.4s, v1.s[2]
	mul	v30.4s, v12.4s, v1.s[3]
	sqrdmulh	v23.4s, v10.4s, v0.s[2]
	sqrdmulh	v24.4s, v12.4s, v0.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v14.4s, v3.s[0]
	mul	v30.4s, v16.4s, v3.s[1]
	sqrdmulh	v25.4s, v14.4s, v2.s[0]
	sqrdmulh	v26.4s, v16.4s, v2.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v18.4s, v3.s[2]
	mul	v30.4s, v20.4s, v3.s[3]
	sqrdmulh	v27.4s, v18.4s, v2.s[2]
	sqrdmulh	v28.4s, v20.4s, v2.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	str	q5, [x0, #32]
	str	q6, [x0, #96]
	str	q7, [x0, #160]
	str	q8, [x0, #224]
	str	q9, [x0, #288]
	str	q10, [x0, #352]
	str	q11, [x0, #416]
	str	q12, [x0, #480]
	str	q13, [x0, #544]
	str	q14, [x0, #608]
	str	q15, [x0, #672]
	str	q16, [x0, #736]
	str	q17, [x0, #800]
	str	q18, [x0, #864]
	str	q19, [x0, #928]
	str	q20, [x0, #992]
	ldr	q5, [x0, #48]
	ldr	q6, [x0, #112]
	ldr	q7, [x0, #176]
	ldr	q8, [x0, #240]
	ldr	q9, [x0, #304]
	ldr	q10, [x0, #368]
	ldr	q11, [x0, #432]
	ldr	q12, [x0, #496]
	ldr	q13, [x0, #560]
	ldr	q14, [x0, #624]
	ldr	q15, [x0, #688]
	ldr	q16, [x0, #752]
	ldr	q17, [x0, #816]
	ldr	q18, [x0, #880]
	ldr	q19, [x0, #944]
	ldr	q20, [x0, #1008]
	ldr	q0, [x1]
	ldr	q1, [x2]
	mul	v29.4s, v13.4s, v1.s[1]
	mul	v30.4s, v14.4s, v1.s[1]
	sqrdmulh	v21.4s, v13.4s, v0.s[1]
	sqrdmulh	v22.4s, v14.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v15.4s, v1.s[1]
	mul	v30.4s, v16.4s, v1.s[1]
	sqrdmulh	v23.4s, v15.4s, v0.s[1]
	sqrdmulh	v24.4s, v16.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v17.4s, v1.s[1]
	mul	v30.4s, v18.4s, v1.s[1]
	sqrdmulh	v25.4s, v17.4s, v0.s[1]
	sqrdmulh	v26.4s, v18.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[1]
	mul	v30.4s, v20.4s, v1.s[1]
	sqrdmulh	v27.4s, v19.4s, v0.s[1]
	sqrdmulh	v28.4s, v20.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v13.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v14.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v15.4s, v7.4s, v23.4s
	add	v7.4s, v7.4s, v23.4s
	sub	v16.4s, v8.4s, v24.4s
	add	v8.4s, v8.4s, v24.4s
	sub	v17.4s, v9.4s, v25.4s
	add	v9.4s, v9.4s, v25.4s
	sub	v18.4s, v10.4s, v26.4s
	add	v10.4s, v10.4s, v26.4s
	sub	v19.4s, v11.4s, v27.4s
	add	v11.4s, v11.4s, v27.4s
	sub	v20.4s, v12.4s, v28.4s
	add	v12.4s, v12.4s, v28.4s
	mul	v29.4s, v9.4s, v1.s[2]
	mul	v30.4s, v10.4s, v1.s[2]
	sqrdmulh	v21.4s, v9.4s, v0.s[2]
	sqrdmulh	v22.4s, v10.4s, v0.s[2]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v11.4s, v1.s[2]
	mul	v30.4s, v12.4s, v1.s[2]
	sqrdmulh	v23.4s, v11.4s, v0.s[2]
	sqrdmulh	v24.4s, v12.4s, v0.s[2]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v17.4s, v1.s[3]
	mul	v30.4s, v18.4s, v1.s[3]
	sqrdmulh	v25.4s, v17.4s, v0.s[3]
	sqrdmulh	v26.4s, v18.4s, v0.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[3]
	mul	v30.4s, v20.4s, v1.s[3]
	sqrdmulh	v27.4s, v19.4s, v0.s[3]
	sqrdmulh	v28.4s, v20.4s, v0.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v9.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v10.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v11.4s, v7.4s, v23.4s
	add	v7.4s, v7.4s, v23.4s
	sub	v12.4s, v8.4s, v24.4s
	add	v8.4s, v8.4s, v24.4s
	sub	v17.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v18.4s, v14.4s, v26.4s
	add	v14.4s, v14.4s, v26.4s
	sub	v19.4s, v15.4s, v27.4s
	add	v15.4s, v15.4s, v27.4s
	sub	v20.4s, v16.4s, v28.4s
	add	v16.4s, v16.4s, v28.4s
	ldr	q0, [x1, #16]
	ldr	q1, [x2, #16]
	mul	v29.4s, v7.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[0]
	sqrdmulh	v21.4s, v7.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[0]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v11.4s, v1.s[1]
	mul	v30.4s, v12.4s, v1.s[1]
	sqrdmulh	v23.4s, v11.4s, v0.s[1]
	sqrdmulh	v24.4s, v12.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v15.4s, v1.s[2]
	mul	v30.4s, v16.4s, v1.s[2]
	sqrdmulh	v25.4s, v15.4s, v0.s[2]
	sqrdmulh	v26.4s, v16.4s, v0.s[2]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[3]
	mul	v30.4s, v20.4s, v1.s[3]
	sqrdmulh	v27.4s, v19.4s, v0.s[3]
	sqrdmulh	v28.4s, v20.4s, v0.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v7.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v11.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v10.4s, v24.4s
	add	v10.4s, v10.4s, v24.4s
	sub	v15.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v14.4s, v26.4s
	add	v14.4s, v14.4s, v26.4s
	sub	v19.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v18.4s, v28.4s
	add	v18.4s, v18.4s, v28.4s
	ldp	q0, q2, [x1, #32]
	ldp	q1, q3, [x2, #32]
	mul	v29.4s, v6.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[1]
	sqrdmulh	v21.4s, v6.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v10.4s, v1.s[2]
	mul	v30.4s, v12.4s, v1.s[3]
	sqrdmulh	v23.4s, v10.4s, v0.s[2]
	sqrdmulh	v24.4s, v12.4s, v0.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v14.4s, v3.s[0]
	mul	v30.4s, v16.4s, v3.s[1]
	sqrdmulh	v25.4s, v14.4s, v2.s[0]
	sqrdmulh	v26.4s, v16.4s, v2.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v18.4s, v3.s[2]
	mul	v30.4s, v20.4s, v3.s[3]
	sqrdmulh	v27.4s, v18.4s, v2.s[2]
	sqrdmulh	v28.4s, v20.4s, v2.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	str	q5, [x0, #48]
	str	q6, [x0, #112]
	str	q7, [x0, #176]
	str	q8, [x0, #240]
	str	q9, [x0, #304]
	str	q10, [x0, #368]
	str	q11, [x0, #432]
	str	q12, [x0, #496]
	str	q13, [x0, #560]
	str	q14, [x0, #624]
	str	q15, [x0, #688]
	str	q16, [x0, #752]
	str	q17, [x0, #816]
	str	q18, [x0, #880]
	str	q19, [x0, #944]
	str	q20, [x0, #1008]
	ldp	q5, q6, [x0]
	ldp	q7, q8, [x0, #32]
	ldp	q9, q10, [x0, #64]
	ldp	q11, q12, [x0, #96]
	ldp	q13, q14, [x0, #128]
	ldp	q15, q16, [x0, #160]
	ldp	q17, q18, [x0, #192]
	ldp	q19, q20, [x0, #224]
	ldr	q0, [x1, #64]
	ldr	q1, [x2, #64]
	mul	v29.4s, v7.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[0]
	sqrdmulh	v21.4s, v7.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[0]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v11.4s, v1.s[1]
	mul	v30.4s, v12.4s, v1.s[1]
	sqrdmulh	v23.4s, v11.4s, v0.s[1]
	sqrdmulh	v24.4s, v12.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v15.4s, v1.s[2]
	mul	v30.4s, v16.4s, v1.s[2]
	sqrdmulh	v25.4s, v15.4s, v0.s[2]
	sqrdmulh	v26.4s, v16.4s, v0.s[2]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[3]
	mul	v30.4s, v20.4s, v1.s[3]
	sqrdmulh	v27.4s, v19.4s, v0.s[3]
	sqrdmulh	v28.4s, v20.4s, v0.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v7.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v11.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v10.4s, v24.4s
	add	v10.4s, v10.4s, v24.4s
	sub	v15.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v14.4s, v26.4s
	add	v14.4s, v14.4s, v26.4s
	sub	v19.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v18.4s, v28.4s
	add	v18.4s, v18.4s, v28.4s
	ldp	q0, q2, [x1, #128]
	ldp	q1, q3, [x2, #128]
	mul	v29.4s, v6.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[1]
	sqrdmulh	v21.4s, v6.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v10.4s, v1.s[2]
	mul	v30.4s, v12.4s, v1.s[3]
	sqrdmulh	v23.4s, v10.4s, v0.s[2]
	sqrdmulh	v24.4s, v12.4s, v0.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v14.4s, v3.s[0]
	mul	v30.4s, v16.4s, v3.s[1]
	sqrdmulh	v25.4s, v14.4s, v2.s[0]
	sqrdmulh	v26.4s, v16.4s, v2.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v18.4s, v3.s[2]
	mul	v30.4s, v20.4s, v3.s[3]
	sqrdmulh	v27.4s, v18.4s, v2.s[2]
	sqrdmulh	v28.4s, v20.4s, v2.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	ldp	q0, q2, [x1, #256]
	ldp	q1, q3, [x2, #256]
	mov	v29.16b, v5.16b
	mov	v30.16b, v7.16b
	trn1	v5.2d, v5.2d, v6.2d
	trn1	v7.2d, v7.2d, v8.2d
	trn2	v6.2d, v29.2d, v6.2d
	trn2	v8.2d, v30.2d, v8.2d
	mul	v29.4s, v6.4s, v1.4s
	mul	v30.4s, v8.4s, v3.4s
	sqrdmulh	v21.4s, v6.4s, v0.4s
	sqrdmulh	v22.4s, v8.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	ldp	q0, q2, [x1, #288]
	ldp	q1, q3, [x2, #288]
	mov	v29.16b, v9.16b
	mov	v30.16b, v11.16b
	trn1	v9.2d, v9.2d, v10.2d
	trn1	v11.2d, v11.2d, v12.2d
	trn2	v10.2d, v29.2d, v10.2d
	trn2	v12.2d, v30.2d, v12.2d
	mul	v29.4s, v10.4s, v1.4s
	mul	v30.4s, v12.4s, v3.4s
	sqrdmulh	v23.4s, v10.4s, v0.4s
	sqrdmulh	v24.4s, v12.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	ldp	q0, q2, [x1, #320]
	ldp	q1, q3, [x2, #320]
	mov	v29.16b, v13.16b
	mov	v30.16b, v15.16b
	trn1	v13.2d, v13.2d, v14.2d
	trn1	v15.2d, v15.2d, v16.2d
	trn2	v14.2d, v29.2d, v14.2d
	trn2	v16.2d, v30.2d, v16.2d
	mul	v29.4s, v14.4s, v1.4s
	mul	v30.4s, v16.4s, v3.4s
	sqrdmulh	v25.4s, v14.4s, v0.4s
	sqrdmulh	v26.4s, v16.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	ldp	q0, q2, [x1, #352]
	ldp	q1, q3, [x2, #352]
	mov	v29.16b, v17.16b
	mov	v30.16b, v19.16b
	trn1	v17.2d, v17.2d, v18.2d
	trn1	v19.2d, v19.2d, v20.2d
	trn2	v18.2d, v29.2d, v18.2d
	trn2	v20.2d, v30.2d, v20.2d
	mul	v29.4s, v18.4s, v1.4s
	mul	v30.4s, v20.4s, v3.4s
	sqrdmulh	v27.4s, v18.4s, v0.4s
	sqrdmulh	v28.4s, v20.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	ldp	q0, q2, [x1, #768]
	ldp	q1, q3, [x2, #768]
	mov	v29.16b, v5.16b
	mov	v30.16b, v7.16b
	trn1	v5.4s, v5.4s, v6.4s
	trn1	v7.4s, v7.4s, v8.4s
	trn2	v6.4s, v29.4s, v6.4s
	trn2	v8.4s, v30.4s, v8.4s
	mul	v29.4s, v6.4s, v1.4s
	mul	v30.4s, v8.4s, v3.4s
	sqrdmulh	v21.4s, v6.4s, v0.4s
	sqrdmulh	v22.4s, v8.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	ldp	q0, q2, [x1, #800]
	ldp	q1, q3, [x2, #800]
	mov	v29.16b, v9.16b
	mov	v30.16b, v11.16b
	trn1	v9.4s, v9.4s, v10.4s
	trn1	v11.4s, v11.4s, v12.4s
	trn2	v10.4s, v29.4s, v10.4s
	trn2	v12.4s, v30.4s, v12.4s
	mul	v29.4s, v10.4s, v1.4s
	mul	v30.4s, v12.4s, v3.4s
	sqrdmulh	v23.4s, v10.4s, v0.4s
	sqrdmulh	v24.4s, v12.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	ldp	q0, q2, [x1, #832]
	ldp	q1, q3, [x2, #832]
	mov	v29.16b, v13.16b
	mov	v30.16b, v15.16b
	trn1	v13.4s, v13.4s, v14.4s
	trn1	v15.4s, v15.4s, v16.4s
	trn2	v14.4s, v29.4s, v14.4s
	trn2	v16.4s, v30.4s, v16.4s
	mul	v29.4s, v14.4s, v1.4s
	mul	v30.4s, v16.4s, v3.4s
	sqrdmulh	v25.4s, v14.4s, v0.4s
	sqrdmulh	v26.4s, v16.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	ldp	q0, q2, [x1, #864]
	ldp	q1, q3, [x2, #864]
	mov	v29.16b, v17.16b
	mov	v30.16b, v19.16b
	trn1	v17.4s, v17.4s, v18.4s
	trn1	v19.4s, v19.4s, v20.4s
	trn2	v18.4s, v29.4s, v18.4s
	trn2	v20.4s, v30.4s, v20.4s
	mul	v29.4s, v18.4s, v1.4s
	mul	v30.4s, v20.4s, v3.4s
	sqrdmulh	v27.4s, v18.4s, v0.4s
	sqrdmulh	v28.4s, v20.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	trn1	v29.4s, v5.4s, v6.4s
	trn2	v30.4s, v5.4s, v6.4s
	trn1	v5.2d, v29.2d, v30.2d
	trn2	v6.2d, v29.2d, v30.2d
	trn1	v29.4s, v7.4s, v8.4s
	trn2	v30.4s, v7.4s, v8.4s
	trn1	v7.2d, v29.2d, v30.2d
	trn2	v8.2d, v29.2d, v30.2d
	trn1	v29.4s, v9.4s, v10.4s
	trn2	v30.4s, v9.4s, v10.4s
	trn1	v9.2d, v29.2d, v30.2d
	trn2	v10.2d, v29.2d, v30.2d
	trn1	v29.4s, v11.4s, v12.4s
	trn2	v30.4s, v11.4s, v12.4s
	trn1	v11.2d, v29.2d, v30.2d
	trn2	v12.2d, v29.2d, v30.2d
	trn1	v29.4s, v13.4s, v14.4s
	trn2	v30.4s, v13.4s, v14.4s
	trn1	v13.2d, v29.2d, v30.2d
	trn2	v14.2d, v29.2d, v30.2d
	trn1	v29.4s, v15.4s, v16.4s
	trn2	v30.4s, v15.4s, v16.4s
	trn1	v15.2d, v29.2d, v30.2d
	trn2	v16.2d, v29.2d, v30.2d
	trn1	v29.4s, v17.4s, v18.4s
	trn2	v30.4s, v17.4s, v18.4s
	trn1	v17.2d, v29.2d, v30.2d
	trn2	v18.2d, v29.2d, v30.2d
	trn1	v29.4s, v19.4s, v20.4s
	trn2	v30.4s, v19.4s, v20.4s
	trn1	v19.2d, v29.2d, v30.2d
	trn2	v20.2d, v29.2d, v30.2d
	stp	q5, q6, [x0]
	stp	q7, q8, [x0, #32]
	stp	q9, q10, [x0, #64]
	stp	q11, q12, [x0, #96]
	stp	q13, q14, [x0, #128]
	stp	q15, q16, [x0, #160]
	stp	q17, q18, [x0, #192]
	stp	q19, q20, [x0, #224]
	ldp	q5, q6, [x0, #256]
	ldp	q7, q8, [x0, #288]
	ldp	q9, q10, [x0, #320]
	ldp	q11, q12, [x0, #352]
	ldp	q13, q14, [x0, #384]
	ldp	q15, q16, [x0, #416]
	ldp	q17, q18, [x0, #448]
	ldp	q19, q20, [x0, #480]
	ldr	q0, [x1, #80]
	ldr	q1, [x2, #80]
	mul	v29.4s, v7.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[0]
	sqrdmulh	v21.4s, v7.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[0]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v11.4s, v1.s[1]
	mul	v30.4s, v12.4s, v1.s[1]
	sqrdmulh	v23.4s, v11.4s, v0.s[1]
	sqrdmulh	v24.4s, v12.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v15.4s, v1.s[2]
	mul	v30.4s, v16.4s, v1.s[2]
	sqrdmulh	v25.4s, v15.4s, v0.s[2]
	sqrdmulh	v26.4s, v16.4s, v0.s[2]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[3]
	mul	v30.4s, v20.4s, v1.s[3]
	sqrdmulh	v27.4s, v19.4s, v0.s[3]
	sqrdmulh	v28.4s, v20.4s, v0.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v7.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v11.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v10.4s, v24.4s
	add	v10.4s, v10.4s, v24.4s
	sub	v15.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v14.4s, v26.4s
	add	v14.4s, v14.4s, v26.4s
	sub	v19.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v18.4s, v28.4s
	add	v18.4s, v18.4s, v28.4s
	ldp	q0, q2, [x1, #160]
	ldp	q1, q3, [x2, #160]
	mul	v29.4s, v6.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[1]
	sqrdmulh	v21.4s, v6.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v10.4s, v1.s[2]
	mul	v30.4s, v12.4s, v1.s[3]
	sqrdmulh	v23.4s, v10.4s, v0.s[2]
	sqrdmulh	v24.4s, v12.4s, v0.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v14.4s, v3.s[0]
	mul	v30.4s, v16.4s, v3.s[1]
	sqrdmulh	v25.4s, v14.4s, v2.s[0]
	sqrdmulh	v26.4s, v16.4s, v2.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v18.4s, v3.s[2]
	mul	v30.4s, v20.4s, v3.s[3]
	sqrdmulh	v27.4s, v18.4s, v2.s[2]
	sqrdmulh	v28.4s, v20.4s, v2.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	ldp	q0, q2, [x1, #384]
	ldp	q1, q3, [x2, #384]
	mov	v29.16b, v5.16b
	mov	v30.16b, v7.16b
	trn1	v5.2d, v5.2d, v6.2d
	trn1	v7.2d, v7.2d, v8.2d
	trn2	v6.2d, v29.2d, v6.2d
	trn2	v8.2d, v30.2d, v8.2d
	mul	v29.4s, v6.4s, v1.4s
	mul	v30.4s, v8.4s, v3.4s
	sqrdmulh	v21.4s, v6.4s, v0.4s
	sqrdmulh	v22.4s, v8.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	ldp	q0, q2, [x1, #416]
	ldp	q1, q3, [x2, #416]
	mov	v29.16b, v9.16b
	mov	v30.16b, v11.16b
	trn1	v9.2d, v9.2d, v10.2d
	trn1	v11.2d, v11.2d, v12.2d
	trn2	v10.2d, v29.2d, v10.2d
	trn2	v12.2d, v30.2d, v12.2d
	mul	v29.4s, v10.4s, v1.4s
	mul	v30.4s, v12.4s, v3.4s
	sqrdmulh	v23.4s, v10.4s, v0.4s
	sqrdmulh	v24.4s, v12.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	ldp	q0, q2, [x1, #448]
	ldp	q1, q3, [x2, #448]
	mov	v29.16b, v13.16b
	mov	v30.16b, v15.16b
	trn1	v13.2d, v13.2d, v14.2d
	trn1	v15.2d, v15.2d, v16.2d
	trn2	v14.2d, v29.2d, v14.2d
	trn2	v16.2d, v30.2d, v16.2d
	mul	v29.4s, v14.4s, v1.4s
	mul	v30.4s, v16.4s, v3.4s
	sqrdmulh	v25.4s, v14.4s, v0.4s
	sqrdmulh	v26.4s, v16.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	ldp	q0, q2, [x1, #480]
	ldp	q1, q3, [x2, #480]
	mov	v29.16b, v17.16b
	mov	v30.16b, v19.16b
	trn1	v17.2d, v17.2d, v18.2d
	trn1	v19.2d, v19.2d, v20.2d
	trn2	v18.2d, v29.2d, v18.2d
	trn2	v20.2d, v30.2d, v20.2d
	mul	v29.4s, v18.4s, v1.4s
	mul	v30.4s, v20.4s, v3.4s
	sqrdmulh	v27.4s, v18.4s, v0.4s
	sqrdmulh	v28.4s, v20.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	ldp	q0, q2, [x1, #896]
	ldp	q1, q3, [x2, #896]
	mov	v29.16b, v5.16b
	mov	v30.16b, v7.16b
	trn1	v5.4s, v5.4s, v6.4s
	trn1	v7.4s, v7.4s, v8.4s
	trn2	v6.4s, v29.4s, v6.4s
	trn2	v8.4s, v30.4s, v8.4s
	mul	v29.4s, v6.4s, v1.4s
	mul	v30.4s, v8.4s, v3.4s
	sqrdmulh	v21.4s, v6.4s, v0.4s
	sqrdmulh	v22.4s, v8.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	ldp	q0, q2, [x1, #928]
	ldp	q1, q3, [x2, #928]
	mov	v29.16b, v9.16b
	mov	v30.16b, v11.16b
	trn1	v9.4s, v9.4s, v10.4s
	trn1	v11.4s, v11.4s, v12.4s
	trn2	v10.4s, v29.4s, v10.4s
	trn2	v12.4s, v30.4s, v12.4s
	mul	v29.4s, v10.4s, v1.4s
	mul	v30.4s, v12.4s, v3.4s
	sqrdmulh	v23.4s, v10.4s, v0.4s
	sqrdmulh	v24.4s, v12.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	ldp	q0, q2, [x1, #960]
	ldp	q1, q3, [x2, #960]
	mov	v29.16b, v13.16b
	mov	v30.16b, v15.16b
	trn1	v13.4s, v13.4s, v14.4s
	trn1	v15.4s, v15.4s, v16.4s
	trn2	v14.4s, v29.4s, v14.4s
	trn2	v16.4s, v30.4s, v16.4s
	mul	v29.4s, v14.4s, v1.4s
	mul	v30.4s, v16.4s, v3.4s
	sqrdmulh	v25.4s, v14.4s, v0.4s
	sqrdmulh	v26.4s, v16.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	ldp	q0, q2, [x1, #992]
	ldp	q1, q3, [x2, #992]
	mov	v29.16b, v17.16b
	mov	v30.16b, v19.16b
	trn1	v17.4s, v17.4s, v18.4s
	trn1	v19.4s, v19.4s, v20.4s
	trn2	v18.4s, v29.4s, v18.4s
	trn2	v20.4s, v30.4s, v20.4s
	mul	v29.4s, v18.4s, v1.4s
	mul	v30.4s, v20.4s, v3.4s
	sqrdmulh	v27.4s, v18.4s, v0.4s
	sqrdmulh	v28.4s, v20.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	trn1	v29.4s, v5.4s, v6.4s
	trn2	v30.4s, v5.4s, v6.4s
	trn1	v5.2d, v29.2d, v30.2d
	trn2	v6.2d, v29.2d, v30.2d
	trn1	v29.4s, v7.4s, v8.4s
	trn2	v30.4s, v7.4s, v8.4s
	trn1	v7.2d, v29.2d, v30.2d
	trn2	v8.2d, v29.2d, v30.2d
	trn1	v29.4s, v9.4s, v10.4s
	trn2	v30.4s, v9.4s, v10.4s
	trn1	v9.2d, v29.2d, v30.2d
	trn2	v10.2d, v29.2d, v30.2d
	trn1	v29.4s, v11.4s, v12.4s
	trn2	v30.4s, v11.4s, v12.4s
	trn1	v11.2d, v29.2d, v30.2d
	trn2	v12.2d, v29.2d, v30.2d
	trn1	v29.4s, v13.4s, v14.4s
	trn2	v30.4s, v13.4s, v14.4s
	trn1	v13.2d, v29.2d, v30.2d
	trn2	v14.2d, v29.2d, v30.2d
	trn1	v29.4s, v15.4s, v16.4s
	trn2	v30.4s, v15.4s, v16.4s
	trn1	v15.2d, v29.2d, v30.2d
	trn2	v16.2d, v29.2d, v30.2d
	trn1	v29.4s, v17.4s, v18.4s
	trn2	v30.4s, v17.4s, v18.4s
	trn1	v17.2d, v29.2d, v30.2d
	trn2	v18.2d, v29.2d, v30.2d
	trn1	v29.4s, v19.4s, v20.4s
	trn2	v30.4s, v19.4s, v20.4s
	trn1	v19.2d, v29.2d, v30.2d
	trn2	v20.2d, v29.2d, v30.2d
	stp	q5, q6, [x0, #256]
	stp	q7, q8, [x0, #288]
	stp	q9, q10, [x0, #320]
	stp	q11, q12, [x0, #352]
	stp	q13, q14, [x0, #384]
	stp	q15, q16, [x0, #416]
	stp	q17, q18, [x0, #448]
	stp	q19, q20, [x0, #480]
	ldp	q5, q6, [x0, #512]
	ldp	q7, q8, [x0, #544]
	ldp	q9, q10, [x0, #576]
	ldp	q11, q12, [x0, #608]
	ldp	q13, q14, [x0, #640]
	ldp	q15, q16, [x0, #672]
	ldp	q17, q18, [x0, #704]
	ldp	q19, q20, [x0, #736]
	ldr	q0, [x1, #96]
	ldr	q1, [x2, #96]
	mul	v29.4s, v7.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[0]
	sqrdmulh	v21.4s, v7.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[0]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v11.4s, v1.s[1]
	mul	v30.4s, v12.4s, v1.s[1]
	sqrdmulh	v23.4s, v11.4s, v0.s[1]
	sqrdmulh	v24.4s, v12.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v15.4s, v1.s[2]
	mul	v30.4s, v16.4s, v1.s[2]
	sqrdmulh	v25.4s, v15.4s, v0.s[2]
	sqrdmulh	v26.4s, v16.4s, v0.s[2]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[3]
	mul	v30.4s, v20.4s, v1.s[3]
	sqrdmulh	v27.4s, v19.4s, v0.s[3]
	sqrdmulh	v28.4s, v20.4s, v0.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v7.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v11.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v10.4s, v24.4s
	add	v10.4s, v10.4s, v24.4s
	sub	v15.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v14.4s, v26.4s
	add	v14.4s, v14.4s, v26.4s
	sub	v19.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v18.4s, v28.4s
	add	v18.4s, v18.4s, v28.4s
	ldp	q0, q2, [x1, #192]
	ldp	q1, q3, [x2, #192]
	mul	v29.4s, v6.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[1]
	sqrdmulh	v21.4s, v6.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v10.4s, v1.s[2]
	mul	v30.4s, v12.4s, v1.s[3]
	sqrdmulh	v23.4s, v10.4s, v0.s[2]
	sqrdmulh	v24.4s, v12.4s, v0.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v14.4s, v3.s[0]
	mul	v30.4s, v16.4s, v3.s[1]
	sqrdmulh	v25.4s, v14.4s, v2.s[0]
	sqrdmulh	v26.4s, v16.4s, v2.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v18.4s, v3.s[2]
	mul	v30.4s, v20.4s, v3.s[3]
	sqrdmulh	v27.4s, v18.4s, v2.s[2]
	sqrdmulh	v28.4s, v20.4s, v2.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	ldp	q0, q2, [x1, #512]
	ldp	q1, q3, [x2, #512]
	mov	v29.16b, v5.16b
	mov	v30.16b, v7.16b
	trn1	v5.2d, v5.2d, v6.2d
	trn1	v7.2d, v7.2d, v8.2d
	trn2	v6.2d, v29.2d, v6.2d
	trn2	v8.2d, v30.2d, v8.2d
	mul	v29.4s, v6.4s, v1.4s
	mul	v30.4s, v8.4s, v3.4s
	sqrdmulh	v21.4s, v6.4s, v0.4s
	sqrdmulh	v22.4s, v8.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	ldp	q0, q2, [x1, #544]
	ldp	q1, q3, [x2, #544]
	mov	v29.16b, v9.16b
	mov	v30.16b, v11.16b
	trn1	v9.2d, v9.2d, v10.2d
	trn1	v11.2d, v11.2d, v12.2d
	trn2	v10.2d, v29.2d, v10.2d
	trn2	v12.2d, v30.2d, v12.2d
	mul	v29.4s, v10.4s, v1.4s
	mul	v30.4s, v12.4s, v3.4s
	sqrdmulh	v23.4s, v10.4s, v0.4s
	sqrdmulh	v24.4s, v12.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	ldp	q0, q2, [x1, #576]
	ldp	q1, q3, [x2, #576]
	mov	v29.16b, v13.16b
	mov	v30.16b, v15.16b
	trn1	v13.2d, v13.2d, v14.2d
	trn1	v15.2d, v15.2d, v16.2d
	trn2	v14.2d, v29.2d, v14.2d
	trn2	v16.2d, v30.2d, v16.2d
	mul	v29.4s, v14.4s, v1.4s
	mul	v30.4s, v16.4s, v3.4s
	sqrdmulh	v25.4s, v14.4s, v0.4s
	sqrdmulh	v26.4s, v16.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	ldp	q0, q2, [x1, #608]
	ldp	q1, q3, [x2, #608]
	mov	v29.16b, v17.16b
	mov	v30.16b, v19.16b
	trn1	v17.2d, v17.2d, v18.2d
	trn1	v19.2d, v19.2d, v20.2d
	trn2	v18.2d, v29.2d, v18.2d
	trn2	v20.2d, v30.2d, v20.2d
	mul	v29.4s, v18.4s, v1.4s
	mul	v30.4s, v20.4s, v3.4s
	sqrdmulh	v27.4s, v18.4s, v0.4s
	sqrdmulh	v28.4s, v20.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	ldr	q0, [x1, #1024]
	ldr	q2, [x1, #1040]
	ldr	q1, [x2, #1024]
	ldr	q3, [x2, #1040]
	mov	v29.16b, v5.16b
	mov	v30.16b, v7.16b
	trn1	v5.4s, v5.4s, v6.4s
	trn1	v7.4s, v7.4s, v8.4s
	trn2	v6.4s, v29.4s, v6.4s
	trn2	v8.4s, v30.4s, v8.4s
	mul	v29.4s, v6.4s, v1.4s
	mul	v30.4s, v8.4s, v3.4s
	sqrdmulh	v21.4s, v6.4s, v0.4s
	sqrdmulh	v22.4s, v8.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	ldr	q0, [x1, #1056]
	ldr	q2, [x1, #1072]
	ldr	q1, [x2, #1056]
	ldr	q3, [x2, #1072]
	mov	v29.16b, v9.16b
	mov	v30.16b, v11.16b
	trn1	v9.4s, v9.4s, v10.4s
	trn1	v11.4s, v11.4s, v12.4s
	trn2	v10.4s, v29.4s, v10.4s
	trn2	v12.4s, v30.4s, v12.4s
	mul	v29.4s, v10.4s, v1.4s
	mul	v30.4s, v12.4s, v3.4s
	sqrdmulh	v23.4s, v10.4s, v0.4s
	sqrdmulh	v24.4s, v12.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	ldr	q0, [x1, #1088]
	ldr	q2, [x1, #1104]
	ldr	q1, [x2, #1088]
	ldr	q3, [x2, #1104]
	mov	v29.16b, v13.16b
	mov	v30.16b, v15.16b
	trn1	v13.4s, v13.4s, v14.4s
	trn1	v15.4s, v15.4s, v16.4s
	trn2	v14.4s, v29.4s, v14.4s
	trn2	v16.4s, v30.4s, v16.4s
	mul	v29.4s, v14.4s, v1.4s
	mul	v30.4s, v16.4s, v3.4s
	sqrdmulh	v25.4s, v14.4s, v0.4s
	sqrdmulh	v26.4s, v16.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	ldr	q0, [x1, #1120]
	ldr	q2, [x1, #1136]
	ldr	q1, [x2, #1120]
	ldr	q3, [x2, #1136]
	mov	v29.16b, v17.16b
	mov	v30.16b, v19.16b
	trn1	v17.4s, v17.4s, v18.4s
	trn1	v19.4s, v19.4s, v20.4s
	trn2	v18.4s, v29.4s, v18.4s
	trn2	v20.4s, v30.4s, v20.4s
	mul	v29.4s, v18.4s, v1.4s
	mul	v30.4s, v20.4s, v3.4s
	sqrdmulh	v27.4s, v18.4s, v0.4s
	sqrdmulh	v28.4s, v20.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	trn1	v29.4s, v5.4s, v6.4s
	trn2	v30.4s, v5.4s, v6.4s
	trn1	v5.2d, v29.2d, v30.2d
	trn2	v6.2d, v29.2d, v30.2d
	trn1	v29.4s, v7.4s, v8.4s
	trn2	v30.4s, v7.4s, v8.4s
	trn1	v7.2d, v29.2d, v30.2d
	trn2	v8.2d, v29.2d, v30.2d
	trn1	v29.4s, v9.4s, v10.4s
	trn2	v30.4s, v9.4s, v10.4s
	trn1	v9.2d, v29.2d, v30.2d
	trn2	v10.2d, v29.2d, v30.2d
	trn1	v29.4s, v11.4s, v12.4s
	trn2	v30.4s, v11.4s, v12.4s
	trn1	v11.2d, v29.2d, v30.2d
	trn2	v12.2d, v29.2d, v30.2d
	trn1	v29.4s, v13.4s, v14.4s
	trn2	v30.4s, v13.4s, v14.4s
	trn1	v13.2d, v29.2d, v30.2d
	trn2	v14.2d, v29.2d, v30.2d
	trn1	v29.4s, v15.4s, v16.4s
	trn2	v30.4s, v15.4s, v16.4s
	trn1	v15.2d, v29.2d, v30.2d
	trn2	v16.2d, v29.2d, v30.2d
	trn1	v29.4s, v17.4s, v18.4s
	trn2	v30.4s, v17.4s, v18.4s
	trn1	v17.2d, v29.2d, v30.2d
	trn2	v18.2d, v29.2d, v30.2d
	trn1	v29.4s, v19.4s, v20.4s
	trn2	v30.4s, v19.4s, v20.4s
	trn1	v19.2d, v29.2d, v30.2d
	trn2	v20.2d, v29.2d, v30.2d
	stp	q5, q6, [x0, #512]
	stp	q7, q8, [x0, #544]
	stp	q9, q10, [x0, #576]
	stp	q11, q12, [x0, #608]
	stp	q13, q14, [x0, #640]
	stp	q15, q16, [x0, #672]
	stp	q17, q18, [x0, #704]
	stp	q19, q20, [x0, #736]
	ldp	q5, q6, [x0, #768]
	ldp	q7, q8, [x0, #800]
	ldp	q9, q10, [x0, #832]
	ldp	q11, q12, [x0, #864]
	ldp	q13, q14, [x0, #896]
	ldp	q15, q16, [x0, #928]
	ldp	q17, q18, [x0, #960]
	ldp	q19, q20, [x0, #992]
	ldr	q0, [x1, #112]
	ldr	q1, [x2, #112]
	mul	v29.4s, v7.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[0]
	sqrdmulh	v21.4s, v7.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[0]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v11.4s, v1.s[1]
	mul	v30.4s, v12.4s, v1.s[1]
	sqrdmulh	v23.4s, v11.4s, v0.s[1]
	sqrdmulh	v24.4s, v12.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v15.4s, v1.s[2]
	mul	v30.4s, v16.4s, v1.s[2]
	sqrdmulh	v25.4s, v15.4s, v0.s[2]
	sqrdmulh	v26.4s, v16.4s, v0.s[2]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[3]
	mul	v30.4s, v20.4s, v1.s[3]
	sqrdmulh	v27.4s, v19.4s, v0.s[3]
	sqrdmulh	v28.4s, v20.4s, v0.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v7.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v11.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v10.4s, v24.4s
	add	v10.4s, v10.4s, v24.4s
	sub	v15.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v14.4s, v26.4s
	add	v14.4s, v14.4s, v26.4s
	sub	v19.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v18.4s, v28.4s
	add	v18.4s, v18.4s, v28.4s
	ldp	q0, q2, [x1, #224]
	ldp	q1, q3, [x2, #224]
	mul	v29.4s, v6.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[1]
	sqrdmulh	v21.4s, v6.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v10.4s, v1.s[2]
	mul	v30.4s, v12.4s, v1.s[3]
	sqrdmulh	v23.4s, v10.4s, v0.s[2]
	sqrdmulh	v24.4s, v12.4s, v0.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v14.4s, v3.s[0]
	mul	v30.4s, v16.4s, v3.s[1]
	sqrdmulh	v25.4s, v14.4s, v2.s[0]
	sqrdmulh	v26.4s, v16.4s, v2.s[1]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v18.4s, v3.s[2]
	mul	v30.4s, v20.4s, v3.s[3]
	sqrdmulh	v27.4s, v18.4s, v2.s[2]
	sqrdmulh	v28.4s, v20.4s, v2.s[3]
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	ldp	q0, q2, [x1, #640]
	ldp	q1, q3, [x2, #640]
	mov	v29.16b, v5.16b
	mov	v30.16b, v7.16b
	trn1	v5.2d, v5.2d, v6.2d
	trn1	v7.2d, v7.2d, v8.2d
	trn2	v6.2d, v29.2d, v6.2d
	trn2	v8.2d, v30.2d, v8.2d
	mul	v29.4s, v6.4s, v1.4s
	mul	v30.4s, v8.4s, v3.4s
	sqrdmulh	v21.4s, v6.4s, v0.4s
	sqrdmulh	v22.4s, v8.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	ldp	q0, q2, [x1, #672]
	ldp	q1, q3, [x2, #672]
	mov	v29.16b, v9.16b
	mov	v30.16b, v11.16b
	trn1	v9.2d, v9.2d, v10.2d
	trn1	v11.2d, v11.2d, v12.2d
	trn2	v10.2d, v29.2d, v10.2d
	trn2	v12.2d, v30.2d, v12.2d
	mul	v29.4s, v10.4s, v1.4s
	mul	v30.4s, v12.4s, v3.4s
	sqrdmulh	v23.4s, v10.4s, v0.4s
	sqrdmulh	v24.4s, v12.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	ldp	q0, q2, [x1, #704]
	ldp	q1, q3, [x2, #704]
	mov	v29.16b, v13.16b
	mov	v30.16b, v15.16b
	trn1	v13.2d, v13.2d, v14.2d
	trn1	v15.2d, v15.2d, v16.2d
	trn2	v14.2d, v29.2d, v14.2d
	trn2	v16.2d, v30.2d, v16.2d
	mul	v29.4s, v14.4s, v1.4s
	mul	v30.4s, v16.4s, v3.4s
	sqrdmulh	v25.4s, v14.4s, v0.4s
	sqrdmulh	v26.4s, v16.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	ldp	q0, q2, [x1, #736]
	ldp	q1, q3, [x2, #736]
	mov	v29.16b, v17.16b
	mov	v30.16b, v19.16b
	trn1	v17.2d, v17.2d, v18.2d
	trn1	v19.2d, v19.2d, v20.2d
	trn2	v18.2d, v29.2d, v18.2d
	trn2	v20.2d, v30.2d, v20.2d
	mul	v29.4s, v18.4s, v1.4s
	mul	v30.4s, v20.4s, v3.4s
	sqrdmulh	v27.4s, v18.4s, v0.4s
	sqrdmulh	v28.4s, v20.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	ldr	q0, [x1, #1152]
	ldr	q2, [x1, #1168]
	ldr	q1, [x2, #1152]
	ldr	q3, [x2, #1168]
	mov	v29.16b, v5.16b
	mov	v30.16b, v7.16b
	trn1	v5.4s, v5.4s, v6.4s
	trn1	v7.4s, v7.4s, v8.4s
	trn2	v6.4s, v29.4s, v6.4s
	trn2	v8.4s, v30.4s, v8.4s
	mul	v29.4s, v6.4s, v1.4s
	mul	v30.4s, v8.4s, v3.4s
	sqrdmulh	v21.4s, v6.4s, v0.4s
	sqrdmulh	v22.4s, v8.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v21.4s, v21.4s, v29.4s
	sub	v22.4s, v22.4s, v30.4s
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	ldr	q0, [x1, #1184]
	ldr	q2, [x1, #1200]
	ldr	q1, [x2, #1184]
	ldr	q3, [x2, #1200]
	mov	v29.16b, v9.16b
	mov	v30.16b, v11.16b
	trn1	v9.4s, v9.4s, v10.4s
	trn1	v11.4s, v11.4s, v12.4s
	trn2	v10.4s, v29.4s, v10.4s
	trn2	v12.4s, v30.4s, v12.4s
	mul	v29.4s, v10.4s, v1.4s
	mul	v30.4s, v12.4s, v3.4s
	sqrdmulh	v23.4s, v10.4s, v0.4s
	sqrdmulh	v24.4s, v12.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v23.4s, v23.4s, v29.4s
	sub	v24.4s, v24.4s, v30.4s
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	ldr	q0, [x1, #1216]
	ldr	q2, [x1, #1232]
	ldr	q1, [x2, #1216]
	ldr	q3, [x2, #1232]
	mov	v29.16b, v13.16b
	mov	v30.16b, v15.16b
	trn1	v13.4s, v13.4s, v14.4s
	trn1	v15.4s, v15.4s, v16.4s
	trn2	v14.4s, v29.4s, v14.4s
	trn2	v16.4s, v30.4s, v16.4s
	mul	v29.4s, v14.4s, v1.4s
	mul	v30.4s, v16.4s, v3.4s
	sqrdmulh	v25.4s, v14.4s, v0.4s
	sqrdmulh	v26.4s, v16.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v25.4s, v25.4s, v29.4s
	sub	v26.4s, v26.4s, v30.4s
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	ldr	q0, [x1, #1248]
	ldr	q2, [x1, #1264]
	ldr	q1, [x2, #1248]
	ldr	q3, [x2, #1264]
	mov	v29.16b, v17.16b
	mov	v30.16b, v19.16b
	trn1	v17.4s, v17.4s, v18.4s
	trn1	v19.4s, v19.4s, v20.4s
	trn2	v18.4s, v29.4s, v18.4s
	trn2	v20.4s, v30.4s, v20.4s
	mul	v29.4s, v18.4s, v1.4s
	mul	v30.4s, v20.4s, v3.4s
	sqrdmulh	v27.4s, v18.4s, v0.4s
	sqrdmulh	v28.4s, v20.4s, v2.4s
	sqrdmulh	v29.4s, v29.4s, v4.s[0]
	sqrdmulh	v30.4s, v30.4s, v4.s[0]
	sub	v27.4s, v27.4s, v29.4s
	sub	v28.4s, v28.4s, v30.4s
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	trn1	v29.4s, v5.4s, v6.4s
	trn2	v30.4s, v5.4s, v6.4s
	trn1	v5.2d, v29.2d, v30.2d
	trn2	v6.2d, v29.2d, v30.2d
	trn1	v29.4s, v7.4s, v8.4s
	trn2	v30.4s, v7.4s, v8.4s
	trn1	v7.2d, v29.2d, v30.2d
	trn2	v8.2d, v29.2d, v30.2d
	trn1	v29.4s, v9.4s, v10.4s
	trn2	v30.4s, v9.4s, v10.4s
	trn1	v9.2d, v29.2d, v30.2d
	trn2	v10.2d, v29.2d, v30.2d
	trn1	v29.4s, v11.4s, v12.4s
	trn2	v30.4s, v11.4s, v12.4s
	trn1	v11.2d, v29.2d, v30.2d
	trn2	v12.2d, v29.2d, v30.2d
	trn1	v29.4s, v13.4s, v14.4s
	trn2	v30.4s, v13.4s, v14.4s
	trn1	v13.2d, v29.2d, v30.2d
	trn2	v14.2d, v29.2d, v30.2d
	trn1	v29.4s, v15.4s, v16.4s
	trn2	v30.4s, v15.4s, v16.4s
	trn1	v15.2d, v29.2d, v30.2d
	trn2	v16.2d, v29.2d, v30.2d
	trn1	v29.4s, v17.4s, v18.4s
	trn2	v30.4s, v17.4s, v18.4s
	trn1	v17.2d, v29.2d, v30.2d
	trn2	v18.2d, v29.2d, v30.2d
	trn1	v29.4s, v19.4s, v20.4s
	trn2	v30.4s, v19.4s, v20.4s
	trn1	v19.2d, v29.2d, v30.2d
	trn2	v20.2d, v29.2d, v30.2d
	stp	q5, q6, [x0, #768]
	stp	q7, q8, [x0, #800]
	stp	q9, q10, [x0, #832]
	stp	q11, q12, [x0, #864]
	stp	q13, q14, [x0, #896]
	stp	q15, q16, [x0, #928]
	stp	q17, q18, [x0, #960]
	stp	q19, q20, [x0, #992]
	ldp	d8, d9, [x29, #16]
	ldp	d10, d11, [x29, #32]
	ldp	d12, d13, [x29, #48]
	ldp	d14, d15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
#ifndef __APPLE__
	.size	mldsa_ntt_full_neon,.-mldsa_ntt_full_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	mldsa_invntt_neon
WC_ASM_ATT_HIDDEN(mldsa_invntt_neon)
.type	mldsa_invntt_neon,@function
.align	2
mldsa_invntt_neon:
#else
.section	__TEXT,__text
.globl	_mldsa_invntt_neon
WC_ASM_ATT_HIDDEN(_mldsa_invntt_neon)
.p2align	2
_mldsa_invntt_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
	stp	d12, d13, [x29, #48]
	stp	d14, d15, [x29, #64]
#ifndef __APPLE__
	adrp x1, L_mldsa_aarch64_zetas_inv
	add  x1, x1, :lo12:L_mldsa_aarch64_zetas_inv
#else
	adrp x1, L_mldsa_aarch64_zetas_inv@PAGE
	add  x1, x1, L_mldsa_aarch64_zetas_inv@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x2, L_mldsa_aarch64_zetas_inv_qinv
	add  x2, x2, :lo12:L_mldsa_aarch64_zetas_inv_qinv
#else
	adrp x2, L_mldsa_aarch64_zetas_inv_qinv@PAGE
	add  x2, x2, L_mldsa_aarch64_zetas_inv_qinv@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x3, L_mldsa_aarch64_consts
	add  x3, x3, :lo12:L_mldsa_aarch64_consts
#else
	adrp x3, L_mldsa_aarch64_consts@PAGE
	add  x3, x3, L_mldsa_aarch64_consts@PAGEOFF
#endif /* __APPLE__ */
	ldr	q4, [x3]
	ldp	q5, q6, [x0]
	ldp	q7, q8, [x0, #32]
	ldp	q9, q10, [x0, #64]
	ldp	q11, q12, [x0, #96]
	ldp	q13, q14, [x0, #128]
	ldp	q15, q16, [x0, #160]
	ldp	q17, q18, [x0, #192]
	ldp	q19, q20, [x0, #224]
	ldp	q0, q1, [x1]
	ldp	q2, q3, [x2]
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v6.4s, v22.4s, v0.4s
	sqrdmulh	v8.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v6.4s, v6.4s, v21.4s
	sub	v8.4s, v8.4s, v23.4s
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	ldp	q0, q1, [x1, #32]
	ldp	q2, q3, [x2, #32]
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v10.4s, v22.4s, v0.4s
	sqrdmulh	v12.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v10.4s, v10.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	ldp	q0, q1, [x1, #64]
	ldp	q2, q3, [x2, #64]
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v14.4s, v22.4s, v0.4s
	sqrdmulh	v16.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v14.4s, v14.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	ldp	q0, q1, [x1, #96]
	ldp	q2, q3, [x2, #96]
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v18.4s, v22.4s, v0.4s
	sqrdmulh	v20.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v18.4s, v18.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldp	q0, q1, [x1, #512]
	ldp	q2, q3, [x2, #512]
	mov	v21.16b, v5.16b
	mov	v22.16b, v7.16b
	trn1	v5.4s, v5.4s, v6.4s
	trn1	v7.4s, v7.4s, v8.4s
	trn2	v6.4s, v21.4s, v6.4s
	trn2	v8.4s, v22.4s, v8.4s
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v6.4s, v22.4s, v0.4s
	sqrdmulh	v8.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v6.4s, v6.4s, v21.4s
	sub	v8.4s, v8.4s, v23.4s
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	ldp	q0, q1, [x1, #544]
	ldp	q2, q3, [x2, #544]
	mov	v21.16b, v9.16b
	mov	v22.16b, v11.16b
	trn1	v9.4s, v9.4s, v10.4s
	trn1	v11.4s, v11.4s, v12.4s
	trn2	v10.4s, v21.4s, v10.4s
	trn2	v12.4s, v22.4s, v12.4s
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v10.4s, v22.4s, v0.4s
	sqrdmulh	v12.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v10.4s, v10.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	ldp	q0, q1, [x1, #576]
	ldp	q2, q3, [x2, #576]
	mov	v21.16b, v13.16b
	mov	v22.16b, v15.16b
	trn1	v13.4s, v13.4s, v14.4s
	trn1	v15.4s, v15.4s, v16.4s
	trn2	v14.4s, v21.4s, v14.4s
	trn2	v16.4s, v22.4s, v16.4s
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v14.4s, v22.4s, v0.4s
	sqrdmulh	v16.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v14.4s, v14.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	ldp	q0, q1, [x1, #608]
	ldp	q2, q3, [x2, #608]
	mov	v21.16b, v17.16b
	mov	v22.16b, v19.16b
	trn1	v17.4s, v17.4s, v18.4s
	trn1	v19.4s, v19.4s, v20.4s
	trn2	v18.4s, v21.4s, v18.4s
	trn2	v20.4s, v22.4s, v20.4s
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v18.4s, v22.4s, v0.4s
	sqrdmulh	v20.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v18.4s, v18.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1024]
	ldr	q1, [x1, #1040]
	ldr	q2, [x2, #1024]
	ldr	q3, [x2, #1040]
	mov	v21.16b, v5.16b
	mov	v22.16b, v7.16b
	trn1	v5.2d, v5.2d, v6.2d
	trn1	v7.2d, v7.2d, v8.2d
	trn2	v6.2d, v21.2d, v6.2d
	trn2	v8.2d, v22.2d, v8.2d
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v6.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v6.4s, v6.4s, v21.4s
	sub	v8.4s, v8.4s, v23.4s
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	mov	v21.16b, v9.16b
	mov	v22.16b, v11.16b
	trn1	v9.2d, v9.2d, v10.2d
	trn1	v11.2d, v11.2d, v12.2d
	trn2	v10.2d, v21.2d, v10.2d
	trn2	v12.2d, v22.2d, v12.2d
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v10.4s, v22.4s, v0.s[2]
	sqrdmulh	v12.4s, v24.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v10.4s, v10.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	mov	v21.16b, v13.16b
	mov	v22.16b, v15.16b
	trn1	v13.2d, v13.2d, v14.2d
	trn1	v15.2d, v15.2d, v16.2d
	trn2	v14.2d, v21.2d, v14.2d
	trn2	v16.2d, v22.2d, v16.2d
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v3.s[0]
	mul	v23.4s, v24.4s, v3.s[1]
	sqrdmulh	v14.4s, v22.4s, v1.s[0]
	sqrdmulh	v16.4s, v24.4s, v1.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v14.4s, v14.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	mov	v21.16b, v17.16b
	mov	v22.16b, v19.16b
	trn1	v17.2d, v17.2d, v18.2d
	trn1	v19.2d, v19.2d, v20.2d
	trn2	v18.2d, v21.2d, v18.2d
	trn2	v20.2d, v22.2d, v20.2d
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v3.s[2]
	mul	v23.4s, v24.4s, v3.s[3]
	sqrdmulh	v18.4s, v22.4s, v1.s[2]
	sqrdmulh	v20.4s, v24.4s, v1.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v18.4s, v18.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1152]
	ldr	q2, [x2, #1152]
	sub	v22.4s, v5.4s, v7.4s
	sub	v24.4s, v6.4s, v8.4s
	add	v5.4s, v5.4s, v7.4s
	add	v6.4s, v6.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v7.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[0]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v7.4s, v7.4s, v21.4s
	sub	v8.4s, v8.4s, v23.4s
	sshr	v7.4s, v7.4s, #1
	sshr	v8.4s, v8.4s, #1
	sub	v22.4s, v9.4s, v11.4s
	sub	v24.4s, v10.4s, v12.4s
	add	v9.4s, v9.4s, v11.4s
	add	v10.4s, v10.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v11.4s, v22.4s, v0.s[1]
	sqrdmulh	v12.4s, v24.4s, v0.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v11.4s, v11.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v15.4s
	sub	v24.4s, v14.4s, v16.4s
	add	v13.4s, v13.4s, v15.4s
	add	v14.4s, v14.4s, v16.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v15.4s, v22.4s, v0.s[2]
	sqrdmulh	v16.4s, v24.4s, v0.s[2]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v15.4s, v15.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v15.4s, v15.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v17.4s, v19.4s
	sub	v24.4s, v18.4s, v20.4s
	add	v17.4s, v17.4s, v19.4s
	add	v18.4s, v18.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[3]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v19.4s, v22.4s, v0.s[3]
	sqrdmulh	v20.4s, v24.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v19.4s, v19.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	stp	q5, q6, [x0]
	stp	q7, q8, [x0, #32]
	stp	q9, q10, [x0, #64]
	stp	q11, q12, [x0, #96]
	stp	q13, q14, [x0, #128]
	stp	q15, q16, [x0, #160]
	stp	q17, q18, [x0, #192]
	stp	q19, q20, [x0, #224]
	ldp	q5, q6, [x0, #256]
	ldp	q7, q8, [x0, #288]
	ldp	q9, q10, [x0, #320]
	ldp	q11, q12, [x0, #352]
	ldp	q13, q14, [x0, #384]
	ldp	q15, q16, [x0, #416]
	ldp	q17, q18, [x0, #448]
	ldp	q19, q20, [x0, #480]
	ldp	q0, q1, [x1, #128]
	ldp	q2, q3, [x2, #128]
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v6.4s, v22.4s, v0.4s
	sqrdmulh	v8.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v6.4s, v6.4s, v21.4s
	sub	v8.4s, v8.4s, v23.4s
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	ldp	q0, q1, [x1, #160]
	ldp	q2, q3, [x2, #160]
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v10.4s, v22.4s, v0.4s
	sqrdmulh	v12.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v10.4s, v10.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	ldp	q0, q1, [x1, #192]
	ldp	q2, q3, [x2, #192]
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v14.4s, v22.4s, v0.4s
	sqrdmulh	v16.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v14.4s, v14.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	ldp	q0, q1, [x1, #224]
	ldp	q2, q3, [x2, #224]
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v18.4s, v22.4s, v0.4s
	sqrdmulh	v20.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v18.4s, v18.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldp	q0, q1, [x1, #640]
	ldp	q2, q3, [x2, #640]
	mov	v21.16b, v5.16b
	mov	v22.16b, v7.16b
	trn1	v5.4s, v5.4s, v6.4s
	trn1	v7.4s, v7.4s, v8.4s
	trn2	v6.4s, v21.4s, v6.4s
	trn2	v8.4s, v22.4s, v8.4s
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v6.4s, v22.4s, v0.4s
	sqrdmulh	v8.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v6.4s, v6.4s, v21.4s
	sub	v8.4s, v8.4s, v23.4s
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	ldp	q0, q1, [x1, #672]
	ldp	q2, q3, [x2, #672]
	mov	v21.16b, v9.16b
	mov	v22.16b, v11.16b
	trn1	v9.4s, v9.4s, v10.4s
	trn1	v11.4s, v11.4s, v12.4s
	trn2	v10.4s, v21.4s, v10.4s
	trn2	v12.4s, v22.4s, v12.4s
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v10.4s, v22.4s, v0.4s
	sqrdmulh	v12.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v10.4s, v10.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	ldp	q0, q1, [x1, #704]
	ldp	q2, q3, [x2, #704]
	mov	v21.16b, v13.16b
	mov	v22.16b, v15.16b
	trn1	v13.4s, v13.4s, v14.4s
	trn1	v15.4s, v15.4s, v16.4s
	trn2	v14.4s, v21.4s, v14.4s
	trn2	v16.4s, v22.4s, v16.4s
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v14.4s, v22.4s, v0.4s
	sqrdmulh	v16.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v14.4s, v14.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	ldp	q0, q1, [x1, #736]
	ldp	q2, q3, [x2, #736]
	mov	v21.16b, v17.16b
	mov	v22.16b, v19.16b
	trn1	v17.4s, v17.4s, v18.4s
	trn1	v19.4s, v19.4s, v20.4s
	trn2	v18.4s, v21.4s, v18.4s
	trn2	v20.4s, v22.4s, v20.4s
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v18.4s, v22.4s, v0.4s
	sqrdmulh	v20.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v18.4s, v18.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1056]
	ldr	q1, [x1, #1072]
	ldr	q2, [x2, #1056]
	ldr	q3, [x2, #1072]
	mov	v21.16b, v5.16b
	mov	v22.16b, v7.16b
	trn1	v5.2d, v5.2d, v6.2d
	trn1	v7.2d, v7.2d, v8.2d
	trn2	v6.2d, v21.2d, v6.2d
	trn2	v8.2d, v22.2d, v8.2d
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v6.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v6.4s, v6.4s, v21.4s
	sub	v8.4s, v8.4s, v23.4s
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	mov	v21.16b, v9.16b
	mov	v22.16b, v11.16b
	trn1	v9.2d, v9.2d, v10.2d
	trn1	v11.2d, v11.2d, v12.2d
	trn2	v10.2d, v21.2d, v10.2d
	trn2	v12.2d, v22.2d, v12.2d
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v10.4s, v22.4s, v0.s[2]
	sqrdmulh	v12.4s, v24.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v10.4s, v10.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	mov	v21.16b, v13.16b
	mov	v22.16b, v15.16b
	trn1	v13.2d, v13.2d, v14.2d
	trn1	v15.2d, v15.2d, v16.2d
	trn2	v14.2d, v21.2d, v14.2d
	trn2	v16.2d, v22.2d, v16.2d
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v3.s[0]
	mul	v23.4s, v24.4s, v3.s[1]
	sqrdmulh	v14.4s, v22.4s, v1.s[0]
	sqrdmulh	v16.4s, v24.4s, v1.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v14.4s, v14.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	mov	v21.16b, v17.16b
	mov	v22.16b, v19.16b
	trn1	v17.2d, v17.2d, v18.2d
	trn1	v19.2d, v19.2d, v20.2d
	trn2	v18.2d, v21.2d, v18.2d
	trn2	v20.2d, v22.2d, v20.2d
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v3.s[2]
	mul	v23.4s, v24.4s, v3.s[3]
	sqrdmulh	v18.4s, v22.4s, v1.s[2]
	sqrdmulh	v20.4s, v24.4s, v1.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v18.4s, v18.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1168]
	ldr	q2, [x2, #1168]
	sub	v22.4s, v5.4s, v7.4s
	sub	v24.4s, v6.4s, v8.4s
	add	v5.4s, v5.4s, v7.4s
	add	v6.4s, v6.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v7.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[0]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v7.4s, v7.4s, v21.4s
	sub	v8.4s, v8.4s, v23.4s
	sshr	v7.4s, v7.4s, #1
	sshr	v8.4s, v8.4s, #1
	sub	v22.4s, v9.4s, v11.4s
	sub	v24.4s, v10.4s, v12.4s
	add	v9.4s, v9.4s, v11.4s
	add	v10.4s, v10.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v11.4s, v22.4s, v0.s[1]
	sqrdmulh	v12.4s, v24.4s, v0.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v11.4s, v11.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v15.4s
	sub	v24.4s, v14.4s, v16.4s
	add	v13.4s, v13.4s, v15.4s
	add	v14.4s, v14.4s, v16.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v15.4s, v22.4s, v0.s[2]
	sqrdmulh	v16.4s, v24.4s, v0.s[2]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v15.4s, v15.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v15.4s, v15.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v17.4s, v19.4s
	sub	v24.4s, v18.4s, v20.4s
	add	v17.4s, v17.4s, v19.4s
	add	v18.4s, v18.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[3]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v19.4s, v22.4s, v0.s[3]
	sqrdmulh	v20.4s, v24.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v19.4s, v19.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	stp	q5, q6, [x0, #256]
	stp	q7, q8, [x0, #288]
	stp	q9, q10, [x0, #320]
	stp	q11, q12, [x0, #352]
	stp	q13, q14, [x0, #384]
	stp	q15, q16, [x0, #416]
	stp	q17, q18, [x0, #448]
	stp	q19, q20, [x0, #480]
	ldp	q5, q6, [x0, #512]
	ldp	q7, q8, [x0, #544]
	ldp	q9, q10, [x0, #576]
	ldp	q11, q12, [x0, #608]
	ldp	q13, q14, [x0, #640]
	ldp	q15, q16, [x0, #672]
	ldp	q17, q18, [x0, #704]
	ldp	q19, q20, [x0, #736]
	ldp	q0, q1, [x1, #256]
	ldp	q2, q3, [x2, #256]
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v6.4s, v22.4s, v0.4s
	sqrdmulh	v8.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v6.4s, v6.4s, v21.4s
	sub	v8.4s, v8.4s, v23.4s
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	ldp	q0, q1, [x1, #288]
	ldp	q2, q3, [x2, #288]
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v10.4s, v22.4s, v0.4s
	sqrdmulh	v12.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v10.4s, v10.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	ldp	q0, q1, [x1, #320]
	ldp	q2, q3, [x2, #320]
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v14.4s, v22.4s, v0.4s
	sqrdmulh	v16.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v14.4s, v14.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	ldp	q0, q1, [x1, #352]
	ldp	q2, q3, [x2, #352]
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v18.4s, v22.4s, v0.4s
	sqrdmulh	v20.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v18.4s, v18.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldp	q0, q1, [x1, #768]
	ldp	q2, q3, [x2, #768]
	mov	v21.16b, v5.16b
	mov	v22.16b, v7.16b
	trn1	v5.4s, v5.4s, v6.4s
	trn1	v7.4s, v7.4s, v8.4s
	trn2	v6.4s, v21.4s, v6.4s
	trn2	v8.4s, v22.4s, v8.4s
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v6.4s, v22.4s, v0.4s
	sqrdmulh	v8.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v6.4s, v6.4s, v21.4s
	sub	v8.4s, v8.4s, v23.4s
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	ldp	q0, q1, [x1, #800]
	ldp	q2, q3, [x2, #800]
	mov	v21.16b, v9.16b
	mov	v22.16b, v11.16b
	trn1	v9.4s, v9.4s, v10.4s
	trn1	v11.4s, v11.4s, v12.4s
	trn2	v10.4s, v21.4s, v10.4s
	trn2	v12.4s, v22.4s, v12.4s
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v10.4s, v22.4s, v0.4s
	sqrdmulh	v12.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v10.4s, v10.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	ldp	q0, q1, [x1, #832]
	ldp	q2, q3, [x2, #832]
	mov	v21.16b, v13.16b
	mov	v22.16b, v15.16b
	trn1	v13.4s, v13.4s, v14.4s
	trn1	v15.4s, v15.4s, v16.4s
	trn2	v14.4s, v21.4s, v14.4s
	trn2	v16.4s, v22.4s, v16.4s
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v14.4s, v22.4s, v0.4s
	sqrdmulh	v16.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v14.4s, v14.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	ldp	q0, q1, [x1, #864]
	ldp	q2, q3, [x2, #864]
	mov	v21.16b, v17.16b
	mov	v22.16b, v19.16b
	trn1	v17.4s, v17.4s, v18.4s
	trn1	v19.4s, v19.4s, v20.4s
	trn2	v18.4s, v21.4s, v18.4s
	trn2	v20.4s, v22.4s, v20.4s
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v18.4s, v22.4s, v0.4s
	sqrdmulh	v20.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v18.4s, v18.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1088]
	ldr	q1, [x1, #1104]
	ldr	q2, [x2, #1088]
	ldr	q3, [x2, #1104]
	mov	v21.16b, v5.16b
	mov	v22.16b, v7.16b
	trn1	v5.2d, v5.2d, v6.2d
	trn1	v7.2d, v7.2d, v8.2d
	trn2	v6.2d, v21.2d, v6.2d
	trn2	v8.2d, v22.2d, v8.2d
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v6.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v6.4s, v6.4s, v21.4s
	sub	v8.4s, v8.4s, v23.4s
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	mov	v21.16b, v9.16b
	mov	v22.16b, v11.16b
	trn1	v9.2d, v9.2d, v10.2d
	trn1	v11.2d, v11.2d, v12.2d
	trn2	v10.2d, v21.2d, v10.2d
	trn2	v12.2d, v22.2d, v12.2d
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v10.4s, v22.4s, v0.s[2]
	sqrdmulh	v12.4s, v24.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v10.4s, v10.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	mov	v21.16b, v13.16b
	mov	v22.16b, v15.16b
	trn1	v13.2d, v13.2d, v14.2d
	trn1	v15.2d, v15.2d, v16.2d
	trn2	v14.2d, v21.2d, v14.2d
	trn2	v16.2d, v22.2d, v16.2d
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v3.s[0]
	mul	v23.4s, v24.4s, v3.s[1]
	sqrdmulh	v14.4s, v22.4s, v1.s[0]
	sqrdmulh	v16.4s, v24.4s, v1.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v14.4s, v14.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	mov	v21.16b, v17.16b
	mov	v22.16b, v19.16b
	trn1	v17.2d, v17.2d, v18.2d
	trn1	v19.2d, v19.2d, v20.2d
	trn2	v18.2d, v21.2d, v18.2d
	trn2	v20.2d, v22.2d, v20.2d
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v3.s[2]
	mul	v23.4s, v24.4s, v3.s[3]
	sqrdmulh	v18.4s, v22.4s, v1.s[2]
	sqrdmulh	v20.4s, v24.4s, v1.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v18.4s, v18.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1184]
	ldr	q2, [x2, #1184]
	sub	v22.4s, v5.4s, v7.4s
	sub	v24.4s, v6.4s, v8.4s
	add	v5.4s, v5.4s, v7.4s
	add	v6.4s, v6.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v7.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[0]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v7.4s, v7.4s, v21.4s
	sub	v8.4s, v8.4s, v23.4s
	sshr	v7.4s, v7.4s, #1
	sshr	v8.4s, v8.4s, #1
	sub	v22.4s, v9.4s, v11.4s
	sub	v24.4s, v10.4s, v12.4s
	add	v9.4s, v9.4s, v11.4s
	add	v10.4s, v10.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v11.4s, v22.4s, v0.s[1]
	sqrdmulh	v12.4s, v24.4s, v0.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v11.4s, v11.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v15.4s
	sub	v24.4s, v14.4s, v16.4s
	add	v13.4s, v13.4s, v15.4s
	add	v14.4s, v14.4s, v16.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v15.4s, v22.4s, v0.s[2]
	sqrdmulh	v16.4s, v24.4s, v0.s[2]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v15.4s, v15.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v15.4s, v15.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v17.4s, v19.4s
	sub	v24.4s, v18.4s, v20.4s
	add	v17.4s, v17.4s, v19.4s
	add	v18.4s, v18.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[3]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v19.4s, v22.4s, v0.s[3]
	sqrdmulh	v20.4s, v24.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v19.4s, v19.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	stp	q5, q6, [x0, #512]
	stp	q7, q8, [x0, #544]
	stp	q9, q10, [x0, #576]
	stp	q11, q12, [x0, #608]
	stp	q13, q14, [x0, #640]
	stp	q15, q16, [x0, #672]
	stp	q17, q18, [x0, #704]
	stp	q19, q20, [x0, #736]
	ldp	q5, q6, [x0, #768]
	ldp	q7, q8, [x0, #800]
	ldp	q9, q10, [x0, #832]
	ldp	q11, q12, [x0, #864]
	ldp	q13, q14, [x0, #896]
	ldp	q15, q16, [x0, #928]
	ldp	q17, q18, [x0, #960]
	ldp	q19, q20, [x0, #992]
	ldp	q0, q1, [x1, #384]
	ldp	q2, q3, [x2, #384]
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v6.4s, v22.4s, v0.4s
	sqrdmulh	v8.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v6.4s, v6.4s, v21.4s
	sub	v8.4s, v8.4s, v23.4s
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	ldp	q0, q1, [x1, #416]
	ldp	q2, q3, [x2, #416]
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v10.4s, v22.4s, v0.4s
	sqrdmulh	v12.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v10.4s, v10.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	ldp	q0, q1, [x1, #448]
	ldp	q2, q3, [x2, #448]
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v14.4s, v22.4s, v0.4s
	sqrdmulh	v16.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v14.4s, v14.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	ldp	q0, q1, [x1, #480]
	ldp	q2, q3, [x2, #480]
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v18.4s, v22.4s, v0.4s
	sqrdmulh	v20.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v18.4s, v18.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldp	q0, q1, [x1, #896]
	ldp	q2, q3, [x2, #896]
	mov	v21.16b, v5.16b
	mov	v22.16b, v7.16b
	trn1	v5.4s, v5.4s, v6.4s
	trn1	v7.4s, v7.4s, v8.4s
	trn2	v6.4s, v21.4s, v6.4s
	trn2	v8.4s, v22.4s, v8.4s
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v6.4s, v22.4s, v0.4s
	sqrdmulh	v8.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v6.4s, v6.4s, v21.4s
	sub	v8.4s, v8.4s, v23.4s
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	ldp	q0, q1, [x1, #928]
	ldp	q2, q3, [x2, #928]
	mov	v21.16b, v9.16b
	mov	v22.16b, v11.16b
	trn1	v9.4s, v9.4s, v10.4s
	trn1	v11.4s, v11.4s, v12.4s
	trn2	v10.4s, v21.4s, v10.4s
	trn2	v12.4s, v22.4s, v12.4s
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v10.4s, v22.4s, v0.4s
	sqrdmulh	v12.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v10.4s, v10.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	ldp	q0, q1, [x1, #960]
	ldp	q2, q3, [x2, #960]
	mov	v21.16b, v13.16b
	mov	v22.16b, v15.16b
	trn1	v13.4s, v13.4s, v14.4s
	trn1	v15.4s, v15.4s, v16.4s
	trn2	v14.4s, v21.4s, v14.4s
	trn2	v16.4s, v22.4s, v16.4s
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v14.4s, v22.4s, v0.4s
	sqrdmulh	v16.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v14.4s, v14.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	ldp	q0, q1, [x1, #992]
	ldp	q2, q3, [x2, #992]
	mov	v21.16b, v17.16b
	mov	v22.16b, v19.16b
	trn1	v17.4s, v17.4s, v18.4s
	trn1	v19.4s, v19.4s, v20.4s
	trn2	v18.4s, v21.4s, v18.4s
	trn2	v20.4s, v22.4s, v20.4s
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v18.4s, v22.4s, v0.4s
	sqrdmulh	v20.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v18.4s, v18.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1120]
	ldr	q1, [x1, #1136]
	ldr	q2, [x2, #1120]
	ldr	q3, [x2, #1136]
	mov	v21.16b, v5.16b
	mov	v22.16b, v7.16b
	trn1	v5.2d, v5.2d, v6.2d
	trn1	v7.2d, v7.2d, v8.2d
	trn2	v6.2d, v21.2d, v6.2d
	trn2	v8.2d, v22.2d, v8.2d
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v6.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v6.4s, v6.4s, v21.4s
	sub	v8.4s, v8.4s, v23.4s
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	mov	v21.16b, v9.16b
	mov	v22.16b, v11.16b
	trn1	v9.2d, v9.2d, v10.2d
	trn1	v11.2d, v11.2d, v12.2d
	trn2	v10.2d, v21.2d, v10.2d
	trn2	v12.2d, v22.2d, v12.2d
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v10.4s, v22.4s, v0.s[2]
	sqrdmulh	v12.4s, v24.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v10.4s, v10.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	mov	v21.16b, v13.16b
	mov	v22.16b, v15.16b
	trn1	v13.2d, v13.2d, v14.2d
	trn1	v15.2d, v15.2d, v16.2d
	trn2	v14.2d, v21.2d, v14.2d
	trn2	v16.2d, v22.2d, v16.2d
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v3.s[0]
	mul	v23.4s, v24.4s, v3.s[1]
	sqrdmulh	v14.4s, v22.4s, v1.s[0]
	sqrdmulh	v16.4s, v24.4s, v1.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v14.4s, v14.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	mov	v21.16b, v17.16b
	mov	v22.16b, v19.16b
	trn1	v17.2d, v17.2d, v18.2d
	trn1	v19.2d, v19.2d, v20.2d
	trn2	v18.2d, v21.2d, v18.2d
	trn2	v20.2d, v22.2d, v20.2d
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v3.s[2]
	mul	v23.4s, v24.4s, v3.s[3]
	sqrdmulh	v18.4s, v22.4s, v1.s[2]
	sqrdmulh	v20.4s, v24.4s, v1.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v18.4s, v18.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1200]
	ldr	q2, [x2, #1200]
	sub	v22.4s, v5.4s, v7.4s
	sub	v24.4s, v6.4s, v8.4s
	add	v5.4s, v5.4s, v7.4s
	add	v6.4s, v6.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v7.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[0]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v7.4s, v7.4s, v21.4s
	sub	v8.4s, v8.4s, v23.4s
	sshr	v7.4s, v7.4s, #1
	sshr	v8.4s, v8.4s, #1
	sub	v22.4s, v9.4s, v11.4s
	sub	v24.4s, v10.4s, v12.4s
	add	v9.4s, v9.4s, v11.4s
	add	v10.4s, v10.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v11.4s, v22.4s, v0.s[1]
	sqrdmulh	v12.4s, v24.4s, v0.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v11.4s, v11.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v15.4s
	sub	v24.4s, v14.4s, v16.4s
	add	v13.4s, v13.4s, v15.4s
	add	v14.4s, v14.4s, v16.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v15.4s, v22.4s, v0.s[2]
	sqrdmulh	v16.4s, v24.4s, v0.s[2]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v15.4s, v15.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v15.4s, v15.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v17.4s, v19.4s
	sub	v24.4s, v18.4s, v20.4s
	add	v17.4s, v17.4s, v19.4s
	add	v18.4s, v18.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[3]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v19.4s, v22.4s, v0.s[3]
	sqrdmulh	v20.4s, v24.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v19.4s, v19.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	stp	q5, q6, [x0, #768]
	stp	q7, q8, [x0, #800]
	stp	q9, q10, [x0, #832]
	stp	q11, q12, [x0, #864]
	stp	q13, q14, [x0, #896]
	stp	q15, q16, [x0, #928]
	stp	q17, q18, [x0, #960]
	stp	q19, q20, [x0, #992]
	ldr	q5, [x0]
	ldr	q6, [x0, #64]
	ldr	q7, [x0, #128]
	ldr	q8, [x0, #192]
	ldr	q9, [x0, #256]
	ldr	q10, [x0, #320]
	ldr	q11, [x0, #384]
	ldr	q12, [x0, #448]
	ldr	q13, [x0, #512]
	ldr	q14, [x0, #576]
	ldr	q15, [x0, #640]
	ldr	q16, [x0, #704]
	ldr	q17, [x0, #768]
	ldr	q18, [x0, #832]
	ldr	q19, [x0, #896]
	ldr	q20, [x0, #960]
	ldr	q0, [x1, #1216]
	ldr	q1, [x1, #1232]
	ldr	q2, [x2, #1216]
	ldr	q3, [x2, #1232]
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v6.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v6.4s, v6.4s, v21.4s
	sub	v8.4s, v8.4s, v23.4s
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v10.4s, v22.4s, v0.s[2]
	sqrdmulh	v12.4s, v24.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v10.4s, v10.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v3.s[0]
	mul	v23.4s, v24.4s, v3.s[1]
	sqrdmulh	v14.4s, v22.4s, v1.s[0]
	sqrdmulh	v16.4s, v24.4s, v1.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v14.4s, v14.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v3.s[2]
	mul	v23.4s, v24.4s, v3.s[3]
	sqrdmulh	v18.4s, v22.4s, v1.s[2]
	sqrdmulh	v20.4s, v24.4s, v1.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v18.4s, v18.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1248]
	ldr	q2, [x2, #1248]
	sub	v22.4s, v5.4s, v7.4s
	sub	v24.4s, v6.4s, v8.4s
	add	v5.4s, v5.4s, v7.4s
	add	v6.4s, v6.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v7.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[0]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v7.4s, v7.4s, v21.4s
	sub	v8.4s, v8.4s, v23.4s
	sshr	v7.4s, v7.4s, #1
	sshr	v8.4s, v8.4s, #1
	sub	v22.4s, v9.4s, v11.4s
	sub	v24.4s, v10.4s, v12.4s
	add	v9.4s, v9.4s, v11.4s
	add	v10.4s, v10.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v11.4s, v22.4s, v0.s[1]
	sqrdmulh	v12.4s, v24.4s, v0.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v11.4s, v11.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v15.4s
	sub	v24.4s, v14.4s, v16.4s
	add	v13.4s, v13.4s, v15.4s
	add	v14.4s, v14.4s, v16.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v15.4s, v22.4s, v0.s[2]
	sqrdmulh	v16.4s, v24.4s, v0.s[2]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v15.4s, v15.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v15.4s, v15.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v17.4s, v19.4s
	sub	v24.4s, v18.4s, v20.4s
	add	v17.4s, v17.4s, v19.4s
	add	v18.4s, v18.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[3]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v19.4s, v22.4s, v0.s[3]
	sqrdmulh	v20.4s, v24.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v19.4s, v19.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1264]
	ldr	q2, [x2, #1264]
	sub	v22.4s, v5.4s, v9.4s
	sub	v24.4s, v6.4s, v10.4s
	add	v5.4s, v5.4s, v9.4s
	add	v6.4s, v6.4s, v10.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v9.4s, v22.4s, v0.s[0]
	sqrdmulh	v10.4s, v24.4s, v0.s[0]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v9.4s, v9.4s, v21.4s
	sub	v10.4s, v10.4s, v23.4s
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	sub	v22.4s, v7.4s, v11.4s
	sub	v24.4s, v8.4s, v12.4s
	add	v7.4s, v7.4s, v11.4s
	add	v8.4s, v8.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v11.4s, v22.4s, v0.s[0]
	sqrdmulh	v12.4s, v24.4s, v0.s[0]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v11.4s, v11.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v17.4s
	sub	v24.4s, v14.4s, v18.4s
	add	v13.4s, v13.4s, v17.4s
	add	v14.4s, v14.4s, v18.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v17.4s, v22.4s, v0.s[1]
	sqrdmulh	v18.4s, v24.4s, v0.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v17.4s, v17.4s, v21.4s
	sub	v18.4s, v18.4s, v23.4s
	sshr	v17.4s, v17.4s, #1
	sshr	v18.4s, v18.4s, #1
	sub	v22.4s, v15.4s, v19.4s
	sub	v24.4s, v16.4s, v20.4s
	add	v15.4s, v15.4s, v19.4s
	add	v16.4s, v16.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v19.4s, v22.4s, v0.s[1]
	sqrdmulh	v20.4s, v24.4s, v0.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v19.4s, v19.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	sub	v22.4s, v5.4s, v13.4s
	sub	v24.4s, v6.4s, v14.4s
	add	v5.4s, v5.4s, v13.4s
	add	v6.4s, v6.4s, v14.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v13.4s, v22.4s, v0.s[2]
	sqrdmulh	v14.4s, v24.4s, v0.s[2]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v13.4s, v13.4s, v21.4s
	sub	v14.4s, v14.4s, v23.4s
	sshr	v13.4s, v13.4s, #1
	sshr	v14.4s, v14.4s, #1
	sub	v22.4s, v7.4s, v15.4s
	sub	v24.4s, v8.4s, v16.4s
	add	v7.4s, v7.4s, v15.4s
	add	v8.4s, v8.4s, v16.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v15.4s, v22.4s, v0.s[2]
	sqrdmulh	v16.4s, v24.4s, v0.s[2]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v15.4s, v15.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v15.4s, v15.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v9.4s, v17.4s
	sub	v24.4s, v10.4s, v18.4s
	add	v9.4s, v9.4s, v17.4s
	add	v10.4s, v10.4s, v18.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v17.4s, v22.4s, v0.s[2]
	sqrdmulh	v18.4s, v24.4s, v0.s[2]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v17.4s, v17.4s, v21.4s
	sub	v18.4s, v18.4s, v23.4s
	sshr	v17.4s, v17.4s, #1
	sshr	v18.4s, v18.4s, #1
	sub	v22.4s, v11.4s, v19.4s
	sub	v24.4s, v12.4s, v20.4s
	add	v11.4s, v11.4s, v19.4s
	add	v12.4s, v12.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v19.4s, v22.4s, v0.s[2]
	sqrdmulh	v20.4s, v24.4s, v0.s[2]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v19.4s, v19.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	mul	v21.4s, v5.4s, v2.s[3]
	mul	v22.4s, v6.4s, v2.s[3]
	sqrdmulh	v5.4s, v5.4s, v0.s[3]
	sqrdmulh	v6.4s, v6.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v22.4s, v22.4s, v4.s[0]
	sub	v5.4s, v5.4s, v21.4s
	sub	v6.4s, v6.4s, v22.4s
	sshr	v5.4s, v5.4s, #1
	sshr	v6.4s, v6.4s, #1
	mul	v21.4s, v7.4s, v2.s[3]
	mul	v22.4s, v8.4s, v2.s[3]
	sqrdmulh	v7.4s, v7.4s, v0.s[3]
	sqrdmulh	v8.4s, v8.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v22.4s, v22.4s, v4.s[0]
	sub	v7.4s, v7.4s, v21.4s
	sub	v8.4s, v8.4s, v22.4s
	sshr	v7.4s, v7.4s, #1
	sshr	v8.4s, v8.4s, #1
	mul	v21.4s, v9.4s, v2.s[3]
	mul	v22.4s, v10.4s, v2.s[3]
	sqrdmulh	v9.4s, v9.4s, v0.s[3]
	sqrdmulh	v10.4s, v10.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v22.4s, v22.4s, v4.s[0]
	sub	v9.4s, v9.4s, v21.4s
	sub	v10.4s, v10.4s, v22.4s
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	mul	v21.4s, v11.4s, v2.s[3]
	mul	v22.4s, v12.4s, v2.s[3]
	sqrdmulh	v11.4s, v11.4s, v0.s[3]
	sqrdmulh	v12.4s, v12.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v22.4s, v22.4s, v4.s[0]
	sub	v11.4s, v11.4s, v21.4s
	sub	v12.4s, v12.4s, v22.4s
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	str	q5, [x0]
	str	q6, [x0, #64]
	str	q7, [x0, #128]
	str	q8, [x0, #192]
	str	q9, [x0, #256]
	str	q10, [x0, #320]
	str	q11, [x0, #384]
	str	q12, [x0, #448]
	str	q13, [x0, #512]
	str	q14, [x0, #576]
	str	q15, [x0, #640]
	str	q16, [x0, #704]
	str	q17, [x0, #768]
	str	q18, [x0, #832]
	str	q19, [x0, #896]
	str	q20, [x0, #960]
	ldr	q5, [x0, #16]
	ldr	q6, [x0, #80]
	ldr	q7, [x0, #144]
	ldr	q8, [x0, #208]
	ldr	q9, [x0, #272]
	ldr	q10, [x0, #336]
	ldr	q11, [x0, #400]
	ldr	q12, [x0, #464]
	ldr	q13, [x0, #528]
	ldr	q14, [x0, #592]
	ldr	q15, [x0, #656]
	ldr	q16, [x0, #720]
	ldr	q17, [x0, #784]
	ldr	q18, [x0, #848]
	ldr	q19, [x0, #912]
	ldr	q20, [x0, #976]
	ldr	q0, [x1, #1216]
	ldr	q1, [x1, #1232]
	ldr	q2, [x2, #1216]
	ldr	q3, [x2, #1232]
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v6.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v6.4s, v6.4s, v21.4s
	sub	v8.4s, v8.4s, v23.4s
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v10.4s, v22.4s, v0.s[2]
	sqrdmulh	v12.4s, v24.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v10.4s, v10.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v3.s[0]
	mul	v23.4s, v24.4s, v3.s[1]
	sqrdmulh	v14.4s, v22.4s, v1.s[0]
	sqrdmulh	v16.4s, v24.4s, v1.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v14.4s, v14.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v3.s[2]
	mul	v23.4s, v24.4s, v3.s[3]
	sqrdmulh	v18.4s, v22.4s, v1.s[2]
	sqrdmulh	v20.4s, v24.4s, v1.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v18.4s, v18.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1248]
	ldr	q2, [x2, #1248]
	sub	v22.4s, v5.4s, v7.4s
	sub	v24.4s, v6.4s, v8.4s
	add	v5.4s, v5.4s, v7.4s
	add	v6.4s, v6.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v7.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[0]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v7.4s, v7.4s, v21.4s
	sub	v8.4s, v8.4s, v23.4s
	sshr	v7.4s, v7.4s, #1
	sshr	v8.4s, v8.4s, #1
	sub	v22.4s, v9.4s, v11.4s
	sub	v24.4s, v10.4s, v12.4s
	add	v9.4s, v9.4s, v11.4s
	add	v10.4s, v10.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v11.4s, v22.4s, v0.s[1]
	sqrdmulh	v12.4s, v24.4s, v0.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v11.4s, v11.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v15.4s
	sub	v24.4s, v14.4s, v16.4s
	add	v13.4s, v13.4s, v15.4s
	add	v14.4s, v14.4s, v16.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v15.4s, v22.4s, v0.s[2]
	sqrdmulh	v16.4s, v24.4s, v0.s[2]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v15.4s, v15.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v15.4s, v15.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v17.4s, v19.4s
	sub	v24.4s, v18.4s, v20.4s
	add	v17.4s, v17.4s, v19.4s
	add	v18.4s, v18.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[3]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v19.4s, v22.4s, v0.s[3]
	sqrdmulh	v20.4s, v24.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v19.4s, v19.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1264]
	ldr	q2, [x2, #1264]
	sub	v22.4s, v5.4s, v9.4s
	sub	v24.4s, v6.4s, v10.4s
	add	v5.4s, v5.4s, v9.4s
	add	v6.4s, v6.4s, v10.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v9.4s, v22.4s, v0.s[0]
	sqrdmulh	v10.4s, v24.4s, v0.s[0]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v9.4s, v9.4s, v21.4s
	sub	v10.4s, v10.4s, v23.4s
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	sub	v22.4s, v7.4s, v11.4s
	sub	v24.4s, v8.4s, v12.4s
	add	v7.4s, v7.4s, v11.4s
	add	v8.4s, v8.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v11.4s, v22.4s, v0.s[0]
	sqrdmulh	v12.4s, v24.4s, v0.s[0]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v11.4s, v11.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v17.4s
	sub	v24.4s, v14.4s, v18.4s
	add	v13.4s, v13.4s, v17.4s
	add	v14.4s, v14.4s, v18.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v17.4s, v22.4s, v0.s[1]
	sqrdmulh	v18.4s, v24.4s, v0.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v17.4s, v17.4s, v21.4s
	sub	v18.4s, v18.4s, v23.4s
	sshr	v17.4s, v17.4s, #1
	sshr	v18.4s, v18.4s, #1
	sub	v22.4s, v15.4s, v19.4s
	sub	v24.4s, v16.4s, v20.4s
	add	v15.4s, v15.4s, v19.4s
	add	v16.4s, v16.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v19.4s, v22.4s, v0.s[1]
	sqrdmulh	v20.4s, v24.4s, v0.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v19.4s, v19.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	sub	v22.4s, v5.4s, v13.4s
	sub	v24.4s, v6.4s, v14.4s
	add	v5.4s, v5.4s, v13.4s
	add	v6.4s, v6.4s, v14.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v13.4s, v22.4s, v0.s[2]
	sqrdmulh	v14.4s, v24.4s, v0.s[2]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v13.4s, v13.4s, v21.4s
	sub	v14.4s, v14.4s, v23.4s
	sshr	v13.4s, v13.4s, #1
	sshr	v14.4s, v14.4s, #1
	sub	v22.4s, v7.4s, v15.4s
	sub	v24.4s, v8.4s, v16.4s
	add	v7.4s, v7.4s, v15.4s
	add	v8.4s, v8.4s, v16.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v15.4s, v22.4s, v0.s[2]
	sqrdmulh	v16.4s, v24.4s, v0.s[2]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v15.4s, v15.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v15.4s, v15.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v9.4s, v17.4s
	sub	v24.4s, v10.4s, v18.4s
	add	v9.4s, v9.4s, v17.4s
	add	v10.4s, v10.4s, v18.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v17.4s, v22.4s, v0.s[2]
	sqrdmulh	v18.4s, v24.4s, v0.s[2]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v17.4s, v17.4s, v21.4s
	sub	v18.4s, v18.4s, v23.4s
	sshr	v17.4s, v17.4s, #1
	sshr	v18.4s, v18.4s, #1
	sub	v22.4s, v11.4s, v19.4s
	sub	v24.4s, v12.4s, v20.4s
	add	v11.4s, v11.4s, v19.4s
	add	v12.4s, v12.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v19.4s, v22.4s, v0.s[2]
	sqrdmulh	v20.4s, v24.4s, v0.s[2]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v19.4s, v19.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	mul	v21.4s, v5.4s, v2.s[3]
	mul	v22.4s, v6.4s, v2.s[3]
	sqrdmulh	v5.4s, v5.4s, v0.s[3]
	sqrdmulh	v6.4s, v6.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v22.4s, v22.4s, v4.s[0]
	sub	v5.4s, v5.4s, v21.4s
	sub	v6.4s, v6.4s, v22.4s
	sshr	v5.4s, v5.4s, #1
	sshr	v6.4s, v6.4s, #1
	mul	v21.4s, v7.4s, v2.s[3]
	mul	v22.4s, v8.4s, v2.s[3]
	sqrdmulh	v7.4s, v7.4s, v0.s[3]
	sqrdmulh	v8.4s, v8.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v22.4s, v22.4s, v4.s[0]
	sub	v7.4s, v7.4s, v21.4s
	sub	v8.4s, v8.4s, v22.4s
	sshr	v7.4s, v7.4s, #1
	sshr	v8.4s, v8.4s, #1
	mul	v21.4s, v9.4s, v2.s[3]
	mul	v22.4s, v10.4s, v2.s[3]
	sqrdmulh	v9.4s, v9.4s, v0.s[3]
	sqrdmulh	v10.4s, v10.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v22.4s, v22.4s, v4.s[0]
	sub	v9.4s, v9.4s, v21.4s
	sub	v10.4s, v10.4s, v22.4s
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	mul	v21.4s, v11.4s, v2.s[3]
	mul	v22.4s, v12.4s, v2.s[3]
	sqrdmulh	v11.4s, v11.4s, v0.s[3]
	sqrdmulh	v12.4s, v12.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v22.4s, v22.4s, v4.s[0]
	sub	v11.4s, v11.4s, v21.4s
	sub	v12.4s, v12.4s, v22.4s
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	str	q5, [x0, #16]
	str	q6, [x0, #80]
	str	q7, [x0, #144]
	str	q8, [x0, #208]
	str	q9, [x0, #272]
	str	q10, [x0, #336]
	str	q11, [x0, #400]
	str	q12, [x0, #464]
	str	q13, [x0, #528]
	str	q14, [x0, #592]
	str	q15, [x0, #656]
	str	q16, [x0, #720]
	str	q17, [x0, #784]
	str	q18, [x0, #848]
	str	q19, [x0, #912]
	str	q20, [x0, #976]
	ldr	q5, [x0, #32]
	ldr	q6, [x0, #96]
	ldr	q7, [x0, #160]
	ldr	q8, [x0, #224]
	ldr	q9, [x0, #288]
	ldr	q10, [x0, #352]
	ldr	q11, [x0, #416]
	ldr	q12, [x0, #480]
	ldr	q13, [x0, #544]
	ldr	q14, [x0, #608]
	ldr	q15, [x0, #672]
	ldr	q16, [x0, #736]
	ldr	q17, [x0, #800]
	ldr	q18, [x0, #864]
	ldr	q19, [x0, #928]
	ldr	q20, [x0, #992]
	ldr	q0, [x1, #1216]
	ldr	q1, [x1, #1232]
	ldr	q2, [x2, #1216]
	ldr	q3, [x2, #1232]
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v6.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v6.4s, v6.4s, v21.4s
	sub	v8.4s, v8.4s, v23.4s
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v10.4s, v22.4s, v0.s[2]
	sqrdmulh	v12.4s, v24.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v10.4s, v10.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v3.s[0]
	mul	v23.4s, v24.4s, v3.s[1]
	sqrdmulh	v14.4s, v22.4s, v1.s[0]
	sqrdmulh	v16.4s, v24.4s, v1.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v14.4s, v14.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v3.s[2]
	mul	v23.4s, v24.4s, v3.s[3]
	sqrdmulh	v18.4s, v22.4s, v1.s[2]
	sqrdmulh	v20.4s, v24.4s, v1.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v18.4s, v18.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1248]
	ldr	q2, [x2, #1248]
	sub	v22.4s, v5.4s, v7.4s
	sub	v24.4s, v6.4s, v8.4s
	add	v5.4s, v5.4s, v7.4s
	add	v6.4s, v6.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v7.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[0]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v7.4s, v7.4s, v21.4s
	sub	v8.4s, v8.4s, v23.4s
	sshr	v7.4s, v7.4s, #1
	sshr	v8.4s, v8.4s, #1
	sub	v22.4s, v9.4s, v11.4s
	sub	v24.4s, v10.4s, v12.4s
	add	v9.4s, v9.4s, v11.4s
	add	v10.4s, v10.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v11.4s, v22.4s, v0.s[1]
	sqrdmulh	v12.4s, v24.4s, v0.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v11.4s, v11.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v15.4s
	sub	v24.4s, v14.4s, v16.4s
	add	v13.4s, v13.4s, v15.4s
	add	v14.4s, v14.4s, v16.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v15.4s, v22.4s, v0.s[2]
	sqrdmulh	v16.4s, v24.4s, v0.s[2]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v15.4s, v15.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v15.4s, v15.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v17.4s, v19.4s
	sub	v24.4s, v18.4s, v20.4s
	add	v17.4s, v17.4s, v19.4s
	add	v18.4s, v18.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[3]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v19.4s, v22.4s, v0.s[3]
	sqrdmulh	v20.4s, v24.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v19.4s, v19.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1264]
	ldr	q2, [x2, #1264]
	sub	v22.4s, v5.4s, v9.4s
	sub	v24.4s, v6.4s, v10.4s
	add	v5.4s, v5.4s, v9.4s
	add	v6.4s, v6.4s, v10.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v9.4s, v22.4s, v0.s[0]
	sqrdmulh	v10.4s, v24.4s, v0.s[0]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v9.4s, v9.4s, v21.4s
	sub	v10.4s, v10.4s, v23.4s
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	sub	v22.4s, v7.4s, v11.4s
	sub	v24.4s, v8.4s, v12.4s
	add	v7.4s, v7.4s, v11.4s
	add	v8.4s, v8.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v11.4s, v22.4s, v0.s[0]
	sqrdmulh	v12.4s, v24.4s, v0.s[0]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v11.4s, v11.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v17.4s
	sub	v24.4s, v14.4s, v18.4s
	add	v13.4s, v13.4s, v17.4s
	add	v14.4s, v14.4s, v18.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v17.4s, v22.4s, v0.s[1]
	sqrdmulh	v18.4s, v24.4s, v0.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v17.4s, v17.4s, v21.4s
	sub	v18.4s, v18.4s, v23.4s
	sshr	v17.4s, v17.4s, #1
	sshr	v18.4s, v18.4s, #1
	sub	v22.4s, v15.4s, v19.4s
	sub	v24.4s, v16.4s, v20.4s
	add	v15.4s, v15.4s, v19.4s
	add	v16.4s, v16.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v19.4s, v22.4s, v0.s[1]
	sqrdmulh	v20.4s, v24.4s, v0.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v19.4s, v19.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	sub	v22.4s, v5.4s, v13.4s
	sub	v24.4s, v6.4s, v14.4s
	add	v5.4s, v5.4s, v13.4s
	add	v6.4s, v6.4s, v14.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v13.4s, v22.4s, v0.s[2]
	sqrdmulh	v14.4s, v24.4s, v0.s[2]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v13.4s, v13.4s, v21.4s
	sub	v14.4s, v14.4s, v23.4s
	sshr	v13.4s, v13.4s, #1
	sshr	v14.4s, v14.4s, #1
	sub	v22.4s, v7.4s, v15.4s
	sub	v24.4s, v8.4s, v16.4s
	add	v7.4s, v7.4s, v15.4s
	add	v8.4s, v8.4s, v16.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v15.4s, v22.4s, v0.s[2]
	sqrdmulh	v16.4s, v24.4s, v0.s[2]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v15.4s, v15.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v15.4s, v15.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v9.4s, v17.4s
	sub	v24.4s, v10.4s, v18.4s
	add	v9.4s, v9.4s, v17.4s
	add	v10.4s, v10.4s, v18.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v17.4s, v22.4s, v0.s[2]
	sqrdmulh	v18.4s, v24.4s, v0.s[2]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v17.4s, v17.4s, v21.4s
	sub	v18.4s, v18.4s, v23.4s
	sshr	v17.4s, v17.4s, #1
	sshr	v18.4s, v18.4s, #1
	sub	v22.4s, v11.4s, v19.4s
	sub	v24.4s, v12.4s, v20.4s
	add	v11.4s, v11.4s, v19.4s
	add	v12.4s, v12.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v19.4s, v22.4s, v0.s[2]
	sqrdmulh	v20.4s, v24.4s, v0.s[2]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v19.4s, v19.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	mul	v21.4s, v5.4s, v2.s[3]
	mul	v22.4s, v6.4s, v2.s[3]
	sqrdmulh	v5.4s, v5.4s, v0.s[3]
	sqrdmulh	v6.4s, v6.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v22.4s, v22.4s, v4.s[0]
	sub	v5.4s, v5.4s, v21.4s
	sub	v6.4s, v6.4s, v22.4s
	sshr	v5.4s, v5.4s, #1
	sshr	v6.4s, v6.4s, #1
	mul	v21.4s, v7.4s, v2.s[3]
	mul	v22.4s, v8.4s, v2.s[3]
	sqrdmulh	v7.4s, v7.4s, v0.s[3]
	sqrdmulh	v8.4s, v8.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v22.4s, v22.4s, v4.s[0]
	sub	v7.4s, v7.4s, v21.4s
	sub	v8.4s, v8.4s, v22.4s
	sshr	v7.4s, v7.4s, #1
	sshr	v8.4s, v8.4s, #1
	mul	v21.4s, v9.4s, v2.s[3]
	mul	v22.4s, v10.4s, v2.s[3]
	sqrdmulh	v9.4s, v9.4s, v0.s[3]
	sqrdmulh	v10.4s, v10.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v22.4s, v22.4s, v4.s[0]
	sub	v9.4s, v9.4s, v21.4s
	sub	v10.4s, v10.4s, v22.4s
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	mul	v21.4s, v11.4s, v2.s[3]
	mul	v22.4s, v12.4s, v2.s[3]
	sqrdmulh	v11.4s, v11.4s, v0.s[3]
	sqrdmulh	v12.4s, v12.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v22.4s, v22.4s, v4.s[0]
	sub	v11.4s, v11.4s, v21.4s
	sub	v12.4s, v12.4s, v22.4s
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	str	q5, [x0, #32]
	str	q6, [x0, #96]
	str	q7, [x0, #160]
	str	q8, [x0, #224]
	str	q9, [x0, #288]
	str	q10, [x0, #352]
	str	q11, [x0, #416]
	str	q12, [x0, #480]
	str	q13, [x0, #544]
	str	q14, [x0, #608]
	str	q15, [x0, #672]
	str	q16, [x0, #736]
	str	q17, [x0, #800]
	str	q18, [x0, #864]
	str	q19, [x0, #928]
	str	q20, [x0, #992]
	ldr	q5, [x0, #48]
	ldr	q6, [x0, #112]
	ldr	q7, [x0, #176]
	ldr	q8, [x0, #240]
	ldr	q9, [x0, #304]
	ldr	q10, [x0, #368]
	ldr	q11, [x0, #432]
	ldr	q12, [x0, #496]
	ldr	q13, [x0, #560]
	ldr	q14, [x0, #624]
	ldr	q15, [x0, #688]
	ldr	q16, [x0, #752]
	ldr	q17, [x0, #816]
	ldr	q18, [x0, #880]
	ldr	q19, [x0, #944]
	ldr	q20, [x0, #1008]
	ldr	q0, [x1, #1216]
	ldr	q1, [x1, #1232]
	ldr	q2, [x2, #1216]
	ldr	q3, [x2, #1232]
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v6.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v6.4s, v6.4s, v21.4s
	sub	v8.4s, v8.4s, v23.4s
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v10.4s, v22.4s, v0.s[2]
	sqrdmulh	v12.4s, v24.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v10.4s, v10.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v3.s[0]
	mul	v23.4s, v24.4s, v3.s[1]
	sqrdmulh	v14.4s, v22.4s, v1.s[0]
	sqrdmulh	v16.4s, v24.4s, v1.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v14.4s, v14.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v3.s[2]
	mul	v23.4s, v24.4s, v3.s[3]
	sqrdmulh	v18.4s, v22.4s, v1.s[2]
	sqrdmulh	v20.4s, v24.4s, v1.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v18.4s, v18.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1248]
	ldr	q2, [x2, #1248]
	sub	v22.4s, v5.4s, v7.4s
	sub	v24.4s, v6.4s, v8.4s
	add	v5.4s, v5.4s, v7.4s
	add	v6.4s, v6.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v7.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[0]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v7.4s, v7.4s, v21.4s
	sub	v8.4s, v8.4s, v23.4s
	sshr	v7.4s, v7.4s, #1
	sshr	v8.4s, v8.4s, #1
	sub	v22.4s, v9.4s, v11.4s
	sub	v24.4s, v10.4s, v12.4s
	add	v9.4s, v9.4s, v11.4s
	add	v10.4s, v10.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v11.4s, v22.4s, v0.s[1]
	sqrdmulh	v12.4s, v24.4s, v0.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v11.4s, v11.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v15.4s
	sub	v24.4s, v14.4s, v16.4s
	add	v13.4s, v13.4s, v15.4s
	add	v14.4s, v14.4s, v16.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v15.4s, v22.4s, v0.s[2]
	sqrdmulh	v16.4s, v24.4s, v0.s[2]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v15.4s, v15.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v15.4s, v15.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v17.4s, v19.4s
	sub	v24.4s, v18.4s, v20.4s
	add	v17.4s, v17.4s, v19.4s
	add	v18.4s, v18.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[3]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v19.4s, v22.4s, v0.s[3]
	sqrdmulh	v20.4s, v24.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v19.4s, v19.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1264]
	ldr	q2, [x2, #1264]
	sub	v22.4s, v5.4s, v9.4s
	sub	v24.4s, v6.4s, v10.4s
	add	v5.4s, v5.4s, v9.4s
	add	v6.4s, v6.4s, v10.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v9.4s, v22.4s, v0.s[0]
	sqrdmulh	v10.4s, v24.4s, v0.s[0]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v9.4s, v9.4s, v21.4s
	sub	v10.4s, v10.4s, v23.4s
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	sub	v22.4s, v7.4s, v11.4s
	sub	v24.4s, v8.4s, v12.4s
	add	v7.4s, v7.4s, v11.4s
	add	v8.4s, v8.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v11.4s, v22.4s, v0.s[0]
	sqrdmulh	v12.4s, v24.4s, v0.s[0]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v11.4s, v11.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v17.4s
	sub	v24.4s, v14.4s, v18.4s
	add	v13.4s, v13.4s, v17.4s
	add	v14.4s, v14.4s, v18.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v17.4s, v22.4s, v0.s[1]
	sqrdmulh	v18.4s, v24.4s, v0.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v17.4s, v17.4s, v21.4s
	sub	v18.4s, v18.4s, v23.4s
	sshr	v17.4s, v17.4s, #1
	sshr	v18.4s, v18.4s, #1
	sub	v22.4s, v15.4s, v19.4s
	sub	v24.4s, v16.4s, v20.4s
	add	v15.4s, v15.4s, v19.4s
	add	v16.4s, v16.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v19.4s, v22.4s, v0.s[1]
	sqrdmulh	v20.4s, v24.4s, v0.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v19.4s, v19.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	sub	v22.4s, v5.4s, v13.4s
	sub	v24.4s, v6.4s, v14.4s
	add	v5.4s, v5.4s, v13.4s
	add	v6.4s, v6.4s, v14.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v13.4s, v22.4s, v0.s[2]
	sqrdmulh	v14.4s, v24.4s, v0.s[2]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v13.4s, v13.4s, v21.4s
	sub	v14.4s, v14.4s, v23.4s
	sshr	v13.4s, v13.4s, #1
	sshr	v14.4s, v14.4s, #1
	sub	v22.4s, v7.4s, v15.4s
	sub	v24.4s, v8.4s, v16.4s
	add	v7.4s, v7.4s, v15.4s
	add	v8.4s, v8.4s, v16.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v15.4s, v22.4s, v0.s[2]
	sqrdmulh	v16.4s, v24.4s, v0.s[2]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v15.4s, v15.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v15.4s, v15.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v9.4s, v17.4s
	sub	v24.4s, v10.4s, v18.4s
	add	v9.4s, v9.4s, v17.4s
	add	v10.4s, v10.4s, v18.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v17.4s, v22.4s, v0.s[2]
	sqrdmulh	v18.4s, v24.4s, v0.s[2]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v17.4s, v17.4s, v21.4s
	sub	v18.4s, v18.4s, v23.4s
	sshr	v17.4s, v17.4s, #1
	sshr	v18.4s, v18.4s, #1
	sub	v22.4s, v11.4s, v19.4s
	sub	v24.4s, v12.4s, v20.4s
	add	v11.4s, v11.4s, v19.4s
	add	v12.4s, v12.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v19.4s, v22.4s, v0.s[2]
	sqrdmulh	v20.4s, v24.4s, v0.s[2]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v19.4s, v19.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	mul	v21.4s, v5.4s, v2.s[3]
	mul	v22.4s, v6.4s, v2.s[3]
	sqrdmulh	v5.4s, v5.4s, v0.s[3]
	sqrdmulh	v6.4s, v6.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v22.4s, v22.4s, v4.s[0]
	sub	v5.4s, v5.4s, v21.4s
	sub	v6.4s, v6.4s, v22.4s
	sshr	v5.4s, v5.4s, #1
	sshr	v6.4s, v6.4s, #1
	mul	v21.4s, v7.4s, v2.s[3]
	mul	v22.4s, v8.4s, v2.s[3]
	sqrdmulh	v7.4s, v7.4s, v0.s[3]
	sqrdmulh	v8.4s, v8.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v22.4s, v22.4s, v4.s[0]
	sub	v7.4s, v7.4s, v21.4s
	sub	v8.4s, v8.4s, v22.4s
	sshr	v7.4s, v7.4s, #1
	sshr	v8.4s, v8.4s, #1
	mul	v21.4s, v9.4s, v2.s[3]
	mul	v22.4s, v10.4s, v2.s[3]
	sqrdmulh	v9.4s, v9.4s, v0.s[3]
	sqrdmulh	v10.4s, v10.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v22.4s, v22.4s, v4.s[0]
	sub	v9.4s, v9.4s, v21.4s
	sub	v10.4s, v10.4s, v22.4s
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	mul	v21.4s, v11.4s, v2.s[3]
	mul	v22.4s, v12.4s, v2.s[3]
	sqrdmulh	v11.4s, v11.4s, v0.s[3]
	sqrdmulh	v12.4s, v12.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v22.4s, v22.4s, v4.s[0]
	sub	v11.4s, v11.4s, v21.4s
	sub	v12.4s, v12.4s, v22.4s
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	str	q5, [x0, #48]
	str	q6, [x0, #112]
	str	q7, [x0, #176]
	str	q8, [x0, #240]
	str	q9, [x0, #304]
	str	q10, [x0, #368]
	str	q11, [x0, #432]
	str	q12, [x0, #496]
	str	q13, [x0, #560]
	str	q14, [x0, #624]
	str	q15, [x0, #688]
	str	q16, [x0, #752]
	str	q17, [x0, #816]
	str	q18, [x0, #880]
	str	q19, [x0, #944]
	str	q20, [x0, #1008]
	ldp	d8, d9, [x29, #16]
	ldp	d10, d11, [x29, #32]
	ldp	d12, d13, [x29, #48]
	ldp	d14, d15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
#ifndef __APPLE__
	.size	mldsa_invntt_neon,.-mldsa_invntt_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	mldsa_invntt_full_neon
WC_ASM_ATT_HIDDEN(mldsa_invntt_full_neon)
.type	mldsa_invntt_full_neon,@function
.align	2
mldsa_invntt_full_neon:
#else
.section	__TEXT,__text
.globl	_mldsa_invntt_full_neon
WC_ASM_ATT_HIDDEN(_mldsa_invntt_full_neon)
.p2align	2
_mldsa_invntt_full_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
	stp	d12, d13, [x29, #48]
	stp	d14, d15, [x29, #64]
#ifndef __APPLE__
	adrp x1, L_mldsa_aarch64_zetas_inv
	add  x1, x1, :lo12:L_mldsa_aarch64_zetas_inv
#else
	adrp x1, L_mldsa_aarch64_zetas_inv@PAGE
	add  x1, x1, L_mldsa_aarch64_zetas_inv@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x2, L_mldsa_aarch64_zetas_inv_qinv
	add  x2, x2, :lo12:L_mldsa_aarch64_zetas_inv_qinv
#else
	adrp x2, L_mldsa_aarch64_zetas_inv_qinv@PAGE
	add  x2, x2, L_mldsa_aarch64_zetas_inv_qinv@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x3, L_mldsa_aarch64_consts
	add  x3, x3, :lo12:L_mldsa_aarch64_consts
#else
	adrp x3, L_mldsa_aarch64_consts@PAGE
	add  x3, x3, L_mldsa_aarch64_consts@PAGEOFF
#endif /* __APPLE__ */
	ldr	q4, [x3]
	ldp	q5, q6, [x0]
	ldp	q7, q8, [x0, #32]
	ldp	q9, q10, [x0, #64]
	ldp	q11, q12, [x0, #96]
	ldp	q13, q14, [x0, #128]
	ldp	q15, q16, [x0, #160]
	ldp	q17, q18, [x0, #192]
	ldp	q19, q20, [x0, #224]
	trn1	v21.2d, v5.2d, v6.2d
	trn2	v22.2d, v5.2d, v6.2d
	trn1	v5.4s, v21.4s, v22.4s
	trn2	v6.4s, v21.4s, v22.4s
	trn1	v21.2d, v7.2d, v8.2d
	trn2	v22.2d, v7.2d, v8.2d
	trn1	v7.4s, v21.4s, v22.4s
	trn2	v8.4s, v21.4s, v22.4s
	trn1	v21.2d, v9.2d, v10.2d
	trn2	v22.2d, v9.2d, v10.2d
	trn1	v9.4s, v21.4s, v22.4s
	trn2	v10.4s, v21.4s, v22.4s
	trn1	v21.2d, v11.2d, v12.2d
	trn2	v22.2d, v11.2d, v12.2d
	trn1	v11.4s, v21.4s, v22.4s
	trn2	v12.4s, v21.4s, v22.4s
	trn1	v21.2d, v13.2d, v14.2d
	trn2	v22.2d, v13.2d, v14.2d
	trn1	v13.4s, v21.4s, v22.4s
	trn2	v14.4s, v21.4s, v22.4s
	trn1	v21.2d, v15.2d, v16.2d
	trn2	v22.2d, v15.2d, v16.2d
	trn1	v15.4s, v21.4s, v22.4s
	trn2	v16.4s, v21.4s, v22.4s
	trn1	v21.2d, v17.2d, v18.2d
	trn2	v22.2d, v17.2d, v18.2d
	trn1	v17.4s, v21.4s, v22.4s
	trn2	v18.4s, v21.4s, v22.4s
	trn1	v21.2d, v19.2d, v20.2d
	trn2	v22.2d, v19.2d, v20.2d
	trn1	v19.4s, v21.4s, v22.4s
	trn2	v20.4s, v21.4s, v22.4s
	ldp	q0, q1, [x1]
	ldp	q2, q3, [x2]
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v6.4s, v22.4s, v0.4s
	sqrdmulh	v8.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v6.4s, v6.4s, v21.4s
	sub	v8.4s, v8.4s, v23.4s
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	ldp	q0, q1, [x1, #32]
	ldp	q2, q3, [x2, #32]
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v10.4s, v22.4s, v0.4s
	sqrdmulh	v12.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v10.4s, v10.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	ldp	q0, q1, [x1, #64]
	ldp	q2, q3, [x2, #64]
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v14.4s, v22.4s, v0.4s
	sqrdmulh	v16.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v14.4s, v14.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	ldp	q0, q1, [x1, #96]
	ldp	q2, q3, [x2, #96]
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v18.4s, v22.4s, v0.4s
	sqrdmulh	v20.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v18.4s, v18.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldp	q0, q1, [x1, #512]
	ldp	q2, q3, [x2, #512]
	mov	v21.16b, v5.16b
	mov	v22.16b, v7.16b
	trn1	v5.4s, v5.4s, v6.4s
	trn1	v7.4s, v7.4s, v8.4s
	trn2	v6.4s, v21.4s, v6.4s
	trn2	v8.4s, v22.4s, v8.4s
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v6.4s, v22.4s, v0.4s
	sqrdmulh	v8.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v6.4s, v6.4s, v21.4s
	sub	v8.4s, v8.4s, v23.4s
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	ldp	q0, q1, [x1, #544]
	ldp	q2, q3, [x2, #544]
	mov	v21.16b, v9.16b
	mov	v22.16b, v11.16b
	trn1	v9.4s, v9.4s, v10.4s
	trn1	v11.4s, v11.4s, v12.4s
	trn2	v10.4s, v21.4s, v10.4s
	trn2	v12.4s, v22.4s, v12.4s
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v10.4s, v22.4s, v0.4s
	sqrdmulh	v12.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v10.4s, v10.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	ldp	q0, q1, [x1, #576]
	ldp	q2, q3, [x2, #576]
	mov	v21.16b, v13.16b
	mov	v22.16b, v15.16b
	trn1	v13.4s, v13.4s, v14.4s
	trn1	v15.4s, v15.4s, v16.4s
	trn2	v14.4s, v21.4s, v14.4s
	trn2	v16.4s, v22.4s, v16.4s
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v14.4s, v22.4s, v0.4s
	sqrdmulh	v16.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v14.4s, v14.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	ldp	q0, q1, [x1, #608]
	ldp	q2, q3, [x2, #608]
	mov	v21.16b, v17.16b
	mov	v22.16b, v19.16b
	trn1	v17.4s, v17.4s, v18.4s
	trn1	v19.4s, v19.4s, v20.4s
	trn2	v18.4s, v21.4s, v18.4s
	trn2	v20.4s, v22.4s, v20.4s
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v18.4s, v22.4s, v0.4s
	sqrdmulh	v20.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v18.4s, v18.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1024]
	ldr	q1, [x1, #1040]
	ldr	q2, [x2, #1024]
	ldr	q3, [x2, #1040]
	mov	v21.16b, v5.16b
	mov	v22.16b, v7.16b
	trn1	v5.2d, v5.2d, v6.2d
	trn1	v7.2d, v7.2d, v8.2d
	trn2	v6.2d, v21.2d, v6.2d
	trn2	v8.2d, v22.2d, v8.2d
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v6.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v6.4s, v6.4s, v21.4s
	sub	v8.4s, v8.4s, v23.4s
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	mov	v21.16b, v9.16b
	mov	v22.16b, v11.16b
	trn1	v9.2d, v9.2d, v10.2d
	trn1	v11.2d, v11.2d, v12.2d
	trn2	v10.2d, v21.2d, v10.2d
	trn2	v12.2d, v22.2d, v12.2d
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v10.4s, v22.4s, v0.s[2]
	sqrdmulh	v12.4s, v24.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v10.4s, v10.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	mov	v21.16b, v13.16b
	mov	v22.16b, v15.16b
	trn1	v13.2d, v13.2d, v14.2d
	trn1	v15.2d, v15.2d, v16.2d
	trn2	v14.2d, v21.2d, v14.2d
	trn2	v16.2d, v22.2d, v16.2d
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v3.s[0]
	mul	v23.4s, v24.4s, v3.s[1]
	sqrdmulh	v14.4s, v22.4s, v1.s[0]
	sqrdmulh	v16.4s, v24.4s, v1.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v14.4s, v14.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	mov	v21.16b, v17.16b
	mov	v22.16b, v19.16b
	trn1	v17.2d, v17.2d, v18.2d
	trn1	v19.2d, v19.2d, v20.2d
	trn2	v18.2d, v21.2d, v18.2d
	trn2	v20.2d, v22.2d, v20.2d
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v3.s[2]
	mul	v23.4s, v24.4s, v3.s[3]
	sqrdmulh	v18.4s, v22.4s, v1.s[2]
	sqrdmulh	v20.4s, v24.4s, v1.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v18.4s, v18.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1152]
	ldr	q2, [x2, #1152]
	sub	v22.4s, v5.4s, v7.4s
	sub	v24.4s, v6.4s, v8.4s
	add	v5.4s, v5.4s, v7.4s
	add	v6.4s, v6.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v7.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[0]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v7.4s, v7.4s, v21.4s
	sub	v8.4s, v8.4s, v23.4s
	sshr	v7.4s, v7.4s, #1
	sshr	v8.4s, v8.4s, #1
	sub	v22.4s, v9.4s, v11.4s
	sub	v24.4s, v10.4s, v12.4s
	add	v9.4s, v9.4s, v11.4s
	add	v10.4s, v10.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v11.4s, v22.4s, v0.s[1]
	sqrdmulh	v12.4s, v24.4s, v0.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v11.4s, v11.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v15.4s
	sub	v24.4s, v14.4s, v16.4s
	add	v13.4s, v13.4s, v15.4s
	add	v14.4s, v14.4s, v16.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v15.4s, v22.4s, v0.s[2]
	sqrdmulh	v16.4s, v24.4s, v0.s[2]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v15.4s, v15.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v15.4s, v15.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v17.4s, v19.4s
	sub	v24.4s, v18.4s, v20.4s
	add	v17.4s, v17.4s, v19.4s
	add	v18.4s, v18.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[3]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v19.4s, v22.4s, v0.s[3]
	sqrdmulh	v20.4s, v24.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v19.4s, v19.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	stp	q5, q6, [x0]
	stp	q7, q8, [x0, #32]
	stp	q9, q10, [x0, #64]
	stp	q11, q12, [x0, #96]
	stp	q13, q14, [x0, #128]
	stp	q15, q16, [x0, #160]
	stp	q17, q18, [x0, #192]
	stp	q19, q20, [x0, #224]
	ldp	q5, q6, [x0, #256]
	ldp	q7, q8, [x0, #288]
	ldp	q9, q10, [x0, #320]
	ldp	q11, q12, [x0, #352]
	ldp	q13, q14, [x0, #384]
	ldp	q15, q16, [x0, #416]
	ldp	q17, q18, [x0, #448]
	ldp	q19, q20, [x0, #480]
	trn1	v21.2d, v5.2d, v6.2d
	trn2	v22.2d, v5.2d, v6.2d
	trn1	v5.4s, v21.4s, v22.4s
	trn2	v6.4s, v21.4s, v22.4s
	trn1	v21.2d, v7.2d, v8.2d
	trn2	v22.2d, v7.2d, v8.2d
	trn1	v7.4s, v21.4s, v22.4s
	trn2	v8.4s, v21.4s, v22.4s
	trn1	v21.2d, v9.2d, v10.2d
	trn2	v22.2d, v9.2d, v10.2d
	trn1	v9.4s, v21.4s, v22.4s
	trn2	v10.4s, v21.4s, v22.4s
	trn1	v21.2d, v11.2d, v12.2d
	trn2	v22.2d, v11.2d, v12.2d
	trn1	v11.4s, v21.4s, v22.4s
	trn2	v12.4s, v21.4s, v22.4s
	trn1	v21.2d, v13.2d, v14.2d
	trn2	v22.2d, v13.2d, v14.2d
	trn1	v13.4s, v21.4s, v22.4s
	trn2	v14.4s, v21.4s, v22.4s
	trn1	v21.2d, v15.2d, v16.2d
	trn2	v22.2d, v15.2d, v16.2d
	trn1	v15.4s, v21.4s, v22.4s
	trn2	v16.4s, v21.4s, v22.4s
	trn1	v21.2d, v17.2d, v18.2d
	trn2	v22.2d, v17.2d, v18.2d
	trn1	v17.4s, v21.4s, v22.4s
	trn2	v18.4s, v21.4s, v22.4s
	trn1	v21.2d, v19.2d, v20.2d
	trn2	v22.2d, v19.2d, v20.2d
	trn1	v19.4s, v21.4s, v22.4s
	trn2	v20.4s, v21.4s, v22.4s
	ldp	q0, q1, [x1, #128]
	ldp	q2, q3, [x2, #128]
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v6.4s, v22.4s, v0.4s
	sqrdmulh	v8.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v6.4s, v6.4s, v21.4s
	sub	v8.4s, v8.4s, v23.4s
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	ldp	q0, q1, [x1, #160]
	ldp	q2, q3, [x2, #160]
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v10.4s, v22.4s, v0.4s
	sqrdmulh	v12.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v10.4s, v10.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	ldp	q0, q1, [x1, #192]
	ldp	q2, q3, [x2, #192]
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v14.4s, v22.4s, v0.4s
	sqrdmulh	v16.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v14.4s, v14.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	ldp	q0, q1, [x1, #224]
	ldp	q2, q3, [x2, #224]
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v18.4s, v22.4s, v0.4s
	sqrdmulh	v20.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v18.4s, v18.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldp	q0, q1, [x1, #640]
	ldp	q2, q3, [x2, #640]
	mov	v21.16b, v5.16b
	mov	v22.16b, v7.16b
	trn1	v5.4s, v5.4s, v6.4s
	trn1	v7.4s, v7.4s, v8.4s
	trn2	v6.4s, v21.4s, v6.4s
	trn2	v8.4s, v22.4s, v8.4s
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v6.4s, v22.4s, v0.4s
	sqrdmulh	v8.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v6.4s, v6.4s, v21.4s
	sub	v8.4s, v8.4s, v23.4s
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	ldp	q0, q1, [x1, #672]
	ldp	q2, q3, [x2, #672]
	mov	v21.16b, v9.16b
	mov	v22.16b, v11.16b
	trn1	v9.4s, v9.4s, v10.4s
	trn1	v11.4s, v11.4s, v12.4s
	trn2	v10.4s, v21.4s, v10.4s
	trn2	v12.4s, v22.4s, v12.4s
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v10.4s, v22.4s, v0.4s
	sqrdmulh	v12.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v10.4s, v10.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	ldp	q0, q1, [x1, #704]
	ldp	q2, q3, [x2, #704]
	mov	v21.16b, v13.16b
	mov	v22.16b, v15.16b
	trn1	v13.4s, v13.4s, v14.4s
	trn1	v15.4s, v15.4s, v16.4s
	trn2	v14.4s, v21.4s, v14.4s
	trn2	v16.4s, v22.4s, v16.4s
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v14.4s, v22.4s, v0.4s
	sqrdmulh	v16.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v14.4s, v14.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	ldp	q0, q1, [x1, #736]
	ldp	q2, q3, [x2, #736]
	mov	v21.16b, v17.16b
	mov	v22.16b, v19.16b
	trn1	v17.4s, v17.4s, v18.4s
	trn1	v19.4s, v19.4s, v20.4s
	trn2	v18.4s, v21.4s, v18.4s
	trn2	v20.4s, v22.4s, v20.4s
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v18.4s, v22.4s, v0.4s
	sqrdmulh	v20.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v18.4s, v18.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1056]
	ldr	q1, [x1, #1072]
	ldr	q2, [x2, #1056]
	ldr	q3, [x2, #1072]
	mov	v21.16b, v5.16b
	mov	v22.16b, v7.16b
	trn1	v5.2d, v5.2d, v6.2d
	trn1	v7.2d, v7.2d, v8.2d
	trn2	v6.2d, v21.2d, v6.2d
	trn2	v8.2d, v22.2d, v8.2d
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v6.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v6.4s, v6.4s, v21.4s
	sub	v8.4s, v8.4s, v23.4s
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	mov	v21.16b, v9.16b
	mov	v22.16b, v11.16b
	trn1	v9.2d, v9.2d, v10.2d
	trn1	v11.2d, v11.2d, v12.2d
	trn2	v10.2d, v21.2d, v10.2d
	trn2	v12.2d, v22.2d, v12.2d
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v10.4s, v22.4s, v0.s[2]
	sqrdmulh	v12.4s, v24.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v10.4s, v10.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	mov	v21.16b, v13.16b
	mov	v22.16b, v15.16b
	trn1	v13.2d, v13.2d, v14.2d
	trn1	v15.2d, v15.2d, v16.2d
	trn2	v14.2d, v21.2d, v14.2d
	trn2	v16.2d, v22.2d, v16.2d
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v3.s[0]
	mul	v23.4s, v24.4s, v3.s[1]
	sqrdmulh	v14.4s, v22.4s, v1.s[0]
	sqrdmulh	v16.4s, v24.4s, v1.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v14.4s, v14.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	mov	v21.16b, v17.16b
	mov	v22.16b, v19.16b
	trn1	v17.2d, v17.2d, v18.2d
	trn1	v19.2d, v19.2d, v20.2d
	trn2	v18.2d, v21.2d, v18.2d
	trn2	v20.2d, v22.2d, v20.2d
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v3.s[2]
	mul	v23.4s, v24.4s, v3.s[3]
	sqrdmulh	v18.4s, v22.4s, v1.s[2]
	sqrdmulh	v20.4s, v24.4s, v1.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v18.4s, v18.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1168]
	ldr	q2, [x2, #1168]
	sub	v22.4s, v5.4s, v7.4s
	sub	v24.4s, v6.4s, v8.4s
	add	v5.4s, v5.4s, v7.4s
	add	v6.4s, v6.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v7.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[0]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v7.4s, v7.4s, v21.4s
	sub	v8.4s, v8.4s, v23.4s
	sshr	v7.4s, v7.4s, #1
	sshr	v8.4s, v8.4s, #1
	sub	v22.4s, v9.4s, v11.4s
	sub	v24.4s, v10.4s, v12.4s
	add	v9.4s, v9.4s, v11.4s
	add	v10.4s, v10.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v11.4s, v22.4s, v0.s[1]
	sqrdmulh	v12.4s, v24.4s, v0.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v11.4s, v11.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v15.4s
	sub	v24.4s, v14.4s, v16.4s
	add	v13.4s, v13.4s, v15.4s
	add	v14.4s, v14.4s, v16.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v15.4s, v22.4s, v0.s[2]
	sqrdmulh	v16.4s, v24.4s, v0.s[2]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v15.4s, v15.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v15.4s, v15.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v17.4s, v19.4s
	sub	v24.4s, v18.4s, v20.4s
	add	v17.4s, v17.4s, v19.4s
	add	v18.4s, v18.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[3]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v19.4s, v22.4s, v0.s[3]
	sqrdmulh	v20.4s, v24.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v19.4s, v19.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	stp	q5, q6, [x0, #256]
	stp	q7, q8, [x0, #288]
	stp	q9, q10, [x0, #320]
	stp	q11, q12, [x0, #352]
	stp	q13, q14, [x0, #384]
	stp	q15, q16, [x0, #416]
	stp	q17, q18, [x0, #448]
	stp	q19, q20, [x0, #480]
	ldp	q5, q6, [x0, #512]
	ldp	q7, q8, [x0, #544]
	ldp	q9, q10, [x0, #576]
	ldp	q11, q12, [x0, #608]
	ldp	q13, q14, [x0, #640]
	ldp	q15, q16, [x0, #672]
	ldp	q17, q18, [x0, #704]
	ldp	q19, q20, [x0, #736]
	trn1	v21.2d, v5.2d, v6.2d
	trn2	v22.2d, v5.2d, v6.2d
	trn1	v5.4s, v21.4s, v22.4s
	trn2	v6.4s, v21.4s, v22.4s
	trn1	v21.2d, v7.2d, v8.2d
	trn2	v22.2d, v7.2d, v8.2d
	trn1	v7.4s, v21.4s, v22.4s
	trn2	v8.4s, v21.4s, v22.4s
	trn1	v21.2d, v9.2d, v10.2d
	trn2	v22.2d, v9.2d, v10.2d
	trn1	v9.4s, v21.4s, v22.4s
	trn2	v10.4s, v21.4s, v22.4s
	trn1	v21.2d, v11.2d, v12.2d
	trn2	v22.2d, v11.2d, v12.2d
	trn1	v11.4s, v21.4s, v22.4s
	trn2	v12.4s, v21.4s, v22.4s
	trn1	v21.2d, v13.2d, v14.2d
	trn2	v22.2d, v13.2d, v14.2d
	trn1	v13.4s, v21.4s, v22.4s
	trn2	v14.4s, v21.4s, v22.4s
	trn1	v21.2d, v15.2d, v16.2d
	trn2	v22.2d, v15.2d, v16.2d
	trn1	v15.4s, v21.4s, v22.4s
	trn2	v16.4s, v21.4s, v22.4s
	trn1	v21.2d, v17.2d, v18.2d
	trn2	v22.2d, v17.2d, v18.2d
	trn1	v17.4s, v21.4s, v22.4s
	trn2	v18.4s, v21.4s, v22.4s
	trn1	v21.2d, v19.2d, v20.2d
	trn2	v22.2d, v19.2d, v20.2d
	trn1	v19.4s, v21.4s, v22.4s
	trn2	v20.4s, v21.4s, v22.4s
	ldp	q0, q1, [x1, #256]
	ldp	q2, q3, [x2, #256]
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v6.4s, v22.4s, v0.4s
	sqrdmulh	v8.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v6.4s, v6.4s, v21.4s
	sub	v8.4s, v8.4s, v23.4s
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	ldp	q0, q1, [x1, #288]
	ldp	q2, q3, [x2, #288]
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v10.4s, v22.4s, v0.4s
	sqrdmulh	v12.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v10.4s, v10.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	ldp	q0, q1, [x1, #320]
	ldp	q2, q3, [x2, #320]
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v14.4s, v22.4s, v0.4s
	sqrdmulh	v16.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v14.4s, v14.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	ldp	q0, q1, [x1, #352]
	ldp	q2, q3, [x2, #352]
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v18.4s, v22.4s, v0.4s
	sqrdmulh	v20.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v18.4s, v18.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldp	q0, q1, [x1, #768]
	ldp	q2, q3, [x2, #768]
	mov	v21.16b, v5.16b
	mov	v22.16b, v7.16b
	trn1	v5.4s, v5.4s, v6.4s
	trn1	v7.4s, v7.4s, v8.4s
	trn2	v6.4s, v21.4s, v6.4s
	trn2	v8.4s, v22.4s, v8.4s
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v6.4s, v22.4s, v0.4s
	sqrdmulh	v8.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v6.4s, v6.4s, v21.4s
	sub	v8.4s, v8.4s, v23.4s
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	ldp	q0, q1, [x1, #800]
	ldp	q2, q3, [x2, #800]
	mov	v21.16b, v9.16b
	mov	v22.16b, v11.16b
	trn1	v9.4s, v9.4s, v10.4s
	trn1	v11.4s, v11.4s, v12.4s
	trn2	v10.4s, v21.4s, v10.4s
	trn2	v12.4s, v22.4s, v12.4s
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v10.4s, v22.4s, v0.4s
	sqrdmulh	v12.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v10.4s, v10.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	ldp	q0, q1, [x1, #832]
	ldp	q2, q3, [x2, #832]
	mov	v21.16b, v13.16b
	mov	v22.16b, v15.16b
	trn1	v13.4s, v13.4s, v14.4s
	trn1	v15.4s, v15.4s, v16.4s
	trn2	v14.4s, v21.4s, v14.4s
	trn2	v16.4s, v22.4s, v16.4s
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v14.4s, v22.4s, v0.4s
	sqrdmulh	v16.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v14.4s, v14.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	ldp	q0, q1, [x1, #864]
	ldp	q2, q3, [x2, #864]
	mov	v21.16b, v17.16b
	mov	v22.16b, v19.16b
	trn1	v17.4s, v17.4s, v18.4s
	trn1	v19.4s, v19.4s, v20.4s
	trn2	v18.4s, v21.4s, v18.4s
	trn2	v20.4s, v22.4s, v20.4s
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v18.4s, v22.4s, v0.4s
	sqrdmulh	v20.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v18.4s, v18.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1088]
	ldr	q1, [x1, #1104]
	ldr	q2, [x2, #1088]
	ldr	q3, [x2, #1104]
	mov	v21.16b, v5.16b
	mov	v22.16b, v7.16b
	trn1	v5.2d, v5.2d, v6.2d
	trn1	v7.2d, v7.2d, v8.2d
	trn2	v6.2d, v21.2d, v6.2d
	trn2	v8.2d, v22.2d, v8.2d
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v6.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v6.4s, v6.4s, v21.4s
	sub	v8.4s, v8.4s, v23.4s
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	mov	v21.16b, v9.16b
	mov	v22.16b, v11.16b
	trn1	v9.2d, v9.2d, v10.2d
	trn1	v11.2d, v11.2d, v12.2d
	trn2	v10.2d, v21.2d, v10.2d
	trn2	v12.2d, v22.2d, v12.2d
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v10.4s, v22.4s, v0.s[2]
	sqrdmulh	v12.4s, v24.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v10.4s, v10.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	mov	v21.16b, v13.16b
	mov	v22.16b, v15.16b
	trn1	v13.2d, v13.2d, v14.2d
	trn1	v15.2d, v15.2d, v16.2d
	trn2	v14.2d, v21.2d, v14.2d
	trn2	v16.2d, v22.2d, v16.2d
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v3.s[0]
	mul	v23.4s, v24.4s, v3.s[1]
	sqrdmulh	v14.4s, v22.4s, v1.s[0]
	sqrdmulh	v16.4s, v24.4s, v1.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v14.4s, v14.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	mov	v21.16b, v17.16b
	mov	v22.16b, v19.16b
	trn1	v17.2d, v17.2d, v18.2d
	trn1	v19.2d, v19.2d, v20.2d
	trn2	v18.2d, v21.2d, v18.2d
	trn2	v20.2d, v22.2d, v20.2d
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v3.s[2]
	mul	v23.4s, v24.4s, v3.s[3]
	sqrdmulh	v18.4s, v22.4s, v1.s[2]
	sqrdmulh	v20.4s, v24.4s, v1.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v18.4s, v18.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1184]
	ldr	q2, [x2, #1184]
	sub	v22.4s, v5.4s, v7.4s
	sub	v24.4s, v6.4s, v8.4s
	add	v5.4s, v5.4s, v7.4s
	add	v6.4s, v6.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v7.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[0]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v7.4s, v7.4s, v21.4s
	sub	v8.4s, v8.4s, v23.4s
	sshr	v7.4s, v7.4s, #1
	sshr	v8.4s, v8.4s, #1
	sub	v22.4s, v9.4s, v11.4s
	sub	v24.4s, v10.4s, v12.4s
	add	v9.4s, v9.4s, v11.4s
	add	v10.4s, v10.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v11.4s, v22.4s, v0.s[1]
	sqrdmulh	v12.4s, v24.4s, v0.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v11.4s, v11.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v15.4s
	sub	v24.4s, v14.4s, v16.4s
	add	v13.4s, v13.4s, v15.4s
	add	v14.4s, v14.4s, v16.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v15.4s, v22.4s, v0.s[2]
	sqrdmulh	v16.4s, v24.4s, v0.s[2]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v15.4s, v15.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v15.4s, v15.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v17.4s, v19.4s
	sub	v24.4s, v18.4s, v20.4s
	add	v17.4s, v17.4s, v19.4s
	add	v18.4s, v18.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[3]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v19.4s, v22.4s, v0.s[3]
	sqrdmulh	v20.4s, v24.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v19.4s, v19.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	stp	q5, q6, [x0, #512]
	stp	q7, q8, [x0, #544]
	stp	q9, q10, [x0, #576]
	stp	q11, q12, [x0, #608]
	stp	q13, q14, [x0, #640]
	stp	q15, q16, [x0, #672]
	stp	q17, q18, [x0, #704]
	stp	q19, q20, [x0, #736]
	ldp	q5, q6, [x0, #768]
	ldp	q7, q8, [x0, #800]
	ldp	q9, q10, [x0, #832]
	ldp	q11, q12, [x0, #864]
	ldp	q13, q14, [x0, #896]
	ldp	q15, q16, [x0, #928]
	ldp	q17, q18, [x0, #960]
	ldp	q19, q20, [x0, #992]
	trn1	v21.2d, v5.2d, v6.2d
	trn2	v22.2d, v5.2d, v6.2d
	trn1	v5.4s, v21.4s, v22.4s
	trn2	v6.4s, v21.4s, v22.4s
	trn1	v21.2d, v7.2d, v8.2d
	trn2	v22.2d, v7.2d, v8.2d
	trn1	v7.4s, v21.4s, v22.4s
	trn2	v8.4s, v21.4s, v22.4s
	trn1	v21.2d, v9.2d, v10.2d
	trn2	v22.2d, v9.2d, v10.2d
	trn1	v9.4s, v21.4s, v22.4s
	trn2	v10.4s, v21.4s, v22.4s
	trn1	v21.2d, v11.2d, v12.2d
	trn2	v22.2d, v11.2d, v12.2d
	trn1	v11.4s, v21.4s, v22.4s
	trn2	v12.4s, v21.4s, v22.4s
	trn1	v21.2d, v13.2d, v14.2d
	trn2	v22.2d, v13.2d, v14.2d
	trn1	v13.4s, v21.4s, v22.4s
	trn2	v14.4s, v21.4s, v22.4s
	trn1	v21.2d, v15.2d, v16.2d
	trn2	v22.2d, v15.2d, v16.2d
	trn1	v15.4s, v21.4s, v22.4s
	trn2	v16.4s, v21.4s, v22.4s
	trn1	v21.2d, v17.2d, v18.2d
	trn2	v22.2d, v17.2d, v18.2d
	trn1	v17.4s, v21.4s, v22.4s
	trn2	v18.4s, v21.4s, v22.4s
	trn1	v21.2d, v19.2d, v20.2d
	trn2	v22.2d, v19.2d, v20.2d
	trn1	v19.4s, v21.4s, v22.4s
	trn2	v20.4s, v21.4s, v22.4s
	ldp	q0, q1, [x1, #384]
	ldp	q2, q3, [x2, #384]
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v6.4s, v22.4s, v0.4s
	sqrdmulh	v8.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v6.4s, v6.4s, v21.4s
	sub	v8.4s, v8.4s, v23.4s
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	ldp	q0, q1, [x1, #416]
	ldp	q2, q3, [x2, #416]
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v10.4s, v22.4s, v0.4s
	sqrdmulh	v12.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v10.4s, v10.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	ldp	q0, q1, [x1, #448]
	ldp	q2, q3, [x2, #448]
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v14.4s, v22.4s, v0.4s
	sqrdmulh	v16.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v14.4s, v14.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	ldp	q0, q1, [x1, #480]
	ldp	q2, q3, [x2, #480]
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v18.4s, v22.4s, v0.4s
	sqrdmulh	v20.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v18.4s, v18.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldp	q0, q1, [x1, #896]
	ldp	q2, q3, [x2, #896]
	mov	v21.16b, v5.16b
	mov	v22.16b, v7.16b
	trn1	v5.4s, v5.4s, v6.4s
	trn1	v7.4s, v7.4s, v8.4s
	trn2	v6.4s, v21.4s, v6.4s
	trn2	v8.4s, v22.4s, v8.4s
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v6.4s, v22.4s, v0.4s
	sqrdmulh	v8.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v6.4s, v6.4s, v21.4s
	sub	v8.4s, v8.4s, v23.4s
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	ldp	q0, q1, [x1, #928]
	ldp	q2, q3, [x2, #928]
	mov	v21.16b, v9.16b
	mov	v22.16b, v11.16b
	trn1	v9.4s, v9.4s, v10.4s
	trn1	v11.4s, v11.4s, v12.4s
	trn2	v10.4s, v21.4s, v10.4s
	trn2	v12.4s, v22.4s, v12.4s
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v10.4s, v22.4s, v0.4s
	sqrdmulh	v12.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v10.4s, v10.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	ldp	q0, q1, [x1, #960]
	ldp	q2, q3, [x2, #960]
	mov	v21.16b, v13.16b
	mov	v22.16b, v15.16b
	trn1	v13.4s, v13.4s, v14.4s
	trn1	v15.4s, v15.4s, v16.4s
	trn2	v14.4s, v21.4s, v14.4s
	trn2	v16.4s, v22.4s, v16.4s
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v14.4s, v22.4s, v0.4s
	sqrdmulh	v16.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v14.4s, v14.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	ldp	q0, q1, [x1, #992]
	ldp	q2, q3, [x2, #992]
	mov	v21.16b, v17.16b
	mov	v22.16b, v19.16b
	trn1	v17.4s, v17.4s, v18.4s
	trn1	v19.4s, v19.4s, v20.4s
	trn2	v18.4s, v21.4s, v18.4s
	trn2	v20.4s, v22.4s, v20.4s
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v18.4s, v22.4s, v0.4s
	sqrdmulh	v20.4s, v24.4s, v1.4s
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v18.4s, v18.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1120]
	ldr	q1, [x1, #1136]
	ldr	q2, [x2, #1120]
	ldr	q3, [x2, #1136]
	mov	v21.16b, v5.16b
	mov	v22.16b, v7.16b
	trn1	v5.2d, v5.2d, v6.2d
	trn1	v7.2d, v7.2d, v8.2d
	trn2	v6.2d, v21.2d, v6.2d
	trn2	v8.2d, v22.2d, v8.2d
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v6.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v6.4s, v6.4s, v21.4s
	sub	v8.4s, v8.4s, v23.4s
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	mov	v21.16b, v9.16b
	mov	v22.16b, v11.16b
	trn1	v9.2d, v9.2d, v10.2d
	trn1	v11.2d, v11.2d, v12.2d
	trn2	v10.2d, v21.2d, v10.2d
	trn2	v12.2d, v22.2d, v12.2d
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v10.4s, v22.4s, v0.s[2]
	sqrdmulh	v12.4s, v24.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v10.4s, v10.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	mov	v21.16b, v13.16b
	mov	v22.16b, v15.16b
	trn1	v13.2d, v13.2d, v14.2d
	trn1	v15.2d, v15.2d, v16.2d
	trn2	v14.2d, v21.2d, v14.2d
	trn2	v16.2d, v22.2d, v16.2d
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v3.s[0]
	mul	v23.4s, v24.4s, v3.s[1]
	sqrdmulh	v14.4s, v22.4s, v1.s[0]
	sqrdmulh	v16.4s, v24.4s, v1.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v14.4s, v14.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	mov	v21.16b, v17.16b
	mov	v22.16b, v19.16b
	trn1	v17.2d, v17.2d, v18.2d
	trn1	v19.2d, v19.2d, v20.2d
	trn2	v18.2d, v21.2d, v18.2d
	trn2	v20.2d, v22.2d, v20.2d
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v3.s[2]
	mul	v23.4s, v24.4s, v3.s[3]
	sqrdmulh	v18.4s, v22.4s, v1.s[2]
	sqrdmulh	v20.4s, v24.4s, v1.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v18.4s, v18.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1200]
	ldr	q2, [x2, #1200]
	sub	v22.4s, v5.4s, v7.4s
	sub	v24.4s, v6.4s, v8.4s
	add	v5.4s, v5.4s, v7.4s
	add	v6.4s, v6.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v7.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[0]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v7.4s, v7.4s, v21.4s
	sub	v8.4s, v8.4s, v23.4s
	sshr	v7.4s, v7.4s, #1
	sshr	v8.4s, v8.4s, #1
	sub	v22.4s, v9.4s, v11.4s
	sub	v24.4s, v10.4s, v12.4s
	add	v9.4s, v9.4s, v11.4s
	add	v10.4s, v10.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v11.4s, v22.4s, v0.s[1]
	sqrdmulh	v12.4s, v24.4s, v0.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v11.4s, v11.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v15.4s
	sub	v24.4s, v14.4s, v16.4s
	add	v13.4s, v13.4s, v15.4s
	add	v14.4s, v14.4s, v16.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v15.4s, v22.4s, v0.s[2]
	sqrdmulh	v16.4s, v24.4s, v0.s[2]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v15.4s, v15.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v15.4s, v15.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v17.4s, v19.4s
	sub	v24.4s, v18.4s, v20.4s
	add	v17.4s, v17.4s, v19.4s
	add	v18.4s, v18.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[3]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v19.4s, v22.4s, v0.s[3]
	sqrdmulh	v20.4s, v24.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v19.4s, v19.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	stp	q5, q6, [x0, #768]
	stp	q7, q8, [x0, #800]
	stp	q9, q10, [x0, #832]
	stp	q11, q12, [x0, #864]
	stp	q13, q14, [x0, #896]
	stp	q15, q16, [x0, #928]
	stp	q17, q18, [x0, #960]
	stp	q19, q20, [x0, #992]
	ldr	q5, [x0]
	ldr	q6, [x0, #64]
	ldr	q7, [x0, #128]
	ldr	q8, [x0, #192]
	ldr	q9, [x0, #256]
	ldr	q10, [x0, #320]
	ldr	q11, [x0, #384]
	ldr	q12, [x0, #448]
	ldr	q13, [x0, #512]
	ldr	q14, [x0, #576]
	ldr	q15, [x0, #640]
	ldr	q16, [x0, #704]
	ldr	q17, [x0, #768]
	ldr	q18, [x0, #832]
	ldr	q19, [x0, #896]
	ldr	q20, [x0, #960]
	ldr	q0, [x1, #1216]
	ldr	q1, [x1, #1232]
	ldr	q2, [x2, #1216]
	ldr	q3, [x2, #1232]
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v6.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v6.4s, v6.4s, v21.4s
	sub	v8.4s, v8.4s, v23.4s
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v10.4s, v22.4s, v0.s[2]
	sqrdmulh	v12.4s, v24.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v10.4s, v10.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v3.s[0]
	mul	v23.4s, v24.4s, v3.s[1]
	sqrdmulh	v14.4s, v22.4s, v1.s[0]
	sqrdmulh	v16.4s, v24.4s, v1.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v14.4s, v14.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v3.s[2]
	mul	v23.4s, v24.4s, v3.s[3]
	sqrdmulh	v18.4s, v22.4s, v1.s[2]
	sqrdmulh	v20.4s, v24.4s, v1.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v18.4s, v18.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1248]
	ldr	q2, [x2, #1248]
	sub	v22.4s, v5.4s, v7.4s
	sub	v24.4s, v6.4s, v8.4s
	add	v5.4s, v5.4s, v7.4s
	add	v6.4s, v6.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v7.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[0]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v7.4s, v7.4s, v21.4s
	sub	v8.4s, v8.4s, v23.4s
	sshr	v7.4s, v7.4s, #1
	sshr	v8.4s, v8.4s, #1
	sub	v22.4s, v9.4s, v11.4s
	sub	v24.4s, v10.4s, v12.4s
	add	v9.4s, v9.4s, v11.4s
	add	v10.4s, v10.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v11.4s, v22.4s, v0.s[1]
	sqrdmulh	v12.4s, v24.4s, v0.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v11.4s, v11.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v15.4s
	sub	v24.4s, v14.4s, v16.4s
	add	v13.4s, v13.4s, v15.4s
	add	v14.4s, v14.4s, v16.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v15.4s, v22.4s, v0.s[2]
	sqrdmulh	v16.4s, v24.4s, v0.s[2]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v15.4s, v15.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v15.4s, v15.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v17.4s, v19.4s
	sub	v24.4s, v18.4s, v20.4s
	add	v17.4s, v17.4s, v19.4s
	add	v18.4s, v18.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[3]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v19.4s, v22.4s, v0.s[3]
	sqrdmulh	v20.4s, v24.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v19.4s, v19.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1264]
	ldr	q2, [x2, #1264]
	sub	v22.4s, v5.4s, v9.4s
	sub	v24.4s, v6.4s, v10.4s
	add	v5.4s, v5.4s, v9.4s
	add	v6.4s, v6.4s, v10.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v9.4s, v22.4s, v0.s[0]
	sqrdmulh	v10.4s, v24.4s, v0.s[0]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v9.4s, v9.4s, v21.4s
	sub	v10.4s, v10.4s, v23.4s
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	sub	v22.4s, v7.4s, v11.4s
	sub	v24.4s, v8.4s, v12.4s
	add	v7.4s, v7.4s, v11.4s
	add	v8.4s, v8.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v11.4s, v22.4s, v0.s[0]
	sqrdmulh	v12.4s, v24.4s, v0.s[0]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v11.4s, v11.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v17.4s
	sub	v24.4s, v14.4s, v18.4s
	add	v13.4s, v13.4s, v17.4s
	add	v14.4s, v14.4s, v18.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v17.4s, v22.4s, v0.s[1]
	sqrdmulh	v18.4s, v24.4s, v0.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v17.4s, v17.4s, v21.4s
	sub	v18.4s, v18.4s, v23.4s
	sshr	v17.4s, v17.4s, #1
	sshr	v18.4s, v18.4s, #1
	sub	v22.4s, v15.4s, v19.4s
	sub	v24.4s, v16.4s, v20.4s
	add	v15.4s, v15.4s, v19.4s
	add	v16.4s, v16.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v19.4s, v22.4s, v0.s[1]
	sqrdmulh	v20.4s, v24.4s, v0.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v19.4s, v19.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	sub	v22.4s, v5.4s, v13.4s
	sub	v24.4s, v6.4s, v14.4s
	add	v5.4s, v5.4s, v13.4s
	add	v6.4s, v6.4s, v14.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v13.4s, v22.4s, v0.s[2]
	sqrdmulh	v14.4s, v24.4s, v0.s[2]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v13.4s, v13.4s, v21.4s
	sub	v14.4s, v14.4s, v23.4s
	sshr	v13.4s, v13.4s, #1
	sshr	v14.4s, v14.4s, #1
	sub	v22.4s, v7.4s, v15.4s
	sub	v24.4s, v8.4s, v16.4s
	add	v7.4s, v7.4s, v15.4s
	add	v8.4s, v8.4s, v16.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v15.4s, v22.4s, v0.s[2]
	sqrdmulh	v16.4s, v24.4s, v0.s[2]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v15.4s, v15.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v15.4s, v15.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v9.4s, v17.4s
	sub	v24.4s, v10.4s, v18.4s
	add	v9.4s, v9.4s, v17.4s
	add	v10.4s, v10.4s, v18.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v17.4s, v22.4s, v0.s[2]
	sqrdmulh	v18.4s, v24.4s, v0.s[2]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v17.4s, v17.4s, v21.4s
	sub	v18.4s, v18.4s, v23.4s
	sshr	v17.4s, v17.4s, #1
	sshr	v18.4s, v18.4s, #1
	sub	v22.4s, v11.4s, v19.4s
	sub	v24.4s, v12.4s, v20.4s
	add	v11.4s, v11.4s, v19.4s
	add	v12.4s, v12.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v19.4s, v22.4s, v0.s[2]
	sqrdmulh	v20.4s, v24.4s, v0.s[2]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v19.4s, v19.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	mul	v21.4s, v5.4s, v2.s[3]
	mul	v22.4s, v6.4s, v2.s[3]
	sqrdmulh	v5.4s, v5.4s, v0.s[3]
	sqrdmulh	v6.4s, v6.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v22.4s, v22.4s, v4.s[0]
	sub	v5.4s, v5.4s, v21.4s
	sub	v6.4s, v6.4s, v22.4s
	sshr	v5.4s, v5.4s, #1
	sshr	v6.4s, v6.4s, #1
	mul	v21.4s, v7.4s, v2.s[3]
	mul	v22.4s, v8.4s, v2.s[3]
	sqrdmulh	v7.4s, v7.4s, v0.s[3]
	sqrdmulh	v8.4s, v8.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v22.4s, v22.4s, v4.s[0]
	sub	v7.4s, v7.4s, v21.4s
	sub	v8.4s, v8.4s, v22.4s
	sshr	v7.4s, v7.4s, #1
	sshr	v8.4s, v8.4s, #1
	mul	v21.4s, v9.4s, v2.s[3]
	mul	v22.4s, v10.4s, v2.s[3]
	sqrdmulh	v9.4s, v9.4s, v0.s[3]
	sqrdmulh	v10.4s, v10.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v22.4s, v22.4s, v4.s[0]
	sub	v9.4s, v9.4s, v21.4s
	sub	v10.4s, v10.4s, v22.4s
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	mul	v21.4s, v11.4s, v2.s[3]
	mul	v22.4s, v12.4s, v2.s[3]
	sqrdmulh	v11.4s, v11.4s, v0.s[3]
	sqrdmulh	v12.4s, v12.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v22.4s, v22.4s, v4.s[0]
	sub	v11.4s, v11.4s, v21.4s
	sub	v12.4s, v12.4s, v22.4s
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	str	q5, [x0]
	str	q6, [x0, #64]
	str	q7, [x0, #128]
	str	q8, [x0, #192]
	str	q9, [x0, #256]
	str	q10, [x0, #320]
	str	q11, [x0, #384]
	str	q12, [x0, #448]
	str	q13, [x0, #512]
	str	q14, [x0, #576]
	str	q15, [x0, #640]
	str	q16, [x0, #704]
	str	q17, [x0, #768]
	str	q18, [x0, #832]
	str	q19, [x0, #896]
	str	q20, [x0, #960]
	ldr	q5, [x0, #16]
	ldr	q6, [x0, #80]
	ldr	q7, [x0, #144]
	ldr	q8, [x0, #208]
	ldr	q9, [x0, #272]
	ldr	q10, [x0, #336]
	ldr	q11, [x0, #400]
	ldr	q12, [x0, #464]
	ldr	q13, [x0, #528]
	ldr	q14, [x0, #592]
	ldr	q15, [x0, #656]
	ldr	q16, [x0, #720]
	ldr	q17, [x0, #784]
	ldr	q18, [x0, #848]
	ldr	q19, [x0, #912]
	ldr	q20, [x0, #976]
	ldr	q0, [x1, #1216]
	ldr	q1, [x1, #1232]
	ldr	q2, [x2, #1216]
	ldr	q3, [x2, #1232]
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v6.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v6.4s, v6.4s, v21.4s
	sub	v8.4s, v8.4s, v23.4s
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v10.4s, v22.4s, v0.s[2]
	sqrdmulh	v12.4s, v24.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v10.4s, v10.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v3.s[0]
	mul	v23.4s, v24.4s, v3.s[1]
	sqrdmulh	v14.4s, v22.4s, v1.s[0]
	sqrdmulh	v16.4s, v24.4s, v1.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v14.4s, v14.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v3.s[2]
	mul	v23.4s, v24.4s, v3.s[3]
	sqrdmulh	v18.4s, v22.4s, v1.s[2]
	sqrdmulh	v20.4s, v24.4s, v1.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v18.4s, v18.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1248]
	ldr	q2, [x2, #1248]
	sub	v22.4s, v5.4s, v7.4s
	sub	v24.4s, v6.4s, v8.4s
	add	v5.4s, v5.4s, v7.4s
	add	v6.4s, v6.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v7.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[0]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v7.4s, v7.4s, v21.4s
	sub	v8.4s, v8.4s, v23.4s
	sshr	v7.4s, v7.4s, #1
	sshr	v8.4s, v8.4s, #1
	sub	v22.4s, v9.4s, v11.4s
	sub	v24.4s, v10.4s, v12.4s
	add	v9.4s, v9.4s, v11.4s
	add	v10.4s, v10.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v11.4s, v22.4s, v0.s[1]
	sqrdmulh	v12.4s, v24.4s, v0.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v11.4s, v11.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v15.4s
	sub	v24.4s, v14.4s, v16.4s
	add	v13.4s, v13.4s, v15.4s
	add	v14.4s, v14.4s, v16.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v15.4s, v22.4s, v0.s[2]
	sqrdmulh	v16.4s, v24.4s, v0.s[2]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v15.4s, v15.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v15.4s, v15.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v17.4s, v19.4s
	sub	v24.4s, v18.4s, v20.4s
	add	v17.4s, v17.4s, v19.4s
	add	v18.4s, v18.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[3]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v19.4s, v22.4s, v0.s[3]
	sqrdmulh	v20.4s, v24.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v19.4s, v19.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1264]
	ldr	q2, [x2, #1264]
	sub	v22.4s, v5.4s, v9.4s
	sub	v24.4s, v6.4s, v10.4s
	add	v5.4s, v5.4s, v9.4s
	add	v6.4s, v6.4s, v10.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v9.4s, v22.4s, v0.s[0]
	sqrdmulh	v10.4s, v24.4s, v0.s[0]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v9.4s, v9.4s, v21.4s
	sub	v10.4s, v10.4s, v23.4s
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	sub	v22.4s, v7.4s, v11.4s
	sub	v24.4s, v8.4s, v12.4s
	add	v7.4s, v7.4s, v11.4s
	add	v8.4s, v8.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v11.4s, v22.4s, v0.s[0]
	sqrdmulh	v12.4s, v24.4s, v0.s[0]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v11.4s, v11.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v17.4s
	sub	v24.4s, v14.4s, v18.4s
	add	v13.4s, v13.4s, v17.4s
	add	v14.4s, v14.4s, v18.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v17.4s, v22.4s, v0.s[1]
	sqrdmulh	v18.4s, v24.4s, v0.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v17.4s, v17.4s, v21.4s
	sub	v18.4s, v18.4s, v23.4s
	sshr	v17.4s, v17.4s, #1
	sshr	v18.4s, v18.4s, #1
	sub	v22.4s, v15.4s, v19.4s
	sub	v24.4s, v16.4s, v20.4s
	add	v15.4s, v15.4s, v19.4s
	add	v16.4s, v16.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v19.4s, v22.4s, v0.s[1]
	sqrdmulh	v20.4s, v24.4s, v0.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v19.4s, v19.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	sub	v22.4s, v5.4s, v13.4s
	sub	v24.4s, v6.4s, v14.4s
	add	v5.4s, v5.4s, v13.4s
	add	v6.4s, v6.4s, v14.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v13.4s, v22.4s, v0.s[2]
	sqrdmulh	v14.4s, v24.4s, v0.s[2]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v13.4s, v13.4s, v21.4s
	sub	v14.4s, v14.4s, v23.4s
	sshr	v13.4s, v13.4s, #1
	sshr	v14.4s, v14.4s, #1
	sub	v22.4s, v7.4s, v15.4s
	sub	v24.4s, v8.4s, v16.4s
	add	v7.4s, v7.4s, v15.4s
	add	v8.4s, v8.4s, v16.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v15.4s, v22.4s, v0.s[2]
	sqrdmulh	v16.4s, v24.4s, v0.s[2]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v15.4s, v15.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v15.4s, v15.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v9.4s, v17.4s
	sub	v24.4s, v10.4s, v18.4s
	add	v9.4s, v9.4s, v17.4s
	add	v10.4s, v10.4s, v18.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v17.4s, v22.4s, v0.s[2]
	sqrdmulh	v18.4s, v24.4s, v0.s[2]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v17.4s, v17.4s, v21.4s
	sub	v18.4s, v18.4s, v23.4s
	sshr	v17.4s, v17.4s, #1
	sshr	v18.4s, v18.4s, #1
	sub	v22.4s, v11.4s, v19.4s
	sub	v24.4s, v12.4s, v20.4s
	add	v11.4s, v11.4s, v19.4s
	add	v12.4s, v12.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v19.4s, v22.4s, v0.s[2]
	sqrdmulh	v20.4s, v24.4s, v0.s[2]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v19.4s, v19.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	mul	v21.4s, v5.4s, v2.s[3]
	mul	v22.4s, v6.4s, v2.s[3]
	sqrdmulh	v5.4s, v5.4s, v0.s[3]
	sqrdmulh	v6.4s, v6.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v22.4s, v22.4s, v4.s[0]
	sub	v5.4s, v5.4s, v21.4s
	sub	v6.4s, v6.4s, v22.4s
	sshr	v5.4s, v5.4s, #1
	sshr	v6.4s, v6.4s, #1
	mul	v21.4s, v7.4s, v2.s[3]
	mul	v22.4s, v8.4s, v2.s[3]
	sqrdmulh	v7.4s, v7.4s, v0.s[3]
	sqrdmulh	v8.4s, v8.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v22.4s, v22.4s, v4.s[0]
	sub	v7.4s, v7.4s, v21.4s
	sub	v8.4s, v8.4s, v22.4s
	sshr	v7.4s, v7.4s, #1
	sshr	v8.4s, v8.4s, #1
	mul	v21.4s, v9.4s, v2.s[3]
	mul	v22.4s, v10.4s, v2.s[3]
	sqrdmulh	v9.4s, v9.4s, v0.s[3]
	sqrdmulh	v10.4s, v10.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v22.4s, v22.4s, v4.s[0]
	sub	v9.4s, v9.4s, v21.4s
	sub	v10.4s, v10.4s, v22.4s
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	mul	v21.4s, v11.4s, v2.s[3]
	mul	v22.4s, v12.4s, v2.s[3]
	sqrdmulh	v11.4s, v11.4s, v0.s[3]
	sqrdmulh	v12.4s, v12.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v22.4s, v22.4s, v4.s[0]
	sub	v11.4s, v11.4s, v21.4s
	sub	v12.4s, v12.4s, v22.4s
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	str	q5, [x0, #16]
	str	q6, [x0, #80]
	str	q7, [x0, #144]
	str	q8, [x0, #208]
	str	q9, [x0, #272]
	str	q10, [x0, #336]
	str	q11, [x0, #400]
	str	q12, [x0, #464]
	str	q13, [x0, #528]
	str	q14, [x0, #592]
	str	q15, [x0, #656]
	str	q16, [x0, #720]
	str	q17, [x0, #784]
	str	q18, [x0, #848]
	str	q19, [x0, #912]
	str	q20, [x0, #976]
	ldr	q5, [x0, #32]
	ldr	q6, [x0, #96]
	ldr	q7, [x0, #160]
	ldr	q8, [x0, #224]
	ldr	q9, [x0, #288]
	ldr	q10, [x0, #352]
	ldr	q11, [x0, #416]
	ldr	q12, [x0, #480]
	ldr	q13, [x0, #544]
	ldr	q14, [x0, #608]
	ldr	q15, [x0, #672]
	ldr	q16, [x0, #736]
	ldr	q17, [x0, #800]
	ldr	q18, [x0, #864]
	ldr	q19, [x0, #928]
	ldr	q20, [x0, #992]
	ldr	q0, [x1, #1216]
	ldr	q1, [x1, #1232]
	ldr	q2, [x2, #1216]
	ldr	q3, [x2, #1232]
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v6.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v6.4s, v6.4s, v21.4s
	sub	v8.4s, v8.4s, v23.4s
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v10.4s, v22.4s, v0.s[2]
	sqrdmulh	v12.4s, v24.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v10.4s, v10.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v3.s[0]
	mul	v23.4s, v24.4s, v3.s[1]
	sqrdmulh	v14.4s, v22.4s, v1.s[0]
	sqrdmulh	v16.4s, v24.4s, v1.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v14.4s, v14.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v3.s[2]
	mul	v23.4s, v24.4s, v3.s[3]
	sqrdmulh	v18.4s, v22.4s, v1.s[2]
	sqrdmulh	v20.4s, v24.4s, v1.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v18.4s, v18.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1248]
	ldr	q2, [x2, #1248]
	sub	v22.4s, v5.4s, v7.4s
	sub	v24.4s, v6.4s, v8.4s
	add	v5.4s, v5.4s, v7.4s
	add	v6.4s, v6.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v7.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[0]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v7.4s, v7.4s, v21.4s
	sub	v8.4s, v8.4s, v23.4s
	sshr	v7.4s, v7.4s, #1
	sshr	v8.4s, v8.4s, #1
	sub	v22.4s, v9.4s, v11.4s
	sub	v24.4s, v10.4s, v12.4s
	add	v9.4s, v9.4s, v11.4s
	add	v10.4s, v10.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v11.4s, v22.4s, v0.s[1]
	sqrdmulh	v12.4s, v24.4s, v0.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v11.4s, v11.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v15.4s
	sub	v24.4s, v14.4s, v16.4s
	add	v13.4s, v13.4s, v15.4s
	add	v14.4s, v14.4s, v16.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v15.4s, v22.4s, v0.s[2]
	sqrdmulh	v16.4s, v24.4s, v0.s[2]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v15.4s, v15.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v15.4s, v15.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v17.4s, v19.4s
	sub	v24.4s, v18.4s, v20.4s
	add	v17.4s, v17.4s, v19.4s
	add	v18.4s, v18.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[3]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v19.4s, v22.4s, v0.s[3]
	sqrdmulh	v20.4s, v24.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v19.4s, v19.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1264]
	ldr	q2, [x2, #1264]
	sub	v22.4s, v5.4s, v9.4s
	sub	v24.4s, v6.4s, v10.4s
	add	v5.4s, v5.4s, v9.4s
	add	v6.4s, v6.4s, v10.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v9.4s, v22.4s, v0.s[0]
	sqrdmulh	v10.4s, v24.4s, v0.s[0]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v9.4s, v9.4s, v21.4s
	sub	v10.4s, v10.4s, v23.4s
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	sub	v22.4s, v7.4s, v11.4s
	sub	v24.4s, v8.4s, v12.4s
	add	v7.4s, v7.4s, v11.4s
	add	v8.4s, v8.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v11.4s, v22.4s, v0.s[0]
	sqrdmulh	v12.4s, v24.4s, v0.s[0]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v11.4s, v11.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v17.4s
	sub	v24.4s, v14.4s, v18.4s
	add	v13.4s, v13.4s, v17.4s
	add	v14.4s, v14.4s, v18.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v17.4s, v22.4s, v0.s[1]
	sqrdmulh	v18.4s, v24.4s, v0.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v17.4s, v17.4s, v21.4s
	sub	v18.4s, v18.4s, v23.4s
	sshr	v17.4s, v17.4s, #1
	sshr	v18.4s, v18.4s, #1
	sub	v22.4s, v15.4s, v19.4s
	sub	v24.4s, v16.4s, v20.4s
	add	v15.4s, v15.4s, v19.4s
	add	v16.4s, v16.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v19.4s, v22.4s, v0.s[1]
	sqrdmulh	v20.4s, v24.4s, v0.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v19.4s, v19.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	sub	v22.4s, v5.4s, v13.4s
	sub	v24.4s, v6.4s, v14.4s
	add	v5.4s, v5.4s, v13.4s
	add	v6.4s, v6.4s, v14.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v13.4s, v22.4s, v0.s[2]
	sqrdmulh	v14.4s, v24.4s, v0.s[2]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v13.4s, v13.4s, v21.4s
	sub	v14.4s, v14.4s, v23.4s
	sshr	v13.4s, v13.4s, #1
	sshr	v14.4s, v14.4s, #1
	sub	v22.4s, v7.4s, v15.4s
	sub	v24.4s, v8.4s, v16.4s
	add	v7.4s, v7.4s, v15.4s
	add	v8.4s, v8.4s, v16.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v15.4s, v22.4s, v0.s[2]
	sqrdmulh	v16.4s, v24.4s, v0.s[2]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v15.4s, v15.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v15.4s, v15.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v9.4s, v17.4s
	sub	v24.4s, v10.4s, v18.4s
	add	v9.4s, v9.4s, v17.4s
	add	v10.4s, v10.4s, v18.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v17.4s, v22.4s, v0.s[2]
	sqrdmulh	v18.4s, v24.4s, v0.s[2]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v17.4s, v17.4s, v21.4s
	sub	v18.4s, v18.4s, v23.4s
	sshr	v17.4s, v17.4s, #1
	sshr	v18.4s, v18.4s, #1
	sub	v22.4s, v11.4s, v19.4s
	sub	v24.4s, v12.4s, v20.4s
	add	v11.4s, v11.4s, v19.4s
	add	v12.4s, v12.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v19.4s, v22.4s, v0.s[2]
	sqrdmulh	v20.4s, v24.4s, v0.s[2]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v19.4s, v19.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	mul	v21.4s, v5.4s, v2.s[3]
	mul	v22.4s, v6.4s, v2.s[3]
	sqrdmulh	v5.4s, v5.4s, v0.s[3]
	sqrdmulh	v6.4s, v6.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v22.4s, v22.4s, v4.s[0]
	sub	v5.4s, v5.4s, v21.4s
	sub	v6.4s, v6.4s, v22.4s
	sshr	v5.4s, v5.4s, #1
	sshr	v6.4s, v6.4s, #1
	mul	v21.4s, v7.4s, v2.s[3]
	mul	v22.4s, v8.4s, v2.s[3]
	sqrdmulh	v7.4s, v7.4s, v0.s[3]
	sqrdmulh	v8.4s, v8.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v22.4s, v22.4s, v4.s[0]
	sub	v7.4s, v7.4s, v21.4s
	sub	v8.4s, v8.4s, v22.4s
	sshr	v7.4s, v7.4s, #1
	sshr	v8.4s, v8.4s, #1
	mul	v21.4s, v9.4s, v2.s[3]
	mul	v22.4s, v10.4s, v2.s[3]
	sqrdmulh	v9.4s, v9.4s, v0.s[3]
	sqrdmulh	v10.4s, v10.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v22.4s, v22.4s, v4.s[0]
	sub	v9.4s, v9.4s, v21.4s
	sub	v10.4s, v10.4s, v22.4s
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	mul	v21.4s, v11.4s, v2.s[3]
	mul	v22.4s, v12.4s, v2.s[3]
	sqrdmulh	v11.4s, v11.4s, v0.s[3]
	sqrdmulh	v12.4s, v12.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v22.4s, v22.4s, v4.s[0]
	sub	v11.4s, v11.4s, v21.4s
	sub	v12.4s, v12.4s, v22.4s
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	str	q5, [x0, #32]
	str	q6, [x0, #96]
	str	q7, [x0, #160]
	str	q8, [x0, #224]
	str	q9, [x0, #288]
	str	q10, [x0, #352]
	str	q11, [x0, #416]
	str	q12, [x0, #480]
	str	q13, [x0, #544]
	str	q14, [x0, #608]
	str	q15, [x0, #672]
	str	q16, [x0, #736]
	str	q17, [x0, #800]
	str	q18, [x0, #864]
	str	q19, [x0, #928]
	str	q20, [x0, #992]
	ldr	q5, [x0, #48]
	ldr	q6, [x0, #112]
	ldr	q7, [x0, #176]
	ldr	q8, [x0, #240]
	ldr	q9, [x0, #304]
	ldr	q10, [x0, #368]
	ldr	q11, [x0, #432]
	ldr	q12, [x0, #496]
	ldr	q13, [x0, #560]
	ldr	q14, [x0, #624]
	ldr	q15, [x0, #688]
	ldr	q16, [x0, #752]
	ldr	q17, [x0, #816]
	ldr	q18, [x0, #880]
	ldr	q19, [x0, #944]
	ldr	q20, [x0, #1008]
	ldr	q0, [x1, #1216]
	ldr	q1, [x1, #1232]
	ldr	q2, [x2, #1216]
	ldr	q3, [x2, #1232]
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v6.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v6.4s, v6.4s, v21.4s
	sub	v8.4s, v8.4s, v23.4s
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v10.4s, v22.4s, v0.s[2]
	sqrdmulh	v12.4s, v24.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v10.4s, v10.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v3.s[0]
	mul	v23.4s, v24.4s, v3.s[1]
	sqrdmulh	v14.4s, v22.4s, v1.s[0]
	sqrdmulh	v16.4s, v24.4s, v1.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v14.4s, v14.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v3.s[2]
	mul	v23.4s, v24.4s, v3.s[3]
	sqrdmulh	v18.4s, v22.4s, v1.s[2]
	sqrdmulh	v20.4s, v24.4s, v1.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v18.4s, v18.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1248]
	ldr	q2, [x2, #1248]
	sub	v22.4s, v5.4s, v7.4s
	sub	v24.4s, v6.4s, v8.4s
	add	v5.4s, v5.4s, v7.4s
	add	v6.4s, v6.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v7.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[0]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v7.4s, v7.4s, v21.4s
	sub	v8.4s, v8.4s, v23.4s
	sshr	v7.4s, v7.4s, #1
	sshr	v8.4s, v8.4s, #1
	sub	v22.4s, v9.4s, v11.4s
	sub	v24.4s, v10.4s, v12.4s
	add	v9.4s, v9.4s, v11.4s
	add	v10.4s, v10.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v11.4s, v22.4s, v0.s[1]
	sqrdmulh	v12.4s, v24.4s, v0.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v11.4s, v11.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v15.4s
	sub	v24.4s, v14.4s, v16.4s
	add	v13.4s, v13.4s, v15.4s
	add	v14.4s, v14.4s, v16.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v15.4s, v22.4s, v0.s[2]
	sqrdmulh	v16.4s, v24.4s, v0.s[2]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v15.4s, v15.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v15.4s, v15.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v17.4s, v19.4s
	sub	v24.4s, v18.4s, v20.4s
	add	v17.4s, v17.4s, v19.4s
	add	v18.4s, v18.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[3]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v19.4s, v22.4s, v0.s[3]
	sqrdmulh	v20.4s, v24.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v19.4s, v19.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1264]
	ldr	q2, [x2, #1264]
	sub	v22.4s, v5.4s, v9.4s
	sub	v24.4s, v6.4s, v10.4s
	add	v5.4s, v5.4s, v9.4s
	add	v6.4s, v6.4s, v10.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v9.4s, v22.4s, v0.s[0]
	sqrdmulh	v10.4s, v24.4s, v0.s[0]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v9.4s, v9.4s, v21.4s
	sub	v10.4s, v10.4s, v23.4s
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	sub	v22.4s, v7.4s, v11.4s
	sub	v24.4s, v8.4s, v12.4s
	add	v7.4s, v7.4s, v11.4s
	add	v8.4s, v8.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v11.4s, v22.4s, v0.s[0]
	sqrdmulh	v12.4s, v24.4s, v0.s[0]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v11.4s, v11.4s, v21.4s
	sub	v12.4s, v12.4s, v23.4s
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v17.4s
	sub	v24.4s, v14.4s, v18.4s
	add	v13.4s, v13.4s, v17.4s
	add	v14.4s, v14.4s, v18.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v17.4s, v22.4s, v0.s[1]
	sqrdmulh	v18.4s, v24.4s, v0.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v17.4s, v17.4s, v21.4s
	sub	v18.4s, v18.4s, v23.4s
	sshr	v17.4s, v17.4s, #1
	sshr	v18.4s, v18.4s, #1
	sub	v22.4s, v15.4s, v19.4s
	sub	v24.4s, v16.4s, v20.4s
	add	v15.4s, v15.4s, v19.4s
	add	v16.4s, v16.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v19.4s, v22.4s, v0.s[1]
	sqrdmulh	v20.4s, v24.4s, v0.s[1]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v19.4s, v19.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	sub	v22.4s, v5.4s, v13.4s
	sub	v24.4s, v6.4s, v14.4s
	add	v5.4s, v5.4s, v13.4s
	add	v6.4s, v6.4s, v14.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v13.4s, v22.4s, v0.s[2]
	sqrdmulh	v14.4s, v24.4s, v0.s[2]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v13.4s, v13.4s, v21.4s
	sub	v14.4s, v14.4s, v23.4s
	sshr	v13.4s, v13.4s, #1
	sshr	v14.4s, v14.4s, #1
	sub	v22.4s, v7.4s, v15.4s
	sub	v24.4s, v8.4s, v16.4s
	add	v7.4s, v7.4s, v15.4s
	add	v8.4s, v8.4s, v16.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v15.4s, v22.4s, v0.s[2]
	sqrdmulh	v16.4s, v24.4s, v0.s[2]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v15.4s, v15.4s, v21.4s
	sub	v16.4s, v16.4s, v23.4s
	sshr	v15.4s, v15.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v9.4s, v17.4s
	sub	v24.4s, v10.4s, v18.4s
	add	v9.4s, v9.4s, v17.4s
	add	v10.4s, v10.4s, v18.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v17.4s, v22.4s, v0.s[2]
	sqrdmulh	v18.4s, v24.4s, v0.s[2]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v17.4s, v17.4s, v21.4s
	sub	v18.4s, v18.4s, v23.4s
	sshr	v17.4s, v17.4s, #1
	sshr	v18.4s, v18.4s, #1
	sub	v22.4s, v11.4s, v19.4s
	sub	v24.4s, v12.4s, v20.4s
	add	v11.4s, v11.4s, v19.4s
	add	v12.4s, v12.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v19.4s, v22.4s, v0.s[2]
	sqrdmulh	v20.4s, v24.4s, v0.s[2]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v23.4s, v23.4s, v4.s[0]
	sub	v19.4s, v19.4s, v21.4s
	sub	v20.4s, v20.4s, v23.4s
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	mul	v21.4s, v5.4s, v2.s[3]
	mul	v22.4s, v6.4s, v2.s[3]
	sqrdmulh	v5.4s, v5.4s, v0.s[3]
	sqrdmulh	v6.4s, v6.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v22.4s, v22.4s, v4.s[0]
	sub	v5.4s, v5.4s, v21.4s
	sub	v6.4s, v6.4s, v22.4s
	sshr	v5.4s, v5.4s, #1
	sshr	v6.4s, v6.4s, #1
	mul	v21.4s, v7.4s, v2.s[3]
	mul	v22.4s, v8.4s, v2.s[3]
	sqrdmulh	v7.4s, v7.4s, v0.s[3]
	sqrdmulh	v8.4s, v8.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v22.4s, v22.4s, v4.s[0]
	sub	v7.4s, v7.4s, v21.4s
	sub	v8.4s, v8.4s, v22.4s
	sshr	v7.4s, v7.4s, #1
	sshr	v8.4s, v8.4s, #1
	mul	v21.4s, v9.4s, v2.s[3]
	mul	v22.4s, v10.4s, v2.s[3]
	sqrdmulh	v9.4s, v9.4s, v0.s[3]
	sqrdmulh	v10.4s, v10.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v22.4s, v22.4s, v4.s[0]
	sub	v9.4s, v9.4s, v21.4s
	sub	v10.4s, v10.4s, v22.4s
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	mul	v21.4s, v11.4s, v2.s[3]
	mul	v22.4s, v12.4s, v2.s[3]
	sqrdmulh	v11.4s, v11.4s, v0.s[3]
	sqrdmulh	v12.4s, v12.4s, v0.s[3]
	sqrdmulh	v21.4s, v21.4s, v4.s[0]
	sqrdmulh	v22.4s, v22.4s, v4.s[0]
	sub	v11.4s, v11.4s, v21.4s
	sub	v12.4s, v12.4s, v22.4s
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	str	q5, [x0, #48]
	str	q6, [x0, #112]
	str	q7, [x0, #176]
	str	q8, [x0, #240]
	str	q9, [x0, #304]
	str	q10, [x0, #368]
	str	q11, [x0, #432]
	str	q12, [x0, #496]
	str	q13, [x0, #560]
	str	q14, [x0, #624]
	str	q15, [x0, #688]
	str	q16, [x0, #752]
	str	q17, [x0, #816]
	str	q18, [x0, #880]
	str	q19, [x0, #944]
	str	q20, [x0, #1008]
	ldp	d8, d9, [x29, #16]
	ldp	d10, d11, [x29, #32]
	ldp	d12, d13, [x29, #48]
	ldp	d14, d15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
#ifndef __APPLE__
	.size	mldsa_invntt_full_neon,.-mldsa_invntt_full_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	mldsa_mul_neon
WC_ASM_ATT_HIDDEN(mldsa_mul_neon)
.type	mldsa_mul_neon,@function
.align	2
mldsa_mul_neon:
#else
.section	__TEXT,__text
.globl	_mldsa_mul_neon
WC_ASM_ATT_HIDDEN(_mldsa_mul_neon)
.p2align	2
_mldsa_mul_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
	stp	d12, d13, [x29, #48]
	stp	d14, d15, [x29, #64]
#ifndef __APPLE__
	adrp x3, L_mldsa_aarch64_consts
	add  x3, x3, :lo12:L_mldsa_aarch64_consts
#else
	adrp x3, L_mldsa_aarch64_consts@PAGE
	add  x3, x3, L_mldsa_aarch64_consts@PAGEOFF
#endif /* __APPLE__ */
	ldr	q0, [x3]
	ldr	q1, [x1]
	ldr	q5, [x2]
	ldr	q2, [x1, #16]
	ldr	q6, [x2, #16]
	ldr	q3, [x1, #32]
	ldr	q7, [x2, #32]
	ldr	q4, [x1, #48]
	ldr	q8, [x2, #48]
	mul	v13.4s, v5.4s, v0.s[1]
	mul	v14.4s, v6.4s, v0.s[1]
	mul	v17.4s, v1.4s, v13.4s
	mul	v18.4s, v2.4s, v14.4s
	sqrdmulh	v9.4s, v1.4s, v5.4s
	sqrdmulh	v10.4s, v2.4s, v6.4s
	sqrdmulh	v17.4s, v17.4s, v0.s[0]
	sqrdmulh	v18.4s, v18.4s, v0.s[0]
	sub	v9.4s, v9.4s, v17.4s
	sub	v10.4s, v10.4s, v18.4s
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	mul	v15.4s, v7.4s, v0.s[1]
	mul	v16.4s, v8.4s, v0.s[1]
	mul	v17.4s, v3.4s, v15.4s
	mul	v18.4s, v4.4s, v16.4s
	sqrdmulh	v11.4s, v3.4s, v7.4s
	sqrdmulh	v12.4s, v4.4s, v8.4s
	sqrdmulh	v17.4s, v17.4s, v0.s[0]
	sqrdmulh	v18.4s, v18.4s, v0.s[0]
	sub	v11.4s, v11.4s, v17.4s
	sub	v12.4s, v12.4s, v18.4s
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	str	q9, [x0]
	str	q10, [x0, #16]
	str	q11, [x0, #32]
	str	q12, [x0, #48]
	ldr	q1, [x1, #64]
	ldr	q5, [x2, #64]
	ldr	q2, [x1, #80]
	ldr	q6, [x2, #80]
	ldr	q3, [x1, #96]
	ldr	q7, [x2, #96]
	ldr	q4, [x1, #112]
	ldr	q8, [x2, #112]
	mul	v13.4s, v5.4s, v0.s[1]
	mul	v14.4s, v6.4s, v0.s[1]
	mul	v17.4s, v1.4s, v13.4s
	mul	v18.4s, v2.4s, v14.4s
	sqrdmulh	v9.4s, v1.4s, v5.4s
	sqrdmulh	v10.4s, v2.4s, v6.4s
	sqrdmulh	v17.4s, v17.4s, v0.s[0]
	sqrdmulh	v18.4s, v18.4s, v0.s[0]
	sub	v9.4s, v9.4s, v17.4s
	sub	v10.4s, v10.4s, v18.4s
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	mul	v15.4s, v7.4s, v0.s[1]
	mul	v16.4s, v8.4s, v0.s[1]
	mul	v17.4s, v3.4s, v15.4s
	mul	v18.4s, v4.4s, v16.4s
	sqrdmulh	v11.4s, v3.4s, v7.4s
	sqrdmulh	v12.4s, v4.4s, v8.4s
	sqrdmulh	v17.4s, v17.4s, v0.s[0]
	sqrdmulh	v18.4s, v18.4s, v0.s[0]
	sub	v11.4s, v11.4s, v17.4s
	sub	v12.4s, v12.4s, v18.4s
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	str	q9, [x0, #64]
	str	q10, [x0, #80]
	str	q11, [x0, #96]
	str	q12, [x0, #112]
	ldr	q1, [x1, #128]
	ldr	q5, [x2, #128]
	ldr	q2, [x1, #144]
	ldr	q6, [x2, #144]
	ldr	q3, [x1, #160]
	ldr	q7, [x2, #160]
	ldr	q4, [x1, #176]
	ldr	q8, [x2, #176]
	mul	v13.4s, v5.4s, v0.s[1]
	mul	v14.4s, v6.4s, v0.s[1]
	mul	v17.4s, v1.4s, v13.4s
	mul	v18.4s, v2.4s, v14.4s
	sqrdmulh	v9.4s, v1.4s, v5.4s
	sqrdmulh	v10.4s, v2.4s, v6.4s
	sqrdmulh	v17.4s, v17.4s, v0.s[0]
	sqrdmulh	v18.4s, v18.4s, v0.s[0]
	sub	v9.4s, v9.4s, v17.4s
	sub	v10.4s, v10.4s, v18.4s
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	mul	v15.4s, v7.4s, v0.s[1]
	mul	v16.4s, v8.4s, v0.s[1]
	mul	v17.4s, v3.4s, v15.4s
	mul	v18.4s, v4.4s, v16.4s
	sqrdmulh	v11.4s, v3.4s, v7.4s
	sqrdmulh	v12.4s, v4.4s, v8.4s
	sqrdmulh	v17.4s, v17.4s, v0.s[0]
	sqrdmulh	v18.4s, v18.4s, v0.s[0]
	sub	v11.4s, v11.4s, v17.4s
	sub	v12.4s, v12.4s, v18.4s
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	str	q9, [x0, #128]
	str	q10, [x0, #144]
	str	q11, [x0, #160]
	str	q12, [x0, #176]
	ldr	q1, [x1, #192]
	ldr	q5, [x2, #192]
	ldr	q2, [x1, #208]
	ldr	q6, [x2, #208]
	ldr	q3, [x1, #224]
	ldr	q7, [x2, #224]
	ldr	q4, [x1, #240]
	ldr	q8, [x2, #240]
	mul	v13.4s, v5.4s, v0.s[1]
	mul	v14.4s, v6.4s, v0.s[1]
	mul	v17.4s, v1.4s, v13.4s
	mul	v18.4s, v2.4s, v14.4s
	sqrdmulh	v9.4s, v1.4s, v5.4s
	sqrdmulh	v10.4s, v2.4s, v6.4s
	sqrdmulh	v17.4s, v17.4s, v0.s[0]
	sqrdmulh	v18.4s, v18.4s, v0.s[0]
	sub	v9.4s, v9.4s, v17.4s
	sub	v10.4s, v10.4s, v18.4s
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	mul	v15.4s, v7.4s, v0.s[1]
	mul	v16.4s, v8.4s, v0.s[1]
	mul	v17.4s, v3.4s, v15.4s
	mul	v18.4s, v4.4s, v16.4s
	sqrdmulh	v11.4s, v3.4s, v7.4s
	sqrdmulh	v12.4s, v4.4s, v8.4s
	sqrdmulh	v17.4s, v17.4s, v0.s[0]
	sqrdmulh	v18.4s, v18.4s, v0.s[0]
	sub	v11.4s, v11.4s, v17.4s
	sub	v12.4s, v12.4s, v18.4s
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	str	q9, [x0, #192]
	str	q10, [x0, #208]
	str	q11, [x0, #224]
	str	q12, [x0, #240]
	ldr	q1, [x1, #256]
	ldr	q5, [x2, #256]
	ldr	q2, [x1, #272]
	ldr	q6, [x2, #272]
	ldr	q3, [x1, #288]
	ldr	q7, [x2, #288]
	ldr	q4, [x1, #304]
	ldr	q8, [x2, #304]
	mul	v13.4s, v5.4s, v0.s[1]
	mul	v14.4s, v6.4s, v0.s[1]
	mul	v17.4s, v1.4s, v13.4s
	mul	v18.4s, v2.4s, v14.4s
	sqrdmulh	v9.4s, v1.4s, v5.4s
	sqrdmulh	v10.4s, v2.4s, v6.4s
	sqrdmulh	v17.4s, v17.4s, v0.s[0]
	sqrdmulh	v18.4s, v18.4s, v0.s[0]
	sub	v9.4s, v9.4s, v17.4s
	sub	v10.4s, v10.4s, v18.4s
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	mul	v15.4s, v7.4s, v0.s[1]
	mul	v16.4s, v8.4s, v0.s[1]
	mul	v17.4s, v3.4s, v15.4s
	mul	v18.4s, v4.4s, v16.4s
	sqrdmulh	v11.4s, v3.4s, v7.4s
	sqrdmulh	v12.4s, v4.4s, v8.4s
	sqrdmulh	v17.4s, v17.4s, v0.s[0]
	sqrdmulh	v18.4s, v18.4s, v0.s[0]
	sub	v11.4s, v11.4s, v17.4s
	sub	v12.4s, v12.4s, v18.4s
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	str	q9, [x0, #256]
	str	q10, [x0, #272]
	str	q11, [x0, #288]
	str	q12, [x0, #304]
	ldr	q1, [x1, #320]
	ldr	q5, [x2, #320]
	ldr	q2, [x1, #336]
	ldr	q6, [x2, #336]
	ldr	q3, [x1, #352]
	ldr	q7, [x2, #352]
	ldr	q4, [x1, #368]
	ldr	q8, [x2, #368]
	mul	v13.4s, v5.4s, v0.s[1]
	mul	v14.4s, v6.4s, v0.s[1]
	mul	v17.4s, v1.4s, v13.4s
	mul	v18.4s, v2.4s, v14.4s
	sqrdmulh	v9.4s, v1.4s, v5.4s
	sqrdmulh	v10.4s, v2.4s, v6.4s
	sqrdmulh	v17.4s, v17.4s, v0.s[0]
	sqrdmulh	v18.4s, v18.4s, v0.s[0]
	sub	v9.4s, v9.4s, v17.4s
	sub	v10.4s, v10.4s, v18.4s
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	mul	v15.4s, v7.4s, v0.s[1]
	mul	v16.4s, v8.4s, v0.s[1]
	mul	v17.4s, v3.4s, v15.4s
	mul	v18.4s, v4.4s, v16.4s
	sqrdmulh	v11.4s, v3.4s, v7.4s
	sqrdmulh	v12.4s, v4.4s, v8.4s
	sqrdmulh	v17.4s, v17.4s, v0.s[0]
	sqrdmulh	v18.4s, v18.4s, v0.s[0]
	sub	v11.4s, v11.4s, v17.4s
	sub	v12.4s, v12.4s, v18.4s
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	str	q9, [x0, #320]
	str	q10, [x0, #336]
	str	q11, [x0, #352]
	str	q12, [x0, #368]
	ldr	q1, [x1, #384]
	ldr	q5, [x2, #384]
	ldr	q2, [x1, #400]
	ldr	q6, [x2, #400]
	ldr	q3, [x1, #416]
	ldr	q7, [x2, #416]
	ldr	q4, [x1, #432]
	ldr	q8, [x2, #432]
	mul	v13.4s, v5.4s, v0.s[1]
	mul	v14.4s, v6.4s, v0.s[1]
	mul	v17.4s, v1.4s, v13.4s
	mul	v18.4s, v2.4s, v14.4s
	sqrdmulh	v9.4s, v1.4s, v5.4s
	sqrdmulh	v10.4s, v2.4s, v6.4s
	sqrdmulh	v17.4s, v17.4s, v0.s[0]
	sqrdmulh	v18.4s, v18.4s, v0.s[0]
	sub	v9.4s, v9.4s, v17.4s
	sub	v10.4s, v10.4s, v18.4s
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	mul	v15.4s, v7.4s, v0.s[1]
	mul	v16.4s, v8.4s, v0.s[1]
	mul	v17.4s, v3.4s, v15.4s
	mul	v18.4s, v4.4s, v16.4s
	sqrdmulh	v11.4s, v3.4s, v7.4s
	sqrdmulh	v12.4s, v4.4s, v8.4s
	sqrdmulh	v17.4s, v17.4s, v0.s[0]
	sqrdmulh	v18.4s, v18.4s, v0.s[0]
	sub	v11.4s, v11.4s, v17.4s
	sub	v12.4s, v12.4s, v18.4s
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	str	q9, [x0, #384]
	str	q10, [x0, #400]
	str	q11, [x0, #416]
	str	q12, [x0, #432]
	ldr	q1, [x1, #448]
	ldr	q5, [x2, #448]
	ldr	q2, [x1, #464]
	ldr	q6, [x2, #464]
	ldr	q3, [x1, #480]
	ldr	q7, [x2, #480]
	ldr	q4, [x1, #496]
	ldr	q8, [x2, #496]
	mul	v13.4s, v5.4s, v0.s[1]
	mul	v14.4s, v6.4s, v0.s[1]
	mul	v17.4s, v1.4s, v13.4s
	mul	v18.4s, v2.4s, v14.4s
	sqrdmulh	v9.4s, v1.4s, v5.4s
	sqrdmulh	v10.4s, v2.4s, v6.4s
	sqrdmulh	v17.4s, v17.4s, v0.s[0]
	sqrdmulh	v18.4s, v18.4s, v0.s[0]
	sub	v9.4s, v9.4s, v17.4s
	sub	v10.4s, v10.4s, v18.4s
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	mul	v15.4s, v7.4s, v0.s[1]
	mul	v16.4s, v8.4s, v0.s[1]
	mul	v17.4s, v3.4s, v15.4s
	mul	v18.4s, v4.4s, v16.4s
	sqrdmulh	v11.4s, v3.4s, v7.4s
	sqrdmulh	v12.4s, v4.4s, v8.4s
	sqrdmulh	v17.4s, v17.4s, v0.s[0]
	sqrdmulh	v18.4s, v18.4s, v0.s[0]
	sub	v11.4s, v11.4s, v17.4s
	sub	v12.4s, v12.4s, v18.4s
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	str	q9, [x0, #448]
	str	q10, [x0, #464]
	str	q11, [x0, #480]
	str	q12, [x0, #496]
	ldr	q1, [x1, #512]
	ldr	q5, [x2, #512]
	ldr	q2, [x1, #528]
	ldr	q6, [x2, #528]
	ldr	q3, [x1, #544]
	ldr	q7, [x2, #544]
	ldr	q4, [x1, #560]
	ldr	q8, [x2, #560]
	mul	v13.4s, v5.4s, v0.s[1]
	mul	v14.4s, v6.4s, v0.s[1]
	mul	v17.4s, v1.4s, v13.4s
	mul	v18.4s, v2.4s, v14.4s
	sqrdmulh	v9.4s, v1.4s, v5.4s
	sqrdmulh	v10.4s, v2.4s, v6.4s
	sqrdmulh	v17.4s, v17.4s, v0.s[0]
	sqrdmulh	v18.4s, v18.4s, v0.s[0]
	sub	v9.4s, v9.4s, v17.4s
	sub	v10.4s, v10.4s, v18.4s
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	mul	v15.4s, v7.4s, v0.s[1]
	mul	v16.4s, v8.4s, v0.s[1]
	mul	v17.4s, v3.4s, v15.4s
	mul	v18.4s, v4.4s, v16.4s
	sqrdmulh	v11.4s, v3.4s, v7.4s
	sqrdmulh	v12.4s, v4.4s, v8.4s
	sqrdmulh	v17.4s, v17.4s, v0.s[0]
	sqrdmulh	v18.4s, v18.4s, v0.s[0]
	sub	v11.4s, v11.4s, v17.4s
	sub	v12.4s, v12.4s, v18.4s
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	str	q9, [x0, #512]
	str	q10, [x0, #528]
	str	q11, [x0, #544]
	str	q12, [x0, #560]
	ldr	q1, [x1, #576]
	ldr	q5, [x2, #576]
	ldr	q2, [x1, #592]
	ldr	q6, [x2, #592]
	ldr	q3, [x1, #608]
	ldr	q7, [x2, #608]
	ldr	q4, [x1, #624]
	ldr	q8, [x2, #624]
	mul	v13.4s, v5.4s, v0.s[1]
	mul	v14.4s, v6.4s, v0.s[1]
	mul	v17.4s, v1.4s, v13.4s
	mul	v18.4s, v2.4s, v14.4s
	sqrdmulh	v9.4s, v1.4s, v5.4s
	sqrdmulh	v10.4s, v2.4s, v6.4s
	sqrdmulh	v17.4s, v17.4s, v0.s[0]
	sqrdmulh	v18.4s, v18.4s, v0.s[0]
	sub	v9.4s, v9.4s, v17.4s
	sub	v10.4s, v10.4s, v18.4s
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	mul	v15.4s, v7.4s, v0.s[1]
	mul	v16.4s, v8.4s, v0.s[1]
	mul	v17.4s, v3.4s, v15.4s
	mul	v18.4s, v4.4s, v16.4s
	sqrdmulh	v11.4s, v3.4s, v7.4s
	sqrdmulh	v12.4s, v4.4s, v8.4s
	sqrdmulh	v17.4s, v17.4s, v0.s[0]
	sqrdmulh	v18.4s, v18.4s, v0.s[0]
	sub	v11.4s, v11.4s, v17.4s
	sub	v12.4s, v12.4s, v18.4s
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	str	q9, [x0, #576]
	str	q10, [x0, #592]
	str	q11, [x0, #608]
	str	q12, [x0, #624]
	ldr	q1, [x1, #640]
	ldr	q5, [x2, #640]
	ldr	q2, [x1, #656]
	ldr	q6, [x2, #656]
	ldr	q3, [x1, #672]
	ldr	q7, [x2, #672]
	ldr	q4, [x1, #688]
	ldr	q8, [x2, #688]
	mul	v13.4s, v5.4s, v0.s[1]
	mul	v14.4s, v6.4s, v0.s[1]
	mul	v17.4s, v1.4s, v13.4s
	mul	v18.4s, v2.4s, v14.4s
	sqrdmulh	v9.4s, v1.4s, v5.4s
	sqrdmulh	v10.4s, v2.4s, v6.4s
	sqrdmulh	v17.4s, v17.4s, v0.s[0]
	sqrdmulh	v18.4s, v18.4s, v0.s[0]
	sub	v9.4s, v9.4s, v17.4s
	sub	v10.4s, v10.4s, v18.4s
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	mul	v15.4s, v7.4s, v0.s[1]
	mul	v16.4s, v8.4s, v0.s[1]
	mul	v17.4s, v3.4s, v15.4s
	mul	v18.4s, v4.4s, v16.4s
	sqrdmulh	v11.4s, v3.4s, v7.4s
	sqrdmulh	v12.4s, v4.4s, v8.4s
	sqrdmulh	v17.4s, v17.4s, v0.s[0]
	sqrdmulh	v18.4s, v18.4s, v0.s[0]
	sub	v11.4s, v11.4s, v17.4s
	sub	v12.4s, v12.4s, v18.4s
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	str	q9, [x0, #640]
	str	q10, [x0, #656]
	str	q11, [x0, #672]
	str	q12, [x0, #688]
	ldr	q1, [x1, #704]
	ldr	q5, [x2, #704]
	ldr	q2, [x1, #720]
	ldr	q6, [x2, #720]
	ldr	q3, [x1, #736]
	ldr	q7, [x2, #736]
	ldr	q4, [x1, #752]
	ldr	q8, [x2, #752]
	mul	v13.4s, v5.4s, v0.s[1]
	mul	v14.4s, v6.4s, v0.s[1]
	mul	v17.4s, v1.4s, v13.4s
	mul	v18.4s, v2.4s, v14.4s
	sqrdmulh	v9.4s, v1.4s, v5.4s
	sqrdmulh	v10.4s, v2.4s, v6.4s
	sqrdmulh	v17.4s, v17.4s, v0.s[0]
	sqrdmulh	v18.4s, v18.4s, v0.s[0]
	sub	v9.4s, v9.4s, v17.4s
	sub	v10.4s, v10.4s, v18.4s
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	mul	v15.4s, v7.4s, v0.s[1]
	mul	v16.4s, v8.4s, v0.s[1]
	mul	v17.4s, v3.4s, v15.4s
	mul	v18.4s, v4.4s, v16.4s
	sqrdmulh	v11.4s, v3.4s, v7.4s
	sqrdmulh	v12.4s, v4.4s, v8.4s
	sqrdmulh	v17.4s, v17.4s, v0.s[0]
	sqrdmulh	v18.4s, v18.4s, v0.s[0]
	sub	v11.4s, v11.4s, v17.4s
	sub	v12.4s, v12.4s, v18.4s
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	str	q9, [x0, #704]
	str	q10, [x0, #720]
	str	q11, [x0, #736]
	str	q12, [x0, #752]
	ldr	q1, [x1, #768]
	ldr	q5, [x2, #768]
	ldr	q2, [x1, #784]
	ldr	q6, [x2, #784]
	ldr	q3, [x1, #800]
	ldr	q7, [x2, #800]
	ldr	q4, [x1, #816]
	ldr	q8, [x2, #816]
	mul	v13.4s, v5.4s, v0.s[1]
	mul	v14.4s, v6.4s, v0.s[1]
	mul	v17.4s, v1.4s, v13.4s
	mul	v18.4s, v2.4s, v14.4s
	sqrdmulh	v9.4s, v1.4s, v5.4s
	sqrdmulh	v10.4s, v2.4s, v6.4s
	sqrdmulh	v17.4s, v17.4s, v0.s[0]
	sqrdmulh	v18.4s, v18.4s, v0.s[0]
	sub	v9.4s, v9.4s, v17.4s
	sub	v10.4s, v10.4s, v18.4s
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	mul	v15.4s, v7.4s, v0.s[1]
	mul	v16.4s, v8.4s, v0.s[1]
	mul	v17.4s, v3.4s, v15.4s
	mul	v18.4s, v4.4s, v16.4s
	sqrdmulh	v11.4s, v3.4s, v7.4s
	sqrdmulh	v12.4s, v4.4s, v8.4s
	sqrdmulh	v17.4s, v17.4s, v0.s[0]
	sqrdmulh	v18.4s, v18.4s, v0.s[0]
	sub	v11.4s, v11.4s, v17.4s
	sub	v12.4s, v12.4s, v18.4s
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	str	q9, [x0, #768]
	str	q10, [x0, #784]
	str	q11, [x0, #800]
	str	q12, [x0, #816]
	ldr	q1, [x1, #832]
	ldr	q5, [x2, #832]
	ldr	q2, [x1, #848]
	ldr	q6, [x2, #848]
	ldr	q3, [x1, #864]
	ldr	q7, [x2, #864]
	ldr	q4, [x1, #880]
	ldr	q8, [x2, #880]
	mul	v13.4s, v5.4s, v0.s[1]
	mul	v14.4s, v6.4s, v0.s[1]
	mul	v17.4s, v1.4s, v13.4s
	mul	v18.4s, v2.4s, v14.4s
	sqrdmulh	v9.4s, v1.4s, v5.4s
	sqrdmulh	v10.4s, v2.4s, v6.4s
	sqrdmulh	v17.4s, v17.4s, v0.s[0]
	sqrdmulh	v18.4s, v18.4s, v0.s[0]
	sub	v9.4s, v9.4s, v17.4s
	sub	v10.4s, v10.4s, v18.4s
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	mul	v15.4s, v7.4s, v0.s[1]
	mul	v16.4s, v8.4s, v0.s[1]
	mul	v17.4s, v3.4s, v15.4s
	mul	v18.4s, v4.4s, v16.4s
	sqrdmulh	v11.4s, v3.4s, v7.4s
	sqrdmulh	v12.4s, v4.4s, v8.4s
	sqrdmulh	v17.4s, v17.4s, v0.s[0]
	sqrdmulh	v18.4s, v18.4s, v0.s[0]
	sub	v11.4s, v11.4s, v17.4s
	sub	v12.4s, v12.4s, v18.4s
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	str	q9, [x0, #832]
	str	q10, [x0, #848]
	str	q11, [x0, #864]
	str	q12, [x0, #880]
	ldr	q1, [x1, #896]
	ldr	q5, [x2, #896]
	ldr	q2, [x1, #912]
	ldr	q6, [x2, #912]
	ldr	q3, [x1, #928]
	ldr	q7, [x2, #928]
	ldr	q4, [x1, #944]
	ldr	q8, [x2, #944]
	mul	v13.4s, v5.4s, v0.s[1]
	mul	v14.4s, v6.4s, v0.s[1]
	mul	v17.4s, v1.4s, v13.4s
	mul	v18.4s, v2.4s, v14.4s
	sqrdmulh	v9.4s, v1.4s, v5.4s
	sqrdmulh	v10.4s, v2.4s, v6.4s
	sqrdmulh	v17.4s, v17.4s, v0.s[0]
	sqrdmulh	v18.4s, v18.4s, v0.s[0]
	sub	v9.4s, v9.4s, v17.4s
	sub	v10.4s, v10.4s, v18.4s
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	mul	v15.4s, v7.4s, v0.s[1]
	mul	v16.4s, v8.4s, v0.s[1]
	mul	v17.4s, v3.4s, v15.4s
	mul	v18.4s, v4.4s, v16.4s
	sqrdmulh	v11.4s, v3.4s, v7.4s
	sqrdmulh	v12.4s, v4.4s, v8.4s
	sqrdmulh	v17.4s, v17.4s, v0.s[0]
	sqrdmulh	v18.4s, v18.4s, v0.s[0]
	sub	v11.4s, v11.4s, v17.4s
	sub	v12.4s, v12.4s, v18.4s
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	str	q9, [x0, #896]
	str	q10, [x0, #912]
	str	q11, [x0, #928]
	str	q12, [x0, #944]
	ldr	q1, [x1, #960]
	ldr	q5, [x2, #960]
	ldr	q2, [x1, #976]
	ldr	q6, [x2, #976]
	ldr	q3, [x1, #992]
	ldr	q7, [x2, #992]
	ldr	q4, [x1, #1008]
	ldr	q8, [x2, #1008]
	mul	v13.4s, v5.4s, v0.s[1]
	mul	v14.4s, v6.4s, v0.s[1]
	mul	v17.4s, v1.4s, v13.4s
	mul	v18.4s, v2.4s, v14.4s
	sqrdmulh	v9.4s, v1.4s, v5.4s
	sqrdmulh	v10.4s, v2.4s, v6.4s
	sqrdmulh	v17.4s, v17.4s, v0.s[0]
	sqrdmulh	v18.4s, v18.4s, v0.s[0]
	sub	v9.4s, v9.4s, v17.4s
	sub	v10.4s, v10.4s, v18.4s
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	mul	v15.4s, v7.4s, v0.s[1]
	mul	v16.4s, v8.4s, v0.s[1]
	mul	v17.4s, v3.4s, v15.4s
	mul	v18.4s, v4.4s, v16.4s
	sqrdmulh	v11.4s, v3.4s, v7.4s
	sqrdmulh	v12.4s, v4.4s, v8.4s
	sqrdmulh	v17.4s, v17.4s, v0.s[0]
	sqrdmulh	v18.4s, v18.4s, v0.s[0]
	sub	v11.4s, v11.4s, v17.4s
	sub	v12.4s, v12.4s, v18.4s
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	str	q9, [x0, #960]
	str	q10, [x0, #976]
	str	q11, [x0, #992]
	str	q12, [x0, #1008]
	ldp	d8, d9, [x29, #16]
	ldp	d10, d11, [x29, #32]
	ldp	d12, d13, [x29, #48]
	ldp	d14, d15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
#ifndef __APPLE__
	.size	mldsa_mul_neon,.-mldsa_mul_neon
#endif /* __APPLE__ */
#ifndef WOLFSSL_AARCH64_NO_SQRDMLSH
#ifndef __APPLE__
.text
.globl	mldsa_ntt_sqrdmlsh_neon
WC_ASM_ATT_HIDDEN(mldsa_ntt_sqrdmlsh_neon)
.type	mldsa_ntt_sqrdmlsh_neon,@function
.align	2
mldsa_ntt_sqrdmlsh_neon:
#else
.section	__TEXT,__text
.globl	_mldsa_ntt_sqrdmlsh_neon
WC_ASM_ATT_HIDDEN(_mldsa_ntt_sqrdmlsh_neon)
.p2align	2
_mldsa_ntt_sqrdmlsh_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
	stp	d12, d13, [x29, #48]
	stp	d14, d15, [x29, #64]
#ifndef __APPLE__
	adrp x1, L_mldsa_aarch64_zetas
	add  x1, x1, :lo12:L_mldsa_aarch64_zetas
#else
	adrp x1, L_mldsa_aarch64_zetas@PAGE
	add  x1, x1, L_mldsa_aarch64_zetas@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x2, L_mldsa_aarch64_zetas_qinv
	add  x2, x2, :lo12:L_mldsa_aarch64_zetas_qinv
#else
	adrp x2, L_mldsa_aarch64_zetas_qinv@PAGE
	add  x2, x2, L_mldsa_aarch64_zetas_qinv@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x3, L_mldsa_aarch64_consts
	add  x3, x3, :lo12:L_mldsa_aarch64_consts
#else
	adrp x3, L_mldsa_aarch64_consts@PAGE
	add  x3, x3, L_mldsa_aarch64_consts@PAGEOFF
#endif /* __APPLE__ */
	ldr	q4, [x3]
	ldr	q5, [x0]
	ldr	q6, [x0, #64]
	ldr	q7, [x0, #128]
	ldr	q8, [x0, #192]
	ldr	q9, [x0, #256]
	ldr	q10, [x0, #320]
	ldr	q11, [x0, #384]
	ldr	q12, [x0, #448]
	ldr	q13, [x0, #512]
	ldr	q14, [x0, #576]
	ldr	q15, [x0, #640]
	ldr	q16, [x0, #704]
	ldr	q17, [x0, #768]
	ldr	q18, [x0, #832]
	ldr	q19, [x0, #896]
	ldr	q20, [x0, #960]
	ldr	q0, [x1]
	ldr	q1, [x2]
	mul	v29.4s, v13.4s, v1.s[1]
	mul	v30.4s, v14.4s, v1.s[1]
	sqrdmulh	v21.4s, v13.4s, v0.s[1]
	sqrdmulh	v22.4s, v14.4s, v0.s[1]
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v15.4s, v1.s[1]
	mul	v30.4s, v16.4s, v1.s[1]
	sqrdmulh	v23.4s, v15.4s, v0.s[1]
	sqrdmulh	v24.4s, v16.4s, v0.s[1]
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v17.4s, v1.s[1]
	mul	v30.4s, v18.4s, v1.s[1]
	sqrdmulh	v25.4s, v17.4s, v0.s[1]
	sqrdmulh	v26.4s, v18.4s, v0.s[1]
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[1]
	mul	v30.4s, v20.4s, v1.s[1]
	sqrdmulh	v27.4s, v19.4s, v0.s[1]
	sqrdmulh	v28.4s, v20.4s, v0.s[1]
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v13.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v14.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v15.4s, v7.4s, v23.4s
	add	v7.4s, v7.4s, v23.4s
	sub	v16.4s, v8.4s, v24.4s
	add	v8.4s, v8.4s, v24.4s
	sub	v17.4s, v9.4s, v25.4s
	add	v9.4s, v9.4s, v25.4s
	sub	v18.4s, v10.4s, v26.4s
	add	v10.4s, v10.4s, v26.4s
	sub	v19.4s, v11.4s, v27.4s
	add	v11.4s, v11.4s, v27.4s
	sub	v20.4s, v12.4s, v28.4s
	add	v12.4s, v12.4s, v28.4s
	mul	v29.4s, v9.4s, v1.s[2]
	mul	v30.4s, v10.4s, v1.s[2]
	sqrdmulh	v21.4s, v9.4s, v0.s[2]
	sqrdmulh	v22.4s, v10.4s, v0.s[2]
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v11.4s, v1.s[2]
	mul	v30.4s, v12.4s, v1.s[2]
	sqrdmulh	v23.4s, v11.4s, v0.s[2]
	sqrdmulh	v24.4s, v12.4s, v0.s[2]
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v17.4s, v1.s[3]
	mul	v30.4s, v18.4s, v1.s[3]
	sqrdmulh	v25.4s, v17.4s, v0.s[3]
	sqrdmulh	v26.4s, v18.4s, v0.s[3]
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[3]
	mul	v30.4s, v20.4s, v1.s[3]
	sqrdmulh	v27.4s, v19.4s, v0.s[3]
	sqrdmulh	v28.4s, v20.4s, v0.s[3]
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v9.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v10.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v11.4s, v7.4s, v23.4s
	add	v7.4s, v7.4s, v23.4s
	sub	v12.4s, v8.4s, v24.4s
	add	v8.4s, v8.4s, v24.4s
	sub	v17.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v18.4s, v14.4s, v26.4s
	add	v14.4s, v14.4s, v26.4s
	sub	v19.4s, v15.4s, v27.4s
	add	v15.4s, v15.4s, v27.4s
	sub	v20.4s, v16.4s, v28.4s
	add	v16.4s, v16.4s, v28.4s
	ldr	q0, [x1, #16]
	ldr	q1, [x2, #16]
	mul	v29.4s, v7.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[0]
	sqrdmulh	v21.4s, v7.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[0]
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v11.4s, v1.s[1]
	mul	v30.4s, v12.4s, v1.s[1]
	sqrdmulh	v23.4s, v11.4s, v0.s[1]
	sqrdmulh	v24.4s, v12.4s, v0.s[1]
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v15.4s, v1.s[2]
	mul	v30.4s, v16.4s, v1.s[2]
	sqrdmulh	v25.4s, v15.4s, v0.s[2]
	sqrdmulh	v26.4s, v16.4s, v0.s[2]
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[3]
	mul	v30.4s, v20.4s, v1.s[3]
	sqrdmulh	v27.4s, v19.4s, v0.s[3]
	sqrdmulh	v28.4s, v20.4s, v0.s[3]
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v7.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v11.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v10.4s, v24.4s
	add	v10.4s, v10.4s, v24.4s
	sub	v15.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v14.4s, v26.4s
	add	v14.4s, v14.4s, v26.4s
	sub	v19.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v18.4s, v28.4s
	add	v18.4s, v18.4s, v28.4s
	ldp	q0, q2, [x1, #32]
	ldp	q1, q3, [x2, #32]
	mul	v29.4s, v6.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[1]
	sqrdmulh	v21.4s, v6.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[1]
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v10.4s, v1.s[2]
	mul	v30.4s, v12.4s, v1.s[3]
	sqrdmulh	v23.4s, v10.4s, v0.s[2]
	sqrdmulh	v24.4s, v12.4s, v0.s[3]
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v14.4s, v3.s[0]
	mul	v30.4s, v16.4s, v3.s[1]
	sqrdmulh	v25.4s, v14.4s, v2.s[0]
	sqrdmulh	v26.4s, v16.4s, v2.s[1]
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v18.4s, v3.s[2]
	mul	v30.4s, v20.4s, v3.s[3]
	sqrdmulh	v27.4s, v18.4s, v2.s[2]
	sqrdmulh	v28.4s, v20.4s, v2.s[3]
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	str	q5, [x0]
	str	q6, [x0, #64]
	str	q7, [x0, #128]
	str	q8, [x0, #192]
	str	q9, [x0, #256]
	str	q10, [x0, #320]
	str	q11, [x0, #384]
	str	q12, [x0, #448]
	str	q13, [x0, #512]
	str	q14, [x0, #576]
	str	q15, [x0, #640]
	str	q16, [x0, #704]
	str	q17, [x0, #768]
	str	q18, [x0, #832]
	str	q19, [x0, #896]
	str	q20, [x0, #960]
	ldr	q5, [x0, #16]
	ldr	q6, [x0, #80]
	ldr	q7, [x0, #144]
	ldr	q8, [x0, #208]
	ldr	q9, [x0, #272]
	ldr	q10, [x0, #336]
	ldr	q11, [x0, #400]
	ldr	q12, [x0, #464]
	ldr	q13, [x0, #528]
	ldr	q14, [x0, #592]
	ldr	q15, [x0, #656]
	ldr	q16, [x0, #720]
	ldr	q17, [x0, #784]
	ldr	q18, [x0, #848]
	ldr	q19, [x0, #912]
	ldr	q20, [x0, #976]
	ldr	q0, [x1]
	ldr	q1, [x2]
	mul	v29.4s, v13.4s, v1.s[1]
	mul	v30.4s, v14.4s, v1.s[1]
	sqrdmulh	v21.4s, v13.4s, v0.s[1]
	sqrdmulh	v22.4s, v14.4s, v0.s[1]
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v15.4s, v1.s[1]
	mul	v30.4s, v16.4s, v1.s[1]
	sqrdmulh	v23.4s, v15.4s, v0.s[1]
	sqrdmulh	v24.4s, v16.4s, v0.s[1]
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v17.4s, v1.s[1]
	mul	v30.4s, v18.4s, v1.s[1]
	sqrdmulh	v25.4s, v17.4s, v0.s[1]
	sqrdmulh	v26.4s, v18.4s, v0.s[1]
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[1]
	mul	v30.4s, v20.4s, v1.s[1]
	sqrdmulh	v27.4s, v19.4s, v0.s[1]
	sqrdmulh	v28.4s, v20.4s, v0.s[1]
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v13.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v14.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v15.4s, v7.4s, v23.4s
	add	v7.4s, v7.4s, v23.4s
	sub	v16.4s, v8.4s, v24.4s
	add	v8.4s, v8.4s, v24.4s
	sub	v17.4s, v9.4s, v25.4s
	add	v9.4s, v9.4s, v25.4s
	sub	v18.4s, v10.4s, v26.4s
	add	v10.4s, v10.4s, v26.4s
	sub	v19.4s, v11.4s, v27.4s
	add	v11.4s, v11.4s, v27.4s
	sub	v20.4s, v12.4s, v28.4s
	add	v12.4s, v12.4s, v28.4s
	mul	v29.4s, v9.4s, v1.s[2]
	mul	v30.4s, v10.4s, v1.s[2]
	sqrdmulh	v21.4s, v9.4s, v0.s[2]
	sqrdmulh	v22.4s, v10.4s, v0.s[2]
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v11.4s, v1.s[2]
	mul	v30.4s, v12.4s, v1.s[2]
	sqrdmulh	v23.4s, v11.4s, v0.s[2]
	sqrdmulh	v24.4s, v12.4s, v0.s[2]
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v17.4s, v1.s[3]
	mul	v30.4s, v18.4s, v1.s[3]
	sqrdmulh	v25.4s, v17.4s, v0.s[3]
	sqrdmulh	v26.4s, v18.4s, v0.s[3]
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[3]
	mul	v30.4s, v20.4s, v1.s[3]
	sqrdmulh	v27.4s, v19.4s, v0.s[3]
	sqrdmulh	v28.4s, v20.4s, v0.s[3]
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v9.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v10.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v11.4s, v7.4s, v23.4s
	add	v7.4s, v7.4s, v23.4s
	sub	v12.4s, v8.4s, v24.4s
	add	v8.4s, v8.4s, v24.4s
	sub	v17.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v18.4s, v14.4s, v26.4s
	add	v14.4s, v14.4s, v26.4s
	sub	v19.4s, v15.4s, v27.4s
	add	v15.4s, v15.4s, v27.4s
	sub	v20.4s, v16.4s, v28.4s
	add	v16.4s, v16.4s, v28.4s
	ldr	q0, [x1, #16]
	ldr	q1, [x2, #16]
	mul	v29.4s, v7.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[0]
	sqrdmulh	v21.4s, v7.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[0]
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v11.4s, v1.s[1]
	mul	v30.4s, v12.4s, v1.s[1]
	sqrdmulh	v23.4s, v11.4s, v0.s[1]
	sqrdmulh	v24.4s, v12.4s, v0.s[1]
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v15.4s, v1.s[2]
	mul	v30.4s, v16.4s, v1.s[2]
	sqrdmulh	v25.4s, v15.4s, v0.s[2]
	sqrdmulh	v26.4s, v16.4s, v0.s[2]
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[3]
	mul	v30.4s, v20.4s, v1.s[3]
	sqrdmulh	v27.4s, v19.4s, v0.s[3]
	sqrdmulh	v28.4s, v20.4s, v0.s[3]
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v7.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v11.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v10.4s, v24.4s
	add	v10.4s, v10.4s, v24.4s
	sub	v15.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v14.4s, v26.4s
	add	v14.4s, v14.4s, v26.4s
	sub	v19.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v18.4s, v28.4s
	add	v18.4s, v18.4s, v28.4s
	ldp	q0, q2, [x1, #32]
	ldp	q1, q3, [x2, #32]
	mul	v29.4s, v6.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[1]
	sqrdmulh	v21.4s, v6.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[1]
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v10.4s, v1.s[2]
	mul	v30.4s, v12.4s, v1.s[3]
	sqrdmulh	v23.4s, v10.4s, v0.s[2]
	sqrdmulh	v24.4s, v12.4s, v0.s[3]
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v14.4s, v3.s[0]
	mul	v30.4s, v16.4s, v3.s[1]
	sqrdmulh	v25.4s, v14.4s, v2.s[0]
	sqrdmulh	v26.4s, v16.4s, v2.s[1]
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v18.4s, v3.s[2]
	mul	v30.4s, v20.4s, v3.s[3]
	sqrdmulh	v27.4s, v18.4s, v2.s[2]
	sqrdmulh	v28.4s, v20.4s, v2.s[3]
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	str	q5, [x0, #16]
	str	q6, [x0, #80]
	str	q7, [x0, #144]
	str	q8, [x0, #208]
	str	q9, [x0, #272]
	str	q10, [x0, #336]
	str	q11, [x0, #400]
	str	q12, [x0, #464]
	str	q13, [x0, #528]
	str	q14, [x0, #592]
	str	q15, [x0, #656]
	str	q16, [x0, #720]
	str	q17, [x0, #784]
	str	q18, [x0, #848]
	str	q19, [x0, #912]
	str	q20, [x0, #976]
	ldr	q5, [x0, #32]
	ldr	q6, [x0, #96]
	ldr	q7, [x0, #160]
	ldr	q8, [x0, #224]
	ldr	q9, [x0, #288]
	ldr	q10, [x0, #352]
	ldr	q11, [x0, #416]
	ldr	q12, [x0, #480]
	ldr	q13, [x0, #544]
	ldr	q14, [x0, #608]
	ldr	q15, [x0, #672]
	ldr	q16, [x0, #736]
	ldr	q17, [x0, #800]
	ldr	q18, [x0, #864]
	ldr	q19, [x0, #928]
	ldr	q20, [x0, #992]
	ldr	q0, [x1]
	ldr	q1, [x2]
	mul	v29.4s, v13.4s, v1.s[1]
	mul	v30.4s, v14.4s, v1.s[1]
	sqrdmulh	v21.4s, v13.4s, v0.s[1]
	sqrdmulh	v22.4s, v14.4s, v0.s[1]
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v15.4s, v1.s[1]
	mul	v30.4s, v16.4s, v1.s[1]
	sqrdmulh	v23.4s, v15.4s, v0.s[1]
	sqrdmulh	v24.4s, v16.4s, v0.s[1]
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v17.4s, v1.s[1]
	mul	v30.4s, v18.4s, v1.s[1]
	sqrdmulh	v25.4s, v17.4s, v0.s[1]
	sqrdmulh	v26.4s, v18.4s, v0.s[1]
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[1]
	mul	v30.4s, v20.4s, v1.s[1]
	sqrdmulh	v27.4s, v19.4s, v0.s[1]
	sqrdmulh	v28.4s, v20.4s, v0.s[1]
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v13.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v14.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v15.4s, v7.4s, v23.4s
	add	v7.4s, v7.4s, v23.4s
	sub	v16.4s, v8.4s, v24.4s
	add	v8.4s, v8.4s, v24.4s
	sub	v17.4s, v9.4s, v25.4s
	add	v9.4s, v9.4s, v25.4s
	sub	v18.4s, v10.4s, v26.4s
	add	v10.4s, v10.4s, v26.4s
	sub	v19.4s, v11.4s, v27.4s
	add	v11.4s, v11.4s, v27.4s
	sub	v20.4s, v12.4s, v28.4s
	add	v12.4s, v12.4s, v28.4s
	mul	v29.4s, v9.4s, v1.s[2]
	mul	v30.4s, v10.4s, v1.s[2]
	sqrdmulh	v21.4s, v9.4s, v0.s[2]
	sqrdmulh	v22.4s, v10.4s, v0.s[2]
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v11.4s, v1.s[2]
	mul	v30.4s, v12.4s, v1.s[2]
	sqrdmulh	v23.4s, v11.4s, v0.s[2]
	sqrdmulh	v24.4s, v12.4s, v0.s[2]
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v17.4s, v1.s[3]
	mul	v30.4s, v18.4s, v1.s[3]
	sqrdmulh	v25.4s, v17.4s, v0.s[3]
	sqrdmulh	v26.4s, v18.4s, v0.s[3]
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[3]
	mul	v30.4s, v20.4s, v1.s[3]
	sqrdmulh	v27.4s, v19.4s, v0.s[3]
	sqrdmulh	v28.4s, v20.4s, v0.s[3]
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v9.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v10.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v11.4s, v7.4s, v23.4s
	add	v7.4s, v7.4s, v23.4s
	sub	v12.4s, v8.4s, v24.4s
	add	v8.4s, v8.4s, v24.4s
	sub	v17.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v18.4s, v14.4s, v26.4s
	add	v14.4s, v14.4s, v26.4s
	sub	v19.4s, v15.4s, v27.4s
	add	v15.4s, v15.4s, v27.4s
	sub	v20.4s, v16.4s, v28.4s
	add	v16.4s, v16.4s, v28.4s
	ldr	q0, [x1, #16]
	ldr	q1, [x2, #16]
	mul	v29.4s, v7.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[0]
	sqrdmulh	v21.4s, v7.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[0]
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v11.4s, v1.s[1]
	mul	v30.4s, v12.4s, v1.s[1]
	sqrdmulh	v23.4s, v11.4s, v0.s[1]
	sqrdmulh	v24.4s, v12.4s, v0.s[1]
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v15.4s, v1.s[2]
	mul	v30.4s, v16.4s, v1.s[2]
	sqrdmulh	v25.4s, v15.4s, v0.s[2]
	sqrdmulh	v26.4s, v16.4s, v0.s[2]
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[3]
	mul	v30.4s, v20.4s, v1.s[3]
	sqrdmulh	v27.4s, v19.4s, v0.s[3]
	sqrdmulh	v28.4s, v20.4s, v0.s[3]
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v7.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v11.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v10.4s, v24.4s
	add	v10.4s, v10.4s, v24.4s
	sub	v15.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v14.4s, v26.4s
	add	v14.4s, v14.4s, v26.4s
	sub	v19.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v18.4s, v28.4s
	add	v18.4s, v18.4s, v28.4s
	ldp	q0, q2, [x1, #32]
	ldp	q1, q3, [x2, #32]
	mul	v29.4s, v6.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[1]
	sqrdmulh	v21.4s, v6.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[1]
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v10.4s, v1.s[2]
	mul	v30.4s, v12.4s, v1.s[3]
	sqrdmulh	v23.4s, v10.4s, v0.s[2]
	sqrdmulh	v24.4s, v12.4s, v0.s[3]
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v14.4s, v3.s[0]
	mul	v30.4s, v16.4s, v3.s[1]
	sqrdmulh	v25.4s, v14.4s, v2.s[0]
	sqrdmulh	v26.4s, v16.4s, v2.s[1]
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v18.4s, v3.s[2]
	mul	v30.4s, v20.4s, v3.s[3]
	sqrdmulh	v27.4s, v18.4s, v2.s[2]
	sqrdmulh	v28.4s, v20.4s, v2.s[3]
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	str	q5, [x0, #32]
	str	q6, [x0, #96]
	str	q7, [x0, #160]
	str	q8, [x0, #224]
	str	q9, [x0, #288]
	str	q10, [x0, #352]
	str	q11, [x0, #416]
	str	q12, [x0, #480]
	str	q13, [x0, #544]
	str	q14, [x0, #608]
	str	q15, [x0, #672]
	str	q16, [x0, #736]
	str	q17, [x0, #800]
	str	q18, [x0, #864]
	str	q19, [x0, #928]
	str	q20, [x0, #992]
	ldr	q5, [x0, #48]
	ldr	q6, [x0, #112]
	ldr	q7, [x0, #176]
	ldr	q8, [x0, #240]
	ldr	q9, [x0, #304]
	ldr	q10, [x0, #368]
	ldr	q11, [x0, #432]
	ldr	q12, [x0, #496]
	ldr	q13, [x0, #560]
	ldr	q14, [x0, #624]
	ldr	q15, [x0, #688]
	ldr	q16, [x0, #752]
	ldr	q17, [x0, #816]
	ldr	q18, [x0, #880]
	ldr	q19, [x0, #944]
	ldr	q20, [x0, #1008]
	ldr	q0, [x1]
	ldr	q1, [x2]
	mul	v29.4s, v13.4s, v1.s[1]
	mul	v30.4s, v14.4s, v1.s[1]
	sqrdmulh	v21.4s, v13.4s, v0.s[1]
	sqrdmulh	v22.4s, v14.4s, v0.s[1]
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v15.4s, v1.s[1]
	mul	v30.4s, v16.4s, v1.s[1]
	sqrdmulh	v23.4s, v15.4s, v0.s[1]
	sqrdmulh	v24.4s, v16.4s, v0.s[1]
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v17.4s, v1.s[1]
	mul	v30.4s, v18.4s, v1.s[1]
	sqrdmulh	v25.4s, v17.4s, v0.s[1]
	sqrdmulh	v26.4s, v18.4s, v0.s[1]
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[1]
	mul	v30.4s, v20.4s, v1.s[1]
	sqrdmulh	v27.4s, v19.4s, v0.s[1]
	sqrdmulh	v28.4s, v20.4s, v0.s[1]
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v13.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v14.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v15.4s, v7.4s, v23.4s
	add	v7.4s, v7.4s, v23.4s
	sub	v16.4s, v8.4s, v24.4s
	add	v8.4s, v8.4s, v24.4s
	sub	v17.4s, v9.4s, v25.4s
	add	v9.4s, v9.4s, v25.4s
	sub	v18.4s, v10.4s, v26.4s
	add	v10.4s, v10.4s, v26.4s
	sub	v19.4s, v11.4s, v27.4s
	add	v11.4s, v11.4s, v27.4s
	sub	v20.4s, v12.4s, v28.4s
	add	v12.4s, v12.4s, v28.4s
	mul	v29.4s, v9.4s, v1.s[2]
	mul	v30.4s, v10.4s, v1.s[2]
	sqrdmulh	v21.4s, v9.4s, v0.s[2]
	sqrdmulh	v22.4s, v10.4s, v0.s[2]
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v11.4s, v1.s[2]
	mul	v30.4s, v12.4s, v1.s[2]
	sqrdmulh	v23.4s, v11.4s, v0.s[2]
	sqrdmulh	v24.4s, v12.4s, v0.s[2]
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v17.4s, v1.s[3]
	mul	v30.4s, v18.4s, v1.s[3]
	sqrdmulh	v25.4s, v17.4s, v0.s[3]
	sqrdmulh	v26.4s, v18.4s, v0.s[3]
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[3]
	mul	v30.4s, v20.4s, v1.s[3]
	sqrdmulh	v27.4s, v19.4s, v0.s[3]
	sqrdmulh	v28.4s, v20.4s, v0.s[3]
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v9.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v10.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v11.4s, v7.4s, v23.4s
	add	v7.4s, v7.4s, v23.4s
	sub	v12.4s, v8.4s, v24.4s
	add	v8.4s, v8.4s, v24.4s
	sub	v17.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v18.4s, v14.4s, v26.4s
	add	v14.4s, v14.4s, v26.4s
	sub	v19.4s, v15.4s, v27.4s
	add	v15.4s, v15.4s, v27.4s
	sub	v20.4s, v16.4s, v28.4s
	add	v16.4s, v16.4s, v28.4s
	ldr	q0, [x1, #16]
	ldr	q1, [x2, #16]
	mul	v29.4s, v7.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[0]
	sqrdmulh	v21.4s, v7.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[0]
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v11.4s, v1.s[1]
	mul	v30.4s, v12.4s, v1.s[1]
	sqrdmulh	v23.4s, v11.4s, v0.s[1]
	sqrdmulh	v24.4s, v12.4s, v0.s[1]
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v15.4s, v1.s[2]
	mul	v30.4s, v16.4s, v1.s[2]
	sqrdmulh	v25.4s, v15.4s, v0.s[2]
	sqrdmulh	v26.4s, v16.4s, v0.s[2]
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[3]
	mul	v30.4s, v20.4s, v1.s[3]
	sqrdmulh	v27.4s, v19.4s, v0.s[3]
	sqrdmulh	v28.4s, v20.4s, v0.s[3]
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v7.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v11.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v10.4s, v24.4s
	add	v10.4s, v10.4s, v24.4s
	sub	v15.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v14.4s, v26.4s
	add	v14.4s, v14.4s, v26.4s
	sub	v19.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v18.4s, v28.4s
	add	v18.4s, v18.4s, v28.4s
	ldp	q0, q2, [x1, #32]
	ldp	q1, q3, [x2, #32]
	mul	v29.4s, v6.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[1]
	sqrdmulh	v21.4s, v6.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[1]
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v10.4s, v1.s[2]
	mul	v30.4s, v12.4s, v1.s[3]
	sqrdmulh	v23.4s, v10.4s, v0.s[2]
	sqrdmulh	v24.4s, v12.4s, v0.s[3]
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v14.4s, v3.s[0]
	mul	v30.4s, v16.4s, v3.s[1]
	sqrdmulh	v25.4s, v14.4s, v2.s[0]
	sqrdmulh	v26.4s, v16.4s, v2.s[1]
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v18.4s, v3.s[2]
	mul	v30.4s, v20.4s, v3.s[3]
	sqrdmulh	v27.4s, v18.4s, v2.s[2]
	sqrdmulh	v28.4s, v20.4s, v2.s[3]
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	str	q5, [x0, #48]
	str	q6, [x0, #112]
	str	q7, [x0, #176]
	str	q8, [x0, #240]
	str	q9, [x0, #304]
	str	q10, [x0, #368]
	str	q11, [x0, #432]
	str	q12, [x0, #496]
	str	q13, [x0, #560]
	str	q14, [x0, #624]
	str	q15, [x0, #688]
	str	q16, [x0, #752]
	str	q17, [x0, #816]
	str	q18, [x0, #880]
	str	q19, [x0, #944]
	str	q20, [x0, #1008]
	ldp	q5, q6, [x0]
	ldp	q7, q8, [x0, #32]
	ldp	q9, q10, [x0, #64]
	ldp	q11, q12, [x0, #96]
	ldp	q13, q14, [x0, #128]
	ldp	q15, q16, [x0, #160]
	ldp	q17, q18, [x0, #192]
	ldp	q19, q20, [x0, #224]
	ldr	q0, [x1, #64]
	ldr	q1, [x2, #64]
	mul	v29.4s, v7.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[0]
	sqrdmulh	v21.4s, v7.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[0]
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v11.4s, v1.s[1]
	mul	v30.4s, v12.4s, v1.s[1]
	sqrdmulh	v23.4s, v11.4s, v0.s[1]
	sqrdmulh	v24.4s, v12.4s, v0.s[1]
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v15.4s, v1.s[2]
	mul	v30.4s, v16.4s, v1.s[2]
	sqrdmulh	v25.4s, v15.4s, v0.s[2]
	sqrdmulh	v26.4s, v16.4s, v0.s[2]
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[3]
	mul	v30.4s, v20.4s, v1.s[3]
	sqrdmulh	v27.4s, v19.4s, v0.s[3]
	sqrdmulh	v28.4s, v20.4s, v0.s[3]
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v7.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v11.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v10.4s, v24.4s
	add	v10.4s, v10.4s, v24.4s
	sub	v15.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v14.4s, v26.4s
	add	v14.4s, v14.4s, v26.4s
	sub	v19.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v18.4s, v28.4s
	add	v18.4s, v18.4s, v28.4s
	ldp	q0, q2, [x1, #128]
	ldp	q1, q3, [x2, #128]
	mul	v29.4s, v6.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[1]
	sqrdmulh	v21.4s, v6.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[1]
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v10.4s, v1.s[2]
	mul	v30.4s, v12.4s, v1.s[3]
	sqrdmulh	v23.4s, v10.4s, v0.s[2]
	sqrdmulh	v24.4s, v12.4s, v0.s[3]
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v14.4s, v3.s[0]
	mul	v30.4s, v16.4s, v3.s[1]
	sqrdmulh	v25.4s, v14.4s, v2.s[0]
	sqrdmulh	v26.4s, v16.4s, v2.s[1]
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v18.4s, v3.s[2]
	mul	v30.4s, v20.4s, v3.s[3]
	sqrdmulh	v27.4s, v18.4s, v2.s[2]
	sqrdmulh	v28.4s, v20.4s, v2.s[3]
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	ldp	q0, q2, [x1, #256]
	ldp	q1, q3, [x2, #256]
	mov	v29.16b, v5.16b
	mov	v30.16b, v7.16b
	trn1	v5.2d, v5.2d, v6.2d
	trn1	v7.2d, v7.2d, v8.2d
	trn2	v6.2d, v29.2d, v6.2d
	trn2	v8.2d, v30.2d, v8.2d
	mul	v29.4s, v6.4s, v1.4s
	mul	v30.4s, v8.4s, v3.4s
	sqrdmulh	v21.4s, v6.4s, v0.4s
	sqrdmulh	v22.4s, v8.4s, v2.4s
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	ldp	q0, q2, [x1, #288]
	ldp	q1, q3, [x2, #288]
	mov	v29.16b, v9.16b
	mov	v30.16b, v11.16b
	trn1	v9.2d, v9.2d, v10.2d
	trn1	v11.2d, v11.2d, v12.2d
	trn2	v10.2d, v29.2d, v10.2d
	trn2	v12.2d, v30.2d, v12.2d
	mul	v29.4s, v10.4s, v1.4s
	mul	v30.4s, v12.4s, v3.4s
	sqrdmulh	v23.4s, v10.4s, v0.4s
	sqrdmulh	v24.4s, v12.4s, v2.4s
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	ldp	q0, q2, [x1, #320]
	ldp	q1, q3, [x2, #320]
	mov	v29.16b, v13.16b
	mov	v30.16b, v15.16b
	trn1	v13.2d, v13.2d, v14.2d
	trn1	v15.2d, v15.2d, v16.2d
	trn2	v14.2d, v29.2d, v14.2d
	trn2	v16.2d, v30.2d, v16.2d
	mul	v29.4s, v14.4s, v1.4s
	mul	v30.4s, v16.4s, v3.4s
	sqrdmulh	v25.4s, v14.4s, v0.4s
	sqrdmulh	v26.4s, v16.4s, v2.4s
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	ldp	q0, q2, [x1, #352]
	ldp	q1, q3, [x2, #352]
	mov	v29.16b, v17.16b
	mov	v30.16b, v19.16b
	trn1	v17.2d, v17.2d, v18.2d
	trn1	v19.2d, v19.2d, v20.2d
	trn2	v18.2d, v29.2d, v18.2d
	trn2	v20.2d, v30.2d, v20.2d
	mul	v29.4s, v18.4s, v1.4s
	mul	v30.4s, v20.4s, v3.4s
	sqrdmulh	v27.4s, v18.4s, v0.4s
	sqrdmulh	v28.4s, v20.4s, v2.4s
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	ldp	q0, q2, [x1, #768]
	ldp	q1, q3, [x2, #768]
	mov	v29.16b, v5.16b
	mov	v30.16b, v7.16b
	trn1	v5.4s, v5.4s, v6.4s
	trn1	v7.4s, v7.4s, v8.4s
	trn2	v6.4s, v29.4s, v6.4s
	trn2	v8.4s, v30.4s, v8.4s
	mul	v29.4s, v6.4s, v1.4s
	mul	v30.4s, v8.4s, v3.4s
	sqrdmulh	v21.4s, v6.4s, v0.4s
	sqrdmulh	v22.4s, v8.4s, v2.4s
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	ldp	q0, q2, [x1, #800]
	ldp	q1, q3, [x2, #800]
	mov	v29.16b, v9.16b
	mov	v30.16b, v11.16b
	trn1	v9.4s, v9.4s, v10.4s
	trn1	v11.4s, v11.4s, v12.4s
	trn2	v10.4s, v29.4s, v10.4s
	trn2	v12.4s, v30.4s, v12.4s
	mul	v29.4s, v10.4s, v1.4s
	mul	v30.4s, v12.4s, v3.4s
	sqrdmulh	v23.4s, v10.4s, v0.4s
	sqrdmulh	v24.4s, v12.4s, v2.4s
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	ldp	q0, q2, [x1, #832]
	ldp	q1, q3, [x2, #832]
	mov	v29.16b, v13.16b
	mov	v30.16b, v15.16b
	trn1	v13.4s, v13.4s, v14.4s
	trn1	v15.4s, v15.4s, v16.4s
	trn2	v14.4s, v29.4s, v14.4s
	trn2	v16.4s, v30.4s, v16.4s
	mul	v29.4s, v14.4s, v1.4s
	mul	v30.4s, v16.4s, v3.4s
	sqrdmulh	v25.4s, v14.4s, v0.4s
	sqrdmulh	v26.4s, v16.4s, v2.4s
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	ldp	q0, q2, [x1, #864]
	ldp	q1, q3, [x2, #864]
	mov	v29.16b, v17.16b
	mov	v30.16b, v19.16b
	trn1	v17.4s, v17.4s, v18.4s
	trn1	v19.4s, v19.4s, v20.4s
	trn2	v18.4s, v29.4s, v18.4s
	trn2	v20.4s, v30.4s, v20.4s
	mul	v29.4s, v18.4s, v1.4s
	mul	v30.4s, v20.4s, v3.4s
	sqrdmulh	v27.4s, v18.4s, v0.4s
	sqrdmulh	v28.4s, v20.4s, v2.4s
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	stp	q5, q6, [x0]
	stp	q7, q8, [x0, #32]
	stp	q9, q10, [x0, #64]
	stp	q11, q12, [x0, #96]
	stp	q13, q14, [x0, #128]
	stp	q15, q16, [x0, #160]
	stp	q17, q18, [x0, #192]
	stp	q19, q20, [x0, #224]
	ldp	q5, q6, [x0, #256]
	ldp	q7, q8, [x0, #288]
	ldp	q9, q10, [x0, #320]
	ldp	q11, q12, [x0, #352]
	ldp	q13, q14, [x0, #384]
	ldp	q15, q16, [x0, #416]
	ldp	q17, q18, [x0, #448]
	ldp	q19, q20, [x0, #480]
	ldr	q0, [x1, #80]
	ldr	q1, [x2, #80]
	mul	v29.4s, v7.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[0]
	sqrdmulh	v21.4s, v7.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[0]
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v11.4s, v1.s[1]
	mul	v30.4s, v12.4s, v1.s[1]
	sqrdmulh	v23.4s, v11.4s, v0.s[1]
	sqrdmulh	v24.4s, v12.4s, v0.s[1]
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v15.4s, v1.s[2]
	mul	v30.4s, v16.4s, v1.s[2]
	sqrdmulh	v25.4s, v15.4s, v0.s[2]
	sqrdmulh	v26.4s, v16.4s, v0.s[2]
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[3]
	mul	v30.4s, v20.4s, v1.s[3]
	sqrdmulh	v27.4s, v19.4s, v0.s[3]
	sqrdmulh	v28.4s, v20.4s, v0.s[3]
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v7.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v11.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v10.4s, v24.4s
	add	v10.4s, v10.4s, v24.4s
	sub	v15.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v14.4s, v26.4s
	add	v14.4s, v14.4s, v26.4s
	sub	v19.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v18.4s, v28.4s
	add	v18.4s, v18.4s, v28.4s
	ldp	q0, q2, [x1, #160]
	ldp	q1, q3, [x2, #160]
	mul	v29.4s, v6.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[1]
	sqrdmulh	v21.4s, v6.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[1]
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v10.4s, v1.s[2]
	mul	v30.4s, v12.4s, v1.s[3]
	sqrdmulh	v23.4s, v10.4s, v0.s[2]
	sqrdmulh	v24.4s, v12.4s, v0.s[3]
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v14.4s, v3.s[0]
	mul	v30.4s, v16.4s, v3.s[1]
	sqrdmulh	v25.4s, v14.4s, v2.s[0]
	sqrdmulh	v26.4s, v16.4s, v2.s[1]
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v18.4s, v3.s[2]
	mul	v30.4s, v20.4s, v3.s[3]
	sqrdmulh	v27.4s, v18.4s, v2.s[2]
	sqrdmulh	v28.4s, v20.4s, v2.s[3]
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	ldp	q0, q2, [x1, #384]
	ldp	q1, q3, [x2, #384]
	mov	v29.16b, v5.16b
	mov	v30.16b, v7.16b
	trn1	v5.2d, v5.2d, v6.2d
	trn1	v7.2d, v7.2d, v8.2d
	trn2	v6.2d, v29.2d, v6.2d
	trn2	v8.2d, v30.2d, v8.2d
	mul	v29.4s, v6.4s, v1.4s
	mul	v30.4s, v8.4s, v3.4s
	sqrdmulh	v21.4s, v6.4s, v0.4s
	sqrdmulh	v22.4s, v8.4s, v2.4s
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	ldp	q0, q2, [x1, #416]
	ldp	q1, q3, [x2, #416]
	mov	v29.16b, v9.16b
	mov	v30.16b, v11.16b
	trn1	v9.2d, v9.2d, v10.2d
	trn1	v11.2d, v11.2d, v12.2d
	trn2	v10.2d, v29.2d, v10.2d
	trn2	v12.2d, v30.2d, v12.2d
	mul	v29.4s, v10.4s, v1.4s
	mul	v30.4s, v12.4s, v3.4s
	sqrdmulh	v23.4s, v10.4s, v0.4s
	sqrdmulh	v24.4s, v12.4s, v2.4s
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	ldp	q0, q2, [x1, #448]
	ldp	q1, q3, [x2, #448]
	mov	v29.16b, v13.16b
	mov	v30.16b, v15.16b
	trn1	v13.2d, v13.2d, v14.2d
	trn1	v15.2d, v15.2d, v16.2d
	trn2	v14.2d, v29.2d, v14.2d
	trn2	v16.2d, v30.2d, v16.2d
	mul	v29.4s, v14.4s, v1.4s
	mul	v30.4s, v16.4s, v3.4s
	sqrdmulh	v25.4s, v14.4s, v0.4s
	sqrdmulh	v26.4s, v16.4s, v2.4s
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	ldp	q0, q2, [x1, #480]
	ldp	q1, q3, [x2, #480]
	mov	v29.16b, v17.16b
	mov	v30.16b, v19.16b
	trn1	v17.2d, v17.2d, v18.2d
	trn1	v19.2d, v19.2d, v20.2d
	trn2	v18.2d, v29.2d, v18.2d
	trn2	v20.2d, v30.2d, v20.2d
	mul	v29.4s, v18.4s, v1.4s
	mul	v30.4s, v20.4s, v3.4s
	sqrdmulh	v27.4s, v18.4s, v0.4s
	sqrdmulh	v28.4s, v20.4s, v2.4s
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	ldp	q0, q2, [x1, #896]
	ldp	q1, q3, [x2, #896]
	mov	v29.16b, v5.16b
	mov	v30.16b, v7.16b
	trn1	v5.4s, v5.4s, v6.4s
	trn1	v7.4s, v7.4s, v8.4s
	trn2	v6.4s, v29.4s, v6.4s
	trn2	v8.4s, v30.4s, v8.4s
	mul	v29.4s, v6.4s, v1.4s
	mul	v30.4s, v8.4s, v3.4s
	sqrdmulh	v21.4s, v6.4s, v0.4s
	sqrdmulh	v22.4s, v8.4s, v2.4s
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	ldp	q0, q2, [x1, #928]
	ldp	q1, q3, [x2, #928]
	mov	v29.16b, v9.16b
	mov	v30.16b, v11.16b
	trn1	v9.4s, v9.4s, v10.4s
	trn1	v11.4s, v11.4s, v12.4s
	trn2	v10.4s, v29.4s, v10.4s
	trn2	v12.4s, v30.4s, v12.4s
	mul	v29.4s, v10.4s, v1.4s
	mul	v30.4s, v12.4s, v3.4s
	sqrdmulh	v23.4s, v10.4s, v0.4s
	sqrdmulh	v24.4s, v12.4s, v2.4s
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	ldp	q0, q2, [x1, #960]
	ldp	q1, q3, [x2, #960]
	mov	v29.16b, v13.16b
	mov	v30.16b, v15.16b
	trn1	v13.4s, v13.4s, v14.4s
	trn1	v15.4s, v15.4s, v16.4s
	trn2	v14.4s, v29.4s, v14.4s
	trn2	v16.4s, v30.4s, v16.4s
	mul	v29.4s, v14.4s, v1.4s
	mul	v30.4s, v16.4s, v3.4s
	sqrdmulh	v25.4s, v14.4s, v0.4s
	sqrdmulh	v26.4s, v16.4s, v2.4s
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	ldp	q0, q2, [x1, #992]
	ldp	q1, q3, [x2, #992]
	mov	v29.16b, v17.16b
	mov	v30.16b, v19.16b
	trn1	v17.4s, v17.4s, v18.4s
	trn1	v19.4s, v19.4s, v20.4s
	trn2	v18.4s, v29.4s, v18.4s
	trn2	v20.4s, v30.4s, v20.4s
	mul	v29.4s, v18.4s, v1.4s
	mul	v30.4s, v20.4s, v3.4s
	sqrdmulh	v27.4s, v18.4s, v0.4s
	sqrdmulh	v28.4s, v20.4s, v2.4s
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	stp	q5, q6, [x0, #256]
	stp	q7, q8, [x0, #288]
	stp	q9, q10, [x0, #320]
	stp	q11, q12, [x0, #352]
	stp	q13, q14, [x0, #384]
	stp	q15, q16, [x0, #416]
	stp	q17, q18, [x0, #448]
	stp	q19, q20, [x0, #480]
	ldp	q5, q6, [x0, #512]
	ldp	q7, q8, [x0, #544]
	ldp	q9, q10, [x0, #576]
	ldp	q11, q12, [x0, #608]
	ldp	q13, q14, [x0, #640]
	ldp	q15, q16, [x0, #672]
	ldp	q17, q18, [x0, #704]
	ldp	q19, q20, [x0, #736]
	ldr	q0, [x1, #96]
	ldr	q1, [x2, #96]
	mul	v29.4s, v7.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[0]
	sqrdmulh	v21.4s, v7.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[0]
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v11.4s, v1.s[1]
	mul	v30.4s, v12.4s, v1.s[1]
	sqrdmulh	v23.4s, v11.4s, v0.s[1]
	sqrdmulh	v24.4s, v12.4s, v0.s[1]
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v15.4s, v1.s[2]
	mul	v30.4s, v16.4s, v1.s[2]
	sqrdmulh	v25.4s, v15.4s, v0.s[2]
	sqrdmulh	v26.4s, v16.4s, v0.s[2]
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[3]
	mul	v30.4s, v20.4s, v1.s[3]
	sqrdmulh	v27.4s, v19.4s, v0.s[3]
	sqrdmulh	v28.4s, v20.4s, v0.s[3]
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v7.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v11.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v10.4s, v24.4s
	add	v10.4s, v10.4s, v24.4s
	sub	v15.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v14.4s, v26.4s
	add	v14.4s, v14.4s, v26.4s
	sub	v19.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v18.4s, v28.4s
	add	v18.4s, v18.4s, v28.4s
	ldp	q0, q2, [x1, #192]
	ldp	q1, q3, [x2, #192]
	mul	v29.4s, v6.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[1]
	sqrdmulh	v21.4s, v6.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[1]
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v10.4s, v1.s[2]
	mul	v30.4s, v12.4s, v1.s[3]
	sqrdmulh	v23.4s, v10.4s, v0.s[2]
	sqrdmulh	v24.4s, v12.4s, v0.s[3]
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v14.4s, v3.s[0]
	mul	v30.4s, v16.4s, v3.s[1]
	sqrdmulh	v25.4s, v14.4s, v2.s[0]
	sqrdmulh	v26.4s, v16.4s, v2.s[1]
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v18.4s, v3.s[2]
	mul	v30.4s, v20.4s, v3.s[3]
	sqrdmulh	v27.4s, v18.4s, v2.s[2]
	sqrdmulh	v28.4s, v20.4s, v2.s[3]
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	ldp	q0, q2, [x1, #512]
	ldp	q1, q3, [x2, #512]
	mov	v29.16b, v5.16b
	mov	v30.16b, v7.16b
	trn1	v5.2d, v5.2d, v6.2d
	trn1	v7.2d, v7.2d, v8.2d
	trn2	v6.2d, v29.2d, v6.2d
	trn2	v8.2d, v30.2d, v8.2d
	mul	v29.4s, v6.4s, v1.4s
	mul	v30.4s, v8.4s, v3.4s
	sqrdmulh	v21.4s, v6.4s, v0.4s
	sqrdmulh	v22.4s, v8.4s, v2.4s
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	ldp	q0, q2, [x1, #544]
	ldp	q1, q3, [x2, #544]
	mov	v29.16b, v9.16b
	mov	v30.16b, v11.16b
	trn1	v9.2d, v9.2d, v10.2d
	trn1	v11.2d, v11.2d, v12.2d
	trn2	v10.2d, v29.2d, v10.2d
	trn2	v12.2d, v30.2d, v12.2d
	mul	v29.4s, v10.4s, v1.4s
	mul	v30.4s, v12.4s, v3.4s
	sqrdmulh	v23.4s, v10.4s, v0.4s
	sqrdmulh	v24.4s, v12.4s, v2.4s
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	ldp	q0, q2, [x1, #576]
	ldp	q1, q3, [x2, #576]
	mov	v29.16b, v13.16b
	mov	v30.16b, v15.16b
	trn1	v13.2d, v13.2d, v14.2d
	trn1	v15.2d, v15.2d, v16.2d
	trn2	v14.2d, v29.2d, v14.2d
	trn2	v16.2d, v30.2d, v16.2d
	mul	v29.4s, v14.4s, v1.4s
	mul	v30.4s, v16.4s, v3.4s
	sqrdmulh	v25.4s, v14.4s, v0.4s
	sqrdmulh	v26.4s, v16.4s, v2.4s
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	ldp	q0, q2, [x1, #608]
	ldp	q1, q3, [x2, #608]
	mov	v29.16b, v17.16b
	mov	v30.16b, v19.16b
	trn1	v17.2d, v17.2d, v18.2d
	trn1	v19.2d, v19.2d, v20.2d
	trn2	v18.2d, v29.2d, v18.2d
	trn2	v20.2d, v30.2d, v20.2d
	mul	v29.4s, v18.4s, v1.4s
	mul	v30.4s, v20.4s, v3.4s
	sqrdmulh	v27.4s, v18.4s, v0.4s
	sqrdmulh	v28.4s, v20.4s, v2.4s
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	ldr	q0, [x1, #1024]
	ldr	q2, [x1, #1040]
	ldr	q1, [x2, #1024]
	ldr	q3, [x2, #1040]
	mov	v29.16b, v5.16b
	mov	v30.16b, v7.16b
	trn1	v5.4s, v5.4s, v6.4s
	trn1	v7.4s, v7.4s, v8.4s
	trn2	v6.4s, v29.4s, v6.4s
	trn2	v8.4s, v30.4s, v8.4s
	mul	v29.4s, v6.4s, v1.4s
	mul	v30.4s, v8.4s, v3.4s
	sqrdmulh	v21.4s, v6.4s, v0.4s
	sqrdmulh	v22.4s, v8.4s, v2.4s
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	ldr	q0, [x1, #1056]
	ldr	q2, [x1, #1072]
	ldr	q1, [x2, #1056]
	ldr	q3, [x2, #1072]
	mov	v29.16b, v9.16b
	mov	v30.16b, v11.16b
	trn1	v9.4s, v9.4s, v10.4s
	trn1	v11.4s, v11.4s, v12.4s
	trn2	v10.4s, v29.4s, v10.4s
	trn2	v12.4s, v30.4s, v12.4s
	mul	v29.4s, v10.4s, v1.4s
	mul	v30.4s, v12.4s, v3.4s
	sqrdmulh	v23.4s, v10.4s, v0.4s
	sqrdmulh	v24.4s, v12.4s, v2.4s
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	ldr	q0, [x1, #1088]
	ldr	q2, [x1, #1104]
	ldr	q1, [x2, #1088]
	ldr	q3, [x2, #1104]
	mov	v29.16b, v13.16b
	mov	v30.16b, v15.16b
	trn1	v13.4s, v13.4s, v14.4s
	trn1	v15.4s, v15.4s, v16.4s
	trn2	v14.4s, v29.4s, v14.4s
	trn2	v16.4s, v30.4s, v16.4s
	mul	v29.4s, v14.4s, v1.4s
	mul	v30.4s, v16.4s, v3.4s
	sqrdmulh	v25.4s, v14.4s, v0.4s
	sqrdmulh	v26.4s, v16.4s, v2.4s
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	ldr	q0, [x1, #1120]
	ldr	q2, [x1, #1136]
	ldr	q1, [x2, #1120]
	ldr	q3, [x2, #1136]
	mov	v29.16b, v17.16b
	mov	v30.16b, v19.16b
	trn1	v17.4s, v17.4s, v18.4s
	trn1	v19.4s, v19.4s, v20.4s
	trn2	v18.4s, v29.4s, v18.4s
	trn2	v20.4s, v30.4s, v20.4s
	mul	v29.4s, v18.4s, v1.4s
	mul	v30.4s, v20.4s, v3.4s
	sqrdmulh	v27.4s, v18.4s, v0.4s
	sqrdmulh	v28.4s, v20.4s, v2.4s
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	stp	q5, q6, [x0, #512]
	stp	q7, q8, [x0, #544]
	stp	q9, q10, [x0, #576]
	stp	q11, q12, [x0, #608]
	stp	q13, q14, [x0, #640]
	stp	q15, q16, [x0, #672]
	stp	q17, q18, [x0, #704]
	stp	q19, q20, [x0, #736]
	ldp	q5, q6, [x0, #768]
	ldp	q7, q8, [x0, #800]
	ldp	q9, q10, [x0, #832]
	ldp	q11, q12, [x0, #864]
	ldp	q13, q14, [x0, #896]
	ldp	q15, q16, [x0, #928]
	ldp	q17, q18, [x0, #960]
	ldp	q19, q20, [x0, #992]
	ldr	q0, [x1, #112]
	ldr	q1, [x2, #112]
	mul	v29.4s, v7.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[0]
	sqrdmulh	v21.4s, v7.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[0]
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v11.4s, v1.s[1]
	mul	v30.4s, v12.4s, v1.s[1]
	sqrdmulh	v23.4s, v11.4s, v0.s[1]
	sqrdmulh	v24.4s, v12.4s, v0.s[1]
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v15.4s, v1.s[2]
	mul	v30.4s, v16.4s, v1.s[2]
	sqrdmulh	v25.4s, v15.4s, v0.s[2]
	sqrdmulh	v26.4s, v16.4s, v0.s[2]
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[3]
	mul	v30.4s, v20.4s, v1.s[3]
	sqrdmulh	v27.4s, v19.4s, v0.s[3]
	sqrdmulh	v28.4s, v20.4s, v0.s[3]
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v7.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v11.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v10.4s, v24.4s
	add	v10.4s, v10.4s, v24.4s
	sub	v15.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v14.4s, v26.4s
	add	v14.4s, v14.4s, v26.4s
	sub	v19.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v18.4s, v28.4s
	add	v18.4s, v18.4s, v28.4s
	ldp	q0, q2, [x1, #224]
	ldp	q1, q3, [x2, #224]
	mul	v29.4s, v6.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[1]
	sqrdmulh	v21.4s, v6.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[1]
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v10.4s, v1.s[2]
	mul	v30.4s, v12.4s, v1.s[3]
	sqrdmulh	v23.4s, v10.4s, v0.s[2]
	sqrdmulh	v24.4s, v12.4s, v0.s[3]
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v14.4s, v3.s[0]
	mul	v30.4s, v16.4s, v3.s[1]
	sqrdmulh	v25.4s, v14.4s, v2.s[0]
	sqrdmulh	v26.4s, v16.4s, v2.s[1]
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v18.4s, v3.s[2]
	mul	v30.4s, v20.4s, v3.s[3]
	sqrdmulh	v27.4s, v18.4s, v2.s[2]
	sqrdmulh	v28.4s, v20.4s, v2.s[3]
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	ldp	q0, q2, [x1, #640]
	ldp	q1, q3, [x2, #640]
	mov	v29.16b, v5.16b
	mov	v30.16b, v7.16b
	trn1	v5.2d, v5.2d, v6.2d
	trn1	v7.2d, v7.2d, v8.2d
	trn2	v6.2d, v29.2d, v6.2d
	trn2	v8.2d, v30.2d, v8.2d
	mul	v29.4s, v6.4s, v1.4s
	mul	v30.4s, v8.4s, v3.4s
	sqrdmulh	v21.4s, v6.4s, v0.4s
	sqrdmulh	v22.4s, v8.4s, v2.4s
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	ldp	q0, q2, [x1, #672]
	ldp	q1, q3, [x2, #672]
	mov	v29.16b, v9.16b
	mov	v30.16b, v11.16b
	trn1	v9.2d, v9.2d, v10.2d
	trn1	v11.2d, v11.2d, v12.2d
	trn2	v10.2d, v29.2d, v10.2d
	trn2	v12.2d, v30.2d, v12.2d
	mul	v29.4s, v10.4s, v1.4s
	mul	v30.4s, v12.4s, v3.4s
	sqrdmulh	v23.4s, v10.4s, v0.4s
	sqrdmulh	v24.4s, v12.4s, v2.4s
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	ldp	q0, q2, [x1, #704]
	ldp	q1, q3, [x2, #704]
	mov	v29.16b, v13.16b
	mov	v30.16b, v15.16b
	trn1	v13.2d, v13.2d, v14.2d
	trn1	v15.2d, v15.2d, v16.2d
	trn2	v14.2d, v29.2d, v14.2d
	trn2	v16.2d, v30.2d, v16.2d
	mul	v29.4s, v14.4s, v1.4s
	mul	v30.4s, v16.4s, v3.4s
	sqrdmulh	v25.4s, v14.4s, v0.4s
	sqrdmulh	v26.4s, v16.4s, v2.4s
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	ldp	q0, q2, [x1, #736]
	ldp	q1, q3, [x2, #736]
	mov	v29.16b, v17.16b
	mov	v30.16b, v19.16b
	trn1	v17.2d, v17.2d, v18.2d
	trn1	v19.2d, v19.2d, v20.2d
	trn2	v18.2d, v29.2d, v18.2d
	trn2	v20.2d, v30.2d, v20.2d
	mul	v29.4s, v18.4s, v1.4s
	mul	v30.4s, v20.4s, v3.4s
	sqrdmulh	v27.4s, v18.4s, v0.4s
	sqrdmulh	v28.4s, v20.4s, v2.4s
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	ldr	q0, [x1, #1152]
	ldr	q2, [x1, #1168]
	ldr	q1, [x2, #1152]
	ldr	q3, [x2, #1168]
	mov	v29.16b, v5.16b
	mov	v30.16b, v7.16b
	trn1	v5.4s, v5.4s, v6.4s
	trn1	v7.4s, v7.4s, v8.4s
	trn2	v6.4s, v29.4s, v6.4s
	trn2	v8.4s, v30.4s, v8.4s
	mul	v29.4s, v6.4s, v1.4s
	mul	v30.4s, v8.4s, v3.4s
	sqrdmulh	v21.4s, v6.4s, v0.4s
	sqrdmulh	v22.4s, v8.4s, v2.4s
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	ldr	q0, [x1, #1184]
	ldr	q2, [x1, #1200]
	ldr	q1, [x2, #1184]
	ldr	q3, [x2, #1200]
	mov	v29.16b, v9.16b
	mov	v30.16b, v11.16b
	trn1	v9.4s, v9.4s, v10.4s
	trn1	v11.4s, v11.4s, v12.4s
	trn2	v10.4s, v29.4s, v10.4s
	trn2	v12.4s, v30.4s, v12.4s
	mul	v29.4s, v10.4s, v1.4s
	mul	v30.4s, v12.4s, v3.4s
	sqrdmulh	v23.4s, v10.4s, v0.4s
	sqrdmulh	v24.4s, v12.4s, v2.4s
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	ldr	q0, [x1, #1216]
	ldr	q2, [x1, #1232]
	ldr	q1, [x2, #1216]
	ldr	q3, [x2, #1232]
	mov	v29.16b, v13.16b
	mov	v30.16b, v15.16b
	trn1	v13.4s, v13.4s, v14.4s
	trn1	v15.4s, v15.4s, v16.4s
	trn2	v14.4s, v29.4s, v14.4s
	trn2	v16.4s, v30.4s, v16.4s
	mul	v29.4s, v14.4s, v1.4s
	mul	v30.4s, v16.4s, v3.4s
	sqrdmulh	v25.4s, v14.4s, v0.4s
	sqrdmulh	v26.4s, v16.4s, v2.4s
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	ldr	q0, [x1, #1248]
	ldr	q2, [x1, #1264]
	ldr	q1, [x2, #1248]
	ldr	q3, [x2, #1264]
	mov	v29.16b, v17.16b
	mov	v30.16b, v19.16b
	trn1	v17.4s, v17.4s, v18.4s
	trn1	v19.4s, v19.4s, v20.4s
	trn2	v18.4s, v29.4s, v18.4s
	trn2	v20.4s, v30.4s, v20.4s
	mul	v29.4s, v18.4s, v1.4s
	mul	v30.4s, v20.4s, v3.4s
	sqrdmulh	v27.4s, v18.4s, v0.4s
	sqrdmulh	v28.4s, v20.4s, v2.4s
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	stp	q5, q6, [x0, #768]
	stp	q7, q8, [x0, #800]
	stp	q9, q10, [x0, #832]
	stp	q11, q12, [x0, #864]
	stp	q13, q14, [x0, #896]
	stp	q15, q16, [x0, #928]
	stp	q17, q18, [x0, #960]
	stp	q19, q20, [x0, #992]
	ldp	d8, d9, [x29, #16]
	ldp	d10, d11, [x29, #32]
	ldp	d12, d13, [x29, #48]
	ldp	d14, d15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
#ifndef __APPLE__
	.size	mldsa_ntt_sqrdmlsh_neon,.-mldsa_ntt_sqrdmlsh_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	mldsa_ntt_full_sqrdmlsh_neon
WC_ASM_ATT_HIDDEN(mldsa_ntt_full_sqrdmlsh_neon)
.type	mldsa_ntt_full_sqrdmlsh_neon,@function
.align	2
mldsa_ntt_full_sqrdmlsh_neon:
#else
.section	__TEXT,__text
.globl	_mldsa_ntt_full_sqrdmlsh_neon
WC_ASM_ATT_HIDDEN(_mldsa_ntt_full_sqrdmlsh_neon)
.p2align	2
_mldsa_ntt_full_sqrdmlsh_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
	stp	d12, d13, [x29, #48]
	stp	d14, d15, [x29, #64]
#ifndef __APPLE__
	adrp x1, L_mldsa_aarch64_zetas
	add  x1, x1, :lo12:L_mldsa_aarch64_zetas
#else
	adrp x1, L_mldsa_aarch64_zetas@PAGE
	add  x1, x1, L_mldsa_aarch64_zetas@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x2, L_mldsa_aarch64_zetas_qinv
	add  x2, x2, :lo12:L_mldsa_aarch64_zetas_qinv
#else
	adrp x2, L_mldsa_aarch64_zetas_qinv@PAGE
	add  x2, x2, L_mldsa_aarch64_zetas_qinv@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x3, L_mldsa_aarch64_consts
	add  x3, x3, :lo12:L_mldsa_aarch64_consts
#else
	adrp x3, L_mldsa_aarch64_consts@PAGE
	add  x3, x3, L_mldsa_aarch64_consts@PAGEOFF
#endif /* __APPLE__ */
	ldr	q4, [x3]
	ldr	q5, [x0]
	ldr	q6, [x0, #64]
	ldr	q7, [x0, #128]
	ldr	q8, [x0, #192]
	ldr	q9, [x0, #256]
	ldr	q10, [x0, #320]
	ldr	q11, [x0, #384]
	ldr	q12, [x0, #448]
	ldr	q13, [x0, #512]
	ldr	q14, [x0, #576]
	ldr	q15, [x0, #640]
	ldr	q16, [x0, #704]
	ldr	q17, [x0, #768]
	ldr	q18, [x0, #832]
	ldr	q19, [x0, #896]
	ldr	q20, [x0, #960]
	ldr	q0, [x1]
	ldr	q1, [x2]
	mul	v29.4s, v13.4s, v1.s[1]
	mul	v30.4s, v14.4s, v1.s[1]
	sqrdmulh	v21.4s, v13.4s, v0.s[1]
	sqrdmulh	v22.4s, v14.4s, v0.s[1]
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v15.4s, v1.s[1]
	mul	v30.4s, v16.4s, v1.s[1]
	sqrdmulh	v23.4s, v15.4s, v0.s[1]
	sqrdmulh	v24.4s, v16.4s, v0.s[1]
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v17.4s, v1.s[1]
	mul	v30.4s, v18.4s, v1.s[1]
	sqrdmulh	v25.4s, v17.4s, v0.s[1]
	sqrdmulh	v26.4s, v18.4s, v0.s[1]
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[1]
	mul	v30.4s, v20.4s, v1.s[1]
	sqrdmulh	v27.4s, v19.4s, v0.s[1]
	sqrdmulh	v28.4s, v20.4s, v0.s[1]
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v13.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v14.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v15.4s, v7.4s, v23.4s
	add	v7.4s, v7.4s, v23.4s
	sub	v16.4s, v8.4s, v24.4s
	add	v8.4s, v8.4s, v24.4s
	sub	v17.4s, v9.4s, v25.4s
	add	v9.4s, v9.4s, v25.4s
	sub	v18.4s, v10.4s, v26.4s
	add	v10.4s, v10.4s, v26.4s
	sub	v19.4s, v11.4s, v27.4s
	add	v11.4s, v11.4s, v27.4s
	sub	v20.4s, v12.4s, v28.4s
	add	v12.4s, v12.4s, v28.4s
	mul	v29.4s, v9.4s, v1.s[2]
	mul	v30.4s, v10.4s, v1.s[2]
	sqrdmulh	v21.4s, v9.4s, v0.s[2]
	sqrdmulh	v22.4s, v10.4s, v0.s[2]
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v11.4s, v1.s[2]
	mul	v30.4s, v12.4s, v1.s[2]
	sqrdmulh	v23.4s, v11.4s, v0.s[2]
	sqrdmulh	v24.4s, v12.4s, v0.s[2]
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v17.4s, v1.s[3]
	mul	v30.4s, v18.4s, v1.s[3]
	sqrdmulh	v25.4s, v17.4s, v0.s[3]
	sqrdmulh	v26.4s, v18.4s, v0.s[3]
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[3]
	mul	v30.4s, v20.4s, v1.s[3]
	sqrdmulh	v27.4s, v19.4s, v0.s[3]
	sqrdmulh	v28.4s, v20.4s, v0.s[3]
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v9.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v10.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v11.4s, v7.4s, v23.4s
	add	v7.4s, v7.4s, v23.4s
	sub	v12.4s, v8.4s, v24.4s
	add	v8.4s, v8.4s, v24.4s
	sub	v17.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v18.4s, v14.4s, v26.4s
	add	v14.4s, v14.4s, v26.4s
	sub	v19.4s, v15.4s, v27.4s
	add	v15.4s, v15.4s, v27.4s
	sub	v20.4s, v16.4s, v28.4s
	add	v16.4s, v16.4s, v28.4s
	ldr	q0, [x1, #16]
	ldr	q1, [x2, #16]
	mul	v29.4s, v7.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[0]
	sqrdmulh	v21.4s, v7.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[0]
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v11.4s, v1.s[1]
	mul	v30.4s, v12.4s, v1.s[1]
	sqrdmulh	v23.4s, v11.4s, v0.s[1]
	sqrdmulh	v24.4s, v12.4s, v0.s[1]
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v15.4s, v1.s[2]
	mul	v30.4s, v16.4s, v1.s[2]
	sqrdmulh	v25.4s, v15.4s, v0.s[2]
	sqrdmulh	v26.4s, v16.4s, v0.s[2]
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[3]
	mul	v30.4s, v20.4s, v1.s[3]
	sqrdmulh	v27.4s, v19.4s, v0.s[3]
	sqrdmulh	v28.4s, v20.4s, v0.s[3]
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v7.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v11.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v10.4s, v24.4s
	add	v10.4s, v10.4s, v24.4s
	sub	v15.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v14.4s, v26.4s
	add	v14.4s, v14.4s, v26.4s
	sub	v19.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v18.4s, v28.4s
	add	v18.4s, v18.4s, v28.4s
	ldp	q0, q2, [x1, #32]
	ldp	q1, q3, [x2, #32]
	mul	v29.4s, v6.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[1]
	sqrdmulh	v21.4s, v6.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[1]
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v10.4s, v1.s[2]
	mul	v30.4s, v12.4s, v1.s[3]
	sqrdmulh	v23.4s, v10.4s, v0.s[2]
	sqrdmulh	v24.4s, v12.4s, v0.s[3]
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v14.4s, v3.s[0]
	mul	v30.4s, v16.4s, v3.s[1]
	sqrdmulh	v25.4s, v14.4s, v2.s[0]
	sqrdmulh	v26.4s, v16.4s, v2.s[1]
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v18.4s, v3.s[2]
	mul	v30.4s, v20.4s, v3.s[3]
	sqrdmulh	v27.4s, v18.4s, v2.s[2]
	sqrdmulh	v28.4s, v20.4s, v2.s[3]
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	str	q5, [x0]
	str	q6, [x0, #64]
	str	q7, [x0, #128]
	str	q8, [x0, #192]
	str	q9, [x0, #256]
	str	q10, [x0, #320]
	str	q11, [x0, #384]
	str	q12, [x0, #448]
	str	q13, [x0, #512]
	str	q14, [x0, #576]
	str	q15, [x0, #640]
	str	q16, [x0, #704]
	str	q17, [x0, #768]
	str	q18, [x0, #832]
	str	q19, [x0, #896]
	str	q20, [x0, #960]
	ldr	q5, [x0, #16]
	ldr	q6, [x0, #80]
	ldr	q7, [x0, #144]
	ldr	q8, [x0, #208]
	ldr	q9, [x0, #272]
	ldr	q10, [x0, #336]
	ldr	q11, [x0, #400]
	ldr	q12, [x0, #464]
	ldr	q13, [x0, #528]
	ldr	q14, [x0, #592]
	ldr	q15, [x0, #656]
	ldr	q16, [x0, #720]
	ldr	q17, [x0, #784]
	ldr	q18, [x0, #848]
	ldr	q19, [x0, #912]
	ldr	q20, [x0, #976]
	ldr	q0, [x1]
	ldr	q1, [x2]
	mul	v29.4s, v13.4s, v1.s[1]
	mul	v30.4s, v14.4s, v1.s[1]
	sqrdmulh	v21.4s, v13.4s, v0.s[1]
	sqrdmulh	v22.4s, v14.4s, v0.s[1]
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v15.4s, v1.s[1]
	mul	v30.4s, v16.4s, v1.s[1]
	sqrdmulh	v23.4s, v15.4s, v0.s[1]
	sqrdmulh	v24.4s, v16.4s, v0.s[1]
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v17.4s, v1.s[1]
	mul	v30.4s, v18.4s, v1.s[1]
	sqrdmulh	v25.4s, v17.4s, v0.s[1]
	sqrdmulh	v26.4s, v18.4s, v0.s[1]
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[1]
	mul	v30.4s, v20.4s, v1.s[1]
	sqrdmulh	v27.4s, v19.4s, v0.s[1]
	sqrdmulh	v28.4s, v20.4s, v0.s[1]
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v13.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v14.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v15.4s, v7.4s, v23.4s
	add	v7.4s, v7.4s, v23.4s
	sub	v16.4s, v8.4s, v24.4s
	add	v8.4s, v8.4s, v24.4s
	sub	v17.4s, v9.4s, v25.4s
	add	v9.4s, v9.4s, v25.4s
	sub	v18.4s, v10.4s, v26.4s
	add	v10.4s, v10.4s, v26.4s
	sub	v19.4s, v11.4s, v27.4s
	add	v11.4s, v11.4s, v27.4s
	sub	v20.4s, v12.4s, v28.4s
	add	v12.4s, v12.4s, v28.4s
	mul	v29.4s, v9.4s, v1.s[2]
	mul	v30.4s, v10.4s, v1.s[2]
	sqrdmulh	v21.4s, v9.4s, v0.s[2]
	sqrdmulh	v22.4s, v10.4s, v0.s[2]
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v11.4s, v1.s[2]
	mul	v30.4s, v12.4s, v1.s[2]
	sqrdmulh	v23.4s, v11.4s, v0.s[2]
	sqrdmulh	v24.4s, v12.4s, v0.s[2]
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v17.4s, v1.s[3]
	mul	v30.4s, v18.4s, v1.s[3]
	sqrdmulh	v25.4s, v17.4s, v0.s[3]
	sqrdmulh	v26.4s, v18.4s, v0.s[3]
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[3]
	mul	v30.4s, v20.4s, v1.s[3]
	sqrdmulh	v27.4s, v19.4s, v0.s[3]
	sqrdmulh	v28.4s, v20.4s, v0.s[3]
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v9.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v10.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v11.4s, v7.4s, v23.4s
	add	v7.4s, v7.4s, v23.4s
	sub	v12.4s, v8.4s, v24.4s
	add	v8.4s, v8.4s, v24.4s
	sub	v17.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v18.4s, v14.4s, v26.4s
	add	v14.4s, v14.4s, v26.4s
	sub	v19.4s, v15.4s, v27.4s
	add	v15.4s, v15.4s, v27.4s
	sub	v20.4s, v16.4s, v28.4s
	add	v16.4s, v16.4s, v28.4s
	ldr	q0, [x1, #16]
	ldr	q1, [x2, #16]
	mul	v29.4s, v7.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[0]
	sqrdmulh	v21.4s, v7.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[0]
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v11.4s, v1.s[1]
	mul	v30.4s, v12.4s, v1.s[1]
	sqrdmulh	v23.4s, v11.4s, v0.s[1]
	sqrdmulh	v24.4s, v12.4s, v0.s[1]
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v15.4s, v1.s[2]
	mul	v30.4s, v16.4s, v1.s[2]
	sqrdmulh	v25.4s, v15.4s, v0.s[2]
	sqrdmulh	v26.4s, v16.4s, v0.s[2]
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[3]
	mul	v30.4s, v20.4s, v1.s[3]
	sqrdmulh	v27.4s, v19.4s, v0.s[3]
	sqrdmulh	v28.4s, v20.4s, v0.s[3]
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v7.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v11.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v10.4s, v24.4s
	add	v10.4s, v10.4s, v24.4s
	sub	v15.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v14.4s, v26.4s
	add	v14.4s, v14.4s, v26.4s
	sub	v19.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v18.4s, v28.4s
	add	v18.4s, v18.4s, v28.4s
	ldp	q0, q2, [x1, #32]
	ldp	q1, q3, [x2, #32]
	mul	v29.4s, v6.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[1]
	sqrdmulh	v21.4s, v6.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[1]
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v10.4s, v1.s[2]
	mul	v30.4s, v12.4s, v1.s[3]
	sqrdmulh	v23.4s, v10.4s, v0.s[2]
	sqrdmulh	v24.4s, v12.4s, v0.s[3]
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v14.4s, v3.s[0]
	mul	v30.4s, v16.4s, v3.s[1]
	sqrdmulh	v25.4s, v14.4s, v2.s[0]
	sqrdmulh	v26.4s, v16.4s, v2.s[1]
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v18.4s, v3.s[2]
	mul	v30.4s, v20.4s, v3.s[3]
	sqrdmulh	v27.4s, v18.4s, v2.s[2]
	sqrdmulh	v28.4s, v20.4s, v2.s[3]
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	str	q5, [x0, #16]
	str	q6, [x0, #80]
	str	q7, [x0, #144]
	str	q8, [x0, #208]
	str	q9, [x0, #272]
	str	q10, [x0, #336]
	str	q11, [x0, #400]
	str	q12, [x0, #464]
	str	q13, [x0, #528]
	str	q14, [x0, #592]
	str	q15, [x0, #656]
	str	q16, [x0, #720]
	str	q17, [x0, #784]
	str	q18, [x0, #848]
	str	q19, [x0, #912]
	str	q20, [x0, #976]
	ldr	q5, [x0, #32]
	ldr	q6, [x0, #96]
	ldr	q7, [x0, #160]
	ldr	q8, [x0, #224]
	ldr	q9, [x0, #288]
	ldr	q10, [x0, #352]
	ldr	q11, [x0, #416]
	ldr	q12, [x0, #480]
	ldr	q13, [x0, #544]
	ldr	q14, [x0, #608]
	ldr	q15, [x0, #672]
	ldr	q16, [x0, #736]
	ldr	q17, [x0, #800]
	ldr	q18, [x0, #864]
	ldr	q19, [x0, #928]
	ldr	q20, [x0, #992]
	ldr	q0, [x1]
	ldr	q1, [x2]
	mul	v29.4s, v13.4s, v1.s[1]
	mul	v30.4s, v14.4s, v1.s[1]
	sqrdmulh	v21.4s, v13.4s, v0.s[1]
	sqrdmulh	v22.4s, v14.4s, v0.s[1]
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v15.4s, v1.s[1]
	mul	v30.4s, v16.4s, v1.s[1]
	sqrdmulh	v23.4s, v15.4s, v0.s[1]
	sqrdmulh	v24.4s, v16.4s, v0.s[1]
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v17.4s, v1.s[1]
	mul	v30.4s, v18.4s, v1.s[1]
	sqrdmulh	v25.4s, v17.4s, v0.s[1]
	sqrdmulh	v26.4s, v18.4s, v0.s[1]
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[1]
	mul	v30.4s, v20.4s, v1.s[1]
	sqrdmulh	v27.4s, v19.4s, v0.s[1]
	sqrdmulh	v28.4s, v20.4s, v0.s[1]
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v13.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v14.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v15.4s, v7.4s, v23.4s
	add	v7.4s, v7.4s, v23.4s
	sub	v16.4s, v8.4s, v24.4s
	add	v8.4s, v8.4s, v24.4s
	sub	v17.4s, v9.4s, v25.4s
	add	v9.4s, v9.4s, v25.4s
	sub	v18.4s, v10.4s, v26.4s
	add	v10.4s, v10.4s, v26.4s
	sub	v19.4s, v11.4s, v27.4s
	add	v11.4s, v11.4s, v27.4s
	sub	v20.4s, v12.4s, v28.4s
	add	v12.4s, v12.4s, v28.4s
	mul	v29.4s, v9.4s, v1.s[2]
	mul	v30.4s, v10.4s, v1.s[2]
	sqrdmulh	v21.4s, v9.4s, v0.s[2]
	sqrdmulh	v22.4s, v10.4s, v0.s[2]
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v11.4s, v1.s[2]
	mul	v30.4s, v12.4s, v1.s[2]
	sqrdmulh	v23.4s, v11.4s, v0.s[2]
	sqrdmulh	v24.4s, v12.4s, v0.s[2]
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v17.4s, v1.s[3]
	mul	v30.4s, v18.4s, v1.s[3]
	sqrdmulh	v25.4s, v17.4s, v0.s[3]
	sqrdmulh	v26.4s, v18.4s, v0.s[3]
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[3]
	mul	v30.4s, v20.4s, v1.s[3]
	sqrdmulh	v27.4s, v19.4s, v0.s[3]
	sqrdmulh	v28.4s, v20.4s, v0.s[3]
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v9.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v10.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v11.4s, v7.4s, v23.4s
	add	v7.4s, v7.4s, v23.4s
	sub	v12.4s, v8.4s, v24.4s
	add	v8.4s, v8.4s, v24.4s
	sub	v17.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v18.4s, v14.4s, v26.4s
	add	v14.4s, v14.4s, v26.4s
	sub	v19.4s, v15.4s, v27.4s
	add	v15.4s, v15.4s, v27.4s
	sub	v20.4s, v16.4s, v28.4s
	add	v16.4s, v16.4s, v28.4s
	ldr	q0, [x1, #16]
	ldr	q1, [x2, #16]
	mul	v29.4s, v7.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[0]
	sqrdmulh	v21.4s, v7.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[0]
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v11.4s, v1.s[1]
	mul	v30.4s, v12.4s, v1.s[1]
	sqrdmulh	v23.4s, v11.4s, v0.s[1]
	sqrdmulh	v24.4s, v12.4s, v0.s[1]
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v15.4s, v1.s[2]
	mul	v30.4s, v16.4s, v1.s[2]
	sqrdmulh	v25.4s, v15.4s, v0.s[2]
	sqrdmulh	v26.4s, v16.4s, v0.s[2]
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[3]
	mul	v30.4s, v20.4s, v1.s[3]
	sqrdmulh	v27.4s, v19.4s, v0.s[3]
	sqrdmulh	v28.4s, v20.4s, v0.s[3]
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v7.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v11.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v10.4s, v24.4s
	add	v10.4s, v10.4s, v24.4s
	sub	v15.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v14.4s, v26.4s
	add	v14.4s, v14.4s, v26.4s
	sub	v19.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v18.4s, v28.4s
	add	v18.4s, v18.4s, v28.4s
	ldp	q0, q2, [x1, #32]
	ldp	q1, q3, [x2, #32]
	mul	v29.4s, v6.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[1]
	sqrdmulh	v21.4s, v6.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[1]
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v10.4s, v1.s[2]
	mul	v30.4s, v12.4s, v1.s[3]
	sqrdmulh	v23.4s, v10.4s, v0.s[2]
	sqrdmulh	v24.4s, v12.4s, v0.s[3]
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v14.4s, v3.s[0]
	mul	v30.4s, v16.4s, v3.s[1]
	sqrdmulh	v25.4s, v14.4s, v2.s[0]
	sqrdmulh	v26.4s, v16.4s, v2.s[1]
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v18.4s, v3.s[2]
	mul	v30.4s, v20.4s, v3.s[3]
	sqrdmulh	v27.4s, v18.4s, v2.s[2]
	sqrdmulh	v28.4s, v20.4s, v2.s[3]
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	str	q5, [x0, #32]
	str	q6, [x0, #96]
	str	q7, [x0, #160]
	str	q8, [x0, #224]
	str	q9, [x0, #288]
	str	q10, [x0, #352]
	str	q11, [x0, #416]
	str	q12, [x0, #480]
	str	q13, [x0, #544]
	str	q14, [x0, #608]
	str	q15, [x0, #672]
	str	q16, [x0, #736]
	str	q17, [x0, #800]
	str	q18, [x0, #864]
	str	q19, [x0, #928]
	str	q20, [x0, #992]
	ldr	q5, [x0, #48]
	ldr	q6, [x0, #112]
	ldr	q7, [x0, #176]
	ldr	q8, [x0, #240]
	ldr	q9, [x0, #304]
	ldr	q10, [x0, #368]
	ldr	q11, [x0, #432]
	ldr	q12, [x0, #496]
	ldr	q13, [x0, #560]
	ldr	q14, [x0, #624]
	ldr	q15, [x0, #688]
	ldr	q16, [x0, #752]
	ldr	q17, [x0, #816]
	ldr	q18, [x0, #880]
	ldr	q19, [x0, #944]
	ldr	q20, [x0, #1008]
	ldr	q0, [x1]
	ldr	q1, [x2]
	mul	v29.4s, v13.4s, v1.s[1]
	mul	v30.4s, v14.4s, v1.s[1]
	sqrdmulh	v21.4s, v13.4s, v0.s[1]
	sqrdmulh	v22.4s, v14.4s, v0.s[1]
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v15.4s, v1.s[1]
	mul	v30.4s, v16.4s, v1.s[1]
	sqrdmulh	v23.4s, v15.4s, v0.s[1]
	sqrdmulh	v24.4s, v16.4s, v0.s[1]
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v17.4s, v1.s[1]
	mul	v30.4s, v18.4s, v1.s[1]
	sqrdmulh	v25.4s, v17.4s, v0.s[1]
	sqrdmulh	v26.4s, v18.4s, v0.s[1]
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[1]
	mul	v30.4s, v20.4s, v1.s[1]
	sqrdmulh	v27.4s, v19.4s, v0.s[1]
	sqrdmulh	v28.4s, v20.4s, v0.s[1]
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v13.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v14.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v15.4s, v7.4s, v23.4s
	add	v7.4s, v7.4s, v23.4s
	sub	v16.4s, v8.4s, v24.4s
	add	v8.4s, v8.4s, v24.4s
	sub	v17.4s, v9.4s, v25.4s
	add	v9.4s, v9.4s, v25.4s
	sub	v18.4s, v10.4s, v26.4s
	add	v10.4s, v10.4s, v26.4s
	sub	v19.4s, v11.4s, v27.4s
	add	v11.4s, v11.4s, v27.4s
	sub	v20.4s, v12.4s, v28.4s
	add	v12.4s, v12.4s, v28.4s
	mul	v29.4s, v9.4s, v1.s[2]
	mul	v30.4s, v10.4s, v1.s[2]
	sqrdmulh	v21.4s, v9.4s, v0.s[2]
	sqrdmulh	v22.4s, v10.4s, v0.s[2]
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v11.4s, v1.s[2]
	mul	v30.4s, v12.4s, v1.s[2]
	sqrdmulh	v23.4s, v11.4s, v0.s[2]
	sqrdmulh	v24.4s, v12.4s, v0.s[2]
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v17.4s, v1.s[3]
	mul	v30.4s, v18.4s, v1.s[3]
	sqrdmulh	v25.4s, v17.4s, v0.s[3]
	sqrdmulh	v26.4s, v18.4s, v0.s[3]
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[3]
	mul	v30.4s, v20.4s, v1.s[3]
	sqrdmulh	v27.4s, v19.4s, v0.s[3]
	sqrdmulh	v28.4s, v20.4s, v0.s[3]
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v9.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v10.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v11.4s, v7.4s, v23.4s
	add	v7.4s, v7.4s, v23.4s
	sub	v12.4s, v8.4s, v24.4s
	add	v8.4s, v8.4s, v24.4s
	sub	v17.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v18.4s, v14.4s, v26.4s
	add	v14.4s, v14.4s, v26.4s
	sub	v19.4s, v15.4s, v27.4s
	add	v15.4s, v15.4s, v27.4s
	sub	v20.4s, v16.4s, v28.4s
	add	v16.4s, v16.4s, v28.4s
	ldr	q0, [x1, #16]
	ldr	q1, [x2, #16]
	mul	v29.4s, v7.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[0]
	sqrdmulh	v21.4s, v7.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[0]
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v11.4s, v1.s[1]
	mul	v30.4s, v12.4s, v1.s[1]
	sqrdmulh	v23.4s, v11.4s, v0.s[1]
	sqrdmulh	v24.4s, v12.4s, v0.s[1]
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v15.4s, v1.s[2]
	mul	v30.4s, v16.4s, v1.s[2]
	sqrdmulh	v25.4s, v15.4s, v0.s[2]
	sqrdmulh	v26.4s, v16.4s, v0.s[2]
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[3]
	mul	v30.4s, v20.4s, v1.s[3]
	sqrdmulh	v27.4s, v19.4s, v0.s[3]
	sqrdmulh	v28.4s, v20.4s, v0.s[3]
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v7.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v11.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v10.4s, v24.4s
	add	v10.4s, v10.4s, v24.4s
	sub	v15.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v14.4s, v26.4s
	add	v14.4s, v14.4s, v26.4s
	sub	v19.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v18.4s, v28.4s
	add	v18.4s, v18.4s, v28.4s
	ldp	q0, q2, [x1, #32]
	ldp	q1, q3, [x2, #32]
	mul	v29.4s, v6.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[1]
	sqrdmulh	v21.4s, v6.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[1]
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v10.4s, v1.s[2]
	mul	v30.4s, v12.4s, v1.s[3]
	sqrdmulh	v23.4s, v10.4s, v0.s[2]
	sqrdmulh	v24.4s, v12.4s, v0.s[3]
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v14.4s, v3.s[0]
	mul	v30.4s, v16.4s, v3.s[1]
	sqrdmulh	v25.4s, v14.4s, v2.s[0]
	sqrdmulh	v26.4s, v16.4s, v2.s[1]
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v18.4s, v3.s[2]
	mul	v30.4s, v20.4s, v3.s[3]
	sqrdmulh	v27.4s, v18.4s, v2.s[2]
	sqrdmulh	v28.4s, v20.4s, v2.s[3]
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	str	q5, [x0, #48]
	str	q6, [x0, #112]
	str	q7, [x0, #176]
	str	q8, [x0, #240]
	str	q9, [x0, #304]
	str	q10, [x0, #368]
	str	q11, [x0, #432]
	str	q12, [x0, #496]
	str	q13, [x0, #560]
	str	q14, [x0, #624]
	str	q15, [x0, #688]
	str	q16, [x0, #752]
	str	q17, [x0, #816]
	str	q18, [x0, #880]
	str	q19, [x0, #944]
	str	q20, [x0, #1008]
	ldp	q5, q6, [x0]
	ldp	q7, q8, [x0, #32]
	ldp	q9, q10, [x0, #64]
	ldp	q11, q12, [x0, #96]
	ldp	q13, q14, [x0, #128]
	ldp	q15, q16, [x0, #160]
	ldp	q17, q18, [x0, #192]
	ldp	q19, q20, [x0, #224]
	ldr	q0, [x1, #64]
	ldr	q1, [x2, #64]
	mul	v29.4s, v7.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[0]
	sqrdmulh	v21.4s, v7.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[0]
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v11.4s, v1.s[1]
	mul	v30.4s, v12.4s, v1.s[1]
	sqrdmulh	v23.4s, v11.4s, v0.s[1]
	sqrdmulh	v24.4s, v12.4s, v0.s[1]
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v15.4s, v1.s[2]
	mul	v30.4s, v16.4s, v1.s[2]
	sqrdmulh	v25.4s, v15.4s, v0.s[2]
	sqrdmulh	v26.4s, v16.4s, v0.s[2]
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[3]
	mul	v30.4s, v20.4s, v1.s[3]
	sqrdmulh	v27.4s, v19.4s, v0.s[3]
	sqrdmulh	v28.4s, v20.4s, v0.s[3]
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v7.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v11.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v10.4s, v24.4s
	add	v10.4s, v10.4s, v24.4s
	sub	v15.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v14.4s, v26.4s
	add	v14.4s, v14.4s, v26.4s
	sub	v19.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v18.4s, v28.4s
	add	v18.4s, v18.4s, v28.4s
	ldp	q0, q2, [x1, #128]
	ldp	q1, q3, [x2, #128]
	mul	v29.4s, v6.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[1]
	sqrdmulh	v21.4s, v6.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[1]
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v10.4s, v1.s[2]
	mul	v30.4s, v12.4s, v1.s[3]
	sqrdmulh	v23.4s, v10.4s, v0.s[2]
	sqrdmulh	v24.4s, v12.4s, v0.s[3]
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v14.4s, v3.s[0]
	mul	v30.4s, v16.4s, v3.s[1]
	sqrdmulh	v25.4s, v14.4s, v2.s[0]
	sqrdmulh	v26.4s, v16.4s, v2.s[1]
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v18.4s, v3.s[2]
	mul	v30.4s, v20.4s, v3.s[3]
	sqrdmulh	v27.4s, v18.4s, v2.s[2]
	sqrdmulh	v28.4s, v20.4s, v2.s[3]
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	ldp	q0, q2, [x1, #256]
	ldp	q1, q3, [x2, #256]
	mov	v29.16b, v5.16b
	mov	v30.16b, v7.16b
	trn1	v5.2d, v5.2d, v6.2d
	trn1	v7.2d, v7.2d, v8.2d
	trn2	v6.2d, v29.2d, v6.2d
	trn2	v8.2d, v30.2d, v8.2d
	mul	v29.4s, v6.4s, v1.4s
	mul	v30.4s, v8.4s, v3.4s
	sqrdmulh	v21.4s, v6.4s, v0.4s
	sqrdmulh	v22.4s, v8.4s, v2.4s
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	ldp	q0, q2, [x1, #288]
	ldp	q1, q3, [x2, #288]
	mov	v29.16b, v9.16b
	mov	v30.16b, v11.16b
	trn1	v9.2d, v9.2d, v10.2d
	trn1	v11.2d, v11.2d, v12.2d
	trn2	v10.2d, v29.2d, v10.2d
	trn2	v12.2d, v30.2d, v12.2d
	mul	v29.4s, v10.4s, v1.4s
	mul	v30.4s, v12.4s, v3.4s
	sqrdmulh	v23.4s, v10.4s, v0.4s
	sqrdmulh	v24.4s, v12.4s, v2.4s
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	ldp	q0, q2, [x1, #320]
	ldp	q1, q3, [x2, #320]
	mov	v29.16b, v13.16b
	mov	v30.16b, v15.16b
	trn1	v13.2d, v13.2d, v14.2d
	trn1	v15.2d, v15.2d, v16.2d
	trn2	v14.2d, v29.2d, v14.2d
	trn2	v16.2d, v30.2d, v16.2d
	mul	v29.4s, v14.4s, v1.4s
	mul	v30.4s, v16.4s, v3.4s
	sqrdmulh	v25.4s, v14.4s, v0.4s
	sqrdmulh	v26.4s, v16.4s, v2.4s
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	ldp	q0, q2, [x1, #352]
	ldp	q1, q3, [x2, #352]
	mov	v29.16b, v17.16b
	mov	v30.16b, v19.16b
	trn1	v17.2d, v17.2d, v18.2d
	trn1	v19.2d, v19.2d, v20.2d
	trn2	v18.2d, v29.2d, v18.2d
	trn2	v20.2d, v30.2d, v20.2d
	mul	v29.4s, v18.4s, v1.4s
	mul	v30.4s, v20.4s, v3.4s
	sqrdmulh	v27.4s, v18.4s, v0.4s
	sqrdmulh	v28.4s, v20.4s, v2.4s
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	ldp	q0, q2, [x1, #768]
	ldp	q1, q3, [x2, #768]
	mov	v29.16b, v5.16b
	mov	v30.16b, v7.16b
	trn1	v5.4s, v5.4s, v6.4s
	trn1	v7.4s, v7.4s, v8.4s
	trn2	v6.4s, v29.4s, v6.4s
	trn2	v8.4s, v30.4s, v8.4s
	mul	v29.4s, v6.4s, v1.4s
	mul	v30.4s, v8.4s, v3.4s
	sqrdmulh	v21.4s, v6.4s, v0.4s
	sqrdmulh	v22.4s, v8.4s, v2.4s
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	ldp	q0, q2, [x1, #800]
	ldp	q1, q3, [x2, #800]
	mov	v29.16b, v9.16b
	mov	v30.16b, v11.16b
	trn1	v9.4s, v9.4s, v10.4s
	trn1	v11.4s, v11.4s, v12.4s
	trn2	v10.4s, v29.4s, v10.4s
	trn2	v12.4s, v30.4s, v12.4s
	mul	v29.4s, v10.4s, v1.4s
	mul	v30.4s, v12.4s, v3.4s
	sqrdmulh	v23.4s, v10.4s, v0.4s
	sqrdmulh	v24.4s, v12.4s, v2.4s
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	ldp	q0, q2, [x1, #832]
	ldp	q1, q3, [x2, #832]
	mov	v29.16b, v13.16b
	mov	v30.16b, v15.16b
	trn1	v13.4s, v13.4s, v14.4s
	trn1	v15.4s, v15.4s, v16.4s
	trn2	v14.4s, v29.4s, v14.4s
	trn2	v16.4s, v30.4s, v16.4s
	mul	v29.4s, v14.4s, v1.4s
	mul	v30.4s, v16.4s, v3.4s
	sqrdmulh	v25.4s, v14.4s, v0.4s
	sqrdmulh	v26.4s, v16.4s, v2.4s
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	ldp	q0, q2, [x1, #864]
	ldp	q1, q3, [x2, #864]
	mov	v29.16b, v17.16b
	mov	v30.16b, v19.16b
	trn1	v17.4s, v17.4s, v18.4s
	trn1	v19.4s, v19.4s, v20.4s
	trn2	v18.4s, v29.4s, v18.4s
	trn2	v20.4s, v30.4s, v20.4s
	mul	v29.4s, v18.4s, v1.4s
	mul	v30.4s, v20.4s, v3.4s
	sqrdmulh	v27.4s, v18.4s, v0.4s
	sqrdmulh	v28.4s, v20.4s, v2.4s
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	trn1	v29.4s, v5.4s, v6.4s
	trn2	v30.4s, v5.4s, v6.4s
	trn1	v5.2d, v29.2d, v30.2d
	trn2	v6.2d, v29.2d, v30.2d
	trn1	v29.4s, v7.4s, v8.4s
	trn2	v30.4s, v7.4s, v8.4s
	trn1	v7.2d, v29.2d, v30.2d
	trn2	v8.2d, v29.2d, v30.2d
	trn1	v29.4s, v9.4s, v10.4s
	trn2	v30.4s, v9.4s, v10.4s
	trn1	v9.2d, v29.2d, v30.2d
	trn2	v10.2d, v29.2d, v30.2d
	trn1	v29.4s, v11.4s, v12.4s
	trn2	v30.4s, v11.4s, v12.4s
	trn1	v11.2d, v29.2d, v30.2d
	trn2	v12.2d, v29.2d, v30.2d
	trn1	v29.4s, v13.4s, v14.4s
	trn2	v30.4s, v13.4s, v14.4s
	trn1	v13.2d, v29.2d, v30.2d
	trn2	v14.2d, v29.2d, v30.2d
	trn1	v29.4s, v15.4s, v16.4s
	trn2	v30.4s, v15.4s, v16.4s
	trn1	v15.2d, v29.2d, v30.2d
	trn2	v16.2d, v29.2d, v30.2d
	trn1	v29.4s, v17.4s, v18.4s
	trn2	v30.4s, v17.4s, v18.4s
	trn1	v17.2d, v29.2d, v30.2d
	trn2	v18.2d, v29.2d, v30.2d
	trn1	v29.4s, v19.4s, v20.4s
	trn2	v30.4s, v19.4s, v20.4s
	trn1	v19.2d, v29.2d, v30.2d
	trn2	v20.2d, v29.2d, v30.2d
	stp	q5, q6, [x0]
	stp	q7, q8, [x0, #32]
	stp	q9, q10, [x0, #64]
	stp	q11, q12, [x0, #96]
	stp	q13, q14, [x0, #128]
	stp	q15, q16, [x0, #160]
	stp	q17, q18, [x0, #192]
	stp	q19, q20, [x0, #224]
	ldp	q5, q6, [x0, #256]
	ldp	q7, q8, [x0, #288]
	ldp	q9, q10, [x0, #320]
	ldp	q11, q12, [x0, #352]
	ldp	q13, q14, [x0, #384]
	ldp	q15, q16, [x0, #416]
	ldp	q17, q18, [x0, #448]
	ldp	q19, q20, [x0, #480]
	ldr	q0, [x1, #80]
	ldr	q1, [x2, #80]
	mul	v29.4s, v7.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[0]
	sqrdmulh	v21.4s, v7.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[0]
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v11.4s, v1.s[1]
	mul	v30.4s, v12.4s, v1.s[1]
	sqrdmulh	v23.4s, v11.4s, v0.s[1]
	sqrdmulh	v24.4s, v12.4s, v0.s[1]
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v15.4s, v1.s[2]
	mul	v30.4s, v16.4s, v1.s[2]
	sqrdmulh	v25.4s, v15.4s, v0.s[2]
	sqrdmulh	v26.4s, v16.4s, v0.s[2]
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[3]
	mul	v30.4s, v20.4s, v1.s[3]
	sqrdmulh	v27.4s, v19.4s, v0.s[3]
	sqrdmulh	v28.4s, v20.4s, v0.s[3]
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v7.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v11.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v10.4s, v24.4s
	add	v10.4s, v10.4s, v24.4s
	sub	v15.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v14.4s, v26.4s
	add	v14.4s, v14.4s, v26.4s
	sub	v19.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v18.4s, v28.4s
	add	v18.4s, v18.4s, v28.4s
	ldp	q0, q2, [x1, #160]
	ldp	q1, q3, [x2, #160]
	mul	v29.4s, v6.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[1]
	sqrdmulh	v21.4s, v6.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[1]
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v10.4s, v1.s[2]
	mul	v30.4s, v12.4s, v1.s[3]
	sqrdmulh	v23.4s, v10.4s, v0.s[2]
	sqrdmulh	v24.4s, v12.4s, v0.s[3]
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v14.4s, v3.s[0]
	mul	v30.4s, v16.4s, v3.s[1]
	sqrdmulh	v25.4s, v14.4s, v2.s[0]
	sqrdmulh	v26.4s, v16.4s, v2.s[1]
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v18.4s, v3.s[2]
	mul	v30.4s, v20.4s, v3.s[3]
	sqrdmulh	v27.4s, v18.4s, v2.s[2]
	sqrdmulh	v28.4s, v20.4s, v2.s[3]
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	ldp	q0, q2, [x1, #384]
	ldp	q1, q3, [x2, #384]
	mov	v29.16b, v5.16b
	mov	v30.16b, v7.16b
	trn1	v5.2d, v5.2d, v6.2d
	trn1	v7.2d, v7.2d, v8.2d
	trn2	v6.2d, v29.2d, v6.2d
	trn2	v8.2d, v30.2d, v8.2d
	mul	v29.4s, v6.4s, v1.4s
	mul	v30.4s, v8.4s, v3.4s
	sqrdmulh	v21.4s, v6.4s, v0.4s
	sqrdmulh	v22.4s, v8.4s, v2.4s
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	ldp	q0, q2, [x1, #416]
	ldp	q1, q3, [x2, #416]
	mov	v29.16b, v9.16b
	mov	v30.16b, v11.16b
	trn1	v9.2d, v9.2d, v10.2d
	trn1	v11.2d, v11.2d, v12.2d
	trn2	v10.2d, v29.2d, v10.2d
	trn2	v12.2d, v30.2d, v12.2d
	mul	v29.4s, v10.4s, v1.4s
	mul	v30.4s, v12.4s, v3.4s
	sqrdmulh	v23.4s, v10.4s, v0.4s
	sqrdmulh	v24.4s, v12.4s, v2.4s
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	ldp	q0, q2, [x1, #448]
	ldp	q1, q3, [x2, #448]
	mov	v29.16b, v13.16b
	mov	v30.16b, v15.16b
	trn1	v13.2d, v13.2d, v14.2d
	trn1	v15.2d, v15.2d, v16.2d
	trn2	v14.2d, v29.2d, v14.2d
	trn2	v16.2d, v30.2d, v16.2d
	mul	v29.4s, v14.4s, v1.4s
	mul	v30.4s, v16.4s, v3.4s
	sqrdmulh	v25.4s, v14.4s, v0.4s
	sqrdmulh	v26.4s, v16.4s, v2.4s
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	ldp	q0, q2, [x1, #480]
	ldp	q1, q3, [x2, #480]
	mov	v29.16b, v17.16b
	mov	v30.16b, v19.16b
	trn1	v17.2d, v17.2d, v18.2d
	trn1	v19.2d, v19.2d, v20.2d
	trn2	v18.2d, v29.2d, v18.2d
	trn2	v20.2d, v30.2d, v20.2d
	mul	v29.4s, v18.4s, v1.4s
	mul	v30.4s, v20.4s, v3.4s
	sqrdmulh	v27.4s, v18.4s, v0.4s
	sqrdmulh	v28.4s, v20.4s, v2.4s
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	ldp	q0, q2, [x1, #896]
	ldp	q1, q3, [x2, #896]
	mov	v29.16b, v5.16b
	mov	v30.16b, v7.16b
	trn1	v5.4s, v5.4s, v6.4s
	trn1	v7.4s, v7.4s, v8.4s
	trn2	v6.4s, v29.4s, v6.4s
	trn2	v8.4s, v30.4s, v8.4s
	mul	v29.4s, v6.4s, v1.4s
	mul	v30.4s, v8.4s, v3.4s
	sqrdmulh	v21.4s, v6.4s, v0.4s
	sqrdmulh	v22.4s, v8.4s, v2.4s
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	ldp	q0, q2, [x1, #928]
	ldp	q1, q3, [x2, #928]
	mov	v29.16b, v9.16b
	mov	v30.16b, v11.16b
	trn1	v9.4s, v9.4s, v10.4s
	trn1	v11.4s, v11.4s, v12.4s
	trn2	v10.4s, v29.4s, v10.4s
	trn2	v12.4s, v30.4s, v12.4s
	mul	v29.4s, v10.4s, v1.4s
	mul	v30.4s, v12.4s, v3.4s
	sqrdmulh	v23.4s, v10.4s, v0.4s
	sqrdmulh	v24.4s, v12.4s, v2.4s
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	ldp	q0, q2, [x1, #960]
	ldp	q1, q3, [x2, #960]
	mov	v29.16b, v13.16b
	mov	v30.16b, v15.16b
	trn1	v13.4s, v13.4s, v14.4s
	trn1	v15.4s, v15.4s, v16.4s
	trn2	v14.4s, v29.4s, v14.4s
	trn2	v16.4s, v30.4s, v16.4s
	mul	v29.4s, v14.4s, v1.4s
	mul	v30.4s, v16.4s, v3.4s
	sqrdmulh	v25.4s, v14.4s, v0.4s
	sqrdmulh	v26.4s, v16.4s, v2.4s
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	ldp	q0, q2, [x1, #992]
	ldp	q1, q3, [x2, #992]
	mov	v29.16b, v17.16b
	mov	v30.16b, v19.16b
	trn1	v17.4s, v17.4s, v18.4s
	trn1	v19.4s, v19.4s, v20.4s
	trn2	v18.4s, v29.4s, v18.4s
	trn2	v20.4s, v30.4s, v20.4s
	mul	v29.4s, v18.4s, v1.4s
	mul	v30.4s, v20.4s, v3.4s
	sqrdmulh	v27.4s, v18.4s, v0.4s
	sqrdmulh	v28.4s, v20.4s, v2.4s
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	trn1	v29.4s, v5.4s, v6.4s
	trn2	v30.4s, v5.4s, v6.4s
	trn1	v5.2d, v29.2d, v30.2d
	trn2	v6.2d, v29.2d, v30.2d
	trn1	v29.4s, v7.4s, v8.4s
	trn2	v30.4s, v7.4s, v8.4s
	trn1	v7.2d, v29.2d, v30.2d
	trn2	v8.2d, v29.2d, v30.2d
	trn1	v29.4s, v9.4s, v10.4s
	trn2	v30.4s, v9.4s, v10.4s
	trn1	v9.2d, v29.2d, v30.2d
	trn2	v10.2d, v29.2d, v30.2d
	trn1	v29.4s, v11.4s, v12.4s
	trn2	v30.4s, v11.4s, v12.4s
	trn1	v11.2d, v29.2d, v30.2d
	trn2	v12.2d, v29.2d, v30.2d
	trn1	v29.4s, v13.4s, v14.4s
	trn2	v30.4s, v13.4s, v14.4s
	trn1	v13.2d, v29.2d, v30.2d
	trn2	v14.2d, v29.2d, v30.2d
	trn1	v29.4s, v15.4s, v16.4s
	trn2	v30.4s, v15.4s, v16.4s
	trn1	v15.2d, v29.2d, v30.2d
	trn2	v16.2d, v29.2d, v30.2d
	trn1	v29.4s, v17.4s, v18.4s
	trn2	v30.4s, v17.4s, v18.4s
	trn1	v17.2d, v29.2d, v30.2d
	trn2	v18.2d, v29.2d, v30.2d
	trn1	v29.4s, v19.4s, v20.4s
	trn2	v30.4s, v19.4s, v20.4s
	trn1	v19.2d, v29.2d, v30.2d
	trn2	v20.2d, v29.2d, v30.2d
	stp	q5, q6, [x0, #256]
	stp	q7, q8, [x0, #288]
	stp	q9, q10, [x0, #320]
	stp	q11, q12, [x0, #352]
	stp	q13, q14, [x0, #384]
	stp	q15, q16, [x0, #416]
	stp	q17, q18, [x0, #448]
	stp	q19, q20, [x0, #480]
	ldp	q5, q6, [x0, #512]
	ldp	q7, q8, [x0, #544]
	ldp	q9, q10, [x0, #576]
	ldp	q11, q12, [x0, #608]
	ldp	q13, q14, [x0, #640]
	ldp	q15, q16, [x0, #672]
	ldp	q17, q18, [x0, #704]
	ldp	q19, q20, [x0, #736]
	ldr	q0, [x1, #96]
	ldr	q1, [x2, #96]
	mul	v29.4s, v7.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[0]
	sqrdmulh	v21.4s, v7.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[0]
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v11.4s, v1.s[1]
	mul	v30.4s, v12.4s, v1.s[1]
	sqrdmulh	v23.4s, v11.4s, v0.s[1]
	sqrdmulh	v24.4s, v12.4s, v0.s[1]
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v15.4s, v1.s[2]
	mul	v30.4s, v16.4s, v1.s[2]
	sqrdmulh	v25.4s, v15.4s, v0.s[2]
	sqrdmulh	v26.4s, v16.4s, v0.s[2]
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[3]
	mul	v30.4s, v20.4s, v1.s[3]
	sqrdmulh	v27.4s, v19.4s, v0.s[3]
	sqrdmulh	v28.4s, v20.4s, v0.s[3]
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v7.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v11.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v10.4s, v24.4s
	add	v10.4s, v10.4s, v24.4s
	sub	v15.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v14.4s, v26.4s
	add	v14.4s, v14.4s, v26.4s
	sub	v19.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v18.4s, v28.4s
	add	v18.4s, v18.4s, v28.4s
	ldp	q0, q2, [x1, #192]
	ldp	q1, q3, [x2, #192]
	mul	v29.4s, v6.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[1]
	sqrdmulh	v21.4s, v6.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[1]
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v10.4s, v1.s[2]
	mul	v30.4s, v12.4s, v1.s[3]
	sqrdmulh	v23.4s, v10.4s, v0.s[2]
	sqrdmulh	v24.4s, v12.4s, v0.s[3]
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v14.4s, v3.s[0]
	mul	v30.4s, v16.4s, v3.s[1]
	sqrdmulh	v25.4s, v14.4s, v2.s[0]
	sqrdmulh	v26.4s, v16.4s, v2.s[1]
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v18.4s, v3.s[2]
	mul	v30.4s, v20.4s, v3.s[3]
	sqrdmulh	v27.4s, v18.4s, v2.s[2]
	sqrdmulh	v28.4s, v20.4s, v2.s[3]
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	ldp	q0, q2, [x1, #512]
	ldp	q1, q3, [x2, #512]
	mov	v29.16b, v5.16b
	mov	v30.16b, v7.16b
	trn1	v5.2d, v5.2d, v6.2d
	trn1	v7.2d, v7.2d, v8.2d
	trn2	v6.2d, v29.2d, v6.2d
	trn2	v8.2d, v30.2d, v8.2d
	mul	v29.4s, v6.4s, v1.4s
	mul	v30.4s, v8.4s, v3.4s
	sqrdmulh	v21.4s, v6.4s, v0.4s
	sqrdmulh	v22.4s, v8.4s, v2.4s
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	ldp	q0, q2, [x1, #544]
	ldp	q1, q3, [x2, #544]
	mov	v29.16b, v9.16b
	mov	v30.16b, v11.16b
	trn1	v9.2d, v9.2d, v10.2d
	trn1	v11.2d, v11.2d, v12.2d
	trn2	v10.2d, v29.2d, v10.2d
	trn2	v12.2d, v30.2d, v12.2d
	mul	v29.4s, v10.4s, v1.4s
	mul	v30.4s, v12.4s, v3.4s
	sqrdmulh	v23.4s, v10.4s, v0.4s
	sqrdmulh	v24.4s, v12.4s, v2.4s
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	ldp	q0, q2, [x1, #576]
	ldp	q1, q3, [x2, #576]
	mov	v29.16b, v13.16b
	mov	v30.16b, v15.16b
	trn1	v13.2d, v13.2d, v14.2d
	trn1	v15.2d, v15.2d, v16.2d
	trn2	v14.2d, v29.2d, v14.2d
	trn2	v16.2d, v30.2d, v16.2d
	mul	v29.4s, v14.4s, v1.4s
	mul	v30.4s, v16.4s, v3.4s
	sqrdmulh	v25.4s, v14.4s, v0.4s
	sqrdmulh	v26.4s, v16.4s, v2.4s
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	ldp	q0, q2, [x1, #608]
	ldp	q1, q3, [x2, #608]
	mov	v29.16b, v17.16b
	mov	v30.16b, v19.16b
	trn1	v17.2d, v17.2d, v18.2d
	trn1	v19.2d, v19.2d, v20.2d
	trn2	v18.2d, v29.2d, v18.2d
	trn2	v20.2d, v30.2d, v20.2d
	mul	v29.4s, v18.4s, v1.4s
	mul	v30.4s, v20.4s, v3.4s
	sqrdmulh	v27.4s, v18.4s, v0.4s
	sqrdmulh	v28.4s, v20.4s, v2.4s
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	ldr	q0, [x1, #1024]
	ldr	q2, [x1, #1040]
	ldr	q1, [x2, #1024]
	ldr	q3, [x2, #1040]
	mov	v29.16b, v5.16b
	mov	v30.16b, v7.16b
	trn1	v5.4s, v5.4s, v6.4s
	trn1	v7.4s, v7.4s, v8.4s
	trn2	v6.4s, v29.4s, v6.4s
	trn2	v8.4s, v30.4s, v8.4s
	mul	v29.4s, v6.4s, v1.4s
	mul	v30.4s, v8.4s, v3.4s
	sqrdmulh	v21.4s, v6.4s, v0.4s
	sqrdmulh	v22.4s, v8.4s, v2.4s
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	ldr	q0, [x1, #1056]
	ldr	q2, [x1, #1072]
	ldr	q1, [x2, #1056]
	ldr	q3, [x2, #1072]
	mov	v29.16b, v9.16b
	mov	v30.16b, v11.16b
	trn1	v9.4s, v9.4s, v10.4s
	trn1	v11.4s, v11.4s, v12.4s
	trn2	v10.4s, v29.4s, v10.4s
	trn2	v12.4s, v30.4s, v12.4s
	mul	v29.4s, v10.4s, v1.4s
	mul	v30.4s, v12.4s, v3.4s
	sqrdmulh	v23.4s, v10.4s, v0.4s
	sqrdmulh	v24.4s, v12.4s, v2.4s
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	ldr	q0, [x1, #1088]
	ldr	q2, [x1, #1104]
	ldr	q1, [x2, #1088]
	ldr	q3, [x2, #1104]
	mov	v29.16b, v13.16b
	mov	v30.16b, v15.16b
	trn1	v13.4s, v13.4s, v14.4s
	trn1	v15.4s, v15.4s, v16.4s
	trn2	v14.4s, v29.4s, v14.4s
	trn2	v16.4s, v30.4s, v16.4s
	mul	v29.4s, v14.4s, v1.4s
	mul	v30.4s, v16.4s, v3.4s
	sqrdmulh	v25.4s, v14.4s, v0.4s
	sqrdmulh	v26.4s, v16.4s, v2.4s
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	ldr	q0, [x1, #1120]
	ldr	q2, [x1, #1136]
	ldr	q1, [x2, #1120]
	ldr	q3, [x2, #1136]
	mov	v29.16b, v17.16b
	mov	v30.16b, v19.16b
	trn1	v17.4s, v17.4s, v18.4s
	trn1	v19.4s, v19.4s, v20.4s
	trn2	v18.4s, v29.4s, v18.4s
	trn2	v20.4s, v30.4s, v20.4s
	mul	v29.4s, v18.4s, v1.4s
	mul	v30.4s, v20.4s, v3.4s
	sqrdmulh	v27.4s, v18.4s, v0.4s
	sqrdmulh	v28.4s, v20.4s, v2.4s
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	trn1	v29.4s, v5.4s, v6.4s
	trn2	v30.4s, v5.4s, v6.4s
	trn1	v5.2d, v29.2d, v30.2d
	trn2	v6.2d, v29.2d, v30.2d
	trn1	v29.4s, v7.4s, v8.4s
	trn2	v30.4s, v7.4s, v8.4s
	trn1	v7.2d, v29.2d, v30.2d
	trn2	v8.2d, v29.2d, v30.2d
	trn1	v29.4s, v9.4s, v10.4s
	trn2	v30.4s, v9.4s, v10.4s
	trn1	v9.2d, v29.2d, v30.2d
	trn2	v10.2d, v29.2d, v30.2d
	trn1	v29.4s, v11.4s, v12.4s
	trn2	v30.4s, v11.4s, v12.4s
	trn1	v11.2d, v29.2d, v30.2d
	trn2	v12.2d, v29.2d, v30.2d
	trn1	v29.4s, v13.4s, v14.4s
	trn2	v30.4s, v13.4s, v14.4s
	trn1	v13.2d, v29.2d, v30.2d
	trn2	v14.2d, v29.2d, v30.2d
	trn1	v29.4s, v15.4s, v16.4s
	trn2	v30.4s, v15.4s, v16.4s
	trn1	v15.2d, v29.2d, v30.2d
	trn2	v16.2d, v29.2d, v30.2d
	trn1	v29.4s, v17.4s, v18.4s
	trn2	v30.4s, v17.4s, v18.4s
	trn1	v17.2d, v29.2d, v30.2d
	trn2	v18.2d, v29.2d, v30.2d
	trn1	v29.4s, v19.4s, v20.4s
	trn2	v30.4s, v19.4s, v20.4s
	trn1	v19.2d, v29.2d, v30.2d
	trn2	v20.2d, v29.2d, v30.2d
	stp	q5, q6, [x0, #512]
	stp	q7, q8, [x0, #544]
	stp	q9, q10, [x0, #576]
	stp	q11, q12, [x0, #608]
	stp	q13, q14, [x0, #640]
	stp	q15, q16, [x0, #672]
	stp	q17, q18, [x0, #704]
	stp	q19, q20, [x0, #736]
	ldp	q5, q6, [x0, #768]
	ldp	q7, q8, [x0, #800]
	ldp	q9, q10, [x0, #832]
	ldp	q11, q12, [x0, #864]
	ldp	q13, q14, [x0, #896]
	ldp	q15, q16, [x0, #928]
	ldp	q17, q18, [x0, #960]
	ldp	q19, q20, [x0, #992]
	ldr	q0, [x1, #112]
	ldr	q1, [x2, #112]
	mul	v29.4s, v7.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[0]
	sqrdmulh	v21.4s, v7.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[0]
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v11.4s, v1.s[1]
	mul	v30.4s, v12.4s, v1.s[1]
	sqrdmulh	v23.4s, v11.4s, v0.s[1]
	sqrdmulh	v24.4s, v12.4s, v0.s[1]
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v15.4s, v1.s[2]
	mul	v30.4s, v16.4s, v1.s[2]
	sqrdmulh	v25.4s, v15.4s, v0.s[2]
	sqrdmulh	v26.4s, v16.4s, v0.s[2]
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v19.4s, v1.s[3]
	mul	v30.4s, v20.4s, v1.s[3]
	sqrdmulh	v27.4s, v19.4s, v0.s[3]
	sqrdmulh	v28.4s, v20.4s, v0.s[3]
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v7.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v6.4s, v22.4s
	add	v6.4s, v6.4s, v22.4s
	sub	v11.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v10.4s, v24.4s
	add	v10.4s, v10.4s, v24.4s
	sub	v15.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v14.4s, v26.4s
	add	v14.4s, v14.4s, v26.4s
	sub	v19.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v18.4s, v28.4s
	add	v18.4s, v18.4s, v28.4s
	ldp	q0, q2, [x1, #224]
	ldp	q1, q3, [x2, #224]
	mul	v29.4s, v6.4s, v1.s[0]
	mul	v30.4s, v8.4s, v1.s[1]
	sqrdmulh	v21.4s, v6.4s, v0.s[0]
	sqrdmulh	v22.4s, v8.4s, v0.s[1]
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	mul	v29.4s, v10.4s, v1.s[2]
	mul	v30.4s, v12.4s, v1.s[3]
	sqrdmulh	v23.4s, v10.4s, v0.s[2]
	sqrdmulh	v24.4s, v12.4s, v0.s[3]
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	mul	v29.4s, v14.4s, v3.s[0]
	mul	v30.4s, v16.4s, v3.s[1]
	sqrdmulh	v25.4s, v14.4s, v2.s[0]
	sqrdmulh	v26.4s, v16.4s, v2.s[1]
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	mul	v29.4s, v18.4s, v3.s[2]
	mul	v30.4s, v20.4s, v3.s[3]
	sqrdmulh	v27.4s, v18.4s, v2.s[2]
	sqrdmulh	v28.4s, v20.4s, v2.s[3]
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	ldp	q0, q2, [x1, #640]
	ldp	q1, q3, [x2, #640]
	mov	v29.16b, v5.16b
	mov	v30.16b, v7.16b
	trn1	v5.2d, v5.2d, v6.2d
	trn1	v7.2d, v7.2d, v8.2d
	trn2	v6.2d, v29.2d, v6.2d
	trn2	v8.2d, v30.2d, v8.2d
	mul	v29.4s, v6.4s, v1.4s
	mul	v30.4s, v8.4s, v3.4s
	sqrdmulh	v21.4s, v6.4s, v0.4s
	sqrdmulh	v22.4s, v8.4s, v2.4s
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	ldp	q0, q2, [x1, #672]
	ldp	q1, q3, [x2, #672]
	mov	v29.16b, v9.16b
	mov	v30.16b, v11.16b
	trn1	v9.2d, v9.2d, v10.2d
	trn1	v11.2d, v11.2d, v12.2d
	trn2	v10.2d, v29.2d, v10.2d
	trn2	v12.2d, v30.2d, v12.2d
	mul	v29.4s, v10.4s, v1.4s
	mul	v30.4s, v12.4s, v3.4s
	sqrdmulh	v23.4s, v10.4s, v0.4s
	sqrdmulh	v24.4s, v12.4s, v2.4s
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	ldp	q0, q2, [x1, #704]
	ldp	q1, q3, [x2, #704]
	mov	v29.16b, v13.16b
	mov	v30.16b, v15.16b
	trn1	v13.2d, v13.2d, v14.2d
	trn1	v15.2d, v15.2d, v16.2d
	trn2	v14.2d, v29.2d, v14.2d
	trn2	v16.2d, v30.2d, v16.2d
	mul	v29.4s, v14.4s, v1.4s
	mul	v30.4s, v16.4s, v3.4s
	sqrdmulh	v25.4s, v14.4s, v0.4s
	sqrdmulh	v26.4s, v16.4s, v2.4s
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	ldp	q0, q2, [x1, #736]
	ldp	q1, q3, [x2, #736]
	mov	v29.16b, v17.16b
	mov	v30.16b, v19.16b
	trn1	v17.2d, v17.2d, v18.2d
	trn1	v19.2d, v19.2d, v20.2d
	trn2	v18.2d, v29.2d, v18.2d
	trn2	v20.2d, v30.2d, v20.2d
	mul	v29.4s, v18.4s, v1.4s
	mul	v30.4s, v20.4s, v3.4s
	sqrdmulh	v27.4s, v18.4s, v0.4s
	sqrdmulh	v28.4s, v20.4s, v2.4s
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	ldr	q0, [x1, #1152]
	ldr	q2, [x1, #1168]
	ldr	q1, [x2, #1152]
	ldr	q3, [x2, #1168]
	mov	v29.16b, v5.16b
	mov	v30.16b, v7.16b
	trn1	v5.4s, v5.4s, v6.4s
	trn1	v7.4s, v7.4s, v8.4s
	trn2	v6.4s, v29.4s, v6.4s
	trn2	v8.4s, v30.4s, v8.4s
	mul	v29.4s, v6.4s, v1.4s
	mul	v30.4s, v8.4s, v3.4s
	sqrdmulh	v21.4s, v6.4s, v0.4s
	sqrdmulh	v22.4s, v8.4s, v2.4s
	sqrdmlsh	v21.4s, v29.4s, v4.s[0]
	sqrdmlsh	v22.4s, v30.4s, v4.s[0]
	sshr	v21.4s, v21.4s, #1
	sshr	v22.4s, v22.4s, #1
	ldr	q0, [x1, #1184]
	ldr	q2, [x1, #1200]
	ldr	q1, [x2, #1184]
	ldr	q3, [x2, #1200]
	mov	v29.16b, v9.16b
	mov	v30.16b, v11.16b
	trn1	v9.4s, v9.4s, v10.4s
	trn1	v11.4s, v11.4s, v12.4s
	trn2	v10.4s, v29.4s, v10.4s
	trn2	v12.4s, v30.4s, v12.4s
	mul	v29.4s, v10.4s, v1.4s
	mul	v30.4s, v12.4s, v3.4s
	sqrdmulh	v23.4s, v10.4s, v0.4s
	sqrdmulh	v24.4s, v12.4s, v2.4s
	sqrdmlsh	v23.4s, v29.4s, v4.s[0]
	sqrdmlsh	v24.4s, v30.4s, v4.s[0]
	sshr	v23.4s, v23.4s, #1
	sshr	v24.4s, v24.4s, #1
	ldr	q0, [x1, #1216]
	ldr	q2, [x1, #1232]
	ldr	q1, [x2, #1216]
	ldr	q3, [x2, #1232]
	mov	v29.16b, v13.16b
	mov	v30.16b, v15.16b
	trn1	v13.4s, v13.4s, v14.4s
	trn1	v15.4s, v15.4s, v16.4s
	trn2	v14.4s, v29.4s, v14.4s
	trn2	v16.4s, v30.4s, v16.4s
	mul	v29.4s, v14.4s, v1.4s
	mul	v30.4s, v16.4s, v3.4s
	sqrdmulh	v25.4s, v14.4s, v0.4s
	sqrdmulh	v26.4s, v16.4s, v2.4s
	sqrdmlsh	v25.4s, v29.4s, v4.s[0]
	sqrdmlsh	v26.4s, v30.4s, v4.s[0]
	sshr	v25.4s, v25.4s, #1
	sshr	v26.4s, v26.4s, #1
	ldr	q0, [x1, #1248]
	ldr	q2, [x1, #1264]
	ldr	q1, [x2, #1248]
	ldr	q3, [x2, #1264]
	mov	v29.16b, v17.16b
	mov	v30.16b, v19.16b
	trn1	v17.4s, v17.4s, v18.4s
	trn1	v19.4s, v19.4s, v20.4s
	trn2	v18.4s, v29.4s, v18.4s
	trn2	v20.4s, v30.4s, v20.4s
	mul	v29.4s, v18.4s, v1.4s
	mul	v30.4s, v20.4s, v3.4s
	sqrdmulh	v27.4s, v18.4s, v0.4s
	sqrdmulh	v28.4s, v20.4s, v2.4s
	sqrdmlsh	v27.4s, v29.4s, v4.s[0]
	sqrdmlsh	v28.4s, v30.4s, v4.s[0]
	sshr	v27.4s, v27.4s, #1
	sshr	v28.4s, v28.4s, #1
	sub	v6.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v21.4s
	sub	v8.4s, v7.4s, v22.4s
	add	v7.4s, v7.4s, v22.4s
	sub	v10.4s, v9.4s, v23.4s
	add	v9.4s, v9.4s, v23.4s
	sub	v12.4s, v11.4s, v24.4s
	add	v11.4s, v11.4s, v24.4s
	sub	v14.4s, v13.4s, v25.4s
	add	v13.4s, v13.4s, v25.4s
	sub	v16.4s, v15.4s, v26.4s
	add	v15.4s, v15.4s, v26.4s
	sub	v18.4s, v17.4s, v27.4s
	add	v17.4s, v17.4s, v27.4s
	sub	v20.4s, v19.4s, v28.4s
	add	v19.4s, v19.4s, v28.4s
	trn1	v29.4s, v5.4s, v6.4s
	trn2	v30.4s, v5.4s, v6.4s
	trn1	v5.2d, v29.2d, v30.2d
	trn2	v6.2d, v29.2d, v30.2d
	trn1	v29.4s, v7.4s, v8.4s
	trn2	v30.4s, v7.4s, v8.4s
	trn1	v7.2d, v29.2d, v30.2d
	trn2	v8.2d, v29.2d, v30.2d
	trn1	v29.4s, v9.4s, v10.4s
	trn2	v30.4s, v9.4s, v10.4s
	trn1	v9.2d, v29.2d, v30.2d
	trn2	v10.2d, v29.2d, v30.2d
	trn1	v29.4s, v11.4s, v12.4s
	trn2	v30.4s, v11.4s, v12.4s
	trn1	v11.2d, v29.2d, v30.2d
	trn2	v12.2d, v29.2d, v30.2d
	trn1	v29.4s, v13.4s, v14.4s
	trn2	v30.4s, v13.4s, v14.4s
	trn1	v13.2d, v29.2d, v30.2d
	trn2	v14.2d, v29.2d, v30.2d
	trn1	v29.4s, v15.4s, v16.4s
	trn2	v30.4s, v15.4s, v16.4s
	trn1	v15.2d, v29.2d, v30.2d
	trn2	v16.2d, v29.2d, v30.2d
	trn1	v29.4s, v17.4s, v18.4s
	trn2	v30.4s, v17.4s, v18.4s
	trn1	v17.2d, v29.2d, v30.2d
	trn2	v18.2d, v29.2d, v30.2d
	trn1	v29.4s, v19.4s, v20.4s
	trn2	v30.4s, v19.4s, v20.4s
	trn1	v19.2d, v29.2d, v30.2d
	trn2	v20.2d, v29.2d, v30.2d
	stp	q5, q6, [x0, #768]
	stp	q7, q8, [x0, #800]
	stp	q9, q10, [x0, #832]
	stp	q11, q12, [x0, #864]
	stp	q13, q14, [x0, #896]
	stp	q15, q16, [x0, #928]
	stp	q17, q18, [x0, #960]
	stp	q19, q20, [x0, #992]
	ldp	d8, d9, [x29, #16]
	ldp	d10, d11, [x29, #32]
	ldp	d12, d13, [x29, #48]
	ldp	d14, d15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
#ifndef __APPLE__
	.size	mldsa_ntt_full_sqrdmlsh_neon,.-mldsa_ntt_full_sqrdmlsh_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	mldsa_invntt_sqrdmlsh_neon
WC_ASM_ATT_HIDDEN(mldsa_invntt_sqrdmlsh_neon)
.type	mldsa_invntt_sqrdmlsh_neon,@function
.align	2
mldsa_invntt_sqrdmlsh_neon:
#else
.section	__TEXT,__text
.globl	_mldsa_invntt_sqrdmlsh_neon
WC_ASM_ATT_HIDDEN(_mldsa_invntt_sqrdmlsh_neon)
.p2align	2
_mldsa_invntt_sqrdmlsh_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
	stp	d12, d13, [x29, #48]
	stp	d14, d15, [x29, #64]
#ifndef __APPLE__
	adrp x1, L_mldsa_aarch64_zetas_inv
	add  x1, x1, :lo12:L_mldsa_aarch64_zetas_inv
#else
	adrp x1, L_mldsa_aarch64_zetas_inv@PAGE
	add  x1, x1, L_mldsa_aarch64_zetas_inv@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x2, L_mldsa_aarch64_zetas_inv_qinv
	add  x2, x2, :lo12:L_mldsa_aarch64_zetas_inv_qinv
#else
	adrp x2, L_mldsa_aarch64_zetas_inv_qinv@PAGE
	add  x2, x2, L_mldsa_aarch64_zetas_inv_qinv@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x3, L_mldsa_aarch64_consts
	add  x3, x3, :lo12:L_mldsa_aarch64_consts
#else
	adrp x3, L_mldsa_aarch64_consts@PAGE
	add  x3, x3, L_mldsa_aarch64_consts@PAGEOFF
#endif /* __APPLE__ */
	ldr	q4, [x3]
	ldp	q5, q6, [x0]
	ldp	q7, q8, [x0, #32]
	ldp	q9, q10, [x0, #64]
	ldp	q11, q12, [x0, #96]
	ldp	q13, q14, [x0, #128]
	ldp	q15, q16, [x0, #160]
	ldp	q17, q18, [x0, #192]
	ldp	q19, q20, [x0, #224]
	ldp	q0, q1, [x1]
	ldp	q2, q3, [x2]
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v6.4s, v22.4s, v0.4s
	sqrdmulh	v8.4s, v24.4s, v1.4s
	sqrdmlsh	v6.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v23.4s, v4.s[0]
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	ldp	q0, q1, [x1, #32]
	ldp	q2, q3, [x2, #32]
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v10.4s, v22.4s, v0.4s
	sqrdmulh	v12.4s, v24.4s, v1.4s
	sqrdmlsh	v10.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	ldp	q0, q1, [x1, #64]
	ldp	q2, q3, [x2, #64]
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v14.4s, v22.4s, v0.4s
	sqrdmulh	v16.4s, v24.4s, v1.4s
	sqrdmlsh	v14.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	ldp	q0, q1, [x1, #96]
	ldp	q2, q3, [x2, #96]
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v18.4s, v22.4s, v0.4s
	sqrdmulh	v20.4s, v24.4s, v1.4s
	sqrdmlsh	v18.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldp	q0, q1, [x1, #512]
	ldp	q2, q3, [x2, #512]
	mov	v21.16b, v5.16b
	mov	v22.16b, v7.16b
	trn1	v5.4s, v5.4s, v6.4s
	trn1	v7.4s, v7.4s, v8.4s
	trn2	v6.4s, v21.4s, v6.4s
	trn2	v8.4s, v22.4s, v8.4s
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v6.4s, v22.4s, v0.4s
	sqrdmulh	v8.4s, v24.4s, v1.4s
	sqrdmlsh	v6.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v23.4s, v4.s[0]
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	ldp	q0, q1, [x1, #544]
	ldp	q2, q3, [x2, #544]
	mov	v21.16b, v9.16b
	mov	v22.16b, v11.16b
	trn1	v9.4s, v9.4s, v10.4s
	trn1	v11.4s, v11.4s, v12.4s
	trn2	v10.4s, v21.4s, v10.4s
	trn2	v12.4s, v22.4s, v12.4s
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v10.4s, v22.4s, v0.4s
	sqrdmulh	v12.4s, v24.4s, v1.4s
	sqrdmlsh	v10.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	ldp	q0, q1, [x1, #576]
	ldp	q2, q3, [x2, #576]
	mov	v21.16b, v13.16b
	mov	v22.16b, v15.16b
	trn1	v13.4s, v13.4s, v14.4s
	trn1	v15.4s, v15.4s, v16.4s
	trn2	v14.4s, v21.4s, v14.4s
	trn2	v16.4s, v22.4s, v16.4s
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v14.4s, v22.4s, v0.4s
	sqrdmulh	v16.4s, v24.4s, v1.4s
	sqrdmlsh	v14.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	ldp	q0, q1, [x1, #608]
	ldp	q2, q3, [x2, #608]
	mov	v21.16b, v17.16b
	mov	v22.16b, v19.16b
	trn1	v17.4s, v17.4s, v18.4s
	trn1	v19.4s, v19.4s, v20.4s
	trn2	v18.4s, v21.4s, v18.4s
	trn2	v20.4s, v22.4s, v20.4s
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v18.4s, v22.4s, v0.4s
	sqrdmulh	v20.4s, v24.4s, v1.4s
	sqrdmlsh	v18.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1024]
	ldr	q1, [x1, #1040]
	ldr	q2, [x2, #1024]
	ldr	q3, [x2, #1040]
	mov	v21.16b, v5.16b
	mov	v22.16b, v7.16b
	trn1	v5.2d, v5.2d, v6.2d
	trn1	v7.2d, v7.2d, v8.2d
	trn2	v6.2d, v21.2d, v6.2d
	trn2	v8.2d, v22.2d, v8.2d
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v6.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[1]
	sqrdmlsh	v6.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v23.4s, v4.s[0]
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	mov	v21.16b, v9.16b
	mov	v22.16b, v11.16b
	trn1	v9.2d, v9.2d, v10.2d
	trn1	v11.2d, v11.2d, v12.2d
	trn2	v10.2d, v21.2d, v10.2d
	trn2	v12.2d, v22.2d, v12.2d
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v10.4s, v22.4s, v0.s[2]
	sqrdmulh	v12.4s, v24.4s, v0.s[3]
	sqrdmlsh	v10.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	mov	v21.16b, v13.16b
	mov	v22.16b, v15.16b
	trn1	v13.2d, v13.2d, v14.2d
	trn1	v15.2d, v15.2d, v16.2d
	trn2	v14.2d, v21.2d, v14.2d
	trn2	v16.2d, v22.2d, v16.2d
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v3.s[0]
	mul	v23.4s, v24.4s, v3.s[1]
	sqrdmulh	v14.4s, v22.4s, v1.s[0]
	sqrdmulh	v16.4s, v24.4s, v1.s[1]
	sqrdmlsh	v14.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	mov	v21.16b, v17.16b
	mov	v22.16b, v19.16b
	trn1	v17.2d, v17.2d, v18.2d
	trn1	v19.2d, v19.2d, v20.2d
	trn2	v18.2d, v21.2d, v18.2d
	trn2	v20.2d, v22.2d, v20.2d
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v3.s[2]
	mul	v23.4s, v24.4s, v3.s[3]
	sqrdmulh	v18.4s, v22.4s, v1.s[2]
	sqrdmulh	v20.4s, v24.4s, v1.s[3]
	sqrdmlsh	v18.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1152]
	ldr	q2, [x2, #1152]
	sub	v22.4s, v5.4s, v7.4s
	sub	v24.4s, v6.4s, v8.4s
	add	v5.4s, v5.4s, v7.4s
	add	v6.4s, v6.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v7.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[0]
	sqrdmlsh	v7.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v23.4s, v4.s[0]
	sshr	v7.4s, v7.4s, #1
	sshr	v8.4s, v8.4s, #1
	sub	v22.4s, v9.4s, v11.4s
	sub	v24.4s, v10.4s, v12.4s
	add	v9.4s, v9.4s, v11.4s
	add	v10.4s, v10.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v11.4s, v22.4s, v0.s[1]
	sqrdmulh	v12.4s, v24.4s, v0.s[1]
	sqrdmlsh	v11.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v15.4s
	sub	v24.4s, v14.4s, v16.4s
	add	v13.4s, v13.4s, v15.4s
	add	v14.4s, v14.4s, v16.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v15.4s, v22.4s, v0.s[2]
	sqrdmulh	v16.4s, v24.4s, v0.s[2]
	sqrdmlsh	v15.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v15.4s, v15.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v17.4s, v19.4s
	sub	v24.4s, v18.4s, v20.4s
	add	v17.4s, v17.4s, v19.4s
	add	v18.4s, v18.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[3]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v19.4s, v22.4s, v0.s[3]
	sqrdmulh	v20.4s, v24.4s, v0.s[3]
	sqrdmlsh	v19.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	stp	q5, q6, [x0]
	stp	q7, q8, [x0, #32]
	stp	q9, q10, [x0, #64]
	stp	q11, q12, [x0, #96]
	stp	q13, q14, [x0, #128]
	stp	q15, q16, [x0, #160]
	stp	q17, q18, [x0, #192]
	stp	q19, q20, [x0, #224]
	ldp	q5, q6, [x0, #256]
	ldp	q7, q8, [x0, #288]
	ldp	q9, q10, [x0, #320]
	ldp	q11, q12, [x0, #352]
	ldp	q13, q14, [x0, #384]
	ldp	q15, q16, [x0, #416]
	ldp	q17, q18, [x0, #448]
	ldp	q19, q20, [x0, #480]
	ldp	q0, q1, [x1, #128]
	ldp	q2, q3, [x2, #128]
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v6.4s, v22.4s, v0.4s
	sqrdmulh	v8.4s, v24.4s, v1.4s
	sqrdmlsh	v6.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v23.4s, v4.s[0]
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	ldp	q0, q1, [x1, #160]
	ldp	q2, q3, [x2, #160]
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v10.4s, v22.4s, v0.4s
	sqrdmulh	v12.4s, v24.4s, v1.4s
	sqrdmlsh	v10.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	ldp	q0, q1, [x1, #192]
	ldp	q2, q3, [x2, #192]
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v14.4s, v22.4s, v0.4s
	sqrdmulh	v16.4s, v24.4s, v1.4s
	sqrdmlsh	v14.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	ldp	q0, q1, [x1, #224]
	ldp	q2, q3, [x2, #224]
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v18.4s, v22.4s, v0.4s
	sqrdmulh	v20.4s, v24.4s, v1.4s
	sqrdmlsh	v18.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldp	q0, q1, [x1, #640]
	ldp	q2, q3, [x2, #640]
	mov	v21.16b, v5.16b
	mov	v22.16b, v7.16b
	trn1	v5.4s, v5.4s, v6.4s
	trn1	v7.4s, v7.4s, v8.4s
	trn2	v6.4s, v21.4s, v6.4s
	trn2	v8.4s, v22.4s, v8.4s
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v6.4s, v22.4s, v0.4s
	sqrdmulh	v8.4s, v24.4s, v1.4s
	sqrdmlsh	v6.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v23.4s, v4.s[0]
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	ldp	q0, q1, [x1, #672]
	ldp	q2, q3, [x2, #672]
	mov	v21.16b, v9.16b
	mov	v22.16b, v11.16b
	trn1	v9.4s, v9.4s, v10.4s
	trn1	v11.4s, v11.4s, v12.4s
	trn2	v10.4s, v21.4s, v10.4s
	trn2	v12.4s, v22.4s, v12.4s
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v10.4s, v22.4s, v0.4s
	sqrdmulh	v12.4s, v24.4s, v1.4s
	sqrdmlsh	v10.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	ldp	q0, q1, [x1, #704]
	ldp	q2, q3, [x2, #704]
	mov	v21.16b, v13.16b
	mov	v22.16b, v15.16b
	trn1	v13.4s, v13.4s, v14.4s
	trn1	v15.4s, v15.4s, v16.4s
	trn2	v14.4s, v21.4s, v14.4s
	trn2	v16.4s, v22.4s, v16.4s
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v14.4s, v22.4s, v0.4s
	sqrdmulh	v16.4s, v24.4s, v1.4s
	sqrdmlsh	v14.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	ldp	q0, q1, [x1, #736]
	ldp	q2, q3, [x2, #736]
	mov	v21.16b, v17.16b
	mov	v22.16b, v19.16b
	trn1	v17.4s, v17.4s, v18.4s
	trn1	v19.4s, v19.4s, v20.4s
	trn2	v18.4s, v21.4s, v18.4s
	trn2	v20.4s, v22.4s, v20.4s
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v18.4s, v22.4s, v0.4s
	sqrdmulh	v20.4s, v24.4s, v1.4s
	sqrdmlsh	v18.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1056]
	ldr	q1, [x1, #1072]
	ldr	q2, [x2, #1056]
	ldr	q3, [x2, #1072]
	mov	v21.16b, v5.16b
	mov	v22.16b, v7.16b
	trn1	v5.2d, v5.2d, v6.2d
	trn1	v7.2d, v7.2d, v8.2d
	trn2	v6.2d, v21.2d, v6.2d
	trn2	v8.2d, v22.2d, v8.2d
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v6.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[1]
	sqrdmlsh	v6.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v23.4s, v4.s[0]
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	mov	v21.16b, v9.16b
	mov	v22.16b, v11.16b
	trn1	v9.2d, v9.2d, v10.2d
	trn1	v11.2d, v11.2d, v12.2d
	trn2	v10.2d, v21.2d, v10.2d
	trn2	v12.2d, v22.2d, v12.2d
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v10.4s, v22.4s, v0.s[2]
	sqrdmulh	v12.4s, v24.4s, v0.s[3]
	sqrdmlsh	v10.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	mov	v21.16b, v13.16b
	mov	v22.16b, v15.16b
	trn1	v13.2d, v13.2d, v14.2d
	trn1	v15.2d, v15.2d, v16.2d
	trn2	v14.2d, v21.2d, v14.2d
	trn2	v16.2d, v22.2d, v16.2d
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v3.s[0]
	mul	v23.4s, v24.4s, v3.s[1]
	sqrdmulh	v14.4s, v22.4s, v1.s[0]
	sqrdmulh	v16.4s, v24.4s, v1.s[1]
	sqrdmlsh	v14.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	mov	v21.16b, v17.16b
	mov	v22.16b, v19.16b
	trn1	v17.2d, v17.2d, v18.2d
	trn1	v19.2d, v19.2d, v20.2d
	trn2	v18.2d, v21.2d, v18.2d
	trn2	v20.2d, v22.2d, v20.2d
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v3.s[2]
	mul	v23.4s, v24.4s, v3.s[3]
	sqrdmulh	v18.4s, v22.4s, v1.s[2]
	sqrdmulh	v20.4s, v24.4s, v1.s[3]
	sqrdmlsh	v18.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1168]
	ldr	q2, [x2, #1168]
	sub	v22.4s, v5.4s, v7.4s
	sub	v24.4s, v6.4s, v8.4s
	add	v5.4s, v5.4s, v7.4s
	add	v6.4s, v6.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v7.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[0]
	sqrdmlsh	v7.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v23.4s, v4.s[0]
	sshr	v7.4s, v7.4s, #1
	sshr	v8.4s, v8.4s, #1
	sub	v22.4s, v9.4s, v11.4s
	sub	v24.4s, v10.4s, v12.4s
	add	v9.4s, v9.4s, v11.4s
	add	v10.4s, v10.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v11.4s, v22.4s, v0.s[1]
	sqrdmulh	v12.4s, v24.4s, v0.s[1]
	sqrdmlsh	v11.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v15.4s
	sub	v24.4s, v14.4s, v16.4s
	add	v13.4s, v13.4s, v15.4s
	add	v14.4s, v14.4s, v16.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v15.4s, v22.4s, v0.s[2]
	sqrdmulh	v16.4s, v24.4s, v0.s[2]
	sqrdmlsh	v15.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v15.4s, v15.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v17.4s, v19.4s
	sub	v24.4s, v18.4s, v20.4s
	add	v17.4s, v17.4s, v19.4s
	add	v18.4s, v18.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[3]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v19.4s, v22.4s, v0.s[3]
	sqrdmulh	v20.4s, v24.4s, v0.s[3]
	sqrdmlsh	v19.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	stp	q5, q6, [x0, #256]
	stp	q7, q8, [x0, #288]
	stp	q9, q10, [x0, #320]
	stp	q11, q12, [x0, #352]
	stp	q13, q14, [x0, #384]
	stp	q15, q16, [x0, #416]
	stp	q17, q18, [x0, #448]
	stp	q19, q20, [x0, #480]
	ldp	q5, q6, [x0, #512]
	ldp	q7, q8, [x0, #544]
	ldp	q9, q10, [x0, #576]
	ldp	q11, q12, [x0, #608]
	ldp	q13, q14, [x0, #640]
	ldp	q15, q16, [x0, #672]
	ldp	q17, q18, [x0, #704]
	ldp	q19, q20, [x0, #736]
	ldp	q0, q1, [x1, #256]
	ldp	q2, q3, [x2, #256]
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v6.4s, v22.4s, v0.4s
	sqrdmulh	v8.4s, v24.4s, v1.4s
	sqrdmlsh	v6.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v23.4s, v4.s[0]
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	ldp	q0, q1, [x1, #288]
	ldp	q2, q3, [x2, #288]
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v10.4s, v22.4s, v0.4s
	sqrdmulh	v12.4s, v24.4s, v1.4s
	sqrdmlsh	v10.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	ldp	q0, q1, [x1, #320]
	ldp	q2, q3, [x2, #320]
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v14.4s, v22.4s, v0.4s
	sqrdmulh	v16.4s, v24.4s, v1.4s
	sqrdmlsh	v14.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	ldp	q0, q1, [x1, #352]
	ldp	q2, q3, [x2, #352]
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v18.4s, v22.4s, v0.4s
	sqrdmulh	v20.4s, v24.4s, v1.4s
	sqrdmlsh	v18.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldp	q0, q1, [x1, #768]
	ldp	q2, q3, [x2, #768]
	mov	v21.16b, v5.16b
	mov	v22.16b, v7.16b
	trn1	v5.4s, v5.4s, v6.4s
	trn1	v7.4s, v7.4s, v8.4s
	trn2	v6.4s, v21.4s, v6.4s
	trn2	v8.4s, v22.4s, v8.4s
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v6.4s, v22.4s, v0.4s
	sqrdmulh	v8.4s, v24.4s, v1.4s
	sqrdmlsh	v6.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v23.4s, v4.s[0]
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	ldp	q0, q1, [x1, #800]
	ldp	q2, q3, [x2, #800]
	mov	v21.16b, v9.16b
	mov	v22.16b, v11.16b
	trn1	v9.4s, v9.4s, v10.4s
	trn1	v11.4s, v11.4s, v12.4s
	trn2	v10.4s, v21.4s, v10.4s
	trn2	v12.4s, v22.4s, v12.4s
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v10.4s, v22.4s, v0.4s
	sqrdmulh	v12.4s, v24.4s, v1.4s
	sqrdmlsh	v10.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	ldp	q0, q1, [x1, #832]
	ldp	q2, q3, [x2, #832]
	mov	v21.16b, v13.16b
	mov	v22.16b, v15.16b
	trn1	v13.4s, v13.4s, v14.4s
	trn1	v15.4s, v15.4s, v16.4s
	trn2	v14.4s, v21.4s, v14.4s
	trn2	v16.4s, v22.4s, v16.4s
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v14.4s, v22.4s, v0.4s
	sqrdmulh	v16.4s, v24.4s, v1.4s
	sqrdmlsh	v14.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	ldp	q0, q1, [x1, #864]
	ldp	q2, q3, [x2, #864]
	mov	v21.16b, v17.16b
	mov	v22.16b, v19.16b
	trn1	v17.4s, v17.4s, v18.4s
	trn1	v19.4s, v19.4s, v20.4s
	trn2	v18.4s, v21.4s, v18.4s
	trn2	v20.4s, v22.4s, v20.4s
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v18.4s, v22.4s, v0.4s
	sqrdmulh	v20.4s, v24.4s, v1.4s
	sqrdmlsh	v18.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1088]
	ldr	q1, [x1, #1104]
	ldr	q2, [x2, #1088]
	ldr	q3, [x2, #1104]
	mov	v21.16b, v5.16b
	mov	v22.16b, v7.16b
	trn1	v5.2d, v5.2d, v6.2d
	trn1	v7.2d, v7.2d, v8.2d
	trn2	v6.2d, v21.2d, v6.2d
	trn2	v8.2d, v22.2d, v8.2d
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v6.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[1]
	sqrdmlsh	v6.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v23.4s, v4.s[0]
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	mov	v21.16b, v9.16b
	mov	v22.16b, v11.16b
	trn1	v9.2d, v9.2d, v10.2d
	trn1	v11.2d, v11.2d, v12.2d
	trn2	v10.2d, v21.2d, v10.2d
	trn2	v12.2d, v22.2d, v12.2d
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v10.4s, v22.4s, v0.s[2]
	sqrdmulh	v12.4s, v24.4s, v0.s[3]
	sqrdmlsh	v10.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	mov	v21.16b, v13.16b
	mov	v22.16b, v15.16b
	trn1	v13.2d, v13.2d, v14.2d
	trn1	v15.2d, v15.2d, v16.2d
	trn2	v14.2d, v21.2d, v14.2d
	trn2	v16.2d, v22.2d, v16.2d
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v3.s[0]
	mul	v23.4s, v24.4s, v3.s[1]
	sqrdmulh	v14.4s, v22.4s, v1.s[0]
	sqrdmulh	v16.4s, v24.4s, v1.s[1]
	sqrdmlsh	v14.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	mov	v21.16b, v17.16b
	mov	v22.16b, v19.16b
	trn1	v17.2d, v17.2d, v18.2d
	trn1	v19.2d, v19.2d, v20.2d
	trn2	v18.2d, v21.2d, v18.2d
	trn2	v20.2d, v22.2d, v20.2d
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v3.s[2]
	mul	v23.4s, v24.4s, v3.s[3]
	sqrdmulh	v18.4s, v22.4s, v1.s[2]
	sqrdmulh	v20.4s, v24.4s, v1.s[3]
	sqrdmlsh	v18.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1184]
	ldr	q2, [x2, #1184]
	sub	v22.4s, v5.4s, v7.4s
	sub	v24.4s, v6.4s, v8.4s
	add	v5.4s, v5.4s, v7.4s
	add	v6.4s, v6.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v7.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[0]
	sqrdmlsh	v7.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v23.4s, v4.s[0]
	sshr	v7.4s, v7.4s, #1
	sshr	v8.4s, v8.4s, #1
	sub	v22.4s, v9.4s, v11.4s
	sub	v24.4s, v10.4s, v12.4s
	add	v9.4s, v9.4s, v11.4s
	add	v10.4s, v10.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v11.4s, v22.4s, v0.s[1]
	sqrdmulh	v12.4s, v24.4s, v0.s[1]
	sqrdmlsh	v11.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v15.4s
	sub	v24.4s, v14.4s, v16.4s
	add	v13.4s, v13.4s, v15.4s
	add	v14.4s, v14.4s, v16.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v15.4s, v22.4s, v0.s[2]
	sqrdmulh	v16.4s, v24.4s, v0.s[2]
	sqrdmlsh	v15.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v15.4s, v15.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v17.4s, v19.4s
	sub	v24.4s, v18.4s, v20.4s
	add	v17.4s, v17.4s, v19.4s
	add	v18.4s, v18.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[3]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v19.4s, v22.4s, v0.s[3]
	sqrdmulh	v20.4s, v24.4s, v0.s[3]
	sqrdmlsh	v19.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	stp	q5, q6, [x0, #512]
	stp	q7, q8, [x0, #544]
	stp	q9, q10, [x0, #576]
	stp	q11, q12, [x0, #608]
	stp	q13, q14, [x0, #640]
	stp	q15, q16, [x0, #672]
	stp	q17, q18, [x0, #704]
	stp	q19, q20, [x0, #736]
	ldp	q5, q6, [x0, #768]
	ldp	q7, q8, [x0, #800]
	ldp	q9, q10, [x0, #832]
	ldp	q11, q12, [x0, #864]
	ldp	q13, q14, [x0, #896]
	ldp	q15, q16, [x0, #928]
	ldp	q17, q18, [x0, #960]
	ldp	q19, q20, [x0, #992]
	ldp	q0, q1, [x1, #384]
	ldp	q2, q3, [x2, #384]
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v6.4s, v22.4s, v0.4s
	sqrdmulh	v8.4s, v24.4s, v1.4s
	sqrdmlsh	v6.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v23.4s, v4.s[0]
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	ldp	q0, q1, [x1, #416]
	ldp	q2, q3, [x2, #416]
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v10.4s, v22.4s, v0.4s
	sqrdmulh	v12.4s, v24.4s, v1.4s
	sqrdmlsh	v10.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	ldp	q0, q1, [x1, #448]
	ldp	q2, q3, [x2, #448]
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v14.4s, v22.4s, v0.4s
	sqrdmulh	v16.4s, v24.4s, v1.4s
	sqrdmlsh	v14.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	ldp	q0, q1, [x1, #480]
	ldp	q2, q3, [x2, #480]
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v18.4s, v22.4s, v0.4s
	sqrdmulh	v20.4s, v24.4s, v1.4s
	sqrdmlsh	v18.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldp	q0, q1, [x1, #896]
	ldp	q2, q3, [x2, #896]
	mov	v21.16b, v5.16b
	mov	v22.16b, v7.16b
	trn1	v5.4s, v5.4s, v6.4s
	trn1	v7.4s, v7.4s, v8.4s
	trn2	v6.4s, v21.4s, v6.4s
	trn2	v8.4s, v22.4s, v8.4s
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v6.4s, v22.4s, v0.4s
	sqrdmulh	v8.4s, v24.4s, v1.4s
	sqrdmlsh	v6.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v23.4s, v4.s[0]
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	ldp	q0, q1, [x1, #928]
	ldp	q2, q3, [x2, #928]
	mov	v21.16b, v9.16b
	mov	v22.16b, v11.16b
	trn1	v9.4s, v9.4s, v10.4s
	trn1	v11.4s, v11.4s, v12.4s
	trn2	v10.4s, v21.4s, v10.4s
	trn2	v12.4s, v22.4s, v12.4s
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v10.4s, v22.4s, v0.4s
	sqrdmulh	v12.4s, v24.4s, v1.4s
	sqrdmlsh	v10.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	ldp	q0, q1, [x1, #960]
	ldp	q2, q3, [x2, #960]
	mov	v21.16b, v13.16b
	mov	v22.16b, v15.16b
	trn1	v13.4s, v13.4s, v14.4s
	trn1	v15.4s, v15.4s, v16.4s
	trn2	v14.4s, v21.4s, v14.4s
	trn2	v16.4s, v22.4s, v16.4s
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v14.4s, v22.4s, v0.4s
	sqrdmulh	v16.4s, v24.4s, v1.4s
	sqrdmlsh	v14.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	ldp	q0, q1, [x1, #992]
	ldp	q2, q3, [x2, #992]
	mov	v21.16b, v17.16b
	mov	v22.16b, v19.16b
	trn1	v17.4s, v17.4s, v18.4s
	trn1	v19.4s, v19.4s, v20.4s
	trn2	v18.4s, v21.4s, v18.4s
	trn2	v20.4s, v22.4s, v20.4s
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v18.4s, v22.4s, v0.4s
	sqrdmulh	v20.4s, v24.4s, v1.4s
	sqrdmlsh	v18.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1120]
	ldr	q1, [x1, #1136]
	ldr	q2, [x2, #1120]
	ldr	q3, [x2, #1136]
	mov	v21.16b, v5.16b
	mov	v22.16b, v7.16b
	trn1	v5.2d, v5.2d, v6.2d
	trn1	v7.2d, v7.2d, v8.2d
	trn2	v6.2d, v21.2d, v6.2d
	trn2	v8.2d, v22.2d, v8.2d
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v6.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[1]
	sqrdmlsh	v6.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v23.4s, v4.s[0]
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	mov	v21.16b, v9.16b
	mov	v22.16b, v11.16b
	trn1	v9.2d, v9.2d, v10.2d
	trn1	v11.2d, v11.2d, v12.2d
	trn2	v10.2d, v21.2d, v10.2d
	trn2	v12.2d, v22.2d, v12.2d
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v10.4s, v22.4s, v0.s[2]
	sqrdmulh	v12.4s, v24.4s, v0.s[3]
	sqrdmlsh	v10.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	mov	v21.16b, v13.16b
	mov	v22.16b, v15.16b
	trn1	v13.2d, v13.2d, v14.2d
	trn1	v15.2d, v15.2d, v16.2d
	trn2	v14.2d, v21.2d, v14.2d
	trn2	v16.2d, v22.2d, v16.2d
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v3.s[0]
	mul	v23.4s, v24.4s, v3.s[1]
	sqrdmulh	v14.4s, v22.4s, v1.s[0]
	sqrdmulh	v16.4s, v24.4s, v1.s[1]
	sqrdmlsh	v14.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	mov	v21.16b, v17.16b
	mov	v22.16b, v19.16b
	trn1	v17.2d, v17.2d, v18.2d
	trn1	v19.2d, v19.2d, v20.2d
	trn2	v18.2d, v21.2d, v18.2d
	trn2	v20.2d, v22.2d, v20.2d
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v3.s[2]
	mul	v23.4s, v24.4s, v3.s[3]
	sqrdmulh	v18.4s, v22.4s, v1.s[2]
	sqrdmulh	v20.4s, v24.4s, v1.s[3]
	sqrdmlsh	v18.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1200]
	ldr	q2, [x2, #1200]
	sub	v22.4s, v5.4s, v7.4s
	sub	v24.4s, v6.4s, v8.4s
	add	v5.4s, v5.4s, v7.4s
	add	v6.4s, v6.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v7.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[0]
	sqrdmlsh	v7.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v23.4s, v4.s[0]
	sshr	v7.4s, v7.4s, #1
	sshr	v8.4s, v8.4s, #1
	sub	v22.4s, v9.4s, v11.4s
	sub	v24.4s, v10.4s, v12.4s
	add	v9.4s, v9.4s, v11.4s
	add	v10.4s, v10.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v11.4s, v22.4s, v0.s[1]
	sqrdmulh	v12.4s, v24.4s, v0.s[1]
	sqrdmlsh	v11.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v15.4s
	sub	v24.4s, v14.4s, v16.4s
	add	v13.4s, v13.4s, v15.4s
	add	v14.4s, v14.4s, v16.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v15.4s, v22.4s, v0.s[2]
	sqrdmulh	v16.4s, v24.4s, v0.s[2]
	sqrdmlsh	v15.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v15.4s, v15.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v17.4s, v19.4s
	sub	v24.4s, v18.4s, v20.4s
	add	v17.4s, v17.4s, v19.4s
	add	v18.4s, v18.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[3]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v19.4s, v22.4s, v0.s[3]
	sqrdmulh	v20.4s, v24.4s, v0.s[3]
	sqrdmlsh	v19.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	stp	q5, q6, [x0, #768]
	stp	q7, q8, [x0, #800]
	stp	q9, q10, [x0, #832]
	stp	q11, q12, [x0, #864]
	stp	q13, q14, [x0, #896]
	stp	q15, q16, [x0, #928]
	stp	q17, q18, [x0, #960]
	stp	q19, q20, [x0, #992]
	ldr	q5, [x0]
	ldr	q6, [x0, #64]
	ldr	q7, [x0, #128]
	ldr	q8, [x0, #192]
	ldr	q9, [x0, #256]
	ldr	q10, [x0, #320]
	ldr	q11, [x0, #384]
	ldr	q12, [x0, #448]
	ldr	q13, [x0, #512]
	ldr	q14, [x0, #576]
	ldr	q15, [x0, #640]
	ldr	q16, [x0, #704]
	ldr	q17, [x0, #768]
	ldr	q18, [x0, #832]
	ldr	q19, [x0, #896]
	ldr	q20, [x0, #960]
	ldr	q0, [x1, #1216]
	ldr	q1, [x1, #1232]
	ldr	q2, [x2, #1216]
	ldr	q3, [x2, #1232]
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v6.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[1]
	sqrdmlsh	v6.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v23.4s, v4.s[0]
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v10.4s, v22.4s, v0.s[2]
	sqrdmulh	v12.4s, v24.4s, v0.s[3]
	sqrdmlsh	v10.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v3.s[0]
	mul	v23.4s, v24.4s, v3.s[1]
	sqrdmulh	v14.4s, v22.4s, v1.s[0]
	sqrdmulh	v16.4s, v24.4s, v1.s[1]
	sqrdmlsh	v14.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v3.s[2]
	mul	v23.4s, v24.4s, v3.s[3]
	sqrdmulh	v18.4s, v22.4s, v1.s[2]
	sqrdmulh	v20.4s, v24.4s, v1.s[3]
	sqrdmlsh	v18.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1248]
	ldr	q2, [x2, #1248]
	sub	v22.4s, v5.4s, v7.4s
	sub	v24.4s, v6.4s, v8.4s
	add	v5.4s, v5.4s, v7.4s
	add	v6.4s, v6.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v7.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[0]
	sqrdmlsh	v7.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v23.4s, v4.s[0]
	sshr	v7.4s, v7.4s, #1
	sshr	v8.4s, v8.4s, #1
	sub	v22.4s, v9.4s, v11.4s
	sub	v24.4s, v10.4s, v12.4s
	add	v9.4s, v9.4s, v11.4s
	add	v10.4s, v10.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v11.4s, v22.4s, v0.s[1]
	sqrdmulh	v12.4s, v24.4s, v0.s[1]
	sqrdmlsh	v11.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v15.4s
	sub	v24.4s, v14.4s, v16.4s
	add	v13.4s, v13.4s, v15.4s
	add	v14.4s, v14.4s, v16.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v15.4s, v22.4s, v0.s[2]
	sqrdmulh	v16.4s, v24.4s, v0.s[2]
	sqrdmlsh	v15.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v15.4s, v15.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v17.4s, v19.4s
	sub	v24.4s, v18.4s, v20.4s
	add	v17.4s, v17.4s, v19.4s
	add	v18.4s, v18.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[3]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v19.4s, v22.4s, v0.s[3]
	sqrdmulh	v20.4s, v24.4s, v0.s[3]
	sqrdmlsh	v19.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1264]
	ldr	q2, [x2, #1264]
	sub	v22.4s, v5.4s, v9.4s
	sub	v24.4s, v6.4s, v10.4s
	add	v5.4s, v5.4s, v9.4s
	add	v6.4s, v6.4s, v10.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v9.4s, v22.4s, v0.s[0]
	sqrdmulh	v10.4s, v24.4s, v0.s[0]
	sqrdmlsh	v9.4s, v21.4s, v4.s[0]
	sqrdmlsh	v10.4s, v23.4s, v4.s[0]
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	sub	v22.4s, v7.4s, v11.4s
	sub	v24.4s, v8.4s, v12.4s
	add	v7.4s, v7.4s, v11.4s
	add	v8.4s, v8.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v11.4s, v22.4s, v0.s[0]
	sqrdmulh	v12.4s, v24.4s, v0.s[0]
	sqrdmlsh	v11.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v17.4s
	sub	v24.4s, v14.4s, v18.4s
	add	v13.4s, v13.4s, v17.4s
	add	v14.4s, v14.4s, v18.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v17.4s, v22.4s, v0.s[1]
	sqrdmulh	v18.4s, v24.4s, v0.s[1]
	sqrdmlsh	v17.4s, v21.4s, v4.s[0]
	sqrdmlsh	v18.4s, v23.4s, v4.s[0]
	sshr	v17.4s, v17.4s, #1
	sshr	v18.4s, v18.4s, #1
	sub	v22.4s, v15.4s, v19.4s
	sub	v24.4s, v16.4s, v20.4s
	add	v15.4s, v15.4s, v19.4s
	add	v16.4s, v16.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v19.4s, v22.4s, v0.s[1]
	sqrdmulh	v20.4s, v24.4s, v0.s[1]
	sqrdmlsh	v19.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	sub	v22.4s, v5.4s, v13.4s
	sub	v24.4s, v6.4s, v14.4s
	add	v5.4s, v5.4s, v13.4s
	add	v6.4s, v6.4s, v14.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v13.4s, v22.4s, v0.s[2]
	sqrdmulh	v14.4s, v24.4s, v0.s[2]
	sqrdmlsh	v13.4s, v21.4s, v4.s[0]
	sqrdmlsh	v14.4s, v23.4s, v4.s[0]
	sshr	v13.4s, v13.4s, #1
	sshr	v14.4s, v14.4s, #1
	sub	v22.4s, v7.4s, v15.4s
	sub	v24.4s, v8.4s, v16.4s
	add	v7.4s, v7.4s, v15.4s
	add	v8.4s, v8.4s, v16.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v15.4s, v22.4s, v0.s[2]
	sqrdmulh	v16.4s, v24.4s, v0.s[2]
	sqrdmlsh	v15.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v15.4s, v15.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v9.4s, v17.4s
	sub	v24.4s, v10.4s, v18.4s
	add	v9.4s, v9.4s, v17.4s
	add	v10.4s, v10.4s, v18.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v17.4s, v22.4s, v0.s[2]
	sqrdmulh	v18.4s, v24.4s, v0.s[2]
	sqrdmlsh	v17.4s, v21.4s, v4.s[0]
	sqrdmlsh	v18.4s, v23.4s, v4.s[0]
	sshr	v17.4s, v17.4s, #1
	sshr	v18.4s, v18.4s, #1
	sub	v22.4s, v11.4s, v19.4s
	sub	v24.4s, v12.4s, v20.4s
	add	v11.4s, v11.4s, v19.4s
	add	v12.4s, v12.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v19.4s, v22.4s, v0.s[2]
	sqrdmulh	v20.4s, v24.4s, v0.s[2]
	sqrdmlsh	v19.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	mul	v21.4s, v5.4s, v2.s[3]
	mul	v22.4s, v6.4s, v2.s[3]
	sqrdmulh	v5.4s, v5.4s, v0.s[3]
	sqrdmulh	v6.4s, v6.4s, v0.s[3]
	sqrdmlsh	v5.4s, v21.4s, v4.s[0]
	sqrdmlsh	v6.4s, v22.4s, v4.s[0]
	sshr	v5.4s, v5.4s, #1
	sshr	v6.4s, v6.4s, #1
	mul	v21.4s, v7.4s, v2.s[3]
	mul	v22.4s, v8.4s, v2.s[3]
	sqrdmulh	v7.4s, v7.4s, v0.s[3]
	sqrdmulh	v8.4s, v8.4s, v0.s[3]
	sqrdmlsh	v7.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v22.4s, v4.s[0]
	sshr	v7.4s, v7.4s, #1
	sshr	v8.4s, v8.4s, #1
	mul	v21.4s, v9.4s, v2.s[3]
	mul	v22.4s, v10.4s, v2.s[3]
	sqrdmulh	v9.4s, v9.4s, v0.s[3]
	sqrdmulh	v10.4s, v10.4s, v0.s[3]
	sqrdmlsh	v9.4s, v21.4s, v4.s[0]
	sqrdmlsh	v10.4s, v22.4s, v4.s[0]
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	mul	v21.4s, v11.4s, v2.s[3]
	mul	v22.4s, v12.4s, v2.s[3]
	sqrdmulh	v11.4s, v11.4s, v0.s[3]
	sqrdmulh	v12.4s, v12.4s, v0.s[3]
	sqrdmlsh	v11.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v22.4s, v4.s[0]
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	str	q5, [x0]
	str	q6, [x0, #64]
	str	q7, [x0, #128]
	str	q8, [x0, #192]
	str	q9, [x0, #256]
	str	q10, [x0, #320]
	str	q11, [x0, #384]
	str	q12, [x0, #448]
	str	q13, [x0, #512]
	str	q14, [x0, #576]
	str	q15, [x0, #640]
	str	q16, [x0, #704]
	str	q17, [x0, #768]
	str	q18, [x0, #832]
	str	q19, [x0, #896]
	str	q20, [x0, #960]
	ldr	q5, [x0, #16]
	ldr	q6, [x0, #80]
	ldr	q7, [x0, #144]
	ldr	q8, [x0, #208]
	ldr	q9, [x0, #272]
	ldr	q10, [x0, #336]
	ldr	q11, [x0, #400]
	ldr	q12, [x0, #464]
	ldr	q13, [x0, #528]
	ldr	q14, [x0, #592]
	ldr	q15, [x0, #656]
	ldr	q16, [x0, #720]
	ldr	q17, [x0, #784]
	ldr	q18, [x0, #848]
	ldr	q19, [x0, #912]
	ldr	q20, [x0, #976]
	ldr	q0, [x1, #1216]
	ldr	q1, [x1, #1232]
	ldr	q2, [x2, #1216]
	ldr	q3, [x2, #1232]
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v6.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[1]
	sqrdmlsh	v6.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v23.4s, v4.s[0]
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v10.4s, v22.4s, v0.s[2]
	sqrdmulh	v12.4s, v24.4s, v0.s[3]
	sqrdmlsh	v10.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v3.s[0]
	mul	v23.4s, v24.4s, v3.s[1]
	sqrdmulh	v14.4s, v22.4s, v1.s[0]
	sqrdmulh	v16.4s, v24.4s, v1.s[1]
	sqrdmlsh	v14.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v3.s[2]
	mul	v23.4s, v24.4s, v3.s[3]
	sqrdmulh	v18.4s, v22.4s, v1.s[2]
	sqrdmulh	v20.4s, v24.4s, v1.s[3]
	sqrdmlsh	v18.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1248]
	ldr	q2, [x2, #1248]
	sub	v22.4s, v5.4s, v7.4s
	sub	v24.4s, v6.4s, v8.4s
	add	v5.4s, v5.4s, v7.4s
	add	v6.4s, v6.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v7.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[0]
	sqrdmlsh	v7.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v23.4s, v4.s[0]
	sshr	v7.4s, v7.4s, #1
	sshr	v8.4s, v8.4s, #1
	sub	v22.4s, v9.4s, v11.4s
	sub	v24.4s, v10.4s, v12.4s
	add	v9.4s, v9.4s, v11.4s
	add	v10.4s, v10.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v11.4s, v22.4s, v0.s[1]
	sqrdmulh	v12.4s, v24.4s, v0.s[1]
	sqrdmlsh	v11.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v15.4s
	sub	v24.4s, v14.4s, v16.4s
	add	v13.4s, v13.4s, v15.4s
	add	v14.4s, v14.4s, v16.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v15.4s, v22.4s, v0.s[2]
	sqrdmulh	v16.4s, v24.4s, v0.s[2]
	sqrdmlsh	v15.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v15.4s, v15.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v17.4s, v19.4s
	sub	v24.4s, v18.4s, v20.4s
	add	v17.4s, v17.4s, v19.4s
	add	v18.4s, v18.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[3]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v19.4s, v22.4s, v0.s[3]
	sqrdmulh	v20.4s, v24.4s, v0.s[3]
	sqrdmlsh	v19.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1264]
	ldr	q2, [x2, #1264]
	sub	v22.4s, v5.4s, v9.4s
	sub	v24.4s, v6.4s, v10.4s
	add	v5.4s, v5.4s, v9.4s
	add	v6.4s, v6.4s, v10.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v9.4s, v22.4s, v0.s[0]
	sqrdmulh	v10.4s, v24.4s, v0.s[0]
	sqrdmlsh	v9.4s, v21.4s, v4.s[0]
	sqrdmlsh	v10.4s, v23.4s, v4.s[0]
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	sub	v22.4s, v7.4s, v11.4s
	sub	v24.4s, v8.4s, v12.4s
	add	v7.4s, v7.4s, v11.4s
	add	v8.4s, v8.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v11.4s, v22.4s, v0.s[0]
	sqrdmulh	v12.4s, v24.4s, v0.s[0]
	sqrdmlsh	v11.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v17.4s
	sub	v24.4s, v14.4s, v18.4s
	add	v13.4s, v13.4s, v17.4s
	add	v14.4s, v14.4s, v18.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v17.4s, v22.4s, v0.s[1]
	sqrdmulh	v18.4s, v24.4s, v0.s[1]
	sqrdmlsh	v17.4s, v21.4s, v4.s[0]
	sqrdmlsh	v18.4s, v23.4s, v4.s[0]
	sshr	v17.4s, v17.4s, #1
	sshr	v18.4s, v18.4s, #1
	sub	v22.4s, v15.4s, v19.4s
	sub	v24.4s, v16.4s, v20.4s
	add	v15.4s, v15.4s, v19.4s
	add	v16.4s, v16.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v19.4s, v22.4s, v0.s[1]
	sqrdmulh	v20.4s, v24.4s, v0.s[1]
	sqrdmlsh	v19.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	sub	v22.4s, v5.4s, v13.4s
	sub	v24.4s, v6.4s, v14.4s
	add	v5.4s, v5.4s, v13.4s
	add	v6.4s, v6.4s, v14.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v13.4s, v22.4s, v0.s[2]
	sqrdmulh	v14.4s, v24.4s, v0.s[2]
	sqrdmlsh	v13.4s, v21.4s, v4.s[0]
	sqrdmlsh	v14.4s, v23.4s, v4.s[0]
	sshr	v13.4s, v13.4s, #1
	sshr	v14.4s, v14.4s, #1
	sub	v22.4s, v7.4s, v15.4s
	sub	v24.4s, v8.4s, v16.4s
	add	v7.4s, v7.4s, v15.4s
	add	v8.4s, v8.4s, v16.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v15.4s, v22.4s, v0.s[2]
	sqrdmulh	v16.4s, v24.4s, v0.s[2]
	sqrdmlsh	v15.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v15.4s, v15.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v9.4s, v17.4s
	sub	v24.4s, v10.4s, v18.4s
	add	v9.4s, v9.4s, v17.4s
	add	v10.4s, v10.4s, v18.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v17.4s, v22.4s, v0.s[2]
	sqrdmulh	v18.4s, v24.4s, v0.s[2]
	sqrdmlsh	v17.4s, v21.4s, v4.s[0]
	sqrdmlsh	v18.4s, v23.4s, v4.s[0]
	sshr	v17.4s, v17.4s, #1
	sshr	v18.4s, v18.4s, #1
	sub	v22.4s, v11.4s, v19.4s
	sub	v24.4s, v12.4s, v20.4s
	add	v11.4s, v11.4s, v19.4s
	add	v12.4s, v12.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v19.4s, v22.4s, v0.s[2]
	sqrdmulh	v20.4s, v24.4s, v0.s[2]
	sqrdmlsh	v19.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	mul	v21.4s, v5.4s, v2.s[3]
	mul	v22.4s, v6.4s, v2.s[3]
	sqrdmulh	v5.4s, v5.4s, v0.s[3]
	sqrdmulh	v6.4s, v6.4s, v0.s[3]
	sqrdmlsh	v5.4s, v21.4s, v4.s[0]
	sqrdmlsh	v6.4s, v22.4s, v4.s[0]
	sshr	v5.4s, v5.4s, #1
	sshr	v6.4s, v6.4s, #1
	mul	v21.4s, v7.4s, v2.s[3]
	mul	v22.4s, v8.4s, v2.s[3]
	sqrdmulh	v7.4s, v7.4s, v0.s[3]
	sqrdmulh	v8.4s, v8.4s, v0.s[3]
	sqrdmlsh	v7.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v22.4s, v4.s[0]
	sshr	v7.4s, v7.4s, #1
	sshr	v8.4s, v8.4s, #1
	mul	v21.4s, v9.4s, v2.s[3]
	mul	v22.4s, v10.4s, v2.s[3]
	sqrdmulh	v9.4s, v9.4s, v0.s[3]
	sqrdmulh	v10.4s, v10.4s, v0.s[3]
	sqrdmlsh	v9.4s, v21.4s, v4.s[0]
	sqrdmlsh	v10.4s, v22.4s, v4.s[0]
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	mul	v21.4s, v11.4s, v2.s[3]
	mul	v22.4s, v12.4s, v2.s[3]
	sqrdmulh	v11.4s, v11.4s, v0.s[3]
	sqrdmulh	v12.4s, v12.4s, v0.s[3]
	sqrdmlsh	v11.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v22.4s, v4.s[0]
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	str	q5, [x0, #16]
	str	q6, [x0, #80]
	str	q7, [x0, #144]
	str	q8, [x0, #208]
	str	q9, [x0, #272]
	str	q10, [x0, #336]
	str	q11, [x0, #400]
	str	q12, [x0, #464]
	str	q13, [x0, #528]
	str	q14, [x0, #592]
	str	q15, [x0, #656]
	str	q16, [x0, #720]
	str	q17, [x0, #784]
	str	q18, [x0, #848]
	str	q19, [x0, #912]
	str	q20, [x0, #976]
	ldr	q5, [x0, #32]
	ldr	q6, [x0, #96]
	ldr	q7, [x0, #160]
	ldr	q8, [x0, #224]
	ldr	q9, [x0, #288]
	ldr	q10, [x0, #352]
	ldr	q11, [x0, #416]
	ldr	q12, [x0, #480]
	ldr	q13, [x0, #544]
	ldr	q14, [x0, #608]
	ldr	q15, [x0, #672]
	ldr	q16, [x0, #736]
	ldr	q17, [x0, #800]
	ldr	q18, [x0, #864]
	ldr	q19, [x0, #928]
	ldr	q20, [x0, #992]
	ldr	q0, [x1, #1216]
	ldr	q1, [x1, #1232]
	ldr	q2, [x2, #1216]
	ldr	q3, [x2, #1232]
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v6.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[1]
	sqrdmlsh	v6.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v23.4s, v4.s[0]
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v10.4s, v22.4s, v0.s[2]
	sqrdmulh	v12.4s, v24.4s, v0.s[3]
	sqrdmlsh	v10.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v3.s[0]
	mul	v23.4s, v24.4s, v3.s[1]
	sqrdmulh	v14.4s, v22.4s, v1.s[0]
	sqrdmulh	v16.4s, v24.4s, v1.s[1]
	sqrdmlsh	v14.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v3.s[2]
	mul	v23.4s, v24.4s, v3.s[3]
	sqrdmulh	v18.4s, v22.4s, v1.s[2]
	sqrdmulh	v20.4s, v24.4s, v1.s[3]
	sqrdmlsh	v18.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1248]
	ldr	q2, [x2, #1248]
	sub	v22.4s, v5.4s, v7.4s
	sub	v24.4s, v6.4s, v8.4s
	add	v5.4s, v5.4s, v7.4s
	add	v6.4s, v6.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v7.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[0]
	sqrdmlsh	v7.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v23.4s, v4.s[0]
	sshr	v7.4s, v7.4s, #1
	sshr	v8.4s, v8.4s, #1
	sub	v22.4s, v9.4s, v11.4s
	sub	v24.4s, v10.4s, v12.4s
	add	v9.4s, v9.4s, v11.4s
	add	v10.4s, v10.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v11.4s, v22.4s, v0.s[1]
	sqrdmulh	v12.4s, v24.4s, v0.s[1]
	sqrdmlsh	v11.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v15.4s
	sub	v24.4s, v14.4s, v16.4s
	add	v13.4s, v13.4s, v15.4s
	add	v14.4s, v14.4s, v16.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v15.4s, v22.4s, v0.s[2]
	sqrdmulh	v16.4s, v24.4s, v0.s[2]
	sqrdmlsh	v15.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v15.4s, v15.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v17.4s, v19.4s
	sub	v24.4s, v18.4s, v20.4s
	add	v17.4s, v17.4s, v19.4s
	add	v18.4s, v18.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[3]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v19.4s, v22.4s, v0.s[3]
	sqrdmulh	v20.4s, v24.4s, v0.s[3]
	sqrdmlsh	v19.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1264]
	ldr	q2, [x2, #1264]
	sub	v22.4s, v5.4s, v9.4s
	sub	v24.4s, v6.4s, v10.4s
	add	v5.4s, v5.4s, v9.4s
	add	v6.4s, v6.4s, v10.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v9.4s, v22.4s, v0.s[0]
	sqrdmulh	v10.4s, v24.4s, v0.s[0]
	sqrdmlsh	v9.4s, v21.4s, v4.s[0]
	sqrdmlsh	v10.4s, v23.4s, v4.s[0]
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	sub	v22.4s, v7.4s, v11.4s
	sub	v24.4s, v8.4s, v12.4s
	add	v7.4s, v7.4s, v11.4s
	add	v8.4s, v8.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v11.4s, v22.4s, v0.s[0]
	sqrdmulh	v12.4s, v24.4s, v0.s[0]
	sqrdmlsh	v11.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v17.4s
	sub	v24.4s, v14.4s, v18.4s
	add	v13.4s, v13.4s, v17.4s
	add	v14.4s, v14.4s, v18.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v17.4s, v22.4s, v0.s[1]
	sqrdmulh	v18.4s, v24.4s, v0.s[1]
	sqrdmlsh	v17.4s, v21.4s, v4.s[0]
	sqrdmlsh	v18.4s, v23.4s, v4.s[0]
	sshr	v17.4s, v17.4s, #1
	sshr	v18.4s, v18.4s, #1
	sub	v22.4s, v15.4s, v19.4s
	sub	v24.4s, v16.4s, v20.4s
	add	v15.4s, v15.4s, v19.4s
	add	v16.4s, v16.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v19.4s, v22.4s, v0.s[1]
	sqrdmulh	v20.4s, v24.4s, v0.s[1]
	sqrdmlsh	v19.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	sub	v22.4s, v5.4s, v13.4s
	sub	v24.4s, v6.4s, v14.4s
	add	v5.4s, v5.4s, v13.4s
	add	v6.4s, v6.4s, v14.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v13.4s, v22.4s, v0.s[2]
	sqrdmulh	v14.4s, v24.4s, v0.s[2]
	sqrdmlsh	v13.4s, v21.4s, v4.s[0]
	sqrdmlsh	v14.4s, v23.4s, v4.s[0]
	sshr	v13.4s, v13.4s, #1
	sshr	v14.4s, v14.4s, #1
	sub	v22.4s, v7.4s, v15.4s
	sub	v24.4s, v8.4s, v16.4s
	add	v7.4s, v7.4s, v15.4s
	add	v8.4s, v8.4s, v16.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v15.4s, v22.4s, v0.s[2]
	sqrdmulh	v16.4s, v24.4s, v0.s[2]
	sqrdmlsh	v15.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v15.4s, v15.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v9.4s, v17.4s
	sub	v24.4s, v10.4s, v18.4s
	add	v9.4s, v9.4s, v17.4s
	add	v10.4s, v10.4s, v18.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v17.4s, v22.4s, v0.s[2]
	sqrdmulh	v18.4s, v24.4s, v0.s[2]
	sqrdmlsh	v17.4s, v21.4s, v4.s[0]
	sqrdmlsh	v18.4s, v23.4s, v4.s[0]
	sshr	v17.4s, v17.4s, #1
	sshr	v18.4s, v18.4s, #1
	sub	v22.4s, v11.4s, v19.4s
	sub	v24.4s, v12.4s, v20.4s
	add	v11.4s, v11.4s, v19.4s
	add	v12.4s, v12.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v19.4s, v22.4s, v0.s[2]
	sqrdmulh	v20.4s, v24.4s, v0.s[2]
	sqrdmlsh	v19.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	mul	v21.4s, v5.4s, v2.s[3]
	mul	v22.4s, v6.4s, v2.s[3]
	sqrdmulh	v5.4s, v5.4s, v0.s[3]
	sqrdmulh	v6.4s, v6.4s, v0.s[3]
	sqrdmlsh	v5.4s, v21.4s, v4.s[0]
	sqrdmlsh	v6.4s, v22.4s, v4.s[0]
	sshr	v5.4s, v5.4s, #1
	sshr	v6.4s, v6.4s, #1
	mul	v21.4s, v7.4s, v2.s[3]
	mul	v22.4s, v8.4s, v2.s[3]
	sqrdmulh	v7.4s, v7.4s, v0.s[3]
	sqrdmulh	v8.4s, v8.4s, v0.s[3]
	sqrdmlsh	v7.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v22.4s, v4.s[0]
	sshr	v7.4s, v7.4s, #1
	sshr	v8.4s, v8.4s, #1
	mul	v21.4s, v9.4s, v2.s[3]
	mul	v22.4s, v10.4s, v2.s[3]
	sqrdmulh	v9.4s, v9.4s, v0.s[3]
	sqrdmulh	v10.4s, v10.4s, v0.s[3]
	sqrdmlsh	v9.4s, v21.4s, v4.s[0]
	sqrdmlsh	v10.4s, v22.4s, v4.s[0]
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	mul	v21.4s, v11.4s, v2.s[3]
	mul	v22.4s, v12.4s, v2.s[3]
	sqrdmulh	v11.4s, v11.4s, v0.s[3]
	sqrdmulh	v12.4s, v12.4s, v0.s[3]
	sqrdmlsh	v11.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v22.4s, v4.s[0]
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	str	q5, [x0, #32]
	str	q6, [x0, #96]
	str	q7, [x0, #160]
	str	q8, [x0, #224]
	str	q9, [x0, #288]
	str	q10, [x0, #352]
	str	q11, [x0, #416]
	str	q12, [x0, #480]
	str	q13, [x0, #544]
	str	q14, [x0, #608]
	str	q15, [x0, #672]
	str	q16, [x0, #736]
	str	q17, [x0, #800]
	str	q18, [x0, #864]
	str	q19, [x0, #928]
	str	q20, [x0, #992]
	ldr	q5, [x0, #48]
	ldr	q6, [x0, #112]
	ldr	q7, [x0, #176]
	ldr	q8, [x0, #240]
	ldr	q9, [x0, #304]
	ldr	q10, [x0, #368]
	ldr	q11, [x0, #432]
	ldr	q12, [x0, #496]
	ldr	q13, [x0, #560]
	ldr	q14, [x0, #624]
	ldr	q15, [x0, #688]
	ldr	q16, [x0, #752]
	ldr	q17, [x0, #816]
	ldr	q18, [x0, #880]
	ldr	q19, [x0, #944]
	ldr	q20, [x0, #1008]
	ldr	q0, [x1, #1216]
	ldr	q1, [x1, #1232]
	ldr	q2, [x2, #1216]
	ldr	q3, [x2, #1232]
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v6.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[1]
	sqrdmlsh	v6.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v23.4s, v4.s[0]
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v10.4s, v22.4s, v0.s[2]
	sqrdmulh	v12.4s, v24.4s, v0.s[3]
	sqrdmlsh	v10.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v3.s[0]
	mul	v23.4s, v24.4s, v3.s[1]
	sqrdmulh	v14.4s, v22.4s, v1.s[0]
	sqrdmulh	v16.4s, v24.4s, v1.s[1]
	sqrdmlsh	v14.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v3.s[2]
	mul	v23.4s, v24.4s, v3.s[3]
	sqrdmulh	v18.4s, v22.4s, v1.s[2]
	sqrdmulh	v20.4s, v24.4s, v1.s[3]
	sqrdmlsh	v18.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1248]
	ldr	q2, [x2, #1248]
	sub	v22.4s, v5.4s, v7.4s
	sub	v24.4s, v6.4s, v8.4s
	add	v5.4s, v5.4s, v7.4s
	add	v6.4s, v6.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v7.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[0]
	sqrdmlsh	v7.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v23.4s, v4.s[0]
	sshr	v7.4s, v7.4s, #1
	sshr	v8.4s, v8.4s, #1
	sub	v22.4s, v9.4s, v11.4s
	sub	v24.4s, v10.4s, v12.4s
	add	v9.4s, v9.4s, v11.4s
	add	v10.4s, v10.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v11.4s, v22.4s, v0.s[1]
	sqrdmulh	v12.4s, v24.4s, v0.s[1]
	sqrdmlsh	v11.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v15.4s
	sub	v24.4s, v14.4s, v16.4s
	add	v13.4s, v13.4s, v15.4s
	add	v14.4s, v14.4s, v16.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v15.4s, v22.4s, v0.s[2]
	sqrdmulh	v16.4s, v24.4s, v0.s[2]
	sqrdmlsh	v15.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v15.4s, v15.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v17.4s, v19.4s
	sub	v24.4s, v18.4s, v20.4s
	add	v17.4s, v17.4s, v19.4s
	add	v18.4s, v18.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[3]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v19.4s, v22.4s, v0.s[3]
	sqrdmulh	v20.4s, v24.4s, v0.s[3]
	sqrdmlsh	v19.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1264]
	ldr	q2, [x2, #1264]
	sub	v22.4s, v5.4s, v9.4s
	sub	v24.4s, v6.4s, v10.4s
	add	v5.4s, v5.4s, v9.4s
	add	v6.4s, v6.4s, v10.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v9.4s, v22.4s, v0.s[0]
	sqrdmulh	v10.4s, v24.4s, v0.s[0]
	sqrdmlsh	v9.4s, v21.4s, v4.s[0]
	sqrdmlsh	v10.4s, v23.4s, v4.s[0]
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	sub	v22.4s, v7.4s, v11.4s
	sub	v24.4s, v8.4s, v12.4s
	add	v7.4s, v7.4s, v11.4s
	add	v8.4s, v8.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v11.4s, v22.4s, v0.s[0]
	sqrdmulh	v12.4s, v24.4s, v0.s[0]
	sqrdmlsh	v11.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v17.4s
	sub	v24.4s, v14.4s, v18.4s
	add	v13.4s, v13.4s, v17.4s
	add	v14.4s, v14.4s, v18.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v17.4s, v22.4s, v0.s[1]
	sqrdmulh	v18.4s, v24.4s, v0.s[1]
	sqrdmlsh	v17.4s, v21.4s, v4.s[0]
	sqrdmlsh	v18.4s, v23.4s, v4.s[0]
	sshr	v17.4s, v17.4s, #1
	sshr	v18.4s, v18.4s, #1
	sub	v22.4s, v15.4s, v19.4s
	sub	v24.4s, v16.4s, v20.4s
	add	v15.4s, v15.4s, v19.4s
	add	v16.4s, v16.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v19.4s, v22.4s, v0.s[1]
	sqrdmulh	v20.4s, v24.4s, v0.s[1]
	sqrdmlsh	v19.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	sub	v22.4s, v5.4s, v13.4s
	sub	v24.4s, v6.4s, v14.4s
	add	v5.4s, v5.4s, v13.4s
	add	v6.4s, v6.4s, v14.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v13.4s, v22.4s, v0.s[2]
	sqrdmulh	v14.4s, v24.4s, v0.s[2]
	sqrdmlsh	v13.4s, v21.4s, v4.s[0]
	sqrdmlsh	v14.4s, v23.4s, v4.s[0]
	sshr	v13.4s, v13.4s, #1
	sshr	v14.4s, v14.4s, #1
	sub	v22.4s, v7.4s, v15.4s
	sub	v24.4s, v8.4s, v16.4s
	add	v7.4s, v7.4s, v15.4s
	add	v8.4s, v8.4s, v16.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v15.4s, v22.4s, v0.s[2]
	sqrdmulh	v16.4s, v24.4s, v0.s[2]
	sqrdmlsh	v15.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v15.4s, v15.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v9.4s, v17.4s
	sub	v24.4s, v10.4s, v18.4s
	add	v9.4s, v9.4s, v17.4s
	add	v10.4s, v10.4s, v18.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v17.4s, v22.4s, v0.s[2]
	sqrdmulh	v18.4s, v24.4s, v0.s[2]
	sqrdmlsh	v17.4s, v21.4s, v4.s[0]
	sqrdmlsh	v18.4s, v23.4s, v4.s[0]
	sshr	v17.4s, v17.4s, #1
	sshr	v18.4s, v18.4s, #1
	sub	v22.4s, v11.4s, v19.4s
	sub	v24.4s, v12.4s, v20.4s
	add	v11.4s, v11.4s, v19.4s
	add	v12.4s, v12.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v19.4s, v22.4s, v0.s[2]
	sqrdmulh	v20.4s, v24.4s, v0.s[2]
	sqrdmlsh	v19.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	mul	v21.4s, v5.4s, v2.s[3]
	mul	v22.4s, v6.4s, v2.s[3]
	sqrdmulh	v5.4s, v5.4s, v0.s[3]
	sqrdmulh	v6.4s, v6.4s, v0.s[3]
	sqrdmlsh	v5.4s, v21.4s, v4.s[0]
	sqrdmlsh	v6.4s, v22.4s, v4.s[0]
	sshr	v5.4s, v5.4s, #1
	sshr	v6.4s, v6.4s, #1
	mul	v21.4s, v7.4s, v2.s[3]
	mul	v22.4s, v8.4s, v2.s[3]
	sqrdmulh	v7.4s, v7.4s, v0.s[3]
	sqrdmulh	v8.4s, v8.4s, v0.s[3]
	sqrdmlsh	v7.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v22.4s, v4.s[0]
	sshr	v7.4s, v7.4s, #1
	sshr	v8.4s, v8.4s, #1
	mul	v21.4s, v9.4s, v2.s[3]
	mul	v22.4s, v10.4s, v2.s[3]
	sqrdmulh	v9.4s, v9.4s, v0.s[3]
	sqrdmulh	v10.4s, v10.4s, v0.s[3]
	sqrdmlsh	v9.4s, v21.4s, v4.s[0]
	sqrdmlsh	v10.4s, v22.4s, v4.s[0]
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	mul	v21.4s, v11.4s, v2.s[3]
	mul	v22.4s, v12.4s, v2.s[3]
	sqrdmulh	v11.4s, v11.4s, v0.s[3]
	sqrdmulh	v12.4s, v12.4s, v0.s[3]
	sqrdmlsh	v11.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v22.4s, v4.s[0]
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	str	q5, [x0, #48]
	str	q6, [x0, #112]
	str	q7, [x0, #176]
	str	q8, [x0, #240]
	str	q9, [x0, #304]
	str	q10, [x0, #368]
	str	q11, [x0, #432]
	str	q12, [x0, #496]
	str	q13, [x0, #560]
	str	q14, [x0, #624]
	str	q15, [x0, #688]
	str	q16, [x0, #752]
	str	q17, [x0, #816]
	str	q18, [x0, #880]
	str	q19, [x0, #944]
	str	q20, [x0, #1008]
	ldp	d8, d9, [x29, #16]
	ldp	d10, d11, [x29, #32]
	ldp	d12, d13, [x29, #48]
	ldp	d14, d15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
#ifndef __APPLE__
	.size	mldsa_invntt_sqrdmlsh_neon,.-mldsa_invntt_sqrdmlsh_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	mldsa_invntt_full_sqrdmlsh_neon
WC_ASM_ATT_HIDDEN(mldsa_invntt_full_sqrdmlsh_neon)
.type	mldsa_invntt_full_sqrdmlsh_neon,@function
.align	2
mldsa_invntt_full_sqrdmlsh_neon:
#else
.section	__TEXT,__text
.globl	_mldsa_invntt_full_sqrdmlsh_neon
WC_ASM_ATT_HIDDEN(_mldsa_invntt_full_sqrdmlsh_neon)
.p2align	2
_mldsa_invntt_full_sqrdmlsh_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
	stp	d12, d13, [x29, #48]
	stp	d14, d15, [x29, #64]
#ifndef __APPLE__
	adrp x1, L_mldsa_aarch64_zetas_inv
	add  x1, x1, :lo12:L_mldsa_aarch64_zetas_inv
#else
	adrp x1, L_mldsa_aarch64_zetas_inv@PAGE
	add  x1, x1, L_mldsa_aarch64_zetas_inv@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x2, L_mldsa_aarch64_zetas_inv_qinv
	add  x2, x2, :lo12:L_mldsa_aarch64_zetas_inv_qinv
#else
	adrp x2, L_mldsa_aarch64_zetas_inv_qinv@PAGE
	add  x2, x2, L_mldsa_aarch64_zetas_inv_qinv@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x3, L_mldsa_aarch64_consts
	add  x3, x3, :lo12:L_mldsa_aarch64_consts
#else
	adrp x3, L_mldsa_aarch64_consts@PAGE
	add  x3, x3, L_mldsa_aarch64_consts@PAGEOFF
#endif /* __APPLE__ */
	ldr	q4, [x3]
	ldp	q5, q6, [x0]
	ldp	q7, q8, [x0, #32]
	ldp	q9, q10, [x0, #64]
	ldp	q11, q12, [x0, #96]
	ldp	q13, q14, [x0, #128]
	ldp	q15, q16, [x0, #160]
	ldp	q17, q18, [x0, #192]
	ldp	q19, q20, [x0, #224]
	trn1	v21.2d, v5.2d, v6.2d
	trn2	v22.2d, v5.2d, v6.2d
	trn1	v5.4s, v21.4s, v22.4s
	trn2	v6.4s, v21.4s, v22.4s
	trn1	v21.2d, v7.2d, v8.2d
	trn2	v22.2d, v7.2d, v8.2d
	trn1	v7.4s, v21.4s, v22.4s
	trn2	v8.4s, v21.4s, v22.4s
	trn1	v21.2d, v9.2d, v10.2d
	trn2	v22.2d, v9.2d, v10.2d
	trn1	v9.4s, v21.4s, v22.4s
	trn2	v10.4s, v21.4s, v22.4s
	trn1	v21.2d, v11.2d, v12.2d
	trn2	v22.2d, v11.2d, v12.2d
	trn1	v11.4s, v21.4s, v22.4s
	trn2	v12.4s, v21.4s, v22.4s
	trn1	v21.2d, v13.2d, v14.2d
	trn2	v22.2d, v13.2d, v14.2d
	trn1	v13.4s, v21.4s, v22.4s
	trn2	v14.4s, v21.4s, v22.4s
	trn1	v21.2d, v15.2d, v16.2d
	trn2	v22.2d, v15.2d, v16.2d
	trn1	v15.4s, v21.4s, v22.4s
	trn2	v16.4s, v21.4s, v22.4s
	trn1	v21.2d, v17.2d, v18.2d
	trn2	v22.2d, v17.2d, v18.2d
	trn1	v17.4s, v21.4s, v22.4s
	trn2	v18.4s, v21.4s, v22.4s
	trn1	v21.2d, v19.2d, v20.2d
	trn2	v22.2d, v19.2d, v20.2d
	trn1	v19.4s, v21.4s, v22.4s
	trn2	v20.4s, v21.4s, v22.4s
	ldp	q0, q1, [x1]
	ldp	q2, q3, [x2]
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v6.4s, v22.4s, v0.4s
	sqrdmulh	v8.4s, v24.4s, v1.4s
	sqrdmlsh	v6.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v23.4s, v4.s[0]
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	ldp	q0, q1, [x1, #32]
	ldp	q2, q3, [x2, #32]
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v10.4s, v22.4s, v0.4s
	sqrdmulh	v12.4s, v24.4s, v1.4s
	sqrdmlsh	v10.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	ldp	q0, q1, [x1, #64]
	ldp	q2, q3, [x2, #64]
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v14.4s, v22.4s, v0.4s
	sqrdmulh	v16.4s, v24.4s, v1.4s
	sqrdmlsh	v14.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	ldp	q0, q1, [x1, #96]
	ldp	q2, q3, [x2, #96]
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v18.4s, v22.4s, v0.4s
	sqrdmulh	v20.4s, v24.4s, v1.4s
	sqrdmlsh	v18.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldp	q0, q1, [x1, #512]
	ldp	q2, q3, [x2, #512]
	mov	v21.16b, v5.16b
	mov	v22.16b, v7.16b
	trn1	v5.4s, v5.4s, v6.4s
	trn1	v7.4s, v7.4s, v8.4s
	trn2	v6.4s, v21.4s, v6.4s
	trn2	v8.4s, v22.4s, v8.4s
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v6.4s, v22.4s, v0.4s
	sqrdmulh	v8.4s, v24.4s, v1.4s
	sqrdmlsh	v6.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v23.4s, v4.s[0]
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	ldp	q0, q1, [x1, #544]
	ldp	q2, q3, [x2, #544]
	mov	v21.16b, v9.16b
	mov	v22.16b, v11.16b
	trn1	v9.4s, v9.4s, v10.4s
	trn1	v11.4s, v11.4s, v12.4s
	trn2	v10.4s, v21.4s, v10.4s
	trn2	v12.4s, v22.4s, v12.4s
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v10.4s, v22.4s, v0.4s
	sqrdmulh	v12.4s, v24.4s, v1.4s
	sqrdmlsh	v10.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	ldp	q0, q1, [x1, #576]
	ldp	q2, q3, [x2, #576]
	mov	v21.16b, v13.16b
	mov	v22.16b, v15.16b
	trn1	v13.4s, v13.4s, v14.4s
	trn1	v15.4s, v15.4s, v16.4s
	trn2	v14.4s, v21.4s, v14.4s
	trn2	v16.4s, v22.4s, v16.4s
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v14.4s, v22.4s, v0.4s
	sqrdmulh	v16.4s, v24.4s, v1.4s
	sqrdmlsh	v14.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	ldp	q0, q1, [x1, #608]
	ldp	q2, q3, [x2, #608]
	mov	v21.16b, v17.16b
	mov	v22.16b, v19.16b
	trn1	v17.4s, v17.4s, v18.4s
	trn1	v19.4s, v19.4s, v20.4s
	trn2	v18.4s, v21.4s, v18.4s
	trn2	v20.4s, v22.4s, v20.4s
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v18.4s, v22.4s, v0.4s
	sqrdmulh	v20.4s, v24.4s, v1.4s
	sqrdmlsh	v18.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1024]
	ldr	q1, [x1, #1040]
	ldr	q2, [x2, #1024]
	ldr	q3, [x2, #1040]
	mov	v21.16b, v5.16b
	mov	v22.16b, v7.16b
	trn1	v5.2d, v5.2d, v6.2d
	trn1	v7.2d, v7.2d, v8.2d
	trn2	v6.2d, v21.2d, v6.2d
	trn2	v8.2d, v22.2d, v8.2d
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v6.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[1]
	sqrdmlsh	v6.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v23.4s, v4.s[0]
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	mov	v21.16b, v9.16b
	mov	v22.16b, v11.16b
	trn1	v9.2d, v9.2d, v10.2d
	trn1	v11.2d, v11.2d, v12.2d
	trn2	v10.2d, v21.2d, v10.2d
	trn2	v12.2d, v22.2d, v12.2d
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v10.4s, v22.4s, v0.s[2]
	sqrdmulh	v12.4s, v24.4s, v0.s[3]
	sqrdmlsh	v10.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	mov	v21.16b, v13.16b
	mov	v22.16b, v15.16b
	trn1	v13.2d, v13.2d, v14.2d
	trn1	v15.2d, v15.2d, v16.2d
	trn2	v14.2d, v21.2d, v14.2d
	trn2	v16.2d, v22.2d, v16.2d
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v3.s[0]
	mul	v23.4s, v24.4s, v3.s[1]
	sqrdmulh	v14.4s, v22.4s, v1.s[0]
	sqrdmulh	v16.4s, v24.4s, v1.s[1]
	sqrdmlsh	v14.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	mov	v21.16b, v17.16b
	mov	v22.16b, v19.16b
	trn1	v17.2d, v17.2d, v18.2d
	trn1	v19.2d, v19.2d, v20.2d
	trn2	v18.2d, v21.2d, v18.2d
	trn2	v20.2d, v22.2d, v20.2d
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v3.s[2]
	mul	v23.4s, v24.4s, v3.s[3]
	sqrdmulh	v18.4s, v22.4s, v1.s[2]
	sqrdmulh	v20.4s, v24.4s, v1.s[3]
	sqrdmlsh	v18.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1152]
	ldr	q2, [x2, #1152]
	sub	v22.4s, v5.4s, v7.4s
	sub	v24.4s, v6.4s, v8.4s
	add	v5.4s, v5.4s, v7.4s
	add	v6.4s, v6.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v7.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[0]
	sqrdmlsh	v7.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v23.4s, v4.s[0]
	sshr	v7.4s, v7.4s, #1
	sshr	v8.4s, v8.4s, #1
	sub	v22.4s, v9.4s, v11.4s
	sub	v24.4s, v10.4s, v12.4s
	add	v9.4s, v9.4s, v11.4s
	add	v10.4s, v10.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v11.4s, v22.4s, v0.s[1]
	sqrdmulh	v12.4s, v24.4s, v0.s[1]
	sqrdmlsh	v11.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v15.4s
	sub	v24.4s, v14.4s, v16.4s
	add	v13.4s, v13.4s, v15.4s
	add	v14.4s, v14.4s, v16.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v15.4s, v22.4s, v0.s[2]
	sqrdmulh	v16.4s, v24.4s, v0.s[2]
	sqrdmlsh	v15.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v15.4s, v15.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v17.4s, v19.4s
	sub	v24.4s, v18.4s, v20.4s
	add	v17.4s, v17.4s, v19.4s
	add	v18.4s, v18.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[3]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v19.4s, v22.4s, v0.s[3]
	sqrdmulh	v20.4s, v24.4s, v0.s[3]
	sqrdmlsh	v19.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	stp	q5, q6, [x0]
	stp	q7, q8, [x0, #32]
	stp	q9, q10, [x0, #64]
	stp	q11, q12, [x0, #96]
	stp	q13, q14, [x0, #128]
	stp	q15, q16, [x0, #160]
	stp	q17, q18, [x0, #192]
	stp	q19, q20, [x0, #224]
	ldp	q5, q6, [x0, #256]
	ldp	q7, q8, [x0, #288]
	ldp	q9, q10, [x0, #320]
	ldp	q11, q12, [x0, #352]
	ldp	q13, q14, [x0, #384]
	ldp	q15, q16, [x0, #416]
	ldp	q17, q18, [x0, #448]
	ldp	q19, q20, [x0, #480]
	trn1	v21.2d, v5.2d, v6.2d
	trn2	v22.2d, v5.2d, v6.2d
	trn1	v5.4s, v21.4s, v22.4s
	trn2	v6.4s, v21.4s, v22.4s
	trn1	v21.2d, v7.2d, v8.2d
	trn2	v22.2d, v7.2d, v8.2d
	trn1	v7.4s, v21.4s, v22.4s
	trn2	v8.4s, v21.4s, v22.4s
	trn1	v21.2d, v9.2d, v10.2d
	trn2	v22.2d, v9.2d, v10.2d
	trn1	v9.4s, v21.4s, v22.4s
	trn2	v10.4s, v21.4s, v22.4s
	trn1	v21.2d, v11.2d, v12.2d
	trn2	v22.2d, v11.2d, v12.2d
	trn1	v11.4s, v21.4s, v22.4s
	trn2	v12.4s, v21.4s, v22.4s
	trn1	v21.2d, v13.2d, v14.2d
	trn2	v22.2d, v13.2d, v14.2d
	trn1	v13.4s, v21.4s, v22.4s
	trn2	v14.4s, v21.4s, v22.4s
	trn1	v21.2d, v15.2d, v16.2d
	trn2	v22.2d, v15.2d, v16.2d
	trn1	v15.4s, v21.4s, v22.4s
	trn2	v16.4s, v21.4s, v22.4s
	trn1	v21.2d, v17.2d, v18.2d
	trn2	v22.2d, v17.2d, v18.2d
	trn1	v17.4s, v21.4s, v22.4s
	trn2	v18.4s, v21.4s, v22.4s
	trn1	v21.2d, v19.2d, v20.2d
	trn2	v22.2d, v19.2d, v20.2d
	trn1	v19.4s, v21.4s, v22.4s
	trn2	v20.4s, v21.4s, v22.4s
	ldp	q0, q1, [x1, #128]
	ldp	q2, q3, [x2, #128]
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v6.4s, v22.4s, v0.4s
	sqrdmulh	v8.4s, v24.4s, v1.4s
	sqrdmlsh	v6.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v23.4s, v4.s[0]
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	ldp	q0, q1, [x1, #160]
	ldp	q2, q3, [x2, #160]
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v10.4s, v22.4s, v0.4s
	sqrdmulh	v12.4s, v24.4s, v1.4s
	sqrdmlsh	v10.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	ldp	q0, q1, [x1, #192]
	ldp	q2, q3, [x2, #192]
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v14.4s, v22.4s, v0.4s
	sqrdmulh	v16.4s, v24.4s, v1.4s
	sqrdmlsh	v14.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	ldp	q0, q1, [x1, #224]
	ldp	q2, q3, [x2, #224]
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v18.4s, v22.4s, v0.4s
	sqrdmulh	v20.4s, v24.4s, v1.4s
	sqrdmlsh	v18.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldp	q0, q1, [x1, #640]
	ldp	q2, q3, [x2, #640]
	mov	v21.16b, v5.16b
	mov	v22.16b, v7.16b
	trn1	v5.4s, v5.4s, v6.4s
	trn1	v7.4s, v7.4s, v8.4s
	trn2	v6.4s, v21.4s, v6.4s
	trn2	v8.4s, v22.4s, v8.4s
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v6.4s, v22.4s, v0.4s
	sqrdmulh	v8.4s, v24.4s, v1.4s
	sqrdmlsh	v6.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v23.4s, v4.s[0]
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	ldp	q0, q1, [x1, #672]
	ldp	q2, q3, [x2, #672]
	mov	v21.16b, v9.16b
	mov	v22.16b, v11.16b
	trn1	v9.4s, v9.4s, v10.4s
	trn1	v11.4s, v11.4s, v12.4s
	trn2	v10.4s, v21.4s, v10.4s
	trn2	v12.4s, v22.4s, v12.4s
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v10.4s, v22.4s, v0.4s
	sqrdmulh	v12.4s, v24.4s, v1.4s
	sqrdmlsh	v10.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	ldp	q0, q1, [x1, #704]
	ldp	q2, q3, [x2, #704]
	mov	v21.16b, v13.16b
	mov	v22.16b, v15.16b
	trn1	v13.4s, v13.4s, v14.4s
	trn1	v15.4s, v15.4s, v16.4s
	trn2	v14.4s, v21.4s, v14.4s
	trn2	v16.4s, v22.4s, v16.4s
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v14.4s, v22.4s, v0.4s
	sqrdmulh	v16.4s, v24.4s, v1.4s
	sqrdmlsh	v14.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	ldp	q0, q1, [x1, #736]
	ldp	q2, q3, [x2, #736]
	mov	v21.16b, v17.16b
	mov	v22.16b, v19.16b
	trn1	v17.4s, v17.4s, v18.4s
	trn1	v19.4s, v19.4s, v20.4s
	trn2	v18.4s, v21.4s, v18.4s
	trn2	v20.4s, v22.4s, v20.4s
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v18.4s, v22.4s, v0.4s
	sqrdmulh	v20.4s, v24.4s, v1.4s
	sqrdmlsh	v18.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1056]
	ldr	q1, [x1, #1072]
	ldr	q2, [x2, #1056]
	ldr	q3, [x2, #1072]
	mov	v21.16b, v5.16b
	mov	v22.16b, v7.16b
	trn1	v5.2d, v5.2d, v6.2d
	trn1	v7.2d, v7.2d, v8.2d
	trn2	v6.2d, v21.2d, v6.2d
	trn2	v8.2d, v22.2d, v8.2d
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v6.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[1]
	sqrdmlsh	v6.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v23.4s, v4.s[0]
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	mov	v21.16b, v9.16b
	mov	v22.16b, v11.16b
	trn1	v9.2d, v9.2d, v10.2d
	trn1	v11.2d, v11.2d, v12.2d
	trn2	v10.2d, v21.2d, v10.2d
	trn2	v12.2d, v22.2d, v12.2d
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v10.4s, v22.4s, v0.s[2]
	sqrdmulh	v12.4s, v24.4s, v0.s[3]
	sqrdmlsh	v10.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	mov	v21.16b, v13.16b
	mov	v22.16b, v15.16b
	trn1	v13.2d, v13.2d, v14.2d
	trn1	v15.2d, v15.2d, v16.2d
	trn2	v14.2d, v21.2d, v14.2d
	trn2	v16.2d, v22.2d, v16.2d
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v3.s[0]
	mul	v23.4s, v24.4s, v3.s[1]
	sqrdmulh	v14.4s, v22.4s, v1.s[0]
	sqrdmulh	v16.4s, v24.4s, v1.s[1]
	sqrdmlsh	v14.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	mov	v21.16b, v17.16b
	mov	v22.16b, v19.16b
	trn1	v17.2d, v17.2d, v18.2d
	trn1	v19.2d, v19.2d, v20.2d
	trn2	v18.2d, v21.2d, v18.2d
	trn2	v20.2d, v22.2d, v20.2d
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v3.s[2]
	mul	v23.4s, v24.4s, v3.s[3]
	sqrdmulh	v18.4s, v22.4s, v1.s[2]
	sqrdmulh	v20.4s, v24.4s, v1.s[3]
	sqrdmlsh	v18.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1168]
	ldr	q2, [x2, #1168]
	sub	v22.4s, v5.4s, v7.4s
	sub	v24.4s, v6.4s, v8.4s
	add	v5.4s, v5.4s, v7.4s
	add	v6.4s, v6.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v7.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[0]
	sqrdmlsh	v7.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v23.4s, v4.s[0]
	sshr	v7.4s, v7.4s, #1
	sshr	v8.4s, v8.4s, #1
	sub	v22.4s, v9.4s, v11.4s
	sub	v24.4s, v10.4s, v12.4s
	add	v9.4s, v9.4s, v11.4s
	add	v10.4s, v10.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v11.4s, v22.4s, v0.s[1]
	sqrdmulh	v12.4s, v24.4s, v0.s[1]
	sqrdmlsh	v11.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v15.4s
	sub	v24.4s, v14.4s, v16.4s
	add	v13.4s, v13.4s, v15.4s
	add	v14.4s, v14.4s, v16.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v15.4s, v22.4s, v0.s[2]
	sqrdmulh	v16.4s, v24.4s, v0.s[2]
	sqrdmlsh	v15.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v15.4s, v15.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v17.4s, v19.4s
	sub	v24.4s, v18.4s, v20.4s
	add	v17.4s, v17.4s, v19.4s
	add	v18.4s, v18.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[3]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v19.4s, v22.4s, v0.s[3]
	sqrdmulh	v20.4s, v24.4s, v0.s[3]
	sqrdmlsh	v19.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	stp	q5, q6, [x0, #256]
	stp	q7, q8, [x0, #288]
	stp	q9, q10, [x0, #320]
	stp	q11, q12, [x0, #352]
	stp	q13, q14, [x0, #384]
	stp	q15, q16, [x0, #416]
	stp	q17, q18, [x0, #448]
	stp	q19, q20, [x0, #480]
	ldp	q5, q6, [x0, #512]
	ldp	q7, q8, [x0, #544]
	ldp	q9, q10, [x0, #576]
	ldp	q11, q12, [x0, #608]
	ldp	q13, q14, [x0, #640]
	ldp	q15, q16, [x0, #672]
	ldp	q17, q18, [x0, #704]
	ldp	q19, q20, [x0, #736]
	trn1	v21.2d, v5.2d, v6.2d
	trn2	v22.2d, v5.2d, v6.2d
	trn1	v5.4s, v21.4s, v22.4s
	trn2	v6.4s, v21.4s, v22.4s
	trn1	v21.2d, v7.2d, v8.2d
	trn2	v22.2d, v7.2d, v8.2d
	trn1	v7.4s, v21.4s, v22.4s
	trn2	v8.4s, v21.4s, v22.4s
	trn1	v21.2d, v9.2d, v10.2d
	trn2	v22.2d, v9.2d, v10.2d
	trn1	v9.4s, v21.4s, v22.4s
	trn2	v10.4s, v21.4s, v22.4s
	trn1	v21.2d, v11.2d, v12.2d
	trn2	v22.2d, v11.2d, v12.2d
	trn1	v11.4s, v21.4s, v22.4s
	trn2	v12.4s, v21.4s, v22.4s
	trn1	v21.2d, v13.2d, v14.2d
	trn2	v22.2d, v13.2d, v14.2d
	trn1	v13.4s, v21.4s, v22.4s
	trn2	v14.4s, v21.4s, v22.4s
	trn1	v21.2d, v15.2d, v16.2d
	trn2	v22.2d, v15.2d, v16.2d
	trn1	v15.4s, v21.4s, v22.4s
	trn2	v16.4s, v21.4s, v22.4s
	trn1	v21.2d, v17.2d, v18.2d
	trn2	v22.2d, v17.2d, v18.2d
	trn1	v17.4s, v21.4s, v22.4s
	trn2	v18.4s, v21.4s, v22.4s
	trn1	v21.2d, v19.2d, v20.2d
	trn2	v22.2d, v19.2d, v20.2d
	trn1	v19.4s, v21.4s, v22.4s
	trn2	v20.4s, v21.4s, v22.4s
	ldp	q0, q1, [x1, #256]
	ldp	q2, q3, [x2, #256]
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v6.4s, v22.4s, v0.4s
	sqrdmulh	v8.4s, v24.4s, v1.4s
	sqrdmlsh	v6.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v23.4s, v4.s[0]
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	ldp	q0, q1, [x1, #288]
	ldp	q2, q3, [x2, #288]
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v10.4s, v22.4s, v0.4s
	sqrdmulh	v12.4s, v24.4s, v1.4s
	sqrdmlsh	v10.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	ldp	q0, q1, [x1, #320]
	ldp	q2, q3, [x2, #320]
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v14.4s, v22.4s, v0.4s
	sqrdmulh	v16.4s, v24.4s, v1.4s
	sqrdmlsh	v14.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	ldp	q0, q1, [x1, #352]
	ldp	q2, q3, [x2, #352]
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v18.4s, v22.4s, v0.4s
	sqrdmulh	v20.4s, v24.4s, v1.4s
	sqrdmlsh	v18.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldp	q0, q1, [x1, #768]
	ldp	q2, q3, [x2, #768]
	mov	v21.16b, v5.16b
	mov	v22.16b, v7.16b
	trn1	v5.4s, v5.4s, v6.4s
	trn1	v7.4s, v7.4s, v8.4s
	trn2	v6.4s, v21.4s, v6.4s
	trn2	v8.4s, v22.4s, v8.4s
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v6.4s, v22.4s, v0.4s
	sqrdmulh	v8.4s, v24.4s, v1.4s
	sqrdmlsh	v6.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v23.4s, v4.s[0]
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	ldp	q0, q1, [x1, #800]
	ldp	q2, q3, [x2, #800]
	mov	v21.16b, v9.16b
	mov	v22.16b, v11.16b
	trn1	v9.4s, v9.4s, v10.4s
	trn1	v11.4s, v11.4s, v12.4s
	trn2	v10.4s, v21.4s, v10.4s
	trn2	v12.4s, v22.4s, v12.4s
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v10.4s, v22.4s, v0.4s
	sqrdmulh	v12.4s, v24.4s, v1.4s
	sqrdmlsh	v10.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	ldp	q0, q1, [x1, #832]
	ldp	q2, q3, [x2, #832]
	mov	v21.16b, v13.16b
	mov	v22.16b, v15.16b
	trn1	v13.4s, v13.4s, v14.4s
	trn1	v15.4s, v15.4s, v16.4s
	trn2	v14.4s, v21.4s, v14.4s
	trn2	v16.4s, v22.4s, v16.4s
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v14.4s, v22.4s, v0.4s
	sqrdmulh	v16.4s, v24.4s, v1.4s
	sqrdmlsh	v14.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	ldp	q0, q1, [x1, #864]
	ldp	q2, q3, [x2, #864]
	mov	v21.16b, v17.16b
	mov	v22.16b, v19.16b
	trn1	v17.4s, v17.4s, v18.4s
	trn1	v19.4s, v19.4s, v20.4s
	trn2	v18.4s, v21.4s, v18.4s
	trn2	v20.4s, v22.4s, v20.4s
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v18.4s, v22.4s, v0.4s
	sqrdmulh	v20.4s, v24.4s, v1.4s
	sqrdmlsh	v18.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1088]
	ldr	q1, [x1, #1104]
	ldr	q2, [x2, #1088]
	ldr	q3, [x2, #1104]
	mov	v21.16b, v5.16b
	mov	v22.16b, v7.16b
	trn1	v5.2d, v5.2d, v6.2d
	trn1	v7.2d, v7.2d, v8.2d
	trn2	v6.2d, v21.2d, v6.2d
	trn2	v8.2d, v22.2d, v8.2d
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v6.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[1]
	sqrdmlsh	v6.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v23.4s, v4.s[0]
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	mov	v21.16b, v9.16b
	mov	v22.16b, v11.16b
	trn1	v9.2d, v9.2d, v10.2d
	trn1	v11.2d, v11.2d, v12.2d
	trn2	v10.2d, v21.2d, v10.2d
	trn2	v12.2d, v22.2d, v12.2d
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v10.4s, v22.4s, v0.s[2]
	sqrdmulh	v12.4s, v24.4s, v0.s[3]
	sqrdmlsh	v10.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	mov	v21.16b, v13.16b
	mov	v22.16b, v15.16b
	trn1	v13.2d, v13.2d, v14.2d
	trn1	v15.2d, v15.2d, v16.2d
	trn2	v14.2d, v21.2d, v14.2d
	trn2	v16.2d, v22.2d, v16.2d
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v3.s[0]
	mul	v23.4s, v24.4s, v3.s[1]
	sqrdmulh	v14.4s, v22.4s, v1.s[0]
	sqrdmulh	v16.4s, v24.4s, v1.s[1]
	sqrdmlsh	v14.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	mov	v21.16b, v17.16b
	mov	v22.16b, v19.16b
	trn1	v17.2d, v17.2d, v18.2d
	trn1	v19.2d, v19.2d, v20.2d
	trn2	v18.2d, v21.2d, v18.2d
	trn2	v20.2d, v22.2d, v20.2d
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v3.s[2]
	mul	v23.4s, v24.4s, v3.s[3]
	sqrdmulh	v18.4s, v22.4s, v1.s[2]
	sqrdmulh	v20.4s, v24.4s, v1.s[3]
	sqrdmlsh	v18.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1184]
	ldr	q2, [x2, #1184]
	sub	v22.4s, v5.4s, v7.4s
	sub	v24.4s, v6.4s, v8.4s
	add	v5.4s, v5.4s, v7.4s
	add	v6.4s, v6.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v7.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[0]
	sqrdmlsh	v7.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v23.4s, v4.s[0]
	sshr	v7.4s, v7.4s, #1
	sshr	v8.4s, v8.4s, #1
	sub	v22.4s, v9.4s, v11.4s
	sub	v24.4s, v10.4s, v12.4s
	add	v9.4s, v9.4s, v11.4s
	add	v10.4s, v10.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v11.4s, v22.4s, v0.s[1]
	sqrdmulh	v12.4s, v24.4s, v0.s[1]
	sqrdmlsh	v11.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v15.4s
	sub	v24.4s, v14.4s, v16.4s
	add	v13.4s, v13.4s, v15.4s
	add	v14.4s, v14.4s, v16.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v15.4s, v22.4s, v0.s[2]
	sqrdmulh	v16.4s, v24.4s, v0.s[2]
	sqrdmlsh	v15.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v15.4s, v15.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v17.4s, v19.4s
	sub	v24.4s, v18.4s, v20.4s
	add	v17.4s, v17.4s, v19.4s
	add	v18.4s, v18.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[3]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v19.4s, v22.4s, v0.s[3]
	sqrdmulh	v20.4s, v24.4s, v0.s[3]
	sqrdmlsh	v19.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	stp	q5, q6, [x0, #512]
	stp	q7, q8, [x0, #544]
	stp	q9, q10, [x0, #576]
	stp	q11, q12, [x0, #608]
	stp	q13, q14, [x0, #640]
	stp	q15, q16, [x0, #672]
	stp	q17, q18, [x0, #704]
	stp	q19, q20, [x0, #736]
	ldp	q5, q6, [x0, #768]
	ldp	q7, q8, [x0, #800]
	ldp	q9, q10, [x0, #832]
	ldp	q11, q12, [x0, #864]
	ldp	q13, q14, [x0, #896]
	ldp	q15, q16, [x0, #928]
	ldp	q17, q18, [x0, #960]
	ldp	q19, q20, [x0, #992]
	trn1	v21.2d, v5.2d, v6.2d
	trn2	v22.2d, v5.2d, v6.2d
	trn1	v5.4s, v21.4s, v22.4s
	trn2	v6.4s, v21.4s, v22.4s
	trn1	v21.2d, v7.2d, v8.2d
	trn2	v22.2d, v7.2d, v8.2d
	trn1	v7.4s, v21.4s, v22.4s
	trn2	v8.4s, v21.4s, v22.4s
	trn1	v21.2d, v9.2d, v10.2d
	trn2	v22.2d, v9.2d, v10.2d
	trn1	v9.4s, v21.4s, v22.4s
	trn2	v10.4s, v21.4s, v22.4s
	trn1	v21.2d, v11.2d, v12.2d
	trn2	v22.2d, v11.2d, v12.2d
	trn1	v11.4s, v21.4s, v22.4s
	trn2	v12.4s, v21.4s, v22.4s
	trn1	v21.2d, v13.2d, v14.2d
	trn2	v22.2d, v13.2d, v14.2d
	trn1	v13.4s, v21.4s, v22.4s
	trn2	v14.4s, v21.4s, v22.4s
	trn1	v21.2d, v15.2d, v16.2d
	trn2	v22.2d, v15.2d, v16.2d
	trn1	v15.4s, v21.4s, v22.4s
	trn2	v16.4s, v21.4s, v22.4s
	trn1	v21.2d, v17.2d, v18.2d
	trn2	v22.2d, v17.2d, v18.2d
	trn1	v17.4s, v21.4s, v22.4s
	trn2	v18.4s, v21.4s, v22.4s
	trn1	v21.2d, v19.2d, v20.2d
	trn2	v22.2d, v19.2d, v20.2d
	trn1	v19.4s, v21.4s, v22.4s
	trn2	v20.4s, v21.4s, v22.4s
	ldp	q0, q1, [x1, #384]
	ldp	q2, q3, [x2, #384]
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v6.4s, v22.4s, v0.4s
	sqrdmulh	v8.4s, v24.4s, v1.4s
	sqrdmlsh	v6.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v23.4s, v4.s[0]
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	ldp	q0, q1, [x1, #416]
	ldp	q2, q3, [x2, #416]
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v10.4s, v22.4s, v0.4s
	sqrdmulh	v12.4s, v24.4s, v1.4s
	sqrdmlsh	v10.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	ldp	q0, q1, [x1, #448]
	ldp	q2, q3, [x2, #448]
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v14.4s, v22.4s, v0.4s
	sqrdmulh	v16.4s, v24.4s, v1.4s
	sqrdmlsh	v14.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	ldp	q0, q1, [x1, #480]
	ldp	q2, q3, [x2, #480]
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v18.4s, v22.4s, v0.4s
	sqrdmulh	v20.4s, v24.4s, v1.4s
	sqrdmlsh	v18.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldp	q0, q1, [x1, #896]
	ldp	q2, q3, [x2, #896]
	mov	v21.16b, v5.16b
	mov	v22.16b, v7.16b
	trn1	v5.4s, v5.4s, v6.4s
	trn1	v7.4s, v7.4s, v8.4s
	trn2	v6.4s, v21.4s, v6.4s
	trn2	v8.4s, v22.4s, v8.4s
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v6.4s, v22.4s, v0.4s
	sqrdmulh	v8.4s, v24.4s, v1.4s
	sqrdmlsh	v6.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v23.4s, v4.s[0]
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	ldp	q0, q1, [x1, #928]
	ldp	q2, q3, [x2, #928]
	mov	v21.16b, v9.16b
	mov	v22.16b, v11.16b
	trn1	v9.4s, v9.4s, v10.4s
	trn1	v11.4s, v11.4s, v12.4s
	trn2	v10.4s, v21.4s, v10.4s
	trn2	v12.4s, v22.4s, v12.4s
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v10.4s, v22.4s, v0.4s
	sqrdmulh	v12.4s, v24.4s, v1.4s
	sqrdmlsh	v10.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	ldp	q0, q1, [x1, #960]
	ldp	q2, q3, [x2, #960]
	mov	v21.16b, v13.16b
	mov	v22.16b, v15.16b
	trn1	v13.4s, v13.4s, v14.4s
	trn1	v15.4s, v15.4s, v16.4s
	trn2	v14.4s, v21.4s, v14.4s
	trn2	v16.4s, v22.4s, v16.4s
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v14.4s, v22.4s, v0.4s
	sqrdmulh	v16.4s, v24.4s, v1.4s
	sqrdmlsh	v14.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	ldp	q0, q1, [x1, #992]
	ldp	q2, q3, [x2, #992]
	mov	v21.16b, v17.16b
	mov	v22.16b, v19.16b
	trn1	v17.4s, v17.4s, v18.4s
	trn1	v19.4s, v19.4s, v20.4s
	trn2	v18.4s, v21.4s, v18.4s
	trn2	v20.4s, v22.4s, v20.4s
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v2.4s
	mul	v23.4s, v24.4s, v3.4s
	sqrdmulh	v18.4s, v22.4s, v0.4s
	sqrdmulh	v20.4s, v24.4s, v1.4s
	sqrdmlsh	v18.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1120]
	ldr	q1, [x1, #1136]
	ldr	q2, [x2, #1120]
	ldr	q3, [x2, #1136]
	mov	v21.16b, v5.16b
	mov	v22.16b, v7.16b
	trn1	v5.2d, v5.2d, v6.2d
	trn1	v7.2d, v7.2d, v8.2d
	trn2	v6.2d, v21.2d, v6.2d
	trn2	v8.2d, v22.2d, v8.2d
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v6.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[1]
	sqrdmlsh	v6.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v23.4s, v4.s[0]
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	mov	v21.16b, v9.16b
	mov	v22.16b, v11.16b
	trn1	v9.2d, v9.2d, v10.2d
	trn1	v11.2d, v11.2d, v12.2d
	trn2	v10.2d, v21.2d, v10.2d
	trn2	v12.2d, v22.2d, v12.2d
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v10.4s, v22.4s, v0.s[2]
	sqrdmulh	v12.4s, v24.4s, v0.s[3]
	sqrdmlsh	v10.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	mov	v21.16b, v13.16b
	mov	v22.16b, v15.16b
	trn1	v13.2d, v13.2d, v14.2d
	trn1	v15.2d, v15.2d, v16.2d
	trn2	v14.2d, v21.2d, v14.2d
	trn2	v16.2d, v22.2d, v16.2d
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v3.s[0]
	mul	v23.4s, v24.4s, v3.s[1]
	sqrdmulh	v14.4s, v22.4s, v1.s[0]
	sqrdmulh	v16.4s, v24.4s, v1.s[1]
	sqrdmlsh	v14.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	mov	v21.16b, v17.16b
	mov	v22.16b, v19.16b
	trn1	v17.2d, v17.2d, v18.2d
	trn1	v19.2d, v19.2d, v20.2d
	trn2	v18.2d, v21.2d, v18.2d
	trn2	v20.2d, v22.2d, v20.2d
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v3.s[2]
	mul	v23.4s, v24.4s, v3.s[3]
	sqrdmulh	v18.4s, v22.4s, v1.s[2]
	sqrdmulh	v20.4s, v24.4s, v1.s[3]
	sqrdmlsh	v18.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1200]
	ldr	q2, [x2, #1200]
	sub	v22.4s, v5.4s, v7.4s
	sub	v24.4s, v6.4s, v8.4s
	add	v5.4s, v5.4s, v7.4s
	add	v6.4s, v6.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v7.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[0]
	sqrdmlsh	v7.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v23.4s, v4.s[0]
	sshr	v7.4s, v7.4s, #1
	sshr	v8.4s, v8.4s, #1
	sub	v22.4s, v9.4s, v11.4s
	sub	v24.4s, v10.4s, v12.4s
	add	v9.4s, v9.4s, v11.4s
	add	v10.4s, v10.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v11.4s, v22.4s, v0.s[1]
	sqrdmulh	v12.4s, v24.4s, v0.s[1]
	sqrdmlsh	v11.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v15.4s
	sub	v24.4s, v14.4s, v16.4s
	add	v13.4s, v13.4s, v15.4s
	add	v14.4s, v14.4s, v16.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v15.4s, v22.4s, v0.s[2]
	sqrdmulh	v16.4s, v24.4s, v0.s[2]
	sqrdmlsh	v15.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v15.4s, v15.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v17.4s, v19.4s
	sub	v24.4s, v18.4s, v20.4s
	add	v17.4s, v17.4s, v19.4s
	add	v18.4s, v18.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[3]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v19.4s, v22.4s, v0.s[3]
	sqrdmulh	v20.4s, v24.4s, v0.s[3]
	sqrdmlsh	v19.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	stp	q5, q6, [x0, #768]
	stp	q7, q8, [x0, #800]
	stp	q9, q10, [x0, #832]
	stp	q11, q12, [x0, #864]
	stp	q13, q14, [x0, #896]
	stp	q15, q16, [x0, #928]
	stp	q17, q18, [x0, #960]
	stp	q19, q20, [x0, #992]
	ldr	q5, [x0]
	ldr	q6, [x0, #64]
	ldr	q7, [x0, #128]
	ldr	q8, [x0, #192]
	ldr	q9, [x0, #256]
	ldr	q10, [x0, #320]
	ldr	q11, [x0, #384]
	ldr	q12, [x0, #448]
	ldr	q13, [x0, #512]
	ldr	q14, [x0, #576]
	ldr	q15, [x0, #640]
	ldr	q16, [x0, #704]
	ldr	q17, [x0, #768]
	ldr	q18, [x0, #832]
	ldr	q19, [x0, #896]
	ldr	q20, [x0, #960]
	ldr	q0, [x1, #1216]
	ldr	q1, [x1, #1232]
	ldr	q2, [x2, #1216]
	ldr	q3, [x2, #1232]
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v6.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[1]
	sqrdmlsh	v6.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v23.4s, v4.s[0]
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v10.4s, v22.4s, v0.s[2]
	sqrdmulh	v12.4s, v24.4s, v0.s[3]
	sqrdmlsh	v10.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v3.s[0]
	mul	v23.4s, v24.4s, v3.s[1]
	sqrdmulh	v14.4s, v22.4s, v1.s[0]
	sqrdmulh	v16.4s, v24.4s, v1.s[1]
	sqrdmlsh	v14.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v3.s[2]
	mul	v23.4s, v24.4s, v3.s[3]
	sqrdmulh	v18.4s, v22.4s, v1.s[2]
	sqrdmulh	v20.4s, v24.4s, v1.s[3]
	sqrdmlsh	v18.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1248]
	ldr	q2, [x2, #1248]
	sub	v22.4s, v5.4s, v7.4s
	sub	v24.4s, v6.4s, v8.4s
	add	v5.4s, v5.4s, v7.4s
	add	v6.4s, v6.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v7.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[0]
	sqrdmlsh	v7.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v23.4s, v4.s[0]
	sshr	v7.4s, v7.4s, #1
	sshr	v8.4s, v8.4s, #1
	sub	v22.4s, v9.4s, v11.4s
	sub	v24.4s, v10.4s, v12.4s
	add	v9.4s, v9.4s, v11.4s
	add	v10.4s, v10.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v11.4s, v22.4s, v0.s[1]
	sqrdmulh	v12.4s, v24.4s, v0.s[1]
	sqrdmlsh	v11.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v15.4s
	sub	v24.4s, v14.4s, v16.4s
	add	v13.4s, v13.4s, v15.4s
	add	v14.4s, v14.4s, v16.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v15.4s, v22.4s, v0.s[2]
	sqrdmulh	v16.4s, v24.4s, v0.s[2]
	sqrdmlsh	v15.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v15.4s, v15.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v17.4s, v19.4s
	sub	v24.4s, v18.4s, v20.4s
	add	v17.4s, v17.4s, v19.4s
	add	v18.4s, v18.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[3]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v19.4s, v22.4s, v0.s[3]
	sqrdmulh	v20.4s, v24.4s, v0.s[3]
	sqrdmlsh	v19.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1264]
	ldr	q2, [x2, #1264]
	sub	v22.4s, v5.4s, v9.4s
	sub	v24.4s, v6.4s, v10.4s
	add	v5.4s, v5.4s, v9.4s
	add	v6.4s, v6.4s, v10.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v9.4s, v22.4s, v0.s[0]
	sqrdmulh	v10.4s, v24.4s, v0.s[0]
	sqrdmlsh	v9.4s, v21.4s, v4.s[0]
	sqrdmlsh	v10.4s, v23.4s, v4.s[0]
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	sub	v22.4s, v7.4s, v11.4s
	sub	v24.4s, v8.4s, v12.4s
	add	v7.4s, v7.4s, v11.4s
	add	v8.4s, v8.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v11.4s, v22.4s, v0.s[0]
	sqrdmulh	v12.4s, v24.4s, v0.s[0]
	sqrdmlsh	v11.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v17.4s
	sub	v24.4s, v14.4s, v18.4s
	add	v13.4s, v13.4s, v17.4s
	add	v14.4s, v14.4s, v18.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v17.4s, v22.4s, v0.s[1]
	sqrdmulh	v18.4s, v24.4s, v0.s[1]
	sqrdmlsh	v17.4s, v21.4s, v4.s[0]
	sqrdmlsh	v18.4s, v23.4s, v4.s[0]
	sshr	v17.4s, v17.4s, #1
	sshr	v18.4s, v18.4s, #1
	sub	v22.4s, v15.4s, v19.4s
	sub	v24.4s, v16.4s, v20.4s
	add	v15.4s, v15.4s, v19.4s
	add	v16.4s, v16.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v19.4s, v22.4s, v0.s[1]
	sqrdmulh	v20.4s, v24.4s, v0.s[1]
	sqrdmlsh	v19.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	sub	v22.4s, v5.4s, v13.4s
	sub	v24.4s, v6.4s, v14.4s
	add	v5.4s, v5.4s, v13.4s
	add	v6.4s, v6.4s, v14.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v13.4s, v22.4s, v0.s[2]
	sqrdmulh	v14.4s, v24.4s, v0.s[2]
	sqrdmlsh	v13.4s, v21.4s, v4.s[0]
	sqrdmlsh	v14.4s, v23.4s, v4.s[0]
	sshr	v13.4s, v13.4s, #1
	sshr	v14.4s, v14.4s, #1
	sub	v22.4s, v7.4s, v15.4s
	sub	v24.4s, v8.4s, v16.4s
	add	v7.4s, v7.4s, v15.4s
	add	v8.4s, v8.4s, v16.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v15.4s, v22.4s, v0.s[2]
	sqrdmulh	v16.4s, v24.4s, v0.s[2]
	sqrdmlsh	v15.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v15.4s, v15.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v9.4s, v17.4s
	sub	v24.4s, v10.4s, v18.4s
	add	v9.4s, v9.4s, v17.4s
	add	v10.4s, v10.4s, v18.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v17.4s, v22.4s, v0.s[2]
	sqrdmulh	v18.4s, v24.4s, v0.s[2]
	sqrdmlsh	v17.4s, v21.4s, v4.s[0]
	sqrdmlsh	v18.4s, v23.4s, v4.s[0]
	sshr	v17.4s, v17.4s, #1
	sshr	v18.4s, v18.4s, #1
	sub	v22.4s, v11.4s, v19.4s
	sub	v24.4s, v12.4s, v20.4s
	add	v11.4s, v11.4s, v19.4s
	add	v12.4s, v12.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v19.4s, v22.4s, v0.s[2]
	sqrdmulh	v20.4s, v24.4s, v0.s[2]
	sqrdmlsh	v19.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	mul	v21.4s, v5.4s, v2.s[3]
	mul	v22.4s, v6.4s, v2.s[3]
	sqrdmulh	v5.4s, v5.4s, v0.s[3]
	sqrdmulh	v6.4s, v6.4s, v0.s[3]
	sqrdmlsh	v5.4s, v21.4s, v4.s[0]
	sqrdmlsh	v6.4s, v22.4s, v4.s[0]
	sshr	v5.4s, v5.4s, #1
	sshr	v6.4s, v6.4s, #1
	mul	v21.4s, v7.4s, v2.s[3]
	mul	v22.4s, v8.4s, v2.s[3]
	sqrdmulh	v7.4s, v7.4s, v0.s[3]
	sqrdmulh	v8.4s, v8.4s, v0.s[3]
	sqrdmlsh	v7.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v22.4s, v4.s[0]
	sshr	v7.4s, v7.4s, #1
	sshr	v8.4s, v8.4s, #1
	mul	v21.4s, v9.4s, v2.s[3]
	mul	v22.4s, v10.4s, v2.s[3]
	sqrdmulh	v9.4s, v9.4s, v0.s[3]
	sqrdmulh	v10.4s, v10.4s, v0.s[3]
	sqrdmlsh	v9.4s, v21.4s, v4.s[0]
	sqrdmlsh	v10.4s, v22.4s, v4.s[0]
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	mul	v21.4s, v11.4s, v2.s[3]
	mul	v22.4s, v12.4s, v2.s[3]
	sqrdmulh	v11.4s, v11.4s, v0.s[3]
	sqrdmulh	v12.4s, v12.4s, v0.s[3]
	sqrdmlsh	v11.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v22.4s, v4.s[0]
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	str	q5, [x0]
	str	q6, [x0, #64]
	str	q7, [x0, #128]
	str	q8, [x0, #192]
	str	q9, [x0, #256]
	str	q10, [x0, #320]
	str	q11, [x0, #384]
	str	q12, [x0, #448]
	str	q13, [x0, #512]
	str	q14, [x0, #576]
	str	q15, [x0, #640]
	str	q16, [x0, #704]
	str	q17, [x0, #768]
	str	q18, [x0, #832]
	str	q19, [x0, #896]
	str	q20, [x0, #960]
	ldr	q5, [x0, #16]
	ldr	q6, [x0, #80]
	ldr	q7, [x0, #144]
	ldr	q8, [x0, #208]
	ldr	q9, [x0, #272]
	ldr	q10, [x0, #336]
	ldr	q11, [x0, #400]
	ldr	q12, [x0, #464]
	ldr	q13, [x0, #528]
	ldr	q14, [x0, #592]
	ldr	q15, [x0, #656]
	ldr	q16, [x0, #720]
	ldr	q17, [x0, #784]
	ldr	q18, [x0, #848]
	ldr	q19, [x0, #912]
	ldr	q20, [x0, #976]
	ldr	q0, [x1, #1216]
	ldr	q1, [x1, #1232]
	ldr	q2, [x2, #1216]
	ldr	q3, [x2, #1232]
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v6.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[1]
	sqrdmlsh	v6.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v23.4s, v4.s[0]
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v10.4s, v22.4s, v0.s[2]
	sqrdmulh	v12.4s, v24.4s, v0.s[3]
	sqrdmlsh	v10.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v3.s[0]
	mul	v23.4s, v24.4s, v3.s[1]
	sqrdmulh	v14.4s, v22.4s, v1.s[0]
	sqrdmulh	v16.4s, v24.4s, v1.s[1]
	sqrdmlsh	v14.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v3.s[2]
	mul	v23.4s, v24.4s, v3.s[3]
	sqrdmulh	v18.4s, v22.4s, v1.s[2]
	sqrdmulh	v20.4s, v24.4s, v1.s[3]
	sqrdmlsh	v18.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1248]
	ldr	q2, [x2, #1248]
	sub	v22.4s, v5.4s, v7.4s
	sub	v24.4s, v6.4s, v8.4s
	add	v5.4s, v5.4s, v7.4s
	add	v6.4s, v6.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v7.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[0]
	sqrdmlsh	v7.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v23.4s, v4.s[0]
	sshr	v7.4s, v7.4s, #1
	sshr	v8.4s, v8.4s, #1
	sub	v22.4s, v9.4s, v11.4s
	sub	v24.4s, v10.4s, v12.4s
	add	v9.4s, v9.4s, v11.4s
	add	v10.4s, v10.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v11.4s, v22.4s, v0.s[1]
	sqrdmulh	v12.4s, v24.4s, v0.s[1]
	sqrdmlsh	v11.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v15.4s
	sub	v24.4s, v14.4s, v16.4s
	add	v13.4s, v13.4s, v15.4s
	add	v14.4s, v14.4s, v16.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v15.4s, v22.4s, v0.s[2]
	sqrdmulh	v16.4s, v24.4s, v0.s[2]
	sqrdmlsh	v15.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v15.4s, v15.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v17.4s, v19.4s
	sub	v24.4s, v18.4s, v20.4s
	add	v17.4s, v17.4s, v19.4s
	add	v18.4s, v18.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[3]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v19.4s, v22.4s, v0.s[3]
	sqrdmulh	v20.4s, v24.4s, v0.s[3]
	sqrdmlsh	v19.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1264]
	ldr	q2, [x2, #1264]
	sub	v22.4s, v5.4s, v9.4s
	sub	v24.4s, v6.4s, v10.4s
	add	v5.4s, v5.4s, v9.4s
	add	v6.4s, v6.4s, v10.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v9.4s, v22.4s, v0.s[0]
	sqrdmulh	v10.4s, v24.4s, v0.s[0]
	sqrdmlsh	v9.4s, v21.4s, v4.s[0]
	sqrdmlsh	v10.4s, v23.4s, v4.s[0]
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	sub	v22.4s, v7.4s, v11.4s
	sub	v24.4s, v8.4s, v12.4s
	add	v7.4s, v7.4s, v11.4s
	add	v8.4s, v8.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v11.4s, v22.4s, v0.s[0]
	sqrdmulh	v12.4s, v24.4s, v0.s[0]
	sqrdmlsh	v11.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v17.4s
	sub	v24.4s, v14.4s, v18.4s
	add	v13.4s, v13.4s, v17.4s
	add	v14.4s, v14.4s, v18.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v17.4s, v22.4s, v0.s[1]
	sqrdmulh	v18.4s, v24.4s, v0.s[1]
	sqrdmlsh	v17.4s, v21.4s, v4.s[0]
	sqrdmlsh	v18.4s, v23.4s, v4.s[0]
	sshr	v17.4s, v17.4s, #1
	sshr	v18.4s, v18.4s, #1
	sub	v22.4s, v15.4s, v19.4s
	sub	v24.4s, v16.4s, v20.4s
	add	v15.4s, v15.4s, v19.4s
	add	v16.4s, v16.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v19.4s, v22.4s, v0.s[1]
	sqrdmulh	v20.4s, v24.4s, v0.s[1]
	sqrdmlsh	v19.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	sub	v22.4s, v5.4s, v13.4s
	sub	v24.4s, v6.4s, v14.4s
	add	v5.4s, v5.4s, v13.4s
	add	v6.4s, v6.4s, v14.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v13.4s, v22.4s, v0.s[2]
	sqrdmulh	v14.4s, v24.4s, v0.s[2]
	sqrdmlsh	v13.4s, v21.4s, v4.s[0]
	sqrdmlsh	v14.4s, v23.4s, v4.s[0]
	sshr	v13.4s, v13.4s, #1
	sshr	v14.4s, v14.4s, #1
	sub	v22.4s, v7.4s, v15.4s
	sub	v24.4s, v8.4s, v16.4s
	add	v7.4s, v7.4s, v15.4s
	add	v8.4s, v8.4s, v16.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v15.4s, v22.4s, v0.s[2]
	sqrdmulh	v16.4s, v24.4s, v0.s[2]
	sqrdmlsh	v15.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v15.4s, v15.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v9.4s, v17.4s
	sub	v24.4s, v10.4s, v18.4s
	add	v9.4s, v9.4s, v17.4s
	add	v10.4s, v10.4s, v18.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v17.4s, v22.4s, v0.s[2]
	sqrdmulh	v18.4s, v24.4s, v0.s[2]
	sqrdmlsh	v17.4s, v21.4s, v4.s[0]
	sqrdmlsh	v18.4s, v23.4s, v4.s[0]
	sshr	v17.4s, v17.4s, #1
	sshr	v18.4s, v18.4s, #1
	sub	v22.4s, v11.4s, v19.4s
	sub	v24.4s, v12.4s, v20.4s
	add	v11.4s, v11.4s, v19.4s
	add	v12.4s, v12.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v19.4s, v22.4s, v0.s[2]
	sqrdmulh	v20.4s, v24.4s, v0.s[2]
	sqrdmlsh	v19.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	mul	v21.4s, v5.4s, v2.s[3]
	mul	v22.4s, v6.4s, v2.s[3]
	sqrdmulh	v5.4s, v5.4s, v0.s[3]
	sqrdmulh	v6.4s, v6.4s, v0.s[3]
	sqrdmlsh	v5.4s, v21.4s, v4.s[0]
	sqrdmlsh	v6.4s, v22.4s, v4.s[0]
	sshr	v5.4s, v5.4s, #1
	sshr	v6.4s, v6.4s, #1
	mul	v21.4s, v7.4s, v2.s[3]
	mul	v22.4s, v8.4s, v2.s[3]
	sqrdmulh	v7.4s, v7.4s, v0.s[3]
	sqrdmulh	v8.4s, v8.4s, v0.s[3]
	sqrdmlsh	v7.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v22.4s, v4.s[0]
	sshr	v7.4s, v7.4s, #1
	sshr	v8.4s, v8.4s, #1
	mul	v21.4s, v9.4s, v2.s[3]
	mul	v22.4s, v10.4s, v2.s[3]
	sqrdmulh	v9.4s, v9.4s, v0.s[3]
	sqrdmulh	v10.4s, v10.4s, v0.s[3]
	sqrdmlsh	v9.4s, v21.4s, v4.s[0]
	sqrdmlsh	v10.4s, v22.4s, v4.s[0]
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	mul	v21.4s, v11.4s, v2.s[3]
	mul	v22.4s, v12.4s, v2.s[3]
	sqrdmulh	v11.4s, v11.4s, v0.s[3]
	sqrdmulh	v12.4s, v12.4s, v0.s[3]
	sqrdmlsh	v11.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v22.4s, v4.s[0]
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	str	q5, [x0, #16]
	str	q6, [x0, #80]
	str	q7, [x0, #144]
	str	q8, [x0, #208]
	str	q9, [x0, #272]
	str	q10, [x0, #336]
	str	q11, [x0, #400]
	str	q12, [x0, #464]
	str	q13, [x0, #528]
	str	q14, [x0, #592]
	str	q15, [x0, #656]
	str	q16, [x0, #720]
	str	q17, [x0, #784]
	str	q18, [x0, #848]
	str	q19, [x0, #912]
	str	q20, [x0, #976]
	ldr	q5, [x0, #32]
	ldr	q6, [x0, #96]
	ldr	q7, [x0, #160]
	ldr	q8, [x0, #224]
	ldr	q9, [x0, #288]
	ldr	q10, [x0, #352]
	ldr	q11, [x0, #416]
	ldr	q12, [x0, #480]
	ldr	q13, [x0, #544]
	ldr	q14, [x0, #608]
	ldr	q15, [x0, #672]
	ldr	q16, [x0, #736]
	ldr	q17, [x0, #800]
	ldr	q18, [x0, #864]
	ldr	q19, [x0, #928]
	ldr	q20, [x0, #992]
	ldr	q0, [x1, #1216]
	ldr	q1, [x1, #1232]
	ldr	q2, [x2, #1216]
	ldr	q3, [x2, #1232]
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v6.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[1]
	sqrdmlsh	v6.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v23.4s, v4.s[0]
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v10.4s, v22.4s, v0.s[2]
	sqrdmulh	v12.4s, v24.4s, v0.s[3]
	sqrdmlsh	v10.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v3.s[0]
	mul	v23.4s, v24.4s, v3.s[1]
	sqrdmulh	v14.4s, v22.4s, v1.s[0]
	sqrdmulh	v16.4s, v24.4s, v1.s[1]
	sqrdmlsh	v14.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v3.s[2]
	mul	v23.4s, v24.4s, v3.s[3]
	sqrdmulh	v18.4s, v22.4s, v1.s[2]
	sqrdmulh	v20.4s, v24.4s, v1.s[3]
	sqrdmlsh	v18.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1248]
	ldr	q2, [x2, #1248]
	sub	v22.4s, v5.4s, v7.4s
	sub	v24.4s, v6.4s, v8.4s
	add	v5.4s, v5.4s, v7.4s
	add	v6.4s, v6.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v7.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[0]
	sqrdmlsh	v7.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v23.4s, v4.s[0]
	sshr	v7.4s, v7.4s, #1
	sshr	v8.4s, v8.4s, #1
	sub	v22.4s, v9.4s, v11.4s
	sub	v24.4s, v10.4s, v12.4s
	add	v9.4s, v9.4s, v11.4s
	add	v10.4s, v10.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v11.4s, v22.4s, v0.s[1]
	sqrdmulh	v12.4s, v24.4s, v0.s[1]
	sqrdmlsh	v11.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v15.4s
	sub	v24.4s, v14.4s, v16.4s
	add	v13.4s, v13.4s, v15.4s
	add	v14.4s, v14.4s, v16.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v15.4s, v22.4s, v0.s[2]
	sqrdmulh	v16.4s, v24.4s, v0.s[2]
	sqrdmlsh	v15.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v15.4s, v15.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v17.4s, v19.4s
	sub	v24.4s, v18.4s, v20.4s
	add	v17.4s, v17.4s, v19.4s
	add	v18.4s, v18.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[3]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v19.4s, v22.4s, v0.s[3]
	sqrdmulh	v20.4s, v24.4s, v0.s[3]
	sqrdmlsh	v19.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1264]
	ldr	q2, [x2, #1264]
	sub	v22.4s, v5.4s, v9.4s
	sub	v24.4s, v6.4s, v10.4s
	add	v5.4s, v5.4s, v9.4s
	add	v6.4s, v6.4s, v10.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v9.4s, v22.4s, v0.s[0]
	sqrdmulh	v10.4s, v24.4s, v0.s[0]
	sqrdmlsh	v9.4s, v21.4s, v4.s[0]
	sqrdmlsh	v10.4s, v23.4s, v4.s[0]
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	sub	v22.4s, v7.4s, v11.4s
	sub	v24.4s, v8.4s, v12.4s
	add	v7.4s, v7.4s, v11.4s
	add	v8.4s, v8.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v11.4s, v22.4s, v0.s[0]
	sqrdmulh	v12.4s, v24.4s, v0.s[0]
	sqrdmlsh	v11.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v17.4s
	sub	v24.4s, v14.4s, v18.4s
	add	v13.4s, v13.4s, v17.4s
	add	v14.4s, v14.4s, v18.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v17.4s, v22.4s, v0.s[1]
	sqrdmulh	v18.4s, v24.4s, v0.s[1]
	sqrdmlsh	v17.4s, v21.4s, v4.s[0]
	sqrdmlsh	v18.4s, v23.4s, v4.s[0]
	sshr	v17.4s, v17.4s, #1
	sshr	v18.4s, v18.4s, #1
	sub	v22.4s, v15.4s, v19.4s
	sub	v24.4s, v16.4s, v20.4s
	add	v15.4s, v15.4s, v19.4s
	add	v16.4s, v16.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v19.4s, v22.4s, v0.s[1]
	sqrdmulh	v20.4s, v24.4s, v0.s[1]
	sqrdmlsh	v19.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	sub	v22.4s, v5.4s, v13.4s
	sub	v24.4s, v6.4s, v14.4s
	add	v5.4s, v5.4s, v13.4s
	add	v6.4s, v6.4s, v14.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v13.4s, v22.4s, v0.s[2]
	sqrdmulh	v14.4s, v24.4s, v0.s[2]
	sqrdmlsh	v13.4s, v21.4s, v4.s[0]
	sqrdmlsh	v14.4s, v23.4s, v4.s[0]
	sshr	v13.4s, v13.4s, #1
	sshr	v14.4s, v14.4s, #1
	sub	v22.4s, v7.4s, v15.4s
	sub	v24.4s, v8.4s, v16.4s
	add	v7.4s, v7.4s, v15.4s
	add	v8.4s, v8.4s, v16.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v15.4s, v22.4s, v0.s[2]
	sqrdmulh	v16.4s, v24.4s, v0.s[2]
	sqrdmlsh	v15.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v15.4s, v15.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v9.4s, v17.4s
	sub	v24.4s, v10.4s, v18.4s
	add	v9.4s, v9.4s, v17.4s
	add	v10.4s, v10.4s, v18.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v17.4s, v22.4s, v0.s[2]
	sqrdmulh	v18.4s, v24.4s, v0.s[2]
	sqrdmlsh	v17.4s, v21.4s, v4.s[0]
	sqrdmlsh	v18.4s, v23.4s, v4.s[0]
	sshr	v17.4s, v17.4s, #1
	sshr	v18.4s, v18.4s, #1
	sub	v22.4s, v11.4s, v19.4s
	sub	v24.4s, v12.4s, v20.4s
	add	v11.4s, v11.4s, v19.4s
	add	v12.4s, v12.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v19.4s, v22.4s, v0.s[2]
	sqrdmulh	v20.4s, v24.4s, v0.s[2]
	sqrdmlsh	v19.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	mul	v21.4s, v5.4s, v2.s[3]
	mul	v22.4s, v6.4s, v2.s[3]
	sqrdmulh	v5.4s, v5.4s, v0.s[3]
	sqrdmulh	v6.4s, v6.4s, v0.s[3]
	sqrdmlsh	v5.4s, v21.4s, v4.s[0]
	sqrdmlsh	v6.4s, v22.4s, v4.s[0]
	sshr	v5.4s, v5.4s, #1
	sshr	v6.4s, v6.4s, #1
	mul	v21.4s, v7.4s, v2.s[3]
	mul	v22.4s, v8.4s, v2.s[3]
	sqrdmulh	v7.4s, v7.4s, v0.s[3]
	sqrdmulh	v8.4s, v8.4s, v0.s[3]
	sqrdmlsh	v7.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v22.4s, v4.s[0]
	sshr	v7.4s, v7.4s, #1
	sshr	v8.4s, v8.4s, #1
	mul	v21.4s, v9.4s, v2.s[3]
	mul	v22.4s, v10.4s, v2.s[3]
	sqrdmulh	v9.4s, v9.4s, v0.s[3]
	sqrdmulh	v10.4s, v10.4s, v0.s[3]
	sqrdmlsh	v9.4s, v21.4s, v4.s[0]
	sqrdmlsh	v10.4s, v22.4s, v4.s[0]
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	mul	v21.4s, v11.4s, v2.s[3]
	mul	v22.4s, v12.4s, v2.s[3]
	sqrdmulh	v11.4s, v11.4s, v0.s[3]
	sqrdmulh	v12.4s, v12.4s, v0.s[3]
	sqrdmlsh	v11.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v22.4s, v4.s[0]
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	str	q5, [x0, #32]
	str	q6, [x0, #96]
	str	q7, [x0, #160]
	str	q8, [x0, #224]
	str	q9, [x0, #288]
	str	q10, [x0, #352]
	str	q11, [x0, #416]
	str	q12, [x0, #480]
	str	q13, [x0, #544]
	str	q14, [x0, #608]
	str	q15, [x0, #672]
	str	q16, [x0, #736]
	str	q17, [x0, #800]
	str	q18, [x0, #864]
	str	q19, [x0, #928]
	str	q20, [x0, #992]
	ldr	q5, [x0, #48]
	ldr	q6, [x0, #112]
	ldr	q7, [x0, #176]
	ldr	q8, [x0, #240]
	ldr	q9, [x0, #304]
	ldr	q10, [x0, #368]
	ldr	q11, [x0, #432]
	ldr	q12, [x0, #496]
	ldr	q13, [x0, #560]
	ldr	q14, [x0, #624]
	ldr	q15, [x0, #688]
	ldr	q16, [x0, #752]
	ldr	q17, [x0, #816]
	ldr	q18, [x0, #880]
	ldr	q19, [x0, #944]
	ldr	q20, [x0, #1008]
	ldr	q0, [x1, #1216]
	ldr	q1, [x1, #1232]
	ldr	q2, [x2, #1216]
	ldr	q3, [x2, #1232]
	sub	v22.4s, v5.4s, v6.4s
	sub	v24.4s, v7.4s, v8.4s
	add	v5.4s, v5.4s, v6.4s
	add	v7.4s, v7.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v6.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[1]
	sqrdmlsh	v6.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v23.4s, v4.s[0]
	sshr	v6.4s, v6.4s, #1
	sshr	v8.4s, v8.4s, #1
	sub	v22.4s, v9.4s, v10.4s
	sub	v24.4s, v11.4s, v12.4s
	add	v9.4s, v9.4s, v10.4s
	add	v11.4s, v11.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v10.4s, v22.4s, v0.s[2]
	sqrdmulh	v12.4s, v24.4s, v0.s[3]
	sqrdmlsh	v10.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v10.4s, v10.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v14.4s
	sub	v24.4s, v15.4s, v16.4s
	add	v13.4s, v13.4s, v14.4s
	add	v15.4s, v15.4s, v16.4s
	mul	v21.4s, v22.4s, v3.s[0]
	mul	v23.4s, v24.4s, v3.s[1]
	sqrdmulh	v14.4s, v22.4s, v1.s[0]
	sqrdmulh	v16.4s, v24.4s, v1.s[1]
	sqrdmlsh	v14.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v14.4s, v14.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v17.4s, v18.4s
	sub	v24.4s, v19.4s, v20.4s
	add	v17.4s, v17.4s, v18.4s
	add	v19.4s, v19.4s, v20.4s
	mul	v21.4s, v22.4s, v3.s[2]
	mul	v23.4s, v24.4s, v3.s[3]
	sqrdmulh	v18.4s, v22.4s, v1.s[2]
	sqrdmulh	v20.4s, v24.4s, v1.s[3]
	sqrdmlsh	v18.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v18.4s, v18.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1248]
	ldr	q2, [x2, #1248]
	sub	v22.4s, v5.4s, v7.4s
	sub	v24.4s, v6.4s, v8.4s
	add	v5.4s, v5.4s, v7.4s
	add	v6.4s, v6.4s, v8.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v7.4s, v22.4s, v0.s[0]
	sqrdmulh	v8.4s, v24.4s, v0.s[0]
	sqrdmlsh	v7.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v23.4s, v4.s[0]
	sshr	v7.4s, v7.4s, #1
	sshr	v8.4s, v8.4s, #1
	sub	v22.4s, v9.4s, v11.4s
	sub	v24.4s, v10.4s, v12.4s
	add	v9.4s, v9.4s, v11.4s
	add	v10.4s, v10.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v11.4s, v22.4s, v0.s[1]
	sqrdmulh	v12.4s, v24.4s, v0.s[1]
	sqrdmlsh	v11.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v15.4s
	sub	v24.4s, v14.4s, v16.4s
	add	v13.4s, v13.4s, v15.4s
	add	v14.4s, v14.4s, v16.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v15.4s, v22.4s, v0.s[2]
	sqrdmulh	v16.4s, v24.4s, v0.s[2]
	sqrdmlsh	v15.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v15.4s, v15.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v17.4s, v19.4s
	sub	v24.4s, v18.4s, v20.4s
	add	v17.4s, v17.4s, v19.4s
	add	v18.4s, v18.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[3]
	mul	v23.4s, v24.4s, v2.s[3]
	sqrdmulh	v19.4s, v22.4s, v0.s[3]
	sqrdmulh	v20.4s, v24.4s, v0.s[3]
	sqrdmlsh	v19.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	ldr	q0, [x1, #1264]
	ldr	q2, [x2, #1264]
	sub	v22.4s, v5.4s, v9.4s
	sub	v24.4s, v6.4s, v10.4s
	add	v5.4s, v5.4s, v9.4s
	add	v6.4s, v6.4s, v10.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v9.4s, v22.4s, v0.s[0]
	sqrdmulh	v10.4s, v24.4s, v0.s[0]
	sqrdmlsh	v9.4s, v21.4s, v4.s[0]
	sqrdmlsh	v10.4s, v23.4s, v4.s[0]
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	sub	v22.4s, v7.4s, v11.4s
	sub	v24.4s, v8.4s, v12.4s
	add	v7.4s, v7.4s, v11.4s
	add	v8.4s, v8.4s, v12.4s
	mul	v21.4s, v22.4s, v2.s[0]
	mul	v23.4s, v24.4s, v2.s[0]
	sqrdmulh	v11.4s, v22.4s, v0.s[0]
	sqrdmulh	v12.4s, v24.4s, v0.s[0]
	sqrdmlsh	v11.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v23.4s, v4.s[0]
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	sub	v22.4s, v13.4s, v17.4s
	sub	v24.4s, v14.4s, v18.4s
	add	v13.4s, v13.4s, v17.4s
	add	v14.4s, v14.4s, v18.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v17.4s, v22.4s, v0.s[1]
	sqrdmulh	v18.4s, v24.4s, v0.s[1]
	sqrdmlsh	v17.4s, v21.4s, v4.s[0]
	sqrdmlsh	v18.4s, v23.4s, v4.s[0]
	sshr	v17.4s, v17.4s, #1
	sshr	v18.4s, v18.4s, #1
	sub	v22.4s, v15.4s, v19.4s
	sub	v24.4s, v16.4s, v20.4s
	add	v15.4s, v15.4s, v19.4s
	add	v16.4s, v16.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[1]
	mul	v23.4s, v24.4s, v2.s[1]
	sqrdmulh	v19.4s, v22.4s, v0.s[1]
	sqrdmulh	v20.4s, v24.4s, v0.s[1]
	sqrdmlsh	v19.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	sub	v22.4s, v5.4s, v13.4s
	sub	v24.4s, v6.4s, v14.4s
	add	v5.4s, v5.4s, v13.4s
	add	v6.4s, v6.4s, v14.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v13.4s, v22.4s, v0.s[2]
	sqrdmulh	v14.4s, v24.4s, v0.s[2]
	sqrdmlsh	v13.4s, v21.4s, v4.s[0]
	sqrdmlsh	v14.4s, v23.4s, v4.s[0]
	sshr	v13.4s, v13.4s, #1
	sshr	v14.4s, v14.4s, #1
	sub	v22.4s, v7.4s, v15.4s
	sub	v24.4s, v8.4s, v16.4s
	add	v7.4s, v7.4s, v15.4s
	add	v8.4s, v8.4s, v16.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v15.4s, v22.4s, v0.s[2]
	sqrdmulh	v16.4s, v24.4s, v0.s[2]
	sqrdmlsh	v15.4s, v21.4s, v4.s[0]
	sqrdmlsh	v16.4s, v23.4s, v4.s[0]
	sshr	v15.4s, v15.4s, #1
	sshr	v16.4s, v16.4s, #1
	sub	v22.4s, v9.4s, v17.4s
	sub	v24.4s, v10.4s, v18.4s
	add	v9.4s, v9.4s, v17.4s
	add	v10.4s, v10.4s, v18.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v17.4s, v22.4s, v0.s[2]
	sqrdmulh	v18.4s, v24.4s, v0.s[2]
	sqrdmlsh	v17.4s, v21.4s, v4.s[0]
	sqrdmlsh	v18.4s, v23.4s, v4.s[0]
	sshr	v17.4s, v17.4s, #1
	sshr	v18.4s, v18.4s, #1
	sub	v22.4s, v11.4s, v19.4s
	sub	v24.4s, v12.4s, v20.4s
	add	v11.4s, v11.4s, v19.4s
	add	v12.4s, v12.4s, v20.4s
	mul	v21.4s, v22.4s, v2.s[2]
	mul	v23.4s, v24.4s, v2.s[2]
	sqrdmulh	v19.4s, v22.4s, v0.s[2]
	sqrdmulh	v20.4s, v24.4s, v0.s[2]
	sqrdmlsh	v19.4s, v21.4s, v4.s[0]
	sqrdmlsh	v20.4s, v23.4s, v4.s[0]
	sshr	v19.4s, v19.4s, #1
	sshr	v20.4s, v20.4s, #1
	mul	v21.4s, v5.4s, v2.s[3]
	mul	v22.4s, v6.4s, v2.s[3]
	sqrdmulh	v5.4s, v5.4s, v0.s[3]
	sqrdmulh	v6.4s, v6.4s, v0.s[3]
	sqrdmlsh	v5.4s, v21.4s, v4.s[0]
	sqrdmlsh	v6.4s, v22.4s, v4.s[0]
	sshr	v5.4s, v5.4s, #1
	sshr	v6.4s, v6.4s, #1
	mul	v21.4s, v7.4s, v2.s[3]
	mul	v22.4s, v8.4s, v2.s[3]
	sqrdmulh	v7.4s, v7.4s, v0.s[3]
	sqrdmulh	v8.4s, v8.4s, v0.s[3]
	sqrdmlsh	v7.4s, v21.4s, v4.s[0]
	sqrdmlsh	v8.4s, v22.4s, v4.s[0]
	sshr	v7.4s, v7.4s, #1
	sshr	v8.4s, v8.4s, #1
	mul	v21.4s, v9.4s, v2.s[3]
	mul	v22.4s, v10.4s, v2.s[3]
	sqrdmulh	v9.4s, v9.4s, v0.s[3]
	sqrdmulh	v10.4s, v10.4s, v0.s[3]
	sqrdmlsh	v9.4s, v21.4s, v4.s[0]
	sqrdmlsh	v10.4s, v22.4s, v4.s[0]
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	mul	v21.4s, v11.4s, v2.s[3]
	mul	v22.4s, v12.4s, v2.s[3]
	sqrdmulh	v11.4s, v11.4s, v0.s[3]
	sqrdmulh	v12.4s, v12.4s, v0.s[3]
	sqrdmlsh	v11.4s, v21.4s, v4.s[0]
	sqrdmlsh	v12.4s, v22.4s, v4.s[0]
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	str	q5, [x0, #48]
	str	q6, [x0, #112]
	str	q7, [x0, #176]
	str	q8, [x0, #240]
	str	q9, [x0, #304]
	str	q10, [x0, #368]
	str	q11, [x0, #432]
	str	q12, [x0, #496]
	str	q13, [x0, #560]
	str	q14, [x0, #624]
	str	q15, [x0, #688]
	str	q16, [x0, #752]
	str	q17, [x0, #816]
	str	q18, [x0, #880]
	str	q19, [x0, #944]
	str	q20, [x0, #1008]
	ldp	d8, d9, [x29, #16]
	ldp	d10, d11, [x29, #32]
	ldp	d12, d13, [x29, #48]
	ldp	d14, d15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
#ifndef __APPLE__
	.size	mldsa_invntt_full_sqrdmlsh_neon,.-mldsa_invntt_full_sqrdmlsh_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	mldsa_mul_sqrdmlsh_neon
WC_ASM_ATT_HIDDEN(mldsa_mul_sqrdmlsh_neon)
.type	mldsa_mul_sqrdmlsh_neon,@function
.align	2
mldsa_mul_sqrdmlsh_neon:
#else
.section	__TEXT,__text
.globl	_mldsa_mul_sqrdmlsh_neon
WC_ASM_ATT_HIDDEN(_mldsa_mul_sqrdmlsh_neon)
.p2align	2
_mldsa_mul_sqrdmlsh_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
	stp	d12, d13, [x29, #48]
	stp	d14, d15, [x29, #64]
#ifndef __APPLE__
	adrp x3, L_mldsa_aarch64_consts
	add  x3, x3, :lo12:L_mldsa_aarch64_consts
#else
	adrp x3, L_mldsa_aarch64_consts@PAGE
	add  x3, x3, L_mldsa_aarch64_consts@PAGEOFF
#endif /* __APPLE__ */
	ldr	q0, [x3]
	ldr	q1, [x1]
	ldr	q5, [x2]
	ldr	q2, [x1, #16]
	ldr	q6, [x2, #16]
	ldr	q3, [x1, #32]
	ldr	q7, [x2, #32]
	ldr	q4, [x1, #48]
	ldr	q8, [x2, #48]
	mul	v13.4s, v5.4s, v0.s[1]
	mul	v14.4s, v6.4s, v0.s[1]
	mul	v17.4s, v1.4s, v13.4s
	mul	v18.4s, v2.4s, v14.4s
	sqrdmulh	v9.4s, v1.4s, v5.4s
	sqrdmulh	v10.4s, v2.4s, v6.4s
	sqrdmlsh	v9.4s, v17.4s, v0.s[0]
	sqrdmlsh	v10.4s, v18.4s, v0.s[0]
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	mul	v15.4s, v7.4s, v0.s[1]
	mul	v16.4s, v8.4s, v0.s[1]
	mul	v17.4s, v3.4s, v15.4s
	mul	v18.4s, v4.4s, v16.4s
	sqrdmulh	v11.4s, v3.4s, v7.4s
	sqrdmulh	v12.4s, v4.4s, v8.4s
	sqrdmlsh	v11.4s, v17.4s, v0.s[0]
	sqrdmlsh	v12.4s, v18.4s, v0.s[0]
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	str	q9, [x0]
	str	q10, [x0, #16]
	str	q11, [x0, #32]
	str	q12, [x0, #48]
	ldr	q1, [x1, #64]
	ldr	q5, [x2, #64]
	ldr	q2, [x1, #80]
	ldr	q6, [x2, #80]
	ldr	q3, [x1, #96]
	ldr	q7, [x2, #96]
	ldr	q4, [x1, #112]
	ldr	q8, [x2, #112]
	mul	v13.4s, v5.4s, v0.s[1]
	mul	v14.4s, v6.4s, v0.s[1]
	mul	v17.4s, v1.4s, v13.4s
	mul	v18.4s, v2.4s, v14.4s
	sqrdmulh	v9.4s, v1.4s, v5.4s
	sqrdmulh	v10.4s, v2.4s, v6.4s
	sqrdmlsh	v9.4s, v17.4s, v0.s[0]
	sqrdmlsh	v10.4s, v18.4s, v0.s[0]
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	mul	v15.4s, v7.4s, v0.s[1]
	mul	v16.4s, v8.4s, v0.s[1]
	mul	v17.4s, v3.4s, v15.4s
	mul	v18.4s, v4.4s, v16.4s
	sqrdmulh	v11.4s, v3.4s, v7.4s
	sqrdmulh	v12.4s, v4.4s, v8.4s
	sqrdmlsh	v11.4s, v17.4s, v0.s[0]
	sqrdmlsh	v12.4s, v18.4s, v0.s[0]
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	str	q9, [x0, #64]
	str	q10, [x0, #80]
	str	q11, [x0, #96]
	str	q12, [x0, #112]
	ldr	q1, [x1, #128]
	ldr	q5, [x2, #128]
	ldr	q2, [x1, #144]
	ldr	q6, [x2, #144]
	ldr	q3, [x1, #160]
	ldr	q7, [x2, #160]
	ldr	q4, [x1, #176]
	ldr	q8, [x2, #176]
	mul	v13.4s, v5.4s, v0.s[1]
	mul	v14.4s, v6.4s, v0.s[1]
	mul	v17.4s, v1.4s, v13.4s
	mul	v18.4s, v2.4s, v14.4s
	sqrdmulh	v9.4s, v1.4s, v5.4s
	sqrdmulh	v10.4s, v2.4s, v6.4s
	sqrdmlsh	v9.4s, v17.4s, v0.s[0]
	sqrdmlsh	v10.4s, v18.4s, v0.s[0]
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	mul	v15.4s, v7.4s, v0.s[1]
	mul	v16.4s, v8.4s, v0.s[1]
	mul	v17.4s, v3.4s, v15.4s
	mul	v18.4s, v4.4s, v16.4s
	sqrdmulh	v11.4s, v3.4s, v7.4s
	sqrdmulh	v12.4s, v4.4s, v8.4s
	sqrdmlsh	v11.4s, v17.4s, v0.s[0]
	sqrdmlsh	v12.4s, v18.4s, v0.s[0]
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	str	q9, [x0, #128]
	str	q10, [x0, #144]
	str	q11, [x0, #160]
	str	q12, [x0, #176]
	ldr	q1, [x1, #192]
	ldr	q5, [x2, #192]
	ldr	q2, [x1, #208]
	ldr	q6, [x2, #208]
	ldr	q3, [x1, #224]
	ldr	q7, [x2, #224]
	ldr	q4, [x1, #240]
	ldr	q8, [x2, #240]
	mul	v13.4s, v5.4s, v0.s[1]
	mul	v14.4s, v6.4s, v0.s[1]
	mul	v17.4s, v1.4s, v13.4s
	mul	v18.4s, v2.4s, v14.4s
	sqrdmulh	v9.4s, v1.4s, v5.4s
	sqrdmulh	v10.4s, v2.4s, v6.4s
	sqrdmlsh	v9.4s, v17.4s, v0.s[0]
	sqrdmlsh	v10.4s, v18.4s, v0.s[0]
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	mul	v15.4s, v7.4s, v0.s[1]
	mul	v16.4s, v8.4s, v0.s[1]
	mul	v17.4s, v3.4s, v15.4s
	mul	v18.4s, v4.4s, v16.4s
	sqrdmulh	v11.4s, v3.4s, v7.4s
	sqrdmulh	v12.4s, v4.4s, v8.4s
	sqrdmlsh	v11.4s, v17.4s, v0.s[0]
	sqrdmlsh	v12.4s, v18.4s, v0.s[0]
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	str	q9, [x0, #192]
	str	q10, [x0, #208]
	str	q11, [x0, #224]
	str	q12, [x0, #240]
	ldr	q1, [x1, #256]
	ldr	q5, [x2, #256]
	ldr	q2, [x1, #272]
	ldr	q6, [x2, #272]
	ldr	q3, [x1, #288]
	ldr	q7, [x2, #288]
	ldr	q4, [x1, #304]
	ldr	q8, [x2, #304]
	mul	v13.4s, v5.4s, v0.s[1]
	mul	v14.4s, v6.4s, v0.s[1]
	mul	v17.4s, v1.4s, v13.4s
	mul	v18.4s, v2.4s, v14.4s
	sqrdmulh	v9.4s, v1.4s, v5.4s
	sqrdmulh	v10.4s, v2.4s, v6.4s
	sqrdmlsh	v9.4s, v17.4s, v0.s[0]
	sqrdmlsh	v10.4s, v18.4s, v0.s[0]
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	mul	v15.4s, v7.4s, v0.s[1]
	mul	v16.4s, v8.4s, v0.s[1]
	mul	v17.4s, v3.4s, v15.4s
	mul	v18.4s, v4.4s, v16.4s
	sqrdmulh	v11.4s, v3.4s, v7.4s
	sqrdmulh	v12.4s, v4.4s, v8.4s
	sqrdmlsh	v11.4s, v17.4s, v0.s[0]
	sqrdmlsh	v12.4s, v18.4s, v0.s[0]
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	str	q9, [x0, #256]
	str	q10, [x0, #272]
	str	q11, [x0, #288]
	str	q12, [x0, #304]
	ldr	q1, [x1, #320]
	ldr	q5, [x2, #320]
	ldr	q2, [x1, #336]
	ldr	q6, [x2, #336]
	ldr	q3, [x1, #352]
	ldr	q7, [x2, #352]
	ldr	q4, [x1, #368]
	ldr	q8, [x2, #368]
	mul	v13.4s, v5.4s, v0.s[1]
	mul	v14.4s, v6.4s, v0.s[1]
	mul	v17.4s, v1.4s, v13.4s
	mul	v18.4s, v2.4s, v14.4s
	sqrdmulh	v9.4s, v1.4s, v5.4s
	sqrdmulh	v10.4s, v2.4s, v6.4s
	sqrdmlsh	v9.4s, v17.4s, v0.s[0]
	sqrdmlsh	v10.4s, v18.4s, v0.s[0]
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	mul	v15.4s, v7.4s, v0.s[1]
	mul	v16.4s, v8.4s, v0.s[1]
	mul	v17.4s, v3.4s, v15.4s
	mul	v18.4s, v4.4s, v16.4s
	sqrdmulh	v11.4s, v3.4s, v7.4s
	sqrdmulh	v12.4s, v4.4s, v8.4s
	sqrdmlsh	v11.4s, v17.4s, v0.s[0]
	sqrdmlsh	v12.4s, v18.4s, v0.s[0]
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	str	q9, [x0, #320]
	str	q10, [x0, #336]
	str	q11, [x0, #352]
	str	q12, [x0, #368]
	ldr	q1, [x1, #384]
	ldr	q5, [x2, #384]
	ldr	q2, [x1, #400]
	ldr	q6, [x2, #400]
	ldr	q3, [x1, #416]
	ldr	q7, [x2, #416]
	ldr	q4, [x1, #432]
	ldr	q8, [x2, #432]
	mul	v13.4s, v5.4s, v0.s[1]
	mul	v14.4s, v6.4s, v0.s[1]
	mul	v17.4s, v1.4s, v13.4s
	mul	v18.4s, v2.4s, v14.4s
	sqrdmulh	v9.4s, v1.4s, v5.4s
	sqrdmulh	v10.4s, v2.4s, v6.4s
	sqrdmlsh	v9.4s, v17.4s, v0.s[0]
	sqrdmlsh	v10.4s, v18.4s, v0.s[0]
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	mul	v15.4s, v7.4s, v0.s[1]
	mul	v16.4s, v8.4s, v0.s[1]
	mul	v17.4s, v3.4s, v15.4s
	mul	v18.4s, v4.4s, v16.4s
	sqrdmulh	v11.4s, v3.4s, v7.4s
	sqrdmulh	v12.4s, v4.4s, v8.4s
	sqrdmlsh	v11.4s, v17.4s, v0.s[0]
	sqrdmlsh	v12.4s, v18.4s, v0.s[0]
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	str	q9, [x0, #384]
	str	q10, [x0, #400]
	str	q11, [x0, #416]
	str	q12, [x0, #432]
	ldr	q1, [x1, #448]
	ldr	q5, [x2, #448]
	ldr	q2, [x1, #464]
	ldr	q6, [x2, #464]
	ldr	q3, [x1, #480]
	ldr	q7, [x2, #480]
	ldr	q4, [x1, #496]
	ldr	q8, [x2, #496]
	mul	v13.4s, v5.4s, v0.s[1]
	mul	v14.4s, v6.4s, v0.s[1]
	mul	v17.4s, v1.4s, v13.4s
	mul	v18.4s, v2.4s, v14.4s
	sqrdmulh	v9.4s, v1.4s, v5.4s
	sqrdmulh	v10.4s, v2.4s, v6.4s
	sqrdmlsh	v9.4s, v17.4s, v0.s[0]
	sqrdmlsh	v10.4s, v18.4s, v0.s[0]
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	mul	v15.4s, v7.4s, v0.s[1]
	mul	v16.4s, v8.4s, v0.s[1]
	mul	v17.4s, v3.4s, v15.4s
	mul	v18.4s, v4.4s, v16.4s
	sqrdmulh	v11.4s, v3.4s, v7.4s
	sqrdmulh	v12.4s, v4.4s, v8.4s
	sqrdmlsh	v11.4s, v17.4s, v0.s[0]
	sqrdmlsh	v12.4s, v18.4s, v0.s[0]
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	str	q9, [x0, #448]
	str	q10, [x0, #464]
	str	q11, [x0, #480]
	str	q12, [x0, #496]
	ldr	q1, [x1, #512]
	ldr	q5, [x2, #512]
	ldr	q2, [x1, #528]
	ldr	q6, [x2, #528]
	ldr	q3, [x1, #544]
	ldr	q7, [x2, #544]
	ldr	q4, [x1, #560]
	ldr	q8, [x2, #560]
	mul	v13.4s, v5.4s, v0.s[1]
	mul	v14.4s, v6.4s, v0.s[1]
	mul	v17.4s, v1.4s, v13.4s
	mul	v18.4s, v2.4s, v14.4s
	sqrdmulh	v9.4s, v1.4s, v5.4s
	sqrdmulh	v10.4s, v2.4s, v6.4s
	sqrdmlsh	v9.4s, v17.4s, v0.s[0]
	sqrdmlsh	v10.4s, v18.4s, v0.s[0]
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	mul	v15.4s, v7.4s, v0.s[1]
	mul	v16.4s, v8.4s, v0.s[1]
	mul	v17.4s, v3.4s, v15.4s
	mul	v18.4s, v4.4s, v16.4s
	sqrdmulh	v11.4s, v3.4s, v7.4s
	sqrdmulh	v12.4s, v4.4s, v8.4s
	sqrdmlsh	v11.4s, v17.4s, v0.s[0]
	sqrdmlsh	v12.4s, v18.4s, v0.s[0]
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	str	q9, [x0, #512]
	str	q10, [x0, #528]
	str	q11, [x0, #544]
	str	q12, [x0, #560]
	ldr	q1, [x1, #576]
	ldr	q5, [x2, #576]
	ldr	q2, [x1, #592]
	ldr	q6, [x2, #592]
	ldr	q3, [x1, #608]
	ldr	q7, [x2, #608]
	ldr	q4, [x1, #624]
	ldr	q8, [x2, #624]
	mul	v13.4s, v5.4s, v0.s[1]
	mul	v14.4s, v6.4s, v0.s[1]
	mul	v17.4s, v1.4s, v13.4s
	mul	v18.4s, v2.4s, v14.4s
	sqrdmulh	v9.4s, v1.4s, v5.4s
	sqrdmulh	v10.4s, v2.4s, v6.4s
	sqrdmlsh	v9.4s, v17.4s, v0.s[0]
	sqrdmlsh	v10.4s, v18.4s, v0.s[0]
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	mul	v15.4s, v7.4s, v0.s[1]
	mul	v16.4s, v8.4s, v0.s[1]
	mul	v17.4s, v3.4s, v15.4s
	mul	v18.4s, v4.4s, v16.4s
	sqrdmulh	v11.4s, v3.4s, v7.4s
	sqrdmulh	v12.4s, v4.4s, v8.4s
	sqrdmlsh	v11.4s, v17.4s, v0.s[0]
	sqrdmlsh	v12.4s, v18.4s, v0.s[0]
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	str	q9, [x0, #576]
	str	q10, [x0, #592]
	str	q11, [x0, #608]
	str	q12, [x0, #624]
	ldr	q1, [x1, #640]
	ldr	q5, [x2, #640]
	ldr	q2, [x1, #656]
	ldr	q6, [x2, #656]
	ldr	q3, [x1, #672]
	ldr	q7, [x2, #672]
	ldr	q4, [x1, #688]
	ldr	q8, [x2, #688]
	mul	v13.4s, v5.4s, v0.s[1]
	mul	v14.4s, v6.4s, v0.s[1]
	mul	v17.4s, v1.4s, v13.4s
	mul	v18.4s, v2.4s, v14.4s
	sqrdmulh	v9.4s, v1.4s, v5.4s
	sqrdmulh	v10.4s, v2.4s, v6.4s
	sqrdmlsh	v9.4s, v17.4s, v0.s[0]
	sqrdmlsh	v10.4s, v18.4s, v0.s[0]
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	mul	v15.4s, v7.4s, v0.s[1]
	mul	v16.4s, v8.4s, v0.s[1]
	mul	v17.4s, v3.4s, v15.4s
	mul	v18.4s, v4.4s, v16.4s
	sqrdmulh	v11.4s, v3.4s, v7.4s
	sqrdmulh	v12.4s, v4.4s, v8.4s
	sqrdmlsh	v11.4s, v17.4s, v0.s[0]
	sqrdmlsh	v12.4s, v18.4s, v0.s[0]
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	str	q9, [x0, #640]
	str	q10, [x0, #656]
	str	q11, [x0, #672]
	str	q12, [x0, #688]
	ldr	q1, [x1, #704]
	ldr	q5, [x2, #704]
	ldr	q2, [x1, #720]
	ldr	q6, [x2, #720]
	ldr	q3, [x1, #736]
	ldr	q7, [x2, #736]
	ldr	q4, [x1, #752]
	ldr	q8, [x2, #752]
	mul	v13.4s, v5.4s, v0.s[1]
	mul	v14.4s, v6.4s, v0.s[1]
	mul	v17.4s, v1.4s, v13.4s
	mul	v18.4s, v2.4s, v14.4s
	sqrdmulh	v9.4s, v1.4s, v5.4s
	sqrdmulh	v10.4s, v2.4s, v6.4s
	sqrdmlsh	v9.4s, v17.4s, v0.s[0]
	sqrdmlsh	v10.4s, v18.4s, v0.s[0]
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	mul	v15.4s, v7.4s, v0.s[1]
	mul	v16.4s, v8.4s, v0.s[1]
	mul	v17.4s, v3.4s, v15.4s
	mul	v18.4s, v4.4s, v16.4s
	sqrdmulh	v11.4s, v3.4s, v7.4s
	sqrdmulh	v12.4s, v4.4s, v8.4s
	sqrdmlsh	v11.4s, v17.4s, v0.s[0]
	sqrdmlsh	v12.4s, v18.4s, v0.s[0]
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	str	q9, [x0, #704]
	str	q10, [x0, #720]
	str	q11, [x0, #736]
	str	q12, [x0, #752]
	ldr	q1, [x1, #768]
	ldr	q5, [x2, #768]
	ldr	q2, [x1, #784]
	ldr	q6, [x2, #784]
	ldr	q3, [x1, #800]
	ldr	q7, [x2, #800]
	ldr	q4, [x1, #816]
	ldr	q8, [x2, #816]
	mul	v13.4s, v5.4s, v0.s[1]
	mul	v14.4s, v6.4s, v0.s[1]
	mul	v17.4s, v1.4s, v13.4s
	mul	v18.4s, v2.4s, v14.4s
	sqrdmulh	v9.4s, v1.4s, v5.4s
	sqrdmulh	v10.4s, v2.4s, v6.4s
	sqrdmlsh	v9.4s, v17.4s, v0.s[0]
	sqrdmlsh	v10.4s, v18.4s, v0.s[0]
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	mul	v15.4s, v7.4s, v0.s[1]
	mul	v16.4s, v8.4s, v0.s[1]
	mul	v17.4s, v3.4s, v15.4s
	mul	v18.4s, v4.4s, v16.4s
	sqrdmulh	v11.4s, v3.4s, v7.4s
	sqrdmulh	v12.4s, v4.4s, v8.4s
	sqrdmlsh	v11.4s, v17.4s, v0.s[0]
	sqrdmlsh	v12.4s, v18.4s, v0.s[0]
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	str	q9, [x0, #768]
	str	q10, [x0, #784]
	str	q11, [x0, #800]
	str	q12, [x0, #816]
	ldr	q1, [x1, #832]
	ldr	q5, [x2, #832]
	ldr	q2, [x1, #848]
	ldr	q6, [x2, #848]
	ldr	q3, [x1, #864]
	ldr	q7, [x2, #864]
	ldr	q4, [x1, #880]
	ldr	q8, [x2, #880]
	mul	v13.4s, v5.4s, v0.s[1]
	mul	v14.4s, v6.4s, v0.s[1]
	mul	v17.4s, v1.4s, v13.4s
	mul	v18.4s, v2.4s, v14.4s
	sqrdmulh	v9.4s, v1.4s, v5.4s
	sqrdmulh	v10.4s, v2.4s, v6.4s
	sqrdmlsh	v9.4s, v17.4s, v0.s[0]
	sqrdmlsh	v10.4s, v18.4s, v0.s[0]
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	mul	v15.4s, v7.4s, v0.s[1]
	mul	v16.4s, v8.4s, v0.s[1]
	mul	v17.4s, v3.4s, v15.4s
	mul	v18.4s, v4.4s, v16.4s
	sqrdmulh	v11.4s, v3.4s, v7.4s
	sqrdmulh	v12.4s, v4.4s, v8.4s
	sqrdmlsh	v11.4s, v17.4s, v0.s[0]
	sqrdmlsh	v12.4s, v18.4s, v0.s[0]
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	str	q9, [x0, #832]
	str	q10, [x0, #848]
	str	q11, [x0, #864]
	str	q12, [x0, #880]
	ldr	q1, [x1, #896]
	ldr	q5, [x2, #896]
	ldr	q2, [x1, #912]
	ldr	q6, [x2, #912]
	ldr	q3, [x1, #928]
	ldr	q7, [x2, #928]
	ldr	q4, [x1, #944]
	ldr	q8, [x2, #944]
	mul	v13.4s, v5.4s, v0.s[1]
	mul	v14.4s, v6.4s, v0.s[1]
	mul	v17.4s, v1.4s, v13.4s
	mul	v18.4s, v2.4s, v14.4s
	sqrdmulh	v9.4s, v1.4s, v5.4s
	sqrdmulh	v10.4s, v2.4s, v6.4s
	sqrdmlsh	v9.4s, v17.4s, v0.s[0]
	sqrdmlsh	v10.4s, v18.4s, v0.s[0]
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	mul	v15.4s, v7.4s, v0.s[1]
	mul	v16.4s, v8.4s, v0.s[1]
	mul	v17.4s, v3.4s, v15.4s
	mul	v18.4s, v4.4s, v16.4s
	sqrdmulh	v11.4s, v3.4s, v7.4s
	sqrdmulh	v12.4s, v4.4s, v8.4s
	sqrdmlsh	v11.4s, v17.4s, v0.s[0]
	sqrdmlsh	v12.4s, v18.4s, v0.s[0]
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	str	q9, [x0, #896]
	str	q10, [x0, #912]
	str	q11, [x0, #928]
	str	q12, [x0, #944]
	ldr	q1, [x1, #960]
	ldr	q5, [x2, #960]
	ldr	q2, [x1, #976]
	ldr	q6, [x2, #976]
	ldr	q3, [x1, #992]
	ldr	q7, [x2, #992]
	ldr	q4, [x1, #1008]
	ldr	q8, [x2, #1008]
	mul	v13.4s, v5.4s, v0.s[1]
	mul	v14.4s, v6.4s, v0.s[1]
	mul	v17.4s, v1.4s, v13.4s
	mul	v18.4s, v2.4s, v14.4s
	sqrdmulh	v9.4s, v1.4s, v5.4s
	sqrdmulh	v10.4s, v2.4s, v6.4s
	sqrdmlsh	v9.4s, v17.4s, v0.s[0]
	sqrdmlsh	v10.4s, v18.4s, v0.s[0]
	sshr	v9.4s, v9.4s, #1
	sshr	v10.4s, v10.4s, #1
	mul	v15.4s, v7.4s, v0.s[1]
	mul	v16.4s, v8.4s, v0.s[1]
	mul	v17.4s, v3.4s, v15.4s
	mul	v18.4s, v4.4s, v16.4s
	sqrdmulh	v11.4s, v3.4s, v7.4s
	sqrdmulh	v12.4s, v4.4s, v8.4s
	sqrdmlsh	v11.4s, v17.4s, v0.s[0]
	sqrdmlsh	v12.4s, v18.4s, v0.s[0]
	sshr	v11.4s, v11.4s, #1
	sshr	v12.4s, v12.4s, #1
	str	q9, [x0, #960]
	str	q10, [x0, #976]
	str	q11, [x0, #992]
	str	q12, [x0, #1008]
	ldp	d8, d9, [x29, #16]
	ldp	d10, d11, [x29, #32]
	ldp	d12, d13, [x29, #48]
	ldp	d14, d15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
#ifndef __APPLE__
	.size	mldsa_mul_sqrdmlsh_neon,.-mldsa_mul_sqrdmlsh_neon
#endif /* __APPLE__ */
#endif /* WOLFSSL_AARCH64_NO_SQRDMLSH */
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mldsa_decompose_q88_consts, %object
	.size	L_mldsa_decompose_q88_consts, 96
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_decompose_q88_consts:
	.long	0x0000002c,0x0000002c,0x0000002c,0x0000002c
	.long	0x003fefd4,0x003fefd4,0x003fefd4,0x003fefd4
	.long	0x0002e800,0x0002e800,0x0002e800,0x0002e800
	.long	0x00017400,0x00017400,0x00017400,0x00017400
	.long	0x0000002b,0x0000002b,0x0000002b,0x0000002b
	.long	0x007fe001,0x007fe001,0x007fe001,0x007fe001
#ifndef __APPLE__
.text
.globl	mldsa_decompose_q88_neon
WC_ASM_ATT_HIDDEN(mldsa_decompose_q88_neon)
.type	mldsa_decompose_q88_neon,@function
.align	2
mldsa_decompose_q88_neon:
#else
.section	__TEXT,__text
.globl	_mldsa_decompose_q88_neon
WC_ASM_ATT_HIDDEN(_mldsa_decompose_q88_neon)
.p2align	2
_mldsa_decompose_q88_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
	stp	d12, d13, [x29, #48]
	stp	d14, d15, [x29, #64]
#ifndef __APPLE__
	adrp x3, L_mldsa_decompose_q88_consts
	add  x3, x3, :lo12:L_mldsa_decompose_q88_consts
#else
	adrp x3, L_mldsa_decompose_q88_consts@PAGE
	add  x3, x3, L_mldsa_decompose_q88_consts@PAGEOFF
#endif /* __APPLE__ */
	ldr	q0, [x3]
	ldr	q1, [x3, #16]
	ldr	q2, [x3, #32]
	ldr	q3, [x3, #48]
	ldr	q4, [x3, #64]
	mov	x4, #16
L_mldsa_decompose_q88_loop:
	ldr	q5, [x0]
	ldr	q6, [x0, #16]
	ldr	q7, [x0, #32]
	ldr	q8, [x0, #48]
	mov	v13.16b, v1.16b
	mla	v13.4s, v5.4s, v0.4s
	sshr	v13.4s, v13.4s, #23
	mov	v9.16b, v5.16b
	mls	v9.4s, v13.4s, v2.4s
	sub	v17.4s, v3.4s, v9.4s
	usra	v13.4s, v17.4s, #31
	mov	v9.16b, v5.16b
	mls	v9.4s, v13.4s, v2.4s
	sub	v17.4s, v4.4s, v13.4s
	ushr	v17.4s, v17.4s, #31
	sub	v9.4s, v9.4s, v17.4s
	sub	v17.4s, v13.4s, v0.4s
	ushr	v17.4s, v17.4s, #31
	neg	v17.4s, v17.4s
	and	v13.16b, v13.16b, v17.16b
	mov	v14.16b, v1.16b
	mla	v14.4s, v6.4s, v0.4s
	sshr	v14.4s, v14.4s, #23
	mov	v10.16b, v6.16b
	mls	v10.4s, v14.4s, v2.4s
	sub	v18.4s, v3.4s, v10.4s
	usra	v14.4s, v18.4s, #31
	mov	v10.16b, v6.16b
	mls	v10.4s, v14.4s, v2.4s
	sub	v18.4s, v4.4s, v14.4s
	ushr	v18.4s, v18.4s, #31
	sub	v10.4s, v10.4s, v18.4s
	sub	v18.4s, v14.4s, v0.4s
	ushr	v18.4s, v18.4s, #31
	neg	v18.4s, v18.4s
	and	v14.16b, v14.16b, v18.16b
	mov	v15.16b, v1.16b
	mla	v15.4s, v7.4s, v0.4s
	sshr	v15.4s, v15.4s, #23
	mov	v11.16b, v7.16b
	mls	v11.4s, v15.4s, v2.4s
	sub	v19.4s, v3.4s, v11.4s
	usra	v15.4s, v19.4s, #31
	mov	v11.16b, v7.16b
	mls	v11.4s, v15.4s, v2.4s
	sub	v19.4s, v4.4s, v15.4s
	ushr	v19.4s, v19.4s, #31
	sub	v11.4s, v11.4s, v19.4s
	sub	v19.4s, v15.4s, v0.4s
	ushr	v19.4s, v19.4s, #31
	neg	v19.4s, v19.4s
	and	v15.16b, v15.16b, v19.16b
	mov	v16.16b, v1.16b
	mla	v16.4s, v8.4s, v0.4s
	sshr	v16.4s, v16.4s, #23
	mov	v12.16b, v8.16b
	mls	v12.4s, v16.4s, v2.4s
	sub	v20.4s, v3.4s, v12.4s
	usra	v16.4s, v20.4s, #31
	mov	v12.16b, v8.16b
	mls	v12.4s, v16.4s, v2.4s
	sub	v20.4s, v4.4s, v16.4s
	ushr	v20.4s, v20.4s, #31
	sub	v12.4s, v12.4s, v20.4s
	sub	v20.4s, v16.4s, v0.4s
	ushr	v20.4s, v20.4s, #31
	neg	v20.4s, v20.4s
	and	v16.16b, v16.16b, v20.16b
	str	q9, [x1]
	str	q13, [x2]
	str	q10, [x1, #16]
	str	q14, [x2, #16]
	str	q11, [x1, #32]
	str	q15, [x2, #32]
	str	q12, [x1, #48]
	str	q16, [x2, #48]
	add	x0, x0, #0x40
	add	x1, x1, #0x40
	add	x2, x2, #0x40
	subs	x4, x4, #1
	bne	L_mldsa_decompose_q88_loop
	ldp	d8, d9, [x29, #16]
	ldp	d10, d11, [x29, #32]
	ldp	d12, d13, [x29, #48]
	ldp	d14, d15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
#ifndef __APPLE__
	.size	mldsa_decompose_q88_neon,.-mldsa_decompose_q88_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mldsa_decompose_q32_consts, %object
	.size	L_mldsa_decompose_q32_consts, 80
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_decompose_q32_consts:
	.long	0x0003feff,0x0003feff,0x0003feff,0x0003feff
	.long	0x0003ff00,0x0003ff00,0x0003ff00,0x0003ff00
	.long	0x0000000f,0x0000000f,0x0000000f,0x0000000f
	.long	0x0007fe00,0x0007fe00,0x0007fe00,0x0007fe00
	.long	0x007fe001,0x007fe001,0x007fe001,0x007fe001
#ifndef __APPLE__
.text
.globl	mldsa_decompose_q32_neon
WC_ASM_ATT_HIDDEN(mldsa_decompose_q32_neon)
.type	mldsa_decompose_q32_neon,@function
.align	2
mldsa_decompose_q32_neon:
#else
.section	__TEXT,__text
.globl	_mldsa_decompose_q32_neon
WC_ASM_ATT_HIDDEN(_mldsa_decompose_q32_neon)
.p2align	2
_mldsa_decompose_q32_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
	stp	d12, d13, [x29, #48]
	stp	d14, d15, [x29, #64]
#ifndef __APPLE__
	adrp x3, L_mldsa_decompose_q32_consts
	add  x3, x3, :lo12:L_mldsa_decompose_q32_consts
#else
	adrp x3, L_mldsa_decompose_q32_consts@PAGE
	add  x3, x3, L_mldsa_decompose_q32_consts@PAGEOFF
#endif /* __APPLE__ */
	ldr	q0, [x3]
	ldr	q1, [x3, #16]
	ldr	q2, [x3, #32]
	ldr	q3, [x3, #48]
	mov	x4, #16
L_mldsa_decompose_q32_loop:
	ldr	q4, [x0]
	ldr	q5, [x0, #16]
	ldr	q6, [x0, #32]
	ldr	q7, [x0, #48]
	add	v12.4s, v4.4s, v0.4s
	sshr	v12.4s, v12.4s, #19
	mov	v8.16b, v4.16b
	mls	v8.4s, v12.4s, v3.4s
	sub	v16.4s, v1.4s, v8.4s
	usra	v12.4s, v16.4s, #31
	mov	v8.16b, v4.16b
	mls	v8.4s, v12.4s, v3.4s
	sshr	v16.4s, v12.4s, #4
	sub	v8.4s, v8.4s, v16.4s
	and	v12.16b, v12.16b, v2.16b
	add	v13.4s, v5.4s, v0.4s
	sshr	v13.4s, v13.4s, #19
	mov	v9.16b, v5.16b
	mls	v9.4s, v13.4s, v3.4s
	sub	v17.4s, v1.4s, v9.4s
	usra	v13.4s, v17.4s, #31
	mov	v9.16b, v5.16b
	mls	v9.4s, v13.4s, v3.4s
	sshr	v17.4s, v13.4s, #4
	sub	v9.4s, v9.4s, v17.4s
	and	v13.16b, v13.16b, v2.16b
	add	v14.4s, v6.4s, v0.4s
	sshr	v14.4s, v14.4s, #19
	mov	v10.16b, v6.16b
	mls	v10.4s, v14.4s, v3.4s
	sub	v18.4s, v1.4s, v10.4s
	usra	v14.4s, v18.4s, #31
	mov	v10.16b, v6.16b
	mls	v10.4s, v14.4s, v3.4s
	sshr	v18.4s, v14.4s, #4
	sub	v10.4s, v10.4s, v18.4s
	and	v14.16b, v14.16b, v2.16b
	add	v15.4s, v7.4s, v0.4s
	sshr	v15.4s, v15.4s, #19
	mov	v11.16b, v7.16b
	mls	v11.4s, v15.4s, v3.4s
	sub	v19.4s, v1.4s, v11.4s
	usra	v15.4s, v19.4s, #31
	mov	v11.16b, v7.16b
	mls	v11.4s, v15.4s, v3.4s
	sshr	v19.4s, v15.4s, #4
	sub	v11.4s, v11.4s, v19.4s
	and	v15.16b, v15.16b, v2.16b
	str	q8, [x1]
	str	q12, [x2]
	str	q9, [x1, #16]
	str	q13, [x2, #16]
	str	q10, [x1, #32]
	str	q14, [x2, #32]
	str	q11, [x1, #48]
	str	q15, [x2, #48]
	add	x0, x0, #0x40
	add	x1, x1, #0x40
	add	x2, x2, #0x40
	subs	x4, x4, #1
	bne	L_mldsa_decompose_q32_loop
	ldp	d8, d9, [x29, #16]
	ldp	d10, d11, [x29, #32]
	ldp	d12, d13, [x29, #48]
	ldp	d14, d15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
#ifndef __APPLE__
	.size	mldsa_decompose_q32_neon,.-mldsa_decompose_q32_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mldsa_use_hint_q88_consts, %object
	.size	L_mldsa_use_hint_q88_consts, 96
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_use_hint_q88_consts:
	.long	0x0000002c,0x0000002c,0x0000002c,0x0000002c
	.long	0x003fefd4,0x003fefd4,0x003fefd4,0x003fefd4
	.long	0x0002e800,0x0002e800,0x0002e800,0x0002e800
	.long	0x00017400,0x00017400,0x00017400,0x00017400
	.long	0x0000002b,0x0000002b,0x0000002b,0x0000002b
	.long	0x007fe001,0x007fe001,0x007fe001,0x007fe001
#ifndef __APPLE__
.text
.globl	mldsa_use_hint_q88_neon
WC_ASM_ATT_HIDDEN(mldsa_use_hint_q88_neon)
.type	mldsa_use_hint_q88_neon,@function
.align	2
mldsa_use_hint_q88_neon:
#else
.section	__TEXT,__text
.globl	_mldsa_use_hint_q88_neon
WC_ASM_ATT_HIDDEN(_mldsa_use_hint_q88_neon)
.p2align	2
_mldsa_use_hint_q88_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
	stp	d12, d13, [x29, #48]
	stp	d14, d15, [x29, #64]
#ifndef __APPLE__
	adrp x1, L_mldsa_use_hint_q88_consts
	add  x1, x1, :lo12:L_mldsa_use_hint_q88_consts
#else
	adrp x1, L_mldsa_use_hint_q88_consts@PAGE
	add  x1, x1, L_mldsa_use_hint_q88_consts@PAGEOFF
#endif /* __APPLE__ */
	ldr	q0, [x1]
	ldr	q1, [x1, #16]
	ldr	q2, [x1, #32]
	ldr	q3, [x1, #48]
	ldr	q4, [x1, #64]
	ldr	q5, [x1, #80]
	mov	x2, #16
L_mldsa_use_hint_q88_loop:
	ldr	q6, [x0]
	ldr	q7, [x0, #16]
	ldr	q8, [x0, #32]
	ldr	q9, [x0, #48]
	sshr	v18.4s, v6.4s, #31
	and	v18.16b, v18.16b, v5.16b
	add	v6.4s, v6.4s, v18.4s
	sshr	v19.4s, v7.4s, #31
	and	v19.16b, v19.16b, v5.16b
	add	v7.4s, v7.4s, v19.4s
	sshr	v20.4s, v8.4s, #31
	and	v20.16b, v20.16b, v5.16b
	add	v8.4s, v8.4s, v20.4s
	sshr	v21.4s, v9.4s, #31
	and	v21.16b, v21.16b, v5.16b
	add	v9.4s, v9.4s, v21.4s
	mov	v14.16b, v1.16b
	mla	v14.4s, v6.4s, v0.4s
	sshr	v14.4s, v14.4s, #23
	mov	v10.16b, v6.16b
	mls	v10.4s, v14.4s, v2.4s
	sub	v18.4s, v3.4s, v10.4s
	usra	v14.4s, v18.4s, #31
	mov	v10.16b, v6.16b
	mls	v10.4s, v14.4s, v2.4s
	sub	v18.4s, v4.4s, v14.4s
	ushr	v18.4s, v18.4s, #31
	sub	v10.4s, v10.4s, v18.4s
	sub	v18.4s, v14.4s, v0.4s
	ushr	v18.4s, v18.4s, #31
	neg	v18.4s, v18.4s
	and	v14.16b, v14.16b, v18.16b
	mov	v15.16b, v1.16b
	mla	v15.4s, v7.4s, v0.4s
	sshr	v15.4s, v15.4s, #23
	mov	v11.16b, v7.16b
	mls	v11.4s, v15.4s, v2.4s
	sub	v19.4s, v3.4s, v11.4s
	usra	v15.4s, v19.4s, #31
	mov	v11.16b, v7.16b
	mls	v11.4s, v15.4s, v2.4s
	sub	v19.4s, v4.4s, v15.4s
	ushr	v19.4s, v19.4s, #31
	sub	v11.4s, v11.4s, v19.4s
	sub	v19.4s, v15.4s, v0.4s
	ushr	v19.4s, v19.4s, #31
	neg	v19.4s, v19.4s
	and	v15.16b, v15.16b, v19.16b
	mov	v16.16b, v1.16b
	mla	v16.4s, v8.4s, v0.4s
	sshr	v16.4s, v16.4s, #23
	mov	v12.16b, v8.16b
	mls	v12.4s, v16.4s, v2.4s
	sub	v20.4s, v3.4s, v12.4s
	usra	v16.4s, v20.4s, #31
	mov	v12.16b, v8.16b
	mls	v12.4s, v16.4s, v2.4s
	sub	v20.4s, v4.4s, v16.4s
	ushr	v20.4s, v20.4s, #31
	sub	v12.4s, v12.4s, v20.4s
	sub	v20.4s, v16.4s, v0.4s
	ushr	v20.4s, v20.4s, #31
	neg	v20.4s, v20.4s
	and	v16.16b, v16.16b, v20.16b
	mov	v17.16b, v1.16b
	mla	v17.4s, v9.4s, v0.4s
	sshr	v17.4s, v17.4s, #23
	mov	v13.16b, v9.16b
	mls	v13.4s, v17.4s, v2.4s
	sub	v21.4s, v3.4s, v13.4s
	usra	v17.4s, v21.4s, #31
	mov	v13.16b, v9.16b
	mls	v13.4s, v17.4s, v2.4s
	sub	v21.4s, v4.4s, v17.4s
	ushr	v21.4s, v21.4s, #31
	sub	v13.4s, v13.4s, v21.4s
	sub	v21.4s, v17.4s, v0.4s
	ushr	v21.4s, v21.4s, #31
	neg	v21.4s, v21.4s
	and	v17.16b, v17.16b, v21.16b
	str	q14, [x0]
	str	q15, [x0, #16]
	str	q16, [x0, #32]
	str	q17, [x0, #48]
	add	x0, x0, #0x40
	subs	x2, x2, #1
	bne	L_mldsa_use_hint_q88_loop
	ldp	d8, d9, [x29, #16]
	ldp	d10, d11, [x29, #32]
	ldp	d12, d13, [x29, #48]
	ldp	d14, d15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
#ifndef __APPLE__
	.size	mldsa_use_hint_q88_neon,.-mldsa_use_hint_q88_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mldsa_use_hint_q32_consts, %object
	.size	L_mldsa_use_hint_q32_consts, 80
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_use_hint_q32_consts:
	.long	0x0003feff,0x0003feff,0x0003feff,0x0003feff
	.long	0x0003ff00,0x0003ff00,0x0003ff00,0x0003ff00
	.long	0x0000000f,0x0000000f,0x0000000f,0x0000000f
	.long	0x0007fe00,0x0007fe00,0x0007fe00,0x0007fe00
	.long	0x007fe001,0x007fe001,0x007fe001,0x007fe001
#ifndef __APPLE__
.text
.globl	mldsa_use_hint_q32_neon
WC_ASM_ATT_HIDDEN(mldsa_use_hint_q32_neon)
.type	mldsa_use_hint_q32_neon,@function
.align	2
mldsa_use_hint_q32_neon:
#else
.section	__TEXT,__text
.globl	_mldsa_use_hint_q32_neon
WC_ASM_ATT_HIDDEN(_mldsa_use_hint_q32_neon)
.p2align	2
_mldsa_use_hint_q32_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
	stp	d12, d13, [x29, #48]
	stp	d14, d15, [x29, #64]
#ifndef __APPLE__
	adrp x1, L_mldsa_use_hint_q32_consts
	add  x1, x1, :lo12:L_mldsa_use_hint_q32_consts
#else
	adrp x1, L_mldsa_use_hint_q32_consts@PAGE
	add  x1, x1, L_mldsa_use_hint_q32_consts@PAGEOFF
#endif /* __APPLE__ */
	ldr	q0, [x1]
	ldr	q1, [x1, #16]
	ldr	q2, [x1, #32]
	ldr	q3, [x1, #48]
	ldr	q4, [x1, #64]
	mov	x2, #16
L_mldsa_use_hint_q32_loop:
	ldr	q5, [x0]
	ldr	q6, [x0, #16]
	ldr	q7, [x0, #32]
	ldr	q8, [x0, #48]
	sshr	v17.4s, v5.4s, #31
	and	v17.16b, v17.16b, v4.16b
	add	v5.4s, v5.4s, v17.4s
	sshr	v18.4s, v6.4s, #31
	and	v18.16b, v18.16b, v4.16b
	add	v6.4s, v6.4s, v18.4s
	sshr	v19.4s, v7.4s, #31
	and	v19.16b, v19.16b, v4.16b
	add	v7.4s, v7.4s, v19.4s
	sshr	v20.4s, v8.4s, #31
	and	v20.16b, v20.16b, v4.16b
	add	v8.4s, v8.4s, v20.4s
	add	v13.4s, v5.4s, v0.4s
	sshr	v13.4s, v13.4s, #19
	mov	v9.16b, v5.16b
	mls	v9.4s, v13.4s, v3.4s
	sub	v17.4s, v1.4s, v9.4s
	usra	v13.4s, v17.4s, #31
	mov	v9.16b, v5.16b
	mls	v9.4s, v13.4s, v3.4s
	sshr	v17.4s, v13.4s, #4
	sub	v9.4s, v9.4s, v17.4s
	and	v13.16b, v13.16b, v2.16b
	add	v14.4s, v6.4s, v0.4s
	sshr	v14.4s, v14.4s, #19
	mov	v10.16b, v6.16b
	mls	v10.4s, v14.4s, v3.4s
	sub	v18.4s, v1.4s, v10.4s
	usra	v14.4s, v18.4s, #31
	mov	v10.16b, v6.16b
	mls	v10.4s, v14.4s, v3.4s
	sshr	v18.4s, v14.4s, #4
	sub	v10.4s, v10.4s, v18.4s
	and	v14.16b, v14.16b, v2.16b
	add	v15.4s, v7.4s, v0.4s
	sshr	v15.4s, v15.4s, #19
	mov	v11.16b, v7.16b
	mls	v11.4s, v15.4s, v3.4s
	sub	v19.4s, v1.4s, v11.4s
	usra	v15.4s, v19.4s, #31
	mov	v11.16b, v7.16b
	mls	v11.4s, v15.4s, v3.4s
	sshr	v19.4s, v15.4s, #4
	sub	v11.4s, v11.4s, v19.4s
	and	v15.16b, v15.16b, v2.16b
	add	v16.4s, v8.4s, v0.4s
	sshr	v16.4s, v16.4s, #19
	mov	v12.16b, v8.16b
	mls	v12.4s, v16.4s, v3.4s
	sub	v20.4s, v1.4s, v12.4s
	usra	v16.4s, v20.4s, #31
	mov	v12.16b, v8.16b
	mls	v12.4s, v16.4s, v3.4s
	sshr	v20.4s, v16.4s, #4
	sub	v12.4s, v12.4s, v20.4s
	and	v16.16b, v16.16b, v2.16b
	str	q13, [x0]
	str	q14, [x0, #16]
	str	q15, [x0, #32]
	str	q16, [x0, #48]
	add	x0, x0, #0x40
	subs	x2, x2, #1
	bne	L_mldsa_use_hint_q32_loop
	ldp	d8, d9, [x29, #16]
	ldp	d10, d11, [x29, #32]
	ldp	d12, d13, [x29, #48]
	ldp	d14, d15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
#ifndef __APPLE__
	.size	mldsa_use_hint_q32_neon,.-mldsa_use_hint_q32_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mldsa_make_hint_bits, %object
	.size	L_mldsa_make_hint_bits, 64
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_make_hint_bits:
	.long	0x00000001,0x00000002,0x00000004,0x00000008
	.long	0x00000010,0x00000020,0x00000040,0x00000080
	.long	0x00000100,0x00000200,0x00000400,0x00000800
	.long	0x00001000,0x00002000,0x00004000,0x00008000
#ifndef __APPLE__
.text
.globl	mldsa_make_hint_neon
WC_ASM_ATT_HIDDEN(mldsa_make_hint_neon)
.type	mldsa_make_hint_neon,@function
.align	2
mldsa_make_hint_neon:
#else
.section	__TEXT,__text
.globl	_mldsa_make_hint_neon
WC_ASM_ATT_HIDDEN(_mldsa_make_hint_neon)
.p2align	2
_mldsa_make_hint_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
	stp	d12, d13, [x29, #48]
	stp	d14, d15, [x29, #64]
#ifndef __APPLE__
	adrp x6, L_mldsa_make_hint_bits
	add  x6, x6, :lo12:L_mldsa_make_hint_bits
#else
	adrp x6, L_mldsa_make_hint_bits@PAGE
	add  x6, x6, L_mldsa_make_hint_bits@PAGEOFF
#endif /* __APPLE__ */
	dup	v0.4s, w5
	neg	v1.4s, v0.4s
	ldr	q2, [x6]
	ldr	q3, [x6, #16]
	ldr	q4, [x6, #32]
	ldr	q5, [x6, #48]
	eor	x7, x7, x7
L_mldsa_make_hint_loop:
	ldr	q6, [x0]
	ldr	q10, [x1]
	ldr	q7, [x0, #16]
	ldr	q11, [x1, #16]
	ldr	q8, [x0, #32]
	ldr	q12, [x1, #32]
	ldr	q9, [x0, #48]
	ldr	q13, [x1, #48]
	cmgt	v14.4s, v6.4s, v0.4s
	cmgt	v18.4s, v1.4s, v6.4s
	cmeq	v22.4s, v6.4s, v1.4s
	cmeq	v10.4s, v10.4s, #0
	bic	v22.16b, v22.16b, v10.16b
	orr	v14.16b, v14.16b, v18.16b
	orr	v14.16b, v14.16b, v22.16b
	and	v14.16b, v14.16b, v2.16b
	cmgt	v15.4s, v7.4s, v0.4s
	cmgt	v19.4s, v1.4s, v7.4s
	cmeq	v23.4s, v7.4s, v1.4s
	cmeq	v11.4s, v11.4s, #0
	bic	v23.16b, v23.16b, v11.16b
	orr	v15.16b, v15.16b, v19.16b
	orr	v15.16b, v15.16b, v23.16b
	and	v15.16b, v15.16b, v3.16b
	cmgt	v16.4s, v8.4s, v0.4s
	cmgt	v20.4s, v1.4s, v8.4s
	cmeq	v24.4s, v8.4s, v1.4s
	cmeq	v12.4s, v12.4s, #0
	bic	v24.16b, v24.16b, v12.16b
	orr	v16.16b, v16.16b, v20.16b
	orr	v16.16b, v16.16b, v24.16b
	and	v16.16b, v16.16b, v4.16b
	cmgt	v17.4s, v9.4s, v0.4s
	cmgt	v21.4s, v1.4s, v9.4s
	cmeq	v25.4s, v9.4s, v1.4s
	cmeq	v13.4s, v13.4s, #0
	bic	v25.16b, v25.16b, v13.16b
	orr	v17.16b, v17.16b, v21.16b
	orr	v17.16b, v17.16b, v25.16b
	and	v17.16b, v17.16b, v5.16b
	orr	v14.16b, v14.16b, v15.16b
	orr	v16.16b, v16.16b, v17.16b
	orr	v14.16b, v14.16b, v16.16b
	addv	s14, v14.4s
	mov	w8, v14.s[0]
	cbz	w8, L_mldsa_make_hint_next
L_mldsa_make_hint_bit:
	rbit	w9, w8
	clz	w9, w9
	add	w9, w9, w7
	strb	w9, [x2]
	add	x2, x2, #1
	add	w3, w3, #1
	subs	wzr, w3, w4
	bgt	L_mldsa_make_hint_fail
	sub	w10, w8, #1
	and	w8, w8, w10
	cbnz	w8, L_mldsa_make_hint_bit
L_mldsa_make_hint_next:
	add	x0, x0, #0x40
	add	x1, x1, #0x40
	add	x7, x7, #16
	subs	wzr, w7, #0x100
	blt	L_mldsa_make_hint_loop
	mov	x0, x3
	b	L_mldsa_make_hint_done
L_mldsa_make_hint_fail:
	movn	x0, #0
L_mldsa_make_hint_done:
	ldp	d8, d9, [x29, #16]
	ldp	d10, d11, [x29, #32]
	ldp	d12, d13, [x29, #48]
	ldp	d14, d15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
#ifndef __APPLE__
	.size	mldsa_make_hint_neon,.-mldsa_make_hint_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	mldsa_mul_vec_4_neon
WC_ASM_ATT_HIDDEN(mldsa_mul_vec_4_neon)
.type	mldsa_mul_vec_4_neon,@function
.align	2
mldsa_mul_vec_4_neon:
#else
.section	__TEXT,__text
.globl	_mldsa_mul_vec_4_neon
WC_ASM_ATT_HIDDEN(_mldsa_mul_vec_4_neon)
.p2align	2
_mldsa_mul_vec_4_neon:
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x3, L_mldsa_aarch64_consts
	add  x3, x3, :lo12:L_mldsa_aarch64_consts
#else
	adrp x3, L_mldsa_aarch64_consts@PAGE
	add  x3, x3, L_mldsa_aarch64_consts@PAGEOFF
#endif /* __APPLE__ */
	ldr	q0, [x3]
	ldr	q1, [x1]
	ldr	q2, [x2]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1024]
	ldr	q2, [x2, #1024]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2048]
	ldr	q2, [x2, #2048]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3072]
	ldr	q2, [x2, #3072]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0]
	ldr	q1, [x1, #16]
	ldr	q2, [x2, #16]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1040]
	ldr	q2, [x2, #1040]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2064]
	ldr	q2, [x2, #2064]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3088]
	ldr	q2, [x2, #3088]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #16]
	ldr	q1, [x1, #32]
	ldr	q2, [x2, #32]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1056]
	ldr	q2, [x2, #1056]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2080]
	ldr	q2, [x2, #2080]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3104]
	ldr	q2, [x2, #3104]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #32]
	ldr	q1, [x1, #48]
	ldr	q2, [x2, #48]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1072]
	ldr	q2, [x2, #1072]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2096]
	ldr	q2, [x2, #2096]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3120]
	ldr	q2, [x2, #3120]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #48]
	ldr	q1, [x1, #64]
	ldr	q2, [x2, #64]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1088]
	ldr	q2, [x2, #1088]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2112]
	ldr	q2, [x2, #2112]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3136]
	ldr	q2, [x2, #3136]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #64]
	ldr	q1, [x1, #80]
	ldr	q2, [x2, #80]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1104]
	ldr	q2, [x2, #1104]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2128]
	ldr	q2, [x2, #2128]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3152]
	ldr	q2, [x2, #3152]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #80]
	ldr	q1, [x1, #96]
	ldr	q2, [x2, #96]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1120]
	ldr	q2, [x2, #1120]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2144]
	ldr	q2, [x2, #2144]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3168]
	ldr	q2, [x2, #3168]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #96]
	ldr	q1, [x1, #112]
	ldr	q2, [x2, #112]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1136]
	ldr	q2, [x2, #1136]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2160]
	ldr	q2, [x2, #2160]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3184]
	ldr	q2, [x2, #3184]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #112]
	ldr	q1, [x1, #128]
	ldr	q2, [x2, #128]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1152]
	ldr	q2, [x2, #1152]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2176]
	ldr	q2, [x2, #2176]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3200]
	ldr	q2, [x2, #3200]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #128]
	ldr	q1, [x1, #144]
	ldr	q2, [x2, #144]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1168]
	ldr	q2, [x2, #1168]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2192]
	ldr	q2, [x2, #2192]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3216]
	ldr	q2, [x2, #3216]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #144]
	ldr	q1, [x1, #160]
	ldr	q2, [x2, #160]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1184]
	ldr	q2, [x2, #1184]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2208]
	ldr	q2, [x2, #2208]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3232]
	ldr	q2, [x2, #3232]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #160]
	ldr	q1, [x1, #176]
	ldr	q2, [x2, #176]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1200]
	ldr	q2, [x2, #1200]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2224]
	ldr	q2, [x2, #2224]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3248]
	ldr	q2, [x2, #3248]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #176]
	ldr	q1, [x1, #192]
	ldr	q2, [x2, #192]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1216]
	ldr	q2, [x2, #1216]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2240]
	ldr	q2, [x2, #2240]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3264]
	ldr	q2, [x2, #3264]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #192]
	ldr	q1, [x1, #208]
	ldr	q2, [x2, #208]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1232]
	ldr	q2, [x2, #1232]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2256]
	ldr	q2, [x2, #2256]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3280]
	ldr	q2, [x2, #3280]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #208]
	ldr	q1, [x1, #224]
	ldr	q2, [x2, #224]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1248]
	ldr	q2, [x2, #1248]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2272]
	ldr	q2, [x2, #2272]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3296]
	ldr	q2, [x2, #3296]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #224]
	ldr	q1, [x1, #240]
	ldr	q2, [x2, #240]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1264]
	ldr	q2, [x2, #1264]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2288]
	ldr	q2, [x2, #2288]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3312]
	ldr	q2, [x2, #3312]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #240]
	ldr	q1, [x1, #256]
	ldr	q2, [x2, #256]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1280]
	ldr	q2, [x2, #1280]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2304]
	ldr	q2, [x2, #2304]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3328]
	ldr	q2, [x2, #3328]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #256]
	ldr	q1, [x1, #272]
	ldr	q2, [x2, #272]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1296]
	ldr	q2, [x2, #1296]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2320]
	ldr	q2, [x2, #2320]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3344]
	ldr	q2, [x2, #3344]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #272]
	ldr	q1, [x1, #288]
	ldr	q2, [x2, #288]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1312]
	ldr	q2, [x2, #1312]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2336]
	ldr	q2, [x2, #2336]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3360]
	ldr	q2, [x2, #3360]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #288]
	ldr	q1, [x1, #304]
	ldr	q2, [x2, #304]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1328]
	ldr	q2, [x2, #1328]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2352]
	ldr	q2, [x2, #2352]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3376]
	ldr	q2, [x2, #3376]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #304]
	ldr	q1, [x1, #320]
	ldr	q2, [x2, #320]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1344]
	ldr	q2, [x2, #1344]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2368]
	ldr	q2, [x2, #2368]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3392]
	ldr	q2, [x2, #3392]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #320]
	ldr	q1, [x1, #336]
	ldr	q2, [x2, #336]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1360]
	ldr	q2, [x2, #1360]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2384]
	ldr	q2, [x2, #2384]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3408]
	ldr	q2, [x2, #3408]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #336]
	ldr	q1, [x1, #352]
	ldr	q2, [x2, #352]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1376]
	ldr	q2, [x2, #1376]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2400]
	ldr	q2, [x2, #2400]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3424]
	ldr	q2, [x2, #3424]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #352]
	ldr	q1, [x1, #368]
	ldr	q2, [x2, #368]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1392]
	ldr	q2, [x2, #1392]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2416]
	ldr	q2, [x2, #2416]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3440]
	ldr	q2, [x2, #3440]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #368]
	ldr	q1, [x1, #384]
	ldr	q2, [x2, #384]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1408]
	ldr	q2, [x2, #1408]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2432]
	ldr	q2, [x2, #2432]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3456]
	ldr	q2, [x2, #3456]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #384]
	ldr	q1, [x1, #400]
	ldr	q2, [x2, #400]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1424]
	ldr	q2, [x2, #1424]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2448]
	ldr	q2, [x2, #2448]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3472]
	ldr	q2, [x2, #3472]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #400]
	ldr	q1, [x1, #416]
	ldr	q2, [x2, #416]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1440]
	ldr	q2, [x2, #1440]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2464]
	ldr	q2, [x2, #2464]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3488]
	ldr	q2, [x2, #3488]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #416]
	ldr	q1, [x1, #432]
	ldr	q2, [x2, #432]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1456]
	ldr	q2, [x2, #1456]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2480]
	ldr	q2, [x2, #2480]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3504]
	ldr	q2, [x2, #3504]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #432]
	ldr	q1, [x1, #448]
	ldr	q2, [x2, #448]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1472]
	ldr	q2, [x2, #1472]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2496]
	ldr	q2, [x2, #2496]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3520]
	ldr	q2, [x2, #3520]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #448]
	ldr	q1, [x1, #464]
	ldr	q2, [x2, #464]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1488]
	ldr	q2, [x2, #1488]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2512]
	ldr	q2, [x2, #2512]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3536]
	ldr	q2, [x2, #3536]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #464]
	ldr	q1, [x1, #480]
	ldr	q2, [x2, #480]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1504]
	ldr	q2, [x2, #1504]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2528]
	ldr	q2, [x2, #2528]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3552]
	ldr	q2, [x2, #3552]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #480]
	ldr	q1, [x1, #496]
	ldr	q2, [x2, #496]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1520]
	ldr	q2, [x2, #1520]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2544]
	ldr	q2, [x2, #2544]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3568]
	ldr	q2, [x2, #3568]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #496]
	ldr	q1, [x1, #512]
	ldr	q2, [x2, #512]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1536]
	ldr	q2, [x2, #1536]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2560]
	ldr	q2, [x2, #2560]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3584]
	ldr	q2, [x2, #3584]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #512]
	ldr	q1, [x1, #528]
	ldr	q2, [x2, #528]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1552]
	ldr	q2, [x2, #1552]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2576]
	ldr	q2, [x2, #2576]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3600]
	ldr	q2, [x2, #3600]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #528]
	ldr	q1, [x1, #544]
	ldr	q2, [x2, #544]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1568]
	ldr	q2, [x2, #1568]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2592]
	ldr	q2, [x2, #2592]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3616]
	ldr	q2, [x2, #3616]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #544]
	ldr	q1, [x1, #560]
	ldr	q2, [x2, #560]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1584]
	ldr	q2, [x2, #1584]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2608]
	ldr	q2, [x2, #2608]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3632]
	ldr	q2, [x2, #3632]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #560]
	ldr	q1, [x1, #576]
	ldr	q2, [x2, #576]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1600]
	ldr	q2, [x2, #1600]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2624]
	ldr	q2, [x2, #2624]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3648]
	ldr	q2, [x2, #3648]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #576]
	ldr	q1, [x1, #592]
	ldr	q2, [x2, #592]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1616]
	ldr	q2, [x2, #1616]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2640]
	ldr	q2, [x2, #2640]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3664]
	ldr	q2, [x2, #3664]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #592]
	ldr	q1, [x1, #608]
	ldr	q2, [x2, #608]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1632]
	ldr	q2, [x2, #1632]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2656]
	ldr	q2, [x2, #2656]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3680]
	ldr	q2, [x2, #3680]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #608]
	ldr	q1, [x1, #624]
	ldr	q2, [x2, #624]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1648]
	ldr	q2, [x2, #1648]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2672]
	ldr	q2, [x2, #2672]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3696]
	ldr	q2, [x2, #3696]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #624]
	ldr	q1, [x1, #640]
	ldr	q2, [x2, #640]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1664]
	ldr	q2, [x2, #1664]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2688]
	ldr	q2, [x2, #2688]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3712]
	ldr	q2, [x2, #3712]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #640]
	ldr	q1, [x1, #656]
	ldr	q2, [x2, #656]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1680]
	ldr	q2, [x2, #1680]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2704]
	ldr	q2, [x2, #2704]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3728]
	ldr	q2, [x2, #3728]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #656]
	ldr	q1, [x1, #672]
	ldr	q2, [x2, #672]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1696]
	ldr	q2, [x2, #1696]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2720]
	ldr	q2, [x2, #2720]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3744]
	ldr	q2, [x2, #3744]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #672]
	ldr	q1, [x1, #688]
	ldr	q2, [x2, #688]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1712]
	ldr	q2, [x2, #1712]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2736]
	ldr	q2, [x2, #2736]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3760]
	ldr	q2, [x2, #3760]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #688]
	ldr	q1, [x1, #704]
	ldr	q2, [x2, #704]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1728]
	ldr	q2, [x2, #1728]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2752]
	ldr	q2, [x2, #2752]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3776]
	ldr	q2, [x2, #3776]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #704]
	ldr	q1, [x1, #720]
	ldr	q2, [x2, #720]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1744]
	ldr	q2, [x2, #1744]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2768]
	ldr	q2, [x2, #2768]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3792]
	ldr	q2, [x2, #3792]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #720]
	ldr	q1, [x1, #736]
	ldr	q2, [x2, #736]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1760]
	ldr	q2, [x2, #1760]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2784]
	ldr	q2, [x2, #2784]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3808]
	ldr	q2, [x2, #3808]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #736]
	ldr	q1, [x1, #752]
	ldr	q2, [x2, #752]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1776]
	ldr	q2, [x2, #1776]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2800]
	ldr	q2, [x2, #2800]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3824]
	ldr	q2, [x2, #3824]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #752]
	ldr	q1, [x1, #768]
	ldr	q2, [x2, #768]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1792]
	ldr	q2, [x2, #1792]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2816]
	ldr	q2, [x2, #2816]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3840]
	ldr	q2, [x2, #3840]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #768]
	ldr	q1, [x1, #784]
	ldr	q2, [x2, #784]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1808]
	ldr	q2, [x2, #1808]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2832]
	ldr	q2, [x2, #2832]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3856]
	ldr	q2, [x2, #3856]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #784]
	ldr	q1, [x1, #800]
	ldr	q2, [x2, #800]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1824]
	ldr	q2, [x2, #1824]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2848]
	ldr	q2, [x2, #2848]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3872]
	ldr	q2, [x2, #3872]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #800]
	ldr	q1, [x1, #816]
	ldr	q2, [x2, #816]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1840]
	ldr	q2, [x2, #1840]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2864]
	ldr	q2, [x2, #2864]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3888]
	ldr	q2, [x2, #3888]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #816]
	ldr	q1, [x1, #832]
	ldr	q2, [x2, #832]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1856]
	ldr	q2, [x2, #1856]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2880]
	ldr	q2, [x2, #2880]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3904]
	ldr	q2, [x2, #3904]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #832]
	ldr	q1, [x1, #848]
	ldr	q2, [x2, #848]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1872]
	ldr	q2, [x2, #1872]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2896]
	ldr	q2, [x2, #2896]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3920]
	ldr	q2, [x2, #3920]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #848]
	ldr	q1, [x1, #864]
	ldr	q2, [x2, #864]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1888]
	ldr	q2, [x2, #1888]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2912]
	ldr	q2, [x2, #2912]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3936]
	ldr	q2, [x2, #3936]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #864]
	ldr	q1, [x1, #880]
	ldr	q2, [x2, #880]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1904]
	ldr	q2, [x2, #1904]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2928]
	ldr	q2, [x2, #2928]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3952]
	ldr	q2, [x2, #3952]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #880]
	ldr	q1, [x1, #896]
	ldr	q2, [x2, #896]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1920]
	ldr	q2, [x2, #1920]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2944]
	ldr	q2, [x2, #2944]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3968]
	ldr	q2, [x2, #3968]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #896]
	ldr	q1, [x1, #912]
	ldr	q2, [x2, #912]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1936]
	ldr	q2, [x2, #1936]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2960]
	ldr	q2, [x2, #2960]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3984]
	ldr	q2, [x2, #3984]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #912]
	ldr	q1, [x1, #928]
	ldr	q2, [x2, #928]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1952]
	ldr	q2, [x2, #1952]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2976]
	ldr	q2, [x2, #2976]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4000]
	ldr	q2, [x2, #4000]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #928]
	ldr	q1, [x1, #944]
	ldr	q2, [x2, #944]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1968]
	ldr	q2, [x2, #1968]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2992]
	ldr	q2, [x2, #2992]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4016]
	ldr	q2, [x2, #4016]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #944]
	ldr	q1, [x1, #960]
	ldr	q2, [x2, #960]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1984]
	ldr	q2, [x2, #1984]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3008]
	ldr	q2, [x2, #3008]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4032]
	ldr	q2, [x2, #4032]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #960]
	ldr	q1, [x1, #976]
	ldr	q2, [x2, #976]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2000]
	ldr	q2, [x2, #2000]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3024]
	ldr	q2, [x2, #3024]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4048]
	ldr	q2, [x2, #4048]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #976]
	ldr	q1, [x1, #992]
	ldr	q2, [x2, #992]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2016]
	ldr	q2, [x2, #2016]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3040]
	ldr	q2, [x2, #3040]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4064]
	ldr	q2, [x2, #4064]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #992]
	ldr	q1, [x1, #1008]
	ldr	q2, [x2, #1008]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2032]
	ldr	q2, [x2, #2032]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3056]
	ldr	q2, [x2, #3056]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4080]
	ldr	q2, [x2, #4080]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #1008]
	ret
#ifndef __APPLE__
	.size	mldsa_mul_vec_4_neon,.-mldsa_mul_vec_4_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	mldsa_mul_vec_5_neon
WC_ASM_ATT_HIDDEN(mldsa_mul_vec_5_neon)
.type	mldsa_mul_vec_5_neon,@function
.align	2
mldsa_mul_vec_5_neon:
#else
.section	__TEXT,__text
.globl	_mldsa_mul_vec_5_neon
WC_ASM_ATT_HIDDEN(_mldsa_mul_vec_5_neon)
.p2align	2
_mldsa_mul_vec_5_neon:
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x3, L_mldsa_aarch64_consts
	add  x3, x3, :lo12:L_mldsa_aarch64_consts
#else
	adrp x3, L_mldsa_aarch64_consts@PAGE
	add  x3, x3, L_mldsa_aarch64_consts@PAGEOFF
#endif /* __APPLE__ */
	ldr	q0, [x3]
	ldr	q1, [x1]
	ldr	q2, [x2]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1024]
	ldr	q2, [x2, #1024]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2048]
	ldr	q2, [x2, #2048]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3072]
	ldr	q2, [x2, #3072]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4096]
	ldr	q2, [x2, #4096]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0]
	ldr	q1, [x1, #16]
	ldr	q2, [x2, #16]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1040]
	ldr	q2, [x2, #1040]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2064]
	ldr	q2, [x2, #2064]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3088]
	ldr	q2, [x2, #3088]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4112]
	ldr	q2, [x2, #4112]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #16]
	ldr	q1, [x1, #32]
	ldr	q2, [x2, #32]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1056]
	ldr	q2, [x2, #1056]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2080]
	ldr	q2, [x2, #2080]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3104]
	ldr	q2, [x2, #3104]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4128]
	ldr	q2, [x2, #4128]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #32]
	ldr	q1, [x1, #48]
	ldr	q2, [x2, #48]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1072]
	ldr	q2, [x2, #1072]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2096]
	ldr	q2, [x2, #2096]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3120]
	ldr	q2, [x2, #3120]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4144]
	ldr	q2, [x2, #4144]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #48]
	ldr	q1, [x1, #64]
	ldr	q2, [x2, #64]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1088]
	ldr	q2, [x2, #1088]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2112]
	ldr	q2, [x2, #2112]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3136]
	ldr	q2, [x2, #3136]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4160]
	ldr	q2, [x2, #4160]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #64]
	ldr	q1, [x1, #80]
	ldr	q2, [x2, #80]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1104]
	ldr	q2, [x2, #1104]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2128]
	ldr	q2, [x2, #2128]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3152]
	ldr	q2, [x2, #3152]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4176]
	ldr	q2, [x2, #4176]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #80]
	ldr	q1, [x1, #96]
	ldr	q2, [x2, #96]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1120]
	ldr	q2, [x2, #1120]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2144]
	ldr	q2, [x2, #2144]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3168]
	ldr	q2, [x2, #3168]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4192]
	ldr	q2, [x2, #4192]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #96]
	ldr	q1, [x1, #112]
	ldr	q2, [x2, #112]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1136]
	ldr	q2, [x2, #1136]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2160]
	ldr	q2, [x2, #2160]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3184]
	ldr	q2, [x2, #3184]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4208]
	ldr	q2, [x2, #4208]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #112]
	ldr	q1, [x1, #128]
	ldr	q2, [x2, #128]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1152]
	ldr	q2, [x2, #1152]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2176]
	ldr	q2, [x2, #2176]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3200]
	ldr	q2, [x2, #3200]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4224]
	ldr	q2, [x2, #4224]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #128]
	ldr	q1, [x1, #144]
	ldr	q2, [x2, #144]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1168]
	ldr	q2, [x2, #1168]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2192]
	ldr	q2, [x2, #2192]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3216]
	ldr	q2, [x2, #3216]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4240]
	ldr	q2, [x2, #4240]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #144]
	ldr	q1, [x1, #160]
	ldr	q2, [x2, #160]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1184]
	ldr	q2, [x2, #1184]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2208]
	ldr	q2, [x2, #2208]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3232]
	ldr	q2, [x2, #3232]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4256]
	ldr	q2, [x2, #4256]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #160]
	ldr	q1, [x1, #176]
	ldr	q2, [x2, #176]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1200]
	ldr	q2, [x2, #1200]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2224]
	ldr	q2, [x2, #2224]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3248]
	ldr	q2, [x2, #3248]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4272]
	ldr	q2, [x2, #4272]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #176]
	ldr	q1, [x1, #192]
	ldr	q2, [x2, #192]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1216]
	ldr	q2, [x2, #1216]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2240]
	ldr	q2, [x2, #2240]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3264]
	ldr	q2, [x2, #3264]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4288]
	ldr	q2, [x2, #4288]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #192]
	ldr	q1, [x1, #208]
	ldr	q2, [x2, #208]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1232]
	ldr	q2, [x2, #1232]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2256]
	ldr	q2, [x2, #2256]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3280]
	ldr	q2, [x2, #3280]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4304]
	ldr	q2, [x2, #4304]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #208]
	ldr	q1, [x1, #224]
	ldr	q2, [x2, #224]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1248]
	ldr	q2, [x2, #1248]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2272]
	ldr	q2, [x2, #2272]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3296]
	ldr	q2, [x2, #3296]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4320]
	ldr	q2, [x2, #4320]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #224]
	ldr	q1, [x1, #240]
	ldr	q2, [x2, #240]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1264]
	ldr	q2, [x2, #1264]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2288]
	ldr	q2, [x2, #2288]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3312]
	ldr	q2, [x2, #3312]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4336]
	ldr	q2, [x2, #4336]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #240]
	ldr	q1, [x1, #256]
	ldr	q2, [x2, #256]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1280]
	ldr	q2, [x2, #1280]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2304]
	ldr	q2, [x2, #2304]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3328]
	ldr	q2, [x2, #3328]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4352]
	ldr	q2, [x2, #4352]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #256]
	ldr	q1, [x1, #272]
	ldr	q2, [x2, #272]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1296]
	ldr	q2, [x2, #1296]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2320]
	ldr	q2, [x2, #2320]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3344]
	ldr	q2, [x2, #3344]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4368]
	ldr	q2, [x2, #4368]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #272]
	ldr	q1, [x1, #288]
	ldr	q2, [x2, #288]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1312]
	ldr	q2, [x2, #1312]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2336]
	ldr	q2, [x2, #2336]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3360]
	ldr	q2, [x2, #3360]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4384]
	ldr	q2, [x2, #4384]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #288]
	ldr	q1, [x1, #304]
	ldr	q2, [x2, #304]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1328]
	ldr	q2, [x2, #1328]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2352]
	ldr	q2, [x2, #2352]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3376]
	ldr	q2, [x2, #3376]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4400]
	ldr	q2, [x2, #4400]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #304]
	ldr	q1, [x1, #320]
	ldr	q2, [x2, #320]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1344]
	ldr	q2, [x2, #1344]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2368]
	ldr	q2, [x2, #2368]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3392]
	ldr	q2, [x2, #3392]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4416]
	ldr	q2, [x2, #4416]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #320]
	ldr	q1, [x1, #336]
	ldr	q2, [x2, #336]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1360]
	ldr	q2, [x2, #1360]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2384]
	ldr	q2, [x2, #2384]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3408]
	ldr	q2, [x2, #3408]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4432]
	ldr	q2, [x2, #4432]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #336]
	ldr	q1, [x1, #352]
	ldr	q2, [x2, #352]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1376]
	ldr	q2, [x2, #1376]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2400]
	ldr	q2, [x2, #2400]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3424]
	ldr	q2, [x2, #3424]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4448]
	ldr	q2, [x2, #4448]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #352]
	ldr	q1, [x1, #368]
	ldr	q2, [x2, #368]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1392]
	ldr	q2, [x2, #1392]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2416]
	ldr	q2, [x2, #2416]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3440]
	ldr	q2, [x2, #3440]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4464]
	ldr	q2, [x2, #4464]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #368]
	ldr	q1, [x1, #384]
	ldr	q2, [x2, #384]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1408]
	ldr	q2, [x2, #1408]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2432]
	ldr	q2, [x2, #2432]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3456]
	ldr	q2, [x2, #3456]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4480]
	ldr	q2, [x2, #4480]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #384]
	ldr	q1, [x1, #400]
	ldr	q2, [x2, #400]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1424]
	ldr	q2, [x2, #1424]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2448]
	ldr	q2, [x2, #2448]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3472]
	ldr	q2, [x2, #3472]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4496]
	ldr	q2, [x2, #4496]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #400]
	ldr	q1, [x1, #416]
	ldr	q2, [x2, #416]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1440]
	ldr	q2, [x2, #1440]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2464]
	ldr	q2, [x2, #2464]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3488]
	ldr	q2, [x2, #3488]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4512]
	ldr	q2, [x2, #4512]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #416]
	ldr	q1, [x1, #432]
	ldr	q2, [x2, #432]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1456]
	ldr	q2, [x2, #1456]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2480]
	ldr	q2, [x2, #2480]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3504]
	ldr	q2, [x2, #3504]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4528]
	ldr	q2, [x2, #4528]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #432]
	ldr	q1, [x1, #448]
	ldr	q2, [x2, #448]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1472]
	ldr	q2, [x2, #1472]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2496]
	ldr	q2, [x2, #2496]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3520]
	ldr	q2, [x2, #3520]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4544]
	ldr	q2, [x2, #4544]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #448]
	ldr	q1, [x1, #464]
	ldr	q2, [x2, #464]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1488]
	ldr	q2, [x2, #1488]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2512]
	ldr	q2, [x2, #2512]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3536]
	ldr	q2, [x2, #3536]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4560]
	ldr	q2, [x2, #4560]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #464]
	ldr	q1, [x1, #480]
	ldr	q2, [x2, #480]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1504]
	ldr	q2, [x2, #1504]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2528]
	ldr	q2, [x2, #2528]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3552]
	ldr	q2, [x2, #3552]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4576]
	ldr	q2, [x2, #4576]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #480]
	ldr	q1, [x1, #496]
	ldr	q2, [x2, #496]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1520]
	ldr	q2, [x2, #1520]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2544]
	ldr	q2, [x2, #2544]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3568]
	ldr	q2, [x2, #3568]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4592]
	ldr	q2, [x2, #4592]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #496]
	ldr	q1, [x1, #512]
	ldr	q2, [x2, #512]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1536]
	ldr	q2, [x2, #1536]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2560]
	ldr	q2, [x2, #2560]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3584]
	ldr	q2, [x2, #3584]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4608]
	ldr	q2, [x2, #4608]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #512]
	ldr	q1, [x1, #528]
	ldr	q2, [x2, #528]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1552]
	ldr	q2, [x2, #1552]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2576]
	ldr	q2, [x2, #2576]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3600]
	ldr	q2, [x2, #3600]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4624]
	ldr	q2, [x2, #4624]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #528]
	ldr	q1, [x1, #544]
	ldr	q2, [x2, #544]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1568]
	ldr	q2, [x2, #1568]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2592]
	ldr	q2, [x2, #2592]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3616]
	ldr	q2, [x2, #3616]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4640]
	ldr	q2, [x2, #4640]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #544]
	ldr	q1, [x1, #560]
	ldr	q2, [x2, #560]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1584]
	ldr	q2, [x2, #1584]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2608]
	ldr	q2, [x2, #2608]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3632]
	ldr	q2, [x2, #3632]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4656]
	ldr	q2, [x2, #4656]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #560]
	ldr	q1, [x1, #576]
	ldr	q2, [x2, #576]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1600]
	ldr	q2, [x2, #1600]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2624]
	ldr	q2, [x2, #2624]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3648]
	ldr	q2, [x2, #3648]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4672]
	ldr	q2, [x2, #4672]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #576]
	ldr	q1, [x1, #592]
	ldr	q2, [x2, #592]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1616]
	ldr	q2, [x2, #1616]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2640]
	ldr	q2, [x2, #2640]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3664]
	ldr	q2, [x2, #3664]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4688]
	ldr	q2, [x2, #4688]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #592]
	ldr	q1, [x1, #608]
	ldr	q2, [x2, #608]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1632]
	ldr	q2, [x2, #1632]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2656]
	ldr	q2, [x2, #2656]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3680]
	ldr	q2, [x2, #3680]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4704]
	ldr	q2, [x2, #4704]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #608]
	ldr	q1, [x1, #624]
	ldr	q2, [x2, #624]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1648]
	ldr	q2, [x2, #1648]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2672]
	ldr	q2, [x2, #2672]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3696]
	ldr	q2, [x2, #3696]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4720]
	ldr	q2, [x2, #4720]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #624]
	ldr	q1, [x1, #640]
	ldr	q2, [x2, #640]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1664]
	ldr	q2, [x2, #1664]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2688]
	ldr	q2, [x2, #2688]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3712]
	ldr	q2, [x2, #3712]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4736]
	ldr	q2, [x2, #4736]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #640]
	ldr	q1, [x1, #656]
	ldr	q2, [x2, #656]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1680]
	ldr	q2, [x2, #1680]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2704]
	ldr	q2, [x2, #2704]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3728]
	ldr	q2, [x2, #3728]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4752]
	ldr	q2, [x2, #4752]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #656]
	ldr	q1, [x1, #672]
	ldr	q2, [x2, #672]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1696]
	ldr	q2, [x2, #1696]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2720]
	ldr	q2, [x2, #2720]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3744]
	ldr	q2, [x2, #3744]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4768]
	ldr	q2, [x2, #4768]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #672]
	ldr	q1, [x1, #688]
	ldr	q2, [x2, #688]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1712]
	ldr	q2, [x2, #1712]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2736]
	ldr	q2, [x2, #2736]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3760]
	ldr	q2, [x2, #3760]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4784]
	ldr	q2, [x2, #4784]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #688]
	ldr	q1, [x1, #704]
	ldr	q2, [x2, #704]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1728]
	ldr	q2, [x2, #1728]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2752]
	ldr	q2, [x2, #2752]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3776]
	ldr	q2, [x2, #3776]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4800]
	ldr	q2, [x2, #4800]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #704]
	ldr	q1, [x1, #720]
	ldr	q2, [x2, #720]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1744]
	ldr	q2, [x2, #1744]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2768]
	ldr	q2, [x2, #2768]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3792]
	ldr	q2, [x2, #3792]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4816]
	ldr	q2, [x2, #4816]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #720]
	ldr	q1, [x1, #736]
	ldr	q2, [x2, #736]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1760]
	ldr	q2, [x2, #1760]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2784]
	ldr	q2, [x2, #2784]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3808]
	ldr	q2, [x2, #3808]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4832]
	ldr	q2, [x2, #4832]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #736]
	ldr	q1, [x1, #752]
	ldr	q2, [x2, #752]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1776]
	ldr	q2, [x2, #1776]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2800]
	ldr	q2, [x2, #2800]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3824]
	ldr	q2, [x2, #3824]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4848]
	ldr	q2, [x2, #4848]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #752]
	ldr	q1, [x1, #768]
	ldr	q2, [x2, #768]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1792]
	ldr	q2, [x2, #1792]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2816]
	ldr	q2, [x2, #2816]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3840]
	ldr	q2, [x2, #3840]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4864]
	ldr	q2, [x2, #4864]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #768]
	ldr	q1, [x1, #784]
	ldr	q2, [x2, #784]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1808]
	ldr	q2, [x2, #1808]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2832]
	ldr	q2, [x2, #2832]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3856]
	ldr	q2, [x2, #3856]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4880]
	ldr	q2, [x2, #4880]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #784]
	ldr	q1, [x1, #800]
	ldr	q2, [x2, #800]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1824]
	ldr	q2, [x2, #1824]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2848]
	ldr	q2, [x2, #2848]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3872]
	ldr	q2, [x2, #3872]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4896]
	ldr	q2, [x2, #4896]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #800]
	ldr	q1, [x1, #816]
	ldr	q2, [x2, #816]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1840]
	ldr	q2, [x2, #1840]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2864]
	ldr	q2, [x2, #2864]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3888]
	ldr	q2, [x2, #3888]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4912]
	ldr	q2, [x2, #4912]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #816]
	ldr	q1, [x1, #832]
	ldr	q2, [x2, #832]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1856]
	ldr	q2, [x2, #1856]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2880]
	ldr	q2, [x2, #2880]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3904]
	ldr	q2, [x2, #3904]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4928]
	ldr	q2, [x2, #4928]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #832]
	ldr	q1, [x1, #848]
	ldr	q2, [x2, #848]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1872]
	ldr	q2, [x2, #1872]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2896]
	ldr	q2, [x2, #2896]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3920]
	ldr	q2, [x2, #3920]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4944]
	ldr	q2, [x2, #4944]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #848]
	ldr	q1, [x1, #864]
	ldr	q2, [x2, #864]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1888]
	ldr	q2, [x2, #1888]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2912]
	ldr	q2, [x2, #2912]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3936]
	ldr	q2, [x2, #3936]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4960]
	ldr	q2, [x2, #4960]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #864]
	ldr	q1, [x1, #880]
	ldr	q2, [x2, #880]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1904]
	ldr	q2, [x2, #1904]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2928]
	ldr	q2, [x2, #2928]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3952]
	ldr	q2, [x2, #3952]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4976]
	ldr	q2, [x2, #4976]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #880]
	ldr	q1, [x1, #896]
	ldr	q2, [x2, #896]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1920]
	ldr	q2, [x2, #1920]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2944]
	ldr	q2, [x2, #2944]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3968]
	ldr	q2, [x2, #3968]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4992]
	ldr	q2, [x2, #4992]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #896]
	ldr	q1, [x1, #912]
	ldr	q2, [x2, #912]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1936]
	ldr	q2, [x2, #1936]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2960]
	ldr	q2, [x2, #2960]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3984]
	ldr	q2, [x2, #3984]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5008]
	ldr	q2, [x2, #5008]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #912]
	ldr	q1, [x1, #928]
	ldr	q2, [x2, #928]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1952]
	ldr	q2, [x2, #1952]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2976]
	ldr	q2, [x2, #2976]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4000]
	ldr	q2, [x2, #4000]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5024]
	ldr	q2, [x2, #5024]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #928]
	ldr	q1, [x1, #944]
	ldr	q2, [x2, #944]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1968]
	ldr	q2, [x2, #1968]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2992]
	ldr	q2, [x2, #2992]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4016]
	ldr	q2, [x2, #4016]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5040]
	ldr	q2, [x2, #5040]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #944]
	ldr	q1, [x1, #960]
	ldr	q2, [x2, #960]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1984]
	ldr	q2, [x2, #1984]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3008]
	ldr	q2, [x2, #3008]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4032]
	ldr	q2, [x2, #4032]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5056]
	ldr	q2, [x2, #5056]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #960]
	ldr	q1, [x1, #976]
	ldr	q2, [x2, #976]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2000]
	ldr	q2, [x2, #2000]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3024]
	ldr	q2, [x2, #3024]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4048]
	ldr	q2, [x2, #4048]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5072]
	ldr	q2, [x2, #5072]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #976]
	ldr	q1, [x1, #992]
	ldr	q2, [x2, #992]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2016]
	ldr	q2, [x2, #2016]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3040]
	ldr	q2, [x2, #3040]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4064]
	ldr	q2, [x2, #4064]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5088]
	ldr	q2, [x2, #5088]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #992]
	ldr	q1, [x1, #1008]
	ldr	q2, [x2, #1008]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2032]
	ldr	q2, [x2, #2032]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3056]
	ldr	q2, [x2, #3056]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4080]
	ldr	q2, [x2, #4080]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5104]
	ldr	q2, [x2, #5104]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #1008]
	ret
#ifndef __APPLE__
	.size	mldsa_mul_vec_5_neon,.-mldsa_mul_vec_5_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	mldsa_mul_vec_7_neon
WC_ASM_ATT_HIDDEN(mldsa_mul_vec_7_neon)
.type	mldsa_mul_vec_7_neon,@function
.align	2
mldsa_mul_vec_7_neon:
#else
.section	__TEXT,__text
.globl	_mldsa_mul_vec_7_neon
WC_ASM_ATT_HIDDEN(_mldsa_mul_vec_7_neon)
.p2align	2
_mldsa_mul_vec_7_neon:
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x3, L_mldsa_aarch64_consts
	add  x3, x3, :lo12:L_mldsa_aarch64_consts
#else
	adrp x3, L_mldsa_aarch64_consts@PAGE
	add  x3, x3, L_mldsa_aarch64_consts@PAGEOFF
#endif /* __APPLE__ */
	ldr	q0, [x3]
	ldr	q1, [x1]
	ldr	q2, [x2]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1024]
	ldr	q2, [x2, #1024]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2048]
	ldr	q2, [x2, #2048]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3072]
	ldr	q2, [x2, #3072]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4096]
	ldr	q2, [x2, #4096]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5120]
	ldr	q2, [x2, #5120]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6144]
	ldr	q2, [x2, #6144]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0]
	ldr	q1, [x1, #16]
	ldr	q2, [x2, #16]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1040]
	ldr	q2, [x2, #1040]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2064]
	ldr	q2, [x2, #2064]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3088]
	ldr	q2, [x2, #3088]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4112]
	ldr	q2, [x2, #4112]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5136]
	ldr	q2, [x2, #5136]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6160]
	ldr	q2, [x2, #6160]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #16]
	ldr	q1, [x1, #32]
	ldr	q2, [x2, #32]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1056]
	ldr	q2, [x2, #1056]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2080]
	ldr	q2, [x2, #2080]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3104]
	ldr	q2, [x2, #3104]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4128]
	ldr	q2, [x2, #4128]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5152]
	ldr	q2, [x2, #5152]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6176]
	ldr	q2, [x2, #6176]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #32]
	ldr	q1, [x1, #48]
	ldr	q2, [x2, #48]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1072]
	ldr	q2, [x2, #1072]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2096]
	ldr	q2, [x2, #2096]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3120]
	ldr	q2, [x2, #3120]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4144]
	ldr	q2, [x2, #4144]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5168]
	ldr	q2, [x2, #5168]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6192]
	ldr	q2, [x2, #6192]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #48]
	ldr	q1, [x1, #64]
	ldr	q2, [x2, #64]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1088]
	ldr	q2, [x2, #1088]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2112]
	ldr	q2, [x2, #2112]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3136]
	ldr	q2, [x2, #3136]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4160]
	ldr	q2, [x2, #4160]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5184]
	ldr	q2, [x2, #5184]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6208]
	ldr	q2, [x2, #6208]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #64]
	ldr	q1, [x1, #80]
	ldr	q2, [x2, #80]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1104]
	ldr	q2, [x2, #1104]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2128]
	ldr	q2, [x2, #2128]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3152]
	ldr	q2, [x2, #3152]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4176]
	ldr	q2, [x2, #4176]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5200]
	ldr	q2, [x2, #5200]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6224]
	ldr	q2, [x2, #6224]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #80]
	ldr	q1, [x1, #96]
	ldr	q2, [x2, #96]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1120]
	ldr	q2, [x2, #1120]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2144]
	ldr	q2, [x2, #2144]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3168]
	ldr	q2, [x2, #3168]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4192]
	ldr	q2, [x2, #4192]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5216]
	ldr	q2, [x2, #5216]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6240]
	ldr	q2, [x2, #6240]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #96]
	ldr	q1, [x1, #112]
	ldr	q2, [x2, #112]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1136]
	ldr	q2, [x2, #1136]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2160]
	ldr	q2, [x2, #2160]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3184]
	ldr	q2, [x2, #3184]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4208]
	ldr	q2, [x2, #4208]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5232]
	ldr	q2, [x2, #5232]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6256]
	ldr	q2, [x2, #6256]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #112]
	ldr	q1, [x1, #128]
	ldr	q2, [x2, #128]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1152]
	ldr	q2, [x2, #1152]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2176]
	ldr	q2, [x2, #2176]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3200]
	ldr	q2, [x2, #3200]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4224]
	ldr	q2, [x2, #4224]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5248]
	ldr	q2, [x2, #5248]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6272]
	ldr	q2, [x2, #6272]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #128]
	ldr	q1, [x1, #144]
	ldr	q2, [x2, #144]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1168]
	ldr	q2, [x2, #1168]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2192]
	ldr	q2, [x2, #2192]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3216]
	ldr	q2, [x2, #3216]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4240]
	ldr	q2, [x2, #4240]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5264]
	ldr	q2, [x2, #5264]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6288]
	ldr	q2, [x2, #6288]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #144]
	ldr	q1, [x1, #160]
	ldr	q2, [x2, #160]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1184]
	ldr	q2, [x2, #1184]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2208]
	ldr	q2, [x2, #2208]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3232]
	ldr	q2, [x2, #3232]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4256]
	ldr	q2, [x2, #4256]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5280]
	ldr	q2, [x2, #5280]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6304]
	ldr	q2, [x2, #6304]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #160]
	ldr	q1, [x1, #176]
	ldr	q2, [x2, #176]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1200]
	ldr	q2, [x2, #1200]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2224]
	ldr	q2, [x2, #2224]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3248]
	ldr	q2, [x2, #3248]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4272]
	ldr	q2, [x2, #4272]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5296]
	ldr	q2, [x2, #5296]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6320]
	ldr	q2, [x2, #6320]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #176]
	ldr	q1, [x1, #192]
	ldr	q2, [x2, #192]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1216]
	ldr	q2, [x2, #1216]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2240]
	ldr	q2, [x2, #2240]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3264]
	ldr	q2, [x2, #3264]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4288]
	ldr	q2, [x2, #4288]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5312]
	ldr	q2, [x2, #5312]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6336]
	ldr	q2, [x2, #6336]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #192]
	ldr	q1, [x1, #208]
	ldr	q2, [x2, #208]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1232]
	ldr	q2, [x2, #1232]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2256]
	ldr	q2, [x2, #2256]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3280]
	ldr	q2, [x2, #3280]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4304]
	ldr	q2, [x2, #4304]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5328]
	ldr	q2, [x2, #5328]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6352]
	ldr	q2, [x2, #6352]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #208]
	ldr	q1, [x1, #224]
	ldr	q2, [x2, #224]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1248]
	ldr	q2, [x2, #1248]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2272]
	ldr	q2, [x2, #2272]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3296]
	ldr	q2, [x2, #3296]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4320]
	ldr	q2, [x2, #4320]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5344]
	ldr	q2, [x2, #5344]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6368]
	ldr	q2, [x2, #6368]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #224]
	ldr	q1, [x1, #240]
	ldr	q2, [x2, #240]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1264]
	ldr	q2, [x2, #1264]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2288]
	ldr	q2, [x2, #2288]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3312]
	ldr	q2, [x2, #3312]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4336]
	ldr	q2, [x2, #4336]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5360]
	ldr	q2, [x2, #5360]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6384]
	ldr	q2, [x2, #6384]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #240]
	ldr	q1, [x1, #256]
	ldr	q2, [x2, #256]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1280]
	ldr	q2, [x2, #1280]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2304]
	ldr	q2, [x2, #2304]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3328]
	ldr	q2, [x2, #3328]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4352]
	ldr	q2, [x2, #4352]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5376]
	ldr	q2, [x2, #5376]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6400]
	ldr	q2, [x2, #6400]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #256]
	ldr	q1, [x1, #272]
	ldr	q2, [x2, #272]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1296]
	ldr	q2, [x2, #1296]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2320]
	ldr	q2, [x2, #2320]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3344]
	ldr	q2, [x2, #3344]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4368]
	ldr	q2, [x2, #4368]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5392]
	ldr	q2, [x2, #5392]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6416]
	ldr	q2, [x2, #6416]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #272]
	ldr	q1, [x1, #288]
	ldr	q2, [x2, #288]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1312]
	ldr	q2, [x2, #1312]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2336]
	ldr	q2, [x2, #2336]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3360]
	ldr	q2, [x2, #3360]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4384]
	ldr	q2, [x2, #4384]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5408]
	ldr	q2, [x2, #5408]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6432]
	ldr	q2, [x2, #6432]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #288]
	ldr	q1, [x1, #304]
	ldr	q2, [x2, #304]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1328]
	ldr	q2, [x2, #1328]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2352]
	ldr	q2, [x2, #2352]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3376]
	ldr	q2, [x2, #3376]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4400]
	ldr	q2, [x2, #4400]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5424]
	ldr	q2, [x2, #5424]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6448]
	ldr	q2, [x2, #6448]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #304]
	ldr	q1, [x1, #320]
	ldr	q2, [x2, #320]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1344]
	ldr	q2, [x2, #1344]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2368]
	ldr	q2, [x2, #2368]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3392]
	ldr	q2, [x2, #3392]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4416]
	ldr	q2, [x2, #4416]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5440]
	ldr	q2, [x2, #5440]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6464]
	ldr	q2, [x2, #6464]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #320]
	ldr	q1, [x1, #336]
	ldr	q2, [x2, #336]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1360]
	ldr	q2, [x2, #1360]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2384]
	ldr	q2, [x2, #2384]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3408]
	ldr	q2, [x2, #3408]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4432]
	ldr	q2, [x2, #4432]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5456]
	ldr	q2, [x2, #5456]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6480]
	ldr	q2, [x2, #6480]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #336]
	ldr	q1, [x1, #352]
	ldr	q2, [x2, #352]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1376]
	ldr	q2, [x2, #1376]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2400]
	ldr	q2, [x2, #2400]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3424]
	ldr	q2, [x2, #3424]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4448]
	ldr	q2, [x2, #4448]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5472]
	ldr	q2, [x2, #5472]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6496]
	ldr	q2, [x2, #6496]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #352]
	ldr	q1, [x1, #368]
	ldr	q2, [x2, #368]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1392]
	ldr	q2, [x2, #1392]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2416]
	ldr	q2, [x2, #2416]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3440]
	ldr	q2, [x2, #3440]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4464]
	ldr	q2, [x2, #4464]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5488]
	ldr	q2, [x2, #5488]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6512]
	ldr	q2, [x2, #6512]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #368]
	ldr	q1, [x1, #384]
	ldr	q2, [x2, #384]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1408]
	ldr	q2, [x2, #1408]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2432]
	ldr	q2, [x2, #2432]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3456]
	ldr	q2, [x2, #3456]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4480]
	ldr	q2, [x2, #4480]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5504]
	ldr	q2, [x2, #5504]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6528]
	ldr	q2, [x2, #6528]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #384]
	ldr	q1, [x1, #400]
	ldr	q2, [x2, #400]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1424]
	ldr	q2, [x2, #1424]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2448]
	ldr	q2, [x2, #2448]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3472]
	ldr	q2, [x2, #3472]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4496]
	ldr	q2, [x2, #4496]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5520]
	ldr	q2, [x2, #5520]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6544]
	ldr	q2, [x2, #6544]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #400]
	ldr	q1, [x1, #416]
	ldr	q2, [x2, #416]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1440]
	ldr	q2, [x2, #1440]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2464]
	ldr	q2, [x2, #2464]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3488]
	ldr	q2, [x2, #3488]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4512]
	ldr	q2, [x2, #4512]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5536]
	ldr	q2, [x2, #5536]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6560]
	ldr	q2, [x2, #6560]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #416]
	ldr	q1, [x1, #432]
	ldr	q2, [x2, #432]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1456]
	ldr	q2, [x2, #1456]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2480]
	ldr	q2, [x2, #2480]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3504]
	ldr	q2, [x2, #3504]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4528]
	ldr	q2, [x2, #4528]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5552]
	ldr	q2, [x2, #5552]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6576]
	ldr	q2, [x2, #6576]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #432]
	ldr	q1, [x1, #448]
	ldr	q2, [x2, #448]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1472]
	ldr	q2, [x2, #1472]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2496]
	ldr	q2, [x2, #2496]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3520]
	ldr	q2, [x2, #3520]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4544]
	ldr	q2, [x2, #4544]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5568]
	ldr	q2, [x2, #5568]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6592]
	ldr	q2, [x2, #6592]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #448]
	ldr	q1, [x1, #464]
	ldr	q2, [x2, #464]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1488]
	ldr	q2, [x2, #1488]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2512]
	ldr	q2, [x2, #2512]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3536]
	ldr	q2, [x2, #3536]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4560]
	ldr	q2, [x2, #4560]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5584]
	ldr	q2, [x2, #5584]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6608]
	ldr	q2, [x2, #6608]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #464]
	ldr	q1, [x1, #480]
	ldr	q2, [x2, #480]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1504]
	ldr	q2, [x2, #1504]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2528]
	ldr	q2, [x2, #2528]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3552]
	ldr	q2, [x2, #3552]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4576]
	ldr	q2, [x2, #4576]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5600]
	ldr	q2, [x2, #5600]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6624]
	ldr	q2, [x2, #6624]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #480]
	ldr	q1, [x1, #496]
	ldr	q2, [x2, #496]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1520]
	ldr	q2, [x2, #1520]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2544]
	ldr	q2, [x2, #2544]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3568]
	ldr	q2, [x2, #3568]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4592]
	ldr	q2, [x2, #4592]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5616]
	ldr	q2, [x2, #5616]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6640]
	ldr	q2, [x2, #6640]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #496]
	ldr	q1, [x1, #512]
	ldr	q2, [x2, #512]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1536]
	ldr	q2, [x2, #1536]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2560]
	ldr	q2, [x2, #2560]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3584]
	ldr	q2, [x2, #3584]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4608]
	ldr	q2, [x2, #4608]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5632]
	ldr	q2, [x2, #5632]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6656]
	ldr	q2, [x2, #6656]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #512]
	ldr	q1, [x1, #528]
	ldr	q2, [x2, #528]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1552]
	ldr	q2, [x2, #1552]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2576]
	ldr	q2, [x2, #2576]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3600]
	ldr	q2, [x2, #3600]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4624]
	ldr	q2, [x2, #4624]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5648]
	ldr	q2, [x2, #5648]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6672]
	ldr	q2, [x2, #6672]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #528]
	ldr	q1, [x1, #544]
	ldr	q2, [x2, #544]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1568]
	ldr	q2, [x2, #1568]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2592]
	ldr	q2, [x2, #2592]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3616]
	ldr	q2, [x2, #3616]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4640]
	ldr	q2, [x2, #4640]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5664]
	ldr	q2, [x2, #5664]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6688]
	ldr	q2, [x2, #6688]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #544]
	ldr	q1, [x1, #560]
	ldr	q2, [x2, #560]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1584]
	ldr	q2, [x2, #1584]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2608]
	ldr	q2, [x2, #2608]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3632]
	ldr	q2, [x2, #3632]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4656]
	ldr	q2, [x2, #4656]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5680]
	ldr	q2, [x2, #5680]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6704]
	ldr	q2, [x2, #6704]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #560]
	ldr	q1, [x1, #576]
	ldr	q2, [x2, #576]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1600]
	ldr	q2, [x2, #1600]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2624]
	ldr	q2, [x2, #2624]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3648]
	ldr	q2, [x2, #3648]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4672]
	ldr	q2, [x2, #4672]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5696]
	ldr	q2, [x2, #5696]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6720]
	ldr	q2, [x2, #6720]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #576]
	ldr	q1, [x1, #592]
	ldr	q2, [x2, #592]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1616]
	ldr	q2, [x2, #1616]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2640]
	ldr	q2, [x2, #2640]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3664]
	ldr	q2, [x2, #3664]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4688]
	ldr	q2, [x2, #4688]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5712]
	ldr	q2, [x2, #5712]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6736]
	ldr	q2, [x2, #6736]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #592]
	ldr	q1, [x1, #608]
	ldr	q2, [x2, #608]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1632]
	ldr	q2, [x2, #1632]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2656]
	ldr	q2, [x2, #2656]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3680]
	ldr	q2, [x2, #3680]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4704]
	ldr	q2, [x2, #4704]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5728]
	ldr	q2, [x2, #5728]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6752]
	ldr	q2, [x2, #6752]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #608]
	ldr	q1, [x1, #624]
	ldr	q2, [x2, #624]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1648]
	ldr	q2, [x2, #1648]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2672]
	ldr	q2, [x2, #2672]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3696]
	ldr	q2, [x2, #3696]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4720]
	ldr	q2, [x2, #4720]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5744]
	ldr	q2, [x2, #5744]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6768]
	ldr	q2, [x2, #6768]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #624]
	ldr	q1, [x1, #640]
	ldr	q2, [x2, #640]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1664]
	ldr	q2, [x2, #1664]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2688]
	ldr	q2, [x2, #2688]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3712]
	ldr	q2, [x2, #3712]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4736]
	ldr	q2, [x2, #4736]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5760]
	ldr	q2, [x2, #5760]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6784]
	ldr	q2, [x2, #6784]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #640]
	ldr	q1, [x1, #656]
	ldr	q2, [x2, #656]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1680]
	ldr	q2, [x2, #1680]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2704]
	ldr	q2, [x2, #2704]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3728]
	ldr	q2, [x2, #3728]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4752]
	ldr	q2, [x2, #4752]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5776]
	ldr	q2, [x2, #5776]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6800]
	ldr	q2, [x2, #6800]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #656]
	ldr	q1, [x1, #672]
	ldr	q2, [x2, #672]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1696]
	ldr	q2, [x2, #1696]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2720]
	ldr	q2, [x2, #2720]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3744]
	ldr	q2, [x2, #3744]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4768]
	ldr	q2, [x2, #4768]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5792]
	ldr	q2, [x2, #5792]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6816]
	ldr	q2, [x2, #6816]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #672]
	ldr	q1, [x1, #688]
	ldr	q2, [x2, #688]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1712]
	ldr	q2, [x2, #1712]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2736]
	ldr	q2, [x2, #2736]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3760]
	ldr	q2, [x2, #3760]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4784]
	ldr	q2, [x2, #4784]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5808]
	ldr	q2, [x2, #5808]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6832]
	ldr	q2, [x2, #6832]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #688]
	ldr	q1, [x1, #704]
	ldr	q2, [x2, #704]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1728]
	ldr	q2, [x2, #1728]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2752]
	ldr	q2, [x2, #2752]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3776]
	ldr	q2, [x2, #3776]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4800]
	ldr	q2, [x2, #4800]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5824]
	ldr	q2, [x2, #5824]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6848]
	ldr	q2, [x2, #6848]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #704]
	ldr	q1, [x1, #720]
	ldr	q2, [x2, #720]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1744]
	ldr	q2, [x2, #1744]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2768]
	ldr	q2, [x2, #2768]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3792]
	ldr	q2, [x2, #3792]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4816]
	ldr	q2, [x2, #4816]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5840]
	ldr	q2, [x2, #5840]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6864]
	ldr	q2, [x2, #6864]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #720]
	ldr	q1, [x1, #736]
	ldr	q2, [x2, #736]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1760]
	ldr	q2, [x2, #1760]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2784]
	ldr	q2, [x2, #2784]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3808]
	ldr	q2, [x2, #3808]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4832]
	ldr	q2, [x2, #4832]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5856]
	ldr	q2, [x2, #5856]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6880]
	ldr	q2, [x2, #6880]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #736]
	ldr	q1, [x1, #752]
	ldr	q2, [x2, #752]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1776]
	ldr	q2, [x2, #1776]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2800]
	ldr	q2, [x2, #2800]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3824]
	ldr	q2, [x2, #3824]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4848]
	ldr	q2, [x2, #4848]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5872]
	ldr	q2, [x2, #5872]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6896]
	ldr	q2, [x2, #6896]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #752]
	ldr	q1, [x1, #768]
	ldr	q2, [x2, #768]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1792]
	ldr	q2, [x2, #1792]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2816]
	ldr	q2, [x2, #2816]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3840]
	ldr	q2, [x2, #3840]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4864]
	ldr	q2, [x2, #4864]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5888]
	ldr	q2, [x2, #5888]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6912]
	ldr	q2, [x2, #6912]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #768]
	ldr	q1, [x1, #784]
	ldr	q2, [x2, #784]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1808]
	ldr	q2, [x2, #1808]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2832]
	ldr	q2, [x2, #2832]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3856]
	ldr	q2, [x2, #3856]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4880]
	ldr	q2, [x2, #4880]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5904]
	ldr	q2, [x2, #5904]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6928]
	ldr	q2, [x2, #6928]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #784]
	ldr	q1, [x1, #800]
	ldr	q2, [x2, #800]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1824]
	ldr	q2, [x2, #1824]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2848]
	ldr	q2, [x2, #2848]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3872]
	ldr	q2, [x2, #3872]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4896]
	ldr	q2, [x2, #4896]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5920]
	ldr	q2, [x2, #5920]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6944]
	ldr	q2, [x2, #6944]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #800]
	ldr	q1, [x1, #816]
	ldr	q2, [x2, #816]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1840]
	ldr	q2, [x2, #1840]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2864]
	ldr	q2, [x2, #2864]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3888]
	ldr	q2, [x2, #3888]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4912]
	ldr	q2, [x2, #4912]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5936]
	ldr	q2, [x2, #5936]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6960]
	ldr	q2, [x2, #6960]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #816]
	ldr	q1, [x1, #832]
	ldr	q2, [x2, #832]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1856]
	ldr	q2, [x2, #1856]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2880]
	ldr	q2, [x2, #2880]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3904]
	ldr	q2, [x2, #3904]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4928]
	ldr	q2, [x2, #4928]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5952]
	ldr	q2, [x2, #5952]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6976]
	ldr	q2, [x2, #6976]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #832]
	ldr	q1, [x1, #848]
	ldr	q2, [x2, #848]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1872]
	ldr	q2, [x2, #1872]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2896]
	ldr	q2, [x2, #2896]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3920]
	ldr	q2, [x2, #3920]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4944]
	ldr	q2, [x2, #4944]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5968]
	ldr	q2, [x2, #5968]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6992]
	ldr	q2, [x2, #6992]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #848]
	ldr	q1, [x1, #864]
	ldr	q2, [x2, #864]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1888]
	ldr	q2, [x2, #1888]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2912]
	ldr	q2, [x2, #2912]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3936]
	ldr	q2, [x2, #3936]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4960]
	ldr	q2, [x2, #4960]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5984]
	ldr	q2, [x2, #5984]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #7008]
	ldr	q2, [x2, #7008]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #864]
	ldr	q1, [x1, #880]
	ldr	q2, [x2, #880]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1904]
	ldr	q2, [x2, #1904]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2928]
	ldr	q2, [x2, #2928]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3952]
	ldr	q2, [x2, #3952]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4976]
	ldr	q2, [x2, #4976]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6000]
	ldr	q2, [x2, #6000]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #7024]
	ldr	q2, [x2, #7024]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #880]
	ldr	q1, [x1, #896]
	ldr	q2, [x2, #896]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1920]
	ldr	q2, [x2, #1920]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2944]
	ldr	q2, [x2, #2944]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3968]
	ldr	q2, [x2, #3968]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4992]
	ldr	q2, [x2, #4992]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6016]
	ldr	q2, [x2, #6016]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #7040]
	ldr	q2, [x2, #7040]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #896]
	ldr	q1, [x1, #912]
	ldr	q2, [x2, #912]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1936]
	ldr	q2, [x2, #1936]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2960]
	ldr	q2, [x2, #2960]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3984]
	ldr	q2, [x2, #3984]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5008]
	ldr	q2, [x2, #5008]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6032]
	ldr	q2, [x2, #6032]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #7056]
	ldr	q2, [x2, #7056]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #912]
	ldr	q1, [x1, #928]
	ldr	q2, [x2, #928]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1952]
	ldr	q2, [x2, #1952]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2976]
	ldr	q2, [x2, #2976]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4000]
	ldr	q2, [x2, #4000]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5024]
	ldr	q2, [x2, #5024]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6048]
	ldr	q2, [x2, #6048]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #7072]
	ldr	q2, [x2, #7072]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #928]
	ldr	q1, [x1, #944]
	ldr	q2, [x2, #944]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1968]
	ldr	q2, [x2, #1968]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2992]
	ldr	q2, [x2, #2992]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4016]
	ldr	q2, [x2, #4016]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5040]
	ldr	q2, [x2, #5040]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6064]
	ldr	q2, [x2, #6064]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #7088]
	ldr	q2, [x2, #7088]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #944]
	ldr	q1, [x1, #960]
	ldr	q2, [x2, #960]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #1984]
	ldr	q2, [x2, #1984]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3008]
	ldr	q2, [x2, #3008]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4032]
	ldr	q2, [x2, #4032]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5056]
	ldr	q2, [x2, #5056]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6080]
	ldr	q2, [x2, #6080]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #7104]
	ldr	q2, [x2, #7104]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #960]
	ldr	q1, [x1, #976]
	ldr	q2, [x2, #976]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2000]
	ldr	q2, [x2, #2000]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3024]
	ldr	q2, [x2, #3024]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4048]
	ldr	q2, [x2, #4048]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5072]
	ldr	q2, [x2, #5072]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6096]
	ldr	q2, [x2, #6096]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #7120]
	ldr	q2, [x2, #7120]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #976]
	ldr	q1, [x1, #992]
	ldr	q2, [x2, #992]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2016]
	ldr	q2, [x2, #2016]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3040]
	ldr	q2, [x2, #3040]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4064]
	ldr	q2, [x2, #4064]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5088]
	ldr	q2, [x2, #5088]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6112]
	ldr	q2, [x2, #6112]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #7136]
	ldr	q2, [x2, #7136]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #992]
	ldr	q1, [x1, #1008]
	ldr	q2, [x2, #1008]
	smull	v3.2d, v1.2s, v2.2s
	smull2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #2032]
	ldr	q2, [x2, #2032]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #3056]
	ldr	q2, [x2, #3056]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #4080]
	ldr	q2, [x2, #4080]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #5104]
	ldr	q2, [x2, #5104]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #6128]
	ldr	q2, [x2, #6128]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	ldr	q1, [x1, #7152]
	ldr	q2, [x2, #7152]
	smlal	v3.2d, v1.2s, v2.2s
	smlal2	v4.2d, v1.4s, v2.4s
	uzp1	v5.4s, v3.4s, v4.4s
	mul	v5.4s, v5.4s, v0.s[1]
	smull	v6.2d, v5.2s, v0.s[0]
	smull2	v7.2d, v5.4s, v0.s[0]
	sub	v3.2d, v3.2d, v6.2d
	sub	v4.2d, v4.2d, v7.2d
	uzp2	v5.4s, v3.4s, v4.4s
	str	q5, [x0, #1008]
	ret
#ifndef __APPLE__
	.size	mldsa_mul_vec_7_neon,.-mldsa_mul_vec_7_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mldsa_aarch64_q, %object
	.size	L_mldsa_aarch64_q, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_aarch64_q:
	.long	0x007fe001,0x007fe001,0x007fe001,0x007fe001
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mldsa_decode_eta_2_neon_idx, %object
	.size	L_mldsa_decode_eta_2_neon_idx, 192
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
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
	.section	.rodata
	.type	L_mldsa_decode_eta_2_neon_shift, %object
	.size	L_mldsa_decode_eta_2_neon_shift, 32
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_decode_eta_2_neon_shift:
	.long	0x00000000,0xfffffffd,0xfffffffa,0xffffffff
	.long	0xfffffffc,0xfffffff9,0xfffffffe,0xfffffffb
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mldsa_decode_eta_2_neon_mask, %object
	.size	L_mldsa_decode_eta_2_neon_mask, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_decode_eta_2_neon_mask:
	.long	0x00000007,0x00000007,0x00000007,0x00000007
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mldsa_decode_eta_2_neon_konst, %object
	.size	L_mldsa_decode_eta_2_neon_konst, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_decode_eta_2_neon_konst:
	.long	0x00000002,0x00000002,0x00000002,0x00000002
#ifndef __APPLE__
.text
.globl	mldsa_decode_eta_2_neon
WC_ASM_ATT_HIDDEN(mldsa_decode_eta_2_neon)
.type	mldsa_decode_eta_2_neon,@function
.align	2
mldsa_decode_eta_2_neon:
#else
.section	__TEXT,__text
.globl	_mldsa_decode_eta_2_neon
WC_ASM_ATT_HIDDEN(_mldsa_decode_eta_2_neon)
.p2align	2
_mldsa_decode_eta_2_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-32]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
#ifndef __APPLE__
	adrp x2, L_mldsa_decode_eta_2_neon_idx
	add  x2, x2, :lo12:L_mldsa_decode_eta_2_neon_idx
#else
	adrp x2, L_mldsa_decode_eta_2_neon_idx@PAGE
	add  x2, x2, L_mldsa_decode_eta_2_neon_idx@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x3, L_mldsa_decode_eta_2_neon_shift
	add  x3, x3, :lo12:L_mldsa_decode_eta_2_neon_shift
#else
	adrp x3, L_mldsa_decode_eta_2_neon_shift@PAGE
	add  x3, x3, L_mldsa_decode_eta_2_neon_shift@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x4, L_mldsa_decode_eta_2_neon_mask
	add  x4, x4, :lo12:L_mldsa_decode_eta_2_neon_mask
#else
	adrp x4, L_mldsa_decode_eta_2_neon_mask@PAGE
	add  x4, x4, L_mldsa_decode_eta_2_neon_mask@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x5, L_mldsa_decode_eta_2_neon_konst
	add  x5, x5, :lo12:L_mldsa_decode_eta_2_neon_konst
#else
	adrp x5, L_mldsa_decode_eta_2_neon_konst@PAGE
	add  x5, x5, L_mldsa_decode_eta_2_neon_konst@PAGEOFF
#endif /* __APPLE__ */
	ldr	q1, [x2]
	ldr	q3, [x3]
	ldr	q2, [x2, #16]
	ldr	q4, [x3, #16]
	ldr	q5, [x4]
	ldr	q6, [x5]
	mov	x6, #27
L_mldsa_decode_eta_2_neon_loop:
	ldr	q0, [x0]
	tbl	v7.16b, {v0.16b}, v1.16b
	ushl	v7.4s, v7.4s, v3.4s
	and	v7.16b, v7.16b, v5.16b
	sub	v7.4s, v6.4s, v7.4s
	str	q7, [x1]
	tbl	v8.16b, {v0.16b}, v2.16b
	ushl	v8.4s, v8.4s, v4.4s
	and	v8.16b, v8.16b, v5.16b
	sub	v8.4s, v6.4s, v8.4s
	str	q8, [x1, #16]
	add	x0, x0, #3
	add	x1, x1, #32
	subs	x6, x6, #1
	bne	L_mldsa_decode_eta_2_neon_loop
	sub	x0, x0, #1
	ldr	q0, [x0]
	ldr	q1, [x2, #32]
	ldr	q2, [x2, #48]
	tbl	v7.16b, {v0.16b}, v1.16b
	ushl	v7.4s, v7.4s, v3.4s
	and	v7.16b, v7.16b, v5.16b
	sub	v7.4s, v6.4s, v7.4s
	str	q7, [x1]
	tbl	v8.16b, {v0.16b}, v2.16b
	ushl	v8.4s, v8.4s, v4.4s
	and	v8.16b, v8.16b, v5.16b
	sub	v8.4s, v6.4s, v8.4s
	str	q8, [x1, #16]
	add	x1, x1, #32
	ldr	q1, [x2, #64]
	ldr	q2, [x2, #80]
	tbl	v7.16b, {v0.16b}, v1.16b
	ushl	v7.4s, v7.4s, v3.4s
	and	v7.16b, v7.16b, v5.16b
	sub	v7.4s, v6.4s, v7.4s
	str	q7, [x1]
	tbl	v8.16b, {v0.16b}, v2.16b
	ushl	v8.4s, v8.4s, v4.4s
	and	v8.16b, v8.16b, v5.16b
	sub	v8.4s, v6.4s, v8.4s
	str	q8, [x1, #16]
	add	x1, x1, #32
	ldr	q1, [x2, #96]
	ldr	q2, [x2, #112]
	tbl	v7.16b, {v0.16b}, v1.16b
	ushl	v7.4s, v7.4s, v3.4s
	and	v7.16b, v7.16b, v5.16b
	sub	v7.4s, v6.4s, v7.4s
	str	q7, [x1]
	tbl	v8.16b, {v0.16b}, v2.16b
	ushl	v8.4s, v8.4s, v4.4s
	and	v8.16b, v8.16b, v5.16b
	sub	v8.4s, v6.4s, v8.4s
	str	q8, [x1, #16]
	add	x1, x1, #32
	ldr	q1, [x2, #128]
	ldr	q2, [x2, #144]
	tbl	v7.16b, {v0.16b}, v1.16b
	ushl	v7.4s, v7.4s, v3.4s
	and	v7.16b, v7.16b, v5.16b
	sub	v7.4s, v6.4s, v7.4s
	str	q7, [x1]
	tbl	v8.16b, {v0.16b}, v2.16b
	ushl	v8.4s, v8.4s, v4.4s
	and	v8.16b, v8.16b, v5.16b
	sub	v8.4s, v6.4s, v8.4s
	str	q8, [x1, #16]
	add	x1, x1, #32
	ldr	q1, [x2, #160]
	ldr	q2, [x2, #176]
	tbl	v7.16b, {v0.16b}, v1.16b
	ushl	v7.4s, v7.4s, v3.4s
	and	v7.16b, v7.16b, v5.16b
	sub	v7.4s, v6.4s, v7.4s
	str	q7, [x1]
	tbl	v8.16b, {v0.16b}, v2.16b
	ushl	v8.4s, v8.4s, v4.4s
	and	v8.16b, v8.16b, v5.16b
	sub	v8.4s, v6.4s, v8.4s
	str	q8, [x1, #16]
	ldp	d8, d9, [x29, #16]
	ldp	x29, x30, [sp], #32
	ret
#ifndef __APPLE__
	.size	mldsa_decode_eta_2_neon,.-mldsa_decode_eta_2_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mldsa_decode_eta_4_neon_idx, %object
	.size	L_mldsa_decode_eta_4_neon_idx, 128
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
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
	.section	.rodata
	.type	L_mldsa_decode_eta_4_neon_shift, %object
	.size	L_mldsa_decode_eta_4_neon_shift, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_decode_eta_4_neon_shift:
	.long	0x00000000,0xfffffffc,0x00000000,0xfffffffc
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mldsa_decode_eta_4_neon_mask, %object
	.size	L_mldsa_decode_eta_4_neon_mask, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_decode_eta_4_neon_mask:
	.long	0x0000000f,0x0000000f,0x0000000f,0x0000000f
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mldsa_decode_eta_4_neon_konst, %object
	.size	L_mldsa_decode_eta_4_neon_konst, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_decode_eta_4_neon_konst:
	.long	0x00000004,0x00000004,0x00000004,0x00000004
#ifndef __APPLE__
.text
.globl	mldsa_decode_eta_4_neon
WC_ASM_ATT_HIDDEN(mldsa_decode_eta_4_neon)
.type	mldsa_decode_eta_4_neon,@function
.align	2
mldsa_decode_eta_4_neon:
#else
.section	__TEXT,__text
.globl	_mldsa_decode_eta_4_neon
WC_ASM_ATT_HIDDEN(_mldsa_decode_eta_4_neon)
.p2align	2
_mldsa_decode_eta_4_neon:
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x2, L_mldsa_decode_eta_4_neon_idx
	add  x2, x2, :lo12:L_mldsa_decode_eta_4_neon_idx
#else
	adrp x2, L_mldsa_decode_eta_4_neon_idx@PAGE
	add  x2, x2, L_mldsa_decode_eta_4_neon_idx@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x3, L_mldsa_decode_eta_4_neon_shift
	add  x3, x3, :lo12:L_mldsa_decode_eta_4_neon_shift
#else
	adrp x3, L_mldsa_decode_eta_4_neon_shift@PAGE
	add  x3, x3, L_mldsa_decode_eta_4_neon_shift@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x4, L_mldsa_decode_eta_4_neon_mask
	add  x4, x4, :lo12:L_mldsa_decode_eta_4_neon_mask
#else
	adrp x4, L_mldsa_decode_eta_4_neon_mask@PAGE
	add  x4, x4, L_mldsa_decode_eta_4_neon_mask@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x5, L_mldsa_decode_eta_4_neon_konst
	add  x5, x5, :lo12:L_mldsa_decode_eta_4_neon_konst
#else
	adrp x5, L_mldsa_decode_eta_4_neon_konst@PAGE
	add  x5, x5, L_mldsa_decode_eta_4_neon_konst@PAGEOFF
#endif /* __APPLE__ */
	ldr	q1, [x2]
	ldr	q2, [x3]
	ldr	q3, [x4]
	ldr	q4, [x5]
	mov	x6, #57
L_mldsa_decode_eta_4_neon_loop:
	ldr	q0, [x0]
	tbl	v5.16b, {v0.16b}, v1.16b
	ushl	v5.4s, v5.4s, v2.4s
	and	v5.16b, v5.16b, v3.16b
	sub	v5.4s, v4.4s, v5.4s
	str	q5, [x1]
	add	x0, x0, #2
	add	x1, x1, #16
	subs	x6, x6, #1
	bne	L_mldsa_decode_eta_4_neon_loop
	sub	x0, x0, #2
	ldr	q0, [x0]
	ldr	q1, [x2, #16]
	tbl	v5.16b, {v0.16b}, v1.16b
	ushl	v5.4s, v5.4s, v2.4s
	and	v5.16b, v5.16b, v3.16b
	sub	v5.4s, v4.4s, v5.4s
	str	q5, [x1]
	add	x1, x1, #16
	ldr	q1, [x2, #32]
	tbl	v5.16b, {v0.16b}, v1.16b
	ushl	v5.4s, v5.4s, v2.4s
	and	v5.16b, v5.16b, v3.16b
	sub	v5.4s, v4.4s, v5.4s
	str	q5, [x1]
	add	x1, x1, #16
	ldr	q1, [x2, #48]
	tbl	v5.16b, {v0.16b}, v1.16b
	ushl	v5.4s, v5.4s, v2.4s
	and	v5.16b, v5.16b, v3.16b
	sub	v5.4s, v4.4s, v5.4s
	str	q5, [x1]
	add	x1, x1, #16
	ldr	q1, [x2, #64]
	tbl	v5.16b, {v0.16b}, v1.16b
	ushl	v5.4s, v5.4s, v2.4s
	and	v5.16b, v5.16b, v3.16b
	sub	v5.4s, v4.4s, v5.4s
	str	q5, [x1]
	add	x1, x1, #16
	ldr	q1, [x2, #80]
	tbl	v5.16b, {v0.16b}, v1.16b
	ushl	v5.4s, v5.4s, v2.4s
	and	v5.16b, v5.16b, v3.16b
	sub	v5.4s, v4.4s, v5.4s
	str	q5, [x1]
	add	x1, x1, #16
	ldr	q1, [x2, #96]
	tbl	v5.16b, {v0.16b}, v1.16b
	ushl	v5.4s, v5.4s, v2.4s
	and	v5.16b, v5.16b, v3.16b
	sub	v5.4s, v4.4s, v5.4s
	str	q5, [x1]
	add	x1, x1, #16
	ldr	q1, [x2, #112]
	tbl	v5.16b, {v0.16b}, v1.16b
	ushl	v5.4s, v5.4s, v2.4s
	and	v5.16b, v5.16b, v3.16b
	sub	v5.4s, v4.4s, v5.4s
	str	q5, [x1]
	ret
#ifndef __APPLE__
	.size	mldsa_decode_eta_4_neon,.-mldsa_decode_eta_4_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mldsa_decode_t1_neon_idx, %object
	.size	L_mldsa_decode_t1_neon_idx, 64
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
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
	.section	.rodata
	.type	L_mldsa_decode_t1_neon_shift, %object
	.size	L_mldsa_decode_t1_neon_shift, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_decode_t1_neon_shift:
	.long	0x00000000,0xfffffffe,0xfffffffc,0xfffffffa
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mldsa_decode_t1_neon_mask, %object
	.size	L_mldsa_decode_t1_neon_mask, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_decode_t1_neon_mask:
	.long	0x000003ff,0x000003ff,0x000003ff,0x000003ff
#ifndef __APPLE__
.text
.globl	mldsa_decode_t1_neon
WC_ASM_ATT_HIDDEN(mldsa_decode_t1_neon)
.type	mldsa_decode_t1_neon,@function
.align	2
mldsa_decode_t1_neon:
#else
.section	__TEXT,__text
.globl	_mldsa_decode_t1_neon
WC_ASM_ATT_HIDDEN(_mldsa_decode_t1_neon)
.p2align	2
_mldsa_decode_t1_neon:
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x2, L_mldsa_decode_t1_neon_idx
	add  x2, x2, :lo12:L_mldsa_decode_t1_neon_idx
#else
	adrp x2, L_mldsa_decode_t1_neon_idx@PAGE
	add  x2, x2, L_mldsa_decode_t1_neon_idx@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x3, L_mldsa_decode_t1_neon_shift
	add  x3, x3, :lo12:L_mldsa_decode_t1_neon_shift
#else
	adrp x3, L_mldsa_decode_t1_neon_shift@PAGE
	add  x3, x3, L_mldsa_decode_t1_neon_shift@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x4, L_mldsa_decode_t1_neon_mask
	add  x4, x4, :lo12:L_mldsa_decode_t1_neon_mask
#else
	adrp x4, L_mldsa_decode_t1_neon_mask@PAGE
	add  x4, x4, L_mldsa_decode_t1_neon_mask@PAGEOFF
#endif /* __APPLE__ */
	ldr	q1, [x2]
	ldr	q2, [x3]
	ldr	q3, [x4]
	mov	x5, #61
L_mldsa_decode_t1_neon_loop:
	ldr	q0, [x0]
	tbl	v4.16b, {v0.16b}, v1.16b
	ushl	v4.4s, v4.4s, v2.4s
	and	v4.16b, v4.16b, v3.16b
	shl	v4.4s, v4.4s, #13
	str	q4, [x1]
	add	x0, x0, #5
	add	x1, x1, #16
	subs	x5, x5, #1
	bne	L_mldsa_decode_t1_neon_loop
	sub	x0, x0, #1
	ldr	q0, [x0]
	ldr	q1, [x2, #16]
	tbl	v4.16b, {v0.16b}, v1.16b
	ushl	v4.4s, v4.4s, v2.4s
	and	v4.16b, v4.16b, v3.16b
	shl	v4.4s, v4.4s, #13
	str	q4, [x1]
	add	x1, x1, #16
	ldr	q1, [x2, #32]
	tbl	v4.16b, {v0.16b}, v1.16b
	ushl	v4.4s, v4.4s, v2.4s
	and	v4.16b, v4.16b, v3.16b
	shl	v4.4s, v4.4s, #13
	str	q4, [x1]
	add	x1, x1, #16
	ldr	q1, [x2, #48]
	tbl	v4.16b, {v0.16b}, v1.16b
	ushl	v4.4s, v4.4s, v2.4s
	and	v4.16b, v4.16b, v3.16b
	shl	v4.4s, v4.4s, #13
	str	q4, [x1]
	ret
#ifndef __APPLE__
	.size	mldsa_decode_t1_neon,.-mldsa_decode_t1_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mldsa_decode_t0_neon_idx, %object
	.size	L_mldsa_decode_t0_neon_idx, 64
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
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
	.section	.rodata
	.type	L_mldsa_decode_t0_neon_shift, %object
	.size	L_mldsa_decode_t0_neon_shift, 32
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_decode_t0_neon_shift:
	.long	0x00000000,0xfffffffb,0xfffffffe,0xfffffff9
	.long	0xfffffffc,0xffffffff,0xfffffffa,0xfffffffd
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mldsa_decode_t0_neon_mask, %object
	.size	L_mldsa_decode_t0_neon_mask, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_decode_t0_neon_mask:
	.long	0x00001fff,0x00001fff,0x00001fff,0x00001fff
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mldsa_decode_t0_neon_konst, %object
	.size	L_mldsa_decode_t0_neon_konst, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_decode_t0_neon_konst:
	.long	0x00001000,0x00001000,0x00001000,0x00001000
#ifndef __APPLE__
.text
.globl	mldsa_decode_t0_neon
WC_ASM_ATT_HIDDEN(mldsa_decode_t0_neon)
.type	mldsa_decode_t0_neon,@function
.align	2
mldsa_decode_t0_neon:
#else
.section	__TEXT,__text
.globl	_mldsa_decode_t0_neon
WC_ASM_ATT_HIDDEN(_mldsa_decode_t0_neon)
.p2align	2
_mldsa_decode_t0_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-32]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
#ifndef __APPLE__
	adrp x2, L_mldsa_decode_t0_neon_idx
	add  x2, x2, :lo12:L_mldsa_decode_t0_neon_idx
#else
	adrp x2, L_mldsa_decode_t0_neon_idx@PAGE
	add  x2, x2, L_mldsa_decode_t0_neon_idx@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x3, L_mldsa_decode_t0_neon_shift
	add  x3, x3, :lo12:L_mldsa_decode_t0_neon_shift
#else
	adrp x3, L_mldsa_decode_t0_neon_shift@PAGE
	add  x3, x3, L_mldsa_decode_t0_neon_shift@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x4, L_mldsa_decode_t0_neon_mask
	add  x4, x4, :lo12:L_mldsa_decode_t0_neon_mask
#else
	adrp x4, L_mldsa_decode_t0_neon_mask@PAGE
	add  x4, x4, L_mldsa_decode_t0_neon_mask@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x5, L_mldsa_decode_t0_neon_konst
	add  x5, x5, :lo12:L_mldsa_decode_t0_neon_konst
#else
	adrp x5, L_mldsa_decode_t0_neon_konst@PAGE
	add  x5, x5, L_mldsa_decode_t0_neon_konst@PAGEOFF
#endif /* __APPLE__ */
	ldr	q1, [x2]
	ldr	q3, [x3]
	ldr	q2, [x2, #16]
	ldr	q4, [x3, #16]
	ldr	q5, [x4]
	ldr	q6, [x5]
	mov	x6, #31
L_mldsa_decode_t0_neon_loop:
	ldr	q0, [x0]
	tbl	v7.16b, {v0.16b}, v1.16b
	ushl	v7.4s, v7.4s, v3.4s
	and	v7.16b, v7.16b, v5.16b
	sub	v7.4s, v6.4s, v7.4s
	str	q7, [x1]
	tbl	v8.16b, {v0.16b}, v2.16b
	ushl	v8.4s, v8.4s, v4.4s
	and	v8.16b, v8.16b, v5.16b
	sub	v8.4s, v6.4s, v8.4s
	str	q8, [x1, #16]
	add	x0, x0, #13
	add	x1, x1, #32
	subs	x6, x6, #1
	bne	L_mldsa_decode_t0_neon_loop
	sub	x0, x0, #3
	ldr	q0, [x0]
	ldr	q1, [x2, #32]
	ldr	q2, [x2, #48]
	tbl	v7.16b, {v0.16b}, v1.16b
	ushl	v7.4s, v7.4s, v3.4s
	and	v7.16b, v7.16b, v5.16b
	sub	v7.4s, v6.4s, v7.4s
	str	q7, [x1]
	tbl	v8.16b, {v0.16b}, v2.16b
	ushl	v8.4s, v8.4s, v4.4s
	and	v8.16b, v8.16b, v5.16b
	sub	v8.4s, v6.4s, v8.4s
	str	q8, [x1, #16]
	ldp	d8, d9, [x29, #16]
	ldp	x29, x30, [sp], #32
	ret
#ifndef __APPLE__
	.size	mldsa_decode_t0_neon,.-mldsa_decode_t0_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mldsa_decode_gamma1_17_neon_idx, %object
	.size	L_mldsa_decode_gamma1_17_neon_idx, 32
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_decode_gamma1_17_neon_idx:
	.byte	0x00,0x01,0x02,0xff,0x02,0x03,0x04,0xff
	.byte	0x04,0x05,0x06,0xff,0x06,0x07,0x08,0xff
	.byte	0x07,0x08,0x09,0xff,0x09,0x0a,0x0b,0xff
	.byte	0x0b,0x0c,0x0d,0xff,0x0d,0x0e,0x0f,0xff
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mldsa_decode_gamma1_17_neon_shift, %object
	.size	L_mldsa_decode_gamma1_17_neon_shift, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_decode_gamma1_17_neon_shift:
	.long	0x00000000,0xfffffffe,0xfffffffc,0xfffffffa
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mldsa_decode_gamma1_17_neon_mask, %object
	.size	L_mldsa_decode_gamma1_17_neon_mask, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_decode_gamma1_17_neon_mask:
	.long	0x0003ffff,0x0003ffff,0x0003ffff,0x0003ffff
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mldsa_decode_gamma1_17_neon_konst, %object
	.size	L_mldsa_decode_gamma1_17_neon_konst, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_decode_gamma1_17_neon_konst:
	.long	0x00020000,0x00020000,0x00020000,0x00020000
#ifndef __APPLE__
.text
.globl	mldsa_decode_gamma1_17_neon
WC_ASM_ATT_HIDDEN(mldsa_decode_gamma1_17_neon)
.type	mldsa_decode_gamma1_17_neon,@function
.align	2
mldsa_decode_gamma1_17_neon:
#else
.section	__TEXT,__text
.globl	_mldsa_decode_gamma1_17_neon
WC_ASM_ATT_HIDDEN(_mldsa_decode_gamma1_17_neon)
.p2align	2
_mldsa_decode_gamma1_17_neon:
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x2, L_mldsa_decode_gamma1_17_neon_idx
	add  x2, x2, :lo12:L_mldsa_decode_gamma1_17_neon_idx
#else
	adrp x2, L_mldsa_decode_gamma1_17_neon_idx@PAGE
	add  x2, x2, L_mldsa_decode_gamma1_17_neon_idx@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x3, L_mldsa_decode_gamma1_17_neon_shift
	add  x3, x3, :lo12:L_mldsa_decode_gamma1_17_neon_shift
#else
	adrp x3, L_mldsa_decode_gamma1_17_neon_shift@PAGE
	add  x3, x3, L_mldsa_decode_gamma1_17_neon_shift@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x4, L_mldsa_decode_gamma1_17_neon_mask
	add  x4, x4, :lo12:L_mldsa_decode_gamma1_17_neon_mask
#else
	adrp x4, L_mldsa_decode_gamma1_17_neon_mask@PAGE
	add  x4, x4, L_mldsa_decode_gamma1_17_neon_mask@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x5, L_mldsa_decode_gamma1_17_neon_konst
	add  x5, x5, :lo12:L_mldsa_decode_gamma1_17_neon_konst
#else
	adrp x5, L_mldsa_decode_gamma1_17_neon_konst@PAGE
	add  x5, x5, L_mldsa_decode_gamma1_17_neon_konst@PAGEOFF
#endif /* __APPLE__ */
	ldr	q1, [x2]
	ldr	q2, [x3]
	ldr	q3, [x4]
	ldr	q4, [x5]
	mov	x6, #63
L_mldsa_decode_gamma1_17_neon_loop:
	ldr	q0, [x0]
	tbl	v5.16b, {v0.16b}, v1.16b
	ushl	v5.4s, v5.4s, v2.4s
	and	v5.16b, v5.16b, v3.16b
	sub	v5.4s, v4.4s, v5.4s
	str	q5, [x1]
	add	x0, x0, #9
	add	x1, x1, #16
	subs	x6, x6, #1
	bne	L_mldsa_decode_gamma1_17_neon_loop
	sub	x0, x0, #7
	ldr	q0, [x0]
	ldr	q1, [x2, #16]
	tbl	v5.16b, {v0.16b}, v1.16b
	ushl	v5.4s, v5.4s, v2.4s
	and	v5.16b, v5.16b, v3.16b
	sub	v5.4s, v4.4s, v5.4s
	str	q5, [x1]
	ret
#ifndef __APPLE__
	.size	mldsa_decode_gamma1_17_neon,.-mldsa_decode_gamma1_17_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mldsa_decode_gamma1_19_neon_idx, %object
	.size	L_mldsa_decode_gamma1_19_neon_idx, 32
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_decode_gamma1_19_neon_idx:
	.byte	0x00,0x01,0x02,0xff,0x02,0x03,0x04,0xff
	.byte	0x05,0x06,0x07,0xff,0x07,0x08,0x09,0xff
	.byte	0x06,0x07,0x08,0xff,0x08,0x09,0x0a,0xff
	.byte	0x0b,0x0c,0x0d,0xff,0x0d,0x0e,0x0f,0xff
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mldsa_decode_gamma1_19_neon_shift, %object
	.size	L_mldsa_decode_gamma1_19_neon_shift, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_decode_gamma1_19_neon_shift:
	.long	0x00000000,0xfffffffc,0x00000000,0xfffffffc
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mldsa_decode_gamma1_19_neon_mask, %object
	.size	L_mldsa_decode_gamma1_19_neon_mask, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_decode_gamma1_19_neon_mask:
	.long	0x000fffff,0x000fffff,0x000fffff,0x000fffff
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mldsa_decode_gamma1_19_neon_konst, %object
	.size	L_mldsa_decode_gamma1_19_neon_konst, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_decode_gamma1_19_neon_konst:
	.long	0x00080000,0x00080000,0x00080000,0x00080000
#ifndef __APPLE__
.text
.globl	mldsa_decode_gamma1_19_neon
WC_ASM_ATT_HIDDEN(mldsa_decode_gamma1_19_neon)
.type	mldsa_decode_gamma1_19_neon,@function
.align	2
mldsa_decode_gamma1_19_neon:
#else
.section	__TEXT,__text
.globl	_mldsa_decode_gamma1_19_neon
WC_ASM_ATT_HIDDEN(_mldsa_decode_gamma1_19_neon)
.p2align	2
_mldsa_decode_gamma1_19_neon:
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x2, L_mldsa_decode_gamma1_19_neon_idx
	add  x2, x2, :lo12:L_mldsa_decode_gamma1_19_neon_idx
#else
	adrp x2, L_mldsa_decode_gamma1_19_neon_idx@PAGE
	add  x2, x2, L_mldsa_decode_gamma1_19_neon_idx@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x3, L_mldsa_decode_gamma1_19_neon_shift
	add  x3, x3, :lo12:L_mldsa_decode_gamma1_19_neon_shift
#else
	adrp x3, L_mldsa_decode_gamma1_19_neon_shift@PAGE
	add  x3, x3, L_mldsa_decode_gamma1_19_neon_shift@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x4, L_mldsa_decode_gamma1_19_neon_mask
	add  x4, x4, :lo12:L_mldsa_decode_gamma1_19_neon_mask
#else
	adrp x4, L_mldsa_decode_gamma1_19_neon_mask@PAGE
	add  x4, x4, L_mldsa_decode_gamma1_19_neon_mask@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x5, L_mldsa_decode_gamma1_19_neon_konst
	add  x5, x5, :lo12:L_mldsa_decode_gamma1_19_neon_konst
#else
	adrp x5, L_mldsa_decode_gamma1_19_neon_konst@PAGE
	add  x5, x5, L_mldsa_decode_gamma1_19_neon_konst@PAGEOFF
#endif /* __APPLE__ */
	ldr	q1, [x2]
	ldr	q2, [x3]
	ldr	q3, [x4]
	ldr	q4, [x5]
	mov	x6, #63
L_mldsa_decode_gamma1_19_neon_loop:
	ldr	q0, [x0]
	tbl	v5.16b, {v0.16b}, v1.16b
	ushl	v5.4s, v5.4s, v2.4s
	and	v5.16b, v5.16b, v3.16b
	sub	v5.4s, v4.4s, v5.4s
	str	q5, [x1]
	add	x0, x0, #10
	add	x1, x1, #16
	subs	x6, x6, #1
	bne	L_mldsa_decode_gamma1_19_neon_loop
	sub	x0, x0, #6
	ldr	q0, [x0]
	ldr	q1, [x2, #16]
	tbl	v5.16b, {v0.16b}, v1.16b
	ushl	v5.4s, v5.4s, v2.4s
	and	v5.16b, v5.16b, v3.16b
	sub	v5.4s, v4.4s, v5.4s
	str	q5, [x1]
	ret
#ifndef __APPLE__
	.size	mldsa_decode_gamma1_19_neon,.-mldsa_decode_gamma1_19_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mldsa_encode_w1_88_neon_idx, %object
	.size	L_mldsa_encode_w1_88_neon_idx, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_encode_w1_88_neon_idx:
	.byte	0x00,0x01,0x02,0x04,0x05,0x06,0x08,0x09
	.byte	0x0a,0x0c,0x0d,0x0e,0xff,0xff,0xff,0xff
#ifndef __APPLE__
.text
.globl	mldsa_encode_w1_88_neon
WC_ASM_ATT_HIDDEN(mldsa_encode_w1_88_neon)
.type	mldsa_encode_w1_88_neon,@function
.align	2
mldsa_encode_w1_88_neon:
#else
.section	__TEXT,__text
.globl	_mldsa_encode_w1_88_neon
WC_ASM_ATT_HIDDEN(_mldsa_encode_w1_88_neon)
.p2align	2
_mldsa_encode_w1_88_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-32]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
#ifndef __APPLE__
	adrp x2, L_mldsa_encode_w1_88_neon_idx
	add  x2, x2, :lo12:L_mldsa_encode_w1_88_neon_idx
#else
	adrp x2, L_mldsa_encode_w1_88_neon_idx@PAGE
	add  x2, x2, L_mldsa_encode_w1_88_neon_idx@PAGEOFF
#endif /* __APPLE__ */
	ldr	q8, [x2]
	mov	x3, #16
L_mldsa_encode_w1_88_neon_loop:
	ldr	q0, [x0]
	ldr	q1, [x0, #16]
	ldr	q2, [x0, #32]
	ldr	q3, [x0, #48]
	uzp1	v4.4s, v0.4s, v1.4s
	uzp2	v7.4s, v0.4s, v1.4s
	sli	v4.4s, v7.4s, #6
	uzp1	v5.4s, v2.4s, v3.4s
	uzp2	v7.4s, v2.4s, v3.4s
	sli	v5.4s, v7.4s, #6
	uzp1	v6.4s, v4.4s, v5.4s
	uzp2	v7.4s, v4.4s, v5.4s
	sli	v6.4s, v7.4s, #12
	tbl	v9.16b, {v6.16b}, v8.16b
	str	d9, [x1]
	ext	v9.16b, v9.16b, v9.16b, #8
	str	s9, [x1, #8]
	add	x0, x0, #0x40
	add	x1, x1, #12
	subs	x3, x3, #1
	bne	L_mldsa_encode_w1_88_neon_loop
	ldp	d8, d9, [x29, #16]
	ldp	x29, x30, [sp], #32
	ret
#ifndef __APPLE__
	.size	mldsa_encode_w1_88_neon,.-mldsa_encode_w1_88_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mldsa_encode_w1_32_neon_idx, %object
	.size	L_mldsa_encode_w1_32_neon_idx, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_encode_w1_32_neon_idx:
	.byte	0x00,0x04,0x08,0x0c,0x10,0x14,0x18,0x1c
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
#ifndef __APPLE__
.text
.globl	mldsa_encode_w1_32_neon
WC_ASM_ATT_HIDDEN(mldsa_encode_w1_32_neon)
.type	mldsa_encode_w1_32_neon,@function
.align	2
mldsa_encode_w1_32_neon:
#else
.section	__TEXT,__text
.globl	_mldsa_encode_w1_32_neon
WC_ASM_ATT_HIDDEN(_mldsa_encode_w1_32_neon)
.p2align	2
_mldsa_encode_w1_32_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-32]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
#ifndef __APPLE__
	adrp x2, L_mldsa_encode_w1_32_neon_idx
	add  x2, x2, :lo12:L_mldsa_encode_w1_32_neon_idx
#else
	adrp x2, L_mldsa_encode_w1_32_neon_idx@PAGE
	add  x2, x2, L_mldsa_encode_w1_32_neon_idx@PAGEOFF
#endif /* __APPLE__ */
	ldr	q8, [x2]
	mov	x3, #16
L_mldsa_encode_w1_32_neon_loop:
	ldr	q0, [x0]
	ldr	q1, [x0, #16]
	ldr	q2, [x0, #32]
	ldr	q3, [x0, #48]
	uzp1	v4.4s, v0.4s, v1.4s
	uzp2	v7.4s, v0.4s, v1.4s
	sli	v4.4s, v7.4s, #4
	uzp1	v5.4s, v2.4s, v3.4s
	uzp2	v7.4s, v2.4s, v3.4s
	sli	v5.4s, v7.4s, #4
	tbl	v9.16b, {v4.16b, v5.16b}, v8.16b
	str	d9, [x1]
	add	x0, x0, #0x40
	add	x1, x1, #8
	subs	x3, x3, #1
	bne	L_mldsa_encode_w1_32_neon_loop
	ldp	d8, d9, [x29, #16]
	ldp	x29, x30, [sp], #32
	ret
#ifndef __APPLE__
	.size	mldsa_encode_w1_32_neon,.-mldsa_encode_w1_32_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mldsa_encode_gamma1_17_neon_idx, %object
	.size	L_mldsa_encode_gamma1_17_neon_idx, 32
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_encode_gamma1_17_neon_idx:
	.byte	0x00,0x01,0x02,0xff,0x08,0x09,0x0a,0xff
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0x04,0x05,0x06,0xff,0x0c,0x0d
	.byte	0x0e,0xff,0xff,0xff,0xff,0xff,0xff,0xff
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mldsa_encode_gamma1_17_neon_shift, %object
	.size	L_mldsa_encode_gamma1_17_neon_shift, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_encode_gamma1_17_neon_shift:
	.long	0x00000000,0x00000002,0x00000004,0x00000006
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mldsa_encode_gamma1_17_neon_gam, %object
	.size	L_mldsa_encode_gamma1_17_neon_gam, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_encode_gamma1_17_neon_gam:
	.long	0x00020000,0x00020000,0x00020000,0x00020000
#ifndef __APPLE__
.text
.globl	mldsa_encode_gamma1_17_neon
WC_ASM_ATT_HIDDEN(mldsa_encode_gamma1_17_neon)
.type	mldsa_encode_gamma1_17_neon,@function
.align	2
mldsa_encode_gamma1_17_neon:
#else
.section	__TEXT,__text
.globl	_mldsa_encode_gamma1_17_neon
WC_ASM_ATT_HIDDEN(_mldsa_encode_gamma1_17_neon)
.p2align	2
_mldsa_encode_gamma1_17_neon:
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x2, L_mldsa_encode_gamma1_17_neon_idx
	add  x2, x2, :lo12:L_mldsa_encode_gamma1_17_neon_idx
#else
	adrp x2, L_mldsa_encode_gamma1_17_neon_idx@PAGE
	add  x2, x2, L_mldsa_encode_gamma1_17_neon_idx@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x3, L_mldsa_encode_gamma1_17_neon_shift
	add  x3, x3, :lo12:L_mldsa_encode_gamma1_17_neon_shift
#else
	adrp x3, L_mldsa_encode_gamma1_17_neon_shift@PAGE
	add  x3, x3, L_mldsa_encode_gamma1_17_neon_shift@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x4, L_mldsa_encode_gamma1_17_neon_gam
	add  x4, x4, :lo12:L_mldsa_encode_gamma1_17_neon_gam
#else
	adrp x4, L_mldsa_encode_gamma1_17_neon_gam@PAGE
	add  x4, x4, L_mldsa_encode_gamma1_17_neon_gam@PAGEOFF
#endif /* __APPLE__ */
	ldr	q3, [x2]
	ldr	q4, [x2, #16]
	ldr	q1, [x3]
	ldr	q2, [x4]
	mov	x5, #0x40
L_mldsa_encode_gamma1_17_neon_loop:
	ldr	q0, [x0]
	sub	v0.4s, v2.4s, v0.4s
	ushl	v0.4s, v0.4s, v1.4s
	tbl	v5.16b, {v0.16b}, v3.16b
	tbl	v6.16b, {v0.16b}, v4.16b
	orr	v5.16b, v5.16b, v6.16b
	str	d5, [x1]
	ext	v5.16b, v5.16b, v5.16b, #8
	str	b5, [x1, #8]
	add	x0, x0, #16
	add	x1, x1, #9
	subs	x5, x5, #1
	bne	L_mldsa_encode_gamma1_17_neon_loop
	ret
#ifndef __APPLE__
	.size	mldsa_encode_gamma1_17_neon,.-mldsa_encode_gamma1_17_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mldsa_encode_gamma1_19_neon_idx, %object
	.size	L_mldsa_encode_gamma1_19_neon_idx, 32
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_encode_gamma1_19_neon_idx:
	.byte	0x00,0x01,0x02,0xff,0xff,0x08,0x09,0x0a
	.byte	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte	0xff,0xff,0x04,0x05,0x06,0xff,0xff,0x0c
	.byte	0x0d,0x0e,0xff,0xff,0xff,0xff,0xff,0xff
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mldsa_encode_gamma1_19_neon_shift, %object
	.size	L_mldsa_encode_gamma1_19_neon_shift, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_encode_gamma1_19_neon_shift:
	.long	0x00000000,0x00000004,0x00000000,0x00000004
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mldsa_encode_gamma1_19_neon_gam, %object
	.size	L_mldsa_encode_gamma1_19_neon_gam, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_encode_gamma1_19_neon_gam:
	.long	0x00080000,0x00080000,0x00080000,0x00080000
#ifndef __APPLE__
.text
.globl	mldsa_encode_gamma1_19_neon
WC_ASM_ATT_HIDDEN(mldsa_encode_gamma1_19_neon)
.type	mldsa_encode_gamma1_19_neon,@function
.align	2
mldsa_encode_gamma1_19_neon:
#else
.section	__TEXT,__text
.globl	_mldsa_encode_gamma1_19_neon
WC_ASM_ATT_HIDDEN(_mldsa_encode_gamma1_19_neon)
.p2align	2
_mldsa_encode_gamma1_19_neon:
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x2, L_mldsa_encode_gamma1_19_neon_idx
	add  x2, x2, :lo12:L_mldsa_encode_gamma1_19_neon_idx
#else
	adrp x2, L_mldsa_encode_gamma1_19_neon_idx@PAGE
	add  x2, x2, L_mldsa_encode_gamma1_19_neon_idx@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x3, L_mldsa_encode_gamma1_19_neon_shift
	add  x3, x3, :lo12:L_mldsa_encode_gamma1_19_neon_shift
#else
	adrp x3, L_mldsa_encode_gamma1_19_neon_shift@PAGE
	add  x3, x3, L_mldsa_encode_gamma1_19_neon_shift@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x4, L_mldsa_encode_gamma1_19_neon_gam
	add  x4, x4, :lo12:L_mldsa_encode_gamma1_19_neon_gam
#else
	adrp x4, L_mldsa_encode_gamma1_19_neon_gam@PAGE
	add  x4, x4, L_mldsa_encode_gamma1_19_neon_gam@PAGEOFF
#endif /* __APPLE__ */
	ldr	q3, [x2]
	ldr	q4, [x2, #16]
	ldr	q1, [x3]
	ldr	q2, [x4]
	mov	x5, #0x40
L_mldsa_encode_gamma1_19_neon_loop:
	ldr	q0, [x0]
	sub	v0.4s, v2.4s, v0.4s
	ushl	v0.4s, v0.4s, v1.4s
	tbl	v5.16b, {v0.16b}, v3.16b
	tbl	v6.16b, {v0.16b}, v4.16b
	orr	v5.16b, v5.16b, v6.16b
	str	d5, [x1]
	ext	v5.16b, v5.16b, v5.16b, #8
	str	h5, [x1, #8]
	add	x0, x0, #16
	add	x1, x1, #10
	subs	x5, x5, #1
	bne	L_mldsa_encode_gamma1_19_neon_loop
	ret
#ifndef __APPLE__
	.size	mldsa_encode_gamma1_19_neon,.-mldsa_encode_gamma1_19_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	mldsa_vec_check_low_neon
WC_ASM_ATT_HIDDEN(mldsa_vec_check_low_neon)
.type	mldsa_vec_check_low_neon,@function
.align	2
mldsa_vec_check_low_neon:
#else
.section	__TEXT,__text
.globl	_mldsa_vec_check_low_neon
WC_ASM_ATT_HIDDEN(_mldsa_vec_check_low_neon)
.p2align	2
_mldsa_vec_check_low_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-64]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
	stp	d12, d13, [x29, #48]
	dup	v0.4s, w2
	eor	v1.16b, v1.16b, v1.16b
	eor	v2.16b, v2.16b, v2.16b
	eor	v3.16b, v3.16b, v3.16b
	eor	v4.16b, v4.16b, v4.16b
L_mldsa_vec_check_low_outer:
	mov	x3, #16
L_mldsa_vec_check_low_inner:
	ldr	q5, [x0]
	ldr	q6, [x0, #16]
	ldr	q7, [x0, #32]
	ldr	q8, [x0, #48]
	sqabs	v9.4s, v5.4s
	cmge	v9.4s, v9.4s, v0.4s
	orr	v1.16b, v1.16b, v9.16b
	sqabs	v10.4s, v6.4s
	cmge	v10.4s, v10.4s, v0.4s
	orr	v2.16b, v2.16b, v10.16b
	sqabs	v11.4s, v7.4s
	cmge	v11.4s, v11.4s, v0.4s
	orr	v3.16b, v3.16b, v11.16b
	sqabs	v12.4s, v8.4s
	cmge	v12.4s, v12.4s, v0.4s
	orr	v4.16b, v4.16b, v12.16b
	add	x0, x0, #0x40
	subs	x3, x3, #1
	bne	L_mldsa_vec_check_low_inner
	subs	w1, w1, #1
	bne	L_mldsa_vec_check_low_outer
	orr	v1.16b, v1.16b, v2.16b
	orr	v3.16b, v3.16b, v4.16b
	orr	v1.16b, v1.16b, v3.16b
	umaxv	s1, v1.4s
	mov	w4, v1.s[0]
	cmp	w4, #0
	cset	w4, eq
	mov	x0, x4
	ldp	d8, d9, [x29, #16]
	ldp	d10, d11, [x29, #32]
	ldp	d12, d13, [x29, #48]
	ldp	x29, x30, [sp], #0x40
	ret
#ifndef __APPLE__
	.size	mldsa_vec_check_low_neon,.-mldsa_vec_check_low_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	mldsa_poly_add_neon
WC_ASM_ATT_HIDDEN(mldsa_poly_add_neon)
.type	mldsa_poly_add_neon,@function
.align	2
mldsa_poly_add_neon:
#else
.section	__TEXT,__text
.globl	_mldsa_poly_add_neon
WC_ASM_ATT_HIDDEN(_mldsa_poly_add_neon)
.p2align	2
_mldsa_poly_add_neon:
#endif /* __APPLE__ */
	mov	x2, #16
L_mldsa_poly_add_neon_loop:
	ldr	q0, [x0]
	ldr	q4, [x1]
	ldr	q1, [x0, #16]
	ldr	q5, [x1, #16]
	ldr	q2, [x0, #32]
	ldr	q6, [x1, #32]
	ldr	q3, [x0, #48]
	ldr	q7, [x1, #48]
	add	v0.4s, v0.4s, v4.4s
	add	v1.4s, v1.4s, v5.4s
	add	v2.4s, v2.4s, v6.4s
	add	v3.4s, v3.4s, v7.4s
	str	q0, [x0]
	str	q1, [x0, #16]
	str	q2, [x0, #32]
	str	q3, [x0, #48]
	add	x0, x0, #0x40
	add	x1, x1, #0x40
	subs	x2, x2, #1
	bne	L_mldsa_poly_add_neon_loop
	ret
#ifndef __APPLE__
	.size	mldsa_poly_add_neon,.-mldsa_poly_add_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	mldsa_poly_sub_neon
WC_ASM_ATT_HIDDEN(mldsa_poly_sub_neon)
.type	mldsa_poly_sub_neon,@function
.align	2
mldsa_poly_sub_neon:
#else
.section	__TEXT,__text
.globl	_mldsa_poly_sub_neon
WC_ASM_ATT_HIDDEN(_mldsa_poly_sub_neon)
.p2align	2
_mldsa_poly_sub_neon:
#endif /* __APPLE__ */
	mov	x2, #16
L_mldsa_poly_sub_neon_loop:
	ldr	q0, [x0]
	ldr	q4, [x1]
	ldr	q1, [x0, #16]
	ldr	q5, [x1, #16]
	ldr	q2, [x0, #32]
	ldr	q6, [x1, #32]
	ldr	q3, [x0, #48]
	ldr	q7, [x1, #48]
	sub	v0.4s, v0.4s, v4.4s
	sub	v1.4s, v1.4s, v5.4s
	sub	v2.4s, v2.4s, v6.4s
	sub	v3.4s, v3.4s, v7.4s
	str	q0, [x0]
	str	q1, [x0, #16]
	str	q2, [x0, #32]
	str	q3, [x0, #48]
	add	x0, x0, #0x40
	add	x1, x1, #0x40
	subs	x2, x2, #1
	bne	L_mldsa_poly_sub_neon_loop
	ret
#ifndef __APPLE__
	.size	mldsa_poly_sub_neon,.-mldsa_poly_sub_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
	.text
	.section	.rodata
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
#ifndef __APPLE__
.text
.globl	mldsa_poly_make_pos_neon
WC_ASM_ATT_HIDDEN(mldsa_poly_make_pos_neon)
.type	mldsa_poly_make_pos_neon,@function
.align	2
mldsa_poly_make_pos_neon:
#else
.section	__TEXT,__text
.globl	_mldsa_poly_make_pos_neon
WC_ASM_ATT_HIDDEN(_mldsa_poly_make_pos_neon)
.p2align	2
_mldsa_poly_make_pos_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-32]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
#ifndef __APPLE__
	adrp x1, L_mldsa_poly_make_pos_neon_q
	add  x1, x1, :lo12:L_mldsa_poly_make_pos_neon_q
#else
	adrp x1, L_mldsa_poly_make_pos_neon_q@PAGE
	add  x1, x1, L_mldsa_poly_make_pos_neon_q@PAGEOFF
#endif /* __APPLE__ */
	ldr	q0, [x1]
	mov	x2, #16
L_mldsa_poly_make_pos_neon_loop:
	ldr	q1, [x0]
	ldr	q2, [x0, #16]
	ldr	q3, [x0, #32]
	ldr	q4, [x0, #48]
	sshr	v5.4s, v1.4s, #31
	mls	v1.4s, v5.4s, v0.4s
	sshr	v6.4s, v2.4s, #31
	mls	v2.4s, v6.4s, v0.4s
	sshr	v7.4s, v3.4s, #31
	mls	v3.4s, v7.4s, v0.4s
	sshr	v8.4s, v4.4s, #31
	mls	v4.4s, v8.4s, v0.4s
	str	q1, [x0]
	str	q2, [x0, #16]
	str	q3, [x0, #32]
	str	q4, [x0, #48]
	add	x0, x0, #0x40
	subs	x2, x2, #1
	bne	L_mldsa_poly_make_pos_neon_loop
	ldp	d8, d9, [x29, #16]
	ldp	x29, x30, [sp], #32
	ret
#ifndef __APPLE__
	.size	mldsa_poly_make_pos_neon,.-mldsa_poly_make_pos_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
	.text
	.section	.rodata
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
#ifndef __APPLE__
.text
.globl	mldsa_poly_red_neon
WC_ASM_ATT_HIDDEN(mldsa_poly_red_neon)
.type	mldsa_poly_red_neon,@function
.align	2
mldsa_poly_red_neon:
#else
.section	__TEXT,__text
.globl	_mldsa_poly_red_neon
WC_ASM_ATT_HIDDEN(_mldsa_poly_red_neon)
.p2align	2
_mldsa_poly_red_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-32]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
#ifndef __APPLE__
	adrp x1, L_mldsa_poly_red_neon_q
	add  x1, x1, :lo12:L_mldsa_poly_red_neon_q
#else
	adrp x1, L_mldsa_poly_red_neon_q@PAGE
	add  x1, x1, L_mldsa_poly_red_neon_q@PAGEOFF
#endif /* __APPLE__ */
	ldr	q0, [x1]
	ldr	q1, [x1, #16]
	mov	x2, #16
L_mldsa_poly_red_neon_loop:
	ldr	q2, [x0]
	ldr	q3, [x0, #16]
	ldr	q4, [x0, #32]
	ldr	q5, [x0, #48]
	add	v6.4s, v2.4s, v1.4s
	sshr	v6.4s, v6.4s, #23
	mls	v2.4s, v6.4s, v0.4s
	add	v7.4s, v3.4s, v1.4s
	sshr	v7.4s, v7.4s, #23
	mls	v3.4s, v7.4s, v0.4s
	add	v8.4s, v4.4s, v1.4s
	sshr	v8.4s, v8.4s, #23
	mls	v4.4s, v8.4s, v0.4s
	add	v9.4s, v5.4s, v1.4s
	sshr	v9.4s, v9.4s, #23
	mls	v5.4s, v9.4s, v0.4s
	str	q2, [x0]
	str	q3, [x0, #16]
	str	q4, [x0, #32]
	str	q5, [x0, #48]
	add	x0, x0, #0x40
	subs	x2, x2, #1
	bne	L_mldsa_poly_red_neon_loop
	ldp	d8, d9, [x29, #16]
	ldp	x29, x30, [sp], #32
	ret
#ifndef __APPLE__
	.size	mldsa_poly_red_neon,.-mldsa_poly_red_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mldsa_extract_coeffs_eta2_neon_map, %object
	.size	L_mldsa_extract_coeffs_eta2_neon_map, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_extract_coeffs_eta2_neon_map:
	.byte	0x02,0x01,0x00,0xff,0xfe,0x02,0x01,0x00
	.byte	0xff,0xfe,0x02,0x01,0x00,0xff,0xfe,0x00
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mldsa_extract_coeffs_eta2_neon_lim, %object
	.size	L_mldsa_extract_coeffs_eta2_neon_lim, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_extract_coeffs_eta2_neon_lim:
	.byte	0x0f,0x0f,0x0f,0x0f,0x0f,0x0f,0x0f,0x0f
	.byte	0x0f,0x0f,0x0f,0x0f,0x0f,0x0f,0x0f,0x0f
#ifndef __APPLE__
	.text
	.section	.rodata
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
	.section	.rodata
	.type	L_mldsa_extract_coeffs_eta2_neon_idx, %object
	.size	L_mldsa_extract_coeffs_eta2_neon_idx, 256
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
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
#ifndef __APPLE__
.text
.globl	mldsa_extract_coeffs_eta2_neon
WC_ASM_ATT_HIDDEN(mldsa_extract_coeffs_eta2_neon)
.type	mldsa_extract_coeffs_eta2_neon,@function
.align	2
mldsa_extract_coeffs_eta2_neon:
#else
.section	__TEXT,__text
.globl	_mldsa_extract_coeffs_eta2_neon
WC_ASM_ATT_HIDDEN(_mldsa_extract_coeffs_eta2_neon)
.p2align	2
_mldsa_extract_coeffs_eta2_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
	stp	d12, d13, [x29, #48]
	stp	d14, d15, [x29, #64]
#ifndef __APPLE__
	adrp x4, L_mldsa_extract_coeffs_eta2_neon_map
	add  x4, x4, :lo12:L_mldsa_extract_coeffs_eta2_neon_map
#else
	adrp x4, L_mldsa_extract_coeffs_eta2_neon_map@PAGE
	add  x4, x4, L_mldsa_extract_coeffs_eta2_neon_map@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x5, L_mldsa_extract_coeffs_eta2_neon_lim
	add  x5, x5, :lo12:L_mldsa_extract_coeffs_eta2_neon_lim
#else
	adrp x5, L_mldsa_extract_coeffs_eta2_neon_lim@PAGE
	add  x5, x5, L_mldsa_extract_coeffs_eta2_neon_lim@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x6, L_mldsa_extract_coeffs_eta2_neon_bits
	add  x6, x6, :lo12:L_mldsa_extract_coeffs_eta2_neon_bits
#else
	adrp x6, L_mldsa_extract_coeffs_eta2_neon_bits@PAGE
	add  x6, x6, L_mldsa_extract_coeffs_eta2_neon_bits@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x7, L_mldsa_extract_coeffs_eta2_neon_idx
	add  x7, x7, :lo12:L_mldsa_extract_coeffs_eta2_neon_idx
#else
	adrp x7, L_mldsa_extract_coeffs_eta2_neon_idx@PAGE
	add  x7, x7, L_mldsa_extract_coeffs_eta2_neon_idx@PAGEOFF
#endif /* __APPLE__ */
	ldr	q2, [x4]
	ldr	q0, [x5]
	ldr	q1, [x6]
	ldr	w8, [x3]
	add	x2, x2, x8, lsl 2
L_mldsa_extract_coeffs_eta2_neon_wide:
	subs	wzr, w1, #8
	blt	L_mldsa_extract_coeffs_eta2_neon_tail
	subs	wzr, w8, #0xf0
	bgt	L_mldsa_extract_coeffs_eta2_neon_tail
	ldr	d3, [x0]
	movi	v18.16b, #15
	ushr	v5.16b, v3.16b, #4
	and	v4.16b, v3.16b, v18.16b
	zip1	v3.16b, v4.16b, v5.16b
	tbl	v6.16b, {v2.16b}, v3.16b
	cmhi	v8.16b, v0.16b, v3.16b
	sxtl	v7.8h, v6.8b
	sxtl2	v18.8h, v6.16b
	sxtl	v10.4s, v7.4h
	sxtl2	v11.4s, v7.8h
	sxtl	v12.4s, v18.4h
	sxtl2	v13.4s, v18.8h
	sxtl	v9.8h, v8.8b
	sxtl2	v18.8h, v8.16b
	sxtl	v14.4s, v9.4h
	sxtl2	v15.4s, v9.8h
	sxtl	v16.4s, v18.4h
	sxtl2	v17.4s, v18.8h
	ushr	v18.4s, v14.4s, #31
	addv	s18, v18.4s
	mov	w10, v18.s[0]
	and	v18.16b, v14.16b, v1.16b
	addv	s18, v18.4s
	mov	w9, v18.s[0]
	lsl	x9, x9, #4
	ldr	q18, [x7, x9]
	tbl	v10.16b, {v10.16b}, v18.16b
	str	q10, [x2]
	add	x2, x2, x10, lsl 2
	add	x8, x8, x10
	ushr	v18.4s, v15.4s, #31
	addv	s18, v18.4s
	mov	w10, v18.s[0]
	and	v18.16b, v15.16b, v1.16b
	addv	s18, v18.4s
	mov	w9, v18.s[0]
	lsl	x9, x9, #4
	ldr	q18, [x7, x9]
	tbl	v11.16b, {v11.16b}, v18.16b
	str	q11, [x2]
	add	x2, x2, x10, lsl 2
	add	x8, x8, x10
	ushr	v18.4s, v16.4s, #31
	addv	s18, v18.4s
	mov	w10, v18.s[0]
	and	v18.16b, v16.16b, v1.16b
	addv	s18, v18.4s
	mov	w9, v18.s[0]
	lsl	x9, x9, #4
	ldr	q18, [x7, x9]
	tbl	v12.16b, {v12.16b}, v18.16b
	str	q12, [x2]
	add	x2, x2, x10, lsl 2
	add	x8, x8, x10
	ushr	v18.4s, v17.4s, #31
	addv	s18, v18.4s
	mov	w10, v18.s[0]
	and	v18.16b, v17.16b, v1.16b
	addv	s18, v18.4s
	mov	w9, v18.s[0]
	lsl	x9, x9, #4
	ldr	q18, [x7, x9]
	tbl	v13.16b, {v13.16b}, v18.16b
	str	q13, [x2]
	add	x2, x2, x10, lsl 2
	add	x8, x8, x10
	add	x0, x0, #8
	sub	w1, w1, #8
	b	L_mldsa_extract_coeffs_eta2_neon_wide
L_mldsa_extract_coeffs_eta2_neon_tail:
	subs	wzr, w1, #0
	beq	L_mldsa_extract_coeffs_eta2_neon_done
	subs	wzr, w8, #0x100
	beq	L_mldsa_extract_coeffs_eta2_neon_done
	ldrb	w11, [x0]
	add	x0, x0, #1
	sub	w1, w1, #1
	and	w12, w11, #15
	subs	wzr, w12, #15
	bcs	L_mldsa_extract_coeffs_eta2_neon_skip_lo
	ldrsb	w12, [x4, x12]
	str	w12, [x2]
	add	x2, x2, #4
	add	x8, x8, #1
	subs	wzr, w8, #0x100
	beq	L_mldsa_extract_coeffs_eta2_neon_done
L_mldsa_extract_coeffs_eta2_neon_skip_lo:
	lsr	w12, w11, #4
	subs	wzr, w12, #15
	bcs	L_mldsa_extract_coeffs_eta2_neon_skip_hi
	ldrsb	w12, [x4, x12]
	str	w12, [x2]
	add	x2, x2, #4
	add	x8, x8, #1
L_mldsa_extract_coeffs_eta2_neon_skip_hi:
	b	L_mldsa_extract_coeffs_eta2_neon_tail
L_mldsa_extract_coeffs_eta2_neon_done:
	str	w8, [x3]
	ldp	d8, d9, [x29, #16]
	ldp	d10, d11, [x29, #32]
	ldp	d12, d13, [x29, #48]
	ldp	d14, d15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
#ifndef __APPLE__
	.size	mldsa_extract_coeffs_eta2_neon,.-mldsa_extract_coeffs_eta2_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mldsa_extract_coeffs_eta4_neon_map, %object
	.size	L_mldsa_extract_coeffs_eta4_neon_map, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_extract_coeffs_eta4_neon_map:
	.byte	0x04,0x03,0x02,0x01,0x00,0xff,0xfe,0xfd
	.byte	0xfc,0x00,0x00,0x00,0x00,0x00,0x00,0x00
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mldsa_extract_coeffs_eta4_neon_lim, %object
	.size	L_mldsa_extract_coeffs_eta4_neon_lim, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_extract_coeffs_eta4_neon_lim:
	.byte	0x09,0x09,0x09,0x09,0x09,0x09,0x09,0x09
	.byte	0x09,0x09,0x09,0x09,0x09,0x09,0x09,0x09
#ifndef __APPLE__
	.text
	.section	.rodata
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
	.section	.rodata
	.type	L_mldsa_extract_coeffs_eta4_neon_idx, %object
	.size	L_mldsa_extract_coeffs_eta4_neon_idx, 256
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
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
#ifndef __APPLE__
.text
.globl	mldsa_extract_coeffs_eta4_neon
WC_ASM_ATT_HIDDEN(mldsa_extract_coeffs_eta4_neon)
.type	mldsa_extract_coeffs_eta4_neon,@function
.align	2
mldsa_extract_coeffs_eta4_neon:
#else
.section	__TEXT,__text
.globl	_mldsa_extract_coeffs_eta4_neon
WC_ASM_ATT_HIDDEN(_mldsa_extract_coeffs_eta4_neon)
.p2align	2
_mldsa_extract_coeffs_eta4_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
	stp	d12, d13, [x29, #48]
	stp	d14, d15, [x29, #64]
#ifndef __APPLE__
	adrp x4, L_mldsa_extract_coeffs_eta4_neon_map
	add  x4, x4, :lo12:L_mldsa_extract_coeffs_eta4_neon_map
#else
	adrp x4, L_mldsa_extract_coeffs_eta4_neon_map@PAGE
	add  x4, x4, L_mldsa_extract_coeffs_eta4_neon_map@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x5, L_mldsa_extract_coeffs_eta4_neon_lim
	add  x5, x5, :lo12:L_mldsa_extract_coeffs_eta4_neon_lim
#else
	adrp x5, L_mldsa_extract_coeffs_eta4_neon_lim@PAGE
	add  x5, x5, L_mldsa_extract_coeffs_eta4_neon_lim@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x6, L_mldsa_extract_coeffs_eta4_neon_bits
	add  x6, x6, :lo12:L_mldsa_extract_coeffs_eta4_neon_bits
#else
	adrp x6, L_mldsa_extract_coeffs_eta4_neon_bits@PAGE
	add  x6, x6, L_mldsa_extract_coeffs_eta4_neon_bits@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x7, L_mldsa_extract_coeffs_eta4_neon_idx
	add  x7, x7, :lo12:L_mldsa_extract_coeffs_eta4_neon_idx
#else
	adrp x7, L_mldsa_extract_coeffs_eta4_neon_idx@PAGE
	add  x7, x7, L_mldsa_extract_coeffs_eta4_neon_idx@PAGEOFF
#endif /* __APPLE__ */
	ldr	q2, [x4]
	ldr	q0, [x5]
	ldr	q1, [x6]
	ldr	w8, [x3]
	add	x2, x2, x8, lsl 2
L_mldsa_extract_coeffs_eta4_neon_wide:
	subs	wzr, w1, #8
	blt	L_mldsa_extract_coeffs_eta4_neon_tail
	subs	wzr, w8, #0xf0
	bgt	L_mldsa_extract_coeffs_eta4_neon_tail
	ldr	d3, [x0]
	movi	v18.16b, #15
	ushr	v5.16b, v3.16b, #4
	and	v4.16b, v3.16b, v18.16b
	zip1	v3.16b, v4.16b, v5.16b
	tbl	v6.16b, {v2.16b}, v3.16b
	cmhi	v8.16b, v0.16b, v3.16b
	sxtl	v7.8h, v6.8b
	sxtl2	v18.8h, v6.16b
	sxtl	v10.4s, v7.4h
	sxtl2	v11.4s, v7.8h
	sxtl	v12.4s, v18.4h
	sxtl2	v13.4s, v18.8h
	sxtl	v9.8h, v8.8b
	sxtl2	v18.8h, v8.16b
	sxtl	v14.4s, v9.4h
	sxtl2	v15.4s, v9.8h
	sxtl	v16.4s, v18.4h
	sxtl2	v17.4s, v18.8h
	ushr	v18.4s, v14.4s, #31
	addv	s18, v18.4s
	mov	w10, v18.s[0]
	and	v18.16b, v14.16b, v1.16b
	addv	s18, v18.4s
	mov	w9, v18.s[0]
	lsl	x9, x9, #4
	ldr	q18, [x7, x9]
	tbl	v10.16b, {v10.16b}, v18.16b
	str	q10, [x2]
	add	x2, x2, x10, lsl 2
	add	x8, x8, x10
	ushr	v18.4s, v15.4s, #31
	addv	s18, v18.4s
	mov	w10, v18.s[0]
	and	v18.16b, v15.16b, v1.16b
	addv	s18, v18.4s
	mov	w9, v18.s[0]
	lsl	x9, x9, #4
	ldr	q18, [x7, x9]
	tbl	v11.16b, {v11.16b}, v18.16b
	str	q11, [x2]
	add	x2, x2, x10, lsl 2
	add	x8, x8, x10
	ushr	v18.4s, v16.4s, #31
	addv	s18, v18.4s
	mov	w10, v18.s[0]
	and	v18.16b, v16.16b, v1.16b
	addv	s18, v18.4s
	mov	w9, v18.s[0]
	lsl	x9, x9, #4
	ldr	q18, [x7, x9]
	tbl	v12.16b, {v12.16b}, v18.16b
	str	q12, [x2]
	add	x2, x2, x10, lsl 2
	add	x8, x8, x10
	ushr	v18.4s, v17.4s, #31
	addv	s18, v18.4s
	mov	w10, v18.s[0]
	and	v18.16b, v17.16b, v1.16b
	addv	s18, v18.4s
	mov	w9, v18.s[0]
	lsl	x9, x9, #4
	ldr	q18, [x7, x9]
	tbl	v13.16b, {v13.16b}, v18.16b
	str	q13, [x2]
	add	x2, x2, x10, lsl 2
	add	x8, x8, x10
	add	x0, x0, #8
	sub	w1, w1, #8
	b	L_mldsa_extract_coeffs_eta4_neon_wide
L_mldsa_extract_coeffs_eta4_neon_tail:
	subs	wzr, w1, #0
	beq	L_mldsa_extract_coeffs_eta4_neon_done
	subs	wzr, w8, #0x100
	beq	L_mldsa_extract_coeffs_eta4_neon_done
	ldrb	w11, [x0]
	add	x0, x0, #1
	sub	w1, w1, #1
	and	w12, w11, #15
	subs	wzr, w12, #9
	bcs	L_mldsa_extract_coeffs_eta4_neon_skip_lo
	ldrsb	w12, [x4, x12]
	str	w12, [x2]
	add	x2, x2, #4
	add	x8, x8, #1
	subs	wzr, w8, #0x100
	beq	L_mldsa_extract_coeffs_eta4_neon_done
L_mldsa_extract_coeffs_eta4_neon_skip_lo:
	lsr	w12, w11, #4
	subs	wzr, w12, #9
	bcs	L_mldsa_extract_coeffs_eta4_neon_skip_hi
	ldrsb	w12, [x4, x12]
	str	w12, [x2]
	add	x2, x2, #4
	add	x8, x8, #1
L_mldsa_extract_coeffs_eta4_neon_skip_hi:
	b	L_mldsa_extract_coeffs_eta4_neon_tail
L_mldsa_extract_coeffs_eta4_neon_done:
	str	w8, [x3]
	ldp	d8, d9, [x29, #16]
	ldp	d10, d11, [x29, #32]
	ldp	d12, d13, [x29, #48]
	ldp	d14, d15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
#ifndef __APPLE__
	.size	mldsa_extract_coeffs_eta4_neon,.-mldsa_extract_coeffs_eta4_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mldsa_rej_uniform_mask, %object
	.size	L_mldsa_rej_uniform_mask, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_rej_uniform_mask:
	.long	0x007fffff,0x007fffff,0x007fffff,0x007fffff
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mldsa_rej_uniform_shuffle0, %object
	.size	L_mldsa_rej_uniform_shuffle0, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_rej_uniform_shuffle0:
	.byte	0x00,0x01,0x02,0xff,0x03,0x04,0x05,0xff
	.byte	0x06,0x07,0x08,0xff,0x09,0x0a,0x0b,0xff
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mldsa_rej_uniform_shuffle1, %object
	.size	L_mldsa_rej_uniform_shuffle1, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_rej_uniform_shuffle1:
	.byte	0x0c,0x0d,0x0e,0xff,0x0f,0x10,0x11,0xff
	.byte	0x12,0x13,0x14,0xff,0x15,0x16,0x17,0xff
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mldsa_rej_uniform_bits, %object
	.size	L_mldsa_rej_uniform_bits, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_rej_uniform_bits:
	.long	0x00000001,0x00000002,0x00000004,0x00000008
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mldsa_rej_uniform_indices, %object
	.size	L_mldsa_rej_uniform_indices, 256
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mldsa_rej_uniform_indices:
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
#ifndef __APPLE__
.text
.globl	mldsa_rej_uniform_neon
WC_ASM_ATT_HIDDEN(mldsa_rej_uniform_neon)
.type	mldsa_rej_uniform_neon,@function
.align	2
mldsa_rej_uniform_neon:
#else
.section	__TEXT,__text
.globl	_mldsa_rej_uniform_neon
WC_ASM_ATT_HIDDEN(_mldsa_rej_uniform_neon)
.p2align	2
_mldsa_rej_uniform_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-64]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
	stp	d12, d13, [x29, #48]
#ifndef __APPLE__
	adrp x4, L_mldsa_rej_uniform_mask
	add  x4, x4, :lo12:L_mldsa_rej_uniform_mask
#else
	adrp x4, L_mldsa_rej_uniform_mask@PAGE
	add  x4, x4, L_mldsa_rej_uniform_mask@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x5, L_mldsa_aarch64_q
	add  x5, x5, :lo12:L_mldsa_aarch64_q
#else
	adrp x5, L_mldsa_aarch64_q@PAGE
	add  x5, x5, L_mldsa_aarch64_q@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x6, L_mldsa_rej_uniform_bits
	add  x6, x6, :lo12:L_mldsa_rej_uniform_bits
#else
	adrp x6, L_mldsa_rej_uniform_bits@PAGE
	add  x6, x6, L_mldsa_rej_uniform_bits@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x7, L_mldsa_rej_uniform_indices
	add  x7, x7, :lo12:L_mldsa_rej_uniform_indices
#else
	adrp x7, L_mldsa_rej_uniform_indices@PAGE
	add  x7, x7, L_mldsa_rej_uniform_indices@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x8, L_mldsa_rej_uniform_shuffle0
	add  x8, x8, :lo12:L_mldsa_rej_uniform_shuffle0
#else
	adrp x8, L_mldsa_rej_uniform_shuffle0@PAGE
	add  x8, x8, L_mldsa_rej_uniform_shuffle0@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x9, L_mldsa_rej_uniform_shuffle1
	add  x9, x9, :lo12:L_mldsa_rej_uniform_shuffle1
#else
	adrp x9, L_mldsa_rej_uniform_shuffle1@PAGE
	add  x9, x9, L_mldsa_rej_uniform_shuffle1@PAGEOFF
#endif /* __APPLE__ */
	movz	x15, #0xe001
	eor	v1.16b, v1.16b, v1.16b
	eor	v12.16b, v12.16b, v12.16b
	eor	v13.16b, v13.16b, v13.16b
	movk	x15, #0x7f, lsl 16
	eor	x14, x14, x14
	eor	v10.16b, v10.16b, v10.16b
	eor	v11.16b, v11.16b, v11.16b
	ldr	q0, [x4]
	ldr	q3, [x5]
	ldr	q2, [x6]
	ldr	q4, [x8]
	ldr	q5, [x9]
	subs	wzr, w1, #0
	beq	L_mldsa_rej_uniform_done
	subs	wzr, w1, #16
	blt	L_mldsa_rej_uniform_loop_2
L_mldsa_rej_uniform_loop_8:
	ldr	q6, [x2]
	ldr	d7, [x2, #16]
	add	x2, x2, #24
	tbl	v8.16b, {v6.16b, v7.16b}, v4.16b
	tbl	v9.16b, {v6.16b, v7.16b}, v5.16b
	and	v6.16b, v8.16b, v0.16b
	and	v7.16b, v9.16b, v0.16b
	cmgt	v8.4s, v3.4s, v6.4s
	cmgt	v9.4s, v3.4s, v7.4s
	ushr	v12.4s, v8.4s, #31
	ushr	v13.4s, v9.4s, #31
	addv	s12, v12.4s
	addv	s13, v13.4s
	mov	x12, v12.d[0]
	mov	x13, v13.d[0]
	and	v10.16b, v8.16b, v2.16b
	and	v11.16b, v9.16b, v2.16b
	addv	s10, v10.4s
	addv	s11, v11.4s
	mov	w10, v10.s[0]
	mov	w11, v11.s[0]
	lsl	w10, w10, #4
	lsl	w11, w11, #4
	ldr	q10, [x7, x10]
	ldr	q11, [x7, x11]
	tbl	v8.16b, {v6.16b}, v10.16b
	tbl	v9.16b, {v7.16b}, v11.16b
	str	q8, [x0]
	add	x0, x0, x12, lsl 2
	add	x14, x14, x12
	str	q9, [x0]
	add	x0, x0, x13, lsl 2
	add	x14, x14, x13
	subs	w3, w3, #24
	beq	L_mldsa_rej_uniform_done
	sub	w12, w1, w14
	subs	x12, x12, #8
	blt	L_mldsa_rej_uniform_loop_2
	b	L_mldsa_rej_uniform_loop_8
L_mldsa_rej_uniform_loop_2:
	subs	w12, w1, w14
	beq	L_mldsa_rej_uniform_done
	subs	x12, x12, #2
	blt	L_mldsa_rej_uniform_loop_lt_2
	ldr	x4, [x2], #6
	lsr	x5, x4, #24
	and	x4, x4, #0x7fffff
	and	x5, x5, #0x7fffff
	str	w4, [x0]
	add	x6, x0, #4
	subs	xzr, x4, x15
	csel	x0, x6, x0, lt
	cinc	x14, x14, lt
	str	w5, [x0]
	add	x6, x0, #4
	subs	xzr, x5, x15
	csel	x0, x6, x0, lt
	cinc	x14, x14, lt
	subs	w3, w3, #6
	beq	L_mldsa_rej_uniform_done
	b	L_mldsa_rej_uniform_loop_2
L_mldsa_rej_uniform_loop_lt_2:
	ldr	x4, [x2], #6
	lsr	x5, x4, #24
	and	x4, x4, #0x7fffff
	and	x5, x5, #0x7fffff
	str	w4, [x0]
	add	x6, x0, #4
	subs	xzr, x4, x15
	csel	x0, x6, x0, lt
	cinc	x14, x14, lt
	subs	wzr, w1, w14
	beq	L_mldsa_rej_uniform_done
	str	w5, [x0]
	add	x6, x0, #4
	subs	xzr, x5, x15
	csel	x0, x6, x0, lt
	cinc	x14, x14, lt
	subs	wzr, w1, w14
	beq	L_mldsa_rej_uniform_done
	subs	w3, w3, #6
	beq	L_mldsa_rej_uniform_done
	b	L_mldsa_rej_uniform_loop_lt_2
L_mldsa_rej_uniform_done:
	mov	x0, x14
	ldp	d8, d9, [x29, #16]
	ldp	d10, d11, [x29, #32]
	ldp	d12, d13, [x29, #48]
	ldp	x29, x30, [sp], #0x40
	ret
#ifndef __APPLE__
	.size	mldsa_rej_uniform_neon,.-mldsa_rej_uniform_neon
#endif /* __APPLE__ */
#endif /* WOLFSSL_HAVE_MLDSA */
#endif /* __aarch64__ */
#endif /* WOLFSSL_ARMASM */

#if defined(__linux__) && defined(__ELF__)
.section	.note.GNU-stack,"",%progbits
#endif
#endif /* !WOLFSSL_ARMASM_INLINE */
