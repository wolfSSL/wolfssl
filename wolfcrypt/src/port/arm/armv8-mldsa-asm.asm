; /* armv8-mldsa-asm
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
;   ruby ./mldsa/mldsa.rb arm64 \
;       ../wolfssl/wolfcrypt/src/port/arm/armv8-mldsa-asm.asm
	IF :DEF:WOLFSSL_HAVE_MLDSA
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_aarch64_consts
	DCD	0x007fe001, 0x03802001, 0x00400000, 0x00000000
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_aarch64_zetas
	DCD	0xffff5c06, 0x000064f7, 0xffd83102, 0xfff81503
	DCD	0x00039e44, 0xfff42118, 0xfff2a128, 0x00071e24
	DCD	0x001bde2b, 0x0023e92b, 0xfffa84ad, 0xffe0147f
	DCD	0x002f9a75, 0xffd3fb09, 0x002f7a49, 0x0028e527
	DCD	0x00299658, 0x000fa070, 0xffef85a4, 0x0036b788
	DCD	0xfff79d90, 0xffeeeaa0, 0x0027f968, 0xffdfd37b
	DCD	0xffdfadd6, 0xffc51ae7, 0xffeaa4f7, 0xffcdfc98
	DCD	0x001ad035, 0xffffb422, 0x003d3201, 0x000445c5
	DCD	0x00294a67, 0x00017620, 0x002ef4cd, 0x0035dec5
	DCD	0xffe6a503, 0xffc9302c, 0xffd947d4, 0x003bbeaf
	DCD	0xffc51585, 0xffd18e7c, 0x00368a96, 0xffd43e41
	DCD	0x00360400, 0xfffb6a4d, 0x0023d69c, 0xfff7c55d
	DCD	0xffe6123d, 0xffe6ead6, 0x00357e1e, 0xffc5af59
	DCD	0x0035843f, 0xffdf5617, 0xffe7945c, 0x0038738c
	DCD	0x000c63a8, 0x00081b9a, 0x000e8f76, 0x003b3853
	DCD	0x003b8534, 0xffd8fc30, 0x001f9d54, 0xffd54f2d
	DCD	0xffc406e5, 0xffc406e5, 0xffe8ac81, 0xffe8ac81
	DCD	0xffc7e1cf, 0xffc7e1cf, 0xffd19819, 0xffd19819
	DCD	0xffe9d65d, 0xffe9d65d, 0x003509ee, 0x003509ee
	DCD	0x002135c7, 0x002135c7, 0xffe7cfbb, 0xffe7cfbb
	DCD	0xffeccf75, 0xffeccf75, 0x001d9772, 0x001d9772
	DCD	0xffc1b072, 0xffc1b072, 0xfff0bcf6, 0xfff0bcf6
	DCD	0xffcf5280, 0xffcf5280, 0xffcfd2ae, 0xffcfd2ae
	DCD	0xffc890e0, 0xffc890e0, 0x0001efca, 0x0001efca
	DCD	0x003410f2, 0x003410f2, 0xfff0fe85, 0xfff0fe85
	DCD	0x0020c638, 0x0020c638, 0x00296e9f, 0x00296e9f
	DCD	0xffd2b7a3, 0xffd2b7a3, 0xffc7a44b, 0xffc7a44b
	DCD	0xfff9ba6d, 0xfff9ba6d, 0xffda3409, 0xffda3409
	DCD	0xfff5c282, 0xfff5c282, 0xffed4113, 0xffed4113
	DCD	0xffffa63b, 0xffffa63b, 0xffec09f7, 0xffec09f7
	DCD	0xfffa2bdd, 0xfffa2bdd, 0x001495d4, 0x001495d4
	DCD	0x001c4563, 0x001c4563, 0xffea2c62, 0xffea2c62
	DCD	0xffccfbe9, 0xffccfbe9, 0x00040af0, 0x00040af0
	DCD	0x0007c417, 0x0007c417, 0x002f4588, 0x002f4588
	DCD	0x0000ad00, 0x0000ad00, 0xffef36be, 0xffef36be
	DCD	0x000dcd44, 0x000dcd44, 0x003c675a, 0x003c675a
	DCD	0xffc72bca, 0xffc72bca, 0xffffde7e, 0xffffde7e
	DCD	0x00193948, 0x00193948, 0xffce69c0, 0xffce69c0
	DCD	0x0024756c, 0x0024756c, 0xfffcc7df, 0xfffcc7df
	DCD	0x000b98a1, 0x000b98a1, 0xffebe808, 0xffebe808
	DCD	0x0002e46c, 0x0002e46c, 0xffc9c808, 0xffc9c808
	DCD	0x003036c2, 0x003036c2, 0xffe3bff6, 0xffe3bff6
	DCD	0xffdb3c93, 0xffdb3c93, 0xfffd4ae0, 0xfffd4ae0
	DCD	0x00141305, 0x00141305, 0x00147792, 0x00147792
	DCD	0x00139e25, 0x00139e25, 0xffe7d0e0, 0xffe7d0e0
	DCD	0xfff39944, 0xfff39944, 0xffea0802, 0xffea0802
	DCD	0xffd1eea2, 0xffd1eea2, 0xffc4c79c, 0xffc4c79c
	DCD	0xffc8a057, 0xffc8a057, 0x003a97d9, 0x003a97d9
	DCD	0x001fea93, 0x0033ff5a, 0x002358d4, 0x003a41f8
	DCD	0xffccff72, 0x00223dfb, 0xffdaab9f, 0xffc9a422
	DCD	0x000412f5, 0x00252587, 0xffed24f0, 0x00359b5d
	DCD	0xffca48a0, 0xffc6a2fc, 0xffedbb56, 0xffcf45de
	DCD	0x000dbe5e, 0x001c5e1a, 0x000de0e6, 0x000c7f5a
	DCD	0x00078f83, 0xffe7628a, 0xffff5704, 0xfff806fc
	DCD	0xfff60021, 0xffd05af6, 0x001f0084, 0x0030ef86
	DCD	0xffc9b97d, 0xfff7fcd6, 0xfff44592, 0xffc921c2
	DCD	0x00053919, 0x0004610c, 0xffdacd41, 0x003eb01b
	DCD	0x003472e7, 0xffcd003b, 0x001a7cc7, 0x00031924
	DCD	0x002b5ee5, 0x00291199, 0xffd87a3a, 0x00134d71
	DCD	0x003de11c, 0x00130984, 0x0025f051, 0x00185a46
	DCD	0xffc68518, 0x001314be, 0x00283891, 0xffc9db90
	DCD	0xffd25089, 0x001c853f, 0x001d0b4b, 0xffeff6a6
	DCD	0xffeba8be, 0x0012e11b, 0xffcd5e3e, 0xffea2d2f
	DCD	0xfff91de4, 0x001406c7, 0x00327283, 0xffe20d6e
	DCD	0xffec7953, 0x001d4099, 0xffd92578, 0xffeb05ad
	DCD	0x0016e405, 0x000bdbe7, 0x00221de8, 0x0033f8cf
	DCD	0xfff7b934, 0xffd4ca0c, 0xffe67ff8, 0xffe3d157
	DCD	0xffd8911b, 0xffc72c12, 0x000910d8, 0xffc65e1f
	DCD	0xffe14658, 0x00251d8b, 0x002573b7, 0xfffd7c8f
	DCD	0x001ddd98, 0x00336898, 0x0002d4bb, 0xffed93a7
	DCD	0xffcf6cbe, 0x00027c1c, 0x0018aa08, 0x002dfd71
	DCD	0x000c5ca5, 0x0019379a, 0xffc7a167, 0xffe48c3d
	DCD	0xffd1a13c, 0x0035c539, 0x003b0115, 0x00041dc0
	DCD	0x0021c4f7, 0xfff11bf4, 0x001a35e7, 0x0007340e
	DCD	0xfff97d45, 0x001a4cd0, 0xffe47cae, 0x001d2668
	DCD	0xffe68e98, 0xffef2633, 0xfffc05da, 0xffc57fdb
	DCD	0xffd32764, 0xffdde1af, 0xfff993dd, 0xffdd1d09
	DCD	0x0002cc93, 0xfff11805, 0x00189c2a, 0xffc9e5a9
	DCD	0xfff78a50, 0x003bcf2c, 0xffff434e, 0xffeb36df
	DCD	0x003c15ca, 0x00155e68, 0xfff316b6, 0x001e29ce
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_aarch64_zetas_qinv
	DCD	0x00801c06, 0x6d1f44f7, 0x8cf87102, 0x8d187503
	DCD	0x61cc1e44, 0x58172118, 0x6017a128, 0x61cb9e24
	DCD	0x12613e2b, 0x93c9492b, 0xae1024ad, 0xbeeff47f
	DCD	0x8cfe3a75, 0x1eb51b09, 0xeef89a49, 0x254dc527
	DCD	0x66f49658, 0x7c1da070, 0xaea405a4, 0x3327b788
	DCD	0x6ba99d90, 0x0d42eaa0, 0xeb54f968, 0x28cf337b
	DCD	0x629a6dd6, 0xcba1fae7, 0xb50984f7, 0xd360fc98
	DCD	0x13a17035, 0x6d83f422, 0xa9fd5201, 0xba3ce5c5
	DCD	0x91f62a67, 0x9ec57620, 0xac4894cd, 0x6d8e7ec5
	DCD	0x5f070503, 0xbfceb02c, 0x8ed3c7d4, 0xdc919eaf
	DCD	0xf3f5b585, 0xe3a10e7c, 0xde894a96, 0x6b1c5e41
	DCD	0xc0b60400, 0x7ac50a4d, 0x9cf7569c, 0xbe23655d
	DCD	0x97adb23d, 0xca41aad6, 0x18f93e1e, 0x6d30cf59
	DCD	0x8d3d643f, 0x3b223617, 0x3473145c, 0x78a9f38c
	DCD	0x588163a8, 0x9e7b5b9a, 0xeefd4f76, 0x89c59853
	DCD	0xa6e20534, 0xc75efc30, 0x99ca1d54, 0xc73aef2d
	DCD	0xa220a6e5, 0xa220a6e5, 0xd8f8cc81, 0xd8f8cc81
	DCD	0x5081c1cf, 0x5081c1cf, 0x8a54b819, 0x8a54b819
	DCD	0x8035765d, 0x8035765d, 0x6272c9ee, 0x6272c9ee
	DCD	0x5f5a15c7, 0x5f5a15c7, 0x085f2fbb, 0x085f2fbb
	DCD	0xb35b6f75, 0xb35b6f75, 0xc20bd772, 0xc20bd772
	DCD	0xc4cff072, 0xc4cff072, 0x748f7cf6, 0x748f7cf6
	DCD	0xaa1f5280, 0xaa1f5280, 0x5b2592ae, 0x5b2592ae
	DCD	0x21e490e0, 0x21e490e0, 0x80fb2fca, 0x80fb2fca
	DCD	0xd15250f2, 0xd15250f2, 0xf1419e85, 0xf1419e85
	DCD	0xdce7c638, 0xdce7c638, 0x5a7d4e9f, 0x5a7d4e9f
	DCD	0x114717a3, 0x114717a3, 0xfad1044b, 0xfad1044b
	DCD	0xb4c75a6d, 0xb4c75a6d, 0x65db5409, 0x65db5409
	DCD	0x7f460282, 0x7f460282, 0x6a8fa113, 0x6a8fa113
	DCD	0xc347063b, 0xc347063b, 0x61aae9f7, 0x61aae9f7
	DCD	0xcaf5cbdd, 0xcaf5cbdd, 0xf8cf15d4, 0xf8cf15d4
	DCD	0x6348a563, 0x6348a563, 0x9c766c62, 0x9c766c62
	DCD	0x4eca1be9, 0x4eca1be9, 0xc9620af0, 0xc9620af0
	DCD	0x490aa417, 0x490aa417, 0x44e04588, 0x44e04588
	DCD	0x95a0ad00, 0x95a0ad00, 0x7fc6f6be, 0x7fc6f6be
	DCD	0x27b64d44, 0x27b64d44, 0x4827a75a, 0x4827a75a
	DCD	0x28406bca, 0x28406bca, 0xb4cf9e7e, 0xb4cf9e7e
	DCD	0xa3423948, 0xa3423948, 0xed0669c0, 0xed0669c0
	DCD	0x88d1f56c, 0x88d1f56c, 0x2578a7df, 0x2578a7df
	DCD	0xa69fb8a1, 0xa69fb8a1, 0x98ece808, 0x98ece808
	DCD	0xd690646c, 0xd690646c, 0x54cac808, 0x54cac808
	DCD	0xae0876c2, 0xae0876c2, 0x54e27ff6, 0x54e27ff6
	DCD	0x69ed9c93, 0x69ed9c93, 0xb9594ae0, 0xb9594ae0
	DCD	0x13f4b305, 0x13f4b305, 0x0e06b792, 0x0e06b792
	DCD	0xf5583e25, 0xf5583e25, 0x0a03d0e0, 0x0a03d0e0
	DCD	0xe11c1944, 0xe11c1944, 0x47ea4802, 0x47ea4802
	DCD	0x74a62ea2, 0x74a62ea2, 0x3ab8479c, 0x3ab8479c
	DCD	0x44538057, 0x44538057, 0xcab5b7d9, 0xcab5b7d9
	DCD	0xfff24a93, 0x3b1f3f5a, 0x513dd8d4, 0x2c7941f8
	DCD	0xaebb3f72, 0x36619dfb, 0x01ce8b9f, 0xab4de422
	DCD	0xdbe2b2f5, 0xfd560587, 0xec8b24f0, 0x79213b5d
	DCD	0x78de48a0, 0x462622fc, 0x64587b56, 0x718b05de
	DCD	0x00d97e5e, 0xe6df9e1a, 0xe12aa0e6, 0x4af7bf5a
	DCD	0x3c77ef83, 0xcf38a28a, 0x78dfd704, 0x72d786fc
	DCD	0x337a2021, 0x682f1af6, 0xae2f8084, 0x7321af86
	DCD	0x6c79597d, 0xec92bcd6, 0x07a68592, 0x4b0161c2
	DCD	0x7ea85919, 0x3625e10c, 0xbd02ed41, 0x34c2101b
	DCD	0xb71152e7, 0x6e54603b, 0x08335cc7, 0x61279924
	DCD	0x8d87fee5, 0xb9dc3199, 0xda1fba3a, 0x75416d71
	DCD	0x9e61611c, 0xaf438984, 0xd9b01051, 0x00611a46
	DCD	0xa4698518, 0xfbaad4be, 0x02ba5891, 0xb33bdb90
	DCD	0x29637089, 0xed44653f, 0x28066b4b, 0x43c4b6a6
	DCD	0x0e0368be, 0x3ab6411b, 0x84951e3e, 0x6a100d2f
	DCD	0xc1b59de4, 0x396ce6c7, 0x1902d283, 0x428fcd6e
	DCD	0x3196d953, 0xbfb06099, 0x48882578, 0x3e20a5ad
	DCD	0xee178405, 0x2408bbe7, 0xefdf1de8, 0x53cdd8cf
	DCD	0x2d1e3934, 0xc3164a0c, 0xb3e57ff8, 0x2a8eb157
	DCD	0xf07bf11b, 0x24496c12, 0x162410d8, 0x380a3e1f
	DCD	0x5cac4658, 0x0a567d8b, 0xaf1c53b7, 0xa40f5c8f
	DCD	0x4fd0dd98, 0x81466898, 0xe91a34bb, 0x7ae273a7
	DCD	0x86672cbe, 0xb185fc1c, 0x3159aa08, 0xcb5c1d71
	DCD	0xcd20fca5, 0xc20c779a, 0xdc748167, 0x66ec2c3d
	DCD	0x85f9213c, 0x005ce539, 0x29dda115, 0xa3bc1dc0
	DCD	0x9940a4f7, 0xf96f9bf4, 0xef5715e7, 0x1788f40e
	DCD	0xa1221d45, 0x21b44cd0, 0xf07a3cae, 0x10ea2668
	DCD	0xe5b98e98, 0x97358633, 0xfbb745da, 0x2e40dfdb
	DCD	0x42bfa764, 0xa093c1af, 0xb7f533dd, 0x42fe3d09
	DCD	0x5c152c93, 0x3471b805, 0xa69ddc2a, 0x0bff05a9
	DCD	0x09418a50, 0x94214f2c, 0x7969034e, 0x734716df
	DCD	0xc5f555ca, 0x17e25e68, 0xdfc9d6b6, 0x1657e9ce
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_aarch64_zetas_inv
	DCD	0xffe1d632, 0x000ce94a, 0xffeaa198, 0xffc3ea36
	DCD	0x0014c921, 0x0000bcb2, 0xffc430d4, 0x000875b0
	DCD	0x00361a57, 0xffe763d6, 0x000ee7fb, 0xfffd336d
	DCD	0x0022e2f7, 0x00066c23, 0x00221e51, 0x002cd89c
	DCD	0x003a8025, 0x0003fa26, 0x0010d9cd, 0x00197168
	DCD	0xffe2d998, 0x001b8352, 0xffe5b330, 0x000682bb
	DCD	0xfff8cbf2, 0xffe5ca19, 0x000ee40c, 0xffde3b09
	DCD	0xfffbe240, 0xffc4feeb, 0xffca3ac7, 0x002e5ec4
	DCD	0x001b73c3, 0x00385e99, 0xffe6c866, 0xfff3a35b
	DCD	0xffd2028f, 0xffe755f8, 0xfffd83e4, 0x00309342
	DCD	0x00126c59, 0xfffd2b45, 0xffcc9768, 0xffe22268
	DCD	0x00028371, 0xffda8c49, 0xffdae275, 0x001eb9a8
	DCD	0x0039a1e1, 0xfff6ef28, 0x0038d3ee, 0x00276ee5
	DCD	0x001c2ea9, 0x00198008, 0x002b35f4, 0x000846cc
	DCD	0xffcc0731, 0xffdde218, 0xfff42419, 0xffe91bfb
	DCD	0x0014fa53, 0x0026da88, 0xffe2bf67, 0x001386ad
	DCD	0x001df292, 0xffcd8d7d, 0xffebf939, 0x0006e21c
	DCD	0x0015d2d1, 0x0032a1c2, 0xffed1ee5, 0x00145742
	DCD	0x0010095a, 0xffe2f4b5, 0xffe37ac1, 0x002daf77
	DCD	0x00362470, 0xffd7c76f, 0xffeceb42, 0x00397ae8
	DCD	0xffe7a5ba, 0xffda0faf, 0xffecf67c, 0xffc21ee4
	DCD	0xffecb28f, 0x002785c6, 0xffd6ee67, 0xffd4a11b
	DCD	0xfffce6dc, 0xffe58339, 0x0032ffc5, 0xffcb8d19
	DCD	0xffc14fe5, 0x002532bf, 0xfffb9ef4, 0xfffac6e7
	DCD	0x0036de3e, 0x000bba6e, 0x0008032a, 0x00364683
	DCD	0xffcf107a, 0xffe0ff7c, 0x002fa50a, 0x0009ffdf
	DCD	0x0007f904, 0x0000a8fc, 0x00189d76, 0xfff8707d
	DCD	0xfff380a6, 0xfff21f1a, 0xffe3a1e6, 0xfff241a2
	DCD	0x0030ba22, 0x001244aa, 0x00395d04, 0x0035b760
	DCD	0xffca64a3, 0x0012db10, 0xffdada79, 0xfffbed0b
	DCD	0x00365bde, 0x00255461, 0xffddc205, 0x0033008e
	DCD	0xffc5be08, 0xffdca72c, 0xffcc00a6, 0xffe0156d
	DCD	0xffc56827, 0xffc56827, 0x00375fa9, 0x00375fa9
	DCD	0x003b3864, 0x003b3864, 0x002e115e, 0x002e115e
	DCD	0x0015f7fe, 0x0015f7fe, 0x000c66bc, 0x000c66bc
	DCD	0x00182f20, 0x00182f20, 0xffec61db, 0xffec61db
	DCD	0xffeb886e, 0xffeb886e, 0xffebecfb, 0xffebecfb
	DCD	0x0002b520, 0x0002b520, 0x0024c36d, 0x0024c36d
	DCD	0x001c400a, 0x001c400a, 0xffcfc93e, 0xffcfc93e
	DCD	0x003637f8, 0x003637f8, 0xfffd1b94, 0xfffd1b94
	DCD	0x001417f8, 0x001417f8, 0xfff4675f, 0xfff4675f
	DCD	0x00033821, 0x00033821, 0xffdb8a94, 0xffdb8a94
	DCD	0x00319640, 0x00319640, 0xffe6c6b8, 0xffe6c6b8
	DCD	0x00002182, 0x00002182, 0x0038d436, 0x0038d436
	DCD	0xffc398a6, 0xffc398a6, 0xfff232bc, 0xfff232bc
	DCD	0x0010c942, 0x0010c942, 0xffff5300, 0xffff5300
	DCD	0xffd0ba78, 0xffd0ba78, 0xfff83be9, 0xfff83be9
	DCD	0xfffbf510, 0xfffbf510, 0x00330417, 0x00330417
	DCD	0x0015d39e, 0x0015d39e, 0xffe3ba9d, 0xffe3ba9d
	DCD	0xffeb6a2c, 0xffeb6a2c, 0x0005d423, 0x0005d423
	DCD	0x0013f609, 0x0013f609, 0x000059c5, 0x000059c5
	DCD	0x0012beed, 0x0012beed, 0x000a3d7e, 0x000a3d7e
	DCD	0x0025cbf7, 0x0025cbf7, 0x00064593, 0x00064593
	DCD	0x00385bb5, 0x00385bb5, 0x002d485d, 0x002d485d
	DCD	0xffd69161, 0xffd69161, 0xffdf39c8, 0xffdf39c8
	DCD	0x000f017b, 0x000f017b, 0xffcbef0e, 0xffcbef0e
	DCD	0xfffe1036, 0xfffe1036, 0x00376f20, 0x00376f20
	DCD	0x00302d52, 0x00302d52, 0x0030ad80, 0x0030ad80
	DCD	0x000f430a, 0x000f430a, 0x003e4f8e, 0x003e4f8e
	DCD	0xffe2688e, 0xffe2688e, 0x0013308b, 0x0013308b
	DCD	0x00183045, 0x00183045, 0xffdeca39, 0xffdeca39
	DCD	0xffcaf612, 0xffcaf612, 0x001629a3, 0x001629a3
	DCD	0x002e67e7, 0x002e67e7, 0x00381e31, 0x00381e31
	DCD	0x0017537f, 0x0017537f, 0x003bf91b, 0x003bf91b
	DCD	0x002ab0d3, 0xffe062ac, 0x002703d0, 0xffc47acc
	DCD	0xffc4c7ad, 0xfff1708a, 0xfff7e466, 0xfff39c58
	DCD	0xffc78c74, 0x00186ba4, 0x0020a9e9, 0xffca7bc1
	DCD	0x003a50a7, 0xffca81e2, 0x0019152a, 0x0019edc3
	DCD	0x00083aa3, 0xffdc2964, 0x000495b3, 0xffc9fc00
	DCD	0x002bc1bf, 0xffc9756a, 0x002e7184, 0x003aea7b
	DCD	0xffc44151, 0x0026b82c, 0x0036cfd4, 0x00195afd
	DCD	0xffca213b, 0xffd10b33, 0xfffe89e0, 0xffd6b599
	DCD	0xfffbba3b, 0xffc2cdff, 0x00004bde, 0xffe52fcb
	DCD	0x00320368, 0x00155b09, 0x003ae519, 0x0020522a
	DCD	0x00202c85, 0xffd80698, 0x00111560, 0x00086270
	DCD	0xffc94878, 0x00107a5c, 0xfff05f90, 0xffd669a8
	DCD	0xffd71ad9, 0xffd085b7, 0x002c04f7, 0xffd0658b
	DCD	0x001feb81, 0x00057b53, 0xffdc16d5, 0xffe421d5
	DCD	0xfff8e1dc, 0x000d5ed8, 0x000bdee8, 0xfffc61bc
	DCD	0x0007eafd, 0x0027cefe, 0x003caa21, 0x0000a3fa
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_aarch64_zetas_inv_qinv
	DCD	0xe9a81632, 0x2036294a, 0xe81da198, 0x3a0aaa36
	DCD	0x8cb8e921, 0x8696fcb2, 0x6bdeb0d4, 0xf6be75b0
	DCD	0xf400fa57, 0x596223d6, 0xcb8e47fb, 0xa3ead36d
	DCD	0xbd01c2f7, 0x480acc23, 0x5f6c3e51, 0xbd40589c
	DCD	0xd1bf2025, 0x0448ba26, 0x68ca79cd, 0x1a467168
	DCD	0xef15d998, 0x0f85c352, 0xde4bb330, 0x5edde2bb
	DCD	0xe8770bf2, 0x10a8ea19, 0x0690640c, 0x66bf5b09
	DCD	0x5c43e240, 0xd6225eeb, 0xffa31ac7, 0x7a06dec4
	DCD	0x9913d3c3, 0x238b7e99, 0x3df38866, 0x32df035b
	DCD	0x34a3e28f, 0xcea655f8, 0x4e7a03e4, 0x7998d342
	DCD	0x851d8c59, 0x16e5cb45, 0x7eb99768, 0xb02f2268
	DCD	0x5bf0a371, 0x50e3ac49, 0xf5a98275, 0xa353b9a8
	DCD	0xc7f5c1e1, 0xe9dbef28, 0xdbb693ee, 0x0f840ee5
	DCD	0xd5714ea9, 0x4c1a8008, 0x3ce9b5f4, 0xd2e1c6cc
	DCD	0xac322731, 0x1020e218, 0xdbf74419, 0x11e87bfb
	DCD	0xc1df5a53, 0xb777da88, 0x404f9f67, 0xce6926ad
	DCD	0xbd703292, 0xe6fd2d7d, 0xc6931939, 0x3e4a621c
	DCD	0x95eff2d1, 0x7b6ae1c2, 0xc549bee5, 0xf1fc9742
	DCD	0xbc3b495a, 0xd7f994b5, 0x12bb9ac1, 0xd69c8f77
	DCD	0x4cc42470, 0xfd45a76f, 0x04552b42, 0x5b967ae8
	DCD	0xff9ee5ba, 0x264fefaf, 0x50bc767c, 0x619e9ee4
	DCD	0x8abe928f, 0x25e045c6, 0x4623ce67, 0x7278011b
	DCD	0x9ed866dc, 0xf7cca339, 0x91ab9fc5, 0x48eead19
	DCD	0xcb3defe5, 0x42fd12bf, 0xc9da1ef4, 0x8157a6e7
	DCD	0xb4fe9e3e, 0xf8597a6e, 0x136d432a, 0x9386a683
	DCD	0x8cde507a, 0x51d07f7c, 0x97d0e50a, 0xcc85dfdf
	DCD	0x8d287904, 0x872028fc, 0x30c75d76, 0xc388107d
	DCD	0xb50840a6, 0x1ed55f1a, 0x192061e6, 0xff2681a2
	DCD	0x8e74fa22, 0x9ba784aa, 0xb9d9dd04, 0x8721b760
	DCD	0x86dec4a3, 0x1374db10, 0x02a9fa79, 0x241d4d0b
	DCD	0x54b21bde, 0xfe317461, 0xc99e6205, 0x5144c08e
	DCD	0xd386be08, 0xaec2272c, 0xc4e0c0a6, 0x000db56d
	DCD	0x354a4827, 0x354a4827, 0xbbac7fa9, 0xbbac7fa9
	DCD	0xc547b864, 0xc547b864, 0x8b59d15e, 0x8b59d15e
	DCD	0xb815b7fe, 0xb815b7fe, 0x1ee3e6bc, 0x1ee3e6bc
	DCD	0xf5fc2f20, 0xf5fc2f20, 0x0aa7c1db, 0x0aa7c1db
	DCD	0xf1f9486e, 0xf1f9486e, 0xec0b4cfb, 0xec0b4cfb
	DCD	0x46a6b520, 0x46a6b520, 0x9612636d, 0x9612636d
	DCD	0xab1d800a, 0xab1d800a, 0x51f7893e, 0x51f7893e
	DCD	0xab3537f8, 0xab3537f8, 0x296f9b94, 0x296f9b94
	DCD	0x671317f8, 0x671317f8, 0x5960475f, 0x5960475f
	DCD	0xda875821, 0xda875821, 0x772e0a94, 0x772e0a94
	DCD	0x12f99640, 0x12f99640, 0x5cbdc6b8, 0x5cbdc6b8
	DCD	0x4b306182, 0x4b306182, 0xd7bf9436, 0xd7bf9436
	DCD	0xb7d858a6, 0xb7d858a6, 0xd849b2bc, 0xd849b2bc
	DCD	0x80390942, 0x80390942, 0x6a5f5300, 0x6a5f5300
	DCD	0xbb1fba78, 0xbb1fba78, 0xb6f55be9, 0xb6f55be9
	DCD	0x369df510, 0x369df510, 0xb135e417, 0xb135e417
	DCD	0x6389939e, 0x6389939e, 0x9cb75a9d, 0x9cb75a9d
	DCD	0x0730ea2c, 0x0730ea2c, 0x350a3423, 0x350a3423
	DCD	0x9e551609, 0x9e551609, 0x3cb8f9c5, 0x3cb8f9c5
	DCD	0x95705eed, 0x95705eed, 0x80b9fd7e, 0x80b9fd7e
	DCD	0x9a24abf7, 0x9a24abf7, 0x4b38a593, 0x4b38a593
	DCD	0x052efbb5, 0x052efbb5, 0xeeb8e85d, 0xeeb8e85d
	DCD	0xa582b161, 0xa582b161, 0x231839c8, 0x231839c8
	DCD	0x0ebe617b, 0x0ebe617b, 0x2eadaf0e, 0x2eadaf0e
	DCD	0x7f04d036, 0x7f04d036, 0xde1b6f20, 0xde1b6f20
	DCD	0xa4da6d52, 0xa4da6d52, 0x55e0ad80, 0x55e0ad80
	DCD	0x8b70830a, 0x8b70830a, 0x3b300f8e, 0x3b300f8e
	DCD	0x3df4288e, 0x3df4288e, 0x4ca4908b, 0x4ca4908b
	DCD	0xf7a0d045, 0xf7a0d045, 0xa0a5ea39, 0xa0a5ea39
	DCD	0x9d8d3612, 0x9d8d3612, 0x7fca89a3, 0x7fca89a3
	DCD	0x75ab47e7, 0x75ab47e7, 0xaf7e3e31, 0xaf7e3e31
	DCD	0x2707337f, 0x2707337f, 0x5ddf591b, 0x5ddf591b
	DCD	0x38c510d3, 0x6635e2ac, 0x38a103d0, 0x591dfacc
	DCD	0x763a67ad, 0x1102b08a, 0x6184a466, 0xa77e9c58
	DCD	0x87560c74, 0xcb8ceba4, 0xc4ddc9e9, 0x72c29bc1
	DCD	0x92cf30a7, 0xe706c1e2, 0x35be552a, 0x68524dc3
	DCD	0x41dc9aa3, 0x6308a964, 0x853af5b3, 0x3f49fc00
	DCD	0x94e3a1bf, 0x2176b56a, 0x1c5ef184, 0x0c0a4a7b
	DCD	0x236e6151, 0x712c382c, 0x40314fd4, 0xa0f8fafd
	DCD	0x9271813b, 0x53b76b33, 0x613a89e0, 0x6e09d599
	DCD	0x45c31a3b, 0x5602adff, 0x927c0bde, 0xec5e8fcb
	DCD	0x2c9f0368, 0x4af67b09, 0x345e0519, 0x9d65922a
	DCD	0xd730cc85, 0x14ab0698, 0xf2bd1560, 0x94566270
	DCD	0xccd84878, 0x515bfa5c, 0x83e25f90, 0x990b69a8
	DCD	0xdab23ad9, 0x110765b7, 0xe14ae4f7, 0x7301c58b
	DCD	0x41100b81, 0x51efdb53, 0x6c36b6d5, 0xed9ec1d5
	DCD	0x9e3461dc, 0x9fe85ed8, 0xa7e8dee8, 0x9e33e1bc
	DCD	0x72e78afd, 0x73078efe, 0x0900ca21, 0xff7fe3fa
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mldsa_ntt_neon
mldsa_ntt_neon PROC
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	stp	D10, D11, [x29, #32]
	stp	D12, D13, [x29, #48]
	stp	D14, D15, [x29, #64]
	adrp	x1, L_mldsa_aarch64_zetas
	add	x1, x1, L_mldsa_aarch64_zetas
	adrp	x2, L_mldsa_aarch64_zetas_qinv
	add	x2, x2, L_mldsa_aarch64_zetas_qinv
	adrp	x3, L_mldsa_aarch64_consts
	add	x3, x3, L_mldsa_aarch64_consts
	ldr	Q4, [x3]
	ldr	Q5, [x0]
	ldr	Q6, [x0, #64]
	ldr	Q7, [x0, #128]
	ldr	Q8, [x0, #192]
	ldr	Q9, [x0, #256]
	ldr	Q10, [x0, #320]
	ldr	Q11, [x0, #384]
	ldr	Q12, [x0, #448]
	ldr	Q13, [x0, #512]
	ldr	Q14, [x0, #576]
	ldr	Q15, [x0, #640]
	ldr	Q16, [x0, #704]
	ldr	Q17, [x0, #768]
	ldr	Q18, [x0, #832]
	ldr	Q19, [x0, #896]
	ldr	Q20, [x0, #960]
	ldr	Q0, [x1]
	ldr	Q1, [x2]
	mul	V29.4S, V13.4S, V1.S[1]
	mul	V30.4S, V14.4S, V1.S[1]
	sqrdmulh	V21.4S, V13.4S, V0.S[1]
	sqrdmulh	V22.4S, V14.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V15.4S, V1.S[1]
	mul	V30.4S, V16.4S, V1.S[1]
	sqrdmulh	V23.4S, V15.4S, V0.S[1]
	sqrdmulh	V24.4S, V16.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V17.4S, V1.S[1]
	mul	V30.4S, V18.4S, V1.S[1]
	sqrdmulh	V25.4S, V17.4S, V0.S[1]
	sqrdmulh	V26.4S, V18.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[1]
	mul	V30.4S, V20.4S, V1.S[1]
	sqrdmulh	V27.4S, V19.4S, V0.S[1]
	sqrdmulh	V28.4S, V20.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V13.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V14.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V15.4S, V7.4S, V23.4S
	add	V7.4S, V7.4S, V23.4S
	sub	V16.4S, V8.4S, V24.4S
	add	V8.4S, V8.4S, V24.4S
	sub	V17.4S, V9.4S, V25.4S
	add	V9.4S, V9.4S, V25.4S
	sub	V18.4S, V10.4S, V26.4S
	add	V10.4S, V10.4S, V26.4S
	sub	V19.4S, V11.4S, V27.4S
	add	V11.4S, V11.4S, V27.4S
	sub	V20.4S, V12.4S, V28.4S
	add	V12.4S, V12.4S, V28.4S
	mul	V29.4S, V9.4S, V1.S[2]
	mul	V30.4S, V10.4S, V1.S[2]
	sqrdmulh	V21.4S, V9.4S, V0.S[2]
	sqrdmulh	V22.4S, V10.4S, V0.S[2]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V11.4S, V1.S[2]
	mul	V30.4S, V12.4S, V1.S[2]
	sqrdmulh	V23.4S, V11.4S, V0.S[2]
	sqrdmulh	V24.4S, V12.4S, V0.S[2]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V17.4S, V1.S[3]
	mul	V30.4S, V18.4S, V1.S[3]
	sqrdmulh	V25.4S, V17.4S, V0.S[3]
	sqrdmulh	V26.4S, V18.4S, V0.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[3]
	mul	V30.4S, V20.4S, V1.S[3]
	sqrdmulh	V27.4S, V19.4S, V0.S[3]
	sqrdmulh	V28.4S, V20.4S, V0.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V9.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V10.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V11.4S, V7.4S, V23.4S
	add	V7.4S, V7.4S, V23.4S
	sub	V12.4S, V8.4S, V24.4S
	add	V8.4S, V8.4S, V24.4S
	sub	V17.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V18.4S, V14.4S, V26.4S
	add	V14.4S, V14.4S, V26.4S
	sub	V19.4S, V15.4S, V27.4S
	add	V15.4S, V15.4S, V27.4S
	sub	V20.4S, V16.4S, V28.4S
	add	V16.4S, V16.4S, V28.4S
	ldr	Q0, [x1, #16]
	ldr	Q1, [x2, #16]
	mul	V29.4S, V7.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[0]
	sqrdmulh	V21.4S, V7.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[0]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V11.4S, V1.S[1]
	mul	V30.4S, V12.4S, V1.S[1]
	sqrdmulh	V23.4S, V11.4S, V0.S[1]
	sqrdmulh	V24.4S, V12.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V15.4S, V1.S[2]
	mul	V30.4S, V16.4S, V1.S[2]
	sqrdmulh	V25.4S, V15.4S, V0.S[2]
	sqrdmulh	V26.4S, V16.4S, V0.S[2]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[3]
	mul	V30.4S, V20.4S, V1.S[3]
	sqrdmulh	V27.4S, V19.4S, V0.S[3]
	sqrdmulh	V28.4S, V20.4S, V0.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V7.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V11.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V10.4S, V24.4S
	add	V10.4S, V10.4S, V24.4S
	sub	V15.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V14.4S, V26.4S
	add	V14.4S, V14.4S, V26.4S
	sub	V19.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V18.4S, V28.4S
	add	V18.4S, V18.4S, V28.4S
	ldp	Q0, Q2, [x1, #32]
	ldp	Q1, Q3, [x2, #32]
	mul	V29.4S, V6.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[1]
	sqrdmulh	V21.4S, V6.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V10.4S, V1.S[2]
	mul	V30.4S, V12.4S, V1.S[3]
	sqrdmulh	V23.4S, V10.4S, V0.S[2]
	sqrdmulh	V24.4S, V12.4S, V0.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V14.4S, V3.S[0]
	mul	V30.4S, V16.4S, V3.S[1]
	sqrdmulh	V25.4S, V14.4S, V2.S[0]
	sqrdmulh	V26.4S, V16.4S, V2.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V18.4S, V3.S[2]
	mul	V30.4S, V20.4S, V3.S[3]
	sqrdmulh	V27.4S, V18.4S, V2.S[2]
	sqrdmulh	V28.4S, V20.4S, V2.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	str	Q5, [x0]
	str	Q6, [x0, #64]
	str	Q7, [x0, #128]
	str	Q8, [x0, #192]
	str	Q9, [x0, #256]
	str	Q10, [x0, #320]
	str	Q11, [x0, #384]
	str	Q12, [x0, #448]
	str	Q13, [x0, #512]
	str	Q14, [x0, #576]
	str	Q15, [x0, #640]
	str	Q16, [x0, #704]
	str	Q17, [x0, #768]
	str	Q18, [x0, #832]
	str	Q19, [x0, #896]
	str	Q20, [x0, #960]
	ldr	Q5, [x0, #16]
	ldr	Q6, [x0, #80]
	ldr	Q7, [x0, #144]
	ldr	Q8, [x0, #208]
	ldr	Q9, [x0, #272]
	ldr	Q10, [x0, #336]
	ldr	Q11, [x0, #400]
	ldr	Q12, [x0, #464]
	ldr	Q13, [x0, #528]
	ldr	Q14, [x0, #592]
	ldr	Q15, [x0, #656]
	ldr	Q16, [x0, #720]
	ldr	Q17, [x0, #784]
	ldr	Q18, [x0, #848]
	ldr	Q19, [x0, #912]
	ldr	Q20, [x0, #976]
	ldr	Q0, [x1]
	ldr	Q1, [x2]
	mul	V29.4S, V13.4S, V1.S[1]
	mul	V30.4S, V14.4S, V1.S[1]
	sqrdmulh	V21.4S, V13.4S, V0.S[1]
	sqrdmulh	V22.4S, V14.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V15.4S, V1.S[1]
	mul	V30.4S, V16.4S, V1.S[1]
	sqrdmulh	V23.4S, V15.4S, V0.S[1]
	sqrdmulh	V24.4S, V16.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V17.4S, V1.S[1]
	mul	V30.4S, V18.4S, V1.S[1]
	sqrdmulh	V25.4S, V17.4S, V0.S[1]
	sqrdmulh	V26.4S, V18.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[1]
	mul	V30.4S, V20.4S, V1.S[1]
	sqrdmulh	V27.4S, V19.4S, V0.S[1]
	sqrdmulh	V28.4S, V20.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V13.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V14.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V15.4S, V7.4S, V23.4S
	add	V7.4S, V7.4S, V23.4S
	sub	V16.4S, V8.4S, V24.4S
	add	V8.4S, V8.4S, V24.4S
	sub	V17.4S, V9.4S, V25.4S
	add	V9.4S, V9.4S, V25.4S
	sub	V18.4S, V10.4S, V26.4S
	add	V10.4S, V10.4S, V26.4S
	sub	V19.4S, V11.4S, V27.4S
	add	V11.4S, V11.4S, V27.4S
	sub	V20.4S, V12.4S, V28.4S
	add	V12.4S, V12.4S, V28.4S
	mul	V29.4S, V9.4S, V1.S[2]
	mul	V30.4S, V10.4S, V1.S[2]
	sqrdmulh	V21.4S, V9.4S, V0.S[2]
	sqrdmulh	V22.4S, V10.4S, V0.S[2]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V11.4S, V1.S[2]
	mul	V30.4S, V12.4S, V1.S[2]
	sqrdmulh	V23.4S, V11.4S, V0.S[2]
	sqrdmulh	V24.4S, V12.4S, V0.S[2]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V17.4S, V1.S[3]
	mul	V30.4S, V18.4S, V1.S[3]
	sqrdmulh	V25.4S, V17.4S, V0.S[3]
	sqrdmulh	V26.4S, V18.4S, V0.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[3]
	mul	V30.4S, V20.4S, V1.S[3]
	sqrdmulh	V27.4S, V19.4S, V0.S[3]
	sqrdmulh	V28.4S, V20.4S, V0.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V9.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V10.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V11.4S, V7.4S, V23.4S
	add	V7.4S, V7.4S, V23.4S
	sub	V12.4S, V8.4S, V24.4S
	add	V8.4S, V8.4S, V24.4S
	sub	V17.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V18.4S, V14.4S, V26.4S
	add	V14.4S, V14.4S, V26.4S
	sub	V19.4S, V15.4S, V27.4S
	add	V15.4S, V15.4S, V27.4S
	sub	V20.4S, V16.4S, V28.4S
	add	V16.4S, V16.4S, V28.4S
	ldr	Q0, [x1, #16]
	ldr	Q1, [x2, #16]
	mul	V29.4S, V7.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[0]
	sqrdmulh	V21.4S, V7.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[0]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V11.4S, V1.S[1]
	mul	V30.4S, V12.4S, V1.S[1]
	sqrdmulh	V23.4S, V11.4S, V0.S[1]
	sqrdmulh	V24.4S, V12.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V15.4S, V1.S[2]
	mul	V30.4S, V16.4S, V1.S[2]
	sqrdmulh	V25.4S, V15.4S, V0.S[2]
	sqrdmulh	V26.4S, V16.4S, V0.S[2]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[3]
	mul	V30.4S, V20.4S, V1.S[3]
	sqrdmulh	V27.4S, V19.4S, V0.S[3]
	sqrdmulh	V28.4S, V20.4S, V0.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V7.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V11.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V10.4S, V24.4S
	add	V10.4S, V10.4S, V24.4S
	sub	V15.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V14.4S, V26.4S
	add	V14.4S, V14.4S, V26.4S
	sub	V19.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V18.4S, V28.4S
	add	V18.4S, V18.4S, V28.4S
	ldp	Q0, Q2, [x1, #32]
	ldp	Q1, Q3, [x2, #32]
	mul	V29.4S, V6.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[1]
	sqrdmulh	V21.4S, V6.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V10.4S, V1.S[2]
	mul	V30.4S, V12.4S, V1.S[3]
	sqrdmulh	V23.4S, V10.4S, V0.S[2]
	sqrdmulh	V24.4S, V12.4S, V0.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V14.4S, V3.S[0]
	mul	V30.4S, V16.4S, V3.S[1]
	sqrdmulh	V25.4S, V14.4S, V2.S[0]
	sqrdmulh	V26.4S, V16.4S, V2.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V18.4S, V3.S[2]
	mul	V30.4S, V20.4S, V3.S[3]
	sqrdmulh	V27.4S, V18.4S, V2.S[2]
	sqrdmulh	V28.4S, V20.4S, V2.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	str	Q5, [x0, #16]
	str	Q6, [x0, #80]
	str	Q7, [x0, #144]
	str	Q8, [x0, #208]
	str	Q9, [x0, #272]
	str	Q10, [x0, #336]
	str	Q11, [x0, #400]
	str	Q12, [x0, #464]
	str	Q13, [x0, #528]
	str	Q14, [x0, #592]
	str	Q15, [x0, #656]
	str	Q16, [x0, #720]
	str	Q17, [x0, #784]
	str	Q18, [x0, #848]
	str	Q19, [x0, #912]
	str	Q20, [x0, #976]
	ldr	Q5, [x0, #32]
	ldr	Q6, [x0, #96]
	ldr	Q7, [x0, #160]
	ldr	Q8, [x0, #224]
	ldr	Q9, [x0, #288]
	ldr	Q10, [x0, #352]
	ldr	Q11, [x0, #416]
	ldr	Q12, [x0, #480]
	ldr	Q13, [x0, #544]
	ldr	Q14, [x0, #608]
	ldr	Q15, [x0, #672]
	ldr	Q16, [x0, #736]
	ldr	Q17, [x0, #800]
	ldr	Q18, [x0, #864]
	ldr	Q19, [x0, #928]
	ldr	Q20, [x0, #992]
	ldr	Q0, [x1]
	ldr	Q1, [x2]
	mul	V29.4S, V13.4S, V1.S[1]
	mul	V30.4S, V14.4S, V1.S[1]
	sqrdmulh	V21.4S, V13.4S, V0.S[1]
	sqrdmulh	V22.4S, V14.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V15.4S, V1.S[1]
	mul	V30.4S, V16.4S, V1.S[1]
	sqrdmulh	V23.4S, V15.4S, V0.S[1]
	sqrdmulh	V24.4S, V16.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V17.4S, V1.S[1]
	mul	V30.4S, V18.4S, V1.S[1]
	sqrdmulh	V25.4S, V17.4S, V0.S[1]
	sqrdmulh	V26.4S, V18.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[1]
	mul	V30.4S, V20.4S, V1.S[1]
	sqrdmulh	V27.4S, V19.4S, V0.S[1]
	sqrdmulh	V28.4S, V20.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V13.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V14.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V15.4S, V7.4S, V23.4S
	add	V7.4S, V7.4S, V23.4S
	sub	V16.4S, V8.4S, V24.4S
	add	V8.4S, V8.4S, V24.4S
	sub	V17.4S, V9.4S, V25.4S
	add	V9.4S, V9.4S, V25.4S
	sub	V18.4S, V10.4S, V26.4S
	add	V10.4S, V10.4S, V26.4S
	sub	V19.4S, V11.4S, V27.4S
	add	V11.4S, V11.4S, V27.4S
	sub	V20.4S, V12.4S, V28.4S
	add	V12.4S, V12.4S, V28.4S
	mul	V29.4S, V9.4S, V1.S[2]
	mul	V30.4S, V10.4S, V1.S[2]
	sqrdmulh	V21.4S, V9.4S, V0.S[2]
	sqrdmulh	V22.4S, V10.4S, V0.S[2]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V11.4S, V1.S[2]
	mul	V30.4S, V12.4S, V1.S[2]
	sqrdmulh	V23.4S, V11.4S, V0.S[2]
	sqrdmulh	V24.4S, V12.4S, V0.S[2]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V17.4S, V1.S[3]
	mul	V30.4S, V18.4S, V1.S[3]
	sqrdmulh	V25.4S, V17.4S, V0.S[3]
	sqrdmulh	V26.4S, V18.4S, V0.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[3]
	mul	V30.4S, V20.4S, V1.S[3]
	sqrdmulh	V27.4S, V19.4S, V0.S[3]
	sqrdmulh	V28.4S, V20.4S, V0.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V9.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V10.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V11.4S, V7.4S, V23.4S
	add	V7.4S, V7.4S, V23.4S
	sub	V12.4S, V8.4S, V24.4S
	add	V8.4S, V8.4S, V24.4S
	sub	V17.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V18.4S, V14.4S, V26.4S
	add	V14.4S, V14.4S, V26.4S
	sub	V19.4S, V15.4S, V27.4S
	add	V15.4S, V15.4S, V27.4S
	sub	V20.4S, V16.4S, V28.4S
	add	V16.4S, V16.4S, V28.4S
	ldr	Q0, [x1, #16]
	ldr	Q1, [x2, #16]
	mul	V29.4S, V7.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[0]
	sqrdmulh	V21.4S, V7.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[0]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V11.4S, V1.S[1]
	mul	V30.4S, V12.4S, V1.S[1]
	sqrdmulh	V23.4S, V11.4S, V0.S[1]
	sqrdmulh	V24.4S, V12.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V15.4S, V1.S[2]
	mul	V30.4S, V16.4S, V1.S[2]
	sqrdmulh	V25.4S, V15.4S, V0.S[2]
	sqrdmulh	V26.4S, V16.4S, V0.S[2]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[3]
	mul	V30.4S, V20.4S, V1.S[3]
	sqrdmulh	V27.4S, V19.4S, V0.S[3]
	sqrdmulh	V28.4S, V20.4S, V0.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V7.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V11.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V10.4S, V24.4S
	add	V10.4S, V10.4S, V24.4S
	sub	V15.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V14.4S, V26.4S
	add	V14.4S, V14.4S, V26.4S
	sub	V19.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V18.4S, V28.4S
	add	V18.4S, V18.4S, V28.4S
	ldp	Q0, Q2, [x1, #32]
	ldp	Q1, Q3, [x2, #32]
	mul	V29.4S, V6.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[1]
	sqrdmulh	V21.4S, V6.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V10.4S, V1.S[2]
	mul	V30.4S, V12.4S, V1.S[3]
	sqrdmulh	V23.4S, V10.4S, V0.S[2]
	sqrdmulh	V24.4S, V12.4S, V0.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V14.4S, V3.S[0]
	mul	V30.4S, V16.4S, V3.S[1]
	sqrdmulh	V25.4S, V14.4S, V2.S[0]
	sqrdmulh	V26.4S, V16.4S, V2.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V18.4S, V3.S[2]
	mul	V30.4S, V20.4S, V3.S[3]
	sqrdmulh	V27.4S, V18.4S, V2.S[2]
	sqrdmulh	V28.4S, V20.4S, V2.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	str	Q5, [x0, #32]
	str	Q6, [x0, #96]
	str	Q7, [x0, #160]
	str	Q8, [x0, #224]
	str	Q9, [x0, #288]
	str	Q10, [x0, #352]
	str	Q11, [x0, #416]
	str	Q12, [x0, #480]
	str	Q13, [x0, #544]
	str	Q14, [x0, #608]
	str	Q15, [x0, #672]
	str	Q16, [x0, #736]
	str	Q17, [x0, #800]
	str	Q18, [x0, #864]
	str	Q19, [x0, #928]
	str	Q20, [x0, #992]
	ldr	Q5, [x0, #48]
	ldr	Q6, [x0, #112]
	ldr	Q7, [x0, #176]
	ldr	Q8, [x0, #240]
	ldr	Q9, [x0, #304]
	ldr	Q10, [x0, #368]
	ldr	Q11, [x0, #432]
	ldr	Q12, [x0, #496]
	ldr	Q13, [x0, #560]
	ldr	Q14, [x0, #624]
	ldr	Q15, [x0, #688]
	ldr	Q16, [x0, #752]
	ldr	Q17, [x0, #816]
	ldr	Q18, [x0, #880]
	ldr	Q19, [x0, #944]
	ldr	Q20, [x0, #1008]
	ldr	Q0, [x1]
	ldr	Q1, [x2]
	mul	V29.4S, V13.4S, V1.S[1]
	mul	V30.4S, V14.4S, V1.S[1]
	sqrdmulh	V21.4S, V13.4S, V0.S[1]
	sqrdmulh	V22.4S, V14.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V15.4S, V1.S[1]
	mul	V30.4S, V16.4S, V1.S[1]
	sqrdmulh	V23.4S, V15.4S, V0.S[1]
	sqrdmulh	V24.4S, V16.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V17.4S, V1.S[1]
	mul	V30.4S, V18.4S, V1.S[1]
	sqrdmulh	V25.4S, V17.4S, V0.S[1]
	sqrdmulh	V26.4S, V18.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[1]
	mul	V30.4S, V20.4S, V1.S[1]
	sqrdmulh	V27.4S, V19.4S, V0.S[1]
	sqrdmulh	V28.4S, V20.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V13.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V14.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V15.4S, V7.4S, V23.4S
	add	V7.4S, V7.4S, V23.4S
	sub	V16.4S, V8.4S, V24.4S
	add	V8.4S, V8.4S, V24.4S
	sub	V17.4S, V9.4S, V25.4S
	add	V9.4S, V9.4S, V25.4S
	sub	V18.4S, V10.4S, V26.4S
	add	V10.4S, V10.4S, V26.4S
	sub	V19.4S, V11.4S, V27.4S
	add	V11.4S, V11.4S, V27.4S
	sub	V20.4S, V12.4S, V28.4S
	add	V12.4S, V12.4S, V28.4S
	mul	V29.4S, V9.4S, V1.S[2]
	mul	V30.4S, V10.4S, V1.S[2]
	sqrdmulh	V21.4S, V9.4S, V0.S[2]
	sqrdmulh	V22.4S, V10.4S, V0.S[2]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V11.4S, V1.S[2]
	mul	V30.4S, V12.4S, V1.S[2]
	sqrdmulh	V23.4S, V11.4S, V0.S[2]
	sqrdmulh	V24.4S, V12.4S, V0.S[2]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V17.4S, V1.S[3]
	mul	V30.4S, V18.4S, V1.S[3]
	sqrdmulh	V25.4S, V17.4S, V0.S[3]
	sqrdmulh	V26.4S, V18.4S, V0.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[3]
	mul	V30.4S, V20.4S, V1.S[3]
	sqrdmulh	V27.4S, V19.4S, V0.S[3]
	sqrdmulh	V28.4S, V20.4S, V0.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V9.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V10.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V11.4S, V7.4S, V23.4S
	add	V7.4S, V7.4S, V23.4S
	sub	V12.4S, V8.4S, V24.4S
	add	V8.4S, V8.4S, V24.4S
	sub	V17.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V18.4S, V14.4S, V26.4S
	add	V14.4S, V14.4S, V26.4S
	sub	V19.4S, V15.4S, V27.4S
	add	V15.4S, V15.4S, V27.4S
	sub	V20.4S, V16.4S, V28.4S
	add	V16.4S, V16.4S, V28.4S
	ldr	Q0, [x1, #16]
	ldr	Q1, [x2, #16]
	mul	V29.4S, V7.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[0]
	sqrdmulh	V21.4S, V7.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[0]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V11.4S, V1.S[1]
	mul	V30.4S, V12.4S, V1.S[1]
	sqrdmulh	V23.4S, V11.4S, V0.S[1]
	sqrdmulh	V24.4S, V12.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V15.4S, V1.S[2]
	mul	V30.4S, V16.4S, V1.S[2]
	sqrdmulh	V25.4S, V15.4S, V0.S[2]
	sqrdmulh	V26.4S, V16.4S, V0.S[2]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[3]
	mul	V30.4S, V20.4S, V1.S[3]
	sqrdmulh	V27.4S, V19.4S, V0.S[3]
	sqrdmulh	V28.4S, V20.4S, V0.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V7.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V11.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V10.4S, V24.4S
	add	V10.4S, V10.4S, V24.4S
	sub	V15.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V14.4S, V26.4S
	add	V14.4S, V14.4S, V26.4S
	sub	V19.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V18.4S, V28.4S
	add	V18.4S, V18.4S, V28.4S
	ldp	Q0, Q2, [x1, #32]
	ldp	Q1, Q3, [x2, #32]
	mul	V29.4S, V6.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[1]
	sqrdmulh	V21.4S, V6.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V10.4S, V1.S[2]
	mul	V30.4S, V12.4S, V1.S[3]
	sqrdmulh	V23.4S, V10.4S, V0.S[2]
	sqrdmulh	V24.4S, V12.4S, V0.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V14.4S, V3.S[0]
	mul	V30.4S, V16.4S, V3.S[1]
	sqrdmulh	V25.4S, V14.4S, V2.S[0]
	sqrdmulh	V26.4S, V16.4S, V2.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V18.4S, V3.S[2]
	mul	V30.4S, V20.4S, V3.S[3]
	sqrdmulh	V27.4S, V18.4S, V2.S[2]
	sqrdmulh	V28.4S, V20.4S, V2.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	str	Q5, [x0, #48]
	str	Q6, [x0, #112]
	str	Q7, [x0, #176]
	str	Q8, [x0, #240]
	str	Q9, [x0, #304]
	str	Q10, [x0, #368]
	str	Q11, [x0, #432]
	str	Q12, [x0, #496]
	str	Q13, [x0, #560]
	str	Q14, [x0, #624]
	str	Q15, [x0, #688]
	str	Q16, [x0, #752]
	str	Q17, [x0, #816]
	str	Q18, [x0, #880]
	str	Q19, [x0, #944]
	str	Q20, [x0, #1008]
	ldp	Q5, Q6, [x0]
	ldp	Q7, Q8, [x0, #32]
	ldp	Q9, Q10, [x0, #64]
	ldp	Q11, Q12, [x0, #96]
	ldp	Q13, Q14, [x0, #128]
	ldp	Q15, Q16, [x0, #160]
	ldp	Q17, Q18, [x0, #192]
	ldp	Q19, Q20, [x0, #224]
	ldr	Q0, [x1, #64]
	ldr	Q1, [x2, #64]
	mul	V29.4S, V7.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[0]
	sqrdmulh	V21.4S, V7.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[0]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V11.4S, V1.S[1]
	mul	V30.4S, V12.4S, V1.S[1]
	sqrdmulh	V23.4S, V11.4S, V0.S[1]
	sqrdmulh	V24.4S, V12.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V15.4S, V1.S[2]
	mul	V30.4S, V16.4S, V1.S[2]
	sqrdmulh	V25.4S, V15.4S, V0.S[2]
	sqrdmulh	V26.4S, V16.4S, V0.S[2]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[3]
	mul	V30.4S, V20.4S, V1.S[3]
	sqrdmulh	V27.4S, V19.4S, V0.S[3]
	sqrdmulh	V28.4S, V20.4S, V0.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V7.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V11.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V10.4S, V24.4S
	add	V10.4S, V10.4S, V24.4S
	sub	V15.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V14.4S, V26.4S
	add	V14.4S, V14.4S, V26.4S
	sub	V19.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V18.4S, V28.4S
	add	V18.4S, V18.4S, V28.4S
	ldp	Q0, Q2, [x1, #128]
	ldp	Q1, Q3, [x2, #128]
	mul	V29.4S, V6.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[1]
	sqrdmulh	V21.4S, V6.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V10.4S, V1.S[2]
	mul	V30.4S, V12.4S, V1.S[3]
	sqrdmulh	V23.4S, V10.4S, V0.S[2]
	sqrdmulh	V24.4S, V12.4S, V0.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V14.4S, V3.S[0]
	mul	V30.4S, V16.4S, V3.S[1]
	sqrdmulh	V25.4S, V14.4S, V2.S[0]
	sqrdmulh	V26.4S, V16.4S, V2.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V18.4S, V3.S[2]
	mul	V30.4S, V20.4S, V3.S[3]
	sqrdmulh	V27.4S, V18.4S, V2.S[2]
	sqrdmulh	V28.4S, V20.4S, V2.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	ldp	Q0, Q2, [x1, #256]
	ldp	Q1, Q3, [x2, #256]
	mov	V29.16B, V5.16B
	mov	V30.16B, V7.16B
	trn1	V5.2D, V5.2D, V6.2D
	trn1	V7.2D, V7.2D, V8.2D
	trn2	V6.2D, V29.2D, V6.2D
	trn2	V8.2D, V30.2D, V8.2D
	mul	V29.4S, V6.4S, V1.4S
	mul	V30.4S, V8.4S, V3.4S
	sqrdmulh	V21.4S, V6.4S, V0.4S
	sqrdmulh	V22.4S, V8.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	ldp	Q0, Q2, [x1, #288]
	ldp	Q1, Q3, [x2, #288]
	mov	V29.16B, V9.16B
	mov	V30.16B, V11.16B
	trn1	V9.2D, V9.2D, V10.2D
	trn1	V11.2D, V11.2D, V12.2D
	trn2	V10.2D, V29.2D, V10.2D
	trn2	V12.2D, V30.2D, V12.2D
	mul	V29.4S, V10.4S, V1.4S
	mul	V30.4S, V12.4S, V3.4S
	sqrdmulh	V23.4S, V10.4S, V0.4S
	sqrdmulh	V24.4S, V12.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	ldp	Q0, Q2, [x1, #320]
	ldp	Q1, Q3, [x2, #320]
	mov	V29.16B, V13.16B
	mov	V30.16B, V15.16B
	trn1	V13.2D, V13.2D, V14.2D
	trn1	V15.2D, V15.2D, V16.2D
	trn2	V14.2D, V29.2D, V14.2D
	trn2	V16.2D, V30.2D, V16.2D
	mul	V29.4S, V14.4S, V1.4S
	mul	V30.4S, V16.4S, V3.4S
	sqrdmulh	V25.4S, V14.4S, V0.4S
	sqrdmulh	V26.4S, V16.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	ldp	Q0, Q2, [x1, #352]
	ldp	Q1, Q3, [x2, #352]
	mov	V29.16B, V17.16B
	mov	V30.16B, V19.16B
	trn1	V17.2D, V17.2D, V18.2D
	trn1	V19.2D, V19.2D, V20.2D
	trn2	V18.2D, V29.2D, V18.2D
	trn2	V20.2D, V30.2D, V20.2D
	mul	V29.4S, V18.4S, V1.4S
	mul	V30.4S, V20.4S, V3.4S
	sqrdmulh	V27.4S, V18.4S, V0.4S
	sqrdmulh	V28.4S, V20.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	ldp	Q0, Q2, [x1, #768]
	ldp	Q1, Q3, [x2, #768]
	mov	V29.16B, V5.16B
	mov	V30.16B, V7.16B
	trn1	V5.4S, V5.4S, V6.4S
	trn1	V7.4S, V7.4S, V8.4S
	trn2	V6.4S, V29.4S, V6.4S
	trn2	V8.4S, V30.4S, V8.4S
	mul	V29.4S, V6.4S, V1.4S
	mul	V30.4S, V8.4S, V3.4S
	sqrdmulh	V21.4S, V6.4S, V0.4S
	sqrdmulh	V22.4S, V8.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	ldp	Q0, Q2, [x1, #800]
	ldp	Q1, Q3, [x2, #800]
	mov	V29.16B, V9.16B
	mov	V30.16B, V11.16B
	trn1	V9.4S, V9.4S, V10.4S
	trn1	V11.4S, V11.4S, V12.4S
	trn2	V10.4S, V29.4S, V10.4S
	trn2	V12.4S, V30.4S, V12.4S
	mul	V29.4S, V10.4S, V1.4S
	mul	V30.4S, V12.4S, V3.4S
	sqrdmulh	V23.4S, V10.4S, V0.4S
	sqrdmulh	V24.4S, V12.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	ldp	Q0, Q2, [x1, #832]
	ldp	Q1, Q3, [x2, #832]
	mov	V29.16B, V13.16B
	mov	V30.16B, V15.16B
	trn1	V13.4S, V13.4S, V14.4S
	trn1	V15.4S, V15.4S, V16.4S
	trn2	V14.4S, V29.4S, V14.4S
	trn2	V16.4S, V30.4S, V16.4S
	mul	V29.4S, V14.4S, V1.4S
	mul	V30.4S, V16.4S, V3.4S
	sqrdmulh	V25.4S, V14.4S, V0.4S
	sqrdmulh	V26.4S, V16.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	ldp	Q0, Q2, [x1, #864]
	ldp	Q1, Q3, [x2, #864]
	mov	V29.16B, V17.16B
	mov	V30.16B, V19.16B
	trn1	V17.4S, V17.4S, V18.4S
	trn1	V19.4S, V19.4S, V20.4S
	trn2	V18.4S, V29.4S, V18.4S
	trn2	V20.4S, V30.4S, V20.4S
	mul	V29.4S, V18.4S, V1.4S
	mul	V30.4S, V20.4S, V3.4S
	sqrdmulh	V27.4S, V18.4S, V0.4S
	sqrdmulh	V28.4S, V20.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	stp	Q5, Q6, [x0]
	stp	Q7, Q8, [x0, #32]
	stp	Q9, Q10, [x0, #64]
	stp	Q11, Q12, [x0, #96]
	stp	Q13, Q14, [x0, #128]
	stp	Q15, Q16, [x0, #160]
	stp	Q17, Q18, [x0, #192]
	stp	Q19, Q20, [x0, #224]
	ldp	Q5, Q6, [x0, #256]
	ldp	Q7, Q8, [x0, #288]
	ldp	Q9, Q10, [x0, #320]
	ldp	Q11, Q12, [x0, #352]
	ldp	Q13, Q14, [x0, #384]
	ldp	Q15, Q16, [x0, #416]
	ldp	Q17, Q18, [x0, #448]
	ldp	Q19, Q20, [x0, #480]
	ldr	Q0, [x1, #80]
	ldr	Q1, [x2, #80]
	mul	V29.4S, V7.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[0]
	sqrdmulh	V21.4S, V7.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[0]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V11.4S, V1.S[1]
	mul	V30.4S, V12.4S, V1.S[1]
	sqrdmulh	V23.4S, V11.4S, V0.S[1]
	sqrdmulh	V24.4S, V12.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V15.4S, V1.S[2]
	mul	V30.4S, V16.4S, V1.S[2]
	sqrdmulh	V25.4S, V15.4S, V0.S[2]
	sqrdmulh	V26.4S, V16.4S, V0.S[2]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[3]
	mul	V30.4S, V20.4S, V1.S[3]
	sqrdmulh	V27.4S, V19.4S, V0.S[3]
	sqrdmulh	V28.4S, V20.4S, V0.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V7.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V11.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V10.4S, V24.4S
	add	V10.4S, V10.4S, V24.4S
	sub	V15.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V14.4S, V26.4S
	add	V14.4S, V14.4S, V26.4S
	sub	V19.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V18.4S, V28.4S
	add	V18.4S, V18.4S, V28.4S
	ldp	Q0, Q2, [x1, #160]
	ldp	Q1, Q3, [x2, #160]
	mul	V29.4S, V6.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[1]
	sqrdmulh	V21.4S, V6.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V10.4S, V1.S[2]
	mul	V30.4S, V12.4S, V1.S[3]
	sqrdmulh	V23.4S, V10.4S, V0.S[2]
	sqrdmulh	V24.4S, V12.4S, V0.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V14.4S, V3.S[0]
	mul	V30.4S, V16.4S, V3.S[1]
	sqrdmulh	V25.4S, V14.4S, V2.S[0]
	sqrdmulh	V26.4S, V16.4S, V2.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V18.4S, V3.S[2]
	mul	V30.4S, V20.4S, V3.S[3]
	sqrdmulh	V27.4S, V18.4S, V2.S[2]
	sqrdmulh	V28.4S, V20.4S, V2.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	ldp	Q0, Q2, [x1, #384]
	ldp	Q1, Q3, [x2, #384]
	mov	V29.16B, V5.16B
	mov	V30.16B, V7.16B
	trn1	V5.2D, V5.2D, V6.2D
	trn1	V7.2D, V7.2D, V8.2D
	trn2	V6.2D, V29.2D, V6.2D
	trn2	V8.2D, V30.2D, V8.2D
	mul	V29.4S, V6.4S, V1.4S
	mul	V30.4S, V8.4S, V3.4S
	sqrdmulh	V21.4S, V6.4S, V0.4S
	sqrdmulh	V22.4S, V8.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	ldp	Q0, Q2, [x1, #416]
	ldp	Q1, Q3, [x2, #416]
	mov	V29.16B, V9.16B
	mov	V30.16B, V11.16B
	trn1	V9.2D, V9.2D, V10.2D
	trn1	V11.2D, V11.2D, V12.2D
	trn2	V10.2D, V29.2D, V10.2D
	trn2	V12.2D, V30.2D, V12.2D
	mul	V29.4S, V10.4S, V1.4S
	mul	V30.4S, V12.4S, V3.4S
	sqrdmulh	V23.4S, V10.4S, V0.4S
	sqrdmulh	V24.4S, V12.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	ldp	Q0, Q2, [x1, #448]
	ldp	Q1, Q3, [x2, #448]
	mov	V29.16B, V13.16B
	mov	V30.16B, V15.16B
	trn1	V13.2D, V13.2D, V14.2D
	trn1	V15.2D, V15.2D, V16.2D
	trn2	V14.2D, V29.2D, V14.2D
	trn2	V16.2D, V30.2D, V16.2D
	mul	V29.4S, V14.4S, V1.4S
	mul	V30.4S, V16.4S, V3.4S
	sqrdmulh	V25.4S, V14.4S, V0.4S
	sqrdmulh	V26.4S, V16.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	ldp	Q0, Q2, [x1, #480]
	ldp	Q1, Q3, [x2, #480]
	mov	V29.16B, V17.16B
	mov	V30.16B, V19.16B
	trn1	V17.2D, V17.2D, V18.2D
	trn1	V19.2D, V19.2D, V20.2D
	trn2	V18.2D, V29.2D, V18.2D
	trn2	V20.2D, V30.2D, V20.2D
	mul	V29.4S, V18.4S, V1.4S
	mul	V30.4S, V20.4S, V3.4S
	sqrdmulh	V27.4S, V18.4S, V0.4S
	sqrdmulh	V28.4S, V20.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	ldp	Q0, Q2, [x1, #896]
	ldp	Q1, Q3, [x2, #896]
	mov	V29.16B, V5.16B
	mov	V30.16B, V7.16B
	trn1	V5.4S, V5.4S, V6.4S
	trn1	V7.4S, V7.4S, V8.4S
	trn2	V6.4S, V29.4S, V6.4S
	trn2	V8.4S, V30.4S, V8.4S
	mul	V29.4S, V6.4S, V1.4S
	mul	V30.4S, V8.4S, V3.4S
	sqrdmulh	V21.4S, V6.4S, V0.4S
	sqrdmulh	V22.4S, V8.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	ldp	Q0, Q2, [x1, #928]
	ldp	Q1, Q3, [x2, #928]
	mov	V29.16B, V9.16B
	mov	V30.16B, V11.16B
	trn1	V9.4S, V9.4S, V10.4S
	trn1	V11.4S, V11.4S, V12.4S
	trn2	V10.4S, V29.4S, V10.4S
	trn2	V12.4S, V30.4S, V12.4S
	mul	V29.4S, V10.4S, V1.4S
	mul	V30.4S, V12.4S, V3.4S
	sqrdmulh	V23.4S, V10.4S, V0.4S
	sqrdmulh	V24.4S, V12.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	ldp	Q0, Q2, [x1, #960]
	ldp	Q1, Q3, [x2, #960]
	mov	V29.16B, V13.16B
	mov	V30.16B, V15.16B
	trn1	V13.4S, V13.4S, V14.4S
	trn1	V15.4S, V15.4S, V16.4S
	trn2	V14.4S, V29.4S, V14.4S
	trn2	V16.4S, V30.4S, V16.4S
	mul	V29.4S, V14.4S, V1.4S
	mul	V30.4S, V16.4S, V3.4S
	sqrdmulh	V25.4S, V14.4S, V0.4S
	sqrdmulh	V26.4S, V16.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	ldp	Q0, Q2, [x1, #992]
	ldp	Q1, Q3, [x2, #992]
	mov	V29.16B, V17.16B
	mov	V30.16B, V19.16B
	trn1	V17.4S, V17.4S, V18.4S
	trn1	V19.4S, V19.4S, V20.4S
	trn2	V18.4S, V29.4S, V18.4S
	trn2	V20.4S, V30.4S, V20.4S
	mul	V29.4S, V18.4S, V1.4S
	mul	V30.4S, V20.4S, V3.4S
	sqrdmulh	V27.4S, V18.4S, V0.4S
	sqrdmulh	V28.4S, V20.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	stp	Q5, Q6, [x0, #256]
	stp	Q7, Q8, [x0, #288]
	stp	Q9, Q10, [x0, #320]
	stp	Q11, Q12, [x0, #352]
	stp	Q13, Q14, [x0, #384]
	stp	Q15, Q16, [x0, #416]
	stp	Q17, Q18, [x0, #448]
	stp	Q19, Q20, [x0, #480]
	ldp	Q5, Q6, [x0, #512]
	ldp	Q7, Q8, [x0, #544]
	ldp	Q9, Q10, [x0, #576]
	ldp	Q11, Q12, [x0, #608]
	ldp	Q13, Q14, [x0, #640]
	ldp	Q15, Q16, [x0, #672]
	ldp	Q17, Q18, [x0, #704]
	ldp	Q19, Q20, [x0, #736]
	ldr	Q0, [x1, #96]
	ldr	Q1, [x2, #96]
	mul	V29.4S, V7.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[0]
	sqrdmulh	V21.4S, V7.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[0]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V11.4S, V1.S[1]
	mul	V30.4S, V12.4S, V1.S[1]
	sqrdmulh	V23.4S, V11.4S, V0.S[1]
	sqrdmulh	V24.4S, V12.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V15.4S, V1.S[2]
	mul	V30.4S, V16.4S, V1.S[2]
	sqrdmulh	V25.4S, V15.4S, V0.S[2]
	sqrdmulh	V26.4S, V16.4S, V0.S[2]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[3]
	mul	V30.4S, V20.4S, V1.S[3]
	sqrdmulh	V27.4S, V19.4S, V0.S[3]
	sqrdmulh	V28.4S, V20.4S, V0.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V7.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V11.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V10.4S, V24.4S
	add	V10.4S, V10.4S, V24.4S
	sub	V15.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V14.4S, V26.4S
	add	V14.4S, V14.4S, V26.4S
	sub	V19.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V18.4S, V28.4S
	add	V18.4S, V18.4S, V28.4S
	ldp	Q0, Q2, [x1, #192]
	ldp	Q1, Q3, [x2, #192]
	mul	V29.4S, V6.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[1]
	sqrdmulh	V21.4S, V6.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V10.4S, V1.S[2]
	mul	V30.4S, V12.4S, V1.S[3]
	sqrdmulh	V23.4S, V10.4S, V0.S[2]
	sqrdmulh	V24.4S, V12.4S, V0.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V14.4S, V3.S[0]
	mul	V30.4S, V16.4S, V3.S[1]
	sqrdmulh	V25.4S, V14.4S, V2.S[0]
	sqrdmulh	V26.4S, V16.4S, V2.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V18.4S, V3.S[2]
	mul	V30.4S, V20.4S, V3.S[3]
	sqrdmulh	V27.4S, V18.4S, V2.S[2]
	sqrdmulh	V28.4S, V20.4S, V2.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	ldp	Q0, Q2, [x1, #512]
	ldp	Q1, Q3, [x2, #512]
	mov	V29.16B, V5.16B
	mov	V30.16B, V7.16B
	trn1	V5.2D, V5.2D, V6.2D
	trn1	V7.2D, V7.2D, V8.2D
	trn2	V6.2D, V29.2D, V6.2D
	trn2	V8.2D, V30.2D, V8.2D
	mul	V29.4S, V6.4S, V1.4S
	mul	V30.4S, V8.4S, V3.4S
	sqrdmulh	V21.4S, V6.4S, V0.4S
	sqrdmulh	V22.4S, V8.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	ldp	Q0, Q2, [x1, #544]
	ldp	Q1, Q3, [x2, #544]
	mov	V29.16B, V9.16B
	mov	V30.16B, V11.16B
	trn1	V9.2D, V9.2D, V10.2D
	trn1	V11.2D, V11.2D, V12.2D
	trn2	V10.2D, V29.2D, V10.2D
	trn2	V12.2D, V30.2D, V12.2D
	mul	V29.4S, V10.4S, V1.4S
	mul	V30.4S, V12.4S, V3.4S
	sqrdmulh	V23.4S, V10.4S, V0.4S
	sqrdmulh	V24.4S, V12.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	ldp	Q0, Q2, [x1, #576]
	ldp	Q1, Q3, [x2, #576]
	mov	V29.16B, V13.16B
	mov	V30.16B, V15.16B
	trn1	V13.2D, V13.2D, V14.2D
	trn1	V15.2D, V15.2D, V16.2D
	trn2	V14.2D, V29.2D, V14.2D
	trn2	V16.2D, V30.2D, V16.2D
	mul	V29.4S, V14.4S, V1.4S
	mul	V30.4S, V16.4S, V3.4S
	sqrdmulh	V25.4S, V14.4S, V0.4S
	sqrdmulh	V26.4S, V16.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	ldp	Q0, Q2, [x1, #608]
	ldp	Q1, Q3, [x2, #608]
	mov	V29.16B, V17.16B
	mov	V30.16B, V19.16B
	trn1	V17.2D, V17.2D, V18.2D
	trn1	V19.2D, V19.2D, V20.2D
	trn2	V18.2D, V29.2D, V18.2D
	trn2	V20.2D, V30.2D, V20.2D
	mul	V29.4S, V18.4S, V1.4S
	mul	V30.4S, V20.4S, V3.4S
	sqrdmulh	V27.4S, V18.4S, V0.4S
	sqrdmulh	V28.4S, V20.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	ldr	Q0, [x1, #1024]
	ldr	Q2, [x1, #1040]
	ldr	Q1, [x2, #1024]
	ldr	Q3, [x2, #1040]
	mov	V29.16B, V5.16B
	mov	V30.16B, V7.16B
	trn1	V5.4S, V5.4S, V6.4S
	trn1	V7.4S, V7.4S, V8.4S
	trn2	V6.4S, V29.4S, V6.4S
	trn2	V8.4S, V30.4S, V8.4S
	mul	V29.4S, V6.4S, V1.4S
	mul	V30.4S, V8.4S, V3.4S
	sqrdmulh	V21.4S, V6.4S, V0.4S
	sqrdmulh	V22.4S, V8.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	ldr	Q0, [x1, #1056]
	ldr	Q2, [x1, #1072]
	ldr	Q1, [x2, #1056]
	ldr	Q3, [x2, #1072]
	mov	V29.16B, V9.16B
	mov	V30.16B, V11.16B
	trn1	V9.4S, V9.4S, V10.4S
	trn1	V11.4S, V11.4S, V12.4S
	trn2	V10.4S, V29.4S, V10.4S
	trn2	V12.4S, V30.4S, V12.4S
	mul	V29.4S, V10.4S, V1.4S
	mul	V30.4S, V12.4S, V3.4S
	sqrdmulh	V23.4S, V10.4S, V0.4S
	sqrdmulh	V24.4S, V12.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	ldr	Q0, [x1, #1088]
	ldr	Q2, [x1, #1104]
	ldr	Q1, [x2, #1088]
	ldr	Q3, [x2, #1104]
	mov	V29.16B, V13.16B
	mov	V30.16B, V15.16B
	trn1	V13.4S, V13.4S, V14.4S
	trn1	V15.4S, V15.4S, V16.4S
	trn2	V14.4S, V29.4S, V14.4S
	trn2	V16.4S, V30.4S, V16.4S
	mul	V29.4S, V14.4S, V1.4S
	mul	V30.4S, V16.4S, V3.4S
	sqrdmulh	V25.4S, V14.4S, V0.4S
	sqrdmulh	V26.4S, V16.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	ldr	Q0, [x1, #1120]
	ldr	Q2, [x1, #1136]
	ldr	Q1, [x2, #1120]
	ldr	Q3, [x2, #1136]
	mov	V29.16B, V17.16B
	mov	V30.16B, V19.16B
	trn1	V17.4S, V17.4S, V18.4S
	trn1	V19.4S, V19.4S, V20.4S
	trn2	V18.4S, V29.4S, V18.4S
	trn2	V20.4S, V30.4S, V20.4S
	mul	V29.4S, V18.4S, V1.4S
	mul	V30.4S, V20.4S, V3.4S
	sqrdmulh	V27.4S, V18.4S, V0.4S
	sqrdmulh	V28.4S, V20.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	stp	Q5, Q6, [x0, #512]
	stp	Q7, Q8, [x0, #544]
	stp	Q9, Q10, [x0, #576]
	stp	Q11, Q12, [x0, #608]
	stp	Q13, Q14, [x0, #640]
	stp	Q15, Q16, [x0, #672]
	stp	Q17, Q18, [x0, #704]
	stp	Q19, Q20, [x0, #736]
	ldp	Q5, Q6, [x0, #768]
	ldp	Q7, Q8, [x0, #800]
	ldp	Q9, Q10, [x0, #832]
	ldp	Q11, Q12, [x0, #864]
	ldp	Q13, Q14, [x0, #896]
	ldp	Q15, Q16, [x0, #928]
	ldp	Q17, Q18, [x0, #960]
	ldp	Q19, Q20, [x0, #992]
	ldr	Q0, [x1, #112]
	ldr	Q1, [x2, #112]
	mul	V29.4S, V7.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[0]
	sqrdmulh	V21.4S, V7.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[0]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V11.4S, V1.S[1]
	mul	V30.4S, V12.4S, V1.S[1]
	sqrdmulh	V23.4S, V11.4S, V0.S[1]
	sqrdmulh	V24.4S, V12.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V15.4S, V1.S[2]
	mul	V30.4S, V16.4S, V1.S[2]
	sqrdmulh	V25.4S, V15.4S, V0.S[2]
	sqrdmulh	V26.4S, V16.4S, V0.S[2]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[3]
	mul	V30.4S, V20.4S, V1.S[3]
	sqrdmulh	V27.4S, V19.4S, V0.S[3]
	sqrdmulh	V28.4S, V20.4S, V0.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V7.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V11.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V10.4S, V24.4S
	add	V10.4S, V10.4S, V24.4S
	sub	V15.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V14.4S, V26.4S
	add	V14.4S, V14.4S, V26.4S
	sub	V19.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V18.4S, V28.4S
	add	V18.4S, V18.4S, V28.4S
	ldp	Q0, Q2, [x1, #224]
	ldp	Q1, Q3, [x2, #224]
	mul	V29.4S, V6.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[1]
	sqrdmulh	V21.4S, V6.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V10.4S, V1.S[2]
	mul	V30.4S, V12.4S, V1.S[3]
	sqrdmulh	V23.4S, V10.4S, V0.S[2]
	sqrdmulh	V24.4S, V12.4S, V0.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V14.4S, V3.S[0]
	mul	V30.4S, V16.4S, V3.S[1]
	sqrdmulh	V25.4S, V14.4S, V2.S[0]
	sqrdmulh	V26.4S, V16.4S, V2.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V18.4S, V3.S[2]
	mul	V30.4S, V20.4S, V3.S[3]
	sqrdmulh	V27.4S, V18.4S, V2.S[2]
	sqrdmulh	V28.4S, V20.4S, V2.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	ldp	Q0, Q2, [x1, #640]
	ldp	Q1, Q3, [x2, #640]
	mov	V29.16B, V5.16B
	mov	V30.16B, V7.16B
	trn1	V5.2D, V5.2D, V6.2D
	trn1	V7.2D, V7.2D, V8.2D
	trn2	V6.2D, V29.2D, V6.2D
	trn2	V8.2D, V30.2D, V8.2D
	mul	V29.4S, V6.4S, V1.4S
	mul	V30.4S, V8.4S, V3.4S
	sqrdmulh	V21.4S, V6.4S, V0.4S
	sqrdmulh	V22.4S, V8.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	ldp	Q0, Q2, [x1, #672]
	ldp	Q1, Q3, [x2, #672]
	mov	V29.16B, V9.16B
	mov	V30.16B, V11.16B
	trn1	V9.2D, V9.2D, V10.2D
	trn1	V11.2D, V11.2D, V12.2D
	trn2	V10.2D, V29.2D, V10.2D
	trn2	V12.2D, V30.2D, V12.2D
	mul	V29.4S, V10.4S, V1.4S
	mul	V30.4S, V12.4S, V3.4S
	sqrdmulh	V23.4S, V10.4S, V0.4S
	sqrdmulh	V24.4S, V12.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	ldp	Q0, Q2, [x1, #704]
	ldp	Q1, Q3, [x2, #704]
	mov	V29.16B, V13.16B
	mov	V30.16B, V15.16B
	trn1	V13.2D, V13.2D, V14.2D
	trn1	V15.2D, V15.2D, V16.2D
	trn2	V14.2D, V29.2D, V14.2D
	trn2	V16.2D, V30.2D, V16.2D
	mul	V29.4S, V14.4S, V1.4S
	mul	V30.4S, V16.4S, V3.4S
	sqrdmulh	V25.4S, V14.4S, V0.4S
	sqrdmulh	V26.4S, V16.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	ldp	Q0, Q2, [x1, #736]
	ldp	Q1, Q3, [x2, #736]
	mov	V29.16B, V17.16B
	mov	V30.16B, V19.16B
	trn1	V17.2D, V17.2D, V18.2D
	trn1	V19.2D, V19.2D, V20.2D
	trn2	V18.2D, V29.2D, V18.2D
	trn2	V20.2D, V30.2D, V20.2D
	mul	V29.4S, V18.4S, V1.4S
	mul	V30.4S, V20.4S, V3.4S
	sqrdmulh	V27.4S, V18.4S, V0.4S
	sqrdmulh	V28.4S, V20.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	ldr	Q0, [x1, #1152]
	ldr	Q2, [x1, #1168]
	ldr	Q1, [x2, #1152]
	ldr	Q3, [x2, #1168]
	mov	V29.16B, V5.16B
	mov	V30.16B, V7.16B
	trn1	V5.4S, V5.4S, V6.4S
	trn1	V7.4S, V7.4S, V8.4S
	trn2	V6.4S, V29.4S, V6.4S
	trn2	V8.4S, V30.4S, V8.4S
	mul	V29.4S, V6.4S, V1.4S
	mul	V30.4S, V8.4S, V3.4S
	sqrdmulh	V21.4S, V6.4S, V0.4S
	sqrdmulh	V22.4S, V8.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	ldr	Q0, [x1, #1184]
	ldr	Q2, [x1, #1200]
	ldr	Q1, [x2, #1184]
	ldr	Q3, [x2, #1200]
	mov	V29.16B, V9.16B
	mov	V30.16B, V11.16B
	trn1	V9.4S, V9.4S, V10.4S
	trn1	V11.4S, V11.4S, V12.4S
	trn2	V10.4S, V29.4S, V10.4S
	trn2	V12.4S, V30.4S, V12.4S
	mul	V29.4S, V10.4S, V1.4S
	mul	V30.4S, V12.4S, V3.4S
	sqrdmulh	V23.4S, V10.4S, V0.4S
	sqrdmulh	V24.4S, V12.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	ldr	Q0, [x1, #1216]
	ldr	Q2, [x1, #1232]
	ldr	Q1, [x2, #1216]
	ldr	Q3, [x2, #1232]
	mov	V29.16B, V13.16B
	mov	V30.16B, V15.16B
	trn1	V13.4S, V13.4S, V14.4S
	trn1	V15.4S, V15.4S, V16.4S
	trn2	V14.4S, V29.4S, V14.4S
	trn2	V16.4S, V30.4S, V16.4S
	mul	V29.4S, V14.4S, V1.4S
	mul	V30.4S, V16.4S, V3.4S
	sqrdmulh	V25.4S, V14.4S, V0.4S
	sqrdmulh	V26.4S, V16.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	ldr	Q0, [x1, #1248]
	ldr	Q2, [x1, #1264]
	ldr	Q1, [x2, #1248]
	ldr	Q3, [x2, #1264]
	mov	V29.16B, V17.16B
	mov	V30.16B, V19.16B
	trn1	V17.4S, V17.4S, V18.4S
	trn1	V19.4S, V19.4S, V20.4S
	trn2	V18.4S, V29.4S, V18.4S
	trn2	V20.4S, V30.4S, V20.4S
	mul	V29.4S, V18.4S, V1.4S
	mul	V30.4S, V20.4S, V3.4S
	sqrdmulh	V27.4S, V18.4S, V0.4S
	sqrdmulh	V28.4S, V20.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	stp	Q5, Q6, [x0, #768]
	stp	Q7, Q8, [x0, #800]
	stp	Q9, Q10, [x0, #832]
	stp	Q11, Q12, [x0, #864]
	stp	Q13, Q14, [x0, #896]
	stp	Q15, Q16, [x0, #928]
	stp	Q17, Q18, [x0, #960]
	stp	Q19, Q20, [x0, #992]
	ldp	D8, D9, [x29, #16]
	ldp	D10, D11, [x29, #32]
	ldp	D12, D13, [x29, #48]
	ldp	D14, D15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
	ENDP
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mldsa_ntt_full_neon
mldsa_ntt_full_neon PROC
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	stp	D10, D11, [x29, #32]
	stp	D12, D13, [x29, #48]
	stp	D14, D15, [x29, #64]
	adrp	x1, L_mldsa_aarch64_zetas
	add	x1, x1, L_mldsa_aarch64_zetas
	adrp	x2, L_mldsa_aarch64_zetas_qinv
	add	x2, x2, L_mldsa_aarch64_zetas_qinv
	adrp	x3, L_mldsa_aarch64_consts
	add	x3, x3, L_mldsa_aarch64_consts
	ldr	Q4, [x3]
	ldr	Q5, [x0]
	ldr	Q6, [x0, #64]
	ldr	Q7, [x0, #128]
	ldr	Q8, [x0, #192]
	ldr	Q9, [x0, #256]
	ldr	Q10, [x0, #320]
	ldr	Q11, [x0, #384]
	ldr	Q12, [x0, #448]
	ldr	Q13, [x0, #512]
	ldr	Q14, [x0, #576]
	ldr	Q15, [x0, #640]
	ldr	Q16, [x0, #704]
	ldr	Q17, [x0, #768]
	ldr	Q18, [x0, #832]
	ldr	Q19, [x0, #896]
	ldr	Q20, [x0, #960]
	ldr	Q0, [x1]
	ldr	Q1, [x2]
	mul	V29.4S, V13.4S, V1.S[1]
	mul	V30.4S, V14.4S, V1.S[1]
	sqrdmulh	V21.4S, V13.4S, V0.S[1]
	sqrdmulh	V22.4S, V14.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V15.4S, V1.S[1]
	mul	V30.4S, V16.4S, V1.S[1]
	sqrdmulh	V23.4S, V15.4S, V0.S[1]
	sqrdmulh	V24.4S, V16.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V17.4S, V1.S[1]
	mul	V30.4S, V18.4S, V1.S[1]
	sqrdmulh	V25.4S, V17.4S, V0.S[1]
	sqrdmulh	V26.4S, V18.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[1]
	mul	V30.4S, V20.4S, V1.S[1]
	sqrdmulh	V27.4S, V19.4S, V0.S[1]
	sqrdmulh	V28.4S, V20.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V13.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V14.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V15.4S, V7.4S, V23.4S
	add	V7.4S, V7.4S, V23.4S
	sub	V16.4S, V8.4S, V24.4S
	add	V8.4S, V8.4S, V24.4S
	sub	V17.4S, V9.4S, V25.4S
	add	V9.4S, V9.4S, V25.4S
	sub	V18.4S, V10.4S, V26.4S
	add	V10.4S, V10.4S, V26.4S
	sub	V19.4S, V11.4S, V27.4S
	add	V11.4S, V11.4S, V27.4S
	sub	V20.4S, V12.4S, V28.4S
	add	V12.4S, V12.4S, V28.4S
	mul	V29.4S, V9.4S, V1.S[2]
	mul	V30.4S, V10.4S, V1.S[2]
	sqrdmulh	V21.4S, V9.4S, V0.S[2]
	sqrdmulh	V22.4S, V10.4S, V0.S[2]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V11.4S, V1.S[2]
	mul	V30.4S, V12.4S, V1.S[2]
	sqrdmulh	V23.4S, V11.4S, V0.S[2]
	sqrdmulh	V24.4S, V12.4S, V0.S[2]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V17.4S, V1.S[3]
	mul	V30.4S, V18.4S, V1.S[3]
	sqrdmulh	V25.4S, V17.4S, V0.S[3]
	sqrdmulh	V26.4S, V18.4S, V0.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[3]
	mul	V30.4S, V20.4S, V1.S[3]
	sqrdmulh	V27.4S, V19.4S, V0.S[3]
	sqrdmulh	V28.4S, V20.4S, V0.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V9.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V10.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V11.4S, V7.4S, V23.4S
	add	V7.4S, V7.4S, V23.4S
	sub	V12.4S, V8.4S, V24.4S
	add	V8.4S, V8.4S, V24.4S
	sub	V17.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V18.4S, V14.4S, V26.4S
	add	V14.4S, V14.4S, V26.4S
	sub	V19.4S, V15.4S, V27.4S
	add	V15.4S, V15.4S, V27.4S
	sub	V20.4S, V16.4S, V28.4S
	add	V16.4S, V16.4S, V28.4S
	ldr	Q0, [x1, #16]
	ldr	Q1, [x2, #16]
	mul	V29.4S, V7.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[0]
	sqrdmulh	V21.4S, V7.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[0]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V11.4S, V1.S[1]
	mul	V30.4S, V12.4S, V1.S[1]
	sqrdmulh	V23.4S, V11.4S, V0.S[1]
	sqrdmulh	V24.4S, V12.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V15.4S, V1.S[2]
	mul	V30.4S, V16.4S, V1.S[2]
	sqrdmulh	V25.4S, V15.4S, V0.S[2]
	sqrdmulh	V26.4S, V16.4S, V0.S[2]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[3]
	mul	V30.4S, V20.4S, V1.S[3]
	sqrdmulh	V27.4S, V19.4S, V0.S[3]
	sqrdmulh	V28.4S, V20.4S, V0.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V7.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V11.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V10.4S, V24.4S
	add	V10.4S, V10.4S, V24.4S
	sub	V15.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V14.4S, V26.4S
	add	V14.4S, V14.4S, V26.4S
	sub	V19.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V18.4S, V28.4S
	add	V18.4S, V18.4S, V28.4S
	ldp	Q0, Q2, [x1, #32]
	ldp	Q1, Q3, [x2, #32]
	mul	V29.4S, V6.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[1]
	sqrdmulh	V21.4S, V6.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V10.4S, V1.S[2]
	mul	V30.4S, V12.4S, V1.S[3]
	sqrdmulh	V23.4S, V10.4S, V0.S[2]
	sqrdmulh	V24.4S, V12.4S, V0.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V14.4S, V3.S[0]
	mul	V30.4S, V16.4S, V3.S[1]
	sqrdmulh	V25.4S, V14.4S, V2.S[0]
	sqrdmulh	V26.4S, V16.4S, V2.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V18.4S, V3.S[2]
	mul	V30.4S, V20.4S, V3.S[3]
	sqrdmulh	V27.4S, V18.4S, V2.S[2]
	sqrdmulh	V28.4S, V20.4S, V2.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	str	Q5, [x0]
	str	Q6, [x0, #64]
	str	Q7, [x0, #128]
	str	Q8, [x0, #192]
	str	Q9, [x0, #256]
	str	Q10, [x0, #320]
	str	Q11, [x0, #384]
	str	Q12, [x0, #448]
	str	Q13, [x0, #512]
	str	Q14, [x0, #576]
	str	Q15, [x0, #640]
	str	Q16, [x0, #704]
	str	Q17, [x0, #768]
	str	Q18, [x0, #832]
	str	Q19, [x0, #896]
	str	Q20, [x0, #960]
	ldr	Q5, [x0, #16]
	ldr	Q6, [x0, #80]
	ldr	Q7, [x0, #144]
	ldr	Q8, [x0, #208]
	ldr	Q9, [x0, #272]
	ldr	Q10, [x0, #336]
	ldr	Q11, [x0, #400]
	ldr	Q12, [x0, #464]
	ldr	Q13, [x0, #528]
	ldr	Q14, [x0, #592]
	ldr	Q15, [x0, #656]
	ldr	Q16, [x0, #720]
	ldr	Q17, [x0, #784]
	ldr	Q18, [x0, #848]
	ldr	Q19, [x0, #912]
	ldr	Q20, [x0, #976]
	ldr	Q0, [x1]
	ldr	Q1, [x2]
	mul	V29.4S, V13.4S, V1.S[1]
	mul	V30.4S, V14.4S, V1.S[1]
	sqrdmulh	V21.4S, V13.4S, V0.S[1]
	sqrdmulh	V22.4S, V14.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V15.4S, V1.S[1]
	mul	V30.4S, V16.4S, V1.S[1]
	sqrdmulh	V23.4S, V15.4S, V0.S[1]
	sqrdmulh	V24.4S, V16.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V17.4S, V1.S[1]
	mul	V30.4S, V18.4S, V1.S[1]
	sqrdmulh	V25.4S, V17.4S, V0.S[1]
	sqrdmulh	V26.4S, V18.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[1]
	mul	V30.4S, V20.4S, V1.S[1]
	sqrdmulh	V27.4S, V19.4S, V0.S[1]
	sqrdmulh	V28.4S, V20.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V13.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V14.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V15.4S, V7.4S, V23.4S
	add	V7.4S, V7.4S, V23.4S
	sub	V16.4S, V8.4S, V24.4S
	add	V8.4S, V8.4S, V24.4S
	sub	V17.4S, V9.4S, V25.4S
	add	V9.4S, V9.4S, V25.4S
	sub	V18.4S, V10.4S, V26.4S
	add	V10.4S, V10.4S, V26.4S
	sub	V19.4S, V11.4S, V27.4S
	add	V11.4S, V11.4S, V27.4S
	sub	V20.4S, V12.4S, V28.4S
	add	V12.4S, V12.4S, V28.4S
	mul	V29.4S, V9.4S, V1.S[2]
	mul	V30.4S, V10.4S, V1.S[2]
	sqrdmulh	V21.4S, V9.4S, V0.S[2]
	sqrdmulh	V22.4S, V10.4S, V0.S[2]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V11.4S, V1.S[2]
	mul	V30.4S, V12.4S, V1.S[2]
	sqrdmulh	V23.4S, V11.4S, V0.S[2]
	sqrdmulh	V24.4S, V12.4S, V0.S[2]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V17.4S, V1.S[3]
	mul	V30.4S, V18.4S, V1.S[3]
	sqrdmulh	V25.4S, V17.4S, V0.S[3]
	sqrdmulh	V26.4S, V18.4S, V0.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[3]
	mul	V30.4S, V20.4S, V1.S[3]
	sqrdmulh	V27.4S, V19.4S, V0.S[3]
	sqrdmulh	V28.4S, V20.4S, V0.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V9.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V10.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V11.4S, V7.4S, V23.4S
	add	V7.4S, V7.4S, V23.4S
	sub	V12.4S, V8.4S, V24.4S
	add	V8.4S, V8.4S, V24.4S
	sub	V17.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V18.4S, V14.4S, V26.4S
	add	V14.4S, V14.4S, V26.4S
	sub	V19.4S, V15.4S, V27.4S
	add	V15.4S, V15.4S, V27.4S
	sub	V20.4S, V16.4S, V28.4S
	add	V16.4S, V16.4S, V28.4S
	ldr	Q0, [x1, #16]
	ldr	Q1, [x2, #16]
	mul	V29.4S, V7.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[0]
	sqrdmulh	V21.4S, V7.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[0]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V11.4S, V1.S[1]
	mul	V30.4S, V12.4S, V1.S[1]
	sqrdmulh	V23.4S, V11.4S, V0.S[1]
	sqrdmulh	V24.4S, V12.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V15.4S, V1.S[2]
	mul	V30.4S, V16.4S, V1.S[2]
	sqrdmulh	V25.4S, V15.4S, V0.S[2]
	sqrdmulh	V26.4S, V16.4S, V0.S[2]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[3]
	mul	V30.4S, V20.4S, V1.S[3]
	sqrdmulh	V27.4S, V19.4S, V0.S[3]
	sqrdmulh	V28.4S, V20.4S, V0.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V7.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V11.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V10.4S, V24.4S
	add	V10.4S, V10.4S, V24.4S
	sub	V15.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V14.4S, V26.4S
	add	V14.4S, V14.4S, V26.4S
	sub	V19.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V18.4S, V28.4S
	add	V18.4S, V18.4S, V28.4S
	ldp	Q0, Q2, [x1, #32]
	ldp	Q1, Q3, [x2, #32]
	mul	V29.4S, V6.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[1]
	sqrdmulh	V21.4S, V6.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V10.4S, V1.S[2]
	mul	V30.4S, V12.4S, V1.S[3]
	sqrdmulh	V23.4S, V10.4S, V0.S[2]
	sqrdmulh	V24.4S, V12.4S, V0.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V14.4S, V3.S[0]
	mul	V30.4S, V16.4S, V3.S[1]
	sqrdmulh	V25.4S, V14.4S, V2.S[0]
	sqrdmulh	V26.4S, V16.4S, V2.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V18.4S, V3.S[2]
	mul	V30.4S, V20.4S, V3.S[3]
	sqrdmulh	V27.4S, V18.4S, V2.S[2]
	sqrdmulh	V28.4S, V20.4S, V2.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	str	Q5, [x0, #16]
	str	Q6, [x0, #80]
	str	Q7, [x0, #144]
	str	Q8, [x0, #208]
	str	Q9, [x0, #272]
	str	Q10, [x0, #336]
	str	Q11, [x0, #400]
	str	Q12, [x0, #464]
	str	Q13, [x0, #528]
	str	Q14, [x0, #592]
	str	Q15, [x0, #656]
	str	Q16, [x0, #720]
	str	Q17, [x0, #784]
	str	Q18, [x0, #848]
	str	Q19, [x0, #912]
	str	Q20, [x0, #976]
	ldr	Q5, [x0, #32]
	ldr	Q6, [x0, #96]
	ldr	Q7, [x0, #160]
	ldr	Q8, [x0, #224]
	ldr	Q9, [x0, #288]
	ldr	Q10, [x0, #352]
	ldr	Q11, [x0, #416]
	ldr	Q12, [x0, #480]
	ldr	Q13, [x0, #544]
	ldr	Q14, [x0, #608]
	ldr	Q15, [x0, #672]
	ldr	Q16, [x0, #736]
	ldr	Q17, [x0, #800]
	ldr	Q18, [x0, #864]
	ldr	Q19, [x0, #928]
	ldr	Q20, [x0, #992]
	ldr	Q0, [x1]
	ldr	Q1, [x2]
	mul	V29.4S, V13.4S, V1.S[1]
	mul	V30.4S, V14.4S, V1.S[1]
	sqrdmulh	V21.4S, V13.4S, V0.S[1]
	sqrdmulh	V22.4S, V14.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V15.4S, V1.S[1]
	mul	V30.4S, V16.4S, V1.S[1]
	sqrdmulh	V23.4S, V15.4S, V0.S[1]
	sqrdmulh	V24.4S, V16.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V17.4S, V1.S[1]
	mul	V30.4S, V18.4S, V1.S[1]
	sqrdmulh	V25.4S, V17.4S, V0.S[1]
	sqrdmulh	V26.4S, V18.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[1]
	mul	V30.4S, V20.4S, V1.S[1]
	sqrdmulh	V27.4S, V19.4S, V0.S[1]
	sqrdmulh	V28.4S, V20.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V13.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V14.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V15.4S, V7.4S, V23.4S
	add	V7.4S, V7.4S, V23.4S
	sub	V16.4S, V8.4S, V24.4S
	add	V8.4S, V8.4S, V24.4S
	sub	V17.4S, V9.4S, V25.4S
	add	V9.4S, V9.4S, V25.4S
	sub	V18.4S, V10.4S, V26.4S
	add	V10.4S, V10.4S, V26.4S
	sub	V19.4S, V11.4S, V27.4S
	add	V11.4S, V11.4S, V27.4S
	sub	V20.4S, V12.4S, V28.4S
	add	V12.4S, V12.4S, V28.4S
	mul	V29.4S, V9.4S, V1.S[2]
	mul	V30.4S, V10.4S, V1.S[2]
	sqrdmulh	V21.4S, V9.4S, V0.S[2]
	sqrdmulh	V22.4S, V10.4S, V0.S[2]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V11.4S, V1.S[2]
	mul	V30.4S, V12.4S, V1.S[2]
	sqrdmulh	V23.4S, V11.4S, V0.S[2]
	sqrdmulh	V24.4S, V12.4S, V0.S[2]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V17.4S, V1.S[3]
	mul	V30.4S, V18.4S, V1.S[3]
	sqrdmulh	V25.4S, V17.4S, V0.S[3]
	sqrdmulh	V26.4S, V18.4S, V0.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[3]
	mul	V30.4S, V20.4S, V1.S[3]
	sqrdmulh	V27.4S, V19.4S, V0.S[3]
	sqrdmulh	V28.4S, V20.4S, V0.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V9.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V10.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V11.4S, V7.4S, V23.4S
	add	V7.4S, V7.4S, V23.4S
	sub	V12.4S, V8.4S, V24.4S
	add	V8.4S, V8.4S, V24.4S
	sub	V17.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V18.4S, V14.4S, V26.4S
	add	V14.4S, V14.4S, V26.4S
	sub	V19.4S, V15.4S, V27.4S
	add	V15.4S, V15.4S, V27.4S
	sub	V20.4S, V16.4S, V28.4S
	add	V16.4S, V16.4S, V28.4S
	ldr	Q0, [x1, #16]
	ldr	Q1, [x2, #16]
	mul	V29.4S, V7.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[0]
	sqrdmulh	V21.4S, V7.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[0]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V11.4S, V1.S[1]
	mul	V30.4S, V12.4S, V1.S[1]
	sqrdmulh	V23.4S, V11.4S, V0.S[1]
	sqrdmulh	V24.4S, V12.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V15.4S, V1.S[2]
	mul	V30.4S, V16.4S, V1.S[2]
	sqrdmulh	V25.4S, V15.4S, V0.S[2]
	sqrdmulh	V26.4S, V16.4S, V0.S[2]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[3]
	mul	V30.4S, V20.4S, V1.S[3]
	sqrdmulh	V27.4S, V19.4S, V0.S[3]
	sqrdmulh	V28.4S, V20.4S, V0.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V7.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V11.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V10.4S, V24.4S
	add	V10.4S, V10.4S, V24.4S
	sub	V15.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V14.4S, V26.4S
	add	V14.4S, V14.4S, V26.4S
	sub	V19.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V18.4S, V28.4S
	add	V18.4S, V18.4S, V28.4S
	ldp	Q0, Q2, [x1, #32]
	ldp	Q1, Q3, [x2, #32]
	mul	V29.4S, V6.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[1]
	sqrdmulh	V21.4S, V6.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V10.4S, V1.S[2]
	mul	V30.4S, V12.4S, V1.S[3]
	sqrdmulh	V23.4S, V10.4S, V0.S[2]
	sqrdmulh	V24.4S, V12.4S, V0.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V14.4S, V3.S[0]
	mul	V30.4S, V16.4S, V3.S[1]
	sqrdmulh	V25.4S, V14.4S, V2.S[0]
	sqrdmulh	V26.4S, V16.4S, V2.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V18.4S, V3.S[2]
	mul	V30.4S, V20.4S, V3.S[3]
	sqrdmulh	V27.4S, V18.4S, V2.S[2]
	sqrdmulh	V28.4S, V20.4S, V2.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	str	Q5, [x0, #32]
	str	Q6, [x0, #96]
	str	Q7, [x0, #160]
	str	Q8, [x0, #224]
	str	Q9, [x0, #288]
	str	Q10, [x0, #352]
	str	Q11, [x0, #416]
	str	Q12, [x0, #480]
	str	Q13, [x0, #544]
	str	Q14, [x0, #608]
	str	Q15, [x0, #672]
	str	Q16, [x0, #736]
	str	Q17, [x0, #800]
	str	Q18, [x0, #864]
	str	Q19, [x0, #928]
	str	Q20, [x0, #992]
	ldr	Q5, [x0, #48]
	ldr	Q6, [x0, #112]
	ldr	Q7, [x0, #176]
	ldr	Q8, [x0, #240]
	ldr	Q9, [x0, #304]
	ldr	Q10, [x0, #368]
	ldr	Q11, [x0, #432]
	ldr	Q12, [x0, #496]
	ldr	Q13, [x0, #560]
	ldr	Q14, [x0, #624]
	ldr	Q15, [x0, #688]
	ldr	Q16, [x0, #752]
	ldr	Q17, [x0, #816]
	ldr	Q18, [x0, #880]
	ldr	Q19, [x0, #944]
	ldr	Q20, [x0, #1008]
	ldr	Q0, [x1]
	ldr	Q1, [x2]
	mul	V29.4S, V13.4S, V1.S[1]
	mul	V30.4S, V14.4S, V1.S[1]
	sqrdmulh	V21.4S, V13.4S, V0.S[1]
	sqrdmulh	V22.4S, V14.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V15.4S, V1.S[1]
	mul	V30.4S, V16.4S, V1.S[1]
	sqrdmulh	V23.4S, V15.4S, V0.S[1]
	sqrdmulh	V24.4S, V16.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V17.4S, V1.S[1]
	mul	V30.4S, V18.4S, V1.S[1]
	sqrdmulh	V25.4S, V17.4S, V0.S[1]
	sqrdmulh	V26.4S, V18.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[1]
	mul	V30.4S, V20.4S, V1.S[1]
	sqrdmulh	V27.4S, V19.4S, V0.S[1]
	sqrdmulh	V28.4S, V20.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V13.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V14.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V15.4S, V7.4S, V23.4S
	add	V7.4S, V7.4S, V23.4S
	sub	V16.4S, V8.4S, V24.4S
	add	V8.4S, V8.4S, V24.4S
	sub	V17.4S, V9.4S, V25.4S
	add	V9.4S, V9.4S, V25.4S
	sub	V18.4S, V10.4S, V26.4S
	add	V10.4S, V10.4S, V26.4S
	sub	V19.4S, V11.4S, V27.4S
	add	V11.4S, V11.4S, V27.4S
	sub	V20.4S, V12.4S, V28.4S
	add	V12.4S, V12.4S, V28.4S
	mul	V29.4S, V9.4S, V1.S[2]
	mul	V30.4S, V10.4S, V1.S[2]
	sqrdmulh	V21.4S, V9.4S, V0.S[2]
	sqrdmulh	V22.4S, V10.4S, V0.S[2]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V11.4S, V1.S[2]
	mul	V30.4S, V12.4S, V1.S[2]
	sqrdmulh	V23.4S, V11.4S, V0.S[2]
	sqrdmulh	V24.4S, V12.4S, V0.S[2]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V17.4S, V1.S[3]
	mul	V30.4S, V18.4S, V1.S[3]
	sqrdmulh	V25.4S, V17.4S, V0.S[3]
	sqrdmulh	V26.4S, V18.4S, V0.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[3]
	mul	V30.4S, V20.4S, V1.S[3]
	sqrdmulh	V27.4S, V19.4S, V0.S[3]
	sqrdmulh	V28.4S, V20.4S, V0.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V9.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V10.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V11.4S, V7.4S, V23.4S
	add	V7.4S, V7.4S, V23.4S
	sub	V12.4S, V8.4S, V24.4S
	add	V8.4S, V8.4S, V24.4S
	sub	V17.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V18.4S, V14.4S, V26.4S
	add	V14.4S, V14.4S, V26.4S
	sub	V19.4S, V15.4S, V27.4S
	add	V15.4S, V15.4S, V27.4S
	sub	V20.4S, V16.4S, V28.4S
	add	V16.4S, V16.4S, V28.4S
	ldr	Q0, [x1, #16]
	ldr	Q1, [x2, #16]
	mul	V29.4S, V7.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[0]
	sqrdmulh	V21.4S, V7.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[0]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V11.4S, V1.S[1]
	mul	V30.4S, V12.4S, V1.S[1]
	sqrdmulh	V23.4S, V11.4S, V0.S[1]
	sqrdmulh	V24.4S, V12.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V15.4S, V1.S[2]
	mul	V30.4S, V16.4S, V1.S[2]
	sqrdmulh	V25.4S, V15.4S, V0.S[2]
	sqrdmulh	V26.4S, V16.4S, V0.S[2]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[3]
	mul	V30.4S, V20.4S, V1.S[3]
	sqrdmulh	V27.4S, V19.4S, V0.S[3]
	sqrdmulh	V28.4S, V20.4S, V0.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V7.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V11.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V10.4S, V24.4S
	add	V10.4S, V10.4S, V24.4S
	sub	V15.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V14.4S, V26.4S
	add	V14.4S, V14.4S, V26.4S
	sub	V19.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V18.4S, V28.4S
	add	V18.4S, V18.4S, V28.4S
	ldp	Q0, Q2, [x1, #32]
	ldp	Q1, Q3, [x2, #32]
	mul	V29.4S, V6.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[1]
	sqrdmulh	V21.4S, V6.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V10.4S, V1.S[2]
	mul	V30.4S, V12.4S, V1.S[3]
	sqrdmulh	V23.4S, V10.4S, V0.S[2]
	sqrdmulh	V24.4S, V12.4S, V0.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V14.4S, V3.S[0]
	mul	V30.4S, V16.4S, V3.S[1]
	sqrdmulh	V25.4S, V14.4S, V2.S[0]
	sqrdmulh	V26.4S, V16.4S, V2.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V18.4S, V3.S[2]
	mul	V30.4S, V20.4S, V3.S[3]
	sqrdmulh	V27.4S, V18.4S, V2.S[2]
	sqrdmulh	V28.4S, V20.4S, V2.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	str	Q5, [x0, #48]
	str	Q6, [x0, #112]
	str	Q7, [x0, #176]
	str	Q8, [x0, #240]
	str	Q9, [x0, #304]
	str	Q10, [x0, #368]
	str	Q11, [x0, #432]
	str	Q12, [x0, #496]
	str	Q13, [x0, #560]
	str	Q14, [x0, #624]
	str	Q15, [x0, #688]
	str	Q16, [x0, #752]
	str	Q17, [x0, #816]
	str	Q18, [x0, #880]
	str	Q19, [x0, #944]
	str	Q20, [x0, #1008]
	ldp	Q5, Q6, [x0]
	ldp	Q7, Q8, [x0, #32]
	ldp	Q9, Q10, [x0, #64]
	ldp	Q11, Q12, [x0, #96]
	ldp	Q13, Q14, [x0, #128]
	ldp	Q15, Q16, [x0, #160]
	ldp	Q17, Q18, [x0, #192]
	ldp	Q19, Q20, [x0, #224]
	ldr	Q0, [x1, #64]
	ldr	Q1, [x2, #64]
	mul	V29.4S, V7.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[0]
	sqrdmulh	V21.4S, V7.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[0]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V11.4S, V1.S[1]
	mul	V30.4S, V12.4S, V1.S[1]
	sqrdmulh	V23.4S, V11.4S, V0.S[1]
	sqrdmulh	V24.4S, V12.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V15.4S, V1.S[2]
	mul	V30.4S, V16.4S, V1.S[2]
	sqrdmulh	V25.4S, V15.4S, V0.S[2]
	sqrdmulh	V26.4S, V16.4S, V0.S[2]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[3]
	mul	V30.4S, V20.4S, V1.S[3]
	sqrdmulh	V27.4S, V19.4S, V0.S[3]
	sqrdmulh	V28.4S, V20.4S, V0.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V7.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V11.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V10.4S, V24.4S
	add	V10.4S, V10.4S, V24.4S
	sub	V15.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V14.4S, V26.4S
	add	V14.4S, V14.4S, V26.4S
	sub	V19.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V18.4S, V28.4S
	add	V18.4S, V18.4S, V28.4S
	ldp	Q0, Q2, [x1, #128]
	ldp	Q1, Q3, [x2, #128]
	mul	V29.4S, V6.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[1]
	sqrdmulh	V21.4S, V6.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V10.4S, V1.S[2]
	mul	V30.4S, V12.4S, V1.S[3]
	sqrdmulh	V23.4S, V10.4S, V0.S[2]
	sqrdmulh	V24.4S, V12.4S, V0.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V14.4S, V3.S[0]
	mul	V30.4S, V16.4S, V3.S[1]
	sqrdmulh	V25.4S, V14.4S, V2.S[0]
	sqrdmulh	V26.4S, V16.4S, V2.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V18.4S, V3.S[2]
	mul	V30.4S, V20.4S, V3.S[3]
	sqrdmulh	V27.4S, V18.4S, V2.S[2]
	sqrdmulh	V28.4S, V20.4S, V2.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	ldp	Q0, Q2, [x1, #256]
	ldp	Q1, Q3, [x2, #256]
	mov	V29.16B, V5.16B
	mov	V30.16B, V7.16B
	trn1	V5.2D, V5.2D, V6.2D
	trn1	V7.2D, V7.2D, V8.2D
	trn2	V6.2D, V29.2D, V6.2D
	trn2	V8.2D, V30.2D, V8.2D
	mul	V29.4S, V6.4S, V1.4S
	mul	V30.4S, V8.4S, V3.4S
	sqrdmulh	V21.4S, V6.4S, V0.4S
	sqrdmulh	V22.4S, V8.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	ldp	Q0, Q2, [x1, #288]
	ldp	Q1, Q3, [x2, #288]
	mov	V29.16B, V9.16B
	mov	V30.16B, V11.16B
	trn1	V9.2D, V9.2D, V10.2D
	trn1	V11.2D, V11.2D, V12.2D
	trn2	V10.2D, V29.2D, V10.2D
	trn2	V12.2D, V30.2D, V12.2D
	mul	V29.4S, V10.4S, V1.4S
	mul	V30.4S, V12.4S, V3.4S
	sqrdmulh	V23.4S, V10.4S, V0.4S
	sqrdmulh	V24.4S, V12.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	ldp	Q0, Q2, [x1, #320]
	ldp	Q1, Q3, [x2, #320]
	mov	V29.16B, V13.16B
	mov	V30.16B, V15.16B
	trn1	V13.2D, V13.2D, V14.2D
	trn1	V15.2D, V15.2D, V16.2D
	trn2	V14.2D, V29.2D, V14.2D
	trn2	V16.2D, V30.2D, V16.2D
	mul	V29.4S, V14.4S, V1.4S
	mul	V30.4S, V16.4S, V3.4S
	sqrdmulh	V25.4S, V14.4S, V0.4S
	sqrdmulh	V26.4S, V16.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	ldp	Q0, Q2, [x1, #352]
	ldp	Q1, Q3, [x2, #352]
	mov	V29.16B, V17.16B
	mov	V30.16B, V19.16B
	trn1	V17.2D, V17.2D, V18.2D
	trn1	V19.2D, V19.2D, V20.2D
	trn2	V18.2D, V29.2D, V18.2D
	trn2	V20.2D, V30.2D, V20.2D
	mul	V29.4S, V18.4S, V1.4S
	mul	V30.4S, V20.4S, V3.4S
	sqrdmulh	V27.4S, V18.4S, V0.4S
	sqrdmulh	V28.4S, V20.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	ldp	Q0, Q2, [x1, #768]
	ldp	Q1, Q3, [x2, #768]
	mov	V29.16B, V5.16B
	mov	V30.16B, V7.16B
	trn1	V5.4S, V5.4S, V6.4S
	trn1	V7.4S, V7.4S, V8.4S
	trn2	V6.4S, V29.4S, V6.4S
	trn2	V8.4S, V30.4S, V8.4S
	mul	V29.4S, V6.4S, V1.4S
	mul	V30.4S, V8.4S, V3.4S
	sqrdmulh	V21.4S, V6.4S, V0.4S
	sqrdmulh	V22.4S, V8.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	ldp	Q0, Q2, [x1, #800]
	ldp	Q1, Q3, [x2, #800]
	mov	V29.16B, V9.16B
	mov	V30.16B, V11.16B
	trn1	V9.4S, V9.4S, V10.4S
	trn1	V11.4S, V11.4S, V12.4S
	trn2	V10.4S, V29.4S, V10.4S
	trn2	V12.4S, V30.4S, V12.4S
	mul	V29.4S, V10.4S, V1.4S
	mul	V30.4S, V12.4S, V3.4S
	sqrdmulh	V23.4S, V10.4S, V0.4S
	sqrdmulh	V24.4S, V12.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	ldp	Q0, Q2, [x1, #832]
	ldp	Q1, Q3, [x2, #832]
	mov	V29.16B, V13.16B
	mov	V30.16B, V15.16B
	trn1	V13.4S, V13.4S, V14.4S
	trn1	V15.4S, V15.4S, V16.4S
	trn2	V14.4S, V29.4S, V14.4S
	trn2	V16.4S, V30.4S, V16.4S
	mul	V29.4S, V14.4S, V1.4S
	mul	V30.4S, V16.4S, V3.4S
	sqrdmulh	V25.4S, V14.4S, V0.4S
	sqrdmulh	V26.4S, V16.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	ldp	Q0, Q2, [x1, #864]
	ldp	Q1, Q3, [x2, #864]
	mov	V29.16B, V17.16B
	mov	V30.16B, V19.16B
	trn1	V17.4S, V17.4S, V18.4S
	trn1	V19.4S, V19.4S, V20.4S
	trn2	V18.4S, V29.4S, V18.4S
	trn2	V20.4S, V30.4S, V20.4S
	mul	V29.4S, V18.4S, V1.4S
	mul	V30.4S, V20.4S, V3.4S
	sqrdmulh	V27.4S, V18.4S, V0.4S
	sqrdmulh	V28.4S, V20.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	trn1	V29.4S, V5.4S, V6.4S
	trn2	V30.4S, V5.4S, V6.4S
	trn1	V5.2D, V29.2D, V30.2D
	trn2	V6.2D, V29.2D, V30.2D
	trn1	V29.4S, V7.4S, V8.4S
	trn2	V30.4S, V7.4S, V8.4S
	trn1	V7.2D, V29.2D, V30.2D
	trn2	V8.2D, V29.2D, V30.2D
	trn1	V29.4S, V9.4S, V10.4S
	trn2	V30.4S, V9.4S, V10.4S
	trn1	V9.2D, V29.2D, V30.2D
	trn2	V10.2D, V29.2D, V30.2D
	trn1	V29.4S, V11.4S, V12.4S
	trn2	V30.4S, V11.4S, V12.4S
	trn1	V11.2D, V29.2D, V30.2D
	trn2	V12.2D, V29.2D, V30.2D
	trn1	V29.4S, V13.4S, V14.4S
	trn2	V30.4S, V13.4S, V14.4S
	trn1	V13.2D, V29.2D, V30.2D
	trn2	V14.2D, V29.2D, V30.2D
	trn1	V29.4S, V15.4S, V16.4S
	trn2	V30.4S, V15.4S, V16.4S
	trn1	V15.2D, V29.2D, V30.2D
	trn2	V16.2D, V29.2D, V30.2D
	trn1	V29.4S, V17.4S, V18.4S
	trn2	V30.4S, V17.4S, V18.4S
	trn1	V17.2D, V29.2D, V30.2D
	trn2	V18.2D, V29.2D, V30.2D
	trn1	V29.4S, V19.4S, V20.4S
	trn2	V30.4S, V19.4S, V20.4S
	trn1	V19.2D, V29.2D, V30.2D
	trn2	V20.2D, V29.2D, V30.2D
	stp	Q5, Q6, [x0]
	stp	Q7, Q8, [x0, #32]
	stp	Q9, Q10, [x0, #64]
	stp	Q11, Q12, [x0, #96]
	stp	Q13, Q14, [x0, #128]
	stp	Q15, Q16, [x0, #160]
	stp	Q17, Q18, [x0, #192]
	stp	Q19, Q20, [x0, #224]
	ldp	Q5, Q6, [x0, #256]
	ldp	Q7, Q8, [x0, #288]
	ldp	Q9, Q10, [x0, #320]
	ldp	Q11, Q12, [x0, #352]
	ldp	Q13, Q14, [x0, #384]
	ldp	Q15, Q16, [x0, #416]
	ldp	Q17, Q18, [x0, #448]
	ldp	Q19, Q20, [x0, #480]
	ldr	Q0, [x1, #80]
	ldr	Q1, [x2, #80]
	mul	V29.4S, V7.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[0]
	sqrdmulh	V21.4S, V7.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[0]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V11.4S, V1.S[1]
	mul	V30.4S, V12.4S, V1.S[1]
	sqrdmulh	V23.4S, V11.4S, V0.S[1]
	sqrdmulh	V24.4S, V12.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V15.4S, V1.S[2]
	mul	V30.4S, V16.4S, V1.S[2]
	sqrdmulh	V25.4S, V15.4S, V0.S[2]
	sqrdmulh	V26.4S, V16.4S, V0.S[2]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[3]
	mul	V30.4S, V20.4S, V1.S[3]
	sqrdmulh	V27.4S, V19.4S, V0.S[3]
	sqrdmulh	V28.4S, V20.4S, V0.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V7.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V11.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V10.4S, V24.4S
	add	V10.4S, V10.4S, V24.4S
	sub	V15.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V14.4S, V26.4S
	add	V14.4S, V14.4S, V26.4S
	sub	V19.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V18.4S, V28.4S
	add	V18.4S, V18.4S, V28.4S
	ldp	Q0, Q2, [x1, #160]
	ldp	Q1, Q3, [x2, #160]
	mul	V29.4S, V6.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[1]
	sqrdmulh	V21.4S, V6.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V10.4S, V1.S[2]
	mul	V30.4S, V12.4S, V1.S[3]
	sqrdmulh	V23.4S, V10.4S, V0.S[2]
	sqrdmulh	V24.4S, V12.4S, V0.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V14.4S, V3.S[0]
	mul	V30.4S, V16.4S, V3.S[1]
	sqrdmulh	V25.4S, V14.4S, V2.S[0]
	sqrdmulh	V26.4S, V16.4S, V2.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V18.4S, V3.S[2]
	mul	V30.4S, V20.4S, V3.S[3]
	sqrdmulh	V27.4S, V18.4S, V2.S[2]
	sqrdmulh	V28.4S, V20.4S, V2.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	ldp	Q0, Q2, [x1, #384]
	ldp	Q1, Q3, [x2, #384]
	mov	V29.16B, V5.16B
	mov	V30.16B, V7.16B
	trn1	V5.2D, V5.2D, V6.2D
	trn1	V7.2D, V7.2D, V8.2D
	trn2	V6.2D, V29.2D, V6.2D
	trn2	V8.2D, V30.2D, V8.2D
	mul	V29.4S, V6.4S, V1.4S
	mul	V30.4S, V8.4S, V3.4S
	sqrdmulh	V21.4S, V6.4S, V0.4S
	sqrdmulh	V22.4S, V8.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	ldp	Q0, Q2, [x1, #416]
	ldp	Q1, Q3, [x2, #416]
	mov	V29.16B, V9.16B
	mov	V30.16B, V11.16B
	trn1	V9.2D, V9.2D, V10.2D
	trn1	V11.2D, V11.2D, V12.2D
	trn2	V10.2D, V29.2D, V10.2D
	trn2	V12.2D, V30.2D, V12.2D
	mul	V29.4S, V10.4S, V1.4S
	mul	V30.4S, V12.4S, V3.4S
	sqrdmulh	V23.4S, V10.4S, V0.4S
	sqrdmulh	V24.4S, V12.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	ldp	Q0, Q2, [x1, #448]
	ldp	Q1, Q3, [x2, #448]
	mov	V29.16B, V13.16B
	mov	V30.16B, V15.16B
	trn1	V13.2D, V13.2D, V14.2D
	trn1	V15.2D, V15.2D, V16.2D
	trn2	V14.2D, V29.2D, V14.2D
	trn2	V16.2D, V30.2D, V16.2D
	mul	V29.4S, V14.4S, V1.4S
	mul	V30.4S, V16.4S, V3.4S
	sqrdmulh	V25.4S, V14.4S, V0.4S
	sqrdmulh	V26.4S, V16.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	ldp	Q0, Q2, [x1, #480]
	ldp	Q1, Q3, [x2, #480]
	mov	V29.16B, V17.16B
	mov	V30.16B, V19.16B
	trn1	V17.2D, V17.2D, V18.2D
	trn1	V19.2D, V19.2D, V20.2D
	trn2	V18.2D, V29.2D, V18.2D
	trn2	V20.2D, V30.2D, V20.2D
	mul	V29.4S, V18.4S, V1.4S
	mul	V30.4S, V20.4S, V3.4S
	sqrdmulh	V27.4S, V18.4S, V0.4S
	sqrdmulh	V28.4S, V20.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	ldp	Q0, Q2, [x1, #896]
	ldp	Q1, Q3, [x2, #896]
	mov	V29.16B, V5.16B
	mov	V30.16B, V7.16B
	trn1	V5.4S, V5.4S, V6.4S
	trn1	V7.4S, V7.4S, V8.4S
	trn2	V6.4S, V29.4S, V6.4S
	trn2	V8.4S, V30.4S, V8.4S
	mul	V29.4S, V6.4S, V1.4S
	mul	V30.4S, V8.4S, V3.4S
	sqrdmulh	V21.4S, V6.4S, V0.4S
	sqrdmulh	V22.4S, V8.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	ldp	Q0, Q2, [x1, #928]
	ldp	Q1, Q3, [x2, #928]
	mov	V29.16B, V9.16B
	mov	V30.16B, V11.16B
	trn1	V9.4S, V9.4S, V10.4S
	trn1	V11.4S, V11.4S, V12.4S
	trn2	V10.4S, V29.4S, V10.4S
	trn2	V12.4S, V30.4S, V12.4S
	mul	V29.4S, V10.4S, V1.4S
	mul	V30.4S, V12.4S, V3.4S
	sqrdmulh	V23.4S, V10.4S, V0.4S
	sqrdmulh	V24.4S, V12.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	ldp	Q0, Q2, [x1, #960]
	ldp	Q1, Q3, [x2, #960]
	mov	V29.16B, V13.16B
	mov	V30.16B, V15.16B
	trn1	V13.4S, V13.4S, V14.4S
	trn1	V15.4S, V15.4S, V16.4S
	trn2	V14.4S, V29.4S, V14.4S
	trn2	V16.4S, V30.4S, V16.4S
	mul	V29.4S, V14.4S, V1.4S
	mul	V30.4S, V16.4S, V3.4S
	sqrdmulh	V25.4S, V14.4S, V0.4S
	sqrdmulh	V26.4S, V16.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	ldp	Q0, Q2, [x1, #992]
	ldp	Q1, Q3, [x2, #992]
	mov	V29.16B, V17.16B
	mov	V30.16B, V19.16B
	trn1	V17.4S, V17.4S, V18.4S
	trn1	V19.4S, V19.4S, V20.4S
	trn2	V18.4S, V29.4S, V18.4S
	trn2	V20.4S, V30.4S, V20.4S
	mul	V29.4S, V18.4S, V1.4S
	mul	V30.4S, V20.4S, V3.4S
	sqrdmulh	V27.4S, V18.4S, V0.4S
	sqrdmulh	V28.4S, V20.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	trn1	V29.4S, V5.4S, V6.4S
	trn2	V30.4S, V5.4S, V6.4S
	trn1	V5.2D, V29.2D, V30.2D
	trn2	V6.2D, V29.2D, V30.2D
	trn1	V29.4S, V7.4S, V8.4S
	trn2	V30.4S, V7.4S, V8.4S
	trn1	V7.2D, V29.2D, V30.2D
	trn2	V8.2D, V29.2D, V30.2D
	trn1	V29.4S, V9.4S, V10.4S
	trn2	V30.4S, V9.4S, V10.4S
	trn1	V9.2D, V29.2D, V30.2D
	trn2	V10.2D, V29.2D, V30.2D
	trn1	V29.4S, V11.4S, V12.4S
	trn2	V30.4S, V11.4S, V12.4S
	trn1	V11.2D, V29.2D, V30.2D
	trn2	V12.2D, V29.2D, V30.2D
	trn1	V29.4S, V13.4S, V14.4S
	trn2	V30.4S, V13.4S, V14.4S
	trn1	V13.2D, V29.2D, V30.2D
	trn2	V14.2D, V29.2D, V30.2D
	trn1	V29.4S, V15.4S, V16.4S
	trn2	V30.4S, V15.4S, V16.4S
	trn1	V15.2D, V29.2D, V30.2D
	trn2	V16.2D, V29.2D, V30.2D
	trn1	V29.4S, V17.4S, V18.4S
	trn2	V30.4S, V17.4S, V18.4S
	trn1	V17.2D, V29.2D, V30.2D
	trn2	V18.2D, V29.2D, V30.2D
	trn1	V29.4S, V19.4S, V20.4S
	trn2	V30.4S, V19.4S, V20.4S
	trn1	V19.2D, V29.2D, V30.2D
	trn2	V20.2D, V29.2D, V30.2D
	stp	Q5, Q6, [x0, #256]
	stp	Q7, Q8, [x0, #288]
	stp	Q9, Q10, [x0, #320]
	stp	Q11, Q12, [x0, #352]
	stp	Q13, Q14, [x0, #384]
	stp	Q15, Q16, [x0, #416]
	stp	Q17, Q18, [x0, #448]
	stp	Q19, Q20, [x0, #480]
	ldp	Q5, Q6, [x0, #512]
	ldp	Q7, Q8, [x0, #544]
	ldp	Q9, Q10, [x0, #576]
	ldp	Q11, Q12, [x0, #608]
	ldp	Q13, Q14, [x0, #640]
	ldp	Q15, Q16, [x0, #672]
	ldp	Q17, Q18, [x0, #704]
	ldp	Q19, Q20, [x0, #736]
	ldr	Q0, [x1, #96]
	ldr	Q1, [x2, #96]
	mul	V29.4S, V7.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[0]
	sqrdmulh	V21.4S, V7.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[0]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V11.4S, V1.S[1]
	mul	V30.4S, V12.4S, V1.S[1]
	sqrdmulh	V23.4S, V11.4S, V0.S[1]
	sqrdmulh	V24.4S, V12.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V15.4S, V1.S[2]
	mul	V30.4S, V16.4S, V1.S[2]
	sqrdmulh	V25.4S, V15.4S, V0.S[2]
	sqrdmulh	V26.4S, V16.4S, V0.S[2]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[3]
	mul	V30.4S, V20.4S, V1.S[3]
	sqrdmulh	V27.4S, V19.4S, V0.S[3]
	sqrdmulh	V28.4S, V20.4S, V0.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V7.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V11.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V10.4S, V24.4S
	add	V10.4S, V10.4S, V24.4S
	sub	V15.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V14.4S, V26.4S
	add	V14.4S, V14.4S, V26.4S
	sub	V19.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V18.4S, V28.4S
	add	V18.4S, V18.4S, V28.4S
	ldp	Q0, Q2, [x1, #192]
	ldp	Q1, Q3, [x2, #192]
	mul	V29.4S, V6.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[1]
	sqrdmulh	V21.4S, V6.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V10.4S, V1.S[2]
	mul	V30.4S, V12.4S, V1.S[3]
	sqrdmulh	V23.4S, V10.4S, V0.S[2]
	sqrdmulh	V24.4S, V12.4S, V0.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V14.4S, V3.S[0]
	mul	V30.4S, V16.4S, V3.S[1]
	sqrdmulh	V25.4S, V14.4S, V2.S[0]
	sqrdmulh	V26.4S, V16.4S, V2.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V18.4S, V3.S[2]
	mul	V30.4S, V20.4S, V3.S[3]
	sqrdmulh	V27.4S, V18.4S, V2.S[2]
	sqrdmulh	V28.4S, V20.4S, V2.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	ldp	Q0, Q2, [x1, #512]
	ldp	Q1, Q3, [x2, #512]
	mov	V29.16B, V5.16B
	mov	V30.16B, V7.16B
	trn1	V5.2D, V5.2D, V6.2D
	trn1	V7.2D, V7.2D, V8.2D
	trn2	V6.2D, V29.2D, V6.2D
	trn2	V8.2D, V30.2D, V8.2D
	mul	V29.4S, V6.4S, V1.4S
	mul	V30.4S, V8.4S, V3.4S
	sqrdmulh	V21.4S, V6.4S, V0.4S
	sqrdmulh	V22.4S, V8.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	ldp	Q0, Q2, [x1, #544]
	ldp	Q1, Q3, [x2, #544]
	mov	V29.16B, V9.16B
	mov	V30.16B, V11.16B
	trn1	V9.2D, V9.2D, V10.2D
	trn1	V11.2D, V11.2D, V12.2D
	trn2	V10.2D, V29.2D, V10.2D
	trn2	V12.2D, V30.2D, V12.2D
	mul	V29.4S, V10.4S, V1.4S
	mul	V30.4S, V12.4S, V3.4S
	sqrdmulh	V23.4S, V10.4S, V0.4S
	sqrdmulh	V24.4S, V12.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	ldp	Q0, Q2, [x1, #576]
	ldp	Q1, Q3, [x2, #576]
	mov	V29.16B, V13.16B
	mov	V30.16B, V15.16B
	trn1	V13.2D, V13.2D, V14.2D
	trn1	V15.2D, V15.2D, V16.2D
	trn2	V14.2D, V29.2D, V14.2D
	trn2	V16.2D, V30.2D, V16.2D
	mul	V29.4S, V14.4S, V1.4S
	mul	V30.4S, V16.4S, V3.4S
	sqrdmulh	V25.4S, V14.4S, V0.4S
	sqrdmulh	V26.4S, V16.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	ldp	Q0, Q2, [x1, #608]
	ldp	Q1, Q3, [x2, #608]
	mov	V29.16B, V17.16B
	mov	V30.16B, V19.16B
	trn1	V17.2D, V17.2D, V18.2D
	trn1	V19.2D, V19.2D, V20.2D
	trn2	V18.2D, V29.2D, V18.2D
	trn2	V20.2D, V30.2D, V20.2D
	mul	V29.4S, V18.4S, V1.4S
	mul	V30.4S, V20.4S, V3.4S
	sqrdmulh	V27.4S, V18.4S, V0.4S
	sqrdmulh	V28.4S, V20.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	ldr	Q0, [x1, #1024]
	ldr	Q2, [x1, #1040]
	ldr	Q1, [x2, #1024]
	ldr	Q3, [x2, #1040]
	mov	V29.16B, V5.16B
	mov	V30.16B, V7.16B
	trn1	V5.4S, V5.4S, V6.4S
	trn1	V7.4S, V7.4S, V8.4S
	trn2	V6.4S, V29.4S, V6.4S
	trn2	V8.4S, V30.4S, V8.4S
	mul	V29.4S, V6.4S, V1.4S
	mul	V30.4S, V8.4S, V3.4S
	sqrdmulh	V21.4S, V6.4S, V0.4S
	sqrdmulh	V22.4S, V8.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	ldr	Q0, [x1, #1056]
	ldr	Q2, [x1, #1072]
	ldr	Q1, [x2, #1056]
	ldr	Q3, [x2, #1072]
	mov	V29.16B, V9.16B
	mov	V30.16B, V11.16B
	trn1	V9.4S, V9.4S, V10.4S
	trn1	V11.4S, V11.4S, V12.4S
	trn2	V10.4S, V29.4S, V10.4S
	trn2	V12.4S, V30.4S, V12.4S
	mul	V29.4S, V10.4S, V1.4S
	mul	V30.4S, V12.4S, V3.4S
	sqrdmulh	V23.4S, V10.4S, V0.4S
	sqrdmulh	V24.4S, V12.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	ldr	Q0, [x1, #1088]
	ldr	Q2, [x1, #1104]
	ldr	Q1, [x2, #1088]
	ldr	Q3, [x2, #1104]
	mov	V29.16B, V13.16B
	mov	V30.16B, V15.16B
	trn1	V13.4S, V13.4S, V14.4S
	trn1	V15.4S, V15.4S, V16.4S
	trn2	V14.4S, V29.4S, V14.4S
	trn2	V16.4S, V30.4S, V16.4S
	mul	V29.4S, V14.4S, V1.4S
	mul	V30.4S, V16.4S, V3.4S
	sqrdmulh	V25.4S, V14.4S, V0.4S
	sqrdmulh	V26.4S, V16.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	ldr	Q0, [x1, #1120]
	ldr	Q2, [x1, #1136]
	ldr	Q1, [x2, #1120]
	ldr	Q3, [x2, #1136]
	mov	V29.16B, V17.16B
	mov	V30.16B, V19.16B
	trn1	V17.4S, V17.4S, V18.4S
	trn1	V19.4S, V19.4S, V20.4S
	trn2	V18.4S, V29.4S, V18.4S
	trn2	V20.4S, V30.4S, V20.4S
	mul	V29.4S, V18.4S, V1.4S
	mul	V30.4S, V20.4S, V3.4S
	sqrdmulh	V27.4S, V18.4S, V0.4S
	sqrdmulh	V28.4S, V20.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	trn1	V29.4S, V5.4S, V6.4S
	trn2	V30.4S, V5.4S, V6.4S
	trn1	V5.2D, V29.2D, V30.2D
	trn2	V6.2D, V29.2D, V30.2D
	trn1	V29.4S, V7.4S, V8.4S
	trn2	V30.4S, V7.4S, V8.4S
	trn1	V7.2D, V29.2D, V30.2D
	trn2	V8.2D, V29.2D, V30.2D
	trn1	V29.4S, V9.4S, V10.4S
	trn2	V30.4S, V9.4S, V10.4S
	trn1	V9.2D, V29.2D, V30.2D
	trn2	V10.2D, V29.2D, V30.2D
	trn1	V29.4S, V11.4S, V12.4S
	trn2	V30.4S, V11.4S, V12.4S
	trn1	V11.2D, V29.2D, V30.2D
	trn2	V12.2D, V29.2D, V30.2D
	trn1	V29.4S, V13.4S, V14.4S
	trn2	V30.4S, V13.4S, V14.4S
	trn1	V13.2D, V29.2D, V30.2D
	trn2	V14.2D, V29.2D, V30.2D
	trn1	V29.4S, V15.4S, V16.4S
	trn2	V30.4S, V15.4S, V16.4S
	trn1	V15.2D, V29.2D, V30.2D
	trn2	V16.2D, V29.2D, V30.2D
	trn1	V29.4S, V17.4S, V18.4S
	trn2	V30.4S, V17.4S, V18.4S
	trn1	V17.2D, V29.2D, V30.2D
	trn2	V18.2D, V29.2D, V30.2D
	trn1	V29.4S, V19.4S, V20.4S
	trn2	V30.4S, V19.4S, V20.4S
	trn1	V19.2D, V29.2D, V30.2D
	trn2	V20.2D, V29.2D, V30.2D
	stp	Q5, Q6, [x0, #512]
	stp	Q7, Q8, [x0, #544]
	stp	Q9, Q10, [x0, #576]
	stp	Q11, Q12, [x0, #608]
	stp	Q13, Q14, [x0, #640]
	stp	Q15, Q16, [x0, #672]
	stp	Q17, Q18, [x0, #704]
	stp	Q19, Q20, [x0, #736]
	ldp	Q5, Q6, [x0, #768]
	ldp	Q7, Q8, [x0, #800]
	ldp	Q9, Q10, [x0, #832]
	ldp	Q11, Q12, [x0, #864]
	ldp	Q13, Q14, [x0, #896]
	ldp	Q15, Q16, [x0, #928]
	ldp	Q17, Q18, [x0, #960]
	ldp	Q19, Q20, [x0, #992]
	ldr	Q0, [x1, #112]
	ldr	Q1, [x2, #112]
	mul	V29.4S, V7.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[0]
	sqrdmulh	V21.4S, V7.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[0]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V11.4S, V1.S[1]
	mul	V30.4S, V12.4S, V1.S[1]
	sqrdmulh	V23.4S, V11.4S, V0.S[1]
	sqrdmulh	V24.4S, V12.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V15.4S, V1.S[2]
	mul	V30.4S, V16.4S, V1.S[2]
	sqrdmulh	V25.4S, V15.4S, V0.S[2]
	sqrdmulh	V26.4S, V16.4S, V0.S[2]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[3]
	mul	V30.4S, V20.4S, V1.S[3]
	sqrdmulh	V27.4S, V19.4S, V0.S[3]
	sqrdmulh	V28.4S, V20.4S, V0.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V7.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V11.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V10.4S, V24.4S
	add	V10.4S, V10.4S, V24.4S
	sub	V15.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V14.4S, V26.4S
	add	V14.4S, V14.4S, V26.4S
	sub	V19.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V18.4S, V28.4S
	add	V18.4S, V18.4S, V28.4S
	ldp	Q0, Q2, [x1, #224]
	ldp	Q1, Q3, [x2, #224]
	mul	V29.4S, V6.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[1]
	sqrdmulh	V21.4S, V6.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V10.4S, V1.S[2]
	mul	V30.4S, V12.4S, V1.S[3]
	sqrdmulh	V23.4S, V10.4S, V0.S[2]
	sqrdmulh	V24.4S, V12.4S, V0.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V14.4S, V3.S[0]
	mul	V30.4S, V16.4S, V3.S[1]
	sqrdmulh	V25.4S, V14.4S, V2.S[0]
	sqrdmulh	V26.4S, V16.4S, V2.S[1]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V18.4S, V3.S[2]
	mul	V30.4S, V20.4S, V3.S[3]
	sqrdmulh	V27.4S, V18.4S, V2.S[2]
	sqrdmulh	V28.4S, V20.4S, V2.S[3]
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	ldp	Q0, Q2, [x1, #640]
	ldp	Q1, Q3, [x2, #640]
	mov	V29.16B, V5.16B
	mov	V30.16B, V7.16B
	trn1	V5.2D, V5.2D, V6.2D
	trn1	V7.2D, V7.2D, V8.2D
	trn2	V6.2D, V29.2D, V6.2D
	trn2	V8.2D, V30.2D, V8.2D
	mul	V29.4S, V6.4S, V1.4S
	mul	V30.4S, V8.4S, V3.4S
	sqrdmulh	V21.4S, V6.4S, V0.4S
	sqrdmulh	V22.4S, V8.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	ldp	Q0, Q2, [x1, #672]
	ldp	Q1, Q3, [x2, #672]
	mov	V29.16B, V9.16B
	mov	V30.16B, V11.16B
	trn1	V9.2D, V9.2D, V10.2D
	trn1	V11.2D, V11.2D, V12.2D
	trn2	V10.2D, V29.2D, V10.2D
	trn2	V12.2D, V30.2D, V12.2D
	mul	V29.4S, V10.4S, V1.4S
	mul	V30.4S, V12.4S, V3.4S
	sqrdmulh	V23.4S, V10.4S, V0.4S
	sqrdmulh	V24.4S, V12.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	ldp	Q0, Q2, [x1, #704]
	ldp	Q1, Q3, [x2, #704]
	mov	V29.16B, V13.16B
	mov	V30.16B, V15.16B
	trn1	V13.2D, V13.2D, V14.2D
	trn1	V15.2D, V15.2D, V16.2D
	trn2	V14.2D, V29.2D, V14.2D
	trn2	V16.2D, V30.2D, V16.2D
	mul	V29.4S, V14.4S, V1.4S
	mul	V30.4S, V16.4S, V3.4S
	sqrdmulh	V25.4S, V14.4S, V0.4S
	sqrdmulh	V26.4S, V16.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	ldp	Q0, Q2, [x1, #736]
	ldp	Q1, Q3, [x2, #736]
	mov	V29.16B, V17.16B
	mov	V30.16B, V19.16B
	trn1	V17.2D, V17.2D, V18.2D
	trn1	V19.2D, V19.2D, V20.2D
	trn2	V18.2D, V29.2D, V18.2D
	trn2	V20.2D, V30.2D, V20.2D
	mul	V29.4S, V18.4S, V1.4S
	mul	V30.4S, V20.4S, V3.4S
	sqrdmulh	V27.4S, V18.4S, V0.4S
	sqrdmulh	V28.4S, V20.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	ldr	Q0, [x1, #1152]
	ldr	Q2, [x1, #1168]
	ldr	Q1, [x2, #1152]
	ldr	Q3, [x2, #1168]
	mov	V29.16B, V5.16B
	mov	V30.16B, V7.16B
	trn1	V5.4S, V5.4S, V6.4S
	trn1	V7.4S, V7.4S, V8.4S
	trn2	V6.4S, V29.4S, V6.4S
	trn2	V8.4S, V30.4S, V8.4S
	mul	V29.4S, V6.4S, V1.4S
	mul	V30.4S, V8.4S, V3.4S
	sqrdmulh	V21.4S, V6.4S, V0.4S
	sqrdmulh	V22.4S, V8.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V21.4S, V21.4S, V29.4S
	sub	V22.4S, V22.4S, V30.4S
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	ldr	Q0, [x1, #1184]
	ldr	Q2, [x1, #1200]
	ldr	Q1, [x2, #1184]
	ldr	Q3, [x2, #1200]
	mov	V29.16B, V9.16B
	mov	V30.16B, V11.16B
	trn1	V9.4S, V9.4S, V10.4S
	trn1	V11.4S, V11.4S, V12.4S
	trn2	V10.4S, V29.4S, V10.4S
	trn2	V12.4S, V30.4S, V12.4S
	mul	V29.4S, V10.4S, V1.4S
	mul	V30.4S, V12.4S, V3.4S
	sqrdmulh	V23.4S, V10.4S, V0.4S
	sqrdmulh	V24.4S, V12.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V23.4S, V23.4S, V29.4S
	sub	V24.4S, V24.4S, V30.4S
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	ldr	Q0, [x1, #1216]
	ldr	Q2, [x1, #1232]
	ldr	Q1, [x2, #1216]
	ldr	Q3, [x2, #1232]
	mov	V29.16B, V13.16B
	mov	V30.16B, V15.16B
	trn1	V13.4S, V13.4S, V14.4S
	trn1	V15.4S, V15.4S, V16.4S
	trn2	V14.4S, V29.4S, V14.4S
	trn2	V16.4S, V30.4S, V16.4S
	mul	V29.4S, V14.4S, V1.4S
	mul	V30.4S, V16.4S, V3.4S
	sqrdmulh	V25.4S, V14.4S, V0.4S
	sqrdmulh	V26.4S, V16.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V25.4S, V25.4S, V29.4S
	sub	V26.4S, V26.4S, V30.4S
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	ldr	Q0, [x1, #1248]
	ldr	Q2, [x1, #1264]
	ldr	Q1, [x2, #1248]
	ldr	Q3, [x2, #1264]
	mov	V29.16B, V17.16B
	mov	V30.16B, V19.16B
	trn1	V17.4S, V17.4S, V18.4S
	trn1	V19.4S, V19.4S, V20.4S
	trn2	V18.4S, V29.4S, V18.4S
	trn2	V20.4S, V30.4S, V20.4S
	mul	V29.4S, V18.4S, V1.4S
	mul	V30.4S, V20.4S, V3.4S
	sqrdmulh	V27.4S, V18.4S, V0.4S
	sqrdmulh	V28.4S, V20.4S, V2.4S
	sqrdmulh	V29.4S, V29.4S, V4.S[0]
	sqrdmulh	V30.4S, V30.4S, V4.S[0]
	sub	V27.4S, V27.4S, V29.4S
	sub	V28.4S, V28.4S, V30.4S
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	trn1	V29.4S, V5.4S, V6.4S
	trn2	V30.4S, V5.4S, V6.4S
	trn1	V5.2D, V29.2D, V30.2D
	trn2	V6.2D, V29.2D, V30.2D
	trn1	V29.4S, V7.4S, V8.4S
	trn2	V30.4S, V7.4S, V8.4S
	trn1	V7.2D, V29.2D, V30.2D
	trn2	V8.2D, V29.2D, V30.2D
	trn1	V29.4S, V9.4S, V10.4S
	trn2	V30.4S, V9.4S, V10.4S
	trn1	V9.2D, V29.2D, V30.2D
	trn2	V10.2D, V29.2D, V30.2D
	trn1	V29.4S, V11.4S, V12.4S
	trn2	V30.4S, V11.4S, V12.4S
	trn1	V11.2D, V29.2D, V30.2D
	trn2	V12.2D, V29.2D, V30.2D
	trn1	V29.4S, V13.4S, V14.4S
	trn2	V30.4S, V13.4S, V14.4S
	trn1	V13.2D, V29.2D, V30.2D
	trn2	V14.2D, V29.2D, V30.2D
	trn1	V29.4S, V15.4S, V16.4S
	trn2	V30.4S, V15.4S, V16.4S
	trn1	V15.2D, V29.2D, V30.2D
	trn2	V16.2D, V29.2D, V30.2D
	trn1	V29.4S, V17.4S, V18.4S
	trn2	V30.4S, V17.4S, V18.4S
	trn1	V17.2D, V29.2D, V30.2D
	trn2	V18.2D, V29.2D, V30.2D
	trn1	V29.4S, V19.4S, V20.4S
	trn2	V30.4S, V19.4S, V20.4S
	trn1	V19.2D, V29.2D, V30.2D
	trn2	V20.2D, V29.2D, V30.2D
	stp	Q5, Q6, [x0, #768]
	stp	Q7, Q8, [x0, #800]
	stp	Q9, Q10, [x0, #832]
	stp	Q11, Q12, [x0, #864]
	stp	Q13, Q14, [x0, #896]
	stp	Q15, Q16, [x0, #928]
	stp	Q17, Q18, [x0, #960]
	stp	Q19, Q20, [x0, #992]
	ldp	D8, D9, [x29, #16]
	ldp	D10, D11, [x29, #32]
	ldp	D12, D13, [x29, #48]
	ldp	D14, D15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
	ENDP
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mldsa_invntt_neon
mldsa_invntt_neon PROC
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	stp	D10, D11, [x29, #32]
	stp	D12, D13, [x29, #48]
	stp	D14, D15, [x29, #64]
	adrp	x1, L_mldsa_aarch64_zetas_inv
	add	x1, x1, L_mldsa_aarch64_zetas_inv
	adrp	x2, L_mldsa_aarch64_zetas_inv_qinv
	add	x2, x2, L_mldsa_aarch64_zetas_inv_qinv
	adrp	x3, L_mldsa_aarch64_consts
	add	x3, x3, L_mldsa_aarch64_consts
	ldr	Q4, [x3]
	ldp	Q5, Q6, [x0]
	ldp	Q7, Q8, [x0, #32]
	ldp	Q9, Q10, [x0, #64]
	ldp	Q11, Q12, [x0, #96]
	ldp	Q13, Q14, [x0, #128]
	ldp	Q15, Q16, [x0, #160]
	ldp	Q17, Q18, [x0, #192]
	ldp	Q19, Q20, [x0, #224]
	ldp	Q0, Q1, [x1]
	ldp	Q2, Q3, [x2]
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V6.4S, V22.4S, V0.4S
	sqrdmulh	V8.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V6.4S, V6.4S, V21.4S
	sub	V8.4S, V8.4S, V23.4S
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	ldp	Q0, Q1, [x1, #32]
	ldp	Q2, Q3, [x2, #32]
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V10.4S, V22.4S, V0.4S
	sqrdmulh	V12.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V10.4S, V10.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	ldp	Q0, Q1, [x1, #64]
	ldp	Q2, Q3, [x2, #64]
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V14.4S, V22.4S, V0.4S
	sqrdmulh	V16.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V14.4S, V14.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	ldp	Q0, Q1, [x1, #96]
	ldp	Q2, Q3, [x2, #96]
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V18.4S, V22.4S, V0.4S
	sqrdmulh	V20.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V18.4S, V18.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldp	Q0, Q1, [x1, #512]
	ldp	Q2, Q3, [x2, #512]
	mov	V21.16B, V5.16B
	mov	V22.16B, V7.16B
	trn1	V5.4S, V5.4S, V6.4S
	trn1	V7.4S, V7.4S, V8.4S
	trn2	V6.4S, V21.4S, V6.4S
	trn2	V8.4S, V22.4S, V8.4S
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V6.4S, V22.4S, V0.4S
	sqrdmulh	V8.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V6.4S, V6.4S, V21.4S
	sub	V8.4S, V8.4S, V23.4S
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	ldp	Q0, Q1, [x1, #544]
	ldp	Q2, Q3, [x2, #544]
	mov	V21.16B, V9.16B
	mov	V22.16B, V11.16B
	trn1	V9.4S, V9.4S, V10.4S
	trn1	V11.4S, V11.4S, V12.4S
	trn2	V10.4S, V21.4S, V10.4S
	trn2	V12.4S, V22.4S, V12.4S
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V10.4S, V22.4S, V0.4S
	sqrdmulh	V12.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V10.4S, V10.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	ldp	Q0, Q1, [x1, #576]
	ldp	Q2, Q3, [x2, #576]
	mov	V21.16B, V13.16B
	mov	V22.16B, V15.16B
	trn1	V13.4S, V13.4S, V14.4S
	trn1	V15.4S, V15.4S, V16.4S
	trn2	V14.4S, V21.4S, V14.4S
	trn2	V16.4S, V22.4S, V16.4S
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V14.4S, V22.4S, V0.4S
	sqrdmulh	V16.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V14.4S, V14.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	ldp	Q0, Q1, [x1, #608]
	ldp	Q2, Q3, [x2, #608]
	mov	V21.16B, V17.16B
	mov	V22.16B, V19.16B
	trn1	V17.4S, V17.4S, V18.4S
	trn1	V19.4S, V19.4S, V20.4S
	trn2	V18.4S, V21.4S, V18.4S
	trn2	V20.4S, V22.4S, V20.4S
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V18.4S, V22.4S, V0.4S
	sqrdmulh	V20.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V18.4S, V18.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1024]
	ldr	Q1, [x1, #1040]
	ldr	Q2, [x2, #1024]
	ldr	Q3, [x2, #1040]
	mov	V21.16B, V5.16B
	mov	V22.16B, V7.16B
	trn1	V5.2D, V5.2D, V6.2D
	trn1	V7.2D, V7.2D, V8.2D
	trn2	V6.2D, V21.2D, V6.2D
	trn2	V8.2D, V22.2D, V8.2D
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V6.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V6.4S, V6.4S, V21.4S
	sub	V8.4S, V8.4S, V23.4S
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	mov	V21.16B, V9.16B
	mov	V22.16B, V11.16B
	trn1	V9.2D, V9.2D, V10.2D
	trn1	V11.2D, V11.2D, V12.2D
	trn2	V10.2D, V21.2D, V10.2D
	trn2	V12.2D, V22.2D, V12.2D
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V10.4S, V22.4S, V0.S[2]
	sqrdmulh	V12.4S, V24.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V10.4S, V10.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	mov	V21.16B, V13.16B
	mov	V22.16B, V15.16B
	trn1	V13.2D, V13.2D, V14.2D
	trn1	V15.2D, V15.2D, V16.2D
	trn2	V14.2D, V21.2D, V14.2D
	trn2	V16.2D, V22.2D, V16.2D
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V3.S[0]
	mul	V23.4S, V24.4S, V3.S[1]
	sqrdmulh	V14.4S, V22.4S, V1.S[0]
	sqrdmulh	V16.4S, V24.4S, V1.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V14.4S, V14.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	mov	V21.16B, V17.16B
	mov	V22.16B, V19.16B
	trn1	V17.2D, V17.2D, V18.2D
	trn1	V19.2D, V19.2D, V20.2D
	trn2	V18.2D, V21.2D, V18.2D
	trn2	V20.2D, V22.2D, V20.2D
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V3.S[2]
	mul	V23.4S, V24.4S, V3.S[3]
	sqrdmulh	V18.4S, V22.4S, V1.S[2]
	sqrdmulh	V20.4S, V24.4S, V1.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V18.4S, V18.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1152]
	ldr	Q2, [x2, #1152]
	sub	V22.4S, V5.4S, V7.4S
	sub	V24.4S, V6.4S, V8.4S
	add	V5.4S, V5.4S, V7.4S
	add	V6.4S, V6.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V7.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[0]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V7.4S, V7.4S, V21.4S
	sub	V8.4S, V8.4S, V23.4S
	sshr	V7.4S, V7.4S, #1
	sshr	V8.4S, V8.4S, #1
	sub	V22.4S, V9.4S, V11.4S
	sub	V24.4S, V10.4S, V12.4S
	add	V9.4S, V9.4S, V11.4S
	add	V10.4S, V10.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V11.4S, V22.4S, V0.S[1]
	sqrdmulh	V12.4S, V24.4S, V0.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V11.4S, V11.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V15.4S
	sub	V24.4S, V14.4S, V16.4S
	add	V13.4S, V13.4S, V15.4S
	add	V14.4S, V14.4S, V16.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V15.4S, V22.4S, V0.S[2]
	sqrdmulh	V16.4S, V24.4S, V0.S[2]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V15.4S, V15.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V15.4S, V15.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V17.4S, V19.4S
	sub	V24.4S, V18.4S, V20.4S
	add	V17.4S, V17.4S, V19.4S
	add	V18.4S, V18.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[3]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V19.4S, V22.4S, V0.S[3]
	sqrdmulh	V20.4S, V24.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V19.4S, V19.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	stp	Q5, Q6, [x0]
	stp	Q7, Q8, [x0, #32]
	stp	Q9, Q10, [x0, #64]
	stp	Q11, Q12, [x0, #96]
	stp	Q13, Q14, [x0, #128]
	stp	Q15, Q16, [x0, #160]
	stp	Q17, Q18, [x0, #192]
	stp	Q19, Q20, [x0, #224]
	ldp	Q5, Q6, [x0, #256]
	ldp	Q7, Q8, [x0, #288]
	ldp	Q9, Q10, [x0, #320]
	ldp	Q11, Q12, [x0, #352]
	ldp	Q13, Q14, [x0, #384]
	ldp	Q15, Q16, [x0, #416]
	ldp	Q17, Q18, [x0, #448]
	ldp	Q19, Q20, [x0, #480]
	ldp	Q0, Q1, [x1, #128]
	ldp	Q2, Q3, [x2, #128]
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V6.4S, V22.4S, V0.4S
	sqrdmulh	V8.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V6.4S, V6.4S, V21.4S
	sub	V8.4S, V8.4S, V23.4S
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	ldp	Q0, Q1, [x1, #160]
	ldp	Q2, Q3, [x2, #160]
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V10.4S, V22.4S, V0.4S
	sqrdmulh	V12.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V10.4S, V10.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	ldp	Q0, Q1, [x1, #192]
	ldp	Q2, Q3, [x2, #192]
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V14.4S, V22.4S, V0.4S
	sqrdmulh	V16.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V14.4S, V14.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	ldp	Q0, Q1, [x1, #224]
	ldp	Q2, Q3, [x2, #224]
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V18.4S, V22.4S, V0.4S
	sqrdmulh	V20.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V18.4S, V18.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldp	Q0, Q1, [x1, #640]
	ldp	Q2, Q3, [x2, #640]
	mov	V21.16B, V5.16B
	mov	V22.16B, V7.16B
	trn1	V5.4S, V5.4S, V6.4S
	trn1	V7.4S, V7.4S, V8.4S
	trn2	V6.4S, V21.4S, V6.4S
	trn2	V8.4S, V22.4S, V8.4S
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V6.4S, V22.4S, V0.4S
	sqrdmulh	V8.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V6.4S, V6.4S, V21.4S
	sub	V8.4S, V8.4S, V23.4S
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	ldp	Q0, Q1, [x1, #672]
	ldp	Q2, Q3, [x2, #672]
	mov	V21.16B, V9.16B
	mov	V22.16B, V11.16B
	trn1	V9.4S, V9.4S, V10.4S
	trn1	V11.4S, V11.4S, V12.4S
	trn2	V10.4S, V21.4S, V10.4S
	trn2	V12.4S, V22.4S, V12.4S
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V10.4S, V22.4S, V0.4S
	sqrdmulh	V12.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V10.4S, V10.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	ldp	Q0, Q1, [x1, #704]
	ldp	Q2, Q3, [x2, #704]
	mov	V21.16B, V13.16B
	mov	V22.16B, V15.16B
	trn1	V13.4S, V13.4S, V14.4S
	trn1	V15.4S, V15.4S, V16.4S
	trn2	V14.4S, V21.4S, V14.4S
	trn2	V16.4S, V22.4S, V16.4S
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V14.4S, V22.4S, V0.4S
	sqrdmulh	V16.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V14.4S, V14.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	ldp	Q0, Q1, [x1, #736]
	ldp	Q2, Q3, [x2, #736]
	mov	V21.16B, V17.16B
	mov	V22.16B, V19.16B
	trn1	V17.4S, V17.4S, V18.4S
	trn1	V19.4S, V19.4S, V20.4S
	trn2	V18.4S, V21.4S, V18.4S
	trn2	V20.4S, V22.4S, V20.4S
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V18.4S, V22.4S, V0.4S
	sqrdmulh	V20.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V18.4S, V18.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1056]
	ldr	Q1, [x1, #1072]
	ldr	Q2, [x2, #1056]
	ldr	Q3, [x2, #1072]
	mov	V21.16B, V5.16B
	mov	V22.16B, V7.16B
	trn1	V5.2D, V5.2D, V6.2D
	trn1	V7.2D, V7.2D, V8.2D
	trn2	V6.2D, V21.2D, V6.2D
	trn2	V8.2D, V22.2D, V8.2D
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V6.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V6.4S, V6.4S, V21.4S
	sub	V8.4S, V8.4S, V23.4S
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	mov	V21.16B, V9.16B
	mov	V22.16B, V11.16B
	trn1	V9.2D, V9.2D, V10.2D
	trn1	V11.2D, V11.2D, V12.2D
	trn2	V10.2D, V21.2D, V10.2D
	trn2	V12.2D, V22.2D, V12.2D
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V10.4S, V22.4S, V0.S[2]
	sqrdmulh	V12.4S, V24.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V10.4S, V10.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	mov	V21.16B, V13.16B
	mov	V22.16B, V15.16B
	trn1	V13.2D, V13.2D, V14.2D
	trn1	V15.2D, V15.2D, V16.2D
	trn2	V14.2D, V21.2D, V14.2D
	trn2	V16.2D, V22.2D, V16.2D
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V3.S[0]
	mul	V23.4S, V24.4S, V3.S[1]
	sqrdmulh	V14.4S, V22.4S, V1.S[0]
	sqrdmulh	V16.4S, V24.4S, V1.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V14.4S, V14.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	mov	V21.16B, V17.16B
	mov	V22.16B, V19.16B
	trn1	V17.2D, V17.2D, V18.2D
	trn1	V19.2D, V19.2D, V20.2D
	trn2	V18.2D, V21.2D, V18.2D
	trn2	V20.2D, V22.2D, V20.2D
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V3.S[2]
	mul	V23.4S, V24.4S, V3.S[3]
	sqrdmulh	V18.4S, V22.4S, V1.S[2]
	sqrdmulh	V20.4S, V24.4S, V1.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V18.4S, V18.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1168]
	ldr	Q2, [x2, #1168]
	sub	V22.4S, V5.4S, V7.4S
	sub	V24.4S, V6.4S, V8.4S
	add	V5.4S, V5.4S, V7.4S
	add	V6.4S, V6.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V7.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[0]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V7.4S, V7.4S, V21.4S
	sub	V8.4S, V8.4S, V23.4S
	sshr	V7.4S, V7.4S, #1
	sshr	V8.4S, V8.4S, #1
	sub	V22.4S, V9.4S, V11.4S
	sub	V24.4S, V10.4S, V12.4S
	add	V9.4S, V9.4S, V11.4S
	add	V10.4S, V10.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V11.4S, V22.4S, V0.S[1]
	sqrdmulh	V12.4S, V24.4S, V0.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V11.4S, V11.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V15.4S
	sub	V24.4S, V14.4S, V16.4S
	add	V13.4S, V13.4S, V15.4S
	add	V14.4S, V14.4S, V16.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V15.4S, V22.4S, V0.S[2]
	sqrdmulh	V16.4S, V24.4S, V0.S[2]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V15.4S, V15.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V15.4S, V15.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V17.4S, V19.4S
	sub	V24.4S, V18.4S, V20.4S
	add	V17.4S, V17.4S, V19.4S
	add	V18.4S, V18.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[3]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V19.4S, V22.4S, V0.S[3]
	sqrdmulh	V20.4S, V24.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V19.4S, V19.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	stp	Q5, Q6, [x0, #256]
	stp	Q7, Q8, [x0, #288]
	stp	Q9, Q10, [x0, #320]
	stp	Q11, Q12, [x0, #352]
	stp	Q13, Q14, [x0, #384]
	stp	Q15, Q16, [x0, #416]
	stp	Q17, Q18, [x0, #448]
	stp	Q19, Q20, [x0, #480]
	ldp	Q5, Q6, [x0, #512]
	ldp	Q7, Q8, [x0, #544]
	ldp	Q9, Q10, [x0, #576]
	ldp	Q11, Q12, [x0, #608]
	ldp	Q13, Q14, [x0, #640]
	ldp	Q15, Q16, [x0, #672]
	ldp	Q17, Q18, [x0, #704]
	ldp	Q19, Q20, [x0, #736]
	ldp	Q0, Q1, [x1, #256]
	ldp	Q2, Q3, [x2, #256]
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V6.4S, V22.4S, V0.4S
	sqrdmulh	V8.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V6.4S, V6.4S, V21.4S
	sub	V8.4S, V8.4S, V23.4S
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	ldp	Q0, Q1, [x1, #288]
	ldp	Q2, Q3, [x2, #288]
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V10.4S, V22.4S, V0.4S
	sqrdmulh	V12.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V10.4S, V10.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	ldp	Q0, Q1, [x1, #320]
	ldp	Q2, Q3, [x2, #320]
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V14.4S, V22.4S, V0.4S
	sqrdmulh	V16.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V14.4S, V14.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	ldp	Q0, Q1, [x1, #352]
	ldp	Q2, Q3, [x2, #352]
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V18.4S, V22.4S, V0.4S
	sqrdmulh	V20.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V18.4S, V18.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldp	Q0, Q1, [x1, #768]
	ldp	Q2, Q3, [x2, #768]
	mov	V21.16B, V5.16B
	mov	V22.16B, V7.16B
	trn1	V5.4S, V5.4S, V6.4S
	trn1	V7.4S, V7.4S, V8.4S
	trn2	V6.4S, V21.4S, V6.4S
	trn2	V8.4S, V22.4S, V8.4S
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V6.4S, V22.4S, V0.4S
	sqrdmulh	V8.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V6.4S, V6.4S, V21.4S
	sub	V8.4S, V8.4S, V23.4S
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	ldp	Q0, Q1, [x1, #800]
	ldp	Q2, Q3, [x2, #800]
	mov	V21.16B, V9.16B
	mov	V22.16B, V11.16B
	trn1	V9.4S, V9.4S, V10.4S
	trn1	V11.4S, V11.4S, V12.4S
	trn2	V10.4S, V21.4S, V10.4S
	trn2	V12.4S, V22.4S, V12.4S
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V10.4S, V22.4S, V0.4S
	sqrdmulh	V12.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V10.4S, V10.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	ldp	Q0, Q1, [x1, #832]
	ldp	Q2, Q3, [x2, #832]
	mov	V21.16B, V13.16B
	mov	V22.16B, V15.16B
	trn1	V13.4S, V13.4S, V14.4S
	trn1	V15.4S, V15.4S, V16.4S
	trn2	V14.4S, V21.4S, V14.4S
	trn2	V16.4S, V22.4S, V16.4S
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V14.4S, V22.4S, V0.4S
	sqrdmulh	V16.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V14.4S, V14.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	ldp	Q0, Q1, [x1, #864]
	ldp	Q2, Q3, [x2, #864]
	mov	V21.16B, V17.16B
	mov	V22.16B, V19.16B
	trn1	V17.4S, V17.4S, V18.4S
	trn1	V19.4S, V19.4S, V20.4S
	trn2	V18.4S, V21.4S, V18.4S
	trn2	V20.4S, V22.4S, V20.4S
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V18.4S, V22.4S, V0.4S
	sqrdmulh	V20.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V18.4S, V18.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1088]
	ldr	Q1, [x1, #1104]
	ldr	Q2, [x2, #1088]
	ldr	Q3, [x2, #1104]
	mov	V21.16B, V5.16B
	mov	V22.16B, V7.16B
	trn1	V5.2D, V5.2D, V6.2D
	trn1	V7.2D, V7.2D, V8.2D
	trn2	V6.2D, V21.2D, V6.2D
	trn2	V8.2D, V22.2D, V8.2D
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V6.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V6.4S, V6.4S, V21.4S
	sub	V8.4S, V8.4S, V23.4S
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	mov	V21.16B, V9.16B
	mov	V22.16B, V11.16B
	trn1	V9.2D, V9.2D, V10.2D
	trn1	V11.2D, V11.2D, V12.2D
	trn2	V10.2D, V21.2D, V10.2D
	trn2	V12.2D, V22.2D, V12.2D
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V10.4S, V22.4S, V0.S[2]
	sqrdmulh	V12.4S, V24.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V10.4S, V10.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	mov	V21.16B, V13.16B
	mov	V22.16B, V15.16B
	trn1	V13.2D, V13.2D, V14.2D
	trn1	V15.2D, V15.2D, V16.2D
	trn2	V14.2D, V21.2D, V14.2D
	trn2	V16.2D, V22.2D, V16.2D
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V3.S[0]
	mul	V23.4S, V24.4S, V3.S[1]
	sqrdmulh	V14.4S, V22.4S, V1.S[0]
	sqrdmulh	V16.4S, V24.4S, V1.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V14.4S, V14.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	mov	V21.16B, V17.16B
	mov	V22.16B, V19.16B
	trn1	V17.2D, V17.2D, V18.2D
	trn1	V19.2D, V19.2D, V20.2D
	trn2	V18.2D, V21.2D, V18.2D
	trn2	V20.2D, V22.2D, V20.2D
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V3.S[2]
	mul	V23.4S, V24.4S, V3.S[3]
	sqrdmulh	V18.4S, V22.4S, V1.S[2]
	sqrdmulh	V20.4S, V24.4S, V1.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V18.4S, V18.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1184]
	ldr	Q2, [x2, #1184]
	sub	V22.4S, V5.4S, V7.4S
	sub	V24.4S, V6.4S, V8.4S
	add	V5.4S, V5.4S, V7.4S
	add	V6.4S, V6.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V7.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[0]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V7.4S, V7.4S, V21.4S
	sub	V8.4S, V8.4S, V23.4S
	sshr	V7.4S, V7.4S, #1
	sshr	V8.4S, V8.4S, #1
	sub	V22.4S, V9.4S, V11.4S
	sub	V24.4S, V10.4S, V12.4S
	add	V9.4S, V9.4S, V11.4S
	add	V10.4S, V10.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V11.4S, V22.4S, V0.S[1]
	sqrdmulh	V12.4S, V24.4S, V0.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V11.4S, V11.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V15.4S
	sub	V24.4S, V14.4S, V16.4S
	add	V13.4S, V13.4S, V15.4S
	add	V14.4S, V14.4S, V16.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V15.4S, V22.4S, V0.S[2]
	sqrdmulh	V16.4S, V24.4S, V0.S[2]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V15.4S, V15.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V15.4S, V15.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V17.4S, V19.4S
	sub	V24.4S, V18.4S, V20.4S
	add	V17.4S, V17.4S, V19.4S
	add	V18.4S, V18.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[3]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V19.4S, V22.4S, V0.S[3]
	sqrdmulh	V20.4S, V24.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V19.4S, V19.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	stp	Q5, Q6, [x0, #512]
	stp	Q7, Q8, [x0, #544]
	stp	Q9, Q10, [x0, #576]
	stp	Q11, Q12, [x0, #608]
	stp	Q13, Q14, [x0, #640]
	stp	Q15, Q16, [x0, #672]
	stp	Q17, Q18, [x0, #704]
	stp	Q19, Q20, [x0, #736]
	ldp	Q5, Q6, [x0, #768]
	ldp	Q7, Q8, [x0, #800]
	ldp	Q9, Q10, [x0, #832]
	ldp	Q11, Q12, [x0, #864]
	ldp	Q13, Q14, [x0, #896]
	ldp	Q15, Q16, [x0, #928]
	ldp	Q17, Q18, [x0, #960]
	ldp	Q19, Q20, [x0, #992]
	ldp	Q0, Q1, [x1, #384]
	ldp	Q2, Q3, [x2, #384]
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V6.4S, V22.4S, V0.4S
	sqrdmulh	V8.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V6.4S, V6.4S, V21.4S
	sub	V8.4S, V8.4S, V23.4S
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	ldp	Q0, Q1, [x1, #416]
	ldp	Q2, Q3, [x2, #416]
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V10.4S, V22.4S, V0.4S
	sqrdmulh	V12.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V10.4S, V10.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	ldp	Q0, Q1, [x1, #448]
	ldp	Q2, Q3, [x2, #448]
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V14.4S, V22.4S, V0.4S
	sqrdmulh	V16.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V14.4S, V14.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	ldp	Q0, Q1, [x1, #480]
	ldp	Q2, Q3, [x2, #480]
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V18.4S, V22.4S, V0.4S
	sqrdmulh	V20.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V18.4S, V18.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldp	Q0, Q1, [x1, #896]
	ldp	Q2, Q3, [x2, #896]
	mov	V21.16B, V5.16B
	mov	V22.16B, V7.16B
	trn1	V5.4S, V5.4S, V6.4S
	trn1	V7.4S, V7.4S, V8.4S
	trn2	V6.4S, V21.4S, V6.4S
	trn2	V8.4S, V22.4S, V8.4S
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V6.4S, V22.4S, V0.4S
	sqrdmulh	V8.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V6.4S, V6.4S, V21.4S
	sub	V8.4S, V8.4S, V23.4S
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	ldp	Q0, Q1, [x1, #928]
	ldp	Q2, Q3, [x2, #928]
	mov	V21.16B, V9.16B
	mov	V22.16B, V11.16B
	trn1	V9.4S, V9.4S, V10.4S
	trn1	V11.4S, V11.4S, V12.4S
	trn2	V10.4S, V21.4S, V10.4S
	trn2	V12.4S, V22.4S, V12.4S
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V10.4S, V22.4S, V0.4S
	sqrdmulh	V12.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V10.4S, V10.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	ldp	Q0, Q1, [x1, #960]
	ldp	Q2, Q3, [x2, #960]
	mov	V21.16B, V13.16B
	mov	V22.16B, V15.16B
	trn1	V13.4S, V13.4S, V14.4S
	trn1	V15.4S, V15.4S, V16.4S
	trn2	V14.4S, V21.4S, V14.4S
	trn2	V16.4S, V22.4S, V16.4S
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V14.4S, V22.4S, V0.4S
	sqrdmulh	V16.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V14.4S, V14.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	ldp	Q0, Q1, [x1, #992]
	ldp	Q2, Q3, [x2, #992]
	mov	V21.16B, V17.16B
	mov	V22.16B, V19.16B
	trn1	V17.4S, V17.4S, V18.4S
	trn1	V19.4S, V19.4S, V20.4S
	trn2	V18.4S, V21.4S, V18.4S
	trn2	V20.4S, V22.4S, V20.4S
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V18.4S, V22.4S, V0.4S
	sqrdmulh	V20.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V18.4S, V18.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1120]
	ldr	Q1, [x1, #1136]
	ldr	Q2, [x2, #1120]
	ldr	Q3, [x2, #1136]
	mov	V21.16B, V5.16B
	mov	V22.16B, V7.16B
	trn1	V5.2D, V5.2D, V6.2D
	trn1	V7.2D, V7.2D, V8.2D
	trn2	V6.2D, V21.2D, V6.2D
	trn2	V8.2D, V22.2D, V8.2D
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V6.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V6.4S, V6.4S, V21.4S
	sub	V8.4S, V8.4S, V23.4S
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	mov	V21.16B, V9.16B
	mov	V22.16B, V11.16B
	trn1	V9.2D, V9.2D, V10.2D
	trn1	V11.2D, V11.2D, V12.2D
	trn2	V10.2D, V21.2D, V10.2D
	trn2	V12.2D, V22.2D, V12.2D
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V10.4S, V22.4S, V0.S[2]
	sqrdmulh	V12.4S, V24.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V10.4S, V10.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	mov	V21.16B, V13.16B
	mov	V22.16B, V15.16B
	trn1	V13.2D, V13.2D, V14.2D
	trn1	V15.2D, V15.2D, V16.2D
	trn2	V14.2D, V21.2D, V14.2D
	trn2	V16.2D, V22.2D, V16.2D
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V3.S[0]
	mul	V23.4S, V24.4S, V3.S[1]
	sqrdmulh	V14.4S, V22.4S, V1.S[0]
	sqrdmulh	V16.4S, V24.4S, V1.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V14.4S, V14.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	mov	V21.16B, V17.16B
	mov	V22.16B, V19.16B
	trn1	V17.2D, V17.2D, V18.2D
	trn1	V19.2D, V19.2D, V20.2D
	trn2	V18.2D, V21.2D, V18.2D
	trn2	V20.2D, V22.2D, V20.2D
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V3.S[2]
	mul	V23.4S, V24.4S, V3.S[3]
	sqrdmulh	V18.4S, V22.4S, V1.S[2]
	sqrdmulh	V20.4S, V24.4S, V1.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V18.4S, V18.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1200]
	ldr	Q2, [x2, #1200]
	sub	V22.4S, V5.4S, V7.4S
	sub	V24.4S, V6.4S, V8.4S
	add	V5.4S, V5.4S, V7.4S
	add	V6.4S, V6.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V7.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[0]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V7.4S, V7.4S, V21.4S
	sub	V8.4S, V8.4S, V23.4S
	sshr	V7.4S, V7.4S, #1
	sshr	V8.4S, V8.4S, #1
	sub	V22.4S, V9.4S, V11.4S
	sub	V24.4S, V10.4S, V12.4S
	add	V9.4S, V9.4S, V11.4S
	add	V10.4S, V10.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V11.4S, V22.4S, V0.S[1]
	sqrdmulh	V12.4S, V24.4S, V0.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V11.4S, V11.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V15.4S
	sub	V24.4S, V14.4S, V16.4S
	add	V13.4S, V13.4S, V15.4S
	add	V14.4S, V14.4S, V16.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V15.4S, V22.4S, V0.S[2]
	sqrdmulh	V16.4S, V24.4S, V0.S[2]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V15.4S, V15.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V15.4S, V15.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V17.4S, V19.4S
	sub	V24.4S, V18.4S, V20.4S
	add	V17.4S, V17.4S, V19.4S
	add	V18.4S, V18.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[3]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V19.4S, V22.4S, V0.S[3]
	sqrdmulh	V20.4S, V24.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V19.4S, V19.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	stp	Q5, Q6, [x0, #768]
	stp	Q7, Q8, [x0, #800]
	stp	Q9, Q10, [x0, #832]
	stp	Q11, Q12, [x0, #864]
	stp	Q13, Q14, [x0, #896]
	stp	Q15, Q16, [x0, #928]
	stp	Q17, Q18, [x0, #960]
	stp	Q19, Q20, [x0, #992]
	ldr	Q5, [x0]
	ldr	Q6, [x0, #64]
	ldr	Q7, [x0, #128]
	ldr	Q8, [x0, #192]
	ldr	Q9, [x0, #256]
	ldr	Q10, [x0, #320]
	ldr	Q11, [x0, #384]
	ldr	Q12, [x0, #448]
	ldr	Q13, [x0, #512]
	ldr	Q14, [x0, #576]
	ldr	Q15, [x0, #640]
	ldr	Q16, [x0, #704]
	ldr	Q17, [x0, #768]
	ldr	Q18, [x0, #832]
	ldr	Q19, [x0, #896]
	ldr	Q20, [x0, #960]
	ldr	Q0, [x1, #1216]
	ldr	Q1, [x1, #1232]
	ldr	Q2, [x2, #1216]
	ldr	Q3, [x2, #1232]
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V6.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V6.4S, V6.4S, V21.4S
	sub	V8.4S, V8.4S, V23.4S
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V10.4S, V22.4S, V0.S[2]
	sqrdmulh	V12.4S, V24.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V10.4S, V10.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V3.S[0]
	mul	V23.4S, V24.4S, V3.S[1]
	sqrdmulh	V14.4S, V22.4S, V1.S[0]
	sqrdmulh	V16.4S, V24.4S, V1.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V14.4S, V14.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V3.S[2]
	mul	V23.4S, V24.4S, V3.S[3]
	sqrdmulh	V18.4S, V22.4S, V1.S[2]
	sqrdmulh	V20.4S, V24.4S, V1.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V18.4S, V18.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1248]
	ldr	Q2, [x2, #1248]
	sub	V22.4S, V5.4S, V7.4S
	sub	V24.4S, V6.4S, V8.4S
	add	V5.4S, V5.4S, V7.4S
	add	V6.4S, V6.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V7.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[0]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V7.4S, V7.4S, V21.4S
	sub	V8.4S, V8.4S, V23.4S
	sshr	V7.4S, V7.4S, #1
	sshr	V8.4S, V8.4S, #1
	sub	V22.4S, V9.4S, V11.4S
	sub	V24.4S, V10.4S, V12.4S
	add	V9.4S, V9.4S, V11.4S
	add	V10.4S, V10.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V11.4S, V22.4S, V0.S[1]
	sqrdmulh	V12.4S, V24.4S, V0.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V11.4S, V11.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V15.4S
	sub	V24.4S, V14.4S, V16.4S
	add	V13.4S, V13.4S, V15.4S
	add	V14.4S, V14.4S, V16.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V15.4S, V22.4S, V0.S[2]
	sqrdmulh	V16.4S, V24.4S, V0.S[2]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V15.4S, V15.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V15.4S, V15.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V17.4S, V19.4S
	sub	V24.4S, V18.4S, V20.4S
	add	V17.4S, V17.4S, V19.4S
	add	V18.4S, V18.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[3]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V19.4S, V22.4S, V0.S[3]
	sqrdmulh	V20.4S, V24.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V19.4S, V19.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1264]
	ldr	Q2, [x2, #1264]
	sub	V22.4S, V5.4S, V9.4S
	sub	V24.4S, V6.4S, V10.4S
	add	V5.4S, V5.4S, V9.4S
	add	V6.4S, V6.4S, V10.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V9.4S, V22.4S, V0.S[0]
	sqrdmulh	V10.4S, V24.4S, V0.S[0]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V9.4S, V9.4S, V21.4S
	sub	V10.4S, V10.4S, V23.4S
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	sub	V22.4S, V7.4S, V11.4S
	sub	V24.4S, V8.4S, V12.4S
	add	V7.4S, V7.4S, V11.4S
	add	V8.4S, V8.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V11.4S, V22.4S, V0.S[0]
	sqrdmulh	V12.4S, V24.4S, V0.S[0]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V11.4S, V11.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V17.4S
	sub	V24.4S, V14.4S, V18.4S
	add	V13.4S, V13.4S, V17.4S
	add	V14.4S, V14.4S, V18.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V17.4S, V22.4S, V0.S[1]
	sqrdmulh	V18.4S, V24.4S, V0.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V17.4S, V17.4S, V21.4S
	sub	V18.4S, V18.4S, V23.4S
	sshr	V17.4S, V17.4S, #1
	sshr	V18.4S, V18.4S, #1
	sub	V22.4S, V15.4S, V19.4S
	sub	V24.4S, V16.4S, V20.4S
	add	V15.4S, V15.4S, V19.4S
	add	V16.4S, V16.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V19.4S, V22.4S, V0.S[1]
	sqrdmulh	V20.4S, V24.4S, V0.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V19.4S, V19.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	sub	V22.4S, V5.4S, V13.4S
	sub	V24.4S, V6.4S, V14.4S
	add	V5.4S, V5.4S, V13.4S
	add	V6.4S, V6.4S, V14.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V13.4S, V22.4S, V0.S[2]
	sqrdmulh	V14.4S, V24.4S, V0.S[2]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V13.4S, V13.4S, V21.4S
	sub	V14.4S, V14.4S, V23.4S
	sshr	V13.4S, V13.4S, #1
	sshr	V14.4S, V14.4S, #1
	sub	V22.4S, V7.4S, V15.4S
	sub	V24.4S, V8.4S, V16.4S
	add	V7.4S, V7.4S, V15.4S
	add	V8.4S, V8.4S, V16.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V15.4S, V22.4S, V0.S[2]
	sqrdmulh	V16.4S, V24.4S, V0.S[2]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V15.4S, V15.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V15.4S, V15.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V9.4S, V17.4S
	sub	V24.4S, V10.4S, V18.4S
	add	V9.4S, V9.4S, V17.4S
	add	V10.4S, V10.4S, V18.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V17.4S, V22.4S, V0.S[2]
	sqrdmulh	V18.4S, V24.4S, V0.S[2]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V17.4S, V17.4S, V21.4S
	sub	V18.4S, V18.4S, V23.4S
	sshr	V17.4S, V17.4S, #1
	sshr	V18.4S, V18.4S, #1
	sub	V22.4S, V11.4S, V19.4S
	sub	V24.4S, V12.4S, V20.4S
	add	V11.4S, V11.4S, V19.4S
	add	V12.4S, V12.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V19.4S, V22.4S, V0.S[2]
	sqrdmulh	V20.4S, V24.4S, V0.S[2]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V19.4S, V19.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	mul	V21.4S, V5.4S, V2.S[3]
	mul	V22.4S, V6.4S, V2.S[3]
	sqrdmulh	V5.4S, V5.4S, V0.S[3]
	sqrdmulh	V6.4S, V6.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V22.4S, V22.4S, V4.S[0]
	sub	V5.4S, V5.4S, V21.4S
	sub	V6.4S, V6.4S, V22.4S
	sshr	V5.4S, V5.4S, #1
	sshr	V6.4S, V6.4S, #1
	mul	V21.4S, V7.4S, V2.S[3]
	mul	V22.4S, V8.4S, V2.S[3]
	sqrdmulh	V7.4S, V7.4S, V0.S[3]
	sqrdmulh	V8.4S, V8.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V22.4S, V22.4S, V4.S[0]
	sub	V7.4S, V7.4S, V21.4S
	sub	V8.4S, V8.4S, V22.4S
	sshr	V7.4S, V7.4S, #1
	sshr	V8.4S, V8.4S, #1
	mul	V21.4S, V9.4S, V2.S[3]
	mul	V22.4S, V10.4S, V2.S[3]
	sqrdmulh	V9.4S, V9.4S, V0.S[3]
	sqrdmulh	V10.4S, V10.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V22.4S, V22.4S, V4.S[0]
	sub	V9.4S, V9.4S, V21.4S
	sub	V10.4S, V10.4S, V22.4S
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	mul	V21.4S, V11.4S, V2.S[3]
	mul	V22.4S, V12.4S, V2.S[3]
	sqrdmulh	V11.4S, V11.4S, V0.S[3]
	sqrdmulh	V12.4S, V12.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V22.4S, V22.4S, V4.S[0]
	sub	V11.4S, V11.4S, V21.4S
	sub	V12.4S, V12.4S, V22.4S
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	str	Q5, [x0]
	str	Q6, [x0, #64]
	str	Q7, [x0, #128]
	str	Q8, [x0, #192]
	str	Q9, [x0, #256]
	str	Q10, [x0, #320]
	str	Q11, [x0, #384]
	str	Q12, [x0, #448]
	str	Q13, [x0, #512]
	str	Q14, [x0, #576]
	str	Q15, [x0, #640]
	str	Q16, [x0, #704]
	str	Q17, [x0, #768]
	str	Q18, [x0, #832]
	str	Q19, [x0, #896]
	str	Q20, [x0, #960]
	ldr	Q5, [x0, #16]
	ldr	Q6, [x0, #80]
	ldr	Q7, [x0, #144]
	ldr	Q8, [x0, #208]
	ldr	Q9, [x0, #272]
	ldr	Q10, [x0, #336]
	ldr	Q11, [x0, #400]
	ldr	Q12, [x0, #464]
	ldr	Q13, [x0, #528]
	ldr	Q14, [x0, #592]
	ldr	Q15, [x0, #656]
	ldr	Q16, [x0, #720]
	ldr	Q17, [x0, #784]
	ldr	Q18, [x0, #848]
	ldr	Q19, [x0, #912]
	ldr	Q20, [x0, #976]
	ldr	Q0, [x1, #1216]
	ldr	Q1, [x1, #1232]
	ldr	Q2, [x2, #1216]
	ldr	Q3, [x2, #1232]
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V6.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V6.4S, V6.4S, V21.4S
	sub	V8.4S, V8.4S, V23.4S
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V10.4S, V22.4S, V0.S[2]
	sqrdmulh	V12.4S, V24.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V10.4S, V10.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V3.S[0]
	mul	V23.4S, V24.4S, V3.S[1]
	sqrdmulh	V14.4S, V22.4S, V1.S[0]
	sqrdmulh	V16.4S, V24.4S, V1.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V14.4S, V14.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V3.S[2]
	mul	V23.4S, V24.4S, V3.S[3]
	sqrdmulh	V18.4S, V22.4S, V1.S[2]
	sqrdmulh	V20.4S, V24.4S, V1.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V18.4S, V18.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1248]
	ldr	Q2, [x2, #1248]
	sub	V22.4S, V5.4S, V7.4S
	sub	V24.4S, V6.4S, V8.4S
	add	V5.4S, V5.4S, V7.4S
	add	V6.4S, V6.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V7.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[0]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V7.4S, V7.4S, V21.4S
	sub	V8.4S, V8.4S, V23.4S
	sshr	V7.4S, V7.4S, #1
	sshr	V8.4S, V8.4S, #1
	sub	V22.4S, V9.4S, V11.4S
	sub	V24.4S, V10.4S, V12.4S
	add	V9.4S, V9.4S, V11.4S
	add	V10.4S, V10.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V11.4S, V22.4S, V0.S[1]
	sqrdmulh	V12.4S, V24.4S, V0.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V11.4S, V11.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V15.4S
	sub	V24.4S, V14.4S, V16.4S
	add	V13.4S, V13.4S, V15.4S
	add	V14.4S, V14.4S, V16.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V15.4S, V22.4S, V0.S[2]
	sqrdmulh	V16.4S, V24.4S, V0.S[2]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V15.4S, V15.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V15.4S, V15.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V17.4S, V19.4S
	sub	V24.4S, V18.4S, V20.4S
	add	V17.4S, V17.4S, V19.4S
	add	V18.4S, V18.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[3]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V19.4S, V22.4S, V0.S[3]
	sqrdmulh	V20.4S, V24.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V19.4S, V19.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1264]
	ldr	Q2, [x2, #1264]
	sub	V22.4S, V5.4S, V9.4S
	sub	V24.4S, V6.4S, V10.4S
	add	V5.4S, V5.4S, V9.4S
	add	V6.4S, V6.4S, V10.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V9.4S, V22.4S, V0.S[0]
	sqrdmulh	V10.4S, V24.4S, V0.S[0]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V9.4S, V9.4S, V21.4S
	sub	V10.4S, V10.4S, V23.4S
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	sub	V22.4S, V7.4S, V11.4S
	sub	V24.4S, V8.4S, V12.4S
	add	V7.4S, V7.4S, V11.4S
	add	V8.4S, V8.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V11.4S, V22.4S, V0.S[0]
	sqrdmulh	V12.4S, V24.4S, V0.S[0]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V11.4S, V11.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V17.4S
	sub	V24.4S, V14.4S, V18.4S
	add	V13.4S, V13.4S, V17.4S
	add	V14.4S, V14.4S, V18.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V17.4S, V22.4S, V0.S[1]
	sqrdmulh	V18.4S, V24.4S, V0.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V17.4S, V17.4S, V21.4S
	sub	V18.4S, V18.4S, V23.4S
	sshr	V17.4S, V17.4S, #1
	sshr	V18.4S, V18.4S, #1
	sub	V22.4S, V15.4S, V19.4S
	sub	V24.4S, V16.4S, V20.4S
	add	V15.4S, V15.4S, V19.4S
	add	V16.4S, V16.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V19.4S, V22.4S, V0.S[1]
	sqrdmulh	V20.4S, V24.4S, V0.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V19.4S, V19.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	sub	V22.4S, V5.4S, V13.4S
	sub	V24.4S, V6.4S, V14.4S
	add	V5.4S, V5.4S, V13.4S
	add	V6.4S, V6.4S, V14.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V13.4S, V22.4S, V0.S[2]
	sqrdmulh	V14.4S, V24.4S, V0.S[2]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V13.4S, V13.4S, V21.4S
	sub	V14.4S, V14.4S, V23.4S
	sshr	V13.4S, V13.4S, #1
	sshr	V14.4S, V14.4S, #1
	sub	V22.4S, V7.4S, V15.4S
	sub	V24.4S, V8.4S, V16.4S
	add	V7.4S, V7.4S, V15.4S
	add	V8.4S, V8.4S, V16.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V15.4S, V22.4S, V0.S[2]
	sqrdmulh	V16.4S, V24.4S, V0.S[2]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V15.4S, V15.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V15.4S, V15.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V9.4S, V17.4S
	sub	V24.4S, V10.4S, V18.4S
	add	V9.4S, V9.4S, V17.4S
	add	V10.4S, V10.4S, V18.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V17.4S, V22.4S, V0.S[2]
	sqrdmulh	V18.4S, V24.4S, V0.S[2]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V17.4S, V17.4S, V21.4S
	sub	V18.4S, V18.4S, V23.4S
	sshr	V17.4S, V17.4S, #1
	sshr	V18.4S, V18.4S, #1
	sub	V22.4S, V11.4S, V19.4S
	sub	V24.4S, V12.4S, V20.4S
	add	V11.4S, V11.4S, V19.4S
	add	V12.4S, V12.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V19.4S, V22.4S, V0.S[2]
	sqrdmulh	V20.4S, V24.4S, V0.S[2]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V19.4S, V19.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	mul	V21.4S, V5.4S, V2.S[3]
	mul	V22.4S, V6.4S, V2.S[3]
	sqrdmulh	V5.4S, V5.4S, V0.S[3]
	sqrdmulh	V6.4S, V6.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V22.4S, V22.4S, V4.S[0]
	sub	V5.4S, V5.4S, V21.4S
	sub	V6.4S, V6.4S, V22.4S
	sshr	V5.4S, V5.4S, #1
	sshr	V6.4S, V6.4S, #1
	mul	V21.4S, V7.4S, V2.S[3]
	mul	V22.4S, V8.4S, V2.S[3]
	sqrdmulh	V7.4S, V7.4S, V0.S[3]
	sqrdmulh	V8.4S, V8.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V22.4S, V22.4S, V4.S[0]
	sub	V7.4S, V7.4S, V21.4S
	sub	V8.4S, V8.4S, V22.4S
	sshr	V7.4S, V7.4S, #1
	sshr	V8.4S, V8.4S, #1
	mul	V21.4S, V9.4S, V2.S[3]
	mul	V22.4S, V10.4S, V2.S[3]
	sqrdmulh	V9.4S, V9.4S, V0.S[3]
	sqrdmulh	V10.4S, V10.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V22.4S, V22.4S, V4.S[0]
	sub	V9.4S, V9.4S, V21.4S
	sub	V10.4S, V10.4S, V22.4S
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	mul	V21.4S, V11.4S, V2.S[3]
	mul	V22.4S, V12.4S, V2.S[3]
	sqrdmulh	V11.4S, V11.4S, V0.S[3]
	sqrdmulh	V12.4S, V12.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V22.4S, V22.4S, V4.S[0]
	sub	V11.4S, V11.4S, V21.4S
	sub	V12.4S, V12.4S, V22.4S
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	str	Q5, [x0, #16]
	str	Q6, [x0, #80]
	str	Q7, [x0, #144]
	str	Q8, [x0, #208]
	str	Q9, [x0, #272]
	str	Q10, [x0, #336]
	str	Q11, [x0, #400]
	str	Q12, [x0, #464]
	str	Q13, [x0, #528]
	str	Q14, [x0, #592]
	str	Q15, [x0, #656]
	str	Q16, [x0, #720]
	str	Q17, [x0, #784]
	str	Q18, [x0, #848]
	str	Q19, [x0, #912]
	str	Q20, [x0, #976]
	ldr	Q5, [x0, #32]
	ldr	Q6, [x0, #96]
	ldr	Q7, [x0, #160]
	ldr	Q8, [x0, #224]
	ldr	Q9, [x0, #288]
	ldr	Q10, [x0, #352]
	ldr	Q11, [x0, #416]
	ldr	Q12, [x0, #480]
	ldr	Q13, [x0, #544]
	ldr	Q14, [x0, #608]
	ldr	Q15, [x0, #672]
	ldr	Q16, [x0, #736]
	ldr	Q17, [x0, #800]
	ldr	Q18, [x0, #864]
	ldr	Q19, [x0, #928]
	ldr	Q20, [x0, #992]
	ldr	Q0, [x1, #1216]
	ldr	Q1, [x1, #1232]
	ldr	Q2, [x2, #1216]
	ldr	Q3, [x2, #1232]
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V6.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V6.4S, V6.4S, V21.4S
	sub	V8.4S, V8.4S, V23.4S
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V10.4S, V22.4S, V0.S[2]
	sqrdmulh	V12.4S, V24.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V10.4S, V10.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V3.S[0]
	mul	V23.4S, V24.4S, V3.S[1]
	sqrdmulh	V14.4S, V22.4S, V1.S[0]
	sqrdmulh	V16.4S, V24.4S, V1.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V14.4S, V14.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V3.S[2]
	mul	V23.4S, V24.4S, V3.S[3]
	sqrdmulh	V18.4S, V22.4S, V1.S[2]
	sqrdmulh	V20.4S, V24.4S, V1.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V18.4S, V18.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1248]
	ldr	Q2, [x2, #1248]
	sub	V22.4S, V5.4S, V7.4S
	sub	V24.4S, V6.4S, V8.4S
	add	V5.4S, V5.4S, V7.4S
	add	V6.4S, V6.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V7.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[0]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V7.4S, V7.4S, V21.4S
	sub	V8.4S, V8.4S, V23.4S
	sshr	V7.4S, V7.4S, #1
	sshr	V8.4S, V8.4S, #1
	sub	V22.4S, V9.4S, V11.4S
	sub	V24.4S, V10.4S, V12.4S
	add	V9.4S, V9.4S, V11.4S
	add	V10.4S, V10.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V11.4S, V22.4S, V0.S[1]
	sqrdmulh	V12.4S, V24.4S, V0.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V11.4S, V11.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V15.4S
	sub	V24.4S, V14.4S, V16.4S
	add	V13.4S, V13.4S, V15.4S
	add	V14.4S, V14.4S, V16.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V15.4S, V22.4S, V0.S[2]
	sqrdmulh	V16.4S, V24.4S, V0.S[2]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V15.4S, V15.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V15.4S, V15.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V17.4S, V19.4S
	sub	V24.4S, V18.4S, V20.4S
	add	V17.4S, V17.4S, V19.4S
	add	V18.4S, V18.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[3]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V19.4S, V22.4S, V0.S[3]
	sqrdmulh	V20.4S, V24.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V19.4S, V19.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1264]
	ldr	Q2, [x2, #1264]
	sub	V22.4S, V5.4S, V9.4S
	sub	V24.4S, V6.4S, V10.4S
	add	V5.4S, V5.4S, V9.4S
	add	V6.4S, V6.4S, V10.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V9.4S, V22.4S, V0.S[0]
	sqrdmulh	V10.4S, V24.4S, V0.S[0]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V9.4S, V9.4S, V21.4S
	sub	V10.4S, V10.4S, V23.4S
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	sub	V22.4S, V7.4S, V11.4S
	sub	V24.4S, V8.4S, V12.4S
	add	V7.4S, V7.4S, V11.4S
	add	V8.4S, V8.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V11.4S, V22.4S, V0.S[0]
	sqrdmulh	V12.4S, V24.4S, V0.S[0]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V11.4S, V11.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V17.4S
	sub	V24.4S, V14.4S, V18.4S
	add	V13.4S, V13.4S, V17.4S
	add	V14.4S, V14.4S, V18.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V17.4S, V22.4S, V0.S[1]
	sqrdmulh	V18.4S, V24.4S, V0.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V17.4S, V17.4S, V21.4S
	sub	V18.4S, V18.4S, V23.4S
	sshr	V17.4S, V17.4S, #1
	sshr	V18.4S, V18.4S, #1
	sub	V22.4S, V15.4S, V19.4S
	sub	V24.4S, V16.4S, V20.4S
	add	V15.4S, V15.4S, V19.4S
	add	V16.4S, V16.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V19.4S, V22.4S, V0.S[1]
	sqrdmulh	V20.4S, V24.4S, V0.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V19.4S, V19.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	sub	V22.4S, V5.4S, V13.4S
	sub	V24.4S, V6.4S, V14.4S
	add	V5.4S, V5.4S, V13.4S
	add	V6.4S, V6.4S, V14.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V13.4S, V22.4S, V0.S[2]
	sqrdmulh	V14.4S, V24.4S, V0.S[2]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V13.4S, V13.4S, V21.4S
	sub	V14.4S, V14.4S, V23.4S
	sshr	V13.4S, V13.4S, #1
	sshr	V14.4S, V14.4S, #1
	sub	V22.4S, V7.4S, V15.4S
	sub	V24.4S, V8.4S, V16.4S
	add	V7.4S, V7.4S, V15.4S
	add	V8.4S, V8.4S, V16.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V15.4S, V22.4S, V0.S[2]
	sqrdmulh	V16.4S, V24.4S, V0.S[2]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V15.4S, V15.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V15.4S, V15.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V9.4S, V17.4S
	sub	V24.4S, V10.4S, V18.4S
	add	V9.4S, V9.4S, V17.4S
	add	V10.4S, V10.4S, V18.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V17.4S, V22.4S, V0.S[2]
	sqrdmulh	V18.4S, V24.4S, V0.S[2]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V17.4S, V17.4S, V21.4S
	sub	V18.4S, V18.4S, V23.4S
	sshr	V17.4S, V17.4S, #1
	sshr	V18.4S, V18.4S, #1
	sub	V22.4S, V11.4S, V19.4S
	sub	V24.4S, V12.4S, V20.4S
	add	V11.4S, V11.4S, V19.4S
	add	V12.4S, V12.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V19.4S, V22.4S, V0.S[2]
	sqrdmulh	V20.4S, V24.4S, V0.S[2]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V19.4S, V19.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	mul	V21.4S, V5.4S, V2.S[3]
	mul	V22.4S, V6.4S, V2.S[3]
	sqrdmulh	V5.4S, V5.4S, V0.S[3]
	sqrdmulh	V6.4S, V6.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V22.4S, V22.4S, V4.S[0]
	sub	V5.4S, V5.4S, V21.4S
	sub	V6.4S, V6.4S, V22.4S
	sshr	V5.4S, V5.4S, #1
	sshr	V6.4S, V6.4S, #1
	mul	V21.4S, V7.4S, V2.S[3]
	mul	V22.4S, V8.4S, V2.S[3]
	sqrdmulh	V7.4S, V7.4S, V0.S[3]
	sqrdmulh	V8.4S, V8.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V22.4S, V22.4S, V4.S[0]
	sub	V7.4S, V7.4S, V21.4S
	sub	V8.4S, V8.4S, V22.4S
	sshr	V7.4S, V7.4S, #1
	sshr	V8.4S, V8.4S, #1
	mul	V21.4S, V9.4S, V2.S[3]
	mul	V22.4S, V10.4S, V2.S[3]
	sqrdmulh	V9.4S, V9.4S, V0.S[3]
	sqrdmulh	V10.4S, V10.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V22.4S, V22.4S, V4.S[0]
	sub	V9.4S, V9.4S, V21.4S
	sub	V10.4S, V10.4S, V22.4S
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	mul	V21.4S, V11.4S, V2.S[3]
	mul	V22.4S, V12.4S, V2.S[3]
	sqrdmulh	V11.4S, V11.4S, V0.S[3]
	sqrdmulh	V12.4S, V12.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V22.4S, V22.4S, V4.S[0]
	sub	V11.4S, V11.4S, V21.4S
	sub	V12.4S, V12.4S, V22.4S
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	str	Q5, [x0, #32]
	str	Q6, [x0, #96]
	str	Q7, [x0, #160]
	str	Q8, [x0, #224]
	str	Q9, [x0, #288]
	str	Q10, [x0, #352]
	str	Q11, [x0, #416]
	str	Q12, [x0, #480]
	str	Q13, [x0, #544]
	str	Q14, [x0, #608]
	str	Q15, [x0, #672]
	str	Q16, [x0, #736]
	str	Q17, [x0, #800]
	str	Q18, [x0, #864]
	str	Q19, [x0, #928]
	str	Q20, [x0, #992]
	ldr	Q5, [x0, #48]
	ldr	Q6, [x0, #112]
	ldr	Q7, [x0, #176]
	ldr	Q8, [x0, #240]
	ldr	Q9, [x0, #304]
	ldr	Q10, [x0, #368]
	ldr	Q11, [x0, #432]
	ldr	Q12, [x0, #496]
	ldr	Q13, [x0, #560]
	ldr	Q14, [x0, #624]
	ldr	Q15, [x0, #688]
	ldr	Q16, [x0, #752]
	ldr	Q17, [x0, #816]
	ldr	Q18, [x0, #880]
	ldr	Q19, [x0, #944]
	ldr	Q20, [x0, #1008]
	ldr	Q0, [x1, #1216]
	ldr	Q1, [x1, #1232]
	ldr	Q2, [x2, #1216]
	ldr	Q3, [x2, #1232]
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V6.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V6.4S, V6.4S, V21.4S
	sub	V8.4S, V8.4S, V23.4S
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V10.4S, V22.4S, V0.S[2]
	sqrdmulh	V12.4S, V24.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V10.4S, V10.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V3.S[0]
	mul	V23.4S, V24.4S, V3.S[1]
	sqrdmulh	V14.4S, V22.4S, V1.S[0]
	sqrdmulh	V16.4S, V24.4S, V1.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V14.4S, V14.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V3.S[2]
	mul	V23.4S, V24.4S, V3.S[3]
	sqrdmulh	V18.4S, V22.4S, V1.S[2]
	sqrdmulh	V20.4S, V24.4S, V1.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V18.4S, V18.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1248]
	ldr	Q2, [x2, #1248]
	sub	V22.4S, V5.4S, V7.4S
	sub	V24.4S, V6.4S, V8.4S
	add	V5.4S, V5.4S, V7.4S
	add	V6.4S, V6.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V7.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[0]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V7.4S, V7.4S, V21.4S
	sub	V8.4S, V8.4S, V23.4S
	sshr	V7.4S, V7.4S, #1
	sshr	V8.4S, V8.4S, #1
	sub	V22.4S, V9.4S, V11.4S
	sub	V24.4S, V10.4S, V12.4S
	add	V9.4S, V9.4S, V11.4S
	add	V10.4S, V10.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V11.4S, V22.4S, V0.S[1]
	sqrdmulh	V12.4S, V24.4S, V0.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V11.4S, V11.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V15.4S
	sub	V24.4S, V14.4S, V16.4S
	add	V13.4S, V13.4S, V15.4S
	add	V14.4S, V14.4S, V16.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V15.4S, V22.4S, V0.S[2]
	sqrdmulh	V16.4S, V24.4S, V0.S[2]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V15.4S, V15.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V15.4S, V15.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V17.4S, V19.4S
	sub	V24.4S, V18.4S, V20.4S
	add	V17.4S, V17.4S, V19.4S
	add	V18.4S, V18.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[3]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V19.4S, V22.4S, V0.S[3]
	sqrdmulh	V20.4S, V24.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V19.4S, V19.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1264]
	ldr	Q2, [x2, #1264]
	sub	V22.4S, V5.4S, V9.4S
	sub	V24.4S, V6.4S, V10.4S
	add	V5.4S, V5.4S, V9.4S
	add	V6.4S, V6.4S, V10.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V9.4S, V22.4S, V0.S[0]
	sqrdmulh	V10.4S, V24.4S, V0.S[0]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V9.4S, V9.4S, V21.4S
	sub	V10.4S, V10.4S, V23.4S
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	sub	V22.4S, V7.4S, V11.4S
	sub	V24.4S, V8.4S, V12.4S
	add	V7.4S, V7.4S, V11.4S
	add	V8.4S, V8.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V11.4S, V22.4S, V0.S[0]
	sqrdmulh	V12.4S, V24.4S, V0.S[0]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V11.4S, V11.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V17.4S
	sub	V24.4S, V14.4S, V18.4S
	add	V13.4S, V13.4S, V17.4S
	add	V14.4S, V14.4S, V18.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V17.4S, V22.4S, V0.S[1]
	sqrdmulh	V18.4S, V24.4S, V0.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V17.4S, V17.4S, V21.4S
	sub	V18.4S, V18.4S, V23.4S
	sshr	V17.4S, V17.4S, #1
	sshr	V18.4S, V18.4S, #1
	sub	V22.4S, V15.4S, V19.4S
	sub	V24.4S, V16.4S, V20.4S
	add	V15.4S, V15.4S, V19.4S
	add	V16.4S, V16.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V19.4S, V22.4S, V0.S[1]
	sqrdmulh	V20.4S, V24.4S, V0.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V19.4S, V19.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	sub	V22.4S, V5.4S, V13.4S
	sub	V24.4S, V6.4S, V14.4S
	add	V5.4S, V5.4S, V13.4S
	add	V6.4S, V6.4S, V14.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V13.4S, V22.4S, V0.S[2]
	sqrdmulh	V14.4S, V24.4S, V0.S[2]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V13.4S, V13.4S, V21.4S
	sub	V14.4S, V14.4S, V23.4S
	sshr	V13.4S, V13.4S, #1
	sshr	V14.4S, V14.4S, #1
	sub	V22.4S, V7.4S, V15.4S
	sub	V24.4S, V8.4S, V16.4S
	add	V7.4S, V7.4S, V15.4S
	add	V8.4S, V8.4S, V16.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V15.4S, V22.4S, V0.S[2]
	sqrdmulh	V16.4S, V24.4S, V0.S[2]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V15.4S, V15.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V15.4S, V15.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V9.4S, V17.4S
	sub	V24.4S, V10.4S, V18.4S
	add	V9.4S, V9.4S, V17.4S
	add	V10.4S, V10.4S, V18.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V17.4S, V22.4S, V0.S[2]
	sqrdmulh	V18.4S, V24.4S, V0.S[2]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V17.4S, V17.4S, V21.4S
	sub	V18.4S, V18.4S, V23.4S
	sshr	V17.4S, V17.4S, #1
	sshr	V18.4S, V18.4S, #1
	sub	V22.4S, V11.4S, V19.4S
	sub	V24.4S, V12.4S, V20.4S
	add	V11.4S, V11.4S, V19.4S
	add	V12.4S, V12.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V19.4S, V22.4S, V0.S[2]
	sqrdmulh	V20.4S, V24.4S, V0.S[2]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V19.4S, V19.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	mul	V21.4S, V5.4S, V2.S[3]
	mul	V22.4S, V6.4S, V2.S[3]
	sqrdmulh	V5.4S, V5.4S, V0.S[3]
	sqrdmulh	V6.4S, V6.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V22.4S, V22.4S, V4.S[0]
	sub	V5.4S, V5.4S, V21.4S
	sub	V6.4S, V6.4S, V22.4S
	sshr	V5.4S, V5.4S, #1
	sshr	V6.4S, V6.4S, #1
	mul	V21.4S, V7.4S, V2.S[3]
	mul	V22.4S, V8.4S, V2.S[3]
	sqrdmulh	V7.4S, V7.4S, V0.S[3]
	sqrdmulh	V8.4S, V8.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V22.4S, V22.4S, V4.S[0]
	sub	V7.4S, V7.4S, V21.4S
	sub	V8.4S, V8.4S, V22.4S
	sshr	V7.4S, V7.4S, #1
	sshr	V8.4S, V8.4S, #1
	mul	V21.4S, V9.4S, V2.S[3]
	mul	V22.4S, V10.4S, V2.S[3]
	sqrdmulh	V9.4S, V9.4S, V0.S[3]
	sqrdmulh	V10.4S, V10.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V22.4S, V22.4S, V4.S[0]
	sub	V9.4S, V9.4S, V21.4S
	sub	V10.4S, V10.4S, V22.4S
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	mul	V21.4S, V11.4S, V2.S[3]
	mul	V22.4S, V12.4S, V2.S[3]
	sqrdmulh	V11.4S, V11.4S, V0.S[3]
	sqrdmulh	V12.4S, V12.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V22.4S, V22.4S, V4.S[0]
	sub	V11.4S, V11.4S, V21.4S
	sub	V12.4S, V12.4S, V22.4S
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	str	Q5, [x0, #48]
	str	Q6, [x0, #112]
	str	Q7, [x0, #176]
	str	Q8, [x0, #240]
	str	Q9, [x0, #304]
	str	Q10, [x0, #368]
	str	Q11, [x0, #432]
	str	Q12, [x0, #496]
	str	Q13, [x0, #560]
	str	Q14, [x0, #624]
	str	Q15, [x0, #688]
	str	Q16, [x0, #752]
	str	Q17, [x0, #816]
	str	Q18, [x0, #880]
	str	Q19, [x0, #944]
	str	Q20, [x0, #1008]
	ldp	D8, D9, [x29, #16]
	ldp	D10, D11, [x29, #32]
	ldp	D12, D13, [x29, #48]
	ldp	D14, D15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
	ENDP
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mldsa_invntt_full_neon
mldsa_invntt_full_neon PROC
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	stp	D10, D11, [x29, #32]
	stp	D12, D13, [x29, #48]
	stp	D14, D15, [x29, #64]
	adrp	x1, L_mldsa_aarch64_zetas_inv
	add	x1, x1, L_mldsa_aarch64_zetas_inv
	adrp	x2, L_mldsa_aarch64_zetas_inv_qinv
	add	x2, x2, L_mldsa_aarch64_zetas_inv_qinv
	adrp	x3, L_mldsa_aarch64_consts
	add	x3, x3, L_mldsa_aarch64_consts
	ldr	Q4, [x3]
	ldp	Q5, Q6, [x0]
	ldp	Q7, Q8, [x0, #32]
	ldp	Q9, Q10, [x0, #64]
	ldp	Q11, Q12, [x0, #96]
	ldp	Q13, Q14, [x0, #128]
	ldp	Q15, Q16, [x0, #160]
	ldp	Q17, Q18, [x0, #192]
	ldp	Q19, Q20, [x0, #224]
	trn1	V21.2D, V5.2D, V6.2D
	trn2	V22.2D, V5.2D, V6.2D
	trn1	V5.4S, V21.4S, V22.4S
	trn2	V6.4S, V21.4S, V22.4S
	trn1	V21.2D, V7.2D, V8.2D
	trn2	V22.2D, V7.2D, V8.2D
	trn1	V7.4S, V21.4S, V22.4S
	trn2	V8.4S, V21.4S, V22.4S
	trn1	V21.2D, V9.2D, V10.2D
	trn2	V22.2D, V9.2D, V10.2D
	trn1	V9.4S, V21.4S, V22.4S
	trn2	V10.4S, V21.4S, V22.4S
	trn1	V21.2D, V11.2D, V12.2D
	trn2	V22.2D, V11.2D, V12.2D
	trn1	V11.4S, V21.4S, V22.4S
	trn2	V12.4S, V21.4S, V22.4S
	trn1	V21.2D, V13.2D, V14.2D
	trn2	V22.2D, V13.2D, V14.2D
	trn1	V13.4S, V21.4S, V22.4S
	trn2	V14.4S, V21.4S, V22.4S
	trn1	V21.2D, V15.2D, V16.2D
	trn2	V22.2D, V15.2D, V16.2D
	trn1	V15.4S, V21.4S, V22.4S
	trn2	V16.4S, V21.4S, V22.4S
	trn1	V21.2D, V17.2D, V18.2D
	trn2	V22.2D, V17.2D, V18.2D
	trn1	V17.4S, V21.4S, V22.4S
	trn2	V18.4S, V21.4S, V22.4S
	trn1	V21.2D, V19.2D, V20.2D
	trn2	V22.2D, V19.2D, V20.2D
	trn1	V19.4S, V21.4S, V22.4S
	trn2	V20.4S, V21.4S, V22.4S
	ldp	Q0, Q1, [x1]
	ldp	Q2, Q3, [x2]
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V6.4S, V22.4S, V0.4S
	sqrdmulh	V8.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V6.4S, V6.4S, V21.4S
	sub	V8.4S, V8.4S, V23.4S
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	ldp	Q0, Q1, [x1, #32]
	ldp	Q2, Q3, [x2, #32]
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V10.4S, V22.4S, V0.4S
	sqrdmulh	V12.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V10.4S, V10.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	ldp	Q0, Q1, [x1, #64]
	ldp	Q2, Q3, [x2, #64]
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V14.4S, V22.4S, V0.4S
	sqrdmulh	V16.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V14.4S, V14.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	ldp	Q0, Q1, [x1, #96]
	ldp	Q2, Q3, [x2, #96]
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V18.4S, V22.4S, V0.4S
	sqrdmulh	V20.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V18.4S, V18.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldp	Q0, Q1, [x1, #512]
	ldp	Q2, Q3, [x2, #512]
	mov	V21.16B, V5.16B
	mov	V22.16B, V7.16B
	trn1	V5.4S, V5.4S, V6.4S
	trn1	V7.4S, V7.4S, V8.4S
	trn2	V6.4S, V21.4S, V6.4S
	trn2	V8.4S, V22.4S, V8.4S
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V6.4S, V22.4S, V0.4S
	sqrdmulh	V8.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V6.4S, V6.4S, V21.4S
	sub	V8.4S, V8.4S, V23.4S
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	ldp	Q0, Q1, [x1, #544]
	ldp	Q2, Q3, [x2, #544]
	mov	V21.16B, V9.16B
	mov	V22.16B, V11.16B
	trn1	V9.4S, V9.4S, V10.4S
	trn1	V11.4S, V11.4S, V12.4S
	trn2	V10.4S, V21.4S, V10.4S
	trn2	V12.4S, V22.4S, V12.4S
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V10.4S, V22.4S, V0.4S
	sqrdmulh	V12.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V10.4S, V10.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	ldp	Q0, Q1, [x1, #576]
	ldp	Q2, Q3, [x2, #576]
	mov	V21.16B, V13.16B
	mov	V22.16B, V15.16B
	trn1	V13.4S, V13.4S, V14.4S
	trn1	V15.4S, V15.4S, V16.4S
	trn2	V14.4S, V21.4S, V14.4S
	trn2	V16.4S, V22.4S, V16.4S
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V14.4S, V22.4S, V0.4S
	sqrdmulh	V16.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V14.4S, V14.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	ldp	Q0, Q1, [x1, #608]
	ldp	Q2, Q3, [x2, #608]
	mov	V21.16B, V17.16B
	mov	V22.16B, V19.16B
	trn1	V17.4S, V17.4S, V18.4S
	trn1	V19.4S, V19.4S, V20.4S
	trn2	V18.4S, V21.4S, V18.4S
	trn2	V20.4S, V22.4S, V20.4S
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V18.4S, V22.4S, V0.4S
	sqrdmulh	V20.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V18.4S, V18.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1024]
	ldr	Q1, [x1, #1040]
	ldr	Q2, [x2, #1024]
	ldr	Q3, [x2, #1040]
	mov	V21.16B, V5.16B
	mov	V22.16B, V7.16B
	trn1	V5.2D, V5.2D, V6.2D
	trn1	V7.2D, V7.2D, V8.2D
	trn2	V6.2D, V21.2D, V6.2D
	trn2	V8.2D, V22.2D, V8.2D
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V6.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V6.4S, V6.4S, V21.4S
	sub	V8.4S, V8.4S, V23.4S
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	mov	V21.16B, V9.16B
	mov	V22.16B, V11.16B
	trn1	V9.2D, V9.2D, V10.2D
	trn1	V11.2D, V11.2D, V12.2D
	trn2	V10.2D, V21.2D, V10.2D
	trn2	V12.2D, V22.2D, V12.2D
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V10.4S, V22.4S, V0.S[2]
	sqrdmulh	V12.4S, V24.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V10.4S, V10.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	mov	V21.16B, V13.16B
	mov	V22.16B, V15.16B
	trn1	V13.2D, V13.2D, V14.2D
	trn1	V15.2D, V15.2D, V16.2D
	trn2	V14.2D, V21.2D, V14.2D
	trn2	V16.2D, V22.2D, V16.2D
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V3.S[0]
	mul	V23.4S, V24.4S, V3.S[1]
	sqrdmulh	V14.4S, V22.4S, V1.S[0]
	sqrdmulh	V16.4S, V24.4S, V1.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V14.4S, V14.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	mov	V21.16B, V17.16B
	mov	V22.16B, V19.16B
	trn1	V17.2D, V17.2D, V18.2D
	trn1	V19.2D, V19.2D, V20.2D
	trn2	V18.2D, V21.2D, V18.2D
	trn2	V20.2D, V22.2D, V20.2D
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V3.S[2]
	mul	V23.4S, V24.4S, V3.S[3]
	sqrdmulh	V18.4S, V22.4S, V1.S[2]
	sqrdmulh	V20.4S, V24.4S, V1.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V18.4S, V18.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1152]
	ldr	Q2, [x2, #1152]
	sub	V22.4S, V5.4S, V7.4S
	sub	V24.4S, V6.4S, V8.4S
	add	V5.4S, V5.4S, V7.4S
	add	V6.4S, V6.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V7.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[0]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V7.4S, V7.4S, V21.4S
	sub	V8.4S, V8.4S, V23.4S
	sshr	V7.4S, V7.4S, #1
	sshr	V8.4S, V8.4S, #1
	sub	V22.4S, V9.4S, V11.4S
	sub	V24.4S, V10.4S, V12.4S
	add	V9.4S, V9.4S, V11.4S
	add	V10.4S, V10.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V11.4S, V22.4S, V0.S[1]
	sqrdmulh	V12.4S, V24.4S, V0.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V11.4S, V11.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V15.4S
	sub	V24.4S, V14.4S, V16.4S
	add	V13.4S, V13.4S, V15.4S
	add	V14.4S, V14.4S, V16.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V15.4S, V22.4S, V0.S[2]
	sqrdmulh	V16.4S, V24.4S, V0.S[2]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V15.4S, V15.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V15.4S, V15.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V17.4S, V19.4S
	sub	V24.4S, V18.4S, V20.4S
	add	V17.4S, V17.4S, V19.4S
	add	V18.4S, V18.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[3]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V19.4S, V22.4S, V0.S[3]
	sqrdmulh	V20.4S, V24.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V19.4S, V19.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	stp	Q5, Q6, [x0]
	stp	Q7, Q8, [x0, #32]
	stp	Q9, Q10, [x0, #64]
	stp	Q11, Q12, [x0, #96]
	stp	Q13, Q14, [x0, #128]
	stp	Q15, Q16, [x0, #160]
	stp	Q17, Q18, [x0, #192]
	stp	Q19, Q20, [x0, #224]
	ldp	Q5, Q6, [x0, #256]
	ldp	Q7, Q8, [x0, #288]
	ldp	Q9, Q10, [x0, #320]
	ldp	Q11, Q12, [x0, #352]
	ldp	Q13, Q14, [x0, #384]
	ldp	Q15, Q16, [x0, #416]
	ldp	Q17, Q18, [x0, #448]
	ldp	Q19, Q20, [x0, #480]
	trn1	V21.2D, V5.2D, V6.2D
	trn2	V22.2D, V5.2D, V6.2D
	trn1	V5.4S, V21.4S, V22.4S
	trn2	V6.4S, V21.4S, V22.4S
	trn1	V21.2D, V7.2D, V8.2D
	trn2	V22.2D, V7.2D, V8.2D
	trn1	V7.4S, V21.4S, V22.4S
	trn2	V8.4S, V21.4S, V22.4S
	trn1	V21.2D, V9.2D, V10.2D
	trn2	V22.2D, V9.2D, V10.2D
	trn1	V9.4S, V21.4S, V22.4S
	trn2	V10.4S, V21.4S, V22.4S
	trn1	V21.2D, V11.2D, V12.2D
	trn2	V22.2D, V11.2D, V12.2D
	trn1	V11.4S, V21.4S, V22.4S
	trn2	V12.4S, V21.4S, V22.4S
	trn1	V21.2D, V13.2D, V14.2D
	trn2	V22.2D, V13.2D, V14.2D
	trn1	V13.4S, V21.4S, V22.4S
	trn2	V14.4S, V21.4S, V22.4S
	trn1	V21.2D, V15.2D, V16.2D
	trn2	V22.2D, V15.2D, V16.2D
	trn1	V15.4S, V21.4S, V22.4S
	trn2	V16.4S, V21.4S, V22.4S
	trn1	V21.2D, V17.2D, V18.2D
	trn2	V22.2D, V17.2D, V18.2D
	trn1	V17.4S, V21.4S, V22.4S
	trn2	V18.4S, V21.4S, V22.4S
	trn1	V21.2D, V19.2D, V20.2D
	trn2	V22.2D, V19.2D, V20.2D
	trn1	V19.4S, V21.4S, V22.4S
	trn2	V20.4S, V21.4S, V22.4S
	ldp	Q0, Q1, [x1, #128]
	ldp	Q2, Q3, [x2, #128]
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V6.4S, V22.4S, V0.4S
	sqrdmulh	V8.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V6.4S, V6.4S, V21.4S
	sub	V8.4S, V8.4S, V23.4S
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	ldp	Q0, Q1, [x1, #160]
	ldp	Q2, Q3, [x2, #160]
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V10.4S, V22.4S, V0.4S
	sqrdmulh	V12.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V10.4S, V10.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	ldp	Q0, Q1, [x1, #192]
	ldp	Q2, Q3, [x2, #192]
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V14.4S, V22.4S, V0.4S
	sqrdmulh	V16.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V14.4S, V14.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	ldp	Q0, Q1, [x1, #224]
	ldp	Q2, Q3, [x2, #224]
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V18.4S, V22.4S, V0.4S
	sqrdmulh	V20.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V18.4S, V18.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldp	Q0, Q1, [x1, #640]
	ldp	Q2, Q3, [x2, #640]
	mov	V21.16B, V5.16B
	mov	V22.16B, V7.16B
	trn1	V5.4S, V5.4S, V6.4S
	trn1	V7.4S, V7.4S, V8.4S
	trn2	V6.4S, V21.4S, V6.4S
	trn2	V8.4S, V22.4S, V8.4S
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V6.4S, V22.4S, V0.4S
	sqrdmulh	V8.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V6.4S, V6.4S, V21.4S
	sub	V8.4S, V8.4S, V23.4S
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	ldp	Q0, Q1, [x1, #672]
	ldp	Q2, Q3, [x2, #672]
	mov	V21.16B, V9.16B
	mov	V22.16B, V11.16B
	trn1	V9.4S, V9.4S, V10.4S
	trn1	V11.4S, V11.4S, V12.4S
	trn2	V10.4S, V21.4S, V10.4S
	trn2	V12.4S, V22.4S, V12.4S
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V10.4S, V22.4S, V0.4S
	sqrdmulh	V12.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V10.4S, V10.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	ldp	Q0, Q1, [x1, #704]
	ldp	Q2, Q3, [x2, #704]
	mov	V21.16B, V13.16B
	mov	V22.16B, V15.16B
	trn1	V13.4S, V13.4S, V14.4S
	trn1	V15.4S, V15.4S, V16.4S
	trn2	V14.4S, V21.4S, V14.4S
	trn2	V16.4S, V22.4S, V16.4S
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V14.4S, V22.4S, V0.4S
	sqrdmulh	V16.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V14.4S, V14.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	ldp	Q0, Q1, [x1, #736]
	ldp	Q2, Q3, [x2, #736]
	mov	V21.16B, V17.16B
	mov	V22.16B, V19.16B
	trn1	V17.4S, V17.4S, V18.4S
	trn1	V19.4S, V19.4S, V20.4S
	trn2	V18.4S, V21.4S, V18.4S
	trn2	V20.4S, V22.4S, V20.4S
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V18.4S, V22.4S, V0.4S
	sqrdmulh	V20.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V18.4S, V18.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1056]
	ldr	Q1, [x1, #1072]
	ldr	Q2, [x2, #1056]
	ldr	Q3, [x2, #1072]
	mov	V21.16B, V5.16B
	mov	V22.16B, V7.16B
	trn1	V5.2D, V5.2D, V6.2D
	trn1	V7.2D, V7.2D, V8.2D
	trn2	V6.2D, V21.2D, V6.2D
	trn2	V8.2D, V22.2D, V8.2D
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V6.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V6.4S, V6.4S, V21.4S
	sub	V8.4S, V8.4S, V23.4S
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	mov	V21.16B, V9.16B
	mov	V22.16B, V11.16B
	trn1	V9.2D, V9.2D, V10.2D
	trn1	V11.2D, V11.2D, V12.2D
	trn2	V10.2D, V21.2D, V10.2D
	trn2	V12.2D, V22.2D, V12.2D
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V10.4S, V22.4S, V0.S[2]
	sqrdmulh	V12.4S, V24.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V10.4S, V10.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	mov	V21.16B, V13.16B
	mov	V22.16B, V15.16B
	trn1	V13.2D, V13.2D, V14.2D
	trn1	V15.2D, V15.2D, V16.2D
	trn2	V14.2D, V21.2D, V14.2D
	trn2	V16.2D, V22.2D, V16.2D
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V3.S[0]
	mul	V23.4S, V24.4S, V3.S[1]
	sqrdmulh	V14.4S, V22.4S, V1.S[0]
	sqrdmulh	V16.4S, V24.4S, V1.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V14.4S, V14.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	mov	V21.16B, V17.16B
	mov	V22.16B, V19.16B
	trn1	V17.2D, V17.2D, V18.2D
	trn1	V19.2D, V19.2D, V20.2D
	trn2	V18.2D, V21.2D, V18.2D
	trn2	V20.2D, V22.2D, V20.2D
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V3.S[2]
	mul	V23.4S, V24.4S, V3.S[3]
	sqrdmulh	V18.4S, V22.4S, V1.S[2]
	sqrdmulh	V20.4S, V24.4S, V1.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V18.4S, V18.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1168]
	ldr	Q2, [x2, #1168]
	sub	V22.4S, V5.4S, V7.4S
	sub	V24.4S, V6.4S, V8.4S
	add	V5.4S, V5.4S, V7.4S
	add	V6.4S, V6.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V7.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[0]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V7.4S, V7.4S, V21.4S
	sub	V8.4S, V8.4S, V23.4S
	sshr	V7.4S, V7.4S, #1
	sshr	V8.4S, V8.4S, #1
	sub	V22.4S, V9.4S, V11.4S
	sub	V24.4S, V10.4S, V12.4S
	add	V9.4S, V9.4S, V11.4S
	add	V10.4S, V10.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V11.4S, V22.4S, V0.S[1]
	sqrdmulh	V12.4S, V24.4S, V0.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V11.4S, V11.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V15.4S
	sub	V24.4S, V14.4S, V16.4S
	add	V13.4S, V13.4S, V15.4S
	add	V14.4S, V14.4S, V16.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V15.4S, V22.4S, V0.S[2]
	sqrdmulh	V16.4S, V24.4S, V0.S[2]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V15.4S, V15.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V15.4S, V15.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V17.4S, V19.4S
	sub	V24.4S, V18.4S, V20.4S
	add	V17.4S, V17.4S, V19.4S
	add	V18.4S, V18.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[3]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V19.4S, V22.4S, V0.S[3]
	sqrdmulh	V20.4S, V24.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V19.4S, V19.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	stp	Q5, Q6, [x0, #256]
	stp	Q7, Q8, [x0, #288]
	stp	Q9, Q10, [x0, #320]
	stp	Q11, Q12, [x0, #352]
	stp	Q13, Q14, [x0, #384]
	stp	Q15, Q16, [x0, #416]
	stp	Q17, Q18, [x0, #448]
	stp	Q19, Q20, [x0, #480]
	ldp	Q5, Q6, [x0, #512]
	ldp	Q7, Q8, [x0, #544]
	ldp	Q9, Q10, [x0, #576]
	ldp	Q11, Q12, [x0, #608]
	ldp	Q13, Q14, [x0, #640]
	ldp	Q15, Q16, [x0, #672]
	ldp	Q17, Q18, [x0, #704]
	ldp	Q19, Q20, [x0, #736]
	trn1	V21.2D, V5.2D, V6.2D
	trn2	V22.2D, V5.2D, V6.2D
	trn1	V5.4S, V21.4S, V22.4S
	trn2	V6.4S, V21.4S, V22.4S
	trn1	V21.2D, V7.2D, V8.2D
	trn2	V22.2D, V7.2D, V8.2D
	trn1	V7.4S, V21.4S, V22.4S
	trn2	V8.4S, V21.4S, V22.4S
	trn1	V21.2D, V9.2D, V10.2D
	trn2	V22.2D, V9.2D, V10.2D
	trn1	V9.4S, V21.4S, V22.4S
	trn2	V10.4S, V21.4S, V22.4S
	trn1	V21.2D, V11.2D, V12.2D
	trn2	V22.2D, V11.2D, V12.2D
	trn1	V11.4S, V21.4S, V22.4S
	trn2	V12.4S, V21.4S, V22.4S
	trn1	V21.2D, V13.2D, V14.2D
	trn2	V22.2D, V13.2D, V14.2D
	trn1	V13.4S, V21.4S, V22.4S
	trn2	V14.4S, V21.4S, V22.4S
	trn1	V21.2D, V15.2D, V16.2D
	trn2	V22.2D, V15.2D, V16.2D
	trn1	V15.4S, V21.4S, V22.4S
	trn2	V16.4S, V21.4S, V22.4S
	trn1	V21.2D, V17.2D, V18.2D
	trn2	V22.2D, V17.2D, V18.2D
	trn1	V17.4S, V21.4S, V22.4S
	trn2	V18.4S, V21.4S, V22.4S
	trn1	V21.2D, V19.2D, V20.2D
	trn2	V22.2D, V19.2D, V20.2D
	trn1	V19.4S, V21.4S, V22.4S
	trn2	V20.4S, V21.4S, V22.4S
	ldp	Q0, Q1, [x1, #256]
	ldp	Q2, Q3, [x2, #256]
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V6.4S, V22.4S, V0.4S
	sqrdmulh	V8.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V6.4S, V6.4S, V21.4S
	sub	V8.4S, V8.4S, V23.4S
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	ldp	Q0, Q1, [x1, #288]
	ldp	Q2, Q3, [x2, #288]
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V10.4S, V22.4S, V0.4S
	sqrdmulh	V12.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V10.4S, V10.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	ldp	Q0, Q1, [x1, #320]
	ldp	Q2, Q3, [x2, #320]
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V14.4S, V22.4S, V0.4S
	sqrdmulh	V16.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V14.4S, V14.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	ldp	Q0, Q1, [x1, #352]
	ldp	Q2, Q3, [x2, #352]
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V18.4S, V22.4S, V0.4S
	sqrdmulh	V20.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V18.4S, V18.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldp	Q0, Q1, [x1, #768]
	ldp	Q2, Q3, [x2, #768]
	mov	V21.16B, V5.16B
	mov	V22.16B, V7.16B
	trn1	V5.4S, V5.4S, V6.4S
	trn1	V7.4S, V7.4S, V8.4S
	trn2	V6.4S, V21.4S, V6.4S
	trn2	V8.4S, V22.4S, V8.4S
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V6.4S, V22.4S, V0.4S
	sqrdmulh	V8.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V6.4S, V6.4S, V21.4S
	sub	V8.4S, V8.4S, V23.4S
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	ldp	Q0, Q1, [x1, #800]
	ldp	Q2, Q3, [x2, #800]
	mov	V21.16B, V9.16B
	mov	V22.16B, V11.16B
	trn1	V9.4S, V9.4S, V10.4S
	trn1	V11.4S, V11.4S, V12.4S
	trn2	V10.4S, V21.4S, V10.4S
	trn2	V12.4S, V22.4S, V12.4S
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V10.4S, V22.4S, V0.4S
	sqrdmulh	V12.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V10.4S, V10.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	ldp	Q0, Q1, [x1, #832]
	ldp	Q2, Q3, [x2, #832]
	mov	V21.16B, V13.16B
	mov	V22.16B, V15.16B
	trn1	V13.4S, V13.4S, V14.4S
	trn1	V15.4S, V15.4S, V16.4S
	trn2	V14.4S, V21.4S, V14.4S
	trn2	V16.4S, V22.4S, V16.4S
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V14.4S, V22.4S, V0.4S
	sqrdmulh	V16.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V14.4S, V14.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	ldp	Q0, Q1, [x1, #864]
	ldp	Q2, Q3, [x2, #864]
	mov	V21.16B, V17.16B
	mov	V22.16B, V19.16B
	trn1	V17.4S, V17.4S, V18.4S
	trn1	V19.4S, V19.4S, V20.4S
	trn2	V18.4S, V21.4S, V18.4S
	trn2	V20.4S, V22.4S, V20.4S
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V18.4S, V22.4S, V0.4S
	sqrdmulh	V20.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V18.4S, V18.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1088]
	ldr	Q1, [x1, #1104]
	ldr	Q2, [x2, #1088]
	ldr	Q3, [x2, #1104]
	mov	V21.16B, V5.16B
	mov	V22.16B, V7.16B
	trn1	V5.2D, V5.2D, V6.2D
	trn1	V7.2D, V7.2D, V8.2D
	trn2	V6.2D, V21.2D, V6.2D
	trn2	V8.2D, V22.2D, V8.2D
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V6.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V6.4S, V6.4S, V21.4S
	sub	V8.4S, V8.4S, V23.4S
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	mov	V21.16B, V9.16B
	mov	V22.16B, V11.16B
	trn1	V9.2D, V9.2D, V10.2D
	trn1	V11.2D, V11.2D, V12.2D
	trn2	V10.2D, V21.2D, V10.2D
	trn2	V12.2D, V22.2D, V12.2D
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V10.4S, V22.4S, V0.S[2]
	sqrdmulh	V12.4S, V24.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V10.4S, V10.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	mov	V21.16B, V13.16B
	mov	V22.16B, V15.16B
	trn1	V13.2D, V13.2D, V14.2D
	trn1	V15.2D, V15.2D, V16.2D
	trn2	V14.2D, V21.2D, V14.2D
	trn2	V16.2D, V22.2D, V16.2D
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V3.S[0]
	mul	V23.4S, V24.4S, V3.S[1]
	sqrdmulh	V14.4S, V22.4S, V1.S[0]
	sqrdmulh	V16.4S, V24.4S, V1.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V14.4S, V14.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	mov	V21.16B, V17.16B
	mov	V22.16B, V19.16B
	trn1	V17.2D, V17.2D, V18.2D
	trn1	V19.2D, V19.2D, V20.2D
	trn2	V18.2D, V21.2D, V18.2D
	trn2	V20.2D, V22.2D, V20.2D
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V3.S[2]
	mul	V23.4S, V24.4S, V3.S[3]
	sqrdmulh	V18.4S, V22.4S, V1.S[2]
	sqrdmulh	V20.4S, V24.4S, V1.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V18.4S, V18.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1184]
	ldr	Q2, [x2, #1184]
	sub	V22.4S, V5.4S, V7.4S
	sub	V24.4S, V6.4S, V8.4S
	add	V5.4S, V5.4S, V7.4S
	add	V6.4S, V6.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V7.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[0]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V7.4S, V7.4S, V21.4S
	sub	V8.4S, V8.4S, V23.4S
	sshr	V7.4S, V7.4S, #1
	sshr	V8.4S, V8.4S, #1
	sub	V22.4S, V9.4S, V11.4S
	sub	V24.4S, V10.4S, V12.4S
	add	V9.4S, V9.4S, V11.4S
	add	V10.4S, V10.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V11.4S, V22.4S, V0.S[1]
	sqrdmulh	V12.4S, V24.4S, V0.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V11.4S, V11.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V15.4S
	sub	V24.4S, V14.4S, V16.4S
	add	V13.4S, V13.4S, V15.4S
	add	V14.4S, V14.4S, V16.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V15.4S, V22.4S, V0.S[2]
	sqrdmulh	V16.4S, V24.4S, V0.S[2]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V15.4S, V15.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V15.4S, V15.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V17.4S, V19.4S
	sub	V24.4S, V18.4S, V20.4S
	add	V17.4S, V17.4S, V19.4S
	add	V18.4S, V18.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[3]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V19.4S, V22.4S, V0.S[3]
	sqrdmulh	V20.4S, V24.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V19.4S, V19.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	stp	Q5, Q6, [x0, #512]
	stp	Q7, Q8, [x0, #544]
	stp	Q9, Q10, [x0, #576]
	stp	Q11, Q12, [x0, #608]
	stp	Q13, Q14, [x0, #640]
	stp	Q15, Q16, [x0, #672]
	stp	Q17, Q18, [x0, #704]
	stp	Q19, Q20, [x0, #736]
	ldp	Q5, Q6, [x0, #768]
	ldp	Q7, Q8, [x0, #800]
	ldp	Q9, Q10, [x0, #832]
	ldp	Q11, Q12, [x0, #864]
	ldp	Q13, Q14, [x0, #896]
	ldp	Q15, Q16, [x0, #928]
	ldp	Q17, Q18, [x0, #960]
	ldp	Q19, Q20, [x0, #992]
	trn1	V21.2D, V5.2D, V6.2D
	trn2	V22.2D, V5.2D, V6.2D
	trn1	V5.4S, V21.4S, V22.4S
	trn2	V6.4S, V21.4S, V22.4S
	trn1	V21.2D, V7.2D, V8.2D
	trn2	V22.2D, V7.2D, V8.2D
	trn1	V7.4S, V21.4S, V22.4S
	trn2	V8.4S, V21.4S, V22.4S
	trn1	V21.2D, V9.2D, V10.2D
	trn2	V22.2D, V9.2D, V10.2D
	trn1	V9.4S, V21.4S, V22.4S
	trn2	V10.4S, V21.4S, V22.4S
	trn1	V21.2D, V11.2D, V12.2D
	trn2	V22.2D, V11.2D, V12.2D
	trn1	V11.4S, V21.4S, V22.4S
	trn2	V12.4S, V21.4S, V22.4S
	trn1	V21.2D, V13.2D, V14.2D
	trn2	V22.2D, V13.2D, V14.2D
	trn1	V13.4S, V21.4S, V22.4S
	trn2	V14.4S, V21.4S, V22.4S
	trn1	V21.2D, V15.2D, V16.2D
	trn2	V22.2D, V15.2D, V16.2D
	trn1	V15.4S, V21.4S, V22.4S
	trn2	V16.4S, V21.4S, V22.4S
	trn1	V21.2D, V17.2D, V18.2D
	trn2	V22.2D, V17.2D, V18.2D
	trn1	V17.4S, V21.4S, V22.4S
	trn2	V18.4S, V21.4S, V22.4S
	trn1	V21.2D, V19.2D, V20.2D
	trn2	V22.2D, V19.2D, V20.2D
	trn1	V19.4S, V21.4S, V22.4S
	trn2	V20.4S, V21.4S, V22.4S
	ldp	Q0, Q1, [x1, #384]
	ldp	Q2, Q3, [x2, #384]
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V6.4S, V22.4S, V0.4S
	sqrdmulh	V8.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V6.4S, V6.4S, V21.4S
	sub	V8.4S, V8.4S, V23.4S
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	ldp	Q0, Q1, [x1, #416]
	ldp	Q2, Q3, [x2, #416]
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V10.4S, V22.4S, V0.4S
	sqrdmulh	V12.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V10.4S, V10.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	ldp	Q0, Q1, [x1, #448]
	ldp	Q2, Q3, [x2, #448]
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V14.4S, V22.4S, V0.4S
	sqrdmulh	V16.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V14.4S, V14.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	ldp	Q0, Q1, [x1, #480]
	ldp	Q2, Q3, [x2, #480]
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V18.4S, V22.4S, V0.4S
	sqrdmulh	V20.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V18.4S, V18.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldp	Q0, Q1, [x1, #896]
	ldp	Q2, Q3, [x2, #896]
	mov	V21.16B, V5.16B
	mov	V22.16B, V7.16B
	trn1	V5.4S, V5.4S, V6.4S
	trn1	V7.4S, V7.4S, V8.4S
	trn2	V6.4S, V21.4S, V6.4S
	trn2	V8.4S, V22.4S, V8.4S
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V6.4S, V22.4S, V0.4S
	sqrdmulh	V8.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V6.4S, V6.4S, V21.4S
	sub	V8.4S, V8.4S, V23.4S
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	ldp	Q0, Q1, [x1, #928]
	ldp	Q2, Q3, [x2, #928]
	mov	V21.16B, V9.16B
	mov	V22.16B, V11.16B
	trn1	V9.4S, V9.4S, V10.4S
	trn1	V11.4S, V11.4S, V12.4S
	trn2	V10.4S, V21.4S, V10.4S
	trn2	V12.4S, V22.4S, V12.4S
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V10.4S, V22.4S, V0.4S
	sqrdmulh	V12.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V10.4S, V10.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	ldp	Q0, Q1, [x1, #960]
	ldp	Q2, Q3, [x2, #960]
	mov	V21.16B, V13.16B
	mov	V22.16B, V15.16B
	trn1	V13.4S, V13.4S, V14.4S
	trn1	V15.4S, V15.4S, V16.4S
	trn2	V14.4S, V21.4S, V14.4S
	trn2	V16.4S, V22.4S, V16.4S
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V14.4S, V22.4S, V0.4S
	sqrdmulh	V16.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V14.4S, V14.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	ldp	Q0, Q1, [x1, #992]
	ldp	Q2, Q3, [x2, #992]
	mov	V21.16B, V17.16B
	mov	V22.16B, V19.16B
	trn1	V17.4S, V17.4S, V18.4S
	trn1	V19.4S, V19.4S, V20.4S
	trn2	V18.4S, V21.4S, V18.4S
	trn2	V20.4S, V22.4S, V20.4S
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V18.4S, V22.4S, V0.4S
	sqrdmulh	V20.4S, V24.4S, V1.4S
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V18.4S, V18.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1120]
	ldr	Q1, [x1, #1136]
	ldr	Q2, [x2, #1120]
	ldr	Q3, [x2, #1136]
	mov	V21.16B, V5.16B
	mov	V22.16B, V7.16B
	trn1	V5.2D, V5.2D, V6.2D
	trn1	V7.2D, V7.2D, V8.2D
	trn2	V6.2D, V21.2D, V6.2D
	trn2	V8.2D, V22.2D, V8.2D
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V6.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V6.4S, V6.4S, V21.4S
	sub	V8.4S, V8.4S, V23.4S
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	mov	V21.16B, V9.16B
	mov	V22.16B, V11.16B
	trn1	V9.2D, V9.2D, V10.2D
	trn1	V11.2D, V11.2D, V12.2D
	trn2	V10.2D, V21.2D, V10.2D
	trn2	V12.2D, V22.2D, V12.2D
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V10.4S, V22.4S, V0.S[2]
	sqrdmulh	V12.4S, V24.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V10.4S, V10.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	mov	V21.16B, V13.16B
	mov	V22.16B, V15.16B
	trn1	V13.2D, V13.2D, V14.2D
	trn1	V15.2D, V15.2D, V16.2D
	trn2	V14.2D, V21.2D, V14.2D
	trn2	V16.2D, V22.2D, V16.2D
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V3.S[0]
	mul	V23.4S, V24.4S, V3.S[1]
	sqrdmulh	V14.4S, V22.4S, V1.S[0]
	sqrdmulh	V16.4S, V24.4S, V1.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V14.4S, V14.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	mov	V21.16B, V17.16B
	mov	V22.16B, V19.16B
	trn1	V17.2D, V17.2D, V18.2D
	trn1	V19.2D, V19.2D, V20.2D
	trn2	V18.2D, V21.2D, V18.2D
	trn2	V20.2D, V22.2D, V20.2D
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V3.S[2]
	mul	V23.4S, V24.4S, V3.S[3]
	sqrdmulh	V18.4S, V22.4S, V1.S[2]
	sqrdmulh	V20.4S, V24.4S, V1.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V18.4S, V18.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1200]
	ldr	Q2, [x2, #1200]
	sub	V22.4S, V5.4S, V7.4S
	sub	V24.4S, V6.4S, V8.4S
	add	V5.4S, V5.4S, V7.4S
	add	V6.4S, V6.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V7.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[0]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V7.4S, V7.4S, V21.4S
	sub	V8.4S, V8.4S, V23.4S
	sshr	V7.4S, V7.4S, #1
	sshr	V8.4S, V8.4S, #1
	sub	V22.4S, V9.4S, V11.4S
	sub	V24.4S, V10.4S, V12.4S
	add	V9.4S, V9.4S, V11.4S
	add	V10.4S, V10.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V11.4S, V22.4S, V0.S[1]
	sqrdmulh	V12.4S, V24.4S, V0.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V11.4S, V11.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V15.4S
	sub	V24.4S, V14.4S, V16.4S
	add	V13.4S, V13.4S, V15.4S
	add	V14.4S, V14.4S, V16.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V15.4S, V22.4S, V0.S[2]
	sqrdmulh	V16.4S, V24.4S, V0.S[2]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V15.4S, V15.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V15.4S, V15.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V17.4S, V19.4S
	sub	V24.4S, V18.4S, V20.4S
	add	V17.4S, V17.4S, V19.4S
	add	V18.4S, V18.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[3]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V19.4S, V22.4S, V0.S[3]
	sqrdmulh	V20.4S, V24.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V19.4S, V19.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	stp	Q5, Q6, [x0, #768]
	stp	Q7, Q8, [x0, #800]
	stp	Q9, Q10, [x0, #832]
	stp	Q11, Q12, [x0, #864]
	stp	Q13, Q14, [x0, #896]
	stp	Q15, Q16, [x0, #928]
	stp	Q17, Q18, [x0, #960]
	stp	Q19, Q20, [x0, #992]
	ldr	Q5, [x0]
	ldr	Q6, [x0, #64]
	ldr	Q7, [x0, #128]
	ldr	Q8, [x0, #192]
	ldr	Q9, [x0, #256]
	ldr	Q10, [x0, #320]
	ldr	Q11, [x0, #384]
	ldr	Q12, [x0, #448]
	ldr	Q13, [x0, #512]
	ldr	Q14, [x0, #576]
	ldr	Q15, [x0, #640]
	ldr	Q16, [x0, #704]
	ldr	Q17, [x0, #768]
	ldr	Q18, [x0, #832]
	ldr	Q19, [x0, #896]
	ldr	Q20, [x0, #960]
	ldr	Q0, [x1, #1216]
	ldr	Q1, [x1, #1232]
	ldr	Q2, [x2, #1216]
	ldr	Q3, [x2, #1232]
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V6.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V6.4S, V6.4S, V21.4S
	sub	V8.4S, V8.4S, V23.4S
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V10.4S, V22.4S, V0.S[2]
	sqrdmulh	V12.4S, V24.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V10.4S, V10.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V3.S[0]
	mul	V23.4S, V24.4S, V3.S[1]
	sqrdmulh	V14.4S, V22.4S, V1.S[0]
	sqrdmulh	V16.4S, V24.4S, V1.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V14.4S, V14.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V3.S[2]
	mul	V23.4S, V24.4S, V3.S[3]
	sqrdmulh	V18.4S, V22.4S, V1.S[2]
	sqrdmulh	V20.4S, V24.4S, V1.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V18.4S, V18.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1248]
	ldr	Q2, [x2, #1248]
	sub	V22.4S, V5.4S, V7.4S
	sub	V24.4S, V6.4S, V8.4S
	add	V5.4S, V5.4S, V7.4S
	add	V6.4S, V6.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V7.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[0]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V7.4S, V7.4S, V21.4S
	sub	V8.4S, V8.4S, V23.4S
	sshr	V7.4S, V7.4S, #1
	sshr	V8.4S, V8.4S, #1
	sub	V22.4S, V9.4S, V11.4S
	sub	V24.4S, V10.4S, V12.4S
	add	V9.4S, V9.4S, V11.4S
	add	V10.4S, V10.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V11.4S, V22.4S, V0.S[1]
	sqrdmulh	V12.4S, V24.4S, V0.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V11.4S, V11.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V15.4S
	sub	V24.4S, V14.4S, V16.4S
	add	V13.4S, V13.4S, V15.4S
	add	V14.4S, V14.4S, V16.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V15.4S, V22.4S, V0.S[2]
	sqrdmulh	V16.4S, V24.4S, V0.S[2]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V15.4S, V15.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V15.4S, V15.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V17.4S, V19.4S
	sub	V24.4S, V18.4S, V20.4S
	add	V17.4S, V17.4S, V19.4S
	add	V18.4S, V18.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[3]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V19.4S, V22.4S, V0.S[3]
	sqrdmulh	V20.4S, V24.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V19.4S, V19.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1264]
	ldr	Q2, [x2, #1264]
	sub	V22.4S, V5.4S, V9.4S
	sub	V24.4S, V6.4S, V10.4S
	add	V5.4S, V5.4S, V9.4S
	add	V6.4S, V6.4S, V10.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V9.4S, V22.4S, V0.S[0]
	sqrdmulh	V10.4S, V24.4S, V0.S[0]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V9.4S, V9.4S, V21.4S
	sub	V10.4S, V10.4S, V23.4S
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	sub	V22.4S, V7.4S, V11.4S
	sub	V24.4S, V8.4S, V12.4S
	add	V7.4S, V7.4S, V11.4S
	add	V8.4S, V8.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V11.4S, V22.4S, V0.S[0]
	sqrdmulh	V12.4S, V24.4S, V0.S[0]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V11.4S, V11.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V17.4S
	sub	V24.4S, V14.4S, V18.4S
	add	V13.4S, V13.4S, V17.4S
	add	V14.4S, V14.4S, V18.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V17.4S, V22.4S, V0.S[1]
	sqrdmulh	V18.4S, V24.4S, V0.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V17.4S, V17.4S, V21.4S
	sub	V18.4S, V18.4S, V23.4S
	sshr	V17.4S, V17.4S, #1
	sshr	V18.4S, V18.4S, #1
	sub	V22.4S, V15.4S, V19.4S
	sub	V24.4S, V16.4S, V20.4S
	add	V15.4S, V15.4S, V19.4S
	add	V16.4S, V16.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V19.4S, V22.4S, V0.S[1]
	sqrdmulh	V20.4S, V24.4S, V0.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V19.4S, V19.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	sub	V22.4S, V5.4S, V13.4S
	sub	V24.4S, V6.4S, V14.4S
	add	V5.4S, V5.4S, V13.4S
	add	V6.4S, V6.4S, V14.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V13.4S, V22.4S, V0.S[2]
	sqrdmulh	V14.4S, V24.4S, V0.S[2]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V13.4S, V13.4S, V21.4S
	sub	V14.4S, V14.4S, V23.4S
	sshr	V13.4S, V13.4S, #1
	sshr	V14.4S, V14.4S, #1
	sub	V22.4S, V7.4S, V15.4S
	sub	V24.4S, V8.4S, V16.4S
	add	V7.4S, V7.4S, V15.4S
	add	V8.4S, V8.4S, V16.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V15.4S, V22.4S, V0.S[2]
	sqrdmulh	V16.4S, V24.4S, V0.S[2]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V15.4S, V15.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V15.4S, V15.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V9.4S, V17.4S
	sub	V24.4S, V10.4S, V18.4S
	add	V9.4S, V9.4S, V17.4S
	add	V10.4S, V10.4S, V18.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V17.4S, V22.4S, V0.S[2]
	sqrdmulh	V18.4S, V24.4S, V0.S[2]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V17.4S, V17.4S, V21.4S
	sub	V18.4S, V18.4S, V23.4S
	sshr	V17.4S, V17.4S, #1
	sshr	V18.4S, V18.4S, #1
	sub	V22.4S, V11.4S, V19.4S
	sub	V24.4S, V12.4S, V20.4S
	add	V11.4S, V11.4S, V19.4S
	add	V12.4S, V12.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V19.4S, V22.4S, V0.S[2]
	sqrdmulh	V20.4S, V24.4S, V0.S[2]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V19.4S, V19.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	mul	V21.4S, V5.4S, V2.S[3]
	mul	V22.4S, V6.4S, V2.S[3]
	sqrdmulh	V5.4S, V5.4S, V0.S[3]
	sqrdmulh	V6.4S, V6.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V22.4S, V22.4S, V4.S[0]
	sub	V5.4S, V5.4S, V21.4S
	sub	V6.4S, V6.4S, V22.4S
	sshr	V5.4S, V5.4S, #1
	sshr	V6.4S, V6.4S, #1
	mul	V21.4S, V7.4S, V2.S[3]
	mul	V22.4S, V8.4S, V2.S[3]
	sqrdmulh	V7.4S, V7.4S, V0.S[3]
	sqrdmulh	V8.4S, V8.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V22.4S, V22.4S, V4.S[0]
	sub	V7.4S, V7.4S, V21.4S
	sub	V8.4S, V8.4S, V22.4S
	sshr	V7.4S, V7.4S, #1
	sshr	V8.4S, V8.4S, #1
	mul	V21.4S, V9.4S, V2.S[3]
	mul	V22.4S, V10.4S, V2.S[3]
	sqrdmulh	V9.4S, V9.4S, V0.S[3]
	sqrdmulh	V10.4S, V10.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V22.4S, V22.4S, V4.S[0]
	sub	V9.4S, V9.4S, V21.4S
	sub	V10.4S, V10.4S, V22.4S
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	mul	V21.4S, V11.4S, V2.S[3]
	mul	V22.4S, V12.4S, V2.S[3]
	sqrdmulh	V11.4S, V11.4S, V0.S[3]
	sqrdmulh	V12.4S, V12.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V22.4S, V22.4S, V4.S[0]
	sub	V11.4S, V11.4S, V21.4S
	sub	V12.4S, V12.4S, V22.4S
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	str	Q5, [x0]
	str	Q6, [x0, #64]
	str	Q7, [x0, #128]
	str	Q8, [x0, #192]
	str	Q9, [x0, #256]
	str	Q10, [x0, #320]
	str	Q11, [x0, #384]
	str	Q12, [x0, #448]
	str	Q13, [x0, #512]
	str	Q14, [x0, #576]
	str	Q15, [x0, #640]
	str	Q16, [x0, #704]
	str	Q17, [x0, #768]
	str	Q18, [x0, #832]
	str	Q19, [x0, #896]
	str	Q20, [x0, #960]
	ldr	Q5, [x0, #16]
	ldr	Q6, [x0, #80]
	ldr	Q7, [x0, #144]
	ldr	Q8, [x0, #208]
	ldr	Q9, [x0, #272]
	ldr	Q10, [x0, #336]
	ldr	Q11, [x0, #400]
	ldr	Q12, [x0, #464]
	ldr	Q13, [x0, #528]
	ldr	Q14, [x0, #592]
	ldr	Q15, [x0, #656]
	ldr	Q16, [x0, #720]
	ldr	Q17, [x0, #784]
	ldr	Q18, [x0, #848]
	ldr	Q19, [x0, #912]
	ldr	Q20, [x0, #976]
	ldr	Q0, [x1, #1216]
	ldr	Q1, [x1, #1232]
	ldr	Q2, [x2, #1216]
	ldr	Q3, [x2, #1232]
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V6.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V6.4S, V6.4S, V21.4S
	sub	V8.4S, V8.4S, V23.4S
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V10.4S, V22.4S, V0.S[2]
	sqrdmulh	V12.4S, V24.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V10.4S, V10.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V3.S[0]
	mul	V23.4S, V24.4S, V3.S[1]
	sqrdmulh	V14.4S, V22.4S, V1.S[0]
	sqrdmulh	V16.4S, V24.4S, V1.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V14.4S, V14.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V3.S[2]
	mul	V23.4S, V24.4S, V3.S[3]
	sqrdmulh	V18.4S, V22.4S, V1.S[2]
	sqrdmulh	V20.4S, V24.4S, V1.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V18.4S, V18.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1248]
	ldr	Q2, [x2, #1248]
	sub	V22.4S, V5.4S, V7.4S
	sub	V24.4S, V6.4S, V8.4S
	add	V5.4S, V5.4S, V7.4S
	add	V6.4S, V6.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V7.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[0]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V7.4S, V7.4S, V21.4S
	sub	V8.4S, V8.4S, V23.4S
	sshr	V7.4S, V7.4S, #1
	sshr	V8.4S, V8.4S, #1
	sub	V22.4S, V9.4S, V11.4S
	sub	V24.4S, V10.4S, V12.4S
	add	V9.4S, V9.4S, V11.4S
	add	V10.4S, V10.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V11.4S, V22.4S, V0.S[1]
	sqrdmulh	V12.4S, V24.4S, V0.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V11.4S, V11.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V15.4S
	sub	V24.4S, V14.4S, V16.4S
	add	V13.4S, V13.4S, V15.4S
	add	V14.4S, V14.4S, V16.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V15.4S, V22.4S, V0.S[2]
	sqrdmulh	V16.4S, V24.4S, V0.S[2]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V15.4S, V15.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V15.4S, V15.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V17.4S, V19.4S
	sub	V24.4S, V18.4S, V20.4S
	add	V17.4S, V17.4S, V19.4S
	add	V18.4S, V18.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[3]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V19.4S, V22.4S, V0.S[3]
	sqrdmulh	V20.4S, V24.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V19.4S, V19.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1264]
	ldr	Q2, [x2, #1264]
	sub	V22.4S, V5.4S, V9.4S
	sub	V24.4S, V6.4S, V10.4S
	add	V5.4S, V5.4S, V9.4S
	add	V6.4S, V6.4S, V10.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V9.4S, V22.4S, V0.S[0]
	sqrdmulh	V10.4S, V24.4S, V0.S[0]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V9.4S, V9.4S, V21.4S
	sub	V10.4S, V10.4S, V23.4S
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	sub	V22.4S, V7.4S, V11.4S
	sub	V24.4S, V8.4S, V12.4S
	add	V7.4S, V7.4S, V11.4S
	add	V8.4S, V8.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V11.4S, V22.4S, V0.S[0]
	sqrdmulh	V12.4S, V24.4S, V0.S[0]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V11.4S, V11.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V17.4S
	sub	V24.4S, V14.4S, V18.4S
	add	V13.4S, V13.4S, V17.4S
	add	V14.4S, V14.4S, V18.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V17.4S, V22.4S, V0.S[1]
	sqrdmulh	V18.4S, V24.4S, V0.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V17.4S, V17.4S, V21.4S
	sub	V18.4S, V18.4S, V23.4S
	sshr	V17.4S, V17.4S, #1
	sshr	V18.4S, V18.4S, #1
	sub	V22.4S, V15.4S, V19.4S
	sub	V24.4S, V16.4S, V20.4S
	add	V15.4S, V15.4S, V19.4S
	add	V16.4S, V16.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V19.4S, V22.4S, V0.S[1]
	sqrdmulh	V20.4S, V24.4S, V0.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V19.4S, V19.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	sub	V22.4S, V5.4S, V13.4S
	sub	V24.4S, V6.4S, V14.4S
	add	V5.4S, V5.4S, V13.4S
	add	V6.4S, V6.4S, V14.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V13.4S, V22.4S, V0.S[2]
	sqrdmulh	V14.4S, V24.4S, V0.S[2]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V13.4S, V13.4S, V21.4S
	sub	V14.4S, V14.4S, V23.4S
	sshr	V13.4S, V13.4S, #1
	sshr	V14.4S, V14.4S, #1
	sub	V22.4S, V7.4S, V15.4S
	sub	V24.4S, V8.4S, V16.4S
	add	V7.4S, V7.4S, V15.4S
	add	V8.4S, V8.4S, V16.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V15.4S, V22.4S, V0.S[2]
	sqrdmulh	V16.4S, V24.4S, V0.S[2]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V15.4S, V15.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V15.4S, V15.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V9.4S, V17.4S
	sub	V24.4S, V10.4S, V18.4S
	add	V9.4S, V9.4S, V17.4S
	add	V10.4S, V10.4S, V18.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V17.4S, V22.4S, V0.S[2]
	sqrdmulh	V18.4S, V24.4S, V0.S[2]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V17.4S, V17.4S, V21.4S
	sub	V18.4S, V18.4S, V23.4S
	sshr	V17.4S, V17.4S, #1
	sshr	V18.4S, V18.4S, #1
	sub	V22.4S, V11.4S, V19.4S
	sub	V24.4S, V12.4S, V20.4S
	add	V11.4S, V11.4S, V19.4S
	add	V12.4S, V12.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V19.4S, V22.4S, V0.S[2]
	sqrdmulh	V20.4S, V24.4S, V0.S[2]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V19.4S, V19.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	mul	V21.4S, V5.4S, V2.S[3]
	mul	V22.4S, V6.4S, V2.S[3]
	sqrdmulh	V5.4S, V5.4S, V0.S[3]
	sqrdmulh	V6.4S, V6.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V22.4S, V22.4S, V4.S[0]
	sub	V5.4S, V5.4S, V21.4S
	sub	V6.4S, V6.4S, V22.4S
	sshr	V5.4S, V5.4S, #1
	sshr	V6.4S, V6.4S, #1
	mul	V21.4S, V7.4S, V2.S[3]
	mul	V22.4S, V8.4S, V2.S[3]
	sqrdmulh	V7.4S, V7.4S, V0.S[3]
	sqrdmulh	V8.4S, V8.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V22.4S, V22.4S, V4.S[0]
	sub	V7.4S, V7.4S, V21.4S
	sub	V8.4S, V8.4S, V22.4S
	sshr	V7.4S, V7.4S, #1
	sshr	V8.4S, V8.4S, #1
	mul	V21.4S, V9.4S, V2.S[3]
	mul	V22.4S, V10.4S, V2.S[3]
	sqrdmulh	V9.4S, V9.4S, V0.S[3]
	sqrdmulh	V10.4S, V10.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V22.4S, V22.4S, V4.S[0]
	sub	V9.4S, V9.4S, V21.4S
	sub	V10.4S, V10.4S, V22.4S
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	mul	V21.4S, V11.4S, V2.S[3]
	mul	V22.4S, V12.4S, V2.S[3]
	sqrdmulh	V11.4S, V11.4S, V0.S[3]
	sqrdmulh	V12.4S, V12.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V22.4S, V22.4S, V4.S[0]
	sub	V11.4S, V11.4S, V21.4S
	sub	V12.4S, V12.4S, V22.4S
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	str	Q5, [x0, #16]
	str	Q6, [x0, #80]
	str	Q7, [x0, #144]
	str	Q8, [x0, #208]
	str	Q9, [x0, #272]
	str	Q10, [x0, #336]
	str	Q11, [x0, #400]
	str	Q12, [x0, #464]
	str	Q13, [x0, #528]
	str	Q14, [x0, #592]
	str	Q15, [x0, #656]
	str	Q16, [x0, #720]
	str	Q17, [x0, #784]
	str	Q18, [x0, #848]
	str	Q19, [x0, #912]
	str	Q20, [x0, #976]
	ldr	Q5, [x0, #32]
	ldr	Q6, [x0, #96]
	ldr	Q7, [x0, #160]
	ldr	Q8, [x0, #224]
	ldr	Q9, [x0, #288]
	ldr	Q10, [x0, #352]
	ldr	Q11, [x0, #416]
	ldr	Q12, [x0, #480]
	ldr	Q13, [x0, #544]
	ldr	Q14, [x0, #608]
	ldr	Q15, [x0, #672]
	ldr	Q16, [x0, #736]
	ldr	Q17, [x0, #800]
	ldr	Q18, [x0, #864]
	ldr	Q19, [x0, #928]
	ldr	Q20, [x0, #992]
	ldr	Q0, [x1, #1216]
	ldr	Q1, [x1, #1232]
	ldr	Q2, [x2, #1216]
	ldr	Q3, [x2, #1232]
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V6.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V6.4S, V6.4S, V21.4S
	sub	V8.4S, V8.4S, V23.4S
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V10.4S, V22.4S, V0.S[2]
	sqrdmulh	V12.4S, V24.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V10.4S, V10.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V3.S[0]
	mul	V23.4S, V24.4S, V3.S[1]
	sqrdmulh	V14.4S, V22.4S, V1.S[0]
	sqrdmulh	V16.4S, V24.4S, V1.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V14.4S, V14.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V3.S[2]
	mul	V23.4S, V24.4S, V3.S[3]
	sqrdmulh	V18.4S, V22.4S, V1.S[2]
	sqrdmulh	V20.4S, V24.4S, V1.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V18.4S, V18.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1248]
	ldr	Q2, [x2, #1248]
	sub	V22.4S, V5.4S, V7.4S
	sub	V24.4S, V6.4S, V8.4S
	add	V5.4S, V5.4S, V7.4S
	add	V6.4S, V6.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V7.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[0]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V7.4S, V7.4S, V21.4S
	sub	V8.4S, V8.4S, V23.4S
	sshr	V7.4S, V7.4S, #1
	sshr	V8.4S, V8.4S, #1
	sub	V22.4S, V9.4S, V11.4S
	sub	V24.4S, V10.4S, V12.4S
	add	V9.4S, V9.4S, V11.4S
	add	V10.4S, V10.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V11.4S, V22.4S, V0.S[1]
	sqrdmulh	V12.4S, V24.4S, V0.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V11.4S, V11.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V15.4S
	sub	V24.4S, V14.4S, V16.4S
	add	V13.4S, V13.4S, V15.4S
	add	V14.4S, V14.4S, V16.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V15.4S, V22.4S, V0.S[2]
	sqrdmulh	V16.4S, V24.4S, V0.S[2]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V15.4S, V15.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V15.4S, V15.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V17.4S, V19.4S
	sub	V24.4S, V18.4S, V20.4S
	add	V17.4S, V17.4S, V19.4S
	add	V18.4S, V18.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[3]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V19.4S, V22.4S, V0.S[3]
	sqrdmulh	V20.4S, V24.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V19.4S, V19.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1264]
	ldr	Q2, [x2, #1264]
	sub	V22.4S, V5.4S, V9.4S
	sub	V24.4S, V6.4S, V10.4S
	add	V5.4S, V5.4S, V9.4S
	add	V6.4S, V6.4S, V10.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V9.4S, V22.4S, V0.S[0]
	sqrdmulh	V10.4S, V24.4S, V0.S[0]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V9.4S, V9.4S, V21.4S
	sub	V10.4S, V10.4S, V23.4S
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	sub	V22.4S, V7.4S, V11.4S
	sub	V24.4S, V8.4S, V12.4S
	add	V7.4S, V7.4S, V11.4S
	add	V8.4S, V8.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V11.4S, V22.4S, V0.S[0]
	sqrdmulh	V12.4S, V24.4S, V0.S[0]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V11.4S, V11.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V17.4S
	sub	V24.4S, V14.4S, V18.4S
	add	V13.4S, V13.4S, V17.4S
	add	V14.4S, V14.4S, V18.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V17.4S, V22.4S, V0.S[1]
	sqrdmulh	V18.4S, V24.4S, V0.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V17.4S, V17.4S, V21.4S
	sub	V18.4S, V18.4S, V23.4S
	sshr	V17.4S, V17.4S, #1
	sshr	V18.4S, V18.4S, #1
	sub	V22.4S, V15.4S, V19.4S
	sub	V24.4S, V16.4S, V20.4S
	add	V15.4S, V15.4S, V19.4S
	add	V16.4S, V16.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V19.4S, V22.4S, V0.S[1]
	sqrdmulh	V20.4S, V24.4S, V0.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V19.4S, V19.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	sub	V22.4S, V5.4S, V13.4S
	sub	V24.4S, V6.4S, V14.4S
	add	V5.4S, V5.4S, V13.4S
	add	V6.4S, V6.4S, V14.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V13.4S, V22.4S, V0.S[2]
	sqrdmulh	V14.4S, V24.4S, V0.S[2]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V13.4S, V13.4S, V21.4S
	sub	V14.4S, V14.4S, V23.4S
	sshr	V13.4S, V13.4S, #1
	sshr	V14.4S, V14.4S, #1
	sub	V22.4S, V7.4S, V15.4S
	sub	V24.4S, V8.4S, V16.4S
	add	V7.4S, V7.4S, V15.4S
	add	V8.4S, V8.4S, V16.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V15.4S, V22.4S, V0.S[2]
	sqrdmulh	V16.4S, V24.4S, V0.S[2]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V15.4S, V15.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V15.4S, V15.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V9.4S, V17.4S
	sub	V24.4S, V10.4S, V18.4S
	add	V9.4S, V9.4S, V17.4S
	add	V10.4S, V10.4S, V18.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V17.4S, V22.4S, V0.S[2]
	sqrdmulh	V18.4S, V24.4S, V0.S[2]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V17.4S, V17.4S, V21.4S
	sub	V18.4S, V18.4S, V23.4S
	sshr	V17.4S, V17.4S, #1
	sshr	V18.4S, V18.4S, #1
	sub	V22.4S, V11.4S, V19.4S
	sub	V24.4S, V12.4S, V20.4S
	add	V11.4S, V11.4S, V19.4S
	add	V12.4S, V12.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V19.4S, V22.4S, V0.S[2]
	sqrdmulh	V20.4S, V24.4S, V0.S[2]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V19.4S, V19.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	mul	V21.4S, V5.4S, V2.S[3]
	mul	V22.4S, V6.4S, V2.S[3]
	sqrdmulh	V5.4S, V5.4S, V0.S[3]
	sqrdmulh	V6.4S, V6.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V22.4S, V22.4S, V4.S[0]
	sub	V5.4S, V5.4S, V21.4S
	sub	V6.4S, V6.4S, V22.4S
	sshr	V5.4S, V5.4S, #1
	sshr	V6.4S, V6.4S, #1
	mul	V21.4S, V7.4S, V2.S[3]
	mul	V22.4S, V8.4S, V2.S[3]
	sqrdmulh	V7.4S, V7.4S, V0.S[3]
	sqrdmulh	V8.4S, V8.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V22.4S, V22.4S, V4.S[0]
	sub	V7.4S, V7.4S, V21.4S
	sub	V8.4S, V8.4S, V22.4S
	sshr	V7.4S, V7.4S, #1
	sshr	V8.4S, V8.4S, #1
	mul	V21.4S, V9.4S, V2.S[3]
	mul	V22.4S, V10.4S, V2.S[3]
	sqrdmulh	V9.4S, V9.4S, V0.S[3]
	sqrdmulh	V10.4S, V10.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V22.4S, V22.4S, V4.S[0]
	sub	V9.4S, V9.4S, V21.4S
	sub	V10.4S, V10.4S, V22.4S
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	mul	V21.4S, V11.4S, V2.S[3]
	mul	V22.4S, V12.4S, V2.S[3]
	sqrdmulh	V11.4S, V11.4S, V0.S[3]
	sqrdmulh	V12.4S, V12.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V22.4S, V22.4S, V4.S[0]
	sub	V11.4S, V11.4S, V21.4S
	sub	V12.4S, V12.4S, V22.4S
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	str	Q5, [x0, #32]
	str	Q6, [x0, #96]
	str	Q7, [x0, #160]
	str	Q8, [x0, #224]
	str	Q9, [x0, #288]
	str	Q10, [x0, #352]
	str	Q11, [x0, #416]
	str	Q12, [x0, #480]
	str	Q13, [x0, #544]
	str	Q14, [x0, #608]
	str	Q15, [x0, #672]
	str	Q16, [x0, #736]
	str	Q17, [x0, #800]
	str	Q18, [x0, #864]
	str	Q19, [x0, #928]
	str	Q20, [x0, #992]
	ldr	Q5, [x0, #48]
	ldr	Q6, [x0, #112]
	ldr	Q7, [x0, #176]
	ldr	Q8, [x0, #240]
	ldr	Q9, [x0, #304]
	ldr	Q10, [x0, #368]
	ldr	Q11, [x0, #432]
	ldr	Q12, [x0, #496]
	ldr	Q13, [x0, #560]
	ldr	Q14, [x0, #624]
	ldr	Q15, [x0, #688]
	ldr	Q16, [x0, #752]
	ldr	Q17, [x0, #816]
	ldr	Q18, [x0, #880]
	ldr	Q19, [x0, #944]
	ldr	Q20, [x0, #1008]
	ldr	Q0, [x1, #1216]
	ldr	Q1, [x1, #1232]
	ldr	Q2, [x2, #1216]
	ldr	Q3, [x2, #1232]
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V6.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V6.4S, V6.4S, V21.4S
	sub	V8.4S, V8.4S, V23.4S
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V10.4S, V22.4S, V0.S[2]
	sqrdmulh	V12.4S, V24.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V10.4S, V10.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V3.S[0]
	mul	V23.4S, V24.4S, V3.S[1]
	sqrdmulh	V14.4S, V22.4S, V1.S[0]
	sqrdmulh	V16.4S, V24.4S, V1.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V14.4S, V14.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V3.S[2]
	mul	V23.4S, V24.4S, V3.S[3]
	sqrdmulh	V18.4S, V22.4S, V1.S[2]
	sqrdmulh	V20.4S, V24.4S, V1.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V18.4S, V18.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1248]
	ldr	Q2, [x2, #1248]
	sub	V22.4S, V5.4S, V7.4S
	sub	V24.4S, V6.4S, V8.4S
	add	V5.4S, V5.4S, V7.4S
	add	V6.4S, V6.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V7.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[0]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V7.4S, V7.4S, V21.4S
	sub	V8.4S, V8.4S, V23.4S
	sshr	V7.4S, V7.4S, #1
	sshr	V8.4S, V8.4S, #1
	sub	V22.4S, V9.4S, V11.4S
	sub	V24.4S, V10.4S, V12.4S
	add	V9.4S, V9.4S, V11.4S
	add	V10.4S, V10.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V11.4S, V22.4S, V0.S[1]
	sqrdmulh	V12.4S, V24.4S, V0.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V11.4S, V11.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V15.4S
	sub	V24.4S, V14.4S, V16.4S
	add	V13.4S, V13.4S, V15.4S
	add	V14.4S, V14.4S, V16.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V15.4S, V22.4S, V0.S[2]
	sqrdmulh	V16.4S, V24.4S, V0.S[2]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V15.4S, V15.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V15.4S, V15.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V17.4S, V19.4S
	sub	V24.4S, V18.4S, V20.4S
	add	V17.4S, V17.4S, V19.4S
	add	V18.4S, V18.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[3]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V19.4S, V22.4S, V0.S[3]
	sqrdmulh	V20.4S, V24.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V19.4S, V19.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1264]
	ldr	Q2, [x2, #1264]
	sub	V22.4S, V5.4S, V9.4S
	sub	V24.4S, V6.4S, V10.4S
	add	V5.4S, V5.4S, V9.4S
	add	V6.4S, V6.4S, V10.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V9.4S, V22.4S, V0.S[0]
	sqrdmulh	V10.4S, V24.4S, V0.S[0]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V9.4S, V9.4S, V21.4S
	sub	V10.4S, V10.4S, V23.4S
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	sub	V22.4S, V7.4S, V11.4S
	sub	V24.4S, V8.4S, V12.4S
	add	V7.4S, V7.4S, V11.4S
	add	V8.4S, V8.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V11.4S, V22.4S, V0.S[0]
	sqrdmulh	V12.4S, V24.4S, V0.S[0]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V11.4S, V11.4S, V21.4S
	sub	V12.4S, V12.4S, V23.4S
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V17.4S
	sub	V24.4S, V14.4S, V18.4S
	add	V13.4S, V13.4S, V17.4S
	add	V14.4S, V14.4S, V18.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V17.4S, V22.4S, V0.S[1]
	sqrdmulh	V18.4S, V24.4S, V0.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V17.4S, V17.4S, V21.4S
	sub	V18.4S, V18.4S, V23.4S
	sshr	V17.4S, V17.4S, #1
	sshr	V18.4S, V18.4S, #1
	sub	V22.4S, V15.4S, V19.4S
	sub	V24.4S, V16.4S, V20.4S
	add	V15.4S, V15.4S, V19.4S
	add	V16.4S, V16.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V19.4S, V22.4S, V0.S[1]
	sqrdmulh	V20.4S, V24.4S, V0.S[1]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V19.4S, V19.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	sub	V22.4S, V5.4S, V13.4S
	sub	V24.4S, V6.4S, V14.4S
	add	V5.4S, V5.4S, V13.4S
	add	V6.4S, V6.4S, V14.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V13.4S, V22.4S, V0.S[2]
	sqrdmulh	V14.4S, V24.4S, V0.S[2]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V13.4S, V13.4S, V21.4S
	sub	V14.4S, V14.4S, V23.4S
	sshr	V13.4S, V13.4S, #1
	sshr	V14.4S, V14.4S, #1
	sub	V22.4S, V7.4S, V15.4S
	sub	V24.4S, V8.4S, V16.4S
	add	V7.4S, V7.4S, V15.4S
	add	V8.4S, V8.4S, V16.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V15.4S, V22.4S, V0.S[2]
	sqrdmulh	V16.4S, V24.4S, V0.S[2]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V15.4S, V15.4S, V21.4S
	sub	V16.4S, V16.4S, V23.4S
	sshr	V15.4S, V15.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V9.4S, V17.4S
	sub	V24.4S, V10.4S, V18.4S
	add	V9.4S, V9.4S, V17.4S
	add	V10.4S, V10.4S, V18.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V17.4S, V22.4S, V0.S[2]
	sqrdmulh	V18.4S, V24.4S, V0.S[2]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V17.4S, V17.4S, V21.4S
	sub	V18.4S, V18.4S, V23.4S
	sshr	V17.4S, V17.4S, #1
	sshr	V18.4S, V18.4S, #1
	sub	V22.4S, V11.4S, V19.4S
	sub	V24.4S, V12.4S, V20.4S
	add	V11.4S, V11.4S, V19.4S
	add	V12.4S, V12.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V19.4S, V22.4S, V0.S[2]
	sqrdmulh	V20.4S, V24.4S, V0.S[2]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V23.4S, V23.4S, V4.S[0]
	sub	V19.4S, V19.4S, V21.4S
	sub	V20.4S, V20.4S, V23.4S
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	mul	V21.4S, V5.4S, V2.S[3]
	mul	V22.4S, V6.4S, V2.S[3]
	sqrdmulh	V5.4S, V5.4S, V0.S[3]
	sqrdmulh	V6.4S, V6.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V22.4S, V22.4S, V4.S[0]
	sub	V5.4S, V5.4S, V21.4S
	sub	V6.4S, V6.4S, V22.4S
	sshr	V5.4S, V5.4S, #1
	sshr	V6.4S, V6.4S, #1
	mul	V21.4S, V7.4S, V2.S[3]
	mul	V22.4S, V8.4S, V2.S[3]
	sqrdmulh	V7.4S, V7.4S, V0.S[3]
	sqrdmulh	V8.4S, V8.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V22.4S, V22.4S, V4.S[0]
	sub	V7.4S, V7.4S, V21.4S
	sub	V8.4S, V8.4S, V22.4S
	sshr	V7.4S, V7.4S, #1
	sshr	V8.4S, V8.4S, #1
	mul	V21.4S, V9.4S, V2.S[3]
	mul	V22.4S, V10.4S, V2.S[3]
	sqrdmulh	V9.4S, V9.4S, V0.S[3]
	sqrdmulh	V10.4S, V10.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V22.4S, V22.4S, V4.S[0]
	sub	V9.4S, V9.4S, V21.4S
	sub	V10.4S, V10.4S, V22.4S
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	mul	V21.4S, V11.4S, V2.S[3]
	mul	V22.4S, V12.4S, V2.S[3]
	sqrdmulh	V11.4S, V11.4S, V0.S[3]
	sqrdmulh	V12.4S, V12.4S, V0.S[3]
	sqrdmulh	V21.4S, V21.4S, V4.S[0]
	sqrdmulh	V22.4S, V22.4S, V4.S[0]
	sub	V11.4S, V11.4S, V21.4S
	sub	V12.4S, V12.4S, V22.4S
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	str	Q5, [x0, #48]
	str	Q6, [x0, #112]
	str	Q7, [x0, #176]
	str	Q8, [x0, #240]
	str	Q9, [x0, #304]
	str	Q10, [x0, #368]
	str	Q11, [x0, #432]
	str	Q12, [x0, #496]
	str	Q13, [x0, #560]
	str	Q14, [x0, #624]
	str	Q15, [x0, #688]
	str	Q16, [x0, #752]
	str	Q17, [x0, #816]
	str	Q18, [x0, #880]
	str	Q19, [x0, #944]
	str	Q20, [x0, #1008]
	ldp	D8, D9, [x29, #16]
	ldp	D10, D11, [x29, #32]
	ldp	D12, D13, [x29, #48]
	ldp	D14, D15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
	ENDP
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mldsa_mul_neon
mldsa_mul_neon PROC
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	stp	D10, D11, [x29, #32]
	stp	D12, D13, [x29, #48]
	stp	D14, D15, [x29, #64]
	adrp	x3, L_mldsa_aarch64_consts
	add	x3, x3, L_mldsa_aarch64_consts
	ldr	Q0, [x3]
	ldr	Q1, [x1]
	ldr	Q5, [x2]
	ldr	Q2, [x1, #16]
	ldr	Q6, [x2, #16]
	ldr	Q3, [x1, #32]
	ldr	Q7, [x2, #32]
	ldr	Q4, [x1, #48]
	ldr	Q8, [x2, #48]
	mul	V13.4S, V5.4S, V0.S[1]
	mul	V14.4S, V6.4S, V0.S[1]
	mul	V17.4S, V1.4S, V13.4S
	mul	V18.4S, V2.4S, V14.4S
	sqrdmulh	V9.4S, V1.4S, V5.4S
	sqrdmulh	V10.4S, V2.4S, V6.4S
	sqrdmulh	V17.4S, V17.4S, V0.S[0]
	sqrdmulh	V18.4S, V18.4S, V0.S[0]
	sub	V9.4S, V9.4S, V17.4S
	sub	V10.4S, V10.4S, V18.4S
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	mul	V15.4S, V7.4S, V0.S[1]
	mul	V16.4S, V8.4S, V0.S[1]
	mul	V17.4S, V3.4S, V15.4S
	mul	V18.4S, V4.4S, V16.4S
	sqrdmulh	V11.4S, V3.4S, V7.4S
	sqrdmulh	V12.4S, V4.4S, V8.4S
	sqrdmulh	V17.4S, V17.4S, V0.S[0]
	sqrdmulh	V18.4S, V18.4S, V0.S[0]
	sub	V11.4S, V11.4S, V17.4S
	sub	V12.4S, V12.4S, V18.4S
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	str	Q9, [x0]
	str	Q10, [x0, #16]
	str	Q11, [x0, #32]
	str	Q12, [x0, #48]
	ldr	Q1, [x1, #64]
	ldr	Q5, [x2, #64]
	ldr	Q2, [x1, #80]
	ldr	Q6, [x2, #80]
	ldr	Q3, [x1, #96]
	ldr	Q7, [x2, #96]
	ldr	Q4, [x1, #112]
	ldr	Q8, [x2, #112]
	mul	V13.4S, V5.4S, V0.S[1]
	mul	V14.4S, V6.4S, V0.S[1]
	mul	V17.4S, V1.4S, V13.4S
	mul	V18.4S, V2.4S, V14.4S
	sqrdmulh	V9.4S, V1.4S, V5.4S
	sqrdmulh	V10.4S, V2.4S, V6.4S
	sqrdmulh	V17.4S, V17.4S, V0.S[0]
	sqrdmulh	V18.4S, V18.4S, V0.S[0]
	sub	V9.4S, V9.4S, V17.4S
	sub	V10.4S, V10.4S, V18.4S
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	mul	V15.4S, V7.4S, V0.S[1]
	mul	V16.4S, V8.4S, V0.S[1]
	mul	V17.4S, V3.4S, V15.4S
	mul	V18.4S, V4.4S, V16.4S
	sqrdmulh	V11.4S, V3.4S, V7.4S
	sqrdmulh	V12.4S, V4.4S, V8.4S
	sqrdmulh	V17.4S, V17.4S, V0.S[0]
	sqrdmulh	V18.4S, V18.4S, V0.S[0]
	sub	V11.4S, V11.4S, V17.4S
	sub	V12.4S, V12.4S, V18.4S
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	str	Q9, [x0, #64]
	str	Q10, [x0, #80]
	str	Q11, [x0, #96]
	str	Q12, [x0, #112]
	ldr	Q1, [x1, #128]
	ldr	Q5, [x2, #128]
	ldr	Q2, [x1, #144]
	ldr	Q6, [x2, #144]
	ldr	Q3, [x1, #160]
	ldr	Q7, [x2, #160]
	ldr	Q4, [x1, #176]
	ldr	Q8, [x2, #176]
	mul	V13.4S, V5.4S, V0.S[1]
	mul	V14.4S, V6.4S, V0.S[1]
	mul	V17.4S, V1.4S, V13.4S
	mul	V18.4S, V2.4S, V14.4S
	sqrdmulh	V9.4S, V1.4S, V5.4S
	sqrdmulh	V10.4S, V2.4S, V6.4S
	sqrdmulh	V17.4S, V17.4S, V0.S[0]
	sqrdmulh	V18.4S, V18.4S, V0.S[0]
	sub	V9.4S, V9.4S, V17.4S
	sub	V10.4S, V10.4S, V18.4S
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	mul	V15.4S, V7.4S, V0.S[1]
	mul	V16.4S, V8.4S, V0.S[1]
	mul	V17.4S, V3.4S, V15.4S
	mul	V18.4S, V4.4S, V16.4S
	sqrdmulh	V11.4S, V3.4S, V7.4S
	sqrdmulh	V12.4S, V4.4S, V8.4S
	sqrdmulh	V17.4S, V17.4S, V0.S[0]
	sqrdmulh	V18.4S, V18.4S, V0.S[0]
	sub	V11.4S, V11.4S, V17.4S
	sub	V12.4S, V12.4S, V18.4S
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	str	Q9, [x0, #128]
	str	Q10, [x0, #144]
	str	Q11, [x0, #160]
	str	Q12, [x0, #176]
	ldr	Q1, [x1, #192]
	ldr	Q5, [x2, #192]
	ldr	Q2, [x1, #208]
	ldr	Q6, [x2, #208]
	ldr	Q3, [x1, #224]
	ldr	Q7, [x2, #224]
	ldr	Q4, [x1, #240]
	ldr	Q8, [x2, #240]
	mul	V13.4S, V5.4S, V0.S[1]
	mul	V14.4S, V6.4S, V0.S[1]
	mul	V17.4S, V1.4S, V13.4S
	mul	V18.4S, V2.4S, V14.4S
	sqrdmulh	V9.4S, V1.4S, V5.4S
	sqrdmulh	V10.4S, V2.4S, V6.4S
	sqrdmulh	V17.4S, V17.4S, V0.S[0]
	sqrdmulh	V18.4S, V18.4S, V0.S[0]
	sub	V9.4S, V9.4S, V17.4S
	sub	V10.4S, V10.4S, V18.4S
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	mul	V15.4S, V7.4S, V0.S[1]
	mul	V16.4S, V8.4S, V0.S[1]
	mul	V17.4S, V3.4S, V15.4S
	mul	V18.4S, V4.4S, V16.4S
	sqrdmulh	V11.4S, V3.4S, V7.4S
	sqrdmulh	V12.4S, V4.4S, V8.4S
	sqrdmulh	V17.4S, V17.4S, V0.S[0]
	sqrdmulh	V18.4S, V18.4S, V0.S[0]
	sub	V11.4S, V11.4S, V17.4S
	sub	V12.4S, V12.4S, V18.4S
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	str	Q9, [x0, #192]
	str	Q10, [x0, #208]
	str	Q11, [x0, #224]
	str	Q12, [x0, #240]
	ldr	Q1, [x1, #256]
	ldr	Q5, [x2, #256]
	ldr	Q2, [x1, #272]
	ldr	Q6, [x2, #272]
	ldr	Q3, [x1, #288]
	ldr	Q7, [x2, #288]
	ldr	Q4, [x1, #304]
	ldr	Q8, [x2, #304]
	mul	V13.4S, V5.4S, V0.S[1]
	mul	V14.4S, V6.4S, V0.S[1]
	mul	V17.4S, V1.4S, V13.4S
	mul	V18.4S, V2.4S, V14.4S
	sqrdmulh	V9.4S, V1.4S, V5.4S
	sqrdmulh	V10.4S, V2.4S, V6.4S
	sqrdmulh	V17.4S, V17.4S, V0.S[0]
	sqrdmulh	V18.4S, V18.4S, V0.S[0]
	sub	V9.4S, V9.4S, V17.4S
	sub	V10.4S, V10.4S, V18.4S
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	mul	V15.4S, V7.4S, V0.S[1]
	mul	V16.4S, V8.4S, V0.S[1]
	mul	V17.4S, V3.4S, V15.4S
	mul	V18.4S, V4.4S, V16.4S
	sqrdmulh	V11.4S, V3.4S, V7.4S
	sqrdmulh	V12.4S, V4.4S, V8.4S
	sqrdmulh	V17.4S, V17.4S, V0.S[0]
	sqrdmulh	V18.4S, V18.4S, V0.S[0]
	sub	V11.4S, V11.4S, V17.4S
	sub	V12.4S, V12.4S, V18.4S
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	str	Q9, [x0, #256]
	str	Q10, [x0, #272]
	str	Q11, [x0, #288]
	str	Q12, [x0, #304]
	ldr	Q1, [x1, #320]
	ldr	Q5, [x2, #320]
	ldr	Q2, [x1, #336]
	ldr	Q6, [x2, #336]
	ldr	Q3, [x1, #352]
	ldr	Q7, [x2, #352]
	ldr	Q4, [x1, #368]
	ldr	Q8, [x2, #368]
	mul	V13.4S, V5.4S, V0.S[1]
	mul	V14.4S, V6.4S, V0.S[1]
	mul	V17.4S, V1.4S, V13.4S
	mul	V18.4S, V2.4S, V14.4S
	sqrdmulh	V9.4S, V1.4S, V5.4S
	sqrdmulh	V10.4S, V2.4S, V6.4S
	sqrdmulh	V17.4S, V17.4S, V0.S[0]
	sqrdmulh	V18.4S, V18.4S, V0.S[0]
	sub	V9.4S, V9.4S, V17.4S
	sub	V10.4S, V10.4S, V18.4S
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	mul	V15.4S, V7.4S, V0.S[1]
	mul	V16.4S, V8.4S, V0.S[1]
	mul	V17.4S, V3.4S, V15.4S
	mul	V18.4S, V4.4S, V16.4S
	sqrdmulh	V11.4S, V3.4S, V7.4S
	sqrdmulh	V12.4S, V4.4S, V8.4S
	sqrdmulh	V17.4S, V17.4S, V0.S[0]
	sqrdmulh	V18.4S, V18.4S, V0.S[0]
	sub	V11.4S, V11.4S, V17.4S
	sub	V12.4S, V12.4S, V18.4S
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	str	Q9, [x0, #320]
	str	Q10, [x0, #336]
	str	Q11, [x0, #352]
	str	Q12, [x0, #368]
	ldr	Q1, [x1, #384]
	ldr	Q5, [x2, #384]
	ldr	Q2, [x1, #400]
	ldr	Q6, [x2, #400]
	ldr	Q3, [x1, #416]
	ldr	Q7, [x2, #416]
	ldr	Q4, [x1, #432]
	ldr	Q8, [x2, #432]
	mul	V13.4S, V5.4S, V0.S[1]
	mul	V14.4S, V6.4S, V0.S[1]
	mul	V17.4S, V1.4S, V13.4S
	mul	V18.4S, V2.4S, V14.4S
	sqrdmulh	V9.4S, V1.4S, V5.4S
	sqrdmulh	V10.4S, V2.4S, V6.4S
	sqrdmulh	V17.4S, V17.4S, V0.S[0]
	sqrdmulh	V18.4S, V18.4S, V0.S[0]
	sub	V9.4S, V9.4S, V17.4S
	sub	V10.4S, V10.4S, V18.4S
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	mul	V15.4S, V7.4S, V0.S[1]
	mul	V16.4S, V8.4S, V0.S[1]
	mul	V17.4S, V3.4S, V15.4S
	mul	V18.4S, V4.4S, V16.4S
	sqrdmulh	V11.4S, V3.4S, V7.4S
	sqrdmulh	V12.4S, V4.4S, V8.4S
	sqrdmulh	V17.4S, V17.4S, V0.S[0]
	sqrdmulh	V18.4S, V18.4S, V0.S[0]
	sub	V11.4S, V11.4S, V17.4S
	sub	V12.4S, V12.4S, V18.4S
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	str	Q9, [x0, #384]
	str	Q10, [x0, #400]
	str	Q11, [x0, #416]
	str	Q12, [x0, #432]
	ldr	Q1, [x1, #448]
	ldr	Q5, [x2, #448]
	ldr	Q2, [x1, #464]
	ldr	Q6, [x2, #464]
	ldr	Q3, [x1, #480]
	ldr	Q7, [x2, #480]
	ldr	Q4, [x1, #496]
	ldr	Q8, [x2, #496]
	mul	V13.4S, V5.4S, V0.S[1]
	mul	V14.4S, V6.4S, V0.S[1]
	mul	V17.4S, V1.4S, V13.4S
	mul	V18.4S, V2.4S, V14.4S
	sqrdmulh	V9.4S, V1.4S, V5.4S
	sqrdmulh	V10.4S, V2.4S, V6.4S
	sqrdmulh	V17.4S, V17.4S, V0.S[0]
	sqrdmulh	V18.4S, V18.4S, V0.S[0]
	sub	V9.4S, V9.4S, V17.4S
	sub	V10.4S, V10.4S, V18.4S
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	mul	V15.4S, V7.4S, V0.S[1]
	mul	V16.4S, V8.4S, V0.S[1]
	mul	V17.4S, V3.4S, V15.4S
	mul	V18.4S, V4.4S, V16.4S
	sqrdmulh	V11.4S, V3.4S, V7.4S
	sqrdmulh	V12.4S, V4.4S, V8.4S
	sqrdmulh	V17.4S, V17.4S, V0.S[0]
	sqrdmulh	V18.4S, V18.4S, V0.S[0]
	sub	V11.4S, V11.4S, V17.4S
	sub	V12.4S, V12.4S, V18.4S
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	str	Q9, [x0, #448]
	str	Q10, [x0, #464]
	str	Q11, [x0, #480]
	str	Q12, [x0, #496]
	ldr	Q1, [x1, #512]
	ldr	Q5, [x2, #512]
	ldr	Q2, [x1, #528]
	ldr	Q6, [x2, #528]
	ldr	Q3, [x1, #544]
	ldr	Q7, [x2, #544]
	ldr	Q4, [x1, #560]
	ldr	Q8, [x2, #560]
	mul	V13.4S, V5.4S, V0.S[1]
	mul	V14.4S, V6.4S, V0.S[1]
	mul	V17.4S, V1.4S, V13.4S
	mul	V18.4S, V2.4S, V14.4S
	sqrdmulh	V9.4S, V1.4S, V5.4S
	sqrdmulh	V10.4S, V2.4S, V6.4S
	sqrdmulh	V17.4S, V17.4S, V0.S[0]
	sqrdmulh	V18.4S, V18.4S, V0.S[0]
	sub	V9.4S, V9.4S, V17.4S
	sub	V10.4S, V10.4S, V18.4S
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	mul	V15.4S, V7.4S, V0.S[1]
	mul	V16.4S, V8.4S, V0.S[1]
	mul	V17.4S, V3.4S, V15.4S
	mul	V18.4S, V4.4S, V16.4S
	sqrdmulh	V11.4S, V3.4S, V7.4S
	sqrdmulh	V12.4S, V4.4S, V8.4S
	sqrdmulh	V17.4S, V17.4S, V0.S[0]
	sqrdmulh	V18.4S, V18.4S, V0.S[0]
	sub	V11.4S, V11.4S, V17.4S
	sub	V12.4S, V12.4S, V18.4S
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	str	Q9, [x0, #512]
	str	Q10, [x0, #528]
	str	Q11, [x0, #544]
	str	Q12, [x0, #560]
	ldr	Q1, [x1, #576]
	ldr	Q5, [x2, #576]
	ldr	Q2, [x1, #592]
	ldr	Q6, [x2, #592]
	ldr	Q3, [x1, #608]
	ldr	Q7, [x2, #608]
	ldr	Q4, [x1, #624]
	ldr	Q8, [x2, #624]
	mul	V13.4S, V5.4S, V0.S[1]
	mul	V14.4S, V6.4S, V0.S[1]
	mul	V17.4S, V1.4S, V13.4S
	mul	V18.4S, V2.4S, V14.4S
	sqrdmulh	V9.4S, V1.4S, V5.4S
	sqrdmulh	V10.4S, V2.4S, V6.4S
	sqrdmulh	V17.4S, V17.4S, V0.S[0]
	sqrdmulh	V18.4S, V18.4S, V0.S[0]
	sub	V9.4S, V9.4S, V17.4S
	sub	V10.4S, V10.4S, V18.4S
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	mul	V15.4S, V7.4S, V0.S[1]
	mul	V16.4S, V8.4S, V0.S[1]
	mul	V17.4S, V3.4S, V15.4S
	mul	V18.4S, V4.4S, V16.4S
	sqrdmulh	V11.4S, V3.4S, V7.4S
	sqrdmulh	V12.4S, V4.4S, V8.4S
	sqrdmulh	V17.4S, V17.4S, V0.S[0]
	sqrdmulh	V18.4S, V18.4S, V0.S[0]
	sub	V11.4S, V11.4S, V17.4S
	sub	V12.4S, V12.4S, V18.4S
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	str	Q9, [x0, #576]
	str	Q10, [x0, #592]
	str	Q11, [x0, #608]
	str	Q12, [x0, #624]
	ldr	Q1, [x1, #640]
	ldr	Q5, [x2, #640]
	ldr	Q2, [x1, #656]
	ldr	Q6, [x2, #656]
	ldr	Q3, [x1, #672]
	ldr	Q7, [x2, #672]
	ldr	Q4, [x1, #688]
	ldr	Q8, [x2, #688]
	mul	V13.4S, V5.4S, V0.S[1]
	mul	V14.4S, V6.4S, V0.S[1]
	mul	V17.4S, V1.4S, V13.4S
	mul	V18.4S, V2.4S, V14.4S
	sqrdmulh	V9.4S, V1.4S, V5.4S
	sqrdmulh	V10.4S, V2.4S, V6.4S
	sqrdmulh	V17.4S, V17.4S, V0.S[0]
	sqrdmulh	V18.4S, V18.4S, V0.S[0]
	sub	V9.4S, V9.4S, V17.4S
	sub	V10.4S, V10.4S, V18.4S
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	mul	V15.4S, V7.4S, V0.S[1]
	mul	V16.4S, V8.4S, V0.S[1]
	mul	V17.4S, V3.4S, V15.4S
	mul	V18.4S, V4.4S, V16.4S
	sqrdmulh	V11.4S, V3.4S, V7.4S
	sqrdmulh	V12.4S, V4.4S, V8.4S
	sqrdmulh	V17.4S, V17.4S, V0.S[0]
	sqrdmulh	V18.4S, V18.4S, V0.S[0]
	sub	V11.4S, V11.4S, V17.4S
	sub	V12.4S, V12.4S, V18.4S
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	str	Q9, [x0, #640]
	str	Q10, [x0, #656]
	str	Q11, [x0, #672]
	str	Q12, [x0, #688]
	ldr	Q1, [x1, #704]
	ldr	Q5, [x2, #704]
	ldr	Q2, [x1, #720]
	ldr	Q6, [x2, #720]
	ldr	Q3, [x1, #736]
	ldr	Q7, [x2, #736]
	ldr	Q4, [x1, #752]
	ldr	Q8, [x2, #752]
	mul	V13.4S, V5.4S, V0.S[1]
	mul	V14.4S, V6.4S, V0.S[1]
	mul	V17.4S, V1.4S, V13.4S
	mul	V18.4S, V2.4S, V14.4S
	sqrdmulh	V9.4S, V1.4S, V5.4S
	sqrdmulh	V10.4S, V2.4S, V6.4S
	sqrdmulh	V17.4S, V17.4S, V0.S[0]
	sqrdmulh	V18.4S, V18.4S, V0.S[0]
	sub	V9.4S, V9.4S, V17.4S
	sub	V10.4S, V10.4S, V18.4S
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	mul	V15.4S, V7.4S, V0.S[1]
	mul	V16.4S, V8.4S, V0.S[1]
	mul	V17.4S, V3.4S, V15.4S
	mul	V18.4S, V4.4S, V16.4S
	sqrdmulh	V11.4S, V3.4S, V7.4S
	sqrdmulh	V12.4S, V4.4S, V8.4S
	sqrdmulh	V17.4S, V17.4S, V0.S[0]
	sqrdmulh	V18.4S, V18.4S, V0.S[0]
	sub	V11.4S, V11.4S, V17.4S
	sub	V12.4S, V12.4S, V18.4S
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	str	Q9, [x0, #704]
	str	Q10, [x0, #720]
	str	Q11, [x0, #736]
	str	Q12, [x0, #752]
	ldr	Q1, [x1, #768]
	ldr	Q5, [x2, #768]
	ldr	Q2, [x1, #784]
	ldr	Q6, [x2, #784]
	ldr	Q3, [x1, #800]
	ldr	Q7, [x2, #800]
	ldr	Q4, [x1, #816]
	ldr	Q8, [x2, #816]
	mul	V13.4S, V5.4S, V0.S[1]
	mul	V14.4S, V6.4S, V0.S[1]
	mul	V17.4S, V1.4S, V13.4S
	mul	V18.4S, V2.4S, V14.4S
	sqrdmulh	V9.4S, V1.4S, V5.4S
	sqrdmulh	V10.4S, V2.4S, V6.4S
	sqrdmulh	V17.4S, V17.4S, V0.S[0]
	sqrdmulh	V18.4S, V18.4S, V0.S[0]
	sub	V9.4S, V9.4S, V17.4S
	sub	V10.4S, V10.4S, V18.4S
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	mul	V15.4S, V7.4S, V0.S[1]
	mul	V16.4S, V8.4S, V0.S[1]
	mul	V17.4S, V3.4S, V15.4S
	mul	V18.4S, V4.4S, V16.4S
	sqrdmulh	V11.4S, V3.4S, V7.4S
	sqrdmulh	V12.4S, V4.4S, V8.4S
	sqrdmulh	V17.4S, V17.4S, V0.S[0]
	sqrdmulh	V18.4S, V18.4S, V0.S[0]
	sub	V11.4S, V11.4S, V17.4S
	sub	V12.4S, V12.4S, V18.4S
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	str	Q9, [x0, #768]
	str	Q10, [x0, #784]
	str	Q11, [x0, #800]
	str	Q12, [x0, #816]
	ldr	Q1, [x1, #832]
	ldr	Q5, [x2, #832]
	ldr	Q2, [x1, #848]
	ldr	Q6, [x2, #848]
	ldr	Q3, [x1, #864]
	ldr	Q7, [x2, #864]
	ldr	Q4, [x1, #880]
	ldr	Q8, [x2, #880]
	mul	V13.4S, V5.4S, V0.S[1]
	mul	V14.4S, V6.4S, V0.S[1]
	mul	V17.4S, V1.4S, V13.4S
	mul	V18.4S, V2.4S, V14.4S
	sqrdmulh	V9.4S, V1.4S, V5.4S
	sqrdmulh	V10.4S, V2.4S, V6.4S
	sqrdmulh	V17.4S, V17.4S, V0.S[0]
	sqrdmulh	V18.4S, V18.4S, V0.S[0]
	sub	V9.4S, V9.4S, V17.4S
	sub	V10.4S, V10.4S, V18.4S
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	mul	V15.4S, V7.4S, V0.S[1]
	mul	V16.4S, V8.4S, V0.S[1]
	mul	V17.4S, V3.4S, V15.4S
	mul	V18.4S, V4.4S, V16.4S
	sqrdmulh	V11.4S, V3.4S, V7.4S
	sqrdmulh	V12.4S, V4.4S, V8.4S
	sqrdmulh	V17.4S, V17.4S, V0.S[0]
	sqrdmulh	V18.4S, V18.4S, V0.S[0]
	sub	V11.4S, V11.4S, V17.4S
	sub	V12.4S, V12.4S, V18.4S
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	str	Q9, [x0, #832]
	str	Q10, [x0, #848]
	str	Q11, [x0, #864]
	str	Q12, [x0, #880]
	ldr	Q1, [x1, #896]
	ldr	Q5, [x2, #896]
	ldr	Q2, [x1, #912]
	ldr	Q6, [x2, #912]
	ldr	Q3, [x1, #928]
	ldr	Q7, [x2, #928]
	ldr	Q4, [x1, #944]
	ldr	Q8, [x2, #944]
	mul	V13.4S, V5.4S, V0.S[1]
	mul	V14.4S, V6.4S, V0.S[1]
	mul	V17.4S, V1.4S, V13.4S
	mul	V18.4S, V2.4S, V14.4S
	sqrdmulh	V9.4S, V1.4S, V5.4S
	sqrdmulh	V10.4S, V2.4S, V6.4S
	sqrdmulh	V17.4S, V17.4S, V0.S[0]
	sqrdmulh	V18.4S, V18.4S, V0.S[0]
	sub	V9.4S, V9.4S, V17.4S
	sub	V10.4S, V10.4S, V18.4S
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	mul	V15.4S, V7.4S, V0.S[1]
	mul	V16.4S, V8.4S, V0.S[1]
	mul	V17.4S, V3.4S, V15.4S
	mul	V18.4S, V4.4S, V16.4S
	sqrdmulh	V11.4S, V3.4S, V7.4S
	sqrdmulh	V12.4S, V4.4S, V8.4S
	sqrdmulh	V17.4S, V17.4S, V0.S[0]
	sqrdmulh	V18.4S, V18.4S, V0.S[0]
	sub	V11.4S, V11.4S, V17.4S
	sub	V12.4S, V12.4S, V18.4S
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	str	Q9, [x0, #896]
	str	Q10, [x0, #912]
	str	Q11, [x0, #928]
	str	Q12, [x0, #944]
	ldr	Q1, [x1, #960]
	ldr	Q5, [x2, #960]
	ldr	Q2, [x1, #976]
	ldr	Q6, [x2, #976]
	ldr	Q3, [x1, #992]
	ldr	Q7, [x2, #992]
	ldr	Q4, [x1, #1008]
	ldr	Q8, [x2, #1008]
	mul	V13.4S, V5.4S, V0.S[1]
	mul	V14.4S, V6.4S, V0.S[1]
	mul	V17.4S, V1.4S, V13.4S
	mul	V18.4S, V2.4S, V14.4S
	sqrdmulh	V9.4S, V1.4S, V5.4S
	sqrdmulh	V10.4S, V2.4S, V6.4S
	sqrdmulh	V17.4S, V17.4S, V0.S[0]
	sqrdmulh	V18.4S, V18.4S, V0.S[0]
	sub	V9.4S, V9.4S, V17.4S
	sub	V10.4S, V10.4S, V18.4S
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	mul	V15.4S, V7.4S, V0.S[1]
	mul	V16.4S, V8.4S, V0.S[1]
	mul	V17.4S, V3.4S, V15.4S
	mul	V18.4S, V4.4S, V16.4S
	sqrdmulh	V11.4S, V3.4S, V7.4S
	sqrdmulh	V12.4S, V4.4S, V8.4S
	sqrdmulh	V17.4S, V17.4S, V0.S[0]
	sqrdmulh	V18.4S, V18.4S, V0.S[0]
	sub	V11.4S, V11.4S, V17.4S
	sub	V12.4S, V12.4S, V18.4S
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	str	Q9, [x0, #960]
	str	Q10, [x0, #976]
	str	Q11, [x0, #992]
	str	Q12, [x0, #1008]
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
	EXPORT	mldsa_ntt_sqrdmlsh_neon
mldsa_ntt_sqrdmlsh_neon PROC
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	stp	D10, D11, [x29, #32]
	stp	D12, D13, [x29, #48]
	stp	D14, D15, [x29, #64]
	adrp	x1, L_mldsa_aarch64_zetas
	add	x1, x1, L_mldsa_aarch64_zetas
	adrp	x2, L_mldsa_aarch64_zetas_qinv
	add	x2, x2, L_mldsa_aarch64_zetas_qinv
	adrp	x3, L_mldsa_aarch64_consts
	add	x3, x3, L_mldsa_aarch64_consts
	ldr	Q4, [x3]
	ldr	Q5, [x0]
	ldr	Q6, [x0, #64]
	ldr	Q7, [x0, #128]
	ldr	Q8, [x0, #192]
	ldr	Q9, [x0, #256]
	ldr	Q10, [x0, #320]
	ldr	Q11, [x0, #384]
	ldr	Q12, [x0, #448]
	ldr	Q13, [x0, #512]
	ldr	Q14, [x0, #576]
	ldr	Q15, [x0, #640]
	ldr	Q16, [x0, #704]
	ldr	Q17, [x0, #768]
	ldr	Q18, [x0, #832]
	ldr	Q19, [x0, #896]
	ldr	Q20, [x0, #960]
	ldr	Q0, [x1]
	ldr	Q1, [x2]
	mul	V29.4S, V13.4S, V1.S[1]
	mul	V30.4S, V14.4S, V1.S[1]
	sqrdmulh	V21.4S, V13.4S, V0.S[1]
	sqrdmulh	V22.4S, V14.4S, V0.S[1]
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V15.4S, V1.S[1]
	mul	V30.4S, V16.4S, V1.S[1]
	sqrdmulh	V23.4S, V15.4S, V0.S[1]
	sqrdmulh	V24.4S, V16.4S, V0.S[1]
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V17.4S, V1.S[1]
	mul	V30.4S, V18.4S, V1.S[1]
	sqrdmulh	V25.4S, V17.4S, V0.S[1]
	sqrdmulh	V26.4S, V18.4S, V0.S[1]
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[1]
	mul	V30.4S, V20.4S, V1.S[1]
	sqrdmulh	V27.4S, V19.4S, V0.S[1]
	sqrdmulh	V28.4S, V20.4S, V0.S[1]
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V13.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V14.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V15.4S, V7.4S, V23.4S
	add	V7.4S, V7.4S, V23.4S
	sub	V16.4S, V8.4S, V24.4S
	add	V8.4S, V8.4S, V24.4S
	sub	V17.4S, V9.4S, V25.4S
	add	V9.4S, V9.4S, V25.4S
	sub	V18.4S, V10.4S, V26.4S
	add	V10.4S, V10.4S, V26.4S
	sub	V19.4S, V11.4S, V27.4S
	add	V11.4S, V11.4S, V27.4S
	sub	V20.4S, V12.4S, V28.4S
	add	V12.4S, V12.4S, V28.4S
	mul	V29.4S, V9.4S, V1.S[2]
	mul	V30.4S, V10.4S, V1.S[2]
	sqrdmulh	V21.4S, V9.4S, V0.S[2]
	sqrdmulh	V22.4S, V10.4S, V0.S[2]
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V11.4S, V1.S[2]
	mul	V30.4S, V12.4S, V1.S[2]
	sqrdmulh	V23.4S, V11.4S, V0.S[2]
	sqrdmulh	V24.4S, V12.4S, V0.S[2]
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V17.4S, V1.S[3]
	mul	V30.4S, V18.4S, V1.S[3]
	sqrdmulh	V25.4S, V17.4S, V0.S[3]
	sqrdmulh	V26.4S, V18.4S, V0.S[3]
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[3]
	mul	V30.4S, V20.4S, V1.S[3]
	sqrdmulh	V27.4S, V19.4S, V0.S[3]
	sqrdmulh	V28.4S, V20.4S, V0.S[3]
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V9.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V10.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V11.4S, V7.4S, V23.4S
	add	V7.4S, V7.4S, V23.4S
	sub	V12.4S, V8.4S, V24.4S
	add	V8.4S, V8.4S, V24.4S
	sub	V17.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V18.4S, V14.4S, V26.4S
	add	V14.4S, V14.4S, V26.4S
	sub	V19.4S, V15.4S, V27.4S
	add	V15.4S, V15.4S, V27.4S
	sub	V20.4S, V16.4S, V28.4S
	add	V16.4S, V16.4S, V28.4S
	ldr	Q0, [x1, #16]
	ldr	Q1, [x2, #16]
	mul	V29.4S, V7.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[0]
	sqrdmulh	V21.4S, V7.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[0]
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V11.4S, V1.S[1]
	mul	V30.4S, V12.4S, V1.S[1]
	sqrdmulh	V23.4S, V11.4S, V0.S[1]
	sqrdmulh	V24.4S, V12.4S, V0.S[1]
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V15.4S, V1.S[2]
	mul	V30.4S, V16.4S, V1.S[2]
	sqrdmulh	V25.4S, V15.4S, V0.S[2]
	sqrdmulh	V26.4S, V16.4S, V0.S[2]
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[3]
	mul	V30.4S, V20.4S, V1.S[3]
	sqrdmulh	V27.4S, V19.4S, V0.S[3]
	sqrdmulh	V28.4S, V20.4S, V0.S[3]
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V7.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V11.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V10.4S, V24.4S
	add	V10.4S, V10.4S, V24.4S
	sub	V15.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V14.4S, V26.4S
	add	V14.4S, V14.4S, V26.4S
	sub	V19.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V18.4S, V28.4S
	add	V18.4S, V18.4S, V28.4S
	ldp	Q0, Q2, [x1, #32]
	ldp	Q1, Q3, [x2, #32]
	mul	V29.4S, V6.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[1]
	sqrdmulh	V21.4S, V6.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[1]
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V10.4S, V1.S[2]
	mul	V30.4S, V12.4S, V1.S[3]
	sqrdmulh	V23.4S, V10.4S, V0.S[2]
	sqrdmulh	V24.4S, V12.4S, V0.S[3]
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V14.4S, V3.S[0]
	mul	V30.4S, V16.4S, V3.S[1]
	sqrdmulh	V25.4S, V14.4S, V2.S[0]
	sqrdmulh	V26.4S, V16.4S, V2.S[1]
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V18.4S, V3.S[2]
	mul	V30.4S, V20.4S, V3.S[3]
	sqrdmulh	V27.4S, V18.4S, V2.S[2]
	sqrdmulh	V28.4S, V20.4S, V2.S[3]
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	str	Q5, [x0]
	str	Q6, [x0, #64]
	str	Q7, [x0, #128]
	str	Q8, [x0, #192]
	str	Q9, [x0, #256]
	str	Q10, [x0, #320]
	str	Q11, [x0, #384]
	str	Q12, [x0, #448]
	str	Q13, [x0, #512]
	str	Q14, [x0, #576]
	str	Q15, [x0, #640]
	str	Q16, [x0, #704]
	str	Q17, [x0, #768]
	str	Q18, [x0, #832]
	str	Q19, [x0, #896]
	str	Q20, [x0, #960]
	ldr	Q5, [x0, #16]
	ldr	Q6, [x0, #80]
	ldr	Q7, [x0, #144]
	ldr	Q8, [x0, #208]
	ldr	Q9, [x0, #272]
	ldr	Q10, [x0, #336]
	ldr	Q11, [x0, #400]
	ldr	Q12, [x0, #464]
	ldr	Q13, [x0, #528]
	ldr	Q14, [x0, #592]
	ldr	Q15, [x0, #656]
	ldr	Q16, [x0, #720]
	ldr	Q17, [x0, #784]
	ldr	Q18, [x0, #848]
	ldr	Q19, [x0, #912]
	ldr	Q20, [x0, #976]
	ldr	Q0, [x1]
	ldr	Q1, [x2]
	mul	V29.4S, V13.4S, V1.S[1]
	mul	V30.4S, V14.4S, V1.S[1]
	sqrdmulh	V21.4S, V13.4S, V0.S[1]
	sqrdmulh	V22.4S, V14.4S, V0.S[1]
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V15.4S, V1.S[1]
	mul	V30.4S, V16.4S, V1.S[1]
	sqrdmulh	V23.4S, V15.4S, V0.S[1]
	sqrdmulh	V24.4S, V16.4S, V0.S[1]
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V17.4S, V1.S[1]
	mul	V30.4S, V18.4S, V1.S[1]
	sqrdmulh	V25.4S, V17.4S, V0.S[1]
	sqrdmulh	V26.4S, V18.4S, V0.S[1]
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[1]
	mul	V30.4S, V20.4S, V1.S[1]
	sqrdmulh	V27.4S, V19.4S, V0.S[1]
	sqrdmulh	V28.4S, V20.4S, V0.S[1]
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V13.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V14.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V15.4S, V7.4S, V23.4S
	add	V7.4S, V7.4S, V23.4S
	sub	V16.4S, V8.4S, V24.4S
	add	V8.4S, V8.4S, V24.4S
	sub	V17.4S, V9.4S, V25.4S
	add	V9.4S, V9.4S, V25.4S
	sub	V18.4S, V10.4S, V26.4S
	add	V10.4S, V10.4S, V26.4S
	sub	V19.4S, V11.4S, V27.4S
	add	V11.4S, V11.4S, V27.4S
	sub	V20.4S, V12.4S, V28.4S
	add	V12.4S, V12.4S, V28.4S
	mul	V29.4S, V9.4S, V1.S[2]
	mul	V30.4S, V10.4S, V1.S[2]
	sqrdmulh	V21.4S, V9.4S, V0.S[2]
	sqrdmulh	V22.4S, V10.4S, V0.S[2]
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V11.4S, V1.S[2]
	mul	V30.4S, V12.4S, V1.S[2]
	sqrdmulh	V23.4S, V11.4S, V0.S[2]
	sqrdmulh	V24.4S, V12.4S, V0.S[2]
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V17.4S, V1.S[3]
	mul	V30.4S, V18.4S, V1.S[3]
	sqrdmulh	V25.4S, V17.4S, V0.S[3]
	sqrdmulh	V26.4S, V18.4S, V0.S[3]
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[3]
	mul	V30.4S, V20.4S, V1.S[3]
	sqrdmulh	V27.4S, V19.4S, V0.S[3]
	sqrdmulh	V28.4S, V20.4S, V0.S[3]
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V9.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V10.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V11.4S, V7.4S, V23.4S
	add	V7.4S, V7.4S, V23.4S
	sub	V12.4S, V8.4S, V24.4S
	add	V8.4S, V8.4S, V24.4S
	sub	V17.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V18.4S, V14.4S, V26.4S
	add	V14.4S, V14.4S, V26.4S
	sub	V19.4S, V15.4S, V27.4S
	add	V15.4S, V15.4S, V27.4S
	sub	V20.4S, V16.4S, V28.4S
	add	V16.4S, V16.4S, V28.4S
	ldr	Q0, [x1, #16]
	ldr	Q1, [x2, #16]
	mul	V29.4S, V7.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[0]
	sqrdmulh	V21.4S, V7.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[0]
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V11.4S, V1.S[1]
	mul	V30.4S, V12.4S, V1.S[1]
	sqrdmulh	V23.4S, V11.4S, V0.S[1]
	sqrdmulh	V24.4S, V12.4S, V0.S[1]
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V15.4S, V1.S[2]
	mul	V30.4S, V16.4S, V1.S[2]
	sqrdmulh	V25.4S, V15.4S, V0.S[2]
	sqrdmulh	V26.4S, V16.4S, V0.S[2]
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[3]
	mul	V30.4S, V20.4S, V1.S[3]
	sqrdmulh	V27.4S, V19.4S, V0.S[3]
	sqrdmulh	V28.4S, V20.4S, V0.S[3]
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V7.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V11.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V10.4S, V24.4S
	add	V10.4S, V10.4S, V24.4S
	sub	V15.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V14.4S, V26.4S
	add	V14.4S, V14.4S, V26.4S
	sub	V19.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V18.4S, V28.4S
	add	V18.4S, V18.4S, V28.4S
	ldp	Q0, Q2, [x1, #32]
	ldp	Q1, Q3, [x2, #32]
	mul	V29.4S, V6.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[1]
	sqrdmulh	V21.4S, V6.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[1]
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V10.4S, V1.S[2]
	mul	V30.4S, V12.4S, V1.S[3]
	sqrdmulh	V23.4S, V10.4S, V0.S[2]
	sqrdmulh	V24.4S, V12.4S, V0.S[3]
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V14.4S, V3.S[0]
	mul	V30.4S, V16.4S, V3.S[1]
	sqrdmulh	V25.4S, V14.4S, V2.S[0]
	sqrdmulh	V26.4S, V16.4S, V2.S[1]
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V18.4S, V3.S[2]
	mul	V30.4S, V20.4S, V3.S[3]
	sqrdmulh	V27.4S, V18.4S, V2.S[2]
	sqrdmulh	V28.4S, V20.4S, V2.S[3]
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	str	Q5, [x0, #16]
	str	Q6, [x0, #80]
	str	Q7, [x0, #144]
	str	Q8, [x0, #208]
	str	Q9, [x0, #272]
	str	Q10, [x0, #336]
	str	Q11, [x0, #400]
	str	Q12, [x0, #464]
	str	Q13, [x0, #528]
	str	Q14, [x0, #592]
	str	Q15, [x0, #656]
	str	Q16, [x0, #720]
	str	Q17, [x0, #784]
	str	Q18, [x0, #848]
	str	Q19, [x0, #912]
	str	Q20, [x0, #976]
	ldr	Q5, [x0, #32]
	ldr	Q6, [x0, #96]
	ldr	Q7, [x0, #160]
	ldr	Q8, [x0, #224]
	ldr	Q9, [x0, #288]
	ldr	Q10, [x0, #352]
	ldr	Q11, [x0, #416]
	ldr	Q12, [x0, #480]
	ldr	Q13, [x0, #544]
	ldr	Q14, [x0, #608]
	ldr	Q15, [x0, #672]
	ldr	Q16, [x0, #736]
	ldr	Q17, [x0, #800]
	ldr	Q18, [x0, #864]
	ldr	Q19, [x0, #928]
	ldr	Q20, [x0, #992]
	ldr	Q0, [x1]
	ldr	Q1, [x2]
	mul	V29.4S, V13.4S, V1.S[1]
	mul	V30.4S, V14.4S, V1.S[1]
	sqrdmulh	V21.4S, V13.4S, V0.S[1]
	sqrdmulh	V22.4S, V14.4S, V0.S[1]
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V15.4S, V1.S[1]
	mul	V30.4S, V16.4S, V1.S[1]
	sqrdmulh	V23.4S, V15.4S, V0.S[1]
	sqrdmulh	V24.4S, V16.4S, V0.S[1]
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V17.4S, V1.S[1]
	mul	V30.4S, V18.4S, V1.S[1]
	sqrdmulh	V25.4S, V17.4S, V0.S[1]
	sqrdmulh	V26.4S, V18.4S, V0.S[1]
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[1]
	mul	V30.4S, V20.4S, V1.S[1]
	sqrdmulh	V27.4S, V19.4S, V0.S[1]
	sqrdmulh	V28.4S, V20.4S, V0.S[1]
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V13.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V14.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V15.4S, V7.4S, V23.4S
	add	V7.4S, V7.4S, V23.4S
	sub	V16.4S, V8.4S, V24.4S
	add	V8.4S, V8.4S, V24.4S
	sub	V17.4S, V9.4S, V25.4S
	add	V9.4S, V9.4S, V25.4S
	sub	V18.4S, V10.4S, V26.4S
	add	V10.4S, V10.4S, V26.4S
	sub	V19.4S, V11.4S, V27.4S
	add	V11.4S, V11.4S, V27.4S
	sub	V20.4S, V12.4S, V28.4S
	add	V12.4S, V12.4S, V28.4S
	mul	V29.4S, V9.4S, V1.S[2]
	mul	V30.4S, V10.4S, V1.S[2]
	sqrdmulh	V21.4S, V9.4S, V0.S[2]
	sqrdmulh	V22.4S, V10.4S, V0.S[2]
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V11.4S, V1.S[2]
	mul	V30.4S, V12.4S, V1.S[2]
	sqrdmulh	V23.4S, V11.4S, V0.S[2]
	sqrdmulh	V24.4S, V12.4S, V0.S[2]
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V17.4S, V1.S[3]
	mul	V30.4S, V18.4S, V1.S[3]
	sqrdmulh	V25.4S, V17.4S, V0.S[3]
	sqrdmulh	V26.4S, V18.4S, V0.S[3]
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[3]
	mul	V30.4S, V20.4S, V1.S[3]
	sqrdmulh	V27.4S, V19.4S, V0.S[3]
	sqrdmulh	V28.4S, V20.4S, V0.S[3]
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V9.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V10.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V11.4S, V7.4S, V23.4S
	add	V7.4S, V7.4S, V23.4S
	sub	V12.4S, V8.4S, V24.4S
	add	V8.4S, V8.4S, V24.4S
	sub	V17.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V18.4S, V14.4S, V26.4S
	add	V14.4S, V14.4S, V26.4S
	sub	V19.4S, V15.4S, V27.4S
	add	V15.4S, V15.4S, V27.4S
	sub	V20.4S, V16.4S, V28.4S
	add	V16.4S, V16.4S, V28.4S
	ldr	Q0, [x1, #16]
	ldr	Q1, [x2, #16]
	mul	V29.4S, V7.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[0]
	sqrdmulh	V21.4S, V7.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[0]
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V11.4S, V1.S[1]
	mul	V30.4S, V12.4S, V1.S[1]
	sqrdmulh	V23.4S, V11.4S, V0.S[1]
	sqrdmulh	V24.4S, V12.4S, V0.S[1]
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V15.4S, V1.S[2]
	mul	V30.4S, V16.4S, V1.S[2]
	sqrdmulh	V25.4S, V15.4S, V0.S[2]
	sqrdmulh	V26.4S, V16.4S, V0.S[2]
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[3]
	mul	V30.4S, V20.4S, V1.S[3]
	sqrdmulh	V27.4S, V19.4S, V0.S[3]
	sqrdmulh	V28.4S, V20.4S, V0.S[3]
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V7.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V11.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V10.4S, V24.4S
	add	V10.4S, V10.4S, V24.4S
	sub	V15.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V14.4S, V26.4S
	add	V14.4S, V14.4S, V26.4S
	sub	V19.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V18.4S, V28.4S
	add	V18.4S, V18.4S, V28.4S
	ldp	Q0, Q2, [x1, #32]
	ldp	Q1, Q3, [x2, #32]
	mul	V29.4S, V6.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[1]
	sqrdmulh	V21.4S, V6.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[1]
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V10.4S, V1.S[2]
	mul	V30.4S, V12.4S, V1.S[3]
	sqrdmulh	V23.4S, V10.4S, V0.S[2]
	sqrdmulh	V24.4S, V12.4S, V0.S[3]
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V14.4S, V3.S[0]
	mul	V30.4S, V16.4S, V3.S[1]
	sqrdmulh	V25.4S, V14.4S, V2.S[0]
	sqrdmulh	V26.4S, V16.4S, V2.S[1]
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V18.4S, V3.S[2]
	mul	V30.4S, V20.4S, V3.S[3]
	sqrdmulh	V27.4S, V18.4S, V2.S[2]
	sqrdmulh	V28.4S, V20.4S, V2.S[3]
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	str	Q5, [x0, #32]
	str	Q6, [x0, #96]
	str	Q7, [x0, #160]
	str	Q8, [x0, #224]
	str	Q9, [x0, #288]
	str	Q10, [x0, #352]
	str	Q11, [x0, #416]
	str	Q12, [x0, #480]
	str	Q13, [x0, #544]
	str	Q14, [x0, #608]
	str	Q15, [x0, #672]
	str	Q16, [x0, #736]
	str	Q17, [x0, #800]
	str	Q18, [x0, #864]
	str	Q19, [x0, #928]
	str	Q20, [x0, #992]
	ldr	Q5, [x0, #48]
	ldr	Q6, [x0, #112]
	ldr	Q7, [x0, #176]
	ldr	Q8, [x0, #240]
	ldr	Q9, [x0, #304]
	ldr	Q10, [x0, #368]
	ldr	Q11, [x0, #432]
	ldr	Q12, [x0, #496]
	ldr	Q13, [x0, #560]
	ldr	Q14, [x0, #624]
	ldr	Q15, [x0, #688]
	ldr	Q16, [x0, #752]
	ldr	Q17, [x0, #816]
	ldr	Q18, [x0, #880]
	ldr	Q19, [x0, #944]
	ldr	Q20, [x0, #1008]
	ldr	Q0, [x1]
	ldr	Q1, [x2]
	mul	V29.4S, V13.4S, V1.S[1]
	mul	V30.4S, V14.4S, V1.S[1]
	sqrdmulh	V21.4S, V13.4S, V0.S[1]
	sqrdmulh	V22.4S, V14.4S, V0.S[1]
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V15.4S, V1.S[1]
	mul	V30.4S, V16.4S, V1.S[1]
	sqrdmulh	V23.4S, V15.4S, V0.S[1]
	sqrdmulh	V24.4S, V16.4S, V0.S[1]
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V17.4S, V1.S[1]
	mul	V30.4S, V18.4S, V1.S[1]
	sqrdmulh	V25.4S, V17.4S, V0.S[1]
	sqrdmulh	V26.4S, V18.4S, V0.S[1]
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[1]
	mul	V30.4S, V20.4S, V1.S[1]
	sqrdmulh	V27.4S, V19.4S, V0.S[1]
	sqrdmulh	V28.4S, V20.4S, V0.S[1]
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V13.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V14.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V15.4S, V7.4S, V23.4S
	add	V7.4S, V7.4S, V23.4S
	sub	V16.4S, V8.4S, V24.4S
	add	V8.4S, V8.4S, V24.4S
	sub	V17.4S, V9.4S, V25.4S
	add	V9.4S, V9.4S, V25.4S
	sub	V18.4S, V10.4S, V26.4S
	add	V10.4S, V10.4S, V26.4S
	sub	V19.4S, V11.4S, V27.4S
	add	V11.4S, V11.4S, V27.4S
	sub	V20.4S, V12.4S, V28.4S
	add	V12.4S, V12.4S, V28.4S
	mul	V29.4S, V9.4S, V1.S[2]
	mul	V30.4S, V10.4S, V1.S[2]
	sqrdmulh	V21.4S, V9.4S, V0.S[2]
	sqrdmulh	V22.4S, V10.4S, V0.S[2]
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V11.4S, V1.S[2]
	mul	V30.4S, V12.4S, V1.S[2]
	sqrdmulh	V23.4S, V11.4S, V0.S[2]
	sqrdmulh	V24.4S, V12.4S, V0.S[2]
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V17.4S, V1.S[3]
	mul	V30.4S, V18.4S, V1.S[3]
	sqrdmulh	V25.4S, V17.4S, V0.S[3]
	sqrdmulh	V26.4S, V18.4S, V0.S[3]
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[3]
	mul	V30.4S, V20.4S, V1.S[3]
	sqrdmulh	V27.4S, V19.4S, V0.S[3]
	sqrdmulh	V28.4S, V20.4S, V0.S[3]
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V9.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V10.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V11.4S, V7.4S, V23.4S
	add	V7.4S, V7.4S, V23.4S
	sub	V12.4S, V8.4S, V24.4S
	add	V8.4S, V8.4S, V24.4S
	sub	V17.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V18.4S, V14.4S, V26.4S
	add	V14.4S, V14.4S, V26.4S
	sub	V19.4S, V15.4S, V27.4S
	add	V15.4S, V15.4S, V27.4S
	sub	V20.4S, V16.4S, V28.4S
	add	V16.4S, V16.4S, V28.4S
	ldr	Q0, [x1, #16]
	ldr	Q1, [x2, #16]
	mul	V29.4S, V7.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[0]
	sqrdmulh	V21.4S, V7.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[0]
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V11.4S, V1.S[1]
	mul	V30.4S, V12.4S, V1.S[1]
	sqrdmulh	V23.4S, V11.4S, V0.S[1]
	sqrdmulh	V24.4S, V12.4S, V0.S[1]
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V15.4S, V1.S[2]
	mul	V30.4S, V16.4S, V1.S[2]
	sqrdmulh	V25.4S, V15.4S, V0.S[2]
	sqrdmulh	V26.4S, V16.4S, V0.S[2]
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[3]
	mul	V30.4S, V20.4S, V1.S[3]
	sqrdmulh	V27.4S, V19.4S, V0.S[3]
	sqrdmulh	V28.4S, V20.4S, V0.S[3]
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V7.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V11.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V10.4S, V24.4S
	add	V10.4S, V10.4S, V24.4S
	sub	V15.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V14.4S, V26.4S
	add	V14.4S, V14.4S, V26.4S
	sub	V19.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V18.4S, V28.4S
	add	V18.4S, V18.4S, V28.4S
	ldp	Q0, Q2, [x1, #32]
	ldp	Q1, Q3, [x2, #32]
	mul	V29.4S, V6.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[1]
	sqrdmulh	V21.4S, V6.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[1]
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V10.4S, V1.S[2]
	mul	V30.4S, V12.4S, V1.S[3]
	sqrdmulh	V23.4S, V10.4S, V0.S[2]
	sqrdmulh	V24.4S, V12.4S, V0.S[3]
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V14.4S, V3.S[0]
	mul	V30.4S, V16.4S, V3.S[1]
	sqrdmulh	V25.4S, V14.4S, V2.S[0]
	sqrdmulh	V26.4S, V16.4S, V2.S[1]
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V18.4S, V3.S[2]
	mul	V30.4S, V20.4S, V3.S[3]
	sqrdmulh	V27.4S, V18.4S, V2.S[2]
	sqrdmulh	V28.4S, V20.4S, V2.S[3]
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	str	Q5, [x0, #48]
	str	Q6, [x0, #112]
	str	Q7, [x0, #176]
	str	Q8, [x0, #240]
	str	Q9, [x0, #304]
	str	Q10, [x0, #368]
	str	Q11, [x0, #432]
	str	Q12, [x0, #496]
	str	Q13, [x0, #560]
	str	Q14, [x0, #624]
	str	Q15, [x0, #688]
	str	Q16, [x0, #752]
	str	Q17, [x0, #816]
	str	Q18, [x0, #880]
	str	Q19, [x0, #944]
	str	Q20, [x0, #1008]
	ldp	Q5, Q6, [x0]
	ldp	Q7, Q8, [x0, #32]
	ldp	Q9, Q10, [x0, #64]
	ldp	Q11, Q12, [x0, #96]
	ldp	Q13, Q14, [x0, #128]
	ldp	Q15, Q16, [x0, #160]
	ldp	Q17, Q18, [x0, #192]
	ldp	Q19, Q20, [x0, #224]
	ldr	Q0, [x1, #64]
	ldr	Q1, [x2, #64]
	mul	V29.4S, V7.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[0]
	sqrdmulh	V21.4S, V7.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[0]
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V11.4S, V1.S[1]
	mul	V30.4S, V12.4S, V1.S[1]
	sqrdmulh	V23.4S, V11.4S, V0.S[1]
	sqrdmulh	V24.4S, V12.4S, V0.S[1]
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V15.4S, V1.S[2]
	mul	V30.4S, V16.4S, V1.S[2]
	sqrdmulh	V25.4S, V15.4S, V0.S[2]
	sqrdmulh	V26.4S, V16.4S, V0.S[2]
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[3]
	mul	V30.4S, V20.4S, V1.S[3]
	sqrdmulh	V27.4S, V19.4S, V0.S[3]
	sqrdmulh	V28.4S, V20.4S, V0.S[3]
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V7.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V11.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V10.4S, V24.4S
	add	V10.4S, V10.4S, V24.4S
	sub	V15.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V14.4S, V26.4S
	add	V14.4S, V14.4S, V26.4S
	sub	V19.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V18.4S, V28.4S
	add	V18.4S, V18.4S, V28.4S
	ldp	Q0, Q2, [x1, #128]
	ldp	Q1, Q3, [x2, #128]
	mul	V29.4S, V6.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[1]
	sqrdmulh	V21.4S, V6.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[1]
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V10.4S, V1.S[2]
	mul	V30.4S, V12.4S, V1.S[3]
	sqrdmulh	V23.4S, V10.4S, V0.S[2]
	sqrdmulh	V24.4S, V12.4S, V0.S[3]
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V14.4S, V3.S[0]
	mul	V30.4S, V16.4S, V3.S[1]
	sqrdmulh	V25.4S, V14.4S, V2.S[0]
	sqrdmulh	V26.4S, V16.4S, V2.S[1]
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V18.4S, V3.S[2]
	mul	V30.4S, V20.4S, V3.S[3]
	sqrdmulh	V27.4S, V18.4S, V2.S[2]
	sqrdmulh	V28.4S, V20.4S, V2.S[3]
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	ldp	Q0, Q2, [x1, #256]
	ldp	Q1, Q3, [x2, #256]
	mov	V29.16B, V5.16B
	mov	V30.16B, V7.16B
	trn1	V5.2D, V5.2D, V6.2D
	trn1	V7.2D, V7.2D, V8.2D
	trn2	V6.2D, V29.2D, V6.2D
	trn2	V8.2D, V30.2D, V8.2D
	mul	V29.4S, V6.4S, V1.4S
	mul	V30.4S, V8.4S, V3.4S
	sqrdmulh	V21.4S, V6.4S, V0.4S
	sqrdmulh	V22.4S, V8.4S, V2.4S
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	ldp	Q0, Q2, [x1, #288]
	ldp	Q1, Q3, [x2, #288]
	mov	V29.16B, V9.16B
	mov	V30.16B, V11.16B
	trn1	V9.2D, V9.2D, V10.2D
	trn1	V11.2D, V11.2D, V12.2D
	trn2	V10.2D, V29.2D, V10.2D
	trn2	V12.2D, V30.2D, V12.2D
	mul	V29.4S, V10.4S, V1.4S
	mul	V30.4S, V12.4S, V3.4S
	sqrdmulh	V23.4S, V10.4S, V0.4S
	sqrdmulh	V24.4S, V12.4S, V2.4S
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	ldp	Q0, Q2, [x1, #320]
	ldp	Q1, Q3, [x2, #320]
	mov	V29.16B, V13.16B
	mov	V30.16B, V15.16B
	trn1	V13.2D, V13.2D, V14.2D
	trn1	V15.2D, V15.2D, V16.2D
	trn2	V14.2D, V29.2D, V14.2D
	trn2	V16.2D, V30.2D, V16.2D
	mul	V29.4S, V14.4S, V1.4S
	mul	V30.4S, V16.4S, V3.4S
	sqrdmulh	V25.4S, V14.4S, V0.4S
	sqrdmulh	V26.4S, V16.4S, V2.4S
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	ldp	Q0, Q2, [x1, #352]
	ldp	Q1, Q3, [x2, #352]
	mov	V29.16B, V17.16B
	mov	V30.16B, V19.16B
	trn1	V17.2D, V17.2D, V18.2D
	trn1	V19.2D, V19.2D, V20.2D
	trn2	V18.2D, V29.2D, V18.2D
	trn2	V20.2D, V30.2D, V20.2D
	mul	V29.4S, V18.4S, V1.4S
	mul	V30.4S, V20.4S, V3.4S
	sqrdmulh	V27.4S, V18.4S, V0.4S
	sqrdmulh	V28.4S, V20.4S, V2.4S
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	ldp	Q0, Q2, [x1, #768]
	ldp	Q1, Q3, [x2, #768]
	mov	V29.16B, V5.16B
	mov	V30.16B, V7.16B
	trn1	V5.4S, V5.4S, V6.4S
	trn1	V7.4S, V7.4S, V8.4S
	trn2	V6.4S, V29.4S, V6.4S
	trn2	V8.4S, V30.4S, V8.4S
	mul	V29.4S, V6.4S, V1.4S
	mul	V30.4S, V8.4S, V3.4S
	sqrdmulh	V21.4S, V6.4S, V0.4S
	sqrdmulh	V22.4S, V8.4S, V2.4S
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	ldp	Q0, Q2, [x1, #800]
	ldp	Q1, Q3, [x2, #800]
	mov	V29.16B, V9.16B
	mov	V30.16B, V11.16B
	trn1	V9.4S, V9.4S, V10.4S
	trn1	V11.4S, V11.4S, V12.4S
	trn2	V10.4S, V29.4S, V10.4S
	trn2	V12.4S, V30.4S, V12.4S
	mul	V29.4S, V10.4S, V1.4S
	mul	V30.4S, V12.4S, V3.4S
	sqrdmulh	V23.4S, V10.4S, V0.4S
	sqrdmulh	V24.4S, V12.4S, V2.4S
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	ldp	Q0, Q2, [x1, #832]
	ldp	Q1, Q3, [x2, #832]
	mov	V29.16B, V13.16B
	mov	V30.16B, V15.16B
	trn1	V13.4S, V13.4S, V14.4S
	trn1	V15.4S, V15.4S, V16.4S
	trn2	V14.4S, V29.4S, V14.4S
	trn2	V16.4S, V30.4S, V16.4S
	mul	V29.4S, V14.4S, V1.4S
	mul	V30.4S, V16.4S, V3.4S
	sqrdmulh	V25.4S, V14.4S, V0.4S
	sqrdmulh	V26.4S, V16.4S, V2.4S
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	ldp	Q0, Q2, [x1, #864]
	ldp	Q1, Q3, [x2, #864]
	mov	V29.16B, V17.16B
	mov	V30.16B, V19.16B
	trn1	V17.4S, V17.4S, V18.4S
	trn1	V19.4S, V19.4S, V20.4S
	trn2	V18.4S, V29.4S, V18.4S
	trn2	V20.4S, V30.4S, V20.4S
	mul	V29.4S, V18.4S, V1.4S
	mul	V30.4S, V20.4S, V3.4S
	sqrdmulh	V27.4S, V18.4S, V0.4S
	sqrdmulh	V28.4S, V20.4S, V2.4S
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	stp	Q5, Q6, [x0]
	stp	Q7, Q8, [x0, #32]
	stp	Q9, Q10, [x0, #64]
	stp	Q11, Q12, [x0, #96]
	stp	Q13, Q14, [x0, #128]
	stp	Q15, Q16, [x0, #160]
	stp	Q17, Q18, [x0, #192]
	stp	Q19, Q20, [x0, #224]
	ldp	Q5, Q6, [x0, #256]
	ldp	Q7, Q8, [x0, #288]
	ldp	Q9, Q10, [x0, #320]
	ldp	Q11, Q12, [x0, #352]
	ldp	Q13, Q14, [x0, #384]
	ldp	Q15, Q16, [x0, #416]
	ldp	Q17, Q18, [x0, #448]
	ldp	Q19, Q20, [x0, #480]
	ldr	Q0, [x1, #80]
	ldr	Q1, [x2, #80]
	mul	V29.4S, V7.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[0]
	sqrdmulh	V21.4S, V7.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[0]
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V11.4S, V1.S[1]
	mul	V30.4S, V12.4S, V1.S[1]
	sqrdmulh	V23.4S, V11.4S, V0.S[1]
	sqrdmulh	V24.4S, V12.4S, V0.S[1]
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V15.4S, V1.S[2]
	mul	V30.4S, V16.4S, V1.S[2]
	sqrdmulh	V25.4S, V15.4S, V0.S[2]
	sqrdmulh	V26.4S, V16.4S, V0.S[2]
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[3]
	mul	V30.4S, V20.4S, V1.S[3]
	sqrdmulh	V27.4S, V19.4S, V0.S[3]
	sqrdmulh	V28.4S, V20.4S, V0.S[3]
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V7.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V11.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V10.4S, V24.4S
	add	V10.4S, V10.4S, V24.4S
	sub	V15.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V14.4S, V26.4S
	add	V14.4S, V14.4S, V26.4S
	sub	V19.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V18.4S, V28.4S
	add	V18.4S, V18.4S, V28.4S
	ldp	Q0, Q2, [x1, #160]
	ldp	Q1, Q3, [x2, #160]
	mul	V29.4S, V6.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[1]
	sqrdmulh	V21.4S, V6.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[1]
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V10.4S, V1.S[2]
	mul	V30.4S, V12.4S, V1.S[3]
	sqrdmulh	V23.4S, V10.4S, V0.S[2]
	sqrdmulh	V24.4S, V12.4S, V0.S[3]
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V14.4S, V3.S[0]
	mul	V30.4S, V16.4S, V3.S[1]
	sqrdmulh	V25.4S, V14.4S, V2.S[0]
	sqrdmulh	V26.4S, V16.4S, V2.S[1]
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V18.4S, V3.S[2]
	mul	V30.4S, V20.4S, V3.S[3]
	sqrdmulh	V27.4S, V18.4S, V2.S[2]
	sqrdmulh	V28.4S, V20.4S, V2.S[3]
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	ldp	Q0, Q2, [x1, #384]
	ldp	Q1, Q3, [x2, #384]
	mov	V29.16B, V5.16B
	mov	V30.16B, V7.16B
	trn1	V5.2D, V5.2D, V6.2D
	trn1	V7.2D, V7.2D, V8.2D
	trn2	V6.2D, V29.2D, V6.2D
	trn2	V8.2D, V30.2D, V8.2D
	mul	V29.4S, V6.4S, V1.4S
	mul	V30.4S, V8.4S, V3.4S
	sqrdmulh	V21.4S, V6.4S, V0.4S
	sqrdmulh	V22.4S, V8.4S, V2.4S
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	ldp	Q0, Q2, [x1, #416]
	ldp	Q1, Q3, [x2, #416]
	mov	V29.16B, V9.16B
	mov	V30.16B, V11.16B
	trn1	V9.2D, V9.2D, V10.2D
	trn1	V11.2D, V11.2D, V12.2D
	trn2	V10.2D, V29.2D, V10.2D
	trn2	V12.2D, V30.2D, V12.2D
	mul	V29.4S, V10.4S, V1.4S
	mul	V30.4S, V12.4S, V3.4S
	sqrdmulh	V23.4S, V10.4S, V0.4S
	sqrdmulh	V24.4S, V12.4S, V2.4S
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	ldp	Q0, Q2, [x1, #448]
	ldp	Q1, Q3, [x2, #448]
	mov	V29.16B, V13.16B
	mov	V30.16B, V15.16B
	trn1	V13.2D, V13.2D, V14.2D
	trn1	V15.2D, V15.2D, V16.2D
	trn2	V14.2D, V29.2D, V14.2D
	trn2	V16.2D, V30.2D, V16.2D
	mul	V29.4S, V14.4S, V1.4S
	mul	V30.4S, V16.4S, V3.4S
	sqrdmulh	V25.4S, V14.4S, V0.4S
	sqrdmulh	V26.4S, V16.4S, V2.4S
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	ldp	Q0, Q2, [x1, #480]
	ldp	Q1, Q3, [x2, #480]
	mov	V29.16B, V17.16B
	mov	V30.16B, V19.16B
	trn1	V17.2D, V17.2D, V18.2D
	trn1	V19.2D, V19.2D, V20.2D
	trn2	V18.2D, V29.2D, V18.2D
	trn2	V20.2D, V30.2D, V20.2D
	mul	V29.4S, V18.4S, V1.4S
	mul	V30.4S, V20.4S, V3.4S
	sqrdmulh	V27.4S, V18.4S, V0.4S
	sqrdmulh	V28.4S, V20.4S, V2.4S
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	ldp	Q0, Q2, [x1, #896]
	ldp	Q1, Q3, [x2, #896]
	mov	V29.16B, V5.16B
	mov	V30.16B, V7.16B
	trn1	V5.4S, V5.4S, V6.4S
	trn1	V7.4S, V7.4S, V8.4S
	trn2	V6.4S, V29.4S, V6.4S
	trn2	V8.4S, V30.4S, V8.4S
	mul	V29.4S, V6.4S, V1.4S
	mul	V30.4S, V8.4S, V3.4S
	sqrdmulh	V21.4S, V6.4S, V0.4S
	sqrdmulh	V22.4S, V8.4S, V2.4S
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	ldp	Q0, Q2, [x1, #928]
	ldp	Q1, Q3, [x2, #928]
	mov	V29.16B, V9.16B
	mov	V30.16B, V11.16B
	trn1	V9.4S, V9.4S, V10.4S
	trn1	V11.4S, V11.4S, V12.4S
	trn2	V10.4S, V29.4S, V10.4S
	trn2	V12.4S, V30.4S, V12.4S
	mul	V29.4S, V10.4S, V1.4S
	mul	V30.4S, V12.4S, V3.4S
	sqrdmulh	V23.4S, V10.4S, V0.4S
	sqrdmulh	V24.4S, V12.4S, V2.4S
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	ldp	Q0, Q2, [x1, #960]
	ldp	Q1, Q3, [x2, #960]
	mov	V29.16B, V13.16B
	mov	V30.16B, V15.16B
	trn1	V13.4S, V13.4S, V14.4S
	trn1	V15.4S, V15.4S, V16.4S
	trn2	V14.4S, V29.4S, V14.4S
	trn2	V16.4S, V30.4S, V16.4S
	mul	V29.4S, V14.4S, V1.4S
	mul	V30.4S, V16.4S, V3.4S
	sqrdmulh	V25.4S, V14.4S, V0.4S
	sqrdmulh	V26.4S, V16.4S, V2.4S
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	ldp	Q0, Q2, [x1, #992]
	ldp	Q1, Q3, [x2, #992]
	mov	V29.16B, V17.16B
	mov	V30.16B, V19.16B
	trn1	V17.4S, V17.4S, V18.4S
	trn1	V19.4S, V19.4S, V20.4S
	trn2	V18.4S, V29.4S, V18.4S
	trn2	V20.4S, V30.4S, V20.4S
	mul	V29.4S, V18.4S, V1.4S
	mul	V30.4S, V20.4S, V3.4S
	sqrdmulh	V27.4S, V18.4S, V0.4S
	sqrdmulh	V28.4S, V20.4S, V2.4S
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	stp	Q5, Q6, [x0, #256]
	stp	Q7, Q8, [x0, #288]
	stp	Q9, Q10, [x0, #320]
	stp	Q11, Q12, [x0, #352]
	stp	Q13, Q14, [x0, #384]
	stp	Q15, Q16, [x0, #416]
	stp	Q17, Q18, [x0, #448]
	stp	Q19, Q20, [x0, #480]
	ldp	Q5, Q6, [x0, #512]
	ldp	Q7, Q8, [x0, #544]
	ldp	Q9, Q10, [x0, #576]
	ldp	Q11, Q12, [x0, #608]
	ldp	Q13, Q14, [x0, #640]
	ldp	Q15, Q16, [x0, #672]
	ldp	Q17, Q18, [x0, #704]
	ldp	Q19, Q20, [x0, #736]
	ldr	Q0, [x1, #96]
	ldr	Q1, [x2, #96]
	mul	V29.4S, V7.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[0]
	sqrdmulh	V21.4S, V7.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[0]
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V11.4S, V1.S[1]
	mul	V30.4S, V12.4S, V1.S[1]
	sqrdmulh	V23.4S, V11.4S, V0.S[1]
	sqrdmulh	V24.4S, V12.4S, V0.S[1]
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V15.4S, V1.S[2]
	mul	V30.4S, V16.4S, V1.S[2]
	sqrdmulh	V25.4S, V15.4S, V0.S[2]
	sqrdmulh	V26.4S, V16.4S, V0.S[2]
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[3]
	mul	V30.4S, V20.4S, V1.S[3]
	sqrdmulh	V27.4S, V19.4S, V0.S[3]
	sqrdmulh	V28.4S, V20.4S, V0.S[3]
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V7.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V11.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V10.4S, V24.4S
	add	V10.4S, V10.4S, V24.4S
	sub	V15.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V14.4S, V26.4S
	add	V14.4S, V14.4S, V26.4S
	sub	V19.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V18.4S, V28.4S
	add	V18.4S, V18.4S, V28.4S
	ldp	Q0, Q2, [x1, #192]
	ldp	Q1, Q3, [x2, #192]
	mul	V29.4S, V6.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[1]
	sqrdmulh	V21.4S, V6.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[1]
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V10.4S, V1.S[2]
	mul	V30.4S, V12.4S, V1.S[3]
	sqrdmulh	V23.4S, V10.4S, V0.S[2]
	sqrdmulh	V24.4S, V12.4S, V0.S[3]
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V14.4S, V3.S[0]
	mul	V30.4S, V16.4S, V3.S[1]
	sqrdmulh	V25.4S, V14.4S, V2.S[0]
	sqrdmulh	V26.4S, V16.4S, V2.S[1]
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V18.4S, V3.S[2]
	mul	V30.4S, V20.4S, V3.S[3]
	sqrdmulh	V27.4S, V18.4S, V2.S[2]
	sqrdmulh	V28.4S, V20.4S, V2.S[3]
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	ldp	Q0, Q2, [x1, #512]
	ldp	Q1, Q3, [x2, #512]
	mov	V29.16B, V5.16B
	mov	V30.16B, V7.16B
	trn1	V5.2D, V5.2D, V6.2D
	trn1	V7.2D, V7.2D, V8.2D
	trn2	V6.2D, V29.2D, V6.2D
	trn2	V8.2D, V30.2D, V8.2D
	mul	V29.4S, V6.4S, V1.4S
	mul	V30.4S, V8.4S, V3.4S
	sqrdmulh	V21.4S, V6.4S, V0.4S
	sqrdmulh	V22.4S, V8.4S, V2.4S
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	ldp	Q0, Q2, [x1, #544]
	ldp	Q1, Q3, [x2, #544]
	mov	V29.16B, V9.16B
	mov	V30.16B, V11.16B
	trn1	V9.2D, V9.2D, V10.2D
	trn1	V11.2D, V11.2D, V12.2D
	trn2	V10.2D, V29.2D, V10.2D
	trn2	V12.2D, V30.2D, V12.2D
	mul	V29.4S, V10.4S, V1.4S
	mul	V30.4S, V12.4S, V3.4S
	sqrdmulh	V23.4S, V10.4S, V0.4S
	sqrdmulh	V24.4S, V12.4S, V2.4S
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	ldp	Q0, Q2, [x1, #576]
	ldp	Q1, Q3, [x2, #576]
	mov	V29.16B, V13.16B
	mov	V30.16B, V15.16B
	trn1	V13.2D, V13.2D, V14.2D
	trn1	V15.2D, V15.2D, V16.2D
	trn2	V14.2D, V29.2D, V14.2D
	trn2	V16.2D, V30.2D, V16.2D
	mul	V29.4S, V14.4S, V1.4S
	mul	V30.4S, V16.4S, V3.4S
	sqrdmulh	V25.4S, V14.4S, V0.4S
	sqrdmulh	V26.4S, V16.4S, V2.4S
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	ldp	Q0, Q2, [x1, #608]
	ldp	Q1, Q3, [x2, #608]
	mov	V29.16B, V17.16B
	mov	V30.16B, V19.16B
	trn1	V17.2D, V17.2D, V18.2D
	trn1	V19.2D, V19.2D, V20.2D
	trn2	V18.2D, V29.2D, V18.2D
	trn2	V20.2D, V30.2D, V20.2D
	mul	V29.4S, V18.4S, V1.4S
	mul	V30.4S, V20.4S, V3.4S
	sqrdmulh	V27.4S, V18.4S, V0.4S
	sqrdmulh	V28.4S, V20.4S, V2.4S
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	ldr	Q0, [x1, #1024]
	ldr	Q2, [x1, #1040]
	ldr	Q1, [x2, #1024]
	ldr	Q3, [x2, #1040]
	mov	V29.16B, V5.16B
	mov	V30.16B, V7.16B
	trn1	V5.4S, V5.4S, V6.4S
	trn1	V7.4S, V7.4S, V8.4S
	trn2	V6.4S, V29.4S, V6.4S
	trn2	V8.4S, V30.4S, V8.4S
	mul	V29.4S, V6.4S, V1.4S
	mul	V30.4S, V8.4S, V3.4S
	sqrdmulh	V21.4S, V6.4S, V0.4S
	sqrdmulh	V22.4S, V8.4S, V2.4S
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	ldr	Q0, [x1, #1056]
	ldr	Q2, [x1, #1072]
	ldr	Q1, [x2, #1056]
	ldr	Q3, [x2, #1072]
	mov	V29.16B, V9.16B
	mov	V30.16B, V11.16B
	trn1	V9.4S, V9.4S, V10.4S
	trn1	V11.4S, V11.4S, V12.4S
	trn2	V10.4S, V29.4S, V10.4S
	trn2	V12.4S, V30.4S, V12.4S
	mul	V29.4S, V10.4S, V1.4S
	mul	V30.4S, V12.4S, V3.4S
	sqrdmulh	V23.4S, V10.4S, V0.4S
	sqrdmulh	V24.4S, V12.4S, V2.4S
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	ldr	Q0, [x1, #1088]
	ldr	Q2, [x1, #1104]
	ldr	Q1, [x2, #1088]
	ldr	Q3, [x2, #1104]
	mov	V29.16B, V13.16B
	mov	V30.16B, V15.16B
	trn1	V13.4S, V13.4S, V14.4S
	trn1	V15.4S, V15.4S, V16.4S
	trn2	V14.4S, V29.4S, V14.4S
	trn2	V16.4S, V30.4S, V16.4S
	mul	V29.4S, V14.4S, V1.4S
	mul	V30.4S, V16.4S, V3.4S
	sqrdmulh	V25.4S, V14.4S, V0.4S
	sqrdmulh	V26.4S, V16.4S, V2.4S
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	ldr	Q0, [x1, #1120]
	ldr	Q2, [x1, #1136]
	ldr	Q1, [x2, #1120]
	ldr	Q3, [x2, #1136]
	mov	V29.16B, V17.16B
	mov	V30.16B, V19.16B
	trn1	V17.4S, V17.4S, V18.4S
	trn1	V19.4S, V19.4S, V20.4S
	trn2	V18.4S, V29.4S, V18.4S
	trn2	V20.4S, V30.4S, V20.4S
	mul	V29.4S, V18.4S, V1.4S
	mul	V30.4S, V20.4S, V3.4S
	sqrdmulh	V27.4S, V18.4S, V0.4S
	sqrdmulh	V28.4S, V20.4S, V2.4S
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	stp	Q5, Q6, [x0, #512]
	stp	Q7, Q8, [x0, #544]
	stp	Q9, Q10, [x0, #576]
	stp	Q11, Q12, [x0, #608]
	stp	Q13, Q14, [x0, #640]
	stp	Q15, Q16, [x0, #672]
	stp	Q17, Q18, [x0, #704]
	stp	Q19, Q20, [x0, #736]
	ldp	Q5, Q6, [x0, #768]
	ldp	Q7, Q8, [x0, #800]
	ldp	Q9, Q10, [x0, #832]
	ldp	Q11, Q12, [x0, #864]
	ldp	Q13, Q14, [x0, #896]
	ldp	Q15, Q16, [x0, #928]
	ldp	Q17, Q18, [x0, #960]
	ldp	Q19, Q20, [x0, #992]
	ldr	Q0, [x1, #112]
	ldr	Q1, [x2, #112]
	mul	V29.4S, V7.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[0]
	sqrdmulh	V21.4S, V7.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[0]
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V11.4S, V1.S[1]
	mul	V30.4S, V12.4S, V1.S[1]
	sqrdmulh	V23.4S, V11.4S, V0.S[1]
	sqrdmulh	V24.4S, V12.4S, V0.S[1]
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V15.4S, V1.S[2]
	mul	V30.4S, V16.4S, V1.S[2]
	sqrdmulh	V25.4S, V15.4S, V0.S[2]
	sqrdmulh	V26.4S, V16.4S, V0.S[2]
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[3]
	mul	V30.4S, V20.4S, V1.S[3]
	sqrdmulh	V27.4S, V19.4S, V0.S[3]
	sqrdmulh	V28.4S, V20.4S, V0.S[3]
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V7.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V11.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V10.4S, V24.4S
	add	V10.4S, V10.4S, V24.4S
	sub	V15.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V14.4S, V26.4S
	add	V14.4S, V14.4S, V26.4S
	sub	V19.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V18.4S, V28.4S
	add	V18.4S, V18.4S, V28.4S
	ldp	Q0, Q2, [x1, #224]
	ldp	Q1, Q3, [x2, #224]
	mul	V29.4S, V6.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[1]
	sqrdmulh	V21.4S, V6.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[1]
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V10.4S, V1.S[2]
	mul	V30.4S, V12.4S, V1.S[3]
	sqrdmulh	V23.4S, V10.4S, V0.S[2]
	sqrdmulh	V24.4S, V12.4S, V0.S[3]
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V14.4S, V3.S[0]
	mul	V30.4S, V16.4S, V3.S[1]
	sqrdmulh	V25.4S, V14.4S, V2.S[0]
	sqrdmulh	V26.4S, V16.4S, V2.S[1]
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V18.4S, V3.S[2]
	mul	V30.4S, V20.4S, V3.S[3]
	sqrdmulh	V27.4S, V18.4S, V2.S[2]
	sqrdmulh	V28.4S, V20.4S, V2.S[3]
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	ldp	Q0, Q2, [x1, #640]
	ldp	Q1, Q3, [x2, #640]
	mov	V29.16B, V5.16B
	mov	V30.16B, V7.16B
	trn1	V5.2D, V5.2D, V6.2D
	trn1	V7.2D, V7.2D, V8.2D
	trn2	V6.2D, V29.2D, V6.2D
	trn2	V8.2D, V30.2D, V8.2D
	mul	V29.4S, V6.4S, V1.4S
	mul	V30.4S, V8.4S, V3.4S
	sqrdmulh	V21.4S, V6.4S, V0.4S
	sqrdmulh	V22.4S, V8.4S, V2.4S
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	ldp	Q0, Q2, [x1, #672]
	ldp	Q1, Q3, [x2, #672]
	mov	V29.16B, V9.16B
	mov	V30.16B, V11.16B
	trn1	V9.2D, V9.2D, V10.2D
	trn1	V11.2D, V11.2D, V12.2D
	trn2	V10.2D, V29.2D, V10.2D
	trn2	V12.2D, V30.2D, V12.2D
	mul	V29.4S, V10.4S, V1.4S
	mul	V30.4S, V12.4S, V3.4S
	sqrdmulh	V23.4S, V10.4S, V0.4S
	sqrdmulh	V24.4S, V12.4S, V2.4S
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	ldp	Q0, Q2, [x1, #704]
	ldp	Q1, Q3, [x2, #704]
	mov	V29.16B, V13.16B
	mov	V30.16B, V15.16B
	trn1	V13.2D, V13.2D, V14.2D
	trn1	V15.2D, V15.2D, V16.2D
	trn2	V14.2D, V29.2D, V14.2D
	trn2	V16.2D, V30.2D, V16.2D
	mul	V29.4S, V14.4S, V1.4S
	mul	V30.4S, V16.4S, V3.4S
	sqrdmulh	V25.4S, V14.4S, V0.4S
	sqrdmulh	V26.4S, V16.4S, V2.4S
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	ldp	Q0, Q2, [x1, #736]
	ldp	Q1, Q3, [x2, #736]
	mov	V29.16B, V17.16B
	mov	V30.16B, V19.16B
	trn1	V17.2D, V17.2D, V18.2D
	trn1	V19.2D, V19.2D, V20.2D
	trn2	V18.2D, V29.2D, V18.2D
	trn2	V20.2D, V30.2D, V20.2D
	mul	V29.4S, V18.4S, V1.4S
	mul	V30.4S, V20.4S, V3.4S
	sqrdmulh	V27.4S, V18.4S, V0.4S
	sqrdmulh	V28.4S, V20.4S, V2.4S
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	ldr	Q0, [x1, #1152]
	ldr	Q2, [x1, #1168]
	ldr	Q1, [x2, #1152]
	ldr	Q3, [x2, #1168]
	mov	V29.16B, V5.16B
	mov	V30.16B, V7.16B
	trn1	V5.4S, V5.4S, V6.4S
	trn1	V7.4S, V7.4S, V8.4S
	trn2	V6.4S, V29.4S, V6.4S
	trn2	V8.4S, V30.4S, V8.4S
	mul	V29.4S, V6.4S, V1.4S
	mul	V30.4S, V8.4S, V3.4S
	sqrdmulh	V21.4S, V6.4S, V0.4S
	sqrdmulh	V22.4S, V8.4S, V2.4S
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	ldr	Q0, [x1, #1184]
	ldr	Q2, [x1, #1200]
	ldr	Q1, [x2, #1184]
	ldr	Q3, [x2, #1200]
	mov	V29.16B, V9.16B
	mov	V30.16B, V11.16B
	trn1	V9.4S, V9.4S, V10.4S
	trn1	V11.4S, V11.4S, V12.4S
	trn2	V10.4S, V29.4S, V10.4S
	trn2	V12.4S, V30.4S, V12.4S
	mul	V29.4S, V10.4S, V1.4S
	mul	V30.4S, V12.4S, V3.4S
	sqrdmulh	V23.4S, V10.4S, V0.4S
	sqrdmulh	V24.4S, V12.4S, V2.4S
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	ldr	Q0, [x1, #1216]
	ldr	Q2, [x1, #1232]
	ldr	Q1, [x2, #1216]
	ldr	Q3, [x2, #1232]
	mov	V29.16B, V13.16B
	mov	V30.16B, V15.16B
	trn1	V13.4S, V13.4S, V14.4S
	trn1	V15.4S, V15.4S, V16.4S
	trn2	V14.4S, V29.4S, V14.4S
	trn2	V16.4S, V30.4S, V16.4S
	mul	V29.4S, V14.4S, V1.4S
	mul	V30.4S, V16.4S, V3.4S
	sqrdmulh	V25.4S, V14.4S, V0.4S
	sqrdmulh	V26.4S, V16.4S, V2.4S
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	ldr	Q0, [x1, #1248]
	ldr	Q2, [x1, #1264]
	ldr	Q1, [x2, #1248]
	ldr	Q3, [x2, #1264]
	mov	V29.16B, V17.16B
	mov	V30.16B, V19.16B
	trn1	V17.4S, V17.4S, V18.4S
	trn1	V19.4S, V19.4S, V20.4S
	trn2	V18.4S, V29.4S, V18.4S
	trn2	V20.4S, V30.4S, V20.4S
	mul	V29.4S, V18.4S, V1.4S
	mul	V30.4S, V20.4S, V3.4S
	sqrdmulh	V27.4S, V18.4S, V0.4S
	sqrdmulh	V28.4S, V20.4S, V2.4S
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	stp	Q5, Q6, [x0, #768]
	stp	Q7, Q8, [x0, #800]
	stp	Q9, Q10, [x0, #832]
	stp	Q11, Q12, [x0, #864]
	stp	Q13, Q14, [x0, #896]
	stp	Q15, Q16, [x0, #928]
	stp	Q17, Q18, [x0, #960]
	stp	Q19, Q20, [x0, #992]
	ldp	D8, D9, [x29, #16]
	ldp	D10, D11, [x29, #32]
	ldp	D12, D13, [x29, #48]
	ldp	D14, D15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
	ENDP
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mldsa_ntt_full_sqrdmlsh_neon
mldsa_ntt_full_sqrdmlsh_neon PROC
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	stp	D10, D11, [x29, #32]
	stp	D12, D13, [x29, #48]
	stp	D14, D15, [x29, #64]
	adrp	x1, L_mldsa_aarch64_zetas
	add	x1, x1, L_mldsa_aarch64_zetas
	adrp	x2, L_mldsa_aarch64_zetas_qinv
	add	x2, x2, L_mldsa_aarch64_zetas_qinv
	adrp	x3, L_mldsa_aarch64_consts
	add	x3, x3, L_mldsa_aarch64_consts
	ldr	Q4, [x3]
	ldr	Q5, [x0]
	ldr	Q6, [x0, #64]
	ldr	Q7, [x0, #128]
	ldr	Q8, [x0, #192]
	ldr	Q9, [x0, #256]
	ldr	Q10, [x0, #320]
	ldr	Q11, [x0, #384]
	ldr	Q12, [x0, #448]
	ldr	Q13, [x0, #512]
	ldr	Q14, [x0, #576]
	ldr	Q15, [x0, #640]
	ldr	Q16, [x0, #704]
	ldr	Q17, [x0, #768]
	ldr	Q18, [x0, #832]
	ldr	Q19, [x0, #896]
	ldr	Q20, [x0, #960]
	ldr	Q0, [x1]
	ldr	Q1, [x2]
	mul	V29.4S, V13.4S, V1.S[1]
	mul	V30.4S, V14.4S, V1.S[1]
	sqrdmulh	V21.4S, V13.4S, V0.S[1]
	sqrdmulh	V22.4S, V14.4S, V0.S[1]
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V15.4S, V1.S[1]
	mul	V30.4S, V16.4S, V1.S[1]
	sqrdmulh	V23.4S, V15.4S, V0.S[1]
	sqrdmulh	V24.4S, V16.4S, V0.S[1]
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V17.4S, V1.S[1]
	mul	V30.4S, V18.4S, V1.S[1]
	sqrdmulh	V25.4S, V17.4S, V0.S[1]
	sqrdmulh	V26.4S, V18.4S, V0.S[1]
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[1]
	mul	V30.4S, V20.4S, V1.S[1]
	sqrdmulh	V27.4S, V19.4S, V0.S[1]
	sqrdmulh	V28.4S, V20.4S, V0.S[1]
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V13.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V14.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V15.4S, V7.4S, V23.4S
	add	V7.4S, V7.4S, V23.4S
	sub	V16.4S, V8.4S, V24.4S
	add	V8.4S, V8.4S, V24.4S
	sub	V17.4S, V9.4S, V25.4S
	add	V9.4S, V9.4S, V25.4S
	sub	V18.4S, V10.4S, V26.4S
	add	V10.4S, V10.4S, V26.4S
	sub	V19.4S, V11.4S, V27.4S
	add	V11.4S, V11.4S, V27.4S
	sub	V20.4S, V12.4S, V28.4S
	add	V12.4S, V12.4S, V28.4S
	mul	V29.4S, V9.4S, V1.S[2]
	mul	V30.4S, V10.4S, V1.S[2]
	sqrdmulh	V21.4S, V9.4S, V0.S[2]
	sqrdmulh	V22.4S, V10.4S, V0.S[2]
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V11.4S, V1.S[2]
	mul	V30.4S, V12.4S, V1.S[2]
	sqrdmulh	V23.4S, V11.4S, V0.S[2]
	sqrdmulh	V24.4S, V12.4S, V0.S[2]
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V17.4S, V1.S[3]
	mul	V30.4S, V18.4S, V1.S[3]
	sqrdmulh	V25.4S, V17.4S, V0.S[3]
	sqrdmulh	V26.4S, V18.4S, V0.S[3]
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[3]
	mul	V30.4S, V20.4S, V1.S[3]
	sqrdmulh	V27.4S, V19.4S, V0.S[3]
	sqrdmulh	V28.4S, V20.4S, V0.S[3]
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V9.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V10.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V11.4S, V7.4S, V23.4S
	add	V7.4S, V7.4S, V23.4S
	sub	V12.4S, V8.4S, V24.4S
	add	V8.4S, V8.4S, V24.4S
	sub	V17.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V18.4S, V14.4S, V26.4S
	add	V14.4S, V14.4S, V26.4S
	sub	V19.4S, V15.4S, V27.4S
	add	V15.4S, V15.4S, V27.4S
	sub	V20.4S, V16.4S, V28.4S
	add	V16.4S, V16.4S, V28.4S
	ldr	Q0, [x1, #16]
	ldr	Q1, [x2, #16]
	mul	V29.4S, V7.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[0]
	sqrdmulh	V21.4S, V7.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[0]
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V11.4S, V1.S[1]
	mul	V30.4S, V12.4S, V1.S[1]
	sqrdmulh	V23.4S, V11.4S, V0.S[1]
	sqrdmulh	V24.4S, V12.4S, V0.S[1]
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V15.4S, V1.S[2]
	mul	V30.4S, V16.4S, V1.S[2]
	sqrdmulh	V25.4S, V15.4S, V0.S[2]
	sqrdmulh	V26.4S, V16.4S, V0.S[2]
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[3]
	mul	V30.4S, V20.4S, V1.S[3]
	sqrdmulh	V27.4S, V19.4S, V0.S[3]
	sqrdmulh	V28.4S, V20.4S, V0.S[3]
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V7.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V11.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V10.4S, V24.4S
	add	V10.4S, V10.4S, V24.4S
	sub	V15.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V14.4S, V26.4S
	add	V14.4S, V14.4S, V26.4S
	sub	V19.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V18.4S, V28.4S
	add	V18.4S, V18.4S, V28.4S
	ldp	Q0, Q2, [x1, #32]
	ldp	Q1, Q3, [x2, #32]
	mul	V29.4S, V6.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[1]
	sqrdmulh	V21.4S, V6.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[1]
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V10.4S, V1.S[2]
	mul	V30.4S, V12.4S, V1.S[3]
	sqrdmulh	V23.4S, V10.4S, V0.S[2]
	sqrdmulh	V24.4S, V12.4S, V0.S[3]
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V14.4S, V3.S[0]
	mul	V30.4S, V16.4S, V3.S[1]
	sqrdmulh	V25.4S, V14.4S, V2.S[0]
	sqrdmulh	V26.4S, V16.4S, V2.S[1]
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V18.4S, V3.S[2]
	mul	V30.4S, V20.4S, V3.S[3]
	sqrdmulh	V27.4S, V18.4S, V2.S[2]
	sqrdmulh	V28.4S, V20.4S, V2.S[3]
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	str	Q5, [x0]
	str	Q6, [x0, #64]
	str	Q7, [x0, #128]
	str	Q8, [x0, #192]
	str	Q9, [x0, #256]
	str	Q10, [x0, #320]
	str	Q11, [x0, #384]
	str	Q12, [x0, #448]
	str	Q13, [x0, #512]
	str	Q14, [x0, #576]
	str	Q15, [x0, #640]
	str	Q16, [x0, #704]
	str	Q17, [x0, #768]
	str	Q18, [x0, #832]
	str	Q19, [x0, #896]
	str	Q20, [x0, #960]
	ldr	Q5, [x0, #16]
	ldr	Q6, [x0, #80]
	ldr	Q7, [x0, #144]
	ldr	Q8, [x0, #208]
	ldr	Q9, [x0, #272]
	ldr	Q10, [x0, #336]
	ldr	Q11, [x0, #400]
	ldr	Q12, [x0, #464]
	ldr	Q13, [x0, #528]
	ldr	Q14, [x0, #592]
	ldr	Q15, [x0, #656]
	ldr	Q16, [x0, #720]
	ldr	Q17, [x0, #784]
	ldr	Q18, [x0, #848]
	ldr	Q19, [x0, #912]
	ldr	Q20, [x0, #976]
	ldr	Q0, [x1]
	ldr	Q1, [x2]
	mul	V29.4S, V13.4S, V1.S[1]
	mul	V30.4S, V14.4S, V1.S[1]
	sqrdmulh	V21.4S, V13.4S, V0.S[1]
	sqrdmulh	V22.4S, V14.4S, V0.S[1]
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V15.4S, V1.S[1]
	mul	V30.4S, V16.4S, V1.S[1]
	sqrdmulh	V23.4S, V15.4S, V0.S[1]
	sqrdmulh	V24.4S, V16.4S, V0.S[1]
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V17.4S, V1.S[1]
	mul	V30.4S, V18.4S, V1.S[1]
	sqrdmulh	V25.4S, V17.4S, V0.S[1]
	sqrdmulh	V26.4S, V18.4S, V0.S[1]
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[1]
	mul	V30.4S, V20.4S, V1.S[1]
	sqrdmulh	V27.4S, V19.4S, V0.S[1]
	sqrdmulh	V28.4S, V20.4S, V0.S[1]
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V13.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V14.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V15.4S, V7.4S, V23.4S
	add	V7.4S, V7.4S, V23.4S
	sub	V16.4S, V8.4S, V24.4S
	add	V8.4S, V8.4S, V24.4S
	sub	V17.4S, V9.4S, V25.4S
	add	V9.4S, V9.4S, V25.4S
	sub	V18.4S, V10.4S, V26.4S
	add	V10.4S, V10.4S, V26.4S
	sub	V19.4S, V11.4S, V27.4S
	add	V11.4S, V11.4S, V27.4S
	sub	V20.4S, V12.4S, V28.4S
	add	V12.4S, V12.4S, V28.4S
	mul	V29.4S, V9.4S, V1.S[2]
	mul	V30.4S, V10.4S, V1.S[2]
	sqrdmulh	V21.4S, V9.4S, V0.S[2]
	sqrdmulh	V22.4S, V10.4S, V0.S[2]
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V11.4S, V1.S[2]
	mul	V30.4S, V12.4S, V1.S[2]
	sqrdmulh	V23.4S, V11.4S, V0.S[2]
	sqrdmulh	V24.4S, V12.4S, V0.S[2]
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V17.4S, V1.S[3]
	mul	V30.4S, V18.4S, V1.S[3]
	sqrdmulh	V25.4S, V17.4S, V0.S[3]
	sqrdmulh	V26.4S, V18.4S, V0.S[3]
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[3]
	mul	V30.4S, V20.4S, V1.S[3]
	sqrdmulh	V27.4S, V19.4S, V0.S[3]
	sqrdmulh	V28.4S, V20.4S, V0.S[3]
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V9.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V10.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V11.4S, V7.4S, V23.4S
	add	V7.4S, V7.4S, V23.4S
	sub	V12.4S, V8.4S, V24.4S
	add	V8.4S, V8.4S, V24.4S
	sub	V17.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V18.4S, V14.4S, V26.4S
	add	V14.4S, V14.4S, V26.4S
	sub	V19.4S, V15.4S, V27.4S
	add	V15.4S, V15.4S, V27.4S
	sub	V20.4S, V16.4S, V28.4S
	add	V16.4S, V16.4S, V28.4S
	ldr	Q0, [x1, #16]
	ldr	Q1, [x2, #16]
	mul	V29.4S, V7.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[0]
	sqrdmulh	V21.4S, V7.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[0]
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V11.4S, V1.S[1]
	mul	V30.4S, V12.4S, V1.S[1]
	sqrdmulh	V23.4S, V11.4S, V0.S[1]
	sqrdmulh	V24.4S, V12.4S, V0.S[1]
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V15.4S, V1.S[2]
	mul	V30.4S, V16.4S, V1.S[2]
	sqrdmulh	V25.4S, V15.4S, V0.S[2]
	sqrdmulh	V26.4S, V16.4S, V0.S[2]
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[3]
	mul	V30.4S, V20.4S, V1.S[3]
	sqrdmulh	V27.4S, V19.4S, V0.S[3]
	sqrdmulh	V28.4S, V20.4S, V0.S[3]
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V7.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V11.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V10.4S, V24.4S
	add	V10.4S, V10.4S, V24.4S
	sub	V15.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V14.4S, V26.4S
	add	V14.4S, V14.4S, V26.4S
	sub	V19.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V18.4S, V28.4S
	add	V18.4S, V18.4S, V28.4S
	ldp	Q0, Q2, [x1, #32]
	ldp	Q1, Q3, [x2, #32]
	mul	V29.4S, V6.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[1]
	sqrdmulh	V21.4S, V6.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[1]
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V10.4S, V1.S[2]
	mul	V30.4S, V12.4S, V1.S[3]
	sqrdmulh	V23.4S, V10.4S, V0.S[2]
	sqrdmulh	V24.4S, V12.4S, V0.S[3]
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V14.4S, V3.S[0]
	mul	V30.4S, V16.4S, V3.S[1]
	sqrdmulh	V25.4S, V14.4S, V2.S[0]
	sqrdmulh	V26.4S, V16.4S, V2.S[1]
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V18.4S, V3.S[2]
	mul	V30.4S, V20.4S, V3.S[3]
	sqrdmulh	V27.4S, V18.4S, V2.S[2]
	sqrdmulh	V28.4S, V20.4S, V2.S[3]
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	str	Q5, [x0, #16]
	str	Q6, [x0, #80]
	str	Q7, [x0, #144]
	str	Q8, [x0, #208]
	str	Q9, [x0, #272]
	str	Q10, [x0, #336]
	str	Q11, [x0, #400]
	str	Q12, [x0, #464]
	str	Q13, [x0, #528]
	str	Q14, [x0, #592]
	str	Q15, [x0, #656]
	str	Q16, [x0, #720]
	str	Q17, [x0, #784]
	str	Q18, [x0, #848]
	str	Q19, [x0, #912]
	str	Q20, [x0, #976]
	ldr	Q5, [x0, #32]
	ldr	Q6, [x0, #96]
	ldr	Q7, [x0, #160]
	ldr	Q8, [x0, #224]
	ldr	Q9, [x0, #288]
	ldr	Q10, [x0, #352]
	ldr	Q11, [x0, #416]
	ldr	Q12, [x0, #480]
	ldr	Q13, [x0, #544]
	ldr	Q14, [x0, #608]
	ldr	Q15, [x0, #672]
	ldr	Q16, [x0, #736]
	ldr	Q17, [x0, #800]
	ldr	Q18, [x0, #864]
	ldr	Q19, [x0, #928]
	ldr	Q20, [x0, #992]
	ldr	Q0, [x1]
	ldr	Q1, [x2]
	mul	V29.4S, V13.4S, V1.S[1]
	mul	V30.4S, V14.4S, V1.S[1]
	sqrdmulh	V21.4S, V13.4S, V0.S[1]
	sqrdmulh	V22.4S, V14.4S, V0.S[1]
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V15.4S, V1.S[1]
	mul	V30.4S, V16.4S, V1.S[1]
	sqrdmulh	V23.4S, V15.4S, V0.S[1]
	sqrdmulh	V24.4S, V16.4S, V0.S[1]
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V17.4S, V1.S[1]
	mul	V30.4S, V18.4S, V1.S[1]
	sqrdmulh	V25.4S, V17.4S, V0.S[1]
	sqrdmulh	V26.4S, V18.4S, V0.S[1]
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[1]
	mul	V30.4S, V20.4S, V1.S[1]
	sqrdmulh	V27.4S, V19.4S, V0.S[1]
	sqrdmulh	V28.4S, V20.4S, V0.S[1]
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V13.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V14.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V15.4S, V7.4S, V23.4S
	add	V7.4S, V7.4S, V23.4S
	sub	V16.4S, V8.4S, V24.4S
	add	V8.4S, V8.4S, V24.4S
	sub	V17.4S, V9.4S, V25.4S
	add	V9.4S, V9.4S, V25.4S
	sub	V18.4S, V10.4S, V26.4S
	add	V10.4S, V10.4S, V26.4S
	sub	V19.4S, V11.4S, V27.4S
	add	V11.4S, V11.4S, V27.4S
	sub	V20.4S, V12.4S, V28.4S
	add	V12.4S, V12.4S, V28.4S
	mul	V29.4S, V9.4S, V1.S[2]
	mul	V30.4S, V10.4S, V1.S[2]
	sqrdmulh	V21.4S, V9.4S, V0.S[2]
	sqrdmulh	V22.4S, V10.4S, V0.S[2]
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V11.4S, V1.S[2]
	mul	V30.4S, V12.4S, V1.S[2]
	sqrdmulh	V23.4S, V11.4S, V0.S[2]
	sqrdmulh	V24.4S, V12.4S, V0.S[2]
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V17.4S, V1.S[3]
	mul	V30.4S, V18.4S, V1.S[3]
	sqrdmulh	V25.4S, V17.4S, V0.S[3]
	sqrdmulh	V26.4S, V18.4S, V0.S[3]
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[3]
	mul	V30.4S, V20.4S, V1.S[3]
	sqrdmulh	V27.4S, V19.4S, V0.S[3]
	sqrdmulh	V28.4S, V20.4S, V0.S[3]
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V9.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V10.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V11.4S, V7.4S, V23.4S
	add	V7.4S, V7.4S, V23.4S
	sub	V12.4S, V8.4S, V24.4S
	add	V8.4S, V8.4S, V24.4S
	sub	V17.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V18.4S, V14.4S, V26.4S
	add	V14.4S, V14.4S, V26.4S
	sub	V19.4S, V15.4S, V27.4S
	add	V15.4S, V15.4S, V27.4S
	sub	V20.4S, V16.4S, V28.4S
	add	V16.4S, V16.4S, V28.4S
	ldr	Q0, [x1, #16]
	ldr	Q1, [x2, #16]
	mul	V29.4S, V7.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[0]
	sqrdmulh	V21.4S, V7.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[0]
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V11.4S, V1.S[1]
	mul	V30.4S, V12.4S, V1.S[1]
	sqrdmulh	V23.4S, V11.4S, V0.S[1]
	sqrdmulh	V24.4S, V12.4S, V0.S[1]
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V15.4S, V1.S[2]
	mul	V30.4S, V16.4S, V1.S[2]
	sqrdmulh	V25.4S, V15.4S, V0.S[2]
	sqrdmulh	V26.4S, V16.4S, V0.S[2]
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[3]
	mul	V30.4S, V20.4S, V1.S[3]
	sqrdmulh	V27.4S, V19.4S, V0.S[3]
	sqrdmulh	V28.4S, V20.4S, V0.S[3]
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V7.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V11.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V10.4S, V24.4S
	add	V10.4S, V10.4S, V24.4S
	sub	V15.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V14.4S, V26.4S
	add	V14.4S, V14.4S, V26.4S
	sub	V19.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V18.4S, V28.4S
	add	V18.4S, V18.4S, V28.4S
	ldp	Q0, Q2, [x1, #32]
	ldp	Q1, Q3, [x2, #32]
	mul	V29.4S, V6.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[1]
	sqrdmulh	V21.4S, V6.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[1]
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V10.4S, V1.S[2]
	mul	V30.4S, V12.4S, V1.S[3]
	sqrdmulh	V23.4S, V10.4S, V0.S[2]
	sqrdmulh	V24.4S, V12.4S, V0.S[3]
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V14.4S, V3.S[0]
	mul	V30.4S, V16.4S, V3.S[1]
	sqrdmulh	V25.4S, V14.4S, V2.S[0]
	sqrdmulh	V26.4S, V16.4S, V2.S[1]
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V18.4S, V3.S[2]
	mul	V30.4S, V20.4S, V3.S[3]
	sqrdmulh	V27.4S, V18.4S, V2.S[2]
	sqrdmulh	V28.4S, V20.4S, V2.S[3]
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	str	Q5, [x0, #32]
	str	Q6, [x0, #96]
	str	Q7, [x0, #160]
	str	Q8, [x0, #224]
	str	Q9, [x0, #288]
	str	Q10, [x0, #352]
	str	Q11, [x0, #416]
	str	Q12, [x0, #480]
	str	Q13, [x0, #544]
	str	Q14, [x0, #608]
	str	Q15, [x0, #672]
	str	Q16, [x0, #736]
	str	Q17, [x0, #800]
	str	Q18, [x0, #864]
	str	Q19, [x0, #928]
	str	Q20, [x0, #992]
	ldr	Q5, [x0, #48]
	ldr	Q6, [x0, #112]
	ldr	Q7, [x0, #176]
	ldr	Q8, [x0, #240]
	ldr	Q9, [x0, #304]
	ldr	Q10, [x0, #368]
	ldr	Q11, [x0, #432]
	ldr	Q12, [x0, #496]
	ldr	Q13, [x0, #560]
	ldr	Q14, [x0, #624]
	ldr	Q15, [x0, #688]
	ldr	Q16, [x0, #752]
	ldr	Q17, [x0, #816]
	ldr	Q18, [x0, #880]
	ldr	Q19, [x0, #944]
	ldr	Q20, [x0, #1008]
	ldr	Q0, [x1]
	ldr	Q1, [x2]
	mul	V29.4S, V13.4S, V1.S[1]
	mul	V30.4S, V14.4S, V1.S[1]
	sqrdmulh	V21.4S, V13.4S, V0.S[1]
	sqrdmulh	V22.4S, V14.4S, V0.S[1]
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V15.4S, V1.S[1]
	mul	V30.4S, V16.4S, V1.S[1]
	sqrdmulh	V23.4S, V15.4S, V0.S[1]
	sqrdmulh	V24.4S, V16.4S, V0.S[1]
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V17.4S, V1.S[1]
	mul	V30.4S, V18.4S, V1.S[1]
	sqrdmulh	V25.4S, V17.4S, V0.S[1]
	sqrdmulh	V26.4S, V18.4S, V0.S[1]
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[1]
	mul	V30.4S, V20.4S, V1.S[1]
	sqrdmulh	V27.4S, V19.4S, V0.S[1]
	sqrdmulh	V28.4S, V20.4S, V0.S[1]
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V13.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V14.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V15.4S, V7.4S, V23.4S
	add	V7.4S, V7.4S, V23.4S
	sub	V16.4S, V8.4S, V24.4S
	add	V8.4S, V8.4S, V24.4S
	sub	V17.4S, V9.4S, V25.4S
	add	V9.4S, V9.4S, V25.4S
	sub	V18.4S, V10.4S, V26.4S
	add	V10.4S, V10.4S, V26.4S
	sub	V19.4S, V11.4S, V27.4S
	add	V11.4S, V11.4S, V27.4S
	sub	V20.4S, V12.4S, V28.4S
	add	V12.4S, V12.4S, V28.4S
	mul	V29.4S, V9.4S, V1.S[2]
	mul	V30.4S, V10.4S, V1.S[2]
	sqrdmulh	V21.4S, V9.4S, V0.S[2]
	sqrdmulh	V22.4S, V10.4S, V0.S[2]
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V11.4S, V1.S[2]
	mul	V30.4S, V12.4S, V1.S[2]
	sqrdmulh	V23.4S, V11.4S, V0.S[2]
	sqrdmulh	V24.4S, V12.4S, V0.S[2]
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V17.4S, V1.S[3]
	mul	V30.4S, V18.4S, V1.S[3]
	sqrdmulh	V25.4S, V17.4S, V0.S[3]
	sqrdmulh	V26.4S, V18.4S, V0.S[3]
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[3]
	mul	V30.4S, V20.4S, V1.S[3]
	sqrdmulh	V27.4S, V19.4S, V0.S[3]
	sqrdmulh	V28.4S, V20.4S, V0.S[3]
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V9.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V10.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V11.4S, V7.4S, V23.4S
	add	V7.4S, V7.4S, V23.4S
	sub	V12.4S, V8.4S, V24.4S
	add	V8.4S, V8.4S, V24.4S
	sub	V17.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V18.4S, V14.4S, V26.4S
	add	V14.4S, V14.4S, V26.4S
	sub	V19.4S, V15.4S, V27.4S
	add	V15.4S, V15.4S, V27.4S
	sub	V20.4S, V16.4S, V28.4S
	add	V16.4S, V16.4S, V28.4S
	ldr	Q0, [x1, #16]
	ldr	Q1, [x2, #16]
	mul	V29.4S, V7.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[0]
	sqrdmulh	V21.4S, V7.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[0]
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V11.4S, V1.S[1]
	mul	V30.4S, V12.4S, V1.S[1]
	sqrdmulh	V23.4S, V11.4S, V0.S[1]
	sqrdmulh	V24.4S, V12.4S, V0.S[1]
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V15.4S, V1.S[2]
	mul	V30.4S, V16.4S, V1.S[2]
	sqrdmulh	V25.4S, V15.4S, V0.S[2]
	sqrdmulh	V26.4S, V16.4S, V0.S[2]
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[3]
	mul	V30.4S, V20.4S, V1.S[3]
	sqrdmulh	V27.4S, V19.4S, V0.S[3]
	sqrdmulh	V28.4S, V20.4S, V0.S[3]
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V7.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V11.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V10.4S, V24.4S
	add	V10.4S, V10.4S, V24.4S
	sub	V15.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V14.4S, V26.4S
	add	V14.4S, V14.4S, V26.4S
	sub	V19.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V18.4S, V28.4S
	add	V18.4S, V18.4S, V28.4S
	ldp	Q0, Q2, [x1, #32]
	ldp	Q1, Q3, [x2, #32]
	mul	V29.4S, V6.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[1]
	sqrdmulh	V21.4S, V6.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[1]
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V10.4S, V1.S[2]
	mul	V30.4S, V12.4S, V1.S[3]
	sqrdmulh	V23.4S, V10.4S, V0.S[2]
	sqrdmulh	V24.4S, V12.4S, V0.S[3]
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V14.4S, V3.S[0]
	mul	V30.4S, V16.4S, V3.S[1]
	sqrdmulh	V25.4S, V14.4S, V2.S[0]
	sqrdmulh	V26.4S, V16.4S, V2.S[1]
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V18.4S, V3.S[2]
	mul	V30.4S, V20.4S, V3.S[3]
	sqrdmulh	V27.4S, V18.4S, V2.S[2]
	sqrdmulh	V28.4S, V20.4S, V2.S[3]
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	str	Q5, [x0, #48]
	str	Q6, [x0, #112]
	str	Q7, [x0, #176]
	str	Q8, [x0, #240]
	str	Q9, [x0, #304]
	str	Q10, [x0, #368]
	str	Q11, [x0, #432]
	str	Q12, [x0, #496]
	str	Q13, [x0, #560]
	str	Q14, [x0, #624]
	str	Q15, [x0, #688]
	str	Q16, [x0, #752]
	str	Q17, [x0, #816]
	str	Q18, [x0, #880]
	str	Q19, [x0, #944]
	str	Q20, [x0, #1008]
	ldp	Q5, Q6, [x0]
	ldp	Q7, Q8, [x0, #32]
	ldp	Q9, Q10, [x0, #64]
	ldp	Q11, Q12, [x0, #96]
	ldp	Q13, Q14, [x0, #128]
	ldp	Q15, Q16, [x0, #160]
	ldp	Q17, Q18, [x0, #192]
	ldp	Q19, Q20, [x0, #224]
	ldr	Q0, [x1, #64]
	ldr	Q1, [x2, #64]
	mul	V29.4S, V7.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[0]
	sqrdmulh	V21.4S, V7.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[0]
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V11.4S, V1.S[1]
	mul	V30.4S, V12.4S, V1.S[1]
	sqrdmulh	V23.4S, V11.4S, V0.S[1]
	sqrdmulh	V24.4S, V12.4S, V0.S[1]
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V15.4S, V1.S[2]
	mul	V30.4S, V16.4S, V1.S[2]
	sqrdmulh	V25.4S, V15.4S, V0.S[2]
	sqrdmulh	V26.4S, V16.4S, V0.S[2]
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[3]
	mul	V30.4S, V20.4S, V1.S[3]
	sqrdmulh	V27.4S, V19.4S, V0.S[3]
	sqrdmulh	V28.4S, V20.4S, V0.S[3]
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V7.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V11.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V10.4S, V24.4S
	add	V10.4S, V10.4S, V24.4S
	sub	V15.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V14.4S, V26.4S
	add	V14.4S, V14.4S, V26.4S
	sub	V19.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V18.4S, V28.4S
	add	V18.4S, V18.4S, V28.4S
	ldp	Q0, Q2, [x1, #128]
	ldp	Q1, Q3, [x2, #128]
	mul	V29.4S, V6.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[1]
	sqrdmulh	V21.4S, V6.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[1]
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V10.4S, V1.S[2]
	mul	V30.4S, V12.4S, V1.S[3]
	sqrdmulh	V23.4S, V10.4S, V0.S[2]
	sqrdmulh	V24.4S, V12.4S, V0.S[3]
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V14.4S, V3.S[0]
	mul	V30.4S, V16.4S, V3.S[1]
	sqrdmulh	V25.4S, V14.4S, V2.S[0]
	sqrdmulh	V26.4S, V16.4S, V2.S[1]
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V18.4S, V3.S[2]
	mul	V30.4S, V20.4S, V3.S[3]
	sqrdmulh	V27.4S, V18.4S, V2.S[2]
	sqrdmulh	V28.4S, V20.4S, V2.S[3]
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	ldp	Q0, Q2, [x1, #256]
	ldp	Q1, Q3, [x2, #256]
	mov	V29.16B, V5.16B
	mov	V30.16B, V7.16B
	trn1	V5.2D, V5.2D, V6.2D
	trn1	V7.2D, V7.2D, V8.2D
	trn2	V6.2D, V29.2D, V6.2D
	trn2	V8.2D, V30.2D, V8.2D
	mul	V29.4S, V6.4S, V1.4S
	mul	V30.4S, V8.4S, V3.4S
	sqrdmulh	V21.4S, V6.4S, V0.4S
	sqrdmulh	V22.4S, V8.4S, V2.4S
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	ldp	Q0, Q2, [x1, #288]
	ldp	Q1, Q3, [x2, #288]
	mov	V29.16B, V9.16B
	mov	V30.16B, V11.16B
	trn1	V9.2D, V9.2D, V10.2D
	trn1	V11.2D, V11.2D, V12.2D
	trn2	V10.2D, V29.2D, V10.2D
	trn2	V12.2D, V30.2D, V12.2D
	mul	V29.4S, V10.4S, V1.4S
	mul	V30.4S, V12.4S, V3.4S
	sqrdmulh	V23.4S, V10.4S, V0.4S
	sqrdmulh	V24.4S, V12.4S, V2.4S
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	ldp	Q0, Q2, [x1, #320]
	ldp	Q1, Q3, [x2, #320]
	mov	V29.16B, V13.16B
	mov	V30.16B, V15.16B
	trn1	V13.2D, V13.2D, V14.2D
	trn1	V15.2D, V15.2D, V16.2D
	trn2	V14.2D, V29.2D, V14.2D
	trn2	V16.2D, V30.2D, V16.2D
	mul	V29.4S, V14.4S, V1.4S
	mul	V30.4S, V16.4S, V3.4S
	sqrdmulh	V25.4S, V14.4S, V0.4S
	sqrdmulh	V26.4S, V16.4S, V2.4S
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	ldp	Q0, Q2, [x1, #352]
	ldp	Q1, Q3, [x2, #352]
	mov	V29.16B, V17.16B
	mov	V30.16B, V19.16B
	trn1	V17.2D, V17.2D, V18.2D
	trn1	V19.2D, V19.2D, V20.2D
	trn2	V18.2D, V29.2D, V18.2D
	trn2	V20.2D, V30.2D, V20.2D
	mul	V29.4S, V18.4S, V1.4S
	mul	V30.4S, V20.4S, V3.4S
	sqrdmulh	V27.4S, V18.4S, V0.4S
	sqrdmulh	V28.4S, V20.4S, V2.4S
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	ldp	Q0, Q2, [x1, #768]
	ldp	Q1, Q3, [x2, #768]
	mov	V29.16B, V5.16B
	mov	V30.16B, V7.16B
	trn1	V5.4S, V5.4S, V6.4S
	trn1	V7.4S, V7.4S, V8.4S
	trn2	V6.4S, V29.4S, V6.4S
	trn2	V8.4S, V30.4S, V8.4S
	mul	V29.4S, V6.4S, V1.4S
	mul	V30.4S, V8.4S, V3.4S
	sqrdmulh	V21.4S, V6.4S, V0.4S
	sqrdmulh	V22.4S, V8.4S, V2.4S
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	ldp	Q0, Q2, [x1, #800]
	ldp	Q1, Q3, [x2, #800]
	mov	V29.16B, V9.16B
	mov	V30.16B, V11.16B
	trn1	V9.4S, V9.4S, V10.4S
	trn1	V11.4S, V11.4S, V12.4S
	trn2	V10.4S, V29.4S, V10.4S
	trn2	V12.4S, V30.4S, V12.4S
	mul	V29.4S, V10.4S, V1.4S
	mul	V30.4S, V12.4S, V3.4S
	sqrdmulh	V23.4S, V10.4S, V0.4S
	sqrdmulh	V24.4S, V12.4S, V2.4S
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	ldp	Q0, Q2, [x1, #832]
	ldp	Q1, Q3, [x2, #832]
	mov	V29.16B, V13.16B
	mov	V30.16B, V15.16B
	trn1	V13.4S, V13.4S, V14.4S
	trn1	V15.4S, V15.4S, V16.4S
	trn2	V14.4S, V29.4S, V14.4S
	trn2	V16.4S, V30.4S, V16.4S
	mul	V29.4S, V14.4S, V1.4S
	mul	V30.4S, V16.4S, V3.4S
	sqrdmulh	V25.4S, V14.4S, V0.4S
	sqrdmulh	V26.4S, V16.4S, V2.4S
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	ldp	Q0, Q2, [x1, #864]
	ldp	Q1, Q3, [x2, #864]
	mov	V29.16B, V17.16B
	mov	V30.16B, V19.16B
	trn1	V17.4S, V17.4S, V18.4S
	trn1	V19.4S, V19.4S, V20.4S
	trn2	V18.4S, V29.4S, V18.4S
	trn2	V20.4S, V30.4S, V20.4S
	mul	V29.4S, V18.4S, V1.4S
	mul	V30.4S, V20.4S, V3.4S
	sqrdmulh	V27.4S, V18.4S, V0.4S
	sqrdmulh	V28.4S, V20.4S, V2.4S
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	trn1	V29.4S, V5.4S, V6.4S
	trn2	V30.4S, V5.4S, V6.4S
	trn1	V5.2D, V29.2D, V30.2D
	trn2	V6.2D, V29.2D, V30.2D
	trn1	V29.4S, V7.4S, V8.4S
	trn2	V30.4S, V7.4S, V8.4S
	trn1	V7.2D, V29.2D, V30.2D
	trn2	V8.2D, V29.2D, V30.2D
	trn1	V29.4S, V9.4S, V10.4S
	trn2	V30.4S, V9.4S, V10.4S
	trn1	V9.2D, V29.2D, V30.2D
	trn2	V10.2D, V29.2D, V30.2D
	trn1	V29.4S, V11.4S, V12.4S
	trn2	V30.4S, V11.4S, V12.4S
	trn1	V11.2D, V29.2D, V30.2D
	trn2	V12.2D, V29.2D, V30.2D
	trn1	V29.4S, V13.4S, V14.4S
	trn2	V30.4S, V13.4S, V14.4S
	trn1	V13.2D, V29.2D, V30.2D
	trn2	V14.2D, V29.2D, V30.2D
	trn1	V29.4S, V15.4S, V16.4S
	trn2	V30.4S, V15.4S, V16.4S
	trn1	V15.2D, V29.2D, V30.2D
	trn2	V16.2D, V29.2D, V30.2D
	trn1	V29.4S, V17.4S, V18.4S
	trn2	V30.4S, V17.4S, V18.4S
	trn1	V17.2D, V29.2D, V30.2D
	trn2	V18.2D, V29.2D, V30.2D
	trn1	V29.4S, V19.4S, V20.4S
	trn2	V30.4S, V19.4S, V20.4S
	trn1	V19.2D, V29.2D, V30.2D
	trn2	V20.2D, V29.2D, V30.2D
	stp	Q5, Q6, [x0]
	stp	Q7, Q8, [x0, #32]
	stp	Q9, Q10, [x0, #64]
	stp	Q11, Q12, [x0, #96]
	stp	Q13, Q14, [x0, #128]
	stp	Q15, Q16, [x0, #160]
	stp	Q17, Q18, [x0, #192]
	stp	Q19, Q20, [x0, #224]
	ldp	Q5, Q6, [x0, #256]
	ldp	Q7, Q8, [x0, #288]
	ldp	Q9, Q10, [x0, #320]
	ldp	Q11, Q12, [x0, #352]
	ldp	Q13, Q14, [x0, #384]
	ldp	Q15, Q16, [x0, #416]
	ldp	Q17, Q18, [x0, #448]
	ldp	Q19, Q20, [x0, #480]
	ldr	Q0, [x1, #80]
	ldr	Q1, [x2, #80]
	mul	V29.4S, V7.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[0]
	sqrdmulh	V21.4S, V7.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[0]
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V11.4S, V1.S[1]
	mul	V30.4S, V12.4S, V1.S[1]
	sqrdmulh	V23.4S, V11.4S, V0.S[1]
	sqrdmulh	V24.4S, V12.4S, V0.S[1]
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V15.4S, V1.S[2]
	mul	V30.4S, V16.4S, V1.S[2]
	sqrdmulh	V25.4S, V15.4S, V0.S[2]
	sqrdmulh	V26.4S, V16.4S, V0.S[2]
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[3]
	mul	V30.4S, V20.4S, V1.S[3]
	sqrdmulh	V27.4S, V19.4S, V0.S[3]
	sqrdmulh	V28.4S, V20.4S, V0.S[3]
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V7.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V11.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V10.4S, V24.4S
	add	V10.4S, V10.4S, V24.4S
	sub	V15.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V14.4S, V26.4S
	add	V14.4S, V14.4S, V26.4S
	sub	V19.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V18.4S, V28.4S
	add	V18.4S, V18.4S, V28.4S
	ldp	Q0, Q2, [x1, #160]
	ldp	Q1, Q3, [x2, #160]
	mul	V29.4S, V6.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[1]
	sqrdmulh	V21.4S, V6.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[1]
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V10.4S, V1.S[2]
	mul	V30.4S, V12.4S, V1.S[3]
	sqrdmulh	V23.4S, V10.4S, V0.S[2]
	sqrdmulh	V24.4S, V12.4S, V0.S[3]
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V14.4S, V3.S[0]
	mul	V30.4S, V16.4S, V3.S[1]
	sqrdmulh	V25.4S, V14.4S, V2.S[0]
	sqrdmulh	V26.4S, V16.4S, V2.S[1]
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V18.4S, V3.S[2]
	mul	V30.4S, V20.4S, V3.S[3]
	sqrdmulh	V27.4S, V18.4S, V2.S[2]
	sqrdmulh	V28.4S, V20.4S, V2.S[3]
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	ldp	Q0, Q2, [x1, #384]
	ldp	Q1, Q3, [x2, #384]
	mov	V29.16B, V5.16B
	mov	V30.16B, V7.16B
	trn1	V5.2D, V5.2D, V6.2D
	trn1	V7.2D, V7.2D, V8.2D
	trn2	V6.2D, V29.2D, V6.2D
	trn2	V8.2D, V30.2D, V8.2D
	mul	V29.4S, V6.4S, V1.4S
	mul	V30.4S, V8.4S, V3.4S
	sqrdmulh	V21.4S, V6.4S, V0.4S
	sqrdmulh	V22.4S, V8.4S, V2.4S
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	ldp	Q0, Q2, [x1, #416]
	ldp	Q1, Q3, [x2, #416]
	mov	V29.16B, V9.16B
	mov	V30.16B, V11.16B
	trn1	V9.2D, V9.2D, V10.2D
	trn1	V11.2D, V11.2D, V12.2D
	trn2	V10.2D, V29.2D, V10.2D
	trn2	V12.2D, V30.2D, V12.2D
	mul	V29.4S, V10.4S, V1.4S
	mul	V30.4S, V12.4S, V3.4S
	sqrdmulh	V23.4S, V10.4S, V0.4S
	sqrdmulh	V24.4S, V12.4S, V2.4S
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	ldp	Q0, Q2, [x1, #448]
	ldp	Q1, Q3, [x2, #448]
	mov	V29.16B, V13.16B
	mov	V30.16B, V15.16B
	trn1	V13.2D, V13.2D, V14.2D
	trn1	V15.2D, V15.2D, V16.2D
	trn2	V14.2D, V29.2D, V14.2D
	trn2	V16.2D, V30.2D, V16.2D
	mul	V29.4S, V14.4S, V1.4S
	mul	V30.4S, V16.4S, V3.4S
	sqrdmulh	V25.4S, V14.4S, V0.4S
	sqrdmulh	V26.4S, V16.4S, V2.4S
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	ldp	Q0, Q2, [x1, #480]
	ldp	Q1, Q3, [x2, #480]
	mov	V29.16B, V17.16B
	mov	V30.16B, V19.16B
	trn1	V17.2D, V17.2D, V18.2D
	trn1	V19.2D, V19.2D, V20.2D
	trn2	V18.2D, V29.2D, V18.2D
	trn2	V20.2D, V30.2D, V20.2D
	mul	V29.4S, V18.4S, V1.4S
	mul	V30.4S, V20.4S, V3.4S
	sqrdmulh	V27.4S, V18.4S, V0.4S
	sqrdmulh	V28.4S, V20.4S, V2.4S
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	ldp	Q0, Q2, [x1, #896]
	ldp	Q1, Q3, [x2, #896]
	mov	V29.16B, V5.16B
	mov	V30.16B, V7.16B
	trn1	V5.4S, V5.4S, V6.4S
	trn1	V7.4S, V7.4S, V8.4S
	trn2	V6.4S, V29.4S, V6.4S
	trn2	V8.4S, V30.4S, V8.4S
	mul	V29.4S, V6.4S, V1.4S
	mul	V30.4S, V8.4S, V3.4S
	sqrdmulh	V21.4S, V6.4S, V0.4S
	sqrdmulh	V22.4S, V8.4S, V2.4S
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	ldp	Q0, Q2, [x1, #928]
	ldp	Q1, Q3, [x2, #928]
	mov	V29.16B, V9.16B
	mov	V30.16B, V11.16B
	trn1	V9.4S, V9.4S, V10.4S
	trn1	V11.4S, V11.4S, V12.4S
	trn2	V10.4S, V29.4S, V10.4S
	trn2	V12.4S, V30.4S, V12.4S
	mul	V29.4S, V10.4S, V1.4S
	mul	V30.4S, V12.4S, V3.4S
	sqrdmulh	V23.4S, V10.4S, V0.4S
	sqrdmulh	V24.4S, V12.4S, V2.4S
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	ldp	Q0, Q2, [x1, #960]
	ldp	Q1, Q3, [x2, #960]
	mov	V29.16B, V13.16B
	mov	V30.16B, V15.16B
	trn1	V13.4S, V13.4S, V14.4S
	trn1	V15.4S, V15.4S, V16.4S
	trn2	V14.4S, V29.4S, V14.4S
	trn2	V16.4S, V30.4S, V16.4S
	mul	V29.4S, V14.4S, V1.4S
	mul	V30.4S, V16.4S, V3.4S
	sqrdmulh	V25.4S, V14.4S, V0.4S
	sqrdmulh	V26.4S, V16.4S, V2.4S
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	ldp	Q0, Q2, [x1, #992]
	ldp	Q1, Q3, [x2, #992]
	mov	V29.16B, V17.16B
	mov	V30.16B, V19.16B
	trn1	V17.4S, V17.4S, V18.4S
	trn1	V19.4S, V19.4S, V20.4S
	trn2	V18.4S, V29.4S, V18.4S
	trn2	V20.4S, V30.4S, V20.4S
	mul	V29.4S, V18.4S, V1.4S
	mul	V30.4S, V20.4S, V3.4S
	sqrdmulh	V27.4S, V18.4S, V0.4S
	sqrdmulh	V28.4S, V20.4S, V2.4S
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	trn1	V29.4S, V5.4S, V6.4S
	trn2	V30.4S, V5.4S, V6.4S
	trn1	V5.2D, V29.2D, V30.2D
	trn2	V6.2D, V29.2D, V30.2D
	trn1	V29.4S, V7.4S, V8.4S
	trn2	V30.4S, V7.4S, V8.4S
	trn1	V7.2D, V29.2D, V30.2D
	trn2	V8.2D, V29.2D, V30.2D
	trn1	V29.4S, V9.4S, V10.4S
	trn2	V30.4S, V9.4S, V10.4S
	trn1	V9.2D, V29.2D, V30.2D
	trn2	V10.2D, V29.2D, V30.2D
	trn1	V29.4S, V11.4S, V12.4S
	trn2	V30.4S, V11.4S, V12.4S
	trn1	V11.2D, V29.2D, V30.2D
	trn2	V12.2D, V29.2D, V30.2D
	trn1	V29.4S, V13.4S, V14.4S
	trn2	V30.4S, V13.4S, V14.4S
	trn1	V13.2D, V29.2D, V30.2D
	trn2	V14.2D, V29.2D, V30.2D
	trn1	V29.4S, V15.4S, V16.4S
	trn2	V30.4S, V15.4S, V16.4S
	trn1	V15.2D, V29.2D, V30.2D
	trn2	V16.2D, V29.2D, V30.2D
	trn1	V29.4S, V17.4S, V18.4S
	trn2	V30.4S, V17.4S, V18.4S
	trn1	V17.2D, V29.2D, V30.2D
	trn2	V18.2D, V29.2D, V30.2D
	trn1	V29.4S, V19.4S, V20.4S
	trn2	V30.4S, V19.4S, V20.4S
	trn1	V19.2D, V29.2D, V30.2D
	trn2	V20.2D, V29.2D, V30.2D
	stp	Q5, Q6, [x0, #256]
	stp	Q7, Q8, [x0, #288]
	stp	Q9, Q10, [x0, #320]
	stp	Q11, Q12, [x0, #352]
	stp	Q13, Q14, [x0, #384]
	stp	Q15, Q16, [x0, #416]
	stp	Q17, Q18, [x0, #448]
	stp	Q19, Q20, [x0, #480]
	ldp	Q5, Q6, [x0, #512]
	ldp	Q7, Q8, [x0, #544]
	ldp	Q9, Q10, [x0, #576]
	ldp	Q11, Q12, [x0, #608]
	ldp	Q13, Q14, [x0, #640]
	ldp	Q15, Q16, [x0, #672]
	ldp	Q17, Q18, [x0, #704]
	ldp	Q19, Q20, [x0, #736]
	ldr	Q0, [x1, #96]
	ldr	Q1, [x2, #96]
	mul	V29.4S, V7.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[0]
	sqrdmulh	V21.4S, V7.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[0]
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V11.4S, V1.S[1]
	mul	V30.4S, V12.4S, V1.S[1]
	sqrdmulh	V23.4S, V11.4S, V0.S[1]
	sqrdmulh	V24.4S, V12.4S, V0.S[1]
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V15.4S, V1.S[2]
	mul	V30.4S, V16.4S, V1.S[2]
	sqrdmulh	V25.4S, V15.4S, V0.S[2]
	sqrdmulh	V26.4S, V16.4S, V0.S[2]
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[3]
	mul	V30.4S, V20.4S, V1.S[3]
	sqrdmulh	V27.4S, V19.4S, V0.S[3]
	sqrdmulh	V28.4S, V20.4S, V0.S[3]
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V7.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V11.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V10.4S, V24.4S
	add	V10.4S, V10.4S, V24.4S
	sub	V15.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V14.4S, V26.4S
	add	V14.4S, V14.4S, V26.4S
	sub	V19.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V18.4S, V28.4S
	add	V18.4S, V18.4S, V28.4S
	ldp	Q0, Q2, [x1, #192]
	ldp	Q1, Q3, [x2, #192]
	mul	V29.4S, V6.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[1]
	sqrdmulh	V21.4S, V6.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[1]
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V10.4S, V1.S[2]
	mul	V30.4S, V12.4S, V1.S[3]
	sqrdmulh	V23.4S, V10.4S, V0.S[2]
	sqrdmulh	V24.4S, V12.4S, V0.S[3]
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V14.4S, V3.S[0]
	mul	V30.4S, V16.4S, V3.S[1]
	sqrdmulh	V25.4S, V14.4S, V2.S[0]
	sqrdmulh	V26.4S, V16.4S, V2.S[1]
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V18.4S, V3.S[2]
	mul	V30.4S, V20.4S, V3.S[3]
	sqrdmulh	V27.4S, V18.4S, V2.S[2]
	sqrdmulh	V28.4S, V20.4S, V2.S[3]
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	ldp	Q0, Q2, [x1, #512]
	ldp	Q1, Q3, [x2, #512]
	mov	V29.16B, V5.16B
	mov	V30.16B, V7.16B
	trn1	V5.2D, V5.2D, V6.2D
	trn1	V7.2D, V7.2D, V8.2D
	trn2	V6.2D, V29.2D, V6.2D
	trn2	V8.2D, V30.2D, V8.2D
	mul	V29.4S, V6.4S, V1.4S
	mul	V30.4S, V8.4S, V3.4S
	sqrdmulh	V21.4S, V6.4S, V0.4S
	sqrdmulh	V22.4S, V8.4S, V2.4S
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	ldp	Q0, Q2, [x1, #544]
	ldp	Q1, Q3, [x2, #544]
	mov	V29.16B, V9.16B
	mov	V30.16B, V11.16B
	trn1	V9.2D, V9.2D, V10.2D
	trn1	V11.2D, V11.2D, V12.2D
	trn2	V10.2D, V29.2D, V10.2D
	trn2	V12.2D, V30.2D, V12.2D
	mul	V29.4S, V10.4S, V1.4S
	mul	V30.4S, V12.4S, V3.4S
	sqrdmulh	V23.4S, V10.4S, V0.4S
	sqrdmulh	V24.4S, V12.4S, V2.4S
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	ldp	Q0, Q2, [x1, #576]
	ldp	Q1, Q3, [x2, #576]
	mov	V29.16B, V13.16B
	mov	V30.16B, V15.16B
	trn1	V13.2D, V13.2D, V14.2D
	trn1	V15.2D, V15.2D, V16.2D
	trn2	V14.2D, V29.2D, V14.2D
	trn2	V16.2D, V30.2D, V16.2D
	mul	V29.4S, V14.4S, V1.4S
	mul	V30.4S, V16.4S, V3.4S
	sqrdmulh	V25.4S, V14.4S, V0.4S
	sqrdmulh	V26.4S, V16.4S, V2.4S
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	ldp	Q0, Q2, [x1, #608]
	ldp	Q1, Q3, [x2, #608]
	mov	V29.16B, V17.16B
	mov	V30.16B, V19.16B
	trn1	V17.2D, V17.2D, V18.2D
	trn1	V19.2D, V19.2D, V20.2D
	trn2	V18.2D, V29.2D, V18.2D
	trn2	V20.2D, V30.2D, V20.2D
	mul	V29.4S, V18.4S, V1.4S
	mul	V30.4S, V20.4S, V3.4S
	sqrdmulh	V27.4S, V18.4S, V0.4S
	sqrdmulh	V28.4S, V20.4S, V2.4S
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	ldr	Q0, [x1, #1024]
	ldr	Q2, [x1, #1040]
	ldr	Q1, [x2, #1024]
	ldr	Q3, [x2, #1040]
	mov	V29.16B, V5.16B
	mov	V30.16B, V7.16B
	trn1	V5.4S, V5.4S, V6.4S
	trn1	V7.4S, V7.4S, V8.4S
	trn2	V6.4S, V29.4S, V6.4S
	trn2	V8.4S, V30.4S, V8.4S
	mul	V29.4S, V6.4S, V1.4S
	mul	V30.4S, V8.4S, V3.4S
	sqrdmulh	V21.4S, V6.4S, V0.4S
	sqrdmulh	V22.4S, V8.4S, V2.4S
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	ldr	Q0, [x1, #1056]
	ldr	Q2, [x1, #1072]
	ldr	Q1, [x2, #1056]
	ldr	Q3, [x2, #1072]
	mov	V29.16B, V9.16B
	mov	V30.16B, V11.16B
	trn1	V9.4S, V9.4S, V10.4S
	trn1	V11.4S, V11.4S, V12.4S
	trn2	V10.4S, V29.4S, V10.4S
	trn2	V12.4S, V30.4S, V12.4S
	mul	V29.4S, V10.4S, V1.4S
	mul	V30.4S, V12.4S, V3.4S
	sqrdmulh	V23.4S, V10.4S, V0.4S
	sqrdmulh	V24.4S, V12.4S, V2.4S
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	ldr	Q0, [x1, #1088]
	ldr	Q2, [x1, #1104]
	ldr	Q1, [x2, #1088]
	ldr	Q3, [x2, #1104]
	mov	V29.16B, V13.16B
	mov	V30.16B, V15.16B
	trn1	V13.4S, V13.4S, V14.4S
	trn1	V15.4S, V15.4S, V16.4S
	trn2	V14.4S, V29.4S, V14.4S
	trn2	V16.4S, V30.4S, V16.4S
	mul	V29.4S, V14.4S, V1.4S
	mul	V30.4S, V16.4S, V3.4S
	sqrdmulh	V25.4S, V14.4S, V0.4S
	sqrdmulh	V26.4S, V16.4S, V2.4S
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	ldr	Q0, [x1, #1120]
	ldr	Q2, [x1, #1136]
	ldr	Q1, [x2, #1120]
	ldr	Q3, [x2, #1136]
	mov	V29.16B, V17.16B
	mov	V30.16B, V19.16B
	trn1	V17.4S, V17.4S, V18.4S
	trn1	V19.4S, V19.4S, V20.4S
	trn2	V18.4S, V29.4S, V18.4S
	trn2	V20.4S, V30.4S, V20.4S
	mul	V29.4S, V18.4S, V1.4S
	mul	V30.4S, V20.4S, V3.4S
	sqrdmulh	V27.4S, V18.4S, V0.4S
	sqrdmulh	V28.4S, V20.4S, V2.4S
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	trn1	V29.4S, V5.4S, V6.4S
	trn2	V30.4S, V5.4S, V6.4S
	trn1	V5.2D, V29.2D, V30.2D
	trn2	V6.2D, V29.2D, V30.2D
	trn1	V29.4S, V7.4S, V8.4S
	trn2	V30.4S, V7.4S, V8.4S
	trn1	V7.2D, V29.2D, V30.2D
	trn2	V8.2D, V29.2D, V30.2D
	trn1	V29.4S, V9.4S, V10.4S
	trn2	V30.4S, V9.4S, V10.4S
	trn1	V9.2D, V29.2D, V30.2D
	trn2	V10.2D, V29.2D, V30.2D
	trn1	V29.4S, V11.4S, V12.4S
	trn2	V30.4S, V11.4S, V12.4S
	trn1	V11.2D, V29.2D, V30.2D
	trn2	V12.2D, V29.2D, V30.2D
	trn1	V29.4S, V13.4S, V14.4S
	trn2	V30.4S, V13.4S, V14.4S
	trn1	V13.2D, V29.2D, V30.2D
	trn2	V14.2D, V29.2D, V30.2D
	trn1	V29.4S, V15.4S, V16.4S
	trn2	V30.4S, V15.4S, V16.4S
	trn1	V15.2D, V29.2D, V30.2D
	trn2	V16.2D, V29.2D, V30.2D
	trn1	V29.4S, V17.4S, V18.4S
	trn2	V30.4S, V17.4S, V18.4S
	trn1	V17.2D, V29.2D, V30.2D
	trn2	V18.2D, V29.2D, V30.2D
	trn1	V29.4S, V19.4S, V20.4S
	trn2	V30.4S, V19.4S, V20.4S
	trn1	V19.2D, V29.2D, V30.2D
	trn2	V20.2D, V29.2D, V30.2D
	stp	Q5, Q6, [x0, #512]
	stp	Q7, Q8, [x0, #544]
	stp	Q9, Q10, [x0, #576]
	stp	Q11, Q12, [x0, #608]
	stp	Q13, Q14, [x0, #640]
	stp	Q15, Q16, [x0, #672]
	stp	Q17, Q18, [x0, #704]
	stp	Q19, Q20, [x0, #736]
	ldp	Q5, Q6, [x0, #768]
	ldp	Q7, Q8, [x0, #800]
	ldp	Q9, Q10, [x0, #832]
	ldp	Q11, Q12, [x0, #864]
	ldp	Q13, Q14, [x0, #896]
	ldp	Q15, Q16, [x0, #928]
	ldp	Q17, Q18, [x0, #960]
	ldp	Q19, Q20, [x0, #992]
	ldr	Q0, [x1, #112]
	ldr	Q1, [x2, #112]
	mul	V29.4S, V7.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[0]
	sqrdmulh	V21.4S, V7.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[0]
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V11.4S, V1.S[1]
	mul	V30.4S, V12.4S, V1.S[1]
	sqrdmulh	V23.4S, V11.4S, V0.S[1]
	sqrdmulh	V24.4S, V12.4S, V0.S[1]
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V15.4S, V1.S[2]
	mul	V30.4S, V16.4S, V1.S[2]
	sqrdmulh	V25.4S, V15.4S, V0.S[2]
	sqrdmulh	V26.4S, V16.4S, V0.S[2]
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V19.4S, V1.S[3]
	mul	V30.4S, V20.4S, V1.S[3]
	sqrdmulh	V27.4S, V19.4S, V0.S[3]
	sqrdmulh	V28.4S, V20.4S, V0.S[3]
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V7.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V6.4S, V22.4S
	add	V6.4S, V6.4S, V22.4S
	sub	V11.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V10.4S, V24.4S
	add	V10.4S, V10.4S, V24.4S
	sub	V15.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V14.4S, V26.4S
	add	V14.4S, V14.4S, V26.4S
	sub	V19.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V18.4S, V28.4S
	add	V18.4S, V18.4S, V28.4S
	ldp	Q0, Q2, [x1, #224]
	ldp	Q1, Q3, [x2, #224]
	mul	V29.4S, V6.4S, V1.S[0]
	mul	V30.4S, V8.4S, V1.S[1]
	sqrdmulh	V21.4S, V6.4S, V0.S[0]
	sqrdmulh	V22.4S, V8.4S, V0.S[1]
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	mul	V29.4S, V10.4S, V1.S[2]
	mul	V30.4S, V12.4S, V1.S[3]
	sqrdmulh	V23.4S, V10.4S, V0.S[2]
	sqrdmulh	V24.4S, V12.4S, V0.S[3]
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	mul	V29.4S, V14.4S, V3.S[0]
	mul	V30.4S, V16.4S, V3.S[1]
	sqrdmulh	V25.4S, V14.4S, V2.S[0]
	sqrdmulh	V26.4S, V16.4S, V2.S[1]
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	mul	V29.4S, V18.4S, V3.S[2]
	mul	V30.4S, V20.4S, V3.S[3]
	sqrdmulh	V27.4S, V18.4S, V2.S[2]
	sqrdmulh	V28.4S, V20.4S, V2.S[3]
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	ldp	Q0, Q2, [x1, #640]
	ldp	Q1, Q3, [x2, #640]
	mov	V29.16B, V5.16B
	mov	V30.16B, V7.16B
	trn1	V5.2D, V5.2D, V6.2D
	trn1	V7.2D, V7.2D, V8.2D
	trn2	V6.2D, V29.2D, V6.2D
	trn2	V8.2D, V30.2D, V8.2D
	mul	V29.4S, V6.4S, V1.4S
	mul	V30.4S, V8.4S, V3.4S
	sqrdmulh	V21.4S, V6.4S, V0.4S
	sqrdmulh	V22.4S, V8.4S, V2.4S
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	ldp	Q0, Q2, [x1, #672]
	ldp	Q1, Q3, [x2, #672]
	mov	V29.16B, V9.16B
	mov	V30.16B, V11.16B
	trn1	V9.2D, V9.2D, V10.2D
	trn1	V11.2D, V11.2D, V12.2D
	trn2	V10.2D, V29.2D, V10.2D
	trn2	V12.2D, V30.2D, V12.2D
	mul	V29.4S, V10.4S, V1.4S
	mul	V30.4S, V12.4S, V3.4S
	sqrdmulh	V23.4S, V10.4S, V0.4S
	sqrdmulh	V24.4S, V12.4S, V2.4S
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	ldp	Q0, Q2, [x1, #704]
	ldp	Q1, Q3, [x2, #704]
	mov	V29.16B, V13.16B
	mov	V30.16B, V15.16B
	trn1	V13.2D, V13.2D, V14.2D
	trn1	V15.2D, V15.2D, V16.2D
	trn2	V14.2D, V29.2D, V14.2D
	trn2	V16.2D, V30.2D, V16.2D
	mul	V29.4S, V14.4S, V1.4S
	mul	V30.4S, V16.4S, V3.4S
	sqrdmulh	V25.4S, V14.4S, V0.4S
	sqrdmulh	V26.4S, V16.4S, V2.4S
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	ldp	Q0, Q2, [x1, #736]
	ldp	Q1, Q3, [x2, #736]
	mov	V29.16B, V17.16B
	mov	V30.16B, V19.16B
	trn1	V17.2D, V17.2D, V18.2D
	trn1	V19.2D, V19.2D, V20.2D
	trn2	V18.2D, V29.2D, V18.2D
	trn2	V20.2D, V30.2D, V20.2D
	mul	V29.4S, V18.4S, V1.4S
	mul	V30.4S, V20.4S, V3.4S
	sqrdmulh	V27.4S, V18.4S, V0.4S
	sqrdmulh	V28.4S, V20.4S, V2.4S
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	ldr	Q0, [x1, #1152]
	ldr	Q2, [x1, #1168]
	ldr	Q1, [x2, #1152]
	ldr	Q3, [x2, #1168]
	mov	V29.16B, V5.16B
	mov	V30.16B, V7.16B
	trn1	V5.4S, V5.4S, V6.4S
	trn1	V7.4S, V7.4S, V8.4S
	trn2	V6.4S, V29.4S, V6.4S
	trn2	V8.4S, V30.4S, V8.4S
	mul	V29.4S, V6.4S, V1.4S
	mul	V30.4S, V8.4S, V3.4S
	sqrdmulh	V21.4S, V6.4S, V0.4S
	sqrdmulh	V22.4S, V8.4S, V2.4S
	sqrdmlsh	V21.4S, V29.4S, V4.S[0]
	sqrdmlsh	V22.4S, V30.4S, V4.S[0]
	sshr	V21.4S, V21.4S, #1
	sshr	V22.4S, V22.4S, #1
	ldr	Q0, [x1, #1184]
	ldr	Q2, [x1, #1200]
	ldr	Q1, [x2, #1184]
	ldr	Q3, [x2, #1200]
	mov	V29.16B, V9.16B
	mov	V30.16B, V11.16B
	trn1	V9.4S, V9.4S, V10.4S
	trn1	V11.4S, V11.4S, V12.4S
	trn2	V10.4S, V29.4S, V10.4S
	trn2	V12.4S, V30.4S, V12.4S
	mul	V29.4S, V10.4S, V1.4S
	mul	V30.4S, V12.4S, V3.4S
	sqrdmulh	V23.4S, V10.4S, V0.4S
	sqrdmulh	V24.4S, V12.4S, V2.4S
	sqrdmlsh	V23.4S, V29.4S, V4.S[0]
	sqrdmlsh	V24.4S, V30.4S, V4.S[0]
	sshr	V23.4S, V23.4S, #1
	sshr	V24.4S, V24.4S, #1
	ldr	Q0, [x1, #1216]
	ldr	Q2, [x1, #1232]
	ldr	Q1, [x2, #1216]
	ldr	Q3, [x2, #1232]
	mov	V29.16B, V13.16B
	mov	V30.16B, V15.16B
	trn1	V13.4S, V13.4S, V14.4S
	trn1	V15.4S, V15.4S, V16.4S
	trn2	V14.4S, V29.4S, V14.4S
	trn2	V16.4S, V30.4S, V16.4S
	mul	V29.4S, V14.4S, V1.4S
	mul	V30.4S, V16.4S, V3.4S
	sqrdmulh	V25.4S, V14.4S, V0.4S
	sqrdmulh	V26.4S, V16.4S, V2.4S
	sqrdmlsh	V25.4S, V29.4S, V4.S[0]
	sqrdmlsh	V26.4S, V30.4S, V4.S[0]
	sshr	V25.4S, V25.4S, #1
	sshr	V26.4S, V26.4S, #1
	ldr	Q0, [x1, #1248]
	ldr	Q2, [x1, #1264]
	ldr	Q1, [x2, #1248]
	ldr	Q3, [x2, #1264]
	mov	V29.16B, V17.16B
	mov	V30.16B, V19.16B
	trn1	V17.4S, V17.4S, V18.4S
	trn1	V19.4S, V19.4S, V20.4S
	trn2	V18.4S, V29.4S, V18.4S
	trn2	V20.4S, V30.4S, V20.4S
	mul	V29.4S, V18.4S, V1.4S
	mul	V30.4S, V20.4S, V3.4S
	sqrdmulh	V27.4S, V18.4S, V0.4S
	sqrdmulh	V28.4S, V20.4S, V2.4S
	sqrdmlsh	V27.4S, V29.4S, V4.S[0]
	sqrdmlsh	V28.4S, V30.4S, V4.S[0]
	sshr	V27.4S, V27.4S, #1
	sshr	V28.4S, V28.4S, #1
	sub	V6.4S, V5.4S, V21.4S
	add	V5.4S, V5.4S, V21.4S
	sub	V8.4S, V7.4S, V22.4S
	add	V7.4S, V7.4S, V22.4S
	sub	V10.4S, V9.4S, V23.4S
	add	V9.4S, V9.4S, V23.4S
	sub	V12.4S, V11.4S, V24.4S
	add	V11.4S, V11.4S, V24.4S
	sub	V14.4S, V13.4S, V25.4S
	add	V13.4S, V13.4S, V25.4S
	sub	V16.4S, V15.4S, V26.4S
	add	V15.4S, V15.4S, V26.4S
	sub	V18.4S, V17.4S, V27.4S
	add	V17.4S, V17.4S, V27.4S
	sub	V20.4S, V19.4S, V28.4S
	add	V19.4S, V19.4S, V28.4S
	trn1	V29.4S, V5.4S, V6.4S
	trn2	V30.4S, V5.4S, V6.4S
	trn1	V5.2D, V29.2D, V30.2D
	trn2	V6.2D, V29.2D, V30.2D
	trn1	V29.4S, V7.4S, V8.4S
	trn2	V30.4S, V7.4S, V8.4S
	trn1	V7.2D, V29.2D, V30.2D
	trn2	V8.2D, V29.2D, V30.2D
	trn1	V29.4S, V9.4S, V10.4S
	trn2	V30.4S, V9.4S, V10.4S
	trn1	V9.2D, V29.2D, V30.2D
	trn2	V10.2D, V29.2D, V30.2D
	trn1	V29.4S, V11.4S, V12.4S
	trn2	V30.4S, V11.4S, V12.4S
	trn1	V11.2D, V29.2D, V30.2D
	trn2	V12.2D, V29.2D, V30.2D
	trn1	V29.4S, V13.4S, V14.4S
	trn2	V30.4S, V13.4S, V14.4S
	trn1	V13.2D, V29.2D, V30.2D
	trn2	V14.2D, V29.2D, V30.2D
	trn1	V29.4S, V15.4S, V16.4S
	trn2	V30.4S, V15.4S, V16.4S
	trn1	V15.2D, V29.2D, V30.2D
	trn2	V16.2D, V29.2D, V30.2D
	trn1	V29.4S, V17.4S, V18.4S
	trn2	V30.4S, V17.4S, V18.4S
	trn1	V17.2D, V29.2D, V30.2D
	trn2	V18.2D, V29.2D, V30.2D
	trn1	V29.4S, V19.4S, V20.4S
	trn2	V30.4S, V19.4S, V20.4S
	trn1	V19.2D, V29.2D, V30.2D
	trn2	V20.2D, V29.2D, V30.2D
	stp	Q5, Q6, [x0, #768]
	stp	Q7, Q8, [x0, #800]
	stp	Q9, Q10, [x0, #832]
	stp	Q11, Q12, [x0, #864]
	stp	Q13, Q14, [x0, #896]
	stp	Q15, Q16, [x0, #928]
	stp	Q17, Q18, [x0, #960]
	stp	Q19, Q20, [x0, #992]
	ldp	D8, D9, [x29, #16]
	ldp	D10, D11, [x29, #32]
	ldp	D12, D13, [x29, #48]
	ldp	D14, D15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
	ENDP
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mldsa_invntt_sqrdmlsh_neon
mldsa_invntt_sqrdmlsh_neon PROC
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	stp	D10, D11, [x29, #32]
	stp	D12, D13, [x29, #48]
	stp	D14, D15, [x29, #64]
	adrp	x1, L_mldsa_aarch64_zetas_inv
	add	x1, x1, L_mldsa_aarch64_zetas_inv
	adrp	x2, L_mldsa_aarch64_zetas_inv_qinv
	add	x2, x2, L_mldsa_aarch64_zetas_inv_qinv
	adrp	x3, L_mldsa_aarch64_consts
	add	x3, x3, L_mldsa_aarch64_consts
	ldr	Q4, [x3]
	ldp	Q5, Q6, [x0]
	ldp	Q7, Q8, [x0, #32]
	ldp	Q9, Q10, [x0, #64]
	ldp	Q11, Q12, [x0, #96]
	ldp	Q13, Q14, [x0, #128]
	ldp	Q15, Q16, [x0, #160]
	ldp	Q17, Q18, [x0, #192]
	ldp	Q19, Q20, [x0, #224]
	ldp	Q0, Q1, [x1]
	ldp	Q2, Q3, [x2]
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V6.4S, V22.4S, V0.4S
	sqrdmulh	V8.4S, V24.4S, V1.4S
	sqrdmlsh	V6.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V23.4S, V4.S[0]
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	ldp	Q0, Q1, [x1, #32]
	ldp	Q2, Q3, [x2, #32]
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V10.4S, V22.4S, V0.4S
	sqrdmulh	V12.4S, V24.4S, V1.4S
	sqrdmlsh	V10.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	ldp	Q0, Q1, [x1, #64]
	ldp	Q2, Q3, [x2, #64]
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V14.4S, V22.4S, V0.4S
	sqrdmulh	V16.4S, V24.4S, V1.4S
	sqrdmlsh	V14.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	ldp	Q0, Q1, [x1, #96]
	ldp	Q2, Q3, [x2, #96]
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V18.4S, V22.4S, V0.4S
	sqrdmulh	V20.4S, V24.4S, V1.4S
	sqrdmlsh	V18.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldp	Q0, Q1, [x1, #512]
	ldp	Q2, Q3, [x2, #512]
	mov	V21.16B, V5.16B
	mov	V22.16B, V7.16B
	trn1	V5.4S, V5.4S, V6.4S
	trn1	V7.4S, V7.4S, V8.4S
	trn2	V6.4S, V21.4S, V6.4S
	trn2	V8.4S, V22.4S, V8.4S
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V6.4S, V22.4S, V0.4S
	sqrdmulh	V8.4S, V24.4S, V1.4S
	sqrdmlsh	V6.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V23.4S, V4.S[0]
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	ldp	Q0, Q1, [x1, #544]
	ldp	Q2, Q3, [x2, #544]
	mov	V21.16B, V9.16B
	mov	V22.16B, V11.16B
	trn1	V9.4S, V9.4S, V10.4S
	trn1	V11.4S, V11.4S, V12.4S
	trn2	V10.4S, V21.4S, V10.4S
	trn2	V12.4S, V22.4S, V12.4S
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V10.4S, V22.4S, V0.4S
	sqrdmulh	V12.4S, V24.4S, V1.4S
	sqrdmlsh	V10.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	ldp	Q0, Q1, [x1, #576]
	ldp	Q2, Q3, [x2, #576]
	mov	V21.16B, V13.16B
	mov	V22.16B, V15.16B
	trn1	V13.4S, V13.4S, V14.4S
	trn1	V15.4S, V15.4S, V16.4S
	trn2	V14.4S, V21.4S, V14.4S
	trn2	V16.4S, V22.4S, V16.4S
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V14.4S, V22.4S, V0.4S
	sqrdmulh	V16.4S, V24.4S, V1.4S
	sqrdmlsh	V14.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	ldp	Q0, Q1, [x1, #608]
	ldp	Q2, Q3, [x2, #608]
	mov	V21.16B, V17.16B
	mov	V22.16B, V19.16B
	trn1	V17.4S, V17.4S, V18.4S
	trn1	V19.4S, V19.4S, V20.4S
	trn2	V18.4S, V21.4S, V18.4S
	trn2	V20.4S, V22.4S, V20.4S
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V18.4S, V22.4S, V0.4S
	sqrdmulh	V20.4S, V24.4S, V1.4S
	sqrdmlsh	V18.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1024]
	ldr	Q1, [x1, #1040]
	ldr	Q2, [x2, #1024]
	ldr	Q3, [x2, #1040]
	mov	V21.16B, V5.16B
	mov	V22.16B, V7.16B
	trn1	V5.2D, V5.2D, V6.2D
	trn1	V7.2D, V7.2D, V8.2D
	trn2	V6.2D, V21.2D, V6.2D
	trn2	V8.2D, V22.2D, V8.2D
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V6.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[1]
	sqrdmlsh	V6.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V23.4S, V4.S[0]
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	mov	V21.16B, V9.16B
	mov	V22.16B, V11.16B
	trn1	V9.2D, V9.2D, V10.2D
	trn1	V11.2D, V11.2D, V12.2D
	trn2	V10.2D, V21.2D, V10.2D
	trn2	V12.2D, V22.2D, V12.2D
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V10.4S, V22.4S, V0.S[2]
	sqrdmulh	V12.4S, V24.4S, V0.S[3]
	sqrdmlsh	V10.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	mov	V21.16B, V13.16B
	mov	V22.16B, V15.16B
	trn1	V13.2D, V13.2D, V14.2D
	trn1	V15.2D, V15.2D, V16.2D
	trn2	V14.2D, V21.2D, V14.2D
	trn2	V16.2D, V22.2D, V16.2D
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V3.S[0]
	mul	V23.4S, V24.4S, V3.S[1]
	sqrdmulh	V14.4S, V22.4S, V1.S[0]
	sqrdmulh	V16.4S, V24.4S, V1.S[1]
	sqrdmlsh	V14.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	mov	V21.16B, V17.16B
	mov	V22.16B, V19.16B
	trn1	V17.2D, V17.2D, V18.2D
	trn1	V19.2D, V19.2D, V20.2D
	trn2	V18.2D, V21.2D, V18.2D
	trn2	V20.2D, V22.2D, V20.2D
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V3.S[2]
	mul	V23.4S, V24.4S, V3.S[3]
	sqrdmulh	V18.4S, V22.4S, V1.S[2]
	sqrdmulh	V20.4S, V24.4S, V1.S[3]
	sqrdmlsh	V18.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1152]
	ldr	Q2, [x2, #1152]
	sub	V22.4S, V5.4S, V7.4S
	sub	V24.4S, V6.4S, V8.4S
	add	V5.4S, V5.4S, V7.4S
	add	V6.4S, V6.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V7.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[0]
	sqrdmlsh	V7.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V23.4S, V4.S[0]
	sshr	V7.4S, V7.4S, #1
	sshr	V8.4S, V8.4S, #1
	sub	V22.4S, V9.4S, V11.4S
	sub	V24.4S, V10.4S, V12.4S
	add	V9.4S, V9.4S, V11.4S
	add	V10.4S, V10.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V11.4S, V22.4S, V0.S[1]
	sqrdmulh	V12.4S, V24.4S, V0.S[1]
	sqrdmlsh	V11.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V15.4S
	sub	V24.4S, V14.4S, V16.4S
	add	V13.4S, V13.4S, V15.4S
	add	V14.4S, V14.4S, V16.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V15.4S, V22.4S, V0.S[2]
	sqrdmulh	V16.4S, V24.4S, V0.S[2]
	sqrdmlsh	V15.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V15.4S, V15.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V17.4S, V19.4S
	sub	V24.4S, V18.4S, V20.4S
	add	V17.4S, V17.4S, V19.4S
	add	V18.4S, V18.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[3]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V19.4S, V22.4S, V0.S[3]
	sqrdmulh	V20.4S, V24.4S, V0.S[3]
	sqrdmlsh	V19.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	stp	Q5, Q6, [x0]
	stp	Q7, Q8, [x0, #32]
	stp	Q9, Q10, [x0, #64]
	stp	Q11, Q12, [x0, #96]
	stp	Q13, Q14, [x0, #128]
	stp	Q15, Q16, [x0, #160]
	stp	Q17, Q18, [x0, #192]
	stp	Q19, Q20, [x0, #224]
	ldp	Q5, Q6, [x0, #256]
	ldp	Q7, Q8, [x0, #288]
	ldp	Q9, Q10, [x0, #320]
	ldp	Q11, Q12, [x0, #352]
	ldp	Q13, Q14, [x0, #384]
	ldp	Q15, Q16, [x0, #416]
	ldp	Q17, Q18, [x0, #448]
	ldp	Q19, Q20, [x0, #480]
	ldp	Q0, Q1, [x1, #128]
	ldp	Q2, Q3, [x2, #128]
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V6.4S, V22.4S, V0.4S
	sqrdmulh	V8.4S, V24.4S, V1.4S
	sqrdmlsh	V6.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V23.4S, V4.S[0]
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	ldp	Q0, Q1, [x1, #160]
	ldp	Q2, Q3, [x2, #160]
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V10.4S, V22.4S, V0.4S
	sqrdmulh	V12.4S, V24.4S, V1.4S
	sqrdmlsh	V10.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	ldp	Q0, Q1, [x1, #192]
	ldp	Q2, Q3, [x2, #192]
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V14.4S, V22.4S, V0.4S
	sqrdmulh	V16.4S, V24.4S, V1.4S
	sqrdmlsh	V14.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	ldp	Q0, Q1, [x1, #224]
	ldp	Q2, Q3, [x2, #224]
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V18.4S, V22.4S, V0.4S
	sqrdmulh	V20.4S, V24.4S, V1.4S
	sqrdmlsh	V18.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldp	Q0, Q1, [x1, #640]
	ldp	Q2, Q3, [x2, #640]
	mov	V21.16B, V5.16B
	mov	V22.16B, V7.16B
	trn1	V5.4S, V5.4S, V6.4S
	trn1	V7.4S, V7.4S, V8.4S
	trn2	V6.4S, V21.4S, V6.4S
	trn2	V8.4S, V22.4S, V8.4S
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V6.4S, V22.4S, V0.4S
	sqrdmulh	V8.4S, V24.4S, V1.4S
	sqrdmlsh	V6.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V23.4S, V4.S[0]
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	ldp	Q0, Q1, [x1, #672]
	ldp	Q2, Q3, [x2, #672]
	mov	V21.16B, V9.16B
	mov	V22.16B, V11.16B
	trn1	V9.4S, V9.4S, V10.4S
	trn1	V11.4S, V11.4S, V12.4S
	trn2	V10.4S, V21.4S, V10.4S
	trn2	V12.4S, V22.4S, V12.4S
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V10.4S, V22.4S, V0.4S
	sqrdmulh	V12.4S, V24.4S, V1.4S
	sqrdmlsh	V10.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	ldp	Q0, Q1, [x1, #704]
	ldp	Q2, Q3, [x2, #704]
	mov	V21.16B, V13.16B
	mov	V22.16B, V15.16B
	trn1	V13.4S, V13.4S, V14.4S
	trn1	V15.4S, V15.4S, V16.4S
	trn2	V14.4S, V21.4S, V14.4S
	trn2	V16.4S, V22.4S, V16.4S
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V14.4S, V22.4S, V0.4S
	sqrdmulh	V16.4S, V24.4S, V1.4S
	sqrdmlsh	V14.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	ldp	Q0, Q1, [x1, #736]
	ldp	Q2, Q3, [x2, #736]
	mov	V21.16B, V17.16B
	mov	V22.16B, V19.16B
	trn1	V17.4S, V17.4S, V18.4S
	trn1	V19.4S, V19.4S, V20.4S
	trn2	V18.4S, V21.4S, V18.4S
	trn2	V20.4S, V22.4S, V20.4S
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V18.4S, V22.4S, V0.4S
	sqrdmulh	V20.4S, V24.4S, V1.4S
	sqrdmlsh	V18.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1056]
	ldr	Q1, [x1, #1072]
	ldr	Q2, [x2, #1056]
	ldr	Q3, [x2, #1072]
	mov	V21.16B, V5.16B
	mov	V22.16B, V7.16B
	trn1	V5.2D, V5.2D, V6.2D
	trn1	V7.2D, V7.2D, V8.2D
	trn2	V6.2D, V21.2D, V6.2D
	trn2	V8.2D, V22.2D, V8.2D
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V6.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[1]
	sqrdmlsh	V6.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V23.4S, V4.S[0]
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	mov	V21.16B, V9.16B
	mov	V22.16B, V11.16B
	trn1	V9.2D, V9.2D, V10.2D
	trn1	V11.2D, V11.2D, V12.2D
	trn2	V10.2D, V21.2D, V10.2D
	trn2	V12.2D, V22.2D, V12.2D
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V10.4S, V22.4S, V0.S[2]
	sqrdmulh	V12.4S, V24.4S, V0.S[3]
	sqrdmlsh	V10.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	mov	V21.16B, V13.16B
	mov	V22.16B, V15.16B
	trn1	V13.2D, V13.2D, V14.2D
	trn1	V15.2D, V15.2D, V16.2D
	trn2	V14.2D, V21.2D, V14.2D
	trn2	V16.2D, V22.2D, V16.2D
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V3.S[0]
	mul	V23.4S, V24.4S, V3.S[1]
	sqrdmulh	V14.4S, V22.4S, V1.S[0]
	sqrdmulh	V16.4S, V24.4S, V1.S[1]
	sqrdmlsh	V14.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	mov	V21.16B, V17.16B
	mov	V22.16B, V19.16B
	trn1	V17.2D, V17.2D, V18.2D
	trn1	V19.2D, V19.2D, V20.2D
	trn2	V18.2D, V21.2D, V18.2D
	trn2	V20.2D, V22.2D, V20.2D
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V3.S[2]
	mul	V23.4S, V24.4S, V3.S[3]
	sqrdmulh	V18.4S, V22.4S, V1.S[2]
	sqrdmulh	V20.4S, V24.4S, V1.S[3]
	sqrdmlsh	V18.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1168]
	ldr	Q2, [x2, #1168]
	sub	V22.4S, V5.4S, V7.4S
	sub	V24.4S, V6.4S, V8.4S
	add	V5.4S, V5.4S, V7.4S
	add	V6.4S, V6.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V7.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[0]
	sqrdmlsh	V7.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V23.4S, V4.S[0]
	sshr	V7.4S, V7.4S, #1
	sshr	V8.4S, V8.4S, #1
	sub	V22.4S, V9.4S, V11.4S
	sub	V24.4S, V10.4S, V12.4S
	add	V9.4S, V9.4S, V11.4S
	add	V10.4S, V10.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V11.4S, V22.4S, V0.S[1]
	sqrdmulh	V12.4S, V24.4S, V0.S[1]
	sqrdmlsh	V11.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V15.4S
	sub	V24.4S, V14.4S, V16.4S
	add	V13.4S, V13.4S, V15.4S
	add	V14.4S, V14.4S, V16.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V15.4S, V22.4S, V0.S[2]
	sqrdmulh	V16.4S, V24.4S, V0.S[2]
	sqrdmlsh	V15.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V15.4S, V15.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V17.4S, V19.4S
	sub	V24.4S, V18.4S, V20.4S
	add	V17.4S, V17.4S, V19.4S
	add	V18.4S, V18.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[3]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V19.4S, V22.4S, V0.S[3]
	sqrdmulh	V20.4S, V24.4S, V0.S[3]
	sqrdmlsh	V19.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	stp	Q5, Q6, [x0, #256]
	stp	Q7, Q8, [x0, #288]
	stp	Q9, Q10, [x0, #320]
	stp	Q11, Q12, [x0, #352]
	stp	Q13, Q14, [x0, #384]
	stp	Q15, Q16, [x0, #416]
	stp	Q17, Q18, [x0, #448]
	stp	Q19, Q20, [x0, #480]
	ldp	Q5, Q6, [x0, #512]
	ldp	Q7, Q8, [x0, #544]
	ldp	Q9, Q10, [x0, #576]
	ldp	Q11, Q12, [x0, #608]
	ldp	Q13, Q14, [x0, #640]
	ldp	Q15, Q16, [x0, #672]
	ldp	Q17, Q18, [x0, #704]
	ldp	Q19, Q20, [x0, #736]
	ldp	Q0, Q1, [x1, #256]
	ldp	Q2, Q3, [x2, #256]
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V6.4S, V22.4S, V0.4S
	sqrdmulh	V8.4S, V24.4S, V1.4S
	sqrdmlsh	V6.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V23.4S, V4.S[0]
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	ldp	Q0, Q1, [x1, #288]
	ldp	Q2, Q3, [x2, #288]
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V10.4S, V22.4S, V0.4S
	sqrdmulh	V12.4S, V24.4S, V1.4S
	sqrdmlsh	V10.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	ldp	Q0, Q1, [x1, #320]
	ldp	Q2, Q3, [x2, #320]
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V14.4S, V22.4S, V0.4S
	sqrdmulh	V16.4S, V24.4S, V1.4S
	sqrdmlsh	V14.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	ldp	Q0, Q1, [x1, #352]
	ldp	Q2, Q3, [x2, #352]
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V18.4S, V22.4S, V0.4S
	sqrdmulh	V20.4S, V24.4S, V1.4S
	sqrdmlsh	V18.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldp	Q0, Q1, [x1, #768]
	ldp	Q2, Q3, [x2, #768]
	mov	V21.16B, V5.16B
	mov	V22.16B, V7.16B
	trn1	V5.4S, V5.4S, V6.4S
	trn1	V7.4S, V7.4S, V8.4S
	trn2	V6.4S, V21.4S, V6.4S
	trn2	V8.4S, V22.4S, V8.4S
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V6.4S, V22.4S, V0.4S
	sqrdmulh	V8.4S, V24.4S, V1.4S
	sqrdmlsh	V6.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V23.4S, V4.S[0]
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	ldp	Q0, Q1, [x1, #800]
	ldp	Q2, Q3, [x2, #800]
	mov	V21.16B, V9.16B
	mov	V22.16B, V11.16B
	trn1	V9.4S, V9.4S, V10.4S
	trn1	V11.4S, V11.4S, V12.4S
	trn2	V10.4S, V21.4S, V10.4S
	trn2	V12.4S, V22.4S, V12.4S
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V10.4S, V22.4S, V0.4S
	sqrdmulh	V12.4S, V24.4S, V1.4S
	sqrdmlsh	V10.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	ldp	Q0, Q1, [x1, #832]
	ldp	Q2, Q3, [x2, #832]
	mov	V21.16B, V13.16B
	mov	V22.16B, V15.16B
	trn1	V13.4S, V13.4S, V14.4S
	trn1	V15.4S, V15.4S, V16.4S
	trn2	V14.4S, V21.4S, V14.4S
	trn2	V16.4S, V22.4S, V16.4S
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V14.4S, V22.4S, V0.4S
	sqrdmulh	V16.4S, V24.4S, V1.4S
	sqrdmlsh	V14.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	ldp	Q0, Q1, [x1, #864]
	ldp	Q2, Q3, [x2, #864]
	mov	V21.16B, V17.16B
	mov	V22.16B, V19.16B
	trn1	V17.4S, V17.4S, V18.4S
	trn1	V19.4S, V19.4S, V20.4S
	trn2	V18.4S, V21.4S, V18.4S
	trn2	V20.4S, V22.4S, V20.4S
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V18.4S, V22.4S, V0.4S
	sqrdmulh	V20.4S, V24.4S, V1.4S
	sqrdmlsh	V18.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1088]
	ldr	Q1, [x1, #1104]
	ldr	Q2, [x2, #1088]
	ldr	Q3, [x2, #1104]
	mov	V21.16B, V5.16B
	mov	V22.16B, V7.16B
	trn1	V5.2D, V5.2D, V6.2D
	trn1	V7.2D, V7.2D, V8.2D
	trn2	V6.2D, V21.2D, V6.2D
	trn2	V8.2D, V22.2D, V8.2D
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V6.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[1]
	sqrdmlsh	V6.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V23.4S, V4.S[0]
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	mov	V21.16B, V9.16B
	mov	V22.16B, V11.16B
	trn1	V9.2D, V9.2D, V10.2D
	trn1	V11.2D, V11.2D, V12.2D
	trn2	V10.2D, V21.2D, V10.2D
	trn2	V12.2D, V22.2D, V12.2D
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V10.4S, V22.4S, V0.S[2]
	sqrdmulh	V12.4S, V24.4S, V0.S[3]
	sqrdmlsh	V10.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	mov	V21.16B, V13.16B
	mov	V22.16B, V15.16B
	trn1	V13.2D, V13.2D, V14.2D
	trn1	V15.2D, V15.2D, V16.2D
	trn2	V14.2D, V21.2D, V14.2D
	trn2	V16.2D, V22.2D, V16.2D
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V3.S[0]
	mul	V23.4S, V24.4S, V3.S[1]
	sqrdmulh	V14.4S, V22.4S, V1.S[0]
	sqrdmulh	V16.4S, V24.4S, V1.S[1]
	sqrdmlsh	V14.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	mov	V21.16B, V17.16B
	mov	V22.16B, V19.16B
	trn1	V17.2D, V17.2D, V18.2D
	trn1	V19.2D, V19.2D, V20.2D
	trn2	V18.2D, V21.2D, V18.2D
	trn2	V20.2D, V22.2D, V20.2D
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V3.S[2]
	mul	V23.4S, V24.4S, V3.S[3]
	sqrdmulh	V18.4S, V22.4S, V1.S[2]
	sqrdmulh	V20.4S, V24.4S, V1.S[3]
	sqrdmlsh	V18.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1184]
	ldr	Q2, [x2, #1184]
	sub	V22.4S, V5.4S, V7.4S
	sub	V24.4S, V6.4S, V8.4S
	add	V5.4S, V5.4S, V7.4S
	add	V6.4S, V6.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V7.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[0]
	sqrdmlsh	V7.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V23.4S, V4.S[0]
	sshr	V7.4S, V7.4S, #1
	sshr	V8.4S, V8.4S, #1
	sub	V22.4S, V9.4S, V11.4S
	sub	V24.4S, V10.4S, V12.4S
	add	V9.4S, V9.4S, V11.4S
	add	V10.4S, V10.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V11.4S, V22.4S, V0.S[1]
	sqrdmulh	V12.4S, V24.4S, V0.S[1]
	sqrdmlsh	V11.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V15.4S
	sub	V24.4S, V14.4S, V16.4S
	add	V13.4S, V13.4S, V15.4S
	add	V14.4S, V14.4S, V16.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V15.4S, V22.4S, V0.S[2]
	sqrdmulh	V16.4S, V24.4S, V0.S[2]
	sqrdmlsh	V15.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V15.4S, V15.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V17.4S, V19.4S
	sub	V24.4S, V18.4S, V20.4S
	add	V17.4S, V17.4S, V19.4S
	add	V18.4S, V18.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[3]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V19.4S, V22.4S, V0.S[3]
	sqrdmulh	V20.4S, V24.4S, V0.S[3]
	sqrdmlsh	V19.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	stp	Q5, Q6, [x0, #512]
	stp	Q7, Q8, [x0, #544]
	stp	Q9, Q10, [x0, #576]
	stp	Q11, Q12, [x0, #608]
	stp	Q13, Q14, [x0, #640]
	stp	Q15, Q16, [x0, #672]
	stp	Q17, Q18, [x0, #704]
	stp	Q19, Q20, [x0, #736]
	ldp	Q5, Q6, [x0, #768]
	ldp	Q7, Q8, [x0, #800]
	ldp	Q9, Q10, [x0, #832]
	ldp	Q11, Q12, [x0, #864]
	ldp	Q13, Q14, [x0, #896]
	ldp	Q15, Q16, [x0, #928]
	ldp	Q17, Q18, [x0, #960]
	ldp	Q19, Q20, [x0, #992]
	ldp	Q0, Q1, [x1, #384]
	ldp	Q2, Q3, [x2, #384]
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V6.4S, V22.4S, V0.4S
	sqrdmulh	V8.4S, V24.4S, V1.4S
	sqrdmlsh	V6.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V23.4S, V4.S[0]
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	ldp	Q0, Q1, [x1, #416]
	ldp	Q2, Q3, [x2, #416]
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V10.4S, V22.4S, V0.4S
	sqrdmulh	V12.4S, V24.4S, V1.4S
	sqrdmlsh	V10.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	ldp	Q0, Q1, [x1, #448]
	ldp	Q2, Q3, [x2, #448]
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V14.4S, V22.4S, V0.4S
	sqrdmulh	V16.4S, V24.4S, V1.4S
	sqrdmlsh	V14.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	ldp	Q0, Q1, [x1, #480]
	ldp	Q2, Q3, [x2, #480]
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V18.4S, V22.4S, V0.4S
	sqrdmulh	V20.4S, V24.4S, V1.4S
	sqrdmlsh	V18.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldp	Q0, Q1, [x1, #896]
	ldp	Q2, Q3, [x2, #896]
	mov	V21.16B, V5.16B
	mov	V22.16B, V7.16B
	trn1	V5.4S, V5.4S, V6.4S
	trn1	V7.4S, V7.4S, V8.4S
	trn2	V6.4S, V21.4S, V6.4S
	trn2	V8.4S, V22.4S, V8.4S
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V6.4S, V22.4S, V0.4S
	sqrdmulh	V8.4S, V24.4S, V1.4S
	sqrdmlsh	V6.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V23.4S, V4.S[0]
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	ldp	Q0, Q1, [x1, #928]
	ldp	Q2, Q3, [x2, #928]
	mov	V21.16B, V9.16B
	mov	V22.16B, V11.16B
	trn1	V9.4S, V9.4S, V10.4S
	trn1	V11.4S, V11.4S, V12.4S
	trn2	V10.4S, V21.4S, V10.4S
	trn2	V12.4S, V22.4S, V12.4S
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V10.4S, V22.4S, V0.4S
	sqrdmulh	V12.4S, V24.4S, V1.4S
	sqrdmlsh	V10.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	ldp	Q0, Q1, [x1, #960]
	ldp	Q2, Q3, [x2, #960]
	mov	V21.16B, V13.16B
	mov	V22.16B, V15.16B
	trn1	V13.4S, V13.4S, V14.4S
	trn1	V15.4S, V15.4S, V16.4S
	trn2	V14.4S, V21.4S, V14.4S
	trn2	V16.4S, V22.4S, V16.4S
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V14.4S, V22.4S, V0.4S
	sqrdmulh	V16.4S, V24.4S, V1.4S
	sqrdmlsh	V14.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	ldp	Q0, Q1, [x1, #992]
	ldp	Q2, Q3, [x2, #992]
	mov	V21.16B, V17.16B
	mov	V22.16B, V19.16B
	trn1	V17.4S, V17.4S, V18.4S
	trn1	V19.4S, V19.4S, V20.4S
	trn2	V18.4S, V21.4S, V18.4S
	trn2	V20.4S, V22.4S, V20.4S
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V18.4S, V22.4S, V0.4S
	sqrdmulh	V20.4S, V24.4S, V1.4S
	sqrdmlsh	V18.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1120]
	ldr	Q1, [x1, #1136]
	ldr	Q2, [x2, #1120]
	ldr	Q3, [x2, #1136]
	mov	V21.16B, V5.16B
	mov	V22.16B, V7.16B
	trn1	V5.2D, V5.2D, V6.2D
	trn1	V7.2D, V7.2D, V8.2D
	trn2	V6.2D, V21.2D, V6.2D
	trn2	V8.2D, V22.2D, V8.2D
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V6.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[1]
	sqrdmlsh	V6.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V23.4S, V4.S[0]
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	mov	V21.16B, V9.16B
	mov	V22.16B, V11.16B
	trn1	V9.2D, V9.2D, V10.2D
	trn1	V11.2D, V11.2D, V12.2D
	trn2	V10.2D, V21.2D, V10.2D
	trn2	V12.2D, V22.2D, V12.2D
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V10.4S, V22.4S, V0.S[2]
	sqrdmulh	V12.4S, V24.4S, V0.S[3]
	sqrdmlsh	V10.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	mov	V21.16B, V13.16B
	mov	V22.16B, V15.16B
	trn1	V13.2D, V13.2D, V14.2D
	trn1	V15.2D, V15.2D, V16.2D
	trn2	V14.2D, V21.2D, V14.2D
	trn2	V16.2D, V22.2D, V16.2D
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V3.S[0]
	mul	V23.4S, V24.4S, V3.S[1]
	sqrdmulh	V14.4S, V22.4S, V1.S[0]
	sqrdmulh	V16.4S, V24.4S, V1.S[1]
	sqrdmlsh	V14.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	mov	V21.16B, V17.16B
	mov	V22.16B, V19.16B
	trn1	V17.2D, V17.2D, V18.2D
	trn1	V19.2D, V19.2D, V20.2D
	trn2	V18.2D, V21.2D, V18.2D
	trn2	V20.2D, V22.2D, V20.2D
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V3.S[2]
	mul	V23.4S, V24.4S, V3.S[3]
	sqrdmulh	V18.4S, V22.4S, V1.S[2]
	sqrdmulh	V20.4S, V24.4S, V1.S[3]
	sqrdmlsh	V18.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1200]
	ldr	Q2, [x2, #1200]
	sub	V22.4S, V5.4S, V7.4S
	sub	V24.4S, V6.4S, V8.4S
	add	V5.4S, V5.4S, V7.4S
	add	V6.4S, V6.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V7.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[0]
	sqrdmlsh	V7.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V23.4S, V4.S[0]
	sshr	V7.4S, V7.4S, #1
	sshr	V8.4S, V8.4S, #1
	sub	V22.4S, V9.4S, V11.4S
	sub	V24.4S, V10.4S, V12.4S
	add	V9.4S, V9.4S, V11.4S
	add	V10.4S, V10.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V11.4S, V22.4S, V0.S[1]
	sqrdmulh	V12.4S, V24.4S, V0.S[1]
	sqrdmlsh	V11.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V15.4S
	sub	V24.4S, V14.4S, V16.4S
	add	V13.4S, V13.4S, V15.4S
	add	V14.4S, V14.4S, V16.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V15.4S, V22.4S, V0.S[2]
	sqrdmulh	V16.4S, V24.4S, V0.S[2]
	sqrdmlsh	V15.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V15.4S, V15.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V17.4S, V19.4S
	sub	V24.4S, V18.4S, V20.4S
	add	V17.4S, V17.4S, V19.4S
	add	V18.4S, V18.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[3]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V19.4S, V22.4S, V0.S[3]
	sqrdmulh	V20.4S, V24.4S, V0.S[3]
	sqrdmlsh	V19.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	stp	Q5, Q6, [x0, #768]
	stp	Q7, Q8, [x0, #800]
	stp	Q9, Q10, [x0, #832]
	stp	Q11, Q12, [x0, #864]
	stp	Q13, Q14, [x0, #896]
	stp	Q15, Q16, [x0, #928]
	stp	Q17, Q18, [x0, #960]
	stp	Q19, Q20, [x0, #992]
	ldr	Q5, [x0]
	ldr	Q6, [x0, #64]
	ldr	Q7, [x0, #128]
	ldr	Q8, [x0, #192]
	ldr	Q9, [x0, #256]
	ldr	Q10, [x0, #320]
	ldr	Q11, [x0, #384]
	ldr	Q12, [x0, #448]
	ldr	Q13, [x0, #512]
	ldr	Q14, [x0, #576]
	ldr	Q15, [x0, #640]
	ldr	Q16, [x0, #704]
	ldr	Q17, [x0, #768]
	ldr	Q18, [x0, #832]
	ldr	Q19, [x0, #896]
	ldr	Q20, [x0, #960]
	ldr	Q0, [x1, #1216]
	ldr	Q1, [x1, #1232]
	ldr	Q2, [x2, #1216]
	ldr	Q3, [x2, #1232]
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V6.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[1]
	sqrdmlsh	V6.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V23.4S, V4.S[0]
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V10.4S, V22.4S, V0.S[2]
	sqrdmulh	V12.4S, V24.4S, V0.S[3]
	sqrdmlsh	V10.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V3.S[0]
	mul	V23.4S, V24.4S, V3.S[1]
	sqrdmulh	V14.4S, V22.4S, V1.S[0]
	sqrdmulh	V16.4S, V24.4S, V1.S[1]
	sqrdmlsh	V14.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V3.S[2]
	mul	V23.4S, V24.4S, V3.S[3]
	sqrdmulh	V18.4S, V22.4S, V1.S[2]
	sqrdmulh	V20.4S, V24.4S, V1.S[3]
	sqrdmlsh	V18.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1248]
	ldr	Q2, [x2, #1248]
	sub	V22.4S, V5.4S, V7.4S
	sub	V24.4S, V6.4S, V8.4S
	add	V5.4S, V5.4S, V7.4S
	add	V6.4S, V6.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V7.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[0]
	sqrdmlsh	V7.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V23.4S, V4.S[0]
	sshr	V7.4S, V7.4S, #1
	sshr	V8.4S, V8.4S, #1
	sub	V22.4S, V9.4S, V11.4S
	sub	V24.4S, V10.4S, V12.4S
	add	V9.4S, V9.4S, V11.4S
	add	V10.4S, V10.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V11.4S, V22.4S, V0.S[1]
	sqrdmulh	V12.4S, V24.4S, V0.S[1]
	sqrdmlsh	V11.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V15.4S
	sub	V24.4S, V14.4S, V16.4S
	add	V13.4S, V13.4S, V15.4S
	add	V14.4S, V14.4S, V16.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V15.4S, V22.4S, V0.S[2]
	sqrdmulh	V16.4S, V24.4S, V0.S[2]
	sqrdmlsh	V15.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V15.4S, V15.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V17.4S, V19.4S
	sub	V24.4S, V18.4S, V20.4S
	add	V17.4S, V17.4S, V19.4S
	add	V18.4S, V18.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[3]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V19.4S, V22.4S, V0.S[3]
	sqrdmulh	V20.4S, V24.4S, V0.S[3]
	sqrdmlsh	V19.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1264]
	ldr	Q2, [x2, #1264]
	sub	V22.4S, V5.4S, V9.4S
	sub	V24.4S, V6.4S, V10.4S
	add	V5.4S, V5.4S, V9.4S
	add	V6.4S, V6.4S, V10.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V9.4S, V22.4S, V0.S[0]
	sqrdmulh	V10.4S, V24.4S, V0.S[0]
	sqrdmlsh	V9.4S, V21.4S, V4.S[0]
	sqrdmlsh	V10.4S, V23.4S, V4.S[0]
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	sub	V22.4S, V7.4S, V11.4S
	sub	V24.4S, V8.4S, V12.4S
	add	V7.4S, V7.4S, V11.4S
	add	V8.4S, V8.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V11.4S, V22.4S, V0.S[0]
	sqrdmulh	V12.4S, V24.4S, V0.S[0]
	sqrdmlsh	V11.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V17.4S
	sub	V24.4S, V14.4S, V18.4S
	add	V13.4S, V13.4S, V17.4S
	add	V14.4S, V14.4S, V18.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V17.4S, V22.4S, V0.S[1]
	sqrdmulh	V18.4S, V24.4S, V0.S[1]
	sqrdmlsh	V17.4S, V21.4S, V4.S[0]
	sqrdmlsh	V18.4S, V23.4S, V4.S[0]
	sshr	V17.4S, V17.4S, #1
	sshr	V18.4S, V18.4S, #1
	sub	V22.4S, V15.4S, V19.4S
	sub	V24.4S, V16.4S, V20.4S
	add	V15.4S, V15.4S, V19.4S
	add	V16.4S, V16.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V19.4S, V22.4S, V0.S[1]
	sqrdmulh	V20.4S, V24.4S, V0.S[1]
	sqrdmlsh	V19.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	sub	V22.4S, V5.4S, V13.4S
	sub	V24.4S, V6.4S, V14.4S
	add	V5.4S, V5.4S, V13.4S
	add	V6.4S, V6.4S, V14.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V13.4S, V22.4S, V0.S[2]
	sqrdmulh	V14.4S, V24.4S, V0.S[2]
	sqrdmlsh	V13.4S, V21.4S, V4.S[0]
	sqrdmlsh	V14.4S, V23.4S, V4.S[0]
	sshr	V13.4S, V13.4S, #1
	sshr	V14.4S, V14.4S, #1
	sub	V22.4S, V7.4S, V15.4S
	sub	V24.4S, V8.4S, V16.4S
	add	V7.4S, V7.4S, V15.4S
	add	V8.4S, V8.4S, V16.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V15.4S, V22.4S, V0.S[2]
	sqrdmulh	V16.4S, V24.4S, V0.S[2]
	sqrdmlsh	V15.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V15.4S, V15.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V9.4S, V17.4S
	sub	V24.4S, V10.4S, V18.4S
	add	V9.4S, V9.4S, V17.4S
	add	V10.4S, V10.4S, V18.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V17.4S, V22.4S, V0.S[2]
	sqrdmulh	V18.4S, V24.4S, V0.S[2]
	sqrdmlsh	V17.4S, V21.4S, V4.S[0]
	sqrdmlsh	V18.4S, V23.4S, V4.S[0]
	sshr	V17.4S, V17.4S, #1
	sshr	V18.4S, V18.4S, #1
	sub	V22.4S, V11.4S, V19.4S
	sub	V24.4S, V12.4S, V20.4S
	add	V11.4S, V11.4S, V19.4S
	add	V12.4S, V12.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V19.4S, V22.4S, V0.S[2]
	sqrdmulh	V20.4S, V24.4S, V0.S[2]
	sqrdmlsh	V19.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	mul	V21.4S, V5.4S, V2.S[3]
	mul	V22.4S, V6.4S, V2.S[3]
	sqrdmulh	V5.4S, V5.4S, V0.S[3]
	sqrdmulh	V6.4S, V6.4S, V0.S[3]
	sqrdmlsh	V5.4S, V21.4S, V4.S[0]
	sqrdmlsh	V6.4S, V22.4S, V4.S[0]
	sshr	V5.4S, V5.4S, #1
	sshr	V6.4S, V6.4S, #1
	mul	V21.4S, V7.4S, V2.S[3]
	mul	V22.4S, V8.4S, V2.S[3]
	sqrdmulh	V7.4S, V7.4S, V0.S[3]
	sqrdmulh	V8.4S, V8.4S, V0.S[3]
	sqrdmlsh	V7.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V22.4S, V4.S[0]
	sshr	V7.4S, V7.4S, #1
	sshr	V8.4S, V8.4S, #1
	mul	V21.4S, V9.4S, V2.S[3]
	mul	V22.4S, V10.4S, V2.S[3]
	sqrdmulh	V9.4S, V9.4S, V0.S[3]
	sqrdmulh	V10.4S, V10.4S, V0.S[3]
	sqrdmlsh	V9.4S, V21.4S, V4.S[0]
	sqrdmlsh	V10.4S, V22.4S, V4.S[0]
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	mul	V21.4S, V11.4S, V2.S[3]
	mul	V22.4S, V12.4S, V2.S[3]
	sqrdmulh	V11.4S, V11.4S, V0.S[3]
	sqrdmulh	V12.4S, V12.4S, V0.S[3]
	sqrdmlsh	V11.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V22.4S, V4.S[0]
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	str	Q5, [x0]
	str	Q6, [x0, #64]
	str	Q7, [x0, #128]
	str	Q8, [x0, #192]
	str	Q9, [x0, #256]
	str	Q10, [x0, #320]
	str	Q11, [x0, #384]
	str	Q12, [x0, #448]
	str	Q13, [x0, #512]
	str	Q14, [x0, #576]
	str	Q15, [x0, #640]
	str	Q16, [x0, #704]
	str	Q17, [x0, #768]
	str	Q18, [x0, #832]
	str	Q19, [x0, #896]
	str	Q20, [x0, #960]
	ldr	Q5, [x0, #16]
	ldr	Q6, [x0, #80]
	ldr	Q7, [x0, #144]
	ldr	Q8, [x0, #208]
	ldr	Q9, [x0, #272]
	ldr	Q10, [x0, #336]
	ldr	Q11, [x0, #400]
	ldr	Q12, [x0, #464]
	ldr	Q13, [x0, #528]
	ldr	Q14, [x0, #592]
	ldr	Q15, [x0, #656]
	ldr	Q16, [x0, #720]
	ldr	Q17, [x0, #784]
	ldr	Q18, [x0, #848]
	ldr	Q19, [x0, #912]
	ldr	Q20, [x0, #976]
	ldr	Q0, [x1, #1216]
	ldr	Q1, [x1, #1232]
	ldr	Q2, [x2, #1216]
	ldr	Q3, [x2, #1232]
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V6.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[1]
	sqrdmlsh	V6.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V23.4S, V4.S[0]
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V10.4S, V22.4S, V0.S[2]
	sqrdmulh	V12.4S, V24.4S, V0.S[3]
	sqrdmlsh	V10.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V3.S[0]
	mul	V23.4S, V24.4S, V3.S[1]
	sqrdmulh	V14.4S, V22.4S, V1.S[0]
	sqrdmulh	V16.4S, V24.4S, V1.S[1]
	sqrdmlsh	V14.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V3.S[2]
	mul	V23.4S, V24.4S, V3.S[3]
	sqrdmulh	V18.4S, V22.4S, V1.S[2]
	sqrdmulh	V20.4S, V24.4S, V1.S[3]
	sqrdmlsh	V18.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1248]
	ldr	Q2, [x2, #1248]
	sub	V22.4S, V5.4S, V7.4S
	sub	V24.4S, V6.4S, V8.4S
	add	V5.4S, V5.4S, V7.4S
	add	V6.4S, V6.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V7.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[0]
	sqrdmlsh	V7.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V23.4S, V4.S[0]
	sshr	V7.4S, V7.4S, #1
	sshr	V8.4S, V8.4S, #1
	sub	V22.4S, V9.4S, V11.4S
	sub	V24.4S, V10.4S, V12.4S
	add	V9.4S, V9.4S, V11.4S
	add	V10.4S, V10.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V11.4S, V22.4S, V0.S[1]
	sqrdmulh	V12.4S, V24.4S, V0.S[1]
	sqrdmlsh	V11.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V15.4S
	sub	V24.4S, V14.4S, V16.4S
	add	V13.4S, V13.4S, V15.4S
	add	V14.4S, V14.4S, V16.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V15.4S, V22.4S, V0.S[2]
	sqrdmulh	V16.4S, V24.4S, V0.S[2]
	sqrdmlsh	V15.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V15.4S, V15.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V17.4S, V19.4S
	sub	V24.4S, V18.4S, V20.4S
	add	V17.4S, V17.4S, V19.4S
	add	V18.4S, V18.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[3]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V19.4S, V22.4S, V0.S[3]
	sqrdmulh	V20.4S, V24.4S, V0.S[3]
	sqrdmlsh	V19.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1264]
	ldr	Q2, [x2, #1264]
	sub	V22.4S, V5.4S, V9.4S
	sub	V24.4S, V6.4S, V10.4S
	add	V5.4S, V5.4S, V9.4S
	add	V6.4S, V6.4S, V10.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V9.4S, V22.4S, V0.S[0]
	sqrdmulh	V10.4S, V24.4S, V0.S[0]
	sqrdmlsh	V9.4S, V21.4S, V4.S[0]
	sqrdmlsh	V10.4S, V23.4S, V4.S[0]
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	sub	V22.4S, V7.4S, V11.4S
	sub	V24.4S, V8.4S, V12.4S
	add	V7.4S, V7.4S, V11.4S
	add	V8.4S, V8.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V11.4S, V22.4S, V0.S[0]
	sqrdmulh	V12.4S, V24.4S, V0.S[0]
	sqrdmlsh	V11.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V17.4S
	sub	V24.4S, V14.4S, V18.4S
	add	V13.4S, V13.4S, V17.4S
	add	V14.4S, V14.4S, V18.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V17.4S, V22.4S, V0.S[1]
	sqrdmulh	V18.4S, V24.4S, V0.S[1]
	sqrdmlsh	V17.4S, V21.4S, V4.S[0]
	sqrdmlsh	V18.4S, V23.4S, V4.S[0]
	sshr	V17.4S, V17.4S, #1
	sshr	V18.4S, V18.4S, #1
	sub	V22.4S, V15.4S, V19.4S
	sub	V24.4S, V16.4S, V20.4S
	add	V15.4S, V15.4S, V19.4S
	add	V16.4S, V16.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V19.4S, V22.4S, V0.S[1]
	sqrdmulh	V20.4S, V24.4S, V0.S[1]
	sqrdmlsh	V19.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	sub	V22.4S, V5.4S, V13.4S
	sub	V24.4S, V6.4S, V14.4S
	add	V5.4S, V5.4S, V13.4S
	add	V6.4S, V6.4S, V14.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V13.4S, V22.4S, V0.S[2]
	sqrdmulh	V14.4S, V24.4S, V0.S[2]
	sqrdmlsh	V13.4S, V21.4S, V4.S[0]
	sqrdmlsh	V14.4S, V23.4S, V4.S[0]
	sshr	V13.4S, V13.4S, #1
	sshr	V14.4S, V14.4S, #1
	sub	V22.4S, V7.4S, V15.4S
	sub	V24.4S, V8.4S, V16.4S
	add	V7.4S, V7.4S, V15.4S
	add	V8.4S, V8.4S, V16.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V15.4S, V22.4S, V0.S[2]
	sqrdmulh	V16.4S, V24.4S, V0.S[2]
	sqrdmlsh	V15.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V15.4S, V15.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V9.4S, V17.4S
	sub	V24.4S, V10.4S, V18.4S
	add	V9.4S, V9.4S, V17.4S
	add	V10.4S, V10.4S, V18.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V17.4S, V22.4S, V0.S[2]
	sqrdmulh	V18.4S, V24.4S, V0.S[2]
	sqrdmlsh	V17.4S, V21.4S, V4.S[0]
	sqrdmlsh	V18.4S, V23.4S, V4.S[0]
	sshr	V17.4S, V17.4S, #1
	sshr	V18.4S, V18.4S, #1
	sub	V22.4S, V11.4S, V19.4S
	sub	V24.4S, V12.4S, V20.4S
	add	V11.4S, V11.4S, V19.4S
	add	V12.4S, V12.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V19.4S, V22.4S, V0.S[2]
	sqrdmulh	V20.4S, V24.4S, V0.S[2]
	sqrdmlsh	V19.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	mul	V21.4S, V5.4S, V2.S[3]
	mul	V22.4S, V6.4S, V2.S[3]
	sqrdmulh	V5.4S, V5.4S, V0.S[3]
	sqrdmulh	V6.4S, V6.4S, V0.S[3]
	sqrdmlsh	V5.4S, V21.4S, V4.S[0]
	sqrdmlsh	V6.4S, V22.4S, V4.S[0]
	sshr	V5.4S, V5.4S, #1
	sshr	V6.4S, V6.4S, #1
	mul	V21.4S, V7.4S, V2.S[3]
	mul	V22.4S, V8.4S, V2.S[3]
	sqrdmulh	V7.4S, V7.4S, V0.S[3]
	sqrdmulh	V8.4S, V8.4S, V0.S[3]
	sqrdmlsh	V7.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V22.4S, V4.S[0]
	sshr	V7.4S, V7.4S, #1
	sshr	V8.4S, V8.4S, #1
	mul	V21.4S, V9.4S, V2.S[3]
	mul	V22.4S, V10.4S, V2.S[3]
	sqrdmulh	V9.4S, V9.4S, V0.S[3]
	sqrdmulh	V10.4S, V10.4S, V0.S[3]
	sqrdmlsh	V9.4S, V21.4S, V4.S[0]
	sqrdmlsh	V10.4S, V22.4S, V4.S[0]
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	mul	V21.4S, V11.4S, V2.S[3]
	mul	V22.4S, V12.4S, V2.S[3]
	sqrdmulh	V11.4S, V11.4S, V0.S[3]
	sqrdmulh	V12.4S, V12.4S, V0.S[3]
	sqrdmlsh	V11.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V22.4S, V4.S[0]
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	str	Q5, [x0, #16]
	str	Q6, [x0, #80]
	str	Q7, [x0, #144]
	str	Q8, [x0, #208]
	str	Q9, [x0, #272]
	str	Q10, [x0, #336]
	str	Q11, [x0, #400]
	str	Q12, [x0, #464]
	str	Q13, [x0, #528]
	str	Q14, [x0, #592]
	str	Q15, [x0, #656]
	str	Q16, [x0, #720]
	str	Q17, [x0, #784]
	str	Q18, [x0, #848]
	str	Q19, [x0, #912]
	str	Q20, [x0, #976]
	ldr	Q5, [x0, #32]
	ldr	Q6, [x0, #96]
	ldr	Q7, [x0, #160]
	ldr	Q8, [x0, #224]
	ldr	Q9, [x0, #288]
	ldr	Q10, [x0, #352]
	ldr	Q11, [x0, #416]
	ldr	Q12, [x0, #480]
	ldr	Q13, [x0, #544]
	ldr	Q14, [x0, #608]
	ldr	Q15, [x0, #672]
	ldr	Q16, [x0, #736]
	ldr	Q17, [x0, #800]
	ldr	Q18, [x0, #864]
	ldr	Q19, [x0, #928]
	ldr	Q20, [x0, #992]
	ldr	Q0, [x1, #1216]
	ldr	Q1, [x1, #1232]
	ldr	Q2, [x2, #1216]
	ldr	Q3, [x2, #1232]
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V6.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[1]
	sqrdmlsh	V6.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V23.4S, V4.S[0]
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V10.4S, V22.4S, V0.S[2]
	sqrdmulh	V12.4S, V24.4S, V0.S[3]
	sqrdmlsh	V10.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V3.S[0]
	mul	V23.4S, V24.4S, V3.S[1]
	sqrdmulh	V14.4S, V22.4S, V1.S[0]
	sqrdmulh	V16.4S, V24.4S, V1.S[1]
	sqrdmlsh	V14.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V3.S[2]
	mul	V23.4S, V24.4S, V3.S[3]
	sqrdmulh	V18.4S, V22.4S, V1.S[2]
	sqrdmulh	V20.4S, V24.4S, V1.S[3]
	sqrdmlsh	V18.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1248]
	ldr	Q2, [x2, #1248]
	sub	V22.4S, V5.4S, V7.4S
	sub	V24.4S, V6.4S, V8.4S
	add	V5.4S, V5.4S, V7.4S
	add	V6.4S, V6.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V7.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[0]
	sqrdmlsh	V7.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V23.4S, V4.S[0]
	sshr	V7.4S, V7.4S, #1
	sshr	V8.4S, V8.4S, #1
	sub	V22.4S, V9.4S, V11.4S
	sub	V24.4S, V10.4S, V12.4S
	add	V9.4S, V9.4S, V11.4S
	add	V10.4S, V10.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V11.4S, V22.4S, V0.S[1]
	sqrdmulh	V12.4S, V24.4S, V0.S[1]
	sqrdmlsh	V11.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V15.4S
	sub	V24.4S, V14.4S, V16.4S
	add	V13.4S, V13.4S, V15.4S
	add	V14.4S, V14.4S, V16.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V15.4S, V22.4S, V0.S[2]
	sqrdmulh	V16.4S, V24.4S, V0.S[2]
	sqrdmlsh	V15.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V15.4S, V15.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V17.4S, V19.4S
	sub	V24.4S, V18.4S, V20.4S
	add	V17.4S, V17.4S, V19.4S
	add	V18.4S, V18.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[3]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V19.4S, V22.4S, V0.S[3]
	sqrdmulh	V20.4S, V24.4S, V0.S[3]
	sqrdmlsh	V19.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1264]
	ldr	Q2, [x2, #1264]
	sub	V22.4S, V5.4S, V9.4S
	sub	V24.4S, V6.4S, V10.4S
	add	V5.4S, V5.4S, V9.4S
	add	V6.4S, V6.4S, V10.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V9.4S, V22.4S, V0.S[0]
	sqrdmulh	V10.4S, V24.4S, V0.S[0]
	sqrdmlsh	V9.4S, V21.4S, V4.S[0]
	sqrdmlsh	V10.4S, V23.4S, V4.S[0]
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	sub	V22.4S, V7.4S, V11.4S
	sub	V24.4S, V8.4S, V12.4S
	add	V7.4S, V7.4S, V11.4S
	add	V8.4S, V8.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V11.4S, V22.4S, V0.S[0]
	sqrdmulh	V12.4S, V24.4S, V0.S[0]
	sqrdmlsh	V11.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V17.4S
	sub	V24.4S, V14.4S, V18.4S
	add	V13.4S, V13.4S, V17.4S
	add	V14.4S, V14.4S, V18.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V17.4S, V22.4S, V0.S[1]
	sqrdmulh	V18.4S, V24.4S, V0.S[1]
	sqrdmlsh	V17.4S, V21.4S, V4.S[0]
	sqrdmlsh	V18.4S, V23.4S, V4.S[0]
	sshr	V17.4S, V17.4S, #1
	sshr	V18.4S, V18.4S, #1
	sub	V22.4S, V15.4S, V19.4S
	sub	V24.4S, V16.4S, V20.4S
	add	V15.4S, V15.4S, V19.4S
	add	V16.4S, V16.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V19.4S, V22.4S, V0.S[1]
	sqrdmulh	V20.4S, V24.4S, V0.S[1]
	sqrdmlsh	V19.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	sub	V22.4S, V5.4S, V13.4S
	sub	V24.4S, V6.4S, V14.4S
	add	V5.4S, V5.4S, V13.4S
	add	V6.4S, V6.4S, V14.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V13.4S, V22.4S, V0.S[2]
	sqrdmulh	V14.4S, V24.4S, V0.S[2]
	sqrdmlsh	V13.4S, V21.4S, V4.S[0]
	sqrdmlsh	V14.4S, V23.4S, V4.S[0]
	sshr	V13.4S, V13.4S, #1
	sshr	V14.4S, V14.4S, #1
	sub	V22.4S, V7.4S, V15.4S
	sub	V24.4S, V8.4S, V16.4S
	add	V7.4S, V7.4S, V15.4S
	add	V8.4S, V8.4S, V16.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V15.4S, V22.4S, V0.S[2]
	sqrdmulh	V16.4S, V24.4S, V0.S[2]
	sqrdmlsh	V15.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V15.4S, V15.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V9.4S, V17.4S
	sub	V24.4S, V10.4S, V18.4S
	add	V9.4S, V9.4S, V17.4S
	add	V10.4S, V10.4S, V18.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V17.4S, V22.4S, V0.S[2]
	sqrdmulh	V18.4S, V24.4S, V0.S[2]
	sqrdmlsh	V17.4S, V21.4S, V4.S[0]
	sqrdmlsh	V18.4S, V23.4S, V4.S[0]
	sshr	V17.4S, V17.4S, #1
	sshr	V18.4S, V18.4S, #1
	sub	V22.4S, V11.4S, V19.4S
	sub	V24.4S, V12.4S, V20.4S
	add	V11.4S, V11.4S, V19.4S
	add	V12.4S, V12.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V19.4S, V22.4S, V0.S[2]
	sqrdmulh	V20.4S, V24.4S, V0.S[2]
	sqrdmlsh	V19.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	mul	V21.4S, V5.4S, V2.S[3]
	mul	V22.4S, V6.4S, V2.S[3]
	sqrdmulh	V5.4S, V5.4S, V0.S[3]
	sqrdmulh	V6.4S, V6.4S, V0.S[3]
	sqrdmlsh	V5.4S, V21.4S, V4.S[0]
	sqrdmlsh	V6.4S, V22.4S, V4.S[0]
	sshr	V5.4S, V5.4S, #1
	sshr	V6.4S, V6.4S, #1
	mul	V21.4S, V7.4S, V2.S[3]
	mul	V22.4S, V8.4S, V2.S[3]
	sqrdmulh	V7.4S, V7.4S, V0.S[3]
	sqrdmulh	V8.4S, V8.4S, V0.S[3]
	sqrdmlsh	V7.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V22.4S, V4.S[0]
	sshr	V7.4S, V7.4S, #1
	sshr	V8.4S, V8.4S, #1
	mul	V21.4S, V9.4S, V2.S[3]
	mul	V22.4S, V10.4S, V2.S[3]
	sqrdmulh	V9.4S, V9.4S, V0.S[3]
	sqrdmulh	V10.4S, V10.4S, V0.S[3]
	sqrdmlsh	V9.4S, V21.4S, V4.S[0]
	sqrdmlsh	V10.4S, V22.4S, V4.S[0]
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	mul	V21.4S, V11.4S, V2.S[3]
	mul	V22.4S, V12.4S, V2.S[3]
	sqrdmulh	V11.4S, V11.4S, V0.S[3]
	sqrdmulh	V12.4S, V12.4S, V0.S[3]
	sqrdmlsh	V11.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V22.4S, V4.S[0]
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	str	Q5, [x0, #32]
	str	Q6, [x0, #96]
	str	Q7, [x0, #160]
	str	Q8, [x0, #224]
	str	Q9, [x0, #288]
	str	Q10, [x0, #352]
	str	Q11, [x0, #416]
	str	Q12, [x0, #480]
	str	Q13, [x0, #544]
	str	Q14, [x0, #608]
	str	Q15, [x0, #672]
	str	Q16, [x0, #736]
	str	Q17, [x0, #800]
	str	Q18, [x0, #864]
	str	Q19, [x0, #928]
	str	Q20, [x0, #992]
	ldr	Q5, [x0, #48]
	ldr	Q6, [x0, #112]
	ldr	Q7, [x0, #176]
	ldr	Q8, [x0, #240]
	ldr	Q9, [x0, #304]
	ldr	Q10, [x0, #368]
	ldr	Q11, [x0, #432]
	ldr	Q12, [x0, #496]
	ldr	Q13, [x0, #560]
	ldr	Q14, [x0, #624]
	ldr	Q15, [x0, #688]
	ldr	Q16, [x0, #752]
	ldr	Q17, [x0, #816]
	ldr	Q18, [x0, #880]
	ldr	Q19, [x0, #944]
	ldr	Q20, [x0, #1008]
	ldr	Q0, [x1, #1216]
	ldr	Q1, [x1, #1232]
	ldr	Q2, [x2, #1216]
	ldr	Q3, [x2, #1232]
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V6.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[1]
	sqrdmlsh	V6.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V23.4S, V4.S[0]
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V10.4S, V22.4S, V0.S[2]
	sqrdmulh	V12.4S, V24.4S, V0.S[3]
	sqrdmlsh	V10.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V3.S[0]
	mul	V23.4S, V24.4S, V3.S[1]
	sqrdmulh	V14.4S, V22.4S, V1.S[0]
	sqrdmulh	V16.4S, V24.4S, V1.S[1]
	sqrdmlsh	V14.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V3.S[2]
	mul	V23.4S, V24.4S, V3.S[3]
	sqrdmulh	V18.4S, V22.4S, V1.S[2]
	sqrdmulh	V20.4S, V24.4S, V1.S[3]
	sqrdmlsh	V18.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1248]
	ldr	Q2, [x2, #1248]
	sub	V22.4S, V5.4S, V7.4S
	sub	V24.4S, V6.4S, V8.4S
	add	V5.4S, V5.4S, V7.4S
	add	V6.4S, V6.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V7.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[0]
	sqrdmlsh	V7.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V23.4S, V4.S[0]
	sshr	V7.4S, V7.4S, #1
	sshr	V8.4S, V8.4S, #1
	sub	V22.4S, V9.4S, V11.4S
	sub	V24.4S, V10.4S, V12.4S
	add	V9.4S, V9.4S, V11.4S
	add	V10.4S, V10.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V11.4S, V22.4S, V0.S[1]
	sqrdmulh	V12.4S, V24.4S, V0.S[1]
	sqrdmlsh	V11.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V15.4S
	sub	V24.4S, V14.4S, V16.4S
	add	V13.4S, V13.4S, V15.4S
	add	V14.4S, V14.4S, V16.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V15.4S, V22.4S, V0.S[2]
	sqrdmulh	V16.4S, V24.4S, V0.S[2]
	sqrdmlsh	V15.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V15.4S, V15.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V17.4S, V19.4S
	sub	V24.4S, V18.4S, V20.4S
	add	V17.4S, V17.4S, V19.4S
	add	V18.4S, V18.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[3]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V19.4S, V22.4S, V0.S[3]
	sqrdmulh	V20.4S, V24.4S, V0.S[3]
	sqrdmlsh	V19.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1264]
	ldr	Q2, [x2, #1264]
	sub	V22.4S, V5.4S, V9.4S
	sub	V24.4S, V6.4S, V10.4S
	add	V5.4S, V5.4S, V9.4S
	add	V6.4S, V6.4S, V10.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V9.4S, V22.4S, V0.S[0]
	sqrdmulh	V10.4S, V24.4S, V0.S[0]
	sqrdmlsh	V9.4S, V21.4S, V4.S[0]
	sqrdmlsh	V10.4S, V23.4S, V4.S[0]
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	sub	V22.4S, V7.4S, V11.4S
	sub	V24.4S, V8.4S, V12.4S
	add	V7.4S, V7.4S, V11.4S
	add	V8.4S, V8.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V11.4S, V22.4S, V0.S[0]
	sqrdmulh	V12.4S, V24.4S, V0.S[0]
	sqrdmlsh	V11.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V17.4S
	sub	V24.4S, V14.4S, V18.4S
	add	V13.4S, V13.4S, V17.4S
	add	V14.4S, V14.4S, V18.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V17.4S, V22.4S, V0.S[1]
	sqrdmulh	V18.4S, V24.4S, V0.S[1]
	sqrdmlsh	V17.4S, V21.4S, V4.S[0]
	sqrdmlsh	V18.4S, V23.4S, V4.S[0]
	sshr	V17.4S, V17.4S, #1
	sshr	V18.4S, V18.4S, #1
	sub	V22.4S, V15.4S, V19.4S
	sub	V24.4S, V16.4S, V20.4S
	add	V15.4S, V15.4S, V19.4S
	add	V16.4S, V16.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V19.4S, V22.4S, V0.S[1]
	sqrdmulh	V20.4S, V24.4S, V0.S[1]
	sqrdmlsh	V19.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	sub	V22.4S, V5.4S, V13.4S
	sub	V24.4S, V6.4S, V14.4S
	add	V5.4S, V5.4S, V13.4S
	add	V6.4S, V6.4S, V14.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V13.4S, V22.4S, V0.S[2]
	sqrdmulh	V14.4S, V24.4S, V0.S[2]
	sqrdmlsh	V13.4S, V21.4S, V4.S[0]
	sqrdmlsh	V14.4S, V23.4S, V4.S[0]
	sshr	V13.4S, V13.4S, #1
	sshr	V14.4S, V14.4S, #1
	sub	V22.4S, V7.4S, V15.4S
	sub	V24.4S, V8.4S, V16.4S
	add	V7.4S, V7.4S, V15.4S
	add	V8.4S, V8.4S, V16.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V15.4S, V22.4S, V0.S[2]
	sqrdmulh	V16.4S, V24.4S, V0.S[2]
	sqrdmlsh	V15.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V15.4S, V15.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V9.4S, V17.4S
	sub	V24.4S, V10.4S, V18.4S
	add	V9.4S, V9.4S, V17.4S
	add	V10.4S, V10.4S, V18.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V17.4S, V22.4S, V0.S[2]
	sqrdmulh	V18.4S, V24.4S, V0.S[2]
	sqrdmlsh	V17.4S, V21.4S, V4.S[0]
	sqrdmlsh	V18.4S, V23.4S, V4.S[0]
	sshr	V17.4S, V17.4S, #1
	sshr	V18.4S, V18.4S, #1
	sub	V22.4S, V11.4S, V19.4S
	sub	V24.4S, V12.4S, V20.4S
	add	V11.4S, V11.4S, V19.4S
	add	V12.4S, V12.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V19.4S, V22.4S, V0.S[2]
	sqrdmulh	V20.4S, V24.4S, V0.S[2]
	sqrdmlsh	V19.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	mul	V21.4S, V5.4S, V2.S[3]
	mul	V22.4S, V6.4S, V2.S[3]
	sqrdmulh	V5.4S, V5.4S, V0.S[3]
	sqrdmulh	V6.4S, V6.4S, V0.S[3]
	sqrdmlsh	V5.4S, V21.4S, V4.S[0]
	sqrdmlsh	V6.4S, V22.4S, V4.S[0]
	sshr	V5.4S, V5.4S, #1
	sshr	V6.4S, V6.4S, #1
	mul	V21.4S, V7.4S, V2.S[3]
	mul	V22.4S, V8.4S, V2.S[3]
	sqrdmulh	V7.4S, V7.4S, V0.S[3]
	sqrdmulh	V8.4S, V8.4S, V0.S[3]
	sqrdmlsh	V7.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V22.4S, V4.S[0]
	sshr	V7.4S, V7.4S, #1
	sshr	V8.4S, V8.4S, #1
	mul	V21.4S, V9.4S, V2.S[3]
	mul	V22.4S, V10.4S, V2.S[3]
	sqrdmulh	V9.4S, V9.4S, V0.S[3]
	sqrdmulh	V10.4S, V10.4S, V0.S[3]
	sqrdmlsh	V9.4S, V21.4S, V4.S[0]
	sqrdmlsh	V10.4S, V22.4S, V4.S[0]
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	mul	V21.4S, V11.4S, V2.S[3]
	mul	V22.4S, V12.4S, V2.S[3]
	sqrdmulh	V11.4S, V11.4S, V0.S[3]
	sqrdmulh	V12.4S, V12.4S, V0.S[3]
	sqrdmlsh	V11.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V22.4S, V4.S[0]
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	str	Q5, [x0, #48]
	str	Q6, [x0, #112]
	str	Q7, [x0, #176]
	str	Q8, [x0, #240]
	str	Q9, [x0, #304]
	str	Q10, [x0, #368]
	str	Q11, [x0, #432]
	str	Q12, [x0, #496]
	str	Q13, [x0, #560]
	str	Q14, [x0, #624]
	str	Q15, [x0, #688]
	str	Q16, [x0, #752]
	str	Q17, [x0, #816]
	str	Q18, [x0, #880]
	str	Q19, [x0, #944]
	str	Q20, [x0, #1008]
	ldp	D8, D9, [x29, #16]
	ldp	D10, D11, [x29, #32]
	ldp	D12, D13, [x29, #48]
	ldp	D14, D15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
	ENDP
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mldsa_invntt_full_sqrdmlsh_neon
mldsa_invntt_full_sqrdmlsh_neon PROC
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	stp	D10, D11, [x29, #32]
	stp	D12, D13, [x29, #48]
	stp	D14, D15, [x29, #64]
	adrp	x1, L_mldsa_aarch64_zetas_inv
	add	x1, x1, L_mldsa_aarch64_zetas_inv
	adrp	x2, L_mldsa_aarch64_zetas_inv_qinv
	add	x2, x2, L_mldsa_aarch64_zetas_inv_qinv
	adrp	x3, L_mldsa_aarch64_consts
	add	x3, x3, L_mldsa_aarch64_consts
	ldr	Q4, [x3]
	ldp	Q5, Q6, [x0]
	ldp	Q7, Q8, [x0, #32]
	ldp	Q9, Q10, [x0, #64]
	ldp	Q11, Q12, [x0, #96]
	ldp	Q13, Q14, [x0, #128]
	ldp	Q15, Q16, [x0, #160]
	ldp	Q17, Q18, [x0, #192]
	ldp	Q19, Q20, [x0, #224]
	trn1	V21.2D, V5.2D, V6.2D
	trn2	V22.2D, V5.2D, V6.2D
	trn1	V5.4S, V21.4S, V22.4S
	trn2	V6.4S, V21.4S, V22.4S
	trn1	V21.2D, V7.2D, V8.2D
	trn2	V22.2D, V7.2D, V8.2D
	trn1	V7.4S, V21.4S, V22.4S
	trn2	V8.4S, V21.4S, V22.4S
	trn1	V21.2D, V9.2D, V10.2D
	trn2	V22.2D, V9.2D, V10.2D
	trn1	V9.4S, V21.4S, V22.4S
	trn2	V10.4S, V21.4S, V22.4S
	trn1	V21.2D, V11.2D, V12.2D
	trn2	V22.2D, V11.2D, V12.2D
	trn1	V11.4S, V21.4S, V22.4S
	trn2	V12.4S, V21.4S, V22.4S
	trn1	V21.2D, V13.2D, V14.2D
	trn2	V22.2D, V13.2D, V14.2D
	trn1	V13.4S, V21.4S, V22.4S
	trn2	V14.4S, V21.4S, V22.4S
	trn1	V21.2D, V15.2D, V16.2D
	trn2	V22.2D, V15.2D, V16.2D
	trn1	V15.4S, V21.4S, V22.4S
	trn2	V16.4S, V21.4S, V22.4S
	trn1	V21.2D, V17.2D, V18.2D
	trn2	V22.2D, V17.2D, V18.2D
	trn1	V17.4S, V21.4S, V22.4S
	trn2	V18.4S, V21.4S, V22.4S
	trn1	V21.2D, V19.2D, V20.2D
	trn2	V22.2D, V19.2D, V20.2D
	trn1	V19.4S, V21.4S, V22.4S
	trn2	V20.4S, V21.4S, V22.4S
	ldp	Q0, Q1, [x1]
	ldp	Q2, Q3, [x2]
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V6.4S, V22.4S, V0.4S
	sqrdmulh	V8.4S, V24.4S, V1.4S
	sqrdmlsh	V6.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V23.4S, V4.S[0]
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	ldp	Q0, Q1, [x1, #32]
	ldp	Q2, Q3, [x2, #32]
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V10.4S, V22.4S, V0.4S
	sqrdmulh	V12.4S, V24.4S, V1.4S
	sqrdmlsh	V10.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	ldp	Q0, Q1, [x1, #64]
	ldp	Q2, Q3, [x2, #64]
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V14.4S, V22.4S, V0.4S
	sqrdmulh	V16.4S, V24.4S, V1.4S
	sqrdmlsh	V14.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	ldp	Q0, Q1, [x1, #96]
	ldp	Q2, Q3, [x2, #96]
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V18.4S, V22.4S, V0.4S
	sqrdmulh	V20.4S, V24.4S, V1.4S
	sqrdmlsh	V18.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldp	Q0, Q1, [x1, #512]
	ldp	Q2, Q3, [x2, #512]
	mov	V21.16B, V5.16B
	mov	V22.16B, V7.16B
	trn1	V5.4S, V5.4S, V6.4S
	trn1	V7.4S, V7.4S, V8.4S
	trn2	V6.4S, V21.4S, V6.4S
	trn2	V8.4S, V22.4S, V8.4S
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V6.4S, V22.4S, V0.4S
	sqrdmulh	V8.4S, V24.4S, V1.4S
	sqrdmlsh	V6.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V23.4S, V4.S[0]
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	ldp	Q0, Q1, [x1, #544]
	ldp	Q2, Q3, [x2, #544]
	mov	V21.16B, V9.16B
	mov	V22.16B, V11.16B
	trn1	V9.4S, V9.4S, V10.4S
	trn1	V11.4S, V11.4S, V12.4S
	trn2	V10.4S, V21.4S, V10.4S
	trn2	V12.4S, V22.4S, V12.4S
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V10.4S, V22.4S, V0.4S
	sqrdmulh	V12.4S, V24.4S, V1.4S
	sqrdmlsh	V10.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	ldp	Q0, Q1, [x1, #576]
	ldp	Q2, Q3, [x2, #576]
	mov	V21.16B, V13.16B
	mov	V22.16B, V15.16B
	trn1	V13.4S, V13.4S, V14.4S
	trn1	V15.4S, V15.4S, V16.4S
	trn2	V14.4S, V21.4S, V14.4S
	trn2	V16.4S, V22.4S, V16.4S
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V14.4S, V22.4S, V0.4S
	sqrdmulh	V16.4S, V24.4S, V1.4S
	sqrdmlsh	V14.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	ldp	Q0, Q1, [x1, #608]
	ldp	Q2, Q3, [x2, #608]
	mov	V21.16B, V17.16B
	mov	V22.16B, V19.16B
	trn1	V17.4S, V17.4S, V18.4S
	trn1	V19.4S, V19.4S, V20.4S
	trn2	V18.4S, V21.4S, V18.4S
	trn2	V20.4S, V22.4S, V20.4S
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V18.4S, V22.4S, V0.4S
	sqrdmulh	V20.4S, V24.4S, V1.4S
	sqrdmlsh	V18.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1024]
	ldr	Q1, [x1, #1040]
	ldr	Q2, [x2, #1024]
	ldr	Q3, [x2, #1040]
	mov	V21.16B, V5.16B
	mov	V22.16B, V7.16B
	trn1	V5.2D, V5.2D, V6.2D
	trn1	V7.2D, V7.2D, V8.2D
	trn2	V6.2D, V21.2D, V6.2D
	trn2	V8.2D, V22.2D, V8.2D
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V6.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[1]
	sqrdmlsh	V6.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V23.4S, V4.S[0]
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	mov	V21.16B, V9.16B
	mov	V22.16B, V11.16B
	trn1	V9.2D, V9.2D, V10.2D
	trn1	V11.2D, V11.2D, V12.2D
	trn2	V10.2D, V21.2D, V10.2D
	trn2	V12.2D, V22.2D, V12.2D
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V10.4S, V22.4S, V0.S[2]
	sqrdmulh	V12.4S, V24.4S, V0.S[3]
	sqrdmlsh	V10.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	mov	V21.16B, V13.16B
	mov	V22.16B, V15.16B
	trn1	V13.2D, V13.2D, V14.2D
	trn1	V15.2D, V15.2D, V16.2D
	trn2	V14.2D, V21.2D, V14.2D
	trn2	V16.2D, V22.2D, V16.2D
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V3.S[0]
	mul	V23.4S, V24.4S, V3.S[1]
	sqrdmulh	V14.4S, V22.4S, V1.S[0]
	sqrdmulh	V16.4S, V24.4S, V1.S[1]
	sqrdmlsh	V14.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	mov	V21.16B, V17.16B
	mov	V22.16B, V19.16B
	trn1	V17.2D, V17.2D, V18.2D
	trn1	V19.2D, V19.2D, V20.2D
	trn2	V18.2D, V21.2D, V18.2D
	trn2	V20.2D, V22.2D, V20.2D
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V3.S[2]
	mul	V23.4S, V24.4S, V3.S[3]
	sqrdmulh	V18.4S, V22.4S, V1.S[2]
	sqrdmulh	V20.4S, V24.4S, V1.S[3]
	sqrdmlsh	V18.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1152]
	ldr	Q2, [x2, #1152]
	sub	V22.4S, V5.4S, V7.4S
	sub	V24.4S, V6.4S, V8.4S
	add	V5.4S, V5.4S, V7.4S
	add	V6.4S, V6.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V7.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[0]
	sqrdmlsh	V7.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V23.4S, V4.S[0]
	sshr	V7.4S, V7.4S, #1
	sshr	V8.4S, V8.4S, #1
	sub	V22.4S, V9.4S, V11.4S
	sub	V24.4S, V10.4S, V12.4S
	add	V9.4S, V9.4S, V11.4S
	add	V10.4S, V10.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V11.4S, V22.4S, V0.S[1]
	sqrdmulh	V12.4S, V24.4S, V0.S[1]
	sqrdmlsh	V11.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V15.4S
	sub	V24.4S, V14.4S, V16.4S
	add	V13.4S, V13.4S, V15.4S
	add	V14.4S, V14.4S, V16.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V15.4S, V22.4S, V0.S[2]
	sqrdmulh	V16.4S, V24.4S, V0.S[2]
	sqrdmlsh	V15.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V15.4S, V15.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V17.4S, V19.4S
	sub	V24.4S, V18.4S, V20.4S
	add	V17.4S, V17.4S, V19.4S
	add	V18.4S, V18.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[3]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V19.4S, V22.4S, V0.S[3]
	sqrdmulh	V20.4S, V24.4S, V0.S[3]
	sqrdmlsh	V19.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	stp	Q5, Q6, [x0]
	stp	Q7, Q8, [x0, #32]
	stp	Q9, Q10, [x0, #64]
	stp	Q11, Q12, [x0, #96]
	stp	Q13, Q14, [x0, #128]
	stp	Q15, Q16, [x0, #160]
	stp	Q17, Q18, [x0, #192]
	stp	Q19, Q20, [x0, #224]
	ldp	Q5, Q6, [x0, #256]
	ldp	Q7, Q8, [x0, #288]
	ldp	Q9, Q10, [x0, #320]
	ldp	Q11, Q12, [x0, #352]
	ldp	Q13, Q14, [x0, #384]
	ldp	Q15, Q16, [x0, #416]
	ldp	Q17, Q18, [x0, #448]
	ldp	Q19, Q20, [x0, #480]
	trn1	V21.2D, V5.2D, V6.2D
	trn2	V22.2D, V5.2D, V6.2D
	trn1	V5.4S, V21.4S, V22.4S
	trn2	V6.4S, V21.4S, V22.4S
	trn1	V21.2D, V7.2D, V8.2D
	trn2	V22.2D, V7.2D, V8.2D
	trn1	V7.4S, V21.4S, V22.4S
	trn2	V8.4S, V21.4S, V22.4S
	trn1	V21.2D, V9.2D, V10.2D
	trn2	V22.2D, V9.2D, V10.2D
	trn1	V9.4S, V21.4S, V22.4S
	trn2	V10.4S, V21.4S, V22.4S
	trn1	V21.2D, V11.2D, V12.2D
	trn2	V22.2D, V11.2D, V12.2D
	trn1	V11.4S, V21.4S, V22.4S
	trn2	V12.4S, V21.4S, V22.4S
	trn1	V21.2D, V13.2D, V14.2D
	trn2	V22.2D, V13.2D, V14.2D
	trn1	V13.4S, V21.4S, V22.4S
	trn2	V14.4S, V21.4S, V22.4S
	trn1	V21.2D, V15.2D, V16.2D
	trn2	V22.2D, V15.2D, V16.2D
	trn1	V15.4S, V21.4S, V22.4S
	trn2	V16.4S, V21.4S, V22.4S
	trn1	V21.2D, V17.2D, V18.2D
	trn2	V22.2D, V17.2D, V18.2D
	trn1	V17.4S, V21.4S, V22.4S
	trn2	V18.4S, V21.4S, V22.4S
	trn1	V21.2D, V19.2D, V20.2D
	trn2	V22.2D, V19.2D, V20.2D
	trn1	V19.4S, V21.4S, V22.4S
	trn2	V20.4S, V21.4S, V22.4S
	ldp	Q0, Q1, [x1, #128]
	ldp	Q2, Q3, [x2, #128]
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V6.4S, V22.4S, V0.4S
	sqrdmulh	V8.4S, V24.4S, V1.4S
	sqrdmlsh	V6.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V23.4S, V4.S[0]
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	ldp	Q0, Q1, [x1, #160]
	ldp	Q2, Q3, [x2, #160]
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V10.4S, V22.4S, V0.4S
	sqrdmulh	V12.4S, V24.4S, V1.4S
	sqrdmlsh	V10.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	ldp	Q0, Q1, [x1, #192]
	ldp	Q2, Q3, [x2, #192]
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V14.4S, V22.4S, V0.4S
	sqrdmulh	V16.4S, V24.4S, V1.4S
	sqrdmlsh	V14.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	ldp	Q0, Q1, [x1, #224]
	ldp	Q2, Q3, [x2, #224]
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V18.4S, V22.4S, V0.4S
	sqrdmulh	V20.4S, V24.4S, V1.4S
	sqrdmlsh	V18.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldp	Q0, Q1, [x1, #640]
	ldp	Q2, Q3, [x2, #640]
	mov	V21.16B, V5.16B
	mov	V22.16B, V7.16B
	trn1	V5.4S, V5.4S, V6.4S
	trn1	V7.4S, V7.4S, V8.4S
	trn2	V6.4S, V21.4S, V6.4S
	trn2	V8.4S, V22.4S, V8.4S
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V6.4S, V22.4S, V0.4S
	sqrdmulh	V8.4S, V24.4S, V1.4S
	sqrdmlsh	V6.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V23.4S, V4.S[0]
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	ldp	Q0, Q1, [x1, #672]
	ldp	Q2, Q3, [x2, #672]
	mov	V21.16B, V9.16B
	mov	V22.16B, V11.16B
	trn1	V9.4S, V9.4S, V10.4S
	trn1	V11.4S, V11.4S, V12.4S
	trn2	V10.4S, V21.4S, V10.4S
	trn2	V12.4S, V22.4S, V12.4S
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V10.4S, V22.4S, V0.4S
	sqrdmulh	V12.4S, V24.4S, V1.4S
	sqrdmlsh	V10.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	ldp	Q0, Q1, [x1, #704]
	ldp	Q2, Q3, [x2, #704]
	mov	V21.16B, V13.16B
	mov	V22.16B, V15.16B
	trn1	V13.4S, V13.4S, V14.4S
	trn1	V15.4S, V15.4S, V16.4S
	trn2	V14.4S, V21.4S, V14.4S
	trn2	V16.4S, V22.4S, V16.4S
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V14.4S, V22.4S, V0.4S
	sqrdmulh	V16.4S, V24.4S, V1.4S
	sqrdmlsh	V14.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	ldp	Q0, Q1, [x1, #736]
	ldp	Q2, Q3, [x2, #736]
	mov	V21.16B, V17.16B
	mov	V22.16B, V19.16B
	trn1	V17.4S, V17.4S, V18.4S
	trn1	V19.4S, V19.4S, V20.4S
	trn2	V18.4S, V21.4S, V18.4S
	trn2	V20.4S, V22.4S, V20.4S
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V18.4S, V22.4S, V0.4S
	sqrdmulh	V20.4S, V24.4S, V1.4S
	sqrdmlsh	V18.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1056]
	ldr	Q1, [x1, #1072]
	ldr	Q2, [x2, #1056]
	ldr	Q3, [x2, #1072]
	mov	V21.16B, V5.16B
	mov	V22.16B, V7.16B
	trn1	V5.2D, V5.2D, V6.2D
	trn1	V7.2D, V7.2D, V8.2D
	trn2	V6.2D, V21.2D, V6.2D
	trn2	V8.2D, V22.2D, V8.2D
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V6.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[1]
	sqrdmlsh	V6.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V23.4S, V4.S[0]
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	mov	V21.16B, V9.16B
	mov	V22.16B, V11.16B
	trn1	V9.2D, V9.2D, V10.2D
	trn1	V11.2D, V11.2D, V12.2D
	trn2	V10.2D, V21.2D, V10.2D
	trn2	V12.2D, V22.2D, V12.2D
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V10.4S, V22.4S, V0.S[2]
	sqrdmulh	V12.4S, V24.4S, V0.S[3]
	sqrdmlsh	V10.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	mov	V21.16B, V13.16B
	mov	V22.16B, V15.16B
	trn1	V13.2D, V13.2D, V14.2D
	trn1	V15.2D, V15.2D, V16.2D
	trn2	V14.2D, V21.2D, V14.2D
	trn2	V16.2D, V22.2D, V16.2D
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V3.S[0]
	mul	V23.4S, V24.4S, V3.S[1]
	sqrdmulh	V14.4S, V22.4S, V1.S[0]
	sqrdmulh	V16.4S, V24.4S, V1.S[1]
	sqrdmlsh	V14.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	mov	V21.16B, V17.16B
	mov	V22.16B, V19.16B
	trn1	V17.2D, V17.2D, V18.2D
	trn1	V19.2D, V19.2D, V20.2D
	trn2	V18.2D, V21.2D, V18.2D
	trn2	V20.2D, V22.2D, V20.2D
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V3.S[2]
	mul	V23.4S, V24.4S, V3.S[3]
	sqrdmulh	V18.4S, V22.4S, V1.S[2]
	sqrdmulh	V20.4S, V24.4S, V1.S[3]
	sqrdmlsh	V18.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1168]
	ldr	Q2, [x2, #1168]
	sub	V22.4S, V5.4S, V7.4S
	sub	V24.4S, V6.4S, V8.4S
	add	V5.4S, V5.4S, V7.4S
	add	V6.4S, V6.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V7.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[0]
	sqrdmlsh	V7.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V23.4S, V4.S[0]
	sshr	V7.4S, V7.4S, #1
	sshr	V8.4S, V8.4S, #1
	sub	V22.4S, V9.4S, V11.4S
	sub	V24.4S, V10.4S, V12.4S
	add	V9.4S, V9.4S, V11.4S
	add	V10.4S, V10.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V11.4S, V22.4S, V0.S[1]
	sqrdmulh	V12.4S, V24.4S, V0.S[1]
	sqrdmlsh	V11.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V15.4S
	sub	V24.4S, V14.4S, V16.4S
	add	V13.4S, V13.4S, V15.4S
	add	V14.4S, V14.4S, V16.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V15.4S, V22.4S, V0.S[2]
	sqrdmulh	V16.4S, V24.4S, V0.S[2]
	sqrdmlsh	V15.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V15.4S, V15.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V17.4S, V19.4S
	sub	V24.4S, V18.4S, V20.4S
	add	V17.4S, V17.4S, V19.4S
	add	V18.4S, V18.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[3]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V19.4S, V22.4S, V0.S[3]
	sqrdmulh	V20.4S, V24.4S, V0.S[3]
	sqrdmlsh	V19.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	stp	Q5, Q6, [x0, #256]
	stp	Q7, Q8, [x0, #288]
	stp	Q9, Q10, [x0, #320]
	stp	Q11, Q12, [x0, #352]
	stp	Q13, Q14, [x0, #384]
	stp	Q15, Q16, [x0, #416]
	stp	Q17, Q18, [x0, #448]
	stp	Q19, Q20, [x0, #480]
	ldp	Q5, Q6, [x0, #512]
	ldp	Q7, Q8, [x0, #544]
	ldp	Q9, Q10, [x0, #576]
	ldp	Q11, Q12, [x0, #608]
	ldp	Q13, Q14, [x0, #640]
	ldp	Q15, Q16, [x0, #672]
	ldp	Q17, Q18, [x0, #704]
	ldp	Q19, Q20, [x0, #736]
	trn1	V21.2D, V5.2D, V6.2D
	trn2	V22.2D, V5.2D, V6.2D
	trn1	V5.4S, V21.4S, V22.4S
	trn2	V6.4S, V21.4S, V22.4S
	trn1	V21.2D, V7.2D, V8.2D
	trn2	V22.2D, V7.2D, V8.2D
	trn1	V7.4S, V21.4S, V22.4S
	trn2	V8.4S, V21.4S, V22.4S
	trn1	V21.2D, V9.2D, V10.2D
	trn2	V22.2D, V9.2D, V10.2D
	trn1	V9.4S, V21.4S, V22.4S
	trn2	V10.4S, V21.4S, V22.4S
	trn1	V21.2D, V11.2D, V12.2D
	trn2	V22.2D, V11.2D, V12.2D
	trn1	V11.4S, V21.4S, V22.4S
	trn2	V12.4S, V21.4S, V22.4S
	trn1	V21.2D, V13.2D, V14.2D
	trn2	V22.2D, V13.2D, V14.2D
	trn1	V13.4S, V21.4S, V22.4S
	trn2	V14.4S, V21.4S, V22.4S
	trn1	V21.2D, V15.2D, V16.2D
	trn2	V22.2D, V15.2D, V16.2D
	trn1	V15.4S, V21.4S, V22.4S
	trn2	V16.4S, V21.4S, V22.4S
	trn1	V21.2D, V17.2D, V18.2D
	trn2	V22.2D, V17.2D, V18.2D
	trn1	V17.4S, V21.4S, V22.4S
	trn2	V18.4S, V21.4S, V22.4S
	trn1	V21.2D, V19.2D, V20.2D
	trn2	V22.2D, V19.2D, V20.2D
	trn1	V19.4S, V21.4S, V22.4S
	trn2	V20.4S, V21.4S, V22.4S
	ldp	Q0, Q1, [x1, #256]
	ldp	Q2, Q3, [x2, #256]
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V6.4S, V22.4S, V0.4S
	sqrdmulh	V8.4S, V24.4S, V1.4S
	sqrdmlsh	V6.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V23.4S, V4.S[0]
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	ldp	Q0, Q1, [x1, #288]
	ldp	Q2, Q3, [x2, #288]
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V10.4S, V22.4S, V0.4S
	sqrdmulh	V12.4S, V24.4S, V1.4S
	sqrdmlsh	V10.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	ldp	Q0, Q1, [x1, #320]
	ldp	Q2, Q3, [x2, #320]
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V14.4S, V22.4S, V0.4S
	sqrdmulh	V16.4S, V24.4S, V1.4S
	sqrdmlsh	V14.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	ldp	Q0, Q1, [x1, #352]
	ldp	Q2, Q3, [x2, #352]
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V18.4S, V22.4S, V0.4S
	sqrdmulh	V20.4S, V24.4S, V1.4S
	sqrdmlsh	V18.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldp	Q0, Q1, [x1, #768]
	ldp	Q2, Q3, [x2, #768]
	mov	V21.16B, V5.16B
	mov	V22.16B, V7.16B
	trn1	V5.4S, V5.4S, V6.4S
	trn1	V7.4S, V7.4S, V8.4S
	trn2	V6.4S, V21.4S, V6.4S
	trn2	V8.4S, V22.4S, V8.4S
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V6.4S, V22.4S, V0.4S
	sqrdmulh	V8.4S, V24.4S, V1.4S
	sqrdmlsh	V6.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V23.4S, V4.S[0]
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	ldp	Q0, Q1, [x1, #800]
	ldp	Q2, Q3, [x2, #800]
	mov	V21.16B, V9.16B
	mov	V22.16B, V11.16B
	trn1	V9.4S, V9.4S, V10.4S
	trn1	V11.4S, V11.4S, V12.4S
	trn2	V10.4S, V21.4S, V10.4S
	trn2	V12.4S, V22.4S, V12.4S
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V10.4S, V22.4S, V0.4S
	sqrdmulh	V12.4S, V24.4S, V1.4S
	sqrdmlsh	V10.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	ldp	Q0, Q1, [x1, #832]
	ldp	Q2, Q3, [x2, #832]
	mov	V21.16B, V13.16B
	mov	V22.16B, V15.16B
	trn1	V13.4S, V13.4S, V14.4S
	trn1	V15.4S, V15.4S, V16.4S
	trn2	V14.4S, V21.4S, V14.4S
	trn2	V16.4S, V22.4S, V16.4S
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V14.4S, V22.4S, V0.4S
	sqrdmulh	V16.4S, V24.4S, V1.4S
	sqrdmlsh	V14.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	ldp	Q0, Q1, [x1, #864]
	ldp	Q2, Q3, [x2, #864]
	mov	V21.16B, V17.16B
	mov	V22.16B, V19.16B
	trn1	V17.4S, V17.4S, V18.4S
	trn1	V19.4S, V19.4S, V20.4S
	trn2	V18.4S, V21.4S, V18.4S
	trn2	V20.4S, V22.4S, V20.4S
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V18.4S, V22.4S, V0.4S
	sqrdmulh	V20.4S, V24.4S, V1.4S
	sqrdmlsh	V18.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1088]
	ldr	Q1, [x1, #1104]
	ldr	Q2, [x2, #1088]
	ldr	Q3, [x2, #1104]
	mov	V21.16B, V5.16B
	mov	V22.16B, V7.16B
	trn1	V5.2D, V5.2D, V6.2D
	trn1	V7.2D, V7.2D, V8.2D
	trn2	V6.2D, V21.2D, V6.2D
	trn2	V8.2D, V22.2D, V8.2D
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V6.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[1]
	sqrdmlsh	V6.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V23.4S, V4.S[0]
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	mov	V21.16B, V9.16B
	mov	V22.16B, V11.16B
	trn1	V9.2D, V9.2D, V10.2D
	trn1	V11.2D, V11.2D, V12.2D
	trn2	V10.2D, V21.2D, V10.2D
	trn2	V12.2D, V22.2D, V12.2D
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V10.4S, V22.4S, V0.S[2]
	sqrdmulh	V12.4S, V24.4S, V0.S[3]
	sqrdmlsh	V10.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	mov	V21.16B, V13.16B
	mov	V22.16B, V15.16B
	trn1	V13.2D, V13.2D, V14.2D
	trn1	V15.2D, V15.2D, V16.2D
	trn2	V14.2D, V21.2D, V14.2D
	trn2	V16.2D, V22.2D, V16.2D
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V3.S[0]
	mul	V23.4S, V24.4S, V3.S[1]
	sqrdmulh	V14.4S, V22.4S, V1.S[0]
	sqrdmulh	V16.4S, V24.4S, V1.S[1]
	sqrdmlsh	V14.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	mov	V21.16B, V17.16B
	mov	V22.16B, V19.16B
	trn1	V17.2D, V17.2D, V18.2D
	trn1	V19.2D, V19.2D, V20.2D
	trn2	V18.2D, V21.2D, V18.2D
	trn2	V20.2D, V22.2D, V20.2D
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V3.S[2]
	mul	V23.4S, V24.4S, V3.S[3]
	sqrdmulh	V18.4S, V22.4S, V1.S[2]
	sqrdmulh	V20.4S, V24.4S, V1.S[3]
	sqrdmlsh	V18.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1184]
	ldr	Q2, [x2, #1184]
	sub	V22.4S, V5.4S, V7.4S
	sub	V24.4S, V6.4S, V8.4S
	add	V5.4S, V5.4S, V7.4S
	add	V6.4S, V6.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V7.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[0]
	sqrdmlsh	V7.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V23.4S, V4.S[0]
	sshr	V7.4S, V7.4S, #1
	sshr	V8.4S, V8.4S, #1
	sub	V22.4S, V9.4S, V11.4S
	sub	V24.4S, V10.4S, V12.4S
	add	V9.4S, V9.4S, V11.4S
	add	V10.4S, V10.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V11.4S, V22.4S, V0.S[1]
	sqrdmulh	V12.4S, V24.4S, V0.S[1]
	sqrdmlsh	V11.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V15.4S
	sub	V24.4S, V14.4S, V16.4S
	add	V13.4S, V13.4S, V15.4S
	add	V14.4S, V14.4S, V16.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V15.4S, V22.4S, V0.S[2]
	sqrdmulh	V16.4S, V24.4S, V0.S[2]
	sqrdmlsh	V15.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V15.4S, V15.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V17.4S, V19.4S
	sub	V24.4S, V18.4S, V20.4S
	add	V17.4S, V17.4S, V19.4S
	add	V18.4S, V18.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[3]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V19.4S, V22.4S, V0.S[3]
	sqrdmulh	V20.4S, V24.4S, V0.S[3]
	sqrdmlsh	V19.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	stp	Q5, Q6, [x0, #512]
	stp	Q7, Q8, [x0, #544]
	stp	Q9, Q10, [x0, #576]
	stp	Q11, Q12, [x0, #608]
	stp	Q13, Q14, [x0, #640]
	stp	Q15, Q16, [x0, #672]
	stp	Q17, Q18, [x0, #704]
	stp	Q19, Q20, [x0, #736]
	ldp	Q5, Q6, [x0, #768]
	ldp	Q7, Q8, [x0, #800]
	ldp	Q9, Q10, [x0, #832]
	ldp	Q11, Q12, [x0, #864]
	ldp	Q13, Q14, [x0, #896]
	ldp	Q15, Q16, [x0, #928]
	ldp	Q17, Q18, [x0, #960]
	ldp	Q19, Q20, [x0, #992]
	trn1	V21.2D, V5.2D, V6.2D
	trn2	V22.2D, V5.2D, V6.2D
	trn1	V5.4S, V21.4S, V22.4S
	trn2	V6.4S, V21.4S, V22.4S
	trn1	V21.2D, V7.2D, V8.2D
	trn2	V22.2D, V7.2D, V8.2D
	trn1	V7.4S, V21.4S, V22.4S
	trn2	V8.4S, V21.4S, V22.4S
	trn1	V21.2D, V9.2D, V10.2D
	trn2	V22.2D, V9.2D, V10.2D
	trn1	V9.4S, V21.4S, V22.4S
	trn2	V10.4S, V21.4S, V22.4S
	trn1	V21.2D, V11.2D, V12.2D
	trn2	V22.2D, V11.2D, V12.2D
	trn1	V11.4S, V21.4S, V22.4S
	trn2	V12.4S, V21.4S, V22.4S
	trn1	V21.2D, V13.2D, V14.2D
	trn2	V22.2D, V13.2D, V14.2D
	trn1	V13.4S, V21.4S, V22.4S
	trn2	V14.4S, V21.4S, V22.4S
	trn1	V21.2D, V15.2D, V16.2D
	trn2	V22.2D, V15.2D, V16.2D
	trn1	V15.4S, V21.4S, V22.4S
	trn2	V16.4S, V21.4S, V22.4S
	trn1	V21.2D, V17.2D, V18.2D
	trn2	V22.2D, V17.2D, V18.2D
	trn1	V17.4S, V21.4S, V22.4S
	trn2	V18.4S, V21.4S, V22.4S
	trn1	V21.2D, V19.2D, V20.2D
	trn2	V22.2D, V19.2D, V20.2D
	trn1	V19.4S, V21.4S, V22.4S
	trn2	V20.4S, V21.4S, V22.4S
	ldp	Q0, Q1, [x1, #384]
	ldp	Q2, Q3, [x2, #384]
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V6.4S, V22.4S, V0.4S
	sqrdmulh	V8.4S, V24.4S, V1.4S
	sqrdmlsh	V6.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V23.4S, V4.S[0]
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	ldp	Q0, Q1, [x1, #416]
	ldp	Q2, Q3, [x2, #416]
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V10.4S, V22.4S, V0.4S
	sqrdmulh	V12.4S, V24.4S, V1.4S
	sqrdmlsh	V10.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	ldp	Q0, Q1, [x1, #448]
	ldp	Q2, Q3, [x2, #448]
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V14.4S, V22.4S, V0.4S
	sqrdmulh	V16.4S, V24.4S, V1.4S
	sqrdmlsh	V14.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	ldp	Q0, Q1, [x1, #480]
	ldp	Q2, Q3, [x2, #480]
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V18.4S, V22.4S, V0.4S
	sqrdmulh	V20.4S, V24.4S, V1.4S
	sqrdmlsh	V18.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldp	Q0, Q1, [x1, #896]
	ldp	Q2, Q3, [x2, #896]
	mov	V21.16B, V5.16B
	mov	V22.16B, V7.16B
	trn1	V5.4S, V5.4S, V6.4S
	trn1	V7.4S, V7.4S, V8.4S
	trn2	V6.4S, V21.4S, V6.4S
	trn2	V8.4S, V22.4S, V8.4S
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V6.4S, V22.4S, V0.4S
	sqrdmulh	V8.4S, V24.4S, V1.4S
	sqrdmlsh	V6.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V23.4S, V4.S[0]
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	ldp	Q0, Q1, [x1, #928]
	ldp	Q2, Q3, [x2, #928]
	mov	V21.16B, V9.16B
	mov	V22.16B, V11.16B
	trn1	V9.4S, V9.4S, V10.4S
	trn1	V11.4S, V11.4S, V12.4S
	trn2	V10.4S, V21.4S, V10.4S
	trn2	V12.4S, V22.4S, V12.4S
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V10.4S, V22.4S, V0.4S
	sqrdmulh	V12.4S, V24.4S, V1.4S
	sqrdmlsh	V10.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	ldp	Q0, Q1, [x1, #960]
	ldp	Q2, Q3, [x2, #960]
	mov	V21.16B, V13.16B
	mov	V22.16B, V15.16B
	trn1	V13.4S, V13.4S, V14.4S
	trn1	V15.4S, V15.4S, V16.4S
	trn2	V14.4S, V21.4S, V14.4S
	trn2	V16.4S, V22.4S, V16.4S
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V14.4S, V22.4S, V0.4S
	sqrdmulh	V16.4S, V24.4S, V1.4S
	sqrdmlsh	V14.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	ldp	Q0, Q1, [x1, #992]
	ldp	Q2, Q3, [x2, #992]
	mov	V21.16B, V17.16B
	mov	V22.16B, V19.16B
	trn1	V17.4S, V17.4S, V18.4S
	trn1	V19.4S, V19.4S, V20.4S
	trn2	V18.4S, V21.4S, V18.4S
	trn2	V20.4S, V22.4S, V20.4S
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V2.4S
	mul	V23.4S, V24.4S, V3.4S
	sqrdmulh	V18.4S, V22.4S, V0.4S
	sqrdmulh	V20.4S, V24.4S, V1.4S
	sqrdmlsh	V18.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1120]
	ldr	Q1, [x1, #1136]
	ldr	Q2, [x2, #1120]
	ldr	Q3, [x2, #1136]
	mov	V21.16B, V5.16B
	mov	V22.16B, V7.16B
	trn1	V5.2D, V5.2D, V6.2D
	trn1	V7.2D, V7.2D, V8.2D
	trn2	V6.2D, V21.2D, V6.2D
	trn2	V8.2D, V22.2D, V8.2D
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V6.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[1]
	sqrdmlsh	V6.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V23.4S, V4.S[0]
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	mov	V21.16B, V9.16B
	mov	V22.16B, V11.16B
	trn1	V9.2D, V9.2D, V10.2D
	trn1	V11.2D, V11.2D, V12.2D
	trn2	V10.2D, V21.2D, V10.2D
	trn2	V12.2D, V22.2D, V12.2D
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V10.4S, V22.4S, V0.S[2]
	sqrdmulh	V12.4S, V24.4S, V0.S[3]
	sqrdmlsh	V10.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	mov	V21.16B, V13.16B
	mov	V22.16B, V15.16B
	trn1	V13.2D, V13.2D, V14.2D
	trn1	V15.2D, V15.2D, V16.2D
	trn2	V14.2D, V21.2D, V14.2D
	trn2	V16.2D, V22.2D, V16.2D
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V3.S[0]
	mul	V23.4S, V24.4S, V3.S[1]
	sqrdmulh	V14.4S, V22.4S, V1.S[0]
	sqrdmulh	V16.4S, V24.4S, V1.S[1]
	sqrdmlsh	V14.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	mov	V21.16B, V17.16B
	mov	V22.16B, V19.16B
	trn1	V17.2D, V17.2D, V18.2D
	trn1	V19.2D, V19.2D, V20.2D
	trn2	V18.2D, V21.2D, V18.2D
	trn2	V20.2D, V22.2D, V20.2D
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V3.S[2]
	mul	V23.4S, V24.4S, V3.S[3]
	sqrdmulh	V18.4S, V22.4S, V1.S[2]
	sqrdmulh	V20.4S, V24.4S, V1.S[3]
	sqrdmlsh	V18.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1200]
	ldr	Q2, [x2, #1200]
	sub	V22.4S, V5.4S, V7.4S
	sub	V24.4S, V6.4S, V8.4S
	add	V5.4S, V5.4S, V7.4S
	add	V6.4S, V6.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V7.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[0]
	sqrdmlsh	V7.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V23.4S, V4.S[0]
	sshr	V7.4S, V7.4S, #1
	sshr	V8.4S, V8.4S, #1
	sub	V22.4S, V9.4S, V11.4S
	sub	V24.4S, V10.4S, V12.4S
	add	V9.4S, V9.4S, V11.4S
	add	V10.4S, V10.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V11.4S, V22.4S, V0.S[1]
	sqrdmulh	V12.4S, V24.4S, V0.S[1]
	sqrdmlsh	V11.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V15.4S
	sub	V24.4S, V14.4S, V16.4S
	add	V13.4S, V13.4S, V15.4S
	add	V14.4S, V14.4S, V16.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V15.4S, V22.4S, V0.S[2]
	sqrdmulh	V16.4S, V24.4S, V0.S[2]
	sqrdmlsh	V15.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V15.4S, V15.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V17.4S, V19.4S
	sub	V24.4S, V18.4S, V20.4S
	add	V17.4S, V17.4S, V19.4S
	add	V18.4S, V18.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[3]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V19.4S, V22.4S, V0.S[3]
	sqrdmulh	V20.4S, V24.4S, V0.S[3]
	sqrdmlsh	V19.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	stp	Q5, Q6, [x0, #768]
	stp	Q7, Q8, [x0, #800]
	stp	Q9, Q10, [x0, #832]
	stp	Q11, Q12, [x0, #864]
	stp	Q13, Q14, [x0, #896]
	stp	Q15, Q16, [x0, #928]
	stp	Q17, Q18, [x0, #960]
	stp	Q19, Q20, [x0, #992]
	ldr	Q5, [x0]
	ldr	Q6, [x0, #64]
	ldr	Q7, [x0, #128]
	ldr	Q8, [x0, #192]
	ldr	Q9, [x0, #256]
	ldr	Q10, [x0, #320]
	ldr	Q11, [x0, #384]
	ldr	Q12, [x0, #448]
	ldr	Q13, [x0, #512]
	ldr	Q14, [x0, #576]
	ldr	Q15, [x0, #640]
	ldr	Q16, [x0, #704]
	ldr	Q17, [x0, #768]
	ldr	Q18, [x0, #832]
	ldr	Q19, [x0, #896]
	ldr	Q20, [x0, #960]
	ldr	Q0, [x1, #1216]
	ldr	Q1, [x1, #1232]
	ldr	Q2, [x2, #1216]
	ldr	Q3, [x2, #1232]
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V6.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[1]
	sqrdmlsh	V6.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V23.4S, V4.S[0]
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V10.4S, V22.4S, V0.S[2]
	sqrdmulh	V12.4S, V24.4S, V0.S[3]
	sqrdmlsh	V10.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V3.S[0]
	mul	V23.4S, V24.4S, V3.S[1]
	sqrdmulh	V14.4S, V22.4S, V1.S[0]
	sqrdmulh	V16.4S, V24.4S, V1.S[1]
	sqrdmlsh	V14.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V3.S[2]
	mul	V23.4S, V24.4S, V3.S[3]
	sqrdmulh	V18.4S, V22.4S, V1.S[2]
	sqrdmulh	V20.4S, V24.4S, V1.S[3]
	sqrdmlsh	V18.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1248]
	ldr	Q2, [x2, #1248]
	sub	V22.4S, V5.4S, V7.4S
	sub	V24.4S, V6.4S, V8.4S
	add	V5.4S, V5.4S, V7.4S
	add	V6.4S, V6.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V7.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[0]
	sqrdmlsh	V7.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V23.4S, V4.S[0]
	sshr	V7.4S, V7.4S, #1
	sshr	V8.4S, V8.4S, #1
	sub	V22.4S, V9.4S, V11.4S
	sub	V24.4S, V10.4S, V12.4S
	add	V9.4S, V9.4S, V11.4S
	add	V10.4S, V10.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V11.4S, V22.4S, V0.S[1]
	sqrdmulh	V12.4S, V24.4S, V0.S[1]
	sqrdmlsh	V11.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V15.4S
	sub	V24.4S, V14.4S, V16.4S
	add	V13.4S, V13.4S, V15.4S
	add	V14.4S, V14.4S, V16.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V15.4S, V22.4S, V0.S[2]
	sqrdmulh	V16.4S, V24.4S, V0.S[2]
	sqrdmlsh	V15.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V15.4S, V15.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V17.4S, V19.4S
	sub	V24.4S, V18.4S, V20.4S
	add	V17.4S, V17.4S, V19.4S
	add	V18.4S, V18.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[3]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V19.4S, V22.4S, V0.S[3]
	sqrdmulh	V20.4S, V24.4S, V0.S[3]
	sqrdmlsh	V19.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1264]
	ldr	Q2, [x2, #1264]
	sub	V22.4S, V5.4S, V9.4S
	sub	V24.4S, V6.4S, V10.4S
	add	V5.4S, V5.4S, V9.4S
	add	V6.4S, V6.4S, V10.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V9.4S, V22.4S, V0.S[0]
	sqrdmulh	V10.4S, V24.4S, V0.S[0]
	sqrdmlsh	V9.4S, V21.4S, V4.S[0]
	sqrdmlsh	V10.4S, V23.4S, V4.S[0]
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	sub	V22.4S, V7.4S, V11.4S
	sub	V24.4S, V8.4S, V12.4S
	add	V7.4S, V7.4S, V11.4S
	add	V8.4S, V8.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V11.4S, V22.4S, V0.S[0]
	sqrdmulh	V12.4S, V24.4S, V0.S[0]
	sqrdmlsh	V11.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V17.4S
	sub	V24.4S, V14.4S, V18.4S
	add	V13.4S, V13.4S, V17.4S
	add	V14.4S, V14.4S, V18.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V17.4S, V22.4S, V0.S[1]
	sqrdmulh	V18.4S, V24.4S, V0.S[1]
	sqrdmlsh	V17.4S, V21.4S, V4.S[0]
	sqrdmlsh	V18.4S, V23.4S, V4.S[0]
	sshr	V17.4S, V17.4S, #1
	sshr	V18.4S, V18.4S, #1
	sub	V22.4S, V15.4S, V19.4S
	sub	V24.4S, V16.4S, V20.4S
	add	V15.4S, V15.4S, V19.4S
	add	V16.4S, V16.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V19.4S, V22.4S, V0.S[1]
	sqrdmulh	V20.4S, V24.4S, V0.S[1]
	sqrdmlsh	V19.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	sub	V22.4S, V5.4S, V13.4S
	sub	V24.4S, V6.4S, V14.4S
	add	V5.4S, V5.4S, V13.4S
	add	V6.4S, V6.4S, V14.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V13.4S, V22.4S, V0.S[2]
	sqrdmulh	V14.4S, V24.4S, V0.S[2]
	sqrdmlsh	V13.4S, V21.4S, V4.S[0]
	sqrdmlsh	V14.4S, V23.4S, V4.S[0]
	sshr	V13.4S, V13.4S, #1
	sshr	V14.4S, V14.4S, #1
	sub	V22.4S, V7.4S, V15.4S
	sub	V24.4S, V8.4S, V16.4S
	add	V7.4S, V7.4S, V15.4S
	add	V8.4S, V8.4S, V16.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V15.4S, V22.4S, V0.S[2]
	sqrdmulh	V16.4S, V24.4S, V0.S[2]
	sqrdmlsh	V15.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V15.4S, V15.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V9.4S, V17.4S
	sub	V24.4S, V10.4S, V18.4S
	add	V9.4S, V9.4S, V17.4S
	add	V10.4S, V10.4S, V18.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V17.4S, V22.4S, V0.S[2]
	sqrdmulh	V18.4S, V24.4S, V0.S[2]
	sqrdmlsh	V17.4S, V21.4S, V4.S[0]
	sqrdmlsh	V18.4S, V23.4S, V4.S[0]
	sshr	V17.4S, V17.4S, #1
	sshr	V18.4S, V18.4S, #1
	sub	V22.4S, V11.4S, V19.4S
	sub	V24.4S, V12.4S, V20.4S
	add	V11.4S, V11.4S, V19.4S
	add	V12.4S, V12.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V19.4S, V22.4S, V0.S[2]
	sqrdmulh	V20.4S, V24.4S, V0.S[2]
	sqrdmlsh	V19.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	mul	V21.4S, V5.4S, V2.S[3]
	mul	V22.4S, V6.4S, V2.S[3]
	sqrdmulh	V5.4S, V5.4S, V0.S[3]
	sqrdmulh	V6.4S, V6.4S, V0.S[3]
	sqrdmlsh	V5.4S, V21.4S, V4.S[0]
	sqrdmlsh	V6.4S, V22.4S, V4.S[0]
	sshr	V5.4S, V5.4S, #1
	sshr	V6.4S, V6.4S, #1
	mul	V21.4S, V7.4S, V2.S[3]
	mul	V22.4S, V8.4S, V2.S[3]
	sqrdmulh	V7.4S, V7.4S, V0.S[3]
	sqrdmulh	V8.4S, V8.4S, V0.S[3]
	sqrdmlsh	V7.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V22.4S, V4.S[0]
	sshr	V7.4S, V7.4S, #1
	sshr	V8.4S, V8.4S, #1
	mul	V21.4S, V9.4S, V2.S[3]
	mul	V22.4S, V10.4S, V2.S[3]
	sqrdmulh	V9.4S, V9.4S, V0.S[3]
	sqrdmulh	V10.4S, V10.4S, V0.S[3]
	sqrdmlsh	V9.4S, V21.4S, V4.S[0]
	sqrdmlsh	V10.4S, V22.4S, V4.S[0]
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	mul	V21.4S, V11.4S, V2.S[3]
	mul	V22.4S, V12.4S, V2.S[3]
	sqrdmulh	V11.4S, V11.4S, V0.S[3]
	sqrdmulh	V12.4S, V12.4S, V0.S[3]
	sqrdmlsh	V11.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V22.4S, V4.S[0]
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	str	Q5, [x0]
	str	Q6, [x0, #64]
	str	Q7, [x0, #128]
	str	Q8, [x0, #192]
	str	Q9, [x0, #256]
	str	Q10, [x0, #320]
	str	Q11, [x0, #384]
	str	Q12, [x0, #448]
	str	Q13, [x0, #512]
	str	Q14, [x0, #576]
	str	Q15, [x0, #640]
	str	Q16, [x0, #704]
	str	Q17, [x0, #768]
	str	Q18, [x0, #832]
	str	Q19, [x0, #896]
	str	Q20, [x0, #960]
	ldr	Q5, [x0, #16]
	ldr	Q6, [x0, #80]
	ldr	Q7, [x0, #144]
	ldr	Q8, [x0, #208]
	ldr	Q9, [x0, #272]
	ldr	Q10, [x0, #336]
	ldr	Q11, [x0, #400]
	ldr	Q12, [x0, #464]
	ldr	Q13, [x0, #528]
	ldr	Q14, [x0, #592]
	ldr	Q15, [x0, #656]
	ldr	Q16, [x0, #720]
	ldr	Q17, [x0, #784]
	ldr	Q18, [x0, #848]
	ldr	Q19, [x0, #912]
	ldr	Q20, [x0, #976]
	ldr	Q0, [x1, #1216]
	ldr	Q1, [x1, #1232]
	ldr	Q2, [x2, #1216]
	ldr	Q3, [x2, #1232]
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V6.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[1]
	sqrdmlsh	V6.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V23.4S, V4.S[0]
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V10.4S, V22.4S, V0.S[2]
	sqrdmulh	V12.4S, V24.4S, V0.S[3]
	sqrdmlsh	V10.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V3.S[0]
	mul	V23.4S, V24.4S, V3.S[1]
	sqrdmulh	V14.4S, V22.4S, V1.S[0]
	sqrdmulh	V16.4S, V24.4S, V1.S[1]
	sqrdmlsh	V14.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V3.S[2]
	mul	V23.4S, V24.4S, V3.S[3]
	sqrdmulh	V18.4S, V22.4S, V1.S[2]
	sqrdmulh	V20.4S, V24.4S, V1.S[3]
	sqrdmlsh	V18.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1248]
	ldr	Q2, [x2, #1248]
	sub	V22.4S, V5.4S, V7.4S
	sub	V24.4S, V6.4S, V8.4S
	add	V5.4S, V5.4S, V7.4S
	add	V6.4S, V6.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V7.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[0]
	sqrdmlsh	V7.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V23.4S, V4.S[0]
	sshr	V7.4S, V7.4S, #1
	sshr	V8.4S, V8.4S, #1
	sub	V22.4S, V9.4S, V11.4S
	sub	V24.4S, V10.4S, V12.4S
	add	V9.4S, V9.4S, V11.4S
	add	V10.4S, V10.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V11.4S, V22.4S, V0.S[1]
	sqrdmulh	V12.4S, V24.4S, V0.S[1]
	sqrdmlsh	V11.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V15.4S
	sub	V24.4S, V14.4S, V16.4S
	add	V13.4S, V13.4S, V15.4S
	add	V14.4S, V14.4S, V16.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V15.4S, V22.4S, V0.S[2]
	sqrdmulh	V16.4S, V24.4S, V0.S[2]
	sqrdmlsh	V15.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V15.4S, V15.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V17.4S, V19.4S
	sub	V24.4S, V18.4S, V20.4S
	add	V17.4S, V17.4S, V19.4S
	add	V18.4S, V18.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[3]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V19.4S, V22.4S, V0.S[3]
	sqrdmulh	V20.4S, V24.4S, V0.S[3]
	sqrdmlsh	V19.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1264]
	ldr	Q2, [x2, #1264]
	sub	V22.4S, V5.4S, V9.4S
	sub	V24.4S, V6.4S, V10.4S
	add	V5.4S, V5.4S, V9.4S
	add	V6.4S, V6.4S, V10.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V9.4S, V22.4S, V0.S[0]
	sqrdmulh	V10.4S, V24.4S, V0.S[0]
	sqrdmlsh	V9.4S, V21.4S, V4.S[0]
	sqrdmlsh	V10.4S, V23.4S, V4.S[0]
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	sub	V22.4S, V7.4S, V11.4S
	sub	V24.4S, V8.4S, V12.4S
	add	V7.4S, V7.4S, V11.4S
	add	V8.4S, V8.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V11.4S, V22.4S, V0.S[0]
	sqrdmulh	V12.4S, V24.4S, V0.S[0]
	sqrdmlsh	V11.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V17.4S
	sub	V24.4S, V14.4S, V18.4S
	add	V13.4S, V13.4S, V17.4S
	add	V14.4S, V14.4S, V18.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V17.4S, V22.4S, V0.S[1]
	sqrdmulh	V18.4S, V24.4S, V0.S[1]
	sqrdmlsh	V17.4S, V21.4S, V4.S[0]
	sqrdmlsh	V18.4S, V23.4S, V4.S[0]
	sshr	V17.4S, V17.4S, #1
	sshr	V18.4S, V18.4S, #1
	sub	V22.4S, V15.4S, V19.4S
	sub	V24.4S, V16.4S, V20.4S
	add	V15.4S, V15.4S, V19.4S
	add	V16.4S, V16.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V19.4S, V22.4S, V0.S[1]
	sqrdmulh	V20.4S, V24.4S, V0.S[1]
	sqrdmlsh	V19.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	sub	V22.4S, V5.4S, V13.4S
	sub	V24.4S, V6.4S, V14.4S
	add	V5.4S, V5.4S, V13.4S
	add	V6.4S, V6.4S, V14.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V13.4S, V22.4S, V0.S[2]
	sqrdmulh	V14.4S, V24.4S, V0.S[2]
	sqrdmlsh	V13.4S, V21.4S, V4.S[0]
	sqrdmlsh	V14.4S, V23.4S, V4.S[0]
	sshr	V13.4S, V13.4S, #1
	sshr	V14.4S, V14.4S, #1
	sub	V22.4S, V7.4S, V15.4S
	sub	V24.4S, V8.4S, V16.4S
	add	V7.4S, V7.4S, V15.4S
	add	V8.4S, V8.4S, V16.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V15.4S, V22.4S, V0.S[2]
	sqrdmulh	V16.4S, V24.4S, V0.S[2]
	sqrdmlsh	V15.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V15.4S, V15.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V9.4S, V17.4S
	sub	V24.4S, V10.4S, V18.4S
	add	V9.4S, V9.4S, V17.4S
	add	V10.4S, V10.4S, V18.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V17.4S, V22.4S, V0.S[2]
	sqrdmulh	V18.4S, V24.4S, V0.S[2]
	sqrdmlsh	V17.4S, V21.4S, V4.S[0]
	sqrdmlsh	V18.4S, V23.4S, V4.S[0]
	sshr	V17.4S, V17.4S, #1
	sshr	V18.4S, V18.4S, #1
	sub	V22.4S, V11.4S, V19.4S
	sub	V24.4S, V12.4S, V20.4S
	add	V11.4S, V11.4S, V19.4S
	add	V12.4S, V12.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V19.4S, V22.4S, V0.S[2]
	sqrdmulh	V20.4S, V24.4S, V0.S[2]
	sqrdmlsh	V19.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	mul	V21.4S, V5.4S, V2.S[3]
	mul	V22.4S, V6.4S, V2.S[3]
	sqrdmulh	V5.4S, V5.4S, V0.S[3]
	sqrdmulh	V6.4S, V6.4S, V0.S[3]
	sqrdmlsh	V5.4S, V21.4S, V4.S[0]
	sqrdmlsh	V6.4S, V22.4S, V4.S[0]
	sshr	V5.4S, V5.4S, #1
	sshr	V6.4S, V6.4S, #1
	mul	V21.4S, V7.4S, V2.S[3]
	mul	V22.4S, V8.4S, V2.S[3]
	sqrdmulh	V7.4S, V7.4S, V0.S[3]
	sqrdmulh	V8.4S, V8.4S, V0.S[3]
	sqrdmlsh	V7.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V22.4S, V4.S[0]
	sshr	V7.4S, V7.4S, #1
	sshr	V8.4S, V8.4S, #1
	mul	V21.4S, V9.4S, V2.S[3]
	mul	V22.4S, V10.4S, V2.S[3]
	sqrdmulh	V9.4S, V9.4S, V0.S[3]
	sqrdmulh	V10.4S, V10.4S, V0.S[3]
	sqrdmlsh	V9.4S, V21.4S, V4.S[0]
	sqrdmlsh	V10.4S, V22.4S, V4.S[0]
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	mul	V21.4S, V11.4S, V2.S[3]
	mul	V22.4S, V12.4S, V2.S[3]
	sqrdmulh	V11.4S, V11.4S, V0.S[3]
	sqrdmulh	V12.4S, V12.4S, V0.S[3]
	sqrdmlsh	V11.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V22.4S, V4.S[0]
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	str	Q5, [x0, #16]
	str	Q6, [x0, #80]
	str	Q7, [x0, #144]
	str	Q8, [x0, #208]
	str	Q9, [x0, #272]
	str	Q10, [x0, #336]
	str	Q11, [x0, #400]
	str	Q12, [x0, #464]
	str	Q13, [x0, #528]
	str	Q14, [x0, #592]
	str	Q15, [x0, #656]
	str	Q16, [x0, #720]
	str	Q17, [x0, #784]
	str	Q18, [x0, #848]
	str	Q19, [x0, #912]
	str	Q20, [x0, #976]
	ldr	Q5, [x0, #32]
	ldr	Q6, [x0, #96]
	ldr	Q7, [x0, #160]
	ldr	Q8, [x0, #224]
	ldr	Q9, [x0, #288]
	ldr	Q10, [x0, #352]
	ldr	Q11, [x0, #416]
	ldr	Q12, [x0, #480]
	ldr	Q13, [x0, #544]
	ldr	Q14, [x0, #608]
	ldr	Q15, [x0, #672]
	ldr	Q16, [x0, #736]
	ldr	Q17, [x0, #800]
	ldr	Q18, [x0, #864]
	ldr	Q19, [x0, #928]
	ldr	Q20, [x0, #992]
	ldr	Q0, [x1, #1216]
	ldr	Q1, [x1, #1232]
	ldr	Q2, [x2, #1216]
	ldr	Q3, [x2, #1232]
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V6.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[1]
	sqrdmlsh	V6.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V23.4S, V4.S[0]
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V10.4S, V22.4S, V0.S[2]
	sqrdmulh	V12.4S, V24.4S, V0.S[3]
	sqrdmlsh	V10.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V3.S[0]
	mul	V23.4S, V24.4S, V3.S[1]
	sqrdmulh	V14.4S, V22.4S, V1.S[0]
	sqrdmulh	V16.4S, V24.4S, V1.S[1]
	sqrdmlsh	V14.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V3.S[2]
	mul	V23.4S, V24.4S, V3.S[3]
	sqrdmulh	V18.4S, V22.4S, V1.S[2]
	sqrdmulh	V20.4S, V24.4S, V1.S[3]
	sqrdmlsh	V18.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1248]
	ldr	Q2, [x2, #1248]
	sub	V22.4S, V5.4S, V7.4S
	sub	V24.4S, V6.4S, V8.4S
	add	V5.4S, V5.4S, V7.4S
	add	V6.4S, V6.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V7.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[0]
	sqrdmlsh	V7.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V23.4S, V4.S[0]
	sshr	V7.4S, V7.4S, #1
	sshr	V8.4S, V8.4S, #1
	sub	V22.4S, V9.4S, V11.4S
	sub	V24.4S, V10.4S, V12.4S
	add	V9.4S, V9.4S, V11.4S
	add	V10.4S, V10.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V11.4S, V22.4S, V0.S[1]
	sqrdmulh	V12.4S, V24.4S, V0.S[1]
	sqrdmlsh	V11.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V15.4S
	sub	V24.4S, V14.4S, V16.4S
	add	V13.4S, V13.4S, V15.4S
	add	V14.4S, V14.4S, V16.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V15.4S, V22.4S, V0.S[2]
	sqrdmulh	V16.4S, V24.4S, V0.S[2]
	sqrdmlsh	V15.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V15.4S, V15.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V17.4S, V19.4S
	sub	V24.4S, V18.4S, V20.4S
	add	V17.4S, V17.4S, V19.4S
	add	V18.4S, V18.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[3]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V19.4S, V22.4S, V0.S[3]
	sqrdmulh	V20.4S, V24.4S, V0.S[3]
	sqrdmlsh	V19.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1264]
	ldr	Q2, [x2, #1264]
	sub	V22.4S, V5.4S, V9.4S
	sub	V24.4S, V6.4S, V10.4S
	add	V5.4S, V5.4S, V9.4S
	add	V6.4S, V6.4S, V10.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V9.4S, V22.4S, V0.S[0]
	sqrdmulh	V10.4S, V24.4S, V0.S[0]
	sqrdmlsh	V9.4S, V21.4S, V4.S[0]
	sqrdmlsh	V10.4S, V23.4S, V4.S[0]
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	sub	V22.4S, V7.4S, V11.4S
	sub	V24.4S, V8.4S, V12.4S
	add	V7.4S, V7.4S, V11.4S
	add	V8.4S, V8.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V11.4S, V22.4S, V0.S[0]
	sqrdmulh	V12.4S, V24.4S, V0.S[0]
	sqrdmlsh	V11.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V17.4S
	sub	V24.4S, V14.4S, V18.4S
	add	V13.4S, V13.4S, V17.4S
	add	V14.4S, V14.4S, V18.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V17.4S, V22.4S, V0.S[1]
	sqrdmulh	V18.4S, V24.4S, V0.S[1]
	sqrdmlsh	V17.4S, V21.4S, V4.S[0]
	sqrdmlsh	V18.4S, V23.4S, V4.S[0]
	sshr	V17.4S, V17.4S, #1
	sshr	V18.4S, V18.4S, #1
	sub	V22.4S, V15.4S, V19.4S
	sub	V24.4S, V16.4S, V20.4S
	add	V15.4S, V15.4S, V19.4S
	add	V16.4S, V16.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V19.4S, V22.4S, V0.S[1]
	sqrdmulh	V20.4S, V24.4S, V0.S[1]
	sqrdmlsh	V19.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	sub	V22.4S, V5.4S, V13.4S
	sub	V24.4S, V6.4S, V14.4S
	add	V5.4S, V5.4S, V13.4S
	add	V6.4S, V6.4S, V14.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V13.4S, V22.4S, V0.S[2]
	sqrdmulh	V14.4S, V24.4S, V0.S[2]
	sqrdmlsh	V13.4S, V21.4S, V4.S[0]
	sqrdmlsh	V14.4S, V23.4S, V4.S[0]
	sshr	V13.4S, V13.4S, #1
	sshr	V14.4S, V14.4S, #1
	sub	V22.4S, V7.4S, V15.4S
	sub	V24.4S, V8.4S, V16.4S
	add	V7.4S, V7.4S, V15.4S
	add	V8.4S, V8.4S, V16.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V15.4S, V22.4S, V0.S[2]
	sqrdmulh	V16.4S, V24.4S, V0.S[2]
	sqrdmlsh	V15.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V15.4S, V15.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V9.4S, V17.4S
	sub	V24.4S, V10.4S, V18.4S
	add	V9.4S, V9.4S, V17.4S
	add	V10.4S, V10.4S, V18.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V17.4S, V22.4S, V0.S[2]
	sqrdmulh	V18.4S, V24.4S, V0.S[2]
	sqrdmlsh	V17.4S, V21.4S, V4.S[0]
	sqrdmlsh	V18.4S, V23.4S, V4.S[0]
	sshr	V17.4S, V17.4S, #1
	sshr	V18.4S, V18.4S, #1
	sub	V22.4S, V11.4S, V19.4S
	sub	V24.4S, V12.4S, V20.4S
	add	V11.4S, V11.4S, V19.4S
	add	V12.4S, V12.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V19.4S, V22.4S, V0.S[2]
	sqrdmulh	V20.4S, V24.4S, V0.S[2]
	sqrdmlsh	V19.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	mul	V21.4S, V5.4S, V2.S[3]
	mul	V22.4S, V6.4S, V2.S[3]
	sqrdmulh	V5.4S, V5.4S, V0.S[3]
	sqrdmulh	V6.4S, V6.4S, V0.S[3]
	sqrdmlsh	V5.4S, V21.4S, V4.S[0]
	sqrdmlsh	V6.4S, V22.4S, V4.S[0]
	sshr	V5.4S, V5.4S, #1
	sshr	V6.4S, V6.4S, #1
	mul	V21.4S, V7.4S, V2.S[3]
	mul	V22.4S, V8.4S, V2.S[3]
	sqrdmulh	V7.4S, V7.4S, V0.S[3]
	sqrdmulh	V8.4S, V8.4S, V0.S[3]
	sqrdmlsh	V7.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V22.4S, V4.S[0]
	sshr	V7.4S, V7.4S, #1
	sshr	V8.4S, V8.4S, #1
	mul	V21.4S, V9.4S, V2.S[3]
	mul	V22.4S, V10.4S, V2.S[3]
	sqrdmulh	V9.4S, V9.4S, V0.S[3]
	sqrdmulh	V10.4S, V10.4S, V0.S[3]
	sqrdmlsh	V9.4S, V21.4S, V4.S[0]
	sqrdmlsh	V10.4S, V22.4S, V4.S[0]
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	mul	V21.4S, V11.4S, V2.S[3]
	mul	V22.4S, V12.4S, V2.S[3]
	sqrdmulh	V11.4S, V11.4S, V0.S[3]
	sqrdmulh	V12.4S, V12.4S, V0.S[3]
	sqrdmlsh	V11.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V22.4S, V4.S[0]
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	str	Q5, [x0, #32]
	str	Q6, [x0, #96]
	str	Q7, [x0, #160]
	str	Q8, [x0, #224]
	str	Q9, [x0, #288]
	str	Q10, [x0, #352]
	str	Q11, [x0, #416]
	str	Q12, [x0, #480]
	str	Q13, [x0, #544]
	str	Q14, [x0, #608]
	str	Q15, [x0, #672]
	str	Q16, [x0, #736]
	str	Q17, [x0, #800]
	str	Q18, [x0, #864]
	str	Q19, [x0, #928]
	str	Q20, [x0, #992]
	ldr	Q5, [x0, #48]
	ldr	Q6, [x0, #112]
	ldr	Q7, [x0, #176]
	ldr	Q8, [x0, #240]
	ldr	Q9, [x0, #304]
	ldr	Q10, [x0, #368]
	ldr	Q11, [x0, #432]
	ldr	Q12, [x0, #496]
	ldr	Q13, [x0, #560]
	ldr	Q14, [x0, #624]
	ldr	Q15, [x0, #688]
	ldr	Q16, [x0, #752]
	ldr	Q17, [x0, #816]
	ldr	Q18, [x0, #880]
	ldr	Q19, [x0, #944]
	ldr	Q20, [x0, #1008]
	ldr	Q0, [x1, #1216]
	ldr	Q1, [x1, #1232]
	ldr	Q2, [x2, #1216]
	ldr	Q3, [x2, #1232]
	sub	V22.4S, V5.4S, V6.4S
	sub	V24.4S, V7.4S, V8.4S
	add	V5.4S, V5.4S, V6.4S
	add	V7.4S, V7.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V6.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[1]
	sqrdmlsh	V6.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V23.4S, V4.S[0]
	sshr	V6.4S, V6.4S, #1
	sshr	V8.4S, V8.4S, #1
	sub	V22.4S, V9.4S, V10.4S
	sub	V24.4S, V11.4S, V12.4S
	add	V9.4S, V9.4S, V10.4S
	add	V11.4S, V11.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V10.4S, V22.4S, V0.S[2]
	sqrdmulh	V12.4S, V24.4S, V0.S[3]
	sqrdmlsh	V10.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V10.4S, V10.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V14.4S
	sub	V24.4S, V15.4S, V16.4S
	add	V13.4S, V13.4S, V14.4S
	add	V15.4S, V15.4S, V16.4S
	mul	V21.4S, V22.4S, V3.S[0]
	mul	V23.4S, V24.4S, V3.S[1]
	sqrdmulh	V14.4S, V22.4S, V1.S[0]
	sqrdmulh	V16.4S, V24.4S, V1.S[1]
	sqrdmlsh	V14.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V14.4S, V14.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V17.4S, V18.4S
	sub	V24.4S, V19.4S, V20.4S
	add	V17.4S, V17.4S, V18.4S
	add	V19.4S, V19.4S, V20.4S
	mul	V21.4S, V22.4S, V3.S[2]
	mul	V23.4S, V24.4S, V3.S[3]
	sqrdmulh	V18.4S, V22.4S, V1.S[2]
	sqrdmulh	V20.4S, V24.4S, V1.S[3]
	sqrdmlsh	V18.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V18.4S, V18.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1248]
	ldr	Q2, [x2, #1248]
	sub	V22.4S, V5.4S, V7.4S
	sub	V24.4S, V6.4S, V8.4S
	add	V5.4S, V5.4S, V7.4S
	add	V6.4S, V6.4S, V8.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V7.4S, V22.4S, V0.S[0]
	sqrdmulh	V8.4S, V24.4S, V0.S[0]
	sqrdmlsh	V7.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V23.4S, V4.S[0]
	sshr	V7.4S, V7.4S, #1
	sshr	V8.4S, V8.4S, #1
	sub	V22.4S, V9.4S, V11.4S
	sub	V24.4S, V10.4S, V12.4S
	add	V9.4S, V9.4S, V11.4S
	add	V10.4S, V10.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V11.4S, V22.4S, V0.S[1]
	sqrdmulh	V12.4S, V24.4S, V0.S[1]
	sqrdmlsh	V11.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V15.4S
	sub	V24.4S, V14.4S, V16.4S
	add	V13.4S, V13.4S, V15.4S
	add	V14.4S, V14.4S, V16.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V15.4S, V22.4S, V0.S[2]
	sqrdmulh	V16.4S, V24.4S, V0.S[2]
	sqrdmlsh	V15.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V15.4S, V15.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V17.4S, V19.4S
	sub	V24.4S, V18.4S, V20.4S
	add	V17.4S, V17.4S, V19.4S
	add	V18.4S, V18.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[3]
	mul	V23.4S, V24.4S, V2.S[3]
	sqrdmulh	V19.4S, V22.4S, V0.S[3]
	sqrdmulh	V20.4S, V24.4S, V0.S[3]
	sqrdmlsh	V19.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	ldr	Q0, [x1, #1264]
	ldr	Q2, [x2, #1264]
	sub	V22.4S, V5.4S, V9.4S
	sub	V24.4S, V6.4S, V10.4S
	add	V5.4S, V5.4S, V9.4S
	add	V6.4S, V6.4S, V10.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V9.4S, V22.4S, V0.S[0]
	sqrdmulh	V10.4S, V24.4S, V0.S[0]
	sqrdmlsh	V9.4S, V21.4S, V4.S[0]
	sqrdmlsh	V10.4S, V23.4S, V4.S[0]
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	sub	V22.4S, V7.4S, V11.4S
	sub	V24.4S, V8.4S, V12.4S
	add	V7.4S, V7.4S, V11.4S
	add	V8.4S, V8.4S, V12.4S
	mul	V21.4S, V22.4S, V2.S[0]
	mul	V23.4S, V24.4S, V2.S[0]
	sqrdmulh	V11.4S, V22.4S, V0.S[0]
	sqrdmulh	V12.4S, V24.4S, V0.S[0]
	sqrdmlsh	V11.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V23.4S, V4.S[0]
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	sub	V22.4S, V13.4S, V17.4S
	sub	V24.4S, V14.4S, V18.4S
	add	V13.4S, V13.4S, V17.4S
	add	V14.4S, V14.4S, V18.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V17.4S, V22.4S, V0.S[1]
	sqrdmulh	V18.4S, V24.4S, V0.S[1]
	sqrdmlsh	V17.4S, V21.4S, V4.S[0]
	sqrdmlsh	V18.4S, V23.4S, V4.S[0]
	sshr	V17.4S, V17.4S, #1
	sshr	V18.4S, V18.4S, #1
	sub	V22.4S, V15.4S, V19.4S
	sub	V24.4S, V16.4S, V20.4S
	add	V15.4S, V15.4S, V19.4S
	add	V16.4S, V16.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[1]
	mul	V23.4S, V24.4S, V2.S[1]
	sqrdmulh	V19.4S, V22.4S, V0.S[1]
	sqrdmulh	V20.4S, V24.4S, V0.S[1]
	sqrdmlsh	V19.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	sub	V22.4S, V5.4S, V13.4S
	sub	V24.4S, V6.4S, V14.4S
	add	V5.4S, V5.4S, V13.4S
	add	V6.4S, V6.4S, V14.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V13.4S, V22.4S, V0.S[2]
	sqrdmulh	V14.4S, V24.4S, V0.S[2]
	sqrdmlsh	V13.4S, V21.4S, V4.S[0]
	sqrdmlsh	V14.4S, V23.4S, V4.S[0]
	sshr	V13.4S, V13.4S, #1
	sshr	V14.4S, V14.4S, #1
	sub	V22.4S, V7.4S, V15.4S
	sub	V24.4S, V8.4S, V16.4S
	add	V7.4S, V7.4S, V15.4S
	add	V8.4S, V8.4S, V16.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V15.4S, V22.4S, V0.S[2]
	sqrdmulh	V16.4S, V24.4S, V0.S[2]
	sqrdmlsh	V15.4S, V21.4S, V4.S[0]
	sqrdmlsh	V16.4S, V23.4S, V4.S[0]
	sshr	V15.4S, V15.4S, #1
	sshr	V16.4S, V16.4S, #1
	sub	V22.4S, V9.4S, V17.4S
	sub	V24.4S, V10.4S, V18.4S
	add	V9.4S, V9.4S, V17.4S
	add	V10.4S, V10.4S, V18.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V17.4S, V22.4S, V0.S[2]
	sqrdmulh	V18.4S, V24.4S, V0.S[2]
	sqrdmlsh	V17.4S, V21.4S, V4.S[0]
	sqrdmlsh	V18.4S, V23.4S, V4.S[0]
	sshr	V17.4S, V17.4S, #1
	sshr	V18.4S, V18.4S, #1
	sub	V22.4S, V11.4S, V19.4S
	sub	V24.4S, V12.4S, V20.4S
	add	V11.4S, V11.4S, V19.4S
	add	V12.4S, V12.4S, V20.4S
	mul	V21.4S, V22.4S, V2.S[2]
	mul	V23.4S, V24.4S, V2.S[2]
	sqrdmulh	V19.4S, V22.4S, V0.S[2]
	sqrdmulh	V20.4S, V24.4S, V0.S[2]
	sqrdmlsh	V19.4S, V21.4S, V4.S[0]
	sqrdmlsh	V20.4S, V23.4S, V4.S[0]
	sshr	V19.4S, V19.4S, #1
	sshr	V20.4S, V20.4S, #1
	mul	V21.4S, V5.4S, V2.S[3]
	mul	V22.4S, V6.4S, V2.S[3]
	sqrdmulh	V5.4S, V5.4S, V0.S[3]
	sqrdmulh	V6.4S, V6.4S, V0.S[3]
	sqrdmlsh	V5.4S, V21.4S, V4.S[0]
	sqrdmlsh	V6.4S, V22.4S, V4.S[0]
	sshr	V5.4S, V5.4S, #1
	sshr	V6.4S, V6.4S, #1
	mul	V21.4S, V7.4S, V2.S[3]
	mul	V22.4S, V8.4S, V2.S[3]
	sqrdmulh	V7.4S, V7.4S, V0.S[3]
	sqrdmulh	V8.4S, V8.4S, V0.S[3]
	sqrdmlsh	V7.4S, V21.4S, V4.S[0]
	sqrdmlsh	V8.4S, V22.4S, V4.S[0]
	sshr	V7.4S, V7.4S, #1
	sshr	V8.4S, V8.4S, #1
	mul	V21.4S, V9.4S, V2.S[3]
	mul	V22.4S, V10.4S, V2.S[3]
	sqrdmulh	V9.4S, V9.4S, V0.S[3]
	sqrdmulh	V10.4S, V10.4S, V0.S[3]
	sqrdmlsh	V9.4S, V21.4S, V4.S[0]
	sqrdmlsh	V10.4S, V22.4S, V4.S[0]
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	mul	V21.4S, V11.4S, V2.S[3]
	mul	V22.4S, V12.4S, V2.S[3]
	sqrdmulh	V11.4S, V11.4S, V0.S[3]
	sqrdmulh	V12.4S, V12.4S, V0.S[3]
	sqrdmlsh	V11.4S, V21.4S, V4.S[0]
	sqrdmlsh	V12.4S, V22.4S, V4.S[0]
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	str	Q5, [x0, #48]
	str	Q6, [x0, #112]
	str	Q7, [x0, #176]
	str	Q8, [x0, #240]
	str	Q9, [x0, #304]
	str	Q10, [x0, #368]
	str	Q11, [x0, #432]
	str	Q12, [x0, #496]
	str	Q13, [x0, #560]
	str	Q14, [x0, #624]
	str	Q15, [x0, #688]
	str	Q16, [x0, #752]
	str	Q17, [x0, #816]
	str	Q18, [x0, #880]
	str	Q19, [x0, #944]
	str	Q20, [x0, #1008]
	ldp	D8, D9, [x29, #16]
	ldp	D10, D11, [x29, #32]
	ldp	D12, D13, [x29, #48]
	ldp	D14, D15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
	ENDP
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mldsa_mul_sqrdmlsh_neon
mldsa_mul_sqrdmlsh_neon PROC
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	stp	D10, D11, [x29, #32]
	stp	D12, D13, [x29, #48]
	stp	D14, D15, [x29, #64]
	adrp	x3, L_mldsa_aarch64_consts
	add	x3, x3, L_mldsa_aarch64_consts
	ldr	Q0, [x3]
	ldr	Q1, [x1]
	ldr	Q5, [x2]
	ldr	Q2, [x1, #16]
	ldr	Q6, [x2, #16]
	ldr	Q3, [x1, #32]
	ldr	Q7, [x2, #32]
	ldr	Q4, [x1, #48]
	ldr	Q8, [x2, #48]
	mul	V13.4S, V5.4S, V0.S[1]
	mul	V14.4S, V6.4S, V0.S[1]
	mul	V17.4S, V1.4S, V13.4S
	mul	V18.4S, V2.4S, V14.4S
	sqrdmulh	V9.4S, V1.4S, V5.4S
	sqrdmulh	V10.4S, V2.4S, V6.4S
	sqrdmlsh	V9.4S, V17.4S, V0.S[0]
	sqrdmlsh	V10.4S, V18.4S, V0.S[0]
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	mul	V15.4S, V7.4S, V0.S[1]
	mul	V16.4S, V8.4S, V0.S[1]
	mul	V17.4S, V3.4S, V15.4S
	mul	V18.4S, V4.4S, V16.4S
	sqrdmulh	V11.4S, V3.4S, V7.4S
	sqrdmulh	V12.4S, V4.4S, V8.4S
	sqrdmlsh	V11.4S, V17.4S, V0.S[0]
	sqrdmlsh	V12.4S, V18.4S, V0.S[0]
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	str	Q9, [x0]
	str	Q10, [x0, #16]
	str	Q11, [x0, #32]
	str	Q12, [x0, #48]
	ldr	Q1, [x1, #64]
	ldr	Q5, [x2, #64]
	ldr	Q2, [x1, #80]
	ldr	Q6, [x2, #80]
	ldr	Q3, [x1, #96]
	ldr	Q7, [x2, #96]
	ldr	Q4, [x1, #112]
	ldr	Q8, [x2, #112]
	mul	V13.4S, V5.4S, V0.S[1]
	mul	V14.4S, V6.4S, V0.S[1]
	mul	V17.4S, V1.4S, V13.4S
	mul	V18.4S, V2.4S, V14.4S
	sqrdmulh	V9.4S, V1.4S, V5.4S
	sqrdmulh	V10.4S, V2.4S, V6.4S
	sqrdmlsh	V9.4S, V17.4S, V0.S[0]
	sqrdmlsh	V10.4S, V18.4S, V0.S[0]
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	mul	V15.4S, V7.4S, V0.S[1]
	mul	V16.4S, V8.4S, V0.S[1]
	mul	V17.4S, V3.4S, V15.4S
	mul	V18.4S, V4.4S, V16.4S
	sqrdmulh	V11.4S, V3.4S, V7.4S
	sqrdmulh	V12.4S, V4.4S, V8.4S
	sqrdmlsh	V11.4S, V17.4S, V0.S[0]
	sqrdmlsh	V12.4S, V18.4S, V0.S[0]
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	str	Q9, [x0, #64]
	str	Q10, [x0, #80]
	str	Q11, [x0, #96]
	str	Q12, [x0, #112]
	ldr	Q1, [x1, #128]
	ldr	Q5, [x2, #128]
	ldr	Q2, [x1, #144]
	ldr	Q6, [x2, #144]
	ldr	Q3, [x1, #160]
	ldr	Q7, [x2, #160]
	ldr	Q4, [x1, #176]
	ldr	Q8, [x2, #176]
	mul	V13.4S, V5.4S, V0.S[1]
	mul	V14.4S, V6.4S, V0.S[1]
	mul	V17.4S, V1.4S, V13.4S
	mul	V18.4S, V2.4S, V14.4S
	sqrdmulh	V9.4S, V1.4S, V5.4S
	sqrdmulh	V10.4S, V2.4S, V6.4S
	sqrdmlsh	V9.4S, V17.4S, V0.S[0]
	sqrdmlsh	V10.4S, V18.4S, V0.S[0]
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	mul	V15.4S, V7.4S, V0.S[1]
	mul	V16.4S, V8.4S, V0.S[1]
	mul	V17.4S, V3.4S, V15.4S
	mul	V18.4S, V4.4S, V16.4S
	sqrdmulh	V11.4S, V3.4S, V7.4S
	sqrdmulh	V12.4S, V4.4S, V8.4S
	sqrdmlsh	V11.4S, V17.4S, V0.S[0]
	sqrdmlsh	V12.4S, V18.4S, V0.S[0]
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	str	Q9, [x0, #128]
	str	Q10, [x0, #144]
	str	Q11, [x0, #160]
	str	Q12, [x0, #176]
	ldr	Q1, [x1, #192]
	ldr	Q5, [x2, #192]
	ldr	Q2, [x1, #208]
	ldr	Q6, [x2, #208]
	ldr	Q3, [x1, #224]
	ldr	Q7, [x2, #224]
	ldr	Q4, [x1, #240]
	ldr	Q8, [x2, #240]
	mul	V13.4S, V5.4S, V0.S[1]
	mul	V14.4S, V6.4S, V0.S[1]
	mul	V17.4S, V1.4S, V13.4S
	mul	V18.4S, V2.4S, V14.4S
	sqrdmulh	V9.4S, V1.4S, V5.4S
	sqrdmulh	V10.4S, V2.4S, V6.4S
	sqrdmlsh	V9.4S, V17.4S, V0.S[0]
	sqrdmlsh	V10.4S, V18.4S, V0.S[0]
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	mul	V15.4S, V7.4S, V0.S[1]
	mul	V16.4S, V8.4S, V0.S[1]
	mul	V17.4S, V3.4S, V15.4S
	mul	V18.4S, V4.4S, V16.4S
	sqrdmulh	V11.4S, V3.4S, V7.4S
	sqrdmulh	V12.4S, V4.4S, V8.4S
	sqrdmlsh	V11.4S, V17.4S, V0.S[0]
	sqrdmlsh	V12.4S, V18.4S, V0.S[0]
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	str	Q9, [x0, #192]
	str	Q10, [x0, #208]
	str	Q11, [x0, #224]
	str	Q12, [x0, #240]
	ldr	Q1, [x1, #256]
	ldr	Q5, [x2, #256]
	ldr	Q2, [x1, #272]
	ldr	Q6, [x2, #272]
	ldr	Q3, [x1, #288]
	ldr	Q7, [x2, #288]
	ldr	Q4, [x1, #304]
	ldr	Q8, [x2, #304]
	mul	V13.4S, V5.4S, V0.S[1]
	mul	V14.4S, V6.4S, V0.S[1]
	mul	V17.4S, V1.4S, V13.4S
	mul	V18.4S, V2.4S, V14.4S
	sqrdmulh	V9.4S, V1.4S, V5.4S
	sqrdmulh	V10.4S, V2.4S, V6.4S
	sqrdmlsh	V9.4S, V17.4S, V0.S[0]
	sqrdmlsh	V10.4S, V18.4S, V0.S[0]
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	mul	V15.4S, V7.4S, V0.S[1]
	mul	V16.4S, V8.4S, V0.S[1]
	mul	V17.4S, V3.4S, V15.4S
	mul	V18.4S, V4.4S, V16.4S
	sqrdmulh	V11.4S, V3.4S, V7.4S
	sqrdmulh	V12.4S, V4.4S, V8.4S
	sqrdmlsh	V11.4S, V17.4S, V0.S[0]
	sqrdmlsh	V12.4S, V18.4S, V0.S[0]
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	str	Q9, [x0, #256]
	str	Q10, [x0, #272]
	str	Q11, [x0, #288]
	str	Q12, [x0, #304]
	ldr	Q1, [x1, #320]
	ldr	Q5, [x2, #320]
	ldr	Q2, [x1, #336]
	ldr	Q6, [x2, #336]
	ldr	Q3, [x1, #352]
	ldr	Q7, [x2, #352]
	ldr	Q4, [x1, #368]
	ldr	Q8, [x2, #368]
	mul	V13.4S, V5.4S, V0.S[1]
	mul	V14.4S, V6.4S, V0.S[1]
	mul	V17.4S, V1.4S, V13.4S
	mul	V18.4S, V2.4S, V14.4S
	sqrdmulh	V9.4S, V1.4S, V5.4S
	sqrdmulh	V10.4S, V2.4S, V6.4S
	sqrdmlsh	V9.4S, V17.4S, V0.S[0]
	sqrdmlsh	V10.4S, V18.4S, V0.S[0]
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	mul	V15.4S, V7.4S, V0.S[1]
	mul	V16.4S, V8.4S, V0.S[1]
	mul	V17.4S, V3.4S, V15.4S
	mul	V18.4S, V4.4S, V16.4S
	sqrdmulh	V11.4S, V3.4S, V7.4S
	sqrdmulh	V12.4S, V4.4S, V8.4S
	sqrdmlsh	V11.4S, V17.4S, V0.S[0]
	sqrdmlsh	V12.4S, V18.4S, V0.S[0]
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	str	Q9, [x0, #320]
	str	Q10, [x0, #336]
	str	Q11, [x0, #352]
	str	Q12, [x0, #368]
	ldr	Q1, [x1, #384]
	ldr	Q5, [x2, #384]
	ldr	Q2, [x1, #400]
	ldr	Q6, [x2, #400]
	ldr	Q3, [x1, #416]
	ldr	Q7, [x2, #416]
	ldr	Q4, [x1, #432]
	ldr	Q8, [x2, #432]
	mul	V13.4S, V5.4S, V0.S[1]
	mul	V14.4S, V6.4S, V0.S[1]
	mul	V17.4S, V1.4S, V13.4S
	mul	V18.4S, V2.4S, V14.4S
	sqrdmulh	V9.4S, V1.4S, V5.4S
	sqrdmulh	V10.4S, V2.4S, V6.4S
	sqrdmlsh	V9.4S, V17.4S, V0.S[0]
	sqrdmlsh	V10.4S, V18.4S, V0.S[0]
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	mul	V15.4S, V7.4S, V0.S[1]
	mul	V16.4S, V8.4S, V0.S[1]
	mul	V17.4S, V3.4S, V15.4S
	mul	V18.4S, V4.4S, V16.4S
	sqrdmulh	V11.4S, V3.4S, V7.4S
	sqrdmulh	V12.4S, V4.4S, V8.4S
	sqrdmlsh	V11.4S, V17.4S, V0.S[0]
	sqrdmlsh	V12.4S, V18.4S, V0.S[0]
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	str	Q9, [x0, #384]
	str	Q10, [x0, #400]
	str	Q11, [x0, #416]
	str	Q12, [x0, #432]
	ldr	Q1, [x1, #448]
	ldr	Q5, [x2, #448]
	ldr	Q2, [x1, #464]
	ldr	Q6, [x2, #464]
	ldr	Q3, [x1, #480]
	ldr	Q7, [x2, #480]
	ldr	Q4, [x1, #496]
	ldr	Q8, [x2, #496]
	mul	V13.4S, V5.4S, V0.S[1]
	mul	V14.4S, V6.4S, V0.S[1]
	mul	V17.4S, V1.4S, V13.4S
	mul	V18.4S, V2.4S, V14.4S
	sqrdmulh	V9.4S, V1.4S, V5.4S
	sqrdmulh	V10.4S, V2.4S, V6.4S
	sqrdmlsh	V9.4S, V17.4S, V0.S[0]
	sqrdmlsh	V10.4S, V18.4S, V0.S[0]
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	mul	V15.4S, V7.4S, V0.S[1]
	mul	V16.4S, V8.4S, V0.S[1]
	mul	V17.4S, V3.4S, V15.4S
	mul	V18.4S, V4.4S, V16.4S
	sqrdmulh	V11.4S, V3.4S, V7.4S
	sqrdmulh	V12.4S, V4.4S, V8.4S
	sqrdmlsh	V11.4S, V17.4S, V0.S[0]
	sqrdmlsh	V12.4S, V18.4S, V0.S[0]
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	str	Q9, [x0, #448]
	str	Q10, [x0, #464]
	str	Q11, [x0, #480]
	str	Q12, [x0, #496]
	ldr	Q1, [x1, #512]
	ldr	Q5, [x2, #512]
	ldr	Q2, [x1, #528]
	ldr	Q6, [x2, #528]
	ldr	Q3, [x1, #544]
	ldr	Q7, [x2, #544]
	ldr	Q4, [x1, #560]
	ldr	Q8, [x2, #560]
	mul	V13.4S, V5.4S, V0.S[1]
	mul	V14.4S, V6.4S, V0.S[1]
	mul	V17.4S, V1.4S, V13.4S
	mul	V18.4S, V2.4S, V14.4S
	sqrdmulh	V9.4S, V1.4S, V5.4S
	sqrdmulh	V10.4S, V2.4S, V6.4S
	sqrdmlsh	V9.4S, V17.4S, V0.S[0]
	sqrdmlsh	V10.4S, V18.4S, V0.S[0]
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	mul	V15.4S, V7.4S, V0.S[1]
	mul	V16.4S, V8.4S, V0.S[1]
	mul	V17.4S, V3.4S, V15.4S
	mul	V18.4S, V4.4S, V16.4S
	sqrdmulh	V11.4S, V3.4S, V7.4S
	sqrdmulh	V12.4S, V4.4S, V8.4S
	sqrdmlsh	V11.4S, V17.4S, V0.S[0]
	sqrdmlsh	V12.4S, V18.4S, V0.S[0]
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	str	Q9, [x0, #512]
	str	Q10, [x0, #528]
	str	Q11, [x0, #544]
	str	Q12, [x0, #560]
	ldr	Q1, [x1, #576]
	ldr	Q5, [x2, #576]
	ldr	Q2, [x1, #592]
	ldr	Q6, [x2, #592]
	ldr	Q3, [x1, #608]
	ldr	Q7, [x2, #608]
	ldr	Q4, [x1, #624]
	ldr	Q8, [x2, #624]
	mul	V13.4S, V5.4S, V0.S[1]
	mul	V14.4S, V6.4S, V0.S[1]
	mul	V17.4S, V1.4S, V13.4S
	mul	V18.4S, V2.4S, V14.4S
	sqrdmulh	V9.4S, V1.4S, V5.4S
	sqrdmulh	V10.4S, V2.4S, V6.4S
	sqrdmlsh	V9.4S, V17.4S, V0.S[0]
	sqrdmlsh	V10.4S, V18.4S, V0.S[0]
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	mul	V15.4S, V7.4S, V0.S[1]
	mul	V16.4S, V8.4S, V0.S[1]
	mul	V17.4S, V3.4S, V15.4S
	mul	V18.4S, V4.4S, V16.4S
	sqrdmulh	V11.4S, V3.4S, V7.4S
	sqrdmulh	V12.4S, V4.4S, V8.4S
	sqrdmlsh	V11.4S, V17.4S, V0.S[0]
	sqrdmlsh	V12.4S, V18.4S, V0.S[0]
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	str	Q9, [x0, #576]
	str	Q10, [x0, #592]
	str	Q11, [x0, #608]
	str	Q12, [x0, #624]
	ldr	Q1, [x1, #640]
	ldr	Q5, [x2, #640]
	ldr	Q2, [x1, #656]
	ldr	Q6, [x2, #656]
	ldr	Q3, [x1, #672]
	ldr	Q7, [x2, #672]
	ldr	Q4, [x1, #688]
	ldr	Q8, [x2, #688]
	mul	V13.4S, V5.4S, V0.S[1]
	mul	V14.4S, V6.4S, V0.S[1]
	mul	V17.4S, V1.4S, V13.4S
	mul	V18.4S, V2.4S, V14.4S
	sqrdmulh	V9.4S, V1.4S, V5.4S
	sqrdmulh	V10.4S, V2.4S, V6.4S
	sqrdmlsh	V9.4S, V17.4S, V0.S[0]
	sqrdmlsh	V10.4S, V18.4S, V0.S[0]
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	mul	V15.4S, V7.4S, V0.S[1]
	mul	V16.4S, V8.4S, V0.S[1]
	mul	V17.4S, V3.4S, V15.4S
	mul	V18.4S, V4.4S, V16.4S
	sqrdmulh	V11.4S, V3.4S, V7.4S
	sqrdmulh	V12.4S, V4.4S, V8.4S
	sqrdmlsh	V11.4S, V17.4S, V0.S[0]
	sqrdmlsh	V12.4S, V18.4S, V0.S[0]
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	str	Q9, [x0, #640]
	str	Q10, [x0, #656]
	str	Q11, [x0, #672]
	str	Q12, [x0, #688]
	ldr	Q1, [x1, #704]
	ldr	Q5, [x2, #704]
	ldr	Q2, [x1, #720]
	ldr	Q6, [x2, #720]
	ldr	Q3, [x1, #736]
	ldr	Q7, [x2, #736]
	ldr	Q4, [x1, #752]
	ldr	Q8, [x2, #752]
	mul	V13.4S, V5.4S, V0.S[1]
	mul	V14.4S, V6.4S, V0.S[1]
	mul	V17.4S, V1.4S, V13.4S
	mul	V18.4S, V2.4S, V14.4S
	sqrdmulh	V9.4S, V1.4S, V5.4S
	sqrdmulh	V10.4S, V2.4S, V6.4S
	sqrdmlsh	V9.4S, V17.4S, V0.S[0]
	sqrdmlsh	V10.4S, V18.4S, V0.S[0]
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	mul	V15.4S, V7.4S, V0.S[1]
	mul	V16.4S, V8.4S, V0.S[1]
	mul	V17.4S, V3.4S, V15.4S
	mul	V18.4S, V4.4S, V16.4S
	sqrdmulh	V11.4S, V3.4S, V7.4S
	sqrdmulh	V12.4S, V4.4S, V8.4S
	sqrdmlsh	V11.4S, V17.4S, V0.S[0]
	sqrdmlsh	V12.4S, V18.4S, V0.S[0]
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	str	Q9, [x0, #704]
	str	Q10, [x0, #720]
	str	Q11, [x0, #736]
	str	Q12, [x0, #752]
	ldr	Q1, [x1, #768]
	ldr	Q5, [x2, #768]
	ldr	Q2, [x1, #784]
	ldr	Q6, [x2, #784]
	ldr	Q3, [x1, #800]
	ldr	Q7, [x2, #800]
	ldr	Q4, [x1, #816]
	ldr	Q8, [x2, #816]
	mul	V13.4S, V5.4S, V0.S[1]
	mul	V14.4S, V6.4S, V0.S[1]
	mul	V17.4S, V1.4S, V13.4S
	mul	V18.4S, V2.4S, V14.4S
	sqrdmulh	V9.4S, V1.4S, V5.4S
	sqrdmulh	V10.4S, V2.4S, V6.4S
	sqrdmlsh	V9.4S, V17.4S, V0.S[0]
	sqrdmlsh	V10.4S, V18.4S, V0.S[0]
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	mul	V15.4S, V7.4S, V0.S[1]
	mul	V16.4S, V8.4S, V0.S[1]
	mul	V17.4S, V3.4S, V15.4S
	mul	V18.4S, V4.4S, V16.4S
	sqrdmulh	V11.4S, V3.4S, V7.4S
	sqrdmulh	V12.4S, V4.4S, V8.4S
	sqrdmlsh	V11.4S, V17.4S, V0.S[0]
	sqrdmlsh	V12.4S, V18.4S, V0.S[0]
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	str	Q9, [x0, #768]
	str	Q10, [x0, #784]
	str	Q11, [x0, #800]
	str	Q12, [x0, #816]
	ldr	Q1, [x1, #832]
	ldr	Q5, [x2, #832]
	ldr	Q2, [x1, #848]
	ldr	Q6, [x2, #848]
	ldr	Q3, [x1, #864]
	ldr	Q7, [x2, #864]
	ldr	Q4, [x1, #880]
	ldr	Q8, [x2, #880]
	mul	V13.4S, V5.4S, V0.S[1]
	mul	V14.4S, V6.4S, V0.S[1]
	mul	V17.4S, V1.4S, V13.4S
	mul	V18.4S, V2.4S, V14.4S
	sqrdmulh	V9.4S, V1.4S, V5.4S
	sqrdmulh	V10.4S, V2.4S, V6.4S
	sqrdmlsh	V9.4S, V17.4S, V0.S[0]
	sqrdmlsh	V10.4S, V18.4S, V0.S[0]
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	mul	V15.4S, V7.4S, V0.S[1]
	mul	V16.4S, V8.4S, V0.S[1]
	mul	V17.4S, V3.4S, V15.4S
	mul	V18.4S, V4.4S, V16.4S
	sqrdmulh	V11.4S, V3.4S, V7.4S
	sqrdmulh	V12.4S, V4.4S, V8.4S
	sqrdmlsh	V11.4S, V17.4S, V0.S[0]
	sqrdmlsh	V12.4S, V18.4S, V0.S[0]
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	str	Q9, [x0, #832]
	str	Q10, [x0, #848]
	str	Q11, [x0, #864]
	str	Q12, [x0, #880]
	ldr	Q1, [x1, #896]
	ldr	Q5, [x2, #896]
	ldr	Q2, [x1, #912]
	ldr	Q6, [x2, #912]
	ldr	Q3, [x1, #928]
	ldr	Q7, [x2, #928]
	ldr	Q4, [x1, #944]
	ldr	Q8, [x2, #944]
	mul	V13.4S, V5.4S, V0.S[1]
	mul	V14.4S, V6.4S, V0.S[1]
	mul	V17.4S, V1.4S, V13.4S
	mul	V18.4S, V2.4S, V14.4S
	sqrdmulh	V9.4S, V1.4S, V5.4S
	sqrdmulh	V10.4S, V2.4S, V6.4S
	sqrdmlsh	V9.4S, V17.4S, V0.S[0]
	sqrdmlsh	V10.4S, V18.4S, V0.S[0]
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	mul	V15.4S, V7.4S, V0.S[1]
	mul	V16.4S, V8.4S, V0.S[1]
	mul	V17.4S, V3.4S, V15.4S
	mul	V18.4S, V4.4S, V16.4S
	sqrdmulh	V11.4S, V3.4S, V7.4S
	sqrdmulh	V12.4S, V4.4S, V8.4S
	sqrdmlsh	V11.4S, V17.4S, V0.S[0]
	sqrdmlsh	V12.4S, V18.4S, V0.S[0]
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	str	Q9, [x0, #896]
	str	Q10, [x0, #912]
	str	Q11, [x0, #928]
	str	Q12, [x0, #944]
	ldr	Q1, [x1, #960]
	ldr	Q5, [x2, #960]
	ldr	Q2, [x1, #976]
	ldr	Q6, [x2, #976]
	ldr	Q3, [x1, #992]
	ldr	Q7, [x2, #992]
	ldr	Q4, [x1, #1008]
	ldr	Q8, [x2, #1008]
	mul	V13.4S, V5.4S, V0.S[1]
	mul	V14.4S, V6.4S, V0.S[1]
	mul	V17.4S, V1.4S, V13.4S
	mul	V18.4S, V2.4S, V14.4S
	sqrdmulh	V9.4S, V1.4S, V5.4S
	sqrdmulh	V10.4S, V2.4S, V6.4S
	sqrdmlsh	V9.4S, V17.4S, V0.S[0]
	sqrdmlsh	V10.4S, V18.4S, V0.S[0]
	sshr	V9.4S, V9.4S, #1
	sshr	V10.4S, V10.4S, #1
	mul	V15.4S, V7.4S, V0.S[1]
	mul	V16.4S, V8.4S, V0.S[1]
	mul	V17.4S, V3.4S, V15.4S
	mul	V18.4S, V4.4S, V16.4S
	sqrdmulh	V11.4S, V3.4S, V7.4S
	sqrdmulh	V12.4S, V4.4S, V8.4S
	sqrdmlsh	V11.4S, V17.4S, V0.S[0]
	sqrdmlsh	V12.4S, V18.4S, V0.S[0]
	sshr	V11.4S, V11.4S, #1
	sshr	V12.4S, V12.4S, #1
	str	Q9, [x0, #960]
	str	Q10, [x0, #976]
	str	Q11, [x0, #992]
	str	Q12, [x0, #1008]
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
L_mldsa_decompose_q88_consts
	DCD	0x0000002c, 0x0000002c, 0x0000002c, 0x0000002c
	DCD	0x003fefd4, 0x003fefd4, 0x003fefd4, 0x003fefd4
	DCD	0x0002e800, 0x0002e800, 0x0002e800, 0x0002e800
	DCD	0x00017400, 0x00017400, 0x00017400, 0x00017400
	DCD	0x0000002b, 0x0000002b, 0x0000002b, 0x0000002b
	DCD	0x007fe001, 0x007fe001, 0x007fe001, 0x007fe001
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mldsa_decompose_q88_neon
mldsa_decompose_q88_neon PROC
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	stp	D10, D11, [x29, #32]
	stp	D12, D13, [x29, #48]
	stp	D14, D15, [x29, #64]
	adrp	x3, L_mldsa_decompose_q88_consts
	add	x3, x3, L_mldsa_decompose_q88_consts
	ldr	Q0, [x3]
	ldr	Q1, [x3, #16]
	ldr	Q2, [x3, #32]
	ldr	Q3, [x3, #48]
	ldr	Q4, [x3, #64]
	mov	x4, #16
L_mldsa_decompose_q88_loop
	ldr	Q5, [x0]
	ldr	Q6, [x0, #16]
	ldr	Q7, [x0, #32]
	ldr	Q8, [x0, #48]
	mov	V13.16B, V1.16B
	mla	V13.4S, V5.4S, V0.4S
	sshr	V13.4S, V13.4S, #23
	mov	V9.16B, V5.16B
	mls	V9.4S, V13.4S, V2.4S
	sub	V17.4S, V3.4S, V9.4S
	usra	V13.4S, V17.4S, #31
	mov	V9.16B, V5.16B
	mls	V9.4S, V13.4S, V2.4S
	sub	V17.4S, V4.4S, V13.4S
	ushr	V17.4S, V17.4S, #31
	sub	V9.4S, V9.4S, V17.4S
	sub	V17.4S, V13.4S, V0.4S
	ushr	V17.4S, V17.4S, #31
	neg	V17.4S, V17.4S
	and	V13.16B, V13.16B, V17.16B
	mov	V14.16B, V1.16B
	mla	V14.4S, V6.4S, V0.4S
	sshr	V14.4S, V14.4S, #23
	mov	V10.16B, V6.16B
	mls	V10.4S, V14.4S, V2.4S
	sub	V18.4S, V3.4S, V10.4S
	usra	V14.4S, V18.4S, #31
	mov	V10.16B, V6.16B
	mls	V10.4S, V14.4S, V2.4S
	sub	V18.4S, V4.4S, V14.4S
	ushr	V18.4S, V18.4S, #31
	sub	V10.4S, V10.4S, V18.4S
	sub	V18.4S, V14.4S, V0.4S
	ushr	V18.4S, V18.4S, #31
	neg	V18.4S, V18.4S
	and	V14.16B, V14.16B, V18.16B
	mov	V15.16B, V1.16B
	mla	V15.4S, V7.4S, V0.4S
	sshr	V15.4S, V15.4S, #23
	mov	V11.16B, V7.16B
	mls	V11.4S, V15.4S, V2.4S
	sub	V19.4S, V3.4S, V11.4S
	usra	V15.4S, V19.4S, #31
	mov	V11.16B, V7.16B
	mls	V11.4S, V15.4S, V2.4S
	sub	V19.4S, V4.4S, V15.4S
	ushr	V19.4S, V19.4S, #31
	sub	V11.4S, V11.4S, V19.4S
	sub	V19.4S, V15.4S, V0.4S
	ushr	V19.4S, V19.4S, #31
	neg	V19.4S, V19.4S
	and	V15.16B, V15.16B, V19.16B
	mov	V16.16B, V1.16B
	mla	V16.4S, V8.4S, V0.4S
	sshr	V16.4S, V16.4S, #23
	mov	V12.16B, V8.16B
	mls	V12.4S, V16.4S, V2.4S
	sub	V20.4S, V3.4S, V12.4S
	usra	V16.4S, V20.4S, #31
	mov	V12.16B, V8.16B
	mls	V12.4S, V16.4S, V2.4S
	sub	V20.4S, V4.4S, V16.4S
	ushr	V20.4S, V20.4S, #31
	sub	V12.4S, V12.4S, V20.4S
	sub	V20.4S, V16.4S, V0.4S
	ushr	V20.4S, V20.4S, #31
	neg	V20.4S, V20.4S
	and	V16.16B, V16.16B, V20.16B
	str	Q9, [x1]
	str	Q13, [x2]
	str	Q10, [x1, #16]
	str	Q14, [x2, #16]
	str	Q11, [x1, #32]
	str	Q15, [x2, #32]
	str	Q12, [x1, #48]
	str	Q16, [x2, #48]
	add	x0, x0, #0x40
	add	x1, x1, #0x40
	add	x2, x2, #0x40
	subs	x4, x4, #1
	bne	L_mldsa_decompose_q88_loop
	ldp	D8, D9, [x29, #16]
	ldp	D10, D11, [x29, #32]
	ldp	D12, D13, [x29, #48]
	ldp	D14, D15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
	ENDP
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_decompose_q32_consts
	DCD	0x0003feff, 0x0003feff, 0x0003feff, 0x0003feff
	DCD	0x0003ff00, 0x0003ff00, 0x0003ff00, 0x0003ff00
	DCD	0x0000000f, 0x0000000f, 0x0000000f, 0x0000000f
	DCD	0x0007fe00, 0x0007fe00, 0x0007fe00, 0x0007fe00
	DCD	0x007fe001, 0x007fe001, 0x007fe001, 0x007fe001
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mldsa_decompose_q32_neon
mldsa_decompose_q32_neon PROC
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	stp	D10, D11, [x29, #32]
	stp	D12, D13, [x29, #48]
	stp	D14, D15, [x29, #64]
	adrp	x3, L_mldsa_decompose_q32_consts
	add	x3, x3, L_mldsa_decompose_q32_consts
	ldr	Q0, [x3]
	ldr	Q1, [x3, #16]
	ldr	Q2, [x3, #32]
	ldr	Q3, [x3, #48]
	mov	x4, #16
L_mldsa_decompose_q32_loop
	ldr	Q4, [x0]
	ldr	Q5, [x0, #16]
	ldr	Q6, [x0, #32]
	ldr	Q7, [x0, #48]
	add	V12.4S, V4.4S, V0.4S
	sshr	V12.4S, V12.4S, #19
	mov	V8.16B, V4.16B
	mls	V8.4S, V12.4S, V3.4S
	sub	V16.4S, V1.4S, V8.4S
	usra	V12.4S, V16.4S, #31
	mov	V8.16B, V4.16B
	mls	V8.4S, V12.4S, V3.4S
	sshr	V16.4S, V12.4S, #4
	sub	V8.4S, V8.4S, V16.4S
	and	V12.16B, V12.16B, V2.16B
	add	V13.4S, V5.4S, V0.4S
	sshr	V13.4S, V13.4S, #19
	mov	V9.16B, V5.16B
	mls	V9.4S, V13.4S, V3.4S
	sub	V17.4S, V1.4S, V9.4S
	usra	V13.4S, V17.4S, #31
	mov	V9.16B, V5.16B
	mls	V9.4S, V13.4S, V3.4S
	sshr	V17.4S, V13.4S, #4
	sub	V9.4S, V9.4S, V17.4S
	and	V13.16B, V13.16B, V2.16B
	add	V14.4S, V6.4S, V0.4S
	sshr	V14.4S, V14.4S, #19
	mov	V10.16B, V6.16B
	mls	V10.4S, V14.4S, V3.4S
	sub	V18.4S, V1.4S, V10.4S
	usra	V14.4S, V18.4S, #31
	mov	V10.16B, V6.16B
	mls	V10.4S, V14.4S, V3.4S
	sshr	V18.4S, V14.4S, #4
	sub	V10.4S, V10.4S, V18.4S
	and	V14.16B, V14.16B, V2.16B
	add	V15.4S, V7.4S, V0.4S
	sshr	V15.4S, V15.4S, #19
	mov	V11.16B, V7.16B
	mls	V11.4S, V15.4S, V3.4S
	sub	V19.4S, V1.4S, V11.4S
	usra	V15.4S, V19.4S, #31
	mov	V11.16B, V7.16B
	mls	V11.4S, V15.4S, V3.4S
	sshr	V19.4S, V15.4S, #4
	sub	V11.4S, V11.4S, V19.4S
	and	V15.16B, V15.16B, V2.16B
	str	Q8, [x1]
	str	Q12, [x2]
	str	Q9, [x1, #16]
	str	Q13, [x2, #16]
	str	Q10, [x1, #32]
	str	Q14, [x2, #32]
	str	Q11, [x1, #48]
	str	Q15, [x2, #48]
	add	x0, x0, #0x40
	add	x1, x1, #0x40
	add	x2, x2, #0x40
	subs	x4, x4, #1
	bne	L_mldsa_decompose_q32_loop
	ldp	D8, D9, [x29, #16]
	ldp	D10, D11, [x29, #32]
	ldp	D12, D13, [x29, #48]
	ldp	D14, D15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
	ENDP
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_use_hint_q88_consts
	DCD	0x0000002c, 0x0000002c, 0x0000002c, 0x0000002c
	DCD	0x003fefd4, 0x003fefd4, 0x003fefd4, 0x003fefd4
	DCD	0x0002e800, 0x0002e800, 0x0002e800, 0x0002e800
	DCD	0x00017400, 0x00017400, 0x00017400, 0x00017400
	DCD	0x0000002b, 0x0000002b, 0x0000002b, 0x0000002b
	DCD	0x007fe001, 0x007fe001, 0x007fe001, 0x007fe001
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mldsa_use_hint_q88_neon
mldsa_use_hint_q88_neon PROC
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	stp	D10, D11, [x29, #32]
	stp	D12, D13, [x29, #48]
	stp	D14, D15, [x29, #64]
	adrp	x1, L_mldsa_use_hint_q88_consts
	add	x1, x1, L_mldsa_use_hint_q88_consts
	ldr	Q0, [x1]
	ldr	Q1, [x1, #16]
	ldr	Q2, [x1, #32]
	ldr	Q3, [x1, #48]
	ldr	Q4, [x1, #64]
	ldr	Q5, [x1, #80]
	mov	x2, #16
L_mldsa_use_hint_q88_loop
	ldr	Q6, [x0]
	ldr	Q7, [x0, #16]
	ldr	Q8, [x0, #32]
	ldr	Q9, [x0, #48]
	sshr	V18.4S, V6.4S, #31
	and	V18.16B, V18.16B, V5.16B
	add	V6.4S, V6.4S, V18.4S
	sshr	V19.4S, V7.4S, #31
	and	V19.16B, V19.16B, V5.16B
	add	V7.4S, V7.4S, V19.4S
	sshr	V20.4S, V8.4S, #31
	and	V20.16B, V20.16B, V5.16B
	add	V8.4S, V8.4S, V20.4S
	sshr	V21.4S, V9.4S, #31
	and	V21.16B, V21.16B, V5.16B
	add	V9.4S, V9.4S, V21.4S
	mov	V14.16B, V1.16B
	mla	V14.4S, V6.4S, V0.4S
	sshr	V14.4S, V14.4S, #23
	mov	V10.16B, V6.16B
	mls	V10.4S, V14.4S, V2.4S
	sub	V18.4S, V3.4S, V10.4S
	usra	V14.4S, V18.4S, #31
	mov	V10.16B, V6.16B
	mls	V10.4S, V14.4S, V2.4S
	sub	V18.4S, V4.4S, V14.4S
	ushr	V18.4S, V18.4S, #31
	sub	V10.4S, V10.4S, V18.4S
	sub	V18.4S, V14.4S, V0.4S
	ushr	V18.4S, V18.4S, #31
	neg	V18.4S, V18.4S
	and	V14.16B, V14.16B, V18.16B
	mov	V15.16B, V1.16B
	mla	V15.4S, V7.4S, V0.4S
	sshr	V15.4S, V15.4S, #23
	mov	V11.16B, V7.16B
	mls	V11.4S, V15.4S, V2.4S
	sub	V19.4S, V3.4S, V11.4S
	usra	V15.4S, V19.4S, #31
	mov	V11.16B, V7.16B
	mls	V11.4S, V15.4S, V2.4S
	sub	V19.4S, V4.4S, V15.4S
	ushr	V19.4S, V19.4S, #31
	sub	V11.4S, V11.4S, V19.4S
	sub	V19.4S, V15.4S, V0.4S
	ushr	V19.4S, V19.4S, #31
	neg	V19.4S, V19.4S
	and	V15.16B, V15.16B, V19.16B
	mov	V16.16B, V1.16B
	mla	V16.4S, V8.4S, V0.4S
	sshr	V16.4S, V16.4S, #23
	mov	V12.16B, V8.16B
	mls	V12.4S, V16.4S, V2.4S
	sub	V20.4S, V3.4S, V12.4S
	usra	V16.4S, V20.4S, #31
	mov	V12.16B, V8.16B
	mls	V12.4S, V16.4S, V2.4S
	sub	V20.4S, V4.4S, V16.4S
	ushr	V20.4S, V20.4S, #31
	sub	V12.4S, V12.4S, V20.4S
	sub	V20.4S, V16.4S, V0.4S
	ushr	V20.4S, V20.4S, #31
	neg	V20.4S, V20.4S
	and	V16.16B, V16.16B, V20.16B
	mov	V17.16B, V1.16B
	mla	V17.4S, V9.4S, V0.4S
	sshr	V17.4S, V17.4S, #23
	mov	V13.16B, V9.16B
	mls	V13.4S, V17.4S, V2.4S
	sub	V21.4S, V3.4S, V13.4S
	usra	V17.4S, V21.4S, #31
	mov	V13.16B, V9.16B
	mls	V13.4S, V17.4S, V2.4S
	sub	V21.4S, V4.4S, V17.4S
	ushr	V21.4S, V21.4S, #31
	sub	V13.4S, V13.4S, V21.4S
	sub	V21.4S, V17.4S, V0.4S
	ushr	V21.4S, V21.4S, #31
	neg	V21.4S, V21.4S
	and	V17.16B, V17.16B, V21.16B
	str	Q14, [x0]
	str	Q15, [x0, #16]
	str	Q16, [x0, #32]
	str	Q17, [x0, #48]
	add	x0, x0, #0x40
	subs	x2, x2, #1
	bne	L_mldsa_use_hint_q88_loop
	ldp	D8, D9, [x29, #16]
	ldp	D10, D11, [x29, #32]
	ldp	D12, D13, [x29, #48]
	ldp	D14, D15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
	ENDP
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_use_hint_q32_consts
	DCD	0x0003feff, 0x0003feff, 0x0003feff, 0x0003feff
	DCD	0x0003ff00, 0x0003ff00, 0x0003ff00, 0x0003ff00
	DCD	0x0000000f, 0x0000000f, 0x0000000f, 0x0000000f
	DCD	0x0007fe00, 0x0007fe00, 0x0007fe00, 0x0007fe00
	DCD	0x007fe001, 0x007fe001, 0x007fe001, 0x007fe001
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mldsa_use_hint_q32_neon
mldsa_use_hint_q32_neon PROC
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	stp	D10, D11, [x29, #32]
	stp	D12, D13, [x29, #48]
	stp	D14, D15, [x29, #64]
	adrp	x1, L_mldsa_use_hint_q32_consts
	add	x1, x1, L_mldsa_use_hint_q32_consts
	ldr	Q0, [x1]
	ldr	Q1, [x1, #16]
	ldr	Q2, [x1, #32]
	ldr	Q3, [x1, #48]
	ldr	Q4, [x1, #64]
	mov	x2, #16
L_mldsa_use_hint_q32_loop
	ldr	Q5, [x0]
	ldr	Q6, [x0, #16]
	ldr	Q7, [x0, #32]
	ldr	Q8, [x0, #48]
	sshr	V17.4S, V5.4S, #31
	and	V17.16B, V17.16B, V4.16B
	add	V5.4S, V5.4S, V17.4S
	sshr	V18.4S, V6.4S, #31
	and	V18.16B, V18.16B, V4.16B
	add	V6.4S, V6.4S, V18.4S
	sshr	V19.4S, V7.4S, #31
	and	V19.16B, V19.16B, V4.16B
	add	V7.4S, V7.4S, V19.4S
	sshr	V20.4S, V8.4S, #31
	and	V20.16B, V20.16B, V4.16B
	add	V8.4S, V8.4S, V20.4S
	add	V13.4S, V5.4S, V0.4S
	sshr	V13.4S, V13.4S, #19
	mov	V9.16B, V5.16B
	mls	V9.4S, V13.4S, V3.4S
	sub	V17.4S, V1.4S, V9.4S
	usra	V13.4S, V17.4S, #31
	mov	V9.16B, V5.16B
	mls	V9.4S, V13.4S, V3.4S
	sshr	V17.4S, V13.4S, #4
	sub	V9.4S, V9.4S, V17.4S
	and	V13.16B, V13.16B, V2.16B
	add	V14.4S, V6.4S, V0.4S
	sshr	V14.4S, V14.4S, #19
	mov	V10.16B, V6.16B
	mls	V10.4S, V14.4S, V3.4S
	sub	V18.4S, V1.4S, V10.4S
	usra	V14.4S, V18.4S, #31
	mov	V10.16B, V6.16B
	mls	V10.4S, V14.4S, V3.4S
	sshr	V18.4S, V14.4S, #4
	sub	V10.4S, V10.4S, V18.4S
	and	V14.16B, V14.16B, V2.16B
	add	V15.4S, V7.4S, V0.4S
	sshr	V15.4S, V15.4S, #19
	mov	V11.16B, V7.16B
	mls	V11.4S, V15.4S, V3.4S
	sub	V19.4S, V1.4S, V11.4S
	usra	V15.4S, V19.4S, #31
	mov	V11.16B, V7.16B
	mls	V11.4S, V15.4S, V3.4S
	sshr	V19.4S, V15.4S, #4
	sub	V11.4S, V11.4S, V19.4S
	and	V15.16B, V15.16B, V2.16B
	add	V16.4S, V8.4S, V0.4S
	sshr	V16.4S, V16.4S, #19
	mov	V12.16B, V8.16B
	mls	V12.4S, V16.4S, V3.4S
	sub	V20.4S, V1.4S, V12.4S
	usra	V16.4S, V20.4S, #31
	mov	V12.16B, V8.16B
	mls	V12.4S, V16.4S, V3.4S
	sshr	V20.4S, V16.4S, #4
	sub	V12.4S, V12.4S, V20.4S
	and	V16.16B, V16.16B, V2.16B
	str	Q13, [x0]
	str	Q14, [x0, #16]
	str	Q15, [x0, #32]
	str	Q16, [x0, #48]
	add	x0, x0, #0x40
	subs	x2, x2, #1
	bne	L_mldsa_use_hint_q32_loop
	ldp	D8, D9, [x29, #16]
	ldp	D10, D11, [x29, #32]
	ldp	D12, D13, [x29, #48]
	ldp	D14, D15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
	ENDP
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_make_hint_bits
	DCD	0x00000001, 0x00000002, 0x00000004, 0x00000008
	DCD	0x00000010, 0x00000020, 0x00000040, 0x00000080
	DCD	0x00000100, 0x00000200, 0x00000400, 0x00000800
	DCD	0x00001000, 0x00002000, 0x00004000, 0x00008000
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mldsa_make_hint_neon
mldsa_make_hint_neon PROC
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	stp	D10, D11, [x29, #32]
	stp	D12, D13, [x29, #48]
	stp	D14, D15, [x29, #64]
	adrp	x6, L_mldsa_make_hint_bits
	add	x6, x6, L_mldsa_make_hint_bits
	dup	V0.4S, w5
	neg	V1.4S, V0.4S
	ldr	Q2, [x6]
	ldr	Q3, [x6, #16]
	ldr	Q4, [x6, #32]
	ldr	Q5, [x6, #48]
	eor	x7, x7, x7
L_mldsa_make_hint_loop
	ldr	Q6, [x0]
	ldr	Q10, [x1]
	ldr	Q7, [x0, #16]
	ldr	Q11, [x1, #16]
	ldr	Q8, [x0, #32]
	ldr	Q12, [x1, #32]
	ldr	Q9, [x0, #48]
	ldr	Q13, [x1, #48]
	cmgt	V14.4S, V6.4S, V0.4S
	cmgt	V18.4S, V1.4S, V6.4S
	cmeq	V22.4S, V6.4S, V1.4S
	cmeq	V10.4S, V10.4S, #0
	bic	V22.16B, V22.16B, V10.16B
	orr	V14.16B, V14.16B, V18.16B
	orr	V14.16B, V14.16B, V22.16B
	and	V14.16B, V14.16B, V2.16B
	cmgt	V15.4S, V7.4S, V0.4S
	cmgt	V19.4S, V1.4S, V7.4S
	cmeq	V23.4S, V7.4S, V1.4S
	cmeq	V11.4S, V11.4S, #0
	bic	V23.16B, V23.16B, V11.16B
	orr	V15.16B, V15.16B, V19.16B
	orr	V15.16B, V15.16B, V23.16B
	and	V15.16B, V15.16B, V3.16B
	cmgt	V16.4S, V8.4S, V0.4S
	cmgt	V20.4S, V1.4S, V8.4S
	cmeq	V24.4S, V8.4S, V1.4S
	cmeq	V12.4S, V12.4S, #0
	bic	V24.16B, V24.16B, V12.16B
	orr	V16.16B, V16.16B, V20.16B
	orr	V16.16B, V16.16B, V24.16B
	and	V16.16B, V16.16B, V4.16B
	cmgt	V17.4S, V9.4S, V0.4S
	cmgt	V21.4S, V1.4S, V9.4S
	cmeq	V25.4S, V9.4S, V1.4S
	cmeq	V13.4S, V13.4S, #0
	bic	V25.16B, V25.16B, V13.16B
	orr	V17.16B, V17.16B, V21.16B
	orr	V17.16B, V17.16B, V25.16B
	and	V17.16B, V17.16B, V5.16B
	orr	V14.16B, V14.16B, V15.16B
	orr	V16.16B, V16.16B, V17.16B
	orr	V14.16B, V14.16B, V16.16B
	addv	S14, V14.4S
	mov	w8, V14.S[0]
	cbz	w8, L_mldsa_make_hint_next
L_mldsa_make_hint_bit
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
L_mldsa_make_hint_next
	add	x0, x0, #0x40
	add	x1, x1, #0x40
	add	x7, x7, #16
	subs	wzr, w7, #0x100
	blt	L_mldsa_make_hint_loop
	mov	x0, x3
	b	L_mldsa_make_hint_done
L_mldsa_make_hint_fail
	movn	x0, #0
L_mldsa_make_hint_done
	ldp	D8, D9, [x29, #16]
	ldp	D10, D11, [x29, #32]
	ldp	D12, D13, [x29, #48]
	ldp	D14, D15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
	ENDP
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mldsa_mul_vec_4_neon
mldsa_mul_vec_4_neon PROC
	adrp	x3, L_mldsa_aarch64_consts
	add	x3, x3, L_mldsa_aarch64_consts
	ldr	Q0, [x3]
	ldr	Q1, [x1]
	ldr	Q2, [x2]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1024]
	ldr	Q2, [x2, #1024]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2048]
	ldr	Q2, [x2, #2048]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3072]
	ldr	Q2, [x2, #3072]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0]
	ldr	Q1, [x1, #16]
	ldr	Q2, [x2, #16]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1040]
	ldr	Q2, [x2, #1040]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2064]
	ldr	Q2, [x2, #2064]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3088]
	ldr	Q2, [x2, #3088]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #16]
	ldr	Q1, [x1, #32]
	ldr	Q2, [x2, #32]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1056]
	ldr	Q2, [x2, #1056]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2080]
	ldr	Q2, [x2, #2080]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3104]
	ldr	Q2, [x2, #3104]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #32]
	ldr	Q1, [x1, #48]
	ldr	Q2, [x2, #48]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1072]
	ldr	Q2, [x2, #1072]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2096]
	ldr	Q2, [x2, #2096]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3120]
	ldr	Q2, [x2, #3120]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #48]
	ldr	Q1, [x1, #64]
	ldr	Q2, [x2, #64]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1088]
	ldr	Q2, [x2, #1088]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2112]
	ldr	Q2, [x2, #2112]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3136]
	ldr	Q2, [x2, #3136]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #64]
	ldr	Q1, [x1, #80]
	ldr	Q2, [x2, #80]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1104]
	ldr	Q2, [x2, #1104]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2128]
	ldr	Q2, [x2, #2128]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3152]
	ldr	Q2, [x2, #3152]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #80]
	ldr	Q1, [x1, #96]
	ldr	Q2, [x2, #96]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1120]
	ldr	Q2, [x2, #1120]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2144]
	ldr	Q2, [x2, #2144]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3168]
	ldr	Q2, [x2, #3168]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #96]
	ldr	Q1, [x1, #112]
	ldr	Q2, [x2, #112]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1136]
	ldr	Q2, [x2, #1136]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2160]
	ldr	Q2, [x2, #2160]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3184]
	ldr	Q2, [x2, #3184]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #112]
	ldr	Q1, [x1, #128]
	ldr	Q2, [x2, #128]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1152]
	ldr	Q2, [x2, #1152]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2176]
	ldr	Q2, [x2, #2176]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3200]
	ldr	Q2, [x2, #3200]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #128]
	ldr	Q1, [x1, #144]
	ldr	Q2, [x2, #144]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1168]
	ldr	Q2, [x2, #1168]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2192]
	ldr	Q2, [x2, #2192]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3216]
	ldr	Q2, [x2, #3216]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #144]
	ldr	Q1, [x1, #160]
	ldr	Q2, [x2, #160]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1184]
	ldr	Q2, [x2, #1184]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2208]
	ldr	Q2, [x2, #2208]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3232]
	ldr	Q2, [x2, #3232]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #160]
	ldr	Q1, [x1, #176]
	ldr	Q2, [x2, #176]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1200]
	ldr	Q2, [x2, #1200]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2224]
	ldr	Q2, [x2, #2224]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3248]
	ldr	Q2, [x2, #3248]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #176]
	ldr	Q1, [x1, #192]
	ldr	Q2, [x2, #192]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1216]
	ldr	Q2, [x2, #1216]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2240]
	ldr	Q2, [x2, #2240]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3264]
	ldr	Q2, [x2, #3264]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #192]
	ldr	Q1, [x1, #208]
	ldr	Q2, [x2, #208]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1232]
	ldr	Q2, [x2, #1232]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2256]
	ldr	Q2, [x2, #2256]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3280]
	ldr	Q2, [x2, #3280]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #208]
	ldr	Q1, [x1, #224]
	ldr	Q2, [x2, #224]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1248]
	ldr	Q2, [x2, #1248]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2272]
	ldr	Q2, [x2, #2272]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3296]
	ldr	Q2, [x2, #3296]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #224]
	ldr	Q1, [x1, #240]
	ldr	Q2, [x2, #240]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1264]
	ldr	Q2, [x2, #1264]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2288]
	ldr	Q2, [x2, #2288]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3312]
	ldr	Q2, [x2, #3312]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #240]
	ldr	Q1, [x1, #256]
	ldr	Q2, [x2, #256]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1280]
	ldr	Q2, [x2, #1280]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2304]
	ldr	Q2, [x2, #2304]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3328]
	ldr	Q2, [x2, #3328]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #256]
	ldr	Q1, [x1, #272]
	ldr	Q2, [x2, #272]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1296]
	ldr	Q2, [x2, #1296]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2320]
	ldr	Q2, [x2, #2320]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3344]
	ldr	Q2, [x2, #3344]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #272]
	ldr	Q1, [x1, #288]
	ldr	Q2, [x2, #288]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1312]
	ldr	Q2, [x2, #1312]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2336]
	ldr	Q2, [x2, #2336]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3360]
	ldr	Q2, [x2, #3360]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #288]
	ldr	Q1, [x1, #304]
	ldr	Q2, [x2, #304]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1328]
	ldr	Q2, [x2, #1328]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2352]
	ldr	Q2, [x2, #2352]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3376]
	ldr	Q2, [x2, #3376]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #304]
	ldr	Q1, [x1, #320]
	ldr	Q2, [x2, #320]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1344]
	ldr	Q2, [x2, #1344]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2368]
	ldr	Q2, [x2, #2368]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3392]
	ldr	Q2, [x2, #3392]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #320]
	ldr	Q1, [x1, #336]
	ldr	Q2, [x2, #336]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1360]
	ldr	Q2, [x2, #1360]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2384]
	ldr	Q2, [x2, #2384]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3408]
	ldr	Q2, [x2, #3408]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #336]
	ldr	Q1, [x1, #352]
	ldr	Q2, [x2, #352]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1376]
	ldr	Q2, [x2, #1376]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2400]
	ldr	Q2, [x2, #2400]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3424]
	ldr	Q2, [x2, #3424]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #352]
	ldr	Q1, [x1, #368]
	ldr	Q2, [x2, #368]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1392]
	ldr	Q2, [x2, #1392]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2416]
	ldr	Q2, [x2, #2416]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3440]
	ldr	Q2, [x2, #3440]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #368]
	ldr	Q1, [x1, #384]
	ldr	Q2, [x2, #384]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1408]
	ldr	Q2, [x2, #1408]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2432]
	ldr	Q2, [x2, #2432]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3456]
	ldr	Q2, [x2, #3456]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #384]
	ldr	Q1, [x1, #400]
	ldr	Q2, [x2, #400]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1424]
	ldr	Q2, [x2, #1424]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2448]
	ldr	Q2, [x2, #2448]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3472]
	ldr	Q2, [x2, #3472]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #400]
	ldr	Q1, [x1, #416]
	ldr	Q2, [x2, #416]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1440]
	ldr	Q2, [x2, #1440]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2464]
	ldr	Q2, [x2, #2464]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3488]
	ldr	Q2, [x2, #3488]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #416]
	ldr	Q1, [x1, #432]
	ldr	Q2, [x2, #432]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1456]
	ldr	Q2, [x2, #1456]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2480]
	ldr	Q2, [x2, #2480]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3504]
	ldr	Q2, [x2, #3504]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #432]
	ldr	Q1, [x1, #448]
	ldr	Q2, [x2, #448]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1472]
	ldr	Q2, [x2, #1472]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2496]
	ldr	Q2, [x2, #2496]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3520]
	ldr	Q2, [x2, #3520]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #448]
	ldr	Q1, [x1, #464]
	ldr	Q2, [x2, #464]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1488]
	ldr	Q2, [x2, #1488]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2512]
	ldr	Q2, [x2, #2512]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3536]
	ldr	Q2, [x2, #3536]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #464]
	ldr	Q1, [x1, #480]
	ldr	Q2, [x2, #480]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1504]
	ldr	Q2, [x2, #1504]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2528]
	ldr	Q2, [x2, #2528]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3552]
	ldr	Q2, [x2, #3552]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #480]
	ldr	Q1, [x1, #496]
	ldr	Q2, [x2, #496]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1520]
	ldr	Q2, [x2, #1520]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2544]
	ldr	Q2, [x2, #2544]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3568]
	ldr	Q2, [x2, #3568]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #496]
	ldr	Q1, [x1, #512]
	ldr	Q2, [x2, #512]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1536]
	ldr	Q2, [x2, #1536]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2560]
	ldr	Q2, [x2, #2560]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3584]
	ldr	Q2, [x2, #3584]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #512]
	ldr	Q1, [x1, #528]
	ldr	Q2, [x2, #528]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1552]
	ldr	Q2, [x2, #1552]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2576]
	ldr	Q2, [x2, #2576]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3600]
	ldr	Q2, [x2, #3600]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #528]
	ldr	Q1, [x1, #544]
	ldr	Q2, [x2, #544]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1568]
	ldr	Q2, [x2, #1568]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2592]
	ldr	Q2, [x2, #2592]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3616]
	ldr	Q2, [x2, #3616]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #544]
	ldr	Q1, [x1, #560]
	ldr	Q2, [x2, #560]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1584]
	ldr	Q2, [x2, #1584]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2608]
	ldr	Q2, [x2, #2608]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3632]
	ldr	Q2, [x2, #3632]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #560]
	ldr	Q1, [x1, #576]
	ldr	Q2, [x2, #576]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1600]
	ldr	Q2, [x2, #1600]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2624]
	ldr	Q2, [x2, #2624]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3648]
	ldr	Q2, [x2, #3648]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #576]
	ldr	Q1, [x1, #592]
	ldr	Q2, [x2, #592]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1616]
	ldr	Q2, [x2, #1616]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2640]
	ldr	Q2, [x2, #2640]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3664]
	ldr	Q2, [x2, #3664]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #592]
	ldr	Q1, [x1, #608]
	ldr	Q2, [x2, #608]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1632]
	ldr	Q2, [x2, #1632]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2656]
	ldr	Q2, [x2, #2656]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3680]
	ldr	Q2, [x2, #3680]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #608]
	ldr	Q1, [x1, #624]
	ldr	Q2, [x2, #624]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1648]
	ldr	Q2, [x2, #1648]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2672]
	ldr	Q2, [x2, #2672]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3696]
	ldr	Q2, [x2, #3696]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #624]
	ldr	Q1, [x1, #640]
	ldr	Q2, [x2, #640]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1664]
	ldr	Q2, [x2, #1664]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2688]
	ldr	Q2, [x2, #2688]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3712]
	ldr	Q2, [x2, #3712]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #640]
	ldr	Q1, [x1, #656]
	ldr	Q2, [x2, #656]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1680]
	ldr	Q2, [x2, #1680]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2704]
	ldr	Q2, [x2, #2704]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3728]
	ldr	Q2, [x2, #3728]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #656]
	ldr	Q1, [x1, #672]
	ldr	Q2, [x2, #672]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1696]
	ldr	Q2, [x2, #1696]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2720]
	ldr	Q2, [x2, #2720]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3744]
	ldr	Q2, [x2, #3744]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #672]
	ldr	Q1, [x1, #688]
	ldr	Q2, [x2, #688]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1712]
	ldr	Q2, [x2, #1712]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2736]
	ldr	Q2, [x2, #2736]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3760]
	ldr	Q2, [x2, #3760]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #688]
	ldr	Q1, [x1, #704]
	ldr	Q2, [x2, #704]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1728]
	ldr	Q2, [x2, #1728]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2752]
	ldr	Q2, [x2, #2752]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3776]
	ldr	Q2, [x2, #3776]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #704]
	ldr	Q1, [x1, #720]
	ldr	Q2, [x2, #720]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1744]
	ldr	Q2, [x2, #1744]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2768]
	ldr	Q2, [x2, #2768]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3792]
	ldr	Q2, [x2, #3792]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #720]
	ldr	Q1, [x1, #736]
	ldr	Q2, [x2, #736]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1760]
	ldr	Q2, [x2, #1760]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2784]
	ldr	Q2, [x2, #2784]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3808]
	ldr	Q2, [x2, #3808]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #736]
	ldr	Q1, [x1, #752]
	ldr	Q2, [x2, #752]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1776]
	ldr	Q2, [x2, #1776]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2800]
	ldr	Q2, [x2, #2800]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3824]
	ldr	Q2, [x2, #3824]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #752]
	ldr	Q1, [x1, #768]
	ldr	Q2, [x2, #768]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1792]
	ldr	Q2, [x2, #1792]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2816]
	ldr	Q2, [x2, #2816]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3840]
	ldr	Q2, [x2, #3840]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #768]
	ldr	Q1, [x1, #784]
	ldr	Q2, [x2, #784]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1808]
	ldr	Q2, [x2, #1808]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2832]
	ldr	Q2, [x2, #2832]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3856]
	ldr	Q2, [x2, #3856]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #784]
	ldr	Q1, [x1, #800]
	ldr	Q2, [x2, #800]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1824]
	ldr	Q2, [x2, #1824]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2848]
	ldr	Q2, [x2, #2848]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3872]
	ldr	Q2, [x2, #3872]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #800]
	ldr	Q1, [x1, #816]
	ldr	Q2, [x2, #816]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1840]
	ldr	Q2, [x2, #1840]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2864]
	ldr	Q2, [x2, #2864]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3888]
	ldr	Q2, [x2, #3888]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #816]
	ldr	Q1, [x1, #832]
	ldr	Q2, [x2, #832]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1856]
	ldr	Q2, [x2, #1856]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2880]
	ldr	Q2, [x2, #2880]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3904]
	ldr	Q2, [x2, #3904]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #832]
	ldr	Q1, [x1, #848]
	ldr	Q2, [x2, #848]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1872]
	ldr	Q2, [x2, #1872]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2896]
	ldr	Q2, [x2, #2896]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3920]
	ldr	Q2, [x2, #3920]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #848]
	ldr	Q1, [x1, #864]
	ldr	Q2, [x2, #864]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1888]
	ldr	Q2, [x2, #1888]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2912]
	ldr	Q2, [x2, #2912]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3936]
	ldr	Q2, [x2, #3936]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #864]
	ldr	Q1, [x1, #880]
	ldr	Q2, [x2, #880]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1904]
	ldr	Q2, [x2, #1904]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2928]
	ldr	Q2, [x2, #2928]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3952]
	ldr	Q2, [x2, #3952]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #880]
	ldr	Q1, [x1, #896]
	ldr	Q2, [x2, #896]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1920]
	ldr	Q2, [x2, #1920]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2944]
	ldr	Q2, [x2, #2944]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3968]
	ldr	Q2, [x2, #3968]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #896]
	ldr	Q1, [x1, #912]
	ldr	Q2, [x2, #912]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1936]
	ldr	Q2, [x2, #1936]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2960]
	ldr	Q2, [x2, #2960]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3984]
	ldr	Q2, [x2, #3984]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #912]
	ldr	Q1, [x1, #928]
	ldr	Q2, [x2, #928]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1952]
	ldr	Q2, [x2, #1952]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2976]
	ldr	Q2, [x2, #2976]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4000]
	ldr	Q2, [x2, #4000]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #928]
	ldr	Q1, [x1, #944]
	ldr	Q2, [x2, #944]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1968]
	ldr	Q2, [x2, #1968]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2992]
	ldr	Q2, [x2, #2992]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4016]
	ldr	Q2, [x2, #4016]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #944]
	ldr	Q1, [x1, #960]
	ldr	Q2, [x2, #960]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1984]
	ldr	Q2, [x2, #1984]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3008]
	ldr	Q2, [x2, #3008]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4032]
	ldr	Q2, [x2, #4032]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #960]
	ldr	Q1, [x1, #976]
	ldr	Q2, [x2, #976]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2000]
	ldr	Q2, [x2, #2000]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3024]
	ldr	Q2, [x2, #3024]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4048]
	ldr	Q2, [x2, #4048]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #976]
	ldr	Q1, [x1, #992]
	ldr	Q2, [x2, #992]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2016]
	ldr	Q2, [x2, #2016]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3040]
	ldr	Q2, [x2, #3040]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4064]
	ldr	Q2, [x2, #4064]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #992]
	ldr	Q1, [x1, #1008]
	ldr	Q2, [x2, #1008]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2032]
	ldr	Q2, [x2, #2032]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3056]
	ldr	Q2, [x2, #3056]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4080]
	ldr	Q2, [x2, #4080]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #1008]
	ret
	ENDP
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mldsa_mul_vec_5_neon
mldsa_mul_vec_5_neon PROC
	adrp	x3, L_mldsa_aarch64_consts
	add	x3, x3, L_mldsa_aarch64_consts
	ldr	Q0, [x3]
	ldr	Q1, [x1]
	ldr	Q2, [x2]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1024]
	ldr	Q2, [x2, #1024]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2048]
	ldr	Q2, [x2, #2048]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3072]
	ldr	Q2, [x2, #3072]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4096]
	ldr	Q2, [x2, #4096]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0]
	ldr	Q1, [x1, #16]
	ldr	Q2, [x2, #16]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1040]
	ldr	Q2, [x2, #1040]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2064]
	ldr	Q2, [x2, #2064]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3088]
	ldr	Q2, [x2, #3088]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4112]
	ldr	Q2, [x2, #4112]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #16]
	ldr	Q1, [x1, #32]
	ldr	Q2, [x2, #32]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1056]
	ldr	Q2, [x2, #1056]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2080]
	ldr	Q2, [x2, #2080]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3104]
	ldr	Q2, [x2, #3104]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4128]
	ldr	Q2, [x2, #4128]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #32]
	ldr	Q1, [x1, #48]
	ldr	Q2, [x2, #48]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1072]
	ldr	Q2, [x2, #1072]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2096]
	ldr	Q2, [x2, #2096]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3120]
	ldr	Q2, [x2, #3120]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4144]
	ldr	Q2, [x2, #4144]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #48]
	ldr	Q1, [x1, #64]
	ldr	Q2, [x2, #64]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1088]
	ldr	Q2, [x2, #1088]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2112]
	ldr	Q2, [x2, #2112]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3136]
	ldr	Q2, [x2, #3136]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4160]
	ldr	Q2, [x2, #4160]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #64]
	ldr	Q1, [x1, #80]
	ldr	Q2, [x2, #80]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1104]
	ldr	Q2, [x2, #1104]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2128]
	ldr	Q2, [x2, #2128]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3152]
	ldr	Q2, [x2, #3152]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4176]
	ldr	Q2, [x2, #4176]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #80]
	ldr	Q1, [x1, #96]
	ldr	Q2, [x2, #96]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1120]
	ldr	Q2, [x2, #1120]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2144]
	ldr	Q2, [x2, #2144]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3168]
	ldr	Q2, [x2, #3168]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4192]
	ldr	Q2, [x2, #4192]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #96]
	ldr	Q1, [x1, #112]
	ldr	Q2, [x2, #112]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1136]
	ldr	Q2, [x2, #1136]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2160]
	ldr	Q2, [x2, #2160]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3184]
	ldr	Q2, [x2, #3184]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4208]
	ldr	Q2, [x2, #4208]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #112]
	ldr	Q1, [x1, #128]
	ldr	Q2, [x2, #128]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1152]
	ldr	Q2, [x2, #1152]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2176]
	ldr	Q2, [x2, #2176]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3200]
	ldr	Q2, [x2, #3200]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4224]
	ldr	Q2, [x2, #4224]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #128]
	ldr	Q1, [x1, #144]
	ldr	Q2, [x2, #144]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1168]
	ldr	Q2, [x2, #1168]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2192]
	ldr	Q2, [x2, #2192]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3216]
	ldr	Q2, [x2, #3216]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4240]
	ldr	Q2, [x2, #4240]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #144]
	ldr	Q1, [x1, #160]
	ldr	Q2, [x2, #160]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1184]
	ldr	Q2, [x2, #1184]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2208]
	ldr	Q2, [x2, #2208]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3232]
	ldr	Q2, [x2, #3232]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4256]
	ldr	Q2, [x2, #4256]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #160]
	ldr	Q1, [x1, #176]
	ldr	Q2, [x2, #176]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1200]
	ldr	Q2, [x2, #1200]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2224]
	ldr	Q2, [x2, #2224]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3248]
	ldr	Q2, [x2, #3248]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4272]
	ldr	Q2, [x2, #4272]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #176]
	ldr	Q1, [x1, #192]
	ldr	Q2, [x2, #192]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1216]
	ldr	Q2, [x2, #1216]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2240]
	ldr	Q2, [x2, #2240]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3264]
	ldr	Q2, [x2, #3264]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4288]
	ldr	Q2, [x2, #4288]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #192]
	ldr	Q1, [x1, #208]
	ldr	Q2, [x2, #208]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1232]
	ldr	Q2, [x2, #1232]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2256]
	ldr	Q2, [x2, #2256]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3280]
	ldr	Q2, [x2, #3280]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4304]
	ldr	Q2, [x2, #4304]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #208]
	ldr	Q1, [x1, #224]
	ldr	Q2, [x2, #224]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1248]
	ldr	Q2, [x2, #1248]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2272]
	ldr	Q2, [x2, #2272]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3296]
	ldr	Q2, [x2, #3296]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4320]
	ldr	Q2, [x2, #4320]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #224]
	ldr	Q1, [x1, #240]
	ldr	Q2, [x2, #240]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1264]
	ldr	Q2, [x2, #1264]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2288]
	ldr	Q2, [x2, #2288]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3312]
	ldr	Q2, [x2, #3312]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4336]
	ldr	Q2, [x2, #4336]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #240]
	ldr	Q1, [x1, #256]
	ldr	Q2, [x2, #256]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1280]
	ldr	Q2, [x2, #1280]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2304]
	ldr	Q2, [x2, #2304]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3328]
	ldr	Q2, [x2, #3328]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4352]
	ldr	Q2, [x2, #4352]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #256]
	ldr	Q1, [x1, #272]
	ldr	Q2, [x2, #272]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1296]
	ldr	Q2, [x2, #1296]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2320]
	ldr	Q2, [x2, #2320]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3344]
	ldr	Q2, [x2, #3344]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4368]
	ldr	Q2, [x2, #4368]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #272]
	ldr	Q1, [x1, #288]
	ldr	Q2, [x2, #288]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1312]
	ldr	Q2, [x2, #1312]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2336]
	ldr	Q2, [x2, #2336]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3360]
	ldr	Q2, [x2, #3360]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4384]
	ldr	Q2, [x2, #4384]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #288]
	ldr	Q1, [x1, #304]
	ldr	Q2, [x2, #304]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1328]
	ldr	Q2, [x2, #1328]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2352]
	ldr	Q2, [x2, #2352]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3376]
	ldr	Q2, [x2, #3376]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4400]
	ldr	Q2, [x2, #4400]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #304]
	ldr	Q1, [x1, #320]
	ldr	Q2, [x2, #320]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1344]
	ldr	Q2, [x2, #1344]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2368]
	ldr	Q2, [x2, #2368]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3392]
	ldr	Q2, [x2, #3392]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4416]
	ldr	Q2, [x2, #4416]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #320]
	ldr	Q1, [x1, #336]
	ldr	Q2, [x2, #336]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1360]
	ldr	Q2, [x2, #1360]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2384]
	ldr	Q2, [x2, #2384]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3408]
	ldr	Q2, [x2, #3408]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4432]
	ldr	Q2, [x2, #4432]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #336]
	ldr	Q1, [x1, #352]
	ldr	Q2, [x2, #352]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1376]
	ldr	Q2, [x2, #1376]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2400]
	ldr	Q2, [x2, #2400]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3424]
	ldr	Q2, [x2, #3424]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4448]
	ldr	Q2, [x2, #4448]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #352]
	ldr	Q1, [x1, #368]
	ldr	Q2, [x2, #368]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1392]
	ldr	Q2, [x2, #1392]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2416]
	ldr	Q2, [x2, #2416]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3440]
	ldr	Q2, [x2, #3440]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4464]
	ldr	Q2, [x2, #4464]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #368]
	ldr	Q1, [x1, #384]
	ldr	Q2, [x2, #384]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1408]
	ldr	Q2, [x2, #1408]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2432]
	ldr	Q2, [x2, #2432]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3456]
	ldr	Q2, [x2, #3456]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4480]
	ldr	Q2, [x2, #4480]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #384]
	ldr	Q1, [x1, #400]
	ldr	Q2, [x2, #400]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1424]
	ldr	Q2, [x2, #1424]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2448]
	ldr	Q2, [x2, #2448]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3472]
	ldr	Q2, [x2, #3472]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4496]
	ldr	Q2, [x2, #4496]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #400]
	ldr	Q1, [x1, #416]
	ldr	Q2, [x2, #416]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1440]
	ldr	Q2, [x2, #1440]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2464]
	ldr	Q2, [x2, #2464]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3488]
	ldr	Q2, [x2, #3488]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4512]
	ldr	Q2, [x2, #4512]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #416]
	ldr	Q1, [x1, #432]
	ldr	Q2, [x2, #432]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1456]
	ldr	Q2, [x2, #1456]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2480]
	ldr	Q2, [x2, #2480]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3504]
	ldr	Q2, [x2, #3504]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4528]
	ldr	Q2, [x2, #4528]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #432]
	ldr	Q1, [x1, #448]
	ldr	Q2, [x2, #448]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1472]
	ldr	Q2, [x2, #1472]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2496]
	ldr	Q2, [x2, #2496]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3520]
	ldr	Q2, [x2, #3520]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4544]
	ldr	Q2, [x2, #4544]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #448]
	ldr	Q1, [x1, #464]
	ldr	Q2, [x2, #464]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1488]
	ldr	Q2, [x2, #1488]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2512]
	ldr	Q2, [x2, #2512]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3536]
	ldr	Q2, [x2, #3536]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4560]
	ldr	Q2, [x2, #4560]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #464]
	ldr	Q1, [x1, #480]
	ldr	Q2, [x2, #480]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1504]
	ldr	Q2, [x2, #1504]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2528]
	ldr	Q2, [x2, #2528]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3552]
	ldr	Q2, [x2, #3552]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4576]
	ldr	Q2, [x2, #4576]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #480]
	ldr	Q1, [x1, #496]
	ldr	Q2, [x2, #496]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1520]
	ldr	Q2, [x2, #1520]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2544]
	ldr	Q2, [x2, #2544]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3568]
	ldr	Q2, [x2, #3568]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4592]
	ldr	Q2, [x2, #4592]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #496]
	ldr	Q1, [x1, #512]
	ldr	Q2, [x2, #512]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1536]
	ldr	Q2, [x2, #1536]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2560]
	ldr	Q2, [x2, #2560]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3584]
	ldr	Q2, [x2, #3584]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4608]
	ldr	Q2, [x2, #4608]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #512]
	ldr	Q1, [x1, #528]
	ldr	Q2, [x2, #528]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1552]
	ldr	Q2, [x2, #1552]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2576]
	ldr	Q2, [x2, #2576]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3600]
	ldr	Q2, [x2, #3600]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4624]
	ldr	Q2, [x2, #4624]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #528]
	ldr	Q1, [x1, #544]
	ldr	Q2, [x2, #544]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1568]
	ldr	Q2, [x2, #1568]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2592]
	ldr	Q2, [x2, #2592]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3616]
	ldr	Q2, [x2, #3616]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4640]
	ldr	Q2, [x2, #4640]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #544]
	ldr	Q1, [x1, #560]
	ldr	Q2, [x2, #560]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1584]
	ldr	Q2, [x2, #1584]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2608]
	ldr	Q2, [x2, #2608]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3632]
	ldr	Q2, [x2, #3632]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4656]
	ldr	Q2, [x2, #4656]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #560]
	ldr	Q1, [x1, #576]
	ldr	Q2, [x2, #576]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1600]
	ldr	Q2, [x2, #1600]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2624]
	ldr	Q2, [x2, #2624]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3648]
	ldr	Q2, [x2, #3648]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4672]
	ldr	Q2, [x2, #4672]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #576]
	ldr	Q1, [x1, #592]
	ldr	Q2, [x2, #592]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1616]
	ldr	Q2, [x2, #1616]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2640]
	ldr	Q2, [x2, #2640]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3664]
	ldr	Q2, [x2, #3664]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4688]
	ldr	Q2, [x2, #4688]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #592]
	ldr	Q1, [x1, #608]
	ldr	Q2, [x2, #608]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1632]
	ldr	Q2, [x2, #1632]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2656]
	ldr	Q2, [x2, #2656]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3680]
	ldr	Q2, [x2, #3680]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4704]
	ldr	Q2, [x2, #4704]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #608]
	ldr	Q1, [x1, #624]
	ldr	Q2, [x2, #624]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1648]
	ldr	Q2, [x2, #1648]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2672]
	ldr	Q2, [x2, #2672]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3696]
	ldr	Q2, [x2, #3696]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4720]
	ldr	Q2, [x2, #4720]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #624]
	ldr	Q1, [x1, #640]
	ldr	Q2, [x2, #640]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1664]
	ldr	Q2, [x2, #1664]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2688]
	ldr	Q2, [x2, #2688]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3712]
	ldr	Q2, [x2, #3712]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4736]
	ldr	Q2, [x2, #4736]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #640]
	ldr	Q1, [x1, #656]
	ldr	Q2, [x2, #656]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1680]
	ldr	Q2, [x2, #1680]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2704]
	ldr	Q2, [x2, #2704]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3728]
	ldr	Q2, [x2, #3728]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4752]
	ldr	Q2, [x2, #4752]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #656]
	ldr	Q1, [x1, #672]
	ldr	Q2, [x2, #672]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1696]
	ldr	Q2, [x2, #1696]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2720]
	ldr	Q2, [x2, #2720]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3744]
	ldr	Q2, [x2, #3744]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4768]
	ldr	Q2, [x2, #4768]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #672]
	ldr	Q1, [x1, #688]
	ldr	Q2, [x2, #688]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1712]
	ldr	Q2, [x2, #1712]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2736]
	ldr	Q2, [x2, #2736]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3760]
	ldr	Q2, [x2, #3760]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4784]
	ldr	Q2, [x2, #4784]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #688]
	ldr	Q1, [x1, #704]
	ldr	Q2, [x2, #704]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1728]
	ldr	Q2, [x2, #1728]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2752]
	ldr	Q2, [x2, #2752]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3776]
	ldr	Q2, [x2, #3776]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4800]
	ldr	Q2, [x2, #4800]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #704]
	ldr	Q1, [x1, #720]
	ldr	Q2, [x2, #720]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1744]
	ldr	Q2, [x2, #1744]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2768]
	ldr	Q2, [x2, #2768]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3792]
	ldr	Q2, [x2, #3792]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4816]
	ldr	Q2, [x2, #4816]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #720]
	ldr	Q1, [x1, #736]
	ldr	Q2, [x2, #736]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1760]
	ldr	Q2, [x2, #1760]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2784]
	ldr	Q2, [x2, #2784]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3808]
	ldr	Q2, [x2, #3808]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4832]
	ldr	Q2, [x2, #4832]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #736]
	ldr	Q1, [x1, #752]
	ldr	Q2, [x2, #752]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1776]
	ldr	Q2, [x2, #1776]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2800]
	ldr	Q2, [x2, #2800]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3824]
	ldr	Q2, [x2, #3824]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4848]
	ldr	Q2, [x2, #4848]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #752]
	ldr	Q1, [x1, #768]
	ldr	Q2, [x2, #768]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1792]
	ldr	Q2, [x2, #1792]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2816]
	ldr	Q2, [x2, #2816]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3840]
	ldr	Q2, [x2, #3840]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4864]
	ldr	Q2, [x2, #4864]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #768]
	ldr	Q1, [x1, #784]
	ldr	Q2, [x2, #784]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1808]
	ldr	Q2, [x2, #1808]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2832]
	ldr	Q2, [x2, #2832]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3856]
	ldr	Q2, [x2, #3856]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4880]
	ldr	Q2, [x2, #4880]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #784]
	ldr	Q1, [x1, #800]
	ldr	Q2, [x2, #800]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1824]
	ldr	Q2, [x2, #1824]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2848]
	ldr	Q2, [x2, #2848]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3872]
	ldr	Q2, [x2, #3872]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4896]
	ldr	Q2, [x2, #4896]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #800]
	ldr	Q1, [x1, #816]
	ldr	Q2, [x2, #816]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1840]
	ldr	Q2, [x2, #1840]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2864]
	ldr	Q2, [x2, #2864]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3888]
	ldr	Q2, [x2, #3888]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4912]
	ldr	Q2, [x2, #4912]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #816]
	ldr	Q1, [x1, #832]
	ldr	Q2, [x2, #832]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1856]
	ldr	Q2, [x2, #1856]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2880]
	ldr	Q2, [x2, #2880]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3904]
	ldr	Q2, [x2, #3904]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4928]
	ldr	Q2, [x2, #4928]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #832]
	ldr	Q1, [x1, #848]
	ldr	Q2, [x2, #848]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1872]
	ldr	Q2, [x2, #1872]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2896]
	ldr	Q2, [x2, #2896]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3920]
	ldr	Q2, [x2, #3920]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4944]
	ldr	Q2, [x2, #4944]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #848]
	ldr	Q1, [x1, #864]
	ldr	Q2, [x2, #864]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1888]
	ldr	Q2, [x2, #1888]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2912]
	ldr	Q2, [x2, #2912]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3936]
	ldr	Q2, [x2, #3936]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4960]
	ldr	Q2, [x2, #4960]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #864]
	ldr	Q1, [x1, #880]
	ldr	Q2, [x2, #880]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1904]
	ldr	Q2, [x2, #1904]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2928]
	ldr	Q2, [x2, #2928]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3952]
	ldr	Q2, [x2, #3952]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4976]
	ldr	Q2, [x2, #4976]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #880]
	ldr	Q1, [x1, #896]
	ldr	Q2, [x2, #896]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1920]
	ldr	Q2, [x2, #1920]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2944]
	ldr	Q2, [x2, #2944]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3968]
	ldr	Q2, [x2, #3968]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4992]
	ldr	Q2, [x2, #4992]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #896]
	ldr	Q1, [x1, #912]
	ldr	Q2, [x2, #912]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1936]
	ldr	Q2, [x2, #1936]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2960]
	ldr	Q2, [x2, #2960]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3984]
	ldr	Q2, [x2, #3984]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5008]
	ldr	Q2, [x2, #5008]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #912]
	ldr	Q1, [x1, #928]
	ldr	Q2, [x2, #928]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1952]
	ldr	Q2, [x2, #1952]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2976]
	ldr	Q2, [x2, #2976]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4000]
	ldr	Q2, [x2, #4000]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5024]
	ldr	Q2, [x2, #5024]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #928]
	ldr	Q1, [x1, #944]
	ldr	Q2, [x2, #944]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1968]
	ldr	Q2, [x2, #1968]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2992]
	ldr	Q2, [x2, #2992]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4016]
	ldr	Q2, [x2, #4016]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5040]
	ldr	Q2, [x2, #5040]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #944]
	ldr	Q1, [x1, #960]
	ldr	Q2, [x2, #960]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1984]
	ldr	Q2, [x2, #1984]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3008]
	ldr	Q2, [x2, #3008]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4032]
	ldr	Q2, [x2, #4032]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5056]
	ldr	Q2, [x2, #5056]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #960]
	ldr	Q1, [x1, #976]
	ldr	Q2, [x2, #976]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2000]
	ldr	Q2, [x2, #2000]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3024]
	ldr	Q2, [x2, #3024]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4048]
	ldr	Q2, [x2, #4048]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5072]
	ldr	Q2, [x2, #5072]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #976]
	ldr	Q1, [x1, #992]
	ldr	Q2, [x2, #992]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2016]
	ldr	Q2, [x2, #2016]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3040]
	ldr	Q2, [x2, #3040]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4064]
	ldr	Q2, [x2, #4064]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5088]
	ldr	Q2, [x2, #5088]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #992]
	ldr	Q1, [x1, #1008]
	ldr	Q2, [x2, #1008]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2032]
	ldr	Q2, [x2, #2032]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3056]
	ldr	Q2, [x2, #3056]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4080]
	ldr	Q2, [x2, #4080]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5104]
	ldr	Q2, [x2, #5104]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #1008]
	ret
	ENDP
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mldsa_mul_vec_7_neon
mldsa_mul_vec_7_neon PROC
	adrp	x3, L_mldsa_aarch64_consts
	add	x3, x3, L_mldsa_aarch64_consts
	ldr	Q0, [x3]
	ldr	Q1, [x1]
	ldr	Q2, [x2]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1024]
	ldr	Q2, [x2, #1024]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2048]
	ldr	Q2, [x2, #2048]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3072]
	ldr	Q2, [x2, #3072]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4096]
	ldr	Q2, [x2, #4096]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5120]
	ldr	Q2, [x2, #5120]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6144]
	ldr	Q2, [x2, #6144]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0]
	ldr	Q1, [x1, #16]
	ldr	Q2, [x2, #16]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1040]
	ldr	Q2, [x2, #1040]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2064]
	ldr	Q2, [x2, #2064]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3088]
	ldr	Q2, [x2, #3088]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4112]
	ldr	Q2, [x2, #4112]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5136]
	ldr	Q2, [x2, #5136]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6160]
	ldr	Q2, [x2, #6160]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #16]
	ldr	Q1, [x1, #32]
	ldr	Q2, [x2, #32]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1056]
	ldr	Q2, [x2, #1056]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2080]
	ldr	Q2, [x2, #2080]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3104]
	ldr	Q2, [x2, #3104]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4128]
	ldr	Q2, [x2, #4128]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5152]
	ldr	Q2, [x2, #5152]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6176]
	ldr	Q2, [x2, #6176]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #32]
	ldr	Q1, [x1, #48]
	ldr	Q2, [x2, #48]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1072]
	ldr	Q2, [x2, #1072]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2096]
	ldr	Q2, [x2, #2096]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3120]
	ldr	Q2, [x2, #3120]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4144]
	ldr	Q2, [x2, #4144]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5168]
	ldr	Q2, [x2, #5168]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6192]
	ldr	Q2, [x2, #6192]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #48]
	ldr	Q1, [x1, #64]
	ldr	Q2, [x2, #64]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1088]
	ldr	Q2, [x2, #1088]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2112]
	ldr	Q2, [x2, #2112]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3136]
	ldr	Q2, [x2, #3136]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4160]
	ldr	Q2, [x2, #4160]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5184]
	ldr	Q2, [x2, #5184]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6208]
	ldr	Q2, [x2, #6208]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #64]
	ldr	Q1, [x1, #80]
	ldr	Q2, [x2, #80]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1104]
	ldr	Q2, [x2, #1104]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2128]
	ldr	Q2, [x2, #2128]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3152]
	ldr	Q2, [x2, #3152]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4176]
	ldr	Q2, [x2, #4176]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5200]
	ldr	Q2, [x2, #5200]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6224]
	ldr	Q2, [x2, #6224]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #80]
	ldr	Q1, [x1, #96]
	ldr	Q2, [x2, #96]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1120]
	ldr	Q2, [x2, #1120]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2144]
	ldr	Q2, [x2, #2144]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3168]
	ldr	Q2, [x2, #3168]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4192]
	ldr	Q2, [x2, #4192]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5216]
	ldr	Q2, [x2, #5216]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6240]
	ldr	Q2, [x2, #6240]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #96]
	ldr	Q1, [x1, #112]
	ldr	Q2, [x2, #112]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1136]
	ldr	Q2, [x2, #1136]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2160]
	ldr	Q2, [x2, #2160]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3184]
	ldr	Q2, [x2, #3184]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4208]
	ldr	Q2, [x2, #4208]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5232]
	ldr	Q2, [x2, #5232]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6256]
	ldr	Q2, [x2, #6256]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #112]
	ldr	Q1, [x1, #128]
	ldr	Q2, [x2, #128]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1152]
	ldr	Q2, [x2, #1152]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2176]
	ldr	Q2, [x2, #2176]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3200]
	ldr	Q2, [x2, #3200]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4224]
	ldr	Q2, [x2, #4224]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5248]
	ldr	Q2, [x2, #5248]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6272]
	ldr	Q2, [x2, #6272]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #128]
	ldr	Q1, [x1, #144]
	ldr	Q2, [x2, #144]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1168]
	ldr	Q2, [x2, #1168]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2192]
	ldr	Q2, [x2, #2192]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3216]
	ldr	Q2, [x2, #3216]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4240]
	ldr	Q2, [x2, #4240]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5264]
	ldr	Q2, [x2, #5264]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6288]
	ldr	Q2, [x2, #6288]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #144]
	ldr	Q1, [x1, #160]
	ldr	Q2, [x2, #160]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1184]
	ldr	Q2, [x2, #1184]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2208]
	ldr	Q2, [x2, #2208]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3232]
	ldr	Q2, [x2, #3232]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4256]
	ldr	Q2, [x2, #4256]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5280]
	ldr	Q2, [x2, #5280]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6304]
	ldr	Q2, [x2, #6304]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #160]
	ldr	Q1, [x1, #176]
	ldr	Q2, [x2, #176]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1200]
	ldr	Q2, [x2, #1200]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2224]
	ldr	Q2, [x2, #2224]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3248]
	ldr	Q2, [x2, #3248]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4272]
	ldr	Q2, [x2, #4272]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5296]
	ldr	Q2, [x2, #5296]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6320]
	ldr	Q2, [x2, #6320]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #176]
	ldr	Q1, [x1, #192]
	ldr	Q2, [x2, #192]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1216]
	ldr	Q2, [x2, #1216]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2240]
	ldr	Q2, [x2, #2240]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3264]
	ldr	Q2, [x2, #3264]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4288]
	ldr	Q2, [x2, #4288]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5312]
	ldr	Q2, [x2, #5312]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6336]
	ldr	Q2, [x2, #6336]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #192]
	ldr	Q1, [x1, #208]
	ldr	Q2, [x2, #208]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1232]
	ldr	Q2, [x2, #1232]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2256]
	ldr	Q2, [x2, #2256]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3280]
	ldr	Q2, [x2, #3280]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4304]
	ldr	Q2, [x2, #4304]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5328]
	ldr	Q2, [x2, #5328]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6352]
	ldr	Q2, [x2, #6352]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #208]
	ldr	Q1, [x1, #224]
	ldr	Q2, [x2, #224]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1248]
	ldr	Q2, [x2, #1248]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2272]
	ldr	Q2, [x2, #2272]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3296]
	ldr	Q2, [x2, #3296]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4320]
	ldr	Q2, [x2, #4320]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5344]
	ldr	Q2, [x2, #5344]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6368]
	ldr	Q2, [x2, #6368]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #224]
	ldr	Q1, [x1, #240]
	ldr	Q2, [x2, #240]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1264]
	ldr	Q2, [x2, #1264]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2288]
	ldr	Q2, [x2, #2288]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3312]
	ldr	Q2, [x2, #3312]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4336]
	ldr	Q2, [x2, #4336]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5360]
	ldr	Q2, [x2, #5360]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6384]
	ldr	Q2, [x2, #6384]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #240]
	ldr	Q1, [x1, #256]
	ldr	Q2, [x2, #256]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1280]
	ldr	Q2, [x2, #1280]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2304]
	ldr	Q2, [x2, #2304]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3328]
	ldr	Q2, [x2, #3328]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4352]
	ldr	Q2, [x2, #4352]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5376]
	ldr	Q2, [x2, #5376]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6400]
	ldr	Q2, [x2, #6400]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #256]
	ldr	Q1, [x1, #272]
	ldr	Q2, [x2, #272]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1296]
	ldr	Q2, [x2, #1296]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2320]
	ldr	Q2, [x2, #2320]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3344]
	ldr	Q2, [x2, #3344]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4368]
	ldr	Q2, [x2, #4368]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5392]
	ldr	Q2, [x2, #5392]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6416]
	ldr	Q2, [x2, #6416]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #272]
	ldr	Q1, [x1, #288]
	ldr	Q2, [x2, #288]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1312]
	ldr	Q2, [x2, #1312]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2336]
	ldr	Q2, [x2, #2336]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3360]
	ldr	Q2, [x2, #3360]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4384]
	ldr	Q2, [x2, #4384]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5408]
	ldr	Q2, [x2, #5408]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6432]
	ldr	Q2, [x2, #6432]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #288]
	ldr	Q1, [x1, #304]
	ldr	Q2, [x2, #304]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1328]
	ldr	Q2, [x2, #1328]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2352]
	ldr	Q2, [x2, #2352]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3376]
	ldr	Q2, [x2, #3376]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4400]
	ldr	Q2, [x2, #4400]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5424]
	ldr	Q2, [x2, #5424]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6448]
	ldr	Q2, [x2, #6448]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #304]
	ldr	Q1, [x1, #320]
	ldr	Q2, [x2, #320]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1344]
	ldr	Q2, [x2, #1344]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2368]
	ldr	Q2, [x2, #2368]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3392]
	ldr	Q2, [x2, #3392]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4416]
	ldr	Q2, [x2, #4416]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5440]
	ldr	Q2, [x2, #5440]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6464]
	ldr	Q2, [x2, #6464]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #320]
	ldr	Q1, [x1, #336]
	ldr	Q2, [x2, #336]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1360]
	ldr	Q2, [x2, #1360]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2384]
	ldr	Q2, [x2, #2384]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3408]
	ldr	Q2, [x2, #3408]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4432]
	ldr	Q2, [x2, #4432]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5456]
	ldr	Q2, [x2, #5456]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6480]
	ldr	Q2, [x2, #6480]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #336]
	ldr	Q1, [x1, #352]
	ldr	Q2, [x2, #352]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1376]
	ldr	Q2, [x2, #1376]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2400]
	ldr	Q2, [x2, #2400]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3424]
	ldr	Q2, [x2, #3424]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4448]
	ldr	Q2, [x2, #4448]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5472]
	ldr	Q2, [x2, #5472]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6496]
	ldr	Q2, [x2, #6496]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #352]
	ldr	Q1, [x1, #368]
	ldr	Q2, [x2, #368]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1392]
	ldr	Q2, [x2, #1392]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2416]
	ldr	Q2, [x2, #2416]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3440]
	ldr	Q2, [x2, #3440]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4464]
	ldr	Q2, [x2, #4464]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5488]
	ldr	Q2, [x2, #5488]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6512]
	ldr	Q2, [x2, #6512]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #368]
	ldr	Q1, [x1, #384]
	ldr	Q2, [x2, #384]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1408]
	ldr	Q2, [x2, #1408]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2432]
	ldr	Q2, [x2, #2432]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3456]
	ldr	Q2, [x2, #3456]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4480]
	ldr	Q2, [x2, #4480]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5504]
	ldr	Q2, [x2, #5504]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6528]
	ldr	Q2, [x2, #6528]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #384]
	ldr	Q1, [x1, #400]
	ldr	Q2, [x2, #400]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1424]
	ldr	Q2, [x2, #1424]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2448]
	ldr	Q2, [x2, #2448]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3472]
	ldr	Q2, [x2, #3472]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4496]
	ldr	Q2, [x2, #4496]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5520]
	ldr	Q2, [x2, #5520]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6544]
	ldr	Q2, [x2, #6544]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #400]
	ldr	Q1, [x1, #416]
	ldr	Q2, [x2, #416]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1440]
	ldr	Q2, [x2, #1440]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2464]
	ldr	Q2, [x2, #2464]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3488]
	ldr	Q2, [x2, #3488]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4512]
	ldr	Q2, [x2, #4512]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5536]
	ldr	Q2, [x2, #5536]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6560]
	ldr	Q2, [x2, #6560]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #416]
	ldr	Q1, [x1, #432]
	ldr	Q2, [x2, #432]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1456]
	ldr	Q2, [x2, #1456]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2480]
	ldr	Q2, [x2, #2480]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3504]
	ldr	Q2, [x2, #3504]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4528]
	ldr	Q2, [x2, #4528]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5552]
	ldr	Q2, [x2, #5552]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6576]
	ldr	Q2, [x2, #6576]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #432]
	ldr	Q1, [x1, #448]
	ldr	Q2, [x2, #448]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1472]
	ldr	Q2, [x2, #1472]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2496]
	ldr	Q2, [x2, #2496]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3520]
	ldr	Q2, [x2, #3520]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4544]
	ldr	Q2, [x2, #4544]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5568]
	ldr	Q2, [x2, #5568]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6592]
	ldr	Q2, [x2, #6592]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #448]
	ldr	Q1, [x1, #464]
	ldr	Q2, [x2, #464]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1488]
	ldr	Q2, [x2, #1488]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2512]
	ldr	Q2, [x2, #2512]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3536]
	ldr	Q2, [x2, #3536]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4560]
	ldr	Q2, [x2, #4560]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5584]
	ldr	Q2, [x2, #5584]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6608]
	ldr	Q2, [x2, #6608]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #464]
	ldr	Q1, [x1, #480]
	ldr	Q2, [x2, #480]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1504]
	ldr	Q2, [x2, #1504]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2528]
	ldr	Q2, [x2, #2528]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3552]
	ldr	Q2, [x2, #3552]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4576]
	ldr	Q2, [x2, #4576]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5600]
	ldr	Q2, [x2, #5600]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6624]
	ldr	Q2, [x2, #6624]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #480]
	ldr	Q1, [x1, #496]
	ldr	Q2, [x2, #496]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1520]
	ldr	Q2, [x2, #1520]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2544]
	ldr	Q2, [x2, #2544]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3568]
	ldr	Q2, [x2, #3568]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4592]
	ldr	Q2, [x2, #4592]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5616]
	ldr	Q2, [x2, #5616]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6640]
	ldr	Q2, [x2, #6640]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #496]
	ldr	Q1, [x1, #512]
	ldr	Q2, [x2, #512]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1536]
	ldr	Q2, [x2, #1536]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2560]
	ldr	Q2, [x2, #2560]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3584]
	ldr	Q2, [x2, #3584]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4608]
	ldr	Q2, [x2, #4608]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5632]
	ldr	Q2, [x2, #5632]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6656]
	ldr	Q2, [x2, #6656]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #512]
	ldr	Q1, [x1, #528]
	ldr	Q2, [x2, #528]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1552]
	ldr	Q2, [x2, #1552]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2576]
	ldr	Q2, [x2, #2576]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3600]
	ldr	Q2, [x2, #3600]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4624]
	ldr	Q2, [x2, #4624]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5648]
	ldr	Q2, [x2, #5648]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6672]
	ldr	Q2, [x2, #6672]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #528]
	ldr	Q1, [x1, #544]
	ldr	Q2, [x2, #544]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1568]
	ldr	Q2, [x2, #1568]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2592]
	ldr	Q2, [x2, #2592]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3616]
	ldr	Q2, [x2, #3616]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4640]
	ldr	Q2, [x2, #4640]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5664]
	ldr	Q2, [x2, #5664]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6688]
	ldr	Q2, [x2, #6688]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #544]
	ldr	Q1, [x1, #560]
	ldr	Q2, [x2, #560]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1584]
	ldr	Q2, [x2, #1584]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2608]
	ldr	Q2, [x2, #2608]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3632]
	ldr	Q2, [x2, #3632]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4656]
	ldr	Q2, [x2, #4656]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5680]
	ldr	Q2, [x2, #5680]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6704]
	ldr	Q2, [x2, #6704]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #560]
	ldr	Q1, [x1, #576]
	ldr	Q2, [x2, #576]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1600]
	ldr	Q2, [x2, #1600]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2624]
	ldr	Q2, [x2, #2624]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3648]
	ldr	Q2, [x2, #3648]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4672]
	ldr	Q2, [x2, #4672]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5696]
	ldr	Q2, [x2, #5696]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6720]
	ldr	Q2, [x2, #6720]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #576]
	ldr	Q1, [x1, #592]
	ldr	Q2, [x2, #592]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1616]
	ldr	Q2, [x2, #1616]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2640]
	ldr	Q2, [x2, #2640]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3664]
	ldr	Q2, [x2, #3664]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4688]
	ldr	Q2, [x2, #4688]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5712]
	ldr	Q2, [x2, #5712]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6736]
	ldr	Q2, [x2, #6736]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #592]
	ldr	Q1, [x1, #608]
	ldr	Q2, [x2, #608]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1632]
	ldr	Q2, [x2, #1632]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2656]
	ldr	Q2, [x2, #2656]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3680]
	ldr	Q2, [x2, #3680]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4704]
	ldr	Q2, [x2, #4704]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5728]
	ldr	Q2, [x2, #5728]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6752]
	ldr	Q2, [x2, #6752]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #608]
	ldr	Q1, [x1, #624]
	ldr	Q2, [x2, #624]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1648]
	ldr	Q2, [x2, #1648]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2672]
	ldr	Q2, [x2, #2672]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3696]
	ldr	Q2, [x2, #3696]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4720]
	ldr	Q2, [x2, #4720]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5744]
	ldr	Q2, [x2, #5744]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6768]
	ldr	Q2, [x2, #6768]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #624]
	ldr	Q1, [x1, #640]
	ldr	Q2, [x2, #640]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1664]
	ldr	Q2, [x2, #1664]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2688]
	ldr	Q2, [x2, #2688]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3712]
	ldr	Q2, [x2, #3712]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4736]
	ldr	Q2, [x2, #4736]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5760]
	ldr	Q2, [x2, #5760]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6784]
	ldr	Q2, [x2, #6784]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #640]
	ldr	Q1, [x1, #656]
	ldr	Q2, [x2, #656]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1680]
	ldr	Q2, [x2, #1680]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2704]
	ldr	Q2, [x2, #2704]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3728]
	ldr	Q2, [x2, #3728]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4752]
	ldr	Q2, [x2, #4752]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5776]
	ldr	Q2, [x2, #5776]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6800]
	ldr	Q2, [x2, #6800]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #656]
	ldr	Q1, [x1, #672]
	ldr	Q2, [x2, #672]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1696]
	ldr	Q2, [x2, #1696]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2720]
	ldr	Q2, [x2, #2720]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3744]
	ldr	Q2, [x2, #3744]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4768]
	ldr	Q2, [x2, #4768]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5792]
	ldr	Q2, [x2, #5792]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6816]
	ldr	Q2, [x2, #6816]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #672]
	ldr	Q1, [x1, #688]
	ldr	Q2, [x2, #688]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1712]
	ldr	Q2, [x2, #1712]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2736]
	ldr	Q2, [x2, #2736]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3760]
	ldr	Q2, [x2, #3760]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4784]
	ldr	Q2, [x2, #4784]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5808]
	ldr	Q2, [x2, #5808]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6832]
	ldr	Q2, [x2, #6832]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #688]
	ldr	Q1, [x1, #704]
	ldr	Q2, [x2, #704]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1728]
	ldr	Q2, [x2, #1728]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2752]
	ldr	Q2, [x2, #2752]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3776]
	ldr	Q2, [x2, #3776]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4800]
	ldr	Q2, [x2, #4800]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5824]
	ldr	Q2, [x2, #5824]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6848]
	ldr	Q2, [x2, #6848]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #704]
	ldr	Q1, [x1, #720]
	ldr	Q2, [x2, #720]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1744]
	ldr	Q2, [x2, #1744]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2768]
	ldr	Q2, [x2, #2768]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3792]
	ldr	Q2, [x2, #3792]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4816]
	ldr	Q2, [x2, #4816]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5840]
	ldr	Q2, [x2, #5840]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6864]
	ldr	Q2, [x2, #6864]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #720]
	ldr	Q1, [x1, #736]
	ldr	Q2, [x2, #736]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1760]
	ldr	Q2, [x2, #1760]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2784]
	ldr	Q2, [x2, #2784]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3808]
	ldr	Q2, [x2, #3808]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4832]
	ldr	Q2, [x2, #4832]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5856]
	ldr	Q2, [x2, #5856]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6880]
	ldr	Q2, [x2, #6880]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #736]
	ldr	Q1, [x1, #752]
	ldr	Q2, [x2, #752]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1776]
	ldr	Q2, [x2, #1776]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2800]
	ldr	Q2, [x2, #2800]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3824]
	ldr	Q2, [x2, #3824]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4848]
	ldr	Q2, [x2, #4848]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5872]
	ldr	Q2, [x2, #5872]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6896]
	ldr	Q2, [x2, #6896]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #752]
	ldr	Q1, [x1, #768]
	ldr	Q2, [x2, #768]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1792]
	ldr	Q2, [x2, #1792]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2816]
	ldr	Q2, [x2, #2816]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3840]
	ldr	Q2, [x2, #3840]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4864]
	ldr	Q2, [x2, #4864]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5888]
	ldr	Q2, [x2, #5888]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6912]
	ldr	Q2, [x2, #6912]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #768]
	ldr	Q1, [x1, #784]
	ldr	Q2, [x2, #784]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1808]
	ldr	Q2, [x2, #1808]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2832]
	ldr	Q2, [x2, #2832]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3856]
	ldr	Q2, [x2, #3856]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4880]
	ldr	Q2, [x2, #4880]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5904]
	ldr	Q2, [x2, #5904]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6928]
	ldr	Q2, [x2, #6928]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #784]
	ldr	Q1, [x1, #800]
	ldr	Q2, [x2, #800]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1824]
	ldr	Q2, [x2, #1824]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2848]
	ldr	Q2, [x2, #2848]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3872]
	ldr	Q2, [x2, #3872]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4896]
	ldr	Q2, [x2, #4896]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5920]
	ldr	Q2, [x2, #5920]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6944]
	ldr	Q2, [x2, #6944]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #800]
	ldr	Q1, [x1, #816]
	ldr	Q2, [x2, #816]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1840]
	ldr	Q2, [x2, #1840]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2864]
	ldr	Q2, [x2, #2864]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3888]
	ldr	Q2, [x2, #3888]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4912]
	ldr	Q2, [x2, #4912]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5936]
	ldr	Q2, [x2, #5936]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6960]
	ldr	Q2, [x2, #6960]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #816]
	ldr	Q1, [x1, #832]
	ldr	Q2, [x2, #832]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1856]
	ldr	Q2, [x2, #1856]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2880]
	ldr	Q2, [x2, #2880]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3904]
	ldr	Q2, [x2, #3904]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4928]
	ldr	Q2, [x2, #4928]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5952]
	ldr	Q2, [x2, #5952]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6976]
	ldr	Q2, [x2, #6976]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #832]
	ldr	Q1, [x1, #848]
	ldr	Q2, [x2, #848]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1872]
	ldr	Q2, [x2, #1872]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2896]
	ldr	Q2, [x2, #2896]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3920]
	ldr	Q2, [x2, #3920]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4944]
	ldr	Q2, [x2, #4944]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5968]
	ldr	Q2, [x2, #5968]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6992]
	ldr	Q2, [x2, #6992]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #848]
	ldr	Q1, [x1, #864]
	ldr	Q2, [x2, #864]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1888]
	ldr	Q2, [x2, #1888]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2912]
	ldr	Q2, [x2, #2912]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3936]
	ldr	Q2, [x2, #3936]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4960]
	ldr	Q2, [x2, #4960]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5984]
	ldr	Q2, [x2, #5984]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #7008]
	ldr	Q2, [x2, #7008]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #864]
	ldr	Q1, [x1, #880]
	ldr	Q2, [x2, #880]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1904]
	ldr	Q2, [x2, #1904]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2928]
	ldr	Q2, [x2, #2928]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3952]
	ldr	Q2, [x2, #3952]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4976]
	ldr	Q2, [x2, #4976]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6000]
	ldr	Q2, [x2, #6000]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #7024]
	ldr	Q2, [x2, #7024]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #880]
	ldr	Q1, [x1, #896]
	ldr	Q2, [x2, #896]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1920]
	ldr	Q2, [x2, #1920]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2944]
	ldr	Q2, [x2, #2944]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3968]
	ldr	Q2, [x2, #3968]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4992]
	ldr	Q2, [x2, #4992]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6016]
	ldr	Q2, [x2, #6016]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #7040]
	ldr	Q2, [x2, #7040]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #896]
	ldr	Q1, [x1, #912]
	ldr	Q2, [x2, #912]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1936]
	ldr	Q2, [x2, #1936]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2960]
	ldr	Q2, [x2, #2960]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3984]
	ldr	Q2, [x2, #3984]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5008]
	ldr	Q2, [x2, #5008]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6032]
	ldr	Q2, [x2, #6032]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #7056]
	ldr	Q2, [x2, #7056]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #912]
	ldr	Q1, [x1, #928]
	ldr	Q2, [x2, #928]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1952]
	ldr	Q2, [x2, #1952]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2976]
	ldr	Q2, [x2, #2976]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4000]
	ldr	Q2, [x2, #4000]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5024]
	ldr	Q2, [x2, #5024]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6048]
	ldr	Q2, [x2, #6048]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #7072]
	ldr	Q2, [x2, #7072]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #928]
	ldr	Q1, [x1, #944]
	ldr	Q2, [x2, #944]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1968]
	ldr	Q2, [x2, #1968]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2992]
	ldr	Q2, [x2, #2992]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4016]
	ldr	Q2, [x2, #4016]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5040]
	ldr	Q2, [x2, #5040]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6064]
	ldr	Q2, [x2, #6064]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #7088]
	ldr	Q2, [x2, #7088]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #944]
	ldr	Q1, [x1, #960]
	ldr	Q2, [x2, #960]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #1984]
	ldr	Q2, [x2, #1984]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3008]
	ldr	Q2, [x2, #3008]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4032]
	ldr	Q2, [x2, #4032]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5056]
	ldr	Q2, [x2, #5056]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6080]
	ldr	Q2, [x2, #6080]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #7104]
	ldr	Q2, [x2, #7104]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #960]
	ldr	Q1, [x1, #976]
	ldr	Q2, [x2, #976]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2000]
	ldr	Q2, [x2, #2000]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3024]
	ldr	Q2, [x2, #3024]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4048]
	ldr	Q2, [x2, #4048]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5072]
	ldr	Q2, [x2, #5072]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6096]
	ldr	Q2, [x2, #6096]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #7120]
	ldr	Q2, [x2, #7120]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #976]
	ldr	Q1, [x1, #992]
	ldr	Q2, [x2, #992]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2016]
	ldr	Q2, [x2, #2016]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3040]
	ldr	Q2, [x2, #3040]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4064]
	ldr	Q2, [x2, #4064]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5088]
	ldr	Q2, [x2, #5088]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6112]
	ldr	Q2, [x2, #6112]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #7136]
	ldr	Q2, [x2, #7136]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #992]
	ldr	Q1, [x1, #1008]
	ldr	Q2, [x2, #1008]
	smull	V3.2D, V1.2S, V2.2S
	smull2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #2032]
	ldr	Q2, [x2, #2032]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #3056]
	ldr	Q2, [x2, #3056]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #4080]
	ldr	Q2, [x2, #4080]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #5104]
	ldr	Q2, [x2, #5104]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #6128]
	ldr	Q2, [x2, #6128]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	ldr	Q1, [x1, #7152]
	ldr	Q2, [x2, #7152]
	smlal	V3.2D, V1.2S, V2.2S
	smlal2	V4.2D, V1.4S, V2.4S
	uzp1	V5.4S, V3.4S, V4.4S
	mul	V5.4S, V5.4S, V0.S[1]
	smull	V6.2D, V5.2S, V0.S[0]
	smull2	V7.2D, V5.4S, V0.S[0]
	sub	V3.2D, V3.2D, V6.2D
	sub	V4.2D, V4.2D, V7.2D
	uzp2	V5.4S, V3.4S, V4.4S
	str	Q5, [x0, #1008]
	ret
	ENDP
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_aarch64_q
	DCD	0x007fe001, 0x007fe001, 0x007fe001, 0x007fe001
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_decode_eta_2_neon_idx
	DCB	0x00, 0xff, 0xff, 0xff, 0x00, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0xff, 0xff, 0x01, 0xff, 0xff, 0xff
	DCB	0x01, 0xff, 0xff, 0xff, 0x01, 0x02, 0xff, 0xff
	DCB	0x02, 0xff, 0xff, 0xff, 0x02, 0xff, 0xff, 0xff
	DCB	0x01, 0xff, 0xff, 0xff, 0x01, 0xff, 0xff, 0xff
	DCB	0x01, 0x02, 0xff, 0xff, 0x02, 0xff, 0xff, 0xff
	DCB	0x02, 0xff, 0xff, 0xff, 0x02, 0x03, 0xff, 0xff
	DCB	0x03, 0xff, 0xff, 0xff, 0x03, 0xff, 0xff, 0xff
	DCB	0x04, 0xff, 0xff, 0xff, 0x04, 0xff, 0xff, 0xff
	DCB	0x04, 0x05, 0xff, 0xff, 0x05, 0xff, 0xff, 0xff
	DCB	0x05, 0xff, 0xff, 0xff, 0x05, 0x06, 0xff, 0xff
	DCB	0x06, 0xff, 0xff, 0xff, 0x06, 0xff, 0xff, 0xff
	DCB	0x07, 0xff, 0xff, 0xff, 0x07, 0xff, 0xff, 0xff
	DCB	0x07, 0x08, 0xff, 0xff, 0x08, 0xff, 0xff, 0xff
	DCB	0x08, 0xff, 0xff, 0xff, 0x08, 0x09, 0xff, 0xff
	DCB	0x09, 0xff, 0xff, 0xff, 0x09, 0xff, 0xff, 0xff
	DCB	0x0a, 0xff, 0xff, 0xff, 0x0a, 0xff, 0xff, 0xff
	DCB	0x0a, 0x0b, 0xff, 0xff, 0x0b, 0xff, 0xff, 0xff
	DCB	0x0b, 0xff, 0xff, 0xff, 0x0b, 0x0c, 0xff, 0xff
	DCB	0x0c, 0xff, 0xff, 0xff, 0x0c, 0xff, 0xff, 0xff
	DCB	0x0d, 0xff, 0xff, 0xff, 0x0d, 0xff, 0xff, 0xff
	DCB	0x0d, 0x0e, 0xff, 0xff, 0x0e, 0xff, 0xff, 0xff
	DCB	0x0e, 0xff, 0xff, 0xff, 0x0e, 0x0f, 0xff, 0xff
	DCB	0x0f, 0xff, 0xff, 0xff, 0x0f, 0xff, 0xff, 0xff
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_decode_eta_2_neon_shift
	DCD	0x00000000, 0xfffffffd, 0xfffffffa, 0xffffffff
	DCD	0xfffffffc, 0xfffffff9, 0xfffffffe, 0xfffffffb
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_decode_eta_2_neon_mask
	DCD	0x00000007, 0x00000007, 0x00000007, 0x00000007
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_decode_eta_2_neon_konst
	DCD	0x00000002, 0x00000002, 0x00000002, 0x00000002
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mldsa_decode_eta_2_neon
mldsa_decode_eta_2_neon PROC
	stp	x29, x30, [sp, #-32]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	adrp	x2, L_mldsa_decode_eta_2_neon_idx
	add	x2, x2, L_mldsa_decode_eta_2_neon_idx
	adrp	x3, L_mldsa_decode_eta_2_neon_shift
	add	x3, x3, L_mldsa_decode_eta_2_neon_shift
	adrp	x4, L_mldsa_decode_eta_2_neon_mask
	add	x4, x4, L_mldsa_decode_eta_2_neon_mask
	adrp	x5, L_mldsa_decode_eta_2_neon_konst
	add	x5, x5, L_mldsa_decode_eta_2_neon_konst
	ldr	Q1, [x2]
	ldr	Q3, [x3]
	ldr	Q2, [x2, #16]
	ldr	Q4, [x3, #16]
	ldr	Q5, [x4]
	ldr	Q6, [x5]
	mov	x6, #27
L_mldsa_decode_eta_2_neon_loop
	ldr	Q0, [x0]
	tbl	V7.16B, {V0.16B}, V1.16B
	ushl	V7.4S, V7.4S, V3.4S
	and	V7.16B, V7.16B, V5.16B
	sub	V7.4S, V6.4S, V7.4S
	str	Q7, [x1]
	tbl	V8.16B, {V0.16B}, V2.16B
	ushl	V8.4S, V8.4S, V4.4S
	and	V8.16B, V8.16B, V5.16B
	sub	V8.4S, V6.4S, V8.4S
	str	Q8, [x1, #16]
	add	x0, x0, #3
	add	x1, x1, #32
	subs	x6, x6, #1
	bne	L_mldsa_decode_eta_2_neon_loop
	sub	x0, x0, #1
	ldr	Q0, [x0]
	ldr	Q1, [x2, #32]
	ldr	Q2, [x2, #48]
	tbl	V7.16B, {V0.16B}, V1.16B
	ushl	V7.4S, V7.4S, V3.4S
	and	V7.16B, V7.16B, V5.16B
	sub	V7.4S, V6.4S, V7.4S
	str	Q7, [x1]
	tbl	V8.16B, {V0.16B}, V2.16B
	ushl	V8.4S, V8.4S, V4.4S
	and	V8.16B, V8.16B, V5.16B
	sub	V8.4S, V6.4S, V8.4S
	str	Q8, [x1, #16]
	add	x1, x1, #32
	ldr	Q1, [x2, #64]
	ldr	Q2, [x2, #80]
	tbl	V7.16B, {V0.16B}, V1.16B
	ushl	V7.4S, V7.4S, V3.4S
	and	V7.16B, V7.16B, V5.16B
	sub	V7.4S, V6.4S, V7.4S
	str	Q7, [x1]
	tbl	V8.16B, {V0.16B}, V2.16B
	ushl	V8.4S, V8.4S, V4.4S
	and	V8.16B, V8.16B, V5.16B
	sub	V8.4S, V6.4S, V8.4S
	str	Q8, [x1, #16]
	add	x1, x1, #32
	ldr	Q1, [x2, #96]
	ldr	Q2, [x2, #112]
	tbl	V7.16B, {V0.16B}, V1.16B
	ushl	V7.4S, V7.4S, V3.4S
	and	V7.16B, V7.16B, V5.16B
	sub	V7.4S, V6.4S, V7.4S
	str	Q7, [x1]
	tbl	V8.16B, {V0.16B}, V2.16B
	ushl	V8.4S, V8.4S, V4.4S
	and	V8.16B, V8.16B, V5.16B
	sub	V8.4S, V6.4S, V8.4S
	str	Q8, [x1, #16]
	add	x1, x1, #32
	ldr	Q1, [x2, #128]
	ldr	Q2, [x2, #144]
	tbl	V7.16B, {V0.16B}, V1.16B
	ushl	V7.4S, V7.4S, V3.4S
	and	V7.16B, V7.16B, V5.16B
	sub	V7.4S, V6.4S, V7.4S
	str	Q7, [x1]
	tbl	V8.16B, {V0.16B}, V2.16B
	ushl	V8.4S, V8.4S, V4.4S
	and	V8.16B, V8.16B, V5.16B
	sub	V8.4S, V6.4S, V8.4S
	str	Q8, [x1, #16]
	add	x1, x1, #32
	ldr	Q1, [x2, #160]
	ldr	Q2, [x2, #176]
	tbl	V7.16B, {V0.16B}, V1.16B
	ushl	V7.4S, V7.4S, V3.4S
	and	V7.16B, V7.16B, V5.16B
	sub	V7.4S, V6.4S, V7.4S
	str	Q7, [x1]
	tbl	V8.16B, {V0.16B}, V2.16B
	ushl	V8.4S, V8.4S, V4.4S
	and	V8.16B, V8.16B, V5.16B
	sub	V8.4S, V6.4S, V8.4S
	str	Q8, [x1, #16]
	ldp	D8, D9, [x29, #16]
	ldp	x29, x30, [sp], #32
	ret
	ENDP
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_decode_eta_4_neon_idx
	DCB	0x00, 0xff, 0xff, 0xff, 0x00, 0xff, 0xff, 0xff
	DCB	0x01, 0xff, 0xff, 0xff, 0x01, 0xff, 0xff, 0xff
	DCB	0x02, 0xff, 0xff, 0xff, 0x02, 0xff, 0xff, 0xff
	DCB	0x03, 0xff, 0xff, 0xff, 0x03, 0xff, 0xff, 0xff
	DCB	0x04, 0xff, 0xff, 0xff, 0x04, 0xff, 0xff, 0xff
	DCB	0x05, 0xff, 0xff, 0xff, 0x05, 0xff, 0xff, 0xff
	DCB	0x06, 0xff, 0xff, 0xff, 0x06, 0xff, 0xff, 0xff
	DCB	0x07, 0xff, 0xff, 0xff, 0x07, 0xff, 0xff, 0xff
	DCB	0x08, 0xff, 0xff, 0xff, 0x08, 0xff, 0xff, 0xff
	DCB	0x09, 0xff, 0xff, 0xff, 0x09, 0xff, 0xff, 0xff
	DCB	0x0a, 0xff, 0xff, 0xff, 0x0a, 0xff, 0xff, 0xff
	DCB	0x0b, 0xff, 0xff, 0xff, 0x0b, 0xff, 0xff, 0xff
	DCB	0x0c, 0xff, 0xff, 0xff, 0x0c, 0xff, 0xff, 0xff
	DCB	0x0d, 0xff, 0xff, 0xff, 0x0d, 0xff, 0xff, 0xff
	DCB	0x0e, 0xff, 0xff, 0xff, 0x0e, 0xff, 0xff, 0xff
	DCB	0x0f, 0xff, 0xff, 0xff, 0x0f, 0xff, 0xff, 0xff
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_decode_eta_4_neon_shift
	DCD	0x00000000, 0xfffffffc, 0x00000000, 0xfffffffc
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_decode_eta_4_neon_mask
	DCD	0x0000000f, 0x0000000f, 0x0000000f, 0x0000000f
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_decode_eta_4_neon_konst
	DCD	0x00000004, 0x00000004, 0x00000004, 0x00000004
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mldsa_decode_eta_4_neon
mldsa_decode_eta_4_neon PROC
	adrp	x2, L_mldsa_decode_eta_4_neon_idx
	add	x2, x2, L_mldsa_decode_eta_4_neon_idx
	adrp	x3, L_mldsa_decode_eta_4_neon_shift
	add	x3, x3, L_mldsa_decode_eta_4_neon_shift
	adrp	x4, L_mldsa_decode_eta_4_neon_mask
	add	x4, x4, L_mldsa_decode_eta_4_neon_mask
	adrp	x5, L_mldsa_decode_eta_4_neon_konst
	add	x5, x5, L_mldsa_decode_eta_4_neon_konst
	ldr	Q1, [x2]
	ldr	Q2, [x3]
	ldr	Q3, [x4]
	ldr	Q4, [x5]
	mov	x6, #57
L_mldsa_decode_eta_4_neon_loop
	ldr	Q0, [x0]
	tbl	V5.16B, {V0.16B}, V1.16B
	ushl	V5.4S, V5.4S, V2.4S
	and	V5.16B, V5.16B, V3.16B
	sub	V5.4S, V4.4S, V5.4S
	str	Q5, [x1]
	add	x0, x0, #2
	add	x1, x1, #16
	subs	x6, x6, #1
	bne	L_mldsa_decode_eta_4_neon_loop
	sub	x0, x0, #2
	ldr	Q0, [x0]
	ldr	Q1, [x2, #16]
	tbl	V5.16B, {V0.16B}, V1.16B
	ushl	V5.4S, V5.4S, V2.4S
	and	V5.16B, V5.16B, V3.16B
	sub	V5.4S, V4.4S, V5.4S
	str	Q5, [x1]
	add	x1, x1, #16
	ldr	Q1, [x2, #32]
	tbl	V5.16B, {V0.16B}, V1.16B
	ushl	V5.4S, V5.4S, V2.4S
	and	V5.16B, V5.16B, V3.16B
	sub	V5.4S, V4.4S, V5.4S
	str	Q5, [x1]
	add	x1, x1, #16
	ldr	Q1, [x2, #48]
	tbl	V5.16B, {V0.16B}, V1.16B
	ushl	V5.4S, V5.4S, V2.4S
	and	V5.16B, V5.16B, V3.16B
	sub	V5.4S, V4.4S, V5.4S
	str	Q5, [x1]
	add	x1, x1, #16
	ldr	Q1, [x2, #64]
	tbl	V5.16B, {V0.16B}, V1.16B
	ushl	V5.4S, V5.4S, V2.4S
	and	V5.16B, V5.16B, V3.16B
	sub	V5.4S, V4.4S, V5.4S
	str	Q5, [x1]
	add	x1, x1, #16
	ldr	Q1, [x2, #80]
	tbl	V5.16B, {V0.16B}, V1.16B
	ushl	V5.4S, V5.4S, V2.4S
	and	V5.16B, V5.16B, V3.16B
	sub	V5.4S, V4.4S, V5.4S
	str	Q5, [x1]
	add	x1, x1, #16
	ldr	Q1, [x2, #96]
	tbl	V5.16B, {V0.16B}, V1.16B
	ushl	V5.4S, V5.4S, V2.4S
	and	V5.16B, V5.16B, V3.16B
	sub	V5.4S, V4.4S, V5.4S
	str	Q5, [x1]
	add	x1, x1, #16
	ldr	Q1, [x2, #112]
	tbl	V5.16B, {V0.16B}, V1.16B
	ushl	V5.4S, V5.4S, V2.4S
	and	V5.16B, V5.16B, V3.16B
	sub	V5.4S, V4.4S, V5.4S
	str	Q5, [x1]
	ret
	ENDP
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_decode_t1_neon_idx
	DCB	0x00, 0x01, 0xff, 0xff, 0x01, 0x02, 0xff, 0xff
	DCB	0x02, 0x03, 0xff, 0xff, 0x03, 0x04, 0xff, 0xff
	DCB	0x01, 0x02, 0xff, 0xff, 0x02, 0x03, 0xff, 0xff
	DCB	0x03, 0x04, 0xff, 0xff, 0x04, 0x05, 0xff, 0xff
	DCB	0x06, 0x07, 0xff, 0xff, 0x07, 0x08, 0xff, 0xff
	DCB	0x08, 0x09, 0xff, 0xff, 0x09, 0x0a, 0xff, 0xff
	DCB	0x0b, 0x0c, 0xff, 0xff, 0x0c, 0x0d, 0xff, 0xff
	DCB	0x0d, 0x0e, 0xff, 0xff, 0x0e, 0x0f, 0xff, 0xff
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_decode_t1_neon_shift
	DCD	0x00000000, 0xfffffffe, 0xfffffffc, 0xfffffffa
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_decode_t1_neon_mask
	DCD	0x000003ff, 0x000003ff, 0x000003ff, 0x000003ff
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mldsa_decode_t1_neon
mldsa_decode_t1_neon PROC
	adrp	x2, L_mldsa_decode_t1_neon_idx
	add	x2, x2, L_mldsa_decode_t1_neon_idx
	adrp	x3, L_mldsa_decode_t1_neon_shift
	add	x3, x3, L_mldsa_decode_t1_neon_shift
	adrp	x4, L_mldsa_decode_t1_neon_mask
	add	x4, x4, L_mldsa_decode_t1_neon_mask
	ldr	Q1, [x2]
	ldr	Q2, [x3]
	ldr	Q3, [x4]
	mov	x5, #61
L_mldsa_decode_t1_neon_loop
	ldr	Q0, [x0]
	tbl	V4.16B, {V0.16B}, V1.16B
	ushl	V4.4S, V4.4S, V2.4S
	and	V4.16B, V4.16B, V3.16B
	shl	V4.4S, V4.4S, #13
	str	Q4, [x1]
	add	x0, x0, #5
	add	x1, x1, #16
	subs	x5, x5, #1
	bne	L_mldsa_decode_t1_neon_loop
	sub	x0, x0, #1
	ldr	Q0, [x0]
	ldr	Q1, [x2, #16]
	tbl	V4.16B, {V0.16B}, V1.16B
	ushl	V4.4S, V4.4S, V2.4S
	and	V4.16B, V4.16B, V3.16B
	shl	V4.4S, V4.4S, #13
	str	Q4, [x1]
	add	x1, x1, #16
	ldr	Q1, [x2, #32]
	tbl	V4.16B, {V0.16B}, V1.16B
	ushl	V4.4S, V4.4S, V2.4S
	and	V4.16B, V4.16B, V3.16B
	shl	V4.4S, V4.4S, #13
	str	Q4, [x1]
	add	x1, x1, #16
	ldr	Q1, [x2, #48]
	tbl	V4.16B, {V0.16B}, V1.16B
	ushl	V4.4S, V4.4S, V2.4S
	and	V4.16B, V4.16B, V3.16B
	shl	V4.4S, V4.4S, #13
	str	Q4, [x1]
	ret
	ENDP
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_decode_t0_neon_idx
	DCB	0x00, 0x01, 0xff, 0xff, 0x01, 0x02, 0x03, 0xff
	DCB	0x03, 0x04, 0xff, 0xff, 0x04, 0x05, 0x06, 0xff
	DCB	0x06, 0x07, 0x08, 0xff, 0x08, 0x09, 0xff, 0xff
	DCB	0x09, 0x0a, 0x0b, 0xff, 0x0b, 0x0c, 0xff, 0xff
	DCB	0x03, 0x04, 0xff, 0xff, 0x04, 0x05, 0x06, 0xff
	DCB	0x06, 0x07, 0xff, 0xff, 0x07, 0x08, 0x09, 0xff
	DCB	0x09, 0x0a, 0x0b, 0xff, 0x0b, 0x0c, 0xff, 0xff
	DCB	0x0c, 0x0d, 0x0e, 0xff, 0x0e, 0x0f, 0xff, 0xff
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_decode_t0_neon_shift
	DCD	0x00000000, 0xfffffffb, 0xfffffffe, 0xfffffff9
	DCD	0xfffffffc, 0xffffffff, 0xfffffffa, 0xfffffffd
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_decode_t0_neon_mask
	DCD	0x00001fff, 0x00001fff, 0x00001fff, 0x00001fff
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_decode_t0_neon_konst
	DCD	0x00001000, 0x00001000, 0x00001000, 0x00001000
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mldsa_decode_t0_neon
mldsa_decode_t0_neon PROC
	stp	x29, x30, [sp, #-32]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	adrp	x2, L_mldsa_decode_t0_neon_idx
	add	x2, x2, L_mldsa_decode_t0_neon_idx
	adrp	x3, L_mldsa_decode_t0_neon_shift
	add	x3, x3, L_mldsa_decode_t0_neon_shift
	adrp	x4, L_mldsa_decode_t0_neon_mask
	add	x4, x4, L_mldsa_decode_t0_neon_mask
	adrp	x5, L_mldsa_decode_t0_neon_konst
	add	x5, x5, L_mldsa_decode_t0_neon_konst
	ldr	Q1, [x2]
	ldr	Q3, [x3]
	ldr	Q2, [x2, #16]
	ldr	Q4, [x3, #16]
	ldr	Q5, [x4]
	ldr	Q6, [x5]
	mov	x6, #31
L_mldsa_decode_t0_neon_loop
	ldr	Q0, [x0]
	tbl	V7.16B, {V0.16B}, V1.16B
	ushl	V7.4S, V7.4S, V3.4S
	and	V7.16B, V7.16B, V5.16B
	sub	V7.4S, V6.4S, V7.4S
	str	Q7, [x1]
	tbl	V8.16B, {V0.16B}, V2.16B
	ushl	V8.4S, V8.4S, V4.4S
	and	V8.16B, V8.16B, V5.16B
	sub	V8.4S, V6.4S, V8.4S
	str	Q8, [x1, #16]
	add	x0, x0, #13
	add	x1, x1, #32
	subs	x6, x6, #1
	bne	L_mldsa_decode_t0_neon_loop
	sub	x0, x0, #3
	ldr	Q0, [x0]
	ldr	Q1, [x2, #32]
	ldr	Q2, [x2, #48]
	tbl	V7.16B, {V0.16B}, V1.16B
	ushl	V7.4S, V7.4S, V3.4S
	and	V7.16B, V7.16B, V5.16B
	sub	V7.4S, V6.4S, V7.4S
	str	Q7, [x1]
	tbl	V8.16B, {V0.16B}, V2.16B
	ushl	V8.4S, V8.4S, V4.4S
	and	V8.16B, V8.16B, V5.16B
	sub	V8.4S, V6.4S, V8.4S
	str	Q8, [x1, #16]
	ldp	D8, D9, [x29, #16]
	ldp	x29, x30, [sp], #32
	ret
	ENDP
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_decode_gamma1_17_neon_idx
	DCB	0x00, 0x01, 0x02, 0xff, 0x02, 0x03, 0x04, 0xff
	DCB	0x04, 0x05, 0x06, 0xff, 0x06, 0x07, 0x08, 0xff
	DCB	0x07, 0x08, 0x09, 0xff, 0x09, 0x0a, 0x0b, 0xff
	DCB	0x0b, 0x0c, 0x0d, 0xff, 0x0d, 0x0e, 0x0f, 0xff
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_decode_gamma1_17_neon_shift
	DCD	0x00000000, 0xfffffffe, 0xfffffffc, 0xfffffffa
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_decode_gamma1_17_neon_mask
	DCD	0x0003ffff, 0x0003ffff, 0x0003ffff, 0x0003ffff
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_decode_gamma1_17_neon_konst
	DCD	0x00020000, 0x00020000, 0x00020000, 0x00020000
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mldsa_decode_gamma1_17_neon
mldsa_decode_gamma1_17_neon PROC
	adrp	x2, L_mldsa_decode_gamma1_17_neon_idx
	add	x2, x2, L_mldsa_decode_gamma1_17_neon_idx
	adrp	x3, L_mldsa_decode_gamma1_17_neon_shift
	add	x3, x3, L_mldsa_decode_gamma1_17_neon_shift
	adrp	x4, L_mldsa_decode_gamma1_17_neon_mask
	add	x4, x4, L_mldsa_decode_gamma1_17_neon_mask
	adrp	x5, L_mldsa_decode_gamma1_17_neon_konst
	add	x5, x5, L_mldsa_decode_gamma1_17_neon_konst
	ldr	Q1, [x2]
	ldr	Q2, [x3]
	ldr	Q3, [x4]
	ldr	Q4, [x5]
	mov	x6, #63
L_mldsa_decode_gamma1_17_neon_loop
	ldr	Q0, [x0]
	tbl	V5.16B, {V0.16B}, V1.16B
	ushl	V5.4S, V5.4S, V2.4S
	and	V5.16B, V5.16B, V3.16B
	sub	V5.4S, V4.4S, V5.4S
	str	Q5, [x1]
	add	x0, x0, #9
	add	x1, x1, #16
	subs	x6, x6, #1
	bne	L_mldsa_decode_gamma1_17_neon_loop
	sub	x0, x0, #7
	ldr	Q0, [x0]
	ldr	Q1, [x2, #16]
	tbl	V5.16B, {V0.16B}, V1.16B
	ushl	V5.4S, V5.4S, V2.4S
	and	V5.16B, V5.16B, V3.16B
	sub	V5.4S, V4.4S, V5.4S
	str	Q5, [x1]
	ret
	ENDP
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_decode_gamma1_19_neon_idx
	DCB	0x00, 0x01, 0x02, 0xff, 0x02, 0x03, 0x04, 0xff
	DCB	0x05, 0x06, 0x07, 0xff, 0x07, 0x08, 0x09, 0xff
	DCB	0x06, 0x07, 0x08, 0xff, 0x08, 0x09, 0x0a, 0xff
	DCB	0x0b, 0x0c, 0x0d, 0xff, 0x0d, 0x0e, 0x0f, 0xff
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_decode_gamma1_19_neon_shift
	DCD	0x00000000, 0xfffffffc, 0x00000000, 0xfffffffc
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_decode_gamma1_19_neon_mask
	DCD	0x000fffff, 0x000fffff, 0x000fffff, 0x000fffff
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_decode_gamma1_19_neon_konst
	DCD	0x00080000, 0x00080000, 0x00080000, 0x00080000
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mldsa_decode_gamma1_19_neon
mldsa_decode_gamma1_19_neon PROC
	adrp	x2, L_mldsa_decode_gamma1_19_neon_idx
	add	x2, x2, L_mldsa_decode_gamma1_19_neon_idx
	adrp	x3, L_mldsa_decode_gamma1_19_neon_shift
	add	x3, x3, L_mldsa_decode_gamma1_19_neon_shift
	adrp	x4, L_mldsa_decode_gamma1_19_neon_mask
	add	x4, x4, L_mldsa_decode_gamma1_19_neon_mask
	adrp	x5, L_mldsa_decode_gamma1_19_neon_konst
	add	x5, x5, L_mldsa_decode_gamma1_19_neon_konst
	ldr	Q1, [x2]
	ldr	Q2, [x3]
	ldr	Q3, [x4]
	ldr	Q4, [x5]
	mov	x6, #63
L_mldsa_decode_gamma1_19_neon_loop
	ldr	Q0, [x0]
	tbl	V5.16B, {V0.16B}, V1.16B
	ushl	V5.4S, V5.4S, V2.4S
	and	V5.16B, V5.16B, V3.16B
	sub	V5.4S, V4.4S, V5.4S
	str	Q5, [x1]
	add	x0, x0, #10
	add	x1, x1, #16
	subs	x6, x6, #1
	bne	L_mldsa_decode_gamma1_19_neon_loop
	sub	x0, x0, #6
	ldr	Q0, [x0]
	ldr	Q1, [x2, #16]
	tbl	V5.16B, {V0.16B}, V1.16B
	ushl	V5.4S, V5.4S, V2.4S
	and	V5.16B, V5.16B, V3.16B
	sub	V5.4S, V4.4S, V5.4S
	str	Q5, [x1]
	ret
	ENDP
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_encode_w1_88_neon_idx
	DCB	0x00, 0x01, 0x02, 0x04, 0x05, 0x06, 0x08, 0x09
	DCB	0x0a, 0x0c, 0x0d, 0x0e, 0xff, 0xff, 0xff, 0xff
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mldsa_encode_w1_88_neon
mldsa_encode_w1_88_neon PROC
	stp	x29, x30, [sp, #-32]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	adrp	x2, L_mldsa_encode_w1_88_neon_idx
	add	x2, x2, L_mldsa_encode_w1_88_neon_idx
	ldr	Q8, [x2]
	mov	x3, #16
L_mldsa_encode_w1_88_neon_loop
	ldr	Q0, [x0]
	ldr	Q1, [x0, #16]
	ldr	Q2, [x0, #32]
	ldr	Q3, [x0, #48]
	uzp1	V4.4S, V0.4S, V1.4S
	uzp2	V7.4S, V0.4S, V1.4S
	sli	V4.4S, V7.4S, #6
	uzp1	V5.4S, V2.4S, V3.4S
	uzp2	V7.4S, V2.4S, V3.4S
	sli	V5.4S, V7.4S, #6
	uzp1	V6.4S, V4.4S, V5.4S
	uzp2	V7.4S, V4.4S, V5.4S
	sli	V6.4S, V7.4S, #12
	tbl	V9.16B, {V6.16B}, V8.16B
	str	D9, [x1]
	ext8	V9.16B, V9.16B, V9.16B, #8
	str	S9, [x1, #8]
	add	x0, x0, #0x40
	add	x1, x1, #12
	subs	x3, x3, #1
	bne	L_mldsa_encode_w1_88_neon_loop
	ldp	D8, D9, [x29, #16]
	ldp	x29, x30, [sp], #32
	ret
	ENDP
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_encode_w1_32_neon_idx
	DCB	0x00, 0x04, 0x08, 0x0c, 0x10, 0x14, 0x18, 0x1c
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mldsa_encode_w1_32_neon
mldsa_encode_w1_32_neon PROC
	stp	x29, x30, [sp, #-32]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	adrp	x2, L_mldsa_encode_w1_32_neon_idx
	add	x2, x2, L_mldsa_encode_w1_32_neon_idx
	ldr	Q8, [x2]
	mov	x3, #16
L_mldsa_encode_w1_32_neon_loop
	ldr	Q0, [x0]
	ldr	Q1, [x0, #16]
	ldr	Q2, [x0, #32]
	ldr	Q3, [x0, #48]
	uzp1	V4.4S, V0.4S, V1.4S
	uzp2	V7.4S, V0.4S, V1.4S
	sli	V4.4S, V7.4S, #4
	uzp1	V5.4S, V2.4S, V3.4S
	uzp2	V7.4S, V2.4S, V3.4S
	sli	V5.4S, V7.4S, #4
	tbl	V9.16B, {V4.16B, V5.16B}, V8.16B
	str	D9, [x1]
	add	x0, x0, #0x40
	add	x1, x1, #8
	subs	x3, x3, #1
	bne	L_mldsa_encode_w1_32_neon_loop
	ldp	D8, D9, [x29, #16]
	ldp	x29, x30, [sp], #32
	ret
	ENDP
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_encode_gamma1_17_neon_idx
	DCB	0x00, 0x01, 0x02, 0xff, 0x08, 0x09, 0x0a, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0x04, 0x05, 0x06, 0xff, 0x0c, 0x0d
	DCB	0x0e, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_encode_gamma1_17_neon_shift
	DCD	0x00000000, 0x00000002, 0x00000004, 0x00000006
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_encode_gamma1_17_neon_gam
	DCD	0x00020000, 0x00020000, 0x00020000, 0x00020000
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mldsa_encode_gamma1_17_neon
mldsa_encode_gamma1_17_neon PROC
	adrp	x2, L_mldsa_encode_gamma1_17_neon_idx
	add	x2, x2, L_mldsa_encode_gamma1_17_neon_idx
	adrp	x3, L_mldsa_encode_gamma1_17_neon_shift
	add	x3, x3, L_mldsa_encode_gamma1_17_neon_shift
	adrp	x4, L_mldsa_encode_gamma1_17_neon_gam
	add	x4, x4, L_mldsa_encode_gamma1_17_neon_gam
	ldr	Q3, [x2]
	ldr	Q4, [x2, #16]
	ldr	Q1, [x3]
	ldr	Q2, [x4]
	mov	x5, #0x40
L_mldsa_encode_gamma1_17_neon_loop
	ldr	Q0, [x0]
	sub	V0.4S, V2.4S, V0.4S
	ushl	V0.4S, V0.4S, V1.4S
	tbl	V5.16B, {V0.16B}, V3.16B
	tbl	V6.16B, {V0.16B}, V4.16B
	orr	V5.16B, V5.16B, V6.16B
	str	D5, [x1]
	ext8	V5.16B, V5.16B, V5.16B, #8
	str	B5, [x1, #8]
	add	x0, x0, #16
	add	x1, x1, #9
	subs	x5, x5, #1
	bne	L_mldsa_encode_gamma1_17_neon_loop
	ret
	ENDP
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_encode_gamma1_19_neon_idx
	DCB	0x00, 0x01, 0x02, 0xff, 0xff, 0x08, 0x09, 0x0a
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0x04, 0x05, 0x06, 0xff, 0xff, 0x0c
	DCB	0x0d, 0x0e, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_encode_gamma1_19_neon_shift
	DCD	0x00000000, 0x00000004, 0x00000000, 0x00000004
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_encode_gamma1_19_neon_gam
	DCD	0x00080000, 0x00080000, 0x00080000, 0x00080000
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mldsa_encode_gamma1_19_neon
mldsa_encode_gamma1_19_neon PROC
	adrp	x2, L_mldsa_encode_gamma1_19_neon_idx
	add	x2, x2, L_mldsa_encode_gamma1_19_neon_idx
	adrp	x3, L_mldsa_encode_gamma1_19_neon_shift
	add	x3, x3, L_mldsa_encode_gamma1_19_neon_shift
	adrp	x4, L_mldsa_encode_gamma1_19_neon_gam
	add	x4, x4, L_mldsa_encode_gamma1_19_neon_gam
	ldr	Q3, [x2]
	ldr	Q4, [x2, #16]
	ldr	Q1, [x3]
	ldr	Q2, [x4]
	mov	x5, #0x40
L_mldsa_encode_gamma1_19_neon_loop
	ldr	Q0, [x0]
	sub	V0.4S, V2.4S, V0.4S
	ushl	V0.4S, V0.4S, V1.4S
	tbl	V5.16B, {V0.16B}, V3.16B
	tbl	V6.16B, {V0.16B}, V4.16B
	orr	V5.16B, V5.16B, V6.16B
	str	D5, [x1]
	ext8	V5.16B, V5.16B, V5.16B, #8
	str	H5, [x1, #8]
	add	x0, x0, #16
	add	x1, x1, #10
	subs	x5, x5, #1
	bne	L_mldsa_encode_gamma1_19_neon_loop
	ret
	ENDP
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mldsa_vec_check_low_neon
mldsa_vec_check_low_neon PROC
	stp	x29, x30, [sp, #-64]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	stp	D10, D11, [x29, #32]
	stp	D12, D13, [x29, #48]
	dup	V0.4S, w2
	eor	V1.16B, V1.16B, V1.16B
	eor	V2.16B, V2.16B, V2.16B
	eor	V3.16B, V3.16B, V3.16B
	eor	V4.16B, V4.16B, V4.16B
L_mldsa_vec_check_low_outer
	mov	x3, #16
L_mldsa_vec_check_low_inner
	ldr	Q5, [x0]
	ldr	Q6, [x0, #16]
	ldr	Q7, [x0, #32]
	ldr	Q8, [x0, #48]
	sqabs	V9.4S, V5.4S
	cmge	V9.4S, V9.4S, V0.4S
	orr	V1.16B, V1.16B, V9.16B
	sqabs	V10.4S, V6.4S
	cmge	V10.4S, V10.4S, V0.4S
	orr	V2.16B, V2.16B, V10.16B
	sqabs	V11.4S, V7.4S
	cmge	V11.4S, V11.4S, V0.4S
	orr	V3.16B, V3.16B, V11.16B
	sqabs	V12.4S, V8.4S
	cmge	V12.4S, V12.4S, V0.4S
	orr	V4.16B, V4.16B, V12.16B
	add	x0, x0, #0x40
	subs	x3, x3, #1
	bne	L_mldsa_vec_check_low_inner
	subs	w1, w1, #1
	bne	L_mldsa_vec_check_low_outer
	orr	V1.16B, V1.16B, V2.16B
	orr	V3.16B, V3.16B, V4.16B
	orr	V1.16B, V1.16B, V3.16B
	umaxv	S1, V1.4S
	mov	w4, V1.S[0]
	cmp	w4, #0
	cset	w4, eq
	mov	x0, x4
	ldp	D8, D9, [x29, #16]
	ldp	D10, D11, [x29, #32]
	ldp	D12, D13, [x29, #48]
	ldp	x29, x30, [sp], #0x40
	ret
	ENDP
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mldsa_poly_add_neon
mldsa_poly_add_neon PROC
	mov	x2, #16
L_mldsa_poly_add_neon_loop
	ldr	Q0, [x0]
	ldr	Q4, [x1]
	ldr	Q1, [x0, #16]
	ldr	Q5, [x1, #16]
	ldr	Q2, [x0, #32]
	ldr	Q6, [x1, #32]
	ldr	Q3, [x0, #48]
	ldr	Q7, [x1, #48]
	add	V0.4S, V0.4S, V4.4S
	add	V1.4S, V1.4S, V5.4S
	add	V2.4S, V2.4S, V6.4S
	add	V3.4S, V3.4S, V7.4S
	str	Q0, [x0]
	str	Q1, [x0, #16]
	str	Q2, [x0, #32]
	str	Q3, [x0, #48]
	add	x0, x0, #0x40
	add	x1, x1, #0x40
	subs	x2, x2, #1
	bne	L_mldsa_poly_add_neon_loop
	ret
	ENDP
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mldsa_poly_sub_neon
mldsa_poly_sub_neon PROC
	mov	x2, #16
L_mldsa_poly_sub_neon_loop
	ldr	Q0, [x0]
	ldr	Q4, [x1]
	ldr	Q1, [x0, #16]
	ldr	Q5, [x1, #16]
	ldr	Q2, [x0, #32]
	ldr	Q6, [x1, #32]
	ldr	Q3, [x0, #48]
	ldr	Q7, [x1, #48]
	sub	V0.4S, V0.4S, V4.4S
	sub	V1.4S, V1.4S, V5.4S
	sub	V2.4S, V2.4S, V6.4S
	sub	V3.4S, V3.4S, V7.4S
	str	Q0, [x0]
	str	Q1, [x0, #16]
	str	Q2, [x0, #32]
	str	Q3, [x0, #48]
	add	x0, x0, #0x40
	add	x1, x1, #0x40
	subs	x2, x2, #1
	bne	L_mldsa_poly_sub_neon_loop
	ret
	ENDP
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_poly_make_pos_neon_q
	DCD	0x007fe001, 0x007fe001, 0x007fe001, 0x007fe001
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mldsa_poly_make_pos_neon
mldsa_poly_make_pos_neon PROC
	stp	x29, x30, [sp, #-32]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	adrp	x1, L_mldsa_poly_make_pos_neon_q
	add	x1, x1, L_mldsa_poly_make_pos_neon_q
	ldr	Q0, [x1]
	mov	x2, #16
L_mldsa_poly_make_pos_neon_loop
	ldr	Q1, [x0]
	ldr	Q2, [x0, #16]
	ldr	Q3, [x0, #32]
	ldr	Q4, [x0, #48]
	sshr	V5.4S, V1.4S, #31
	mls	V1.4S, V5.4S, V0.4S
	sshr	V6.4S, V2.4S, #31
	mls	V2.4S, V6.4S, V0.4S
	sshr	V7.4S, V3.4S, #31
	mls	V3.4S, V7.4S, V0.4S
	sshr	V8.4S, V4.4S, #31
	mls	V4.4S, V8.4S, V0.4S
	str	Q1, [x0]
	str	Q2, [x0, #16]
	str	Q3, [x0, #32]
	str	Q4, [x0, #48]
	add	x0, x0, #0x40
	subs	x2, x2, #1
	bne	L_mldsa_poly_make_pos_neon_loop
	ldp	D8, D9, [x29, #16]
	ldp	x29, x30, [sp], #32
	ret
	ENDP
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_poly_red_neon_q
	DCD	0x007fe001, 0x007fe001, 0x007fe001, 0x007fe001
	DCD	0x00400000, 0x00400000, 0x00400000, 0x00400000
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mldsa_poly_red_neon
mldsa_poly_red_neon PROC
	stp	x29, x30, [sp, #-32]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	adrp	x1, L_mldsa_poly_red_neon_q
	add	x1, x1, L_mldsa_poly_red_neon_q
	ldr	Q0, [x1]
	ldr	Q1, [x1, #16]
	mov	x2, #16
L_mldsa_poly_red_neon_loop
	ldr	Q2, [x0]
	ldr	Q3, [x0, #16]
	ldr	Q4, [x0, #32]
	ldr	Q5, [x0, #48]
	add	V6.4S, V2.4S, V1.4S
	sshr	V6.4S, V6.4S, #23
	mls	V2.4S, V6.4S, V0.4S
	add	V7.4S, V3.4S, V1.4S
	sshr	V7.4S, V7.4S, #23
	mls	V3.4S, V7.4S, V0.4S
	add	V8.4S, V4.4S, V1.4S
	sshr	V8.4S, V8.4S, #23
	mls	V4.4S, V8.4S, V0.4S
	add	V9.4S, V5.4S, V1.4S
	sshr	V9.4S, V9.4S, #23
	mls	V5.4S, V9.4S, V0.4S
	str	Q2, [x0]
	str	Q3, [x0, #16]
	str	Q4, [x0, #32]
	str	Q5, [x0, #48]
	add	x0, x0, #0x40
	subs	x2, x2, #1
	bne	L_mldsa_poly_red_neon_loop
	ldp	D8, D9, [x29, #16]
	ldp	x29, x30, [sp], #32
	ret
	ENDP
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_extract_coeffs_eta2_neon_map
	DCB	0x02, 0x01, 0x00, 0xff, 0xfe, 0x02, 0x01, 0x00
	DCB	0xff, 0xfe, 0x02, 0x01, 0x00, 0xff, 0xfe, 0x00
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_extract_coeffs_eta2_neon_lim
	DCB	0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f
	DCB	0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_extract_coeffs_eta2_neon_bits
	DCD	0x00000001, 0x00000002, 0x00000004, 0x00000008
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_extract_coeffs_eta2_neon_idx
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x04, 0x05, 0x06, 0x07, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x08, 0x09, 0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
	DCB	0x08, 0x09, 0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff
	DCB	0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x0c, 0x0d, 0x0e, 0x0f
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x04, 0x05, 0x06, 0x07, 0x0c, 0x0d, 0x0e, 0x0f
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
	DCB	0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff
	DCB	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b
	DCB	0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff
	DCB	0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b
	DCB	0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
	DCB	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mldsa_extract_coeffs_eta2_neon
mldsa_extract_coeffs_eta2_neon PROC
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	stp	D10, D11, [x29, #32]
	stp	D12, D13, [x29, #48]
	stp	D14, D15, [x29, #64]
	adrp	x4, L_mldsa_extract_coeffs_eta2_neon_map
	add	x4, x4, L_mldsa_extract_coeffs_eta2_neon_map
	adrp	x5, L_mldsa_extract_coeffs_eta2_neon_lim
	add	x5, x5, L_mldsa_extract_coeffs_eta2_neon_lim
	adrp	x6, L_mldsa_extract_coeffs_eta2_neon_bits
	add	x6, x6, L_mldsa_extract_coeffs_eta2_neon_bits
	adrp	x7, L_mldsa_extract_coeffs_eta2_neon_idx
	add	x7, x7, L_mldsa_extract_coeffs_eta2_neon_idx
	ldr	Q2, [x4]
	ldr	Q0, [x5]
	ldr	Q1, [x6]
	ldr	w8, [x3]
	add	x2, x2, x8, lsl 2
L_mldsa_extract_coeffs_eta2_neon_wide
	subs	wzr, w1, #8
	blt	L_mldsa_extract_coeffs_eta2_neon_tail
	subs	wzr, w8, #0xf0
	bgt	L_mldsa_extract_coeffs_eta2_neon_tail
	ldr	D3, [x0]
	movi	V18.16B, #15
	ushr	V5.16B, V3.16B, #4
	and	V4.16B, V3.16B, V18.16B
	zip1	V3.16B, V4.16B, V5.16B
	tbl	V6.16B, {V2.16B}, V3.16B
	cmhi	V8.16B, V0.16B, V3.16B
	sxtl	V7.8H, V6.8B
	sxtl2	V18.8H, V6.16B
	sxtl	V10.4S, V7.4H
	sxtl2	V11.4S, V7.8H
	sxtl	V12.4S, V18.4H
	sxtl2	V13.4S, V18.8H
	sxtl	V9.8H, V8.8B
	sxtl2	V18.8H, V8.16B
	sxtl	V14.4S, V9.4H
	sxtl2	V15.4S, V9.8H
	sxtl	V16.4S, V18.4H
	sxtl2	V17.4S, V18.8H
	ushr	V18.4S, V14.4S, #31
	addv	S18, V18.4S
	mov	w10, V18.S[0]
	and	V18.16B, V14.16B, V1.16B
	addv	S18, V18.4S
	mov	w9, V18.S[0]
	lsl	x9, x9, #4
	ldr	Q18, [x7, x9]
	tbl	V10.16B, {V10.16B}, V18.16B
	str	Q10, [x2]
	add	x2, x2, x10, lsl 2
	add	x8, x8, x10
	ushr	V18.4S, V15.4S, #31
	addv	S18, V18.4S
	mov	w10, V18.S[0]
	and	V18.16B, V15.16B, V1.16B
	addv	S18, V18.4S
	mov	w9, V18.S[0]
	lsl	x9, x9, #4
	ldr	Q18, [x7, x9]
	tbl	V11.16B, {V11.16B}, V18.16B
	str	Q11, [x2]
	add	x2, x2, x10, lsl 2
	add	x8, x8, x10
	ushr	V18.4S, V16.4S, #31
	addv	S18, V18.4S
	mov	w10, V18.S[0]
	and	V18.16B, V16.16B, V1.16B
	addv	S18, V18.4S
	mov	w9, V18.S[0]
	lsl	x9, x9, #4
	ldr	Q18, [x7, x9]
	tbl	V12.16B, {V12.16B}, V18.16B
	str	Q12, [x2]
	add	x2, x2, x10, lsl 2
	add	x8, x8, x10
	ushr	V18.4S, V17.4S, #31
	addv	S18, V18.4S
	mov	w10, V18.S[0]
	and	V18.16B, V17.16B, V1.16B
	addv	S18, V18.4S
	mov	w9, V18.S[0]
	lsl	x9, x9, #4
	ldr	Q18, [x7, x9]
	tbl	V13.16B, {V13.16B}, V18.16B
	str	Q13, [x2]
	add	x2, x2, x10, lsl 2
	add	x8, x8, x10
	add	x0, x0, #8
	sub	w1, w1, #8
	b	L_mldsa_extract_coeffs_eta2_neon_wide
L_mldsa_extract_coeffs_eta2_neon_tail
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
L_mldsa_extract_coeffs_eta2_neon_skip_lo
	lsr	w12, w11, #4
	subs	wzr, w12, #15
	bcs	L_mldsa_extract_coeffs_eta2_neon_skip_hi
	ldrsb	w12, [x4, x12]
	str	w12, [x2]
	add	x2, x2, #4
	add	x8, x8, #1
L_mldsa_extract_coeffs_eta2_neon_skip_hi
	b	L_mldsa_extract_coeffs_eta2_neon_tail
L_mldsa_extract_coeffs_eta2_neon_done
	str	w8, [x3]
	ldp	D8, D9, [x29, #16]
	ldp	D10, D11, [x29, #32]
	ldp	D12, D13, [x29, #48]
	ldp	D14, D15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
	ENDP
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_extract_coeffs_eta4_neon_map
	DCB	0x04, 0x03, 0x02, 0x01, 0x00, 0xff, 0xfe, 0xfd
	DCB	0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_extract_coeffs_eta4_neon_lim
	DCB	0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09
	DCB	0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_extract_coeffs_eta4_neon_bits
	DCD	0x00000001, 0x00000002, 0x00000004, 0x00000008
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_extract_coeffs_eta4_neon_idx
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x04, 0x05, 0x06, 0x07, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x08, 0x09, 0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
	DCB	0x08, 0x09, 0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff
	DCB	0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x0c, 0x0d, 0x0e, 0x0f
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x04, 0x05, 0x06, 0x07, 0x0c, 0x0d, 0x0e, 0x0f
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
	DCB	0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff
	DCB	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b
	DCB	0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff
	DCB	0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b
	DCB	0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
	DCB	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mldsa_extract_coeffs_eta4_neon
mldsa_extract_coeffs_eta4_neon PROC
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	stp	D10, D11, [x29, #32]
	stp	D12, D13, [x29, #48]
	stp	D14, D15, [x29, #64]
	adrp	x4, L_mldsa_extract_coeffs_eta4_neon_map
	add	x4, x4, L_mldsa_extract_coeffs_eta4_neon_map
	adrp	x5, L_mldsa_extract_coeffs_eta4_neon_lim
	add	x5, x5, L_mldsa_extract_coeffs_eta4_neon_lim
	adrp	x6, L_mldsa_extract_coeffs_eta4_neon_bits
	add	x6, x6, L_mldsa_extract_coeffs_eta4_neon_bits
	adrp	x7, L_mldsa_extract_coeffs_eta4_neon_idx
	add	x7, x7, L_mldsa_extract_coeffs_eta4_neon_idx
	ldr	Q2, [x4]
	ldr	Q0, [x5]
	ldr	Q1, [x6]
	ldr	w8, [x3]
	add	x2, x2, x8, lsl 2
L_mldsa_extract_coeffs_eta4_neon_wide
	subs	wzr, w1, #8
	blt	L_mldsa_extract_coeffs_eta4_neon_tail
	subs	wzr, w8, #0xf0
	bgt	L_mldsa_extract_coeffs_eta4_neon_tail
	ldr	D3, [x0]
	movi	V18.16B, #15
	ushr	V5.16B, V3.16B, #4
	and	V4.16B, V3.16B, V18.16B
	zip1	V3.16B, V4.16B, V5.16B
	tbl	V6.16B, {V2.16B}, V3.16B
	cmhi	V8.16B, V0.16B, V3.16B
	sxtl	V7.8H, V6.8B
	sxtl2	V18.8H, V6.16B
	sxtl	V10.4S, V7.4H
	sxtl2	V11.4S, V7.8H
	sxtl	V12.4S, V18.4H
	sxtl2	V13.4S, V18.8H
	sxtl	V9.8H, V8.8B
	sxtl2	V18.8H, V8.16B
	sxtl	V14.4S, V9.4H
	sxtl2	V15.4S, V9.8H
	sxtl	V16.4S, V18.4H
	sxtl2	V17.4S, V18.8H
	ushr	V18.4S, V14.4S, #31
	addv	S18, V18.4S
	mov	w10, V18.S[0]
	and	V18.16B, V14.16B, V1.16B
	addv	S18, V18.4S
	mov	w9, V18.S[0]
	lsl	x9, x9, #4
	ldr	Q18, [x7, x9]
	tbl	V10.16B, {V10.16B}, V18.16B
	str	Q10, [x2]
	add	x2, x2, x10, lsl 2
	add	x8, x8, x10
	ushr	V18.4S, V15.4S, #31
	addv	S18, V18.4S
	mov	w10, V18.S[0]
	and	V18.16B, V15.16B, V1.16B
	addv	S18, V18.4S
	mov	w9, V18.S[0]
	lsl	x9, x9, #4
	ldr	Q18, [x7, x9]
	tbl	V11.16B, {V11.16B}, V18.16B
	str	Q11, [x2]
	add	x2, x2, x10, lsl 2
	add	x8, x8, x10
	ushr	V18.4S, V16.4S, #31
	addv	S18, V18.4S
	mov	w10, V18.S[0]
	and	V18.16B, V16.16B, V1.16B
	addv	S18, V18.4S
	mov	w9, V18.S[0]
	lsl	x9, x9, #4
	ldr	Q18, [x7, x9]
	tbl	V12.16B, {V12.16B}, V18.16B
	str	Q12, [x2]
	add	x2, x2, x10, lsl 2
	add	x8, x8, x10
	ushr	V18.4S, V17.4S, #31
	addv	S18, V18.4S
	mov	w10, V18.S[0]
	and	V18.16B, V17.16B, V1.16B
	addv	S18, V18.4S
	mov	w9, V18.S[0]
	lsl	x9, x9, #4
	ldr	Q18, [x7, x9]
	tbl	V13.16B, {V13.16B}, V18.16B
	str	Q13, [x2]
	add	x2, x2, x10, lsl 2
	add	x8, x8, x10
	add	x0, x0, #8
	sub	w1, w1, #8
	b	L_mldsa_extract_coeffs_eta4_neon_wide
L_mldsa_extract_coeffs_eta4_neon_tail
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
L_mldsa_extract_coeffs_eta4_neon_skip_lo
	lsr	w12, w11, #4
	subs	wzr, w12, #9
	bcs	L_mldsa_extract_coeffs_eta4_neon_skip_hi
	ldrsb	w12, [x4, x12]
	str	w12, [x2]
	add	x2, x2, #4
	add	x8, x8, #1
L_mldsa_extract_coeffs_eta4_neon_skip_hi
	b	L_mldsa_extract_coeffs_eta4_neon_tail
L_mldsa_extract_coeffs_eta4_neon_done
	str	w8, [x3]
	ldp	D8, D9, [x29, #16]
	ldp	D10, D11, [x29, #32]
	ldp	D12, D13, [x29, #48]
	ldp	D14, D15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
	ENDP
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_rej_uniform_mask
	DCD	0x007fffff, 0x007fffff, 0x007fffff, 0x007fffff
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_rej_uniform_shuffle0
	DCB	0x00, 0x01, 0x02, 0xff, 0x03, 0x04, 0x05, 0xff
	DCB	0x06, 0x07, 0x08, 0xff, 0x09, 0x0a, 0x0b, 0xff
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_rej_uniform_shuffle1
	DCB	0x0c, 0x0d, 0x0e, 0xff, 0x0f, 0x10, 0x11, 0xff
	DCB	0x12, 0x13, 0x14, 0xff, 0x15, 0x16, 0x17, 0xff
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_rej_uniform_bits
	DCD	0x00000001, 0x00000002, 0x00000004, 0x00000008
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_mldsa_rej_uniform_indices
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x04, 0x05, 0x06, 0x07, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x08, 0x09, 0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
	DCB	0x08, 0x09, 0x0a, 0x0b, 0xff, 0xff, 0xff, 0xff
	DCB	0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x0c, 0x0d, 0x0e, 0x0f
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x04, 0x05, 0x06, 0x07, 0x0c, 0x0d, 0x0e, 0x0f
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
	DCB	0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff
	DCB	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
	DCB	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b
	DCB	0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff
	DCB	0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b
	DCB	0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff
	DCB	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
	DCB	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	mldsa_rej_uniform_neon
mldsa_rej_uniform_neon PROC
	stp	x29, x30, [sp, #-64]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	stp	D10, D11, [x29, #32]
	stp	D12, D13, [x29, #48]
	adrp	x4, L_mldsa_rej_uniform_mask
	add	x4, x4, L_mldsa_rej_uniform_mask
	adrp	x5, L_mldsa_aarch64_q
	add	x5, x5, L_mldsa_aarch64_q
	adrp	x6, L_mldsa_rej_uniform_bits
	add	x6, x6, L_mldsa_rej_uniform_bits
	adrp	x7, L_mldsa_rej_uniform_indices
	add	x7, x7, L_mldsa_rej_uniform_indices
	adrp	x8, L_mldsa_rej_uniform_shuffle0
	add	x8, x8, L_mldsa_rej_uniform_shuffle0
	adrp	x9, L_mldsa_rej_uniform_shuffle1
	add	x9, x9, L_mldsa_rej_uniform_shuffle1
	movz	x15, #0xe001
	eor	V1.16B, V1.16B, V1.16B
	eor	V12.16B, V12.16B, V12.16B
	eor	V13.16B, V13.16B, V13.16B
	movk	x15, #0x7f, lsl 16
	eor	x14, x14, x14
	eor	V10.16B, V10.16B, V10.16B
	eor	V11.16B, V11.16B, V11.16B
	ldr	Q0, [x4]
	ldr	Q3, [x5]
	ldr	Q2, [x6]
	ldr	Q4, [x8]
	ldr	Q5, [x9]
	subs	wzr, w1, #0
	beq	L_mldsa_rej_uniform_done
	subs	wzr, w1, #16
	blt	L_mldsa_rej_uniform_loop_2
L_mldsa_rej_uniform_loop_8
	ldr	Q6, [x2]
	ldr	D7, [x2, #16]
	add	x2, x2, #24
	tbl	V8.16B, {V6.16B, V7.16B}, V4.16B
	tbl	V9.16B, {V6.16B, V7.16B}, V5.16B
	and	V6.16B, V8.16B, V0.16B
	and	V7.16B, V9.16B, V0.16B
	cmgt	V8.4S, V3.4S, V6.4S
	cmgt	V9.4S, V3.4S, V7.4S
	ushr	V12.4S, V8.4S, #31
	ushr	V13.4S, V9.4S, #31
	addv	S12, V12.4S
	addv	S13, V13.4S
	mov	x12, V12.D[0]
	mov	x13, V13.D[0]
	and	V10.16B, V8.16B, V2.16B
	and	V11.16B, V9.16B, V2.16B
	addv	S10, V10.4S
	addv	S11, V11.4S
	mov	w10, V10.S[0]
	mov	w11, V11.S[0]
	lsl	w10, w10, #4
	lsl	w11, w11, #4
	ldr	Q10, [x7, x10]
	ldr	Q11, [x7, x11]
	tbl	V8.16B, {V6.16B}, V10.16B
	tbl	V9.16B, {V7.16B}, V11.16B
	str	Q8, [x0]
	add	x0, x0, x12, lsl 2
	add	x14, x14, x12
	str	Q9, [x0]
	add	x0, x0, x13, lsl 2
	add	x14, x14, x13
	subs	w3, w3, #24
	beq	L_mldsa_rej_uniform_done
	sub	w12, w1, w14
	subs	x12, x12, #8
	blt	L_mldsa_rej_uniform_loop_2
	b	L_mldsa_rej_uniform_loop_8
L_mldsa_rej_uniform_loop_2
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
L_mldsa_rej_uniform_loop_lt_2
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
L_mldsa_rej_uniform_done
	mov	x0, x14
	ldp	D8, D9, [x29, #16]
	ldp	D10, D11, [x29, #32]
	ldp	D12, D13, [x29, #48]
	ldp	x29, x30, [sp], #0x40
	ret
	ENDP
	ENDIF
	END
