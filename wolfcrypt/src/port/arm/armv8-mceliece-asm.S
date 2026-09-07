/* armv8-mceliece-asm
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
 *   ruby ./mceliece/mceliece.rb arm64 \
 *       /home/sparki/wolfssl/github/mceliece/wolfssl/wolfcrypt/src/port/arm/armv8-mceliece-asm.S
 */

#define _WC_BUILDING_ARMV8_MCELIECE_ASM_S

#include <wolfssl/wolfcrypt/libwolfssl_sources_asm.h>

#ifdef WOLFSSL_ARMASM
#ifdef __aarch64__
#ifndef WOLFSSL_ARMASM_INLINE
#ifdef WOLFSSL_HAVE_MCELIECE
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mc_aff_powers_neon, %object
	.size	L_mc_aff_powers_neon, 13312
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 16-byte aligned, 128-bit aligned
#ifndef __APPLE__
	.align	4
#else
	.p2align	4
#endif /* __APPLE__ */
L_mc_aff_powers_neon:
	.quad	0x5aa55aa5a55aa55a,0x5aa55aa5a55aa55a
	.quad	0xa55aa55a5aa55aa5,0xa55aa55a5aa55aa5
	.quad	0x3cc33cc3c33cc33c,0xc33cc33c3cc33cc3
	.quad	0xc33cc33c3cc33cc3,0x3cc33cc3c33cc33c
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0xffff0000ffff0000,0x0000ffff0000ffff
	.quad	0x0000ffff0000ffff,0xffff0000ffff0000
	.quad	0x33cc33cc33cc33cc,0x33cc33cc33cc33cc
	.quad	0x33cc33cc33cc33cc,0x33cc33cc33cc33cc
	.quad	0xf00ff00f0ff00ff0,0x0ff00ff0f00ff00f
	.quad	0xf00ff00f0ff00ff0,0x0ff00ff0f00ff00f
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0x6969696996969696,0x6969696996969696
	.quad	0x6969696996969696,0x6969696996969696
	.quad	0x5a5a5a5a5a5a5a5a,0x5a5a5a5a5a5a5a5a
	.quad	0xa5a5a5a5a5a5a5a5,0xa5a5a5a5a5a5a5a5
	.quad	0xa5a5a5a55a5a5a5a,0xa5a5a5a55a5a5a5a
	.quad	0x5a5a5a5aa5a5a5a5,0x5a5a5a5aa5a5a5a5
	.quad	0xaaaa55555555aaaa,0x5555aaaaaaaa5555
	.quad	0xaaaa55555555aaaa,0x5555aaaaaaaa5555
	.quad	0x0ff00ff00ff00ff0,0xf00ff00ff00ff00f
	.quad	0x0ff00ff00ff00ff0,0xf00ff00ff00ff00f
	.quad	0x0f0ff0f00f0ff0f0,0xf0f00f0ff0f00f0f
	.quad	0xf0f00f0ff0f00f0f,0x0f0ff0f00f0ff0f0
	.quad	0xa55aa55a5aa55aa5,0xa55aa55a5aa55aa5
	.quad	0x5aa55aa5a55aa55a,0x5aa55aa5a55aa55a
	.quad	0x3cc33cc3c33cc33c,0xc33cc33c3cc33cc3
	.quad	0xc33cc33c3cc33cc3,0x3cc33cc3c33cc33c
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0x0000ffff0000ffff,0xffff0000ffff0000
	.quad	0xffff0000ffff0000,0x0000ffff0000ffff
	.quad	0xcc33cc33cc33cc33,0xcc33cc33cc33cc33
	.quad	0xcc33cc33cc33cc33,0xcc33cc33cc33cc33
	.quad	0xf00ff00f0ff00ff0,0x0ff00ff0f00ff00f
	.quad	0xf00ff00f0ff00ff0,0x0ff00ff0f00ff00f
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0x9696969669696969,0x9696969669696969
	.quad	0x9696969669696969,0x9696969669696969
	.quad	0x5a5a5a5a5a5a5a5a,0x5a5a5a5a5a5a5a5a
	.quad	0xa5a5a5a5a5a5a5a5,0xa5a5a5a5a5a5a5a5
	.quad	0x5a5a5a5aa5a5a5a5,0x5a5a5a5aa5a5a5a5
	.quad	0xa5a5a5a55a5a5a5a,0xa5a5a5a55a5a5a5a
	.quad	0xaaaa55555555aaaa,0x5555aaaaaaaa5555
	.quad	0xaaaa55555555aaaa,0x5555aaaaaaaa5555
	.quad	0xf00ff00ff00ff00f,0x0ff00ff00ff00ff0
	.quad	0xf00ff00ff00ff00f,0x0ff00ff00ff00ff0
	.quad	0x0f0ff0f00f0ff0f0,0xf0f00f0ff0f00f0f
	.quad	0xf0f00f0ff0f00f0f,0x0f0ff0f00f0ff0f0
	.quad	0x5aa55aa5a55aa55a,0x5aa55aa5a55aa55a
	.quad	0xa55aa55a5aa55aa5,0xa55aa55a5aa55aa5
	.quad	0xc33cc33c3cc33cc3,0x3cc33cc3c33cc33c
	.quad	0x3cc33cc3c33cc33c,0xc33cc33c3cc33cc3
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0x0000ffff0000ffff,0xffff0000ffff0000
	.quad	0xffff0000ffff0000,0x0000ffff0000ffff
	.quad	0xcc33cc33cc33cc33,0xcc33cc33cc33cc33
	.quad	0xcc33cc33cc33cc33,0xcc33cc33cc33cc33
	.quad	0xf00ff00f0ff00ff0,0x0ff00ff0f00ff00f
	.quad	0xf00ff00f0ff00ff0,0x0ff00ff0f00ff00f
	.quad	0x00000000ffffffff,0x00000000ffffffff
	.quad	0x00000000ffffffff,0x00000000ffffffff
	.quad	0x9696969669696969,0x9696969669696969
	.quad	0x9696969669696969,0x9696969669696969
	.quad	0xa5a5a5a5a5a5a5a5,0xa5a5a5a5a5a5a5a5
	.quad	0x5a5a5a5a5a5a5a5a,0x5a5a5a5a5a5a5a5a
	.quad	0xa5a5a5a55a5a5a5a,0xa5a5a5a55a5a5a5a
	.quad	0x5a5a5a5aa5a5a5a5,0x5a5a5a5aa5a5a5a5
	.quad	0x5555aaaaaaaa5555,0xaaaa55555555aaaa
	.quad	0x5555aaaaaaaa5555,0xaaaa55555555aaaa
	.quad	0x0ff00ff00ff00ff0,0xf00ff00ff00ff00f
	.quad	0x0ff00ff00ff00ff0,0xf00ff00ff00ff00f
	.quad	0x0f0ff0f00f0ff0f0,0xf0f00f0ff0f00f0f
	.quad	0xf0f00f0ff0f00f0f,0x0f0ff0f00f0ff0f0
	.quad	0xa55aa55a5aa55aa5,0xa55aa55a5aa55aa5
	.quad	0x5aa55aa5a55aa55a,0x5aa55aa5a55aa55a
	.quad	0xc33cc33c3cc33cc3,0x3cc33cc3c33cc33c
	.quad	0x3cc33cc3c33cc33c,0xc33cc33c3cc33cc3
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0xffff0000ffff0000,0x0000ffff0000ffff
	.quad	0x0000ffff0000ffff,0xffff0000ffff0000
	.quad	0x33cc33cc33cc33cc,0x33cc33cc33cc33cc
	.quad	0x33cc33cc33cc33cc,0x33cc33cc33cc33cc
	.quad	0xf00ff00f0ff00ff0,0x0ff00ff0f00ff00f
	.quad	0xf00ff00f0ff00ff0,0x0ff00ff0f00ff00f
	.quad	0x00000000ffffffff,0x00000000ffffffff
	.quad	0x00000000ffffffff,0x00000000ffffffff
	.quad	0x6969696996969696,0x6969696996969696
	.quad	0x6969696996969696,0x6969696996969696
	.quad	0xa5a5a5a5a5a5a5a5,0xa5a5a5a5a5a5a5a5
	.quad	0x5a5a5a5a5a5a5a5a,0x5a5a5a5a5a5a5a5a
	.quad	0x5a5a5a5aa5a5a5a5,0x5a5a5a5aa5a5a5a5
	.quad	0xa5a5a5a55a5a5a5a,0xa5a5a5a55a5a5a5a
	.quad	0x5555aaaaaaaa5555,0xaaaa55555555aaaa
	.quad	0x5555aaaaaaaa5555,0xaaaa55555555aaaa
	.quad	0xf00ff00ff00ff00f,0x0ff00ff00ff00ff0
	.quad	0xf00ff00ff00ff00f,0x0ff00ff00ff00ff0
	.quad	0x0f0ff0f00f0ff0f0,0xf0f00f0ff0f00f0f
	.quad	0xf0f00f0ff0f00f0f,0x0f0ff0f00f0ff0f0
	.quad	0x5aa55aa5a55aa55a,0x5aa55aa5a55aa55a
	.quad	0xa55aa55a5aa55aa5,0xa55aa55a5aa55aa5
	.quad	0x3cc33cc3c33cc33c,0xc33cc33c3cc33cc3
	.quad	0xc33cc33c3cc33cc3,0x3cc33cc3c33cc33c
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0xffff0000ffff0000,0x0000ffff0000ffff
	.quad	0x0000ffff0000ffff,0xffff0000ffff0000
	.quad	0x33cc33cc33cc33cc,0x33cc33cc33cc33cc
	.quad	0x33cc33cc33cc33cc,0x33cc33cc33cc33cc
	.quad	0x0ff00ff0f00ff00f,0xf00ff00f0ff00ff0
	.quad	0x0ff00ff0f00ff00f,0xf00ff00f0ff00ff0
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0x6969696996969696,0x6969696996969696
	.quad	0x6969696996969696,0x6969696996969696
	.quad	0xa5a5a5a5a5a5a5a5,0xa5a5a5a5a5a5a5a5
	.quad	0x5a5a5a5a5a5a5a5a,0x5a5a5a5a5a5a5a5a
	.quad	0xa5a5a5a55a5a5a5a,0xa5a5a5a55a5a5a5a
	.quad	0x5a5a5a5aa5a5a5a5,0x5a5a5a5aa5a5a5a5
	.quad	0xaaaa55555555aaaa,0x5555aaaaaaaa5555
	.quad	0xaaaa55555555aaaa,0x5555aaaaaaaa5555
	.quad	0xf00ff00ff00ff00f,0x0ff00ff00ff00ff0
	.quad	0xf00ff00ff00ff00f,0x0ff00ff00ff00ff0
	.quad	0xf0f00f0ff0f00f0f,0x0f0ff0f00f0ff0f0
	.quad	0x0f0ff0f00f0ff0f0,0xf0f00f0ff0f00f0f
	.quad	0xa55aa55a5aa55aa5,0xa55aa55a5aa55aa5
	.quad	0x5aa55aa5a55aa55a,0x5aa55aa5a55aa55a
	.quad	0x3cc33cc3c33cc33c,0xc33cc33c3cc33cc3
	.quad	0xc33cc33c3cc33cc3,0x3cc33cc3c33cc33c
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0x0000ffff0000ffff,0xffff0000ffff0000
	.quad	0xffff0000ffff0000,0x0000ffff0000ffff
	.quad	0xcc33cc33cc33cc33,0xcc33cc33cc33cc33
	.quad	0xcc33cc33cc33cc33,0xcc33cc33cc33cc33
	.quad	0x0ff00ff0f00ff00f,0xf00ff00f0ff00ff0
	.quad	0x0ff00ff0f00ff00f,0xf00ff00f0ff00ff0
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0x9696969669696969,0x9696969669696969
	.quad	0x9696969669696969,0x9696969669696969
	.quad	0xa5a5a5a5a5a5a5a5,0xa5a5a5a5a5a5a5a5
	.quad	0x5a5a5a5a5a5a5a5a,0x5a5a5a5a5a5a5a5a
	.quad	0x5a5a5a5aa5a5a5a5,0x5a5a5a5aa5a5a5a5
	.quad	0xa5a5a5a55a5a5a5a,0xa5a5a5a55a5a5a5a
	.quad	0xaaaa55555555aaaa,0x5555aaaaaaaa5555
	.quad	0xaaaa55555555aaaa,0x5555aaaaaaaa5555
	.quad	0x0ff00ff00ff00ff0,0xf00ff00ff00ff00f
	.quad	0x0ff00ff00ff00ff0,0xf00ff00ff00ff00f
	.quad	0xf0f00f0ff0f00f0f,0x0f0ff0f00f0ff0f0
	.quad	0x0f0ff0f00f0ff0f0,0xf0f00f0ff0f00f0f
	.quad	0x5aa55aa5a55aa55a,0x5aa55aa5a55aa55a
	.quad	0xa55aa55a5aa55aa5,0xa55aa55a5aa55aa5
	.quad	0xc33cc33c3cc33cc3,0x3cc33cc3c33cc33c
	.quad	0x3cc33cc3c33cc33c,0xc33cc33c3cc33cc3
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0x0000ffff0000ffff,0xffff0000ffff0000
	.quad	0xffff0000ffff0000,0x0000ffff0000ffff
	.quad	0xcc33cc33cc33cc33,0xcc33cc33cc33cc33
	.quad	0xcc33cc33cc33cc33,0xcc33cc33cc33cc33
	.quad	0x0ff00ff0f00ff00f,0xf00ff00f0ff00ff0
	.quad	0x0ff00ff0f00ff00f,0xf00ff00f0ff00ff0
	.quad	0x00000000ffffffff,0x00000000ffffffff
	.quad	0x00000000ffffffff,0x00000000ffffffff
	.quad	0x9696969669696969,0x9696969669696969
	.quad	0x9696969669696969,0x9696969669696969
	.quad	0x5a5a5a5a5a5a5a5a,0x5a5a5a5a5a5a5a5a
	.quad	0xa5a5a5a5a5a5a5a5,0xa5a5a5a5a5a5a5a5
	.quad	0xa5a5a5a55a5a5a5a,0xa5a5a5a55a5a5a5a
	.quad	0x5a5a5a5aa5a5a5a5,0x5a5a5a5aa5a5a5a5
	.quad	0x5555aaaaaaaa5555,0xaaaa55555555aaaa
	.quad	0x5555aaaaaaaa5555,0xaaaa55555555aaaa
	.quad	0xf00ff00ff00ff00f,0x0ff00ff00ff00ff0
	.quad	0xf00ff00ff00ff00f,0x0ff00ff00ff00ff0
	.quad	0xf0f00f0ff0f00f0f,0x0f0ff0f00f0ff0f0
	.quad	0x0f0ff0f00f0ff0f0,0xf0f00f0ff0f00f0f
	.quad	0xa55aa55a5aa55aa5,0xa55aa55a5aa55aa5
	.quad	0x5aa55aa5a55aa55a,0x5aa55aa5a55aa55a
	.quad	0xc33cc33c3cc33cc3,0x3cc33cc3c33cc33c
	.quad	0x3cc33cc3c33cc33c,0xc33cc33c3cc33cc3
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0xffff0000ffff0000,0x0000ffff0000ffff
	.quad	0x0000ffff0000ffff,0xffff0000ffff0000
	.quad	0x33cc33cc33cc33cc,0x33cc33cc33cc33cc
	.quad	0x33cc33cc33cc33cc,0x33cc33cc33cc33cc
	.quad	0x0ff00ff0f00ff00f,0xf00ff00f0ff00ff0
	.quad	0x0ff00ff0f00ff00f,0xf00ff00f0ff00ff0
	.quad	0x00000000ffffffff,0x00000000ffffffff
	.quad	0x00000000ffffffff,0x00000000ffffffff
	.quad	0x6969696996969696,0x6969696996969696
	.quad	0x6969696996969696,0x6969696996969696
	.quad	0x5a5a5a5a5a5a5a5a,0x5a5a5a5a5a5a5a5a
	.quad	0xa5a5a5a5a5a5a5a5,0xa5a5a5a5a5a5a5a5
	.quad	0x5a5a5a5aa5a5a5a5,0x5a5a5a5aa5a5a5a5
	.quad	0xa5a5a5a55a5a5a5a,0xa5a5a5a55a5a5a5a
	.quad	0x5555aaaaaaaa5555,0xaaaa55555555aaaa
	.quad	0x5555aaaaaaaa5555,0xaaaa55555555aaaa
	.quad	0x0ff00ff00ff00ff0,0xf00ff00ff00ff00f
	.quad	0x0ff00ff00ff00ff0,0xf00ff00ff00ff00f
	.quad	0xf0f00f0ff0f00f0f,0x0f0ff0f00f0ff0f0
	.quad	0x0f0ff0f00f0ff0f0,0xf0f00f0ff0f00f0f
	.quad	0xa55aa55a5aa55aa5,0xa55aa55a5aa55aa5
	.quad	0x5aa55aa5a55aa55a,0x5aa55aa5a55aa55a
	.quad	0x3cc33cc3c33cc33c,0xc33cc33c3cc33cc3
	.quad	0xc33cc33c3cc33cc3,0x3cc33cc3c33cc33c
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0xffff0000ffff0000,0x0000ffff0000ffff
	.quad	0x0000ffff0000ffff,0xffff0000ffff0000
	.quad	0x33cc33cc33cc33cc,0x33cc33cc33cc33cc
	.quad	0x33cc33cc33cc33cc,0x33cc33cc33cc33cc
	.quad	0x0ff00ff0f00ff00f,0xf00ff00f0ff00ff0
	.quad	0x0ff00ff0f00ff00f,0xf00ff00f0ff00ff0
	.quad	0x00000000ffffffff,0x00000000ffffffff
	.quad	0x00000000ffffffff,0x00000000ffffffff
	.quad	0x6969696996969696,0x6969696996969696
	.quad	0x6969696996969696,0x6969696996969696
	.quad	0x5a5a5a5a5a5a5a5a,0x5a5a5a5a5a5a5a5a
	.quad	0xa5a5a5a5a5a5a5a5,0xa5a5a5a5a5a5a5a5
	.quad	0x5a5a5a5aa5a5a5a5,0x5a5a5a5aa5a5a5a5
	.quad	0xa5a5a5a55a5a5a5a,0xa5a5a5a55a5a5a5a
	.quad	0xaaaa55555555aaaa,0x5555aaaaaaaa5555
	.quad	0xaaaa55555555aaaa,0x5555aaaaaaaa5555
	.quad	0xf00ff00ff00ff00f,0x0ff00ff00ff00ff0
	.quad	0xf00ff00ff00ff00f,0x0ff00ff00ff00ff0
	.quad	0xf0f00f0ff0f00f0f,0x0f0ff0f00f0ff0f0
	.quad	0x0f0ff0f00f0ff0f0,0xf0f00f0ff0f00f0f
	.quad	0x5aa55aa5a55aa55a,0x5aa55aa5a55aa55a
	.quad	0xa55aa55a5aa55aa5,0xa55aa55a5aa55aa5
	.quad	0x3cc33cc3c33cc33c,0xc33cc33c3cc33cc3
	.quad	0xc33cc33c3cc33cc3,0x3cc33cc3c33cc33c
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0x0000ffff0000ffff,0xffff0000ffff0000
	.quad	0xffff0000ffff0000,0x0000ffff0000ffff
	.quad	0xcc33cc33cc33cc33,0xcc33cc33cc33cc33
	.quad	0xcc33cc33cc33cc33,0xcc33cc33cc33cc33
	.quad	0x0ff00ff0f00ff00f,0xf00ff00f0ff00ff0
	.quad	0x0ff00ff0f00ff00f,0xf00ff00f0ff00ff0
	.quad	0x00000000ffffffff,0x00000000ffffffff
	.quad	0x00000000ffffffff,0x00000000ffffffff
	.quad	0x9696969669696969,0x9696969669696969
	.quad	0x9696969669696969,0x9696969669696969
	.quad	0x5a5a5a5a5a5a5a5a,0x5a5a5a5a5a5a5a5a
	.quad	0xa5a5a5a5a5a5a5a5,0xa5a5a5a5a5a5a5a5
	.quad	0xa5a5a5a55a5a5a5a,0xa5a5a5a55a5a5a5a
	.quad	0x5a5a5a5aa5a5a5a5,0x5a5a5a5aa5a5a5a5
	.quad	0xaaaa55555555aaaa,0x5555aaaaaaaa5555
	.quad	0xaaaa55555555aaaa,0x5555aaaaaaaa5555
	.quad	0x0ff00ff00ff00ff0,0xf00ff00ff00ff00f
	.quad	0x0ff00ff00ff00ff0,0xf00ff00ff00ff00f
	.quad	0xf0f00f0ff0f00f0f,0x0f0ff0f00f0ff0f0
	.quad	0x0f0ff0f00f0ff0f0,0xf0f00f0ff0f00f0f
	.quad	0xa55aa55a5aa55aa5,0xa55aa55a5aa55aa5
	.quad	0x5aa55aa5a55aa55a,0x5aa55aa5a55aa55a
	.quad	0xc33cc33c3cc33cc3,0x3cc33cc3c33cc33c
	.quad	0x3cc33cc3c33cc33c,0xc33cc33c3cc33cc3
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0x0000ffff0000ffff,0xffff0000ffff0000
	.quad	0xffff0000ffff0000,0x0000ffff0000ffff
	.quad	0xcc33cc33cc33cc33,0xcc33cc33cc33cc33
	.quad	0xcc33cc33cc33cc33,0xcc33cc33cc33cc33
	.quad	0x0ff00ff0f00ff00f,0xf00ff00f0ff00ff0
	.quad	0x0ff00ff0f00ff00f,0xf00ff00f0ff00ff0
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0x9696969669696969,0x9696969669696969
	.quad	0x9696969669696969,0x9696969669696969
	.quad	0xa5a5a5a5a5a5a5a5,0xa5a5a5a5a5a5a5a5
	.quad	0x5a5a5a5a5a5a5a5a,0x5a5a5a5a5a5a5a5a
	.quad	0x5a5a5a5aa5a5a5a5,0x5a5a5a5aa5a5a5a5
	.quad	0xa5a5a5a55a5a5a5a,0xa5a5a5a55a5a5a5a
	.quad	0x5555aaaaaaaa5555,0xaaaa55555555aaaa
	.quad	0x5555aaaaaaaa5555,0xaaaa55555555aaaa
	.quad	0xf00ff00ff00ff00f,0x0ff00ff00ff00ff0
	.quad	0xf00ff00ff00ff00f,0x0ff00ff00ff00ff0
	.quad	0xf0f00f0ff0f00f0f,0x0f0ff0f00f0ff0f0
	.quad	0x0f0ff0f00f0ff0f0,0xf0f00f0ff0f00f0f
	.quad	0x5aa55aa5a55aa55a,0x5aa55aa5a55aa55a
	.quad	0xa55aa55a5aa55aa5,0xa55aa55a5aa55aa5
	.quad	0xc33cc33c3cc33cc3,0x3cc33cc3c33cc33c
	.quad	0x3cc33cc3c33cc33c,0xc33cc33c3cc33cc3
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0xffff0000ffff0000,0x0000ffff0000ffff
	.quad	0x0000ffff0000ffff,0xffff0000ffff0000
	.quad	0x33cc33cc33cc33cc,0x33cc33cc33cc33cc
	.quad	0x33cc33cc33cc33cc,0x33cc33cc33cc33cc
	.quad	0x0ff00ff0f00ff00f,0xf00ff00f0ff00ff0
	.quad	0x0ff00ff0f00ff00f,0xf00ff00f0ff00ff0
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0x6969696996969696,0x6969696996969696
	.quad	0x6969696996969696,0x6969696996969696
	.quad	0xa5a5a5a5a5a5a5a5,0xa5a5a5a5a5a5a5a5
	.quad	0x5a5a5a5a5a5a5a5a,0x5a5a5a5a5a5a5a5a
	.quad	0xa5a5a5a55a5a5a5a,0xa5a5a5a55a5a5a5a
	.quad	0x5a5a5a5aa5a5a5a5,0x5a5a5a5aa5a5a5a5
	.quad	0x5555aaaaaaaa5555,0xaaaa55555555aaaa
	.quad	0x5555aaaaaaaa5555,0xaaaa55555555aaaa
	.quad	0x0ff00ff00ff00ff0,0xf00ff00ff00ff00f
	.quad	0x0ff00ff00ff00ff0,0xf00ff00ff00ff00f
	.quad	0xf0f00f0ff0f00f0f,0x0f0ff0f00f0ff0f0
	.quad	0x0f0ff0f00f0ff0f0,0xf0f00f0ff0f00f0f
	.quad	0xa55aa55a5aa55aa5,0xa55aa55a5aa55aa5
	.quad	0x5aa55aa5a55aa55a,0x5aa55aa5a55aa55a
	.quad	0x3cc33cc3c33cc33c,0xc33cc33c3cc33cc3
	.quad	0xc33cc33c3cc33cc3,0x3cc33cc3c33cc33c
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0xffff0000ffff0000,0x0000ffff0000ffff
	.quad	0x0000ffff0000ffff,0xffff0000ffff0000
	.quad	0x33cc33cc33cc33cc,0x33cc33cc33cc33cc
	.quad	0x33cc33cc33cc33cc,0x33cc33cc33cc33cc
	.quad	0xf00ff00f0ff00ff0,0x0ff00ff0f00ff00f
	.quad	0xf00ff00f0ff00ff0,0x0ff00ff0f00ff00f
	.quad	0x00000000ffffffff,0x00000000ffffffff
	.quad	0x00000000ffffffff,0x00000000ffffffff
	.quad	0x6969696996969696,0x6969696996969696
	.quad	0x6969696996969696,0x6969696996969696
	.quad	0xa5a5a5a5a5a5a5a5,0xa5a5a5a5a5a5a5a5
	.quad	0x5a5a5a5a5a5a5a5a,0x5a5a5a5a5a5a5a5a
	.quad	0x5a5a5a5aa5a5a5a5,0x5a5a5a5aa5a5a5a5
	.quad	0xa5a5a5a55a5a5a5a,0xa5a5a5a55a5a5a5a
	.quad	0xaaaa55555555aaaa,0x5555aaaaaaaa5555
	.quad	0xaaaa55555555aaaa,0x5555aaaaaaaa5555
	.quad	0x0ff00ff00ff00ff0,0xf00ff00ff00ff00f
	.quad	0x0ff00ff00ff00ff0,0xf00ff00ff00ff00f
	.quad	0x0f0ff0f00f0ff0f0,0xf0f00f0ff0f00f0f
	.quad	0xf0f00f0ff0f00f0f,0x0f0ff0f00f0ff0f0
	.quad	0x5aa55aa5a55aa55a,0x5aa55aa5a55aa55a
	.quad	0xa55aa55a5aa55aa5,0xa55aa55a5aa55aa5
	.quad	0x3cc33cc3c33cc33c,0xc33cc33c3cc33cc3
	.quad	0xc33cc33c3cc33cc3,0x3cc33cc3c33cc33c
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0x0000ffff0000ffff,0xffff0000ffff0000
	.quad	0xffff0000ffff0000,0x0000ffff0000ffff
	.quad	0xcc33cc33cc33cc33,0xcc33cc33cc33cc33
	.quad	0xcc33cc33cc33cc33,0xcc33cc33cc33cc33
	.quad	0xf00ff00f0ff00ff0,0x0ff00ff0f00ff00f
	.quad	0xf00ff00f0ff00ff0,0x0ff00ff0f00ff00f
	.quad	0x00000000ffffffff,0x00000000ffffffff
	.quad	0x00000000ffffffff,0x00000000ffffffff
	.quad	0x9696969669696969,0x9696969669696969
	.quad	0x9696969669696969,0x9696969669696969
	.quad	0xa5a5a5a5a5a5a5a5,0xa5a5a5a5a5a5a5a5
	.quad	0x5a5a5a5a5a5a5a5a,0x5a5a5a5a5a5a5a5a
	.quad	0xa5a5a5a55a5a5a5a,0xa5a5a5a55a5a5a5a
	.quad	0x5a5a5a5aa5a5a5a5,0x5a5a5a5aa5a5a5a5
	.quad	0xaaaa55555555aaaa,0x5555aaaaaaaa5555
	.quad	0xaaaa55555555aaaa,0x5555aaaaaaaa5555
	.quad	0xf00ff00ff00ff00f,0x0ff00ff00ff00ff0
	.quad	0xf00ff00ff00ff00f,0x0ff00ff00ff00ff0
	.quad	0x0f0ff0f00f0ff0f0,0xf0f00f0ff0f00f0f
	.quad	0xf0f00f0ff0f00f0f,0x0f0ff0f00f0ff0f0
	.quad	0xa55aa55a5aa55aa5,0xa55aa55a5aa55aa5
	.quad	0x5aa55aa5a55aa55a,0x5aa55aa5a55aa55a
	.quad	0xc33cc33c3cc33cc3,0x3cc33cc3c33cc33c
	.quad	0x3cc33cc3c33cc33c,0xc33cc33c3cc33cc3
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0x0000ffff0000ffff,0xffff0000ffff0000
	.quad	0xffff0000ffff0000,0x0000ffff0000ffff
	.quad	0xcc33cc33cc33cc33,0xcc33cc33cc33cc33
	.quad	0xcc33cc33cc33cc33,0xcc33cc33cc33cc33
	.quad	0xf00ff00f0ff00ff0,0x0ff00ff0f00ff00f
	.quad	0xf00ff00f0ff00ff0,0x0ff00ff0f00ff00f
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0x9696969669696969,0x9696969669696969
	.quad	0x9696969669696969,0x9696969669696969
	.quad	0x5a5a5a5a5a5a5a5a,0x5a5a5a5a5a5a5a5a
	.quad	0xa5a5a5a5a5a5a5a5,0xa5a5a5a5a5a5a5a5
	.quad	0x5a5a5a5aa5a5a5a5,0x5a5a5a5aa5a5a5a5
	.quad	0xa5a5a5a55a5a5a5a,0xa5a5a5a55a5a5a5a
	.quad	0x5555aaaaaaaa5555,0xaaaa55555555aaaa
	.quad	0x5555aaaaaaaa5555,0xaaaa55555555aaaa
	.quad	0x0ff00ff00ff00ff0,0xf00ff00ff00ff00f
	.quad	0x0ff00ff00ff00ff0,0xf00ff00ff00ff00f
	.quad	0x0f0ff0f00f0ff0f0,0xf0f00f0ff0f00f0f
	.quad	0xf0f00f0ff0f00f0f,0x0f0ff0f00f0ff0f0
	.quad	0x5aa55aa5a55aa55a,0x5aa55aa5a55aa55a
	.quad	0xa55aa55a5aa55aa5,0xa55aa55a5aa55aa5
	.quad	0xc33cc33c3cc33cc3,0x3cc33cc3c33cc33c
	.quad	0x3cc33cc3c33cc33c,0xc33cc33c3cc33cc3
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0xffff0000ffff0000,0x0000ffff0000ffff
	.quad	0x0000ffff0000ffff,0xffff0000ffff0000
	.quad	0x33cc33cc33cc33cc,0x33cc33cc33cc33cc
	.quad	0x33cc33cc33cc33cc,0x33cc33cc33cc33cc
	.quad	0xf00ff00f0ff00ff0,0x0ff00ff0f00ff00f
	.quad	0xf00ff00f0ff00ff0,0x0ff00ff0f00ff00f
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0x6969696996969696,0x6969696996969696
	.quad	0x6969696996969696,0x6969696996969696
	.quad	0x5a5a5a5a5a5a5a5a,0x5a5a5a5a5a5a5a5a
	.quad	0xa5a5a5a5a5a5a5a5,0xa5a5a5a5a5a5a5a5
	.quad	0xa5a5a5a55a5a5a5a,0xa5a5a5a55a5a5a5a
	.quad	0x5a5a5a5aa5a5a5a5,0x5a5a5a5aa5a5a5a5
	.quad	0x5555aaaaaaaa5555,0xaaaa55555555aaaa
	.quad	0x5555aaaaaaaa5555,0xaaaa55555555aaaa
	.quad	0xf00ff00ff00ff00f,0x0ff00ff00ff00ff0
	.quad	0xf00ff00ff00ff00f,0x0ff00ff00ff00ff0
	.quad	0x0f0ff0f00f0ff0f0,0xf0f00f0ff0f00f0f
	.quad	0xf0f00f0ff0f00f0f,0x0f0ff0f00f0ff0f0
	.quad	0xa55aa55a5aa55aa5,0xa55aa55a5aa55aa5
	.quad	0x5aa55aa5a55aa55a,0x5aa55aa5a55aa55a
	.quad	0x3cc33cc3c33cc33c,0xc33cc33c3cc33cc3
	.quad	0xc33cc33c3cc33cc3,0x3cc33cc3c33cc33c
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0xffff0000ffff0000,0x0000ffff0000ffff
	.quad	0x0000ffff0000ffff,0xffff0000ffff0000
	.quad	0x33cc33cc33cc33cc,0x33cc33cc33cc33cc
	.quad	0x33cc33cc33cc33cc,0x33cc33cc33cc33cc
	.quad	0xf00ff00f0ff00ff0,0x0ff00ff0f00ff00f
	.quad	0xf00ff00f0ff00ff0,0x0ff00ff0f00ff00f
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0x6969696996969696,0x6969696996969696
	.quad	0x6969696996969696,0x6969696996969696
	.quad	0x5a5a5a5a5a5a5a5a,0x5a5a5a5a5a5a5a5a
	.quad	0xa5a5a5a5a5a5a5a5,0xa5a5a5a5a5a5a5a5
	.quad	0xa5a5a5a55a5a5a5a,0xa5a5a5a55a5a5a5a
	.quad	0x5a5a5a5aa5a5a5a5,0x5a5a5a5aa5a5a5a5
	.quad	0xaaaa55555555aaaa,0x5555aaaaaaaa5555
	.quad	0xaaaa55555555aaaa,0x5555aaaaaaaa5555
	.quad	0x0ff00ff00ff00ff0,0xf00ff00ff00ff00f
	.quad	0x0ff00ff00ff00ff0,0xf00ff00ff00ff00f
	.quad	0x0f0ff0f00f0ff0f0,0xf0f00f0ff0f00f0f
	.quad	0xf0f00f0ff0f00f0f,0x0f0ff0f00f0ff0f0
	.quad	0x5aa55aa5a55aa55a,0x5aa55aa5a55aa55a
	.quad	0xa55aa55a5aa55aa5,0xa55aa55a5aa55aa5
	.quad	0x3cc33cc3c33cc33c,0xc33cc33c3cc33cc3
	.quad	0xc33cc33c3cc33cc3,0x3cc33cc3c33cc33c
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0x0000ffff0000ffff,0xffff0000ffff0000
	.quad	0xffff0000ffff0000,0x0000ffff0000ffff
	.quad	0xcc33cc33cc33cc33,0xcc33cc33cc33cc33
	.quad	0xcc33cc33cc33cc33,0xcc33cc33cc33cc33
	.quad	0xf00ff00f0ff00ff0,0x0ff00ff0f00ff00f
	.quad	0xf00ff00f0ff00ff0,0x0ff00ff0f00ff00f
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0x9696969669696969,0x9696969669696969
	.quad	0x9696969669696969,0x9696969669696969
	.quad	0x5a5a5a5a5a5a5a5a,0x5a5a5a5a5a5a5a5a
	.quad	0xa5a5a5a5a5a5a5a5,0xa5a5a5a5a5a5a5a5
	.quad	0x5a5a5a5aa5a5a5a5,0x5a5a5a5aa5a5a5a5
	.quad	0xa5a5a5a55a5a5a5a,0xa5a5a5a55a5a5a5a
	.quad	0xaaaa55555555aaaa,0x5555aaaaaaaa5555
	.quad	0xaaaa55555555aaaa,0x5555aaaaaaaa5555
	.quad	0xf00ff00ff00ff00f,0x0ff00ff00ff00ff0
	.quad	0xf00ff00ff00ff00f,0x0ff00ff00ff00ff0
	.quad	0x0f0ff0f00f0ff0f0,0xf0f00f0ff0f00f0f
	.quad	0xf0f00f0ff0f00f0f,0x0f0ff0f00f0ff0f0
	.quad	0xa55aa55a5aa55aa5,0xa55aa55a5aa55aa5
	.quad	0x5aa55aa5a55aa55a,0x5aa55aa5a55aa55a
	.quad	0xc33cc33c3cc33cc3,0x3cc33cc3c33cc33c
	.quad	0x3cc33cc3c33cc33c,0xc33cc33c3cc33cc3
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0x0000ffff0000ffff,0xffff0000ffff0000
	.quad	0xffff0000ffff0000,0x0000ffff0000ffff
	.quad	0xcc33cc33cc33cc33,0xcc33cc33cc33cc33
	.quad	0xcc33cc33cc33cc33,0xcc33cc33cc33cc33
	.quad	0xf00ff00f0ff00ff0,0x0ff00ff0f00ff00f
	.quad	0xf00ff00f0ff00ff0,0x0ff00ff0f00ff00f
	.quad	0x00000000ffffffff,0x00000000ffffffff
	.quad	0x00000000ffffffff,0x00000000ffffffff
	.quad	0x9696969669696969,0x9696969669696969
	.quad	0x9696969669696969,0x9696969669696969
	.quad	0xa5a5a5a5a5a5a5a5,0xa5a5a5a5a5a5a5a5
	.quad	0x5a5a5a5a5a5a5a5a,0x5a5a5a5a5a5a5a5a
	.quad	0xa5a5a5a55a5a5a5a,0xa5a5a5a55a5a5a5a
	.quad	0x5a5a5a5aa5a5a5a5,0x5a5a5a5aa5a5a5a5
	.quad	0x5555aaaaaaaa5555,0xaaaa55555555aaaa
	.quad	0x5555aaaaaaaa5555,0xaaaa55555555aaaa
	.quad	0x0ff00ff00ff00ff0,0xf00ff00ff00ff00f
	.quad	0x0ff00ff00ff00ff0,0xf00ff00ff00ff00f
	.quad	0x0f0ff0f00f0ff0f0,0xf0f00f0ff0f00f0f
	.quad	0xf0f00f0ff0f00f0f,0x0f0ff0f00f0ff0f0
	.quad	0x5aa55aa5a55aa55a,0x5aa55aa5a55aa55a
	.quad	0xa55aa55a5aa55aa5,0xa55aa55a5aa55aa5
	.quad	0xc33cc33c3cc33cc3,0x3cc33cc3c33cc33c
	.quad	0x3cc33cc3c33cc33c,0xc33cc33c3cc33cc3
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0xffff0000ffff0000,0x0000ffff0000ffff
	.quad	0x0000ffff0000ffff,0xffff0000ffff0000
	.quad	0x33cc33cc33cc33cc,0x33cc33cc33cc33cc
	.quad	0x33cc33cc33cc33cc,0x33cc33cc33cc33cc
	.quad	0xf00ff00f0ff00ff0,0x0ff00ff0f00ff00f
	.quad	0xf00ff00f0ff00ff0,0x0ff00ff0f00ff00f
	.quad	0x00000000ffffffff,0x00000000ffffffff
	.quad	0x00000000ffffffff,0x00000000ffffffff
	.quad	0x6969696996969696,0x6969696996969696
	.quad	0x6969696996969696,0x6969696996969696
	.quad	0xa5a5a5a5a5a5a5a5,0xa5a5a5a5a5a5a5a5
	.quad	0x5a5a5a5a5a5a5a5a,0x5a5a5a5a5a5a5a5a
	.quad	0x5a5a5a5aa5a5a5a5,0x5a5a5a5aa5a5a5a5
	.quad	0xa5a5a5a55a5a5a5a,0xa5a5a5a55a5a5a5a
	.quad	0x5555aaaaaaaa5555,0xaaaa55555555aaaa
	.quad	0x5555aaaaaaaa5555,0xaaaa55555555aaaa
	.quad	0xf00ff00ff00ff00f,0x0ff00ff00ff00ff0
	.quad	0xf00ff00ff00ff00f,0x0ff00ff00ff00ff0
	.quad	0x0f0ff0f00f0ff0f0,0xf0f00f0ff0f00f0f
	.quad	0xf0f00f0ff0f00f0f,0x0f0ff0f00f0ff0f0
	.quad	0xa55aa55a5aa55aa5,0xa55aa55a5aa55aa5
	.quad	0x5aa55aa5a55aa55a,0x5aa55aa5a55aa55a
	.quad	0x3cc33cc3c33cc33c,0xc33cc33c3cc33cc3
	.quad	0xc33cc33c3cc33cc3,0x3cc33cc3c33cc33c
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0xffff0000ffff0000,0x0000ffff0000ffff
	.quad	0x0000ffff0000ffff,0xffff0000ffff0000
	.quad	0x33cc33cc33cc33cc,0x33cc33cc33cc33cc
	.quad	0x33cc33cc33cc33cc,0x33cc33cc33cc33cc
	.quad	0x0ff00ff0f00ff00f,0xf00ff00f0ff00ff0
	.quad	0x0ff00ff0f00ff00f,0xf00ff00f0ff00ff0
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0x6969696996969696,0x6969696996969696
	.quad	0x6969696996969696,0x6969696996969696
	.quad	0xa5a5a5a5a5a5a5a5,0xa5a5a5a5a5a5a5a5
	.quad	0x5a5a5a5a5a5a5a5a,0x5a5a5a5a5a5a5a5a
	.quad	0xa5a5a5a55a5a5a5a,0xa5a5a5a55a5a5a5a
	.quad	0x5a5a5a5aa5a5a5a5,0x5a5a5a5aa5a5a5a5
	.quad	0xaaaa55555555aaaa,0x5555aaaaaaaa5555
	.quad	0xaaaa55555555aaaa,0x5555aaaaaaaa5555
	.quad	0xf00ff00ff00ff00f,0x0ff00ff00ff00ff0
	.quad	0xf00ff00ff00ff00f,0x0ff00ff00ff00ff0
	.quad	0xf0f00f0ff0f00f0f,0x0f0ff0f00f0ff0f0
	.quad	0x0f0ff0f00f0ff0f0,0xf0f00f0ff0f00f0f
	.quad	0x5aa55aa5a55aa55a,0x5aa55aa5a55aa55a
	.quad	0xa55aa55a5aa55aa5,0xa55aa55a5aa55aa5
	.quad	0x3cc33cc3c33cc33c,0xc33cc33c3cc33cc3
	.quad	0xc33cc33c3cc33cc3,0x3cc33cc3c33cc33c
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0x0000ffff0000ffff,0xffff0000ffff0000
	.quad	0xffff0000ffff0000,0x0000ffff0000ffff
	.quad	0xcc33cc33cc33cc33,0xcc33cc33cc33cc33
	.quad	0xcc33cc33cc33cc33,0xcc33cc33cc33cc33
	.quad	0x0ff00ff0f00ff00f,0xf00ff00f0ff00ff0
	.quad	0x0ff00ff0f00ff00f,0xf00ff00f0ff00ff0
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0x9696969669696969,0x9696969669696969
	.quad	0x9696969669696969,0x9696969669696969
	.quad	0xa5a5a5a5a5a5a5a5,0xa5a5a5a5a5a5a5a5
	.quad	0x5a5a5a5a5a5a5a5a,0x5a5a5a5a5a5a5a5a
	.quad	0x5a5a5a5aa5a5a5a5,0x5a5a5a5aa5a5a5a5
	.quad	0xa5a5a5a55a5a5a5a,0xa5a5a5a55a5a5a5a
	.quad	0xaaaa55555555aaaa,0x5555aaaaaaaa5555
	.quad	0xaaaa55555555aaaa,0x5555aaaaaaaa5555
	.quad	0x0ff00ff00ff00ff0,0xf00ff00ff00ff00f
	.quad	0x0ff00ff00ff00ff0,0xf00ff00ff00ff00f
	.quad	0xf0f00f0ff0f00f0f,0x0f0ff0f00f0ff0f0
	.quad	0x0f0ff0f00f0ff0f0,0xf0f00f0ff0f00f0f
	.quad	0xa55aa55a5aa55aa5,0xa55aa55a5aa55aa5
	.quad	0x5aa55aa5a55aa55a,0x5aa55aa5a55aa55a
	.quad	0xc33cc33c3cc33cc3,0x3cc33cc3c33cc33c
	.quad	0x3cc33cc3c33cc33c,0xc33cc33c3cc33cc3
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0x0000ffff0000ffff,0xffff0000ffff0000
	.quad	0xffff0000ffff0000,0x0000ffff0000ffff
	.quad	0xcc33cc33cc33cc33,0xcc33cc33cc33cc33
	.quad	0xcc33cc33cc33cc33,0xcc33cc33cc33cc33
	.quad	0x0ff00ff0f00ff00f,0xf00ff00f0ff00ff0
	.quad	0x0ff00ff0f00ff00f,0xf00ff00f0ff00ff0
	.quad	0x00000000ffffffff,0x00000000ffffffff
	.quad	0x00000000ffffffff,0x00000000ffffffff
	.quad	0x9696969669696969,0x9696969669696969
	.quad	0x9696969669696969,0x9696969669696969
	.quad	0x5a5a5a5a5a5a5a5a,0x5a5a5a5a5a5a5a5a
	.quad	0xa5a5a5a5a5a5a5a5,0xa5a5a5a5a5a5a5a5
	.quad	0xa5a5a5a55a5a5a5a,0xa5a5a5a55a5a5a5a
	.quad	0x5a5a5a5aa5a5a5a5,0x5a5a5a5aa5a5a5a5
	.quad	0x5555aaaaaaaa5555,0xaaaa55555555aaaa
	.quad	0x5555aaaaaaaa5555,0xaaaa55555555aaaa
	.quad	0xf00ff00ff00ff00f,0x0ff00ff00ff00ff0
	.quad	0xf00ff00ff00ff00f,0x0ff00ff00ff00ff0
	.quad	0xf0f00f0ff0f00f0f,0x0f0ff0f00f0ff0f0
	.quad	0x0f0ff0f00f0ff0f0,0xf0f00f0ff0f00f0f
	.quad	0x5aa55aa5a55aa55a,0x5aa55aa5a55aa55a
	.quad	0xa55aa55a5aa55aa5,0xa55aa55a5aa55aa5
	.quad	0xc33cc33c3cc33cc3,0x3cc33cc3c33cc33c
	.quad	0x3cc33cc3c33cc33c,0xc33cc33c3cc33cc3
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0xffff0000ffff0000,0x0000ffff0000ffff
	.quad	0x0000ffff0000ffff,0xffff0000ffff0000
	.quad	0x33cc33cc33cc33cc,0x33cc33cc33cc33cc
	.quad	0x33cc33cc33cc33cc,0x33cc33cc33cc33cc
	.quad	0x0ff00ff0f00ff00f,0xf00ff00f0ff00ff0
	.quad	0x0ff00ff0f00ff00f,0xf00ff00f0ff00ff0
	.quad	0x00000000ffffffff,0x00000000ffffffff
	.quad	0x00000000ffffffff,0x00000000ffffffff
	.quad	0x6969696996969696,0x6969696996969696
	.quad	0x6969696996969696,0x6969696996969696
	.quad	0x5a5a5a5a5a5a5a5a,0x5a5a5a5a5a5a5a5a
	.quad	0xa5a5a5a5a5a5a5a5,0xa5a5a5a5a5a5a5a5
	.quad	0x5a5a5a5aa5a5a5a5,0x5a5a5a5aa5a5a5a5
	.quad	0xa5a5a5a55a5a5a5a,0xa5a5a5a55a5a5a5a
	.quad	0x5555aaaaaaaa5555,0xaaaa55555555aaaa
	.quad	0x5555aaaaaaaa5555,0xaaaa55555555aaaa
	.quad	0x0ff00ff00ff00ff0,0xf00ff00ff00ff00f
	.quad	0x0ff00ff00ff00ff0,0xf00ff00ff00ff00f
	.quad	0xf0f00f0ff0f00f0f,0x0f0ff0f00f0ff0f0
	.quad	0x0f0ff0f00f0ff0f0,0xf0f00f0ff0f00f0f
	.quad	0x5aa55aa5a55aa55a,0x5aa55aa5a55aa55a
	.quad	0xa55aa55a5aa55aa5,0xa55aa55a5aa55aa5
	.quad	0x3cc33cc3c33cc33c,0xc33cc33c3cc33cc3
	.quad	0xc33cc33c3cc33cc3,0x3cc33cc3c33cc33c
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0xffff0000ffff0000,0x0000ffff0000ffff
	.quad	0x0000ffff0000ffff,0xffff0000ffff0000
	.quad	0x33cc33cc33cc33cc,0x33cc33cc33cc33cc
	.quad	0x33cc33cc33cc33cc,0x33cc33cc33cc33cc
	.quad	0x0ff00ff0f00ff00f,0xf00ff00f0ff00ff0
	.quad	0x0ff00ff0f00ff00f,0xf00ff00f0ff00ff0
	.quad	0x00000000ffffffff,0x00000000ffffffff
	.quad	0x00000000ffffffff,0x00000000ffffffff
	.quad	0x6969696996969696,0x6969696996969696
	.quad	0x6969696996969696,0x6969696996969696
	.quad	0x5a5a5a5a5a5a5a5a,0x5a5a5a5a5a5a5a5a
	.quad	0xa5a5a5a5a5a5a5a5,0xa5a5a5a5a5a5a5a5
	.quad	0x5a5a5a5aa5a5a5a5,0x5a5a5a5aa5a5a5a5
	.quad	0xa5a5a5a55a5a5a5a,0xa5a5a5a55a5a5a5a
	.quad	0xaaaa55555555aaaa,0x5555aaaaaaaa5555
	.quad	0xaaaa55555555aaaa,0x5555aaaaaaaa5555
	.quad	0xf00ff00ff00ff00f,0x0ff00ff00ff00ff0
	.quad	0xf00ff00ff00ff00f,0x0ff00ff00ff00ff0
	.quad	0xf0f00f0ff0f00f0f,0x0f0ff0f00f0ff0f0
	.quad	0x0f0ff0f00f0ff0f0,0xf0f00f0ff0f00f0f
	.quad	0xa55aa55a5aa55aa5,0xa55aa55a5aa55aa5
	.quad	0x5aa55aa5a55aa55a,0x5aa55aa5a55aa55a
	.quad	0x3cc33cc3c33cc33c,0xc33cc33c3cc33cc3
	.quad	0xc33cc33c3cc33cc3,0x3cc33cc3c33cc33c
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0x0000ffff0000ffff,0xffff0000ffff0000
	.quad	0xffff0000ffff0000,0x0000ffff0000ffff
	.quad	0xcc33cc33cc33cc33,0xcc33cc33cc33cc33
	.quad	0xcc33cc33cc33cc33,0xcc33cc33cc33cc33
	.quad	0x0ff00ff0f00ff00f,0xf00ff00f0ff00ff0
	.quad	0x0ff00ff0f00ff00f,0xf00ff00f0ff00ff0
	.quad	0x00000000ffffffff,0x00000000ffffffff
	.quad	0x00000000ffffffff,0x00000000ffffffff
	.quad	0x9696969669696969,0x9696969669696969
	.quad	0x9696969669696969,0x9696969669696969
	.quad	0x5a5a5a5a5a5a5a5a,0x5a5a5a5a5a5a5a5a
	.quad	0xa5a5a5a5a5a5a5a5,0xa5a5a5a5a5a5a5a5
	.quad	0xa5a5a5a55a5a5a5a,0xa5a5a5a55a5a5a5a
	.quad	0x5a5a5a5aa5a5a5a5,0x5a5a5a5aa5a5a5a5
	.quad	0xaaaa55555555aaaa,0x5555aaaaaaaa5555
	.quad	0xaaaa55555555aaaa,0x5555aaaaaaaa5555
	.quad	0x0ff00ff00ff00ff0,0xf00ff00ff00ff00f
	.quad	0x0ff00ff00ff00ff0,0xf00ff00ff00ff00f
	.quad	0xf0f00f0ff0f00f0f,0x0f0ff0f00f0ff0f0
	.quad	0x0f0ff0f00f0ff0f0,0xf0f00f0ff0f00f0f
	.quad	0x5aa55aa5a55aa55a,0x5aa55aa5a55aa55a
	.quad	0xa55aa55a5aa55aa5,0xa55aa55a5aa55aa5
	.quad	0xc33cc33c3cc33cc3,0x3cc33cc3c33cc33c
	.quad	0x3cc33cc3c33cc33c,0xc33cc33c3cc33cc3
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0x0000ffff0000ffff,0xffff0000ffff0000
	.quad	0xffff0000ffff0000,0x0000ffff0000ffff
	.quad	0xcc33cc33cc33cc33,0xcc33cc33cc33cc33
	.quad	0xcc33cc33cc33cc33,0xcc33cc33cc33cc33
	.quad	0x0ff00ff0f00ff00f,0xf00ff00f0ff00ff0
	.quad	0x0ff00ff0f00ff00f,0xf00ff00f0ff00ff0
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0x9696969669696969,0x9696969669696969
	.quad	0x9696969669696969,0x9696969669696969
	.quad	0xa5a5a5a5a5a5a5a5,0xa5a5a5a5a5a5a5a5
	.quad	0x5a5a5a5a5a5a5a5a,0x5a5a5a5a5a5a5a5a
	.quad	0x5a5a5a5aa5a5a5a5,0x5a5a5a5aa5a5a5a5
	.quad	0xa5a5a5a55a5a5a5a,0xa5a5a5a55a5a5a5a
	.quad	0x5555aaaaaaaa5555,0xaaaa55555555aaaa
	.quad	0x5555aaaaaaaa5555,0xaaaa55555555aaaa
	.quad	0xf00ff00ff00ff00f,0x0ff00ff00ff00ff0
	.quad	0xf00ff00ff00ff00f,0x0ff00ff00ff00ff0
	.quad	0xf0f00f0ff0f00f0f,0x0f0ff0f00f0ff0f0
	.quad	0x0f0ff0f00f0ff0f0,0xf0f00f0ff0f00f0f
	.quad	0xa55aa55a5aa55aa5,0xa55aa55a5aa55aa5
	.quad	0x5aa55aa5a55aa55a,0x5aa55aa5a55aa55a
	.quad	0xc33cc33c3cc33cc3,0x3cc33cc3c33cc33c
	.quad	0x3cc33cc3c33cc33c,0xc33cc33c3cc33cc3
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0xffff0000ffff0000,0x0000ffff0000ffff
	.quad	0x0000ffff0000ffff,0xffff0000ffff0000
	.quad	0x33cc33cc33cc33cc,0x33cc33cc33cc33cc
	.quad	0x33cc33cc33cc33cc,0x33cc33cc33cc33cc
	.quad	0x0ff00ff0f00ff00f,0xf00ff00f0ff00ff0
	.quad	0x0ff00ff0f00ff00f,0xf00ff00f0ff00ff0
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0x6969696996969696,0x6969696996969696
	.quad	0x6969696996969696,0x6969696996969696
	.quad	0xa5a5a5a5a5a5a5a5,0xa5a5a5a5a5a5a5a5
	.quad	0x5a5a5a5a5a5a5a5a,0x5a5a5a5a5a5a5a5a
	.quad	0xa5a5a5a55a5a5a5a,0xa5a5a5a55a5a5a5a
	.quad	0x5a5a5a5aa5a5a5a5,0x5a5a5a5aa5a5a5a5
	.quad	0x5555aaaaaaaa5555,0xaaaa55555555aaaa
	.quad	0x5555aaaaaaaa5555,0xaaaa55555555aaaa
	.quad	0x0ff00ff00ff00ff0,0xf00ff00ff00ff00f
	.quad	0x0ff00ff00ff00ff0,0xf00ff00ff00ff00f
	.quad	0xf0f00f0ff0f00f0f,0x0f0ff0f00f0ff0f0
	.quad	0x0f0ff0f00f0ff0f0,0xf0f00f0ff0f00f0f
	.quad	0x5aa55aa5a55aa55a,0x5aa55aa5a55aa55a
	.quad	0xa55aa55a5aa55aa5,0xa55aa55a5aa55aa5
	.quad	0x3cc33cc3c33cc33c,0xc33cc33c3cc33cc3
	.quad	0xc33cc33c3cc33cc3,0x3cc33cc3c33cc33c
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0xffff0000ffff0000,0x0000ffff0000ffff
	.quad	0x0000ffff0000ffff,0xffff0000ffff0000
	.quad	0x33cc33cc33cc33cc,0x33cc33cc33cc33cc
	.quad	0x33cc33cc33cc33cc,0x33cc33cc33cc33cc
	.quad	0xf00ff00f0ff00ff0,0x0ff00ff0f00ff00f
	.quad	0xf00ff00f0ff00ff0,0x0ff00ff0f00ff00f
	.quad	0x00000000ffffffff,0x00000000ffffffff
	.quad	0x00000000ffffffff,0x00000000ffffffff
	.quad	0x6969696996969696,0x6969696996969696
	.quad	0x6969696996969696,0x6969696996969696
	.quad	0xa5a5a5a5a5a5a5a5,0xa5a5a5a5a5a5a5a5
	.quad	0x5a5a5a5a5a5a5a5a,0x5a5a5a5a5a5a5a5a
	.quad	0x5a5a5a5aa5a5a5a5,0x5a5a5a5aa5a5a5a5
	.quad	0xa5a5a5a55a5a5a5a,0xa5a5a5a55a5a5a5a
	.quad	0xaaaa55555555aaaa,0x5555aaaaaaaa5555
	.quad	0xaaaa55555555aaaa,0x5555aaaaaaaa5555
	.quad	0x0ff00ff00ff00ff0,0xf00ff00ff00ff00f
	.quad	0x0ff00ff00ff00ff0,0xf00ff00ff00ff00f
	.quad	0x0f0ff0f00f0ff0f0,0xf0f00f0ff0f00f0f
	.quad	0xf0f00f0ff0f00f0f,0x0f0ff0f00f0ff0f0
	.quad	0xa55aa55a5aa55aa5,0xa55aa55a5aa55aa5
	.quad	0x5aa55aa5a55aa55a,0x5aa55aa5a55aa55a
	.quad	0x3cc33cc3c33cc33c,0xc33cc33c3cc33cc3
	.quad	0xc33cc33c3cc33cc3,0x3cc33cc3c33cc33c
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0x0000ffff0000ffff,0xffff0000ffff0000
	.quad	0xffff0000ffff0000,0x0000ffff0000ffff
	.quad	0xcc33cc33cc33cc33,0xcc33cc33cc33cc33
	.quad	0xcc33cc33cc33cc33,0xcc33cc33cc33cc33
	.quad	0xf00ff00f0ff00ff0,0x0ff00ff0f00ff00f
	.quad	0xf00ff00f0ff00ff0,0x0ff00ff0f00ff00f
	.quad	0x00000000ffffffff,0x00000000ffffffff
	.quad	0x00000000ffffffff,0x00000000ffffffff
	.quad	0x9696969669696969,0x9696969669696969
	.quad	0x9696969669696969,0x9696969669696969
	.quad	0xa5a5a5a5a5a5a5a5,0xa5a5a5a5a5a5a5a5
	.quad	0x5a5a5a5a5a5a5a5a,0x5a5a5a5a5a5a5a5a
	.quad	0xa5a5a5a55a5a5a5a,0xa5a5a5a55a5a5a5a
	.quad	0x5a5a5a5aa5a5a5a5,0x5a5a5a5aa5a5a5a5
	.quad	0xaaaa55555555aaaa,0x5555aaaaaaaa5555
	.quad	0xaaaa55555555aaaa,0x5555aaaaaaaa5555
	.quad	0xf00ff00ff00ff00f,0x0ff00ff00ff00ff0
	.quad	0xf00ff00ff00ff00f,0x0ff00ff00ff00ff0
	.quad	0x0f0ff0f00f0ff0f0,0xf0f00f0ff0f00f0f
	.quad	0xf0f00f0ff0f00f0f,0x0f0ff0f00f0ff0f0
	.quad	0x5aa55aa5a55aa55a,0x5aa55aa5a55aa55a
	.quad	0xa55aa55a5aa55aa5,0xa55aa55a5aa55aa5
	.quad	0xc33cc33c3cc33cc3,0x3cc33cc3c33cc33c
	.quad	0x3cc33cc3c33cc33c,0xc33cc33c3cc33cc3
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0x0000ffff0000ffff,0xffff0000ffff0000
	.quad	0xffff0000ffff0000,0x0000ffff0000ffff
	.quad	0xcc33cc33cc33cc33,0xcc33cc33cc33cc33
	.quad	0xcc33cc33cc33cc33,0xcc33cc33cc33cc33
	.quad	0xf00ff00f0ff00ff0,0x0ff00ff0f00ff00f
	.quad	0xf00ff00f0ff00ff0,0x0ff00ff0f00ff00f
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0x9696969669696969,0x9696969669696969
	.quad	0x9696969669696969,0x9696969669696969
	.quad	0x5a5a5a5a5a5a5a5a,0x5a5a5a5a5a5a5a5a
	.quad	0xa5a5a5a5a5a5a5a5,0xa5a5a5a5a5a5a5a5
	.quad	0x5a5a5a5aa5a5a5a5,0x5a5a5a5aa5a5a5a5
	.quad	0xa5a5a5a55a5a5a5a,0xa5a5a5a55a5a5a5a
	.quad	0x5555aaaaaaaa5555,0xaaaa55555555aaaa
	.quad	0x5555aaaaaaaa5555,0xaaaa55555555aaaa
	.quad	0x0ff00ff00ff00ff0,0xf00ff00ff00ff00f
	.quad	0x0ff00ff00ff00ff0,0xf00ff00ff00ff00f
	.quad	0x0f0ff0f00f0ff0f0,0xf0f00f0ff0f00f0f
	.quad	0xf0f00f0ff0f00f0f,0x0f0ff0f00f0ff0f0
	.quad	0xa55aa55a5aa55aa5,0xa55aa55a5aa55aa5
	.quad	0x5aa55aa5a55aa55a,0x5aa55aa5a55aa55a
	.quad	0xc33cc33c3cc33cc3,0x3cc33cc3c33cc33c
	.quad	0x3cc33cc3c33cc33c,0xc33cc33c3cc33cc3
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0xa5a55a5aa5a55a5a,0xa5a55a5aa5a55a5a
	.quad	0xffff0000ffff0000,0x0000ffff0000ffff
	.quad	0x0000ffff0000ffff,0xffff0000ffff0000
	.quad	0x33cc33cc33cc33cc,0x33cc33cc33cc33cc
	.quad	0x33cc33cc33cc33cc,0x33cc33cc33cc33cc
	.quad	0xf00ff00f0ff00ff0,0x0ff00ff0f00ff00f
	.quad	0xf00ff00f0ff00ff0,0x0ff00ff0f00ff00f
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0x6969696996969696,0x6969696996969696
	.quad	0x6969696996969696,0x6969696996969696
	.quad	0x5a5a5a5a5a5a5a5a,0x5a5a5a5a5a5a5a5a
	.quad	0xa5a5a5a5a5a5a5a5,0xa5a5a5a5a5a5a5a5
	.quad	0xa5a5a5a55a5a5a5a,0xa5a5a5a55a5a5a5a
	.quad	0x5a5a5a5aa5a5a5a5,0x5a5a5a5aa5a5a5a5
	.quad	0x5555aaaaaaaa5555,0xaaaa55555555aaaa
	.quad	0x5555aaaaaaaa5555,0xaaaa55555555aaaa
	.quad	0xf00ff00ff00ff00f,0x0ff00ff00ff00ff0
	.quad	0xf00ff00ff00ff00f,0x0ff00ff00ff00ff0
	.quad	0x0f0ff0f00f0ff0f0,0xf0f00f0ff0f00f0f
	.quad	0xf0f00f0ff0f00f0f,0x0f0ff0f00f0ff0f0
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mc_aff_consts_neon, %object
	.size	L_mc_aff_consts_neon, 13728
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 16-byte aligned, 128-bit aligned
#ifndef __APPLE__
	.align	4
#else
	.p2align	4
#endif /* __APPLE__ */
L_mc_aff_consts_neon:
	.quad	0x6969969669699696,0x6969969669699696
	.quad	0x6969969669699696,0x6969969669699696
	.quad	0x9966669966999966,0x9966669966999966
	.quad	0x9966669966999966,0x9966669966999966
	.quad	0x9966669966999966,0x9966669966999966
	.quad	0x9966669966999966,0x9966669966999966
	.quad	0xff0000ff00ffff00,0xff0000ff00ffff00
	.quad	0xff0000ff00ffff00,0xff0000ff00ffff00
	.quad	0xcc3333cccc3333cc,0xcc3333cccc3333cc
	.quad	0xcc3333cccc3333cc,0xcc3333cccc3333cc
	.quad	0x9966669966999966,0x9966669966999966
	.quad	0x9966669966999966,0x9966669966999966
	.quad	0x6666666666666666,0x6666666666666666
	.quad	0x6666666666666666,0x6666666666666666
	.quad	0xa55aa55aa55aa55a,0xa55aa55aa55aa55a
	.quad	0xa55aa55aa55aa55a,0xa55aa55aa55aa55a
	.quad	0xcccc33333333cccc,0xcccc33333333cccc
	.quad	0xcccc33333333cccc,0xcccc33333333cccc
	.quad	0x5a5a5a5a5a5a5a5a,0x5a5a5a5a5a5a5a5a
	.quad	0x5a5a5a5a5a5a5a5a,0x5a5a5a5a5a5a5a5a
	.quad	0x55aaaa55aa5555aa,0x55aaaa55aa5555aa
	.quad	0x55aaaa55aa5555aa,0x55aaaa55aa5555aa
	.quad	0x0ff0f00ff00f0ff0,0x0ff0f00ff00f0ff0
	.quad	0x0ff0f00ff00f0ff0,0x0ff0f00ff00f0ff0
	.quad	0x5aa55aa5a55aa55a,0x5aa55aa5a55aa55a
	.quad	0x5aa55aa5a55aa55a,0x5aa55aa5a55aa55a
	.quad	0xa55a5aa55aa5a55a,0xa55a5aa55aa5a55a
	.quad	0xa55a5aa55aa5a55a,0xa55a5aa55aa5a55a
	.quad	0x6969696996969696,0x6969696996969696
	.quad	0x6969696996969696,0x6969696996969696
	.quad	0x5aa55aa5a55aa55a,0x5aa55aa5a55aa55a
	.quad	0x5aa55aa5a55aa55a,0x5aa55aa5a55aa55a
	.quad	0x9999999966666666,0x6666666699999999
	.quad	0x9999999966666666,0x6666666699999999
	.quad	0x3c3cc3c3c3c33c3c,0xc3c33c3c3c3cc3c3
	.quad	0x3c3cc3c3c3c33c3c,0xc3c33c3c3c3cc3c3
	.quad	0xffff0000ffff0000,0x0000ffff0000ffff
	.quad	0xffff0000ffff0000,0x0000ffff0000ffff
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0xcc33cc3333cc33cc,0x33cc33cccc33cc33
	.quad	0xcc33cc3333cc33cc,0x33cc33cccc33cc33
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x3c3c3c3c3c3c3c3c,0x3c3c3c3c3c3c3c3c
	.quad	0x3c3c3c3c3c3c3c3c,0x3c3c3c3c3c3c3c3c
	.quad	0xaa5555aaaa5555aa,0xaa5555aaaa5555aa
	.quad	0xaa5555aaaa5555aa,0xaa5555aaaa5555aa
	.quad	0xc33c3cc33cc3c33c,0xc33c3cc33cc3c33c
	.quad	0xc33c3cc33cc3c33c,0xc33c3cc33cc3c33c
	.quad	0x00ffff0000ffff00,0xff0000ffff0000ff
	.quad	0x00ffff0000ffff00,0xff0000ffff0000ff
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xa5a5a5a55a5a5a5a,0xa5a5a5a55a5a5a5a
	.quad	0x5a5a5a5aa5a5a5a5,0x5a5a5a5aa5a5a5a5
	.quad	0x0ff0f00ff00f0ff0,0x0ff0f00ff00f0ff0
	.quad	0xf00f0ff00ff0f00f,0xf00f0ff00ff0f00f
	.quad	0x9669966969966996,0x6996699696699669
	.quad	0x6996699696699669,0x9669966969966996
	.quad	0x0000ffffffff0000,0xffff00000000ffff
	.quad	0x0000ffffffff0000,0xffff00000000ffff
	.quad	0x33333333cccccccc,0x33333333cccccccc
	.quad	0x33333333cccccccc,0x33333333cccccccc
	.quad	0xa55a5aa55aa5a55a,0x5aa5a55aa55a5aa5
	.quad	0x5aa5a55aa55a5aa5,0xa55a5aa55aa5a55a
	.quad	0x00ffff0000ffff00,0xff0000ffff0000ff
	.quad	0xff0000ffff0000ff,0x00ffff0000ffff00
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0xffffffffffffffff,0x0000000000000000
	.quad	0xc33cc33cc33cc33c,0xc33cc33cc33cc33c
	.quad	0xc33cc33cc33cc33c,0xc33cc33cc33cc33c
	.quad	0x0f0ff0f00f0ff0f0,0x0f0ff0f00f0ff0f0
	.quad	0x0f0ff0f00f0ff0f0,0x0f0ff0f00f0ff0f0
	.quad	0xcccccccccccccccc,0xcccccccccccccccc
	.quad	0xcccccccccccccccc,0xcccccccccccccccc
	.quad	0xaaaa55555555aaaa,0x5555aaaaaaaa5555
	.quad	0xaaaa55555555aaaa,0x5555aaaaaaaa5555
	.quad	0xc33c3cc33cc3c33c,0x3cc3c33cc33c3cc3
	.quad	0xc33c3cc33cc3c33c,0x3cc3c33cc33c3cc3
	.quad	0x9966669966999966,0x6699996699666699
	.quad	0x9966669966999966,0x6699996699666699
	.quad	0x9966996699669966,0x6699669966996699
	.quad	0x6699669966996699,0x9966996699669966
	.quad	0x6969969669699696,0x6969969669699696
	.quad	0x6969969669699696,0x6969969669699696
	.quad	0xaa55aa5555aa55aa,0xaa55aa5555aa55aa
	.quad	0xaa55aa5555aa55aa,0xaa55aa5555aa55aa
	.quad	0x9966996699669966,0x9966996699669966
	.quad	0x6699669966996699,0x6699669966996699
	.quad	0x5aa5a55a5aa5a55a,0xa55a5aa5a55a5aa5
	.quad	0x5aa5a55a5aa5a55a,0xa55a5aa5a55a5aa5
	.quad	0xc3c3c3c33c3c3c3c,0xc3c3c3c33c3c3c3c
	.quad	0x3c3c3c3cc3c3c3c3,0x3c3c3c3cc3c3c3c3
	.quad	0x3cc33cc3c33cc33c,0x3cc33cc3c33cc33c
	.quad	0xc33cc33c3cc33cc3,0xc33cc33c3cc33cc3
	.quad	0x3333cccc3333cccc,0x3333cccc3333cccc
	.quad	0xcccc3333cccc3333,0xcccc3333cccc3333
	.quad	0x9999999966666666,0x6666666699999999
	.quad	0x6666666699999999,0x9999999966666666
	.quad	0xc33cc33cc33cc33c,0x3cc33cc33cc33cc3
	.quad	0xc33cc33cc33cc33c,0x3cc33cc33cc33cc3
	.quad	0x6666999999996666,0x9999666666669999
	.quad	0x9999666666669999,0x6666999999996666
	.quad	0xc33c3cc33cc3c33c,0x3cc3c33cc33c3cc3
	.quad	0xc33c3cc33cc3c33c,0x3cc3c33cc33c3cc3
	.quad	0x6699996699666699,0x9966669966999966
	.quad	0x6699996699666699,0x9966669966999966
	.quad	0x6699669966996699,0x9966996699669966
	.quad	0x9966996699669966,0x6699669966996699
	.quad	0x6969969669699696,0x6969969669699696
	.quad	0x6969969669699696,0x6969969669699696
	.quad	0x55aa55aaaa55aa55,0x55aa55aaaa55aa55
	.quad	0x55aa55aaaa55aa55,0x55aa55aaaa55aa55
	.quad	0x9966996699669966,0x9966996699669966
	.quad	0x6699669966996699,0x6699669966996699
	.quad	0x5aa5a55a5aa5a55a,0xa55a5aa5a55a5aa5
	.quad	0x5aa5a55a5aa5a55a,0xa55a5aa5a55a5aa5
	.quad	0xc3c3c3c33c3c3c3c,0xc3c3c3c33c3c3c3c
	.quad	0x3c3c3c3cc3c3c3c3,0x3c3c3c3cc3c3c3c3
	.quad	0xc33cc33c3cc33cc3,0xc33cc33c3cc33cc3
	.quad	0x3cc33cc3c33cc33c,0x3cc33cc3c33cc33c
	.quad	0x3333cccc3333cccc,0x3333cccc3333cccc
	.quad	0xcccc3333cccc3333,0xcccc3333cccc3333
	.quad	0x9999999966666666,0x6666666699999999
	.quad	0x6666666699999999,0x9999999966666666
	.quad	0xc33cc33cc33cc33c,0x3cc33cc33cc33cc3
	.quad	0xc33cc33cc33cc33c,0x3cc33cc33cc33cc3
	.quad	0x6666999999996666,0x9999666666669999
	.quad	0x9999666666669999,0x6666999999996666
	.quad	0x3c3cc3c3c3c33c3c,0xc3c33c3c3c3cc3c3
	.quad	0x3c3cc3c3c3c33c3c,0xc3c33c3c3c3cc3c3
	.quad	0x55555555aaaaaaaa,0x55555555aaaaaaaa
	.quad	0x55555555aaaaaaaa,0x55555555aaaaaaaa
	.quad	0xf00ff00f0ff00ff0,0x0ff00ff0f00ff00f
	.quad	0xf00ff00f0ff00ff0,0x0ff00ff0f00ff00f
	.quad	0x5aa55aa5a55aa55a,0x5aa55aa5a55aa55a
	.quad	0xa55aa55a5aa55aa5,0xa55aa55a5aa55aa5
	.quad	0x55aaaa55aa5555aa,0x55aaaa55aa5555aa
	.quad	0xaa5555aa55aaaa55,0xaa5555aa55aaaa55
	.quad	0xf00f0ff0f00f0ff0,0xf00f0ff0f00f0ff0
	.quad	0x0ff0f00f0ff0f00f,0x0ff0f00f0ff0f00f
	.quad	0x9669699696696996,0x9669699696696996
	.quad	0x9669699696696996,0x9669699696696996
	.quad	0xa55aa55aa55aa55a,0x5aa55aa55aa55aa5
	.quad	0x5aa55aa55aa55aa5,0xa55aa55aa55aa55a
	.quad	0x55555555aaaaaaaa,0x55555555aaaaaaaa
	.quad	0xaaaaaaaa55555555,0xaaaaaaaa55555555
	.quad	0xcccc33333333cccc,0x3333cccccccc3333
	.quad	0x3333cccccccc3333,0xcccc33333333cccc
	.quad	0x0000ffffffff0000,0x0000ffffffff0000
	.quad	0xffff00000000ffff,0xffff00000000ffff
	.quad	0xff0000ff00ffff00,0x00ffff00ff0000ff
	.quad	0xff0000ff00ffff00,0x00ffff00ff0000ff
	.quad	0x6996699669966996,0x9669966996699669
	.quad	0x9669966996699669,0x6996699669966996
	.quad	0x3c3cc3c3c3c33c3c,0xc3c33c3c3c3cc3c3
	.quad	0x3c3cc3c3c3c33c3c,0xc3c33c3c3c3cc3c3
	.quad	0x55555555aaaaaaaa,0x55555555aaaaaaaa
	.quad	0x55555555aaaaaaaa,0x55555555aaaaaaaa
	.quad	0x0ff00ff0f00ff00f,0xf00ff00f0ff00ff0
	.quad	0x0ff00ff0f00ff00f,0xf00ff00f0ff00ff0
	.quad	0xa55aa55a5aa55aa5,0xa55aa55a5aa55aa5
	.quad	0x5aa55aa5a55aa55a,0x5aa55aa5a55aa55a
	.quad	0xaa5555aa55aaaa55,0xaa5555aa55aaaa55
	.quad	0x55aaaa55aa5555aa,0x55aaaa55aa5555aa
	.quad	0x0ff0f00f0ff0f00f,0x0ff0f00f0ff0f00f
	.quad	0xf00f0ff0f00f0ff0,0xf00f0ff0f00f0ff0
	.quad	0x6996966969969669,0x6996966969969669
	.quad	0x6996966969969669,0x6996966969969669
	.quad	0xa55aa55aa55aa55a,0x5aa55aa55aa55aa5
	.quad	0x5aa55aa55aa55aa5,0xa55aa55aa55aa55a
	.quad	0xaaaaaaaa55555555,0xaaaaaaaa55555555
	.quad	0x55555555aaaaaaaa,0x55555555aaaaaaaa
	.quad	0xcccc33333333cccc,0x3333cccccccc3333
	.quad	0x3333cccccccc3333,0xcccc33333333cccc
	.quad	0x0000ffffffff0000,0x0000ffffffff0000
	.quad	0xffff00000000ffff,0xffff00000000ffff
	.quad	0xff0000ff00ffff00,0x00ffff00ff0000ff
	.quad	0xff0000ff00ffff00,0x00ffff00ff0000ff
	.quad	0x6996699669966996,0x9669966996699669
	.quad	0x9669966996699669,0x6996699669966996
	.quad	0x3c3cc3c3c3c33c3c,0xc3c33c3c3c3cc3c3
	.quad	0x3c3cc3c3c3c33c3c,0xc3c33c3c3c3cc3c3
	.quad	0xaaaaaaaa55555555,0xaaaaaaaa55555555
	.quad	0xaaaaaaaa55555555,0xaaaaaaaa55555555
	.quad	0x0ff00ff0f00ff00f,0xf00ff00f0ff00ff0
	.quad	0x0ff00ff0f00ff00f,0xf00ff00f0ff00ff0
	.quad	0x5aa55aa5a55aa55a,0x5aa55aa5a55aa55a
	.quad	0xa55aa55a5aa55aa5,0xa55aa55a5aa55aa5
	.quad	0xaa5555aa55aaaa55,0xaa5555aa55aaaa55
	.quad	0x55aaaa55aa5555aa,0x55aaaa55aa5555aa
	.quad	0xf00f0ff0f00f0ff0,0xf00f0ff0f00f0ff0
	.quad	0x0ff0f00f0ff0f00f,0x0ff0f00f0ff0f00f
	.quad	0x9669699696696996,0x9669699696696996
	.quad	0x9669699696696996,0x9669699696696996
	.quad	0xa55aa55aa55aa55a,0x5aa55aa55aa55aa5
	.quad	0x5aa55aa55aa55aa5,0xa55aa55aa55aa55a
	.quad	0x55555555aaaaaaaa,0x55555555aaaaaaaa
	.quad	0xaaaaaaaa55555555,0xaaaaaaaa55555555
	.quad	0xcccc33333333cccc,0x3333cccccccc3333
	.quad	0x3333cccccccc3333,0xcccc33333333cccc
	.quad	0x0000ffffffff0000,0x0000ffffffff0000
	.quad	0xffff00000000ffff,0xffff00000000ffff
	.quad	0xff0000ff00ffff00,0x00ffff00ff0000ff
	.quad	0xff0000ff00ffff00,0x00ffff00ff0000ff
	.quad	0x6996699669966996,0x9669966996699669
	.quad	0x9669966996699669,0x6996699669966996
	.quad	0x3c3cc3c3c3c33c3c,0xc3c33c3c3c3cc3c3
	.quad	0x3c3cc3c3c3c33c3c,0xc3c33c3c3c3cc3c3
	.quad	0xaaaaaaaa55555555,0xaaaaaaaa55555555
	.quad	0xaaaaaaaa55555555,0xaaaaaaaa55555555
	.quad	0xf00ff00f0ff00ff0,0x0ff00ff0f00ff00f
	.quad	0xf00ff00f0ff00ff0,0x0ff00ff0f00ff00f
	.quad	0xa55aa55a5aa55aa5,0xa55aa55a5aa55aa5
	.quad	0x5aa55aa5a55aa55a,0x5aa55aa5a55aa55a
	.quad	0x55aaaa55aa5555aa,0x55aaaa55aa5555aa
	.quad	0xaa5555aa55aaaa55,0xaa5555aa55aaaa55
	.quad	0x0ff0f00f0ff0f00f,0x0ff0f00f0ff0f00f
	.quad	0xf00f0ff0f00f0ff0,0xf00f0ff0f00f0ff0
	.quad	0x6996966969969669,0x6996966969969669
	.quad	0x6996966969969669,0x6996966969969669
	.quad	0xa55aa55aa55aa55a,0x5aa55aa55aa55aa5
	.quad	0x5aa55aa55aa55aa5,0xa55aa55aa55aa55a
	.quad	0xaaaaaaaa55555555,0xaaaaaaaa55555555
	.quad	0x55555555aaaaaaaa,0x55555555aaaaaaaa
	.quad	0xcccc33333333cccc,0x3333cccccccc3333
	.quad	0x3333cccccccc3333,0xcccc33333333cccc
	.quad	0x0000ffffffff0000,0x0000ffffffff0000
	.quad	0xffff00000000ffff,0xffff00000000ffff
	.quad	0xff0000ff00ffff00,0x00ffff00ff0000ff
	.quad	0xff0000ff00ffff00,0x00ffff00ff0000ff
	.quad	0x6996699669966996,0x9669966996699669
	.quad	0x9669966996699669,0x6996699669966996
	.quad	0x3cc3c33c3cc3c33c,0x3cc3c33c3cc3c33c
	.quad	0x3cc3c33c3cc3c33c,0x3cc3c33c3cc3c33c
	.quad	0xaaaaaaaaaaaaaaaa,0xaaaaaaaaaaaaaaaa
	.quad	0xaaaaaaaaaaaaaaaa,0xaaaaaaaaaaaaaaaa
	.quad	0xffff0000ffff0000,0xffff0000ffff0000
	.quad	0xffff0000ffff0000,0xffff0000ffff0000
	.quad	0x3cc3c33c3cc3c33c,0x3cc3c33c3cc3c33c
	.quad	0x3cc3c33c3cc3c33c,0x3cc3c33c3cc3c33c
	.quad	0x55aa55aa55aa55aa,0x55aa55aa55aa55aa
	.quad	0xaa55aa55aa55aa55,0xaa55aa55aa55aa55
	.quad	0xffff0000ffff0000,0x0000ffff0000ffff
	.quad	0x0000ffff0000ffff,0xffff0000ffff0000
	.quad	0x0f0f0f0ff0f0f0f0,0xf0f0f0f00f0f0f0f
	.quad	0xf0f0f0f00f0f0f0f,0x0f0f0f0ff0f0f0f0
	.quad	0xff0000ff00ffff00,0x00ffff00ff0000ff
	.quad	0x00ffff00ff0000ff,0xff0000ff00ffff00
	.quad	0x33cccc33cc3333cc,0xcc3333cc33cccc33
	.quad	0xcc3333cc33cccc33,0x33cccc33cc3333cc
	.quad	0xff0000ff00ffff00,0x00ffff00ff0000ff
	.quad	0xff0000ff00ffff00,0x00ffff00ff0000ff
	.quad	0x6996966996696996,0x9669699669969669
	.quad	0x6996966996696996,0x9669699669969669
	.quad	0xa55a5aa55aa5a55a,0xa55a5aa55aa5a55a
	.quad	0xa55a5aa55aa5a55a,0xa55a5aa55aa5a55a
	.quad	0x6996966996696996,0x6996966996696996
	.quad	0x6996966996696996,0x6996966996696996
	.quad	0x3cc3c33c3cc3c33c,0x3cc3c33c3cc3c33c
	.quad	0x3cc3c33c3cc3c33c,0x3cc3c33c3cc3c33c
	.quad	0xaaaaaaaaaaaaaaaa,0xaaaaaaaaaaaaaaaa
	.quad	0xaaaaaaaaaaaaaaaa,0xaaaaaaaaaaaaaaaa
	.quad	0xffff0000ffff0000,0xffff0000ffff0000
	.quad	0xffff0000ffff0000,0xffff0000ffff0000
	.quad	0xc33c3cc3c33c3cc3,0xc33c3cc3c33c3cc3
	.quad	0xc33c3cc3c33c3cc3,0xc33c3cc3c33c3cc3
	.quad	0xaa55aa55aa55aa55,0xaa55aa55aa55aa55
	.quad	0x55aa55aa55aa55aa,0x55aa55aa55aa55aa
	.quad	0x0000ffff0000ffff,0xffff0000ffff0000
	.quad	0xffff0000ffff0000,0x0000ffff0000ffff
	.quad	0xf0f0f0f00f0f0f0f,0x0f0f0f0ff0f0f0f0
	.quad	0x0f0f0f0ff0f0f0f0,0xf0f0f0f00f0f0f0f
	.quad	0xff0000ff00ffff00,0x00ffff00ff0000ff
	.quad	0x00ffff00ff0000ff,0xff0000ff00ffff00
	.quad	0x33cccc33cc3333cc,0xcc3333cc33cccc33
	.quad	0xcc3333cc33cccc33,0x33cccc33cc3333cc
	.quad	0xff0000ff00ffff00,0x00ffff00ff0000ff
	.quad	0xff0000ff00ffff00,0x00ffff00ff0000ff
	.quad	0x6996966996696996,0x9669699669969669
	.quad	0x6996966996696996,0x9669699669969669
	.quad	0xa55a5aa55aa5a55a,0xa55a5aa55aa5a55a
	.quad	0xa55a5aa55aa5a55a,0xa55a5aa55aa5a55a
	.quad	0x6996966996696996,0x6996966996696996
	.quad	0x6996966996696996,0x6996966996696996
	.quad	0x3cc3c33c3cc3c33c,0x3cc3c33c3cc3c33c
	.quad	0x3cc3c33c3cc3c33c,0x3cc3c33c3cc3c33c
	.quad	0xaaaaaaaaaaaaaaaa,0xaaaaaaaaaaaaaaaa
	.quad	0xaaaaaaaaaaaaaaaa,0xaaaaaaaaaaaaaaaa
	.quad	0x0000ffff0000ffff,0x0000ffff0000ffff
	.quad	0x0000ffff0000ffff,0x0000ffff0000ffff
	.quad	0xc33c3cc3c33c3cc3,0xc33c3cc3c33c3cc3
	.quad	0xc33c3cc3c33c3cc3,0xc33c3cc3c33c3cc3
	.quad	0xaa55aa55aa55aa55,0xaa55aa55aa55aa55
	.quad	0x55aa55aa55aa55aa,0x55aa55aa55aa55aa
	.quad	0xffff0000ffff0000,0x0000ffff0000ffff
	.quad	0x0000ffff0000ffff,0xffff0000ffff0000
	.quad	0x0f0f0f0ff0f0f0f0,0xf0f0f0f00f0f0f0f
	.quad	0xf0f0f0f00f0f0f0f,0x0f0f0f0ff0f0f0f0
	.quad	0xff0000ff00ffff00,0x00ffff00ff0000ff
	.quad	0x00ffff00ff0000ff,0xff0000ff00ffff00
	.quad	0x33cccc33cc3333cc,0xcc3333cc33cccc33
	.quad	0xcc3333cc33cccc33,0x33cccc33cc3333cc
	.quad	0xff0000ff00ffff00,0x00ffff00ff0000ff
	.quad	0xff0000ff00ffff00,0x00ffff00ff0000ff
	.quad	0x6996966996696996,0x9669699669969669
	.quad	0x6996966996696996,0x9669699669969669
	.quad	0xa55a5aa55aa5a55a,0xa55a5aa55aa5a55a
	.quad	0xa55a5aa55aa5a55a,0xa55a5aa55aa5a55a
	.quad	0x6996966996696996,0x6996966996696996
	.quad	0x6996966996696996,0x6996966996696996
	.quad	0x3cc3c33c3cc3c33c,0x3cc3c33c3cc3c33c
	.quad	0x3cc3c33c3cc3c33c,0x3cc3c33c3cc3c33c
	.quad	0xaaaaaaaaaaaaaaaa,0xaaaaaaaaaaaaaaaa
	.quad	0xaaaaaaaaaaaaaaaa,0xaaaaaaaaaaaaaaaa
	.quad	0x0000ffff0000ffff,0x0000ffff0000ffff
	.quad	0x0000ffff0000ffff,0x0000ffff0000ffff
	.quad	0x3cc3c33c3cc3c33c,0x3cc3c33c3cc3c33c
	.quad	0x3cc3c33c3cc3c33c,0x3cc3c33c3cc3c33c
	.quad	0x55aa55aa55aa55aa,0x55aa55aa55aa55aa
	.quad	0xaa55aa55aa55aa55,0xaa55aa55aa55aa55
	.quad	0x0000ffff0000ffff,0xffff0000ffff0000
	.quad	0xffff0000ffff0000,0x0000ffff0000ffff
	.quad	0xf0f0f0f00f0f0f0f,0x0f0f0f0ff0f0f0f0
	.quad	0x0f0f0f0ff0f0f0f0,0xf0f0f0f00f0f0f0f
	.quad	0xff0000ff00ffff00,0x00ffff00ff0000ff
	.quad	0x00ffff00ff0000ff,0xff0000ff00ffff00
	.quad	0x33cccc33cc3333cc,0xcc3333cc33cccc33
	.quad	0xcc3333cc33cccc33,0x33cccc33cc3333cc
	.quad	0xff0000ff00ffff00,0x00ffff00ff0000ff
	.quad	0xff0000ff00ffff00,0x00ffff00ff0000ff
	.quad	0x6996966996696996,0x9669699669969669
	.quad	0x6996966996696996,0x9669699669969669
	.quad	0xa55a5aa55aa5a55a,0xa55a5aa55aa5a55a
	.quad	0xa55a5aa55aa5a55a,0xa55a5aa55aa5a55a
	.quad	0x6996966996696996,0x6996966996696996
	.quad	0x6996966996696996,0x6996966996696996
	.quad	0x3cc3c33c3cc3c33c,0x3cc3c33c3cc3c33c
	.quad	0x3cc3c33c3cc3c33c,0x3cc3c33c3cc3c33c
	.quad	0x5555555555555555,0x5555555555555555
	.quad	0x5555555555555555,0x5555555555555555
	.quad	0x0000ffff0000ffff,0x0000ffff0000ffff
	.quad	0x0000ffff0000ffff,0x0000ffff0000ffff
	.quad	0x3cc3c33c3cc3c33c,0x3cc3c33c3cc3c33c
	.quad	0x3cc3c33c3cc3c33c,0x3cc3c33c3cc3c33c
	.quad	0x55aa55aa55aa55aa,0x55aa55aa55aa55aa
	.quad	0xaa55aa55aa55aa55,0xaa55aa55aa55aa55
	.quad	0xffff0000ffff0000,0x0000ffff0000ffff
	.quad	0x0000ffff0000ffff,0xffff0000ffff0000
	.quad	0x0f0f0f0ff0f0f0f0,0xf0f0f0f00f0f0f0f
	.quad	0xf0f0f0f00f0f0f0f,0x0f0f0f0ff0f0f0f0
	.quad	0xff0000ff00ffff00,0x00ffff00ff0000ff
	.quad	0x00ffff00ff0000ff,0xff0000ff00ffff00
	.quad	0x33cccc33cc3333cc,0xcc3333cc33cccc33
	.quad	0xcc3333cc33cccc33,0x33cccc33cc3333cc
	.quad	0xff0000ff00ffff00,0x00ffff00ff0000ff
	.quad	0xff0000ff00ffff00,0x00ffff00ff0000ff
	.quad	0x6996966996696996,0x9669699669969669
	.quad	0x6996966996696996,0x9669699669969669
	.quad	0xa55a5aa55aa5a55a,0xa55a5aa55aa5a55a
	.quad	0xa55a5aa55aa5a55a,0xa55a5aa55aa5a55a
	.quad	0x6996966996696996,0x6996966996696996
	.quad	0x6996966996696996,0x6996966996696996
	.quad	0x3cc3c33c3cc3c33c,0x3cc3c33c3cc3c33c
	.quad	0x3cc3c33c3cc3c33c,0x3cc3c33c3cc3c33c
	.quad	0x5555555555555555,0x5555555555555555
	.quad	0x5555555555555555,0x5555555555555555
	.quad	0x0000ffff0000ffff,0x0000ffff0000ffff
	.quad	0x0000ffff0000ffff,0x0000ffff0000ffff
	.quad	0xc33c3cc3c33c3cc3,0xc33c3cc3c33c3cc3
	.quad	0xc33c3cc3c33c3cc3,0xc33c3cc3c33c3cc3
	.quad	0xaa55aa55aa55aa55,0xaa55aa55aa55aa55
	.quad	0x55aa55aa55aa55aa,0x55aa55aa55aa55aa
	.quad	0x0000ffff0000ffff,0xffff0000ffff0000
	.quad	0xffff0000ffff0000,0x0000ffff0000ffff
	.quad	0xf0f0f0f00f0f0f0f,0x0f0f0f0ff0f0f0f0
	.quad	0x0f0f0f0ff0f0f0f0,0xf0f0f0f00f0f0f0f
	.quad	0xff0000ff00ffff00,0x00ffff00ff0000ff
	.quad	0x00ffff00ff0000ff,0xff0000ff00ffff00
	.quad	0x33cccc33cc3333cc,0xcc3333cc33cccc33
	.quad	0xcc3333cc33cccc33,0x33cccc33cc3333cc
	.quad	0xff0000ff00ffff00,0x00ffff00ff0000ff
	.quad	0xff0000ff00ffff00,0x00ffff00ff0000ff
	.quad	0x6996966996696996,0x9669699669969669
	.quad	0x6996966996696996,0x9669699669969669
	.quad	0xa55a5aa55aa5a55a,0xa55a5aa55aa5a55a
	.quad	0xa55a5aa55aa5a55a,0xa55a5aa55aa5a55a
	.quad	0x6996966996696996,0x6996966996696996
	.quad	0x6996966996696996,0x6996966996696996
	.quad	0x3cc3c33c3cc3c33c,0x3cc3c33c3cc3c33c
	.quad	0x3cc3c33c3cc3c33c,0x3cc3c33c3cc3c33c
	.quad	0x5555555555555555,0x5555555555555555
	.quad	0x5555555555555555,0x5555555555555555
	.quad	0xffff0000ffff0000,0xffff0000ffff0000
	.quad	0xffff0000ffff0000,0xffff0000ffff0000
	.quad	0xc33c3cc3c33c3cc3,0xc33c3cc3c33c3cc3
	.quad	0xc33c3cc3c33c3cc3,0xc33c3cc3c33c3cc3
	.quad	0xaa55aa55aa55aa55,0xaa55aa55aa55aa55
	.quad	0x55aa55aa55aa55aa,0x55aa55aa55aa55aa
	.quad	0xffff0000ffff0000,0x0000ffff0000ffff
	.quad	0x0000ffff0000ffff,0xffff0000ffff0000
	.quad	0x0f0f0f0ff0f0f0f0,0xf0f0f0f00f0f0f0f
	.quad	0xf0f0f0f00f0f0f0f,0x0f0f0f0ff0f0f0f0
	.quad	0xff0000ff00ffff00,0x00ffff00ff0000ff
	.quad	0x00ffff00ff0000ff,0xff0000ff00ffff00
	.quad	0x33cccc33cc3333cc,0xcc3333cc33cccc33
	.quad	0xcc3333cc33cccc33,0x33cccc33cc3333cc
	.quad	0xff0000ff00ffff00,0x00ffff00ff0000ff
	.quad	0xff0000ff00ffff00,0x00ffff00ff0000ff
	.quad	0x6996966996696996,0x9669699669969669
	.quad	0x6996966996696996,0x9669699669969669
	.quad	0xa55a5aa55aa5a55a,0xa55a5aa55aa5a55a
	.quad	0xa55a5aa55aa5a55a,0xa55a5aa55aa5a55a
	.quad	0x6996966996696996,0x6996966996696996
	.quad	0x6996966996696996,0x6996966996696996
	.quad	0x3cc3c33c3cc3c33c,0x3cc3c33c3cc3c33c
	.quad	0x3cc3c33c3cc3c33c,0x3cc3c33c3cc3c33c
	.quad	0x5555555555555555,0x5555555555555555
	.quad	0x5555555555555555,0x5555555555555555
	.quad	0xffff0000ffff0000,0xffff0000ffff0000
	.quad	0xffff0000ffff0000,0xffff0000ffff0000
	.quad	0x3cc3c33c3cc3c33c,0x3cc3c33c3cc3c33c
	.quad	0x3cc3c33c3cc3c33c,0x3cc3c33c3cc3c33c
	.quad	0x55aa55aa55aa55aa,0x55aa55aa55aa55aa
	.quad	0xaa55aa55aa55aa55,0xaa55aa55aa55aa55
	.quad	0x0000ffff0000ffff,0xffff0000ffff0000
	.quad	0xffff0000ffff0000,0x0000ffff0000ffff
	.quad	0xf0f0f0f00f0f0f0f,0x0f0f0f0ff0f0f0f0
	.quad	0x0f0f0f0ff0f0f0f0,0xf0f0f0f00f0f0f0f
	.quad	0xff0000ff00ffff00,0x00ffff00ff0000ff
	.quad	0x00ffff00ff0000ff,0xff0000ff00ffff00
	.quad	0x33cccc33cc3333cc,0xcc3333cc33cccc33
	.quad	0xcc3333cc33cccc33,0x33cccc33cc3333cc
	.quad	0xff0000ff00ffff00,0x00ffff00ff0000ff
	.quad	0xff0000ff00ffff00,0x00ffff00ff0000ff
	.quad	0x6996966996696996,0x9669699669969669
	.quad	0x6996966996696996,0x9669699669969669
	.quad	0xa55a5aa55aa5a55a,0xa55a5aa55aa5a55a
	.quad	0xa55a5aa55aa5a55a,0xa55a5aa55aa5a55a
	.quad	0x6996966996696996,0x6996966996696996
	.quad	0x6996966996696996,0x6996966996696996
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffff0000ffff0000,0xffff0000ffff0000
	.quad	0xffff0000ffff0000,0xffff0000ffff0000
	.quad	0xff00ff00ff00ff00,0xff00ff00ff00ff00
	.quad	0xff00ff00ff00ff00,0xff00ff00ff00ff00
	.quad	0xf0f0f0f0f0f0f0f0,0xf0f0f0f0f0f0f0f0
	.quad	0xf0f0f0f0f0f0f0f0,0xf0f0f0f0f0f0f0f0
	.quad	0xcccccccccccccccc,0xcccccccccccccccc
	.quad	0xcccccccccccccccc,0xcccccccccccccccc
	.quad	0xaaaaaaaaaaaaaaaa,0xaaaaaaaaaaaaaaaa
	.quad	0xaaaaaaaaaaaaaaaa,0xaaaaaaaaaaaaaaaa
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffff0000ffff0000,0xffff0000ffff0000
	.quad	0xffff0000ffff0000,0xffff0000ffff0000
	.quad	0xff00ff00ff00ff00,0xff00ff00ff00ff00
	.quad	0xff00ff00ff00ff00,0xff00ff00ff00ff00
	.quad	0xf0f0f0f0f0f0f0f0,0xf0f0f0f0f0f0f0f0
	.quad	0xf0f0f0f0f0f0f0f0,0xf0f0f0f0f0f0f0f0
	.quad	0xcccccccccccccccc,0xcccccccccccccccc
	.quad	0xcccccccccccccccc,0xcccccccccccccccc
	.quad	0xaaaaaaaaaaaaaaaa,0xaaaaaaaaaaaaaaaa
	.quad	0xaaaaaaaaaaaaaaaa,0xaaaaaaaaaaaaaaaa
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffff0000ffff0000,0xffff0000ffff0000
	.quad	0xffff0000ffff0000,0xffff0000ffff0000
	.quad	0xff00ff00ff00ff00,0xff00ff00ff00ff00
	.quad	0xff00ff00ff00ff00,0xff00ff00ff00ff00
	.quad	0xf0f0f0f0f0f0f0f0,0xf0f0f0f0f0f0f0f0
	.quad	0xf0f0f0f0f0f0f0f0,0xf0f0f0f0f0f0f0f0
	.quad	0xcccccccccccccccc,0xcccccccccccccccc
	.quad	0xcccccccccccccccc,0xcccccccccccccccc
	.quad	0xaaaaaaaaaaaaaaaa,0xaaaaaaaaaaaaaaaa
	.quad	0xaaaaaaaaaaaaaaaa,0xaaaaaaaaaaaaaaaa
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffff0000ffff0000,0xffff0000ffff0000
	.quad	0xffff0000ffff0000,0xffff0000ffff0000
	.quad	0xff00ff00ff00ff00,0xff00ff00ff00ff00
	.quad	0xff00ff00ff00ff00,0xff00ff00ff00ff00
	.quad	0xf0f0f0f0f0f0f0f0,0xf0f0f0f0f0f0f0f0
	.quad	0xf0f0f0f0f0f0f0f0,0xf0f0f0f0f0f0f0f0
	.quad	0xcccccccccccccccc,0xcccccccccccccccc
	.quad	0xcccccccccccccccc,0xcccccccccccccccc
	.quad	0xaaaaaaaaaaaaaaaa,0xaaaaaaaaaaaaaaaa
	.quad	0xaaaaaaaaaaaaaaaa,0xaaaaaaaaaaaaaaaa
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffff0000ffff0000,0xffff0000ffff0000
	.quad	0xffff0000ffff0000,0xffff0000ffff0000
	.quad	0xff00ff00ff00ff00,0xff00ff00ff00ff00
	.quad	0xff00ff00ff00ff00,0xff00ff00ff00ff00
	.quad	0xf0f0f0f0f0f0f0f0,0xf0f0f0f0f0f0f0f0
	.quad	0xf0f0f0f0f0f0f0f0,0xf0f0f0f0f0f0f0f0
	.quad	0xcccccccccccccccc,0xcccccccccccccccc
	.quad	0xcccccccccccccccc,0xcccccccccccccccc
	.quad	0xaaaaaaaaaaaaaaaa,0xaaaaaaaaaaaaaaaa
	.quad	0xaaaaaaaaaaaaaaaa,0xaaaaaaaaaaaaaaaa
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffff0000ffff0000,0xffff0000ffff0000
	.quad	0xffff0000ffff0000,0xffff0000ffff0000
	.quad	0xff00ff00ff00ff00,0xff00ff00ff00ff00
	.quad	0xff00ff00ff00ff00,0xff00ff00ff00ff00
	.quad	0xf0f0f0f0f0f0f0f0,0xf0f0f0f0f0f0f0f0
	.quad	0xf0f0f0f0f0f0f0f0,0xf0f0f0f0f0f0f0f0
	.quad	0xcccccccccccccccc,0xcccccccccccccccc
	.quad	0xcccccccccccccccc,0xcccccccccccccccc
	.quad	0xaaaaaaaaaaaaaaaa,0xaaaaaaaaaaaaaaaa
	.quad	0xaaaaaaaaaaaaaaaa,0xaaaaaaaaaaaaaaaa
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffff0000ffff0000,0xffff0000ffff0000
	.quad	0xffff0000ffff0000,0xffff0000ffff0000
	.quad	0xff00ff00ff00ff00,0xff00ff00ff00ff00
	.quad	0xff00ff00ff00ff00,0xff00ff00ff00ff00
	.quad	0xf0f0f0f0f0f0f0f0,0xf0f0f0f0f0f0f0f0
	.quad	0xf0f0f0f0f0f0f0f0,0xf0f0f0f0f0f0f0f0
	.quad	0xcccccccccccccccc,0xcccccccccccccccc
	.quad	0xcccccccccccccccc,0xcccccccccccccccc
	.quad	0xaaaaaaaaaaaaaaaa,0xaaaaaaaaaaaaaaaa
	.quad	0xaaaaaaaaaaaaaaaa,0xaaaaaaaaaaaaaaaa
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffff0000ffff0000,0xffff0000ffff0000
	.quad	0xffff0000ffff0000,0xffff0000ffff0000
	.quad	0xff00ff00ff00ff00,0xff00ff00ff00ff00
	.quad	0xff00ff00ff00ff00,0xff00ff00ff00ff00
	.quad	0xf0f0f0f0f0f0f0f0,0xf0f0f0f0f0f0f0f0
	.quad	0xf0f0f0f0f0f0f0f0,0xf0f0f0f0f0f0f0f0
	.quad	0xcccccccccccccccc,0xcccccccccccccccc
	.quad	0xcccccccccccccccc,0xcccccccccccccccc
	.quad	0xaaaaaaaaaaaaaaaa,0xaaaaaaaaaaaaaaaa
	.quad	0xaaaaaaaaaaaaaaaa,0xaaaaaaaaaaaaaaaa
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffff0000ffff0000,0xffff0000ffff0000
	.quad	0xffff0000ffff0000,0xffff0000ffff0000
	.quad	0xff00ff00ff00ff00,0xff00ff00ff00ff00
	.quad	0xff00ff00ff00ff00,0xff00ff00ff00ff00
	.quad	0xf0f0f0f0f0f0f0f0,0xf0f0f0f0f0f0f0f0
	.quad	0xf0f0f0f0f0f0f0f0,0xf0f0f0f0f0f0f0f0
	.quad	0xcccccccccccccccc,0xcccccccccccccccc
	.quad	0xcccccccccccccccc,0xcccccccccccccccc
	.quad	0xaaaaaaaaaaaaaaaa,0xaaaaaaaaaaaaaaaa
	.quad	0xaaaaaaaaaaaaaaaa,0xaaaaaaaaaaaaaaaa
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffff0000ffff0000,0xffff0000ffff0000
	.quad	0xffff0000ffff0000,0xffff0000ffff0000
	.quad	0xff00ff00ff00ff00,0xff00ff00ff00ff00
	.quad	0xff00ff00ff00ff00,0xff00ff00ff00ff00
	.quad	0xf0f0f0f0f0f0f0f0,0xf0f0f0f0f0f0f0f0
	.quad	0xf0f0f0f0f0f0f0f0,0xf0f0f0f0f0f0f0f0
	.quad	0xcccccccccccccccc,0xcccccccccccccccc
	.quad	0xcccccccccccccccc,0xcccccccccccccccc
	.quad	0xaaaaaaaaaaaaaaaa,0xaaaaaaaaaaaaaaaa
	.quad	0xaaaaaaaaaaaaaaaa,0xaaaaaaaaaaaaaaaa
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffff0000ffff0000,0xffff0000ffff0000
	.quad	0xffff0000ffff0000,0xffff0000ffff0000
	.quad	0xff00ff00ff00ff00,0xff00ff00ff00ff00
	.quad	0xff00ff00ff00ff00,0xff00ff00ff00ff00
	.quad	0xf0f0f0f0f0f0f0f0,0xf0f0f0f0f0f0f0f0
	.quad	0xf0f0f0f0f0f0f0f0,0xf0f0f0f0f0f0f0f0
	.quad	0xcccccccccccccccc,0xcccccccccccccccc
	.quad	0xcccccccccccccccc,0xcccccccccccccccc
	.quad	0xaaaaaaaaaaaaaaaa,0xaaaaaaaaaaaaaaaa
	.quad	0xaaaaaaaaaaaaaaaa,0xaaaaaaaaaaaaaaaa
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffff0000ffff0000,0xffff0000ffff0000
	.quad	0xffff0000ffff0000,0xffff0000ffff0000
	.quad	0xff00ff00ff00ff00,0xff00ff00ff00ff00
	.quad	0xff00ff00ff00ff00,0xff00ff00ff00ff00
	.quad	0xf0f0f0f0f0f0f0f0,0xf0f0f0f0f0f0f0f0
	.quad	0xf0f0f0f0f0f0f0f0,0xf0f0f0f0f0f0f0f0
	.quad	0xcccccccccccccccc,0xcccccccccccccccc
	.quad	0xcccccccccccccccc,0xcccccccccccccccc
	.quad	0xaaaaaaaaaaaaaaaa,0xaaaaaaaaaaaaaaaa
	.quad	0xaaaaaaaaaaaaaaaa,0xaaaaaaaaaaaaaaaa
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffff0000ffff0000,0xffff0000ffff0000
	.quad	0xffff0000ffff0000,0xffff0000ffff0000
	.quad	0xff00ff00ff00ff00,0xff00ff00ff00ff00
	.quad	0xff00ff00ff00ff00,0xff00ff00ff00ff00
	.quad	0xf0f0f0f0f0f0f0f0,0xf0f0f0f0f0f0f0f0
	.quad	0xf0f0f0f0f0f0f0f0,0xf0f0f0f0f0f0f0f0
	.quad	0xcccccccccccccccc,0xcccccccccccccccc
	.quad	0xcccccccccccccccc,0xcccccccccccccccc
	.quad	0xaaaaaaaaaaaaaaaa,0xaaaaaaaaaaaaaaaa
	.quad	0xaaaaaaaaaaaaaaaa,0xaaaaaaaaaaaaaaaa
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffff0000ffff0000,0xffff0000ffff0000
	.quad	0xffff0000ffff0000,0xffff0000ffff0000
	.quad	0xff00ff00ff00ff00,0xff00ff00ff00ff00
	.quad	0xff00ff00ff00ff00,0xff00ff00ff00ff00
	.quad	0xf0f0f0f0f0f0f0f0,0xf0f0f0f0f0f0f0f0
	.quad	0xf0f0f0f0f0f0f0f0,0xf0f0f0f0f0f0f0f0
	.quad	0xcccccccccccccccc,0xcccccccccccccccc
	.quad	0xcccccccccccccccc,0xcccccccccccccccc
	.quad	0xaaaaaaaaaaaaaaaa,0xaaaaaaaaaaaaaaaa
	.quad	0xaaaaaaaaaaaaaaaa,0xaaaaaaaaaaaaaaaa
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffff0000ffff0000,0xffff0000ffff0000
	.quad	0xffff0000ffff0000,0xffff0000ffff0000
	.quad	0xff00ff00ff00ff00,0xff00ff00ff00ff00
	.quad	0xff00ff00ff00ff00,0xff00ff00ff00ff00
	.quad	0xf0f0f0f0f0f0f0f0,0xf0f0f0f0f0f0f0f0
	.quad	0xf0f0f0f0f0f0f0f0,0xf0f0f0f0f0f0f0f0
	.quad	0xcccccccccccccccc,0xcccccccccccccccc
	.quad	0xcccccccccccccccc,0xcccccccccccccccc
	.quad	0xaaaaaaaaaaaaaaaa,0xaaaaaaaaaaaaaaaa
	.quad	0xaaaaaaaaaaaaaaaa,0xaaaaaaaaaaaaaaaa
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffff0000ffff0000,0xffff0000ffff0000
	.quad	0xffff0000ffff0000,0xffff0000ffff0000
	.quad	0xff00ff00ff00ff00,0xff00ff00ff00ff00
	.quad	0xff00ff00ff00ff00,0xff00ff00ff00ff00
	.quad	0xf0f0f0f0f0f0f0f0,0xf0f0f0f0f0f0f0f0
	.quad	0xf0f0f0f0f0f0f0f0,0xf0f0f0f0f0f0f0f0
	.quad	0xcccccccccccccccc,0xcccccccccccccccc
	.quad	0xcccccccccccccccc,0xcccccccccccccccc
	.quad	0xaaaaaaaaaaaaaaaa,0xaaaaaaaaaaaaaaaa
	.quad	0xaaaaaaaaaaaaaaaa,0xaaaaaaaaaaaaaaaa
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mc_aff_scal2x_neon, %object
	.size	L_mc_aff_scal2x_neon, 1040
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 16-byte aligned, 128-bit aligned
#ifndef __APPLE__
	.align	4
#else
	.p2align	4
#endif /* __APPLE__ */
L_mc_aff_scal2x_neon:
	.quad	0x3c3cf30c0000c003,0x0c0f0fcf0f0cf330
	.quad	0x0cccc3f333c0000c,0xf0000fc33c3ccf3c
	.quad	0x03c33f33fcc0c03c,0x3c0f3f00c3c300fc
	.quad	0x0003000f3c03c0c0,0x3c33ccc0f0f3cc30
	.quad	0xf33ff33030cf03f0,0xc0cfffffcccc30cc
	.quad	0x0cf0303300f0ccc0,0x3fc3f3ccfffc033f
	.quad	0xff3f0c0cc0ff3cc0,0xfc3030ccccc0cfcf
	.quad	0xcf3cf0ff003fc000,0x0fcf0c00ccf333c3
	.quad	0xc00ff3cf0303f300,0xcffcf33000cff030
	.quad	0x3ccc0cc00cf0cc00,0x00cffcc330f30fcc
	.quad	0xf30ffc3c3fccfc00,0x3ccc3fccc0f3fff3
	.quad	0x3f0fc3f0ccf0c000,0xf00f0c3fc003c0ff
	.quad	0x3000ff33ccf0f000,0x330ccfcc03c0fc33
	.quad	0x0f0f0ff0f000000f,0xf0fffffff0f00f00
	.quad	0x00ffffffff0000f0,0x00fff0ffff0000ff
	.quad	0xffff00ff00000f00,0x00ff00000f0f0fff
	.quad	0xfff000f00f0ff000,0xf000f0000f00ff0f
	.quad	0xfff0000f0ff000f0,0xff000000fff00000
	.quad	0x00ff000fff000000,0xf0ff000ff00f0ff0
	.quad	0xff0f0fff0f0ff000,0x0f0f0f00ff000f0f
	.quad	0x0fff0000000f0000,0x0f0f00f0f0f0f000
	.quad	0x00f000f0fff00f00,0x00f00f00f00f000f
	.quad	0x00f00ff00f00f000,0x00f0f0f00000fff0
	.quad	0xfff000f000f00000,0xffffff0ff00f0fff
	.quad	0x00f00f000ff00000,0x0f0ffff00fffffff
	.quad	0x0000ff0f0000f000,0xffff0f0fff0fff00
	.quad	0x00ff0000000000ff,0x00ff00ff00ff0000
	.quad	0xffffffffff00ff00,0xff00ffff000000ff
	.quad	0xff0000ff00ff0000,0x0000ffff000000ff
	.quad	0xffff000000ff0000,0x00ffff00ff000000
	.quad	0xff00000000ff0000,0xffffff0000ff00ff
	.quad	0x00ffffffff000000,0x0000ffff00ffff00
	.quad	0xff0000ffffff0000,0xff00ff0000ffff00
	.quad	0xff00ff00ffff0000,0x00000000ffffffff
	.quad	0x00ffffffff00ff00,0x0000ff0000000000
	.quad	0xffff000000000000,0xff00ffff00ffff00
	.quad	0x00ff0000ff000000,0x00ffff00000000ff
	.quad	0xff00ff00ff000000,0x0000ff00ff00ffff
	.quad	0x00ff00ffff000000,0xff0000ffffff0000
	.quad	0x000000000000ffff,0x0000ffff00000000
	.quad	0xffffffffffff0000,0xffffffff0000ffff
	.quad	0x0000000000000000,0x00000000ffffffff
	.quad	0xffff0000ffff0000,0x0000000000000000
	.quad	0xffffffffffff0000,0x0000ffff00000000
	.quad	0x0000ffff00000000,0xffff0000ffff0000
	.quad	0x0000ffffffff0000,0x0000ffffffff0000
	.quad	0xffff0000ffff0000,0x0000ffff0000ffff
	.quad	0x0000ffff00000000,0xffffffff0000ffff
	.quad	0xffff000000000000,0x00000000ffff0000
	.quad	0xffff000000000000,0xffff0000ffffffff
	.quad	0xffff000000000000,0xffff0000ffffffff
	.quad	0xffffffff00000000,0x0000000000000000
	.quad	0x00000000ffffffff,0x0000000000000000
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0xffffffff00000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0xffffffff00000000,0x00000000ffffffff
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffffffff00000000,0x0000000000000000
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0xffffffff00000000,0x00000000ffffffff
	.quad	0x0000000000000000,0xffffffff00000000
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0xffffffff00000000,0xffffffff00000000
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mc_aff_scal4x_neon, %object
	.size	L_mc_aff_scal4x_neon, 2496
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 16-byte aligned, 128-bit aligned
#ifndef __APPLE__
	.align	4
#else
	.p2align	4
#endif /* __APPLE__ */
L_mc_aff_scal4x_neon:
	.quad	0x3c3cf30c0000c003,0x0c0f0fcf0f0cf330
	.quad	0xf0f30c33cf03f03f,0x3f30cc0c000f3fcc
	.quad	0x0cccc3f333c0000c,0xf0000fc33c3ccf3c
	.quad	0x00f30fc00c3300ff,0xfc3cf030fc3fff03
	.quad	0x03c33f33fcc0c03c,0x3c0f3f00c3c300fc
	.quad	0xf3cc3cf3f3fcf33f,0x33fffcff0ccf3cc3
	.quad	0x0003000f3c03c0c0,0x3c33ccc0f0f3cc30
	.quad	0x3c0fc0fc303c3f3c,0x003cff33c3cc30cf
	.quad	0xf33ff33030cf03f0,0xc0cfffffcccc30cc
	.quad	0xfc30cf303f3ff00f,0xcff3cf33c00f3003
	.quad	0x0cf0303300f0ccc0,0x3fc3f3ccfffc033f
	.quad	0x33300c0cc3300cf3,0x00f3cc0cf3003ccf
	.quad	0xff3f0c0cc0ff3cc0,0xfc3030ccccc0cfcf
	.quad	0x3c030cf3f03ff3f3,0x3c000cfccc3c3333
	.quad	0xcf3cf0ff003fc000,0x0fcf0c00ccf333c3
	.quad	0x3ccc03fccc3ffc03,0xf3cf03c0fcf03ff0
	.quad	0xc00ff3cf0303f300,0xcffcf33000cff030
	.quad	0x033c3c3cf0003fc3,0x3f3c3cf0c330330c
	.quad	0x3ccc0cc00cf0cc00,0x00cffcc330f30fcc
	.quad	0xffc0ff00f0ff0f03,0x33ccfcc0ff0033f0
	.quad	0xf30ffc3c3fccfc00,0x3ccc3fccc0f3fff3
	.quad	0xf3f30cf003fcc303,0x33c300c0f0c003f3
	.quad	0x3f0fc3f0ccf0c000,0xf00f0c3fc003c0ff
	.quad	0x30cfcfc3cc0f3000,0x003ff0003f00c00c
	.quad	0x3000ff33ccf0f000,0x330ccfcc03c0fc33
	.quad	0x0cf30ccf3fcfcc0f,0xcff3c3033f030fff
	.quad	0x0f0f0ff0f000000f,0xf0fffffff0f00f00
	.quad	0x0f0f00ff0ff0ffff,0xff0f0f00f000f0ff
	.quad	0x00ffffffff0000f0,0x00fff0ffff0000ff
	.quad	0xf000f0f00f00ff0f,0x0fffffffff00000f
	.quad	0xffff00ff00000f00,0x00ff00000f0f0fff
	.quad	0x000ffff0fff0ff0f,0xf0ffff000f00f0ff
	.quad	0xfff000f00f0ff000,0xf000f0000f00ff0f
	.quad	0x00f00fff00000ff0,0x0f0000f00fff0fff
	.quad	0xfff0000f0ff000f0,0xff000000fff00000
	.quad	0xfffff0000ffff00f,0x0f0f0f00ff0f000f
	.quad	0x00ff000fff000000,0xf0ff000ff00f0ff0
	.quad	0xfff0fff0000ffff0,0x000f0f0ffff0f000
	.quad	0xff0f0fff0f0ff000,0x0f0f0f00ff000f0f
	.quad	0xf0f0f0000f0f0f00,0xf0ffff0f00f0ff0f
	.quad	0x0fff0000000f0000,0x0f0f00f0f0f0f000
	.quad	0x00f000f0f00fff00,0x0f0f000f0f00f0ff
	.quad	0x00f000f0fff00f00,0x00f00f00f00f000f
	.quad	0xf0ff0f0fff00f0ff,0x0000f0ff00ff0f0f
	.quad	0x00f00ff00f00f000,0x00f0f0f00000fff0
	.quad	0xf0ff0ffff0f0f0ff,0x00ffff0ff0fff0f0
	.quad	0xfff000f000f00000,0xffffff0ff00f0fff
	.quad	0x00fffffffffffff0,0x0000000f00f0fff0
	.quad	0x00f00f000ff00000,0x0f0ffff00fffffff
	.quad	0x00fff0f0ff000f0f,0xf0f00000ff00f0f0
	.quad	0x0000ff0f0000f000,0xffff0f0fff0fff00
	.quad	0x000ffff0000fff00,0x0f0f0fffffffffff
	.quad	0x00ff0000000000ff,0x00ff00ff00ff0000
	.quad	0xffff00ff00ff00ff,0xff0000ffffff00ff
	.quad	0xffffffffff00ff00,0xff00ffff000000ff
	.quad	0x00ffff000000ff00,0xffff0000ffffffff
	.quad	0xff0000ff00ff0000,0x0000ffff000000ff
	.quad	0xffff00ffffffff00,0xffff000000ffffff
	.quad	0xffff000000ff0000,0x00ffff00ff000000
	.quad	0x0000ffff00ffffff,0x00ffff00ff0000ff
	.quad	0xff00000000ff0000,0xffffff0000ff00ff
	.quad	0x00ff0000ff0000ff,0xffffff00ffffff00
	.quad	0x00ffffffff000000,0x0000ffff00ffff00
	.quad	0xffff0000ff00ffff,0x00ffff00ffff00ff
	.quad	0xff0000ffffff0000,0xff00ff0000ffff00
	.quad	0xff000000ffffff00,0x0000ffff00ff0000
	.quad	0xff00ff00ffff0000,0x00000000ffffffff
	.quad	0x000000000000ffff,0x000000ffff000000
	.quad	0x00ffffffff00ff00,0x0000ff0000000000
	.quad	0xff00ff00ffff0000,0xff00ff0000ff00ff
	.quad	0xffff000000000000,0xff00ffff00ffff00
	.quad	0xffff00ffff00ffff,0x00ff0000000000ff
	.quad	0x00ff0000ff000000,0x00ffff00000000ff
	.quad	0xffffffffff00ff00,0xff00ffff00ff00ff
	.quad	0xff00ff00ff000000,0x0000ff00ff00ffff
	.quad	0xffff00ffff0000ff,0xffffffffffffffff
	.quad	0x00ff00ffff000000,0xff0000ffffff0000
	.quad	0x0000ff00000000ff,0x0000ff000000ffff
	.quad	0x000000000000ffff,0x0000ffff00000000
	.quad	0xffffffffffffffff,0x0000ffffffffffff
	.quad	0xffffffffffff0000,0xffffffff0000ffff
	.quad	0xffffffff00000000,0x0000ffff0000ffff
	.quad	0x0000000000000000,0x00000000ffffffff
	.quad	0xffff000000000000,0x0000ffffffff0000
	.quad	0xffff0000ffff0000,0x0000000000000000
	.quad	0x0000ffff00000000,0xffff0000ffffffff
	.quad	0xffffffffffff0000,0x0000ffff00000000
	.quad	0x00000000ffff0000,0x00000000ffff0000
	.quad	0x0000ffff00000000,0xffff0000ffff0000
	.quad	0x0000ffffffffffff,0xffff00000000ffff
	.quad	0x0000ffffffff0000,0x0000ffffffff0000
	.quad	0x0000ffffffffffff,0x0000ffff0000ffff
	.quad	0xffff0000ffff0000,0x0000ffff0000ffff
	.quad	0xffffffff00000000,0xffff00000000ffff
	.quad	0x0000ffff00000000,0xffffffff0000ffff
	.quad	0x000000000000ffff,0x0000ffff0000ffff
	.quad	0xffff000000000000,0x00000000ffff0000
	.quad	0x000000000000ffff,0x0000ffff00000000
	.quad	0xffff000000000000,0xffff0000ffffffff
	.quad	0xffffffffffff0000,0xffffffff00000000
	.quad	0xffff000000000000,0xffff0000ffffffff
	.quad	0xffffffff0000ffff,0x0000ffffffff0000
	.quad	0xffffffff00000000,0x0000000000000000
	.quad	0xffff0000ffffffff,0x0000ffffffffffff
	.quad	0x00000000ffffffff,0x0000000000000000
	.quad	0x00000000ffffffff,0xffffffffffffffff
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0xffffffff00000000,0x00000000ffffffff
	.quad	0xffffffff00000000,0x0000000000000000
	.quad	0xffffffff00000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0xffffffff00000000,0x00000000ffffffff
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffffffffffffffff,0x0000000000000000
	.quad	0xffffffff00000000,0x0000000000000000
	.quad	0xffffffffffffffff,0xffffffff00000000
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0x0000000000000000,0x00000000ffffffff
	.quad	0xffffffff00000000,0x00000000ffffffff
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0x0000000000000000,0xffffffff00000000
	.quad	0x00000000ffffffff,0x0000000000000000
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0xffffffffffffffff,0xffffffff00000000
	.quad	0xffffffff00000000,0xffffffff00000000
	.quad	0xffffffffffffffff,0xffffffff00000000
	.quad	0xffffffffffffffff,0x0000000000000000
	.quad	0xffffffffffffffff,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0xffffffffffffffff,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0xffffffffffffffff,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0xffffffffffffffff,0xffffffffffffffff
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0x0000000000000000,0xffffffffffffffff
	.quad	0xffffffffffffffff,0x0000000000000000
	.quad	0x0000000000000000,0x0000000000000000
	.quad	0xffffffffffffffff,0xffffffffffffffff
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mc_bs_powers_neon, %object
	.size	L_mc_bs_powers_neon, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mc_bs_powers_neon:
	.short	0x0001,0x0002,0x0004,0x0008,0x0010,0x0020,0x0040,0x0080
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mc_aff_rmask0_neon, %object
	.size	L_mc_aff_rmask0_neon, 40
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 16-byte aligned, 128-bit aligned
#ifndef __APPLE__
	.align	4
#else
	.p2align	4
#endif /* __APPLE__ */
L_mc_aff_rmask0_neon:
	.quad	0x8888888888888888,0xc0c0c0c0c0c0c0c0
	.quad	0xf000f000f000f000,0xff000000ff000000
	.quad	0xffff000000000000
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mc_aff_rmask1_neon, %object
	.size	L_mc_aff_rmask1_neon, 40
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 16-byte aligned, 128-bit aligned
#ifndef __APPLE__
	.align	4
#else
	.p2align	4
#endif /* __APPLE__ */
L_mc_aff_rmask1_neon:
	.quad	0x4444444444444444,0x3030303030303030
	.quad	0x0f000f000f000f00,0x00ff000000ff0000
	.quad	0x0000ffff00000000
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mc_aff_tmask0_neon, %object
	.size	L_mc_aff_tmask0_neon, 48
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 16-byte aligned, 128-bit aligned
#ifndef __APPLE__
	.align	4
#else
	.p2align	4
#endif /* __APPLE__ */
L_mc_aff_tmask0_neon:
	.quad	0x2222222222222222,0x0c0c0c0c0c0c0c0c
	.quad	0x00f000f000f000f0,0x0000ff000000ff00
	.quad	0x00000000ffff0000,0xffffffff00000000
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mc_aff_tmask1_neon, %object
	.size	L_mc_aff_tmask1_neon, 48
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 16-byte aligned, 128-bit aligned
#ifndef __APPLE__
	.align	4
#else
	.p2align	4
#endif /* __APPLE__ */
L_mc_aff_tmask1_neon:
	.quad	0x4444444444444444,0x3030303030303030
	.quad	0x0f000f000f000f00,0x00ff000000ff0000
	.quad	0x0000ffff00000000,0x00000000ffffffff
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_mc_aff_reversal_neon, %object
	.size	L_mc_aff_reversal_neon, 64
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_mc_aff_reversal_neon:
	.byte	0x00,0x20,0x10,0x30,0x08,0x28,0x18,0x38
	.byte	0x04,0x24,0x14,0x34,0x0c,0x2c,0x1c,0x3c
	.byte	0x02,0x22,0x12,0x32,0x0a,0x2a,0x1a,0x3a
	.byte	0x06,0x26,0x16,0x36,0x0e,0x2e,0x1e,0x3e
	.byte	0x01,0x21,0x11,0x31,0x09,0x29,0x19,0x39
	.byte	0x05,0x25,0x15,0x35,0x0d,0x2d,0x1d,0x3d
	.byte	0x03,0x23,0x13,0x33,0x0b,0x2b,0x1b,0x3b
	.byte	0x07,0x27,0x17,0x37,0x0f,0x2f,0x1f,0x3f
#ifndef WOLFSSL_MCELIECE_NO_ENCAPSULATE
#ifndef WOLFSSL_MCELIECE_SMALL
#ifndef __APPLE__
.text
.globl	wc_mceliece_encap_fixedweight_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_encap_fixedweight_neon)
.type	wc_mceliece_encap_fixedweight_neon,@function
.align	2
wc_mceliece_encap_fixedweight_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_encap_fixedweight_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_encap_fixedweight_neon)
.p2align	2
_wc_mceliece_encap_fixedweight_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-64]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #16]
	stp	x20, x21, [x29, #32]
	stp	x22, x23, [x29, #48]
	mov	w6, w3
	mov	w7, w4
	mov	w8, w5
	mov	w9, w2
	lsl	x10, x8, #1
	mov	x11, #0
L_mc_fw_retry:
	add	x20, x11, x10
	cmp	x20, x9
	bgt	L_mc_fw_depl
	add	x12, x0, x11
	mov	x13, #0
	mov	x14, #0
L_mc_fw_filter:
	cmp	x14, x8
	bge	L_mc_fw_filterd
	cmp	x13, x7
	bge	L_mc_fw_filterd
	lsl	x20, x14, #1
	add	x20, x12, x20
	ldrh	w21, [x20]
	and	x21, x21, #0x1fff
	lsl	x22, x13, #1
	add	x22, x1, x22
	strh	w21, [x22]
	cmp	x21, x6
	cinc	x13, x13, lt
	add	x14, x14, #1
	b	L_mc_fw_filter
L_mc_fw_filterd:
	add	x11, x11, x10
	cmp	x13, x7
	blt	L_mc_fw_retry
	mov	x17, #0
	mov	x14, #1
L_mc_fw_dupi:
	cmp	x14, x7
	bge	L_mc_fw_dupd
	lsl	x20, x14, #1
	add	x20, x1, x20
	ldrh	w16, [x20]
	dup	v0.8h, w16
	eor	v1.16b, v1.16b, v1.16b
	mov	x15, #0
L_mc_fw_dupj8:
	add	x20, x15, #8
	cmp	x20, x14
	bgt	L_mc_fw_duprem
	lsl	x21, x15, #1
	add	x21, x1, x21
	ld1	{v2.8h}, [x21]
	cmeq	v2.8h, v2.8h, v0.8h
	orr	v1.16b, v1.16b, v2.16b
	add	x15, x15, #8
	b	L_mc_fw_dupj8
L_mc_fw_duprem:
	umaxv	h2, v1.8h
	umov	w21, v2.h[0]
	orr	x17, x17, x21
L_mc_fw_duprem1:
	cmp	x15, x14
	bge	L_mc_fw_dupie
	lsl	x20, x15, #1
	add	x20, x1, x20
	ldrh	w21, [x20]
	cmp	x21, x16
	cinc	x17, x17, eq
	add	x15, x15, #1
	b	L_mc_fw_duprem1
L_mc_fw_dupie:
	add	x14, x14, #1
	b	L_mc_fw_dupi
L_mc_fw_dupd:
	cbnz	x17, L_mc_fw_retry
	mov	x19, #0
	b	L_mc_fw_ret
L_mc_fw_depl:
	mov	x19, #2
L_mc_fw_ret:
	mov	x0, x19
	ldp	x17, x19, [x29, #16]
	ldp	x20, x21, [x29, #32]
	ldp	x22, x23, [x29, #48]
	ldp	x29, x30, [sp], #0x40
	ret
#ifndef __APPLE__
	.size	wc_mceliece_encap_fixedweight_neon,.-wc_mceliece_encap_fixedweight_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_encap_scatter_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_encap_scatter_neon)
.type	wc_mceliece_encap_scatter_neon,@function
.align	2
wc_mceliece_encap_scatter_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_encap_scatter_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_encap_scatter_neon)
.p2align	2
_wc_mceliece_encap_scatter_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-32]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	mov	w4, w2
	mov	w5, w3
	mov	x10, #1
	dup	v6.2d, x10
	mov	x10, #63
	dup	v7.2d, x10
	mov	x6, #0
L_mc_sc_w:
	cmp	x6, x5
	bge	L_mc_sc_end
	eor	v0.16b, v0.16b, v0.16b
	dup	v8.2d, x6
	mov	x7, #0
	mov	x8, x1
L_mc_sc_j2:
	add	x10, x7, #2
	cmp	x10, x4
	bgt	L_mc_sc_jtail
	ldr	s1, [x8], #4
	ushll	v1.4s, v1.4h, #0
	ushll	v1.2d, v1.2s, #0
	and	v2.16b, v1.16b, v7.16b
	ushr	v3.2d, v1.2d, #6
	ushl	v4.2d, v6.2d, v2.2d
	cmeq	v5.2d, v3.2d, v8.2d
	and	v4.16b, v4.16b, v5.16b
	orr	v0.16b, v0.16b, v4.16b
	add	x7, x7, #2
	b	L_mc_sc_j2
L_mc_sc_jtail:
	umov	x9, v0.d[0]
	umov	x10, v0.d[1]
	orr	x9, x9, x10
	cmp	x7, x4
	bge	L_mc_sc_store
L_mc_sc_tail1:
	ldrh	w10, [x8]
	add	x8, x8, #2
	and	x11, x10, #63
	lsr	x12, x10, #6
	mov	x13, #1
	lsl	x13, x13, x11
	cmp	x12, x6
	csel	x13, x13, xzr, eq
	orr	x9, x9, x13
	add	x7, x7, #1
	cmp	x7, x4
	blt	L_mc_sc_tail1
L_mc_sc_store:
	lsl	x10, x6, #3
	add	x10, x0, x10
	str	x9, [x10]
	add	x6, x6, #1
	b	L_mc_sc_w
L_mc_sc_end:
	ldp	d8, d9, [x29, #16]
	ldp	x29, x30, [sp], #32
	ret
#ifndef __APPLE__
	.size	wc_mceliece_encap_scatter_neon,.-wc_mceliece_encap_scatter_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_encap_syndrome_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_encap_syndrome_neon)
.type	wc_mceliece_encap_syndrome_neon,@function
.align	2
wc_mceliece_encap_syndrome_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_encap_syndrome_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_encap_syndrome_neon)
.p2align	2
_wc_mceliece_encap_syndrome_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-64]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #16]
	stp	x20, x21, [x29, #32]
	stp	x22, x23, [x29, #48]
	mov	w6, w4
	mov	w7, w5
	and	x8, x6, #7
	lsr	x9, x6, #3
	cbz	x8, L_mc_syn_notail
	mov	x10, x3
	add	x13, x1, x9
	mov	x16, #0
	sub	x20, x7, #1
	mov	x21, #8
	sub	x21, x21, x8
L_mc_syn_bld:
	cmp	x16, x7
	bge	L_mc_syn_main
	add	x22, x13, x16
	ldrb	w22, [x22]
	lsr	x22, x22, x8
	cmp	x16, x20
	bge	L_mc_syn_bldhi0
	add	x23, x13, x16
	add	x23, x23, #1
	ldrb	w23, [x23]
	lsl	x23, x23, x21
	orr	x22, x22, x23
L_mc_syn_bldhi0:
	add	x23, x3, x16
	strb	w22, [x23]
	add	x16, x16, #1
	b	L_mc_syn_bld
L_mc_syn_notail:
	add	x10, x1, x9
L_mc_syn_main:
	mov	x15, #0
	mov	x11, x0
L_mc_syn_mainl:
	cmp	x15, x9
	bge	L_mc_syn_tailbyte
	mov	x19, #0
	mov	x17, #0
	mov	x12, x11
L_mc_syn_rowl:
	mov	x13, x10
	mov	x14, x7
	eor	v0.16b, v0.16b, v0.16b
L_mc_syn_ap16_m:
	cmp	x14, #16
	blt	L_mc_syn_apd_m
	ld1	{v1.16b}, [x12], #16
	ld1	{v2.16b}, [x13], #16
	and	v1.16b, v1.16b, v2.16b
	eor	v0.16b, v0.16b, v1.16b
	sub	x14, x14, #16
	b	L_mc_syn_ap16_m
L_mc_syn_apd_m:
	cmp	x14, #8
	blt	L_mc_syn_ap8_m
	ldr	d1, [x12], #8
	ldr	d2, [x13], #8
	and	v1.16b, v1.16b, v2.16b
	eor	v0.16b, v0.16b, v1.16b
	sub	x14, x14, #8
L_mc_syn_ap8_m:
	cmp	x14, #4
	blt	L_mc_syn_ap4_m
	ldr	s1, [x12], #4
	ldr	s2, [x13], #4
	and	v1.16b, v1.16b, v2.16b
	eor	v0.16b, v0.16b, v1.16b
	sub	x14, x14, #4
L_mc_syn_ap4_m:
	cmp	x14, #2
	blt	L_mc_syn_ap2_m
	ldr	h1, [x12], #2
	ldr	h2, [x13], #2
	and	v1.16b, v1.16b, v2.16b
	eor	v0.16b, v0.16b, v1.16b
	sub	x14, x14, #2
L_mc_syn_ap2_m:
	cmp	x14, #1
	blt	L_mc_syn_ap1_m
	ldr	b1, [x12], #1
	ldr	b2, [x13], #1
	and	v1.16b, v1.16b, v2.16b
	eor	v0.16b, v0.16b, v1.16b
	sub	x14, x14, #1
L_mc_syn_ap1_m:
	cnt	v0.16b, v0.16b
	uaddlv	h3, v0.16b
	umov	w20, v3.h[0]
	and	x20, x20, #1
	lsl	x20, x20, x17
	orr	x19, x19, x20
	add	x17, x17, #1
	cmp	x17, #8
	blt	L_mc_syn_rowl
	mov	x11, x12
	add	x21, x1, x15
	ldrb	w21, [x21]
	eor	x19, x19, x21
	add	x22, x2, x15
	strb	w19, [x22]
	add	x15, x15, #1
	b	L_mc_syn_mainl
L_mc_syn_tailbyte:
	cbz	x8, L_mc_syn_end
	mov	x19, #0
	mov	x17, #0
	add	x23, x1, x9
	ldrb	w23, [x23]
L_mc_syn_taill:
	mov	x12, x11
	mov	x13, x10
	mov	x14, x7
	eor	v0.16b, v0.16b, v0.16b
L_mc_syn_ap16_t:
	cmp	x14, #16
	blt	L_mc_syn_apd_t
	ld1	{v1.16b}, [x12], #16
	ld1	{v2.16b}, [x13], #16
	and	v1.16b, v1.16b, v2.16b
	eor	v0.16b, v0.16b, v1.16b
	sub	x14, x14, #16
	b	L_mc_syn_ap16_t
L_mc_syn_apd_t:
	cmp	x14, #8
	blt	L_mc_syn_ap8_t
	ldr	d1, [x12], #8
	ldr	d2, [x13], #8
	and	v1.16b, v1.16b, v2.16b
	eor	v0.16b, v0.16b, v1.16b
	sub	x14, x14, #8
L_mc_syn_ap8_t:
	cmp	x14, #4
	blt	L_mc_syn_ap4_t
	ldr	s1, [x12], #4
	ldr	s2, [x13], #4
	and	v1.16b, v1.16b, v2.16b
	eor	v0.16b, v0.16b, v1.16b
	sub	x14, x14, #4
L_mc_syn_ap4_t:
	cmp	x14, #2
	blt	L_mc_syn_ap2_t
	ldr	h1, [x12], #2
	ldr	h2, [x13], #2
	and	v1.16b, v1.16b, v2.16b
	eor	v0.16b, v0.16b, v1.16b
	sub	x14, x14, #2
L_mc_syn_ap2_t:
	cmp	x14, #1
	blt	L_mc_syn_ap1_t
	ldr	b1, [x12], #1
	ldr	b2, [x13], #1
	and	v1.16b, v1.16b, v2.16b
	eor	v0.16b, v0.16b, v1.16b
	sub	x14, x14, #1
L_mc_syn_ap1_t:
	cnt	v0.16b, v0.16b
	uaddlv	h3, v0.16b
	umov	w20, v3.h[0]
	and	x20, x20, #1
	lsr	x21, x23, x17
	and	x21, x21, #1
	eor	x20, x20, x21
	lsl	x20, x20, x17
	orr	x19, x19, x20
	add	x11, x11, x7
	add	x17, x17, #1
	cmp	x17, x8
	blt	L_mc_syn_taill
	add	x22, x2, x9
	strb	w19, [x22]
L_mc_syn_end:
	ldp	x17, x19, [x29, #16]
	ldp	x20, x21, [x29, #32]
	ldp	x22, x23, [x29, #48]
	ldp	x29, x30, [sp], #0x40
	ret
#ifndef __APPLE__
	.size	wc_mceliece_encap_syndrome_neon,.-wc_mceliece_encap_syndrome_neon
#endif /* __APPLE__ */
#endif /* WOLFSSL_MCELIECE_SMALL */
#endif /* WOLFSSL_MCELIECE_NO_ENCAPSULATE */
#ifndef WOLFSSL_MCELIECE_NO_DECAPSULATE
#ifndef WOLFSSL_MCELIECE_SMALL
#ifndef __APPLE__
.text
.globl	wc_mceliece_transpose_64x64_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_transpose_64x64_neon)
.type	wc_mceliece_transpose_64x64_neon,@function
.align	2
wc_mceliece_transpose_64x64_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_transpose_64x64_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_transpose_64x64_neon)
.p2align	2
_wc_mceliece_transpose_64x64_neon:
#endif /* __APPLE__ */
	mov	x2, x0
	mov	x3, x1
	mov	x4, #0x200
L_mc_tr_copy:
	ld1	{v0.16b}, [x3], #16
	st1	{v0.16b}, [x2], #16
	sub	x4, x4, #16
	cbnz	x4, L_mc_tr_copy
	mov	x9, #0xffffffff
	dup	v6.2d, x9
	mov	x5, #0
L_mc_tr_i5:
	cmp	x5, #0x40
	bge	L_mc_tr_e5
	mov	x6, #0
L_mc_tr_k5:
	cmp	x6, #32
	bge	L_mc_tr_ni5
	add	x10, x5, x6
	lsl	x10, x10, #3
	add	x7, x0, x10
	add	x8, x7, #0x100
	ld1	{v0.2d}, [x7]
	ld1	{v1.2d}, [x8]
	and	v2.16b, v0.16b, v6.16b
	and	v3.16b, v1.16b, v6.16b
	shl	v3.2d, v3.2d, #32
	orr	v2.16b, v2.16b, v3.16b
	bic	v4.16b, v0.16b, v6.16b
	ushr	v4.2d, v4.2d, #32
	bic	v5.16b, v1.16b, v6.16b
	orr	v4.16b, v4.16b, v5.16b
	st1	{v2.2d}, [x7]
	st1	{v4.2d}, [x8]
	add	x6, x6, #2
	b	L_mc_tr_k5
L_mc_tr_ni5:
	add	x5, x5, #0x40
	b	L_mc_tr_i5
L_mc_tr_e5:
	mov	x9, #0xffff0000ffff
	dup	v6.2d, x9
	mov	x5, #0
L_mc_tr_i4:
	cmp	x5, #0x40
	bge	L_mc_tr_e4
	mov	x6, #0
L_mc_tr_k4:
	cmp	x6, #16
	bge	L_mc_tr_ni4
	add	x10, x5, x6
	lsl	x10, x10, #3
	add	x7, x0, x10
	add	x8, x7, #0x80
	ld1	{v0.2d}, [x7]
	ld1	{v1.2d}, [x8]
	and	v2.16b, v0.16b, v6.16b
	and	v3.16b, v1.16b, v6.16b
	shl	v3.2d, v3.2d, #16
	orr	v2.16b, v2.16b, v3.16b
	bic	v4.16b, v0.16b, v6.16b
	ushr	v4.2d, v4.2d, #16
	bic	v5.16b, v1.16b, v6.16b
	orr	v4.16b, v4.16b, v5.16b
	st1	{v2.2d}, [x7]
	st1	{v4.2d}, [x8]
	add	x6, x6, #2
	b	L_mc_tr_k4
L_mc_tr_ni4:
	add	x5, x5, #32
	b	L_mc_tr_i4
L_mc_tr_e4:
	mov	x9, #0xff00ff00ff00ff
	dup	v6.2d, x9
	mov	x5, #0
L_mc_tr_i3:
	cmp	x5, #0x40
	bge	L_mc_tr_e3
	mov	x6, #0
L_mc_tr_k3:
	cmp	x6, #8
	bge	L_mc_tr_ni3
	add	x10, x5, x6
	lsl	x10, x10, #3
	add	x7, x0, x10
	add	x8, x7, #0x40
	ld1	{v0.2d}, [x7]
	ld1	{v1.2d}, [x8]
	and	v2.16b, v0.16b, v6.16b
	and	v3.16b, v1.16b, v6.16b
	shl	v3.2d, v3.2d, #8
	orr	v2.16b, v2.16b, v3.16b
	bic	v4.16b, v0.16b, v6.16b
	ushr	v4.2d, v4.2d, #8
	bic	v5.16b, v1.16b, v6.16b
	orr	v4.16b, v4.16b, v5.16b
	st1	{v2.2d}, [x7]
	st1	{v4.2d}, [x8]
	add	x6, x6, #2
	b	L_mc_tr_k3
L_mc_tr_ni3:
	add	x5, x5, #16
	b	L_mc_tr_i3
L_mc_tr_e3:
	mov	x9, #0xf0f0f0f0f0f0f0f
	dup	v6.2d, x9
	mov	x5, #0
L_mc_tr_i2:
	cmp	x5, #0x40
	bge	L_mc_tr_e2
	mov	x6, #0
L_mc_tr_k2:
	cmp	x6, #4
	bge	L_mc_tr_ni2
	add	x10, x5, x6
	lsl	x10, x10, #3
	add	x7, x0, x10
	add	x8, x7, #32
	ld1	{v0.2d}, [x7]
	ld1	{v1.2d}, [x8]
	and	v2.16b, v0.16b, v6.16b
	and	v3.16b, v1.16b, v6.16b
	shl	v3.2d, v3.2d, #4
	orr	v2.16b, v2.16b, v3.16b
	bic	v4.16b, v0.16b, v6.16b
	ushr	v4.2d, v4.2d, #4
	bic	v5.16b, v1.16b, v6.16b
	orr	v4.16b, v4.16b, v5.16b
	st1	{v2.2d}, [x7]
	st1	{v4.2d}, [x8]
	add	x6, x6, #2
	b	L_mc_tr_k2
L_mc_tr_ni2:
	add	x5, x5, #8
	b	L_mc_tr_i2
L_mc_tr_e2:
	mov	x9, #0x3333333333333333
	dup	v6.2d, x9
	mov	x5, #0
L_mc_tr_i1:
	cmp	x5, #0x40
	bge	L_mc_tr_e1
	mov	x6, #0
L_mc_tr_k1:
	cmp	x6, #2
	bge	L_mc_tr_ni1
	add	x10, x5, x6
	lsl	x10, x10, #3
	add	x7, x0, x10
	add	x8, x7, #16
	ld1	{v0.2d}, [x7]
	ld1	{v1.2d}, [x8]
	and	v2.16b, v0.16b, v6.16b
	and	v3.16b, v1.16b, v6.16b
	shl	v3.2d, v3.2d, #2
	orr	v2.16b, v2.16b, v3.16b
	bic	v4.16b, v0.16b, v6.16b
	ushr	v4.2d, v4.2d, #2
	bic	v5.16b, v1.16b, v6.16b
	orr	v4.16b, v4.16b, v5.16b
	st1	{v2.2d}, [x7]
	st1	{v4.2d}, [x8]
	add	x6, x6, #2
	b	L_mc_tr_k1
L_mc_tr_ni1:
	add	x5, x5, #4
	b	L_mc_tr_i1
L_mc_tr_e1:
	mov	x9, #0x5555555555555555
	dup	v6.2d, x9
	mov	x5, #0
L_mc_tr_sc0:
	cmp	x5, #0x40
	bge	L_mc_tr_e0
	lsl	x10, x5, #3
	add	x7, x0, x10
	ldr	x10, [x7]
	ldr	x11, [x7, #8]
	and	x12, x10, x9
	and	x13, x11, x9
	lsl	x13, x13, #1
	orr	x12, x12, x13
	bic	x13, x10, x9
	lsr	x13, x13, #1
	bic	x10, x11, x9
	orr	x13, x13, x10
	str	x12, [x7]
	str	x13, [x7, #8]
	add	x5, x5, #2
	b	L_mc_tr_sc0
L_mc_tr_e0:
	ret
#ifndef __APPLE__
	.size	wc_mceliece_transpose_64x64_neon,.-wc_mceliece_transpose_64x64_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_layer_in_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_layer_in_neon)
.type	wc_mceliece_layer_in_neon,@function
.align	2
wc_mceliece_layer_in_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_layer_in_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_layer_in_neon)
.p2align	2
_wc_mceliece_layer_in_neon:
#endif /* __APPLE__ */
	mov	x12, #1
	mov	w3, w2
	lsl	x4, x12, x3
	cmp	x4, #1
	beq	L_mc_lin_sc
	lsl	x5, x4, #3
	mov	x6, #0
L_mc_lin_i:
	cmp	x6, #0x40
	bge	L_mc_lin_done
	mov	x7, x6
	add	x12, x6, x4
L_mc_lin_j:
	cmp	x7, x12
	bge	L_mc_lin_ni
	lsl	x13, x7, #3
	add	x8, x0, x13
	add	x9, x8, #0x200
	add	x10, x8, x5
	add	x11, x9, x5
	ld1	{v0.2d}, [x8]
	ld1	{v1.2d}, [x10]
	ld1	{v2.2d}, [x9]
	ld1	{v3.2d}, [x11]
	ld2	{v5.2d, v6.2d}, [x1], #32
	eor	v4.16b, v0.16b, v1.16b
	and	v4.16b, v4.16b, v5.16b
	eor	v0.16b, v0.16b, v4.16b
	eor	v1.16b, v1.16b, v4.16b
	eor	v4.16b, v2.16b, v3.16b
	and	v4.16b, v4.16b, v6.16b
	eor	v2.16b, v2.16b, v4.16b
	eor	v3.16b, v3.16b, v4.16b
	st1	{v0.2d}, [x8]
	st1	{v1.2d}, [x10]
	st1	{v2.2d}, [x9]
	st1	{v3.2d}, [x11]
	add	x7, x7, #2
	b	L_mc_lin_j
L_mc_lin_ni:
	add	x13, x4, x4
	add	x6, x6, x13
	b	L_mc_lin_i
L_mc_lin_sc:
	mov	x6, #0
L_mc_lin_sl:
	cmp	x6, #0x40
	bge	L_mc_lin_done
	lsl	x10, x6, #3
	add	x8, x0, x10
	add	x9, x8, #0x200
	ldr	x12, [x8]
	ldr	x13, [x8, #8]
	ldr	x4, [x1], #8
	eor	x5, x12, x13
	and	x5, x5, x4
	eor	x12, x12, x5
	eor	x13, x13, x5
	str	x12, [x8]
	str	x13, [x8, #8]
	ldr	x12, [x9]
	ldr	x13, [x9, #8]
	ldr	x4, [x1], #8
	eor	x5, x12, x13
	and	x5, x5, x4
	eor	x12, x12, x5
	eor	x13, x13, x5
	str	x12, [x9]
	str	x13, [x9, #8]
	add	x6, x6, #2
	b	L_mc_lin_sl
L_mc_lin_done:
	ret
#ifndef __APPLE__
	.size	wc_mceliece_layer_in_neon,.-wc_mceliece_layer_in_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_layer_ex_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_layer_ex_neon)
.type	wc_mceliece_layer_ex_neon,@function
.align	2
wc_mceliece_layer_ex_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_layer_ex_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_layer_ex_neon)
.p2align	2
_wc_mceliece_layer_ex_neon:
#endif /* __APPLE__ */
	mov	x10, #1
	mov	w3, w2
	lsl	x4, x10, x3
	cmp	x4, #1
	beq	L_mc_lex_sc
	lsl	x5, x4, #3
	mov	x6, #0
L_mc_lex_i:
	cmp	x6, #0x80
	bge	L_mc_lex_done
	mov	x7, #0
L_mc_lex_k:
	cmp	x7, x4
	bge	L_mc_lex_ni
	add	x10, x6, x7
	lsl	x10, x10, #3
	add	x8, x0, x10
	add	x9, x8, x5
	ld1	{v0.2d}, [x8]
	ld1	{v1.2d}, [x9]
	ld1	{v3.2d}, [x1], #16
	eor	v2.16b, v0.16b, v1.16b
	and	v2.16b, v2.16b, v3.16b
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v2.16b
	st1	{v0.2d}, [x8]
	st1	{v1.2d}, [x9]
	add	x7, x7, #2
	b	L_mc_lex_k
L_mc_lex_ni:
	add	x10, x4, x4
	add	x6, x6, x10
	b	L_mc_lex_i
L_mc_lex_sc:
	mov	x6, #0
L_mc_lex_sl:
	cmp	x6, #0x80
	bge	L_mc_lex_done
	lsl	x10, x6, #3
	add	x8, x0, x10
	ldr	x10, [x8]
	ldr	x11, [x8, #8]
	ldr	x12, [x1], #8
	eor	x13, x10, x11
	and	x13, x13, x12
	eor	x10, x10, x13
	eor	x11, x11, x13
	str	x10, [x8]
	str	x11, [x8, #8]
	add	x6, x6, #2
	b	L_mc_lex_sl
L_mc_lex_done:
	ret
#ifndef __APPLE__
	.size	wc_mceliece_layer_ex_neon,.-wc_mceliece_layer_ex_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_apply_benes_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_apply_benes_neon)
.type	wc_mceliece_apply_benes_neon,@function
.align	2
wc_mceliece_apply_benes_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_apply_benes_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_apply_benes_neon)
.p2align	2
_wc_mceliece_apply_benes_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-64]!
	add	x29, sp, #0
	stp	x19, x20, [x29, #24]
	stp	x21, x22, [x29, #40]
	str	x23, [x29, #56]
	mov	x19, x0
	mov	x20, x3
	mov	x21, x1
	mov	x22, #0
	cbz	x2, L_mc_ab_norev
	mov	x5, #0x3000
	add	x21, x21, x5
	mov	x22, #0x400
	neg	x22, x22
L_mc_ab_norev:
	mov	x4, #0
L_mc_ab_rl:
	cmp	x4, #0x40
	bge	L_mc_ab_rle
	lsl	x8, x4, #4
	add	x7, x19, x8
	ldr	x5, [x7]
	ldr	x6, [x7, #8]
	lsl	x8, x4, #3
	add	x7, x20, x8
	str	x5, [x7]
	str	x6, [x7, #512]
	add	x4, x4, #1
	b	L_mc_ab_rl
L_mc_ab_rle:
	add	x0, x20, #0x400
	add	x1, x20, #0
#ifndef __APPLE__
	bl	wc_mceliece_transpose_64x64_neon
#else
	bl	_wc_mceliece_transpose_64x64_neon
#endif /* __APPLE__ */
	add	x0, x20, #0x600
	add	x1, x20, #0x200
#ifndef __APPLE__
	bl	wc_mceliece_transpose_64x64_neon
#else
	bl	_wc_mceliece_transpose_64x64_neon
#endif /* __APPLE__ */
	mov	x23, #0
L_mc_ab_x1:
	cmp	x23, #6
	bgt	L_mc_ab_x1e
	mov	x4, #0
L_mc_bnl_x1:
	cmp	x4, #0x40
	bge	L_mc_bnle_x1
	ldr	x5, [x21]
	lsl	x8, x4, #3
	add	x7, x20, x8
	str	x5, [x7, #2048]
	add	x21, x21, #8
	add	x4, x4, #1
	b	L_mc_bnl_x1
L_mc_bnle_x1:
	add	x21, x21, x22
	add	x0, x20, #0xa00
	add	x1, x20, #0x800
#ifndef __APPLE__
	bl	wc_mceliece_transpose_64x64_neon
#else
	bl	_wc_mceliece_transpose_64x64_neon
#endif /* __APPLE__ */
	add	x0, x20, #0x400
	add	x1, x20, #0xa00
	mov	w2, w23
#ifndef __APPLE__
	bl	wc_mceliece_layer_ex_neon
#else
	bl	_wc_mceliece_layer_ex_neon
#endif /* __APPLE__ */
	add	x23, x23, #1
	b	L_mc_ab_x1
L_mc_ab_x1e:
	add	x0, x20, #0
	add	x1, x20, #0x400
#ifndef __APPLE__
	bl	wc_mceliece_transpose_64x64_neon
#else
	bl	_wc_mceliece_transpose_64x64_neon
#endif /* __APPLE__ */
	add	x0, x20, #0x200
	add	x1, x20, #0x600
#ifndef __APPLE__
	bl	wc_mceliece_transpose_64x64_neon
#else
	bl	_wc_mceliece_transpose_64x64_neon
#endif /* __APPLE__ */
	mov	x23, #0
L_mc_ab_n1:
	cmp	x23, #5
	bgt	L_mc_ab_n1e
	mov	x4, #0
L_mc_bnl_n1:
	cmp	x4, #0x40
	bge	L_mc_bnle_n1
	ldr	x5, [x21]
	lsl	x8, x4, #3
	add	x7, x20, x8
	str	x5, [x7, #2048]
	add	x21, x21, #8
	add	x4, x4, #1
	b	L_mc_bnl_n1
L_mc_bnle_n1:
	add	x21, x21, x22
	mov	x0, x20
	add	x1, x20, #0x800
	mov	w2, w23
#ifndef __APPLE__
	bl	wc_mceliece_layer_in_neon
#else
	bl	_wc_mceliece_layer_in_neon
#endif /* __APPLE__ */
	add	x23, x23, #1
	b	L_mc_ab_n1
L_mc_ab_n1e:
	mov	x23, #4
L_mc_ab_n2:
	cmp	x23, #0
	blt	L_mc_ab_n2e
	mov	x4, #0
L_mc_bnl_n2:
	cmp	x4, #0x40
	bge	L_mc_bnle_n2
	ldr	x5, [x21]
	lsl	x8, x4, #3
	add	x7, x20, x8
	str	x5, [x7, #2048]
	add	x21, x21, #8
	add	x4, x4, #1
	b	L_mc_bnl_n2
L_mc_bnle_n2:
	add	x21, x21, x22
	mov	x0, x20
	add	x1, x20, #0x800
	mov	w2, w23
#ifndef __APPLE__
	bl	wc_mceliece_layer_in_neon
#else
	bl	_wc_mceliece_layer_in_neon
#endif /* __APPLE__ */
	sub	x23, x23, #1
	b	L_mc_ab_n2
L_mc_ab_n2e:
	add	x0, x20, #0x400
	add	x1, x20, #0
#ifndef __APPLE__
	bl	wc_mceliece_transpose_64x64_neon
#else
	bl	_wc_mceliece_transpose_64x64_neon
#endif /* __APPLE__ */
	add	x0, x20, #0x600
	add	x1, x20, #0x200
#ifndef __APPLE__
	bl	wc_mceliece_transpose_64x64_neon
#else
	bl	_wc_mceliece_transpose_64x64_neon
#endif /* __APPLE__ */
	mov	x23, #6
L_mc_ab_x2:
	cmp	x23, #0
	blt	L_mc_ab_x2e
	mov	x4, #0
L_mc_bnl_x2:
	cmp	x4, #0x40
	bge	L_mc_bnle_x2
	ldr	x5, [x21]
	lsl	x8, x4, #3
	add	x7, x20, x8
	str	x5, [x7, #2048]
	add	x21, x21, #8
	add	x4, x4, #1
	b	L_mc_bnl_x2
L_mc_bnle_x2:
	add	x21, x21, x22
	add	x0, x20, #0xa00
	add	x1, x20, #0x800
#ifndef __APPLE__
	bl	wc_mceliece_transpose_64x64_neon
#else
	bl	_wc_mceliece_transpose_64x64_neon
#endif /* __APPLE__ */
	add	x0, x20, #0x400
	add	x1, x20, #0xa00
	mov	w2, w23
#ifndef __APPLE__
	bl	wc_mceliece_layer_ex_neon
#else
	bl	_wc_mceliece_layer_ex_neon
#endif /* __APPLE__ */
	sub	x23, x23, #1
	b	L_mc_ab_x2
L_mc_ab_x2e:
	add	x0, x20, #0
	add	x1, x20, #0x400
#ifndef __APPLE__
	bl	wc_mceliece_transpose_64x64_neon
#else
	bl	_wc_mceliece_transpose_64x64_neon
#endif /* __APPLE__ */
	add	x0, x20, #0x200
	add	x1, x20, #0x600
#ifndef __APPLE__
	bl	wc_mceliece_transpose_64x64_neon
#else
	bl	_wc_mceliece_transpose_64x64_neon
#endif /* __APPLE__ */
	mov	x4, #0
L_mc_ab_st:
	cmp	x4, #0x40
	bge	L_mc_ab_ste
	lsl	x8, x4, #3
	add	x7, x20, x8
	ldr	x5, [x7]
	ldr	x6, [x7, #512]
	lsl	x8, x4, #4
	add	x7, x19, x8
	str	x5, [x7]
	str	x6, [x7, #8]
	add	x4, x4, #1
	b	L_mc_ab_st
L_mc_ab_ste:
	ldp	x19, x20, [x29, #24]
	ldp	x21, x22, [x29, #40]
	ldr	x23, [x29, #56]
	ldp	x29, x30, [sp], #0x40
	ret
#ifndef __APPLE__
	.size	wc_mceliece_apply_benes_neon,.-wc_mceliece_apply_benes_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_gf_discrepancy_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_gf_discrepancy_neon)
.type	wc_mceliece_gf_discrepancy_neon,@function
.align	2
wc_mceliece_gf_discrepancy_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_gf_discrepancy_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_gf_discrepancy_neon)
.p2align	2
_wc_mceliece_gf_discrepancy_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
	stp	d12, d13, [x29, #48]
	stp	d14, d15, [x29, #64]
	eor	v0.16b, v0.16b, v0.16b
	eor	v16.16b, v16.16b, v16.16b
	mov	x5, #0x1ff
	dup	v1.4s, w5
	shl	v1.4s, v1.4s, #16
	mov	x5, #0xe000
	dup	v2.4s, w5
	mov	x5, #0x1fff
	dup	v3.4s, w5
	mov	x3, #0
L_mc_gdc:
	cmp	w3, w2
	bge	L_mc_gdce
	lsl	x5, x3, #1
	add	x4, x0, x5
	ldr	q4, [x4]
	add	x5, x3, #7
	lsl	x5, x5, #1
	sub	x4, x1, x5
	ldr	q5, [x4]
	rev64	v5.8h, v5.8h
	ext	v5.16b, v5.16b, v5.16b, #8
	zip1	v6.8h, v4.8h, v0.8h
	zip2	v7.8h, v4.8h, v0.8h
	zip1	v8.8h, v5.8h, v0.8h
	zip2	v9.8h, v5.8h, v0.8h
	shl	v13.4s, v8.4s, #31
	sshr	v13.4s, v13.4s, #31
	and	v10.16b, v6.16b, v13.16b
	shl	v13.4s, v8.4s, #30
	sshr	v13.4s, v13.4s, #31
	shl	v12.4s, v6.4s, #1
	and	v12.16b, v12.16b, v13.16b
	eor	v10.16b, v10.16b, v12.16b
	shl	v13.4s, v8.4s, #29
	sshr	v13.4s, v13.4s, #31
	shl	v12.4s, v6.4s, #2
	and	v12.16b, v12.16b, v13.16b
	eor	v10.16b, v10.16b, v12.16b
	shl	v13.4s, v8.4s, #28
	sshr	v13.4s, v13.4s, #31
	shl	v12.4s, v6.4s, #3
	and	v12.16b, v12.16b, v13.16b
	eor	v10.16b, v10.16b, v12.16b
	shl	v13.4s, v8.4s, #27
	sshr	v13.4s, v13.4s, #31
	shl	v12.4s, v6.4s, #4
	and	v12.16b, v12.16b, v13.16b
	eor	v10.16b, v10.16b, v12.16b
	shl	v13.4s, v8.4s, #26
	sshr	v13.4s, v13.4s, #31
	shl	v12.4s, v6.4s, #5
	and	v12.16b, v12.16b, v13.16b
	eor	v10.16b, v10.16b, v12.16b
	shl	v13.4s, v8.4s, #25
	sshr	v13.4s, v13.4s, #31
	shl	v12.4s, v6.4s, #6
	and	v12.16b, v12.16b, v13.16b
	eor	v10.16b, v10.16b, v12.16b
	shl	v13.4s, v8.4s, #24
	sshr	v13.4s, v13.4s, #31
	shl	v12.4s, v6.4s, #7
	and	v12.16b, v12.16b, v13.16b
	eor	v10.16b, v10.16b, v12.16b
	shl	v13.4s, v8.4s, #23
	sshr	v13.4s, v13.4s, #31
	shl	v12.4s, v6.4s, #8
	and	v12.16b, v12.16b, v13.16b
	eor	v10.16b, v10.16b, v12.16b
	shl	v13.4s, v8.4s, #22
	sshr	v13.4s, v13.4s, #31
	shl	v12.4s, v6.4s, #9
	and	v12.16b, v12.16b, v13.16b
	eor	v10.16b, v10.16b, v12.16b
	shl	v13.4s, v8.4s, #21
	sshr	v13.4s, v13.4s, #31
	shl	v12.4s, v6.4s, #10
	and	v12.16b, v12.16b, v13.16b
	eor	v10.16b, v10.16b, v12.16b
	shl	v13.4s, v8.4s, #20
	sshr	v13.4s, v13.4s, #31
	shl	v12.4s, v6.4s, #11
	and	v12.16b, v12.16b, v13.16b
	eor	v10.16b, v10.16b, v12.16b
	shl	v13.4s, v8.4s, #19
	sshr	v13.4s, v13.4s, #31
	shl	v12.4s, v6.4s, #12
	and	v12.16b, v12.16b, v13.16b
	eor	v10.16b, v10.16b, v12.16b
	and	v14.16b, v10.16b, v1.16b
	ushr	v15.4s, v14.4s, #9
	eor	v10.16b, v10.16b, v15.16b
	ushr	v15.4s, v14.4s, #10
	eor	v10.16b, v10.16b, v15.16b
	ushr	v15.4s, v14.4s, #12
	eor	v10.16b, v10.16b, v15.16b
	ushr	v15.4s, v14.4s, #13
	eor	v10.16b, v10.16b, v15.16b
	and	v14.16b, v10.16b, v2.16b
	ushr	v15.4s, v14.4s, #9
	eor	v10.16b, v10.16b, v15.16b
	ushr	v15.4s, v14.4s, #10
	eor	v10.16b, v10.16b, v15.16b
	ushr	v15.4s, v14.4s, #12
	eor	v10.16b, v10.16b, v15.16b
	ushr	v15.4s, v14.4s, #13
	eor	v10.16b, v10.16b, v15.16b
	and	v10.16b, v10.16b, v3.16b
	shl	v13.4s, v9.4s, #31
	sshr	v13.4s, v13.4s, #31
	and	v11.16b, v7.16b, v13.16b
	shl	v13.4s, v9.4s, #30
	sshr	v13.4s, v13.4s, #31
	shl	v12.4s, v7.4s, #1
	and	v12.16b, v12.16b, v13.16b
	eor	v11.16b, v11.16b, v12.16b
	shl	v13.4s, v9.4s, #29
	sshr	v13.4s, v13.4s, #31
	shl	v12.4s, v7.4s, #2
	and	v12.16b, v12.16b, v13.16b
	eor	v11.16b, v11.16b, v12.16b
	shl	v13.4s, v9.4s, #28
	sshr	v13.4s, v13.4s, #31
	shl	v12.4s, v7.4s, #3
	and	v12.16b, v12.16b, v13.16b
	eor	v11.16b, v11.16b, v12.16b
	shl	v13.4s, v9.4s, #27
	sshr	v13.4s, v13.4s, #31
	shl	v12.4s, v7.4s, #4
	and	v12.16b, v12.16b, v13.16b
	eor	v11.16b, v11.16b, v12.16b
	shl	v13.4s, v9.4s, #26
	sshr	v13.4s, v13.4s, #31
	shl	v12.4s, v7.4s, #5
	and	v12.16b, v12.16b, v13.16b
	eor	v11.16b, v11.16b, v12.16b
	shl	v13.4s, v9.4s, #25
	sshr	v13.4s, v13.4s, #31
	shl	v12.4s, v7.4s, #6
	and	v12.16b, v12.16b, v13.16b
	eor	v11.16b, v11.16b, v12.16b
	shl	v13.4s, v9.4s, #24
	sshr	v13.4s, v13.4s, #31
	shl	v12.4s, v7.4s, #7
	and	v12.16b, v12.16b, v13.16b
	eor	v11.16b, v11.16b, v12.16b
	shl	v13.4s, v9.4s, #23
	sshr	v13.4s, v13.4s, #31
	shl	v12.4s, v7.4s, #8
	and	v12.16b, v12.16b, v13.16b
	eor	v11.16b, v11.16b, v12.16b
	shl	v13.4s, v9.4s, #22
	sshr	v13.4s, v13.4s, #31
	shl	v12.4s, v7.4s, #9
	and	v12.16b, v12.16b, v13.16b
	eor	v11.16b, v11.16b, v12.16b
	shl	v13.4s, v9.4s, #21
	sshr	v13.4s, v13.4s, #31
	shl	v12.4s, v7.4s, #10
	and	v12.16b, v12.16b, v13.16b
	eor	v11.16b, v11.16b, v12.16b
	shl	v13.4s, v9.4s, #20
	sshr	v13.4s, v13.4s, #31
	shl	v12.4s, v7.4s, #11
	and	v12.16b, v12.16b, v13.16b
	eor	v11.16b, v11.16b, v12.16b
	shl	v13.4s, v9.4s, #19
	sshr	v13.4s, v13.4s, #31
	shl	v12.4s, v7.4s, #12
	and	v12.16b, v12.16b, v13.16b
	eor	v11.16b, v11.16b, v12.16b
	and	v14.16b, v11.16b, v1.16b
	ushr	v15.4s, v14.4s, #9
	eor	v11.16b, v11.16b, v15.16b
	ushr	v15.4s, v14.4s, #10
	eor	v11.16b, v11.16b, v15.16b
	ushr	v15.4s, v14.4s, #12
	eor	v11.16b, v11.16b, v15.16b
	ushr	v15.4s, v14.4s, #13
	eor	v11.16b, v11.16b, v15.16b
	and	v14.16b, v11.16b, v2.16b
	ushr	v15.4s, v14.4s, #9
	eor	v11.16b, v11.16b, v15.16b
	ushr	v15.4s, v14.4s, #10
	eor	v11.16b, v11.16b, v15.16b
	ushr	v15.4s, v14.4s, #12
	eor	v11.16b, v11.16b, v15.16b
	ushr	v15.4s, v14.4s, #13
	eor	v11.16b, v11.16b, v15.16b
	and	v11.16b, v11.16b, v3.16b
	uzp1	v17.8h, v10.8h, v11.8h
	eor	v16.16b, v16.16b, v17.16b
	add	x3, x3, #8
	b	L_mc_gdc
L_mc_gdce:
	ext	v14.16b, v16.16b, v16.16b, #8
	eor	v16.16b, v16.16b, v14.16b
	ext	v14.16b, v16.16b, v16.16b, #4
	eor	v16.16b, v16.16b, v14.16b
	ext	v14.16b, v16.16b, v16.16b, #2
	eor	v16.16b, v16.16b, v14.16b
	umov	w6, v16.h[0]
	mov	x0, x6
	ldp	d8, d9, [x29, #16]
	ldp	d10, d11, [x29, #32]
	ldp	d12, d13, [x29, #48]
	ldp	d14, d15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
#ifndef __APPLE__
	.size	wc_mceliece_gf_discrepancy_neon,.-wc_mceliece_gf_discrepancy_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_synd_unpack_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_synd_unpack_neon)
.type	wc_mceliece_synd_unpack_neon,@function
.align	2
wc_mceliece_synd_unpack_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_synd_unpack_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_synd_unpack_neon)
.p2align	2
_wc_mceliece_synd_unpack_neon:
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x3, L_mc_bs_powers_neon
	add  x3, x3, :lo12:L_mc_bs_powers_neon
#else
	adrp x3, L_mc_bs_powers_neon@PAGE
	add  x3, x3, L_mc_bs_powers_neon@PAGEOFF
#endif /* __APPLE__ */
	ldr	q0, [x3]
	movi	v1.8h, #1
	mov	w10, w2
	lsr	x10, x10, #3
	mov	x4, #0
L_mc_sunp:
	cmp	x4, x10
	bge	L_mc_sunpe
	lsr	x5, x4, #3
	lsl	x6, x5, #3
	and	x7, x4, #7
	lsl	x7, x7, #3
	eor	v4.16b, v4.16b, v4.16b
	add	x9, x1, #0
	add	x9, x9, x6
	ldr	x8, [x9]
	lsr	x8, x8, x7
	dup	v2.8h, w8
	cmtst	v3.8h, v2.8h, v0.8h
	and	v3.16b, v3.16b, v1.16b
	orr	v4.16b, v4.16b, v3.16b
	add	x9, x1, #32
	add	x9, x9, x6
	ldr	x8, [x9]
	lsr	x8, x8, x7
	dup	v2.8h, w8
	cmtst	v3.8h, v2.8h, v0.8h
	and	v3.16b, v3.16b, v1.16b
	shl	v3.8h, v3.8h, #1
	orr	v4.16b, v4.16b, v3.16b
	add	x9, x1, #0x40
	add	x9, x9, x6
	ldr	x8, [x9]
	lsr	x8, x8, x7
	dup	v2.8h, w8
	cmtst	v3.8h, v2.8h, v0.8h
	and	v3.16b, v3.16b, v1.16b
	shl	v3.8h, v3.8h, #2
	orr	v4.16b, v4.16b, v3.16b
	add	x9, x1, #0x60
	add	x9, x9, x6
	ldr	x8, [x9]
	lsr	x8, x8, x7
	dup	v2.8h, w8
	cmtst	v3.8h, v2.8h, v0.8h
	and	v3.16b, v3.16b, v1.16b
	shl	v3.8h, v3.8h, #3
	orr	v4.16b, v4.16b, v3.16b
	add	x9, x1, #0x80
	add	x9, x9, x6
	ldr	x8, [x9]
	lsr	x8, x8, x7
	dup	v2.8h, w8
	cmtst	v3.8h, v2.8h, v0.8h
	and	v3.16b, v3.16b, v1.16b
	shl	v3.8h, v3.8h, #4
	orr	v4.16b, v4.16b, v3.16b
	add	x9, x1, #0xa0
	add	x9, x9, x6
	ldr	x8, [x9]
	lsr	x8, x8, x7
	dup	v2.8h, w8
	cmtst	v3.8h, v2.8h, v0.8h
	and	v3.16b, v3.16b, v1.16b
	shl	v3.8h, v3.8h, #5
	orr	v4.16b, v4.16b, v3.16b
	add	x9, x1, #0xc0
	add	x9, x9, x6
	ldr	x8, [x9]
	lsr	x8, x8, x7
	dup	v2.8h, w8
	cmtst	v3.8h, v2.8h, v0.8h
	and	v3.16b, v3.16b, v1.16b
	shl	v3.8h, v3.8h, #6
	orr	v4.16b, v4.16b, v3.16b
	add	x9, x1, #0xe0
	add	x9, x9, x6
	ldr	x8, [x9]
	lsr	x8, x8, x7
	dup	v2.8h, w8
	cmtst	v3.8h, v2.8h, v0.8h
	and	v3.16b, v3.16b, v1.16b
	shl	v3.8h, v3.8h, #7
	orr	v4.16b, v4.16b, v3.16b
	add	x9, x1, #0x100
	add	x9, x9, x6
	ldr	x8, [x9]
	lsr	x8, x8, x7
	dup	v2.8h, w8
	cmtst	v3.8h, v2.8h, v0.8h
	and	v3.16b, v3.16b, v1.16b
	shl	v3.8h, v3.8h, #8
	orr	v4.16b, v4.16b, v3.16b
	add	x9, x1, #0x120
	add	x9, x9, x6
	ldr	x8, [x9]
	lsr	x8, x8, x7
	dup	v2.8h, w8
	cmtst	v3.8h, v2.8h, v0.8h
	and	v3.16b, v3.16b, v1.16b
	shl	v3.8h, v3.8h, #9
	orr	v4.16b, v4.16b, v3.16b
	add	x9, x1, #0x140
	add	x9, x9, x6
	ldr	x8, [x9]
	lsr	x8, x8, x7
	dup	v2.8h, w8
	cmtst	v3.8h, v2.8h, v0.8h
	and	v3.16b, v3.16b, v1.16b
	shl	v3.8h, v3.8h, #10
	orr	v4.16b, v4.16b, v3.16b
	add	x9, x1, #0x160
	add	x9, x9, x6
	ldr	x8, [x9]
	lsr	x8, x8, x7
	dup	v2.8h, w8
	cmtst	v3.8h, v2.8h, v0.8h
	and	v3.16b, v3.16b, v1.16b
	shl	v3.8h, v3.8h, #11
	orr	v4.16b, v4.16b, v3.16b
	add	x9, x1, #0x180
	add	x9, x9, x6
	ldr	x8, [x9]
	lsr	x8, x8, x7
	dup	v2.8h, w8
	cmtst	v3.8h, v2.8h, v0.8h
	and	v3.16b, v3.16b, v1.16b
	shl	v3.8h, v3.8h, #12
	orr	v4.16b, v4.16b, v3.16b
	lsl	x9, x4, #4
	add	x9, x0, x9
	str	q4, [x9]
	add	x4, x4, #1
	b	L_mc_sunp
L_mc_sunpe:
	ret
#ifndef __APPLE__
	.size	wc_mceliece_synd_unpack_neon,.-wc_mceliece_synd_unpack_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_berlekamp_massey_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_berlekamp_massey_neon)
.type	wc_mceliece_berlekamp_massey_neon,@function
.align	2
wc_mceliece_berlekamp_massey_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_berlekamp_massey_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_berlekamp_massey_neon)
.p2align	2
_wc_mceliece_berlekamp_massey_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-112]!
	add	x29, sp, #0
	stp	x19, x20, [x29, #32]
	stp	x21, x22, [x29, #48]
	stp	x23, x24, [x29, #64]
	stp	x25, x26, [x29, #80]
	stp	x27, x28, [x29, #96]
	str	x0, [x29, #16]
	mov	x19, x1
	mov	w20, w2
	mov	x21, x3
	add	x22, x3, #0x200
	add	x23, x3, #0x400
	mov	w7, #0
	mov	x4, #0
L_mc_bm_in:
	cmp	x4, x20
	bgt	L_mc_bm_ine
	lsl	x5, x4, #1
	add	x6, x22, x5
	strh	w7, [x6]
	add	x6, x23, x5
	strh	w7, [x6]
	add	x4, x4, #1
	b	L_mc_bm_in
L_mc_bm_ine:
	mov	w7, #1
	strh	w7, [x22]
	add	x6, x23, #2
	strh	w7, [x6]
	mov	w25, #0
	mov	w26, #1
	mov	w24, #0
L_mc_bm_n:
	lsl	x8, x20, #1
	cmp	x24, x8
	bge	L_mc_bm_ne
	mov	w27, #0
	mov	x9, x20
	cmp	x24, x20
	bge	L_mc_bm_dsk
	mov	x9, x24
L_mc_bm_dsk:
	add	x10, x9, #1
	lsr	x10, x10, #3
	lsl	x10, x10, #3
	cbz	x10, L_mc_bm_dt
	mov	x0, x22
	lsl	x5, x24, #1
	add	x1, x19, x5
	mov	w2, w10
#ifndef __APPLE__
	bl	wc_mceliece_gf_discrepancy_neon
#else
	bl	_wc_mceliece_gf_discrepancy_neon
#endif /* __APPLE__ */
	mov	w27, w0
L_mc_bm_dt:
	mov	x9, x20
	cmp	x24, x20
	bge	L_mc_bm_tc
	mov	x9, x24
L_mc_bm_tc:
	add	x10, x9, #1
	lsr	x10, x10, #3
	lsl	x10, x10, #3
	mov	x28, x10
L_mc_bm_dte:
	cmp	x28, x9
	bgt	L_mc_bm_zc
	lsl	x5, x28, #1
	add	x6, x22, x5
	ldrh	w0, [x6]
	sub	x5, x24, x28
	lsl	x5, x5, #1
	add	x6, x19, x5
	ldrh	w1, [x6]
#ifndef __APPLE__
	bl	wc_mceliece_gf_mul_scalar_neon
#else
	bl	_wc_mceliece_gf_mul_scalar_neon
#endif /* __APPLE__ */
	eor	w27, w27, w0
	add	x28, x28, #1
	b	L_mc_bm_dte
L_mc_bm_zc:
	mov	x4, #0
L_mc_bm_tce:
	cmp	x4, x20
	bgt	L_mc_bm_zce
	lsl	x5, x4, #1
	add	x6, x22, x5
	ldrh	w7, [x6]
	add	x6, x21, x5
	strh	w7, [x6]
	add	x6, x22, x5
	mov	w8, #0
	strh	w8, [x6]
	add	x4, x4, #1
	b	L_mc_bm_tce
L_mc_bm_zce:
	add	x8, x20, #1
	lsr	x10, x8, #3
	lsl	x10, x10, #3
	cbz	x10, L_mc_bm_msk
	mov	x0, x22
	mov	w1, w26
	mov	x2, x21
	mov	w3, w10
#ifndef __APPLE__
	bl	wc_mceliece_gf_mulc_mac_neon
#else
	bl	_wc_mceliece_gf_mulc_mac_neon
#endif /* __APPLE__ */
	add	x8, x20, #1
	lsr	x10, x8, #3
	lsl	x10, x10, #3
	mov	x0, x22
	mov	w1, w27
	mov	x2, x23
	mov	w3, w10
#ifndef __APPLE__
	bl	wc_mceliece_gf_mulc_mac_neon
#else
	bl	_wc_mceliece_gf_mulc_mac_neon
#endif /* __APPLE__ */
L_mc_bm_msk:
	add	x8, x20, #1
	lsr	x10, x8, #3
	lsl	x10, x10, #3
	mov	x28, x10
L_mc_bm_mt:
	cmp	x28, x20
	bgt	L_mc_bm_mte
	lsl	x5, x28, #1
	add	x6, x21, x5
	ldrh	w1, [x6]
	mov	w0, w26
#ifndef __APPLE__
	bl	wc_mceliece_gf_mul_scalar_neon
#else
	bl	_wc_mceliece_gf_mul_scalar_neon
#endif /* __APPLE__ */
	lsl	x5, x28, #1
	add	x6, x22, x5
	ldrh	w7, [x6]
	eor	w7, w7, w0
	strh	w7, [x6]
	lsl	x5, x28, #1
	add	x6, x23, x5
	ldrh	w1, [x6]
	mov	w0, w27
#ifndef __APPLE__
	bl	wc_mceliece_gf_mul_scalar_neon
#else
	bl	_wc_mceliece_gf_mul_scalar_neon
#endif /* __APPLE__ */
	lsl	x5, x28, #1
	add	x6, x22, x5
	ldrh	w7, [x6]
	eor	w7, w7, w0
	strh	w7, [x6]
	add	x28, x28, #1
	b	L_mc_bm_mt
L_mc_bm_mte:
	sub	w8, w27, #1
	lsr	w8, w8, #31
	sub	w8, w8, #1
	lsl	w7, w25, #1
	sub	w11, w24, w7
	lsr	w11, w11, #31
	sub	w11, w11, #1
	and	w11, w11, w8
	add	w7, w24, #1
	sub	w7, w7, w25
	eor	w8, w25, w7
	and	w8, w8, w11
	eor	w25, w25, w8
	mov	x4, #0
L_mc_bm_bu:
	cmp	x4, x20
	bgt	L_mc_bm_bue
	lsl	x5, x4, #1
	add	x6, x23, x5
	ldrh	w7, [x6]
	add	x6, x21, x5
	ldrh	w8, [x6]
	eor	w8, w8, w7
	and	w8, w8, w11
	eor	w7, w7, w8
	add	x6, x23, x5
	strh	w7, [x6]
	add	x4, x4, #1
	b	L_mc_bm_bu
L_mc_bm_bue:
	eor	w8, w26, w27
	and	w8, w8, w11
	eor	w26, w26, w8
	mov	x4, x20
L_mc_bm_bs:
	cmp	x4, #1
	blt	L_mc_bm_bse
	sub	x8, x4, #1
	lsl	x5, x8, #1
	add	x6, x23, x5
	ldrh	w7, [x6]
	lsl	x5, x4, #1
	add	x6, x23, x5
	strh	w7, [x6]
	sub	x4, x4, #1
	b	L_mc_bm_bs
L_mc_bm_bse:
	mov	w7, #0
	strh	w7, [x23]
	add	x24, x24, #1
	b	L_mc_bm_n
L_mc_bm_ne:
	ldrh	w0, [x22]
#ifndef __APPLE__
	bl	wc_mceliece_gf_inv_scalar_neon
#else
	bl	_wc_mceliece_gf_inv_scalar_neon
#endif /* __APPLE__ */
	mov	w27, w0
	ldr	x24, [x29, #16]
	mov	x28, #0
L_mc_bm_nm:
	cmp	x28, x20
	bgt	L_mc_bm_nme
	sub	x5, x20, x28
	lsl	x5, x5, #1
	add	x6, x22, x5
	ldrh	w0, [x6]
	mov	w1, w27
#ifndef __APPLE__
	bl	wc_mceliece_gf_mul_scalar_neon
#else
	bl	_wc_mceliece_gf_mul_scalar_neon
#endif /* __APPLE__ */
	lsl	x5, x28, #1
	add	x6, x24, x5
	strh	w0, [x6]
	add	x28, x28, #1
	b	L_mc_bm_nm
L_mc_bm_nme:
	ldp	x19, x20, [x29, #32]
	ldp	x21, x22, [x29, #48]
	ldp	x23, x24, [x29, #64]
	ldp	x25, x26, [x29, #80]
	ldp	x27, x28, [x29, #96]
	ldp	x29, x30, [sp], #0x70
	ret
#ifndef __APPLE__
	.size	wc_mceliece_berlekamp_massey_neon,.-wc_mceliece_berlekamp_massey_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_syndrome_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_syndrome_neon)
.type	wc_mceliece_syndrome_neon,@function
.align	2
wc_mceliece_syndrome_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_syndrome_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_syndrome_neon)
.p2align	2
_wc_mceliece_syndrome_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-64]!
	add	x29, sp, #0
	stp	x19, x20, [x29, #24]
	stp	x21, x22, [x29, #40]
	str	x23, [x29, #56]
	mov	x19, x0
	mov	x20, x1
	mov	x21, x2
	mov	x22, x3
	mov	x23, x4
	mov	x0, x22
	mov	x1, x21
	mov	x2, x20
#ifndef __APPLE__
	bl	wc_mceliece_aff_synd_mask_neon
#else
	bl	_wc_mceliece_aff_synd_mask_neon
#endif /* __APPLE__ */
	mov	x0, x19
	mov	x1, x22
	mov	x2, x23
#ifndef __APPLE__
	bl	wc_mceliece_aff_butterflies_tr_neon
#else
	bl	_wc_mceliece_aff_butterflies_tr_neon
#endif /* __APPLE__ */
	mov	x0, x19
	mov	x1, x23
#ifndef __APPLE__
	bl	wc_mceliece_radix_conv_tr_neon
#else
	bl	_wc_mceliece_radix_conv_tr_neon
#endif /* __APPLE__ */
	ldp	x19, x20, [x29, #24]
	ldp	x21, x22, [x29, #40]
	ldr	x23, [x29, #56]
	ldp	x29, x30, [sp], #0x40
	ret
#ifndef __APPLE__
	.size	wc_mceliece_syndrome_neon,.-wc_mceliece_syndrome_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_goppa_eval_inv_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_goppa_eval_inv_neon)
.type	wc_mceliece_goppa_eval_inv_neon,@function
.align	2
wc_mceliece_goppa_eval_inv_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_goppa_eval_inv_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_goppa_eval_inv_neon)
.p2align	2
_wc_mceliece_goppa_eval_inv_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-64]!
	add	x29, sp, #0
	stp	x19, x20, [x29, #16]
	stp	x21, x22, [x29, #32]
	stp	x23, x24, [x29, #48]
	mov	x8, #0x1300
	add	x24, x6, x8
	mov	w11, w3
	mov	x12, #0
	mov	x7, #0
L_mc_gei_l:
	cmp	x7, x11
	bge	L_mc_gei_le
	lsl	x8, x7, #1
	add	x9, x2, x8
	ldrh	w10, [x9]
	and	x10, x10, #0x1fff
	add	x9, x24, x8
	strh	w10, [x9]
	add	x7, x7, #1
	b	L_mc_gei_l
L_mc_gei_le:
	cmp	x11, #0x80
	bge	L_mc_gei_ze
	lsl	x8, x11, #1
	add	x9, x24, x8
	mov	x10, #1
	strh	w10, [x9]
	add	x7, x11, #1
L_mc_gei_z:
	cmp	x7, #0x80
	bge	L_mc_gei_ze
	lsl	x8, x7, #1
	add	x9, x24, x8
	strh	w12, [x9]
	add	x7, x7, #1
	b	L_mc_gei_z
L_mc_gei_ze:
	mov	x19, x0
	mov	x20, x1
	mov	w21, w4
	mov	x22, x5
	mov	x23, x6
	mov	x0, x22
	mov	x1, x24
#ifndef __APPLE__
	bl	wc_mceliece_bs_poly_neon
#else
	bl	_wc_mceliece_bs_poly_neon
#endif /* __APPLE__ */
	mov	x0, x22
	mov	x1, x23
#ifndef __APPLE__
	bl	wc_mceliece_radix_conv_neon
#else
	bl	_wc_mceliece_radix_conv_neon
#endif /* __APPLE__ */
	mov	x0, x20
	mov	x1, x22
	mov	w2, w21
	mov	x3, x23
#ifndef __APPLE__
	bl	wc_mceliece_fft_fwd_butterflies_neon
#else
	bl	_wc_mceliece_fft_fwd_butterflies_neon
#endif /* __APPLE__ */
	mov	x0, x19
	mov	x1, x20
	mov	x2, x23
	add	x3, x23, #0x340
#ifndef __APPLE__
	bl	wc_mceliece_mont_batch_inv_neon
#else
	bl	_wc_mceliece_mont_batch_inv_neon
#endif /* __APPLE__ */
	ldp	x19, x20, [x29, #16]
	ldp	x21, x22, [x29, #32]
	ldp	x23, x24, [x29, #48]
	ldp	x29, x30, [sp], #0x40
	ret
#ifndef __APPLE__
	.size	wc_mceliece_goppa_eval_inv_neon,.-wc_mceliece_goppa_eval_inv_neon
#endif /* __APPLE__ */
#endif /* WOLFSSL_MCELIECE_SMALL */
#endif /* WOLFSSL_MCELIECE_NO_DECAPSULATE */
#if !defined(WOLFSSL_MCELIECE_NO_MAKE_KEY) || !defined(WOLFSSL_MCELIECE_NO_DECAPSULATE)
#ifndef WOLFSSL_MCELIECE_SMALL
#ifndef __APPLE__
.text
.globl	wc_mceliece_aff_transpose_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_aff_transpose_neon)
.type	wc_mceliece_aff_transpose_neon,@function
.align	2
wc_mceliece_aff_transpose_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_aff_transpose_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_aff_transpose_neon)
.p2align	2
_wc_mceliece_aff_transpose_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-48]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
	mov	x5, #0xffffffff
	dup	v10.2d, x5
	mov	x1, #0
L_mc_at_i5:
	cmp	x1, #0x40
	bge	L_mc_at_e5
	mov	x2, x1
	add	x6, x1, #32
L_mc_at_j5:
	cmp	x2, x6
	bge	L_mc_at_ni5
	lsl	x7, x2, #5
	add	x3, x0, x7
	add	x4, x3, #0x400
	ldp	q0, q1, [x3]
	ldp	q2, q3, [x4]
	and	v4.16b, v0.16b, v10.16b
	and	v8.16b, v2.16b, v10.16b
	shl	v8.2d, v8.2d, #32
	orr	v4.16b, v4.16b, v8.16b
	and	v5.16b, v1.16b, v10.16b
	and	v9.16b, v3.16b, v10.16b
	shl	v9.2d, v9.2d, #32
	orr	v5.16b, v5.16b, v9.16b
	bic	v6.16b, v0.16b, v10.16b
	ushr	v6.2d, v6.2d, #32
	bic	v8.16b, v2.16b, v10.16b
	orr	v6.16b, v6.16b, v8.16b
	bic	v7.16b, v1.16b, v10.16b
	ushr	v7.2d, v7.2d, #32
	bic	v9.16b, v3.16b, v10.16b
	orr	v7.16b, v7.16b, v9.16b
	stp	q4, q5, [x3]
	stp	q6, q7, [x4]
	add	x2, x2, #1
	b	L_mc_at_j5
L_mc_at_ni5:
	add	x1, x1, #0x40
	b	L_mc_at_i5
L_mc_at_e5:
	mov	x5, #0xffff0000ffff
	dup	v10.2d, x5
	mov	x1, #0
L_mc_at_i4:
	cmp	x1, #0x40
	bge	L_mc_at_e4
	mov	x2, x1
	add	x6, x1, #16
L_mc_at_j4:
	cmp	x2, x6
	bge	L_mc_at_ni4
	lsl	x7, x2, #5
	add	x3, x0, x7
	add	x4, x3, #0x200
	ldp	q0, q1, [x3]
	ldp	q2, q3, [x4]
	and	v4.16b, v0.16b, v10.16b
	and	v8.16b, v2.16b, v10.16b
	shl	v8.2d, v8.2d, #16
	orr	v4.16b, v4.16b, v8.16b
	and	v5.16b, v1.16b, v10.16b
	and	v9.16b, v3.16b, v10.16b
	shl	v9.2d, v9.2d, #16
	orr	v5.16b, v5.16b, v9.16b
	bic	v6.16b, v0.16b, v10.16b
	ushr	v6.2d, v6.2d, #16
	bic	v8.16b, v2.16b, v10.16b
	orr	v6.16b, v6.16b, v8.16b
	bic	v7.16b, v1.16b, v10.16b
	ushr	v7.2d, v7.2d, #16
	bic	v9.16b, v3.16b, v10.16b
	orr	v7.16b, v7.16b, v9.16b
	stp	q4, q5, [x3]
	stp	q6, q7, [x4]
	add	x2, x2, #1
	b	L_mc_at_j4
L_mc_at_ni4:
	add	x1, x1, #32
	b	L_mc_at_i4
L_mc_at_e4:
	mov	x5, #0xff00ff00ff00ff
	dup	v10.2d, x5
	mov	x1, #0
L_mc_at_i3:
	cmp	x1, #0x40
	bge	L_mc_at_e3
	mov	x2, x1
	add	x6, x1, #8
L_mc_at_j3:
	cmp	x2, x6
	bge	L_mc_at_ni3
	lsl	x7, x2, #5
	add	x3, x0, x7
	add	x4, x3, #0x100
	ldp	q0, q1, [x3]
	ldp	q2, q3, [x4]
	and	v4.16b, v0.16b, v10.16b
	and	v8.16b, v2.16b, v10.16b
	shl	v8.2d, v8.2d, #8
	orr	v4.16b, v4.16b, v8.16b
	and	v5.16b, v1.16b, v10.16b
	and	v9.16b, v3.16b, v10.16b
	shl	v9.2d, v9.2d, #8
	orr	v5.16b, v5.16b, v9.16b
	bic	v6.16b, v0.16b, v10.16b
	ushr	v6.2d, v6.2d, #8
	bic	v8.16b, v2.16b, v10.16b
	orr	v6.16b, v6.16b, v8.16b
	bic	v7.16b, v1.16b, v10.16b
	ushr	v7.2d, v7.2d, #8
	bic	v9.16b, v3.16b, v10.16b
	orr	v7.16b, v7.16b, v9.16b
	stp	q4, q5, [x3]
	stp	q6, q7, [x4]
	add	x2, x2, #1
	b	L_mc_at_j3
L_mc_at_ni3:
	add	x1, x1, #16
	b	L_mc_at_i3
L_mc_at_e3:
	mov	x5, #0xf0f0f0f0f0f0f0f
	dup	v10.2d, x5
	mov	x1, #0
L_mc_at_i2:
	cmp	x1, #0x40
	bge	L_mc_at_e2
	mov	x2, x1
	add	x6, x1, #4
L_mc_at_j2:
	cmp	x2, x6
	bge	L_mc_at_ni2
	lsl	x7, x2, #5
	add	x3, x0, x7
	add	x4, x3, #0x80
	ldp	q0, q1, [x3]
	ldp	q2, q3, [x4]
	and	v4.16b, v0.16b, v10.16b
	and	v8.16b, v2.16b, v10.16b
	shl	v8.2d, v8.2d, #4
	orr	v4.16b, v4.16b, v8.16b
	and	v5.16b, v1.16b, v10.16b
	and	v9.16b, v3.16b, v10.16b
	shl	v9.2d, v9.2d, #4
	orr	v5.16b, v5.16b, v9.16b
	bic	v6.16b, v0.16b, v10.16b
	ushr	v6.2d, v6.2d, #4
	bic	v8.16b, v2.16b, v10.16b
	orr	v6.16b, v6.16b, v8.16b
	bic	v7.16b, v1.16b, v10.16b
	ushr	v7.2d, v7.2d, #4
	bic	v9.16b, v3.16b, v10.16b
	orr	v7.16b, v7.16b, v9.16b
	stp	q4, q5, [x3]
	stp	q6, q7, [x4]
	add	x2, x2, #1
	b	L_mc_at_j2
L_mc_at_ni2:
	add	x1, x1, #8
	b	L_mc_at_i2
L_mc_at_e2:
	mov	x5, #0x3333333333333333
	dup	v10.2d, x5
	mov	x1, #0
L_mc_at_i1:
	cmp	x1, #0x40
	bge	L_mc_at_e1
	mov	x2, x1
	add	x6, x1, #2
L_mc_at_j1:
	cmp	x2, x6
	bge	L_mc_at_ni1
	lsl	x7, x2, #5
	add	x3, x0, x7
	add	x4, x3, #0x40
	ldp	q0, q1, [x3]
	ldp	q2, q3, [x4]
	and	v4.16b, v0.16b, v10.16b
	and	v8.16b, v2.16b, v10.16b
	shl	v8.2d, v8.2d, #2
	orr	v4.16b, v4.16b, v8.16b
	and	v5.16b, v1.16b, v10.16b
	and	v9.16b, v3.16b, v10.16b
	shl	v9.2d, v9.2d, #2
	orr	v5.16b, v5.16b, v9.16b
	bic	v6.16b, v0.16b, v10.16b
	ushr	v6.2d, v6.2d, #2
	bic	v8.16b, v2.16b, v10.16b
	orr	v6.16b, v6.16b, v8.16b
	bic	v7.16b, v1.16b, v10.16b
	ushr	v7.2d, v7.2d, #2
	bic	v9.16b, v3.16b, v10.16b
	orr	v7.16b, v7.16b, v9.16b
	stp	q4, q5, [x3]
	stp	q6, q7, [x4]
	add	x2, x2, #1
	b	L_mc_at_j1
L_mc_at_ni1:
	add	x1, x1, #4
	b	L_mc_at_i1
L_mc_at_e1:
	mov	x5, #0x5555555555555555
	dup	v10.2d, x5
	mov	x1, #0
L_mc_at_i0:
	cmp	x1, #0x40
	bge	L_mc_at_e0
	mov	x2, x1
	add	x6, x1, #1
L_mc_at_j0:
	cmp	x2, x6
	bge	L_mc_at_ni0
	lsl	x7, x2, #5
	add	x3, x0, x7
	add	x4, x3, #32
	ldp	q0, q1, [x3]
	ldp	q2, q3, [x4]
	and	v4.16b, v0.16b, v10.16b
	and	v8.16b, v2.16b, v10.16b
	shl	v8.2d, v8.2d, #1
	orr	v4.16b, v4.16b, v8.16b
	and	v5.16b, v1.16b, v10.16b
	and	v9.16b, v3.16b, v10.16b
	shl	v9.2d, v9.2d, #1
	orr	v5.16b, v5.16b, v9.16b
	bic	v6.16b, v0.16b, v10.16b
	ushr	v6.2d, v6.2d, #1
	bic	v8.16b, v2.16b, v10.16b
	orr	v6.16b, v6.16b, v8.16b
	bic	v7.16b, v1.16b, v10.16b
	ushr	v7.2d, v7.2d, #1
	bic	v9.16b, v3.16b, v10.16b
	orr	v7.16b, v7.16b, v9.16b
	stp	q4, q5, [x3]
	stp	q6, q7, [x4]
	add	x2, x2, #1
	b	L_mc_at_j0
L_mc_at_ni0:
	add	x1, x1, #2
	b	L_mc_at_i0
L_mc_at_e0:
	ldp	d8, d9, [x29, #16]
	ldp	d10, d11, [x29, #32]
	ldp	x29, x30, [sp], #48
	ret
#ifndef __APPLE__
	.size	wc_mceliece_aff_transpose_neon,.-wc_mceliece_aff_transpose_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_aff_v128_mul_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_aff_v128_mul_neon)
.type	wc_mceliece_aff_v128_mul_neon,@function
.align	2
wc_mceliece_aff_v128_mul_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_aff_v128_mul_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_aff_v128_mul_neon)
.p2align	2
_wc_mceliece_aff_v128_mul_neon:
#endif /* __APPLE__ */
	eor	v5.16b, v5.16b, v5.16b
	mov	x11, x3
	mov	x6, #0
L_mc_v128_z:
	str	q5, [x11]
	add	x11, x11, #16
	add	x6, x6, #1
	cmp	x6, #25
	blt	L_mc_v128_z
	mov	x4, #0
L_mc_v128_i:
	cmp	x4, #13
	bge	L_mc_v128_rs
	lsl	x12, x4, #4
	add	x7, x1, x12
	ldr	q0, [x7]
	mov	x5, #0
L_mc_v128_j:
	cmp	x5, #13
	bge	L_mc_v128_in
	lsl	x12, x5, #4
	add	x8, x2, x12
	ldr	q1, [x8]
	and	v2.16b, v0.16b, v1.16b
	add	x12, x4, x5
	lsl	x12, x12, #4
	add	x9, x3, x12
	ldr	q3, [x9]
	eor	v3.16b, v3.16b, v2.16b
	str	q3, [x9]
	add	x5, x5, #1
	b	L_mc_v128_j
L_mc_v128_in:
	add	x4, x4, #1
	b	L_mc_v128_i
L_mc_v128_rs:
	mov	x6, #24
L_mc_v128_rk:
	cmp	x6, #13
	blt	L_mc_v128_copy
	lsl	x12, x6, #4
	add	x9, x3, x12
	ldr	q3, [x9]
	sub	x13, x6, #9
	lsl	x13, x13, #4
	add	x10, x3, x13
	ldr	q4, [x10]
	eor	v4.16b, v4.16b, v3.16b
	str	q4, [x10]
	sub	x13, x6, #10
	lsl	x13, x13, #4
	add	x10, x3, x13
	ldr	q4, [x10]
	eor	v4.16b, v4.16b, v3.16b
	str	q4, [x10]
	sub	x13, x6, #12
	lsl	x13, x13, #4
	add	x10, x3, x13
	ldr	q4, [x10]
	eor	v4.16b, v4.16b, v3.16b
	str	q4, [x10]
	sub	x13, x6, #13
	lsl	x13, x13, #4
	add	x10, x3, x13
	ldr	q4, [x10]
	eor	v4.16b, v4.16b, v3.16b
	str	q4, [x10]
	sub	x6, x6, #1
	b	L_mc_v128_rk
L_mc_v128_copy:
	mov	x6, #0
L_mc_v128_cp:
	cmp	x6, #13
	bge	L_mc_v128_done
	lsl	x12, x6, #4
	add	x9, x3, x12
	add	x10, x0, x12
	ldr	q3, [x9]
	str	q3, [x10]
	add	x6, x6, #1
	b	L_mc_v128_cp
L_mc_v128_done:
	ret
#ifndef __APPLE__
	.size	wc_mceliece_aff_v128_mul_neon,.-wc_mceliece_aff_v128_mul_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_aff_v256_mul_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_aff_v256_mul_neon)
.type	wc_mceliece_aff_v256_mul_neon,@function
.align	2
wc_mceliece_aff_v256_mul_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_aff_v256_mul_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_aff_v256_mul_neon)
.p2align	2
_wc_mceliece_aff_v256_mul_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-48]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
	eor	v10.16b, v10.16b, v10.16b
	mov	x11, x3
	mov	x6, #0
L_mc_v256_z:
	stp	q10, q10, [x11]
	add	x11, x11, #32
	add	x6, x6, #1
	cmp	x6, #25
	blt	L_mc_v256_z
	mov	x4, #0
L_mc_v256_i:
	cmp	x4, #13
	bge	L_mc_v256_rs
	lsl	x12, x4, #5
	add	x7, x1, x12
	ldp	q0, q1, [x7]
	mov	x5, #0
L_mc_v256_j:
	cmp	x5, #13
	bge	L_mc_v256_in
	lsl	x12, x5, #5
	add	x8, x2, x12
	ldp	q2, q3, [x8]
	and	v4.16b, v0.16b, v2.16b
	and	v5.16b, v1.16b, v3.16b
	add	x12, x4, x5
	lsl	x12, x12, #5
	add	x9, x3, x12
	ldp	q6, q7, [x9]
	eor	v6.16b, v6.16b, v4.16b
	eor	v7.16b, v7.16b, v5.16b
	stp	q6, q7, [x9]
	add	x5, x5, #1
	b	L_mc_v256_j
L_mc_v256_in:
	add	x4, x4, #1
	b	L_mc_v256_i
L_mc_v256_rs:
	mov	x6, #24
L_mc_v256_rk:
	cmp	x6, #13
	blt	L_mc_v256_copy
	lsl	x12, x6, #5
	add	x9, x3, x12
	ldp	q6, q7, [x9]
	sub	x13, x6, #9
	lsl	x13, x13, #5
	add	x10, x3, x13
	ldp	q8, q9, [x10]
	eor	v8.16b, v8.16b, v6.16b
	eor	v9.16b, v9.16b, v7.16b
	stp	q8, q9, [x10]
	sub	x13, x6, #10
	lsl	x13, x13, #5
	add	x10, x3, x13
	ldp	q8, q9, [x10]
	eor	v8.16b, v8.16b, v6.16b
	eor	v9.16b, v9.16b, v7.16b
	stp	q8, q9, [x10]
	sub	x13, x6, #12
	lsl	x13, x13, #5
	add	x10, x3, x13
	ldp	q8, q9, [x10]
	eor	v8.16b, v8.16b, v6.16b
	eor	v9.16b, v9.16b, v7.16b
	stp	q8, q9, [x10]
	sub	x13, x6, #13
	lsl	x13, x13, #5
	add	x10, x3, x13
	ldp	q8, q9, [x10]
	eor	v8.16b, v8.16b, v6.16b
	eor	v9.16b, v9.16b, v7.16b
	stp	q8, q9, [x10]
	sub	x6, x6, #1
	b	L_mc_v256_rk
L_mc_v256_copy:
	mov	x6, #0
L_mc_v256_cp:
	cmp	x6, #13
	bge	L_mc_v256_done
	lsl	x12, x6, #5
	add	x9, x3, x12
	add	x10, x0, x12
	ldp	q6, q7, [x9]
	stp	q6, q7, [x10]
	add	x6, x6, #1
	b	L_mc_v256_cp
L_mc_v256_done:
	ldp	d8, d9, [x29, #16]
	ldp	d10, d11, [x29, #32]
	ldp	x29, x30, [sp], #48
	ret
#ifndef __APPLE__
	.size	wc_mceliece_aff_v256_mul_neon,.-wc_mceliece_aff_v256_mul_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_aff_v256_sqr_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_aff_v256_sqr_neon)
.type	wc_mceliece_aff_v256_sqr_neon,@function
.align	2
wc_mceliece_aff_v256_sqr_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_aff_v256_sqr_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_aff_v256_sqr_neon)
.p2align	2
_wc_mceliece_aff_v256_sqr_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
	stp	d12, d13, [x29, #48]
	stp	d14, d15, [x29, #64]
	mov	x2, x1
	ldp	q0, q1, [x2]
	add	x2, x2, #32
	ldp	q2, q3, [x2]
	add	x2, x2, #32
	ldp	q4, q5, [x2]
	add	x2, x2, #32
	ldp	q6, q7, [x2]
	add	x2, x2, #32
	ldp	q8, q9, [x2]
	add	x2, x2, #32
	ldp	q10, q11, [x2]
	add	x2, x2, #32
	ldp	q12, q13, [x2]
	add	x2, x2, #32
	ldp	q14, q15, [x2]
	add	x2, x2, #32
	ldp	q16, q17, [x2]
	add	x2, x2, #32
	ldp	q18, q19, [x2]
	add	x2, x2, #32
	ldp	q20, q21, [x2]
	add	x2, x2, #32
	ldp	q22, q23, [x2]
	add	x2, x2, #32
	ldp	q24, q25, [x2]
	add	x2, x2, #32
	mov	x3, x0
	eor	v26.16b, v0.16b, v22.16b
	eor	v27.16b, v1.16b, v23.16b
	stp	q26, q27, [x3]
	add	x3, x3, #32
	eor	v26.16b, v14.16b, v22.16b
	eor	v27.16b, v15.16b, v23.16b
	eor	v26.16b, v26.16b, v24.16b
	eor	v27.16b, v27.16b, v25.16b
	stp	q26, q27, [x3]
	add	x3, x3, #32
	eor	v26.16b, v2.16b, v14.16b
	eor	v27.16b, v3.16b, v15.16b
	stp	q26, q27, [x3]
	add	x3, x3, #32
	eor	v26.16b, v16.16b, v22.16b
	eor	v27.16b, v17.16b, v23.16b
	eor	v26.16b, v26.16b, v24.16b
	eor	v27.16b, v27.16b, v25.16b
	stp	q26, q27, [x3]
	add	x3, x3, #32
	eor	v26.16b, v4.16b, v14.16b
	eor	v27.16b, v5.16b, v15.16b
	eor	v26.16b, v26.16b, v16.16b
	eor	v27.16b, v27.16b, v17.16b
	eor	v26.16b, v26.16b, v22.16b
	eor	v27.16b, v27.16b, v23.16b
	eor	v26.16b, v26.16b, v24.16b
	eor	v27.16b, v27.16b, v25.16b
	stp	q26, q27, [x3]
	add	x3, x3, #32
	eor	v26.16b, v14.16b, v18.16b
	eor	v27.16b, v15.16b, v19.16b
	stp	q26, q27, [x3]
	add	x3, x3, #32
	eor	v26.16b, v6.16b, v16.16b
	eor	v27.16b, v7.16b, v17.16b
	eor	v26.16b, v26.16b, v18.16b
	eor	v27.16b, v27.16b, v19.16b
	eor	v26.16b, v26.16b, v24.16b
	eor	v27.16b, v27.16b, v25.16b
	stp	q26, q27, [x3]
	add	x3, x3, #32
	eor	v26.16b, v16.16b, v20.16b
	eor	v27.16b, v17.16b, v21.16b
	stp	q26, q27, [x3]
	add	x3, x3, #32
	eor	v26.16b, v8.16b, v18.16b
	eor	v27.16b, v9.16b, v19.16b
	eor	v26.16b, v26.16b, v20.16b
	eor	v27.16b, v27.16b, v21.16b
	stp	q26, q27, [x3]
	add	x3, x3, #32
	eor	v26.16b, v18.16b, v22.16b
	eor	v27.16b, v19.16b, v23.16b
	stp	q26, q27, [x3]
	add	x3, x3, #32
	eor	v26.16b, v10.16b, v20.16b
	eor	v27.16b, v11.16b, v21.16b
	eor	v26.16b, v26.16b, v22.16b
	eor	v27.16b, v27.16b, v23.16b
	stp	q26, q27, [x3]
	add	x3, x3, #32
	eor	v26.16b, v20.16b, v24.16b
	eor	v27.16b, v21.16b, v25.16b
	stp	q26, q27, [x3]
	add	x3, x3, #32
	eor	v26.16b, v12.16b, v22.16b
	eor	v27.16b, v13.16b, v23.16b
	eor	v26.16b, v26.16b, v24.16b
	eor	v27.16b, v27.16b, v25.16b
	stp	q26, q27, [x3]
	add	x3, x3, #32
	ldp	d8, d9, [x29, #16]
	ldp	d10, d11, [x29, #32]
	ldp	d12, d13, [x29, #48]
	ldp	d14, d15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
#ifndef __APPLE__
	.size	wc_mceliece_aff_v256_sqr_neon,.-wc_mceliece_aff_v256_sqr_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_radix_conv_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_radix_conv_neon)
.type	wc_mceliece_radix_conv_neon,@function
.align	2
wc_mceliece_radix_conv_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_radix_conv_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_radix_conv_neon)
.p2align	2
_wc_mceliece_radix_conv_neon:
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x4, L_mc_aff_rmask0_neon
	add  x4, x4, :lo12:L_mc_aff_rmask0_neon
#else
	adrp x4, L_mc_aff_rmask0_neon@PAGE
	add  x4, x4, L_mc_aff_rmask0_neon@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x5, L_mc_aff_rmask1_neon
	add  x5, x5, :lo12:L_mc_aff_rmask1_neon
#else
	adrp x5, L_mc_aff_rmask1_neon@PAGE
	add  x5, x5, L_mc_aff_rmask1_neon@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x6, L_mc_aff_scal2x_neon
	add  x6, x6, :lo12:L_mc_aff_scal2x_neon
#else
	adrp x6, L_mc_aff_scal2x_neon@PAGE
	add  x6, x6, L_mc_aff_scal2x_neon@PAGEOFF
#endif /* __APPLE__ */
	mov	x2, #0
L_mc_rconv_j:
	cmp	x2, #5
	bgt	L_mc_rconv_je
	eor	v6.16b, v6.16b, v6.16b
	mov	x16, #1
	mov	x10, #0
L_mc_rdx_t_rc:
	cmp	x10, #13
	bge	L_mc_rdx_te_rc
	lsl	x11, x10, #4
	add	x12, x0, x11
	ldr	q0, [x12]
	ushr	v5.2d, v0.2d, #32
	zip2	v5.2d, v6.2d, v5.2d
	eor	v0.16b, v0.16b, v5.16b
	shl	v5.2d, v0.2d, #32
	zip2	v5.2d, v5.2d, v6.2d
	eor	v0.16b, v0.16b, v5.16b
	str	q0, [x12]
	add	x10, x10, #1
	b	L_mc_rdx_t_rc
L_mc_rdx_te_rc:
	mov	x7, #4
L_mc_rdx_k_rc:
	cmp	x7, x2
	blt	L_mc_rdx_ke_rc
	lsl	x8, x16, x7
	neg	x9, x8
	dup	v4.2d, x9
	lsl	x11, x7, #3
	add	x13, x4, x11
	ldr	x14, [x13]
	dup	v2.2d, x14
	add	x13, x5, x11
	ldr	x15, [x13]
	dup	v3.2d, x15
	mov	x10, #0
L_mc_rdx_ki_rc:
	cmp	x10, #13
	bge	L_mc_rdx_kie_rc
	lsl	x11, x10, #4
	add	x12, x0, x11
	ldr	q0, [x12]
	and	v1.16b, v0.16b, v2.16b
	ushl	v1.2d, v1.2d, v4.2d
	eor	v0.16b, v0.16b, v1.16b
	and	v1.16b, v0.16b, v3.16b
	ushl	v1.2d, v1.2d, v4.2d
	eor	v0.16b, v0.16b, v1.16b
	str	q0, [x12]
	add	x10, x10, #1
	b	L_mc_rdx_ki_rc
L_mc_rdx_kie_rc:
	sub	x7, x7, #1
	b	L_mc_rdx_k_rc
L_mc_rdx_ke_rc:
	cmp	x2, #5
	bge	L_mc_rconv_sk
	mov	x3, #0xd0
	mul	x3, x2, x3
	add	x3, x6, x3
	eor	v5.16b, v5.16b, v5.16b
	mov	x14, x1
	mov	x9, #0
L_mc_v128_z_rc:
	str	q5, [x14]
	add	x14, x14, #16
	add	x9, x9, #1
	cmp	x9, #25
	blt	L_mc_v128_z_rc
	mov	x7, #0
L_mc_v128_i_rc:
	cmp	x7, #13
	bge	L_mc_v128_rs_rc
	lsl	x15, x7, #4
	add	x10, x0, x15
	ldr	q0, [x10]
	mov	x8, #0
L_mc_v128_j_rc:
	cmp	x8, #13
	bge	L_mc_v128_in_rc
	lsl	x15, x8, #4
	add	x11, x3, x15
	ldr	q1, [x11]
	and	v2.16b, v0.16b, v1.16b
	add	x15, x7, x8
	lsl	x15, x15, #4
	add	x12, x1, x15
	ldr	q3, [x12]
	eor	v3.16b, v3.16b, v2.16b
	str	q3, [x12]
	add	x8, x8, #1
	b	L_mc_v128_j_rc
L_mc_v128_in_rc:
	add	x7, x7, #1
	b	L_mc_v128_i_rc
L_mc_v128_rs_rc:
	mov	x9, #24
L_mc_v128_rk_rc:
	cmp	x9, #13
	blt	L_mc_v128_copy_rc
	lsl	x15, x9, #4
	add	x12, x1, x15
	ldr	q3, [x12]
	sub	x16, x9, #9
	lsl	x16, x16, #4
	add	x13, x1, x16
	ldr	q4, [x13]
	eor	v4.16b, v4.16b, v3.16b
	str	q4, [x13]
	sub	x16, x9, #10
	lsl	x16, x16, #4
	add	x13, x1, x16
	ldr	q4, [x13]
	eor	v4.16b, v4.16b, v3.16b
	str	q4, [x13]
	sub	x16, x9, #12
	lsl	x16, x16, #4
	add	x13, x1, x16
	ldr	q4, [x13]
	eor	v4.16b, v4.16b, v3.16b
	str	q4, [x13]
	sub	x16, x9, #13
	lsl	x16, x16, #4
	add	x13, x1, x16
	ldr	q4, [x13]
	eor	v4.16b, v4.16b, v3.16b
	str	q4, [x13]
	sub	x9, x9, #1
	b	L_mc_v128_rk_rc
L_mc_v128_copy_rc:
	mov	x9, #0
L_mc_v128_cp_rc:
	cmp	x9, #13
	bge	L_mc_v128_done_rc
	lsl	x15, x9, #4
	add	x12, x1, x15
	add	x13, x0, x15
	ldr	q3, [x12]
	str	q3, [x13]
	add	x9, x9, #1
	b	L_mc_v128_cp_rc
L_mc_v128_done_rc:
L_mc_rconv_sk:
	add	x2, x2, #1
	b	L_mc_rconv_j
L_mc_rconv_je:
	ret
#ifndef __APPLE__
	.size	wc_mceliece_radix_conv_neon,.-wc_mceliece_radix_conv_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_aff_inv256_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_aff_inv256_neon)
.type	wc_mceliece_aff_inv256_neon,@function
.align	2
wc_mceliece_aff_inv256_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_aff_inv256_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_aff_inv256_neon)
.p2align	2
_wc_mceliece_aff_inv256_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
	stp	d12, d13, [x29, #48]
	stp	d14, d15, [x29, #64]
	mov	x6, x1
	ldp	q0, q1, [x6]
	add	x6, x6, #32
	ldp	q2, q3, [x6]
	add	x6, x6, #32
	ldp	q4, q5, [x6]
	add	x6, x6, #32
	ldp	q6, q7, [x6]
	add	x6, x6, #32
	ldp	q8, q9, [x6]
	add	x6, x6, #32
	ldp	q10, q11, [x6]
	add	x6, x6, #32
	ldp	q12, q13, [x6]
	add	x6, x6, #32
	ldp	q14, q15, [x6]
	add	x6, x6, #32
	ldp	q16, q17, [x6]
	add	x6, x6, #32
	ldp	q18, q19, [x6]
	add	x6, x6, #32
	ldp	q20, q21, [x6]
	add	x6, x6, #32
	ldp	q22, q23, [x6]
	add	x6, x6, #32
	ldp	q24, q25, [x6]
	add	x6, x6, #32
	mov	x7, x2
	eor	v26.16b, v0.16b, v22.16b
	eor	v27.16b, v1.16b, v23.16b
	stp	q26, q27, [x7]
	add	x7, x7, #32
	eor	v26.16b, v14.16b, v22.16b
	eor	v27.16b, v15.16b, v23.16b
	eor	v26.16b, v26.16b, v24.16b
	eor	v27.16b, v27.16b, v25.16b
	stp	q26, q27, [x7]
	add	x7, x7, #32
	eor	v26.16b, v2.16b, v14.16b
	eor	v27.16b, v3.16b, v15.16b
	stp	q26, q27, [x7]
	add	x7, x7, #32
	eor	v26.16b, v16.16b, v22.16b
	eor	v27.16b, v17.16b, v23.16b
	eor	v26.16b, v26.16b, v24.16b
	eor	v27.16b, v27.16b, v25.16b
	stp	q26, q27, [x7]
	add	x7, x7, #32
	eor	v26.16b, v4.16b, v14.16b
	eor	v27.16b, v5.16b, v15.16b
	eor	v26.16b, v26.16b, v16.16b
	eor	v27.16b, v27.16b, v17.16b
	eor	v26.16b, v26.16b, v22.16b
	eor	v27.16b, v27.16b, v23.16b
	eor	v26.16b, v26.16b, v24.16b
	eor	v27.16b, v27.16b, v25.16b
	stp	q26, q27, [x7]
	add	x7, x7, #32
	eor	v26.16b, v14.16b, v18.16b
	eor	v27.16b, v15.16b, v19.16b
	stp	q26, q27, [x7]
	add	x7, x7, #32
	eor	v26.16b, v6.16b, v16.16b
	eor	v27.16b, v7.16b, v17.16b
	eor	v26.16b, v26.16b, v18.16b
	eor	v27.16b, v27.16b, v19.16b
	eor	v26.16b, v26.16b, v24.16b
	eor	v27.16b, v27.16b, v25.16b
	stp	q26, q27, [x7]
	add	x7, x7, #32
	eor	v26.16b, v16.16b, v20.16b
	eor	v27.16b, v17.16b, v21.16b
	stp	q26, q27, [x7]
	add	x7, x7, #32
	eor	v26.16b, v8.16b, v18.16b
	eor	v27.16b, v9.16b, v19.16b
	eor	v26.16b, v26.16b, v20.16b
	eor	v27.16b, v27.16b, v21.16b
	stp	q26, q27, [x7]
	add	x7, x7, #32
	eor	v26.16b, v18.16b, v22.16b
	eor	v27.16b, v19.16b, v23.16b
	stp	q26, q27, [x7]
	add	x7, x7, #32
	eor	v26.16b, v10.16b, v20.16b
	eor	v27.16b, v11.16b, v21.16b
	eor	v26.16b, v26.16b, v22.16b
	eor	v27.16b, v27.16b, v23.16b
	stp	q26, q27, [x7]
	add	x7, x7, #32
	eor	v26.16b, v20.16b, v24.16b
	eor	v27.16b, v21.16b, v25.16b
	stp	q26, q27, [x7]
	add	x7, x7, #32
	eor	v26.16b, v12.16b, v22.16b
	eor	v27.16b, v13.16b, v23.16b
	eor	v26.16b, v26.16b, v24.16b
	eor	v27.16b, v27.16b, v25.16b
	stp	q26, q27, [x7]
	add	x7, x7, #32
	mov	x5, #0
L_mc_inv_cp:
	cmp	x5, #13
	bge	L_mc_inv_cpe
	lsl	x6, x5, #5
	add	x7, x2, x6
	ldp	q0, q1, [x7]
	add	x8, x0, x6
	stp	q0, q1, [x8]
	add	x5, x5, #1
	b	L_mc_inv_cp
L_mc_inv_cpe:
	mov	x4, #2
L_mc_inv_l:
	cmp	x4, #12
	bgt	L_mc_inv_le
	mov	x6, x2
	ldp	q0, q1, [x6]
	add	x6, x6, #32
	ldp	q2, q3, [x6]
	add	x6, x6, #32
	ldp	q4, q5, [x6]
	add	x6, x6, #32
	ldp	q6, q7, [x6]
	add	x6, x6, #32
	ldp	q8, q9, [x6]
	add	x6, x6, #32
	ldp	q10, q11, [x6]
	add	x6, x6, #32
	ldp	q12, q13, [x6]
	add	x6, x6, #32
	ldp	q14, q15, [x6]
	add	x6, x6, #32
	ldp	q16, q17, [x6]
	add	x6, x6, #32
	ldp	q18, q19, [x6]
	add	x6, x6, #32
	ldp	q20, q21, [x6]
	add	x6, x6, #32
	ldp	q22, q23, [x6]
	add	x6, x6, #32
	ldp	q24, q25, [x6]
	add	x6, x6, #32
	mov	x7, x2
	eor	v26.16b, v0.16b, v22.16b
	eor	v27.16b, v1.16b, v23.16b
	stp	q26, q27, [x7]
	add	x7, x7, #32
	eor	v26.16b, v14.16b, v22.16b
	eor	v27.16b, v15.16b, v23.16b
	eor	v26.16b, v26.16b, v24.16b
	eor	v27.16b, v27.16b, v25.16b
	stp	q26, q27, [x7]
	add	x7, x7, #32
	eor	v26.16b, v2.16b, v14.16b
	eor	v27.16b, v3.16b, v15.16b
	stp	q26, q27, [x7]
	add	x7, x7, #32
	eor	v26.16b, v16.16b, v22.16b
	eor	v27.16b, v17.16b, v23.16b
	eor	v26.16b, v26.16b, v24.16b
	eor	v27.16b, v27.16b, v25.16b
	stp	q26, q27, [x7]
	add	x7, x7, #32
	eor	v26.16b, v4.16b, v14.16b
	eor	v27.16b, v5.16b, v15.16b
	eor	v26.16b, v26.16b, v16.16b
	eor	v27.16b, v27.16b, v17.16b
	eor	v26.16b, v26.16b, v22.16b
	eor	v27.16b, v27.16b, v23.16b
	eor	v26.16b, v26.16b, v24.16b
	eor	v27.16b, v27.16b, v25.16b
	stp	q26, q27, [x7]
	add	x7, x7, #32
	eor	v26.16b, v14.16b, v18.16b
	eor	v27.16b, v15.16b, v19.16b
	stp	q26, q27, [x7]
	add	x7, x7, #32
	eor	v26.16b, v6.16b, v16.16b
	eor	v27.16b, v7.16b, v17.16b
	eor	v26.16b, v26.16b, v18.16b
	eor	v27.16b, v27.16b, v19.16b
	eor	v26.16b, v26.16b, v24.16b
	eor	v27.16b, v27.16b, v25.16b
	stp	q26, q27, [x7]
	add	x7, x7, #32
	eor	v26.16b, v16.16b, v20.16b
	eor	v27.16b, v17.16b, v21.16b
	stp	q26, q27, [x7]
	add	x7, x7, #32
	eor	v26.16b, v8.16b, v18.16b
	eor	v27.16b, v9.16b, v19.16b
	eor	v26.16b, v26.16b, v20.16b
	eor	v27.16b, v27.16b, v21.16b
	stp	q26, q27, [x7]
	add	x7, x7, #32
	eor	v26.16b, v18.16b, v22.16b
	eor	v27.16b, v19.16b, v23.16b
	stp	q26, q27, [x7]
	add	x7, x7, #32
	eor	v26.16b, v10.16b, v20.16b
	eor	v27.16b, v11.16b, v21.16b
	eor	v26.16b, v26.16b, v22.16b
	eor	v27.16b, v27.16b, v23.16b
	stp	q26, q27, [x7]
	add	x7, x7, #32
	eor	v26.16b, v20.16b, v24.16b
	eor	v27.16b, v21.16b, v25.16b
	stp	q26, q27, [x7]
	add	x7, x7, #32
	eor	v26.16b, v12.16b, v22.16b
	eor	v27.16b, v13.16b, v23.16b
	eor	v26.16b, v26.16b, v24.16b
	eor	v27.16b, v27.16b, v25.16b
	stp	q26, q27, [x7]
	add	x7, x7, #32
	eor	v10.16b, v10.16b, v10.16b
	mov	x13, x3
	mov	x8, #0
L_mc_v256_z_iv:
	stp	q10, q10, [x13]
	add	x13, x13, #32
	add	x8, x8, #1
	cmp	x8, #25
	blt	L_mc_v256_z_iv
	mov	x6, #0
L_mc_v256_i_iv:
	cmp	x6, #13
	bge	L_mc_v256_rs_iv
	lsl	x14, x6, #5
	add	x9, x0, x14
	ldp	q0, q1, [x9]
	mov	x7, #0
L_mc_v256_j_iv:
	cmp	x7, #13
	bge	L_mc_v256_in_iv
	lsl	x14, x7, #5
	add	x10, x2, x14
	ldp	q2, q3, [x10]
	and	v4.16b, v0.16b, v2.16b
	and	v5.16b, v1.16b, v3.16b
	add	x14, x6, x7
	lsl	x14, x14, #5
	add	x11, x3, x14
	ldp	q6, q7, [x11]
	eor	v6.16b, v6.16b, v4.16b
	eor	v7.16b, v7.16b, v5.16b
	stp	q6, q7, [x11]
	add	x7, x7, #1
	b	L_mc_v256_j_iv
L_mc_v256_in_iv:
	add	x6, x6, #1
	b	L_mc_v256_i_iv
L_mc_v256_rs_iv:
	mov	x8, #24
L_mc_v256_rk_iv:
	cmp	x8, #13
	blt	L_mc_v256_copy_iv
	lsl	x14, x8, #5
	add	x11, x3, x14
	ldp	q6, q7, [x11]
	sub	x15, x8, #9
	lsl	x15, x15, #5
	add	x12, x3, x15
	ldp	q8, q9, [x12]
	eor	v8.16b, v8.16b, v6.16b
	eor	v9.16b, v9.16b, v7.16b
	stp	q8, q9, [x12]
	sub	x15, x8, #10
	lsl	x15, x15, #5
	add	x12, x3, x15
	ldp	q8, q9, [x12]
	eor	v8.16b, v8.16b, v6.16b
	eor	v9.16b, v9.16b, v7.16b
	stp	q8, q9, [x12]
	sub	x15, x8, #12
	lsl	x15, x15, #5
	add	x12, x3, x15
	ldp	q8, q9, [x12]
	eor	v8.16b, v8.16b, v6.16b
	eor	v9.16b, v9.16b, v7.16b
	stp	q8, q9, [x12]
	sub	x15, x8, #13
	lsl	x15, x15, #5
	add	x12, x3, x15
	ldp	q8, q9, [x12]
	eor	v8.16b, v8.16b, v6.16b
	eor	v9.16b, v9.16b, v7.16b
	stp	q8, q9, [x12]
	sub	x8, x8, #1
	b	L_mc_v256_rk_iv
L_mc_v256_copy_iv:
	mov	x8, #0
L_mc_v256_cp_iv:
	cmp	x8, #13
	bge	L_mc_v256_done_iv
	lsl	x14, x8, #5
	add	x11, x3, x14
	add	x12, x0, x14
	ldp	q6, q7, [x11]
	stp	q6, q7, [x12]
	add	x8, x8, #1
	b	L_mc_v256_cp_iv
L_mc_v256_done_iv:
	add	x4, x4, #1
	b	L_mc_inv_l
L_mc_inv_le:
	ldp	d8, d9, [x29, #16]
	ldp	d10, d11, [x29, #32]
	ldp	d12, d13, [x29, #48]
	ldp	d14, d15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
#ifndef __APPLE__
	.size	wc_mceliece_aff_inv256_neon,.-wc_mceliece_aff_inv256_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_aff_maa_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_aff_maa_neon)
.type	wc_mceliece_aff_maa_neon,@function
.align	2
wc_mceliece_aff_maa_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_aff_maa_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_aff_maa_neon)
.p2align	2
_wc_mceliece_aff_maa_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-48]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
	eor	v10.16b, v10.16b, v10.16b
	mov	x12, x4
	mov	x7, #0
L_mc_v256_z_maa:
	stp	q10, q10, [x12]
	add	x12, x12, #32
	add	x7, x7, #1
	cmp	x7, #25
	blt	L_mc_v256_z_maa
	mov	x5, #0
L_mc_v256_i_maa:
	cmp	x5, #13
	bge	L_mc_v256_rs_maa
	lsl	x13, x5, #5
	add	x8, x1, x13
	ldp	q0, q1, [x8]
	mov	x6, #0
L_mc_v256_j_maa:
	cmp	x6, #13
	bge	L_mc_v256_in_maa
	lsl	x13, x6, #5
	add	x9, x2, x13
	ldp	q2, q3, [x9]
	and	v4.16b, v0.16b, v2.16b
	and	v5.16b, v1.16b, v3.16b
	add	x13, x5, x6
	lsl	x13, x13, #5
	add	x10, x4, x13
	ldp	q6, q7, [x10]
	eor	v6.16b, v6.16b, v4.16b
	eor	v7.16b, v7.16b, v5.16b
	stp	q6, q7, [x10]
	add	x6, x6, #1
	b	L_mc_v256_j_maa
L_mc_v256_in_maa:
	add	x5, x5, #1
	b	L_mc_v256_i_maa
L_mc_v256_rs_maa:
	mov	x7, #24
L_mc_v256_rk_maa:
	cmp	x7, #13
	blt	L_mc_v256_copy_maa
	lsl	x13, x7, #5
	add	x10, x4, x13
	ldp	q6, q7, [x10]
	sub	x14, x7, #9
	lsl	x14, x14, #5
	add	x11, x4, x14
	ldp	q8, q9, [x11]
	eor	v8.16b, v8.16b, v6.16b
	eor	v9.16b, v9.16b, v7.16b
	stp	q8, q9, [x11]
	sub	x14, x7, #10
	lsl	x14, x14, #5
	add	x11, x4, x14
	ldp	q8, q9, [x11]
	eor	v8.16b, v8.16b, v6.16b
	eor	v9.16b, v9.16b, v7.16b
	stp	q8, q9, [x11]
	sub	x14, x7, #12
	lsl	x14, x14, #5
	add	x11, x4, x14
	ldp	q8, q9, [x11]
	eor	v8.16b, v8.16b, v6.16b
	eor	v9.16b, v9.16b, v7.16b
	stp	q8, q9, [x11]
	sub	x14, x7, #13
	lsl	x14, x14, #5
	add	x11, x4, x14
	ldp	q8, q9, [x11]
	eor	v8.16b, v8.16b, v6.16b
	eor	v9.16b, v9.16b, v7.16b
	stp	q8, q9, [x11]
	sub	x7, x7, #1
	b	L_mc_v256_rk_maa
L_mc_v256_copy_maa:
	mov	x7, #0
L_mc_v256_cp_maa:
	cmp	x7, #13
	bge	L_mc_v256_done_maa
	lsl	x13, x7, #5
	add	x10, x4, x13
	add	x11, x3, x13
	ldp	q6, q7, [x10]
	stp	q6, q7, [x11]
	add	x7, x7, #1
	b	L_mc_v256_cp_maa
L_mc_v256_done_maa:
	mov	x5, #0
L_mc_xor13_k_maaa:
	lsl	x6, x5, #5
	add	x8, x0, x6
	ldp	q0, q1, [x8]
	add	x9, x3, x6
	ldp	q2, q3, [x9]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x7, x0, x6
	stp	q0, q1, [x7]
	add	x5, x5, #1
	cmp	x5, #13
	blt	L_mc_xor13_k_maaa
	mov	x5, #0
L_mc_xor13_k_maab:
	lsl	x6, x5, #5
	add	x8, x1, x6
	ldp	q0, q1, [x8]
	add	x9, x0, x6
	ldp	q2, q3, [x9]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x7, x1, x6
	stp	q0, q1, [x7]
	add	x5, x5, #1
	cmp	x5, #13
	blt	L_mc_xor13_k_maab
	ldp	d8, d9, [x29, #16]
	ldp	d10, d11, [x29, #32]
	ldp	x29, x30, [sp], #48
	ret
#ifndef __APPLE__
	.size	wc_mceliece_aff_maa_neon,.-wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_aff_v256_xor13_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_aff_v256_xor13_neon)
.type	wc_mceliece_aff_v256_xor13_neon,@function
.align	2
wc_mceliece_aff_v256_xor13_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_aff_v256_xor13_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_aff_v256_xor13_neon)
.p2align	2
_wc_mceliece_aff_v256_xor13_neon:
#endif /* __APPLE__ */
	mov	x3, #0
L_mc_xor13_k:
	lsl	x4, x3, #5
	add	x6, x1, x4
	ldp	q0, q1, [x6]
	add	x7, x2, x4
	ldp	q2, q3, [x7]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x5, x0, x4
	stp	q0, q1, [x5]
	add	x3, x3, #1
	cmp	x3, #13
	blt	L_mc_xor13_k
	ret
#ifndef __APPLE__
	.size	wc_mceliece_aff_v256_xor13_neon,.-wc_mceliece_aff_v256_xor13_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_aff_pack_lh_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_aff_pack_lh_neon)
.type	wc_mceliece_aff_pack_lh_neon,@function
.align	2
wc_mceliece_aff_pack_lh_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_aff_pack_lh_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_aff_pack_lh_neon)
.p2align	2
_wc_mceliece_aff_pack_lh_neon:
#endif /* __APPLE__ */
	mov	x4, #0
L_mc_packlh_p:
	lsl	x5, x4, #5
	add	x8, x2, x5
	ldp	q0, q1, [x8]
	add	x9, x3, x5
	ldp	q2, q3, [x9]
	add	x6, x0, x5
	stp	q0, q2, [x6]
	add	x7, x1, x5
	stp	q1, q3, [x7]
	add	x4, x4, #1
	cmp	x4, #13
	blt	L_mc_packlh_p
	ret
#ifndef __APPLE__
	.size	wc_mceliece_aff_pack_lh_neon,.-wc_mceliece_aff_pack_lh_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_aff_radix_step_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_aff_radix_step_neon)
.type	wc_mceliece_aff_radix_step_neon,@function
.align	2
wc_mceliece_aff_radix_step_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_aff_radix_step_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_aff_radix_step_neon)
.p2align	2
_wc_mceliece_aff_radix_step_neon:
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x3, L_mc_aff_rmask0_neon
	add  x3, x3, :lo12:L_mc_aff_rmask0_neon
#else
	adrp x3, L_mc_aff_rmask0_neon@PAGE
	add  x3, x3, L_mc_aff_rmask0_neon@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x4, L_mc_aff_rmask1_neon
	add  x4, x4, :lo12:L_mc_aff_rmask1_neon
#else
	adrp x4, L_mc_aff_rmask1_neon@PAGE
	add  x4, x4, L_mc_aff_rmask1_neon@PAGEOFF
#endif /* __APPLE__ */
	mov	w2, w1
	eor	v6.16b, v6.16b, v6.16b
	mov	x14, #1
	mov	x8, #0
L_mc_rdx_t:
	cmp	x8, #13
	bge	L_mc_rdx_te
	lsl	x9, x8, #4
	add	x10, x0, x9
	ldr	q0, [x10]
	ushr	v5.2d, v0.2d, #32
	zip2	v5.2d, v6.2d, v5.2d
	eor	v0.16b, v0.16b, v5.16b
	shl	v5.2d, v0.2d, #32
	zip2	v5.2d, v5.2d, v6.2d
	eor	v0.16b, v0.16b, v5.16b
	str	q0, [x10]
	add	x8, x8, #1
	b	L_mc_rdx_t
L_mc_rdx_te:
	mov	x5, #4
L_mc_rdx_k:
	cmp	x5, x2
	blt	L_mc_rdx_ke
	lsl	x6, x14, x5
	neg	x7, x6
	dup	v4.2d, x7
	lsl	x9, x5, #3
	add	x11, x3, x9
	ldr	x12, [x11]
	dup	v2.2d, x12
	add	x11, x4, x9
	ldr	x13, [x11]
	dup	v3.2d, x13
	mov	x8, #0
L_mc_rdx_ki:
	cmp	x8, #13
	bge	L_mc_rdx_kie
	lsl	x9, x8, #4
	add	x10, x0, x9
	ldr	q0, [x10]
	and	v1.16b, v0.16b, v2.16b
	ushl	v1.2d, v1.2d, v4.2d
	eor	v0.16b, v0.16b, v1.16b
	and	v1.16b, v0.16b, v3.16b
	ushl	v1.2d, v1.2d, v4.2d
	eor	v0.16b, v0.16b, v1.16b
	str	q0, [x10]
	add	x8, x8, #1
	b	L_mc_rdx_ki
L_mc_rdx_kie:
	sub	x5, x5, #1
	b	L_mc_rdx_k
L_mc_rdx_ke:
	ret
#ifndef __APPLE__
	.size	wc_mceliece_aff_radix_step_neon,.-wc_mceliece_aff_radix_step_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_aff_fwd_out_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_aff_fwd_out_neon)
.type	wc_mceliece_aff_fwd_out_neon,@function
.align	2
wc_mceliece_aff_fwd_out_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_aff_fwd_out_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_aff_fwd_out_neon)
.p2align	2
_wc_mceliece_aff_fwd_out_neon:
#endif /* __APPLE__ */
	mov	w4, w3
	mov	x14, #13
	mov	x5, #0
L_mc_fwo_j:
	cmp	x5, #32
	bge	L_mc_fwo_e
	lsl	x8, x5, #1
	add	x9, x2, x8
	ldrb	w6, [x9]
	add	x9, x9, #1
	ldrb	w7, [x9]
	lsl	x8, x6, #5
	add	x10, x1, x8
	ldp	q0, q1, [x10]
	lsl	x8, x7, #5
	add	x11, x1, x8
	ldp	q2, q3, [x11]
	madd	x8, x5, x14, x4
	lsl	x8, x8, #5
	add	x12, x0, x8
	stp	q0, q2, [x12]
	cmp	x4, #12
	beq	L_mc_fwo_no
	add	x13, x12, #32
	stp	q1, q3, [x13]
L_mc_fwo_no:
	add	x5, x5, #1
	b	L_mc_fwo_j
L_mc_fwo_e:
	ret
#ifndef __APPLE__
	.size	wc_mceliece_aff_fwd_out_neon,.-wc_mceliece_aff_fwd_out_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_fft_fwd_butterflies_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_fft_fwd_butterflies_neon)
.type	wc_mceliece_fft_fwd_butterflies_neon,@function
.align	2
wc_mceliece_fft_fwd_butterflies_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_fft_fwd_butterflies_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_fft_fwd_butterflies_neon)
.p2align	2
_wc_mceliece_fft_fwd_butterflies_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	x19, x20, [x29, #16]
	stp	x21, x22, [x29, #32]
	stp	x23, x24, [x29, #48]
	stp	x25, x26, [x29, #64]
#ifndef __APPLE__
	adrp x4, L_mc_aff_consts_neon
	add  x4, x4, :lo12:L_mc_aff_consts_neon
#else
	adrp x4, L_mc_aff_consts_neon@PAGE
	add  x4, x4, L_mc_aff_consts_neon@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x5, L_mc_aff_powers_neon
	add  x5, x5, :lo12:L_mc_aff_powers_neon
#else
	adrp x5, L_mc_aff_powers_neon@PAGE
	add  x5, x5, L_mc_aff_powers_neon@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x6, L_mc_aff_reversal_neon
	add  x6, x6, :lo12:L_mc_aff_reversal_neon
#else
	adrp x6, L_mc_aff_reversal_neon@PAGE
	add  x6, x6, L_mc_aff_reversal_neon@PAGEOFF
#endif /* __APPLE__ */
	mov	x19, x0
	mov	x20, x1
	mov	w21, w2
	mov	x22, x3
	mov	x23, x4
	mov	x24, x5
	mov	x25, x6
	add	x12, x22, #0x1a0
	mov	x8, #0
	mov	x7, #0
L_mc_ffb_pz:
	cmp	x7, #0xe0
	bge	L_mc_ffb_pze
	lsl	x10, x7, #3
	add	x9, x12, x10
	str	x8, [x9]
	add	x7, x7, #1
	b	L_mc_ffb_pz
L_mc_ffb_pze:
	add	x7, x20, #0
	ldr	x8, [x7, #8]
	add	x7, x22, #0xd0
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x20, #16
	ldr	x8, [x7, #8]
	add	x7, x22, #0xe0
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x20, #32
	ldr	x8, [x7, #8]
	add	x7, x22, #0xf0
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x20, #48
	ldr	x8, [x7, #8]
	add	x7, x22, #0x100
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x20, #0x40
	ldr	x8, [x7, #8]
	add	x7, x22, #0x110
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x20, #0x50
	ldr	x8, [x7, #8]
	add	x7, x22, #0x120
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x20, #0x60
	ldr	x8, [x7, #8]
	add	x7, x22, #0x130
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x20, #0x70
	ldr	x8, [x7, #8]
	add	x7, x22, #0x140
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x20, #0x80
	ldr	x8, [x7, #8]
	add	x7, x22, #0x150
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x20, #0x90
	ldr	x8, [x7, #8]
	add	x7, x22, #0x160
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x20, #0xa0
	ldr	x8, [x7, #8]
	add	x7, x22, #0x170
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x20, #0xb0
	ldr	x8, [x7, #8]
	add	x7, x22, #0x180
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x20, #0xc0
	ldr	x8, [x7, #8]
	add	x7, x22, #0x190
	str	x8, [x7]
	str	x8, [x7, #8]
	mov	x16, #0
	sub	x16, x16, #1
	mov	x9, #0
	add	x7, x22, #0
	str	x9, [x7]
	str	x16, [x7, #8]
	add	x7, x22, #16
	str	x16, [x7]
	str	x16, [x7, #8]
	add	x7, x22, #32
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #48
	str	x16, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0x40
	str	x16, [x7]
	str	x16, [x7, #8]
	add	x7, x22, #0x50
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0x60
	str	x16, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0x70
	str	x16, [x7]
	str	x16, [x7, #8]
	add	x7, x22, #0x80
	str	x16, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0x90
	str	x9, [x7]
	str	x16, [x7, #8]
	add	x7, x22, #0xa0
	str	x9, [x7]
	str	x16, [x7, #8]
	add	x7, x22, #0xb0
	str	x16, [x7]
	str	x16, [x7, #8]
	add	x7, x22, #0xc0
	str	x9, [x7]
	str	x16, [x7, #8]
	mov	x0, x22
	add	x1, x22, #0xd0
	mov	x2, x22
	add	x3, x22, #0x8a0
#ifndef __APPLE__
	bl	wc_mceliece_aff_v128_mul_neon
#else
	bl	_wc_mceliece_aff_v128_mul_neon
#endif /* __APPLE__ */
	add	x7, x22, #0
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x1a0
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x280
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #16
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x1b0
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x290
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #32
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x1c0
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x2a0
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #48
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x1d0
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x2b0
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0x40
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x1e0
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x2c0
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0x50
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x1f0
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x2d0
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0x60
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x200
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x2e0
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0x70
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x210
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x2f0
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0x80
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x220
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x300
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0x90
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x230
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x310
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0xa0
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x240
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x320
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0xb0
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x250
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x330
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0xc0
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x260
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x340
	str	x9, [x7]
	str	x9, [x7, #8]
	mov	x16, #0
	sub	x16, x16, #1
	mov	x9, #0
	add	x7, x22, #0
	str	x16, [x7]
	str	x16, [x7, #8]
	add	x7, x22, #16
	str	x9, [x7]
	str	x16, [x7, #8]
	add	x7, x22, #32
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #48
	str	x16, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0x40
	str	x16, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0x50
	str	x16, [x7]
	str	x16, [x7, #8]
	add	x7, x22, #0x60
	str	x16, [x7]
	str	x16, [x7, #8]
	add	x7, x22, #0x70
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0x80
	str	x9, [x7]
	str	x16, [x7, #8]
	add	x7, x22, #0x90
	str	x16, [x7]
	str	x16, [x7, #8]
	add	x7, x22, #0xa0
	str	x16, [x7]
	str	x16, [x7, #8]
	add	x7, x22, #0xb0
	str	x16, [x7]
	str	x16, [x7, #8]
	add	x7, x22, #0xc0
	str	x16, [x7]
	str	x16, [x7, #8]
	mov	x0, x22
	add	x1, x22, #0xd0
	mov	x2, x22
	add	x3, x22, #0x8a0
#ifndef __APPLE__
	bl	wc_mceliece_aff_v128_mul_neon
#else
	bl	_wc_mceliece_aff_v128_mul_neon
#endif /* __APPLE__ */
	add	x7, x22, #0
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x360
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x440
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #16
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x370
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x450
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #32
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x380
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x460
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #48
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x390
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x470
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0x40
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x3a0
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x480
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0x50
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x3b0
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x490
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0x60
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x3c0
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x4a0
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0x70
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x3d0
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x4b0
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0x80
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x3e0
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x4c0
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0x90
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x3f0
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x4d0
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0xa0
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x400
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x4e0
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0xb0
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x410
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x4f0
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0xc0
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x420
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x500
	str	x9, [x7]
	str	x9, [x7, #8]
	mov	x16, #0
	sub	x16, x16, #1
	mov	x9, #0
	add	x7, x22, #0
	str	x16, [x7]
	str	x16, [x7, #8]
	add	x7, x22, #16
	str	x9, [x7]
	str	x16, [x7, #8]
	add	x7, x22, #32
	str	x9, [x7]
	str	x16, [x7, #8]
	add	x7, x22, #48
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0x40
	str	x16, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0x50
	str	x16, [x7]
	str	x16, [x7, #8]
	add	x7, x22, #0x60
	str	x16, [x7]
	str	x16, [x7, #8]
	add	x7, x22, #0x70
	str	x16, [x7]
	str	x16, [x7, #8]
	add	x7, x22, #0x80
	str	x9, [x7]
	str	x16, [x7, #8]
	add	x7, x22, #0x90
	str	x16, [x7]
	str	x16, [x7, #8]
	add	x7, x22, #0xa0
	str	x9, [x7]
	str	x16, [x7, #8]
	add	x7, x22, #0xb0
	str	x16, [x7]
	str	x16, [x7, #8]
	add	x7, x22, #0xc0
	str	x16, [x7]
	str	x16, [x7, #8]
	mov	x0, x22
	add	x1, x22, #0xd0
	mov	x2, x22
	add	x3, x22, #0x8a0
#ifndef __APPLE__
	bl	wc_mceliece_aff_v128_mul_neon
#else
	bl	_wc_mceliece_aff_v128_mul_neon
#endif /* __APPLE__ */
	add	x7, x22, #0
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x520
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x600
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #16
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x530
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x610
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #32
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x540
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x620
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #48
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x550
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x630
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0x40
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x560
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x640
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0x50
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x570
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x650
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0x60
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x580
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x660
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0x70
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x590
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x670
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0x80
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x5a0
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x680
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0x90
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x5b0
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x690
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0xa0
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x5c0
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x6a0
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0xb0
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x5d0
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x6b0
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0xc0
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x5e0
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x6c0
	str	x9, [x7]
	str	x9, [x7, #8]
	mov	x16, #0
	sub	x16, x16, #1
	mov	x9, #0
	add	x7, x22, #0
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #16
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #32
	str	x16, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #48
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0x40
	str	x16, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0x50
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0x60
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0x70
	str	x16, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0x80
	str	x16, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0x90
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0xa0
	str	x16, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0xb0
	str	x16, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0xc0
	str	x9, [x7]
	str	x9, [x7, #8]
	mov	x0, x22
	add	x1, x22, #0xd0
	mov	x2, x22
	add	x3, x22, #0x8a0
#ifndef __APPLE__
	bl	wc_mceliece_aff_v128_mul_neon
#else
	bl	_wc_mceliece_aff_v128_mul_neon
#endif /* __APPLE__ */
	add	x7, x22, #0
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x6e0
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x7c0
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #16
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x6f0
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x7d0
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #32
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x700
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x7e0
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #48
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x710
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x7f0
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0x40
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x720
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x800
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0x50
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x730
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x810
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0x60
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x740
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x820
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0x70
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x750
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x830
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0x80
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x760
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x840
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0x90
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x770
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x850
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0xa0
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x780
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x860
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0xb0
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x790
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x870
	str	x9, [x7]
	str	x9, [x7, #8]
	add	x7, x22, #0xc0
	ldr	x8, [x7]
	ldr	x9, [x7, #8]
	add	x7, x22, #0x7a0
	str	x8, [x7]
	str	x8, [x7, #8]
	add	x7, x22, #0x880
	str	x9, [x7]
	str	x9, [x7, #8]
	mov	x26, #0
L_mc_ffb_i:
	cmp	x26, #13
	bge	L_mc_ffb_ie
	lsl	x10, x26, #4
	add	x11, x20, x10
	add	x13, x22, #0x8a0
	ldr	x7, [x11]
	str	x7, [x13]
	add	x12, x22, #0x6e0
	add	x12, x12, x10
	ldr	x8, [x12]
	eor	x9, x7, x8
	str	x9, [x13, #8]
	cmp	x26, #12
	beq	L_mc_ffb_hi
	ldr	x7, [x11, #16]
	str	x7, [x13, #16]
	ldr	x8, [x12, #16]
	eor	x9, x7, x8
	str	x9, [x13, #24]
L_mc_ffb_hi:
	lsr	x15, x26, #1
	lsl	x10, x15, #5
	add	x14, x22, x10
	add	x14, x14, #0x1a0
	add	x7, x13, #0
	ldp	q0, q1, [x7]
	add	x8, x14, #0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #32
	stp	q0, q1, [x9]
	add	x7, x13, #0
	ldp	q0, q1, [x7]
	add	x8, x14, #0x380
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x200
	stp	q0, q1, [x9]
	add	x7, x13, #32
	ldp	q0, q1, [x7]
	add	x8, x14, #0xe0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x60
	stp	q0, q1, [x9]
	add	x7, x13, #0x200
	ldp	q0, q1, [x7]
	add	x8, x14, #0x460
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x600
	stp	q0, q1, [x9]
	add	x7, x13, #0x600
	ldp	q0, q1, [x7]
	add	x8, x14, #0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x620
	stp	q0, q1, [x9]
	add	x7, x13, #0
	ldp	q0, q1, [x7]
	add	x8, x14, #0xe0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x40
	stp	q0, q1, [x9]
	add	x7, x13, #0x620
	ldp	q0, q1, [x7]
	add	x8, x14, #0xe0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x660
	stp	q0, q1, [x9]
	add	x7, x13, #0x40
	ldp	q0, q1, [x7]
	add	x8, x14, #0x1c0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0xc0
	stp	q0, q1, [x9]
	add	x7, x13, #0x660
	ldp	q0, q1, [x7]
	add	x8, x14, #0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x640
	stp	q0, q1, [x9]
	add	x7, x13, #0xc0
	ldp	q0, q1, [x7]
	add	x8, x14, #0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0xe0
	stp	q0, q1, [x9]
	add	x7, x13, #0x640
	ldp	q0, q1, [x7]
	add	x8, x14, #0x1c0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x6c0
	stp	q0, q1, [x9]
	add	x7, x13, #0xe0
	ldp	q0, q1, [x7]
	add	x8, x14, #0xe0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0xa0
	stp	q0, q1, [x9]
	add	x7, x13, #0x6c0
	ldp	q0, q1, [x7]
	add	x8, x14, #0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x6e0
	stp	q0, q1, [x9]
	add	x7, x13, #0x6e0
	ldp	q0, q1, [x7]
	add	x8, x14, #0xe0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x6a0
	stp	q0, q1, [x9]
	add	x7, x13, #0
	ldp	q0, q1, [x7]
	add	x8, x14, #0x1c0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x80
	stp	q0, q1, [x9]
	add	x7, x13, #0x6a0
	ldp	q0, q1, [x7]
	add	x8, x14, #0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x680
	stp	q0, q1, [x9]
	add	x7, x13, #0x80
	ldp	q0, q1, [x7]
	add	x8, x14, #0x2a0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x180
	stp	q0, q1, [x9]
	add	x7, x13, #0x680
	ldp	q0, q1, [x7]
	add	x8, x14, #0x2a0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x780
	stp	q0, q1, [x9]
	add	x7, x13, #0x180
	ldp	q0, q1, [x7]
	add	x8, x14, #0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x1a0
	stp	q0, q1, [x9]
	add	x7, x13, #0x780
	ldp	q0, q1, [x7]
	add	x8, x14, #0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x7a0
	stp	q0, q1, [x9]
	add	x7, x13, #0x1a0
	ldp	q0, q1, [x7]
	add	x8, x14, #0xe0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x1e0
	stp	q0, q1, [x9]
	add	x7, x13, #0x7a0
	ldp	q0, q1, [x7]
	add	x8, x14, #0xe0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x7e0
	stp	q0, q1, [x9]
	add	x7, x13, #0x1e0
	ldp	q0, q1, [x7]
	add	x8, x14, #0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x1c0
	stp	q0, q1, [x9]
	add	x7, x13, #0x7e0
	ldp	q0, q1, [x7]
	add	x8, x14, #0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x7c0
	stp	q0, q1, [x9]
	add	x7, x13, #0x1c0
	ldp	q0, q1, [x7]
	add	x8, x14, #0x1c0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x140
	stp	q0, q1, [x9]
	add	x7, x13, #0x7c0
	ldp	q0, q1, [x7]
	add	x8, x14, #0x1c0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x740
	stp	q0, q1, [x9]
	add	x7, x13, #0x140
	ldp	q0, q1, [x7]
	add	x8, x14, #0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x160
	stp	q0, q1, [x9]
	add	x7, x13, #0x740
	ldp	q0, q1, [x7]
	add	x8, x14, #0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x760
	stp	q0, q1, [x9]
	add	x7, x13, #0x160
	ldp	q0, q1, [x7]
	add	x8, x14, #0xe0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x120
	stp	q0, q1, [x9]
	add	x7, x13, #0x760
	ldp	q0, q1, [x7]
	add	x8, x14, #0xe0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x720
	stp	q0, q1, [x9]
	add	x7, x13, #0x720
	ldp	q0, q1, [x7]
	add	x8, x14, #0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x700
	stp	q0, q1, [x9]
	add	x7, x13, #0
	ldp	q0, q1, [x7]
	add	x8, x14, #0x2a0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x100
	stp	q0, q1, [x9]
	add	x7, x13, #0x700
	ldp	q0, q1, [x7]
	add	x8, x14, #0x380
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x500
	stp	q0, q1, [x9]
	add	x7, x13, #0x100
	ldp	q0, q1, [x7]
	add	x8, x14, #0x380
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x300
	stp	q0, q1, [x9]
	add	x7, x13, #0x500
	ldp	q0, q1, [x7]
	add	x8, x14, #0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x520
	stp	q0, q1, [x9]
	add	x7, x13, #0x300
	ldp	q0, q1, [x7]
	add	x8, x14, #0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x320
	stp	q0, q1, [x9]
	add	x7, x13, #0x520
	ldp	q0, q1, [x7]
	add	x8, x14, #0xe0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x560
	stp	q0, q1, [x9]
	add	x7, x13, #0x320
	ldp	q0, q1, [x7]
	add	x8, x14, #0xe0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x360
	stp	q0, q1, [x9]
	add	x7, x13, #0x560
	ldp	q0, q1, [x7]
	add	x8, x14, #0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x540
	stp	q0, q1, [x9]
	add	x7, x13, #0x360
	ldp	q0, q1, [x7]
	add	x8, x14, #0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x340
	stp	q0, q1, [x9]
	add	x7, x13, #0x540
	ldp	q0, q1, [x7]
	add	x8, x14, #0x1c0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x5c0
	stp	q0, q1, [x9]
	add	x7, x13, #0x340
	ldp	q0, q1, [x7]
	add	x8, x14, #0x1c0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x3c0
	stp	q0, q1, [x9]
	add	x7, x13, #0x5c0
	ldp	q0, q1, [x7]
	add	x8, x14, #0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x5e0
	stp	q0, q1, [x9]
	add	x7, x13, #0x3c0
	ldp	q0, q1, [x7]
	add	x8, x14, #0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x3e0
	stp	q0, q1, [x9]
	add	x7, x13, #0x5e0
	ldp	q0, q1, [x7]
	add	x8, x14, #0xe0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x5a0
	stp	q0, q1, [x9]
	add	x7, x13, #0x3e0
	ldp	q0, q1, [x7]
	add	x8, x14, #0xe0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x3a0
	stp	q0, q1, [x9]
	add	x7, x13, #0x5a0
	ldp	q0, q1, [x7]
	add	x8, x14, #0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x580
	stp	q0, q1, [x9]
	add	x7, x13, #0x3a0
	ldp	q0, q1, [x7]
	add	x8, x14, #0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x380
	stp	q0, q1, [x9]
	add	x7, x13, #0x580
	ldp	q0, q1, [x7]
	add	x8, x14, #0x2a0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x480
	stp	q0, q1, [x9]
	add	x7, x13, #0x380
	ldp	q0, q1, [x7]
	add	x8, x14, #0x2a0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x280
	stp	q0, q1, [x9]
	add	x7, x13, #0x480
	ldp	q0, q1, [x7]
	add	x8, x14, #0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x4a0
	stp	q0, q1, [x9]
	add	x7, x13, #0x280
	ldp	q0, q1, [x7]
	add	x8, x14, #0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x2a0
	stp	q0, q1, [x9]
	add	x7, x13, #0x4a0
	ldp	q0, q1, [x7]
	add	x8, x14, #0xe0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x4e0
	stp	q0, q1, [x9]
	add	x7, x13, #0x2a0
	ldp	q0, q1, [x7]
	add	x8, x14, #0xe0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x2e0
	stp	q0, q1, [x9]
	add	x7, x13, #0x4e0
	ldp	q0, q1, [x7]
	add	x8, x14, #0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x4c0
	stp	q0, q1, [x9]
	add	x7, x13, #0x2e0
	ldp	q0, q1, [x7]
	add	x8, x14, #0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x2c0
	stp	q0, q1, [x9]
	add	x7, x13, #0x4c0
	ldp	q0, q1, [x7]
	add	x8, x14, #0x1c0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x440
	stp	q0, q1, [x9]
	add	x7, x13, #0x2c0
	ldp	q0, q1, [x7]
	add	x8, x14, #0x1c0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x240
	stp	q0, q1, [x9]
	add	x7, x13, #0x440
	ldp	q0, q1, [x7]
	add	x8, x14, #0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x460
	stp	q0, q1, [x9]
	add	x7, x13, #0x240
	ldp	q0, q1, [x7]
	add	x8, x14, #0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x260
	stp	q0, q1, [x9]
	add	x7, x13, #0x460
	ldp	q0, q1, [x7]
	add	x8, x14, #0xe0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x420
	stp	q0, q1, [x9]
	add	x7, x13, #0x260
	ldp	q0, q1, [x7]
	add	x8, x14, #0xe0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x220
	stp	q0, q1, [x9]
	add	x7, x13, #0x420
	ldp	q0, q1, [x7]
	add	x8, x14, #0
	ldp	q2, q3, [x8]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x9, x13, #0x400
	stp	q0, q1, [x9]
	add	x0, x22, #0x8a0
#ifndef __APPLE__
	bl	wc_mceliece_aff_transpose_neon
#else
	bl	_wc_mceliece_aff_transpose_neon
#endif /* __APPLE__ */
	mov	x0, x19
	add	x1, x22, #0x8a0
	mov	x2, x25
	mov	w3, w26
#ifndef __APPLE__
	bl	wc_mceliece_aff_fwd_out_neon
#else
	bl	_wc_mceliece_aff_fwd_out_neon
#endif /* __APPLE__ */
	add	x26, x26, #2
	b	L_mc_ffb_i
L_mc_ffb_ie:
	mov	x26, #0
L_mc_ffb_pk:
	cmp	x26, #32
	bge	L_mc_ffb_pke
	mov	x7, #0x1a0
	mul	x10, x26, x7
	add	x0, x22, #0x8a0
	add	x1, x22, #0xa40
	add	x2, x19, x10
	add	x3, x2, #0x1a0
#ifndef __APPLE__
	bl	wc_mceliece_aff_pack_lh_neon
#else
	bl	_wc_mceliece_aff_pack_lh_neon
#endif /* __APPLE__ */
	add	x0, x22, #0x8a0
	add	x1, x22, #0xa40
	add	x2, x23, #0x1a0
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x1a0
	mul	x10, x26, x7
	add	x0, x19, x10
	add	x1, x0, #0x1a0
	add	x2, x22, #0x8a0
	add	x3, x22, #0xa40
#ifndef __APPLE__
	bl	wc_mceliece_aff_pack_lh_neon
#else
	bl	_wc_mceliece_aff_pack_lh_neon
#endif /* __APPLE__ */
	add	x26, x26, #2
	b	L_mc_ffb_pk
L_mc_ffb_pke:
	mov	x7, #0
	add	x0, x19, x7
	mov	x7, #0x1a0
	add	x1, x19, x7
	mov	x7, #0x340
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x340
	add	x0, x19, x7
	mov	x7, #0x4e0
	add	x1, x19, x7
	mov	x7, #0x340
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x680
	add	x0, x19, x7
	mov	x7, #0x820
	add	x1, x19, x7
	mov	x7, #0x340
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x9c0
	add	x0, x19, x7
	mov	x7, #0xb60
	add	x1, x19, x7
	mov	x7, #0x340
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0xd00
	add	x0, x19, x7
	mov	x7, #0xea0
	add	x1, x19, x7
	mov	x7, #0x340
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x1040
	add	x0, x19, x7
	mov	x7, #0x11e0
	add	x1, x19, x7
	mov	x7, #0x340
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x1380
	add	x0, x19, x7
	mov	x7, #0x1520
	add	x1, x19, x7
	mov	x7, #0x340
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x16c0
	add	x0, x19, x7
	mov	x7, #0x1860
	add	x1, x19, x7
	mov	x7, #0x340
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x1a00
	add	x0, x19, x7
	mov	x7, #0x1ba0
	add	x1, x19, x7
	mov	x7, #0x340
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x1d40
	add	x0, x19, x7
	mov	x7, #0x1ee0
	add	x1, x19, x7
	mov	x7, #0x340
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x2080
	add	x0, x19, x7
	mov	x7, #0x2220
	add	x1, x19, x7
	mov	x7, #0x340
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x23c0
	add	x0, x19, x7
	mov	x7, #0x2560
	add	x1, x19, x7
	mov	x7, #0x340
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x2700
	add	x0, x19, x7
	mov	x7, #0x28a0
	add	x1, x19, x7
	mov	x7, #0x340
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x2a40
	add	x0, x19, x7
	mov	x7, #0x2be0
	add	x1, x19, x7
	mov	x7, #0x340
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x2d80
	add	x0, x19, x7
	mov	x7, #0x2f20
	add	x1, x19, x7
	mov	x7, #0x340
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x30c0
	add	x0, x19, x7
	mov	x7, #0x3260
	add	x1, x19, x7
	mov	x7, #0x340
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0
	add	x0, x19, x7
	mov	x7, #0x340
	add	x1, x19, x7
	mov	x7, #0x4e0
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x1a0
	add	x0, x19, x7
	mov	x7, #0x4e0
	add	x1, x19, x7
	mov	x7, #0x680
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x680
	add	x0, x19, x7
	mov	x7, #0x9c0
	add	x1, x19, x7
	mov	x7, #0x4e0
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x820
	add	x0, x19, x7
	mov	x7, #0xb60
	add	x1, x19, x7
	mov	x7, #0x680
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0xd00
	add	x0, x19, x7
	mov	x7, #0x1040
	add	x1, x19, x7
	mov	x7, #0x4e0
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0xea0
	add	x0, x19, x7
	mov	x7, #0x11e0
	add	x1, x19, x7
	mov	x7, #0x680
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x1380
	add	x0, x19, x7
	mov	x7, #0x16c0
	add	x1, x19, x7
	mov	x7, #0x4e0
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x1520
	add	x0, x19, x7
	mov	x7, #0x1860
	add	x1, x19, x7
	mov	x7, #0x680
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x1a00
	add	x0, x19, x7
	mov	x7, #0x1d40
	add	x1, x19, x7
	mov	x7, #0x4e0
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x1ba0
	add	x0, x19, x7
	mov	x7, #0x1ee0
	add	x1, x19, x7
	mov	x7, #0x680
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x2080
	add	x0, x19, x7
	mov	x7, #0x23c0
	add	x1, x19, x7
	mov	x7, #0x4e0
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x2220
	add	x0, x19, x7
	mov	x7, #0x2560
	add	x1, x19, x7
	mov	x7, #0x680
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x2700
	add	x0, x19, x7
	mov	x7, #0x2a40
	add	x1, x19, x7
	mov	x7, #0x4e0
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x28a0
	add	x0, x19, x7
	mov	x7, #0x2be0
	add	x1, x19, x7
	mov	x7, #0x680
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x2d80
	add	x0, x19, x7
	mov	x7, #0x30c0
	add	x1, x19, x7
	mov	x7, #0x4e0
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x2f20
	add	x0, x19, x7
	mov	x7, #0x3260
	add	x1, x19, x7
	mov	x7, #0x680
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0
	add	x0, x19, x7
	mov	x7, #0x680
	add	x1, x19, x7
	mov	x7, #0x820
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x1a0
	add	x0, x19, x7
	mov	x7, #0x820
	add	x1, x19, x7
	mov	x7, #0x9c0
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x340
	add	x0, x19, x7
	mov	x7, #0x9c0
	add	x1, x19, x7
	mov	x7, #0xb60
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x4e0
	add	x0, x19, x7
	mov	x7, #0xb60
	add	x1, x19, x7
	mov	x7, #0xd00
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0xd00
	add	x0, x19, x7
	mov	x7, #0x1380
	add	x1, x19, x7
	mov	x7, #0x820
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0xea0
	add	x0, x19, x7
	mov	x7, #0x1520
	add	x1, x19, x7
	mov	x7, #0x9c0
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x1040
	add	x0, x19, x7
	mov	x7, #0x16c0
	add	x1, x19, x7
	mov	x7, #0xb60
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x11e0
	add	x0, x19, x7
	mov	x7, #0x1860
	add	x1, x19, x7
	mov	x7, #0xd00
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x1a00
	add	x0, x19, x7
	mov	x7, #0x2080
	add	x1, x19, x7
	mov	x7, #0x820
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x1ba0
	add	x0, x19, x7
	mov	x7, #0x2220
	add	x1, x19, x7
	mov	x7, #0x9c0
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x1d40
	add	x0, x19, x7
	mov	x7, #0x23c0
	add	x1, x19, x7
	mov	x7, #0xb60
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x1ee0
	add	x0, x19, x7
	mov	x7, #0x2560
	add	x1, x19, x7
	mov	x7, #0xd00
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x2700
	add	x0, x19, x7
	mov	x7, #0x2d80
	add	x1, x19, x7
	mov	x7, #0x820
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x28a0
	add	x0, x19, x7
	mov	x7, #0x2f20
	add	x1, x19, x7
	mov	x7, #0x9c0
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x2a40
	add	x0, x19, x7
	mov	x7, #0x30c0
	add	x1, x19, x7
	mov	x7, #0xb60
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x2be0
	add	x0, x19, x7
	mov	x7, #0x3260
	add	x1, x19, x7
	mov	x7, #0xd00
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0
	add	x0, x19, x7
	mov	x7, #0xd00
	add	x1, x19, x7
	mov	x7, #0xea0
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x1a0
	add	x0, x19, x7
	mov	x7, #0xea0
	add	x1, x19, x7
	mov	x7, #0x1040
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x340
	add	x0, x19, x7
	mov	x7, #0x1040
	add	x1, x19, x7
	mov	x7, #0x11e0
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x4e0
	add	x0, x19, x7
	mov	x7, #0x11e0
	add	x1, x19, x7
	mov	x7, #0x1380
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x680
	add	x0, x19, x7
	mov	x7, #0x1380
	add	x1, x19, x7
	mov	x7, #0x1520
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x820
	add	x0, x19, x7
	mov	x7, #0x1520
	add	x1, x19, x7
	mov	x7, #0x16c0
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x9c0
	add	x0, x19, x7
	mov	x7, #0x16c0
	add	x1, x19, x7
	mov	x7, #0x1860
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0xb60
	add	x0, x19, x7
	mov	x7, #0x1860
	add	x1, x19, x7
	mov	x7, #0x1a00
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x1a00
	add	x0, x19, x7
	mov	x7, #0x2700
	add	x1, x19, x7
	mov	x7, #0xea0
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x1ba0
	add	x0, x19, x7
	mov	x7, #0x28a0
	add	x1, x19, x7
	mov	x7, #0x1040
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x1d40
	add	x0, x19, x7
	mov	x7, #0x2a40
	add	x1, x19, x7
	mov	x7, #0x11e0
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x1ee0
	add	x0, x19, x7
	mov	x7, #0x2be0
	add	x1, x19, x7
	mov	x7, #0x1380
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x2080
	add	x0, x19, x7
	mov	x7, #0x2d80
	add	x1, x19, x7
	mov	x7, #0x1520
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x2220
	add	x0, x19, x7
	mov	x7, #0x2f20
	add	x1, x19, x7
	mov	x7, #0x16c0
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x23c0
	add	x0, x19, x7
	mov	x7, #0x30c0
	add	x1, x19, x7
	mov	x7, #0x1860
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x2560
	add	x0, x19, x7
	mov	x7, #0x3260
	add	x1, x19, x7
	mov	x7, #0x1a00
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0
	add	x0, x19, x7
	mov	x7, #0x1a00
	add	x1, x19, x7
	mov	x7, #0x1ba0
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x1a0
	add	x0, x19, x7
	mov	x7, #0x1ba0
	add	x1, x19, x7
	mov	x7, #0x1d40
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x340
	add	x0, x19, x7
	mov	x7, #0x1d40
	add	x1, x19, x7
	mov	x7, #0x1ee0
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x4e0
	add	x0, x19, x7
	mov	x7, #0x1ee0
	add	x1, x19, x7
	mov	x7, #0x2080
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x680
	add	x0, x19, x7
	mov	x7, #0x2080
	add	x1, x19, x7
	mov	x7, #0x2220
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x820
	add	x0, x19, x7
	mov	x7, #0x2220
	add	x1, x19, x7
	mov	x7, #0x23c0
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x9c0
	add	x0, x19, x7
	mov	x7, #0x23c0
	add	x1, x19, x7
	mov	x7, #0x2560
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0xb60
	add	x0, x19, x7
	mov	x7, #0x2560
	add	x1, x19, x7
	mov	x7, #0x2700
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0xd00
	add	x0, x19, x7
	mov	x7, #0x2700
	add	x1, x19, x7
	mov	x7, #0x28a0
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0xea0
	add	x0, x19, x7
	mov	x7, #0x28a0
	add	x1, x19, x7
	mov	x7, #0x2a40
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x1040
	add	x0, x19, x7
	mov	x7, #0x2a40
	add	x1, x19, x7
	mov	x7, #0x2be0
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x11e0
	add	x0, x19, x7
	mov	x7, #0x2be0
	add	x1, x19, x7
	mov	x7, #0x2d80
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x1380
	add	x0, x19, x7
	mov	x7, #0x2d80
	add	x1, x19, x7
	mov	x7, #0x2f20
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x1520
	add	x0, x19, x7
	mov	x7, #0x2f20
	add	x1, x19, x7
	mov	x7, #0x30c0
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x16c0
	add	x0, x19, x7
	mov	x7, #0x30c0
	add	x1, x19, x7
	mov	x7, #0x3260
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	mov	x7, #0x1860
	add	x0, x19, x7
	mov	x7, #0x3260
	add	x1, x19, x7
	mov	x7, #0x3400
	add	x2, x23, x7
	add	x3, x22, #0xbe0
	add	x4, x22, #0xd80
#ifndef __APPLE__
	bl	wc_mceliece_aff_maa_neon
#else
	bl	_wc_mceliece_aff_maa_neon
#endif /* __APPLE__ */
	cbz	w21, L_mc_ffb_nm
	mov	x7, #0
L_mc_ffb_mo:
	cmp	x7, #0x1a0
	bge	L_mc_ffb_moe
	lsl	x10, x7, #5
	add	x8, x19, x10
	ldp	q0, q1, [x8]
	add	x9, x24, x10
	ldp	q2, q3, [x9]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x8]
	add	x7, x7, #1
	b	L_mc_ffb_mo
L_mc_ffb_moe:
L_mc_ffb_nm:
	ldp	x19, x20, [x29, #16]
	ldp	x21, x22, [x29, #32]
	ldp	x23, x24, [x29, #48]
	ldp	x25, x26, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
#ifndef __APPLE__
	.size	wc_mceliece_fft_fwd_butterflies_neon,.-wc_mceliece_fft_fwd_butterflies_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_bs_poly_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_bs_poly_neon)
.type	wc_mceliece_bs_poly_neon,@function
.align	2
wc_mceliece_bs_poly_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_bs_poly_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_bs_poly_neon)
.p2align	2
_wc_mceliece_bs_poly_neon:
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x2, L_mc_bs_powers_neon
	add  x2, x2, :lo12:L_mc_bs_powers_neon
#else
	adrp x2, L_mc_bs_powers_neon@PAGE
	add  x2, x2, L_mc_bs_powers_neon@PAGEOFF
#endif /* __APPLE__ */
	ldr	q0, [x2]
	movi	v1.8h, #1
	mov	x3, #0
L_mc_bsp:
	cmp	x3, #8
	bge	L_mc_bspe
	lsl	x6, x3, #4
	add	x4, x1, x6
	ldr	q2, [x4]
	add	x4, x4, #0x80
	ldr	q3, [x4]
	and	v4.16b, v2.16b, v1.16b
	mul	v4.8h, v4.8h, v0.8h
	ext	v5.16b, v4.16b, v4.16b, #8
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #4
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #2
	add	v4.8h, v4.8h, v5.8h
	umov	w5, v4.h[0]
	add	x4, x0, #0
	add	x4, x4, x3
	strb	w5, [x4]
	ushr	v4.8h, v2.8h, #1
	and	v4.16b, v4.16b, v1.16b
	mul	v4.8h, v4.8h, v0.8h
	ext	v5.16b, v4.16b, v4.16b, #8
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #4
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #2
	add	v4.8h, v4.8h, v5.8h
	umov	w5, v4.h[0]
	add	x4, x0, #16
	add	x4, x4, x3
	strb	w5, [x4]
	ushr	v4.8h, v2.8h, #2
	and	v4.16b, v4.16b, v1.16b
	mul	v4.8h, v4.8h, v0.8h
	ext	v5.16b, v4.16b, v4.16b, #8
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #4
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #2
	add	v4.8h, v4.8h, v5.8h
	umov	w5, v4.h[0]
	add	x4, x0, #32
	add	x4, x4, x3
	strb	w5, [x4]
	ushr	v4.8h, v2.8h, #3
	and	v4.16b, v4.16b, v1.16b
	mul	v4.8h, v4.8h, v0.8h
	ext	v5.16b, v4.16b, v4.16b, #8
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #4
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #2
	add	v4.8h, v4.8h, v5.8h
	umov	w5, v4.h[0]
	add	x4, x0, #48
	add	x4, x4, x3
	strb	w5, [x4]
	ushr	v4.8h, v2.8h, #4
	and	v4.16b, v4.16b, v1.16b
	mul	v4.8h, v4.8h, v0.8h
	ext	v5.16b, v4.16b, v4.16b, #8
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #4
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #2
	add	v4.8h, v4.8h, v5.8h
	umov	w5, v4.h[0]
	add	x4, x0, #0x40
	add	x4, x4, x3
	strb	w5, [x4]
	ushr	v4.8h, v2.8h, #5
	and	v4.16b, v4.16b, v1.16b
	mul	v4.8h, v4.8h, v0.8h
	ext	v5.16b, v4.16b, v4.16b, #8
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #4
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #2
	add	v4.8h, v4.8h, v5.8h
	umov	w5, v4.h[0]
	add	x4, x0, #0x50
	add	x4, x4, x3
	strb	w5, [x4]
	ushr	v4.8h, v2.8h, #6
	and	v4.16b, v4.16b, v1.16b
	mul	v4.8h, v4.8h, v0.8h
	ext	v5.16b, v4.16b, v4.16b, #8
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #4
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #2
	add	v4.8h, v4.8h, v5.8h
	umov	w5, v4.h[0]
	add	x4, x0, #0x60
	add	x4, x4, x3
	strb	w5, [x4]
	ushr	v4.8h, v2.8h, #7
	and	v4.16b, v4.16b, v1.16b
	mul	v4.8h, v4.8h, v0.8h
	ext	v5.16b, v4.16b, v4.16b, #8
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #4
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #2
	add	v4.8h, v4.8h, v5.8h
	umov	w5, v4.h[0]
	add	x4, x0, #0x70
	add	x4, x4, x3
	strb	w5, [x4]
	ushr	v4.8h, v2.8h, #8
	and	v4.16b, v4.16b, v1.16b
	mul	v4.8h, v4.8h, v0.8h
	ext	v5.16b, v4.16b, v4.16b, #8
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #4
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #2
	add	v4.8h, v4.8h, v5.8h
	umov	w5, v4.h[0]
	add	x4, x0, #0x80
	add	x4, x4, x3
	strb	w5, [x4]
	ushr	v4.8h, v2.8h, #9
	and	v4.16b, v4.16b, v1.16b
	mul	v4.8h, v4.8h, v0.8h
	ext	v5.16b, v4.16b, v4.16b, #8
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #4
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #2
	add	v4.8h, v4.8h, v5.8h
	umov	w5, v4.h[0]
	add	x4, x0, #0x90
	add	x4, x4, x3
	strb	w5, [x4]
	ushr	v4.8h, v2.8h, #10
	and	v4.16b, v4.16b, v1.16b
	mul	v4.8h, v4.8h, v0.8h
	ext	v5.16b, v4.16b, v4.16b, #8
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #4
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #2
	add	v4.8h, v4.8h, v5.8h
	umov	w5, v4.h[0]
	add	x4, x0, #0xa0
	add	x4, x4, x3
	strb	w5, [x4]
	ushr	v4.8h, v2.8h, #11
	and	v4.16b, v4.16b, v1.16b
	mul	v4.8h, v4.8h, v0.8h
	ext	v5.16b, v4.16b, v4.16b, #8
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #4
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #2
	add	v4.8h, v4.8h, v5.8h
	umov	w5, v4.h[0]
	add	x4, x0, #0xb0
	add	x4, x4, x3
	strb	w5, [x4]
	ushr	v4.8h, v2.8h, #12
	and	v4.16b, v4.16b, v1.16b
	mul	v4.8h, v4.8h, v0.8h
	ext	v5.16b, v4.16b, v4.16b, #8
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #4
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #2
	add	v4.8h, v4.8h, v5.8h
	umov	w5, v4.h[0]
	add	x4, x0, #0xc0
	add	x4, x4, x3
	strb	w5, [x4]
	and	v4.16b, v3.16b, v1.16b
	mul	v4.8h, v4.8h, v0.8h
	ext	v5.16b, v4.16b, v4.16b, #8
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #4
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #2
	add	v4.8h, v4.8h, v5.8h
	umov	w5, v4.h[0]
	add	x4, x0, #8
	add	x4, x4, x3
	strb	w5, [x4]
	ushr	v4.8h, v3.8h, #1
	and	v4.16b, v4.16b, v1.16b
	mul	v4.8h, v4.8h, v0.8h
	ext	v5.16b, v4.16b, v4.16b, #8
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #4
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #2
	add	v4.8h, v4.8h, v5.8h
	umov	w5, v4.h[0]
	add	x4, x0, #24
	add	x4, x4, x3
	strb	w5, [x4]
	ushr	v4.8h, v3.8h, #2
	and	v4.16b, v4.16b, v1.16b
	mul	v4.8h, v4.8h, v0.8h
	ext	v5.16b, v4.16b, v4.16b, #8
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #4
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #2
	add	v4.8h, v4.8h, v5.8h
	umov	w5, v4.h[0]
	add	x4, x0, #40
	add	x4, x4, x3
	strb	w5, [x4]
	ushr	v4.8h, v3.8h, #3
	and	v4.16b, v4.16b, v1.16b
	mul	v4.8h, v4.8h, v0.8h
	ext	v5.16b, v4.16b, v4.16b, #8
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #4
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #2
	add	v4.8h, v4.8h, v5.8h
	umov	w5, v4.h[0]
	add	x4, x0, #56
	add	x4, x4, x3
	strb	w5, [x4]
	ushr	v4.8h, v3.8h, #4
	and	v4.16b, v4.16b, v1.16b
	mul	v4.8h, v4.8h, v0.8h
	ext	v5.16b, v4.16b, v4.16b, #8
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #4
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #2
	add	v4.8h, v4.8h, v5.8h
	umov	w5, v4.h[0]
	add	x4, x0, #0x48
	add	x4, x4, x3
	strb	w5, [x4]
	ushr	v4.8h, v3.8h, #5
	and	v4.16b, v4.16b, v1.16b
	mul	v4.8h, v4.8h, v0.8h
	ext	v5.16b, v4.16b, v4.16b, #8
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #4
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #2
	add	v4.8h, v4.8h, v5.8h
	umov	w5, v4.h[0]
	add	x4, x0, #0x58
	add	x4, x4, x3
	strb	w5, [x4]
	ushr	v4.8h, v3.8h, #6
	and	v4.16b, v4.16b, v1.16b
	mul	v4.8h, v4.8h, v0.8h
	ext	v5.16b, v4.16b, v4.16b, #8
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #4
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #2
	add	v4.8h, v4.8h, v5.8h
	umov	w5, v4.h[0]
	add	x4, x0, #0x68
	add	x4, x4, x3
	strb	w5, [x4]
	ushr	v4.8h, v3.8h, #7
	and	v4.16b, v4.16b, v1.16b
	mul	v4.8h, v4.8h, v0.8h
	ext	v5.16b, v4.16b, v4.16b, #8
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #4
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #2
	add	v4.8h, v4.8h, v5.8h
	umov	w5, v4.h[0]
	add	x4, x0, #0x78
	add	x4, x4, x3
	strb	w5, [x4]
	ushr	v4.8h, v3.8h, #8
	and	v4.16b, v4.16b, v1.16b
	mul	v4.8h, v4.8h, v0.8h
	ext	v5.16b, v4.16b, v4.16b, #8
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #4
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #2
	add	v4.8h, v4.8h, v5.8h
	umov	w5, v4.h[0]
	add	x4, x0, #0x88
	add	x4, x4, x3
	strb	w5, [x4]
	ushr	v4.8h, v3.8h, #9
	and	v4.16b, v4.16b, v1.16b
	mul	v4.8h, v4.8h, v0.8h
	ext	v5.16b, v4.16b, v4.16b, #8
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #4
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #2
	add	v4.8h, v4.8h, v5.8h
	umov	w5, v4.h[0]
	add	x4, x0, #0x98
	add	x4, x4, x3
	strb	w5, [x4]
	ushr	v4.8h, v3.8h, #10
	and	v4.16b, v4.16b, v1.16b
	mul	v4.8h, v4.8h, v0.8h
	ext	v5.16b, v4.16b, v4.16b, #8
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #4
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #2
	add	v4.8h, v4.8h, v5.8h
	umov	w5, v4.h[0]
	add	x4, x0, #0xa8
	add	x4, x4, x3
	strb	w5, [x4]
	ushr	v4.8h, v3.8h, #11
	and	v4.16b, v4.16b, v1.16b
	mul	v4.8h, v4.8h, v0.8h
	ext	v5.16b, v4.16b, v4.16b, #8
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #4
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #2
	add	v4.8h, v4.8h, v5.8h
	umov	w5, v4.h[0]
	add	x4, x0, #0xb8
	add	x4, x4, x3
	strb	w5, [x4]
	ushr	v4.8h, v3.8h, #12
	and	v4.16b, v4.16b, v1.16b
	mul	v4.8h, v4.8h, v0.8h
	ext	v5.16b, v4.16b, v4.16b, #8
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #4
	add	v4.8h, v4.8h, v5.8h
	ext	v5.16b, v4.16b, v4.16b, #2
	add	v4.8h, v4.8h, v5.8h
	umov	w5, v4.h[0]
	add	x4, x0, #0xc8
	add	x4, x4, x3
	strb	w5, [x4]
	add	x3, x3, #1
	b	L_mc_bsp
L_mc_bspe:
	ret
#ifndef __APPLE__
	.size	wc_mceliece_bs_poly_neon,.-wc_mceliece_bs_poly_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_gf_mul_scalar_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_gf_mul_scalar_neon)
.type	wc_mceliece_gf_mul_scalar_neon,@function
.align	2
wc_mceliece_gf_mul_scalar_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_gf_mul_scalar_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_gf_mul_scalar_neon)
.p2align	2
_wc_mceliece_gf_mul_scalar_neon:
#endif /* __APPLE__ */
	mov	w6, w0
	mov	w2, #0
	lsr	w3, w1, #0
	and	w3, w3, #1
	neg	w3, w3
	and	w4, w6, w3
	eor	w2, w2, w4
	lsr	w3, w1, #1
	and	w3, w3, #1
	neg	w3, w3
	lsl	w4, w6, #1
	and	w4, w4, w3
	eor	w2, w2, w4
	lsr	w3, w1, #2
	and	w3, w3, #1
	neg	w3, w3
	lsl	w4, w6, #2
	and	w4, w4, w3
	eor	w2, w2, w4
	lsr	w3, w1, #3
	and	w3, w3, #1
	neg	w3, w3
	lsl	w4, w6, #3
	and	w4, w4, w3
	eor	w2, w2, w4
	lsr	w3, w1, #4
	and	w3, w3, #1
	neg	w3, w3
	lsl	w4, w6, #4
	and	w4, w4, w3
	eor	w2, w2, w4
	lsr	w3, w1, #5
	and	w3, w3, #1
	neg	w3, w3
	lsl	w4, w6, #5
	and	w4, w4, w3
	eor	w2, w2, w4
	lsr	w3, w1, #6
	and	w3, w3, #1
	neg	w3, w3
	lsl	w4, w6, #6
	and	w4, w4, w3
	eor	w2, w2, w4
	lsr	w3, w1, #7
	and	w3, w3, #1
	neg	w3, w3
	lsl	w4, w6, #7
	and	w4, w4, w3
	eor	w2, w2, w4
	lsr	w3, w1, #8
	and	w3, w3, #1
	neg	w3, w3
	lsl	w4, w6, #8
	and	w4, w4, w3
	eor	w2, w2, w4
	lsr	w3, w1, #9
	and	w3, w3, #1
	neg	w3, w3
	lsl	w4, w6, #9
	and	w4, w4, w3
	eor	w2, w2, w4
	lsr	w3, w1, #10
	and	w3, w3, #1
	neg	w3, w3
	lsl	w4, w6, #10
	and	w4, w4, w3
	eor	w2, w2, w4
	lsr	w3, w1, #11
	and	w3, w3, #1
	neg	w3, w3
	lsl	w4, w6, #11
	and	w4, w4, w3
	eor	w2, w2, w4
	lsr	w3, w1, #12
	and	w3, w3, #1
	neg	w3, w3
	lsl	w4, w6, #12
	and	w4, w4, w3
	eor	w2, w2, w4
	mov	w7, #0x1ff
	lsl	w7, w7, #16
	and	w4, w2, w7
	lsr	w5, w4, #9
	eor	w2, w2, w5
	lsr	w5, w4, #10
	eor	w2, w2, w5
	lsr	w5, w4, #12
	eor	w2, w2, w5
	lsr	w5, w4, #13
	eor	w2, w2, w5
	mov	w7, #0xe000
	and	w4, w2, w7
	lsr	w5, w4, #9
	eor	w2, w2, w5
	lsr	w5, w4, #10
	eor	w2, w2, w5
	lsr	w5, w4, #12
	eor	w2, w2, w5
	lsr	w5, w4, #13
	eor	w2, w2, w5
	mov	w7, #0x1fff
	and	w0, w2, w7
	ret
#ifndef __APPLE__
	.size	wc_mceliece_gf_mul_scalar_neon,.-wc_mceliece_gf_mul_scalar_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_gf_inv_scalar_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_gf_inv_scalar_neon)
.type	wc_mceliece_gf_inv_scalar_neon,@function
.align	2
wc_mceliece_gf_inv_scalar_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_gf_inv_scalar_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_gf_inv_scalar_neon)
.p2align	2
_wc_mceliece_gf_inv_scalar_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-48]!
	add	x29, sp, #0
	stp	x19, x20, [x29, #24]
	str	x21, [x29, #40]
	mov	w19, w0
	mov	w1, w0
#ifndef __APPLE__
	bl	wc_mceliece_gf_mul_scalar_neon
#else
	bl	_wc_mceliece_gf_mul_scalar_neon
#endif /* __APPLE__ */
	mov	w1, w19
#ifndef __APPLE__
	bl	wc_mceliece_gf_mul_scalar_neon
#else
	bl	_wc_mceliece_gf_mul_scalar_neon
#endif /* __APPLE__ */
	mov	w20, w0
	mov	w1, w0
#ifndef __APPLE__
	bl	wc_mceliece_gf_mul_scalar_neon
#else
	bl	_wc_mceliece_gf_mul_scalar_neon
#endif /* __APPLE__ */
	mov	w1, w0
#ifndef __APPLE__
	bl	wc_mceliece_gf_mul_scalar_neon
#else
	bl	_wc_mceliece_gf_mul_scalar_neon
#endif /* __APPLE__ */
	mov	w1, w20
#ifndef __APPLE__
	bl	wc_mceliece_gf_mul_scalar_neon
#else
	bl	_wc_mceliece_gf_mul_scalar_neon
#endif /* __APPLE__ */
	mov	w21, w0
	mov	w1, w0
#ifndef __APPLE__
	bl	wc_mceliece_gf_mul_scalar_neon
#else
	bl	_wc_mceliece_gf_mul_scalar_neon
#endif /* __APPLE__ */
	mov	w1, w0
#ifndef __APPLE__
	bl	wc_mceliece_gf_mul_scalar_neon
#else
	bl	_wc_mceliece_gf_mul_scalar_neon
#endif /* __APPLE__ */
	mov	w1, w0
#ifndef __APPLE__
	bl	wc_mceliece_gf_mul_scalar_neon
#else
	bl	_wc_mceliece_gf_mul_scalar_neon
#endif /* __APPLE__ */
	mov	w1, w0
#ifndef __APPLE__
	bl	wc_mceliece_gf_mul_scalar_neon
#else
	bl	_wc_mceliece_gf_mul_scalar_neon
#endif /* __APPLE__ */
	mov	w1, w21
#ifndef __APPLE__
	bl	wc_mceliece_gf_mul_scalar_neon
#else
	bl	_wc_mceliece_gf_mul_scalar_neon
#endif /* __APPLE__ */
	mov	w1, w0
#ifndef __APPLE__
	bl	wc_mceliece_gf_mul_scalar_neon
#else
	bl	_wc_mceliece_gf_mul_scalar_neon
#endif /* __APPLE__ */
	mov	w1, w0
#ifndef __APPLE__
	bl	wc_mceliece_gf_mul_scalar_neon
#else
	bl	_wc_mceliece_gf_mul_scalar_neon
#endif /* __APPLE__ */
	mov	w1, w0
#ifndef __APPLE__
	bl	wc_mceliece_gf_mul_scalar_neon
#else
	bl	_wc_mceliece_gf_mul_scalar_neon
#endif /* __APPLE__ */
	mov	w1, w0
#ifndef __APPLE__
	bl	wc_mceliece_gf_mul_scalar_neon
#else
	bl	_wc_mceliece_gf_mul_scalar_neon
#endif /* __APPLE__ */
	mov	w1, w21
#ifndef __APPLE__
	bl	wc_mceliece_gf_mul_scalar_neon
#else
	bl	_wc_mceliece_gf_mul_scalar_neon
#endif /* __APPLE__ */
	mov	w1, w0
#ifndef __APPLE__
	bl	wc_mceliece_gf_mul_scalar_neon
#else
	bl	_wc_mceliece_gf_mul_scalar_neon
#endif /* __APPLE__ */
	ldp	x19, x20, [x29, #24]
	ldr	x21, [x29, #40]
	ldp	x29, x30, [sp], #48
	ret
#ifndef __APPLE__
	.size	wc_mceliece_gf_inv_scalar_neon,.-wc_mceliece_gf_inv_scalar_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_gf_mulc_mac_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_gf_mulc_mac_neon)
.type	wc_mceliece_gf_mulc_mac_neon,@function
.align	2
wc_mceliece_gf_mulc_mac_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_gf_mulc_mac_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_gf_mulc_mac_neon)
.p2align	2
_wc_mceliece_gf_mulc_mac_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
	stp	d12, d13, [x29, #48]
	stp	d14, d15, [x29, #64]
	eor	v0.16b, v0.16b, v0.16b
	mov	x6, #0x1ff
	dup	v1.4s, w6
	shl	v1.4s, v1.4s, #16
	mov	x6, #0xe000
	dup	v2.4s, w6
	mov	x6, #0x1fff
	dup	v3.4s, w6
	mov	w7, w1
	lsr	x6, x7, #0
	and	x6, x6, #1
	neg	x6, x6
	dup	v4.4s, w6
	lsr	x6, x7, #1
	and	x6, x6, #1
	neg	x6, x6
	dup	v5.4s, w6
	lsr	x6, x7, #2
	and	x6, x6, #1
	neg	x6, x6
	dup	v6.4s, w6
	lsr	x6, x7, #3
	and	x6, x6, #1
	neg	x6, x6
	dup	v7.4s, w6
	lsr	x6, x7, #4
	and	x6, x6, #1
	neg	x6, x6
	dup	v8.4s, w6
	lsr	x6, x7, #5
	and	x6, x6, #1
	neg	x6, x6
	dup	v9.4s, w6
	lsr	x6, x7, #6
	and	x6, x6, #1
	neg	x6, x6
	dup	v10.4s, w6
	lsr	x6, x7, #7
	and	x6, x6, #1
	neg	x6, x6
	dup	v11.4s, w6
	lsr	x6, x7, #8
	and	x6, x6, #1
	neg	x6, x6
	dup	v12.4s, w6
	lsr	x6, x7, #9
	and	x6, x6, #1
	neg	x6, x6
	dup	v13.4s, w6
	lsr	x6, x7, #10
	and	x6, x6, #1
	neg	x6, x6
	dup	v14.4s, w6
	lsr	x6, x7, #11
	and	x6, x6, #1
	neg	x6, x6
	dup	v15.4s, w6
	lsr	x6, x7, #12
	and	x6, x6, #1
	neg	x6, x6
	dup	v16.4s, w6
	mov	x4, #0
L_mc_gmm:
	cmp	w4, w3
	bge	L_mc_gmme
	lsl	x5, x4, #1
	add	x6, x2, x5
	ldr	q17, [x6]
	zip1	v18.8h, v17.8h, v0.8h
	and	v19.16b, v18.16b, v4.16b
	shl	v21.4s, v18.4s, #1
	and	v21.16b, v21.16b, v5.16b
	eor	v19.16b, v19.16b, v21.16b
	shl	v21.4s, v18.4s, #2
	and	v21.16b, v21.16b, v6.16b
	eor	v19.16b, v19.16b, v21.16b
	shl	v21.4s, v18.4s, #3
	and	v21.16b, v21.16b, v7.16b
	eor	v19.16b, v19.16b, v21.16b
	shl	v21.4s, v18.4s, #4
	and	v21.16b, v21.16b, v8.16b
	eor	v19.16b, v19.16b, v21.16b
	shl	v21.4s, v18.4s, #5
	and	v21.16b, v21.16b, v9.16b
	eor	v19.16b, v19.16b, v21.16b
	shl	v21.4s, v18.4s, #6
	and	v21.16b, v21.16b, v10.16b
	eor	v19.16b, v19.16b, v21.16b
	shl	v21.4s, v18.4s, #7
	and	v21.16b, v21.16b, v11.16b
	eor	v19.16b, v19.16b, v21.16b
	shl	v21.4s, v18.4s, #8
	and	v21.16b, v21.16b, v12.16b
	eor	v19.16b, v19.16b, v21.16b
	shl	v21.4s, v18.4s, #9
	and	v21.16b, v21.16b, v13.16b
	eor	v19.16b, v19.16b, v21.16b
	shl	v21.4s, v18.4s, #10
	and	v21.16b, v21.16b, v14.16b
	eor	v19.16b, v19.16b, v21.16b
	shl	v21.4s, v18.4s, #11
	and	v21.16b, v21.16b, v15.16b
	eor	v19.16b, v19.16b, v21.16b
	shl	v21.4s, v18.4s, #12
	and	v21.16b, v21.16b, v16.16b
	eor	v19.16b, v19.16b, v21.16b
	and	v21.16b, v19.16b, v1.16b
	ushr	v22.4s, v21.4s, #9
	eor	v19.16b, v19.16b, v22.16b
	ushr	v22.4s, v21.4s, #10
	eor	v19.16b, v19.16b, v22.16b
	ushr	v22.4s, v21.4s, #12
	eor	v19.16b, v19.16b, v22.16b
	ushr	v22.4s, v21.4s, #13
	eor	v19.16b, v19.16b, v22.16b
	and	v21.16b, v19.16b, v2.16b
	ushr	v22.4s, v21.4s, #9
	eor	v19.16b, v19.16b, v22.16b
	ushr	v22.4s, v21.4s, #10
	eor	v19.16b, v19.16b, v22.16b
	ushr	v22.4s, v21.4s, #12
	eor	v19.16b, v19.16b, v22.16b
	ushr	v22.4s, v21.4s, #13
	eor	v19.16b, v19.16b, v22.16b
	and	v19.16b, v19.16b, v3.16b
	zip2	v18.8h, v17.8h, v0.8h
	and	v20.16b, v18.16b, v4.16b
	shl	v21.4s, v18.4s, #1
	and	v21.16b, v21.16b, v5.16b
	eor	v20.16b, v20.16b, v21.16b
	shl	v21.4s, v18.4s, #2
	and	v21.16b, v21.16b, v6.16b
	eor	v20.16b, v20.16b, v21.16b
	shl	v21.4s, v18.4s, #3
	and	v21.16b, v21.16b, v7.16b
	eor	v20.16b, v20.16b, v21.16b
	shl	v21.4s, v18.4s, #4
	and	v21.16b, v21.16b, v8.16b
	eor	v20.16b, v20.16b, v21.16b
	shl	v21.4s, v18.4s, #5
	and	v21.16b, v21.16b, v9.16b
	eor	v20.16b, v20.16b, v21.16b
	shl	v21.4s, v18.4s, #6
	and	v21.16b, v21.16b, v10.16b
	eor	v20.16b, v20.16b, v21.16b
	shl	v21.4s, v18.4s, #7
	and	v21.16b, v21.16b, v11.16b
	eor	v20.16b, v20.16b, v21.16b
	shl	v21.4s, v18.4s, #8
	and	v21.16b, v21.16b, v12.16b
	eor	v20.16b, v20.16b, v21.16b
	shl	v21.4s, v18.4s, #9
	and	v21.16b, v21.16b, v13.16b
	eor	v20.16b, v20.16b, v21.16b
	shl	v21.4s, v18.4s, #10
	and	v21.16b, v21.16b, v14.16b
	eor	v20.16b, v20.16b, v21.16b
	shl	v21.4s, v18.4s, #11
	and	v21.16b, v21.16b, v15.16b
	eor	v20.16b, v20.16b, v21.16b
	shl	v21.4s, v18.4s, #12
	and	v21.16b, v21.16b, v16.16b
	eor	v20.16b, v20.16b, v21.16b
	and	v21.16b, v20.16b, v1.16b
	ushr	v22.4s, v21.4s, #9
	eor	v20.16b, v20.16b, v22.16b
	ushr	v22.4s, v21.4s, #10
	eor	v20.16b, v20.16b, v22.16b
	ushr	v22.4s, v21.4s, #12
	eor	v20.16b, v20.16b, v22.16b
	ushr	v22.4s, v21.4s, #13
	eor	v20.16b, v20.16b, v22.16b
	and	v21.16b, v20.16b, v2.16b
	ushr	v22.4s, v21.4s, #9
	eor	v20.16b, v20.16b, v22.16b
	ushr	v22.4s, v21.4s, #10
	eor	v20.16b, v20.16b, v22.16b
	ushr	v22.4s, v21.4s, #12
	eor	v20.16b, v20.16b, v22.16b
	ushr	v22.4s, v21.4s, #13
	eor	v20.16b, v20.16b, v22.16b
	and	v20.16b, v20.16b, v3.16b
	uzp1	v19.8h, v19.8h, v20.8h
	add	x6, x0, x5
	ldr	q20, [x6]
	eor	v19.16b, v19.16b, v20.16b
	str	q19, [x6]
	add	x4, x4, #8
	b	L_mc_gmm
L_mc_gmme:
	ldp	d8, d9, [x29, #16]
	ldp	d10, d11, [x29, #32]
	ldp	d12, d13, [x29, #48]
	ldp	d14, d15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
#ifndef __APPLE__
	.size	wc_mceliece_gf_mulc_mac_neon,.-wc_mceliece_gf_mulc_mac_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_gf_mulc_mac_full_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_gf_mulc_mac_full_neon)
.type	wc_mceliece_gf_mulc_mac_full_neon,@function
.align	2
wc_mceliece_gf_mulc_mac_full_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_gf_mulc_mac_full_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_gf_mulc_mac_full_neon)
.p2align	2
_wc_mceliece_gf_mulc_mac_full_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-64]!
	add	x29, sp, #0
	stp	x19, x20, [x29, #24]
	stp	x21, x22, [x29, #40]
	str	x23, [x29, #56]
	mov	x19, x0
	mov	w20, w1
	mov	x21, x2
	mov	w22, w3
	lsr	x4, x22, #3
	lsl	x4, x4, #3
	cbz	x4, L_mc_mmf_s
	mov	x0, x19
	mov	w1, w20
	mov	x2, x21
	mov	w3, w4
#ifndef __APPLE__
	bl	wc_mceliece_gf_mulc_mac_neon
#else
	bl	_wc_mceliece_gf_mulc_mac_neon
#endif /* __APPLE__ */
L_mc_mmf_s:
	lsr	x4, x22, #3
	lsl	x4, x4, #3
	mov	x23, x4
L_mc_mmf_t:
	cmp	x23, x22
	bge	L_mc_mmf_te
	mov	w0, w20
	lsl	x5, x23, #1
	add	x6, x21, x5
	ldrh	w1, [x6]
#ifndef __APPLE__
	bl	wc_mceliece_gf_mul_scalar_neon
#else
	bl	_wc_mceliece_gf_mul_scalar_neon
#endif /* __APPLE__ */
	lsl	x5, x23, #1
	add	x6, x19, x5
	ldrh	w7, [x6]
	eor	w7, w7, w0
	strh	w7, [x6]
	add	x23, x23, #1
	b	L_mc_mmf_t
L_mc_mmf_te:
	ldp	x19, x20, [x29, #24]
	ldp	x21, x22, [x29, #40]
	ldr	x23, [x29, #56]
	ldp	x29, x30, [sp], #0x40
	ret
#ifndef __APPLE__
	.size	wc_mceliece_gf_mulc_mac_full_neon,.-wc_mceliece_gf_mulc_mac_full_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_mont_batch_inv_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_mont_batch_inv_neon)
.type	wc_mceliece_mont_batch_inv_neon,@function
.align	2
wc_mceliece_mont_batch_inv_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_mont_batch_inv_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_mont_batch_inv_neon)
.p2align	2
_wc_mceliece_mont_batch_inv_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-64]!
	add	x29, sp, #0
	stp	x19, x20, [x29, #24]
	stp	x21, x22, [x29, #40]
	str	x23, [x29, #56]
	mov	x19, x0
	mov	x20, x1
	mov	x21, x2
	mov	x23, #0x1a0
	cbz	w4, L_mc_mbi_sqe
	mov	x22, #0
L_mc_mbi_sq:
	cmp	x22, #32
	bge	L_mc_mbi_sqe
	mul	x5, x22, x23
	add	x0, x20, x5
	mov	x1, x0
	mov	x2, x0
	add	x3, x21, #0x340
#ifndef __APPLE__
	bl	wc_mceliece_aff_v256_mul_neon
#else
	bl	_wc_mceliece_aff_v256_mul_neon
#endif /* __APPLE__ */
	add	x22, x22, #1
	b	L_mc_mbi_sq
L_mc_mbi_sqe:
	add	x6, x20, #0
	ldp	q0, q1, [x6]
	add	x6, x19, #0
	stp	q0, q1, [x6]
	add	x6, x20, #32
	ldp	q0, q1, [x6]
	add	x6, x19, #32
	stp	q0, q1, [x6]
	add	x6, x20, #0x40
	ldp	q0, q1, [x6]
	add	x6, x19, #0x40
	stp	q0, q1, [x6]
	add	x6, x20, #0x60
	ldp	q0, q1, [x6]
	add	x6, x19, #0x60
	stp	q0, q1, [x6]
	add	x6, x20, #0x80
	ldp	q0, q1, [x6]
	add	x6, x19, #0x80
	stp	q0, q1, [x6]
	add	x6, x20, #0xa0
	ldp	q0, q1, [x6]
	add	x6, x19, #0xa0
	stp	q0, q1, [x6]
	add	x6, x20, #0xc0
	ldp	q0, q1, [x6]
	add	x6, x19, #0xc0
	stp	q0, q1, [x6]
	add	x6, x20, #0xe0
	ldp	q0, q1, [x6]
	add	x6, x19, #0xe0
	stp	q0, q1, [x6]
	add	x6, x20, #0x100
	ldp	q0, q1, [x6]
	add	x6, x19, #0x100
	stp	q0, q1, [x6]
	add	x6, x20, #0x120
	ldp	q0, q1, [x6]
	add	x6, x19, #0x120
	stp	q0, q1, [x6]
	add	x6, x20, #0x140
	ldp	q0, q1, [x6]
	add	x6, x19, #0x140
	stp	q0, q1, [x6]
	add	x6, x20, #0x160
	ldp	q0, q1, [x6]
	add	x6, x19, #0x160
	stp	q0, q1, [x6]
	add	x6, x20, #0x180
	ldp	q0, q1, [x6]
	add	x6, x19, #0x180
	stp	q0, q1, [x6]
	mov	x22, #1
L_mc_mbi_pf:
	cmp	x22, #32
	bge	L_mc_mbi_pfe
	mul	x5, x22, x23
	add	x0, x19, x5
	sub	x1, x0, #0x1a0
	add	x2, x20, x5
	add	x3, x21, #0x340
#ifndef __APPLE__
	bl	wc_mceliece_aff_v256_mul_neon
#else
	bl	_wc_mceliece_aff_v256_mul_neon
#endif /* __APPLE__ */
	add	x22, x22, #1
	b	L_mc_mbi_pf
L_mc_mbi_pfe:
	mov	x5, #0x3260
	mov	x0, x21
	add	x1, x19, x5
	add	x2, x21, #0x660
	add	x3, x21, #0x340
#ifndef __APPLE__
	bl	wc_mceliece_aff_inv256_neon
#else
	bl	_wc_mceliece_aff_inv256_neon
#endif /* __APPLE__ */
	mov	x22, #31
L_mc_mbi_sf:
	cmp	x22, #1
	blt	L_mc_mbi_sfe
	mul	x5, x22, x23
	add	x0, x21, #0x1a0
	mov	x1, x21
	add	x2, x19, x5
	sub	x2, x2, #0x1a0
	add	x3, x21, #0x340
#ifndef __APPLE__
	bl	wc_mceliece_aff_v256_mul_neon
#else
	bl	_wc_mceliece_aff_v256_mul_neon
#endif /* __APPLE__ */
	mov	x0, x21
	mov	x1, x21
	mul	x5, x22, x23
	add	x2, x20, x5
	add	x3, x21, #0x340
#ifndef __APPLE__
	bl	wc_mceliece_aff_v256_mul_neon
#else
	bl	_wc_mceliece_aff_v256_mul_neon
#endif /* __APPLE__ */
	mul	x5, x22, x23
	add	x0, x19, x5
	add	x1, x21, #0x1a0
	add	x6, x1, #0
	ldp	q0, q1, [x6]
	add	x6, x0, #0
	stp	q0, q1, [x6]
	add	x6, x1, #32
	ldp	q0, q1, [x6]
	add	x6, x0, #32
	stp	q0, q1, [x6]
	add	x6, x1, #0x40
	ldp	q0, q1, [x6]
	add	x6, x0, #0x40
	stp	q0, q1, [x6]
	add	x6, x1, #0x60
	ldp	q0, q1, [x6]
	add	x6, x0, #0x60
	stp	q0, q1, [x6]
	add	x6, x1, #0x80
	ldp	q0, q1, [x6]
	add	x6, x0, #0x80
	stp	q0, q1, [x6]
	add	x6, x1, #0xa0
	ldp	q0, q1, [x6]
	add	x6, x0, #0xa0
	stp	q0, q1, [x6]
	add	x6, x1, #0xc0
	ldp	q0, q1, [x6]
	add	x6, x0, #0xc0
	stp	q0, q1, [x6]
	add	x6, x1, #0xe0
	ldp	q0, q1, [x6]
	add	x6, x0, #0xe0
	stp	q0, q1, [x6]
	add	x6, x1, #0x100
	ldp	q0, q1, [x6]
	add	x6, x0, #0x100
	stp	q0, q1, [x6]
	add	x6, x1, #0x120
	ldp	q0, q1, [x6]
	add	x6, x0, #0x120
	stp	q0, q1, [x6]
	add	x6, x1, #0x140
	ldp	q0, q1, [x6]
	add	x6, x0, #0x140
	stp	q0, q1, [x6]
	add	x6, x1, #0x160
	ldp	q0, q1, [x6]
	add	x6, x0, #0x160
	stp	q0, q1, [x6]
	add	x6, x1, #0x180
	ldp	q0, q1, [x6]
	add	x6, x0, #0x180
	stp	q0, q1, [x6]
	sub	x22, x22, #1
	b	L_mc_mbi_sf
L_mc_mbi_sfe:
	mov	x0, x19
	mov	x1, x21
	add	x6, x1, #0
	ldp	q0, q1, [x6]
	add	x6, x0, #0
	stp	q0, q1, [x6]
	add	x6, x1, #32
	ldp	q0, q1, [x6]
	add	x6, x0, #32
	stp	q0, q1, [x6]
	add	x6, x1, #0x40
	ldp	q0, q1, [x6]
	add	x6, x0, #0x40
	stp	q0, q1, [x6]
	add	x6, x1, #0x60
	ldp	q0, q1, [x6]
	add	x6, x0, #0x60
	stp	q0, q1, [x6]
	add	x6, x1, #0x80
	ldp	q0, q1, [x6]
	add	x6, x0, #0x80
	stp	q0, q1, [x6]
	add	x6, x1, #0xa0
	ldp	q0, q1, [x6]
	add	x6, x0, #0xa0
	stp	q0, q1, [x6]
	add	x6, x1, #0xc0
	ldp	q0, q1, [x6]
	add	x6, x0, #0xc0
	stp	q0, q1, [x6]
	add	x6, x1, #0xe0
	ldp	q0, q1, [x6]
	add	x6, x0, #0xe0
	stp	q0, q1, [x6]
	add	x6, x1, #0x100
	ldp	q0, q1, [x6]
	add	x6, x0, #0x100
	stp	q0, q1, [x6]
	add	x6, x1, #0x120
	ldp	q0, q1, [x6]
	add	x6, x0, #0x120
	stp	q0, q1, [x6]
	add	x6, x1, #0x140
	ldp	q0, q1, [x6]
	add	x6, x0, #0x140
	stp	q0, q1, [x6]
	add	x6, x1, #0x160
	ldp	q0, q1, [x6]
	add	x6, x0, #0x160
	stp	q0, q1, [x6]
	add	x6, x1, #0x180
	ldp	q0, q1, [x6]
	add	x6, x0, #0x180
	stp	q0, q1, [x6]
	ldp	x19, x20, [x29, #24]
	ldp	x21, x22, [x29, #40]
	ldr	x23, [x29, #56]
	ldp	x29, x30, [sp], #0x40
	ret
#ifndef __APPLE__
	.size	wc_mceliece_mont_batch_inv_neon,.-wc_mceliece_mont_batch_inv_neon
#endif /* __APPLE__ */
#ifndef WOLFSSL_MCELIECE_NO_DECAPSULATE
#ifndef __APPLE__
.text
.globl	wc_mceliece_aff_ama_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_aff_ama_neon)
.type	wc_mceliece_aff_ama_neon,@function
.align	2
wc_mceliece_aff_ama_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_aff_ama_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_aff_ama_neon)
.p2align	2
_wc_mceliece_aff_ama_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-48]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
	mov	x5, #0
L_mc_xor13_k_amaa:
	lsl	x6, x5, #5
	add	x8, x0, x6
	ldp	q0, q1, [x8]
	add	x9, x1, x6
	ldp	q2, q3, [x9]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x7, x0, x6
	stp	q0, q1, [x7]
	add	x5, x5, #1
	cmp	x5, #13
	blt	L_mc_xor13_k_amaa
	eor	v10.16b, v10.16b, v10.16b
	mov	x12, x4
	mov	x7, #0
L_mc_v256_z_amam:
	stp	q10, q10, [x12]
	add	x12, x12, #32
	add	x7, x7, #1
	cmp	x7, #25
	blt	L_mc_v256_z_amam
	mov	x5, #0
L_mc_v256_i_amam:
	cmp	x5, #13
	bge	L_mc_v256_rs_amam
	lsl	x13, x5, #5
	add	x8, x0, x13
	ldp	q0, q1, [x8]
	mov	x6, #0
L_mc_v256_j_amam:
	cmp	x6, #13
	bge	L_mc_v256_in_amam
	lsl	x13, x6, #5
	add	x9, x2, x13
	ldp	q2, q3, [x9]
	and	v4.16b, v0.16b, v2.16b
	and	v5.16b, v1.16b, v3.16b
	add	x13, x5, x6
	lsl	x13, x13, #5
	add	x10, x4, x13
	ldp	q6, q7, [x10]
	eor	v6.16b, v6.16b, v4.16b
	eor	v7.16b, v7.16b, v5.16b
	stp	q6, q7, [x10]
	add	x6, x6, #1
	b	L_mc_v256_j_amam
L_mc_v256_in_amam:
	add	x5, x5, #1
	b	L_mc_v256_i_amam
L_mc_v256_rs_amam:
	mov	x7, #24
L_mc_v256_rk_amam:
	cmp	x7, #13
	blt	L_mc_v256_copy_amam
	lsl	x13, x7, #5
	add	x10, x4, x13
	ldp	q6, q7, [x10]
	sub	x14, x7, #9
	lsl	x14, x14, #5
	add	x11, x4, x14
	ldp	q8, q9, [x11]
	eor	v8.16b, v8.16b, v6.16b
	eor	v9.16b, v9.16b, v7.16b
	stp	q8, q9, [x11]
	sub	x14, x7, #10
	lsl	x14, x14, #5
	add	x11, x4, x14
	ldp	q8, q9, [x11]
	eor	v8.16b, v8.16b, v6.16b
	eor	v9.16b, v9.16b, v7.16b
	stp	q8, q9, [x11]
	sub	x14, x7, #12
	lsl	x14, x14, #5
	add	x11, x4, x14
	ldp	q8, q9, [x11]
	eor	v8.16b, v8.16b, v6.16b
	eor	v9.16b, v9.16b, v7.16b
	stp	q8, q9, [x11]
	sub	x14, x7, #13
	lsl	x14, x14, #5
	add	x11, x4, x14
	ldp	q8, q9, [x11]
	eor	v8.16b, v8.16b, v6.16b
	eor	v9.16b, v9.16b, v7.16b
	stp	q8, q9, [x11]
	sub	x7, x7, #1
	b	L_mc_v256_rk_amam
L_mc_v256_copy_amam:
	mov	x7, #0
L_mc_v256_cp_amam:
	cmp	x7, #13
	bge	L_mc_v256_done_amam
	lsl	x13, x7, #5
	add	x10, x4, x13
	add	x11, x3, x13
	ldp	q6, q7, [x10]
	stp	q6, q7, [x11]
	add	x7, x7, #1
	b	L_mc_v256_cp_amam
L_mc_v256_done_amam:
	mov	x5, #0
L_mc_xor13_k_amab:
	lsl	x6, x5, #5
	add	x8, x1, x6
	ldp	q0, q1, [x8]
	add	x9, x3, x6
	ldp	q2, q3, [x9]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	add	x7, x1, x6
	stp	q0, q1, [x7]
	add	x5, x5, #1
	cmp	x5, #13
	blt	L_mc_xor13_k_amab
	ldp	d8, d9, [x29, #16]
	ldp	d10, d11, [x29, #32]
	ldp	x29, x30, [sp], #48
	ret
#ifndef __APPLE__
	.size	wc_mceliece_aff_ama_neon,.-wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_aff_btr_net_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_aff_btr_net_neon)
.type	wc_mceliece_aff_btr_net_neon,@function
.align	2
wc_mceliece_aff_btr_net_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_aff_btr_net_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_aff_btr_net_neon)
.p2align	2
_wc_mceliece_aff_btr_net_neon:
#endif /* __APPLE__ */
	lsl	x8, x4, #5
	add	x5, x0, x8
	add	x6, x1, #0x400
	ldp	q0, q1, [x6]
	add	x7, x5, #0
	stp	q0, q1, [x7]
	add	x7, x1, #0x420
	ldp	q0, q1, [x7]
	add	x6, x1, #0x400
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x6, x1, #0x420
	ldp	q0, q1, [x6]
	add	x7, x5, #0xe0
	stp	q0, q1, [x7]
	add	x7, x1, #0x460
	ldp	q0, q1, [x7]
	add	x6, x1, #0x420
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x460
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x440
	ldp	q0, q1, [x7]
	add	x6, x1, #0x460
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x6, x1, #0x440
	ldp	q0, q1, [x6]
	add	x7, x5, #0x1c0
	stp	q0, q1, [x7]
	add	x7, x1, #0x4c0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x440
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x4c0
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x4e0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x4c0
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0xe0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x4e0
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x4a0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x4e0
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x4a0
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x480
	ldp	q0, q1, [x7]
	add	x6, x1, #0x4a0
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x6, x1, #0x480
	ldp	q0, q1, [x6]
	add	x7, x5, #0x2a0
	stp	q0, q1, [x7]
	add	x7, x1, #0x580
	ldp	q0, q1, [x7]
	add	x6, x1, #0x480
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x580
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x5a0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x580
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0xe0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x5a0
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x5e0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x5a0
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x5e0
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x5c0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x5e0
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0x1c0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x5c0
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x540
	ldp	q0, q1, [x7]
	add	x6, x1, #0x5c0
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x540
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x560
	ldp	q0, q1, [x7]
	add	x6, x1, #0x540
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0xe0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x560
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x520
	ldp	q0, q1, [x7]
	add	x6, x1, #0x560
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x520
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x500
	ldp	q0, q1, [x7]
	add	x6, x1, #0x520
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x6, x1, #0x500
	ldp	q0, q1, [x6]
	add	x7, x5, #0x380
	stp	q0, q1, [x7]
	add	x7, x1, #0x700
	ldp	q0, q1, [x7]
	add	x6, x1, #0x500
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x700
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x720
	ldp	q0, q1, [x7]
	add	x6, x1, #0x700
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0xe0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x720
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x760
	ldp	q0, q1, [x7]
	add	x6, x1, #0x720
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x760
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x740
	ldp	q0, q1, [x7]
	add	x6, x1, #0x760
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0x1c0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x740
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x7c0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x740
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x7c0
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x7e0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x7c0
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0xe0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x7e0
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x7a0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x7e0
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x7a0
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x780
	ldp	q0, q1, [x7]
	add	x6, x1, #0x7a0
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0x2a0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x780
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x680
	ldp	q0, q1, [x7]
	add	x6, x1, #0x780
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x680
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x6a0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x680
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0xe0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x6a0
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x6e0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x6a0
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x6e0
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x6c0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x6e0
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0x1c0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x6c0
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x640
	ldp	q0, q1, [x7]
	add	x6, x1, #0x6c0
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x640
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x660
	ldp	q0, q1, [x7]
	add	x6, x1, #0x640
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0xe0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x660
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x620
	ldp	q0, q1, [x7]
	add	x6, x1, #0x660
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x620
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x600
	ldp	q0, q1, [x7]
	add	x6, x1, #0x620
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x6, x1, #0x600
	ldp	q0, q1, [x6]
	add	x7, x5, #0x460
	stp	q0, q1, [x7]
	add	x7, x1, #0x200
	ldp	q0, q1, [x7]
	add	x6, x1, #0x600
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x200
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x220
	ldp	q0, q1, [x7]
	add	x6, x1, #0x200
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0xe0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x220
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x260
	ldp	q0, q1, [x7]
	add	x6, x1, #0x220
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x260
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x240
	ldp	q0, q1, [x7]
	add	x6, x1, #0x260
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0x1c0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x240
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x2c0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x240
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x2c0
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x2e0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x2c0
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0xe0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x2e0
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x2a0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x2e0
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x2a0
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x280
	ldp	q0, q1, [x7]
	add	x6, x1, #0x2a0
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0x2a0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x280
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x380
	ldp	q0, q1, [x7]
	add	x6, x1, #0x280
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x380
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x3a0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x380
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0xe0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x3a0
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x3e0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x3a0
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x3e0
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x3c0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x3e0
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0x1c0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x3c0
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x340
	ldp	q0, q1, [x7]
	add	x6, x1, #0x3c0
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x340
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x360
	ldp	q0, q1, [x7]
	add	x6, x1, #0x340
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0xe0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x360
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x320
	ldp	q0, q1, [x7]
	add	x6, x1, #0x360
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x320
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x300
	ldp	q0, q1, [x7]
	add	x6, x1, #0x320
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0x380
	ldp	q0, q1, [x7]
	add	x6, x1, #0x300
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x100
	ldp	q0, q1, [x7]
	add	x6, x1, #0x300
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x100
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x120
	ldp	q0, q1, [x7]
	add	x6, x1, #0x100
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0xe0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x120
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x160
	ldp	q0, q1, [x7]
	add	x6, x1, #0x120
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x160
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x140
	ldp	q0, q1, [x7]
	add	x6, x1, #0x160
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0x1c0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x140
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x1c0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x140
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x1c0
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x1e0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x1c0
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0xe0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x1e0
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x1a0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x1e0
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x1a0
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x180
	ldp	q0, q1, [x7]
	add	x6, x1, #0x1a0
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0x2a0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x180
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x80
	ldp	q0, q1, [x7]
	add	x6, x1, #0x180
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x80
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0xa0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x80
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0xe0
	ldp	q0, q1, [x7]
	add	x6, x1, #0xa0
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0xe0
	ldp	q0, q1, [x7]
	add	x6, x1, #0xa0
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0
	ldp	q0, q1, [x7]
	add	x6, x1, #0xe0
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0xc0
	ldp	q0, q1, [x7]
	add	x6, x1, #0xe0
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0x1c0
	ldp	q0, q1, [x7]
	add	x6, x1, #0xc0
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x40
	ldp	q0, q1, [x7]
	add	x6, x1, #0xc0
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x40
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #0x60
	ldp	q0, q1, [x7]
	add	x6, x1, #0x40
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0xe0
	ldp	q0, q1, [x7]
	add	x6, x1, #0x60
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x1, #32
	ldp	q0, q1, [x7]
	add	x6, x1, #0x60
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	add	x7, x5, #0
	ldp	q0, q1, [x7]
	add	x6, x1, #32
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x7]
	ldp	q0, q1, [x1]
	add	x6, x1, #32
	ldp	q2, q3, [x6]
	eor	v0.16b, v0.16b, v2.16b
	eor	v1.16b, v1.16b, v3.16b
	lsl	x8, x3, #5
	add	x7, x2, x8
	str	q0, [x7]
	cmp	w3, #12
	beq	L_mc_btrn_nh
	add	x7, x7, #32
	str	q1, [x7]
L_mc_btrn_nh:
	ret
#ifndef __APPLE__
	.size	wc_mceliece_aff_btr_net_neon,.-wc_mceliece_aff_btr_net_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_aff_butterflies_tr_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_aff_butterflies_tr_neon)
.type	wc_mceliece_aff_butterflies_tr_neon,@function
.align	2
wc_mceliece_aff_butterflies_tr_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_aff_butterflies_tr_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_aff_butterflies_tr_neon)
.p2align	2
_wc_mceliece_aff_butterflies_tr_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-64]!
	add	x29, sp, #0
	stp	x19, x20, [x29, #16]
	stp	x21, x22, [x29, #32]
	stp	x23, x24, [x29, #48]
#ifndef __APPLE__
	adrp x3, L_mc_aff_consts_neon
	add  x3, x3, :lo12:L_mc_aff_consts_neon
#else
	adrp x3, L_mc_aff_consts_neon@PAGE
	add  x3, x3, L_mc_aff_consts_neon@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x4, L_mc_aff_reversal_neon
	add  x4, x4, :lo12:L_mc_aff_reversal_neon
#else
	adrp x4, L_mc_aff_reversal_neon@PAGE
	add  x4, x4, L_mc_aff_reversal_neon@PAGEOFF
#endif /* __APPLE__ */
	mov	x19, x0
	mov	x20, x1
	mov	x21, x2
	mov	x22, x3
	mov	x23, x4
	mov	x5, #0
	add	x0, x20, x5
	mov	x5, #0x1a00
	add	x1, x20, x5
	mov	x5, #0x1ba0
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x1a0
	add	x0, x20, x5
	mov	x5, #0x1ba0
	add	x1, x20, x5
	mov	x5, #0x1d40
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x340
	add	x0, x20, x5
	mov	x5, #0x1d40
	add	x1, x20, x5
	mov	x5, #0x1ee0
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x4e0
	add	x0, x20, x5
	mov	x5, #0x1ee0
	add	x1, x20, x5
	mov	x5, #0x2080
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x680
	add	x0, x20, x5
	mov	x5, #0x2080
	add	x1, x20, x5
	mov	x5, #0x2220
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x820
	add	x0, x20, x5
	mov	x5, #0x2220
	add	x1, x20, x5
	mov	x5, #0x23c0
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x9c0
	add	x0, x20, x5
	mov	x5, #0x23c0
	add	x1, x20, x5
	mov	x5, #0x2560
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0xb60
	add	x0, x20, x5
	mov	x5, #0x2560
	add	x1, x20, x5
	mov	x5, #0x2700
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0xd00
	add	x0, x20, x5
	mov	x5, #0x2700
	add	x1, x20, x5
	mov	x5, #0x28a0
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0xea0
	add	x0, x20, x5
	mov	x5, #0x28a0
	add	x1, x20, x5
	mov	x5, #0x2a40
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x1040
	add	x0, x20, x5
	mov	x5, #0x2a40
	add	x1, x20, x5
	mov	x5, #0x2be0
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x11e0
	add	x0, x20, x5
	mov	x5, #0x2be0
	add	x1, x20, x5
	mov	x5, #0x2d80
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x1380
	add	x0, x20, x5
	mov	x5, #0x2d80
	add	x1, x20, x5
	mov	x5, #0x2f20
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x1520
	add	x0, x20, x5
	mov	x5, #0x2f20
	add	x1, x20, x5
	mov	x5, #0x30c0
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x16c0
	add	x0, x20, x5
	mov	x5, #0x30c0
	add	x1, x20, x5
	mov	x5, #0x3260
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x1860
	add	x0, x20, x5
	mov	x5, #0x3260
	add	x1, x20, x5
	mov	x5, #0x3400
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0
	add	x0, x20, x5
	mov	x5, #0xd00
	add	x1, x20, x5
	mov	x5, #0xea0
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x1a0
	add	x0, x20, x5
	mov	x5, #0xea0
	add	x1, x20, x5
	mov	x5, #0x1040
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x340
	add	x0, x20, x5
	mov	x5, #0x1040
	add	x1, x20, x5
	mov	x5, #0x11e0
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x4e0
	add	x0, x20, x5
	mov	x5, #0x11e0
	add	x1, x20, x5
	mov	x5, #0x1380
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x680
	add	x0, x20, x5
	mov	x5, #0x1380
	add	x1, x20, x5
	mov	x5, #0x1520
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x820
	add	x0, x20, x5
	mov	x5, #0x1520
	add	x1, x20, x5
	mov	x5, #0x16c0
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x9c0
	add	x0, x20, x5
	mov	x5, #0x16c0
	add	x1, x20, x5
	mov	x5, #0x1860
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0xb60
	add	x0, x20, x5
	mov	x5, #0x1860
	add	x1, x20, x5
	mov	x5, #0x1a00
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x1a00
	add	x0, x20, x5
	mov	x5, #0x2700
	add	x1, x20, x5
	mov	x5, #0xea0
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x1ba0
	add	x0, x20, x5
	mov	x5, #0x28a0
	add	x1, x20, x5
	mov	x5, #0x1040
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x1d40
	add	x0, x20, x5
	mov	x5, #0x2a40
	add	x1, x20, x5
	mov	x5, #0x11e0
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x1ee0
	add	x0, x20, x5
	mov	x5, #0x2be0
	add	x1, x20, x5
	mov	x5, #0x1380
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x2080
	add	x0, x20, x5
	mov	x5, #0x2d80
	add	x1, x20, x5
	mov	x5, #0x1520
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x2220
	add	x0, x20, x5
	mov	x5, #0x2f20
	add	x1, x20, x5
	mov	x5, #0x16c0
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x23c0
	add	x0, x20, x5
	mov	x5, #0x30c0
	add	x1, x20, x5
	mov	x5, #0x1860
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x2560
	add	x0, x20, x5
	mov	x5, #0x3260
	add	x1, x20, x5
	mov	x5, #0x1a00
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0
	add	x0, x20, x5
	mov	x5, #0x680
	add	x1, x20, x5
	mov	x5, #0x820
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x1a0
	add	x0, x20, x5
	mov	x5, #0x820
	add	x1, x20, x5
	mov	x5, #0x9c0
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x340
	add	x0, x20, x5
	mov	x5, #0x9c0
	add	x1, x20, x5
	mov	x5, #0xb60
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x4e0
	add	x0, x20, x5
	mov	x5, #0xb60
	add	x1, x20, x5
	mov	x5, #0xd00
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0xd00
	add	x0, x20, x5
	mov	x5, #0x1380
	add	x1, x20, x5
	mov	x5, #0x820
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0xea0
	add	x0, x20, x5
	mov	x5, #0x1520
	add	x1, x20, x5
	mov	x5, #0x9c0
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x1040
	add	x0, x20, x5
	mov	x5, #0x16c0
	add	x1, x20, x5
	mov	x5, #0xb60
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x11e0
	add	x0, x20, x5
	mov	x5, #0x1860
	add	x1, x20, x5
	mov	x5, #0xd00
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x1a00
	add	x0, x20, x5
	mov	x5, #0x2080
	add	x1, x20, x5
	mov	x5, #0x820
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x1ba0
	add	x0, x20, x5
	mov	x5, #0x2220
	add	x1, x20, x5
	mov	x5, #0x9c0
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x1d40
	add	x0, x20, x5
	mov	x5, #0x23c0
	add	x1, x20, x5
	mov	x5, #0xb60
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x1ee0
	add	x0, x20, x5
	mov	x5, #0x2560
	add	x1, x20, x5
	mov	x5, #0xd00
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x2700
	add	x0, x20, x5
	mov	x5, #0x2d80
	add	x1, x20, x5
	mov	x5, #0x820
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x28a0
	add	x0, x20, x5
	mov	x5, #0x2f20
	add	x1, x20, x5
	mov	x5, #0x9c0
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x2a40
	add	x0, x20, x5
	mov	x5, #0x30c0
	add	x1, x20, x5
	mov	x5, #0xb60
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x2be0
	add	x0, x20, x5
	mov	x5, #0x3260
	add	x1, x20, x5
	mov	x5, #0xd00
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0
	add	x0, x20, x5
	mov	x5, #0x340
	add	x1, x20, x5
	mov	x5, #0x4e0
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x1a0
	add	x0, x20, x5
	mov	x5, #0x4e0
	add	x1, x20, x5
	mov	x5, #0x680
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x680
	add	x0, x20, x5
	mov	x5, #0x9c0
	add	x1, x20, x5
	mov	x5, #0x4e0
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x820
	add	x0, x20, x5
	mov	x5, #0xb60
	add	x1, x20, x5
	mov	x5, #0x680
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0xd00
	add	x0, x20, x5
	mov	x5, #0x1040
	add	x1, x20, x5
	mov	x5, #0x4e0
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0xea0
	add	x0, x20, x5
	mov	x5, #0x11e0
	add	x1, x20, x5
	mov	x5, #0x680
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x1380
	add	x0, x20, x5
	mov	x5, #0x16c0
	add	x1, x20, x5
	mov	x5, #0x4e0
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x1520
	add	x0, x20, x5
	mov	x5, #0x1860
	add	x1, x20, x5
	mov	x5, #0x680
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x1a00
	add	x0, x20, x5
	mov	x5, #0x1d40
	add	x1, x20, x5
	mov	x5, #0x4e0
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x1ba0
	add	x0, x20, x5
	mov	x5, #0x1ee0
	add	x1, x20, x5
	mov	x5, #0x680
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x2080
	add	x0, x20, x5
	mov	x5, #0x23c0
	add	x1, x20, x5
	mov	x5, #0x4e0
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x2220
	add	x0, x20, x5
	mov	x5, #0x2560
	add	x1, x20, x5
	mov	x5, #0x680
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x2700
	add	x0, x20, x5
	mov	x5, #0x2a40
	add	x1, x20, x5
	mov	x5, #0x4e0
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x28a0
	add	x0, x20, x5
	mov	x5, #0x2be0
	add	x1, x20, x5
	mov	x5, #0x680
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x2d80
	add	x0, x20, x5
	mov	x5, #0x30c0
	add	x1, x20, x5
	mov	x5, #0x4e0
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x2f20
	add	x0, x20, x5
	mov	x5, #0x3260
	add	x1, x20, x5
	mov	x5, #0x680
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0
	add	x0, x20, x5
	mov	x5, #0x1a0
	add	x1, x20, x5
	mov	x5, #0x340
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x340
	add	x0, x20, x5
	mov	x5, #0x4e0
	add	x1, x20, x5
	mov	x5, #0x340
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x680
	add	x0, x20, x5
	mov	x5, #0x820
	add	x1, x20, x5
	mov	x5, #0x340
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x9c0
	add	x0, x20, x5
	mov	x5, #0xb60
	add	x1, x20, x5
	mov	x5, #0x340
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0xd00
	add	x0, x20, x5
	mov	x5, #0xea0
	add	x1, x20, x5
	mov	x5, #0x340
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x1040
	add	x0, x20, x5
	mov	x5, #0x11e0
	add	x1, x20, x5
	mov	x5, #0x340
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x1380
	add	x0, x20, x5
	mov	x5, #0x1520
	add	x1, x20, x5
	mov	x5, #0x340
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x16c0
	add	x0, x20, x5
	mov	x5, #0x1860
	add	x1, x20, x5
	mov	x5, #0x340
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x1a00
	add	x0, x20, x5
	mov	x5, #0x1ba0
	add	x1, x20, x5
	mov	x5, #0x340
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x1d40
	add	x0, x20, x5
	mov	x5, #0x1ee0
	add	x1, x20, x5
	mov	x5, #0x340
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x2080
	add	x0, x20, x5
	mov	x5, #0x2220
	add	x1, x20, x5
	mov	x5, #0x340
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x23c0
	add	x0, x20, x5
	mov	x5, #0x2560
	add	x1, x20, x5
	mov	x5, #0x340
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x2700
	add	x0, x20, x5
	mov	x5, #0x28a0
	add	x1, x20, x5
	mov	x5, #0x340
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x2a40
	add	x0, x20, x5
	mov	x5, #0x2be0
	add	x1, x20, x5
	mov	x5, #0x340
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x2d80
	add	x0, x20, x5
	mov	x5, #0x2f20
	add	x1, x20, x5
	mov	x5, #0x340
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x30c0
	add	x0, x20, x5
	mov	x5, #0x3260
	add	x1, x20, x5
	mov	x5, #0x340
	add	x2, x22, x5
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x24, #0
L_mc_btr_pk:
	cmp	x24, #32
	bge	L_mc_btr_pke
	mov	x5, #0x1a0
	mul	x8, x24, x5
	add	x0, x21, #0x610
	add	x1, x21, #0x7b0
	add	x2, x20, x8
	add	x3, x2, #0x1a0
#ifndef __APPLE__
	bl	wc_mceliece_aff_pack_lh_neon
#else
	bl	_wc_mceliece_aff_pack_lh_neon
#endif /* __APPLE__ */
	add	x0, x21, #0x610
	add	x1, x21, #0x7b0
	add	x2, x22, #0x1a0
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x1a0
	mul	x8, x24, x5
	add	x0, x20, x8
	add	x1, x0, #0x1a0
	add	x2, x21, #0x610
	add	x3, x21, #0x7b0
#ifndef __APPLE__
	bl	wc_mceliece_aff_pack_lh_neon
#else
	bl	_wc_mceliece_aff_pack_lh_neon
#endif /* __APPLE__ */
	mov	x5, #0x1a0
	mul	x8, x24, x5
	add	x0, x21, #0x610
	add	x1, x21, #0x7b0
	add	x2, x20, x8
	add	x3, x2, #0x1a0
#ifndef __APPLE__
	bl	wc_mceliece_aff_pack_lh2_neon
#else
	bl	_wc_mceliece_aff_pack_lh2_neon
#endif /* __APPLE__ */
	add	x0, x21, #0x610
	add	x1, x21, #0x7b0
	mov	x2, x22
	add	x3, x21, #0xe10
	add	x4, x21, #0xfb0
#ifndef __APPLE__
	bl	wc_mceliece_aff_ama_neon
#else
	bl	_wc_mceliece_aff_ama_neon
#endif /* __APPLE__ */
	mov	x5, #0x1a0
	mul	x8, x24, x5
	add	x0, x20, x8
	add	x1, x0, #0x1a0
	add	x2, x21, #0x610
	add	x3, x21, #0x7b0
#ifndef __APPLE__
	bl	wc_mceliece_aff_pack_lh2_neon
#else
	bl	_wc_mceliece_aff_pack_lh2_neon
#endif /* __APPLE__ */
	add	x24, x24, #2
	b	L_mc_btr_pk
L_mc_btr_pke:
	mov	x24, #0
L_mc_btr_i:
	cmp	x24, #13
	bge	L_mc_btr_ie
	add	x0, x21, #0x610
	mov	x1, x20
	mov	x2, x23
	mov	w3, w24
#ifndef __APPLE__
	bl	wc_mceliece_aff_btr_in_neon
#else
	bl	_wc_mceliece_aff_btr_in_neon
#endif /* __APPLE__ */
	add	x0, x21, #0x610
#ifndef __APPLE__
	bl	wc_mceliece_aff_transpose_neon
#else
	bl	_wc_mceliece_aff_transpose_neon
#endif /* __APPLE__ */
	add	x0, x21, #0xd0
	add	x1, x21, #0x610
	mov	x2, x19
	mov	w3, w24
	lsr	x8, x24, #1
	mov	w4, w8
#ifndef __APPLE__
	bl	wc_mceliece_aff_btr_net_neon
#else
	bl	_wc_mceliece_aff_btr_net_neon
#endif /* __APPLE__ */
	add	x24, x24, #2
	b	L_mc_btr_i
L_mc_btr_ie:
	mov	x9, #0
	sub	x9, x9, #1
	mov	x10, #0
	add	x5, x21, #0
	str	x10, [x5]
	str	x10, [x5, #8]
	add	x5, x21, #16
	str	x9, [x5]
	str	x9, [x5, #8]
	add	x5, x21, #32
	str	x9, [x5]
	str	x9, [x5, #8]
	add	x5, x21, #48
	str	x9, [x5]
	str	x9, [x5, #8]
	add	x5, x21, #0x40
	str	x9, [x5]
	str	x9, [x5, #8]
	add	x5, x21, #0x50
	str	x9, [x5]
	str	x9, [x5, #8]
	add	x5, x21, #0x60
	str	x9, [x5]
	str	x9, [x5, #8]
	add	x5, x21, #0x70
	str	x10, [x5]
	str	x10, [x5, #8]
	add	x5, x21, #0x80
	str	x10, [x5]
	str	x10, [x5, #8]
	add	x5, x21, #0x90
	str	x10, [x5]
	str	x10, [x5, #8]
	add	x5, x21, #0xa0
	str	x9, [x5]
	str	x9, [x5, #8]
	add	x5, x21, #0xb0
	str	x10, [x5]
	str	x10, [x5, #8]
	add	x5, x21, #0xc0
	str	x9, [x5]
	str	x9, [x5, #8]
	mov	x0, x21
	add	x1, x21, #0xd0
	mov	x2, x21
	add	x3, x21, #0x610
#ifndef __APPLE__
	bl	wc_mceliece_aff_v128_mul_neon
#else
	bl	_wc_mceliece_aff_v128_mul_neon
#endif /* __APPLE__ */
	add	x5, x21, #0
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0
	str	x6, [x8, #16]
	str	x7, [x8, #24]
	add	x5, x21, #16
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #32
	str	x6, [x8, #16]
	str	x7, [x8, #24]
	add	x5, x21, #32
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0x40
	str	x6, [x8, #16]
	str	x7, [x8, #24]
	add	x5, x21, #48
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0x60
	str	x6, [x8, #16]
	str	x7, [x8, #24]
	add	x5, x21, #0x40
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0x80
	str	x6, [x8, #16]
	str	x7, [x8, #24]
	add	x5, x21, #0x50
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0xa0
	str	x6, [x8, #16]
	str	x7, [x8, #24]
	add	x5, x21, #0x60
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0xc0
	str	x6, [x8, #16]
	str	x7, [x8, #24]
	add	x5, x21, #0x70
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0xe0
	str	x6, [x8, #16]
	str	x7, [x8, #24]
	add	x5, x21, #0x80
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0x100
	str	x6, [x8, #16]
	str	x7, [x8, #24]
	add	x5, x21, #0x90
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0x120
	str	x6, [x8, #16]
	str	x7, [x8, #24]
	add	x5, x21, #0xa0
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0x140
	str	x6, [x8, #16]
	str	x7, [x8, #24]
	add	x5, x21, #0xb0
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0x160
	str	x6, [x8, #16]
	str	x7, [x8, #24]
	add	x5, x21, #0xc0
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0x180
	str	x6, [x8, #16]
	str	x7, [x8, #24]
	mov	x9, #0
	sub	x9, x9, #1
	mov	x10, #0
	add	x5, x21, #0
	str	x10, [x5]
	str	x10, [x5, #8]
	add	x5, x21, #16
	str	x9, [x5]
	str	x9, [x5, #8]
	add	x5, x21, #32
	str	x10, [x5]
	str	x10, [x5, #8]
	add	x5, x21, #48
	str	x9, [x5]
	str	x9, [x5, #8]
	add	x5, x21, #0x40
	str	x9, [x5]
	str	x9, [x5, #8]
	add	x5, x21, #0x50
	str	x9, [x5]
	str	x9, [x5, #8]
	add	x5, x21, #0x60
	str	x10, [x5]
	str	x10, [x5, #8]
	add	x5, x21, #0x70
	str	x9, [x5]
	str	x9, [x5, #8]
	add	x5, x21, #0x80
	str	x10, [x5]
	str	x10, [x5, #8]
	add	x5, x21, #0x90
	str	x10, [x5]
	str	x10, [x5, #8]
	add	x5, x21, #0xa0
	str	x9, [x5]
	str	x9, [x5, #8]
	add	x5, x21, #0xb0
	str	x10, [x5]
	str	x10, [x5, #8]
	add	x5, x21, #0xc0
	str	x9, [x5]
	str	x9, [x5, #8]
	mov	x0, x21
	add	x1, x21, #0x1b0
	mov	x2, x21
	add	x3, x21, #0x610
#ifndef __APPLE__
	bl	wc_mceliece_aff_v128_mul_neon
#else
	bl	_wc_mceliece_aff_v128_mul_neon
#endif /* __APPLE__ */
	add	x5, x21, #0
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #16
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #32
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #32
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0x40
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #48
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0x60
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #0x40
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0x80
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #0x50
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0xa0
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #0x60
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0xc0
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #0x70
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0xe0
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #0x80
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0x100
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #0x90
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0x120
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #0xa0
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0x140
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #0xb0
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0x160
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #0xc0
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0x180
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	mov	x9, #0
	sub	x9, x9, #1
	mov	x10, #0
	add	x5, x21, #0
	str	x9, [x5]
	str	x9, [x5, #8]
	add	x5, x21, #16
	str	x9, [x5]
	str	x9, [x5, #8]
	add	x5, x21, #32
	str	x9, [x5]
	str	x9, [x5, #8]
	add	x5, x21, #48
	str	x10, [x5]
	str	x10, [x5, #8]
	add	x5, x21, #0x40
	str	x9, [x5]
	str	x9, [x5, #8]
	add	x5, x21, #0x50
	str	x10, [x5]
	str	x10, [x5, #8]
	add	x5, x21, #0x60
	str	x10, [x5]
	str	x10, [x5, #8]
	add	x5, x21, #0x70
	str	x9, [x5]
	str	x9, [x5, #8]
	add	x5, x21, #0x80
	str	x9, [x5]
	str	x9, [x5, #8]
	add	x5, x21, #0x90
	str	x9, [x5]
	str	x9, [x5, #8]
	add	x5, x21, #0xa0
	str	x9, [x5]
	str	x9, [x5, #8]
	add	x5, x21, #0xb0
	str	x10, [x5]
	str	x10, [x5, #8]
	add	x5, x21, #0xc0
	str	x9, [x5]
	str	x9, [x5, #8]
	mov	x0, x21
	add	x1, x21, #0x290
	mov	x2, x21
	add	x3, x21, #0x610
#ifndef __APPLE__
	bl	wc_mceliece_aff_v128_mul_neon
#else
	bl	_wc_mceliece_aff_v128_mul_neon
#endif /* __APPLE__ */
	add	x5, x21, #0
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #16
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #32
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #32
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0x40
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #48
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0x60
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #0x40
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0x80
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #0x50
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0xa0
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #0x60
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0xc0
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #0x70
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0xe0
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #0x80
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0x100
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #0x90
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0x120
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #0xa0
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0x140
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #0xb0
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0x160
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #0xc0
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0x180
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	mov	x9, #0
	sub	x9, x9, #1
	mov	x10, #0
	add	x5, x21, #0
	str	x9, [x5]
	str	x9, [x5, #8]
	add	x5, x21, #16
	str	x10, [x5]
	str	x10, [x5, #8]
	add	x5, x21, #32
	str	x9, [x5]
	str	x9, [x5, #8]
	add	x5, x21, #48
	str	x9, [x5]
	str	x9, [x5, #8]
	add	x5, x21, #0x40
	str	x9, [x5]
	str	x9, [x5, #8]
	add	x5, x21, #0x50
	str	x10, [x5]
	str	x10, [x5, #8]
	add	x5, x21, #0x60
	str	x10, [x5]
	str	x10, [x5, #8]
	add	x5, x21, #0x70
	str	x10, [x5]
	str	x10, [x5, #8]
	add	x5, x21, #0x80
	str	x10, [x5]
	str	x10, [x5, #8]
	add	x5, x21, #0x90
	str	x9, [x5]
	str	x9, [x5, #8]
	add	x5, x21, #0xa0
	str	x10, [x5]
	str	x10, [x5, #8]
	add	x5, x21, #0xb0
	str	x9, [x5]
	str	x9, [x5, #8]
	add	x5, x21, #0xc0
	str	x9, [x5]
	str	x9, [x5, #8]
	mov	x0, x21
	add	x1, x21, #0x370
	mov	x2, x21
	add	x3, x21, #0x610
#ifndef __APPLE__
	bl	wc_mceliece_aff_v128_mul_neon
#else
	bl	_wc_mceliece_aff_v128_mul_neon
#endif /* __APPLE__ */
	add	x5, x21, #0
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #16
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #32
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #32
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0x40
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #48
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0x60
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #0x40
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0x80
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #0x50
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0xa0
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #0x60
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0xc0
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #0x70
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0xe0
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #0x80
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0x100
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #0x90
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0x120
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #0xa0
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0x140
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #0xb0
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0x160
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #0xc0
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0x180
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	mov	x9, #0
	sub	x9, x9, #1
	mov	x10, #0
	add	x5, x21, #0
	str	x9, [x5]
	str	x9, [x5, #8]
	add	x5, x21, #16
	str	x10, [x5]
	str	x10, [x5, #8]
	add	x5, x21, #32
	str	x10, [x5]
	str	x10, [x5, #8]
	add	x5, x21, #48
	str	x9, [x5]
	str	x9, [x5, #8]
	add	x5, x21, #0x40
	str	x10, [x5]
	str	x10, [x5, #8]
	add	x5, x21, #0x50
	str	x9, [x5]
	str	x9, [x5, #8]
	add	x5, x21, #0x60
	str	x10, [x5]
	str	x10, [x5, #8]
	add	x5, x21, #0x70
	str	x10, [x5]
	str	x10, [x5, #8]
	add	x5, x21, #0x80
	str	x9, [x5]
	str	x9, [x5, #8]
	add	x5, x21, #0x90
	str	x9, [x5]
	str	x9, [x5, #8]
	add	x5, x21, #0xa0
	str	x10, [x5]
	str	x10, [x5, #8]
	add	x5, x21, #0xb0
	str	x10, [x5]
	str	x10, [x5, #8]
	add	x5, x21, #0xc0
	str	x9, [x5]
	str	x9, [x5, #8]
	mov	x0, x21
	add	x1, x21, #0x450
	mov	x2, x21
	add	x3, x21, #0x610
#ifndef __APPLE__
	bl	wc_mceliece_aff_v128_mul_neon
#else
	bl	_wc_mceliece_aff_v128_mul_neon
#endif /* __APPLE__ */
	add	x5, x21, #0
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #16
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #32
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #32
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0x40
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #48
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0x60
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #0x40
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0x80
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #0x50
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0xa0
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #0x60
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0xc0
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #0x70
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0xe0
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #0x80
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0x100
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #0x90
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0x120
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #0xa0
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0x140
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #0xb0
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0x160
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #0xc0
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0x180
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	mov	x9, #0
	sub	x9, x9, #1
	mov	x10, #0
	add	x5, x21, #0
	str	x9, [x5]
	str	x9, [x5, #8]
	add	x5, x21, #16
	str	x9, [x5]
	str	x9, [x5, #8]
	add	x5, x21, #32
	str	x10, [x5]
	str	x10, [x5, #8]
	add	x5, x21, #48
	str	x10, [x5]
	str	x10, [x5, #8]
	add	x5, x21, #0x40
	str	x10, [x5]
	str	x10, [x5, #8]
	add	x5, x21, #0x50
	str	x9, [x5]
	str	x9, [x5, #8]
	add	x5, x21, #0x60
	str	x9, [x5]
	str	x9, [x5, #8]
	add	x5, x21, #0x70
	str	x10, [x5]
	str	x10, [x5, #8]
	add	x5, x21, #0x80
	str	x10, [x5]
	str	x10, [x5, #8]
	add	x5, x21, #0x90
	str	x9, [x5]
	str	x9, [x5, #8]
	add	x5, x21, #0xa0
	str	x10, [x5]
	str	x10, [x5, #8]
	add	x5, x21, #0xb0
	str	x9, [x5]
	str	x9, [x5, #8]
	add	x5, x21, #0xc0
	str	x9, [x5]
	str	x9, [x5, #8]
	mov	x0, x21
	add	x1, x21, #0x530
	mov	x2, x21
	add	x3, x21, #0x610
#ifndef __APPLE__
	bl	wc_mceliece_aff_v128_mul_neon
#else
	bl	_wc_mceliece_aff_v128_mul_neon
#endif /* __APPLE__ */
	add	x5, x21, #0
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #16
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #32
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #32
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0x40
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #48
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0x60
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #0x40
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0x80
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #0x50
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0xa0
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #0x60
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0xc0
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #0x70
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0xe0
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #0x80
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0x100
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #0x90
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0x120
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #0xa0
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0x140
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #0xb0
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0x160
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	add	x5, x21, #0xc0
	ldr	x6, [x5]
	ldr	x7, [x5, #8]
	add	x8, x19, #0x180
	ldr	x11, [x8, #16]
	eor	x11, x11, x6
	str	x11, [x8, #16]
	ldr	x12, [x8, #24]
	eor	x12, x12, x7
	str	x12, [x8, #24]
	ldp	x19, x20, [x29, #16]
	ldp	x21, x22, [x29, #32]
	ldp	x23, x24, [x29, #48]
	ldp	x29, x30, [sp], #0x40
	ret
#ifndef __APPLE__
	.size	wc_mceliece_aff_butterflies_tr_neon,.-wc_mceliece_aff_butterflies_tr_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_aff_pack_lh2_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_aff_pack_lh2_neon)
.type	wc_mceliece_aff_pack_lh2_neon,@function
.align	2
wc_mceliece_aff_pack_lh2_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_aff_pack_lh2_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_aff_pack_lh2_neon)
.p2align	2
_wc_mceliece_aff_pack_lh2_neon:
#endif /* __APPLE__ */
	mov	x4, #0
L_mc_packlh2_p:
	lsl	x5, x4, #5
	add	x8, x2, x5
	ldp	q0, q1, [x8]
	add	x9, x3, x5
	ldp	q2, q3, [x9]
	zip1	v4.2d, v0.2d, v2.2d
	zip1	v5.2d, v1.2d, v3.2d
	add	x6, x0, x5
	stp	q4, q5, [x6]
	zip2	v4.2d, v0.2d, v2.2d
	zip2	v5.2d, v1.2d, v3.2d
	add	x7, x1, x5
	stp	q4, q5, [x7]
	add	x4, x4, #1
	cmp	x4, #13
	blt	L_mc_packlh2_p
	ret
#ifndef __APPLE__
	.size	wc_mceliece_aff_pack_lh2_neon,.-wc_mceliece_aff_pack_lh2_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_aff_radix_tr_step_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_aff_radix_tr_step_neon)
.type	wc_mceliece_aff_radix_tr_step_neon,@function
.align	2
wc_mceliece_aff_radix_tr_step_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_aff_radix_tr_step_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_aff_radix_tr_step_neon)
.p2align	2
_wc_mceliece_aff_radix_tr_step_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-32]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	mov	w4, w3
	eor	v8.16b, v8.16b, v8.16b
	mov	x13, #1
	mov	x5, x4
L_mc_rtr_k:
	cmp	x5, #4
	bgt	L_mc_rtr_ke
	lsl	x6, x13, x5
	dup	v6.2d, x6
	lsl	x8, x5, #3
	add	x10, x1, x8
	ldr	x11, [x10]
	dup	v4.2d, x11
	add	x10, x2, x8
	ldr	x12, [x10]
	dup	v5.2d, x12
	mov	x7, #0
L_mc_rtr_ki:
	cmp	x7, #13
	bge	L_mc_rtr_kie
	lsl	x8, x7, #5
	add	x9, x0, x8
	ldp	q0, q1, [x9]
	and	v2.16b, v0.16b, v4.16b
	ushl	v2.2d, v2.2d, v6.2d
	eor	v0.16b, v0.16b, v2.16b
	and	v3.16b, v1.16b, v4.16b
	ushl	v3.2d, v3.2d, v6.2d
	eor	v1.16b, v1.16b, v3.16b
	and	v2.16b, v0.16b, v5.16b
	ushl	v2.2d, v2.2d, v6.2d
	eor	v0.16b, v0.16b, v2.16b
	and	v3.16b, v1.16b, v5.16b
	ushl	v3.2d, v3.2d, v6.2d
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x9]
	add	x7, x7, #1
	b	L_mc_rtr_ki
L_mc_rtr_kie:
	add	x5, x5, #1
	b	L_mc_rtr_k
L_mc_rtr_ke:
	cmp	x4, #5
	bgt	L_mc_rtr_tsk
	mov	x7, #0
L_mc_rtr_t:
	cmp	x7, #13
	bge	L_mc_rtr_te
	lsl	x8, x7, #5
	add	x9, x0, x8
	ldp	q0, q1, [x9]
	ushr	v7.2d, v0.2d, #32
	zip1	v7.2d, v8.2d, v7.2d
	eor	v0.16b, v0.16b, v7.16b
	shl	v7.2d, v0.2d, #32
	zip2	v7.2d, v8.2d, v7.2d
	eor	v0.16b, v0.16b, v7.16b
	ushr	v7.2d, v1.2d, #32
	zip1	v7.2d, v8.2d, v7.2d
	eor	v1.16b, v1.16b, v7.16b
	shl	v7.2d, v1.2d, #32
	zip2	v7.2d, v8.2d, v7.2d
	eor	v1.16b, v1.16b, v7.16b
	stp	q0, q1, [x9]
	add	x7, x7, #1
	b	L_mc_rtr_t
L_mc_rtr_te:
L_mc_rtr_tsk:
	mov	x7, #0
L_mc_rtr_c:
	cmp	x7, #13
	bge	L_mc_rtr_ce
	lsl	x8, x7, #5
	add	x9, x0, x8
	ldp	q0, q1, [x9]
	zip2	v7.2d, v0.2d, v8.2d
	eor	v1.16b, v1.16b, v7.16b
	zip1	v7.2d, v8.2d, v1.2d
	eor	v1.16b, v1.16b, v7.16b
	stp	q0, q1, [x9]
	add	x7, x7, #1
	b	L_mc_rtr_c
L_mc_rtr_ce:
	ldp	d8, d9, [x29, #16]
	ldp	x29, x30, [sp], #32
	ret
#ifndef __APPLE__
	.size	wc_mceliece_aff_radix_tr_step_neon,.-wc_mceliece_aff_radix_tr_step_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_radix_conv_tr_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_radix_conv_tr_neon)
.type	wc_mceliece_radix_conv_tr_neon,@function
.align	2
wc_mceliece_radix_conv_tr_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_radix_conv_tr_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_radix_conv_tr_neon)
.p2align	2
_wc_mceliece_radix_conv_tr_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-48]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
#ifndef __APPLE__
	adrp x2, L_mc_aff_tmask0_neon
	add  x2, x2, :lo12:L_mc_aff_tmask0_neon
#else
	adrp x2, L_mc_aff_tmask0_neon@PAGE
	add  x2, x2, L_mc_aff_tmask0_neon@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x3, L_mc_aff_tmask1_neon
	add  x3, x3, :lo12:L_mc_aff_tmask1_neon
#else
	adrp x3, L_mc_aff_tmask1_neon@PAGE
	add  x3, x3, L_mc_aff_tmask1_neon@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x4, L_mc_aff_scal4x_neon
	add  x4, x4, :lo12:L_mc_aff_scal4x_neon
#else
	adrp x4, L_mc_aff_scal4x_neon@PAGE
	add  x4, x4, L_mc_aff_scal4x_neon@PAGEOFF
#endif /* __APPLE__ */
	mov	x5, #6
L_mc_rctr_j:
	cmp	x5, #0
	blt	L_mc_rctr_je
	cmp	x5, #6
	bge	L_mc_rctr_sk
	mov	x6, #0x1a0
	mul	x6, x5, x6
	add	x6, x4, x6
	eor	v10.16b, v10.16b, v10.16b
	mov	x14, x1
	mov	x9, #0
L_mc_v256_z_rt:
	stp	q10, q10, [x14]
	add	x14, x14, #32
	add	x9, x9, #1
	cmp	x9, #25
	blt	L_mc_v256_z_rt
	mov	x7, #0
L_mc_v256_i_rt:
	cmp	x7, #13
	bge	L_mc_v256_rs_rt
	lsl	x15, x7, #5
	add	x10, x0, x15
	ldp	q0, q1, [x10]
	mov	x8, #0
L_mc_v256_j_rt:
	cmp	x8, #13
	bge	L_mc_v256_in_rt
	lsl	x15, x8, #5
	add	x11, x6, x15
	ldp	q2, q3, [x11]
	and	v4.16b, v0.16b, v2.16b
	and	v5.16b, v1.16b, v3.16b
	add	x15, x7, x8
	lsl	x15, x15, #5
	add	x12, x1, x15
	ldp	q6, q7, [x12]
	eor	v6.16b, v6.16b, v4.16b
	eor	v7.16b, v7.16b, v5.16b
	stp	q6, q7, [x12]
	add	x8, x8, #1
	b	L_mc_v256_j_rt
L_mc_v256_in_rt:
	add	x7, x7, #1
	b	L_mc_v256_i_rt
L_mc_v256_rs_rt:
	mov	x9, #24
L_mc_v256_rk_rt:
	cmp	x9, #13
	blt	L_mc_v256_copy_rt
	lsl	x15, x9, #5
	add	x12, x1, x15
	ldp	q6, q7, [x12]
	sub	x16, x9, #9
	lsl	x16, x16, #5
	add	x13, x1, x16
	ldp	q8, q9, [x13]
	eor	v8.16b, v8.16b, v6.16b
	eor	v9.16b, v9.16b, v7.16b
	stp	q8, q9, [x13]
	sub	x16, x9, #10
	lsl	x16, x16, #5
	add	x13, x1, x16
	ldp	q8, q9, [x13]
	eor	v8.16b, v8.16b, v6.16b
	eor	v9.16b, v9.16b, v7.16b
	stp	q8, q9, [x13]
	sub	x16, x9, #12
	lsl	x16, x16, #5
	add	x13, x1, x16
	ldp	q8, q9, [x13]
	eor	v8.16b, v8.16b, v6.16b
	eor	v9.16b, v9.16b, v7.16b
	stp	q8, q9, [x13]
	sub	x16, x9, #13
	lsl	x16, x16, #5
	add	x13, x1, x16
	ldp	q8, q9, [x13]
	eor	v8.16b, v8.16b, v6.16b
	eor	v9.16b, v9.16b, v7.16b
	stp	q8, q9, [x13]
	sub	x9, x9, #1
	b	L_mc_v256_rk_rt
L_mc_v256_copy_rt:
	mov	x9, #0
L_mc_v256_cp_rt:
	cmp	x9, #13
	bge	L_mc_v256_done_rt
	lsl	x15, x9, #5
	add	x12, x1, x15
	add	x13, x0, x15
	ldp	q6, q7, [x12]
	stp	q6, q7, [x13]
	add	x9, x9, #1
	b	L_mc_v256_cp_rt
L_mc_v256_done_rt:
L_mc_rctr_sk:
	eor	v8.16b, v8.16b, v8.16b
	mov	x15, #1
	mov	x7, x5
L_mc_rtr_k_rt:
	cmp	x7, #4
	bgt	L_mc_rtr_ke_rt
	lsl	x8, x15, x7
	dup	v6.2d, x8
	lsl	x10, x7, #3
	add	x12, x2, x10
	ldr	x13, [x12]
	dup	v4.2d, x13
	add	x12, x3, x10
	ldr	x14, [x12]
	dup	v5.2d, x14
	mov	x9, #0
L_mc_rtr_ki_rt:
	cmp	x9, #13
	bge	L_mc_rtr_kie_rt
	lsl	x10, x9, #5
	add	x11, x0, x10
	ldp	q0, q1, [x11]
	and	v2.16b, v0.16b, v4.16b
	ushl	v2.2d, v2.2d, v6.2d
	eor	v0.16b, v0.16b, v2.16b
	and	v3.16b, v1.16b, v4.16b
	ushl	v3.2d, v3.2d, v6.2d
	eor	v1.16b, v1.16b, v3.16b
	and	v2.16b, v0.16b, v5.16b
	ushl	v2.2d, v2.2d, v6.2d
	eor	v0.16b, v0.16b, v2.16b
	and	v3.16b, v1.16b, v5.16b
	ushl	v3.2d, v3.2d, v6.2d
	eor	v1.16b, v1.16b, v3.16b
	stp	q0, q1, [x11]
	add	x9, x9, #1
	b	L_mc_rtr_ki_rt
L_mc_rtr_kie_rt:
	add	x7, x7, #1
	b	L_mc_rtr_k_rt
L_mc_rtr_ke_rt:
	cmp	x5, #5
	bgt	L_mc_rtr_tsk_rt
	mov	x9, #0
L_mc_rtr_t_rt:
	cmp	x9, #13
	bge	L_mc_rtr_te_rt
	lsl	x10, x9, #5
	add	x11, x0, x10
	ldp	q0, q1, [x11]
	ushr	v7.2d, v0.2d, #32
	zip1	v7.2d, v8.2d, v7.2d
	eor	v0.16b, v0.16b, v7.16b
	shl	v7.2d, v0.2d, #32
	zip2	v7.2d, v8.2d, v7.2d
	eor	v0.16b, v0.16b, v7.16b
	ushr	v7.2d, v1.2d, #32
	zip1	v7.2d, v8.2d, v7.2d
	eor	v1.16b, v1.16b, v7.16b
	shl	v7.2d, v1.2d, #32
	zip2	v7.2d, v8.2d, v7.2d
	eor	v1.16b, v1.16b, v7.16b
	stp	q0, q1, [x11]
	add	x9, x9, #1
	b	L_mc_rtr_t_rt
L_mc_rtr_te_rt:
L_mc_rtr_tsk_rt:
	mov	x9, #0
L_mc_rtr_c_rt:
	cmp	x9, #13
	bge	L_mc_rtr_ce_rt
	lsl	x10, x9, #5
	add	x11, x0, x10
	ldp	q0, q1, [x11]
	zip2	v7.2d, v0.2d, v8.2d
	eor	v1.16b, v1.16b, v7.16b
	zip1	v7.2d, v8.2d, v1.2d
	eor	v1.16b, v1.16b, v7.16b
	stp	q0, q1, [x11]
	add	x9, x9, #1
	b	L_mc_rtr_c_rt
L_mc_rtr_ce_rt:
	sub	x5, x5, #1
	b	L_mc_rctr_j
L_mc_rctr_je:
	ldp	d8, d9, [x29, #16]
	ldp	d10, d11, [x29, #32]
	ldp	x29, x30, [sp], #48
	ret
#ifndef __APPLE__
	.size	wc_mceliece_radix_conv_tr_neon,.-wc_mceliece_radix_conv_tr_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_aff_btr_in_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_aff_btr_in_neon)
.type	wc_mceliece_aff_btr_in_neon,@function
.align	2
wc_mceliece_aff_btr_in_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_aff_btr_in_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_aff_btr_in_neon)
.p2align	2
_wc_mceliece_aff_btr_in_neon:
#endif /* __APPLE__ */
	mov	w4, w3
	mov	x13, #13
	mov	x5, #0
L_mc_bti_k:
	cmp	x5, #32
	bge	L_mc_bti_e
	lsl	x8, x5, #1
	add	x9, x2, x8
	ldrb	w6, [x9]
	add	x9, x9, #1
	ldrb	w7, [x9]
	lsl	x8, x6, #5
	add	x10, x0, x8
	lsl	x8, x7, #5
	add	x11, x0, x8
	madd	x8, x5, x13, x4
	lsl	x8, x8, #5
	add	x12, x1, x8
	ldp	q0, q1, [x12]
	str	q0, [x10]
	str	q1, [x11]
	cmp	x4, #12
	beq	L_mc_bti_no
	add	x12, x12, #32
	ldp	q2, q3, [x12]
	add	x9, x10, #16
	str	q2, [x9]
	add	x9, x11, #16
	str	q3, [x9]
L_mc_bti_no:
	add	x5, x5, #1
	b	L_mc_bti_k
L_mc_bti_e:
	ret
#ifndef __APPLE__
	.size	wc_mceliece_aff_btr_in_neon,.-wc_mceliece_aff_btr_in_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_aff_synd_mask_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_aff_synd_mask_neon)
.type	wc_mceliece_aff_synd_mask_neon,@function
.align	2
wc_mceliece_aff_synd_mask_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_aff_synd_mask_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_aff_synd_mask_neon)
.p2align	2
_wc_mceliece_aff_synd_mask_neon:
#endif /* __APPLE__ */
	mov	x9, #13
	mov	x3, #0
L_mc_sm_i:
	cmp	x3, #32
	bge	L_mc_sm_ie
	lsl	x5, x3, #5
	add	x6, x2, x5
	ldp	q0, q1, [x6]
	mov	x4, #0
L_mc_sm_k:
	cmp	x4, #13
	bge	L_mc_sm_ke
	madd	x5, x3, x9, x4
	lsl	x5, x5, #5
	add	x7, x1, x5
	ldp	q2, q3, [x7]
	and	v2.16b, v2.16b, v0.16b
	and	v3.16b, v3.16b, v1.16b
	add	x8, x0, x5
	stp	q2, q3, [x8]
	add	x4, x4, #1
	b	L_mc_sm_k
L_mc_sm_ke:
	add	x3, x3, #1
	b	L_mc_sm_i
L_mc_sm_ie:
	ret
#ifndef __APPLE__
	.size	wc_mceliece_aff_synd_mask_neon,.-wc_mceliece_aff_synd_mask_neon
#endif /* __APPLE__ */
#endif /* WOLFSSL_MCELIECE_NO_DECAPSULATE */
#endif /* WOLFSSL_MCELIECE_SMALL */
#endif /* !WOLFSSL_MCELIECE_NO_MAKE_KEY || !WOLFSSL_MCELIECE_NO_DECAPSULATE */
#ifndef WOLFSSL_MCELIECE_NO_MAKE_KEY
#ifndef WOLFSSL_MCELIECE_SMALL
#ifndef __APPLE__
.text
.globl	wc_mceliece_u64_minmax_vec_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_u64_minmax_vec_neon)
.type	wc_mceliece_u64_minmax_vec_neon,@function
.align	2
wc_mceliece_u64_minmax_vec_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_u64_minmax_vec_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_u64_minmax_vec_neon)
.p2align	2
_wc_mceliece_u64_minmax_vec_neon:
#endif /* __APPLE__ */
	mov	w4, w2
	lsr	x4, x4, #1
	lsl	x4, x4, #1
	mov	x3, #0
L_mc_mmv:
	cmp	x3, x4
	bge	L_mc_mmve
	ldr	q0, [x0]
	ldr	q1, [x1]
	sub	v2.2d, v1.2d, v0.2d
	sshr	v2.2d, v2.2d, #63
	eor	v3.16b, v0.16b, v1.16b
	and	v3.16b, v3.16b, v2.16b
	eor	v0.16b, v0.16b, v3.16b
	eor	v1.16b, v1.16b, v3.16b
	str	q0, [x0]
	str	q1, [x1]
	add	x0, x0, #16
	add	x1, x1, #16
	add	x3, x3, #2
	b	L_mc_mmv
L_mc_mmve:
L_mc_mmvt:
	cmp	w3, w2
	bge	L_mc_mmvte
	ldr	x7, [x0]
	ldr	x8, [x1]
	sub	x9, x8, x7
	lsr	x9, x9, #63
	neg	x9, x9
	eor	x10, x7, x8
	and	x10, x10, x9
	eor	x7, x7, x10
	eor	x8, x8, x10
	str	x7, [x0]
	str	x8, [x1]
	add	x0, x0, #8
	add	x1, x1, #8
	add	x3, x3, #1
	b	L_mc_mmvt
L_mc_mmvte:
	ret
#ifndef __APPLE__
	.size	wc_mceliece_u64_minmax_vec_neon,.-wc_mceliece_u64_minmax_vec_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_pk_gen_cswap_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_pk_gen_cswap_neon)
.type	wc_mceliece_pk_gen_cswap_neon,@function
.align	2
wc_mceliece_pk_gen_cswap_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_pk_gen_cswap_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_pk_gen_cswap_neon)
.p2align	2
_wc_mceliece_pk_gen_cswap_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-112]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #24]
	stp	x20, x21, [x29, #40]
	stp	x22, x23, [x29, #56]
	stp	x24, x25, [x29, #72]
	stp	x26, x27, [x29, #88]
	str	x28, [x29, #104]
	mov	w7, w4
	mov	w8, w3
	mov	w9, w6
	mov	w10, w2
	mov	w16, w5
	lsl	x16, x16, #3
	mul	x15, x10, x7
	lsl	x15, x15, #3
	add	x11, x0, x15
	lsl	x15, x10, #1
	add	x23, x1, x15
	ldrh	w22, [x23]
	add	x12, x10, #1
L_mc_pkc_kk:
	cmp	x12, x8
	bge	L_mc_pkc_kke
	mul	x15, x12, x7
	lsl	x15, x15, #3
	add	x13, x0, x15
	add	x28, x11, x16
	ldr	x21, [x28]
	lsr	x17, x21, x9
	and	x17, x17, #1
	add	x27, x13, x16
	ldr	x21, [x27]
	lsr	x19, x21, x9
	and	x19, x19, #1
	eor	x17, x17, #1
	and	x20, x19, x17
	neg	x20, x20
	dup	v6.2d, x20
	lsl	x15, x12, #1
	add	x24, x1, x15
	ldrh	w25, [x24]
	eor	x26, x22, x25
	and	x26, x26, x20
	eor	x22, x22, x26
	eor	x25, x25, x26
	strh	w25, [x24]
	mov	x14, #0
L_mc_pkc_c:
	cmp	x14, x7
	bge	L_mc_pkc_ce
	lsl	x15, x14, #3
	add	x28, x11, x15
	ldp	q0, q1, [x28]
	add	x27, x13, x15
	ldp	q2, q3, [x27]
	eor	v4.16b, v0.16b, v2.16b
	eor	v5.16b, v1.16b, v3.16b
	and	v4.16b, v4.16b, v6.16b
	and	v5.16b, v5.16b, v6.16b
	eor	v0.16b, v0.16b, v4.16b
	eor	v1.16b, v1.16b, v5.16b
	stp	q0, q1, [x28]
	eor	v2.16b, v2.16b, v4.16b
	eor	v3.16b, v3.16b, v5.16b
	stp	q2, q3, [x27]
	add	x14, x14, #4
	b	L_mc_pkc_c
L_mc_pkc_ce:
	add	x12, x12, #1
	b	L_mc_pkc_kk
L_mc_pkc_kke:
	strh	w22, [x23]
	ldp	x17, x19, [x29, #24]
	ldp	x20, x21, [x29, #40]
	ldp	x22, x23, [x29, #56]
	ldp	x24, x25, [x29, #72]
	ldp	x26, x27, [x29, #88]
	ldr	x28, [x29, #104]
	ldp	x29, x30, [sp], #0x70
	ret
#ifndef __APPLE__
	.size	wc_mceliece_pk_gen_cswap_neon,.-wc_mceliece_pk_gen_cswap_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_pk_gen_elim_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_pk_gen_elim_neon)
.type	wc_mceliece_pk_gen_elim_neon,@function
.align	2
wc_mceliece_pk_gen_elim_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_pk_gen_elim_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_pk_gen_elim_neon)
.p2align	2
_wc_mceliece_pk_gen_elim_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-64]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #16]
	stp	x20, x21, [x29, #32]
	stp	x22, x23, [x29, #48]
	mov	w6, w3
	mov	w7, w2
	mov	w8, w5
	mov	w9, w1
	mov	x21, #1
	mov	w15, w4
	lsl	x15, x15, #3
	mul	x14, x9, x6
	lsl	x14, x14, #3
	add	x10, x0, x14
	add	x11, x9, #1
L_mc_pke_kk:
	cmp	x11, x7
	bge	L_mc_pke_kke
	mul	x14, x11, x6
	lsl	x14, x14, #3
	add	x12, x0, x14
	add	x22, x12, x15
	ldr	x16, [x22]
	lsr	x17, x16, x8
	and	x17, x17, #1
	neg	x20, x17
	dup	v6.2d, x20
	lsl	x19, x21, x8
	and	x19, x16, x19
	mov	x13, #0
L_mc_pke_c:
	cmp	x13, x6
	bge	L_mc_pke_ce
	lsl	x14, x13, #3
	add	x23, x10, x14
	ldp	q2, q3, [x23]
	add	x22, x12, x14
	ldp	q0, q1, [x22]
	and	v4.16b, v2.16b, v6.16b
	and	v5.16b, v3.16b, v6.16b
	eor	v0.16b, v0.16b, v4.16b
	eor	v1.16b, v1.16b, v5.16b
	stp	q0, q1, [x22]
	add	x13, x13, #4
	b	L_mc_pke_c
L_mc_pke_ce:
	add	x22, x12, x15
	ldr	x16, [x22]
	orr	x16, x16, x19
	str	x16, [x22]
	add	x11, x11, #1
	b	L_mc_pke_kk
L_mc_pke_kke:
	ldp	x17, x19, [x29, #16]
	ldp	x20, x21, [x29, #32]
	ldp	x22, x23, [x29, #48]
	ldp	x29, x30, [sp], #0x40
	ret
#ifndef __APPLE__
	.size	wc_mceliece_pk_gen_elim_neon,.-wc_mceliece_pk_gen_elim_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_bs_pk_gen_reduce_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_bs_pk_gen_reduce_neon)
.type	wc_mceliece_bs_pk_gen_reduce_neon,@function
.align	2
wc_mceliece_bs_pk_gen_reduce_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_bs_pk_gen_reduce_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_bs_pk_gen_reduce_neon)
.p2align	2
_wc_mceliece_bs_pk_gen_reduce_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	x19, x20, [x29, #16]
	stp	x21, x22, [x29, #32]
	stp	x23, x24, [x29, #48]
	stp	x25, x26, [x29, #64]
	mov	x19, x0
	mov	x20, x1
	mov	w21, w2
	mov	w22, w3
	mov	w23, w4
	mov	x24, x5
	mov	x25, x6
	mov	x26, #0
L_mc_pgr_r:
	cmp	x26, x21
	bge	L_mc_pgr_re
	cbz	w23, L_mc_pgr_sk
	sub	x11, x21, #32
	cmp	x26, x11
	bne	L_mc_pgr_sk
	mov	x0, x19
	mov	w1, w22
	mov	w2, w21
	mov	x3, x24
	mov	x4, x25
#ifndef __APPLE__
	bl	wc_mceliece_bs_mov_columns_neon
#else
	bl	_wc_mceliece_bs_mov_columns_neon
#endif /* __APPLE__ */
	cmp	w0, #0
	bne	L_mc_pgr_f
L_mc_pgr_sk:
	lsr	x7, x26, #6
	and	x8, x26, #63
	mov	x0, x19
	mov	x1, x20
	mov	w2, w26
	mov	w3, w21
	mov	w4, w22
	mov	w5, w7
	mov	w6, w8
#ifndef __APPLE__
	bl	wc_mceliece_pk_gen_cswap_neon
#else
	bl	_wc_mceliece_pk_gen_cswap_neon
#endif /* __APPLE__ */
	lsr	x7, x26, #6
	and	x8, x26, #63
	mul	x9, x26, x22
	add	x9, x9, x7
	lsl	x9, x9, #3
	add	x10, x19, x9
	ldr	x11, [x10]
	lsr	x11, x11, x8
	and	x11, x11, #1
	cbz	x11, L_mc_pgr_f
	mov	x0, x19
	mov	w1, w26
	mov	w2, w21
	mov	w3, w22
	mov	w4, w7
	mov	w5, w8
#ifndef __APPLE__
	bl	wc_mceliece_pk_gen_elim_neon
#else
	bl	_wc_mceliece_pk_gen_elim_neon
#endif /* __APPLE__ */
	add	x26, x26, #1
	b	L_mc_pgr_r
L_mc_pgr_re:
	mov	w0, #0
	b	L_mc_pgr_e
L_mc_pgr_f:
	mov	w0, #0
	sub	w0, w0, #1
L_mc_pgr_e:
	ldp	x19, x20, [x29, #16]
	ldp	x21, x22, [x29, #32]
	ldp	x23, x24, [x29, #48]
	ldp	x25, x26, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
#ifndef __APPLE__
	.size	wc_mceliece_bs_pk_gen_reduce_neon,.-wc_mceliece_bs_pk_gen_reduce_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_bs_lu_fill_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_bs_lu_fill_neon)
.type	wc_mceliece_bs_lu_fill_neon,@function
.align	2
wc_mceliece_bs_lu_fill_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_bs_lu_fill_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_bs_lu_fill_neon)
.p2align	2
_wc_mceliece_bs_lu_fill_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-96]!
	add	x29, sp, #0
	stp	x19, x20, [x29, #16]
	stp	x21, x22, [x29, #32]
	stp	x23, x24, [x29, #48]
	stp	x25, x26, [x29, #64]
	stp	x27, x28, [x29, #80]
	mov	x19, x0
	mov	x20, x1
	mov	x21, x2
	mov	w23, w3
	mov	w24, w4
	mov	w25, w5
	mov	w26, w6
	mov	x22, x7
	mov	x27, #0
L_mc_luf_i:
	cmp	x27, x23
	bge	L_mc_luf_ie
	mov	x28, #0
L_mc_luf_j:
	cmp	x28, x25
	bge	L_mc_luf_je
	cbz	x27, L_mc_luf_nm
	mul	x8, x28, x24
	lsl	x8, x8, #2
	lsl	x8, x8, #3
	add	x0, x20, x8
	mov	x1, x0
	add	x2, x21, x8
	mov	x3, x22
#ifndef __APPLE__
	bl	wc_mceliece_aff_v256_mul_neon
#else
	bl	_wc_mceliece_aff_v256_mul_neon
#endif /* __APPLE__ */
L_mc_luf_nm:
	mul	x8, x27, x24
	mul	x8, x8, x26
	lsl	x13, x28, #2
	add	x8, x8, x13
	lsl	x8, x8, #3
	add	x9, x19, x8
	mul	x8, x28, x24
	lsl	x8, x8, #2
	lsl	x8, x8, #3
	add	x10, x20, x8
	lsl	x11, x26, #3
	mov	x12, x24
L_mc_luf_kk:
	ldp	q0, q1, [x10]
	stp	q0, q1, [x9]
	add	x10, x10, #32
	add	x9, x9, x11
	subs	x12, x12, #1
	bne	L_mc_luf_kk
	add	x28, x28, #1
	b	L_mc_luf_j
L_mc_luf_je:
	add	x27, x27, #1
	b	L_mc_luf_i
L_mc_luf_ie:
	ldp	x19, x20, [x29, #16]
	ldp	x21, x22, [x29, #32]
	ldp	x23, x24, [x29, #48]
	ldp	x25, x26, [x29, #64]
	ldp	x27, x28, [x29, #80]
	ldp	x29, x30, [sp], #0x60
	ret
#ifndef __APPLE__
	.size	wc_mceliece_bs_lu_fill_neon,.-wc_mceliece_bs_lu_fill_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_bs_par_fill_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_bs_par_fill_neon)
.type	wc_mceliece_bs_par_fill_neon,@function
.align	2
wc_mceliece_bs_par_fill_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_bs_par_fill_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_bs_par_fill_neon)
.p2align	2
_wc_mceliece_bs_par_fill_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-96]!
	add	x29, sp, #0
	stp	x19, x20, [x29, #16]
	stp	x21, x22, [x29, #32]
	stp	x23, x24, [x29, #48]
	stp	x25, x26, [x29, #64]
	stp	x27, x28, [x29, #80]
	mov	x19, x0
	mov	x20, x1
	mov	x21, x2
	mov	w23, w3
	mov	w24, w4
	mov	w25, w5
	mov	w26, w6
	mov	x22, x7
	mov	x27, #0
L_mc_prf_i:
	cmp	x27, x23
	bge	L_mc_prf_ie
	mov	x28, #0
L_mc_prf_b:
	cmp	x28, x25
	bge	L_mc_prf_be
	cmp	x28, x26
	bge	L_mc_prf_sk
	mul	x8, x28, x24
	lsl	x8, x8, #2
	lsl	x8, x8, #3
	cbz	x27, L_mc_prf_nm
	add	x0, x20, x8
	mov	x1, x0
	add	x2, x21, x8
	mov	x3, x22
#ifndef __APPLE__
	bl	wc_mceliece_aff_v256_mul_neon
#else
	bl	_wc_mceliece_aff_v256_mul_neon
#endif /* __APPLE__ */
L_mc_prf_nm:
	mul	x8, x28, x24
	lsl	x8, x8, #2
	lsl	x8, x8, #3
	add	x10, x20, x8
	lsl	x11, x25, #2
	mul	x8, x27, x24
	mul	x8, x8, x11
	lsl	x13, x28, #2
	add	x8, x8, x13
	lsl	x8, x8, #3
	add	x9, x19, x8
	lsl	x11, x11, #3
	mov	x12, x24
L_mc_prf_kk:
	ldp	q0, q1, [x10]
	stp	q0, q1, [x9]
	add	x10, x10, #32
	add	x9, x9, x11
	subs	x12, x12, #1
	bne	L_mc_prf_kk
L_mc_prf_sk:
	add	x28, x28, #1
	b	L_mc_prf_b
L_mc_prf_be:
	add	x27, x27, #1
	b	L_mc_prf_i
L_mc_prf_ie:
	ldp	x19, x20, [x29, #16]
	ldp	x21, x22, [x29, #32]
	ldp	x23, x24, [x29, #48]
	ldp	x25, x26, [x29, #64]
	ldp	x27, x28, [x29, #80]
	ldp	x29, x30, [sp], #0x60
	ret
#ifndef __APPLE__
	.size	wc_mceliece_bs_par_fill_neon,.-wc_mceliece_bs_par_fill_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_bs_tri_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_bs_tri_neon)
.type	wc_mceliece_bs_tri_neon,@function
.align	2
wc_mceliece_bs_tri_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_bs_tri_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_bs_tri_neon)
.p2align	2
_wc_mceliece_bs_tri_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-32]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #16]
	mov	w6, w3
	mov	w7, w5
	mov	w9, w4
	mov	w12, w2
	mul	x12, x12, x6
	lsl	x12, x12, #3
	add	x8, x0, x12
L_mc_tri_i:
	cmp	x9, x7
	bge	L_mc_tri_ie
	lsr	x13, x9, #6
	lsl	x13, x13, #3
	add	x17, x1, x13
	ldr	x15, [x17]
	and	x14, x9, #63
	lsr	x15, x15, x14
	and	x15, x15, #1
	neg	x16, x15
	dup	v3.2d, x16
	mul	x12, x9, x6
	lsl	x12, x12, #3
	add	x10, x0, x12
	mov	x11, #0
L_mc_tri_c:
	cmp	x11, x6
	bge	L_mc_tri_ce
	lsl	x12, x11, #3
	add	x17, x8, x12
	ldr	q0, [x17]
	add	x19, x10, x12
	ldr	q1, [x19]
	and	v2.16b, v1.16b, v3.16b
	eor	v0.16b, v0.16b, v2.16b
	str	q0, [x17]
	add	x11, x11, #2
	b	L_mc_tri_c
L_mc_tri_ce:
	add	x9, x9, #1
	b	L_mc_tri_i
L_mc_tri_ie:
	ldp	x17, x19, [x29, #16]
	ldp	x29, x30, [sp], #32
	ret
#ifndef __APPLE__
	.size	wc_mceliece_bs_tri_neon,.-wc_mceliece_bs_tri_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_bs_minmax_rows_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_bs_minmax_rows_neon)
.type	wc_mceliece_bs_minmax_rows_neon,@function
.align	2
wc_mceliece_bs_minmax_rows_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_bs_minmax_rows_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_bs_minmax_rows_neon)
.p2align	2
_wc_mceliece_bs_minmax_rows_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-48]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #16]
	stp	x20, x21, [x29, #32]
	mov	w5, w2
	lsl	x5, x5, #2
	mov	w6, w3
	mov	w7, w4
	lsl	x19, x6, #1
	add	x8, x0, x19
	ldrh	w10, [x8]
	lsl	x19, x7, #1
	add	x9, x0, x19
	ldrh	w11, [x9]
	sub	x12, x11, x10
	asr	x13, x12, #63
	dup	v6.2d, x13
	eor	x14, x10, x11
	and	x14, x14, x13
	eor	x10, x10, x14
	strh	w10, [x8]
	eor	x11, x11, x14
	strh	w11, [x9]
	mul	x19, x6, x5
	lsl	x19, x19, #3
	add	x15, x1, x19
	mul	x19, x7, x5
	lsl	x19, x19, #3
	add	x16, x1, x19
	mov	x17, #0
L_mc_mmr_c:
	cmp	x17, x5
	bge	L_mc_mmr_ce
	ldp	q0, q1, [x15]
	ldp	q2, q3, [x16]
	eor	v4.16b, v0.16b, v2.16b
	eor	v5.16b, v1.16b, v3.16b
	and	v4.16b, v4.16b, v6.16b
	and	v5.16b, v5.16b, v6.16b
	eor	v0.16b, v0.16b, v4.16b
	eor	v1.16b, v1.16b, v5.16b
	stp	q0, q1, [x15]
	eor	v2.16b, v2.16b, v4.16b
	eor	v3.16b, v3.16b, v5.16b
	stp	q2, q3, [x16]
	add	x15, x15, #32
	add	x16, x16, #32
	add	x17, x17, #4
	b	L_mc_mmr_c
L_mc_mmr_ce:
	ldp	x17, x19, [x29, #16]
	ldp	x20, x21, [x29, #32]
	ldp	x29, x30, [sp], #48
	ret
#ifndef __APPLE__
	.size	wc_mceliece_bs_minmax_rows_neon,.-wc_mceliece_bs_minmax_rows_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_bs_sort_rows_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_bs_sort_rows_neon)
.type	wc_mceliece_bs_sort_rows_neon,@function
.align	2
wc_mceliece_bs_sort_rows_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_bs_sort_rows_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_bs_sort_rows_neon)
.p2align	2
_wc_mceliece_bs_sort_rows_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-96]!
	add	x29, sp, #0
	stp	x19, x20, [x29, #16]
	stp	x21, x22, [x29, #32]
	stp	x23, x24, [x29, #48]
	stp	x25, x26, [x29, #64]
	stp	x27, x28, [x29, #80]
	mov	x19, x0
	mov	x20, x1
	mov	w21, w2
	mov	w22, w3
	mov	x23, #1
L_mc_srt_tw:
	mov	x7, #1
	lsl	x7, x7, x23
	cmp	x7, x22
	bge	L_mc_srt_twe
	add	x23, x23, #1
	b	L_mc_srt_tw
L_mc_srt_twe:
	sub	x24, x23, #1
L_mc_srt_j:
	cmp	x24, #0
	blt	L_mc_srt_je
	mov	x25, #1
	sub	x7, x23, #1
	lsl	x25, x25, x7
	mov	x26, #0
	mov	x5, #1
	lsl	x5, x5, x24
	mov	x27, x5
L_mc_srt_ps:
	mov	x28, #0
L_mc_srt_i:
	sub	x6, x22, x27
	cmp	x28, x6
	bge	L_mc_srt_ie
	mov	x5, #1
	lsl	x5, x5, x24
	and	x7, x28, x5
	cmp	x7, x26
	bne	L_mc_srt_sk
	mov	x0, x19
	mov	x1, x20
	mov	w2, w21
	mov	w3, w28
	add	x7, x28, x27
	mov	w4, w7
#ifndef __APPLE__
	bl	wc_mceliece_bs_minmax_rows_neon
#else
	bl	_wc_mceliece_bs_minmax_rows_neon
#endif /* __APPLE__ */
L_mc_srt_sk:
	add	x28, x28, #1
	b	L_mc_srt_i
L_mc_srt_ie:
	mov	x5, #1
	lsl	x5, x5, x24
	cmp	x25, x5
	beq	L_mc_srt_pse
	sub	x27, x25, x5
	lsr	x25, x25, #1
	mov	x26, x5
	b	L_mc_srt_ps
L_mc_srt_pse:
	sub	x24, x24, #1
	b	L_mc_srt_j
L_mc_srt_je:
	ldp	x19, x20, [x29, #16]
	ldp	x21, x22, [x29, #32]
	ldp	x23, x24, [x29, #48]
	ldp	x25, x26, [x29, #64]
	ldp	x27, x28, [x29, #80]
	ldp	x29, x30, [sp], #0x60
	ret
#ifndef __APPLE__
	.size	wc_mceliece_bs_sort_rows_neon,.-wc_mceliece_bs_sort_rows_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_bs_phase10_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_bs_phase10_neon)
.type	wc_mceliece_bs_phase10_neon,@function
.align	2
wc_mceliece_bs_phase10_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_bs_phase10_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_bs_phase10_neon)
.p2align	2
_wc_mceliece_bs_phase10_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-96]!
	add	x29, sp, #0
	stp	x19, x20, [x29, #16]
	stp	x21, x22, [x29, #32]
	stp	x23, x24, [x29, #48]
	stp	x25, x26, [x29, #64]
	stp	x27, x28, [x29, #80]
	mov	x19, x0
	ldr	x20, [x19, #72]
	ldr	x21, [x19, #32]
	ldr	x22, [x19, #96]
	ldr	x23, [x19, #144]
	ldr	x24, [x19, #168]
	ldr	x26, [x19, #184]
	add	x8, x23, #0xff
	lsr	x8, x8, #8
	lsl	x25, x8, #2
	mul	x13, x23, x26
	lsr	x9, x13, #3
	and	x10, x13, #7
	mov	x11, x22
	mov	x12, #0
	mov	x8, #0
L_mc_p10_zw:
	cmp	x8, x9
	bge	L_mc_p10_zwe
	str	x12, [x11]
	add	x11, x11, #8
	add	x8, x8, #1
	b	L_mc_p10_zw
L_mc_p10_zwe:
	mov	x8, #0
L_mc_p10_zb:
	cmp	x8, x10
	bge	L_mc_p10_zbe
	strb	w12, [x11]
	add	x11, x11, #1
	add	x8, x8, #1
	b	L_mc_p10_zb
L_mc_p10_zbe:
	ldr	x27, [x19, #176]
L_mc_p10_j:
	cmp	x27, x24
	bge	L_mc_p10_je
	mov	x8, #52
	mul	x8, x27, x8
	lsl	x8, x8, #3
	mov	x0, x20
	ldr	x10, [x19, #40]
	add	x1, x10, x8
	ldr	x10, [x19, #48]
	add	x2, x10, x8
	ldr	x10, [x19, #136]
	mov	w3, w10
	mov	w4, #13
	mov	w5, #7
	sub	x11, x24, x27
	mov	w6, w11
	ldr	x7, [x19, #104]
#ifndef __APPLE__
	bl	wc_mceliece_bs_par_fill_neon
#else
	bl	_wc_mceliece_bs_par_fill_neon
#endif /* __APPLE__ */
	ldr	x8, [x19, #80]
	ldr	x9, [x19, #88]
	mov	x10, #0
L_mc_p10_ic:
	cmp	x10, x23
	bge	L_mc_p10_ice
	ldrh	w11, [x9]
	strh	w11, [x8]
	add	x8, x8, #2
	add	x9, x9, #2
	add	x10, x10, #1
	b	L_mc_p10_ic
L_mc_p10_ice:
	ldr	x0, [x19, #80]
	mov	x1, x20
	mov	w2, #7
	mov	w3, w23
#ifndef __APPLE__
	bl	wc_mceliece_bs_sort_rows_neon
#else
	bl	_wc_mceliece_bs_sort_rows_neon
#endif /* __APPLE__ */
	sub	x28, x23, #1
L_mc_p10_l:
	cmp	x28, #0
	blt	L_mc_p10_le
	mov	x0, x20
	mul	x8, x28, x25
	lsl	x8, x8, #3
	add	x1, x21, x8
	mov	w2, w28
	mov	w3, #28
	mov	w4, #0
	mov	w5, w28
#ifndef __APPLE__
	bl	wc_mceliece_bs_tri_neon
#else
	bl	_wc_mceliece_bs_tri_neon
#endif /* __APPLE__ */
	sub	x28, x28, #1
	b	L_mc_p10_l
L_mc_p10_le:
	ldr	x8, [x19, #176]
	cmp	x27, x8
	bne	L_mc_p10_ove
	sub	x12, x25, #4
	mov	x10, #0
L_mc_p10_or:
	cmp	x10, x23
	bge	L_mc_p10_ore
	mul	x8, x10, x25
	add	x8, x8, x12
	lsl	x8, x8, #3
	add	x14, x21, x8
	mov	x8, #28
	mul	x8, x10, x8
	lsl	x8, x8, #3
	add	x15, x20, x8
	ldp	q0, q1, [x14]
	stp	q0, q1, [x15]
	add	x10, x10, #1
	b	L_mc_p10_or
L_mc_p10_ore:
L_mc_p10_ove:
	sub	x28, x23, #1
L_mc_p10_u:
	cmp	x28, #0
	blt	L_mc_p10_ue
	mov	x0, x20
	mul	x8, x28, x25
	lsl	x8, x8, #3
	add	x1, x21, x8
	mov	w2, w28
	mov	w3, #28
	add	x9, x28, #1
	mov	w4, w9
	mov	w5, w23
#ifndef __APPLE__
	bl	wc_mceliece_bs_tri_neon
#else
	bl	_wc_mceliece_bs_tri_neon
#endif /* __APPLE__ */
	sub	x28, x28, #1
	b	L_mc_p10_u
L_mc_p10_ue:
	mov	x12, #0
L_mc_p10_b:
	cmp	x12, #7
	bge	L_mc_p10_be
	add	x13, x27, x12
	cmp	x13, x24
	bge	L_mc_p10_bsk
	mov	x10, #0
L_mc_p10_br:
	cmp	x10, x23
	bge	L_mc_p10_bre
	mul	x8, x10, x26
	lsl	x9, x13, #5
	add	x8, x8, x9
	add	x15, x22, x8
	mov	x8, #28
	mul	x8, x10, x8
	lsl	x9, x12, #2
	add	x8, x8, x9
	lsl	x8, x8, #3
	add	x14, x20, x8
	ldp	q0, q1, [x14]
	stp	q0, q1, [x15]
	add	x10, x10, #1
	b	L_mc_p10_br
L_mc_p10_bre:
L_mc_p10_bsk:
	add	x12, x12, #1
	b	L_mc_p10_b
L_mc_p10_be:
	add	x27, x27, #7
	b	L_mc_p10_j
L_mc_p10_je:
	ldp	x19, x20, [x29, #16]
	ldp	x21, x22, [x29, #32]
	ldp	x23, x24, [x29, #48]
	ldp	x25, x26, [x29, #64]
	ldp	x27, x28, [x29, #80]
	ldp	x29, x30, [sp], #0x60
	ret
#ifndef __APPLE__
	.size	wc_mceliece_bs_phase10_neon,.-wc_mceliece_bs_phase10_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_bs_packbuf_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_bs_packbuf_neon)
.type	wc_mceliece_bs_packbuf_neon,@function
.align	2
wc_mceliece_bs_packbuf_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_bs_packbuf_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_bs_packbuf_neon)
.p2align	2
_wc_mceliece_bs_packbuf_neon:
#endif /* __APPLE__ */
	mov	w7, #0x1fff
	mov	w8, #0x2000
	mov	x3, #0
L_mc_pkb:
	ldr	w4, [x1]
	add	x1, x1, #4
	ldr	x5, [x2]
	add	x2, x2, #8
	and	x5, x5, x7
	lsl	x5, x5, #13
	lsl	x6, x4, #31
	orr	x6, x6, x5
	orr	x6, x6, x3
	str	x6, [x0]
	add	x0, x0, #8
	add	x3, x3, #1
	cmp	x3, x8
	blt	L_mc_pkb
	ret
#ifndef __APPLE__
	.size	wc_mceliece_bs_packbuf_neon,.-wc_mceliece_bs_packbuf_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_bs_dup_pi_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_bs_dup_pi_neon)
.type	wc_mceliece_bs_dup_pi_neon,@function
.align	2
wc_mceliece_bs_dup_pi_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_bs_dup_pi_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_bs_dup_pi_neon)
.p2align	2
_wc_mceliece_bs_dup_pi_neon:
#endif /* __APPLE__ */
	mov	w8, #0
	mov	w6, #0x2000
	mov	x2, x1
	ldr	x5, [x2]
	lsr	x5, x5, #31
	add	x2, x2, #8
	mov	x3, #1
L_mc_dup_c:
	ldr	x4, [x2]
	lsr	x4, x4, #31
	cmp	x4, x5
	beq	L_mc_dup_bad
	mov	x5, x4
	add	x2, x2, #8
	add	x3, x3, #1
	cmp	x3, x6
	blt	L_mc_dup_c
	mov	w7, #0x1fff
	mov	x2, x1
	mov	x3, #0
L_mc_dup_pi:
	ldr	x4, [x2]
	and	x4, x4, x7
	strh	w4, [x0]
	add	x0, x0, #2
	add	x2, x2, #8
	add	x3, x3, #1
	cmp	x3, x6
	blt	L_mc_dup_pi
	b	L_mc_dup_end
L_mc_dup_bad:
	mov	w8, #0
	sub	w8, w8, #1
L_mc_dup_end:
	mov	w0, w8
	ret
#ifndef __APPLE__
	.size	wc_mceliece_bs_dup_pi_neon,.-wc_mceliece_bs_dup_pi_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_bs_gload_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_bs_gload_neon)
.type	wc_mceliece_bs_gload_neon,@function
.align	2
wc_mceliece_bs_gload_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_bs_gload_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_bs_gload_neon)
.p2align	2
_wc_mceliece_bs_gload_neon:
#endif /* __APPLE__ */
	mov	w10, w3
	mov	w9, #0x1fff
	lsl	x5, x10, #1
	add	x5, x0, x5
	mov	w6, #1
	strh	w6, [x5]
	mov	x4, #0
	mov	x7, x0
L_mc_gld_ld:
	cmp	x4, x10
	bge	L_mc_gld_lde
	ldrh	w6, [x2]
	add	x2, x2, #2
	and	x6, x6, x9
	strh	w6, [x7]
	add	x7, x7, #2
	add	x4, x4, #1
	b	L_mc_gld_ld
L_mc_gld_lde:
	mov	x4, #0
	mov	x8, x1
L_mc_gld_f:
	cmp	x4, #0x80
	bge	L_mc_gld_fe
	cmp	x4, x10
	bgt	L_mc_gld_fz
	lsl	x5, x4, #1
	add	x5, x0, x5
	ldrh	w6, [x5]
	b	L_mc_gld_fs
L_mc_gld_fz:
	mov	w6, #0
L_mc_gld_fs:
	strh	w6, [x8]
	add	x8, x8, #2
	add	x4, x4, #1
	b	L_mc_gld_f
L_mc_gld_fe:
	ret
#ifndef __APPLE__
	.size	wc_mceliece_bs_gload_neon,.-wc_mceliece_bs_gload_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_cb_layer_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_cb_layer_neon)
.type	wc_mceliece_cb_layer_neon,@function
.align	2
wc_mceliece_cb_layer_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_cb_layer_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_cb_layer_neon)
.p2align	2
_wc_mceliece_cb_layer_neon:
#endif /* __APPLE__ */
	mov	w14, w3
	mov	w15, w2
	mov	x4, #1
	lsl	x4, x4, x15
	lsl	x5, x4, #1
	mov	x8, #0
	mov	x6, #0
L_mc_cbl_i:
	cmp	x6, x14
	bge	L_mc_cbl_end
	mov	x7, #0
L_mc_cbl_j:
	cmp	x7, x4
	bge	L_mc_cbl_ni
	lsr	x13, x8, #3
	add	x13, x1, x13
	ldrb	w13, [x13]
	and	x11, x8, #7
	lsr	x13, x13, x11
	and	x13, x13, #1
	neg	x13, x13
	add	x9, x6, x7
	lsl	x9, x9, #1
	add	x9, x0, x9
	add	x10, x9, x5
	ldrh	w11, [x9]
	ldrh	w12, [x10]
	eor	x11, x11, x12
	and	x11, x11, x13
	ldrh	w12, [x9]
	eor	x12, x12, x11
	strh	w12, [x9]
	ldrh	w12, [x10]
	eor	x12, x12, x11
	strh	w12, [x10]
	add	x8, x8, #1
	add	x7, x7, #1
	b	L_mc_cbl_j
L_mc_cbl_ni:
	add	x6, x6, x5
	b	L_mc_cbl_i
L_mc_cbl_end:
	ret
#ifndef __APPLE__
	.size	wc_mceliece_cb_layer_neon,.-wc_mceliece_cb_layer_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_bs_debitslice_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_bs_debitslice_neon)
.type	wc_mceliece_bs_debitslice_neon,@function
.align	2
wc_mceliece_bs_debitslice_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_bs_debitslice_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_bs_debitslice_neon)
.p2align	2
_wc_mceliece_bs_debitslice_neon:
#endif /* __APPLE__ */
	mov	x2, x1
	mov	x3, #0
L_mc_dbs_i:
	mov	x4, #0
L_mc_dbs_l:
	mov	x5, #0
L_mc_dbs_r:
	lsl	x7, x4, #3
	add	x7, x2, x7
	mov	x8, #0
	mov	x6, #0
L_mc_dbs_j:
	ldr	x9, [x7]
	lsr	x9, x9, x5
	and	x9, x9, #1
	lsl	x9, x9, x6
	orr	x8, x8, x9
	add	x7, x7, #32
	add	x6, x6, #1
	cmp	x6, #13
	blt	L_mc_dbs_j
	str	x8, [x0]
	add	x0, x0, #8
	add	x5, x5, #1
	cmp	x5, #0x40
	blt	L_mc_dbs_r
	add	x4, x4, #1
	cmp	x4, #4
	blt	L_mc_dbs_l
	add	x2, x2, #0x1a0
	add	x3, x3, #1
	cmp	x3, #32
	blt	L_mc_dbs_i
	ret
#ifndef __APPLE__
	.size	wc_mceliece_bs_debitslice_neon,.-wc_mceliece_bs_debitslice_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_bs_tobitslice2x_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_bs_tobitslice2x_neon)
.type	wc_mceliece_bs_tobitslice2x_neon,@function
.align	2
wc_mceliece_bs_tobitslice2x_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_bs_tobitslice2x_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_bs_tobitslice2x_neon)
.p2align	2
_wc_mceliece_bs_tobitslice2x_neon:
#endif /* __APPLE__ */
	mov	x3, #0
L_mc_tbs_i:
	mov	x4, #0
L_mc_tbs_j:
	mov	x5, #0
L_mc_tbs_k:
	lsl	x9, x3, #11
	add	x9, x2, x9
	lsl	x13, x5, #9
	add	x9, x9, x13
	mov	x6, #12
	sub	x6, x6, x4
	add	x7, x4, #13
	mov	x11, #0
	mov	x12, #0
	mov	x8, #0
L_mc_tbs_r:
	ldr	x10, [x9]
	add	x9, x9, #8
	lsr	x13, x10, x6
	and	x13, x13, #1
	lsl	x13, x13, x8
	orr	x11, x11, x13
	lsr	x14, x10, x7
	and	x14, x14, #1
	lsl	x14, x14, x8
	orr	x12, x12, x14
	add	x8, x8, #1
	cmp	x8, #0x40
	blt	L_mc_tbs_r
	str	x11, [x0]
	str	x12, [x1]
	add	x0, x0, #8
	add	x1, x1, #8
	add	x5, x5, #1
	cmp	x5, #4
	blt	L_mc_tbs_k
	add	x4, x4, #1
	cmp	x4, #13
	blt	L_mc_tbs_j
	add	x3, x3, #1
	cmp	x3, #32
	blt	L_mc_tbs_i
	ret
#ifndef __APPLE__
	.size	wc_mceliece_bs_tobitslice2x_neon,.-wc_mceliece_bs_tobitslice2x_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_bs_mov_columns_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_bs_mov_columns_neon)
.type	wc_mceliece_bs_mov_columns_neon,@function
.align	2
wc_mceliece_bs_mov_columns_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_bs_mov_columns_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_bs_mov_columns_neon)
.p2align	2
_wc_mceliece_bs_mov_columns_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-480]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #400]
	stp	x20, x21, [x29, #416]
	stp	x22, x23, [x29, #432]
	stp	x24, x25, [x29, #448]
	stp	x26, x27, [x29, #464]
	add	x11, x29, #16
	mov	w5, w1
	mov	w6, w2
	sub	x7, x6, #32
	and	x8, x7, #63
	mov	x9, #0x40
	sub	x9, x9, x8
	lsr	x10, x7, #6
	mul	x25, x7, x5
	add	x25, x25, x10
	lsl	x25, x25, #3
	add	x19, x0, x25
	mov	x12, #0
L_mc_mov_p1:
	cmp	x12, #32
	bge	L_mc_mov_p1e
	ldr	x20, [x19]
	ldr	x21, [x19, #8]
	lsr	x20, x20, x8
	lsl	x21, x21, x9
	orr	x20, x20, x21
	lsl	x25, x12, #3
	add	x25, x11, x25
	str	x20, [x25]
	lsl	x25, x5, #3
	add	x19, x19, x25
	add	x12, x12, #1
	b	L_mc_mov_p1
L_mc_mov_p1e:
	mov	x15, #0
	mov	x12, #0
L_mc_mov_p2:
	cmp	x12, #32
	bge	L_mc_mov_p2e
	lsl	x25, x12, #3
	add	x26, x11, x25
	ldr	x23, [x26]
	add	x13, x12, #1
L_mc_mov_or:
	cmp	x13, #32
	bge	L_mc_mov_ore
	lsl	x25, x13, #3
	add	x26, x11, x25
	ldr	x24, [x26]
	orr	x23, x23, x24
	add	x13, x13, #1
	b	L_mc_mov_or
L_mc_mov_ore:
	cbz	x23, L_mc_mov_fail
	rbit	x25, x23
	clz	x14, x25
	lsl	x25, x12, #2
	add	x26, x11, x25
	add	x26, x26, #0x100
	str	w14, [x26]
	mov	x25, #1
	lsl	x25, x25, x14
	orr	x15, x15, x25
	lsl	x25, x12, #3
	add	x17, x11, x25
	ldr	x16, [x17]
	add	x13, x12, #1
L_mc_mov_i1:
	cmp	x13, #32
	bge	L_mc_mov_i1e
	lsr	x25, x16, x14
	and	x25, x25, #1
	sub	x25, x25, #1
	lsl	x24, x13, #3
	add	x26, x11, x24
	ldr	x24, [x26]
	and	x24, x24, x25
	eor	x16, x16, x24
	add	x13, x13, #1
	b	L_mc_mov_i1
L_mc_mov_i1e:
	str	x16, [x17]
	add	x13, x12, #1
L_mc_mov_i2:
	cmp	x13, #32
	bge	L_mc_mov_i2e
	lsl	x24, x13, #3
	add	x26, x11, x24
	ldr	x20, [x26]
	lsr	x25, x20, x14
	and	x25, x25, #1
	neg	x25, x25
	and	x25, x16, x25
	eor	x20, x20, x25
	str	x20, [x26]
	add	x13, x13, #1
	b	L_mc_mov_i2
L_mc_mov_i2e:
	add	x12, x12, #1
	b	L_mc_mov_p2
L_mc_mov_p2e:
	str	x15, [x4]
	lsl	x25, x7, #1
	add	x19, x3, x25
	mov	x12, #0
L_mc_mov_p3i:
	cmp	x12, #32
	bge	L_mc_mov_p3ie
	lsl	x25, x12, #2
	add	x26, x11, x25
	add	x26, x26, #0x100
	ldr	w14, [x26]
	lsl	x25, x12, #1
	add	x17, x19, x25
	ldrh	w16, [x17]
	add	x13, x12, #1
L_mc_mov_p3j:
	cmp	x13, #0x40
	bge	L_mc_mov_p3je
	lsl	x25, x13, #1
	add	x26, x19, x25
	ldrh	w24, [x26]
	eor	x25, x16, x24
	cmp	x13, x14
	csetm	x20, eq
	and	x25, x25, x20
	eor	x16, x16, x25
	eor	x24, x24, x25
	strh	w24, [x26]
	add	x13, x13, #1
	b	L_mc_mov_p3j
L_mc_mov_p3je:
	strh	w16, [x17]
	add	x12, x12, #1
	b	L_mc_mov_p3i
L_mc_mov_p3ie:
	mov	x12, #0
L_mc_mov_p4:
	cmp	x12, x6
	bge	L_mc_mov_p4e
	mul	x25, x12, x5
	add	x25, x25, x10
	lsl	x25, x25, #3
	add	x19, x0, x25
	ldr	x20, [x19]
	ldr	x21, [x19, #8]
	lsr	x22, x20, x8
	lsl	x24, x21, x9
	orr	x22, x22, x24
	mov	x13, #0
L_mc_mov_p4j:
	cmp	x13, #32
	bge	L_mc_mov_p4je
	lsl	x25, x13, #2
	add	x26, x11, x25
	add	x26, x26, #0x100
	ldr	w14, [x26]
	lsr	x24, x22, x13
	lsr	x25, x22, x14
	eor	x24, x24, x25
	and	x24, x24, #1
	lsl	x25, x24, x14
	eor	x22, x22, x25
	lsl	x25, x24, x13
	eor	x22, x22, x25
	add	x13, x13, #1
	b	L_mc_mov_p4j
L_mc_mov_p4je:
	mov	x27, #1
	lsl	x27, x27, x8
	sub	x27, x27, #1
	and	x20, x20, x27
	lsl	x24, x22, x8
	orr	x20, x20, x24
	str	x20, [x19]
	mvn	x25, x27
	and	x21, x21, x25
	lsr	x24, x22, x9
	orr	x21, x21, x24
	str	x21, [x19, #8]
	add	x12, x12, #1
	b	L_mc_mov_p4
L_mc_mov_p4e:
	mov	w0, #0
	b	L_mc_mov_done
L_mc_mov_fail:
	str	x15, [x4]
	mov	w0, #0
	sub	w0, w0, #1
L_mc_mov_done:
	ldp	x17, x19, [x29, #400]
	ldp	x20, x21, [x29, #416]
	ldp	x22, x23, [x29, #432]
	ldp	x24, x25, [x29, #448]
	ldp	x26, x27, [x29, #464]
	ldp	x29, x30, [sp], #0x1e0
	ret
#ifndef __APPLE__
	.size	wc_mceliece_bs_mov_columns_neon,.-wc_mceliece_bs_mov_columns_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_i32_sort_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_i32_sort_neon)
.type	wc_mceliece_i32_sort_neon,@function
.align	2
wc_mceliece_i32_sort_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_i32_sort_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_i32_sort_neon)
.p2align	2
_wc_mceliece_i32_sort_neon:
#endif /* __APPLE__ */
	mov	w2, w1
	cmp	x2, #2
	blt	L_mc_is_ret
	mov	x3, #1
L_mc_is_top:
	sub	x8, x2, x3
	cmp	x3, x8
	bge	L_mc_is_tope
	lsl	x3, x3, #1
	b	L_mc_is_top
L_mc_is_tope:
	mov	x4, x3
L_mc_is_p:
	cbz	x4, L_mc_is_ret
	mov	x6, #0
L_mc_is_b:
	sub	x8, x2, x4
	cmp	x6, x8
	bge	L_mc_is_be
	add	x7, x6, x4
	cmp	x7, x8
	ble	L_mc_is_lim
	mov	x7, x8
L_mc_is_lim:
	mov	x5, x6
L_mc_is_i:
	cmp	x5, x7
	bge	L_mc_is_ie
	lsl	x9, x5, #2
	add	x9, x0, x9
	add	x8, x5, x4
	lsl	x10, x8, #2
	add	x10, x0, x10
	ldr	w11, [x9]
	ldr	w12, [x10]
	sub	w13, w11, w12
	asr	w14, w13, #31
	and	w13, w13, w14
	add	w14, w12, w13
	str	w14, [x9]
	sub	w14, w11, w13
	str	w14, [x10]
	add	x5, x5, #1
	b	L_mc_is_i
L_mc_is_ie:
	add	x6, x6, x4
	add	x6, x6, x4
	b	L_mc_is_b
L_mc_is_be:
	mov	x5, #0
	mov	x6, x3
L_mc_is_q:
	cmp	x6, x4
	ble	L_mc_is_qe
L_mc_is_iq:
	sub	x8, x2, x6
	cmp	x5, x8
	bge	L_mc_is_iqe
	and	x8, x5, x4
	cbnz	x8, L_mc_is_next
	mov	x7, x6
L_mc_is_r:
	cmp	x7, x4
	ble	L_mc_is_re
	add	x8, x5, x4
	lsl	x9, x8, #2
	add	x9, x0, x9
	add	x8, x5, x7
	lsl	x10, x8, #2
	add	x10, x0, x10
	ldr	w11, [x9]
	ldr	w12, [x10]
	sub	w13, w11, w12
	asr	w14, w13, #31
	and	w13, w13, w14
	add	w14, w12, w13
	str	w14, [x9]
	sub	w14, w11, w13
	str	w14, [x10]
	lsr	x7, x7, #1
	b	L_mc_is_r
L_mc_is_re:
L_mc_is_next:
	add	x5, x5, #1
	b	L_mc_is_iq
L_mc_is_iqe:
	lsr	x6, x6, #1
	b	L_mc_is_q
L_mc_is_qe:
	lsr	x4, x4, #1
	b	L_mc_is_p
L_mc_is_ret:
	ret
#ifndef __APPLE__
	.size	wc_mceliece_i32_sort_neon,.-wc_mceliece_i32_sort_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_cb_compose10_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_cb_compose10_neon)
.type	wc_mceliece_cb_compose10_neon,@function
.align	2
wc_mceliece_cb_compose10_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_cb_compose10_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_cb_compose10_neon)
.p2align	2
_wc_mceliece_cb_compose10_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-64]!
	add	x29, sp, #0
	stp	x19, x20, [x29, #24]
	stp	x21, x22, [x29, #40]
	str	x23, [x29, #56]
	mov	x19, x0
	mov	x20, x1
	mov	w21, w2
	mov	w22, w3
	mov	x5, x19
	mov	x6, x20
	mov	x4, #0
L_mc_c10_1:
	cmp	x4, x21
	bge	L_mc_c10_1e
	ldr	w7, [x5]
	and	w7, w7, #0xffff
	lsl	w7, w7, #10
	ldr	w8, [x6]
	and	w8, w8, #0x3ff
	orr	w7, w7, w8
	str	w7, [x6]
	add	x5, x5, #4
	add	x6, x6, #4
	add	x4, x4, #1
	b	L_mc_c10_1
L_mc_c10_1e:
	mov	x23, #1
L_mc_c10_i:
	sub	x7, x22, #1
	cmp	x23, x7
	bge	L_mc_c10_ie
	mov	x5, x19
	mov	x6, x20
	mov	x4, #0
L_mc_c10_a1:
	cmp	x4, x21
	bge	L_mc_c10_a1e
	ldr	w7, [x6]
	lsr	w7, w7, #10
	lsl	w7, w7, #10
	lsl	w7, w7, #6
	orr	w7, w7, w4
	str	w7, [x5]
	add	x5, x5, #4
	add	x6, x6, #4
	add	x4, x4, #1
	b	L_mc_c10_a1
L_mc_c10_a1e:
	mov	x0, x19
	mov	w1, w21
#ifndef __APPLE__
	bl	wc_mceliece_i32_sort_neon
#else
	bl	_wc_mceliece_i32_sort_neon
#endif /* __APPLE__ */
	mov	x5, x19
	mov	x6, x20
	mov	x4, #0
L_mc_c10_a2:
	cmp	x4, x21
	bge	L_mc_c10_a2e
	ldr	w7, [x5]
	lsl	w7, w7, #20
	ldr	w8, [x6]
	orr	w7, w7, w8
	str	w7, [x5]
	add	x5, x5, #4
	add	x6, x6, #4
	add	x4, x4, #1
	b	L_mc_c10_a2
L_mc_c10_a2e:
	mov	x0, x19
	mov	w1, w21
#ifndef __APPLE__
	bl	wc_mceliece_i32_sort_neon
#else
	bl	_wc_mceliece_i32_sort_neon
#endif /* __APPLE__ */
	mov	x5, x19
	mov	x6, x20
	mov	x4, #0
L_mc_c10_a3:
	cmp	x4, x21
	bge	L_mc_c10_a3e
	ldr	w7, [x5]
	and	w9, w7, #0xfffff
	and	w7, w7, #0xffc00
	ldr	w8, [x6]
	and	w8, w8, #0x3ff
	orr	w7, w7, w8
	eor	w8, w7, w9
	sub	w11, w9, w7
	eor	w10, w11, w9
	and	w10, w10, w8
	eor	w11, w11, w10
	asr	w11, w11, #31
	and	w11, w11, w8
	eor	w10, w7, w11
	str	w10, [x6]
	add	x5, x5, #4
	add	x6, x6, #4
	add	x4, x4, #1
	b	L_mc_c10_a3
L_mc_c10_a3e:
	add	x23, x23, #1
	b	L_mc_c10_i
L_mc_c10_ie:
	mov	x6, x20
	mov	x4, #0
L_mc_c10_f:
	cmp	x4, x21
	bge	L_mc_c10_fe
	ldr	w7, [x6]
	and	w7, w7, #0x3ff
	str	w7, [x6]
	add	x6, x6, #4
	add	x4, x4, #1
	b	L_mc_c10_f
L_mc_c10_fe:
	ldp	x19, x20, [x29, #24]
	ldp	x21, x22, [x29, #40]
	ldr	x23, [x29, #56]
	ldp	x29, x30, [sp], #0x40
	ret
#ifndef __APPLE__
	.size	wc_mceliece_cb_compose10_neon,.-wc_mceliece_cb_compose10_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_cb_compose16_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_cb_compose16_neon)
.type	wc_mceliece_cb_compose16_neon,@function
.align	2
wc_mceliece_cb_compose16_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_cb_compose16_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_cb_compose16_neon)
.p2align	2
_wc_mceliece_cb_compose16_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-64]!
	add	x29, sp, #0
	stp	x19, x20, [x29, #24]
	stp	x21, x22, [x29, #40]
	str	x23, [x29, #56]
	mov	x19, x0
	mov	x20, x1
	mov	w21, w2
	mov	w22, w3
	mov	x5, x19
	mov	x6, x20
	mov	x4, #0
L_mc_c16_1:
	cmp	x4, x21
	bge	L_mc_c16_1e
	ldr	w7, [x5]
	lsl	w7, w7, #16
	ldr	w8, [x6]
	and	w8, w8, #0xffff
	orr	w7, w7, w8
	str	w7, [x6]
	add	x5, x5, #4
	add	x6, x6, #4
	add	x4, x4, #1
	b	L_mc_c16_1
L_mc_c16_1e:
	mov	x23, #1
L_mc_c16_i:
	sub	x7, x22, #1
	cmp	x23, x7
	bge	L_mc_c16_ie
	mov	x5, x19
	mov	x6, x20
	mov	x4, #0
L_mc_c16_a1:
	cmp	x4, x21
	bge	L_mc_c16_a1e
	ldr	w7, [x6]
	lsr	w7, w7, #16
	lsl	w7, w7, #16
	orr	w7, w7, w4
	str	w7, [x5]
	add	x5, x5, #4
	add	x6, x6, #4
	add	x4, x4, #1
	b	L_mc_c16_a1
L_mc_c16_a1e:
	mov	x0, x19
	mov	w1, w21
#ifndef __APPLE__
	bl	wc_mceliece_i32_sort_neon
#else
	bl	_wc_mceliece_i32_sort_neon
#endif /* __APPLE__ */
	mov	x5, x19
	mov	x6, x20
	mov	x4, #0
L_mc_c16_a2:
	cmp	x4, x21
	bge	L_mc_c16_a2e
	ldr	w7, [x5]
	lsl	w7, w7, #16
	ldr	w8, [x6]
	and	w8, w8, #0xffff
	orr	w7, w7, w8
	str	w7, [x5]
	add	x5, x5, #4
	add	x6, x6, #4
	add	x4, x4, #1
	b	L_mc_c16_a2
L_mc_c16_a2e:
	sub	x7, x22, #2
	cmp	x23, x7
	bge	L_mc_c16_sk
	mov	x5, x19
	mov	x6, x20
	mov	x4, #0
L_mc_c16_b1:
	cmp	x4, x21
	bge	L_mc_c16_b1e
	ldr	w7, [x5]
	lsr	w7, w7, #16
	lsl	w7, w7, #16
	ldr	w8, [x6]
	asr	w8, w8, #16
	orr	w7, w7, w8
	str	w7, [x6]
	add	x5, x5, #4
	add	x6, x6, #4
	add	x4, x4, #1
	b	L_mc_c16_b1
L_mc_c16_b1e:
	mov	x0, x20
	mov	w1, w21
#ifndef __APPLE__
	bl	wc_mceliece_i32_sort_neon
#else
	bl	_wc_mceliece_i32_sort_neon
#endif /* __APPLE__ */
	mov	x5, x19
	mov	x6, x20
	mov	x4, #0
L_mc_c16_b2:
	cmp	x4, x21
	bge	L_mc_c16_b2e
	ldr	w7, [x6]
	lsl	w7, w7, #16
	ldr	w8, [x5]
	and	w8, w8, #0xffff
	orr	w7, w7, w8
	str	w7, [x6]
	add	x5, x5, #4
	add	x6, x6, #4
	add	x4, x4, #1
	b	L_mc_c16_b2
L_mc_c16_b2e:
L_mc_c16_sk:
	mov	x0, x19
	mov	w1, w21
#ifndef __APPLE__
	bl	wc_mceliece_i32_sort_neon
#else
	bl	_wc_mceliece_i32_sort_neon
#endif /* __APPLE__ */
	mov	x5, x19
	mov	x6, x20
	mov	x4, #0
L_mc_c16_a3:
	cmp	x4, x21
	bge	L_mc_c16_a3e
	ldr	w9, [x6]
	lsr	w7, w9, #16
	lsl	w7, w7, #16
	ldr	w8, [x5]
	and	w8, w8, #0xffff
	orr	w7, w7, w8
	eor	w8, w9, w7
	sub	w11, w7, w9
	eor	w10, w11, w7
	and	w10, w10, w8
	eor	w11, w11, w10
	asr	w11, w11, #31
	and	w11, w11, w8
	eor	w10, w9, w11
	str	w10, [x6]
	add	x5, x5, #4
	add	x6, x6, #4
	add	x4, x4, #1
	b	L_mc_c16_a3
L_mc_c16_a3e:
	add	x23, x23, #1
	b	L_mc_c16_i
L_mc_c16_ie:
	mov	x6, x20
	mov	x4, #0
L_mc_c16_f:
	cmp	x4, x21
	bge	L_mc_c16_fe
	ldr	w7, [x6]
	and	w7, w7, #0xffff
	str	w7, [x6]
	add	x6, x6, #4
	add	x4, x4, #1
	b	L_mc_c16_f
L_mc_c16_fe:
	ldp	x19, x20, [x29, #24]
	ldp	x21, x22, [x29, #40]
	ldr	x23, [x29, #56]
	ldp	x29, x30, [sp], #0x40
	ret
#ifndef __APPLE__
	.size	wc_mceliece_cb_compose16_neon,.-wc_mceliece_cb_compose16_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_cb_build_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_cb_build_neon)
.type	wc_mceliece_cb_build_neon,@function
.align	2
wc_mceliece_cb_build_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_cb_build_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_cb_build_neon)
.p2align	2
_wc_mceliece_cb_build_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-96]!
	add	x29, sp, #0
	stp	x19, x20, [x29, #24]
	stp	x21, x22, [x29, #40]
	stp	x23, x24, [x29, #56]
	stp	x25, x26, [x29, #72]
	str	x27, [x29, #88]
	mov	x19, x0
	mov	x20, x6
	mov	x21, x7
	str	x1, [x21]
	str	x2, [x21, #8]
	str	x3, [x21, #16]
	str	x4, [x21, #24]
	str	x5, [x21, #32]
	mov	x22, #1
L_cbb_w:
	cbz	x22, L_cbb_end
	sub	x22, x22, #1
	mov	x9, #40
	mul	x10, x22, x9
	add	x16, x21, x10
	ldr	x23, [x16]
	ldr	x24, [x16, #8]
	ldr	x25, [x16, #16]
	ldr	x26, [x16, #24]
	ldr	x27, [x16, #32]
	cmp	x26, #1
	bne	L_cbb_not1
	lsr	x9, x23, #3
	add	x9, x19, x9
	ldrb	w10, [x9]
	ldrh	w11, [x25]
	and	x12, x23, #7
	lsl	x11, x11, x12
	eor	x10, x10, x11
	strb	w10, [x9]
	b	L_cbb_w
L_cbb_not1:
	mov	x14, x20
	mov	x8, #0
L_cbb_s1:
	cmp	x8, x27
	bge	L_cbb_s1e
	lsl	x9, x8, #1
	add	x9, x25, x9
	ldrh	w10, [x9]
	eor	w11, w10, #1
	lsl	w11, w11, #16
	eor	x9, x8, #1
	lsl	x9, x9, #1
	add	x9, x25, x9
	ldrh	w9, [x9]
	orr	w11, w11, w9
	str	w11, [x14]
	add	x14, x14, #4
	add	x8, x8, #1
	b	L_cbb_s1
L_cbb_s1e:
	mov	x0, x20
	mov	w1, w27
#ifndef __APPLE__
	bl	wc_mceliece_i32_sort_neon
#else
	bl	_wc_mceliece_i32_sort_neon
#endif /* __APPLE__ */
	lsl	x9, x27, #2
	add	x15, x20, x9
	mov	x14, x20
	mov	x8, #0
L_cbb_s2:
	cmp	x8, x27
	bge	L_cbb_s2e
	ldr	w9, [x14]
	and	w9, w9, #0xffff
	eor	w11, w9, w8
	sub	w12, w8, w9
	eor	w10, w12, w8
	and	w10, w10, w11
	eor	w12, w12, w10
	asr	w12, w12, #31
	and	w12, w12, w11
	eor	w10, w9, w12
	lsl	w11, w9, #16
	orr	w11, w11, w10
	str	w11, [x15]
	add	x14, x14, #4
	add	x15, x15, #4
	add	x8, x8, #1
	b	L_cbb_s2
L_cbb_s2e:
	mov	x14, x20
	mov	x8, #0
L_cbb_s3:
	cmp	x8, x27
	bge	L_cbb_s3e
	ldr	w9, [x14]
	lsl	w9, w9, #16
	orr	w9, w9, w8
	str	w9, [x14]
	add	x14, x14, #4
	add	x8, x8, #1
	b	L_cbb_s3
L_cbb_s3e:
	mov	x0, x20
	mov	w1, w27
#ifndef __APPLE__
	bl	wc_mceliece_i32_sort_neon
#else
	bl	_wc_mceliece_i32_sort_neon
#endif /* __APPLE__ */
	lsl	x9, x27, #2
	add	x15, x20, x9
	mov	x14, x20
	mov	x8, #0
L_cbb_s4:
	cmp	x8, x27
	bge	L_cbb_s4e
	ldr	w9, [x14]
	lsl	w9, w9, #16
	ldr	w10, [x15]
	asr	w10, w10, #16
	add	w9, w9, w10
	str	w9, [x14]
	add	x14, x14, #4
	add	x15, x15, #4
	add	x8, x8, #1
	b	L_cbb_s4
L_cbb_s4e:
	mov	x0, x20
	mov	w1, w27
#ifndef __APPLE__
	bl	wc_mceliece_i32_sort_neon
#else
	bl	_wc_mceliece_i32_sort_neon
#endif /* __APPLE__ */
	lsl	x9, x27, #2
	add	x1, x20, x9
	mov	w2, w27
	mov	w3, w26
	mov	x0, x20
	cmp	x26, #10
	bgt	L_cbb_c16
#ifndef __APPLE__
	bl	wc_mceliece_cb_compose10_neon
#else
	bl	_wc_mceliece_cb_compose10_neon
#endif /* __APPLE__ */
	b	L_cbb_c5e
L_cbb_c16:
#ifndef __APPLE__
	bl	wc_mceliece_cb_compose16_neon
#else
	bl	_wc_mceliece_cb_compose16_neon
#endif /* __APPLE__ */
L_cbb_c5e:
	mov	x14, x20
	mov	x8, #0
L_cbb_s6:
	cmp	x8, x27
	bge	L_cbb_s6e
	lsl	x9, x8, #1
	add	x9, x25, x9
	ldrh	w10, [x9]
	lsl	w10, w10, #16
	add	w10, w10, w8
	str	w10, [x14]
	add	x14, x14, #4
	add	x8, x8, #1
	b	L_cbb_s6
L_cbb_s6e:
	mov	x0, x20
	mov	w1, w27
#ifndef __APPLE__
	bl	wc_mceliece_i32_sort_neon
#else
	bl	_wc_mceliece_i32_sort_neon
#endif /* __APPLE__ */
	lsr	x13, x27, #1
	lsl	x9, x27, #2
	add	x15, x20, x9
	mov	x14, x20
	mov	x8, #0
L_cbb_s7:
	cmp	x8, x13
	bge	L_cbb_s7e
	ldr	w9, [x15]
	and	x10, x9, #1
	lsr	x11, x23, #3
	add	x11, x19, x11
	ldrb	w12, [x11]
	and	x9, x23, #7
	lsl	x9, x10, x9
	eor	x12, x12, x9
	strb	w12, [x11]
	add	x23, x23, x24
	add	x12, x8, x8
	add	x12, x12, x10
	ldr	w9, [x14]
	lsl	w9, w9, #16
	orr	w9, w9, w12
	str	w9, [x15]
	eor	x12, x12, #1
	add	x16, x14, #4
	ldr	w9, [x16]
	lsl	w9, w9, #16
	orr	w9, w9, w12
	add	x16, x15, #4
	str	w9, [x16]
	add	x14, x14, #8
	add	x15, x15, #8
	add	x8, x8, #1
	b	L_cbb_s7
L_cbb_s7e:
	lsl	x9, x27, #2
	add	x0, x20, x9
	mov	w1, w27
#ifndef __APPLE__
	bl	wc_mceliece_i32_sort_neon
#else
	bl	_wc_mceliece_i32_sort_neon
#endif /* __APPLE__ */
	add	x9, x26, x26
	sub	x9, x9, #3
	mul	x9, x9, x24
	lsr	x10, x27, #1
	mul	x9, x9, x10
	add	x23, x23, x9
	lsr	x13, x27, #1
	lsl	x9, x27, #2
	add	x15, x20, x9
	mov	x14, x20
	mov	x8, #0
L_cbb_s8:
	cmp	x8, x13
	bge	L_cbb_s8e
	ldr	w9, [x15]
	and	x10, x9, #1
	lsr	x11, x23, #3
	add	x11, x19, x11
	ldrb	w12, [x11]
	and	x9, x23, #7
	lsl	x9, x10, x9
	eor	x12, x12, x9
	strb	w12, [x11]
	add	x23, x23, x24
	add	x12, x8, x8
	add	x12, x12, x10
	ldr	w9, [x15]
	and	w9, w9, #0xffff
	lsl	w11, w12, #16
	orr	w9, w9, w11
	str	w9, [x14]
	eor	x12, x12, #1
	add	x16, x15, #4
	ldr	w9, [x16]
	and	w9, w9, #0xffff
	lsl	w11, w12, #16
	orr	w9, w9, w11
	add	x16, x14, #4
	str	w9, [x16]
	add	x14, x14, #8
	add	x15, x15, #8
	add	x8, x8, #1
	b	L_cbb_s8
L_cbb_s8e:
	mov	x0, x20
	mov	w1, w27
#ifndef __APPLE__
	bl	wc_mceliece_i32_sort_neon
#else
	bl	_wc_mceliece_i32_sort_neon
#endif /* __APPLE__ */
	add	x9, x26, x26
	sub	x9, x9, #2
	mul	x9, x9, x24
	lsr	x10, x27, #1
	mul	x9, x9, x10
	sub	x23, x23, x9
	lsr	x10, x27, #2
	add	x9, x27, x10
	lsl	x9, x9, #2
	add	x15, x20, x9
	lsr	x13, x27, #1
	mov	x14, x20
	mov	x8, #0
L_cbb_s10:
	cmp	x8, x13
	bge	L_cbb_s10e
	ldr	w9, [x14]
	and	w9, w9, #0xffff
	lsr	w9, w9, #1
	lsl	x10, x8, #1
	add	x10, x15, x10
	strh	w9, [x10]
	add	x16, x14, #4
	ldr	w9, [x16]
	and	w9, w9, #0xffff
	lsr	w9, w9, #1
	add	x11, x8, x13
	lsl	x11, x11, #1
	add	x11, x15, x11
	strh	w9, [x11]
	add	x14, x14, #8
	add	x8, x8, #1
	b	L_cbb_s10
L_cbb_s10e:
	lsr	x10, x27, #2
	add	x9, x27, x10
	lsl	x9, x9, #2
	add	x15, x20, x9
	lsr	x13, x27, #1
	add	x12, x24, x24
	sub	x11, x26, #1
	mov	x9, #40
	mul	x10, x22, x9
	add	x16, x21, x10
	add	x9, x23, x24
	str	x9, [x16]
	str	x12, [x16, #8]
	lsl	x9, x13, #1
	add	x9, x15, x9
	str	x9, [x16, #16]
	str	x11, [x16, #24]
	str	x13, [x16, #32]
	add	x22, x22, #1
	mov	x9, #40
	mul	x10, x22, x9
	add	x16, x21, x10
	str	x23, [x16]
	str	x12, [x16, #8]
	str	x15, [x16, #16]
	str	x11, [x16, #24]
	str	x13, [x16, #32]
	add	x22, x22, #1
	b	L_cbb_w
L_cbb_end:
	ldp	x19, x20, [x29, #24]
	ldp	x21, x22, [x29, #40]
	ldp	x23, x24, [x29, #56]
	ldp	x25, x26, [x29, #72]
	ldr	x27, [x29, #88]
	ldp	x29, x30, [sp], #0x60
	ret
#ifndef __APPLE__
	.size	wc_mceliece_cb_build_neon,.-wc_mceliece_cb_build_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_bs_fftbuild_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_bs_fftbuild_neon)
.type	wc_mceliece_bs_fftbuild_neon,@function
.align	2
wc_mceliece_bs_fftbuild_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_bs_fftbuild_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_bs_fftbuild_neon)
.p2align	2
_wc_mceliece_bs_fftbuild_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-48]!
	add	x29, sp, #0
	stp	x19, x20, [x29, #24]
	str	x21, [x29, #40]
	mov	x19, x0
	ldr	x20, [x19, #24]
	ldr	x0, [x19, #128]
	mov	x1, x20
	ldr	x2, [x19]
	ldr	x7, [x19, #136]
	mov	w3, w7
#ifndef __APPLE__
	bl	wc_mceliece_bs_gload_neon
#else
	bl	_wc_mceliece_bs_gload_neon
#endif /* __APPLE__ */
	add	x0, x20, #0x100
	mov	x1, x20
#ifndef __APPLE__
	bl	wc_mceliece_bs_poly_neon
#else
	bl	_wc_mceliece_bs_poly_neon
#endif /* __APPLE__ */
	add	x0, x20, #0x100
	add	x1, x20, #0xa00
#ifndef __APPLE__
	bl	wc_mceliece_radix_conv_neon
#else
	bl	_wc_mceliece_radix_conv_neon
#endif /* __APPLE__ */
	ldr	x0, [x19, #56]
	add	x1, x20, #0x100
	ldr	x7, [x19, #152]
	mov	w2, w7
	add	x3, x20, #0xa00
#ifndef __APPLE__
	bl	wc_mceliece_fft_fwd_butterflies_neon
#else
	bl	_wc_mceliece_fft_fwd_butterflies_neon
#endif /* __APPLE__ */
	ldr	x0, [x19, #40]
	ldr	x1, [x19, #56]
	add	x2, x20, #0x200
	add	x3, x20, #0x540
	mov	w4, #0
#ifndef __APPLE__
	bl	wc_mceliece_mont_batch_inv_neon
#else
	bl	_wc_mceliece_mont_batch_inv_neon
#endif /* __APPLE__ */
	ldr	x0, [x19, #64]
	ldr	x1, [x19, #40]
#ifndef __APPLE__
	bl	wc_mceliece_bs_debitslice_neon
#else
	bl	_wc_mceliece_bs_debitslice_neon
#endif /* __APPLE__ */
	mov	x0, x20
	ldr	x1, [x19, #8]
	ldr	x2, [x19, #64]
#ifndef __APPLE__
	bl	wc_mceliece_bs_packbuf_neon
#else
	bl	_wc_mceliece_bs_packbuf_neon
#endif /* __APPLE__ */
	mov	x0, x20
	mov	w1, #0x2000
#ifndef __APPLE__
	bl	wc_mceliece_u64_sort_neon
#else
	bl	_wc_mceliece_u64_sort_neon
#endif /* __APPLE__ */
	ldr	x0, [x19, #16]
	mov	x1, x20
#ifndef __APPLE__
	bl	wc_mceliece_bs_dup_pi_neon
#else
	bl	_wc_mceliece_bs_dup_pi_neon
#endif /* __APPLE__ */
	cbz	w0, L_mc_fftb_nd
	mov	w21, #0
	sub	w21, w21, #1
	b	L_mc_fftb_end
L_mc_fftb_nd:
	ldr	x0, [x19, #48]
	ldr	x1, [x19, #40]
	mov	x2, x20
#ifndef __APPLE__
	bl	wc_mceliece_bs_tobitslice2x_neon
#else
	bl	_wc_mceliece_bs_tobitslice2x_neon
#endif /* __APPLE__ */
	mov	w21, #0
L_mc_fftb_end:
	mov	w0, w21
	ldp	x19, x20, [x29, #24]
	ldr	x21, [x29, #40]
	ldp	x29, x30, [sp], #48
	ret
#ifndef __APPLE__
	.size	wc_mceliece_bs_fftbuild_neon,.-wc_mceliece_bs_fftbuild_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_u64_sort_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_u64_sort_neon)
.type	wc_mceliece_u64_sort_neon,@function
.align	2
wc_mceliece_u64_sort_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_u64_sort_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_u64_sort_neon)
.p2align	2
_wc_mceliece_u64_sort_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-96]!
	add	x29, sp, #0
	stp	x19, x20, [x29, #24]
	stp	x21, x22, [x29, #40]
	stp	x23, x24, [x29, #56]
	stp	x25, x26, [x29, #72]
	str	x27, [x29, #88]
	mov	x19, x0
	mov	w20, w1
	cmp	x20, #2
	blt	L_mc_us_end
	mov	x21, #1
L_mc_us_top:
	sub	x4, x20, x21
	cmp	x21, x4
	bge	L_mc_us_tope
	lsl	x21, x21, #1
	b	L_mc_us_top
L_mc_us_tope:
	mov	x22, x21
L_mc_us_p:
	cbz	x22, L_mc_us_pe
	mov	x27, #0
L_mc_us_bs:
	sub	x4, x20, x22
	cmp	x27, x4
	bge	L_mc_us_bse
	sub	x26, x20, x22
	sub	x26, x26, x27
	cmp	x26, x22
	ble	L_mc_us_l1
	mov	x26, x22
L_mc_us_l1:
	lsl	x4, x27, #3
	add	x0, x19, x4
	add	x5, x27, x22
	lsl	x5, x5, #3
	add	x1, x19, x5
	mov	w2, w26
#ifndef __APPLE__
	bl	wc_mceliece_u64_minmax_vec_neon
#else
	bl	_wc_mceliece_u64_minmax_vec_neon
#endif /* __APPLE__ */
	add	x27, x27, x22
	add	x27, x27, x22
	b	L_mc_us_bs
L_mc_us_bse:
	mov	x25, #0
	mov	x23, x21
L_mc_us_q:
	cmp	x23, x22
	ble	L_mc_us_qe
L_mc_us_w:
	sub	x4, x20, x23
	cmp	x25, x4
	bge	L_mc_us_we
	and	x4, x25, x22
	cbz	x4, L_mc_us_sel
	sub	x4, x22, #1
	orr	x25, x25, x4
	add	x25, x25, #1
	b	L_mc_us_w
L_mc_us_sel:
	neg	x4, x22
	and	x3, x25, x4
	add	x3, x3, x22
	sub	x26, x3, x25
	sub	x5, x20, x23
	cmp	x3, x5
	ble	L_mc_us_l2
	sub	x26, x5, x25
L_mc_us_l2:
	mov	x24, x23
L_mc_us_r:
	cmp	x24, x22
	ble	L_mc_us_re
	add	x4, x25, x22
	lsl	x4, x4, #3
	add	x0, x19, x4
	add	x5, x25, x24
	lsl	x5, x5, #3
	add	x1, x19, x5
	mov	w2, w26
#ifndef __APPLE__
	bl	wc_mceliece_u64_minmax_vec_neon
#else
	bl	_wc_mceliece_u64_minmax_vec_neon
#endif /* __APPLE__ */
	lsr	x24, x24, #1
	b	L_mc_us_r
L_mc_us_re:
	add	x25, x25, x26
	b	L_mc_us_w
L_mc_us_we:
	lsr	x23, x23, #1
	b	L_mc_us_q
L_mc_us_qe:
	lsr	x22, x22, #1
	b	L_mc_us_p
L_mc_us_pe:
L_mc_us_end:
	ldp	x19, x20, [x29, #24]
	ldp	x21, x22, [x29, #40]
	ldp	x23, x24, [x29, #56]
	ldp	x25, x26, [x29, #72]
	ldr	x27, [x29, #88]
	ldp	x29, x30, [sp], #0x60
	ret
#ifndef __APPLE__
	.size	wc_mceliece_u64_sort_neon,.-wc_mceliece_u64_sort_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_bs_composeinv_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_bs_composeinv_neon)
.type	wc_mceliece_bs_composeinv_neon,@function
.align	2
wc_mceliece_bs_composeinv_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_bs_composeinv_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_bs_composeinv_neon)
.p2align	2
_wc_mceliece_bs_composeinv_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-48]!
	add	x29, sp, #0
	stp	x19, x20, [x29, #24]
	str	x21, [x29, #40]
	mov	w19, w0
	mov	x20, x1
	mov	x21, x4
	mov	x6, x2
	mov	x7, x3
	mov	x8, x4
	mov	x5, #0
L_mc_cinv_p:
	cmp	x5, x19
	bge	L_mc_cinv_pe
	ldrh	w9, [x7]
	lsl	x9, x9, #16
	ldrh	w10, [x6]
	orr	x9, x9, x10
	str	x9, [x8]
	add	x6, x6, #2
	add	x7, x7, #2
	add	x8, x8, #8
	add	x5, x5, #1
	b	L_mc_cinv_p
L_mc_cinv_pe:
	mov	x0, x21
	mov	w1, w19
#ifndef __APPLE__
	bl	wc_mceliece_u64_sort_neon
#else
	bl	_wc_mceliece_u64_sort_neon
#endif /* __APPLE__ */
	mov	x8, x21
	mov	x6, x20
	mov	x5, #0
L_mc_cinv_u:
	cmp	x5, x19
	bge	L_mc_cinv_ue
	ldr	x9, [x8]
	strh	w9, [x6]
	add	x8, x8, #8
	add	x6, x6, #2
	add	x5, x5, #1
	b	L_mc_cinv_u
L_mc_cinv_ue:
	ldp	x19, x20, [x29, #24]
	ldr	x21, [x29, #40]
	ldp	x29, x30, [sp], #48
	ret
#ifndef __APPLE__
	.size	wc_mceliece_bs_composeinv_neon,.-wc_mceliece_bs_composeinv_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_controlbits_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_controlbits_neon)
.type	wc_mceliece_controlbits_neon,@function
.align	2
wc_mceliece_controlbits_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_controlbits_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_controlbits_neon)
.p2align	2
_wc_mceliece_controlbits_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-96]!
	add	x29, sp, #0
	stp	x19, x20, [x29, #16]
	stp	x21, x22, [x29, #32]
	stp	x23, x24, [x29, #48]
	stp	x25, x26, [x29, #64]
	stp	x27, x28, [x29, #80]
	mov	x19, x0
	mov	x20, x1
	mov	w21, w2
	mov	w22, w3
	mov	x23, x4
	mov	x24, x5
	mov	x25, x6
	mov	x12, #0
	mov	x26, #0
L_mc_cb_o:
	cmp	x26, #2
	bge	L_mc_cb_fail
	lsl	x10, x21, #1
	sub	x10, x10, #1
	lsr	x13, x22, #1
	mul	x10, x10, x13
	add	x10, x10, #7
	lsr	x10, x10, #3
	lsr	x11, x10, #3
	mov	x9, x19
	mov	x8, #0
L_mc_cb_zw:
	cmp	x8, x11
	bge	L_mc_cb_zwe
	str	x12, [x9]
	add	x9, x9, #8
	add	x8, x8, #1
	b	L_mc_cb_zw
L_mc_cb_zwe:
	and	x13, x10, #7
	mov	x8, #0
L_mc_cb_zb:
	cmp	x8, x13
	bge	L_mc_cb_zbe
	strb	w12, [x9]
	add	x9, x9, #1
	add	x8, x8, #1
	b	L_mc_cb_zb
L_mc_cb_zbe:
	mov	x0, x19
	mov	x1, #0
	mov	x2, #1
	mov	x3, x20
	mov	x4, x21
	mov	x5, x22
	mov	x6, x23
	mov	x7, x25
#ifndef __APPLE__
	bl	wc_mceliece_cb_build_neon
#else
	bl	_wc_mceliece_cb_build_neon
#endif /* __APPLE__ */
	mov	x9, x24
	mov	x8, #0
L_mc_cb_pt:
	cmp	x8, x22
	bge	L_mc_cb_pte
	strh	w8, [x9]
	add	x9, x9, #2
	add	x8, x8, #1
	b	L_mc_cb_pt
L_mc_cb_pte:
	mov	x27, x19
	mov	x28, #0
L_mc_cb_fw:
	cmp	x28, x21
	bge	L_mc_cb_fwe
	mov	x0, x24
	mov	x1, x27
	mov	w2, w28
	mov	w3, w22
#ifndef __APPLE__
	bl	wc_mceliece_cb_layer_neon
#else
	bl	_wc_mceliece_cb_layer_neon
#endif /* __APPLE__ */
	lsr	x13, x22, #4
	add	x27, x27, x13
	add	x28, x28, #1
	b	L_mc_cb_fw
L_mc_cb_fwe:
	sub	x28, x21, #2
L_mc_cb_bw:
	cmp	x28, #0
	blt	L_mc_cb_bwe
	mov	x0, x24
	mov	x1, x27
	mov	w2, w28
	mov	w3, w22
#ifndef __APPLE__
	bl	wc_mceliece_cb_layer_neon
#else
	bl	_wc_mceliece_cb_layer_neon
#endif /* __APPLE__ */
	lsr	x13, x22, #4
	add	x27, x27, x13
	sub	x28, x28, #1
	b	L_mc_cb_bw
L_mc_cb_bwe:
	mov	x15, #0
	mov	x8, #0
L_mc_cb_vf:
	cmp	x8, x22
	bge	L_mc_cb_vfe
	lsl	x13, x8, #1
	add	x14, x20, x13
	ldrh	w16, [x14]
	add	x14, x24, x13
	ldrh	w13, [x14]
	eor	x16, x16, x13
	orr	x15, x15, x16
	add	x8, x8, #1
	b	L_mc_cb_vf
L_mc_cb_vfe:
	cbz	x15, L_mc_cb_ok
	add	x26, x26, #1
	b	L_mc_cb_o
L_mc_cb_fail:
	mov	w0, #0
	sub	w0, w0, #1
	b	L_mc_cb_end
L_mc_cb_ok:
	mov	w0, #0
L_mc_cb_end:
	ldp	x19, x20, [x29, #16]
	ldp	x21, x22, [x29, #32]
	ldp	x23, x24, [x29, #48]
	ldp	x25, x26, [x29, #64]
	ldp	x27, x28, [x29, #80]
	ldp	x29, x30, [sp], #0x60
	ret
#ifndef __APPLE__
	.size	wc_mceliece_controlbits_neon,.-wc_mceliece_controlbits_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_bs_extract_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_bs_extract_neon)
.type	wc_mceliece_bs_extract_neon,@function
.align	2
wc_mceliece_bs_extract_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_bs_extract_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_bs_extract_neon)
.p2align	2
_wc_mceliece_bs_extract_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-32]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #16]
	mov	x5, x0
	mov	x6, x1
	mov	w7, w2
	mov	w8, w3
	mov	w9, w4
	lsr	x10, x7, #3
	and	x11, x7, #7
	cbz	x11, L_mc_ext_z
	mov	x15, x5
	mov	x12, #0
L_mc_ext_ti:
	cmp	x12, x7
	bge	L_mc_ext_end
	mul	x19, x12, x8
	add	x14, x6, x19
	add	x14, x14, x10
	mov	x13, x10
L_mc_ext_tj:
	sub	x19, x9, #1
	cmp	x13, x19
	bge	L_mc_ext_tjd
	ldrh	w16, [x14]
	lsr	x16, x16, x11
	strb	w16, [x15]
	add	x14, x14, #1
	add	x15, x15, #1
	add	x13, x13, #1
	b	L_mc_ext_tj
L_mc_ext_tjd:
	ldrb	w16, [x14]
	lsr	x16, x16, x11
	strb	w16, [x15]
	add	x15, x15, #1
	add	x12, x12, #1
	b	L_mc_ext_ti
L_mc_ext_z:
	sub	x17, x9, x10
	mov	x12, #0
L_mc_ext_zi:
	cmp	x12, x7
	bge	L_mc_ext_end
	mul	x19, x12, x8
	add	x14, x6, x19
	add	x14, x14, x10
	mul	x19, x12, x17
	add	x15, x5, x19
	mov	x13, #0
L_mc_ext_zj:
	cmp	x13, x17
	bge	L_mc_ext_zjd
	ldrb	w16, [x14]
	strb	w16, [x15]
	add	x14, x14, #1
	add	x15, x15, #1
	add	x13, x13, #1
	b	L_mc_ext_zj
L_mc_ext_zjd:
	add	x12, x12, #1
	b	L_mc_ext_zi
L_mc_ext_end:
	ldp	x17, x19, [x29, #16]
	ldp	x29, x30, [sp], #32
	ret
#ifndef __APPLE__
	.size	wc_mceliece_bs_extract_neon,.-wc_mceliece_bs_extract_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_pk_gen_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_pk_gen_neon)
.type	wc_mceliece_pk_gen_neon,@function
.align	2
wc_mceliece_pk_gen_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_pk_gen_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_pk_gen_neon)
.p2align	2
_wc_mceliece_pk_gen_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-32]!
	add	x29, sp, #0
	stp	x19, x20, [x29, #16]
	mov	x19, x0
	mov	x20, #0
	mov	x0, x19
#ifndef __APPLE__
	bl	wc_mceliece_bs_fftbuild_neon
#else
	bl	_wc_mceliece_bs_fftbuild_neon
#endif /* __APPLE__ */
	mov	w20, w0
	cbnz	w0, L_mc_pkg_end
	ldr	x0, [x19, #32]
	ldr	x1, [x19, #40]
	ldr	x2, [x19, #48]
	ldr	x14, [x19, #136]
	mov	w3, w14
	mov	w4, #13
	ldr	x8, [x19, #144]
	add	x9, x8, #0xff
	lsr	x9, x9, #8
	lsl	x10, x9, #2
	mov	w5, w9
	mov	w6, w10
	ldr	x7, [x19, #104]
#ifndef __APPLE__
	bl	wc_mceliece_bs_lu_fill_neon
#else
	bl	_wc_mceliece_bs_lu_fill_neon
#endif /* __APPLE__ */
	ldr	x8, [x19, #144]
	ldr	x12, [x19, #80]
	ldr	x13, [x19, #88]
	mov	x11, #0
L_mc_pkg_ii:
	cmp	x11, x8
	bge	L_mc_pkg_iid
	strh	w11, [x12]
	strh	w11, [x13]
	add	x12, x12, #2
	add	x13, x13, #2
	add	x11, x11, #1
	b	L_mc_pkg_ii
L_mc_pkg_iid:
	ldr	x0, [x19, #32]
	ldr	x1, [x19, #80]
	ldr	x8, [x19, #144]
	mov	w2, w8
	add	x9, x8, #0xff
	lsr	x9, x9, #8
	lsl	x10, x9, #2
	mov	w3, w10
	ldr	x14, [x19, #160]
	mov	w4, w14
	ldr	x5, [x19, #16]
	ldr	x6, [x19, #112]
#ifndef __APPLE__
	bl	wc_mceliece_bs_pk_gen_reduce_neon
#else
	bl	_wc_mceliece_bs_pk_gen_reduce_neon
#endif /* __APPLE__ */
	mov	w20, w0
	cbnz	w0, L_mc_pkg_end
	ldr	x8, [x19, #144]
	mov	w0, w8
	ldr	x1, [x19, #88]
	ldr	x2, [x19, #88]
	ldr	x3, [x19, #80]
	ldr	x4, [x19, #104]
#ifndef __APPLE__
	bl	wc_mceliece_bs_composeinv_neon
#else
	bl	_wc_mceliece_bs_composeinv_neon
#endif /* __APPLE__ */
	mov	x0, x19
#ifndef __APPLE__
	bl	wc_mceliece_bs_phase10_neon
#else
	bl	_wc_mceliece_bs_phase10_neon
#endif /* __APPLE__ */
	ldr	x0, [x19, #120]
	ldr	x1, [x19, #96]
	ldr	x8, [x19, #144]
	mov	w2, w8
	ldr	x14, [x19, #184]
	mov	w3, w14
	ldr	x14, [x19, #192]
	mov	w4, w14
#ifndef __APPLE__
	bl	wc_mceliece_bs_extract_neon
#else
	bl	_wc_mceliece_bs_extract_neon
#endif /* __APPLE__ */
	mov	w20, #0
L_mc_pkg_end:
	mov	w0, w20
	ldp	x19, x20, [x29, #16]
	ldp	x29, x30, [sp], #32
	ret
#ifndef __APPLE__
	.size	wc_mceliece_pk_gen_neon,.-wc_mceliece_pk_gen_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_mceliece_genpoly_neon
WC_ASM_ATT_HIDDEN(wc_mceliece_genpoly_neon)
.type	wc_mceliece_genpoly_neon,@function
.align	2
wc_mceliece_genpoly_neon:
#else
.section	__TEXT,__text
.globl	_wc_mceliece_genpoly_neon
WC_ASM_ATT_HIDDEN(_wc_mceliece_genpoly_neon)
.p2align	2
_wc_mceliece_genpoly_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-112]!
	add	x29, sp, #0
	stp	x19, x20, [x29, #32]
	stp	x21, x22, [x29, #48]
	stp	x23, x24, [x29, #64]
	stp	x25, x26, [x29, #80]
	stp	x27, x28, [x29, #96]
	mov	x19, x0
	mov	x20, x1
	mov	w21, w2
	mov	x22, x3
	mov	x23, x4
	str	x5, [x29, #16]
	mov	x28, x6
	mov	w27, #0
	mov	w11, #1
	strh	w11, [x22]
	mov	w11, #0
	mov	x7, #1
L_mc_gp_c0:
	cmp	x7, x21
	bge	L_mc_gp_c0e
	lsl	x9, x7, #1
	add	x10, x22, x9
	strh	w11, [x10]
	add	x7, x7, #1
	b	L_mc_gp_c0
L_mc_gp_c0e:
	mov	x7, #0
L_mc_gp_c1:
	cmp	x7, x21
	bge	L_mc_gp_c1e
	lsl	x9, x7, #1
	add	x10, x20, x9
	ldrh	w11, [x10]
	add	x8, x21, x7
	lsl	x9, x8, #1
	add	x10, x22, x9
	strh	w11, [x10]
	add	x7, x7, #1
	b	L_mc_gp_c1
L_mc_gp_c1e:
	mov	x24, #2
L_mc_gp_j:
	cmp	x24, x21
	bgt	L_mc_gp_je
	mov	w11, #0
	mov	x7, #0
	lsl	x12, x21, #1
	sub	x12, x12, #1
L_mc_gp_pz:
	cmp	x7, x12
	bge	L_mc_gp_pze
	lsl	x9, x7, #1
	add	x10, x23, x9
	strh	w11, [x10]
	add	x7, x7, #1
	b	L_mc_gp_pz
L_mc_gp_pze:
	mov	x25, #0
L_mc_gp_pm:
	cmp	x25, x21
	bge	L_mc_gp_pme
	sub	x8, x24, #1
	mul	x8, x8, x21
	add	x8, x8, x25
	lsl	x9, x8, #1
	add	x10, x22, x9
	ldrh	w11, [x10]
	lsl	x9, x25, #1
	add	x0, x23, x9
	mov	w1, w11
	mov	x2, x20
	mov	w3, w21
#ifndef __APPLE__
	bl	wc_mceliece_gf_mulc_mac_full_neon
#else
	bl	_wc_mceliece_gf_mulc_mac_full_neon
#endif /* __APPLE__ */
	add	x25, x25, #1
	b	L_mc_gp_pm
L_mc_gp_pme:
	lsl	x7, x21, #1
	sub	x7, x7, #2
	cmp	x21, #0x77
	beq	L_mc_gp_119
L_mc_gp_rd:
	cmp	x7, x21
	blt	L_mc_gp_rde
	lsl	x9, x7, #1
	add	x10, x23, x9
	ldrh	w12, [x10]
	sub	x8, x7, x21
	add	x13, x8, #0
	lsl	x9, x13, #1
	add	x10, x23, x9
	ldrh	w11, [x10]
	eor	w11, w11, w12
	strh	w11, [x10]
	add	x13, x8, #1
	lsl	x9, x13, #1
	add	x10, x23, x9
	ldrh	w11, [x10]
	eor	w11, w11, w12
	strh	w11, [x10]
	add	x13, x8, #2
	lsl	x9, x13, #1
	add	x10, x23, x9
	ldrh	w11, [x10]
	eor	w11, w11, w12
	strh	w11, [x10]
	add	x13, x8, #7
	lsl	x9, x13, #1
	add	x10, x23, x9
	ldrh	w11, [x10]
	eor	w11, w11, w12
	strh	w11, [x10]
	sub	x7, x7, #1
	b	L_mc_gp_rd
L_mc_gp_119:
	cmp	x7, x21
	blt	L_mc_gp_rde
	lsl	x9, x7, #1
	add	x10, x23, x9
	ldrh	w12, [x10]
	sub	x8, x7, x21
	add	x13, x8, #0
	lsl	x9, x13, #1
	add	x10, x23, x9
	ldrh	w11, [x10]
	eor	w11, w11, w12
	strh	w11, [x10]
	add	x13, x8, #8
	lsl	x9, x13, #1
	add	x10, x23, x9
	ldrh	w11, [x10]
	eor	w11, w11, w12
	strh	w11, [x10]
	sub	x7, x7, #1
	b	L_mc_gp_119
L_mc_gp_rde:
	mul	x12, x24, x21
	mov	x7, #0
L_mc_gp_cp:
	cmp	x7, x21
	bge	L_mc_gp_cpe
	lsl	x9, x7, #1
	add	x10, x23, x9
	ldrh	w11, [x10]
	add	x8, x12, x7
	lsl	x9, x8, #1
	add	x10, x22, x9
	strh	w11, [x10]
	add	x7, x7, #1
	b	L_mc_gp_cp
L_mc_gp_cpe:
	add	x24, x24, #1
	b	L_mc_gp_j
L_mc_gp_je:
	mov	x24, #0
L_mc_gp_e:
	cmp	x24, x21
	bge	L_mc_gp_ee
	add	x8, x24, #1
L_mc_gp_pk:
	cmp	x8, x21
	bge	L_mc_gp_pke
	mul	x9, x24, x21
	add	x9, x9, x24
	lsl	x9, x9, #1
	add	x10, x22, x9
	ldrh	w11, [x10]
	sub	w14, w11, #1
	lsr	w14, w14, #31
	neg	w14, w14
	mov	x13, x24
L_mc_gp_pc:
	cmp	x13, x21
	bgt	L_mc_gp_pce
	mul	x9, x13, x21
	add	x12, x9, x8
	add	x9, x9, x24
	lsl	x12, x12, #1
	add	x10, x22, x12
	ldrh	w11, [x10]
	and	w11, w11, w14
	lsl	x9, x9, #1
	add	x10, x22, x9
	ldrh	w12, [x10]
	eor	w12, w12, w11
	strh	w12, [x10]
	add	x13, x13, #1
	b	L_mc_gp_pc
L_mc_gp_pce:
	add	x8, x8, #1
	b	L_mc_gp_pk
L_mc_gp_pke:
	mul	x9, x24, x21
	add	x9, x9, x24
	lsl	x9, x9, #1
	add	x10, x22, x9
	ldrh	w11, [x10]
	cbz	w11, L_mc_gp_sg
	mov	w0, w11
#ifndef __APPLE__
	bl	wc_mceliece_gf_inv_scalar_neon
#else
	bl	_wc_mceliece_gf_inv_scalar_neon
#endif /* __APPLE__ */
	mov	w26, w0
	mov	x25, x24
L_mc_gp_nc:
	cmp	x25, x21
	bgt	L_mc_gp_nce
	mul	x9, x25, x21
	add	x9, x9, x24
	lsl	x9, x9, #1
	add	x10, x22, x9
	ldrh	w0, [x10]
	mov	w1, w26
#ifndef __APPLE__
	bl	wc_mceliece_gf_mul_scalar_neon
#else
	bl	_wc_mceliece_gf_mul_scalar_neon
#endif /* __APPLE__ */
	mul	x9, x25, x21
	add	x9, x9, x24
	lsl	x9, x9, #1
	add	x10, x22, x9
	strh	w0, [x10]
	add	x25, x25, #1
	b	L_mc_gp_nc
L_mc_gp_nce:
	mov	x7, #0
L_mc_gp_sv:
	cmp	x7, x21
	bge	L_mc_gp_sve
	mul	x9, x24, x21
	add	x9, x9, x7
	lsl	x9, x9, #1
	add	x10, x22, x9
	ldrh	w11, [x10]
	lsl	x9, x7, #1
	add	x10, x23, x9
	strh	w11, [x10]
	add	x7, x7, #1
	b	L_mc_gp_sv
L_mc_gp_sve:
	mov	w11, #0
	lsl	x9, x24, #1
	add	x10, x23, x9
	strh	w11, [x10]
	mov	x25, x24
L_mc_gp_el:
	cmp	x25, x21
	bgt	L_mc_gp_ele
	mul	x9, x25, x21
	add	x8, x9, x24
	lsl	x8, x8, #1
	add	x10, x22, x8
	ldrh	w11, [x10]
	mul	x9, x25, x21
	lsl	x9, x9, #1
	add	x0, x22, x9
	mov	w1, w11
	mov	x2, x23
	mov	w3, w21
#ifndef __APPLE__
	bl	wc_mceliece_gf_mulc_mac_full_neon
#else
	bl	_wc_mceliece_gf_mulc_mac_full_neon
#endif /* __APPLE__ */
	add	x25, x25, #1
	b	L_mc_gp_el
L_mc_gp_ele:
	add	x24, x24, #1
	b	L_mc_gp_e
L_mc_gp_sg:
	mov	w27, #0
	sub	w27, w27, #1
	b	L_mc_gp_dn
L_mc_gp_ee:
	mul	x12, x21, x21
	mov	x7, #0
L_mc_gp_o:
	cmp	x7, x21
	bge	L_mc_gp_oe
	add	x8, x12, x7
	lsl	x9, x8, #1
	add	x10, x22, x9
	ldrh	w11, [x10]
	lsl	x9, x7, #1
	add	x10, x19, x9
	strh	w11, [x10]
	add	x7, x7, #1
	b	L_mc_gp_o
L_mc_gp_oe:
	ldr	x13, [x29, #16]
	lsr	x8, x21, #3
	lsl	x8, x8, #3
	mov	x7, #0
L_mc_gp_stv:
	cmp	x7, x8
	bge	L_mc_gp_stve
	lsl	x9, x7, #1
	add	x10, x19, x9
	ldr	q0, [x10]
	add	x10, x13, x9
	str	q0, [x10]
	add	x7, x7, #8
	b	L_mc_gp_stv
L_mc_gp_stve:
L_mc_gp_stg:
	cmp	x7, x21
	bge	L_mc_gp_stge
	lsl	x9, x7, #1
	add	x10, x19, x9
	ldrh	w11, [x10]
	add	x10, x13, x9
	strh	w11, [x10]
	add	x7, x7, #1
	b	L_mc_gp_stg
L_mc_gp_stge:
	mov	x0, x28
#ifndef __APPLE__
	bl	wc_mceliece_pk_gen_neon
#else
	bl	_wc_mceliece_pk_gen_neon
#endif /* __APPLE__ */
	mov	w27, w0
L_mc_gp_dn:
	mov	w0, w27
	ldp	x19, x20, [x29, #32]
	ldp	x21, x22, [x29, #48]
	ldp	x23, x24, [x29, #64]
	ldp	x25, x26, [x29, #80]
	ldp	x27, x28, [x29, #96]
	ldp	x29, x30, [sp], #0x70
	ret
#ifndef __APPLE__
	.size	wc_mceliece_genpoly_neon,.-wc_mceliece_genpoly_neon
#endif /* __APPLE__ */
#endif /* WOLFSSL_MCELIECE_SMALL */
#endif /* WOLFSSL_MCELIECE_NO_MAKE_KEY */
#endif /* WOLFSSL_HAVE_MCELIECE */
#endif /* __aarch64__ */
#endif /* WOLFSSL_ARMASM */

#if defined(__linux__) && defined(__ELF__)
.section	.note.GNU-stack,"",%progbits
#endif
#endif /* !WOLFSSL_ARMASM_INLINE */
