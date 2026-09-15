/* armv8-32-mceliece-asm
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
 *   ruby ./mceliece/mceliece.rb arm32 \
 *       /home/sparki/wolfssl/github/mceliece/wolfssl/wolfcrypt/src/port/arm/armv8-32-mceliece-asm.S
 */

#define _WC_BUILDING_ARMV8_32_MCELIECE_ASM_S

#include <wolfssl/wolfcrypt/libwolfssl_sources_asm.h>

#ifdef WOLFSSL_ARMASM
#if !defined(__aarch64__) && !defined(WOLFSSL_ARMASM_THUMB2)
#ifndef WOLFSSL_ARMASM_INLINE
#ifdef WOLFSSL_HAVE_MCELIECE
#ifndef WOLFSSL_ARMASM_NO_NEON
#ifndef __APPLE__
	.text
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
	.type	L_mc_bs_powers_neon, %object
	.size	L_mc_bs_powers_neon, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 4-byte aligned, 32-bit aligned
#ifndef __APPLE__
	.align	2
#else
	.p2align	2
#endif /* __APPLE__ */
L_mc_bs_powers_neon:
	.short	0x0001,0x0002,0x0004,0x0008,0x0010,0x0020,0x0040,0x0080
#ifndef __APPLE__
	.text
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
	.type	L_mc_aff_reversal_neon, %object
	.size	L_mc_aff_reversal_neon, 64
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 4-byte aligned, 32-bit aligned
#ifndef __APPLE__
	.align	2
#else
	.p2align	2
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
	.text
	.align	4
	.globl	wc_mceliece_gf_mul_scalar_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_gf_mul_scalar_neon)
	.type	wc_mceliece_gf_mul_scalar_neon, %function
wc_mceliece_gf_mul_scalar_neon:
	push	{r4, r5, lr}
	mov	r4, r0
	mov	r2, #0
	and	r3, r1, #1
	neg	r3, r3
	and	r12, r4, r3
	eor	r2, r2, r12
	lsr	r3, r1, #1
	and	r3, r3, #1
	neg	r3, r3
	lsl	r12, r4, #1
	and	r12, r12, r3
	eor	r2, r2, r12
	lsr	r3, r1, #2
	and	r3, r3, #1
	neg	r3, r3
	lsl	r12, r4, #2
	and	r12, r12, r3
	eor	r2, r2, r12
	lsr	r3, r1, #3
	and	r3, r3, #1
	neg	r3, r3
	lsl	r12, r4, #3
	and	r12, r12, r3
	eor	r2, r2, r12
	lsr	r3, r1, #4
	and	r3, r3, #1
	neg	r3, r3
	lsl	r12, r4, #4
	and	r12, r12, r3
	eor	r2, r2, r12
	lsr	r3, r1, #5
	and	r3, r3, #1
	neg	r3, r3
	lsl	r12, r4, #5
	and	r12, r12, r3
	eor	r2, r2, r12
	lsr	r3, r1, #6
	and	r3, r3, #1
	neg	r3, r3
	lsl	r12, r4, #6
	and	r12, r12, r3
	eor	r2, r2, r12
	lsr	r3, r1, #7
	and	r3, r3, #1
	neg	r3, r3
	lsl	r12, r4, #7
	and	r12, r12, r3
	eor	r2, r2, r12
	lsr	r3, r1, #8
	and	r3, r3, #1
	neg	r3, r3
	lsl	r12, r4, #8
	and	r12, r12, r3
	eor	r2, r2, r12
	lsr	r3, r1, #9
	and	r3, r3, #1
	neg	r3, r3
	lsl	r12, r4, #9
	and	r12, r12, r3
	eor	r2, r2, r12
	lsr	r3, r1, #10
	and	r3, r3, #1
	neg	r3, r3
	lsl	r12, r4, #10
	and	r12, r12, r3
	eor	r2, r2, r12
	lsr	r3, r1, #11
	and	r3, r3, #1
	neg	r3, r3
	lsl	r12, r4, #11
	and	r12, r12, r3
	eor	r2, r2, r12
	lsr	r3, r1, #12
	and	r3, r3, #1
	neg	r3, r3
	lsl	r12, r4, #12
	and	r12, r12, r3
	eor	r2, r2, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r5, #0xff
	orr	r5, r5, #0x100
#else
	mov	r5, #0x1ff
#endif
	lsl	r5, r5, #16
	and	r12, r2, r5
	lsr	lr, r12, #9
	eor	r2, r2, lr
	lsr	lr, r12, #10
	eor	r2, r2, lr
	lsr	lr, r12, #12
	eor	r2, r2, lr
	lsr	lr, r12, #13
	eor	r2, r2, lr
	mov	r5, #0xe000
	and	r12, r2, r5
	lsr	lr, r12, #9
	eor	r2, r2, lr
	lsr	lr, r12, #10
	eor	r2, r2, lr
	lsr	lr, r12, #12
	eor	r2, r2, lr
	lsr	lr, r12, #13
	eor	r2, r2, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r5, #0xff
	orr	r5, r5, #0x1f00
#else
	mov	r5, #0x1fff
#endif
	and	r0, r2, r5
	pop	{r4, r5, pc}
	.size	wc_mceliece_gf_mul_scalar_neon,.-wc_mceliece_gf_mul_scalar_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_gf_inv_scalar_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_gf_inv_scalar_neon)
	.type	wc_mceliece_gf_inv_scalar_neon, %function
wc_mceliece_gf_inv_scalar_neon:
	push	{r4, r5, r6, lr}
	mov	r4, r0
	mov	r1, r0
	bl	wc_mceliece_gf_mul_scalar_neon
	mov	r1, r4
	bl	wc_mceliece_gf_mul_scalar_neon
	mov	r5, r0
	mov	r1, r0
	bl	wc_mceliece_gf_mul_scalar_neon
	mov	r1, r0
	bl	wc_mceliece_gf_mul_scalar_neon
	mov	r1, r5
	bl	wc_mceliece_gf_mul_scalar_neon
	mov	r6, r0
	mov	r1, r0
	bl	wc_mceliece_gf_mul_scalar_neon
	mov	r1, r0
	bl	wc_mceliece_gf_mul_scalar_neon
	mov	r1, r0
	bl	wc_mceliece_gf_mul_scalar_neon
	mov	r1, r0
	bl	wc_mceliece_gf_mul_scalar_neon
	mov	r1, r6
	bl	wc_mceliece_gf_mul_scalar_neon
	mov	r1, r0
	bl	wc_mceliece_gf_mul_scalar_neon
	mov	r1, r0
	bl	wc_mceliece_gf_mul_scalar_neon
	mov	r1, r0
	bl	wc_mceliece_gf_mul_scalar_neon
	mov	r1, r0
	bl	wc_mceliece_gf_mul_scalar_neon
	mov	r1, r6
	bl	wc_mceliece_gf_mul_scalar_neon
	mov	r1, r0
	bl	wc_mceliece_gf_mul_scalar_neon
	pop	{r4, r5, r6, pc}
	.size	wc_mceliece_gf_inv_scalar_neon,.-wc_mceliece_gf_inv_scalar_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_gf_mulc_mac_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_gf_mulc_mac_neon)
	.type	wc_mceliece_gf_mulc_mac_neon, %function
wc_mceliece_gf_mulc_mac_neon:
	push	{r4, lr}
	vpush	{d8-d15}
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r4, #0xff
	orr	r4, r4, #0x100
#else
	mov	r4, #0x1ff
#endif
	vdup.32	q0, r4
	vshl.i32	q0, q0, #16
	mov	r4, #0xe000
	vdup.32	q1, r4
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r4, #0xff
	orr	r4, r4, #0x1f00
#else
	mov	r4, #0x1fff
#endif
	vdup.32	q2, r4
	vdup.32	q3, r1
	mov	r12, #0
L_mc_gmm:
	cmp	r12, r3
	bge	L_mc_gmme
	lsl	lr, r12, #1
	add	r4, r2, lr
	vld1.8	{d8-d9}, [r4]
	vmovl.u16	q5, d8
	vshl.i32	q9, q3, #31
	vshr.s32	q9, q9, #31
	vand	q6, q5, q9
	vshl.i32	q9, q3, #30
	vshr.s32	q9, q9, #31
	vshl.i32	q8, q5, #1
	vand	q8, q8, q9
	veor	q6, q6, q8
	vshl.i32	q9, q3, #29
	vshr.s32	q9, q9, #31
	vshl.i32	q8, q5, #2
	vand	q8, q8, q9
	veor	q6, q6, q8
	vshl.i32	q9, q3, #28
	vshr.s32	q9, q9, #31
	vshl.i32	q8, q5, #3
	vand	q8, q8, q9
	veor	q6, q6, q8
	vshl.i32	q9, q3, #27
	vshr.s32	q9, q9, #31
	vshl.i32	q8, q5, #4
	vand	q8, q8, q9
	veor	q6, q6, q8
	vshl.i32	q9, q3, #26
	vshr.s32	q9, q9, #31
	vshl.i32	q8, q5, #5
	vand	q8, q8, q9
	veor	q6, q6, q8
	vshl.i32	q9, q3, #25
	vshr.s32	q9, q9, #31
	vshl.i32	q8, q5, #6
	vand	q8, q8, q9
	veor	q6, q6, q8
	vshl.i32	q9, q3, #24
	vshr.s32	q9, q9, #31
	vshl.i32	q8, q5, #7
	vand	q8, q8, q9
	veor	q6, q6, q8
	vshl.i32	q9, q3, #23
	vshr.s32	q9, q9, #31
	vshl.i32	q8, q5, #8
	vand	q8, q8, q9
	veor	q6, q6, q8
	vshl.i32	q9, q3, #22
	vshr.s32	q9, q9, #31
	vshl.i32	q8, q5, #9
	vand	q8, q8, q9
	veor	q6, q6, q8
	vshl.i32	q9, q3, #21
	vshr.s32	q9, q9, #31
	vshl.i32	q8, q5, #10
	vand	q8, q8, q9
	veor	q6, q6, q8
	vshl.i32	q9, q3, #20
	vshr.s32	q9, q9, #31
	vshl.i32	q8, q5, #11
	vand	q8, q8, q9
	veor	q6, q6, q8
	vshl.i32	q9, q3, #19
	vshr.s32	q9, q9, #31
	vshl.i32	q8, q5, #12
	vand	q8, q8, q9
	veor	q6, q6, q8
	vand	q10, q6, q0
	vshr.u32	q11, q10, #9
	veor	q6, q6, q11
	vshr.u32	q11, q10, #10
	veor	q6, q6, q11
	vshr.u32	q11, q10, #12
	veor	q6, q6, q11
	vshr.u32	q11, q10, #13
	veor	q6, q6, q11
	vand	q10, q6, q1
	vshr.u32	q11, q10, #9
	veor	q6, q6, q11
	vshr.u32	q11, q10, #10
	veor	q6, q6, q11
	vshr.u32	q11, q10, #12
	veor	q6, q6, q11
	vshr.u32	q11, q10, #13
	veor	q6, q6, q11
	vand	q6, q6, q2
	vmovl.u16	q5, d9
	vshl.i32	q9, q3, #31
	vshr.s32	q9, q9, #31
	vand	q7, q5, q9
	vshl.i32	q9, q3, #30
	vshr.s32	q9, q9, #31
	vshl.i32	q8, q5, #1
	vand	q8, q8, q9
	veor	q7, q7, q8
	vshl.i32	q9, q3, #29
	vshr.s32	q9, q9, #31
	vshl.i32	q8, q5, #2
	vand	q8, q8, q9
	veor	q7, q7, q8
	vshl.i32	q9, q3, #28
	vshr.s32	q9, q9, #31
	vshl.i32	q8, q5, #3
	vand	q8, q8, q9
	veor	q7, q7, q8
	vshl.i32	q9, q3, #27
	vshr.s32	q9, q9, #31
	vshl.i32	q8, q5, #4
	vand	q8, q8, q9
	veor	q7, q7, q8
	vshl.i32	q9, q3, #26
	vshr.s32	q9, q9, #31
	vshl.i32	q8, q5, #5
	vand	q8, q8, q9
	veor	q7, q7, q8
	vshl.i32	q9, q3, #25
	vshr.s32	q9, q9, #31
	vshl.i32	q8, q5, #6
	vand	q8, q8, q9
	veor	q7, q7, q8
	vshl.i32	q9, q3, #24
	vshr.s32	q9, q9, #31
	vshl.i32	q8, q5, #7
	vand	q8, q8, q9
	veor	q7, q7, q8
	vshl.i32	q9, q3, #23
	vshr.s32	q9, q9, #31
	vshl.i32	q8, q5, #8
	vand	q8, q8, q9
	veor	q7, q7, q8
	vshl.i32	q9, q3, #22
	vshr.s32	q9, q9, #31
	vshl.i32	q8, q5, #9
	vand	q8, q8, q9
	veor	q7, q7, q8
	vshl.i32	q9, q3, #21
	vshr.s32	q9, q9, #31
	vshl.i32	q8, q5, #10
	vand	q8, q8, q9
	veor	q7, q7, q8
	vshl.i32	q9, q3, #20
	vshr.s32	q9, q9, #31
	vshl.i32	q8, q5, #11
	vand	q8, q8, q9
	veor	q7, q7, q8
	vshl.i32	q9, q3, #19
	vshr.s32	q9, q9, #31
	vshl.i32	q8, q5, #12
	vand	q8, q8, q9
	veor	q7, q7, q8
	vand	q10, q7, q0
	vshr.u32	q11, q10, #9
	veor	q7, q7, q11
	vshr.u32	q11, q10, #10
	veor	q7, q7, q11
	vshr.u32	q11, q10, #12
	veor	q7, q7, q11
	vshr.u32	q11, q10, #13
	veor	q7, q7, q11
	vand	q10, q7, q1
	vshr.u32	q11, q10, #9
	veor	q7, q7, q11
	vshr.u32	q11, q10, #10
	veor	q7, q7, q11
	vshr.u32	q11, q10, #12
	veor	q7, q7, q11
	vshr.u32	q11, q10, #13
	veor	q7, q7, q11
	vand	q7, q7, q2
	vmovn.i32	d20, q6
	vmovn.i32	d21, q7
	add	r4, r0, lr
	vld1.8	{d12-d13}, [r4]
	veor	q10, q10, q6
	vst1.8	{d20-d21}, [r4]
	add	r12, r12, #8
	b	L_mc_gmm
L_mc_gmme:
	vpop	{d8-d15}
	pop	{r4, pc}
	.size	wc_mceliece_gf_mulc_mac_neon,.-wc_mceliece_gf_mulc_mac_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_gf_mulc_mac_full_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_gf_mulc_mac_full_neon)
	.type	wc_mceliece_gf_mulc_mac_full_neon, %function
wc_mceliece_gf_mulc_mac_full_neon:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	mov	r4, r0
	mov	r5, r1
	mov	r6, r2
	mov	r7, r3
	lsr	r12, r7, #3
	lsl	r12, r12, #3
	cmp	r12, #0
	beq	L_mc_mmf_s
	mov	r0, r4
	mov	r1, r5
	mov	r2, r6
	mov	r3, r12
	bl	wc_mceliece_gf_mulc_mac_neon
L_mc_mmf_s:
	lsr	r12, r7, #3
	lsl	r12, r12, #3
	mov	r8, r12
L_mc_mmf_t:
	cmp	r8, r7
	bge	L_mc_mmf_te
	mov	r0, r5
	lsl	r9, r8, #1
	add	r10, r6, r9
	ldrh	r1, [r10]
	bl	wc_mceliece_gf_mul_scalar_neon
	lsl	r9, r8, #1
	add	r10, r4, r9
	ldrh	r11, [r10]
	eor	r11, r11, r0
	strh	r11, [r10]
	add	r8, r8, #1
	b	L_mc_mmf_t
L_mc_mmf_te:
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	wc_mceliece_gf_mulc_mac_full_neon,.-wc_mceliece_gf_mulc_mac_full_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_gf_discrepancy_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_gf_discrepancy_neon)
	.type	wc_mceliece_gf_discrepancy_neon, %function
wc_mceliece_gf_discrepancy_neon:
	push	{r4, lr}
	vpush	{d8-d15}
	veor	q13, q13, q13
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	lr, #0xff
	orr	lr, lr, #0x100
#else
	mov	lr, #0x1ff
#endif
	vdup.32	q0, lr
	vshl.i32	q0, q0, #16
	mov	lr, #0xe000
	vdup.32	q1, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	lr, #0xff
	orr	lr, lr, #0x1f00
#else
	mov	lr, #0x1fff
#endif
	vdup.32	q2, lr
	mov	r3, #0
L_mc_gdc:
	cmp	r3, r2
	bge	L_mc_gdce
	lsl	lr, r3, #1
	add	r12, r0, lr
	vld1.8	{d6-d7}, [r12]
	add	lr, r3, #7
	lsl	lr, lr, #1
	sub	r12, r1, lr
	vld1.8	{d8-d9}, [r12]
	vrev64.16	q4, q4
	vext.8	q4, q4, q4, #8
	vmovl.u16	q5, d6
	vmovl.u16	q6, d8
	vshl.i32	q10, q6, #31
	vshr.s32	q10, q10, #31
	vand	q7, q5, q10
	vshl.i32	q10, q6, #30
	vshr.s32	q10, q10, #31
	vshl.i32	q9, q5, #1
	vand	q9, q9, q10
	veor	q7, q7, q9
	vshl.i32	q10, q6, #29
	vshr.s32	q10, q10, #31
	vshl.i32	q9, q5, #2
	vand	q9, q9, q10
	veor	q7, q7, q9
	vshl.i32	q10, q6, #28
	vshr.s32	q10, q10, #31
	vshl.i32	q9, q5, #3
	vand	q9, q9, q10
	veor	q7, q7, q9
	vshl.i32	q10, q6, #27
	vshr.s32	q10, q10, #31
	vshl.i32	q9, q5, #4
	vand	q9, q9, q10
	veor	q7, q7, q9
	vshl.i32	q10, q6, #26
	vshr.s32	q10, q10, #31
	vshl.i32	q9, q5, #5
	vand	q9, q9, q10
	veor	q7, q7, q9
	vshl.i32	q10, q6, #25
	vshr.s32	q10, q10, #31
	vshl.i32	q9, q5, #6
	vand	q9, q9, q10
	veor	q7, q7, q9
	vshl.i32	q10, q6, #24
	vshr.s32	q10, q10, #31
	vshl.i32	q9, q5, #7
	vand	q9, q9, q10
	veor	q7, q7, q9
	vshl.i32	q10, q6, #23
	vshr.s32	q10, q10, #31
	vshl.i32	q9, q5, #8
	vand	q9, q9, q10
	veor	q7, q7, q9
	vshl.i32	q10, q6, #22
	vshr.s32	q10, q10, #31
	vshl.i32	q9, q5, #9
	vand	q9, q9, q10
	veor	q7, q7, q9
	vshl.i32	q10, q6, #21
	vshr.s32	q10, q10, #31
	vshl.i32	q9, q5, #10
	vand	q9, q9, q10
	veor	q7, q7, q9
	vshl.i32	q10, q6, #20
	vshr.s32	q10, q10, #31
	vshl.i32	q9, q5, #11
	vand	q9, q9, q10
	veor	q7, q7, q9
	vshl.i32	q10, q6, #19
	vshr.s32	q10, q10, #31
	vshl.i32	q9, q5, #12
	vand	q9, q9, q10
	veor	q7, q7, q9
	vand	q11, q7, q0
	vshr.u32	q12, q11, #9
	veor	q7, q7, q12
	vshr.u32	q12, q11, #10
	veor	q7, q7, q12
	vshr.u32	q12, q11, #12
	veor	q7, q7, q12
	vshr.u32	q12, q11, #13
	veor	q7, q7, q12
	vand	q11, q7, q1
	vshr.u32	q12, q11, #9
	veor	q7, q7, q12
	vshr.u32	q12, q11, #10
	veor	q7, q7, q12
	vshr.u32	q12, q11, #12
	veor	q7, q7, q12
	vshr.u32	q12, q11, #13
	veor	q7, q7, q12
	vand	q7, q7, q2
	vmovl.u16	q5, d7
	vmovl.u16	q6, d9
	vshl.i32	q10, q6, #31
	vshr.s32	q10, q10, #31
	vand	q8, q5, q10
	vshl.i32	q10, q6, #30
	vshr.s32	q10, q10, #31
	vshl.i32	q9, q5, #1
	vand	q9, q9, q10
	veor	q8, q8, q9
	vshl.i32	q10, q6, #29
	vshr.s32	q10, q10, #31
	vshl.i32	q9, q5, #2
	vand	q9, q9, q10
	veor	q8, q8, q9
	vshl.i32	q10, q6, #28
	vshr.s32	q10, q10, #31
	vshl.i32	q9, q5, #3
	vand	q9, q9, q10
	veor	q8, q8, q9
	vshl.i32	q10, q6, #27
	vshr.s32	q10, q10, #31
	vshl.i32	q9, q5, #4
	vand	q9, q9, q10
	veor	q8, q8, q9
	vshl.i32	q10, q6, #26
	vshr.s32	q10, q10, #31
	vshl.i32	q9, q5, #5
	vand	q9, q9, q10
	veor	q8, q8, q9
	vshl.i32	q10, q6, #25
	vshr.s32	q10, q10, #31
	vshl.i32	q9, q5, #6
	vand	q9, q9, q10
	veor	q8, q8, q9
	vshl.i32	q10, q6, #24
	vshr.s32	q10, q10, #31
	vshl.i32	q9, q5, #7
	vand	q9, q9, q10
	veor	q8, q8, q9
	vshl.i32	q10, q6, #23
	vshr.s32	q10, q10, #31
	vshl.i32	q9, q5, #8
	vand	q9, q9, q10
	veor	q8, q8, q9
	vshl.i32	q10, q6, #22
	vshr.s32	q10, q10, #31
	vshl.i32	q9, q5, #9
	vand	q9, q9, q10
	veor	q8, q8, q9
	vshl.i32	q10, q6, #21
	vshr.s32	q10, q10, #31
	vshl.i32	q9, q5, #10
	vand	q9, q9, q10
	veor	q8, q8, q9
	vshl.i32	q10, q6, #20
	vshr.s32	q10, q10, #31
	vshl.i32	q9, q5, #11
	vand	q9, q9, q10
	veor	q8, q8, q9
	vshl.i32	q10, q6, #19
	vshr.s32	q10, q10, #31
	vshl.i32	q9, q5, #12
	vand	q9, q9, q10
	veor	q8, q8, q9
	vand	q11, q8, q0
	vshr.u32	q12, q11, #9
	veor	q8, q8, q12
	vshr.u32	q12, q11, #10
	veor	q8, q8, q12
	vshr.u32	q12, q11, #12
	veor	q8, q8, q12
	vshr.u32	q12, q11, #13
	veor	q8, q8, q12
	vand	q11, q8, q1
	vshr.u32	q12, q11, #9
	veor	q8, q8, q12
	vshr.u32	q12, q11, #10
	veor	q8, q8, q12
	vshr.u32	q12, q11, #12
	veor	q8, q8, q12
	vshr.u32	q12, q11, #13
	veor	q8, q8, q12
	vand	q8, q8, q2
	vmovn.i32	d22, q7
	vmovn.i32	d23, q8
	veor	q13, q13, q11
	add	r3, r3, #8
	b	L_mc_gdc
L_mc_gdce:
	vext.8	q11, q13, q13, #8
	veor	q13, q13, q11
	vext.8	q11, q13, q13, #4
	veor	q13, q13, q11
	vext.8	q11, q13, q13, #2
	veor	q13, q13, q11
	vmov.u16	r4, d26[0]
	mov	r0, r4
	vpop	{d8-d15}
	pop	{r4, pc}
	.size	wc_mceliece_gf_discrepancy_neon,.-wc_mceliece_gf_discrepancy_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_aff_synd_mask_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_aff_synd_mask_neon)
	.type	wc_mceliece_aff_synd_mask_neon, %function
wc_mceliece_aff_synd_mask_neon:
	push	{r4, r5, r6, r7, lr}
	mov	r7, #13
	mov	r3, #0
L_mc_sm_i:
	cmp	r3, #32
	bge	L_mc_sm_ie
	lsl	lr, r3, #5
	add	r4, r2, lr
	vld1.8	{d0-d3}, [r4]
	mul	lr, r3, r7
	lsl	lr, lr, #5
	add	r5, r1, lr
	add	r6, r0, lr
	mov	r12, #0
L_mc_sm_k:
	vld1.8	{d4-d7}, [r5]
	vand	q2, q2, q0
	vand	q3, q3, q1
	vst1.8	{d4-d7}, [r6]
	add	r5, r5, #32
	add	r6, r6, #32
	add	r12, r12, #1
	cmp	r12, #13
	blt	L_mc_sm_k
L_mc_sm_ke:
	add	r3, r3, #1
	b	L_mc_sm_i
L_mc_sm_ie:
	pop	{r4, r5, r6, r7, pc}
	.size	wc_mceliece_aff_synd_mask_neon,.-wc_mceliece_aff_synd_mask_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_aff_fwd_out_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_aff_fwd_out_neon)
	.type	wc_mceliece_aff_fwd_out_neon, %function
wc_mceliece_aff_fwd_out_neon:
	push	{r4, r5, r6, r7, r8, r9, r10, lr}
	ldr	r3, =L_mc_aff_reversal_neon
	mov	r10, #13
	mov	r12, #0
L_mc_fwo_j:
	cmp	r12, #32
	bge	L_mc_fwo_e
	lsl	r5, r12, #1
	add	r6, r3, r5
	ldrb	lr, [r6]
	add	r6, r6, #1
	ldrb	r4, [r6]
	lsl	r5, lr, #5
	add	r7, r1, r5
	vld1.8	{d0-d3}, [r7]
	lsl	r5, r4, #5
	add	r8, r1, r5
	vld1.8	{d4-d7}, [r8]
	mul	r5, r12, r10
	add	r5, r5, r2
	lsl	r5, r5, #5
	add	r9, r0, r5
	vst1.8	{d0-d1}, [r9]
	add	r9, r9, #16
	vst1.8	{d4-d5}, [r9]
	add	r9, r9, #16
	cmp	r2, #12
	beq	L_mc_fwo_no
	vst1.8	{d2-d3}, [r9]
	add	r9, r9, #16
	vst1.8	{d6-d7}, [r9]
L_mc_fwo_no:
	add	r12, r12, #1
	b	L_mc_fwo_j
L_mc_fwo_e:
	pop	{r4, r5, r6, r7, r8, r9, r10, pc}
	.size	wc_mceliece_aff_fwd_out_neon,.-wc_mceliece_aff_fwd_out_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_aff_pack_lh2_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_aff_pack_lh2_neon)
	.type	wc_mceliece_aff_pack_lh2_neon, %function
wc_mceliece_aff_pack_lh2_neon:
	push	{r4, r5, r6, r7, lr}
	vpush	{d8-d11}
	mov	r12, #0
L_mc_packlh2_p:
	lsl	lr, r12, #5
	add	r6, r2, lr
	vld1.8	{d0-d3}, [r6]
	add	r7, r3, lr
	vld1.8	{d4-d7}, [r7]
	vmov	d8, d0
	vmov	d9, d4
	vmov	d10, d2
	vmov	d11, d6
	add	r4, r0, lr
	vst1.8	{d8-d11}, [r4]
	vmov	d8, d1
	vmov	d9, d5
	vmov	d10, d3
	vmov	d11, d7
	add	r5, r1, lr
	vst1.8	{d8-d11}, [r5]
	add	r12, r12, #1
	cmp	r12, #13
	blt	L_mc_packlh2_p
	vpop	{d8-d11}
	pop	{r4, r5, r6, r7, pc}
	.size	wc_mceliece_aff_pack_lh2_neon,.-wc_mceliece_aff_pack_lh2_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_bs_poly_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_bs_poly_neon)
	.type	wc_mceliece_bs_poly_neon, %function
wc_mceliece_bs_poly_neon:
	push	{r4, lr}
	vpush	{d8-d11}
	ldr	r2, =L_mc_bs_powers_neon
	vld1.8	{d0-d1}, [r2]
	vmov.i16	q1, #1
	mov	r3, #0
L_mc_bsp:
	cmp	r3, #8
	bge	L_mc_bspe
	lsl	r4, r3, #4
	add	r12, r1, r4
	vld1.8	{d4-d5}, [r12]
	add	r12, r12, #0x80
	vld1.8	{d6-d7}, [r12]
	vand	q4, q2, q1
	vmul.i16	q4, q4, q0
	vext.8	q5, q4, q4, #8
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #4
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #2
	vadd.i16	q4, q4, q5
	vmov.u16	lr, d8[0]
	add	r12, r0, #0
	add	r12, r12, r3
	strb	lr, [r12]
	vshr.u16	q4, q2, #1
	vand	q4, q4, q1
	vmul.i16	q4, q4, q0
	vext.8	q5, q4, q4, #8
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #4
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #2
	vadd.i16	q4, q4, q5
	vmov.u16	lr, d8[0]
	add	r12, r0, #16
	add	r12, r12, r3
	strb	lr, [r12]
	vshr.u16	q4, q2, #2
	vand	q4, q4, q1
	vmul.i16	q4, q4, q0
	vext.8	q5, q4, q4, #8
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #4
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #2
	vadd.i16	q4, q4, q5
	vmov.u16	lr, d8[0]
	add	r12, r0, #32
	add	r12, r12, r3
	strb	lr, [r12]
	vshr.u16	q4, q2, #3
	vand	q4, q4, q1
	vmul.i16	q4, q4, q0
	vext.8	q5, q4, q4, #8
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #4
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #2
	vadd.i16	q4, q4, q5
	vmov.u16	lr, d8[0]
	add	r12, r0, #48
	add	r12, r12, r3
	strb	lr, [r12]
	vshr.u16	q4, q2, #4
	vand	q4, q4, q1
	vmul.i16	q4, q4, q0
	vext.8	q5, q4, q4, #8
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #4
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #2
	vadd.i16	q4, q4, q5
	vmov.u16	lr, d8[0]
	add	r12, r0, #0x40
	add	r12, r12, r3
	strb	lr, [r12]
	vshr.u16	q4, q2, #5
	vand	q4, q4, q1
	vmul.i16	q4, q4, q0
	vext.8	q5, q4, q4, #8
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #4
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #2
	vadd.i16	q4, q4, q5
	vmov.u16	lr, d8[0]
	add	r12, r0, #0x50
	add	r12, r12, r3
	strb	lr, [r12]
	vshr.u16	q4, q2, #6
	vand	q4, q4, q1
	vmul.i16	q4, q4, q0
	vext.8	q5, q4, q4, #8
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #4
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #2
	vadd.i16	q4, q4, q5
	vmov.u16	lr, d8[0]
	add	r12, r0, #0x60
	add	r12, r12, r3
	strb	lr, [r12]
	vshr.u16	q4, q2, #7
	vand	q4, q4, q1
	vmul.i16	q4, q4, q0
	vext.8	q5, q4, q4, #8
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #4
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #2
	vadd.i16	q4, q4, q5
	vmov.u16	lr, d8[0]
	add	r12, r0, #0x70
	add	r12, r12, r3
	strb	lr, [r12]
	vshr.u16	q4, q2, #8
	vand	q4, q4, q1
	vmul.i16	q4, q4, q0
	vext.8	q5, q4, q4, #8
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #4
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #2
	vadd.i16	q4, q4, q5
	vmov.u16	lr, d8[0]
	add	r12, r0, #0x80
	add	r12, r12, r3
	strb	lr, [r12]
	vshr.u16	q4, q2, #9
	vand	q4, q4, q1
	vmul.i16	q4, q4, q0
	vext.8	q5, q4, q4, #8
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #4
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #2
	vadd.i16	q4, q4, q5
	vmov.u16	lr, d8[0]
	add	r12, r0, #0x90
	add	r12, r12, r3
	strb	lr, [r12]
	vshr.u16	q4, q2, #10
	vand	q4, q4, q1
	vmul.i16	q4, q4, q0
	vext.8	q5, q4, q4, #8
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #4
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #2
	vadd.i16	q4, q4, q5
	vmov.u16	lr, d8[0]
	add	r12, r0, #0xa0
	add	r12, r12, r3
	strb	lr, [r12]
	vshr.u16	q4, q2, #11
	vand	q4, q4, q1
	vmul.i16	q4, q4, q0
	vext.8	q5, q4, q4, #8
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #4
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #2
	vadd.i16	q4, q4, q5
	vmov.u16	lr, d8[0]
	add	r12, r0, #0xb0
	add	r12, r12, r3
	strb	lr, [r12]
	vshr.u16	q4, q2, #12
	vand	q4, q4, q1
	vmul.i16	q4, q4, q0
	vext.8	q5, q4, q4, #8
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #4
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #2
	vadd.i16	q4, q4, q5
	vmov.u16	lr, d8[0]
	add	r12, r0, #0xc0
	add	r12, r12, r3
	strb	lr, [r12]
	vand	q4, q3, q1
	vmul.i16	q4, q4, q0
	vext.8	q5, q4, q4, #8
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #4
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #2
	vadd.i16	q4, q4, q5
	vmov.u16	lr, d8[0]
	add	r12, r0, #8
	add	r12, r12, r3
	strb	lr, [r12]
	vshr.u16	q4, q3, #1
	vand	q4, q4, q1
	vmul.i16	q4, q4, q0
	vext.8	q5, q4, q4, #8
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #4
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #2
	vadd.i16	q4, q4, q5
	vmov.u16	lr, d8[0]
	add	r12, r0, #24
	add	r12, r12, r3
	strb	lr, [r12]
	vshr.u16	q4, q3, #2
	vand	q4, q4, q1
	vmul.i16	q4, q4, q0
	vext.8	q5, q4, q4, #8
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #4
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #2
	vadd.i16	q4, q4, q5
	vmov.u16	lr, d8[0]
	add	r12, r0, #40
	add	r12, r12, r3
	strb	lr, [r12]
	vshr.u16	q4, q3, #3
	vand	q4, q4, q1
	vmul.i16	q4, q4, q0
	vext.8	q5, q4, q4, #8
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #4
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #2
	vadd.i16	q4, q4, q5
	vmov.u16	lr, d8[0]
	add	r12, r0, #56
	add	r12, r12, r3
	strb	lr, [r12]
	vshr.u16	q4, q3, #4
	vand	q4, q4, q1
	vmul.i16	q4, q4, q0
	vext.8	q5, q4, q4, #8
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #4
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #2
	vadd.i16	q4, q4, q5
	vmov.u16	lr, d8[0]
	add	r12, r0, #0x48
	add	r12, r12, r3
	strb	lr, [r12]
	vshr.u16	q4, q3, #5
	vand	q4, q4, q1
	vmul.i16	q4, q4, q0
	vext.8	q5, q4, q4, #8
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #4
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #2
	vadd.i16	q4, q4, q5
	vmov.u16	lr, d8[0]
	add	r12, r0, #0x58
	add	r12, r12, r3
	strb	lr, [r12]
	vshr.u16	q4, q3, #6
	vand	q4, q4, q1
	vmul.i16	q4, q4, q0
	vext.8	q5, q4, q4, #8
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #4
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #2
	vadd.i16	q4, q4, q5
	vmov.u16	lr, d8[0]
	add	r12, r0, #0x68
	add	r12, r12, r3
	strb	lr, [r12]
	vshr.u16	q4, q3, #7
	vand	q4, q4, q1
	vmul.i16	q4, q4, q0
	vext.8	q5, q4, q4, #8
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #4
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #2
	vadd.i16	q4, q4, q5
	vmov.u16	lr, d8[0]
	add	r12, r0, #0x78
	add	r12, r12, r3
	strb	lr, [r12]
	vshr.u16	q4, q3, #8
	vand	q4, q4, q1
	vmul.i16	q4, q4, q0
	vext.8	q5, q4, q4, #8
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #4
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #2
	vadd.i16	q4, q4, q5
	vmov.u16	lr, d8[0]
	add	r12, r0, #0x88
	add	r12, r12, r3
	strb	lr, [r12]
	vshr.u16	q4, q3, #9
	vand	q4, q4, q1
	vmul.i16	q4, q4, q0
	vext.8	q5, q4, q4, #8
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #4
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #2
	vadd.i16	q4, q4, q5
	vmov.u16	lr, d8[0]
	add	r12, r0, #0x98
	add	r12, r12, r3
	strb	lr, [r12]
	vshr.u16	q4, q3, #10
	vand	q4, q4, q1
	vmul.i16	q4, q4, q0
	vext.8	q5, q4, q4, #8
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #4
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #2
	vadd.i16	q4, q4, q5
	vmov.u16	lr, d8[0]
	add	r12, r0, #0xa8
	add	r12, r12, r3
	strb	lr, [r12]
	vshr.u16	q4, q3, #11
	vand	q4, q4, q1
	vmul.i16	q4, q4, q0
	vext.8	q5, q4, q4, #8
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #4
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #2
	vadd.i16	q4, q4, q5
	vmov.u16	lr, d8[0]
	add	r12, r0, #0xb8
	add	r12, r12, r3
	strb	lr, [r12]
	vshr.u16	q4, q3, #12
	vand	q4, q4, q1
	vmul.i16	q4, q4, q0
	vext.8	q5, q4, q4, #8
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #4
	vadd.i16	q4, q4, q5
	vext.8	q5, q4, q4, #2
	vadd.i16	q4, q4, q5
	vmov.u16	lr, d8[0]
	add	r12, r0, #0xc8
	add	r12, r12, r3
	strb	lr, [r12]
	add	r3, r3, #1
	b	L_mc_bsp
L_mc_bspe:
	vpop	{d8-d11}
	pop	{r4, pc}
	.size	wc_mceliece_bs_poly_neon,.-wc_mceliece_bs_poly_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_aff_btr_net_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_aff_btr_net_neon)
	.type	wc_mceliece_aff_btr_net_neon, %function
wc_mceliece_aff_btr_net_neon:
	push	{r4, r5, r6, lr}
	ldr	r12, [sp, #16]
	lsl	r6, r12, #5
	add	lr, r0, r6
	add	r4, r1, #0x400
	vld1.8	{d0-d3}, [r4]
	add	r5, lr, #0
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x420
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x400
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r4, r1, #0x420
	vld1.8	{d0-d3}, [r4]
	add	r5, lr, #0xe0
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x460
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x420
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x460
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x440
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x460
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r4, r1, #0x440
	vld1.8	{d0-d3}, [r4]
	add	r5, lr, #0x1c0
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x4c0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x440
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x4c0
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x4e0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x4c0
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0xe0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x4e0
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x4a0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x4e0
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x4a0
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x480
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x4a0
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r4, r1, #0x480
	vld1.8	{d0-d3}, [r4]
	add	r5, lr, #0x2a0
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x580
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x480
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x580
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x5a0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x580
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0xe0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x5a0
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x5e0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x5a0
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x5e0
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x5c0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x5e0
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0x1c0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x5c0
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x540
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x5c0
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x540
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x560
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x540
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0xe0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x560
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x520
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x560
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x520
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x500
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x520
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r4, r1, #0x500
	vld1.8	{d0-d3}, [r4]
	add	r5, lr, #0x380
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x700
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x500
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x700
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x720
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x700
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0xe0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x720
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x760
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x720
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x760
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x740
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x760
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0x1c0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x740
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x7c0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x740
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x7c0
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x7e0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x7c0
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0xe0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x7e0
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x7a0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x7e0
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x7a0
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x780
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x7a0
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0x2a0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x780
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x680
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x780
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x680
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x6a0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x680
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0xe0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x6a0
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x6e0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x6a0
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x6e0
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x6c0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x6e0
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0x1c0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x6c0
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x640
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x6c0
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x640
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x660
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x640
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0xe0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x660
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x620
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x660
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x620
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x600
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x620
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r4, r1, #0x600
	vld1.8	{d0-d3}, [r4]
	add	r5, lr, #0x460
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x200
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x600
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x200
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x220
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x200
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0xe0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x220
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x260
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x220
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x260
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x240
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x260
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0x1c0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x240
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x2c0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x240
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x2c0
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x2e0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x2c0
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0xe0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x2e0
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x2a0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x2e0
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x2a0
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x280
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x2a0
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0x2a0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x280
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x380
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x280
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x380
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x3a0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x380
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0xe0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x3a0
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x3e0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x3a0
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x3e0
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x3c0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x3e0
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0x1c0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x3c0
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x340
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x3c0
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x340
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x360
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x340
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0xe0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x360
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x320
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x360
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x320
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x300
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x320
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0x380
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x300
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x100
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x300
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x100
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x120
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x100
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0xe0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x120
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x160
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x120
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x160
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x140
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x160
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0x1c0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x140
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x1c0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x140
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x1c0
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x1e0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x1c0
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0xe0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x1e0
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x1a0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x1e0
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x1a0
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x180
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x1a0
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0x2a0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x180
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x80
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x180
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x80
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0xa0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x80
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0xe0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0xa0
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0xe0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0xa0
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0xe0
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0xc0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0xe0
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0x1c0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0xc0
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x40
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0xc0
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x40
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #0x60
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x40
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0xe0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x60
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, r1, #32
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #0x60
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	add	r5, lr, #0
	vld1.8	{d0-d3}, [r5]
	add	r4, r1, #32
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r5]
	vld1.8	{d0-d3}, [r1]
	add	r4, r1, #32
	vld1.8	{d4-d7}, [r4]
	veor	q0, q0, q2
	veor	q1, q1, q3
	lsl	r6, r3, #5
	add	r5, r2, r6
	vst1.8	{d0-d1}, [r5]
	cmp	r3, #12
	beq	L_mc_btrn_nh
	add	r5, r5, #32
	vst1.8	{d2-d3}, [r5]
L_mc_btrn_nh:
	pop	{r4, r5, r6, pc}
	.size	wc_mceliece_aff_btr_net_neon,.-wc_mceliece_aff_btr_net_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_aff_btr_in_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_aff_btr_in_neon)
	.type	wc_mceliece_aff_btr_in_neon, %function
wc_mceliece_aff_btr_in_neon:
	push	{r4, r5, r6, r7, r8, r9, r10, lr}
	ldr	r3, =L_mc_aff_reversal_neon
	mov	r10, #13
	mov	r12, #0
L_mc_bti_k:
	cmp	r12, #32
	bge	L_mc_bti_e
	lsl	r5, r12, #1
	add	r6, r3, r5
	ldrb	lr, [r6]
	add	r6, r6, #1
	ldrb	r4, [r6]
	lsl	r5, lr, #5
	add	r7, r0, r5
	lsl	r5, r4, #5
	add	r8, r0, r5
	mul	r5, r12, r10
	add	r5, r5, r2
	lsl	r5, r5, #5
	add	r9, r1, r5
	vld1.8	{d0-d3}, [r9]
	vst1.8	{d0-d1}, [r7]
	vst1.8	{d2-d3}, [r8]
	cmp	r2, #12
	beq	L_mc_bti_no
	add	r9, r9, #32
	vld1.8	{d4-d7}, [r9]
	add	r6, r7, #16
	vst1.8	{d4-d5}, [r6]
	add	r6, r8, #16
	vst1.8	{d6-d7}, [r6]
L_mc_bti_no:
	add	r12, r12, #1
	b	L_mc_bti_k
L_mc_bti_e:
	pop	{r4, r5, r6, r7, r8, r9, r10, pc}
	.size	wc_mceliece_aff_btr_in_neon,.-wc_mceliece_aff_btr_in_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_bs_minmax_rows_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_bs_minmax_rows_neon)
	.type	wc_mceliece_bs_minmax_rows_neon, %function
wc_mceliece_bs_minmax_rows_neon:
	push	{r4, r5, r6, r7, r8, r9, lr}
	vpush	{d8-d13}
	ldr	r12, [sp, #76]
	lsl	r2, r2, #2
	lsl	r9, r3, #1
	add	lr, r0, r9
	ldrh	r5, [lr]
	lsl	r9, r12, #1
	add	r4, r0, r9
	ldrh	r6, [r4]
	sub	r7, r6, r5
	asr	r7, r7, #31
	vdup.32	q6, r7
	eor	r8, r5, r6
	and	r8, r8, r7
	eor	r5, r5, r8
	strh	r5, [lr]
	eor	r6, r6, r8
	strh	r6, [r4]
	mul	r9, r3, r2
	lsl	r9, r9, #3
	add	lr, r1, r9
	mul	r9, r12, r2
	lsl	r9, r9, #3
	add	r4, r1, r9
	mov	r5, #0
L_mc_mmr_c:
	cmp	r5, r2
	bge	L_mc_mmr_ce
	vld1.8	{d0-d3}, [lr]
	vld1.8	{d4-d7}, [r4]
	veor	q4, q0, q2
	veor	q5, q1, q3
	vand	q4, q4, q6
	vand	q5, q5, q6
	veor	q0, q0, q4
	veor	q1, q1, q5
	vst1.8	{d0-d3}, [lr]
	veor	q2, q2, q4
	veor	q3, q3, q5
	vst1.8	{d4-d7}, [r4]
	add	lr, lr, #32
	add	r4, r4, #32
	add	r5, r5, #4
	cmp	r5, r2
	blt	L_mc_mmr_c
L_mc_mmr_ce:
	vpop	{d8-d13}
	pop	{r4, r5, r6, r7, r8, r9, pc}
	.size	wc_mceliece_bs_minmax_rows_neon,.-wc_mceliece_bs_minmax_rows_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_bs_extract_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_bs_extract_neon)
	.type	wc_mceliece_bs_extract_neon, %function
wc_mceliece_bs_extract_neon:
	push	{r4, r5, r6, r7, r8, r9, r10, lr}
	ldr	r12, [sp, #32]
	lsr	lr, r2, #3
	and	r4, r2, #7
	cmp	r4, #0
	beq	L_mc_ext_z
	mov	r8, r0
	mov	r5, #0
L_mc_ext_ti:
	cmp	r5, r2
	bge	L_mc_ext_end
	mul	r10, r5, r3
	add	r7, r1, r10
	add	r7, r7, lr
	mov	r6, lr
L_mc_ext_tj:
	sub	r10, r12, #1
	cmp	r6, r10
	bge	L_mc_ext_tjd
	ldrh	r9, [r7]
	lsr	r9, r9, r4
	strb	r9, [r8]
	add	r7, r7, #1
	add	r8, r8, #1
	add	r6, r6, #1
	b	L_mc_ext_tj
L_mc_ext_tjd:
	ldrb	r9, [r7]
	lsr	r9, r9, r4
	strb	r9, [r8]
	add	r8, r8, #1
	add	r5, r5, #1
	b	L_mc_ext_ti
L_mc_ext_z:
	sub	r4, r12, lr
	mov	r5, #0
L_mc_ext_zi:
	cmp	r5, r2
	bge	L_mc_ext_end
	mul	r10, r5, r3
	add	r7, r1, r10
	add	r7, r7, lr
	mul	r10, r5, r4
	add	r8, r0, r10
	mov	r6, #0
L_mc_ext_zj:
	cmp	r6, r4
	bge	L_mc_ext_zjd
	ldrb	r9, [r7]
	strb	r9, [r8]
	add	r7, r7, #1
	add	r8, r8, #1
	add	r6, r6, #1
	b	L_mc_ext_zj
L_mc_ext_zjd:
	add	r5, r5, #1
	b	L_mc_ext_zi
L_mc_ext_end:
	pop	{r4, r5, r6, r7, r8, r9, r10, pc}
	.size	wc_mceliece_bs_extract_neon,.-wc_mceliece_bs_extract_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_bs_tri_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_bs_tri_neon)
	.type	wc_mceliece_bs_tri_neon, %function
wc_mceliece_bs_tri_neon:
	push	{r4, r5, r6, r7, r8, r9, r10, lr}
	ldr	r12, [sp, #32]
	ldr	lr, [sp, #36]
	mul	r7, r2, r3
	lsl	r7, r7, #3
	add	r4, r0, r7
L_mc_tri_i:
	cmp	r12, lr
	bge	L_mc_tri_ie
	lsr	r7, r12, #3
	add	r10, r1, r7
	ldrb	r9, [r10]
	and	r7, r12, #7
	lsr	r9, r9, r7
	and	r9, r9, #1
	neg	r8, r9
	vdup.32	q3, r8
	mul	r7, r12, r3
	lsl	r7, r7, #3
	add	r5, r0, r7
	mov	r10, r4
	mov	r7, r5
	mov	r6, #0
L_mc_tri_c:
	cmp	r6, r3
	bge	L_mc_tri_ce
	vld1.8	{d0-d1}, [r10]
	vld1.8	{d2-d3}, [r7]
	vand	q2, q1, q3
	veor	q0, q0, q2
	vst1.8	{d0-d1}, [r10]
	add	r10, r10, #16
	add	r7, r7, #16
	add	r6, r6, #2
	cmp	r6, r3
	blt	L_mc_tri_c
L_mc_tri_ce:
	add	r12, r12, #1
	b	L_mc_tri_i
L_mc_tri_ie:
	pop	{r4, r5, r6, r7, r8, r9, r10, pc}
	.size	wc_mceliece_bs_tri_neon,.-wc_mceliece_bs_tri_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_u64_sort_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_u64_sort_neon)
	.type	wc_mceliece_u64_sort_neon, %function
wc_mceliece_u64_sort_neon:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	mov	r4, r0
	mov	r5, r1
	cmp	r5, #2
	blt	L_mc_us_end
	mov	r6, #1
L_mc_us_top:
	sub	r3, r5, r6
	cmp	r6, r3
	bge	L_mc_us_tope
	lsl	r6, r6, #1
	b	L_mc_us_top
L_mc_us_tope:
	mov	r7, r6
L_mc_us_p:
	cmp	r7, #0
	beq	L_mc_us_pe
	mov	r11, #0
L_mc_us_bs:
	sub	r3, r5, r7
	cmp	r11, r3
	bge	L_mc_us_bse
	sub	r10, r5, r7
	sub	r10, r10, r11
	cmp	r10, r7
	ble	L_mc_us_l1
	mov	r10, r7
L_mc_us_l1:
	lsl	r3, r11, #3
	add	r0, r4, r3
	add	r12, r11, r7
	lsl	r12, r12, #3
	add	r1, r4, r12
	mov	r2, r10
	bl	wc_mceliece_u64_minmax_vec_neon
	add	r11, r11, r7
	add	r11, r11, r7
	b	L_mc_us_bs
L_mc_us_bse:
	mov	r9, #0
	mov	r8, r6
L_mc_us_q:
	cmp	r8, r7
	ble	L_mc_us_qe
L_mc_us_w:
	sub	r3, r5, r8
	cmp	r9, r3
	bge	L_mc_us_we
	and	r3, r9, r7
	cmp	r3, #0
	beq	L_mc_us_sel
	sub	r3, r7, #1
	orr	r9, r9, r3
	add	r9, r9, #1
	b	L_mc_us_w
L_mc_us_sel:
	neg	r3, r7
	and	r3, r9, r3
	add	r3, r3, r7
	sub	r10, r3, r9
	sub	r12, r5, r8
	cmp	r3, r12
	ble	L_mc_us_l2
	sub	r10, r12, r9
L_mc_us_l2:
	mov	r11, r8
L_mc_us_r:
	cmp	r11, r7
	ble	L_mc_us_re
	add	r3, r9, r7
	lsl	r3, r3, #3
	add	r0, r4, r3
	add	r12, r9, r11
	lsl	r12, r12, #3
	add	r1, r4, r12
	mov	r2, r10
	bl	wc_mceliece_u64_minmax_vec_neon
	lsr	r11, r11, #1
	b	L_mc_us_r
L_mc_us_re:
	add	r9, r9, r10
	b	L_mc_us_w
L_mc_us_we:
	lsr	r8, r8, #1
	b	L_mc_us_q
L_mc_us_qe:
	lsr	r7, r7, #1
	b	L_mc_us_p
L_mc_us_pe:
L_mc_us_end:
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	wc_mceliece_u64_sort_neon,.-wc_mceliece_u64_sort_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_bs_composeinv_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_bs_composeinv_neon)
	.type	wc_mceliece_bs_composeinv_neon, %function
wc_mceliece_bs_composeinv_neon:
	push	{r4, r5, r6, r7, r8, r9, r10, lr}
	ldr	r6, [sp, #32]
	mov	r4, r0
	mov	r5, r1
	mov	r10, #0
	mov	r7, r6
	mov	r12, #0
L_mc_cinv_p:
	cmp	r12, r4
	bge	L_mc_cinv_pe
	ldrh	r8, [r3]
	lsl	r8, r8, #16
	ldrh	r9, [r2]
	orr	r8, r8, r9
	vmov	d0, r8, r10
	vst1.8	{d0}, [r7]
	add	r2, r2, #2
	add	r3, r3, #2
	add	r7, r7, #8
	add	r12, r12, #1
	b	L_mc_cinv_p
L_mc_cinv_pe:
	mov	r0, r6
	mov	r1, r4
	bl	wc_mceliece_u64_sort_neon
	mov	r7, r6
	mov	r2, r5
	mov	r12, #0
L_mc_cinv_u:
	cmp	r12, r4
	bge	L_mc_cinv_ue
	ldr	r8, [r7]
	strh	r8, [r2]
	add	r7, r7, #8
	add	r2, r2, #2
	add	r12, r12, #1
	b	L_mc_cinv_u
L_mc_cinv_ue:
	pop	{r4, r5, r6, r7, r8, r9, r10, pc}
	.size	wc_mceliece_bs_composeinv_neon,.-wc_mceliece_bs_composeinv_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_mont_batch_inv_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_mont_batch_inv_neon)
	.type	wc_mceliece_mont_batch_inv_neon, %function
wc_mceliece_mont_batch_inv_neon:
	push	{r4, r5, r6, r7, r8, r9, r10, lr}
	ldr	r10, [sp, #32]
	mov	r4, r0
	mov	r5, r1
	mov	r6, r2
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r8, #0xa0
	orr	r8, r8, #0x100
#else
	mov	r8, #0x1a0
#endif
	cmp	r10, #0
	beq	L_mc_mbi_sqe
	mov	r7, #0
L_mc_mbi_sq:
	cmp	r7, #32
	bge	L_mc_mbi_sqe
	mul	r12, r7, r8
	add	r0, r5, r12
	mov	r1, r0
	mov	r2, r0
	add	r3, r6, #0x340
	bl	wc_mceliece_aff_v256_mul_neon
	add	r7, r7, #1
	b	L_mc_mbi_sq
L_mc_mbi_sqe:
	add	r9, r5, #0
	vld1.8	{d0-d3}, [r9]
	add	r9, r4, #0
	vst1.8	{d0-d3}, [r9]
	add	r9, r5, #32
	vld1.8	{d0-d3}, [r9]
	add	r9, r4, #32
	vst1.8	{d0-d3}, [r9]
	add	r9, r5, #0x40
	vld1.8	{d0-d3}, [r9]
	add	r9, r4, #0x40
	vst1.8	{d0-d3}, [r9]
	add	r9, r5, #0x60
	vld1.8	{d0-d3}, [r9]
	add	r9, r4, #0x60
	vst1.8	{d0-d3}, [r9]
	add	r9, r5, #0x80
	vld1.8	{d0-d3}, [r9]
	add	r9, r4, #0x80
	vst1.8	{d0-d3}, [r9]
	add	r9, r5, #0xa0
	vld1.8	{d0-d3}, [r9]
	add	r9, r4, #0xa0
	vst1.8	{d0-d3}, [r9]
	add	r9, r5, #0xc0
	vld1.8	{d0-d3}, [r9]
	add	r9, r4, #0xc0
	vst1.8	{d0-d3}, [r9]
	add	r9, r5, #0xe0
	vld1.8	{d0-d3}, [r9]
	add	r9, r4, #0xe0
	vst1.8	{d0-d3}, [r9]
	add	r9, r5, #0x100
	vld1.8	{d0-d3}, [r9]
	add	r9, r4, #0x100
	vst1.8	{d0-d3}, [r9]
	add	r9, r5, #0x120
	vld1.8	{d0-d3}, [r9]
	add	r9, r4, #0x120
	vst1.8	{d0-d3}, [r9]
	add	r9, r5, #0x140
	vld1.8	{d0-d3}, [r9]
	add	r9, r4, #0x140
	vst1.8	{d0-d3}, [r9]
	add	r9, r5, #0x160
	vld1.8	{d0-d3}, [r9]
	add	r9, r4, #0x160
	vst1.8	{d0-d3}, [r9]
	add	r9, r5, #0x180
	vld1.8	{d0-d3}, [r9]
	add	r9, r4, #0x180
	vst1.8	{d0-d3}, [r9]
	mov	r7, #1
L_mc_mbi_pf:
	cmp	r7, #32
	bge	L_mc_mbi_pfe
	mul	r12, r7, r8
	add	r0, r4, r12
	sub	r1, r0, #0x1a0
	add	r2, r5, r12
	add	r3, r6, #0x340
	bl	wc_mceliece_aff_v256_mul_neon
	add	r7, r7, #1
	b	L_mc_mbi_pf
L_mc_mbi_pfe:
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r12, #0x60
	orr	r12, r12, #0x3200
#else
	mov	r12, #0x3260
#endif
	mov	r0, r6
	add	r1, r4, r12
	add	r2, r6, #0x660
	add	r3, r6, #0x340
	bl	wc_mceliece_aff_inv256_neon
	mov	r7, #31
L_mc_mbi_sf:
	cmp	r7, #1
	blt	L_mc_mbi_sfe
	mul	r12, r7, r8
	add	r0, r6, #0x1a0
	mov	r1, r6
	add	r2, r4, r12
	sub	r2, r2, #0x1a0
	add	r3, r6, #0x340
	bl	wc_mceliece_aff_v256_mul_neon
	mov	r0, r6
	mov	r1, r6
	mul	r12, r7, r8
	add	r2, r5, r12
	add	r3, r6, #0x340
	bl	wc_mceliece_aff_v256_mul_neon
	mul	r12, r7, r8
	add	r0, r4, r12
	add	r1, r6, #0x1a0
	add	r9, r1, #0
	vld1.8	{d0-d3}, [r9]
	add	r9, r0, #0
	vst1.8	{d0-d3}, [r9]
	add	r9, r1, #32
	vld1.8	{d0-d3}, [r9]
	add	r9, r0, #32
	vst1.8	{d0-d3}, [r9]
	add	r9, r1, #0x40
	vld1.8	{d0-d3}, [r9]
	add	r9, r0, #0x40
	vst1.8	{d0-d3}, [r9]
	add	r9, r1, #0x60
	vld1.8	{d0-d3}, [r9]
	add	r9, r0, #0x60
	vst1.8	{d0-d3}, [r9]
	add	r9, r1, #0x80
	vld1.8	{d0-d3}, [r9]
	add	r9, r0, #0x80
	vst1.8	{d0-d3}, [r9]
	add	r9, r1, #0xa0
	vld1.8	{d0-d3}, [r9]
	add	r9, r0, #0xa0
	vst1.8	{d0-d3}, [r9]
	add	r9, r1, #0xc0
	vld1.8	{d0-d3}, [r9]
	add	r9, r0, #0xc0
	vst1.8	{d0-d3}, [r9]
	add	r9, r1, #0xe0
	vld1.8	{d0-d3}, [r9]
	add	r9, r0, #0xe0
	vst1.8	{d0-d3}, [r9]
	add	r9, r1, #0x100
	vld1.8	{d0-d3}, [r9]
	add	r9, r0, #0x100
	vst1.8	{d0-d3}, [r9]
	add	r9, r1, #0x120
	vld1.8	{d0-d3}, [r9]
	add	r9, r0, #0x120
	vst1.8	{d0-d3}, [r9]
	add	r9, r1, #0x140
	vld1.8	{d0-d3}, [r9]
	add	r9, r0, #0x140
	vst1.8	{d0-d3}, [r9]
	add	r9, r1, #0x160
	vld1.8	{d0-d3}, [r9]
	add	r9, r0, #0x160
	vst1.8	{d0-d3}, [r9]
	add	r9, r1, #0x180
	vld1.8	{d0-d3}, [r9]
	add	r9, r0, #0x180
	vst1.8	{d0-d3}, [r9]
	sub	r7, r7, #1
	b	L_mc_mbi_sf
L_mc_mbi_sfe:
	mov	r0, r4
	mov	r1, r6
	add	r9, r1, #0
	vld1.8	{d0-d3}, [r9]
	add	r9, r0, #0
	vst1.8	{d0-d3}, [r9]
	add	r9, r1, #32
	vld1.8	{d0-d3}, [r9]
	add	r9, r0, #32
	vst1.8	{d0-d3}, [r9]
	add	r9, r1, #0x40
	vld1.8	{d0-d3}, [r9]
	add	r9, r0, #0x40
	vst1.8	{d0-d3}, [r9]
	add	r9, r1, #0x60
	vld1.8	{d0-d3}, [r9]
	add	r9, r0, #0x60
	vst1.8	{d0-d3}, [r9]
	add	r9, r1, #0x80
	vld1.8	{d0-d3}, [r9]
	add	r9, r0, #0x80
	vst1.8	{d0-d3}, [r9]
	add	r9, r1, #0xa0
	vld1.8	{d0-d3}, [r9]
	add	r9, r0, #0xa0
	vst1.8	{d0-d3}, [r9]
	add	r9, r1, #0xc0
	vld1.8	{d0-d3}, [r9]
	add	r9, r0, #0xc0
	vst1.8	{d0-d3}, [r9]
	add	r9, r1, #0xe0
	vld1.8	{d0-d3}, [r9]
	add	r9, r0, #0xe0
	vst1.8	{d0-d3}, [r9]
	add	r9, r1, #0x100
	vld1.8	{d0-d3}, [r9]
	add	r9, r0, #0x100
	vst1.8	{d0-d3}, [r9]
	add	r9, r1, #0x120
	vld1.8	{d0-d3}, [r9]
	add	r9, r0, #0x120
	vst1.8	{d0-d3}, [r9]
	add	r9, r1, #0x140
	vld1.8	{d0-d3}, [r9]
	add	r9, r0, #0x140
	vst1.8	{d0-d3}, [r9]
	add	r9, r1, #0x160
	vld1.8	{d0-d3}, [r9]
	add	r9, r0, #0x160
	vst1.8	{d0-d3}, [r9]
	add	r9, r1, #0x180
	vld1.8	{d0-d3}, [r9]
	add	r9, r0, #0x180
	vst1.8	{d0-d3}, [r9]
	pop	{r4, r5, r6, r7, r8, r9, r10, pc}
	.size	wc_mceliece_mont_batch_inv_neon,.-wc_mceliece_mont_batch_inv_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_pk_gen_elim_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_pk_gen_elim_neon)
	.type	wc_mceliece_pk_gen_elim_neon, %function
wc_mceliece_pk_gen_elim_neon:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	vpush	{d8-d13}
	ldr	r11, [sp, #84]
	ldr	r9, [sp, #88]
	lsl	lr, r11, #3
	lsr	r11, r9, #3
	add	lr, lr, r11
	and	r9, r9, #7
	mov	r4, #1
	lsl	r4, r4, r9
	mul	r9, r1, r3
	lsl	r9, r9, #3
	add	r12, r0, r9
	add	r5, r1, #1
L_mc_pke_kk:
	cmp	r5, r2
	bge	L_mc_pke_kke
	mul	r9, r5, r3
	lsl	r9, r9, #3
	add	r6, r0, r9
	add	r10, r6, lr
	ldrb	r11, [r10]
	and	r7, r11, r4
	rsb	r11, r7, #0
	orr	r11, r11, r7
	asr	r8, r11, #31
	vdup.32	q6, r8
	lsl	r8, r3, #3
	mov	r9, #0
L_mc_pke_c:
	add	r10, r12, r9
	vld1.8	{d4-d7}, [r10]
	add	r10, r6, r9
	vld1.8	{d0-d3}, [r10]
	vand	q4, q2, q6
	vand	q5, q3, q6
	veor	q0, q0, q4
	veor	q1, q1, q5
	vst1.8	{d0-d3}, [r10]
	add	r9, r9, #32
	cmp	r9, r8
	blt	L_mc_pke_c
L_mc_pke_ce:
	add	r10, r6, lr
	ldrb	r11, [r10]
	orr	r11, r11, r7
	strb	r11, [r10]
	add	r5, r5, #1
	b	L_mc_pke_kk
L_mc_pke_kke:
	vpop	{d8-d13}
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	wc_mceliece_pk_gen_elim_neon,.-wc_mceliece_pk_gen_elim_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_pk_gen_cswap_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_pk_gen_cswap_neon)
	.type	wc_mceliece_pk_gen_cswap_neon, %function
wc_mceliece_pk_gen_cswap_neon:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	vpush	{d8-d13}
	sub	sp, sp, #4
	ldr	r12, [sp, #88]
	ldr	r7, [sp, #92]
	ldr	r8, [sp, #96]
	lsl	r9, r7, #3
	lsr	r10, r8, #3
	add	r9, r9, r10
	str	r9, [sp]
	and	r4, r8, #7
	mul	r7, r2, r12
	lsl	r7, r7, #3
	add	lr, r0, r7
	add	r5, r2, #1
L_mc_pkc_kk:
	cmp	r5, r3
	bge	L_mc_pkc_kke
	mul	r7, r5, r12
	lsl	r7, r7, #3
	add	r6, r0, r7
	ldr	r11, [sp]
	add	r10, lr, r11
	ldrb	r7, [r10]
	lsr	r7, r7, r4
	and	r7, r7, #1
	add	r10, r6, r11
	ldrb	r8, [r10]
	lsr	r8, r8, r4
	and	r8, r8, #1
	eor	r7, r7, #1
	and	r9, r8, r7
	neg	r9, r9
	vdup.32	q6, r9
	lsl	r10, r2, #1
	add	r10, r1, r10
	ldrh	r7, [r10]
	lsl	r10, r5, #1
	add	r10, r1, r10
	ldrh	r8, [r10]
	eor	r11, r7, r8
	and	r11, r11, r9
	eor	r8, r8, r11
	strh	r8, [r10]
	eor	r7, r7, r11
	lsl	r10, r2, #1
	add	r10, r1, r10
	strh	r7, [r10]
	mov	r9, lr
	mov	r10, r6
	mov	r7, #0
L_mc_pkc_c:
	cmp	r7, r12
	bge	L_mc_pkc_ce
	vld1.8	{d0-d3}, [r9]
	vld1.8	{d4-d7}, [r10]
	veor	q4, q0, q2
	veor	q5, q1, q3
	vand	q4, q4, q6
	vand	q5, q5, q6
	veor	q0, q0, q4
	veor	q1, q1, q5
	vst1.8	{d0-d3}, [r9]
	veor	q2, q2, q4
	veor	q3, q3, q5
	vst1.8	{d4-d7}, [r10]
	add	r9, r9, #32
	add	r10, r10, #32
	add	r7, r7, #4
	cmp	r7, r12
	blt	L_mc_pkc_c
L_mc_pkc_ce:
	add	r5, r5, #1
	b	L_mc_pkc_kk
L_mc_pkc_kke:
	add	sp, sp, #4
	vpop	{d8-d13}
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	wc_mceliece_pk_gen_cswap_neon,.-wc_mceliece_pk_gen_cswap_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_bs_par_fill_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_bs_par_fill_neon)
	.type	wc_mceliece_bs_par_fill_neon, %function
wc_mceliece_bs_par_fill_neon:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	sub	sp, sp, #8
	str	r2, [sp]
	ldr	r7, [sp, #44]
	ldr	r8, [sp, #48]
	ldr	r9, [sp, #52]
	ldr	r12, [sp, #56]
	str	r12, [sp, #4]
	mov	r4, r0
	mov	r5, r1
	mov	r6, r3
	mov	r10, #0
L_mc_prf_i:
	cmp	r10, r6
	bge	L_mc_prf_ie
	mov	r11, #0
L_mc_prf_b:
	cmp	r11, r8
	bge	L_mc_prf_be
	cmp	r11, r9
	bge	L_mc_prf_sk
	cmp	r10, #0
	beq	L_mc_prf_nm
	mul	r0, r11, r7
	lsl	r0, r0, #2
	lsl	r0, r0, #3
	add	r1, r5, r0
	ldr	r2, [sp]
	add	r2, r2, r0
	ldr	r3, [sp, #4]
	mov	r0, r1
	bl	wc_mceliece_aff_v256_mul_neon
L_mc_prf_nm:
	mul	r1, r11, r7
	lsl	r1, r1, #2
	lsl	r1, r1, #3
	add	r1, r5, r1
	lsl	r3, r8, #2
	mul	r0, r10, r7
	mul	r0, r0, r3
	lsl	r12, r11, #2
	add	r0, r0, r12
	lsl	r0, r0, #3
	add	r2, r4, r0
	lsl	r3, r3, #3
	mov	r12, r7
L_mc_prf_kk:
	vld1.8	{d0-d3}, [r1]
	vst1.8	{d0-d3}, [r2]
	add	r1, r1, #32
	add	r2, r2, r3
	subs	r12, r12, #1
	bne	L_mc_prf_kk
L_mc_prf_sk:
	add	r11, r11, #1
	b	L_mc_prf_b
L_mc_prf_be:
	add	r10, r10, #1
	b	L_mc_prf_i
L_mc_prf_ie:
	add	sp, sp, #8
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	wc_mceliece_bs_par_fill_neon,.-wc_mceliece_bs_par_fill_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_bs_lu_fill_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_bs_lu_fill_neon)
	.type	wc_mceliece_bs_lu_fill_neon, %function
wc_mceliece_bs_lu_fill_neon:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	sub	sp, sp, #8
	str	r2, [sp]
	ldr	r7, [sp, #44]
	ldr	r8, [sp, #48]
	ldr	r9, [sp, #52]
	ldr	r12, [sp, #56]
	str	r12, [sp, #4]
	mov	r4, r0
	mov	r5, r1
	mov	r6, r3
	mov	r10, #0
L_mc_luf_i:
	cmp	r10, r6
	bge	L_mc_luf_ie
	mov	r11, #0
L_mc_luf_j:
	cmp	r11, r8
	bge	L_mc_luf_je
	cmp	r10, #0
	beq	L_mc_luf_nm
	mul	r0, r11, r7
	lsl	r0, r0, #2
	lsl	r0, r0, #3
	add	r1, r5, r0
	ldr	r2, [sp]
	add	r2, r2, r0
	ldr	r3, [sp, #4]
	mov	r0, r1
	bl	wc_mceliece_aff_v256_mul_neon
L_mc_luf_nm:
	mul	r0, r10, r7
	mul	r0, r0, r9
	lsl	r12, r11, #2
	add	r0, r0, r12
	lsl	r0, r0, #3
	add	r2, r4, r0
	mul	r1, r11, r7
	lsl	r1, r1, #2
	lsl	r1, r1, #3
	add	r1, r5, r1
	lsl	r3, r9, #3
	mov	r12, r7
L_mc_luf_kk:
	vld1.8	{d0-d3}, [r1]
	vst1.8	{d0-d3}, [r2]
	add	r1, r1, #32
	add	r2, r2, r3
	subs	r12, r12, #1
	bne	L_mc_luf_kk
	add	r11, r11, #1
	b	L_mc_luf_j
L_mc_luf_je:
	add	r10, r10, #1
	b	L_mc_luf_i
L_mc_luf_ie:
	add	sp, sp, #8
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	wc_mceliece_bs_lu_fill_neon,.-wc_mceliece_bs_lu_fill_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_bs_sort_rows_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_bs_sort_rows_neon)
	.type	wc_mceliece_bs_sort_rows_neon, %function
wc_mceliece_bs_sort_rows_neon:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	sub	sp, sp, #12
	mov	r4, r0
	mov	r5, r1
	mov	r6, r2
	mov	r7, r3
	mov	r0, #1
L_mc_srt_tw:
	mov	r1, #1
	lsl	r1, r1, r0
	cmp	r1, r7
	bge	L_mc_srt_twe
	add	r0, r0, #1
	b	L_mc_srt_tw
L_mc_srt_twe:
	str	r0, [sp, #4]
	sub	r8, r0, #1
L_mc_srt_j:
	cmp	r8, #0
	blt	L_mc_srt_je
	ldr	r0, [sp, #4]
	mov	r1, #1
	sub	r0, r0, #1
	lsl	r1, r1, r0
	str	r1, [sp, #8]
	mov	r9, #0
	mov	r0, #1
	lsl	r0, r0, r8
	mov	r10, r0
L_mc_srt_ps:
	mov	r11, #0
L_mc_srt_i:
	sub	r12, r7, r10
	cmp	r11, r12
	bge	L_mc_srt_ie
	mov	r0, #1
	lsl	r0, r0, r8
	and	r1, r11, r0
	cmp	r1, r9
	bne	L_mc_srt_sk
	add	r1, r11, r10
	str	r1, [sp]
	mov	r0, r4
	mov	r1, r5
	mov	r2, r6
	mov	r3, r11
	bl	wc_mceliece_bs_minmax_rows_neon
L_mc_srt_sk:
	add	r11, r11, #1
	b	L_mc_srt_i
L_mc_srt_ie:
	mov	r0, #1
	lsl	r0, r0, r8
	ldr	r1, [sp, #8]
	cmp	r1, r0
	beq	L_mc_srt_pse
	sub	r10, r1, r0
	lsr	r1, r1, #1
	str	r1, [sp, #8]
	mov	r9, r0
	b	L_mc_srt_ps
L_mc_srt_pse:
	sub	r8, r8, #1
	b	L_mc_srt_j
L_mc_srt_je:
	add	sp, sp, #12
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	wc_mceliece_bs_sort_rows_neon,.-wc_mceliece_bs_sort_rows_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_bs_pk_gen_reduce_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_bs_pk_gen_reduce_neon)
	.type	wc_mceliece_bs_pk_gen_reduce_neon, %function
wc_mceliece_bs_pk_gen_reduce_neon:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	sub	sp, sp, #12
	mov	r4, r0
	mov	r5, r1
	mov	r6, r2
	mov	r7, r3
	ldr	r8, [sp, #48]
	ldr	r9, [sp, #52]
	ldr	r10, [sp, #56]
	mov	r11, #0
L_mc_pgr_r:
	cmp	r11, r6
	bge	L_mc_pgr_re
	cmp	r8, #0
	beq	L_mc_pgr_sk
	sub	r12, r6, #32
	cmp	r11, r12
	bne	L_mc_pgr_sk
	str	r10, [sp]
	mov	r0, r4
	mov	r1, r7
	mov	r2, r6
	mov	r3, r9
	bl	wc_mceliece_bs_mov_columns_neon
	cmp	r0, #0
	bne	L_mc_pgr_f
L_mc_pgr_sk:
	lsr	r12, r11, #6
	and	r0, r11, #63
	str	r7, [sp]
	str	r12, [sp, #4]
	str	r0, [sp, #8]
	mov	r0, r4
	mov	r1, r5
	mov	r2, r11
	mov	r3, r6
	bl	wc_mceliece_pk_gen_cswap_neon
	lsr	r0, r11, #6
	and	r1, r11, #63
	mul	r2, r11, r7
	add	r2, r2, r0
	lsl	r2, r2, #3
	lsr	r3, r1, #3
	add	r2, r2, r3
	add	r2, r4, r2
	ldrb	r2, [r2]
	and	r3, r1, #7
	lsr	r2, r2, r3
	and	r2, r2, #1
	cmp	r2, #0
	beq	L_mc_pgr_f
	lsr	r0, r11, #6
	and	r1, r11, #63
	str	r0, [sp]
	str	r1, [sp, #4]
	mov	r0, r4
	mov	r1, r11
	mov	r2, r6
	mov	r3, r7
	bl	wc_mceliece_pk_gen_elim_neon
	add	r11, r11, #1
	b	L_mc_pgr_r
L_mc_pgr_re:
	mov	r0, #0
	b	L_mc_pgr_e
L_mc_pgr_f:
	mov	r0, #0
	sub	r0, r0, #1
L_mc_pgr_e:
	add	sp, sp, #12
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	wc_mceliece_bs_pk_gen_reduce_neon,.-wc_mceliece_bs_pk_gen_reduce_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_berlekamp_massey_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_berlekamp_massey_neon)
	.type	wc_mceliece_berlekamp_massey_neon, %function
wc_mceliece_berlekamp_massey_neon:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	sub	sp, sp, #8
	str	r0, [sp]
	mov	r4, r1
	str	r2, [sp, #4]
	add	r5, r3, #0x200
	mov	r0, #0
	mov	r1, #0
L_mc_bm_in:
	ldr	r2, [sp, #4]
	cmp	r1, r2
	bgt	L_mc_bm_ine
	lsl	r2, r1, #1
	add	r12, r5, r2
	strh	r0, [r12]
	add	r12, r12, #0x200
	strh	r0, [r12]
	add	r1, r1, #1
	b	L_mc_bm_in
L_mc_bm_ine:
	mov	r0, #1
	strh	r0, [r5]
	add	r12, r5, #0x200
	add	r12, r12, #2
	strh	r0, [r12]
	mov	r7, #0
	mov	r8, #1
	mov	r6, #0
L_mc_bm_n:
	ldr	r0, [sp, #4]
	lsl	r11, r0, #1
	cmp	r6, r11
	bge	L_mc_bm_ne
	mov	r9, #0
	ldr	r0, [sp, #4]
	mov	r11, r0
	cmp	r6, r0
	bge	L_mc_bm_d1
	mov	r11, r6
L_mc_bm_d1:
	add	r11, r11, #1
	lsr	r11, r11, #3
	lsl	r11, r11, #3
	cmp	r11, #0
	beq	L_mc_bm_dt
	mov	r0, r5
	lsl	r2, r6, #1
	add	r1, r4, r2
	mov	r2, r11
	bl	wc_mceliece_gf_discrepancy_neon
	mov	r9, r0
L_mc_bm_dt:
	ldr	r0, [sp, #4]
	mov	r11, r0
	cmp	r6, r0
	bge	L_mc_bm_d2
	mov	r11, r6
L_mc_bm_d2:
	add	r0, r11, #1
	lsr	r0, r0, #3
	lsl	r0, r0, #3
	mov	r10, r0
L_mc_bm_dte:
	cmp	r10, r11
	bgt	L_mc_bm_zc
	lsl	r0, r10, #1
	add	r0, r5, r0
	ldrh	r0, [r0]
	sub	r1, r6, r10
	lsl	r1, r1, #1
	add	r1, r4, r1
	ldrh	r1, [r1]
	bl	wc_mceliece_gf_mul_scalar_neon
	eor	r9, r9, r0
	add	r10, r10, #1
	b	L_mc_bm_dte
L_mc_bm_zc:
	mov	r12, #0
L_mc_bm_tce:
	ldr	r0, [sp, #4]
	cmp	r12, r0
	bgt	L_mc_bm_zce
	lsl	r0, r12, #1
	add	r1, r5, r0
	ldrh	r2, [r1]
	sub	r1, r1, #0x200
	strh	r2, [r1]
	add	r1, r5, r0
	mov	r3, #0
	strh	r3, [r1]
	add	r12, r12, #1
	b	L_mc_bm_tce
L_mc_bm_zce:
	ldr	r0, [sp, #4]
	add	r0, r0, #1
	lsr	r0, r0, #3
	lsl	r0, r0, #3
	cmp	r0, #0
	beq	L_mc_bm_msk
	mov	r11, r0
	mov	r0, r5
	mov	r1, r8
	sub	r2, r5, #0x200
	mov	r3, r11
	bl	wc_mceliece_gf_mulc_mac_neon
	mov	r0, r5
	mov	r1, r9
	add	r2, r5, #0x200
	mov	r3, r11
	bl	wc_mceliece_gf_mulc_mac_neon
L_mc_bm_msk:
	ldr	r0, [sp, #4]
	add	r0, r0, #1
	lsr	r0, r0, #3
	lsl	r0, r0, #3
	mov	r10, r0
L_mc_bm_mt:
	ldr	r0, [sp, #4]
	cmp	r10, r0
	bgt	L_mc_bm_mte
	lsl	r0, r10, #1
	sub	r1, r5, #0x200
	add	r1, r1, r0
	ldrh	r1, [r1]
	mov	r0, r8
	bl	wc_mceliece_gf_mul_scalar_neon
	lsl	r1, r10, #1
	add	r1, r5, r1
	ldrh	r2, [r1]
	eor	r2, r2, r0
	strh	r2, [r1]
	lsl	r0, r10, #1
	add	r1, r5, #0x200
	add	r1, r1, r0
	ldrh	r1, [r1]
	mov	r0, r9
	bl	wc_mceliece_gf_mul_scalar_neon
	lsl	r1, r10, #1
	add	r1, r5, r1
	ldrh	r2, [r1]
	eor	r2, r2, r0
	strh	r2, [r1]
	add	r10, r10, #1
	b	L_mc_bm_mt
L_mc_bm_mte:
	sub	r0, r9, #1
	lsr	r0, r0, #31
	sub	r0, r0, #1
	lsl	r1, r7, #1
	sub	r2, r6, r1
	lsr	r2, r2, #31
	sub	r2, r2, #1
	and	r2, r2, r0
	add	r1, r6, #1
	sub	r1, r1, r7
	eor	r0, r7, r1
	and	r0, r0, r2
	eor	r7, r7, r0
	mov	r12, #0
L_mc_bm_bu:
	ldr	r0, [sp, #4]
	cmp	r12, r0
	bgt	L_mc_bm_bue
	lsl	r0, r12, #1
	add	r1, r5, #0x200
	add	r1, r1, r0
	ldrh	r3, [r1]
	sub	r0, r1, #0x400
	ldrh	r0, [r0]
	eor	r0, r0, r3
	and	r0, r0, r2
	eor	r3, r3, r0
	strh	r3, [r1]
	add	r12, r12, #1
	b	L_mc_bm_bu
L_mc_bm_bue:
	eor	r0, r8, r9
	and	r0, r0, r2
	eor	r8, r8, r0
	ldr	r12, [sp, #4]
L_mc_bm_bs:
	cmp	r12, #1
	blt	L_mc_bm_bse
	sub	r0, r12, #1
	lsl	r0, r0, #1
	add	r1, r5, #0x200
	add	r1, r1, r0
	ldrh	r0, [r1]
	lsl	r1, r12, #1
	add	r2, r5, #0x200
	add	r2, r2, r1
	strh	r0, [r2]
	sub	r12, r12, #1
	b	L_mc_bm_bs
L_mc_bm_bse:
	mov	r0, #0
	add	r1, r5, #0x200
	strh	r0, [r1]
	add	r6, r6, #1
	b	L_mc_bm_n
L_mc_bm_ne:
	ldrh	r0, [r5]
	bl	wc_mceliece_gf_inv_scalar_neon
	mov	r9, r0
	ldr	r6, [sp]
	mov	r10, #0
L_mc_bm_nm:
	ldr	r0, [sp, #4]
	cmp	r10, r0
	bgt	L_mc_bm_nme
	ldr	r0, [sp, #4]
	sub	r0, r0, r10
	lsl	r0, r0, #1
	add	r0, r5, r0
	ldrh	r0, [r0]
	mov	r1, r9
	bl	wc_mceliece_gf_mul_scalar_neon
	lsl	r1, r10, #1
	add	r1, r6, r1
	strh	r0, [r1]
	add	r10, r10, #1
	b	L_mc_bm_nm
L_mc_bm_nme:
	add	sp, sp, #8
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	wc_mceliece_berlekamp_massey_neon,.-wc_mceliece_berlekamp_massey_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_synd_unpack_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_synd_unpack_neon)
	.type	wc_mceliece_synd_unpack_neon, %function
wc_mceliece_synd_unpack_neon:
	push	{r4, r5, lr}
	vpush	{d8-d9}
	ldr	r3, =L_mc_bs_powers_neon
	vld1.8	{d0-d1}, [r3]
	vmov.i16	q1, #1
	lsr	r5, r2, #3
	mov	r12, #0
L_mc_sunp:
	cmp	r12, r5
	bge	L_mc_sunpe
	veor	q4, q4, q4
	add	r4, r1, #0
	add	r4, r4, r12
	ldrb	lr, [r4]
	vdup.16	q2, lr
	vtst.16	q3, q2, q0
	vand	q3, q3, q1
	vorr	q4, q4, q3
	add	r4, r1, #32
	add	r4, r4, r12
	ldrb	lr, [r4]
	vdup.16	q2, lr
	vtst.16	q3, q2, q0
	vand	q3, q3, q1
	vshl.i16	q3, q3, #1
	vorr	q4, q4, q3
	add	r4, r1, #0x40
	add	r4, r4, r12
	ldrb	lr, [r4]
	vdup.16	q2, lr
	vtst.16	q3, q2, q0
	vand	q3, q3, q1
	vshl.i16	q3, q3, #2
	vorr	q4, q4, q3
	add	r4, r1, #0x60
	add	r4, r4, r12
	ldrb	lr, [r4]
	vdup.16	q2, lr
	vtst.16	q3, q2, q0
	vand	q3, q3, q1
	vshl.i16	q3, q3, #3
	vorr	q4, q4, q3
	add	r4, r1, #0x80
	add	r4, r4, r12
	ldrb	lr, [r4]
	vdup.16	q2, lr
	vtst.16	q3, q2, q0
	vand	q3, q3, q1
	vshl.i16	q3, q3, #4
	vorr	q4, q4, q3
	add	r4, r1, #0xa0
	add	r4, r4, r12
	ldrb	lr, [r4]
	vdup.16	q2, lr
	vtst.16	q3, q2, q0
	vand	q3, q3, q1
	vshl.i16	q3, q3, #5
	vorr	q4, q4, q3
	add	r4, r1, #0xc0
	add	r4, r4, r12
	ldrb	lr, [r4]
	vdup.16	q2, lr
	vtst.16	q3, q2, q0
	vand	q3, q3, q1
	vshl.i16	q3, q3, #6
	vorr	q4, q4, q3
	add	r4, r1, #0xe0
	add	r4, r4, r12
	ldrb	lr, [r4]
	vdup.16	q2, lr
	vtst.16	q3, q2, q0
	vand	q3, q3, q1
	vshl.i16	q3, q3, #7
	vorr	q4, q4, q3
	add	r4, r1, #0x100
	add	r4, r4, r12
	ldrb	lr, [r4]
	vdup.16	q2, lr
	vtst.16	q3, q2, q0
	vand	q3, q3, q1
	vshl.i16	q3, q3, #8
	vorr	q4, q4, q3
	add	r4, r1, #0x120
	add	r4, r4, r12
	ldrb	lr, [r4]
	vdup.16	q2, lr
	vtst.16	q3, q2, q0
	vand	q3, q3, q1
	vshl.i16	q3, q3, #9
	vorr	q4, q4, q3
	add	r4, r1, #0x140
	add	r4, r4, r12
	ldrb	lr, [r4]
	vdup.16	q2, lr
	vtst.16	q3, q2, q0
	vand	q3, q3, q1
	vshl.i16	q3, q3, #10
	vorr	q4, q4, q3
	add	r4, r1, #0x160
	add	r4, r4, r12
	ldrb	lr, [r4]
	vdup.16	q2, lr
	vtst.16	q3, q2, q0
	vand	q3, q3, q1
	vshl.i16	q3, q3, #11
	vorr	q4, q4, q3
	add	r4, r1, #0x180
	add	r4, r4, r12
	ldrb	lr, [r4]
	vdup.16	q2, lr
	vtst.16	q3, q2, q0
	vand	q3, q3, q1
	vshl.i16	q3, q3, #12
	vorr	q4, q4, q3
	lsl	r4, r12, #4
	add	r4, r0, r4
	vst1.8	{d8-d9}, [r4]
	add	r12, r12, #1
	b	L_mc_sunp
L_mc_sunpe:
	vpop	{d8-d9}
	pop	{r4, r5, pc}
	.size	wc_mceliece_synd_unpack_neon,.-wc_mceliece_synd_unpack_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_syndrome_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_syndrome_neon)
	.type	wc_mceliece_syndrome_neon, %function
wc_mceliece_syndrome_neon:
	push	{r4, r5, r6, r7, r8, lr}
	sub	sp, sp, #4
	mov	r4, r0
	mov	r5, r1
	mov	r6, r2
	mov	r7, r3
	ldr	r8, [sp, #28]
	mov	r0, r7
	mov	r1, r6
	mov	r2, r5
	bl	wc_mceliece_aff_synd_mask_neon
	mov	r0, r4
	mov	r1, r7
	mov	r2, r8
	bl	wc_mceliece_aff_butterflies_tr_neon
	mov	r0, r4
	bl	wc_mceliece_radix_conv_tr_neon
	add	sp, sp, #4
	pop	{r4, r5, r6, r7, r8, pc}
	.size	wc_mceliece_syndrome_neon,.-wc_mceliece_syndrome_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_encap_scatter_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_encap_scatter_neon)
	.type	wc_mceliece_encap_scatter_neon, %function
wc_mceliece_encap_scatter_neon:
	push	{r4, r5, r6, r7, lr}
	vpush	{d8-d15}
	mov	r5, #0
	mov	r6, #1
	vmov	d14, r6, r5
	vmov	d15, d14
	mov	r6, #63
	vmov	d16, r6, r5
	vmov	d17, d16
	mov	r12, #0
L_mc_sc_w:
	cmp	r12, r3
	bge	L_mc_sc_end
	veor	q0, q0, q0
	vmov	d18, r12, r5
	vmov	d19, d18
	mov	lr, #0
	mov	r4, r1
L_mc_sc_j2:
	add	r6, lr, #2
	cmp	r6, r2
	bgt	L_mc_sc_jtail
	ldr	r6, [r4]
	add	r4, r4, #4
	vmov	d2, r6, r5
	vmovl.u16	q2, d2
	vmovl.u32	q1, d4
	vand	q3, q1, q8
	vshr.u64	q4, q1, #6
	vshl.u64	q5, q7, q3
	vceq.i32	q6, q4, q9
	vrev64.32	q10, q6
	vand	q6, q6, q10
	vand	q5, q5, q6
	vorr	q0, q0, q5
	add	lr, lr, #2
	b	L_mc_sc_j2
L_mc_sc_jtail:
	vorr	d0, d0, d1
	cmp	lr, r2
	bge	L_mc_sc_store
L_mc_sc_tail1:
	ldrh	r6, [r4]
	add	r4, r4, #2
	vmov	d2, r6, r5
	vand	q3, q1, q8
	vshr.u64	q4, q1, #6
	vshl.u64	q5, q7, q3
	vceq.i32	q6, q4, q9
	vrev64.32	q10, q6
	vand	q6, q6, q10
	vand	q5, q5, q6
	vorr	d0, d0, d10
	add	lr, lr, #1
	cmp	lr, r2
	blt	L_mc_sc_tail1
L_mc_sc_store:
	lsl	r6, r12, #3
	add	r6, r0, r6
	vst1.8	{d0}, [r6]
	add	r12, r12, #1
	b	L_mc_sc_w
L_mc_sc_end:
	vpop	{d8-d15}
	pop	{r4, r5, r6, r7, pc}
	.size	wc_mceliece_encap_scatter_neon,.-wc_mceliece_encap_scatter_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_encap_syndrome_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_encap_syndrome_neon)
	.type	wc_mceliece_encap_syndrome_neon, %function
wc_mceliece_encap_syndrome_neon:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	sub	sp, sp, #16
	ldr	r7, [sp, #52]
	ldr	r8, [sp, #56]
	str	r8, [sp, #4]
	and	r9, r7, #7
	str	r9, [sp, #8]
	lsr	r8, r7, #3
	str	r8, [sp]
	ldr	r9, [sp, #8]
	cmp	r9, #0
	beq	L_mc_syn_notail
	str	r3, [sp, #12]
	ldr	r8, [sp]
	add	r12, r1, r8
	mov	r6, #0
	ldr	r10, [sp, #8]
	ldr	r9, [sp, #4]
	sub	r7, r9, #1
L_mc_syn_bld:
	cmp	r6, r9
	bge	L_mc_syn_main
	cmp	r6, r7
	bge	L_mc_syn_last
	add	r11, r12, r6
	ldrh	r11, [r11]
	lsr	r11, r11, r10
	b	L_mc_syn_stv
L_mc_syn_last:
	add	r11, r12, r6
	ldrb	r11, [r11]
	lsr	r11, r11, r10
L_mc_syn_stv:
	add	r4, r3, r6
	strb	r11, [r4]
	add	r6, r6, #1
	b	L_mc_syn_bld
L_mc_syn_notail:
	ldr	r8, [sp]
	add	r8, r1, r8
	str	r8, [sp, #12]
L_mc_syn_main:
	mov	r6, #0
	mov	r12, r0
L_mc_syn_mainl:
	ldr	r8, [sp]
	cmp	r6, r8
	bge	L_mc_syn_tail
	mov	r4, #0
	mov	r5, #0
L_mc_syn_rowl:
	ldr	lr, [sp, #12]
	ldr	r7, [sp, #4]
	veor	q0, q0, q0
	mov	r10, #0
	cmp	r7, #16
	blt	L_mc_syn_aptl_m
L_mc_syn_ap16_m:
	vld1.8	{d2-d3}, [r12]
	add	r12, r12, #16
	vld1.8	{d4-d5}, [lr]
	add	lr, lr, #16
	vand	q1, q1, q2
	veor	q0, q0, q1
	sub	r7, r7, #16
	cmp	r7, #16
	bge	L_mc_syn_ap16_m
L_mc_syn_aptl_m:
	cmp	r7, #0
	beq	L_mc_syn_aptd_m
L_mc_syn_aptll_m:
	ldrb	r8, [r12]
	add	r12, r12, #1
	ldrb	r9, [lr]
	add	lr, lr, #1
	and	r8, r8, r9
	eor	r10, r10, r8
	subs	r7, r7, #1
	bne	L_mc_syn_aptll_m
L_mc_syn_aptd_m:
	vcnt.8	q0, q0
	vpaddl.u8	q3, q0
	vpaddl.u16	q3, q3
	vpaddl.u32	q3, q3
	vadd.i64	d6, d6, d7
	vmov	r11, r8, d6
	and	r11, r11, #1
	lsr	r9, r10, #4
	eor	r10, r10, r9
	lsr	r9, r10, #2
	eor	r10, r10, r9
	lsr	r9, r10, #1
	eor	r10, r10, r9
	and	r10, r10, #1
	eor	r11, r11, r10
	lsl	r11, r11, r5
	orr	r4, r4, r11
	add	r5, r5, #1
	cmp	r5, #8
	blt	L_mc_syn_rowl
	add	r8, r1, r6
	ldrb	r8, [r8]
	eor	r4, r4, r8
	add	r8, r2, r6
	strb	r4, [r8]
	add	r6, r6, #1
	b	L_mc_syn_mainl
L_mc_syn_tail:
	ldr	r8, [sp, #8]
	cmp	r8, #0
	beq	L_mc_syn_end
	mov	r4, #0
	mov	r5, #0
	ldr	r8, [sp]
	add	r6, r1, r8
	ldrb	r6, [r6]
L_mc_syn_taill:
	ldr	lr, [sp, #12]
	ldr	r7, [sp, #4]
	veor	q0, q0, q0
	mov	r10, #0
	cmp	r7, #16
	blt	L_mc_syn_aptl_t
L_mc_syn_ap16_t:
	vld1.8	{d2-d3}, [r12]
	add	r12, r12, #16
	vld1.8	{d4-d5}, [lr]
	add	lr, lr, #16
	vand	q1, q1, q2
	veor	q0, q0, q1
	sub	r7, r7, #16
	cmp	r7, #16
	bge	L_mc_syn_ap16_t
L_mc_syn_aptl_t:
	cmp	r7, #0
	beq	L_mc_syn_aptd_t
L_mc_syn_aptll_t:
	ldrb	r8, [r12]
	add	r12, r12, #1
	ldrb	r9, [lr]
	add	lr, lr, #1
	and	r8, r8, r9
	eor	r10, r10, r8
	subs	r7, r7, #1
	bne	L_mc_syn_aptll_t
L_mc_syn_aptd_t:
	vcnt.8	q0, q0
	vpaddl.u8	q3, q0
	vpaddl.u16	q3, q3
	vpaddl.u32	q3, q3
	vadd.i64	d6, d6, d7
	vmov	r11, r8, d6
	and	r11, r11, #1
	lsr	r9, r10, #4
	eor	r10, r10, r9
	lsr	r9, r10, #2
	eor	r10, r10, r9
	lsr	r9, r10, #1
	eor	r10, r10, r9
	and	r10, r10, #1
	eor	r11, r11, r10
	lsr	r8, r6, r5
	and	r8, r8, #1
	eor	r11, r11, r8
	lsl	r11, r11, r5
	orr	r4, r4, r11
	add	r5, r5, #1
	ldr	r8, [sp, #8]
	cmp	r5, r8
	blt	L_mc_syn_taill
	ldr	r8, [sp]
	add	r8, r2, r8
	strb	r4, [r8]
L_mc_syn_end:
	add	sp, sp, #16
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	wc_mceliece_encap_syndrome_neon,.-wc_mceliece_encap_syndrome_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_encap_fixedweight_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_encap_fixedweight_neon)
	.type	wc_mceliece_encap_fixedweight_neon, %function
wc_mceliece_encap_fixedweight_neon:
	push	{r4, r5, r6, r7, r8, r9, r10, lr}
	sub	sp, sp, #8
	ldr	r8, [sp, #40]
	str	r8, [sp]
	ldr	r8, [sp, #44]
	str	r8, [sp, #4]
	mov	r12, #0
L_mc_fw_retry:
	ldr	r8, [sp, #4]
	lsl	r8, r8, #1
	add	r9, r12, r8
	cmp	r9, r2
	bgt	L_mc_fw_depl
	add	r5, r0, r12
	mov	lr, #0
	mov	r4, #0
	ldr	r10, [sp, #4]
L_mc_fw_filter:
	cmp	r4, r10
	bge	L_mc_fw_filterd
	ldr	r9, [sp]
	cmp	lr, r9
	bge	L_mc_fw_filterd
	lsl	r8, r4, #1
	add	r8, r5, r8
	ldrh	r8, [r8]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r9, #0xff
	orr	r9, r9, #0x1f00
#else
	mov	r9, #0x1fff
#endif
	and	r8, r8, r9
	lsl	r9, lr, #1
	add	r9, r1, r9
	strh	r8, [r9]
	sub	r9, r8, r3
	lsr	r9, r9, #31
	add	lr, lr, r9
	add	r4, r4, #1
	b	L_mc_fw_filter
L_mc_fw_filterd:
	ldr	r8, [sp, #4]
	lsl	r8, r8, #1
	add	r12, r12, r8
	ldr	r9, [sp]
	cmp	lr, r9
	blt	L_mc_fw_retry
	mov	lr, #0
	mov	r4, #1
L_mc_fw_dupi:
	ldr	r8, [sp]
	cmp	r4, r8
	bge	L_mc_fw_dupd
	lsl	r8, r4, #1
	add	r8, r1, r8
	ldrh	r7, [r8]
	vdup.16	q0, r7
	veor	q1, q1, q1
	mov	r6, #0
L_mc_fw_dupj8:
	add	r8, r6, #8
	cmp	r8, r4
	bgt	L_mc_fw_duprem
	lsl	r8, r6, #1
	add	r8, r1, r8
	vld1.8	{d4-d5}, [r8]
	vceq.i16	q2, q2, q0
	vorr	q1, q1, q2
	add	r6, r6, #8
	b	L_mc_fw_dupj8
L_mc_fw_duprem:
	vpmax.u16	d2, d2, d3
	vpmax.u16	d2, d2, d2
	vpmax.u16	d2, d2, d2
	vmov.u16	r8, d2[0]
	orr	lr, lr, r8
L_mc_fw_duprem1:
	cmp	r6, r4
	bge	L_mc_fw_dupie
	lsl	r8, r6, #1
	add	r8, r1, r8
	ldrh	r8, [r8]
	sub	r9, r8, r7
	rsb	r8, r9, #0
	orr	r9, r9, r8
	lsr	r9, r9, #31
	eor	r9, r9, #1
	add	lr, lr, r9
	add	r6, r6, #1
	b	L_mc_fw_duprem1
L_mc_fw_dupie:
	add	r4, r4, #1
	b	L_mc_fw_dupi
L_mc_fw_dupd:
	cmp	lr, #0
	bne	L_mc_fw_retry
	mov	r0, #0
	b	L_mc_fw_ret
L_mc_fw_depl:
	mov	r0, #2
L_mc_fw_ret:
	add	sp, sp, #8
	pop	{r4, r5, r6, r7, r8, r9, r10, pc}
	.size	wc_mceliece_encap_fixedweight_neon,.-wc_mceliece_encap_fixedweight_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_layer_ex_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_layer_ex_neon)
	.type	wc_mceliece_layer_ex_neon, %function
wc_mceliece_layer_ex_neon:
	push	{r4, r5, r6, r7, r8, lr}
	mov	r7, #1
	lsl	r3, r7, r2
	cmp	r3, #1
	beq	L_mc_lex_sc
	lsl	r12, r3, #3
	mov	lr, #0
L_mc_lex_i:
	cmp	lr, #0x80
	bge	L_mc_lex_done
	lsl	r7, lr, #3
	add	r5, r0, r7
	add	r6, r5, r12
	mov	r4, #0
L_mc_lex_k:
	vld1.8	{d0-d1}, [r5]
	vld1.8	{d2-d3}, [r6]
	vld1.8	{d6-d7}, [r1]
	add	r1, r1, #16
	veor	q2, q0, q1
	vand	q2, q2, q3
	veor	q0, q0, q2
	veor	q1, q1, q2
	vst1.8	{d0-d1}, [r5]
	vst1.8	{d2-d3}, [r6]
	add	r5, r5, #16
	add	r6, r6, #16
	add	r4, r4, #2
	cmp	r4, r3
	blt	L_mc_lex_k
L_mc_lex_ni:
	add	r7, r3, r3
	add	lr, lr, r7
	b	L_mc_lex_i
L_mc_lex_sc:
	mov	r5, r0
	mov	lr, #0
L_mc_lex_sl:
	add	r8, r5, #8
	vld1.8	{d0}, [r5]
	vld1.8	{d2}, [r8]
	vld1.8	{d6}, [r1]
	add	r1, r1, #8
	veor	d4, d0, d2
	vand	d4, d4, d6
	veor	d0, d0, d4
	veor	d2, d2, d4
	vst1.8	{d0}, [r5]
	vst1.8	{d2}, [r8]
	add	r5, r5, #16
	add	lr, lr, #2
	cmp	lr, #0x80
	blt	L_mc_lex_sl
L_mc_lex_done:
	pop	{r4, r5, r6, r7, r8, pc}
	.size	wc_mceliece_layer_ex_neon,.-wc_mceliece_layer_ex_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_layer_in_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_layer_in_neon)
	.type	wc_mceliece_layer_in_neon, %function
wc_mceliece_layer_in_neon:
	push	{r4, r5, r6, r7, r8, r9, r10, lr}
	vpush	{d8-d13}
	mov	r9, #1
	lsl	r3, r9, r2
	cmp	r3, #1
	beq	L_mc_lin_sc
	lsl	r12, r3, #3
	mov	lr, #0
L_mc_lin_i:
	cmp	lr, #0x40
	bge	L_mc_lin_done
	lsl	r10, lr, #3
	add	r5, r0, r10
	add	r6, r5, #0x200
	add	r7, r5, r12
	add	r8, r6, r12
	mov	r4, lr
	add	r9, lr, r3
L_mc_lin_j:
	vld1.8	{d0-d1}, [r5]
	vld1.8	{d2-d3}, [r7]
	vld1.8	{d4-d5}, [r6]
	vld1.8	{d6-d7}, [r8]
	vld1.8	{d10-d13}, [r1]
	add	r1, r1, #32
	vmov	d8, d11
	vmov	d11, d12
	vmov	d12, d8
	veor	q4, q0, q1
	vand	q4, q4, q5
	veor	q0, q0, q4
	veor	q1, q1, q4
	veor	q4, q2, q3
	vand	q4, q4, q6
	veor	q2, q2, q4
	veor	q3, q3, q4
	vst1.8	{d0-d1}, [r5]
	vst1.8	{d2-d3}, [r7]
	vst1.8	{d4-d5}, [r6]
	vst1.8	{d6-d7}, [r8]
	add	r5, r5, #16
	add	r7, r7, #16
	add	r6, r6, #16
	add	r8, r8, #16
	add	r4, r4, #2
	cmp	r4, r9
	blt	L_mc_lin_j
L_mc_lin_ni:
	add	r10, r3, r3
	add	lr, lr, r10
	b	L_mc_lin_i
L_mc_lin_sc:
	mov	r5, r0
	add	r6, r5, #0x200
	mov	lr, #0
L_mc_lin_sl:
	add	r9, r5, #8
	vld1.8	{d0}, [r5]
	vld1.8	{d2}, [r9]
	vld1.8	{d10}, [r1]
	add	r1, r1, #8
	veor	d8, d0, d2
	vand	d8, d8, d10
	veor	d0, d0, d8
	veor	d2, d2, d8
	vst1.8	{d0}, [r5]
	vst1.8	{d2}, [r9]
	add	r10, r6, #8
	vld1.8	{d4}, [r6]
	vld1.8	{d6}, [r10]
	vld1.8	{d12}, [r1]
	add	r1, r1, #8
	veor	d8, d4, d6
	vand	d8, d8, d12
	veor	d4, d4, d8
	veor	d6, d6, d8
	vst1.8	{d4}, [r6]
	vst1.8	{d6}, [r10]
	add	r5, r5, #16
	add	r6, r6, #16
	add	lr, lr, #2
	cmp	lr, #0x40
	blt	L_mc_lin_sl
L_mc_lin_done:
	vpop	{d8-d13}
	pop	{r4, r5, r6, r7, r8, r9, r10, pc}
	.size	wc_mceliece_layer_in_neon,.-wc_mceliece_layer_in_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_apply_benes_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_apply_benes_neon)
	.type	wc_mceliece_apply_benes_neon, %function
wc_mceliece_apply_benes_neon:
	push	{r4, r5, r6, r7, r8, r9, r10, lr}
	mov	r4, r0
	mov	r5, r3
	mov	r6, r1
	mov	r7, #0
	cmp	r2, #0
	beq	L_mc_ab_norev
	add	r6, r6, #0x3000
	mov	r7, #0x400
	neg	r7, r7
L_mc_ab_norev:
	mov	r9, #0
L_mc_ab_rl:
	cmp	r9, #0x40
	bge	L_mc_ab_rle
	lsl	r10, r9, #4
	add	r10, r4, r10
	vld1.8	{d0-d1}, [r10]
	lsl	r10, r9, #3
	add	r10, r5, r10
	vst1.8	{d0}, [r10]
	add	r10, r10, #0x200
	vst1.8	{d1}, [r10]
	add	r9, r9, #1
	b	L_mc_ab_rl
L_mc_ab_rle:
	add	r0, r5, #0x400
	add	r1, r5, #0
	bl	wc_mceliece_transpose_64x64_neon
	add	r0, r5, #0x600
	add	r1, r5, #0x200
	bl	wc_mceliece_transpose_64x64_neon
	mov	r8, #0
L_mc_ab_x1:
	cmp	r8, #6
	bgt	L_mc_ab_x1e
	mov	r9, #0
L_mc_bnl_x1:
	cmp	r9, #0x40
	bge	L_mc_bnle_x1
	vld1.8	{d0}, [r6]
	lsl	r10, r9, #3
	add	r10, r5, r10
	add	r10, r10, #0x800
	vst1.8	{d0}, [r10]
	add	r6, r6, #8
	add	r9, r9, #1
	b	L_mc_bnl_x1
L_mc_bnle_x1:
	add	r6, r6, r7
	add	r0, r5, #0xa00
	add	r1, r5, #0x800
	bl	wc_mceliece_transpose_64x64_neon
	add	r0, r5, #0x400
	add	r1, r5, #0xa00
	mov	r2, r8
	bl	wc_mceliece_layer_ex_neon
	add	r8, r8, #1
	b	L_mc_ab_x1
L_mc_ab_x1e:
	add	r0, r5, #0
	add	r1, r5, #0x400
	bl	wc_mceliece_transpose_64x64_neon
	add	r0, r5, #0x200
	add	r1, r5, #0x600
	bl	wc_mceliece_transpose_64x64_neon
	mov	r8, #0
L_mc_ab_n1:
	cmp	r8, #5
	bgt	L_mc_ab_n1e
	mov	r9, #0
L_mc_bnl_n1:
	cmp	r9, #0x40
	bge	L_mc_bnle_n1
	vld1.8	{d0}, [r6]
	lsl	r10, r9, #3
	add	r10, r5, r10
	add	r10, r10, #0x800
	vst1.8	{d0}, [r10]
	add	r6, r6, #8
	add	r9, r9, #1
	b	L_mc_bnl_n1
L_mc_bnle_n1:
	add	r6, r6, r7
	mov	r0, r5
	add	r1, r5, #0x800
	mov	r2, r8
	bl	wc_mceliece_layer_in_neon
	add	r8, r8, #1
	b	L_mc_ab_n1
L_mc_ab_n1e:
	mov	r8, #4
L_mc_ab_n2:
	cmp	r8, #0
	blt	L_mc_ab_n2e
	mov	r9, #0
L_mc_bnl_n2:
	cmp	r9, #0x40
	bge	L_mc_bnle_n2
	vld1.8	{d0}, [r6]
	lsl	r10, r9, #3
	add	r10, r5, r10
	add	r10, r10, #0x800
	vst1.8	{d0}, [r10]
	add	r6, r6, #8
	add	r9, r9, #1
	b	L_mc_bnl_n2
L_mc_bnle_n2:
	add	r6, r6, r7
	mov	r0, r5
	add	r1, r5, #0x800
	mov	r2, r8
	bl	wc_mceliece_layer_in_neon
	sub	r8, r8, #1
	b	L_mc_ab_n2
L_mc_ab_n2e:
	add	r0, r5, #0x400
	add	r1, r5, #0
	bl	wc_mceliece_transpose_64x64_neon
	add	r0, r5, #0x600
	add	r1, r5, #0x200
	bl	wc_mceliece_transpose_64x64_neon
	mov	r8, #6
L_mc_ab_x2:
	cmp	r8, #0
	blt	L_mc_ab_x2e
	mov	r9, #0
L_mc_bnl_x2:
	cmp	r9, #0x40
	bge	L_mc_bnle_x2
	vld1.8	{d0}, [r6]
	lsl	r10, r9, #3
	add	r10, r5, r10
	add	r10, r10, #0x800
	vst1.8	{d0}, [r10]
	add	r6, r6, #8
	add	r9, r9, #1
	b	L_mc_bnl_x2
L_mc_bnle_x2:
	add	r6, r6, r7
	add	r0, r5, #0xa00
	add	r1, r5, #0x800
	bl	wc_mceliece_transpose_64x64_neon
	add	r0, r5, #0x400
	add	r1, r5, #0xa00
	mov	r2, r8
	bl	wc_mceliece_layer_ex_neon
	sub	r8, r8, #1
	b	L_mc_ab_x2
L_mc_ab_x2e:
	add	r0, r5, #0
	add	r1, r5, #0x400
	bl	wc_mceliece_transpose_64x64_neon
	add	r0, r5, #0x200
	add	r1, r5, #0x600
	bl	wc_mceliece_transpose_64x64_neon
	mov	r9, #0
L_mc_ab_st:
	cmp	r9, #0x40
	bge	L_mc_ab_ste
	lsl	r10, r9, #3
	add	r10, r5, r10
	vld1.8	{d0}, [r10]
	add	r10, r10, #0x200
	vld1.8	{d1}, [r10]
	lsl	r10, r9, #4
	add	r10, r4, r10
	vst1.8	{d0-d1}, [r10]
	add	r9, r9, #1
	b	L_mc_ab_st
L_mc_ab_ste:
	pop	{r4, r5, r6, r7, r8, r9, r10, pc}
	.size	wc_mceliece_apply_benes_neon,.-wc_mceliece_apply_benes_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_transpose_64x64_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_transpose_64x64_neon)
	.type	wc_mceliece_transpose_64x64_neon, %function
wc_mceliece_transpose_64x64_neon:
	push	{r4, r5, r6, r7, r8, lr}
	vpush	{d8-d13}
	mov	r2, r0
	mov	r3, r1
	mov	r12, #0x200
L_mc_tr_copy:
	vld1.8	{d0-d1}, [r3]
	add	r3, r3, #16
	vst1.8	{d0-d1}, [r2]
	add	r2, r2, #16
	subs	r12, r12, #16
	bne	L_mc_tr_copy
	vmov.i64	q6, #0xffffffff
	mov	lr, #0
L_mc_tr_i5:
	cmp	lr, #0x40
	bge	L_mc_tr_e5
	lsl	r7, lr, #3
	add	r5, r0, r7
	add	r6, r5, #0x100
	mov	r4, #0
L_mc_tr_k5:
	vld1.8	{d0-d1}, [r5]
	vld1.8	{d2-d3}, [r6]
	vand	q2, q0, q6
	vand	q3, q1, q6
	vshl.i64	q3, q3, #32
	veor	q2, q2, q3
	vbic	q4, q0, q6
	vshr.u64	q4, q4, #32
	vbic	q5, q1, q6
	veor	q4, q4, q5
	vst1.8	{d4-d5}, [r5]
	vst1.8	{d8-d9}, [r6]
	add	r5, r5, #16
	add	r6, r6, #16
	add	r4, r4, #2
	cmp	r4, #32
	blt	L_mc_tr_k5
L_mc_tr_ni5:
	add	lr, lr, #0x40
	b	L_mc_tr_i5
L_mc_tr_e5:
	vmov.i32	q6, #0xffff
	mov	lr, #0
L_mc_tr_i4:
	cmp	lr, #0x40
	bge	L_mc_tr_e4
	lsl	r7, lr, #3
	add	r5, r0, r7
	add	r6, r5, #0x80
	mov	r4, #0
L_mc_tr_k4:
	vld1.8	{d0-d1}, [r5]
	vld1.8	{d2-d3}, [r6]
	vand	q2, q0, q6
	vand	q3, q1, q6
	vshl.i64	q3, q3, #16
	veor	q2, q2, q3
	vbic	q4, q0, q6
	vshr.u64	q4, q4, #16
	vbic	q5, q1, q6
	veor	q4, q4, q5
	vst1.8	{d4-d5}, [r5]
	vst1.8	{d8-d9}, [r6]
	add	r5, r5, #16
	add	r6, r6, #16
	add	r4, r4, #2
	cmp	r4, #16
	blt	L_mc_tr_k4
L_mc_tr_ni4:
	add	lr, lr, #32
	b	L_mc_tr_i4
L_mc_tr_e4:
	vmov.i16	q6, #0xff
	mov	lr, #0
L_mc_tr_i3:
	cmp	lr, #0x40
	bge	L_mc_tr_e3
	lsl	r7, lr, #3
	add	r5, r0, r7
	add	r6, r5, #0x40
	mov	r4, #0
L_mc_tr_k3:
	vld1.8	{d0-d1}, [r5]
	vld1.8	{d2-d3}, [r6]
	vand	q2, q0, q6
	vand	q3, q1, q6
	vshl.i64	q3, q3, #8
	veor	q2, q2, q3
	vbic	q4, q0, q6
	vshr.u64	q4, q4, #8
	vbic	q5, q1, q6
	veor	q4, q4, q5
	vst1.8	{d4-d5}, [r5]
	vst1.8	{d8-d9}, [r6]
	add	r5, r5, #16
	add	r6, r6, #16
	add	r4, r4, #2
	cmp	r4, #8
	blt	L_mc_tr_k3
L_mc_tr_ni3:
	add	lr, lr, #16
	b	L_mc_tr_i3
L_mc_tr_e3:
	vmov.i8	q6, #15
	mov	lr, #0
L_mc_tr_i2:
	cmp	lr, #0x40
	bge	L_mc_tr_e2
	lsl	r7, lr, #3
	add	r5, r0, r7
	add	r6, r5, #32
	mov	r4, #0
L_mc_tr_k2:
	vld1.8	{d0-d1}, [r5]
	vld1.8	{d2-d3}, [r6]
	vand	q2, q0, q6
	vand	q3, q1, q6
	vshl.i64	q3, q3, #4
	veor	q2, q2, q3
	vbic	q4, q0, q6
	vshr.u64	q4, q4, #4
	vbic	q5, q1, q6
	veor	q4, q4, q5
	vst1.8	{d4-d5}, [r5]
	vst1.8	{d8-d9}, [r6]
	add	r5, r5, #16
	add	r6, r6, #16
	add	r4, r4, #2
	cmp	r4, #4
	blt	L_mc_tr_k2
L_mc_tr_ni2:
	add	lr, lr, #8
	b	L_mc_tr_i2
L_mc_tr_e2:
	vmov.i8	q6, #51
	mov	lr, #0
L_mc_tr_i1:
	cmp	lr, #0x40
	bge	L_mc_tr_e1
	lsl	r7, lr, #3
	add	r5, r0, r7
	add	r6, r5, #16
	mov	r4, #0
L_mc_tr_k1:
	vld1.8	{d0-d1}, [r5]
	vld1.8	{d2-d3}, [r6]
	vand	q2, q0, q6
	vand	q3, q1, q6
	vshl.i64	q3, q3, #2
	veor	q2, q2, q3
	vbic	q4, q0, q6
	vshr.u64	q4, q4, #2
	vbic	q5, q1, q6
	veor	q4, q4, q5
	vst1.8	{d4-d5}, [r5]
	vst1.8	{d8-d9}, [r6]
	add	r5, r5, #16
	add	r6, r6, #16
	add	r4, r4, #2
	cmp	r4, #2
	blt	L_mc_tr_k1
L_mc_tr_ni1:
	add	lr, lr, #4
	b	L_mc_tr_i1
L_mc_tr_e1:
	vmov.i8	q6, #0x55
	mov	r5, r0
	mov	lr, #0
L_mc_tr_sc0:
	add	r8, r5, #8
	vld1.8	{d0}, [r5]
	vld1.8	{d2}, [r8]
	vand	d4, d0, d12
	vand	d6, d2, d12
	vshl.i64	d6, d6, #1
	veor	d4, d4, d6
	vbic	d8, d0, d12
	vshr.u64	d8, d8, #1
	vbic	d10, d2, d12
	veor	d8, d8, d10
	vst1.8	{d4}, [r5]
	vst1.8	{d8}, [r8]
	add	r5, r5, #16
	add	lr, lr, #2
	cmp	lr, #0x40
	blt	L_mc_tr_sc0
L_mc_tr_e0:
	vpop	{d8-d13}
	pop	{r4, r5, r6, r7, r8, pc}
	.size	wc_mceliece_transpose_64x64_neon,.-wc_mceliece_transpose_64x64_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_aff_transpose_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_aff_transpose_neon)
	.type	wc_mceliece_aff_transpose_neon, %function
wc_mceliece_aff_transpose_neon:
	push	{r4, lr}
	vpush	{d8-d15}
	vmov.i64	q10, #0xffffffff
	mov	r1, #0
L_mc_at_i5:
	cmp	r1, #0x40
	bge	L_mc_at_e5
	lsl	r4, r1, #5
	add	r3, r0, r4
	add	r12, r3, #0x400
	mov	r2, r1
	add	lr, r1, #32
L_mc_at_j5:
	vld1.8	{d0-d3}, [r3]
	vld1.8	{d4-d7}, [r12]
	vand	q4, q0, q10
	vand	q8, q2, q10
	vshl.i64	q8, q8, #32
	veor	q4, q4, q8
	vand	q5, q1, q10
	vand	q9, q3, q10
	vshl.i64	q9, q9, #32
	veor	q5, q5, q9
	vbic	q6, q0, q10
	vshr.u64	q6, q6, #32
	vbic	q8, q2, q10
	veor	q6, q6, q8
	vbic	q7, q1, q10
	vshr.u64	q7, q7, #32
	vbic	q9, q3, q10
	veor	q7, q7, q9
	vst1.8	{d8-d11}, [r3]
	vst1.8	{d12-d15}, [r12]
	add	r3, r3, #32
	add	r12, r12, #32
	add	r2, r2, #1
	cmp	r2, lr
	blt	L_mc_at_j5
L_mc_at_ni5:
	add	r1, r1, #0x40
	b	L_mc_at_i5
L_mc_at_e5:
	vmov.i32	q10, #0xffff
	mov	r1, #0
L_mc_at_i4:
	cmp	r1, #0x40
	bge	L_mc_at_e4
	lsl	r4, r1, #5
	add	r3, r0, r4
	add	r12, r3, #0x200
	mov	r2, r1
	add	lr, r1, #16
L_mc_at_j4:
	vld1.8	{d0-d3}, [r3]
	vld1.8	{d4-d7}, [r12]
	vand	q4, q0, q10
	vand	q8, q2, q10
	vshl.i64	q8, q8, #16
	veor	q4, q4, q8
	vand	q5, q1, q10
	vand	q9, q3, q10
	vshl.i64	q9, q9, #16
	veor	q5, q5, q9
	vbic	q6, q0, q10
	vshr.u64	q6, q6, #16
	vbic	q8, q2, q10
	veor	q6, q6, q8
	vbic	q7, q1, q10
	vshr.u64	q7, q7, #16
	vbic	q9, q3, q10
	veor	q7, q7, q9
	vst1.8	{d8-d11}, [r3]
	vst1.8	{d12-d15}, [r12]
	add	r3, r3, #32
	add	r12, r12, #32
	add	r2, r2, #1
	cmp	r2, lr
	blt	L_mc_at_j4
L_mc_at_ni4:
	add	r1, r1, #32
	b	L_mc_at_i4
L_mc_at_e4:
	vmov.i16	q10, #0xff
	mov	r1, #0
L_mc_at_i3:
	cmp	r1, #0x40
	bge	L_mc_at_e3
	lsl	r4, r1, #5
	add	r3, r0, r4
	add	r12, r3, #0x100
	mov	r2, r1
	add	lr, r1, #8
L_mc_at_j3:
	vld1.8	{d0-d3}, [r3]
	vld1.8	{d4-d7}, [r12]
	vand	q4, q0, q10
	vand	q8, q2, q10
	vshl.i64	q8, q8, #8
	veor	q4, q4, q8
	vand	q5, q1, q10
	vand	q9, q3, q10
	vshl.i64	q9, q9, #8
	veor	q5, q5, q9
	vbic	q6, q0, q10
	vshr.u64	q6, q6, #8
	vbic	q8, q2, q10
	veor	q6, q6, q8
	vbic	q7, q1, q10
	vshr.u64	q7, q7, #8
	vbic	q9, q3, q10
	veor	q7, q7, q9
	vst1.8	{d8-d11}, [r3]
	vst1.8	{d12-d15}, [r12]
	add	r3, r3, #32
	add	r12, r12, #32
	add	r2, r2, #1
	cmp	r2, lr
	blt	L_mc_at_j3
L_mc_at_ni3:
	add	r1, r1, #16
	b	L_mc_at_i3
L_mc_at_e3:
	vmov.i8	q10, #15
	mov	r1, #0
L_mc_at_i2:
	cmp	r1, #0x40
	bge	L_mc_at_e2
	lsl	r4, r1, #5
	add	r3, r0, r4
	add	r12, r3, #0x80
	mov	r2, r1
	add	lr, r1, #4
L_mc_at_j2:
	vld1.8	{d0-d3}, [r3]
	vld1.8	{d4-d7}, [r12]
	vand	q4, q0, q10
	vand	q8, q2, q10
	vshl.i64	q8, q8, #4
	veor	q4, q4, q8
	vand	q5, q1, q10
	vand	q9, q3, q10
	vshl.i64	q9, q9, #4
	veor	q5, q5, q9
	vbic	q6, q0, q10
	vshr.u64	q6, q6, #4
	vbic	q8, q2, q10
	veor	q6, q6, q8
	vbic	q7, q1, q10
	vshr.u64	q7, q7, #4
	vbic	q9, q3, q10
	veor	q7, q7, q9
	vst1.8	{d8-d11}, [r3]
	vst1.8	{d12-d15}, [r12]
	add	r3, r3, #32
	add	r12, r12, #32
	add	r2, r2, #1
	cmp	r2, lr
	blt	L_mc_at_j2
L_mc_at_ni2:
	add	r1, r1, #8
	b	L_mc_at_i2
L_mc_at_e2:
	vmov.i8	q10, #51
	mov	r1, #0
L_mc_at_i1:
	cmp	r1, #0x40
	bge	L_mc_at_e1
	lsl	r4, r1, #5
	add	r3, r0, r4
	add	r12, r3, #0x40
	mov	r2, r1
	add	lr, r1, #2
L_mc_at_j1:
	vld1.8	{d0-d3}, [r3]
	vld1.8	{d4-d7}, [r12]
	vand	q4, q0, q10
	vand	q8, q2, q10
	vshl.i64	q8, q8, #2
	veor	q4, q4, q8
	vand	q5, q1, q10
	vand	q9, q3, q10
	vshl.i64	q9, q9, #2
	veor	q5, q5, q9
	vbic	q6, q0, q10
	vshr.u64	q6, q6, #2
	vbic	q8, q2, q10
	veor	q6, q6, q8
	vbic	q7, q1, q10
	vshr.u64	q7, q7, #2
	vbic	q9, q3, q10
	veor	q7, q7, q9
	vst1.8	{d8-d11}, [r3]
	vst1.8	{d12-d15}, [r12]
	add	r3, r3, #32
	add	r12, r12, #32
	add	r2, r2, #1
	cmp	r2, lr
	blt	L_mc_at_j1
L_mc_at_ni1:
	add	r1, r1, #4
	b	L_mc_at_i1
L_mc_at_e1:
	vmov.i8	q10, #0x55
	mov	r1, #0
L_mc_at_i0:
	cmp	r1, #0x40
	bge	L_mc_at_e0
	lsl	r4, r1, #5
	add	r3, r0, r4
	add	r12, r3, #32
	mov	r2, r1
	add	lr, r1, #1
L_mc_at_j0:
	vld1.8	{d0-d3}, [r3]
	vld1.8	{d4-d7}, [r12]
	vand	q4, q0, q10
	vand	q8, q2, q10
	vshl.i64	q8, q8, #1
	veor	q4, q4, q8
	vand	q5, q1, q10
	vand	q9, q3, q10
	vshl.i64	q9, q9, #1
	veor	q5, q5, q9
	vbic	q6, q0, q10
	vshr.u64	q6, q6, #1
	vbic	q8, q2, q10
	veor	q6, q6, q8
	vbic	q7, q1, q10
	vshr.u64	q7, q7, #1
	vbic	q9, q3, q10
	veor	q7, q7, q9
	vst1.8	{d8-d11}, [r3]
	vst1.8	{d12-d15}, [r12]
	add	r3, r3, #32
	add	r12, r12, #32
	add	r2, r2, #1
	cmp	r2, lr
	blt	L_mc_at_j0
L_mc_at_ni0:
	add	r1, r1, #2
	b	L_mc_at_i0
L_mc_at_e0:
	vpop	{d8-d15}
	pop	{r4, pc}
	.size	wc_mceliece_aff_transpose_neon,.-wc_mceliece_aff_transpose_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_aff_v128_mul_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_aff_v128_mul_neon)
	.type	wc_mceliece_aff_v128_mul_neon, %function
wc_mceliece_aff_v128_mul_neon:
	push	{r4, r5, r6, r7, r8, r9, lr}
	vpush	{d8-d11}
	veor	q5, q5, q5
	mov	r7, r3
	mov	r4, #0
L_mc_v128_z:
	vst1.8	{d10-d11}, [r7]
	add	r7, r7, #16
	add	r4, r4, #1
	cmp	r4, #25
	blt	L_mc_v128_z
	mov	r12, #0
L_mc_v128_i:
	cmp	r12, #13
	bge	L_mc_v128_rs
	lsl	r9, r12, #4
	add	r5, r1, r9
	vld1.8	{d0-d1}, [r5]
	mov	lr, #0
L_mc_v128_j:
	cmp	lr, #13
	bge	L_mc_v128_in
	lsl	r9, lr, #4
	add	r6, r2, r9
	vld1.8	{d2-d3}, [r6]
	vand	q2, q0, q1
	add	r9, r12, lr
	lsl	r9, r9, #4
	add	r7, r3, r9
	vld1.8	{d6-d7}, [r7]
	veor	q3, q3, q2
	vst1.8	{d6-d7}, [r7]
	add	lr, lr, #1
	b	L_mc_v128_j
L_mc_v128_in:
	add	r12, r12, #1
	b	L_mc_v128_i
L_mc_v128_rs:
	mov	r4, #24
L_mc_v128_rk:
	cmp	r4, #13
	blt	L_mc_v128_copy
	lsl	r9, r4, #4
	add	r7, r3, r9
	vld1.8	{d6-d7}, [r7]
	sub	r5, r4, #9
	lsl	r5, r5, #4
	add	r8, r3, r5
	vld1.8	{d8-d9}, [r8]
	veor	q4, q4, q3
	vst1.8	{d8-d9}, [r8]
	sub	r5, r4, #10
	lsl	r5, r5, #4
	add	r8, r3, r5
	vld1.8	{d8-d9}, [r8]
	veor	q4, q4, q3
	vst1.8	{d8-d9}, [r8]
	sub	r5, r4, #12
	lsl	r5, r5, #4
	add	r8, r3, r5
	vld1.8	{d8-d9}, [r8]
	veor	q4, q4, q3
	vst1.8	{d8-d9}, [r8]
	sub	r5, r4, #13
	lsl	r5, r5, #4
	add	r8, r3, r5
	vld1.8	{d8-d9}, [r8]
	veor	q4, q4, q3
	vst1.8	{d8-d9}, [r8]
	sub	r4, r4, #1
	b	L_mc_v128_rk
L_mc_v128_copy:
	mov	r4, #0
L_mc_v128_cp:
	cmp	r4, #13
	bge	L_mc_v128_done
	lsl	r9, r4, #4
	add	r7, r3, r9
	add	r8, r0, r9
	vld1.8	{d6-d7}, [r7]
	vst1.8	{d6-d7}, [r8]
	add	r4, r4, #1
	b	L_mc_v128_cp
L_mc_v128_done:
	vpop	{d8-d11}
	pop	{r4, r5, r6, r7, r8, r9, pc}
	.size	wc_mceliece_aff_v128_mul_neon,.-wc_mceliece_aff_v128_mul_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_aff_v256_mul_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_aff_v256_mul_neon)
	.type	wc_mceliece_aff_v256_mul_neon, %function
wc_mceliece_aff_v256_mul_neon:
	push	{r4, r5, r6, r7, r8, r9, lr}
	vpush	{d8-d15}
	veor	q10, q10, q10
	mov	r7, r3
	mov	r4, #0
L_mc_v256_z:
	vst1.8	{d20-d21}, [r7]
	add	r7, r7, #16
	vst1.8	{d20-d21}, [r7]
	add	r7, r7, #16
	add	r4, r4, #1
	cmp	r4, #25
	blt	L_mc_v256_z
	mov	r12, #0
	mov	r5, r1
	mov	r8, r3
L_mc_v256_i:
	vld1.8	{d0-d3}, [r5]
	mov	r6, r2
	mov	r7, r8
	mov	lr, #0
L_mc_v256_j:
	vld1.8	{d4-d7}, [r6]
	vld1.8	{d12-d15}, [r7]
	add	r6, r6, #32
	vand	q4, q0, q2
	vand	q5, q1, q3
	veor	q6, q6, q4
	veor	q7, q7, q5
	vst1.8	{d12-d15}, [r7]
	add	r7, r7, #32
	add	lr, lr, #1
	cmp	lr, #13
	blt	L_mc_v256_j
L_mc_v256_in:
	add	r5, r5, #32
	add	r8, r8, #32
	add	r12, r12, #1
	cmp	r12, #13
	blt	L_mc_v256_i
L_mc_v256_rs:
	mov	r4, #24
	lsl	r9, r4, #5
	add	r7, r3, r9
L_mc_v256_rk:
	vld1.8	{d12-d15}, [r7]
	sub	r5, r4, #9
	lsl	r5, r5, #5
	add	r8, r3, r5
	vld1.8	{d16-d19}, [r8]
	veor	q8, q8, q6
	veor	q9, q9, q7
	vst1.8	{d16-d19}, [r8]
	sub	r5, r4, #10
	lsl	r5, r5, #5
	add	r8, r3, r5
	vld1.8	{d16-d19}, [r8]
	veor	q8, q8, q6
	veor	q9, q9, q7
	vst1.8	{d16-d19}, [r8]
	sub	r5, r4, #12
	lsl	r5, r5, #5
	add	r8, r3, r5
	vld1.8	{d16-d19}, [r8]
	veor	q8, q8, q6
	veor	q9, q9, q7
	vst1.8	{d16-d19}, [r8]
	sub	r5, r4, #13
	lsl	r5, r5, #5
	add	r8, r3, r5
	vld1.8	{d16-d19}, [r8]
	veor	q8, q8, q6
	veor	q9, q9, q7
	vst1.8	{d16-d19}, [r8]
	sub	r7, r7, #32
	sub	r4, r4, #1
	cmp	r4, #13
	bge	L_mc_v256_rk
L_mc_v256_copy:
	mov	r4, #0
	mov	r7, r3
	mov	r8, r0
L_mc_v256_cp:
	vld1.8	{d12-d15}, [r7]
	add	r7, r7, #32
	vst1.8	{d12-d15}, [r8]
	add	r8, r8, #32
	add	r4, r4, #1
	cmp	r4, #13
	blt	L_mc_v256_cp
L_mc_v256_done:
	vpop	{d8-d15}
	pop	{r4, r5, r6, r7, r8, r9, pc}
	.size	wc_mceliece_aff_v256_mul_neon,.-wc_mceliece_aff_v256_mul_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_aff_radix_step_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_aff_radix_step_neon)
	.type	wc_mceliece_aff_radix_step_neon, %function
wc_mceliece_aff_radix_step_neon:
	push	{r4, r5, r6, lr}
	vpush	{d8-d13}
	ldr	r2, =L_mc_aff_rmask0_neon
	ldr	r3, =L_mc_aff_rmask1_neon
	veor	q6, q6, q6
	mov	r4, #0
L_mc_rdx_t:
	cmp	r4, #13
	bge	L_mc_rdx_te
	lsl	r5, r4, #4
	add	r6, r0, r5
	vld1.8	{d0-d1}, [r6]
	vshr.u64	q5, q0, #32
	vmov	d10, d12
	veor	q0, q0, q5
	vshl.i64	q5, q0, #32
	vmov	d10, d11
	vmov	d11, d12
	veor	q0, q0, q5
	vst1.8	{d0-d1}, [r6]
	add	r4, r4, #1
	b	L_mc_rdx_t
L_mc_rdx_te:
	mov	r12, #4
L_mc_rdx_k:
	cmp	r12, r1
	blt	L_mc_rdx_ke
	mov	lr, #1
	lsl	lr, lr, r12
	neg	lr, lr
	vdup.32	q4, lr
	lsl	r5, r12, #3
	add	r6, r2, r5
	vld1.8	{d4}, [r6]
	vmov	d5, d4
	add	r6, r3, r5
	vld1.8	{d6}, [r6]
	vmov	d7, d6
	mov	r4, #0
L_mc_rdx_ki:
	cmp	r4, #13
	bge	L_mc_rdx_kie
	lsl	r5, r4, #4
	add	r6, r0, r5
	vld1.8	{d0-d1}, [r6]
	vand	q1, q0, q2
	vshl.u64	q1, q1, q4
	veor	q0, q0, q1
	vand	q1, q0, q3
	vshl.u64	q1, q1, q4
	veor	q0, q0, q1
	vst1.8	{d0-d1}, [r6]
	add	r4, r4, #1
	b	L_mc_rdx_ki
L_mc_rdx_kie:
	sub	r12, r12, #1
	b	L_mc_rdx_k
L_mc_rdx_ke:
	vpop	{d8-d13}
	pop	{r4, r5, r6, pc}
	.size	wc_mceliece_aff_radix_step_neon,.-wc_mceliece_aff_radix_step_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_aff_radix_tr_step_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_aff_radix_tr_step_neon)
	.type	wc_mceliece_aff_radix_tr_step_neon, %function
wc_mceliece_aff_radix_tr_step_neon:
	push	{r4, r5, r6, lr}
	vpush	{d8-d15}
	ldr	r2, =L_mc_aff_tmask0_neon
	ldr	r3, =L_mc_aff_tmask1_neon
	veor	q8, q8, q8
	mov	r12, r1
L_mc_rtr_k:
	cmp	r12, #4
	bgt	L_mc_rtr_ke
	mov	lr, #1
	lsl	lr, lr, r12
	vdup.32	q6, lr
	lsl	r5, r12, #3
	add	r6, r2, r5
	vld1.8	{d8}, [r6]
	vmov	d9, d8
	add	r6, r3, r5
	vld1.8	{d10}, [r6]
	vmov	d11, d10
	mov	r4, #0
L_mc_rtr_ki:
	cmp	r4, #13
	bge	L_mc_rtr_kie
	lsl	r5, r4, #5
	add	r6, r0, r5
	vld1.8	{d0-d3}, [r6]
	vand	q2, q0, q4
	vshl.u64	q2, q2, q6
	veor	q0, q0, q2
	vand	q3, q1, q4
	vshl.u64	q3, q3, q6
	veor	q1, q1, q3
	vand	q2, q0, q5
	vshl.u64	q2, q2, q6
	veor	q0, q0, q2
	vand	q3, q1, q5
	vshl.u64	q3, q3, q6
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r6]
	add	r4, r4, #1
	b	L_mc_rtr_ki
L_mc_rtr_kie:
	add	r12, r12, #1
	b	L_mc_rtr_k
L_mc_rtr_ke:
	cmp	r1, #5
	bgt	L_mc_rtr_tsk
	mov	r4, #0
L_mc_rtr_t:
	cmp	r4, #13
	bge	L_mc_rtr_te
	lsl	r5, r4, #5
	add	r6, r0, r5
	vld1.8	{d0-d3}, [r6]
	vshr.u64	q7, q0, #32
	vmov	d15, d14
	vmov	d14, d16
	veor	q0, q0, q7
	vshl.i64	q7, q0, #32
	vmov	d14, d16
	veor	q0, q0, q7
	vshr.u64	q7, q1, #32
	vmov	d15, d14
	vmov	d14, d16
	veor	q1, q1, q7
	vshl.i64	q7, q1, #32
	vmov	d14, d16
	veor	q1, q1, q7
	vst1.8	{d0-d3}, [r6]
	add	r4, r4, #1
	b	L_mc_rtr_t
L_mc_rtr_te:
L_mc_rtr_tsk:
	mov	r4, #0
L_mc_rtr_c:
	cmp	r4, #13
	bge	L_mc_rtr_ce
	lsl	r5, r4, #5
	add	r6, r0, r5
	vld1.8	{d0-d3}, [r6]
	vmov	d14, d1
	vmov	d15, d16
	veor	q1, q1, q7
	vmov	d15, d2
	vmov	d14, d16
	veor	q1, q1, q7
	vst1.8	{d0-d3}, [r6]
	add	r4, r4, #1
	b	L_mc_rtr_c
L_mc_rtr_ce:
	vpop	{d8-d15}
	pop	{r4, r5, r6, pc}
	.size	wc_mceliece_aff_radix_tr_step_neon,.-wc_mceliece_aff_radix_tr_step_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_radix_conv_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_radix_conv_neon)
	.type	wc_mceliece_radix_conv_neon, %function
wc_mceliece_radix_conv_neon:
	push	{r4, r5, r6, r7, r8, r9, r10, lr}
	vpush	{d8-d13}
	sub	sp, sp, #0x190
	ldr	r2, =L_mc_aff_rmask0_neon
	ldr	r3, =L_mc_aff_rmask1_neon
	ldr	r12, =L_mc_aff_scal2x_neon
	mov	r1, #0
L_mc_rconv_j:
	cmp	r1, #5
	bgt	L_mc_rconv_je
	veor	q6, q6, q6
	mov	r5, #0
L_mc_rdx_t_rc:
	cmp	r5, #13
	bge	L_mc_rdx_te_rc
	lsl	r6, r5, #4
	add	r7, r0, r6
	vld1.8	{d0-d1}, [r7]
	vshr.u64	q5, q0, #32
	vmov	d10, d12
	veor	q0, q0, q5
	vshl.i64	q5, q0, #32
	vmov	d10, d11
	vmov	d11, d12
	veor	q0, q0, q5
	vst1.8	{d0-d1}, [r7]
	add	r5, r5, #1
	b	L_mc_rdx_t_rc
L_mc_rdx_te_rc:
	mov	lr, #4
L_mc_rdx_k_rc:
	cmp	lr, r1
	blt	L_mc_rdx_ke_rc
	mov	r4, #1
	lsl	r4, r4, lr
	neg	r4, r4
	vdup.32	q4, r4
	lsl	r6, lr, #3
	add	r7, r2, r6
	vld1.8	{d4}, [r7]
	vmov	d5, d4
	add	r7, r3, r6
	vld1.8	{d6}, [r7]
	vmov	d7, d6
	mov	r5, #0
L_mc_rdx_ki_rc:
	cmp	r5, #13
	bge	L_mc_rdx_kie_rc
	lsl	r6, r5, #4
	add	r7, r0, r6
	vld1.8	{d0-d1}, [r7]
	vand	q1, q0, q2
	vshl.u64	q1, q1, q4
	veor	q0, q0, q1
	vand	q1, q0, q3
	vshl.u64	q1, q1, q4
	veor	q0, q0, q1
	vst1.8	{d0-d1}, [r7]
	add	r5, r5, #1
	b	L_mc_rdx_ki_rc
L_mc_rdx_kie_rc:
	sub	lr, lr, #1
	b	L_mc_rdx_k_rc
L_mc_rdx_ke_rc:
	cmp	r1, #5
	bge	L_mc_rconv_sk
	veor	q5, q5, q5
	mov	r8, sp
	mov	r5, #0
L_mc_v128_z_rc:
	vst1.8	{d10-d11}, [r8]
	add	r8, r8, #16
	add	r5, r5, #1
	cmp	r5, #25
	blt	L_mc_v128_z_rc
	mov	lr, #0
L_mc_v128_i_rc:
	cmp	lr, #13
	bge	L_mc_v128_rs_rc
	lsl	r10, lr, #4
	add	r6, r0, r10
	vld1.8	{d0-d1}, [r6]
	mov	r4, #0
L_mc_v128_j_rc:
	cmp	r4, #13
	bge	L_mc_v128_in_rc
	lsl	r10, r4, #4
	add	r7, r12, r10
	vld1.8	{d2-d3}, [r7]
	vand	q2, q0, q1
	add	r10, lr, r4
	lsl	r10, r10, #4
	add	r8, sp, r10
	vld1.8	{d6-d7}, [r8]
	veor	q3, q3, q2
	vst1.8	{d6-d7}, [r8]
	add	r4, r4, #1
	b	L_mc_v128_j_rc
L_mc_v128_in_rc:
	add	lr, lr, #1
	b	L_mc_v128_i_rc
L_mc_v128_rs_rc:
	mov	r5, #24
L_mc_v128_rk_rc:
	cmp	r5, #13
	blt	L_mc_v128_copy_rc
	lsl	r10, r5, #4
	add	r8, sp, r10
	vld1.8	{d6-d7}, [r8]
	sub	r6, r5, #9
	lsl	r6, r6, #4
	add	r9, sp, r6
	vld1.8	{d8-d9}, [r9]
	veor	q4, q4, q3
	vst1.8	{d8-d9}, [r9]
	sub	r6, r5, #10
	lsl	r6, r6, #4
	add	r9, sp, r6
	vld1.8	{d8-d9}, [r9]
	veor	q4, q4, q3
	vst1.8	{d8-d9}, [r9]
	sub	r6, r5, #12
	lsl	r6, r6, #4
	add	r9, sp, r6
	vld1.8	{d8-d9}, [r9]
	veor	q4, q4, q3
	vst1.8	{d8-d9}, [r9]
	sub	r6, r5, #13
	lsl	r6, r6, #4
	add	r9, sp, r6
	vld1.8	{d8-d9}, [r9]
	veor	q4, q4, q3
	vst1.8	{d8-d9}, [r9]
	sub	r5, r5, #1
	b	L_mc_v128_rk_rc
L_mc_v128_copy_rc:
	mov	r5, #0
L_mc_v128_cp_rc:
	cmp	r5, #13
	bge	L_mc_v128_done_rc
	lsl	r10, r5, #4
	add	r8, sp, r10
	add	r9, r0, r10
	vld1.8	{d6-d7}, [r8]
	vst1.8	{d6-d7}, [r9]
	add	r5, r5, #1
	b	L_mc_v128_cp_rc
L_mc_v128_done_rc:
	add	r12, r12, #0xd0
L_mc_rconv_sk:
	add	r1, r1, #1
	b	L_mc_rconv_j
L_mc_rconv_je:
	add	sp, sp, #0x190
	vpop	{d8-d13}
	pop	{r4, r5, r6, r7, r8, r9, r10, pc}
	.size	wc_mceliece_radix_conv_neon,.-wc_mceliece_radix_conv_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_radix_conv_tr_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_radix_conv_tr_neon)
	.type	wc_mceliece_radix_conv_tr_neon, %function
wc_mceliece_radix_conv_tr_neon:
	push	{r4, r5, r6, r7, r8, r9, r10, lr}
	vpush	{d8-d15}
	sub	sp, sp, #0x320
	ldr	r2, =L_mc_aff_tmask0_neon
	ldr	r3, =L_mc_aff_tmask1_neon
	ldr	r12, =L_mc_aff_scal4x_neon
	add	r12, r12, #0x800
	add	r12, r12, #32
	mov	r1, #6
L_mc_rctr_j:
	cmp	r1, #0
	blt	L_mc_rctr_je
	cmp	r1, #6
	bge	L_mc_rctr_sk
	veor	q10, q10, q10
	mov	r8, sp
	mov	r5, #0
L_mc_v256_z_rt:
	vst1.8	{d20-d21}, [r8]
	add	r8, r8, #16
	vst1.8	{d20-d21}, [r8]
	add	r8, r8, #16
	add	r5, r5, #1
	cmp	r5, #25
	blt	L_mc_v256_z_rt
	mov	lr, #0
	mov	r6, r0
	mov	r9, sp
L_mc_v256_i_rt:
	vld1.8	{d0-d3}, [r6]
	mov	r7, r12
	mov	r8, r9
	mov	r4, #0
L_mc_v256_j_rt:
	vld1.8	{d4-d7}, [r7]
	vld1.8	{d12-d15}, [r8]
	add	r7, r7, #32
	vand	q4, q0, q2
	vand	q5, q1, q3
	veor	q6, q6, q4
	veor	q7, q7, q5
	vst1.8	{d12-d15}, [r8]
	add	r8, r8, #32
	add	r4, r4, #1
	cmp	r4, #13
	blt	L_mc_v256_j_rt
L_mc_v256_in_rt:
	add	r6, r6, #32
	add	r9, r9, #32
	add	lr, lr, #1
	cmp	lr, #13
	blt	L_mc_v256_i_rt
L_mc_v256_rs_rt:
	mov	r5, #24
	lsl	r10, r5, #5
	add	r8, sp, r10
L_mc_v256_rk_rt:
	vld1.8	{d12-d15}, [r8]
	sub	r6, r5, #9
	lsl	r6, r6, #5
	add	r9, sp, r6
	vld1.8	{d16-d19}, [r9]
	veor	q8, q8, q6
	veor	q9, q9, q7
	vst1.8	{d16-d19}, [r9]
	sub	r6, r5, #10
	lsl	r6, r6, #5
	add	r9, sp, r6
	vld1.8	{d16-d19}, [r9]
	veor	q8, q8, q6
	veor	q9, q9, q7
	vst1.8	{d16-d19}, [r9]
	sub	r6, r5, #12
	lsl	r6, r6, #5
	add	r9, sp, r6
	vld1.8	{d16-d19}, [r9]
	veor	q8, q8, q6
	veor	q9, q9, q7
	vst1.8	{d16-d19}, [r9]
	sub	r6, r5, #13
	lsl	r6, r6, #5
	add	r9, sp, r6
	vld1.8	{d16-d19}, [r9]
	veor	q8, q8, q6
	veor	q9, q9, q7
	vst1.8	{d16-d19}, [r9]
	sub	r8, r8, #32
	sub	r5, r5, #1
	cmp	r5, #13
	bge	L_mc_v256_rk_rt
L_mc_v256_copy_rt:
	mov	r5, #0
	mov	r8, sp
	mov	r9, r0
L_mc_v256_cp_rt:
	vld1.8	{d12-d15}, [r8]
	add	r8, r8, #32
	vst1.8	{d12-d15}, [r9]
	add	r9, r9, #32
	add	r5, r5, #1
	cmp	r5, #13
	blt	L_mc_v256_cp_rt
L_mc_v256_done_rt:
	sub	r12, r12, #0x1a0
L_mc_rctr_sk:
	veor	q8, q8, q8
	mov	lr, r1
L_mc_rtr_k_rt:
	cmp	lr, #4
	bgt	L_mc_rtr_ke_rt
	mov	r4, #1
	lsl	r4, r4, lr
	vdup.32	q6, r4
	lsl	r6, lr, #3
	add	r7, r2, r6
	vld1.8	{d8}, [r7]
	vmov	d9, d8
	add	r7, r3, r6
	vld1.8	{d10}, [r7]
	vmov	d11, d10
	mov	r5, #0
L_mc_rtr_ki_rt:
	cmp	r5, #13
	bge	L_mc_rtr_kie_rt
	lsl	r6, r5, #5
	add	r7, r0, r6
	vld1.8	{d0-d3}, [r7]
	vand	q2, q0, q4
	vshl.u64	q2, q2, q6
	veor	q0, q0, q2
	vand	q3, q1, q4
	vshl.u64	q3, q3, q6
	veor	q1, q1, q3
	vand	q2, q0, q5
	vshl.u64	q2, q2, q6
	veor	q0, q0, q2
	vand	q3, q1, q5
	vshl.u64	q3, q3, q6
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r7]
	add	r5, r5, #1
	b	L_mc_rtr_ki_rt
L_mc_rtr_kie_rt:
	add	lr, lr, #1
	b	L_mc_rtr_k_rt
L_mc_rtr_ke_rt:
	cmp	r1, #5
	bgt	L_mc_rtr_tsk_rt
	mov	r5, #0
L_mc_rtr_t_rt:
	cmp	r5, #13
	bge	L_mc_rtr_te_rt
	lsl	r6, r5, #5
	add	r7, r0, r6
	vld1.8	{d0-d3}, [r7]
	vshr.u64	q7, q0, #32
	vmov	d15, d14
	vmov	d14, d16
	veor	q0, q0, q7
	vshl.i64	q7, q0, #32
	vmov	d14, d16
	veor	q0, q0, q7
	vshr.u64	q7, q1, #32
	vmov	d15, d14
	vmov	d14, d16
	veor	q1, q1, q7
	vshl.i64	q7, q1, #32
	vmov	d14, d16
	veor	q1, q1, q7
	vst1.8	{d0-d3}, [r7]
	add	r5, r5, #1
	b	L_mc_rtr_t_rt
L_mc_rtr_te_rt:
L_mc_rtr_tsk_rt:
	mov	r5, #0
L_mc_rtr_c_rt:
	cmp	r5, #13
	bge	L_mc_rtr_ce_rt
	lsl	r6, r5, #5
	add	r7, r0, r6
	vld1.8	{d0-d3}, [r7]
	vmov	d14, d1
	vmov	d15, d16
	veor	q1, q1, q7
	vmov	d15, d2
	vmov	d14, d16
	veor	q1, q1, q7
	vst1.8	{d0-d3}, [r7]
	add	r5, r5, #1
	b	L_mc_rtr_c_rt
L_mc_rtr_ce_rt:
	sub	r1, r1, #1
	b	L_mc_rctr_j
L_mc_rctr_je:
	add	sp, sp, #0x320
	vpop	{d8-d15}
	pop	{r4, r5, r6, r7, r8, r9, r10, pc}
	.size	wc_mceliece_radix_conv_tr_neon,.-wc_mceliece_radix_conv_tr_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_aff_inv256_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_aff_inv256_neon)
	.type	wc_mceliece_aff_inv256_neon, %function
wc_mceliece_aff_inv256_neon:
	push	{r4, r5, r6, r7, r8, r9, r10, lr}
	vpush	{d8-d15}
	sub	sp, sp, #0x1a0
	mov	lr, r1
	mov	r4, sp
	mov	r6, #0
L_mc_sqr_s_iv1:
	vld1.8	{d0-d3}, [lr]
	vst1.8	{d0-d3}, [r4]
	add	lr, lr, #32
	add	r4, r4, #32
	add	r6, r6, #1
	cmp	r6, #13
	blt	L_mc_sqr_s_iv1
	add	r5, sp, #0
	vld1.8	{d0-d3}, [r5]
	add	r5, sp, #0x160
	vld1.8	{d4-d7}, [r5]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, r2, #0
	vst1.8	{d0-d3}, [r5]
	add	r5, sp, #0xe0
	vld1.8	{d0-d3}, [r5]
	add	r5, sp, #0x160
	vld1.8	{d4-d7}, [r5]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, sp, #0x180
	vld1.8	{d4-d7}, [r5]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, r2, #32
	vst1.8	{d0-d3}, [r5]
	add	r5, sp, #32
	vld1.8	{d0-d3}, [r5]
	add	r5, sp, #0xe0
	vld1.8	{d4-d7}, [r5]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, r2, #0x40
	vst1.8	{d0-d3}, [r5]
	add	r5, sp, #0x100
	vld1.8	{d0-d3}, [r5]
	add	r5, sp, #0x160
	vld1.8	{d4-d7}, [r5]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, sp, #0x180
	vld1.8	{d4-d7}, [r5]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, r2, #0x60
	vst1.8	{d0-d3}, [r5]
	add	r5, sp, #0x40
	vld1.8	{d0-d3}, [r5]
	add	r5, sp, #0xe0
	vld1.8	{d4-d7}, [r5]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, sp, #0x100
	vld1.8	{d4-d7}, [r5]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, sp, #0x160
	vld1.8	{d4-d7}, [r5]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, sp, #0x180
	vld1.8	{d4-d7}, [r5]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, r2, #0x80
	vst1.8	{d0-d3}, [r5]
	add	r5, sp, #0xe0
	vld1.8	{d0-d3}, [r5]
	add	r5, sp, #0x120
	vld1.8	{d4-d7}, [r5]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, r2, #0xa0
	vst1.8	{d0-d3}, [r5]
	add	r5, sp, #0x60
	vld1.8	{d0-d3}, [r5]
	add	r5, sp, #0x100
	vld1.8	{d4-d7}, [r5]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, sp, #0x120
	vld1.8	{d4-d7}, [r5]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, sp, #0x180
	vld1.8	{d4-d7}, [r5]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, r2, #0xc0
	vst1.8	{d0-d3}, [r5]
	add	r5, sp, #0x100
	vld1.8	{d0-d3}, [r5]
	add	r5, sp, #0x140
	vld1.8	{d4-d7}, [r5]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, r2, #0xe0
	vst1.8	{d0-d3}, [r5]
	add	r5, sp, #0x80
	vld1.8	{d0-d3}, [r5]
	add	r5, sp, #0x120
	vld1.8	{d4-d7}, [r5]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, sp, #0x140
	vld1.8	{d4-d7}, [r5]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, r2, #0x100
	vst1.8	{d0-d3}, [r5]
	add	r5, sp, #0x120
	vld1.8	{d0-d3}, [r5]
	add	r5, sp, #0x160
	vld1.8	{d4-d7}, [r5]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, r2, #0x120
	vst1.8	{d0-d3}, [r5]
	add	r5, sp, #0xa0
	vld1.8	{d0-d3}, [r5]
	add	r5, sp, #0x140
	vld1.8	{d4-d7}, [r5]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, sp, #0x160
	vld1.8	{d4-d7}, [r5]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, r2, #0x140
	vst1.8	{d0-d3}, [r5]
	add	r5, sp, #0x140
	vld1.8	{d0-d3}, [r5]
	add	r5, sp, #0x180
	vld1.8	{d4-d7}, [r5]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, r2, #0x160
	vst1.8	{d0-d3}, [r5]
	add	r5, sp, #0xc0
	vld1.8	{d0-d3}, [r5]
	add	r5, sp, #0x160
	vld1.8	{d4-d7}, [r5]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, sp, #0x180
	vld1.8	{d4-d7}, [r5]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, r2, #0x180
	vst1.8	{d0-d3}, [r5]
	mov	r12, #0
L_mc_inv_cp:
	cmp	r12, #13
	bge	L_mc_inv_cpe
	lsl	lr, r12, #5
	add	r4, r2, lr
	vld1.8	{d0-d3}, [r4]
	add	r5, r0, lr
	vst1.8	{d0-d3}, [r5]
	add	r12, r12, #1
	b	L_mc_inv_cp
L_mc_inv_cpe:
	mov	r12, #2
L_mc_inv_l:
	cmp	r12, #12
	bgt	L_mc_inv_le
	mov	lr, r2
	mov	r4, sp
	mov	r6, #0
L_mc_sqr_s_iv2:
	vld1.8	{d0-d3}, [lr]
	vst1.8	{d0-d3}, [r4]
	add	lr, lr, #32
	add	r4, r4, #32
	add	r6, r6, #1
	cmp	r6, #13
	blt	L_mc_sqr_s_iv2
	add	r5, sp, #0
	vld1.8	{d0-d3}, [r5]
	add	r5, sp, #0x160
	vld1.8	{d4-d7}, [r5]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, r2, #0
	vst1.8	{d0-d3}, [r5]
	add	r5, sp, #0xe0
	vld1.8	{d0-d3}, [r5]
	add	r5, sp, #0x160
	vld1.8	{d4-d7}, [r5]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, sp, #0x180
	vld1.8	{d4-d7}, [r5]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, r2, #32
	vst1.8	{d0-d3}, [r5]
	add	r5, sp, #32
	vld1.8	{d0-d3}, [r5]
	add	r5, sp, #0xe0
	vld1.8	{d4-d7}, [r5]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, r2, #0x40
	vst1.8	{d0-d3}, [r5]
	add	r5, sp, #0x100
	vld1.8	{d0-d3}, [r5]
	add	r5, sp, #0x160
	vld1.8	{d4-d7}, [r5]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, sp, #0x180
	vld1.8	{d4-d7}, [r5]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, r2, #0x60
	vst1.8	{d0-d3}, [r5]
	add	r5, sp, #0x40
	vld1.8	{d0-d3}, [r5]
	add	r5, sp, #0xe0
	vld1.8	{d4-d7}, [r5]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, sp, #0x100
	vld1.8	{d4-d7}, [r5]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, sp, #0x160
	vld1.8	{d4-d7}, [r5]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, sp, #0x180
	vld1.8	{d4-d7}, [r5]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, r2, #0x80
	vst1.8	{d0-d3}, [r5]
	add	r5, sp, #0xe0
	vld1.8	{d0-d3}, [r5]
	add	r5, sp, #0x120
	vld1.8	{d4-d7}, [r5]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, r2, #0xa0
	vst1.8	{d0-d3}, [r5]
	add	r5, sp, #0x60
	vld1.8	{d0-d3}, [r5]
	add	r5, sp, #0x100
	vld1.8	{d4-d7}, [r5]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, sp, #0x120
	vld1.8	{d4-d7}, [r5]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, sp, #0x180
	vld1.8	{d4-d7}, [r5]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, r2, #0xc0
	vst1.8	{d0-d3}, [r5]
	add	r5, sp, #0x100
	vld1.8	{d0-d3}, [r5]
	add	r5, sp, #0x140
	vld1.8	{d4-d7}, [r5]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, r2, #0xe0
	vst1.8	{d0-d3}, [r5]
	add	r5, sp, #0x80
	vld1.8	{d0-d3}, [r5]
	add	r5, sp, #0x120
	vld1.8	{d4-d7}, [r5]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, sp, #0x140
	vld1.8	{d4-d7}, [r5]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, r2, #0x100
	vst1.8	{d0-d3}, [r5]
	add	r5, sp, #0x120
	vld1.8	{d0-d3}, [r5]
	add	r5, sp, #0x160
	vld1.8	{d4-d7}, [r5]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, r2, #0x120
	vst1.8	{d0-d3}, [r5]
	add	r5, sp, #0xa0
	vld1.8	{d0-d3}, [r5]
	add	r5, sp, #0x140
	vld1.8	{d4-d7}, [r5]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, sp, #0x160
	vld1.8	{d4-d7}, [r5]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, r2, #0x140
	vst1.8	{d0-d3}, [r5]
	add	r5, sp, #0x140
	vld1.8	{d0-d3}, [r5]
	add	r5, sp, #0x180
	vld1.8	{d4-d7}, [r5]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, r2, #0x160
	vst1.8	{d0-d3}, [r5]
	add	r5, sp, #0xc0
	vld1.8	{d0-d3}, [r5]
	add	r5, sp, #0x160
	vld1.8	{d4-d7}, [r5]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, sp, #0x180
	vld1.8	{d4-d7}, [r5]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, r2, #0x180
	vst1.8	{d0-d3}, [r5]
	veor	q10, q10, q10
	mov	r8, r3
	mov	r5, #0
L_mc_v256_z_iv:
	vst1.8	{d20-d21}, [r8]
	add	r8, r8, #16
	vst1.8	{d20-d21}, [r8]
	add	r8, r8, #16
	add	r5, r5, #1
	cmp	r5, #25
	blt	L_mc_v256_z_iv
	mov	lr, #0
	mov	r6, r0
	mov	r9, r3
L_mc_v256_i_iv:
	vld1.8	{d0-d3}, [r6]
	mov	r7, r2
	mov	r8, r9
	mov	r4, #0
L_mc_v256_j_iv:
	vld1.8	{d4-d7}, [r7]
	vld1.8	{d12-d15}, [r8]
	add	r7, r7, #32
	vand	q4, q0, q2
	vand	q5, q1, q3
	veor	q6, q6, q4
	veor	q7, q7, q5
	vst1.8	{d12-d15}, [r8]
	add	r8, r8, #32
	add	r4, r4, #1
	cmp	r4, #13
	blt	L_mc_v256_j_iv
L_mc_v256_in_iv:
	add	r6, r6, #32
	add	r9, r9, #32
	add	lr, lr, #1
	cmp	lr, #13
	blt	L_mc_v256_i_iv
L_mc_v256_rs_iv:
	mov	r5, #24
	lsl	r10, r5, #5
	add	r8, r3, r10
L_mc_v256_rk_iv:
	vld1.8	{d12-d15}, [r8]
	sub	r6, r5, #9
	lsl	r6, r6, #5
	add	r9, r3, r6
	vld1.8	{d16-d19}, [r9]
	veor	q8, q8, q6
	veor	q9, q9, q7
	vst1.8	{d16-d19}, [r9]
	sub	r6, r5, #10
	lsl	r6, r6, #5
	add	r9, r3, r6
	vld1.8	{d16-d19}, [r9]
	veor	q8, q8, q6
	veor	q9, q9, q7
	vst1.8	{d16-d19}, [r9]
	sub	r6, r5, #12
	lsl	r6, r6, #5
	add	r9, r3, r6
	vld1.8	{d16-d19}, [r9]
	veor	q8, q8, q6
	veor	q9, q9, q7
	vst1.8	{d16-d19}, [r9]
	sub	r6, r5, #13
	lsl	r6, r6, #5
	add	r9, r3, r6
	vld1.8	{d16-d19}, [r9]
	veor	q8, q8, q6
	veor	q9, q9, q7
	vst1.8	{d16-d19}, [r9]
	sub	r8, r8, #32
	sub	r5, r5, #1
	cmp	r5, #13
	bge	L_mc_v256_rk_iv
L_mc_v256_copy_iv:
	mov	r5, #0
	mov	r8, r3
	mov	r9, r0
L_mc_v256_cp_iv:
	vld1.8	{d12-d15}, [r8]
	add	r8, r8, #32
	vst1.8	{d12-d15}, [r9]
	add	r9, r9, #32
	add	r5, r5, #1
	cmp	r5, #13
	blt	L_mc_v256_cp_iv
L_mc_v256_done_iv:
	add	r12, r12, #1
	b	L_mc_inv_l
L_mc_inv_le:
	add	sp, sp, #0x1a0
	vpop	{d8-d15}
	pop	{r4, r5, r6, r7, r8, r9, r10, pc}
	.size	wc_mceliece_aff_inv256_neon,.-wc_mceliece_aff_inv256_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_aff_v256_sqr_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_aff_v256_sqr_neon)
	.type	wc_mceliece_aff_v256_sqr_neon, %function
wc_mceliece_aff_v256_sqr_neon:
	push	{lr}
	sub	sp, sp, #0x1a0
	mov	r2, r1
	mov	r3, sp
	mov	lr, #0
L_mc_sqr_s:
	vld1.8	{d0-d3}, [r2]
	vst1.8	{d0-d3}, [r3]
	add	r2, r2, #32
	add	r3, r3, #32
	add	lr, lr, #1
	cmp	lr, #13
	blt	L_mc_sqr_s
	add	r12, sp, #0
	vld1.8	{d0-d3}, [r12]
	add	r12, sp, #0x160
	vld1.8	{d4-d7}, [r12]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r0, #0
	vst1.8	{d0-d3}, [r12]
	add	r12, sp, #0xe0
	vld1.8	{d0-d3}, [r12]
	add	r12, sp, #0x160
	vld1.8	{d4-d7}, [r12]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, sp, #0x180
	vld1.8	{d4-d7}, [r12]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r0, #32
	vst1.8	{d0-d3}, [r12]
	add	r12, sp, #32
	vld1.8	{d0-d3}, [r12]
	add	r12, sp, #0xe0
	vld1.8	{d4-d7}, [r12]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r0, #0x40
	vst1.8	{d0-d3}, [r12]
	add	r12, sp, #0x100
	vld1.8	{d0-d3}, [r12]
	add	r12, sp, #0x160
	vld1.8	{d4-d7}, [r12]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, sp, #0x180
	vld1.8	{d4-d7}, [r12]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r0, #0x60
	vst1.8	{d0-d3}, [r12]
	add	r12, sp, #0x40
	vld1.8	{d0-d3}, [r12]
	add	r12, sp, #0xe0
	vld1.8	{d4-d7}, [r12]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, sp, #0x100
	vld1.8	{d4-d7}, [r12]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, sp, #0x160
	vld1.8	{d4-d7}, [r12]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, sp, #0x180
	vld1.8	{d4-d7}, [r12]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r0, #0x80
	vst1.8	{d0-d3}, [r12]
	add	r12, sp, #0xe0
	vld1.8	{d0-d3}, [r12]
	add	r12, sp, #0x120
	vld1.8	{d4-d7}, [r12]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r0, #0xa0
	vst1.8	{d0-d3}, [r12]
	add	r12, sp, #0x60
	vld1.8	{d0-d3}, [r12]
	add	r12, sp, #0x100
	vld1.8	{d4-d7}, [r12]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, sp, #0x120
	vld1.8	{d4-d7}, [r12]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, sp, #0x180
	vld1.8	{d4-d7}, [r12]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r0, #0xc0
	vst1.8	{d0-d3}, [r12]
	add	r12, sp, #0x100
	vld1.8	{d0-d3}, [r12]
	add	r12, sp, #0x140
	vld1.8	{d4-d7}, [r12]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r0, #0xe0
	vst1.8	{d0-d3}, [r12]
	add	r12, sp, #0x80
	vld1.8	{d0-d3}, [r12]
	add	r12, sp, #0x120
	vld1.8	{d4-d7}, [r12]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, sp, #0x140
	vld1.8	{d4-d7}, [r12]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r0, #0x100
	vst1.8	{d0-d3}, [r12]
	add	r12, sp, #0x120
	vld1.8	{d0-d3}, [r12]
	add	r12, sp, #0x160
	vld1.8	{d4-d7}, [r12]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r0, #0x120
	vst1.8	{d0-d3}, [r12]
	add	r12, sp, #0xa0
	vld1.8	{d0-d3}, [r12]
	add	r12, sp, #0x140
	vld1.8	{d4-d7}, [r12]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, sp, #0x160
	vld1.8	{d4-d7}, [r12]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r0, #0x140
	vst1.8	{d0-d3}, [r12]
	add	r12, sp, #0x140
	vld1.8	{d0-d3}, [r12]
	add	r12, sp, #0x180
	vld1.8	{d4-d7}, [r12]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r0, #0x160
	vst1.8	{d0-d3}, [r12]
	add	r12, sp, #0xc0
	vld1.8	{d0-d3}, [r12]
	add	r12, sp, #0x160
	vld1.8	{d4-d7}, [r12]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, sp, #0x180
	vld1.8	{d4-d7}, [r12]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r0, #0x180
	vst1.8	{d0-d3}, [r12]
	add	sp, sp, #0x1a0
	pop	{pc}
	.size	wc_mceliece_aff_v256_sqr_neon,.-wc_mceliece_aff_v256_sqr_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_aff_v256_xor13_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_aff_v256_xor13_neon)
	.type	wc_mceliece_aff_v256_xor13_neon, %function
wc_mceliece_aff_v256_xor13_neon:
	push	{r4, r5, lr}
	mov	r3, #0
L_mc_xor13_k:
	lsl	r12, r3, #5
	add	r4, r1, r12
	vld1.8	{d0-d3}, [r4]
	add	r5, r2, r12
	vld1.8	{d4-d7}, [r5]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	lr, r0, r12
	vst1.8	{d0-d3}, [lr]
	add	r3, r3, #1
	cmp	r3, #13
	blt	L_mc_xor13_k
	pop	{r4, r5, pc}
	.size	wc_mceliece_aff_v256_xor13_neon,.-wc_mceliece_aff_v256_xor13_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_aff_pack_lh_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_aff_pack_lh_neon)
	.type	wc_mceliece_aff_pack_lh_neon, %function
wc_mceliece_aff_pack_lh_neon:
	push	{r4, r5, r6, r7, lr}
	mov	r12, #0
L_mc_packlh_p:
	lsl	lr, r12, #5
	add	r6, r2, lr
	vld1.8	{d0-d3}, [r6]
	add	r7, r3, lr
	vld1.8	{d4-d7}, [r7]
	add	r4, r0, lr
	vst1.8	{d0-d1}, [r4]
	add	r4, r4, #16
	vst1.8	{d4-d5}, [r4]
	add	r5, r1, lr
	vst1.8	{d2-d3}, [r5]
	add	r5, r5, #16
	vst1.8	{d6-d7}, [r5]
	add	r12, r12, #1
	cmp	r12, #13
	blt	L_mc_packlh_p
	pop	{r4, r5, r6, r7, pc}
	.size	wc_mceliece_aff_pack_lh_neon,.-wc_mceliece_aff_pack_lh_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_aff_maa_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_aff_maa_neon)
	.type	wc_mceliece_aff_maa_neon, %function
wc_mceliece_aff_maa_neon:
	push	{r4, r5, r6, r7, r8, r9, r10, lr}
	vpush	{d8-d15}
	ldr	r12, [sp, #96]
	veor	q10, q10, q10
	mov	r8, r12
	mov	r5, #0
L_mc_v256_z_maa:
	vst1.8	{d20-d21}, [r8]
	add	r8, r8, #16
	vst1.8	{d20-d21}, [r8]
	add	r8, r8, #16
	add	r5, r5, #1
	cmp	r5, #25
	blt	L_mc_v256_z_maa
	mov	lr, #0
	mov	r6, r1
	mov	r9, r12
L_mc_v256_i_maa:
	vld1.8	{d0-d3}, [r6]
	mov	r7, r2
	mov	r8, r9
	mov	r4, #0
L_mc_v256_j_maa:
	vld1.8	{d4-d7}, [r7]
	vld1.8	{d12-d15}, [r8]
	add	r7, r7, #32
	vand	q4, q0, q2
	vand	q5, q1, q3
	veor	q6, q6, q4
	veor	q7, q7, q5
	vst1.8	{d12-d15}, [r8]
	add	r8, r8, #32
	add	r4, r4, #1
	cmp	r4, #13
	blt	L_mc_v256_j_maa
L_mc_v256_in_maa:
	add	r6, r6, #32
	add	r9, r9, #32
	add	lr, lr, #1
	cmp	lr, #13
	blt	L_mc_v256_i_maa
L_mc_v256_rs_maa:
	mov	r5, #24
	lsl	r10, r5, #5
	add	r8, r12, r10
L_mc_v256_rk_maa:
	vld1.8	{d12-d15}, [r8]
	sub	r6, r5, #9
	lsl	r6, r6, #5
	add	r9, r12, r6
	vld1.8	{d16-d19}, [r9]
	veor	q8, q8, q6
	veor	q9, q9, q7
	vst1.8	{d16-d19}, [r9]
	sub	r6, r5, #10
	lsl	r6, r6, #5
	add	r9, r12, r6
	vld1.8	{d16-d19}, [r9]
	veor	q8, q8, q6
	veor	q9, q9, q7
	vst1.8	{d16-d19}, [r9]
	sub	r6, r5, #12
	lsl	r6, r6, #5
	add	r9, r12, r6
	vld1.8	{d16-d19}, [r9]
	veor	q8, q8, q6
	veor	q9, q9, q7
	vst1.8	{d16-d19}, [r9]
	sub	r6, r5, #13
	lsl	r6, r6, #5
	add	r9, r12, r6
	vld1.8	{d16-d19}, [r9]
	veor	q8, q8, q6
	veor	q9, q9, q7
	vst1.8	{d16-d19}, [r9]
	sub	r8, r8, #32
	sub	r5, r5, #1
	cmp	r5, #13
	bge	L_mc_v256_rk_maa
L_mc_v256_copy_maa:
	mov	r5, #0
	mov	r8, r12
	mov	r9, r3
L_mc_v256_cp_maa:
	vld1.8	{d12-d15}, [r8]
	add	r8, r8, #32
	vst1.8	{d12-d15}, [r9]
	add	r9, r9, #32
	add	r5, r5, #1
	cmp	r5, #13
	blt	L_mc_v256_cp_maa
L_mc_v256_done_maa:
	mov	lr, #0
L_mc_xor13_k_maaa:
	lsl	r4, lr, #5
	add	r6, r0, r4
	vld1.8	{d0-d3}, [r6]
	add	r7, r3, r4
	vld1.8	{d4-d7}, [r7]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, r0, r4
	vst1.8	{d0-d3}, [r5]
	add	lr, lr, #1
	cmp	lr, #13
	blt	L_mc_xor13_k_maaa
	mov	lr, #0
L_mc_xor13_k_maab:
	lsl	r4, lr, #5
	add	r6, r1, r4
	vld1.8	{d0-d3}, [r6]
	add	r7, r0, r4
	vld1.8	{d4-d7}, [r7]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, r1, r4
	vst1.8	{d0-d3}, [r5]
	add	lr, lr, #1
	cmp	lr, #13
	blt	L_mc_xor13_k_maab
	vpop	{d8-d15}
	pop	{r4, r5, r6, r7, r8, r9, r10, pc}
	.size	wc_mceliece_aff_maa_neon,.-wc_mceliece_aff_maa_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_aff_ama_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_aff_ama_neon)
	.type	wc_mceliece_aff_ama_neon, %function
wc_mceliece_aff_ama_neon:
	push	{r4, r5, r6, r7, r8, r9, r10, lr}
	vpush	{d8-d15}
	ldr	r12, [sp, #96]
	mov	lr, #0
L_mc_xor13_k_amaa:
	lsl	r4, lr, #5
	add	r6, r0, r4
	vld1.8	{d0-d3}, [r6]
	add	r7, r1, r4
	vld1.8	{d4-d7}, [r7]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, r0, r4
	vst1.8	{d0-d3}, [r5]
	add	lr, lr, #1
	cmp	lr, #13
	blt	L_mc_xor13_k_amaa
	veor	q10, q10, q10
	mov	r8, r12
	mov	r5, #0
L_mc_v256_z_amam:
	vst1.8	{d20-d21}, [r8]
	add	r8, r8, #16
	vst1.8	{d20-d21}, [r8]
	add	r8, r8, #16
	add	r5, r5, #1
	cmp	r5, #25
	blt	L_mc_v256_z_amam
	mov	lr, #0
	mov	r6, r0
	mov	r9, r12
L_mc_v256_i_amam:
	vld1.8	{d0-d3}, [r6]
	mov	r7, r2
	mov	r8, r9
	mov	r4, #0
L_mc_v256_j_amam:
	vld1.8	{d4-d7}, [r7]
	vld1.8	{d12-d15}, [r8]
	add	r7, r7, #32
	vand	q4, q0, q2
	vand	q5, q1, q3
	veor	q6, q6, q4
	veor	q7, q7, q5
	vst1.8	{d12-d15}, [r8]
	add	r8, r8, #32
	add	r4, r4, #1
	cmp	r4, #13
	blt	L_mc_v256_j_amam
L_mc_v256_in_amam:
	add	r6, r6, #32
	add	r9, r9, #32
	add	lr, lr, #1
	cmp	lr, #13
	blt	L_mc_v256_i_amam
L_mc_v256_rs_amam:
	mov	r5, #24
	lsl	r10, r5, #5
	add	r8, r12, r10
L_mc_v256_rk_amam:
	vld1.8	{d12-d15}, [r8]
	sub	r6, r5, #9
	lsl	r6, r6, #5
	add	r9, r12, r6
	vld1.8	{d16-d19}, [r9]
	veor	q8, q8, q6
	veor	q9, q9, q7
	vst1.8	{d16-d19}, [r9]
	sub	r6, r5, #10
	lsl	r6, r6, #5
	add	r9, r12, r6
	vld1.8	{d16-d19}, [r9]
	veor	q8, q8, q6
	veor	q9, q9, q7
	vst1.8	{d16-d19}, [r9]
	sub	r6, r5, #12
	lsl	r6, r6, #5
	add	r9, r12, r6
	vld1.8	{d16-d19}, [r9]
	veor	q8, q8, q6
	veor	q9, q9, q7
	vst1.8	{d16-d19}, [r9]
	sub	r6, r5, #13
	lsl	r6, r6, #5
	add	r9, r12, r6
	vld1.8	{d16-d19}, [r9]
	veor	q8, q8, q6
	veor	q9, q9, q7
	vst1.8	{d16-d19}, [r9]
	sub	r8, r8, #32
	sub	r5, r5, #1
	cmp	r5, #13
	bge	L_mc_v256_rk_amam
L_mc_v256_copy_amam:
	mov	r5, #0
	mov	r8, r12
	mov	r9, r3
L_mc_v256_cp_amam:
	vld1.8	{d12-d15}, [r8]
	add	r8, r8, #32
	vst1.8	{d12-d15}, [r9]
	add	r9, r9, #32
	add	r5, r5, #1
	cmp	r5, #13
	blt	L_mc_v256_cp_amam
L_mc_v256_done_amam:
	mov	lr, #0
L_mc_xor13_k_amab:
	lsl	r4, lr, #5
	add	r6, r1, r4
	vld1.8	{d0-d3}, [r6]
	add	r7, r3, r4
	vld1.8	{d4-d7}, [r7]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r5, r1, r4
	vst1.8	{d0-d3}, [r5]
	add	lr, lr, #1
	cmp	lr, #13
	blt	L_mc_xor13_k_amab
	vpop	{d8-d15}
	pop	{r4, r5, r6, r7, r8, r9, r10, pc}
	.size	wc_mceliece_aff_ama_neon,.-wc_mceliece_aff_ama_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_fft_fwd_butterflies_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_fft_fwd_butterflies_neon)
	.type	wc_mceliece_fft_fwd_butterflies_neon, %function
wc_mceliece_fft_fwd_butterflies_neon:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	vpush	{d8-d15}
	sub	sp, sp, #4
	ldr	r8, =L_mc_aff_consts_neon
	ldr	r9, =L_mc_aff_powers_neon
	ldr	r10, =L_mc_aff_reversal_neon
	mov	r4, r0
	mov	r5, r1
	mov	r6, r2
	mov	r7, r3
	b	L_mc_pool_1
	.ltorg
L_mc_pool_1:
	veor	q4, q4, q4
	add	r0, r7, #0x1a0
	mov	r1, #0
L_mc_ffb_pz:
	cmp	r1, #0x700
	bge	L_mc_ffb_pze
	add	r2, r0, r1
	vst1.8	{d8-d9}, [r2]
	add	r1, r1, #16
	b	L_mc_ffb_pz
L_mc_ffb_pze:
	add	r0, r5, #8
	vld1.8	{d8}, [r0]
	vmov	d9, d8
	add	r1, r7, #0xd0
	vst1.8	{d8-d9}, [r1]
	add	r0, r5, #24
	vld1.8	{d8}, [r0]
	vmov	d9, d8
	add	r1, r7, #0xe0
	vst1.8	{d8-d9}, [r1]
	add	r0, r5, #40
	vld1.8	{d8}, [r0]
	vmov	d9, d8
	add	r1, r7, #0xf0
	vst1.8	{d8-d9}, [r1]
	add	r0, r5, #56
	vld1.8	{d8}, [r0]
	vmov	d9, d8
	add	r1, r7, #0x100
	vst1.8	{d8-d9}, [r1]
	add	r0, r5, #0x48
	vld1.8	{d8}, [r0]
	vmov	d9, d8
	add	r1, r7, #0x110
	vst1.8	{d8-d9}, [r1]
	add	r0, r5, #0x58
	vld1.8	{d8}, [r0]
	vmov	d9, d8
	add	r1, r7, #0x120
	vst1.8	{d8-d9}, [r1]
	add	r0, r5, #0x68
	vld1.8	{d8}, [r0]
	vmov	d9, d8
	add	r1, r7, #0x130
	vst1.8	{d8-d9}, [r1]
	add	r0, r5, #0x78
	vld1.8	{d8}, [r0]
	vmov	d9, d8
	add	r1, r7, #0x140
	vst1.8	{d8-d9}, [r1]
	add	r0, r5, #0x88
	vld1.8	{d8}, [r0]
	vmov	d9, d8
	add	r1, r7, #0x150
	vst1.8	{d8-d9}, [r1]
	add	r0, r5, #0x98
	vld1.8	{d8}, [r0]
	vmov	d9, d8
	add	r1, r7, #0x160
	vst1.8	{d8-d9}, [r1]
	add	r0, r5, #0xa8
	vld1.8	{d8}, [r0]
	vmov	d9, d8
	add	r1, r7, #0x170
	vst1.8	{d8-d9}, [r1]
	add	r0, r5, #0xb8
	vld1.8	{d8}, [r0]
	vmov	d9, d8
	add	r1, r7, #0x180
	vst1.8	{d8-d9}, [r1]
	add	r0, r5, #0xc8
	vld1.8	{d8}, [r0]
	vmov	d9, d8
	add	r1, r7, #0x190
	vst1.8	{d8-d9}, [r1]
	vmov.i8	q6, #0xff
	veor	q7, q7, q7
	add	r0, r7, #0
	vst1.8	{d14}, [r0]
	add	r0, r0, #8
	vst1.8	{d12}, [r0]
	add	r0, r7, #16
	vst1.8	{d12}, [r0]
	add	r0, r0, #8
	vst1.8	{d12}, [r0]
	add	r0, r7, #32
	vst1.8	{d14}, [r0]
	add	r0, r0, #8
	vst1.8	{d14}, [r0]
	add	r0, r7, #48
	vst1.8	{d12}, [r0]
	add	r0, r0, #8
	vst1.8	{d14}, [r0]
	add	r0, r7, #0x40
	vst1.8	{d12}, [r0]
	add	r0, r0, #8
	vst1.8	{d12}, [r0]
	add	r0, r7, #0x50
	vst1.8	{d14}, [r0]
	add	r0, r0, #8
	vst1.8	{d14}, [r0]
	add	r0, r7, #0x60
	vst1.8	{d12}, [r0]
	add	r0, r0, #8
	vst1.8	{d14}, [r0]
	add	r0, r7, #0x70
	vst1.8	{d12}, [r0]
	add	r0, r0, #8
	vst1.8	{d12}, [r0]
	add	r0, r7, #0x80
	vst1.8	{d12}, [r0]
	add	r0, r0, #8
	vst1.8	{d14}, [r0]
	add	r0, r7, #0x90
	vst1.8	{d14}, [r0]
	add	r0, r0, #8
	vst1.8	{d12}, [r0]
	add	r0, r7, #0xa0
	vst1.8	{d14}, [r0]
	add	r0, r0, #8
	vst1.8	{d12}, [r0]
	add	r0, r7, #0xb0
	vst1.8	{d12}, [r0]
	add	r0, r0, #8
	vst1.8	{d12}, [r0]
	add	r0, r7, #0xc0
	vst1.8	{d14}, [r0]
	add	r0, r0, #8
	vst1.8	{d12}, [r0]
	mov	r0, r7
	add	r1, r7, #0xd0
	mov	r2, r7
	add	r3, r7, #0x8a0
	bl	wc_mceliece_aff_v128_mul_neon
	add	r0, r7, #0
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x1a0
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x280
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #16
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x1b0
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x290
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #32
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x1c0
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x2a0
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #48
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x1d0
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x2b0
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #0x40
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x1e0
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x2c0
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #0x50
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x1f0
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x2d0
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #0x60
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x200
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x2e0
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #0x70
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x210
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x2f0
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #0x80
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x220
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x300
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #0x90
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x230
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x310
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #0xa0
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x240
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x320
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #0xb0
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x250
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x330
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #0xc0
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x260
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x340
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #0
	vst1.8	{d12}, [r0]
	add	r0, r0, #8
	vst1.8	{d12}, [r0]
	add	r0, r7, #16
	vst1.8	{d14}, [r0]
	add	r0, r0, #8
	vst1.8	{d12}, [r0]
	add	r0, r7, #32
	vst1.8	{d14}, [r0]
	add	r0, r0, #8
	vst1.8	{d14}, [r0]
	add	r0, r7, #48
	vst1.8	{d12}, [r0]
	add	r0, r0, #8
	vst1.8	{d14}, [r0]
	add	r0, r7, #0x40
	vst1.8	{d12}, [r0]
	add	r0, r0, #8
	vst1.8	{d14}, [r0]
	add	r0, r7, #0x50
	vst1.8	{d12}, [r0]
	add	r0, r0, #8
	vst1.8	{d12}, [r0]
	add	r0, r7, #0x60
	vst1.8	{d12}, [r0]
	add	r0, r0, #8
	vst1.8	{d12}, [r0]
	add	r0, r7, #0x70
	vst1.8	{d14}, [r0]
	add	r0, r0, #8
	vst1.8	{d14}, [r0]
	add	r0, r7, #0x80
	vst1.8	{d14}, [r0]
	add	r0, r0, #8
	vst1.8	{d12}, [r0]
	add	r0, r7, #0x90
	vst1.8	{d12}, [r0]
	add	r0, r0, #8
	vst1.8	{d12}, [r0]
	add	r0, r7, #0xa0
	vst1.8	{d12}, [r0]
	add	r0, r0, #8
	vst1.8	{d12}, [r0]
	add	r0, r7, #0xb0
	vst1.8	{d12}, [r0]
	add	r0, r0, #8
	vst1.8	{d12}, [r0]
	add	r0, r7, #0xc0
	vst1.8	{d12}, [r0]
	add	r0, r0, #8
	vst1.8	{d12}, [r0]
	mov	r0, r7
	add	r1, r7, #0xd0
	mov	r2, r7
	add	r3, r7, #0x8a0
	bl	wc_mceliece_aff_v128_mul_neon
	add	r0, r7, #0
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x360
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x440
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #16
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x370
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x450
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #32
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x380
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x460
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #48
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x390
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x470
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #0x40
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x3a0
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x480
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #0x50
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x3b0
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x490
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #0x60
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x3c0
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x4a0
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #0x70
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x3d0
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x4b0
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #0x80
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x3e0
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x4c0
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #0x90
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x3f0
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x4d0
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #0xa0
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x400
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x4e0
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #0xb0
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x410
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x4f0
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #0xc0
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x420
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x500
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #0
	vst1.8	{d12}, [r0]
	add	r0, r0, #8
	vst1.8	{d12}, [r0]
	add	r0, r7, #16
	vst1.8	{d14}, [r0]
	add	r0, r0, #8
	vst1.8	{d12}, [r0]
	add	r0, r7, #32
	vst1.8	{d14}, [r0]
	add	r0, r0, #8
	vst1.8	{d12}, [r0]
	add	r0, r7, #48
	vst1.8	{d14}, [r0]
	add	r0, r0, #8
	vst1.8	{d14}, [r0]
	add	r0, r7, #0x40
	vst1.8	{d12}, [r0]
	add	r0, r0, #8
	vst1.8	{d14}, [r0]
	add	r0, r7, #0x50
	vst1.8	{d12}, [r0]
	add	r0, r0, #8
	vst1.8	{d12}, [r0]
	add	r0, r7, #0x60
	vst1.8	{d12}, [r0]
	add	r0, r0, #8
	vst1.8	{d12}, [r0]
	add	r0, r7, #0x70
	vst1.8	{d12}, [r0]
	add	r0, r0, #8
	vst1.8	{d12}, [r0]
	add	r0, r7, #0x80
	vst1.8	{d14}, [r0]
	add	r0, r0, #8
	vst1.8	{d12}, [r0]
	add	r0, r7, #0x90
	vst1.8	{d12}, [r0]
	add	r0, r0, #8
	vst1.8	{d12}, [r0]
	add	r0, r7, #0xa0
	vst1.8	{d14}, [r0]
	add	r0, r0, #8
	vst1.8	{d12}, [r0]
	add	r0, r7, #0xb0
	vst1.8	{d12}, [r0]
	add	r0, r0, #8
	vst1.8	{d12}, [r0]
	add	r0, r7, #0xc0
	vst1.8	{d12}, [r0]
	add	r0, r0, #8
	vst1.8	{d12}, [r0]
	mov	r0, r7
	add	r1, r7, #0xd0
	mov	r2, r7
	add	r3, r7, #0x8a0
	bl	wc_mceliece_aff_v128_mul_neon
	add	r0, r7, #0
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x520
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x600
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #16
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x530
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x610
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #32
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x540
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x620
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #48
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x550
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x630
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #0x40
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x560
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x640
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #0x50
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x570
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x650
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #0x60
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x580
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x660
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #0x70
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x590
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x670
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #0x80
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x5a0
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x680
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #0x90
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x5b0
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x690
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #0xa0
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x5c0
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x6a0
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #0xb0
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x5d0
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x6b0
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #0xc0
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x5e0
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x6c0
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #0
	vst1.8	{d14}, [r0]
	add	r0, r0, #8
	vst1.8	{d14}, [r0]
	add	r0, r7, #16
	vst1.8	{d14}, [r0]
	add	r0, r0, #8
	vst1.8	{d14}, [r0]
	add	r0, r7, #32
	vst1.8	{d12}, [r0]
	add	r0, r0, #8
	vst1.8	{d14}, [r0]
	add	r0, r7, #48
	vst1.8	{d14}, [r0]
	add	r0, r0, #8
	vst1.8	{d14}, [r0]
	add	r0, r7, #0x40
	vst1.8	{d12}, [r0]
	add	r0, r0, #8
	vst1.8	{d14}, [r0]
	add	r0, r7, #0x50
	vst1.8	{d14}, [r0]
	add	r0, r0, #8
	vst1.8	{d14}, [r0]
	add	r0, r7, #0x60
	vst1.8	{d14}, [r0]
	add	r0, r0, #8
	vst1.8	{d14}, [r0]
	add	r0, r7, #0x70
	vst1.8	{d12}, [r0]
	add	r0, r0, #8
	vst1.8	{d14}, [r0]
	add	r0, r7, #0x80
	vst1.8	{d12}, [r0]
	add	r0, r0, #8
	vst1.8	{d14}, [r0]
	add	r0, r7, #0x90
	vst1.8	{d14}, [r0]
	add	r0, r0, #8
	vst1.8	{d14}, [r0]
	add	r0, r7, #0xa0
	vst1.8	{d12}, [r0]
	add	r0, r0, #8
	vst1.8	{d14}, [r0]
	add	r0, r7, #0xb0
	vst1.8	{d12}, [r0]
	add	r0, r0, #8
	vst1.8	{d14}, [r0]
	add	r0, r7, #0xc0
	vst1.8	{d14}, [r0]
	add	r0, r0, #8
	vst1.8	{d14}, [r0]
	mov	r0, r7
	add	r1, r7, #0xd0
	mov	r2, r7
	add	r3, r7, #0x8a0
	bl	wc_mceliece_aff_v128_mul_neon
	add	r0, r7, #0
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x6e0
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x7c0
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #16
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x6f0
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x7d0
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #32
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x700
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x7e0
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #48
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x710
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x7f0
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #0x40
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x720
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x800
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #0x50
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x730
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x810
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #0x60
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x740
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x820
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #0x70
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x750
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x830
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #0x80
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x760
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x840
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #0x90
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x770
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x850
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #0xa0
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x780
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x860
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #0xb0
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x790
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x870
	vst1.8	{d10-d11}, [r1]
	add	r0, r7, #0xc0
	vld1.8	{d8}, [r0]
	add	r0, r0, #8
	vld1.8	{d9}, [r0]
	vmov	d10, d8
	vmov	d11, d8
	add	r1, r7, #0x7a0
	vst1.8	{d10-d11}, [r1]
	vmov	d10, d9
	vmov	d11, d9
	add	r1, r7, #0x880
	vst1.8	{d10-d11}, [r1]
	mov	r11, #0
L_mc_ffb_i:
	cmp	r11, #13
	bge	L_mc_ffb_ie
	lsl	r0, r11, #4
	add	r1, r5, r0
	add	r2, r7, #0x8a0
	vld1.8	{d8}, [r1]
	vst1.8	{d8}, [r2]
	add	r3, r7, #0x6e0
	add	r3, r3, r0
	vld1.8	{d9}, [r3]
	veor	d10, d8, d9
	add	r12, r2, #8
	vst1.8	{d10}, [r12]
	cmp	r11, #12
	beq	L_mc_ffb_hi
	add	r12, r1, #16
	vld1.8	{d8}, [r12]
	add	r12, r2, #16
	vst1.8	{d8}, [r12]
	add	r12, r3, #16
	vld1.8	{d9}, [r12]
	veor	d10, d8, d9
	add	r12, r2, #24
	vst1.8	{d10}, [r12]
L_mc_ffb_hi:
	lsr	r0, r11, #1
	lsl	r0, r0, #5
	add	r3, r7, r0
	add	r3, r3, #0x1a0
	vld1.8	{d0-d3}, [r2]
	vld1.8	{d4-d7}, [r3]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #32
	vst1.8	{d0-d3}, [r12]
	vld1.8	{d0-d3}, [r2]
	add	r1, r3, #0x380
	vld1.8	{d4-d7}, [r1]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x200
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #32
	vld1.8	{d0-d3}, [r0]
	add	r1, r3, #0xe0
	vld1.8	{d4-d7}, [r1]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x60
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x200
	vld1.8	{d0-d3}, [r0]
	add	r1, r3, #0x460
	vld1.8	{d4-d7}, [r1]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x600
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x600
	vld1.8	{d0-d3}, [r0]
	vld1.8	{d4-d7}, [r3]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x620
	vst1.8	{d0-d3}, [r12]
	vld1.8	{d0-d3}, [r2]
	add	r1, r3, #0xe0
	vld1.8	{d4-d7}, [r1]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x40
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x620
	vld1.8	{d0-d3}, [r0]
	add	r1, r3, #0xe0
	vld1.8	{d4-d7}, [r1]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x660
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x40
	vld1.8	{d0-d3}, [r0]
	add	r1, r3, #0x1c0
	vld1.8	{d4-d7}, [r1]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0xc0
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x660
	vld1.8	{d0-d3}, [r0]
	vld1.8	{d4-d7}, [r3]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x640
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0xc0
	vld1.8	{d0-d3}, [r0]
	vld1.8	{d4-d7}, [r3]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0xe0
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x640
	vld1.8	{d0-d3}, [r0]
	add	r1, r3, #0x1c0
	vld1.8	{d4-d7}, [r1]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x6c0
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0xe0
	vld1.8	{d0-d3}, [r0]
	add	r1, r3, #0xe0
	vld1.8	{d4-d7}, [r1]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0xa0
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x6c0
	vld1.8	{d0-d3}, [r0]
	vld1.8	{d4-d7}, [r3]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x6e0
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x6e0
	vld1.8	{d0-d3}, [r0]
	add	r1, r3, #0xe0
	vld1.8	{d4-d7}, [r1]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x6a0
	vst1.8	{d0-d3}, [r12]
	vld1.8	{d0-d3}, [r2]
	add	r1, r3, #0x1c0
	vld1.8	{d4-d7}, [r1]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x80
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x6a0
	vld1.8	{d0-d3}, [r0]
	vld1.8	{d4-d7}, [r3]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x680
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x80
	vld1.8	{d0-d3}, [r0]
	add	r1, r3, #0x2a0
	vld1.8	{d4-d7}, [r1]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x180
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x680
	vld1.8	{d0-d3}, [r0]
	add	r1, r3, #0x2a0
	vld1.8	{d4-d7}, [r1]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x780
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x180
	vld1.8	{d0-d3}, [r0]
	vld1.8	{d4-d7}, [r3]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x1a0
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x780
	vld1.8	{d0-d3}, [r0]
	vld1.8	{d4-d7}, [r3]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x7a0
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x1a0
	vld1.8	{d0-d3}, [r0]
	add	r1, r3, #0xe0
	vld1.8	{d4-d7}, [r1]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x1e0
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x7a0
	vld1.8	{d0-d3}, [r0]
	add	r1, r3, #0xe0
	vld1.8	{d4-d7}, [r1]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x7e0
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x1e0
	vld1.8	{d0-d3}, [r0]
	vld1.8	{d4-d7}, [r3]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x1c0
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x7e0
	vld1.8	{d0-d3}, [r0]
	vld1.8	{d4-d7}, [r3]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x7c0
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x1c0
	vld1.8	{d0-d3}, [r0]
	add	r1, r3, #0x1c0
	vld1.8	{d4-d7}, [r1]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x140
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x7c0
	vld1.8	{d0-d3}, [r0]
	add	r1, r3, #0x1c0
	vld1.8	{d4-d7}, [r1]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x740
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x140
	vld1.8	{d0-d3}, [r0]
	vld1.8	{d4-d7}, [r3]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x160
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x740
	vld1.8	{d0-d3}, [r0]
	vld1.8	{d4-d7}, [r3]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x760
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x160
	vld1.8	{d0-d3}, [r0]
	add	r1, r3, #0xe0
	vld1.8	{d4-d7}, [r1]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x120
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x760
	vld1.8	{d0-d3}, [r0]
	add	r1, r3, #0xe0
	vld1.8	{d4-d7}, [r1]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x720
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x720
	vld1.8	{d0-d3}, [r0]
	vld1.8	{d4-d7}, [r3]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x700
	vst1.8	{d0-d3}, [r12]
	vld1.8	{d0-d3}, [r2]
	add	r1, r3, #0x2a0
	vld1.8	{d4-d7}, [r1]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x100
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x700
	vld1.8	{d0-d3}, [r0]
	add	r1, r3, #0x380
	vld1.8	{d4-d7}, [r1]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x500
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x100
	vld1.8	{d0-d3}, [r0]
	add	r1, r3, #0x380
	vld1.8	{d4-d7}, [r1]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x300
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x500
	vld1.8	{d0-d3}, [r0]
	vld1.8	{d4-d7}, [r3]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x520
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x300
	vld1.8	{d0-d3}, [r0]
	vld1.8	{d4-d7}, [r3]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x320
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x520
	vld1.8	{d0-d3}, [r0]
	add	r1, r3, #0xe0
	vld1.8	{d4-d7}, [r1]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x560
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x320
	vld1.8	{d0-d3}, [r0]
	add	r1, r3, #0xe0
	vld1.8	{d4-d7}, [r1]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x360
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x560
	vld1.8	{d0-d3}, [r0]
	vld1.8	{d4-d7}, [r3]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x540
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x360
	vld1.8	{d0-d3}, [r0]
	vld1.8	{d4-d7}, [r3]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x340
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x540
	vld1.8	{d0-d3}, [r0]
	add	r1, r3, #0x1c0
	vld1.8	{d4-d7}, [r1]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x5c0
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x340
	vld1.8	{d0-d3}, [r0]
	add	r1, r3, #0x1c0
	vld1.8	{d4-d7}, [r1]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x3c0
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x5c0
	vld1.8	{d0-d3}, [r0]
	vld1.8	{d4-d7}, [r3]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x5e0
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x3c0
	vld1.8	{d0-d3}, [r0]
	vld1.8	{d4-d7}, [r3]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x3e0
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x5e0
	vld1.8	{d0-d3}, [r0]
	add	r1, r3, #0xe0
	vld1.8	{d4-d7}, [r1]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x5a0
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x3e0
	vld1.8	{d0-d3}, [r0]
	add	r1, r3, #0xe0
	vld1.8	{d4-d7}, [r1]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x3a0
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x5a0
	vld1.8	{d0-d3}, [r0]
	vld1.8	{d4-d7}, [r3]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x580
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x3a0
	vld1.8	{d0-d3}, [r0]
	vld1.8	{d4-d7}, [r3]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x380
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x580
	vld1.8	{d0-d3}, [r0]
	add	r1, r3, #0x2a0
	vld1.8	{d4-d7}, [r1]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x480
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x380
	vld1.8	{d0-d3}, [r0]
	add	r1, r3, #0x2a0
	vld1.8	{d4-d7}, [r1]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x280
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x480
	vld1.8	{d0-d3}, [r0]
	vld1.8	{d4-d7}, [r3]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x4a0
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x280
	vld1.8	{d0-d3}, [r0]
	vld1.8	{d4-d7}, [r3]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x2a0
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x4a0
	vld1.8	{d0-d3}, [r0]
	add	r1, r3, #0xe0
	vld1.8	{d4-d7}, [r1]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x4e0
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x2a0
	vld1.8	{d0-d3}, [r0]
	add	r1, r3, #0xe0
	vld1.8	{d4-d7}, [r1]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x2e0
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x4e0
	vld1.8	{d0-d3}, [r0]
	vld1.8	{d4-d7}, [r3]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x4c0
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x2e0
	vld1.8	{d0-d3}, [r0]
	vld1.8	{d4-d7}, [r3]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x2c0
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x4c0
	vld1.8	{d0-d3}, [r0]
	add	r1, r3, #0x1c0
	vld1.8	{d4-d7}, [r1]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x440
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x2c0
	vld1.8	{d0-d3}, [r0]
	add	r1, r3, #0x1c0
	vld1.8	{d4-d7}, [r1]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x240
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x440
	vld1.8	{d0-d3}, [r0]
	vld1.8	{d4-d7}, [r3]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x460
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x240
	vld1.8	{d0-d3}, [r0]
	vld1.8	{d4-d7}, [r3]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x260
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x460
	vld1.8	{d0-d3}, [r0]
	add	r1, r3, #0xe0
	vld1.8	{d4-d7}, [r1]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x420
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x260
	vld1.8	{d0-d3}, [r0]
	add	r1, r3, #0xe0
	vld1.8	{d4-d7}, [r1]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x220
	vst1.8	{d0-d3}, [r12]
	add	r0, r2, #0x420
	vld1.8	{d0-d3}, [r0]
	vld1.8	{d4-d7}, [r3]
	veor	q0, q0, q2
	veor	q1, q1, q3
	add	r12, r2, #0x400
	vst1.8	{d0-d3}, [r12]
	add	r0, r7, #0x8a0
	bl	wc_mceliece_aff_transpose_neon
	mov	r0, r4
	add	r1, r7, #0x8a0
	mov	r2, r11
	bl	wc_mceliece_aff_fwd_out_neon
	add	r11, r11, #2
	b	L_mc_ffb_i
L_mc_ffb_ie:
	mov	r11, #0
L_mc_ffb_pk:
	cmp	r11, #32
	bge	L_mc_ffb_pke
	add	r0, r7, #0x8a0
	add	r1, r7, #0xa40
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r12, #0xa0
	orr	r12, r12, #0x100
#else
	mov	r12, #0x1a0
#endif
	mul	r2, r11, r12
	add	r2, r4, r2
	add	r3, r2, #0x1a0
	bl	wc_mceliece_aff_pack_lh_neon
	add	r0, r7, #0x8a0
	add	r1, r7, #0xa40
	add	r2, r8, #0x1a0
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r12, #0xa0
	orr	r12, r12, #0x100
#else
	mov	r12, #0x1a0
#endif
	mul	r0, r11, r12
	add	r0, r4, r0
	add	r1, r0, #0x1a0
	add	r2, r7, #0x8a0
	add	r3, r7, #0xa40
	bl	wc_mceliece_aff_pack_lh_neon
	add	r11, r11, #2
	b	L_mc_ffb_pk
L_mc_ffb_pke:
	mov	r0, #0
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xa0
	orr	r1, r1, #0x100
#else
	mov	r1, #0x1a0
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x40
	orr	r2, r2, #0x300
#else
	mov	r2, #0x340
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x40
	orr	r0, r0, #0x300
#else
	mov	r0, #0x340
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xe0
	orr	r1, r1, #0x400
#else
	mov	r1, #0x4e0
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x40
	orr	r2, r2, #0x300
#else
	mov	r2, #0x340
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x80
	orr	r0, r0, #0x600
#else
	mov	r0, #0x680
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x20
	orr	r1, r1, #0x800
#else
	mov	r1, #0x820
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x40
	orr	r2, r2, #0x300
#else
	mov	r2, #0x340
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xc0
	orr	r0, r0, #0x900
#else
	mov	r0, #0x9c0
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x60
	orr	r1, r1, #0xb00
#else
	mov	r1, #0xb60
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x40
	orr	r2, r2, #0x300
#else
	mov	r2, #0x340
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
	mov	r0, #0xd00
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xa0
	orr	r1, r1, #0xe00
#else
	mov	r1, #0xea0
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x40
	orr	r2, r2, #0x300
#else
	mov	r2, #0x340
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x40
	orr	r0, r0, #0x1000
#else
	mov	r0, #0x1040
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xe0
	orr	r1, r1, #0x1100
#else
	mov	r1, #0x11e0
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x40
	orr	r2, r2, #0x300
#else
	mov	r2, #0x340
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x80
	orr	r0, r0, #0x1300
#else
	mov	r0, #0x1380
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x20
	orr	r1, r1, #0x1500
#else
	mov	r1, #0x1520
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x40
	orr	r2, r2, #0x300
#else
	mov	r2, #0x340
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xc0
	orr	r0, r0, #0x1600
#else
	mov	r0, #0x16c0
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x60
	orr	r1, r1, #0x1800
#else
	mov	r1, #0x1860
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x40
	orr	r2, r2, #0x300
#else
	mov	r2, #0x340
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
	mov	r0, #0x1a00
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xa0
	orr	r1, r1, #0x1b00
#else
	mov	r1, #0x1ba0
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x40
	orr	r2, r2, #0x300
#else
	mov	r2, #0x340
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x40
	orr	r0, r0, #0x1d00
#else
	mov	r0, #0x1d40
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xe0
	orr	r1, r1, #0x1e00
#else
	mov	r1, #0x1ee0
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x40
	orr	r2, r2, #0x300
#else
	mov	r2, #0x340
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x80
	orr	r0, r0, #0x2000
#else
	mov	r0, #0x2080
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x20
	orr	r1, r1, #0x2200
#else
	mov	r1, #0x2220
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x40
	orr	r2, r2, #0x300
#else
	mov	r2, #0x340
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xc0
	orr	r0, r0, #0x2300
#else
	mov	r0, #0x23c0
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x60
	orr	r1, r1, #0x2500
#else
	mov	r1, #0x2560
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x40
	orr	r2, r2, #0x300
#else
	mov	r2, #0x340
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
	mov	r0, #0x2700
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xa0
	orr	r1, r1, #0x2800
#else
	mov	r1, #0x28a0
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x40
	orr	r2, r2, #0x300
#else
	mov	r2, #0x340
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x40
	orr	r0, r0, #0x2a00
#else
	mov	r0, #0x2a40
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xe0
	orr	r1, r1, #0x2b00
#else
	mov	r1, #0x2be0
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x40
	orr	r2, r2, #0x300
#else
	mov	r2, #0x340
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x80
	orr	r0, r0, #0x2d00
#else
	mov	r0, #0x2d80
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x20
	orr	r1, r1, #0x2f00
#else
	mov	r1, #0x2f20
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x40
	orr	r2, r2, #0x300
#else
	mov	r2, #0x340
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xc0
	orr	r0, r0, #0x3000
#else
	mov	r0, #0x30c0
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x60
	orr	r1, r1, #0x3200
#else
	mov	r1, #0x3260
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x40
	orr	r2, r2, #0x300
#else
	mov	r2, #0x340
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
	mov	r0, #0
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x40
	orr	r1, r1, #0x300
#else
	mov	r1, #0x340
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xe0
	orr	r2, r2, #0x400
#else
	mov	r2, #0x4e0
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xa0
	orr	r0, r0, #0x100
#else
	mov	r0, #0x1a0
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xe0
	orr	r1, r1, #0x400
#else
	mov	r1, #0x4e0
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x80
	orr	r2, r2, #0x600
#else
	mov	r2, #0x680
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x80
	orr	r0, r0, #0x600
#else
	mov	r0, #0x680
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xc0
	orr	r1, r1, #0x900
#else
	mov	r1, #0x9c0
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xe0
	orr	r2, r2, #0x400
#else
	mov	r2, #0x4e0
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x20
	orr	r0, r0, #0x800
#else
	mov	r0, #0x820
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x60
	orr	r1, r1, #0xb00
#else
	mov	r1, #0xb60
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x80
	orr	r2, r2, #0x600
#else
	mov	r2, #0x680
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
	mov	r0, #0xd00
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x40
	orr	r1, r1, #0x1000
#else
	mov	r1, #0x1040
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xe0
	orr	r2, r2, #0x400
#else
	mov	r2, #0x4e0
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xa0
	orr	r0, r0, #0xe00
#else
	mov	r0, #0xea0
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xe0
	orr	r1, r1, #0x1100
#else
	mov	r1, #0x11e0
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x80
	orr	r2, r2, #0x600
#else
	mov	r2, #0x680
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x80
	orr	r0, r0, #0x1300
#else
	mov	r0, #0x1380
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xc0
	orr	r1, r1, #0x1600
#else
	mov	r1, #0x16c0
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xe0
	orr	r2, r2, #0x400
#else
	mov	r2, #0x4e0
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x20
	orr	r0, r0, #0x1500
#else
	mov	r0, #0x1520
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x60
	orr	r1, r1, #0x1800
#else
	mov	r1, #0x1860
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x80
	orr	r2, r2, #0x600
#else
	mov	r2, #0x680
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
	mov	r0, #0x1a00
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x40
	orr	r1, r1, #0x1d00
#else
	mov	r1, #0x1d40
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xe0
	orr	r2, r2, #0x400
#else
	mov	r2, #0x4e0
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xa0
	orr	r0, r0, #0x1b00
#else
	mov	r0, #0x1ba0
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xe0
	orr	r1, r1, #0x1e00
#else
	mov	r1, #0x1ee0
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x80
	orr	r2, r2, #0x600
#else
	mov	r2, #0x680
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x80
	orr	r0, r0, #0x2000
#else
	mov	r0, #0x2080
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xc0
	orr	r1, r1, #0x2300
#else
	mov	r1, #0x23c0
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xe0
	orr	r2, r2, #0x400
#else
	mov	r2, #0x4e0
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x20
	orr	r0, r0, #0x2200
#else
	mov	r0, #0x2220
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x60
	orr	r1, r1, #0x2500
#else
	mov	r1, #0x2560
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x80
	orr	r2, r2, #0x600
#else
	mov	r2, #0x680
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
	mov	r0, #0x2700
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x40
	orr	r1, r1, #0x2a00
#else
	mov	r1, #0x2a40
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xe0
	orr	r2, r2, #0x400
#else
	mov	r2, #0x4e0
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xa0
	orr	r0, r0, #0x2800
#else
	mov	r0, #0x28a0
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xe0
	orr	r1, r1, #0x2b00
#else
	mov	r1, #0x2be0
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x80
	orr	r2, r2, #0x600
#else
	mov	r2, #0x680
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x80
	orr	r0, r0, #0x2d00
#else
	mov	r0, #0x2d80
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xc0
	orr	r1, r1, #0x3000
#else
	mov	r1, #0x30c0
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xe0
	orr	r2, r2, #0x400
#else
	mov	r2, #0x4e0
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x20
	orr	r0, r0, #0x2f00
#else
	mov	r0, #0x2f20
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x60
	orr	r1, r1, #0x3200
#else
	mov	r1, #0x3260
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x80
	orr	r2, r2, #0x600
#else
	mov	r2, #0x680
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
	mov	r0, #0
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x80
	orr	r1, r1, #0x600
#else
	mov	r1, #0x680
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x20
	orr	r2, r2, #0x800
#else
	mov	r2, #0x820
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xa0
	orr	r0, r0, #0x100
#else
	mov	r0, #0x1a0
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x20
	orr	r1, r1, #0x800
#else
	mov	r1, #0x820
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xc0
	orr	r2, r2, #0x900
#else
	mov	r2, #0x9c0
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x40
	orr	r0, r0, #0x300
#else
	mov	r0, #0x340
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xc0
	orr	r1, r1, #0x900
#else
	mov	r1, #0x9c0
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x60
	orr	r2, r2, #0xb00
#else
	mov	r2, #0xb60
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xe0
	orr	r0, r0, #0x400
#else
	mov	r0, #0x4e0
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x60
	orr	r1, r1, #0xb00
#else
	mov	r1, #0xb60
#endif
	add	r1, r4, r1
	mov	r2, #0xd00
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
	mov	r0, #0xd00
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x80
	orr	r1, r1, #0x1300
#else
	mov	r1, #0x1380
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x20
	orr	r2, r2, #0x800
#else
	mov	r2, #0x820
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xa0
	orr	r0, r0, #0xe00
#else
	mov	r0, #0xea0
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x20
	orr	r1, r1, #0x1500
#else
	mov	r1, #0x1520
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xc0
	orr	r2, r2, #0x900
#else
	mov	r2, #0x9c0
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x40
	orr	r0, r0, #0x1000
#else
	mov	r0, #0x1040
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xc0
	orr	r1, r1, #0x1600
#else
	mov	r1, #0x16c0
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x60
	orr	r2, r2, #0xb00
#else
	mov	r2, #0xb60
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xe0
	orr	r0, r0, #0x1100
#else
	mov	r0, #0x11e0
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x60
	orr	r1, r1, #0x1800
#else
	mov	r1, #0x1860
#endif
	add	r1, r4, r1
	mov	r2, #0xd00
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
	mov	r0, #0x1a00
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x80
	orr	r1, r1, #0x2000
#else
	mov	r1, #0x2080
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x20
	orr	r2, r2, #0x800
#else
	mov	r2, #0x820
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xa0
	orr	r0, r0, #0x1b00
#else
	mov	r0, #0x1ba0
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x20
	orr	r1, r1, #0x2200
#else
	mov	r1, #0x2220
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xc0
	orr	r2, r2, #0x900
#else
	mov	r2, #0x9c0
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x40
	orr	r0, r0, #0x1d00
#else
	mov	r0, #0x1d40
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xc0
	orr	r1, r1, #0x2300
#else
	mov	r1, #0x23c0
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x60
	orr	r2, r2, #0xb00
#else
	mov	r2, #0xb60
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xe0
	orr	r0, r0, #0x1e00
#else
	mov	r0, #0x1ee0
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x60
	orr	r1, r1, #0x2500
#else
	mov	r1, #0x2560
#endif
	add	r1, r4, r1
	mov	r2, #0xd00
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
	mov	r0, #0x2700
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x80
	orr	r1, r1, #0x2d00
#else
	mov	r1, #0x2d80
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x20
	orr	r2, r2, #0x800
#else
	mov	r2, #0x820
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xa0
	orr	r0, r0, #0x2800
#else
	mov	r0, #0x28a0
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x20
	orr	r1, r1, #0x2f00
#else
	mov	r1, #0x2f20
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xc0
	orr	r2, r2, #0x900
#else
	mov	r2, #0x9c0
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x40
	orr	r0, r0, #0x2a00
#else
	mov	r0, #0x2a40
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xc0
	orr	r1, r1, #0x3000
#else
	mov	r1, #0x30c0
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x60
	orr	r2, r2, #0xb00
#else
	mov	r2, #0xb60
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xe0
	orr	r0, r0, #0x2b00
#else
	mov	r0, #0x2be0
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x60
	orr	r1, r1, #0x3200
#else
	mov	r1, #0x3260
#endif
	add	r1, r4, r1
	mov	r2, #0xd00
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
	mov	r0, #0
	add	r0, r4, r0
	mov	r1, #0xd00
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xa0
	orr	r2, r2, #0xe00
#else
	mov	r2, #0xea0
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xa0
	orr	r0, r0, #0x100
#else
	mov	r0, #0x1a0
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xa0
	orr	r1, r1, #0xe00
#else
	mov	r1, #0xea0
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x40
	orr	r2, r2, #0x1000
#else
	mov	r2, #0x1040
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x40
	orr	r0, r0, #0x300
#else
	mov	r0, #0x340
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x40
	orr	r1, r1, #0x1000
#else
	mov	r1, #0x1040
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xe0
	orr	r2, r2, #0x1100
#else
	mov	r2, #0x11e0
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xe0
	orr	r0, r0, #0x400
#else
	mov	r0, #0x4e0
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xe0
	orr	r1, r1, #0x1100
#else
	mov	r1, #0x11e0
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x80
	orr	r2, r2, #0x1300
#else
	mov	r2, #0x1380
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x80
	orr	r0, r0, #0x600
#else
	mov	r0, #0x680
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x80
	orr	r1, r1, #0x1300
#else
	mov	r1, #0x1380
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x20
	orr	r2, r2, #0x1500
#else
	mov	r2, #0x1520
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x20
	orr	r0, r0, #0x800
#else
	mov	r0, #0x820
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x20
	orr	r1, r1, #0x1500
#else
	mov	r1, #0x1520
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xc0
	orr	r2, r2, #0x1600
#else
	mov	r2, #0x16c0
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xc0
	orr	r0, r0, #0x900
#else
	mov	r0, #0x9c0
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xc0
	orr	r1, r1, #0x1600
#else
	mov	r1, #0x16c0
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x60
	orr	r2, r2, #0x1800
#else
	mov	r2, #0x1860
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x60
	orr	r0, r0, #0xb00
#else
	mov	r0, #0xb60
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x60
	orr	r1, r1, #0x1800
#else
	mov	r1, #0x1860
#endif
	add	r1, r4, r1
	mov	r2, #0x1a00
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
	mov	r0, #0x1a00
	add	r0, r4, r0
	mov	r1, #0x2700
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xa0
	orr	r2, r2, #0xe00
#else
	mov	r2, #0xea0
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xa0
	orr	r0, r0, #0x1b00
#else
	mov	r0, #0x1ba0
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xa0
	orr	r1, r1, #0x2800
#else
	mov	r1, #0x28a0
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x40
	orr	r2, r2, #0x1000
#else
	mov	r2, #0x1040
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x40
	orr	r0, r0, #0x1d00
#else
	mov	r0, #0x1d40
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x40
	orr	r1, r1, #0x2a00
#else
	mov	r1, #0x2a40
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xe0
	orr	r2, r2, #0x1100
#else
	mov	r2, #0x11e0
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xe0
	orr	r0, r0, #0x1e00
#else
	mov	r0, #0x1ee0
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xe0
	orr	r1, r1, #0x2b00
#else
	mov	r1, #0x2be0
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x80
	orr	r2, r2, #0x1300
#else
	mov	r2, #0x1380
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x80
	orr	r0, r0, #0x2000
#else
	mov	r0, #0x2080
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x80
	orr	r1, r1, #0x2d00
#else
	mov	r1, #0x2d80
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x20
	orr	r2, r2, #0x1500
#else
	mov	r2, #0x1520
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x20
	orr	r0, r0, #0x2200
#else
	mov	r0, #0x2220
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x20
	orr	r1, r1, #0x2f00
#else
	mov	r1, #0x2f20
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xc0
	orr	r2, r2, #0x1600
#else
	mov	r2, #0x16c0
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xc0
	orr	r0, r0, #0x2300
#else
	mov	r0, #0x23c0
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xc0
	orr	r1, r1, #0x3000
#else
	mov	r1, #0x30c0
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x60
	orr	r2, r2, #0x1800
#else
	mov	r2, #0x1860
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x60
	orr	r0, r0, #0x2500
#else
	mov	r0, #0x2560
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x60
	orr	r1, r1, #0x3200
#else
	mov	r1, #0x3260
#endif
	add	r1, r4, r1
	mov	r2, #0x1a00
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
	mov	r0, #0
	add	r0, r4, r0
	mov	r1, #0x1a00
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xa0
	orr	r2, r2, #0x1b00
#else
	mov	r2, #0x1ba0
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xa0
	orr	r0, r0, #0x100
#else
	mov	r0, #0x1a0
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xa0
	orr	r1, r1, #0x1b00
#else
	mov	r1, #0x1ba0
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x40
	orr	r2, r2, #0x1d00
#else
	mov	r2, #0x1d40
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x40
	orr	r0, r0, #0x300
#else
	mov	r0, #0x340
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x40
	orr	r1, r1, #0x1d00
#else
	mov	r1, #0x1d40
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xe0
	orr	r2, r2, #0x1e00
#else
	mov	r2, #0x1ee0
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xe0
	orr	r0, r0, #0x400
#else
	mov	r0, #0x4e0
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xe0
	orr	r1, r1, #0x1e00
#else
	mov	r1, #0x1ee0
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x80
	orr	r2, r2, #0x2000
#else
	mov	r2, #0x2080
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x80
	orr	r0, r0, #0x600
#else
	mov	r0, #0x680
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x80
	orr	r1, r1, #0x2000
#else
	mov	r1, #0x2080
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x20
	orr	r2, r2, #0x2200
#else
	mov	r2, #0x2220
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x20
	orr	r0, r0, #0x800
#else
	mov	r0, #0x820
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x20
	orr	r1, r1, #0x2200
#else
	mov	r1, #0x2220
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xc0
	orr	r2, r2, #0x2300
#else
	mov	r2, #0x23c0
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xc0
	orr	r0, r0, #0x900
#else
	mov	r0, #0x9c0
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xc0
	orr	r1, r1, #0x2300
#else
	mov	r1, #0x23c0
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x60
	orr	r2, r2, #0x2500
#else
	mov	r2, #0x2560
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x60
	orr	r0, r0, #0xb00
#else
	mov	r0, #0xb60
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x60
	orr	r1, r1, #0x2500
#else
	mov	r1, #0x2560
#endif
	add	r1, r4, r1
	mov	r2, #0x2700
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
	mov	r0, #0xd00
	add	r0, r4, r0
	mov	r1, #0x2700
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xa0
	orr	r2, r2, #0x2800
#else
	mov	r2, #0x28a0
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xa0
	orr	r0, r0, #0xe00
#else
	mov	r0, #0xea0
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xa0
	orr	r1, r1, #0x2800
#else
	mov	r1, #0x28a0
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x40
	orr	r2, r2, #0x2a00
#else
	mov	r2, #0x2a40
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x40
	orr	r0, r0, #0x1000
#else
	mov	r0, #0x1040
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x40
	orr	r1, r1, #0x2a00
#else
	mov	r1, #0x2a40
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xe0
	orr	r2, r2, #0x2b00
#else
	mov	r2, #0x2be0
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xe0
	orr	r0, r0, #0x1100
#else
	mov	r0, #0x11e0
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xe0
	orr	r1, r1, #0x2b00
#else
	mov	r1, #0x2be0
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x80
	orr	r2, r2, #0x2d00
#else
	mov	r2, #0x2d80
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x80
	orr	r0, r0, #0x1300
#else
	mov	r0, #0x1380
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x80
	orr	r1, r1, #0x2d00
#else
	mov	r1, #0x2d80
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x20
	orr	r2, r2, #0x2f00
#else
	mov	r2, #0x2f20
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x20
	orr	r0, r0, #0x1500
#else
	mov	r0, #0x1520
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x20
	orr	r1, r1, #0x2f00
#else
	mov	r1, #0x2f20
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xc0
	orr	r2, r2, #0x3000
#else
	mov	r2, #0x30c0
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xc0
	orr	r0, r0, #0x1600
#else
	mov	r0, #0x16c0
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xc0
	orr	r1, r1, #0x3000
#else
	mov	r1, #0x30c0
#endif
	add	r1, r4, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x60
	orr	r2, r2, #0x3200
#else
	mov	r2, #0x3260
#endif
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x60
	orr	r0, r0, #0x1800
#else
	mov	r0, #0x1860
#endif
	add	r0, r4, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x60
	orr	r1, r1, #0x3200
#else
	mov	r1, #0x3260
#endif
	add	r1, r4, r1
	mov	r2, #0x3400
	add	r2, r8, r2
	add	r3, r7, #0xbe0
	add	r12, r7, #0xd80
	str	r12, [sp]
	bl	wc_mceliece_aff_maa_neon
	cmp	r6, #0
	beq	L_mc_ffb_nm
	mov	r0, #0
L_mc_ffb_mo:
	cmp	r0, #0x1a0
	bge	L_mc_ffb_moe
	lsl	r1, r0, #5
	add	r2, r4, r1
	vld1.8	{d0-d3}, [r2]
	add	r3, r9, r1
	vld1.8	{d4-d7}, [r3]
	veor	q0, q0, q2
	veor	q1, q1, q3
	vst1.8	{d0-d3}, [r2]
	add	r0, r0, #1
	b	L_mc_ffb_mo
L_mc_ffb_moe:
L_mc_ffb_nm:
	add	sp, sp, #4
	vpop	{d8-d15}
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	wc_mceliece_fft_fwd_butterflies_neon,.-wc_mceliece_fft_fwd_butterflies_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_aff_butterflies_tr_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_aff_butterflies_tr_neon)
	.type	wc_mceliece_aff_butterflies_tr_neon, %function
wc_mceliece_aff_butterflies_tr_neon:
	push	{r4, r5, r6, r7, r8, r9, lr}
	sub	sp, sp, #4
	ldr	r7, =L_mc_aff_consts_neon
	ldr	r8, =L_mc_aff_reversal_neon
	mov	r4, r0
	mov	r5, r1
	mov	r6, r2
	b	L_mc_pool_2
	.ltorg
L_mc_pool_2:
	mov	r0, #0
	add	r0, r5, r0
	mov	r1, #0x1a00
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xa0
	orr	r2, r2, #0x1b00
#else
	mov	r2, #0x1ba0
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xa0
	orr	r0, r0, #0x100
#else
	mov	r0, #0x1a0
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xa0
	orr	r1, r1, #0x1b00
#else
	mov	r1, #0x1ba0
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x40
	orr	r2, r2, #0x1d00
#else
	mov	r2, #0x1d40
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x40
	orr	r0, r0, #0x300
#else
	mov	r0, #0x340
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x40
	orr	r1, r1, #0x1d00
#else
	mov	r1, #0x1d40
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xe0
	orr	r2, r2, #0x1e00
#else
	mov	r2, #0x1ee0
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xe0
	orr	r0, r0, #0x400
#else
	mov	r0, #0x4e0
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xe0
	orr	r1, r1, #0x1e00
#else
	mov	r1, #0x1ee0
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x80
	orr	r2, r2, #0x2000
#else
	mov	r2, #0x2080
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x80
	orr	r0, r0, #0x600
#else
	mov	r0, #0x680
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x80
	orr	r1, r1, #0x2000
#else
	mov	r1, #0x2080
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x20
	orr	r2, r2, #0x2200
#else
	mov	r2, #0x2220
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x20
	orr	r0, r0, #0x800
#else
	mov	r0, #0x820
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x20
	orr	r1, r1, #0x2200
#else
	mov	r1, #0x2220
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xc0
	orr	r2, r2, #0x2300
#else
	mov	r2, #0x23c0
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xc0
	orr	r0, r0, #0x900
#else
	mov	r0, #0x9c0
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xc0
	orr	r1, r1, #0x2300
#else
	mov	r1, #0x23c0
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x60
	orr	r2, r2, #0x2500
#else
	mov	r2, #0x2560
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x60
	orr	r0, r0, #0xb00
#else
	mov	r0, #0xb60
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x60
	orr	r1, r1, #0x2500
#else
	mov	r1, #0x2560
#endif
	add	r1, r5, r1
	mov	r2, #0x2700
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
	mov	r0, #0xd00
	add	r0, r5, r0
	mov	r1, #0x2700
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xa0
	orr	r2, r2, #0x2800
#else
	mov	r2, #0x28a0
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xa0
	orr	r0, r0, #0xe00
#else
	mov	r0, #0xea0
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xa0
	orr	r1, r1, #0x2800
#else
	mov	r1, #0x28a0
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x40
	orr	r2, r2, #0x2a00
#else
	mov	r2, #0x2a40
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x40
	orr	r0, r0, #0x1000
#else
	mov	r0, #0x1040
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x40
	orr	r1, r1, #0x2a00
#else
	mov	r1, #0x2a40
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xe0
	orr	r2, r2, #0x2b00
#else
	mov	r2, #0x2be0
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xe0
	orr	r0, r0, #0x1100
#else
	mov	r0, #0x11e0
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xe0
	orr	r1, r1, #0x2b00
#else
	mov	r1, #0x2be0
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x80
	orr	r2, r2, #0x2d00
#else
	mov	r2, #0x2d80
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x80
	orr	r0, r0, #0x1300
#else
	mov	r0, #0x1380
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x80
	orr	r1, r1, #0x2d00
#else
	mov	r1, #0x2d80
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x20
	orr	r2, r2, #0x2f00
#else
	mov	r2, #0x2f20
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x20
	orr	r0, r0, #0x1500
#else
	mov	r0, #0x1520
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x20
	orr	r1, r1, #0x2f00
#else
	mov	r1, #0x2f20
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xc0
	orr	r2, r2, #0x3000
#else
	mov	r2, #0x30c0
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xc0
	orr	r0, r0, #0x1600
#else
	mov	r0, #0x16c0
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xc0
	orr	r1, r1, #0x3000
#else
	mov	r1, #0x30c0
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x60
	orr	r2, r2, #0x3200
#else
	mov	r2, #0x3260
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x60
	orr	r0, r0, #0x1800
#else
	mov	r0, #0x1860
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x60
	orr	r1, r1, #0x3200
#else
	mov	r1, #0x3260
#endif
	add	r1, r5, r1
	mov	r2, #0x3400
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
	mov	r0, #0
	add	r0, r5, r0
	mov	r1, #0xd00
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xa0
	orr	r2, r2, #0xe00
#else
	mov	r2, #0xea0
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xa0
	orr	r0, r0, #0x100
#else
	mov	r0, #0x1a0
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xa0
	orr	r1, r1, #0xe00
#else
	mov	r1, #0xea0
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x40
	orr	r2, r2, #0x1000
#else
	mov	r2, #0x1040
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x40
	orr	r0, r0, #0x300
#else
	mov	r0, #0x340
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x40
	orr	r1, r1, #0x1000
#else
	mov	r1, #0x1040
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xe0
	orr	r2, r2, #0x1100
#else
	mov	r2, #0x11e0
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xe0
	orr	r0, r0, #0x400
#else
	mov	r0, #0x4e0
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xe0
	orr	r1, r1, #0x1100
#else
	mov	r1, #0x11e0
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x80
	orr	r2, r2, #0x1300
#else
	mov	r2, #0x1380
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x80
	orr	r0, r0, #0x600
#else
	mov	r0, #0x680
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x80
	orr	r1, r1, #0x1300
#else
	mov	r1, #0x1380
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x20
	orr	r2, r2, #0x1500
#else
	mov	r2, #0x1520
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x20
	orr	r0, r0, #0x800
#else
	mov	r0, #0x820
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x20
	orr	r1, r1, #0x1500
#else
	mov	r1, #0x1520
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xc0
	orr	r2, r2, #0x1600
#else
	mov	r2, #0x16c0
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xc0
	orr	r0, r0, #0x900
#else
	mov	r0, #0x9c0
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xc0
	orr	r1, r1, #0x1600
#else
	mov	r1, #0x16c0
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x60
	orr	r2, r2, #0x1800
#else
	mov	r2, #0x1860
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x60
	orr	r0, r0, #0xb00
#else
	mov	r0, #0xb60
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x60
	orr	r1, r1, #0x1800
#else
	mov	r1, #0x1860
#endif
	add	r1, r5, r1
	mov	r2, #0x1a00
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
	mov	r0, #0x1a00
	add	r0, r5, r0
	mov	r1, #0x2700
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xa0
	orr	r2, r2, #0xe00
#else
	mov	r2, #0xea0
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xa0
	orr	r0, r0, #0x1b00
#else
	mov	r0, #0x1ba0
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xa0
	orr	r1, r1, #0x2800
#else
	mov	r1, #0x28a0
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x40
	orr	r2, r2, #0x1000
#else
	mov	r2, #0x1040
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x40
	orr	r0, r0, #0x1d00
#else
	mov	r0, #0x1d40
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x40
	orr	r1, r1, #0x2a00
#else
	mov	r1, #0x2a40
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xe0
	orr	r2, r2, #0x1100
#else
	mov	r2, #0x11e0
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xe0
	orr	r0, r0, #0x1e00
#else
	mov	r0, #0x1ee0
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xe0
	orr	r1, r1, #0x2b00
#else
	mov	r1, #0x2be0
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x80
	orr	r2, r2, #0x1300
#else
	mov	r2, #0x1380
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x80
	orr	r0, r0, #0x2000
#else
	mov	r0, #0x2080
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x80
	orr	r1, r1, #0x2d00
#else
	mov	r1, #0x2d80
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x20
	orr	r2, r2, #0x1500
#else
	mov	r2, #0x1520
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x20
	orr	r0, r0, #0x2200
#else
	mov	r0, #0x2220
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x20
	orr	r1, r1, #0x2f00
#else
	mov	r1, #0x2f20
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xc0
	orr	r2, r2, #0x1600
#else
	mov	r2, #0x16c0
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xc0
	orr	r0, r0, #0x2300
#else
	mov	r0, #0x23c0
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xc0
	orr	r1, r1, #0x3000
#else
	mov	r1, #0x30c0
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x60
	orr	r2, r2, #0x1800
#else
	mov	r2, #0x1860
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x60
	orr	r0, r0, #0x2500
#else
	mov	r0, #0x2560
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x60
	orr	r1, r1, #0x3200
#else
	mov	r1, #0x3260
#endif
	add	r1, r5, r1
	mov	r2, #0x1a00
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
	mov	r0, #0
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x80
	orr	r1, r1, #0x600
#else
	mov	r1, #0x680
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x20
	orr	r2, r2, #0x800
#else
	mov	r2, #0x820
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xa0
	orr	r0, r0, #0x100
#else
	mov	r0, #0x1a0
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x20
	orr	r1, r1, #0x800
#else
	mov	r1, #0x820
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xc0
	orr	r2, r2, #0x900
#else
	mov	r2, #0x9c0
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x40
	orr	r0, r0, #0x300
#else
	mov	r0, #0x340
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xc0
	orr	r1, r1, #0x900
#else
	mov	r1, #0x9c0
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x60
	orr	r2, r2, #0xb00
#else
	mov	r2, #0xb60
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xe0
	orr	r0, r0, #0x400
#else
	mov	r0, #0x4e0
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x60
	orr	r1, r1, #0xb00
#else
	mov	r1, #0xb60
#endif
	add	r1, r5, r1
	mov	r2, #0xd00
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
	mov	r0, #0xd00
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x80
	orr	r1, r1, #0x1300
#else
	mov	r1, #0x1380
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x20
	orr	r2, r2, #0x800
#else
	mov	r2, #0x820
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xa0
	orr	r0, r0, #0xe00
#else
	mov	r0, #0xea0
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x20
	orr	r1, r1, #0x1500
#else
	mov	r1, #0x1520
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xc0
	orr	r2, r2, #0x900
#else
	mov	r2, #0x9c0
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x40
	orr	r0, r0, #0x1000
#else
	mov	r0, #0x1040
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xc0
	orr	r1, r1, #0x1600
#else
	mov	r1, #0x16c0
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x60
	orr	r2, r2, #0xb00
#else
	mov	r2, #0xb60
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xe0
	orr	r0, r0, #0x1100
#else
	mov	r0, #0x11e0
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x60
	orr	r1, r1, #0x1800
#else
	mov	r1, #0x1860
#endif
	add	r1, r5, r1
	mov	r2, #0xd00
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
	mov	r0, #0x1a00
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x80
	orr	r1, r1, #0x2000
#else
	mov	r1, #0x2080
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x20
	orr	r2, r2, #0x800
#else
	mov	r2, #0x820
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xa0
	orr	r0, r0, #0x1b00
#else
	mov	r0, #0x1ba0
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x20
	orr	r1, r1, #0x2200
#else
	mov	r1, #0x2220
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xc0
	orr	r2, r2, #0x900
#else
	mov	r2, #0x9c0
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x40
	orr	r0, r0, #0x1d00
#else
	mov	r0, #0x1d40
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xc0
	orr	r1, r1, #0x2300
#else
	mov	r1, #0x23c0
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x60
	orr	r2, r2, #0xb00
#else
	mov	r2, #0xb60
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xe0
	orr	r0, r0, #0x1e00
#else
	mov	r0, #0x1ee0
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x60
	orr	r1, r1, #0x2500
#else
	mov	r1, #0x2560
#endif
	add	r1, r5, r1
	mov	r2, #0xd00
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
	mov	r0, #0x2700
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x80
	orr	r1, r1, #0x2d00
#else
	mov	r1, #0x2d80
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x20
	orr	r2, r2, #0x800
#else
	mov	r2, #0x820
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xa0
	orr	r0, r0, #0x2800
#else
	mov	r0, #0x28a0
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x20
	orr	r1, r1, #0x2f00
#else
	mov	r1, #0x2f20
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xc0
	orr	r2, r2, #0x900
#else
	mov	r2, #0x9c0
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x40
	orr	r0, r0, #0x2a00
#else
	mov	r0, #0x2a40
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xc0
	orr	r1, r1, #0x3000
#else
	mov	r1, #0x30c0
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x60
	orr	r2, r2, #0xb00
#else
	mov	r2, #0xb60
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xe0
	orr	r0, r0, #0x2b00
#else
	mov	r0, #0x2be0
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x60
	orr	r1, r1, #0x3200
#else
	mov	r1, #0x3260
#endif
	add	r1, r5, r1
	mov	r2, #0xd00
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
	mov	r0, #0
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x40
	orr	r1, r1, #0x300
#else
	mov	r1, #0x340
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xe0
	orr	r2, r2, #0x400
#else
	mov	r2, #0x4e0
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xa0
	orr	r0, r0, #0x100
#else
	mov	r0, #0x1a0
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xe0
	orr	r1, r1, #0x400
#else
	mov	r1, #0x4e0
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x80
	orr	r2, r2, #0x600
#else
	mov	r2, #0x680
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x80
	orr	r0, r0, #0x600
#else
	mov	r0, #0x680
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xc0
	orr	r1, r1, #0x900
#else
	mov	r1, #0x9c0
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xe0
	orr	r2, r2, #0x400
#else
	mov	r2, #0x4e0
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x20
	orr	r0, r0, #0x800
#else
	mov	r0, #0x820
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x60
	orr	r1, r1, #0xb00
#else
	mov	r1, #0xb60
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x80
	orr	r2, r2, #0x600
#else
	mov	r2, #0x680
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
	mov	r0, #0xd00
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x40
	orr	r1, r1, #0x1000
#else
	mov	r1, #0x1040
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xe0
	orr	r2, r2, #0x400
#else
	mov	r2, #0x4e0
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xa0
	orr	r0, r0, #0xe00
#else
	mov	r0, #0xea0
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xe0
	orr	r1, r1, #0x1100
#else
	mov	r1, #0x11e0
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x80
	orr	r2, r2, #0x600
#else
	mov	r2, #0x680
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x80
	orr	r0, r0, #0x1300
#else
	mov	r0, #0x1380
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xc0
	orr	r1, r1, #0x1600
#else
	mov	r1, #0x16c0
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xe0
	orr	r2, r2, #0x400
#else
	mov	r2, #0x4e0
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x20
	orr	r0, r0, #0x1500
#else
	mov	r0, #0x1520
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x60
	orr	r1, r1, #0x1800
#else
	mov	r1, #0x1860
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x80
	orr	r2, r2, #0x600
#else
	mov	r2, #0x680
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
	mov	r0, #0x1a00
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x40
	orr	r1, r1, #0x1d00
#else
	mov	r1, #0x1d40
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xe0
	orr	r2, r2, #0x400
#else
	mov	r2, #0x4e0
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xa0
	orr	r0, r0, #0x1b00
#else
	mov	r0, #0x1ba0
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xe0
	orr	r1, r1, #0x1e00
#else
	mov	r1, #0x1ee0
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x80
	orr	r2, r2, #0x600
#else
	mov	r2, #0x680
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x80
	orr	r0, r0, #0x2000
#else
	mov	r0, #0x2080
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xc0
	orr	r1, r1, #0x2300
#else
	mov	r1, #0x23c0
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xe0
	orr	r2, r2, #0x400
#else
	mov	r2, #0x4e0
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x20
	orr	r0, r0, #0x2200
#else
	mov	r0, #0x2220
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x60
	orr	r1, r1, #0x2500
#else
	mov	r1, #0x2560
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x80
	orr	r2, r2, #0x600
#else
	mov	r2, #0x680
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
	mov	r0, #0x2700
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x40
	orr	r1, r1, #0x2a00
#else
	mov	r1, #0x2a40
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xe0
	orr	r2, r2, #0x400
#else
	mov	r2, #0x4e0
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xa0
	orr	r0, r0, #0x2800
#else
	mov	r0, #0x28a0
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xe0
	orr	r1, r1, #0x2b00
#else
	mov	r1, #0x2be0
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x80
	orr	r2, r2, #0x600
#else
	mov	r2, #0x680
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x80
	orr	r0, r0, #0x2d00
#else
	mov	r0, #0x2d80
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xc0
	orr	r1, r1, #0x3000
#else
	mov	r1, #0x30c0
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xe0
	orr	r2, r2, #0x400
#else
	mov	r2, #0x4e0
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x20
	orr	r0, r0, #0x2f00
#else
	mov	r0, #0x2f20
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x60
	orr	r1, r1, #0x3200
#else
	mov	r1, #0x3260
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x80
	orr	r2, r2, #0x600
#else
	mov	r2, #0x680
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
	mov	r0, #0
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xa0
	orr	r1, r1, #0x100
#else
	mov	r1, #0x1a0
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x40
	orr	r2, r2, #0x300
#else
	mov	r2, #0x340
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x40
	orr	r0, r0, #0x300
#else
	mov	r0, #0x340
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xe0
	orr	r1, r1, #0x400
#else
	mov	r1, #0x4e0
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x40
	orr	r2, r2, #0x300
#else
	mov	r2, #0x340
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x80
	orr	r0, r0, #0x600
#else
	mov	r0, #0x680
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x20
	orr	r1, r1, #0x800
#else
	mov	r1, #0x820
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x40
	orr	r2, r2, #0x300
#else
	mov	r2, #0x340
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xc0
	orr	r0, r0, #0x900
#else
	mov	r0, #0x9c0
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x60
	orr	r1, r1, #0xb00
#else
	mov	r1, #0xb60
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x40
	orr	r2, r2, #0x300
#else
	mov	r2, #0x340
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
	mov	r0, #0xd00
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xa0
	orr	r1, r1, #0xe00
#else
	mov	r1, #0xea0
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x40
	orr	r2, r2, #0x300
#else
	mov	r2, #0x340
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x40
	orr	r0, r0, #0x1000
#else
	mov	r0, #0x1040
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xe0
	orr	r1, r1, #0x1100
#else
	mov	r1, #0x11e0
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x40
	orr	r2, r2, #0x300
#else
	mov	r2, #0x340
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x80
	orr	r0, r0, #0x1300
#else
	mov	r0, #0x1380
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x20
	orr	r1, r1, #0x1500
#else
	mov	r1, #0x1520
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x40
	orr	r2, r2, #0x300
#else
	mov	r2, #0x340
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xc0
	orr	r0, r0, #0x1600
#else
	mov	r0, #0x16c0
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x60
	orr	r1, r1, #0x1800
#else
	mov	r1, #0x1860
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x40
	orr	r2, r2, #0x300
#else
	mov	r2, #0x340
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
	mov	r0, #0x1a00
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xa0
	orr	r1, r1, #0x1b00
#else
	mov	r1, #0x1ba0
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x40
	orr	r2, r2, #0x300
#else
	mov	r2, #0x340
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x40
	orr	r0, r0, #0x1d00
#else
	mov	r0, #0x1d40
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xe0
	orr	r1, r1, #0x1e00
#else
	mov	r1, #0x1ee0
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x40
	orr	r2, r2, #0x300
#else
	mov	r2, #0x340
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x80
	orr	r0, r0, #0x2000
#else
	mov	r0, #0x2080
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x20
	orr	r1, r1, #0x2200
#else
	mov	r1, #0x2220
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x40
	orr	r2, r2, #0x300
#else
	mov	r2, #0x340
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xc0
	orr	r0, r0, #0x2300
#else
	mov	r0, #0x23c0
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x60
	orr	r1, r1, #0x2500
#else
	mov	r1, #0x2560
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x40
	orr	r2, r2, #0x300
#else
	mov	r2, #0x340
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
	mov	r0, #0x2700
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xa0
	orr	r1, r1, #0x2800
#else
	mov	r1, #0x28a0
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x40
	orr	r2, r2, #0x300
#else
	mov	r2, #0x340
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x40
	orr	r0, r0, #0x2a00
#else
	mov	r0, #0x2a40
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xe0
	orr	r1, r1, #0x2b00
#else
	mov	r1, #0x2be0
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x40
	orr	r2, r2, #0x300
#else
	mov	r2, #0x340
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0x80
	orr	r0, r0, #0x2d00
#else
	mov	r0, #0x2d80
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x20
	orr	r1, r1, #0x2f00
#else
	mov	r1, #0x2f20
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x40
	orr	r2, r2, #0x300
#else
	mov	r2, #0x340
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r0, #0xc0
	orr	r0, r0, #0x3000
#else
	mov	r0, #0x30c0
#endif
	add	r0, r5, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x60
	orr	r1, r1, #0x3200
#else
	mov	r1, #0x3260
#endif
	add	r1, r5, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x40
	orr	r2, r2, #0x300
#else
	mov	r2, #0x340
#endif
	add	r2, r7, r2
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
	mov	r9, #0
L_mc_btr_pk:
	cmp	r9, #32
	bge	L_mc_btr_pke
	add	r0, r6, #0x610
	add	r1, r6, #0x7b0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r12, #0xa0
	orr	r12, r12, #0x100
#else
	mov	r12, #0x1a0
#endif
	mul	r2, r9, r12
	add	r2, r5, r2
	add	r3, r2, #0x1a0
	bl	wc_mceliece_aff_pack_lh_neon
	add	r0, r6, #0x610
	add	r1, r6, #0x7b0
	add	r2, r7, #0x1a0
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r12, #0xa0
	orr	r12, r12, #0x100
#else
	mov	r12, #0x1a0
#endif
	mul	r0, r9, r12
	add	r0, r5, r0
	add	r1, r0, #0x1a0
	add	r2, r6, #0x610
	add	r3, r6, #0x7b0
	bl	wc_mceliece_aff_pack_lh_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r12, #0xa0
	orr	r12, r12, #0x100
#else
	mov	r12, #0x1a0
#endif
	mul	r2, r9, r12
	add	r0, r6, #0x610
	add	r1, r6, #0x7b0
	add	r2, r5, r2
	add	r3, r2, #0x1a0
	bl	wc_mceliece_aff_pack_lh2_neon
	add	r0, r6, #0x610
	add	r1, r6, #0x7b0
	mov	r2, r7
	add	r3, r6, #0xe10
	add	r12, r6, #0xfb0
	str	r12, [sp]
	bl	wc_mceliece_aff_ama_neon
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r12, #0xa0
	orr	r12, r12, #0x100
#else
	mov	r12, #0x1a0
#endif
	mul	r0, r9, r12
	add	r0, r5, r0
	add	r1, r0, #0x1a0
	add	r2, r6, #0x610
	add	r3, r6, #0x7b0
	bl	wc_mceliece_aff_pack_lh2_neon
	add	r9, r9, #2
	b	L_mc_btr_pk
L_mc_btr_pke:
	mov	r9, #0
L_mc_btr_i:
	cmp	r9, #13
	bge	L_mc_btr_ie
	add	r0, r6, #0x610
	mov	r1, r5
	mov	r2, r9
	bl	wc_mceliece_aff_btr_in_neon
	add	r0, r6, #0x610
	bl	wc_mceliece_aff_transpose_neon
	add	r0, r6, #0xd0
	add	r1, r6, #0x610
	mov	r2, r4
	mov	r3, r9
	lsr	r12, r9, #1
	str	r12, [sp]
	bl	wc_mceliece_aff_btr_net_neon
	add	r9, r9, #2
	b	L_mc_btr_i
L_mc_btr_ie:
	vmov.i8	q2, #0xff
	veor	q3, q3, q3
	add	r0, r6, #0
	vst1.8	{d6}, [r0]
	add	r0, r0, #8
	vst1.8	{d6}, [r0]
	add	r0, r6, #16
	vst1.8	{d4}, [r0]
	add	r0, r0, #8
	vst1.8	{d4}, [r0]
	add	r0, r6, #32
	vst1.8	{d4}, [r0]
	add	r0, r0, #8
	vst1.8	{d4}, [r0]
	add	r0, r6, #48
	vst1.8	{d4}, [r0]
	add	r0, r0, #8
	vst1.8	{d4}, [r0]
	add	r0, r6, #0x40
	vst1.8	{d4}, [r0]
	add	r0, r0, #8
	vst1.8	{d4}, [r0]
	add	r0, r6, #0x50
	vst1.8	{d4}, [r0]
	add	r0, r0, #8
	vst1.8	{d4}, [r0]
	add	r0, r6, #0x60
	vst1.8	{d4}, [r0]
	add	r0, r0, #8
	vst1.8	{d4}, [r0]
	add	r0, r6, #0x70
	vst1.8	{d6}, [r0]
	add	r0, r0, #8
	vst1.8	{d6}, [r0]
	add	r0, r6, #0x80
	vst1.8	{d6}, [r0]
	add	r0, r0, #8
	vst1.8	{d6}, [r0]
	add	r0, r6, #0x90
	vst1.8	{d6}, [r0]
	add	r0, r0, #8
	vst1.8	{d6}, [r0]
	add	r0, r6, #0xa0
	vst1.8	{d4}, [r0]
	add	r0, r0, #8
	vst1.8	{d4}, [r0]
	add	r0, r6, #0xb0
	vst1.8	{d6}, [r0]
	add	r0, r0, #8
	vst1.8	{d6}, [r0]
	add	r0, r6, #0xc0
	vst1.8	{d4}, [r0]
	add	r0, r0, #8
	vst1.8	{d4}, [r0]
	mov	r0, r6
	add	r1, r6, #0xd0
	mov	r2, r6
	add	r3, r6, #0x610
	bl	wc_mceliece_aff_v128_mul_neon
	add	r0, r6, #0
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0
	add	r12, r1, #16
	vst1.8	{d0}, [r12]
	add	r12, r1, #24
	vst1.8	{d1}, [r12]
	add	r0, r6, #16
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #32
	add	r12, r1, #16
	vst1.8	{d0}, [r12]
	add	r12, r1, #24
	vst1.8	{d1}, [r12]
	add	r0, r6, #32
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0x40
	add	r12, r1, #16
	vst1.8	{d0}, [r12]
	add	r12, r1, #24
	vst1.8	{d1}, [r12]
	add	r0, r6, #48
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0x60
	add	r12, r1, #16
	vst1.8	{d0}, [r12]
	add	r12, r1, #24
	vst1.8	{d1}, [r12]
	add	r0, r6, #0x40
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0x80
	add	r12, r1, #16
	vst1.8	{d0}, [r12]
	add	r12, r1, #24
	vst1.8	{d1}, [r12]
	add	r0, r6, #0x50
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0xa0
	add	r12, r1, #16
	vst1.8	{d0}, [r12]
	add	r12, r1, #24
	vst1.8	{d1}, [r12]
	add	r0, r6, #0x60
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0xc0
	add	r12, r1, #16
	vst1.8	{d0}, [r12]
	add	r12, r1, #24
	vst1.8	{d1}, [r12]
	add	r0, r6, #0x70
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0xe0
	add	r12, r1, #16
	vst1.8	{d0}, [r12]
	add	r12, r1, #24
	vst1.8	{d1}, [r12]
	add	r0, r6, #0x80
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0x100
	add	r12, r1, #16
	vst1.8	{d0}, [r12]
	add	r12, r1, #24
	vst1.8	{d1}, [r12]
	add	r0, r6, #0x90
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0x120
	add	r12, r1, #16
	vst1.8	{d0}, [r12]
	add	r12, r1, #24
	vst1.8	{d1}, [r12]
	add	r0, r6, #0xa0
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0x140
	add	r12, r1, #16
	vst1.8	{d0}, [r12]
	add	r12, r1, #24
	vst1.8	{d1}, [r12]
	add	r0, r6, #0xb0
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0x160
	add	r12, r1, #16
	vst1.8	{d0}, [r12]
	add	r12, r1, #24
	vst1.8	{d1}, [r12]
	add	r0, r6, #0xc0
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0x180
	add	r12, r1, #16
	vst1.8	{d0}, [r12]
	add	r12, r1, #24
	vst1.8	{d1}, [r12]
	vmov.i8	q2, #0xff
	veor	q3, q3, q3
	add	r0, r6, #0
	vst1.8	{d6}, [r0]
	add	r0, r0, #8
	vst1.8	{d6}, [r0]
	add	r0, r6, #16
	vst1.8	{d4}, [r0]
	add	r0, r0, #8
	vst1.8	{d4}, [r0]
	add	r0, r6, #32
	vst1.8	{d6}, [r0]
	add	r0, r0, #8
	vst1.8	{d6}, [r0]
	add	r0, r6, #48
	vst1.8	{d4}, [r0]
	add	r0, r0, #8
	vst1.8	{d4}, [r0]
	add	r0, r6, #0x40
	vst1.8	{d4}, [r0]
	add	r0, r0, #8
	vst1.8	{d4}, [r0]
	add	r0, r6, #0x50
	vst1.8	{d4}, [r0]
	add	r0, r0, #8
	vst1.8	{d4}, [r0]
	add	r0, r6, #0x60
	vst1.8	{d6}, [r0]
	add	r0, r0, #8
	vst1.8	{d6}, [r0]
	add	r0, r6, #0x70
	vst1.8	{d4}, [r0]
	add	r0, r0, #8
	vst1.8	{d4}, [r0]
	add	r0, r6, #0x80
	vst1.8	{d6}, [r0]
	add	r0, r0, #8
	vst1.8	{d6}, [r0]
	add	r0, r6, #0x90
	vst1.8	{d6}, [r0]
	add	r0, r0, #8
	vst1.8	{d6}, [r0]
	add	r0, r6, #0xa0
	vst1.8	{d4}, [r0]
	add	r0, r0, #8
	vst1.8	{d4}, [r0]
	add	r0, r6, #0xb0
	vst1.8	{d6}, [r0]
	add	r0, r0, #8
	vst1.8	{d6}, [r0]
	add	r0, r6, #0xc0
	vst1.8	{d4}, [r0]
	add	r0, r0, #8
	vst1.8	{d4}, [r0]
	mov	r0, r6
	add	r1, r6, #0x1b0
	mov	r2, r6
	add	r3, r6, #0x610
	bl	wc_mceliece_aff_v128_mul_neon
	add	r0, r6, #0
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #16
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #32
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #32
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0x40
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #48
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0x60
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #0x40
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0x80
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #0x50
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0xa0
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #0x60
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0xc0
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #0x70
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0xe0
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #0x80
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0x100
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #0x90
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0x120
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #0xa0
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0x140
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #0xb0
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0x160
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #0xc0
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0x180
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	vmov.i8	q2, #0xff
	veor	q3, q3, q3
	add	r0, r6, #0
	vst1.8	{d4}, [r0]
	add	r0, r0, #8
	vst1.8	{d4}, [r0]
	add	r0, r6, #16
	vst1.8	{d4}, [r0]
	add	r0, r0, #8
	vst1.8	{d4}, [r0]
	add	r0, r6, #32
	vst1.8	{d4}, [r0]
	add	r0, r0, #8
	vst1.8	{d4}, [r0]
	add	r0, r6, #48
	vst1.8	{d6}, [r0]
	add	r0, r0, #8
	vst1.8	{d6}, [r0]
	add	r0, r6, #0x40
	vst1.8	{d4}, [r0]
	add	r0, r0, #8
	vst1.8	{d4}, [r0]
	add	r0, r6, #0x50
	vst1.8	{d6}, [r0]
	add	r0, r0, #8
	vst1.8	{d6}, [r0]
	add	r0, r6, #0x60
	vst1.8	{d6}, [r0]
	add	r0, r0, #8
	vst1.8	{d6}, [r0]
	add	r0, r6, #0x70
	vst1.8	{d4}, [r0]
	add	r0, r0, #8
	vst1.8	{d4}, [r0]
	add	r0, r6, #0x80
	vst1.8	{d4}, [r0]
	add	r0, r0, #8
	vst1.8	{d4}, [r0]
	add	r0, r6, #0x90
	vst1.8	{d4}, [r0]
	add	r0, r0, #8
	vst1.8	{d4}, [r0]
	add	r0, r6, #0xa0
	vst1.8	{d4}, [r0]
	add	r0, r0, #8
	vst1.8	{d4}, [r0]
	add	r0, r6, #0xb0
	vst1.8	{d6}, [r0]
	add	r0, r0, #8
	vst1.8	{d6}, [r0]
	add	r0, r6, #0xc0
	vst1.8	{d4}, [r0]
	add	r0, r0, #8
	vst1.8	{d4}, [r0]
	mov	r0, r6
	add	r1, r6, #0x290
	mov	r2, r6
	add	r3, r6, #0x610
	bl	wc_mceliece_aff_v128_mul_neon
	add	r0, r6, #0
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #16
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #32
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #32
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0x40
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #48
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0x60
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #0x40
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0x80
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #0x50
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0xa0
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #0x60
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0xc0
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #0x70
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0xe0
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #0x80
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0x100
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #0x90
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0x120
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #0xa0
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0x140
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #0xb0
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0x160
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #0xc0
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0x180
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	vmov.i8	q2, #0xff
	veor	q3, q3, q3
	add	r0, r6, #0
	vst1.8	{d4}, [r0]
	add	r0, r0, #8
	vst1.8	{d4}, [r0]
	add	r0, r6, #16
	vst1.8	{d6}, [r0]
	add	r0, r0, #8
	vst1.8	{d6}, [r0]
	add	r0, r6, #32
	vst1.8	{d4}, [r0]
	add	r0, r0, #8
	vst1.8	{d4}, [r0]
	add	r0, r6, #48
	vst1.8	{d4}, [r0]
	add	r0, r0, #8
	vst1.8	{d4}, [r0]
	add	r0, r6, #0x40
	vst1.8	{d4}, [r0]
	add	r0, r0, #8
	vst1.8	{d4}, [r0]
	add	r0, r6, #0x50
	vst1.8	{d6}, [r0]
	add	r0, r0, #8
	vst1.8	{d6}, [r0]
	add	r0, r6, #0x60
	vst1.8	{d6}, [r0]
	add	r0, r0, #8
	vst1.8	{d6}, [r0]
	add	r0, r6, #0x70
	vst1.8	{d6}, [r0]
	add	r0, r0, #8
	vst1.8	{d6}, [r0]
	add	r0, r6, #0x80
	vst1.8	{d6}, [r0]
	add	r0, r0, #8
	vst1.8	{d6}, [r0]
	add	r0, r6, #0x90
	vst1.8	{d4}, [r0]
	add	r0, r0, #8
	vst1.8	{d4}, [r0]
	add	r0, r6, #0xa0
	vst1.8	{d6}, [r0]
	add	r0, r0, #8
	vst1.8	{d6}, [r0]
	add	r0, r6, #0xb0
	vst1.8	{d4}, [r0]
	add	r0, r0, #8
	vst1.8	{d4}, [r0]
	add	r0, r6, #0xc0
	vst1.8	{d4}, [r0]
	add	r0, r0, #8
	vst1.8	{d4}, [r0]
	mov	r0, r6
	add	r1, r6, #0x370
	mov	r2, r6
	add	r3, r6, #0x610
	bl	wc_mceliece_aff_v128_mul_neon
	add	r0, r6, #0
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #16
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #32
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #32
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0x40
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #48
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0x60
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #0x40
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0x80
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #0x50
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0xa0
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #0x60
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0xc0
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #0x70
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0xe0
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #0x80
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0x100
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #0x90
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0x120
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #0xa0
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0x140
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #0xb0
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0x160
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #0xc0
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0x180
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	vmov.i8	q2, #0xff
	veor	q3, q3, q3
	add	r0, r6, #0
	vst1.8	{d4}, [r0]
	add	r0, r0, #8
	vst1.8	{d4}, [r0]
	add	r0, r6, #16
	vst1.8	{d6}, [r0]
	add	r0, r0, #8
	vst1.8	{d6}, [r0]
	add	r0, r6, #32
	vst1.8	{d6}, [r0]
	add	r0, r0, #8
	vst1.8	{d6}, [r0]
	add	r0, r6, #48
	vst1.8	{d4}, [r0]
	add	r0, r0, #8
	vst1.8	{d4}, [r0]
	add	r0, r6, #0x40
	vst1.8	{d6}, [r0]
	add	r0, r0, #8
	vst1.8	{d6}, [r0]
	add	r0, r6, #0x50
	vst1.8	{d4}, [r0]
	add	r0, r0, #8
	vst1.8	{d4}, [r0]
	add	r0, r6, #0x60
	vst1.8	{d6}, [r0]
	add	r0, r0, #8
	vst1.8	{d6}, [r0]
	add	r0, r6, #0x70
	vst1.8	{d6}, [r0]
	add	r0, r0, #8
	vst1.8	{d6}, [r0]
	add	r0, r6, #0x80
	vst1.8	{d4}, [r0]
	add	r0, r0, #8
	vst1.8	{d4}, [r0]
	add	r0, r6, #0x90
	vst1.8	{d4}, [r0]
	add	r0, r0, #8
	vst1.8	{d4}, [r0]
	add	r0, r6, #0xa0
	vst1.8	{d6}, [r0]
	add	r0, r0, #8
	vst1.8	{d6}, [r0]
	add	r0, r6, #0xb0
	vst1.8	{d6}, [r0]
	add	r0, r0, #8
	vst1.8	{d6}, [r0]
	add	r0, r6, #0xc0
	vst1.8	{d4}, [r0]
	add	r0, r0, #8
	vst1.8	{d4}, [r0]
	mov	r0, r6
	add	r1, r6, #0x450
	mov	r2, r6
	add	r3, r6, #0x610
	bl	wc_mceliece_aff_v128_mul_neon
	add	r0, r6, #0
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #16
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #32
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #32
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0x40
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #48
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0x60
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #0x40
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0x80
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #0x50
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0xa0
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #0x60
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0xc0
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #0x70
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0xe0
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #0x80
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0x100
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #0x90
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0x120
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #0xa0
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0x140
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #0xb0
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0x160
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #0xc0
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0x180
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	vmov.i8	q2, #0xff
	veor	q3, q3, q3
	add	r0, r6, #0
	vst1.8	{d4}, [r0]
	add	r0, r0, #8
	vst1.8	{d4}, [r0]
	add	r0, r6, #16
	vst1.8	{d4}, [r0]
	add	r0, r0, #8
	vst1.8	{d4}, [r0]
	add	r0, r6, #32
	vst1.8	{d6}, [r0]
	add	r0, r0, #8
	vst1.8	{d6}, [r0]
	add	r0, r6, #48
	vst1.8	{d6}, [r0]
	add	r0, r0, #8
	vst1.8	{d6}, [r0]
	add	r0, r6, #0x40
	vst1.8	{d6}, [r0]
	add	r0, r0, #8
	vst1.8	{d6}, [r0]
	add	r0, r6, #0x50
	vst1.8	{d4}, [r0]
	add	r0, r0, #8
	vst1.8	{d4}, [r0]
	add	r0, r6, #0x60
	vst1.8	{d4}, [r0]
	add	r0, r0, #8
	vst1.8	{d4}, [r0]
	add	r0, r6, #0x70
	vst1.8	{d6}, [r0]
	add	r0, r0, #8
	vst1.8	{d6}, [r0]
	add	r0, r6, #0x80
	vst1.8	{d6}, [r0]
	add	r0, r0, #8
	vst1.8	{d6}, [r0]
	add	r0, r6, #0x90
	vst1.8	{d4}, [r0]
	add	r0, r0, #8
	vst1.8	{d4}, [r0]
	add	r0, r6, #0xa0
	vst1.8	{d6}, [r0]
	add	r0, r0, #8
	vst1.8	{d6}, [r0]
	add	r0, r6, #0xb0
	vst1.8	{d4}, [r0]
	add	r0, r0, #8
	vst1.8	{d4}, [r0]
	add	r0, r6, #0xc0
	vst1.8	{d4}, [r0]
	add	r0, r0, #8
	vst1.8	{d4}, [r0]
	mov	r0, r6
	add	r1, r6, #0x530
	mov	r2, r6
	add	r3, r6, #0x610
	bl	wc_mceliece_aff_v128_mul_neon
	add	r0, r6, #0
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #16
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #32
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #32
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0x40
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #48
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0x60
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #0x40
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0x80
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #0x50
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0xa0
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #0x60
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0xc0
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #0x70
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0xe0
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #0x80
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0x100
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #0x90
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0x120
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #0xa0
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0x140
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #0xb0
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0x160
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	r0, r6, #0xc0
	vld1.8	{d0}, [r0]
	add	r0, r0, #8
	vld1.8	{d1}, [r0]
	add	r1, r4, #0x180
	add	r12, r1, #16
	vld1.8	{d2}, [r12]
	veor	d2, d2, d0
	vst1.8	{d2}, [r12]
	add	r12, r1, #24
	vld1.8	{d3}, [r12]
	veor	d3, d3, d1
	vst1.8	{d3}, [r12]
	add	sp, sp, #4
	pop	{r4, r5, r6, r7, r8, r9, pc}
	.size	wc_mceliece_aff_butterflies_tr_neon,.-wc_mceliece_aff_butterflies_tr_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_goppa_eval_inv_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_goppa_eval_inv_neon)
	.type	wc_mceliece_goppa_eval_inv_neon, %function
wc_mceliece_goppa_eval_inv_neon:
	push	{r4, r5, r6, r7, r8, r10, lr}
	sub	sp, sp, #12
	mov	r4, r0
	mov	r5, r1
	mov	r0, r2
	mov	r1, r3
	ldr	r6, [sp, #40]
	ldr	r7, [sp, #44]
	ldr	r8, [sp, #48]
	mov	r12, #0x1300
	add	r10, r8, r12
	mov	r2, #0
L_mc_gei_l:
	cmp	r2, r1
	bge	L_mc_gei_le
	lsl	r3, r2, #1
	add	r12, r0, r3
	ldrh	r12, [r12]
	lsl	r12, r12, #19
	lsr	r12, r12, #19
	add	r3, r10, r3
	strh	r12, [r3]
	add	r2, r2, #1
	b	L_mc_gei_l
L_mc_gei_le:
	cmp	r1, #0x80
	bge	L_mc_gei_ze
	lsl	r3, r1, #1
	add	r3, r10, r3
	mov	r12, #1
	strh	r12, [r3]
	add	r2, r1, #1
	mov	r12, #0
L_mc_gei_z:
	cmp	r2, #0x80
	bge	L_mc_gei_ze
	lsl	r3, r2, #1
	add	r3, r10, r3
	strh	r12, [r3]
	add	r2, r2, #1
	b	L_mc_gei_z
L_mc_gei_ze:
	mov	r0, r7
	mov	r1, r10
	bl	wc_mceliece_bs_poly_neon
	mov	r0, r7
	bl	wc_mceliece_radix_conv_neon
	mov	r0, r5
	mov	r1, r7
	mov	r2, r6
	mov	r3, r8
	bl	wc_mceliece_fft_fwd_butterflies_neon
	mov	r0, r4
	mov	r1, r5
	mov	r2, r8
	add	r3, r8, #0x340
	mov	r12, #1
	str	r12, [sp]
	bl	wc_mceliece_mont_batch_inv_neon
	add	sp, sp, #12
	pop	{r4, r5, r6, r7, r8, r10, pc}
	.size	wc_mceliece_goppa_eval_inv_neon,.-wc_mceliece_goppa_eval_inv_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_bs_packbuf_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_bs_packbuf_neon)
	.type	wc_mceliece_bs_packbuf_neon, %function
wc_mceliece_bs_packbuf_neon:
	push	{r4, r5, r6, r7, lr}
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r6, #0xff
	orr	r6, r6, #0x1f00
#else
	mov	r6, #0x1fff
#endif
	mov	r7, #0x2000
	mov	r3, #0
L_mc_pkb:
	ldr	r12, [r1]
	add	r1, r1, #4
	ldr	lr, [r2]
	add	r2, r2, #8
	and	lr, lr, r6
	lsl	lr, lr, #13
	orr	r4, lr, r3
	lsl	r5, r12, #31
	orr	r4, r4, r5
	lsr	r5, r12, #1
	str	r4, [r0]
	str	r5, [r0, #4]
	add	r0, r0, #8
	add	r3, r3, #1
	cmp	r3, r7
	blt	L_mc_pkb
	pop	{r4, r5, r6, r7, pc}
	.size	wc_mceliece_bs_packbuf_neon,.-wc_mceliece_bs_packbuf_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_bs_dup_pi_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_bs_dup_pi_neon)
	.type	wc_mceliece_bs_dup_pi_neon, %function
wc_mceliece_bs_dup_pi_neon:
	push	{r4, r5, r6, r7, r8, lr}
	mov	r8, #0
	mov	r6, #0x2000
	mov	r2, r1
	ldr	r12, [r2]
	ldr	lr, [r2, #4]
	lsr	r5, r12, #31
	lsl	lr, lr, #1
	orr	r5, r5, lr
	add	r2, r2, #8
	mov	r3, #1
L_mc_dup_c:
	ldr	r12, [r2]
	ldr	lr, [r2, #4]
	lsr	r4, r12, #31
	lsl	lr, lr, #1
	orr	r4, r4, lr
	cmp	r4, r5
	beq	L_mc_dup_bad
	mov	r5, r4
	add	r2, r2, #8
	add	r3, r3, #1
	cmp	r3, r6
	blt	L_mc_dup_c
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r7, #0xff
	orr	r7, r7, #0x1f00
#else
	mov	r7, #0x1fff
#endif
	mov	r2, r1
	mov	r3, #0
L_mc_dup_pi:
	ldr	r12, [r2]
	and	r12, r12, r7
	strh	r12, [r0]
	add	r0, r0, #2
	add	r2, r2, #8
	add	r3, r3, #1
	cmp	r3, r6
	blt	L_mc_dup_pi
	b	L_mc_dup_end
L_mc_dup_bad:
	mov	r8, #0
	sub	r8, r8, #1
L_mc_dup_end:
	mov	r0, r8
	pop	{r4, r5, r6, r7, r8, pc}
	.size	wc_mceliece_bs_dup_pi_neon,.-wc_mceliece_bs_dup_pi_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_bs_debitslice_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_bs_debitslice_neon)
	.type	wc_mceliece_bs_debitslice_neon, %function
wc_mceliece_bs_debitslice_neon:
	push	{r4, r5, r6, r7, r8, r9, r10, lr}
	mov	r10, #0
	mov	r2, r1
	mov	r3, #0
L_mc_dbs_i:
	mov	r12, #0
L_mc_dbs_l:
	mov	lr, #0
L_mc_dbs_r:
	lsl	r5, r12, #3
	add	r5, r5, r2
	lsr	r9, lr, #5
	lsl	r9, r9, #2
	add	r5, r5, r9
	and	r9, lr, #31
	mov	r6, #0
	mov	r4, #0
L_mc_dbs_j:
	ldr	r7, [r5]
	lsr	r7, r7, r9
	and	r7, r7, #1
	lsl	r7, r7, r4
	orr	r6, r6, r7
	add	r5, r5, #32
	add	r4, r4, #1
	cmp	r4, #13
	blt	L_mc_dbs_j
	str	r6, [r0]
	str	r10, [r0, #4]
	add	r0, r0, #8
	add	lr, lr, #1
	cmp	lr, #0x40
	blt	L_mc_dbs_r
	add	r12, r12, #1
	cmp	r12, #4
	blt	L_mc_dbs_l
	add	r2, r2, #0x1a0
	add	r3, r3, #1
	cmp	r3, #32
	blt	L_mc_dbs_i
	pop	{r4, r5, r6, r7, r8, r9, r10, pc}
	.size	wc_mceliece_bs_debitslice_neon,.-wc_mceliece_bs_debitslice_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_bs_tobitslice2x_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_bs_tobitslice2x_neon)
	.type	wc_mceliece_bs_tobitslice2x_neon, %function
wc_mceliece_bs_tobitslice2x_neon:
	push	{r4, r5, r6, r7, r8, r9, lr}
	mov	r3, #0
L_mc_tbs_i:
	mov	r12, #0
L_mc_tbs_j:
	mov	lr, #0
L_mc_tbs_k:
	rsb	r4, r12, #12
	lsl	r5, r3, #11
	add	r5, r5, r2
	lsl	r8, lr, #9
	add	r5, r5, r8
	mov	r9, #0
	mov	r6, #0
L_mc_tbs_lo_0:
	ldr	r7, [r5]
	add	r5, r5, #8
	lsr	r8, r7, r4
	and	r8, r8, #1
	lsl	r8, r8, r6
	orr	r9, r9, r8
	add	r6, r6, #1
	cmp	r6, #32
	blt	L_mc_tbs_lo_0
	str	r9, [r0]
	mov	r9, #0
	mov	r6, #0
L_mc_tbs_hi_0:
	ldr	r7, [r5]
	add	r5, r5, #8
	lsr	r8, r7, r4
	and	r8, r8, #1
	lsl	r8, r8, r6
	orr	r9, r9, r8
	add	r6, r6, #1
	cmp	r6, #32
	blt	L_mc_tbs_hi_0
	str	r9, [r0, #4]
	add	r4, r12, #13
	lsl	r5, r3, #11
	add	r5, r5, r2
	lsl	r8, lr, #9
	add	r5, r5, r8
	mov	r9, #0
	mov	r6, #0
L_mc_tbs_lo_1:
	ldr	r7, [r5]
	add	r5, r5, #8
	lsr	r8, r7, r4
	and	r8, r8, #1
	lsl	r8, r8, r6
	orr	r9, r9, r8
	add	r6, r6, #1
	cmp	r6, #32
	blt	L_mc_tbs_lo_1
	str	r9, [r1]
	mov	r9, #0
	mov	r6, #0
L_mc_tbs_hi_1:
	ldr	r7, [r5]
	add	r5, r5, #8
	lsr	r8, r7, r4
	and	r8, r8, #1
	lsl	r8, r8, r6
	orr	r9, r9, r8
	add	r6, r6, #1
	cmp	r6, #32
	blt	L_mc_tbs_hi_1
	str	r9, [r1, #4]
	add	r0, r0, #8
	add	r1, r1, #8
	add	lr, lr, #1
	cmp	lr, #4
	blt	L_mc_tbs_k
	add	r12, r12, #1
	cmp	r12, #13
	blt	L_mc_tbs_j
	add	r3, r3, #1
	cmp	r3, #32
	blt	L_mc_tbs_i
	pop	{r4, r5, r6, r7, r8, r9, pc}
	.size	wc_mceliece_bs_tobitslice2x_neon,.-wc_mceliece_bs_tobitslice2x_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_bs_gload_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_bs_gload_neon)
	.type	wc_mceliece_bs_gload_neon, %function
wc_mceliece_bs_gload_neon:
	push	{r4, r5, r6, r7, lr}
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r7, #0xff
	orr	r7, r7, #0x1f00
#else
	mov	r7, #0x1fff
#endif
	lsl	lr, r3, #1
	add	lr, r0, lr
	mov	r4, #1
	strh	r4, [lr]
	mov	r12, #0
	mov	r5, r0
L_mc_gld_ld:
	cmp	r12, r3
	bge	L_mc_gld_lde
	ldrh	r4, [r2]
	add	r2, r2, #2
	and	r4, r4, r7
	strh	r4, [r5]
	add	r5, r5, #2
	add	r12, r12, #1
	b	L_mc_gld_ld
L_mc_gld_lde:
	mov	r12, #0
	mov	r6, r1
L_mc_gld_f:
	cmp	r12, #0x80
	bge	L_mc_gld_fe
	cmp	r12, r3
	bgt	L_mc_gld_fz
	lsl	lr, r12, #1
	add	lr, r0, lr
	ldrh	r4, [lr]
	b	L_mc_gld_fs
L_mc_gld_fz:
	mov	r4, #0
L_mc_gld_fs:
	strh	r4, [r6]
	add	r6, r6, #2
	add	r12, r12, #1
	b	L_mc_gld_f
L_mc_gld_fe:
	pop	{r4, r5, r6, r7, pc}
	.size	wc_mceliece_bs_gload_neon,.-wc_mceliece_bs_gload_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_cb_layer_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_cb_layer_neon)
	.type	wc_mceliece_cb_layer_neon, %function
wc_mceliece_cb_layer_neon:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	mov	r12, #1
	lsl	r12, r12, r2
	lsl	lr, r12, #1
	mov	r6, #0
	mov	r4, #0
L_mc_cbl_i:
	cmp	r4, r3
	bge	L_mc_cbl_end
	mov	r5, #0
L_mc_cbl_j:
	cmp	r5, r12
	bge	L_mc_cbl_ni
	lsr	r11, r6, #3
	add	r11, r1, r11
	ldrb	r11, [r11]
	and	r7, r6, #7
	lsr	r11, r11, r7
	and	r11, r11, #1
	rsb	r11, r11, #0
	add	r7, r4, r5
	lsl	r7, r7, #1
	add	r7, r0, r7
	add	r8, r7, lr
	ldrh	r9, [r7]
	ldrh	r10, [r8]
	eor	r9, r9, r10
	and	r9, r9, r11
	ldrh	r10, [r7]
	eor	r10, r10, r9
	strh	r10, [r7]
	ldrh	r10, [r8]
	eor	r10, r10, r9
	strh	r10, [r8]
	add	r6, r6, #1
	add	r5, r5, #1
	b	L_mc_cbl_j
L_mc_cbl_ni:
	add	r4, r4, lr
	b	L_mc_cbl_i
L_mc_cbl_end:
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	wc_mceliece_cb_layer_neon,.-wc_mceliece_cb_layer_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_bs_mov_columns_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_bs_mov_columns_neon)
	.type	wc_mceliece_bs_mov_columns_neon, %function
wc_mceliece_bs_mov_columns_neon:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	vpush	{d8-d15}
	sub	sp, sp, #0x190
	mov	r12, #0
	mov	r8, #1
	vmov	d16, r8, r12
	mvn	r8, r12
	vmov	d24, r8, r8
	veor	q7, q7, q7
	sub	r8, r2, #32
	and	lr, r8, #63
	rsb	r4, lr, #0x40
	lsr	r9, r8, #6
	mul	r11, r8, r1
	add	r11, r11, r9
	lsl	r11, r11, #3
	add	r10, r0, r11
	lsl	r11, r1, #3
	mov	r5, #0
L_mc_mov_p1:
	cmp	r5, #32
	bge	L_mc_mov_p1x
	vld1.8	{d0}, [r10]
	add	r8, r10, #8
	vld1.8	{d2}, [r8]
	rsb	r8, lr, #0
	vmov	d22, r8, r12
	vshl.u64	q0, q0, q11
	vmov	d22, r4, r12
	vshl.u64	q1, q1, q11
	vorr	q0, q0, q1
	lsl	r8, r5, #3
	add	r8, sp, r8
	vst1.8	{d0}, [r8]
	add	r10, r10, r11
	add	r5, r5, #1
	b	L_mc_mov_p1
L_mc_mov_p1x:
	str	lr, [sp, #384]
	str	r4, [sp, #388]
	mov	r5, #0
L_mc_mov_p2:
	cmp	r5, #32
	bge	L_mc_mov_p2e
	lsl	r8, r5, #3
	add	r8, sp, r8
	vld1.8	{d4}, [r8]
	add	r6, r5, #1
L_mc_mov_or:
	cmp	r6, #32
	bge	L_mc_mov_ore
	lsl	r8, r6, #3
	add	r8, sp, r8
	vld1.8	{d6}, [r8]
	vorr	q2, q2, q3
	add	r6, r6, #1
	b	L_mc_mov_or
L_mc_mov_ore:
	vmov	r8, r9, d4
	orr	r10, r8, r9
	cmp	r10, #0
	beq	L_mc_mov_fail
	rbit	r10, r8
	clz	r10, r10
	rbit	r11, r9
	clz	r11, r11
	add	r11, r11, #32
	rsb	r7, r8, #0
	orr	r7, r7, r8
	asr	r7, r7, #31
	and	r10, r10, r7
	bic	r11, r11, r7
	orr	r7, r10, r11
	lsl	r8, r5, #2
	add	r8, sp, r8
	add	r8, r8, #0x100
	str	r7, [r8]
	vmov	d22, r7, r12
	vshl.u64	q9, q8, q11
	vorr	q7, q7, q9
	lsl	r8, r5, #3
	add	r10, sp, r8
	vld1.8	{d8}, [r10]
	add	r6, r5, #1
L_mc_mov_i1:
	cmp	r6, #32
	bge	L_mc_mov_i1e
	rsb	r8, r7, #0
	vmov	d22, r8, r12
	vshl.u64	q2, q4, q11
	vmov	r8, r9, d4
	and	r8, r8, #1
	sub	r8, r8, #1
	vmov	d20, r8, r8
	lsl	r8, r6, #3
	add	r8, sp, r8
	vld1.8	{d10}, [r8]
	vand	q5, q5, q10
	veor	q4, q4, q5
	add	r6, r6, #1
	b	L_mc_mov_i1
L_mc_mov_i1e:
	vst1.8	{d8}, [r10]
	add	r6, r5, #1
L_mc_mov_i2:
	cmp	r6, #32
	bge	L_mc_mov_i2e
	lsl	r8, r6, #3
	add	r11, sp, r8
	vld1.8	{d10}, [r11]
	rsb	r8, r7, #0
	vmov	d22, r8, r12
	vshl.u64	q2, q5, q11
	vmov	r8, r9, d4
	and	r8, r8, #1
	rsb	r8, r8, #0
	vmov	d20, r8, r8
	vand	q2, q4, q10
	veor	q5, q5, q2
	vst1.8	{d10}, [r11]
	add	r6, r6, #1
	b	L_mc_mov_i2
L_mc_mov_i2e:
	add	r5, r5, #1
	b	L_mc_mov_p2
L_mc_mov_p2e:
	ldr	r8, [sp, #500]
	vst1.8	{d14}, [r8]
	sub	r8, r2, #32
	lsl	r8, r8, #1
	add	r10, r3, r8
	mov	r5, #0
L_mc_mov_p3i:
	cmp	r5, #32
	bge	L_mc_mov_p3ie
	lsl	r8, r5, #2
	add	r8, sp, r8
	add	r8, r8, #0x100
	ldr	r7, [r8]
	lsl	r8, r5, #1
	add	r8, r10, r8
	ldrh	r9, [r8]
	add	r6, r5, #1
L_mc_mov_p3j:
	cmp	r6, #0x40
	bge	L_mc_mov_p3je
	lsl	r8, r6, #1
	add	r8, r10, r8
	ldrh	lr, [r8]
	eor	r4, r9, lr
	eor	r3, r6, r7
	rsb	r11, r3, #0
	orr	r3, r3, r11
	lsr	r3, r3, #31
	sub	r3, r3, #1
	and	r4, r4, r3
	eor	r9, r9, r4
	eor	lr, lr, r4
	strh	lr, [r8]
	add	r6, r6, #1
	b	L_mc_mov_p3j
L_mc_mov_p3je:
	lsl	r11, r5, #1
	add	r11, r10, r11
	strh	r9, [r11]
	add	r5, r5, #1
	b	L_mc_mov_p3i
L_mc_mov_p3ie:
	ldr	lr, [sp, #384]
	ldr	r4, [sp, #388]
	sub	r8, r2, #32
	lsr	r11, r8, #6
	mov	r5, #0
L_mc_mov_p4:
	cmp	r5, r2
	bge	L_mc_mov_p4e
	mul	r8, r5, r1
	add	r8, r8, r11
	lsl	r8, r8, #3
	add	r10, r0, r8
	vld1.8	{d0}, [r10]
	add	r8, r10, #8
	vld1.8	{d2}, [r8]
	rsb	r8, lr, #0
	vmov	d22, r8, r12
	vshl.u64	q6, q0, q11
	vmov	d22, r4, r12
	vshl.u64	q3, q1, q11
	vorr	q6, q6, q3
	mov	r6, #0
L_mc_mov_p4j:
	cmp	r6, #32
	bge	L_mc_mov_p4je
	lsl	r8, r6, #2
	add	r8, sp, r8
	add	r8, r8, #0x100
	ldr	r7, [r8]
	rsb	r8, r6, #0
	vmov	d22, r8, r12
	vshl.u64	q2, q6, q11
	rsb	r8, r7, #0
	vmov	d22, r8, r12
	vshl.u64	q3, q6, q11
	veor	q2, q2, q3
	vand	q2, q2, q8
	vmov	d22, r7, r12
	vshl.u64	q3, q2, q11
	veor	q6, q6, q3
	vmov	d22, r6, r12
	vshl.u64	q3, q2, q11
	veor	q6, q6, q3
	add	r6, r6, #1
	b	L_mc_mov_p4j
L_mc_mov_p4je:
	rsb	r8, r4, #0
	vmov	d22, r8, r12
	vshl.u64	q10, q12, q11
	vmov	d22, lr, r12
	vshl.u64	q2, q6, q11
	vand	q0, q0, q10
	vorr	q0, q0, q2
	vst1.8	{d0}, [r10]
	rsb	r8, r4, #0
	vmov	d22, r8, r12
	vshl.u64	q2, q6, q11
	vbic	q1, q1, q10
	vorr	q1, q1, q2
	add	r8, r10, #8
	vst1.8	{d2}, [r8]
	add	r5, r5, #1
	b	L_mc_mov_p4
L_mc_mov_p4e:
	mov	r0, #0
	b	L_mc_mov_done
L_mc_mov_fail:
	ldr	r8, [sp, #500]
	vst1.8	{d14}, [r8]
	mov	r0, #0
	sub	r0, r0, #1
L_mc_mov_done:
	add	sp, sp, #0x190
	vpop	{d8-d15}
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	wc_mceliece_bs_mov_columns_neon,.-wc_mceliece_bs_mov_columns_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_i32_sort_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_i32_sort_neon)
	.type	wc_mceliece_i32_sort_neon, %function
wc_mceliece_i32_sort_neon:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	cmp	r1, #2
	blt	L_mc_is_ret
	mov	r2, #1
L_mc_is_top:
	sub	r5, r1, r2
	cmp	r2, r5
	bge	L_mc_is_tope
	add	r2, r2, r2
	b	L_mc_is_top
L_mc_is_tope:
	mov	r3, r2
L_mc_is_p:
	cmp	r3, #0
	ble	L_mc_is_ret
	mov	lr, #0
L_mc_is_b:
	sub	r5, r1, r3
	cmp	lr, r5
	bge	L_mc_is_be
	add	r4, lr, r3
	cmp	r4, r5
	ble	L_mc_is_lim
	mov	r4, r5
L_mc_is_lim:
	mov	r12, lr
L_mc_is_i:
	cmp	r12, r4
	bge	L_mc_is_ie
	lsl	r6, r12, #2
	add	r6, r0, r6
	add	r5, r12, r3
	lsl	r7, r5, #2
	add	r7, r0, r7
	ldr	r8, [r6]
	ldr	r9, [r7]
	sub	r10, r8, r9
	asr	r11, r10, #31
	and	r10, r10, r11
	add	r11, r9, r10
	str	r11, [r6]
	sub	r11, r8, r10
	str	r11, [r7]
	add	r12, r12, #1
	b	L_mc_is_i
L_mc_is_ie:
	add	lr, lr, r3
	add	lr, lr, r3
	b	L_mc_is_b
L_mc_is_be:
	mov	r12, #0
	mov	lr, r2
L_mc_is_q:
	cmp	lr, r3
	ble	L_mc_is_qe
L_mc_is_iq:
	sub	r5, r1, lr
	cmp	r12, r5
	bge	L_mc_is_iqe
	and	r5, r12, r3
	cmp	r5, #0
	bne	L_mc_is_next
	mov	r4, lr
L_mc_is_r:
	cmp	r4, r3
	ble	L_mc_is_re
	add	r5, r12, r3
	lsl	r6, r5, #2
	add	r6, r0, r6
	add	r5, r12, r4
	lsl	r7, r5, #2
	add	r7, r0, r7
	ldr	r8, [r6]
	ldr	r9, [r7]
	sub	r10, r8, r9
	asr	r11, r10, #31
	and	r10, r10, r11
	add	r11, r9, r10
	str	r11, [r6]
	sub	r11, r8, r10
	str	r11, [r7]
	asr	r4, r4, #1
	b	L_mc_is_r
L_mc_is_re:
L_mc_is_next:
	add	r12, r12, #1
	b	L_mc_is_iq
L_mc_is_iqe:
	asr	lr, lr, #1
	b	L_mc_is_q
L_mc_is_qe:
	asr	r3, r3, #1
	b	L_mc_is_p
L_mc_is_ret:
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	wc_mceliece_i32_sort_neon,.-wc_mceliece_i32_sort_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_cb_compose10_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_cb_compose10_neon)
	.type	wc_mceliece_cb_compose10_neon, %function
wc_mceliece_cb_compose10_neon:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	mov	r4, r0
	mov	r5, r1
	mov	r6, r2
	mov	r7, r3
	mov	r1, r4
	mov	r2, r5
	mov	r0, #0
L_mc_c10_1:
	cmp	r0, r6
	bge	L_mc_c10_1e
	ldr	r3, [r1]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r12, #0xff
	orr	r12, r12, #0xff00
#else
	mov	r12, #0xffff
#endif
	and	r3, r3, r12
	lsl	r3, r3, #10
	ldr	r9, [r2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xff
	orr	r10, r10, #0x300
#else
	mov	r10, #0x3ff
#endif
	and	r9, r9, r10
	orr	r3, r3, r9
	str	r3, [r2]
	add	r1, r1, #4
	add	r2, r2, #4
	add	r0, r0, #1
	b	L_mc_c10_1
L_mc_c10_1e:
	mov	r8, #1
L_mc_c10_i:
	sub	r3, r7, #1
	cmp	r8, r3
	bge	L_mc_c10_ie
	mov	r1, r4
	mov	r2, r5
	mov	r0, #0
L_mc_c10_a1:
	cmp	r0, r6
	bge	L_mc_c10_a1e
	ldr	r3, [r2]
	movw	r12, #0xfc00
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	orr	r12, r12, #0xff000000
	orr	r12, r12, #0xff0000
#else
	movt	r12, #0xffff
#endif
	and	r3, r3, r12
	lsl	r3, r3, #6
	orr	r3, r3, r0
	str	r3, [r1]
	add	r1, r1, #4
	add	r2, r2, #4
	add	r0, r0, #1
	b	L_mc_c10_a1
L_mc_c10_a1e:
	mov	r0, r4
	mov	r1, r6
	bl	wc_mceliece_i32_sort_neon
	mov	r1, r4
	mov	r2, r5
	mov	r0, #0
L_mc_c10_a2:
	cmp	r0, r6
	bge	L_mc_c10_a2e
	ldr	r3, [r1]
	lsl	r3, r3, #20
	ldr	r12, [r2]
	orr	r3, r3, r12
	str	r3, [r1]
	add	r1, r1, #4
	add	r2, r2, #4
	add	r0, r0, #1
	b	L_mc_c10_a2
L_mc_c10_a2e:
	mov	r0, r4
	mov	r1, r6
	bl	wc_mceliece_i32_sort_neon
	mov	r1, r4
	mov	r2, r5
	mov	r0, #0
L_mc_c10_a3:
	cmp	r0, r6
	bge	L_mc_c10_a3e
	ldr	r3, [r1]
	movw	r12, #0xffff
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	orr	r12, r12, #0xf0000
#else
	movt	r12, #0xf
#endif
	and	r9, r3, r12
	movw	r12, #0xfc00
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	orr	r12, r12, #0xf0000
#else
	movt	r12, #0xf
#endif
	and	r3, r3, r12
	ldr	r12, [r2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xff
	orr	r10, r10, #0x300
#else
	mov	r10, #0x3ff
#endif
	and	r12, r12, r10
	orr	r3, r3, r12
	eor	r12, r3, r9
	sub	r11, r9, r3
	eor	r10, r11, r9
	and	r10, r10, r12
	eor	r11, r11, r10
	asr	r11, r11, #31
	and	r11, r11, r12
	eor	r10, r3, r11
	str	r10, [r2]
	add	r1, r1, #4
	add	r2, r2, #4
	add	r0, r0, #1
	b	L_mc_c10_a3
L_mc_c10_a3e:
	add	r8, r8, #1
	b	L_mc_c10_i
L_mc_c10_ie:
	mov	r2, r5
	mov	r0, #0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r12, #0xff
	orr	r12, r12, #0x300
#else
	mov	r12, #0x3ff
#endif
L_mc_c10_f:
	cmp	r0, r6
	bge	L_mc_c10_fe
	ldr	r3, [r2]
	and	r3, r3, r12
	str	r3, [r2]
	add	r2, r2, #4
	add	r0, r0, #1
	b	L_mc_c10_f
L_mc_c10_fe:
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	wc_mceliece_cb_compose10_neon,.-wc_mceliece_cb_compose10_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_cb_compose16_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_cb_compose16_neon)
	.type	wc_mceliece_cb_compose16_neon, %function
wc_mceliece_cb_compose16_neon:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	mov	r4, r0
	mov	r5, r1
	mov	r6, r2
	mov	r7, r3
	mov	r1, r4
	mov	r2, r5
	mov	r0, #0
L_mc_c16_1:
	cmp	r0, r6
	bge	L_mc_c16_1e
	ldr	r3, [r1]
	lsl	r3, r3, #16
	ldr	r12, [r2]
	uxth	r12, r12
	orr	r3, r3, r12
	str	r3, [r2]
	add	r1, r1, #4
	add	r2, r2, #4
	add	r0, r0, #1
	b	L_mc_c16_1
L_mc_c16_1e:
	mov	r8, #1
L_mc_c16_i:
	sub	r3, r7, #1
	cmp	r8, r3
	bge	L_mc_c16_ie
	mov	r1, r4
	mov	r2, r5
	mov	r0, #0
L_mc_c16_a1:
	cmp	r0, r6
	bge	L_mc_c16_a1e
	ldr	r3, [r2]
	movw	r12, #0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	orr	r12, r12, #0xff000000
	orr	r12, r12, #0xff0000
#else
	movt	r12, #0xffff
#endif
	and	r3, r3, r12
	orr	r3, r3, r0
	str	r3, [r1]
	add	r1, r1, #4
	add	r2, r2, #4
	add	r0, r0, #1
	b	L_mc_c16_a1
L_mc_c16_a1e:
	mov	r0, r4
	mov	r1, r6
	bl	wc_mceliece_i32_sort_neon
	mov	r1, r4
	mov	r2, r5
	mov	r0, #0
L_mc_c16_a2:
	cmp	r0, r6
	bge	L_mc_c16_a2e
	ldr	r3, [r1]
	lsl	r3, r3, #16
	ldr	r12, [r2]
	uxth	r12, r12
	orr	r3, r3, r12
	str	r3, [r1]
	add	r1, r1, #4
	add	r2, r2, #4
	add	r0, r0, #1
	b	L_mc_c16_a2
L_mc_c16_a2e:
	sub	r3, r7, #2
	cmp	r8, r3
	bge	L_mc_c16_sk
	mov	r1, r4
	mov	r2, r5
	mov	r0, #0
L_mc_c16_b1:
	cmp	r0, r6
	bge	L_mc_c16_b1e
	ldr	r3, [r1]
	movw	r12, #0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	orr	r12, r12, #0xff000000
	orr	r12, r12, #0xff0000
#else
	movt	r12, #0xffff
#endif
	and	r3, r3, r12
	ldr	r12, [r2]
	asr	r12, r12, #16
	orr	r3, r3, r12
	str	r3, [r2]
	add	r1, r1, #4
	add	r2, r2, #4
	add	r0, r0, #1
	b	L_mc_c16_b1
L_mc_c16_b1e:
	mov	r0, r5
	mov	r1, r6
	bl	wc_mceliece_i32_sort_neon
	mov	r1, r4
	mov	r2, r5
	mov	r0, #0
L_mc_c16_b2:
	cmp	r0, r6
	bge	L_mc_c16_b2e
	ldr	r3, [r2]
	lsl	r3, r3, #16
	ldr	r12, [r1]
	uxth	r12, r12
	orr	r3, r3, r12
	str	r3, [r2]
	add	r1, r1, #4
	add	r2, r2, #4
	add	r0, r0, #1
	b	L_mc_c16_b2
L_mc_c16_b2e:
L_mc_c16_sk:
	mov	r0, r4
	mov	r1, r6
	bl	wc_mceliece_i32_sort_neon
	mov	r1, r4
	mov	r2, r5
	mov	r0, #0
L_mc_c16_a3:
	cmp	r0, r6
	bge	L_mc_c16_a3e
	ldr	r9, [r2]
	movw	r12, #0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	orr	r12, r12, #0xff000000
	orr	r12, r12, #0xff0000
#else
	movt	r12, #0xffff
#endif
	and	r3, r9, r12
	ldr	r12, [r1]
	uxth	r12, r12
	orr	r3, r3, r12
	eor	r12, r9, r3
	sub	r11, r3, r9
	eor	r10, r11, r3
	and	r10, r10, r12
	eor	r11, r11, r10
	asr	r11, r11, #31
	and	r11, r11, r12
	eor	r10, r9, r11
	str	r10, [r2]
	add	r1, r1, #4
	add	r2, r2, #4
	add	r0, r0, #1
	b	L_mc_c16_a3
L_mc_c16_a3e:
	add	r8, r8, #1
	b	L_mc_c16_i
L_mc_c16_ie:
	mov	r2, r5
	mov	r0, #0
L_mc_c16_f:
	cmp	r0, r6
	bge	L_mc_c16_fe
	ldr	r3, [r2]
	uxth	r3, r3
	str	r3, [r2]
	add	r2, r2, #4
	add	r0, r0, #1
	b	L_mc_c16_f
L_mc_c16_fe:
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	wc_mceliece_cb_compose16_neon,.-wc_mceliece_cb_compose16_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_cb_build_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_cb_build_neon)
	.type	wc_mceliece_cb_build_neon, %function
wc_mceliece_cb_build_neon:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	sub	sp, sp, #32
	mov	r4, r0
	ldr	r5, [sp, #76]
	ldr	r6, [sp, #80]
	ldr	r0, [sp, #68]
	ldr	r8, [sp, #72]
	mov	r7, #1
	str	r1, [r6]
	str	r2, [r6, #4]
	str	r3, [r6, #8]
	str	r0, [r6, #12]
	str	r8, [r6, #16]
L_mc_cbb_w:
	cmp	r7, #0
	ble	L_mc_cbb_end
	sub	r7, r7, #1
	mov	r0, #20
	mul	r1, r7, r0
	add	r12, r6, r1
	ldr	r0, [r12]
	str	r0, [sp]
	ldr	r0, [r12, #4]
	str	r0, [sp, #4]
	ldr	r0, [r12, #8]
	str	r0, [sp, #8]
	ldr	r0, [r12, #12]
	str	r0, [sp, #12]
	ldr	r0, [r12, #16]
	str	r0, [sp, #16]
	ldr	r3, [sp, #12]
	cmp	r3, #1
	bne	L_mc_cbb_not1
	ldr	r0, [sp]
	lsr	r1, r0, #3
	add	r1, r4, r1
	ldrb	r2, [r1]
	ldr	r3, [sp, #8]
	ldrh	r3, [r3]
	and	r0, r0, #7
	lsl	r3, r3, r0
	eor	r2, r2, r3
	strb	r2, [r1]
	b	L_mc_cbb_w
L_mc_cbb_not1:
	ldr	r8, [sp, #16]
	ldr	r9, [sp, #8]
	mov	r10, r5
	mov	r11, #0
L_mc_cbb_s1:
	cmp	r11, r8
	bge	L_mc_cbb_s1e
	lsl	r0, r11, #1
	add	r0, r9, r0
	ldrh	r1, [r0]
	eor	r2, r1, #1
	lsl	r2, r2, #16
	eor	r0, r11, #1
	lsl	r0, r0, #1
	add	r0, r9, r0
	ldrh	r0, [r0]
	orr	r2, r2, r0
	str	r2, [r10]
	add	r10, r10, #4
	add	r11, r11, #1
	b	L_mc_cbb_s1
L_mc_cbb_s1e:
	mov	r0, r5
	ldr	r1, [sp, #16]
	bl	wc_mceliece_i32_sort_neon
	ldr	r8, [sp, #16]
	lsl	r0, r8, #2
	add	r9, r5, r0
	mov	r10, r5
	mov	r11, #0
L_mc_cbb_s2:
	cmp	r11, r8
	bge	L_mc_cbb_s2e
	ldr	r0, [r10]
	uxth	r12, r0
	eor	r2, r12, r11
	sub	r3, r11, r12
	eor	r1, r3, r11
	and	r1, r1, r2
	eor	r3, r3, r1
	asr	r3, r3, #31
	and	r3, r3, r2
	eor	r1, r12, r3
	lsl	r12, r12, #16
	orr	r12, r12, r1
	str	r12, [r9]
	add	r10, r10, #4
	add	r9, r9, #4
	add	r11, r11, #1
	b	L_mc_cbb_s2
L_mc_cbb_s2e:
	ldr	r8, [sp, #16]
	mov	r10, r5
	mov	r11, #0
L_mc_cbb_s3:
	cmp	r11, r8
	bge	L_mc_cbb_s3e
	ldr	r0, [r10]
	lsl	r0, r0, #16
	orr	r0, r0, r11
	str	r0, [r10]
	add	r10, r10, #4
	add	r11, r11, #1
	b	L_mc_cbb_s3
L_mc_cbb_s3e:
	mov	r0, r5
	ldr	r1, [sp, #16]
	bl	wc_mceliece_i32_sort_neon
	ldr	r8, [sp, #16]
	lsl	r0, r8, #2
	add	r9, r5, r0
	mov	r10, r5
	mov	r11, #0
L_mc_cbb_s4:
	cmp	r11, r8
	bge	L_mc_cbb_s4e
	ldr	r0, [r10]
	lsl	r0, r0, #16
	ldr	r1, [r9]
	asr	r1, r1, #16
	add	r0, r0, r1
	str	r0, [r10]
	add	r10, r10, #4
	add	r9, r9, #4
	add	r11, r11, #1
	b	L_mc_cbb_s4
L_mc_cbb_s4e:
	mov	r0, r5
	ldr	r1, [sp, #16]
	bl	wc_mceliece_i32_sort_neon
	ldr	r8, [sp, #16]
	lsl	r9, r8, #2
	add	r1, r5, r9
	mov	r2, r8
	ldr	r3, [sp, #12]
	mov	r0, r5
	cmp	r3, #10
	bgt	L_mc_cbb_c16
	bl	wc_mceliece_cb_compose10_neon
	b	L_mc_cbb_c5e
L_mc_cbb_c16:
	bl	wc_mceliece_cb_compose16_neon
L_mc_cbb_c5e:
	ldr	r8, [sp, #16]
	ldr	r9, [sp, #8]
	mov	r10, r5
	mov	r11, #0
L_mc_cbb_s6:
	cmp	r11, r8
	bge	L_mc_cbb_s6e
	lsl	r0, r11, #1
	add	r0, r9, r0
	ldrh	r1, [r0]
	lsl	r1, r1, #16
	add	r1, r1, r11
	str	r1, [r10]
	add	r10, r10, #4
	add	r11, r11, #1
	b	L_mc_cbb_s6
L_mc_cbb_s6e:
	mov	r0, r5
	ldr	r1, [sp, #16]
	bl	wc_mceliece_i32_sort_neon
	ldr	r12, [sp]
	ldr	r8, [sp, #16]
	lsr	r8, r8, #1
	ldr	r9, [sp, #16]
	lsl	r0, r9, #2
	add	r9, r5, r0
	mov	r10, r5
	mov	r11, #0
L_mc_cbb_s7:
	cmp	r11, r8
	bge	L_mc_cbb_s7e
	ldr	r0, [r9]
	and	r1, r0, #1
	lsr	r2, r12, #3
	add	r2, r4, r2
	ldrb	r3, [r2]
	and	r0, r12, #7
	lsl	r0, r1, r0
	eor	r3, r3, r0
	strb	r3, [r2]
	ldr	r2, [sp, #4]
	add	r12, r12, r2
	add	r3, r11, r11
	add	r3, r3, r1
	ldr	r0, [r10]
	lsl	r0, r0, #16
	orr	r0, r0, r3
	str	r0, [r9]
	eor	r3, r3, #1
	ldr	r0, [r10, #4]
	lsl	r0, r0, #16
	orr	r0, r0, r3
	str	r0, [r9, #4]
	add	r10, r10, #8
	add	r9, r9, #8
	add	r11, r11, #1
	b	L_mc_cbb_s7
L_mc_cbb_s7e:
	str	r12, [sp]
	ldr	r8, [sp, #16]
	lsl	r0, r8, #2
	add	r0, r5, r0
	ldr	r1, [sp, #16]
	bl	wc_mceliece_i32_sort_neon
	ldr	r12, [sp]
	ldr	r0, [sp, #12]
	add	r0, r0, r0
	sub	r0, r0, #3
	ldr	r1, [sp, #4]
	mul	r0, r0, r1
	ldr	r2, [sp, #16]
	lsr	r2, r2, #1
	mul	r0, r0, r2
	add	r12, r12, r0
	ldr	r8, [sp, #16]
	lsr	r8, r8, #1
	ldr	r9, [sp, #16]
	lsl	r0, r9, #2
	add	r9, r5, r0
	mov	r10, r5
	mov	r11, #0
L_mc_cbb_s8:
	cmp	r11, r8
	bge	L_mc_cbb_s8e
	ldr	r0, [r9]
	and	r1, r0, #1
	lsr	r2, r12, #3
	add	r2, r4, r2
	ldrb	r3, [r2]
	and	r0, r12, #7
	lsl	r0, r1, r0
	eor	r3, r3, r0
	strb	r3, [r2]
	ldr	r2, [sp, #4]
	add	r12, r12, r2
	add	r3, r11, r11
	add	r3, r3, r1
	ldr	r0, [r9]
	uxth	r0, r0
	lsl	r2, r3, #16
	orr	r0, r0, r2
	str	r0, [r10]
	eor	r3, r3, #1
	ldr	r0, [r9, #4]
	uxth	r0, r0
	lsl	r2, r3, #16
	orr	r0, r0, r2
	str	r0, [r10, #4]
	add	r10, r10, #8
	add	r9, r9, #8
	add	r11, r11, #1
	b	L_mc_cbb_s8
L_mc_cbb_s8e:
	str	r12, [sp]
	mov	r0, r5
	ldr	r1, [sp, #16]
	bl	wc_mceliece_i32_sort_neon
	ldr	r12, [sp]
	ldr	r0, [sp, #12]
	add	r0, r0, r0
	sub	r0, r0, #2
	ldr	r1, [sp, #4]
	mul	r0, r0, r1
	ldr	r2, [sp, #16]
	lsr	r2, r2, #1
	mul	r0, r0, r2
	sub	r12, r12, r0
	str	r12, [sp]
	ldr	r8, [sp, #16]
	lsr	r9, r8, #2
	add	r0, r8, r9
	lsl	r0, r0, #2
	add	r9, r5, r0
	lsr	r8, r8, #1
	mov	r10, r5
	mov	r11, #0
L_mc_cbb_s10:
	cmp	r11, r8
	bge	L_mc_cbb_s10e
	ldr	r0, [r10]
	uxth	r0, r0
	lsr	r0, r0, #1
	lsl	r1, r11, #1
	add	r1, r9, r1
	strh	r0, [r1]
	ldr	r0, [r10, #4]
	uxth	r0, r0
	lsr	r0, r0, #1
	add	r2, r11, r8
	lsl	r2, r2, #1
	add	r2, r9, r2
	strh	r0, [r2]
	add	r10, r10, #8
	add	r11, r11, #1
	b	L_mc_cbb_s10
L_mc_cbb_s10e:
	ldr	r0, [sp, #16]
	lsr	r1, r0, #2
	add	r2, r0, r1
	lsl	r2, r2, #2
	add	r9, r5, r2
	lsr	r10, r0, #1
	ldr	r3, [sp, #4]
	add	r3, r3, r3
	ldr	r11, [sp, #12]
	sub	r11, r11, #1
	ldr	r12, [sp]
	mov	r0, #20
	mul	r1, r7, r0
	add	r2, r6, r1
	ldr	r0, [sp, #4]
	add	r0, r12, r0
	str	r0, [r2]
	str	r3, [r2, #4]
	lsl	r0, r10, #1
	add	r0, r9, r0
	str	r0, [r2, #8]
	str	r11, [r2, #12]
	str	r10, [r2, #16]
	add	r7, r7, #1
	mov	r0, #20
	mul	r1, r7, r0
	add	r2, r6, r1
	str	r12, [r2]
	str	r3, [r2, #4]
	str	r9, [r2, #8]
	str	r11, [r2, #12]
	str	r10, [r2, #16]
	add	r7, r7, #1
	b	L_mc_cbb_w
L_mc_cbb_end:
	add	sp, sp, #32
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	wc_mceliece_cb_build_neon,.-wc_mceliece_cb_build_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_bs_fftbuild_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_bs_fftbuild_neon)
	.type	wc_mceliece_bs_fftbuild_neon, %function
wc_mceliece_bs_fftbuild_neon:
	push	{r4, r5, r6, lr}
	sub	sp, sp, #12
	mov	r4, r0
	ldr	r5, [r4, #12]
	ldr	r0, [r4, #64]
	mov	r1, r5
	ldr	r2, [r4]
	ldr	r3, [r4, #72]
	bl	wc_mceliece_bs_gload_neon
	add	r0, r5, #0x100
	mov	r1, r5
	bl	wc_mceliece_bs_poly_neon
	add	r0, r5, #0x100
	bl	wc_mceliece_radix_conv_neon
	ldr	r0, [r4, #28]
	add	r1, r5, #0x100
	ldr	r2, [r4, #88]
	add	r3, r5, #0xa00
	bl	wc_mceliece_fft_fwd_butterflies_neon
	ldr	r0, [r4, #20]
	ldr	r1, [r4, #28]
	add	r2, r5, #0x200
	add	r3, r5, #0x540
	mov	r12, #0
	str	r12, [sp]
	bl	wc_mceliece_mont_batch_inv_neon
	ldr	r0, [r4, #32]
	ldr	r1, [r4, #20]
	bl	wc_mceliece_bs_debitslice_neon
	mov	r0, r5
	ldr	r1, [r4, #4]
	ldr	r2, [r4, #32]
	bl	wc_mceliece_bs_packbuf_neon
	mov	r0, r5
	mov	r1, #0x2000
	bl	wc_mceliece_u64_sort_neon
	ldr	r0, [r4, #8]
	mov	r1, r5
	bl	wc_mceliece_bs_dup_pi_neon
	cmp	r0, #0
	beq	L_mc_fftb_nd
	mov	r6, #0
	sub	r6, r6, #1
	b	L_mc_fftb_end
L_mc_fftb_nd:
	ldr	r0, [r4, #24]
	ldr	r1, [r4, #20]
	mov	r2, r5
	bl	wc_mceliece_bs_tobitslice2x_neon
	mov	r6, #0
L_mc_fftb_end:
	mov	r0, r6
	add	sp, sp, #12
	pop	{r4, r5, r6, pc}
	.size	wc_mceliece_bs_fftbuild_neon,.-wc_mceliece_bs_fftbuild_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_bs_phase10_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_bs_phase10_neon)
	.type	wc_mceliece_bs_phase10_neon, %function
wc_mceliece_bs_phase10_neon:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	sub	sp, sp, #16
	mov	r4, r0
	ldr	r5, [r4, #36]
	ldr	r6, [r4, #80]
	ldr	r10, [r4, #48]
	ldr	r11, [r4, #120]
	add	r12, r6, #0xff
	lsr	r12, r12, #8
	lsl	r7, r12, #2
	mul	r0, r6, r11
	lsr	r1, r0, #2
	and	r2, r0, #3
	mov	r3, r10
	mov	r12, #0
	mov	r0, #0
L_mc_p10_zw:
	cmp	r0, r1
	bge	L_mc_p10_zwe
	str	r12, [r3]
	add	r3, r3, #4
	add	r0, r0, #1
	b	L_mc_p10_zw
L_mc_p10_zwe:
	mov	r0, #0
L_mc_p10_zb:
	cmp	r0, r2
	bge	L_mc_p10_zbe
	strb	r12, [r3]
	add	r3, r3, #1
	add	r0, r0, #1
	b	L_mc_p10_zb
L_mc_p10_zbe:
	ldr	r8, [r4, #112]
L_mc_p10_j:
	ldr	r12, [r4, #104]
	cmp	r8, r12
	bge	L_mc_p10_je
	mov	r0, #52
	mul	r12, r8, r0
	lsl	r12, r12, #3
	mov	r0, r5
	ldr	r1, [r4, #20]
	add	r1, r1, r12
	ldr	r2, [r4, #24]
	add	r2, r2, r12
	ldr	r3, [r4, #72]
	mov	r12, #13
	str	r12, [sp]
	mov	r12, #7
	str	r12, [sp, #4]
	ldr	r12, [r4, #104]
	sub	r12, r12, r8
	str	r12, [sp, #8]
	ldr	r12, [r4, #52]
	str	r12, [sp, #12]
	bl	wc_mceliece_bs_par_fill_neon
	ldr	r0, [r4, #40]
	ldr	r1, [r4, #44]
	mov	r2, #0
L_mc_p10_ic:
	cmp	r2, r6
	bge	L_mc_p10_ice
	ldrh	r12, [r1]
	strh	r12, [r0]
	add	r0, r0, #2
	add	r1, r1, #2
	add	r2, r2, #1
	b	L_mc_p10_ic
L_mc_p10_ice:
	ldr	r0, [r4, #40]
	mov	r1, r5
	mov	r2, #7
	mov	r3, r6
	bl	wc_mceliece_bs_sort_rows_neon
	sub	r9, r6, #1
L_mc_p10_l:
	cmp	r9, #0
	blt	L_mc_p10_le
	mov	r0, r5
	ldr	r1, [r4, #16]
	mul	r12, r9, r7
	lsl	r12, r12, #3
	add	r1, r1, r12
	mov	r2, r9
	mov	r3, #28
	mov	r12, #0
	str	r12, [sp]
	str	r9, [sp, #4]
	bl	wc_mceliece_bs_tri_neon
	sub	r9, r9, #1
	b	L_mc_p10_l
L_mc_p10_le:
	ldr	r12, [r4, #112]
	cmp	r8, r12
	bne	L_mc_p10_ove
	mov	r2, #0
L_mc_p10_or:
	cmp	r2, r6
	bge	L_mc_p10_ore
	mul	r0, r2, r7
	add	r0, r0, r7
	sub	r0, r0, #4
	lsl	r0, r0, #3
	ldr	r12, [r4, #16]
	add	r0, r12, r0
	mov	r12, #28
	mul	r1, r2, r12
	lsl	r1, r1, #3
	add	r1, r5, r1
	vld1.8	{d0-d3}, [r0]
	vst1.8	{d0-d3}, [r1]
	add	r2, r2, #1
	b	L_mc_p10_or
L_mc_p10_ore:
L_mc_p10_ove:
	sub	r9, r6, #1
L_mc_p10_u:
	cmp	r9, #0
	blt	L_mc_p10_ue
	mov	r0, r5
	ldr	r1, [r4, #16]
	mul	r12, r9, r7
	lsl	r12, r12, #3
	add	r1, r1, r12
	mov	r2, r9
	mov	r3, #28
	add	r12, r9, #1
	str	r12, [sp]
	str	r6, [sp, #4]
	bl	wc_mceliece_bs_tri_neon
	sub	r9, r9, #1
	b	L_mc_p10_u
L_mc_p10_ue:
	mov	r9, #0
L_mc_p10_b:
	cmp	r9, #7
	bge	L_mc_p10_be
	add	r2, r8, r9
	ldr	r12, [r4, #104]
	cmp	r2, r12
	bge	L_mc_p10_bsk
	mov	r3, #0
L_mc_p10_br:
	cmp	r3, r6
	bge	L_mc_p10_bre
	mul	r0, r3, r11
	lsl	r12, r2, #5
	add	r0, r0, r12
	add	r0, r10, r0
	mov	r12, #28
	mul	r1, r3, r12
	lsl	r12, r9, #2
	add	r1, r1, r12
	lsl	r1, r1, #3
	add	r1, r5, r1
	vld1.8	{d0-d3}, [r1]
	vst1.8	{d0-d3}, [r0]
	add	r3, r3, #1
	b	L_mc_p10_br
L_mc_p10_bre:
L_mc_p10_bsk:
	add	r9, r9, #1
	b	L_mc_p10_b
L_mc_p10_be:
	add	r8, r8, #7
	b	L_mc_p10_j
L_mc_p10_je:
	add	sp, sp, #16
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	wc_mceliece_bs_phase10_neon,.-wc_mceliece_bs_phase10_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_pk_gen_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_pk_gen_neon)
	.type	wc_mceliece_pk_gen_neon, %function
wc_mceliece_pk_gen_neon:
	push	{r4, r5, lr}
	sub	sp, sp, #16
	mov	r4, r0
	mov	r0, r4
	bl	wc_mceliece_bs_fftbuild_neon
	mov	r5, r0
	cmp	r0, #0
	bne	L_mc_pkg_end
	ldr	r0, [r4, #16]
	ldr	r1, [r4, #20]
	ldr	r2, [r4, #24]
	ldr	r3, [r4, #72]
	mov	r12, #13
	str	r12, [sp]
	ldr	r12, [r4, #80]
	add	r12, r12, #0xff
	lsr	r12, r12, #8
	str	r12, [sp, #4]
	lsl	r12, r12, #2
	str	r12, [sp, #8]
	ldr	r12, [r4, #52]
	str	r12, [sp, #12]
	bl	wc_mceliece_bs_lu_fill_neon
	ldr	r0, [r4, #80]
	ldr	r1, [r4, #40]
	ldr	r2, [r4, #44]
	mov	r3, #0
L_mc_pkg_ii:
	cmp	r3, r0
	bge	L_mc_pkg_iid
	strh	r3, [r1]
	strh	r3, [r2]
	add	r1, r1, #2
	add	r2, r2, #2
	add	r3, r3, #1
	b	L_mc_pkg_ii
L_mc_pkg_iid:
	ldr	r0, [r4, #16]
	ldr	r1, [r4, #40]
	ldr	r2, [r4, #80]
	ldr	r12, [r4, #80]
	add	r12, r12, #0xff
	lsr	r12, r12, #8
	lsl	r3, r12, #2
	ldr	r12, [r4, #96]
	str	r12, [sp]
	ldr	r12, [r4, #8]
	str	r12, [sp, #4]
	ldr	r12, [r4, #56]
	str	r12, [sp, #8]
	bl	wc_mceliece_bs_pk_gen_reduce_neon
	mov	r5, r0
	cmp	r0, #0
	bne	L_mc_pkg_end
	ldr	r0, [r4, #80]
	ldr	r1, [r4, #44]
	ldr	r2, [r4, #44]
	ldr	r3, [r4, #40]
	ldr	r12, [r4, #52]
	str	r12, [sp]
	bl	wc_mceliece_bs_composeinv_neon
	mov	r0, r4
	bl	wc_mceliece_bs_phase10_neon
	ldr	r0, [r4, #60]
	ldr	r1, [r4, #48]
	ldr	r2, [r4, #80]
	ldr	r3, [r4, #120]
	ldr	r12, [r4, #128]
	str	r12, [sp]
	bl	wc_mceliece_bs_extract_neon
	mov	r5, #0
L_mc_pkg_end:
	mov	r0, r5
	add	sp, sp, #16
	pop	{r4, r5, pc}
	.size	wc_mceliece_pk_gen_neon,.-wc_mceliece_pk_gen_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_genpoly_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_genpoly_neon)
	.type	wc_mceliece_genpoly_neon, %function
wc_mceliece_genpoly_neon:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	sub	sp, sp, #12
	str	r0, [sp]
	mov	r11, r1
	mov	r4, r2
	mov	r5, r3
	ldr	r6, [sp, #48]
	ldr	r12, [sp, #52]
	str	r12, [sp, #8]
	ldr	r12, [sp, #56]
	str	r12, [sp, #4]
	mov	r10, #0
	mov	r0, #1
	strh	r0, [r5]
	mov	r0, #0
	mov	r1, #1
L_mc_gp_c0:
	cmp	r1, r4
	bge	L_mc_gp_c0e
	lsl	r2, r1, #1
	add	r3, r5, r2
	strh	r0, [r3]
	add	r1, r1, #1
	b	L_mc_gp_c0
L_mc_gp_c0e:
	mov	r1, #0
L_mc_gp_c1:
	cmp	r1, r4
	bge	L_mc_gp_c1e
	lsl	r2, r1, #1
	add	r3, r11, r2
	ldrh	r0, [r3]
	add	r12, r4, r1
	lsl	r12, r12, #1
	add	r3, r5, r12
	strh	r0, [r3]
	add	r1, r1, #1
	b	L_mc_gp_c1
L_mc_gp_c1e:
	mov	r7, #2
L_mc_gp_j:
	cmp	r7, r4
	bgt	L_mc_gp_je
	mov	r0, #0
	lsl	r1, r4, #1
	sub	r1, r1, #1
	mov	r2, #0
L_mc_gp_pz:
	cmp	r2, r1
	bge	L_mc_gp_pze
	lsl	r3, r2, #1
	add	r12, r6, r3
	strh	r0, [r12]
	add	r2, r2, #1
	b	L_mc_gp_pz
L_mc_gp_pze:
	mov	r8, #0
L_mc_gp_pm:
	cmp	r8, r4
	bge	L_mc_gp_pme
	sub	r1, r7, #1
	mul	r0, r1, r4
	add	r0, r0, r8
	lsl	r0, r0, #1
	add	r0, r5, r0
	ldrh	r1, [r0]
	lsl	r0, r8, #1
	add	r0, r6, r0
	mov	r2, r11
	mov	r3, r4
	bl	wc_mceliece_gf_mulc_mac_full_neon
	add	r8, r8, #1
	b	L_mc_gp_pm
L_mc_gp_pme:
	lsl	r0, r4, #1
	sub	r0, r0, #2
	cmp	r4, #0x77
	beq	L_mc_gp_119
L_mc_gp_rd:
	cmp	r0, r4
	blt	L_mc_gp_rde
	lsl	r1, r0, #1
	add	r2, r6, r1
	ldrh	r3, [r2]
	sub	r1, r0, r4
	add	r12, r1, #0
	lsl	r12, r12, #1
	add	r12, r6, r12
	ldrh	r2, [r12]
	eor	r2, r2, r3
	strh	r2, [r12]
	add	r12, r1, #1
	lsl	r12, r12, #1
	add	r12, r6, r12
	ldrh	r2, [r12]
	eor	r2, r2, r3
	strh	r2, [r12]
	add	r12, r1, #2
	lsl	r12, r12, #1
	add	r12, r6, r12
	ldrh	r2, [r12]
	eor	r2, r2, r3
	strh	r2, [r12]
	add	r12, r1, #7
	lsl	r12, r12, #1
	add	r12, r6, r12
	ldrh	r2, [r12]
	eor	r2, r2, r3
	strh	r2, [r12]
	sub	r0, r0, #1
	b	L_mc_gp_rd
L_mc_gp_119:
	cmp	r0, r4
	blt	L_mc_gp_rde
	lsl	r1, r0, #1
	add	r2, r6, r1
	ldrh	r3, [r2]
	sub	r1, r0, r4
	add	r12, r1, #0
	lsl	r12, r12, #1
	add	r12, r6, r12
	ldrh	r2, [r12]
	eor	r2, r2, r3
	strh	r2, [r12]
	add	r12, r1, #8
	lsl	r12, r12, #1
	add	r12, r6, r12
	ldrh	r2, [r12]
	eor	r2, r2, r3
	strh	r2, [r12]
	sub	r0, r0, #1
	b	L_mc_gp_119
L_mc_gp_rde:
	mul	r12, r7, r4
	mov	r0, #0
L_mc_gp_cp:
	cmp	r0, r4
	bge	L_mc_gp_cpe
	lsl	r1, r0, #1
	add	r2, r6, r1
	ldrh	r3, [r2]
	add	r1, r12, r0
	lsl	r1, r1, #1
	add	r2, r5, r1
	strh	r3, [r2]
	add	r0, r0, #1
	b	L_mc_gp_cp
L_mc_gp_cpe:
	add	r7, r7, #1
	b	L_mc_gp_j
L_mc_gp_je:
	mov	r7, #0
L_mc_gp_e:
	cmp	r7, r4
	bge	L_mc_gp_ee
	add	r11, r7, #1
L_mc_gp_pk:
	cmp	r11, r4
	bge	L_mc_gp_pke
	mul	r0, r7, r4
	add	r0, r0, r7
	lsl	r0, r0, #1
	add	r0, r5, r0
	ldrh	r0, [r0]
	sub	r1, r0, #1
	lsr	r1, r1, #31
	neg	r1, r1
	mov	r2, r7
L_mc_gp_pc:
	cmp	r2, r4
	bgt	L_mc_gp_pce
	mul	r3, r2, r4
	add	r12, r3, r11
	add	r3, r3, r7
	lsl	r12, r12, #1
	add	r12, r5, r12
	ldrh	r12, [r12]
	and	r12, r12, r1
	lsl	r3, r3, #1
	add	r3, r5, r3
	ldrh	r0, [r3]
	eor	r0, r0, r12
	strh	r0, [r3]
	add	r2, r2, #1
	b	L_mc_gp_pc
L_mc_gp_pce:
	add	r11, r11, #1
	b	L_mc_gp_pk
L_mc_gp_pke:
	mul	r0, r7, r4
	add	r0, r0, r7
	lsl	r0, r0, #1
	add	r0, r5, r0
	ldrh	r0, [r0]
	cmp	r0, #0
	beq	L_mc_gp_sg
	bl	wc_mceliece_gf_inv_scalar_neon
	mov	r9, r0
	mov	r8, r7
L_mc_gp_nc:
	cmp	r8, r4
	bgt	L_mc_gp_nce
	mul	r0, r8, r4
	add	r0, r0, r7
	lsl	r0, r0, #1
	add	r0, r5, r0
	ldrh	r0, [r0]
	mov	r1, r9
	bl	wc_mceliece_gf_mul_scalar_neon
	mul	r1, r8, r4
	add	r1, r1, r7
	lsl	r1, r1, #1
	add	r1, r5, r1
	strh	r0, [r1]
	add	r8, r8, #1
	b	L_mc_gp_nc
L_mc_gp_nce:
	mov	r0, #0
L_mc_gp_sv:
	cmp	r0, r4
	bge	L_mc_gp_sve
	mul	r1, r7, r4
	add	r1, r1, r0
	lsl	r1, r1, #1
	add	r1, r5, r1
	ldrh	r2, [r1]
	lsl	r1, r0, #1
	add	r1, r6, r1
	strh	r2, [r1]
	add	r0, r0, #1
	b	L_mc_gp_sv
L_mc_gp_sve:
	mov	r0, #0
	lsl	r1, r7, #1
	add	r1, r6, r1
	strh	r0, [r1]
	mov	r8, r7
L_mc_gp_el:
	cmp	r8, r4
	bgt	L_mc_gp_ele
	mul	r0, r8, r4
	add	r1, r0, r7
	lsl	r1, r1, #1
	add	r1, r5, r1
	ldrh	r1, [r1]
	lsl	r0, r0, #1
	add	r0, r5, r0
	mov	r2, r6
	mov	r3, r4
	bl	wc_mceliece_gf_mulc_mac_full_neon
	add	r8, r8, #1
	b	L_mc_gp_el
L_mc_gp_ele:
	add	r7, r7, #1
	b	L_mc_gp_e
L_mc_gp_sg:
	mov	r10, #0
	sub	r10, r10, #1
	b	L_mc_gp_dn
L_mc_gp_ee:
	mul	r12, r4, r4
	ldr	r1, [sp]
	mov	r0, #0
L_mc_gp_o:
	cmp	r0, r4
	bge	L_mc_gp_oe
	add	r2, r12, r0
	lsl	r2, r2, #1
	add	r2, r5, r2
	ldrh	r3, [r2]
	lsl	r2, r0, #1
	add	r2, r1, r2
	strh	r3, [r2]
	add	r0, r0, #1
	b	L_mc_gp_o
L_mc_gp_oe:
	ldr	r1, [sp]
	ldr	r2, [sp, #8]
	lsr	r12, r4, #3
	lsl	r12, r12, #3
	mov	r0, #0
L_mc_gp_stv:
	cmp	r0, r12
	bge	L_mc_gp_stve
	lsl	r3, r0, #1
	add	r3, r1, r3
	vld1.8	{d0-d1}, [r3]
	lsl	r3, r0, #1
	add	r3, r2, r3
	vst1.8	{d0-d1}, [r3]
	add	r0, r0, #8
	b	L_mc_gp_stv
L_mc_gp_stve:
L_mc_gp_stg:
	cmp	r0, r4
	bge	L_mc_gp_stge
	lsl	r12, r0, #1
	add	r3, r1, r12
	ldrh	r3, [r3]
	add	r12, r2, r12
	strh	r3, [r12]
	add	r0, r0, #1
	b	L_mc_gp_stg
L_mc_gp_stge:
	ldr	r0, [sp, #4]
	bl	wc_mceliece_pk_gen_neon
	mov	r10, r0
L_mc_gp_dn:
	mov	r0, r10
	add	sp, sp, #12
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	wc_mceliece_genpoly_neon,.-wc_mceliece_genpoly_neon
	.ltorg
	.text
	.align	4
	.globl	wc_mceliece_controlbits_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_controlbits_neon)
	.type	wc_mceliece_controlbits_neon, %function
wc_mceliece_controlbits_neon:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	sub	sp, sp, #16
	mov	r4, r0
	mov	r5, r1
	mov	r6, r2
	mov	r7, r3
	ldr	r8, [sp, #56]
	mov	r9, #0
L_mc_cb_o:
	cmp	r9, #2
	bge	L_mc_cb_fail
	lsl	r0, r6, #1
	sub	r0, r0, #1
	lsr	r1, r7, #1
	mul	r2, r0, r1
	add	r2, r2, #7
	lsr	r2, r2, #3
	lsr	r0, r2, #2
	and	r1, r2, #3
	mov	r3, r4
	mov	r12, #0
	mov	r2, #0
L_mc_cb_zw:
	cmp	r2, r0
	bge	L_mc_cb_zwe
	str	r12, [r3]
	add	r3, r3, #4
	add	r2, r2, #1
	b	L_mc_cb_zw
L_mc_cb_zwe:
	mov	r2, #0
L_mc_cb_zb:
	cmp	r2, r1
	bge	L_mc_cb_zbe
	strb	r12, [r3]
	add	r3, r3, #1
	add	r2, r2, #1
	b	L_mc_cb_zb
L_mc_cb_zbe:
	mov	r0, r4
	mov	r1, #0
	mov	r2, #1
	mov	r3, r5
	mov	r12, r6
	str	r12, [sp]
	mov	r12, r7
	str	r12, [sp, #4]
	ldr	r12, [sp, #52]
	str	r12, [sp, #8]
	ldr	r12, [sp, #60]
	str	r12, [sp, #12]
	bl	wc_mceliece_cb_build_neon
	mov	r0, r8
	mov	r1, #0
L_mc_cb_pt:
	cmp	r1, r7
	bge	L_mc_cb_pte
	strh	r1, [r0]
	add	r0, r0, #2
	add	r1, r1, #1
	b	L_mc_cb_pt
L_mc_cb_pte:
	mov	r10, r4
	mov	r11, #0
L_mc_cb_fw:
	cmp	r11, r6
	bge	L_mc_cb_fwe
	mov	r0, r8
	mov	r1, r10
	mov	r2, r11
	mov	r3, r7
	bl	wc_mceliece_cb_layer_neon
	lsr	r12, r7, #4
	add	r10, r10, r12
	add	r11, r11, #1
	b	L_mc_cb_fw
L_mc_cb_fwe:
	sub	r11, r6, #2
L_mc_cb_bw:
	cmp	r11, #0
	blt	L_mc_cb_bwe
	mov	r0, r8
	mov	r1, r10
	mov	r2, r11
	mov	r3, r7
	bl	wc_mceliece_cb_layer_neon
	lsr	r12, r7, #4
	add	r10, r10, r12
	sub	r11, r11, #1
	b	L_mc_cb_bw
L_mc_cb_bwe:
	mov	r0, #0
	mov	r1, #0
L_mc_cb_vf:
	cmp	r1, r7
	bge	L_mc_cb_vfe
	lsl	r2, r1, #1
	add	r3, r5, r2
	ldrh	r3, [r3]
	add	r12, r8, r2
	ldrh	r12, [r12]
	eor	r3, r3, r12
	orr	r0, r0, r3
	add	r1, r1, #1
	b	L_mc_cb_vf
L_mc_cb_vfe:
	cmp	r0, #0
	beq	L_mc_cb_ok
	add	r9, r9, #1
	b	L_mc_cb_o
L_mc_cb_fail:
	mov	r0, #0
	sub	r0, r0, #1
	b	L_mc_cb_end
L_mc_cb_ok:
	mov	r0, #0
L_mc_cb_end:
	add	sp, sp, #16
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	wc_mceliece_controlbits_neon,.-wc_mceliece_controlbits_neon
	.ltorg
	.text
	.align	4
	.fpu	neon
	.globl	wc_mceliece_u64_minmax_vec_neon
	WC_ASM_ATT_HIDDEN(wc_mceliece_u64_minmax_vec_neon)
	.type	wc_mceliece_u64_minmax_vec_neon, %function
wc_mceliece_u64_minmax_vec_neon:
	bic	r3, r2, #0x1
	mov	r12, #0
L_mc_mmv:
	cmp	r12, r3
	bge	L_mc_mmve
	vld1.8	{d0-d1}, [r0]
	vld1.8	{d2-d3}, [r1]
	vsub.i64	q2, q1, q0
	vshr.s64	q2, q2, #63
	veor	q3, q0, q1
	vand	q3, q3, q2
	veor	q0, q0, q3
	veor	q1, q1, q3
	vst1.8	{d0-d1}, [r0]
	vst1.8	{d2-d3}, [r1]
	add	r0, r0, #16
	add	r1, r1, #16
	add	r12, r12, #2
	b	L_mc_mmv
L_mc_mmve:
L_mc_mmvt:
	cmp	r12, r2
	bge	L_mc_mmvte
	vld1.8	{d0}, [r0]
	vld1.8	{d2}, [r1]
	vsub.i64	d4, d2, d0
	vshr.s64	d4, d4, #63
	veor	d6, d0, d2
	vand	d6, d6, d4
	veor	d0, d0, d6
	veor	d2, d2, d6
	vst1.8	{d0}, [r0]
	vst1.8	{d2}, [r1]
	add	r0, r0, #8
	add	r1, r1, #8
	add	r12, r12, #1
	b	L_mc_mmvt
L_mc_mmvte:
	bx	lr
	.size	wc_mceliece_u64_minmax_vec_neon,.-wc_mceliece_u64_minmax_vec_neon
	.ltorg
#endif /* WOLFSSL_ARMASM_NO_NEON */
#endif /* WOLFSSL_HAVE_MCELIECE */

#if defined(__linux__) && defined(__ELF__)
.section	.note.GNU-stack,"",%progbits
#endif
#endif /* !WOLFSSL_ARMASM_INLINE */
#endif /* !__aarch64__ && !WOLFSSL_ARMASM_THUMB2 */
#endif /* WOLFSSL_ARMASM */
