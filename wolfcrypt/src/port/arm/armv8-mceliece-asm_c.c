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
 *       /home/sparki/wolfssl/github/mceliece/wolfssl/wolfcrypt/src/port/arm/armv8-mceliece-asm.c
 */

#define _WC_BUILDING_ARMV8_MCELIECE_ASM_C

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#ifdef WOLFSSL_ARMASM
#ifdef __aarch64__
#ifdef WOLFSSL_ARMASM_INLINE
#include <wolfssl/wolfcrypt/wc_mceliece.h>

#ifdef WOLFSSL_HAVE_MCELIECE
XALIGNED(16) static const word64 L_mc_aff_powers_neon[] = {
    0x5aa55aa5a55aa55aUL, 0x5aa55aa5a55aa55aUL,
    0xa55aa55a5aa55aa5UL, 0xa55aa55a5aa55aa5UL,
    0x3cc33cc3c33cc33cUL, 0xc33cc33c3cc33cc3UL,
    0xc33cc33c3cc33cc3UL, 0x3cc33cc3c33cc33cUL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0xffff0000ffff0000UL, 0x0000ffff0000ffffUL,
    0x0000ffff0000ffffUL, 0xffff0000ffff0000UL,
    0x33cc33cc33cc33ccUL, 0x33cc33cc33cc33ccUL,
    0x33cc33cc33cc33ccUL, 0x33cc33cc33cc33ccUL,
    0xf00ff00f0ff00ff0UL, 0x0ff00ff0f00ff00fUL,
    0xf00ff00f0ff00ff0UL, 0x0ff00ff0f00ff00fUL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0x6969696996969696UL, 0x6969696996969696UL,
    0x6969696996969696UL, 0x6969696996969696UL,
    0x5a5a5a5a5a5a5a5aUL, 0x5a5a5a5a5a5a5a5aUL,
    0xa5a5a5a5a5a5a5a5UL, 0xa5a5a5a5a5a5a5a5UL,
    0xa5a5a5a55a5a5a5aUL, 0xa5a5a5a55a5a5a5aUL,
    0x5a5a5a5aa5a5a5a5UL, 0x5a5a5a5aa5a5a5a5UL,
    0xaaaa55555555aaaaUL, 0x5555aaaaaaaa5555UL,
    0xaaaa55555555aaaaUL, 0x5555aaaaaaaa5555UL,
    0x0ff00ff00ff00ff0UL, 0xf00ff00ff00ff00fUL,
    0x0ff00ff00ff00ff0UL, 0xf00ff00ff00ff00fUL,
    0x0f0ff0f00f0ff0f0UL, 0xf0f00f0ff0f00f0fUL,
    0xf0f00f0ff0f00f0fUL, 0x0f0ff0f00f0ff0f0UL,
    0xa55aa55a5aa55aa5UL, 0xa55aa55a5aa55aa5UL,
    0x5aa55aa5a55aa55aUL, 0x5aa55aa5a55aa55aUL,
    0x3cc33cc3c33cc33cUL, 0xc33cc33c3cc33cc3UL,
    0xc33cc33c3cc33cc3UL, 0x3cc33cc3c33cc33cUL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0x0000ffff0000ffffUL, 0xffff0000ffff0000UL,
    0xffff0000ffff0000UL, 0x0000ffff0000ffffUL,
    0xcc33cc33cc33cc33UL, 0xcc33cc33cc33cc33UL,
    0xcc33cc33cc33cc33UL, 0xcc33cc33cc33cc33UL,
    0xf00ff00f0ff00ff0UL, 0x0ff00ff0f00ff00fUL,
    0xf00ff00f0ff00ff0UL, 0x0ff00ff0f00ff00fUL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0x9696969669696969UL, 0x9696969669696969UL,
    0x9696969669696969UL, 0x9696969669696969UL,
    0x5a5a5a5a5a5a5a5aUL, 0x5a5a5a5a5a5a5a5aUL,
    0xa5a5a5a5a5a5a5a5UL, 0xa5a5a5a5a5a5a5a5UL,
    0x5a5a5a5aa5a5a5a5UL, 0x5a5a5a5aa5a5a5a5UL,
    0xa5a5a5a55a5a5a5aUL, 0xa5a5a5a55a5a5a5aUL,
    0xaaaa55555555aaaaUL, 0x5555aaaaaaaa5555UL,
    0xaaaa55555555aaaaUL, 0x5555aaaaaaaa5555UL,
    0xf00ff00ff00ff00fUL, 0x0ff00ff00ff00ff0UL,
    0xf00ff00ff00ff00fUL, 0x0ff00ff00ff00ff0UL,
    0x0f0ff0f00f0ff0f0UL, 0xf0f00f0ff0f00f0fUL,
    0xf0f00f0ff0f00f0fUL, 0x0f0ff0f00f0ff0f0UL,
    0x5aa55aa5a55aa55aUL, 0x5aa55aa5a55aa55aUL,
    0xa55aa55a5aa55aa5UL, 0xa55aa55a5aa55aa5UL,
    0xc33cc33c3cc33cc3UL, 0x3cc33cc3c33cc33cUL,
    0x3cc33cc3c33cc33cUL, 0xc33cc33c3cc33cc3UL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0x0000ffff0000ffffUL, 0xffff0000ffff0000UL,
    0xffff0000ffff0000UL, 0x0000ffff0000ffffUL,
    0xcc33cc33cc33cc33UL, 0xcc33cc33cc33cc33UL,
    0xcc33cc33cc33cc33UL, 0xcc33cc33cc33cc33UL,
    0xf00ff00f0ff00ff0UL, 0x0ff00ff0f00ff00fUL,
    0xf00ff00f0ff00ff0UL, 0x0ff00ff0f00ff00fUL,
    0x00000000ffffffffUL, 0x00000000ffffffffUL,
    0x00000000ffffffffUL, 0x00000000ffffffffUL,
    0x9696969669696969UL, 0x9696969669696969UL,
    0x9696969669696969UL, 0x9696969669696969UL,
    0xa5a5a5a5a5a5a5a5UL, 0xa5a5a5a5a5a5a5a5UL,
    0x5a5a5a5a5a5a5a5aUL, 0x5a5a5a5a5a5a5a5aUL,
    0xa5a5a5a55a5a5a5aUL, 0xa5a5a5a55a5a5a5aUL,
    0x5a5a5a5aa5a5a5a5UL, 0x5a5a5a5aa5a5a5a5UL,
    0x5555aaaaaaaa5555UL, 0xaaaa55555555aaaaUL,
    0x5555aaaaaaaa5555UL, 0xaaaa55555555aaaaUL,
    0x0ff00ff00ff00ff0UL, 0xf00ff00ff00ff00fUL,
    0x0ff00ff00ff00ff0UL, 0xf00ff00ff00ff00fUL,
    0x0f0ff0f00f0ff0f0UL, 0xf0f00f0ff0f00f0fUL,
    0xf0f00f0ff0f00f0fUL, 0x0f0ff0f00f0ff0f0UL,
    0xa55aa55a5aa55aa5UL, 0xa55aa55a5aa55aa5UL,
    0x5aa55aa5a55aa55aUL, 0x5aa55aa5a55aa55aUL,
    0xc33cc33c3cc33cc3UL, 0x3cc33cc3c33cc33cUL,
    0x3cc33cc3c33cc33cUL, 0xc33cc33c3cc33cc3UL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0xffff0000ffff0000UL, 0x0000ffff0000ffffUL,
    0x0000ffff0000ffffUL, 0xffff0000ffff0000UL,
    0x33cc33cc33cc33ccUL, 0x33cc33cc33cc33ccUL,
    0x33cc33cc33cc33ccUL, 0x33cc33cc33cc33ccUL,
    0xf00ff00f0ff00ff0UL, 0x0ff00ff0f00ff00fUL,
    0xf00ff00f0ff00ff0UL, 0x0ff00ff0f00ff00fUL,
    0x00000000ffffffffUL, 0x00000000ffffffffUL,
    0x00000000ffffffffUL, 0x00000000ffffffffUL,
    0x6969696996969696UL, 0x6969696996969696UL,
    0x6969696996969696UL, 0x6969696996969696UL,
    0xa5a5a5a5a5a5a5a5UL, 0xa5a5a5a5a5a5a5a5UL,
    0x5a5a5a5a5a5a5a5aUL, 0x5a5a5a5a5a5a5a5aUL,
    0x5a5a5a5aa5a5a5a5UL, 0x5a5a5a5aa5a5a5a5UL,
    0xa5a5a5a55a5a5a5aUL, 0xa5a5a5a55a5a5a5aUL,
    0x5555aaaaaaaa5555UL, 0xaaaa55555555aaaaUL,
    0x5555aaaaaaaa5555UL, 0xaaaa55555555aaaaUL,
    0xf00ff00ff00ff00fUL, 0x0ff00ff00ff00ff0UL,
    0xf00ff00ff00ff00fUL, 0x0ff00ff00ff00ff0UL,
    0x0f0ff0f00f0ff0f0UL, 0xf0f00f0ff0f00f0fUL,
    0xf0f00f0ff0f00f0fUL, 0x0f0ff0f00f0ff0f0UL,
    0x5aa55aa5a55aa55aUL, 0x5aa55aa5a55aa55aUL,
    0xa55aa55a5aa55aa5UL, 0xa55aa55a5aa55aa5UL,
    0x3cc33cc3c33cc33cUL, 0xc33cc33c3cc33cc3UL,
    0xc33cc33c3cc33cc3UL, 0x3cc33cc3c33cc33cUL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0xffff0000ffff0000UL, 0x0000ffff0000ffffUL,
    0x0000ffff0000ffffUL, 0xffff0000ffff0000UL,
    0x33cc33cc33cc33ccUL, 0x33cc33cc33cc33ccUL,
    0x33cc33cc33cc33ccUL, 0x33cc33cc33cc33ccUL,
    0x0ff00ff0f00ff00fUL, 0xf00ff00f0ff00ff0UL,
    0x0ff00ff0f00ff00fUL, 0xf00ff00f0ff00ff0UL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0x6969696996969696UL, 0x6969696996969696UL,
    0x6969696996969696UL, 0x6969696996969696UL,
    0xa5a5a5a5a5a5a5a5UL, 0xa5a5a5a5a5a5a5a5UL,
    0x5a5a5a5a5a5a5a5aUL, 0x5a5a5a5a5a5a5a5aUL,
    0xa5a5a5a55a5a5a5aUL, 0xa5a5a5a55a5a5a5aUL,
    0x5a5a5a5aa5a5a5a5UL, 0x5a5a5a5aa5a5a5a5UL,
    0xaaaa55555555aaaaUL, 0x5555aaaaaaaa5555UL,
    0xaaaa55555555aaaaUL, 0x5555aaaaaaaa5555UL,
    0xf00ff00ff00ff00fUL, 0x0ff00ff00ff00ff0UL,
    0xf00ff00ff00ff00fUL, 0x0ff00ff00ff00ff0UL,
    0xf0f00f0ff0f00f0fUL, 0x0f0ff0f00f0ff0f0UL,
    0x0f0ff0f00f0ff0f0UL, 0xf0f00f0ff0f00f0fUL,
    0xa55aa55a5aa55aa5UL, 0xa55aa55a5aa55aa5UL,
    0x5aa55aa5a55aa55aUL, 0x5aa55aa5a55aa55aUL,
    0x3cc33cc3c33cc33cUL, 0xc33cc33c3cc33cc3UL,
    0xc33cc33c3cc33cc3UL, 0x3cc33cc3c33cc33cUL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0x0000ffff0000ffffUL, 0xffff0000ffff0000UL,
    0xffff0000ffff0000UL, 0x0000ffff0000ffffUL,
    0xcc33cc33cc33cc33UL, 0xcc33cc33cc33cc33UL,
    0xcc33cc33cc33cc33UL, 0xcc33cc33cc33cc33UL,
    0x0ff00ff0f00ff00fUL, 0xf00ff00f0ff00ff0UL,
    0x0ff00ff0f00ff00fUL, 0xf00ff00f0ff00ff0UL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0x9696969669696969UL, 0x9696969669696969UL,
    0x9696969669696969UL, 0x9696969669696969UL,
    0xa5a5a5a5a5a5a5a5UL, 0xa5a5a5a5a5a5a5a5UL,
    0x5a5a5a5a5a5a5a5aUL, 0x5a5a5a5a5a5a5a5aUL,
    0x5a5a5a5aa5a5a5a5UL, 0x5a5a5a5aa5a5a5a5UL,
    0xa5a5a5a55a5a5a5aUL, 0xa5a5a5a55a5a5a5aUL,
    0xaaaa55555555aaaaUL, 0x5555aaaaaaaa5555UL,
    0xaaaa55555555aaaaUL, 0x5555aaaaaaaa5555UL,
    0x0ff00ff00ff00ff0UL, 0xf00ff00ff00ff00fUL,
    0x0ff00ff00ff00ff0UL, 0xf00ff00ff00ff00fUL,
    0xf0f00f0ff0f00f0fUL, 0x0f0ff0f00f0ff0f0UL,
    0x0f0ff0f00f0ff0f0UL, 0xf0f00f0ff0f00f0fUL,
    0x5aa55aa5a55aa55aUL, 0x5aa55aa5a55aa55aUL,
    0xa55aa55a5aa55aa5UL, 0xa55aa55a5aa55aa5UL,
    0xc33cc33c3cc33cc3UL, 0x3cc33cc3c33cc33cUL,
    0x3cc33cc3c33cc33cUL, 0xc33cc33c3cc33cc3UL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0x0000ffff0000ffffUL, 0xffff0000ffff0000UL,
    0xffff0000ffff0000UL, 0x0000ffff0000ffffUL,
    0xcc33cc33cc33cc33UL, 0xcc33cc33cc33cc33UL,
    0xcc33cc33cc33cc33UL, 0xcc33cc33cc33cc33UL,
    0x0ff00ff0f00ff00fUL, 0xf00ff00f0ff00ff0UL,
    0x0ff00ff0f00ff00fUL, 0xf00ff00f0ff00ff0UL,
    0x00000000ffffffffUL, 0x00000000ffffffffUL,
    0x00000000ffffffffUL, 0x00000000ffffffffUL,
    0x9696969669696969UL, 0x9696969669696969UL,
    0x9696969669696969UL, 0x9696969669696969UL,
    0x5a5a5a5a5a5a5a5aUL, 0x5a5a5a5a5a5a5a5aUL,
    0xa5a5a5a5a5a5a5a5UL, 0xa5a5a5a5a5a5a5a5UL,
    0xa5a5a5a55a5a5a5aUL, 0xa5a5a5a55a5a5a5aUL,
    0x5a5a5a5aa5a5a5a5UL, 0x5a5a5a5aa5a5a5a5UL,
    0x5555aaaaaaaa5555UL, 0xaaaa55555555aaaaUL,
    0x5555aaaaaaaa5555UL, 0xaaaa55555555aaaaUL,
    0xf00ff00ff00ff00fUL, 0x0ff00ff00ff00ff0UL,
    0xf00ff00ff00ff00fUL, 0x0ff00ff00ff00ff0UL,
    0xf0f00f0ff0f00f0fUL, 0x0f0ff0f00f0ff0f0UL,
    0x0f0ff0f00f0ff0f0UL, 0xf0f00f0ff0f00f0fUL,
    0xa55aa55a5aa55aa5UL, 0xa55aa55a5aa55aa5UL,
    0x5aa55aa5a55aa55aUL, 0x5aa55aa5a55aa55aUL,
    0xc33cc33c3cc33cc3UL, 0x3cc33cc3c33cc33cUL,
    0x3cc33cc3c33cc33cUL, 0xc33cc33c3cc33cc3UL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0xffff0000ffff0000UL, 0x0000ffff0000ffffUL,
    0x0000ffff0000ffffUL, 0xffff0000ffff0000UL,
    0x33cc33cc33cc33ccUL, 0x33cc33cc33cc33ccUL,
    0x33cc33cc33cc33ccUL, 0x33cc33cc33cc33ccUL,
    0x0ff00ff0f00ff00fUL, 0xf00ff00f0ff00ff0UL,
    0x0ff00ff0f00ff00fUL, 0xf00ff00f0ff00ff0UL,
    0x00000000ffffffffUL, 0x00000000ffffffffUL,
    0x00000000ffffffffUL, 0x00000000ffffffffUL,
    0x6969696996969696UL, 0x6969696996969696UL,
    0x6969696996969696UL, 0x6969696996969696UL,
    0x5a5a5a5a5a5a5a5aUL, 0x5a5a5a5a5a5a5a5aUL,
    0xa5a5a5a5a5a5a5a5UL, 0xa5a5a5a5a5a5a5a5UL,
    0x5a5a5a5aa5a5a5a5UL, 0x5a5a5a5aa5a5a5a5UL,
    0xa5a5a5a55a5a5a5aUL, 0xa5a5a5a55a5a5a5aUL,
    0x5555aaaaaaaa5555UL, 0xaaaa55555555aaaaUL,
    0x5555aaaaaaaa5555UL, 0xaaaa55555555aaaaUL,
    0x0ff00ff00ff00ff0UL, 0xf00ff00ff00ff00fUL,
    0x0ff00ff00ff00ff0UL, 0xf00ff00ff00ff00fUL,
    0xf0f00f0ff0f00f0fUL, 0x0f0ff0f00f0ff0f0UL,
    0x0f0ff0f00f0ff0f0UL, 0xf0f00f0ff0f00f0fUL,
    0xa55aa55a5aa55aa5UL, 0xa55aa55a5aa55aa5UL,
    0x5aa55aa5a55aa55aUL, 0x5aa55aa5a55aa55aUL,
    0x3cc33cc3c33cc33cUL, 0xc33cc33c3cc33cc3UL,
    0xc33cc33c3cc33cc3UL, 0x3cc33cc3c33cc33cUL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0xffff0000ffff0000UL, 0x0000ffff0000ffffUL,
    0x0000ffff0000ffffUL, 0xffff0000ffff0000UL,
    0x33cc33cc33cc33ccUL, 0x33cc33cc33cc33ccUL,
    0x33cc33cc33cc33ccUL, 0x33cc33cc33cc33ccUL,
    0x0ff00ff0f00ff00fUL, 0xf00ff00f0ff00ff0UL,
    0x0ff00ff0f00ff00fUL, 0xf00ff00f0ff00ff0UL,
    0x00000000ffffffffUL, 0x00000000ffffffffUL,
    0x00000000ffffffffUL, 0x00000000ffffffffUL,
    0x6969696996969696UL, 0x6969696996969696UL,
    0x6969696996969696UL, 0x6969696996969696UL,
    0x5a5a5a5a5a5a5a5aUL, 0x5a5a5a5a5a5a5a5aUL,
    0xa5a5a5a5a5a5a5a5UL, 0xa5a5a5a5a5a5a5a5UL,
    0x5a5a5a5aa5a5a5a5UL, 0x5a5a5a5aa5a5a5a5UL,
    0xa5a5a5a55a5a5a5aUL, 0xa5a5a5a55a5a5a5aUL,
    0xaaaa55555555aaaaUL, 0x5555aaaaaaaa5555UL,
    0xaaaa55555555aaaaUL, 0x5555aaaaaaaa5555UL,
    0xf00ff00ff00ff00fUL, 0x0ff00ff00ff00ff0UL,
    0xf00ff00ff00ff00fUL, 0x0ff00ff00ff00ff0UL,
    0xf0f00f0ff0f00f0fUL, 0x0f0ff0f00f0ff0f0UL,
    0x0f0ff0f00f0ff0f0UL, 0xf0f00f0ff0f00f0fUL,
    0x5aa55aa5a55aa55aUL, 0x5aa55aa5a55aa55aUL,
    0xa55aa55a5aa55aa5UL, 0xa55aa55a5aa55aa5UL,
    0x3cc33cc3c33cc33cUL, 0xc33cc33c3cc33cc3UL,
    0xc33cc33c3cc33cc3UL, 0x3cc33cc3c33cc33cUL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0x0000ffff0000ffffUL, 0xffff0000ffff0000UL,
    0xffff0000ffff0000UL, 0x0000ffff0000ffffUL,
    0xcc33cc33cc33cc33UL, 0xcc33cc33cc33cc33UL,
    0xcc33cc33cc33cc33UL, 0xcc33cc33cc33cc33UL,
    0x0ff00ff0f00ff00fUL, 0xf00ff00f0ff00ff0UL,
    0x0ff00ff0f00ff00fUL, 0xf00ff00f0ff00ff0UL,
    0x00000000ffffffffUL, 0x00000000ffffffffUL,
    0x00000000ffffffffUL, 0x00000000ffffffffUL,
    0x9696969669696969UL, 0x9696969669696969UL,
    0x9696969669696969UL, 0x9696969669696969UL,
    0x5a5a5a5a5a5a5a5aUL, 0x5a5a5a5a5a5a5a5aUL,
    0xa5a5a5a5a5a5a5a5UL, 0xa5a5a5a5a5a5a5a5UL,
    0xa5a5a5a55a5a5a5aUL, 0xa5a5a5a55a5a5a5aUL,
    0x5a5a5a5aa5a5a5a5UL, 0x5a5a5a5aa5a5a5a5UL,
    0xaaaa55555555aaaaUL, 0x5555aaaaaaaa5555UL,
    0xaaaa55555555aaaaUL, 0x5555aaaaaaaa5555UL,
    0x0ff00ff00ff00ff0UL, 0xf00ff00ff00ff00fUL,
    0x0ff00ff00ff00ff0UL, 0xf00ff00ff00ff00fUL,
    0xf0f00f0ff0f00f0fUL, 0x0f0ff0f00f0ff0f0UL,
    0x0f0ff0f00f0ff0f0UL, 0xf0f00f0ff0f00f0fUL,
    0xa55aa55a5aa55aa5UL, 0xa55aa55a5aa55aa5UL,
    0x5aa55aa5a55aa55aUL, 0x5aa55aa5a55aa55aUL,
    0xc33cc33c3cc33cc3UL, 0x3cc33cc3c33cc33cUL,
    0x3cc33cc3c33cc33cUL, 0xc33cc33c3cc33cc3UL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0x0000ffff0000ffffUL, 0xffff0000ffff0000UL,
    0xffff0000ffff0000UL, 0x0000ffff0000ffffUL,
    0xcc33cc33cc33cc33UL, 0xcc33cc33cc33cc33UL,
    0xcc33cc33cc33cc33UL, 0xcc33cc33cc33cc33UL,
    0x0ff00ff0f00ff00fUL, 0xf00ff00f0ff00ff0UL,
    0x0ff00ff0f00ff00fUL, 0xf00ff00f0ff00ff0UL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0x9696969669696969UL, 0x9696969669696969UL,
    0x9696969669696969UL, 0x9696969669696969UL,
    0xa5a5a5a5a5a5a5a5UL, 0xa5a5a5a5a5a5a5a5UL,
    0x5a5a5a5a5a5a5a5aUL, 0x5a5a5a5a5a5a5a5aUL,
    0x5a5a5a5aa5a5a5a5UL, 0x5a5a5a5aa5a5a5a5UL,
    0xa5a5a5a55a5a5a5aUL, 0xa5a5a5a55a5a5a5aUL,
    0x5555aaaaaaaa5555UL, 0xaaaa55555555aaaaUL,
    0x5555aaaaaaaa5555UL, 0xaaaa55555555aaaaUL,
    0xf00ff00ff00ff00fUL, 0x0ff00ff00ff00ff0UL,
    0xf00ff00ff00ff00fUL, 0x0ff00ff00ff00ff0UL,
    0xf0f00f0ff0f00f0fUL, 0x0f0ff0f00f0ff0f0UL,
    0x0f0ff0f00f0ff0f0UL, 0xf0f00f0ff0f00f0fUL,
    0x5aa55aa5a55aa55aUL, 0x5aa55aa5a55aa55aUL,
    0xa55aa55a5aa55aa5UL, 0xa55aa55a5aa55aa5UL,
    0xc33cc33c3cc33cc3UL, 0x3cc33cc3c33cc33cUL,
    0x3cc33cc3c33cc33cUL, 0xc33cc33c3cc33cc3UL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0xffff0000ffff0000UL, 0x0000ffff0000ffffUL,
    0x0000ffff0000ffffUL, 0xffff0000ffff0000UL,
    0x33cc33cc33cc33ccUL, 0x33cc33cc33cc33ccUL,
    0x33cc33cc33cc33ccUL, 0x33cc33cc33cc33ccUL,
    0x0ff00ff0f00ff00fUL, 0xf00ff00f0ff00ff0UL,
    0x0ff00ff0f00ff00fUL, 0xf00ff00f0ff00ff0UL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0x6969696996969696UL, 0x6969696996969696UL,
    0x6969696996969696UL, 0x6969696996969696UL,
    0xa5a5a5a5a5a5a5a5UL, 0xa5a5a5a5a5a5a5a5UL,
    0x5a5a5a5a5a5a5a5aUL, 0x5a5a5a5a5a5a5a5aUL,
    0xa5a5a5a55a5a5a5aUL, 0xa5a5a5a55a5a5a5aUL,
    0x5a5a5a5aa5a5a5a5UL, 0x5a5a5a5aa5a5a5a5UL,
    0x5555aaaaaaaa5555UL, 0xaaaa55555555aaaaUL,
    0x5555aaaaaaaa5555UL, 0xaaaa55555555aaaaUL,
    0x0ff00ff00ff00ff0UL, 0xf00ff00ff00ff00fUL,
    0x0ff00ff00ff00ff0UL, 0xf00ff00ff00ff00fUL,
    0xf0f00f0ff0f00f0fUL, 0x0f0ff0f00f0ff0f0UL,
    0x0f0ff0f00f0ff0f0UL, 0xf0f00f0ff0f00f0fUL,
    0xa55aa55a5aa55aa5UL, 0xa55aa55a5aa55aa5UL,
    0x5aa55aa5a55aa55aUL, 0x5aa55aa5a55aa55aUL,
    0x3cc33cc3c33cc33cUL, 0xc33cc33c3cc33cc3UL,
    0xc33cc33c3cc33cc3UL, 0x3cc33cc3c33cc33cUL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0xffff0000ffff0000UL, 0x0000ffff0000ffffUL,
    0x0000ffff0000ffffUL, 0xffff0000ffff0000UL,
    0x33cc33cc33cc33ccUL, 0x33cc33cc33cc33ccUL,
    0x33cc33cc33cc33ccUL, 0x33cc33cc33cc33ccUL,
    0xf00ff00f0ff00ff0UL, 0x0ff00ff0f00ff00fUL,
    0xf00ff00f0ff00ff0UL, 0x0ff00ff0f00ff00fUL,
    0x00000000ffffffffUL, 0x00000000ffffffffUL,
    0x00000000ffffffffUL, 0x00000000ffffffffUL,
    0x6969696996969696UL, 0x6969696996969696UL,
    0x6969696996969696UL, 0x6969696996969696UL,
    0xa5a5a5a5a5a5a5a5UL, 0xa5a5a5a5a5a5a5a5UL,
    0x5a5a5a5a5a5a5a5aUL, 0x5a5a5a5a5a5a5a5aUL,
    0x5a5a5a5aa5a5a5a5UL, 0x5a5a5a5aa5a5a5a5UL,
    0xa5a5a5a55a5a5a5aUL, 0xa5a5a5a55a5a5a5aUL,
    0xaaaa55555555aaaaUL, 0x5555aaaaaaaa5555UL,
    0xaaaa55555555aaaaUL, 0x5555aaaaaaaa5555UL,
    0x0ff00ff00ff00ff0UL, 0xf00ff00ff00ff00fUL,
    0x0ff00ff00ff00ff0UL, 0xf00ff00ff00ff00fUL,
    0x0f0ff0f00f0ff0f0UL, 0xf0f00f0ff0f00f0fUL,
    0xf0f00f0ff0f00f0fUL, 0x0f0ff0f00f0ff0f0UL,
    0x5aa55aa5a55aa55aUL, 0x5aa55aa5a55aa55aUL,
    0xa55aa55a5aa55aa5UL, 0xa55aa55a5aa55aa5UL,
    0x3cc33cc3c33cc33cUL, 0xc33cc33c3cc33cc3UL,
    0xc33cc33c3cc33cc3UL, 0x3cc33cc3c33cc33cUL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0x0000ffff0000ffffUL, 0xffff0000ffff0000UL,
    0xffff0000ffff0000UL, 0x0000ffff0000ffffUL,
    0xcc33cc33cc33cc33UL, 0xcc33cc33cc33cc33UL,
    0xcc33cc33cc33cc33UL, 0xcc33cc33cc33cc33UL,
    0xf00ff00f0ff00ff0UL, 0x0ff00ff0f00ff00fUL,
    0xf00ff00f0ff00ff0UL, 0x0ff00ff0f00ff00fUL,
    0x00000000ffffffffUL, 0x00000000ffffffffUL,
    0x00000000ffffffffUL, 0x00000000ffffffffUL,
    0x9696969669696969UL, 0x9696969669696969UL,
    0x9696969669696969UL, 0x9696969669696969UL,
    0xa5a5a5a5a5a5a5a5UL, 0xa5a5a5a5a5a5a5a5UL,
    0x5a5a5a5a5a5a5a5aUL, 0x5a5a5a5a5a5a5a5aUL,
    0xa5a5a5a55a5a5a5aUL, 0xa5a5a5a55a5a5a5aUL,
    0x5a5a5a5aa5a5a5a5UL, 0x5a5a5a5aa5a5a5a5UL,
    0xaaaa55555555aaaaUL, 0x5555aaaaaaaa5555UL,
    0xaaaa55555555aaaaUL, 0x5555aaaaaaaa5555UL,
    0xf00ff00ff00ff00fUL, 0x0ff00ff00ff00ff0UL,
    0xf00ff00ff00ff00fUL, 0x0ff00ff00ff00ff0UL,
    0x0f0ff0f00f0ff0f0UL, 0xf0f00f0ff0f00f0fUL,
    0xf0f00f0ff0f00f0fUL, 0x0f0ff0f00f0ff0f0UL,
    0xa55aa55a5aa55aa5UL, 0xa55aa55a5aa55aa5UL,
    0x5aa55aa5a55aa55aUL, 0x5aa55aa5a55aa55aUL,
    0xc33cc33c3cc33cc3UL, 0x3cc33cc3c33cc33cUL,
    0x3cc33cc3c33cc33cUL, 0xc33cc33c3cc33cc3UL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0x0000ffff0000ffffUL, 0xffff0000ffff0000UL,
    0xffff0000ffff0000UL, 0x0000ffff0000ffffUL,
    0xcc33cc33cc33cc33UL, 0xcc33cc33cc33cc33UL,
    0xcc33cc33cc33cc33UL, 0xcc33cc33cc33cc33UL,
    0xf00ff00f0ff00ff0UL, 0x0ff00ff0f00ff00fUL,
    0xf00ff00f0ff00ff0UL, 0x0ff00ff0f00ff00fUL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0x9696969669696969UL, 0x9696969669696969UL,
    0x9696969669696969UL, 0x9696969669696969UL,
    0x5a5a5a5a5a5a5a5aUL, 0x5a5a5a5a5a5a5a5aUL,
    0xa5a5a5a5a5a5a5a5UL, 0xa5a5a5a5a5a5a5a5UL,
    0x5a5a5a5aa5a5a5a5UL, 0x5a5a5a5aa5a5a5a5UL,
    0xa5a5a5a55a5a5a5aUL, 0xa5a5a5a55a5a5a5aUL,
    0x5555aaaaaaaa5555UL, 0xaaaa55555555aaaaUL,
    0x5555aaaaaaaa5555UL, 0xaaaa55555555aaaaUL,
    0x0ff00ff00ff00ff0UL, 0xf00ff00ff00ff00fUL,
    0x0ff00ff00ff00ff0UL, 0xf00ff00ff00ff00fUL,
    0x0f0ff0f00f0ff0f0UL, 0xf0f00f0ff0f00f0fUL,
    0xf0f00f0ff0f00f0fUL, 0x0f0ff0f00f0ff0f0UL,
    0x5aa55aa5a55aa55aUL, 0x5aa55aa5a55aa55aUL,
    0xa55aa55a5aa55aa5UL, 0xa55aa55a5aa55aa5UL,
    0xc33cc33c3cc33cc3UL, 0x3cc33cc3c33cc33cUL,
    0x3cc33cc3c33cc33cUL, 0xc33cc33c3cc33cc3UL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0xffff0000ffff0000UL, 0x0000ffff0000ffffUL,
    0x0000ffff0000ffffUL, 0xffff0000ffff0000UL,
    0x33cc33cc33cc33ccUL, 0x33cc33cc33cc33ccUL,
    0x33cc33cc33cc33ccUL, 0x33cc33cc33cc33ccUL,
    0xf00ff00f0ff00ff0UL, 0x0ff00ff0f00ff00fUL,
    0xf00ff00f0ff00ff0UL, 0x0ff00ff0f00ff00fUL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0x6969696996969696UL, 0x6969696996969696UL,
    0x6969696996969696UL, 0x6969696996969696UL,
    0x5a5a5a5a5a5a5a5aUL, 0x5a5a5a5a5a5a5a5aUL,
    0xa5a5a5a5a5a5a5a5UL, 0xa5a5a5a5a5a5a5a5UL,
    0xa5a5a5a55a5a5a5aUL, 0xa5a5a5a55a5a5a5aUL,
    0x5a5a5a5aa5a5a5a5UL, 0x5a5a5a5aa5a5a5a5UL,
    0x5555aaaaaaaa5555UL, 0xaaaa55555555aaaaUL,
    0x5555aaaaaaaa5555UL, 0xaaaa55555555aaaaUL,
    0xf00ff00ff00ff00fUL, 0x0ff00ff00ff00ff0UL,
    0xf00ff00ff00ff00fUL, 0x0ff00ff00ff00ff0UL,
    0x0f0ff0f00f0ff0f0UL, 0xf0f00f0ff0f00f0fUL,
    0xf0f00f0ff0f00f0fUL, 0x0f0ff0f00f0ff0f0UL,
    0xa55aa55a5aa55aa5UL, 0xa55aa55a5aa55aa5UL,
    0x5aa55aa5a55aa55aUL, 0x5aa55aa5a55aa55aUL,
    0x3cc33cc3c33cc33cUL, 0xc33cc33c3cc33cc3UL,
    0xc33cc33c3cc33cc3UL, 0x3cc33cc3c33cc33cUL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0xffff0000ffff0000UL, 0x0000ffff0000ffffUL,
    0x0000ffff0000ffffUL, 0xffff0000ffff0000UL,
    0x33cc33cc33cc33ccUL, 0x33cc33cc33cc33ccUL,
    0x33cc33cc33cc33ccUL, 0x33cc33cc33cc33ccUL,
    0xf00ff00f0ff00ff0UL, 0x0ff00ff0f00ff00fUL,
    0xf00ff00f0ff00ff0UL, 0x0ff00ff0f00ff00fUL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0x6969696996969696UL, 0x6969696996969696UL,
    0x6969696996969696UL, 0x6969696996969696UL,
    0x5a5a5a5a5a5a5a5aUL, 0x5a5a5a5a5a5a5a5aUL,
    0xa5a5a5a5a5a5a5a5UL, 0xa5a5a5a5a5a5a5a5UL,
    0xa5a5a5a55a5a5a5aUL, 0xa5a5a5a55a5a5a5aUL,
    0x5a5a5a5aa5a5a5a5UL, 0x5a5a5a5aa5a5a5a5UL,
    0xaaaa55555555aaaaUL, 0x5555aaaaaaaa5555UL,
    0xaaaa55555555aaaaUL, 0x5555aaaaaaaa5555UL,
    0x0ff00ff00ff00ff0UL, 0xf00ff00ff00ff00fUL,
    0x0ff00ff00ff00ff0UL, 0xf00ff00ff00ff00fUL,
    0x0f0ff0f00f0ff0f0UL, 0xf0f00f0ff0f00f0fUL,
    0xf0f00f0ff0f00f0fUL, 0x0f0ff0f00f0ff0f0UL,
    0x5aa55aa5a55aa55aUL, 0x5aa55aa5a55aa55aUL,
    0xa55aa55a5aa55aa5UL, 0xa55aa55a5aa55aa5UL,
    0x3cc33cc3c33cc33cUL, 0xc33cc33c3cc33cc3UL,
    0xc33cc33c3cc33cc3UL, 0x3cc33cc3c33cc33cUL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0x0000ffff0000ffffUL, 0xffff0000ffff0000UL,
    0xffff0000ffff0000UL, 0x0000ffff0000ffffUL,
    0xcc33cc33cc33cc33UL, 0xcc33cc33cc33cc33UL,
    0xcc33cc33cc33cc33UL, 0xcc33cc33cc33cc33UL,
    0xf00ff00f0ff00ff0UL, 0x0ff00ff0f00ff00fUL,
    0xf00ff00f0ff00ff0UL, 0x0ff00ff0f00ff00fUL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0x9696969669696969UL, 0x9696969669696969UL,
    0x9696969669696969UL, 0x9696969669696969UL,
    0x5a5a5a5a5a5a5a5aUL, 0x5a5a5a5a5a5a5a5aUL,
    0xa5a5a5a5a5a5a5a5UL, 0xa5a5a5a5a5a5a5a5UL,
    0x5a5a5a5aa5a5a5a5UL, 0x5a5a5a5aa5a5a5a5UL,
    0xa5a5a5a55a5a5a5aUL, 0xa5a5a5a55a5a5a5aUL,
    0xaaaa55555555aaaaUL, 0x5555aaaaaaaa5555UL,
    0xaaaa55555555aaaaUL, 0x5555aaaaaaaa5555UL,
    0xf00ff00ff00ff00fUL, 0x0ff00ff00ff00ff0UL,
    0xf00ff00ff00ff00fUL, 0x0ff00ff00ff00ff0UL,
    0x0f0ff0f00f0ff0f0UL, 0xf0f00f0ff0f00f0fUL,
    0xf0f00f0ff0f00f0fUL, 0x0f0ff0f00f0ff0f0UL,
    0xa55aa55a5aa55aa5UL, 0xa55aa55a5aa55aa5UL,
    0x5aa55aa5a55aa55aUL, 0x5aa55aa5a55aa55aUL,
    0xc33cc33c3cc33cc3UL, 0x3cc33cc3c33cc33cUL,
    0x3cc33cc3c33cc33cUL, 0xc33cc33c3cc33cc3UL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0x0000ffff0000ffffUL, 0xffff0000ffff0000UL,
    0xffff0000ffff0000UL, 0x0000ffff0000ffffUL,
    0xcc33cc33cc33cc33UL, 0xcc33cc33cc33cc33UL,
    0xcc33cc33cc33cc33UL, 0xcc33cc33cc33cc33UL,
    0xf00ff00f0ff00ff0UL, 0x0ff00ff0f00ff00fUL,
    0xf00ff00f0ff00ff0UL, 0x0ff00ff0f00ff00fUL,
    0x00000000ffffffffUL, 0x00000000ffffffffUL,
    0x00000000ffffffffUL, 0x00000000ffffffffUL,
    0x9696969669696969UL, 0x9696969669696969UL,
    0x9696969669696969UL, 0x9696969669696969UL,
    0xa5a5a5a5a5a5a5a5UL, 0xa5a5a5a5a5a5a5a5UL,
    0x5a5a5a5a5a5a5a5aUL, 0x5a5a5a5a5a5a5a5aUL,
    0xa5a5a5a55a5a5a5aUL, 0xa5a5a5a55a5a5a5aUL,
    0x5a5a5a5aa5a5a5a5UL, 0x5a5a5a5aa5a5a5a5UL,
    0x5555aaaaaaaa5555UL, 0xaaaa55555555aaaaUL,
    0x5555aaaaaaaa5555UL, 0xaaaa55555555aaaaUL,
    0x0ff00ff00ff00ff0UL, 0xf00ff00ff00ff00fUL,
    0x0ff00ff00ff00ff0UL, 0xf00ff00ff00ff00fUL,
    0x0f0ff0f00f0ff0f0UL, 0xf0f00f0ff0f00f0fUL,
    0xf0f00f0ff0f00f0fUL, 0x0f0ff0f00f0ff0f0UL,
    0x5aa55aa5a55aa55aUL, 0x5aa55aa5a55aa55aUL,
    0xa55aa55a5aa55aa5UL, 0xa55aa55a5aa55aa5UL,
    0xc33cc33c3cc33cc3UL, 0x3cc33cc3c33cc33cUL,
    0x3cc33cc3c33cc33cUL, 0xc33cc33c3cc33cc3UL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0xffff0000ffff0000UL, 0x0000ffff0000ffffUL,
    0x0000ffff0000ffffUL, 0xffff0000ffff0000UL,
    0x33cc33cc33cc33ccUL, 0x33cc33cc33cc33ccUL,
    0x33cc33cc33cc33ccUL, 0x33cc33cc33cc33ccUL,
    0xf00ff00f0ff00ff0UL, 0x0ff00ff0f00ff00fUL,
    0xf00ff00f0ff00ff0UL, 0x0ff00ff0f00ff00fUL,
    0x00000000ffffffffUL, 0x00000000ffffffffUL,
    0x00000000ffffffffUL, 0x00000000ffffffffUL,
    0x6969696996969696UL, 0x6969696996969696UL,
    0x6969696996969696UL, 0x6969696996969696UL,
    0xa5a5a5a5a5a5a5a5UL, 0xa5a5a5a5a5a5a5a5UL,
    0x5a5a5a5a5a5a5a5aUL, 0x5a5a5a5a5a5a5a5aUL,
    0x5a5a5a5aa5a5a5a5UL, 0x5a5a5a5aa5a5a5a5UL,
    0xa5a5a5a55a5a5a5aUL, 0xa5a5a5a55a5a5a5aUL,
    0x5555aaaaaaaa5555UL, 0xaaaa55555555aaaaUL,
    0x5555aaaaaaaa5555UL, 0xaaaa55555555aaaaUL,
    0xf00ff00ff00ff00fUL, 0x0ff00ff00ff00ff0UL,
    0xf00ff00ff00ff00fUL, 0x0ff00ff00ff00ff0UL,
    0x0f0ff0f00f0ff0f0UL, 0xf0f00f0ff0f00f0fUL,
    0xf0f00f0ff0f00f0fUL, 0x0f0ff0f00f0ff0f0UL,
    0xa55aa55a5aa55aa5UL, 0xa55aa55a5aa55aa5UL,
    0x5aa55aa5a55aa55aUL, 0x5aa55aa5a55aa55aUL,
    0x3cc33cc3c33cc33cUL, 0xc33cc33c3cc33cc3UL,
    0xc33cc33c3cc33cc3UL, 0x3cc33cc3c33cc33cUL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0xffff0000ffff0000UL, 0x0000ffff0000ffffUL,
    0x0000ffff0000ffffUL, 0xffff0000ffff0000UL,
    0x33cc33cc33cc33ccUL, 0x33cc33cc33cc33ccUL,
    0x33cc33cc33cc33ccUL, 0x33cc33cc33cc33ccUL,
    0x0ff00ff0f00ff00fUL, 0xf00ff00f0ff00ff0UL,
    0x0ff00ff0f00ff00fUL, 0xf00ff00f0ff00ff0UL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0x6969696996969696UL, 0x6969696996969696UL,
    0x6969696996969696UL, 0x6969696996969696UL,
    0xa5a5a5a5a5a5a5a5UL, 0xa5a5a5a5a5a5a5a5UL,
    0x5a5a5a5a5a5a5a5aUL, 0x5a5a5a5a5a5a5a5aUL,
    0xa5a5a5a55a5a5a5aUL, 0xa5a5a5a55a5a5a5aUL,
    0x5a5a5a5aa5a5a5a5UL, 0x5a5a5a5aa5a5a5a5UL,
    0xaaaa55555555aaaaUL, 0x5555aaaaaaaa5555UL,
    0xaaaa55555555aaaaUL, 0x5555aaaaaaaa5555UL,
    0xf00ff00ff00ff00fUL, 0x0ff00ff00ff00ff0UL,
    0xf00ff00ff00ff00fUL, 0x0ff00ff00ff00ff0UL,
    0xf0f00f0ff0f00f0fUL, 0x0f0ff0f00f0ff0f0UL,
    0x0f0ff0f00f0ff0f0UL, 0xf0f00f0ff0f00f0fUL,
    0x5aa55aa5a55aa55aUL, 0x5aa55aa5a55aa55aUL,
    0xa55aa55a5aa55aa5UL, 0xa55aa55a5aa55aa5UL,
    0x3cc33cc3c33cc33cUL, 0xc33cc33c3cc33cc3UL,
    0xc33cc33c3cc33cc3UL, 0x3cc33cc3c33cc33cUL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0x0000ffff0000ffffUL, 0xffff0000ffff0000UL,
    0xffff0000ffff0000UL, 0x0000ffff0000ffffUL,
    0xcc33cc33cc33cc33UL, 0xcc33cc33cc33cc33UL,
    0xcc33cc33cc33cc33UL, 0xcc33cc33cc33cc33UL,
    0x0ff00ff0f00ff00fUL, 0xf00ff00f0ff00ff0UL,
    0x0ff00ff0f00ff00fUL, 0xf00ff00f0ff00ff0UL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0x9696969669696969UL, 0x9696969669696969UL,
    0x9696969669696969UL, 0x9696969669696969UL,
    0xa5a5a5a5a5a5a5a5UL, 0xa5a5a5a5a5a5a5a5UL,
    0x5a5a5a5a5a5a5a5aUL, 0x5a5a5a5a5a5a5a5aUL,
    0x5a5a5a5aa5a5a5a5UL, 0x5a5a5a5aa5a5a5a5UL,
    0xa5a5a5a55a5a5a5aUL, 0xa5a5a5a55a5a5a5aUL,
    0xaaaa55555555aaaaUL, 0x5555aaaaaaaa5555UL,
    0xaaaa55555555aaaaUL, 0x5555aaaaaaaa5555UL,
    0x0ff00ff00ff00ff0UL, 0xf00ff00ff00ff00fUL,
    0x0ff00ff00ff00ff0UL, 0xf00ff00ff00ff00fUL,
    0xf0f00f0ff0f00f0fUL, 0x0f0ff0f00f0ff0f0UL,
    0x0f0ff0f00f0ff0f0UL, 0xf0f00f0ff0f00f0fUL,
    0xa55aa55a5aa55aa5UL, 0xa55aa55a5aa55aa5UL,
    0x5aa55aa5a55aa55aUL, 0x5aa55aa5a55aa55aUL,
    0xc33cc33c3cc33cc3UL, 0x3cc33cc3c33cc33cUL,
    0x3cc33cc3c33cc33cUL, 0xc33cc33c3cc33cc3UL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0x0000ffff0000ffffUL, 0xffff0000ffff0000UL,
    0xffff0000ffff0000UL, 0x0000ffff0000ffffUL,
    0xcc33cc33cc33cc33UL, 0xcc33cc33cc33cc33UL,
    0xcc33cc33cc33cc33UL, 0xcc33cc33cc33cc33UL,
    0x0ff00ff0f00ff00fUL, 0xf00ff00f0ff00ff0UL,
    0x0ff00ff0f00ff00fUL, 0xf00ff00f0ff00ff0UL,
    0x00000000ffffffffUL, 0x00000000ffffffffUL,
    0x00000000ffffffffUL, 0x00000000ffffffffUL,
    0x9696969669696969UL, 0x9696969669696969UL,
    0x9696969669696969UL, 0x9696969669696969UL,
    0x5a5a5a5a5a5a5a5aUL, 0x5a5a5a5a5a5a5a5aUL,
    0xa5a5a5a5a5a5a5a5UL, 0xa5a5a5a5a5a5a5a5UL,
    0xa5a5a5a55a5a5a5aUL, 0xa5a5a5a55a5a5a5aUL,
    0x5a5a5a5aa5a5a5a5UL, 0x5a5a5a5aa5a5a5a5UL,
    0x5555aaaaaaaa5555UL, 0xaaaa55555555aaaaUL,
    0x5555aaaaaaaa5555UL, 0xaaaa55555555aaaaUL,
    0xf00ff00ff00ff00fUL, 0x0ff00ff00ff00ff0UL,
    0xf00ff00ff00ff00fUL, 0x0ff00ff00ff00ff0UL,
    0xf0f00f0ff0f00f0fUL, 0x0f0ff0f00f0ff0f0UL,
    0x0f0ff0f00f0ff0f0UL, 0xf0f00f0ff0f00f0fUL,
    0x5aa55aa5a55aa55aUL, 0x5aa55aa5a55aa55aUL,
    0xa55aa55a5aa55aa5UL, 0xa55aa55a5aa55aa5UL,
    0xc33cc33c3cc33cc3UL, 0x3cc33cc3c33cc33cUL,
    0x3cc33cc3c33cc33cUL, 0xc33cc33c3cc33cc3UL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0xffff0000ffff0000UL, 0x0000ffff0000ffffUL,
    0x0000ffff0000ffffUL, 0xffff0000ffff0000UL,
    0x33cc33cc33cc33ccUL, 0x33cc33cc33cc33ccUL,
    0x33cc33cc33cc33ccUL, 0x33cc33cc33cc33ccUL,
    0x0ff00ff0f00ff00fUL, 0xf00ff00f0ff00ff0UL,
    0x0ff00ff0f00ff00fUL, 0xf00ff00f0ff00ff0UL,
    0x00000000ffffffffUL, 0x00000000ffffffffUL,
    0x00000000ffffffffUL, 0x00000000ffffffffUL,
    0x6969696996969696UL, 0x6969696996969696UL,
    0x6969696996969696UL, 0x6969696996969696UL,
    0x5a5a5a5a5a5a5a5aUL, 0x5a5a5a5a5a5a5a5aUL,
    0xa5a5a5a5a5a5a5a5UL, 0xa5a5a5a5a5a5a5a5UL,
    0x5a5a5a5aa5a5a5a5UL, 0x5a5a5a5aa5a5a5a5UL,
    0xa5a5a5a55a5a5a5aUL, 0xa5a5a5a55a5a5a5aUL,
    0x5555aaaaaaaa5555UL, 0xaaaa55555555aaaaUL,
    0x5555aaaaaaaa5555UL, 0xaaaa55555555aaaaUL,
    0x0ff00ff00ff00ff0UL, 0xf00ff00ff00ff00fUL,
    0x0ff00ff00ff00ff0UL, 0xf00ff00ff00ff00fUL,
    0xf0f00f0ff0f00f0fUL, 0x0f0ff0f00f0ff0f0UL,
    0x0f0ff0f00f0ff0f0UL, 0xf0f00f0ff0f00f0fUL,
    0x5aa55aa5a55aa55aUL, 0x5aa55aa5a55aa55aUL,
    0xa55aa55a5aa55aa5UL, 0xa55aa55a5aa55aa5UL,
    0x3cc33cc3c33cc33cUL, 0xc33cc33c3cc33cc3UL,
    0xc33cc33c3cc33cc3UL, 0x3cc33cc3c33cc33cUL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0xffff0000ffff0000UL, 0x0000ffff0000ffffUL,
    0x0000ffff0000ffffUL, 0xffff0000ffff0000UL,
    0x33cc33cc33cc33ccUL, 0x33cc33cc33cc33ccUL,
    0x33cc33cc33cc33ccUL, 0x33cc33cc33cc33ccUL,
    0x0ff00ff0f00ff00fUL, 0xf00ff00f0ff00ff0UL,
    0x0ff00ff0f00ff00fUL, 0xf00ff00f0ff00ff0UL,
    0x00000000ffffffffUL, 0x00000000ffffffffUL,
    0x00000000ffffffffUL, 0x00000000ffffffffUL,
    0x6969696996969696UL, 0x6969696996969696UL,
    0x6969696996969696UL, 0x6969696996969696UL,
    0x5a5a5a5a5a5a5a5aUL, 0x5a5a5a5a5a5a5a5aUL,
    0xa5a5a5a5a5a5a5a5UL, 0xa5a5a5a5a5a5a5a5UL,
    0x5a5a5a5aa5a5a5a5UL, 0x5a5a5a5aa5a5a5a5UL,
    0xa5a5a5a55a5a5a5aUL, 0xa5a5a5a55a5a5a5aUL,
    0xaaaa55555555aaaaUL, 0x5555aaaaaaaa5555UL,
    0xaaaa55555555aaaaUL, 0x5555aaaaaaaa5555UL,
    0xf00ff00ff00ff00fUL, 0x0ff00ff00ff00ff0UL,
    0xf00ff00ff00ff00fUL, 0x0ff00ff00ff00ff0UL,
    0xf0f00f0ff0f00f0fUL, 0x0f0ff0f00f0ff0f0UL,
    0x0f0ff0f00f0ff0f0UL, 0xf0f00f0ff0f00f0fUL,
    0xa55aa55a5aa55aa5UL, 0xa55aa55a5aa55aa5UL,
    0x5aa55aa5a55aa55aUL, 0x5aa55aa5a55aa55aUL,
    0x3cc33cc3c33cc33cUL, 0xc33cc33c3cc33cc3UL,
    0xc33cc33c3cc33cc3UL, 0x3cc33cc3c33cc33cUL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0x0000ffff0000ffffUL, 0xffff0000ffff0000UL,
    0xffff0000ffff0000UL, 0x0000ffff0000ffffUL,
    0xcc33cc33cc33cc33UL, 0xcc33cc33cc33cc33UL,
    0xcc33cc33cc33cc33UL, 0xcc33cc33cc33cc33UL,
    0x0ff00ff0f00ff00fUL, 0xf00ff00f0ff00ff0UL,
    0x0ff00ff0f00ff00fUL, 0xf00ff00f0ff00ff0UL,
    0x00000000ffffffffUL, 0x00000000ffffffffUL,
    0x00000000ffffffffUL, 0x00000000ffffffffUL,
    0x9696969669696969UL, 0x9696969669696969UL,
    0x9696969669696969UL, 0x9696969669696969UL,
    0x5a5a5a5a5a5a5a5aUL, 0x5a5a5a5a5a5a5a5aUL,
    0xa5a5a5a5a5a5a5a5UL, 0xa5a5a5a5a5a5a5a5UL,
    0xa5a5a5a55a5a5a5aUL, 0xa5a5a5a55a5a5a5aUL,
    0x5a5a5a5aa5a5a5a5UL, 0x5a5a5a5aa5a5a5a5UL,
    0xaaaa55555555aaaaUL, 0x5555aaaaaaaa5555UL,
    0xaaaa55555555aaaaUL, 0x5555aaaaaaaa5555UL,
    0x0ff00ff00ff00ff0UL, 0xf00ff00ff00ff00fUL,
    0x0ff00ff00ff00ff0UL, 0xf00ff00ff00ff00fUL,
    0xf0f00f0ff0f00f0fUL, 0x0f0ff0f00f0ff0f0UL,
    0x0f0ff0f00f0ff0f0UL, 0xf0f00f0ff0f00f0fUL,
    0x5aa55aa5a55aa55aUL, 0x5aa55aa5a55aa55aUL,
    0xa55aa55a5aa55aa5UL, 0xa55aa55a5aa55aa5UL,
    0xc33cc33c3cc33cc3UL, 0x3cc33cc3c33cc33cUL,
    0x3cc33cc3c33cc33cUL, 0xc33cc33c3cc33cc3UL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0x0000ffff0000ffffUL, 0xffff0000ffff0000UL,
    0xffff0000ffff0000UL, 0x0000ffff0000ffffUL,
    0xcc33cc33cc33cc33UL, 0xcc33cc33cc33cc33UL,
    0xcc33cc33cc33cc33UL, 0xcc33cc33cc33cc33UL,
    0x0ff00ff0f00ff00fUL, 0xf00ff00f0ff00ff0UL,
    0x0ff00ff0f00ff00fUL, 0xf00ff00f0ff00ff0UL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0x9696969669696969UL, 0x9696969669696969UL,
    0x9696969669696969UL, 0x9696969669696969UL,
    0xa5a5a5a5a5a5a5a5UL, 0xa5a5a5a5a5a5a5a5UL,
    0x5a5a5a5a5a5a5a5aUL, 0x5a5a5a5a5a5a5a5aUL,
    0x5a5a5a5aa5a5a5a5UL, 0x5a5a5a5aa5a5a5a5UL,
    0xa5a5a5a55a5a5a5aUL, 0xa5a5a5a55a5a5a5aUL,
    0x5555aaaaaaaa5555UL, 0xaaaa55555555aaaaUL,
    0x5555aaaaaaaa5555UL, 0xaaaa55555555aaaaUL,
    0xf00ff00ff00ff00fUL, 0x0ff00ff00ff00ff0UL,
    0xf00ff00ff00ff00fUL, 0x0ff00ff00ff00ff0UL,
    0xf0f00f0ff0f00f0fUL, 0x0f0ff0f00f0ff0f0UL,
    0x0f0ff0f00f0ff0f0UL, 0xf0f00f0ff0f00f0fUL,
    0xa55aa55a5aa55aa5UL, 0xa55aa55a5aa55aa5UL,
    0x5aa55aa5a55aa55aUL, 0x5aa55aa5a55aa55aUL,
    0xc33cc33c3cc33cc3UL, 0x3cc33cc3c33cc33cUL,
    0x3cc33cc3c33cc33cUL, 0xc33cc33c3cc33cc3UL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0xffff0000ffff0000UL, 0x0000ffff0000ffffUL,
    0x0000ffff0000ffffUL, 0xffff0000ffff0000UL,
    0x33cc33cc33cc33ccUL, 0x33cc33cc33cc33ccUL,
    0x33cc33cc33cc33ccUL, 0x33cc33cc33cc33ccUL,
    0x0ff00ff0f00ff00fUL, 0xf00ff00f0ff00ff0UL,
    0x0ff00ff0f00ff00fUL, 0xf00ff00f0ff00ff0UL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0x6969696996969696UL, 0x6969696996969696UL,
    0x6969696996969696UL, 0x6969696996969696UL,
    0xa5a5a5a5a5a5a5a5UL, 0xa5a5a5a5a5a5a5a5UL,
    0x5a5a5a5a5a5a5a5aUL, 0x5a5a5a5a5a5a5a5aUL,
    0xa5a5a5a55a5a5a5aUL, 0xa5a5a5a55a5a5a5aUL,
    0x5a5a5a5aa5a5a5a5UL, 0x5a5a5a5aa5a5a5a5UL,
    0x5555aaaaaaaa5555UL, 0xaaaa55555555aaaaUL,
    0x5555aaaaaaaa5555UL, 0xaaaa55555555aaaaUL,
    0x0ff00ff00ff00ff0UL, 0xf00ff00ff00ff00fUL,
    0x0ff00ff00ff00ff0UL, 0xf00ff00ff00ff00fUL,
    0xf0f00f0ff0f00f0fUL, 0x0f0ff0f00f0ff0f0UL,
    0x0f0ff0f00f0ff0f0UL, 0xf0f00f0ff0f00f0fUL,
    0x5aa55aa5a55aa55aUL, 0x5aa55aa5a55aa55aUL,
    0xa55aa55a5aa55aa5UL, 0xa55aa55a5aa55aa5UL,
    0x3cc33cc3c33cc33cUL, 0xc33cc33c3cc33cc3UL,
    0xc33cc33c3cc33cc3UL, 0x3cc33cc3c33cc33cUL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0xffff0000ffff0000UL, 0x0000ffff0000ffffUL,
    0x0000ffff0000ffffUL, 0xffff0000ffff0000UL,
    0x33cc33cc33cc33ccUL, 0x33cc33cc33cc33ccUL,
    0x33cc33cc33cc33ccUL, 0x33cc33cc33cc33ccUL,
    0xf00ff00f0ff00ff0UL, 0x0ff00ff0f00ff00fUL,
    0xf00ff00f0ff00ff0UL, 0x0ff00ff0f00ff00fUL,
    0x00000000ffffffffUL, 0x00000000ffffffffUL,
    0x00000000ffffffffUL, 0x00000000ffffffffUL,
    0x6969696996969696UL, 0x6969696996969696UL,
    0x6969696996969696UL, 0x6969696996969696UL,
    0xa5a5a5a5a5a5a5a5UL, 0xa5a5a5a5a5a5a5a5UL,
    0x5a5a5a5a5a5a5a5aUL, 0x5a5a5a5a5a5a5a5aUL,
    0x5a5a5a5aa5a5a5a5UL, 0x5a5a5a5aa5a5a5a5UL,
    0xa5a5a5a55a5a5a5aUL, 0xa5a5a5a55a5a5a5aUL,
    0xaaaa55555555aaaaUL, 0x5555aaaaaaaa5555UL,
    0xaaaa55555555aaaaUL, 0x5555aaaaaaaa5555UL,
    0x0ff00ff00ff00ff0UL, 0xf00ff00ff00ff00fUL,
    0x0ff00ff00ff00ff0UL, 0xf00ff00ff00ff00fUL,
    0x0f0ff0f00f0ff0f0UL, 0xf0f00f0ff0f00f0fUL,
    0xf0f00f0ff0f00f0fUL, 0x0f0ff0f00f0ff0f0UL,
    0xa55aa55a5aa55aa5UL, 0xa55aa55a5aa55aa5UL,
    0x5aa55aa5a55aa55aUL, 0x5aa55aa5a55aa55aUL,
    0x3cc33cc3c33cc33cUL, 0xc33cc33c3cc33cc3UL,
    0xc33cc33c3cc33cc3UL, 0x3cc33cc3c33cc33cUL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0x0000ffff0000ffffUL, 0xffff0000ffff0000UL,
    0xffff0000ffff0000UL, 0x0000ffff0000ffffUL,
    0xcc33cc33cc33cc33UL, 0xcc33cc33cc33cc33UL,
    0xcc33cc33cc33cc33UL, 0xcc33cc33cc33cc33UL,
    0xf00ff00f0ff00ff0UL, 0x0ff00ff0f00ff00fUL,
    0xf00ff00f0ff00ff0UL, 0x0ff00ff0f00ff00fUL,
    0x00000000ffffffffUL, 0x00000000ffffffffUL,
    0x00000000ffffffffUL, 0x00000000ffffffffUL,
    0x9696969669696969UL, 0x9696969669696969UL,
    0x9696969669696969UL, 0x9696969669696969UL,
    0xa5a5a5a5a5a5a5a5UL, 0xa5a5a5a5a5a5a5a5UL,
    0x5a5a5a5a5a5a5a5aUL, 0x5a5a5a5a5a5a5a5aUL,
    0xa5a5a5a55a5a5a5aUL, 0xa5a5a5a55a5a5a5aUL,
    0x5a5a5a5aa5a5a5a5UL, 0x5a5a5a5aa5a5a5a5UL,
    0xaaaa55555555aaaaUL, 0x5555aaaaaaaa5555UL,
    0xaaaa55555555aaaaUL, 0x5555aaaaaaaa5555UL,
    0xf00ff00ff00ff00fUL, 0x0ff00ff00ff00ff0UL,
    0xf00ff00ff00ff00fUL, 0x0ff00ff00ff00ff0UL,
    0x0f0ff0f00f0ff0f0UL, 0xf0f00f0ff0f00f0fUL,
    0xf0f00f0ff0f00f0fUL, 0x0f0ff0f00f0ff0f0UL,
    0x5aa55aa5a55aa55aUL, 0x5aa55aa5a55aa55aUL,
    0xa55aa55a5aa55aa5UL, 0xa55aa55a5aa55aa5UL,
    0xc33cc33c3cc33cc3UL, 0x3cc33cc3c33cc33cUL,
    0x3cc33cc3c33cc33cUL, 0xc33cc33c3cc33cc3UL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0x0000ffff0000ffffUL, 0xffff0000ffff0000UL,
    0xffff0000ffff0000UL, 0x0000ffff0000ffffUL,
    0xcc33cc33cc33cc33UL, 0xcc33cc33cc33cc33UL,
    0xcc33cc33cc33cc33UL, 0xcc33cc33cc33cc33UL,
    0xf00ff00f0ff00ff0UL, 0x0ff00ff0f00ff00fUL,
    0xf00ff00f0ff00ff0UL, 0x0ff00ff0f00ff00fUL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0x9696969669696969UL, 0x9696969669696969UL,
    0x9696969669696969UL, 0x9696969669696969UL,
    0x5a5a5a5a5a5a5a5aUL, 0x5a5a5a5a5a5a5a5aUL,
    0xa5a5a5a5a5a5a5a5UL, 0xa5a5a5a5a5a5a5a5UL,
    0x5a5a5a5aa5a5a5a5UL, 0x5a5a5a5aa5a5a5a5UL,
    0xa5a5a5a55a5a5a5aUL, 0xa5a5a5a55a5a5a5aUL,
    0x5555aaaaaaaa5555UL, 0xaaaa55555555aaaaUL,
    0x5555aaaaaaaa5555UL, 0xaaaa55555555aaaaUL,
    0x0ff00ff00ff00ff0UL, 0xf00ff00ff00ff00fUL,
    0x0ff00ff00ff00ff0UL, 0xf00ff00ff00ff00fUL,
    0x0f0ff0f00f0ff0f0UL, 0xf0f00f0ff0f00f0fUL,
    0xf0f00f0ff0f00f0fUL, 0x0f0ff0f00f0ff0f0UL,
    0xa55aa55a5aa55aa5UL, 0xa55aa55a5aa55aa5UL,
    0x5aa55aa5a55aa55aUL, 0x5aa55aa5a55aa55aUL,
    0xc33cc33c3cc33cc3UL, 0x3cc33cc3c33cc33cUL,
    0x3cc33cc3c33cc33cUL, 0xc33cc33c3cc33cc3UL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0xa5a55a5aa5a55a5aUL, 0xa5a55a5aa5a55a5aUL,
    0xffff0000ffff0000UL, 0x0000ffff0000ffffUL,
    0x0000ffff0000ffffUL, 0xffff0000ffff0000UL,
    0x33cc33cc33cc33ccUL, 0x33cc33cc33cc33ccUL,
    0x33cc33cc33cc33ccUL, 0x33cc33cc33cc33ccUL,
    0xf00ff00f0ff00ff0UL, 0x0ff00ff0f00ff00fUL,
    0xf00ff00f0ff00ff0UL, 0x0ff00ff0f00ff00fUL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0x6969696996969696UL, 0x6969696996969696UL,
    0x6969696996969696UL, 0x6969696996969696UL,
    0x5a5a5a5a5a5a5a5aUL, 0x5a5a5a5a5a5a5a5aUL,
    0xa5a5a5a5a5a5a5a5UL, 0xa5a5a5a5a5a5a5a5UL,
    0xa5a5a5a55a5a5a5aUL, 0xa5a5a5a55a5a5a5aUL,
    0x5a5a5a5aa5a5a5a5UL, 0x5a5a5a5aa5a5a5a5UL,
    0x5555aaaaaaaa5555UL, 0xaaaa55555555aaaaUL,
    0x5555aaaaaaaa5555UL, 0xaaaa55555555aaaaUL,
    0xf00ff00ff00ff00fUL, 0x0ff00ff00ff00ff0UL,
    0xf00ff00ff00ff00fUL, 0x0ff00ff00ff00ff0UL,
    0x0f0ff0f00f0ff0f0UL, 0xf0f00f0ff0f00f0fUL,
    0xf0f00f0ff0f00f0fUL, 0x0f0ff0f00f0ff0f0UL,
};

XALIGNED(16) static const word64 L_mc_aff_consts_neon[] = {
    0x6969969669699696UL, 0x6969969669699696UL,
    0x6969969669699696UL, 0x6969969669699696UL,
    0x9966669966999966UL, 0x9966669966999966UL,
    0x9966669966999966UL, 0x9966669966999966UL,
    0x9966669966999966UL, 0x9966669966999966UL,
    0x9966669966999966UL, 0x9966669966999966UL,
    0xff0000ff00ffff00UL, 0xff0000ff00ffff00UL,
    0xff0000ff00ffff00UL, 0xff0000ff00ffff00UL,
    0xcc3333cccc3333ccUL, 0xcc3333cccc3333ccUL,
    0xcc3333cccc3333ccUL, 0xcc3333cccc3333ccUL,
    0x9966669966999966UL, 0x9966669966999966UL,
    0x9966669966999966UL, 0x9966669966999966UL,
    0x6666666666666666UL, 0x6666666666666666UL,
    0x6666666666666666UL, 0x6666666666666666UL,
    0xa55aa55aa55aa55aUL, 0xa55aa55aa55aa55aUL,
    0xa55aa55aa55aa55aUL, 0xa55aa55aa55aa55aUL,
    0xcccc33333333ccccUL, 0xcccc33333333ccccUL,
    0xcccc33333333ccccUL, 0xcccc33333333ccccUL,
    0x5a5a5a5a5a5a5a5aUL, 0x5a5a5a5a5a5a5a5aUL,
    0x5a5a5a5a5a5a5a5aUL, 0x5a5a5a5a5a5a5a5aUL,
    0x55aaaa55aa5555aaUL, 0x55aaaa55aa5555aaUL,
    0x55aaaa55aa5555aaUL, 0x55aaaa55aa5555aaUL,
    0x0ff0f00ff00f0ff0UL, 0x0ff0f00ff00f0ff0UL,
    0x0ff0f00ff00f0ff0UL, 0x0ff0f00ff00f0ff0UL,
    0x5aa55aa5a55aa55aUL, 0x5aa55aa5a55aa55aUL,
    0x5aa55aa5a55aa55aUL, 0x5aa55aa5a55aa55aUL,
    0xa55a5aa55aa5a55aUL, 0xa55a5aa55aa5a55aUL,
    0xa55a5aa55aa5a55aUL, 0xa55a5aa55aa5a55aUL,
    0x6969696996969696UL, 0x6969696996969696UL,
    0x6969696996969696UL, 0x6969696996969696UL,
    0x5aa55aa5a55aa55aUL, 0x5aa55aa5a55aa55aUL,
    0x5aa55aa5a55aa55aUL, 0x5aa55aa5a55aa55aUL,
    0x9999999966666666UL, 0x6666666699999999UL,
    0x9999999966666666UL, 0x6666666699999999UL,
    0x3c3cc3c3c3c33c3cUL, 0xc3c33c3c3c3cc3c3UL,
    0x3c3cc3c3c3c33c3cUL, 0xc3c33c3c3c3cc3c3UL,
    0xffff0000ffff0000UL, 0x0000ffff0000ffffUL,
    0xffff0000ffff0000UL, 0x0000ffff0000ffffUL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0xcc33cc3333cc33ccUL, 0x33cc33cccc33cc33UL,
    0xcc33cc3333cc33ccUL, 0x33cc33cccc33cc33UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x3c3c3c3c3c3c3c3cUL, 0x3c3c3c3c3c3c3c3cUL,
    0x3c3c3c3c3c3c3c3cUL, 0x3c3c3c3c3c3c3c3cUL,
    0xaa5555aaaa5555aaUL, 0xaa5555aaaa5555aaUL,
    0xaa5555aaaa5555aaUL, 0xaa5555aaaa5555aaUL,
    0xc33c3cc33cc3c33cUL, 0xc33c3cc33cc3c33cUL,
    0xc33c3cc33cc3c33cUL, 0xc33c3cc33cc3c33cUL,
    0x00ffff0000ffff00UL, 0xff0000ffff0000ffUL,
    0x00ffff0000ffff00UL, 0xff0000ffff0000ffUL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xa5a5a5a55a5a5a5aUL, 0xa5a5a5a55a5a5a5aUL,
    0x5a5a5a5aa5a5a5a5UL, 0x5a5a5a5aa5a5a5a5UL,
    0x0ff0f00ff00f0ff0UL, 0x0ff0f00ff00f0ff0UL,
    0xf00f0ff00ff0f00fUL, 0xf00f0ff00ff0f00fUL,
    0x9669966969966996UL, 0x6996699696699669UL,
    0x6996699696699669UL, 0x9669966969966996UL,
    0x0000ffffffff0000UL, 0xffff00000000ffffUL,
    0x0000ffffffff0000UL, 0xffff00000000ffffUL,
    0x33333333ccccccccUL, 0x33333333ccccccccUL,
    0x33333333ccccccccUL, 0x33333333ccccccccUL,
    0xa55a5aa55aa5a55aUL, 0x5aa5a55aa55a5aa5UL,
    0x5aa5a55aa55a5aa5UL, 0xa55a5aa55aa5a55aUL,
    0x00ffff0000ffff00UL, 0xff0000ffff0000ffUL,
    0xff0000ffff0000ffUL, 0x00ffff0000ffff00UL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0x0000000000000000UL,
    0xc33cc33cc33cc33cUL, 0xc33cc33cc33cc33cUL,
    0xc33cc33cc33cc33cUL, 0xc33cc33cc33cc33cUL,
    0x0f0ff0f00f0ff0f0UL, 0x0f0ff0f00f0ff0f0UL,
    0x0f0ff0f00f0ff0f0UL, 0x0f0ff0f00f0ff0f0UL,
    0xccccccccccccccccUL, 0xccccccccccccccccUL,
    0xccccccccccccccccUL, 0xccccccccccccccccUL,
    0xaaaa55555555aaaaUL, 0x5555aaaaaaaa5555UL,
    0xaaaa55555555aaaaUL, 0x5555aaaaaaaa5555UL,
    0xc33c3cc33cc3c33cUL, 0x3cc3c33cc33c3cc3UL,
    0xc33c3cc33cc3c33cUL, 0x3cc3c33cc33c3cc3UL,
    0x9966669966999966UL, 0x6699996699666699UL,
    0x9966669966999966UL, 0x6699996699666699UL,
    0x9966996699669966UL, 0x6699669966996699UL,
    0x6699669966996699UL, 0x9966996699669966UL,
    0x6969969669699696UL, 0x6969969669699696UL,
    0x6969969669699696UL, 0x6969969669699696UL,
    0xaa55aa5555aa55aaUL, 0xaa55aa5555aa55aaUL,
    0xaa55aa5555aa55aaUL, 0xaa55aa5555aa55aaUL,
    0x9966996699669966UL, 0x9966996699669966UL,
    0x6699669966996699UL, 0x6699669966996699UL,
    0x5aa5a55a5aa5a55aUL, 0xa55a5aa5a55a5aa5UL,
    0x5aa5a55a5aa5a55aUL, 0xa55a5aa5a55a5aa5UL,
    0xc3c3c3c33c3c3c3cUL, 0xc3c3c3c33c3c3c3cUL,
    0x3c3c3c3cc3c3c3c3UL, 0x3c3c3c3cc3c3c3c3UL,
    0x3cc33cc3c33cc33cUL, 0x3cc33cc3c33cc33cUL,
    0xc33cc33c3cc33cc3UL, 0xc33cc33c3cc33cc3UL,
    0x3333cccc3333ccccUL, 0x3333cccc3333ccccUL,
    0xcccc3333cccc3333UL, 0xcccc3333cccc3333UL,
    0x9999999966666666UL, 0x6666666699999999UL,
    0x6666666699999999UL, 0x9999999966666666UL,
    0xc33cc33cc33cc33cUL, 0x3cc33cc33cc33cc3UL,
    0xc33cc33cc33cc33cUL, 0x3cc33cc33cc33cc3UL,
    0x6666999999996666UL, 0x9999666666669999UL,
    0x9999666666669999UL, 0x6666999999996666UL,
    0xc33c3cc33cc3c33cUL, 0x3cc3c33cc33c3cc3UL,
    0xc33c3cc33cc3c33cUL, 0x3cc3c33cc33c3cc3UL,
    0x6699996699666699UL, 0x9966669966999966UL,
    0x6699996699666699UL, 0x9966669966999966UL,
    0x6699669966996699UL, 0x9966996699669966UL,
    0x9966996699669966UL, 0x6699669966996699UL,
    0x6969969669699696UL, 0x6969969669699696UL,
    0x6969969669699696UL, 0x6969969669699696UL,
    0x55aa55aaaa55aa55UL, 0x55aa55aaaa55aa55UL,
    0x55aa55aaaa55aa55UL, 0x55aa55aaaa55aa55UL,
    0x9966996699669966UL, 0x9966996699669966UL,
    0x6699669966996699UL, 0x6699669966996699UL,
    0x5aa5a55a5aa5a55aUL, 0xa55a5aa5a55a5aa5UL,
    0x5aa5a55a5aa5a55aUL, 0xa55a5aa5a55a5aa5UL,
    0xc3c3c3c33c3c3c3cUL, 0xc3c3c3c33c3c3c3cUL,
    0x3c3c3c3cc3c3c3c3UL, 0x3c3c3c3cc3c3c3c3UL,
    0xc33cc33c3cc33cc3UL, 0xc33cc33c3cc33cc3UL,
    0x3cc33cc3c33cc33cUL, 0x3cc33cc3c33cc33cUL,
    0x3333cccc3333ccccUL, 0x3333cccc3333ccccUL,
    0xcccc3333cccc3333UL, 0xcccc3333cccc3333UL,
    0x9999999966666666UL, 0x6666666699999999UL,
    0x6666666699999999UL, 0x9999999966666666UL,
    0xc33cc33cc33cc33cUL, 0x3cc33cc33cc33cc3UL,
    0xc33cc33cc33cc33cUL, 0x3cc33cc33cc33cc3UL,
    0x6666999999996666UL, 0x9999666666669999UL,
    0x9999666666669999UL, 0x6666999999996666UL,
    0x3c3cc3c3c3c33c3cUL, 0xc3c33c3c3c3cc3c3UL,
    0x3c3cc3c3c3c33c3cUL, 0xc3c33c3c3c3cc3c3UL,
    0x55555555aaaaaaaaUL, 0x55555555aaaaaaaaUL,
    0x55555555aaaaaaaaUL, 0x55555555aaaaaaaaUL,
    0xf00ff00f0ff00ff0UL, 0x0ff00ff0f00ff00fUL,
    0xf00ff00f0ff00ff0UL, 0x0ff00ff0f00ff00fUL,
    0x5aa55aa5a55aa55aUL, 0x5aa55aa5a55aa55aUL,
    0xa55aa55a5aa55aa5UL, 0xa55aa55a5aa55aa5UL,
    0x55aaaa55aa5555aaUL, 0x55aaaa55aa5555aaUL,
    0xaa5555aa55aaaa55UL, 0xaa5555aa55aaaa55UL,
    0xf00f0ff0f00f0ff0UL, 0xf00f0ff0f00f0ff0UL,
    0x0ff0f00f0ff0f00fUL, 0x0ff0f00f0ff0f00fUL,
    0x9669699696696996UL, 0x9669699696696996UL,
    0x9669699696696996UL, 0x9669699696696996UL,
    0xa55aa55aa55aa55aUL, 0x5aa55aa55aa55aa5UL,
    0x5aa55aa55aa55aa5UL, 0xa55aa55aa55aa55aUL,
    0x55555555aaaaaaaaUL, 0x55555555aaaaaaaaUL,
    0xaaaaaaaa55555555UL, 0xaaaaaaaa55555555UL,
    0xcccc33333333ccccUL, 0x3333cccccccc3333UL,
    0x3333cccccccc3333UL, 0xcccc33333333ccccUL,
    0x0000ffffffff0000UL, 0x0000ffffffff0000UL,
    0xffff00000000ffffUL, 0xffff00000000ffffUL,
    0xff0000ff00ffff00UL, 0x00ffff00ff0000ffUL,
    0xff0000ff00ffff00UL, 0x00ffff00ff0000ffUL,
    0x6996699669966996UL, 0x9669966996699669UL,
    0x9669966996699669UL, 0x6996699669966996UL,
    0x3c3cc3c3c3c33c3cUL, 0xc3c33c3c3c3cc3c3UL,
    0x3c3cc3c3c3c33c3cUL, 0xc3c33c3c3c3cc3c3UL,
    0x55555555aaaaaaaaUL, 0x55555555aaaaaaaaUL,
    0x55555555aaaaaaaaUL, 0x55555555aaaaaaaaUL,
    0x0ff00ff0f00ff00fUL, 0xf00ff00f0ff00ff0UL,
    0x0ff00ff0f00ff00fUL, 0xf00ff00f0ff00ff0UL,
    0xa55aa55a5aa55aa5UL, 0xa55aa55a5aa55aa5UL,
    0x5aa55aa5a55aa55aUL, 0x5aa55aa5a55aa55aUL,
    0xaa5555aa55aaaa55UL, 0xaa5555aa55aaaa55UL,
    0x55aaaa55aa5555aaUL, 0x55aaaa55aa5555aaUL,
    0x0ff0f00f0ff0f00fUL, 0x0ff0f00f0ff0f00fUL,
    0xf00f0ff0f00f0ff0UL, 0xf00f0ff0f00f0ff0UL,
    0x6996966969969669UL, 0x6996966969969669UL,
    0x6996966969969669UL, 0x6996966969969669UL,
    0xa55aa55aa55aa55aUL, 0x5aa55aa55aa55aa5UL,
    0x5aa55aa55aa55aa5UL, 0xa55aa55aa55aa55aUL,
    0xaaaaaaaa55555555UL, 0xaaaaaaaa55555555UL,
    0x55555555aaaaaaaaUL, 0x55555555aaaaaaaaUL,
    0xcccc33333333ccccUL, 0x3333cccccccc3333UL,
    0x3333cccccccc3333UL, 0xcccc33333333ccccUL,
    0x0000ffffffff0000UL, 0x0000ffffffff0000UL,
    0xffff00000000ffffUL, 0xffff00000000ffffUL,
    0xff0000ff00ffff00UL, 0x00ffff00ff0000ffUL,
    0xff0000ff00ffff00UL, 0x00ffff00ff0000ffUL,
    0x6996699669966996UL, 0x9669966996699669UL,
    0x9669966996699669UL, 0x6996699669966996UL,
    0x3c3cc3c3c3c33c3cUL, 0xc3c33c3c3c3cc3c3UL,
    0x3c3cc3c3c3c33c3cUL, 0xc3c33c3c3c3cc3c3UL,
    0xaaaaaaaa55555555UL, 0xaaaaaaaa55555555UL,
    0xaaaaaaaa55555555UL, 0xaaaaaaaa55555555UL,
    0x0ff00ff0f00ff00fUL, 0xf00ff00f0ff00ff0UL,
    0x0ff00ff0f00ff00fUL, 0xf00ff00f0ff00ff0UL,
    0x5aa55aa5a55aa55aUL, 0x5aa55aa5a55aa55aUL,
    0xa55aa55a5aa55aa5UL, 0xa55aa55a5aa55aa5UL,
    0xaa5555aa55aaaa55UL, 0xaa5555aa55aaaa55UL,
    0x55aaaa55aa5555aaUL, 0x55aaaa55aa5555aaUL,
    0xf00f0ff0f00f0ff0UL, 0xf00f0ff0f00f0ff0UL,
    0x0ff0f00f0ff0f00fUL, 0x0ff0f00f0ff0f00fUL,
    0x9669699696696996UL, 0x9669699696696996UL,
    0x9669699696696996UL, 0x9669699696696996UL,
    0xa55aa55aa55aa55aUL, 0x5aa55aa55aa55aa5UL,
    0x5aa55aa55aa55aa5UL, 0xa55aa55aa55aa55aUL,
    0x55555555aaaaaaaaUL, 0x55555555aaaaaaaaUL,
    0xaaaaaaaa55555555UL, 0xaaaaaaaa55555555UL,
    0xcccc33333333ccccUL, 0x3333cccccccc3333UL,
    0x3333cccccccc3333UL, 0xcccc33333333ccccUL,
    0x0000ffffffff0000UL, 0x0000ffffffff0000UL,
    0xffff00000000ffffUL, 0xffff00000000ffffUL,
    0xff0000ff00ffff00UL, 0x00ffff00ff0000ffUL,
    0xff0000ff00ffff00UL, 0x00ffff00ff0000ffUL,
    0x6996699669966996UL, 0x9669966996699669UL,
    0x9669966996699669UL, 0x6996699669966996UL,
    0x3c3cc3c3c3c33c3cUL, 0xc3c33c3c3c3cc3c3UL,
    0x3c3cc3c3c3c33c3cUL, 0xc3c33c3c3c3cc3c3UL,
    0xaaaaaaaa55555555UL, 0xaaaaaaaa55555555UL,
    0xaaaaaaaa55555555UL, 0xaaaaaaaa55555555UL,
    0xf00ff00f0ff00ff0UL, 0x0ff00ff0f00ff00fUL,
    0xf00ff00f0ff00ff0UL, 0x0ff00ff0f00ff00fUL,
    0xa55aa55a5aa55aa5UL, 0xa55aa55a5aa55aa5UL,
    0x5aa55aa5a55aa55aUL, 0x5aa55aa5a55aa55aUL,
    0x55aaaa55aa5555aaUL, 0x55aaaa55aa5555aaUL,
    0xaa5555aa55aaaa55UL, 0xaa5555aa55aaaa55UL,
    0x0ff0f00f0ff0f00fUL, 0x0ff0f00f0ff0f00fUL,
    0xf00f0ff0f00f0ff0UL, 0xf00f0ff0f00f0ff0UL,
    0x6996966969969669UL, 0x6996966969969669UL,
    0x6996966969969669UL, 0x6996966969969669UL,
    0xa55aa55aa55aa55aUL, 0x5aa55aa55aa55aa5UL,
    0x5aa55aa55aa55aa5UL, 0xa55aa55aa55aa55aUL,
    0xaaaaaaaa55555555UL, 0xaaaaaaaa55555555UL,
    0x55555555aaaaaaaaUL, 0x55555555aaaaaaaaUL,
    0xcccc33333333ccccUL, 0x3333cccccccc3333UL,
    0x3333cccccccc3333UL, 0xcccc33333333ccccUL,
    0x0000ffffffff0000UL, 0x0000ffffffff0000UL,
    0xffff00000000ffffUL, 0xffff00000000ffffUL,
    0xff0000ff00ffff00UL, 0x00ffff00ff0000ffUL,
    0xff0000ff00ffff00UL, 0x00ffff00ff0000ffUL,
    0x6996699669966996UL, 0x9669966996699669UL,
    0x9669966996699669UL, 0x6996699669966996UL,
    0x3cc3c33c3cc3c33cUL, 0x3cc3c33c3cc3c33cUL,
    0x3cc3c33c3cc3c33cUL, 0x3cc3c33c3cc3c33cUL,
    0xaaaaaaaaaaaaaaaaUL, 0xaaaaaaaaaaaaaaaaUL,
    0xaaaaaaaaaaaaaaaaUL, 0xaaaaaaaaaaaaaaaaUL,
    0xffff0000ffff0000UL, 0xffff0000ffff0000UL,
    0xffff0000ffff0000UL, 0xffff0000ffff0000UL,
    0x3cc3c33c3cc3c33cUL, 0x3cc3c33c3cc3c33cUL,
    0x3cc3c33c3cc3c33cUL, 0x3cc3c33c3cc3c33cUL,
    0x55aa55aa55aa55aaUL, 0x55aa55aa55aa55aaUL,
    0xaa55aa55aa55aa55UL, 0xaa55aa55aa55aa55UL,
    0xffff0000ffff0000UL, 0x0000ffff0000ffffUL,
    0x0000ffff0000ffffUL, 0xffff0000ffff0000UL,
    0x0f0f0f0ff0f0f0f0UL, 0xf0f0f0f00f0f0f0fUL,
    0xf0f0f0f00f0f0f0fUL, 0x0f0f0f0ff0f0f0f0UL,
    0xff0000ff00ffff00UL, 0x00ffff00ff0000ffUL,
    0x00ffff00ff0000ffUL, 0xff0000ff00ffff00UL,
    0x33cccc33cc3333ccUL, 0xcc3333cc33cccc33UL,
    0xcc3333cc33cccc33UL, 0x33cccc33cc3333ccUL,
    0xff0000ff00ffff00UL, 0x00ffff00ff0000ffUL,
    0xff0000ff00ffff00UL, 0x00ffff00ff0000ffUL,
    0x6996966996696996UL, 0x9669699669969669UL,
    0x6996966996696996UL, 0x9669699669969669UL,
    0xa55a5aa55aa5a55aUL, 0xa55a5aa55aa5a55aUL,
    0xa55a5aa55aa5a55aUL, 0xa55a5aa55aa5a55aUL,
    0x6996966996696996UL, 0x6996966996696996UL,
    0x6996966996696996UL, 0x6996966996696996UL,
    0x3cc3c33c3cc3c33cUL, 0x3cc3c33c3cc3c33cUL,
    0x3cc3c33c3cc3c33cUL, 0x3cc3c33c3cc3c33cUL,
    0xaaaaaaaaaaaaaaaaUL, 0xaaaaaaaaaaaaaaaaUL,
    0xaaaaaaaaaaaaaaaaUL, 0xaaaaaaaaaaaaaaaaUL,
    0xffff0000ffff0000UL, 0xffff0000ffff0000UL,
    0xffff0000ffff0000UL, 0xffff0000ffff0000UL,
    0xc33c3cc3c33c3cc3UL, 0xc33c3cc3c33c3cc3UL,
    0xc33c3cc3c33c3cc3UL, 0xc33c3cc3c33c3cc3UL,
    0xaa55aa55aa55aa55UL, 0xaa55aa55aa55aa55UL,
    0x55aa55aa55aa55aaUL, 0x55aa55aa55aa55aaUL,
    0x0000ffff0000ffffUL, 0xffff0000ffff0000UL,
    0xffff0000ffff0000UL, 0x0000ffff0000ffffUL,
    0xf0f0f0f00f0f0f0fUL, 0x0f0f0f0ff0f0f0f0UL,
    0x0f0f0f0ff0f0f0f0UL, 0xf0f0f0f00f0f0f0fUL,
    0xff0000ff00ffff00UL, 0x00ffff00ff0000ffUL,
    0x00ffff00ff0000ffUL, 0xff0000ff00ffff00UL,
    0x33cccc33cc3333ccUL, 0xcc3333cc33cccc33UL,
    0xcc3333cc33cccc33UL, 0x33cccc33cc3333ccUL,
    0xff0000ff00ffff00UL, 0x00ffff00ff0000ffUL,
    0xff0000ff00ffff00UL, 0x00ffff00ff0000ffUL,
    0x6996966996696996UL, 0x9669699669969669UL,
    0x6996966996696996UL, 0x9669699669969669UL,
    0xa55a5aa55aa5a55aUL, 0xa55a5aa55aa5a55aUL,
    0xa55a5aa55aa5a55aUL, 0xa55a5aa55aa5a55aUL,
    0x6996966996696996UL, 0x6996966996696996UL,
    0x6996966996696996UL, 0x6996966996696996UL,
    0x3cc3c33c3cc3c33cUL, 0x3cc3c33c3cc3c33cUL,
    0x3cc3c33c3cc3c33cUL, 0x3cc3c33c3cc3c33cUL,
    0xaaaaaaaaaaaaaaaaUL, 0xaaaaaaaaaaaaaaaaUL,
    0xaaaaaaaaaaaaaaaaUL, 0xaaaaaaaaaaaaaaaaUL,
    0x0000ffff0000ffffUL, 0x0000ffff0000ffffUL,
    0x0000ffff0000ffffUL, 0x0000ffff0000ffffUL,
    0xc33c3cc3c33c3cc3UL, 0xc33c3cc3c33c3cc3UL,
    0xc33c3cc3c33c3cc3UL, 0xc33c3cc3c33c3cc3UL,
    0xaa55aa55aa55aa55UL, 0xaa55aa55aa55aa55UL,
    0x55aa55aa55aa55aaUL, 0x55aa55aa55aa55aaUL,
    0xffff0000ffff0000UL, 0x0000ffff0000ffffUL,
    0x0000ffff0000ffffUL, 0xffff0000ffff0000UL,
    0x0f0f0f0ff0f0f0f0UL, 0xf0f0f0f00f0f0f0fUL,
    0xf0f0f0f00f0f0f0fUL, 0x0f0f0f0ff0f0f0f0UL,
    0xff0000ff00ffff00UL, 0x00ffff00ff0000ffUL,
    0x00ffff00ff0000ffUL, 0xff0000ff00ffff00UL,
    0x33cccc33cc3333ccUL, 0xcc3333cc33cccc33UL,
    0xcc3333cc33cccc33UL, 0x33cccc33cc3333ccUL,
    0xff0000ff00ffff00UL, 0x00ffff00ff0000ffUL,
    0xff0000ff00ffff00UL, 0x00ffff00ff0000ffUL,
    0x6996966996696996UL, 0x9669699669969669UL,
    0x6996966996696996UL, 0x9669699669969669UL,
    0xa55a5aa55aa5a55aUL, 0xa55a5aa55aa5a55aUL,
    0xa55a5aa55aa5a55aUL, 0xa55a5aa55aa5a55aUL,
    0x6996966996696996UL, 0x6996966996696996UL,
    0x6996966996696996UL, 0x6996966996696996UL,
    0x3cc3c33c3cc3c33cUL, 0x3cc3c33c3cc3c33cUL,
    0x3cc3c33c3cc3c33cUL, 0x3cc3c33c3cc3c33cUL,
    0xaaaaaaaaaaaaaaaaUL, 0xaaaaaaaaaaaaaaaaUL,
    0xaaaaaaaaaaaaaaaaUL, 0xaaaaaaaaaaaaaaaaUL,
    0x0000ffff0000ffffUL, 0x0000ffff0000ffffUL,
    0x0000ffff0000ffffUL, 0x0000ffff0000ffffUL,
    0x3cc3c33c3cc3c33cUL, 0x3cc3c33c3cc3c33cUL,
    0x3cc3c33c3cc3c33cUL, 0x3cc3c33c3cc3c33cUL,
    0x55aa55aa55aa55aaUL, 0x55aa55aa55aa55aaUL,
    0xaa55aa55aa55aa55UL, 0xaa55aa55aa55aa55UL,
    0x0000ffff0000ffffUL, 0xffff0000ffff0000UL,
    0xffff0000ffff0000UL, 0x0000ffff0000ffffUL,
    0xf0f0f0f00f0f0f0fUL, 0x0f0f0f0ff0f0f0f0UL,
    0x0f0f0f0ff0f0f0f0UL, 0xf0f0f0f00f0f0f0fUL,
    0xff0000ff00ffff00UL, 0x00ffff00ff0000ffUL,
    0x00ffff00ff0000ffUL, 0xff0000ff00ffff00UL,
    0x33cccc33cc3333ccUL, 0xcc3333cc33cccc33UL,
    0xcc3333cc33cccc33UL, 0x33cccc33cc3333ccUL,
    0xff0000ff00ffff00UL, 0x00ffff00ff0000ffUL,
    0xff0000ff00ffff00UL, 0x00ffff00ff0000ffUL,
    0x6996966996696996UL, 0x9669699669969669UL,
    0x6996966996696996UL, 0x9669699669969669UL,
    0xa55a5aa55aa5a55aUL, 0xa55a5aa55aa5a55aUL,
    0xa55a5aa55aa5a55aUL, 0xa55a5aa55aa5a55aUL,
    0x6996966996696996UL, 0x6996966996696996UL,
    0x6996966996696996UL, 0x6996966996696996UL,
    0x3cc3c33c3cc3c33cUL, 0x3cc3c33c3cc3c33cUL,
    0x3cc3c33c3cc3c33cUL, 0x3cc3c33c3cc3c33cUL,
    0x5555555555555555UL, 0x5555555555555555UL,
    0x5555555555555555UL, 0x5555555555555555UL,
    0x0000ffff0000ffffUL, 0x0000ffff0000ffffUL,
    0x0000ffff0000ffffUL, 0x0000ffff0000ffffUL,
    0x3cc3c33c3cc3c33cUL, 0x3cc3c33c3cc3c33cUL,
    0x3cc3c33c3cc3c33cUL, 0x3cc3c33c3cc3c33cUL,
    0x55aa55aa55aa55aaUL, 0x55aa55aa55aa55aaUL,
    0xaa55aa55aa55aa55UL, 0xaa55aa55aa55aa55UL,
    0xffff0000ffff0000UL, 0x0000ffff0000ffffUL,
    0x0000ffff0000ffffUL, 0xffff0000ffff0000UL,
    0x0f0f0f0ff0f0f0f0UL, 0xf0f0f0f00f0f0f0fUL,
    0xf0f0f0f00f0f0f0fUL, 0x0f0f0f0ff0f0f0f0UL,
    0xff0000ff00ffff00UL, 0x00ffff00ff0000ffUL,
    0x00ffff00ff0000ffUL, 0xff0000ff00ffff00UL,
    0x33cccc33cc3333ccUL, 0xcc3333cc33cccc33UL,
    0xcc3333cc33cccc33UL, 0x33cccc33cc3333ccUL,
    0xff0000ff00ffff00UL, 0x00ffff00ff0000ffUL,
    0xff0000ff00ffff00UL, 0x00ffff00ff0000ffUL,
    0x6996966996696996UL, 0x9669699669969669UL,
    0x6996966996696996UL, 0x9669699669969669UL,
    0xa55a5aa55aa5a55aUL, 0xa55a5aa55aa5a55aUL,
    0xa55a5aa55aa5a55aUL, 0xa55a5aa55aa5a55aUL,
    0x6996966996696996UL, 0x6996966996696996UL,
    0x6996966996696996UL, 0x6996966996696996UL,
    0x3cc3c33c3cc3c33cUL, 0x3cc3c33c3cc3c33cUL,
    0x3cc3c33c3cc3c33cUL, 0x3cc3c33c3cc3c33cUL,
    0x5555555555555555UL, 0x5555555555555555UL,
    0x5555555555555555UL, 0x5555555555555555UL,
    0x0000ffff0000ffffUL, 0x0000ffff0000ffffUL,
    0x0000ffff0000ffffUL, 0x0000ffff0000ffffUL,
    0xc33c3cc3c33c3cc3UL, 0xc33c3cc3c33c3cc3UL,
    0xc33c3cc3c33c3cc3UL, 0xc33c3cc3c33c3cc3UL,
    0xaa55aa55aa55aa55UL, 0xaa55aa55aa55aa55UL,
    0x55aa55aa55aa55aaUL, 0x55aa55aa55aa55aaUL,
    0x0000ffff0000ffffUL, 0xffff0000ffff0000UL,
    0xffff0000ffff0000UL, 0x0000ffff0000ffffUL,
    0xf0f0f0f00f0f0f0fUL, 0x0f0f0f0ff0f0f0f0UL,
    0x0f0f0f0ff0f0f0f0UL, 0xf0f0f0f00f0f0f0fUL,
    0xff0000ff00ffff00UL, 0x00ffff00ff0000ffUL,
    0x00ffff00ff0000ffUL, 0xff0000ff00ffff00UL,
    0x33cccc33cc3333ccUL, 0xcc3333cc33cccc33UL,
    0xcc3333cc33cccc33UL, 0x33cccc33cc3333ccUL,
    0xff0000ff00ffff00UL, 0x00ffff00ff0000ffUL,
    0xff0000ff00ffff00UL, 0x00ffff00ff0000ffUL,
    0x6996966996696996UL, 0x9669699669969669UL,
    0x6996966996696996UL, 0x9669699669969669UL,
    0xa55a5aa55aa5a55aUL, 0xa55a5aa55aa5a55aUL,
    0xa55a5aa55aa5a55aUL, 0xa55a5aa55aa5a55aUL,
    0x6996966996696996UL, 0x6996966996696996UL,
    0x6996966996696996UL, 0x6996966996696996UL,
    0x3cc3c33c3cc3c33cUL, 0x3cc3c33c3cc3c33cUL,
    0x3cc3c33c3cc3c33cUL, 0x3cc3c33c3cc3c33cUL,
    0x5555555555555555UL, 0x5555555555555555UL,
    0x5555555555555555UL, 0x5555555555555555UL,
    0xffff0000ffff0000UL, 0xffff0000ffff0000UL,
    0xffff0000ffff0000UL, 0xffff0000ffff0000UL,
    0xc33c3cc3c33c3cc3UL, 0xc33c3cc3c33c3cc3UL,
    0xc33c3cc3c33c3cc3UL, 0xc33c3cc3c33c3cc3UL,
    0xaa55aa55aa55aa55UL, 0xaa55aa55aa55aa55UL,
    0x55aa55aa55aa55aaUL, 0x55aa55aa55aa55aaUL,
    0xffff0000ffff0000UL, 0x0000ffff0000ffffUL,
    0x0000ffff0000ffffUL, 0xffff0000ffff0000UL,
    0x0f0f0f0ff0f0f0f0UL, 0xf0f0f0f00f0f0f0fUL,
    0xf0f0f0f00f0f0f0fUL, 0x0f0f0f0ff0f0f0f0UL,
    0xff0000ff00ffff00UL, 0x00ffff00ff0000ffUL,
    0x00ffff00ff0000ffUL, 0xff0000ff00ffff00UL,
    0x33cccc33cc3333ccUL, 0xcc3333cc33cccc33UL,
    0xcc3333cc33cccc33UL, 0x33cccc33cc3333ccUL,
    0xff0000ff00ffff00UL, 0x00ffff00ff0000ffUL,
    0xff0000ff00ffff00UL, 0x00ffff00ff0000ffUL,
    0x6996966996696996UL, 0x9669699669969669UL,
    0x6996966996696996UL, 0x9669699669969669UL,
    0xa55a5aa55aa5a55aUL, 0xa55a5aa55aa5a55aUL,
    0xa55a5aa55aa5a55aUL, 0xa55a5aa55aa5a55aUL,
    0x6996966996696996UL, 0x6996966996696996UL,
    0x6996966996696996UL, 0x6996966996696996UL,
    0x3cc3c33c3cc3c33cUL, 0x3cc3c33c3cc3c33cUL,
    0x3cc3c33c3cc3c33cUL, 0x3cc3c33c3cc3c33cUL,
    0x5555555555555555UL, 0x5555555555555555UL,
    0x5555555555555555UL, 0x5555555555555555UL,
    0xffff0000ffff0000UL, 0xffff0000ffff0000UL,
    0xffff0000ffff0000UL, 0xffff0000ffff0000UL,
    0x3cc3c33c3cc3c33cUL, 0x3cc3c33c3cc3c33cUL,
    0x3cc3c33c3cc3c33cUL, 0x3cc3c33c3cc3c33cUL,
    0x55aa55aa55aa55aaUL, 0x55aa55aa55aa55aaUL,
    0xaa55aa55aa55aa55UL, 0xaa55aa55aa55aa55UL,
    0x0000ffff0000ffffUL, 0xffff0000ffff0000UL,
    0xffff0000ffff0000UL, 0x0000ffff0000ffffUL,
    0xf0f0f0f00f0f0f0fUL, 0x0f0f0f0ff0f0f0f0UL,
    0x0f0f0f0ff0f0f0f0UL, 0xf0f0f0f00f0f0f0fUL,
    0xff0000ff00ffff00UL, 0x00ffff00ff0000ffUL,
    0x00ffff00ff0000ffUL, 0xff0000ff00ffff00UL,
    0x33cccc33cc3333ccUL, 0xcc3333cc33cccc33UL,
    0xcc3333cc33cccc33UL, 0x33cccc33cc3333ccUL,
    0xff0000ff00ffff00UL, 0x00ffff00ff0000ffUL,
    0xff0000ff00ffff00UL, 0x00ffff00ff0000ffUL,
    0x6996966996696996UL, 0x9669699669969669UL,
    0x6996966996696996UL, 0x9669699669969669UL,
    0xa55a5aa55aa5a55aUL, 0xa55a5aa55aa5a55aUL,
    0xa55a5aa55aa5a55aUL, 0xa55a5aa55aa5a55aUL,
    0x6996966996696996UL, 0x6996966996696996UL,
    0x6996966996696996UL, 0x6996966996696996UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffff0000ffff0000UL, 0xffff0000ffff0000UL,
    0xffff0000ffff0000UL, 0xffff0000ffff0000UL,
    0xff00ff00ff00ff00UL, 0xff00ff00ff00ff00UL,
    0xff00ff00ff00ff00UL, 0xff00ff00ff00ff00UL,
    0xf0f0f0f0f0f0f0f0UL, 0xf0f0f0f0f0f0f0f0UL,
    0xf0f0f0f0f0f0f0f0UL, 0xf0f0f0f0f0f0f0f0UL,
    0xccccccccccccccccUL, 0xccccccccccccccccUL,
    0xccccccccccccccccUL, 0xccccccccccccccccUL,
    0xaaaaaaaaaaaaaaaaUL, 0xaaaaaaaaaaaaaaaaUL,
    0xaaaaaaaaaaaaaaaaUL, 0xaaaaaaaaaaaaaaaaUL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffff0000ffff0000UL, 0xffff0000ffff0000UL,
    0xffff0000ffff0000UL, 0xffff0000ffff0000UL,
    0xff00ff00ff00ff00UL, 0xff00ff00ff00ff00UL,
    0xff00ff00ff00ff00UL, 0xff00ff00ff00ff00UL,
    0xf0f0f0f0f0f0f0f0UL, 0xf0f0f0f0f0f0f0f0UL,
    0xf0f0f0f0f0f0f0f0UL, 0xf0f0f0f0f0f0f0f0UL,
    0xccccccccccccccccUL, 0xccccccccccccccccUL,
    0xccccccccccccccccUL, 0xccccccccccccccccUL,
    0xaaaaaaaaaaaaaaaaUL, 0xaaaaaaaaaaaaaaaaUL,
    0xaaaaaaaaaaaaaaaaUL, 0xaaaaaaaaaaaaaaaaUL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffff0000ffff0000UL, 0xffff0000ffff0000UL,
    0xffff0000ffff0000UL, 0xffff0000ffff0000UL,
    0xff00ff00ff00ff00UL, 0xff00ff00ff00ff00UL,
    0xff00ff00ff00ff00UL, 0xff00ff00ff00ff00UL,
    0xf0f0f0f0f0f0f0f0UL, 0xf0f0f0f0f0f0f0f0UL,
    0xf0f0f0f0f0f0f0f0UL, 0xf0f0f0f0f0f0f0f0UL,
    0xccccccccccccccccUL, 0xccccccccccccccccUL,
    0xccccccccccccccccUL, 0xccccccccccccccccUL,
    0xaaaaaaaaaaaaaaaaUL, 0xaaaaaaaaaaaaaaaaUL,
    0xaaaaaaaaaaaaaaaaUL, 0xaaaaaaaaaaaaaaaaUL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffff0000ffff0000UL, 0xffff0000ffff0000UL,
    0xffff0000ffff0000UL, 0xffff0000ffff0000UL,
    0xff00ff00ff00ff00UL, 0xff00ff00ff00ff00UL,
    0xff00ff00ff00ff00UL, 0xff00ff00ff00ff00UL,
    0xf0f0f0f0f0f0f0f0UL, 0xf0f0f0f0f0f0f0f0UL,
    0xf0f0f0f0f0f0f0f0UL, 0xf0f0f0f0f0f0f0f0UL,
    0xccccccccccccccccUL, 0xccccccccccccccccUL,
    0xccccccccccccccccUL, 0xccccccccccccccccUL,
    0xaaaaaaaaaaaaaaaaUL, 0xaaaaaaaaaaaaaaaaUL,
    0xaaaaaaaaaaaaaaaaUL, 0xaaaaaaaaaaaaaaaaUL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffff0000ffff0000UL, 0xffff0000ffff0000UL,
    0xffff0000ffff0000UL, 0xffff0000ffff0000UL,
    0xff00ff00ff00ff00UL, 0xff00ff00ff00ff00UL,
    0xff00ff00ff00ff00UL, 0xff00ff00ff00ff00UL,
    0xf0f0f0f0f0f0f0f0UL, 0xf0f0f0f0f0f0f0f0UL,
    0xf0f0f0f0f0f0f0f0UL, 0xf0f0f0f0f0f0f0f0UL,
    0xccccccccccccccccUL, 0xccccccccccccccccUL,
    0xccccccccccccccccUL, 0xccccccccccccccccUL,
    0xaaaaaaaaaaaaaaaaUL, 0xaaaaaaaaaaaaaaaaUL,
    0xaaaaaaaaaaaaaaaaUL, 0xaaaaaaaaaaaaaaaaUL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffff0000ffff0000UL, 0xffff0000ffff0000UL,
    0xffff0000ffff0000UL, 0xffff0000ffff0000UL,
    0xff00ff00ff00ff00UL, 0xff00ff00ff00ff00UL,
    0xff00ff00ff00ff00UL, 0xff00ff00ff00ff00UL,
    0xf0f0f0f0f0f0f0f0UL, 0xf0f0f0f0f0f0f0f0UL,
    0xf0f0f0f0f0f0f0f0UL, 0xf0f0f0f0f0f0f0f0UL,
    0xccccccccccccccccUL, 0xccccccccccccccccUL,
    0xccccccccccccccccUL, 0xccccccccccccccccUL,
    0xaaaaaaaaaaaaaaaaUL, 0xaaaaaaaaaaaaaaaaUL,
    0xaaaaaaaaaaaaaaaaUL, 0xaaaaaaaaaaaaaaaaUL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffff0000ffff0000UL, 0xffff0000ffff0000UL,
    0xffff0000ffff0000UL, 0xffff0000ffff0000UL,
    0xff00ff00ff00ff00UL, 0xff00ff00ff00ff00UL,
    0xff00ff00ff00ff00UL, 0xff00ff00ff00ff00UL,
    0xf0f0f0f0f0f0f0f0UL, 0xf0f0f0f0f0f0f0f0UL,
    0xf0f0f0f0f0f0f0f0UL, 0xf0f0f0f0f0f0f0f0UL,
    0xccccccccccccccccUL, 0xccccccccccccccccUL,
    0xccccccccccccccccUL, 0xccccccccccccccccUL,
    0xaaaaaaaaaaaaaaaaUL, 0xaaaaaaaaaaaaaaaaUL,
    0xaaaaaaaaaaaaaaaaUL, 0xaaaaaaaaaaaaaaaaUL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffff0000ffff0000UL, 0xffff0000ffff0000UL,
    0xffff0000ffff0000UL, 0xffff0000ffff0000UL,
    0xff00ff00ff00ff00UL, 0xff00ff00ff00ff00UL,
    0xff00ff00ff00ff00UL, 0xff00ff00ff00ff00UL,
    0xf0f0f0f0f0f0f0f0UL, 0xf0f0f0f0f0f0f0f0UL,
    0xf0f0f0f0f0f0f0f0UL, 0xf0f0f0f0f0f0f0f0UL,
    0xccccccccccccccccUL, 0xccccccccccccccccUL,
    0xccccccccccccccccUL, 0xccccccccccccccccUL,
    0xaaaaaaaaaaaaaaaaUL, 0xaaaaaaaaaaaaaaaaUL,
    0xaaaaaaaaaaaaaaaaUL, 0xaaaaaaaaaaaaaaaaUL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffff0000ffff0000UL, 0xffff0000ffff0000UL,
    0xffff0000ffff0000UL, 0xffff0000ffff0000UL,
    0xff00ff00ff00ff00UL, 0xff00ff00ff00ff00UL,
    0xff00ff00ff00ff00UL, 0xff00ff00ff00ff00UL,
    0xf0f0f0f0f0f0f0f0UL, 0xf0f0f0f0f0f0f0f0UL,
    0xf0f0f0f0f0f0f0f0UL, 0xf0f0f0f0f0f0f0f0UL,
    0xccccccccccccccccUL, 0xccccccccccccccccUL,
    0xccccccccccccccccUL, 0xccccccccccccccccUL,
    0xaaaaaaaaaaaaaaaaUL, 0xaaaaaaaaaaaaaaaaUL,
    0xaaaaaaaaaaaaaaaaUL, 0xaaaaaaaaaaaaaaaaUL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffff0000ffff0000UL, 0xffff0000ffff0000UL,
    0xffff0000ffff0000UL, 0xffff0000ffff0000UL,
    0xff00ff00ff00ff00UL, 0xff00ff00ff00ff00UL,
    0xff00ff00ff00ff00UL, 0xff00ff00ff00ff00UL,
    0xf0f0f0f0f0f0f0f0UL, 0xf0f0f0f0f0f0f0f0UL,
    0xf0f0f0f0f0f0f0f0UL, 0xf0f0f0f0f0f0f0f0UL,
    0xccccccccccccccccUL, 0xccccccccccccccccUL,
    0xccccccccccccccccUL, 0xccccccccccccccccUL,
    0xaaaaaaaaaaaaaaaaUL, 0xaaaaaaaaaaaaaaaaUL,
    0xaaaaaaaaaaaaaaaaUL, 0xaaaaaaaaaaaaaaaaUL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffff0000ffff0000UL, 0xffff0000ffff0000UL,
    0xffff0000ffff0000UL, 0xffff0000ffff0000UL,
    0xff00ff00ff00ff00UL, 0xff00ff00ff00ff00UL,
    0xff00ff00ff00ff00UL, 0xff00ff00ff00ff00UL,
    0xf0f0f0f0f0f0f0f0UL, 0xf0f0f0f0f0f0f0f0UL,
    0xf0f0f0f0f0f0f0f0UL, 0xf0f0f0f0f0f0f0f0UL,
    0xccccccccccccccccUL, 0xccccccccccccccccUL,
    0xccccccccccccccccUL, 0xccccccccccccccccUL,
    0xaaaaaaaaaaaaaaaaUL, 0xaaaaaaaaaaaaaaaaUL,
    0xaaaaaaaaaaaaaaaaUL, 0xaaaaaaaaaaaaaaaaUL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffff0000ffff0000UL, 0xffff0000ffff0000UL,
    0xffff0000ffff0000UL, 0xffff0000ffff0000UL,
    0xff00ff00ff00ff00UL, 0xff00ff00ff00ff00UL,
    0xff00ff00ff00ff00UL, 0xff00ff00ff00ff00UL,
    0xf0f0f0f0f0f0f0f0UL, 0xf0f0f0f0f0f0f0f0UL,
    0xf0f0f0f0f0f0f0f0UL, 0xf0f0f0f0f0f0f0f0UL,
    0xccccccccccccccccUL, 0xccccccccccccccccUL,
    0xccccccccccccccccUL, 0xccccccccccccccccUL,
    0xaaaaaaaaaaaaaaaaUL, 0xaaaaaaaaaaaaaaaaUL,
    0xaaaaaaaaaaaaaaaaUL, 0xaaaaaaaaaaaaaaaaUL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffff0000ffff0000UL, 0xffff0000ffff0000UL,
    0xffff0000ffff0000UL, 0xffff0000ffff0000UL,
    0xff00ff00ff00ff00UL, 0xff00ff00ff00ff00UL,
    0xff00ff00ff00ff00UL, 0xff00ff00ff00ff00UL,
    0xf0f0f0f0f0f0f0f0UL, 0xf0f0f0f0f0f0f0f0UL,
    0xf0f0f0f0f0f0f0f0UL, 0xf0f0f0f0f0f0f0f0UL,
    0xccccccccccccccccUL, 0xccccccccccccccccUL,
    0xccccccccccccccccUL, 0xccccccccccccccccUL,
    0xaaaaaaaaaaaaaaaaUL, 0xaaaaaaaaaaaaaaaaUL,
    0xaaaaaaaaaaaaaaaaUL, 0xaaaaaaaaaaaaaaaaUL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffff0000ffff0000UL, 0xffff0000ffff0000UL,
    0xffff0000ffff0000UL, 0xffff0000ffff0000UL,
    0xff00ff00ff00ff00UL, 0xff00ff00ff00ff00UL,
    0xff00ff00ff00ff00UL, 0xff00ff00ff00ff00UL,
    0xf0f0f0f0f0f0f0f0UL, 0xf0f0f0f0f0f0f0f0UL,
    0xf0f0f0f0f0f0f0f0UL, 0xf0f0f0f0f0f0f0f0UL,
    0xccccccccccccccccUL, 0xccccccccccccccccUL,
    0xccccccccccccccccUL, 0xccccccccccccccccUL,
    0xaaaaaaaaaaaaaaaaUL, 0xaaaaaaaaaaaaaaaaUL,
    0xaaaaaaaaaaaaaaaaUL, 0xaaaaaaaaaaaaaaaaUL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffff0000ffff0000UL, 0xffff0000ffff0000UL,
    0xffff0000ffff0000UL, 0xffff0000ffff0000UL,
    0xff00ff00ff00ff00UL, 0xff00ff00ff00ff00UL,
    0xff00ff00ff00ff00UL, 0xff00ff00ff00ff00UL,
    0xf0f0f0f0f0f0f0f0UL, 0xf0f0f0f0f0f0f0f0UL,
    0xf0f0f0f0f0f0f0f0UL, 0xf0f0f0f0f0f0f0f0UL,
    0xccccccccccccccccUL, 0xccccccccccccccccUL,
    0xccccccccccccccccUL, 0xccccccccccccccccUL,
    0xaaaaaaaaaaaaaaaaUL, 0xaaaaaaaaaaaaaaaaUL,
    0xaaaaaaaaaaaaaaaaUL, 0xaaaaaaaaaaaaaaaaUL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffff0000ffff0000UL, 0xffff0000ffff0000UL,
    0xffff0000ffff0000UL, 0xffff0000ffff0000UL,
    0xff00ff00ff00ff00UL, 0xff00ff00ff00ff00UL,
    0xff00ff00ff00ff00UL, 0xff00ff00ff00ff00UL,
    0xf0f0f0f0f0f0f0f0UL, 0xf0f0f0f0f0f0f0f0UL,
    0xf0f0f0f0f0f0f0f0UL, 0xf0f0f0f0f0f0f0f0UL,
    0xccccccccccccccccUL, 0xccccccccccccccccUL,
    0xccccccccccccccccUL, 0xccccccccccccccccUL,
    0xaaaaaaaaaaaaaaaaUL, 0xaaaaaaaaaaaaaaaaUL,
    0xaaaaaaaaaaaaaaaaUL, 0xaaaaaaaaaaaaaaaaUL,
};

XALIGNED(16) static const word64 L_mc_aff_scal2x_neon[] = {
    0x3c3cf30c0000c003UL, 0x0c0f0fcf0f0cf330UL,
    0x0cccc3f333c0000cUL, 0xf0000fc33c3ccf3cUL,
    0x03c33f33fcc0c03cUL, 0x3c0f3f00c3c300fcUL,
    0x0003000f3c03c0c0UL, 0x3c33ccc0f0f3cc30UL,
    0xf33ff33030cf03f0UL, 0xc0cfffffcccc30ccUL,
    0x0cf0303300f0ccc0UL, 0x3fc3f3ccfffc033fUL,
    0xff3f0c0cc0ff3cc0UL, 0xfc3030ccccc0cfcfUL,
    0xcf3cf0ff003fc000UL, 0x0fcf0c00ccf333c3UL,
    0xc00ff3cf0303f300UL, 0xcffcf33000cff030UL,
    0x3ccc0cc00cf0cc00UL, 0x00cffcc330f30fccUL,
    0xf30ffc3c3fccfc00UL, 0x3ccc3fccc0f3fff3UL,
    0x3f0fc3f0ccf0c000UL, 0xf00f0c3fc003c0ffUL,
    0x3000ff33ccf0f000UL, 0x330ccfcc03c0fc33UL,
    0x0f0f0ff0f000000fUL, 0xf0fffffff0f00f00UL,
    0x00ffffffff0000f0UL, 0x00fff0ffff0000ffUL,
    0xffff00ff00000f00UL, 0x00ff00000f0f0fffUL,
    0xfff000f00f0ff000UL, 0xf000f0000f00ff0fUL,
    0xfff0000f0ff000f0UL, 0xff000000fff00000UL,
    0x00ff000fff000000UL, 0xf0ff000ff00f0ff0UL,
    0xff0f0fff0f0ff000UL, 0x0f0f0f00ff000f0fUL,
    0x0fff0000000f0000UL, 0x0f0f00f0f0f0f000UL,
    0x00f000f0fff00f00UL, 0x00f00f00f00f000fUL,
    0x00f00ff00f00f000UL, 0x00f0f0f00000fff0UL,
    0xfff000f000f00000UL, 0xffffff0ff00f0fffUL,
    0x00f00f000ff00000UL, 0x0f0ffff00fffffffUL,
    0x0000ff0f0000f000UL, 0xffff0f0fff0fff00UL,
    0x00ff0000000000ffUL, 0x00ff00ff00ff0000UL,
    0xffffffffff00ff00UL, 0xff00ffff000000ffUL,
    0xff0000ff00ff0000UL, 0x0000ffff000000ffUL,
    0xffff000000ff0000UL, 0x00ffff00ff000000UL,
    0xff00000000ff0000UL, 0xffffff0000ff00ffUL,
    0x00ffffffff000000UL, 0x0000ffff00ffff00UL,
    0xff0000ffffff0000UL, 0xff00ff0000ffff00UL,
    0xff00ff00ffff0000UL, 0x00000000ffffffffUL,
    0x00ffffffff00ff00UL, 0x0000ff0000000000UL,
    0xffff000000000000UL, 0xff00ffff00ffff00UL,
    0x00ff0000ff000000UL, 0x00ffff00000000ffUL,
    0xff00ff00ff000000UL, 0x0000ff00ff00ffffUL,
    0x00ff00ffff000000UL, 0xff0000ffffff0000UL,
    0x000000000000ffffUL, 0x0000ffff00000000UL,
    0xffffffffffff0000UL, 0xffffffff0000ffffUL,
    0x0000000000000000UL, 0x00000000ffffffffUL,
    0xffff0000ffff0000UL, 0x0000000000000000UL,
    0xffffffffffff0000UL, 0x0000ffff00000000UL,
    0x0000ffff00000000UL, 0xffff0000ffff0000UL,
    0x0000ffffffff0000UL, 0x0000ffffffff0000UL,
    0xffff0000ffff0000UL, 0x0000ffff0000ffffUL,
    0x0000ffff00000000UL, 0xffffffff0000ffffUL,
    0xffff000000000000UL, 0x00000000ffff0000UL,
    0xffff000000000000UL, 0xffff0000ffffffffUL,
    0xffff000000000000UL, 0xffff0000ffffffffUL,
    0xffffffff00000000UL, 0x0000000000000000UL,
    0x00000000ffffffffUL, 0x0000000000000000UL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0xffffffff00000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0xffffffff00000000UL, 0x00000000ffffffffUL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffffffff00000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0xffffffff00000000UL, 0x00000000ffffffffUL,
    0x0000000000000000UL, 0xffffffff00000000UL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
};

XALIGNED(16) static const word64 L_mc_aff_scal4x_neon[] = {
    0x3c3cf30c0000c003UL, 0x0c0f0fcf0f0cf330UL,
    0xf0f30c33cf03f03fUL, 0x3f30cc0c000f3fccUL,
    0x0cccc3f333c0000cUL, 0xf0000fc33c3ccf3cUL,
    0x00f30fc00c3300ffUL, 0xfc3cf030fc3fff03UL,
    0x03c33f33fcc0c03cUL, 0x3c0f3f00c3c300fcUL,
    0xf3cc3cf3f3fcf33fUL, 0x33fffcff0ccf3cc3UL,
    0x0003000f3c03c0c0UL, 0x3c33ccc0f0f3cc30UL,
    0x3c0fc0fc303c3f3cUL, 0x003cff33c3cc30cfUL,
    0xf33ff33030cf03f0UL, 0xc0cfffffcccc30ccUL,
    0xfc30cf303f3ff00fUL, 0xcff3cf33c00f3003UL,
    0x0cf0303300f0ccc0UL, 0x3fc3f3ccfffc033fUL,
    0x33300c0cc3300cf3UL, 0x00f3cc0cf3003ccfUL,
    0xff3f0c0cc0ff3cc0UL, 0xfc3030ccccc0cfcfUL,
    0x3c030cf3f03ff3f3UL, 0x3c000cfccc3c3333UL,
    0xcf3cf0ff003fc000UL, 0x0fcf0c00ccf333c3UL,
    0x3ccc03fccc3ffc03UL, 0xf3cf03c0fcf03ff0UL,
    0xc00ff3cf0303f300UL, 0xcffcf33000cff030UL,
    0x033c3c3cf0003fc3UL, 0x3f3c3cf0c330330cUL,
    0x3ccc0cc00cf0cc00UL, 0x00cffcc330f30fccUL,
    0xffc0ff00f0ff0f03UL, 0x33ccfcc0ff0033f0UL,
    0xf30ffc3c3fccfc00UL, 0x3ccc3fccc0f3fff3UL,
    0xf3f30cf003fcc303UL, 0x33c300c0f0c003f3UL,
    0x3f0fc3f0ccf0c000UL, 0xf00f0c3fc003c0ffUL,
    0x30cfcfc3cc0f3000UL, 0x003ff0003f00c00cUL,
    0x3000ff33ccf0f000UL, 0x330ccfcc03c0fc33UL,
    0x0cf30ccf3fcfcc0fUL, 0xcff3c3033f030fffUL,
    0x0f0f0ff0f000000fUL, 0xf0fffffff0f00f00UL,
    0x0f0f00ff0ff0ffffUL, 0xff0f0f00f000f0ffUL,
    0x00ffffffff0000f0UL, 0x00fff0ffff0000ffUL,
    0xf000f0f00f00ff0fUL, 0x0fffffffff00000fUL,
    0xffff00ff00000f00UL, 0x00ff00000f0f0fffUL,
    0x000ffff0fff0ff0fUL, 0xf0ffff000f00f0ffUL,
    0xfff000f00f0ff000UL, 0xf000f0000f00ff0fUL,
    0x00f00fff00000ff0UL, 0x0f0000f00fff0fffUL,
    0xfff0000f0ff000f0UL, 0xff000000fff00000UL,
    0xfffff0000ffff00fUL, 0x0f0f0f00ff0f000fUL,
    0x00ff000fff000000UL, 0xf0ff000ff00f0ff0UL,
    0xfff0fff0000ffff0UL, 0x000f0f0ffff0f000UL,
    0xff0f0fff0f0ff000UL, 0x0f0f0f00ff000f0fUL,
    0xf0f0f0000f0f0f00UL, 0xf0ffff0f00f0ff0fUL,
    0x0fff0000000f0000UL, 0x0f0f00f0f0f0f000UL,
    0x00f000f0f00fff00UL, 0x0f0f000f0f00f0ffUL,
    0x00f000f0fff00f00UL, 0x00f00f00f00f000fUL,
    0xf0ff0f0fff00f0ffUL, 0x0000f0ff00ff0f0fUL,
    0x00f00ff00f00f000UL, 0x00f0f0f00000fff0UL,
    0xf0ff0ffff0f0f0ffUL, 0x00ffff0ff0fff0f0UL,
    0xfff000f000f00000UL, 0xffffff0ff00f0fffUL,
    0x00fffffffffffff0UL, 0x0000000f00f0fff0UL,
    0x00f00f000ff00000UL, 0x0f0ffff00fffffffUL,
    0x00fff0f0ff000f0fUL, 0xf0f00000ff00f0f0UL,
    0x0000ff0f0000f000UL, 0xffff0f0fff0fff00UL,
    0x000ffff0000fff00UL, 0x0f0f0fffffffffffUL,
    0x00ff0000000000ffUL, 0x00ff00ff00ff0000UL,
    0xffff00ff00ff00ffUL, 0xff0000ffffff00ffUL,
    0xffffffffff00ff00UL, 0xff00ffff000000ffUL,
    0x00ffff000000ff00UL, 0xffff0000ffffffffUL,
    0xff0000ff00ff0000UL, 0x0000ffff000000ffUL,
    0xffff00ffffffff00UL, 0xffff000000ffffffUL,
    0xffff000000ff0000UL, 0x00ffff00ff000000UL,
    0x0000ffff00ffffffUL, 0x00ffff00ff0000ffUL,
    0xff00000000ff0000UL, 0xffffff0000ff00ffUL,
    0x00ff0000ff0000ffUL, 0xffffff00ffffff00UL,
    0x00ffffffff000000UL, 0x0000ffff00ffff00UL,
    0xffff0000ff00ffffUL, 0x00ffff00ffff00ffUL,
    0xff0000ffffff0000UL, 0xff00ff0000ffff00UL,
    0xff000000ffffff00UL, 0x0000ffff00ff0000UL,
    0xff00ff00ffff0000UL, 0x00000000ffffffffUL,
    0x000000000000ffffUL, 0x000000ffff000000UL,
    0x00ffffffff00ff00UL, 0x0000ff0000000000UL,
    0xff00ff00ffff0000UL, 0xff00ff0000ff00ffUL,
    0xffff000000000000UL, 0xff00ffff00ffff00UL,
    0xffff00ffff00ffffUL, 0x00ff0000000000ffUL,
    0x00ff0000ff000000UL, 0x00ffff00000000ffUL,
    0xffffffffff00ff00UL, 0xff00ffff00ff00ffUL,
    0xff00ff00ff000000UL, 0x0000ff00ff00ffffUL,
    0xffff00ffff0000ffUL, 0xffffffffffffffffUL,
    0x00ff00ffff000000UL, 0xff0000ffffff0000UL,
    0x0000ff00000000ffUL, 0x0000ff000000ffffUL,
    0x000000000000ffffUL, 0x0000ffff00000000UL,
    0xffffffffffffffffUL, 0x0000ffffffffffffUL,
    0xffffffffffff0000UL, 0xffffffff0000ffffUL,
    0xffffffff00000000UL, 0x0000ffff0000ffffUL,
    0x0000000000000000UL, 0x00000000ffffffffUL,
    0xffff000000000000UL, 0x0000ffffffff0000UL,
    0xffff0000ffff0000UL, 0x0000000000000000UL,
    0x0000ffff00000000UL, 0xffff0000ffffffffUL,
    0xffffffffffff0000UL, 0x0000ffff00000000UL,
    0x00000000ffff0000UL, 0x00000000ffff0000UL,
    0x0000ffff00000000UL, 0xffff0000ffff0000UL,
    0x0000ffffffffffffUL, 0xffff00000000ffffUL,
    0x0000ffffffff0000UL, 0x0000ffffffff0000UL,
    0x0000ffffffffffffUL, 0x0000ffff0000ffffUL,
    0xffff0000ffff0000UL, 0x0000ffff0000ffffUL,
    0xffffffff00000000UL, 0xffff00000000ffffUL,
    0x0000ffff00000000UL, 0xffffffff0000ffffUL,
    0x000000000000ffffUL, 0x0000ffff0000ffffUL,
    0xffff000000000000UL, 0x00000000ffff0000UL,
    0x000000000000ffffUL, 0x0000ffff00000000UL,
    0xffff000000000000UL, 0xffff0000ffffffffUL,
    0xffffffffffff0000UL, 0xffffffff00000000UL,
    0xffff000000000000UL, 0xffff0000ffffffffUL,
    0xffffffff0000ffffUL, 0x0000ffffffff0000UL,
    0xffffffff00000000UL, 0x0000000000000000UL,
    0xffff0000ffffffffUL, 0x0000ffffffffffffUL,
    0x00000000ffffffffUL, 0x0000000000000000UL,
    0x00000000ffffffffUL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0xffffffff00000000UL, 0x00000000ffffffffUL,
    0xffffffff00000000UL, 0x0000000000000000UL,
    0xffffffff00000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0xffffffff00000000UL, 0x00000000ffffffffUL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffffffffffffffffUL, 0x0000000000000000UL,
    0xffffffff00000000UL, 0x0000000000000000UL,
    0xffffffffffffffffUL, 0xffffffff00000000UL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0x00000000ffffffffUL,
    0xffffffff00000000UL, 0x00000000ffffffffUL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0x0000000000000000UL, 0xffffffff00000000UL,
    0x00000000ffffffffUL, 0x0000000000000000UL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0xffffffff00000000UL,
    0xffffffff00000000UL, 0xffffffff00000000UL,
    0xffffffffffffffffUL, 0xffffffff00000000UL,
    0xffffffffffffffffUL, 0x0000000000000000UL,
    0xffffffffffffffffUL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0xffffffffffffffffUL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0x0000000000000000UL, 0xffffffffffffffffUL,
    0xffffffffffffffffUL, 0x0000000000000000UL,
    0x0000000000000000UL, 0x0000000000000000UL,
    0xffffffffffffffffUL, 0xffffffffffffffffUL,
};

XALIGNED(4) static const word16 L_mc_bs_powers_neon[] = {
    0x0001, 0x0002, 0x0004, 0x0008, 0x0010, 0x0020, 0x0040, 0x0080,
};

XALIGNED(16) static const word64 L_mc_aff_rmask0_neon[] = {
    0x8888888888888888UL, 0xc0c0c0c0c0c0c0c0UL,
    0xf000f000f000f000UL, 0xff000000ff000000UL,
    0xffff000000000000UL
};

XALIGNED(16) static const word64 L_mc_aff_rmask1_neon[] = {
    0x4444444444444444UL, 0x3030303030303030UL,
    0x0f000f000f000f00UL, 0x00ff000000ff0000UL,
    0x0000ffff00000000UL
};

XALIGNED(16) static const word64 L_mc_aff_tmask0_neon[] = {
    0x2222222222222222UL, 0x0c0c0c0c0c0c0c0cUL,
    0x00f000f000f000f0UL, 0x0000ff000000ff00UL,
    0x00000000ffff0000UL, 0xffffffff00000000UL,
};

XALIGNED(16) static const word64 L_mc_aff_tmask1_neon[] = {
    0x4444444444444444UL, 0x3030303030303030UL,
    0x0f000f000f000f00UL, 0x00ff000000ff0000UL,
    0x0000ffff00000000UL, 0x00000000ffffffffUL,
};

XALIGNED(4) static const word8 L_mc_aff_reversal_neon[] = {
    0x00, 0x20, 0x10, 0x30, 0x08, 0x28, 0x18, 0x38,
    0x04, 0x24, 0x14, 0x34, 0x0c, 0x2c, 0x1c, 0x3c,
    0x02, 0x22, 0x12, 0x32, 0x0a, 0x2a, 0x1a, 0x3a,
    0x06, 0x26, 0x16, 0x36, 0x0e, 0x2e, 0x1e, 0x3e,
    0x01, 0x21, 0x11, 0x31, 0x09, 0x29, 0x19, 0x39,
    0x05, 0x25, 0x15, 0x35, 0x0d, 0x2d, 0x1d, 0x3d,
    0x03, 0x23, 0x13, 0x33, 0x0b, 0x2b, 0x1b, 0x3b,
    0x07, 0x27, 0x17, 0x37, 0x0f, 0x2f, 0x1f, 0x3f,
};

#ifndef WOLFSSL_MCELIECE_NO_ENCAPSULATE
#ifndef WOLFSSL_MCELIECE_SMALL
WOLFSSL_LOCAL int wc_mceliece_encap_fixedweight_neon(const byte* rand_p,
    word16* ind_p, int randLen_p, int n_p, int t_p, int tau_p);
int wc_mceliece_encap_fixedweight_neon(const byte* rand_p, word16* ind_p,
    int randLen_p, int n_p, int t_p, int tau_p)
{
    register const byte* rand __asm__ ("x0") = (const byte*)rand_p;
    register word16* ind __asm__ ("x1") = (word16*)ind_p;
    register int randLen __asm__ ("w2") = (int)randLen_p;
    register int n __asm__ ("w3") = (int)n_p;
    register int t __asm__ ("w4") = (int)t_p;
    register int tau __asm__ ("w5") = (int)tau_p;
    __asm__ __volatile__ (
        "mov	w6, %w[n]\n\t"
        "mov	w7, %w[t]\n\t"
        "mov	w8, %w[tau]\n\t"
        "mov	w9, %w[randLen]\n\t"
        "lsl	x10, x8, #1\n\t"
        "mov	x11, #0\n\t"
        "\n"
    "L_mc_fw_retry_%=:\n\t"
        "add	x20, x11, x10\n\t"
        "cmp	x20, x9\n\t"
        "b.gt	L_mc_fw_depl_%=\n\t"
        "add	x12, %x[rand], x11\n\t"
        "mov	x13, #0\n\t"
        "mov	x14, #0\n\t"
        "\n"
    "L_mc_fw_filter_%=:\n\t"
        "cmp	x14, x8\n\t"
        "b.ge	L_mc_fw_filterd_%=\n\t"
        "cmp	x13, x7\n\t"
        "b.ge	L_mc_fw_filterd_%=\n\t"
        "lsl	x20, x14, #1\n\t"
        "add	x20, x12, x20\n\t"
        "ldrh	w21, [x20]\n\t"
        "and	x21, x21, #0x1fff\n\t"
        "lsl	x22, x13, #1\n\t"
        "add	x22, %x[ind], x22\n\t"
        "strh	w21, [x22]\n\t"
        "cmp	x21, x6\n\t"
        "cinc	x13, x13, lt\n\t"
        "add	x14, x14, #1\n\t"
        "b	L_mc_fw_filter_%=\n\t"
        "\n"
    "L_mc_fw_filterd_%=:\n\t"
        "add	x11, x11, x10\n\t"
        "cmp	x13, x7\n\t"
        "b.lt	L_mc_fw_retry_%=\n\t"
        "mov	x17, #0\n\t"
        "mov	x14, #1\n\t"
        "\n"
    "L_mc_fw_dupi_%=:\n\t"
        "cmp	x14, x7\n\t"
        "b.ge	L_mc_fw_dupd_%=\n\t"
        "lsl	x20, x14, #1\n\t"
        "add	x20, %x[ind], x20\n\t"
        "ldrh	w16, [x20]\n\t"
        "dup	v0.8h, w16\n\t"
        "eor	v1.16b, v1.16b, v1.16b\n\t"
        "mov	x15, #0\n\t"
        "\n"
    "L_mc_fw_dupj8_%=:\n\t"
        "add	x20, x15, #8\n\t"
        "cmp	x20, x14\n\t"
        "b.gt	L_mc_fw_duprem_%=\n\t"
        "lsl	x21, x15, #1\n\t"
        "add	x21, %x[ind], x21\n\t"
        "ld1	{v2.8h}, [x21]\n\t"
        "cmeq	v2.8h, v2.8h, v0.8h\n\t"
        "orr	v1.16b, v1.16b, v2.16b\n\t"
        "add	x15, x15, #8\n\t"
        "b	L_mc_fw_dupj8_%=\n\t"
        "\n"
    "L_mc_fw_duprem_%=:\n\t"
        "umaxv	h2, v1.8h\n\t"
        "umov	w21, v2.h[0]\n\t"
        "orr	x17, x17, x21\n\t"
        "\n"
    "L_mc_fw_duprem1_%=:\n\t"
        "cmp	x15, x14\n\t"
        "b.ge	L_mc_fw_dupie_%=\n\t"
        "lsl	x20, x15, #1\n\t"
        "add	x20, %x[ind], x20\n\t"
        "ldrh	w21, [x20]\n\t"
        "cmp	x21, x16\n\t"
        "cinc	x17, x17, eq\n\t"
        "add	x15, x15, #1\n\t"
        "b	L_mc_fw_duprem1_%=\n\t"
        "\n"
    "L_mc_fw_dupie_%=:\n\t"
        "add	x14, x14, #1\n\t"
        "b	L_mc_fw_dupi_%=\n\t"
        "\n"
    "L_mc_fw_dupd_%=:\n\t"
        "cbnz	x17, L_mc_fw_retry_%=\n\t"
        "mov	x19, #0\n\t"
        "b	L_mc_fw_ret_%=\n\t"
        "\n"
    "L_mc_fw_depl_%=:\n\t"
        "mov	x19, #2\n\t"
        "\n"
    "L_mc_fw_ret_%=:\n\t"
        "mov	%x[rand], x19\n\t"
        : [rand] "+r" (rand), [ind] "+r" (ind), [randLen] "+r" (randLen),
          [n] "+r" (n), [t] "+r" (t), [tau] "+r" (tau)
        :
        : "memory", "cc", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13",
            "x14", "x15", "x16", "x17", "x19", "x20", "x21", "x22", "x23", "v0",
            "v1", "v2"
    );
    return (word32)(size_t)rand;
}

WOLFSSL_LOCAL void wc_mceliece_encap_scatter_neon(byte* e_p,
    const word16* ind_p, int t_p, int nwords_p);
void wc_mceliece_encap_scatter_neon(byte* e_p, const word16* ind_p, int t_p,
    int nwords_p)
{
    register byte* e __asm__ ("x0") = (byte*)e_p;
    register const word16* ind __asm__ ("x1") = (const word16*)ind_p;
    register int t __asm__ ("w2") = (int)t_p;
    register int nwords __asm__ ("w3") = (int)nwords_p;
    __asm__ __volatile__ (
        "mov	w4, %w[t]\n\t"
        "mov	w5, %w[nwords]\n\t"
        "mov	x10, #1\n\t"
        "dup	v6.2d, x10\n\t"
        "mov	x10, #63\n\t"
        "dup	v7.2d, x10\n\t"
        "mov	x6, #0\n\t"
        "\n"
    "L_mc_sc_w_%=:\n\t"
        "cmp	x6, x5\n\t"
        "b.ge	L_mc_sc_end_%=\n\t"
        "eor	v0.16b, v0.16b, v0.16b\n\t"
        "dup	v8.2d, x6\n\t"
        "mov	x7, #0\n\t"
        "mov	x8, %x[ind]\n\t"
        "\n"
    "L_mc_sc_j2_%=:\n\t"
        "add	x10, x7, #2\n\t"
        "cmp	x10, x4\n\t"
        "b.gt	L_mc_sc_jtail_%=\n\t"
        "ldr	s1, [x8], #4\n\t"
        "ushll	v1.4s, v1.4h, #0\n\t"
        "ushll	v1.2d, v1.2s, #0\n\t"
        "and	v2.16b, v1.16b, v7.16b\n\t"
        "ushr	v3.2d, v1.2d, #6\n\t"
        "ushl	v4.2d, v6.2d, v2.2d\n\t"
        "cmeq	v5.2d, v3.2d, v8.2d\n\t"
        "and	v4.16b, v4.16b, v5.16b\n\t"
        "orr	v0.16b, v0.16b, v4.16b\n\t"
        "add	x7, x7, #2\n\t"
        "b	L_mc_sc_j2_%=\n\t"
        "\n"
    "L_mc_sc_jtail_%=:\n\t"
        "umov	x9, v0.d[0]\n\t"
        "umov	x10, v0.d[1]\n\t"
        "orr	x9, x9, x10\n\t"
        "cmp	x7, x4\n\t"
        "b.ge	L_mc_sc_store_%=\n\t"
        "\n"
    "L_mc_sc_tail1_%=:\n\t"
        "ldrh	w10, [x8]\n\t"
        "add	x8, x8, #2\n\t"
        "and	x11, x10, #63\n\t"
        "lsr	x12, x10, #6\n\t"
        "mov	x13, #1\n\t"
        "lsl	x13, x13, x11\n\t"
        "cmp	x12, x6\n\t"
        "csel	x13, x13, xzr, eq\n\t"
        "orr	x9, x9, x13\n\t"
        "add	x7, x7, #1\n\t"
        "cmp	x7, x4\n\t"
        "b.lt	L_mc_sc_tail1_%=\n\t"
        "\n"
    "L_mc_sc_store_%=:\n\t"
        "lsl	x10, x6, #3\n\t"
        "add	x10, %x[e], x10\n\t"
        "str	x9, [x10]\n\t"
        "add	x6, x6, #1\n\t"
        "b	L_mc_sc_w_%=\n\t"
        "\n"
    "L_mc_sc_end_%=:\n\t"
        : [e] "+r" (e), [t] "+r" (t), [nwords] "+r" (nwords)
        : [ind] "r" (ind)
        : "memory", "cc", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11",
            "x12", "x13", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8"
    );
}

WOLFSSL_LOCAL void wc_mceliece_encap_syndrome_neon(const byte* pk_p,
    const byte* e_p, byte* c0_p, byte* row_p, int mt_p, int rowBytes_p);
void wc_mceliece_encap_syndrome_neon(const byte* pk_p, const byte* e_p,
    byte* c0_p, byte* row_p, int mt_p, int rowBytes_p)
{
    register const byte* pk __asm__ ("x0") = (const byte*)pk_p;
    register const byte* e __asm__ ("x1") = (const byte*)e_p;
    register byte* c0 __asm__ ("x2") = (byte*)c0_p;
    register byte* row __asm__ ("x3") = (byte*)row_p;
    register int mt __asm__ ("w4") = (int)mt_p;
    register int rowBytes __asm__ ("w5") = (int)rowBytes_p;
    __asm__ __volatile__ (
        "mov	w6, %w[mt]\n\t"
        "mov	w7, %w[rowBytes]\n\t"
        "and	x8, x6, #7\n\t"
        "lsr	x9, x6, #3\n\t"
        "cbz	x8, L_mc_syn_notail_%=\n\t"
        "mov	x10, %x[row]\n\t"
        "add	x13, %x[e], x9\n\t"
        "mov	x16, #0\n\t"
        "sub	x20, x7, #1\n\t"
        "mov	x21, #8\n\t"
        "sub	x21, x21, x8\n\t"
        "\n"
    "L_mc_syn_bld_%=:\n\t"
        "cmp	x16, x7\n\t"
        "b.ge	L_mc_syn_main_%=\n\t"
        "add	x22, x13, x16\n\t"
        "ldrb	w22, [x22]\n\t"
        "lsr	x22, x22, x8\n\t"
        "cmp	x16, x20\n\t"
        "b.ge	L_mc_syn_bldhi0_%=\n\t"
        "add	x23, x13, x16\n\t"
        "add	x23, x23, #1\n\t"
        "ldrb	w23, [x23]\n\t"
        "lsl	x23, x23, x21\n\t"
        "orr	x22, x22, x23\n\t"
        "\n"
    "L_mc_syn_bldhi0_%=:\n\t"
        "add	x23, %x[row], x16\n\t"
        "strb	w22, [x23]\n\t"
        "add	x16, x16, #1\n\t"
        "b	L_mc_syn_bld_%=\n\t"
        "\n"
    "L_mc_syn_notail_%=:\n\t"
        "add	x10, %x[e], x9\n\t"
        "\n"
    "L_mc_syn_main_%=:\n\t"
        "mov	x15, #0\n\t"
        "mov	x11, %x[pk]\n\t"
        "\n"
    "L_mc_syn_mainl_%=:\n\t"
        "cmp	x15, x9\n\t"
        "b.ge	L_mc_syn_tailbyte_%=\n\t"
        "mov	x19, #0\n\t"
        "mov	x17, #0\n\t"
        "mov	x12, x11\n\t"
        "\n"
    "L_mc_syn_rowl_%=:\n\t"
        "mov	x13, x10\n\t"
        "mov	x14, x7\n\t"
        "eor	v0.16b, v0.16b, v0.16b\n\t"
        "\n"
    "L_mc_syn_ap16_m_%=:\n\t"
        "cmp	x14, #16\n\t"
        "b.lt	L_mc_syn_apd_m_%=\n\t"
        "ld1	{v1.16b}, [x12], #16\n\t"
        "ld1	{v2.16b}, [x13], #16\n\t"
        "and	v1.16b, v1.16b, v2.16b\n\t"
        "eor	v0.16b, v0.16b, v1.16b\n\t"
        "sub	x14, x14, #16\n\t"
        "b	L_mc_syn_ap16_m_%=\n\t"
        "\n"
    "L_mc_syn_apd_m_%=:\n\t"
        "cmp	x14, #8\n\t"
        "b.lt	L_mc_syn_ap8_m_%=\n\t"
        "ldr	d1, [x12], #8\n\t"
        "ldr	d2, [x13], #8\n\t"
        "and	v1.16b, v1.16b, v2.16b\n\t"
        "eor	v0.16b, v0.16b, v1.16b\n\t"
        "sub	x14, x14, #8\n\t"
        "\n"
    "L_mc_syn_ap8_m_%=:\n\t"
        "cmp	x14, #4\n\t"
        "b.lt	L_mc_syn_ap4_m_%=\n\t"
        "ldr	s1, [x12], #4\n\t"
        "ldr	s2, [x13], #4\n\t"
        "and	v1.16b, v1.16b, v2.16b\n\t"
        "eor	v0.16b, v0.16b, v1.16b\n\t"
        "sub	x14, x14, #4\n\t"
        "\n"
    "L_mc_syn_ap4_m_%=:\n\t"
        "cmp	x14, #2\n\t"
        "b.lt	L_mc_syn_ap2_m_%=\n\t"
        "ldr	h1, [x12], #2\n\t"
        "ldr	h2, [x13], #2\n\t"
        "and	v1.16b, v1.16b, v2.16b\n\t"
        "eor	v0.16b, v0.16b, v1.16b\n\t"
        "sub	x14, x14, #2\n\t"
        "\n"
    "L_mc_syn_ap2_m_%=:\n\t"
        "cmp	x14, #1\n\t"
        "b.lt	L_mc_syn_ap1_m_%=\n\t"
        "ldr	b1, [x12], #1\n\t"
        "ldr	b2, [x13], #1\n\t"
        "and	v1.16b, v1.16b, v2.16b\n\t"
        "eor	v0.16b, v0.16b, v1.16b\n\t"
        "sub	x14, x14, #1\n\t"
        "\n"
    "L_mc_syn_ap1_m_%=:\n\t"
        "cnt	v0.16b, v0.16b\n\t"
        "uaddlv	h3, v0.16b\n\t"
        "umov	w20, v3.h[0]\n\t"
        "and	x20, x20, #1\n\t"
        "lsl	x20, x20, x17\n\t"
        "orr	x19, x19, x20\n\t"
        "add	x17, x17, #1\n\t"
        "cmp	x17, #8\n\t"
        "b.lt	L_mc_syn_rowl_%=\n\t"
        "mov	x11, x12\n\t"
        "add	x21, %x[e], x15\n\t"
        "ldrb	w21, [x21]\n\t"
        "eor	x19, x19, x21\n\t"
        "add	x22, %x[c0], x15\n\t"
        "strb	w19, [x22]\n\t"
        "add	x15, x15, #1\n\t"
        "b	L_mc_syn_mainl_%=\n\t"
        "\n"
    "L_mc_syn_tailbyte_%=:\n\t"
        "cbz	x8, L_mc_syn_end_%=\n\t"
        "mov	x19, #0\n\t"
        "mov	x17, #0\n\t"
        "add	x23, %x[e], x9\n\t"
        "ldrb	w23, [x23]\n\t"
        "\n"
    "L_mc_syn_taill_%=:\n\t"
        "mov	x12, x11\n\t"
        "mov	x13, x10\n\t"
        "mov	x14, x7\n\t"
        "eor	v0.16b, v0.16b, v0.16b\n\t"
        "\n"
    "L_mc_syn_ap16_t_%=:\n\t"
        "cmp	x14, #16\n\t"
        "b.lt	L_mc_syn_apd_t_%=\n\t"
        "ld1	{v1.16b}, [x12], #16\n\t"
        "ld1	{v2.16b}, [x13], #16\n\t"
        "and	v1.16b, v1.16b, v2.16b\n\t"
        "eor	v0.16b, v0.16b, v1.16b\n\t"
        "sub	x14, x14, #16\n\t"
        "b	L_mc_syn_ap16_t_%=\n\t"
        "\n"
    "L_mc_syn_apd_t_%=:\n\t"
        "cmp	x14, #8\n\t"
        "b.lt	L_mc_syn_ap8_t_%=\n\t"
        "ldr	d1, [x12], #8\n\t"
        "ldr	d2, [x13], #8\n\t"
        "and	v1.16b, v1.16b, v2.16b\n\t"
        "eor	v0.16b, v0.16b, v1.16b\n\t"
        "sub	x14, x14, #8\n\t"
        "\n"
    "L_mc_syn_ap8_t_%=:\n\t"
        "cmp	x14, #4\n\t"
        "b.lt	L_mc_syn_ap4_t_%=\n\t"
        "ldr	s1, [x12], #4\n\t"
        "ldr	s2, [x13], #4\n\t"
        "and	v1.16b, v1.16b, v2.16b\n\t"
        "eor	v0.16b, v0.16b, v1.16b\n\t"
        "sub	x14, x14, #4\n\t"
        "\n"
    "L_mc_syn_ap4_t_%=:\n\t"
        "cmp	x14, #2\n\t"
        "b.lt	L_mc_syn_ap2_t_%=\n\t"
        "ldr	h1, [x12], #2\n\t"
        "ldr	h2, [x13], #2\n\t"
        "and	v1.16b, v1.16b, v2.16b\n\t"
        "eor	v0.16b, v0.16b, v1.16b\n\t"
        "sub	x14, x14, #2\n\t"
        "\n"
    "L_mc_syn_ap2_t_%=:\n\t"
        "cmp	x14, #1\n\t"
        "b.lt	L_mc_syn_ap1_t_%=\n\t"
        "ldr	b1, [x12], #1\n\t"
        "ldr	b2, [x13], #1\n\t"
        "and	v1.16b, v1.16b, v2.16b\n\t"
        "eor	v0.16b, v0.16b, v1.16b\n\t"
        "sub	x14, x14, #1\n\t"
        "\n"
    "L_mc_syn_ap1_t_%=:\n\t"
        "cnt	v0.16b, v0.16b\n\t"
        "uaddlv	h3, v0.16b\n\t"
        "umov	w20, v3.h[0]\n\t"
        "and	x20, x20, #1\n\t"
        "lsr	x21, x23, x17\n\t"
        "and	x21, x21, #1\n\t"
        "eor	x20, x20, x21\n\t"
        "lsl	x20, x20, x17\n\t"
        "orr	x19, x19, x20\n\t"
        "add	x11, x11, x7\n\t"
        "add	x17, x17, #1\n\t"
        "cmp	x17, x8\n\t"
        "b.lt	L_mc_syn_taill_%=\n\t"
        "add	x22, %x[c0], x9\n\t"
        "strb	w19, [x22]\n\t"
        "\n"
    "L_mc_syn_end_%=:\n\t"
        : [c0] "+r" (c0), [row] "+r" (row), [mt] "+r" (mt),
          [rowBytes] "+r" (rowBytes)
        : [pk] "r" (pk), [e] "r" (e)
        : "memory", "cc", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13",
            "x14", "x15", "x16", "x17", "x19", "x20", "x21", "x22", "x23", "v0",
            "v1", "v2", "v3"
    );
}

#endif /* WOLFSSL_MCELIECE_SMALL */
#endif /* WOLFSSL_MCELIECE_NO_ENCAPSULATE */
#ifndef WOLFSSL_MCELIECE_NO_DECAPSULATE
#ifndef WOLFSSL_MCELIECE_SMALL
WOLFSSL_LOCAL void wc_mceliece_transpose_64x64_neon(word64* out_p,
    const word64* in_p);
void wc_mceliece_transpose_64x64_neon(word64* out_p, const word64* in_p)
{
    register word64* out __asm__ ("x0") = (word64*)out_p;
    register const word64* in __asm__ ("x1") = (const word64*)in_p;
    __asm__ __volatile__ (
        "mov	x2, %x[out]\n\t"
        "mov	x3, %x[in]\n\t"
        "mov	x4, #0x200\n\t"
        "\n"
    "L_mc_tr_copy_%=:\n\t"
        "ld1	{v0.16b}, [x3], #16\n\t"
        "st1	{v0.16b}, [x2], #16\n\t"
        "sub	x4, x4, #16\n\t"
        "cbnz	x4, L_mc_tr_copy_%=\n\t"
        "mov	x9, #0xffffffff\n\t"
        "dup	v6.2d, x9\n\t"
        "mov	x5, #0\n\t"
        "\n"
    "L_mc_tr_i5_%=:\n\t"
        "cmp	x5, #0x40\n\t"
        "b.ge	L_mc_tr_e5_%=\n\t"
        "mov	x6, #0\n\t"
        "\n"
    "L_mc_tr_k5_%=:\n\t"
        "cmp	x6, #32\n\t"
        "b.ge	L_mc_tr_ni5_%=\n\t"
        "add	x10, x5, x6\n\t"
        "lsl	x10, x10, #3\n\t"
        "add	x7, %x[out], x10\n\t"
        "add	x8, x7, #0x100\n\t"
        "ld1	{v0.2d}, [x7]\n\t"
        "ld1	{v1.2d}, [x8]\n\t"
        "and	v2.16b, v0.16b, v6.16b\n\t"
        "and	v3.16b, v1.16b, v6.16b\n\t"
        "shl	v3.2d, v3.2d, #32\n\t"
        "orr	v2.16b, v2.16b, v3.16b\n\t"
        "bic	v4.16b, v0.16b, v6.16b\n\t"
        "ushr	v4.2d, v4.2d, #32\n\t"
        "bic	v5.16b, v1.16b, v6.16b\n\t"
        "orr	v4.16b, v4.16b, v5.16b\n\t"
        "st1	{v2.2d}, [x7]\n\t"
        "st1	{v4.2d}, [x8]\n\t"
        "add	x6, x6, #2\n\t"
        "b	L_mc_tr_k5_%=\n\t"
        "\n"
    "L_mc_tr_ni5_%=:\n\t"
        "add	x5, x5, #0x40\n\t"
        "b	L_mc_tr_i5_%=\n\t"
        "\n"
    "L_mc_tr_e5_%=:\n\t"
        "mov	x9, #0xffff0000ffff\n\t"
        "dup	v6.2d, x9\n\t"
        "mov	x5, #0\n\t"
        "\n"
    "L_mc_tr_i4_%=:\n\t"
        "cmp	x5, #0x40\n\t"
        "b.ge	L_mc_tr_e4_%=\n\t"
        "mov	x6, #0\n\t"
        "\n"
    "L_mc_tr_k4_%=:\n\t"
        "cmp	x6, #16\n\t"
        "b.ge	L_mc_tr_ni4_%=\n\t"
        "add	x10, x5, x6\n\t"
        "lsl	x10, x10, #3\n\t"
        "add	x7, %x[out], x10\n\t"
        "add	x8, x7, #0x80\n\t"
        "ld1	{v0.2d}, [x7]\n\t"
        "ld1	{v1.2d}, [x8]\n\t"
        "and	v2.16b, v0.16b, v6.16b\n\t"
        "and	v3.16b, v1.16b, v6.16b\n\t"
        "shl	v3.2d, v3.2d, #16\n\t"
        "orr	v2.16b, v2.16b, v3.16b\n\t"
        "bic	v4.16b, v0.16b, v6.16b\n\t"
        "ushr	v4.2d, v4.2d, #16\n\t"
        "bic	v5.16b, v1.16b, v6.16b\n\t"
        "orr	v4.16b, v4.16b, v5.16b\n\t"
        "st1	{v2.2d}, [x7]\n\t"
        "st1	{v4.2d}, [x8]\n\t"
        "add	x6, x6, #2\n\t"
        "b	L_mc_tr_k4_%=\n\t"
        "\n"
    "L_mc_tr_ni4_%=:\n\t"
        "add	x5, x5, #32\n\t"
        "b	L_mc_tr_i4_%=\n\t"
        "\n"
    "L_mc_tr_e4_%=:\n\t"
        "mov	x9, #0xff00ff00ff00ff\n\t"
        "dup	v6.2d, x9\n\t"
        "mov	x5, #0\n\t"
        "\n"
    "L_mc_tr_i3_%=:\n\t"
        "cmp	x5, #0x40\n\t"
        "b.ge	L_mc_tr_e3_%=\n\t"
        "mov	x6, #0\n\t"
        "\n"
    "L_mc_tr_k3_%=:\n\t"
        "cmp	x6, #8\n\t"
        "b.ge	L_mc_tr_ni3_%=\n\t"
        "add	x10, x5, x6\n\t"
        "lsl	x10, x10, #3\n\t"
        "add	x7, %x[out], x10\n\t"
        "add	x8, x7, #0x40\n\t"
        "ld1	{v0.2d}, [x7]\n\t"
        "ld1	{v1.2d}, [x8]\n\t"
        "and	v2.16b, v0.16b, v6.16b\n\t"
        "and	v3.16b, v1.16b, v6.16b\n\t"
        "shl	v3.2d, v3.2d, #8\n\t"
        "orr	v2.16b, v2.16b, v3.16b\n\t"
        "bic	v4.16b, v0.16b, v6.16b\n\t"
        "ushr	v4.2d, v4.2d, #8\n\t"
        "bic	v5.16b, v1.16b, v6.16b\n\t"
        "orr	v4.16b, v4.16b, v5.16b\n\t"
        "st1	{v2.2d}, [x7]\n\t"
        "st1	{v4.2d}, [x8]\n\t"
        "add	x6, x6, #2\n\t"
        "b	L_mc_tr_k3_%=\n\t"
        "\n"
    "L_mc_tr_ni3_%=:\n\t"
        "add	x5, x5, #16\n\t"
        "b	L_mc_tr_i3_%=\n\t"
        "\n"
    "L_mc_tr_e3_%=:\n\t"
        "mov	x9, #0xf0f0f0f0f0f0f0f\n\t"
        "dup	v6.2d, x9\n\t"
        "mov	x5, #0\n\t"
        "\n"
    "L_mc_tr_i2_%=:\n\t"
        "cmp	x5, #0x40\n\t"
        "b.ge	L_mc_tr_e2_%=\n\t"
        "mov	x6, #0\n\t"
        "\n"
    "L_mc_tr_k2_%=:\n\t"
        "cmp	x6, #4\n\t"
        "b.ge	L_mc_tr_ni2_%=\n\t"
        "add	x10, x5, x6\n\t"
        "lsl	x10, x10, #3\n\t"
        "add	x7, %x[out], x10\n\t"
        "add	x8, x7, #32\n\t"
        "ld1	{v0.2d}, [x7]\n\t"
        "ld1	{v1.2d}, [x8]\n\t"
        "and	v2.16b, v0.16b, v6.16b\n\t"
        "and	v3.16b, v1.16b, v6.16b\n\t"
        "shl	v3.2d, v3.2d, #4\n\t"
        "orr	v2.16b, v2.16b, v3.16b\n\t"
        "bic	v4.16b, v0.16b, v6.16b\n\t"
        "ushr	v4.2d, v4.2d, #4\n\t"
        "bic	v5.16b, v1.16b, v6.16b\n\t"
        "orr	v4.16b, v4.16b, v5.16b\n\t"
        "st1	{v2.2d}, [x7]\n\t"
        "st1	{v4.2d}, [x8]\n\t"
        "add	x6, x6, #2\n\t"
        "b	L_mc_tr_k2_%=\n\t"
        "\n"
    "L_mc_tr_ni2_%=:\n\t"
        "add	x5, x5, #8\n\t"
        "b	L_mc_tr_i2_%=\n\t"
        "\n"
    "L_mc_tr_e2_%=:\n\t"
        "mov	x9, #0x3333333333333333\n\t"
        "dup	v6.2d, x9\n\t"
        "mov	x5, #0\n\t"
        "\n"
    "L_mc_tr_i1_%=:\n\t"
        "cmp	x5, #0x40\n\t"
        "b.ge	L_mc_tr_e1_%=\n\t"
        "mov	x6, #0\n\t"
        "\n"
    "L_mc_tr_k1_%=:\n\t"
        "cmp	x6, #2\n\t"
        "b.ge	L_mc_tr_ni1_%=\n\t"
        "add	x10, x5, x6\n\t"
        "lsl	x10, x10, #3\n\t"
        "add	x7, %x[out], x10\n\t"
        "add	x8, x7, #16\n\t"
        "ld1	{v0.2d}, [x7]\n\t"
        "ld1	{v1.2d}, [x8]\n\t"
        "and	v2.16b, v0.16b, v6.16b\n\t"
        "and	v3.16b, v1.16b, v6.16b\n\t"
        "shl	v3.2d, v3.2d, #2\n\t"
        "orr	v2.16b, v2.16b, v3.16b\n\t"
        "bic	v4.16b, v0.16b, v6.16b\n\t"
        "ushr	v4.2d, v4.2d, #2\n\t"
        "bic	v5.16b, v1.16b, v6.16b\n\t"
        "orr	v4.16b, v4.16b, v5.16b\n\t"
        "st1	{v2.2d}, [x7]\n\t"
        "st1	{v4.2d}, [x8]\n\t"
        "add	x6, x6, #2\n\t"
        "b	L_mc_tr_k1_%=\n\t"
        "\n"
    "L_mc_tr_ni1_%=:\n\t"
        "add	x5, x5, #4\n\t"
        "b	L_mc_tr_i1_%=\n\t"
        "\n"
    "L_mc_tr_e1_%=:\n\t"
        "mov	x9, #0x5555555555555555\n\t"
        "dup	v6.2d, x9\n\t"
        "mov	x5, #0\n\t"
        "\n"
    "L_mc_tr_sc0_%=:\n\t"
        "cmp	x5, #0x40\n\t"
        "b.ge	L_mc_tr_e0_%=\n\t"
        "lsl	x10, x5, #3\n\t"
        "add	x7, %x[out], x10\n\t"
        "ldr	x10, [x7]\n\t"
        "ldr	x11, [x7, #8]\n\t"
        "and	x12, x10, x9\n\t"
        "and	x13, x11, x9\n\t"
        "lsl	x13, x13, #1\n\t"
        "orr	x12, x12, x13\n\t"
        "bic	x13, x10, x9\n\t"
        "lsr	x13, x13, #1\n\t"
        "bic	x10, x11, x9\n\t"
        "orr	x13, x13, x10\n\t"
        "str	x12, [x7]\n\t"
        "str	x13, [x7, #8]\n\t"
        "add	x5, x5, #2\n\t"
        "b	L_mc_tr_sc0_%=\n\t"
        "\n"
    "L_mc_tr_e0_%=:\n\t"
        : [out] "+r" (out)
        : [in] "r" (in)
        : "memory", "cc", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
            "x11", "x12", "x13", "v0", "v1", "v2", "v3", "v4", "v5", "v6"
    );
}

WOLFSSL_LOCAL void wc_mceliece_layer_in_neon(word64* data_p,
    const word64* bits_p, int lgs_p);
void wc_mceliece_layer_in_neon(word64* data_p, const word64* bits_p, int lgs_p)
{
    register word64* data __asm__ ("x0") = (word64*)data_p;
    register const word64* bits __asm__ ("x1") = (const word64*)bits_p;
    register int lgs __asm__ ("w2") = (int)lgs_p;
    __asm__ __volatile__ (
        "mov	x12, #1\n\t"
        "mov	w3, %w[lgs]\n\t"
        "lsl	x4, x12, x3\n\t"
        "cmp	x4, #1\n\t"
        "b.eq	L_mc_lin_sc_%=\n\t"
        "lsl	x5, x4, #3\n\t"
        "mov	x6, #0\n\t"
        "\n"
    "L_mc_lin_i_%=:\n\t"
        "cmp	x6, #0x40\n\t"
        "b.ge	L_mc_lin_done_%=\n\t"
        "mov	x7, x6\n\t"
        "add	x12, x6, x4\n\t"
        "\n"
    "L_mc_lin_j_%=:\n\t"
        "cmp	x7, x12\n\t"
        "b.ge	L_mc_lin_ni_%=\n\t"
        "lsl	x13, x7, #3\n\t"
        "add	x8, %x[data], x13\n\t"
        "add	x9, x8, #0x200\n\t"
        "add	x10, x8, x5\n\t"
        "add	x11, x9, x5\n\t"
        "ld1	{v0.2d}, [x8]\n\t"
        "ld1	{v1.2d}, [x10]\n\t"
        "ld1	{v2.2d}, [x9]\n\t"
        "ld1	{v3.2d}, [x11]\n\t"
        "ld2	{v5.2d, v6.2d}, [%x[bits]], #32\n\t"
        "eor	v4.16b, v0.16b, v1.16b\n\t"
        "and	v4.16b, v4.16b, v5.16b\n\t"
        "eor	v0.16b, v0.16b, v4.16b\n\t"
        "eor	v1.16b, v1.16b, v4.16b\n\t"
        "eor	v4.16b, v2.16b, v3.16b\n\t"
        "and	v4.16b, v4.16b, v6.16b\n\t"
        "eor	v2.16b, v2.16b, v4.16b\n\t"
        "eor	v3.16b, v3.16b, v4.16b\n\t"
        "st1	{v0.2d}, [x8]\n\t"
        "st1	{v1.2d}, [x10]\n\t"
        "st1	{v2.2d}, [x9]\n\t"
        "st1	{v3.2d}, [x11]\n\t"
        "add	x7, x7, #2\n\t"
        "b	L_mc_lin_j_%=\n\t"
        "\n"
    "L_mc_lin_ni_%=:\n\t"
        "add	x13, x4, x4\n\t"
        "add	x6, x6, x13\n\t"
        "b	L_mc_lin_i_%=\n\t"
        "\n"
    "L_mc_lin_sc_%=:\n\t"
        "mov	x6, #0\n\t"
        "\n"
    "L_mc_lin_sl_%=:\n\t"
        "cmp	x6, #0x40\n\t"
        "b.ge	L_mc_lin_done_%=\n\t"
        "lsl	x10, x6, #3\n\t"
        "add	x8, %x[data], x10\n\t"
        "add	x9, x8, #0x200\n\t"
        "ldr	x12, [x8]\n\t"
        "ldr	x13, [x8, #8]\n\t"
        "ldr	x4, [%x[bits]], #8\n\t"
        "eor	x5, x12, x13\n\t"
        "and	x5, x5, x4\n\t"
        "eor	x12, x12, x5\n\t"
        "eor	x13, x13, x5\n\t"
        "str	x12, [x8]\n\t"
        "str	x13, [x8, #8]\n\t"
        "ldr	x12, [x9]\n\t"
        "ldr	x13, [x9, #8]\n\t"
        "ldr	x4, [%x[bits]], #8\n\t"
        "eor	x5, x12, x13\n\t"
        "and	x5, x5, x4\n\t"
        "eor	x12, x12, x5\n\t"
        "eor	x13, x13, x5\n\t"
        "str	x12, [x9]\n\t"
        "str	x13, [x9, #8]\n\t"
        "add	x6, x6, #2\n\t"
        "b	L_mc_lin_sl_%=\n\t"
        "\n"
    "L_mc_lin_done_%=:\n\t"
        : [data] "+r" (data), [lgs] "+r" (lgs)
        : [bits] "r" (bits)
        : "memory", "cc", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
            "x11", "x12", "x13", "v0", "v1", "v2", "v3", "v4", "v5", "v6"
    );
}

WOLFSSL_LOCAL void wc_mceliece_layer_ex_neon(word64* data_p,
    const word64* bits_p, int lgs_p);
void wc_mceliece_layer_ex_neon(word64* data_p, const word64* bits_p, int lgs_p)
{
    register word64* data __asm__ ("x0") = (word64*)data_p;
    register const word64* bits __asm__ ("x1") = (const word64*)bits_p;
    register int lgs __asm__ ("w2") = (int)lgs_p;
    __asm__ __volatile__ (
        "mov	x10, #1\n\t"
        "mov	w3, %w[lgs]\n\t"
        "lsl	x4, x10, x3\n\t"
        "cmp	x4, #1\n\t"
        "b.eq	L_mc_lex_sc_%=\n\t"
        "lsl	x5, x4, #3\n\t"
        "mov	x6, #0\n\t"
        "\n"
    "L_mc_lex_i_%=:\n\t"
        "cmp	x6, #0x80\n\t"
        "b.ge	L_mc_lex_done_%=\n\t"
        "mov	x7, #0\n\t"
        "\n"
    "L_mc_lex_k_%=:\n\t"
        "cmp	x7, x4\n\t"
        "b.ge	L_mc_lex_ni_%=\n\t"
        "add	x10, x6, x7\n\t"
        "lsl	x10, x10, #3\n\t"
        "add	x8, %x[data], x10\n\t"
        "add	x9, x8, x5\n\t"
        "ld1	{v0.2d}, [x8]\n\t"
        "ld1	{v1.2d}, [x9]\n\t"
        "ld1	{v3.2d}, [%x[bits]], #16\n\t"
        "eor	v2.16b, v0.16b, v1.16b\n\t"
        "and	v2.16b, v2.16b, v3.16b\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v2.16b\n\t"
        "st1	{v0.2d}, [x8]\n\t"
        "st1	{v1.2d}, [x9]\n\t"
        "add	x7, x7, #2\n\t"
        "b	L_mc_lex_k_%=\n\t"
        "\n"
    "L_mc_lex_ni_%=:\n\t"
        "add	x10, x4, x4\n\t"
        "add	x6, x6, x10\n\t"
        "b	L_mc_lex_i_%=\n\t"
        "\n"
    "L_mc_lex_sc_%=:\n\t"
        "mov	x6, #0\n\t"
        "\n"
    "L_mc_lex_sl_%=:\n\t"
        "cmp	x6, #0x80\n\t"
        "b.ge	L_mc_lex_done_%=\n\t"
        "lsl	x10, x6, #3\n\t"
        "add	x8, %x[data], x10\n\t"
        "ldr	x10, [x8]\n\t"
        "ldr	x11, [x8, #8]\n\t"
        "ldr	x12, [%x[bits]], #8\n\t"
        "eor	x13, x10, x11\n\t"
        "and	x13, x13, x12\n\t"
        "eor	x10, x10, x13\n\t"
        "eor	x11, x11, x13\n\t"
        "str	x10, [x8]\n\t"
        "str	x11, [x8, #8]\n\t"
        "add	x6, x6, #2\n\t"
        "b	L_mc_lex_sl_%=\n\t"
        "\n"
    "L_mc_lex_done_%=:\n\t"
        : [data] "+r" (data), [lgs] "+r" (lgs)
        : [bits] "r" (bits)
        : "memory", "cc", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
            "x11", "x12", "x13", "v0", "v1", "v2", "v3"
    );
}

WOLFSSL_LOCAL void wc_mceliece_apply_benes_neon(byte* r_p, const byte* bits_p,
    int rev_p, word64* work_p);
void wc_mceliece_apply_benes_neon(byte* r_p, const byte* bits_p, int rev_p,
    word64* work_p)
{
    register byte* r __asm__ ("x0") = (byte*)r_p;
    register const byte* bits __asm__ ("x1") = (const byte*)bits_p;
    register int rev __asm__ ("w2") = (int)rev_p;
    register word64* work __asm__ ("x3") = (word64*)work_p;
    __asm__ __volatile__ (
        "mov	x19, %x[r]\n\t"
        "mov	x20, %x[work]\n\t"
        "mov	x21, %x[bits]\n\t"
        "mov	x22, #0\n\t"
        "cbz	%w[rev], L_mc_ab_norev_%=\n\t"
        "mov	x5, #0x3000\n\t"
        "add	x21, x21, x5\n\t"
        "mov	x22, #0x400\n\t"
        "neg	x22, x22\n\t"
        "\n"
    "L_mc_ab_norev_%=:\n\t"
        "mov	x4, #0\n\t"
        "\n"
    "L_mc_ab_rl_%=:\n\t"
        "cmp	x4, #0x40\n\t"
        "b.ge	L_mc_ab_rle_%=\n\t"
        "lsl	x8, x4, #4\n\t"
        "add	x7, x19, x8\n\t"
        "ldr	x5, [x7]\n\t"
        "ldr	x6, [x7, #8]\n\t"
        "lsl	x8, x4, #3\n\t"
        "add	x7, x20, x8\n\t"
        "str	x5, [x7]\n\t"
        "str	x6, [x7, #512]\n\t"
        "add	x4, x4, #1\n\t"
        "b	L_mc_ab_rl_%=\n\t"
        "\n"
    "L_mc_ab_rle_%=:\n\t"
        "add	%x[r], x20, #0x400\n\t"
        "add	%x[bits], x20, #0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_transpose_64x64_neon\n\t"
#else
        "bl	_wc_mceliece_transpose_64x64_neon\n\t"
#endif /* __APPLE__ */
        "add	%x[r], x20, #0x600\n\t"
        "add	%x[bits], x20, #0x200\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_transpose_64x64_neon\n\t"
#else
        "bl	_wc_mceliece_transpose_64x64_neon\n\t"
#endif /* __APPLE__ */
        "mov	x23, #0\n\t"
        "\n"
    "L_mc_ab_x1_%=:\n\t"
        "cmp	x23, #6\n\t"
        "b.gt	L_mc_ab_x1e_%=\n\t"
        "mov	x4, #0\n\t"
        "\n"
    "L_mc_bnl_x1_%=:\n\t"
        "cmp	x4, #0x40\n\t"
        "b.ge	L_mc_bnle_x1_%=\n\t"
        "ldr	x5, [x21]\n\t"
        "lsl	x8, x4, #3\n\t"
        "add	x7, x20, x8\n\t"
        "str	x5, [x7, #2048]\n\t"
        "add	x21, x21, #8\n\t"
        "add	x4, x4, #1\n\t"
        "b	L_mc_bnl_x1_%=\n\t"
        "\n"
    "L_mc_bnle_x1_%=:\n\t"
        "add	x21, x21, x22\n\t"
        "add	%x[r], x20, #0xa00\n\t"
        "add	%x[bits], x20, #0x800\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_transpose_64x64_neon\n\t"
#else
        "bl	_wc_mceliece_transpose_64x64_neon\n\t"
#endif /* __APPLE__ */
        "add	%x[r], x20, #0x400\n\t"
        "add	%x[bits], x20, #0xa00\n\t"
        "mov	%w[rev], w23\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_layer_ex_neon\n\t"
#else
        "bl	_wc_mceliece_layer_ex_neon\n\t"
#endif /* __APPLE__ */
        "add	x23, x23, #1\n\t"
        "b	L_mc_ab_x1_%=\n\t"
        "\n"
    "L_mc_ab_x1e_%=:\n\t"
        "add	%x[r], x20, #0\n\t"
        "add	%x[bits], x20, #0x400\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_transpose_64x64_neon\n\t"
#else
        "bl	_wc_mceliece_transpose_64x64_neon\n\t"
#endif /* __APPLE__ */
        "add	%x[r], x20, #0x200\n\t"
        "add	%x[bits], x20, #0x600\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_transpose_64x64_neon\n\t"
#else
        "bl	_wc_mceliece_transpose_64x64_neon\n\t"
#endif /* __APPLE__ */
        "mov	x23, #0\n\t"
        "\n"
    "L_mc_ab_n1_%=:\n\t"
        "cmp	x23, #5\n\t"
        "b.gt	L_mc_ab_n1e_%=\n\t"
        "mov	x4, #0\n\t"
        "\n"
    "L_mc_bnl_n1_%=:\n\t"
        "cmp	x4, #0x40\n\t"
        "b.ge	L_mc_bnle_n1_%=\n\t"
        "ldr	x5, [x21]\n\t"
        "lsl	x8, x4, #3\n\t"
        "add	x7, x20, x8\n\t"
        "str	x5, [x7, #2048]\n\t"
        "add	x21, x21, #8\n\t"
        "add	x4, x4, #1\n\t"
        "b	L_mc_bnl_n1_%=\n\t"
        "\n"
    "L_mc_bnle_n1_%=:\n\t"
        "add	x21, x21, x22\n\t"
        "mov	%x[r], x20\n\t"
        "add	%x[bits], x20, #0x800\n\t"
        "mov	%w[rev], w23\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_layer_in_neon\n\t"
#else
        "bl	_wc_mceliece_layer_in_neon\n\t"
#endif /* __APPLE__ */
        "add	x23, x23, #1\n\t"
        "b	L_mc_ab_n1_%=\n\t"
        "\n"
    "L_mc_ab_n1e_%=:\n\t"
        "mov	x23, #4\n\t"
        "\n"
    "L_mc_ab_n2_%=:\n\t"
        "cmp	x23, #0\n\t"
        "b.lt	L_mc_ab_n2e_%=\n\t"
        "mov	x4, #0\n\t"
        "\n"
    "L_mc_bnl_n2_%=:\n\t"
        "cmp	x4, #0x40\n\t"
        "b.ge	L_mc_bnle_n2_%=\n\t"
        "ldr	x5, [x21]\n\t"
        "lsl	x8, x4, #3\n\t"
        "add	x7, x20, x8\n\t"
        "str	x5, [x7, #2048]\n\t"
        "add	x21, x21, #8\n\t"
        "add	x4, x4, #1\n\t"
        "b	L_mc_bnl_n2_%=\n\t"
        "\n"
    "L_mc_bnle_n2_%=:\n\t"
        "add	x21, x21, x22\n\t"
        "mov	%x[r], x20\n\t"
        "add	%x[bits], x20, #0x800\n\t"
        "mov	%w[rev], w23\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_layer_in_neon\n\t"
#else
        "bl	_wc_mceliece_layer_in_neon\n\t"
#endif /* __APPLE__ */
        "sub	x23, x23, #1\n\t"
        "b	L_mc_ab_n2_%=\n\t"
        "\n"
    "L_mc_ab_n2e_%=:\n\t"
        "add	%x[r], x20, #0x400\n\t"
        "add	%x[bits], x20, #0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_transpose_64x64_neon\n\t"
#else
        "bl	_wc_mceliece_transpose_64x64_neon\n\t"
#endif /* __APPLE__ */
        "add	%x[r], x20, #0x600\n\t"
        "add	%x[bits], x20, #0x200\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_transpose_64x64_neon\n\t"
#else
        "bl	_wc_mceliece_transpose_64x64_neon\n\t"
#endif /* __APPLE__ */
        "mov	x23, #6\n\t"
        "\n"
    "L_mc_ab_x2_%=:\n\t"
        "cmp	x23, #0\n\t"
        "b.lt	L_mc_ab_x2e_%=\n\t"
        "mov	x4, #0\n\t"
        "\n"
    "L_mc_bnl_x2_%=:\n\t"
        "cmp	x4, #0x40\n\t"
        "b.ge	L_mc_bnle_x2_%=\n\t"
        "ldr	x5, [x21]\n\t"
        "lsl	x8, x4, #3\n\t"
        "add	x7, x20, x8\n\t"
        "str	x5, [x7, #2048]\n\t"
        "add	x21, x21, #8\n\t"
        "add	x4, x4, #1\n\t"
        "b	L_mc_bnl_x2_%=\n\t"
        "\n"
    "L_mc_bnle_x2_%=:\n\t"
        "add	x21, x21, x22\n\t"
        "add	%x[r], x20, #0xa00\n\t"
        "add	%x[bits], x20, #0x800\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_transpose_64x64_neon\n\t"
#else
        "bl	_wc_mceliece_transpose_64x64_neon\n\t"
#endif /* __APPLE__ */
        "add	%x[r], x20, #0x400\n\t"
        "add	%x[bits], x20, #0xa00\n\t"
        "mov	%w[rev], w23\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_layer_ex_neon\n\t"
#else
        "bl	_wc_mceliece_layer_ex_neon\n\t"
#endif /* __APPLE__ */
        "sub	x23, x23, #1\n\t"
        "b	L_mc_ab_x2_%=\n\t"
        "\n"
    "L_mc_ab_x2e_%=:\n\t"
        "add	%x[r], x20, #0\n\t"
        "add	%x[bits], x20, #0x400\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_transpose_64x64_neon\n\t"
#else
        "bl	_wc_mceliece_transpose_64x64_neon\n\t"
#endif /* __APPLE__ */
        "add	%x[r], x20, #0x200\n\t"
        "add	%x[bits], x20, #0x600\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_transpose_64x64_neon\n\t"
#else
        "bl	_wc_mceliece_transpose_64x64_neon\n\t"
#endif /* __APPLE__ */
        "mov	x4, #0\n\t"
        "\n"
    "L_mc_ab_st_%=:\n\t"
        "cmp	x4, #0x40\n\t"
        "b.ge	L_mc_ab_ste_%=\n\t"
        "lsl	x8, x4, #3\n\t"
        "add	x7, x20, x8\n\t"
        "ldr	x5, [x7]\n\t"
        "ldr	x6, [x7, #512]\n\t"
        "lsl	x8, x4, #4\n\t"
        "add	x7, x19, x8\n\t"
        "str	x5, [x7]\n\t"
        "str	x6, [x7, #8]\n\t"
        "add	x4, x4, #1\n\t"
        "b	L_mc_ab_st_%=\n\t"
        "\n"
    "L_mc_ab_ste_%=:\n\t"
        : [r] "+r" (r), [bits] "+r" (bits), [rev] "+r" (rev),
          [work] "+r" (work)
        :
        : "memory", "cc", "x19", "x20", "x21", "x22", "x23", "x4", "x5", "x6",
            "x7", "x8", "x30"
    );
}

WOLFSSL_LOCAL int wc_mceliece_gf_discrepancy_neon(const word16* c_p,
    const word16* sn_p, int count_p);
int wc_mceliece_gf_discrepancy_neon(const word16* c_p, const word16* sn_p,
    int count_p)
{
    register const word16* c __asm__ ("x0") = (const word16*)c_p;
    register const word16* sn __asm__ ("x1") = (const word16*)sn_p;
    register int count __asm__ ("w2") = (int)count_p;
    __asm__ __volatile__ (
        "eor	v0.16b, v0.16b, v0.16b\n\t"
        "eor	v16.16b, v16.16b, v16.16b\n\t"
        "mov	x5, #0x1ff\n\t"
        "dup	v1.4s, w5\n\t"
        "shl	v1.4s, v1.4s, #16\n\t"
        "mov	x5, #0xe000\n\t"
        "dup	v2.4s, w5\n\t"
        "mov	x5, #0x1fff\n\t"
        "dup	v3.4s, w5\n\t"
        "mov	x3, #0\n\t"
        "\n"
    "L_mc_gdc_%=:\n\t"
        "cmp	w3, %w[count]\n\t"
        "b.ge	L_mc_gdce_%=\n\t"
        "lsl	x5, x3, #1\n\t"
        "add	x4, %x[c], x5\n\t"
        "ldr	q4, [x4]\n\t"
        "add	x5, x3, #7\n\t"
        "lsl	x5, x5, #1\n\t"
        "sub	x4, %x[sn], x5\n\t"
        "ldr	q5, [x4]\n\t"
        "rev64	v5.8h, v5.8h\n\t"
        "ext	v5.16b, v5.16b, v5.16b, #8\n\t"
        "zip1	v6.8h, v4.8h, v0.8h\n\t"
        "zip2	v7.8h, v4.8h, v0.8h\n\t"
        "zip1	v8.8h, v5.8h, v0.8h\n\t"
        "zip2	v9.8h, v5.8h, v0.8h\n\t"
        "shl	v13.4s, v8.4s, #31\n\t"
        "sshr	v13.4s, v13.4s, #31\n\t"
        "and	v10.16b, v6.16b, v13.16b\n\t"
        "shl	v13.4s, v8.4s, #30\n\t"
        "sshr	v13.4s, v13.4s, #31\n\t"
        "shl	v12.4s, v6.4s, #1\n\t"
        "and	v12.16b, v12.16b, v13.16b\n\t"
        "eor	v10.16b, v10.16b, v12.16b\n\t"
        "shl	v13.4s, v8.4s, #29\n\t"
        "sshr	v13.4s, v13.4s, #31\n\t"
        "shl	v12.4s, v6.4s, #2\n\t"
        "and	v12.16b, v12.16b, v13.16b\n\t"
        "eor	v10.16b, v10.16b, v12.16b\n\t"
        "shl	v13.4s, v8.4s, #28\n\t"
        "sshr	v13.4s, v13.4s, #31\n\t"
        "shl	v12.4s, v6.4s, #3\n\t"
        "and	v12.16b, v12.16b, v13.16b\n\t"
        "eor	v10.16b, v10.16b, v12.16b\n\t"
        "shl	v13.4s, v8.4s, #27\n\t"
        "sshr	v13.4s, v13.4s, #31\n\t"
        "shl	v12.4s, v6.4s, #4\n\t"
        "and	v12.16b, v12.16b, v13.16b\n\t"
        "eor	v10.16b, v10.16b, v12.16b\n\t"
        "shl	v13.4s, v8.4s, #26\n\t"
        "sshr	v13.4s, v13.4s, #31\n\t"
        "shl	v12.4s, v6.4s, #5\n\t"
        "and	v12.16b, v12.16b, v13.16b\n\t"
        "eor	v10.16b, v10.16b, v12.16b\n\t"
        "shl	v13.4s, v8.4s, #25\n\t"
        "sshr	v13.4s, v13.4s, #31\n\t"
        "shl	v12.4s, v6.4s, #6\n\t"
        "and	v12.16b, v12.16b, v13.16b\n\t"
        "eor	v10.16b, v10.16b, v12.16b\n\t"
        "shl	v13.4s, v8.4s, #24\n\t"
        "sshr	v13.4s, v13.4s, #31\n\t"
        "shl	v12.4s, v6.4s, #7\n\t"
        "and	v12.16b, v12.16b, v13.16b\n\t"
        "eor	v10.16b, v10.16b, v12.16b\n\t"
        "shl	v13.4s, v8.4s, #23\n\t"
        "sshr	v13.4s, v13.4s, #31\n\t"
        "shl	v12.4s, v6.4s, #8\n\t"
        "and	v12.16b, v12.16b, v13.16b\n\t"
        "eor	v10.16b, v10.16b, v12.16b\n\t"
        "shl	v13.4s, v8.4s, #22\n\t"
        "sshr	v13.4s, v13.4s, #31\n\t"
        "shl	v12.4s, v6.4s, #9\n\t"
        "and	v12.16b, v12.16b, v13.16b\n\t"
        "eor	v10.16b, v10.16b, v12.16b\n\t"
        "shl	v13.4s, v8.4s, #21\n\t"
        "sshr	v13.4s, v13.4s, #31\n\t"
        "shl	v12.4s, v6.4s, #10\n\t"
        "and	v12.16b, v12.16b, v13.16b\n\t"
        "eor	v10.16b, v10.16b, v12.16b\n\t"
        "shl	v13.4s, v8.4s, #20\n\t"
        "sshr	v13.4s, v13.4s, #31\n\t"
        "shl	v12.4s, v6.4s, #11\n\t"
        "and	v12.16b, v12.16b, v13.16b\n\t"
        "eor	v10.16b, v10.16b, v12.16b\n\t"
        "shl	v13.4s, v8.4s, #19\n\t"
        "sshr	v13.4s, v13.4s, #31\n\t"
        "shl	v12.4s, v6.4s, #12\n\t"
        "and	v12.16b, v12.16b, v13.16b\n\t"
        "eor	v10.16b, v10.16b, v12.16b\n\t"
        "and	v14.16b, v10.16b, v1.16b\n\t"
        "ushr	v15.4s, v14.4s, #9\n\t"
        "eor	v10.16b, v10.16b, v15.16b\n\t"
        "ushr	v15.4s, v14.4s, #10\n\t"
        "eor	v10.16b, v10.16b, v15.16b\n\t"
        "ushr	v15.4s, v14.4s, #12\n\t"
        "eor	v10.16b, v10.16b, v15.16b\n\t"
        "ushr	v15.4s, v14.4s, #13\n\t"
        "eor	v10.16b, v10.16b, v15.16b\n\t"
        "and	v14.16b, v10.16b, v2.16b\n\t"
        "ushr	v15.4s, v14.4s, #9\n\t"
        "eor	v10.16b, v10.16b, v15.16b\n\t"
        "ushr	v15.4s, v14.4s, #10\n\t"
        "eor	v10.16b, v10.16b, v15.16b\n\t"
        "ushr	v15.4s, v14.4s, #12\n\t"
        "eor	v10.16b, v10.16b, v15.16b\n\t"
        "ushr	v15.4s, v14.4s, #13\n\t"
        "eor	v10.16b, v10.16b, v15.16b\n\t"
        "and	v10.16b, v10.16b, v3.16b\n\t"
        "shl	v13.4s, v9.4s, #31\n\t"
        "sshr	v13.4s, v13.4s, #31\n\t"
        "and	v11.16b, v7.16b, v13.16b\n\t"
        "shl	v13.4s, v9.4s, #30\n\t"
        "sshr	v13.4s, v13.4s, #31\n\t"
        "shl	v12.4s, v7.4s, #1\n\t"
        "and	v12.16b, v12.16b, v13.16b\n\t"
        "eor	v11.16b, v11.16b, v12.16b\n\t"
        "shl	v13.4s, v9.4s, #29\n\t"
        "sshr	v13.4s, v13.4s, #31\n\t"
        "shl	v12.4s, v7.4s, #2\n\t"
        "and	v12.16b, v12.16b, v13.16b\n\t"
        "eor	v11.16b, v11.16b, v12.16b\n\t"
        "shl	v13.4s, v9.4s, #28\n\t"
        "sshr	v13.4s, v13.4s, #31\n\t"
        "shl	v12.4s, v7.4s, #3\n\t"
        "and	v12.16b, v12.16b, v13.16b\n\t"
        "eor	v11.16b, v11.16b, v12.16b\n\t"
        "shl	v13.4s, v9.4s, #27\n\t"
        "sshr	v13.4s, v13.4s, #31\n\t"
        "shl	v12.4s, v7.4s, #4\n\t"
        "and	v12.16b, v12.16b, v13.16b\n\t"
        "eor	v11.16b, v11.16b, v12.16b\n\t"
        "shl	v13.4s, v9.4s, #26\n\t"
        "sshr	v13.4s, v13.4s, #31\n\t"
        "shl	v12.4s, v7.4s, #5\n\t"
        "and	v12.16b, v12.16b, v13.16b\n\t"
        "eor	v11.16b, v11.16b, v12.16b\n\t"
        "shl	v13.4s, v9.4s, #25\n\t"
        "sshr	v13.4s, v13.4s, #31\n\t"
        "shl	v12.4s, v7.4s, #6\n\t"
        "and	v12.16b, v12.16b, v13.16b\n\t"
        "eor	v11.16b, v11.16b, v12.16b\n\t"
        "shl	v13.4s, v9.4s, #24\n\t"
        "sshr	v13.4s, v13.4s, #31\n\t"
        "shl	v12.4s, v7.4s, #7\n\t"
        "and	v12.16b, v12.16b, v13.16b\n\t"
        "eor	v11.16b, v11.16b, v12.16b\n\t"
        "shl	v13.4s, v9.4s, #23\n\t"
        "sshr	v13.4s, v13.4s, #31\n\t"
        "shl	v12.4s, v7.4s, #8\n\t"
        "and	v12.16b, v12.16b, v13.16b\n\t"
        "eor	v11.16b, v11.16b, v12.16b\n\t"
        "shl	v13.4s, v9.4s, #22\n\t"
        "sshr	v13.4s, v13.4s, #31\n\t"
        "shl	v12.4s, v7.4s, #9\n\t"
        "and	v12.16b, v12.16b, v13.16b\n\t"
        "eor	v11.16b, v11.16b, v12.16b\n\t"
        "shl	v13.4s, v9.4s, #21\n\t"
        "sshr	v13.4s, v13.4s, #31\n\t"
        "shl	v12.4s, v7.4s, #10\n\t"
        "and	v12.16b, v12.16b, v13.16b\n\t"
        "eor	v11.16b, v11.16b, v12.16b\n\t"
        "shl	v13.4s, v9.4s, #20\n\t"
        "sshr	v13.4s, v13.4s, #31\n\t"
        "shl	v12.4s, v7.4s, #11\n\t"
        "and	v12.16b, v12.16b, v13.16b\n\t"
        "eor	v11.16b, v11.16b, v12.16b\n\t"
        "shl	v13.4s, v9.4s, #19\n\t"
        "sshr	v13.4s, v13.4s, #31\n\t"
        "shl	v12.4s, v7.4s, #12\n\t"
        "and	v12.16b, v12.16b, v13.16b\n\t"
        "eor	v11.16b, v11.16b, v12.16b\n\t"
        "and	v14.16b, v11.16b, v1.16b\n\t"
        "ushr	v15.4s, v14.4s, #9\n\t"
        "eor	v11.16b, v11.16b, v15.16b\n\t"
        "ushr	v15.4s, v14.4s, #10\n\t"
        "eor	v11.16b, v11.16b, v15.16b\n\t"
        "ushr	v15.4s, v14.4s, #12\n\t"
        "eor	v11.16b, v11.16b, v15.16b\n\t"
        "ushr	v15.4s, v14.4s, #13\n\t"
        "eor	v11.16b, v11.16b, v15.16b\n\t"
        "and	v14.16b, v11.16b, v2.16b\n\t"
        "ushr	v15.4s, v14.4s, #9\n\t"
        "eor	v11.16b, v11.16b, v15.16b\n\t"
        "ushr	v15.4s, v14.4s, #10\n\t"
        "eor	v11.16b, v11.16b, v15.16b\n\t"
        "ushr	v15.4s, v14.4s, #12\n\t"
        "eor	v11.16b, v11.16b, v15.16b\n\t"
        "ushr	v15.4s, v14.4s, #13\n\t"
        "eor	v11.16b, v11.16b, v15.16b\n\t"
        "and	v11.16b, v11.16b, v3.16b\n\t"
        "uzp1	v17.8h, v10.8h, v11.8h\n\t"
        "eor	v16.16b, v16.16b, v17.16b\n\t"
        "add	x3, x3, #8\n\t"
        "b	L_mc_gdc_%=\n\t"
        "\n"
    "L_mc_gdce_%=:\n\t"
        "ext	v14.16b, v16.16b, v16.16b, #8\n\t"
        "eor	v16.16b, v16.16b, v14.16b\n\t"
        "ext	v14.16b, v16.16b, v16.16b, #4\n\t"
        "eor	v16.16b, v16.16b, v14.16b\n\t"
        "ext	v14.16b, v16.16b, v16.16b, #2\n\t"
        "eor	v16.16b, v16.16b, v14.16b\n\t"
        "umov	w6, v16.h[0]\n\t"
        "mov	%x[c], x6\n\t"
        : [c] "+r" (c), [count] "+r" (count)
        : [sn] "r" (sn)
        : "memory", "cc", "x3", "x4", "x5", "x6", "v0", "v1", "v2", "v3", "v4",
            "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14",
            "v15", "v16", "v17"
    );
    return (word32)(size_t)c;
}

WOLFSSL_LOCAL void wc_mceliece_synd_unpack_neon(word16* s_p, word64* synd_p,
    int count_p);
void wc_mceliece_synd_unpack_neon(word16* s_p, word64* synd_p, int count_p)
{
    register word16* s __asm__ ("x0") = (word16*)s_p;
    register word64* synd __asm__ ("x1") = (word64*)synd_p;
    register int count __asm__ ("w2") = (int)count_p;
    register const word16* L_mc_bs_powers_neon_c __asm__ ("x3") = L_mc_bs_powers_neon;
    __asm__ __volatile__ (
        "ldr	q0, [%[L_mc_bs_powers_neon_c]]\n\t"
        "movi	v1.8h, #1\n\t"
        "mov	w10, %w[count]\n\t"
        "lsr	x10, x10, #3\n\t"
        "mov	x4, #0\n\t"
        "\n"
    "L_mc_sunp_%=:\n\t"
        "cmp	x4, x10\n\t"
        "b.ge	L_mc_sunpe_%=\n\t"
        "lsr	x5, x4, #3\n\t"
        "lsl	x6, x5, #3\n\t"
        "and	x7, x4, #7\n\t"
        "lsl	x7, x7, #3\n\t"
        "eor	v4.16b, v4.16b, v4.16b\n\t"
        "add	x9, %x[synd], #0\n\t"
        "add	x9, x9, x6\n\t"
        "ldr	x8, [x9]\n\t"
        "lsr	x8, x8, x7\n\t"
        "dup	v2.8h, w8\n\t"
        "cmtst	v3.8h, v2.8h, v0.8h\n\t"
        "and	v3.16b, v3.16b, v1.16b\n\t"
        "orr	v4.16b, v4.16b, v3.16b\n\t"
        "add	x9, %x[synd], #32\n\t"
        "add	x9, x9, x6\n\t"
        "ldr	x8, [x9]\n\t"
        "lsr	x8, x8, x7\n\t"
        "dup	v2.8h, w8\n\t"
        "cmtst	v3.8h, v2.8h, v0.8h\n\t"
        "and	v3.16b, v3.16b, v1.16b\n\t"
        "shl	v3.8h, v3.8h, #1\n\t"
        "orr	v4.16b, v4.16b, v3.16b\n\t"
        "add	x9, %x[synd], #0x40\n\t"
        "add	x9, x9, x6\n\t"
        "ldr	x8, [x9]\n\t"
        "lsr	x8, x8, x7\n\t"
        "dup	v2.8h, w8\n\t"
        "cmtst	v3.8h, v2.8h, v0.8h\n\t"
        "and	v3.16b, v3.16b, v1.16b\n\t"
        "shl	v3.8h, v3.8h, #2\n\t"
        "orr	v4.16b, v4.16b, v3.16b\n\t"
        "add	x9, %x[synd], #0x60\n\t"
        "add	x9, x9, x6\n\t"
        "ldr	x8, [x9]\n\t"
        "lsr	x8, x8, x7\n\t"
        "dup	v2.8h, w8\n\t"
        "cmtst	v3.8h, v2.8h, v0.8h\n\t"
        "and	v3.16b, v3.16b, v1.16b\n\t"
        "shl	v3.8h, v3.8h, #3\n\t"
        "orr	v4.16b, v4.16b, v3.16b\n\t"
        "add	x9, %x[synd], #0x80\n\t"
        "add	x9, x9, x6\n\t"
        "ldr	x8, [x9]\n\t"
        "lsr	x8, x8, x7\n\t"
        "dup	v2.8h, w8\n\t"
        "cmtst	v3.8h, v2.8h, v0.8h\n\t"
        "and	v3.16b, v3.16b, v1.16b\n\t"
        "shl	v3.8h, v3.8h, #4\n\t"
        "orr	v4.16b, v4.16b, v3.16b\n\t"
        "add	x9, %x[synd], #0xa0\n\t"
        "add	x9, x9, x6\n\t"
        "ldr	x8, [x9]\n\t"
        "lsr	x8, x8, x7\n\t"
        "dup	v2.8h, w8\n\t"
        "cmtst	v3.8h, v2.8h, v0.8h\n\t"
        "and	v3.16b, v3.16b, v1.16b\n\t"
        "shl	v3.8h, v3.8h, #5\n\t"
        "orr	v4.16b, v4.16b, v3.16b\n\t"
        "add	x9, %x[synd], #0xc0\n\t"
        "add	x9, x9, x6\n\t"
        "ldr	x8, [x9]\n\t"
        "lsr	x8, x8, x7\n\t"
        "dup	v2.8h, w8\n\t"
        "cmtst	v3.8h, v2.8h, v0.8h\n\t"
        "and	v3.16b, v3.16b, v1.16b\n\t"
        "shl	v3.8h, v3.8h, #6\n\t"
        "orr	v4.16b, v4.16b, v3.16b\n\t"
        "add	x9, %x[synd], #0xe0\n\t"
        "add	x9, x9, x6\n\t"
        "ldr	x8, [x9]\n\t"
        "lsr	x8, x8, x7\n\t"
        "dup	v2.8h, w8\n\t"
        "cmtst	v3.8h, v2.8h, v0.8h\n\t"
        "and	v3.16b, v3.16b, v1.16b\n\t"
        "shl	v3.8h, v3.8h, #7\n\t"
        "orr	v4.16b, v4.16b, v3.16b\n\t"
        "add	x9, %x[synd], #0x100\n\t"
        "add	x9, x9, x6\n\t"
        "ldr	x8, [x9]\n\t"
        "lsr	x8, x8, x7\n\t"
        "dup	v2.8h, w8\n\t"
        "cmtst	v3.8h, v2.8h, v0.8h\n\t"
        "and	v3.16b, v3.16b, v1.16b\n\t"
        "shl	v3.8h, v3.8h, #8\n\t"
        "orr	v4.16b, v4.16b, v3.16b\n\t"
        "add	x9, %x[synd], #0x120\n\t"
        "add	x9, x9, x6\n\t"
        "ldr	x8, [x9]\n\t"
        "lsr	x8, x8, x7\n\t"
        "dup	v2.8h, w8\n\t"
        "cmtst	v3.8h, v2.8h, v0.8h\n\t"
        "and	v3.16b, v3.16b, v1.16b\n\t"
        "shl	v3.8h, v3.8h, #9\n\t"
        "orr	v4.16b, v4.16b, v3.16b\n\t"
        "add	x9, %x[synd], #0x140\n\t"
        "add	x9, x9, x6\n\t"
        "ldr	x8, [x9]\n\t"
        "lsr	x8, x8, x7\n\t"
        "dup	v2.8h, w8\n\t"
        "cmtst	v3.8h, v2.8h, v0.8h\n\t"
        "and	v3.16b, v3.16b, v1.16b\n\t"
        "shl	v3.8h, v3.8h, #10\n\t"
        "orr	v4.16b, v4.16b, v3.16b\n\t"
        "add	x9, %x[synd], #0x160\n\t"
        "add	x9, x9, x6\n\t"
        "ldr	x8, [x9]\n\t"
        "lsr	x8, x8, x7\n\t"
        "dup	v2.8h, w8\n\t"
        "cmtst	v3.8h, v2.8h, v0.8h\n\t"
        "and	v3.16b, v3.16b, v1.16b\n\t"
        "shl	v3.8h, v3.8h, #11\n\t"
        "orr	v4.16b, v4.16b, v3.16b\n\t"
        "add	x9, %x[synd], #0x180\n\t"
        "add	x9, x9, x6\n\t"
        "ldr	x8, [x9]\n\t"
        "lsr	x8, x8, x7\n\t"
        "dup	v2.8h, w8\n\t"
        "cmtst	v3.8h, v2.8h, v0.8h\n\t"
        "and	v3.16b, v3.16b, v1.16b\n\t"
        "shl	v3.8h, v3.8h, #12\n\t"
        "orr	v4.16b, v4.16b, v3.16b\n\t"
        "lsl	x9, x4, #4\n\t"
        "add	x9, %x[s], x9\n\t"
        "str	q4, [x9]\n\t"
        "add	x4, x4, #1\n\t"
        "b	L_mc_sunp_%=\n\t"
        "\n"
    "L_mc_sunpe_%=:\n\t"
        : [s] "+r" (s), [synd] "+r" (synd), [count] "+r" (count)
        : [L_mc_bs_powers_neon_c] "r" (L_mc_bs_powers_neon_c)
        : "memory", "cc", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "v0", "v1",
            "v2", "v3", "v4"
    );
}

WOLFSSL_LOCAL void wc_mceliece_berlekamp_massey_neon(word16* out_p,
    const word16* s_p, int t_p, word64* scratch_p);
void wc_mceliece_berlekamp_massey_neon(word16* out_p, const word16* s_p,
    int t_p, word64* scratch_p)
{
    register word16* out __asm__ ("x0") = (word16*)out_p;
    register const word16* s __asm__ ("x1") = (const word16*)s_p;
    register int t __asm__ ("w2") = (int)t_p;
    register word64* scratch __asm__ ("x3") = (word64*)scratch_p;
    __asm__ __volatile__ (
        "stp	x29, x30, [sp, #-32]!\n\t"
        "add	x29, sp, #0\n\t"
        "str	%x[out], [x29, #16]\n\t"
        "mov	x19, %x[s]\n\t"
        "mov	w20, %w[t]\n\t"
        "mov	x21, %x[scratch]\n\t"
        "add	x22, %x[scratch], #0x200\n\t"
        "add	x23, %x[scratch], #0x400\n\t"
        "mov	w7, #0\n\t"
        "mov	x4, #0\n\t"
        "\n"
    "L_mc_bm_in_%=:\n\t"
        "cmp	x4, x20\n\t"
        "b.gt	L_mc_bm_ine_%=\n\t"
        "lsl	x5, x4, #1\n\t"
        "add	x6, x22, x5\n\t"
        "strh	w7, [x6]\n\t"
        "add	x6, x23, x5\n\t"
        "strh	w7, [x6]\n\t"
        "add	x4, x4, #1\n\t"
        "b	L_mc_bm_in_%=\n\t"
        "\n"
    "L_mc_bm_ine_%=:\n\t"
        "mov	w7, #1\n\t"
        "strh	w7, [x22]\n\t"
        "add	x6, x23, #2\n\t"
        "strh	w7, [x6]\n\t"
        "mov	w25, #0\n\t"
        "mov	w26, #1\n\t"
        "mov	w24, #0\n\t"
        "\n"
    "L_mc_bm_n_%=:\n\t"
        "lsl	x8, x20, #1\n\t"
        "cmp	x24, x8\n\t"
        "b.ge	L_mc_bm_ne_%=\n\t"
        "mov	w27, #0\n\t"
        "mov	x9, x20\n\t"
        "cmp	x24, x20\n\t"
        "b.ge	L_mc_bm_dsk_%=\n\t"
        "mov	x9, x24\n\t"
        "\n"
    "L_mc_bm_dsk_%=:\n\t"
        "add	x10, x9, #1\n\t"
        "lsr	x10, x10, #3\n\t"
        "lsl	x10, x10, #3\n\t"
        "cbz	x10, L_mc_bm_dt_%=\n\t"
        "mov	%x[out], x22\n\t"
        "lsl	x5, x24, #1\n\t"
        "add	%x[s], x19, x5\n\t"
        "mov	%w[t], w10\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_gf_discrepancy_neon\n\t"
#else
        "bl	_wc_mceliece_gf_discrepancy_neon\n\t"
#endif /* __APPLE__ */
        "mov	w27, %w[out]\n\t"
        "\n"
    "L_mc_bm_dt_%=:\n\t"
        "mov	x9, x20\n\t"
        "cmp	x24, x20\n\t"
        "b.ge	L_mc_bm_tc_%=\n\t"
        "mov	x9, x24\n\t"
        "\n"
    "L_mc_bm_tc_%=:\n\t"
        "add	x10, x9, #1\n\t"
        "lsr	x10, x10, #3\n\t"
        "lsl	x10, x10, #3\n\t"
        "mov	x28, x10\n\t"
        "\n"
    "L_mc_bm_dte_%=:\n\t"
        "cmp	x28, x9\n\t"
        "b.gt	L_mc_bm_zc_%=\n\t"
        "lsl	x5, x28, #1\n\t"
        "add	x6, x22, x5\n\t"
        "ldrh	%w[out], [x6]\n\t"
        "sub	x5, x24, x28\n\t"
        "lsl	x5, x5, #1\n\t"
        "add	x6, x19, x5\n\t"
        "ldrh	%w[s], [x6]\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_gf_mul_scalar_neon\n\t"
#else
        "bl	_wc_mceliece_gf_mul_scalar_neon\n\t"
#endif /* __APPLE__ */
        "eor	w27, w27, %w[out]\n\t"
        "add	x28, x28, #1\n\t"
        "b	L_mc_bm_dte_%=\n\t"
        "\n"
    "L_mc_bm_zc_%=:\n\t"
        "mov	x4, #0\n\t"
        "\n"
    "L_mc_bm_tce_%=:\n\t"
        "cmp	x4, x20\n\t"
        "b.gt	L_mc_bm_zce_%=\n\t"
        "lsl	x5, x4, #1\n\t"
        "add	x6, x22, x5\n\t"
        "ldrh	w7, [x6]\n\t"
        "add	x6, x21, x5\n\t"
        "strh	w7, [x6]\n\t"
        "add	x6, x22, x5\n\t"
        "mov	w8, #0\n\t"
        "strh	w8, [x6]\n\t"
        "add	x4, x4, #1\n\t"
        "b	L_mc_bm_tce_%=\n\t"
        "\n"
    "L_mc_bm_zce_%=:\n\t"
        "add	x8, x20, #1\n\t"
        "lsr	x10, x8, #3\n\t"
        "lsl	x10, x10, #3\n\t"
        "cbz	x10, L_mc_bm_msk_%=\n\t"
        "mov	%x[out], x22\n\t"
        "mov	%w[s], w26\n\t"
        "mov	%x[t], x21\n\t"
        "mov	%w[scratch], w10\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_gf_mulc_mac_neon\n\t"
#else
        "bl	_wc_mceliece_gf_mulc_mac_neon\n\t"
#endif /* __APPLE__ */
        "add	x8, x20, #1\n\t"
        "lsr	x10, x8, #3\n\t"
        "lsl	x10, x10, #3\n\t"
        "mov	%x[out], x22\n\t"
        "mov	%w[s], w27\n\t"
        "mov	%x[t], x23\n\t"
        "mov	%w[scratch], w10\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_gf_mulc_mac_neon\n\t"
#else
        "bl	_wc_mceliece_gf_mulc_mac_neon\n\t"
#endif /* __APPLE__ */
        "\n"
    "L_mc_bm_msk_%=:\n\t"
        "add	x8, x20, #1\n\t"
        "lsr	x10, x8, #3\n\t"
        "lsl	x10, x10, #3\n\t"
        "mov	x28, x10\n\t"
        "\n"
    "L_mc_bm_mt_%=:\n\t"
        "cmp	x28, x20\n\t"
        "b.gt	L_mc_bm_mte_%=\n\t"
        "lsl	x5, x28, #1\n\t"
        "add	x6, x21, x5\n\t"
        "ldrh	%w[s], [x6]\n\t"
        "mov	%w[out], w26\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_gf_mul_scalar_neon\n\t"
#else
        "bl	_wc_mceliece_gf_mul_scalar_neon\n\t"
#endif /* __APPLE__ */
        "lsl	x5, x28, #1\n\t"
        "add	x6, x22, x5\n\t"
        "ldrh	w7, [x6]\n\t"
        "eor	w7, w7, %w[out]\n\t"
        "strh	w7, [x6]\n\t"
        "lsl	x5, x28, #1\n\t"
        "add	x6, x23, x5\n\t"
        "ldrh	%w[s], [x6]\n\t"
        "mov	%w[out], w27\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_gf_mul_scalar_neon\n\t"
#else
        "bl	_wc_mceliece_gf_mul_scalar_neon\n\t"
#endif /* __APPLE__ */
        "lsl	x5, x28, #1\n\t"
        "add	x6, x22, x5\n\t"
        "ldrh	w7, [x6]\n\t"
        "eor	w7, w7, %w[out]\n\t"
        "strh	w7, [x6]\n\t"
        "add	x28, x28, #1\n\t"
        "b	L_mc_bm_mt_%=\n\t"
        "\n"
    "L_mc_bm_mte_%=:\n\t"
        "sub	w8, w27, #1\n\t"
        "lsr	w8, w8, #31\n\t"
        "sub	w8, w8, #1\n\t"
        "lsl	w7, w25, #1\n\t"
        "sub	w11, w24, w7\n\t"
        "lsr	w11, w11, #31\n\t"
        "sub	w11, w11, #1\n\t"
        "and	w11, w11, w8\n\t"
        "add	w7, w24, #1\n\t"
        "sub	w7, w7, w25\n\t"
        "eor	w8, w25, w7\n\t"
        "and	w8, w8, w11\n\t"
        "eor	w25, w25, w8\n\t"
        "mov	x4, #0\n\t"
        "\n"
    "L_mc_bm_bu_%=:\n\t"
        "cmp	x4, x20\n\t"
        "b.gt	L_mc_bm_bue_%=\n\t"
        "lsl	x5, x4, #1\n\t"
        "add	x6, x23, x5\n\t"
        "ldrh	w7, [x6]\n\t"
        "add	x6, x21, x5\n\t"
        "ldrh	w8, [x6]\n\t"
        "eor	w8, w8, w7\n\t"
        "and	w8, w8, w11\n\t"
        "eor	w7, w7, w8\n\t"
        "add	x6, x23, x5\n\t"
        "strh	w7, [x6]\n\t"
        "add	x4, x4, #1\n\t"
        "b	L_mc_bm_bu_%=\n\t"
        "\n"
    "L_mc_bm_bue_%=:\n\t"
        "eor	w8, w26, w27\n\t"
        "and	w8, w8, w11\n\t"
        "eor	w26, w26, w8\n\t"
        "mov	x4, x20\n\t"
        "\n"
    "L_mc_bm_bs_%=:\n\t"
        "cmp	x4, #1\n\t"
        "b.lt	L_mc_bm_bse_%=\n\t"
        "sub	x8, x4, #1\n\t"
        "lsl	x5, x8, #1\n\t"
        "add	x6, x23, x5\n\t"
        "ldrh	w7, [x6]\n\t"
        "lsl	x5, x4, #1\n\t"
        "add	x6, x23, x5\n\t"
        "strh	w7, [x6]\n\t"
        "sub	x4, x4, #1\n\t"
        "b	L_mc_bm_bs_%=\n\t"
        "\n"
    "L_mc_bm_bse_%=:\n\t"
        "mov	w7, #0\n\t"
        "strh	w7, [x23]\n\t"
        "add	x24, x24, #1\n\t"
        "b	L_mc_bm_n_%=\n\t"
        "\n"
    "L_mc_bm_ne_%=:\n\t"
        "ldrh	%w[out], [x22]\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_gf_inv_scalar_neon\n\t"
#else
        "bl	_wc_mceliece_gf_inv_scalar_neon\n\t"
#endif /* __APPLE__ */
        "mov	w27, %w[out]\n\t"
        "ldr	x24, [x29, #16]\n\t"
        "mov	x28, #0\n\t"
        "\n"
    "L_mc_bm_nm_%=:\n\t"
        "cmp	x28, x20\n\t"
        "b.gt	L_mc_bm_nme_%=\n\t"
        "sub	x5, x20, x28\n\t"
        "lsl	x5, x5, #1\n\t"
        "add	x6, x22, x5\n\t"
        "ldrh	%w[out], [x6]\n\t"
        "mov	%w[s], w27\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_gf_mul_scalar_neon\n\t"
#else
        "bl	_wc_mceliece_gf_mul_scalar_neon\n\t"
#endif /* __APPLE__ */
        "lsl	x5, x28, #1\n\t"
        "add	x6, x24, x5\n\t"
        "strh	%w[out], [x6]\n\t"
        "add	x28, x28, #1\n\t"
        "b	L_mc_bm_nm_%=\n\t"
        "\n"
    "L_mc_bm_nme_%=:\n\t"
        "ldp	x29, x30, [sp], #32\n\t"
        : [out] "+r" (out), [s] "+r" (s), [t] "+r" (t),
          [scratch] "+r" (scratch)
        :
        : "memory", "cc", "x19", "x20", "x21", "x22", "x23", "x24", "x25",
            "x26", "x27", "x28", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
            "x11", "x30"
    );
}

WOLFSSL_LOCAL void wc_mceliece_syndrome_neon(word64* synd_p,
    const byte* fieldmask_p, word64* einvbs_p, word64* scaled_p,
    word64* scratch_p);
void wc_mceliece_syndrome_neon(word64* synd_p, const byte* fieldmask_p,
    word64* einvbs_p, word64* scaled_p, word64* scratch_p)
{
    register word64* synd __asm__ ("x0") = (word64*)synd_p;
    register const byte* fieldmask __asm__ ("x1") = (const byte*)fieldmask_p;
    register word64* einvbs __asm__ ("x2") = (word64*)einvbs_p;
    register word64* scaled __asm__ ("x3") = (word64*)scaled_p;
    register word64* scratch __asm__ ("x4") = (word64*)scratch_p;
    __asm__ __volatile__ (
        "mov	x19, %x[synd]\n\t"
        "mov	x20, %x[fieldmask]\n\t"
        "mov	x21, %x[einvbs]\n\t"
        "mov	x22, %x[scaled]\n\t"
        "mov	x23, %x[scratch]\n\t"
        "mov	%x[synd], x22\n\t"
        "mov	%x[fieldmask], x21\n\t"
        "mov	%x[einvbs], x20\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_synd_mask_neon\n\t"
#else
        "bl	_wc_mceliece_aff_synd_mask_neon\n\t"
#endif /* __APPLE__ */
        "mov	%x[synd], x19\n\t"
        "mov	%x[fieldmask], x22\n\t"
        "mov	%x[einvbs], x23\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_butterflies_tr_neon\n\t"
#else
        "bl	_wc_mceliece_aff_butterflies_tr_neon\n\t"
#endif /* __APPLE__ */
        "mov	%x[synd], x19\n\t"
        "mov	%x[fieldmask], x23\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_radix_conv_tr_neon\n\t"
#else
        "bl	_wc_mceliece_radix_conv_tr_neon\n\t"
#endif /* __APPLE__ */
        : [synd] "+r" (synd), [fieldmask] "+r" (fieldmask),
          [einvbs] "+r" (einvbs), [scaled] "+r" (scaled),
          [scratch] "+r" (scratch)
        :
        : "memory", "cc", "x19", "x20", "x21", "x22", "x23", "x30"
    );
}

WOLFSSL_LOCAL void wc_mceliece_goppa_eval_inv_neon(word64* einvbs_p,
    word64* ffts_p, const byte* gp_p, int t_p, int mono_p, word64* poly_p,
    word64* scratch_p);
void wc_mceliece_goppa_eval_inv_neon(word64* einvbs_p, word64* ffts_p,
    const byte* gp_p, int t_p, int mono_p, word64* poly_p, word64* scratch_p)
{
    register word64* einvbs __asm__ ("x0") = (word64*)einvbs_p;
    register word64* ffts __asm__ ("x1") = (word64*)ffts_p;
    register const byte* gp __asm__ ("x2") = (const byte*)gp_p;
    register int t __asm__ ("w3") = (int)t_p;
    register int mono __asm__ ("w4") = (int)mono_p;
    register word64* poly __asm__ ("x5") = (word64*)poly_p;
    register word64* scratch __asm__ ("x6") = (word64*)scratch_p;
    __asm__ __volatile__ (
        "mov	x8, #0x1300\n\t"
        "add	x24, %x[scratch], x8\n\t"
        "mov	w11, %w[t]\n\t"
        "mov	x12, #0\n\t"
        "mov	x7, #0\n\t"
        "\n"
    "L_mc_gei_l_%=:\n\t"
        "cmp	x7, x11\n\t"
        "b.ge	L_mc_gei_le_%=\n\t"
        "lsl	x8, x7, #1\n\t"
        "add	x9, %x[gp], x8\n\t"
        "ldrh	w10, [x9]\n\t"
        "and	x10, x10, #0x1fff\n\t"
        "add	x9, x24, x8\n\t"
        "strh	w10, [x9]\n\t"
        "add	x7, x7, #1\n\t"
        "b	L_mc_gei_l_%=\n\t"
        "\n"
    "L_mc_gei_le_%=:\n\t"
        "cmp	x11, #0x80\n\t"
        "b.ge	L_mc_gei_ze_%=\n\t"
        "lsl	x8, x11, #1\n\t"
        "add	x9, x24, x8\n\t"
        "mov	x10, #1\n\t"
        "strh	w10, [x9]\n\t"
        "add	x7, x11, #1\n\t"
        "\n"
    "L_mc_gei_z_%=:\n\t"
        "cmp	x7, #0x80\n\t"
        "b.ge	L_mc_gei_ze_%=\n\t"
        "lsl	x8, x7, #1\n\t"
        "add	x9, x24, x8\n\t"
        "strh	w12, [x9]\n\t"
        "add	x7, x7, #1\n\t"
        "b	L_mc_gei_z_%=\n\t"
        "\n"
    "L_mc_gei_ze_%=:\n\t"
        "mov	x19, %x[einvbs]\n\t"
        "mov	x20, %x[ffts]\n\t"
        "mov	w21, %w[mono]\n\t"
        "mov	x22, %x[poly]\n\t"
        "mov	x23, %x[scratch]\n\t"
        "mov	%x[einvbs], x22\n\t"
        "mov	%x[ffts], x24\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_bs_poly_neon\n\t"
#else
        "bl	_wc_mceliece_bs_poly_neon\n\t"
#endif /* __APPLE__ */
        "mov	%x[einvbs], x22\n\t"
        "mov	%x[ffts], x23\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_radix_conv_neon\n\t"
#else
        "bl	_wc_mceliece_radix_conv_neon\n\t"
#endif /* __APPLE__ */
        "mov	%x[einvbs], x20\n\t"
        "mov	%x[ffts], x22\n\t"
        "mov	%w[gp], w21\n\t"
        "mov	%x[t], x23\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_fft_fwd_butterflies_neon\n\t"
#else
        "bl	_wc_mceliece_fft_fwd_butterflies_neon\n\t"
#endif /* __APPLE__ */
        "mov	%x[einvbs], x19\n\t"
        "mov	%x[ffts], x20\n\t"
        "mov	%x[gp], x23\n\t"
        "add	%x[t], x23, #0x340\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_mont_batch_inv_neon\n\t"
#else
        "bl	_wc_mceliece_mont_batch_inv_neon\n\t"
#endif /* __APPLE__ */
        : [einvbs] "+r" (einvbs), [ffts] "+r" (ffts), [gp] "+r" (gp),
          [t] "+r" (t), [mono] "+r" (mono), [poly] "+r" (poly),
          [scratch] "+r" (scratch)
        :
        : "memory", "cc", "x19", "x20", "x21", "x22", "x23", "x24", "x7", "x8",
            "x9", "x10", "x11", "x12", "x30"
    );
}

#endif /* WOLFSSL_MCELIECE_SMALL */
#endif /* WOLFSSL_MCELIECE_NO_DECAPSULATE */
#if !defined(WOLFSSL_MCELIECE_NO_MAKE_KEY) || \
        !defined(WOLFSSL_MCELIECE_NO_DECAPSULATE)
#ifndef WOLFSSL_MCELIECE_SMALL
WOLFSSL_LOCAL void wc_mceliece_aff_transpose_neon(word64* in_p);
void wc_mceliece_aff_transpose_neon(word64* in_p)
{
    register word64* in __asm__ ("x0") = (word64*)in_p;
    __asm__ __volatile__ (
        "mov	x5, #0xffffffff\n\t"
        "dup	v10.2d, x5\n\t"
        "mov	x1, #0\n\t"
        "\n"
    "L_mc_at_i5_%=:\n\t"
        "cmp	x1, #0x40\n\t"
        "b.ge	L_mc_at_e5_%=\n\t"
        "mov	x2, x1\n\t"
        "add	x6, x1, #32\n\t"
        "\n"
    "L_mc_at_j5_%=:\n\t"
        "cmp	x2, x6\n\t"
        "b.ge	L_mc_at_ni5_%=\n\t"
        "lsl	x7, x2, #5\n\t"
        "add	x3, %x[in], x7\n\t"
        "add	x4, x3, #0x400\n\t"
        "ldp	q0, q1, [x3]\n\t"
        "ldp	q2, q3, [x4]\n\t"
        "and	v4.16b, v0.16b, v10.16b\n\t"
        "and	v8.16b, v2.16b, v10.16b\n\t"
        "shl	v8.2d, v8.2d, #32\n\t"
        "orr	v4.16b, v4.16b, v8.16b\n\t"
        "and	v5.16b, v1.16b, v10.16b\n\t"
        "and	v9.16b, v3.16b, v10.16b\n\t"
        "shl	v9.2d, v9.2d, #32\n\t"
        "orr	v5.16b, v5.16b, v9.16b\n\t"
        "bic	v6.16b, v0.16b, v10.16b\n\t"
        "ushr	v6.2d, v6.2d, #32\n\t"
        "bic	v8.16b, v2.16b, v10.16b\n\t"
        "orr	v6.16b, v6.16b, v8.16b\n\t"
        "bic	v7.16b, v1.16b, v10.16b\n\t"
        "ushr	v7.2d, v7.2d, #32\n\t"
        "bic	v9.16b, v3.16b, v10.16b\n\t"
        "orr	v7.16b, v7.16b, v9.16b\n\t"
        "stp	q4, q5, [x3]\n\t"
        "stp	q6, q7, [x4]\n\t"
        "add	x2, x2, #1\n\t"
        "b	L_mc_at_j5_%=\n\t"
        "\n"
    "L_mc_at_ni5_%=:\n\t"
        "add	x1, x1, #0x40\n\t"
        "b	L_mc_at_i5_%=\n\t"
        "\n"
    "L_mc_at_e5_%=:\n\t"
        "mov	x5, #0xffff0000ffff\n\t"
        "dup	v10.2d, x5\n\t"
        "mov	x1, #0\n\t"
        "\n"
    "L_mc_at_i4_%=:\n\t"
        "cmp	x1, #0x40\n\t"
        "b.ge	L_mc_at_e4_%=\n\t"
        "mov	x2, x1\n\t"
        "add	x6, x1, #16\n\t"
        "\n"
    "L_mc_at_j4_%=:\n\t"
        "cmp	x2, x6\n\t"
        "b.ge	L_mc_at_ni4_%=\n\t"
        "lsl	x7, x2, #5\n\t"
        "add	x3, %x[in], x7\n\t"
        "add	x4, x3, #0x200\n\t"
        "ldp	q0, q1, [x3]\n\t"
        "ldp	q2, q3, [x4]\n\t"
        "and	v4.16b, v0.16b, v10.16b\n\t"
        "and	v8.16b, v2.16b, v10.16b\n\t"
        "shl	v8.2d, v8.2d, #16\n\t"
        "orr	v4.16b, v4.16b, v8.16b\n\t"
        "and	v5.16b, v1.16b, v10.16b\n\t"
        "and	v9.16b, v3.16b, v10.16b\n\t"
        "shl	v9.2d, v9.2d, #16\n\t"
        "orr	v5.16b, v5.16b, v9.16b\n\t"
        "bic	v6.16b, v0.16b, v10.16b\n\t"
        "ushr	v6.2d, v6.2d, #16\n\t"
        "bic	v8.16b, v2.16b, v10.16b\n\t"
        "orr	v6.16b, v6.16b, v8.16b\n\t"
        "bic	v7.16b, v1.16b, v10.16b\n\t"
        "ushr	v7.2d, v7.2d, #16\n\t"
        "bic	v9.16b, v3.16b, v10.16b\n\t"
        "orr	v7.16b, v7.16b, v9.16b\n\t"
        "stp	q4, q5, [x3]\n\t"
        "stp	q6, q7, [x4]\n\t"
        "add	x2, x2, #1\n\t"
        "b	L_mc_at_j4_%=\n\t"
        "\n"
    "L_mc_at_ni4_%=:\n\t"
        "add	x1, x1, #32\n\t"
        "b	L_mc_at_i4_%=\n\t"
        "\n"
    "L_mc_at_e4_%=:\n\t"
        "mov	x5, #0xff00ff00ff00ff\n\t"
        "dup	v10.2d, x5\n\t"
        "mov	x1, #0\n\t"
        "\n"
    "L_mc_at_i3_%=:\n\t"
        "cmp	x1, #0x40\n\t"
        "b.ge	L_mc_at_e3_%=\n\t"
        "mov	x2, x1\n\t"
        "add	x6, x1, #8\n\t"
        "\n"
    "L_mc_at_j3_%=:\n\t"
        "cmp	x2, x6\n\t"
        "b.ge	L_mc_at_ni3_%=\n\t"
        "lsl	x7, x2, #5\n\t"
        "add	x3, %x[in], x7\n\t"
        "add	x4, x3, #0x100\n\t"
        "ldp	q0, q1, [x3]\n\t"
        "ldp	q2, q3, [x4]\n\t"
        "and	v4.16b, v0.16b, v10.16b\n\t"
        "and	v8.16b, v2.16b, v10.16b\n\t"
        "shl	v8.2d, v8.2d, #8\n\t"
        "orr	v4.16b, v4.16b, v8.16b\n\t"
        "and	v5.16b, v1.16b, v10.16b\n\t"
        "and	v9.16b, v3.16b, v10.16b\n\t"
        "shl	v9.2d, v9.2d, #8\n\t"
        "orr	v5.16b, v5.16b, v9.16b\n\t"
        "bic	v6.16b, v0.16b, v10.16b\n\t"
        "ushr	v6.2d, v6.2d, #8\n\t"
        "bic	v8.16b, v2.16b, v10.16b\n\t"
        "orr	v6.16b, v6.16b, v8.16b\n\t"
        "bic	v7.16b, v1.16b, v10.16b\n\t"
        "ushr	v7.2d, v7.2d, #8\n\t"
        "bic	v9.16b, v3.16b, v10.16b\n\t"
        "orr	v7.16b, v7.16b, v9.16b\n\t"
        "stp	q4, q5, [x3]\n\t"
        "stp	q6, q7, [x4]\n\t"
        "add	x2, x2, #1\n\t"
        "b	L_mc_at_j3_%=\n\t"
        "\n"
    "L_mc_at_ni3_%=:\n\t"
        "add	x1, x1, #16\n\t"
        "b	L_mc_at_i3_%=\n\t"
        "\n"
    "L_mc_at_e3_%=:\n\t"
        "mov	x5, #0xf0f0f0f0f0f0f0f\n\t"
        "dup	v10.2d, x5\n\t"
        "mov	x1, #0\n\t"
        "\n"
    "L_mc_at_i2_%=:\n\t"
        "cmp	x1, #0x40\n\t"
        "b.ge	L_mc_at_e2_%=\n\t"
        "mov	x2, x1\n\t"
        "add	x6, x1, #4\n\t"
        "\n"
    "L_mc_at_j2_%=:\n\t"
        "cmp	x2, x6\n\t"
        "b.ge	L_mc_at_ni2_%=\n\t"
        "lsl	x7, x2, #5\n\t"
        "add	x3, %x[in], x7\n\t"
        "add	x4, x3, #0x80\n\t"
        "ldp	q0, q1, [x3]\n\t"
        "ldp	q2, q3, [x4]\n\t"
        "and	v4.16b, v0.16b, v10.16b\n\t"
        "and	v8.16b, v2.16b, v10.16b\n\t"
        "shl	v8.2d, v8.2d, #4\n\t"
        "orr	v4.16b, v4.16b, v8.16b\n\t"
        "and	v5.16b, v1.16b, v10.16b\n\t"
        "and	v9.16b, v3.16b, v10.16b\n\t"
        "shl	v9.2d, v9.2d, #4\n\t"
        "orr	v5.16b, v5.16b, v9.16b\n\t"
        "bic	v6.16b, v0.16b, v10.16b\n\t"
        "ushr	v6.2d, v6.2d, #4\n\t"
        "bic	v8.16b, v2.16b, v10.16b\n\t"
        "orr	v6.16b, v6.16b, v8.16b\n\t"
        "bic	v7.16b, v1.16b, v10.16b\n\t"
        "ushr	v7.2d, v7.2d, #4\n\t"
        "bic	v9.16b, v3.16b, v10.16b\n\t"
        "orr	v7.16b, v7.16b, v9.16b\n\t"
        "stp	q4, q5, [x3]\n\t"
        "stp	q6, q7, [x4]\n\t"
        "add	x2, x2, #1\n\t"
        "b	L_mc_at_j2_%=\n\t"
        "\n"
    "L_mc_at_ni2_%=:\n\t"
        "add	x1, x1, #8\n\t"
        "b	L_mc_at_i2_%=\n\t"
        "\n"
    "L_mc_at_e2_%=:\n\t"
        "mov	x5, #0x3333333333333333\n\t"
        "dup	v10.2d, x5\n\t"
        "mov	x1, #0\n\t"
        "\n"
    "L_mc_at_i1_%=:\n\t"
        "cmp	x1, #0x40\n\t"
        "b.ge	L_mc_at_e1_%=\n\t"
        "mov	x2, x1\n\t"
        "add	x6, x1, #2\n\t"
        "\n"
    "L_mc_at_j1_%=:\n\t"
        "cmp	x2, x6\n\t"
        "b.ge	L_mc_at_ni1_%=\n\t"
        "lsl	x7, x2, #5\n\t"
        "add	x3, %x[in], x7\n\t"
        "add	x4, x3, #0x40\n\t"
        "ldp	q0, q1, [x3]\n\t"
        "ldp	q2, q3, [x4]\n\t"
        "and	v4.16b, v0.16b, v10.16b\n\t"
        "and	v8.16b, v2.16b, v10.16b\n\t"
        "shl	v8.2d, v8.2d, #2\n\t"
        "orr	v4.16b, v4.16b, v8.16b\n\t"
        "and	v5.16b, v1.16b, v10.16b\n\t"
        "and	v9.16b, v3.16b, v10.16b\n\t"
        "shl	v9.2d, v9.2d, #2\n\t"
        "orr	v5.16b, v5.16b, v9.16b\n\t"
        "bic	v6.16b, v0.16b, v10.16b\n\t"
        "ushr	v6.2d, v6.2d, #2\n\t"
        "bic	v8.16b, v2.16b, v10.16b\n\t"
        "orr	v6.16b, v6.16b, v8.16b\n\t"
        "bic	v7.16b, v1.16b, v10.16b\n\t"
        "ushr	v7.2d, v7.2d, #2\n\t"
        "bic	v9.16b, v3.16b, v10.16b\n\t"
        "orr	v7.16b, v7.16b, v9.16b\n\t"
        "stp	q4, q5, [x3]\n\t"
        "stp	q6, q7, [x4]\n\t"
        "add	x2, x2, #1\n\t"
        "b	L_mc_at_j1_%=\n\t"
        "\n"
    "L_mc_at_ni1_%=:\n\t"
        "add	x1, x1, #4\n\t"
        "b	L_mc_at_i1_%=\n\t"
        "\n"
    "L_mc_at_e1_%=:\n\t"
        "mov	x5, #0x5555555555555555\n\t"
        "dup	v10.2d, x5\n\t"
        "mov	x1, #0\n\t"
        "\n"
    "L_mc_at_i0_%=:\n\t"
        "cmp	x1, #0x40\n\t"
        "b.ge	L_mc_at_e0_%=\n\t"
        "mov	x2, x1\n\t"
        "add	x6, x1, #1\n\t"
        "\n"
    "L_mc_at_j0_%=:\n\t"
        "cmp	x2, x6\n\t"
        "b.ge	L_mc_at_ni0_%=\n\t"
        "lsl	x7, x2, #5\n\t"
        "add	x3, %x[in], x7\n\t"
        "add	x4, x3, #32\n\t"
        "ldp	q0, q1, [x3]\n\t"
        "ldp	q2, q3, [x4]\n\t"
        "and	v4.16b, v0.16b, v10.16b\n\t"
        "and	v8.16b, v2.16b, v10.16b\n\t"
        "shl	v8.2d, v8.2d, #1\n\t"
        "orr	v4.16b, v4.16b, v8.16b\n\t"
        "and	v5.16b, v1.16b, v10.16b\n\t"
        "and	v9.16b, v3.16b, v10.16b\n\t"
        "shl	v9.2d, v9.2d, #1\n\t"
        "orr	v5.16b, v5.16b, v9.16b\n\t"
        "bic	v6.16b, v0.16b, v10.16b\n\t"
        "ushr	v6.2d, v6.2d, #1\n\t"
        "bic	v8.16b, v2.16b, v10.16b\n\t"
        "orr	v6.16b, v6.16b, v8.16b\n\t"
        "bic	v7.16b, v1.16b, v10.16b\n\t"
        "ushr	v7.2d, v7.2d, #1\n\t"
        "bic	v9.16b, v3.16b, v10.16b\n\t"
        "orr	v7.16b, v7.16b, v9.16b\n\t"
        "stp	q4, q5, [x3]\n\t"
        "stp	q6, q7, [x4]\n\t"
        "add	x2, x2, #1\n\t"
        "b	L_mc_at_j0_%=\n\t"
        "\n"
    "L_mc_at_ni0_%=:\n\t"
        "add	x1, x1, #2\n\t"
        "b	L_mc_at_i0_%=\n\t"
        "\n"
    "L_mc_at_e0_%=:\n\t"
        : [in] "+r" (in)
        :
        : "memory", "cc", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "v0", "v1",
            "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10"
    );
}

WOLFSSL_LOCAL void wc_mceliece_aff_v128_mul_neon(word64* h_p, const word64* f_p,
    const word64* g_p, word64* c_p);
void wc_mceliece_aff_v128_mul_neon(word64* h_p, const word64* f_p,
    const word64* g_p, word64* c_p)
{
    register word64* h __asm__ ("x0") = (word64*)h_p;
    register const word64* f __asm__ ("x1") = (const word64*)f_p;
    register const word64* g __asm__ ("x2") = (const word64*)g_p;
    register word64* c __asm__ ("x3") = (word64*)c_p;
    __asm__ __volatile__ (
        "eor	v5.16b, v5.16b, v5.16b\n\t"
        "mov	x11, %x[c]\n\t"
        "mov	x6, #0\n\t"
        "\n"
    "L_mc_v128_z_%=:\n\t"
        "str	q5, [x11]\n\t"
        "add	x11, x11, #16\n\t"
        "add	x6, x6, #1\n\t"
        "cmp	x6, #25\n\t"
        "b.lt	L_mc_v128_z_%=\n\t"
        "mov	x4, #0\n\t"
        "\n"
    "L_mc_v128_i_%=:\n\t"
        "cmp	x4, #13\n\t"
        "b.ge	L_mc_v128_rs_%=\n\t"
        "lsl	x12, x4, #4\n\t"
        "add	x7, %x[f], x12\n\t"
        "ldr	q0, [x7]\n\t"
        "mov	x5, #0\n\t"
        "\n"
    "L_mc_v128_j_%=:\n\t"
        "cmp	x5, #13\n\t"
        "b.ge	L_mc_v128_in_%=\n\t"
        "lsl	x12, x5, #4\n\t"
        "add	x8, %x[g], x12\n\t"
        "ldr	q1, [x8]\n\t"
        "and	v2.16b, v0.16b, v1.16b\n\t"
        "add	x12, x4, x5\n\t"
        "lsl	x12, x12, #4\n\t"
        "add	x9, %x[c], x12\n\t"
        "ldr	q3, [x9]\n\t"
        "eor	v3.16b, v3.16b, v2.16b\n\t"
        "str	q3, [x9]\n\t"
        "add	x5, x5, #1\n\t"
        "b	L_mc_v128_j_%=\n\t"
        "\n"
    "L_mc_v128_in_%=:\n\t"
        "add	x4, x4, #1\n\t"
        "b	L_mc_v128_i_%=\n\t"
        "\n"
    "L_mc_v128_rs_%=:\n\t"
        "mov	x6, #24\n\t"
        "\n"
    "L_mc_v128_rk_%=:\n\t"
        "cmp	x6, #13\n\t"
        "b.lt	L_mc_v128_copy_%=\n\t"
        "lsl	x12, x6, #4\n\t"
        "add	x9, %x[c], x12\n\t"
        "ldr	q3, [x9]\n\t"
        "sub	x13, x6, #9\n\t"
        "lsl	x13, x13, #4\n\t"
        "add	x10, %x[c], x13\n\t"
        "ldr	q4, [x10]\n\t"
        "eor	v4.16b, v4.16b, v3.16b\n\t"
        "str	q4, [x10]\n\t"
        "sub	x13, x6, #10\n\t"
        "lsl	x13, x13, #4\n\t"
        "add	x10, %x[c], x13\n\t"
        "ldr	q4, [x10]\n\t"
        "eor	v4.16b, v4.16b, v3.16b\n\t"
        "str	q4, [x10]\n\t"
        "sub	x13, x6, #12\n\t"
        "lsl	x13, x13, #4\n\t"
        "add	x10, %x[c], x13\n\t"
        "ldr	q4, [x10]\n\t"
        "eor	v4.16b, v4.16b, v3.16b\n\t"
        "str	q4, [x10]\n\t"
        "sub	x13, x6, #13\n\t"
        "lsl	x13, x13, #4\n\t"
        "add	x10, %x[c], x13\n\t"
        "ldr	q4, [x10]\n\t"
        "eor	v4.16b, v4.16b, v3.16b\n\t"
        "str	q4, [x10]\n\t"
        "sub	x6, x6, #1\n\t"
        "b	L_mc_v128_rk_%=\n\t"
        "\n"
    "L_mc_v128_copy_%=:\n\t"
        "mov	x6, #0\n\t"
        "\n"
    "L_mc_v128_cp_%=:\n\t"
        "cmp	x6, #13\n\t"
        "b.ge	L_mc_v128_done_%=\n\t"
        "lsl	x12, x6, #4\n\t"
        "add	x9, %x[c], x12\n\t"
        "add	x10, %x[h], x12\n\t"
        "ldr	q3, [x9]\n\t"
        "str	q3, [x10]\n\t"
        "add	x6, x6, #1\n\t"
        "b	L_mc_v128_cp_%=\n\t"
        "\n"
    "L_mc_v128_done_%=:\n\t"
        : [h] "+r" (h), [c] "+r" (c)
        : [f] "r" (f), [g] "r" (g)
        : "memory", "cc", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11",
            "x12", "x13", "v0", "v1", "v2", "v3", "v4", "v5"
    );
}

WOLFSSL_LOCAL void wc_mceliece_aff_v256_mul_neon(word64* h_p, const word64* f_p,
    const word64* g_p, word64* c_p);
void wc_mceliece_aff_v256_mul_neon(word64* h_p, const word64* f_p,
    const word64* g_p, word64* c_p)
{
    register word64* h __asm__ ("x0") = (word64*)h_p;
    register const word64* f __asm__ ("x1") = (const word64*)f_p;
    register const word64* g __asm__ ("x2") = (const word64*)g_p;
    register word64* c __asm__ ("x3") = (word64*)c_p;
    __asm__ __volatile__ (
        "eor	v10.16b, v10.16b, v10.16b\n\t"
        "mov	x11, %x[c]\n\t"
        "mov	x6, #0\n\t"
        "\n"
    "L_mc_v256_z_%=:\n\t"
        "stp	q10, q10, [x11]\n\t"
        "add	x11, x11, #32\n\t"
        "add	x6, x6, #1\n\t"
        "cmp	x6, #25\n\t"
        "b.lt	L_mc_v256_z_%=\n\t"
        "mov	x4, #0\n\t"
        "\n"
    "L_mc_v256_i_%=:\n\t"
        "cmp	x4, #13\n\t"
        "b.ge	L_mc_v256_rs_%=\n\t"
        "lsl	x12, x4, #5\n\t"
        "add	x7, %x[f], x12\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "mov	x5, #0\n\t"
        "\n"
    "L_mc_v256_j_%=:\n\t"
        "cmp	x5, #13\n\t"
        "b.ge	L_mc_v256_in_%=\n\t"
        "lsl	x12, x5, #5\n\t"
        "add	x8, %x[g], x12\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "and	v4.16b, v0.16b, v2.16b\n\t"
        "and	v5.16b, v1.16b, v3.16b\n\t"
        "add	x12, x4, x5\n\t"
        "lsl	x12, x12, #5\n\t"
        "add	x9, %x[c], x12\n\t"
        "ldp	q6, q7, [x9]\n\t"
        "eor	v6.16b, v6.16b, v4.16b\n\t"
        "eor	v7.16b, v7.16b, v5.16b\n\t"
        "stp	q6, q7, [x9]\n\t"
        "add	x5, x5, #1\n\t"
        "b	L_mc_v256_j_%=\n\t"
        "\n"
    "L_mc_v256_in_%=:\n\t"
        "add	x4, x4, #1\n\t"
        "b	L_mc_v256_i_%=\n\t"
        "\n"
    "L_mc_v256_rs_%=:\n\t"
        "mov	x6, #24\n\t"
        "\n"
    "L_mc_v256_rk_%=:\n\t"
        "cmp	x6, #13\n\t"
        "b.lt	L_mc_v256_copy_%=\n\t"
        "lsl	x12, x6, #5\n\t"
        "add	x9, %x[c], x12\n\t"
        "ldp	q6, q7, [x9]\n\t"
        "sub	x13, x6, #9\n\t"
        "lsl	x13, x13, #5\n\t"
        "add	x10, %x[c], x13\n\t"
        "ldp	q8, q9, [x10]\n\t"
        "eor	v8.16b, v8.16b, v6.16b\n\t"
        "eor	v9.16b, v9.16b, v7.16b\n\t"
        "stp	q8, q9, [x10]\n\t"
        "sub	x13, x6, #10\n\t"
        "lsl	x13, x13, #5\n\t"
        "add	x10, %x[c], x13\n\t"
        "ldp	q8, q9, [x10]\n\t"
        "eor	v8.16b, v8.16b, v6.16b\n\t"
        "eor	v9.16b, v9.16b, v7.16b\n\t"
        "stp	q8, q9, [x10]\n\t"
        "sub	x13, x6, #12\n\t"
        "lsl	x13, x13, #5\n\t"
        "add	x10, %x[c], x13\n\t"
        "ldp	q8, q9, [x10]\n\t"
        "eor	v8.16b, v8.16b, v6.16b\n\t"
        "eor	v9.16b, v9.16b, v7.16b\n\t"
        "stp	q8, q9, [x10]\n\t"
        "sub	x13, x6, #13\n\t"
        "lsl	x13, x13, #5\n\t"
        "add	x10, %x[c], x13\n\t"
        "ldp	q8, q9, [x10]\n\t"
        "eor	v8.16b, v8.16b, v6.16b\n\t"
        "eor	v9.16b, v9.16b, v7.16b\n\t"
        "stp	q8, q9, [x10]\n\t"
        "sub	x6, x6, #1\n\t"
        "b	L_mc_v256_rk_%=\n\t"
        "\n"
    "L_mc_v256_copy_%=:\n\t"
        "mov	x6, #0\n\t"
        "\n"
    "L_mc_v256_cp_%=:\n\t"
        "cmp	x6, #13\n\t"
        "b.ge	L_mc_v256_done_%=\n\t"
        "lsl	x12, x6, #5\n\t"
        "add	x9, %x[c], x12\n\t"
        "add	x10, %x[h], x12\n\t"
        "ldp	q6, q7, [x9]\n\t"
        "stp	q6, q7, [x10]\n\t"
        "add	x6, x6, #1\n\t"
        "b	L_mc_v256_cp_%=\n\t"
        "\n"
    "L_mc_v256_done_%=:\n\t"
        : [h] "+r" (h), [c] "+r" (c)
        : [f] "r" (f), [g] "r" (g)
        : "memory", "cc", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11",
            "x12", "x13", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8",
            "v9", "v10"
    );
}

WOLFSSL_LOCAL void wc_mceliece_aff_v256_sqr_neon(word64* r_p,
    const word64* a_p);
void wc_mceliece_aff_v256_sqr_neon(word64* r_p, const word64* a_p)
{
    register word64* r __asm__ ("x0") = (word64*)r_p;
    register const word64* a __asm__ ("x1") = (const word64*)a_p;
    __asm__ __volatile__ (
        "mov	x2, %x[a]\n\t"
        "ldp	q0, q1, [x2]\n\t"
        "add	x2, x2, #32\n\t"
        "ldp	q2, q3, [x2]\n\t"
        "add	x2, x2, #32\n\t"
        "ldp	q4, q5, [x2]\n\t"
        "add	x2, x2, #32\n\t"
        "ldp	q6, q7, [x2]\n\t"
        "add	x2, x2, #32\n\t"
        "ldp	q8, q9, [x2]\n\t"
        "add	x2, x2, #32\n\t"
        "ldp	q10, q11, [x2]\n\t"
        "add	x2, x2, #32\n\t"
        "ldp	q12, q13, [x2]\n\t"
        "add	x2, x2, #32\n\t"
        "ldp	q14, q15, [x2]\n\t"
        "add	x2, x2, #32\n\t"
        "ldp	q16, q17, [x2]\n\t"
        "add	x2, x2, #32\n\t"
        "ldp	q18, q19, [x2]\n\t"
        "add	x2, x2, #32\n\t"
        "ldp	q20, q21, [x2]\n\t"
        "add	x2, x2, #32\n\t"
        "ldp	q22, q23, [x2]\n\t"
        "add	x2, x2, #32\n\t"
        "ldp	q24, q25, [x2]\n\t"
        "add	x2, x2, #32\n\t"
        "mov	x3, %x[r]\n\t"
        "eor	v26.16b, v0.16b, v22.16b\n\t"
        "eor	v27.16b, v1.16b, v23.16b\n\t"
        "stp	q26, q27, [x3]\n\t"
        "add	x3, x3, #32\n\t"
        "eor	v26.16b, v14.16b, v22.16b\n\t"
        "eor	v27.16b, v15.16b, v23.16b\n\t"
        "eor	v26.16b, v26.16b, v24.16b\n\t"
        "eor	v27.16b, v27.16b, v25.16b\n\t"
        "stp	q26, q27, [x3]\n\t"
        "add	x3, x3, #32\n\t"
        "eor	v26.16b, v2.16b, v14.16b\n\t"
        "eor	v27.16b, v3.16b, v15.16b\n\t"
        "stp	q26, q27, [x3]\n\t"
        "add	x3, x3, #32\n\t"
        "eor	v26.16b, v16.16b, v22.16b\n\t"
        "eor	v27.16b, v17.16b, v23.16b\n\t"
        "eor	v26.16b, v26.16b, v24.16b\n\t"
        "eor	v27.16b, v27.16b, v25.16b\n\t"
        "stp	q26, q27, [x3]\n\t"
        "add	x3, x3, #32\n\t"
        "eor	v26.16b, v4.16b, v14.16b\n\t"
        "eor	v27.16b, v5.16b, v15.16b\n\t"
        "eor	v26.16b, v26.16b, v16.16b\n\t"
        "eor	v27.16b, v27.16b, v17.16b\n\t"
        "eor	v26.16b, v26.16b, v22.16b\n\t"
        "eor	v27.16b, v27.16b, v23.16b\n\t"
        "eor	v26.16b, v26.16b, v24.16b\n\t"
        "eor	v27.16b, v27.16b, v25.16b\n\t"
        "stp	q26, q27, [x3]\n\t"
        "add	x3, x3, #32\n\t"
        "eor	v26.16b, v14.16b, v18.16b\n\t"
        "eor	v27.16b, v15.16b, v19.16b\n\t"
        "stp	q26, q27, [x3]\n\t"
        "add	x3, x3, #32\n\t"
        "eor	v26.16b, v6.16b, v16.16b\n\t"
        "eor	v27.16b, v7.16b, v17.16b\n\t"
        "eor	v26.16b, v26.16b, v18.16b\n\t"
        "eor	v27.16b, v27.16b, v19.16b\n\t"
        "eor	v26.16b, v26.16b, v24.16b\n\t"
        "eor	v27.16b, v27.16b, v25.16b\n\t"
        "stp	q26, q27, [x3]\n\t"
        "add	x3, x3, #32\n\t"
        "eor	v26.16b, v16.16b, v20.16b\n\t"
        "eor	v27.16b, v17.16b, v21.16b\n\t"
        "stp	q26, q27, [x3]\n\t"
        "add	x3, x3, #32\n\t"
        "eor	v26.16b, v8.16b, v18.16b\n\t"
        "eor	v27.16b, v9.16b, v19.16b\n\t"
        "eor	v26.16b, v26.16b, v20.16b\n\t"
        "eor	v27.16b, v27.16b, v21.16b\n\t"
        "stp	q26, q27, [x3]\n\t"
        "add	x3, x3, #32\n\t"
        "eor	v26.16b, v18.16b, v22.16b\n\t"
        "eor	v27.16b, v19.16b, v23.16b\n\t"
        "stp	q26, q27, [x3]\n\t"
        "add	x3, x3, #32\n\t"
        "eor	v26.16b, v10.16b, v20.16b\n\t"
        "eor	v27.16b, v11.16b, v21.16b\n\t"
        "eor	v26.16b, v26.16b, v22.16b\n\t"
        "eor	v27.16b, v27.16b, v23.16b\n\t"
        "stp	q26, q27, [x3]\n\t"
        "add	x3, x3, #32\n\t"
        "eor	v26.16b, v20.16b, v24.16b\n\t"
        "eor	v27.16b, v21.16b, v25.16b\n\t"
        "stp	q26, q27, [x3]\n\t"
        "add	x3, x3, #32\n\t"
        "eor	v26.16b, v12.16b, v22.16b\n\t"
        "eor	v27.16b, v13.16b, v23.16b\n\t"
        "eor	v26.16b, v26.16b, v24.16b\n\t"
        "eor	v27.16b, v27.16b, v25.16b\n\t"
        "stp	q26, q27, [x3]\n\t"
        "add	x3, x3, #32\n\t"
        : [r] "+r" (r)
        : [a] "r" (a)
        : "memory", "cc", "x2", "x3", "v0", "v1", "v2", "v3", "v4", "v5", "v6",
            "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15", "v16",
            "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25",
            "v26", "v27"
    );
}

WOLFSSL_LOCAL void wc_mceliece_radix_conv_neon(word64* in_p, word64* c_p);
void wc_mceliece_radix_conv_neon(word64* in_p, word64* c_p)
{
    register word64* in __asm__ ("x0") = (word64*)in_p;
    register word64* c __asm__ ("x1") = (word64*)c_p;
    register const word64* L_mc_aff_rmask0_neon_c __asm__ ("x4") = L_mc_aff_rmask0_neon;
    register const word64* L_mc_aff_rmask1_neon_c __asm__ ("x5") = L_mc_aff_rmask1_neon;
    register const word64* L_mc_aff_scal2x_neon_c __asm__ ("x6") = L_mc_aff_scal2x_neon;
    __asm__ __volatile__ (
        "mov	x2, #0\n\t"
        "\n"
    "L_mc_rconv_j_%=:\n\t"
        "cmp	x2, #5\n\t"
        "b.gt	L_mc_rconv_je_%=\n\t"
        "eor	v6.16b, v6.16b, v6.16b\n\t"
        "mov	x16, #1\n\t"
        "mov	x10, #0\n\t"
        "\n"
    "L_mc_rdx_t_rc_%=:\n\t"
        "cmp	x10, #13\n\t"
        "b.ge	L_mc_rdx_te_rc_%=\n\t"
        "lsl	x11, x10, #4\n\t"
        "add	x12, %x[in], x11\n\t"
        "ldr	q0, [x12]\n\t"
        "ushr	v5.2d, v0.2d, #32\n\t"
        "zip2	v5.2d, v6.2d, v5.2d\n\t"
        "eor	v0.16b, v0.16b, v5.16b\n\t"
        "shl	v5.2d, v0.2d, #32\n\t"
        "zip2	v5.2d, v5.2d, v6.2d\n\t"
        "eor	v0.16b, v0.16b, v5.16b\n\t"
        "str	q0, [x12]\n\t"
        "add	x10, x10, #1\n\t"
        "b	L_mc_rdx_t_rc_%=\n\t"
        "\n"
    "L_mc_rdx_te_rc_%=:\n\t"
        "mov	x7, #4\n\t"
        "\n"
    "L_mc_rdx_k_rc_%=:\n\t"
        "cmp	x7, x2\n\t"
        "b.lt	L_mc_rdx_ke_rc_%=\n\t"
        "lsl	x8, x16, x7\n\t"
        "neg	x9, x8\n\t"
        "dup	v4.2d, x9\n\t"
        "lsl	x11, x7, #3\n\t"
        "add	x13, %[L_mc_aff_rmask0_neon_c], x11\n\t"
        "ldr	x14, [x13]\n\t"
        "dup	v2.2d, x14\n\t"
        "add	x13, %[L_mc_aff_rmask1_neon_c], x11\n\t"
        "ldr	x15, [x13]\n\t"
        "dup	v3.2d, x15\n\t"
        "mov	x10, #0\n\t"
        "\n"
    "L_mc_rdx_ki_rc_%=:\n\t"
        "cmp	x10, #13\n\t"
        "b.ge	L_mc_rdx_kie_rc_%=\n\t"
        "lsl	x11, x10, #4\n\t"
        "add	x12, %x[in], x11\n\t"
        "ldr	q0, [x12]\n\t"
        "and	v1.16b, v0.16b, v2.16b\n\t"
        "ushl	v1.2d, v1.2d, v4.2d\n\t"
        "eor	v0.16b, v0.16b, v1.16b\n\t"
        "and	v1.16b, v0.16b, v3.16b\n\t"
        "ushl	v1.2d, v1.2d, v4.2d\n\t"
        "eor	v0.16b, v0.16b, v1.16b\n\t"
        "str	q0, [x12]\n\t"
        "add	x10, x10, #1\n\t"
        "b	L_mc_rdx_ki_rc_%=\n\t"
        "\n"
    "L_mc_rdx_kie_rc_%=:\n\t"
        "sub	x7, x7, #1\n\t"
        "b	L_mc_rdx_k_rc_%=\n\t"
        "\n"
    "L_mc_rdx_ke_rc_%=:\n\t"
        "cmp	x2, #5\n\t"
        "b.ge	L_mc_rconv_sk_%=\n\t"
        "mov	x3, #0xd0\n\t"
        "mul	x3, x2, x3\n\t"
        "add	x3, %[L_mc_aff_scal2x_neon_c], x3\n\t"
        "eor	v5.16b, v5.16b, v5.16b\n\t"
        "mov	x14, %x[c]\n\t"
        "mov	x9, #0\n\t"
        "\n"
    "L_mc_v128_z_rc_%=:\n\t"
        "str	q5, [x14]\n\t"
        "add	x14, x14, #16\n\t"
        "add	x9, x9, #1\n\t"
        "cmp	x9, #25\n\t"
        "b.lt	L_mc_v128_z_rc_%=\n\t"
        "mov	x7, #0\n\t"
        "\n"
    "L_mc_v128_i_rc_%=:\n\t"
        "cmp	x7, #13\n\t"
        "b.ge	L_mc_v128_rs_rc_%=\n\t"
        "lsl	x15, x7, #4\n\t"
        "add	x10, %x[in], x15\n\t"
        "ldr	q0, [x10]\n\t"
        "mov	x8, #0\n\t"
        "\n"
    "L_mc_v128_j_rc_%=:\n\t"
        "cmp	x8, #13\n\t"
        "b.ge	L_mc_v128_in_rc_%=\n\t"
        "lsl	x15, x8, #4\n\t"
        "add	x11, x3, x15\n\t"
        "ldr	q1, [x11]\n\t"
        "and	v2.16b, v0.16b, v1.16b\n\t"
        "add	x15, x7, x8\n\t"
        "lsl	x15, x15, #4\n\t"
        "add	x12, %x[c], x15\n\t"
        "ldr	q3, [x12]\n\t"
        "eor	v3.16b, v3.16b, v2.16b\n\t"
        "str	q3, [x12]\n\t"
        "add	x8, x8, #1\n\t"
        "b	L_mc_v128_j_rc_%=\n\t"
        "\n"
    "L_mc_v128_in_rc_%=:\n\t"
        "add	x7, x7, #1\n\t"
        "b	L_mc_v128_i_rc_%=\n\t"
        "\n"
    "L_mc_v128_rs_rc_%=:\n\t"
        "mov	x9, #24\n\t"
        "\n"
    "L_mc_v128_rk_rc_%=:\n\t"
        "cmp	x9, #13\n\t"
        "b.lt	L_mc_v128_copy_rc_%=\n\t"
        "lsl	x15, x9, #4\n\t"
        "add	x12, %x[c], x15\n\t"
        "ldr	q3, [x12]\n\t"
        "sub	x16, x9, #9\n\t"
        "lsl	x16, x16, #4\n\t"
        "add	x13, %x[c], x16\n\t"
        "ldr	q4, [x13]\n\t"
        "eor	v4.16b, v4.16b, v3.16b\n\t"
        "str	q4, [x13]\n\t"
        "sub	x16, x9, #10\n\t"
        "lsl	x16, x16, #4\n\t"
        "add	x13, %x[c], x16\n\t"
        "ldr	q4, [x13]\n\t"
        "eor	v4.16b, v4.16b, v3.16b\n\t"
        "str	q4, [x13]\n\t"
        "sub	x16, x9, #12\n\t"
        "lsl	x16, x16, #4\n\t"
        "add	x13, %x[c], x16\n\t"
        "ldr	q4, [x13]\n\t"
        "eor	v4.16b, v4.16b, v3.16b\n\t"
        "str	q4, [x13]\n\t"
        "sub	x16, x9, #13\n\t"
        "lsl	x16, x16, #4\n\t"
        "add	x13, %x[c], x16\n\t"
        "ldr	q4, [x13]\n\t"
        "eor	v4.16b, v4.16b, v3.16b\n\t"
        "str	q4, [x13]\n\t"
        "sub	x9, x9, #1\n\t"
        "b	L_mc_v128_rk_rc_%=\n\t"
        "\n"
    "L_mc_v128_copy_rc_%=:\n\t"
        "mov	x9, #0\n\t"
        "\n"
    "L_mc_v128_cp_rc_%=:\n\t"
        "cmp	x9, #13\n\t"
        "b.ge	L_mc_v128_done_rc_%=\n\t"
        "lsl	x15, x9, #4\n\t"
        "add	x12, %x[c], x15\n\t"
        "add	x13, %x[in], x15\n\t"
        "ldr	q3, [x12]\n\t"
        "str	q3, [x13]\n\t"
        "add	x9, x9, #1\n\t"
        "b	L_mc_v128_cp_rc_%=\n\t"
        "\n"
    "L_mc_v128_done_rc_%=:\n\t"
        "\n"
    "L_mc_rconv_sk_%=:\n\t"
        "add	x2, x2, #1\n\t"
        "b	L_mc_rconv_j_%=\n\t"
        "\n"
    "L_mc_rconv_je_%=:\n\t"
        : [in] "+r" (in), [c] "+r" (c)
        : [L_mc_aff_rmask0_neon_c] "r" (L_mc_aff_rmask0_neon_c),
          [L_mc_aff_rmask1_neon_c] "r" (L_mc_aff_rmask1_neon_c),
          [L_mc_aff_scal2x_neon_c] "r" (L_mc_aff_scal2x_neon_c)
        : "memory", "cc", "x2", "x3", "x7", "x8", "x9", "x10", "x11", "x12",
            "x13", "x14", "x15", "x16", "v0", "v1", "v2", "v3", "v4", "v5",
            "v6"
    );
}

WOLFSSL_LOCAL void wc_mceliece_aff_inv256_neon(word64* out_p,
    const word64* in_p, word64* sq_p, word64* c_p);
void wc_mceliece_aff_inv256_neon(word64* out_p, const word64* in_p,
    word64* sq_p, word64* c_p)
{
    register word64* out __asm__ ("x0") = (word64*)out_p;
    register const word64* in __asm__ ("x1") = (const word64*)in_p;
    register word64* sq __asm__ ("x2") = (word64*)sq_p;
    register word64* c __asm__ ("x3") = (word64*)c_p;
    __asm__ __volatile__ (
        "mov	x6, %x[in]\n\t"
        "ldp	q0, q1, [x6]\n\t"
        "add	x6, x6, #32\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "add	x6, x6, #32\n\t"
        "ldp	q4, q5, [x6]\n\t"
        "add	x6, x6, #32\n\t"
        "ldp	q6, q7, [x6]\n\t"
        "add	x6, x6, #32\n\t"
        "ldp	q8, q9, [x6]\n\t"
        "add	x6, x6, #32\n\t"
        "ldp	q10, q11, [x6]\n\t"
        "add	x6, x6, #32\n\t"
        "ldp	q12, q13, [x6]\n\t"
        "add	x6, x6, #32\n\t"
        "ldp	q14, q15, [x6]\n\t"
        "add	x6, x6, #32\n\t"
        "ldp	q16, q17, [x6]\n\t"
        "add	x6, x6, #32\n\t"
        "ldp	q18, q19, [x6]\n\t"
        "add	x6, x6, #32\n\t"
        "ldp	q20, q21, [x6]\n\t"
        "add	x6, x6, #32\n\t"
        "ldp	q22, q23, [x6]\n\t"
        "add	x6, x6, #32\n\t"
        "ldp	q24, q25, [x6]\n\t"
        "add	x6, x6, #32\n\t"
        "mov	x7, %x[sq]\n\t"
        "eor	v26.16b, v0.16b, v22.16b\n\t"
        "eor	v27.16b, v1.16b, v23.16b\n\t"
        "stp	q26, q27, [x7]\n\t"
        "add	x7, x7, #32\n\t"
        "eor	v26.16b, v14.16b, v22.16b\n\t"
        "eor	v27.16b, v15.16b, v23.16b\n\t"
        "eor	v26.16b, v26.16b, v24.16b\n\t"
        "eor	v27.16b, v27.16b, v25.16b\n\t"
        "stp	q26, q27, [x7]\n\t"
        "add	x7, x7, #32\n\t"
        "eor	v26.16b, v2.16b, v14.16b\n\t"
        "eor	v27.16b, v3.16b, v15.16b\n\t"
        "stp	q26, q27, [x7]\n\t"
        "add	x7, x7, #32\n\t"
        "eor	v26.16b, v16.16b, v22.16b\n\t"
        "eor	v27.16b, v17.16b, v23.16b\n\t"
        "eor	v26.16b, v26.16b, v24.16b\n\t"
        "eor	v27.16b, v27.16b, v25.16b\n\t"
        "stp	q26, q27, [x7]\n\t"
        "add	x7, x7, #32\n\t"
        "eor	v26.16b, v4.16b, v14.16b\n\t"
        "eor	v27.16b, v5.16b, v15.16b\n\t"
        "eor	v26.16b, v26.16b, v16.16b\n\t"
        "eor	v27.16b, v27.16b, v17.16b\n\t"
        "eor	v26.16b, v26.16b, v22.16b\n\t"
        "eor	v27.16b, v27.16b, v23.16b\n\t"
        "eor	v26.16b, v26.16b, v24.16b\n\t"
        "eor	v27.16b, v27.16b, v25.16b\n\t"
        "stp	q26, q27, [x7]\n\t"
        "add	x7, x7, #32\n\t"
        "eor	v26.16b, v14.16b, v18.16b\n\t"
        "eor	v27.16b, v15.16b, v19.16b\n\t"
        "stp	q26, q27, [x7]\n\t"
        "add	x7, x7, #32\n\t"
        "eor	v26.16b, v6.16b, v16.16b\n\t"
        "eor	v27.16b, v7.16b, v17.16b\n\t"
        "eor	v26.16b, v26.16b, v18.16b\n\t"
        "eor	v27.16b, v27.16b, v19.16b\n\t"
        "eor	v26.16b, v26.16b, v24.16b\n\t"
        "eor	v27.16b, v27.16b, v25.16b\n\t"
        "stp	q26, q27, [x7]\n\t"
        "add	x7, x7, #32\n\t"
        "eor	v26.16b, v16.16b, v20.16b\n\t"
        "eor	v27.16b, v17.16b, v21.16b\n\t"
        "stp	q26, q27, [x7]\n\t"
        "add	x7, x7, #32\n\t"
        "eor	v26.16b, v8.16b, v18.16b\n\t"
        "eor	v27.16b, v9.16b, v19.16b\n\t"
        "eor	v26.16b, v26.16b, v20.16b\n\t"
        "eor	v27.16b, v27.16b, v21.16b\n\t"
        "stp	q26, q27, [x7]\n\t"
        "add	x7, x7, #32\n\t"
        "eor	v26.16b, v18.16b, v22.16b\n\t"
        "eor	v27.16b, v19.16b, v23.16b\n\t"
        "stp	q26, q27, [x7]\n\t"
        "add	x7, x7, #32\n\t"
        "eor	v26.16b, v10.16b, v20.16b\n\t"
        "eor	v27.16b, v11.16b, v21.16b\n\t"
        "eor	v26.16b, v26.16b, v22.16b\n\t"
        "eor	v27.16b, v27.16b, v23.16b\n\t"
        "stp	q26, q27, [x7]\n\t"
        "add	x7, x7, #32\n\t"
        "eor	v26.16b, v20.16b, v24.16b\n\t"
        "eor	v27.16b, v21.16b, v25.16b\n\t"
        "stp	q26, q27, [x7]\n\t"
        "add	x7, x7, #32\n\t"
        "eor	v26.16b, v12.16b, v22.16b\n\t"
        "eor	v27.16b, v13.16b, v23.16b\n\t"
        "eor	v26.16b, v26.16b, v24.16b\n\t"
        "eor	v27.16b, v27.16b, v25.16b\n\t"
        "stp	q26, q27, [x7]\n\t"
        "add	x7, x7, #32\n\t"
        "mov	x5, #0\n\t"
        "\n"
    "L_mc_inv_cp_%=:\n\t"
        "cmp	x5, #13\n\t"
        "b.ge	L_mc_inv_cpe_%=\n\t"
        "lsl	x6, x5, #5\n\t"
        "add	x7, %x[sq], x6\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, %x[out], x6\n\t"
        "stp	q0, q1, [x8]\n\t"
        "add	x5, x5, #1\n\t"
        "b	L_mc_inv_cp_%=\n\t"
        "\n"
    "L_mc_inv_cpe_%=:\n\t"
        "mov	x4, #2\n\t"
        "\n"
    "L_mc_inv_l_%=:\n\t"
        "cmp	x4, #12\n\t"
        "b.gt	L_mc_inv_le_%=\n\t"
        "mov	x6, %x[sq]\n\t"
        "ldp	q0, q1, [x6]\n\t"
        "add	x6, x6, #32\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "add	x6, x6, #32\n\t"
        "ldp	q4, q5, [x6]\n\t"
        "add	x6, x6, #32\n\t"
        "ldp	q6, q7, [x6]\n\t"
        "add	x6, x6, #32\n\t"
        "ldp	q8, q9, [x6]\n\t"
        "add	x6, x6, #32\n\t"
        "ldp	q10, q11, [x6]\n\t"
        "add	x6, x6, #32\n\t"
        "ldp	q12, q13, [x6]\n\t"
        "add	x6, x6, #32\n\t"
        "ldp	q14, q15, [x6]\n\t"
        "add	x6, x6, #32\n\t"
        "ldp	q16, q17, [x6]\n\t"
        "add	x6, x6, #32\n\t"
        "ldp	q18, q19, [x6]\n\t"
        "add	x6, x6, #32\n\t"
        "ldp	q20, q21, [x6]\n\t"
        "add	x6, x6, #32\n\t"
        "ldp	q22, q23, [x6]\n\t"
        "add	x6, x6, #32\n\t"
        "ldp	q24, q25, [x6]\n\t"
        "add	x6, x6, #32\n\t"
        "mov	x7, %x[sq]\n\t"
        "eor	v26.16b, v0.16b, v22.16b\n\t"
        "eor	v27.16b, v1.16b, v23.16b\n\t"
        "stp	q26, q27, [x7]\n\t"
        "add	x7, x7, #32\n\t"
        "eor	v26.16b, v14.16b, v22.16b\n\t"
        "eor	v27.16b, v15.16b, v23.16b\n\t"
        "eor	v26.16b, v26.16b, v24.16b\n\t"
        "eor	v27.16b, v27.16b, v25.16b\n\t"
        "stp	q26, q27, [x7]\n\t"
        "add	x7, x7, #32\n\t"
        "eor	v26.16b, v2.16b, v14.16b\n\t"
        "eor	v27.16b, v3.16b, v15.16b\n\t"
        "stp	q26, q27, [x7]\n\t"
        "add	x7, x7, #32\n\t"
        "eor	v26.16b, v16.16b, v22.16b\n\t"
        "eor	v27.16b, v17.16b, v23.16b\n\t"
        "eor	v26.16b, v26.16b, v24.16b\n\t"
        "eor	v27.16b, v27.16b, v25.16b\n\t"
        "stp	q26, q27, [x7]\n\t"
        "add	x7, x7, #32\n\t"
        "eor	v26.16b, v4.16b, v14.16b\n\t"
        "eor	v27.16b, v5.16b, v15.16b\n\t"
        "eor	v26.16b, v26.16b, v16.16b\n\t"
        "eor	v27.16b, v27.16b, v17.16b\n\t"
        "eor	v26.16b, v26.16b, v22.16b\n\t"
        "eor	v27.16b, v27.16b, v23.16b\n\t"
        "eor	v26.16b, v26.16b, v24.16b\n\t"
        "eor	v27.16b, v27.16b, v25.16b\n\t"
        "stp	q26, q27, [x7]\n\t"
        "add	x7, x7, #32\n\t"
        "eor	v26.16b, v14.16b, v18.16b\n\t"
        "eor	v27.16b, v15.16b, v19.16b\n\t"
        "stp	q26, q27, [x7]\n\t"
        "add	x7, x7, #32\n\t"
        "eor	v26.16b, v6.16b, v16.16b\n\t"
        "eor	v27.16b, v7.16b, v17.16b\n\t"
        "eor	v26.16b, v26.16b, v18.16b\n\t"
        "eor	v27.16b, v27.16b, v19.16b\n\t"
        "eor	v26.16b, v26.16b, v24.16b\n\t"
        "eor	v27.16b, v27.16b, v25.16b\n\t"
        "stp	q26, q27, [x7]\n\t"
        "add	x7, x7, #32\n\t"
        "eor	v26.16b, v16.16b, v20.16b\n\t"
        "eor	v27.16b, v17.16b, v21.16b\n\t"
        "stp	q26, q27, [x7]\n\t"
        "add	x7, x7, #32\n\t"
        "eor	v26.16b, v8.16b, v18.16b\n\t"
        "eor	v27.16b, v9.16b, v19.16b\n\t"
        "eor	v26.16b, v26.16b, v20.16b\n\t"
        "eor	v27.16b, v27.16b, v21.16b\n\t"
        "stp	q26, q27, [x7]\n\t"
        "add	x7, x7, #32\n\t"
        "eor	v26.16b, v18.16b, v22.16b\n\t"
        "eor	v27.16b, v19.16b, v23.16b\n\t"
        "stp	q26, q27, [x7]\n\t"
        "add	x7, x7, #32\n\t"
        "eor	v26.16b, v10.16b, v20.16b\n\t"
        "eor	v27.16b, v11.16b, v21.16b\n\t"
        "eor	v26.16b, v26.16b, v22.16b\n\t"
        "eor	v27.16b, v27.16b, v23.16b\n\t"
        "stp	q26, q27, [x7]\n\t"
        "add	x7, x7, #32\n\t"
        "eor	v26.16b, v20.16b, v24.16b\n\t"
        "eor	v27.16b, v21.16b, v25.16b\n\t"
        "stp	q26, q27, [x7]\n\t"
        "add	x7, x7, #32\n\t"
        "eor	v26.16b, v12.16b, v22.16b\n\t"
        "eor	v27.16b, v13.16b, v23.16b\n\t"
        "eor	v26.16b, v26.16b, v24.16b\n\t"
        "eor	v27.16b, v27.16b, v25.16b\n\t"
        "stp	q26, q27, [x7]\n\t"
        "add	x7, x7, #32\n\t"
        "eor	v10.16b, v10.16b, v10.16b\n\t"
        "mov	x13, %x[c]\n\t"
        "mov	x8, #0\n\t"
        "\n"
    "L_mc_v256_z_iv_%=:\n\t"
        "stp	q10, q10, [x13]\n\t"
        "add	x13, x13, #32\n\t"
        "add	x8, x8, #1\n\t"
        "cmp	x8, #25\n\t"
        "b.lt	L_mc_v256_z_iv_%=\n\t"
        "mov	x6, #0\n\t"
        "\n"
    "L_mc_v256_i_iv_%=:\n\t"
        "cmp	x6, #13\n\t"
        "b.ge	L_mc_v256_rs_iv_%=\n\t"
        "lsl	x14, x6, #5\n\t"
        "add	x9, %x[out], x14\n\t"
        "ldp	q0, q1, [x9]\n\t"
        "mov	x7, #0\n\t"
        "\n"
    "L_mc_v256_j_iv_%=:\n\t"
        "cmp	x7, #13\n\t"
        "b.ge	L_mc_v256_in_iv_%=\n\t"
        "lsl	x14, x7, #5\n\t"
        "add	x10, %x[sq], x14\n\t"
        "ldp	q2, q3, [x10]\n\t"
        "and	v4.16b, v0.16b, v2.16b\n\t"
        "and	v5.16b, v1.16b, v3.16b\n\t"
        "add	x14, x6, x7\n\t"
        "lsl	x14, x14, #5\n\t"
        "add	x11, %x[c], x14\n\t"
        "ldp	q6, q7, [x11]\n\t"
        "eor	v6.16b, v6.16b, v4.16b\n\t"
        "eor	v7.16b, v7.16b, v5.16b\n\t"
        "stp	q6, q7, [x11]\n\t"
        "add	x7, x7, #1\n\t"
        "b	L_mc_v256_j_iv_%=\n\t"
        "\n"
    "L_mc_v256_in_iv_%=:\n\t"
        "add	x6, x6, #1\n\t"
        "b	L_mc_v256_i_iv_%=\n\t"
        "\n"
    "L_mc_v256_rs_iv_%=:\n\t"
        "mov	x8, #24\n\t"
        "\n"
    "L_mc_v256_rk_iv_%=:\n\t"
        "cmp	x8, #13\n\t"
        "b.lt	L_mc_v256_copy_iv_%=\n\t"
        "lsl	x14, x8, #5\n\t"
        "add	x11, %x[c], x14\n\t"
        "ldp	q6, q7, [x11]\n\t"
        "sub	x15, x8, #9\n\t"
        "lsl	x15, x15, #5\n\t"
        "add	x12, %x[c], x15\n\t"
        "ldp	q8, q9, [x12]\n\t"
        "eor	v8.16b, v8.16b, v6.16b\n\t"
        "eor	v9.16b, v9.16b, v7.16b\n\t"
        "stp	q8, q9, [x12]\n\t"
        "sub	x15, x8, #10\n\t"
        "lsl	x15, x15, #5\n\t"
        "add	x12, %x[c], x15\n\t"
        "ldp	q8, q9, [x12]\n\t"
        "eor	v8.16b, v8.16b, v6.16b\n\t"
        "eor	v9.16b, v9.16b, v7.16b\n\t"
        "stp	q8, q9, [x12]\n\t"
        "sub	x15, x8, #12\n\t"
        "lsl	x15, x15, #5\n\t"
        "add	x12, %x[c], x15\n\t"
        "ldp	q8, q9, [x12]\n\t"
        "eor	v8.16b, v8.16b, v6.16b\n\t"
        "eor	v9.16b, v9.16b, v7.16b\n\t"
        "stp	q8, q9, [x12]\n\t"
        "sub	x15, x8, #13\n\t"
        "lsl	x15, x15, #5\n\t"
        "add	x12, %x[c], x15\n\t"
        "ldp	q8, q9, [x12]\n\t"
        "eor	v8.16b, v8.16b, v6.16b\n\t"
        "eor	v9.16b, v9.16b, v7.16b\n\t"
        "stp	q8, q9, [x12]\n\t"
        "sub	x8, x8, #1\n\t"
        "b	L_mc_v256_rk_iv_%=\n\t"
        "\n"
    "L_mc_v256_copy_iv_%=:\n\t"
        "mov	x8, #0\n\t"
        "\n"
    "L_mc_v256_cp_iv_%=:\n\t"
        "cmp	x8, #13\n\t"
        "b.ge	L_mc_v256_done_iv_%=\n\t"
        "lsl	x14, x8, #5\n\t"
        "add	x11, %x[c], x14\n\t"
        "add	x12, %x[out], x14\n\t"
        "ldp	q6, q7, [x11]\n\t"
        "stp	q6, q7, [x12]\n\t"
        "add	x8, x8, #1\n\t"
        "b	L_mc_v256_cp_iv_%=\n\t"
        "\n"
    "L_mc_v256_done_iv_%=:\n\t"
        "add	x4, x4, #1\n\t"
        "b	L_mc_inv_l_%=\n\t"
        "\n"
    "L_mc_inv_le_%=:\n\t"
        : [out] "+r" (out), [sq] "+r" (sq), [c] "+r" (c)
        : [in] "r" (in)
        : "memory", "cc", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11",
            "x12", "x13", "x14", "x15", "v0", "v1", "v2", "v3", "v4", "v5",
            "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15",
            "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24",
            "v25", "v26", "v27"
    );
}

WOLFSSL_LOCAL void wc_mceliece_aff_maa_neon(word64* a_p, word64* b_p,
    const word64* c_p, word64* p_p, word64* cscr_p);
void wc_mceliece_aff_maa_neon(word64* a_p, word64* b_p, const word64* c_p,
    word64* p_p, word64* cscr_p)
{
    register word64* a __asm__ ("x0") = (word64*)a_p;
    register word64* b __asm__ ("x1") = (word64*)b_p;
    register const word64* c __asm__ ("x2") = (const word64*)c_p;
    register word64* p __asm__ ("x3") = (word64*)p_p;
    register word64* cscr __asm__ ("x4") = (word64*)cscr_p;
    __asm__ __volatile__ (
        "eor	v10.16b, v10.16b, v10.16b\n\t"
        "mov	x12, %x[cscr]\n\t"
        "mov	x7, #0\n\t"
        "\n"
    "L_mc_v256_z_maa_%=:\n\t"
        "stp	q10, q10, [x12]\n\t"
        "add	x12, x12, #32\n\t"
        "add	x7, x7, #1\n\t"
        "cmp	x7, #25\n\t"
        "b.lt	L_mc_v256_z_maa_%=\n\t"
        "mov	x5, #0\n\t"
        "\n"
    "L_mc_v256_i_maa_%=:\n\t"
        "cmp	x5, #13\n\t"
        "b.ge	L_mc_v256_rs_maa_%=\n\t"
        "lsl	x13, x5, #5\n\t"
        "add	x8, %x[b], x13\n\t"
        "ldp	q0, q1, [x8]\n\t"
        "mov	x6, #0\n\t"
        "\n"
    "L_mc_v256_j_maa_%=:\n\t"
        "cmp	x6, #13\n\t"
        "b.ge	L_mc_v256_in_maa_%=\n\t"
        "lsl	x13, x6, #5\n\t"
        "add	x9, %x[c], x13\n\t"
        "ldp	q2, q3, [x9]\n\t"
        "and	v4.16b, v0.16b, v2.16b\n\t"
        "and	v5.16b, v1.16b, v3.16b\n\t"
        "add	x13, x5, x6\n\t"
        "lsl	x13, x13, #5\n\t"
        "add	x10, %x[cscr], x13\n\t"
        "ldp	q6, q7, [x10]\n\t"
        "eor	v6.16b, v6.16b, v4.16b\n\t"
        "eor	v7.16b, v7.16b, v5.16b\n\t"
        "stp	q6, q7, [x10]\n\t"
        "add	x6, x6, #1\n\t"
        "b	L_mc_v256_j_maa_%=\n\t"
        "\n"
    "L_mc_v256_in_maa_%=:\n\t"
        "add	x5, x5, #1\n\t"
        "b	L_mc_v256_i_maa_%=\n\t"
        "\n"
    "L_mc_v256_rs_maa_%=:\n\t"
        "mov	x7, #24\n\t"
        "\n"
    "L_mc_v256_rk_maa_%=:\n\t"
        "cmp	x7, #13\n\t"
        "b.lt	L_mc_v256_copy_maa_%=\n\t"
        "lsl	x13, x7, #5\n\t"
        "add	x10, %x[cscr], x13\n\t"
        "ldp	q6, q7, [x10]\n\t"
        "sub	x14, x7, #9\n\t"
        "lsl	x14, x14, #5\n\t"
        "add	x11, %x[cscr], x14\n\t"
        "ldp	q8, q9, [x11]\n\t"
        "eor	v8.16b, v8.16b, v6.16b\n\t"
        "eor	v9.16b, v9.16b, v7.16b\n\t"
        "stp	q8, q9, [x11]\n\t"
        "sub	x14, x7, #10\n\t"
        "lsl	x14, x14, #5\n\t"
        "add	x11, %x[cscr], x14\n\t"
        "ldp	q8, q9, [x11]\n\t"
        "eor	v8.16b, v8.16b, v6.16b\n\t"
        "eor	v9.16b, v9.16b, v7.16b\n\t"
        "stp	q8, q9, [x11]\n\t"
        "sub	x14, x7, #12\n\t"
        "lsl	x14, x14, #5\n\t"
        "add	x11, %x[cscr], x14\n\t"
        "ldp	q8, q9, [x11]\n\t"
        "eor	v8.16b, v8.16b, v6.16b\n\t"
        "eor	v9.16b, v9.16b, v7.16b\n\t"
        "stp	q8, q9, [x11]\n\t"
        "sub	x14, x7, #13\n\t"
        "lsl	x14, x14, #5\n\t"
        "add	x11, %x[cscr], x14\n\t"
        "ldp	q8, q9, [x11]\n\t"
        "eor	v8.16b, v8.16b, v6.16b\n\t"
        "eor	v9.16b, v9.16b, v7.16b\n\t"
        "stp	q8, q9, [x11]\n\t"
        "sub	x7, x7, #1\n\t"
        "b	L_mc_v256_rk_maa_%=\n\t"
        "\n"
    "L_mc_v256_copy_maa_%=:\n\t"
        "mov	x7, #0\n\t"
        "\n"
    "L_mc_v256_cp_maa_%=:\n\t"
        "cmp	x7, #13\n\t"
        "b.ge	L_mc_v256_done_maa_%=\n\t"
        "lsl	x13, x7, #5\n\t"
        "add	x10, %x[cscr], x13\n\t"
        "add	x11, %x[p], x13\n\t"
        "ldp	q6, q7, [x10]\n\t"
        "stp	q6, q7, [x11]\n\t"
        "add	x7, x7, #1\n\t"
        "b	L_mc_v256_cp_maa_%=\n\t"
        "\n"
    "L_mc_v256_done_maa_%=:\n\t"
        "mov	x5, #0\n\t"
        "\n"
    "L_mc_xor13_k_maaa_%=:\n\t"
        "lsl	x6, x5, #5\n\t"
        "add	x8, %x[a], x6\n\t"
        "ldp	q0, q1, [x8]\n\t"
        "add	x9, %x[p], x6\n\t"
        "ldp	q2, q3, [x9]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x7, %x[a], x6\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x5, x5, #1\n\t"
        "cmp	x5, #13\n\t"
        "b.lt	L_mc_xor13_k_maaa_%=\n\t"
        "mov	x5, #0\n\t"
        "\n"
    "L_mc_xor13_k_maab_%=:\n\t"
        "lsl	x6, x5, #5\n\t"
        "add	x8, %x[b], x6\n\t"
        "ldp	q0, q1, [x8]\n\t"
        "add	x9, %x[a], x6\n\t"
        "ldp	q2, q3, [x9]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x7, %x[b], x6\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x5, x5, #1\n\t"
        "cmp	x5, #13\n\t"
        "b.lt	L_mc_xor13_k_maab_%=\n\t"
        : [a] "+r" (a), [b] "+r" (b), [p] "+r" (p), [cscr] "+r" (cscr)
        : [c] "r" (c)
        : "memory", "cc", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12",
            "x13", "x14", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8",
            "v9", "v10"
    );
}

WOLFSSL_LOCAL void wc_mceliece_aff_v256_xor13_neon(word64* r_p,
    const word64* a_p, const word64* b_p);
void wc_mceliece_aff_v256_xor13_neon(word64* r_p, const word64* a_p,
    const word64* b_p)
{
    register word64* r __asm__ ("x0") = (word64*)r_p;
    register const word64* a __asm__ ("x1") = (const word64*)a_p;
    register const word64* b __asm__ ("x2") = (const word64*)b_p;
    __asm__ __volatile__ (
        "mov	x3, #0\n\t"
        "\n"
    "L_mc_xor13_k_%=:\n\t"
        "lsl	x4, x3, #5\n\t"
        "add	x6, %x[a], x4\n\t"
        "ldp	q0, q1, [x6]\n\t"
        "add	x7, %x[b], x4\n\t"
        "ldp	q2, q3, [x7]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x5, %x[r], x4\n\t"
        "stp	q0, q1, [x5]\n\t"
        "add	x3, x3, #1\n\t"
        "cmp	x3, #13\n\t"
        "b.lt	L_mc_xor13_k_%=\n\t"
        : [r] "+r" (r)
        : [a] "r" (a), [b] "r" (b)
        : "memory", "cc", "x3", "x4", "x5", "x6", "x7", "v0", "v1", "v2", "v3"
    );
}

WOLFSSL_LOCAL void wc_mceliece_aff_pack_lh_neon(word64* lo_p, word64* hi_p,
    const word64* a_p, const word64* b_p);
void wc_mceliece_aff_pack_lh_neon(word64* lo_p, word64* hi_p, const word64* a_p,
    const word64* b_p)
{
    register word64* lo __asm__ ("x0") = (word64*)lo_p;
    register word64* hi __asm__ ("x1") = (word64*)hi_p;
    register const word64* a __asm__ ("x2") = (const word64*)a_p;
    register const word64* b __asm__ ("x3") = (const word64*)b_p;
    __asm__ __volatile__ (
        "mov	x4, #0\n\t"
        "\n"
    "L_mc_packlh_p_%=:\n\t"
        "lsl	x5, x4, #5\n\t"
        "add	x8, %x[a], x5\n\t"
        "ldp	q0, q1, [x8]\n\t"
        "add	x9, %x[b], x5\n\t"
        "ldp	q2, q3, [x9]\n\t"
        "add	x6, %x[lo], x5\n\t"
        "stp	q0, q2, [x6]\n\t"
        "add	x7, %x[hi], x5\n\t"
        "stp	q1, q3, [x7]\n\t"
        "add	x4, x4, #1\n\t"
        "cmp	x4, #13\n\t"
        "b.lt	L_mc_packlh_p_%=\n\t"
        : [lo] "+r" (lo), [hi] "+r" (hi)
        : [a] "r" (a), [b] "r" (b)
        : "memory", "cc", "x4", "x5", "x6", "x7", "x8", "x9", "v0", "v1", "v2",
            "v3"
    );
}

WOLFSSL_LOCAL void wc_mceliece_aff_radix_step_neon(word64* in_p, int j_p);
void wc_mceliece_aff_radix_step_neon(word64* in_p, int j_p)
{
    register word64* in __asm__ ("x0") = (word64*)in_p;
    register int j __asm__ ("w1") = (int)j_p;
    register const word64* L_mc_aff_rmask0_neon_c __asm__ ("x3") = L_mc_aff_rmask0_neon;
    register const word64* L_mc_aff_rmask1_neon_c __asm__ ("x4") = L_mc_aff_rmask1_neon;
    __asm__ __volatile__ (
        "mov	w2, %w[j]\n\t"
        "eor	v6.16b, v6.16b, v6.16b\n\t"
        "mov	x14, #1\n\t"
        "mov	x8, #0\n\t"
        "\n"
    "L_mc_rdx_t_%=:\n\t"
        "cmp	x8, #13\n\t"
        "b.ge	L_mc_rdx_te_%=\n\t"
        "lsl	x9, x8, #4\n\t"
        "add	x10, %x[in], x9\n\t"
        "ldr	q0, [x10]\n\t"
        "ushr	v5.2d, v0.2d, #32\n\t"
        "zip2	v5.2d, v6.2d, v5.2d\n\t"
        "eor	v0.16b, v0.16b, v5.16b\n\t"
        "shl	v5.2d, v0.2d, #32\n\t"
        "zip2	v5.2d, v5.2d, v6.2d\n\t"
        "eor	v0.16b, v0.16b, v5.16b\n\t"
        "str	q0, [x10]\n\t"
        "add	x8, x8, #1\n\t"
        "b	L_mc_rdx_t_%=\n\t"
        "\n"
    "L_mc_rdx_te_%=:\n\t"
        "mov	x5, #4\n\t"
        "\n"
    "L_mc_rdx_k_%=:\n\t"
        "cmp	x5, x2\n\t"
        "b.lt	L_mc_rdx_ke_%=\n\t"
        "lsl	x6, x14, x5\n\t"
        "neg	x7, x6\n\t"
        "dup	v4.2d, x7\n\t"
        "lsl	x9, x5, #3\n\t"
        "add	x11, %[L_mc_aff_rmask0_neon_c], x9\n\t"
        "ldr	x12, [x11]\n\t"
        "dup	v2.2d, x12\n\t"
        "add	x11, %[L_mc_aff_rmask1_neon_c], x9\n\t"
        "ldr	x13, [x11]\n\t"
        "dup	v3.2d, x13\n\t"
        "mov	x8, #0\n\t"
        "\n"
    "L_mc_rdx_ki_%=:\n\t"
        "cmp	x8, #13\n\t"
        "b.ge	L_mc_rdx_kie_%=\n\t"
        "lsl	x9, x8, #4\n\t"
        "add	x10, %x[in], x9\n\t"
        "ldr	q0, [x10]\n\t"
        "and	v1.16b, v0.16b, v2.16b\n\t"
        "ushl	v1.2d, v1.2d, v4.2d\n\t"
        "eor	v0.16b, v0.16b, v1.16b\n\t"
        "and	v1.16b, v0.16b, v3.16b\n\t"
        "ushl	v1.2d, v1.2d, v4.2d\n\t"
        "eor	v0.16b, v0.16b, v1.16b\n\t"
        "str	q0, [x10]\n\t"
        "add	x8, x8, #1\n\t"
        "b	L_mc_rdx_ki_%=\n\t"
        "\n"
    "L_mc_rdx_kie_%=:\n\t"
        "sub	x5, x5, #1\n\t"
        "b	L_mc_rdx_k_%=\n\t"
        "\n"
    "L_mc_rdx_ke_%=:\n\t"
        : [in] "+r" (in), [j] "+r" (j)
        : [L_mc_aff_rmask0_neon_c] "r" (L_mc_aff_rmask0_neon_c),
          [L_mc_aff_rmask1_neon_c] "r" (L_mc_aff_rmask1_neon_c)
        : "memory", "cc", "x2", "x5", "x6", "x7", "x8", "x9", "x10", "x11",
            "x12", "x13", "x14", "v0", "v1", "v2", "v3", "v4", "v5", "v6"
    );
}

WOLFSSL_LOCAL void wc_mceliece_aff_fwd_out_neon(word64* out_p,
    const word64* buf_p, const byte* rev_p, int i_p);
void wc_mceliece_aff_fwd_out_neon(word64* out_p, const word64* buf_p,
    const byte* rev_p, int i_p)
{
    register word64* out __asm__ ("x0") = (word64*)out_p;
    register const word64* buf __asm__ ("x1") = (const word64*)buf_p;
    register const byte* rev __asm__ ("x2") = (const byte*)rev_p;
    register int i __asm__ ("w3") = (int)i_p;
    __asm__ __volatile__ (
        "mov	w4, %w[i]\n\t"
        "mov	x14, #13\n\t"
        "mov	x5, #0\n\t"
        "\n"
    "L_mc_fwo_j_%=:\n\t"
        "cmp	x5, #32\n\t"
        "b.ge	L_mc_fwo_e_%=\n\t"
        "lsl	x8, x5, #1\n\t"
        "add	x9, %x[rev], x8\n\t"
        "ldrb	w6, [x9]\n\t"
        "add	x9, x9, #1\n\t"
        "ldrb	w7, [x9]\n\t"
        "lsl	x8, x6, #5\n\t"
        "add	x10, %x[buf], x8\n\t"
        "ldp	q0, q1, [x10]\n\t"
        "lsl	x8, x7, #5\n\t"
        "add	x11, %x[buf], x8\n\t"
        "ldp	q2, q3, [x11]\n\t"
        "madd	x8, x5, x14, x4\n\t"
        "lsl	x8, x8, #5\n\t"
        "add	x12, %x[out], x8\n\t"
        "stp	q0, q2, [x12]\n\t"
        "cmp	x4, #12\n\t"
        "b.eq	L_mc_fwo_no_%=\n\t"
        "add	x13, x12, #32\n\t"
        "stp	q1, q3, [x13]\n\t"
        "\n"
    "L_mc_fwo_no_%=:\n\t"
        "add	x5, x5, #1\n\t"
        "b	L_mc_fwo_j_%=\n\t"
        "\n"
    "L_mc_fwo_e_%=:\n\t"
        : [out] "+r" (out), [i] "+r" (i)
        : [buf] "r" (buf), [rev] "r" (rev)
        : "memory", "cc", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11",
            "x12", "x13", "x14", "v0", "v1", "v2", "v3"
    );
}

WOLFSSL_LOCAL void wc_mceliece_fft_fwd_butterflies_neon(word64* out_p,
    word64* in_p, int monic_p, word64* scratch_p);
void wc_mceliece_fft_fwd_butterflies_neon(word64* out_p, word64* in_p,
    int monic_p, word64* scratch_p)
{
    register word64* out __asm__ ("x0") = (word64*)out_p;
    register word64* in __asm__ ("x1") = (word64*)in_p;
    register int monic __asm__ ("w2") = (int)monic_p;
    register word64* scratch __asm__ ("x3") = (word64*)scratch_p;
    register const word64* L_mc_aff_consts_neon_c __asm__ ("x4") = L_mc_aff_consts_neon;
    register const word64* L_mc_aff_powers_neon_c __asm__ ("x5") = L_mc_aff_powers_neon;
    register const word8* L_mc_aff_reversal_neon_c __asm__ ("x6") = L_mc_aff_reversal_neon;
    __asm__ __volatile__ (
        "mov	x19, %x[out]\n\t"
        "mov	x20, %x[in]\n\t"
        "mov	w21, %w[monic]\n\t"
        "mov	x22, %x[scratch]\n\t"
        "mov	x23, %[L_mc_aff_consts_neon_c]\n\t"
        "mov	x24, %[L_mc_aff_powers_neon_c]\n\t"
        "mov	x25, %[L_mc_aff_reversal_neon_c]\n\t"
        "add	x12, x22, #0x1a0\n\t"
        "mov	x8, #0\n\t"
        "mov	x7, #0\n\t"
        "\n"
    "L_mc_ffb_pz_%=:\n\t"
        "cmp	x7, #0xe0\n\t"
        "b.ge	L_mc_ffb_pze_%=\n\t"
        "lsl	x10, x7, #3\n\t"
        "add	x9, x12, x10\n\t"
        "str	x8, [x9]\n\t"
        "add	x7, x7, #1\n\t"
        "b	L_mc_ffb_pz_%=\n\t"
        "\n"
    "L_mc_ffb_pze_%=:\n\t"
        "add	x7, x20, #0\n\t"
        "ldr	x8, [x7, #8]\n\t"
        "add	x7, x22, #0xd0\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x20, #16\n\t"
        "ldr	x8, [x7, #8]\n\t"
        "add	x7, x22, #0xe0\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x20, #32\n\t"
        "ldr	x8, [x7, #8]\n\t"
        "add	x7, x22, #0xf0\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x20, #48\n\t"
        "ldr	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x100\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x20, #0x40\n\t"
        "ldr	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x110\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x20, #0x50\n\t"
        "ldr	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x120\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x20, #0x60\n\t"
        "ldr	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x130\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x20, #0x70\n\t"
        "ldr	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x140\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x20, #0x80\n\t"
        "ldr	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x150\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x20, #0x90\n\t"
        "ldr	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x160\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x20, #0xa0\n\t"
        "ldr	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x170\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x20, #0xb0\n\t"
        "ldr	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x180\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x20, #0xc0\n\t"
        "ldr	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x190\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "mov	x16, #0\n\t"
        "sub	x16, x16, #1\n\t"
        "mov	x9, #0\n\t"
        "add	x7, x22, #0\n\t"
        "str	x9, [x7]\n\t"
        "str	x16, [x7, #8]\n\t"
        "add	x7, x22, #16\n\t"
        "str	x16, [x7]\n\t"
        "str	x16, [x7, #8]\n\t"
        "add	x7, x22, #32\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #48\n\t"
        "str	x16, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x40\n\t"
        "str	x16, [x7]\n\t"
        "str	x16, [x7, #8]\n\t"
        "add	x7, x22, #0x50\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x60\n\t"
        "str	x16, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x70\n\t"
        "str	x16, [x7]\n\t"
        "str	x16, [x7, #8]\n\t"
        "add	x7, x22, #0x80\n\t"
        "str	x16, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x90\n\t"
        "str	x9, [x7]\n\t"
        "str	x16, [x7, #8]\n\t"
        "add	x7, x22, #0xa0\n\t"
        "str	x9, [x7]\n\t"
        "str	x16, [x7, #8]\n\t"
        "add	x7, x22, #0xb0\n\t"
        "str	x16, [x7]\n\t"
        "str	x16, [x7, #8]\n\t"
        "add	x7, x22, #0xc0\n\t"
        "str	x9, [x7]\n\t"
        "str	x16, [x7, #8]\n\t"
        "mov	%x[out], x22\n\t"
        "add	%x[in], x22, #0xd0\n\t"
        "mov	%x[monic], x22\n\t"
        "add	%x[scratch], x22, #0x8a0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_v128_mul_neon\n\t"
#else
        "bl	_wc_mceliece_aff_v128_mul_neon\n\t"
#endif /* __APPLE__ */
        "add	x7, x22, #0\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x1a0\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x280\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #16\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x1b0\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x290\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #32\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x1c0\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x2a0\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #48\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x1d0\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x2b0\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x40\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x1e0\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x2c0\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x50\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x1f0\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x2d0\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x60\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x200\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x2e0\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x70\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x210\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x2f0\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x80\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x220\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x300\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x90\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x230\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x310\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0xa0\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x240\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x320\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0xb0\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x250\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x330\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0xc0\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x260\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x340\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "mov	x16, #0\n\t"
        "sub	x16, x16, #1\n\t"
        "mov	x9, #0\n\t"
        "add	x7, x22, #0\n\t"
        "str	x16, [x7]\n\t"
        "str	x16, [x7, #8]\n\t"
        "add	x7, x22, #16\n\t"
        "str	x9, [x7]\n\t"
        "str	x16, [x7, #8]\n\t"
        "add	x7, x22, #32\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #48\n\t"
        "str	x16, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x40\n\t"
        "str	x16, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x50\n\t"
        "str	x16, [x7]\n\t"
        "str	x16, [x7, #8]\n\t"
        "add	x7, x22, #0x60\n\t"
        "str	x16, [x7]\n\t"
        "str	x16, [x7, #8]\n\t"
        "add	x7, x22, #0x70\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x80\n\t"
        "str	x9, [x7]\n\t"
        "str	x16, [x7, #8]\n\t"
        "add	x7, x22, #0x90\n\t"
        "str	x16, [x7]\n\t"
        "str	x16, [x7, #8]\n\t"
        "add	x7, x22, #0xa0\n\t"
        "str	x16, [x7]\n\t"
        "str	x16, [x7, #8]\n\t"
        "add	x7, x22, #0xb0\n\t"
        "str	x16, [x7]\n\t"
        "str	x16, [x7, #8]\n\t"
        "add	x7, x22, #0xc0\n\t"
        "str	x16, [x7]\n\t"
        "str	x16, [x7, #8]\n\t"
        "mov	%x[out], x22\n\t"
        "add	%x[in], x22, #0xd0\n\t"
        "mov	%x[monic], x22\n\t"
        "add	%x[scratch], x22, #0x8a0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_v128_mul_neon\n\t"
#else
        "bl	_wc_mceliece_aff_v128_mul_neon\n\t"
#endif /* __APPLE__ */
        "add	x7, x22, #0\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x360\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x440\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #16\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x370\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x450\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #32\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x380\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x460\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #48\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x390\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x470\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x40\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x3a0\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x480\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x50\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x3b0\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x490\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x60\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x3c0\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x4a0\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x70\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x3d0\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x4b0\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x80\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x3e0\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x4c0\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x90\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x3f0\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x4d0\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0xa0\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x400\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x4e0\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0xb0\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x410\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x4f0\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0xc0\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x420\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x500\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "mov	x16, #0\n\t"
        "sub	x16, x16, #1\n\t"
        "mov	x9, #0\n\t"
        "add	x7, x22, #0\n\t"
        "str	x16, [x7]\n\t"
        "str	x16, [x7, #8]\n\t"
        "add	x7, x22, #16\n\t"
        "str	x9, [x7]\n\t"
        "str	x16, [x7, #8]\n\t"
        "add	x7, x22, #32\n\t"
        "str	x9, [x7]\n\t"
        "str	x16, [x7, #8]\n\t"
        "add	x7, x22, #48\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x40\n\t"
        "str	x16, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x50\n\t"
        "str	x16, [x7]\n\t"
        "str	x16, [x7, #8]\n\t"
        "add	x7, x22, #0x60\n\t"
        "str	x16, [x7]\n\t"
        "str	x16, [x7, #8]\n\t"
        "add	x7, x22, #0x70\n\t"
        "str	x16, [x7]\n\t"
        "str	x16, [x7, #8]\n\t"
        "add	x7, x22, #0x80\n\t"
        "str	x9, [x7]\n\t"
        "str	x16, [x7, #8]\n\t"
        "add	x7, x22, #0x90\n\t"
        "str	x16, [x7]\n\t"
        "str	x16, [x7, #8]\n\t"
        "add	x7, x22, #0xa0\n\t"
        "str	x9, [x7]\n\t"
        "str	x16, [x7, #8]\n\t"
        "add	x7, x22, #0xb0\n\t"
        "str	x16, [x7]\n\t"
        "str	x16, [x7, #8]\n\t"
        "add	x7, x22, #0xc0\n\t"
        "str	x16, [x7]\n\t"
        "str	x16, [x7, #8]\n\t"
        "mov	%x[out], x22\n\t"
        "add	%x[in], x22, #0xd0\n\t"
        "mov	%x[monic], x22\n\t"
        "add	%x[scratch], x22, #0x8a0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_v128_mul_neon\n\t"
#else
        "bl	_wc_mceliece_aff_v128_mul_neon\n\t"
#endif /* __APPLE__ */
        "add	x7, x22, #0\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x520\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x600\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #16\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x530\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x610\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #32\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x540\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x620\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #48\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x550\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x630\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x40\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x560\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x640\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x50\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x570\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x650\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x60\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x580\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x660\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x70\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x590\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x670\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x80\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x5a0\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x680\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x90\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x5b0\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x690\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0xa0\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x5c0\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x6a0\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0xb0\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x5d0\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x6b0\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0xc0\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x5e0\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x6c0\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "mov	x16, #0\n\t"
        "sub	x16, x16, #1\n\t"
        "mov	x9, #0\n\t"
        "add	x7, x22, #0\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #16\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #32\n\t"
        "str	x16, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #48\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x40\n\t"
        "str	x16, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x50\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x60\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x70\n\t"
        "str	x16, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x80\n\t"
        "str	x16, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x90\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0xa0\n\t"
        "str	x16, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0xb0\n\t"
        "str	x16, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0xc0\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "mov	%x[out], x22\n\t"
        "add	%x[in], x22, #0xd0\n\t"
        "mov	%x[monic], x22\n\t"
        "add	%x[scratch], x22, #0x8a0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_v128_mul_neon\n\t"
#else
        "bl	_wc_mceliece_aff_v128_mul_neon\n\t"
#endif /* __APPLE__ */
        "add	x7, x22, #0\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x6e0\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x7c0\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #16\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x6f0\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x7d0\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #32\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x700\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x7e0\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #48\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x710\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x7f0\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x40\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x720\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x800\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x50\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x730\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x810\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x60\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x740\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x820\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x70\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x750\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x830\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x80\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x760\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x840\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x90\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x770\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x850\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0xa0\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x780\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x860\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0xb0\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x790\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x870\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "add	x7, x22, #0xc0\n\t"
        "ldr	x8, [x7]\n\t"
        "ldr	x9, [x7, #8]\n\t"
        "add	x7, x22, #0x7a0\n\t"
        "str	x8, [x7]\n\t"
        "str	x8, [x7, #8]\n\t"
        "add	x7, x22, #0x880\n\t"
        "str	x9, [x7]\n\t"
        "str	x9, [x7, #8]\n\t"
        "mov	x26, #0\n\t"
        "\n"
    "L_mc_ffb_i_%=:\n\t"
        "cmp	x26, #13\n\t"
        "b.ge	L_mc_ffb_ie_%=\n\t"
        "lsl	x10, x26, #4\n\t"
        "add	x11, x20, x10\n\t"
        "add	x13, x22, #0x8a0\n\t"
        "ldr	x7, [x11]\n\t"
        "str	x7, [x13]\n\t"
        "add	x12, x22, #0x6e0\n\t"
        "add	x12, x12, x10\n\t"
        "ldr	x8, [x12]\n\t"
        "eor	x9, x7, x8\n\t"
        "str	x9, [x13, #8]\n\t"
        "cmp	x26, #12\n\t"
        "b.eq	L_mc_ffb_hi_%=\n\t"
        "ldr	x7, [x11, #16]\n\t"
        "str	x7, [x13, #16]\n\t"
        "ldr	x8, [x12, #16]\n\t"
        "eor	x9, x7, x8\n\t"
        "str	x9, [x13, #24]\n\t"
        "\n"
    "L_mc_ffb_hi_%=:\n\t"
        "lsr	x15, x26, #1\n\t"
        "lsl	x10, x15, #5\n\t"
        "add	x14, x22, x10\n\t"
        "add	x14, x14, #0x1a0\n\t"
        "add	x7, x13, #0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #32\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0x380\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x200\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #32\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0xe0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x60\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x200\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0x460\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x600\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x600\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x620\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0xe0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x40\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x620\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0xe0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x660\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x40\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0x1c0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0xc0\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x660\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x640\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0xc0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0xe0\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x640\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0x1c0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x6c0\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0xe0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0xe0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0xa0\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x6c0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x6e0\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x6e0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0xe0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x6a0\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0x1c0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x80\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x6a0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x680\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x80\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0x2a0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x180\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x680\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0x2a0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x780\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x180\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x1a0\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x780\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x7a0\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x1a0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0xe0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x1e0\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x7a0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0xe0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x7e0\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x1e0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x1c0\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x7e0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x7c0\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x1c0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0x1c0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x140\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x7c0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0x1c0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x740\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x140\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x160\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x740\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x760\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x160\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0xe0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x120\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x760\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0xe0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x720\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x720\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x700\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0x2a0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x100\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x700\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0x380\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x500\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x100\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0x380\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x300\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x500\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x520\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x300\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x320\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x520\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0xe0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x560\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x320\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0xe0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x360\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x560\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x540\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x360\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x340\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x540\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0x1c0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x5c0\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x340\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0x1c0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x3c0\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x5c0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x5e0\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x3c0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x3e0\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x5e0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0xe0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x5a0\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x3e0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0xe0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x3a0\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x5a0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x580\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x3a0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x380\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x580\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0x2a0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x480\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x380\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0x2a0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x280\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x480\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x4a0\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x280\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x2a0\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x4a0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0xe0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x4e0\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x2a0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0xe0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x2e0\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x4e0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x4c0\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x2e0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x2c0\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x4c0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0x1c0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x440\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x2c0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0x1c0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x240\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x440\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x460\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x240\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x260\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x460\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0xe0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x420\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x260\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0xe0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x220\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x13, #0x420\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x8, x14, #0\n\t"
        "ldp	q2, q3, [x8]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x9, x13, #0x400\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	%x[out], x22, #0x8a0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_transpose_neon\n\t"
#else
        "bl	_wc_mceliece_aff_transpose_neon\n\t"
#endif /* __APPLE__ */
        "mov	%x[out], x19\n\t"
        "add	%x[in], x22, #0x8a0\n\t"
        "mov	%x[monic], x25\n\t"
        "mov	%w[scratch], w26\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_fwd_out_neon\n\t"
#else
        "bl	_wc_mceliece_aff_fwd_out_neon\n\t"
#endif /* __APPLE__ */
        "add	x26, x26, #2\n\t"
        "b	L_mc_ffb_i_%=\n\t"
        "\n"
    "L_mc_ffb_ie_%=:\n\t"
        "mov	x26, #0\n\t"
        "\n"
    "L_mc_ffb_pk_%=:\n\t"
        "cmp	x26, #32\n\t"
        "b.ge	L_mc_ffb_pke_%=\n\t"
        "mov	x7, #0x1a0\n\t"
        "mul	x10, x26, x7\n\t"
        "add	%x[out], x22, #0x8a0\n\t"
        "add	%x[in], x22, #0xa40\n\t"
        "add	%x[monic], x19, x10\n\t"
        "add	%x[scratch], %x[monic], #0x1a0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_pack_lh_neon\n\t"
#else
        "bl	_wc_mceliece_aff_pack_lh_neon\n\t"
#endif /* __APPLE__ */
        "add	%x[out], x22, #0x8a0\n\t"
        "add	%x[in], x22, #0xa40\n\t"
        "add	%x[monic], x23, #0x1a0\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x1a0\n\t"
        "mul	x10, x26, x7\n\t"
        "add	%x[out], x19, x10\n\t"
        "add	%x[in], %x[out], #0x1a0\n\t"
        "add	%x[monic], x22, #0x8a0\n\t"
        "add	%x[scratch], x22, #0xa40\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_pack_lh_neon\n\t"
#else
        "bl	_wc_mceliece_aff_pack_lh_neon\n\t"
#endif /* __APPLE__ */
        "add	x26, x26, #2\n\t"
        "b	L_mc_ffb_pk_%=\n\t"
        "\n"
    "L_mc_ffb_pke_%=:\n\t"
        "mov	x7, #0\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x1a0\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x340\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x340\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x4e0\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x340\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x680\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x820\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x340\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x9c0\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0xb60\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x340\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0xd00\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0xea0\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x340\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x1040\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x11e0\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x340\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x1380\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x1520\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x340\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x16c0\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x1860\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x340\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x1a00\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x1ba0\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x340\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x1d40\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x1ee0\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x340\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x2080\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x2220\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x340\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x23c0\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x2560\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x340\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x2700\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x28a0\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x340\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x2a40\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x2be0\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x340\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x2d80\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x2f20\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x340\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x30c0\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x3260\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x340\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x340\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x4e0\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x1a0\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x4e0\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x680\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x680\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x9c0\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x4e0\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x820\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0xb60\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x680\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0xd00\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x1040\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x4e0\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0xea0\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x11e0\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x680\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x1380\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x16c0\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x4e0\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x1520\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x1860\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x680\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x1a00\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x1d40\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x4e0\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x1ba0\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x1ee0\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x680\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x2080\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x23c0\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x4e0\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x2220\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x2560\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x680\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x2700\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x2a40\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x4e0\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x28a0\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x2be0\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x680\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x2d80\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x30c0\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x4e0\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x2f20\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x3260\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x680\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x680\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x820\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x1a0\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x820\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x9c0\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x340\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x9c0\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0xb60\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x4e0\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0xb60\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0xd00\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0xd00\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x1380\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x820\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0xea0\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x1520\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x9c0\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x1040\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x16c0\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0xb60\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x11e0\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x1860\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0xd00\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x1a00\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x2080\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x820\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x1ba0\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x2220\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x9c0\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x1d40\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x23c0\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0xb60\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x1ee0\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x2560\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0xd00\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x2700\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x2d80\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x820\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x28a0\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x2f20\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x9c0\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x2a40\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x30c0\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0xb60\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x2be0\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x3260\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0xd00\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0xd00\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0xea0\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x1a0\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0xea0\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x1040\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x340\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x1040\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x11e0\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x4e0\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x11e0\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x1380\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x680\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x1380\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x1520\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x820\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x1520\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x16c0\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x9c0\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x16c0\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x1860\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0xb60\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x1860\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x1a00\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x1a00\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x2700\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0xea0\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x1ba0\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x28a0\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x1040\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x1d40\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x2a40\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x11e0\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x1ee0\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x2be0\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x1380\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x2080\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x2d80\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x1520\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x2220\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x2f20\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x16c0\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x23c0\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x30c0\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x1860\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x2560\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x3260\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x1a00\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x1a00\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x1ba0\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x1a0\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x1ba0\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x1d40\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x340\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x1d40\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x1ee0\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x4e0\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x1ee0\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x2080\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x680\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x2080\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x2220\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x820\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x2220\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x23c0\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x9c0\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x23c0\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x2560\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0xb60\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x2560\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x2700\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0xd00\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x2700\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x28a0\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0xea0\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x28a0\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x2a40\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x1040\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x2a40\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x2be0\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x11e0\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x2be0\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x2d80\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x1380\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x2d80\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x2f20\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x1520\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x2f20\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x30c0\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x16c0\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x30c0\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x3260\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "mov	x7, #0x1860\n\t"
        "add	%x[out], x19, x7\n\t"
        "mov	x7, #0x3260\n\t"
        "add	%x[in], x19, x7\n\t"
        "mov	x7, #0x3400\n\t"
        "add	%x[monic], x23, x7\n\t"
        "add	%x[scratch], x22, #0xbe0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x22, #0xd80\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_maa_neon\n\t"
#else
        "bl	_wc_mceliece_aff_maa_neon\n\t"
#endif /* __APPLE__ */
        "cbz	w21, L_mc_ffb_nm_%=\n\t"
        "mov	x7, #0\n\t"
        "\n"
    "L_mc_ffb_mo_%=:\n\t"
        "cmp	x7, #0x1a0\n\t"
        "b.ge	L_mc_ffb_moe_%=\n\t"
        "lsl	x10, x7, #5\n\t"
        "add	x8, x19, x10\n\t"
        "ldp	q0, q1, [x8]\n\t"
        "add	x9, x24, x10\n\t"
        "ldp	q2, q3, [x9]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x8]\n\t"
        "add	x7, x7, #1\n\t"
        "b	L_mc_ffb_mo_%=\n\t"
        "\n"
    "L_mc_ffb_moe_%=:\n\t"
        "\n"
    "L_mc_ffb_nm_%=:\n\t"
        : [out] "+r" (out), [in] "+r" (in), [monic] "+r" (monic),
          [scratch] "+r" (scratch)
        : [L_mc_aff_consts_neon_c] "r" (L_mc_aff_consts_neon_c),
          [L_mc_aff_powers_neon_c] "r" (L_mc_aff_powers_neon_c),
          [L_mc_aff_reversal_neon_c] "r" (L_mc_aff_reversal_neon_c)
        : "memory", "cc", "x19", "x20", "x21", "x22", "x23", "x24", "x25",
            "x26", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
            "x16", "v0", "v1", "v2", "v3", "x30"
    );
}

WOLFSSL_LOCAL void wc_mceliece_bs_poly_neon(word64* in_p, const word16* c_p);
void wc_mceliece_bs_poly_neon(word64* in_p, const word16* c_p)
{
    register word64* in __asm__ ("x0") = (word64*)in_p;
    register const word16* c __asm__ ("x1") = (const word16*)c_p;
    register const word16* L_mc_bs_powers_neon_c __asm__ ("x2") = L_mc_bs_powers_neon;
    __asm__ __volatile__ (
        "ldr	q0, [%[L_mc_bs_powers_neon_c]]\n\t"
        "movi	v1.8h, #1\n\t"
        "mov	x3, #0\n\t"
        "\n"
    "L_mc_bsp_%=:\n\t"
        "cmp	x3, #8\n\t"
        "b.ge	L_mc_bspe_%=\n\t"
        "lsl	x6, x3, #4\n\t"
        "add	x4, %x[c], x6\n\t"
        "ldr	q2, [x4]\n\t"
        "add	x4, x4, #0x80\n\t"
        "ldr	q3, [x4]\n\t"
        "and	v4.16b, v2.16b, v1.16b\n\t"
        "mul	v4.8h, v4.8h, v0.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #8\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #4\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #2\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "umov	w5, v4.h[0]\n\t"
        "add	x4, %x[in], #0\n\t"
        "add	x4, x4, x3\n\t"
        "strb	w5, [x4]\n\t"
        "ushr	v4.8h, v2.8h, #1\n\t"
        "and	v4.16b, v4.16b, v1.16b\n\t"
        "mul	v4.8h, v4.8h, v0.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #8\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #4\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #2\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "umov	w5, v4.h[0]\n\t"
        "add	x4, %x[in], #16\n\t"
        "add	x4, x4, x3\n\t"
        "strb	w5, [x4]\n\t"
        "ushr	v4.8h, v2.8h, #2\n\t"
        "and	v4.16b, v4.16b, v1.16b\n\t"
        "mul	v4.8h, v4.8h, v0.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #8\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #4\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #2\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "umov	w5, v4.h[0]\n\t"
        "add	x4, %x[in], #32\n\t"
        "add	x4, x4, x3\n\t"
        "strb	w5, [x4]\n\t"
        "ushr	v4.8h, v2.8h, #3\n\t"
        "and	v4.16b, v4.16b, v1.16b\n\t"
        "mul	v4.8h, v4.8h, v0.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #8\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #4\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #2\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "umov	w5, v4.h[0]\n\t"
        "add	x4, %x[in], #48\n\t"
        "add	x4, x4, x3\n\t"
        "strb	w5, [x4]\n\t"
        "ushr	v4.8h, v2.8h, #4\n\t"
        "and	v4.16b, v4.16b, v1.16b\n\t"
        "mul	v4.8h, v4.8h, v0.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #8\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #4\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #2\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "umov	w5, v4.h[0]\n\t"
        "add	x4, %x[in], #0x40\n\t"
        "add	x4, x4, x3\n\t"
        "strb	w5, [x4]\n\t"
        "ushr	v4.8h, v2.8h, #5\n\t"
        "and	v4.16b, v4.16b, v1.16b\n\t"
        "mul	v4.8h, v4.8h, v0.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #8\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #4\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #2\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "umov	w5, v4.h[0]\n\t"
        "add	x4, %x[in], #0x50\n\t"
        "add	x4, x4, x3\n\t"
        "strb	w5, [x4]\n\t"
        "ushr	v4.8h, v2.8h, #6\n\t"
        "and	v4.16b, v4.16b, v1.16b\n\t"
        "mul	v4.8h, v4.8h, v0.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #8\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #4\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #2\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "umov	w5, v4.h[0]\n\t"
        "add	x4, %x[in], #0x60\n\t"
        "add	x4, x4, x3\n\t"
        "strb	w5, [x4]\n\t"
        "ushr	v4.8h, v2.8h, #7\n\t"
        "and	v4.16b, v4.16b, v1.16b\n\t"
        "mul	v4.8h, v4.8h, v0.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #8\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #4\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #2\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "umov	w5, v4.h[0]\n\t"
        "add	x4, %x[in], #0x70\n\t"
        "add	x4, x4, x3\n\t"
        "strb	w5, [x4]\n\t"
        "ushr	v4.8h, v2.8h, #8\n\t"
        "and	v4.16b, v4.16b, v1.16b\n\t"
        "mul	v4.8h, v4.8h, v0.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #8\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #4\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #2\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "umov	w5, v4.h[0]\n\t"
        "add	x4, %x[in], #0x80\n\t"
        "add	x4, x4, x3\n\t"
        "strb	w5, [x4]\n\t"
        "ushr	v4.8h, v2.8h, #9\n\t"
        "and	v4.16b, v4.16b, v1.16b\n\t"
        "mul	v4.8h, v4.8h, v0.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #8\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #4\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #2\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "umov	w5, v4.h[0]\n\t"
        "add	x4, %x[in], #0x90\n\t"
        "add	x4, x4, x3\n\t"
        "strb	w5, [x4]\n\t"
        "ushr	v4.8h, v2.8h, #10\n\t"
        "and	v4.16b, v4.16b, v1.16b\n\t"
        "mul	v4.8h, v4.8h, v0.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #8\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #4\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #2\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "umov	w5, v4.h[0]\n\t"
        "add	x4, %x[in], #0xa0\n\t"
        "add	x4, x4, x3\n\t"
        "strb	w5, [x4]\n\t"
        "ushr	v4.8h, v2.8h, #11\n\t"
        "and	v4.16b, v4.16b, v1.16b\n\t"
        "mul	v4.8h, v4.8h, v0.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #8\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #4\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #2\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "umov	w5, v4.h[0]\n\t"
        "add	x4, %x[in], #0xb0\n\t"
        "add	x4, x4, x3\n\t"
        "strb	w5, [x4]\n\t"
        "ushr	v4.8h, v2.8h, #12\n\t"
        "and	v4.16b, v4.16b, v1.16b\n\t"
        "mul	v4.8h, v4.8h, v0.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #8\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #4\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #2\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "umov	w5, v4.h[0]\n\t"
        "add	x4, %x[in], #0xc0\n\t"
        "add	x4, x4, x3\n\t"
        "strb	w5, [x4]\n\t"
        "and	v4.16b, v3.16b, v1.16b\n\t"
        "mul	v4.8h, v4.8h, v0.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #8\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #4\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #2\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "umov	w5, v4.h[0]\n\t"
        "add	x4, %x[in], #8\n\t"
        "add	x4, x4, x3\n\t"
        "strb	w5, [x4]\n\t"
        "ushr	v4.8h, v3.8h, #1\n\t"
        "and	v4.16b, v4.16b, v1.16b\n\t"
        "mul	v4.8h, v4.8h, v0.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #8\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #4\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #2\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "umov	w5, v4.h[0]\n\t"
        "add	x4, %x[in], #24\n\t"
        "add	x4, x4, x3\n\t"
        "strb	w5, [x4]\n\t"
        "ushr	v4.8h, v3.8h, #2\n\t"
        "and	v4.16b, v4.16b, v1.16b\n\t"
        "mul	v4.8h, v4.8h, v0.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #8\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #4\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #2\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "umov	w5, v4.h[0]\n\t"
        "add	x4, %x[in], #40\n\t"
        "add	x4, x4, x3\n\t"
        "strb	w5, [x4]\n\t"
        "ushr	v4.8h, v3.8h, #3\n\t"
        "and	v4.16b, v4.16b, v1.16b\n\t"
        "mul	v4.8h, v4.8h, v0.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #8\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #4\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #2\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "umov	w5, v4.h[0]\n\t"
        "add	x4, %x[in], #56\n\t"
        "add	x4, x4, x3\n\t"
        "strb	w5, [x4]\n\t"
        "ushr	v4.8h, v3.8h, #4\n\t"
        "and	v4.16b, v4.16b, v1.16b\n\t"
        "mul	v4.8h, v4.8h, v0.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #8\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #4\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #2\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "umov	w5, v4.h[0]\n\t"
        "add	x4, %x[in], #0x48\n\t"
        "add	x4, x4, x3\n\t"
        "strb	w5, [x4]\n\t"
        "ushr	v4.8h, v3.8h, #5\n\t"
        "and	v4.16b, v4.16b, v1.16b\n\t"
        "mul	v4.8h, v4.8h, v0.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #8\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #4\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #2\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "umov	w5, v4.h[0]\n\t"
        "add	x4, %x[in], #0x58\n\t"
        "add	x4, x4, x3\n\t"
        "strb	w5, [x4]\n\t"
        "ushr	v4.8h, v3.8h, #6\n\t"
        "and	v4.16b, v4.16b, v1.16b\n\t"
        "mul	v4.8h, v4.8h, v0.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #8\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #4\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #2\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "umov	w5, v4.h[0]\n\t"
        "add	x4, %x[in], #0x68\n\t"
        "add	x4, x4, x3\n\t"
        "strb	w5, [x4]\n\t"
        "ushr	v4.8h, v3.8h, #7\n\t"
        "and	v4.16b, v4.16b, v1.16b\n\t"
        "mul	v4.8h, v4.8h, v0.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #8\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #4\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #2\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "umov	w5, v4.h[0]\n\t"
        "add	x4, %x[in], #0x78\n\t"
        "add	x4, x4, x3\n\t"
        "strb	w5, [x4]\n\t"
        "ushr	v4.8h, v3.8h, #8\n\t"
        "and	v4.16b, v4.16b, v1.16b\n\t"
        "mul	v4.8h, v4.8h, v0.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #8\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #4\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #2\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "umov	w5, v4.h[0]\n\t"
        "add	x4, %x[in], #0x88\n\t"
        "add	x4, x4, x3\n\t"
        "strb	w5, [x4]\n\t"
        "ushr	v4.8h, v3.8h, #9\n\t"
        "and	v4.16b, v4.16b, v1.16b\n\t"
        "mul	v4.8h, v4.8h, v0.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #8\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #4\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #2\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "umov	w5, v4.h[0]\n\t"
        "add	x4, %x[in], #0x98\n\t"
        "add	x4, x4, x3\n\t"
        "strb	w5, [x4]\n\t"
        "ushr	v4.8h, v3.8h, #10\n\t"
        "and	v4.16b, v4.16b, v1.16b\n\t"
        "mul	v4.8h, v4.8h, v0.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #8\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #4\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #2\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "umov	w5, v4.h[0]\n\t"
        "add	x4, %x[in], #0xa8\n\t"
        "add	x4, x4, x3\n\t"
        "strb	w5, [x4]\n\t"
        "ushr	v4.8h, v3.8h, #11\n\t"
        "and	v4.16b, v4.16b, v1.16b\n\t"
        "mul	v4.8h, v4.8h, v0.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #8\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #4\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #2\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "umov	w5, v4.h[0]\n\t"
        "add	x4, %x[in], #0xb8\n\t"
        "add	x4, x4, x3\n\t"
        "strb	w5, [x4]\n\t"
        "ushr	v4.8h, v3.8h, #12\n\t"
        "and	v4.16b, v4.16b, v1.16b\n\t"
        "mul	v4.8h, v4.8h, v0.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #8\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #4\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "ext	v5.16b, v4.16b, v4.16b, #2\n\t"
        "add	v4.8h, v4.8h, v5.8h\n\t"
        "umov	w5, v4.h[0]\n\t"
        "add	x4, %x[in], #0xc8\n\t"
        "add	x4, x4, x3\n\t"
        "strb	w5, [x4]\n\t"
        "add	x3, x3, #1\n\t"
        "b	L_mc_bsp_%=\n\t"
        "\n"
    "L_mc_bspe_%=:\n\t"
        : [in] "+r" (in)
        : [c] "r" (c), [L_mc_bs_powers_neon_c] "r" (L_mc_bs_powers_neon_c)
        : "memory", "cc", "x3", "x4", "x5", "x6", "v0", "v1", "v2", "v3", "v4",
            "v5"
    );
}

WOLFSSL_LOCAL int wc_mceliece_gf_mul_scalar_neon(int a_p, int b_p);
int wc_mceliece_gf_mul_scalar_neon(int a_p, int b_p)
{
    register int a __asm__ ("w0") = (int)a_p;
    register int b __asm__ ("w1") = (int)b_p;
    __asm__ __volatile__ (
        "mov	w6, %w[a]\n\t"
        "mov	w2, #0\n\t"
        "lsr	w3, %w[b], #0\n\t"
        "and	w3, w3, #1\n\t"
        "neg	w3, w3\n\t"
        "and	w4, w6, w3\n\t"
        "eor	w2, w2, w4\n\t"
        "lsr	w3, %w[b], #1\n\t"
        "and	w3, w3, #1\n\t"
        "neg	w3, w3\n\t"
        "lsl	w4, w6, #1\n\t"
        "and	w4, w4, w3\n\t"
        "eor	w2, w2, w4\n\t"
        "lsr	w3, %w[b], #2\n\t"
        "and	w3, w3, #1\n\t"
        "neg	w3, w3\n\t"
        "lsl	w4, w6, #2\n\t"
        "and	w4, w4, w3\n\t"
        "eor	w2, w2, w4\n\t"
        "lsr	w3, %w[b], #3\n\t"
        "and	w3, w3, #1\n\t"
        "neg	w3, w3\n\t"
        "lsl	w4, w6, #3\n\t"
        "and	w4, w4, w3\n\t"
        "eor	w2, w2, w4\n\t"
        "lsr	w3, %w[b], #4\n\t"
        "and	w3, w3, #1\n\t"
        "neg	w3, w3\n\t"
        "lsl	w4, w6, #4\n\t"
        "and	w4, w4, w3\n\t"
        "eor	w2, w2, w4\n\t"
        "lsr	w3, %w[b], #5\n\t"
        "and	w3, w3, #1\n\t"
        "neg	w3, w3\n\t"
        "lsl	w4, w6, #5\n\t"
        "and	w4, w4, w3\n\t"
        "eor	w2, w2, w4\n\t"
        "lsr	w3, %w[b], #6\n\t"
        "and	w3, w3, #1\n\t"
        "neg	w3, w3\n\t"
        "lsl	w4, w6, #6\n\t"
        "and	w4, w4, w3\n\t"
        "eor	w2, w2, w4\n\t"
        "lsr	w3, %w[b], #7\n\t"
        "and	w3, w3, #1\n\t"
        "neg	w3, w3\n\t"
        "lsl	w4, w6, #7\n\t"
        "and	w4, w4, w3\n\t"
        "eor	w2, w2, w4\n\t"
        "lsr	w3, %w[b], #8\n\t"
        "and	w3, w3, #1\n\t"
        "neg	w3, w3\n\t"
        "lsl	w4, w6, #8\n\t"
        "and	w4, w4, w3\n\t"
        "eor	w2, w2, w4\n\t"
        "lsr	w3, %w[b], #9\n\t"
        "and	w3, w3, #1\n\t"
        "neg	w3, w3\n\t"
        "lsl	w4, w6, #9\n\t"
        "and	w4, w4, w3\n\t"
        "eor	w2, w2, w4\n\t"
        "lsr	w3, %w[b], #10\n\t"
        "and	w3, w3, #1\n\t"
        "neg	w3, w3\n\t"
        "lsl	w4, w6, #10\n\t"
        "and	w4, w4, w3\n\t"
        "eor	w2, w2, w4\n\t"
        "lsr	w3, %w[b], #11\n\t"
        "and	w3, w3, #1\n\t"
        "neg	w3, w3\n\t"
        "lsl	w4, w6, #11\n\t"
        "and	w4, w4, w3\n\t"
        "eor	w2, w2, w4\n\t"
        "lsr	w3, %w[b], #12\n\t"
        "and	w3, w3, #1\n\t"
        "neg	w3, w3\n\t"
        "lsl	w4, w6, #12\n\t"
        "and	w4, w4, w3\n\t"
        "eor	w2, w2, w4\n\t"
        "mov	w7, #0x1ff\n\t"
        "lsl	w7, w7, #16\n\t"
        "and	w4, w2, w7\n\t"
        "lsr	w5, w4, #9\n\t"
        "eor	w2, w2, w5\n\t"
        "lsr	w5, w4, #10\n\t"
        "eor	w2, w2, w5\n\t"
        "lsr	w5, w4, #12\n\t"
        "eor	w2, w2, w5\n\t"
        "lsr	w5, w4, #13\n\t"
        "eor	w2, w2, w5\n\t"
        "mov	w7, #0xe000\n\t"
        "and	w4, w2, w7\n\t"
        "lsr	w5, w4, #9\n\t"
        "eor	w2, w2, w5\n\t"
        "lsr	w5, w4, #10\n\t"
        "eor	w2, w2, w5\n\t"
        "lsr	w5, w4, #12\n\t"
        "eor	w2, w2, w5\n\t"
        "lsr	w5, w4, #13\n\t"
        "eor	w2, w2, w5\n\t"
        "mov	w7, #0x1fff\n\t"
        "and	%w[a], w2, w7\n\t"
        : [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "cc", "x2", "x3", "x4", "x5", "x6", "x7"
    );
    return (word32)(size_t)a;
}

WOLFSSL_LOCAL int wc_mceliece_gf_inv_scalar_neon(int a_p, int b_p);
int wc_mceliece_gf_inv_scalar_neon(int a_p, int b_p)
{
    register int a __asm__ ("w0") = (int)a_p;
    register int b __asm__ ("w1") = (int)b_p;
    __asm__ __volatile__ (
        "mov	w19, %w[a]\n\t"
        "mov	%w[b], %w[a]\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_gf_mul_scalar_neon\n\t"
#else
        "bl	_wc_mceliece_gf_mul_scalar_neon\n\t"
#endif /* __APPLE__ */
        "mov	%w[b], w19\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_gf_mul_scalar_neon\n\t"
#else
        "bl	_wc_mceliece_gf_mul_scalar_neon\n\t"
#endif /* __APPLE__ */
        "mov	w20, %w[a]\n\t"
        "mov	%w[b], %w[a]\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_gf_mul_scalar_neon\n\t"
#else
        "bl	_wc_mceliece_gf_mul_scalar_neon\n\t"
#endif /* __APPLE__ */
        "mov	%w[b], %w[a]\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_gf_mul_scalar_neon\n\t"
#else
        "bl	_wc_mceliece_gf_mul_scalar_neon\n\t"
#endif /* __APPLE__ */
        "mov	%w[b], w20\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_gf_mul_scalar_neon\n\t"
#else
        "bl	_wc_mceliece_gf_mul_scalar_neon\n\t"
#endif /* __APPLE__ */
        "mov	w21, %w[a]\n\t"
        "mov	%w[b], %w[a]\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_gf_mul_scalar_neon\n\t"
#else
        "bl	_wc_mceliece_gf_mul_scalar_neon\n\t"
#endif /* __APPLE__ */
        "mov	%w[b], %w[a]\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_gf_mul_scalar_neon\n\t"
#else
        "bl	_wc_mceliece_gf_mul_scalar_neon\n\t"
#endif /* __APPLE__ */
        "mov	%w[b], %w[a]\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_gf_mul_scalar_neon\n\t"
#else
        "bl	_wc_mceliece_gf_mul_scalar_neon\n\t"
#endif /* __APPLE__ */
        "mov	%w[b], %w[a]\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_gf_mul_scalar_neon\n\t"
#else
        "bl	_wc_mceliece_gf_mul_scalar_neon\n\t"
#endif /* __APPLE__ */
        "mov	%w[b], w21\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_gf_mul_scalar_neon\n\t"
#else
        "bl	_wc_mceliece_gf_mul_scalar_neon\n\t"
#endif /* __APPLE__ */
        "mov	%w[b], %w[a]\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_gf_mul_scalar_neon\n\t"
#else
        "bl	_wc_mceliece_gf_mul_scalar_neon\n\t"
#endif /* __APPLE__ */
        "mov	%w[b], %w[a]\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_gf_mul_scalar_neon\n\t"
#else
        "bl	_wc_mceliece_gf_mul_scalar_neon\n\t"
#endif /* __APPLE__ */
        "mov	%w[b], %w[a]\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_gf_mul_scalar_neon\n\t"
#else
        "bl	_wc_mceliece_gf_mul_scalar_neon\n\t"
#endif /* __APPLE__ */
        "mov	%w[b], %w[a]\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_gf_mul_scalar_neon\n\t"
#else
        "bl	_wc_mceliece_gf_mul_scalar_neon\n\t"
#endif /* __APPLE__ */
        "mov	%w[b], w21\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_gf_mul_scalar_neon\n\t"
#else
        "bl	_wc_mceliece_gf_mul_scalar_neon\n\t"
#endif /* __APPLE__ */
        "mov	%w[b], %w[a]\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_gf_mul_scalar_neon\n\t"
#else
        "bl	_wc_mceliece_gf_mul_scalar_neon\n\t"
#endif /* __APPLE__ */
        : [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "cc", "x19", "x20", "x21", "x30"
    );
    return (word32)(size_t)a;
}

WOLFSSL_LOCAL void wc_mceliece_gf_mulc_mac_neon(word16* dst_p, int scalar_p,
    const word16* src_p, int count_p);
void wc_mceliece_gf_mulc_mac_neon(word16* dst_p, int scalar_p,
    const word16* src_p, int count_p)
{
    register word16* dst __asm__ ("x0") = (word16*)dst_p;
    register int scalar __asm__ ("w1") = (int)scalar_p;
    register const word16* src __asm__ ("x2") = (const word16*)src_p;
    register int count __asm__ ("w3") = (int)count_p;
    __asm__ __volatile__ (
        "eor	v0.16b, v0.16b, v0.16b\n\t"
        "mov	x6, #0x1ff\n\t"
        "dup	v1.4s, w6\n\t"
        "shl	v1.4s, v1.4s, #16\n\t"
        "mov	x6, #0xe000\n\t"
        "dup	v2.4s, w6\n\t"
        "mov	x6, #0x1fff\n\t"
        "dup	v3.4s, w6\n\t"
        "mov	w7, %w[scalar]\n\t"
        "lsr	x6, x7, #0\n\t"
        "and	x6, x6, #1\n\t"
        "neg	x6, x6\n\t"
        "dup	v4.4s, w6\n\t"
        "lsr	x6, x7, #1\n\t"
        "and	x6, x6, #1\n\t"
        "neg	x6, x6\n\t"
        "dup	v5.4s, w6\n\t"
        "lsr	x6, x7, #2\n\t"
        "and	x6, x6, #1\n\t"
        "neg	x6, x6\n\t"
        "dup	v6.4s, w6\n\t"
        "lsr	x6, x7, #3\n\t"
        "and	x6, x6, #1\n\t"
        "neg	x6, x6\n\t"
        "dup	v7.4s, w6\n\t"
        "lsr	x6, x7, #4\n\t"
        "and	x6, x6, #1\n\t"
        "neg	x6, x6\n\t"
        "dup	v8.4s, w6\n\t"
        "lsr	x6, x7, #5\n\t"
        "and	x6, x6, #1\n\t"
        "neg	x6, x6\n\t"
        "dup	v9.4s, w6\n\t"
        "lsr	x6, x7, #6\n\t"
        "and	x6, x6, #1\n\t"
        "neg	x6, x6\n\t"
        "dup	v10.4s, w6\n\t"
        "lsr	x6, x7, #7\n\t"
        "and	x6, x6, #1\n\t"
        "neg	x6, x6\n\t"
        "dup	v11.4s, w6\n\t"
        "lsr	x6, x7, #8\n\t"
        "and	x6, x6, #1\n\t"
        "neg	x6, x6\n\t"
        "dup	v12.4s, w6\n\t"
        "lsr	x6, x7, #9\n\t"
        "and	x6, x6, #1\n\t"
        "neg	x6, x6\n\t"
        "dup	v13.4s, w6\n\t"
        "lsr	x6, x7, #10\n\t"
        "and	x6, x6, #1\n\t"
        "neg	x6, x6\n\t"
        "dup	v14.4s, w6\n\t"
        "lsr	x6, x7, #11\n\t"
        "and	x6, x6, #1\n\t"
        "neg	x6, x6\n\t"
        "dup	v15.4s, w6\n\t"
        "lsr	x6, x7, #12\n\t"
        "and	x6, x6, #1\n\t"
        "neg	x6, x6\n\t"
        "dup	v16.4s, w6\n\t"
        "mov	x4, #0\n\t"
        "\n"
    "L_mc_gmm_%=:\n\t"
        "cmp	w4, %w[count]\n\t"
        "b.ge	L_mc_gmme_%=\n\t"
        "lsl	x5, x4, #1\n\t"
        "add	x6, %x[src], x5\n\t"
        "ldr	q17, [x6]\n\t"
        "zip1	v18.8h, v17.8h, v0.8h\n\t"
        "and	v19.16b, v18.16b, v4.16b\n\t"
        "shl	v21.4s, v18.4s, #1\n\t"
        "and	v21.16b, v21.16b, v5.16b\n\t"
        "eor	v19.16b, v19.16b, v21.16b\n\t"
        "shl	v21.4s, v18.4s, #2\n\t"
        "and	v21.16b, v21.16b, v6.16b\n\t"
        "eor	v19.16b, v19.16b, v21.16b\n\t"
        "shl	v21.4s, v18.4s, #3\n\t"
        "and	v21.16b, v21.16b, v7.16b\n\t"
        "eor	v19.16b, v19.16b, v21.16b\n\t"
        "shl	v21.4s, v18.4s, #4\n\t"
        "and	v21.16b, v21.16b, v8.16b\n\t"
        "eor	v19.16b, v19.16b, v21.16b\n\t"
        "shl	v21.4s, v18.4s, #5\n\t"
        "and	v21.16b, v21.16b, v9.16b\n\t"
        "eor	v19.16b, v19.16b, v21.16b\n\t"
        "shl	v21.4s, v18.4s, #6\n\t"
        "and	v21.16b, v21.16b, v10.16b\n\t"
        "eor	v19.16b, v19.16b, v21.16b\n\t"
        "shl	v21.4s, v18.4s, #7\n\t"
        "and	v21.16b, v21.16b, v11.16b\n\t"
        "eor	v19.16b, v19.16b, v21.16b\n\t"
        "shl	v21.4s, v18.4s, #8\n\t"
        "and	v21.16b, v21.16b, v12.16b\n\t"
        "eor	v19.16b, v19.16b, v21.16b\n\t"
        "shl	v21.4s, v18.4s, #9\n\t"
        "and	v21.16b, v21.16b, v13.16b\n\t"
        "eor	v19.16b, v19.16b, v21.16b\n\t"
        "shl	v21.4s, v18.4s, #10\n\t"
        "and	v21.16b, v21.16b, v14.16b\n\t"
        "eor	v19.16b, v19.16b, v21.16b\n\t"
        "shl	v21.4s, v18.4s, #11\n\t"
        "and	v21.16b, v21.16b, v15.16b\n\t"
        "eor	v19.16b, v19.16b, v21.16b\n\t"
        "shl	v21.4s, v18.4s, #12\n\t"
        "and	v21.16b, v21.16b, v16.16b\n\t"
        "eor	v19.16b, v19.16b, v21.16b\n\t"
        "and	v21.16b, v19.16b, v1.16b\n\t"
        "ushr	v22.4s, v21.4s, #9\n\t"
        "eor	v19.16b, v19.16b, v22.16b\n\t"
        "ushr	v22.4s, v21.4s, #10\n\t"
        "eor	v19.16b, v19.16b, v22.16b\n\t"
        "ushr	v22.4s, v21.4s, #12\n\t"
        "eor	v19.16b, v19.16b, v22.16b\n\t"
        "ushr	v22.4s, v21.4s, #13\n\t"
        "eor	v19.16b, v19.16b, v22.16b\n\t"
        "and	v21.16b, v19.16b, v2.16b\n\t"
        "ushr	v22.4s, v21.4s, #9\n\t"
        "eor	v19.16b, v19.16b, v22.16b\n\t"
        "ushr	v22.4s, v21.4s, #10\n\t"
        "eor	v19.16b, v19.16b, v22.16b\n\t"
        "ushr	v22.4s, v21.4s, #12\n\t"
        "eor	v19.16b, v19.16b, v22.16b\n\t"
        "ushr	v22.4s, v21.4s, #13\n\t"
        "eor	v19.16b, v19.16b, v22.16b\n\t"
        "and	v19.16b, v19.16b, v3.16b\n\t"
        "zip2	v18.8h, v17.8h, v0.8h\n\t"
        "and	v20.16b, v18.16b, v4.16b\n\t"
        "shl	v21.4s, v18.4s, #1\n\t"
        "and	v21.16b, v21.16b, v5.16b\n\t"
        "eor	v20.16b, v20.16b, v21.16b\n\t"
        "shl	v21.4s, v18.4s, #2\n\t"
        "and	v21.16b, v21.16b, v6.16b\n\t"
        "eor	v20.16b, v20.16b, v21.16b\n\t"
        "shl	v21.4s, v18.4s, #3\n\t"
        "and	v21.16b, v21.16b, v7.16b\n\t"
        "eor	v20.16b, v20.16b, v21.16b\n\t"
        "shl	v21.4s, v18.4s, #4\n\t"
        "and	v21.16b, v21.16b, v8.16b\n\t"
        "eor	v20.16b, v20.16b, v21.16b\n\t"
        "shl	v21.4s, v18.4s, #5\n\t"
        "and	v21.16b, v21.16b, v9.16b\n\t"
        "eor	v20.16b, v20.16b, v21.16b\n\t"
        "shl	v21.4s, v18.4s, #6\n\t"
        "and	v21.16b, v21.16b, v10.16b\n\t"
        "eor	v20.16b, v20.16b, v21.16b\n\t"
        "shl	v21.4s, v18.4s, #7\n\t"
        "and	v21.16b, v21.16b, v11.16b\n\t"
        "eor	v20.16b, v20.16b, v21.16b\n\t"
        "shl	v21.4s, v18.4s, #8\n\t"
        "and	v21.16b, v21.16b, v12.16b\n\t"
        "eor	v20.16b, v20.16b, v21.16b\n\t"
        "shl	v21.4s, v18.4s, #9\n\t"
        "and	v21.16b, v21.16b, v13.16b\n\t"
        "eor	v20.16b, v20.16b, v21.16b\n\t"
        "shl	v21.4s, v18.4s, #10\n\t"
        "and	v21.16b, v21.16b, v14.16b\n\t"
        "eor	v20.16b, v20.16b, v21.16b\n\t"
        "shl	v21.4s, v18.4s, #11\n\t"
        "and	v21.16b, v21.16b, v15.16b\n\t"
        "eor	v20.16b, v20.16b, v21.16b\n\t"
        "shl	v21.4s, v18.4s, #12\n\t"
        "and	v21.16b, v21.16b, v16.16b\n\t"
        "eor	v20.16b, v20.16b, v21.16b\n\t"
        "and	v21.16b, v20.16b, v1.16b\n\t"
        "ushr	v22.4s, v21.4s, #9\n\t"
        "eor	v20.16b, v20.16b, v22.16b\n\t"
        "ushr	v22.4s, v21.4s, #10\n\t"
        "eor	v20.16b, v20.16b, v22.16b\n\t"
        "ushr	v22.4s, v21.4s, #12\n\t"
        "eor	v20.16b, v20.16b, v22.16b\n\t"
        "ushr	v22.4s, v21.4s, #13\n\t"
        "eor	v20.16b, v20.16b, v22.16b\n\t"
        "and	v21.16b, v20.16b, v2.16b\n\t"
        "ushr	v22.4s, v21.4s, #9\n\t"
        "eor	v20.16b, v20.16b, v22.16b\n\t"
        "ushr	v22.4s, v21.4s, #10\n\t"
        "eor	v20.16b, v20.16b, v22.16b\n\t"
        "ushr	v22.4s, v21.4s, #12\n\t"
        "eor	v20.16b, v20.16b, v22.16b\n\t"
        "ushr	v22.4s, v21.4s, #13\n\t"
        "eor	v20.16b, v20.16b, v22.16b\n\t"
        "and	v20.16b, v20.16b, v3.16b\n\t"
        "uzp1	v19.8h, v19.8h, v20.8h\n\t"
        "add	x6, %x[dst], x5\n\t"
        "ldr	q20, [x6]\n\t"
        "eor	v19.16b, v19.16b, v20.16b\n\t"
        "str	q19, [x6]\n\t"
        "add	x4, x4, #8\n\t"
        "b	L_mc_gmm_%=\n\t"
        "\n"
    "L_mc_gmme_%=:\n\t"
        : [dst] "+r" (dst), [scalar] "+r" (scalar), [count] "+r" (count)
        : [src] "r" (src)
        : "memory", "cc", "x4", "x5", "x6", "x7", "v0", "v1", "v2", "v3", "v4",
            "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14",
            "v15", "v16", "v17", "v18", "v19", "v20", "v21", "v22"
    );
}

WOLFSSL_LOCAL void wc_mceliece_gf_mulc_mac_full_neon(word16* dst_p,
    int scalar_p, const word16* src_p, int count_p);
void wc_mceliece_gf_mulc_mac_full_neon(word16* dst_p, int scalar_p,
    const word16* src_p, int count_p)
{
    register word16* dst __asm__ ("x0") = (word16*)dst_p;
    register int scalar __asm__ ("w1") = (int)scalar_p;
    register const word16* src __asm__ ("x2") = (const word16*)src_p;
    register int count __asm__ ("w3") = (int)count_p;
    __asm__ __volatile__ (
        "mov	x19, %x[dst]\n\t"
        "mov	w20, %w[scalar]\n\t"
        "mov	x21, %x[src]\n\t"
        "mov	w22, %w[count]\n\t"
        "lsr	x4, x22, #3\n\t"
        "lsl	x4, x4, #3\n\t"
        "cbz	x4, L_mc_mmf_s_%=\n\t"
        "mov	%x[dst], x19\n\t"
        "mov	%w[scalar], w20\n\t"
        "mov	%x[src], x21\n\t"
        "mov	%w[count], w4\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_gf_mulc_mac_neon\n\t"
#else
        "bl	_wc_mceliece_gf_mulc_mac_neon\n\t"
#endif /* __APPLE__ */
        "\n"
    "L_mc_mmf_s_%=:\n\t"
        "lsr	x4, x22, #3\n\t"
        "lsl	x4, x4, #3\n\t"
        "mov	x23, x4\n\t"
        "\n"
    "L_mc_mmf_t_%=:\n\t"
        "cmp	x23, x22\n\t"
        "b.ge	L_mc_mmf_te_%=\n\t"
        "mov	%w[dst], w20\n\t"
        "lsl	x5, x23, #1\n\t"
        "add	x6, x21, x5\n\t"
        "ldrh	%w[scalar], [x6]\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_gf_mul_scalar_neon\n\t"
#else
        "bl	_wc_mceliece_gf_mul_scalar_neon\n\t"
#endif /* __APPLE__ */
        "lsl	x5, x23, #1\n\t"
        "add	x6, x19, x5\n\t"
        "ldrh	w7, [x6]\n\t"
        "eor	w7, w7, %w[dst]\n\t"
        "strh	w7, [x6]\n\t"
        "add	x23, x23, #1\n\t"
        "b	L_mc_mmf_t_%=\n\t"
        "\n"
    "L_mc_mmf_te_%=:\n\t"
        : [dst] "+r" (dst), [scalar] "+r" (scalar), [count] "+r" (count)
        : [src] "r" (src)
        : "memory", "cc", "x19", "x20", "x21", "x22", "x23", "x4", "x5", "x6",
            "x7", "x30"
    );
}

WOLFSSL_LOCAL void wc_mceliece_mont_batch_inv_neon(word64* einvbs_p,
    word64* ffts_p, word64* scratch_p, word64* c_p, int do_sq_p);
void wc_mceliece_mont_batch_inv_neon(word64* einvbs_p, word64* ffts_p,
    word64* scratch_p, word64* c_p, int do_sq_p)
{
    register word64* einvbs __asm__ ("x0") = (word64*)einvbs_p;
    register word64* ffts __asm__ ("x1") = (word64*)ffts_p;
    register word64* scratch __asm__ ("x2") = (word64*)scratch_p;
    register word64* c __asm__ ("x3") = (word64*)c_p;
    register int do_sq __asm__ ("w4") = (int)do_sq_p;
    __asm__ __volatile__ (
        "mov	x19, %x[einvbs]\n\t"
        "mov	x20, %x[ffts]\n\t"
        "mov	x21, %x[scratch]\n\t"
        "mov	x23, #0x1a0\n\t"
        "cbz	%w[do_sq], L_mc_mbi_sqe_%=\n\t"
        "mov	x22, #0\n\t"
        "\n"
    "L_mc_mbi_sq_%=:\n\t"
        "cmp	x22, #32\n\t"
        "b.ge	L_mc_mbi_sqe_%=\n\t"
        "mul	x5, x22, x23\n\t"
        "add	%x[einvbs], x20, x5\n\t"
        "mov	%x[ffts], %x[einvbs]\n\t"
        "mov	%x[scratch], %x[einvbs]\n\t"
        "add	%x[c], x21, #0x340\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_v256_mul_neon\n\t"
#else
        "bl	_wc_mceliece_aff_v256_mul_neon\n\t"
#endif /* __APPLE__ */
        "add	x22, x22, #1\n\t"
        "b	L_mc_mbi_sq_%=\n\t"
        "\n"
    "L_mc_mbi_sqe_%=:\n\t"
        "add	x6, x20, #0\n\t"
        "ldp	q0, q1, [x6]\n\t"
        "add	x6, x19, #0\n\t"
        "stp	q0, q1, [x6]\n\t"
        "add	x6, x20, #32\n\t"
        "ldp	q0, q1, [x6]\n\t"
        "add	x6, x19, #32\n\t"
        "stp	q0, q1, [x6]\n\t"
        "add	x6, x20, #0x40\n\t"
        "ldp	q0, q1, [x6]\n\t"
        "add	x6, x19, #0x40\n\t"
        "stp	q0, q1, [x6]\n\t"
        "add	x6, x20, #0x60\n\t"
        "ldp	q0, q1, [x6]\n\t"
        "add	x6, x19, #0x60\n\t"
        "stp	q0, q1, [x6]\n\t"
        "add	x6, x20, #0x80\n\t"
        "ldp	q0, q1, [x6]\n\t"
        "add	x6, x19, #0x80\n\t"
        "stp	q0, q1, [x6]\n\t"
        "add	x6, x20, #0xa0\n\t"
        "ldp	q0, q1, [x6]\n\t"
        "add	x6, x19, #0xa0\n\t"
        "stp	q0, q1, [x6]\n\t"
        "add	x6, x20, #0xc0\n\t"
        "ldp	q0, q1, [x6]\n\t"
        "add	x6, x19, #0xc0\n\t"
        "stp	q0, q1, [x6]\n\t"
        "add	x6, x20, #0xe0\n\t"
        "ldp	q0, q1, [x6]\n\t"
        "add	x6, x19, #0xe0\n\t"
        "stp	q0, q1, [x6]\n\t"
        "add	x6, x20, #0x100\n\t"
        "ldp	q0, q1, [x6]\n\t"
        "add	x6, x19, #0x100\n\t"
        "stp	q0, q1, [x6]\n\t"
        "add	x6, x20, #0x120\n\t"
        "ldp	q0, q1, [x6]\n\t"
        "add	x6, x19, #0x120\n\t"
        "stp	q0, q1, [x6]\n\t"
        "add	x6, x20, #0x140\n\t"
        "ldp	q0, q1, [x6]\n\t"
        "add	x6, x19, #0x140\n\t"
        "stp	q0, q1, [x6]\n\t"
        "add	x6, x20, #0x160\n\t"
        "ldp	q0, q1, [x6]\n\t"
        "add	x6, x19, #0x160\n\t"
        "stp	q0, q1, [x6]\n\t"
        "add	x6, x20, #0x180\n\t"
        "ldp	q0, q1, [x6]\n\t"
        "add	x6, x19, #0x180\n\t"
        "stp	q0, q1, [x6]\n\t"
        "mov	x22, #1\n\t"
        "\n"
    "L_mc_mbi_pf_%=:\n\t"
        "cmp	x22, #32\n\t"
        "b.ge	L_mc_mbi_pfe_%=\n\t"
        "mul	x5, x22, x23\n\t"
        "add	%x[einvbs], x19, x5\n\t"
        "sub	%x[ffts], %x[einvbs], #0x1a0\n\t"
        "add	%x[scratch], x20, x5\n\t"
        "add	%x[c], x21, #0x340\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_v256_mul_neon\n\t"
#else
        "bl	_wc_mceliece_aff_v256_mul_neon\n\t"
#endif /* __APPLE__ */
        "add	x22, x22, #1\n\t"
        "b	L_mc_mbi_pf_%=\n\t"
        "\n"
    "L_mc_mbi_pfe_%=:\n\t"
        "mov	x5, #0x3260\n\t"
        "mov	%x[einvbs], x21\n\t"
        "add	%x[ffts], x19, x5\n\t"
        "add	%x[scratch], x21, #0x660\n\t"
        "add	%x[c], x21, #0x340\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_inv256_neon\n\t"
#else
        "bl	_wc_mceliece_aff_inv256_neon\n\t"
#endif /* __APPLE__ */
        "mov	x22, #31\n\t"
        "\n"
    "L_mc_mbi_sf_%=:\n\t"
        "cmp	x22, #1\n\t"
        "b.lt	L_mc_mbi_sfe_%=\n\t"
        "mul	x5, x22, x23\n\t"
        "add	%x[einvbs], x21, #0x1a0\n\t"
        "mov	%x[ffts], x21\n\t"
        "add	%x[scratch], x19, x5\n\t"
        "sub	%x[scratch], %x[scratch], #0x1a0\n\t"
        "add	%x[c], x21, #0x340\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_v256_mul_neon\n\t"
#else
        "bl	_wc_mceliece_aff_v256_mul_neon\n\t"
#endif /* __APPLE__ */
        "mov	%x[einvbs], x21\n\t"
        "mov	%x[ffts], x21\n\t"
        "mul	x5, x22, x23\n\t"
        "add	%x[scratch], x20, x5\n\t"
        "add	%x[c], x21, #0x340\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_v256_mul_neon\n\t"
#else
        "bl	_wc_mceliece_aff_v256_mul_neon\n\t"
#endif /* __APPLE__ */
        "mul	x5, x22, x23\n\t"
        "add	%x[einvbs], x19, x5\n\t"
        "add	%x[ffts], x21, #0x1a0\n\t"
        "add	x6, %x[ffts], #0\n\t"
        "ldp	q0, q1, [x6]\n\t"
        "add	x6, %x[einvbs], #0\n\t"
        "stp	q0, q1, [x6]\n\t"
        "add	x6, %x[ffts], #32\n\t"
        "ldp	q0, q1, [x6]\n\t"
        "add	x6, %x[einvbs], #32\n\t"
        "stp	q0, q1, [x6]\n\t"
        "add	x6, %x[ffts], #0x40\n\t"
        "ldp	q0, q1, [x6]\n\t"
        "add	x6, %x[einvbs], #0x40\n\t"
        "stp	q0, q1, [x6]\n\t"
        "add	x6, %x[ffts], #0x60\n\t"
        "ldp	q0, q1, [x6]\n\t"
        "add	x6, %x[einvbs], #0x60\n\t"
        "stp	q0, q1, [x6]\n\t"
        "add	x6, %x[ffts], #0x80\n\t"
        "ldp	q0, q1, [x6]\n\t"
        "add	x6, %x[einvbs], #0x80\n\t"
        "stp	q0, q1, [x6]\n\t"
        "add	x6, %x[ffts], #0xa0\n\t"
        "ldp	q0, q1, [x6]\n\t"
        "add	x6, %x[einvbs], #0xa0\n\t"
        "stp	q0, q1, [x6]\n\t"
        "add	x6, %x[ffts], #0xc0\n\t"
        "ldp	q0, q1, [x6]\n\t"
        "add	x6, %x[einvbs], #0xc0\n\t"
        "stp	q0, q1, [x6]\n\t"
        "add	x6, %x[ffts], #0xe0\n\t"
        "ldp	q0, q1, [x6]\n\t"
        "add	x6, %x[einvbs], #0xe0\n\t"
        "stp	q0, q1, [x6]\n\t"
        "add	x6, %x[ffts], #0x100\n\t"
        "ldp	q0, q1, [x6]\n\t"
        "add	x6, %x[einvbs], #0x100\n\t"
        "stp	q0, q1, [x6]\n\t"
        "add	x6, %x[ffts], #0x120\n\t"
        "ldp	q0, q1, [x6]\n\t"
        "add	x6, %x[einvbs], #0x120\n\t"
        "stp	q0, q1, [x6]\n\t"
        "add	x6, %x[ffts], #0x140\n\t"
        "ldp	q0, q1, [x6]\n\t"
        "add	x6, %x[einvbs], #0x140\n\t"
        "stp	q0, q1, [x6]\n\t"
        "add	x6, %x[ffts], #0x160\n\t"
        "ldp	q0, q1, [x6]\n\t"
        "add	x6, %x[einvbs], #0x160\n\t"
        "stp	q0, q1, [x6]\n\t"
        "add	x6, %x[ffts], #0x180\n\t"
        "ldp	q0, q1, [x6]\n\t"
        "add	x6, %x[einvbs], #0x180\n\t"
        "stp	q0, q1, [x6]\n\t"
        "sub	x22, x22, #1\n\t"
        "b	L_mc_mbi_sf_%=\n\t"
        "\n"
    "L_mc_mbi_sfe_%=:\n\t"
        "mov	%x[einvbs], x19\n\t"
        "mov	%x[ffts], x21\n\t"
        "add	x6, %x[ffts], #0\n\t"
        "ldp	q0, q1, [x6]\n\t"
        "add	x6, %x[einvbs], #0\n\t"
        "stp	q0, q1, [x6]\n\t"
        "add	x6, %x[ffts], #32\n\t"
        "ldp	q0, q1, [x6]\n\t"
        "add	x6, %x[einvbs], #32\n\t"
        "stp	q0, q1, [x6]\n\t"
        "add	x6, %x[ffts], #0x40\n\t"
        "ldp	q0, q1, [x6]\n\t"
        "add	x6, %x[einvbs], #0x40\n\t"
        "stp	q0, q1, [x6]\n\t"
        "add	x6, %x[ffts], #0x60\n\t"
        "ldp	q0, q1, [x6]\n\t"
        "add	x6, %x[einvbs], #0x60\n\t"
        "stp	q0, q1, [x6]\n\t"
        "add	x6, %x[ffts], #0x80\n\t"
        "ldp	q0, q1, [x6]\n\t"
        "add	x6, %x[einvbs], #0x80\n\t"
        "stp	q0, q1, [x6]\n\t"
        "add	x6, %x[ffts], #0xa0\n\t"
        "ldp	q0, q1, [x6]\n\t"
        "add	x6, %x[einvbs], #0xa0\n\t"
        "stp	q0, q1, [x6]\n\t"
        "add	x6, %x[ffts], #0xc0\n\t"
        "ldp	q0, q1, [x6]\n\t"
        "add	x6, %x[einvbs], #0xc0\n\t"
        "stp	q0, q1, [x6]\n\t"
        "add	x6, %x[ffts], #0xe0\n\t"
        "ldp	q0, q1, [x6]\n\t"
        "add	x6, %x[einvbs], #0xe0\n\t"
        "stp	q0, q1, [x6]\n\t"
        "add	x6, %x[ffts], #0x100\n\t"
        "ldp	q0, q1, [x6]\n\t"
        "add	x6, %x[einvbs], #0x100\n\t"
        "stp	q0, q1, [x6]\n\t"
        "add	x6, %x[ffts], #0x120\n\t"
        "ldp	q0, q1, [x6]\n\t"
        "add	x6, %x[einvbs], #0x120\n\t"
        "stp	q0, q1, [x6]\n\t"
        "add	x6, %x[ffts], #0x140\n\t"
        "ldp	q0, q1, [x6]\n\t"
        "add	x6, %x[einvbs], #0x140\n\t"
        "stp	q0, q1, [x6]\n\t"
        "add	x6, %x[ffts], #0x160\n\t"
        "ldp	q0, q1, [x6]\n\t"
        "add	x6, %x[einvbs], #0x160\n\t"
        "stp	q0, q1, [x6]\n\t"
        "add	x6, %x[ffts], #0x180\n\t"
        "ldp	q0, q1, [x6]\n\t"
        "add	x6, %x[einvbs], #0x180\n\t"
        "stp	q0, q1, [x6]\n\t"
        : [einvbs] "+r" (einvbs), [ffts] "+r" (ffts), [scratch] "+r" (scratch),
          [c] "+r" (c), [do_sq] "+r" (do_sq)
        :
        : "memory", "cc", "x19", "x20", "x21", "x22", "x23", "x5", "x6", "v0",
            "v1", "x30"
    );
}

#ifndef WOLFSSL_MCELIECE_NO_DECAPSULATE
WOLFSSL_LOCAL void wc_mceliece_aff_ama_neon(word64* a_p, word64* b_p,
    const word64* c_p, word64* p_p, word64* cscr_p);
void wc_mceliece_aff_ama_neon(word64* a_p, word64* b_p, const word64* c_p,
    word64* p_p, word64* cscr_p)
{
    register word64* a __asm__ ("x0") = (word64*)a_p;
    register word64* b __asm__ ("x1") = (word64*)b_p;
    register const word64* c __asm__ ("x2") = (const word64*)c_p;
    register word64* p __asm__ ("x3") = (word64*)p_p;
    register word64* cscr __asm__ ("x4") = (word64*)cscr_p;
    __asm__ __volatile__ (
        "mov	x5, #0\n\t"
        "\n"
    "L_mc_xor13_k_amaa_%=:\n\t"
        "lsl	x6, x5, #5\n\t"
        "add	x8, %x[a], x6\n\t"
        "ldp	q0, q1, [x8]\n\t"
        "add	x9, %x[b], x6\n\t"
        "ldp	q2, q3, [x9]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x7, %x[a], x6\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x5, x5, #1\n\t"
        "cmp	x5, #13\n\t"
        "b.lt	L_mc_xor13_k_amaa_%=\n\t"
        "eor	v10.16b, v10.16b, v10.16b\n\t"
        "mov	x12, %x[cscr]\n\t"
        "mov	x7, #0\n\t"
        "\n"
    "L_mc_v256_z_amam_%=:\n\t"
        "stp	q10, q10, [x12]\n\t"
        "add	x12, x12, #32\n\t"
        "add	x7, x7, #1\n\t"
        "cmp	x7, #25\n\t"
        "b.lt	L_mc_v256_z_amam_%=\n\t"
        "mov	x5, #0\n\t"
        "\n"
    "L_mc_v256_i_amam_%=:\n\t"
        "cmp	x5, #13\n\t"
        "b.ge	L_mc_v256_rs_amam_%=\n\t"
        "lsl	x13, x5, #5\n\t"
        "add	x8, %x[a], x13\n\t"
        "ldp	q0, q1, [x8]\n\t"
        "mov	x6, #0\n\t"
        "\n"
    "L_mc_v256_j_amam_%=:\n\t"
        "cmp	x6, #13\n\t"
        "b.ge	L_mc_v256_in_amam_%=\n\t"
        "lsl	x13, x6, #5\n\t"
        "add	x9, %x[c], x13\n\t"
        "ldp	q2, q3, [x9]\n\t"
        "and	v4.16b, v0.16b, v2.16b\n\t"
        "and	v5.16b, v1.16b, v3.16b\n\t"
        "add	x13, x5, x6\n\t"
        "lsl	x13, x13, #5\n\t"
        "add	x10, %x[cscr], x13\n\t"
        "ldp	q6, q7, [x10]\n\t"
        "eor	v6.16b, v6.16b, v4.16b\n\t"
        "eor	v7.16b, v7.16b, v5.16b\n\t"
        "stp	q6, q7, [x10]\n\t"
        "add	x6, x6, #1\n\t"
        "b	L_mc_v256_j_amam_%=\n\t"
        "\n"
    "L_mc_v256_in_amam_%=:\n\t"
        "add	x5, x5, #1\n\t"
        "b	L_mc_v256_i_amam_%=\n\t"
        "\n"
    "L_mc_v256_rs_amam_%=:\n\t"
        "mov	x7, #24\n\t"
        "\n"
    "L_mc_v256_rk_amam_%=:\n\t"
        "cmp	x7, #13\n\t"
        "b.lt	L_mc_v256_copy_amam_%=\n\t"
        "lsl	x13, x7, #5\n\t"
        "add	x10, %x[cscr], x13\n\t"
        "ldp	q6, q7, [x10]\n\t"
        "sub	x14, x7, #9\n\t"
        "lsl	x14, x14, #5\n\t"
        "add	x11, %x[cscr], x14\n\t"
        "ldp	q8, q9, [x11]\n\t"
        "eor	v8.16b, v8.16b, v6.16b\n\t"
        "eor	v9.16b, v9.16b, v7.16b\n\t"
        "stp	q8, q9, [x11]\n\t"
        "sub	x14, x7, #10\n\t"
        "lsl	x14, x14, #5\n\t"
        "add	x11, %x[cscr], x14\n\t"
        "ldp	q8, q9, [x11]\n\t"
        "eor	v8.16b, v8.16b, v6.16b\n\t"
        "eor	v9.16b, v9.16b, v7.16b\n\t"
        "stp	q8, q9, [x11]\n\t"
        "sub	x14, x7, #12\n\t"
        "lsl	x14, x14, #5\n\t"
        "add	x11, %x[cscr], x14\n\t"
        "ldp	q8, q9, [x11]\n\t"
        "eor	v8.16b, v8.16b, v6.16b\n\t"
        "eor	v9.16b, v9.16b, v7.16b\n\t"
        "stp	q8, q9, [x11]\n\t"
        "sub	x14, x7, #13\n\t"
        "lsl	x14, x14, #5\n\t"
        "add	x11, %x[cscr], x14\n\t"
        "ldp	q8, q9, [x11]\n\t"
        "eor	v8.16b, v8.16b, v6.16b\n\t"
        "eor	v9.16b, v9.16b, v7.16b\n\t"
        "stp	q8, q9, [x11]\n\t"
        "sub	x7, x7, #1\n\t"
        "b	L_mc_v256_rk_amam_%=\n\t"
        "\n"
    "L_mc_v256_copy_amam_%=:\n\t"
        "mov	x7, #0\n\t"
        "\n"
    "L_mc_v256_cp_amam_%=:\n\t"
        "cmp	x7, #13\n\t"
        "b.ge	L_mc_v256_done_amam_%=\n\t"
        "lsl	x13, x7, #5\n\t"
        "add	x10, %x[cscr], x13\n\t"
        "add	x11, %x[p], x13\n\t"
        "ldp	q6, q7, [x10]\n\t"
        "stp	q6, q7, [x11]\n\t"
        "add	x7, x7, #1\n\t"
        "b	L_mc_v256_cp_amam_%=\n\t"
        "\n"
    "L_mc_v256_done_amam_%=:\n\t"
        "mov	x5, #0\n\t"
        "\n"
    "L_mc_xor13_k_amab_%=:\n\t"
        "lsl	x6, x5, #5\n\t"
        "add	x8, %x[b], x6\n\t"
        "ldp	q0, q1, [x8]\n\t"
        "add	x9, %x[p], x6\n\t"
        "ldp	q2, q3, [x9]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "add	x7, %x[b], x6\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x5, x5, #1\n\t"
        "cmp	x5, #13\n\t"
        "b.lt	L_mc_xor13_k_amab_%=\n\t"
        : [a] "+r" (a), [b] "+r" (b), [p] "+r" (p), [cscr] "+r" (cscr)
        : [c] "r" (c)
        : "memory", "cc", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12",
            "x13", "x14", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8",
            "v9", "v10"
    );
}

WOLFSSL_LOCAL void wc_mceliece_aff_btr_net_neon(word64* pre_p, word64* buf_p,
    word64* out_p, int i_p, int i2_p);
void wc_mceliece_aff_btr_net_neon(word64* pre_p, word64* buf_p, word64* out_p,
    int i_p, int i2_p)
{
    register word64* pre __asm__ ("x0") = (word64*)pre_p;
    register word64* buf __asm__ ("x1") = (word64*)buf_p;
    register word64* out __asm__ ("x2") = (word64*)out_p;
    register int i __asm__ ("w3") = (int)i_p;
    register int i2 __asm__ ("w4") = (int)i2_p;
    __asm__ __volatile__ (
        "lsl	x8, %x[i2], #5\n\t"
        "add	x5, %x[pre], x8\n\t"
        "add	x6, %x[buf], #0x400\n\t"
        "ldp	q0, q1, [x6]\n\t"
        "add	x7, x5, #0\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x420\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x400\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x420\n\t"
        "ldp	q0, q1, [x6]\n\t"
        "add	x7, x5, #0xe0\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x460\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x420\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x460\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x440\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x460\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x440\n\t"
        "ldp	q0, q1, [x6]\n\t"
        "add	x7, x5, #0x1c0\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x4c0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x440\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x4c0\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x4e0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x4c0\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0xe0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x4e0\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x4a0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x4e0\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x4a0\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x480\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x4a0\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x480\n\t"
        "ldp	q0, q1, [x6]\n\t"
        "add	x7, x5, #0x2a0\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x580\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x480\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x580\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x5a0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x580\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0xe0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x5a0\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x5e0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x5a0\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x5e0\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x5c0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x5e0\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0x1c0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x5c0\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x540\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x5c0\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x540\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x560\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x540\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0xe0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x560\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x520\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x560\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x520\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x500\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x520\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x500\n\t"
        "ldp	q0, q1, [x6]\n\t"
        "add	x7, x5, #0x380\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x700\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x500\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x700\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x720\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x700\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0xe0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x720\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x760\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x720\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x760\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x740\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x760\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0x1c0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x740\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x7c0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x740\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x7c0\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x7e0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x7c0\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0xe0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x7e0\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x7a0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x7e0\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x7a0\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x780\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x7a0\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0x2a0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x780\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x680\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x780\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x680\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x6a0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x680\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0xe0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x6a0\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x6e0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x6a0\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x6e0\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x6c0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x6e0\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0x1c0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x6c0\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x640\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x6c0\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x640\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x660\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x640\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0xe0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x660\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x620\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x660\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x620\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x600\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x620\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x600\n\t"
        "ldp	q0, q1, [x6]\n\t"
        "add	x7, x5, #0x460\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x200\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x600\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x200\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x220\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x200\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0xe0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x220\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x260\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x220\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x260\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x240\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x260\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0x1c0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x240\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x2c0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x240\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x2c0\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x2e0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x2c0\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0xe0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x2e0\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x2a0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x2e0\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x2a0\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x280\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x2a0\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0x2a0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x280\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x380\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x280\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x380\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x3a0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x380\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0xe0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x3a0\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x3e0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x3a0\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x3e0\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x3c0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x3e0\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0x1c0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x3c0\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x340\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x3c0\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x340\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x360\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x340\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0xe0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x360\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x320\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x360\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x320\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x300\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x320\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0x380\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x300\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x100\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x300\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x100\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x120\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x100\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0xe0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x120\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x160\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x120\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x160\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x140\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x160\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0x1c0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x140\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x1c0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x140\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x1c0\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x1e0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x1c0\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0xe0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x1e0\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x1a0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x1e0\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x1a0\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x180\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x1a0\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0x2a0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x180\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x80\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x180\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x80\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0xa0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x80\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0xe0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0xa0\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0xe0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0xa0\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0xe0\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0xc0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0xe0\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0x1c0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0xc0\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x40\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0xc0\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x40\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #0x60\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x40\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0xe0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x60\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, %x[buf], #32\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #0x60\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "add	x7, x5, #0\n\t"
        "ldp	q0, q1, [x7]\n\t"
        "add	x6, %x[buf], #32\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x7]\n\t"
        "ldp	q0, q1, [%x[buf]]\n\t"
        "add	x6, %x[buf], #32\n\t"
        "ldp	q2, q3, [x6]\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "lsl	x8, %x[i], #5\n\t"
        "add	x7, %x[out], x8\n\t"
        "str	q0, [x7]\n\t"
        "cmp	%w[i], #12\n\t"
        "b.eq	L_mc_btrn_nh_%=\n\t"
        "add	x7, x7, #32\n\t"
        "str	q1, [x7]\n\t"
        "\n"
    "L_mc_btrn_nh_%=:\n\t"
        : [pre] "+r" (pre), [buf] "+r" (buf), [out] "+r" (out), [i] "+r" (i),
          [i2] "+r" (i2)
        :
        : "memory", "cc", "x5", "x6", "x7", "x8", "v0", "v1", "v2", "v3"
    );
}

WOLFSSL_LOCAL void wc_mceliece_aff_butterflies_tr_neon(word64* out_p,
    word64* in_p, word64* scratch_p);
void wc_mceliece_aff_butterflies_tr_neon(word64* out_p, word64* in_p,
    word64* scratch_p)
{
    register word64* out __asm__ ("x0") = (word64*)out_p;
    register word64* in __asm__ ("x1") = (word64*)in_p;
    register word64* scratch __asm__ ("x2") = (word64*)scratch_p;
    register const word64* L_mc_aff_consts_neon_c __asm__ ("x3") = L_mc_aff_consts_neon;
    register const word8* L_mc_aff_reversal_neon_c __asm__ ("x4") = L_mc_aff_reversal_neon;
    __asm__ __volatile__ (
        "mov	x19, %x[out]\n\t"
        "mov	x20, %x[in]\n\t"
        "mov	x21, %x[scratch]\n\t"
        "mov	x22, %[L_mc_aff_consts_neon_c]\n\t"
        "mov	x23, %[L_mc_aff_reversal_neon_c]\n\t"
        "mov	x5, #0\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x1a00\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x1ba0\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x1a0\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x1ba0\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x1d40\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x340\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x1d40\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x1ee0\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x4e0\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x1ee0\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x2080\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x680\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x2080\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x2220\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x820\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x2220\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x23c0\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x9c0\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x23c0\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x2560\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0xb60\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x2560\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x2700\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0xd00\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x2700\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x28a0\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0xea0\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x28a0\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x2a40\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x1040\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x2a40\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x2be0\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x11e0\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x2be0\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x2d80\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x1380\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x2d80\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x2f20\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x1520\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x2f20\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x30c0\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x16c0\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x30c0\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x3260\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x1860\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x3260\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x3400\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0xd00\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0xea0\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x1a0\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0xea0\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x1040\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x340\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x1040\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x11e0\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x4e0\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x11e0\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x1380\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x680\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x1380\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x1520\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x820\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x1520\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x16c0\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x9c0\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x16c0\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x1860\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0xb60\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x1860\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x1a00\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x1a00\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x2700\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0xea0\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x1ba0\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x28a0\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x1040\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x1d40\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x2a40\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x11e0\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x1ee0\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x2be0\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x1380\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x2080\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x2d80\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x1520\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x2220\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x2f20\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x16c0\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x23c0\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x30c0\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x1860\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x2560\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x3260\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x1a00\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x680\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x820\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x1a0\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x820\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x9c0\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x340\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x9c0\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0xb60\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x4e0\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0xb60\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0xd00\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0xd00\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x1380\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x820\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0xea0\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x1520\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x9c0\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x1040\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x16c0\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0xb60\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x11e0\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x1860\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0xd00\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x1a00\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x2080\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x820\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x1ba0\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x2220\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x9c0\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x1d40\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x23c0\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0xb60\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x1ee0\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x2560\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0xd00\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x2700\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x2d80\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x820\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x28a0\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x2f20\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x9c0\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x2a40\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x30c0\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0xb60\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x2be0\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x3260\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0xd00\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x340\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x4e0\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x1a0\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x4e0\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x680\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x680\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x9c0\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x4e0\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x820\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0xb60\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x680\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0xd00\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x1040\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x4e0\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0xea0\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x11e0\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x680\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x1380\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x16c0\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x4e0\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x1520\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x1860\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x680\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x1a00\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x1d40\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x4e0\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x1ba0\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x1ee0\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x680\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x2080\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x23c0\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x4e0\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x2220\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x2560\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x680\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x2700\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x2a40\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x4e0\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x28a0\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x2be0\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x680\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x2d80\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x30c0\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x4e0\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x2f20\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x3260\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x680\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x1a0\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x340\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x340\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x4e0\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x340\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x680\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x820\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x340\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x9c0\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0xb60\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x340\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0xd00\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0xea0\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x340\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x1040\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x11e0\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x340\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x1380\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x1520\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x340\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x16c0\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x1860\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x340\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x1a00\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x1ba0\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x340\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x1d40\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x1ee0\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x340\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x2080\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x2220\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x340\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x23c0\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x2560\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x340\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x2700\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x28a0\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x340\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x2a40\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x2be0\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x340\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x2d80\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x2f20\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x340\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x30c0\n\t"
        "add	%x[out], x20, x5\n\t"
        "mov	x5, #0x3260\n\t"
        "add	%x[in], x20, x5\n\t"
        "mov	x5, #0x340\n\t"
        "add	%x[scratch], x22, x5\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x24, #0\n\t"
        "\n"
    "L_mc_btr_pk_%=:\n\t"
        "cmp	x24, #32\n\t"
        "b.ge	L_mc_btr_pke_%=\n\t"
        "mov	x5, #0x1a0\n\t"
        "mul	x8, x24, x5\n\t"
        "add	%x[out], x21, #0x610\n\t"
        "add	%x[in], x21, #0x7b0\n\t"
        "add	%x[scratch], x20, x8\n\t"
        "add	%[L_mc_aff_consts_neon_c], %x[scratch], #0x1a0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_pack_lh_neon\n\t"
#else
        "bl	_wc_mceliece_aff_pack_lh_neon\n\t"
#endif /* __APPLE__ */
        "add	%x[out], x21, #0x610\n\t"
        "add	%x[in], x21, #0x7b0\n\t"
        "add	%x[scratch], x22, #0x1a0\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x1a0\n\t"
        "mul	x8, x24, x5\n\t"
        "add	%x[out], x20, x8\n\t"
        "add	%x[in], %x[out], #0x1a0\n\t"
        "add	%x[scratch], x21, #0x610\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0x7b0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_pack_lh_neon\n\t"
#else
        "bl	_wc_mceliece_aff_pack_lh_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x1a0\n\t"
        "mul	x8, x24, x5\n\t"
        "add	%x[out], x21, #0x610\n\t"
        "add	%x[in], x21, #0x7b0\n\t"
        "add	%x[scratch], x20, x8\n\t"
        "add	%[L_mc_aff_consts_neon_c], %x[scratch], #0x1a0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_pack_lh2_neon\n\t"
#else
        "bl	_wc_mceliece_aff_pack_lh2_neon\n\t"
#endif /* __APPLE__ */
        "add	%x[out], x21, #0x610\n\t"
        "add	%x[in], x21, #0x7b0\n\t"
        "mov	%x[scratch], x22\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0xe10\n\t"
        "add	%[L_mc_aff_reversal_neon_c], x21, #0xfb0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_ama_neon\n\t"
#else
        "bl	_wc_mceliece_aff_ama_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, #0x1a0\n\t"
        "mul	x8, x24, x5\n\t"
        "add	%x[out], x20, x8\n\t"
        "add	%x[in], %x[out], #0x1a0\n\t"
        "add	%x[scratch], x21, #0x610\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0x7b0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_pack_lh2_neon\n\t"
#else
        "bl	_wc_mceliece_aff_pack_lh2_neon\n\t"
#endif /* __APPLE__ */
        "add	x24, x24, #2\n\t"
        "b	L_mc_btr_pk_%=\n\t"
        "\n"
    "L_mc_btr_pke_%=:\n\t"
        "mov	x24, #0\n\t"
        "\n"
    "L_mc_btr_i_%=:\n\t"
        "cmp	x24, #13\n\t"
        "b.ge	L_mc_btr_ie_%=\n\t"
        "add	%x[out], x21, #0x610\n\t"
        "mov	%x[in], x20\n\t"
        "mov	%x[scratch], x23\n\t"
        "mov	%w[L_mc_aff_consts_neon_c], w24\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_btr_in_neon\n\t"
#else
        "bl	_wc_mceliece_aff_btr_in_neon\n\t"
#endif /* __APPLE__ */
        "add	%x[out], x21, #0x610\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_transpose_neon\n\t"
#else
        "bl	_wc_mceliece_aff_transpose_neon\n\t"
#endif /* __APPLE__ */
        "add	%x[out], x21, #0xd0\n\t"
        "add	%x[in], x21, #0x610\n\t"
        "mov	%x[scratch], x19\n\t"
        "mov	%w[L_mc_aff_consts_neon_c], w24\n\t"
        "lsr	x8, x24, #1\n\t"
        "mov	%w[L_mc_aff_reversal_neon_c], w8\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_btr_net_neon\n\t"
#else
        "bl	_wc_mceliece_aff_btr_net_neon\n\t"
#endif /* __APPLE__ */
        "add	x24, x24, #2\n\t"
        "b	L_mc_btr_i_%=\n\t"
        "\n"
    "L_mc_btr_ie_%=:\n\t"
        "mov	x9, #0\n\t"
        "sub	x9, x9, #1\n\t"
        "mov	x10, #0\n\t"
        "add	x5, x21, #0\n\t"
        "str	x10, [x5]\n\t"
        "str	x10, [x5, #8]\n\t"
        "add	x5, x21, #16\n\t"
        "str	x9, [x5]\n\t"
        "str	x9, [x5, #8]\n\t"
        "add	x5, x21, #32\n\t"
        "str	x9, [x5]\n\t"
        "str	x9, [x5, #8]\n\t"
        "add	x5, x21, #48\n\t"
        "str	x9, [x5]\n\t"
        "str	x9, [x5, #8]\n\t"
        "add	x5, x21, #0x40\n\t"
        "str	x9, [x5]\n\t"
        "str	x9, [x5, #8]\n\t"
        "add	x5, x21, #0x50\n\t"
        "str	x9, [x5]\n\t"
        "str	x9, [x5, #8]\n\t"
        "add	x5, x21, #0x60\n\t"
        "str	x9, [x5]\n\t"
        "str	x9, [x5, #8]\n\t"
        "add	x5, x21, #0x70\n\t"
        "str	x10, [x5]\n\t"
        "str	x10, [x5, #8]\n\t"
        "add	x5, x21, #0x80\n\t"
        "str	x10, [x5]\n\t"
        "str	x10, [x5, #8]\n\t"
        "add	x5, x21, #0x90\n\t"
        "str	x10, [x5]\n\t"
        "str	x10, [x5, #8]\n\t"
        "add	x5, x21, #0xa0\n\t"
        "str	x9, [x5]\n\t"
        "str	x9, [x5, #8]\n\t"
        "add	x5, x21, #0xb0\n\t"
        "str	x10, [x5]\n\t"
        "str	x10, [x5, #8]\n\t"
        "add	x5, x21, #0xc0\n\t"
        "str	x9, [x5]\n\t"
        "str	x9, [x5, #8]\n\t"
        "mov	%x[out], x21\n\t"
        "add	%x[in], x21, #0xd0\n\t"
        "mov	%x[scratch], x21\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0x610\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_v128_mul_neon\n\t"
#else
        "bl	_wc_mceliece_aff_v128_mul_neon\n\t"
#endif /* __APPLE__ */
        "add	x5, x21, #0\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0\n\t"
        "str	x6, [x8, #16]\n\t"
        "str	x7, [x8, #24]\n\t"
        "add	x5, x21, #16\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #32\n\t"
        "str	x6, [x8, #16]\n\t"
        "str	x7, [x8, #24]\n\t"
        "add	x5, x21, #32\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0x40\n\t"
        "str	x6, [x8, #16]\n\t"
        "str	x7, [x8, #24]\n\t"
        "add	x5, x21, #48\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0x60\n\t"
        "str	x6, [x8, #16]\n\t"
        "str	x7, [x8, #24]\n\t"
        "add	x5, x21, #0x40\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0x80\n\t"
        "str	x6, [x8, #16]\n\t"
        "str	x7, [x8, #24]\n\t"
        "add	x5, x21, #0x50\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0xa0\n\t"
        "str	x6, [x8, #16]\n\t"
        "str	x7, [x8, #24]\n\t"
        "add	x5, x21, #0x60\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0xc0\n\t"
        "str	x6, [x8, #16]\n\t"
        "str	x7, [x8, #24]\n\t"
        "add	x5, x21, #0x70\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0xe0\n\t"
        "str	x6, [x8, #16]\n\t"
        "str	x7, [x8, #24]\n\t"
        "add	x5, x21, #0x80\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0x100\n\t"
        "str	x6, [x8, #16]\n\t"
        "str	x7, [x8, #24]\n\t"
        "add	x5, x21, #0x90\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0x120\n\t"
        "str	x6, [x8, #16]\n\t"
        "str	x7, [x8, #24]\n\t"
        "add	x5, x21, #0xa0\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0x140\n\t"
        "str	x6, [x8, #16]\n\t"
        "str	x7, [x8, #24]\n\t"
        "add	x5, x21, #0xb0\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0x160\n\t"
        "str	x6, [x8, #16]\n\t"
        "str	x7, [x8, #24]\n\t"
        "add	x5, x21, #0xc0\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0x180\n\t"
        "str	x6, [x8, #16]\n\t"
        "str	x7, [x8, #24]\n\t"
        "mov	x9, #0\n\t"
        "sub	x9, x9, #1\n\t"
        "mov	x10, #0\n\t"
        "add	x5, x21, #0\n\t"
        "str	x10, [x5]\n\t"
        "str	x10, [x5, #8]\n\t"
        "add	x5, x21, #16\n\t"
        "str	x9, [x5]\n\t"
        "str	x9, [x5, #8]\n\t"
        "add	x5, x21, #32\n\t"
        "str	x10, [x5]\n\t"
        "str	x10, [x5, #8]\n\t"
        "add	x5, x21, #48\n\t"
        "str	x9, [x5]\n\t"
        "str	x9, [x5, #8]\n\t"
        "add	x5, x21, #0x40\n\t"
        "str	x9, [x5]\n\t"
        "str	x9, [x5, #8]\n\t"
        "add	x5, x21, #0x50\n\t"
        "str	x9, [x5]\n\t"
        "str	x9, [x5, #8]\n\t"
        "add	x5, x21, #0x60\n\t"
        "str	x10, [x5]\n\t"
        "str	x10, [x5, #8]\n\t"
        "add	x5, x21, #0x70\n\t"
        "str	x9, [x5]\n\t"
        "str	x9, [x5, #8]\n\t"
        "add	x5, x21, #0x80\n\t"
        "str	x10, [x5]\n\t"
        "str	x10, [x5, #8]\n\t"
        "add	x5, x21, #0x90\n\t"
        "str	x10, [x5]\n\t"
        "str	x10, [x5, #8]\n\t"
        "add	x5, x21, #0xa0\n\t"
        "str	x9, [x5]\n\t"
        "str	x9, [x5, #8]\n\t"
        "add	x5, x21, #0xb0\n\t"
        "str	x10, [x5]\n\t"
        "str	x10, [x5, #8]\n\t"
        "add	x5, x21, #0xc0\n\t"
        "str	x9, [x5]\n\t"
        "str	x9, [x5, #8]\n\t"
        "mov	%x[out], x21\n\t"
        "add	%x[in], x21, #0x1b0\n\t"
        "mov	%x[scratch], x21\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0x610\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_v128_mul_neon\n\t"
#else
        "bl	_wc_mceliece_aff_v128_mul_neon\n\t"
#endif /* __APPLE__ */
        "add	x5, x21, #0\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #16\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #32\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #32\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0x40\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #48\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0x60\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #0x40\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0x80\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #0x50\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0xa0\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #0x60\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0xc0\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #0x70\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0xe0\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #0x80\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0x100\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #0x90\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0x120\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #0xa0\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0x140\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #0xb0\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0x160\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #0xc0\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0x180\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "mov	x9, #0\n\t"
        "sub	x9, x9, #1\n\t"
        "mov	x10, #0\n\t"
        "add	x5, x21, #0\n\t"
        "str	x9, [x5]\n\t"
        "str	x9, [x5, #8]\n\t"
        "add	x5, x21, #16\n\t"
        "str	x9, [x5]\n\t"
        "str	x9, [x5, #8]\n\t"
        "add	x5, x21, #32\n\t"
        "str	x9, [x5]\n\t"
        "str	x9, [x5, #8]\n\t"
        "add	x5, x21, #48\n\t"
        "str	x10, [x5]\n\t"
        "str	x10, [x5, #8]\n\t"
        "add	x5, x21, #0x40\n\t"
        "str	x9, [x5]\n\t"
        "str	x9, [x5, #8]\n\t"
        "add	x5, x21, #0x50\n\t"
        "str	x10, [x5]\n\t"
        "str	x10, [x5, #8]\n\t"
        "add	x5, x21, #0x60\n\t"
        "str	x10, [x5]\n\t"
        "str	x10, [x5, #8]\n\t"
        "add	x5, x21, #0x70\n\t"
        "str	x9, [x5]\n\t"
        "str	x9, [x5, #8]\n\t"
        "add	x5, x21, #0x80\n\t"
        "str	x9, [x5]\n\t"
        "str	x9, [x5, #8]\n\t"
        "add	x5, x21, #0x90\n\t"
        "str	x9, [x5]\n\t"
        "str	x9, [x5, #8]\n\t"
        "add	x5, x21, #0xa0\n\t"
        "str	x9, [x5]\n\t"
        "str	x9, [x5, #8]\n\t"
        "add	x5, x21, #0xb0\n\t"
        "str	x10, [x5]\n\t"
        "str	x10, [x5, #8]\n\t"
        "add	x5, x21, #0xc0\n\t"
        "str	x9, [x5]\n\t"
        "str	x9, [x5, #8]\n\t"
        "mov	%x[out], x21\n\t"
        "add	%x[in], x21, #0x290\n\t"
        "mov	%x[scratch], x21\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0x610\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_v128_mul_neon\n\t"
#else
        "bl	_wc_mceliece_aff_v128_mul_neon\n\t"
#endif /* __APPLE__ */
        "add	x5, x21, #0\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #16\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #32\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #32\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0x40\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #48\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0x60\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #0x40\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0x80\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #0x50\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0xa0\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #0x60\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0xc0\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #0x70\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0xe0\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #0x80\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0x100\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #0x90\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0x120\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #0xa0\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0x140\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #0xb0\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0x160\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #0xc0\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0x180\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "mov	x9, #0\n\t"
        "sub	x9, x9, #1\n\t"
        "mov	x10, #0\n\t"
        "add	x5, x21, #0\n\t"
        "str	x9, [x5]\n\t"
        "str	x9, [x5, #8]\n\t"
        "add	x5, x21, #16\n\t"
        "str	x10, [x5]\n\t"
        "str	x10, [x5, #8]\n\t"
        "add	x5, x21, #32\n\t"
        "str	x9, [x5]\n\t"
        "str	x9, [x5, #8]\n\t"
        "add	x5, x21, #48\n\t"
        "str	x9, [x5]\n\t"
        "str	x9, [x5, #8]\n\t"
        "add	x5, x21, #0x40\n\t"
        "str	x9, [x5]\n\t"
        "str	x9, [x5, #8]\n\t"
        "add	x5, x21, #0x50\n\t"
        "str	x10, [x5]\n\t"
        "str	x10, [x5, #8]\n\t"
        "add	x5, x21, #0x60\n\t"
        "str	x10, [x5]\n\t"
        "str	x10, [x5, #8]\n\t"
        "add	x5, x21, #0x70\n\t"
        "str	x10, [x5]\n\t"
        "str	x10, [x5, #8]\n\t"
        "add	x5, x21, #0x80\n\t"
        "str	x10, [x5]\n\t"
        "str	x10, [x5, #8]\n\t"
        "add	x5, x21, #0x90\n\t"
        "str	x9, [x5]\n\t"
        "str	x9, [x5, #8]\n\t"
        "add	x5, x21, #0xa0\n\t"
        "str	x10, [x5]\n\t"
        "str	x10, [x5, #8]\n\t"
        "add	x5, x21, #0xb0\n\t"
        "str	x9, [x5]\n\t"
        "str	x9, [x5, #8]\n\t"
        "add	x5, x21, #0xc0\n\t"
        "str	x9, [x5]\n\t"
        "str	x9, [x5, #8]\n\t"
        "mov	%x[out], x21\n\t"
        "add	%x[in], x21, #0x370\n\t"
        "mov	%x[scratch], x21\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0x610\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_v128_mul_neon\n\t"
#else
        "bl	_wc_mceliece_aff_v128_mul_neon\n\t"
#endif /* __APPLE__ */
        "add	x5, x21, #0\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #16\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #32\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #32\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0x40\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #48\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0x60\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #0x40\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0x80\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #0x50\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0xa0\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #0x60\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0xc0\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #0x70\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0xe0\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #0x80\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0x100\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #0x90\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0x120\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #0xa0\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0x140\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #0xb0\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0x160\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #0xc0\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0x180\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "mov	x9, #0\n\t"
        "sub	x9, x9, #1\n\t"
        "mov	x10, #0\n\t"
        "add	x5, x21, #0\n\t"
        "str	x9, [x5]\n\t"
        "str	x9, [x5, #8]\n\t"
        "add	x5, x21, #16\n\t"
        "str	x10, [x5]\n\t"
        "str	x10, [x5, #8]\n\t"
        "add	x5, x21, #32\n\t"
        "str	x10, [x5]\n\t"
        "str	x10, [x5, #8]\n\t"
        "add	x5, x21, #48\n\t"
        "str	x9, [x5]\n\t"
        "str	x9, [x5, #8]\n\t"
        "add	x5, x21, #0x40\n\t"
        "str	x10, [x5]\n\t"
        "str	x10, [x5, #8]\n\t"
        "add	x5, x21, #0x50\n\t"
        "str	x9, [x5]\n\t"
        "str	x9, [x5, #8]\n\t"
        "add	x5, x21, #0x60\n\t"
        "str	x10, [x5]\n\t"
        "str	x10, [x5, #8]\n\t"
        "add	x5, x21, #0x70\n\t"
        "str	x10, [x5]\n\t"
        "str	x10, [x5, #8]\n\t"
        "add	x5, x21, #0x80\n\t"
        "str	x9, [x5]\n\t"
        "str	x9, [x5, #8]\n\t"
        "add	x5, x21, #0x90\n\t"
        "str	x9, [x5]\n\t"
        "str	x9, [x5, #8]\n\t"
        "add	x5, x21, #0xa0\n\t"
        "str	x10, [x5]\n\t"
        "str	x10, [x5, #8]\n\t"
        "add	x5, x21, #0xb0\n\t"
        "str	x10, [x5]\n\t"
        "str	x10, [x5, #8]\n\t"
        "add	x5, x21, #0xc0\n\t"
        "str	x9, [x5]\n\t"
        "str	x9, [x5, #8]\n\t"
        "mov	%x[out], x21\n\t"
        "add	%x[in], x21, #0x450\n\t"
        "mov	%x[scratch], x21\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0x610\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_v128_mul_neon\n\t"
#else
        "bl	_wc_mceliece_aff_v128_mul_neon\n\t"
#endif /* __APPLE__ */
        "add	x5, x21, #0\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #16\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #32\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #32\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0x40\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #48\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0x60\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #0x40\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0x80\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #0x50\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0xa0\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #0x60\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0xc0\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #0x70\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0xe0\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #0x80\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0x100\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #0x90\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0x120\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #0xa0\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0x140\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #0xb0\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0x160\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #0xc0\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0x180\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "mov	x9, #0\n\t"
        "sub	x9, x9, #1\n\t"
        "mov	x10, #0\n\t"
        "add	x5, x21, #0\n\t"
        "str	x9, [x5]\n\t"
        "str	x9, [x5, #8]\n\t"
        "add	x5, x21, #16\n\t"
        "str	x9, [x5]\n\t"
        "str	x9, [x5, #8]\n\t"
        "add	x5, x21, #32\n\t"
        "str	x10, [x5]\n\t"
        "str	x10, [x5, #8]\n\t"
        "add	x5, x21, #48\n\t"
        "str	x10, [x5]\n\t"
        "str	x10, [x5, #8]\n\t"
        "add	x5, x21, #0x40\n\t"
        "str	x10, [x5]\n\t"
        "str	x10, [x5, #8]\n\t"
        "add	x5, x21, #0x50\n\t"
        "str	x9, [x5]\n\t"
        "str	x9, [x5, #8]\n\t"
        "add	x5, x21, #0x60\n\t"
        "str	x9, [x5]\n\t"
        "str	x9, [x5, #8]\n\t"
        "add	x5, x21, #0x70\n\t"
        "str	x10, [x5]\n\t"
        "str	x10, [x5, #8]\n\t"
        "add	x5, x21, #0x80\n\t"
        "str	x10, [x5]\n\t"
        "str	x10, [x5, #8]\n\t"
        "add	x5, x21, #0x90\n\t"
        "str	x9, [x5]\n\t"
        "str	x9, [x5, #8]\n\t"
        "add	x5, x21, #0xa0\n\t"
        "str	x10, [x5]\n\t"
        "str	x10, [x5, #8]\n\t"
        "add	x5, x21, #0xb0\n\t"
        "str	x9, [x5]\n\t"
        "str	x9, [x5, #8]\n\t"
        "add	x5, x21, #0xc0\n\t"
        "str	x9, [x5]\n\t"
        "str	x9, [x5, #8]\n\t"
        "mov	%x[out], x21\n\t"
        "add	%x[in], x21, #0x530\n\t"
        "mov	%x[scratch], x21\n\t"
        "add	%[L_mc_aff_consts_neon_c], x21, #0x610\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_v128_mul_neon\n\t"
#else
        "bl	_wc_mceliece_aff_v128_mul_neon\n\t"
#endif /* __APPLE__ */
        "add	x5, x21, #0\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #16\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #32\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #32\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0x40\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #48\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0x60\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #0x40\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0x80\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #0x50\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0xa0\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #0x60\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0xc0\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #0x70\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0xe0\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #0x80\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0x100\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #0x90\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0x120\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #0xa0\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0x140\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #0xb0\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0x160\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        "add	x5, x21, #0xc0\n\t"
        "ldr	x6, [x5]\n\t"
        "ldr	x7, [x5, #8]\n\t"
        "add	x8, x19, #0x180\n\t"
        "ldr	x11, [x8, #16]\n\t"
        "eor	x11, x11, x6\n\t"
        "str	x11, [x8, #16]\n\t"
        "ldr	x12, [x8, #24]\n\t"
        "eor	x12, x12, x7\n\t"
        "str	x12, [x8, #24]\n\t"
        : [out] "+r" (out), [in] "+r" (in), [scratch] "+r" (scratch)
        : [L_mc_aff_consts_neon_c] "r" (L_mc_aff_consts_neon_c),
          [L_mc_aff_reversal_neon_c] "r" (L_mc_aff_reversal_neon_c)
        : "memory", "cc", "x19", "x20", "x21", "x22", "x23", "x24", "x5", "x6",
            "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x30"
    );
}

WOLFSSL_LOCAL void wc_mceliece_aff_pack_lh2_neon(word64* lo_p, word64* hi_p,
    const word64* a_p, const word64* b_p);
void wc_mceliece_aff_pack_lh2_neon(word64* lo_p, word64* hi_p,
    const word64* a_p, const word64* b_p)
{
    register word64* lo __asm__ ("x0") = (word64*)lo_p;
    register word64* hi __asm__ ("x1") = (word64*)hi_p;
    register const word64* a __asm__ ("x2") = (const word64*)a_p;
    register const word64* b __asm__ ("x3") = (const word64*)b_p;
    __asm__ __volatile__ (
        "mov	x4, #0\n\t"
        "\n"
    "L_mc_packlh2_p_%=:\n\t"
        "lsl	x5, x4, #5\n\t"
        "add	x8, %x[a], x5\n\t"
        "ldp	q0, q1, [x8]\n\t"
        "add	x9, %x[b], x5\n\t"
        "ldp	q2, q3, [x9]\n\t"
        "zip1	v4.2d, v0.2d, v2.2d\n\t"
        "zip1	v5.2d, v1.2d, v3.2d\n\t"
        "add	x6, %x[lo], x5\n\t"
        "stp	q4, q5, [x6]\n\t"
        "zip2	v4.2d, v0.2d, v2.2d\n\t"
        "zip2	v5.2d, v1.2d, v3.2d\n\t"
        "add	x7, %x[hi], x5\n\t"
        "stp	q4, q5, [x7]\n\t"
        "add	x4, x4, #1\n\t"
        "cmp	x4, #13\n\t"
        "b.lt	L_mc_packlh2_p_%=\n\t"
        : [lo] "+r" (lo), [hi] "+r" (hi)
        : [a] "r" (a), [b] "r" (b)
        : "memory", "cc", "x4", "x5", "x6", "x7", "x8", "x9", "v0", "v1", "v2",
            "v3", "v4", "v5"
    );
}

WOLFSSL_LOCAL void wc_mceliece_aff_radix_tr_step_neon(word64* in_p,
    const word64* tm0_p, const word64* tm1_p, int j_p);
void wc_mceliece_aff_radix_tr_step_neon(word64* in_p, const word64* tm0_p,
    const word64* tm1_p, int j_p)
{
    register word64* in __asm__ ("x0") = (word64*)in_p;
    register const word64* tm0 __asm__ ("x1") = (const word64*)tm0_p;
    register const word64* tm1 __asm__ ("x2") = (const word64*)tm1_p;
    register int j __asm__ ("w3") = (int)j_p;
    __asm__ __volatile__ (
        "mov	w4, %w[j]\n\t"
        "eor	v8.16b, v8.16b, v8.16b\n\t"
        "mov	x13, #1\n\t"
        "mov	x5, x4\n\t"
        "\n"
    "L_mc_rtr_k_%=:\n\t"
        "cmp	x5, #4\n\t"
        "b.gt	L_mc_rtr_ke_%=\n\t"
        "lsl	x6, x13, x5\n\t"
        "dup	v6.2d, x6\n\t"
        "lsl	x8, x5, #3\n\t"
        "add	x10, %x[tm0], x8\n\t"
        "ldr	x11, [x10]\n\t"
        "dup	v4.2d, x11\n\t"
        "add	x10, %x[tm1], x8\n\t"
        "ldr	x12, [x10]\n\t"
        "dup	v5.2d, x12\n\t"
        "mov	x7, #0\n\t"
        "\n"
    "L_mc_rtr_ki_%=:\n\t"
        "cmp	x7, #13\n\t"
        "b.ge	L_mc_rtr_kie_%=\n\t"
        "lsl	x8, x7, #5\n\t"
        "add	x9, %x[in], x8\n\t"
        "ldp	q0, q1, [x9]\n\t"
        "and	v2.16b, v0.16b, v4.16b\n\t"
        "ushl	v2.2d, v2.2d, v6.2d\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "and	v3.16b, v1.16b, v4.16b\n\t"
        "ushl	v3.2d, v3.2d, v6.2d\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "and	v2.16b, v0.16b, v5.16b\n\t"
        "ushl	v2.2d, v2.2d, v6.2d\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "and	v3.16b, v1.16b, v5.16b\n\t"
        "ushl	v3.2d, v3.2d, v6.2d\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x7, #1\n\t"
        "b	L_mc_rtr_ki_%=\n\t"
        "\n"
    "L_mc_rtr_kie_%=:\n\t"
        "add	x5, x5, #1\n\t"
        "b	L_mc_rtr_k_%=\n\t"
        "\n"
    "L_mc_rtr_ke_%=:\n\t"
        "cmp	x4, #5\n\t"
        "b.gt	L_mc_rtr_tsk_%=\n\t"
        "mov	x7, #0\n\t"
        "\n"
    "L_mc_rtr_t_%=:\n\t"
        "cmp	x7, #13\n\t"
        "b.ge	L_mc_rtr_te_%=\n\t"
        "lsl	x8, x7, #5\n\t"
        "add	x9, %x[in], x8\n\t"
        "ldp	q0, q1, [x9]\n\t"
        "ushr	v7.2d, v0.2d, #32\n\t"
        "zip1	v7.2d, v8.2d, v7.2d\n\t"
        "eor	v0.16b, v0.16b, v7.16b\n\t"
        "shl	v7.2d, v0.2d, #32\n\t"
        "zip2	v7.2d, v8.2d, v7.2d\n\t"
        "eor	v0.16b, v0.16b, v7.16b\n\t"
        "ushr	v7.2d, v1.2d, #32\n\t"
        "zip1	v7.2d, v8.2d, v7.2d\n\t"
        "eor	v1.16b, v1.16b, v7.16b\n\t"
        "shl	v7.2d, v1.2d, #32\n\t"
        "zip2	v7.2d, v8.2d, v7.2d\n\t"
        "eor	v1.16b, v1.16b, v7.16b\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x7, #1\n\t"
        "b	L_mc_rtr_t_%=\n\t"
        "\n"
    "L_mc_rtr_te_%=:\n\t"
        "\n"
    "L_mc_rtr_tsk_%=:\n\t"
        "mov	x7, #0\n\t"
        "\n"
    "L_mc_rtr_c_%=:\n\t"
        "cmp	x7, #13\n\t"
        "b.ge	L_mc_rtr_ce_%=\n\t"
        "lsl	x8, x7, #5\n\t"
        "add	x9, %x[in], x8\n\t"
        "ldp	q0, q1, [x9]\n\t"
        "zip2	v7.2d, v0.2d, v8.2d\n\t"
        "eor	v1.16b, v1.16b, v7.16b\n\t"
        "zip1	v7.2d, v8.2d, v1.2d\n\t"
        "eor	v1.16b, v1.16b, v7.16b\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x7, x7, #1\n\t"
        "b	L_mc_rtr_c_%=\n\t"
        "\n"
    "L_mc_rtr_ce_%=:\n\t"
        : [in] "+r" (in), [j] "+r" (j)
        : [tm0] "r" (tm0), [tm1] "r" (tm1)
        : "memory", "cc", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11",
            "x12", "x13", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8"
    );
}

WOLFSSL_LOCAL void wc_mceliece_radix_conv_tr_neon(word64* in_p, word64* c_p);
void wc_mceliece_radix_conv_tr_neon(word64* in_p, word64* c_p)
{
    register word64* in __asm__ ("x0") = (word64*)in_p;
    register word64* c __asm__ ("x1") = (word64*)c_p;
    register const word64* L_mc_aff_tmask0_neon_c __asm__ ("x2") = L_mc_aff_tmask0_neon;
    register const word64* L_mc_aff_tmask1_neon_c __asm__ ("x3") = L_mc_aff_tmask1_neon;
    register const word64* L_mc_aff_scal4x_neon_c __asm__ ("x4") = L_mc_aff_scal4x_neon;
    __asm__ __volatile__ (
        "mov	x5, #6\n\t"
        "\n"
    "L_mc_rctr_j_%=:\n\t"
        "cmp	x5, #0\n\t"
        "b.lt	L_mc_rctr_je_%=\n\t"
        "cmp	x5, #6\n\t"
        "b.ge	L_mc_rctr_sk_%=\n\t"
        "mov	x6, #0x1a0\n\t"
        "mul	x6, x5, x6\n\t"
        "add	x6, %[L_mc_aff_scal4x_neon_c], x6\n\t"
        "eor	v10.16b, v10.16b, v10.16b\n\t"
        "mov	x14, %x[c]\n\t"
        "mov	x9, #0\n\t"
        "\n"
    "L_mc_v256_z_rt_%=:\n\t"
        "stp	q10, q10, [x14]\n\t"
        "add	x14, x14, #32\n\t"
        "add	x9, x9, #1\n\t"
        "cmp	x9, #25\n\t"
        "b.lt	L_mc_v256_z_rt_%=\n\t"
        "mov	x7, #0\n\t"
        "\n"
    "L_mc_v256_i_rt_%=:\n\t"
        "cmp	x7, #13\n\t"
        "b.ge	L_mc_v256_rs_rt_%=\n\t"
        "lsl	x15, x7, #5\n\t"
        "add	x10, %x[in], x15\n\t"
        "ldp	q0, q1, [x10]\n\t"
        "mov	x8, #0\n\t"
        "\n"
    "L_mc_v256_j_rt_%=:\n\t"
        "cmp	x8, #13\n\t"
        "b.ge	L_mc_v256_in_rt_%=\n\t"
        "lsl	x15, x8, #5\n\t"
        "add	x11, x6, x15\n\t"
        "ldp	q2, q3, [x11]\n\t"
        "and	v4.16b, v0.16b, v2.16b\n\t"
        "and	v5.16b, v1.16b, v3.16b\n\t"
        "add	x15, x7, x8\n\t"
        "lsl	x15, x15, #5\n\t"
        "add	x12, %x[c], x15\n\t"
        "ldp	q6, q7, [x12]\n\t"
        "eor	v6.16b, v6.16b, v4.16b\n\t"
        "eor	v7.16b, v7.16b, v5.16b\n\t"
        "stp	q6, q7, [x12]\n\t"
        "add	x8, x8, #1\n\t"
        "b	L_mc_v256_j_rt_%=\n\t"
        "\n"
    "L_mc_v256_in_rt_%=:\n\t"
        "add	x7, x7, #1\n\t"
        "b	L_mc_v256_i_rt_%=\n\t"
        "\n"
    "L_mc_v256_rs_rt_%=:\n\t"
        "mov	x9, #24\n\t"
        "\n"
    "L_mc_v256_rk_rt_%=:\n\t"
        "cmp	x9, #13\n\t"
        "b.lt	L_mc_v256_copy_rt_%=\n\t"
        "lsl	x15, x9, #5\n\t"
        "add	x12, %x[c], x15\n\t"
        "ldp	q6, q7, [x12]\n\t"
        "sub	x16, x9, #9\n\t"
        "lsl	x16, x16, #5\n\t"
        "add	x13, %x[c], x16\n\t"
        "ldp	q8, q9, [x13]\n\t"
        "eor	v8.16b, v8.16b, v6.16b\n\t"
        "eor	v9.16b, v9.16b, v7.16b\n\t"
        "stp	q8, q9, [x13]\n\t"
        "sub	x16, x9, #10\n\t"
        "lsl	x16, x16, #5\n\t"
        "add	x13, %x[c], x16\n\t"
        "ldp	q8, q9, [x13]\n\t"
        "eor	v8.16b, v8.16b, v6.16b\n\t"
        "eor	v9.16b, v9.16b, v7.16b\n\t"
        "stp	q8, q9, [x13]\n\t"
        "sub	x16, x9, #12\n\t"
        "lsl	x16, x16, #5\n\t"
        "add	x13, %x[c], x16\n\t"
        "ldp	q8, q9, [x13]\n\t"
        "eor	v8.16b, v8.16b, v6.16b\n\t"
        "eor	v9.16b, v9.16b, v7.16b\n\t"
        "stp	q8, q9, [x13]\n\t"
        "sub	x16, x9, #13\n\t"
        "lsl	x16, x16, #5\n\t"
        "add	x13, %x[c], x16\n\t"
        "ldp	q8, q9, [x13]\n\t"
        "eor	v8.16b, v8.16b, v6.16b\n\t"
        "eor	v9.16b, v9.16b, v7.16b\n\t"
        "stp	q8, q9, [x13]\n\t"
        "sub	x9, x9, #1\n\t"
        "b	L_mc_v256_rk_rt_%=\n\t"
        "\n"
    "L_mc_v256_copy_rt_%=:\n\t"
        "mov	x9, #0\n\t"
        "\n"
    "L_mc_v256_cp_rt_%=:\n\t"
        "cmp	x9, #13\n\t"
        "b.ge	L_mc_v256_done_rt_%=\n\t"
        "lsl	x15, x9, #5\n\t"
        "add	x12, %x[c], x15\n\t"
        "add	x13, %x[in], x15\n\t"
        "ldp	q6, q7, [x12]\n\t"
        "stp	q6, q7, [x13]\n\t"
        "add	x9, x9, #1\n\t"
        "b	L_mc_v256_cp_rt_%=\n\t"
        "\n"
    "L_mc_v256_done_rt_%=:\n\t"
        "\n"
    "L_mc_rctr_sk_%=:\n\t"
        "eor	v8.16b, v8.16b, v8.16b\n\t"
        "mov	x15, #1\n\t"
        "mov	x7, x5\n\t"
        "\n"
    "L_mc_rtr_k_rt_%=:\n\t"
        "cmp	x7, #4\n\t"
        "b.gt	L_mc_rtr_ke_rt_%=\n\t"
        "lsl	x8, x15, x7\n\t"
        "dup	v6.2d, x8\n\t"
        "lsl	x10, x7, #3\n\t"
        "add	x12, %[L_mc_aff_tmask0_neon_c], x10\n\t"
        "ldr	x13, [x12]\n\t"
        "dup	v4.2d, x13\n\t"
        "add	x12, %[L_mc_aff_tmask1_neon_c], x10\n\t"
        "ldr	x14, [x12]\n\t"
        "dup	v5.2d, x14\n\t"
        "mov	x9, #0\n\t"
        "\n"
    "L_mc_rtr_ki_rt_%=:\n\t"
        "cmp	x9, #13\n\t"
        "b.ge	L_mc_rtr_kie_rt_%=\n\t"
        "lsl	x10, x9, #5\n\t"
        "add	x11, %x[in], x10\n\t"
        "ldp	q0, q1, [x11]\n\t"
        "and	v2.16b, v0.16b, v4.16b\n\t"
        "ushl	v2.2d, v2.2d, v6.2d\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "and	v3.16b, v1.16b, v4.16b\n\t"
        "ushl	v3.2d, v3.2d, v6.2d\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "and	v2.16b, v0.16b, v5.16b\n\t"
        "ushl	v2.2d, v2.2d, v6.2d\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "and	v3.16b, v1.16b, v5.16b\n\t"
        "ushl	v3.2d, v3.2d, v6.2d\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "stp	q0, q1, [x11]\n\t"
        "add	x9, x9, #1\n\t"
        "b	L_mc_rtr_ki_rt_%=\n\t"
        "\n"
    "L_mc_rtr_kie_rt_%=:\n\t"
        "add	x7, x7, #1\n\t"
        "b	L_mc_rtr_k_rt_%=\n\t"
        "\n"
    "L_mc_rtr_ke_rt_%=:\n\t"
        "cmp	x5, #5\n\t"
        "b.gt	L_mc_rtr_tsk_rt_%=\n\t"
        "mov	x9, #0\n\t"
        "\n"
    "L_mc_rtr_t_rt_%=:\n\t"
        "cmp	x9, #13\n\t"
        "b.ge	L_mc_rtr_te_rt_%=\n\t"
        "lsl	x10, x9, #5\n\t"
        "add	x11, %x[in], x10\n\t"
        "ldp	q0, q1, [x11]\n\t"
        "ushr	v7.2d, v0.2d, #32\n\t"
        "zip1	v7.2d, v8.2d, v7.2d\n\t"
        "eor	v0.16b, v0.16b, v7.16b\n\t"
        "shl	v7.2d, v0.2d, #32\n\t"
        "zip2	v7.2d, v8.2d, v7.2d\n\t"
        "eor	v0.16b, v0.16b, v7.16b\n\t"
        "ushr	v7.2d, v1.2d, #32\n\t"
        "zip1	v7.2d, v8.2d, v7.2d\n\t"
        "eor	v1.16b, v1.16b, v7.16b\n\t"
        "shl	v7.2d, v1.2d, #32\n\t"
        "zip2	v7.2d, v8.2d, v7.2d\n\t"
        "eor	v1.16b, v1.16b, v7.16b\n\t"
        "stp	q0, q1, [x11]\n\t"
        "add	x9, x9, #1\n\t"
        "b	L_mc_rtr_t_rt_%=\n\t"
        "\n"
    "L_mc_rtr_te_rt_%=:\n\t"
        "\n"
    "L_mc_rtr_tsk_rt_%=:\n\t"
        "mov	x9, #0\n\t"
        "\n"
    "L_mc_rtr_c_rt_%=:\n\t"
        "cmp	x9, #13\n\t"
        "b.ge	L_mc_rtr_ce_rt_%=\n\t"
        "lsl	x10, x9, #5\n\t"
        "add	x11, %x[in], x10\n\t"
        "ldp	q0, q1, [x11]\n\t"
        "zip2	v7.2d, v0.2d, v8.2d\n\t"
        "eor	v1.16b, v1.16b, v7.16b\n\t"
        "zip1	v7.2d, v8.2d, v1.2d\n\t"
        "eor	v1.16b, v1.16b, v7.16b\n\t"
        "stp	q0, q1, [x11]\n\t"
        "add	x9, x9, #1\n\t"
        "b	L_mc_rtr_c_rt_%=\n\t"
        "\n"
    "L_mc_rtr_ce_rt_%=:\n\t"
        "sub	x5, x5, #1\n\t"
        "b	L_mc_rctr_j_%=\n\t"
        "\n"
    "L_mc_rctr_je_%=:\n\t"
        : [in] "+r" (in), [c] "+r" (c)
        : [L_mc_aff_tmask0_neon_c] "r" (L_mc_aff_tmask0_neon_c),
          [L_mc_aff_tmask1_neon_c] "r" (L_mc_aff_tmask1_neon_c),
          [L_mc_aff_scal4x_neon_c] "r" (L_mc_aff_scal4x_neon_c)
        : "memory", "cc", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12",
            "x13", "x14", "x15", "x16", "v0", "v1", "v2", "v3", "v4", "v5",
            "v6", "v7", "v8", "v9", "v10"
    );
}

WOLFSSL_LOCAL void wc_mceliece_aff_btr_in_neon(word64* buf_p,
    const word64* in_p, const byte* rev_p, int i_p);
void wc_mceliece_aff_btr_in_neon(word64* buf_p, const word64* in_p,
    const byte* rev_p, int i_p)
{
    register word64* buf __asm__ ("x0") = (word64*)buf_p;
    register const word64* in __asm__ ("x1") = (const word64*)in_p;
    register const byte* rev __asm__ ("x2") = (const byte*)rev_p;
    register int i __asm__ ("w3") = (int)i_p;
    __asm__ __volatile__ (
        "mov	w4, %w[i]\n\t"
        "mov	x13, #13\n\t"
        "mov	x5, #0\n\t"
        "\n"
    "L_mc_bti_k_%=:\n\t"
        "cmp	x5, #32\n\t"
        "b.ge	L_mc_bti_e_%=\n\t"
        "lsl	x8, x5, #1\n\t"
        "add	x9, %x[rev], x8\n\t"
        "ldrb	w6, [x9]\n\t"
        "add	x9, x9, #1\n\t"
        "ldrb	w7, [x9]\n\t"
        "lsl	x8, x6, #5\n\t"
        "add	x10, %x[buf], x8\n\t"
        "lsl	x8, x7, #5\n\t"
        "add	x11, %x[buf], x8\n\t"
        "madd	x8, x5, x13, x4\n\t"
        "lsl	x8, x8, #5\n\t"
        "add	x12, %x[in], x8\n\t"
        "ldp	q0, q1, [x12]\n\t"
        "str	q0, [x10]\n\t"
        "str	q1, [x11]\n\t"
        "cmp	x4, #12\n\t"
        "b.eq	L_mc_bti_no_%=\n\t"
        "add	x12, x12, #32\n\t"
        "ldp	q2, q3, [x12]\n\t"
        "add	x9, x10, #16\n\t"
        "str	q2, [x9]\n\t"
        "add	x9, x11, #16\n\t"
        "str	q3, [x9]\n\t"
        "\n"
    "L_mc_bti_no_%=:\n\t"
        "add	x5, x5, #1\n\t"
        "b	L_mc_bti_k_%=\n\t"
        "\n"
    "L_mc_bti_e_%=:\n\t"
        : [buf] "+r" (buf), [i] "+r" (i)
        : [in] "r" (in), [rev] "r" (rev)
        : "memory", "cc", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11",
            "x12", "x13", "v0", "v1", "v2", "v3"
    );
}

WOLFSSL_LOCAL void wc_mceliece_aff_synd_mask_neon(word64* scaled_p,
    const word64* einvbs_p, const byte* fieldmask_p);
void wc_mceliece_aff_synd_mask_neon(word64* scaled_p, const word64* einvbs_p,
    const byte* fieldmask_p)
{
    register word64* scaled __asm__ ("x0") = (word64*)scaled_p;
    register const word64* einvbs __asm__ ("x1") = (const word64*)einvbs_p;
    register const byte* fieldmask __asm__ ("x2") = (const byte*)fieldmask_p;
    __asm__ __volatile__ (
        "mov	x9, #13\n\t"
        "mov	x3, #0\n\t"
        "\n"
    "L_mc_sm_i_%=:\n\t"
        "cmp	x3, #32\n\t"
        "b.ge	L_mc_sm_ie_%=\n\t"
        "lsl	x5, x3, #5\n\t"
        "add	x6, %x[fieldmask], x5\n\t"
        "ldp	q0, q1, [x6]\n\t"
        "mov	x4, #0\n\t"
        "\n"
    "L_mc_sm_k_%=:\n\t"
        "cmp	x4, #13\n\t"
        "b.ge	L_mc_sm_ke_%=\n\t"
        "madd	x5, x3, x9, x4\n\t"
        "lsl	x5, x5, #5\n\t"
        "add	x7, %x[einvbs], x5\n\t"
        "ldp	q2, q3, [x7]\n\t"
        "and	v2.16b, v2.16b, v0.16b\n\t"
        "and	v3.16b, v3.16b, v1.16b\n\t"
        "add	x8, %x[scaled], x5\n\t"
        "stp	q2, q3, [x8]\n\t"
        "add	x4, x4, #1\n\t"
        "b	L_mc_sm_k_%=\n\t"
        "\n"
    "L_mc_sm_ke_%=:\n\t"
        "add	x3, x3, #1\n\t"
        "b	L_mc_sm_i_%=\n\t"
        "\n"
    "L_mc_sm_ie_%=:\n\t"
        : [scaled] "+r" (scaled)
        : [einvbs] "r" (einvbs), [fieldmask] "r" (fieldmask)
        : "memory", "cc", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "v0", "v1",
            "v2", "v3"
    );
}

#endif /* WOLFSSL_MCELIECE_NO_DECAPSULATE */
#endif /* WOLFSSL_MCELIECE_SMALL */
#endif /* !WOLFSSL_MCELIECE_NO_MAKE_KEY || !WOLFSSL_MCELIECE_NO_DECAPSULATE */
#ifndef WOLFSSL_MCELIECE_NO_MAKE_KEY
#ifndef WOLFSSL_MCELIECE_SMALL
WOLFSSL_LOCAL void wc_mceliece_u64_minmax_vec_neon(word64* a_p, word64* b_p,
    int count_p);
void wc_mceliece_u64_minmax_vec_neon(word64* a_p, word64* b_p, int count_p)
{
    register word64* a __asm__ ("x0") = (word64*)a_p;
    register word64* b __asm__ ("x1") = (word64*)b_p;
    register int count __asm__ ("w2") = (int)count_p;
    __asm__ __volatile__ (
        "mov	w4, %w[count]\n\t"
        "lsr	x4, x4, #1\n\t"
        "lsl	x4, x4, #1\n\t"
        "mov	x3, #0\n\t"
        "\n"
    "L_mc_mmv_%=:\n\t"
        "cmp	x3, x4\n\t"
        "b.ge	L_mc_mmve_%=\n\t"
        "ldr	q0, [%x[a]]\n\t"
        "ldr	q1, [%x[b]]\n\t"
        "sub	v2.2d, v1.2d, v0.2d\n\t"
        "sshr	v2.2d, v2.2d, #63\n\t"
        "eor	v3.16b, v0.16b, v1.16b\n\t"
        "and	v3.16b, v3.16b, v2.16b\n\t"
        "eor	v0.16b, v0.16b, v3.16b\n\t"
        "eor	v1.16b, v1.16b, v3.16b\n\t"
        "str	q0, [%x[a]]\n\t"
        "str	q1, [%x[b]]\n\t"
        "add	%x[a], %x[a], #16\n\t"
        "add	%x[b], %x[b], #16\n\t"
        "add	x3, x3, #2\n\t"
        "b	L_mc_mmv_%=\n\t"
        "\n"
    "L_mc_mmve_%=:\n\t"
        "\n"
    "L_mc_mmvt_%=:\n\t"
        "cmp	w3, %w[count]\n\t"
        "b.ge	L_mc_mmvte_%=\n\t"
        "ldr	x7, [%x[a]]\n\t"
        "ldr	x8, [%x[b]]\n\t"
        "sub	x9, x8, x7\n\t"
        "lsr	x9, x9, #63\n\t"
        "neg	x9, x9\n\t"
        "eor	x10, x7, x8\n\t"
        "and	x10, x10, x9\n\t"
        "eor	x7, x7, x10\n\t"
        "eor	x8, x8, x10\n\t"
        "str	x7, [%x[a]]\n\t"
        "str	x8, [%x[b]]\n\t"
        "add	%x[a], %x[a], #8\n\t"
        "add	%x[b], %x[b], #8\n\t"
        "add	x3, x3, #1\n\t"
        "b	L_mc_mmvt_%=\n\t"
        "\n"
    "L_mc_mmvte_%=:\n\t"
        : [a] "+r" (a), [b] "+r" (b), [count] "+r" (count)
        :
        : "memory", "cc", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "v0",
            "v1", "v2", "v3"
    );
}

WOLFSSL_LOCAL void wc_mceliece_pk_gen_cswap_neon(word64* mat_p, sword16* ind_p,
    int row_p, int mt_p, int nbiW_p, int iBlk_p, int jBit_p);
void wc_mceliece_pk_gen_cswap_neon(word64* mat_p, sword16* ind_p, int row_p,
    int mt_p, int nbiW_p, int iBlk_p, int jBit_p)
{
    register word64* mat __asm__ ("x0") = (word64*)mat_p;
    register sword16* ind __asm__ ("x1") = (sword16*)ind_p;
    register int row __asm__ ("w2") = (int)row_p;
    register int mt __asm__ ("w3") = (int)mt_p;
    register int nbiW __asm__ ("w4") = (int)nbiW_p;
    register int iBlk __asm__ ("w5") = (int)iBlk_p;
    register int jBit __asm__ ("w6") = (int)jBit_p;
    __asm__ __volatile__ (
        "mov	w7, %w[nbiW]\n\t"
        "mov	w8, %w[mt]\n\t"
        "mov	w9, %w[jBit]\n\t"
        "mov	w10, %w[row]\n\t"
        "mov	w16, %w[iBlk]\n\t"
        "lsl	x16, x16, #3\n\t"
        "mul	x15, x10, x7\n\t"
        "lsl	x15, x15, #3\n\t"
        "add	x11, %x[mat], x15\n\t"
        "lsl	x15, x10, #1\n\t"
        "add	x23, %x[ind], x15\n\t"
        "ldrh	w22, [x23]\n\t"
        "add	x12, x10, #1\n\t"
        "\n"
    "L_mc_pkc_kk_%=:\n\t"
        "cmp	x12, x8\n\t"
        "b.ge	L_mc_pkc_kke_%=\n\t"
        "mul	x15, x12, x7\n\t"
        "lsl	x15, x15, #3\n\t"
        "add	x13, %x[mat], x15\n\t"
        "add	x28, x11, x16\n\t"
        "ldr	x21, [x28]\n\t"
        "lsr	x17, x21, x9\n\t"
        "and	x17, x17, #1\n\t"
        "add	x27, x13, x16\n\t"
        "ldr	x21, [x27]\n\t"
        "lsr	x19, x21, x9\n\t"
        "and	x19, x19, #1\n\t"
        "eor	x17, x17, #1\n\t"
        "and	x20, x19, x17\n\t"
        "neg	x20, x20\n\t"
        "dup	v6.2d, x20\n\t"
        "lsl	x15, x12, #1\n\t"
        "add	x24, %x[ind], x15\n\t"
        "ldrh	w25, [x24]\n\t"
        "eor	x26, x22, x25\n\t"
        "and	x26, x26, x20\n\t"
        "eor	x22, x22, x26\n\t"
        "eor	x25, x25, x26\n\t"
        "strh	w25, [x24]\n\t"
        "mov	x14, #0\n\t"
        "\n"
    "L_mc_pkc_c_%=:\n\t"
        "cmp	x14, x7\n\t"
        "b.ge	L_mc_pkc_ce_%=\n\t"
        "lsl	x15, x14, #3\n\t"
        "add	x28, x11, x15\n\t"
        "ldp	q0, q1, [x28]\n\t"
        "add	x27, x13, x15\n\t"
        "ldp	q2, q3, [x27]\n\t"
        "eor	v4.16b, v0.16b, v2.16b\n\t"
        "eor	v5.16b, v1.16b, v3.16b\n\t"
        "and	v4.16b, v4.16b, v6.16b\n\t"
        "and	v5.16b, v5.16b, v6.16b\n\t"
        "eor	v0.16b, v0.16b, v4.16b\n\t"
        "eor	v1.16b, v1.16b, v5.16b\n\t"
        "stp	q0, q1, [x28]\n\t"
        "eor	v2.16b, v2.16b, v4.16b\n\t"
        "eor	v3.16b, v3.16b, v5.16b\n\t"
        "stp	q2, q3, [x27]\n\t"
        "add	x14, x14, #4\n\t"
        "b	L_mc_pkc_c_%=\n\t"
        "\n"
    "L_mc_pkc_ce_%=:\n\t"
        "add	x12, x12, #1\n\t"
        "b	L_mc_pkc_kk_%=\n\t"
        "\n"
    "L_mc_pkc_kke_%=:\n\t"
        "strh	w22, [x23]\n\t"
        : [mat] "+r" (mat), [ind] "+r" (ind), [row] "+r" (row), [mt] "+r" (mt),
          [nbiW] "+r" (nbiW), [iBlk] "+r" (iBlk), [jBit] "+r" (jBit)
        :
        : "memory", "cc", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14",
            "x15", "x16", "x17", "x19", "x20", "x21", "x22", "x23", "x24",
            "x25", "x26", "x27", "x28", "v0", "v1", "v2", "v3", "v4", "v5",
            "v6"
    );
}

WOLFSSL_LOCAL void wc_mceliece_pk_gen_elim_neon(word64* mat_p, int row_p,
    int mt_p, int nbiW_p, int iBlk_p, int jBit_p);
void wc_mceliece_pk_gen_elim_neon(word64* mat_p, int row_p, int mt_p,
    int nbiW_p, int iBlk_p, int jBit_p)
{
    register word64* mat __asm__ ("x0") = (word64*)mat_p;
    register int row __asm__ ("w1") = (int)row_p;
    register int mt __asm__ ("w2") = (int)mt_p;
    register int nbiW __asm__ ("w3") = (int)nbiW_p;
    register int iBlk __asm__ ("w4") = (int)iBlk_p;
    register int jBit __asm__ ("w5") = (int)jBit_p;
    __asm__ __volatile__ (
        "mov	w6, %w[nbiW]\n\t"
        "mov	w7, %w[mt]\n\t"
        "mov	w8, %w[jBit]\n\t"
        "mov	w9, %w[row]\n\t"
        "mov	x21, #1\n\t"
        "mov	w15, %w[iBlk]\n\t"
        "lsl	x15, x15, #3\n\t"
        "mul	x14, x9, x6\n\t"
        "lsl	x14, x14, #3\n\t"
        "add	x10, %x[mat], x14\n\t"
        "add	x11, x9, #1\n\t"
        "\n"
    "L_mc_pke_kk_%=:\n\t"
        "cmp	x11, x7\n\t"
        "b.ge	L_mc_pke_kke_%=\n\t"
        "mul	x14, x11, x6\n\t"
        "lsl	x14, x14, #3\n\t"
        "add	x12, %x[mat], x14\n\t"
        "add	x22, x12, x15\n\t"
        "ldr	x16, [x22]\n\t"
        "lsr	x17, x16, x8\n\t"
        "and	x17, x17, #1\n\t"
        "neg	x20, x17\n\t"
        "dup	v6.2d, x20\n\t"
        "lsl	x19, x21, x8\n\t"
        "and	x19, x16, x19\n\t"
        "mov	x13, #0\n\t"
        "\n"
    "L_mc_pke_c_%=:\n\t"
        "cmp	x13, x6\n\t"
        "b.ge	L_mc_pke_ce_%=\n\t"
        "lsl	x14, x13, #3\n\t"
        "add	x23, x10, x14\n\t"
        "ldp	q2, q3, [x23]\n\t"
        "add	x22, x12, x14\n\t"
        "ldp	q0, q1, [x22]\n\t"
        "and	v4.16b, v2.16b, v6.16b\n\t"
        "and	v5.16b, v3.16b, v6.16b\n\t"
        "eor	v0.16b, v0.16b, v4.16b\n\t"
        "eor	v1.16b, v1.16b, v5.16b\n\t"
        "stp	q0, q1, [x22]\n\t"
        "add	x13, x13, #4\n\t"
        "b	L_mc_pke_c_%=\n\t"
        "\n"
    "L_mc_pke_ce_%=:\n\t"
        "add	x22, x12, x15\n\t"
        "ldr	x16, [x22]\n\t"
        "orr	x16, x16, x19\n\t"
        "str	x16, [x22]\n\t"
        "add	x11, x11, #1\n\t"
        "b	L_mc_pke_kk_%=\n\t"
        "\n"
    "L_mc_pke_kke_%=:\n\t"
        : [mat] "+r" (mat), [row] "+r" (row), [mt] "+r" (mt),
          [nbiW] "+r" (nbiW), [iBlk] "+r" (iBlk), [jBit] "+r" (jBit)
        :
        : "memory", "cc", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13",
            "x14", "x15", "x16", "x17", "x19", "x20", "x21", "x22", "x23", "v0",
            "v1", "v2", "v3", "v4", "v5", "v6"
    );
}

WOLFSSL_LOCAL int wc_mceliece_bs_pk_gen_reduce_neon(word64* mat_p,
    sword16* ind_p, int mt_p, int nbiW_p, int isf_p, sword16* pi_p,
    word64* pivots_p);
int wc_mceliece_bs_pk_gen_reduce_neon(word64* mat_p, sword16* ind_p, int mt_p,
    int nbiW_p, int isf_p, sword16* pi_p, word64* pivots_p)
{
    register word64* mat __asm__ ("x0") = (word64*)mat_p;
    register sword16* ind __asm__ ("x1") = (sword16*)ind_p;
    register int mt __asm__ ("w2") = (int)mt_p;
    register int nbiW __asm__ ("w3") = (int)nbiW_p;
    register int isf __asm__ ("w4") = (int)isf_p;
    register sword16* pi __asm__ ("x5") = (sword16*)pi_p;
    register word64* pivots __asm__ ("x6") = (word64*)pivots_p;
    __asm__ __volatile__ (
        "mov	x19, %x[mat]\n\t"
        "mov	x20, %x[ind]\n\t"
        "mov	w21, %w[mt]\n\t"
        "mov	w22, %w[nbiW]\n\t"
        "mov	w23, %w[isf]\n\t"
        "mov	x24, %x[pi]\n\t"
        "mov	x25, %x[pivots]\n\t"
        "mov	x26, #0\n\t"
        "\n"
    "L_mc_pgr_r_%=:\n\t"
        "cmp	x26, x21\n\t"
        "b.ge	L_mc_pgr_re_%=\n\t"
        "cbz	w23, L_mc_pgr_sk_%=\n\t"
        "sub	x11, x21, #32\n\t"
        "cmp	x26, x11\n\t"
        "b.ne	L_mc_pgr_sk_%=\n\t"
        "mov	%x[mat], x19\n\t"
        "mov	%w[ind], w22\n\t"
        "mov	%w[mt], w21\n\t"
        "mov	%x[nbiW], x24\n\t"
        "mov	%x[isf], x25\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_bs_mov_columns_neon\n\t"
#else
        "bl	_wc_mceliece_bs_mov_columns_neon\n\t"
#endif /* __APPLE__ */
        "cmp	%w[mat], #0\n\t"
        "b.ne	L_mc_pgr_f_%=\n\t"
        "\n"
    "L_mc_pgr_sk_%=:\n\t"
        "lsr	x7, x26, #6\n\t"
        "and	x8, x26, #63\n\t"
        "mov	%x[mat], x19\n\t"
        "mov	%x[ind], x20\n\t"
        "mov	%w[mt], w26\n\t"
        "mov	%w[nbiW], w21\n\t"
        "mov	%w[isf], w22\n\t"
        "mov	%w[pi], w7\n\t"
        "mov	%w[pivots], w8\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_pk_gen_cswap_neon\n\t"
#else
        "bl	_wc_mceliece_pk_gen_cswap_neon\n\t"
#endif /* __APPLE__ */
        "lsr	x7, x26, #6\n\t"
        "and	x8, x26, #63\n\t"
        "mul	x9, x26, x22\n\t"
        "add	x9, x9, x7\n\t"
        "lsl	x9, x9, #3\n\t"
        "add	x10, x19, x9\n\t"
        "ldr	x11, [x10]\n\t"
        "lsr	x11, x11, x8\n\t"
        "and	x11, x11, #1\n\t"
        "cbz	x11, L_mc_pgr_f_%=\n\t"
        "mov	%x[mat], x19\n\t"
        "mov	%w[ind], w26\n\t"
        "mov	%w[mt], w21\n\t"
        "mov	%w[nbiW], w22\n\t"
        "mov	%w[isf], w7\n\t"
        "mov	%w[pi], w8\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_pk_gen_elim_neon\n\t"
#else
        "bl	_wc_mceliece_pk_gen_elim_neon\n\t"
#endif /* __APPLE__ */
        "add	x26, x26, #1\n\t"
        "b	L_mc_pgr_r_%=\n\t"
        "\n"
    "L_mc_pgr_re_%=:\n\t"
        "mov	%w[mat], #0\n\t"
        "b	L_mc_pgr_e_%=\n\t"
        "\n"
    "L_mc_pgr_f_%=:\n\t"
        "mov	%w[mat], #0\n\t"
        "sub	%w[mat], %w[mat], #1\n\t"
        "\n"
    "L_mc_pgr_e_%=:\n\t"
        : [mat] "+r" (mat), [ind] "+r" (ind), [mt] "+r" (mt),
          [nbiW] "+r" (nbiW), [isf] "+r" (isf), [pi] "+r" (pi),
          [pivots] "+r" (pivots)
        :
        : "memory", "cc", "x19", "x20", "x21", "x22", "x23", "x24", "x25",
            "x26", "x7", "x8", "x9", "x10", "x11", "x30"
    );
    return (word32)(size_t)mat;
}

WOLFSSL_LOCAL void wc_mceliece_bs_lu_fill_neon(word64* mat_p, word64* prod_p,
    const word64* consts_p, int t_p, int m_p, int nbi_p, int nbiW_p,
    word64* cscr_p);
void wc_mceliece_bs_lu_fill_neon(word64* mat_p, word64* prod_p,
    const word64* consts_p, int t_p, int m_p, int nbi_p, int nbiW_p,
    word64* cscr_p)
{
    register word64* mat __asm__ ("x0") = (word64*)mat_p;
    register word64* prod __asm__ ("x1") = (word64*)prod_p;
    register const word64* consts __asm__ ("x2") = (const word64*)consts_p;
    register int t __asm__ ("w3") = (int)t_p;
    register int m __asm__ ("w4") = (int)m_p;
    register int nbi __asm__ ("w5") = (int)nbi_p;
    register int nbiW __asm__ ("w6") = (int)nbiW_p;
    register word64* cscr __asm__ ("x7") = (word64*)cscr_p;
    __asm__ __volatile__ (
        "mov	x19, %x[mat]\n\t"
        "mov	x20, %x[prod]\n\t"
        "mov	x21, %x[consts]\n\t"
        "mov	w23, %w[t]\n\t"
        "mov	w24, %w[m]\n\t"
        "mov	w25, %w[nbi]\n\t"
        "mov	w26, %w[nbiW]\n\t"
        "mov	x22, %x[cscr]\n\t"
        "mov	x27, #0\n\t"
        "\n"
    "L_mc_luf_i_%=:\n\t"
        "cmp	x27, x23\n\t"
        "b.ge	L_mc_luf_ie_%=\n\t"
        "mov	x28, #0\n\t"
        "\n"
    "L_mc_luf_j_%=:\n\t"
        "cmp	x28, x25\n\t"
        "b.ge	L_mc_luf_je_%=\n\t"
        "cbz	x27, L_mc_luf_nm_%=\n\t"
        "mul	x8, x28, x24\n\t"
        "lsl	x8, x8, #2\n\t"
        "lsl	x8, x8, #3\n\t"
        "add	%x[mat], x20, x8\n\t"
        "mov	%x[prod], %x[mat]\n\t"
        "add	%x[consts], x21, x8\n\t"
        "mov	%x[t], x22\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_v256_mul_neon\n\t"
#else
        "bl	_wc_mceliece_aff_v256_mul_neon\n\t"
#endif /* __APPLE__ */
        "\n"
    "L_mc_luf_nm_%=:\n\t"
        "mul	x8, x27, x24\n\t"
        "mul	x8, x8, x26\n\t"
        "lsl	x13, x28, #2\n\t"
        "add	x8, x8, x13\n\t"
        "lsl	x8, x8, #3\n\t"
        "add	x9, x19, x8\n\t"
        "mul	x8, x28, x24\n\t"
        "lsl	x8, x8, #2\n\t"
        "lsl	x8, x8, #3\n\t"
        "add	x10, x20, x8\n\t"
        "lsl	x11, x26, #3\n\t"
        "mov	x12, x24\n\t"
        "\n"
    "L_mc_luf_kk_%=:\n\t"
        "ldp	q0, q1, [x10]\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x10, x10, #32\n\t"
        "add	x9, x9, x11\n\t"
        "subs	x12, x12, #1\n\t"
        "b.ne	L_mc_luf_kk_%=\n\t"
        "add	x28, x28, #1\n\t"
        "b	L_mc_luf_j_%=\n\t"
        "\n"
    "L_mc_luf_je_%=:\n\t"
        "add	x27, x27, #1\n\t"
        "b	L_mc_luf_i_%=\n\t"
        "\n"
    "L_mc_luf_ie_%=:\n\t"
        : [mat] "+r" (mat), [prod] "+r" (prod), [t] "+r" (t), [m] "+r" (m),
          [nbi] "+r" (nbi), [nbiW] "+r" (nbiW), [cscr] "+r" (cscr)
        : [consts] "r" (consts)
        : "memory", "cc", "x19", "x20", "x21", "x22", "x23", "x24", "x25",
            "x26", "x27", "x28", "x8", "x9", "x10", "x11", "x12", "x13", "x14",
            "x15", "x16", "v0", "v1", "x30"
    );
}

WOLFSSL_LOCAL void wc_mceliece_bs_par_fill_neon(word64* par_p, word64* prod_p,
    const word64* consts_p, int t_p, int m_p, int parW_p, int nvalid_p,
    word64* cscr_p);
void wc_mceliece_bs_par_fill_neon(word64* par_p, word64* prod_p,
    const word64* consts_p, int t_p, int m_p, int parW_p, int nvalid_p,
    word64* cscr_p)
{
    register word64* par __asm__ ("x0") = (word64*)par_p;
    register word64* prod __asm__ ("x1") = (word64*)prod_p;
    register const word64* consts __asm__ ("x2") = (const word64*)consts_p;
    register int t __asm__ ("w3") = (int)t_p;
    register int m __asm__ ("w4") = (int)m_p;
    register int parW __asm__ ("w5") = (int)parW_p;
    register int nvalid __asm__ ("w6") = (int)nvalid_p;
    register word64* cscr __asm__ ("x7") = (word64*)cscr_p;
    __asm__ __volatile__ (
        "mov	x19, %x[par]\n\t"
        "mov	x20, %x[prod]\n\t"
        "mov	x21, %x[consts]\n\t"
        "mov	w23, %w[t]\n\t"
        "mov	w24, %w[m]\n\t"
        "mov	w25, %w[parW]\n\t"
        "mov	w26, %w[nvalid]\n\t"
        "mov	x22, %x[cscr]\n\t"
        "mov	x27, #0\n\t"
        "\n"
    "L_mc_prf_i_%=:\n\t"
        "cmp	x27, x23\n\t"
        "b.ge	L_mc_prf_ie_%=\n\t"
        "mov	x28, #0\n\t"
        "\n"
    "L_mc_prf_b_%=:\n\t"
        "cmp	x28, x25\n\t"
        "b.ge	L_mc_prf_be_%=\n\t"
        "cmp	x28, x26\n\t"
        "b.ge	L_mc_prf_sk_%=\n\t"
        "mul	x8, x28, x24\n\t"
        "lsl	x8, x8, #2\n\t"
        "lsl	x8, x8, #3\n\t"
        "cbz	x27, L_mc_prf_nm_%=\n\t"
        "add	%x[par], x20, x8\n\t"
        "mov	%x[prod], %x[par]\n\t"
        "add	%x[consts], x21, x8\n\t"
        "mov	%x[t], x22\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_aff_v256_mul_neon\n\t"
#else
        "bl	_wc_mceliece_aff_v256_mul_neon\n\t"
#endif /* __APPLE__ */
        "\n"
    "L_mc_prf_nm_%=:\n\t"
        "mul	x8, x28, x24\n\t"
        "lsl	x8, x8, #2\n\t"
        "lsl	x8, x8, #3\n\t"
        "add	x10, x20, x8\n\t"
        "lsl	x11, x25, #2\n\t"
        "mul	x8, x27, x24\n\t"
        "mul	x8, x8, x11\n\t"
        "lsl	x13, x28, #2\n\t"
        "add	x8, x8, x13\n\t"
        "lsl	x8, x8, #3\n\t"
        "add	x9, x19, x8\n\t"
        "lsl	x11, x11, #3\n\t"
        "mov	x12, x24\n\t"
        "\n"
    "L_mc_prf_kk_%=:\n\t"
        "ldp	q0, q1, [x10]\n\t"
        "stp	q0, q1, [x9]\n\t"
        "add	x10, x10, #32\n\t"
        "add	x9, x9, x11\n\t"
        "subs	x12, x12, #1\n\t"
        "b.ne	L_mc_prf_kk_%=\n\t"
        "\n"
    "L_mc_prf_sk_%=:\n\t"
        "add	x28, x28, #1\n\t"
        "b	L_mc_prf_b_%=\n\t"
        "\n"
    "L_mc_prf_be_%=:\n\t"
        "add	x27, x27, #1\n\t"
        "b	L_mc_prf_i_%=\n\t"
        "\n"
    "L_mc_prf_ie_%=:\n\t"
        : [par] "+r" (par), [prod] "+r" (prod), [t] "+r" (t), [m] "+r" (m),
          [parW] "+r" (parW), [nvalid] "+r" (nvalid), [cscr] "+r" (cscr)
        : [consts] "r" (consts)
        : "memory", "cc", "x19", "x20", "x21", "x22", "x23", "x24", "x25",
            "x26", "x27", "x28", "x8", "x9", "x10", "x11", "x12", "x13", "x14",
            "x15", "x16", "v0", "v1", "x30"
    );
}

WOLFSSL_LOCAL void wc_mceliece_bs_tri_neon(word64* par_p,
    const word64* matRow_p, int row_p, int parW4_p, int iLo_p, int iHi_p);
void wc_mceliece_bs_tri_neon(word64* par_p, const word64* matRow_p, int row_p,
    int parW4_p, int iLo_p, int iHi_p)
{
    register word64* par __asm__ ("x0") = (word64*)par_p;
    register const word64* matRow __asm__ ("x1") = (const word64*)matRow_p;
    register int row __asm__ ("w2") = (int)row_p;
    register int parW4 __asm__ ("w3") = (int)parW4_p;
    register int iLo __asm__ ("w4") = (int)iLo_p;
    register int iHi __asm__ ("w5") = (int)iHi_p;
    __asm__ __volatile__ (
        "mov	w6, %w[parW4]\n\t"
        "mov	w7, %w[iHi]\n\t"
        "mov	w9, %w[iLo]\n\t"
        "mov	w12, %w[row]\n\t"
        "mul	x12, x12, x6\n\t"
        "lsl	x12, x12, #3\n\t"
        "add	x8, %x[par], x12\n\t"
        "\n"
    "L_mc_tri_i_%=:\n\t"
        "cmp	x9, x7\n\t"
        "b.ge	L_mc_tri_ie_%=\n\t"
        "lsr	x13, x9, #6\n\t"
        "lsl	x13, x13, #3\n\t"
        "add	x17, %x[matRow], x13\n\t"
        "ldr	x15, [x17]\n\t"
        "and	x14, x9, #63\n\t"
        "lsr	x15, x15, x14\n\t"
        "and	x15, x15, #1\n\t"
        "neg	x16, x15\n\t"
        "dup	v3.2d, x16\n\t"
        "mul	x12, x9, x6\n\t"
        "lsl	x12, x12, #3\n\t"
        "add	x10, %x[par], x12\n\t"
        "mov	x11, #0\n\t"
        "\n"
    "L_mc_tri_c_%=:\n\t"
        "cmp	x11, x6\n\t"
        "b.ge	L_mc_tri_ce_%=\n\t"
        "lsl	x12, x11, #3\n\t"
        "add	x17, x8, x12\n\t"
        "ldr	q0, [x17]\n\t"
        "add	x19, x10, x12\n\t"
        "ldr	q1, [x19]\n\t"
        "and	v2.16b, v1.16b, v3.16b\n\t"
        "eor	v0.16b, v0.16b, v2.16b\n\t"
        "str	q0, [x17]\n\t"
        "add	x11, x11, #2\n\t"
        "b	L_mc_tri_c_%=\n\t"
        "\n"
    "L_mc_tri_ce_%=:\n\t"
        "add	x9, x9, #1\n\t"
        "b	L_mc_tri_i_%=\n\t"
        "\n"
    "L_mc_tri_ie_%=:\n\t"
        : [par] "+r" (par), [row] "+r" (row), [parW4] "+r" (parW4),
          [iLo] "+r" (iLo), [iHi] "+r" (iHi)
        : [matRow] "r" (matRow)
        : "memory", "cc", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13",
            "x14", "x15", "x16", "x17", "x19", "v0", "v1", "v2", "v3"
    );
}

WOLFSSL_LOCAL void wc_mceliece_bs_minmax_rows_neon(sword16* x_p, word64* mat_p,
    int parWidth_p, int i0_p, int i1_p);
void wc_mceliece_bs_minmax_rows_neon(sword16* x_p, word64* mat_p,
    int parWidth_p, int i0_p, int i1_p)
{
    register sword16* x __asm__ ("x0") = (sword16*)x_p;
    register word64* mat __asm__ ("x1") = (word64*)mat_p;
    register int parWidth __asm__ ("w2") = (int)parWidth_p;
    register int i0 __asm__ ("w3") = (int)i0_p;
    register int i1 __asm__ ("w4") = (int)i1_p;
    __asm__ __volatile__ (
        "mov	w5, %w[parWidth]\n\t"
        "lsl	x5, x5, #2\n\t"
        "mov	w6, %w[i0]\n\t"
        "mov	w7, %w[i1]\n\t"
        "lsl	x19, x6, #1\n\t"
        "add	x8, %x[x], x19\n\t"
        "ldrh	w10, [x8]\n\t"
        "lsl	x19, x7, #1\n\t"
        "add	x9, %x[x], x19\n\t"
        "ldrh	w11, [x9]\n\t"
        "sub	x12, x11, x10\n\t"
        "asr	x13, x12, #63\n\t"
        "dup	v6.2d, x13\n\t"
        "eor	x14, x10, x11\n\t"
        "and	x14, x14, x13\n\t"
        "eor	x10, x10, x14\n\t"
        "strh	w10, [x8]\n\t"
        "eor	x11, x11, x14\n\t"
        "strh	w11, [x9]\n\t"
        "mul	x19, x6, x5\n\t"
        "lsl	x19, x19, #3\n\t"
        "add	x15, %x[mat], x19\n\t"
        "mul	x19, x7, x5\n\t"
        "lsl	x19, x19, #3\n\t"
        "add	x16, %x[mat], x19\n\t"
        "mov	x17, #0\n\t"
        "\n"
    "L_mc_mmr_c_%=:\n\t"
        "cmp	x17, x5\n\t"
        "b.ge	L_mc_mmr_ce_%=\n\t"
        "ldp	q0, q1, [x15]\n\t"
        "ldp	q2, q3, [x16]\n\t"
        "eor	v4.16b, v0.16b, v2.16b\n\t"
        "eor	v5.16b, v1.16b, v3.16b\n\t"
        "and	v4.16b, v4.16b, v6.16b\n\t"
        "and	v5.16b, v5.16b, v6.16b\n\t"
        "eor	v0.16b, v0.16b, v4.16b\n\t"
        "eor	v1.16b, v1.16b, v5.16b\n\t"
        "stp	q0, q1, [x15]\n\t"
        "eor	v2.16b, v2.16b, v4.16b\n\t"
        "eor	v3.16b, v3.16b, v5.16b\n\t"
        "stp	q2, q3, [x16]\n\t"
        "add	x15, x15, #32\n\t"
        "add	x16, x16, #32\n\t"
        "add	x17, x17, #4\n\t"
        "b	L_mc_mmr_c_%=\n\t"
        "\n"
    "L_mc_mmr_ce_%=:\n\t"
        : [x] "+r" (x), [mat] "+r" (mat), [parWidth] "+r" (parWidth),
          [i0] "+r" (i0), [i1] "+r" (i1)
        :
        : "memory", "cc", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12",
            "x13", "x14", "x15", "x16", "x17", "x19", "x20", "x21", "v0", "v1",
            "v2", "v3", "v4", "v5", "v6"
    );
}

WOLFSSL_LOCAL void wc_mceliece_bs_sort_rows_neon(sword16* x_p, word64* mat_p,
    int parWidth_p, int n_p);
void wc_mceliece_bs_sort_rows_neon(sword16* x_p, word64* mat_p, int parWidth_p,
    int n_p)
{
    register sword16* x __asm__ ("x0") = (sword16*)x_p;
    register word64* mat __asm__ ("x1") = (word64*)mat_p;
    register int parWidth __asm__ ("w2") = (int)parWidth_p;
    register int n __asm__ ("w3") = (int)n_p;
    __asm__ __volatile__ (
        "mov	x19, %x[x]\n\t"
        "mov	x20, %x[mat]\n\t"
        "mov	w21, %w[parWidth]\n\t"
        "mov	w22, %w[n]\n\t"
        "mov	x23, #1\n\t"
        "\n"
    "L_mc_srt_tw_%=:\n\t"
        "mov	x7, #1\n\t"
        "lsl	x7, x7, x23\n\t"
        "cmp	x7, x22\n\t"
        "b.ge	L_mc_srt_twe_%=\n\t"
        "add	x23, x23, #1\n\t"
        "b	L_mc_srt_tw_%=\n\t"
        "\n"
    "L_mc_srt_twe_%=:\n\t"
        "sub	x24, x23, #1\n\t"
        "\n"
    "L_mc_srt_j_%=:\n\t"
        "cmp	x24, #0\n\t"
        "b.lt	L_mc_srt_je_%=\n\t"
        "mov	x25, #1\n\t"
        "sub	x7, x23, #1\n\t"
        "lsl	x25, x25, x7\n\t"
        "mov	x26, #0\n\t"
        "mov	x5, #1\n\t"
        "lsl	x5, x5, x24\n\t"
        "mov	x27, x5\n\t"
        "\n"
    "L_mc_srt_ps_%=:\n\t"
        "mov	x28, #0\n\t"
        "\n"
    "L_mc_srt_i_%=:\n\t"
        "sub	x6, x22, x27\n\t"
        "cmp	x28, x6\n\t"
        "b.ge	L_mc_srt_ie_%=\n\t"
        "mov	x5, #1\n\t"
        "lsl	x5, x5, x24\n\t"
        "and	x7, x28, x5\n\t"
        "cmp	x7, x26\n\t"
        "b.ne	L_mc_srt_sk_%=\n\t"
        "mov	%x[x], x19\n\t"
        "mov	%x[mat], x20\n\t"
        "mov	%w[parWidth], w21\n\t"
        "mov	%w[n], w28\n\t"
        "add	x7, x28, x27\n\t"
        "mov	w4, w7\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_bs_minmax_rows_neon\n\t"
#else
        "bl	_wc_mceliece_bs_minmax_rows_neon\n\t"
#endif /* __APPLE__ */
        "\n"
    "L_mc_srt_sk_%=:\n\t"
        "add	x28, x28, #1\n\t"
        "b	L_mc_srt_i_%=\n\t"
        "\n"
    "L_mc_srt_ie_%=:\n\t"
        "mov	x5, #1\n\t"
        "lsl	x5, x5, x24\n\t"
        "cmp	x25, x5\n\t"
        "b.eq	L_mc_srt_pse_%=\n\t"
        "sub	x27, x25, x5\n\t"
        "lsr	x25, x25, #1\n\t"
        "mov	x26, x5\n\t"
        "b	L_mc_srt_ps_%=\n\t"
        "\n"
    "L_mc_srt_pse_%=:\n\t"
        "sub	x24, x24, #1\n\t"
        "b	L_mc_srt_j_%=\n\t"
        "\n"
    "L_mc_srt_je_%=:\n\t"
        : [x] "+r" (x), [mat] "+r" (mat), [parWidth] "+r" (parWidth),
          [n] "+r" (n)
        :
        : "memory", "cc", "x4", "x19", "x20", "x21", "x22", "x23", "x24", "x25",
            "x26", "x27", "x28", "x5", "x6", "x7", "x30"
    );
}

WOLFSSL_LOCAL void wc_mceliece_bs_phase10_neon(void* ctx_p);
void wc_mceliece_bs_phase10_neon(void* ctx_p)
{
    register void* ctx __asm__ ("x0") = (void*)ctx_p;
    __asm__ __volatile__ (
        "mov	x19, %x[ctx]\n\t"
        "ldr	x20, [x19, #72]\n\t"
        "ldr	x21, [x19, #32]\n\t"
        "ldr	x22, [x19, #96]\n\t"
        "ldr	x23, [x19, #144]\n\t"
        "ldr	x24, [x19, #168]\n\t"
        "ldr	x26, [x19, #184]\n\t"
        "add	x8, x23, #0xff\n\t"
        "lsr	x8, x8, #8\n\t"
        "lsl	x25, x8, #2\n\t"
        "mul	x13, x23, x26\n\t"
        "lsr	x9, x13, #3\n\t"
        "and	x10, x13, #7\n\t"
        "mov	x11, x22\n\t"
        "mov	x12, #0\n\t"
        "mov	x8, #0\n\t"
        "\n"
    "L_mc_p10_zw_%=:\n\t"
        "cmp	x8, x9\n\t"
        "b.ge	L_mc_p10_zwe_%=\n\t"
        "str	x12, [x11]\n\t"
        "add	x11, x11, #8\n\t"
        "add	x8, x8, #1\n\t"
        "b	L_mc_p10_zw_%=\n\t"
        "\n"
    "L_mc_p10_zwe_%=:\n\t"
        "mov	x8, #0\n\t"
        "\n"
    "L_mc_p10_zb_%=:\n\t"
        "cmp	x8, x10\n\t"
        "b.ge	L_mc_p10_zbe_%=\n\t"
        "strb	w12, [x11]\n\t"
        "add	x11, x11, #1\n\t"
        "add	x8, x8, #1\n\t"
        "b	L_mc_p10_zb_%=\n\t"
        "\n"
    "L_mc_p10_zbe_%=:\n\t"
        "ldr	x27, [x19, #176]\n\t"
        "\n"
    "L_mc_p10_j_%=:\n\t"
        "cmp	x27, x24\n\t"
        "b.ge	L_mc_p10_je_%=\n\t"
        "mov	x8, #52\n\t"
        "mul	x8, x27, x8\n\t"
        "lsl	x8, x8, #3\n\t"
        "mov	%x[ctx], x20\n\t"
        "ldr	x10, [x19, #40]\n\t"
        "add	x1, x10, x8\n\t"
        "ldr	x10, [x19, #48]\n\t"
        "add	x2, x10, x8\n\t"
        "ldr	x10, [x19, #136]\n\t"
        "mov	w3, w10\n\t"
        "mov	w4, #13\n\t"
        "mov	w5, #7\n\t"
        "sub	x11, x24, x27\n\t"
        "mov	w6, w11\n\t"
        "ldr	x7, [x19, #104]\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_bs_par_fill_neon\n\t"
#else
        "bl	_wc_mceliece_bs_par_fill_neon\n\t"
#endif /* __APPLE__ */
        "ldr	x8, [x19, #80]\n\t"
        "ldr	x9, [x19, #88]\n\t"
        "mov	x10, #0\n\t"
        "\n"
    "L_mc_p10_ic_%=:\n\t"
        "cmp	x10, x23\n\t"
        "b.ge	L_mc_p10_ice_%=\n\t"
        "ldrh	w11, [x9]\n\t"
        "strh	w11, [x8]\n\t"
        "add	x8, x8, #2\n\t"
        "add	x9, x9, #2\n\t"
        "add	x10, x10, #1\n\t"
        "b	L_mc_p10_ic_%=\n\t"
        "\n"
    "L_mc_p10_ice_%=:\n\t"
        "ldr	%x[ctx], [x19, #80]\n\t"
        "mov	x1, x20\n\t"
        "mov	w2, #7\n\t"
        "mov	w3, w23\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_bs_sort_rows_neon\n\t"
#else
        "bl	_wc_mceliece_bs_sort_rows_neon\n\t"
#endif /* __APPLE__ */
        "sub	x28, x23, #1\n\t"
        "\n"
    "L_mc_p10_l_%=:\n\t"
        "cmp	x28, #0\n\t"
        "b.lt	L_mc_p10_le_%=\n\t"
        "mov	%x[ctx], x20\n\t"
        "mul	x8, x28, x25\n\t"
        "lsl	x8, x8, #3\n\t"
        "add	x1, x21, x8\n\t"
        "mov	w2, w28\n\t"
        "mov	w3, #28\n\t"
        "mov	w4, #0\n\t"
        "mov	w5, w28\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_bs_tri_neon\n\t"
#else
        "bl	_wc_mceliece_bs_tri_neon\n\t"
#endif /* __APPLE__ */
        "sub	x28, x28, #1\n\t"
        "b	L_mc_p10_l_%=\n\t"
        "\n"
    "L_mc_p10_le_%=:\n\t"
        "ldr	x8, [x19, #176]\n\t"
        "cmp	x27, x8\n\t"
        "b.ne	L_mc_p10_ove_%=\n\t"
        "sub	x12, x25, #4\n\t"
        "mov	x10, #0\n\t"
        "\n"
    "L_mc_p10_or_%=:\n\t"
        "cmp	x10, x23\n\t"
        "b.ge	L_mc_p10_ore_%=\n\t"
        "mul	x8, x10, x25\n\t"
        "add	x8, x8, x12\n\t"
        "lsl	x8, x8, #3\n\t"
        "add	x14, x21, x8\n\t"
        "mov	x8, #28\n\t"
        "mul	x8, x10, x8\n\t"
        "lsl	x8, x8, #3\n\t"
        "add	x15, x20, x8\n\t"
        "ldp	q0, q1, [x14]\n\t"
        "stp	q0, q1, [x15]\n\t"
        "add	x10, x10, #1\n\t"
        "b	L_mc_p10_or_%=\n\t"
        "\n"
    "L_mc_p10_ore_%=:\n\t"
        "\n"
    "L_mc_p10_ove_%=:\n\t"
        "sub	x28, x23, #1\n\t"
        "\n"
    "L_mc_p10_u_%=:\n\t"
        "cmp	x28, #0\n\t"
        "b.lt	L_mc_p10_ue_%=\n\t"
        "mov	%x[ctx], x20\n\t"
        "mul	x8, x28, x25\n\t"
        "lsl	x8, x8, #3\n\t"
        "add	x1, x21, x8\n\t"
        "mov	w2, w28\n\t"
        "mov	w3, #28\n\t"
        "add	x9, x28, #1\n\t"
        "mov	w4, w9\n\t"
        "mov	w5, w23\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_bs_tri_neon\n\t"
#else
        "bl	_wc_mceliece_bs_tri_neon\n\t"
#endif /* __APPLE__ */
        "sub	x28, x28, #1\n\t"
        "b	L_mc_p10_u_%=\n\t"
        "\n"
    "L_mc_p10_ue_%=:\n\t"
        "mov	x12, #0\n\t"
        "\n"
    "L_mc_p10_b_%=:\n\t"
        "cmp	x12, #7\n\t"
        "b.ge	L_mc_p10_be_%=\n\t"
        "add	x13, x27, x12\n\t"
        "cmp	x13, x24\n\t"
        "b.ge	L_mc_p10_bsk_%=\n\t"
        "mov	x10, #0\n\t"
        "\n"
    "L_mc_p10_br_%=:\n\t"
        "cmp	x10, x23\n\t"
        "b.ge	L_mc_p10_bre_%=\n\t"
        "mul	x8, x10, x26\n\t"
        "lsl	x9, x13, #5\n\t"
        "add	x8, x8, x9\n\t"
        "add	x15, x22, x8\n\t"
        "mov	x8, #28\n\t"
        "mul	x8, x10, x8\n\t"
        "lsl	x9, x12, #2\n\t"
        "add	x8, x8, x9\n\t"
        "lsl	x8, x8, #3\n\t"
        "add	x14, x20, x8\n\t"
        "ldp	q0, q1, [x14]\n\t"
        "stp	q0, q1, [x15]\n\t"
        "add	x10, x10, #1\n\t"
        "b	L_mc_p10_br_%=\n\t"
        "\n"
    "L_mc_p10_bre_%=:\n\t"
        "\n"
    "L_mc_p10_bsk_%=:\n\t"
        "add	x12, x12, #1\n\t"
        "b	L_mc_p10_b_%=\n\t"
        "\n"
    "L_mc_p10_be_%=:\n\t"
        "add	x27, x27, #7\n\t"
        "b	L_mc_p10_j_%=\n\t"
        "\n"
    "L_mc_p10_je_%=:\n\t"
        : [ctx] "+r" (ctx)
        :
        : "memory", "cc", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x19",
            "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x8",
            "x9", "x10", "x11", "x12", "x13", "x14", "x15", "v0", "v1", "x30"
    );
}

WOLFSSL_LOCAL void wc_mceliece_bs_packbuf_neon(word64* buf_p,
    const word32* perm_p, const word64* fftinv_p);
void wc_mceliece_bs_packbuf_neon(word64* buf_p, const word32* perm_p,
    const word64* fftinv_p)
{
    register word64* buf __asm__ ("x0") = (word64*)buf_p;
    register const word32* perm __asm__ ("x1") = (const word32*)perm_p;
    register const word64* fftinv __asm__ ("x2") = (const word64*)fftinv_p;
    __asm__ __volatile__ (
        "mov	w7, #0x1fff\n\t"
        "mov	w8, #0x2000\n\t"
        "mov	x3, #0\n\t"
        "\n"
    "L_mc_pkb_%=:\n\t"
        "ldr	w4, [%x[perm]]\n\t"
        "add	%x[perm], %x[perm], #4\n\t"
        "ldr	x5, [%x[fftinv]]\n\t"
        "add	%x[fftinv], %x[fftinv], #8\n\t"
        "and	x5, x5, x7\n\t"
        "lsl	x5, x5, #13\n\t"
        "lsl	x6, x4, #31\n\t"
        "orr	x6, x6, x5\n\t"
        "orr	x6, x6, x3\n\t"
        "str	x6, [%x[buf]]\n\t"
        "add	%x[buf], %x[buf], #8\n\t"
        "add	x3, x3, #1\n\t"
        "cmp	x3, x8\n\t"
        "b.lt	L_mc_pkb_%=\n\t"
        : [buf] "+r" (buf)
        : [perm] "r" (perm), [fftinv] "r" (fftinv)
        : "memory", "cc", "x3", "x4", "x5", "x6", "x7", "x8"
    );
}

WOLFSSL_LOCAL int wc_mceliece_bs_dup_pi_neon(sword16* pi_p,
    const word64* buf_p);
int wc_mceliece_bs_dup_pi_neon(sword16* pi_p, const word64* buf_p)
{
    register sword16* pi __asm__ ("x0") = (sword16*)pi_p;
    register const word64* buf __asm__ ("x1") = (const word64*)buf_p;
    __asm__ __volatile__ (
        "mov	w8, #0\n\t"
        "mov	w6, #0x2000\n\t"
        "mov	x2, %x[buf]\n\t"
        "ldr	x5, [x2]\n\t"
        "lsr	x5, x5, #31\n\t"
        "add	x2, x2, #8\n\t"
        "mov	x3, #1\n\t"
        "\n"
    "L_mc_dup_c_%=:\n\t"
        "ldr	x4, [x2]\n\t"
        "lsr	x4, x4, #31\n\t"
        "cmp	x4, x5\n\t"
        "b.eq	L_mc_dup_bad_%=\n\t"
        "mov	x5, x4\n\t"
        "add	x2, x2, #8\n\t"
        "add	x3, x3, #1\n\t"
        "cmp	x3, x6\n\t"
        "b.lt	L_mc_dup_c_%=\n\t"
        "mov	w7, #0x1fff\n\t"
        "mov	x2, %x[buf]\n\t"
        "mov	x3, #0\n\t"
        "\n"
    "L_mc_dup_pi_%=:\n\t"
        "ldr	x4, [x2]\n\t"
        "and	x4, x4, x7\n\t"
        "strh	w4, [%x[pi]]\n\t"
        "add	%x[pi], %x[pi], #2\n\t"
        "add	x2, x2, #8\n\t"
        "add	x3, x3, #1\n\t"
        "cmp	x3, x6\n\t"
        "b.lt	L_mc_dup_pi_%=\n\t"
        "b	L_mc_dup_end_%=\n\t"
        "\n"
    "L_mc_dup_bad_%=:\n\t"
        "mov	w8, #0\n\t"
        "sub	w8, w8, #1\n\t"
        "\n"
    "L_mc_dup_end_%=:\n\t"
        "mov	%w[pi], w8\n\t"
        : [pi] "+r" (pi)
        : [buf] "r" (buf)
        : "memory", "cc", "x2", "x3", "x4", "x5", "x6", "x7", "x8"
    );
    return (word32)(size_t)pi;
}

WOLFSSL_LOCAL void wc_mceliece_bs_gload_neon(word16* g_p, word16* fftw_p,
    const byte* gbytes_p, int t_p);
void wc_mceliece_bs_gload_neon(word16* g_p, word16* fftw_p,
    const byte* gbytes_p, int t_p)
{
    register word16* g __asm__ ("x0") = (word16*)g_p;
    register word16* fftw __asm__ ("x1") = (word16*)fftw_p;
    register const byte* gbytes __asm__ ("x2") = (const byte*)gbytes_p;
    register int t __asm__ ("w3") = (int)t_p;
    __asm__ __volatile__ (
        "mov	w10, %w[t]\n\t"
        "mov	w9, #0x1fff\n\t"
        "lsl	x5, x10, #1\n\t"
        "add	x5, %x[g], x5\n\t"
        "mov	w6, #1\n\t"
        "strh	w6, [x5]\n\t"
        "mov	x4, #0\n\t"
        "mov	x7, %x[g]\n\t"
        "\n"
    "L_mc_gld_ld_%=:\n\t"
        "cmp	x4, x10\n\t"
        "b.ge	L_mc_gld_lde_%=\n\t"
        "ldrh	w6, [%x[gbytes]]\n\t"
        "add	%x[gbytes], %x[gbytes], #2\n\t"
        "and	x6, x6, x9\n\t"
        "strh	w6, [x7]\n\t"
        "add	x7, x7, #2\n\t"
        "add	x4, x4, #1\n\t"
        "b	L_mc_gld_ld_%=\n\t"
        "\n"
    "L_mc_gld_lde_%=:\n\t"
        "mov	x4, #0\n\t"
        "mov	x8, %x[fftw]\n\t"
        "\n"
    "L_mc_gld_f_%=:\n\t"
        "cmp	x4, #0x80\n\t"
        "b.ge	L_mc_gld_fe_%=\n\t"
        "cmp	x4, x10\n\t"
        "b.gt	L_mc_gld_fz_%=\n\t"
        "lsl	x5, x4, #1\n\t"
        "add	x5, %x[g], x5\n\t"
        "ldrh	w6, [x5]\n\t"
        "b	L_mc_gld_fs_%=\n\t"
        "\n"
    "L_mc_gld_fz_%=:\n\t"
        "mov	w6, #0\n\t"
        "\n"
    "L_mc_gld_fs_%=:\n\t"
        "strh	w6, [x8]\n\t"
        "add	x8, x8, #2\n\t"
        "add	x4, x4, #1\n\t"
        "b	L_mc_gld_f_%=\n\t"
        "\n"
    "L_mc_gld_fe_%=:\n\t"
        : [g] "+r" (g), [fftw] "+r" (fftw), [t] "+r" (t)
        : [gbytes] "r" (gbytes)
        : "memory", "cc", "x4", "x5", "x6", "x7", "x8", "x9", "x10"
    );
}

WOLFSSL_LOCAL void wc_mceliece_cb_layer_neon(sword16* p_p, const byte* cb_p,
    int s_p, int n_p);
void wc_mceliece_cb_layer_neon(sword16* p_p, const byte* cb_p, int s_p, int n_p)
{
    register sword16* p __asm__ ("x0") = (sword16*)p_p;
    register const byte* cb __asm__ ("x1") = (const byte*)cb_p;
    register int s __asm__ ("w2") = (int)s_p;
    register int n __asm__ ("w3") = (int)n_p;
    __asm__ __volatile__ (
        "mov	w14, %w[n]\n\t"
        "mov	w15, %w[s]\n\t"
        "mov	x4, #1\n\t"
        "lsl	x4, x4, x15\n\t"
        "lsl	x5, x4, #1\n\t"
        "mov	x8, #0\n\t"
        "mov	x6, #0\n\t"
        "\n"
    "L_mc_cbl_i_%=:\n\t"
        "cmp	x6, x14\n\t"
        "b.ge	L_mc_cbl_end_%=\n\t"
        "mov	x7, #0\n\t"
        "\n"
    "L_mc_cbl_j_%=:\n\t"
        "cmp	x7, x4\n\t"
        "b.ge	L_mc_cbl_ni_%=\n\t"
        "lsr	x13, x8, #3\n\t"
        "add	x13, %x[cb], x13\n\t"
        "ldrb	w13, [x13]\n\t"
        "and	x11, x8, #7\n\t"
        "lsr	x13, x13, x11\n\t"
        "and	x13, x13, #1\n\t"
        "neg	x13, x13\n\t"
        "add	x9, x6, x7\n\t"
        "lsl	x9, x9, #1\n\t"
        "add	x9, %x[p], x9\n\t"
        "add	x10, x9, x5\n\t"
        "ldrh	w11, [x9]\n\t"
        "ldrh	w12, [x10]\n\t"
        "eor	x11, x11, x12\n\t"
        "and	x11, x11, x13\n\t"
        "ldrh	w12, [x9]\n\t"
        "eor	x12, x12, x11\n\t"
        "strh	w12, [x9]\n\t"
        "ldrh	w12, [x10]\n\t"
        "eor	x12, x12, x11\n\t"
        "strh	w12, [x10]\n\t"
        "add	x8, x8, #1\n\t"
        "add	x7, x7, #1\n\t"
        "b	L_mc_cbl_j_%=\n\t"
        "\n"
    "L_mc_cbl_ni_%=:\n\t"
        "add	x6, x6, x5\n\t"
        "b	L_mc_cbl_i_%=\n\t"
        "\n"
    "L_mc_cbl_end_%=:\n\t"
        : [p] "+r" (p), [s] "+r" (s), [n] "+r" (n)
        : [cb] "r" (cb)
        : "memory", "cc", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11",
            "x12", "x13", "x14", "x15"
    );
}

WOLFSSL_LOCAL void wc_mceliece_bs_debitslice_neon(word64* out_p, word64* in_p);
void wc_mceliece_bs_debitslice_neon(word64* out_p, word64* in_p)
{
    register word64* out __asm__ ("x0") = (word64*)out_p;
    register word64* in __asm__ ("x1") = (word64*)in_p;
    __asm__ __volatile__ (
        "mov	x2, %x[in]\n\t"
        "mov	x3, #0\n\t"
        "\n"
    "L_mc_dbs_i_%=:\n\t"
        "mov	x4, #0\n\t"
        "\n"
    "L_mc_dbs_l_%=:\n\t"
        "mov	x5, #0\n\t"
        "\n"
    "L_mc_dbs_r_%=:\n\t"
        "lsl	x7, x4, #3\n\t"
        "add	x7, x2, x7\n\t"
        "mov	x8, #0\n\t"
        "mov	x6, #0\n\t"
        "\n"
    "L_mc_dbs_j_%=:\n\t"
        "ldr	x9, [x7]\n\t"
        "lsr	x9, x9, x5\n\t"
        "and	x9, x9, #1\n\t"
        "lsl	x9, x9, x6\n\t"
        "orr	x8, x8, x9\n\t"
        "add	x7, x7, #32\n\t"
        "add	x6, x6, #1\n\t"
        "cmp	x6, #13\n\t"
        "b.lt	L_mc_dbs_j_%=\n\t"
        "str	x8, [%x[out]]\n\t"
        "add	%x[out], %x[out], #8\n\t"
        "add	x5, x5, #1\n\t"
        "cmp	x5, #0x40\n\t"
        "b.lt	L_mc_dbs_r_%=\n\t"
        "add	x4, x4, #1\n\t"
        "cmp	x4, #4\n\t"
        "b.lt	L_mc_dbs_l_%=\n\t"
        "add	x2, x2, #0x1a0\n\t"
        "add	x3, x3, #1\n\t"
        "cmp	x3, #32\n\t"
        "b.lt	L_mc_dbs_i_%=\n\t"
        : [out] "+r" (out), [in] "+r" (in)
        :
        : "memory", "cc", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9"
    );
}

WOLFSSL_LOCAL void wc_mceliece_bs_tobitslice2x_neon(word64* out0_p,
    word64* out1_p, const word64* in_p);
void wc_mceliece_bs_tobitslice2x_neon(word64* out0_p, word64* out1_p,
    const word64* in_p)
{
    register word64* out0 __asm__ ("x0") = (word64*)out0_p;
    register word64* out1 __asm__ ("x1") = (word64*)out1_p;
    register const word64* in __asm__ ("x2") = (const word64*)in_p;
    __asm__ __volatile__ (
        "mov	x3, #0\n\t"
        "\n"
    "L_mc_tbs_i_%=:\n\t"
        "mov	x4, #0\n\t"
        "\n"
    "L_mc_tbs_j_%=:\n\t"
        "mov	x5, #0\n\t"
        "\n"
    "L_mc_tbs_k_%=:\n\t"
        "lsl	x9, x3, #11\n\t"
        "add	x9, %x[in], x9\n\t"
        "lsl	x13, x5, #9\n\t"
        "add	x9, x9, x13\n\t"
        "mov	x6, #12\n\t"
        "sub	x6, x6, x4\n\t"
        "add	x7, x4, #13\n\t"
        "mov	x11, #0\n\t"
        "mov	x12, #0\n\t"
        "mov	x8, #0\n\t"
        "\n"
    "L_mc_tbs_r_%=:\n\t"
        "ldr	x10, [x9]\n\t"
        "add	x9, x9, #8\n\t"
        "lsr	x13, x10, x6\n\t"
        "and	x13, x13, #1\n\t"
        "lsl	x13, x13, x8\n\t"
        "orr	x11, x11, x13\n\t"
        "lsr	x14, x10, x7\n\t"
        "and	x14, x14, #1\n\t"
        "lsl	x14, x14, x8\n\t"
        "orr	x12, x12, x14\n\t"
        "add	x8, x8, #1\n\t"
        "cmp	x8, #0x40\n\t"
        "b.lt	L_mc_tbs_r_%=\n\t"
        "str	x11, [%x[out0]]\n\t"
        "str	x12, [%x[out1]]\n\t"
        "add	%x[out0], %x[out0], #8\n\t"
        "add	%x[out1], %x[out1], #8\n\t"
        "add	x5, x5, #1\n\t"
        "cmp	x5, #4\n\t"
        "b.lt	L_mc_tbs_k_%=\n\t"
        "add	x4, x4, #1\n\t"
        "cmp	x4, #13\n\t"
        "b.lt	L_mc_tbs_j_%=\n\t"
        "add	x3, x3, #1\n\t"
        "cmp	x3, #32\n\t"
        "b.lt	L_mc_tbs_i_%=\n\t"
        : [out0] "+r" (out0), [out1] "+r" (out1)
        : [in] "r" (in)
        : "memory", "cc", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
            "x11", "x12", "x13", "x14"
    );
}

WOLFSSL_LOCAL int wc_mceliece_bs_mov_columns_neon(word64* mat_p, int nbiW_p,
    int nRows_p, sword16* pi_p, word64* pivots_p);
int wc_mceliece_bs_mov_columns_neon(word64* mat_p, int nbiW_p, int nRows_p,
    sword16* pi_p, word64* pivots_p)
{
    register word64* mat __asm__ ("x0") = (word64*)mat_p;
    register int nbiW __asm__ ("w1") = (int)nbiW_p;
    register int nRows __asm__ ("w2") = (int)nRows_p;
    register sword16* pi __asm__ ("x3") = (sword16*)pi_p;
    register word64* pivots __asm__ ("x4") = (word64*)pivots_p;
    __asm__ __volatile__ (
        "stp	x29, x30, [sp, #-400]!\n\t"
        "add	x29, sp, #0\n\t"
        "add	x11, x29, #16\n\t"
        "mov	w5, %w[nbiW]\n\t"
        "mov	w6, %w[nRows]\n\t"
        "sub	x7, x6, #32\n\t"
        "and	x8, x7, #63\n\t"
        "mov	x9, #0x40\n\t"
        "sub	x9, x9, x8\n\t"
        "lsr	x10, x7, #6\n\t"
        "mul	x25, x7, x5\n\t"
        "add	x25, x25, x10\n\t"
        "lsl	x25, x25, #3\n\t"
        "add	x19, %x[mat], x25\n\t"
        "mov	x12, #0\n\t"
        "\n"
    "L_mc_mov_p1_%=:\n\t"
        "cmp	x12, #32\n\t"
        "b.ge	L_mc_mov_p1e_%=\n\t"
        "ldr	x20, [x19]\n\t"
        "ldr	x21, [x19, #8]\n\t"
        "lsr	x20, x20, x8\n\t"
        "lsl	x21, x21, x9\n\t"
        "orr	x20, x20, x21\n\t"
        "lsl	x25, x12, #3\n\t"
        "add	x25, x11, x25\n\t"
        "str	x20, [x25]\n\t"
        "lsl	x25, x5, #3\n\t"
        "add	x19, x19, x25\n\t"
        "add	x12, x12, #1\n\t"
        "b	L_mc_mov_p1_%=\n\t"
        "\n"
    "L_mc_mov_p1e_%=:\n\t"
        "mov	x15, #0\n\t"
        "mov	x12, #0\n\t"
        "\n"
    "L_mc_mov_p2_%=:\n\t"
        "cmp	x12, #32\n\t"
        "b.ge	L_mc_mov_p2e_%=\n\t"
        "lsl	x25, x12, #3\n\t"
        "add	x26, x11, x25\n\t"
        "ldr	x23, [x26]\n\t"
        "add	x13, x12, #1\n\t"
        "\n"
    "L_mc_mov_or_%=:\n\t"
        "cmp	x13, #32\n\t"
        "b.ge	L_mc_mov_ore_%=\n\t"
        "lsl	x25, x13, #3\n\t"
        "add	x26, x11, x25\n\t"
        "ldr	x24, [x26]\n\t"
        "orr	x23, x23, x24\n\t"
        "add	x13, x13, #1\n\t"
        "b	L_mc_mov_or_%=\n\t"
        "\n"
    "L_mc_mov_ore_%=:\n\t"
        "cbz	x23, L_mc_mov_fail_%=\n\t"
        "rbit	x25, x23\n\t"
        "clz	x14, x25\n\t"
        "lsl	x25, x12, #2\n\t"
        "add	x26, x11, x25\n\t"
        "add	x26, x26, #0x100\n\t"
        "str	w14, [x26]\n\t"
        "mov	x25, #1\n\t"
        "lsl	x25, x25, x14\n\t"
        "orr	x15, x15, x25\n\t"
        "lsl	x25, x12, #3\n\t"
        "add	x17, x11, x25\n\t"
        "ldr	x16, [x17]\n\t"
        "add	x13, x12, #1\n\t"
        "\n"
    "L_mc_mov_i1_%=:\n\t"
        "cmp	x13, #32\n\t"
        "b.ge	L_mc_mov_i1e_%=\n\t"
        "lsr	x25, x16, x14\n\t"
        "and	x25, x25, #1\n\t"
        "sub	x25, x25, #1\n\t"
        "lsl	x24, x13, #3\n\t"
        "add	x26, x11, x24\n\t"
        "ldr	x24, [x26]\n\t"
        "and	x24, x24, x25\n\t"
        "eor	x16, x16, x24\n\t"
        "add	x13, x13, #1\n\t"
        "b	L_mc_mov_i1_%=\n\t"
        "\n"
    "L_mc_mov_i1e_%=:\n\t"
        "str	x16, [x17]\n\t"
        "add	x13, x12, #1\n\t"
        "\n"
    "L_mc_mov_i2_%=:\n\t"
        "cmp	x13, #32\n\t"
        "b.ge	L_mc_mov_i2e_%=\n\t"
        "lsl	x24, x13, #3\n\t"
        "add	x26, x11, x24\n\t"
        "ldr	x20, [x26]\n\t"
        "lsr	x25, x20, x14\n\t"
        "and	x25, x25, #1\n\t"
        "neg	x25, x25\n\t"
        "and	x25, x16, x25\n\t"
        "eor	x20, x20, x25\n\t"
        "str	x20, [x26]\n\t"
        "add	x13, x13, #1\n\t"
        "b	L_mc_mov_i2_%=\n\t"
        "\n"
    "L_mc_mov_i2e_%=:\n\t"
        "add	x12, x12, #1\n\t"
        "b	L_mc_mov_p2_%=\n\t"
        "\n"
    "L_mc_mov_p2e_%=:\n\t"
        "str	x15, [%x[pivots]]\n\t"
        "lsl	x25, x7, #1\n\t"
        "add	x19, %x[pi], x25\n\t"
        "mov	x12, #0\n\t"
        "\n"
    "L_mc_mov_p3i_%=:\n\t"
        "cmp	x12, #32\n\t"
        "b.ge	L_mc_mov_p3ie_%=\n\t"
        "lsl	x25, x12, #2\n\t"
        "add	x26, x11, x25\n\t"
        "add	x26, x26, #0x100\n\t"
        "ldr	w14, [x26]\n\t"
        "lsl	x25, x12, #1\n\t"
        "add	x17, x19, x25\n\t"
        "ldrh	w16, [x17]\n\t"
        "add	x13, x12, #1\n\t"
        "\n"
    "L_mc_mov_p3j_%=:\n\t"
        "cmp	x13, #0x40\n\t"
        "b.ge	L_mc_mov_p3je_%=\n\t"
        "lsl	x25, x13, #1\n\t"
        "add	x26, x19, x25\n\t"
        "ldrh	w24, [x26]\n\t"
        "eor	x25, x16, x24\n\t"
        "cmp	x13, x14\n\t"
        "csetm	x20, eq\n\t"
        "and	x25, x25, x20\n\t"
        "eor	x16, x16, x25\n\t"
        "eor	x24, x24, x25\n\t"
        "strh	w24, [x26]\n\t"
        "add	x13, x13, #1\n\t"
        "b	L_mc_mov_p3j_%=\n\t"
        "\n"
    "L_mc_mov_p3je_%=:\n\t"
        "strh	w16, [x17]\n\t"
        "add	x12, x12, #1\n\t"
        "b	L_mc_mov_p3i_%=\n\t"
        "\n"
    "L_mc_mov_p3ie_%=:\n\t"
        "mov	x12, #0\n\t"
        "\n"
    "L_mc_mov_p4_%=:\n\t"
        "cmp	x12, x6\n\t"
        "b.ge	L_mc_mov_p4e_%=\n\t"
        "mul	x25, x12, x5\n\t"
        "add	x25, x25, x10\n\t"
        "lsl	x25, x25, #3\n\t"
        "add	x19, %x[mat], x25\n\t"
        "ldr	x20, [x19]\n\t"
        "ldr	x21, [x19, #8]\n\t"
        "lsr	x22, x20, x8\n\t"
        "lsl	x24, x21, x9\n\t"
        "orr	x22, x22, x24\n\t"
        "mov	x13, #0\n\t"
        "\n"
    "L_mc_mov_p4j_%=:\n\t"
        "cmp	x13, #32\n\t"
        "b.ge	L_mc_mov_p4je_%=\n\t"
        "lsl	x25, x13, #2\n\t"
        "add	x26, x11, x25\n\t"
        "add	x26, x26, #0x100\n\t"
        "ldr	w14, [x26]\n\t"
        "lsr	x24, x22, x13\n\t"
        "lsr	x25, x22, x14\n\t"
        "eor	x24, x24, x25\n\t"
        "and	x24, x24, #1\n\t"
        "lsl	x25, x24, x14\n\t"
        "eor	x22, x22, x25\n\t"
        "lsl	x25, x24, x13\n\t"
        "eor	x22, x22, x25\n\t"
        "add	x13, x13, #1\n\t"
        "b	L_mc_mov_p4j_%=\n\t"
        "\n"
    "L_mc_mov_p4je_%=:\n\t"
        "mov	x27, #1\n\t"
        "lsl	x27, x27, x8\n\t"
        "sub	x27, x27, #1\n\t"
        "and	x20, x20, x27\n\t"
        "lsl	x24, x22, x8\n\t"
        "orr	x20, x20, x24\n\t"
        "str	x20, [x19]\n\t"
        "mvn	x25, x27\n\t"
        "and	x21, x21, x25\n\t"
        "lsr	x24, x22, x9\n\t"
        "orr	x21, x21, x24\n\t"
        "str	x21, [x19, #8]\n\t"
        "add	x12, x12, #1\n\t"
        "b	L_mc_mov_p4_%=\n\t"
        "\n"
    "L_mc_mov_p4e_%=:\n\t"
        "mov	%w[mat], #0\n\t"
        "b	L_mc_mov_done_%=\n\t"
        "\n"
    "L_mc_mov_fail_%=:\n\t"
        "str	x15, [%x[pivots]]\n\t"
        "mov	%w[mat], #0\n\t"
        "sub	%w[mat], %w[mat], #1\n\t"
        "\n"
    "L_mc_mov_done_%=:\n\t"
        "ldp	x29, x30, [sp], #0x190\n\t"
        : [mat] "+r" (mat), [nbiW] "+r" (nbiW), [nRows] "+r" (nRows),
          [pi] "+r" (pi), [pivots] "+r" (pivots)
        :
        : "memory", "cc", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12",
            "x13", "x14", "x15", "x16", "x17", "x19", "x20", "x21", "x22",
            "x23", "x24", "x25", "x26", "x27"
    );
    return (word32)(size_t)mat;
}

WOLFSSL_LOCAL void wc_mceliece_i32_sort_neon(sword32* x_p, int n_p);
void wc_mceliece_i32_sort_neon(sword32* x_p, int n_p)
{
    register sword32* x __asm__ ("x0") = (sword32*)x_p;
    register int n __asm__ ("w1") = (int)n_p;
    __asm__ __volatile__ (
        "mov	w2, %w[n]\n\t"
        "cmp	x2, #2\n\t"
        "b.lt	L_mc_is_ret_%=\n\t"
        "mov	x3, #1\n\t"
        "\n"
    "L_mc_is_top_%=:\n\t"
        "sub	x8, x2, x3\n\t"
        "cmp	x3, x8\n\t"
        "b.ge	L_mc_is_tope_%=\n\t"
        "lsl	x3, x3, #1\n\t"
        "b	L_mc_is_top_%=\n\t"
        "\n"
    "L_mc_is_tope_%=:\n\t"
        "mov	x4, x3\n\t"
        "\n"
    "L_mc_is_p_%=:\n\t"
        "cbz	x4, L_mc_is_ret_%=\n\t"
        "mov	x6, #0\n\t"
        "\n"
    "L_mc_is_b_%=:\n\t"
        "sub	x8, x2, x4\n\t"
        "cmp	x6, x8\n\t"
        "b.ge	L_mc_is_be_%=\n\t"
        "add	x7, x6, x4\n\t"
        "cmp	x7, x8\n\t"
        "b.le	L_mc_is_lim_%=\n\t"
        "mov	x7, x8\n\t"
        "\n"
    "L_mc_is_lim_%=:\n\t"
        "mov	x5, x6\n\t"
        "\n"
    "L_mc_is_i_%=:\n\t"
        "cmp	x5, x7\n\t"
        "b.ge	L_mc_is_ie_%=\n\t"
        "lsl	x9, x5, #2\n\t"
        "add	x9, %x[x], x9\n\t"
        "add	x8, x5, x4\n\t"
        "lsl	x10, x8, #2\n\t"
        "add	x10, %x[x], x10\n\t"
        "ldr	w11, [x9]\n\t"
        "ldr	w12, [x10]\n\t"
        "sub	w13, w11, w12\n\t"
        "asr	w14, w13, #31\n\t"
        "and	w13, w13, w14\n\t"
        "add	w14, w12, w13\n\t"
        "str	w14, [x9]\n\t"
        "sub	w14, w11, w13\n\t"
        "str	w14, [x10]\n\t"
        "add	x5, x5, #1\n\t"
        "b	L_mc_is_i_%=\n\t"
        "\n"
    "L_mc_is_ie_%=:\n\t"
        "add	x6, x6, x4\n\t"
        "add	x6, x6, x4\n\t"
        "b	L_mc_is_b_%=\n\t"
        "\n"
    "L_mc_is_be_%=:\n\t"
        "mov	x5, #0\n\t"
        "mov	x6, x3\n\t"
        "\n"
    "L_mc_is_q_%=:\n\t"
        "cmp	x6, x4\n\t"
        "b.le	L_mc_is_qe_%=\n\t"
        "\n"
    "L_mc_is_iq_%=:\n\t"
        "sub	x8, x2, x6\n\t"
        "cmp	x5, x8\n\t"
        "b.ge	L_mc_is_iqe_%=\n\t"
        "and	x8, x5, x4\n\t"
        "cbnz	x8, L_mc_is_next_%=\n\t"
        "mov	x7, x6\n\t"
        "\n"
    "L_mc_is_r_%=:\n\t"
        "cmp	x7, x4\n\t"
        "b.le	L_mc_is_re_%=\n\t"
        "add	x8, x5, x4\n\t"
        "lsl	x9, x8, #2\n\t"
        "add	x9, %x[x], x9\n\t"
        "add	x8, x5, x7\n\t"
        "lsl	x10, x8, #2\n\t"
        "add	x10, %x[x], x10\n\t"
        "ldr	w11, [x9]\n\t"
        "ldr	w12, [x10]\n\t"
        "sub	w13, w11, w12\n\t"
        "asr	w14, w13, #31\n\t"
        "and	w13, w13, w14\n\t"
        "add	w14, w12, w13\n\t"
        "str	w14, [x9]\n\t"
        "sub	w14, w11, w13\n\t"
        "str	w14, [x10]\n\t"
        "lsr	x7, x7, #1\n\t"
        "b	L_mc_is_r_%=\n\t"
        "\n"
    "L_mc_is_re_%=:\n\t"
        "\n"
    "L_mc_is_next_%=:\n\t"
        "add	x5, x5, #1\n\t"
        "b	L_mc_is_iq_%=\n\t"
        "\n"
    "L_mc_is_iqe_%=:\n\t"
        "lsr	x6, x6, #1\n\t"
        "b	L_mc_is_q_%=\n\t"
        "\n"
    "L_mc_is_qe_%=:\n\t"
        "lsr	x4, x4, #1\n\t"
        "b	L_mc_is_p_%=\n\t"
        "\n"
    "L_mc_is_ret_%=:\n\t"
        : [x] "+r" (x), [n] "+r" (n)
        :
        : "memory", "cc", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
            "x11", "x12", "x13", "x14"
    );
}

WOLFSSL_LOCAL void wc_mceliece_cb_compose10_neon(sword32* a_p, sword32* b_p,
    int n_p, int w_p);
void wc_mceliece_cb_compose10_neon(sword32* a_p, sword32* b_p, int n_p, int w_p)
{
    register sword32* a __asm__ ("x0") = (sword32*)a_p;
    register sword32* b __asm__ ("x1") = (sword32*)b_p;
    register int n __asm__ ("w2") = (int)n_p;
    register int w __asm__ ("w3") = (int)w_p;
    __asm__ __volatile__ (
        "mov	x19, %x[a]\n\t"
        "mov	x20, %x[b]\n\t"
        "mov	w21, %w[n]\n\t"
        "mov	w22, %w[w]\n\t"
        "mov	x5, x19\n\t"
        "mov	x6, x20\n\t"
        "mov	x4, #0\n\t"
        "\n"
    "L_mc_c10_1_%=:\n\t"
        "cmp	x4, x21\n\t"
        "b.ge	L_mc_c10_1e_%=\n\t"
        "ldr	w7, [x5]\n\t"
        "and	w7, w7, #0xffff\n\t"
        "lsl	w7, w7, #10\n\t"
        "ldr	w8, [x6]\n\t"
        "and	w8, w8, #0x3ff\n\t"
        "orr	w7, w7, w8\n\t"
        "str	w7, [x6]\n\t"
        "add	x5, x5, #4\n\t"
        "add	x6, x6, #4\n\t"
        "add	x4, x4, #1\n\t"
        "b	L_mc_c10_1_%=\n\t"
        "\n"
    "L_mc_c10_1e_%=:\n\t"
        "mov	x23, #1\n\t"
        "\n"
    "L_mc_c10_i_%=:\n\t"
        "sub	x7, x22, #1\n\t"
        "cmp	x23, x7\n\t"
        "b.ge	L_mc_c10_ie_%=\n\t"
        "mov	x5, x19\n\t"
        "mov	x6, x20\n\t"
        "mov	x4, #0\n\t"
        "\n"
    "L_mc_c10_a1_%=:\n\t"
        "cmp	x4, x21\n\t"
        "b.ge	L_mc_c10_a1e_%=\n\t"
        "ldr	w7, [x6]\n\t"
        "lsr	w7, w7, #10\n\t"
        "lsl	w7, w7, #10\n\t"
        "lsl	w7, w7, #6\n\t"
        "orr	w7, w7, w4\n\t"
        "str	w7, [x5]\n\t"
        "add	x5, x5, #4\n\t"
        "add	x6, x6, #4\n\t"
        "add	x4, x4, #1\n\t"
        "b	L_mc_c10_a1_%=\n\t"
        "\n"
    "L_mc_c10_a1e_%=:\n\t"
        "mov	%x[a], x19\n\t"
        "mov	%w[b], w21\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_i32_sort_neon\n\t"
#else
        "bl	_wc_mceliece_i32_sort_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, x19\n\t"
        "mov	x6, x20\n\t"
        "mov	x4, #0\n\t"
        "\n"
    "L_mc_c10_a2_%=:\n\t"
        "cmp	x4, x21\n\t"
        "b.ge	L_mc_c10_a2e_%=\n\t"
        "ldr	w7, [x5]\n\t"
        "lsl	w7, w7, #20\n\t"
        "ldr	w8, [x6]\n\t"
        "orr	w7, w7, w8\n\t"
        "str	w7, [x5]\n\t"
        "add	x5, x5, #4\n\t"
        "add	x6, x6, #4\n\t"
        "add	x4, x4, #1\n\t"
        "b	L_mc_c10_a2_%=\n\t"
        "\n"
    "L_mc_c10_a2e_%=:\n\t"
        "mov	%x[a], x19\n\t"
        "mov	%w[b], w21\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_i32_sort_neon\n\t"
#else
        "bl	_wc_mceliece_i32_sort_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, x19\n\t"
        "mov	x6, x20\n\t"
        "mov	x4, #0\n\t"
        "\n"
    "L_mc_c10_a3_%=:\n\t"
        "cmp	x4, x21\n\t"
        "b.ge	L_mc_c10_a3e_%=\n\t"
        "ldr	w7, [x5]\n\t"
        "and	w9, w7, #0xfffff\n\t"
        "and	w7, w7, #0xffc00\n\t"
        "ldr	w8, [x6]\n\t"
        "and	w8, w8, #0x3ff\n\t"
        "orr	w7, w7, w8\n\t"
        "eor	w8, w7, w9\n\t"
        "sub	w11, w9, w7\n\t"
        "eor	w10, w11, w9\n\t"
        "and	w10, w10, w8\n\t"
        "eor	w11, w11, w10\n\t"
        "asr	w11, w11, #31\n\t"
        "and	w11, w11, w8\n\t"
        "eor	w10, w7, w11\n\t"
        "str	w10, [x6]\n\t"
        "add	x5, x5, #4\n\t"
        "add	x6, x6, #4\n\t"
        "add	x4, x4, #1\n\t"
        "b	L_mc_c10_a3_%=\n\t"
        "\n"
    "L_mc_c10_a3e_%=:\n\t"
        "add	x23, x23, #1\n\t"
        "b	L_mc_c10_i_%=\n\t"
        "\n"
    "L_mc_c10_ie_%=:\n\t"
        "mov	x6, x20\n\t"
        "mov	x4, #0\n\t"
        "\n"
    "L_mc_c10_f_%=:\n\t"
        "cmp	x4, x21\n\t"
        "b.ge	L_mc_c10_fe_%=\n\t"
        "ldr	w7, [x6]\n\t"
        "and	w7, w7, #0x3ff\n\t"
        "str	w7, [x6]\n\t"
        "add	x6, x6, #4\n\t"
        "add	x4, x4, #1\n\t"
        "b	L_mc_c10_f_%=\n\t"
        "\n"
    "L_mc_c10_fe_%=:\n\t"
        : [a] "+r" (a), [b] "+r" (b), [n] "+r" (n), [w] "+r" (w)
        :
        : "memory", "cc", "x19", "x20", "x21", "x22", "x23", "x4", "x5", "x6",
            "x7", "x8", "x9", "x10", "x11", "x30"
    );
}

WOLFSSL_LOCAL void wc_mceliece_cb_compose16_neon(sword32* a_p, sword32* b_p,
    int n_p, int w_p);
void wc_mceliece_cb_compose16_neon(sword32* a_p, sword32* b_p, int n_p, int w_p)
{
    register sword32* a __asm__ ("x0") = (sword32*)a_p;
    register sword32* b __asm__ ("x1") = (sword32*)b_p;
    register int n __asm__ ("w2") = (int)n_p;
    register int w __asm__ ("w3") = (int)w_p;
    __asm__ __volatile__ (
        "mov	x19, %x[a]\n\t"
        "mov	x20, %x[b]\n\t"
        "mov	w21, %w[n]\n\t"
        "mov	w22, %w[w]\n\t"
        "mov	x5, x19\n\t"
        "mov	x6, x20\n\t"
        "mov	x4, #0\n\t"
        "\n"
    "L_mc_c16_1_%=:\n\t"
        "cmp	x4, x21\n\t"
        "b.ge	L_mc_c16_1e_%=\n\t"
        "ldr	w7, [x5]\n\t"
        "lsl	w7, w7, #16\n\t"
        "ldr	w8, [x6]\n\t"
        "and	w8, w8, #0xffff\n\t"
        "orr	w7, w7, w8\n\t"
        "str	w7, [x6]\n\t"
        "add	x5, x5, #4\n\t"
        "add	x6, x6, #4\n\t"
        "add	x4, x4, #1\n\t"
        "b	L_mc_c16_1_%=\n\t"
        "\n"
    "L_mc_c16_1e_%=:\n\t"
        "mov	x23, #1\n\t"
        "\n"
    "L_mc_c16_i_%=:\n\t"
        "sub	x7, x22, #1\n\t"
        "cmp	x23, x7\n\t"
        "b.ge	L_mc_c16_ie_%=\n\t"
        "mov	x5, x19\n\t"
        "mov	x6, x20\n\t"
        "mov	x4, #0\n\t"
        "\n"
    "L_mc_c16_a1_%=:\n\t"
        "cmp	x4, x21\n\t"
        "b.ge	L_mc_c16_a1e_%=\n\t"
        "ldr	w7, [x6]\n\t"
        "lsr	w7, w7, #16\n\t"
        "lsl	w7, w7, #16\n\t"
        "orr	w7, w7, w4\n\t"
        "str	w7, [x5]\n\t"
        "add	x5, x5, #4\n\t"
        "add	x6, x6, #4\n\t"
        "add	x4, x4, #1\n\t"
        "b	L_mc_c16_a1_%=\n\t"
        "\n"
    "L_mc_c16_a1e_%=:\n\t"
        "mov	%x[a], x19\n\t"
        "mov	%w[b], w21\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_i32_sort_neon\n\t"
#else
        "bl	_wc_mceliece_i32_sort_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, x19\n\t"
        "mov	x6, x20\n\t"
        "mov	x4, #0\n\t"
        "\n"
    "L_mc_c16_a2_%=:\n\t"
        "cmp	x4, x21\n\t"
        "b.ge	L_mc_c16_a2e_%=\n\t"
        "ldr	w7, [x5]\n\t"
        "lsl	w7, w7, #16\n\t"
        "ldr	w8, [x6]\n\t"
        "and	w8, w8, #0xffff\n\t"
        "orr	w7, w7, w8\n\t"
        "str	w7, [x5]\n\t"
        "add	x5, x5, #4\n\t"
        "add	x6, x6, #4\n\t"
        "add	x4, x4, #1\n\t"
        "b	L_mc_c16_a2_%=\n\t"
        "\n"
    "L_mc_c16_a2e_%=:\n\t"
        "sub	x7, x22, #2\n\t"
        "cmp	x23, x7\n\t"
        "b.ge	L_mc_c16_sk_%=\n\t"
        "mov	x5, x19\n\t"
        "mov	x6, x20\n\t"
        "mov	x4, #0\n\t"
        "\n"
    "L_mc_c16_b1_%=:\n\t"
        "cmp	x4, x21\n\t"
        "b.ge	L_mc_c16_b1e_%=\n\t"
        "ldr	w7, [x5]\n\t"
        "lsr	w7, w7, #16\n\t"
        "lsl	w7, w7, #16\n\t"
        "ldr	w8, [x6]\n\t"
        "asr	w8, w8, #16\n\t"
        "orr	w7, w7, w8\n\t"
        "str	w7, [x6]\n\t"
        "add	x5, x5, #4\n\t"
        "add	x6, x6, #4\n\t"
        "add	x4, x4, #1\n\t"
        "b	L_mc_c16_b1_%=\n\t"
        "\n"
    "L_mc_c16_b1e_%=:\n\t"
        "mov	%x[a], x20\n\t"
        "mov	%w[b], w21\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_i32_sort_neon\n\t"
#else
        "bl	_wc_mceliece_i32_sort_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, x19\n\t"
        "mov	x6, x20\n\t"
        "mov	x4, #0\n\t"
        "\n"
    "L_mc_c16_b2_%=:\n\t"
        "cmp	x4, x21\n\t"
        "b.ge	L_mc_c16_b2e_%=\n\t"
        "ldr	w7, [x6]\n\t"
        "lsl	w7, w7, #16\n\t"
        "ldr	w8, [x5]\n\t"
        "and	w8, w8, #0xffff\n\t"
        "orr	w7, w7, w8\n\t"
        "str	w7, [x6]\n\t"
        "add	x5, x5, #4\n\t"
        "add	x6, x6, #4\n\t"
        "add	x4, x4, #1\n\t"
        "b	L_mc_c16_b2_%=\n\t"
        "\n"
    "L_mc_c16_b2e_%=:\n\t"
        "\n"
    "L_mc_c16_sk_%=:\n\t"
        "mov	%x[a], x19\n\t"
        "mov	%w[b], w21\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_i32_sort_neon\n\t"
#else
        "bl	_wc_mceliece_i32_sort_neon\n\t"
#endif /* __APPLE__ */
        "mov	x5, x19\n\t"
        "mov	x6, x20\n\t"
        "mov	x4, #0\n\t"
        "\n"
    "L_mc_c16_a3_%=:\n\t"
        "cmp	x4, x21\n\t"
        "b.ge	L_mc_c16_a3e_%=\n\t"
        "ldr	w9, [x6]\n\t"
        "lsr	w7, w9, #16\n\t"
        "lsl	w7, w7, #16\n\t"
        "ldr	w8, [x5]\n\t"
        "and	w8, w8, #0xffff\n\t"
        "orr	w7, w7, w8\n\t"
        "eor	w8, w9, w7\n\t"
        "sub	w11, w7, w9\n\t"
        "eor	w10, w11, w7\n\t"
        "and	w10, w10, w8\n\t"
        "eor	w11, w11, w10\n\t"
        "asr	w11, w11, #31\n\t"
        "and	w11, w11, w8\n\t"
        "eor	w10, w9, w11\n\t"
        "str	w10, [x6]\n\t"
        "add	x5, x5, #4\n\t"
        "add	x6, x6, #4\n\t"
        "add	x4, x4, #1\n\t"
        "b	L_mc_c16_a3_%=\n\t"
        "\n"
    "L_mc_c16_a3e_%=:\n\t"
        "add	x23, x23, #1\n\t"
        "b	L_mc_c16_i_%=\n\t"
        "\n"
    "L_mc_c16_ie_%=:\n\t"
        "mov	x6, x20\n\t"
        "mov	x4, #0\n\t"
        "\n"
    "L_mc_c16_f_%=:\n\t"
        "cmp	x4, x21\n\t"
        "b.ge	L_mc_c16_fe_%=\n\t"
        "ldr	w7, [x6]\n\t"
        "and	w7, w7, #0xffff\n\t"
        "str	w7, [x6]\n\t"
        "add	x6, x6, #4\n\t"
        "add	x4, x4, #1\n\t"
        "b	L_mc_c16_f_%=\n\t"
        "\n"
    "L_mc_c16_fe_%=:\n\t"
        : [a] "+r" (a), [b] "+r" (b), [n] "+r" (n), [w] "+r" (w)
        :
        : "memory", "cc", "x19", "x20", "x21", "x22", "x23", "x4", "x5", "x6",
            "x7", "x8", "x9", "x10", "x11", "x30"
    );
}

WOLFSSL_LOCAL void wc_mceliece_cb_build_neon(byte* out_p, long pos0_p,
    long step0_p, const sword16* pi0_p, long w0_p, long n0_p, sword32* temp_p,
    void* stack_p);
void wc_mceliece_cb_build_neon(byte* out_p, long pos0_p, long step0_p,
    const sword16* pi0_p, long w0_p, long n0_p, sword32* temp_p, void* stack_p)
{
    register byte* out __asm__ ("x0") = (byte*)out_p;
    register long pos0 __asm__ ("x1") = (long)pos0_p;
    register long step0 __asm__ ("x2") = (long)step0_p;
    register const sword16* pi0 __asm__ ("x3") = (const sword16*)pi0_p;
    register long w0 __asm__ ("x4") = (long)w0_p;
    register long n0 __asm__ ("x5") = (long)n0_p;
    register sword32* temp __asm__ ("x6") = (sword32*)temp_p;
    register void* stack __asm__ ("x7") = (void*)stack_p;
    __asm__ __volatile__ (
        "mov	x19, %x[out]\n\t"
        "mov	x20, %x[temp]\n\t"
        "mov	x21, %x[stack]\n\t"
        "str	%x[pos0], [x21]\n\t"
        "str	%x[step0], [x21, #8]\n\t"
        "str	%x[pi0], [x21, #16]\n\t"
        "str	%x[w0], [x21, #24]\n\t"
        "str	%x[n0], [x21, #32]\n\t"
        "mov	x22, #1\n\t"
        "\n"
    "L_cbb_w_%=:\n\t"
        "cbz	x22, L_cbb_end_%=\n\t"
        "sub	x22, x22, #1\n\t"
        "mov	x9, #40\n\t"
        "mul	x10, x22, x9\n\t"
        "add	x16, x21, x10\n\t"
        "ldr	x23, [x16]\n\t"
        "ldr	x24, [x16, #8]\n\t"
        "ldr	x25, [x16, #16]\n\t"
        "ldr	x26, [x16, #24]\n\t"
        "ldr	x27, [x16, #32]\n\t"
        "cmp	x26, #1\n\t"
        "b.ne	L_cbb_not1_%=\n\t"
        "lsr	x9, x23, #3\n\t"
        "add	x9, x19, x9\n\t"
        "ldrb	w10, [x9]\n\t"
        "ldrh	w11, [x25]\n\t"
        "and	x12, x23, #7\n\t"
        "lsl	x11, x11, x12\n\t"
        "eor	x10, x10, x11\n\t"
        "strb	w10, [x9]\n\t"
        "b	L_cbb_w_%=\n\t"
        "\n"
    "L_cbb_not1_%=:\n\t"
        "mov	x14, x20\n\t"
        "mov	x8, #0\n\t"
        "\n"
    "L_cbb_s1_%=:\n\t"
        "cmp	x8, x27\n\t"
        "b.ge	L_cbb_s1e_%=\n\t"
        "lsl	x9, x8, #1\n\t"
        "add	x9, x25, x9\n\t"
        "ldrh	w10, [x9]\n\t"
        "eor	w11, w10, #1\n\t"
        "lsl	w11, w11, #16\n\t"
        "eor	x9, x8, #1\n\t"
        "lsl	x9, x9, #1\n\t"
        "add	x9, x25, x9\n\t"
        "ldrh	w9, [x9]\n\t"
        "orr	w11, w11, w9\n\t"
        "str	w11, [x14]\n\t"
        "add	x14, x14, #4\n\t"
        "add	x8, x8, #1\n\t"
        "b	L_cbb_s1_%=\n\t"
        "\n"
    "L_cbb_s1e_%=:\n\t"
        "mov	%x[out], x20\n\t"
        "mov	%w[pos0], w27\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_i32_sort_neon\n\t"
#else
        "bl	_wc_mceliece_i32_sort_neon\n\t"
#endif /* __APPLE__ */
        "lsl	x9, x27, #2\n\t"
        "add	x15, x20, x9\n\t"
        "mov	x14, x20\n\t"
        "mov	x8, #0\n\t"
        "\n"
    "L_cbb_s2_%=:\n\t"
        "cmp	x8, x27\n\t"
        "b.ge	L_cbb_s2e_%=\n\t"
        "ldr	w9, [x14]\n\t"
        "and	w9, w9, #0xffff\n\t"
        "eor	w11, w9, w8\n\t"
        "sub	w12, w8, w9\n\t"
        "eor	w10, w12, w8\n\t"
        "and	w10, w10, w11\n\t"
        "eor	w12, w12, w10\n\t"
        "asr	w12, w12, #31\n\t"
        "and	w12, w12, w11\n\t"
        "eor	w10, w9, w12\n\t"
        "lsl	w11, w9, #16\n\t"
        "orr	w11, w11, w10\n\t"
        "str	w11, [x15]\n\t"
        "add	x14, x14, #4\n\t"
        "add	x15, x15, #4\n\t"
        "add	x8, x8, #1\n\t"
        "b	L_cbb_s2_%=\n\t"
        "\n"
    "L_cbb_s2e_%=:\n\t"
        "mov	x14, x20\n\t"
        "mov	x8, #0\n\t"
        "\n"
    "L_cbb_s3_%=:\n\t"
        "cmp	x8, x27\n\t"
        "b.ge	L_cbb_s3e_%=\n\t"
        "ldr	w9, [x14]\n\t"
        "lsl	w9, w9, #16\n\t"
        "orr	w9, w9, w8\n\t"
        "str	w9, [x14]\n\t"
        "add	x14, x14, #4\n\t"
        "add	x8, x8, #1\n\t"
        "b	L_cbb_s3_%=\n\t"
        "\n"
    "L_cbb_s3e_%=:\n\t"
        "mov	%x[out], x20\n\t"
        "mov	%w[pos0], w27\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_i32_sort_neon\n\t"
#else
        "bl	_wc_mceliece_i32_sort_neon\n\t"
#endif /* __APPLE__ */
        "lsl	x9, x27, #2\n\t"
        "add	x15, x20, x9\n\t"
        "mov	x14, x20\n\t"
        "mov	x8, #0\n\t"
        "\n"
    "L_cbb_s4_%=:\n\t"
        "cmp	x8, x27\n\t"
        "b.ge	L_cbb_s4e_%=\n\t"
        "ldr	w9, [x14]\n\t"
        "lsl	w9, w9, #16\n\t"
        "ldr	w10, [x15]\n\t"
        "asr	w10, w10, #16\n\t"
        "add	w9, w9, w10\n\t"
        "str	w9, [x14]\n\t"
        "add	x14, x14, #4\n\t"
        "add	x15, x15, #4\n\t"
        "add	x8, x8, #1\n\t"
        "b	L_cbb_s4_%=\n\t"
        "\n"
    "L_cbb_s4e_%=:\n\t"
        "mov	%x[out], x20\n\t"
        "mov	%w[pos0], w27\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_i32_sort_neon\n\t"
#else
        "bl	_wc_mceliece_i32_sort_neon\n\t"
#endif /* __APPLE__ */
        "lsl	x9, x27, #2\n\t"
        "add	%x[pos0], x20, x9\n\t"
        "mov	%w[step0], w27\n\t"
        "mov	%w[pi0], w26\n\t"
        "mov	%x[out], x20\n\t"
        "cmp	x26, #10\n\t"
        "b.gt	L_cbb_c16_%=\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_cb_compose10_neon\n\t"
#else
        "bl	_wc_mceliece_cb_compose10_neon\n\t"
#endif /* __APPLE__ */
        "b	L_cbb_c5e_%=\n\t"
        "\n"
    "L_cbb_c16_%=:\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_cb_compose16_neon\n\t"
#else
        "bl	_wc_mceliece_cb_compose16_neon\n\t"
#endif /* __APPLE__ */
        "\n"
    "L_cbb_c5e_%=:\n\t"
        "mov	x14, x20\n\t"
        "mov	x8, #0\n\t"
        "\n"
    "L_cbb_s6_%=:\n\t"
        "cmp	x8, x27\n\t"
        "b.ge	L_cbb_s6e_%=\n\t"
        "lsl	x9, x8, #1\n\t"
        "add	x9, x25, x9\n\t"
        "ldrh	w10, [x9]\n\t"
        "lsl	w10, w10, #16\n\t"
        "add	w10, w10, w8\n\t"
        "str	w10, [x14]\n\t"
        "add	x14, x14, #4\n\t"
        "add	x8, x8, #1\n\t"
        "b	L_cbb_s6_%=\n\t"
        "\n"
    "L_cbb_s6e_%=:\n\t"
        "mov	%x[out], x20\n\t"
        "mov	%w[pos0], w27\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_i32_sort_neon\n\t"
#else
        "bl	_wc_mceliece_i32_sort_neon\n\t"
#endif /* __APPLE__ */
        "lsr	x13, x27, #1\n\t"
        "lsl	x9, x27, #2\n\t"
        "add	x15, x20, x9\n\t"
        "mov	x14, x20\n\t"
        "mov	x8, #0\n\t"
        "\n"
    "L_cbb_s7_%=:\n\t"
        "cmp	x8, x13\n\t"
        "b.ge	L_cbb_s7e_%=\n\t"
        "ldr	w9, [x15]\n\t"
        "and	x10, x9, #1\n\t"
        "lsr	x11, x23, #3\n\t"
        "add	x11, x19, x11\n\t"
        "ldrb	w12, [x11]\n\t"
        "and	x9, x23, #7\n\t"
        "lsl	x9, x10, x9\n\t"
        "eor	x12, x12, x9\n\t"
        "strb	w12, [x11]\n\t"
        "add	x23, x23, x24\n\t"
        "add	x12, x8, x8\n\t"
        "add	x12, x12, x10\n\t"
        "ldr	w9, [x14]\n\t"
        "lsl	w9, w9, #16\n\t"
        "orr	w9, w9, w12\n\t"
        "str	w9, [x15]\n\t"
        "eor	x12, x12, #1\n\t"
        "add	x16, x14, #4\n\t"
        "ldr	w9, [x16]\n\t"
        "lsl	w9, w9, #16\n\t"
        "orr	w9, w9, w12\n\t"
        "add	x16, x15, #4\n\t"
        "str	w9, [x16]\n\t"
        "add	x14, x14, #8\n\t"
        "add	x15, x15, #8\n\t"
        "add	x8, x8, #1\n\t"
        "b	L_cbb_s7_%=\n\t"
        "\n"
    "L_cbb_s7e_%=:\n\t"
        "lsl	x9, x27, #2\n\t"
        "add	%x[out], x20, x9\n\t"
        "mov	%w[pos0], w27\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_i32_sort_neon\n\t"
#else
        "bl	_wc_mceliece_i32_sort_neon\n\t"
#endif /* __APPLE__ */
        "add	x9, x26, x26\n\t"
        "sub	x9, x9, #3\n\t"
        "mul	x9, x9, x24\n\t"
        "lsr	x10, x27, #1\n\t"
        "mul	x9, x9, x10\n\t"
        "add	x23, x23, x9\n\t"
        "lsr	x13, x27, #1\n\t"
        "lsl	x9, x27, #2\n\t"
        "add	x15, x20, x9\n\t"
        "mov	x14, x20\n\t"
        "mov	x8, #0\n\t"
        "\n"
    "L_cbb_s8_%=:\n\t"
        "cmp	x8, x13\n\t"
        "b.ge	L_cbb_s8e_%=\n\t"
        "ldr	w9, [x15]\n\t"
        "and	x10, x9, #1\n\t"
        "lsr	x11, x23, #3\n\t"
        "add	x11, x19, x11\n\t"
        "ldrb	w12, [x11]\n\t"
        "and	x9, x23, #7\n\t"
        "lsl	x9, x10, x9\n\t"
        "eor	x12, x12, x9\n\t"
        "strb	w12, [x11]\n\t"
        "add	x23, x23, x24\n\t"
        "add	x12, x8, x8\n\t"
        "add	x12, x12, x10\n\t"
        "ldr	w9, [x15]\n\t"
        "and	w9, w9, #0xffff\n\t"
        "lsl	w11, w12, #16\n\t"
        "orr	w9, w9, w11\n\t"
        "str	w9, [x14]\n\t"
        "eor	x12, x12, #1\n\t"
        "add	x16, x15, #4\n\t"
        "ldr	w9, [x16]\n\t"
        "and	w9, w9, #0xffff\n\t"
        "lsl	w11, w12, #16\n\t"
        "orr	w9, w9, w11\n\t"
        "add	x16, x14, #4\n\t"
        "str	w9, [x16]\n\t"
        "add	x14, x14, #8\n\t"
        "add	x15, x15, #8\n\t"
        "add	x8, x8, #1\n\t"
        "b	L_cbb_s8_%=\n\t"
        "\n"
    "L_cbb_s8e_%=:\n\t"
        "mov	%x[out], x20\n\t"
        "mov	%w[pos0], w27\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_i32_sort_neon\n\t"
#else
        "bl	_wc_mceliece_i32_sort_neon\n\t"
#endif /* __APPLE__ */
        "add	x9, x26, x26\n\t"
        "sub	x9, x9, #2\n\t"
        "mul	x9, x9, x24\n\t"
        "lsr	x10, x27, #1\n\t"
        "mul	x9, x9, x10\n\t"
        "sub	x23, x23, x9\n\t"
        "lsr	x10, x27, #2\n\t"
        "add	x9, x27, x10\n\t"
        "lsl	x9, x9, #2\n\t"
        "add	x15, x20, x9\n\t"
        "lsr	x13, x27, #1\n\t"
        "mov	x14, x20\n\t"
        "mov	x8, #0\n\t"
        "\n"
    "L_cbb_s10_%=:\n\t"
        "cmp	x8, x13\n\t"
        "b.ge	L_cbb_s10e_%=\n\t"
        "ldr	w9, [x14]\n\t"
        "and	w9, w9, #0xffff\n\t"
        "lsr	w9, w9, #1\n\t"
        "lsl	x10, x8, #1\n\t"
        "add	x10, x15, x10\n\t"
        "strh	w9, [x10]\n\t"
        "add	x16, x14, #4\n\t"
        "ldr	w9, [x16]\n\t"
        "and	w9, w9, #0xffff\n\t"
        "lsr	w9, w9, #1\n\t"
        "add	x11, x8, x13\n\t"
        "lsl	x11, x11, #1\n\t"
        "add	x11, x15, x11\n\t"
        "strh	w9, [x11]\n\t"
        "add	x14, x14, #8\n\t"
        "add	x8, x8, #1\n\t"
        "b	L_cbb_s10_%=\n\t"
        "\n"
    "L_cbb_s10e_%=:\n\t"
        "lsr	x10, x27, #2\n\t"
        "add	x9, x27, x10\n\t"
        "lsl	x9, x9, #2\n\t"
        "add	x15, x20, x9\n\t"
        "lsr	x13, x27, #1\n\t"
        "add	x12, x24, x24\n\t"
        "sub	x11, x26, #1\n\t"
        "mov	x9, #40\n\t"
        "mul	x10, x22, x9\n\t"
        "add	x16, x21, x10\n\t"
        "add	x9, x23, x24\n\t"
        "str	x9, [x16]\n\t"
        "str	x12, [x16, #8]\n\t"
        "lsl	x9, x13, #1\n\t"
        "add	x9, x15, x9\n\t"
        "str	x9, [x16, #16]\n\t"
        "str	x11, [x16, #24]\n\t"
        "str	x13, [x16, #32]\n\t"
        "add	x22, x22, #1\n\t"
        "mov	x9, #40\n\t"
        "mul	x10, x22, x9\n\t"
        "add	x16, x21, x10\n\t"
        "str	x23, [x16]\n\t"
        "str	x12, [x16, #8]\n\t"
        "str	x15, [x16, #16]\n\t"
        "str	x11, [x16, #24]\n\t"
        "str	x13, [x16, #32]\n\t"
        "add	x22, x22, #1\n\t"
        "b	L_cbb_w_%=\n\t"
        "\n"
    "L_cbb_end_%=:\n\t"
        : [out] "+r" (out), [pos0] "+r" (pos0), [step0] "+r" (step0),
          [w0] "+r" (w0), [n0] "+r" (n0), [temp] "+r" (temp),
          [stack] "+r" (stack)
        : [pi0] "r" (pi0)
        : "memory", "cc", "x19", "x20", "x21", "x22", "x23", "x24", "x25",
            "x26", "x27", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
            "x16", "x30"
    );
}

WOLFSSL_LOCAL int wc_mceliece_bs_fftbuild_neon(void* ctx_p);
int wc_mceliece_bs_fftbuild_neon(void* ctx_p)
{
    register void* ctx __asm__ ("x0") = (void*)ctx_p;
    __asm__ __volatile__ (
        "mov	x19, %x[ctx]\n\t"
        "ldr	x20, [x19, #24]\n\t"
        "ldr	%x[ctx], [x19, #128]\n\t"
        "mov	x1, x20\n\t"
        "ldr	x2, [x19]\n\t"
        "ldr	x7, [x19, #136]\n\t"
        "mov	w3, w7\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_bs_gload_neon\n\t"
#else
        "bl	_wc_mceliece_bs_gload_neon\n\t"
#endif /* __APPLE__ */
        "add	%x[ctx], x20, #0x100\n\t"
        "mov	x1, x20\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_bs_poly_neon\n\t"
#else
        "bl	_wc_mceliece_bs_poly_neon\n\t"
#endif /* __APPLE__ */
        "add	%x[ctx], x20, #0x100\n\t"
        "add	x1, x20, #0xa00\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_radix_conv_neon\n\t"
#else
        "bl	_wc_mceliece_radix_conv_neon\n\t"
#endif /* __APPLE__ */
        "ldr	%x[ctx], [x19, #56]\n\t"
        "add	x1, x20, #0x100\n\t"
        "ldr	x7, [x19, #152]\n\t"
        "mov	w2, w7\n\t"
        "add	x3, x20, #0xa00\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_fft_fwd_butterflies_neon\n\t"
#else
        "bl	_wc_mceliece_fft_fwd_butterflies_neon\n\t"
#endif /* __APPLE__ */
        "ldr	%x[ctx], [x19, #40]\n\t"
        "ldr	x1, [x19, #56]\n\t"
        "add	x2, x20, #0x200\n\t"
        "add	x3, x20, #0x540\n\t"
        "mov	w4, #0\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_mont_batch_inv_neon\n\t"
#else
        "bl	_wc_mceliece_mont_batch_inv_neon\n\t"
#endif /* __APPLE__ */
        "ldr	%x[ctx], [x19, #64]\n\t"
        "ldr	x1, [x19, #40]\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_bs_debitslice_neon\n\t"
#else
        "bl	_wc_mceliece_bs_debitslice_neon\n\t"
#endif /* __APPLE__ */
        "mov	%x[ctx], x20\n\t"
        "ldr	x1, [x19, #8]\n\t"
        "ldr	x2, [x19, #64]\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_bs_packbuf_neon\n\t"
#else
        "bl	_wc_mceliece_bs_packbuf_neon\n\t"
#endif /* __APPLE__ */
        "mov	%x[ctx], x20\n\t"
        "mov	w1, #0x2000\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_u64_sort_neon\n\t"
#else
        "bl	_wc_mceliece_u64_sort_neon\n\t"
#endif /* __APPLE__ */
        "ldr	%x[ctx], [x19, #16]\n\t"
        "mov	x1, x20\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_bs_dup_pi_neon\n\t"
#else
        "bl	_wc_mceliece_bs_dup_pi_neon\n\t"
#endif /* __APPLE__ */
        "cbz	%w[ctx], L_mc_fftb_nd_%=\n\t"
        "mov	w21, #0\n\t"
        "sub	w21, w21, #1\n\t"
        "b	L_mc_fftb_end_%=\n\t"
        "\n"
    "L_mc_fftb_nd_%=:\n\t"
        "ldr	%x[ctx], [x19, #48]\n\t"
        "ldr	x1, [x19, #40]\n\t"
        "mov	x2, x20\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_bs_tobitslice2x_neon\n\t"
#else
        "bl	_wc_mceliece_bs_tobitslice2x_neon\n\t"
#endif /* __APPLE__ */
        "mov	w21, #0\n\t"
        "\n"
    "L_mc_fftb_end_%=:\n\t"
        "mov	%w[ctx], w21\n\t"
        : [ctx] "+r" (ctx)
        :
        : "memory", "cc", "x1", "x2", "x3", "x4", "x5", "x6", "x19", "x20",
            "x21", "x7", "x30"
    );
    return (word32)(size_t)ctx;
}

WOLFSSL_LOCAL void wc_mceliece_u64_sort_neon(word64* x_p, int n_p);
void wc_mceliece_u64_sort_neon(word64* x_p, int n_p)
{
    register word64* x __asm__ ("x0") = (word64*)x_p;
    register int n __asm__ ("w1") = (int)n_p;
    __asm__ __volatile__ (
        "mov	x19, %x[x]\n\t"
        "mov	w20, %w[n]\n\t"
        "cmp	x20, #2\n\t"
        "b.lt	L_mc_us_end_%=\n\t"
        "mov	x21, #1\n\t"
        "\n"
    "L_mc_us_top_%=:\n\t"
        "sub	x4, x20, x21\n\t"
        "cmp	x21, x4\n\t"
        "b.ge	L_mc_us_tope_%=\n\t"
        "lsl	x21, x21, #1\n\t"
        "b	L_mc_us_top_%=\n\t"
        "\n"
    "L_mc_us_tope_%=:\n\t"
        "mov	x22, x21\n\t"
        "\n"
    "L_mc_us_p_%=:\n\t"
        "cbz	x22, L_mc_us_pe_%=\n\t"
        "mov	x27, #0\n\t"
        "\n"
    "L_mc_us_bs_%=:\n\t"
        "sub	x4, x20, x22\n\t"
        "cmp	x27, x4\n\t"
        "b.ge	L_mc_us_bse_%=\n\t"
        "sub	x26, x20, x22\n\t"
        "sub	x26, x26, x27\n\t"
        "cmp	x26, x22\n\t"
        "b.le	L_mc_us_l1_%=\n\t"
        "mov	x26, x22\n\t"
        "\n"
    "L_mc_us_l1_%=:\n\t"
        "lsl	x4, x27, #3\n\t"
        "add	%x[x], x19, x4\n\t"
        "add	x5, x27, x22\n\t"
        "lsl	x5, x5, #3\n\t"
        "add	%x[n], x19, x5\n\t"
        "mov	w2, w26\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_u64_minmax_vec_neon\n\t"
#else
        "bl	_wc_mceliece_u64_minmax_vec_neon\n\t"
#endif /* __APPLE__ */
        "add	x27, x27, x22\n\t"
        "add	x27, x27, x22\n\t"
        "b	L_mc_us_bs_%=\n\t"
        "\n"
    "L_mc_us_bse_%=:\n\t"
        "mov	x25, #0\n\t"
        "mov	x23, x21\n\t"
        "\n"
    "L_mc_us_q_%=:\n\t"
        "cmp	x23, x22\n\t"
        "b.le	L_mc_us_qe_%=\n\t"
        "\n"
    "L_mc_us_w_%=:\n\t"
        "sub	x4, x20, x23\n\t"
        "cmp	x25, x4\n\t"
        "b.ge	L_mc_us_we_%=\n\t"
        "and	x4, x25, x22\n\t"
        "cbz	x4, L_mc_us_sel_%=\n\t"
        "sub	x4, x22, #1\n\t"
        "orr	x25, x25, x4\n\t"
        "add	x25, x25, #1\n\t"
        "b	L_mc_us_w_%=\n\t"
        "\n"
    "L_mc_us_sel_%=:\n\t"
        "neg	x4, x22\n\t"
        "and	x3, x25, x4\n\t"
        "add	x3, x3, x22\n\t"
        "sub	x26, x3, x25\n\t"
        "sub	x5, x20, x23\n\t"
        "cmp	x3, x5\n\t"
        "b.le	L_mc_us_l2_%=\n\t"
        "sub	x26, x5, x25\n\t"
        "\n"
    "L_mc_us_l2_%=:\n\t"
        "mov	x24, x23\n\t"
        "\n"
    "L_mc_us_r_%=:\n\t"
        "cmp	x24, x22\n\t"
        "b.le	L_mc_us_re_%=\n\t"
        "add	x4, x25, x22\n\t"
        "lsl	x4, x4, #3\n\t"
        "add	%x[x], x19, x4\n\t"
        "add	x5, x25, x24\n\t"
        "lsl	x5, x5, #3\n\t"
        "add	%x[n], x19, x5\n\t"
        "mov	w2, w26\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_u64_minmax_vec_neon\n\t"
#else
        "bl	_wc_mceliece_u64_minmax_vec_neon\n\t"
#endif /* __APPLE__ */
        "lsr	x24, x24, #1\n\t"
        "b	L_mc_us_r_%=\n\t"
        "\n"
    "L_mc_us_re_%=:\n\t"
        "add	x25, x25, x26\n\t"
        "b	L_mc_us_w_%=\n\t"
        "\n"
    "L_mc_us_we_%=:\n\t"
        "lsr	x23, x23, #1\n\t"
        "b	L_mc_us_q_%=\n\t"
        "\n"
    "L_mc_us_qe_%=:\n\t"
        "lsr	x22, x22, #1\n\t"
        "b	L_mc_us_p_%=\n\t"
        "\n"
    "L_mc_us_pe_%=:\n\t"
        "\n"
    "L_mc_us_end_%=:\n\t"
        : [x] "+r" (x), [n] "+r" (n)
        :
        : "memory", "cc", "x2", "x19", "x20", "x21", "x22", "x23", "x24", "x25",
            "x26", "x27", "x3", "x4", "x5", "x30"
    );
}

WOLFSSL_LOCAL void wc_mceliece_bs_composeinv_neon(int n_p, sword16* y_p,
    sword16* x_p, sword16* pi_p, word64* scratch_p);
void wc_mceliece_bs_composeinv_neon(int n_p, sword16* y_p, sword16* x_p,
    sword16* pi_p, word64* scratch_p)
{
    register int n __asm__ ("w0") = (int)n_p;
    register sword16* y __asm__ ("x1") = (sword16*)y_p;
    register sword16* x __asm__ ("x2") = (sword16*)x_p;
    register sword16* pi __asm__ ("x3") = (sword16*)pi_p;
    register word64* scratch __asm__ ("x4") = (word64*)scratch_p;
    __asm__ __volatile__ (
        "mov	w19, %w[n]\n\t"
        "mov	x20, %x[y]\n\t"
        "mov	x21, %x[scratch]\n\t"
        "mov	x6, %x[x]\n\t"
        "mov	x7, %x[pi]\n\t"
        "mov	x8, %x[scratch]\n\t"
        "mov	x5, #0\n\t"
        "\n"
    "L_mc_cinv_p_%=:\n\t"
        "cmp	x5, x19\n\t"
        "b.ge	L_mc_cinv_pe_%=\n\t"
        "ldrh	w9, [x7]\n\t"
        "lsl	x9, x9, #16\n\t"
        "ldrh	w10, [x6]\n\t"
        "orr	x9, x9, x10\n\t"
        "str	x9, [x8]\n\t"
        "add	x6, x6, #2\n\t"
        "add	x7, x7, #2\n\t"
        "add	x8, x8, #8\n\t"
        "add	x5, x5, #1\n\t"
        "b	L_mc_cinv_p_%=\n\t"
        "\n"
    "L_mc_cinv_pe_%=:\n\t"
        "mov	%x[n], x21\n\t"
        "mov	%w[y], w19\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_u64_sort_neon\n\t"
#else
        "bl	_wc_mceliece_u64_sort_neon\n\t"
#endif /* __APPLE__ */
        "mov	x8, x21\n\t"
        "mov	x6, x20\n\t"
        "mov	x5, #0\n\t"
        "\n"
    "L_mc_cinv_u_%=:\n\t"
        "cmp	x5, x19\n\t"
        "b.ge	L_mc_cinv_ue_%=\n\t"
        "ldr	x9, [x8]\n\t"
        "strh	w9, [x6]\n\t"
        "add	x8, x8, #8\n\t"
        "add	x6, x6, #2\n\t"
        "add	x5, x5, #1\n\t"
        "b	L_mc_cinv_u_%=\n\t"
        "\n"
    "L_mc_cinv_ue_%=:\n\t"
        : [n] "+r" (n), [y] "+r" (y), [x] "+r" (x), [pi] "+r" (pi),
          [scratch] "+r" (scratch)
        :
        : "memory", "cc", "x19", "x20", "x21", "x5", "x6", "x7", "x8", "x9",
            "x10", "x30"
    );
}

WOLFSSL_LOCAL int wc_mceliece_controlbits_neon(byte* out_p, const sword16* pi_p,
    int w_p, int n_p, sword32* temp_p, sword16* pi_test_p, void* frames_p);
int wc_mceliece_controlbits_neon(byte* out_p, const sword16* pi_p, int w_p,
    int n_p, sword32* temp_p, sword16* pi_test_p, void* frames_p)
{
    register byte* out __asm__ ("x0") = (byte*)out_p;
    register const sword16* pi __asm__ ("x1") = (const sword16*)pi_p;
    register int w __asm__ ("w2") = (int)w_p;
    register int n __asm__ ("w3") = (int)n_p;
    register sword32* temp __asm__ ("x4") = (sword32*)temp_p;
    register sword16* pi_test __asm__ ("x5") = (sword16*)pi_test_p;
    register void* frames __asm__ ("x6") = (void*)frames_p;
    __asm__ __volatile__ (
        "mov	x19, %x[out]\n\t"
        "mov	x20, %x[pi]\n\t"
        "mov	w21, %w[w]\n\t"
        "mov	w22, %w[n]\n\t"
        "mov	x23, %x[temp]\n\t"
        "mov	x24, %x[pi_test]\n\t"
        "mov	x25, %x[frames]\n\t"
        "mov	x12, #0\n\t"
        "mov	x26, #0\n\t"
        "\n"
    "L_mc_cb_o_%=:\n\t"
        "cmp	x26, #2\n\t"
        "b.ge	L_mc_cb_fail_%=\n\t"
        "lsl	x10, x21, #1\n\t"
        "sub	x10, x10, #1\n\t"
        "lsr	x13, x22, #1\n\t"
        "mul	x10, x10, x13\n\t"
        "add	x10, x10, #7\n\t"
        "lsr	x10, x10, #3\n\t"
        "lsr	x11, x10, #3\n\t"
        "mov	x9, x19\n\t"
        "mov	x8, #0\n\t"
        "\n"
    "L_mc_cb_zw_%=:\n\t"
        "cmp	x8, x11\n\t"
        "b.ge	L_mc_cb_zwe_%=\n\t"
        "str	x12, [x9]\n\t"
        "add	x9, x9, #8\n\t"
        "add	x8, x8, #1\n\t"
        "b	L_mc_cb_zw_%=\n\t"
        "\n"
    "L_mc_cb_zwe_%=:\n\t"
        "and	x13, x10, #7\n\t"
        "mov	x8, #0\n\t"
        "\n"
    "L_mc_cb_zb_%=:\n\t"
        "cmp	x8, x13\n\t"
        "b.ge	L_mc_cb_zbe_%=\n\t"
        "strb	w12, [x9]\n\t"
        "add	x9, x9, #1\n\t"
        "add	x8, x8, #1\n\t"
        "b	L_mc_cb_zb_%=\n\t"
        "\n"
    "L_mc_cb_zbe_%=:\n\t"
        "mov	%x[out], x19\n\t"
        "mov	%x[pi], #0\n\t"
        "mov	%x[w], #1\n\t"
        "mov	%x[n], x20\n\t"
        "mov	%x[temp], x21\n\t"
        "mov	%x[pi_test], x22\n\t"
        "mov	%x[frames], x23\n\t"
        "mov	x7, x25\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_cb_build_neon\n\t"
#else
        "bl	_wc_mceliece_cb_build_neon\n\t"
#endif /* __APPLE__ */
        "mov	x9, x24\n\t"
        "mov	x8, #0\n\t"
        "\n"
    "L_mc_cb_pt_%=:\n\t"
        "cmp	x8, x22\n\t"
        "b.ge	L_mc_cb_pte_%=\n\t"
        "strh	w8, [x9]\n\t"
        "add	x9, x9, #2\n\t"
        "add	x8, x8, #1\n\t"
        "b	L_mc_cb_pt_%=\n\t"
        "\n"
    "L_mc_cb_pte_%=:\n\t"
        "mov	x27, x19\n\t"
        "mov	x28, #0\n\t"
        "\n"
    "L_mc_cb_fw_%=:\n\t"
        "cmp	x28, x21\n\t"
        "b.ge	L_mc_cb_fwe_%=\n\t"
        "mov	%x[out], x24\n\t"
        "mov	%x[pi], x27\n\t"
        "mov	%w[w], w28\n\t"
        "mov	%w[n], w22\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_cb_layer_neon\n\t"
#else
        "bl	_wc_mceliece_cb_layer_neon\n\t"
#endif /* __APPLE__ */
        "lsr	x13, x22, #4\n\t"
        "add	x27, x27, x13\n\t"
        "add	x28, x28, #1\n\t"
        "b	L_mc_cb_fw_%=\n\t"
        "\n"
    "L_mc_cb_fwe_%=:\n\t"
        "sub	x28, x21, #2\n\t"
        "\n"
    "L_mc_cb_bw_%=:\n\t"
        "cmp	x28, #0\n\t"
        "b.lt	L_mc_cb_bwe_%=\n\t"
        "mov	%x[out], x24\n\t"
        "mov	%x[pi], x27\n\t"
        "mov	%w[w], w28\n\t"
        "mov	%w[n], w22\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_cb_layer_neon\n\t"
#else
        "bl	_wc_mceliece_cb_layer_neon\n\t"
#endif /* __APPLE__ */
        "lsr	x13, x22, #4\n\t"
        "add	x27, x27, x13\n\t"
        "sub	x28, x28, #1\n\t"
        "b	L_mc_cb_bw_%=\n\t"
        "\n"
    "L_mc_cb_bwe_%=:\n\t"
        "mov	x15, #0\n\t"
        "mov	x8, #0\n\t"
        "\n"
    "L_mc_cb_vf_%=:\n\t"
        "cmp	x8, x22\n\t"
        "b.ge	L_mc_cb_vfe_%=\n\t"
        "lsl	x13, x8, #1\n\t"
        "add	x14, x20, x13\n\t"
        "ldrh	w16, [x14]\n\t"
        "add	x14, x24, x13\n\t"
        "ldrh	w13, [x14]\n\t"
        "eor	x16, x16, x13\n\t"
        "orr	x15, x15, x16\n\t"
        "add	x8, x8, #1\n\t"
        "b	L_mc_cb_vf_%=\n\t"
        "\n"
    "L_mc_cb_vfe_%=:\n\t"
        "cbz	x15, L_mc_cb_ok_%=\n\t"
        "add	x26, x26, #1\n\t"
        "b	L_mc_cb_o_%=\n\t"
        "\n"
    "L_mc_cb_fail_%=:\n\t"
        "mov	%w[out], #0\n\t"
        "sub	%w[out], %w[out], #1\n\t"
        "b	L_mc_cb_end_%=\n\t"
        "\n"
    "L_mc_cb_ok_%=:\n\t"
        "mov	%w[out], #0\n\t"
        "\n"
    "L_mc_cb_end_%=:\n\t"
        : [out] "+r" (out), [w] "+r" (w), [n] "+r" (n), [temp] "+r" (temp),
          [pi_test] "+r" (pi_test), [frames] "+r" (frames)
        : [pi] "r" (pi)
        : "memory", "cc", "x7", "x19", "x20", "x21", "x22", "x23", "x24", "x25",
            "x26", "x27", "x28", "x8", "x9", "x10", "x11", "x12", "x13", "x14",
            "x15", "x16", "x30"
    );
    return (word32)(size_t)out;
}

WOLFSSL_LOCAL void wc_mceliece_bs_extract_neon(byte* pk_p, const byte* tmat_p,
    int mt_p, int tmatStride_p, int nBytes_p);
void wc_mceliece_bs_extract_neon(byte* pk_p, const byte* tmat_p, int mt_p,
    int tmatStride_p, int nBytes_p)
{
    register byte* pk __asm__ ("x0") = (byte*)pk_p;
    register const byte* tmat __asm__ ("x1") = (const byte*)tmat_p;
    register int mt __asm__ ("w2") = (int)mt_p;
    register int tmatStride __asm__ ("w3") = (int)tmatStride_p;
    register int nBytes __asm__ ("w4") = (int)nBytes_p;
    __asm__ __volatile__ (
        "mov	x5, %x[pk]\n\t"
        "mov	x6, %x[tmat]\n\t"
        "mov	w7, %w[mt]\n\t"
        "mov	w8, %w[tmatStride]\n\t"
        "mov	w9, %w[nBytes]\n\t"
        "lsr	x10, x7, #3\n\t"
        "and	x11, x7, #7\n\t"
        "cbz	x11, L_mc_ext_z_%=\n\t"
        "mov	x15, x5\n\t"
        "mov	x12, #0\n\t"
        "\n"
    "L_mc_ext_ti_%=:\n\t"
        "cmp	x12, x7\n\t"
        "b.ge	L_mc_ext_end_%=\n\t"
        "mul	x19, x12, x8\n\t"
        "add	x14, x6, x19\n\t"
        "add	x14, x14, x10\n\t"
        "mov	x13, x10\n\t"
        "\n"
    "L_mc_ext_tj_%=:\n\t"
        "sub	x19, x9, #1\n\t"
        "cmp	x13, x19\n\t"
        "b.ge	L_mc_ext_tjd_%=\n\t"
        "ldrh	w16, [x14]\n\t"
        "lsr	x16, x16, x11\n\t"
        "strb	w16, [x15]\n\t"
        "add	x14, x14, #1\n\t"
        "add	x15, x15, #1\n\t"
        "add	x13, x13, #1\n\t"
        "b	L_mc_ext_tj_%=\n\t"
        "\n"
    "L_mc_ext_tjd_%=:\n\t"
        "ldrb	w16, [x14]\n\t"
        "lsr	x16, x16, x11\n\t"
        "strb	w16, [x15]\n\t"
        "add	x15, x15, #1\n\t"
        "add	x12, x12, #1\n\t"
        "b	L_mc_ext_ti_%=\n\t"
        "\n"
    "L_mc_ext_z_%=:\n\t"
        "sub	x17, x9, x10\n\t"
        "mov	x12, #0\n\t"
        "\n"
    "L_mc_ext_zi_%=:\n\t"
        "cmp	x12, x7\n\t"
        "b.ge	L_mc_ext_end_%=\n\t"
        "mul	x19, x12, x8\n\t"
        "add	x14, x6, x19\n\t"
        "add	x14, x14, x10\n\t"
        "mul	x19, x12, x17\n\t"
        "add	x15, x5, x19\n\t"
        "mov	x13, #0\n\t"
        "\n"
    "L_mc_ext_zj_%=:\n\t"
        "cmp	x13, x17\n\t"
        "b.ge	L_mc_ext_zjd_%=\n\t"
        "ldrb	w16, [x14]\n\t"
        "strb	w16, [x15]\n\t"
        "add	x14, x14, #1\n\t"
        "add	x15, x15, #1\n\t"
        "add	x13, x13, #1\n\t"
        "b	L_mc_ext_zj_%=\n\t"
        "\n"
    "L_mc_ext_zjd_%=:\n\t"
        "add	x12, x12, #1\n\t"
        "b	L_mc_ext_zi_%=\n\t"
        "\n"
    "L_mc_ext_end_%=:\n\t"
        : [pk] "+r" (pk), [mt] "+r" (mt), [tmatStride] "+r" (tmatStride),
          [nBytes] "+r" (nBytes)
        : [tmat] "r" (tmat)
        : "memory", "cc", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12",
            "x13", "x14", "x15", "x16", "x17", "x19"
    );
}

WOLFSSL_LOCAL int wc_mceliece_pk_gen_neon(void* ctx_p);
int wc_mceliece_pk_gen_neon(void* ctx_p)
{
    register void* ctx __asm__ ("x0") = (void*)ctx_p;
    __asm__ __volatile__ (
        "mov	x19, %x[ctx]\n\t"
        "mov	x20, #0\n\t"
        "mov	%x[ctx], x19\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_bs_fftbuild_neon\n\t"
#else
        "bl	_wc_mceliece_bs_fftbuild_neon\n\t"
#endif /* __APPLE__ */
        "mov	w20, %w[ctx]\n\t"
        "cbnz	%w[ctx], L_mc_pkg_end_%=\n\t"
        "ldr	%x[ctx], [x19, #32]\n\t"
        "ldr	x1, [x19, #40]\n\t"
        "ldr	x2, [x19, #48]\n\t"
        "ldr	x14, [x19, #136]\n\t"
        "mov	w3, w14\n\t"
        "mov	w4, #13\n\t"
        "ldr	x8, [x19, #144]\n\t"
        "add	x9, x8, #0xff\n\t"
        "lsr	x9, x9, #8\n\t"
        "lsl	x10, x9, #2\n\t"
        "mov	w5, w9\n\t"
        "mov	w6, w10\n\t"
        "ldr	x7, [x19, #104]\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_bs_lu_fill_neon\n\t"
#else
        "bl	_wc_mceliece_bs_lu_fill_neon\n\t"
#endif /* __APPLE__ */
        "ldr	x8, [x19, #144]\n\t"
        "ldr	x12, [x19, #80]\n\t"
        "ldr	x13, [x19, #88]\n\t"
        "mov	x11, #0\n\t"
        "\n"
    "L_mc_pkg_ii_%=:\n\t"
        "cmp	x11, x8\n\t"
        "b.ge	L_mc_pkg_iid_%=\n\t"
        "strh	w11, [x12]\n\t"
        "strh	w11, [x13]\n\t"
        "add	x12, x12, #2\n\t"
        "add	x13, x13, #2\n\t"
        "add	x11, x11, #1\n\t"
        "b	L_mc_pkg_ii_%=\n\t"
        "\n"
    "L_mc_pkg_iid_%=:\n\t"
        "ldr	%x[ctx], [x19, #32]\n\t"
        "ldr	x1, [x19, #80]\n\t"
        "ldr	x8, [x19, #144]\n\t"
        "mov	w2, w8\n\t"
        "add	x9, x8, #0xff\n\t"
        "lsr	x9, x9, #8\n\t"
        "lsl	x10, x9, #2\n\t"
        "mov	w3, w10\n\t"
        "ldr	x14, [x19, #160]\n\t"
        "mov	w4, w14\n\t"
        "ldr	x5, [x19, #16]\n\t"
        "ldr	x6, [x19, #112]\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_bs_pk_gen_reduce_neon\n\t"
#else
        "bl	_wc_mceliece_bs_pk_gen_reduce_neon\n\t"
#endif /* __APPLE__ */
        "mov	w20, %w[ctx]\n\t"
        "cbnz	%w[ctx], L_mc_pkg_end_%=\n\t"
        "ldr	x8, [x19, #144]\n\t"
        "mov	%w[ctx], w8\n\t"
        "ldr	x1, [x19, #88]\n\t"
        "ldr	x2, [x19, #88]\n\t"
        "ldr	x3, [x19, #80]\n\t"
        "ldr	x4, [x19, #104]\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_bs_composeinv_neon\n\t"
#else
        "bl	_wc_mceliece_bs_composeinv_neon\n\t"
#endif /* __APPLE__ */
        "mov	%x[ctx], x19\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_bs_phase10_neon\n\t"
#else
        "bl	_wc_mceliece_bs_phase10_neon\n\t"
#endif /* __APPLE__ */
        "ldr	%x[ctx], [x19, #120]\n\t"
        "ldr	x1, [x19, #96]\n\t"
        "ldr	x8, [x19, #144]\n\t"
        "mov	w2, w8\n\t"
        "ldr	x14, [x19, #184]\n\t"
        "mov	w3, w14\n\t"
        "ldr	x14, [x19, #192]\n\t"
        "mov	w4, w14\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_bs_extract_neon\n\t"
#else
        "bl	_wc_mceliece_bs_extract_neon\n\t"
#endif /* __APPLE__ */
        "mov	w20, #0\n\t"
        "\n"
    "L_mc_pkg_end_%=:\n\t"
        "mov	%w[ctx], w20\n\t"
        : [ctx] "+r" (ctx)
        :
        : "memory", "cc", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x19",
            "x20", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x30"
    );
    return (word32)(size_t)ctx;
}

WOLFSSL_LOCAL int wc_mceliece_genpoly_neon(word16* out_p, const word16* f_p,
    int t_p, word16* mat_p, word16* prod_p, byte* skp_p, void* ctx_p);
int wc_mceliece_genpoly_neon(word16* out_p, const word16* f_p, int t_p,
    word16* mat_p, word16* prod_p, byte* skp_p, void* ctx_p)
{
    register word16* out __asm__ ("x0") = (word16*)out_p;
    register const word16* f __asm__ ("x1") = (const word16*)f_p;
    register int t __asm__ ("w2") = (int)t_p;
    register word16* mat __asm__ ("x3") = (word16*)mat_p;
    register word16* prod __asm__ ("x4") = (word16*)prod_p;
    register byte* skp __asm__ ("x5") = (byte*)skp_p;
    register void* ctx __asm__ ("x6") = (void*)ctx_p;
    __asm__ __volatile__ (
        "stp	x29, x30, [sp, #-32]!\n\t"
        "add	x29, sp, #0\n\t"
        "mov	x19, %x[out]\n\t"
        "mov	x20, %x[f]\n\t"
        "mov	w21, %w[t]\n\t"
        "mov	x22, %x[mat]\n\t"
        "mov	x23, %x[prod]\n\t"
        "str	%x[skp], [x29, #16]\n\t"
        "mov	x28, %x[ctx]\n\t"
        "mov	w27, #0\n\t"
        "mov	w11, #1\n\t"
        "strh	w11, [x22]\n\t"
        "mov	w11, #0\n\t"
        "mov	x7, #1\n\t"
        "\n"
    "L_mc_gp_c0_%=:\n\t"
        "cmp	x7, x21\n\t"
        "b.ge	L_mc_gp_c0e_%=\n\t"
        "lsl	x9, x7, #1\n\t"
        "add	x10, x22, x9\n\t"
        "strh	w11, [x10]\n\t"
        "add	x7, x7, #1\n\t"
        "b	L_mc_gp_c0_%=\n\t"
        "\n"
    "L_mc_gp_c0e_%=:\n\t"
        "mov	x7, #0\n\t"
        "\n"
    "L_mc_gp_c1_%=:\n\t"
        "cmp	x7, x21\n\t"
        "b.ge	L_mc_gp_c1e_%=\n\t"
        "lsl	x9, x7, #1\n\t"
        "add	x10, x20, x9\n\t"
        "ldrh	w11, [x10]\n\t"
        "add	x8, x21, x7\n\t"
        "lsl	x9, x8, #1\n\t"
        "add	x10, x22, x9\n\t"
        "strh	w11, [x10]\n\t"
        "add	x7, x7, #1\n\t"
        "b	L_mc_gp_c1_%=\n\t"
        "\n"
    "L_mc_gp_c1e_%=:\n\t"
        "mov	x24, #2\n\t"
        "\n"
    "L_mc_gp_j_%=:\n\t"
        "cmp	x24, x21\n\t"
        "b.gt	L_mc_gp_je_%=\n\t"
        "mov	w11, #0\n\t"
        "mov	x7, #0\n\t"
        "lsl	x12, x21, #1\n\t"
        "sub	x12, x12, #1\n\t"
        "\n"
    "L_mc_gp_pz_%=:\n\t"
        "cmp	x7, x12\n\t"
        "b.ge	L_mc_gp_pze_%=\n\t"
        "lsl	x9, x7, #1\n\t"
        "add	x10, x23, x9\n\t"
        "strh	w11, [x10]\n\t"
        "add	x7, x7, #1\n\t"
        "b	L_mc_gp_pz_%=\n\t"
        "\n"
    "L_mc_gp_pze_%=:\n\t"
        "mov	x25, #0\n\t"
        "\n"
    "L_mc_gp_pm_%=:\n\t"
        "cmp	x25, x21\n\t"
        "b.ge	L_mc_gp_pme_%=\n\t"
        "sub	x8, x24, #1\n\t"
        "mul	x8, x8, x21\n\t"
        "add	x8, x8, x25\n\t"
        "lsl	x9, x8, #1\n\t"
        "add	x10, x22, x9\n\t"
        "ldrh	w11, [x10]\n\t"
        "lsl	x9, x25, #1\n\t"
        "add	%x[out], x23, x9\n\t"
        "mov	%w[f], w11\n\t"
        "mov	%x[t], x20\n\t"
        "mov	%w[mat], w21\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_gf_mulc_mac_full_neon\n\t"
#else
        "bl	_wc_mceliece_gf_mulc_mac_full_neon\n\t"
#endif /* __APPLE__ */
        "add	x25, x25, #1\n\t"
        "b	L_mc_gp_pm_%=\n\t"
        "\n"
    "L_mc_gp_pme_%=:\n\t"
        "lsl	x7, x21, #1\n\t"
        "sub	x7, x7, #2\n\t"
        "cmp	x21, #0x77\n\t"
        "b.eq	L_mc_gp_119_%=\n\t"
        "\n"
    "L_mc_gp_rd_%=:\n\t"
        "cmp	x7, x21\n\t"
        "b.lt	L_mc_gp_rde_%=\n\t"
        "lsl	x9, x7, #1\n\t"
        "add	x10, x23, x9\n\t"
        "ldrh	w12, [x10]\n\t"
        "sub	x8, x7, x21\n\t"
        "add	x13, x8, #0\n\t"
        "lsl	x9, x13, #1\n\t"
        "add	x10, x23, x9\n\t"
        "ldrh	w11, [x10]\n\t"
        "eor	w11, w11, w12\n\t"
        "strh	w11, [x10]\n\t"
        "add	x13, x8, #1\n\t"
        "lsl	x9, x13, #1\n\t"
        "add	x10, x23, x9\n\t"
        "ldrh	w11, [x10]\n\t"
        "eor	w11, w11, w12\n\t"
        "strh	w11, [x10]\n\t"
        "add	x13, x8, #2\n\t"
        "lsl	x9, x13, #1\n\t"
        "add	x10, x23, x9\n\t"
        "ldrh	w11, [x10]\n\t"
        "eor	w11, w11, w12\n\t"
        "strh	w11, [x10]\n\t"
        "add	x13, x8, #7\n\t"
        "lsl	x9, x13, #1\n\t"
        "add	x10, x23, x9\n\t"
        "ldrh	w11, [x10]\n\t"
        "eor	w11, w11, w12\n\t"
        "strh	w11, [x10]\n\t"
        "sub	x7, x7, #1\n\t"
        "b	L_mc_gp_rd_%=\n\t"
        "\n"
    "L_mc_gp_119_%=:\n\t"
        "cmp	x7, x21\n\t"
        "b.lt	L_mc_gp_rde_%=\n\t"
        "lsl	x9, x7, #1\n\t"
        "add	x10, x23, x9\n\t"
        "ldrh	w12, [x10]\n\t"
        "sub	x8, x7, x21\n\t"
        "add	x13, x8, #0\n\t"
        "lsl	x9, x13, #1\n\t"
        "add	x10, x23, x9\n\t"
        "ldrh	w11, [x10]\n\t"
        "eor	w11, w11, w12\n\t"
        "strh	w11, [x10]\n\t"
        "add	x13, x8, #8\n\t"
        "lsl	x9, x13, #1\n\t"
        "add	x10, x23, x9\n\t"
        "ldrh	w11, [x10]\n\t"
        "eor	w11, w11, w12\n\t"
        "strh	w11, [x10]\n\t"
        "sub	x7, x7, #1\n\t"
        "b	L_mc_gp_119_%=\n\t"
        "\n"
    "L_mc_gp_rde_%=:\n\t"
        "mul	x12, x24, x21\n\t"
        "mov	x7, #0\n\t"
        "\n"
    "L_mc_gp_cp_%=:\n\t"
        "cmp	x7, x21\n\t"
        "b.ge	L_mc_gp_cpe_%=\n\t"
        "lsl	x9, x7, #1\n\t"
        "add	x10, x23, x9\n\t"
        "ldrh	w11, [x10]\n\t"
        "add	x8, x12, x7\n\t"
        "lsl	x9, x8, #1\n\t"
        "add	x10, x22, x9\n\t"
        "strh	w11, [x10]\n\t"
        "add	x7, x7, #1\n\t"
        "b	L_mc_gp_cp_%=\n\t"
        "\n"
    "L_mc_gp_cpe_%=:\n\t"
        "add	x24, x24, #1\n\t"
        "b	L_mc_gp_j_%=\n\t"
        "\n"
    "L_mc_gp_je_%=:\n\t"
        "mov	x24, #0\n\t"
        "\n"
    "L_mc_gp_e_%=:\n\t"
        "cmp	x24, x21\n\t"
        "b.ge	L_mc_gp_ee_%=\n\t"
        "add	x8, x24, #1\n\t"
        "\n"
    "L_mc_gp_pk_%=:\n\t"
        "cmp	x8, x21\n\t"
        "b.ge	L_mc_gp_pke_%=\n\t"
        "mul	x9, x24, x21\n\t"
        "add	x9, x9, x24\n\t"
        "lsl	x9, x9, #1\n\t"
        "add	x10, x22, x9\n\t"
        "ldrh	w11, [x10]\n\t"
        "sub	w14, w11, #1\n\t"
        "lsr	w14, w14, #31\n\t"
        "neg	w14, w14\n\t"
        "mov	x13, x24\n\t"
        "\n"
    "L_mc_gp_pc_%=:\n\t"
        "cmp	x13, x21\n\t"
        "b.gt	L_mc_gp_pce_%=\n\t"
        "mul	x9, x13, x21\n\t"
        "add	x12, x9, x8\n\t"
        "add	x9, x9, x24\n\t"
        "lsl	x12, x12, #1\n\t"
        "add	x10, x22, x12\n\t"
        "ldrh	w11, [x10]\n\t"
        "and	w11, w11, w14\n\t"
        "lsl	x9, x9, #1\n\t"
        "add	x10, x22, x9\n\t"
        "ldrh	w12, [x10]\n\t"
        "eor	w12, w12, w11\n\t"
        "strh	w12, [x10]\n\t"
        "add	x13, x13, #1\n\t"
        "b	L_mc_gp_pc_%=\n\t"
        "\n"
    "L_mc_gp_pce_%=:\n\t"
        "add	x8, x8, #1\n\t"
        "b	L_mc_gp_pk_%=\n\t"
        "\n"
    "L_mc_gp_pke_%=:\n\t"
        "mul	x9, x24, x21\n\t"
        "add	x9, x9, x24\n\t"
        "lsl	x9, x9, #1\n\t"
        "add	x10, x22, x9\n\t"
        "ldrh	w11, [x10]\n\t"
        "cbz	w11, L_mc_gp_sg_%=\n\t"
        "mov	%w[out], w11\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_gf_inv_scalar_neon\n\t"
#else
        "bl	_wc_mceliece_gf_inv_scalar_neon\n\t"
#endif /* __APPLE__ */
        "mov	w26, %w[out]\n\t"
        "mov	x25, x24\n\t"
        "\n"
    "L_mc_gp_nc_%=:\n\t"
        "cmp	x25, x21\n\t"
        "b.gt	L_mc_gp_nce_%=\n\t"
        "mul	x9, x25, x21\n\t"
        "add	x9, x9, x24\n\t"
        "lsl	x9, x9, #1\n\t"
        "add	x10, x22, x9\n\t"
        "ldrh	%w[out], [x10]\n\t"
        "mov	%w[f], w26\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_gf_mul_scalar_neon\n\t"
#else
        "bl	_wc_mceliece_gf_mul_scalar_neon\n\t"
#endif /* __APPLE__ */
        "mul	x9, x25, x21\n\t"
        "add	x9, x9, x24\n\t"
        "lsl	x9, x9, #1\n\t"
        "add	x10, x22, x9\n\t"
        "strh	%w[out], [x10]\n\t"
        "add	x25, x25, #1\n\t"
        "b	L_mc_gp_nc_%=\n\t"
        "\n"
    "L_mc_gp_nce_%=:\n\t"
        "mov	x7, #0\n\t"
        "\n"
    "L_mc_gp_sv_%=:\n\t"
        "cmp	x7, x21\n\t"
        "b.ge	L_mc_gp_sve_%=\n\t"
        "mul	x9, x24, x21\n\t"
        "add	x9, x9, x7\n\t"
        "lsl	x9, x9, #1\n\t"
        "add	x10, x22, x9\n\t"
        "ldrh	w11, [x10]\n\t"
        "lsl	x9, x7, #1\n\t"
        "add	x10, x23, x9\n\t"
        "strh	w11, [x10]\n\t"
        "add	x7, x7, #1\n\t"
        "b	L_mc_gp_sv_%=\n\t"
        "\n"
    "L_mc_gp_sve_%=:\n\t"
        "mov	w11, #0\n\t"
        "lsl	x9, x24, #1\n\t"
        "add	x10, x23, x9\n\t"
        "strh	w11, [x10]\n\t"
        "mov	x25, x24\n\t"
        "\n"
    "L_mc_gp_el_%=:\n\t"
        "cmp	x25, x21\n\t"
        "b.gt	L_mc_gp_ele_%=\n\t"
        "mul	x9, x25, x21\n\t"
        "add	x8, x9, x24\n\t"
        "lsl	x8, x8, #1\n\t"
        "add	x10, x22, x8\n\t"
        "ldrh	w11, [x10]\n\t"
        "mul	x9, x25, x21\n\t"
        "lsl	x9, x9, #1\n\t"
        "add	%x[out], x22, x9\n\t"
        "mov	%w[f], w11\n\t"
        "mov	%x[t], x23\n\t"
        "mov	%w[mat], w21\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_gf_mulc_mac_full_neon\n\t"
#else
        "bl	_wc_mceliece_gf_mulc_mac_full_neon\n\t"
#endif /* __APPLE__ */
        "add	x25, x25, #1\n\t"
        "b	L_mc_gp_el_%=\n\t"
        "\n"
    "L_mc_gp_ele_%=:\n\t"
        "add	x24, x24, #1\n\t"
        "b	L_mc_gp_e_%=\n\t"
        "\n"
    "L_mc_gp_sg_%=:\n\t"
        "mov	w27, #0\n\t"
        "sub	w27, w27, #1\n\t"
        "b	L_mc_gp_dn_%=\n\t"
        "\n"
    "L_mc_gp_ee_%=:\n\t"
        "mul	x12, x21, x21\n\t"
        "mov	x7, #0\n\t"
        "\n"
    "L_mc_gp_o_%=:\n\t"
        "cmp	x7, x21\n\t"
        "b.ge	L_mc_gp_oe_%=\n\t"
        "add	x8, x12, x7\n\t"
        "lsl	x9, x8, #1\n\t"
        "add	x10, x22, x9\n\t"
        "ldrh	w11, [x10]\n\t"
        "lsl	x9, x7, #1\n\t"
        "add	x10, x19, x9\n\t"
        "strh	w11, [x10]\n\t"
        "add	x7, x7, #1\n\t"
        "b	L_mc_gp_o_%=\n\t"
        "\n"
    "L_mc_gp_oe_%=:\n\t"
        "ldr	x13, [x29, #16]\n\t"
        "lsr	x8, x21, #3\n\t"
        "lsl	x8, x8, #3\n\t"
        "mov	x7, #0\n\t"
        "\n"
    "L_mc_gp_stv_%=:\n\t"
        "cmp	x7, x8\n\t"
        "b.ge	L_mc_gp_stve_%=\n\t"
        "lsl	x9, x7, #1\n\t"
        "add	x10, x19, x9\n\t"
        "ldr	q0, [x10]\n\t"
        "add	x10, x13, x9\n\t"
        "str	q0, [x10]\n\t"
        "add	x7, x7, #8\n\t"
        "b	L_mc_gp_stv_%=\n\t"
        "\n"
    "L_mc_gp_stve_%=:\n\t"
        "\n"
    "L_mc_gp_stg_%=:\n\t"
        "cmp	x7, x21\n\t"
        "b.ge	L_mc_gp_stge_%=\n\t"
        "lsl	x9, x7, #1\n\t"
        "add	x10, x19, x9\n\t"
        "ldrh	w11, [x10]\n\t"
        "add	x10, x13, x9\n\t"
        "strh	w11, [x10]\n\t"
        "add	x7, x7, #1\n\t"
        "b	L_mc_gp_stg_%=\n\t"
        "\n"
    "L_mc_gp_stge_%=:\n\t"
        "mov	%x[out], x28\n\t"
#ifndef __APPLE__
        "bl	wc_mceliece_pk_gen_neon\n\t"
#else
        "bl	_wc_mceliece_pk_gen_neon\n\t"
#endif /* __APPLE__ */
        "mov	w27, %w[out]\n\t"
        "\n"
    "L_mc_gp_dn_%=:\n\t"
        "mov	%w[out], w27\n\t"
        "ldp	x29, x30, [sp], #32\n\t"
        : [out] "+r" (out), [t] "+r" (t), [mat] "+r" (mat), [prod] "+r" (prod),
          [skp] "+r" (skp), [ctx] "+r" (ctx)
        : [f] "r" (f)
        : "memory", "cc", "x19", "x20", "x21", "x22", "x23", "x24", "x25",
            "x26", "x27", "x28", "x7", "x8", "x9", "x10", "x11", "x12", "x13",
            "x14", "v0", "x30"
    );
    return (word32)(size_t)out;
}

#endif /* WOLFSSL_MCELIECE_SMALL */
#endif /* WOLFSSL_MCELIECE_NO_MAKE_KEY */
#endif /* WOLFSSL_HAVE_MCELIECE */
#endif /* __aarch64__ */
#endif /* WOLFSSL_ARMASM */
#endif /* WOLFSSL_ARMASM_INLINE */
