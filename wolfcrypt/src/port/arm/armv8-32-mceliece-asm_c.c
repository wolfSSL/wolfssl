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
 *       /home/sparki/wolfssl/github/mceliece/wolfssl/wolfcrypt/src/port/arm/armv8-32-mceliece-asm.c
 */

#define _WC_BUILDING_ARMV8_32_MCELIECE_ASM_C

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#ifdef WOLFSSL_ARMASM
#if !defined(__aarch64__) && !defined(WOLFSSL_ARMASM_THUMB2)
#ifdef WOLFSSL_ARMASM_INLINE

#ifdef __IAR_SYSTEMS_ICC__
#define __asm__        asm
#define __volatile__   volatile
#define WOLFSSL_NO_VAR_ASSIGN_REG
#endif /* __IAR_SYSTEMS_ICC__ */
#ifdef __KEIL__
#define __asm__        __asm
#define __volatile__   volatile
#endif /* __KEIL__ */
#ifdef __ghs__
#define __asm__        __asm
#define __volatile__
#define WOLFSSL_NO_VAR_ASSIGN_REG
#endif /* __ghs__ */

#include <wolfssl/wolfcrypt/wc_mceliece.h>

#ifdef WOLFSSL_HAVE_MCELIECE
#ifndef WOLFSSL_ARMASM_NO_NEON
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

WOLFSSL_LOCAL int wc_mceliece_gf_mul_scalar_neon(int a, int b);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER int wc_mceliece_gf_mul_scalar_neon(int a_p, int b_p)
#else
WC_OMIT_FRAME_POINTER int wc_mceliece_gf_mul_scalar_neon(int a, int b)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register int a __asm__ ("r0") = (int)a_p;
    register int b __asm__ ("r1") = (int)b_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "mov	r4, %[a]\n\t"
        "mov	r2, #0\n\t"
        "and	r3, %[b], #1\n\t"
        "neg	r3, r3\n\t"
        "and	r12, r4, r3\n\t"
        "eor	r2, r2, r12\n\t"
        "lsr	r3, %[b], #1\n\t"
        "and	r3, r3, #1\n\t"
        "neg	r3, r3\n\t"
        "lsl	r12, r4, #1\n\t"
        "and	r12, r12, r3\n\t"
        "eor	r2, r2, r12\n\t"
        "lsr	r3, %[b], #2\n\t"
        "and	r3, r3, #1\n\t"
        "neg	r3, r3\n\t"
        "lsl	r12, r4, #2\n\t"
        "and	r12, r12, r3\n\t"
        "eor	r2, r2, r12\n\t"
        "lsr	r3, %[b], #3\n\t"
        "and	r3, r3, #1\n\t"
        "neg	r3, r3\n\t"
        "lsl	r12, r4, #3\n\t"
        "and	r12, r12, r3\n\t"
        "eor	r2, r2, r12\n\t"
        "lsr	r3, %[b], #4\n\t"
        "and	r3, r3, #1\n\t"
        "neg	r3, r3\n\t"
        "lsl	r12, r4, #4\n\t"
        "and	r12, r12, r3\n\t"
        "eor	r2, r2, r12\n\t"
        "lsr	r3, %[b], #5\n\t"
        "and	r3, r3, #1\n\t"
        "neg	r3, r3\n\t"
        "lsl	r12, r4, #5\n\t"
        "and	r12, r12, r3\n\t"
        "eor	r2, r2, r12\n\t"
        "lsr	r3, %[b], #6\n\t"
        "and	r3, r3, #1\n\t"
        "neg	r3, r3\n\t"
        "lsl	r12, r4, #6\n\t"
        "and	r12, r12, r3\n\t"
        "eor	r2, r2, r12\n\t"
        "lsr	r3, %[b], #7\n\t"
        "and	r3, r3, #1\n\t"
        "neg	r3, r3\n\t"
        "lsl	r12, r4, #7\n\t"
        "and	r12, r12, r3\n\t"
        "eor	r2, r2, r12\n\t"
        "lsr	r3, %[b], #8\n\t"
        "and	r3, r3, #1\n\t"
        "neg	r3, r3\n\t"
        "lsl	r12, r4, #8\n\t"
        "and	r12, r12, r3\n\t"
        "eor	r2, r2, r12\n\t"
        "lsr	r3, %[b], #9\n\t"
        "and	r3, r3, #1\n\t"
        "neg	r3, r3\n\t"
        "lsl	r12, r4, #9\n\t"
        "and	r12, r12, r3\n\t"
        "eor	r2, r2, r12\n\t"
        "lsr	r3, %[b], #10\n\t"
        "and	r3, r3, #1\n\t"
        "neg	r3, r3\n\t"
        "lsl	r12, r4, #10\n\t"
        "and	r12, r12, r3\n\t"
        "eor	r2, r2, r12\n\t"
        "lsr	r3, %[b], #11\n\t"
        "and	r3, r3, #1\n\t"
        "neg	r3, r3\n\t"
        "lsl	r12, r4, #11\n\t"
        "and	r12, r12, r3\n\t"
        "eor	r2, r2, r12\n\t"
        "lsr	r3, %[b], #12\n\t"
        "and	r3, r3, #1\n\t"
        "neg	r3, r3\n\t"
        "lsl	r12, r4, #12\n\t"
        "and	r12, r12, r3\n\t"
        "eor	r2, r2, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r5, #0xff\n\t"
        "orr	r5, r5, #0x100\n\t"
#else
        "mov	r5, #0x1ff\n\t"
#endif
        "lsl	r5, r5, #16\n\t"
        "and	r12, r2, r5\n\t"
        "lsr	lr, r12, #9\n\t"
        "eor	r2, r2, lr\n\t"
        "lsr	lr, r12, #10\n\t"
        "eor	r2, r2, lr\n\t"
        "lsr	lr, r12, #12\n\t"
        "eor	r2, r2, lr\n\t"
        "lsr	lr, r12, #13\n\t"
        "eor	r2, r2, lr\n\t"
        "mov	r5, #0xe000\n\t"
        "and	r12, r2, r5\n\t"
        "lsr	lr, r12, #9\n\t"
        "eor	r2, r2, lr\n\t"
        "lsr	lr, r12, #10\n\t"
        "eor	r2, r2, lr\n\t"
        "lsr	lr, r12, #12\n\t"
        "eor	r2, r2, lr\n\t"
        "lsr	lr, r12, #13\n\t"
        "eor	r2, r2, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r5, #0xff\n\t"
        "orr	r5, r5, #0x1f00\n\t"
#else
        "mov	r5, #0x1fff\n\t"
#endif
        "and	%[a], r2, r5\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [a] "+r" (a), [b] "+r" (b)
        :
#else
        :
        : [a] "r" (a), [b] "r" (b)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r2", "r3", "r12", "lr", "r4", "r5"
    );
    return (word32)(size_t)a;
}

WOLFSSL_LOCAL int wc_mceliece_gf_inv_scalar_neon(int a, int b);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER int wc_mceliece_gf_inv_scalar_neon(int a_p, int b_p)
#else
WC_OMIT_FRAME_POINTER int wc_mceliece_gf_inv_scalar_neon(int a, int b)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register int a __asm__ ("r0") = (int)a_p;
    register int b __asm__ ("r1") = (int)b_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "mov	r4, %[a]\n\t"
        "mov	%[b], %[a]\n\t"
        "bl	wc_mceliece_gf_mul_scalar_neon\n\t"
        "mov	%[b], r4\n\t"
        "bl	wc_mceliece_gf_mul_scalar_neon\n\t"
        "mov	r5, %[a]\n\t"
        "mov	%[b], %[a]\n\t"
        "bl	wc_mceliece_gf_mul_scalar_neon\n\t"
        "mov	%[b], %[a]\n\t"
        "bl	wc_mceliece_gf_mul_scalar_neon\n\t"
        "mov	%[b], r5\n\t"
        "bl	wc_mceliece_gf_mul_scalar_neon\n\t"
        "mov	r6, %[a]\n\t"
        "mov	%[b], %[a]\n\t"
        "bl	wc_mceliece_gf_mul_scalar_neon\n\t"
        "mov	%[b], %[a]\n\t"
        "bl	wc_mceliece_gf_mul_scalar_neon\n\t"
        "mov	%[b], %[a]\n\t"
        "bl	wc_mceliece_gf_mul_scalar_neon\n\t"
        "mov	%[b], %[a]\n\t"
        "bl	wc_mceliece_gf_mul_scalar_neon\n\t"
        "mov	%[b], r6\n\t"
        "bl	wc_mceliece_gf_mul_scalar_neon\n\t"
        "mov	%[b], %[a]\n\t"
        "bl	wc_mceliece_gf_mul_scalar_neon\n\t"
        "mov	%[b], %[a]\n\t"
        "bl	wc_mceliece_gf_mul_scalar_neon\n\t"
        "mov	%[b], %[a]\n\t"
        "bl	wc_mceliece_gf_mul_scalar_neon\n\t"
        "mov	%[b], %[a]\n\t"
        "bl	wc_mceliece_gf_mul_scalar_neon\n\t"
        "mov	%[b], r6\n\t"
        "bl	wc_mceliece_gf_mul_scalar_neon\n\t"
        "mov	%[b], %[a]\n\t"
        "bl	wc_mceliece_gf_mul_scalar_neon\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [a] "+r" (a), [b] "+r" (b)
        :
#else
        :
        : [a] "r" (a), [b] "r" (b)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "lr", "r4", "r5", "r6"
    );
    return (word32)(size_t)a;
}

WOLFSSL_LOCAL void wc_mceliece_gf_mulc_mac_neon(word16* dst, int scalar,
    const word16* src, int count);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_gf_mulc_mac_neon(word16* dst_p,
    int scalar_p, const word16* src_p, int count_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_gf_mulc_mac_neon(word16* dst, int scalar,
    const word16* src, int count)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word16* dst __asm__ ("r0") = (word16*)dst_p;
    register int scalar __asm__ ("r1") = (int)scalar_p;
    register const word16* src __asm__ ("r2") = (const word16*)src_p;
    register int count __asm__ ("r3") = (int)count_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r4, #0xff\n\t"
        "orr	r4, r4, #0x100\n\t"
#else
        "mov	r4, #0x1ff\n\t"
#endif
        "vdup.32	q0, r4\n\t"
        "vshl.i32	q0, q0, #16\n\t"
        "mov	r4, #0xe000\n\t"
        "vdup.32	q1, r4\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r4, #0xff\n\t"
        "orr	r4, r4, #0x1f00\n\t"
#else
        "mov	r4, #0x1fff\n\t"
#endif
        "vdup.32	q2, r4\n\t"
        "vdup.32	q3, %[scalar]\n\t"
        "mov	r12, #0\n\t"
        "\n"
    "L_mc_gmm_%=:\n\t"
        "cmp	r12, %[count]\n\t"
        "bge	L_mc_gmme_%=\n\t"
        "lsl	lr, r12, #1\n\t"
        "add	r4, %[src], lr\n\t"
        "vld1.8	{d8-d9}, [r4]\n\t"
        "vmovl.u16	q5, d8\n\t"
        "vshl.i32	q9, q3, #31\n\t"
        "vshr.s32	q9, q9, #31\n\t"
        "vand	q6, q5, q9\n\t"
        "vshl.i32	q9, q3, #30\n\t"
        "vshr.s32	q9, q9, #31\n\t"
        "vshl.i32	q8, q5, #1\n\t"
        "vand	q8, q8, q9\n\t"
        "veor	q6, q6, q8\n\t"
        "vshl.i32	q9, q3, #29\n\t"
        "vshr.s32	q9, q9, #31\n\t"
        "vshl.i32	q8, q5, #2\n\t"
        "vand	q8, q8, q9\n\t"
        "veor	q6, q6, q8\n\t"
        "vshl.i32	q9, q3, #28\n\t"
        "vshr.s32	q9, q9, #31\n\t"
        "vshl.i32	q8, q5, #3\n\t"
        "vand	q8, q8, q9\n\t"
        "veor	q6, q6, q8\n\t"
        "vshl.i32	q9, q3, #27\n\t"
        "vshr.s32	q9, q9, #31\n\t"
        "vshl.i32	q8, q5, #4\n\t"
        "vand	q8, q8, q9\n\t"
        "veor	q6, q6, q8\n\t"
        "vshl.i32	q9, q3, #26\n\t"
        "vshr.s32	q9, q9, #31\n\t"
        "vshl.i32	q8, q5, #5\n\t"
        "vand	q8, q8, q9\n\t"
        "veor	q6, q6, q8\n\t"
        "vshl.i32	q9, q3, #25\n\t"
        "vshr.s32	q9, q9, #31\n\t"
        "vshl.i32	q8, q5, #6\n\t"
        "vand	q8, q8, q9\n\t"
        "veor	q6, q6, q8\n\t"
        "vshl.i32	q9, q3, #24\n\t"
        "vshr.s32	q9, q9, #31\n\t"
        "vshl.i32	q8, q5, #7\n\t"
        "vand	q8, q8, q9\n\t"
        "veor	q6, q6, q8\n\t"
        "vshl.i32	q9, q3, #23\n\t"
        "vshr.s32	q9, q9, #31\n\t"
        "vshl.i32	q8, q5, #8\n\t"
        "vand	q8, q8, q9\n\t"
        "veor	q6, q6, q8\n\t"
        "vshl.i32	q9, q3, #22\n\t"
        "vshr.s32	q9, q9, #31\n\t"
        "vshl.i32	q8, q5, #9\n\t"
        "vand	q8, q8, q9\n\t"
        "veor	q6, q6, q8\n\t"
        "vshl.i32	q9, q3, #21\n\t"
        "vshr.s32	q9, q9, #31\n\t"
        "vshl.i32	q8, q5, #10\n\t"
        "vand	q8, q8, q9\n\t"
        "veor	q6, q6, q8\n\t"
        "vshl.i32	q9, q3, #20\n\t"
        "vshr.s32	q9, q9, #31\n\t"
        "vshl.i32	q8, q5, #11\n\t"
        "vand	q8, q8, q9\n\t"
        "veor	q6, q6, q8\n\t"
        "vshl.i32	q9, q3, #19\n\t"
        "vshr.s32	q9, q9, #31\n\t"
        "vshl.i32	q8, q5, #12\n\t"
        "vand	q8, q8, q9\n\t"
        "veor	q6, q6, q8\n\t"
        "vand	q10, q6, q0\n\t"
        "vshr.u32	q11, q10, #9\n\t"
        "veor	q6, q6, q11\n\t"
        "vshr.u32	q11, q10, #10\n\t"
        "veor	q6, q6, q11\n\t"
        "vshr.u32	q11, q10, #12\n\t"
        "veor	q6, q6, q11\n\t"
        "vshr.u32	q11, q10, #13\n\t"
        "veor	q6, q6, q11\n\t"
        "vand	q10, q6, q1\n\t"
        "vshr.u32	q11, q10, #9\n\t"
        "veor	q6, q6, q11\n\t"
        "vshr.u32	q11, q10, #10\n\t"
        "veor	q6, q6, q11\n\t"
        "vshr.u32	q11, q10, #12\n\t"
        "veor	q6, q6, q11\n\t"
        "vshr.u32	q11, q10, #13\n\t"
        "veor	q6, q6, q11\n\t"
        "vand	q6, q6, q2\n\t"
        "vmovl.u16	q5, d9\n\t"
        "vshl.i32	q9, q3, #31\n\t"
        "vshr.s32	q9, q9, #31\n\t"
        "vand	q7, q5, q9\n\t"
        "vshl.i32	q9, q3, #30\n\t"
        "vshr.s32	q9, q9, #31\n\t"
        "vshl.i32	q8, q5, #1\n\t"
        "vand	q8, q8, q9\n\t"
        "veor	q7, q7, q8\n\t"
        "vshl.i32	q9, q3, #29\n\t"
        "vshr.s32	q9, q9, #31\n\t"
        "vshl.i32	q8, q5, #2\n\t"
        "vand	q8, q8, q9\n\t"
        "veor	q7, q7, q8\n\t"
        "vshl.i32	q9, q3, #28\n\t"
        "vshr.s32	q9, q9, #31\n\t"
        "vshl.i32	q8, q5, #3\n\t"
        "vand	q8, q8, q9\n\t"
        "veor	q7, q7, q8\n\t"
        "vshl.i32	q9, q3, #27\n\t"
        "vshr.s32	q9, q9, #31\n\t"
        "vshl.i32	q8, q5, #4\n\t"
        "vand	q8, q8, q9\n\t"
        "veor	q7, q7, q8\n\t"
        "vshl.i32	q9, q3, #26\n\t"
        "vshr.s32	q9, q9, #31\n\t"
        "vshl.i32	q8, q5, #5\n\t"
        "vand	q8, q8, q9\n\t"
        "veor	q7, q7, q8\n\t"
        "vshl.i32	q9, q3, #25\n\t"
        "vshr.s32	q9, q9, #31\n\t"
        "vshl.i32	q8, q5, #6\n\t"
        "vand	q8, q8, q9\n\t"
        "veor	q7, q7, q8\n\t"
        "vshl.i32	q9, q3, #24\n\t"
        "vshr.s32	q9, q9, #31\n\t"
        "vshl.i32	q8, q5, #7\n\t"
        "vand	q8, q8, q9\n\t"
        "veor	q7, q7, q8\n\t"
        "vshl.i32	q9, q3, #23\n\t"
        "vshr.s32	q9, q9, #31\n\t"
        "vshl.i32	q8, q5, #8\n\t"
        "vand	q8, q8, q9\n\t"
        "veor	q7, q7, q8\n\t"
        "vshl.i32	q9, q3, #22\n\t"
        "vshr.s32	q9, q9, #31\n\t"
        "vshl.i32	q8, q5, #9\n\t"
        "vand	q8, q8, q9\n\t"
        "veor	q7, q7, q8\n\t"
        "vshl.i32	q9, q3, #21\n\t"
        "vshr.s32	q9, q9, #31\n\t"
        "vshl.i32	q8, q5, #10\n\t"
        "vand	q8, q8, q9\n\t"
        "veor	q7, q7, q8\n\t"
        "vshl.i32	q9, q3, #20\n\t"
        "vshr.s32	q9, q9, #31\n\t"
        "vshl.i32	q8, q5, #11\n\t"
        "vand	q8, q8, q9\n\t"
        "veor	q7, q7, q8\n\t"
        "vshl.i32	q9, q3, #19\n\t"
        "vshr.s32	q9, q9, #31\n\t"
        "vshl.i32	q8, q5, #12\n\t"
        "vand	q8, q8, q9\n\t"
        "veor	q7, q7, q8\n\t"
        "vand	q10, q7, q0\n\t"
        "vshr.u32	q11, q10, #9\n\t"
        "veor	q7, q7, q11\n\t"
        "vshr.u32	q11, q10, #10\n\t"
        "veor	q7, q7, q11\n\t"
        "vshr.u32	q11, q10, #12\n\t"
        "veor	q7, q7, q11\n\t"
        "vshr.u32	q11, q10, #13\n\t"
        "veor	q7, q7, q11\n\t"
        "vand	q10, q7, q1\n\t"
        "vshr.u32	q11, q10, #9\n\t"
        "veor	q7, q7, q11\n\t"
        "vshr.u32	q11, q10, #10\n\t"
        "veor	q7, q7, q11\n\t"
        "vshr.u32	q11, q10, #12\n\t"
        "veor	q7, q7, q11\n\t"
        "vshr.u32	q11, q10, #13\n\t"
        "veor	q7, q7, q11\n\t"
        "vand	q7, q7, q2\n\t"
        "vmovn.i32	d20, q6\n\t"
        "vmovn.i32	d21, q7\n\t"
        "add	r4, %[dst], lr\n\t"
        "vld1.8	{d12-d13}, [r4]\n\t"
        "veor	q10, q10, q6\n\t"
        "vst1.8	{d20-d21}, [r4]\n\t"
        "add	r12, r12, #8\n\t"
        "b	L_mc_gmm_%=\n\t"
        "\n"
    "L_mc_gmme_%=:\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [dst] "+r" (dst), [scalar] "+r" (scalar), [src] "+r" (src),
          [count] "+r" (count)
        :
#else
        :
        : [dst] "r" (dst), [scalar] "r" (scalar), [src] "r" (src),
          [count] "r" (count)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r12", "lr", "r4", "q0", "q1", "q2", "q3", "q4", "q5",
            "q6", "q7", "q8", "q9", "q10", "q11"
    );
}

WOLFSSL_LOCAL void wc_mceliece_gf_mulc_mac_full_neon(word16* dst, int scalar,
    const word16* src, int count);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_gf_mulc_mac_full_neon(word16* dst_p,
    int scalar_p, const word16* src_p, int count_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_gf_mulc_mac_full_neon(word16* dst,
    int scalar, const word16* src, int count)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word16* dst __asm__ ("r0") = (word16*)dst_p;
    register int scalar __asm__ ("r1") = (int)scalar_p;
    register const word16* src __asm__ ("r2") = (const word16*)src_p;
    register int count __asm__ ("r3") = (int)count_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "mov	r4, %[dst]\n\t"
        "mov	r5, %[scalar]\n\t"
        "mov	r6, %[src]\n\t"
        "mov	r7, %[count]\n\t"
        "lsr	r12, r7, #3\n\t"
        "lsl	r12, r12, #3\n\t"
        "cmp	r12, #0\n\t"
        "beq	L_mc_mmf_s_%=\n\t"
        "mov	%[dst], r4\n\t"
        "mov	%[scalar], r5\n\t"
        "mov	%[src], r6\n\t"
        "mov	%[count], r12\n\t"
        "bl	wc_mceliece_gf_mulc_mac_neon\n\t"
        "\n"
    "L_mc_mmf_s_%=:\n\t"
        "lsr	r12, r7, #3\n\t"
        "lsl	r12, r12, #3\n\t"
        "mov	r8, r12\n\t"
        "\n"
    "L_mc_mmf_t_%=:\n\t"
        "cmp	r8, r7\n\t"
        "bge	L_mc_mmf_te_%=\n\t"
        "mov	%[dst], r5\n\t"
        "lsl	r9, r8, #1\n\t"
        "add	r10, r6, r9\n\t"
        "ldrh	%[scalar], [r10]\n\t"
        "bl	wc_mceliece_gf_mul_scalar_neon\n\t"
        "lsl	r9, r8, #1\n\t"
        "add	r10, r4, r9\n\t"
        "ldrh	r11, [r10]\n\t"
        "eor	r11, r11, %[dst]\n\t"
        "strh	r11, [r10]\n\t"
        "add	r8, r8, #1\n\t"
        "b	L_mc_mmf_t_%=\n\t"
        "\n"
    "L_mc_mmf_te_%=:\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [dst] "+r" (dst), [scalar] "+r" (scalar), [src] "+r" (src),
          [count] "+r" (count)
        :
#else
        :
        : [dst] "r" (dst), [scalar] "r" (scalar), [src] "r" (src),
          [count] "r" (count)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "lr", "r4", "r5", "r6", "r7", "r8", "r12", "r9",
            "r10", "r11"
    );
}

WOLFSSL_LOCAL int wc_mceliece_gf_discrepancy_neon(const word16* c,
    const word16* sn, int count);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER int wc_mceliece_gf_discrepancy_neon(const word16* c_p,
    const word16* sn_p, int count_p)
#else
WC_OMIT_FRAME_POINTER int wc_mceliece_gf_discrepancy_neon(const word16* c,
    const word16* sn, int count)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register const word16* c __asm__ ("r0") = (const word16*)c_p;
    register const word16* sn __asm__ ("r1") = (const word16*)sn_p;
    register int count __asm__ ("r2") = (int)count_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "veor	q13, q13, q13\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	lr, #0xff\n\t"
        "orr	lr, lr, #0x100\n\t"
#else
        "mov	lr, #0x1ff\n\t"
#endif
        "vdup.32	q0, lr\n\t"
        "vshl.i32	q0, q0, #16\n\t"
        "mov	lr, #0xe000\n\t"
        "vdup.32	q1, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	lr, #0xff\n\t"
        "orr	lr, lr, #0x1f00\n\t"
#else
        "mov	lr, #0x1fff\n\t"
#endif
        "vdup.32	q2, lr\n\t"
        "mov	r3, #0\n\t"
        "\n"
    "L_mc_gdc_%=:\n\t"
        "cmp	r3, %[count]\n\t"
        "bge	L_mc_gdce_%=\n\t"
        "lsl	lr, r3, #1\n\t"
        "add	r12, %[c], lr\n\t"
        "vld1.8	{d6-d7}, [r12]\n\t"
        "add	lr, r3, #7\n\t"
        "lsl	lr, lr, #1\n\t"
        "sub	r12, %[sn], lr\n\t"
        "vld1.8	{d8-d9}, [r12]\n\t"
        "vrev64.16	q4, q4\n\t"
        "vext.8	q4, q4, q4, #8\n\t"
        "vmovl.u16	q5, d6\n\t"
        "vmovl.u16	q6, d8\n\t"
        "vshl.i32	q10, q6, #31\n\t"
        "vshr.s32	q10, q10, #31\n\t"
        "vand	q7, q5, q10\n\t"
        "vshl.i32	q10, q6, #30\n\t"
        "vshr.s32	q10, q10, #31\n\t"
        "vshl.i32	q9, q5, #1\n\t"
        "vand	q9, q9, q10\n\t"
        "veor	q7, q7, q9\n\t"
        "vshl.i32	q10, q6, #29\n\t"
        "vshr.s32	q10, q10, #31\n\t"
        "vshl.i32	q9, q5, #2\n\t"
        "vand	q9, q9, q10\n\t"
        "veor	q7, q7, q9\n\t"
        "vshl.i32	q10, q6, #28\n\t"
        "vshr.s32	q10, q10, #31\n\t"
        "vshl.i32	q9, q5, #3\n\t"
        "vand	q9, q9, q10\n\t"
        "veor	q7, q7, q9\n\t"
        "vshl.i32	q10, q6, #27\n\t"
        "vshr.s32	q10, q10, #31\n\t"
        "vshl.i32	q9, q5, #4\n\t"
        "vand	q9, q9, q10\n\t"
        "veor	q7, q7, q9\n\t"
        "vshl.i32	q10, q6, #26\n\t"
        "vshr.s32	q10, q10, #31\n\t"
        "vshl.i32	q9, q5, #5\n\t"
        "vand	q9, q9, q10\n\t"
        "veor	q7, q7, q9\n\t"
        "vshl.i32	q10, q6, #25\n\t"
        "vshr.s32	q10, q10, #31\n\t"
        "vshl.i32	q9, q5, #6\n\t"
        "vand	q9, q9, q10\n\t"
        "veor	q7, q7, q9\n\t"
        "vshl.i32	q10, q6, #24\n\t"
        "vshr.s32	q10, q10, #31\n\t"
        "vshl.i32	q9, q5, #7\n\t"
        "vand	q9, q9, q10\n\t"
        "veor	q7, q7, q9\n\t"
        "vshl.i32	q10, q6, #23\n\t"
        "vshr.s32	q10, q10, #31\n\t"
        "vshl.i32	q9, q5, #8\n\t"
        "vand	q9, q9, q10\n\t"
        "veor	q7, q7, q9\n\t"
        "vshl.i32	q10, q6, #22\n\t"
        "vshr.s32	q10, q10, #31\n\t"
        "vshl.i32	q9, q5, #9\n\t"
        "vand	q9, q9, q10\n\t"
        "veor	q7, q7, q9\n\t"
        "vshl.i32	q10, q6, #21\n\t"
        "vshr.s32	q10, q10, #31\n\t"
        "vshl.i32	q9, q5, #10\n\t"
        "vand	q9, q9, q10\n\t"
        "veor	q7, q7, q9\n\t"
        "vshl.i32	q10, q6, #20\n\t"
        "vshr.s32	q10, q10, #31\n\t"
        "vshl.i32	q9, q5, #11\n\t"
        "vand	q9, q9, q10\n\t"
        "veor	q7, q7, q9\n\t"
        "vshl.i32	q10, q6, #19\n\t"
        "vshr.s32	q10, q10, #31\n\t"
        "vshl.i32	q9, q5, #12\n\t"
        "vand	q9, q9, q10\n\t"
        "veor	q7, q7, q9\n\t"
        "vand	q11, q7, q0\n\t"
        "vshr.u32	q12, q11, #9\n\t"
        "veor	q7, q7, q12\n\t"
        "vshr.u32	q12, q11, #10\n\t"
        "veor	q7, q7, q12\n\t"
        "vshr.u32	q12, q11, #12\n\t"
        "veor	q7, q7, q12\n\t"
        "vshr.u32	q12, q11, #13\n\t"
        "veor	q7, q7, q12\n\t"
        "vand	q11, q7, q1\n\t"
        "vshr.u32	q12, q11, #9\n\t"
        "veor	q7, q7, q12\n\t"
        "vshr.u32	q12, q11, #10\n\t"
        "veor	q7, q7, q12\n\t"
        "vshr.u32	q12, q11, #12\n\t"
        "veor	q7, q7, q12\n\t"
        "vshr.u32	q12, q11, #13\n\t"
        "veor	q7, q7, q12\n\t"
        "vand	q7, q7, q2\n\t"
        "vmovl.u16	q5, d7\n\t"
        "vmovl.u16	q6, d9\n\t"
        "vshl.i32	q10, q6, #31\n\t"
        "vshr.s32	q10, q10, #31\n\t"
        "vand	q8, q5, q10\n\t"
        "vshl.i32	q10, q6, #30\n\t"
        "vshr.s32	q10, q10, #31\n\t"
        "vshl.i32	q9, q5, #1\n\t"
        "vand	q9, q9, q10\n\t"
        "veor	q8, q8, q9\n\t"
        "vshl.i32	q10, q6, #29\n\t"
        "vshr.s32	q10, q10, #31\n\t"
        "vshl.i32	q9, q5, #2\n\t"
        "vand	q9, q9, q10\n\t"
        "veor	q8, q8, q9\n\t"
        "vshl.i32	q10, q6, #28\n\t"
        "vshr.s32	q10, q10, #31\n\t"
        "vshl.i32	q9, q5, #3\n\t"
        "vand	q9, q9, q10\n\t"
        "veor	q8, q8, q9\n\t"
        "vshl.i32	q10, q6, #27\n\t"
        "vshr.s32	q10, q10, #31\n\t"
        "vshl.i32	q9, q5, #4\n\t"
        "vand	q9, q9, q10\n\t"
        "veor	q8, q8, q9\n\t"
        "vshl.i32	q10, q6, #26\n\t"
        "vshr.s32	q10, q10, #31\n\t"
        "vshl.i32	q9, q5, #5\n\t"
        "vand	q9, q9, q10\n\t"
        "veor	q8, q8, q9\n\t"
        "vshl.i32	q10, q6, #25\n\t"
        "vshr.s32	q10, q10, #31\n\t"
        "vshl.i32	q9, q5, #6\n\t"
        "vand	q9, q9, q10\n\t"
        "veor	q8, q8, q9\n\t"
        "vshl.i32	q10, q6, #24\n\t"
        "vshr.s32	q10, q10, #31\n\t"
        "vshl.i32	q9, q5, #7\n\t"
        "vand	q9, q9, q10\n\t"
        "veor	q8, q8, q9\n\t"
        "vshl.i32	q10, q6, #23\n\t"
        "vshr.s32	q10, q10, #31\n\t"
        "vshl.i32	q9, q5, #8\n\t"
        "vand	q9, q9, q10\n\t"
        "veor	q8, q8, q9\n\t"
        "vshl.i32	q10, q6, #22\n\t"
        "vshr.s32	q10, q10, #31\n\t"
        "vshl.i32	q9, q5, #9\n\t"
        "vand	q9, q9, q10\n\t"
        "veor	q8, q8, q9\n\t"
        "vshl.i32	q10, q6, #21\n\t"
        "vshr.s32	q10, q10, #31\n\t"
        "vshl.i32	q9, q5, #10\n\t"
        "vand	q9, q9, q10\n\t"
        "veor	q8, q8, q9\n\t"
        "vshl.i32	q10, q6, #20\n\t"
        "vshr.s32	q10, q10, #31\n\t"
        "vshl.i32	q9, q5, #11\n\t"
        "vand	q9, q9, q10\n\t"
        "veor	q8, q8, q9\n\t"
        "vshl.i32	q10, q6, #19\n\t"
        "vshr.s32	q10, q10, #31\n\t"
        "vshl.i32	q9, q5, #12\n\t"
        "vand	q9, q9, q10\n\t"
        "veor	q8, q8, q9\n\t"
        "vand	q11, q8, q0\n\t"
        "vshr.u32	q12, q11, #9\n\t"
        "veor	q8, q8, q12\n\t"
        "vshr.u32	q12, q11, #10\n\t"
        "veor	q8, q8, q12\n\t"
        "vshr.u32	q12, q11, #12\n\t"
        "veor	q8, q8, q12\n\t"
        "vshr.u32	q12, q11, #13\n\t"
        "veor	q8, q8, q12\n\t"
        "vand	q11, q8, q1\n\t"
        "vshr.u32	q12, q11, #9\n\t"
        "veor	q8, q8, q12\n\t"
        "vshr.u32	q12, q11, #10\n\t"
        "veor	q8, q8, q12\n\t"
        "vshr.u32	q12, q11, #12\n\t"
        "veor	q8, q8, q12\n\t"
        "vshr.u32	q12, q11, #13\n\t"
        "veor	q8, q8, q12\n\t"
        "vand	q8, q8, q2\n\t"
        "vmovn.i32	d22, q7\n\t"
        "vmovn.i32	d23, q8\n\t"
        "veor	q13, q13, q11\n\t"
        "add	r3, r3, #8\n\t"
        "b	L_mc_gdc_%=\n\t"
        "\n"
    "L_mc_gdce_%=:\n\t"
        "vext.8	q11, q13, q13, #8\n\t"
        "veor	q13, q13, q11\n\t"
        "vext.8	q11, q13, q13, #4\n\t"
        "veor	q13, q13, q11\n\t"
        "vext.8	q11, q13, q13, #2\n\t"
        "veor	q13, q13, q11\n\t"
        "vmov.u16	r4, d26[0]\n\t"
        "mov	%[c], r4\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [c] "+r" (c), [sn] "+r" (sn), [count] "+r" (count)
        :
#else
        :
        : [c] "r" (c), [sn] "r" (sn), [count] "r" (count)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r3", "r12", "lr", "r4", "q0", "q1", "q2", "q3", "q4",
            "q5", "q6", "q7", "q8", "q9", "q10", "q11", "q12", "q13"
    );
    return (word32)(size_t)c;
}

WOLFSSL_LOCAL void wc_mceliece_aff_synd_mask_neon(word64* scaled,
    const word64* einvbs, const byte* fieldmask);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_aff_synd_mask_neon(word64* scaled_p,
    const word64* einvbs_p, const byte* fieldmask_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_aff_synd_mask_neon(word64* scaled,
    const word64* einvbs, const byte* fieldmask)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word64* scaled __asm__ ("r0") = (word64*)scaled_p;
    register const word64* einvbs __asm__ ("r1") = (const word64*)einvbs_p;
    register const byte* fieldmask __asm__ ("r2") = (const byte*)fieldmask_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "mov	r7, #13\n\t"
        "mov	r3, #0\n\t"
        "\n"
    "L_mc_sm_i_%=:\n\t"
        "cmp	r3, #32\n\t"
        "bge	L_mc_sm_ie_%=\n\t"
        "lsl	lr, r3, #5\n\t"
        "add	r4, %[fieldmask], lr\n\t"
        "vld1.8	{d0-d3}, [r4]\n\t"
        "mul	lr, r3, r7\n\t"
        "lsl	lr, lr, #5\n\t"
        "add	r5, %[einvbs], lr\n\t"
        "add	r6, %[scaled], lr\n\t"
        "mov	r12, #0\n\t"
        "\n"
    "L_mc_sm_k_%=:\n\t"
        "vld1.8	{d4-d7}, [r5]\n\t"
        "vand	q2, q2, q0\n\t"
        "vand	q3, q3, q1\n\t"
        "vst1.8	{d4-d7}, [r6]\n\t"
        "add	r5, r5, #32\n\t"
        "add	r6, r6, #32\n\t"
        "add	r12, r12, #1\n\t"
        "cmp	r12, #13\n\t"
        "blt	L_mc_sm_k_%=\n\t"
        "\n"
    "L_mc_sm_ke_%=:\n\t"
        "add	r3, r3, #1\n\t"
        "b	L_mc_sm_i_%=\n\t"
        "\n"
    "L_mc_sm_ie_%=:\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [scaled] "+r" (scaled), [einvbs] "+r" (einvbs),
          [fieldmask] "+r" (fieldmask)
        :
#else
        :
        : [scaled] "r" (scaled), [einvbs] "r" (einvbs),
          [fieldmask] "r" (fieldmask)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r3", "r12", "lr", "r4", "r5", "r6", "r7", "q0", "q1",
            "q2", "q3"
    );
}

WOLFSSL_LOCAL void wc_mceliece_aff_fwd_out_neon(word64* out, const word64* buf,
    int i);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_aff_fwd_out_neon(word64* out_p,
    const word64* buf_p, int i_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_aff_fwd_out_neon(word64* out,
    const word64* buf, int i)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word64* out __asm__ ("r0") = (word64*)out_p;
    register const word64* buf __asm__ ("r1") = (const word64*)buf_p;
    register int i __asm__ ("r2") = (int)i_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    register word8* L_mc_aff_reversal_neon_c __asm__ ("r3") =
        (word8*)&L_mc_aff_reversal_neon;
    __asm__ __volatile__ (
        "mov	r10, #13\n\t"
        "mov	r12, #0\n\t"
        "\n"
    "L_mc_fwo_j_%=:\n\t"
        "cmp	r12, #32\n\t"
        "bge	L_mc_fwo_e_%=\n\t"
        "lsl	r5, r12, #1\n\t"
        "add	r6, %[L_mc_aff_reversal_neon], r5\n\t"
        "ldrb	lr, [r6]\n\t"
        "add	r6, r6, #1\n\t"
        "ldrb	r4, [r6]\n\t"
        "lsl	r5, lr, #5\n\t"
        "add	r7, %[buf], r5\n\t"
        "vld1.8	{d0-d3}, [r7]\n\t"
        "lsl	r5, r4, #5\n\t"
        "add	r8, %[buf], r5\n\t"
        "vld1.8	{d4-d7}, [r8]\n\t"
        "mul	r5, r12, r10\n\t"
        "add	r5, r5, %[i]\n\t"
        "lsl	r5, r5, #5\n\t"
        "add	r9, %[out], r5\n\t"
        "vst1.8	{d0-d1}, [r9]\n\t"
        "add	r9, r9, #16\n\t"
        "vst1.8	{d4-d5}, [r9]\n\t"
        "add	r9, r9, #16\n\t"
        "cmp	%[i], #12\n\t"
        "beq	L_mc_fwo_no_%=\n\t"
        "vst1.8	{d2-d3}, [r9]\n\t"
        "add	r9, r9, #16\n\t"
        "vst1.8	{d6-d7}, [r9]\n\t"
        "\n"
    "L_mc_fwo_no_%=:\n\t"
        "add	r12, r12, #1\n\t"
        "b	L_mc_fwo_j_%=\n\t"
        "\n"
    "L_mc_fwo_e_%=:\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [out] "+r" (out), [buf] "+r" (buf), [i] "+r" (i),
          [L_mc_aff_reversal_neon] "+r" (L_mc_aff_reversal_neon_c)
        :
#else
        :
        : [out] "r" (out), [buf] "r" (buf), [i] "r" (i),
          [L_mc_aff_reversal_neon] "r" (L_mc_aff_reversal_neon_c)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r12", "lr", "r4", "r5", "r6", "r7", "r8", "r9",
            "r10", "q0", "q1", "q2", "q3"
    );
}

WOLFSSL_LOCAL void wc_mceliece_aff_pack_lh2_neon(word64* lo, word64* hi,
    const word64* a, const word64* b);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_aff_pack_lh2_neon(word64* lo_p,
    word64* hi_p, const word64* a_p, const word64* b_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_aff_pack_lh2_neon(word64* lo, word64* hi,
    const word64* a, const word64* b)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word64* lo __asm__ ("r0") = (word64*)lo_p;
    register word64* hi __asm__ ("r1") = (word64*)hi_p;
    register const word64* a __asm__ ("r2") = (const word64*)a_p;
    register const word64* b __asm__ ("r3") = (const word64*)b_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "mov	r12, #0\n\t"
        "\n"
    "L_mc_packlh2_p_%=:\n\t"
        "lsl	lr, r12, #5\n\t"
        "add	r6, %[a], lr\n\t"
        "vld1.8	{d0-d3}, [r6]\n\t"
        "add	r7, %[b], lr\n\t"
        "vld1.8	{d4-d7}, [r7]\n\t"
        "vmov	d8, d0\n\t"
        "vmov	d9, d4\n\t"
        "vmov	d10, d2\n\t"
        "vmov	d11, d6\n\t"
        "add	r4, %[lo], lr\n\t"
        "vst1.8	{d8-d11}, [r4]\n\t"
        "vmov	d8, d1\n\t"
        "vmov	d9, d5\n\t"
        "vmov	d10, d3\n\t"
        "vmov	d11, d7\n\t"
        "add	r5, %[hi], lr\n\t"
        "vst1.8	{d8-d11}, [r5]\n\t"
        "add	r12, r12, #1\n\t"
        "cmp	r12, #13\n\t"
        "blt	L_mc_packlh2_p_%=\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [lo] "+r" (lo), [hi] "+r" (hi), [a] "+r" (a), [b] "+r" (b)
        :
#else
        :
        : [lo] "r" (lo), [hi] "r" (hi), [a] "r" (a), [b] "r" (b)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r12", "lr", "r4", "r5", "r6", "r7", "q0", "q1", "q2",
            "q3", "q4", "q5"
    );
}

WOLFSSL_LOCAL void wc_mceliece_bs_poly_neon(word64* in, const word16* c);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_bs_poly_neon(word64* in_p,
    const word16* c_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_bs_poly_neon(word64* in, const word16* c)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word64* in __asm__ ("r0") = (word64*)in_p;
    register const word16* c __asm__ ("r1") = (const word16*)c_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    register word16* L_mc_bs_powers_neon_c __asm__ ("r2") =
        (word16*)&L_mc_bs_powers_neon;
    __asm__ __volatile__ (
        "vld1.8	{d0-d1}, [%[L_mc_bs_powers_neon]]\n\t"
        "vmov.i16	q1, #1\n\t"
        "mov	r3, #0\n\t"
        "\n"
    "L_mc_bsp_%=:\n\t"
        "cmp	r3, #8\n\t"
        "bge	L_mc_bspe_%=\n\t"
        "lsl	r4, r3, #4\n\t"
        "add	r12, %[c], r4\n\t"
        "vld1.8	{d4-d5}, [r12]\n\t"
        "add	r12, r12, #0x80\n\t"
        "vld1.8	{d6-d7}, [r12]\n\t"
        "vand	q4, q2, q1\n\t"
        "vmul.i16	q4, q4, q0\n\t"
        "vext.8	q5, q4, q4, #8\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #4\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #2\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vmov.u16	lr, d8[0]\n\t"
        "add	r12, %[in], #0\n\t"
        "add	r12, r12, r3\n\t"
        "strb	lr, [r12]\n\t"
        "vshr.u16	q4, q2, #1\n\t"
        "vand	q4, q4, q1\n\t"
        "vmul.i16	q4, q4, q0\n\t"
        "vext.8	q5, q4, q4, #8\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #4\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #2\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vmov.u16	lr, d8[0]\n\t"
        "add	r12, %[in], #16\n\t"
        "add	r12, r12, r3\n\t"
        "strb	lr, [r12]\n\t"
        "vshr.u16	q4, q2, #2\n\t"
        "vand	q4, q4, q1\n\t"
        "vmul.i16	q4, q4, q0\n\t"
        "vext.8	q5, q4, q4, #8\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #4\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #2\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vmov.u16	lr, d8[0]\n\t"
        "add	r12, %[in], #32\n\t"
        "add	r12, r12, r3\n\t"
        "strb	lr, [r12]\n\t"
        "vshr.u16	q4, q2, #3\n\t"
        "vand	q4, q4, q1\n\t"
        "vmul.i16	q4, q4, q0\n\t"
        "vext.8	q5, q4, q4, #8\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #4\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #2\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vmov.u16	lr, d8[0]\n\t"
        "add	r12, %[in], #48\n\t"
        "add	r12, r12, r3\n\t"
        "strb	lr, [r12]\n\t"
        "vshr.u16	q4, q2, #4\n\t"
        "vand	q4, q4, q1\n\t"
        "vmul.i16	q4, q4, q0\n\t"
        "vext.8	q5, q4, q4, #8\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #4\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #2\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vmov.u16	lr, d8[0]\n\t"
        "add	r12, %[in], #0x40\n\t"
        "add	r12, r12, r3\n\t"
        "strb	lr, [r12]\n\t"
        "vshr.u16	q4, q2, #5\n\t"
        "vand	q4, q4, q1\n\t"
        "vmul.i16	q4, q4, q0\n\t"
        "vext.8	q5, q4, q4, #8\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #4\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #2\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vmov.u16	lr, d8[0]\n\t"
        "add	r12, %[in], #0x50\n\t"
        "add	r12, r12, r3\n\t"
        "strb	lr, [r12]\n\t"
        "vshr.u16	q4, q2, #6\n\t"
        "vand	q4, q4, q1\n\t"
        "vmul.i16	q4, q4, q0\n\t"
        "vext.8	q5, q4, q4, #8\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #4\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #2\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vmov.u16	lr, d8[0]\n\t"
        "add	r12, %[in], #0x60\n\t"
        "add	r12, r12, r3\n\t"
        "strb	lr, [r12]\n\t"
        "vshr.u16	q4, q2, #7\n\t"
        "vand	q4, q4, q1\n\t"
        "vmul.i16	q4, q4, q0\n\t"
        "vext.8	q5, q4, q4, #8\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #4\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #2\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vmov.u16	lr, d8[0]\n\t"
        "add	r12, %[in], #0x70\n\t"
        "add	r12, r12, r3\n\t"
        "strb	lr, [r12]\n\t"
        "vshr.u16	q4, q2, #8\n\t"
        "vand	q4, q4, q1\n\t"
        "vmul.i16	q4, q4, q0\n\t"
        "vext.8	q5, q4, q4, #8\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #4\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #2\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vmov.u16	lr, d8[0]\n\t"
        "add	r12, %[in], #0x80\n\t"
        "add	r12, r12, r3\n\t"
        "strb	lr, [r12]\n\t"
        "vshr.u16	q4, q2, #9\n\t"
        "vand	q4, q4, q1\n\t"
        "vmul.i16	q4, q4, q0\n\t"
        "vext.8	q5, q4, q4, #8\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #4\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #2\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vmov.u16	lr, d8[0]\n\t"
        "add	r12, %[in], #0x90\n\t"
        "add	r12, r12, r3\n\t"
        "strb	lr, [r12]\n\t"
        "vshr.u16	q4, q2, #10\n\t"
        "vand	q4, q4, q1\n\t"
        "vmul.i16	q4, q4, q0\n\t"
        "vext.8	q5, q4, q4, #8\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #4\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #2\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vmov.u16	lr, d8[0]\n\t"
        "add	r12, %[in], #0xa0\n\t"
        "add	r12, r12, r3\n\t"
        "strb	lr, [r12]\n\t"
        "vshr.u16	q4, q2, #11\n\t"
        "vand	q4, q4, q1\n\t"
        "vmul.i16	q4, q4, q0\n\t"
        "vext.8	q5, q4, q4, #8\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #4\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #2\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vmov.u16	lr, d8[0]\n\t"
        "add	r12, %[in], #0xb0\n\t"
        "add	r12, r12, r3\n\t"
        "strb	lr, [r12]\n\t"
        "vshr.u16	q4, q2, #12\n\t"
        "vand	q4, q4, q1\n\t"
        "vmul.i16	q4, q4, q0\n\t"
        "vext.8	q5, q4, q4, #8\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #4\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #2\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vmov.u16	lr, d8[0]\n\t"
        "add	r12, %[in], #0xc0\n\t"
        "add	r12, r12, r3\n\t"
        "strb	lr, [r12]\n\t"
        "vand	q4, q3, q1\n\t"
        "vmul.i16	q4, q4, q0\n\t"
        "vext.8	q5, q4, q4, #8\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #4\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #2\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vmov.u16	lr, d8[0]\n\t"
        "add	r12, %[in], #8\n\t"
        "add	r12, r12, r3\n\t"
        "strb	lr, [r12]\n\t"
        "vshr.u16	q4, q3, #1\n\t"
        "vand	q4, q4, q1\n\t"
        "vmul.i16	q4, q4, q0\n\t"
        "vext.8	q5, q4, q4, #8\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #4\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #2\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vmov.u16	lr, d8[0]\n\t"
        "add	r12, %[in], #24\n\t"
        "add	r12, r12, r3\n\t"
        "strb	lr, [r12]\n\t"
        "vshr.u16	q4, q3, #2\n\t"
        "vand	q4, q4, q1\n\t"
        "vmul.i16	q4, q4, q0\n\t"
        "vext.8	q5, q4, q4, #8\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #4\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #2\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vmov.u16	lr, d8[0]\n\t"
        "add	r12, %[in], #40\n\t"
        "add	r12, r12, r3\n\t"
        "strb	lr, [r12]\n\t"
        "vshr.u16	q4, q3, #3\n\t"
        "vand	q4, q4, q1\n\t"
        "vmul.i16	q4, q4, q0\n\t"
        "vext.8	q5, q4, q4, #8\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #4\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #2\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vmov.u16	lr, d8[0]\n\t"
        "add	r12, %[in], #56\n\t"
        "add	r12, r12, r3\n\t"
        "strb	lr, [r12]\n\t"
        "vshr.u16	q4, q3, #4\n\t"
        "vand	q4, q4, q1\n\t"
        "vmul.i16	q4, q4, q0\n\t"
        "vext.8	q5, q4, q4, #8\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #4\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #2\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vmov.u16	lr, d8[0]\n\t"
        "add	r12, %[in], #0x48\n\t"
        "add	r12, r12, r3\n\t"
        "strb	lr, [r12]\n\t"
        "vshr.u16	q4, q3, #5\n\t"
        "vand	q4, q4, q1\n\t"
        "vmul.i16	q4, q4, q0\n\t"
        "vext.8	q5, q4, q4, #8\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #4\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #2\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vmov.u16	lr, d8[0]\n\t"
        "add	r12, %[in], #0x58\n\t"
        "add	r12, r12, r3\n\t"
        "strb	lr, [r12]\n\t"
        "vshr.u16	q4, q3, #6\n\t"
        "vand	q4, q4, q1\n\t"
        "vmul.i16	q4, q4, q0\n\t"
        "vext.8	q5, q4, q4, #8\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #4\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #2\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vmov.u16	lr, d8[0]\n\t"
        "add	r12, %[in], #0x68\n\t"
        "add	r12, r12, r3\n\t"
        "strb	lr, [r12]\n\t"
        "vshr.u16	q4, q3, #7\n\t"
        "vand	q4, q4, q1\n\t"
        "vmul.i16	q4, q4, q0\n\t"
        "vext.8	q5, q4, q4, #8\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #4\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #2\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vmov.u16	lr, d8[0]\n\t"
        "add	r12, %[in], #0x78\n\t"
        "add	r12, r12, r3\n\t"
        "strb	lr, [r12]\n\t"
        "vshr.u16	q4, q3, #8\n\t"
        "vand	q4, q4, q1\n\t"
        "vmul.i16	q4, q4, q0\n\t"
        "vext.8	q5, q4, q4, #8\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #4\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #2\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vmov.u16	lr, d8[0]\n\t"
        "add	r12, %[in], #0x88\n\t"
        "add	r12, r12, r3\n\t"
        "strb	lr, [r12]\n\t"
        "vshr.u16	q4, q3, #9\n\t"
        "vand	q4, q4, q1\n\t"
        "vmul.i16	q4, q4, q0\n\t"
        "vext.8	q5, q4, q4, #8\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #4\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #2\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vmov.u16	lr, d8[0]\n\t"
        "add	r12, %[in], #0x98\n\t"
        "add	r12, r12, r3\n\t"
        "strb	lr, [r12]\n\t"
        "vshr.u16	q4, q3, #10\n\t"
        "vand	q4, q4, q1\n\t"
        "vmul.i16	q4, q4, q0\n\t"
        "vext.8	q5, q4, q4, #8\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #4\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #2\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vmov.u16	lr, d8[0]\n\t"
        "add	r12, %[in], #0xa8\n\t"
        "add	r12, r12, r3\n\t"
        "strb	lr, [r12]\n\t"
        "vshr.u16	q4, q3, #11\n\t"
        "vand	q4, q4, q1\n\t"
        "vmul.i16	q4, q4, q0\n\t"
        "vext.8	q5, q4, q4, #8\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #4\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #2\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vmov.u16	lr, d8[0]\n\t"
        "add	r12, %[in], #0xb8\n\t"
        "add	r12, r12, r3\n\t"
        "strb	lr, [r12]\n\t"
        "vshr.u16	q4, q3, #12\n\t"
        "vand	q4, q4, q1\n\t"
        "vmul.i16	q4, q4, q0\n\t"
        "vext.8	q5, q4, q4, #8\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #4\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vext.8	q5, q4, q4, #2\n\t"
        "vadd.i16	q4, q4, q5\n\t"
        "vmov.u16	lr, d8[0]\n\t"
        "add	r12, %[in], #0xc8\n\t"
        "add	r12, r12, r3\n\t"
        "strb	lr, [r12]\n\t"
        "add	r3, r3, #1\n\t"
        "b	L_mc_bsp_%=\n\t"
        "\n"
    "L_mc_bspe_%=:\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [in] "+r" (in), [c] "+r" (c),
          [L_mc_bs_powers_neon] "+r" (L_mc_bs_powers_neon_c)
        :
#else
        :
        : [in] "r" (in), [c] "r" (c),
          [L_mc_bs_powers_neon] "r" (L_mc_bs_powers_neon_c)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r3", "r12", "lr", "r4", "q0", "q1", "q2", "q3", "q4",
            "q5"
    );
}

WOLFSSL_LOCAL void wc_mceliece_aff_btr_net_neon(word64* pre, word64* buf,
    word64* out, int i, int i2);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_aff_btr_net_neon(word64* pre_p,
    word64* buf_p, word64* out_p, int i_p, int i2_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_aff_btr_net_neon(word64* pre,
    word64* buf, word64* out, int i, int i2)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word64* pre __asm__ ("r0") = (word64*)pre_p;
    register word64* buf __asm__ ("r1") = (word64*)buf_p;
    register word64* out __asm__ ("r2") = (word64*)out_p;
    register int i __asm__ ("r3") = (int)i_p;
    register int i2 __asm__ ("r12") = (int)i2_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "push	{%[i2]}\n\t"
        "ldr	r12, [sp]\n\t"
        "lsl	r6, r12, #5\n\t"
        "add	lr, %[pre], r6\n\t"
        "add	r4, %[buf], #0x400\n\t"
        "vld1.8	{d0-d3}, [r4]\n\t"
        "add	r5, lr, #0\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x420\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x400\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x420\n\t"
        "vld1.8	{d0-d3}, [r4]\n\t"
        "add	r5, lr, #0xe0\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x460\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x420\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x460\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x440\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x460\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x440\n\t"
        "vld1.8	{d0-d3}, [r4]\n\t"
        "add	r5, lr, #0x1c0\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x4c0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x440\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x4c0\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x4e0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x4c0\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0xe0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x4e0\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x4a0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x4e0\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x4a0\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x480\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x4a0\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x480\n\t"
        "vld1.8	{d0-d3}, [r4]\n\t"
        "add	r5, lr, #0x2a0\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x580\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x480\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x580\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x5a0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x580\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0xe0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x5a0\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x5e0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x5a0\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x5e0\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x5c0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x5e0\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0x1c0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x5c0\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x540\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x5c0\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x540\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x560\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x540\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0xe0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x560\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x520\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x560\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x520\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x500\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x520\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x500\n\t"
        "vld1.8	{d0-d3}, [r4]\n\t"
        "add	r5, lr, #0x380\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x700\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x500\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x700\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x720\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x700\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0xe0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x720\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x760\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x720\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x760\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x740\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x760\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0x1c0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x740\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x7c0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x740\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x7c0\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x7e0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x7c0\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0xe0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x7e0\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x7a0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x7e0\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x7a0\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x780\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x7a0\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0x2a0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x780\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x680\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x780\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x680\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x6a0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x680\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0xe0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x6a0\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x6e0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x6a0\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x6e0\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x6c0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x6e0\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0x1c0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x6c0\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x640\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x6c0\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x640\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x660\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x640\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0xe0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x660\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x620\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x660\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x620\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x600\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x620\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x600\n\t"
        "vld1.8	{d0-d3}, [r4]\n\t"
        "add	r5, lr, #0x460\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x200\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x600\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x200\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x220\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x200\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0xe0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x220\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x260\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x220\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x260\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x240\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x260\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0x1c0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x240\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x2c0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x240\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x2c0\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x2e0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x2c0\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0xe0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x2e0\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x2a0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x2e0\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x2a0\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x280\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x2a0\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0x2a0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x280\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x380\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x280\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x380\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x3a0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x380\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0xe0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x3a0\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x3e0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x3a0\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x3e0\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x3c0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x3e0\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0x1c0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x3c0\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x340\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x3c0\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x340\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x360\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x340\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0xe0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x360\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x320\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x360\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x320\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x300\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x320\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0x380\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x300\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x100\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x300\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x100\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x120\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x100\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0xe0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x120\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x160\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x120\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x160\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x140\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x160\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0x1c0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x140\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x1c0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x140\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x1c0\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x1e0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x1c0\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0xe0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x1e0\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x1a0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x1e0\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x1a0\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x180\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x1a0\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0x2a0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x180\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x80\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x180\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x80\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0xa0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x80\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0xe0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0xa0\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0xe0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0xa0\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0xe0\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0xc0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0xe0\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0x1c0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0xc0\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x40\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0xc0\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x40\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #0x60\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x40\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0xe0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x60\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, %[buf], #32\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #0x60\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, lr, #0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r4, %[buf], #32\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "vld1.8	{d0-d3}, [%[buf]]\n\t"
        "add	r4, %[buf], #32\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "lsl	r6, %[i], #5\n\t"
        "add	r5, %[out], r6\n\t"
        "vst1.8	{d0-d1}, [r5]\n\t"
        "cmp	%[i], #12\n\t"
        "beq	L_mc_btrn_nh_%=\n\t"
        "add	r5, r5, #32\n\t"
        "vst1.8	{d2-d3}, [r5]\n\t"
        "\n"
    "L_mc_btrn_nh_%=:\n\t"
        "pop	{%[i2]}\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [pre] "+r" (pre), [buf] "+r" (buf), [out] "+r" (out), [i] "+r" (i),
          [i2] "+r" (i2)
        :
#else
        :
        : [pre] "r" (pre), [buf] "r" (buf), [out] "r" (out), [i] "r" (i),
          [i2] "r" (i2)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "lr", "r4", "r5", "r6", "q0", "q1", "q2", "q3"
    );
}

WOLFSSL_LOCAL void wc_mceliece_aff_btr_in_neon(word64* buf, const word64* in,
    int i);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_aff_btr_in_neon(word64* buf_p,
    const word64* in_p, int i_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_aff_btr_in_neon(word64* buf,
    const word64* in, int i)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word64* buf __asm__ ("r0") = (word64*)buf_p;
    register const word64* in __asm__ ("r1") = (const word64*)in_p;
    register int i __asm__ ("r2") = (int)i_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    register word8* L_mc_aff_reversal_neon_c __asm__ ("r3") =
        (word8*)&L_mc_aff_reversal_neon;
    __asm__ __volatile__ (
        "mov	r10, #13\n\t"
        "mov	r12, #0\n\t"
        "\n"
    "L_mc_bti_k_%=:\n\t"
        "cmp	r12, #32\n\t"
        "bge	L_mc_bti_e_%=\n\t"
        "lsl	r5, r12, #1\n\t"
        "add	r6, %[L_mc_aff_reversal_neon], r5\n\t"
        "ldrb	lr, [r6]\n\t"
        "add	r6, r6, #1\n\t"
        "ldrb	r4, [r6]\n\t"
        "lsl	r5, lr, #5\n\t"
        "add	r7, %[buf], r5\n\t"
        "lsl	r5, r4, #5\n\t"
        "add	r8, %[buf], r5\n\t"
        "mul	r5, r12, r10\n\t"
        "add	r5, r5, %[i]\n\t"
        "lsl	r5, r5, #5\n\t"
        "add	r9, %[in], r5\n\t"
        "vld1.8	{d0-d3}, [r9]\n\t"
        "vst1.8	{d0-d1}, [r7]\n\t"
        "vst1.8	{d2-d3}, [r8]\n\t"
        "cmp	%[i], #12\n\t"
        "beq	L_mc_bti_no_%=\n\t"
        "add	r9, r9, #32\n\t"
        "vld1.8	{d4-d7}, [r9]\n\t"
        "add	r6, r7, #16\n\t"
        "vst1.8	{d4-d5}, [r6]\n\t"
        "add	r6, r8, #16\n\t"
        "vst1.8	{d6-d7}, [r6]\n\t"
        "\n"
    "L_mc_bti_no_%=:\n\t"
        "add	r12, r12, #1\n\t"
        "b	L_mc_bti_k_%=\n\t"
        "\n"
    "L_mc_bti_e_%=:\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [buf] "+r" (buf), [in] "+r" (in), [i] "+r" (i),
          [L_mc_aff_reversal_neon] "+r" (L_mc_aff_reversal_neon_c)
        :
#else
        :
        : [buf] "r" (buf), [in] "r" (in), [i] "r" (i),
          [L_mc_aff_reversal_neon] "r" (L_mc_aff_reversal_neon_c)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r12", "lr", "r4", "r5", "r6", "r7", "r8", "r9",
            "r10", "q0", "q1", "q2", "q3"
    );
}

WOLFSSL_LOCAL void wc_mceliece_bs_minmax_rows_neon(sword16* x, word64* mat,
    int parWidth, int i0, int i1);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_bs_minmax_rows_neon(sword16* x_p,
    word64* mat_p, int parWidth_p, int i0_p, int i1_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_bs_minmax_rows_neon(sword16* x,
    word64* mat, int parWidth, int i0, int i1)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register sword16* x __asm__ ("r0") = (sword16*)x_p;
    register word64* mat __asm__ ("r1") = (word64*)mat_p;
    register int parWidth __asm__ ("r2") = (int)parWidth_p;
    register int i0 __asm__ ("r3") = (int)i0_p;
    register int i1 __asm__ ("r12") = (int)i1_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "push	{%[i1]}\n\t"
        "ldr	r12, [sp]\n\t"
        "lsl	%[parWidth], %[parWidth], #2\n\t"
        "lsl	r9, %[i0], #1\n\t"
        "add	lr, %[x], r9\n\t"
        "ldrh	r5, [lr]\n\t"
        "lsl	r9, r12, #1\n\t"
        "add	r4, %[x], r9\n\t"
        "ldrh	r6, [r4]\n\t"
        "sub	r7, r6, r5\n\t"
        "asr	r7, r7, #31\n\t"
        "vdup.32	q6, r7\n\t"
        "eor	r8, r5, r6\n\t"
        "and	r8, r8, r7\n\t"
        "eor	r5, r5, r8\n\t"
        "strh	r5, [lr]\n\t"
        "eor	r6, r6, r8\n\t"
        "strh	r6, [r4]\n\t"
        "mul	r9, %[i0], %[parWidth]\n\t"
        "lsl	r9, r9, #3\n\t"
        "add	lr, %[mat], r9\n\t"
        "mul	r9, r12, %[parWidth]\n\t"
        "lsl	r9, r9, #3\n\t"
        "add	r4, %[mat], r9\n\t"
        "mov	r5, #0\n\t"
        "\n"
    "L_mc_mmr_c_%=:\n\t"
        "cmp	r5, %[parWidth]\n\t"
        "bge	L_mc_mmr_ce_%=\n\t"
        "vld1.8	{d0-d3}, [lr]\n\t"
        "vld1.8	{d4-d7}, [r4]\n\t"
        "veor	q4, q0, q2\n\t"
        "veor	q5, q1, q3\n\t"
        "vand	q4, q4, q6\n\t"
        "vand	q5, q5, q6\n\t"
        "veor	q0, q0, q4\n\t"
        "veor	q1, q1, q5\n\t"
        "vst1.8	{d0-d3}, [lr]\n\t"
        "veor	q2, q2, q4\n\t"
        "veor	q3, q3, q5\n\t"
        "vst1.8	{d4-d7}, [r4]\n\t"
        "add	lr, lr, #32\n\t"
        "add	r4, r4, #32\n\t"
        "add	r5, r5, #4\n\t"
        "cmp	r5, %[parWidth]\n\t"
        "blt	L_mc_mmr_c_%=\n\t"
        "\n"
    "L_mc_mmr_ce_%=:\n\t"
        "pop	{%[i1]}\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [x] "+r" (x), [mat] "+r" (mat), [parWidth] "+r" (parWidth),
          [i0] "+r" (i0), [i1] "+r" (i1)
        :
#else
        :
        : [x] "r" (x), [mat] "r" (mat), [parWidth] "r" (parWidth),
          [i0] "r" (i0), [i1] "r" (i1)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "lr", "r4", "r5", "r6", "r7", "r8", "r9", "q0", "q1",
            "q2", "q3", "q4", "q5", "q6"
    );
}

WOLFSSL_LOCAL void wc_mceliece_bs_extract_neon(byte* pk, const byte* tmat,
    int mt, int tmatStride, int nBytes);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_bs_extract_neon(byte* pk_p,
    const byte* tmat_p, int mt_p, int tmatStride_p, int nBytes_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_bs_extract_neon(byte* pk,
    const byte* tmat, int mt, int tmatStride, int nBytes)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register byte* pk __asm__ ("r0") = (byte*)pk_p;
    register const byte* tmat __asm__ ("r1") = (const byte*)tmat_p;
    register int mt __asm__ ("r2") = (int)mt_p;
    register int tmatStride __asm__ ("r3") = (int)tmatStride_p;
    register int nBytes __asm__ ("r12") = (int)nBytes_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "push	{%[nBytes]}\n\t"
        "ldr	r12, [sp]\n\t"
        "lsr	lr, %[mt], #3\n\t"
        "and	r4, %[mt], #7\n\t"
        "cmp	r4, #0\n\t"
        "beq	L_mc_ext_z_%=\n\t"
        "mov	r8, %[pk]\n\t"
        "mov	r5, #0\n\t"
        "\n"
    "L_mc_ext_ti_%=:\n\t"
        "cmp	r5, %[mt]\n\t"
        "bge	L_mc_ext_end_%=\n\t"
        "mul	r10, r5, %[tmatStride]\n\t"
        "add	r7, %[tmat], r10\n\t"
        "add	r7, r7, lr\n\t"
        "mov	r6, lr\n\t"
        "\n"
    "L_mc_ext_tj_%=:\n\t"
        "sub	r10, r12, #1\n\t"
        "cmp	r6, r10\n\t"
        "bge	L_mc_ext_tjd_%=\n\t"
        "ldrh	r9, [r7]\n\t"
        "lsr	r9, r9, r4\n\t"
        "strb	r9, [r8]\n\t"
        "add	r7, r7, #1\n\t"
        "add	r8, r8, #1\n\t"
        "add	r6, r6, #1\n\t"
        "b	L_mc_ext_tj_%=\n\t"
        "\n"
    "L_mc_ext_tjd_%=:\n\t"
        "ldrb	r9, [r7]\n\t"
        "lsr	r9, r9, r4\n\t"
        "strb	r9, [r8]\n\t"
        "add	r8, r8, #1\n\t"
        "add	r5, r5, #1\n\t"
        "b	L_mc_ext_ti_%=\n\t"
        "\n"
    "L_mc_ext_z_%=:\n\t"
        "sub	r4, r12, lr\n\t"
        "mov	r5, #0\n\t"
        "\n"
    "L_mc_ext_zi_%=:\n\t"
        "cmp	r5, %[mt]\n\t"
        "bge	L_mc_ext_end_%=\n\t"
        "mul	r10, r5, %[tmatStride]\n\t"
        "add	r7, %[tmat], r10\n\t"
        "add	r7, r7, lr\n\t"
        "mul	r10, r5, r4\n\t"
        "add	r8, %[pk], r10\n\t"
        "mov	r6, #0\n\t"
        "\n"
    "L_mc_ext_zj_%=:\n\t"
        "cmp	r6, r4\n\t"
        "bge	L_mc_ext_zjd_%=\n\t"
        "ldrb	r9, [r7]\n\t"
        "strb	r9, [r8]\n\t"
        "add	r7, r7, #1\n\t"
        "add	r8, r8, #1\n\t"
        "add	r6, r6, #1\n\t"
        "b	L_mc_ext_zj_%=\n\t"
        "\n"
    "L_mc_ext_zjd_%=:\n\t"
        "add	r5, r5, #1\n\t"
        "b	L_mc_ext_zi_%=\n\t"
        "\n"
    "L_mc_ext_end_%=:\n\t"
        "pop	{%[nBytes]}\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [pk] "+r" (pk), [tmat] "+r" (tmat), [mt] "+r" (mt),
          [tmatStride] "+r" (tmatStride), [nBytes] "+r" (nBytes)
        :
#else
        :
        : [pk] "r" (pk), [tmat] "r" (tmat), [mt] "r" (mt),
          [tmatStride] "r" (tmatStride), [nBytes] "r" (nBytes)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "lr", "r4", "r5", "r6", "r7", "r8", "r9", "r10"
    );
}

WOLFSSL_LOCAL void wc_mceliece_bs_tri_neon(word64* par, const word64* matRow,
    int row, int parW4, int iLo, int iHi);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_bs_tri_neon(word64* par_p,
    const word64* matRow_p, int row_p, int parW4_p, int iLo_p, int iHi_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_bs_tri_neon(word64* par,
    const word64* matRow, int row, int parW4, int iLo, int iHi)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word64* par __asm__ ("r0") = (word64*)par_p;
    register const word64* matRow __asm__ ("r1") = (const word64*)matRow_p;
    register int row __asm__ ("r2") = (int)row_p;
    register int parW4 __asm__ ("r3") = (int)parW4_p;
    register int iLo __asm__ ("r12") = (int)iLo_p;
    register int iHi __asm__ ("lr") = (int)iHi_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "push	{%[iLo], %[iHi]}\n\t"
        "ldr	r12, [sp]\n\t"
        "ldr	lr, [sp, #4]\n\t"
        "mul	r7, %[row], %[parW4]\n\t"
        "lsl	r7, r7, #3\n\t"
        "add	r4, %[par], r7\n\t"
        "\n"
    "L_mc_tri_i_%=:\n\t"
        "cmp	r12, lr\n\t"
        "bge	L_mc_tri_ie_%=\n\t"
        "lsr	r7, r12, #3\n\t"
        "add	r10, %[matRow], r7\n\t"
        "ldrb	r9, [r10]\n\t"
        "and	r7, r12, #7\n\t"
        "lsr	r9, r9, r7\n\t"
        "and	r9, r9, #1\n\t"
        "neg	r8, r9\n\t"
        "vdup.32	q3, r8\n\t"
        "mul	r7, r12, %[parW4]\n\t"
        "lsl	r7, r7, #3\n\t"
        "add	r5, %[par], r7\n\t"
        "mov	r10, r4\n\t"
        "mov	r7, r5\n\t"
        "mov	r6, #0\n\t"
        "\n"
    "L_mc_tri_c_%=:\n\t"
        "cmp	r6, %[parW4]\n\t"
        "bge	L_mc_tri_ce_%=\n\t"
        "vld1.8	{d0-d1}, [r10]\n\t"
        "vld1.8	{d2-d3}, [r7]\n\t"
        "vand	q2, q1, q3\n\t"
        "veor	q0, q0, q2\n\t"
        "vst1.8	{d0-d1}, [r10]\n\t"
        "add	r10, r10, #16\n\t"
        "add	r7, r7, #16\n\t"
        "add	r6, r6, #2\n\t"
        "cmp	r6, %[parW4]\n\t"
        "blt	L_mc_tri_c_%=\n\t"
        "\n"
    "L_mc_tri_ce_%=:\n\t"
        "add	r12, r12, #1\n\t"
        "b	L_mc_tri_i_%=\n\t"
        "\n"
    "L_mc_tri_ie_%=:\n\t"
        "pop	{%[iLo], %[iHi]}\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [par] "+r" (par), [matRow] "+r" (matRow), [row] "+r" (row),
          [parW4] "+r" (parW4), [iLo] "+r" (iLo), [iHi] "+r" (iHi)
        :
#else
        :
        : [par] "r" (par), [matRow] "r" (matRow), [row] "r" (row),
          [parW4] "r" (parW4), [iLo] "r" (iLo), [iHi] "r" (iHi)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "q0", "q1",
            "q2", "q3"
    );
}

WOLFSSL_LOCAL void wc_mceliece_u64_sort_neon(word64* x, int n);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_u64_sort_neon(word64* x_p, int n_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_u64_sort_neon(word64* x, int n)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word64* x __asm__ ("r0") = (word64*)x_p;
    register int n __asm__ ("r1") = (int)n_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "mov	r4, %[x]\n\t"
        "mov	r5, %[n]\n\t"
        "cmp	r5, #2\n\t"
        "blt	L_mc_us_end_%=\n\t"
        "mov	r6, #1\n\t"
        "\n"
    "L_mc_us_top_%=:\n\t"
        "sub	r3, r5, r6\n\t"
        "cmp	r6, r3\n\t"
        "bge	L_mc_us_tope_%=\n\t"
        "lsl	r6, r6, #1\n\t"
        "b	L_mc_us_top_%=\n\t"
        "\n"
    "L_mc_us_tope_%=:\n\t"
        "mov	r7, r6\n\t"
        "\n"
    "L_mc_us_p_%=:\n\t"
        "cmp	r7, #0\n\t"
        "beq	L_mc_us_pe_%=\n\t"
        "mov	r11, #0\n\t"
        "\n"
    "L_mc_us_bs_%=:\n\t"
        "sub	r3, r5, r7\n\t"
        "cmp	r11, r3\n\t"
        "bge	L_mc_us_bse_%=\n\t"
        "sub	r10, r5, r7\n\t"
        "sub	r10, r10, r11\n\t"
        "cmp	r10, r7\n\t"
        "ble	L_mc_us_l1_%=\n\t"
        "mov	r10, r7\n\t"
        "\n"
    "L_mc_us_l1_%=:\n\t"
        "lsl	r3, r11, #3\n\t"
        "add	%[x], r4, r3\n\t"
        "add	r12, r11, r7\n\t"
        "lsl	r12, r12, #3\n\t"
        "add	%[n], r4, r12\n\t"
        "mov	r2, r10\n\t"
        "bl	wc_mceliece_u64_minmax_vec_neon\n\t"
        "add	r11, r11, r7\n\t"
        "add	r11, r11, r7\n\t"
        "b	L_mc_us_bs_%=\n\t"
        "\n"
    "L_mc_us_bse_%=:\n\t"
        "mov	r9, #0\n\t"
        "mov	r8, r6\n\t"
        "\n"
    "L_mc_us_q_%=:\n\t"
        "cmp	r8, r7\n\t"
        "ble	L_mc_us_qe_%=\n\t"
        "\n"
    "L_mc_us_w_%=:\n\t"
        "sub	r3, r5, r8\n\t"
        "cmp	r9, r3\n\t"
        "bge	L_mc_us_we_%=\n\t"
        "and	r3, r9, r7\n\t"
        "cmp	r3, #0\n\t"
        "beq	L_mc_us_sel_%=\n\t"
        "sub	r3, r7, #1\n\t"
        "orr	r9, r9, r3\n\t"
        "add	r9, r9, #1\n\t"
        "b	L_mc_us_w_%=\n\t"
        "\n"
    "L_mc_us_sel_%=:\n\t"
        "neg	r3, r7\n\t"
        "and	r3, r9, r3\n\t"
        "add	r3, r3, r7\n\t"
        "sub	r10, r3, r9\n\t"
        "sub	r12, r5, r8\n\t"
        "cmp	r3, r12\n\t"
        "ble	L_mc_us_l2_%=\n\t"
        "sub	r10, r12, r9\n\t"
        "\n"
    "L_mc_us_l2_%=:\n\t"
        "mov	r11, r8\n\t"
        "\n"
    "L_mc_us_r_%=:\n\t"
        "cmp	r11, r7\n\t"
        "ble	L_mc_us_re_%=\n\t"
        "add	r3, r9, r7\n\t"
        "lsl	r3, r3, #3\n\t"
        "add	%[x], r4, r3\n\t"
        "add	r12, r9, r11\n\t"
        "lsl	r12, r12, #3\n\t"
        "add	%[n], r4, r12\n\t"
        "mov	r2, r10\n\t"
        "bl	wc_mceliece_u64_minmax_vec_neon\n\t"
        "lsr	r11, r11, #1\n\t"
        "b	L_mc_us_r_%=\n\t"
        "\n"
    "L_mc_us_re_%=:\n\t"
        "add	r9, r9, r10\n\t"
        "b	L_mc_us_w_%=\n\t"
        "\n"
    "L_mc_us_we_%=:\n\t"
        "lsr	r8, r8, #1\n\t"
        "b	L_mc_us_q_%=\n\t"
        "\n"
    "L_mc_us_qe_%=:\n\t"
        "lsr	r7, r7, #1\n\t"
        "b	L_mc_us_p_%=\n\t"
        "\n"
    "L_mc_us_pe_%=:\n\t"
        "\n"
    "L_mc_us_end_%=:\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [x] "+r" (x), [n] "+r" (n)
        :
#else
        :
        : [x] "r" (x), [n] "r" (n)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r2", "lr", "r4", "r5", "r6", "r7", "r8", "r9", "r10",
            "r11", "r3", "r12"
    );
}

WOLFSSL_LOCAL void wc_mceliece_bs_composeinv_neon(int n, sword16* y, sword16* x,
    sword16* pi, word64* scratch);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_bs_composeinv_neon(int n_p, sword16* y_p,
    sword16* x_p, sword16* pi_p, word64* scratch_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_bs_composeinv_neon(int n, sword16* y,
    sword16* x, sword16* pi, word64* scratch)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register int n __asm__ ("r0") = (int)n_p;
    register sword16* y __asm__ ("r1") = (sword16*)y_p;
    register sword16* x __asm__ ("r2") = (sword16*)x_p;
    register sword16* pi __asm__ ("r3") = (sword16*)pi_p;
    register word64* scratch __asm__ ("r12") = (word64*)scratch_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "push	{%[scratch]}\n\t"
        "ldr	r6, [sp]\n\t"
        "mov	r4, %[n]\n\t"
        "mov	r5, %[y]\n\t"
        "mov	r10, #0\n\t"
        "mov	r7, r6\n\t"
        "mov	r12, #0\n\t"
        "\n"
    "L_mc_cinv_p_%=:\n\t"
        "cmp	r12, r4\n\t"
        "bge	L_mc_cinv_pe_%=\n\t"
        "ldrh	r8, [%[pi]]\n\t"
        "lsl	r8, r8, #16\n\t"
        "ldrh	r9, [%[x]]\n\t"
        "orr	r8, r8, r9\n\t"
        "vmov	d0, r8, r10\n\t"
        "vst1.8	{d0}, [r7]\n\t"
        "add	%[x], %[x], #2\n\t"
        "add	%[pi], %[pi], #2\n\t"
        "add	r7, r7, #8\n\t"
        "add	r12, r12, #1\n\t"
        "b	L_mc_cinv_p_%=\n\t"
        "\n"
    "L_mc_cinv_pe_%=:\n\t"
        "mov	%[n], r6\n\t"
        "mov	%[y], r4\n\t"
        "bl	wc_mceliece_u64_sort_neon\n\t"
        "mov	r7, r6\n\t"
        "mov	%[x], r5\n\t"
        "mov	r12, #0\n\t"
        "\n"
    "L_mc_cinv_u_%=:\n\t"
        "cmp	r12, r4\n\t"
        "bge	L_mc_cinv_ue_%=\n\t"
        "ldr	r8, [r7]\n\t"
        "strh	r8, [%[x]]\n\t"
        "add	r7, r7, #8\n\t"
        "add	%[x], %[x], #2\n\t"
        "add	r12, r12, #1\n\t"
        "b	L_mc_cinv_u_%=\n\t"
        "\n"
    "L_mc_cinv_ue_%=:\n\t"
        "pop	{%[scratch]}\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [n] "+r" (n), [y] "+r" (y), [x] "+r" (x), [pi] "+r" (pi),
          [scratch] "+r" (scratch)
        :
#else
        :
        : [n] "r" (n), [y] "r" (y), [x] "r" (x), [pi] "r" (pi),
          [scratch] "r" (scratch)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "lr", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "q0"
    );
}

WOLFSSL_LOCAL void wc_mceliece_mont_batch_inv_neon(word64* einvbs, word64* ffts,
    word64* scratch, word64* c, int do_sq);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_mont_batch_inv_neon(word64* einvbs_p,
    word64* ffts_p, word64* scratch_p, word64* c_p, int do_sq_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_mont_batch_inv_neon(word64* einvbs,
    word64* ffts, word64* scratch, word64* c, int do_sq)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word64* einvbs __asm__ ("r0") = (word64*)einvbs_p;
    register word64* ffts __asm__ ("r1") = (word64*)ffts_p;
    register word64* scratch __asm__ ("r2") = (word64*)scratch_p;
    register word64* c __asm__ ("r3") = (word64*)c_p;
    register int do_sq __asm__ ("r12") = (int)do_sq_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "push	{%[do_sq]}\n\t"
        "ldr	r10, [sp]\n\t"
        "mov	r4, %[einvbs]\n\t"
        "mov	r5, %[ffts]\n\t"
        "mov	r6, %[scratch]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r8, #0xa0\n\t"
        "orr	r8, r8, #0x100\n\t"
#else
        "mov	r8, #0x1a0\n\t"
#endif
        "cmp	r10, #0\n\t"
        "beq	L_mc_mbi_sqe_%=\n\t"
        "mov	r7, #0\n\t"
        "\n"
    "L_mc_mbi_sq_%=:\n\t"
        "cmp	r7, #32\n\t"
        "bge	L_mc_mbi_sqe_%=\n\t"
        "mul	r12, r7, r8\n\t"
        "add	%[einvbs], r5, r12\n\t"
        "mov	%[ffts], %[einvbs]\n\t"
        "mov	%[scratch], %[einvbs]\n\t"
        "add	%[c], r6, #0x340\n\t"
        "bl	wc_mceliece_aff_v256_mul_neon\n\t"
        "add	r7, r7, #1\n\t"
        "b	L_mc_mbi_sq_%=\n\t"
        "\n"
    "L_mc_mbi_sqe_%=:\n\t"
        "add	r9, r5, #0\n\t"
        "vld1.8	{d0-d3}, [r9]\n\t"
        "add	r9, r4, #0\n\t"
        "vst1.8	{d0-d3}, [r9]\n\t"
        "add	r9, r5, #32\n\t"
        "vld1.8	{d0-d3}, [r9]\n\t"
        "add	r9, r4, #32\n\t"
        "vst1.8	{d0-d3}, [r9]\n\t"
        "add	r9, r5, #0x40\n\t"
        "vld1.8	{d0-d3}, [r9]\n\t"
        "add	r9, r4, #0x40\n\t"
        "vst1.8	{d0-d3}, [r9]\n\t"
        "add	r9, r5, #0x60\n\t"
        "vld1.8	{d0-d3}, [r9]\n\t"
        "add	r9, r4, #0x60\n\t"
        "vst1.8	{d0-d3}, [r9]\n\t"
        "add	r9, r5, #0x80\n\t"
        "vld1.8	{d0-d3}, [r9]\n\t"
        "add	r9, r4, #0x80\n\t"
        "vst1.8	{d0-d3}, [r9]\n\t"
        "add	r9, r5, #0xa0\n\t"
        "vld1.8	{d0-d3}, [r9]\n\t"
        "add	r9, r4, #0xa0\n\t"
        "vst1.8	{d0-d3}, [r9]\n\t"
        "add	r9, r5, #0xc0\n\t"
        "vld1.8	{d0-d3}, [r9]\n\t"
        "add	r9, r4, #0xc0\n\t"
        "vst1.8	{d0-d3}, [r9]\n\t"
        "add	r9, r5, #0xe0\n\t"
        "vld1.8	{d0-d3}, [r9]\n\t"
        "add	r9, r4, #0xe0\n\t"
        "vst1.8	{d0-d3}, [r9]\n\t"
        "add	r9, r5, #0x100\n\t"
        "vld1.8	{d0-d3}, [r9]\n\t"
        "add	r9, r4, #0x100\n\t"
        "vst1.8	{d0-d3}, [r9]\n\t"
        "add	r9, r5, #0x120\n\t"
        "vld1.8	{d0-d3}, [r9]\n\t"
        "add	r9, r4, #0x120\n\t"
        "vst1.8	{d0-d3}, [r9]\n\t"
        "add	r9, r5, #0x140\n\t"
        "vld1.8	{d0-d3}, [r9]\n\t"
        "add	r9, r4, #0x140\n\t"
        "vst1.8	{d0-d3}, [r9]\n\t"
        "add	r9, r5, #0x160\n\t"
        "vld1.8	{d0-d3}, [r9]\n\t"
        "add	r9, r4, #0x160\n\t"
        "vst1.8	{d0-d3}, [r9]\n\t"
        "add	r9, r5, #0x180\n\t"
        "vld1.8	{d0-d3}, [r9]\n\t"
        "add	r9, r4, #0x180\n\t"
        "vst1.8	{d0-d3}, [r9]\n\t"
        "mov	r7, #1\n\t"
        "\n"
    "L_mc_mbi_pf_%=:\n\t"
        "cmp	r7, #32\n\t"
        "bge	L_mc_mbi_pfe_%=\n\t"
        "mul	r12, r7, r8\n\t"
        "add	%[einvbs], r4, r12\n\t"
        "sub	%[ffts], %[einvbs], #0x1a0\n\t"
        "add	%[scratch], r5, r12\n\t"
        "add	%[c], r6, #0x340\n\t"
        "bl	wc_mceliece_aff_v256_mul_neon\n\t"
        "add	r7, r7, #1\n\t"
        "b	L_mc_mbi_pf_%=\n\t"
        "\n"
    "L_mc_mbi_pfe_%=:\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r12, #0x60\n\t"
        "orr	r12, r12, #0x3200\n\t"
#else
        "mov	r12, #0x3260\n\t"
#endif
        "mov	%[einvbs], r6\n\t"
        "add	%[ffts], r4, r12\n\t"
        "add	%[scratch], r6, #0x660\n\t"
        "add	%[c], r6, #0x340\n\t"
        "bl	wc_mceliece_aff_inv256_neon\n\t"
        "mov	r7, #31\n\t"
        "\n"
    "L_mc_mbi_sf_%=:\n\t"
        "cmp	r7, #1\n\t"
        "blt	L_mc_mbi_sfe_%=\n\t"
        "mul	r12, r7, r8\n\t"
        "add	%[einvbs], r6, #0x1a0\n\t"
        "mov	%[ffts], r6\n\t"
        "add	%[scratch], r4, r12\n\t"
        "sub	%[scratch], %[scratch], #0x1a0\n\t"
        "add	%[c], r6, #0x340\n\t"
        "bl	wc_mceliece_aff_v256_mul_neon\n\t"
        "mov	%[einvbs], r6\n\t"
        "mov	%[ffts], r6\n\t"
        "mul	r12, r7, r8\n\t"
        "add	%[scratch], r5, r12\n\t"
        "add	%[c], r6, #0x340\n\t"
        "bl	wc_mceliece_aff_v256_mul_neon\n\t"
        "mul	r12, r7, r8\n\t"
        "add	%[einvbs], r4, r12\n\t"
        "add	%[ffts], r6, #0x1a0\n\t"
        "add	r9, %[ffts], #0\n\t"
        "vld1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[einvbs], #0\n\t"
        "vst1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[ffts], #32\n\t"
        "vld1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[einvbs], #32\n\t"
        "vst1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[ffts], #0x40\n\t"
        "vld1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[einvbs], #0x40\n\t"
        "vst1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[ffts], #0x60\n\t"
        "vld1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[einvbs], #0x60\n\t"
        "vst1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[ffts], #0x80\n\t"
        "vld1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[einvbs], #0x80\n\t"
        "vst1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[ffts], #0xa0\n\t"
        "vld1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[einvbs], #0xa0\n\t"
        "vst1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[ffts], #0xc0\n\t"
        "vld1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[einvbs], #0xc0\n\t"
        "vst1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[ffts], #0xe0\n\t"
        "vld1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[einvbs], #0xe0\n\t"
        "vst1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[ffts], #0x100\n\t"
        "vld1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[einvbs], #0x100\n\t"
        "vst1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[ffts], #0x120\n\t"
        "vld1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[einvbs], #0x120\n\t"
        "vst1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[ffts], #0x140\n\t"
        "vld1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[einvbs], #0x140\n\t"
        "vst1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[ffts], #0x160\n\t"
        "vld1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[einvbs], #0x160\n\t"
        "vst1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[ffts], #0x180\n\t"
        "vld1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[einvbs], #0x180\n\t"
        "vst1.8	{d0-d3}, [r9]\n\t"
        "sub	r7, r7, #1\n\t"
        "b	L_mc_mbi_sf_%=\n\t"
        "\n"
    "L_mc_mbi_sfe_%=:\n\t"
        "mov	%[einvbs], r4\n\t"
        "mov	%[ffts], r6\n\t"
        "add	r9, %[ffts], #0\n\t"
        "vld1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[einvbs], #0\n\t"
        "vst1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[ffts], #32\n\t"
        "vld1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[einvbs], #32\n\t"
        "vst1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[ffts], #0x40\n\t"
        "vld1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[einvbs], #0x40\n\t"
        "vst1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[ffts], #0x60\n\t"
        "vld1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[einvbs], #0x60\n\t"
        "vst1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[ffts], #0x80\n\t"
        "vld1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[einvbs], #0x80\n\t"
        "vst1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[ffts], #0xa0\n\t"
        "vld1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[einvbs], #0xa0\n\t"
        "vst1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[ffts], #0xc0\n\t"
        "vld1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[einvbs], #0xc0\n\t"
        "vst1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[ffts], #0xe0\n\t"
        "vld1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[einvbs], #0xe0\n\t"
        "vst1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[ffts], #0x100\n\t"
        "vld1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[einvbs], #0x100\n\t"
        "vst1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[ffts], #0x120\n\t"
        "vld1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[einvbs], #0x120\n\t"
        "vst1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[ffts], #0x140\n\t"
        "vld1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[einvbs], #0x140\n\t"
        "vst1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[ffts], #0x160\n\t"
        "vld1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[einvbs], #0x160\n\t"
        "vst1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[ffts], #0x180\n\t"
        "vld1.8	{d0-d3}, [r9]\n\t"
        "add	r9, %[einvbs], #0x180\n\t"
        "vst1.8	{d0-d3}, [r9]\n\t"
        "pop	{%[do_sq]}\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [einvbs] "+r" (einvbs), [ffts] "+r" (ffts), [scratch] "+r" (scratch),
          [c] "+r" (c), [do_sq] "+r" (do_sq)
        :
#else
        :
        : [einvbs] "r" (einvbs), [ffts] "r" (ffts), [scratch] "r" (scratch),
          [c] "r" (c), [do_sq] "r" (do_sq)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "lr", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "q0",
            "q1"
    );
}

WOLFSSL_LOCAL void wc_mceliece_pk_gen_elim_neon(word64* mat, int row, int mt,
    int nbiW, int iBlk, int jBit);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_pk_gen_elim_neon(word64* mat_p,
    int row_p, int mt_p, int nbiW_p, int iBlk_p, int jBit_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_pk_gen_elim_neon(word64* mat, int row,
    int mt, int nbiW, int iBlk, int jBit)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word64* mat __asm__ ("r0") = (word64*)mat_p;
    register int row __asm__ ("r1") = (int)row_p;
    register int mt __asm__ ("r2") = (int)mt_p;
    register int nbiW __asm__ ("r3") = (int)nbiW_p;
    register int iBlk __asm__ ("r12") = (int)iBlk_p;
    register int jBit __asm__ ("lr") = (int)jBit_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "push	{%[iBlk], %[jBit]}\n\t"
        "ldr	r11, [sp]\n\t"
        "ldr	r9, [sp, #4]\n\t"
        "lsl	lr, r11, #3\n\t"
        "lsr	r11, r9, #3\n\t"
        "add	lr, lr, r11\n\t"
        "and	r9, r9, #7\n\t"
        "mov	r4, #1\n\t"
        "lsl	r4, r4, r9\n\t"
        "mul	r9, %[row], %[nbiW]\n\t"
        "lsl	r9, r9, #3\n\t"
        "add	r12, %[mat], r9\n\t"
        "add	r5, %[row], #1\n\t"
        "\n"
    "L_mc_pke_kk_%=:\n\t"
        "cmp	r5, %[mt]\n\t"
        "bge	L_mc_pke_kke_%=\n\t"
        "mul	r9, r5, %[nbiW]\n\t"
        "lsl	r9, r9, #3\n\t"
        "add	r6, %[mat], r9\n\t"
        "add	r10, r6, lr\n\t"
        "ldrb	r11, [r10]\n\t"
        "and	r7, r11, r4\n\t"
        "rsb	r11, r7, #0\n\t"
        "orr	r11, r11, r7\n\t"
        "asr	r8, r11, #31\n\t"
        "vdup.32	q6, r8\n\t"
        "lsl	r8, %[nbiW], #3\n\t"
        "mov	r9, #0\n\t"
        "\n"
    "L_mc_pke_c_%=:\n\t"
        "add	r10, r12, r9\n\t"
        "vld1.8	{d4-d7}, [r10]\n\t"
        "add	r10, r6, r9\n\t"
        "vld1.8	{d0-d3}, [r10]\n\t"
        "vand	q4, q2, q6\n\t"
        "vand	q5, q3, q6\n\t"
        "veor	q0, q0, q4\n\t"
        "veor	q1, q1, q5\n\t"
        "vst1.8	{d0-d3}, [r10]\n\t"
        "add	r9, r9, #32\n\t"
        "cmp	r9, r8\n\t"
        "blt	L_mc_pke_c_%=\n\t"
        "\n"
    "L_mc_pke_ce_%=:\n\t"
        "add	r10, r6, lr\n\t"
        "ldrb	r11, [r10]\n\t"
        "orr	r11, r11, r7\n\t"
        "strb	r11, [r10]\n\t"
        "add	r5, r5, #1\n\t"
        "b	L_mc_pke_kk_%=\n\t"
        "\n"
    "L_mc_pke_kke_%=:\n\t"
        "pop	{%[iBlk], %[jBit]}\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [mat] "+r" (mat), [row] "+r" (row), [mt] "+r" (mt),
          [nbiW] "+r" (nbiW), [iBlk] "+r" (iBlk), [jBit] "+r" (jBit)
        :
#else
        :
        : [mat] "r" (mat), [row] "r" (row), [mt] "r" (mt), [nbiW] "r" (nbiW),
          [iBlk] "r" (iBlk), [jBit] "r" (jBit)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11",
            "q0", "q1", "q2", "q3", "q4", "q5", "q6"
    );
}

WOLFSSL_LOCAL void wc_mceliece_pk_gen_cswap_neon(word64* mat, sword16* ind,
    int row, int mt, int nbiW, int iBlk, int jBit);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_pk_gen_cswap_neon(word64* mat_p,
    sword16* ind_p, int row_p, int mt_p, int nbiW_p, int iBlk_p, int jBit_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_pk_gen_cswap_neon(word64* mat,
    sword16* ind, int row, int mt, int nbiW, int iBlk, int jBit)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word64* mat __asm__ ("r0") = (word64*)mat_p;
    register sword16* ind __asm__ ("r1") = (sword16*)ind_p;
    register int row __asm__ ("r2") = (int)row_p;
    register int mt __asm__ ("r3") = (int)mt_p;
    register int nbiW __asm__ ("r12") = (int)nbiW_p;
    register int iBlk __asm__ ("lr") = (int)iBlk_p;
    register int jBit __asm__ ("r4") = (int)jBit_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "push	{%[jBit]}\n\t"
        "push	{%[nbiW], %[iBlk]}\n\t"
        "sub	sp, sp, #4\n\t"
        "ldr	r12, [sp, #4]\n\t"
        "ldr	r7, [sp, #8]\n\t"
        "ldr	r8, [sp, #12]\n\t"
        "lsl	r9, r7, #3\n\t"
        "lsr	r10, r8, #3\n\t"
        "add	r9, r9, r10\n\t"
        "str	r9, [sp]\n\t"
        "and	r4, r8, #7\n\t"
        "mul	r7, %[row], r12\n\t"
        "lsl	r7, r7, #3\n\t"
        "add	lr, %[mat], r7\n\t"
        "add	r5, %[row], #1\n\t"
        "\n"
    "L_mc_pkc_kk_%=:\n\t"
        "cmp	r5, %[mt]\n\t"
        "bge	L_mc_pkc_kke_%=\n\t"
        "mul	r7, r5, r12\n\t"
        "lsl	r7, r7, #3\n\t"
        "add	r6, %[mat], r7\n\t"
        "ldr	r11, [sp]\n\t"
        "add	r10, lr, r11\n\t"
        "ldrb	r7, [r10]\n\t"
        "lsr	r7, r7, r4\n\t"
        "and	r7, r7, #1\n\t"
        "add	r10, r6, r11\n\t"
        "ldrb	r8, [r10]\n\t"
        "lsr	r8, r8, r4\n\t"
        "and	r8, r8, #1\n\t"
        "eor	r7, r7, #1\n\t"
        "and	r9, r8, r7\n\t"
        "neg	r9, r9\n\t"
        "vdup.32	q6, r9\n\t"
        "lsl	r10, %[row], #1\n\t"
        "add	r10, %[ind], r10\n\t"
        "ldrh	r7, [r10]\n\t"
        "lsl	r10, r5, #1\n\t"
        "add	r10, %[ind], r10\n\t"
        "ldrh	r8, [r10]\n\t"
        "eor	r11, r7, r8\n\t"
        "and	r11, r11, r9\n\t"
        "eor	r8, r8, r11\n\t"
        "strh	r8, [r10]\n\t"
        "eor	r7, r7, r11\n\t"
        "lsl	r10, %[row], #1\n\t"
        "add	r10, %[ind], r10\n\t"
        "strh	r7, [r10]\n\t"
        "mov	r9, lr\n\t"
        "mov	r10, r6\n\t"
        "mov	r7, #0\n\t"
        "\n"
    "L_mc_pkc_c_%=:\n\t"
        "cmp	r7, r12\n\t"
        "bge	L_mc_pkc_ce_%=\n\t"
        "vld1.8	{d0-d3}, [r9]\n\t"
        "vld1.8	{d4-d7}, [r10]\n\t"
        "veor	q4, q0, q2\n\t"
        "veor	q5, q1, q3\n\t"
        "vand	q4, q4, q6\n\t"
        "vand	q5, q5, q6\n\t"
        "veor	q0, q0, q4\n\t"
        "veor	q1, q1, q5\n\t"
        "vst1.8	{d0-d3}, [r9]\n\t"
        "veor	q2, q2, q4\n\t"
        "veor	q3, q3, q5\n\t"
        "vst1.8	{d4-d7}, [r10]\n\t"
        "add	r9, r9, #32\n\t"
        "add	r10, r10, #32\n\t"
        "add	r7, r7, #4\n\t"
        "cmp	r7, r12\n\t"
        "blt	L_mc_pkc_c_%=\n\t"
        "\n"
    "L_mc_pkc_ce_%=:\n\t"
        "add	r5, r5, #1\n\t"
        "b	L_mc_pkc_kk_%=\n\t"
        "\n"
    "L_mc_pkc_kke_%=:\n\t"
        "add	sp, sp, #4\n\t"
        "pop	{%[nbiW], %[iBlk]}\n\t"
        "pop	{%[jBit]}\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [mat] "+r" (mat), [ind] "+r" (ind), [row] "+r" (row), [mt] "+r" (mt),
          [nbiW] "+r" (nbiW), [iBlk] "+r" (iBlk), [jBit] "+r" (jBit)
        :
#else
        :
        : [mat] "r" (mat), [ind] "r" (ind), [row] "r" (row), [mt] "r" (mt),
          [nbiW] "r" (nbiW), [iBlk] "r" (iBlk), [jBit] "r" (jBit)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "q0",
            "q1", "q2", "q3", "q4", "q5", "q6"
    );
}

WOLFSSL_LOCAL void wc_mceliece_bs_par_fill_neon(word64* par, word64* prod,
    const word64* consts, int t, int m, int parW, int nvalid, word64* cscr);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_bs_par_fill_neon(word64* par_p,
    word64* prod_p, const word64* consts_p, int t_p, int m_p, int parW_p,
    int nvalid_p, word64* cscr_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_bs_par_fill_neon(word64* par,
    word64* prod, const word64* consts, int t, int m, int parW, int nvalid,
    word64* cscr)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word64* par __asm__ ("r0") = (word64*)par_p;
    register word64* prod __asm__ ("r1") = (word64*)prod_p;
    register const word64* consts __asm__ ("r2") = (const word64*)consts_p;
    register int t __asm__ ("r3") = (int)t_p;
    register int m __asm__ ("r12") = (int)m_p;
    register int parW __asm__ ("lr") = (int)parW_p;
    register int nvalid __asm__ ("r4") = (int)nvalid_p;
    register word64* cscr __asm__ ("r5") = (word64*)cscr_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "push	{%[nvalid], %[cscr]}\n\t"
        "push	{%[m], %[parW]}\n\t"
        "sub	sp, sp, #8\n\t"
        "str	%[consts], [sp]\n\t"
        "ldr	r7, [sp, #8]\n\t"
        "ldr	r8, [sp, #12]\n\t"
        "ldr	r9, [sp, #16]\n\t"
        "ldr	r12, [sp, #20]\n\t"
        "str	r12, [sp, #4]\n\t"
        "mov	r4, %[par]\n\t"
        "mov	r5, %[prod]\n\t"
        "mov	r6, %[t]\n\t"
        "mov	r10, #0\n\t"
        "\n"
    "L_mc_prf_i_%=:\n\t"
        "cmp	r10, r6\n\t"
        "bge	L_mc_prf_ie_%=\n\t"
        "mov	r11, #0\n\t"
        "\n"
    "L_mc_prf_b_%=:\n\t"
        "cmp	r11, r8\n\t"
        "bge	L_mc_prf_be_%=\n\t"
        "cmp	r11, r9\n\t"
        "bge	L_mc_prf_sk_%=\n\t"
        "cmp	r10, #0\n\t"
        "beq	L_mc_prf_nm_%=\n\t"
        "mul	%[par], r11, r7\n\t"
        "lsl	%[par], %[par], #2\n\t"
        "lsl	%[par], %[par], #3\n\t"
        "add	%[prod], r5, %[par]\n\t"
        "ldr	%[consts], [sp]\n\t"
        "add	%[consts], %[consts], %[par]\n\t"
        "ldr	%[t], [sp, #4]\n\t"
        "mov	%[par], %[prod]\n\t"
        "bl	wc_mceliece_aff_v256_mul_neon\n\t"
        "\n"
    "L_mc_prf_nm_%=:\n\t"
        "mul	%[prod], r11, r7\n\t"
        "lsl	%[prod], %[prod], #2\n\t"
        "lsl	%[prod], %[prod], #3\n\t"
        "add	%[prod], r5, %[prod]\n\t"
        "lsl	%[t], r8, #2\n\t"
        "mul	%[par], r10, r7\n\t"
        "mul	%[par], %[par], %[t]\n\t"
        "lsl	r12, r11, #2\n\t"
        "add	%[par], %[par], r12\n\t"
        "lsl	%[par], %[par], #3\n\t"
        "add	%[consts], r4, %[par]\n\t"
        "lsl	%[t], %[t], #3\n\t"
        "mov	r12, r7\n\t"
        "\n"
    "L_mc_prf_kk_%=:\n\t"
        "vld1.8	{d0-d3}, [%[prod]]\n\t"
        "vst1.8	{d0-d3}, [%[consts]]\n\t"
        "add	%[prod], %[prod], #32\n\t"
        "add	%[consts], %[consts], %[t]\n\t"
        "subs	r12, r12, #1\n\t"
        "bne	L_mc_prf_kk_%=\n\t"
        "\n"
    "L_mc_prf_sk_%=:\n\t"
        "add	r11, r11, #1\n\t"
        "b	L_mc_prf_b_%=\n\t"
        "\n"
    "L_mc_prf_be_%=:\n\t"
        "add	r10, r10, #1\n\t"
        "b	L_mc_prf_i_%=\n\t"
        "\n"
    "L_mc_prf_ie_%=:\n\t"
        "add	sp, sp, #8\n\t"
        "pop	{%[m], %[parW]}\n\t"
        "pop	{%[nvalid], %[cscr]}\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [par] "+r" (par), [prod] "+r" (prod), [consts] "+r" (consts),
          [t] "+r" (t), [m] "+r" (m), [parW] "+r" (parW),
          [nvalid] "+r" (nvalid), [cscr] "+r" (cscr)
        :
#else
        :
        : [par] "r" (par), [prod] "r" (prod), [consts] "r" (consts),
          [t] "r" (t), [m] "r" (m), [parW] "r" (parW), [nvalid] "r" (nvalid),
          [cscr] "r" (cscr)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r6", "r7", "r8", "r9", "r10", "r11", "q0", "q1"
    );
}

WOLFSSL_LOCAL void wc_mceliece_bs_lu_fill_neon(word64* mat, word64* prod,
    const word64* consts, int t, int m, int nbi, int nbiW, word64* cscr);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_bs_lu_fill_neon(word64* mat_p,
    word64* prod_p, const word64* consts_p, int t_p, int m_p, int nbi_p,
    int nbiW_p, word64* cscr_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_bs_lu_fill_neon(word64* mat,
    word64* prod, const word64* consts, int t, int m, int nbi, int nbiW,
    word64* cscr)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word64* mat __asm__ ("r0") = (word64*)mat_p;
    register word64* prod __asm__ ("r1") = (word64*)prod_p;
    register const word64* consts __asm__ ("r2") = (const word64*)consts_p;
    register int t __asm__ ("r3") = (int)t_p;
    register int m __asm__ ("r12") = (int)m_p;
    register int nbi __asm__ ("lr") = (int)nbi_p;
    register int nbiW __asm__ ("r4") = (int)nbiW_p;
    register word64* cscr __asm__ ("r5") = (word64*)cscr_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "push	{%[nbiW], %[cscr]}\n\t"
        "push	{%[m], %[nbi]}\n\t"
        "sub	sp, sp, #8\n\t"
        "str	%[consts], [sp]\n\t"
        "ldr	r7, [sp, #8]\n\t"
        "ldr	r8, [sp, #12]\n\t"
        "ldr	r9, [sp, #16]\n\t"
        "ldr	r12, [sp, #20]\n\t"
        "str	r12, [sp, #4]\n\t"
        "mov	r4, %[mat]\n\t"
        "mov	r5, %[prod]\n\t"
        "mov	r6, %[t]\n\t"
        "mov	r10, #0\n\t"
        "\n"
    "L_mc_luf_i_%=:\n\t"
        "cmp	r10, r6\n\t"
        "bge	L_mc_luf_ie_%=\n\t"
        "mov	r11, #0\n\t"
        "\n"
    "L_mc_luf_j_%=:\n\t"
        "cmp	r11, r8\n\t"
        "bge	L_mc_luf_je_%=\n\t"
        "cmp	r10, #0\n\t"
        "beq	L_mc_luf_nm_%=\n\t"
        "mul	%[mat], r11, r7\n\t"
        "lsl	%[mat], %[mat], #2\n\t"
        "lsl	%[mat], %[mat], #3\n\t"
        "add	%[prod], r5, %[mat]\n\t"
        "ldr	%[consts], [sp]\n\t"
        "add	%[consts], %[consts], %[mat]\n\t"
        "ldr	%[t], [sp, #4]\n\t"
        "mov	%[mat], %[prod]\n\t"
        "bl	wc_mceliece_aff_v256_mul_neon\n\t"
        "\n"
    "L_mc_luf_nm_%=:\n\t"
        "mul	%[mat], r10, r7\n\t"
        "mul	%[mat], %[mat], r9\n\t"
        "lsl	r12, r11, #2\n\t"
        "add	%[mat], %[mat], r12\n\t"
        "lsl	%[mat], %[mat], #3\n\t"
        "add	%[consts], r4, %[mat]\n\t"
        "mul	%[prod], r11, r7\n\t"
        "lsl	%[prod], %[prod], #2\n\t"
        "lsl	%[prod], %[prod], #3\n\t"
        "add	%[prod], r5, %[prod]\n\t"
        "lsl	%[t], r9, #3\n\t"
        "mov	r12, r7\n\t"
        "\n"
    "L_mc_luf_kk_%=:\n\t"
        "vld1.8	{d0-d3}, [%[prod]]\n\t"
        "vst1.8	{d0-d3}, [%[consts]]\n\t"
        "add	%[prod], %[prod], #32\n\t"
        "add	%[consts], %[consts], %[t]\n\t"
        "subs	r12, r12, #1\n\t"
        "bne	L_mc_luf_kk_%=\n\t"
        "add	r11, r11, #1\n\t"
        "b	L_mc_luf_j_%=\n\t"
        "\n"
    "L_mc_luf_je_%=:\n\t"
        "add	r10, r10, #1\n\t"
        "b	L_mc_luf_i_%=\n\t"
        "\n"
    "L_mc_luf_ie_%=:\n\t"
        "add	sp, sp, #8\n\t"
        "pop	{%[m], %[nbi]}\n\t"
        "pop	{%[nbiW], %[cscr]}\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [mat] "+r" (mat), [prod] "+r" (prod), [consts] "+r" (consts),
          [t] "+r" (t), [m] "+r" (m), [nbi] "+r" (nbi), [nbiW] "+r" (nbiW),
          [cscr] "+r" (cscr)
        :
#else
        :
        : [mat] "r" (mat), [prod] "r" (prod), [consts] "r" (consts),
          [t] "r" (t), [m] "r" (m), [nbi] "r" (nbi), [nbiW] "r" (nbiW),
          [cscr] "r" (cscr)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r6", "r7", "r8", "r9", "r10", "r11", "q0", "q1"
    );
}

WOLFSSL_LOCAL void wc_mceliece_bs_sort_rows_neon(sword16* x, word64* mat,
    int parWidth, int n);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_bs_sort_rows_neon(sword16* x_p,
    word64* mat_p, int parWidth_p, int n_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_bs_sort_rows_neon(sword16* x,
    word64* mat, int parWidth, int n)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register sword16* x __asm__ ("r0") = (sword16*)x_p;
    register word64* mat __asm__ ("r1") = (word64*)mat_p;
    register int parWidth __asm__ ("r2") = (int)parWidth_p;
    register int n __asm__ ("r3") = (int)n_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "sub	sp, sp, #12\n\t"
        "mov	r4, %[x]\n\t"
        "mov	r5, %[mat]\n\t"
        "mov	r6, %[parWidth]\n\t"
        "mov	r7, %[n]\n\t"
        "mov	%[x], #1\n\t"
        "\n"
    "L_mc_srt_tw_%=:\n\t"
        "mov	%[mat], #1\n\t"
        "lsl	%[mat], %[mat], %[x]\n\t"
        "cmp	%[mat], r7\n\t"
        "bge	L_mc_srt_twe_%=\n\t"
        "add	%[x], %[x], #1\n\t"
        "b	L_mc_srt_tw_%=\n\t"
        "\n"
    "L_mc_srt_twe_%=:\n\t"
        "str	%[x], [sp, #4]\n\t"
        "sub	r8, %[x], #1\n\t"
        "\n"
    "L_mc_srt_j_%=:\n\t"
        "cmp	r8, #0\n\t"
        "blt	L_mc_srt_je_%=\n\t"
        "ldr	%[x], [sp, #4]\n\t"
        "mov	%[mat], #1\n\t"
        "sub	%[x], %[x], #1\n\t"
        "lsl	%[mat], %[mat], %[x]\n\t"
        "str	%[mat], [sp, #8]\n\t"
        "mov	r9, #0\n\t"
        "mov	%[x], #1\n\t"
        "lsl	%[x], %[x], r8\n\t"
        "mov	r10, %[x]\n\t"
        "\n"
    "L_mc_srt_ps_%=:\n\t"
        "mov	r11, #0\n\t"
        "\n"
    "L_mc_srt_i_%=:\n\t"
        "sub	r12, r7, r10\n\t"
        "cmp	r11, r12\n\t"
        "bge	L_mc_srt_ie_%=\n\t"
        "mov	%[x], #1\n\t"
        "lsl	%[x], %[x], r8\n\t"
        "and	%[mat], r11, %[x]\n\t"
        "cmp	%[mat], r9\n\t"
        "bne	L_mc_srt_sk_%=\n\t"
        "add	%[mat], r11, r10\n\t"
        "str	%[mat], [sp]\n\t"
        "mov	%[x], r4\n\t"
        "mov	%[mat], r5\n\t"
        "mov	%[parWidth], r6\n\t"
        "mov	%[n], r11\n\t"
        "bl	wc_mceliece_bs_minmax_rows_neon\n\t"
        "\n"
    "L_mc_srt_sk_%=:\n\t"
        "add	r11, r11, #1\n\t"
        "b	L_mc_srt_i_%=\n\t"
        "\n"
    "L_mc_srt_ie_%=:\n\t"
        "mov	%[x], #1\n\t"
        "lsl	%[x], %[x], r8\n\t"
        "ldr	%[mat], [sp, #8]\n\t"
        "cmp	%[mat], %[x]\n\t"
        "beq	L_mc_srt_pse_%=\n\t"
        "sub	r10, %[mat], %[x]\n\t"
        "lsr	%[mat], %[mat], #1\n\t"
        "str	%[mat], [sp, #8]\n\t"
        "mov	r9, %[x]\n\t"
        "b	L_mc_srt_ps_%=\n\t"
        "\n"
    "L_mc_srt_pse_%=:\n\t"
        "sub	r8, r8, #1\n\t"
        "b	L_mc_srt_j_%=\n\t"
        "\n"
    "L_mc_srt_je_%=:\n\t"
        "add	sp, sp, #12\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [x] "+r" (x), [mat] "+r" (mat), [parWidth] "+r" (parWidth),
          [n] "+r" (n)
        :
#else
        :
        : [x] "r" (x), [mat] "r" (mat), [parWidth] "r" (parWidth), [n] "r" (n)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "lr", "r4", "r5", "r6", "r7", "r8", "r9", "r10",
            "r11", "r12"
    );
}

WOLFSSL_LOCAL int wc_mceliece_bs_pk_gen_reduce_neon(word64* mat, sword16* ind,
    int mt, int nbiW, int isf, sword16* pi, word64* pivots);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER int wc_mceliece_bs_pk_gen_reduce_neon(word64* mat_p,
    sword16* ind_p, int mt_p, int nbiW_p, int isf_p, sword16* pi_p,
    word64* pivots_p)
#else
WC_OMIT_FRAME_POINTER int wc_mceliece_bs_pk_gen_reduce_neon(word64* mat,
    sword16* ind, int mt, int nbiW, int isf, sword16* pi, word64* pivots)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word64* mat __asm__ ("r0") = (word64*)mat_p;
    register sword16* ind __asm__ ("r1") = (sword16*)ind_p;
    register int mt __asm__ ("r2") = (int)mt_p;
    register int nbiW __asm__ ("r3") = (int)nbiW_p;
    register int isf __asm__ ("r12") = (int)isf_p;
    register sword16* pi __asm__ ("lr") = (sword16*)pi_p;
    register word64* pivots __asm__ ("r4") = (word64*)pivots_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "push	{%[pivots]}\n\t"
        "push	{%[isf], %[pi]}\n\t"
        "sub	sp, sp, #12\n\t"
        "mov	r4, %[mat]\n\t"
        "mov	r5, %[ind]\n\t"
        "mov	r6, %[mt]\n\t"
        "mov	r7, %[nbiW]\n\t"
        "ldr	r8, [sp, #12]\n\t"
        "ldr	r9, [sp, #16]\n\t"
        "ldr	r10, [sp, #20]\n\t"
        "mov	r11, #0\n\t"
        "\n"
    "L_mc_pgr_r_%=:\n\t"
        "cmp	r11, r6\n\t"
        "bge	L_mc_pgr_re_%=\n\t"
        "cmp	r8, #0\n\t"
        "beq	L_mc_pgr_sk_%=\n\t"
        "sub	r12, r6, #32\n\t"
        "cmp	r11, r12\n\t"
        "bne	L_mc_pgr_sk_%=\n\t"
        "str	r10, [sp]\n\t"
        "mov	%[mat], r4\n\t"
        "mov	%[ind], r7\n\t"
        "mov	%[mt], r6\n\t"
        "mov	%[nbiW], r9\n\t"
        "bl	wc_mceliece_bs_mov_columns_neon\n\t"
        "cmp	%[mat], #0\n\t"
        "bne	L_mc_pgr_f_%=\n\t"
        "\n"
    "L_mc_pgr_sk_%=:\n\t"
        "lsr	r12, r11, #6\n\t"
        "and	%[mat], r11, #63\n\t"
        "str	r7, [sp]\n\t"
        "str	r12, [sp, #4]\n\t"
        "str	%[mat], [sp, #8]\n\t"
        "mov	%[mat], r4\n\t"
        "mov	%[ind], r5\n\t"
        "mov	%[mt], r11\n\t"
        "mov	%[nbiW], r6\n\t"
        "bl	wc_mceliece_pk_gen_cswap_neon\n\t"
        "lsr	%[mat], r11, #6\n\t"
        "and	%[ind], r11, #63\n\t"
        "mul	%[mt], r11, r7\n\t"
        "add	%[mt], %[mt], %[mat]\n\t"
        "lsl	%[mt], %[mt], #3\n\t"
        "lsr	%[nbiW], %[ind], #3\n\t"
        "add	%[mt], %[mt], %[nbiW]\n\t"
        "add	%[mt], r4, %[mt]\n\t"
        "ldrb	%[mt], [%[mt]]\n\t"
        "and	%[nbiW], %[ind], #7\n\t"
        "lsr	%[mt], %[mt], %[nbiW]\n\t"
        "and	%[mt], %[mt], #1\n\t"
        "cmp	%[mt], #0\n\t"
        "beq	L_mc_pgr_f_%=\n\t"
        "lsr	%[mat], r11, #6\n\t"
        "and	%[ind], r11, #63\n\t"
        "str	%[mat], [sp]\n\t"
        "str	%[ind], [sp, #4]\n\t"
        "mov	%[mat], r4\n\t"
        "mov	%[ind], r11\n\t"
        "mov	%[mt], r6\n\t"
        "mov	%[nbiW], r7\n\t"
        "bl	wc_mceliece_pk_gen_elim_neon\n\t"
        "add	r11, r11, #1\n\t"
        "b	L_mc_pgr_r_%=\n\t"
        "\n"
    "L_mc_pgr_re_%=:\n\t"
        "mov	%[mat], #0\n\t"
        "b	L_mc_pgr_e_%=\n\t"
        "\n"
    "L_mc_pgr_f_%=:\n\t"
        "mov	%[mat], #0\n\t"
        "sub	%[mat], %[mat], #1\n\t"
        "\n"
    "L_mc_pgr_e_%=:\n\t"
        "add	sp, sp, #12\n\t"
        "pop	{%[isf], %[pi]}\n\t"
        "pop	{%[pivots]}\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [mat] "+r" (mat), [ind] "+r" (ind), [mt] "+r" (mt),
          [nbiW] "+r" (nbiW), [isf] "+r" (isf), [pi] "+r" (pi),
          [pivots] "+r" (pivots)
        :
#else
        :
        : [mat] "r" (mat), [ind] "r" (ind), [mt] "r" (mt), [nbiW] "r" (nbiW),
          [isf] "r" (isf), [pi] "r" (pi), [pivots] "r" (pivots)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r5", "r6", "r7", "r8", "r9", "r10", "r11"
    );
    return (word32)(size_t)mat;
}

WOLFSSL_LOCAL void wc_mceliece_berlekamp_massey_neon(word16* out,
    const word16* s, int t, word64* scratch);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_berlekamp_massey_neon(word16* out_p,
    const word16* s_p, int t_p, word64* scratch_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_berlekamp_massey_neon(word16* out,
    const word16* s, int t, word64* scratch)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word16* out __asm__ ("r0") = (word16*)out_p;
    register const word16* s __asm__ ("r1") = (const word16*)s_p;
    register int t __asm__ ("r2") = (int)t_p;
    register word64* scratch __asm__ ("r3") = (word64*)scratch_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "sub	sp, sp, #8\n\t"
        "str	%[out], [sp]\n\t"
        "mov	r4, %[s]\n\t"
        "str	%[t], [sp, #4]\n\t"
        "add	r5, %[scratch], #0x200\n\t"
        "mov	%[out], #0\n\t"
        "mov	%[s], #0\n\t"
        "\n"
    "L_mc_bm_in_%=:\n\t"
        "ldr	%[t], [sp, #4]\n\t"
        "cmp	%[s], %[t]\n\t"
        "bgt	L_mc_bm_ine_%=\n\t"
        "lsl	%[t], %[s], #1\n\t"
        "add	r12, r5, %[t]\n\t"
        "strh	%[out], [r12]\n\t"
        "add	r12, r12, #0x200\n\t"
        "strh	%[out], [r12]\n\t"
        "add	%[s], %[s], #1\n\t"
        "b	L_mc_bm_in_%=\n\t"
        "\n"
    "L_mc_bm_ine_%=:\n\t"
        "mov	%[out], #1\n\t"
        "strh	%[out], [r5]\n\t"
        "add	r12, r5, #0x200\n\t"
        "add	r12, r12, #2\n\t"
        "strh	%[out], [r12]\n\t"
        "mov	r7, #0\n\t"
        "mov	r8, #1\n\t"
        "mov	r6, #0\n\t"
        "\n"
    "L_mc_bm_n_%=:\n\t"
        "ldr	%[out], [sp, #4]\n\t"
        "lsl	r11, %[out], #1\n\t"
        "cmp	r6, r11\n\t"
        "bge	L_mc_bm_ne_%=\n\t"
        "mov	r9, #0\n\t"
        "ldr	%[out], [sp, #4]\n\t"
        "mov	r11, %[out]\n\t"
        "cmp	r6, %[out]\n\t"
        "bge	L_mc_bm_d1_%=\n\t"
        "mov	r11, r6\n\t"
        "\n"
    "L_mc_bm_d1_%=:\n\t"
        "add	r11, r11, #1\n\t"
        "lsr	r11, r11, #3\n\t"
        "lsl	r11, r11, #3\n\t"
        "cmp	r11, #0\n\t"
        "beq	L_mc_bm_dt_%=\n\t"
        "mov	%[out], r5\n\t"
        "lsl	%[t], r6, #1\n\t"
        "add	%[s], r4, %[t]\n\t"
        "mov	%[t], r11\n\t"
        "bl	wc_mceliece_gf_discrepancy_neon\n\t"
        "mov	r9, %[out]\n\t"
        "\n"
    "L_mc_bm_dt_%=:\n\t"
        "ldr	%[out], [sp, #4]\n\t"
        "mov	r11, %[out]\n\t"
        "cmp	r6, %[out]\n\t"
        "bge	L_mc_bm_d2_%=\n\t"
        "mov	r11, r6\n\t"
        "\n"
    "L_mc_bm_d2_%=:\n\t"
        "add	%[out], r11, #1\n\t"
        "lsr	%[out], %[out], #3\n\t"
        "lsl	%[out], %[out], #3\n\t"
        "mov	r10, %[out]\n\t"
        "\n"
    "L_mc_bm_dte_%=:\n\t"
        "cmp	r10, r11\n\t"
        "bgt	L_mc_bm_zc_%=\n\t"
        "lsl	%[out], r10, #1\n\t"
        "add	%[out], r5, %[out]\n\t"
        "ldrh	%[out], [%[out]]\n\t"
        "sub	%[s], r6, r10\n\t"
        "lsl	%[s], %[s], #1\n\t"
        "add	%[s], r4, %[s]\n\t"
        "ldrh	%[s], [%[s]]\n\t"
        "bl	wc_mceliece_gf_mul_scalar_neon\n\t"
        "eor	r9, r9, %[out]\n\t"
        "add	r10, r10, #1\n\t"
        "b	L_mc_bm_dte_%=\n\t"
        "\n"
    "L_mc_bm_zc_%=:\n\t"
        "mov	r12, #0\n\t"
        "\n"
    "L_mc_bm_tce_%=:\n\t"
        "ldr	%[out], [sp, #4]\n\t"
        "cmp	r12, %[out]\n\t"
        "bgt	L_mc_bm_zce_%=\n\t"
        "lsl	%[out], r12, #1\n\t"
        "add	%[s], r5, %[out]\n\t"
        "ldrh	%[t], [%[s]]\n\t"
        "sub	%[s], %[s], #0x200\n\t"
        "strh	%[t], [%[s]]\n\t"
        "add	%[s], r5, %[out]\n\t"
        "mov	%[scratch], #0\n\t"
        "strh	%[scratch], [%[s]]\n\t"
        "add	r12, r12, #1\n\t"
        "b	L_mc_bm_tce_%=\n\t"
        "\n"
    "L_mc_bm_zce_%=:\n\t"
        "ldr	%[out], [sp, #4]\n\t"
        "add	%[out], %[out], #1\n\t"
        "lsr	%[out], %[out], #3\n\t"
        "lsl	%[out], %[out], #3\n\t"
        "cmp	%[out], #0\n\t"
        "beq	L_mc_bm_msk_%=\n\t"
        "mov	r11, %[out]\n\t"
        "mov	%[out], r5\n\t"
        "mov	%[s], r8\n\t"
        "sub	%[t], r5, #0x200\n\t"
        "mov	%[scratch], r11\n\t"
        "bl	wc_mceliece_gf_mulc_mac_neon\n\t"
        "mov	%[out], r5\n\t"
        "mov	%[s], r9\n\t"
        "add	%[t], r5, #0x200\n\t"
        "mov	%[scratch], r11\n\t"
        "bl	wc_mceliece_gf_mulc_mac_neon\n\t"
        "\n"
    "L_mc_bm_msk_%=:\n\t"
        "ldr	%[out], [sp, #4]\n\t"
        "add	%[out], %[out], #1\n\t"
        "lsr	%[out], %[out], #3\n\t"
        "lsl	%[out], %[out], #3\n\t"
        "mov	r10, %[out]\n\t"
        "\n"
    "L_mc_bm_mt_%=:\n\t"
        "ldr	%[out], [sp, #4]\n\t"
        "cmp	r10, %[out]\n\t"
        "bgt	L_mc_bm_mte_%=\n\t"
        "lsl	%[out], r10, #1\n\t"
        "sub	%[s], r5, #0x200\n\t"
        "add	%[s], %[s], %[out]\n\t"
        "ldrh	%[s], [%[s]]\n\t"
        "mov	%[out], r8\n\t"
        "bl	wc_mceliece_gf_mul_scalar_neon\n\t"
        "lsl	%[s], r10, #1\n\t"
        "add	%[s], r5, %[s]\n\t"
        "ldrh	%[t], [%[s]]\n\t"
        "eor	%[t], %[t], %[out]\n\t"
        "strh	%[t], [%[s]]\n\t"
        "lsl	%[out], r10, #1\n\t"
        "add	%[s], r5, #0x200\n\t"
        "add	%[s], %[s], %[out]\n\t"
        "ldrh	%[s], [%[s]]\n\t"
        "mov	%[out], r9\n\t"
        "bl	wc_mceliece_gf_mul_scalar_neon\n\t"
        "lsl	%[s], r10, #1\n\t"
        "add	%[s], r5, %[s]\n\t"
        "ldrh	%[t], [%[s]]\n\t"
        "eor	%[t], %[t], %[out]\n\t"
        "strh	%[t], [%[s]]\n\t"
        "add	r10, r10, #1\n\t"
        "b	L_mc_bm_mt_%=\n\t"
        "\n"
    "L_mc_bm_mte_%=:\n\t"
        "sub	%[out], r9, #1\n\t"
        "lsr	%[out], %[out], #31\n\t"
        "sub	%[out], %[out], #1\n\t"
        "lsl	%[s], r7, #1\n\t"
        "sub	%[t], r6, %[s]\n\t"
        "lsr	%[t], %[t], #31\n\t"
        "sub	%[t], %[t], #1\n\t"
        "and	%[t], %[t], %[out]\n\t"
        "add	%[s], r6, #1\n\t"
        "sub	%[s], %[s], r7\n\t"
        "eor	%[out], r7, %[s]\n\t"
        "and	%[out], %[out], %[t]\n\t"
        "eor	r7, r7, %[out]\n\t"
        "mov	r12, #0\n\t"
        "\n"
    "L_mc_bm_bu_%=:\n\t"
        "ldr	%[out], [sp, #4]\n\t"
        "cmp	r12, %[out]\n\t"
        "bgt	L_mc_bm_bue_%=\n\t"
        "lsl	%[out], r12, #1\n\t"
        "add	%[s], r5, #0x200\n\t"
        "add	%[s], %[s], %[out]\n\t"
        "ldrh	%[scratch], [%[s]]\n\t"
        "sub	%[out], %[s], #0x400\n\t"
        "ldrh	%[out], [%[out]]\n\t"
        "eor	%[out], %[out], %[scratch]\n\t"
        "and	%[out], %[out], %[t]\n\t"
        "eor	%[scratch], %[scratch], %[out]\n\t"
        "strh	%[scratch], [%[s]]\n\t"
        "add	r12, r12, #1\n\t"
        "b	L_mc_bm_bu_%=\n\t"
        "\n"
    "L_mc_bm_bue_%=:\n\t"
        "eor	%[out], r8, r9\n\t"
        "and	%[out], %[out], %[t]\n\t"
        "eor	r8, r8, %[out]\n\t"
        "ldr	r12, [sp, #4]\n\t"
        "\n"
    "L_mc_bm_bs_%=:\n\t"
        "cmp	r12, #1\n\t"
        "blt	L_mc_bm_bse_%=\n\t"
        "sub	%[out], r12, #1\n\t"
        "lsl	%[out], %[out], #1\n\t"
        "add	%[s], r5, #0x200\n\t"
        "add	%[s], %[s], %[out]\n\t"
        "ldrh	%[out], [%[s]]\n\t"
        "lsl	%[s], r12, #1\n\t"
        "add	%[t], r5, #0x200\n\t"
        "add	%[t], %[t], %[s]\n\t"
        "strh	%[out], [%[t]]\n\t"
        "sub	r12, r12, #1\n\t"
        "b	L_mc_bm_bs_%=\n\t"
        "\n"
    "L_mc_bm_bse_%=:\n\t"
        "mov	%[out], #0\n\t"
        "add	%[s], r5, #0x200\n\t"
        "strh	%[out], [%[s]]\n\t"
        "add	r6, r6, #1\n\t"
        "b	L_mc_bm_n_%=\n\t"
        "\n"
    "L_mc_bm_ne_%=:\n\t"
        "ldrh	%[out], [r5]\n\t"
        "bl	wc_mceliece_gf_inv_scalar_neon\n\t"
        "mov	r9, %[out]\n\t"
        "ldr	r6, [sp]\n\t"
        "mov	r10, #0\n\t"
        "\n"
    "L_mc_bm_nm_%=:\n\t"
        "ldr	%[out], [sp, #4]\n\t"
        "cmp	r10, %[out]\n\t"
        "bgt	L_mc_bm_nme_%=\n\t"
        "ldr	%[out], [sp, #4]\n\t"
        "sub	%[out], %[out], r10\n\t"
        "lsl	%[out], %[out], #1\n\t"
        "add	%[out], r5, %[out]\n\t"
        "ldrh	%[out], [%[out]]\n\t"
        "mov	%[s], r9\n\t"
        "bl	wc_mceliece_gf_mul_scalar_neon\n\t"
        "lsl	%[s], r10, #1\n\t"
        "add	%[s], r6, %[s]\n\t"
        "strh	%[out], [%[s]]\n\t"
        "add	r10, r10, #1\n\t"
        "b	L_mc_bm_nm_%=\n\t"
        "\n"
    "L_mc_bm_nme_%=:\n\t"
        "add	sp, sp, #8\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [out] "+r" (out), [s] "+r" (s), [t] "+r" (t),
          [scratch] "+r" (scratch)
        :
#else
        :
        : [out] "r" (out), [s] "r" (s), [t] "r" (t), [scratch] "r" (scratch)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "lr", "r4", "r5", "r6", "r7", "r8", "r9", "r10",
            "r11", "r12"
    );
}

WOLFSSL_LOCAL void wc_mceliece_synd_unpack_neon(word16* s, word64* synd,
    int count);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_synd_unpack_neon(word16* s_p,
    word64* synd_p, int count_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_synd_unpack_neon(word16* s, word64* synd,
    int count)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word16* s __asm__ ("r0") = (word16*)s_p;
    register word64* synd __asm__ ("r1") = (word64*)synd_p;
    register int count __asm__ ("r2") = (int)count_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    register word16* L_mc_bs_powers_neon_c __asm__ ("r3") =
        (word16*)&L_mc_bs_powers_neon;
    __asm__ __volatile__ (
        "vld1.8	{d0-d1}, [%[L_mc_bs_powers_neon]]\n\t"
        "vmov.i16	q1, #1\n\t"
        "lsr	r5, %[count], #3\n\t"
        "mov	r12, #0\n\t"
        "\n"
    "L_mc_sunp_%=:\n\t"
        "cmp	r12, r5\n\t"
        "bge	L_mc_sunpe_%=\n\t"
        "veor	q4, q4, q4\n\t"
        "add	r4, %[synd], #0\n\t"
        "add	r4, r4, r12\n\t"
        "ldrb	lr, [r4]\n\t"
        "vdup.16	q2, lr\n\t"
        "vtst.16	q3, q2, q0\n\t"
        "vand	q3, q3, q1\n\t"
        "vorr	q4, q4, q3\n\t"
        "add	r4, %[synd], #32\n\t"
        "add	r4, r4, r12\n\t"
        "ldrb	lr, [r4]\n\t"
        "vdup.16	q2, lr\n\t"
        "vtst.16	q3, q2, q0\n\t"
        "vand	q3, q3, q1\n\t"
        "vshl.i16	q3, q3, #1\n\t"
        "vorr	q4, q4, q3\n\t"
        "add	r4, %[synd], #0x40\n\t"
        "add	r4, r4, r12\n\t"
        "ldrb	lr, [r4]\n\t"
        "vdup.16	q2, lr\n\t"
        "vtst.16	q3, q2, q0\n\t"
        "vand	q3, q3, q1\n\t"
        "vshl.i16	q3, q3, #2\n\t"
        "vorr	q4, q4, q3\n\t"
        "add	r4, %[synd], #0x60\n\t"
        "add	r4, r4, r12\n\t"
        "ldrb	lr, [r4]\n\t"
        "vdup.16	q2, lr\n\t"
        "vtst.16	q3, q2, q0\n\t"
        "vand	q3, q3, q1\n\t"
        "vshl.i16	q3, q3, #3\n\t"
        "vorr	q4, q4, q3\n\t"
        "add	r4, %[synd], #0x80\n\t"
        "add	r4, r4, r12\n\t"
        "ldrb	lr, [r4]\n\t"
        "vdup.16	q2, lr\n\t"
        "vtst.16	q3, q2, q0\n\t"
        "vand	q3, q3, q1\n\t"
        "vshl.i16	q3, q3, #4\n\t"
        "vorr	q4, q4, q3\n\t"
        "add	r4, %[synd], #0xa0\n\t"
        "add	r4, r4, r12\n\t"
        "ldrb	lr, [r4]\n\t"
        "vdup.16	q2, lr\n\t"
        "vtst.16	q3, q2, q0\n\t"
        "vand	q3, q3, q1\n\t"
        "vshl.i16	q3, q3, #5\n\t"
        "vorr	q4, q4, q3\n\t"
        "add	r4, %[synd], #0xc0\n\t"
        "add	r4, r4, r12\n\t"
        "ldrb	lr, [r4]\n\t"
        "vdup.16	q2, lr\n\t"
        "vtst.16	q3, q2, q0\n\t"
        "vand	q3, q3, q1\n\t"
        "vshl.i16	q3, q3, #6\n\t"
        "vorr	q4, q4, q3\n\t"
        "add	r4, %[synd], #0xe0\n\t"
        "add	r4, r4, r12\n\t"
        "ldrb	lr, [r4]\n\t"
        "vdup.16	q2, lr\n\t"
        "vtst.16	q3, q2, q0\n\t"
        "vand	q3, q3, q1\n\t"
        "vshl.i16	q3, q3, #7\n\t"
        "vorr	q4, q4, q3\n\t"
        "add	r4, %[synd], #0x100\n\t"
        "add	r4, r4, r12\n\t"
        "ldrb	lr, [r4]\n\t"
        "vdup.16	q2, lr\n\t"
        "vtst.16	q3, q2, q0\n\t"
        "vand	q3, q3, q1\n\t"
        "vshl.i16	q3, q3, #8\n\t"
        "vorr	q4, q4, q3\n\t"
        "add	r4, %[synd], #0x120\n\t"
        "add	r4, r4, r12\n\t"
        "ldrb	lr, [r4]\n\t"
        "vdup.16	q2, lr\n\t"
        "vtst.16	q3, q2, q0\n\t"
        "vand	q3, q3, q1\n\t"
        "vshl.i16	q3, q3, #9\n\t"
        "vorr	q4, q4, q3\n\t"
        "add	r4, %[synd], #0x140\n\t"
        "add	r4, r4, r12\n\t"
        "ldrb	lr, [r4]\n\t"
        "vdup.16	q2, lr\n\t"
        "vtst.16	q3, q2, q0\n\t"
        "vand	q3, q3, q1\n\t"
        "vshl.i16	q3, q3, #10\n\t"
        "vorr	q4, q4, q3\n\t"
        "add	r4, %[synd], #0x160\n\t"
        "add	r4, r4, r12\n\t"
        "ldrb	lr, [r4]\n\t"
        "vdup.16	q2, lr\n\t"
        "vtst.16	q3, q2, q0\n\t"
        "vand	q3, q3, q1\n\t"
        "vshl.i16	q3, q3, #11\n\t"
        "vorr	q4, q4, q3\n\t"
        "add	r4, %[synd], #0x180\n\t"
        "add	r4, r4, r12\n\t"
        "ldrb	lr, [r4]\n\t"
        "vdup.16	q2, lr\n\t"
        "vtst.16	q3, q2, q0\n\t"
        "vand	q3, q3, q1\n\t"
        "vshl.i16	q3, q3, #12\n\t"
        "vorr	q4, q4, q3\n\t"
        "lsl	r4, r12, #4\n\t"
        "add	r4, %[s], r4\n\t"
        "vst1.8	{d8-d9}, [r4]\n\t"
        "add	r12, r12, #1\n\t"
        "b	L_mc_sunp_%=\n\t"
        "\n"
    "L_mc_sunpe_%=:\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [s] "+r" (s), [synd] "+r" (synd), [count] "+r" (count),
          [L_mc_bs_powers_neon] "+r" (L_mc_bs_powers_neon_c)
        :
#else
        :
        : [s] "r" (s), [synd] "r" (synd), [count] "r" (count),
          [L_mc_bs_powers_neon] "r" (L_mc_bs_powers_neon_c)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r12", "lr", "r4", "r5", "q0", "q1", "q2", "q3", "q4"
    );
}

WOLFSSL_LOCAL void wc_mceliece_syndrome_neon(word64* synd,
    const byte* fieldmask, word64* einvbs, word64* scaled, word64* scratch);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_syndrome_neon(word64* synd_p,
    const byte* fieldmask_p, word64* einvbs_p, word64* scaled_p,
    word64* scratch_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_syndrome_neon(word64* synd,
    const byte* fieldmask, word64* einvbs, word64* scaled, word64* scratch)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word64* synd __asm__ ("r0") = (word64*)synd_p;
    register const byte* fieldmask __asm__ ("r1") = (const byte*)fieldmask_p;
    register word64* einvbs __asm__ ("r2") = (word64*)einvbs_p;
    register word64* scaled __asm__ ("r3") = (word64*)scaled_p;
    register word64* scratch __asm__ ("r12") = (word64*)scratch_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "push	{%[scratch]}\n\t"
        "sub	sp, sp, #4\n\t"
        "mov	r4, %[synd]\n\t"
        "mov	r5, %[fieldmask]\n\t"
        "mov	r6, %[einvbs]\n\t"
        "mov	r7, %[scaled]\n\t"
        "ldr	r8, [sp, #4]\n\t"
        "mov	%[synd], r7\n\t"
        "mov	%[fieldmask], r6\n\t"
        "mov	%[einvbs], r5\n\t"
        "bl	wc_mceliece_aff_synd_mask_neon\n\t"
        "mov	%[synd], r4\n\t"
        "mov	%[fieldmask], r7\n\t"
        "mov	%[einvbs], r8\n\t"
        "bl	wc_mceliece_aff_butterflies_tr_neon\n\t"
        "mov	%[synd], r4\n\t"
        "bl	wc_mceliece_radix_conv_tr_neon\n\t"
        "add	sp, sp, #4\n\t"
        "pop	{%[scratch]}\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [synd] "+r" (synd), [fieldmask] "+r" (fieldmask),
          [einvbs] "+r" (einvbs), [scaled] "+r" (scaled),
          [scratch] "+r" (scratch)
        :
#else
        :
        : [synd] "r" (synd), [fieldmask] "r" (fieldmask), [einvbs] "r" (einvbs),
          [scaled] "r" (scaled), [scratch] "r" (scratch)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "lr", "r4", "r5", "r6", "r7", "r8"
    );
}

WOLFSSL_LOCAL void wc_mceliece_encap_scatter_neon(byte* e, const word16* ind,
    int t, int nwords);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_encap_scatter_neon(byte* e_p,
    const word16* ind_p, int t_p, int nwords_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_encap_scatter_neon(byte* e,
    const word16* ind, int t, int nwords)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register byte* e __asm__ ("r0") = (byte*)e_p;
    register const word16* ind __asm__ ("r1") = (const word16*)ind_p;
    register int t __asm__ ("r2") = (int)t_p;
    register int nwords __asm__ ("r3") = (int)nwords_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "mov	r5, #0\n\t"
        "mov	r6, #1\n\t"
        "vmov	d14, r6, r5\n\t"
        "vmov	d15, d14\n\t"
        "mov	r6, #63\n\t"
        "vmov	d16, r6, r5\n\t"
        "vmov	d17, d16\n\t"
        "mov	r12, #0\n\t"
        "\n"
    "L_mc_sc_w_%=:\n\t"
        "cmp	r12, %[nwords]\n\t"
        "bge	L_mc_sc_end_%=\n\t"
        "veor	q0, q0, q0\n\t"
        "vmov	d18, r12, r5\n\t"
        "vmov	d19, d18\n\t"
        "mov	lr, #0\n\t"
        "mov	r4, %[ind]\n\t"
        "\n"
    "L_mc_sc_j2_%=:\n\t"
        "add	r6, lr, #2\n\t"
        "cmp	r6, %[t]\n\t"
        "bgt	L_mc_sc_jtail_%=\n\t"
        "ldr	r6, [r4]\n\t"
        "add	r4, r4, #4\n\t"
        "vmov	d2, r6, r5\n\t"
        "vmovl.u16	q2, d2\n\t"
        "vmovl.u32	q1, d4\n\t"
        "vand	q3, q1, q8\n\t"
        "vshr.u64	q4, q1, #6\n\t"
        "vshl.u64	q5, q7, q3\n\t"
        "vceq.i32	q6, q4, q9\n\t"
        "vrev64.32	q10, q6\n\t"
        "vand	q6, q6, q10\n\t"
        "vand	q5, q5, q6\n\t"
        "vorr	q0, q0, q5\n\t"
        "add	lr, lr, #2\n\t"
        "b	L_mc_sc_j2_%=\n\t"
        "\n"
    "L_mc_sc_jtail_%=:\n\t"
        "vorr	d0, d0, d1\n\t"
        "cmp	lr, %[t]\n\t"
        "bge	L_mc_sc_store_%=\n\t"
        "\n"
    "L_mc_sc_tail1_%=:\n\t"
        "ldrh	r6, [r4]\n\t"
        "add	r4, r4, #2\n\t"
        "vmov	d2, r6, r5\n\t"
        "vand	q3, q1, q8\n\t"
        "vshr.u64	q4, q1, #6\n\t"
        "vshl.u64	q5, q7, q3\n\t"
        "vceq.i32	q6, q4, q9\n\t"
        "vrev64.32	q10, q6\n\t"
        "vand	q6, q6, q10\n\t"
        "vand	q5, q5, q6\n\t"
        "vorr	d0, d0, d10\n\t"
        "add	lr, lr, #1\n\t"
        "cmp	lr, %[t]\n\t"
        "blt	L_mc_sc_tail1_%=\n\t"
        "\n"
    "L_mc_sc_store_%=:\n\t"
        "lsl	r6, r12, #3\n\t"
        "add	r6, %[e], r6\n\t"
        "vst1.8	{d0}, [r6]\n\t"
        "add	r12, r12, #1\n\t"
        "b	L_mc_sc_w_%=\n\t"
        "\n"
    "L_mc_sc_end_%=:\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [e] "+r" (e), [ind] "+r" (ind), [t] "+r" (t), [nwords] "+r" (nwords)
        :
#else
        :
        : [e] "r" (e), [ind] "r" (ind), [t] "r" (t), [nwords] "r" (nwords)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r12", "lr", "r4", "r5", "r6", "r7", "q0", "q1", "q2",
            "q3", "q4", "q5", "q6", "q7", "q8", "q9", "q10"
    );
}

WOLFSSL_LOCAL void wc_mceliece_encap_syndrome_neon(const byte* pk,
    const byte* e, byte* c0, byte* row, int mt, int rowBytes);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_encap_syndrome_neon(const byte* pk_p,
    const byte* e_p, byte* c0_p, byte* row_p, int mt_p, int rowBytes_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_encap_syndrome_neon(const byte* pk,
    const byte* e, byte* c0, byte* row, int mt, int rowBytes)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register const byte* pk __asm__ ("r0") = (const byte*)pk_p;
    register const byte* e __asm__ ("r1") = (const byte*)e_p;
    register byte* c0 __asm__ ("r2") = (byte*)c0_p;
    register byte* row __asm__ ("r3") = (byte*)row_p;
    register int mt __asm__ ("r12") = (int)mt_p;
    register int rowBytes __asm__ ("lr") = (int)rowBytes_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "push	{%[mt], %[rowBytes]}\n\t"
        "sub	sp, sp, #16\n\t"
        "ldr	r7, [sp, #16]\n\t"
        "ldr	r8, [sp, #20]\n\t"
        "str	r8, [sp, #4]\n\t"
        "and	r9, r7, #7\n\t"
        "str	r9, [sp, #8]\n\t"
        "lsr	r8, r7, #3\n\t"
        "str	r8, [sp]\n\t"
        "ldr	r9, [sp, #8]\n\t"
        "cmp	r9, #0\n\t"
        "beq	L_mc_syn_notail_%=\n\t"
        "str	%[row], [sp, #12]\n\t"
        "ldr	r8, [sp]\n\t"
        "add	r12, %[e], r8\n\t"
        "mov	r6, #0\n\t"
        "ldr	r10, [sp, #8]\n\t"
        "ldr	r9, [sp, #4]\n\t"
        "sub	r7, r9, #1\n\t"
        "\n"
    "L_mc_syn_bld_%=:\n\t"
        "cmp	r6, r9\n\t"
        "bge	L_mc_syn_main_%=\n\t"
        "cmp	r6, r7\n\t"
        "bge	L_mc_syn_last_%=\n\t"
        "add	r11, r12, r6\n\t"
        "ldrh	r11, [r11]\n\t"
        "lsr	r11, r11, r10\n\t"
        "b	L_mc_syn_stv_%=\n\t"
        "\n"
    "L_mc_syn_last_%=:\n\t"
        "add	r11, r12, r6\n\t"
        "ldrb	r11, [r11]\n\t"
        "lsr	r11, r11, r10\n\t"
        "\n"
    "L_mc_syn_stv_%=:\n\t"
        "add	r4, %[row], r6\n\t"
        "strb	r11, [r4]\n\t"
        "add	r6, r6, #1\n\t"
        "b	L_mc_syn_bld_%=\n\t"
        "\n"
    "L_mc_syn_notail_%=:\n\t"
        "ldr	r8, [sp]\n\t"
        "add	r8, %[e], r8\n\t"
        "str	r8, [sp, #12]\n\t"
        "\n"
    "L_mc_syn_main_%=:\n\t"
        "mov	r6, #0\n\t"
        "mov	r12, %[pk]\n\t"
        "\n"
    "L_mc_syn_mainl_%=:\n\t"
        "ldr	r8, [sp]\n\t"
        "cmp	r6, r8\n\t"
        "bge	L_mc_syn_tail_%=\n\t"
        "mov	r4, #0\n\t"
        "mov	r5, #0\n\t"
        "\n"
    "L_mc_syn_rowl_%=:\n\t"
        "ldr	lr, [sp, #12]\n\t"
        "ldr	r7, [sp, #4]\n\t"
        "veor	q0, q0, q0\n\t"
        "mov	r10, #0\n\t"
        "cmp	r7, #16\n\t"
        "blt	L_mc_syn_aptl_m_%=\n\t"
        "\n"
    "L_mc_syn_ap16_m_%=:\n\t"
        "vld1.8	{d2-d3}, [r12]\n\t"
        "add	r12, r12, #16\n\t"
        "vld1.8	{d4-d5}, [lr]\n\t"
        "add	lr, lr, #16\n\t"
        "vand	q1, q1, q2\n\t"
        "veor	q0, q0, q1\n\t"
        "sub	r7, r7, #16\n\t"
        "cmp	r7, #16\n\t"
        "bge	L_mc_syn_ap16_m_%=\n\t"
        "\n"
    "L_mc_syn_aptl_m_%=:\n\t"
        "cmp	r7, #0\n\t"
        "beq	L_mc_syn_aptd_m_%=\n\t"
        "\n"
    "L_mc_syn_aptll_m_%=:\n\t"
        "ldrb	r8, [r12]\n\t"
        "add	r12, r12, #1\n\t"
        "ldrb	r9, [lr]\n\t"
        "add	lr, lr, #1\n\t"
        "and	r8, r8, r9\n\t"
        "eor	r10, r10, r8\n\t"
        "subs	r7, r7, #1\n\t"
        "bne	L_mc_syn_aptll_m_%=\n\t"
        "\n"
    "L_mc_syn_aptd_m_%=:\n\t"
        "vcnt.8	q0, q0\n\t"
        "vpaddl.u8	q3, q0\n\t"
        "vpaddl.u16	q3, q3\n\t"
        "vpaddl.u32	q3, q3\n\t"
        "vadd.i64	d6, d6, d7\n\t"
        "vmov	r11, r8, d6\n\t"
        "and	r11, r11, #1\n\t"
        "lsr	r9, r10, #4\n\t"
        "eor	r10, r10, r9\n\t"
        "lsr	r9, r10, #2\n\t"
        "eor	r10, r10, r9\n\t"
        "lsr	r9, r10, #1\n\t"
        "eor	r10, r10, r9\n\t"
        "and	r10, r10, #1\n\t"
        "eor	r11, r11, r10\n\t"
        "lsl	r11, r11, r5\n\t"
        "orr	r4, r4, r11\n\t"
        "add	r5, r5, #1\n\t"
        "cmp	r5, #8\n\t"
        "blt	L_mc_syn_rowl_%=\n\t"
        "add	r8, %[e], r6\n\t"
        "ldrb	r8, [r8]\n\t"
        "eor	r4, r4, r8\n\t"
        "add	r8, %[c0], r6\n\t"
        "strb	r4, [r8]\n\t"
        "add	r6, r6, #1\n\t"
        "b	L_mc_syn_mainl_%=\n\t"
        "\n"
    "L_mc_syn_tail_%=:\n\t"
        "ldr	r8, [sp, #8]\n\t"
        "cmp	r8, #0\n\t"
        "beq	L_mc_syn_end_%=\n\t"
        "mov	r4, #0\n\t"
        "mov	r5, #0\n\t"
        "ldr	r8, [sp]\n\t"
        "add	r6, %[e], r8\n\t"
        "ldrb	r6, [r6]\n\t"
        "\n"
    "L_mc_syn_taill_%=:\n\t"
        "ldr	lr, [sp, #12]\n\t"
        "ldr	r7, [sp, #4]\n\t"
        "veor	q0, q0, q0\n\t"
        "mov	r10, #0\n\t"
        "cmp	r7, #16\n\t"
        "blt	L_mc_syn_aptl_t_%=\n\t"
        "\n"
    "L_mc_syn_ap16_t_%=:\n\t"
        "vld1.8	{d2-d3}, [r12]\n\t"
        "add	r12, r12, #16\n\t"
        "vld1.8	{d4-d5}, [lr]\n\t"
        "add	lr, lr, #16\n\t"
        "vand	q1, q1, q2\n\t"
        "veor	q0, q0, q1\n\t"
        "sub	r7, r7, #16\n\t"
        "cmp	r7, #16\n\t"
        "bge	L_mc_syn_ap16_t_%=\n\t"
        "\n"
    "L_mc_syn_aptl_t_%=:\n\t"
        "cmp	r7, #0\n\t"
        "beq	L_mc_syn_aptd_t_%=\n\t"
        "\n"
    "L_mc_syn_aptll_t_%=:\n\t"
        "ldrb	r8, [r12]\n\t"
        "add	r12, r12, #1\n\t"
        "ldrb	r9, [lr]\n\t"
        "add	lr, lr, #1\n\t"
        "and	r8, r8, r9\n\t"
        "eor	r10, r10, r8\n\t"
        "subs	r7, r7, #1\n\t"
        "bne	L_mc_syn_aptll_t_%=\n\t"
        "\n"
    "L_mc_syn_aptd_t_%=:\n\t"
        "vcnt.8	q0, q0\n\t"
        "vpaddl.u8	q3, q0\n\t"
        "vpaddl.u16	q3, q3\n\t"
        "vpaddl.u32	q3, q3\n\t"
        "vadd.i64	d6, d6, d7\n\t"
        "vmov	r11, r8, d6\n\t"
        "and	r11, r11, #1\n\t"
        "lsr	r9, r10, #4\n\t"
        "eor	r10, r10, r9\n\t"
        "lsr	r9, r10, #2\n\t"
        "eor	r10, r10, r9\n\t"
        "lsr	r9, r10, #1\n\t"
        "eor	r10, r10, r9\n\t"
        "and	r10, r10, #1\n\t"
        "eor	r11, r11, r10\n\t"
        "lsr	r8, r6, r5\n\t"
        "and	r8, r8, #1\n\t"
        "eor	r11, r11, r8\n\t"
        "lsl	r11, r11, r5\n\t"
        "orr	r4, r4, r11\n\t"
        "add	r5, r5, #1\n\t"
        "ldr	r8, [sp, #8]\n\t"
        "cmp	r5, r8\n\t"
        "blt	L_mc_syn_taill_%=\n\t"
        "ldr	r8, [sp]\n\t"
        "add	r8, %[c0], r8\n\t"
        "strb	r4, [r8]\n\t"
        "\n"
    "L_mc_syn_end_%=:\n\t"
        "add	sp, sp, #16\n\t"
        "pop	{%[mt], %[rowBytes]}\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [pk] "+r" (pk), [e] "+r" (e), [c0] "+r" (c0), [row] "+r" (row),
          [mt] "+r" (mt), [rowBytes] "+r" (rowBytes)
        :
#else
        :
        : [pk] "r" (pk), [e] "r" (e), [c0] "r" (c0), [row] "r" (row),
          [mt] "r" (mt), [rowBytes] "r" (rowBytes)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11",
            "q0", "q1", "q2", "q3"
    );
}

WOLFSSL_LOCAL int wc_mceliece_encap_fixedweight_neon(const byte* rand,
    word16* ind, int randLen, int n, int t, int tau);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER int wc_mceliece_encap_fixedweight_neon(const byte* rand_p,
    word16* ind_p, int randLen_p, int n_p, int t_p, int tau_p)
#else
WC_OMIT_FRAME_POINTER int wc_mceliece_encap_fixedweight_neon(const byte* rand,
    word16* ind, int randLen, int n, int t, int tau)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register const byte* rand __asm__ ("r0") = (const byte*)rand_p;
    register word16* ind __asm__ ("r1") = (word16*)ind_p;
    register int randLen __asm__ ("r2") = (int)randLen_p;
    register int n __asm__ ("r3") = (int)n_p;
    register int t __asm__ ("r12") = (int)t_p;
    register int tau __asm__ ("lr") = (int)tau_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "push	{%[t], %[tau]}\n\t"
        "sub	sp, sp, #8\n\t"
        "ldr	r8, [sp, #8]\n\t"
        "str	r8, [sp]\n\t"
        "ldr	r8, [sp, #12]\n\t"
        "str	r8, [sp, #4]\n\t"
        "mov	r12, #0\n\t"
        "\n"
    "L_mc_fw_retry_%=:\n\t"
        "ldr	r8, [sp, #4]\n\t"
        "lsl	r8, r8, #1\n\t"
        "add	r9, r12, r8\n\t"
        "cmp	r9, %[randLen]\n\t"
        "bgt	L_mc_fw_depl_%=\n\t"
        "add	r5, %[rand], r12\n\t"
        "mov	lr, #0\n\t"
        "mov	r4, #0\n\t"
        "ldr	r10, [sp, #4]\n\t"
        "\n"
    "L_mc_fw_filter_%=:\n\t"
        "cmp	r4, r10\n\t"
        "bge	L_mc_fw_filterd_%=\n\t"
        "ldr	r9, [sp]\n\t"
        "cmp	lr, r9\n\t"
        "bge	L_mc_fw_filterd_%=\n\t"
        "lsl	r8, r4, #1\n\t"
        "add	r8, r5, r8\n\t"
        "ldrh	r8, [r8]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r9, #0xff\n\t"
        "orr	r9, r9, #0x1f00\n\t"
#else
        "mov	r9, #0x1fff\n\t"
#endif
        "and	r8, r8, r9\n\t"
        "lsl	r9, lr, #1\n\t"
        "add	r9, %[ind], r9\n\t"
        "strh	r8, [r9]\n\t"
        "sub	r9, r8, %[n]\n\t"
        "lsr	r9, r9, #31\n\t"
        "add	lr, lr, r9\n\t"
        "add	r4, r4, #1\n\t"
        "b	L_mc_fw_filter_%=\n\t"
        "\n"
    "L_mc_fw_filterd_%=:\n\t"
        "ldr	r8, [sp, #4]\n\t"
        "lsl	r8, r8, #1\n\t"
        "add	r12, r12, r8\n\t"
        "ldr	r9, [sp]\n\t"
        "cmp	lr, r9\n\t"
        "blt	L_mc_fw_retry_%=\n\t"
        "mov	lr, #0\n\t"
        "mov	r4, #1\n\t"
        "\n"
    "L_mc_fw_dupi_%=:\n\t"
        "ldr	r8, [sp]\n\t"
        "cmp	r4, r8\n\t"
        "bge	L_mc_fw_dupd_%=\n\t"
        "lsl	r8, r4, #1\n\t"
        "add	r8, %[ind], r8\n\t"
        "ldrh	r7, [r8]\n\t"
        "vdup.16	q0, r7\n\t"
        "veor	q1, q1, q1\n\t"
        "mov	r6, #0\n\t"
        "\n"
    "L_mc_fw_dupj8_%=:\n\t"
        "add	r8, r6, #8\n\t"
        "cmp	r8, r4\n\t"
        "bgt	L_mc_fw_duprem_%=\n\t"
        "lsl	r8, r6, #1\n\t"
        "add	r8, %[ind], r8\n\t"
        "vld1.8	{d4-d5}, [r8]\n\t"
        "vceq.i16	q2, q2, q0\n\t"
        "vorr	q1, q1, q2\n\t"
        "add	r6, r6, #8\n\t"
        "b	L_mc_fw_dupj8_%=\n\t"
        "\n"
    "L_mc_fw_duprem_%=:\n\t"
        "vpmax.u16	d2, d2, d3\n\t"
        "vpmax.u16	d2, d2, d2\n\t"
        "vpmax.u16	d2, d2, d2\n\t"
        "vmov.u16	r8, d2[0]\n\t"
        "orr	lr, lr, r8\n\t"
        "\n"
    "L_mc_fw_duprem1_%=:\n\t"
        "cmp	r6, r4\n\t"
        "bge	L_mc_fw_dupie_%=\n\t"
        "lsl	r8, r6, #1\n\t"
        "add	r8, %[ind], r8\n\t"
        "ldrh	r8, [r8]\n\t"
        "sub	r9, r8, r7\n\t"
        "rsb	r8, r9, #0\n\t"
        "orr	r9, r9, r8\n\t"
        "lsr	r9, r9, #31\n\t"
        "eor	r9, r9, #1\n\t"
        "add	lr, lr, r9\n\t"
        "add	r6, r6, #1\n\t"
        "b	L_mc_fw_duprem1_%=\n\t"
        "\n"
    "L_mc_fw_dupie_%=:\n\t"
        "add	r4, r4, #1\n\t"
        "b	L_mc_fw_dupi_%=\n\t"
        "\n"
    "L_mc_fw_dupd_%=:\n\t"
        "cmp	lr, #0\n\t"
        "bne	L_mc_fw_retry_%=\n\t"
        "mov	%[rand], #0\n\t"
        "b	L_mc_fw_ret_%=\n\t"
        "\n"
    "L_mc_fw_depl_%=:\n\t"
        "mov	%[rand], #2\n\t"
        "\n"
    "L_mc_fw_ret_%=:\n\t"
        "add	sp, sp, #8\n\t"
        "pop	{%[t], %[tau]}\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [rand] "+r" (rand), [ind] "+r" (ind), [randLen] "+r" (randLen),
          [n] "+r" (n), [t] "+r" (t), [tau] "+r" (tau)
        :
#else
        :
        : [rand] "r" (rand), [ind] "r" (ind), [randLen] "r" (randLen),
          [n] "r" (n), [t] "r" (t), [tau] "r" (tau)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "q0", "q1",
            "q2"
    );
    return (word32)(size_t)rand;
}

WOLFSSL_LOCAL void wc_mceliece_layer_ex_neon(word64* data, const word64* bits,
    int lgs);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_layer_ex_neon(word64* data_p,
    const word64* bits_p, int lgs_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_layer_ex_neon(word64* data,
    const word64* bits, int lgs)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word64* data __asm__ ("r0") = (word64*)data_p;
    register const word64* bits __asm__ ("r1") = (const word64*)bits_p;
    register int lgs __asm__ ("r2") = (int)lgs_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "mov	r7, #1\n\t"
        "lsl	r3, r7, %[lgs]\n\t"
        "cmp	r3, #1\n\t"
        "beq	L_mc_lex_sc_%=\n\t"
        "lsl	r12, r3, #3\n\t"
        "mov	lr, #0\n\t"
        "\n"
    "L_mc_lex_i_%=:\n\t"
        "cmp	lr, #0x80\n\t"
        "bge	L_mc_lex_done_%=\n\t"
        "lsl	r7, lr, #3\n\t"
        "add	r5, %[data], r7\n\t"
        "add	r6, r5, r12\n\t"
        "mov	r4, #0\n\t"
        "\n"
    "L_mc_lex_k_%=:\n\t"
        "vld1.8	{d0-d1}, [r5]\n\t"
        "vld1.8	{d2-d3}, [r6]\n\t"
        "vld1.8	{d6-d7}, [%[bits]]\n\t"
        "add	%[bits], %[bits], #16\n\t"
        "veor	q2, q0, q1\n\t"
        "vand	q2, q2, q3\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q2\n\t"
        "vst1.8	{d0-d1}, [r5]\n\t"
        "vst1.8	{d2-d3}, [r6]\n\t"
        "add	r5, r5, #16\n\t"
        "add	r6, r6, #16\n\t"
        "add	r4, r4, #2\n\t"
        "cmp	r4, r3\n\t"
        "blt	L_mc_lex_k_%=\n\t"
        "\n"
    "L_mc_lex_ni_%=:\n\t"
        "add	r7, r3, r3\n\t"
        "add	lr, lr, r7\n\t"
        "b	L_mc_lex_i_%=\n\t"
        "\n"
    "L_mc_lex_sc_%=:\n\t"
        "mov	r5, %[data]\n\t"
        "mov	lr, #0\n\t"
        "\n"
    "L_mc_lex_sl_%=:\n\t"
        "add	r8, r5, #8\n\t"
        "vld1.8	{d0}, [r5]\n\t"
        "vld1.8	{d2}, [r8]\n\t"
        "vld1.8	{d6}, [%[bits]]\n\t"
        "add	%[bits], %[bits], #8\n\t"
        "veor	d4, d0, d2\n\t"
        "vand	d4, d4, d6\n\t"
        "veor	d0, d0, d4\n\t"
        "veor	d2, d2, d4\n\t"
        "vst1.8	{d0}, [r5]\n\t"
        "vst1.8	{d2}, [r8]\n\t"
        "add	r5, r5, #16\n\t"
        "add	lr, lr, #2\n\t"
        "cmp	lr, #0x80\n\t"
        "blt	L_mc_lex_sl_%=\n\t"
        "\n"
    "L_mc_lex_done_%=:\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [data] "+r" (data), [bits] "+r" (bits), [lgs] "+r" (lgs)
        :
#else
        :
        : [data] "r" (data), [bits] "r" (bits), [lgs] "r" (lgs)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r3", "r12", "lr", "r4", "r5", "r6", "r7", "r8", "q0",
            "q1", "q2", "q3"
    );
}

WOLFSSL_LOCAL void wc_mceliece_layer_in_neon(word64* data, const word64* bits,
    int lgs);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_layer_in_neon(word64* data_p,
    const word64* bits_p, int lgs_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_layer_in_neon(word64* data,
    const word64* bits, int lgs)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word64* data __asm__ ("r0") = (word64*)data_p;
    register const word64* bits __asm__ ("r1") = (const word64*)bits_p;
    register int lgs __asm__ ("r2") = (int)lgs_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "mov	r9, #1\n\t"
        "lsl	r3, r9, %[lgs]\n\t"
        "cmp	r3, #1\n\t"
        "beq	L_mc_lin_sc_%=\n\t"
        "lsl	r12, r3, #3\n\t"
        "mov	lr, #0\n\t"
        "\n"
    "L_mc_lin_i_%=:\n\t"
        "cmp	lr, #0x40\n\t"
        "bge	L_mc_lin_done_%=\n\t"
        "lsl	r10, lr, #3\n\t"
        "add	r5, %[data], r10\n\t"
        "add	r6, r5, #0x200\n\t"
        "add	r7, r5, r12\n\t"
        "add	r8, r6, r12\n\t"
        "mov	r4, lr\n\t"
        "add	r9, lr, r3\n\t"
        "\n"
    "L_mc_lin_j_%=:\n\t"
        "vld1.8	{d0-d1}, [r5]\n\t"
        "vld1.8	{d2-d3}, [r7]\n\t"
        "vld1.8	{d4-d5}, [r6]\n\t"
        "vld1.8	{d6-d7}, [r8]\n\t"
        "vld1.8	{d10-d13}, [%[bits]]\n\t"
        "add	%[bits], %[bits], #32\n\t"
        "vmov	d8, d11\n\t"
        "vmov	d11, d12\n\t"
        "vmov	d12, d8\n\t"
        "veor	q4, q0, q1\n\t"
        "vand	q4, q4, q5\n\t"
        "veor	q0, q0, q4\n\t"
        "veor	q1, q1, q4\n\t"
        "veor	q4, q2, q3\n\t"
        "vand	q4, q4, q6\n\t"
        "veor	q2, q2, q4\n\t"
        "veor	q3, q3, q4\n\t"
        "vst1.8	{d0-d1}, [r5]\n\t"
        "vst1.8	{d2-d3}, [r7]\n\t"
        "vst1.8	{d4-d5}, [r6]\n\t"
        "vst1.8	{d6-d7}, [r8]\n\t"
        "add	r5, r5, #16\n\t"
        "add	r7, r7, #16\n\t"
        "add	r6, r6, #16\n\t"
        "add	r8, r8, #16\n\t"
        "add	r4, r4, #2\n\t"
        "cmp	r4, r9\n\t"
        "blt	L_mc_lin_j_%=\n\t"
        "\n"
    "L_mc_lin_ni_%=:\n\t"
        "add	r10, r3, r3\n\t"
        "add	lr, lr, r10\n\t"
        "b	L_mc_lin_i_%=\n\t"
        "\n"
    "L_mc_lin_sc_%=:\n\t"
        "mov	r5, %[data]\n\t"
        "add	r6, r5, #0x200\n\t"
        "mov	lr, #0\n\t"
        "\n"
    "L_mc_lin_sl_%=:\n\t"
        "add	r9, r5, #8\n\t"
        "vld1.8	{d0}, [r5]\n\t"
        "vld1.8	{d2}, [r9]\n\t"
        "vld1.8	{d10}, [%[bits]]\n\t"
        "add	%[bits], %[bits], #8\n\t"
        "veor	d8, d0, d2\n\t"
        "vand	d8, d8, d10\n\t"
        "veor	d0, d0, d8\n\t"
        "veor	d2, d2, d8\n\t"
        "vst1.8	{d0}, [r5]\n\t"
        "vst1.8	{d2}, [r9]\n\t"
        "add	r10, r6, #8\n\t"
        "vld1.8	{d4}, [r6]\n\t"
        "vld1.8	{d6}, [r10]\n\t"
        "vld1.8	{d12}, [%[bits]]\n\t"
        "add	%[bits], %[bits], #8\n\t"
        "veor	d8, d4, d6\n\t"
        "vand	d8, d8, d12\n\t"
        "veor	d4, d4, d8\n\t"
        "veor	d6, d6, d8\n\t"
        "vst1.8	{d4}, [r6]\n\t"
        "vst1.8	{d6}, [r10]\n\t"
        "add	r5, r5, #16\n\t"
        "add	r6, r6, #16\n\t"
        "add	lr, lr, #2\n\t"
        "cmp	lr, #0x40\n\t"
        "blt	L_mc_lin_sl_%=\n\t"
        "\n"
    "L_mc_lin_done_%=:\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [data] "+r" (data), [bits] "+r" (bits), [lgs] "+r" (lgs)
        :
#else
        :
        : [data] "r" (data), [bits] "r" (bits), [lgs] "r" (lgs)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r3", "r12", "lr", "r4", "r5", "r6", "r7", "r8", "r9",
            "r10", "q0", "q1", "q2", "q3", "q4", "q5", "q6"
    );
}

WOLFSSL_LOCAL void wc_mceliece_apply_benes_neon(byte* r, const byte* bits,
    int rev, word64* work);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_apply_benes_neon(byte* r_p,
    const byte* bits_p, int rev_p, word64* work_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_apply_benes_neon(byte* r,
    const byte* bits, int rev, word64* work)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register byte* r __asm__ ("r0") = (byte*)r_p;
    register const byte* bits __asm__ ("r1") = (const byte*)bits_p;
    register int rev __asm__ ("r2") = (int)rev_p;
    register word64* work __asm__ ("r3") = (word64*)work_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "mov	r4, %[r]\n\t"
        "mov	r5, %[work]\n\t"
        "mov	r6, %[bits]\n\t"
        "mov	r7, #0\n\t"
        "cmp	%[rev], #0\n\t"
        "beq	L_mc_ab_norev_%=\n\t"
        "add	r6, r6, #0x3000\n\t"
        "mov	r7, #0x400\n\t"
        "neg	r7, r7\n\t"
        "\n"
    "L_mc_ab_norev_%=:\n\t"
        "mov	r9, #0\n\t"
        "\n"
    "L_mc_ab_rl_%=:\n\t"
        "cmp	r9, #0x40\n\t"
        "bge	L_mc_ab_rle_%=\n\t"
        "lsl	r10, r9, #4\n\t"
        "add	r10, r4, r10\n\t"
        "vld1.8	{d0-d1}, [r10]\n\t"
        "lsl	r10, r9, #3\n\t"
        "add	r10, r5, r10\n\t"
        "vst1.8	{d0}, [r10]\n\t"
        "add	r10, r10, #0x200\n\t"
        "vst1.8	{d1}, [r10]\n\t"
        "add	r9, r9, #1\n\t"
        "b	L_mc_ab_rl_%=\n\t"
        "\n"
    "L_mc_ab_rle_%=:\n\t"
        "add	%[r], r5, #0x400\n\t"
        "add	%[bits], r5, #0\n\t"
        "bl	wc_mceliece_transpose_64x64_neon\n\t"
        "add	%[r], r5, #0x600\n\t"
        "add	%[bits], r5, #0x200\n\t"
        "bl	wc_mceliece_transpose_64x64_neon\n\t"
        "mov	r8, #0\n\t"
        "\n"
    "L_mc_ab_x1_%=:\n\t"
        "cmp	r8, #6\n\t"
        "bgt	L_mc_ab_x1e_%=\n\t"
        "mov	r9, #0\n\t"
        "\n"
    "L_mc_bnl_x1_%=:\n\t"
        "cmp	r9, #0x40\n\t"
        "bge	L_mc_bnle_x1_%=\n\t"
        "vld1.8	{d0}, [r6]\n\t"
        "lsl	r10, r9, #3\n\t"
        "add	r10, r5, r10\n\t"
        "add	r10, r10, #0x800\n\t"
        "vst1.8	{d0}, [r10]\n\t"
        "add	r6, r6, #8\n\t"
        "add	r9, r9, #1\n\t"
        "b	L_mc_bnl_x1_%=\n\t"
        "\n"
    "L_mc_bnle_x1_%=:\n\t"
        "add	r6, r6, r7\n\t"
        "add	%[r], r5, #0xa00\n\t"
        "add	%[bits], r5, #0x800\n\t"
        "bl	wc_mceliece_transpose_64x64_neon\n\t"
        "add	%[r], r5, #0x400\n\t"
        "add	%[bits], r5, #0xa00\n\t"
        "mov	%[rev], r8\n\t"
        "bl	wc_mceliece_layer_ex_neon\n\t"
        "add	r8, r8, #1\n\t"
        "b	L_mc_ab_x1_%=\n\t"
        "\n"
    "L_mc_ab_x1e_%=:\n\t"
        "add	%[r], r5, #0\n\t"
        "add	%[bits], r5, #0x400\n\t"
        "bl	wc_mceliece_transpose_64x64_neon\n\t"
        "add	%[r], r5, #0x200\n\t"
        "add	%[bits], r5, #0x600\n\t"
        "bl	wc_mceliece_transpose_64x64_neon\n\t"
        "mov	r8, #0\n\t"
        "\n"
    "L_mc_ab_n1_%=:\n\t"
        "cmp	r8, #5\n\t"
        "bgt	L_mc_ab_n1e_%=\n\t"
        "mov	r9, #0\n\t"
        "\n"
    "L_mc_bnl_n1_%=:\n\t"
        "cmp	r9, #0x40\n\t"
        "bge	L_mc_bnle_n1_%=\n\t"
        "vld1.8	{d0}, [r6]\n\t"
        "lsl	r10, r9, #3\n\t"
        "add	r10, r5, r10\n\t"
        "add	r10, r10, #0x800\n\t"
        "vst1.8	{d0}, [r10]\n\t"
        "add	r6, r6, #8\n\t"
        "add	r9, r9, #1\n\t"
        "b	L_mc_bnl_n1_%=\n\t"
        "\n"
    "L_mc_bnle_n1_%=:\n\t"
        "add	r6, r6, r7\n\t"
        "mov	%[r], r5\n\t"
        "add	%[bits], r5, #0x800\n\t"
        "mov	%[rev], r8\n\t"
        "bl	wc_mceliece_layer_in_neon\n\t"
        "add	r8, r8, #1\n\t"
        "b	L_mc_ab_n1_%=\n\t"
        "\n"
    "L_mc_ab_n1e_%=:\n\t"
        "mov	r8, #4\n\t"
        "\n"
    "L_mc_ab_n2_%=:\n\t"
        "cmp	r8, #0\n\t"
        "blt	L_mc_ab_n2e_%=\n\t"
        "mov	r9, #0\n\t"
        "\n"
    "L_mc_bnl_n2_%=:\n\t"
        "cmp	r9, #0x40\n\t"
        "bge	L_mc_bnle_n2_%=\n\t"
        "vld1.8	{d0}, [r6]\n\t"
        "lsl	r10, r9, #3\n\t"
        "add	r10, r5, r10\n\t"
        "add	r10, r10, #0x800\n\t"
        "vst1.8	{d0}, [r10]\n\t"
        "add	r6, r6, #8\n\t"
        "add	r9, r9, #1\n\t"
        "b	L_mc_bnl_n2_%=\n\t"
        "\n"
    "L_mc_bnle_n2_%=:\n\t"
        "add	r6, r6, r7\n\t"
        "mov	%[r], r5\n\t"
        "add	%[bits], r5, #0x800\n\t"
        "mov	%[rev], r8\n\t"
        "bl	wc_mceliece_layer_in_neon\n\t"
        "sub	r8, r8, #1\n\t"
        "b	L_mc_ab_n2_%=\n\t"
        "\n"
    "L_mc_ab_n2e_%=:\n\t"
        "add	%[r], r5, #0x400\n\t"
        "add	%[bits], r5, #0\n\t"
        "bl	wc_mceliece_transpose_64x64_neon\n\t"
        "add	%[r], r5, #0x600\n\t"
        "add	%[bits], r5, #0x200\n\t"
        "bl	wc_mceliece_transpose_64x64_neon\n\t"
        "mov	r8, #6\n\t"
        "\n"
    "L_mc_ab_x2_%=:\n\t"
        "cmp	r8, #0\n\t"
        "blt	L_mc_ab_x2e_%=\n\t"
        "mov	r9, #0\n\t"
        "\n"
    "L_mc_bnl_x2_%=:\n\t"
        "cmp	r9, #0x40\n\t"
        "bge	L_mc_bnle_x2_%=\n\t"
        "vld1.8	{d0}, [r6]\n\t"
        "lsl	r10, r9, #3\n\t"
        "add	r10, r5, r10\n\t"
        "add	r10, r10, #0x800\n\t"
        "vst1.8	{d0}, [r10]\n\t"
        "add	r6, r6, #8\n\t"
        "add	r9, r9, #1\n\t"
        "b	L_mc_bnl_x2_%=\n\t"
        "\n"
    "L_mc_bnle_x2_%=:\n\t"
        "add	r6, r6, r7\n\t"
        "add	%[r], r5, #0xa00\n\t"
        "add	%[bits], r5, #0x800\n\t"
        "bl	wc_mceliece_transpose_64x64_neon\n\t"
        "add	%[r], r5, #0x400\n\t"
        "add	%[bits], r5, #0xa00\n\t"
        "mov	%[rev], r8\n\t"
        "bl	wc_mceliece_layer_ex_neon\n\t"
        "sub	r8, r8, #1\n\t"
        "b	L_mc_ab_x2_%=\n\t"
        "\n"
    "L_mc_ab_x2e_%=:\n\t"
        "add	%[r], r5, #0\n\t"
        "add	%[bits], r5, #0x400\n\t"
        "bl	wc_mceliece_transpose_64x64_neon\n\t"
        "add	%[r], r5, #0x200\n\t"
        "add	%[bits], r5, #0x600\n\t"
        "bl	wc_mceliece_transpose_64x64_neon\n\t"
        "mov	r9, #0\n\t"
        "\n"
    "L_mc_ab_st_%=:\n\t"
        "cmp	r9, #0x40\n\t"
        "bge	L_mc_ab_ste_%=\n\t"
        "lsl	r10, r9, #3\n\t"
        "add	r10, r5, r10\n\t"
        "vld1.8	{d0}, [r10]\n\t"
        "add	r10, r10, #0x200\n\t"
        "vld1.8	{d1}, [r10]\n\t"
        "lsl	r10, r9, #4\n\t"
        "add	r10, r4, r10\n\t"
        "vst1.8	{d0-d1}, [r10]\n\t"
        "add	r9, r9, #1\n\t"
        "b	L_mc_ab_st_%=\n\t"
        "\n"
    "L_mc_ab_ste_%=:\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [r] "+r" (r), [bits] "+r" (bits), [rev] "+r" (rev),
          [work] "+r" (work)
        :
#else
        :
        : [r] "r" (r), [bits] "r" (bits), [rev] "r" (rev), [work] "r" (work)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "lr", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "q0"
    );
}

WOLFSSL_LOCAL void wc_mceliece_transpose_64x64_neon(word64* out,
    const word64* in);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_transpose_64x64_neon(word64* out_p,
    const word64* in_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_transpose_64x64_neon(word64* out,
    const word64* in)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word64* out __asm__ ("r0") = (word64*)out_p;
    register const word64* in __asm__ ("r1") = (const word64*)in_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "mov	r2, %[out]\n\t"
        "mov	r3, %[in]\n\t"
        "mov	r12, #0x200\n\t"
        "\n"
    "L_mc_tr_copy_%=:\n\t"
        "vld1.8	{d0-d1}, [r3]\n\t"
        "add	r3, r3, #16\n\t"
        "vst1.8	{d0-d1}, [r2]\n\t"
        "add	r2, r2, #16\n\t"
        "subs	r12, r12, #16\n\t"
        "bne	L_mc_tr_copy_%=\n\t"
        "vmov.i64	q6, #0xffffffff\n\t"
        "mov	lr, #0\n\t"
        "\n"
    "L_mc_tr_i5_%=:\n\t"
        "cmp	lr, #0x40\n\t"
        "bge	L_mc_tr_e5_%=\n\t"
        "lsl	r7, lr, #3\n\t"
        "add	r5, %[out], r7\n\t"
        "add	r6, r5, #0x100\n\t"
        "mov	r4, #0\n\t"
        "\n"
    "L_mc_tr_k5_%=:\n\t"
        "vld1.8	{d0-d1}, [r5]\n\t"
        "vld1.8	{d2-d3}, [r6]\n\t"
        "vand	q2, q0, q6\n\t"
        "vand	q3, q1, q6\n\t"
        "vshl.i64	q3, q3, #32\n\t"
        "veor	q2, q2, q3\n\t"
        "vbic	q4, q0, q6\n\t"
        "vshr.u64	q4, q4, #32\n\t"
        "vbic	q5, q1, q6\n\t"
        "veor	q4, q4, q5\n\t"
        "vst1.8	{d4-d5}, [r5]\n\t"
        "vst1.8	{d8-d9}, [r6]\n\t"
        "add	r5, r5, #16\n\t"
        "add	r6, r6, #16\n\t"
        "add	r4, r4, #2\n\t"
        "cmp	r4, #32\n\t"
        "blt	L_mc_tr_k5_%=\n\t"
        "\n"
    "L_mc_tr_ni5_%=:\n\t"
        "add	lr, lr, #0x40\n\t"
        "b	L_mc_tr_i5_%=\n\t"
        "\n"
    "L_mc_tr_e5_%=:\n\t"
        "vmov.i32	q6, #0xffff\n\t"
        "mov	lr, #0\n\t"
        "\n"
    "L_mc_tr_i4_%=:\n\t"
        "cmp	lr, #0x40\n\t"
        "bge	L_mc_tr_e4_%=\n\t"
        "lsl	r7, lr, #3\n\t"
        "add	r5, %[out], r7\n\t"
        "add	r6, r5, #0x80\n\t"
        "mov	r4, #0\n\t"
        "\n"
    "L_mc_tr_k4_%=:\n\t"
        "vld1.8	{d0-d1}, [r5]\n\t"
        "vld1.8	{d2-d3}, [r6]\n\t"
        "vand	q2, q0, q6\n\t"
        "vand	q3, q1, q6\n\t"
        "vshl.i64	q3, q3, #16\n\t"
        "veor	q2, q2, q3\n\t"
        "vbic	q4, q0, q6\n\t"
        "vshr.u64	q4, q4, #16\n\t"
        "vbic	q5, q1, q6\n\t"
        "veor	q4, q4, q5\n\t"
        "vst1.8	{d4-d5}, [r5]\n\t"
        "vst1.8	{d8-d9}, [r6]\n\t"
        "add	r5, r5, #16\n\t"
        "add	r6, r6, #16\n\t"
        "add	r4, r4, #2\n\t"
        "cmp	r4, #16\n\t"
        "blt	L_mc_tr_k4_%=\n\t"
        "\n"
    "L_mc_tr_ni4_%=:\n\t"
        "add	lr, lr, #32\n\t"
        "b	L_mc_tr_i4_%=\n\t"
        "\n"
    "L_mc_tr_e4_%=:\n\t"
        "vmov.i16	q6, #0xff\n\t"
        "mov	lr, #0\n\t"
        "\n"
    "L_mc_tr_i3_%=:\n\t"
        "cmp	lr, #0x40\n\t"
        "bge	L_mc_tr_e3_%=\n\t"
        "lsl	r7, lr, #3\n\t"
        "add	r5, %[out], r7\n\t"
        "add	r6, r5, #0x40\n\t"
        "mov	r4, #0\n\t"
        "\n"
    "L_mc_tr_k3_%=:\n\t"
        "vld1.8	{d0-d1}, [r5]\n\t"
        "vld1.8	{d2-d3}, [r6]\n\t"
        "vand	q2, q0, q6\n\t"
        "vand	q3, q1, q6\n\t"
        "vshl.i64	q3, q3, #8\n\t"
        "veor	q2, q2, q3\n\t"
        "vbic	q4, q0, q6\n\t"
        "vshr.u64	q4, q4, #8\n\t"
        "vbic	q5, q1, q6\n\t"
        "veor	q4, q4, q5\n\t"
        "vst1.8	{d4-d5}, [r5]\n\t"
        "vst1.8	{d8-d9}, [r6]\n\t"
        "add	r5, r5, #16\n\t"
        "add	r6, r6, #16\n\t"
        "add	r4, r4, #2\n\t"
        "cmp	r4, #8\n\t"
        "blt	L_mc_tr_k3_%=\n\t"
        "\n"
    "L_mc_tr_ni3_%=:\n\t"
        "add	lr, lr, #16\n\t"
        "b	L_mc_tr_i3_%=\n\t"
        "\n"
    "L_mc_tr_e3_%=:\n\t"
        "vmov.i8	q6, #15\n\t"
        "mov	lr, #0\n\t"
        "\n"
    "L_mc_tr_i2_%=:\n\t"
        "cmp	lr, #0x40\n\t"
        "bge	L_mc_tr_e2_%=\n\t"
        "lsl	r7, lr, #3\n\t"
        "add	r5, %[out], r7\n\t"
        "add	r6, r5, #32\n\t"
        "mov	r4, #0\n\t"
        "\n"
    "L_mc_tr_k2_%=:\n\t"
        "vld1.8	{d0-d1}, [r5]\n\t"
        "vld1.8	{d2-d3}, [r6]\n\t"
        "vand	q2, q0, q6\n\t"
        "vand	q3, q1, q6\n\t"
        "vshl.i64	q3, q3, #4\n\t"
        "veor	q2, q2, q3\n\t"
        "vbic	q4, q0, q6\n\t"
        "vshr.u64	q4, q4, #4\n\t"
        "vbic	q5, q1, q6\n\t"
        "veor	q4, q4, q5\n\t"
        "vst1.8	{d4-d5}, [r5]\n\t"
        "vst1.8	{d8-d9}, [r6]\n\t"
        "add	r5, r5, #16\n\t"
        "add	r6, r6, #16\n\t"
        "add	r4, r4, #2\n\t"
        "cmp	r4, #4\n\t"
        "blt	L_mc_tr_k2_%=\n\t"
        "\n"
    "L_mc_tr_ni2_%=:\n\t"
        "add	lr, lr, #8\n\t"
        "b	L_mc_tr_i2_%=\n\t"
        "\n"
    "L_mc_tr_e2_%=:\n\t"
        "vmov.i8	q6, #51\n\t"
        "mov	lr, #0\n\t"
        "\n"
    "L_mc_tr_i1_%=:\n\t"
        "cmp	lr, #0x40\n\t"
        "bge	L_mc_tr_e1_%=\n\t"
        "lsl	r7, lr, #3\n\t"
        "add	r5, %[out], r7\n\t"
        "add	r6, r5, #16\n\t"
        "mov	r4, #0\n\t"
        "\n"
    "L_mc_tr_k1_%=:\n\t"
        "vld1.8	{d0-d1}, [r5]\n\t"
        "vld1.8	{d2-d3}, [r6]\n\t"
        "vand	q2, q0, q6\n\t"
        "vand	q3, q1, q6\n\t"
        "vshl.i64	q3, q3, #2\n\t"
        "veor	q2, q2, q3\n\t"
        "vbic	q4, q0, q6\n\t"
        "vshr.u64	q4, q4, #2\n\t"
        "vbic	q5, q1, q6\n\t"
        "veor	q4, q4, q5\n\t"
        "vst1.8	{d4-d5}, [r5]\n\t"
        "vst1.8	{d8-d9}, [r6]\n\t"
        "add	r5, r5, #16\n\t"
        "add	r6, r6, #16\n\t"
        "add	r4, r4, #2\n\t"
        "cmp	r4, #2\n\t"
        "blt	L_mc_tr_k1_%=\n\t"
        "\n"
    "L_mc_tr_ni1_%=:\n\t"
        "add	lr, lr, #4\n\t"
        "b	L_mc_tr_i1_%=\n\t"
        "\n"
    "L_mc_tr_e1_%=:\n\t"
        "vmov.i8	q6, #0x55\n\t"
        "mov	r5, %[out]\n\t"
        "mov	lr, #0\n\t"
        "\n"
    "L_mc_tr_sc0_%=:\n\t"
        "add	r8, r5, #8\n\t"
        "vld1.8	{d0}, [r5]\n\t"
        "vld1.8	{d2}, [r8]\n\t"
        "vand	d4, d0, d12\n\t"
        "vand	d6, d2, d12\n\t"
        "vshl.i64	d6, d6, #1\n\t"
        "veor	d4, d4, d6\n\t"
        "vbic	d8, d0, d12\n\t"
        "vshr.u64	d8, d8, #1\n\t"
        "vbic	d10, d2, d12\n\t"
        "veor	d8, d8, d10\n\t"
        "vst1.8	{d4}, [r5]\n\t"
        "vst1.8	{d8}, [r8]\n\t"
        "add	r5, r5, #16\n\t"
        "add	lr, lr, #2\n\t"
        "cmp	lr, #0x40\n\t"
        "blt	L_mc_tr_sc0_%=\n\t"
        "\n"
    "L_mc_tr_e0_%=:\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [out] "+r" (out), [in] "+r" (in)
        :
#else
        :
        : [out] "r" (out), [in] "r" (in)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r2", "r3", "r12", "lr", "r4", "r5", "r6", "r7", "r8",
            "q0", "q1", "q2", "q3", "q4", "q5", "q6"
    );
}

WOLFSSL_LOCAL void wc_mceliece_aff_transpose_neon(word64* in);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_aff_transpose_neon(word64* in_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_aff_transpose_neon(word64* in)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word64* in __asm__ ("r0") = (word64*)in_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "vmov.i64	q10, #0xffffffff\n\t"
        "mov	r1, #0\n\t"
        "\n"
    "L_mc_at_i5_%=:\n\t"
        "cmp	r1, #0x40\n\t"
        "bge	L_mc_at_e5_%=\n\t"
        "lsl	r4, r1, #5\n\t"
        "add	r3, %[in], r4\n\t"
        "add	r12, r3, #0x400\n\t"
        "mov	r2, r1\n\t"
        "add	lr, r1, #32\n\t"
        "\n"
    "L_mc_at_j5_%=:\n\t"
        "vld1.8	{d0-d3}, [r3]\n\t"
        "vld1.8	{d4-d7}, [r12]\n\t"
        "vand	q4, q0, q10\n\t"
        "vand	q8, q2, q10\n\t"
        "vshl.i64	q8, q8, #32\n\t"
        "veor	q4, q4, q8\n\t"
        "vand	q5, q1, q10\n\t"
        "vand	q9, q3, q10\n\t"
        "vshl.i64	q9, q9, #32\n\t"
        "veor	q5, q5, q9\n\t"
        "vbic	q6, q0, q10\n\t"
        "vshr.u64	q6, q6, #32\n\t"
        "vbic	q8, q2, q10\n\t"
        "veor	q6, q6, q8\n\t"
        "vbic	q7, q1, q10\n\t"
        "vshr.u64	q7, q7, #32\n\t"
        "vbic	q9, q3, q10\n\t"
        "veor	q7, q7, q9\n\t"
        "vst1.8	{d8-d11}, [r3]\n\t"
        "vst1.8	{d12-d15}, [r12]\n\t"
        "add	r3, r3, #32\n\t"
        "add	r12, r12, #32\n\t"
        "add	r2, r2, #1\n\t"
        "cmp	r2, lr\n\t"
        "blt	L_mc_at_j5_%=\n\t"
        "\n"
    "L_mc_at_ni5_%=:\n\t"
        "add	r1, r1, #0x40\n\t"
        "b	L_mc_at_i5_%=\n\t"
        "\n"
    "L_mc_at_e5_%=:\n\t"
        "vmov.i32	q10, #0xffff\n\t"
        "mov	r1, #0\n\t"
        "\n"
    "L_mc_at_i4_%=:\n\t"
        "cmp	r1, #0x40\n\t"
        "bge	L_mc_at_e4_%=\n\t"
        "lsl	r4, r1, #5\n\t"
        "add	r3, %[in], r4\n\t"
        "add	r12, r3, #0x200\n\t"
        "mov	r2, r1\n\t"
        "add	lr, r1, #16\n\t"
        "\n"
    "L_mc_at_j4_%=:\n\t"
        "vld1.8	{d0-d3}, [r3]\n\t"
        "vld1.8	{d4-d7}, [r12]\n\t"
        "vand	q4, q0, q10\n\t"
        "vand	q8, q2, q10\n\t"
        "vshl.i64	q8, q8, #16\n\t"
        "veor	q4, q4, q8\n\t"
        "vand	q5, q1, q10\n\t"
        "vand	q9, q3, q10\n\t"
        "vshl.i64	q9, q9, #16\n\t"
        "veor	q5, q5, q9\n\t"
        "vbic	q6, q0, q10\n\t"
        "vshr.u64	q6, q6, #16\n\t"
        "vbic	q8, q2, q10\n\t"
        "veor	q6, q6, q8\n\t"
        "vbic	q7, q1, q10\n\t"
        "vshr.u64	q7, q7, #16\n\t"
        "vbic	q9, q3, q10\n\t"
        "veor	q7, q7, q9\n\t"
        "vst1.8	{d8-d11}, [r3]\n\t"
        "vst1.8	{d12-d15}, [r12]\n\t"
        "add	r3, r3, #32\n\t"
        "add	r12, r12, #32\n\t"
        "add	r2, r2, #1\n\t"
        "cmp	r2, lr\n\t"
        "blt	L_mc_at_j4_%=\n\t"
        "\n"
    "L_mc_at_ni4_%=:\n\t"
        "add	r1, r1, #32\n\t"
        "b	L_mc_at_i4_%=\n\t"
        "\n"
    "L_mc_at_e4_%=:\n\t"
        "vmov.i16	q10, #0xff\n\t"
        "mov	r1, #0\n\t"
        "\n"
    "L_mc_at_i3_%=:\n\t"
        "cmp	r1, #0x40\n\t"
        "bge	L_mc_at_e3_%=\n\t"
        "lsl	r4, r1, #5\n\t"
        "add	r3, %[in], r4\n\t"
        "add	r12, r3, #0x100\n\t"
        "mov	r2, r1\n\t"
        "add	lr, r1, #8\n\t"
        "\n"
    "L_mc_at_j3_%=:\n\t"
        "vld1.8	{d0-d3}, [r3]\n\t"
        "vld1.8	{d4-d7}, [r12]\n\t"
        "vand	q4, q0, q10\n\t"
        "vand	q8, q2, q10\n\t"
        "vshl.i64	q8, q8, #8\n\t"
        "veor	q4, q4, q8\n\t"
        "vand	q5, q1, q10\n\t"
        "vand	q9, q3, q10\n\t"
        "vshl.i64	q9, q9, #8\n\t"
        "veor	q5, q5, q9\n\t"
        "vbic	q6, q0, q10\n\t"
        "vshr.u64	q6, q6, #8\n\t"
        "vbic	q8, q2, q10\n\t"
        "veor	q6, q6, q8\n\t"
        "vbic	q7, q1, q10\n\t"
        "vshr.u64	q7, q7, #8\n\t"
        "vbic	q9, q3, q10\n\t"
        "veor	q7, q7, q9\n\t"
        "vst1.8	{d8-d11}, [r3]\n\t"
        "vst1.8	{d12-d15}, [r12]\n\t"
        "add	r3, r3, #32\n\t"
        "add	r12, r12, #32\n\t"
        "add	r2, r2, #1\n\t"
        "cmp	r2, lr\n\t"
        "blt	L_mc_at_j3_%=\n\t"
        "\n"
    "L_mc_at_ni3_%=:\n\t"
        "add	r1, r1, #16\n\t"
        "b	L_mc_at_i3_%=\n\t"
        "\n"
    "L_mc_at_e3_%=:\n\t"
        "vmov.i8	q10, #15\n\t"
        "mov	r1, #0\n\t"
        "\n"
    "L_mc_at_i2_%=:\n\t"
        "cmp	r1, #0x40\n\t"
        "bge	L_mc_at_e2_%=\n\t"
        "lsl	r4, r1, #5\n\t"
        "add	r3, %[in], r4\n\t"
        "add	r12, r3, #0x80\n\t"
        "mov	r2, r1\n\t"
        "add	lr, r1, #4\n\t"
        "\n"
    "L_mc_at_j2_%=:\n\t"
        "vld1.8	{d0-d3}, [r3]\n\t"
        "vld1.8	{d4-d7}, [r12]\n\t"
        "vand	q4, q0, q10\n\t"
        "vand	q8, q2, q10\n\t"
        "vshl.i64	q8, q8, #4\n\t"
        "veor	q4, q4, q8\n\t"
        "vand	q5, q1, q10\n\t"
        "vand	q9, q3, q10\n\t"
        "vshl.i64	q9, q9, #4\n\t"
        "veor	q5, q5, q9\n\t"
        "vbic	q6, q0, q10\n\t"
        "vshr.u64	q6, q6, #4\n\t"
        "vbic	q8, q2, q10\n\t"
        "veor	q6, q6, q8\n\t"
        "vbic	q7, q1, q10\n\t"
        "vshr.u64	q7, q7, #4\n\t"
        "vbic	q9, q3, q10\n\t"
        "veor	q7, q7, q9\n\t"
        "vst1.8	{d8-d11}, [r3]\n\t"
        "vst1.8	{d12-d15}, [r12]\n\t"
        "add	r3, r3, #32\n\t"
        "add	r12, r12, #32\n\t"
        "add	r2, r2, #1\n\t"
        "cmp	r2, lr\n\t"
        "blt	L_mc_at_j2_%=\n\t"
        "\n"
    "L_mc_at_ni2_%=:\n\t"
        "add	r1, r1, #8\n\t"
        "b	L_mc_at_i2_%=\n\t"
        "\n"
    "L_mc_at_e2_%=:\n\t"
        "vmov.i8	q10, #51\n\t"
        "mov	r1, #0\n\t"
        "\n"
    "L_mc_at_i1_%=:\n\t"
        "cmp	r1, #0x40\n\t"
        "bge	L_mc_at_e1_%=\n\t"
        "lsl	r4, r1, #5\n\t"
        "add	r3, %[in], r4\n\t"
        "add	r12, r3, #0x40\n\t"
        "mov	r2, r1\n\t"
        "add	lr, r1, #2\n\t"
        "\n"
    "L_mc_at_j1_%=:\n\t"
        "vld1.8	{d0-d3}, [r3]\n\t"
        "vld1.8	{d4-d7}, [r12]\n\t"
        "vand	q4, q0, q10\n\t"
        "vand	q8, q2, q10\n\t"
        "vshl.i64	q8, q8, #2\n\t"
        "veor	q4, q4, q8\n\t"
        "vand	q5, q1, q10\n\t"
        "vand	q9, q3, q10\n\t"
        "vshl.i64	q9, q9, #2\n\t"
        "veor	q5, q5, q9\n\t"
        "vbic	q6, q0, q10\n\t"
        "vshr.u64	q6, q6, #2\n\t"
        "vbic	q8, q2, q10\n\t"
        "veor	q6, q6, q8\n\t"
        "vbic	q7, q1, q10\n\t"
        "vshr.u64	q7, q7, #2\n\t"
        "vbic	q9, q3, q10\n\t"
        "veor	q7, q7, q9\n\t"
        "vst1.8	{d8-d11}, [r3]\n\t"
        "vst1.8	{d12-d15}, [r12]\n\t"
        "add	r3, r3, #32\n\t"
        "add	r12, r12, #32\n\t"
        "add	r2, r2, #1\n\t"
        "cmp	r2, lr\n\t"
        "blt	L_mc_at_j1_%=\n\t"
        "\n"
    "L_mc_at_ni1_%=:\n\t"
        "add	r1, r1, #4\n\t"
        "b	L_mc_at_i1_%=\n\t"
        "\n"
    "L_mc_at_e1_%=:\n\t"
        "vmov.i8	q10, #0x55\n\t"
        "mov	r1, #0\n\t"
        "\n"
    "L_mc_at_i0_%=:\n\t"
        "cmp	r1, #0x40\n\t"
        "bge	L_mc_at_e0_%=\n\t"
        "lsl	r4, r1, #5\n\t"
        "add	r3, %[in], r4\n\t"
        "add	r12, r3, #32\n\t"
        "mov	r2, r1\n\t"
        "add	lr, r1, #1\n\t"
        "\n"
    "L_mc_at_j0_%=:\n\t"
        "vld1.8	{d0-d3}, [r3]\n\t"
        "vld1.8	{d4-d7}, [r12]\n\t"
        "vand	q4, q0, q10\n\t"
        "vand	q8, q2, q10\n\t"
        "vshl.i64	q8, q8, #1\n\t"
        "veor	q4, q4, q8\n\t"
        "vand	q5, q1, q10\n\t"
        "vand	q9, q3, q10\n\t"
        "vshl.i64	q9, q9, #1\n\t"
        "veor	q5, q5, q9\n\t"
        "vbic	q6, q0, q10\n\t"
        "vshr.u64	q6, q6, #1\n\t"
        "vbic	q8, q2, q10\n\t"
        "veor	q6, q6, q8\n\t"
        "vbic	q7, q1, q10\n\t"
        "vshr.u64	q7, q7, #1\n\t"
        "vbic	q9, q3, q10\n\t"
        "veor	q7, q7, q9\n\t"
        "vst1.8	{d8-d11}, [r3]\n\t"
        "vst1.8	{d12-d15}, [r12]\n\t"
        "add	r3, r3, #32\n\t"
        "add	r12, r12, #32\n\t"
        "add	r2, r2, #1\n\t"
        "cmp	r2, lr\n\t"
        "blt	L_mc_at_j0_%=\n\t"
        "\n"
    "L_mc_at_ni0_%=:\n\t"
        "add	r1, r1, #2\n\t"
        "b	L_mc_at_i0_%=\n\t"
        "\n"
    "L_mc_at_e0_%=:\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [in] "+r" (in)
        :
#else
        :
        : [in] "r" (in)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r1", "r2", "r3", "r12", "lr", "r4", "q0", "q1", "q2",
            "q3", "q4", "q5", "q6", "q7", "q8", "q9", "q10"
    );
}

WOLFSSL_LOCAL void wc_mceliece_aff_v128_mul_neon(word64* h, const word64* f,
    const word64* g, word64* c);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_aff_v128_mul_neon(word64* h_p,
    const word64* f_p, const word64* g_p, word64* c_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_aff_v128_mul_neon(word64* h,
    const word64* f, const word64* g, word64* c)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word64* h __asm__ ("r0") = (word64*)h_p;
    register const word64* f __asm__ ("r1") = (const word64*)f_p;
    register const word64* g __asm__ ("r2") = (const word64*)g_p;
    register word64* c __asm__ ("r3") = (word64*)c_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "veor	q5, q5, q5\n\t"
        "mov	r7, %[c]\n\t"
        "mov	r4, #0\n\t"
        "\n"
    "L_mc_v128_z_%=:\n\t"
        "vst1.8	{d10-d11}, [r7]\n\t"
        "add	r7, r7, #16\n\t"
        "add	r4, r4, #1\n\t"
        "cmp	r4, #25\n\t"
        "blt	L_mc_v128_z_%=\n\t"
        "mov	r12, #0\n\t"
        "\n"
    "L_mc_v128_i_%=:\n\t"
        "cmp	r12, #13\n\t"
        "bge	L_mc_v128_rs_%=\n\t"
        "lsl	r9, r12, #4\n\t"
        "add	r5, %[f], r9\n\t"
        "vld1.8	{d0-d1}, [r5]\n\t"
        "mov	lr, #0\n\t"
        "\n"
    "L_mc_v128_j_%=:\n\t"
        "cmp	lr, #13\n\t"
        "bge	L_mc_v128_in_%=\n\t"
        "lsl	r9, lr, #4\n\t"
        "add	r6, %[g], r9\n\t"
        "vld1.8	{d2-d3}, [r6]\n\t"
        "vand	q2, q0, q1\n\t"
        "add	r9, r12, lr\n\t"
        "lsl	r9, r9, #4\n\t"
        "add	r7, %[c], r9\n\t"
        "vld1.8	{d6-d7}, [r7]\n\t"
        "veor	q3, q3, q2\n\t"
        "vst1.8	{d6-d7}, [r7]\n\t"
        "add	lr, lr, #1\n\t"
        "b	L_mc_v128_j_%=\n\t"
        "\n"
    "L_mc_v128_in_%=:\n\t"
        "add	r12, r12, #1\n\t"
        "b	L_mc_v128_i_%=\n\t"
        "\n"
    "L_mc_v128_rs_%=:\n\t"
        "mov	r4, #24\n\t"
        "\n"
    "L_mc_v128_rk_%=:\n\t"
        "cmp	r4, #13\n\t"
        "blt	L_mc_v128_copy_%=\n\t"
        "lsl	r9, r4, #4\n\t"
        "add	r7, %[c], r9\n\t"
        "vld1.8	{d6-d7}, [r7]\n\t"
        "sub	r5, r4, #9\n\t"
        "lsl	r5, r5, #4\n\t"
        "add	r8, %[c], r5\n\t"
        "vld1.8	{d8-d9}, [r8]\n\t"
        "veor	q4, q4, q3\n\t"
        "vst1.8	{d8-d9}, [r8]\n\t"
        "sub	r5, r4, #10\n\t"
        "lsl	r5, r5, #4\n\t"
        "add	r8, %[c], r5\n\t"
        "vld1.8	{d8-d9}, [r8]\n\t"
        "veor	q4, q4, q3\n\t"
        "vst1.8	{d8-d9}, [r8]\n\t"
        "sub	r5, r4, #12\n\t"
        "lsl	r5, r5, #4\n\t"
        "add	r8, %[c], r5\n\t"
        "vld1.8	{d8-d9}, [r8]\n\t"
        "veor	q4, q4, q3\n\t"
        "vst1.8	{d8-d9}, [r8]\n\t"
        "sub	r5, r4, #13\n\t"
        "lsl	r5, r5, #4\n\t"
        "add	r8, %[c], r5\n\t"
        "vld1.8	{d8-d9}, [r8]\n\t"
        "veor	q4, q4, q3\n\t"
        "vst1.8	{d8-d9}, [r8]\n\t"
        "sub	r4, r4, #1\n\t"
        "b	L_mc_v128_rk_%=\n\t"
        "\n"
    "L_mc_v128_copy_%=:\n\t"
        "mov	r4, #0\n\t"
        "\n"
    "L_mc_v128_cp_%=:\n\t"
        "cmp	r4, #13\n\t"
        "bge	L_mc_v128_done_%=\n\t"
        "lsl	r9, r4, #4\n\t"
        "add	r7, %[c], r9\n\t"
        "add	r8, %[h], r9\n\t"
        "vld1.8	{d6-d7}, [r7]\n\t"
        "vst1.8	{d6-d7}, [r8]\n\t"
        "add	r4, r4, #1\n\t"
        "b	L_mc_v128_cp_%=\n\t"
        "\n"
    "L_mc_v128_done_%=:\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [h] "+r" (h), [f] "+r" (f), [g] "+r" (g), [c] "+r" (c)
        :
#else
        :
        : [h] "r" (h), [f] "r" (f), [g] "r" (g), [c] "r" (c)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r12", "lr", "r4", "r5", "r6", "r7", "r8", "r9", "q0",
            "q1", "q2", "q3", "q4", "q5"
    );
}

WOLFSSL_LOCAL void wc_mceliece_aff_v256_mul_neon(word64* h, const word64* f,
    const word64* g, word64* c);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_aff_v256_mul_neon(word64* h_p,
    const word64* f_p, const word64* g_p, word64* c_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_aff_v256_mul_neon(word64* h,
    const word64* f, const word64* g, word64* c)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word64* h __asm__ ("r0") = (word64*)h_p;
    register const word64* f __asm__ ("r1") = (const word64*)f_p;
    register const word64* g __asm__ ("r2") = (const word64*)g_p;
    register word64* c __asm__ ("r3") = (word64*)c_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "veor	q10, q10, q10\n\t"
        "mov	r7, %[c]\n\t"
        "mov	r4, #0\n\t"
        "\n"
    "L_mc_v256_z_%=:\n\t"
        "vst1.8	{d20-d21}, [r7]\n\t"
        "add	r7, r7, #16\n\t"
        "vst1.8	{d20-d21}, [r7]\n\t"
        "add	r7, r7, #16\n\t"
        "add	r4, r4, #1\n\t"
        "cmp	r4, #25\n\t"
        "blt	L_mc_v256_z_%=\n\t"
        "mov	r12, #0\n\t"
        "mov	r5, %[f]\n\t"
        "mov	r8, %[c]\n\t"
        "\n"
    "L_mc_v256_i_%=:\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "mov	r6, %[g]\n\t"
        "mov	r7, r8\n\t"
        "mov	lr, #0\n\t"
        "\n"
    "L_mc_v256_j_%=:\n\t"
        "vld1.8	{d4-d7}, [r6]\n\t"
        "vld1.8	{d12-d15}, [r7]\n\t"
        "add	r6, r6, #32\n\t"
        "vand	q4, q0, q2\n\t"
        "vand	q5, q1, q3\n\t"
        "veor	q6, q6, q4\n\t"
        "veor	q7, q7, q5\n\t"
        "vst1.8	{d12-d15}, [r7]\n\t"
        "add	r7, r7, #32\n\t"
        "add	lr, lr, #1\n\t"
        "cmp	lr, #13\n\t"
        "blt	L_mc_v256_j_%=\n\t"
        "\n"
    "L_mc_v256_in_%=:\n\t"
        "add	r5, r5, #32\n\t"
        "add	r8, r8, #32\n\t"
        "add	r12, r12, #1\n\t"
        "cmp	r12, #13\n\t"
        "blt	L_mc_v256_i_%=\n\t"
        "\n"
    "L_mc_v256_rs_%=:\n\t"
        "mov	r4, #24\n\t"
        "lsl	r9, r4, #5\n\t"
        "add	r7, %[c], r9\n\t"
        "\n"
    "L_mc_v256_rk_%=:\n\t"
        "vld1.8	{d12-d15}, [r7]\n\t"
        "sub	r5, r4, #9\n\t"
        "lsl	r5, r5, #5\n\t"
        "add	r8, %[c], r5\n\t"
        "vld1.8	{d16-d19}, [r8]\n\t"
        "veor	q8, q8, q6\n\t"
        "veor	q9, q9, q7\n\t"
        "vst1.8	{d16-d19}, [r8]\n\t"
        "sub	r5, r4, #10\n\t"
        "lsl	r5, r5, #5\n\t"
        "add	r8, %[c], r5\n\t"
        "vld1.8	{d16-d19}, [r8]\n\t"
        "veor	q8, q8, q6\n\t"
        "veor	q9, q9, q7\n\t"
        "vst1.8	{d16-d19}, [r8]\n\t"
        "sub	r5, r4, #12\n\t"
        "lsl	r5, r5, #5\n\t"
        "add	r8, %[c], r5\n\t"
        "vld1.8	{d16-d19}, [r8]\n\t"
        "veor	q8, q8, q6\n\t"
        "veor	q9, q9, q7\n\t"
        "vst1.8	{d16-d19}, [r8]\n\t"
        "sub	r5, r4, #13\n\t"
        "lsl	r5, r5, #5\n\t"
        "add	r8, %[c], r5\n\t"
        "vld1.8	{d16-d19}, [r8]\n\t"
        "veor	q8, q8, q6\n\t"
        "veor	q9, q9, q7\n\t"
        "vst1.8	{d16-d19}, [r8]\n\t"
        "sub	r7, r7, #32\n\t"
        "sub	r4, r4, #1\n\t"
        "cmp	r4, #13\n\t"
        "bge	L_mc_v256_rk_%=\n\t"
        "\n"
    "L_mc_v256_copy_%=:\n\t"
        "mov	r4, #0\n\t"
        "mov	r7, %[c]\n\t"
        "mov	r8, %[h]\n\t"
        "\n"
    "L_mc_v256_cp_%=:\n\t"
        "vld1.8	{d12-d15}, [r7]\n\t"
        "add	r7, r7, #32\n\t"
        "vst1.8	{d12-d15}, [r8]\n\t"
        "add	r8, r8, #32\n\t"
        "add	r4, r4, #1\n\t"
        "cmp	r4, #13\n\t"
        "blt	L_mc_v256_cp_%=\n\t"
        "\n"
    "L_mc_v256_done_%=:\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [h] "+r" (h), [f] "+r" (f), [g] "+r" (g), [c] "+r" (c)
        :
#else
        :
        : [h] "r" (h), [f] "r" (f), [g] "r" (g), [c] "r" (c)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r12", "lr", "r4", "r5", "r6", "r7", "r8", "r9", "q0",
            "q1", "q2", "q3", "q4", "q5", "q6", "q7", "q8", "q9", "q10"
    );
}

WOLFSSL_LOCAL void wc_mceliece_aff_radix_step_neon(word64* in, int j);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_aff_radix_step_neon(word64* in_p,
    int j_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_aff_radix_step_neon(word64* in, int j)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word64* in __asm__ ("r0") = (word64*)in_p;
    register int j __asm__ ("r1") = (int)j_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    register word64* L_mc_aff_rmask0_neon_c __asm__ ("r2") =
        (word64*)&L_mc_aff_rmask0_neon;
    register word64* L_mc_aff_rmask1_neon_c __asm__ ("r3") =
        (word64*)&L_mc_aff_rmask1_neon;
    __asm__ __volatile__ (
        "veor	q6, q6, q6\n\t"
        "mov	r4, #0\n\t"
        "\n"
    "L_mc_rdx_t_%=:\n\t"
        "cmp	r4, #13\n\t"
        "bge	L_mc_rdx_te_%=\n\t"
        "lsl	r5, r4, #4\n\t"
        "add	r6, %[in], r5\n\t"
        "vld1.8	{d0-d1}, [r6]\n\t"
        "vshr.u64	q5, q0, #32\n\t"
        "vmov	d10, d12\n\t"
        "veor	q0, q0, q5\n\t"
        "vshl.i64	q5, q0, #32\n\t"
        "vmov	d10, d11\n\t"
        "vmov	d11, d12\n\t"
        "veor	q0, q0, q5\n\t"
        "vst1.8	{d0-d1}, [r6]\n\t"
        "add	r4, r4, #1\n\t"
        "b	L_mc_rdx_t_%=\n\t"
        "\n"
    "L_mc_rdx_te_%=:\n\t"
        "mov	r12, #4\n\t"
        "\n"
    "L_mc_rdx_k_%=:\n\t"
        "cmp	r12, %[j]\n\t"
        "blt	L_mc_rdx_ke_%=\n\t"
        "mov	lr, #1\n\t"
        "lsl	lr, lr, r12\n\t"
        "neg	lr, lr\n\t"
        "vdup.32	q4, lr\n\t"
        "lsl	r5, r12, #3\n\t"
        "add	r6, %[L_mc_aff_rmask0_neon], r5\n\t"
        "vld1.8	{d4}, [r6]\n\t"
        "vmov	d5, d4\n\t"
        "add	r6, %[L_mc_aff_rmask1_neon], r5\n\t"
        "vld1.8	{d6}, [r6]\n\t"
        "vmov	d7, d6\n\t"
        "mov	r4, #0\n\t"
        "\n"
    "L_mc_rdx_ki_%=:\n\t"
        "cmp	r4, #13\n\t"
        "bge	L_mc_rdx_kie_%=\n\t"
        "lsl	r5, r4, #4\n\t"
        "add	r6, %[in], r5\n\t"
        "vld1.8	{d0-d1}, [r6]\n\t"
        "vand	q1, q0, q2\n\t"
        "vshl.u64	q1, q1, q4\n\t"
        "veor	q0, q0, q1\n\t"
        "vand	q1, q0, q3\n\t"
        "vshl.u64	q1, q1, q4\n\t"
        "veor	q0, q0, q1\n\t"
        "vst1.8	{d0-d1}, [r6]\n\t"
        "add	r4, r4, #1\n\t"
        "b	L_mc_rdx_ki_%=\n\t"
        "\n"
    "L_mc_rdx_kie_%=:\n\t"
        "sub	r12, r12, #1\n\t"
        "b	L_mc_rdx_k_%=\n\t"
        "\n"
    "L_mc_rdx_ke_%=:\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [in] "+r" (in), [j] "+r" (j),
          [L_mc_aff_rmask0_neon] "+r" (L_mc_aff_rmask0_neon_c),
          [L_mc_aff_rmask1_neon] "+r" (L_mc_aff_rmask1_neon_c)
        :
#else
        :
        : [in] "r" (in), [j] "r" (j),
          [L_mc_aff_rmask0_neon] "r" (L_mc_aff_rmask0_neon_c),
          [L_mc_aff_rmask1_neon] "r" (L_mc_aff_rmask1_neon_c)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r12", "lr", "r4", "r5", "r6", "q0", "q1", "q2", "q3",
            "q4", "q5", "q6"
    );
}

WOLFSSL_LOCAL void wc_mceliece_aff_radix_tr_step_neon(word64* in, int j);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_aff_radix_tr_step_neon(word64* in_p,
    int j_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_aff_radix_tr_step_neon(word64* in, int j)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word64* in __asm__ ("r0") = (word64*)in_p;
    register int j __asm__ ("r1") = (int)j_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    register word64* L_mc_aff_tmask0_neon_c __asm__ ("r2") =
        (word64*)&L_mc_aff_tmask0_neon;
    register word64* L_mc_aff_tmask1_neon_c __asm__ ("r3") =
        (word64*)&L_mc_aff_tmask1_neon;
    __asm__ __volatile__ (
        "veor	q8, q8, q8\n\t"
        "mov	r12, %[j]\n\t"
        "\n"
    "L_mc_rtr_k_%=:\n\t"
        "cmp	r12, #4\n\t"
        "bgt	L_mc_rtr_ke_%=\n\t"
        "mov	lr, #1\n\t"
        "lsl	lr, lr, r12\n\t"
        "vdup.32	q6, lr\n\t"
        "lsl	r5, r12, #3\n\t"
        "add	r6, %[L_mc_aff_tmask0_neon], r5\n\t"
        "vld1.8	{d8}, [r6]\n\t"
        "vmov	d9, d8\n\t"
        "add	r6, %[L_mc_aff_tmask1_neon], r5\n\t"
        "vld1.8	{d10}, [r6]\n\t"
        "vmov	d11, d10\n\t"
        "mov	r4, #0\n\t"
        "\n"
    "L_mc_rtr_ki_%=:\n\t"
        "cmp	r4, #13\n\t"
        "bge	L_mc_rtr_kie_%=\n\t"
        "lsl	r5, r4, #5\n\t"
        "add	r6, %[in], r5\n\t"
        "vld1.8	{d0-d3}, [r6]\n\t"
        "vand	q2, q0, q4\n\t"
        "vshl.u64	q2, q2, q6\n\t"
        "veor	q0, q0, q2\n\t"
        "vand	q3, q1, q4\n\t"
        "vshl.u64	q3, q3, q6\n\t"
        "veor	q1, q1, q3\n\t"
        "vand	q2, q0, q5\n\t"
        "vshl.u64	q2, q2, q6\n\t"
        "veor	q0, q0, q2\n\t"
        "vand	q3, q1, q5\n\t"
        "vshl.u64	q3, q3, q6\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r6]\n\t"
        "add	r4, r4, #1\n\t"
        "b	L_mc_rtr_ki_%=\n\t"
        "\n"
    "L_mc_rtr_kie_%=:\n\t"
        "add	r12, r12, #1\n\t"
        "b	L_mc_rtr_k_%=\n\t"
        "\n"
    "L_mc_rtr_ke_%=:\n\t"
        "cmp	%[j], #5\n\t"
        "bgt	L_mc_rtr_tsk_%=\n\t"
        "mov	r4, #0\n\t"
        "\n"
    "L_mc_rtr_t_%=:\n\t"
        "cmp	r4, #13\n\t"
        "bge	L_mc_rtr_te_%=\n\t"
        "lsl	r5, r4, #5\n\t"
        "add	r6, %[in], r5\n\t"
        "vld1.8	{d0-d3}, [r6]\n\t"
        "vshr.u64	q7, q0, #32\n\t"
        "vmov	d15, d14\n\t"
        "vmov	d14, d16\n\t"
        "veor	q0, q0, q7\n\t"
        "vshl.i64	q7, q0, #32\n\t"
        "vmov	d14, d16\n\t"
        "veor	q0, q0, q7\n\t"
        "vshr.u64	q7, q1, #32\n\t"
        "vmov	d15, d14\n\t"
        "vmov	d14, d16\n\t"
        "veor	q1, q1, q7\n\t"
        "vshl.i64	q7, q1, #32\n\t"
        "vmov	d14, d16\n\t"
        "veor	q1, q1, q7\n\t"
        "vst1.8	{d0-d3}, [r6]\n\t"
        "add	r4, r4, #1\n\t"
        "b	L_mc_rtr_t_%=\n\t"
        "\n"
    "L_mc_rtr_te_%=:\n\t"
        "\n"
    "L_mc_rtr_tsk_%=:\n\t"
        "mov	r4, #0\n\t"
        "\n"
    "L_mc_rtr_c_%=:\n\t"
        "cmp	r4, #13\n\t"
        "bge	L_mc_rtr_ce_%=\n\t"
        "lsl	r5, r4, #5\n\t"
        "add	r6, %[in], r5\n\t"
        "vld1.8	{d0-d3}, [r6]\n\t"
        "vmov	d14, d1\n\t"
        "vmov	d15, d16\n\t"
        "veor	q1, q1, q7\n\t"
        "vmov	d15, d2\n\t"
        "vmov	d14, d16\n\t"
        "veor	q1, q1, q7\n\t"
        "vst1.8	{d0-d3}, [r6]\n\t"
        "add	r4, r4, #1\n\t"
        "b	L_mc_rtr_c_%=\n\t"
        "\n"
    "L_mc_rtr_ce_%=:\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [in] "+r" (in), [j] "+r" (j),
          [L_mc_aff_tmask0_neon] "+r" (L_mc_aff_tmask0_neon_c),
          [L_mc_aff_tmask1_neon] "+r" (L_mc_aff_tmask1_neon_c)
        :
#else
        :
        : [in] "r" (in), [j] "r" (j),
          [L_mc_aff_tmask0_neon] "r" (L_mc_aff_tmask0_neon_c),
          [L_mc_aff_tmask1_neon] "r" (L_mc_aff_tmask1_neon_c)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r12", "lr", "r4", "r5", "r6", "q0", "q1", "q2", "q3",
            "q4", "q5", "q6", "q7", "q8"
    );
}

WOLFSSL_LOCAL void wc_mceliece_radix_conv_neon(word64* in);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_radix_conv_neon(word64* in_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_radix_conv_neon(word64* in)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word64* in __asm__ ("r0") = (word64*)in_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    register word64* L_mc_aff_rmask0_neon_c __asm__ ("r2") =
        (word64*)&L_mc_aff_rmask0_neon;
    register word64* L_mc_aff_rmask1_neon_c __asm__ ("r3") =
        (word64*)&L_mc_aff_rmask1_neon;
    register word64* L_mc_aff_scal2x_neon_c __asm__ ("r12") =
        (word64*)&L_mc_aff_scal2x_neon;
    __asm__ __volatile__ (
        "sub	sp, sp, #0x190\n\t"
        "mov	r1, #0\n\t"
        "\n"
    "L_mc_rconv_j_%=:\n\t"
        "cmp	r1, #5\n\t"
        "bgt	L_mc_rconv_je_%=\n\t"
        "veor	q6, q6, q6\n\t"
        "mov	r5, #0\n\t"
        "\n"
    "L_mc_rdx_t_rc_%=:\n\t"
        "cmp	r5, #13\n\t"
        "bge	L_mc_rdx_te_rc_%=\n\t"
        "lsl	r6, r5, #4\n\t"
        "add	r7, %[in], r6\n\t"
        "vld1.8	{d0-d1}, [r7]\n\t"
        "vshr.u64	q5, q0, #32\n\t"
        "vmov	d10, d12\n\t"
        "veor	q0, q0, q5\n\t"
        "vshl.i64	q5, q0, #32\n\t"
        "vmov	d10, d11\n\t"
        "vmov	d11, d12\n\t"
        "veor	q0, q0, q5\n\t"
        "vst1.8	{d0-d1}, [r7]\n\t"
        "add	r5, r5, #1\n\t"
        "b	L_mc_rdx_t_rc_%=\n\t"
        "\n"
    "L_mc_rdx_te_rc_%=:\n\t"
        "mov	lr, #4\n\t"
        "\n"
    "L_mc_rdx_k_rc_%=:\n\t"
        "cmp	lr, r1\n\t"
        "blt	L_mc_rdx_ke_rc_%=\n\t"
        "mov	r4, #1\n\t"
        "lsl	r4, r4, lr\n\t"
        "neg	r4, r4\n\t"
        "vdup.32	q4, r4\n\t"
        "lsl	r6, lr, #3\n\t"
        "add	r7, %[L_mc_aff_rmask0_neon], r6\n\t"
        "vld1.8	{d4}, [r7]\n\t"
        "vmov	d5, d4\n\t"
        "add	r7, %[L_mc_aff_rmask1_neon], r6\n\t"
        "vld1.8	{d6}, [r7]\n\t"
        "vmov	d7, d6\n\t"
        "mov	r5, #0\n\t"
        "\n"
    "L_mc_rdx_ki_rc_%=:\n\t"
        "cmp	r5, #13\n\t"
        "bge	L_mc_rdx_kie_rc_%=\n\t"
        "lsl	r6, r5, #4\n\t"
        "add	r7, %[in], r6\n\t"
        "vld1.8	{d0-d1}, [r7]\n\t"
        "vand	q1, q0, q2\n\t"
        "vshl.u64	q1, q1, q4\n\t"
        "veor	q0, q0, q1\n\t"
        "vand	q1, q0, q3\n\t"
        "vshl.u64	q1, q1, q4\n\t"
        "veor	q0, q0, q1\n\t"
        "vst1.8	{d0-d1}, [r7]\n\t"
        "add	r5, r5, #1\n\t"
        "b	L_mc_rdx_ki_rc_%=\n\t"
        "\n"
    "L_mc_rdx_kie_rc_%=:\n\t"
        "sub	lr, lr, #1\n\t"
        "b	L_mc_rdx_k_rc_%=\n\t"
        "\n"
    "L_mc_rdx_ke_rc_%=:\n\t"
        "cmp	r1, #5\n\t"
        "bge	L_mc_rconv_sk_%=\n\t"
        "veor	q5, q5, q5\n\t"
        "mov	r8, sp\n\t"
        "mov	r5, #0\n\t"
        "\n"
    "L_mc_v128_z_rc_%=:\n\t"
        "vst1.8	{d10-d11}, [r8]\n\t"
        "add	r8, r8, #16\n\t"
        "add	r5, r5, #1\n\t"
        "cmp	r5, #25\n\t"
        "blt	L_mc_v128_z_rc_%=\n\t"
        "mov	lr, #0\n\t"
        "\n"
    "L_mc_v128_i_rc_%=:\n\t"
        "cmp	lr, #13\n\t"
        "bge	L_mc_v128_rs_rc_%=\n\t"
        "lsl	r10, lr, #4\n\t"
        "add	r6, %[in], r10\n\t"
        "vld1.8	{d0-d1}, [r6]\n\t"
        "mov	r4, #0\n\t"
        "\n"
    "L_mc_v128_j_rc_%=:\n\t"
        "cmp	r4, #13\n\t"
        "bge	L_mc_v128_in_rc_%=\n\t"
        "lsl	r10, r4, #4\n\t"
        "add	r7, %[L_mc_aff_scal2x_neon], r10\n\t"
        "vld1.8	{d2-d3}, [r7]\n\t"
        "vand	q2, q0, q1\n\t"
        "add	r10, lr, r4\n\t"
        "lsl	r10, r10, #4\n\t"
        "add	r8, sp, r10\n\t"
        "vld1.8	{d6-d7}, [r8]\n\t"
        "veor	q3, q3, q2\n\t"
        "vst1.8	{d6-d7}, [r8]\n\t"
        "add	r4, r4, #1\n\t"
        "b	L_mc_v128_j_rc_%=\n\t"
        "\n"
    "L_mc_v128_in_rc_%=:\n\t"
        "add	lr, lr, #1\n\t"
        "b	L_mc_v128_i_rc_%=\n\t"
        "\n"
    "L_mc_v128_rs_rc_%=:\n\t"
        "mov	r5, #24\n\t"
        "\n"
    "L_mc_v128_rk_rc_%=:\n\t"
        "cmp	r5, #13\n\t"
        "blt	L_mc_v128_copy_rc_%=\n\t"
        "lsl	r10, r5, #4\n\t"
        "add	r8, sp, r10\n\t"
        "vld1.8	{d6-d7}, [r8]\n\t"
        "sub	r6, r5, #9\n\t"
        "lsl	r6, r6, #4\n\t"
        "add	r9, sp, r6\n\t"
        "vld1.8	{d8-d9}, [r9]\n\t"
        "veor	q4, q4, q3\n\t"
        "vst1.8	{d8-d9}, [r9]\n\t"
        "sub	r6, r5, #10\n\t"
        "lsl	r6, r6, #4\n\t"
        "add	r9, sp, r6\n\t"
        "vld1.8	{d8-d9}, [r9]\n\t"
        "veor	q4, q4, q3\n\t"
        "vst1.8	{d8-d9}, [r9]\n\t"
        "sub	r6, r5, #12\n\t"
        "lsl	r6, r6, #4\n\t"
        "add	r9, sp, r6\n\t"
        "vld1.8	{d8-d9}, [r9]\n\t"
        "veor	q4, q4, q3\n\t"
        "vst1.8	{d8-d9}, [r9]\n\t"
        "sub	r6, r5, #13\n\t"
        "lsl	r6, r6, #4\n\t"
        "add	r9, sp, r6\n\t"
        "vld1.8	{d8-d9}, [r9]\n\t"
        "veor	q4, q4, q3\n\t"
        "vst1.8	{d8-d9}, [r9]\n\t"
        "sub	r5, r5, #1\n\t"
        "b	L_mc_v128_rk_rc_%=\n\t"
        "\n"
    "L_mc_v128_copy_rc_%=:\n\t"
        "mov	r5, #0\n\t"
        "\n"
    "L_mc_v128_cp_rc_%=:\n\t"
        "cmp	r5, #13\n\t"
        "bge	L_mc_v128_done_rc_%=\n\t"
        "lsl	r10, r5, #4\n\t"
        "add	r8, sp, r10\n\t"
        "add	r9, %[in], r10\n\t"
        "vld1.8	{d6-d7}, [r8]\n\t"
        "vst1.8	{d6-d7}, [r9]\n\t"
        "add	r5, r5, #1\n\t"
        "b	L_mc_v128_cp_rc_%=\n\t"
        "\n"
    "L_mc_v128_done_rc_%=:\n\t"
        "add	%[L_mc_aff_scal2x_neon], %[L_mc_aff_scal2x_neon], #0xd0\n\t"
        "\n"
    "L_mc_rconv_sk_%=:\n\t"
        "add	r1, r1, #1\n\t"
        "b	L_mc_rconv_j_%=\n\t"
        "\n"
    "L_mc_rconv_je_%=:\n\t"
        "add	sp, sp, #0x190\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [in] "+r" (in), [L_mc_aff_rmask0_neon] "+r" (L_mc_aff_rmask0_neon_c),
          [L_mc_aff_rmask1_neon] "+r" (L_mc_aff_rmask1_neon_c),
          [L_mc_aff_scal2x_neon] "+r" (L_mc_aff_scal2x_neon_c)
        :
#else
        :
        : [in] "r" (in), [L_mc_aff_rmask0_neon] "r" (L_mc_aff_rmask0_neon_c),
          [L_mc_aff_rmask1_neon] "r" (L_mc_aff_rmask1_neon_c),
          [L_mc_aff_scal2x_neon] "r" (L_mc_aff_scal2x_neon_c)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r1", "lr", "r4", "r5", "r6", "r7", "r8", "r9", "r10",
            "q0", "q1", "q2", "q3", "q4", "q5", "q6"
    );
}

WOLFSSL_LOCAL void wc_mceliece_radix_conv_tr_neon(word64* in);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_radix_conv_tr_neon(word64* in_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_radix_conv_tr_neon(word64* in)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word64* in __asm__ ("r0") = (word64*)in_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    register word64* L_mc_aff_tmask0_neon_c __asm__ ("r2") =
        (word64*)&L_mc_aff_tmask0_neon;
    register word64* L_mc_aff_tmask1_neon_c __asm__ ("r3") =
        (word64*)&L_mc_aff_tmask1_neon;
    register word64* L_mc_aff_scal4x_neon_c __asm__ ("r12") =
        (word64*)&L_mc_aff_scal4x_neon;
    __asm__ __volatile__ (
        "sub	sp, sp, #0x320\n\t"
        "add	%[L_mc_aff_scal4x_neon], %[L_mc_aff_scal4x_neon], #0x800\n\t"
        "add	%[L_mc_aff_scal4x_neon], %[L_mc_aff_scal4x_neon], #32\n\t"
        "mov	r1, #6\n\t"
        "\n"
    "L_mc_rctr_j_%=:\n\t"
        "cmp	r1, #0\n\t"
        "blt	L_mc_rctr_je_%=\n\t"
        "cmp	r1, #6\n\t"
        "bge	L_mc_rctr_sk_%=\n\t"
        "veor	q10, q10, q10\n\t"
        "mov	r8, sp\n\t"
        "mov	r5, #0\n\t"
        "\n"
    "L_mc_v256_z_rt_%=:\n\t"
        "vst1.8	{d20-d21}, [r8]\n\t"
        "add	r8, r8, #16\n\t"
        "vst1.8	{d20-d21}, [r8]\n\t"
        "add	r8, r8, #16\n\t"
        "add	r5, r5, #1\n\t"
        "cmp	r5, #25\n\t"
        "blt	L_mc_v256_z_rt_%=\n\t"
        "mov	lr, #0\n\t"
        "mov	r6, %[in]\n\t"
        "mov	r9, sp\n\t"
        "\n"
    "L_mc_v256_i_rt_%=:\n\t"
        "vld1.8	{d0-d3}, [r6]\n\t"
        "mov	r7, %[L_mc_aff_scal4x_neon]\n\t"
        "mov	r8, r9\n\t"
        "mov	r4, #0\n\t"
        "\n"
    "L_mc_v256_j_rt_%=:\n\t"
        "vld1.8	{d4-d7}, [r7]\n\t"
        "vld1.8	{d12-d15}, [r8]\n\t"
        "add	r7, r7, #32\n\t"
        "vand	q4, q0, q2\n\t"
        "vand	q5, q1, q3\n\t"
        "veor	q6, q6, q4\n\t"
        "veor	q7, q7, q5\n\t"
        "vst1.8	{d12-d15}, [r8]\n\t"
        "add	r8, r8, #32\n\t"
        "add	r4, r4, #1\n\t"
        "cmp	r4, #13\n\t"
        "blt	L_mc_v256_j_rt_%=\n\t"
        "\n"
    "L_mc_v256_in_rt_%=:\n\t"
        "add	r6, r6, #32\n\t"
        "add	r9, r9, #32\n\t"
        "add	lr, lr, #1\n\t"
        "cmp	lr, #13\n\t"
        "blt	L_mc_v256_i_rt_%=\n\t"
        "\n"
    "L_mc_v256_rs_rt_%=:\n\t"
        "mov	r5, #24\n\t"
        "lsl	r10, r5, #5\n\t"
        "add	r8, sp, r10\n\t"
        "\n"
    "L_mc_v256_rk_rt_%=:\n\t"
        "vld1.8	{d12-d15}, [r8]\n\t"
        "sub	r6, r5, #9\n\t"
        "lsl	r6, r6, #5\n\t"
        "add	r9, sp, r6\n\t"
        "vld1.8	{d16-d19}, [r9]\n\t"
        "veor	q8, q8, q6\n\t"
        "veor	q9, q9, q7\n\t"
        "vst1.8	{d16-d19}, [r9]\n\t"
        "sub	r6, r5, #10\n\t"
        "lsl	r6, r6, #5\n\t"
        "add	r9, sp, r6\n\t"
        "vld1.8	{d16-d19}, [r9]\n\t"
        "veor	q8, q8, q6\n\t"
        "veor	q9, q9, q7\n\t"
        "vst1.8	{d16-d19}, [r9]\n\t"
        "sub	r6, r5, #12\n\t"
        "lsl	r6, r6, #5\n\t"
        "add	r9, sp, r6\n\t"
        "vld1.8	{d16-d19}, [r9]\n\t"
        "veor	q8, q8, q6\n\t"
        "veor	q9, q9, q7\n\t"
        "vst1.8	{d16-d19}, [r9]\n\t"
        "sub	r6, r5, #13\n\t"
        "lsl	r6, r6, #5\n\t"
        "add	r9, sp, r6\n\t"
        "vld1.8	{d16-d19}, [r9]\n\t"
        "veor	q8, q8, q6\n\t"
        "veor	q9, q9, q7\n\t"
        "vst1.8	{d16-d19}, [r9]\n\t"
        "sub	r8, r8, #32\n\t"
        "sub	r5, r5, #1\n\t"
        "cmp	r5, #13\n\t"
        "bge	L_mc_v256_rk_rt_%=\n\t"
        "\n"
    "L_mc_v256_copy_rt_%=:\n\t"
        "mov	r5, #0\n\t"
        "mov	r8, sp\n\t"
        "mov	r9, %[in]\n\t"
        "\n"
    "L_mc_v256_cp_rt_%=:\n\t"
        "vld1.8	{d12-d15}, [r8]\n\t"
        "add	r8, r8, #32\n\t"
        "vst1.8	{d12-d15}, [r9]\n\t"
        "add	r9, r9, #32\n\t"
        "add	r5, r5, #1\n\t"
        "cmp	r5, #13\n\t"
        "blt	L_mc_v256_cp_rt_%=\n\t"
        "\n"
    "L_mc_v256_done_rt_%=:\n\t"
        "sub	%[L_mc_aff_scal4x_neon], %[L_mc_aff_scal4x_neon], #0x1a0\n\t"
        "\n"
    "L_mc_rctr_sk_%=:\n\t"
        "veor	q8, q8, q8\n\t"
        "mov	lr, r1\n\t"
        "\n"
    "L_mc_rtr_k_rt_%=:\n\t"
        "cmp	lr, #4\n\t"
        "bgt	L_mc_rtr_ke_rt_%=\n\t"
        "mov	r4, #1\n\t"
        "lsl	r4, r4, lr\n\t"
        "vdup.32	q6, r4\n\t"
        "lsl	r6, lr, #3\n\t"
        "add	r7, %[L_mc_aff_tmask0_neon], r6\n\t"
        "vld1.8	{d8}, [r7]\n\t"
        "vmov	d9, d8\n\t"
        "add	r7, %[L_mc_aff_tmask1_neon], r6\n\t"
        "vld1.8	{d10}, [r7]\n\t"
        "vmov	d11, d10\n\t"
        "mov	r5, #0\n\t"
        "\n"
    "L_mc_rtr_ki_rt_%=:\n\t"
        "cmp	r5, #13\n\t"
        "bge	L_mc_rtr_kie_rt_%=\n\t"
        "lsl	r6, r5, #5\n\t"
        "add	r7, %[in], r6\n\t"
        "vld1.8	{d0-d3}, [r7]\n\t"
        "vand	q2, q0, q4\n\t"
        "vshl.u64	q2, q2, q6\n\t"
        "veor	q0, q0, q2\n\t"
        "vand	q3, q1, q4\n\t"
        "vshl.u64	q3, q3, q6\n\t"
        "veor	q1, q1, q3\n\t"
        "vand	q2, q0, q5\n\t"
        "vshl.u64	q2, q2, q6\n\t"
        "veor	q0, q0, q2\n\t"
        "vand	q3, q1, q5\n\t"
        "vshl.u64	q3, q3, q6\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [r7]\n\t"
        "add	r5, r5, #1\n\t"
        "b	L_mc_rtr_ki_rt_%=\n\t"
        "\n"
    "L_mc_rtr_kie_rt_%=:\n\t"
        "add	lr, lr, #1\n\t"
        "b	L_mc_rtr_k_rt_%=\n\t"
        "\n"
    "L_mc_rtr_ke_rt_%=:\n\t"
        "cmp	r1, #5\n\t"
        "bgt	L_mc_rtr_tsk_rt_%=\n\t"
        "mov	r5, #0\n\t"
        "\n"
    "L_mc_rtr_t_rt_%=:\n\t"
        "cmp	r5, #13\n\t"
        "bge	L_mc_rtr_te_rt_%=\n\t"
        "lsl	r6, r5, #5\n\t"
        "add	r7, %[in], r6\n\t"
        "vld1.8	{d0-d3}, [r7]\n\t"
        "vshr.u64	q7, q0, #32\n\t"
        "vmov	d15, d14\n\t"
        "vmov	d14, d16\n\t"
        "veor	q0, q0, q7\n\t"
        "vshl.i64	q7, q0, #32\n\t"
        "vmov	d14, d16\n\t"
        "veor	q0, q0, q7\n\t"
        "vshr.u64	q7, q1, #32\n\t"
        "vmov	d15, d14\n\t"
        "vmov	d14, d16\n\t"
        "veor	q1, q1, q7\n\t"
        "vshl.i64	q7, q1, #32\n\t"
        "vmov	d14, d16\n\t"
        "veor	q1, q1, q7\n\t"
        "vst1.8	{d0-d3}, [r7]\n\t"
        "add	r5, r5, #1\n\t"
        "b	L_mc_rtr_t_rt_%=\n\t"
        "\n"
    "L_mc_rtr_te_rt_%=:\n\t"
        "\n"
    "L_mc_rtr_tsk_rt_%=:\n\t"
        "mov	r5, #0\n\t"
        "\n"
    "L_mc_rtr_c_rt_%=:\n\t"
        "cmp	r5, #13\n\t"
        "bge	L_mc_rtr_ce_rt_%=\n\t"
        "lsl	r6, r5, #5\n\t"
        "add	r7, %[in], r6\n\t"
        "vld1.8	{d0-d3}, [r7]\n\t"
        "vmov	d14, d1\n\t"
        "vmov	d15, d16\n\t"
        "veor	q1, q1, q7\n\t"
        "vmov	d15, d2\n\t"
        "vmov	d14, d16\n\t"
        "veor	q1, q1, q7\n\t"
        "vst1.8	{d0-d3}, [r7]\n\t"
        "add	r5, r5, #1\n\t"
        "b	L_mc_rtr_c_rt_%=\n\t"
        "\n"
    "L_mc_rtr_ce_rt_%=:\n\t"
        "sub	r1, r1, #1\n\t"
        "b	L_mc_rctr_j_%=\n\t"
        "\n"
    "L_mc_rctr_je_%=:\n\t"
        "add	sp, sp, #0x320\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [in] "+r" (in), [L_mc_aff_tmask0_neon] "+r" (L_mc_aff_tmask0_neon_c),
          [L_mc_aff_tmask1_neon] "+r" (L_mc_aff_tmask1_neon_c),
          [L_mc_aff_scal4x_neon] "+r" (L_mc_aff_scal4x_neon_c)
        :
#else
        :
        : [in] "r" (in), [L_mc_aff_tmask0_neon] "r" (L_mc_aff_tmask0_neon_c),
          [L_mc_aff_tmask1_neon] "r" (L_mc_aff_tmask1_neon_c),
          [L_mc_aff_scal4x_neon] "r" (L_mc_aff_scal4x_neon_c)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r1", "lr", "r4", "r5", "r6", "r7", "r8", "r9", "r10",
            "q0", "q1", "q2", "q3", "q4", "q5", "q6", "q7", "q8", "q9", "q10"
    );
}

WOLFSSL_LOCAL void wc_mceliece_aff_inv256_neon(word64* out, const word64* in,
    word64* sq, word64* c);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_aff_inv256_neon(word64* out_p,
    const word64* in_p, word64* sq_p, word64* c_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_aff_inv256_neon(word64* out,
    const word64* in, word64* sq, word64* c)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word64* out __asm__ ("r0") = (word64*)out_p;
    register const word64* in __asm__ ("r1") = (const word64*)in_p;
    register word64* sq __asm__ ("r2") = (word64*)sq_p;
    register word64* c __asm__ ("r3") = (word64*)c_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "sub	sp, sp, #0x1a0\n\t"
        "mov	lr, %[in]\n\t"
        "mov	r4, sp\n\t"
        "mov	r6, #0\n\t"
        "\n"
    "L_mc_sqr_s_iv1_%=:\n\t"
        "vld1.8	{d0-d3}, [lr]\n\t"
        "vst1.8	{d0-d3}, [r4]\n\t"
        "add	lr, lr, #32\n\t"
        "add	r4, r4, #32\n\t"
        "add	r6, r6, #1\n\t"
        "cmp	r6, #13\n\t"
        "blt	L_mc_sqr_s_iv1_%=\n\t"
        "add	r5, sp, #0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #0x160\n\t"
        "vld1.8	{d4-d7}, [r5]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, %[sq], #0\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #0xe0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #0x160\n\t"
        "vld1.8	{d4-d7}, [r5]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, sp, #0x180\n\t"
        "vld1.8	{d4-d7}, [r5]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, %[sq], #32\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #32\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #0xe0\n\t"
        "vld1.8	{d4-d7}, [r5]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, %[sq], #0x40\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #0x100\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #0x160\n\t"
        "vld1.8	{d4-d7}, [r5]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, sp, #0x180\n\t"
        "vld1.8	{d4-d7}, [r5]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, %[sq], #0x60\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #0x40\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #0xe0\n\t"
        "vld1.8	{d4-d7}, [r5]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, sp, #0x100\n\t"
        "vld1.8	{d4-d7}, [r5]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, sp, #0x160\n\t"
        "vld1.8	{d4-d7}, [r5]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, sp, #0x180\n\t"
        "vld1.8	{d4-d7}, [r5]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, %[sq], #0x80\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #0xe0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #0x120\n\t"
        "vld1.8	{d4-d7}, [r5]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, %[sq], #0xa0\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #0x60\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #0x100\n\t"
        "vld1.8	{d4-d7}, [r5]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, sp, #0x120\n\t"
        "vld1.8	{d4-d7}, [r5]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, sp, #0x180\n\t"
        "vld1.8	{d4-d7}, [r5]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, %[sq], #0xc0\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #0x100\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #0x140\n\t"
        "vld1.8	{d4-d7}, [r5]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, %[sq], #0xe0\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #0x80\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #0x120\n\t"
        "vld1.8	{d4-d7}, [r5]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, sp, #0x140\n\t"
        "vld1.8	{d4-d7}, [r5]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, %[sq], #0x100\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #0x120\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #0x160\n\t"
        "vld1.8	{d4-d7}, [r5]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, %[sq], #0x120\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #0xa0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #0x140\n\t"
        "vld1.8	{d4-d7}, [r5]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, sp, #0x160\n\t"
        "vld1.8	{d4-d7}, [r5]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, %[sq], #0x140\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #0x140\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #0x180\n\t"
        "vld1.8	{d4-d7}, [r5]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, %[sq], #0x160\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #0xc0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #0x160\n\t"
        "vld1.8	{d4-d7}, [r5]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, sp, #0x180\n\t"
        "vld1.8	{d4-d7}, [r5]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, %[sq], #0x180\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "mov	r12, #0\n\t"
        "\n"
    "L_mc_inv_cp_%=:\n\t"
        "cmp	r12, #13\n\t"
        "bge	L_mc_inv_cpe_%=\n\t"
        "lsl	lr, r12, #5\n\t"
        "add	r4, %[sq], lr\n\t"
        "vld1.8	{d0-d3}, [r4]\n\t"
        "add	r5, %[out], lr\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r12, r12, #1\n\t"
        "b	L_mc_inv_cp_%=\n\t"
        "\n"
    "L_mc_inv_cpe_%=:\n\t"
        "mov	r12, #2\n\t"
        "\n"
    "L_mc_inv_l_%=:\n\t"
        "cmp	r12, #12\n\t"
        "bgt	L_mc_inv_le_%=\n\t"
        "mov	lr, %[sq]\n\t"
        "mov	r4, sp\n\t"
        "mov	r6, #0\n\t"
        "\n"
    "L_mc_sqr_s_iv2_%=:\n\t"
        "vld1.8	{d0-d3}, [lr]\n\t"
        "vst1.8	{d0-d3}, [r4]\n\t"
        "add	lr, lr, #32\n\t"
        "add	r4, r4, #32\n\t"
        "add	r6, r6, #1\n\t"
        "cmp	r6, #13\n\t"
        "blt	L_mc_sqr_s_iv2_%=\n\t"
        "add	r5, sp, #0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #0x160\n\t"
        "vld1.8	{d4-d7}, [r5]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, %[sq], #0\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #0xe0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #0x160\n\t"
        "vld1.8	{d4-d7}, [r5]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, sp, #0x180\n\t"
        "vld1.8	{d4-d7}, [r5]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, %[sq], #32\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #32\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #0xe0\n\t"
        "vld1.8	{d4-d7}, [r5]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, %[sq], #0x40\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #0x100\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #0x160\n\t"
        "vld1.8	{d4-d7}, [r5]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, sp, #0x180\n\t"
        "vld1.8	{d4-d7}, [r5]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, %[sq], #0x60\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #0x40\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #0xe0\n\t"
        "vld1.8	{d4-d7}, [r5]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, sp, #0x100\n\t"
        "vld1.8	{d4-d7}, [r5]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, sp, #0x160\n\t"
        "vld1.8	{d4-d7}, [r5]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, sp, #0x180\n\t"
        "vld1.8	{d4-d7}, [r5]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, %[sq], #0x80\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #0xe0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #0x120\n\t"
        "vld1.8	{d4-d7}, [r5]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, %[sq], #0xa0\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #0x60\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #0x100\n\t"
        "vld1.8	{d4-d7}, [r5]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, sp, #0x120\n\t"
        "vld1.8	{d4-d7}, [r5]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, sp, #0x180\n\t"
        "vld1.8	{d4-d7}, [r5]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, %[sq], #0xc0\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #0x100\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #0x140\n\t"
        "vld1.8	{d4-d7}, [r5]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, %[sq], #0xe0\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #0x80\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #0x120\n\t"
        "vld1.8	{d4-d7}, [r5]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, sp, #0x140\n\t"
        "vld1.8	{d4-d7}, [r5]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, %[sq], #0x100\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #0x120\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #0x160\n\t"
        "vld1.8	{d4-d7}, [r5]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, %[sq], #0x120\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #0xa0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #0x140\n\t"
        "vld1.8	{d4-d7}, [r5]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, sp, #0x160\n\t"
        "vld1.8	{d4-d7}, [r5]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, %[sq], #0x140\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #0x140\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #0x180\n\t"
        "vld1.8	{d4-d7}, [r5]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, %[sq], #0x160\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #0xc0\n\t"
        "vld1.8	{d0-d3}, [r5]\n\t"
        "add	r5, sp, #0x160\n\t"
        "vld1.8	{d4-d7}, [r5]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, sp, #0x180\n\t"
        "vld1.8	{d4-d7}, [r5]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, %[sq], #0x180\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "veor	q10, q10, q10\n\t"
        "mov	r8, %[c]\n\t"
        "mov	r5, #0\n\t"
        "\n"
    "L_mc_v256_z_iv_%=:\n\t"
        "vst1.8	{d20-d21}, [r8]\n\t"
        "add	r8, r8, #16\n\t"
        "vst1.8	{d20-d21}, [r8]\n\t"
        "add	r8, r8, #16\n\t"
        "add	r5, r5, #1\n\t"
        "cmp	r5, #25\n\t"
        "blt	L_mc_v256_z_iv_%=\n\t"
        "mov	lr, #0\n\t"
        "mov	r6, %[out]\n\t"
        "mov	r9, %[c]\n\t"
        "\n"
    "L_mc_v256_i_iv_%=:\n\t"
        "vld1.8	{d0-d3}, [r6]\n\t"
        "mov	r7, %[sq]\n\t"
        "mov	r8, r9\n\t"
        "mov	r4, #0\n\t"
        "\n"
    "L_mc_v256_j_iv_%=:\n\t"
        "vld1.8	{d4-d7}, [r7]\n\t"
        "vld1.8	{d12-d15}, [r8]\n\t"
        "add	r7, r7, #32\n\t"
        "vand	q4, q0, q2\n\t"
        "vand	q5, q1, q3\n\t"
        "veor	q6, q6, q4\n\t"
        "veor	q7, q7, q5\n\t"
        "vst1.8	{d12-d15}, [r8]\n\t"
        "add	r8, r8, #32\n\t"
        "add	r4, r4, #1\n\t"
        "cmp	r4, #13\n\t"
        "blt	L_mc_v256_j_iv_%=\n\t"
        "\n"
    "L_mc_v256_in_iv_%=:\n\t"
        "add	r6, r6, #32\n\t"
        "add	r9, r9, #32\n\t"
        "add	lr, lr, #1\n\t"
        "cmp	lr, #13\n\t"
        "blt	L_mc_v256_i_iv_%=\n\t"
        "\n"
    "L_mc_v256_rs_iv_%=:\n\t"
        "mov	r5, #24\n\t"
        "lsl	r10, r5, #5\n\t"
        "add	r8, %[c], r10\n\t"
        "\n"
    "L_mc_v256_rk_iv_%=:\n\t"
        "vld1.8	{d12-d15}, [r8]\n\t"
        "sub	r6, r5, #9\n\t"
        "lsl	r6, r6, #5\n\t"
        "add	r9, %[c], r6\n\t"
        "vld1.8	{d16-d19}, [r9]\n\t"
        "veor	q8, q8, q6\n\t"
        "veor	q9, q9, q7\n\t"
        "vst1.8	{d16-d19}, [r9]\n\t"
        "sub	r6, r5, #10\n\t"
        "lsl	r6, r6, #5\n\t"
        "add	r9, %[c], r6\n\t"
        "vld1.8	{d16-d19}, [r9]\n\t"
        "veor	q8, q8, q6\n\t"
        "veor	q9, q9, q7\n\t"
        "vst1.8	{d16-d19}, [r9]\n\t"
        "sub	r6, r5, #12\n\t"
        "lsl	r6, r6, #5\n\t"
        "add	r9, %[c], r6\n\t"
        "vld1.8	{d16-d19}, [r9]\n\t"
        "veor	q8, q8, q6\n\t"
        "veor	q9, q9, q7\n\t"
        "vst1.8	{d16-d19}, [r9]\n\t"
        "sub	r6, r5, #13\n\t"
        "lsl	r6, r6, #5\n\t"
        "add	r9, %[c], r6\n\t"
        "vld1.8	{d16-d19}, [r9]\n\t"
        "veor	q8, q8, q6\n\t"
        "veor	q9, q9, q7\n\t"
        "vst1.8	{d16-d19}, [r9]\n\t"
        "sub	r8, r8, #32\n\t"
        "sub	r5, r5, #1\n\t"
        "cmp	r5, #13\n\t"
        "bge	L_mc_v256_rk_iv_%=\n\t"
        "\n"
    "L_mc_v256_copy_iv_%=:\n\t"
        "mov	r5, #0\n\t"
        "mov	r8, %[c]\n\t"
        "mov	r9, %[out]\n\t"
        "\n"
    "L_mc_v256_cp_iv_%=:\n\t"
        "vld1.8	{d12-d15}, [r8]\n\t"
        "add	r8, r8, #32\n\t"
        "vst1.8	{d12-d15}, [r9]\n\t"
        "add	r9, r9, #32\n\t"
        "add	r5, r5, #1\n\t"
        "cmp	r5, #13\n\t"
        "blt	L_mc_v256_cp_iv_%=\n\t"
        "\n"
    "L_mc_v256_done_iv_%=:\n\t"
        "add	r12, r12, #1\n\t"
        "b	L_mc_inv_l_%=\n\t"
        "\n"
    "L_mc_inv_le_%=:\n\t"
        "add	sp, sp, #0x1a0\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [out] "+r" (out), [in] "+r" (in), [sq] "+r" (sq), [c] "+r" (c)
        :
#else
        :
        : [out] "r" (out), [in] "r" (in), [sq] "r" (sq), [c] "r" (c)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r12", "lr", "r4", "r5", "r6", "r7", "r8", "r9",
            "r10", "q0", "q1", "q2", "q3", "q4", "q5", "q6", "q7", "q8", "q9",
            "q10"
    );
}

WOLFSSL_LOCAL void wc_mceliece_aff_v256_sqr_neon(word64* r, const word64* a);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_aff_v256_sqr_neon(word64* r_p,
    const word64* a_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_aff_v256_sqr_neon(word64* r,
    const word64* a)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word64* r __asm__ ("r0") = (word64*)r_p;
    register const word64* a __asm__ ("r1") = (const word64*)a_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "sub	sp, sp, #0x1a0\n\t"
        "mov	r2, %[a]\n\t"
        "mov	r3, sp\n\t"
        "mov	lr, #0\n\t"
        "\n"
    "L_mc_sqr_s_%=:\n\t"
        "vld1.8	{d0-d3}, [r2]\n\t"
        "vst1.8	{d0-d3}, [r3]\n\t"
        "add	r2, r2, #32\n\t"
        "add	r3, r3, #32\n\t"
        "add	lr, lr, #1\n\t"
        "cmp	lr, #13\n\t"
        "blt	L_mc_sqr_s_%=\n\t"
        "add	r12, sp, #0\n\t"
        "vld1.8	{d0-d3}, [r12]\n\t"
        "add	r12, sp, #0x160\n\t"
        "vld1.8	{d4-d7}, [r12]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[r], #0\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	r12, sp, #0xe0\n\t"
        "vld1.8	{d0-d3}, [r12]\n\t"
        "add	r12, sp, #0x160\n\t"
        "vld1.8	{d4-d7}, [r12]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, sp, #0x180\n\t"
        "vld1.8	{d4-d7}, [r12]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[r], #32\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	r12, sp, #32\n\t"
        "vld1.8	{d0-d3}, [r12]\n\t"
        "add	r12, sp, #0xe0\n\t"
        "vld1.8	{d4-d7}, [r12]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[r], #0x40\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	r12, sp, #0x100\n\t"
        "vld1.8	{d0-d3}, [r12]\n\t"
        "add	r12, sp, #0x160\n\t"
        "vld1.8	{d4-d7}, [r12]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, sp, #0x180\n\t"
        "vld1.8	{d4-d7}, [r12]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[r], #0x60\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	r12, sp, #0x40\n\t"
        "vld1.8	{d0-d3}, [r12]\n\t"
        "add	r12, sp, #0xe0\n\t"
        "vld1.8	{d4-d7}, [r12]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, sp, #0x100\n\t"
        "vld1.8	{d4-d7}, [r12]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, sp, #0x160\n\t"
        "vld1.8	{d4-d7}, [r12]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, sp, #0x180\n\t"
        "vld1.8	{d4-d7}, [r12]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[r], #0x80\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	r12, sp, #0xe0\n\t"
        "vld1.8	{d0-d3}, [r12]\n\t"
        "add	r12, sp, #0x120\n\t"
        "vld1.8	{d4-d7}, [r12]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[r], #0xa0\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	r12, sp, #0x60\n\t"
        "vld1.8	{d0-d3}, [r12]\n\t"
        "add	r12, sp, #0x100\n\t"
        "vld1.8	{d4-d7}, [r12]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, sp, #0x120\n\t"
        "vld1.8	{d4-d7}, [r12]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, sp, #0x180\n\t"
        "vld1.8	{d4-d7}, [r12]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[r], #0xc0\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	r12, sp, #0x100\n\t"
        "vld1.8	{d0-d3}, [r12]\n\t"
        "add	r12, sp, #0x140\n\t"
        "vld1.8	{d4-d7}, [r12]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[r], #0xe0\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	r12, sp, #0x80\n\t"
        "vld1.8	{d0-d3}, [r12]\n\t"
        "add	r12, sp, #0x120\n\t"
        "vld1.8	{d4-d7}, [r12]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, sp, #0x140\n\t"
        "vld1.8	{d4-d7}, [r12]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[r], #0x100\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	r12, sp, #0x120\n\t"
        "vld1.8	{d0-d3}, [r12]\n\t"
        "add	r12, sp, #0x160\n\t"
        "vld1.8	{d4-d7}, [r12]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[r], #0x120\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	r12, sp, #0xa0\n\t"
        "vld1.8	{d0-d3}, [r12]\n\t"
        "add	r12, sp, #0x140\n\t"
        "vld1.8	{d4-d7}, [r12]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, sp, #0x160\n\t"
        "vld1.8	{d4-d7}, [r12]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[r], #0x140\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	r12, sp, #0x140\n\t"
        "vld1.8	{d0-d3}, [r12]\n\t"
        "add	r12, sp, #0x180\n\t"
        "vld1.8	{d4-d7}, [r12]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[r], #0x160\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	r12, sp, #0xc0\n\t"
        "vld1.8	{d0-d3}, [r12]\n\t"
        "add	r12, sp, #0x160\n\t"
        "vld1.8	{d4-d7}, [r12]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, sp, #0x180\n\t"
        "vld1.8	{d4-d7}, [r12]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[r], #0x180\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	sp, sp, #0x1a0\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [r] "+r" (r), [a] "+r" (a)
        :
#else
        :
        : [r] "r" (r), [a] "r" (a)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r2", "r3", "r12", "lr", "q0", "q1", "q2", "q3"
    );
}

WOLFSSL_LOCAL void wc_mceliece_aff_v256_xor13_neon(word64* r, const word64* a,
    const word64* b);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_aff_v256_xor13_neon(word64* r_p,
    const word64* a_p, const word64* b_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_aff_v256_xor13_neon(word64* r,
    const word64* a, const word64* b)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word64* r __asm__ ("r0") = (word64*)r_p;
    register const word64* a __asm__ ("r1") = (const word64*)a_p;
    register const word64* b __asm__ ("r2") = (const word64*)b_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "mov	r3, #0\n\t"
        "\n"
    "L_mc_xor13_k_%=:\n\t"
        "lsl	r12, r3, #5\n\t"
        "add	r4, %[a], r12\n\t"
        "vld1.8	{d0-d3}, [r4]\n\t"
        "add	r5, %[b], r12\n\t"
        "vld1.8	{d4-d7}, [r5]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	lr, %[r], r12\n\t"
        "vst1.8	{d0-d3}, [lr]\n\t"
        "add	r3, r3, #1\n\t"
        "cmp	r3, #13\n\t"
        "blt	L_mc_xor13_k_%=\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
#else
        :
        : [r] "r" (r), [a] "r" (a), [b] "r" (b)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r3", "r12", "lr", "r4", "r5", "q0", "q1", "q2", "q3"
    );
}

WOLFSSL_LOCAL void wc_mceliece_aff_pack_lh_neon(word64* lo, word64* hi,
    const word64* a, const word64* b);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_aff_pack_lh_neon(word64* lo_p,
    word64* hi_p, const word64* a_p, const word64* b_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_aff_pack_lh_neon(word64* lo, word64* hi,
    const word64* a, const word64* b)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word64* lo __asm__ ("r0") = (word64*)lo_p;
    register word64* hi __asm__ ("r1") = (word64*)hi_p;
    register const word64* a __asm__ ("r2") = (const word64*)a_p;
    register const word64* b __asm__ ("r3") = (const word64*)b_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "mov	r12, #0\n\t"
        "\n"
    "L_mc_packlh_p_%=:\n\t"
        "lsl	lr, r12, #5\n\t"
        "add	r6, %[a], lr\n\t"
        "vld1.8	{d0-d3}, [r6]\n\t"
        "add	r7, %[b], lr\n\t"
        "vld1.8	{d4-d7}, [r7]\n\t"
        "add	r4, %[lo], lr\n\t"
        "vst1.8	{d0-d1}, [r4]\n\t"
        "add	r4, r4, #16\n\t"
        "vst1.8	{d4-d5}, [r4]\n\t"
        "add	r5, %[hi], lr\n\t"
        "vst1.8	{d2-d3}, [r5]\n\t"
        "add	r5, r5, #16\n\t"
        "vst1.8	{d6-d7}, [r5]\n\t"
        "add	r12, r12, #1\n\t"
        "cmp	r12, #13\n\t"
        "blt	L_mc_packlh_p_%=\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [lo] "+r" (lo), [hi] "+r" (hi), [a] "+r" (a), [b] "+r" (b)
        :
#else
        :
        : [lo] "r" (lo), [hi] "r" (hi), [a] "r" (a), [b] "r" (b)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r12", "lr", "r4", "r5", "r6", "r7", "q0", "q1", "q2",
            "q3"
    );
}

WOLFSSL_LOCAL void wc_mceliece_aff_maa_neon(word64* a, word64* b,
    const word64* c, word64* p, word64* cscr);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_aff_maa_neon(word64* a_p, word64* b_p,
    const word64* c_p, word64* p_p, word64* cscr_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_aff_maa_neon(word64* a, word64* b,
    const word64* c, word64* p, word64* cscr)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word64* a __asm__ ("r0") = (word64*)a_p;
    register word64* b __asm__ ("r1") = (word64*)b_p;
    register const word64* c __asm__ ("r2") = (const word64*)c_p;
    register word64* p __asm__ ("r3") = (word64*)p_p;
    register word64* cscr __asm__ ("r12") = (word64*)cscr_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "push	{%[cscr]}\n\t"
        "ldr	r12, [sp]\n\t"
        "veor	q10, q10, q10\n\t"
        "mov	r8, r12\n\t"
        "mov	r5, #0\n\t"
        "\n"
    "L_mc_v256_z_maa_%=:\n\t"
        "vst1.8	{d20-d21}, [r8]\n\t"
        "add	r8, r8, #16\n\t"
        "vst1.8	{d20-d21}, [r8]\n\t"
        "add	r8, r8, #16\n\t"
        "add	r5, r5, #1\n\t"
        "cmp	r5, #25\n\t"
        "blt	L_mc_v256_z_maa_%=\n\t"
        "mov	lr, #0\n\t"
        "mov	r6, %[b]\n\t"
        "mov	r9, r12\n\t"
        "\n"
    "L_mc_v256_i_maa_%=:\n\t"
        "vld1.8	{d0-d3}, [r6]\n\t"
        "mov	r7, %[c]\n\t"
        "mov	r8, r9\n\t"
        "mov	r4, #0\n\t"
        "\n"
    "L_mc_v256_j_maa_%=:\n\t"
        "vld1.8	{d4-d7}, [r7]\n\t"
        "vld1.8	{d12-d15}, [r8]\n\t"
        "add	r7, r7, #32\n\t"
        "vand	q4, q0, q2\n\t"
        "vand	q5, q1, q3\n\t"
        "veor	q6, q6, q4\n\t"
        "veor	q7, q7, q5\n\t"
        "vst1.8	{d12-d15}, [r8]\n\t"
        "add	r8, r8, #32\n\t"
        "add	r4, r4, #1\n\t"
        "cmp	r4, #13\n\t"
        "blt	L_mc_v256_j_maa_%=\n\t"
        "\n"
    "L_mc_v256_in_maa_%=:\n\t"
        "add	r6, r6, #32\n\t"
        "add	r9, r9, #32\n\t"
        "add	lr, lr, #1\n\t"
        "cmp	lr, #13\n\t"
        "blt	L_mc_v256_i_maa_%=\n\t"
        "\n"
    "L_mc_v256_rs_maa_%=:\n\t"
        "mov	r5, #24\n\t"
        "lsl	r10, r5, #5\n\t"
        "add	r8, r12, r10\n\t"
        "\n"
    "L_mc_v256_rk_maa_%=:\n\t"
        "vld1.8	{d12-d15}, [r8]\n\t"
        "sub	r6, r5, #9\n\t"
        "lsl	r6, r6, #5\n\t"
        "add	r9, r12, r6\n\t"
        "vld1.8	{d16-d19}, [r9]\n\t"
        "veor	q8, q8, q6\n\t"
        "veor	q9, q9, q7\n\t"
        "vst1.8	{d16-d19}, [r9]\n\t"
        "sub	r6, r5, #10\n\t"
        "lsl	r6, r6, #5\n\t"
        "add	r9, r12, r6\n\t"
        "vld1.8	{d16-d19}, [r9]\n\t"
        "veor	q8, q8, q6\n\t"
        "veor	q9, q9, q7\n\t"
        "vst1.8	{d16-d19}, [r9]\n\t"
        "sub	r6, r5, #12\n\t"
        "lsl	r6, r6, #5\n\t"
        "add	r9, r12, r6\n\t"
        "vld1.8	{d16-d19}, [r9]\n\t"
        "veor	q8, q8, q6\n\t"
        "veor	q9, q9, q7\n\t"
        "vst1.8	{d16-d19}, [r9]\n\t"
        "sub	r6, r5, #13\n\t"
        "lsl	r6, r6, #5\n\t"
        "add	r9, r12, r6\n\t"
        "vld1.8	{d16-d19}, [r9]\n\t"
        "veor	q8, q8, q6\n\t"
        "veor	q9, q9, q7\n\t"
        "vst1.8	{d16-d19}, [r9]\n\t"
        "sub	r8, r8, #32\n\t"
        "sub	r5, r5, #1\n\t"
        "cmp	r5, #13\n\t"
        "bge	L_mc_v256_rk_maa_%=\n\t"
        "\n"
    "L_mc_v256_copy_maa_%=:\n\t"
        "mov	r5, #0\n\t"
        "mov	r8, r12\n\t"
        "mov	r9, %[p]\n\t"
        "\n"
    "L_mc_v256_cp_maa_%=:\n\t"
        "vld1.8	{d12-d15}, [r8]\n\t"
        "add	r8, r8, #32\n\t"
        "vst1.8	{d12-d15}, [r9]\n\t"
        "add	r9, r9, #32\n\t"
        "add	r5, r5, #1\n\t"
        "cmp	r5, #13\n\t"
        "blt	L_mc_v256_cp_maa_%=\n\t"
        "\n"
    "L_mc_v256_done_maa_%=:\n\t"
        "mov	lr, #0\n\t"
        "\n"
    "L_mc_xor13_k_maaa_%=:\n\t"
        "lsl	r4, lr, #5\n\t"
        "add	r6, %[a], r4\n\t"
        "vld1.8	{d0-d3}, [r6]\n\t"
        "add	r7, %[p], r4\n\t"
        "vld1.8	{d4-d7}, [r7]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, %[a], r4\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	lr, lr, #1\n\t"
        "cmp	lr, #13\n\t"
        "blt	L_mc_xor13_k_maaa_%=\n\t"
        "mov	lr, #0\n\t"
        "\n"
    "L_mc_xor13_k_maab_%=:\n\t"
        "lsl	r4, lr, #5\n\t"
        "add	r6, %[b], r4\n\t"
        "vld1.8	{d0-d3}, [r6]\n\t"
        "add	r7, %[a], r4\n\t"
        "vld1.8	{d4-d7}, [r7]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, %[b], r4\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	lr, lr, #1\n\t"
        "cmp	lr, #13\n\t"
        "blt	L_mc_xor13_k_maab_%=\n\t"
        "pop	{%[cscr]}\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [a] "+r" (a), [b] "+r" (b), [c] "+r" (c), [p] "+r" (p),
          [cscr] "+r" (cscr)
        :
#else
        :
        : [a] "r" (a), [b] "r" (b), [c] "r" (c), [p] "r" (p), [cscr] "r" (cscr)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "lr", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "q0",
            "q1", "q2", "q3", "q4", "q5", "q6", "q7", "q8", "q9", "q10"
    );
}

WOLFSSL_LOCAL void wc_mceliece_aff_ama_neon(word64* a, word64* b,
    const word64* c, word64* p, word64* cscr);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_aff_ama_neon(word64* a_p, word64* b_p,
    const word64* c_p, word64* p_p, word64* cscr_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_aff_ama_neon(word64* a, word64* b,
    const word64* c, word64* p, word64* cscr)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word64* a __asm__ ("r0") = (word64*)a_p;
    register word64* b __asm__ ("r1") = (word64*)b_p;
    register const word64* c __asm__ ("r2") = (const word64*)c_p;
    register word64* p __asm__ ("r3") = (word64*)p_p;
    register word64* cscr __asm__ ("r12") = (word64*)cscr_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "push	{%[cscr]}\n\t"
        "ldr	r12, [sp]\n\t"
        "mov	lr, #0\n\t"
        "\n"
    "L_mc_xor13_k_amaa_%=:\n\t"
        "lsl	r4, lr, #5\n\t"
        "add	r6, %[a], r4\n\t"
        "vld1.8	{d0-d3}, [r6]\n\t"
        "add	r7, %[b], r4\n\t"
        "vld1.8	{d4-d7}, [r7]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, %[a], r4\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	lr, lr, #1\n\t"
        "cmp	lr, #13\n\t"
        "blt	L_mc_xor13_k_amaa_%=\n\t"
        "veor	q10, q10, q10\n\t"
        "mov	r8, r12\n\t"
        "mov	r5, #0\n\t"
        "\n"
    "L_mc_v256_z_amam_%=:\n\t"
        "vst1.8	{d20-d21}, [r8]\n\t"
        "add	r8, r8, #16\n\t"
        "vst1.8	{d20-d21}, [r8]\n\t"
        "add	r8, r8, #16\n\t"
        "add	r5, r5, #1\n\t"
        "cmp	r5, #25\n\t"
        "blt	L_mc_v256_z_amam_%=\n\t"
        "mov	lr, #0\n\t"
        "mov	r6, %[a]\n\t"
        "mov	r9, r12\n\t"
        "\n"
    "L_mc_v256_i_amam_%=:\n\t"
        "vld1.8	{d0-d3}, [r6]\n\t"
        "mov	r7, %[c]\n\t"
        "mov	r8, r9\n\t"
        "mov	r4, #0\n\t"
        "\n"
    "L_mc_v256_j_amam_%=:\n\t"
        "vld1.8	{d4-d7}, [r7]\n\t"
        "vld1.8	{d12-d15}, [r8]\n\t"
        "add	r7, r7, #32\n\t"
        "vand	q4, q0, q2\n\t"
        "vand	q5, q1, q3\n\t"
        "veor	q6, q6, q4\n\t"
        "veor	q7, q7, q5\n\t"
        "vst1.8	{d12-d15}, [r8]\n\t"
        "add	r8, r8, #32\n\t"
        "add	r4, r4, #1\n\t"
        "cmp	r4, #13\n\t"
        "blt	L_mc_v256_j_amam_%=\n\t"
        "\n"
    "L_mc_v256_in_amam_%=:\n\t"
        "add	r6, r6, #32\n\t"
        "add	r9, r9, #32\n\t"
        "add	lr, lr, #1\n\t"
        "cmp	lr, #13\n\t"
        "blt	L_mc_v256_i_amam_%=\n\t"
        "\n"
    "L_mc_v256_rs_amam_%=:\n\t"
        "mov	r5, #24\n\t"
        "lsl	r10, r5, #5\n\t"
        "add	r8, r12, r10\n\t"
        "\n"
    "L_mc_v256_rk_amam_%=:\n\t"
        "vld1.8	{d12-d15}, [r8]\n\t"
        "sub	r6, r5, #9\n\t"
        "lsl	r6, r6, #5\n\t"
        "add	r9, r12, r6\n\t"
        "vld1.8	{d16-d19}, [r9]\n\t"
        "veor	q8, q8, q6\n\t"
        "veor	q9, q9, q7\n\t"
        "vst1.8	{d16-d19}, [r9]\n\t"
        "sub	r6, r5, #10\n\t"
        "lsl	r6, r6, #5\n\t"
        "add	r9, r12, r6\n\t"
        "vld1.8	{d16-d19}, [r9]\n\t"
        "veor	q8, q8, q6\n\t"
        "veor	q9, q9, q7\n\t"
        "vst1.8	{d16-d19}, [r9]\n\t"
        "sub	r6, r5, #12\n\t"
        "lsl	r6, r6, #5\n\t"
        "add	r9, r12, r6\n\t"
        "vld1.8	{d16-d19}, [r9]\n\t"
        "veor	q8, q8, q6\n\t"
        "veor	q9, q9, q7\n\t"
        "vst1.8	{d16-d19}, [r9]\n\t"
        "sub	r6, r5, #13\n\t"
        "lsl	r6, r6, #5\n\t"
        "add	r9, r12, r6\n\t"
        "vld1.8	{d16-d19}, [r9]\n\t"
        "veor	q8, q8, q6\n\t"
        "veor	q9, q9, q7\n\t"
        "vst1.8	{d16-d19}, [r9]\n\t"
        "sub	r8, r8, #32\n\t"
        "sub	r5, r5, #1\n\t"
        "cmp	r5, #13\n\t"
        "bge	L_mc_v256_rk_amam_%=\n\t"
        "\n"
    "L_mc_v256_copy_amam_%=:\n\t"
        "mov	r5, #0\n\t"
        "mov	r8, r12\n\t"
        "mov	r9, %[p]\n\t"
        "\n"
    "L_mc_v256_cp_amam_%=:\n\t"
        "vld1.8	{d12-d15}, [r8]\n\t"
        "add	r8, r8, #32\n\t"
        "vst1.8	{d12-d15}, [r9]\n\t"
        "add	r9, r9, #32\n\t"
        "add	r5, r5, #1\n\t"
        "cmp	r5, #13\n\t"
        "blt	L_mc_v256_cp_amam_%=\n\t"
        "\n"
    "L_mc_v256_done_amam_%=:\n\t"
        "mov	lr, #0\n\t"
        "\n"
    "L_mc_xor13_k_amab_%=:\n\t"
        "lsl	r4, lr, #5\n\t"
        "add	r6, %[b], r4\n\t"
        "vld1.8	{d0-d3}, [r6]\n\t"
        "add	r7, %[p], r4\n\t"
        "vld1.8	{d4-d7}, [r7]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r5, %[b], r4\n\t"
        "vst1.8	{d0-d3}, [r5]\n\t"
        "add	lr, lr, #1\n\t"
        "cmp	lr, #13\n\t"
        "blt	L_mc_xor13_k_amab_%=\n\t"
        "pop	{%[cscr]}\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [a] "+r" (a), [b] "+r" (b), [c] "+r" (c), [p] "+r" (p),
          [cscr] "+r" (cscr)
        :
#else
        :
        : [a] "r" (a), [b] "r" (b), [c] "r" (c), [p] "r" (p), [cscr] "r" (cscr)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "lr", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "q0",
            "q1", "q2", "q3", "q4", "q5", "q6", "q7", "q8", "q9", "q10"
    );
}

WOLFSSL_LOCAL void wc_mceliece_fft_fwd_butterflies_neon(word64* out, word64* in,
    int monic, word64* scratch);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_fft_fwd_butterflies_neon(word64* out_p,
    word64* in_p, int monic_p, word64* scratch_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_fft_fwd_butterflies_neon(word64* out,
    word64* in, int monic, word64* scratch)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word64* out __asm__ ("r0") = (word64*)out_p;
    register word64* in __asm__ ("r1") = (word64*)in_p;
    register int monic __asm__ ("r2") = (int)monic_p;
    register word64* scratch __asm__ ("r3") = (word64*)scratch_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    register word64* L_mc_aff_consts_neon_c __asm__ ("r8") =
        (word64*)&L_mc_aff_consts_neon;
    register word64* L_mc_aff_powers_neon_c __asm__ ("r9") =
        (word64*)&L_mc_aff_powers_neon;
    register word8* L_mc_aff_reversal_neon_c __asm__ ("r10") =
        (word8*)&L_mc_aff_reversal_neon;
    __asm__ __volatile__ (
        "push	{%[L_mc_aff_reversal_neon]}\n\t"
        "push	{%[L_mc_aff_consts_neon], %[L_mc_aff_powers_neon]}\n\t"
        "sub	sp, sp, #4\n\t"
        "mov	r4, %[out]\n\t"
        "mov	r5, %[in]\n\t"
        "mov	r6, %[monic]\n\t"
        "mov	r7, %[scratch]\n\t"
        "b	L_mc_pool_1_%=\n\t"
        "\n"
    "L_mc_pool_1_%=:\n\t"
        "veor	q4, q4, q4\n\t"
        "add	%[out], r7, #0x1a0\n\t"
        "mov	%[in], #0\n\t"
        "\n"
    "L_mc_ffb_pz_%=:\n\t"
        "cmp	%[in], #0x700\n\t"
        "bge	L_mc_ffb_pze_%=\n\t"
        "add	%[monic], %[out], %[in]\n\t"
        "vst1.8	{d8-d9}, [%[monic]]\n\t"
        "add	%[in], %[in], #16\n\t"
        "b	L_mc_ffb_pz_%=\n\t"
        "\n"
    "L_mc_ffb_pze_%=:\n\t"
        "add	%[out], r5, #8\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "vmov	d9, d8\n\t"
        "add	%[in], r7, #0xd0\n\t"
        "vst1.8	{d8-d9}, [%[in]]\n\t"
        "add	%[out], r5, #24\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "vmov	d9, d8\n\t"
        "add	%[in], r7, #0xe0\n\t"
        "vst1.8	{d8-d9}, [%[in]]\n\t"
        "add	%[out], r5, #40\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "vmov	d9, d8\n\t"
        "add	%[in], r7, #0xf0\n\t"
        "vst1.8	{d8-d9}, [%[in]]\n\t"
        "add	%[out], r5, #56\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "vmov	d9, d8\n\t"
        "add	%[in], r7, #0x100\n\t"
        "vst1.8	{d8-d9}, [%[in]]\n\t"
        "add	%[out], r5, #0x48\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "vmov	d9, d8\n\t"
        "add	%[in], r7, #0x110\n\t"
        "vst1.8	{d8-d9}, [%[in]]\n\t"
        "add	%[out], r5, #0x58\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "vmov	d9, d8\n\t"
        "add	%[in], r7, #0x120\n\t"
        "vst1.8	{d8-d9}, [%[in]]\n\t"
        "add	%[out], r5, #0x68\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "vmov	d9, d8\n\t"
        "add	%[in], r7, #0x130\n\t"
        "vst1.8	{d8-d9}, [%[in]]\n\t"
        "add	%[out], r5, #0x78\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "vmov	d9, d8\n\t"
        "add	%[in], r7, #0x140\n\t"
        "vst1.8	{d8-d9}, [%[in]]\n\t"
        "add	%[out], r5, #0x88\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "vmov	d9, d8\n\t"
        "add	%[in], r7, #0x150\n\t"
        "vst1.8	{d8-d9}, [%[in]]\n\t"
        "add	%[out], r5, #0x98\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "vmov	d9, d8\n\t"
        "add	%[in], r7, #0x160\n\t"
        "vst1.8	{d8-d9}, [%[in]]\n\t"
        "add	%[out], r5, #0xa8\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "vmov	d9, d8\n\t"
        "add	%[in], r7, #0x170\n\t"
        "vst1.8	{d8-d9}, [%[in]]\n\t"
        "add	%[out], r5, #0xb8\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "vmov	d9, d8\n\t"
        "add	%[in], r7, #0x180\n\t"
        "vst1.8	{d8-d9}, [%[in]]\n\t"
        "add	%[out], r5, #0xc8\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "vmov	d9, d8\n\t"
        "add	%[in], r7, #0x190\n\t"
        "vst1.8	{d8-d9}, [%[in]]\n\t"
        "vmov.i8	q6, #0xff\n\t"
        "veor	q7, q7, q7\n\t"
        "add	%[out], r7, #0\n\t"
        "vst1.8	{d14}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], r7, #16\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], r7, #32\n\t"
        "vst1.8	{d14}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d14}, [%[out]]\n\t"
        "add	%[out], r7, #48\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d14}, [%[out]]\n\t"
        "add	%[out], r7, #0x40\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], r7, #0x50\n\t"
        "vst1.8	{d14}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d14}, [%[out]]\n\t"
        "add	%[out], r7, #0x60\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d14}, [%[out]]\n\t"
        "add	%[out], r7, #0x70\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], r7, #0x80\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d14}, [%[out]]\n\t"
        "add	%[out], r7, #0x90\n\t"
        "vst1.8	{d14}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], r7, #0xa0\n\t"
        "vst1.8	{d14}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], r7, #0xb0\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], r7, #0xc0\n\t"
        "vst1.8	{d14}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "mov	%[out], r7\n\t"
        "add	%[in], r7, #0xd0\n\t"
        "mov	%[monic], r7\n\t"
        "add	%[scratch], r7, #0x8a0\n\t"
        "bl	wc_mceliece_aff_v128_mul_neon\n\t"
        "add	%[out], r7, #0\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x1a0\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x280\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #16\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x1b0\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x290\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #32\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x1c0\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x2a0\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #48\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x1d0\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x2b0\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #0x40\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x1e0\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x2c0\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #0x50\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x1f0\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x2d0\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #0x60\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x200\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x2e0\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #0x70\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x210\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x2f0\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #0x80\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x220\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x300\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #0x90\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x230\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x310\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #0xa0\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x240\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x320\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #0xb0\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x250\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x330\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #0xc0\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x260\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x340\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #0\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], r7, #16\n\t"
        "vst1.8	{d14}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], r7, #32\n\t"
        "vst1.8	{d14}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d14}, [%[out]]\n\t"
        "add	%[out], r7, #48\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d14}, [%[out]]\n\t"
        "add	%[out], r7, #0x40\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d14}, [%[out]]\n\t"
        "add	%[out], r7, #0x50\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], r7, #0x60\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], r7, #0x70\n\t"
        "vst1.8	{d14}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d14}, [%[out]]\n\t"
        "add	%[out], r7, #0x80\n\t"
        "vst1.8	{d14}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], r7, #0x90\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], r7, #0xa0\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], r7, #0xb0\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], r7, #0xc0\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "mov	%[out], r7\n\t"
        "add	%[in], r7, #0xd0\n\t"
        "mov	%[monic], r7\n\t"
        "add	%[scratch], r7, #0x8a0\n\t"
        "bl	wc_mceliece_aff_v128_mul_neon\n\t"
        "add	%[out], r7, #0\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x360\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x440\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #16\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x370\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x450\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #32\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x380\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x460\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #48\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x390\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x470\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #0x40\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x3a0\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x480\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #0x50\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x3b0\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x490\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #0x60\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x3c0\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x4a0\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #0x70\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x3d0\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x4b0\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #0x80\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x3e0\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x4c0\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #0x90\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x3f0\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x4d0\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #0xa0\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x400\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x4e0\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #0xb0\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x410\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x4f0\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #0xc0\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x420\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x500\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #0\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], r7, #16\n\t"
        "vst1.8	{d14}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], r7, #32\n\t"
        "vst1.8	{d14}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], r7, #48\n\t"
        "vst1.8	{d14}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d14}, [%[out]]\n\t"
        "add	%[out], r7, #0x40\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d14}, [%[out]]\n\t"
        "add	%[out], r7, #0x50\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], r7, #0x60\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], r7, #0x70\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], r7, #0x80\n\t"
        "vst1.8	{d14}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], r7, #0x90\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], r7, #0xa0\n\t"
        "vst1.8	{d14}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], r7, #0xb0\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], r7, #0xc0\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "mov	%[out], r7\n\t"
        "add	%[in], r7, #0xd0\n\t"
        "mov	%[monic], r7\n\t"
        "add	%[scratch], r7, #0x8a0\n\t"
        "bl	wc_mceliece_aff_v128_mul_neon\n\t"
        "add	%[out], r7, #0\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x520\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x600\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #16\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x530\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x610\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #32\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x540\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x620\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #48\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x550\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x630\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #0x40\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x560\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x640\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #0x50\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x570\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x650\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #0x60\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x580\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x660\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #0x70\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x590\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x670\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #0x80\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x5a0\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x680\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #0x90\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x5b0\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x690\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #0xa0\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x5c0\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x6a0\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #0xb0\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x5d0\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x6b0\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #0xc0\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x5e0\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x6c0\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #0\n\t"
        "vst1.8	{d14}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d14}, [%[out]]\n\t"
        "add	%[out], r7, #16\n\t"
        "vst1.8	{d14}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d14}, [%[out]]\n\t"
        "add	%[out], r7, #32\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d14}, [%[out]]\n\t"
        "add	%[out], r7, #48\n\t"
        "vst1.8	{d14}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d14}, [%[out]]\n\t"
        "add	%[out], r7, #0x40\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d14}, [%[out]]\n\t"
        "add	%[out], r7, #0x50\n\t"
        "vst1.8	{d14}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d14}, [%[out]]\n\t"
        "add	%[out], r7, #0x60\n\t"
        "vst1.8	{d14}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d14}, [%[out]]\n\t"
        "add	%[out], r7, #0x70\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d14}, [%[out]]\n\t"
        "add	%[out], r7, #0x80\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d14}, [%[out]]\n\t"
        "add	%[out], r7, #0x90\n\t"
        "vst1.8	{d14}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d14}, [%[out]]\n\t"
        "add	%[out], r7, #0xa0\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d14}, [%[out]]\n\t"
        "add	%[out], r7, #0xb0\n\t"
        "vst1.8	{d12}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d14}, [%[out]]\n\t"
        "add	%[out], r7, #0xc0\n\t"
        "vst1.8	{d14}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d14}, [%[out]]\n\t"
        "mov	%[out], r7\n\t"
        "add	%[in], r7, #0xd0\n\t"
        "mov	%[monic], r7\n\t"
        "add	%[scratch], r7, #0x8a0\n\t"
        "bl	wc_mceliece_aff_v128_mul_neon\n\t"
        "add	%[out], r7, #0\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x6e0\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x7c0\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #16\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x6f0\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x7d0\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #32\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x700\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x7e0\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #48\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x710\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x7f0\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #0x40\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x720\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x800\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #0x50\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x730\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x810\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #0x60\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x740\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x820\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #0x70\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x750\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x830\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #0x80\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x760\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x840\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #0x90\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x770\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x850\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #0xa0\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x780\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x860\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #0xb0\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x790\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x870\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "add	%[out], r7, #0xc0\n\t"
        "vld1.8	{d8}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d9}, [%[out]]\n\t"
        "vmov	d10, d8\n\t"
        "vmov	d11, d8\n\t"
        "add	%[in], r7, #0x7a0\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "vmov	d10, d9\n\t"
        "vmov	d11, d9\n\t"
        "add	%[in], r7, #0x880\n\t"
        "vst1.8	{d10-d11}, [%[in]]\n\t"
        "mov	r11, #0\n\t"
        "\n"
    "L_mc_ffb_i_%=:\n\t"
        "cmp	r11, #13\n\t"
        "bge	L_mc_ffb_ie_%=\n\t"
        "lsl	%[out], r11, #4\n\t"
        "add	%[in], r5, %[out]\n\t"
        "add	%[monic], r7, #0x8a0\n\t"
        "vld1.8	{d8}, [%[in]]\n\t"
        "vst1.8	{d8}, [%[monic]]\n\t"
        "add	%[scratch], r7, #0x6e0\n\t"
        "add	%[scratch], %[scratch], %[out]\n\t"
        "vld1.8	{d9}, [%[scratch]]\n\t"
        "veor	d10, d8, d9\n\t"
        "add	r12, %[monic], #8\n\t"
        "vst1.8	{d10}, [r12]\n\t"
        "cmp	r11, #12\n\t"
        "beq	L_mc_ffb_hi_%=\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d8}, [r12]\n\t"
        "add	r12, %[monic], #16\n\t"
        "vst1.8	{d8}, [r12]\n\t"
        "add	r12, %[scratch], #16\n\t"
        "vld1.8	{d9}, [r12]\n\t"
        "veor	d10, d8, d9\n\t"
        "add	r12, %[monic], #24\n\t"
        "vst1.8	{d10}, [r12]\n\t"
        "\n"
    "L_mc_ffb_hi_%=:\n\t"
        "lsr	%[out], r11, #1\n\t"
        "lsl	%[out], %[out], #5\n\t"
        "add	%[scratch], r7, %[out]\n\t"
        "add	%[scratch], %[scratch], #0x1a0\n\t"
        "vld1.8	{d0-d3}, [%[monic]]\n\t"
        "vld1.8	{d4-d7}, [%[scratch]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #32\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "vld1.8	{d0-d3}, [%[monic]]\n\t"
        "add	%[in], %[scratch], #0x380\n\t"
        "vld1.8	{d4-d7}, [%[in]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x200\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #32\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "add	%[in], %[scratch], #0xe0\n\t"
        "vld1.8	{d4-d7}, [%[in]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x60\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x200\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "add	%[in], %[scratch], #0x460\n\t"
        "vld1.8	{d4-d7}, [%[in]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x600\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x600\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "vld1.8	{d4-d7}, [%[scratch]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x620\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "vld1.8	{d0-d3}, [%[monic]]\n\t"
        "add	%[in], %[scratch], #0xe0\n\t"
        "vld1.8	{d4-d7}, [%[in]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x40\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x620\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "add	%[in], %[scratch], #0xe0\n\t"
        "vld1.8	{d4-d7}, [%[in]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x660\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x40\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "add	%[in], %[scratch], #0x1c0\n\t"
        "vld1.8	{d4-d7}, [%[in]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0xc0\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x660\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "vld1.8	{d4-d7}, [%[scratch]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x640\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0xc0\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "vld1.8	{d4-d7}, [%[scratch]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0xe0\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x640\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "add	%[in], %[scratch], #0x1c0\n\t"
        "vld1.8	{d4-d7}, [%[in]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x6c0\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0xe0\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "add	%[in], %[scratch], #0xe0\n\t"
        "vld1.8	{d4-d7}, [%[in]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0xa0\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x6c0\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "vld1.8	{d4-d7}, [%[scratch]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x6e0\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x6e0\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "add	%[in], %[scratch], #0xe0\n\t"
        "vld1.8	{d4-d7}, [%[in]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x6a0\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "vld1.8	{d0-d3}, [%[monic]]\n\t"
        "add	%[in], %[scratch], #0x1c0\n\t"
        "vld1.8	{d4-d7}, [%[in]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x80\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x6a0\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "vld1.8	{d4-d7}, [%[scratch]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x680\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x80\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "add	%[in], %[scratch], #0x2a0\n\t"
        "vld1.8	{d4-d7}, [%[in]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x180\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x680\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "add	%[in], %[scratch], #0x2a0\n\t"
        "vld1.8	{d4-d7}, [%[in]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x780\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x180\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "vld1.8	{d4-d7}, [%[scratch]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x1a0\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x780\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "vld1.8	{d4-d7}, [%[scratch]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x7a0\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x1a0\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "add	%[in], %[scratch], #0xe0\n\t"
        "vld1.8	{d4-d7}, [%[in]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x1e0\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x7a0\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "add	%[in], %[scratch], #0xe0\n\t"
        "vld1.8	{d4-d7}, [%[in]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x7e0\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x1e0\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "vld1.8	{d4-d7}, [%[scratch]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x1c0\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x7e0\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "vld1.8	{d4-d7}, [%[scratch]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x7c0\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x1c0\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "add	%[in], %[scratch], #0x1c0\n\t"
        "vld1.8	{d4-d7}, [%[in]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x140\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x7c0\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "add	%[in], %[scratch], #0x1c0\n\t"
        "vld1.8	{d4-d7}, [%[in]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x740\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x140\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "vld1.8	{d4-d7}, [%[scratch]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x160\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x740\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "vld1.8	{d4-d7}, [%[scratch]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x760\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x160\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "add	%[in], %[scratch], #0xe0\n\t"
        "vld1.8	{d4-d7}, [%[in]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x120\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x760\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "add	%[in], %[scratch], #0xe0\n\t"
        "vld1.8	{d4-d7}, [%[in]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x720\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x720\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "vld1.8	{d4-d7}, [%[scratch]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x700\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "vld1.8	{d0-d3}, [%[monic]]\n\t"
        "add	%[in], %[scratch], #0x2a0\n\t"
        "vld1.8	{d4-d7}, [%[in]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x100\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x700\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "add	%[in], %[scratch], #0x380\n\t"
        "vld1.8	{d4-d7}, [%[in]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x500\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x100\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "add	%[in], %[scratch], #0x380\n\t"
        "vld1.8	{d4-d7}, [%[in]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x300\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x500\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "vld1.8	{d4-d7}, [%[scratch]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x520\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x300\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "vld1.8	{d4-d7}, [%[scratch]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x320\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x520\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "add	%[in], %[scratch], #0xe0\n\t"
        "vld1.8	{d4-d7}, [%[in]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x560\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x320\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "add	%[in], %[scratch], #0xe0\n\t"
        "vld1.8	{d4-d7}, [%[in]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x360\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x560\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "vld1.8	{d4-d7}, [%[scratch]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x540\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x360\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "vld1.8	{d4-d7}, [%[scratch]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x340\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x540\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "add	%[in], %[scratch], #0x1c0\n\t"
        "vld1.8	{d4-d7}, [%[in]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x5c0\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x340\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "add	%[in], %[scratch], #0x1c0\n\t"
        "vld1.8	{d4-d7}, [%[in]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x3c0\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x5c0\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "vld1.8	{d4-d7}, [%[scratch]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x5e0\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x3c0\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "vld1.8	{d4-d7}, [%[scratch]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x3e0\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x5e0\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "add	%[in], %[scratch], #0xe0\n\t"
        "vld1.8	{d4-d7}, [%[in]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x5a0\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x3e0\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "add	%[in], %[scratch], #0xe0\n\t"
        "vld1.8	{d4-d7}, [%[in]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x3a0\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x5a0\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "vld1.8	{d4-d7}, [%[scratch]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x580\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x3a0\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "vld1.8	{d4-d7}, [%[scratch]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x380\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x580\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "add	%[in], %[scratch], #0x2a0\n\t"
        "vld1.8	{d4-d7}, [%[in]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x480\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x380\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "add	%[in], %[scratch], #0x2a0\n\t"
        "vld1.8	{d4-d7}, [%[in]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x280\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x480\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "vld1.8	{d4-d7}, [%[scratch]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x4a0\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x280\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "vld1.8	{d4-d7}, [%[scratch]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x2a0\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x4a0\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "add	%[in], %[scratch], #0xe0\n\t"
        "vld1.8	{d4-d7}, [%[in]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x4e0\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x2a0\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "add	%[in], %[scratch], #0xe0\n\t"
        "vld1.8	{d4-d7}, [%[in]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x2e0\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x4e0\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "vld1.8	{d4-d7}, [%[scratch]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x4c0\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x2e0\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "vld1.8	{d4-d7}, [%[scratch]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x2c0\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x4c0\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "add	%[in], %[scratch], #0x1c0\n\t"
        "vld1.8	{d4-d7}, [%[in]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x440\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x2c0\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "add	%[in], %[scratch], #0x1c0\n\t"
        "vld1.8	{d4-d7}, [%[in]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x240\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x440\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "vld1.8	{d4-d7}, [%[scratch]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x460\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x240\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "vld1.8	{d4-d7}, [%[scratch]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x260\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x460\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "add	%[in], %[scratch], #0xe0\n\t"
        "vld1.8	{d4-d7}, [%[in]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x420\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x260\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "add	%[in], %[scratch], #0xe0\n\t"
        "vld1.8	{d4-d7}, [%[in]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x220\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], %[monic], #0x420\n\t"
        "vld1.8	{d0-d3}, [%[out]]\n\t"
        "vld1.8	{d4-d7}, [%[scratch]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "add	r12, %[monic], #0x400\n\t"
        "vst1.8	{d0-d3}, [r12]\n\t"
        "add	%[out], r7, #0x8a0\n\t"
        "bl	wc_mceliece_aff_transpose_neon\n\t"
        "mov	%[out], r4\n\t"
        "add	%[in], r7, #0x8a0\n\t"
        "mov	%[monic], r11\n\t"
        "bl	wc_mceliece_aff_fwd_out_neon\n\t"
        "add	r11, r11, #2\n\t"
        "b	L_mc_ffb_i_%=\n\t"
        "\n"
    "L_mc_ffb_ie_%=:\n\t"
        "mov	r11, #0\n\t"
        "\n"
    "L_mc_ffb_pk_%=:\n\t"
        "cmp	r11, #32\n\t"
        "bge	L_mc_ffb_pke_%=\n\t"
        "add	%[out], r7, #0x8a0\n\t"
        "add	%[in], r7, #0xa40\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r12, #0xa0\n\t"
        "orr	r12, r12, #0x100\n\t"
#else
        "mov	r12, #0x1a0\n\t"
#endif
        "mul	%[monic], r11, r12\n\t"
        "add	%[monic], r4, %[monic]\n\t"
        "add	%[scratch], %[monic], #0x1a0\n\t"
        "bl	wc_mceliece_aff_pack_lh_neon\n\t"
        "add	%[out], r7, #0x8a0\n\t"
        "add	%[in], r7, #0xa40\n\t"
        "add	%[monic], %[L_mc_aff_consts_neon], #0x1a0\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r12, #0xa0\n\t"
        "orr	r12, r12, #0x100\n\t"
#else
        "mov	r12, #0x1a0\n\t"
#endif
        "mul	%[out], r11, r12\n\t"
        "add	%[out], r4, %[out]\n\t"
        "add	%[in], %[out], #0x1a0\n\t"
        "add	%[monic], r7, #0x8a0\n\t"
        "add	%[scratch], r7, #0xa40\n\t"
        "bl	wc_mceliece_aff_pack_lh_neon\n\t"
        "add	r11, r11, #2\n\t"
        "b	L_mc_ffb_pk_%=\n\t"
        "\n"
    "L_mc_ffb_pke_%=:\n\t"
        "mov	%[out], #0\n\t"
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xa0\n\t"
        "orr	%[in], %[in], #0x100\n\t"
#else
        "mov	%[in], #0x1a0\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0x40\n\t"
        "orr	%[monic], %[monic], #0x300\n\t"
#else
        "mov	%[monic], #0x340\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x40\n\t"
        "orr	%[out], %[out], #0x300\n\t"
#else
        "mov	%[out], #0x340\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xe0\n\t"
        "orr	%[in], %[in], #0x400\n\t"
#else
        "mov	%[in], #0x4e0\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0x40\n\t"
        "orr	%[monic], %[monic], #0x300\n\t"
#else
        "mov	%[monic], #0x340\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x80\n\t"
        "orr	%[out], %[out], #0x600\n\t"
#else
        "mov	%[out], #0x680\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x20\n\t"
        "orr	%[in], %[in], #0x800\n\t"
#else
        "mov	%[in], #0x820\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0x40\n\t"
        "orr	%[monic], %[monic], #0x300\n\t"
#else
        "mov	%[monic], #0x340\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xc0\n\t"
        "orr	%[out], %[out], #0x900\n\t"
#else
        "mov	%[out], #0x9c0\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x60\n\t"
        "orr	%[in], %[in], #0xb00\n\t"
#else
        "mov	%[in], #0xb60\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0x40\n\t"
        "orr	%[monic], %[monic], #0x300\n\t"
#else
        "mov	%[monic], #0x340\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
        "mov	%[out], #0xd00\n\t"
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xa0\n\t"
        "orr	%[in], %[in], #0xe00\n\t"
#else
        "mov	%[in], #0xea0\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0x40\n\t"
        "orr	%[monic], %[monic], #0x300\n\t"
#else
        "mov	%[monic], #0x340\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x40\n\t"
        "orr	%[out], %[out], #0x1000\n\t"
#else
        "mov	%[out], #0x1040\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xe0\n\t"
        "orr	%[in], %[in], #0x1100\n\t"
#else
        "mov	%[in], #0x11e0\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0x40\n\t"
        "orr	%[monic], %[monic], #0x300\n\t"
#else
        "mov	%[monic], #0x340\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x80\n\t"
        "orr	%[out], %[out], #0x1300\n\t"
#else
        "mov	%[out], #0x1380\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x20\n\t"
        "orr	%[in], %[in], #0x1500\n\t"
#else
        "mov	%[in], #0x1520\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0x40\n\t"
        "orr	%[monic], %[monic], #0x300\n\t"
#else
        "mov	%[monic], #0x340\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xc0\n\t"
        "orr	%[out], %[out], #0x1600\n\t"
#else
        "mov	%[out], #0x16c0\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x60\n\t"
        "orr	%[in], %[in], #0x1800\n\t"
#else
        "mov	%[in], #0x1860\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0x40\n\t"
        "orr	%[monic], %[monic], #0x300\n\t"
#else
        "mov	%[monic], #0x340\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
        "mov	%[out], #0x1a00\n\t"
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xa0\n\t"
        "orr	%[in], %[in], #0x1b00\n\t"
#else
        "mov	%[in], #0x1ba0\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0x40\n\t"
        "orr	%[monic], %[monic], #0x300\n\t"
#else
        "mov	%[monic], #0x340\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x40\n\t"
        "orr	%[out], %[out], #0x1d00\n\t"
#else
        "mov	%[out], #0x1d40\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xe0\n\t"
        "orr	%[in], %[in], #0x1e00\n\t"
#else
        "mov	%[in], #0x1ee0\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0x40\n\t"
        "orr	%[monic], %[monic], #0x300\n\t"
#else
        "mov	%[monic], #0x340\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x80\n\t"
        "orr	%[out], %[out], #0x2000\n\t"
#else
        "mov	%[out], #0x2080\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x20\n\t"
        "orr	%[in], %[in], #0x2200\n\t"
#else
        "mov	%[in], #0x2220\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0x40\n\t"
        "orr	%[monic], %[monic], #0x300\n\t"
#else
        "mov	%[monic], #0x340\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xc0\n\t"
        "orr	%[out], %[out], #0x2300\n\t"
#else
        "mov	%[out], #0x23c0\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x60\n\t"
        "orr	%[in], %[in], #0x2500\n\t"
#else
        "mov	%[in], #0x2560\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0x40\n\t"
        "orr	%[monic], %[monic], #0x300\n\t"
#else
        "mov	%[monic], #0x340\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
        "mov	%[out], #0x2700\n\t"
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xa0\n\t"
        "orr	%[in], %[in], #0x2800\n\t"
#else
        "mov	%[in], #0x28a0\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0x40\n\t"
        "orr	%[monic], %[monic], #0x300\n\t"
#else
        "mov	%[monic], #0x340\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x40\n\t"
        "orr	%[out], %[out], #0x2a00\n\t"
#else
        "mov	%[out], #0x2a40\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xe0\n\t"
        "orr	%[in], %[in], #0x2b00\n\t"
#else
        "mov	%[in], #0x2be0\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0x40\n\t"
        "orr	%[monic], %[monic], #0x300\n\t"
#else
        "mov	%[monic], #0x340\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x80\n\t"
        "orr	%[out], %[out], #0x2d00\n\t"
#else
        "mov	%[out], #0x2d80\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x20\n\t"
        "orr	%[in], %[in], #0x2f00\n\t"
#else
        "mov	%[in], #0x2f20\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0x40\n\t"
        "orr	%[monic], %[monic], #0x300\n\t"
#else
        "mov	%[monic], #0x340\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xc0\n\t"
        "orr	%[out], %[out], #0x3000\n\t"
#else
        "mov	%[out], #0x30c0\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x60\n\t"
        "orr	%[in], %[in], #0x3200\n\t"
#else
        "mov	%[in], #0x3260\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0x40\n\t"
        "orr	%[monic], %[monic], #0x300\n\t"
#else
        "mov	%[monic], #0x340\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
        "mov	%[out], #0\n\t"
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x40\n\t"
        "orr	%[in], %[in], #0x300\n\t"
#else
        "mov	%[in], #0x340\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0xe0\n\t"
        "orr	%[monic], %[monic], #0x400\n\t"
#else
        "mov	%[monic], #0x4e0\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xa0\n\t"
        "orr	%[out], %[out], #0x100\n\t"
#else
        "mov	%[out], #0x1a0\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xe0\n\t"
        "orr	%[in], %[in], #0x400\n\t"
#else
        "mov	%[in], #0x4e0\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0x80\n\t"
        "orr	%[monic], %[monic], #0x600\n\t"
#else
        "mov	%[monic], #0x680\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x80\n\t"
        "orr	%[out], %[out], #0x600\n\t"
#else
        "mov	%[out], #0x680\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xc0\n\t"
        "orr	%[in], %[in], #0x900\n\t"
#else
        "mov	%[in], #0x9c0\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0xe0\n\t"
        "orr	%[monic], %[monic], #0x400\n\t"
#else
        "mov	%[monic], #0x4e0\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x20\n\t"
        "orr	%[out], %[out], #0x800\n\t"
#else
        "mov	%[out], #0x820\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x60\n\t"
        "orr	%[in], %[in], #0xb00\n\t"
#else
        "mov	%[in], #0xb60\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0x80\n\t"
        "orr	%[monic], %[monic], #0x600\n\t"
#else
        "mov	%[monic], #0x680\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
        "mov	%[out], #0xd00\n\t"
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x40\n\t"
        "orr	%[in], %[in], #0x1000\n\t"
#else
        "mov	%[in], #0x1040\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0xe0\n\t"
        "orr	%[monic], %[monic], #0x400\n\t"
#else
        "mov	%[monic], #0x4e0\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xa0\n\t"
        "orr	%[out], %[out], #0xe00\n\t"
#else
        "mov	%[out], #0xea0\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xe0\n\t"
        "orr	%[in], %[in], #0x1100\n\t"
#else
        "mov	%[in], #0x11e0\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0x80\n\t"
        "orr	%[monic], %[monic], #0x600\n\t"
#else
        "mov	%[monic], #0x680\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x80\n\t"
        "orr	%[out], %[out], #0x1300\n\t"
#else
        "mov	%[out], #0x1380\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xc0\n\t"
        "orr	%[in], %[in], #0x1600\n\t"
#else
        "mov	%[in], #0x16c0\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0xe0\n\t"
        "orr	%[monic], %[monic], #0x400\n\t"
#else
        "mov	%[monic], #0x4e0\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x20\n\t"
        "orr	%[out], %[out], #0x1500\n\t"
#else
        "mov	%[out], #0x1520\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x60\n\t"
        "orr	%[in], %[in], #0x1800\n\t"
#else
        "mov	%[in], #0x1860\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0x80\n\t"
        "orr	%[monic], %[monic], #0x600\n\t"
#else
        "mov	%[monic], #0x680\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
        "mov	%[out], #0x1a00\n\t"
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x40\n\t"
        "orr	%[in], %[in], #0x1d00\n\t"
#else
        "mov	%[in], #0x1d40\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0xe0\n\t"
        "orr	%[monic], %[monic], #0x400\n\t"
#else
        "mov	%[monic], #0x4e0\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xa0\n\t"
        "orr	%[out], %[out], #0x1b00\n\t"
#else
        "mov	%[out], #0x1ba0\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xe0\n\t"
        "orr	%[in], %[in], #0x1e00\n\t"
#else
        "mov	%[in], #0x1ee0\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0x80\n\t"
        "orr	%[monic], %[monic], #0x600\n\t"
#else
        "mov	%[monic], #0x680\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x80\n\t"
        "orr	%[out], %[out], #0x2000\n\t"
#else
        "mov	%[out], #0x2080\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xc0\n\t"
        "orr	%[in], %[in], #0x2300\n\t"
#else
        "mov	%[in], #0x23c0\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0xe0\n\t"
        "orr	%[monic], %[monic], #0x400\n\t"
#else
        "mov	%[monic], #0x4e0\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x20\n\t"
        "orr	%[out], %[out], #0x2200\n\t"
#else
        "mov	%[out], #0x2220\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x60\n\t"
        "orr	%[in], %[in], #0x2500\n\t"
#else
        "mov	%[in], #0x2560\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0x80\n\t"
        "orr	%[monic], %[monic], #0x600\n\t"
#else
        "mov	%[monic], #0x680\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
        "mov	%[out], #0x2700\n\t"
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x40\n\t"
        "orr	%[in], %[in], #0x2a00\n\t"
#else
        "mov	%[in], #0x2a40\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0xe0\n\t"
        "orr	%[monic], %[monic], #0x400\n\t"
#else
        "mov	%[monic], #0x4e0\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xa0\n\t"
        "orr	%[out], %[out], #0x2800\n\t"
#else
        "mov	%[out], #0x28a0\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xe0\n\t"
        "orr	%[in], %[in], #0x2b00\n\t"
#else
        "mov	%[in], #0x2be0\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0x80\n\t"
        "orr	%[monic], %[monic], #0x600\n\t"
#else
        "mov	%[monic], #0x680\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x80\n\t"
        "orr	%[out], %[out], #0x2d00\n\t"
#else
        "mov	%[out], #0x2d80\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xc0\n\t"
        "orr	%[in], %[in], #0x3000\n\t"
#else
        "mov	%[in], #0x30c0\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0xe0\n\t"
        "orr	%[monic], %[monic], #0x400\n\t"
#else
        "mov	%[monic], #0x4e0\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x20\n\t"
        "orr	%[out], %[out], #0x2f00\n\t"
#else
        "mov	%[out], #0x2f20\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x60\n\t"
        "orr	%[in], %[in], #0x3200\n\t"
#else
        "mov	%[in], #0x3260\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0x80\n\t"
        "orr	%[monic], %[monic], #0x600\n\t"
#else
        "mov	%[monic], #0x680\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
        "mov	%[out], #0\n\t"
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x80\n\t"
        "orr	%[in], %[in], #0x600\n\t"
#else
        "mov	%[in], #0x680\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0x20\n\t"
        "orr	%[monic], %[monic], #0x800\n\t"
#else
        "mov	%[monic], #0x820\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xa0\n\t"
        "orr	%[out], %[out], #0x100\n\t"
#else
        "mov	%[out], #0x1a0\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x20\n\t"
        "orr	%[in], %[in], #0x800\n\t"
#else
        "mov	%[in], #0x820\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0xc0\n\t"
        "orr	%[monic], %[monic], #0x900\n\t"
#else
        "mov	%[monic], #0x9c0\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x40\n\t"
        "orr	%[out], %[out], #0x300\n\t"
#else
        "mov	%[out], #0x340\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xc0\n\t"
        "orr	%[in], %[in], #0x900\n\t"
#else
        "mov	%[in], #0x9c0\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0x60\n\t"
        "orr	%[monic], %[monic], #0xb00\n\t"
#else
        "mov	%[monic], #0xb60\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xe0\n\t"
        "orr	%[out], %[out], #0x400\n\t"
#else
        "mov	%[out], #0x4e0\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x60\n\t"
        "orr	%[in], %[in], #0xb00\n\t"
#else
        "mov	%[in], #0xb60\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
        "mov	%[monic], #0xd00\n\t"
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
        "mov	%[out], #0xd00\n\t"
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x80\n\t"
        "orr	%[in], %[in], #0x1300\n\t"
#else
        "mov	%[in], #0x1380\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0x20\n\t"
        "orr	%[monic], %[monic], #0x800\n\t"
#else
        "mov	%[monic], #0x820\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xa0\n\t"
        "orr	%[out], %[out], #0xe00\n\t"
#else
        "mov	%[out], #0xea0\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x20\n\t"
        "orr	%[in], %[in], #0x1500\n\t"
#else
        "mov	%[in], #0x1520\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0xc0\n\t"
        "orr	%[monic], %[monic], #0x900\n\t"
#else
        "mov	%[monic], #0x9c0\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x40\n\t"
        "orr	%[out], %[out], #0x1000\n\t"
#else
        "mov	%[out], #0x1040\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xc0\n\t"
        "orr	%[in], %[in], #0x1600\n\t"
#else
        "mov	%[in], #0x16c0\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0x60\n\t"
        "orr	%[monic], %[monic], #0xb00\n\t"
#else
        "mov	%[monic], #0xb60\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xe0\n\t"
        "orr	%[out], %[out], #0x1100\n\t"
#else
        "mov	%[out], #0x11e0\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x60\n\t"
        "orr	%[in], %[in], #0x1800\n\t"
#else
        "mov	%[in], #0x1860\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
        "mov	%[monic], #0xd00\n\t"
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
        "mov	%[out], #0x1a00\n\t"
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x80\n\t"
        "orr	%[in], %[in], #0x2000\n\t"
#else
        "mov	%[in], #0x2080\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0x20\n\t"
        "orr	%[monic], %[monic], #0x800\n\t"
#else
        "mov	%[monic], #0x820\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xa0\n\t"
        "orr	%[out], %[out], #0x1b00\n\t"
#else
        "mov	%[out], #0x1ba0\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x20\n\t"
        "orr	%[in], %[in], #0x2200\n\t"
#else
        "mov	%[in], #0x2220\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0xc0\n\t"
        "orr	%[monic], %[monic], #0x900\n\t"
#else
        "mov	%[monic], #0x9c0\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x40\n\t"
        "orr	%[out], %[out], #0x1d00\n\t"
#else
        "mov	%[out], #0x1d40\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xc0\n\t"
        "orr	%[in], %[in], #0x2300\n\t"
#else
        "mov	%[in], #0x23c0\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0x60\n\t"
        "orr	%[monic], %[monic], #0xb00\n\t"
#else
        "mov	%[monic], #0xb60\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xe0\n\t"
        "orr	%[out], %[out], #0x1e00\n\t"
#else
        "mov	%[out], #0x1ee0\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x60\n\t"
        "orr	%[in], %[in], #0x2500\n\t"
#else
        "mov	%[in], #0x2560\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
        "mov	%[monic], #0xd00\n\t"
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
        "mov	%[out], #0x2700\n\t"
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x80\n\t"
        "orr	%[in], %[in], #0x2d00\n\t"
#else
        "mov	%[in], #0x2d80\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0x20\n\t"
        "orr	%[monic], %[monic], #0x800\n\t"
#else
        "mov	%[monic], #0x820\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xa0\n\t"
        "orr	%[out], %[out], #0x2800\n\t"
#else
        "mov	%[out], #0x28a0\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x20\n\t"
        "orr	%[in], %[in], #0x2f00\n\t"
#else
        "mov	%[in], #0x2f20\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0xc0\n\t"
        "orr	%[monic], %[monic], #0x900\n\t"
#else
        "mov	%[monic], #0x9c0\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x40\n\t"
        "orr	%[out], %[out], #0x2a00\n\t"
#else
        "mov	%[out], #0x2a40\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xc0\n\t"
        "orr	%[in], %[in], #0x3000\n\t"
#else
        "mov	%[in], #0x30c0\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0x60\n\t"
        "orr	%[monic], %[monic], #0xb00\n\t"
#else
        "mov	%[monic], #0xb60\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xe0\n\t"
        "orr	%[out], %[out], #0x2b00\n\t"
#else
        "mov	%[out], #0x2be0\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x60\n\t"
        "orr	%[in], %[in], #0x3200\n\t"
#else
        "mov	%[in], #0x3260\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
        "mov	%[monic], #0xd00\n\t"
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
        "mov	%[out], #0\n\t"
        "add	%[out], r4, %[out]\n\t"
        "mov	%[in], #0xd00\n\t"
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0xa0\n\t"
        "orr	%[monic], %[monic], #0xe00\n\t"
#else
        "mov	%[monic], #0xea0\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xa0\n\t"
        "orr	%[out], %[out], #0x100\n\t"
#else
        "mov	%[out], #0x1a0\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xa0\n\t"
        "orr	%[in], %[in], #0xe00\n\t"
#else
        "mov	%[in], #0xea0\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0x40\n\t"
        "orr	%[monic], %[monic], #0x1000\n\t"
#else
        "mov	%[monic], #0x1040\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x40\n\t"
        "orr	%[out], %[out], #0x300\n\t"
#else
        "mov	%[out], #0x340\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x40\n\t"
        "orr	%[in], %[in], #0x1000\n\t"
#else
        "mov	%[in], #0x1040\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0xe0\n\t"
        "orr	%[monic], %[monic], #0x1100\n\t"
#else
        "mov	%[monic], #0x11e0\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xe0\n\t"
        "orr	%[out], %[out], #0x400\n\t"
#else
        "mov	%[out], #0x4e0\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xe0\n\t"
        "orr	%[in], %[in], #0x1100\n\t"
#else
        "mov	%[in], #0x11e0\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0x80\n\t"
        "orr	%[monic], %[monic], #0x1300\n\t"
#else
        "mov	%[monic], #0x1380\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x80\n\t"
        "orr	%[out], %[out], #0x600\n\t"
#else
        "mov	%[out], #0x680\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x80\n\t"
        "orr	%[in], %[in], #0x1300\n\t"
#else
        "mov	%[in], #0x1380\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0x20\n\t"
        "orr	%[monic], %[monic], #0x1500\n\t"
#else
        "mov	%[monic], #0x1520\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x20\n\t"
        "orr	%[out], %[out], #0x800\n\t"
#else
        "mov	%[out], #0x820\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x20\n\t"
        "orr	%[in], %[in], #0x1500\n\t"
#else
        "mov	%[in], #0x1520\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0xc0\n\t"
        "orr	%[monic], %[monic], #0x1600\n\t"
#else
        "mov	%[monic], #0x16c0\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xc0\n\t"
        "orr	%[out], %[out], #0x900\n\t"
#else
        "mov	%[out], #0x9c0\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xc0\n\t"
        "orr	%[in], %[in], #0x1600\n\t"
#else
        "mov	%[in], #0x16c0\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0x60\n\t"
        "orr	%[monic], %[monic], #0x1800\n\t"
#else
        "mov	%[monic], #0x1860\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x60\n\t"
        "orr	%[out], %[out], #0xb00\n\t"
#else
        "mov	%[out], #0xb60\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x60\n\t"
        "orr	%[in], %[in], #0x1800\n\t"
#else
        "mov	%[in], #0x1860\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
        "mov	%[monic], #0x1a00\n\t"
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
        "mov	%[out], #0x1a00\n\t"
        "add	%[out], r4, %[out]\n\t"
        "mov	%[in], #0x2700\n\t"
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0xa0\n\t"
        "orr	%[monic], %[monic], #0xe00\n\t"
#else
        "mov	%[monic], #0xea0\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xa0\n\t"
        "orr	%[out], %[out], #0x1b00\n\t"
#else
        "mov	%[out], #0x1ba0\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xa0\n\t"
        "orr	%[in], %[in], #0x2800\n\t"
#else
        "mov	%[in], #0x28a0\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0x40\n\t"
        "orr	%[monic], %[monic], #0x1000\n\t"
#else
        "mov	%[monic], #0x1040\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x40\n\t"
        "orr	%[out], %[out], #0x1d00\n\t"
#else
        "mov	%[out], #0x1d40\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x40\n\t"
        "orr	%[in], %[in], #0x2a00\n\t"
#else
        "mov	%[in], #0x2a40\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0xe0\n\t"
        "orr	%[monic], %[monic], #0x1100\n\t"
#else
        "mov	%[monic], #0x11e0\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xe0\n\t"
        "orr	%[out], %[out], #0x1e00\n\t"
#else
        "mov	%[out], #0x1ee0\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xe0\n\t"
        "orr	%[in], %[in], #0x2b00\n\t"
#else
        "mov	%[in], #0x2be0\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0x80\n\t"
        "orr	%[monic], %[monic], #0x1300\n\t"
#else
        "mov	%[monic], #0x1380\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x80\n\t"
        "orr	%[out], %[out], #0x2000\n\t"
#else
        "mov	%[out], #0x2080\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x80\n\t"
        "orr	%[in], %[in], #0x2d00\n\t"
#else
        "mov	%[in], #0x2d80\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0x20\n\t"
        "orr	%[monic], %[monic], #0x1500\n\t"
#else
        "mov	%[monic], #0x1520\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x20\n\t"
        "orr	%[out], %[out], #0x2200\n\t"
#else
        "mov	%[out], #0x2220\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x20\n\t"
        "orr	%[in], %[in], #0x2f00\n\t"
#else
        "mov	%[in], #0x2f20\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0xc0\n\t"
        "orr	%[monic], %[monic], #0x1600\n\t"
#else
        "mov	%[monic], #0x16c0\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xc0\n\t"
        "orr	%[out], %[out], #0x2300\n\t"
#else
        "mov	%[out], #0x23c0\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xc0\n\t"
        "orr	%[in], %[in], #0x3000\n\t"
#else
        "mov	%[in], #0x30c0\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0x60\n\t"
        "orr	%[monic], %[monic], #0x1800\n\t"
#else
        "mov	%[monic], #0x1860\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x60\n\t"
        "orr	%[out], %[out], #0x2500\n\t"
#else
        "mov	%[out], #0x2560\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x60\n\t"
        "orr	%[in], %[in], #0x3200\n\t"
#else
        "mov	%[in], #0x3260\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
        "mov	%[monic], #0x1a00\n\t"
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
        "mov	%[out], #0\n\t"
        "add	%[out], r4, %[out]\n\t"
        "mov	%[in], #0x1a00\n\t"
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0xa0\n\t"
        "orr	%[monic], %[monic], #0x1b00\n\t"
#else
        "mov	%[monic], #0x1ba0\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xa0\n\t"
        "orr	%[out], %[out], #0x100\n\t"
#else
        "mov	%[out], #0x1a0\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xa0\n\t"
        "orr	%[in], %[in], #0x1b00\n\t"
#else
        "mov	%[in], #0x1ba0\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0x40\n\t"
        "orr	%[monic], %[monic], #0x1d00\n\t"
#else
        "mov	%[monic], #0x1d40\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x40\n\t"
        "orr	%[out], %[out], #0x300\n\t"
#else
        "mov	%[out], #0x340\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x40\n\t"
        "orr	%[in], %[in], #0x1d00\n\t"
#else
        "mov	%[in], #0x1d40\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0xe0\n\t"
        "orr	%[monic], %[monic], #0x1e00\n\t"
#else
        "mov	%[monic], #0x1ee0\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xe0\n\t"
        "orr	%[out], %[out], #0x400\n\t"
#else
        "mov	%[out], #0x4e0\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xe0\n\t"
        "orr	%[in], %[in], #0x1e00\n\t"
#else
        "mov	%[in], #0x1ee0\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0x80\n\t"
        "orr	%[monic], %[monic], #0x2000\n\t"
#else
        "mov	%[monic], #0x2080\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x80\n\t"
        "orr	%[out], %[out], #0x600\n\t"
#else
        "mov	%[out], #0x680\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x80\n\t"
        "orr	%[in], %[in], #0x2000\n\t"
#else
        "mov	%[in], #0x2080\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0x20\n\t"
        "orr	%[monic], %[monic], #0x2200\n\t"
#else
        "mov	%[monic], #0x2220\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x20\n\t"
        "orr	%[out], %[out], #0x800\n\t"
#else
        "mov	%[out], #0x820\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x20\n\t"
        "orr	%[in], %[in], #0x2200\n\t"
#else
        "mov	%[in], #0x2220\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0xc0\n\t"
        "orr	%[monic], %[monic], #0x2300\n\t"
#else
        "mov	%[monic], #0x23c0\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xc0\n\t"
        "orr	%[out], %[out], #0x900\n\t"
#else
        "mov	%[out], #0x9c0\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xc0\n\t"
        "orr	%[in], %[in], #0x2300\n\t"
#else
        "mov	%[in], #0x23c0\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0x60\n\t"
        "orr	%[monic], %[monic], #0x2500\n\t"
#else
        "mov	%[monic], #0x2560\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x60\n\t"
        "orr	%[out], %[out], #0xb00\n\t"
#else
        "mov	%[out], #0xb60\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x60\n\t"
        "orr	%[in], %[in], #0x2500\n\t"
#else
        "mov	%[in], #0x2560\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
        "mov	%[monic], #0x2700\n\t"
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
        "mov	%[out], #0xd00\n\t"
        "add	%[out], r4, %[out]\n\t"
        "mov	%[in], #0x2700\n\t"
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0xa0\n\t"
        "orr	%[monic], %[monic], #0x2800\n\t"
#else
        "mov	%[monic], #0x28a0\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xa0\n\t"
        "orr	%[out], %[out], #0xe00\n\t"
#else
        "mov	%[out], #0xea0\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xa0\n\t"
        "orr	%[in], %[in], #0x2800\n\t"
#else
        "mov	%[in], #0x28a0\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0x40\n\t"
        "orr	%[monic], %[monic], #0x2a00\n\t"
#else
        "mov	%[monic], #0x2a40\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x40\n\t"
        "orr	%[out], %[out], #0x1000\n\t"
#else
        "mov	%[out], #0x1040\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x40\n\t"
        "orr	%[in], %[in], #0x2a00\n\t"
#else
        "mov	%[in], #0x2a40\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0xe0\n\t"
        "orr	%[monic], %[monic], #0x2b00\n\t"
#else
        "mov	%[monic], #0x2be0\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xe0\n\t"
        "orr	%[out], %[out], #0x1100\n\t"
#else
        "mov	%[out], #0x11e0\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xe0\n\t"
        "orr	%[in], %[in], #0x2b00\n\t"
#else
        "mov	%[in], #0x2be0\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0x80\n\t"
        "orr	%[monic], %[monic], #0x2d00\n\t"
#else
        "mov	%[monic], #0x2d80\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x80\n\t"
        "orr	%[out], %[out], #0x1300\n\t"
#else
        "mov	%[out], #0x1380\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x80\n\t"
        "orr	%[in], %[in], #0x2d00\n\t"
#else
        "mov	%[in], #0x2d80\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0x20\n\t"
        "orr	%[monic], %[monic], #0x2f00\n\t"
#else
        "mov	%[monic], #0x2f20\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x20\n\t"
        "orr	%[out], %[out], #0x1500\n\t"
#else
        "mov	%[out], #0x1520\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x20\n\t"
        "orr	%[in], %[in], #0x2f00\n\t"
#else
        "mov	%[in], #0x2f20\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0xc0\n\t"
        "orr	%[monic], %[monic], #0x3000\n\t"
#else
        "mov	%[monic], #0x30c0\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xc0\n\t"
        "orr	%[out], %[out], #0x1600\n\t"
#else
        "mov	%[out], #0x16c0\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xc0\n\t"
        "orr	%[in], %[in], #0x3000\n\t"
#else
        "mov	%[in], #0x30c0\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[monic], #0x60\n\t"
        "orr	%[monic], %[monic], #0x3200\n\t"
#else
        "mov	%[monic], #0x3260\n\t"
#endif
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x60\n\t"
        "orr	%[out], %[out], #0x1800\n\t"
#else
        "mov	%[out], #0x1860\n\t"
#endif
        "add	%[out], r4, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x60\n\t"
        "orr	%[in], %[in], #0x3200\n\t"
#else
        "mov	%[in], #0x3260\n\t"
#endif
        "add	%[in], r4, %[in]\n\t"
        "mov	%[monic], #0x3400\n\t"
        "add	%[monic], %[L_mc_aff_consts_neon], %[monic]\n\t"
        "add	%[scratch], r7, #0xbe0\n\t"
        "add	r12, r7, #0xd80\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_maa_neon\n\t"
        "cmp	r6, #0\n\t"
        "beq	L_mc_ffb_nm_%=\n\t"
        "mov	%[out], #0\n\t"
        "\n"
    "L_mc_ffb_mo_%=:\n\t"
        "cmp	%[out], #0x1a0\n\t"
        "bge	L_mc_ffb_moe_%=\n\t"
        "lsl	%[in], %[out], #5\n\t"
        "add	%[monic], r4, %[in]\n\t"
        "vld1.8	{d0-d3}, [%[monic]]\n\t"
        "add	%[scratch], %[L_mc_aff_powers_neon], %[in]\n\t"
        "vld1.8	{d4-d7}, [%[scratch]]\n\t"
        "veor	q0, q0, q2\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d3}, [%[monic]]\n\t"
        "add	%[out], %[out], #1\n\t"
        "b	L_mc_ffb_mo_%=\n\t"
        "\n"
    "L_mc_ffb_moe_%=:\n\t"
        "\n"
    "L_mc_ffb_nm_%=:\n\t"
        "add	sp, sp, #4\n\t"
        "pop	{%[L_mc_aff_consts_neon], %[L_mc_aff_powers_neon]}\n\t"
        "pop	{%[L_mc_aff_reversal_neon]}\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [out] "+r" (out), [in] "+r" (in), [monic] "+r" (monic),
          [scratch] "+r" (scratch),
          [L_mc_aff_consts_neon] "+r" (L_mc_aff_consts_neon_c),
          [L_mc_aff_powers_neon] "+r" (L_mc_aff_powers_neon_c),
          [L_mc_aff_reversal_neon] "+r" (L_mc_aff_reversal_neon_c)
        :
#else
        :
        : [out] "r" (out), [in] "r" (in), [monic] "r" (monic),
          [scratch] "r" (scratch),
          [L_mc_aff_consts_neon] "r" (L_mc_aff_consts_neon_c),
          [L_mc_aff_powers_neon] "r" (L_mc_aff_powers_neon_c),
          [L_mc_aff_reversal_neon] "r" (L_mc_aff_reversal_neon_c)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "lr", "r4", "r5", "r6", "r7", "r11", "r12", "q0",
            "q1", "q2", "q3", "q4", "q5", "q6", "q7"
    );
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    (void)monic_p;
#else
    (void)monic;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
}

WOLFSSL_LOCAL void wc_mceliece_aff_butterflies_tr_neon(word64* out, word64* in,
    word64* scratch);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_aff_butterflies_tr_neon(word64* out_p,
    word64* in_p, word64* scratch_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_aff_butterflies_tr_neon(word64* out,
    word64* in, word64* scratch)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word64* out __asm__ ("r0") = (word64*)out_p;
    register word64* in __asm__ ("r1") = (word64*)in_p;
    register word64* scratch __asm__ ("r2") = (word64*)scratch_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    register word64* L_mc_aff_consts_neon_c __asm__ ("r7") =
        (word64*)&L_mc_aff_consts_neon;
    register word8* L_mc_aff_reversal_neon_c __asm__ ("r8") =
        (word8*)&L_mc_aff_reversal_neon;
    __asm__ __volatile__ (
        "push	{%[L_mc_aff_reversal_neon]}\n\t"
        "sub	sp, sp, #4\n\t"
        "mov	r4, %[out]\n\t"
        "mov	r5, %[in]\n\t"
        "mov	r6, %[scratch]\n\t"
        "b	L_mc_pool_2_%=\n\t"
        "\n"
    "L_mc_pool_2_%=:\n\t"
        "mov	%[out], #0\n\t"
        "add	%[out], r5, %[out]\n\t"
        "mov	%[in], #0x1a00\n\t"
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0xa0\n\t"
        "orr	%[scratch], %[scratch], #0x1b00\n\t"
#else
        "mov	%[scratch], #0x1ba0\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xa0\n\t"
        "orr	%[out], %[out], #0x100\n\t"
#else
        "mov	%[out], #0x1a0\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xa0\n\t"
        "orr	%[in], %[in], #0x1b00\n\t"
#else
        "mov	%[in], #0x1ba0\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0x40\n\t"
        "orr	%[scratch], %[scratch], #0x1d00\n\t"
#else
        "mov	%[scratch], #0x1d40\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x40\n\t"
        "orr	%[out], %[out], #0x300\n\t"
#else
        "mov	%[out], #0x340\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x40\n\t"
        "orr	%[in], %[in], #0x1d00\n\t"
#else
        "mov	%[in], #0x1d40\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0xe0\n\t"
        "orr	%[scratch], %[scratch], #0x1e00\n\t"
#else
        "mov	%[scratch], #0x1ee0\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xe0\n\t"
        "orr	%[out], %[out], #0x400\n\t"
#else
        "mov	%[out], #0x4e0\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xe0\n\t"
        "orr	%[in], %[in], #0x1e00\n\t"
#else
        "mov	%[in], #0x1ee0\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0x80\n\t"
        "orr	%[scratch], %[scratch], #0x2000\n\t"
#else
        "mov	%[scratch], #0x2080\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x80\n\t"
        "orr	%[out], %[out], #0x600\n\t"
#else
        "mov	%[out], #0x680\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x80\n\t"
        "orr	%[in], %[in], #0x2000\n\t"
#else
        "mov	%[in], #0x2080\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0x20\n\t"
        "orr	%[scratch], %[scratch], #0x2200\n\t"
#else
        "mov	%[scratch], #0x2220\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x20\n\t"
        "orr	%[out], %[out], #0x800\n\t"
#else
        "mov	%[out], #0x820\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x20\n\t"
        "orr	%[in], %[in], #0x2200\n\t"
#else
        "mov	%[in], #0x2220\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0xc0\n\t"
        "orr	%[scratch], %[scratch], #0x2300\n\t"
#else
        "mov	%[scratch], #0x23c0\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xc0\n\t"
        "orr	%[out], %[out], #0x900\n\t"
#else
        "mov	%[out], #0x9c0\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xc0\n\t"
        "orr	%[in], %[in], #0x2300\n\t"
#else
        "mov	%[in], #0x23c0\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0x60\n\t"
        "orr	%[scratch], %[scratch], #0x2500\n\t"
#else
        "mov	%[scratch], #0x2560\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x60\n\t"
        "orr	%[out], %[out], #0xb00\n\t"
#else
        "mov	%[out], #0xb60\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x60\n\t"
        "orr	%[in], %[in], #0x2500\n\t"
#else
        "mov	%[in], #0x2560\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
        "mov	%[scratch], #0x2700\n\t"
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
        "mov	%[out], #0xd00\n\t"
        "add	%[out], r5, %[out]\n\t"
        "mov	%[in], #0x2700\n\t"
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0xa0\n\t"
        "orr	%[scratch], %[scratch], #0x2800\n\t"
#else
        "mov	%[scratch], #0x28a0\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xa0\n\t"
        "orr	%[out], %[out], #0xe00\n\t"
#else
        "mov	%[out], #0xea0\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xa0\n\t"
        "orr	%[in], %[in], #0x2800\n\t"
#else
        "mov	%[in], #0x28a0\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0x40\n\t"
        "orr	%[scratch], %[scratch], #0x2a00\n\t"
#else
        "mov	%[scratch], #0x2a40\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x40\n\t"
        "orr	%[out], %[out], #0x1000\n\t"
#else
        "mov	%[out], #0x1040\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x40\n\t"
        "orr	%[in], %[in], #0x2a00\n\t"
#else
        "mov	%[in], #0x2a40\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0xe0\n\t"
        "orr	%[scratch], %[scratch], #0x2b00\n\t"
#else
        "mov	%[scratch], #0x2be0\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xe0\n\t"
        "orr	%[out], %[out], #0x1100\n\t"
#else
        "mov	%[out], #0x11e0\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xe0\n\t"
        "orr	%[in], %[in], #0x2b00\n\t"
#else
        "mov	%[in], #0x2be0\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0x80\n\t"
        "orr	%[scratch], %[scratch], #0x2d00\n\t"
#else
        "mov	%[scratch], #0x2d80\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x80\n\t"
        "orr	%[out], %[out], #0x1300\n\t"
#else
        "mov	%[out], #0x1380\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x80\n\t"
        "orr	%[in], %[in], #0x2d00\n\t"
#else
        "mov	%[in], #0x2d80\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0x20\n\t"
        "orr	%[scratch], %[scratch], #0x2f00\n\t"
#else
        "mov	%[scratch], #0x2f20\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x20\n\t"
        "orr	%[out], %[out], #0x1500\n\t"
#else
        "mov	%[out], #0x1520\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x20\n\t"
        "orr	%[in], %[in], #0x2f00\n\t"
#else
        "mov	%[in], #0x2f20\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0xc0\n\t"
        "orr	%[scratch], %[scratch], #0x3000\n\t"
#else
        "mov	%[scratch], #0x30c0\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xc0\n\t"
        "orr	%[out], %[out], #0x1600\n\t"
#else
        "mov	%[out], #0x16c0\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xc0\n\t"
        "orr	%[in], %[in], #0x3000\n\t"
#else
        "mov	%[in], #0x30c0\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0x60\n\t"
        "orr	%[scratch], %[scratch], #0x3200\n\t"
#else
        "mov	%[scratch], #0x3260\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x60\n\t"
        "orr	%[out], %[out], #0x1800\n\t"
#else
        "mov	%[out], #0x1860\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x60\n\t"
        "orr	%[in], %[in], #0x3200\n\t"
#else
        "mov	%[in], #0x3260\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
        "mov	%[scratch], #0x3400\n\t"
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
        "mov	%[out], #0\n\t"
        "add	%[out], r5, %[out]\n\t"
        "mov	%[in], #0xd00\n\t"
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0xa0\n\t"
        "orr	%[scratch], %[scratch], #0xe00\n\t"
#else
        "mov	%[scratch], #0xea0\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xa0\n\t"
        "orr	%[out], %[out], #0x100\n\t"
#else
        "mov	%[out], #0x1a0\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xa0\n\t"
        "orr	%[in], %[in], #0xe00\n\t"
#else
        "mov	%[in], #0xea0\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0x40\n\t"
        "orr	%[scratch], %[scratch], #0x1000\n\t"
#else
        "mov	%[scratch], #0x1040\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x40\n\t"
        "orr	%[out], %[out], #0x300\n\t"
#else
        "mov	%[out], #0x340\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x40\n\t"
        "orr	%[in], %[in], #0x1000\n\t"
#else
        "mov	%[in], #0x1040\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0xe0\n\t"
        "orr	%[scratch], %[scratch], #0x1100\n\t"
#else
        "mov	%[scratch], #0x11e0\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xe0\n\t"
        "orr	%[out], %[out], #0x400\n\t"
#else
        "mov	%[out], #0x4e0\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xe0\n\t"
        "orr	%[in], %[in], #0x1100\n\t"
#else
        "mov	%[in], #0x11e0\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0x80\n\t"
        "orr	%[scratch], %[scratch], #0x1300\n\t"
#else
        "mov	%[scratch], #0x1380\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x80\n\t"
        "orr	%[out], %[out], #0x600\n\t"
#else
        "mov	%[out], #0x680\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x80\n\t"
        "orr	%[in], %[in], #0x1300\n\t"
#else
        "mov	%[in], #0x1380\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0x20\n\t"
        "orr	%[scratch], %[scratch], #0x1500\n\t"
#else
        "mov	%[scratch], #0x1520\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x20\n\t"
        "orr	%[out], %[out], #0x800\n\t"
#else
        "mov	%[out], #0x820\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x20\n\t"
        "orr	%[in], %[in], #0x1500\n\t"
#else
        "mov	%[in], #0x1520\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0xc0\n\t"
        "orr	%[scratch], %[scratch], #0x1600\n\t"
#else
        "mov	%[scratch], #0x16c0\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xc0\n\t"
        "orr	%[out], %[out], #0x900\n\t"
#else
        "mov	%[out], #0x9c0\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xc0\n\t"
        "orr	%[in], %[in], #0x1600\n\t"
#else
        "mov	%[in], #0x16c0\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0x60\n\t"
        "orr	%[scratch], %[scratch], #0x1800\n\t"
#else
        "mov	%[scratch], #0x1860\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x60\n\t"
        "orr	%[out], %[out], #0xb00\n\t"
#else
        "mov	%[out], #0xb60\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x60\n\t"
        "orr	%[in], %[in], #0x1800\n\t"
#else
        "mov	%[in], #0x1860\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
        "mov	%[scratch], #0x1a00\n\t"
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
        "mov	%[out], #0x1a00\n\t"
        "add	%[out], r5, %[out]\n\t"
        "mov	%[in], #0x2700\n\t"
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0xa0\n\t"
        "orr	%[scratch], %[scratch], #0xe00\n\t"
#else
        "mov	%[scratch], #0xea0\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xa0\n\t"
        "orr	%[out], %[out], #0x1b00\n\t"
#else
        "mov	%[out], #0x1ba0\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xa0\n\t"
        "orr	%[in], %[in], #0x2800\n\t"
#else
        "mov	%[in], #0x28a0\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0x40\n\t"
        "orr	%[scratch], %[scratch], #0x1000\n\t"
#else
        "mov	%[scratch], #0x1040\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x40\n\t"
        "orr	%[out], %[out], #0x1d00\n\t"
#else
        "mov	%[out], #0x1d40\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x40\n\t"
        "orr	%[in], %[in], #0x2a00\n\t"
#else
        "mov	%[in], #0x2a40\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0xe0\n\t"
        "orr	%[scratch], %[scratch], #0x1100\n\t"
#else
        "mov	%[scratch], #0x11e0\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xe0\n\t"
        "orr	%[out], %[out], #0x1e00\n\t"
#else
        "mov	%[out], #0x1ee0\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xe0\n\t"
        "orr	%[in], %[in], #0x2b00\n\t"
#else
        "mov	%[in], #0x2be0\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0x80\n\t"
        "orr	%[scratch], %[scratch], #0x1300\n\t"
#else
        "mov	%[scratch], #0x1380\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x80\n\t"
        "orr	%[out], %[out], #0x2000\n\t"
#else
        "mov	%[out], #0x2080\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x80\n\t"
        "orr	%[in], %[in], #0x2d00\n\t"
#else
        "mov	%[in], #0x2d80\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0x20\n\t"
        "orr	%[scratch], %[scratch], #0x1500\n\t"
#else
        "mov	%[scratch], #0x1520\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x20\n\t"
        "orr	%[out], %[out], #0x2200\n\t"
#else
        "mov	%[out], #0x2220\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x20\n\t"
        "orr	%[in], %[in], #0x2f00\n\t"
#else
        "mov	%[in], #0x2f20\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0xc0\n\t"
        "orr	%[scratch], %[scratch], #0x1600\n\t"
#else
        "mov	%[scratch], #0x16c0\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xc0\n\t"
        "orr	%[out], %[out], #0x2300\n\t"
#else
        "mov	%[out], #0x23c0\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xc0\n\t"
        "orr	%[in], %[in], #0x3000\n\t"
#else
        "mov	%[in], #0x30c0\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0x60\n\t"
        "orr	%[scratch], %[scratch], #0x1800\n\t"
#else
        "mov	%[scratch], #0x1860\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x60\n\t"
        "orr	%[out], %[out], #0x2500\n\t"
#else
        "mov	%[out], #0x2560\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x60\n\t"
        "orr	%[in], %[in], #0x3200\n\t"
#else
        "mov	%[in], #0x3260\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
        "mov	%[scratch], #0x1a00\n\t"
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
        "mov	%[out], #0\n\t"
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x80\n\t"
        "orr	%[in], %[in], #0x600\n\t"
#else
        "mov	%[in], #0x680\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0x20\n\t"
        "orr	%[scratch], %[scratch], #0x800\n\t"
#else
        "mov	%[scratch], #0x820\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xa0\n\t"
        "orr	%[out], %[out], #0x100\n\t"
#else
        "mov	%[out], #0x1a0\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x20\n\t"
        "orr	%[in], %[in], #0x800\n\t"
#else
        "mov	%[in], #0x820\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0xc0\n\t"
        "orr	%[scratch], %[scratch], #0x900\n\t"
#else
        "mov	%[scratch], #0x9c0\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x40\n\t"
        "orr	%[out], %[out], #0x300\n\t"
#else
        "mov	%[out], #0x340\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xc0\n\t"
        "orr	%[in], %[in], #0x900\n\t"
#else
        "mov	%[in], #0x9c0\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0x60\n\t"
        "orr	%[scratch], %[scratch], #0xb00\n\t"
#else
        "mov	%[scratch], #0xb60\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xe0\n\t"
        "orr	%[out], %[out], #0x400\n\t"
#else
        "mov	%[out], #0x4e0\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x60\n\t"
        "orr	%[in], %[in], #0xb00\n\t"
#else
        "mov	%[in], #0xb60\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
        "mov	%[scratch], #0xd00\n\t"
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
        "mov	%[out], #0xd00\n\t"
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x80\n\t"
        "orr	%[in], %[in], #0x1300\n\t"
#else
        "mov	%[in], #0x1380\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0x20\n\t"
        "orr	%[scratch], %[scratch], #0x800\n\t"
#else
        "mov	%[scratch], #0x820\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xa0\n\t"
        "orr	%[out], %[out], #0xe00\n\t"
#else
        "mov	%[out], #0xea0\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x20\n\t"
        "orr	%[in], %[in], #0x1500\n\t"
#else
        "mov	%[in], #0x1520\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0xc0\n\t"
        "orr	%[scratch], %[scratch], #0x900\n\t"
#else
        "mov	%[scratch], #0x9c0\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x40\n\t"
        "orr	%[out], %[out], #0x1000\n\t"
#else
        "mov	%[out], #0x1040\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xc0\n\t"
        "orr	%[in], %[in], #0x1600\n\t"
#else
        "mov	%[in], #0x16c0\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0x60\n\t"
        "orr	%[scratch], %[scratch], #0xb00\n\t"
#else
        "mov	%[scratch], #0xb60\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xe0\n\t"
        "orr	%[out], %[out], #0x1100\n\t"
#else
        "mov	%[out], #0x11e0\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x60\n\t"
        "orr	%[in], %[in], #0x1800\n\t"
#else
        "mov	%[in], #0x1860\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
        "mov	%[scratch], #0xd00\n\t"
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
        "mov	%[out], #0x1a00\n\t"
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x80\n\t"
        "orr	%[in], %[in], #0x2000\n\t"
#else
        "mov	%[in], #0x2080\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0x20\n\t"
        "orr	%[scratch], %[scratch], #0x800\n\t"
#else
        "mov	%[scratch], #0x820\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xa0\n\t"
        "orr	%[out], %[out], #0x1b00\n\t"
#else
        "mov	%[out], #0x1ba0\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x20\n\t"
        "orr	%[in], %[in], #0x2200\n\t"
#else
        "mov	%[in], #0x2220\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0xc0\n\t"
        "orr	%[scratch], %[scratch], #0x900\n\t"
#else
        "mov	%[scratch], #0x9c0\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x40\n\t"
        "orr	%[out], %[out], #0x1d00\n\t"
#else
        "mov	%[out], #0x1d40\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xc0\n\t"
        "orr	%[in], %[in], #0x2300\n\t"
#else
        "mov	%[in], #0x23c0\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0x60\n\t"
        "orr	%[scratch], %[scratch], #0xb00\n\t"
#else
        "mov	%[scratch], #0xb60\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xe0\n\t"
        "orr	%[out], %[out], #0x1e00\n\t"
#else
        "mov	%[out], #0x1ee0\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x60\n\t"
        "orr	%[in], %[in], #0x2500\n\t"
#else
        "mov	%[in], #0x2560\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
        "mov	%[scratch], #0xd00\n\t"
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
        "mov	%[out], #0x2700\n\t"
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x80\n\t"
        "orr	%[in], %[in], #0x2d00\n\t"
#else
        "mov	%[in], #0x2d80\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0x20\n\t"
        "orr	%[scratch], %[scratch], #0x800\n\t"
#else
        "mov	%[scratch], #0x820\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xa0\n\t"
        "orr	%[out], %[out], #0x2800\n\t"
#else
        "mov	%[out], #0x28a0\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x20\n\t"
        "orr	%[in], %[in], #0x2f00\n\t"
#else
        "mov	%[in], #0x2f20\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0xc0\n\t"
        "orr	%[scratch], %[scratch], #0x900\n\t"
#else
        "mov	%[scratch], #0x9c0\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x40\n\t"
        "orr	%[out], %[out], #0x2a00\n\t"
#else
        "mov	%[out], #0x2a40\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xc0\n\t"
        "orr	%[in], %[in], #0x3000\n\t"
#else
        "mov	%[in], #0x30c0\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0x60\n\t"
        "orr	%[scratch], %[scratch], #0xb00\n\t"
#else
        "mov	%[scratch], #0xb60\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xe0\n\t"
        "orr	%[out], %[out], #0x2b00\n\t"
#else
        "mov	%[out], #0x2be0\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x60\n\t"
        "orr	%[in], %[in], #0x3200\n\t"
#else
        "mov	%[in], #0x3260\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
        "mov	%[scratch], #0xd00\n\t"
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
        "mov	%[out], #0\n\t"
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x40\n\t"
        "orr	%[in], %[in], #0x300\n\t"
#else
        "mov	%[in], #0x340\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0xe0\n\t"
        "orr	%[scratch], %[scratch], #0x400\n\t"
#else
        "mov	%[scratch], #0x4e0\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xa0\n\t"
        "orr	%[out], %[out], #0x100\n\t"
#else
        "mov	%[out], #0x1a0\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xe0\n\t"
        "orr	%[in], %[in], #0x400\n\t"
#else
        "mov	%[in], #0x4e0\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0x80\n\t"
        "orr	%[scratch], %[scratch], #0x600\n\t"
#else
        "mov	%[scratch], #0x680\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x80\n\t"
        "orr	%[out], %[out], #0x600\n\t"
#else
        "mov	%[out], #0x680\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xc0\n\t"
        "orr	%[in], %[in], #0x900\n\t"
#else
        "mov	%[in], #0x9c0\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0xe0\n\t"
        "orr	%[scratch], %[scratch], #0x400\n\t"
#else
        "mov	%[scratch], #0x4e0\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x20\n\t"
        "orr	%[out], %[out], #0x800\n\t"
#else
        "mov	%[out], #0x820\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x60\n\t"
        "orr	%[in], %[in], #0xb00\n\t"
#else
        "mov	%[in], #0xb60\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0x80\n\t"
        "orr	%[scratch], %[scratch], #0x600\n\t"
#else
        "mov	%[scratch], #0x680\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
        "mov	%[out], #0xd00\n\t"
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x40\n\t"
        "orr	%[in], %[in], #0x1000\n\t"
#else
        "mov	%[in], #0x1040\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0xe0\n\t"
        "orr	%[scratch], %[scratch], #0x400\n\t"
#else
        "mov	%[scratch], #0x4e0\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xa0\n\t"
        "orr	%[out], %[out], #0xe00\n\t"
#else
        "mov	%[out], #0xea0\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xe0\n\t"
        "orr	%[in], %[in], #0x1100\n\t"
#else
        "mov	%[in], #0x11e0\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0x80\n\t"
        "orr	%[scratch], %[scratch], #0x600\n\t"
#else
        "mov	%[scratch], #0x680\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x80\n\t"
        "orr	%[out], %[out], #0x1300\n\t"
#else
        "mov	%[out], #0x1380\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xc0\n\t"
        "orr	%[in], %[in], #0x1600\n\t"
#else
        "mov	%[in], #0x16c0\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0xe0\n\t"
        "orr	%[scratch], %[scratch], #0x400\n\t"
#else
        "mov	%[scratch], #0x4e0\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x20\n\t"
        "orr	%[out], %[out], #0x1500\n\t"
#else
        "mov	%[out], #0x1520\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x60\n\t"
        "orr	%[in], %[in], #0x1800\n\t"
#else
        "mov	%[in], #0x1860\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0x80\n\t"
        "orr	%[scratch], %[scratch], #0x600\n\t"
#else
        "mov	%[scratch], #0x680\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
        "mov	%[out], #0x1a00\n\t"
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x40\n\t"
        "orr	%[in], %[in], #0x1d00\n\t"
#else
        "mov	%[in], #0x1d40\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0xe0\n\t"
        "orr	%[scratch], %[scratch], #0x400\n\t"
#else
        "mov	%[scratch], #0x4e0\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xa0\n\t"
        "orr	%[out], %[out], #0x1b00\n\t"
#else
        "mov	%[out], #0x1ba0\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xe0\n\t"
        "orr	%[in], %[in], #0x1e00\n\t"
#else
        "mov	%[in], #0x1ee0\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0x80\n\t"
        "orr	%[scratch], %[scratch], #0x600\n\t"
#else
        "mov	%[scratch], #0x680\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x80\n\t"
        "orr	%[out], %[out], #0x2000\n\t"
#else
        "mov	%[out], #0x2080\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xc0\n\t"
        "orr	%[in], %[in], #0x2300\n\t"
#else
        "mov	%[in], #0x23c0\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0xe0\n\t"
        "orr	%[scratch], %[scratch], #0x400\n\t"
#else
        "mov	%[scratch], #0x4e0\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x20\n\t"
        "orr	%[out], %[out], #0x2200\n\t"
#else
        "mov	%[out], #0x2220\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x60\n\t"
        "orr	%[in], %[in], #0x2500\n\t"
#else
        "mov	%[in], #0x2560\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0x80\n\t"
        "orr	%[scratch], %[scratch], #0x600\n\t"
#else
        "mov	%[scratch], #0x680\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
        "mov	%[out], #0x2700\n\t"
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x40\n\t"
        "orr	%[in], %[in], #0x2a00\n\t"
#else
        "mov	%[in], #0x2a40\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0xe0\n\t"
        "orr	%[scratch], %[scratch], #0x400\n\t"
#else
        "mov	%[scratch], #0x4e0\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xa0\n\t"
        "orr	%[out], %[out], #0x2800\n\t"
#else
        "mov	%[out], #0x28a0\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xe0\n\t"
        "orr	%[in], %[in], #0x2b00\n\t"
#else
        "mov	%[in], #0x2be0\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0x80\n\t"
        "orr	%[scratch], %[scratch], #0x600\n\t"
#else
        "mov	%[scratch], #0x680\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x80\n\t"
        "orr	%[out], %[out], #0x2d00\n\t"
#else
        "mov	%[out], #0x2d80\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xc0\n\t"
        "orr	%[in], %[in], #0x3000\n\t"
#else
        "mov	%[in], #0x30c0\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0xe0\n\t"
        "orr	%[scratch], %[scratch], #0x400\n\t"
#else
        "mov	%[scratch], #0x4e0\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x20\n\t"
        "orr	%[out], %[out], #0x2f00\n\t"
#else
        "mov	%[out], #0x2f20\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x60\n\t"
        "orr	%[in], %[in], #0x3200\n\t"
#else
        "mov	%[in], #0x3260\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0x80\n\t"
        "orr	%[scratch], %[scratch], #0x600\n\t"
#else
        "mov	%[scratch], #0x680\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
        "mov	%[out], #0\n\t"
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xa0\n\t"
        "orr	%[in], %[in], #0x100\n\t"
#else
        "mov	%[in], #0x1a0\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0x40\n\t"
        "orr	%[scratch], %[scratch], #0x300\n\t"
#else
        "mov	%[scratch], #0x340\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x40\n\t"
        "orr	%[out], %[out], #0x300\n\t"
#else
        "mov	%[out], #0x340\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xe0\n\t"
        "orr	%[in], %[in], #0x400\n\t"
#else
        "mov	%[in], #0x4e0\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0x40\n\t"
        "orr	%[scratch], %[scratch], #0x300\n\t"
#else
        "mov	%[scratch], #0x340\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x80\n\t"
        "orr	%[out], %[out], #0x600\n\t"
#else
        "mov	%[out], #0x680\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x20\n\t"
        "orr	%[in], %[in], #0x800\n\t"
#else
        "mov	%[in], #0x820\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0x40\n\t"
        "orr	%[scratch], %[scratch], #0x300\n\t"
#else
        "mov	%[scratch], #0x340\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xc0\n\t"
        "orr	%[out], %[out], #0x900\n\t"
#else
        "mov	%[out], #0x9c0\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x60\n\t"
        "orr	%[in], %[in], #0xb00\n\t"
#else
        "mov	%[in], #0xb60\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0x40\n\t"
        "orr	%[scratch], %[scratch], #0x300\n\t"
#else
        "mov	%[scratch], #0x340\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
        "mov	%[out], #0xd00\n\t"
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xa0\n\t"
        "orr	%[in], %[in], #0xe00\n\t"
#else
        "mov	%[in], #0xea0\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0x40\n\t"
        "orr	%[scratch], %[scratch], #0x300\n\t"
#else
        "mov	%[scratch], #0x340\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x40\n\t"
        "orr	%[out], %[out], #0x1000\n\t"
#else
        "mov	%[out], #0x1040\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xe0\n\t"
        "orr	%[in], %[in], #0x1100\n\t"
#else
        "mov	%[in], #0x11e0\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0x40\n\t"
        "orr	%[scratch], %[scratch], #0x300\n\t"
#else
        "mov	%[scratch], #0x340\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x80\n\t"
        "orr	%[out], %[out], #0x1300\n\t"
#else
        "mov	%[out], #0x1380\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x20\n\t"
        "orr	%[in], %[in], #0x1500\n\t"
#else
        "mov	%[in], #0x1520\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0x40\n\t"
        "orr	%[scratch], %[scratch], #0x300\n\t"
#else
        "mov	%[scratch], #0x340\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xc0\n\t"
        "orr	%[out], %[out], #0x1600\n\t"
#else
        "mov	%[out], #0x16c0\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x60\n\t"
        "orr	%[in], %[in], #0x1800\n\t"
#else
        "mov	%[in], #0x1860\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0x40\n\t"
        "orr	%[scratch], %[scratch], #0x300\n\t"
#else
        "mov	%[scratch], #0x340\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
        "mov	%[out], #0x1a00\n\t"
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xa0\n\t"
        "orr	%[in], %[in], #0x1b00\n\t"
#else
        "mov	%[in], #0x1ba0\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0x40\n\t"
        "orr	%[scratch], %[scratch], #0x300\n\t"
#else
        "mov	%[scratch], #0x340\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x40\n\t"
        "orr	%[out], %[out], #0x1d00\n\t"
#else
        "mov	%[out], #0x1d40\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xe0\n\t"
        "orr	%[in], %[in], #0x1e00\n\t"
#else
        "mov	%[in], #0x1ee0\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0x40\n\t"
        "orr	%[scratch], %[scratch], #0x300\n\t"
#else
        "mov	%[scratch], #0x340\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x80\n\t"
        "orr	%[out], %[out], #0x2000\n\t"
#else
        "mov	%[out], #0x2080\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x20\n\t"
        "orr	%[in], %[in], #0x2200\n\t"
#else
        "mov	%[in], #0x2220\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0x40\n\t"
        "orr	%[scratch], %[scratch], #0x300\n\t"
#else
        "mov	%[scratch], #0x340\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xc0\n\t"
        "orr	%[out], %[out], #0x2300\n\t"
#else
        "mov	%[out], #0x23c0\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x60\n\t"
        "orr	%[in], %[in], #0x2500\n\t"
#else
        "mov	%[in], #0x2560\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0x40\n\t"
        "orr	%[scratch], %[scratch], #0x300\n\t"
#else
        "mov	%[scratch], #0x340\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
        "mov	%[out], #0x2700\n\t"
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xa0\n\t"
        "orr	%[in], %[in], #0x2800\n\t"
#else
        "mov	%[in], #0x28a0\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0x40\n\t"
        "orr	%[scratch], %[scratch], #0x300\n\t"
#else
        "mov	%[scratch], #0x340\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x40\n\t"
        "orr	%[out], %[out], #0x2a00\n\t"
#else
        "mov	%[out], #0x2a40\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0xe0\n\t"
        "orr	%[in], %[in], #0x2b00\n\t"
#else
        "mov	%[in], #0x2be0\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0x40\n\t"
        "orr	%[scratch], %[scratch], #0x300\n\t"
#else
        "mov	%[scratch], #0x340\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0x80\n\t"
        "orr	%[out], %[out], #0x2d00\n\t"
#else
        "mov	%[out], #0x2d80\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x20\n\t"
        "orr	%[in], %[in], #0x2f00\n\t"
#else
        "mov	%[in], #0x2f20\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0x40\n\t"
        "orr	%[scratch], %[scratch], #0x300\n\t"
#else
        "mov	%[scratch], #0x340\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[out], #0xc0\n\t"
        "orr	%[out], %[out], #0x3000\n\t"
#else
        "mov	%[out], #0x30c0\n\t"
#endif
        "add	%[out], r5, %[out]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[in], #0x60\n\t"
        "orr	%[in], %[in], #0x3200\n\t"
#else
        "mov	%[in], #0x3260\n\t"
#endif
        "add	%[in], r5, %[in]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	%[scratch], #0x40\n\t"
        "orr	%[scratch], %[scratch], #0x300\n\t"
#else
        "mov	%[scratch], #0x340\n\t"
#endif
        "add	%[scratch], %[L_mc_aff_consts_neon], %[scratch]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
        "mov	r9, #0\n\t"
        "\n"
    "L_mc_btr_pk_%=:\n\t"
        "cmp	r9, #32\n\t"
        "bge	L_mc_btr_pke_%=\n\t"
        "add	%[out], r6, #0x610\n\t"
        "add	%[in], r6, #0x7b0\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r12, #0xa0\n\t"
        "orr	r12, r12, #0x100\n\t"
#else
        "mov	r12, #0x1a0\n\t"
#endif
        "mul	%[scratch], r9, r12\n\t"
        "add	%[scratch], r5, %[scratch]\n\t"
        "add	r3, %[scratch], #0x1a0\n\t"
        "bl	wc_mceliece_aff_pack_lh_neon\n\t"
        "add	%[out], r6, #0x610\n\t"
        "add	%[in], r6, #0x7b0\n\t"
        "add	%[scratch], %[L_mc_aff_consts_neon], #0x1a0\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r12, #0xa0\n\t"
        "orr	r12, r12, #0x100\n\t"
#else
        "mov	r12, #0x1a0\n\t"
#endif
        "mul	%[out], r9, r12\n\t"
        "add	%[out], r5, %[out]\n\t"
        "add	%[in], %[out], #0x1a0\n\t"
        "add	%[scratch], r6, #0x610\n\t"
        "add	r3, r6, #0x7b0\n\t"
        "bl	wc_mceliece_aff_pack_lh_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r12, #0xa0\n\t"
        "orr	r12, r12, #0x100\n\t"
#else
        "mov	r12, #0x1a0\n\t"
#endif
        "mul	%[scratch], r9, r12\n\t"
        "add	%[out], r6, #0x610\n\t"
        "add	%[in], r6, #0x7b0\n\t"
        "add	%[scratch], r5, %[scratch]\n\t"
        "add	r3, %[scratch], #0x1a0\n\t"
        "bl	wc_mceliece_aff_pack_lh2_neon\n\t"
        "add	%[out], r6, #0x610\n\t"
        "add	%[in], r6, #0x7b0\n\t"
        "mov	%[scratch], %[L_mc_aff_consts_neon]\n\t"
        "add	r3, r6, #0xe10\n\t"
        "add	r12, r6, #0xfb0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_ama_neon\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r12, #0xa0\n\t"
        "orr	r12, r12, #0x100\n\t"
#else
        "mov	r12, #0x1a0\n\t"
#endif
        "mul	%[out], r9, r12\n\t"
        "add	%[out], r5, %[out]\n\t"
        "add	%[in], %[out], #0x1a0\n\t"
        "add	%[scratch], r6, #0x610\n\t"
        "add	r3, r6, #0x7b0\n\t"
        "bl	wc_mceliece_aff_pack_lh2_neon\n\t"
        "add	r9, r9, #2\n\t"
        "b	L_mc_btr_pk_%=\n\t"
        "\n"
    "L_mc_btr_pke_%=:\n\t"
        "mov	r9, #0\n\t"
        "\n"
    "L_mc_btr_i_%=:\n\t"
        "cmp	r9, #13\n\t"
        "bge	L_mc_btr_ie_%=\n\t"
        "add	%[out], r6, #0x610\n\t"
        "mov	%[in], r5\n\t"
        "mov	%[scratch], r9\n\t"
        "bl	wc_mceliece_aff_btr_in_neon\n\t"
        "add	%[out], r6, #0x610\n\t"
        "bl	wc_mceliece_aff_transpose_neon\n\t"
        "add	%[out], r6, #0xd0\n\t"
        "add	%[in], r6, #0x610\n\t"
        "mov	%[scratch], r4\n\t"
        "mov	r3, r9\n\t"
        "lsr	r12, r9, #1\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_aff_btr_net_neon\n\t"
        "add	r9, r9, #2\n\t"
        "b	L_mc_btr_i_%=\n\t"
        "\n"
    "L_mc_btr_ie_%=:\n\t"
        "vmov.i8	q2, #0xff\n\t"
        "veor	q3, q3, q3\n\t"
        "add	%[out], r6, #0\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], r6, #16\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], r6, #32\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], r6, #48\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], r6, #0x40\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], r6, #0x50\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], r6, #0x60\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], r6, #0x70\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], r6, #0x80\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], r6, #0x90\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], r6, #0xa0\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], r6, #0xb0\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], r6, #0xc0\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "mov	%[out], r6\n\t"
        "add	%[in], r6, #0xd0\n\t"
        "mov	%[scratch], r6\n\t"
        "add	r3, r6, #0x610\n\t"
        "bl	wc_mceliece_aff_v128_mul_neon\n\t"
        "add	%[out], r6, #0\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0\n\t"
        "add	r12, %[in], #16\n\t"
        "vst1.8	{d0}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vst1.8	{d1}, [r12]\n\t"
        "add	%[out], r6, #16\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #32\n\t"
        "add	r12, %[in], #16\n\t"
        "vst1.8	{d0}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vst1.8	{d1}, [r12]\n\t"
        "add	%[out], r6, #32\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0x40\n\t"
        "add	r12, %[in], #16\n\t"
        "vst1.8	{d0}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vst1.8	{d1}, [r12]\n\t"
        "add	%[out], r6, #48\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0x60\n\t"
        "add	r12, %[in], #16\n\t"
        "vst1.8	{d0}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vst1.8	{d1}, [r12]\n\t"
        "add	%[out], r6, #0x40\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0x80\n\t"
        "add	r12, %[in], #16\n\t"
        "vst1.8	{d0}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vst1.8	{d1}, [r12]\n\t"
        "add	%[out], r6, #0x50\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0xa0\n\t"
        "add	r12, %[in], #16\n\t"
        "vst1.8	{d0}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vst1.8	{d1}, [r12]\n\t"
        "add	%[out], r6, #0x60\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0xc0\n\t"
        "add	r12, %[in], #16\n\t"
        "vst1.8	{d0}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vst1.8	{d1}, [r12]\n\t"
        "add	%[out], r6, #0x70\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0xe0\n\t"
        "add	r12, %[in], #16\n\t"
        "vst1.8	{d0}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vst1.8	{d1}, [r12]\n\t"
        "add	%[out], r6, #0x80\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0x100\n\t"
        "add	r12, %[in], #16\n\t"
        "vst1.8	{d0}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vst1.8	{d1}, [r12]\n\t"
        "add	%[out], r6, #0x90\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0x120\n\t"
        "add	r12, %[in], #16\n\t"
        "vst1.8	{d0}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vst1.8	{d1}, [r12]\n\t"
        "add	%[out], r6, #0xa0\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0x140\n\t"
        "add	r12, %[in], #16\n\t"
        "vst1.8	{d0}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vst1.8	{d1}, [r12]\n\t"
        "add	%[out], r6, #0xb0\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0x160\n\t"
        "add	r12, %[in], #16\n\t"
        "vst1.8	{d0}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vst1.8	{d1}, [r12]\n\t"
        "add	%[out], r6, #0xc0\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0x180\n\t"
        "add	r12, %[in], #16\n\t"
        "vst1.8	{d0}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vst1.8	{d1}, [r12]\n\t"
        "vmov.i8	q2, #0xff\n\t"
        "veor	q3, q3, q3\n\t"
        "add	%[out], r6, #0\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], r6, #16\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], r6, #32\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], r6, #48\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], r6, #0x40\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], r6, #0x50\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], r6, #0x60\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], r6, #0x70\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], r6, #0x80\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], r6, #0x90\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], r6, #0xa0\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], r6, #0xb0\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], r6, #0xc0\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "mov	%[out], r6\n\t"
        "add	%[in], r6, #0x1b0\n\t"
        "mov	%[scratch], r6\n\t"
        "add	r3, r6, #0x610\n\t"
        "bl	wc_mceliece_aff_v128_mul_neon\n\t"
        "add	%[out], r6, #0\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #16\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #32\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #32\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0x40\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #48\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0x60\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #0x40\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0x80\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #0x50\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0xa0\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #0x60\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0xc0\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #0x70\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0xe0\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #0x80\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0x100\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #0x90\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0x120\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #0xa0\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0x140\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #0xb0\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0x160\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #0xc0\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0x180\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "vmov.i8	q2, #0xff\n\t"
        "veor	q3, q3, q3\n\t"
        "add	%[out], r6, #0\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], r6, #16\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], r6, #32\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], r6, #48\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], r6, #0x40\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], r6, #0x50\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], r6, #0x60\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], r6, #0x70\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], r6, #0x80\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], r6, #0x90\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], r6, #0xa0\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], r6, #0xb0\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], r6, #0xc0\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "mov	%[out], r6\n\t"
        "add	%[in], r6, #0x290\n\t"
        "mov	%[scratch], r6\n\t"
        "add	r3, r6, #0x610\n\t"
        "bl	wc_mceliece_aff_v128_mul_neon\n\t"
        "add	%[out], r6, #0\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #16\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #32\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #32\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0x40\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #48\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0x60\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #0x40\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0x80\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #0x50\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0xa0\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #0x60\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0xc0\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #0x70\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0xe0\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #0x80\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0x100\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #0x90\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0x120\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #0xa0\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0x140\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #0xb0\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0x160\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #0xc0\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0x180\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "vmov.i8	q2, #0xff\n\t"
        "veor	q3, q3, q3\n\t"
        "add	%[out], r6, #0\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], r6, #16\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], r6, #32\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], r6, #48\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], r6, #0x40\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], r6, #0x50\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], r6, #0x60\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], r6, #0x70\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], r6, #0x80\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], r6, #0x90\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], r6, #0xa0\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], r6, #0xb0\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], r6, #0xc0\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "mov	%[out], r6\n\t"
        "add	%[in], r6, #0x370\n\t"
        "mov	%[scratch], r6\n\t"
        "add	r3, r6, #0x610\n\t"
        "bl	wc_mceliece_aff_v128_mul_neon\n\t"
        "add	%[out], r6, #0\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #16\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #32\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #32\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0x40\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #48\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0x60\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #0x40\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0x80\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #0x50\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0xa0\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #0x60\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0xc0\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #0x70\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0xe0\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #0x80\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0x100\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #0x90\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0x120\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #0xa0\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0x140\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #0xb0\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0x160\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #0xc0\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0x180\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "vmov.i8	q2, #0xff\n\t"
        "veor	q3, q3, q3\n\t"
        "add	%[out], r6, #0\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], r6, #16\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], r6, #32\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], r6, #48\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], r6, #0x40\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], r6, #0x50\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], r6, #0x60\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], r6, #0x70\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], r6, #0x80\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], r6, #0x90\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], r6, #0xa0\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], r6, #0xb0\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], r6, #0xc0\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "mov	%[out], r6\n\t"
        "add	%[in], r6, #0x450\n\t"
        "mov	%[scratch], r6\n\t"
        "add	r3, r6, #0x610\n\t"
        "bl	wc_mceliece_aff_v128_mul_neon\n\t"
        "add	%[out], r6, #0\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #16\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #32\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #32\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0x40\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #48\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0x60\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #0x40\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0x80\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #0x50\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0xa0\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #0x60\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0xc0\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #0x70\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0xe0\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #0x80\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0x100\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #0x90\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0x120\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #0xa0\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0x140\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #0xb0\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0x160\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #0xc0\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0x180\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "vmov.i8	q2, #0xff\n\t"
        "veor	q3, q3, q3\n\t"
        "add	%[out], r6, #0\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], r6, #16\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], r6, #32\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], r6, #48\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], r6, #0x40\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], r6, #0x50\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], r6, #0x60\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], r6, #0x70\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], r6, #0x80\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], r6, #0x90\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], r6, #0xa0\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d6}, [%[out]]\n\t"
        "add	%[out], r6, #0xb0\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], r6, #0xc0\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vst1.8	{d4}, [%[out]]\n\t"
        "mov	%[out], r6\n\t"
        "add	%[in], r6, #0x530\n\t"
        "mov	%[scratch], r6\n\t"
        "add	r3, r6, #0x610\n\t"
        "bl	wc_mceliece_aff_v128_mul_neon\n\t"
        "add	%[out], r6, #0\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #16\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #32\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #32\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0x40\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #48\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0x60\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #0x40\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0x80\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #0x50\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0xa0\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #0x60\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0xc0\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #0x70\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0xe0\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #0x80\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0x100\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #0x90\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0x120\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #0xa0\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0x140\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #0xb0\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0x160\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	%[out], r6, #0xc0\n\t"
        "vld1.8	{d0}, [%[out]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "vld1.8	{d1}, [%[out]]\n\t"
        "add	%[in], r4, #0x180\n\t"
        "add	r12, %[in], #16\n\t"
        "vld1.8	{d2}, [r12]\n\t"
        "veor	d2, d2, d0\n\t"
        "vst1.8	{d2}, [r12]\n\t"
        "add	r12, %[in], #24\n\t"
        "vld1.8	{d3}, [r12]\n\t"
        "veor	d3, d3, d1\n\t"
        "vst1.8	{d3}, [r12]\n\t"
        "add	sp, sp, #4\n\t"
        "pop	{%[L_mc_aff_reversal_neon]}\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [out] "+r" (out), [in] "+r" (in), [scratch] "+r" (scratch),
          [L_mc_aff_consts_neon] "+r" (L_mc_aff_consts_neon_c),
          [L_mc_aff_reversal_neon] "+r" (L_mc_aff_reversal_neon_c)
        :
#else
        :
        : [out] "r" (out), [in] "r" (in), [scratch] "r" (scratch),
          [L_mc_aff_consts_neon] "r" (L_mc_aff_consts_neon_c),
          [L_mc_aff_reversal_neon] "r" (L_mc_aff_reversal_neon_c)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r3", "lr", "r4", "r5", "r6", "r9", "r12", "q0", "q1",
            "q2", "q3"
    );
}

WOLFSSL_LOCAL void wc_mceliece_goppa_eval_inv_neon(word64* einvbs, word64* ffts,
    const byte* gp, int t, int mono, word64* poly, word64* scratch);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_goppa_eval_inv_neon(word64* einvbs_p,
    word64* ffts_p, const byte* gp_p, int t_p, int mono_p, word64* poly_p,
    word64* scratch_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_goppa_eval_inv_neon(word64* einvbs,
    word64* ffts, const byte* gp, int t, int mono, word64* poly,
    word64* scratch)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word64* einvbs __asm__ ("r0") = (word64*)einvbs_p;
    register word64* ffts __asm__ ("r1") = (word64*)ffts_p;
    register const byte* gp __asm__ ("r2") = (const byte*)gp_p;
    register int t __asm__ ("r3") = (int)t_p;
    register int mono __asm__ ("r12") = (int)mono_p;
    register word64* poly __asm__ ("lr") = (word64*)poly_p;
    register word64* scratch __asm__ ("r4") = (word64*)scratch_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "push	{%[scratch]}\n\t"
        "push	{%[mono], %[poly]}\n\t"
        "sub	sp, sp, #12\n\t"
        "mov	r4, %[einvbs]\n\t"
        "mov	r5, %[ffts]\n\t"
        "mov	%[einvbs], %[gp]\n\t"
        "mov	%[ffts], %[t]\n\t"
        "ldr	r6, [sp, #12]\n\t"
        "ldr	r7, [sp, #16]\n\t"
        "ldr	r8, [sp, #20]\n\t"
        "mov	r12, #0x1300\n\t"
        "add	r10, r8, r12\n\t"
        "mov	%[gp], #0\n\t"
        "\n"
    "L_mc_gei_l_%=:\n\t"
        "cmp	%[gp], %[ffts]\n\t"
        "bge	L_mc_gei_le_%=\n\t"
        "lsl	%[t], %[gp], #1\n\t"
        "add	r12, %[einvbs], %[t]\n\t"
        "ldrh	r12, [r12]\n\t"
        "lsl	r12, r12, #19\n\t"
        "lsr	r12, r12, #19\n\t"
        "add	%[t], r10, %[t]\n\t"
        "strh	r12, [%[t]]\n\t"
        "add	%[gp], %[gp], #1\n\t"
        "b	L_mc_gei_l_%=\n\t"
        "\n"
    "L_mc_gei_le_%=:\n\t"
        "cmp	%[ffts], #0x80\n\t"
        "bge	L_mc_gei_ze_%=\n\t"
        "lsl	%[t], %[ffts], #1\n\t"
        "add	%[t], r10, %[t]\n\t"
        "mov	r12, #1\n\t"
        "strh	r12, [%[t]]\n\t"
        "add	%[gp], %[ffts], #1\n\t"
        "mov	r12, #0\n\t"
        "\n"
    "L_mc_gei_z_%=:\n\t"
        "cmp	%[gp], #0x80\n\t"
        "bge	L_mc_gei_ze_%=\n\t"
        "lsl	%[t], %[gp], #1\n\t"
        "add	%[t], r10, %[t]\n\t"
        "strh	r12, [%[t]]\n\t"
        "add	%[gp], %[gp], #1\n\t"
        "b	L_mc_gei_z_%=\n\t"
        "\n"
    "L_mc_gei_ze_%=:\n\t"
        "mov	%[einvbs], r7\n\t"
        "mov	%[ffts], r10\n\t"
        "bl	wc_mceliece_bs_poly_neon\n\t"
        "mov	%[einvbs], r7\n\t"
        "bl	wc_mceliece_radix_conv_neon\n\t"
        "mov	%[einvbs], r5\n\t"
        "mov	%[ffts], r7\n\t"
        "mov	%[gp], r6\n\t"
        "mov	%[t], r8\n\t"
        "bl	wc_mceliece_fft_fwd_butterflies_neon\n\t"
        "mov	%[einvbs], r4\n\t"
        "mov	%[ffts], r5\n\t"
        "mov	%[gp], r8\n\t"
        "add	%[t], r8, #0x340\n\t"
        "mov	r12, #1\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_mont_batch_inv_neon\n\t"
        "add	sp, sp, #12\n\t"
        "pop	{%[mono], %[poly]}\n\t"
        "pop	{%[scratch]}\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [einvbs] "+r" (einvbs), [ffts] "+r" (ffts), [gp] "+r" (gp),
          [t] "+r" (t), [mono] "+r" (mono), [poly] "+r" (poly),
          [scratch] "+r" (scratch)
        :
#else
        :
        : [einvbs] "r" (einvbs), [ffts] "r" (ffts), [gp] "r" (gp), [t] "r" (t),
          [mono] "r" (mono), [poly] "r" (poly), [scratch] "r" (scratch)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r5", "r6", "r7", "r8", "r10"
    );
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    (void)t_p;
#else
    (void)t;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    (void)mono_p;
#else
    (void)mono;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
}

WOLFSSL_LOCAL void wc_mceliece_bs_packbuf_neon(word64* buf, const word32* perm,
    const word64* fftinv);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_bs_packbuf_neon(word64* buf_p,
    const word32* perm_p, const word64* fftinv_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_bs_packbuf_neon(word64* buf,
    const word32* perm, const word64* fftinv)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word64* buf __asm__ ("r0") = (word64*)buf_p;
    register const word32* perm __asm__ ("r1") = (const word32*)perm_p;
    register const word64* fftinv __asm__ ("r2") = (const word64*)fftinv_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r6, #0xff\n\t"
        "orr	r6, r6, #0x1f00\n\t"
#else
        "mov	r6, #0x1fff\n\t"
#endif
        "mov	r7, #0x2000\n\t"
        "mov	r3, #0\n\t"
        "\n"
    "L_mc_pkb_%=:\n\t"
        "ldr	r12, [%[perm]]\n\t"
        "add	%[perm], %[perm], #4\n\t"
        "ldr	lr, [%[fftinv]]\n\t"
        "add	%[fftinv], %[fftinv], #8\n\t"
        "and	lr, lr, r6\n\t"
        "lsl	lr, lr, #13\n\t"
        "orr	r4, lr, r3\n\t"
        "lsl	r5, r12, #31\n\t"
        "orr	r4, r4, r5\n\t"
        "lsr	r5, r12, #1\n\t"
        "str	r4, [%[buf]]\n\t"
        "str	r5, [%[buf], #4]\n\t"
        "add	%[buf], %[buf], #8\n\t"
        "add	r3, r3, #1\n\t"
        "cmp	r3, r7\n\t"
        "blt	L_mc_pkb_%=\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [buf] "+r" (buf), [perm] "+r" (perm), [fftinv] "+r" (fftinv)
        :
#else
        :
        : [buf] "r" (buf), [perm] "r" (perm), [fftinv] "r" (fftinv)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r3", "r12", "lr", "r4", "r5", "r6", "r7"
    );
}

WOLFSSL_LOCAL int wc_mceliece_bs_dup_pi_neon(sword16* pi, const word64* buf);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER int wc_mceliece_bs_dup_pi_neon(sword16* pi_p,
    const word64* buf_p)
#else
WC_OMIT_FRAME_POINTER int wc_mceliece_bs_dup_pi_neon(sword16* pi,
    const word64* buf)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register sword16* pi __asm__ ("r0") = (sword16*)pi_p;
    register const word64* buf __asm__ ("r1") = (const word64*)buf_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "mov	r8, #0\n\t"
        "mov	r6, #0x2000\n\t"
        "mov	r2, %[buf]\n\t"
        "ldr	r12, [r2]\n\t"
        "ldr	lr, [r2, #4]\n\t"
        "lsr	r5, r12, #31\n\t"
        "lsl	lr, lr, #1\n\t"
        "orr	r5, r5, lr\n\t"
        "add	r2, r2, #8\n\t"
        "mov	r3, #1\n\t"
        "\n"
    "L_mc_dup_c_%=:\n\t"
        "ldr	r12, [r2]\n\t"
        "ldr	lr, [r2, #4]\n\t"
        "lsr	r4, r12, #31\n\t"
        "lsl	lr, lr, #1\n\t"
        "orr	r4, r4, lr\n\t"
        "cmp	r4, r5\n\t"
        "beq	L_mc_dup_bad_%=\n\t"
        "mov	r5, r4\n\t"
        "add	r2, r2, #8\n\t"
        "add	r3, r3, #1\n\t"
        "cmp	r3, r6\n\t"
        "blt	L_mc_dup_c_%=\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r7, #0xff\n\t"
        "orr	r7, r7, #0x1f00\n\t"
#else
        "mov	r7, #0x1fff\n\t"
#endif
        "mov	r2, %[buf]\n\t"
        "mov	r3, #0\n\t"
        "\n"
    "L_mc_dup_pi_%=:\n\t"
        "ldr	r12, [r2]\n\t"
        "and	r12, r12, r7\n\t"
        "strh	r12, [%[pi]]\n\t"
        "add	%[pi], %[pi], #2\n\t"
        "add	r2, r2, #8\n\t"
        "add	r3, r3, #1\n\t"
        "cmp	r3, r6\n\t"
        "blt	L_mc_dup_pi_%=\n\t"
        "b	L_mc_dup_end_%=\n\t"
        "\n"
    "L_mc_dup_bad_%=:\n\t"
        "mov	r8, #0\n\t"
        "sub	r8, r8, #1\n\t"
        "\n"
    "L_mc_dup_end_%=:\n\t"
        "mov	%[pi], r8\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [pi] "+r" (pi), [buf] "+r" (buf)
        :
#else
        :
        : [pi] "r" (pi), [buf] "r" (buf)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r2", "r3", "r12", "lr", "r4", "r5", "r6", "r7", "r8"
    );
    return (word32)(size_t)pi;
}

WOLFSSL_LOCAL void wc_mceliece_bs_debitslice_neon(word64* out, word64* in);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_bs_debitslice_neon(word64* out_p,
    word64* in_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_bs_debitslice_neon(word64* out,
    word64* in)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word64* out __asm__ ("r0") = (word64*)out_p;
    register word64* in __asm__ ("r1") = (word64*)in_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "mov	r10, #0\n\t"
        "mov	r2, %[in]\n\t"
        "mov	r3, #0\n\t"
        "\n"
    "L_mc_dbs_i_%=:\n\t"
        "mov	r12, #0\n\t"
        "\n"
    "L_mc_dbs_l_%=:\n\t"
        "mov	lr, #0\n\t"
        "\n"
    "L_mc_dbs_r_%=:\n\t"
        "lsl	r5, r12, #3\n\t"
        "add	r5, r5, r2\n\t"
        "lsr	r9, lr, #5\n\t"
        "lsl	r9, r9, #2\n\t"
        "add	r5, r5, r9\n\t"
        "and	r9, lr, #31\n\t"
        "mov	r6, #0\n\t"
        "mov	r4, #0\n\t"
        "\n"
    "L_mc_dbs_j_%=:\n\t"
        "ldr	r7, [r5]\n\t"
        "lsr	r7, r7, r9\n\t"
        "and	r7, r7, #1\n\t"
        "lsl	r7, r7, r4\n\t"
        "orr	r6, r6, r7\n\t"
        "add	r5, r5, #32\n\t"
        "add	r4, r4, #1\n\t"
        "cmp	r4, #13\n\t"
        "blt	L_mc_dbs_j_%=\n\t"
        "str	r6, [%[out]]\n\t"
        "str	r10, [%[out], #4]\n\t"
        "add	%[out], %[out], #8\n\t"
        "add	lr, lr, #1\n\t"
        "cmp	lr, #0x40\n\t"
        "blt	L_mc_dbs_r_%=\n\t"
        "add	r12, r12, #1\n\t"
        "cmp	r12, #4\n\t"
        "blt	L_mc_dbs_l_%=\n\t"
        "add	r2, r2, #0x1a0\n\t"
        "add	r3, r3, #1\n\t"
        "cmp	r3, #32\n\t"
        "blt	L_mc_dbs_i_%=\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [out] "+r" (out), [in] "+r" (in)
        :
#else
        :
        : [out] "r" (out), [in] "r" (in)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r2", "r3", "r12", "lr", "r4", "r5", "r6", "r7", "r8",
            "r9", "r10"
    );
}

WOLFSSL_LOCAL void wc_mceliece_bs_tobitslice2x_neon(word64* out0, word64* out1,
    const word64* in);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_bs_tobitslice2x_neon(word64* out0_p,
    word64* out1_p, const word64* in_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_bs_tobitslice2x_neon(word64* out0,
    word64* out1, const word64* in)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word64* out0 __asm__ ("r0") = (word64*)out0_p;
    register word64* out1 __asm__ ("r1") = (word64*)out1_p;
    register const word64* in __asm__ ("r2") = (const word64*)in_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "mov	r3, #0\n\t"
        "\n"
    "L_mc_tbs_i_%=:\n\t"
        "mov	r12, #0\n\t"
        "\n"
    "L_mc_tbs_j_%=:\n\t"
        "mov	lr, #0\n\t"
        "\n"
    "L_mc_tbs_k_%=:\n\t"
        "rsb	r4, r12, #12\n\t"
        "lsl	r5, r3, #11\n\t"
        "add	r5, r5, %[in]\n\t"
        "lsl	r8, lr, #9\n\t"
        "add	r5, r5, r8\n\t"
        "mov	r9, #0\n\t"
        "mov	r6, #0\n\t"
        "\n"
    "L_mc_tbs_lo_0_%=:\n\t"
        "ldr	r7, [r5]\n\t"
        "add	r5, r5, #8\n\t"
        "lsr	r8, r7, r4\n\t"
        "and	r8, r8, #1\n\t"
        "lsl	r8, r8, r6\n\t"
        "orr	r9, r9, r8\n\t"
        "add	r6, r6, #1\n\t"
        "cmp	r6, #32\n\t"
        "blt	L_mc_tbs_lo_0_%=\n\t"
        "str	r9, [%[out0]]\n\t"
        "mov	r9, #0\n\t"
        "mov	r6, #0\n\t"
        "\n"
    "L_mc_tbs_hi_0_%=:\n\t"
        "ldr	r7, [r5]\n\t"
        "add	r5, r5, #8\n\t"
        "lsr	r8, r7, r4\n\t"
        "and	r8, r8, #1\n\t"
        "lsl	r8, r8, r6\n\t"
        "orr	r9, r9, r8\n\t"
        "add	r6, r6, #1\n\t"
        "cmp	r6, #32\n\t"
        "blt	L_mc_tbs_hi_0_%=\n\t"
        "str	r9, [%[out0], #4]\n\t"
        "add	r4, r12, #13\n\t"
        "lsl	r5, r3, #11\n\t"
        "add	r5, r5, %[in]\n\t"
        "lsl	r8, lr, #9\n\t"
        "add	r5, r5, r8\n\t"
        "mov	r9, #0\n\t"
        "mov	r6, #0\n\t"
        "\n"
    "L_mc_tbs_lo_1_%=:\n\t"
        "ldr	r7, [r5]\n\t"
        "add	r5, r5, #8\n\t"
        "lsr	r8, r7, r4\n\t"
        "and	r8, r8, #1\n\t"
        "lsl	r8, r8, r6\n\t"
        "orr	r9, r9, r8\n\t"
        "add	r6, r6, #1\n\t"
        "cmp	r6, #32\n\t"
        "blt	L_mc_tbs_lo_1_%=\n\t"
        "str	r9, [%[out1]]\n\t"
        "mov	r9, #0\n\t"
        "mov	r6, #0\n\t"
        "\n"
    "L_mc_tbs_hi_1_%=:\n\t"
        "ldr	r7, [r5]\n\t"
        "add	r5, r5, #8\n\t"
        "lsr	r8, r7, r4\n\t"
        "and	r8, r8, #1\n\t"
        "lsl	r8, r8, r6\n\t"
        "orr	r9, r9, r8\n\t"
        "add	r6, r6, #1\n\t"
        "cmp	r6, #32\n\t"
        "blt	L_mc_tbs_hi_1_%=\n\t"
        "str	r9, [%[out1], #4]\n\t"
        "add	%[out0], %[out0], #8\n\t"
        "add	%[out1], %[out1], #8\n\t"
        "add	lr, lr, #1\n\t"
        "cmp	lr, #4\n\t"
        "blt	L_mc_tbs_k_%=\n\t"
        "add	r12, r12, #1\n\t"
        "cmp	r12, #13\n\t"
        "blt	L_mc_tbs_j_%=\n\t"
        "add	r3, r3, #1\n\t"
        "cmp	r3, #32\n\t"
        "blt	L_mc_tbs_i_%=\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [out0] "+r" (out0), [out1] "+r" (out1), [in] "+r" (in)
        :
#else
        :
        : [out0] "r" (out0), [out1] "r" (out1), [in] "r" (in)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r3", "r12", "lr", "r4", "r5", "r6", "r7", "r8", "r9"
    );
}

WOLFSSL_LOCAL void wc_mceliece_bs_gload_neon(word16* g, word16* fftw,
    const byte* gbytes, int t);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_bs_gload_neon(word16* g_p,
    word16* fftw_p, const byte* gbytes_p, int t_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_bs_gload_neon(word16* g, word16* fftw,
    const byte* gbytes, int t)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word16* g __asm__ ("r0") = (word16*)g_p;
    register word16* fftw __asm__ ("r1") = (word16*)fftw_p;
    register const byte* gbytes __asm__ ("r2") = (const byte*)gbytes_p;
    register int t __asm__ ("r3") = (int)t_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r7, #0xff\n\t"
        "orr	r7, r7, #0x1f00\n\t"
#else
        "mov	r7, #0x1fff\n\t"
#endif
        "lsl	lr, %[t], #1\n\t"
        "add	lr, %[g], lr\n\t"
        "mov	r4, #1\n\t"
        "strh	r4, [lr]\n\t"
        "mov	r12, #0\n\t"
        "mov	r5, %[g]\n\t"
        "\n"
    "L_mc_gld_ld_%=:\n\t"
        "cmp	r12, %[t]\n\t"
        "bge	L_mc_gld_lde_%=\n\t"
        "ldrh	r4, [%[gbytes]]\n\t"
        "add	%[gbytes], %[gbytes], #2\n\t"
        "and	r4, r4, r7\n\t"
        "strh	r4, [r5]\n\t"
        "add	r5, r5, #2\n\t"
        "add	r12, r12, #1\n\t"
        "b	L_mc_gld_ld_%=\n\t"
        "\n"
    "L_mc_gld_lde_%=:\n\t"
        "mov	r12, #0\n\t"
        "mov	r6, %[fftw]\n\t"
        "\n"
    "L_mc_gld_f_%=:\n\t"
        "cmp	r12, #0x80\n\t"
        "bge	L_mc_gld_fe_%=\n\t"
        "cmp	r12, %[t]\n\t"
        "bgt	L_mc_gld_fz_%=\n\t"
        "lsl	lr, r12, #1\n\t"
        "add	lr, %[g], lr\n\t"
        "ldrh	r4, [lr]\n\t"
        "b	L_mc_gld_fs_%=\n\t"
        "\n"
    "L_mc_gld_fz_%=:\n\t"
        "mov	r4, #0\n\t"
        "\n"
    "L_mc_gld_fs_%=:\n\t"
        "strh	r4, [r6]\n\t"
        "add	r6, r6, #2\n\t"
        "add	r12, r12, #1\n\t"
        "b	L_mc_gld_f_%=\n\t"
        "\n"
    "L_mc_gld_fe_%=:\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [g] "+r" (g), [fftw] "+r" (fftw), [gbytes] "+r" (gbytes),
          [t] "+r" (t)
        :
#else
        :
        : [g] "r" (g), [fftw] "r" (fftw), [gbytes] "r" (gbytes), [t] "r" (t)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r12", "lr", "r4", "r5", "r6", "r7"
    );
}

WOLFSSL_LOCAL void wc_mceliece_cb_layer_neon(sword16* p, const byte* cb, int s,
    int n);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_cb_layer_neon(sword16* p_p,
    const byte* cb_p, int s_p, int n_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_cb_layer_neon(sword16* p, const byte* cb,
    int s, int n)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register sword16* p __asm__ ("r0") = (sword16*)p_p;
    register const byte* cb __asm__ ("r1") = (const byte*)cb_p;
    register int s __asm__ ("r2") = (int)s_p;
    register int n __asm__ ("r3") = (int)n_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "mov	r12, #1\n\t"
        "lsl	r12, r12, %[s]\n\t"
        "lsl	lr, r12, #1\n\t"
        "mov	r6, #0\n\t"
        "mov	r4, #0\n\t"
        "\n"
    "L_mc_cbl_i_%=:\n\t"
        "cmp	r4, %[n]\n\t"
        "bge	L_mc_cbl_end_%=\n\t"
        "mov	r5, #0\n\t"
        "\n"
    "L_mc_cbl_j_%=:\n\t"
        "cmp	r5, r12\n\t"
        "bge	L_mc_cbl_ni_%=\n\t"
        "lsr	r11, r6, #3\n\t"
        "add	r11, %[cb], r11\n\t"
        "ldrb	r11, [r11]\n\t"
        "and	r7, r6, #7\n\t"
        "lsr	r11, r11, r7\n\t"
        "and	r11, r11, #1\n\t"
        "rsb	r11, r11, #0\n\t"
        "add	r7, r4, r5\n\t"
        "lsl	r7, r7, #1\n\t"
        "add	r7, %[p], r7\n\t"
        "add	r8, r7, lr\n\t"
        "ldrh	r9, [r7]\n\t"
        "ldrh	r10, [r8]\n\t"
        "eor	r9, r9, r10\n\t"
        "and	r9, r9, r11\n\t"
        "ldrh	r10, [r7]\n\t"
        "eor	r10, r10, r9\n\t"
        "strh	r10, [r7]\n\t"
        "ldrh	r10, [r8]\n\t"
        "eor	r10, r10, r9\n\t"
        "strh	r10, [r8]\n\t"
        "add	r6, r6, #1\n\t"
        "add	r5, r5, #1\n\t"
        "b	L_mc_cbl_j_%=\n\t"
        "\n"
    "L_mc_cbl_ni_%=:\n\t"
        "add	r4, r4, lr\n\t"
        "b	L_mc_cbl_i_%=\n\t"
        "\n"
    "L_mc_cbl_end_%=:\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [p] "+r" (p), [cb] "+r" (cb), [s] "+r" (s), [n] "+r" (n)
        :
#else
        :
        : [p] "r" (p), [cb] "r" (cb), [s] "r" (s), [n] "r" (n)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r12", "lr", "r4", "r5", "r6", "r7", "r8", "r9",
            "r10", "r11"
    );
}

WOLFSSL_LOCAL int wc_mceliece_bs_mov_columns_neon(word64* mat, int nbiW,
    int nRows, sword16* pi, word64* pivots);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER int wc_mceliece_bs_mov_columns_neon(word64* mat_p,
    int nbiW_p, int nRows_p, sword16* pi_p, word64* pivots_p)
#else
WC_OMIT_FRAME_POINTER int wc_mceliece_bs_mov_columns_neon(word64* mat, int nbiW,
    int nRows, sword16* pi, word64* pivots)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word64* mat __asm__ ("r0") = (word64*)mat_p;
    register int nbiW __asm__ ("r1") = (int)nbiW_p;
    register int nRows __asm__ ("r2") = (int)nRows_p;
    register sword16* pi __asm__ ("r3") = (sword16*)pi_p;
    register word64* pivots __asm__ ("r12") = (word64*)pivots_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "push	{%[pivots]}\n\t"
        "sub	sp, sp, #0x190\n\t"
        "mov	r12, #0\n\t"
        "mov	r8, #1\n\t"
        "vmov	d16, r8, r12\n\t"
        "mvn	r8, r12\n\t"
        "vmov	d24, r8, r8\n\t"
        "veor	q7, q7, q7\n\t"
        "sub	r8, %[nRows], #32\n\t"
        "and	lr, r8, #63\n\t"
        "rsb	r4, lr, #0x40\n\t"
        "lsr	r9, r8, #6\n\t"
        "mul	r11, r8, %[nbiW]\n\t"
        "add	r11, r11, r9\n\t"
        "lsl	r11, r11, #3\n\t"
        "add	r10, %[mat], r11\n\t"
        "lsl	r11, %[nbiW], #3\n\t"
        "mov	r5, #0\n\t"
        "\n"
    "L_mc_mov_p1_%=:\n\t"
        "cmp	r5, #32\n\t"
        "bge	L_mc_mov_p1x_%=\n\t"
        "vld1.8	{d0}, [r10]\n\t"
        "add	r8, r10, #8\n\t"
        "vld1.8	{d2}, [r8]\n\t"
        "rsb	r8, lr, #0\n\t"
        "vmov	d22, r8, r12\n\t"
        "vshl.u64	q0, q0, q11\n\t"
        "vmov	d22, r4, r12\n\t"
        "vshl.u64	q1, q1, q11\n\t"
        "vorr	q0, q0, q1\n\t"
        "lsl	r8, r5, #3\n\t"
        "add	r8, sp, r8\n\t"
        "vst1.8	{d0}, [r8]\n\t"
        "add	r10, r10, r11\n\t"
        "add	r5, r5, #1\n\t"
        "b	L_mc_mov_p1_%=\n\t"
        "\n"
    "L_mc_mov_p1x_%=:\n\t"
        "str	lr, [sp, #384]\n\t"
        "str	r4, [sp, #388]\n\t"
        "mov	r5, #0\n\t"
        "\n"
    "L_mc_mov_p2_%=:\n\t"
        "cmp	r5, #32\n\t"
        "bge	L_mc_mov_p2e_%=\n\t"
        "lsl	r8, r5, #3\n\t"
        "add	r8, sp, r8\n\t"
        "vld1.8	{d4}, [r8]\n\t"
        "add	r6, r5, #1\n\t"
        "\n"
    "L_mc_mov_or_%=:\n\t"
        "cmp	r6, #32\n\t"
        "bge	L_mc_mov_ore_%=\n\t"
        "lsl	r8, r6, #3\n\t"
        "add	r8, sp, r8\n\t"
        "vld1.8	{d6}, [r8]\n\t"
        "vorr	q2, q2, q3\n\t"
        "add	r6, r6, #1\n\t"
        "b	L_mc_mov_or_%=\n\t"
        "\n"
    "L_mc_mov_ore_%=:\n\t"
        "vmov	r8, r9, d4\n\t"
        "orr	r10, r8, r9\n\t"
        "cmp	r10, #0\n\t"
        "beq	L_mc_mov_fail_%=\n\t"
        "rbit	r10, r8\n\t"
        "clz	r10, r10\n\t"
        "rbit	r11, r9\n\t"
        "clz	r11, r11\n\t"
        "add	r11, r11, #32\n\t"
        "rsb	r7, r8, #0\n\t"
        "orr	r7, r7, r8\n\t"
        "asr	r7, r7, #31\n\t"
        "and	r10, r10, r7\n\t"
        "bic	r11, r11, r7\n\t"
        "orr	r7, r10, r11\n\t"
        "lsl	r8, r5, #2\n\t"
        "add	r8, sp, r8\n\t"
        "add	r8, r8, #0x100\n\t"
        "str	r7, [r8]\n\t"
        "vmov	d22, r7, r12\n\t"
        "vshl.u64	q9, q8, q11\n\t"
        "vorr	q7, q7, q9\n\t"
        "lsl	r8, r5, #3\n\t"
        "add	r10, sp, r8\n\t"
        "vld1.8	{d8}, [r10]\n\t"
        "add	r6, r5, #1\n\t"
        "\n"
    "L_mc_mov_i1_%=:\n\t"
        "cmp	r6, #32\n\t"
        "bge	L_mc_mov_i1e_%=\n\t"
        "rsb	r8, r7, #0\n\t"
        "vmov	d22, r8, r12\n\t"
        "vshl.u64	q2, q4, q11\n\t"
        "vmov	r8, r9, d4\n\t"
        "and	r8, r8, #1\n\t"
        "sub	r8, r8, #1\n\t"
        "vmov	d20, r8, r8\n\t"
        "lsl	r8, r6, #3\n\t"
        "add	r8, sp, r8\n\t"
        "vld1.8	{d10}, [r8]\n\t"
        "vand	q5, q5, q10\n\t"
        "veor	q4, q4, q5\n\t"
        "add	r6, r6, #1\n\t"
        "b	L_mc_mov_i1_%=\n\t"
        "\n"
    "L_mc_mov_i1e_%=:\n\t"
        "vst1.8	{d8}, [r10]\n\t"
        "add	r6, r5, #1\n\t"
        "\n"
    "L_mc_mov_i2_%=:\n\t"
        "cmp	r6, #32\n\t"
        "bge	L_mc_mov_i2e_%=\n\t"
        "lsl	r8, r6, #3\n\t"
        "add	r11, sp, r8\n\t"
        "vld1.8	{d10}, [r11]\n\t"
        "rsb	r8, r7, #0\n\t"
        "vmov	d22, r8, r12\n\t"
        "vshl.u64	q2, q5, q11\n\t"
        "vmov	r8, r9, d4\n\t"
        "and	r8, r8, #1\n\t"
        "rsb	r8, r8, #0\n\t"
        "vmov	d20, r8, r8\n\t"
        "vand	q2, q4, q10\n\t"
        "veor	q5, q5, q2\n\t"
        "vst1.8	{d10}, [r11]\n\t"
        "add	r6, r6, #1\n\t"
        "b	L_mc_mov_i2_%=\n\t"
        "\n"
    "L_mc_mov_i2e_%=:\n\t"
        "add	r5, r5, #1\n\t"
        "b	L_mc_mov_p2_%=\n\t"
        "\n"
    "L_mc_mov_p2e_%=:\n\t"
        "ldr	r8, [sp, #400]\n\t"
        "vst1.8	{d14}, [r8]\n\t"
        "sub	r8, %[nRows], #32\n\t"
        "lsl	r8, r8, #1\n\t"
        "add	r10, %[pi], r8\n\t"
        "mov	r5, #0\n\t"
        "\n"
    "L_mc_mov_p3i_%=:\n\t"
        "cmp	r5, #32\n\t"
        "bge	L_mc_mov_p3ie_%=\n\t"
        "lsl	r8, r5, #2\n\t"
        "add	r8, sp, r8\n\t"
        "add	r8, r8, #0x100\n\t"
        "ldr	r7, [r8]\n\t"
        "lsl	r8, r5, #1\n\t"
        "add	r8, r10, r8\n\t"
        "ldrh	r9, [r8]\n\t"
        "add	r6, r5, #1\n\t"
        "\n"
    "L_mc_mov_p3j_%=:\n\t"
        "cmp	r6, #0x40\n\t"
        "bge	L_mc_mov_p3je_%=\n\t"
        "lsl	r8, r6, #1\n\t"
        "add	r8, r10, r8\n\t"
        "ldrh	lr, [r8]\n\t"
        "eor	r4, r9, lr\n\t"
        "eor	%[pi], r6, r7\n\t"
        "rsb	r11, %[pi], #0\n\t"
        "orr	%[pi], %[pi], r11\n\t"
        "lsr	%[pi], %[pi], #31\n\t"
        "sub	%[pi], %[pi], #1\n\t"
        "and	r4, r4, %[pi]\n\t"
        "eor	r9, r9, r4\n\t"
        "eor	lr, lr, r4\n\t"
        "strh	lr, [r8]\n\t"
        "add	r6, r6, #1\n\t"
        "b	L_mc_mov_p3j_%=\n\t"
        "\n"
    "L_mc_mov_p3je_%=:\n\t"
        "lsl	r11, r5, #1\n\t"
        "add	r11, r10, r11\n\t"
        "strh	r9, [r11]\n\t"
        "add	r5, r5, #1\n\t"
        "b	L_mc_mov_p3i_%=\n\t"
        "\n"
    "L_mc_mov_p3ie_%=:\n\t"
        "ldr	lr, [sp, #384]\n\t"
        "ldr	r4, [sp, #388]\n\t"
        "sub	r8, %[nRows], #32\n\t"
        "lsr	r11, r8, #6\n\t"
        "mov	r5, #0\n\t"
        "\n"
    "L_mc_mov_p4_%=:\n\t"
        "cmp	r5, %[nRows]\n\t"
        "bge	L_mc_mov_p4e_%=\n\t"
        "mul	r8, r5, %[nbiW]\n\t"
        "add	r8, r8, r11\n\t"
        "lsl	r8, r8, #3\n\t"
        "add	r10, %[mat], r8\n\t"
        "vld1.8	{d0}, [r10]\n\t"
        "add	r8, r10, #8\n\t"
        "vld1.8	{d2}, [r8]\n\t"
        "rsb	r8, lr, #0\n\t"
        "vmov	d22, r8, r12\n\t"
        "vshl.u64	q6, q0, q11\n\t"
        "vmov	d22, r4, r12\n\t"
        "vshl.u64	q3, q1, q11\n\t"
        "vorr	q6, q6, q3\n\t"
        "mov	r6, #0\n\t"
        "\n"
    "L_mc_mov_p4j_%=:\n\t"
        "cmp	r6, #32\n\t"
        "bge	L_mc_mov_p4je_%=\n\t"
        "lsl	r8, r6, #2\n\t"
        "add	r8, sp, r8\n\t"
        "add	r8, r8, #0x100\n\t"
        "ldr	r7, [r8]\n\t"
        "rsb	r8, r6, #0\n\t"
        "vmov	d22, r8, r12\n\t"
        "vshl.u64	q2, q6, q11\n\t"
        "rsb	r8, r7, #0\n\t"
        "vmov	d22, r8, r12\n\t"
        "vshl.u64	q3, q6, q11\n\t"
        "veor	q2, q2, q3\n\t"
        "vand	q2, q2, q8\n\t"
        "vmov	d22, r7, r12\n\t"
        "vshl.u64	q3, q2, q11\n\t"
        "veor	q6, q6, q3\n\t"
        "vmov	d22, r6, r12\n\t"
        "vshl.u64	q3, q2, q11\n\t"
        "veor	q6, q6, q3\n\t"
        "add	r6, r6, #1\n\t"
        "b	L_mc_mov_p4j_%=\n\t"
        "\n"
    "L_mc_mov_p4je_%=:\n\t"
        "rsb	r8, r4, #0\n\t"
        "vmov	d22, r8, r12\n\t"
        "vshl.u64	q10, q12, q11\n\t"
        "vmov	d22, lr, r12\n\t"
        "vshl.u64	q2, q6, q11\n\t"
        "vand	q0, q0, q10\n\t"
        "vorr	q0, q0, q2\n\t"
        "vst1.8	{d0}, [r10]\n\t"
        "rsb	r8, r4, #0\n\t"
        "vmov	d22, r8, r12\n\t"
        "vshl.u64	q2, q6, q11\n\t"
        "vbic	q1, q1, q10\n\t"
        "vorr	q1, q1, q2\n\t"
        "add	r8, r10, #8\n\t"
        "vst1.8	{d2}, [r8]\n\t"
        "add	r5, r5, #1\n\t"
        "b	L_mc_mov_p4_%=\n\t"
        "\n"
    "L_mc_mov_p4e_%=:\n\t"
        "mov	%[mat], #0\n\t"
        "b	L_mc_mov_done_%=\n\t"
        "\n"
    "L_mc_mov_fail_%=:\n\t"
        "ldr	r8, [sp, #400]\n\t"
        "vst1.8	{d14}, [r8]\n\t"
        "mov	%[mat], #0\n\t"
        "sub	%[mat], %[mat], #1\n\t"
        "\n"
    "L_mc_mov_done_%=:\n\t"
        "add	sp, sp, #0x190\n\t"
        "pop	{%[pivots]}\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [mat] "+r" (mat), [nbiW] "+r" (nbiW), [nRows] "+r" (nRows),
          [pi] "+r" (pi), [pivots] "+r" (pivots)
        :
#else
        :
        : [mat] "r" (mat), [nbiW] "r" (nbiW), [nRows] "r" (nRows),
          [pi] "r" (pi), [pivots] "r" (pivots)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "lr", "r4", "r5", "r6", "r7", "r8", "r9", "r10",
            "r11", "q0", "q1", "q2", "q3", "q4", "q5", "q6", "q7", "q8", "q9",
            "q10", "q11", "q12"
    );
    return (word32)(size_t)mat;
}

WOLFSSL_LOCAL void wc_mceliece_i32_sort_neon(sword32* x, int n);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_i32_sort_neon(sword32* x_p, int n_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_i32_sort_neon(sword32* x, int n)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register sword32* x __asm__ ("r0") = (sword32*)x_p;
    register int n __asm__ ("r1") = (int)n_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "cmp	%[n], #2\n\t"
        "blt	L_mc_is_ret_%=\n\t"
        "mov	r2, #1\n\t"
        "\n"
    "L_mc_is_top_%=:\n\t"
        "sub	r5, %[n], r2\n\t"
        "cmp	r2, r5\n\t"
        "bge	L_mc_is_tope_%=\n\t"
        "add	r2, r2, r2\n\t"
        "b	L_mc_is_top_%=\n\t"
        "\n"
    "L_mc_is_tope_%=:\n\t"
        "mov	r3, r2\n\t"
        "\n"
    "L_mc_is_p_%=:\n\t"
        "cmp	r3, #0\n\t"
        "ble	L_mc_is_ret_%=\n\t"
        "mov	lr, #0\n\t"
        "\n"
    "L_mc_is_b_%=:\n\t"
        "sub	r5, %[n], r3\n\t"
        "cmp	lr, r5\n\t"
        "bge	L_mc_is_be_%=\n\t"
        "add	r4, lr, r3\n\t"
        "cmp	r4, r5\n\t"
        "ble	L_mc_is_lim_%=\n\t"
        "mov	r4, r5\n\t"
        "\n"
    "L_mc_is_lim_%=:\n\t"
        "mov	r12, lr\n\t"
        "\n"
    "L_mc_is_i_%=:\n\t"
        "cmp	r12, r4\n\t"
        "bge	L_mc_is_ie_%=\n\t"
        "lsl	r6, r12, #2\n\t"
        "add	r6, %[x], r6\n\t"
        "add	r5, r12, r3\n\t"
        "lsl	r7, r5, #2\n\t"
        "add	r7, %[x], r7\n\t"
        "ldr	r8, [r6]\n\t"
        "ldr	r9, [r7]\n\t"
        "sub	r10, r8, r9\n\t"
        "asr	r11, r10, #31\n\t"
        "and	r10, r10, r11\n\t"
        "add	r11, r9, r10\n\t"
        "str	r11, [r6]\n\t"
        "sub	r11, r8, r10\n\t"
        "str	r11, [r7]\n\t"
        "add	r12, r12, #1\n\t"
        "b	L_mc_is_i_%=\n\t"
        "\n"
    "L_mc_is_ie_%=:\n\t"
        "add	lr, lr, r3\n\t"
        "add	lr, lr, r3\n\t"
        "b	L_mc_is_b_%=\n\t"
        "\n"
    "L_mc_is_be_%=:\n\t"
        "mov	r12, #0\n\t"
        "mov	lr, r2\n\t"
        "\n"
    "L_mc_is_q_%=:\n\t"
        "cmp	lr, r3\n\t"
        "ble	L_mc_is_qe_%=\n\t"
        "\n"
    "L_mc_is_iq_%=:\n\t"
        "sub	r5, %[n], lr\n\t"
        "cmp	r12, r5\n\t"
        "bge	L_mc_is_iqe_%=\n\t"
        "and	r5, r12, r3\n\t"
        "cmp	r5, #0\n\t"
        "bne	L_mc_is_next_%=\n\t"
        "mov	r4, lr\n\t"
        "\n"
    "L_mc_is_r_%=:\n\t"
        "cmp	r4, r3\n\t"
        "ble	L_mc_is_re_%=\n\t"
        "add	r5, r12, r3\n\t"
        "lsl	r6, r5, #2\n\t"
        "add	r6, %[x], r6\n\t"
        "add	r5, r12, r4\n\t"
        "lsl	r7, r5, #2\n\t"
        "add	r7, %[x], r7\n\t"
        "ldr	r8, [r6]\n\t"
        "ldr	r9, [r7]\n\t"
        "sub	r10, r8, r9\n\t"
        "asr	r11, r10, #31\n\t"
        "and	r10, r10, r11\n\t"
        "add	r11, r9, r10\n\t"
        "str	r11, [r6]\n\t"
        "sub	r11, r8, r10\n\t"
        "str	r11, [r7]\n\t"
        "asr	r4, r4, #1\n\t"
        "b	L_mc_is_r_%=\n\t"
        "\n"
    "L_mc_is_re_%=:\n\t"
        "\n"
    "L_mc_is_next_%=:\n\t"
        "add	r12, r12, #1\n\t"
        "b	L_mc_is_iq_%=\n\t"
        "\n"
    "L_mc_is_iqe_%=:\n\t"
        "asr	lr, lr, #1\n\t"
        "b	L_mc_is_q_%=\n\t"
        "\n"
    "L_mc_is_qe_%=:\n\t"
        "asr	r3, r3, #1\n\t"
        "b	L_mc_is_p_%=\n\t"
        "\n"
    "L_mc_is_ret_%=:\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [x] "+r" (x), [n] "+r" (n)
        :
#else
        :
        : [x] "r" (x), [n] "r" (n)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r2", "r3", "r12", "lr", "r4", "r5", "r6", "r7", "r8",
            "r9", "r10", "r11"
    );
}

WOLFSSL_LOCAL void wc_mceliece_cb_compose10_neon(sword32* a, sword32* b, int n,
    int w);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_cb_compose10_neon(sword32* a_p,
    sword32* b_p, int n_p, int w_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_cb_compose10_neon(sword32* a, sword32* b,
    int n, int w)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register sword32* a __asm__ ("r0") = (sword32*)a_p;
    register sword32* b __asm__ ("r1") = (sword32*)b_p;
    register int n __asm__ ("r2") = (int)n_p;
    register int w __asm__ ("r3") = (int)w_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "mov	r4, %[a]\n\t"
        "mov	r5, %[b]\n\t"
        "mov	r6, %[n]\n\t"
        "mov	r7, %[w]\n\t"
        "mov	%[b], r4\n\t"
        "mov	%[n], r5\n\t"
        "mov	%[a], #0\n\t"
        "\n"
    "L_mc_c10_1_%=:\n\t"
        "cmp	%[a], r6\n\t"
        "bge	L_mc_c10_1e_%=\n\t"
        "ldr	%[w], [%[b]]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r12, #0xff\n\t"
        "orr	r12, r12, #0xff00\n\t"
#else
        "mov	r12, #0xffff\n\t"
#endif
        "and	%[w], %[w], r12\n\t"
        "lsl	%[w], %[w], #10\n\t"
        "ldr	r9, [%[n]]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xff\n\t"
        "orr	r10, r10, #0x300\n\t"
#else
        "mov	r10, #0x3ff\n\t"
#endif
        "and	r9, r9, r10\n\t"
        "orr	%[w], %[w], r9\n\t"
        "str	%[w], [%[n]]\n\t"
        "add	%[b], %[b], #4\n\t"
        "add	%[n], %[n], #4\n\t"
        "add	%[a], %[a], #1\n\t"
        "b	L_mc_c10_1_%=\n\t"
        "\n"
    "L_mc_c10_1e_%=:\n\t"
        "mov	r8, #1\n\t"
        "\n"
    "L_mc_c10_i_%=:\n\t"
        "sub	%[w], r7, #1\n\t"
        "cmp	r8, %[w]\n\t"
        "bge	L_mc_c10_ie_%=\n\t"
        "mov	%[b], r4\n\t"
        "mov	%[n], r5\n\t"
        "mov	%[a], #0\n\t"
        "\n"
    "L_mc_c10_a1_%=:\n\t"
        "cmp	%[a], r6\n\t"
        "bge	L_mc_c10_a1e_%=\n\t"
        "ldr	%[w], [%[n]]\n\t"
        "movw	r12, #0xfc00\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "orr	r12, r12, #0xff000000\n\t"
        "orr	r12, r12, #0xff0000\n\t"
#else
        "movt	r12, #0xffff\n\t"
#endif
        "and	%[w], %[w], r12\n\t"
        "lsl	%[w], %[w], #6\n\t"
        "orr	%[w], %[w], %[a]\n\t"
        "str	%[w], [%[b]]\n\t"
        "add	%[b], %[b], #4\n\t"
        "add	%[n], %[n], #4\n\t"
        "add	%[a], %[a], #1\n\t"
        "b	L_mc_c10_a1_%=\n\t"
        "\n"
    "L_mc_c10_a1e_%=:\n\t"
        "mov	%[a], r4\n\t"
        "mov	%[b], r6\n\t"
        "bl	wc_mceliece_i32_sort_neon\n\t"
        "mov	%[b], r4\n\t"
        "mov	%[n], r5\n\t"
        "mov	%[a], #0\n\t"
        "\n"
    "L_mc_c10_a2_%=:\n\t"
        "cmp	%[a], r6\n\t"
        "bge	L_mc_c10_a2e_%=\n\t"
        "ldr	%[w], [%[b]]\n\t"
        "lsl	%[w], %[w], #20\n\t"
        "ldr	r12, [%[n]]\n\t"
        "orr	%[w], %[w], r12\n\t"
        "str	%[w], [%[b]]\n\t"
        "add	%[b], %[b], #4\n\t"
        "add	%[n], %[n], #4\n\t"
        "add	%[a], %[a], #1\n\t"
        "b	L_mc_c10_a2_%=\n\t"
        "\n"
    "L_mc_c10_a2e_%=:\n\t"
        "mov	%[a], r4\n\t"
        "mov	%[b], r6\n\t"
        "bl	wc_mceliece_i32_sort_neon\n\t"
        "mov	%[b], r4\n\t"
        "mov	%[n], r5\n\t"
        "mov	%[a], #0\n\t"
        "\n"
    "L_mc_c10_a3_%=:\n\t"
        "cmp	%[a], r6\n\t"
        "bge	L_mc_c10_a3e_%=\n\t"
        "ldr	%[w], [%[b]]\n\t"
        "movw	r12, #0xffff\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "orr	r12, r12, #0xf0000\n\t"
#else
        "movt	r12, #0xf\n\t"
#endif
        "and	r9, %[w], r12\n\t"
        "movw	r12, #0xfc00\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "orr	r12, r12, #0xf0000\n\t"
#else
        "movt	r12, #0xf\n\t"
#endif
        "and	%[w], %[w], r12\n\t"
        "ldr	r12, [%[n]]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xff\n\t"
        "orr	r10, r10, #0x300\n\t"
#else
        "mov	r10, #0x3ff\n\t"
#endif
        "and	r12, r12, r10\n\t"
        "orr	%[w], %[w], r12\n\t"
        "eor	r12, %[w], r9\n\t"
        "sub	r11, r9, %[w]\n\t"
        "eor	r10, r11, r9\n\t"
        "and	r10, r10, r12\n\t"
        "eor	r11, r11, r10\n\t"
        "asr	r11, r11, #31\n\t"
        "and	r11, r11, r12\n\t"
        "eor	r10, %[w], r11\n\t"
        "str	r10, [%[n]]\n\t"
        "add	%[b], %[b], #4\n\t"
        "add	%[n], %[n], #4\n\t"
        "add	%[a], %[a], #1\n\t"
        "b	L_mc_c10_a3_%=\n\t"
        "\n"
    "L_mc_c10_a3e_%=:\n\t"
        "add	r8, r8, #1\n\t"
        "b	L_mc_c10_i_%=\n\t"
        "\n"
    "L_mc_c10_ie_%=:\n\t"
        "mov	%[n], r5\n\t"
        "mov	%[a], #0\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r12, #0xff\n\t"
        "orr	r12, r12, #0x300\n\t"
#else
        "mov	r12, #0x3ff\n\t"
#endif
        "\n"
    "L_mc_c10_f_%=:\n\t"
        "cmp	%[a], r6\n\t"
        "bge	L_mc_c10_fe_%=\n\t"
        "ldr	%[w], [%[n]]\n\t"
        "and	%[w], %[w], r12\n\t"
        "str	%[w], [%[n]]\n\t"
        "add	%[n], %[n], #4\n\t"
        "add	%[a], %[a], #1\n\t"
        "b	L_mc_c10_f_%=\n\t"
        "\n"
    "L_mc_c10_fe_%=:\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [a] "+r" (a), [b] "+r" (b), [n] "+r" (n), [w] "+r" (w)
        :
#else
        :
        : [a] "r" (a), [b] "r" (b), [n] "r" (n), [w] "r" (w)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "lr", "r4", "r5", "r6", "r7", "r8", "r12", "r9",
            "r10", "r11"
    );
}

WOLFSSL_LOCAL void wc_mceliece_cb_compose16_neon(sword32* a, sword32* b, int n,
    int w);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_cb_compose16_neon(sword32* a_p,
    sword32* b_p, int n_p, int w_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_cb_compose16_neon(sword32* a, sword32* b,
    int n, int w)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register sword32* a __asm__ ("r0") = (sword32*)a_p;
    register sword32* b __asm__ ("r1") = (sword32*)b_p;
    register int n __asm__ ("r2") = (int)n_p;
    register int w __asm__ ("r3") = (int)w_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "mov	r4, %[a]\n\t"
        "mov	r5, %[b]\n\t"
        "mov	r6, %[n]\n\t"
        "mov	r7, %[w]\n\t"
        "mov	%[b], r4\n\t"
        "mov	%[n], r5\n\t"
        "mov	%[a], #0\n\t"
        "\n"
    "L_mc_c16_1_%=:\n\t"
        "cmp	%[a], r6\n\t"
        "bge	L_mc_c16_1e_%=\n\t"
        "ldr	%[w], [%[b]]\n\t"
        "lsl	%[w], %[w], #16\n\t"
        "ldr	r12, [%[n]]\n\t"
        "uxth	r12, r12\n\t"
        "orr	%[w], %[w], r12\n\t"
        "str	%[w], [%[n]]\n\t"
        "add	%[b], %[b], #4\n\t"
        "add	%[n], %[n], #4\n\t"
        "add	%[a], %[a], #1\n\t"
        "b	L_mc_c16_1_%=\n\t"
        "\n"
    "L_mc_c16_1e_%=:\n\t"
        "mov	r8, #1\n\t"
        "\n"
    "L_mc_c16_i_%=:\n\t"
        "sub	%[w], r7, #1\n\t"
        "cmp	r8, %[w]\n\t"
        "bge	L_mc_c16_ie_%=\n\t"
        "mov	%[b], r4\n\t"
        "mov	%[n], r5\n\t"
        "mov	%[a], #0\n\t"
        "\n"
    "L_mc_c16_a1_%=:\n\t"
        "cmp	%[a], r6\n\t"
        "bge	L_mc_c16_a1e_%=\n\t"
        "ldr	%[w], [%[n]]\n\t"
        "movw	r12, #0\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "orr	r12, r12, #0xff000000\n\t"
        "orr	r12, r12, #0xff0000\n\t"
#else
        "movt	r12, #0xffff\n\t"
#endif
        "and	%[w], %[w], r12\n\t"
        "orr	%[w], %[w], %[a]\n\t"
        "str	%[w], [%[b]]\n\t"
        "add	%[b], %[b], #4\n\t"
        "add	%[n], %[n], #4\n\t"
        "add	%[a], %[a], #1\n\t"
        "b	L_mc_c16_a1_%=\n\t"
        "\n"
    "L_mc_c16_a1e_%=:\n\t"
        "mov	%[a], r4\n\t"
        "mov	%[b], r6\n\t"
        "bl	wc_mceliece_i32_sort_neon\n\t"
        "mov	%[b], r4\n\t"
        "mov	%[n], r5\n\t"
        "mov	%[a], #0\n\t"
        "\n"
    "L_mc_c16_a2_%=:\n\t"
        "cmp	%[a], r6\n\t"
        "bge	L_mc_c16_a2e_%=\n\t"
        "ldr	%[w], [%[b]]\n\t"
        "lsl	%[w], %[w], #16\n\t"
        "ldr	r12, [%[n]]\n\t"
        "uxth	r12, r12\n\t"
        "orr	%[w], %[w], r12\n\t"
        "str	%[w], [%[b]]\n\t"
        "add	%[b], %[b], #4\n\t"
        "add	%[n], %[n], #4\n\t"
        "add	%[a], %[a], #1\n\t"
        "b	L_mc_c16_a2_%=\n\t"
        "\n"
    "L_mc_c16_a2e_%=:\n\t"
        "sub	%[w], r7, #2\n\t"
        "cmp	r8, %[w]\n\t"
        "bge	L_mc_c16_sk_%=\n\t"
        "mov	%[b], r4\n\t"
        "mov	%[n], r5\n\t"
        "mov	%[a], #0\n\t"
        "\n"
    "L_mc_c16_b1_%=:\n\t"
        "cmp	%[a], r6\n\t"
        "bge	L_mc_c16_b1e_%=\n\t"
        "ldr	%[w], [%[b]]\n\t"
        "movw	r12, #0\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "orr	r12, r12, #0xff000000\n\t"
        "orr	r12, r12, #0xff0000\n\t"
#else
        "movt	r12, #0xffff\n\t"
#endif
        "and	%[w], %[w], r12\n\t"
        "ldr	r12, [%[n]]\n\t"
        "asr	r12, r12, #16\n\t"
        "orr	%[w], %[w], r12\n\t"
        "str	%[w], [%[n]]\n\t"
        "add	%[b], %[b], #4\n\t"
        "add	%[n], %[n], #4\n\t"
        "add	%[a], %[a], #1\n\t"
        "b	L_mc_c16_b1_%=\n\t"
        "\n"
    "L_mc_c16_b1e_%=:\n\t"
        "mov	%[a], r5\n\t"
        "mov	%[b], r6\n\t"
        "bl	wc_mceliece_i32_sort_neon\n\t"
        "mov	%[b], r4\n\t"
        "mov	%[n], r5\n\t"
        "mov	%[a], #0\n\t"
        "\n"
    "L_mc_c16_b2_%=:\n\t"
        "cmp	%[a], r6\n\t"
        "bge	L_mc_c16_b2e_%=\n\t"
        "ldr	%[w], [%[n]]\n\t"
        "lsl	%[w], %[w], #16\n\t"
        "ldr	r12, [%[b]]\n\t"
        "uxth	r12, r12\n\t"
        "orr	%[w], %[w], r12\n\t"
        "str	%[w], [%[n]]\n\t"
        "add	%[b], %[b], #4\n\t"
        "add	%[n], %[n], #4\n\t"
        "add	%[a], %[a], #1\n\t"
        "b	L_mc_c16_b2_%=\n\t"
        "\n"
    "L_mc_c16_b2e_%=:\n\t"
        "\n"
    "L_mc_c16_sk_%=:\n\t"
        "mov	%[a], r4\n\t"
        "mov	%[b], r6\n\t"
        "bl	wc_mceliece_i32_sort_neon\n\t"
        "mov	%[b], r4\n\t"
        "mov	%[n], r5\n\t"
        "mov	%[a], #0\n\t"
        "\n"
    "L_mc_c16_a3_%=:\n\t"
        "cmp	%[a], r6\n\t"
        "bge	L_mc_c16_a3e_%=\n\t"
        "ldr	r9, [%[n]]\n\t"
        "movw	r12, #0\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "orr	r12, r12, #0xff000000\n\t"
        "orr	r12, r12, #0xff0000\n\t"
#else
        "movt	r12, #0xffff\n\t"
#endif
        "and	%[w], r9, r12\n\t"
        "ldr	r12, [%[b]]\n\t"
        "uxth	r12, r12\n\t"
        "orr	%[w], %[w], r12\n\t"
        "eor	r12, r9, %[w]\n\t"
        "sub	r11, %[w], r9\n\t"
        "eor	r10, r11, %[w]\n\t"
        "and	r10, r10, r12\n\t"
        "eor	r11, r11, r10\n\t"
        "asr	r11, r11, #31\n\t"
        "and	r11, r11, r12\n\t"
        "eor	r10, r9, r11\n\t"
        "str	r10, [%[n]]\n\t"
        "add	%[b], %[b], #4\n\t"
        "add	%[n], %[n], #4\n\t"
        "add	%[a], %[a], #1\n\t"
        "b	L_mc_c16_a3_%=\n\t"
        "\n"
    "L_mc_c16_a3e_%=:\n\t"
        "add	r8, r8, #1\n\t"
        "b	L_mc_c16_i_%=\n\t"
        "\n"
    "L_mc_c16_ie_%=:\n\t"
        "mov	%[n], r5\n\t"
        "mov	%[a], #0\n\t"
        "\n"
    "L_mc_c16_f_%=:\n\t"
        "cmp	%[a], r6\n\t"
        "bge	L_mc_c16_fe_%=\n\t"
        "ldr	%[w], [%[n]]\n\t"
        "uxth	%[w], %[w]\n\t"
        "str	%[w], [%[n]]\n\t"
        "add	%[n], %[n], #4\n\t"
        "add	%[a], %[a], #1\n\t"
        "b	L_mc_c16_f_%=\n\t"
        "\n"
    "L_mc_c16_fe_%=:\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [a] "+r" (a), [b] "+r" (b), [n] "+r" (n), [w] "+r" (w)
        :
#else
        :
        : [a] "r" (a), [b] "r" (b), [n] "r" (n), [w] "r" (w)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "lr", "r4", "r5", "r6", "r7", "r8", "r12", "r9",
            "r10", "r11"
    );
}

WOLFSSL_LOCAL void wc_mceliece_cb_build_neon(byte* out, long pos0, long step0,
    const sword16* pi0, long w0, long n0, sword32* temp, void* stack);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_cb_build_neon(byte* out_p, long pos0_p,
    long step0_p, const sword16* pi0_p, long w0_p, long n0_p, sword32* temp_p,
    void* stack_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_cb_build_neon(byte* out, long pos0,
    long step0, const sword16* pi0, long w0, long n0, sword32* temp,
    void* stack)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register byte* out __asm__ ("r0") = (byte*)out_p;
    register long pos0 __asm__ ("r1") = (long)pos0_p;
    register long step0 __asm__ ("r2") = (long)step0_p;
    register const sword16* pi0 __asm__ ("r3") = (const sword16*)pi0_p;
    register long w0 __asm__ ("r12") = (long)w0_p;
    register long n0 __asm__ ("lr") = (long)n0_p;
    register sword32* temp __asm__ ("r4") = (sword32*)temp_p;
    register void* stack __asm__ ("r5") = (void*)stack_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "push	{%[temp], %[stack]}\n\t"
        "push	{%[w0], %[n0]}\n\t"
        "sub	sp, sp, #32\n\t"
        "mov	r4, %[out]\n\t"
        "ldr	r5, [sp, #40]\n\t"
        "ldr	r6, [sp, #44]\n\t"
        "ldr	%[out], [sp, #32]\n\t"
        "ldr	r8, [sp, #36]\n\t"
        "mov	r7, #1\n\t"
        "str	%[pos0], [r6]\n\t"
        "str	%[step0], [r6, #4]\n\t"
        "str	%[pi0], [r6, #8]\n\t"
        "str	%[out], [r6, #12]\n\t"
        "str	r8, [r6, #16]\n\t"
        "\n"
    "L_mc_cbb_w_%=:\n\t"
        "cmp	r7, #0\n\t"
        "ble	L_mc_cbb_end_%=\n\t"
        "sub	r7, r7, #1\n\t"
        "mov	%[out], #20\n\t"
        "mul	%[pos0], r7, %[out]\n\t"
        "add	r12, r6, %[pos0]\n\t"
        "ldr	%[out], [r12]\n\t"
        "str	%[out], [sp]\n\t"
        "ldr	%[out], [r12, #4]\n\t"
        "str	%[out], [sp, #4]\n\t"
        "ldr	%[out], [r12, #8]\n\t"
        "str	%[out], [sp, #8]\n\t"
        "ldr	%[out], [r12, #12]\n\t"
        "str	%[out], [sp, #12]\n\t"
        "ldr	%[out], [r12, #16]\n\t"
        "str	%[out], [sp, #16]\n\t"
        "ldr	%[pi0], [sp, #12]\n\t"
        "cmp	%[pi0], #1\n\t"
        "bne	L_mc_cbb_not1_%=\n\t"
        "ldr	%[out], [sp]\n\t"
        "lsr	%[pos0], %[out], #3\n\t"
        "add	%[pos0], r4, %[pos0]\n\t"
        "ldrb	%[step0], [%[pos0]]\n\t"
        "ldr	%[pi0], [sp, #8]\n\t"
        "ldrh	%[pi0], [%[pi0]]\n\t"
        "and	%[out], %[out], #7\n\t"
        "lsl	%[pi0], %[pi0], %[out]\n\t"
        "eor	%[step0], %[step0], %[pi0]\n\t"
        "strb	%[step0], [%[pos0]]\n\t"
        "b	L_mc_cbb_w_%=\n\t"
        "\n"
    "L_mc_cbb_not1_%=:\n\t"
        "ldr	r8, [sp, #16]\n\t"
        "ldr	r9, [sp, #8]\n\t"
        "mov	r10, r5\n\t"
        "mov	r11, #0\n\t"
        "\n"
    "L_mc_cbb_s1_%=:\n\t"
        "cmp	r11, r8\n\t"
        "bge	L_mc_cbb_s1e_%=\n\t"
        "lsl	%[out], r11, #1\n\t"
        "add	%[out], r9, %[out]\n\t"
        "ldrh	%[pos0], [%[out]]\n\t"
        "eor	%[step0], %[pos0], #1\n\t"
        "lsl	%[step0], %[step0], #16\n\t"
        "eor	%[out], r11, #1\n\t"
        "lsl	%[out], %[out], #1\n\t"
        "add	%[out], r9, %[out]\n\t"
        "ldrh	%[out], [%[out]]\n\t"
        "orr	%[step0], %[step0], %[out]\n\t"
        "str	%[step0], [r10]\n\t"
        "add	r10, r10, #4\n\t"
        "add	r11, r11, #1\n\t"
        "b	L_mc_cbb_s1_%=\n\t"
        "\n"
    "L_mc_cbb_s1e_%=:\n\t"
        "mov	%[out], r5\n\t"
        "ldr	%[pos0], [sp, #16]\n\t"
        "bl	wc_mceliece_i32_sort_neon\n\t"
        "ldr	r8, [sp, #16]\n\t"
        "lsl	%[out], r8, #2\n\t"
        "add	r9, r5, %[out]\n\t"
        "mov	r10, r5\n\t"
        "mov	r11, #0\n\t"
        "\n"
    "L_mc_cbb_s2_%=:\n\t"
        "cmp	r11, r8\n\t"
        "bge	L_mc_cbb_s2e_%=\n\t"
        "ldr	%[out], [r10]\n\t"
        "uxth	r12, %[out]\n\t"
        "eor	%[step0], r12, r11\n\t"
        "sub	%[pi0], r11, r12\n\t"
        "eor	%[pos0], %[pi0], r11\n\t"
        "and	%[pos0], %[pos0], %[step0]\n\t"
        "eor	%[pi0], %[pi0], %[pos0]\n\t"
        "asr	%[pi0], %[pi0], #31\n\t"
        "and	%[pi0], %[pi0], %[step0]\n\t"
        "eor	%[pos0], r12, %[pi0]\n\t"
        "lsl	r12, r12, #16\n\t"
        "orr	r12, r12, %[pos0]\n\t"
        "str	r12, [r9]\n\t"
        "add	r10, r10, #4\n\t"
        "add	r9, r9, #4\n\t"
        "add	r11, r11, #1\n\t"
        "b	L_mc_cbb_s2_%=\n\t"
        "\n"
    "L_mc_cbb_s2e_%=:\n\t"
        "ldr	r8, [sp, #16]\n\t"
        "mov	r10, r5\n\t"
        "mov	r11, #0\n\t"
        "\n"
    "L_mc_cbb_s3_%=:\n\t"
        "cmp	r11, r8\n\t"
        "bge	L_mc_cbb_s3e_%=\n\t"
        "ldr	%[out], [r10]\n\t"
        "lsl	%[out], %[out], #16\n\t"
        "orr	%[out], %[out], r11\n\t"
        "str	%[out], [r10]\n\t"
        "add	r10, r10, #4\n\t"
        "add	r11, r11, #1\n\t"
        "b	L_mc_cbb_s3_%=\n\t"
        "\n"
    "L_mc_cbb_s3e_%=:\n\t"
        "mov	%[out], r5\n\t"
        "ldr	%[pos0], [sp, #16]\n\t"
        "bl	wc_mceliece_i32_sort_neon\n\t"
        "ldr	r8, [sp, #16]\n\t"
        "lsl	%[out], r8, #2\n\t"
        "add	r9, r5, %[out]\n\t"
        "mov	r10, r5\n\t"
        "mov	r11, #0\n\t"
        "\n"
    "L_mc_cbb_s4_%=:\n\t"
        "cmp	r11, r8\n\t"
        "bge	L_mc_cbb_s4e_%=\n\t"
        "ldr	%[out], [r10]\n\t"
        "lsl	%[out], %[out], #16\n\t"
        "ldr	%[pos0], [r9]\n\t"
        "asr	%[pos0], %[pos0], #16\n\t"
        "add	%[out], %[out], %[pos0]\n\t"
        "str	%[out], [r10]\n\t"
        "add	r10, r10, #4\n\t"
        "add	r9, r9, #4\n\t"
        "add	r11, r11, #1\n\t"
        "b	L_mc_cbb_s4_%=\n\t"
        "\n"
    "L_mc_cbb_s4e_%=:\n\t"
        "mov	%[out], r5\n\t"
        "ldr	%[pos0], [sp, #16]\n\t"
        "bl	wc_mceliece_i32_sort_neon\n\t"
        "ldr	r8, [sp, #16]\n\t"
        "lsl	r9, r8, #2\n\t"
        "add	%[pos0], r5, r9\n\t"
        "mov	%[step0], r8\n\t"
        "ldr	%[pi0], [sp, #12]\n\t"
        "mov	%[out], r5\n\t"
        "cmp	%[pi0], #10\n\t"
        "bgt	L_mc_cbb_c16_%=\n\t"
        "bl	wc_mceliece_cb_compose10_neon\n\t"
        "b	L_mc_cbb_c5e_%=\n\t"
        "\n"
    "L_mc_cbb_c16_%=:\n\t"
        "bl	wc_mceliece_cb_compose16_neon\n\t"
        "\n"
    "L_mc_cbb_c5e_%=:\n\t"
        "ldr	r8, [sp, #16]\n\t"
        "ldr	r9, [sp, #8]\n\t"
        "mov	r10, r5\n\t"
        "mov	r11, #0\n\t"
        "\n"
    "L_mc_cbb_s6_%=:\n\t"
        "cmp	r11, r8\n\t"
        "bge	L_mc_cbb_s6e_%=\n\t"
        "lsl	%[out], r11, #1\n\t"
        "add	%[out], r9, %[out]\n\t"
        "ldrh	%[pos0], [%[out]]\n\t"
        "lsl	%[pos0], %[pos0], #16\n\t"
        "add	%[pos0], %[pos0], r11\n\t"
        "str	%[pos0], [r10]\n\t"
        "add	r10, r10, #4\n\t"
        "add	r11, r11, #1\n\t"
        "b	L_mc_cbb_s6_%=\n\t"
        "\n"
    "L_mc_cbb_s6e_%=:\n\t"
        "mov	%[out], r5\n\t"
        "ldr	%[pos0], [sp, #16]\n\t"
        "bl	wc_mceliece_i32_sort_neon\n\t"
        "ldr	r12, [sp]\n\t"
        "ldr	r8, [sp, #16]\n\t"
        "lsr	r8, r8, #1\n\t"
        "ldr	r9, [sp, #16]\n\t"
        "lsl	%[out], r9, #2\n\t"
        "add	r9, r5, %[out]\n\t"
        "mov	r10, r5\n\t"
        "mov	r11, #0\n\t"
        "\n"
    "L_mc_cbb_s7_%=:\n\t"
        "cmp	r11, r8\n\t"
        "bge	L_mc_cbb_s7e_%=\n\t"
        "ldr	%[out], [r9]\n\t"
        "and	%[pos0], %[out], #1\n\t"
        "lsr	%[step0], r12, #3\n\t"
        "add	%[step0], r4, %[step0]\n\t"
        "ldrb	%[pi0], [%[step0]]\n\t"
        "and	%[out], r12, #7\n\t"
        "lsl	%[out], %[pos0], %[out]\n\t"
        "eor	%[pi0], %[pi0], %[out]\n\t"
        "strb	%[pi0], [%[step0]]\n\t"
        "ldr	%[step0], [sp, #4]\n\t"
        "add	r12, r12, %[step0]\n\t"
        "add	%[pi0], r11, r11\n\t"
        "add	%[pi0], %[pi0], %[pos0]\n\t"
        "ldr	%[out], [r10]\n\t"
        "lsl	%[out], %[out], #16\n\t"
        "orr	%[out], %[out], %[pi0]\n\t"
        "str	%[out], [r9]\n\t"
        "eor	%[pi0], %[pi0], #1\n\t"
        "ldr	%[out], [r10, #4]\n\t"
        "lsl	%[out], %[out], #16\n\t"
        "orr	%[out], %[out], %[pi0]\n\t"
        "str	%[out], [r9, #4]\n\t"
        "add	r10, r10, #8\n\t"
        "add	r9, r9, #8\n\t"
        "add	r11, r11, #1\n\t"
        "b	L_mc_cbb_s7_%=\n\t"
        "\n"
    "L_mc_cbb_s7e_%=:\n\t"
        "str	r12, [sp]\n\t"
        "ldr	r8, [sp, #16]\n\t"
        "lsl	%[out], r8, #2\n\t"
        "add	%[out], r5, %[out]\n\t"
        "ldr	%[pos0], [sp, #16]\n\t"
        "bl	wc_mceliece_i32_sort_neon\n\t"
        "ldr	r12, [sp]\n\t"
        "ldr	%[out], [sp, #12]\n\t"
        "add	%[out], %[out], %[out]\n\t"
        "sub	%[out], %[out], #3\n\t"
        "ldr	%[pos0], [sp, #4]\n\t"
        "mul	%[out], %[out], %[pos0]\n\t"
        "ldr	%[step0], [sp, #16]\n\t"
        "lsr	%[step0], %[step0], #1\n\t"
        "mul	%[out], %[out], %[step0]\n\t"
        "add	r12, r12, %[out]\n\t"
        "ldr	r8, [sp, #16]\n\t"
        "lsr	r8, r8, #1\n\t"
        "ldr	r9, [sp, #16]\n\t"
        "lsl	%[out], r9, #2\n\t"
        "add	r9, r5, %[out]\n\t"
        "mov	r10, r5\n\t"
        "mov	r11, #0\n\t"
        "\n"
    "L_mc_cbb_s8_%=:\n\t"
        "cmp	r11, r8\n\t"
        "bge	L_mc_cbb_s8e_%=\n\t"
        "ldr	%[out], [r9]\n\t"
        "and	%[pos0], %[out], #1\n\t"
        "lsr	%[step0], r12, #3\n\t"
        "add	%[step0], r4, %[step0]\n\t"
        "ldrb	%[pi0], [%[step0]]\n\t"
        "and	%[out], r12, #7\n\t"
        "lsl	%[out], %[pos0], %[out]\n\t"
        "eor	%[pi0], %[pi0], %[out]\n\t"
        "strb	%[pi0], [%[step0]]\n\t"
        "ldr	%[step0], [sp, #4]\n\t"
        "add	r12, r12, %[step0]\n\t"
        "add	%[pi0], r11, r11\n\t"
        "add	%[pi0], %[pi0], %[pos0]\n\t"
        "ldr	%[out], [r9]\n\t"
        "uxth	%[out], %[out]\n\t"
        "lsl	%[step0], %[pi0], #16\n\t"
        "orr	%[out], %[out], %[step0]\n\t"
        "str	%[out], [r10]\n\t"
        "eor	%[pi0], %[pi0], #1\n\t"
        "ldr	%[out], [r9, #4]\n\t"
        "uxth	%[out], %[out]\n\t"
        "lsl	%[step0], %[pi0], #16\n\t"
        "orr	%[out], %[out], %[step0]\n\t"
        "str	%[out], [r10, #4]\n\t"
        "add	r10, r10, #8\n\t"
        "add	r9, r9, #8\n\t"
        "add	r11, r11, #1\n\t"
        "b	L_mc_cbb_s8_%=\n\t"
        "\n"
    "L_mc_cbb_s8e_%=:\n\t"
        "str	r12, [sp]\n\t"
        "mov	%[out], r5\n\t"
        "ldr	%[pos0], [sp, #16]\n\t"
        "bl	wc_mceliece_i32_sort_neon\n\t"
        "ldr	r12, [sp]\n\t"
        "ldr	%[out], [sp, #12]\n\t"
        "add	%[out], %[out], %[out]\n\t"
        "sub	%[out], %[out], #2\n\t"
        "ldr	%[pos0], [sp, #4]\n\t"
        "mul	%[out], %[out], %[pos0]\n\t"
        "ldr	%[step0], [sp, #16]\n\t"
        "lsr	%[step0], %[step0], #1\n\t"
        "mul	%[out], %[out], %[step0]\n\t"
        "sub	r12, r12, %[out]\n\t"
        "str	r12, [sp]\n\t"
        "ldr	r8, [sp, #16]\n\t"
        "lsr	r9, r8, #2\n\t"
        "add	%[out], r8, r9\n\t"
        "lsl	%[out], %[out], #2\n\t"
        "add	r9, r5, %[out]\n\t"
        "lsr	r8, r8, #1\n\t"
        "mov	r10, r5\n\t"
        "mov	r11, #0\n\t"
        "\n"
    "L_mc_cbb_s10_%=:\n\t"
        "cmp	r11, r8\n\t"
        "bge	L_mc_cbb_s10e_%=\n\t"
        "ldr	%[out], [r10]\n\t"
        "uxth	%[out], %[out]\n\t"
        "lsr	%[out], %[out], #1\n\t"
        "lsl	%[pos0], r11, #1\n\t"
        "add	%[pos0], r9, %[pos0]\n\t"
        "strh	%[out], [%[pos0]]\n\t"
        "ldr	%[out], [r10, #4]\n\t"
        "uxth	%[out], %[out]\n\t"
        "lsr	%[out], %[out], #1\n\t"
        "add	%[step0], r11, r8\n\t"
        "lsl	%[step0], %[step0], #1\n\t"
        "add	%[step0], r9, %[step0]\n\t"
        "strh	%[out], [%[step0]]\n\t"
        "add	r10, r10, #8\n\t"
        "add	r11, r11, #1\n\t"
        "b	L_mc_cbb_s10_%=\n\t"
        "\n"
    "L_mc_cbb_s10e_%=:\n\t"
        "ldr	%[out], [sp, #16]\n\t"
        "lsr	%[pos0], %[out], #2\n\t"
        "add	%[step0], %[out], %[pos0]\n\t"
        "lsl	%[step0], %[step0], #2\n\t"
        "add	r9, r5, %[step0]\n\t"
        "lsr	r10, %[out], #1\n\t"
        "ldr	%[pi0], [sp, #4]\n\t"
        "add	%[pi0], %[pi0], %[pi0]\n\t"
        "ldr	r11, [sp, #12]\n\t"
        "sub	r11, r11, #1\n\t"
        "ldr	r12, [sp]\n\t"
        "mov	%[out], #20\n\t"
        "mul	%[pos0], r7, %[out]\n\t"
        "add	%[step0], r6, %[pos0]\n\t"
        "ldr	%[out], [sp, #4]\n\t"
        "add	%[out], r12, %[out]\n\t"
        "str	%[out], [%[step0]]\n\t"
        "str	%[pi0], [%[step0], #4]\n\t"
        "lsl	%[out], r10, #1\n\t"
        "add	%[out], r9, %[out]\n\t"
        "str	%[out], [%[step0], #8]\n\t"
        "str	r11, [%[step0], #12]\n\t"
        "str	r10, [%[step0], #16]\n\t"
        "add	r7, r7, #1\n\t"
        "mov	%[out], #20\n\t"
        "mul	%[pos0], r7, %[out]\n\t"
        "add	%[step0], r6, %[pos0]\n\t"
        "str	r12, [%[step0]]\n\t"
        "str	%[pi0], [%[step0], #4]\n\t"
        "str	r9, [%[step0], #8]\n\t"
        "str	r11, [%[step0], #12]\n\t"
        "str	r10, [%[step0], #16]\n\t"
        "add	r7, r7, #1\n\t"
        "b	L_mc_cbb_w_%=\n\t"
        "\n"
    "L_mc_cbb_end_%=:\n\t"
        "add	sp, sp, #32\n\t"
        "pop	{%[w0], %[n0]}\n\t"
        "pop	{%[temp], %[stack]}\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [out] "+r" (out), [pos0] "+r" (pos0), [step0] "+r" (step0),
          [pi0] "+r" (pi0), [w0] "+r" (w0), [n0] "+r" (n0), [temp] "+r" (temp),
          [stack] "+r" (stack)
        :
#else
        :
        : [out] "r" (out), [pos0] "r" (pos0), [step0] "r" (step0),
          [pi0] "r" (pi0), [w0] "r" (w0), [n0] "r" (n0), [temp] "r" (temp),
          [stack] "r" (stack)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r6", "r7", "r8", "r9", "r10", "r11"
    );
}

WOLFSSL_LOCAL int wc_mceliece_bs_fftbuild_neon(void* ctx);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER int wc_mceliece_bs_fftbuild_neon(void* ctx_p)
#else
WC_OMIT_FRAME_POINTER int wc_mceliece_bs_fftbuild_neon(void* ctx)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register void* ctx __asm__ ("r0") = (void*)ctx_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "sub	sp, sp, #12\n\t"
        "mov	r4, %[ctx]\n\t"
        "ldr	r5, [r4, #12]\n\t"
        "ldr	%[ctx], [r4, #64]\n\t"
        "mov	r1, r5\n\t"
        "ldr	r2, [r4]\n\t"
        "ldr	r3, [r4, #72]\n\t"
        "bl	wc_mceliece_bs_gload_neon\n\t"
        "add	%[ctx], r5, #0x100\n\t"
        "mov	r1, r5\n\t"
        "bl	wc_mceliece_bs_poly_neon\n\t"
        "add	%[ctx], r5, #0x100\n\t"
        "bl	wc_mceliece_radix_conv_neon\n\t"
        "ldr	%[ctx], [r4, #28]\n\t"
        "add	r1, r5, #0x100\n\t"
        "ldr	r2, [r4, #88]\n\t"
        "add	r3, r5, #0xa00\n\t"
        "bl	wc_mceliece_fft_fwd_butterflies_neon\n\t"
        "ldr	%[ctx], [r4, #20]\n\t"
        "ldr	r1, [r4, #28]\n\t"
        "add	r2, r5, #0x200\n\t"
        "add	r3, r5, #0x540\n\t"
        "mov	r12, #0\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_mont_batch_inv_neon\n\t"
        "ldr	%[ctx], [r4, #32]\n\t"
        "ldr	r1, [r4, #20]\n\t"
        "bl	wc_mceliece_bs_debitslice_neon\n\t"
        "mov	%[ctx], r5\n\t"
        "ldr	r1, [r4, #4]\n\t"
        "ldr	r2, [r4, #32]\n\t"
        "bl	wc_mceliece_bs_packbuf_neon\n\t"
        "mov	%[ctx], r5\n\t"
        "mov	r1, #0x2000\n\t"
        "bl	wc_mceliece_u64_sort_neon\n\t"
        "ldr	%[ctx], [r4, #8]\n\t"
        "mov	r1, r5\n\t"
        "bl	wc_mceliece_bs_dup_pi_neon\n\t"
        "cmp	%[ctx], #0\n\t"
        "beq	L_mc_fftb_nd_%=\n\t"
        "mov	r6, #0\n\t"
        "sub	r6, r6, #1\n\t"
        "b	L_mc_fftb_end_%=\n\t"
        "\n"
    "L_mc_fftb_nd_%=:\n\t"
        "ldr	%[ctx], [r4, #24]\n\t"
        "ldr	r1, [r4, #20]\n\t"
        "mov	r2, r5\n\t"
        "bl	wc_mceliece_bs_tobitslice2x_neon\n\t"
        "mov	r6, #0\n\t"
        "\n"
    "L_mc_fftb_end_%=:\n\t"
        "mov	%[ctx], r6\n\t"
        "add	sp, sp, #12\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [ctx] "+r" (ctx)
        :
#else
        :
        : [ctx] "r" (ctx)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r1", "r2", "r3", "lr", "r4", "r5", "r6", "r12"
    );
    return (word32)(size_t)ctx;
}

WOLFSSL_LOCAL void wc_mceliece_bs_phase10_neon(void* ctx);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_bs_phase10_neon(void* ctx_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_bs_phase10_neon(void* ctx)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register void* ctx __asm__ ("r0") = (void*)ctx_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "sub	sp, sp, #16\n\t"
        "mov	r4, %[ctx]\n\t"
        "ldr	r5, [r4, #36]\n\t"
        "ldr	r6, [r4, #80]\n\t"
        "ldr	r10, [r4, #48]\n\t"
        "ldr	r11, [r4, #120]\n\t"
        "add	r12, r6, #0xff\n\t"
        "lsr	r12, r12, #8\n\t"
        "lsl	r7, r12, #2\n\t"
        "mul	%[ctx], r6, r11\n\t"
        "lsr	r1, %[ctx], #2\n\t"
        "and	r2, %[ctx], #3\n\t"
        "mov	r3, r10\n\t"
        "mov	r12, #0\n\t"
        "mov	%[ctx], #0\n\t"
        "\n"
    "L_mc_p10_zw_%=:\n\t"
        "cmp	%[ctx], r1\n\t"
        "bge	L_mc_p10_zwe_%=\n\t"
        "str	r12, [r3]\n\t"
        "add	r3, r3, #4\n\t"
        "add	%[ctx], %[ctx], #1\n\t"
        "b	L_mc_p10_zw_%=\n\t"
        "\n"
    "L_mc_p10_zwe_%=:\n\t"
        "mov	%[ctx], #0\n\t"
        "\n"
    "L_mc_p10_zb_%=:\n\t"
        "cmp	%[ctx], r2\n\t"
        "bge	L_mc_p10_zbe_%=\n\t"
        "strb	r12, [r3]\n\t"
        "add	r3, r3, #1\n\t"
        "add	%[ctx], %[ctx], #1\n\t"
        "b	L_mc_p10_zb_%=\n\t"
        "\n"
    "L_mc_p10_zbe_%=:\n\t"
        "ldr	r8, [r4, #112]\n\t"
        "\n"
    "L_mc_p10_j_%=:\n\t"
        "ldr	r12, [r4, #104]\n\t"
        "cmp	r8, r12\n\t"
        "bge	L_mc_p10_je_%=\n\t"
        "mov	%[ctx], #52\n\t"
        "mul	r12, r8, %[ctx]\n\t"
        "lsl	r12, r12, #3\n\t"
        "mov	%[ctx], r5\n\t"
        "ldr	r1, [r4, #20]\n\t"
        "add	r1, r1, r12\n\t"
        "ldr	r2, [r4, #24]\n\t"
        "add	r2, r2, r12\n\t"
        "ldr	r3, [r4, #72]\n\t"
        "mov	r12, #13\n\t"
        "str	r12, [sp]\n\t"
        "mov	r12, #7\n\t"
        "str	r12, [sp, #4]\n\t"
        "ldr	r12, [r4, #104]\n\t"
        "sub	r12, r12, r8\n\t"
        "str	r12, [sp, #8]\n\t"
        "ldr	r12, [r4, #52]\n\t"
        "str	r12, [sp, #12]\n\t"
        "bl	wc_mceliece_bs_par_fill_neon\n\t"
        "ldr	%[ctx], [r4, #40]\n\t"
        "ldr	r1, [r4, #44]\n\t"
        "mov	r2, #0\n\t"
        "\n"
    "L_mc_p10_ic_%=:\n\t"
        "cmp	r2, r6\n\t"
        "bge	L_mc_p10_ice_%=\n\t"
        "ldrh	r12, [r1]\n\t"
        "strh	r12, [%[ctx]]\n\t"
        "add	%[ctx], %[ctx], #2\n\t"
        "add	r1, r1, #2\n\t"
        "add	r2, r2, #1\n\t"
        "b	L_mc_p10_ic_%=\n\t"
        "\n"
    "L_mc_p10_ice_%=:\n\t"
        "ldr	%[ctx], [r4, #40]\n\t"
        "mov	r1, r5\n\t"
        "mov	r2, #7\n\t"
        "mov	r3, r6\n\t"
        "bl	wc_mceliece_bs_sort_rows_neon\n\t"
        "sub	r9, r6, #1\n\t"
        "\n"
    "L_mc_p10_l_%=:\n\t"
        "cmp	r9, #0\n\t"
        "blt	L_mc_p10_le_%=\n\t"
        "mov	%[ctx], r5\n\t"
        "ldr	r1, [r4, #16]\n\t"
        "mul	r12, r9, r7\n\t"
        "lsl	r12, r12, #3\n\t"
        "add	r1, r1, r12\n\t"
        "mov	r2, r9\n\t"
        "mov	r3, #28\n\t"
        "mov	r12, #0\n\t"
        "str	r12, [sp]\n\t"
        "str	r9, [sp, #4]\n\t"
        "bl	wc_mceliece_bs_tri_neon\n\t"
        "sub	r9, r9, #1\n\t"
        "b	L_mc_p10_l_%=\n\t"
        "\n"
    "L_mc_p10_le_%=:\n\t"
        "ldr	r12, [r4, #112]\n\t"
        "cmp	r8, r12\n\t"
        "bne	L_mc_p10_ove_%=\n\t"
        "mov	r2, #0\n\t"
        "\n"
    "L_mc_p10_or_%=:\n\t"
        "cmp	r2, r6\n\t"
        "bge	L_mc_p10_ore_%=\n\t"
        "mul	%[ctx], r2, r7\n\t"
        "add	%[ctx], %[ctx], r7\n\t"
        "sub	%[ctx], %[ctx], #4\n\t"
        "lsl	%[ctx], %[ctx], #3\n\t"
        "ldr	r12, [r4, #16]\n\t"
        "add	%[ctx], r12, %[ctx]\n\t"
        "mov	r12, #28\n\t"
        "mul	r1, r2, r12\n\t"
        "lsl	r1, r1, #3\n\t"
        "add	r1, r5, r1\n\t"
        "vld1.8	{d0-d3}, [%[ctx]]\n\t"
        "vst1.8	{d0-d3}, [r1]\n\t"
        "add	r2, r2, #1\n\t"
        "b	L_mc_p10_or_%=\n\t"
        "\n"
    "L_mc_p10_ore_%=:\n\t"
        "\n"
    "L_mc_p10_ove_%=:\n\t"
        "sub	r9, r6, #1\n\t"
        "\n"
    "L_mc_p10_u_%=:\n\t"
        "cmp	r9, #0\n\t"
        "blt	L_mc_p10_ue_%=\n\t"
        "mov	%[ctx], r5\n\t"
        "ldr	r1, [r4, #16]\n\t"
        "mul	r12, r9, r7\n\t"
        "lsl	r12, r12, #3\n\t"
        "add	r1, r1, r12\n\t"
        "mov	r2, r9\n\t"
        "mov	r3, #28\n\t"
        "add	r12, r9, #1\n\t"
        "str	r12, [sp]\n\t"
        "str	r6, [sp, #4]\n\t"
        "bl	wc_mceliece_bs_tri_neon\n\t"
        "sub	r9, r9, #1\n\t"
        "b	L_mc_p10_u_%=\n\t"
        "\n"
    "L_mc_p10_ue_%=:\n\t"
        "mov	r9, #0\n\t"
        "\n"
    "L_mc_p10_b_%=:\n\t"
        "cmp	r9, #7\n\t"
        "bge	L_mc_p10_be_%=\n\t"
        "add	r2, r8, r9\n\t"
        "ldr	r12, [r4, #104]\n\t"
        "cmp	r2, r12\n\t"
        "bge	L_mc_p10_bsk_%=\n\t"
        "mov	r3, #0\n\t"
        "\n"
    "L_mc_p10_br_%=:\n\t"
        "cmp	r3, r6\n\t"
        "bge	L_mc_p10_bre_%=\n\t"
        "mul	%[ctx], r3, r11\n\t"
        "lsl	r12, r2, #5\n\t"
        "add	%[ctx], %[ctx], r12\n\t"
        "add	%[ctx], r10, %[ctx]\n\t"
        "mov	r12, #28\n\t"
        "mul	r1, r3, r12\n\t"
        "lsl	r12, r9, #2\n\t"
        "add	r1, r1, r12\n\t"
        "lsl	r1, r1, #3\n\t"
        "add	r1, r5, r1\n\t"
        "vld1.8	{d0-d3}, [r1]\n\t"
        "vst1.8	{d0-d3}, [%[ctx]]\n\t"
        "add	r3, r3, #1\n\t"
        "b	L_mc_p10_br_%=\n\t"
        "\n"
    "L_mc_p10_bre_%=:\n\t"
        "\n"
    "L_mc_p10_bsk_%=:\n\t"
        "add	r9, r9, #1\n\t"
        "b	L_mc_p10_b_%=\n\t"
        "\n"
    "L_mc_p10_be_%=:\n\t"
        "add	r8, r8, #7\n\t"
        "b	L_mc_p10_j_%=\n\t"
        "\n"
    "L_mc_p10_je_%=:\n\t"
        "add	sp, sp, #16\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [ctx] "+r" (ctx)
        :
#else
        :
        : [ctx] "r" (ctx)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r1", "r2", "r3", "lr", "r4", "r5", "r6", "r7", "r8",
            "r9", "r10", "r11", "r12", "q0", "q1"
    );
}

WOLFSSL_LOCAL int wc_mceliece_pk_gen_neon(void* ctx);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER int wc_mceliece_pk_gen_neon(void* ctx_p)
#else
WC_OMIT_FRAME_POINTER int wc_mceliece_pk_gen_neon(void* ctx)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register void* ctx __asm__ ("r0") = (void*)ctx_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "sub	sp, sp, #16\n\t"
        "mov	r4, %[ctx]\n\t"
        "mov	%[ctx], r4\n\t"
        "bl	wc_mceliece_bs_fftbuild_neon\n\t"
        "mov	r5, %[ctx]\n\t"
        "cmp	%[ctx], #0\n\t"
        "bne	L_mc_pkg_end_%=\n\t"
        "ldr	%[ctx], [r4, #16]\n\t"
        "ldr	r1, [r4, #20]\n\t"
        "ldr	r2, [r4, #24]\n\t"
        "ldr	r3, [r4, #72]\n\t"
        "mov	r12, #13\n\t"
        "str	r12, [sp]\n\t"
        "ldr	r12, [r4, #80]\n\t"
        "add	r12, r12, #0xff\n\t"
        "lsr	r12, r12, #8\n\t"
        "str	r12, [sp, #4]\n\t"
        "lsl	r12, r12, #2\n\t"
        "str	r12, [sp, #8]\n\t"
        "ldr	r12, [r4, #52]\n\t"
        "str	r12, [sp, #12]\n\t"
        "bl	wc_mceliece_bs_lu_fill_neon\n\t"
        "ldr	%[ctx], [r4, #80]\n\t"
        "ldr	r1, [r4, #40]\n\t"
        "ldr	r2, [r4, #44]\n\t"
        "mov	r3, #0\n\t"
        "\n"
    "L_mc_pkg_ii_%=:\n\t"
        "cmp	r3, %[ctx]\n\t"
        "bge	L_mc_pkg_iid_%=\n\t"
        "strh	r3, [r1]\n\t"
        "strh	r3, [r2]\n\t"
        "add	r1, r1, #2\n\t"
        "add	r2, r2, #2\n\t"
        "add	r3, r3, #1\n\t"
        "b	L_mc_pkg_ii_%=\n\t"
        "\n"
    "L_mc_pkg_iid_%=:\n\t"
        "ldr	%[ctx], [r4, #16]\n\t"
        "ldr	r1, [r4, #40]\n\t"
        "ldr	r2, [r4, #80]\n\t"
        "ldr	r12, [r4, #80]\n\t"
        "add	r12, r12, #0xff\n\t"
        "lsr	r12, r12, #8\n\t"
        "lsl	r3, r12, #2\n\t"
        "ldr	r12, [r4, #96]\n\t"
        "str	r12, [sp]\n\t"
        "ldr	r12, [r4, #8]\n\t"
        "str	r12, [sp, #4]\n\t"
        "ldr	r12, [r4, #56]\n\t"
        "str	r12, [sp, #8]\n\t"
        "bl	wc_mceliece_bs_pk_gen_reduce_neon\n\t"
        "mov	r5, %[ctx]\n\t"
        "cmp	%[ctx], #0\n\t"
        "bne	L_mc_pkg_end_%=\n\t"
        "ldr	%[ctx], [r4, #80]\n\t"
        "ldr	r1, [r4, #44]\n\t"
        "ldr	r2, [r4, #44]\n\t"
        "ldr	r3, [r4, #40]\n\t"
        "ldr	r12, [r4, #52]\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_bs_composeinv_neon\n\t"
        "mov	%[ctx], r4\n\t"
        "bl	wc_mceliece_bs_phase10_neon\n\t"
        "ldr	%[ctx], [r4, #60]\n\t"
        "ldr	r1, [r4, #48]\n\t"
        "ldr	r2, [r4, #80]\n\t"
        "ldr	r3, [r4, #120]\n\t"
        "ldr	r12, [r4, #128]\n\t"
        "str	r12, [sp]\n\t"
        "bl	wc_mceliece_bs_extract_neon\n\t"
        "mov	r5, #0\n\t"
        "\n"
    "L_mc_pkg_end_%=:\n\t"
        "mov	%[ctx], r5\n\t"
        "add	sp, sp, #16\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [ctx] "+r" (ctx)
        :
#else
        :
        : [ctx] "r" (ctx)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r1", "r2", "r3", "lr", "r4", "r5", "r12"
    );
    return (word32)(size_t)ctx;
}

WOLFSSL_LOCAL int wc_mceliece_genpoly_neon(word16* out, const word16* f, int t,
    word16* mat, word16* prod, byte* skp, void* ctx);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER int wc_mceliece_genpoly_neon(word16* out_p,
    const word16* f_p, int t_p, word16* mat_p, word16* prod_p, byte* skp_p,
    void* ctx_p)
#else
WC_OMIT_FRAME_POINTER int wc_mceliece_genpoly_neon(word16* out, const word16* f,
    int t, word16* mat, word16* prod, byte* skp, void* ctx)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word16* out __asm__ ("r0") = (word16*)out_p;
    register const word16* f __asm__ ("r1") = (const word16*)f_p;
    register int t __asm__ ("r2") = (int)t_p;
    register word16* mat __asm__ ("r3") = (word16*)mat_p;
    register word16* prod __asm__ ("r12") = (word16*)prod_p;
    register byte* skp __asm__ ("lr") = (byte*)skp_p;
    register void* ctx __asm__ ("r4") = (void*)ctx_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "push	{%[ctx]}\n\t"
        "push	{%[prod], %[skp]}\n\t"
        "sub	sp, sp, #12\n\t"
        "str	%[out], [sp]\n\t"
        "mov	r11, %[f]\n\t"
        "mov	r4, %[t]\n\t"
        "mov	r5, %[mat]\n\t"
        "ldr	r6, [sp, #12]\n\t"
        "ldr	r12, [sp, #16]\n\t"
        "str	r12, [sp, #8]\n\t"
        "ldr	r12, [sp, #20]\n\t"
        "str	r12, [sp, #4]\n\t"
        "mov	r10, #0\n\t"
        "mov	%[out], #1\n\t"
        "strh	%[out], [r5]\n\t"
        "mov	%[out], #0\n\t"
        "mov	%[f], #1\n\t"
        "\n"
    "L_mc_gp_c0_%=:\n\t"
        "cmp	%[f], r4\n\t"
        "bge	L_mc_gp_c0e_%=\n\t"
        "lsl	%[t], %[f], #1\n\t"
        "add	%[mat], r5, %[t]\n\t"
        "strh	%[out], [%[mat]]\n\t"
        "add	%[f], %[f], #1\n\t"
        "b	L_mc_gp_c0_%=\n\t"
        "\n"
    "L_mc_gp_c0e_%=:\n\t"
        "mov	%[f], #0\n\t"
        "\n"
    "L_mc_gp_c1_%=:\n\t"
        "cmp	%[f], r4\n\t"
        "bge	L_mc_gp_c1e_%=\n\t"
        "lsl	%[t], %[f], #1\n\t"
        "add	%[mat], r11, %[t]\n\t"
        "ldrh	%[out], [%[mat]]\n\t"
        "add	r12, r4, %[f]\n\t"
        "lsl	r12, r12, #1\n\t"
        "add	%[mat], r5, r12\n\t"
        "strh	%[out], [%[mat]]\n\t"
        "add	%[f], %[f], #1\n\t"
        "b	L_mc_gp_c1_%=\n\t"
        "\n"
    "L_mc_gp_c1e_%=:\n\t"
        "mov	r7, #2\n\t"
        "\n"
    "L_mc_gp_j_%=:\n\t"
        "cmp	r7, r4\n\t"
        "bgt	L_mc_gp_je_%=\n\t"
        "mov	%[out], #0\n\t"
        "lsl	%[f], r4, #1\n\t"
        "sub	%[f], %[f], #1\n\t"
        "mov	%[t], #0\n\t"
        "\n"
    "L_mc_gp_pz_%=:\n\t"
        "cmp	%[t], %[f]\n\t"
        "bge	L_mc_gp_pze_%=\n\t"
        "lsl	%[mat], %[t], #1\n\t"
        "add	r12, r6, %[mat]\n\t"
        "strh	%[out], [r12]\n\t"
        "add	%[t], %[t], #1\n\t"
        "b	L_mc_gp_pz_%=\n\t"
        "\n"
    "L_mc_gp_pze_%=:\n\t"
        "mov	r8, #0\n\t"
        "\n"
    "L_mc_gp_pm_%=:\n\t"
        "cmp	r8, r4\n\t"
        "bge	L_mc_gp_pme_%=\n\t"
        "sub	%[f], r7, #1\n\t"
        "mul	%[out], %[f], r4\n\t"
        "add	%[out], %[out], r8\n\t"
        "lsl	%[out], %[out], #1\n\t"
        "add	%[out], r5, %[out]\n\t"
        "ldrh	%[f], [%[out]]\n\t"
        "lsl	%[out], r8, #1\n\t"
        "add	%[out], r6, %[out]\n\t"
        "mov	%[t], r11\n\t"
        "mov	%[mat], r4\n\t"
        "bl	wc_mceliece_gf_mulc_mac_full_neon\n\t"
        "add	r8, r8, #1\n\t"
        "b	L_mc_gp_pm_%=\n\t"
        "\n"
    "L_mc_gp_pme_%=:\n\t"
        "lsl	%[out], r4, #1\n\t"
        "sub	%[out], %[out], #2\n\t"
        "cmp	r4, #0x77\n\t"
        "beq	L_mc_gp_119_%=\n\t"
        "\n"
    "L_mc_gp_rd_%=:\n\t"
        "cmp	%[out], r4\n\t"
        "blt	L_mc_gp_rde_%=\n\t"
        "lsl	%[f], %[out], #1\n\t"
        "add	%[t], r6, %[f]\n\t"
        "ldrh	%[mat], [%[t]]\n\t"
        "sub	%[f], %[out], r4\n\t"
        "add	r12, %[f], #0\n\t"
        "lsl	r12, r12, #1\n\t"
        "add	r12, r6, r12\n\t"
        "ldrh	%[t], [r12]\n\t"
        "eor	%[t], %[t], %[mat]\n\t"
        "strh	%[t], [r12]\n\t"
        "add	r12, %[f], #1\n\t"
        "lsl	r12, r12, #1\n\t"
        "add	r12, r6, r12\n\t"
        "ldrh	%[t], [r12]\n\t"
        "eor	%[t], %[t], %[mat]\n\t"
        "strh	%[t], [r12]\n\t"
        "add	r12, %[f], #2\n\t"
        "lsl	r12, r12, #1\n\t"
        "add	r12, r6, r12\n\t"
        "ldrh	%[t], [r12]\n\t"
        "eor	%[t], %[t], %[mat]\n\t"
        "strh	%[t], [r12]\n\t"
        "add	r12, %[f], #7\n\t"
        "lsl	r12, r12, #1\n\t"
        "add	r12, r6, r12\n\t"
        "ldrh	%[t], [r12]\n\t"
        "eor	%[t], %[t], %[mat]\n\t"
        "strh	%[t], [r12]\n\t"
        "sub	%[out], %[out], #1\n\t"
        "b	L_mc_gp_rd_%=\n\t"
        "\n"
    "L_mc_gp_119_%=:\n\t"
        "cmp	%[out], r4\n\t"
        "blt	L_mc_gp_rde_%=\n\t"
        "lsl	%[f], %[out], #1\n\t"
        "add	%[t], r6, %[f]\n\t"
        "ldrh	%[mat], [%[t]]\n\t"
        "sub	%[f], %[out], r4\n\t"
        "add	r12, %[f], #0\n\t"
        "lsl	r12, r12, #1\n\t"
        "add	r12, r6, r12\n\t"
        "ldrh	%[t], [r12]\n\t"
        "eor	%[t], %[t], %[mat]\n\t"
        "strh	%[t], [r12]\n\t"
        "add	r12, %[f], #8\n\t"
        "lsl	r12, r12, #1\n\t"
        "add	r12, r6, r12\n\t"
        "ldrh	%[t], [r12]\n\t"
        "eor	%[t], %[t], %[mat]\n\t"
        "strh	%[t], [r12]\n\t"
        "sub	%[out], %[out], #1\n\t"
        "b	L_mc_gp_119_%=\n\t"
        "\n"
    "L_mc_gp_rde_%=:\n\t"
        "mul	r12, r7, r4\n\t"
        "mov	%[out], #0\n\t"
        "\n"
    "L_mc_gp_cp_%=:\n\t"
        "cmp	%[out], r4\n\t"
        "bge	L_mc_gp_cpe_%=\n\t"
        "lsl	%[f], %[out], #1\n\t"
        "add	%[t], r6, %[f]\n\t"
        "ldrh	%[mat], [%[t]]\n\t"
        "add	%[f], r12, %[out]\n\t"
        "lsl	%[f], %[f], #1\n\t"
        "add	%[t], r5, %[f]\n\t"
        "strh	%[mat], [%[t]]\n\t"
        "add	%[out], %[out], #1\n\t"
        "b	L_mc_gp_cp_%=\n\t"
        "\n"
    "L_mc_gp_cpe_%=:\n\t"
        "add	r7, r7, #1\n\t"
        "b	L_mc_gp_j_%=\n\t"
        "\n"
    "L_mc_gp_je_%=:\n\t"
        "mov	r7, #0\n\t"
        "\n"
    "L_mc_gp_e_%=:\n\t"
        "cmp	r7, r4\n\t"
        "bge	L_mc_gp_ee_%=\n\t"
        "add	r11, r7, #1\n\t"
        "\n"
    "L_mc_gp_pk_%=:\n\t"
        "cmp	r11, r4\n\t"
        "bge	L_mc_gp_pke_%=\n\t"
        "mul	%[out], r7, r4\n\t"
        "add	%[out], %[out], r7\n\t"
        "lsl	%[out], %[out], #1\n\t"
        "add	%[out], r5, %[out]\n\t"
        "ldrh	%[out], [%[out]]\n\t"
        "sub	%[f], %[out], #1\n\t"
        "lsr	%[f], %[f], #31\n\t"
        "neg	%[f], %[f]\n\t"
        "mov	%[t], r7\n\t"
        "\n"
    "L_mc_gp_pc_%=:\n\t"
        "cmp	%[t], r4\n\t"
        "bgt	L_mc_gp_pce_%=\n\t"
        "mul	%[mat], %[t], r4\n\t"
        "add	r12, %[mat], r11\n\t"
        "add	%[mat], %[mat], r7\n\t"
        "lsl	r12, r12, #1\n\t"
        "add	r12, r5, r12\n\t"
        "ldrh	r12, [r12]\n\t"
        "and	r12, r12, %[f]\n\t"
        "lsl	%[mat], %[mat], #1\n\t"
        "add	%[mat], r5, %[mat]\n\t"
        "ldrh	%[out], [%[mat]]\n\t"
        "eor	%[out], %[out], r12\n\t"
        "strh	%[out], [%[mat]]\n\t"
        "add	%[t], %[t], #1\n\t"
        "b	L_mc_gp_pc_%=\n\t"
        "\n"
    "L_mc_gp_pce_%=:\n\t"
        "add	r11, r11, #1\n\t"
        "b	L_mc_gp_pk_%=\n\t"
        "\n"
    "L_mc_gp_pke_%=:\n\t"
        "mul	%[out], r7, r4\n\t"
        "add	%[out], %[out], r7\n\t"
        "lsl	%[out], %[out], #1\n\t"
        "add	%[out], r5, %[out]\n\t"
        "ldrh	%[out], [%[out]]\n\t"
        "cmp	%[out], #0\n\t"
        "beq	L_mc_gp_sg_%=\n\t"
        "bl	wc_mceliece_gf_inv_scalar_neon\n\t"
        "mov	r9, %[out]\n\t"
        "mov	r8, r7\n\t"
        "\n"
    "L_mc_gp_nc_%=:\n\t"
        "cmp	r8, r4\n\t"
        "bgt	L_mc_gp_nce_%=\n\t"
        "mul	%[out], r8, r4\n\t"
        "add	%[out], %[out], r7\n\t"
        "lsl	%[out], %[out], #1\n\t"
        "add	%[out], r5, %[out]\n\t"
        "ldrh	%[out], [%[out]]\n\t"
        "mov	%[f], r9\n\t"
        "bl	wc_mceliece_gf_mul_scalar_neon\n\t"
        "mul	%[f], r8, r4\n\t"
        "add	%[f], %[f], r7\n\t"
        "lsl	%[f], %[f], #1\n\t"
        "add	%[f], r5, %[f]\n\t"
        "strh	%[out], [%[f]]\n\t"
        "add	r8, r8, #1\n\t"
        "b	L_mc_gp_nc_%=\n\t"
        "\n"
    "L_mc_gp_nce_%=:\n\t"
        "mov	%[out], #0\n\t"
        "\n"
    "L_mc_gp_sv_%=:\n\t"
        "cmp	%[out], r4\n\t"
        "bge	L_mc_gp_sve_%=\n\t"
        "mul	%[f], r7, r4\n\t"
        "add	%[f], %[f], %[out]\n\t"
        "lsl	%[f], %[f], #1\n\t"
        "add	%[f], r5, %[f]\n\t"
        "ldrh	%[t], [%[f]]\n\t"
        "lsl	%[f], %[out], #1\n\t"
        "add	%[f], r6, %[f]\n\t"
        "strh	%[t], [%[f]]\n\t"
        "add	%[out], %[out], #1\n\t"
        "b	L_mc_gp_sv_%=\n\t"
        "\n"
    "L_mc_gp_sve_%=:\n\t"
        "mov	%[out], #0\n\t"
        "lsl	%[f], r7, #1\n\t"
        "add	%[f], r6, %[f]\n\t"
        "strh	%[out], [%[f]]\n\t"
        "mov	r8, r7\n\t"
        "\n"
    "L_mc_gp_el_%=:\n\t"
        "cmp	r8, r4\n\t"
        "bgt	L_mc_gp_ele_%=\n\t"
        "mul	%[out], r8, r4\n\t"
        "add	%[f], %[out], r7\n\t"
        "lsl	%[f], %[f], #1\n\t"
        "add	%[f], r5, %[f]\n\t"
        "ldrh	%[f], [%[f]]\n\t"
        "lsl	%[out], %[out], #1\n\t"
        "add	%[out], r5, %[out]\n\t"
        "mov	%[t], r6\n\t"
        "mov	%[mat], r4\n\t"
        "bl	wc_mceliece_gf_mulc_mac_full_neon\n\t"
        "add	r8, r8, #1\n\t"
        "b	L_mc_gp_el_%=\n\t"
        "\n"
    "L_mc_gp_ele_%=:\n\t"
        "add	r7, r7, #1\n\t"
        "b	L_mc_gp_e_%=\n\t"
        "\n"
    "L_mc_gp_sg_%=:\n\t"
        "mov	r10, #0\n\t"
        "sub	r10, r10, #1\n\t"
        "b	L_mc_gp_dn_%=\n\t"
        "\n"
    "L_mc_gp_ee_%=:\n\t"
        "mul	r12, r4, r4\n\t"
        "ldr	%[f], [sp]\n\t"
        "mov	%[out], #0\n\t"
        "\n"
    "L_mc_gp_o_%=:\n\t"
        "cmp	%[out], r4\n\t"
        "bge	L_mc_gp_oe_%=\n\t"
        "add	%[t], r12, %[out]\n\t"
        "lsl	%[t], %[t], #1\n\t"
        "add	%[t], r5, %[t]\n\t"
        "ldrh	%[mat], [%[t]]\n\t"
        "lsl	%[t], %[out], #1\n\t"
        "add	%[t], %[f], %[t]\n\t"
        "strh	%[mat], [%[t]]\n\t"
        "add	%[out], %[out], #1\n\t"
        "b	L_mc_gp_o_%=\n\t"
        "\n"
    "L_mc_gp_oe_%=:\n\t"
        "ldr	%[f], [sp]\n\t"
        "ldr	%[t], [sp, #8]\n\t"
        "lsr	r12, r4, #3\n\t"
        "lsl	r12, r12, #3\n\t"
        "mov	%[out], #0\n\t"
        "\n"
    "L_mc_gp_stv_%=:\n\t"
        "cmp	%[out], r12\n\t"
        "bge	L_mc_gp_stve_%=\n\t"
        "lsl	%[mat], %[out], #1\n\t"
        "add	%[mat], %[f], %[mat]\n\t"
        "vld1.8	{d0-d1}, [%[mat]]\n\t"
        "lsl	%[mat], %[out], #1\n\t"
        "add	%[mat], %[t], %[mat]\n\t"
        "vst1.8	{d0-d1}, [%[mat]]\n\t"
        "add	%[out], %[out], #8\n\t"
        "b	L_mc_gp_stv_%=\n\t"
        "\n"
    "L_mc_gp_stve_%=:\n\t"
        "\n"
    "L_mc_gp_stg_%=:\n\t"
        "cmp	%[out], r4\n\t"
        "bge	L_mc_gp_stge_%=\n\t"
        "lsl	r12, %[out], #1\n\t"
        "add	%[mat], %[f], r12\n\t"
        "ldrh	%[mat], [%[mat]]\n\t"
        "add	r12, %[t], r12\n\t"
        "strh	%[mat], [r12]\n\t"
        "add	%[out], %[out], #1\n\t"
        "b	L_mc_gp_stg_%=\n\t"
        "\n"
    "L_mc_gp_stge_%=:\n\t"
        "ldr	%[out], [sp, #4]\n\t"
        "bl	wc_mceliece_pk_gen_neon\n\t"
        "mov	r10, %[out]\n\t"
        "\n"
    "L_mc_gp_dn_%=:\n\t"
        "mov	%[out], r10\n\t"
        "add	sp, sp, #12\n\t"
        "pop	{%[prod], %[skp]}\n\t"
        "pop	{%[ctx]}\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [out] "+r" (out), [f] "+r" (f), [t] "+r" (t), [mat] "+r" (mat),
          [prod] "+r" (prod), [skp] "+r" (skp), [ctx] "+r" (ctx)
        :
#else
        :
        : [out] "r" (out), [f] "r" (f), [t] "r" (t), [mat] "r" (mat),
          [prod] "r" (prod), [skp] "r" (skp), [ctx] "r" (ctx)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "q0"
    );
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    (void)t_p;
#else
    (void)t;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
    return (word32)(size_t)out;
}

WOLFSSL_LOCAL int wc_mceliece_controlbits_neon(byte* out, const sword16* pi,
    int w, int n, sword32* temp, sword16* pi_test, void* frames);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER int wc_mceliece_controlbits_neon(byte* out_p,
    const sword16* pi_p, int w_p, int n_p, sword32* temp_p, sword16* pi_test_p,
    void* frames_p)
#else
WC_OMIT_FRAME_POINTER int wc_mceliece_controlbits_neon(byte* out,
    const sword16* pi, int w, int n, sword32* temp, sword16* pi_test,
    void* frames)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register byte* out __asm__ ("r0") = (byte*)out_p;
    register const sword16* pi __asm__ ("r1") = (const sword16*)pi_p;
    register int w __asm__ ("r2") = (int)w_p;
    register int n __asm__ ("r3") = (int)n_p;
    register sword32* temp __asm__ ("r12") = (sword32*)temp_p;
    register sword16* pi_test __asm__ ("lr") = (sword16*)pi_test_p;
    register void* frames __asm__ ("r4") = (void*)frames_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "push	{%[frames]}\n\t"
        "push	{%[temp], %[pi_test]}\n\t"
        "sub	sp, sp, #16\n\t"
        "mov	r4, %[out]\n\t"
        "mov	r5, %[pi]\n\t"
        "mov	r6, %[w]\n\t"
        "mov	r7, %[n]\n\t"
        "ldr	r8, [sp, #20]\n\t"
        "mov	r9, #0\n\t"
        "\n"
    "L_mc_cb_o_%=:\n\t"
        "cmp	r9, #2\n\t"
        "bge	L_mc_cb_fail_%=\n\t"
        "lsl	%[out], r6, #1\n\t"
        "sub	%[out], %[out], #1\n\t"
        "lsr	%[pi], r7, #1\n\t"
        "mul	%[w], %[out], %[pi]\n\t"
        "add	%[w], %[w], #7\n\t"
        "lsr	%[w], %[w], #3\n\t"
        "lsr	%[out], %[w], #2\n\t"
        "and	%[pi], %[w], #3\n\t"
        "mov	%[n], r4\n\t"
        "mov	r12, #0\n\t"
        "mov	%[w], #0\n\t"
        "\n"
    "L_mc_cb_zw_%=:\n\t"
        "cmp	%[w], %[out]\n\t"
        "bge	L_mc_cb_zwe_%=\n\t"
        "str	r12, [%[n]]\n\t"
        "add	%[n], %[n], #4\n\t"
        "add	%[w], %[w], #1\n\t"
        "b	L_mc_cb_zw_%=\n\t"
        "\n"
    "L_mc_cb_zwe_%=:\n\t"
        "mov	%[w], #0\n\t"
        "\n"
    "L_mc_cb_zb_%=:\n\t"
        "cmp	%[w], %[pi]\n\t"
        "bge	L_mc_cb_zbe_%=\n\t"
        "strb	r12, [%[n]]\n\t"
        "add	%[n], %[n], #1\n\t"
        "add	%[w], %[w], #1\n\t"
        "b	L_mc_cb_zb_%=\n\t"
        "\n"
    "L_mc_cb_zbe_%=:\n\t"
        "mov	%[out], r4\n\t"
        "mov	%[pi], #0\n\t"
        "mov	%[w], #1\n\t"
        "mov	%[n], r5\n\t"
        "mov	r12, r6\n\t"
        "str	r12, [sp]\n\t"
        "mov	r12, r7\n\t"
        "str	r12, [sp, #4]\n\t"
        "ldr	r12, [sp, #16]\n\t"
        "str	r12, [sp, #8]\n\t"
        "ldr	r12, [sp, #24]\n\t"
        "str	r12, [sp, #12]\n\t"
        "bl	wc_mceliece_cb_build_neon\n\t"
        "mov	%[out], r8\n\t"
        "mov	%[pi], #0\n\t"
        "\n"
    "L_mc_cb_pt_%=:\n\t"
        "cmp	%[pi], r7\n\t"
        "bge	L_mc_cb_pte_%=\n\t"
        "strh	%[pi], [%[out]]\n\t"
        "add	%[out], %[out], #2\n\t"
        "add	%[pi], %[pi], #1\n\t"
        "b	L_mc_cb_pt_%=\n\t"
        "\n"
    "L_mc_cb_pte_%=:\n\t"
        "mov	r10, r4\n\t"
        "mov	r11, #0\n\t"
        "\n"
    "L_mc_cb_fw_%=:\n\t"
        "cmp	r11, r6\n\t"
        "bge	L_mc_cb_fwe_%=\n\t"
        "mov	%[out], r8\n\t"
        "mov	%[pi], r10\n\t"
        "mov	%[w], r11\n\t"
        "mov	%[n], r7\n\t"
        "bl	wc_mceliece_cb_layer_neon\n\t"
        "lsr	r12, r7, #4\n\t"
        "add	r10, r10, r12\n\t"
        "add	r11, r11, #1\n\t"
        "b	L_mc_cb_fw_%=\n\t"
        "\n"
    "L_mc_cb_fwe_%=:\n\t"
        "sub	r11, r6, #2\n\t"
        "\n"
    "L_mc_cb_bw_%=:\n\t"
        "cmp	r11, #0\n\t"
        "blt	L_mc_cb_bwe_%=\n\t"
        "mov	%[out], r8\n\t"
        "mov	%[pi], r10\n\t"
        "mov	%[w], r11\n\t"
        "mov	%[n], r7\n\t"
        "bl	wc_mceliece_cb_layer_neon\n\t"
        "lsr	r12, r7, #4\n\t"
        "add	r10, r10, r12\n\t"
        "sub	r11, r11, #1\n\t"
        "b	L_mc_cb_bw_%=\n\t"
        "\n"
    "L_mc_cb_bwe_%=:\n\t"
        "mov	%[out], #0\n\t"
        "mov	%[pi], #0\n\t"
        "\n"
    "L_mc_cb_vf_%=:\n\t"
        "cmp	%[pi], r7\n\t"
        "bge	L_mc_cb_vfe_%=\n\t"
        "lsl	%[w], %[pi], #1\n\t"
        "add	%[n], r5, %[w]\n\t"
        "ldrh	%[n], [%[n]]\n\t"
        "add	r12, r8, %[w]\n\t"
        "ldrh	r12, [r12]\n\t"
        "eor	%[n], %[n], r12\n\t"
        "orr	%[out], %[out], %[n]\n\t"
        "add	%[pi], %[pi], #1\n\t"
        "b	L_mc_cb_vf_%=\n\t"
        "\n"
    "L_mc_cb_vfe_%=:\n\t"
        "cmp	%[out], #0\n\t"
        "beq	L_mc_cb_ok_%=\n\t"
        "add	r9, r9, #1\n\t"
        "b	L_mc_cb_o_%=\n\t"
        "\n"
    "L_mc_cb_fail_%=:\n\t"
        "mov	%[out], #0\n\t"
        "sub	%[out], %[out], #1\n\t"
        "b	L_mc_cb_end_%=\n\t"
        "\n"
    "L_mc_cb_ok_%=:\n\t"
        "mov	%[out], #0\n\t"
        "\n"
    "L_mc_cb_end_%=:\n\t"
        "add	sp, sp, #16\n\t"
        "pop	{%[temp], %[pi_test]}\n\t"
        "pop	{%[frames]}\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [out] "+r" (out), [pi] "+r" (pi), [w] "+r" (w), [n] "+r" (n),
          [temp] "+r" (temp), [pi_test] "+r" (pi_test), [frames] "+r" (frames)
        :
#else
        :
        : [out] "r" (out), [pi] "r" (pi), [w] "r" (w), [n] "r" (n),
          [temp] "r" (temp), [pi_test] "r" (pi_test), [frames] "r" (frames)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r5", "r6", "r7", "r8", "r9", "r10", "r11"
    );
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    (void)w_p;
#else
    (void)w;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    (void)n_p;
#else
    (void)n;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
    return (word32)(size_t)out;
}

WOLFSSL_LOCAL void wc_mceliece_u64_minmax_vec_neon(word64* a, word64* b,
    int count);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void wc_mceliece_u64_minmax_vec_neon(word64* a_p,
    word64* b_p, int count_p)
#else
WC_OMIT_FRAME_POINTER void wc_mceliece_u64_minmax_vec_neon(word64* a, word64* b,
    int count)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word64* a __asm__ ("r0") = (word64*)a_p;
    register word64* b __asm__ ("r1") = (word64*)b_p;
    register int count __asm__ ("r2") = (int)count_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "bic	r3, %[count], #0x1\n\t"
        "mov	r12, #0\n\t"
        "\n"
    "L_mc_mmv_%=:\n\t"
        "cmp	r12, r3\n\t"
        "bge	L_mc_mmve_%=\n\t"
        "vld1.8	{d0-d1}, [%[a]]\n\t"
        "vld1.8	{d2-d3}, [%[b]]\n\t"
        "vsub.i64	q2, q1, q0\n\t"
        "vshr.s64	q2, q2, #63\n\t"
        "veor	q3, q0, q1\n\t"
        "vand	q3, q3, q2\n\t"
        "veor	q0, q0, q3\n\t"
        "veor	q1, q1, q3\n\t"
        "vst1.8	{d0-d1}, [%[a]]\n\t"
        "vst1.8	{d2-d3}, [%[b]]\n\t"
        "add	%[a], %[a], #16\n\t"
        "add	%[b], %[b], #16\n\t"
        "add	r12, r12, #2\n\t"
        "b	L_mc_mmv_%=\n\t"
        "\n"
    "L_mc_mmve_%=:\n\t"
        "\n"
    "L_mc_mmvt_%=:\n\t"
        "cmp	r12, %[count]\n\t"
        "bge	L_mc_mmvte_%=\n\t"
        "vld1.8	{d0}, [%[a]]\n\t"
        "vld1.8	{d2}, [%[b]]\n\t"
        "vsub.i64	d4, d2, d0\n\t"
        "vshr.s64	d4, d4, #63\n\t"
        "veor	d6, d0, d2\n\t"
        "vand	d6, d6, d4\n\t"
        "veor	d0, d0, d6\n\t"
        "veor	d2, d2, d6\n\t"
        "vst1.8	{d0}, [%[a]]\n\t"
        "vst1.8	{d2}, [%[b]]\n\t"
        "add	%[a], %[a], #8\n\t"
        "add	%[b], %[b], #8\n\t"
        "add	r12, r12, #1\n\t"
        "b	L_mc_mmvt_%=\n\t"
        "\n"
    "L_mc_mmvte_%=:\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [a] "+r" (a), [b] "+r" (b), [count] "+r" (count)
        :
#else
        :
        : [a] "r" (a), [b] "r" (b), [count] "r" (count)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r3", "r12", "q0", "q1", "q2", "q3"
    );
}

#endif /* WOLFSSL_ARMASM_NO_NEON */
#endif /* WOLFSSL_HAVE_MCELIECE */

#endif /* WOLFSSL_ARMASM_INLINE */
#endif /* !__aarch64__ && !WOLFSSL_ARMASM_THUMB2 */
#endif /* WOLFSSL_ARMASM */
