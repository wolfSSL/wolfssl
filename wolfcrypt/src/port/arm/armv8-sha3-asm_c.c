/* armv8-sha3-asm
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif /* HAVE_CONFIG_H */
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

/* Generated using (from wolfssl):
 *   cd ../scripts
 *   ruby ./sha3/sha3.rb arm64 ../wolfssl/wolfcrypt/src/port/arm/armv8-sha3-asm.c
 */
#ifdef WOLFSSL_ARMASM
#ifdef __aarch64__
#ifdef WOLFSSL_ARMASM_INLINE
#include <wolfssl/wolfcrypt/sha3.h>

#ifdef WOLFSSL_SHA3
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
static const word64 L_SHA3_transform_crypto_r[] = {
    0x1UL,
    0x8082UL,
    0x800000000000808aUL,
    0x8000000080008000UL,
    0x808bUL,
    0x80000001UL,
    0x8000000080008081UL,
    0x8000000000008009UL,
    0x8aUL,
    0x88UL,
    0x80008009UL,
    0x8000000aUL,
    0x8000808bUL,
    0x800000000000008bUL,
    0x8000000000008089UL,
    0x8000000000008003UL,
    0x8000000000008002UL,
    0x8000000000000080UL,
    0x800aUL,
    0x800000008000000aUL,
    0x8000000080008081UL,
    0x8000000000008080UL,
    0x80000001UL,
    0x8000000080008008UL,
};

void BlockSha3_crypto(word64* state)
{
    __asm__ __volatile__ (
#ifdef __APPLE__
    ".arch_extension sha3\n\t"
#endif /* __APPLE__ */
#ifndef __APPLE__
        "adrp x1, %[L_SHA3_transform_crypto_r]\n\t"
        "add  x1, x1, :lo12:%[L_SHA3_transform_crypto_r]\n\t"
#else
        "adrp x1, %[L_SHA3_transform_crypto_r]@PAGE\n\t"
        "add  x1, x1, %[L_SHA3_transform_crypto_r]@PAGEOFF\n\t"
#endif /* __APPLE__ */
        "ld4	{v0.d, v1.d, v2.d, v3.d}[0], [%x[state]], #32\n\t"
        "ld4	{v4.d, v5.d, v6.d, v7.d}[0], [%x[state]], #32\n\t"
        "ld4	{v8.d, v9.d, v10.d, v11.d}[0], [%x[state]], #32\n\t"
        "ld4	{v12.d, v13.d, v14.d, v15.d}[0], [%x[state]], #32\n\t"
        "ld4	{v16.d, v17.d, v18.d, v19.d}[0], [%x[state]], #32\n\t"
        "ld4	{v20.d, v21.d, v22.d, v23.d}[0], [%x[state]], #32\n\t"
        "ld1	{v24.1d}, [%x[state]]\n\t"
        "sub	%x[state], %x[state], #0xc0\n\t"
        "mov	x2, #24\n\t"
        /* Start of 24 rounds */
        "\n"
    "L_sha3_crypto_begin_%=: \n\t"
        /* Col Mix */
        "eor3	v31.16b, v0.16b, v5.16b, v10.16b\n\t"
        "eor3	v27.16b, v1.16b, v6.16b, v11.16b\n\t"
        "eor3	v28.16b, v2.16b, v7.16b, v12.16b\n\t"
        "eor3	v29.16b, v3.16b, v8.16b, v13.16b\n\t"
        "eor3	v30.16b, v4.16b, v9.16b, v14.16b\n\t"
        "eor3	v31.16b, v31.16b, v15.16b, v20.16b\n\t"
        "eor3	v27.16b, v27.16b, v16.16b, v21.16b\n\t"
        "eor3	v28.16b, v28.16b, v17.16b, v22.16b\n\t"
        "eor3	v29.16b, v29.16b, v18.16b, v23.16b\n\t"
        "eor3	v30.16b, v30.16b, v19.16b, v24.16b\n\t"
        "rax1	v25.2d, v30.2d, v27.2d\n\t"
        "rax1	v26.2d, v31.2d, v28.2d\n\t"
        "rax1	v27.2d, v27.2d, v29.2d\n\t"
        "rax1	v28.2d, v28.2d, v30.2d\n\t"
        "rax1	v29.2d, v29.2d, v31.2d\n\t"
        "eor	v0.16b, v0.16b, v25.16b\n\t"
        "xar	v30.2d, v1.2d, v26.2d, #63\n\t"
        "xar	v1.2d, v6.2d, v26.2d, #20\n\t"
        "xar	v6.2d, v9.2d, v29.2d, #44\n\t"
        "xar	v9.2d, v22.2d, v27.2d, #3\n\t"
        "xar	v22.2d, v14.2d, v29.2d, #25\n\t"
        "xar	v14.2d, v20.2d, v25.2d, #46\n\t"
        "xar	v20.2d, v2.2d, v27.2d, #2\n\t"
        "xar	v2.2d, v12.2d, v27.2d, #21\n\t"
        "xar	v12.2d, v13.2d, v28.2d, #39\n\t"
        "xar	v13.2d, v19.2d, v29.2d, #56\n\t"
        "xar	v19.2d, v23.2d, v28.2d, #8\n\t"
        "xar	v23.2d, v15.2d, v25.2d, #23\n\t"
        "xar	v15.2d, v4.2d, v29.2d, #37\n\t"
        "xar	v4.2d, v24.2d, v29.2d, #50\n\t"
        "xar	v24.2d, v21.2d, v26.2d, #62\n\t"
        "xar	v21.2d, v8.2d, v28.2d, #9\n\t"
        "xar	v8.2d, v16.2d, v26.2d, #19\n\t"
        "xar	v16.2d, v5.2d, v25.2d, #28\n\t"
        "xar	v5.2d, v3.2d, v28.2d, #36\n\t"
        "xar	v3.2d, v18.2d, v28.2d, #43\n\t"
        "xar	v18.2d, v17.2d, v27.2d, #49\n\t"
        "xar	v17.2d, v11.2d, v26.2d, #54\n\t"
        "xar	v11.2d, v7.2d, v27.2d, #58\n\t"
        "xar	v7.2d, v10.2d, v25.2d, #61\n\t"
        /* Row Mix */
        "mov	v25.16b, v0.16b\n\t"
        "mov	v26.16b, v1.16b\n\t"
        "bcax	v0.16b, v25.16b, v2.16b, v26.16b\n\t"
        "bcax	v1.16b, v26.16b, v3.16b, v2.16b\n\t"
        "bcax	v2.16b, v2.16b, v4.16b, v3.16b\n\t"
        "bcax	v3.16b, v3.16b, v25.16b, v4.16b\n\t"
        "bcax	v4.16b, v4.16b, v26.16b, v25.16b\n\t"
        "mov	v25.16b, v5.16b\n\t"
        "mov	v26.16b, v6.16b\n\t"
        "bcax	v5.16b, v25.16b, v7.16b, v26.16b\n\t"
        "bcax	v6.16b, v26.16b, v8.16b, v7.16b\n\t"
        "bcax	v7.16b, v7.16b, v9.16b, v8.16b\n\t"
        "bcax	v8.16b, v8.16b, v25.16b, v9.16b\n\t"
        "bcax	v9.16b, v9.16b, v26.16b, v25.16b\n\t"
        "mov	v26.16b, v11.16b\n\t"
        "bcax	v10.16b, v30.16b, v12.16b, v26.16b\n\t"
        "bcax	v11.16b, v26.16b, v13.16b, v12.16b\n\t"
        "bcax	v12.16b, v12.16b, v14.16b, v13.16b\n\t"
        "bcax	v13.16b, v13.16b, v30.16b, v14.16b\n\t"
        "bcax	v14.16b, v14.16b, v26.16b, v30.16b\n\t"
        "mov	v25.16b, v15.16b\n\t"
        "mov	v26.16b, v16.16b\n\t"
        "bcax	v15.16b, v25.16b, v17.16b, v26.16b\n\t"
        "bcax	v16.16b, v26.16b, v18.16b, v17.16b\n\t"
        "bcax	v17.16b, v17.16b, v19.16b, v18.16b\n\t"
        "bcax	v18.16b, v18.16b, v25.16b, v19.16b\n\t"
        "bcax	v19.16b, v19.16b, v26.16b, v25.16b\n\t"
        "mov	v25.16b, v20.16b\n\t"
        "mov	v26.16b, v21.16b\n\t"
        "bcax	v20.16b, v25.16b, v22.16b, v26.16b\n\t"
        "bcax	v21.16b, v26.16b, v23.16b, v22.16b\n\t"
        "bcax	v22.16b, v22.16b, v24.16b, v23.16b\n\t"
        "bcax	v23.16b, v23.16b, v25.16b, v24.16b\n\t"
        "bcax	v24.16b, v24.16b, v26.16b, v25.16b\n\t"
        "ld1r	{v30.2d}, [x1], #8\n\t"
        "subs	x2, x2, #1\n\t"
        "eor	v0.16b, v0.16b, v30.16b\n\t"
        "bne	L_sha3_crypto_begin_%=\n\t"
        "st4	{v0.d, v1.d, v2.d, v3.d}[0], [%x[state]], #32\n\t"
        "st4	{v4.d, v5.d, v6.d, v7.d}[0], [%x[state]], #32\n\t"
        "st4	{v8.d, v9.d, v10.d, v11.d}[0], [%x[state]], #32\n\t"
        "st4	{v12.d, v13.d, v14.d, v15.d}[0], [%x[state]], #32\n\t"
        "st4	{v16.d, v17.d, v18.d, v19.d}[0], [%x[state]], #32\n\t"
        "st4	{v20.d, v21.d, v22.d, v23.d}[0], [%x[state]], #32\n\t"
        "st1	{v24.1d}, [%x[state]]\n\t"
        : [state] "+r" (state)
        : [L_SHA3_transform_crypto_r] "S" (L_SHA3_transform_crypto_r)
        : "memory", "x1", "x2", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15", "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31", "cc"
    );
}

#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
static const word64 L_SHA3_transform_base_r[] = {
    0x1UL,
    0x8082UL,
    0x800000000000808aUL,
    0x8000000080008000UL,
    0x808bUL,
    0x80000001UL,
    0x8000000080008081UL,
    0x8000000000008009UL,
    0x8aUL,
    0x88UL,
    0x80008009UL,
    0x8000000aUL,
    0x8000808bUL,
    0x800000000000008bUL,
    0x8000000000008089UL,
    0x8000000000008003UL,
    0x8000000000008002UL,
    0x8000000000000080UL,
    0x800aUL,
    0x800000008000000aUL,
    0x8000000080008081UL,
    0x8000000000008080UL,
    0x80000001UL,
    0x8000000080008008UL,
};

void BlockSha3_base(word64* state)
{
    __asm__ __volatile__ (
        "stp	x29, x30, [sp, #-64]!\n\t"
        "add	x29, sp, #0\n\t"
#ifndef __APPLE__
        "adrp x27, %[L_SHA3_transform_base_r]\n\t"
        "add  x27, x27, :lo12:%[L_SHA3_transform_base_r]\n\t"
#else
        "adrp x27, %[L_SHA3_transform_base_r]@PAGE\n\t"
        "add  x27, x27, %[L_SHA3_transform_base_r]@PAGEOFF\n\t"
#endif /* __APPLE__ */
        "ldp	x1, x2, [%x[state]]\n\t"
        "ldp	x3, x4, [%x[state], #16]\n\t"
        "ldp	x5, x6, [%x[state], #32]\n\t"
        "ldp	x7, x8, [%x[state], #48]\n\t"
        "ldp	x9, x10, [%x[state], #64]\n\t"
        "ldp	x11, x12, [%x[state], #80]\n\t"
        "ldp	x13, x14, [%x[state], #96]\n\t"
        "ldp	x15, x16, [%x[state], #112]\n\t"
        "ldp	x17, x19, [%x[state], #128]\n\t"
        "ldp	x20, x21, [%x[state], #144]\n\t"
        "ldp	x22, x23, [%x[state], #160]\n\t"
        "ldp	x24, x25, [%x[state], #176]\n\t"
        "ldr	x26, [%x[state], #192]\n\t"
        "str	%x[state], [x29, #40]\n\t"
        "mov	x28, #24\n\t"
        /* Start of 24 rounds */
        "\n"
    "L_SHA3_transform_base_begin_%=: \n\t"
        "stp	x27, x28, [x29, #48]\n\t"
        "eor	%x[state], x5, x10\n\t"
        "eor	x30, x1, x6\n\t"
        "eor	x28, x3, x8\n\t"
        "eor	%x[state], %x[state], x15\n\t"
        "eor	x30, x30, x11\n\t"
        "eor	x28, x28, x13\n\t"
        "eor	%x[state], %x[state], x21\n\t"
        "eor	x30, x30, x16\n\t"
        "eor	x28, x28, x19\n\t"
        "eor	%x[state], %x[state], x26\n\t"
        "eor	x30, x30, x22\n\t"
        "eor	x28, x28, x24\n\t"
        "str	%x[state], [x29, #32]\n\t"
        "str	x28, [x29, #24]\n\t"
        "eor	x27, x2, x7\n\t"
        "eor	x28, x4, x9\n\t"
        "eor	x27, x27, x12\n\t"
        "eor	x28, x28, x14\n\t"
        "eor	x27, x27, x17\n\t"
        "eor	x28, x28, x20\n\t"
        "eor	x27, x27, x23\n\t"
        "eor	x28, x28, x25\n\t"
        "eor	%x[state], %x[state], x27, ror 63\n\t"
        "eor	x27, x27, x28, ror 63\n\t"
        "eor	x1, x1, %x[state]\n\t"
        "eor	x6, x6, %x[state]\n\t"
        "eor	x11, x11, %x[state]\n\t"
        "eor	x16, x16, %x[state]\n\t"
        "eor	x22, x22, %x[state]\n\t"
        "eor	x3, x3, x27\n\t"
        "eor	x8, x8, x27\n\t"
        "eor	x13, x13, x27\n\t"
        "eor	x19, x19, x27\n\t"
        "eor	x24, x24, x27\n\t"
        "ldr	%x[state], [x29, #32]\n\t"
        "ldr	x27, [x29, #24]\n\t"
        "eor	x28, x28, x30, ror 63\n\t"
        "eor	x30, x30, x27, ror 63\n\t"
        "eor	x27, x27, %x[state], ror 63\n\t"
        "eor	x5, x5, x28\n\t"
        "eor	x10, x10, x28\n\t"
        "eor	x15, x15, x28\n\t"
        "eor	x21, x21, x28\n\t"
        "eor	x26, x26, x28\n\t"
        "eor	x2, x2, x30\n\t"
        "eor	x7, x7, x30\n\t"
        "eor	x12, x12, x30\n\t"
        "eor	x17, x17, x30\n\t"
        "eor	x23, x23, x30\n\t"
        "eor	x4, x4, x27\n\t"
        "eor	x9, x9, x27\n\t"
        "eor	x14, x14, x27\n\t"
        "eor	x20, x20, x27\n\t"
        "eor	x25, x25, x27\n\t"
        /* Swap Rotate */
        "ror	%x[state], x2, #63\n\t"
        "ror	x2, x7, #20\n\t"
        "ror	x7, x10, #44\n\t"
        "ror	x10, x24, #3\n\t"
        "ror	x24, x15, #25\n\t"
        "ror	x15, x22, #46\n\t"
        "ror	x22, x3, #2\n\t"
        "ror	x3, x13, #21\n\t"
        "ror	x13, x14, #39\n\t"
        "ror	x14, x21, #56\n\t"
        "ror	x21, x25, #8\n\t"
        "ror	x25, x16, #23\n\t"
        "ror	x16, x5, #37\n\t"
        "ror	x5, x26, #50\n\t"
        "ror	x26, x23, #62\n\t"
        "ror	x23, x9, #9\n\t"
        "ror	x9, x17, #19\n\t"
        "ror	x17, x6, #28\n\t"
        "ror	x6, x4, #36\n\t"
        "ror	x4, x20, #43\n\t"
        "ror	x20, x19, #49\n\t"
        "ror	x19, x12, #54\n\t"
        "ror	x12, x8, #58\n\t"
        "ror	x8, x11, #61\n\t"
        /* Row Mix */
        "bic	x11, x3, x2\n\t"
        "bic	x27, x4, x3\n\t"
        "bic	x28, x1, x5\n\t"
        "bic	x30, x2, x1\n\t"
        "eor	x1, x1, x11\n\t"
        "eor	x2, x2, x27\n\t"
        "bic	x11, x5, x4\n\t"
        "eor	x4, x4, x28\n\t"
        "eor	x3, x3, x11\n\t"
        "eor	x5, x5, x30\n\t"
        "bic	x11, x8, x7\n\t"
        "bic	x27, x9, x8\n\t"
        "bic	x28, x6, x10\n\t"
        "bic	x30, x7, x6\n\t"
        "eor	x6, x6, x11\n\t"
        "eor	x7, x7, x27\n\t"
        "bic	x11, x10, x9\n\t"
        "eor	x9, x9, x28\n\t"
        "eor	x8, x8, x11\n\t"
        "eor	x10, x10, x30\n\t"
        "bic	x11, x13, x12\n\t"
        "bic	x27, x14, x13\n\t"
        "bic	x28, %x[state], x15\n\t"
        "bic	x30, x12, %x[state]\n\t"
        "eor	x11, %x[state], x11\n\t"
        "eor	x12, x12, x27\n\t"
        "bic	%x[state], x15, x14\n\t"
        "eor	x14, x14, x28\n\t"
        "eor	x13, x13, %x[state]\n\t"
        "eor	x15, x15, x30\n\t"
        "bic	%x[state], x19, x17\n\t"
        "bic	x27, x20, x19\n\t"
        "bic	x28, x16, x21\n\t"
        "bic	x30, x17, x16\n\t"
        "eor	x16, x16, %x[state]\n\t"
        "eor	x17, x17, x27\n\t"
        "bic	%x[state], x21, x20\n\t"
        "eor	x20, x20, x28\n\t"
        "eor	x19, x19, %x[state]\n\t"
        "eor	x21, x21, x30\n\t"
        "bic	%x[state], x24, x23\n\t"
        "bic	x27, x25, x24\n\t"
        "bic	x28, x22, x26\n\t"
        "bic	x30, x23, x22\n\t"
        "eor	x22, x22, %x[state]\n\t"
        "eor	x23, x23, x27\n\t"
        "bic	%x[state], x26, x25\n\t"
        "eor	x25, x25, x28\n\t"
        "eor	x24, x24, %x[state]\n\t"
        "eor	x26, x26, x30\n\t"
        /* Done transforming */
        "ldp	x27, x28, [x29, #48]\n\t"
        "ldr	%x[state], [x27], #8\n\t"
        "subs	x28, x28, #1\n\t"
        "eor	x1, x1, %x[state]\n\t"
        "bne	L_SHA3_transform_base_begin_%=\n\t"
        "ldr	%x[state], [x29, #40]\n\t"
        "stp	x1, x2, [%x[state]]\n\t"
        "stp	x3, x4, [%x[state], #16]\n\t"
        "stp	x5, x6, [%x[state], #32]\n\t"
        "stp	x7, x8, [%x[state], #48]\n\t"
        "stp	x9, x10, [%x[state], #64]\n\t"
        "stp	x11, x12, [%x[state], #80]\n\t"
        "stp	x13, x14, [%x[state], #96]\n\t"
        "stp	x15, x16, [%x[state], #112]\n\t"
        "stp	x17, x19, [%x[state], #128]\n\t"
        "stp	x20, x21, [%x[state], #144]\n\t"
        "stp	x22, x23, [%x[state], #160]\n\t"
        "stp	x24, x25, [%x[state], #176]\n\t"
        "str	x26, [%x[state], #192]\n\t"
        "ldp	x29, x30, [sp], #0x40\n\t"
        : [state] "+r" (state)
        : [L_SHA3_transform_base_r] "S" (L_SHA3_transform_base_r)
        : "memory", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "cc"
    );
}

#endif /* WOLFSSL_SHA3 */
#endif /* __aarch64__ */
#endif /* WOLFSSL_ARMASM */
#endif /* WOLFSSL_ARMASM_INLINE */
