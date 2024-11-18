/* armv8-kyber-asm
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
 *   ruby ./kyber/kyber.rb arm64 ../wolfssl/wolfcrypt/src/port/arm/armv8-kyber-asm.c
 */
#ifdef WOLFSSL_ARMASM
#ifdef __aarch64__
#ifdef WOLFSSL_ARMASM_INLINE
static const word16 L_kyber_aarch64_q[] = {
    0xd01,
    0xd01,
    0xd01,
    0xd01,
    0xd01,
    0xd01,
    0xd01,
    0xd01,
};

static const word16 L_kyber_aarch64_consts[] = {
    0xd01,
    0xf301,
    0x4ebf,
    0x549,
    0x5049,
    0x0,
    0x0,
    0x0,
};

static const word64 L_sha3_aarch64_r[] = {
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

#include <wolfssl/wolfcrypt/wc_kyber.h>

#ifdef WOLFSSL_WC_KYBER
static const word16 L_kyber_aarch64_zetas[] = {
    0x8ed,
    0xa0b,
    0xb9a,
    0x714,
    0x5d5,
    0x58e,
    0x11f,
    0xca,
    0xc56,
    0x26e,
    0x629,
    0xb6,
    0x3c2,
    0x84f,
    0x73f,
    0x5bc,
    0x23d,
    0x7d4,
    0x108,
    0x17f,
    0x9c4,
    0x5b2,
    0x6bf,
    0xc7f,
    0xa58,
    0x3f9,
    0x2dc,
    0x260,
    0x6fb,
    0x19b,
    0xc34,
    0x6de,
    0x4c7,
    0x4c7,
    0x4c7,
    0x4c7,
    0x28c,
    0x28c,
    0x28c,
    0x28c,
    0xad9,
    0xad9,
    0xad9,
    0xad9,
    0x3f7,
    0x3f7,
    0x3f7,
    0x3f7,
    0x7f4,
    0x7f4,
    0x7f4,
    0x7f4,
    0x5d3,
    0x5d3,
    0x5d3,
    0x5d3,
    0xbe7,
    0xbe7,
    0xbe7,
    0xbe7,
    0x6f9,
    0x6f9,
    0x6f9,
    0x6f9,
    0x204,
    0x204,
    0x204,
    0x204,
    0xcf9,
    0xcf9,
    0xcf9,
    0xcf9,
    0xbc1,
    0xbc1,
    0xbc1,
    0xbc1,
    0xa67,
    0xa67,
    0xa67,
    0xa67,
    0x6af,
    0x6af,
    0x6af,
    0x6af,
    0x877,
    0x877,
    0x877,
    0x877,
    0x7e,
    0x7e,
    0x7e,
    0x7e,
    0x5bd,
    0x5bd,
    0x5bd,
    0x5bd,
    0x9ac,
    0x9ac,
    0x9ac,
    0x9ac,
    0xca7,
    0xca7,
    0xca7,
    0xca7,
    0xbf2,
    0xbf2,
    0xbf2,
    0xbf2,
    0x33e,
    0x33e,
    0x33e,
    0x33e,
    0x6b,
    0x6b,
    0x6b,
    0x6b,
    0x774,
    0x774,
    0x774,
    0x774,
    0xc0a,
    0xc0a,
    0xc0a,
    0xc0a,
    0x94a,
    0x94a,
    0x94a,
    0x94a,
    0xb73,
    0xb73,
    0xb73,
    0xb73,
    0x3c1,
    0x3c1,
    0x3c1,
    0x3c1,
    0x71d,
    0x71d,
    0x71d,
    0x71d,
    0xa2c,
    0xa2c,
    0xa2c,
    0xa2c,
    0x1c0,
    0x1c0,
    0x1c0,
    0x1c0,
    0x8d8,
    0x8d8,
    0x8d8,
    0x8d8,
    0x2a5,
    0x2a5,
    0x2a5,
    0x2a5,
    0x806,
    0x806,
    0x806,
    0x806,
    0x8b2,
    0x8b2,
    0x1ae,
    0x1ae,
    0x22b,
    0x22b,
    0x34b,
    0x34b,
    0x81e,
    0x81e,
    0x367,
    0x367,
    0x60e,
    0x60e,
    0x69,
    0x69,
    0x1a6,
    0x1a6,
    0x24b,
    0x24b,
    0xb1,
    0xb1,
    0xc16,
    0xc16,
    0xbde,
    0xbde,
    0xb35,
    0xb35,
    0x626,
    0x626,
    0x675,
    0x675,
    0xc0b,
    0xc0b,
    0x30a,
    0x30a,
    0x487,
    0x487,
    0xc6e,
    0xc6e,
    0x9f8,
    0x9f8,
    0x5cb,
    0x5cb,
    0xaa7,
    0xaa7,
    0x45f,
    0x45f,
    0x6cb,
    0x6cb,
    0x284,
    0x284,
    0x999,
    0x999,
    0x15d,
    0x15d,
    0x1a2,
    0x1a2,
    0x149,
    0x149,
    0xc65,
    0xc65,
    0xcb6,
    0xcb6,
    0x331,
    0x331,
    0x449,
    0x449,
    0x25b,
    0x25b,
    0x262,
    0x262,
    0x52a,
    0x52a,
    0x7fc,
    0x7fc,
    0x748,
    0x748,
    0x180,
    0x180,
    0x842,
    0x842,
    0xc79,
    0xc79,
    0x4c2,
    0x4c2,
    0x7ca,
    0x7ca,
    0x997,
    0x997,
    0xdc,
    0xdc,
    0x85e,
    0x85e,
    0x686,
    0x686,
    0x860,
    0x860,
    0x707,
    0x707,
    0x803,
    0x803,
    0x31a,
    0x31a,
    0x71b,
    0x71b,
    0x9ab,
    0x9ab,
    0x99b,
    0x99b,
    0x1de,
    0x1de,
    0xc95,
    0xc95,
    0xbcd,
    0xbcd,
    0x3e4,
    0x3e4,
    0x3df,
    0x3df,
    0x3be,
    0x3be,
    0x74d,
    0x74d,
    0x5f2,
    0x5f2,
    0x65c,
    0x65c,
};

static const word16 L_kyber_aarch64_zetas_qinv[] = {
    0xffed,
    0x7b0b,
    0x399a,
    0x314,
    0x34d5,
    0xcf8e,
    0x6e1f,
    0xbeca,
    0xae56,
    0x6c6e,
    0xf129,
    0xc2b6,
    0x29c2,
    0x54f,
    0xd43f,
    0x79bc,
    0xe93d,
    0x43d4,
    0x9908,
    0x8e7f,
    0x15c4,
    0xfbb2,
    0x53bf,
    0x997f,
    0x9258,
    0x5ef9,
    0xd6dc,
    0x2260,
    0x47fb,
    0x229b,
    0x6834,
    0xc0de,
    0xe9c7,
    0xe9c7,
    0xe9c7,
    0xe9c7,
    0xe68c,
    0xe68c,
    0xe68c,
    0xe68c,
    0x5d9,
    0x5d9,
    0x5d9,
    0x5d9,
    0x78f7,
    0x78f7,
    0x78f7,
    0x78f7,
    0xa3f4,
    0xa3f4,
    0xa3f4,
    0xa3f4,
    0x4ed3,
    0x4ed3,
    0x4ed3,
    0x4ed3,
    0x50e7,
    0x50e7,
    0x50e7,
    0x50e7,
    0x61f9,
    0x61f9,
    0x61f9,
    0x61f9,
    0xce04,
    0xce04,
    0xce04,
    0xce04,
    0x67f9,
    0x67f9,
    0x67f9,
    0x67f9,
    0x3ec1,
    0x3ec1,
    0x3ec1,
    0x3ec1,
    0xcf67,
    0xcf67,
    0xcf67,
    0xcf67,
    0x23af,
    0x23af,
    0x23af,
    0x23af,
    0xfd77,
    0xfd77,
    0xfd77,
    0xfd77,
    0x9a7e,
    0x9a7e,
    0x9a7e,
    0x9a7e,
    0x6cbd,
    0x6cbd,
    0x6cbd,
    0x6cbd,
    0x4dac,
    0x4dac,
    0x4dac,
    0x4dac,
    0x91a7,
    0x91a7,
    0x91a7,
    0x91a7,
    0xc1f2,
    0xc1f2,
    0xc1f2,
    0xc1f2,
    0xdd3e,
    0xdd3e,
    0xdd3e,
    0xdd3e,
    0x916b,
    0x916b,
    0x916b,
    0x916b,
    0x2374,
    0x2374,
    0x2374,
    0x2374,
    0x8a0a,
    0x8a0a,
    0x8a0a,
    0x8a0a,
    0x474a,
    0x474a,
    0x474a,
    0x474a,
    0x3473,
    0x3473,
    0x3473,
    0x3473,
    0x36c1,
    0x36c1,
    0x36c1,
    0x36c1,
    0x8e1d,
    0x8e1d,
    0x8e1d,
    0x8e1d,
    0xce2c,
    0xce2c,
    0xce2c,
    0xce2c,
    0x41c0,
    0x41c0,
    0x41c0,
    0x41c0,
    0x10d8,
    0x10d8,
    0x10d8,
    0x10d8,
    0xa1a5,
    0xa1a5,
    0xa1a5,
    0xa1a5,
    0xba06,
    0xba06,
    0xba06,
    0xba06,
    0xfeb2,
    0xfeb2,
    0x2bae,
    0x2bae,
    0xd32b,
    0xd32b,
    0x344b,
    0x344b,
    0x821e,
    0x821e,
    0xc867,
    0xc867,
    0x500e,
    0x500e,
    0xab69,
    0xab69,
    0x93a6,
    0x93a6,
    0x334b,
    0x334b,
    0x3b1,
    0x3b1,
    0xee16,
    0xee16,
    0xc5de,
    0xc5de,
    0x5a35,
    0x5a35,
    0x1826,
    0x1826,
    0x1575,
    0x1575,
    0x7d0b,
    0x7d0b,
    0x810a,
    0x810a,
    0x2987,
    0x2987,
    0x766e,
    0x766e,
    0x71f8,
    0x71f8,
    0xb6cb,
    0xb6cb,
    0x8fa7,
    0x8fa7,
    0x315f,
    0x315f,
    0xb7cb,
    0xb7cb,
    0x4e84,
    0x4e84,
    0x4499,
    0x4499,
    0x485d,
    0x485d,
    0xc7a2,
    0xc7a2,
    0x4c49,
    0x4c49,
    0xeb65,
    0xeb65,
    0xceb6,
    0xceb6,
    0x8631,
    0x8631,
    0x4f49,
    0x4f49,
    0x635b,
    0x635b,
    0x862,
    0x862,
    0xe32a,
    0xe32a,
    0x3bfc,
    0x3bfc,
    0x5f48,
    0x5f48,
    0x8180,
    0x8180,
    0xae42,
    0xae42,
    0xe779,
    0xe779,
    0x2ac2,
    0x2ac2,
    0xc5ca,
    0xc5ca,
    0x5e97,
    0x5e97,
    0xd4dc,
    0xd4dc,
    0x425e,
    0x425e,
    0x3886,
    0x3886,
    0x2860,
    0x2860,
    0xac07,
    0xac07,
    0xe103,
    0xe103,
    0xb11a,
    0xb11a,
    0xa81b,
    0xa81b,
    0x5aab,
    0x5aab,
    0x2a9b,
    0x2a9b,
    0xbbde,
    0xbbde,
    0x7b95,
    0x7b95,
    0xa2cd,
    0xa2cd,
    0x6fe4,
    0x6fe4,
    0xb0df,
    0xb0df,
    0x5dbe,
    0x5dbe,
    0x1e4d,
    0x1e4d,
    0xbbf2,
    0xbbf2,
    0x5a5c,
    0x5a5c,
};

void kyber_ntt(sword16* r)
{
    __asm__ __volatile__ (
#ifndef __APPLE__
        "adrp x2, %[L_kyber_aarch64_zetas]\n\t"
        "add  x2, x2, :lo12:%[L_kyber_aarch64_zetas]\n\t"
#else
        "adrp x2, %[L_kyber_aarch64_zetas]@PAGE\n\t"
        "add  x2, x2, %[L_kyber_aarch64_zetas]@PAGEOFF\n\t"
#endif /* __APPLE__ */
#ifndef __APPLE__
        "adrp x3, %[L_kyber_aarch64_zetas_qinv]\n\t"
        "add  x3, x3, :lo12:%[L_kyber_aarch64_zetas_qinv]\n\t"
#else
        "adrp x3, %[L_kyber_aarch64_zetas_qinv]@PAGE\n\t"
        "add  x3, x3, %[L_kyber_aarch64_zetas_qinv]@PAGEOFF\n\t"
#endif /* __APPLE__ */
#ifndef __APPLE__
        "adrp x4, %[L_kyber_aarch64_consts]\n\t"
        "add  x4, x4, :lo12:%[L_kyber_aarch64_consts]\n\t"
#else
        "adrp x4, %[L_kyber_aarch64_consts]@PAGE\n\t"
        "add  x4, x4, %[L_kyber_aarch64_consts]@PAGEOFF\n\t"
#endif /* __APPLE__ */
        "add	x1, %x[r], #0x100\n\t"
        "ldr	q4, [x4]\n\t"
        "ldr	q5, [%x[r]]\n\t"
        "ldr	q6, [%x[r], #32]\n\t"
        "ldr	q7, [%x[r], #64]\n\t"
        "ldr	q8, [%x[r], #96]\n\t"
        "ldr	q9, [%x[r], #128]\n\t"
        "ldr	q10, [%x[r], #160]\n\t"
        "ldr	q11, [%x[r], #192]\n\t"
        "ldr	q12, [%x[r], #224]\n\t"
        "ldr	q13, [x1]\n\t"
        "ldr	q14, [x1, #32]\n\t"
        "ldr	q15, [x1, #64]\n\t"
        "ldr	q16, [x1, #96]\n\t"
        "ldr	q17, [x1, #128]\n\t"
        "ldr	q18, [x1, #160]\n\t"
        "ldr	q19, [x1, #192]\n\t"
        "ldr	q20, [x1, #224]\n\t"
        "ldr	q0, [x2]\n\t"
        "ldr	q1, [x3]\n\t"
        "mul	v29.8h, v13.8h, v1.h[1]\n\t"
        "mul	v30.8h, v14.8h, v1.h[1]\n\t"
        "sqrdmulh	v21.8h, v13.8h, v0.h[1]\n\t"
        "sqrdmulh	v22.8h, v14.8h, v0.h[1]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v21.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v22.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v21.8h, v21.8h, v29.8h\n\t"
        "sub	v22.8h, v22.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v21.8h, v21.8h, #1\n\t"
        "sshr	v22.8h, v22.8h, #1\n\t"
        "mul	v29.8h, v15.8h, v1.h[1]\n\t"
        "mul	v30.8h, v16.8h, v1.h[1]\n\t"
        "sqrdmulh	v23.8h, v15.8h, v0.h[1]\n\t"
        "sqrdmulh	v24.8h, v16.8h, v0.h[1]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v23.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v24.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v23.8h, v23.8h, v29.8h\n\t"
        "sub	v24.8h, v24.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v23.8h, v23.8h, #1\n\t"
        "sshr	v24.8h, v24.8h, #1\n\t"
        "mul	v29.8h, v17.8h, v1.h[1]\n\t"
        "mul	v30.8h, v18.8h, v1.h[1]\n\t"
        "sqrdmulh	v25.8h, v17.8h, v0.h[1]\n\t"
        "sqrdmulh	v26.8h, v18.8h, v0.h[1]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v25.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v26.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v25.8h, v25.8h, v29.8h\n\t"
        "sub	v26.8h, v26.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v25.8h, v25.8h, #1\n\t"
        "sshr	v26.8h, v26.8h, #1\n\t"
        "mul	v29.8h, v19.8h, v1.h[1]\n\t"
        "mul	v30.8h, v20.8h, v1.h[1]\n\t"
        "sqrdmulh	v27.8h, v19.8h, v0.h[1]\n\t"
        "sqrdmulh	v28.8h, v20.8h, v0.h[1]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v27.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v28.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v27.8h, v27.8h, v29.8h\n\t"
        "sub	v28.8h, v28.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v27.8h, v27.8h, #1\n\t"
        "sshr	v28.8h, v28.8h, #1\n\t"
        "sub	v13.8h, v5.8h, v21.8h\n\t"
        "add	v5.8h, v5.8h, v21.8h\n\t"
        "sub	v14.8h, v6.8h, v22.8h\n\t"
        "add	v6.8h, v6.8h, v22.8h\n\t"
        "sub	v15.8h, v7.8h, v23.8h\n\t"
        "add	v7.8h, v7.8h, v23.8h\n\t"
        "sub	v16.8h, v8.8h, v24.8h\n\t"
        "add	v8.8h, v8.8h, v24.8h\n\t"
        "sub	v17.8h, v9.8h, v25.8h\n\t"
        "add	v9.8h, v9.8h, v25.8h\n\t"
        "sub	v18.8h, v10.8h, v26.8h\n\t"
        "add	v10.8h, v10.8h, v26.8h\n\t"
        "sub	v19.8h, v11.8h, v27.8h\n\t"
        "add	v11.8h, v11.8h, v27.8h\n\t"
        "sub	v20.8h, v12.8h, v28.8h\n\t"
        "add	v12.8h, v12.8h, v28.8h\n\t"
        "mul	v29.8h, v9.8h, v1.h[2]\n\t"
        "mul	v30.8h, v10.8h, v1.h[2]\n\t"
        "sqrdmulh	v21.8h, v9.8h, v0.h[2]\n\t"
        "sqrdmulh	v22.8h, v10.8h, v0.h[2]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v21.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v22.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v21.8h, v21.8h, v29.8h\n\t"
        "sub	v22.8h, v22.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v21.8h, v21.8h, #1\n\t"
        "sshr	v22.8h, v22.8h, #1\n\t"
        "mul	v29.8h, v11.8h, v1.h[2]\n\t"
        "mul	v30.8h, v12.8h, v1.h[2]\n\t"
        "sqrdmulh	v23.8h, v11.8h, v0.h[2]\n\t"
        "sqrdmulh	v24.8h, v12.8h, v0.h[2]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v23.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v24.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v23.8h, v23.8h, v29.8h\n\t"
        "sub	v24.8h, v24.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v23.8h, v23.8h, #1\n\t"
        "sshr	v24.8h, v24.8h, #1\n\t"
        "mul	v29.8h, v17.8h, v1.h[3]\n\t"
        "mul	v30.8h, v18.8h, v1.h[3]\n\t"
        "sqrdmulh	v25.8h, v17.8h, v0.h[3]\n\t"
        "sqrdmulh	v26.8h, v18.8h, v0.h[3]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v25.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v26.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v25.8h, v25.8h, v29.8h\n\t"
        "sub	v26.8h, v26.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v25.8h, v25.8h, #1\n\t"
        "sshr	v26.8h, v26.8h, #1\n\t"
        "mul	v29.8h, v19.8h, v1.h[3]\n\t"
        "mul	v30.8h, v20.8h, v1.h[3]\n\t"
        "sqrdmulh	v27.8h, v19.8h, v0.h[3]\n\t"
        "sqrdmulh	v28.8h, v20.8h, v0.h[3]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v27.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v28.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v27.8h, v27.8h, v29.8h\n\t"
        "sub	v28.8h, v28.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v27.8h, v27.8h, #1\n\t"
        "sshr	v28.8h, v28.8h, #1\n\t"
        "sub	v9.8h, v5.8h, v21.8h\n\t"
        "add	v5.8h, v5.8h, v21.8h\n\t"
        "sub	v10.8h, v6.8h, v22.8h\n\t"
        "add	v6.8h, v6.8h, v22.8h\n\t"
        "sub	v11.8h, v7.8h, v23.8h\n\t"
        "add	v7.8h, v7.8h, v23.8h\n\t"
        "sub	v12.8h, v8.8h, v24.8h\n\t"
        "add	v8.8h, v8.8h, v24.8h\n\t"
        "sub	v17.8h, v13.8h, v25.8h\n\t"
        "add	v13.8h, v13.8h, v25.8h\n\t"
        "sub	v18.8h, v14.8h, v26.8h\n\t"
        "add	v14.8h, v14.8h, v26.8h\n\t"
        "sub	v19.8h, v15.8h, v27.8h\n\t"
        "add	v15.8h, v15.8h, v27.8h\n\t"
        "sub	v20.8h, v16.8h, v28.8h\n\t"
        "add	v16.8h, v16.8h, v28.8h\n\t"
        "mul	v29.8h, v7.8h, v1.h[4]\n\t"
        "mul	v30.8h, v8.8h, v1.h[4]\n\t"
        "sqrdmulh	v21.8h, v7.8h, v0.h[4]\n\t"
        "sqrdmulh	v22.8h, v8.8h, v0.h[4]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v21.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v22.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v21.8h, v21.8h, v29.8h\n\t"
        "sub	v22.8h, v22.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v21.8h, v21.8h, #1\n\t"
        "sshr	v22.8h, v22.8h, #1\n\t"
        "mul	v29.8h, v11.8h, v1.h[5]\n\t"
        "mul	v30.8h, v12.8h, v1.h[5]\n\t"
        "sqrdmulh	v23.8h, v11.8h, v0.h[5]\n\t"
        "sqrdmulh	v24.8h, v12.8h, v0.h[5]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v23.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v24.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v23.8h, v23.8h, v29.8h\n\t"
        "sub	v24.8h, v24.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v23.8h, v23.8h, #1\n\t"
        "sshr	v24.8h, v24.8h, #1\n\t"
        "mul	v29.8h, v15.8h, v1.h[6]\n\t"
        "mul	v30.8h, v16.8h, v1.h[6]\n\t"
        "sqrdmulh	v25.8h, v15.8h, v0.h[6]\n\t"
        "sqrdmulh	v26.8h, v16.8h, v0.h[6]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v25.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v26.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v25.8h, v25.8h, v29.8h\n\t"
        "sub	v26.8h, v26.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v25.8h, v25.8h, #1\n\t"
        "sshr	v26.8h, v26.8h, #1\n\t"
        "mul	v29.8h, v19.8h, v1.h[7]\n\t"
        "mul	v30.8h, v20.8h, v1.h[7]\n\t"
        "sqrdmulh	v27.8h, v19.8h, v0.h[7]\n\t"
        "sqrdmulh	v28.8h, v20.8h, v0.h[7]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v27.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v28.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v27.8h, v27.8h, v29.8h\n\t"
        "sub	v28.8h, v28.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v27.8h, v27.8h, #1\n\t"
        "sshr	v28.8h, v28.8h, #1\n\t"
        "sub	v7.8h, v5.8h, v21.8h\n\t"
        "add	v5.8h, v5.8h, v21.8h\n\t"
        "sub	v8.8h, v6.8h, v22.8h\n\t"
        "add	v6.8h, v6.8h, v22.8h\n\t"
        "sub	v11.8h, v9.8h, v23.8h\n\t"
        "add	v9.8h, v9.8h, v23.8h\n\t"
        "sub	v12.8h, v10.8h, v24.8h\n\t"
        "add	v10.8h, v10.8h, v24.8h\n\t"
        "sub	v15.8h, v13.8h, v25.8h\n\t"
        "add	v13.8h, v13.8h, v25.8h\n\t"
        "sub	v16.8h, v14.8h, v26.8h\n\t"
        "add	v14.8h, v14.8h, v26.8h\n\t"
        "sub	v19.8h, v17.8h, v27.8h\n\t"
        "add	v17.8h, v17.8h, v27.8h\n\t"
        "sub	v20.8h, v18.8h, v28.8h\n\t"
        "add	v18.8h, v18.8h, v28.8h\n\t"
        "ldr	q0, [x2, #16]\n\t"
        "ldr	q1, [x3, #16]\n\t"
        "mul	v29.8h, v6.8h, v1.h[0]\n\t"
        "mul	v30.8h, v8.8h, v1.h[1]\n\t"
        "sqrdmulh	v21.8h, v6.8h, v0.h[0]\n\t"
        "sqrdmulh	v22.8h, v8.8h, v0.h[1]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v21.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v22.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v21.8h, v21.8h, v29.8h\n\t"
        "sub	v22.8h, v22.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v21.8h, v21.8h, #1\n\t"
        "sshr	v22.8h, v22.8h, #1\n\t"
        "mul	v29.8h, v10.8h, v1.h[2]\n\t"
        "mul	v30.8h, v12.8h, v1.h[3]\n\t"
        "sqrdmulh	v23.8h, v10.8h, v0.h[2]\n\t"
        "sqrdmulh	v24.8h, v12.8h, v0.h[3]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v23.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v24.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v23.8h, v23.8h, v29.8h\n\t"
        "sub	v24.8h, v24.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v23.8h, v23.8h, #1\n\t"
        "sshr	v24.8h, v24.8h, #1\n\t"
        "mul	v29.8h, v14.8h, v1.h[4]\n\t"
        "mul	v30.8h, v16.8h, v1.h[5]\n\t"
        "sqrdmulh	v25.8h, v14.8h, v0.h[4]\n\t"
        "sqrdmulh	v26.8h, v16.8h, v0.h[5]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v25.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v26.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v25.8h, v25.8h, v29.8h\n\t"
        "sub	v26.8h, v26.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v25.8h, v25.8h, #1\n\t"
        "sshr	v26.8h, v26.8h, #1\n\t"
        "mul	v29.8h, v18.8h, v1.h[6]\n\t"
        "mul	v30.8h, v20.8h, v1.h[7]\n\t"
        "sqrdmulh	v27.8h, v18.8h, v0.h[6]\n\t"
        "sqrdmulh	v28.8h, v20.8h, v0.h[7]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v27.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v28.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v27.8h, v27.8h, v29.8h\n\t"
        "sub	v28.8h, v28.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v27.8h, v27.8h, #1\n\t"
        "sshr	v28.8h, v28.8h, #1\n\t"
        "sub	v6.8h, v5.8h, v21.8h\n\t"
        "add	v5.8h, v5.8h, v21.8h\n\t"
        "sub	v8.8h, v7.8h, v22.8h\n\t"
        "add	v7.8h, v7.8h, v22.8h\n\t"
        "sub	v10.8h, v9.8h, v23.8h\n\t"
        "add	v9.8h, v9.8h, v23.8h\n\t"
        "sub	v12.8h, v11.8h, v24.8h\n\t"
        "add	v11.8h, v11.8h, v24.8h\n\t"
        "sub	v14.8h, v13.8h, v25.8h\n\t"
        "add	v13.8h, v13.8h, v25.8h\n\t"
        "sub	v16.8h, v15.8h, v26.8h\n\t"
        "add	v15.8h, v15.8h, v26.8h\n\t"
        "sub	v18.8h, v17.8h, v27.8h\n\t"
        "add	v17.8h, v17.8h, v27.8h\n\t"
        "sub	v20.8h, v19.8h, v28.8h\n\t"
        "add	v19.8h, v19.8h, v28.8h\n\t"
        "str	q5, [%x[r]]\n\t"
        "str	q6, [%x[r], #32]\n\t"
        "str	q7, [%x[r], #64]\n\t"
        "str	q8, [%x[r], #96]\n\t"
        "str	q9, [%x[r], #128]\n\t"
        "str	q10, [%x[r], #160]\n\t"
        "str	q11, [%x[r], #192]\n\t"
        "str	q12, [%x[r], #224]\n\t"
        "str	q13, [x1]\n\t"
        "str	q14, [x1, #32]\n\t"
        "str	q15, [x1, #64]\n\t"
        "str	q16, [x1, #96]\n\t"
        "str	q17, [x1, #128]\n\t"
        "str	q18, [x1, #160]\n\t"
        "str	q19, [x1, #192]\n\t"
        "str	q20, [x1, #224]\n\t"
        "ldr	q5, [%x[r], #16]\n\t"
        "ldr	q6, [%x[r], #48]\n\t"
        "ldr	q7, [%x[r], #80]\n\t"
        "ldr	q8, [%x[r], #112]\n\t"
        "ldr	q9, [%x[r], #144]\n\t"
        "ldr	q10, [%x[r], #176]\n\t"
        "ldr	q11, [%x[r], #208]\n\t"
        "ldr	q12, [%x[r], #240]\n\t"
        "ldr	q13, [x1, #16]\n\t"
        "ldr	q14, [x1, #48]\n\t"
        "ldr	q15, [x1, #80]\n\t"
        "ldr	q16, [x1, #112]\n\t"
        "ldr	q17, [x1, #144]\n\t"
        "ldr	q18, [x1, #176]\n\t"
        "ldr	q19, [x1, #208]\n\t"
        "ldr	q20, [x1, #240]\n\t"
        "ldr	q0, [x2]\n\t"
        "ldr	q1, [x3]\n\t"
        "mul	v29.8h, v13.8h, v1.h[1]\n\t"
        "mul	v30.8h, v14.8h, v1.h[1]\n\t"
        "sqrdmulh	v21.8h, v13.8h, v0.h[1]\n\t"
        "sqrdmulh	v22.8h, v14.8h, v0.h[1]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v21.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v22.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v21.8h, v21.8h, v29.8h\n\t"
        "sub	v22.8h, v22.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v21.8h, v21.8h, #1\n\t"
        "sshr	v22.8h, v22.8h, #1\n\t"
        "mul	v29.8h, v15.8h, v1.h[1]\n\t"
        "mul	v30.8h, v16.8h, v1.h[1]\n\t"
        "sqrdmulh	v23.8h, v15.8h, v0.h[1]\n\t"
        "sqrdmulh	v24.8h, v16.8h, v0.h[1]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v23.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v24.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v23.8h, v23.8h, v29.8h\n\t"
        "sub	v24.8h, v24.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v23.8h, v23.8h, #1\n\t"
        "sshr	v24.8h, v24.8h, #1\n\t"
        "mul	v29.8h, v17.8h, v1.h[1]\n\t"
        "mul	v30.8h, v18.8h, v1.h[1]\n\t"
        "sqrdmulh	v25.8h, v17.8h, v0.h[1]\n\t"
        "sqrdmulh	v26.8h, v18.8h, v0.h[1]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v25.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v26.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v25.8h, v25.8h, v29.8h\n\t"
        "sub	v26.8h, v26.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v25.8h, v25.8h, #1\n\t"
        "sshr	v26.8h, v26.8h, #1\n\t"
        "mul	v29.8h, v19.8h, v1.h[1]\n\t"
        "mul	v30.8h, v20.8h, v1.h[1]\n\t"
        "sqrdmulh	v27.8h, v19.8h, v0.h[1]\n\t"
        "sqrdmulh	v28.8h, v20.8h, v0.h[1]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v27.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v28.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v27.8h, v27.8h, v29.8h\n\t"
        "sub	v28.8h, v28.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v27.8h, v27.8h, #1\n\t"
        "sshr	v28.8h, v28.8h, #1\n\t"
        "sub	v13.8h, v5.8h, v21.8h\n\t"
        "add	v5.8h, v5.8h, v21.8h\n\t"
        "sub	v14.8h, v6.8h, v22.8h\n\t"
        "add	v6.8h, v6.8h, v22.8h\n\t"
        "sub	v15.8h, v7.8h, v23.8h\n\t"
        "add	v7.8h, v7.8h, v23.8h\n\t"
        "sub	v16.8h, v8.8h, v24.8h\n\t"
        "add	v8.8h, v8.8h, v24.8h\n\t"
        "sub	v17.8h, v9.8h, v25.8h\n\t"
        "add	v9.8h, v9.8h, v25.8h\n\t"
        "sub	v18.8h, v10.8h, v26.8h\n\t"
        "add	v10.8h, v10.8h, v26.8h\n\t"
        "sub	v19.8h, v11.8h, v27.8h\n\t"
        "add	v11.8h, v11.8h, v27.8h\n\t"
        "sub	v20.8h, v12.8h, v28.8h\n\t"
        "add	v12.8h, v12.8h, v28.8h\n\t"
        "mul	v29.8h, v9.8h, v1.h[2]\n\t"
        "mul	v30.8h, v10.8h, v1.h[2]\n\t"
        "sqrdmulh	v21.8h, v9.8h, v0.h[2]\n\t"
        "sqrdmulh	v22.8h, v10.8h, v0.h[2]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v21.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v22.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v21.8h, v21.8h, v29.8h\n\t"
        "sub	v22.8h, v22.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v21.8h, v21.8h, #1\n\t"
        "sshr	v22.8h, v22.8h, #1\n\t"
        "mul	v29.8h, v11.8h, v1.h[2]\n\t"
        "mul	v30.8h, v12.8h, v1.h[2]\n\t"
        "sqrdmulh	v23.8h, v11.8h, v0.h[2]\n\t"
        "sqrdmulh	v24.8h, v12.8h, v0.h[2]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v23.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v24.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v23.8h, v23.8h, v29.8h\n\t"
        "sub	v24.8h, v24.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v23.8h, v23.8h, #1\n\t"
        "sshr	v24.8h, v24.8h, #1\n\t"
        "mul	v29.8h, v17.8h, v1.h[3]\n\t"
        "mul	v30.8h, v18.8h, v1.h[3]\n\t"
        "sqrdmulh	v25.8h, v17.8h, v0.h[3]\n\t"
        "sqrdmulh	v26.8h, v18.8h, v0.h[3]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v25.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v26.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v25.8h, v25.8h, v29.8h\n\t"
        "sub	v26.8h, v26.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v25.8h, v25.8h, #1\n\t"
        "sshr	v26.8h, v26.8h, #1\n\t"
        "mul	v29.8h, v19.8h, v1.h[3]\n\t"
        "mul	v30.8h, v20.8h, v1.h[3]\n\t"
        "sqrdmulh	v27.8h, v19.8h, v0.h[3]\n\t"
        "sqrdmulh	v28.8h, v20.8h, v0.h[3]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v27.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v28.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v27.8h, v27.8h, v29.8h\n\t"
        "sub	v28.8h, v28.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v27.8h, v27.8h, #1\n\t"
        "sshr	v28.8h, v28.8h, #1\n\t"
        "sub	v9.8h, v5.8h, v21.8h\n\t"
        "add	v5.8h, v5.8h, v21.8h\n\t"
        "sub	v10.8h, v6.8h, v22.8h\n\t"
        "add	v6.8h, v6.8h, v22.8h\n\t"
        "sub	v11.8h, v7.8h, v23.8h\n\t"
        "add	v7.8h, v7.8h, v23.8h\n\t"
        "sub	v12.8h, v8.8h, v24.8h\n\t"
        "add	v8.8h, v8.8h, v24.8h\n\t"
        "sub	v17.8h, v13.8h, v25.8h\n\t"
        "add	v13.8h, v13.8h, v25.8h\n\t"
        "sub	v18.8h, v14.8h, v26.8h\n\t"
        "add	v14.8h, v14.8h, v26.8h\n\t"
        "sub	v19.8h, v15.8h, v27.8h\n\t"
        "add	v15.8h, v15.8h, v27.8h\n\t"
        "sub	v20.8h, v16.8h, v28.8h\n\t"
        "add	v16.8h, v16.8h, v28.8h\n\t"
        "mul	v29.8h, v7.8h, v1.h[4]\n\t"
        "mul	v30.8h, v8.8h, v1.h[4]\n\t"
        "sqrdmulh	v21.8h, v7.8h, v0.h[4]\n\t"
        "sqrdmulh	v22.8h, v8.8h, v0.h[4]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v21.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v22.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v21.8h, v21.8h, v29.8h\n\t"
        "sub	v22.8h, v22.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v21.8h, v21.8h, #1\n\t"
        "sshr	v22.8h, v22.8h, #1\n\t"
        "mul	v29.8h, v11.8h, v1.h[5]\n\t"
        "mul	v30.8h, v12.8h, v1.h[5]\n\t"
        "sqrdmulh	v23.8h, v11.8h, v0.h[5]\n\t"
        "sqrdmulh	v24.8h, v12.8h, v0.h[5]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v23.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v24.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v23.8h, v23.8h, v29.8h\n\t"
        "sub	v24.8h, v24.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v23.8h, v23.8h, #1\n\t"
        "sshr	v24.8h, v24.8h, #1\n\t"
        "mul	v29.8h, v15.8h, v1.h[6]\n\t"
        "mul	v30.8h, v16.8h, v1.h[6]\n\t"
        "sqrdmulh	v25.8h, v15.8h, v0.h[6]\n\t"
        "sqrdmulh	v26.8h, v16.8h, v0.h[6]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v25.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v26.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v25.8h, v25.8h, v29.8h\n\t"
        "sub	v26.8h, v26.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v25.8h, v25.8h, #1\n\t"
        "sshr	v26.8h, v26.8h, #1\n\t"
        "mul	v29.8h, v19.8h, v1.h[7]\n\t"
        "mul	v30.8h, v20.8h, v1.h[7]\n\t"
        "sqrdmulh	v27.8h, v19.8h, v0.h[7]\n\t"
        "sqrdmulh	v28.8h, v20.8h, v0.h[7]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v27.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v28.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v27.8h, v27.8h, v29.8h\n\t"
        "sub	v28.8h, v28.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v27.8h, v27.8h, #1\n\t"
        "sshr	v28.8h, v28.8h, #1\n\t"
        "sub	v7.8h, v5.8h, v21.8h\n\t"
        "add	v5.8h, v5.8h, v21.8h\n\t"
        "sub	v8.8h, v6.8h, v22.8h\n\t"
        "add	v6.8h, v6.8h, v22.8h\n\t"
        "sub	v11.8h, v9.8h, v23.8h\n\t"
        "add	v9.8h, v9.8h, v23.8h\n\t"
        "sub	v12.8h, v10.8h, v24.8h\n\t"
        "add	v10.8h, v10.8h, v24.8h\n\t"
        "sub	v15.8h, v13.8h, v25.8h\n\t"
        "add	v13.8h, v13.8h, v25.8h\n\t"
        "sub	v16.8h, v14.8h, v26.8h\n\t"
        "add	v14.8h, v14.8h, v26.8h\n\t"
        "sub	v19.8h, v17.8h, v27.8h\n\t"
        "add	v17.8h, v17.8h, v27.8h\n\t"
        "sub	v20.8h, v18.8h, v28.8h\n\t"
        "add	v18.8h, v18.8h, v28.8h\n\t"
        "ldr	q0, [x2, #16]\n\t"
        "ldr	q1, [x3, #16]\n\t"
        "mul	v29.8h, v6.8h, v1.h[0]\n\t"
        "mul	v30.8h, v8.8h, v1.h[1]\n\t"
        "sqrdmulh	v21.8h, v6.8h, v0.h[0]\n\t"
        "sqrdmulh	v22.8h, v8.8h, v0.h[1]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v21.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v22.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v21.8h, v21.8h, v29.8h\n\t"
        "sub	v22.8h, v22.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v21.8h, v21.8h, #1\n\t"
        "sshr	v22.8h, v22.8h, #1\n\t"
        "mul	v29.8h, v10.8h, v1.h[2]\n\t"
        "mul	v30.8h, v12.8h, v1.h[3]\n\t"
        "sqrdmulh	v23.8h, v10.8h, v0.h[2]\n\t"
        "sqrdmulh	v24.8h, v12.8h, v0.h[3]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v23.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v24.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v23.8h, v23.8h, v29.8h\n\t"
        "sub	v24.8h, v24.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v23.8h, v23.8h, #1\n\t"
        "sshr	v24.8h, v24.8h, #1\n\t"
        "mul	v29.8h, v14.8h, v1.h[4]\n\t"
        "mul	v30.8h, v16.8h, v1.h[5]\n\t"
        "sqrdmulh	v25.8h, v14.8h, v0.h[4]\n\t"
        "sqrdmulh	v26.8h, v16.8h, v0.h[5]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v25.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v26.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v25.8h, v25.8h, v29.8h\n\t"
        "sub	v26.8h, v26.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v25.8h, v25.8h, #1\n\t"
        "sshr	v26.8h, v26.8h, #1\n\t"
        "mul	v29.8h, v18.8h, v1.h[6]\n\t"
        "mul	v30.8h, v20.8h, v1.h[7]\n\t"
        "sqrdmulh	v27.8h, v18.8h, v0.h[6]\n\t"
        "sqrdmulh	v28.8h, v20.8h, v0.h[7]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v27.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v28.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v27.8h, v27.8h, v29.8h\n\t"
        "sub	v28.8h, v28.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v27.8h, v27.8h, #1\n\t"
        "sshr	v28.8h, v28.8h, #1\n\t"
        "sub	v6.8h, v5.8h, v21.8h\n\t"
        "add	v5.8h, v5.8h, v21.8h\n\t"
        "sub	v8.8h, v7.8h, v22.8h\n\t"
        "add	v7.8h, v7.8h, v22.8h\n\t"
        "sub	v10.8h, v9.8h, v23.8h\n\t"
        "add	v9.8h, v9.8h, v23.8h\n\t"
        "sub	v12.8h, v11.8h, v24.8h\n\t"
        "add	v11.8h, v11.8h, v24.8h\n\t"
        "sub	v14.8h, v13.8h, v25.8h\n\t"
        "add	v13.8h, v13.8h, v25.8h\n\t"
        "sub	v16.8h, v15.8h, v26.8h\n\t"
        "add	v15.8h, v15.8h, v26.8h\n\t"
        "sub	v18.8h, v17.8h, v27.8h\n\t"
        "add	v17.8h, v17.8h, v27.8h\n\t"
        "sub	v20.8h, v19.8h, v28.8h\n\t"
        "add	v19.8h, v19.8h, v28.8h\n\t"
        "str	q5, [%x[r], #16]\n\t"
        "str	q6, [%x[r], #48]\n\t"
        "str	q7, [%x[r], #80]\n\t"
        "str	q8, [%x[r], #112]\n\t"
        "str	q9, [%x[r], #144]\n\t"
        "str	q10, [%x[r], #176]\n\t"
        "str	q11, [%x[r], #208]\n\t"
        "str	q12, [%x[r], #240]\n\t"
        "str	q13, [x1, #16]\n\t"
        "str	q14, [x1, #48]\n\t"
        "str	q15, [x1, #80]\n\t"
        "str	q16, [x1, #112]\n\t"
        "str	q17, [x1, #144]\n\t"
        "str	q18, [x1, #176]\n\t"
        "str	q19, [x1, #208]\n\t"
        "str	q20, [x1, #240]\n\t"
        "ldp	q5, q6, [%x[r]]\n\t"
        "ldp	q7, q8, [%x[r], #32]\n\t"
        "ldp	q9, q10, [%x[r], #64]\n\t"
        "ldp	q11, q12, [%x[r], #96]\n\t"
        "ldp	q13, q14, [%x[r], #128]\n\t"
        "ldp	q15, q16, [%x[r], #160]\n\t"
        "ldp	q17, q18, [%x[r], #192]\n\t"
        "ldp	q19, q20, [%x[r], #224]\n\t"
        "ldr	q0, [x2, #32]\n\t"
        "ldr	q1, [x3, #32]\n\t"
        "mul	v29.8h, v6.8h, v1.h[0]\n\t"
        "mul	v30.8h, v8.8h, v1.h[1]\n\t"
        "sqrdmulh	v21.8h, v6.8h, v0.h[0]\n\t"
        "sqrdmulh	v22.8h, v8.8h, v0.h[1]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v21.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v22.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v21.8h, v21.8h, v29.8h\n\t"
        "sub	v22.8h, v22.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v21.8h, v21.8h, #1\n\t"
        "sshr	v22.8h, v22.8h, #1\n\t"
        "mul	v29.8h, v10.8h, v1.h[2]\n\t"
        "mul	v30.8h, v12.8h, v1.h[3]\n\t"
        "sqrdmulh	v23.8h, v10.8h, v0.h[2]\n\t"
        "sqrdmulh	v24.8h, v12.8h, v0.h[3]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v23.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v24.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v23.8h, v23.8h, v29.8h\n\t"
        "sub	v24.8h, v24.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v23.8h, v23.8h, #1\n\t"
        "sshr	v24.8h, v24.8h, #1\n\t"
        "mul	v29.8h, v14.8h, v1.h[4]\n\t"
        "mul	v30.8h, v16.8h, v1.h[5]\n\t"
        "sqrdmulh	v25.8h, v14.8h, v0.h[4]\n\t"
        "sqrdmulh	v26.8h, v16.8h, v0.h[5]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v25.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v26.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v25.8h, v25.8h, v29.8h\n\t"
        "sub	v26.8h, v26.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v25.8h, v25.8h, #1\n\t"
        "sshr	v26.8h, v26.8h, #1\n\t"
        "mul	v29.8h, v18.8h, v1.h[6]\n\t"
        "mul	v30.8h, v20.8h, v1.h[7]\n\t"
        "sqrdmulh	v27.8h, v18.8h, v0.h[6]\n\t"
        "sqrdmulh	v28.8h, v20.8h, v0.h[7]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v27.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v28.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v27.8h, v27.8h, v29.8h\n\t"
        "sub	v28.8h, v28.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v27.8h, v27.8h, #1\n\t"
        "sshr	v28.8h, v28.8h, #1\n\t"
        "sub	v6.8h, v5.8h, v21.8h\n\t"
        "add	v5.8h, v5.8h, v21.8h\n\t"
        "sub	v8.8h, v7.8h, v22.8h\n\t"
        "add	v7.8h, v7.8h, v22.8h\n\t"
        "sub	v10.8h, v9.8h, v23.8h\n\t"
        "add	v9.8h, v9.8h, v23.8h\n\t"
        "sub	v12.8h, v11.8h, v24.8h\n\t"
        "add	v11.8h, v11.8h, v24.8h\n\t"
        "sub	v14.8h, v13.8h, v25.8h\n\t"
        "add	v13.8h, v13.8h, v25.8h\n\t"
        "sub	v16.8h, v15.8h, v26.8h\n\t"
        "add	v15.8h, v15.8h, v26.8h\n\t"
        "sub	v18.8h, v17.8h, v27.8h\n\t"
        "add	v17.8h, v17.8h, v27.8h\n\t"
        "sub	v20.8h, v19.8h, v28.8h\n\t"
        "add	v19.8h, v19.8h, v28.8h\n\t"
        "ldr	q0, [x2, #64]\n\t"
        "ldr	q2, [x2, #80]\n\t"
        "ldr	q1, [x3, #64]\n\t"
        "ldr	q3, [x3, #80]\n\t"
        "mov	v29.16b, v5.16b\n\t"
        "mov	v30.16b, v7.16b\n\t"
        "trn1	v5.2d, v5.2d, v6.2d\n\t"
        "trn1	v7.2d, v7.2d, v8.2d\n\t"
        "trn2	v6.2d, v29.2d, v6.2d\n\t"
        "trn2	v8.2d, v30.2d, v8.2d\n\t"
        "mul	v29.8h, v6.8h, v1.8h\n\t"
        "mul	v30.8h, v8.8h, v3.8h\n\t"
        "sqrdmulh	v21.8h, v6.8h, v0.8h\n\t"
        "sqrdmulh	v22.8h, v8.8h, v2.8h\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v21.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v22.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v21.8h, v21.8h, v29.8h\n\t"
        "sub	v22.8h, v22.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v21.8h, v21.8h, #1\n\t"
        "sshr	v22.8h, v22.8h, #1\n\t"
        "ldr	q0, [x2, #96]\n\t"
        "ldr	q2, [x2, #112]\n\t"
        "ldr	q1, [x3, #96]\n\t"
        "ldr	q3, [x3, #112]\n\t"
        "mov	v29.16b, v9.16b\n\t"
        "mov	v30.16b, v11.16b\n\t"
        "trn1	v9.2d, v9.2d, v10.2d\n\t"
        "trn1	v11.2d, v11.2d, v12.2d\n\t"
        "trn2	v10.2d, v29.2d, v10.2d\n\t"
        "trn2	v12.2d, v30.2d, v12.2d\n\t"
        "mul	v29.8h, v10.8h, v1.8h\n\t"
        "mul	v30.8h, v12.8h, v3.8h\n\t"
        "sqrdmulh	v23.8h, v10.8h, v0.8h\n\t"
        "sqrdmulh	v24.8h, v12.8h, v2.8h\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v23.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v24.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v23.8h, v23.8h, v29.8h\n\t"
        "sub	v24.8h, v24.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v23.8h, v23.8h, #1\n\t"
        "sshr	v24.8h, v24.8h, #1\n\t"
        "ldr	q0, [x2, #128]\n\t"
        "ldr	q2, [x2, #144]\n\t"
        "ldr	q1, [x3, #128]\n\t"
        "ldr	q3, [x3, #144]\n\t"
        "mov	v29.16b, v13.16b\n\t"
        "mov	v30.16b, v15.16b\n\t"
        "trn1	v13.2d, v13.2d, v14.2d\n\t"
        "trn1	v15.2d, v15.2d, v16.2d\n\t"
        "trn2	v14.2d, v29.2d, v14.2d\n\t"
        "trn2	v16.2d, v30.2d, v16.2d\n\t"
        "mul	v29.8h, v14.8h, v1.8h\n\t"
        "mul	v30.8h, v16.8h, v3.8h\n\t"
        "sqrdmulh	v25.8h, v14.8h, v0.8h\n\t"
        "sqrdmulh	v26.8h, v16.8h, v2.8h\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v25.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v26.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v25.8h, v25.8h, v29.8h\n\t"
        "sub	v26.8h, v26.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v25.8h, v25.8h, #1\n\t"
        "sshr	v26.8h, v26.8h, #1\n\t"
        "ldr	q0, [x2, #160]\n\t"
        "ldr	q2, [x2, #176]\n\t"
        "ldr	q1, [x3, #160]\n\t"
        "ldr	q3, [x3, #176]\n\t"
        "mov	v29.16b, v17.16b\n\t"
        "mov	v30.16b, v19.16b\n\t"
        "trn1	v17.2d, v17.2d, v18.2d\n\t"
        "trn1	v19.2d, v19.2d, v20.2d\n\t"
        "trn2	v18.2d, v29.2d, v18.2d\n\t"
        "trn2	v20.2d, v30.2d, v20.2d\n\t"
        "mul	v29.8h, v18.8h, v1.8h\n\t"
        "mul	v30.8h, v20.8h, v3.8h\n\t"
        "sqrdmulh	v27.8h, v18.8h, v0.8h\n\t"
        "sqrdmulh	v28.8h, v20.8h, v2.8h\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v27.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v28.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v27.8h, v27.8h, v29.8h\n\t"
        "sub	v28.8h, v28.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v27.8h, v27.8h, #1\n\t"
        "sshr	v28.8h, v28.8h, #1\n\t"
        "sub	v6.8h, v5.8h, v21.8h\n\t"
        "add	v5.8h, v5.8h, v21.8h\n\t"
        "sub	v8.8h, v7.8h, v22.8h\n\t"
        "add	v7.8h, v7.8h, v22.8h\n\t"
        "sub	v10.8h, v9.8h, v23.8h\n\t"
        "add	v9.8h, v9.8h, v23.8h\n\t"
        "sub	v12.8h, v11.8h, v24.8h\n\t"
        "add	v11.8h, v11.8h, v24.8h\n\t"
        "sub	v14.8h, v13.8h, v25.8h\n\t"
        "add	v13.8h, v13.8h, v25.8h\n\t"
        "sub	v16.8h, v15.8h, v26.8h\n\t"
        "add	v15.8h, v15.8h, v26.8h\n\t"
        "sub	v18.8h, v17.8h, v27.8h\n\t"
        "add	v17.8h, v17.8h, v27.8h\n\t"
        "sub	v20.8h, v19.8h, v28.8h\n\t"
        "add	v19.8h, v19.8h, v28.8h\n\t"
        "ldr	q0, [x2, #320]\n\t"
        "ldr	q2, [x2, #336]\n\t"
        "ldr	q1, [x3, #320]\n\t"
        "ldr	q3, [x3, #336]\n\t"
        "mov	v29.16b, v5.16b\n\t"
        "mov	v30.16b, v7.16b\n\t"
        "trn1	v5.4s, v5.4s, v6.4s\n\t"
        "trn1	v7.4s, v7.4s, v8.4s\n\t"
        "trn2	v6.4s, v29.4s, v6.4s\n\t"
        "trn2	v8.4s, v30.4s, v8.4s\n\t"
        "mul	v29.8h, v6.8h, v1.8h\n\t"
        "mul	v30.8h, v8.8h, v3.8h\n\t"
        "sqrdmulh	v21.8h, v6.8h, v0.8h\n\t"
        "sqrdmulh	v22.8h, v8.8h, v2.8h\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v21.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v22.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v21.8h, v21.8h, v29.8h\n\t"
        "sub	v22.8h, v22.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v21.8h, v21.8h, #1\n\t"
        "sshr	v22.8h, v22.8h, #1\n\t"
        "ldr	q0, [x2, #352]\n\t"
        "ldr	q2, [x2, #368]\n\t"
        "ldr	q1, [x3, #352]\n\t"
        "ldr	q3, [x3, #368]\n\t"
        "mov	v29.16b, v9.16b\n\t"
        "mov	v30.16b, v11.16b\n\t"
        "trn1	v9.4s, v9.4s, v10.4s\n\t"
        "trn1	v11.4s, v11.4s, v12.4s\n\t"
        "trn2	v10.4s, v29.4s, v10.4s\n\t"
        "trn2	v12.4s, v30.4s, v12.4s\n\t"
        "mul	v29.8h, v10.8h, v1.8h\n\t"
        "mul	v30.8h, v12.8h, v3.8h\n\t"
        "sqrdmulh	v23.8h, v10.8h, v0.8h\n\t"
        "sqrdmulh	v24.8h, v12.8h, v2.8h\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v23.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v24.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v23.8h, v23.8h, v29.8h\n\t"
        "sub	v24.8h, v24.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v23.8h, v23.8h, #1\n\t"
        "sshr	v24.8h, v24.8h, #1\n\t"
        "ldr	q0, [x2, #384]\n\t"
        "ldr	q2, [x2, #400]\n\t"
        "ldr	q1, [x3, #384]\n\t"
        "ldr	q3, [x3, #400]\n\t"
        "mov	v29.16b, v13.16b\n\t"
        "mov	v30.16b, v15.16b\n\t"
        "trn1	v13.4s, v13.4s, v14.4s\n\t"
        "trn1	v15.4s, v15.4s, v16.4s\n\t"
        "trn2	v14.4s, v29.4s, v14.4s\n\t"
        "trn2	v16.4s, v30.4s, v16.4s\n\t"
        "mul	v29.8h, v14.8h, v1.8h\n\t"
        "mul	v30.8h, v16.8h, v3.8h\n\t"
        "sqrdmulh	v25.8h, v14.8h, v0.8h\n\t"
        "sqrdmulh	v26.8h, v16.8h, v2.8h\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v25.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v26.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v25.8h, v25.8h, v29.8h\n\t"
        "sub	v26.8h, v26.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v25.8h, v25.8h, #1\n\t"
        "sshr	v26.8h, v26.8h, #1\n\t"
        "ldr	q0, [x2, #416]\n\t"
        "ldr	q2, [x2, #432]\n\t"
        "ldr	q1, [x3, #416]\n\t"
        "ldr	q3, [x3, #432]\n\t"
        "mov	v29.16b, v17.16b\n\t"
        "mov	v30.16b, v19.16b\n\t"
        "trn1	v17.4s, v17.4s, v18.4s\n\t"
        "trn1	v19.4s, v19.4s, v20.4s\n\t"
        "trn2	v18.4s, v29.4s, v18.4s\n\t"
        "trn2	v20.4s, v30.4s, v20.4s\n\t"
        "mul	v29.8h, v18.8h, v1.8h\n\t"
        "mul	v30.8h, v20.8h, v3.8h\n\t"
        "sqrdmulh	v27.8h, v18.8h, v0.8h\n\t"
        "sqrdmulh	v28.8h, v20.8h, v2.8h\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v27.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v28.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v27.8h, v27.8h, v29.8h\n\t"
        "sub	v28.8h, v28.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v27.8h, v27.8h, #1\n\t"
        "sshr	v28.8h, v28.8h, #1\n\t"
        "sub	v6.8h, v5.8h, v21.8h\n\t"
        "add	v5.8h, v5.8h, v21.8h\n\t"
        "sub	v8.8h, v7.8h, v22.8h\n\t"
        "add	v7.8h, v7.8h, v22.8h\n\t"
        "sub	v10.8h, v9.8h, v23.8h\n\t"
        "add	v9.8h, v9.8h, v23.8h\n\t"
        "sub	v12.8h, v11.8h, v24.8h\n\t"
        "add	v11.8h, v11.8h, v24.8h\n\t"
        "sub	v14.8h, v13.8h, v25.8h\n\t"
        "add	v13.8h, v13.8h, v25.8h\n\t"
        "sub	v16.8h, v15.8h, v26.8h\n\t"
        "add	v15.8h, v15.8h, v26.8h\n\t"
        "sub	v18.8h, v17.8h, v27.8h\n\t"
        "add	v17.8h, v17.8h, v27.8h\n\t"
        "sub	v20.8h, v19.8h, v28.8h\n\t"
        "add	v19.8h, v19.8h, v28.8h\n\t"
        "sqdmulh	v21.8h, v5.8h, v4.h[2]\n\t"
        "sqdmulh	v22.8h, v6.8h, v4.h[2]\n\t"
        "sshr	v21.8h, v21.8h, #11\n\t"
        "sshr	v22.8h, v22.8h, #11\n\t"
        "mls	v5.8h, v21.8h, v4.h[0]\n\t"
        "mls	v6.8h, v22.8h, v4.h[0]\n\t"
        "sqdmulh	v21.8h, v7.8h, v4.h[2]\n\t"
        "sqdmulh	v22.8h, v8.8h, v4.h[2]\n\t"
        "sshr	v21.8h, v21.8h, #11\n\t"
        "sshr	v22.8h, v22.8h, #11\n\t"
        "mls	v7.8h, v21.8h, v4.h[0]\n\t"
        "mls	v8.8h, v22.8h, v4.h[0]\n\t"
        "sqdmulh	v21.8h, v9.8h, v4.h[2]\n\t"
        "sqdmulh	v22.8h, v10.8h, v4.h[2]\n\t"
        "sshr	v21.8h, v21.8h, #11\n\t"
        "sshr	v22.8h, v22.8h, #11\n\t"
        "mls	v9.8h, v21.8h, v4.h[0]\n\t"
        "mls	v10.8h, v22.8h, v4.h[0]\n\t"
        "sqdmulh	v21.8h, v11.8h, v4.h[2]\n\t"
        "sqdmulh	v22.8h, v12.8h, v4.h[2]\n\t"
        "sshr	v21.8h, v21.8h, #11\n\t"
        "sshr	v22.8h, v22.8h, #11\n\t"
        "mls	v11.8h, v21.8h, v4.h[0]\n\t"
        "mls	v12.8h, v22.8h, v4.h[0]\n\t"
        "sqdmulh	v21.8h, v13.8h, v4.h[2]\n\t"
        "sqdmulh	v22.8h, v14.8h, v4.h[2]\n\t"
        "sshr	v21.8h, v21.8h, #11\n\t"
        "sshr	v22.8h, v22.8h, #11\n\t"
        "mls	v13.8h, v21.8h, v4.h[0]\n\t"
        "mls	v14.8h, v22.8h, v4.h[0]\n\t"
        "sqdmulh	v21.8h, v15.8h, v4.h[2]\n\t"
        "sqdmulh	v22.8h, v16.8h, v4.h[2]\n\t"
        "sshr	v21.8h, v21.8h, #11\n\t"
        "sshr	v22.8h, v22.8h, #11\n\t"
        "mls	v15.8h, v21.8h, v4.h[0]\n\t"
        "mls	v16.8h, v22.8h, v4.h[0]\n\t"
        "sqdmulh	v21.8h, v17.8h, v4.h[2]\n\t"
        "sqdmulh	v22.8h, v18.8h, v4.h[2]\n\t"
        "sshr	v21.8h, v21.8h, #11\n\t"
        "sshr	v22.8h, v22.8h, #11\n\t"
        "mls	v17.8h, v21.8h, v4.h[0]\n\t"
        "mls	v18.8h, v22.8h, v4.h[0]\n\t"
        "sqdmulh	v21.8h, v19.8h, v4.h[2]\n\t"
        "sqdmulh	v22.8h, v20.8h, v4.h[2]\n\t"
        "sshr	v21.8h, v21.8h, #11\n\t"
        "sshr	v22.8h, v22.8h, #11\n\t"
        "mls	v19.8h, v21.8h, v4.h[0]\n\t"
        "mls	v20.8h, v22.8h, v4.h[0]\n\t"
        "mov	v29.16b, v5.16b\n\t"
        "trn1	v5.4s, v5.4s, v6.4s\n\t"
        "trn2	v6.4s, v29.4s, v6.4s\n\t"
        "mov	v29.16b, v5.16b\n\t"
        "trn1	v5.2d, v5.2d, v6.2d\n\t"
        "trn2	v6.2d, v29.2d, v6.2d\n\t"
        "mov	v29.16b, v7.16b\n\t"
        "trn1	v7.4s, v7.4s, v8.4s\n\t"
        "trn2	v8.4s, v29.4s, v8.4s\n\t"
        "mov	v29.16b, v7.16b\n\t"
        "trn1	v7.2d, v7.2d, v8.2d\n\t"
        "trn2	v8.2d, v29.2d, v8.2d\n\t"
        "mov	v29.16b, v9.16b\n\t"
        "trn1	v9.4s, v9.4s, v10.4s\n\t"
        "trn2	v10.4s, v29.4s, v10.4s\n\t"
        "mov	v29.16b, v9.16b\n\t"
        "trn1	v9.2d, v9.2d, v10.2d\n\t"
        "trn2	v10.2d, v29.2d, v10.2d\n\t"
        "mov	v29.16b, v11.16b\n\t"
        "trn1	v11.4s, v11.4s, v12.4s\n\t"
        "trn2	v12.4s, v29.4s, v12.4s\n\t"
        "mov	v29.16b, v11.16b\n\t"
        "trn1	v11.2d, v11.2d, v12.2d\n\t"
        "trn2	v12.2d, v29.2d, v12.2d\n\t"
        "mov	v29.16b, v13.16b\n\t"
        "trn1	v13.4s, v13.4s, v14.4s\n\t"
        "trn2	v14.4s, v29.4s, v14.4s\n\t"
        "mov	v29.16b, v13.16b\n\t"
        "trn1	v13.2d, v13.2d, v14.2d\n\t"
        "trn2	v14.2d, v29.2d, v14.2d\n\t"
        "mov	v29.16b, v15.16b\n\t"
        "trn1	v15.4s, v15.4s, v16.4s\n\t"
        "trn2	v16.4s, v29.4s, v16.4s\n\t"
        "mov	v29.16b, v15.16b\n\t"
        "trn1	v15.2d, v15.2d, v16.2d\n\t"
        "trn2	v16.2d, v29.2d, v16.2d\n\t"
        "mov	v29.16b, v17.16b\n\t"
        "trn1	v17.4s, v17.4s, v18.4s\n\t"
        "trn2	v18.4s, v29.4s, v18.4s\n\t"
        "mov	v29.16b, v17.16b\n\t"
        "trn1	v17.2d, v17.2d, v18.2d\n\t"
        "trn2	v18.2d, v29.2d, v18.2d\n\t"
        "mov	v29.16b, v19.16b\n\t"
        "trn1	v19.4s, v19.4s, v20.4s\n\t"
        "trn2	v20.4s, v29.4s, v20.4s\n\t"
        "mov	v29.16b, v19.16b\n\t"
        "trn1	v19.2d, v19.2d, v20.2d\n\t"
        "trn2	v20.2d, v29.2d, v20.2d\n\t"
        "stp	q5, q6, [%x[r]]\n\t"
        "stp	q7, q8, [%x[r], #32]\n\t"
        "stp	q9, q10, [%x[r], #64]\n\t"
        "stp	q11, q12, [%x[r], #96]\n\t"
        "stp	q13, q14, [%x[r], #128]\n\t"
        "stp	q15, q16, [%x[r], #160]\n\t"
        "stp	q17, q18, [%x[r], #192]\n\t"
        "stp	q19, q20, [%x[r], #224]\n\t"
        "ldp	q5, q6, [x1]\n\t"
        "ldp	q7, q8, [x1, #32]\n\t"
        "ldp	q9, q10, [x1, #64]\n\t"
        "ldp	q11, q12, [x1, #96]\n\t"
        "ldp	q13, q14, [x1, #128]\n\t"
        "ldp	q15, q16, [x1, #160]\n\t"
        "ldp	q17, q18, [x1, #192]\n\t"
        "ldp	q19, q20, [x1, #224]\n\t"
        "ldr	q0, [x2, #48]\n\t"
        "ldr	q1, [x3, #48]\n\t"
        "mul	v29.8h, v6.8h, v1.h[0]\n\t"
        "mul	v30.8h, v8.8h, v1.h[1]\n\t"
        "sqrdmulh	v21.8h, v6.8h, v0.h[0]\n\t"
        "sqrdmulh	v22.8h, v8.8h, v0.h[1]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v21.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v22.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v21.8h, v21.8h, v29.8h\n\t"
        "sub	v22.8h, v22.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v21.8h, v21.8h, #1\n\t"
        "sshr	v22.8h, v22.8h, #1\n\t"
        "mul	v29.8h, v10.8h, v1.h[2]\n\t"
        "mul	v30.8h, v12.8h, v1.h[3]\n\t"
        "sqrdmulh	v23.8h, v10.8h, v0.h[2]\n\t"
        "sqrdmulh	v24.8h, v12.8h, v0.h[3]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v23.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v24.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v23.8h, v23.8h, v29.8h\n\t"
        "sub	v24.8h, v24.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v23.8h, v23.8h, #1\n\t"
        "sshr	v24.8h, v24.8h, #1\n\t"
        "mul	v29.8h, v14.8h, v1.h[4]\n\t"
        "mul	v30.8h, v16.8h, v1.h[5]\n\t"
        "sqrdmulh	v25.8h, v14.8h, v0.h[4]\n\t"
        "sqrdmulh	v26.8h, v16.8h, v0.h[5]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v25.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v26.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v25.8h, v25.8h, v29.8h\n\t"
        "sub	v26.8h, v26.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v25.8h, v25.8h, #1\n\t"
        "sshr	v26.8h, v26.8h, #1\n\t"
        "mul	v29.8h, v18.8h, v1.h[6]\n\t"
        "mul	v30.8h, v20.8h, v1.h[7]\n\t"
        "sqrdmulh	v27.8h, v18.8h, v0.h[6]\n\t"
        "sqrdmulh	v28.8h, v20.8h, v0.h[7]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v27.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v28.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v27.8h, v27.8h, v29.8h\n\t"
        "sub	v28.8h, v28.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v27.8h, v27.8h, #1\n\t"
        "sshr	v28.8h, v28.8h, #1\n\t"
        "sub	v6.8h, v5.8h, v21.8h\n\t"
        "add	v5.8h, v5.8h, v21.8h\n\t"
        "sub	v8.8h, v7.8h, v22.8h\n\t"
        "add	v7.8h, v7.8h, v22.8h\n\t"
        "sub	v10.8h, v9.8h, v23.8h\n\t"
        "add	v9.8h, v9.8h, v23.8h\n\t"
        "sub	v12.8h, v11.8h, v24.8h\n\t"
        "add	v11.8h, v11.8h, v24.8h\n\t"
        "sub	v14.8h, v13.8h, v25.8h\n\t"
        "add	v13.8h, v13.8h, v25.8h\n\t"
        "sub	v16.8h, v15.8h, v26.8h\n\t"
        "add	v15.8h, v15.8h, v26.8h\n\t"
        "sub	v18.8h, v17.8h, v27.8h\n\t"
        "add	v17.8h, v17.8h, v27.8h\n\t"
        "sub	v20.8h, v19.8h, v28.8h\n\t"
        "add	v19.8h, v19.8h, v28.8h\n\t"
        "ldr	q0, [x2, #192]\n\t"
        "ldr	q2, [x2, #208]\n\t"
        "ldr	q1, [x3, #192]\n\t"
        "ldr	q3, [x3, #208]\n\t"
        "mov	v29.16b, v5.16b\n\t"
        "mov	v30.16b, v7.16b\n\t"
        "trn1	v5.2d, v5.2d, v6.2d\n\t"
        "trn1	v7.2d, v7.2d, v8.2d\n\t"
        "trn2	v6.2d, v29.2d, v6.2d\n\t"
        "trn2	v8.2d, v30.2d, v8.2d\n\t"
        "mul	v29.8h, v6.8h, v1.8h\n\t"
        "mul	v30.8h, v8.8h, v3.8h\n\t"
        "sqrdmulh	v21.8h, v6.8h, v0.8h\n\t"
        "sqrdmulh	v22.8h, v8.8h, v2.8h\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v21.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v22.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v21.8h, v21.8h, v29.8h\n\t"
        "sub	v22.8h, v22.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v21.8h, v21.8h, #1\n\t"
        "sshr	v22.8h, v22.8h, #1\n\t"
        "ldr	q0, [x2, #224]\n\t"
        "ldr	q2, [x2, #240]\n\t"
        "ldr	q1, [x3, #224]\n\t"
        "ldr	q3, [x3, #240]\n\t"
        "mov	v29.16b, v9.16b\n\t"
        "mov	v30.16b, v11.16b\n\t"
        "trn1	v9.2d, v9.2d, v10.2d\n\t"
        "trn1	v11.2d, v11.2d, v12.2d\n\t"
        "trn2	v10.2d, v29.2d, v10.2d\n\t"
        "trn2	v12.2d, v30.2d, v12.2d\n\t"
        "mul	v29.8h, v10.8h, v1.8h\n\t"
        "mul	v30.8h, v12.8h, v3.8h\n\t"
        "sqrdmulh	v23.8h, v10.8h, v0.8h\n\t"
        "sqrdmulh	v24.8h, v12.8h, v2.8h\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v23.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v24.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v23.8h, v23.8h, v29.8h\n\t"
        "sub	v24.8h, v24.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v23.8h, v23.8h, #1\n\t"
        "sshr	v24.8h, v24.8h, #1\n\t"
        "ldr	q0, [x2, #256]\n\t"
        "ldr	q2, [x2, #272]\n\t"
        "ldr	q1, [x3, #256]\n\t"
        "ldr	q3, [x3, #272]\n\t"
        "mov	v29.16b, v13.16b\n\t"
        "mov	v30.16b, v15.16b\n\t"
        "trn1	v13.2d, v13.2d, v14.2d\n\t"
        "trn1	v15.2d, v15.2d, v16.2d\n\t"
        "trn2	v14.2d, v29.2d, v14.2d\n\t"
        "trn2	v16.2d, v30.2d, v16.2d\n\t"
        "mul	v29.8h, v14.8h, v1.8h\n\t"
        "mul	v30.8h, v16.8h, v3.8h\n\t"
        "sqrdmulh	v25.8h, v14.8h, v0.8h\n\t"
        "sqrdmulh	v26.8h, v16.8h, v2.8h\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v25.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v26.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v25.8h, v25.8h, v29.8h\n\t"
        "sub	v26.8h, v26.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v25.8h, v25.8h, #1\n\t"
        "sshr	v26.8h, v26.8h, #1\n\t"
        "ldr	q0, [x2, #288]\n\t"
        "ldr	q2, [x2, #304]\n\t"
        "ldr	q1, [x3, #288]\n\t"
        "ldr	q3, [x3, #304]\n\t"
        "mov	v29.16b, v17.16b\n\t"
        "mov	v30.16b, v19.16b\n\t"
        "trn1	v17.2d, v17.2d, v18.2d\n\t"
        "trn1	v19.2d, v19.2d, v20.2d\n\t"
        "trn2	v18.2d, v29.2d, v18.2d\n\t"
        "trn2	v20.2d, v30.2d, v20.2d\n\t"
        "mul	v29.8h, v18.8h, v1.8h\n\t"
        "mul	v30.8h, v20.8h, v3.8h\n\t"
        "sqrdmulh	v27.8h, v18.8h, v0.8h\n\t"
        "sqrdmulh	v28.8h, v20.8h, v2.8h\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v27.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v28.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v27.8h, v27.8h, v29.8h\n\t"
        "sub	v28.8h, v28.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v27.8h, v27.8h, #1\n\t"
        "sshr	v28.8h, v28.8h, #1\n\t"
        "sub	v6.8h, v5.8h, v21.8h\n\t"
        "add	v5.8h, v5.8h, v21.8h\n\t"
        "sub	v8.8h, v7.8h, v22.8h\n\t"
        "add	v7.8h, v7.8h, v22.8h\n\t"
        "sub	v10.8h, v9.8h, v23.8h\n\t"
        "add	v9.8h, v9.8h, v23.8h\n\t"
        "sub	v12.8h, v11.8h, v24.8h\n\t"
        "add	v11.8h, v11.8h, v24.8h\n\t"
        "sub	v14.8h, v13.8h, v25.8h\n\t"
        "add	v13.8h, v13.8h, v25.8h\n\t"
        "sub	v16.8h, v15.8h, v26.8h\n\t"
        "add	v15.8h, v15.8h, v26.8h\n\t"
        "sub	v18.8h, v17.8h, v27.8h\n\t"
        "add	v17.8h, v17.8h, v27.8h\n\t"
        "sub	v20.8h, v19.8h, v28.8h\n\t"
        "add	v19.8h, v19.8h, v28.8h\n\t"
        "ldr	q0, [x2, #448]\n\t"
        "ldr	q2, [x2, #464]\n\t"
        "ldr	q1, [x3, #448]\n\t"
        "ldr	q3, [x3, #464]\n\t"
        "mov	v29.16b, v5.16b\n\t"
        "mov	v30.16b, v7.16b\n\t"
        "trn1	v5.4s, v5.4s, v6.4s\n\t"
        "trn1	v7.4s, v7.4s, v8.4s\n\t"
        "trn2	v6.4s, v29.4s, v6.4s\n\t"
        "trn2	v8.4s, v30.4s, v8.4s\n\t"
        "mul	v29.8h, v6.8h, v1.8h\n\t"
        "mul	v30.8h, v8.8h, v3.8h\n\t"
        "sqrdmulh	v21.8h, v6.8h, v0.8h\n\t"
        "sqrdmulh	v22.8h, v8.8h, v2.8h\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v21.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v22.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v21.8h, v21.8h, v29.8h\n\t"
        "sub	v22.8h, v22.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v21.8h, v21.8h, #1\n\t"
        "sshr	v22.8h, v22.8h, #1\n\t"
        "ldr	q0, [x2, #480]\n\t"
        "ldr	q2, [x2, #496]\n\t"
        "ldr	q1, [x3, #480]\n\t"
        "ldr	q3, [x3, #496]\n\t"
        "mov	v29.16b, v9.16b\n\t"
        "mov	v30.16b, v11.16b\n\t"
        "trn1	v9.4s, v9.4s, v10.4s\n\t"
        "trn1	v11.4s, v11.4s, v12.4s\n\t"
        "trn2	v10.4s, v29.4s, v10.4s\n\t"
        "trn2	v12.4s, v30.4s, v12.4s\n\t"
        "mul	v29.8h, v10.8h, v1.8h\n\t"
        "mul	v30.8h, v12.8h, v3.8h\n\t"
        "sqrdmulh	v23.8h, v10.8h, v0.8h\n\t"
        "sqrdmulh	v24.8h, v12.8h, v2.8h\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v23.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v24.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v23.8h, v23.8h, v29.8h\n\t"
        "sub	v24.8h, v24.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v23.8h, v23.8h, #1\n\t"
        "sshr	v24.8h, v24.8h, #1\n\t"
        "ldr	q0, [x2, #512]\n\t"
        "ldr	q2, [x2, #528]\n\t"
        "ldr	q1, [x3, #512]\n\t"
        "ldr	q3, [x3, #528]\n\t"
        "mov	v29.16b, v13.16b\n\t"
        "mov	v30.16b, v15.16b\n\t"
        "trn1	v13.4s, v13.4s, v14.4s\n\t"
        "trn1	v15.4s, v15.4s, v16.4s\n\t"
        "trn2	v14.4s, v29.4s, v14.4s\n\t"
        "trn2	v16.4s, v30.4s, v16.4s\n\t"
        "mul	v29.8h, v14.8h, v1.8h\n\t"
        "mul	v30.8h, v16.8h, v3.8h\n\t"
        "sqrdmulh	v25.8h, v14.8h, v0.8h\n\t"
        "sqrdmulh	v26.8h, v16.8h, v2.8h\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v25.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v26.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v25.8h, v25.8h, v29.8h\n\t"
        "sub	v26.8h, v26.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v25.8h, v25.8h, #1\n\t"
        "sshr	v26.8h, v26.8h, #1\n\t"
        "ldr	q0, [x2, #544]\n\t"
        "ldr	q2, [x2, #560]\n\t"
        "ldr	q1, [x3, #544]\n\t"
        "ldr	q3, [x3, #560]\n\t"
        "mov	v29.16b, v17.16b\n\t"
        "mov	v30.16b, v19.16b\n\t"
        "trn1	v17.4s, v17.4s, v18.4s\n\t"
        "trn1	v19.4s, v19.4s, v20.4s\n\t"
        "trn2	v18.4s, v29.4s, v18.4s\n\t"
        "trn2	v20.4s, v30.4s, v20.4s\n\t"
        "mul	v29.8h, v18.8h, v1.8h\n\t"
        "mul	v30.8h, v20.8h, v3.8h\n\t"
        "sqrdmulh	v27.8h, v18.8h, v0.8h\n\t"
        "sqrdmulh	v28.8h, v20.8h, v2.8h\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v27.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmlsh	v28.8h, v30.8h, v4.h[0]\n\t"
#else
        "sqrdmulh	v29.8h, v29.8h, v4.h[0]\n\t"
        "sqrdmulh	v30.8h, v30.8h, v4.h[0]\n\t"
        "sub	v27.8h, v27.8h, v29.8h\n\t"
        "sub	v28.8h, v28.8h, v30.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v27.8h, v27.8h, #1\n\t"
        "sshr	v28.8h, v28.8h, #1\n\t"
        "sub	v6.8h, v5.8h, v21.8h\n\t"
        "add	v5.8h, v5.8h, v21.8h\n\t"
        "sub	v8.8h, v7.8h, v22.8h\n\t"
        "add	v7.8h, v7.8h, v22.8h\n\t"
        "sub	v10.8h, v9.8h, v23.8h\n\t"
        "add	v9.8h, v9.8h, v23.8h\n\t"
        "sub	v12.8h, v11.8h, v24.8h\n\t"
        "add	v11.8h, v11.8h, v24.8h\n\t"
        "sub	v14.8h, v13.8h, v25.8h\n\t"
        "add	v13.8h, v13.8h, v25.8h\n\t"
        "sub	v16.8h, v15.8h, v26.8h\n\t"
        "add	v15.8h, v15.8h, v26.8h\n\t"
        "sub	v18.8h, v17.8h, v27.8h\n\t"
        "add	v17.8h, v17.8h, v27.8h\n\t"
        "sub	v20.8h, v19.8h, v28.8h\n\t"
        "add	v19.8h, v19.8h, v28.8h\n\t"
        "sqdmulh	v21.8h, v5.8h, v4.h[2]\n\t"
        "sqdmulh	v22.8h, v6.8h, v4.h[2]\n\t"
        "sshr	v21.8h, v21.8h, #11\n\t"
        "sshr	v22.8h, v22.8h, #11\n\t"
        "mls	v5.8h, v21.8h, v4.h[0]\n\t"
        "mls	v6.8h, v22.8h, v4.h[0]\n\t"
        "sqdmulh	v21.8h, v7.8h, v4.h[2]\n\t"
        "sqdmulh	v22.8h, v8.8h, v4.h[2]\n\t"
        "sshr	v21.8h, v21.8h, #11\n\t"
        "sshr	v22.8h, v22.8h, #11\n\t"
        "mls	v7.8h, v21.8h, v4.h[0]\n\t"
        "mls	v8.8h, v22.8h, v4.h[0]\n\t"
        "sqdmulh	v21.8h, v9.8h, v4.h[2]\n\t"
        "sqdmulh	v22.8h, v10.8h, v4.h[2]\n\t"
        "sshr	v21.8h, v21.8h, #11\n\t"
        "sshr	v22.8h, v22.8h, #11\n\t"
        "mls	v9.8h, v21.8h, v4.h[0]\n\t"
        "mls	v10.8h, v22.8h, v4.h[0]\n\t"
        "sqdmulh	v21.8h, v11.8h, v4.h[2]\n\t"
        "sqdmulh	v22.8h, v12.8h, v4.h[2]\n\t"
        "sshr	v21.8h, v21.8h, #11\n\t"
        "sshr	v22.8h, v22.8h, #11\n\t"
        "mls	v11.8h, v21.8h, v4.h[0]\n\t"
        "mls	v12.8h, v22.8h, v4.h[0]\n\t"
        "sqdmulh	v21.8h, v13.8h, v4.h[2]\n\t"
        "sqdmulh	v22.8h, v14.8h, v4.h[2]\n\t"
        "sshr	v21.8h, v21.8h, #11\n\t"
        "sshr	v22.8h, v22.8h, #11\n\t"
        "mls	v13.8h, v21.8h, v4.h[0]\n\t"
        "mls	v14.8h, v22.8h, v4.h[0]\n\t"
        "sqdmulh	v21.8h, v15.8h, v4.h[2]\n\t"
        "sqdmulh	v22.8h, v16.8h, v4.h[2]\n\t"
        "sshr	v21.8h, v21.8h, #11\n\t"
        "sshr	v22.8h, v22.8h, #11\n\t"
        "mls	v15.8h, v21.8h, v4.h[0]\n\t"
        "mls	v16.8h, v22.8h, v4.h[0]\n\t"
        "sqdmulh	v21.8h, v17.8h, v4.h[2]\n\t"
        "sqdmulh	v22.8h, v18.8h, v4.h[2]\n\t"
        "sshr	v21.8h, v21.8h, #11\n\t"
        "sshr	v22.8h, v22.8h, #11\n\t"
        "mls	v17.8h, v21.8h, v4.h[0]\n\t"
        "mls	v18.8h, v22.8h, v4.h[0]\n\t"
        "sqdmulh	v21.8h, v19.8h, v4.h[2]\n\t"
        "sqdmulh	v22.8h, v20.8h, v4.h[2]\n\t"
        "sshr	v21.8h, v21.8h, #11\n\t"
        "sshr	v22.8h, v22.8h, #11\n\t"
        "mls	v19.8h, v21.8h, v4.h[0]\n\t"
        "mls	v20.8h, v22.8h, v4.h[0]\n\t"
        "mov	v29.16b, v5.16b\n\t"
        "trn1	v5.4s, v5.4s, v6.4s\n\t"
        "trn2	v6.4s, v29.4s, v6.4s\n\t"
        "mov	v29.16b, v5.16b\n\t"
        "trn1	v5.2d, v5.2d, v6.2d\n\t"
        "trn2	v6.2d, v29.2d, v6.2d\n\t"
        "mov	v29.16b, v7.16b\n\t"
        "trn1	v7.4s, v7.4s, v8.4s\n\t"
        "trn2	v8.4s, v29.4s, v8.4s\n\t"
        "mov	v29.16b, v7.16b\n\t"
        "trn1	v7.2d, v7.2d, v8.2d\n\t"
        "trn2	v8.2d, v29.2d, v8.2d\n\t"
        "mov	v29.16b, v9.16b\n\t"
        "trn1	v9.4s, v9.4s, v10.4s\n\t"
        "trn2	v10.4s, v29.4s, v10.4s\n\t"
        "mov	v29.16b, v9.16b\n\t"
        "trn1	v9.2d, v9.2d, v10.2d\n\t"
        "trn2	v10.2d, v29.2d, v10.2d\n\t"
        "mov	v29.16b, v11.16b\n\t"
        "trn1	v11.4s, v11.4s, v12.4s\n\t"
        "trn2	v12.4s, v29.4s, v12.4s\n\t"
        "mov	v29.16b, v11.16b\n\t"
        "trn1	v11.2d, v11.2d, v12.2d\n\t"
        "trn2	v12.2d, v29.2d, v12.2d\n\t"
        "mov	v29.16b, v13.16b\n\t"
        "trn1	v13.4s, v13.4s, v14.4s\n\t"
        "trn2	v14.4s, v29.4s, v14.4s\n\t"
        "mov	v29.16b, v13.16b\n\t"
        "trn1	v13.2d, v13.2d, v14.2d\n\t"
        "trn2	v14.2d, v29.2d, v14.2d\n\t"
        "mov	v29.16b, v15.16b\n\t"
        "trn1	v15.4s, v15.4s, v16.4s\n\t"
        "trn2	v16.4s, v29.4s, v16.4s\n\t"
        "mov	v29.16b, v15.16b\n\t"
        "trn1	v15.2d, v15.2d, v16.2d\n\t"
        "trn2	v16.2d, v29.2d, v16.2d\n\t"
        "mov	v29.16b, v17.16b\n\t"
        "trn1	v17.4s, v17.4s, v18.4s\n\t"
        "trn2	v18.4s, v29.4s, v18.4s\n\t"
        "mov	v29.16b, v17.16b\n\t"
        "trn1	v17.2d, v17.2d, v18.2d\n\t"
        "trn2	v18.2d, v29.2d, v18.2d\n\t"
        "mov	v29.16b, v19.16b\n\t"
        "trn1	v19.4s, v19.4s, v20.4s\n\t"
        "trn2	v20.4s, v29.4s, v20.4s\n\t"
        "mov	v29.16b, v19.16b\n\t"
        "trn1	v19.2d, v19.2d, v20.2d\n\t"
        "trn2	v20.2d, v29.2d, v20.2d\n\t"
        "stp	q5, q6, [x1]\n\t"
        "stp	q7, q8, [x1, #32]\n\t"
        "stp	q9, q10, [x1, #64]\n\t"
        "stp	q11, q12, [x1, #96]\n\t"
        "stp	q13, q14, [x1, #128]\n\t"
        "stp	q15, q16, [x1, #160]\n\t"
        "stp	q17, q18, [x1, #192]\n\t"
        "stp	q19, q20, [x1, #224]\n\t"
        : [r] "+r" (r)
        : [L_kyber_aarch64_q] "S" (L_kyber_aarch64_q), [L_kyber_aarch64_consts] "S" (L_kyber_aarch64_consts), [L_sha3_aarch64_r] "S" (L_sha3_aarch64_r), [L_kyber_aarch64_zetas] "S" (L_kyber_aarch64_zetas), [L_kyber_aarch64_zetas_qinv] "S" (L_kyber_aarch64_zetas_qinv)
        : "memory", "x1", "x2", "x3", "x4", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15", "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26", "v27", "v28", "v29", "v30", "cc"
    );
}

static const word16 L_kyber_aarch64_zetas_inv[] = {
    0x6a5,
    0x6a5,
    0x70f,
    0x70f,
    0x5b4,
    0x5b4,
    0x943,
    0x943,
    0x922,
    0x922,
    0x91d,
    0x91d,
    0x134,
    0x134,
    0x6c,
    0x6c,
    0xb23,
    0xb23,
    0x366,
    0x366,
    0x356,
    0x356,
    0x5e6,
    0x5e6,
    0x9e7,
    0x9e7,
    0x4fe,
    0x4fe,
    0x5fa,
    0x5fa,
    0x4a1,
    0x4a1,
    0x67b,
    0x67b,
    0x4a3,
    0x4a3,
    0xc25,
    0xc25,
    0x36a,
    0x36a,
    0x537,
    0x537,
    0x83f,
    0x83f,
    0x88,
    0x88,
    0x4bf,
    0x4bf,
    0xb81,
    0xb81,
    0x5b9,
    0x5b9,
    0x505,
    0x505,
    0x7d7,
    0x7d7,
    0xa9f,
    0xa9f,
    0xaa6,
    0xaa6,
    0x8b8,
    0x8b8,
    0x9d0,
    0x9d0,
    0x4b,
    0x4b,
    0x9c,
    0x9c,
    0xbb8,
    0xbb8,
    0xb5f,
    0xb5f,
    0xba4,
    0xba4,
    0x368,
    0x368,
    0xa7d,
    0xa7d,
    0x636,
    0x636,
    0x8a2,
    0x8a2,
    0x25a,
    0x25a,
    0x736,
    0x736,
    0x309,
    0x309,
    0x93,
    0x93,
    0x87a,
    0x87a,
    0x9f7,
    0x9f7,
    0xf6,
    0xf6,
    0x68c,
    0x68c,
    0x6db,
    0x6db,
    0x1cc,
    0x1cc,
    0x123,
    0x123,
    0xeb,
    0xeb,
    0xc50,
    0xc50,
    0xab6,
    0xab6,
    0xb5b,
    0xb5b,
    0xc98,
    0xc98,
    0x6f3,
    0x6f3,
    0x99a,
    0x99a,
    0x4e3,
    0x4e3,
    0x9b6,
    0x9b6,
    0xad6,
    0xad6,
    0xb53,
    0xb53,
    0x44f,
    0x44f,
    0x4fb,
    0x4fb,
    0x4fb,
    0x4fb,
    0xa5c,
    0xa5c,
    0xa5c,
    0xa5c,
    0x429,
    0x429,
    0x429,
    0x429,
    0xb41,
    0xb41,
    0xb41,
    0xb41,
    0x2d5,
    0x2d5,
    0x2d5,
    0x2d5,
    0x5e4,
    0x5e4,
    0x5e4,
    0x5e4,
    0x940,
    0x940,
    0x940,
    0x940,
    0x18e,
    0x18e,
    0x18e,
    0x18e,
    0x3b7,
    0x3b7,
    0x3b7,
    0x3b7,
    0xf7,
    0xf7,
    0xf7,
    0xf7,
    0x58d,
    0x58d,
    0x58d,
    0x58d,
    0xc96,
    0xc96,
    0xc96,
    0xc96,
    0x9c3,
    0x9c3,
    0x9c3,
    0x9c3,
    0x10f,
    0x10f,
    0x10f,
    0x10f,
    0x5a,
    0x5a,
    0x5a,
    0x5a,
    0x355,
    0x355,
    0x355,
    0x355,
    0x744,
    0x744,
    0x744,
    0x744,
    0xc83,
    0xc83,
    0xc83,
    0xc83,
    0x48a,
    0x48a,
    0x48a,
    0x48a,
    0x652,
    0x652,
    0x652,
    0x652,
    0x29a,
    0x29a,
    0x29a,
    0x29a,
    0x140,
    0x140,
    0x140,
    0x140,
    0x8,
    0x8,
    0x8,
    0x8,
    0xafd,
    0xafd,
    0xafd,
    0xafd,
    0x608,
    0x608,
    0x608,
    0x608,
    0x11a,
    0x11a,
    0x11a,
    0x11a,
    0x72e,
    0x72e,
    0x72e,
    0x72e,
    0x50d,
    0x50d,
    0x50d,
    0x50d,
    0x90a,
    0x90a,
    0x90a,
    0x90a,
    0x228,
    0x228,
    0x228,
    0x228,
    0xa75,
    0xa75,
    0xa75,
    0xa75,
    0x83a,
    0x83a,
    0x83a,
    0x83a,
    0x623,
    0xcd,
    0xb66,
    0x606,
    0xaa1,
    0xa25,
    0x908,
    0x2a9,
    0x82,
    0x642,
    0x74f,
    0x33d,
    0xb82,
    0xbf9,
    0x52d,
    0xac4,
    0x745,
    0x5c2,
    0x4b2,
    0x93f,
    0xc4b,
    0x6d8,
    0xa93,
    0xab,
    0xc37,
    0xbe2,
    0x773,
    0x72c,
    0x5ed,
    0x167,
    0x2f6,
    0x5a1,
};

static const word16 L_kyber_aarch64_zetas_inv_qinv[] = {
    0xa5a5,
    0xa5a5,
    0x440f,
    0x440f,
    0xe1b4,
    0xe1b4,
    0xa243,
    0xa243,
    0x4f22,
    0x4f22,
    0x901d,
    0x901d,
    0x5d34,
    0x5d34,
    0x846c,
    0x846c,
    0x4423,
    0x4423,
    0xd566,
    0xd566,
    0xa556,
    0xa556,
    0x57e6,
    0x57e6,
    0x4ee7,
    0x4ee7,
    0x1efe,
    0x1efe,
    0x53fa,
    0x53fa,
    0xd7a1,
    0xd7a1,
    0xc77b,
    0xc77b,
    0xbda3,
    0xbda3,
    0x2b25,
    0x2b25,
    0xa16a,
    0xa16a,
    0x3a37,
    0x3a37,
    0xd53f,
    0xd53f,
    0x1888,
    0x1888,
    0x51bf,
    0x51bf,
    0x7e81,
    0x7e81,
    0xa0b9,
    0xa0b9,
    0xc405,
    0xc405,
    0x1cd7,
    0x1cd7,
    0xf79f,
    0xf79f,
    0x9ca6,
    0x9ca6,
    0xb0b8,
    0xb0b8,
    0x79d0,
    0x79d0,
    0x314b,
    0x314b,
    0x149c,
    0x149c,
    0xb3b8,
    0xb3b8,
    0x385f,
    0x385f,
    0xb7a4,
    0xb7a4,
    0xbb68,
    0xbb68,
    0xb17d,
    0xb17d,
    0x4836,
    0x4836,
    0xcea2,
    0xcea2,
    0x705a,
    0x705a,
    0x4936,
    0x4936,
    0x8e09,
    0x8e09,
    0x8993,
    0x8993,
    0xd67a,
    0xd67a,
    0x7ef7,
    0x7ef7,
    0x82f6,
    0x82f6,
    0xea8c,
    0xea8c,
    0xe7db,
    0xe7db,
    0xa5cc,
    0xa5cc,
    0x3a23,
    0x3a23,
    0x11eb,
    0x11eb,
    0xfc50,
    0xfc50,
    0xccb6,
    0xccb6,
    0x6c5b,
    0x6c5b,
    0x5498,
    0x5498,
    0xaff3,
    0xaff3,
    0x379a,
    0x379a,
    0x7de3,
    0x7de3,
    0xcbb6,
    0xcbb6,
    0x2cd6,
    0x2cd6,
    0xd453,
    0xd453,
    0x14f,
    0x14f,
    0x45fb,
    0x45fb,
    0x45fb,
    0x45fb,
    0x5e5c,
    0x5e5c,
    0x5e5c,
    0x5e5c,
    0xef29,
    0xef29,
    0xef29,
    0xef29,
    0xbe41,
    0xbe41,
    0xbe41,
    0xbe41,
    0x31d5,
    0x31d5,
    0x31d5,
    0x31d5,
    0x71e4,
    0x71e4,
    0x71e4,
    0x71e4,
    0xc940,
    0xc940,
    0xc940,
    0xc940,
    0xcb8e,
    0xcb8e,
    0xcb8e,
    0xcb8e,
    0xb8b7,
    0xb8b7,
    0xb8b7,
    0xb8b7,
    0x75f7,
    0x75f7,
    0x75f7,
    0x75f7,
    0xdc8d,
    0xdc8d,
    0xdc8d,
    0xdc8d,
    0x6e96,
    0x6e96,
    0x6e96,
    0x6e96,
    0x22c3,
    0x22c3,
    0x22c3,
    0x22c3,
    0x3e0f,
    0x3e0f,
    0x3e0f,
    0x3e0f,
    0x6e5a,
    0x6e5a,
    0x6e5a,
    0x6e5a,
    0xb255,
    0xb255,
    0xb255,
    0xb255,
    0x9344,
    0x9344,
    0x9344,
    0x9344,
    0x6583,
    0x6583,
    0x6583,
    0x6583,
    0x28a,
    0x28a,
    0x28a,
    0x28a,
    0xdc52,
    0xdc52,
    0xdc52,
    0xdc52,
    0x309a,
    0x309a,
    0x309a,
    0x309a,
    0xc140,
    0xc140,
    0xc140,
    0xc140,
    0x9808,
    0x9808,
    0x9808,
    0x9808,
    0x31fd,
    0x31fd,
    0x31fd,
    0x31fd,
    0x9e08,
    0x9e08,
    0x9e08,
    0x9e08,
    0xaf1a,
    0xaf1a,
    0xaf1a,
    0xaf1a,
    0xb12e,
    0xb12e,
    0xb12e,
    0xb12e,
    0x5c0d,
    0x5c0d,
    0x5c0d,
    0x5c0d,
    0x870a,
    0x870a,
    0x870a,
    0x870a,
    0xfa28,
    0xfa28,
    0xfa28,
    0xfa28,
    0x1975,
    0x1975,
    0x1975,
    0x1975,
    0x163a,
    0x163a,
    0x163a,
    0x163a,
    0x3f23,
    0x97cd,
    0xdd66,
    0xb806,
    0xdda1,
    0x2925,
    0xa108,
    0x6da9,
    0x6682,
    0xac42,
    0x44f,
    0xea3d,
    0x7182,
    0x66f9,
    0xbc2d,
    0x16c4,
    0x8645,
    0x2bc2,
    0xfab2,
    0xd63f,
    0x3d4b,
    0xed8,
    0x9393,
    0x51ab,
    0x4137,
    0x91e2,
    0x3073,
    0xcb2c,
    0xfced,
    0xc667,
    0x84f6,
    0xd8a1,
};

void kyber_invntt(sword16* r)
{
    __asm__ __volatile__ (
#ifndef __APPLE__
        "adrp x2, %[L_kyber_aarch64_zetas_inv]\n\t"
        "add  x2, x2, :lo12:%[L_kyber_aarch64_zetas_inv]\n\t"
#else
        "adrp x2, %[L_kyber_aarch64_zetas_inv]@PAGE\n\t"
        "add  x2, x2, %[L_kyber_aarch64_zetas_inv]@PAGEOFF\n\t"
#endif /* __APPLE__ */
#ifndef __APPLE__
        "adrp x3, %[L_kyber_aarch64_zetas_inv_qinv]\n\t"
        "add  x3, x3, :lo12:%[L_kyber_aarch64_zetas_inv_qinv]\n\t"
#else
        "adrp x3, %[L_kyber_aarch64_zetas_inv_qinv]@PAGE\n\t"
        "add  x3, x3, %[L_kyber_aarch64_zetas_inv_qinv]@PAGEOFF\n\t"
#endif /* __APPLE__ */
#ifndef __APPLE__
        "adrp x4, %[L_kyber_aarch64_consts]\n\t"
        "add  x4, x4, :lo12:%[L_kyber_aarch64_consts]\n\t"
#else
        "adrp x4, %[L_kyber_aarch64_consts]@PAGE\n\t"
        "add  x4, x4, %[L_kyber_aarch64_consts]@PAGEOFF\n\t"
#endif /* __APPLE__ */
        "add	x1, %x[r], #0x100\n\t"
        "ldr	q8, [x4]\n\t"
        "ldp	q9, q10, [%x[r]]\n\t"
        "ldp	q11, q12, [%x[r], #32]\n\t"
        "ldp	q13, q14, [%x[r], #64]\n\t"
        "ldp	q15, q16, [%x[r], #96]\n\t"
        "ldp	q17, q18, [%x[r], #128]\n\t"
        "ldp	q19, q20, [%x[r], #160]\n\t"
        "ldp	q21, q22, [%x[r], #192]\n\t"
        "ldp	q23, q24, [%x[r], #224]\n\t"
        "mov	v25.16b, v9.16b\n\t"
        "trn1	v9.2d, v9.2d, v10.2d\n\t"
        "trn2	v10.2d, v25.2d, v10.2d\n\t"
        "mov	v25.16b, v9.16b\n\t"
        "trn1	v9.4s, v9.4s, v10.4s\n\t"
        "trn2	v10.4s, v25.4s, v10.4s\n\t"
        "mov	v25.16b, v11.16b\n\t"
        "trn1	v11.2d, v11.2d, v12.2d\n\t"
        "trn2	v12.2d, v25.2d, v12.2d\n\t"
        "mov	v25.16b, v11.16b\n\t"
        "trn1	v11.4s, v11.4s, v12.4s\n\t"
        "trn2	v12.4s, v25.4s, v12.4s\n\t"
        "mov	v25.16b, v13.16b\n\t"
        "trn1	v13.2d, v13.2d, v14.2d\n\t"
        "trn2	v14.2d, v25.2d, v14.2d\n\t"
        "mov	v25.16b, v13.16b\n\t"
        "trn1	v13.4s, v13.4s, v14.4s\n\t"
        "trn2	v14.4s, v25.4s, v14.4s\n\t"
        "mov	v25.16b, v15.16b\n\t"
        "trn1	v15.2d, v15.2d, v16.2d\n\t"
        "trn2	v16.2d, v25.2d, v16.2d\n\t"
        "mov	v25.16b, v15.16b\n\t"
        "trn1	v15.4s, v15.4s, v16.4s\n\t"
        "trn2	v16.4s, v25.4s, v16.4s\n\t"
        "mov	v25.16b, v17.16b\n\t"
        "trn1	v17.2d, v17.2d, v18.2d\n\t"
        "trn2	v18.2d, v25.2d, v18.2d\n\t"
        "mov	v25.16b, v17.16b\n\t"
        "trn1	v17.4s, v17.4s, v18.4s\n\t"
        "trn2	v18.4s, v25.4s, v18.4s\n\t"
        "mov	v25.16b, v19.16b\n\t"
        "trn1	v19.2d, v19.2d, v20.2d\n\t"
        "trn2	v20.2d, v25.2d, v20.2d\n\t"
        "mov	v25.16b, v19.16b\n\t"
        "trn1	v19.4s, v19.4s, v20.4s\n\t"
        "trn2	v20.4s, v25.4s, v20.4s\n\t"
        "mov	v25.16b, v21.16b\n\t"
        "trn1	v21.2d, v21.2d, v22.2d\n\t"
        "trn2	v22.2d, v25.2d, v22.2d\n\t"
        "mov	v25.16b, v21.16b\n\t"
        "trn1	v21.4s, v21.4s, v22.4s\n\t"
        "trn2	v22.4s, v25.4s, v22.4s\n\t"
        "mov	v25.16b, v23.16b\n\t"
        "trn1	v23.2d, v23.2d, v24.2d\n\t"
        "trn2	v24.2d, v25.2d, v24.2d\n\t"
        "mov	v25.16b, v23.16b\n\t"
        "trn1	v23.4s, v23.4s, v24.4s\n\t"
        "trn2	v24.4s, v25.4s, v24.4s\n\t"
        "ldr	q0, [x2]\n\t"
        "ldr	q1, [x2, #16]\n\t"
        "ldr	q2, [x3]\n\t"
        "ldr	q3, [x3, #16]\n\t"
        "sub	v26.8h, v9.8h, v10.8h\n\t"
        "sub	v28.8h, v11.8h, v12.8h\n\t"
        "add	v9.8h, v9.8h, v10.8h\n\t"
        "add	v11.8h, v11.8h, v12.8h\n\t"
        "mul	v25.8h, v26.8h, v2.8h\n\t"
        "mul	v27.8h, v28.8h, v3.8h\n\t"
        "sqrdmulh	v10.8h, v26.8h, v0.8h\n\t"
        "sqrdmulh	v12.8h, v28.8h, v1.8h\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v10.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v12.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v10.8h, v10.8h, v25.8h\n\t"
        "sub	v12.8h, v12.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v10.8h, v10.8h, #1\n\t"
        "sshr	v12.8h, v12.8h, #1\n\t"
        "ldr	q0, [x2, #32]\n\t"
        "ldr	q1, [x2, #48]\n\t"
        "ldr	q2, [x3, #32]\n\t"
        "ldr	q3, [x3, #48]\n\t"
        "sub	v26.8h, v13.8h, v14.8h\n\t"
        "sub	v28.8h, v15.8h, v16.8h\n\t"
        "add	v13.8h, v13.8h, v14.8h\n\t"
        "add	v15.8h, v15.8h, v16.8h\n\t"
        "mul	v25.8h, v26.8h, v2.8h\n\t"
        "mul	v27.8h, v28.8h, v3.8h\n\t"
        "sqrdmulh	v14.8h, v26.8h, v0.8h\n\t"
        "sqrdmulh	v16.8h, v28.8h, v1.8h\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v14.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v16.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v14.8h, v14.8h, v25.8h\n\t"
        "sub	v16.8h, v16.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v14.8h, v14.8h, #1\n\t"
        "sshr	v16.8h, v16.8h, #1\n\t"
        "ldr	q0, [x2, #64]\n\t"
        "ldr	q1, [x2, #80]\n\t"
        "ldr	q2, [x3, #64]\n\t"
        "ldr	q3, [x3, #80]\n\t"
        "sub	v26.8h, v17.8h, v18.8h\n\t"
        "sub	v28.8h, v19.8h, v20.8h\n\t"
        "add	v17.8h, v17.8h, v18.8h\n\t"
        "add	v19.8h, v19.8h, v20.8h\n\t"
        "mul	v25.8h, v26.8h, v2.8h\n\t"
        "mul	v27.8h, v28.8h, v3.8h\n\t"
        "sqrdmulh	v18.8h, v26.8h, v0.8h\n\t"
        "sqrdmulh	v20.8h, v28.8h, v1.8h\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v18.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v20.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v18.8h, v18.8h, v25.8h\n\t"
        "sub	v20.8h, v20.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v18.8h, v18.8h, #1\n\t"
        "sshr	v20.8h, v20.8h, #1\n\t"
        "ldr	q0, [x2, #96]\n\t"
        "ldr	q1, [x2, #112]\n\t"
        "ldr	q2, [x3, #96]\n\t"
        "ldr	q3, [x3, #112]\n\t"
        "sub	v26.8h, v21.8h, v22.8h\n\t"
        "sub	v28.8h, v23.8h, v24.8h\n\t"
        "add	v21.8h, v21.8h, v22.8h\n\t"
        "add	v23.8h, v23.8h, v24.8h\n\t"
        "mul	v25.8h, v26.8h, v2.8h\n\t"
        "mul	v27.8h, v28.8h, v3.8h\n\t"
        "sqrdmulh	v22.8h, v26.8h, v0.8h\n\t"
        "sqrdmulh	v24.8h, v28.8h, v1.8h\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v22.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v24.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v22.8h, v22.8h, v25.8h\n\t"
        "sub	v24.8h, v24.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v22.8h, v22.8h, #1\n\t"
        "sshr	v24.8h, v24.8h, #1\n\t"
        "ldr	q0, [x2, #256]\n\t"
        "ldr	q1, [x2, #272]\n\t"
        "ldr	q2, [x3, #256]\n\t"
        "ldr	q3, [x3, #272]\n\t"
        "mov	v25.16b, v9.16b\n\t"
        "mov	v26.16b, v11.16b\n\t"
        "trn1	v9.4s, v9.4s, v10.4s\n\t"
        "trn1	v11.4s, v11.4s, v12.4s\n\t"
        "trn2	v10.4s, v25.4s, v10.4s\n\t"
        "trn2	v12.4s, v26.4s, v12.4s\n\t"
        "sub	v26.8h, v9.8h, v10.8h\n\t"
        "sub	v28.8h, v11.8h, v12.8h\n\t"
        "add	v9.8h, v9.8h, v10.8h\n\t"
        "add	v11.8h, v11.8h, v12.8h\n\t"
        "mul	v25.8h, v26.8h, v2.8h\n\t"
        "mul	v27.8h, v28.8h, v3.8h\n\t"
        "sqrdmulh	v10.8h, v26.8h, v0.8h\n\t"
        "sqrdmulh	v12.8h, v28.8h, v1.8h\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v10.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v12.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v10.8h, v10.8h, v25.8h\n\t"
        "sub	v12.8h, v12.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v10.8h, v10.8h, #1\n\t"
        "sshr	v12.8h, v12.8h, #1\n\t"
        "ldr	q0, [x2, #288]\n\t"
        "ldr	q1, [x2, #304]\n\t"
        "ldr	q2, [x3, #288]\n\t"
        "ldr	q3, [x3, #304]\n\t"
        "mov	v25.16b, v13.16b\n\t"
        "mov	v26.16b, v15.16b\n\t"
        "trn1	v13.4s, v13.4s, v14.4s\n\t"
        "trn1	v15.4s, v15.4s, v16.4s\n\t"
        "trn2	v14.4s, v25.4s, v14.4s\n\t"
        "trn2	v16.4s, v26.4s, v16.4s\n\t"
        "sub	v26.8h, v13.8h, v14.8h\n\t"
        "sub	v28.8h, v15.8h, v16.8h\n\t"
        "add	v13.8h, v13.8h, v14.8h\n\t"
        "add	v15.8h, v15.8h, v16.8h\n\t"
        "mul	v25.8h, v26.8h, v2.8h\n\t"
        "mul	v27.8h, v28.8h, v3.8h\n\t"
        "sqrdmulh	v14.8h, v26.8h, v0.8h\n\t"
        "sqrdmulh	v16.8h, v28.8h, v1.8h\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v14.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v16.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v14.8h, v14.8h, v25.8h\n\t"
        "sub	v16.8h, v16.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v14.8h, v14.8h, #1\n\t"
        "sshr	v16.8h, v16.8h, #1\n\t"
        "ldr	q0, [x2, #320]\n\t"
        "ldr	q1, [x2, #336]\n\t"
        "ldr	q2, [x3, #320]\n\t"
        "ldr	q3, [x3, #336]\n\t"
        "mov	v25.16b, v17.16b\n\t"
        "mov	v26.16b, v19.16b\n\t"
        "trn1	v17.4s, v17.4s, v18.4s\n\t"
        "trn1	v19.4s, v19.4s, v20.4s\n\t"
        "trn2	v18.4s, v25.4s, v18.4s\n\t"
        "trn2	v20.4s, v26.4s, v20.4s\n\t"
        "sub	v26.8h, v17.8h, v18.8h\n\t"
        "sub	v28.8h, v19.8h, v20.8h\n\t"
        "add	v17.8h, v17.8h, v18.8h\n\t"
        "add	v19.8h, v19.8h, v20.8h\n\t"
        "mul	v25.8h, v26.8h, v2.8h\n\t"
        "mul	v27.8h, v28.8h, v3.8h\n\t"
        "sqrdmulh	v18.8h, v26.8h, v0.8h\n\t"
        "sqrdmulh	v20.8h, v28.8h, v1.8h\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v18.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v20.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v18.8h, v18.8h, v25.8h\n\t"
        "sub	v20.8h, v20.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v18.8h, v18.8h, #1\n\t"
        "sshr	v20.8h, v20.8h, #1\n\t"
        "ldr	q0, [x2, #352]\n\t"
        "ldr	q1, [x2, #368]\n\t"
        "ldr	q2, [x3, #352]\n\t"
        "ldr	q3, [x3, #368]\n\t"
        "mov	v25.16b, v21.16b\n\t"
        "mov	v26.16b, v23.16b\n\t"
        "trn1	v21.4s, v21.4s, v22.4s\n\t"
        "trn1	v23.4s, v23.4s, v24.4s\n\t"
        "trn2	v22.4s, v25.4s, v22.4s\n\t"
        "trn2	v24.4s, v26.4s, v24.4s\n\t"
        "sub	v26.8h, v21.8h, v22.8h\n\t"
        "sub	v28.8h, v23.8h, v24.8h\n\t"
        "add	v21.8h, v21.8h, v22.8h\n\t"
        "add	v23.8h, v23.8h, v24.8h\n\t"
        "mul	v25.8h, v26.8h, v2.8h\n\t"
        "mul	v27.8h, v28.8h, v3.8h\n\t"
        "sqrdmulh	v22.8h, v26.8h, v0.8h\n\t"
        "sqrdmulh	v24.8h, v28.8h, v1.8h\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v22.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v24.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v22.8h, v22.8h, v25.8h\n\t"
        "sub	v24.8h, v24.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v22.8h, v22.8h, #1\n\t"
        "sshr	v24.8h, v24.8h, #1\n\t"
        "ldr	q0, [x2, #512]\n\t"
        "ldr	q2, [x3, #512]\n\t"
        "mov	v25.16b, v9.16b\n\t"
        "mov	v26.16b, v11.16b\n\t"
        "trn1	v9.2d, v9.2d, v10.2d\n\t"
        "trn1	v11.2d, v11.2d, v12.2d\n\t"
        "trn2	v10.2d, v25.2d, v10.2d\n\t"
        "trn2	v12.2d, v26.2d, v12.2d\n\t"
        "sub	v26.8h, v9.8h, v10.8h\n\t"
        "sub	v28.8h, v11.8h, v12.8h\n\t"
        "add	v9.8h, v9.8h, v10.8h\n\t"
        "add	v11.8h, v11.8h, v12.8h\n\t"
        "mul	v25.8h, v26.8h, v2.h[0]\n\t"
        "mul	v27.8h, v28.8h, v2.h[1]\n\t"
        "sqrdmulh	v10.8h, v26.8h, v0.h[0]\n\t"
        "sqrdmulh	v12.8h, v28.8h, v0.h[1]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v10.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v12.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v10.8h, v10.8h, v25.8h\n\t"
        "sub	v12.8h, v12.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v10.8h, v10.8h, #1\n\t"
        "sshr	v12.8h, v12.8h, #1\n\t"
        "mov	v25.16b, v13.16b\n\t"
        "mov	v26.16b, v15.16b\n\t"
        "trn1	v13.2d, v13.2d, v14.2d\n\t"
        "trn1	v15.2d, v15.2d, v16.2d\n\t"
        "trn2	v14.2d, v25.2d, v14.2d\n\t"
        "trn2	v16.2d, v26.2d, v16.2d\n\t"
        "sub	v26.8h, v13.8h, v14.8h\n\t"
        "sub	v28.8h, v15.8h, v16.8h\n\t"
        "add	v13.8h, v13.8h, v14.8h\n\t"
        "add	v15.8h, v15.8h, v16.8h\n\t"
        "mul	v25.8h, v26.8h, v2.h[2]\n\t"
        "mul	v27.8h, v28.8h, v2.h[3]\n\t"
        "sqrdmulh	v14.8h, v26.8h, v0.h[2]\n\t"
        "sqrdmulh	v16.8h, v28.8h, v0.h[3]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v14.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v16.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v14.8h, v14.8h, v25.8h\n\t"
        "sub	v16.8h, v16.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v14.8h, v14.8h, #1\n\t"
        "sshr	v16.8h, v16.8h, #1\n\t"
        "mov	v25.16b, v17.16b\n\t"
        "mov	v26.16b, v19.16b\n\t"
        "trn1	v17.2d, v17.2d, v18.2d\n\t"
        "trn1	v19.2d, v19.2d, v20.2d\n\t"
        "trn2	v18.2d, v25.2d, v18.2d\n\t"
        "trn2	v20.2d, v26.2d, v20.2d\n\t"
        "sub	v26.8h, v17.8h, v18.8h\n\t"
        "sub	v28.8h, v19.8h, v20.8h\n\t"
        "add	v17.8h, v17.8h, v18.8h\n\t"
        "add	v19.8h, v19.8h, v20.8h\n\t"
        "mul	v25.8h, v26.8h, v2.h[4]\n\t"
        "mul	v27.8h, v28.8h, v2.h[5]\n\t"
        "sqrdmulh	v18.8h, v26.8h, v0.h[4]\n\t"
        "sqrdmulh	v20.8h, v28.8h, v0.h[5]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v18.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v20.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v18.8h, v18.8h, v25.8h\n\t"
        "sub	v20.8h, v20.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v18.8h, v18.8h, #1\n\t"
        "sshr	v20.8h, v20.8h, #1\n\t"
        "mov	v25.16b, v21.16b\n\t"
        "mov	v26.16b, v23.16b\n\t"
        "trn1	v21.2d, v21.2d, v22.2d\n\t"
        "trn1	v23.2d, v23.2d, v24.2d\n\t"
        "trn2	v22.2d, v25.2d, v22.2d\n\t"
        "trn2	v24.2d, v26.2d, v24.2d\n\t"
        "sub	v26.8h, v21.8h, v22.8h\n\t"
        "sub	v28.8h, v23.8h, v24.8h\n\t"
        "add	v21.8h, v21.8h, v22.8h\n\t"
        "add	v23.8h, v23.8h, v24.8h\n\t"
        "mul	v25.8h, v26.8h, v2.h[6]\n\t"
        "mul	v27.8h, v28.8h, v2.h[7]\n\t"
        "sqrdmulh	v22.8h, v26.8h, v0.h[6]\n\t"
        "sqrdmulh	v24.8h, v28.8h, v0.h[7]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v22.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v24.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v22.8h, v22.8h, v25.8h\n\t"
        "sub	v24.8h, v24.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v22.8h, v22.8h, #1\n\t"
        "sshr	v24.8h, v24.8h, #1\n\t"
        "sqdmulh	v25.8h, v9.8h, v8.h[2]\n\t"
        "sqdmulh	v26.8h, v11.8h, v8.h[2]\n\t"
        "sshr	v25.8h, v25.8h, #11\n\t"
        "sshr	v26.8h, v26.8h, #11\n\t"
        "mls	v9.8h, v25.8h, v8.h[0]\n\t"
        "mls	v11.8h, v26.8h, v8.h[0]\n\t"
        "sqdmulh	v25.8h, v13.8h, v8.h[2]\n\t"
        "sqdmulh	v26.8h, v15.8h, v8.h[2]\n\t"
        "sshr	v25.8h, v25.8h, #11\n\t"
        "sshr	v26.8h, v26.8h, #11\n\t"
        "mls	v13.8h, v25.8h, v8.h[0]\n\t"
        "mls	v15.8h, v26.8h, v8.h[0]\n\t"
        "sqdmulh	v25.8h, v17.8h, v8.h[2]\n\t"
        "sqdmulh	v26.8h, v19.8h, v8.h[2]\n\t"
        "sshr	v25.8h, v25.8h, #11\n\t"
        "sshr	v26.8h, v26.8h, #11\n\t"
        "mls	v17.8h, v25.8h, v8.h[0]\n\t"
        "mls	v19.8h, v26.8h, v8.h[0]\n\t"
        "sqdmulh	v25.8h, v21.8h, v8.h[2]\n\t"
        "sqdmulh	v26.8h, v23.8h, v8.h[2]\n\t"
        "sshr	v25.8h, v25.8h, #11\n\t"
        "sshr	v26.8h, v26.8h, #11\n\t"
        "mls	v21.8h, v25.8h, v8.h[0]\n\t"
        "mls	v23.8h, v26.8h, v8.h[0]\n\t"
        "stp	q9, q10, [%x[r]]\n\t"
        "stp	q11, q12, [%x[r], #32]\n\t"
        "stp	q13, q14, [%x[r], #64]\n\t"
        "stp	q15, q16, [%x[r], #96]\n\t"
        "stp	q17, q18, [%x[r], #128]\n\t"
        "stp	q19, q20, [%x[r], #160]\n\t"
        "stp	q21, q22, [%x[r], #192]\n\t"
        "stp	q23, q24, [%x[r], #224]\n\t"
        "ldp	q9, q10, [x1]\n\t"
        "ldp	q11, q12, [x1, #32]\n\t"
        "ldp	q13, q14, [x1, #64]\n\t"
        "ldp	q15, q16, [x1, #96]\n\t"
        "ldp	q17, q18, [x1, #128]\n\t"
        "ldp	q19, q20, [x1, #160]\n\t"
        "ldp	q21, q22, [x1, #192]\n\t"
        "ldp	q23, q24, [x1, #224]\n\t"
        "mov	v25.16b, v9.16b\n\t"
        "trn1	v9.2d, v9.2d, v10.2d\n\t"
        "trn2	v10.2d, v25.2d, v10.2d\n\t"
        "mov	v25.16b, v9.16b\n\t"
        "trn1	v9.4s, v9.4s, v10.4s\n\t"
        "trn2	v10.4s, v25.4s, v10.4s\n\t"
        "mov	v25.16b, v11.16b\n\t"
        "trn1	v11.2d, v11.2d, v12.2d\n\t"
        "trn2	v12.2d, v25.2d, v12.2d\n\t"
        "mov	v25.16b, v11.16b\n\t"
        "trn1	v11.4s, v11.4s, v12.4s\n\t"
        "trn2	v12.4s, v25.4s, v12.4s\n\t"
        "mov	v25.16b, v13.16b\n\t"
        "trn1	v13.2d, v13.2d, v14.2d\n\t"
        "trn2	v14.2d, v25.2d, v14.2d\n\t"
        "mov	v25.16b, v13.16b\n\t"
        "trn1	v13.4s, v13.4s, v14.4s\n\t"
        "trn2	v14.4s, v25.4s, v14.4s\n\t"
        "mov	v25.16b, v15.16b\n\t"
        "trn1	v15.2d, v15.2d, v16.2d\n\t"
        "trn2	v16.2d, v25.2d, v16.2d\n\t"
        "mov	v25.16b, v15.16b\n\t"
        "trn1	v15.4s, v15.4s, v16.4s\n\t"
        "trn2	v16.4s, v25.4s, v16.4s\n\t"
        "mov	v25.16b, v17.16b\n\t"
        "trn1	v17.2d, v17.2d, v18.2d\n\t"
        "trn2	v18.2d, v25.2d, v18.2d\n\t"
        "mov	v25.16b, v17.16b\n\t"
        "trn1	v17.4s, v17.4s, v18.4s\n\t"
        "trn2	v18.4s, v25.4s, v18.4s\n\t"
        "mov	v25.16b, v19.16b\n\t"
        "trn1	v19.2d, v19.2d, v20.2d\n\t"
        "trn2	v20.2d, v25.2d, v20.2d\n\t"
        "mov	v25.16b, v19.16b\n\t"
        "trn1	v19.4s, v19.4s, v20.4s\n\t"
        "trn2	v20.4s, v25.4s, v20.4s\n\t"
        "mov	v25.16b, v21.16b\n\t"
        "trn1	v21.2d, v21.2d, v22.2d\n\t"
        "trn2	v22.2d, v25.2d, v22.2d\n\t"
        "mov	v25.16b, v21.16b\n\t"
        "trn1	v21.4s, v21.4s, v22.4s\n\t"
        "trn2	v22.4s, v25.4s, v22.4s\n\t"
        "mov	v25.16b, v23.16b\n\t"
        "trn1	v23.2d, v23.2d, v24.2d\n\t"
        "trn2	v24.2d, v25.2d, v24.2d\n\t"
        "mov	v25.16b, v23.16b\n\t"
        "trn1	v23.4s, v23.4s, v24.4s\n\t"
        "trn2	v24.4s, v25.4s, v24.4s\n\t"
        "ldr	q0, [x2, #128]\n\t"
        "ldr	q1, [x2, #144]\n\t"
        "ldr	q2, [x3, #128]\n\t"
        "ldr	q3, [x3, #144]\n\t"
        "sub	v26.8h, v9.8h, v10.8h\n\t"
        "sub	v28.8h, v11.8h, v12.8h\n\t"
        "add	v9.8h, v9.8h, v10.8h\n\t"
        "add	v11.8h, v11.8h, v12.8h\n\t"
        "mul	v25.8h, v26.8h, v2.8h\n\t"
        "mul	v27.8h, v28.8h, v3.8h\n\t"
        "sqrdmulh	v10.8h, v26.8h, v0.8h\n\t"
        "sqrdmulh	v12.8h, v28.8h, v1.8h\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v10.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v12.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v10.8h, v10.8h, v25.8h\n\t"
        "sub	v12.8h, v12.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v10.8h, v10.8h, #1\n\t"
        "sshr	v12.8h, v12.8h, #1\n\t"
        "ldr	q0, [x2, #160]\n\t"
        "ldr	q1, [x2, #176]\n\t"
        "ldr	q2, [x3, #160]\n\t"
        "ldr	q3, [x3, #176]\n\t"
        "sub	v26.8h, v13.8h, v14.8h\n\t"
        "sub	v28.8h, v15.8h, v16.8h\n\t"
        "add	v13.8h, v13.8h, v14.8h\n\t"
        "add	v15.8h, v15.8h, v16.8h\n\t"
        "mul	v25.8h, v26.8h, v2.8h\n\t"
        "mul	v27.8h, v28.8h, v3.8h\n\t"
        "sqrdmulh	v14.8h, v26.8h, v0.8h\n\t"
        "sqrdmulh	v16.8h, v28.8h, v1.8h\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v14.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v16.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v14.8h, v14.8h, v25.8h\n\t"
        "sub	v16.8h, v16.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v14.8h, v14.8h, #1\n\t"
        "sshr	v16.8h, v16.8h, #1\n\t"
        "ldr	q0, [x2, #192]\n\t"
        "ldr	q1, [x2, #208]\n\t"
        "ldr	q2, [x3, #192]\n\t"
        "ldr	q3, [x3, #208]\n\t"
        "sub	v26.8h, v17.8h, v18.8h\n\t"
        "sub	v28.8h, v19.8h, v20.8h\n\t"
        "add	v17.8h, v17.8h, v18.8h\n\t"
        "add	v19.8h, v19.8h, v20.8h\n\t"
        "mul	v25.8h, v26.8h, v2.8h\n\t"
        "mul	v27.8h, v28.8h, v3.8h\n\t"
        "sqrdmulh	v18.8h, v26.8h, v0.8h\n\t"
        "sqrdmulh	v20.8h, v28.8h, v1.8h\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v18.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v20.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v18.8h, v18.8h, v25.8h\n\t"
        "sub	v20.8h, v20.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v18.8h, v18.8h, #1\n\t"
        "sshr	v20.8h, v20.8h, #1\n\t"
        "ldr	q0, [x2, #224]\n\t"
        "ldr	q1, [x2, #240]\n\t"
        "ldr	q2, [x3, #224]\n\t"
        "ldr	q3, [x3, #240]\n\t"
        "sub	v26.8h, v21.8h, v22.8h\n\t"
        "sub	v28.8h, v23.8h, v24.8h\n\t"
        "add	v21.8h, v21.8h, v22.8h\n\t"
        "add	v23.8h, v23.8h, v24.8h\n\t"
        "mul	v25.8h, v26.8h, v2.8h\n\t"
        "mul	v27.8h, v28.8h, v3.8h\n\t"
        "sqrdmulh	v22.8h, v26.8h, v0.8h\n\t"
        "sqrdmulh	v24.8h, v28.8h, v1.8h\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v22.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v24.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v22.8h, v22.8h, v25.8h\n\t"
        "sub	v24.8h, v24.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v22.8h, v22.8h, #1\n\t"
        "sshr	v24.8h, v24.8h, #1\n\t"
        "ldr	q0, [x2, #384]\n\t"
        "ldr	q1, [x2, #400]\n\t"
        "ldr	q2, [x3, #384]\n\t"
        "ldr	q3, [x3, #400]\n\t"
        "mov	v25.16b, v9.16b\n\t"
        "mov	v26.16b, v11.16b\n\t"
        "trn1	v9.4s, v9.4s, v10.4s\n\t"
        "trn1	v11.4s, v11.4s, v12.4s\n\t"
        "trn2	v10.4s, v25.4s, v10.4s\n\t"
        "trn2	v12.4s, v26.4s, v12.4s\n\t"
        "sub	v26.8h, v9.8h, v10.8h\n\t"
        "sub	v28.8h, v11.8h, v12.8h\n\t"
        "add	v9.8h, v9.8h, v10.8h\n\t"
        "add	v11.8h, v11.8h, v12.8h\n\t"
        "mul	v25.8h, v26.8h, v2.8h\n\t"
        "mul	v27.8h, v28.8h, v3.8h\n\t"
        "sqrdmulh	v10.8h, v26.8h, v0.8h\n\t"
        "sqrdmulh	v12.8h, v28.8h, v1.8h\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v10.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v12.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v10.8h, v10.8h, v25.8h\n\t"
        "sub	v12.8h, v12.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v10.8h, v10.8h, #1\n\t"
        "sshr	v12.8h, v12.8h, #1\n\t"
        "ldr	q0, [x2, #416]\n\t"
        "ldr	q1, [x2, #432]\n\t"
        "ldr	q2, [x3, #416]\n\t"
        "ldr	q3, [x3, #432]\n\t"
        "mov	v25.16b, v13.16b\n\t"
        "mov	v26.16b, v15.16b\n\t"
        "trn1	v13.4s, v13.4s, v14.4s\n\t"
        "trn1	v15.4s, v15.4s, v16.4s\n\t"
        "trn2	v14.4s, v25.4s, v14.4s\n\t"
        "trn2	v16.4s, v26.4s, v16.4s\n\t"
        "sub	v26.8h, v13.8h, v14.8h\n\t"
        "sub	v28.8h, v15.8h, v16.8h\n\t"
        "add	v13.8h, v13.8h, v14.8h\n\t"
        "add	v15.8h, v15.8h, v16.8h\n\t"
        "mul	v25.8h, v26.8h, v2.8h\n\t"
        "mul	v27.8h, v28.8h, v3.8h\n\t"
        "sqrdmulh	v14.8h, v26.8h, v0.8h\n\t"
        "sqrdmulh	v16.8h, v28.8h, v1.8h\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v14.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v16.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v14.8h, v14.8h, v25.8h\n\t"
        "sub	v16.8h, v16.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v14.8h, v14.8h, #1\n\t"
        "sshr	v16.8h, v16.8h, #1\n\t"
        "ldr	q0, [x2, #448]\n\t"
        "ldr	q1, [x2, #464]\n\t"
        "ldr	q2, [x3, #448]\n\t"
        "ldr	q3, [x3, #464]\n\t"
        "mov	v25.16b, v17.16b\n\t"
        "mov	v26.16b, v19.16b\n\t"
        "trn1	v17.4s, v17.4s, v18.4s\n\t"
        "trn1	v19.4s, v19.4s, v20.4s\n\t"
        "trn2	v18.4s, v25.4s, v18.4s\n\t"
        "trn2	v20.4s, v26.4s, v20.4s\n\t"
        "sub	v26.8h, v17.8h, v18.8h\n\t"
        "sub	v28.8h, v19.8h, v20.8h\n\t"
        "add	v17.8h, v17.8h, v18.8h\n\t"
        "add	v19.8h, v19.8h, v20.8h\n\t"
        "mul	v25.8h, v26.8h, v2.8h\n\t"
        "mul	v27.8h, v28.8h, v3.8h\n\t"
        "sqrdmulh	v18.8h, v26.8h, v0.8h\n\t"
        "sqrdmulh	v20.8h, v28.8h, v1.8h\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v18.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v20.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v18.8h, v18.8h, v25.8h\n\t"
        "sub	v20.8h, v20.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v18.8h, v18.8h, #1\n\t"
        "sshr	v20.8h, v20.8h, #1\n\t"
        "ldr	q0, [x2, #480]\n\t"
        "ldr	q1, [x2, #496]\n\t"
        "ldr	q2, [x3, #480]\n\t"
        "ldr	q3, [x3, #496]\n\t"
        "mov	v25.16b, v21.16b\n\t"
        "mov	v26.16b, v23.16b\n\t"
        "trn1	v21.4s, v21.4s, v22.4s\n\t"
        "trn1	v23.4s, v23.4s, v24.4s\n\t"
        "trn2	v22.4s, v25.4s, v22.4s\n\t"
        "trn2	v24.4s, v26.4s, v24.4s\n\t"
        "sub	v26.8h, v21.8h, v22.8h\n\t"
        "sub	v28.8h, v23.8h, v24.8h\n\t"
        "add	v21.8h, v21.8h, v22.8h\n\t"
        "add	v23.8h, v23.8h, v24.8h\n\t"
        "mul	v25.8h, v26.8h, v2.8h\n\t"
        "mul	v27.8h, v28.8h, v3.8h\n\t"
        "sqrdmulh	v22.8h, v26.8h, v0.8h\n\t"
        "sqrdmulh	v24.8h, v28.8h, v1.8h\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v22.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v24.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v22.8h, v22.8h, v25.8h\n\t"
        "sub	v24.8h, v24.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v22.8h, v22.8h, #1\n\t"
        "sshr	v24.8h, v24.8h, #1\n\t"
        "ldr	q0, [x2, #528]\n\t"
        "ldr	q2, [x3, #528]\n\t"
        "mov	v25.16b, v9.16b\n\t"
        "mov	v26.16b, v11.16b\n\t"
        "trn1	v9.2d, v9.2d, v10.2d\n\t"
        "trn1	v11.2d, v11.2d, v12.2d\n\t"
        "trn2	v10.2d, v25.2d, v10.2d\n\t"
        "trn2	v12.2d, v26.2d, v12.2d\n\t"
        "sub	v26.8h, v9.8h, v10.8h\n\t"
        "sub	v28.8h, v11.8h, v12.8h\n\t"
        "add	v9.8h, v9.8h, v10.8h\n\t"
        "add	v11.8h, v11.8h, v12.8h\n\t"
        "mul	v25.8h, v26.8h, v2.h[0]\n\t"
        "mul	v27.8h, v28.8h, v2.h[1]\n\t"
        "sqrdmulh	v10.8h, v26.8h, v0.h[0]\n\t"
        "sqrdmulh	v12.8h, v28.8h, v0.h[1]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v10.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v12.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v10.8h, v10.8h, v25.8h\n\t"
        "sub	v12.8h, v12.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v10.8h, v10.8h, #1\n\t"
        "sshr	v12.8h, v12.8h, #1\n\t"
        "mov	v25.16b, v13.16b\n\t"
        "mov	v26.16b, v15.16b\n\t"
        "trn1	v13.2d, v13.2d, v14.2d\n\t"
        "trn1	v15.2d, v15.2d, v16.2d\n\t"
        "trn2	v14.2d, v25.2d, v14.2d\n\t"
        "trn2	v16.2d, v26.2d, v16.2d\n\t"
        "sub	v26.8h, v13.8h, v14.8h\n\t"
        "sub	v28.8h, v15.8h, v16.8h\n\t"
        "add	v13.8h, v13.8h, v14.8h\n\t"
        "add	v15.8h, v15.8h, v16.8h\n\t"
        "mul	v25.8h, v26.8h, v2.h[2]\n\t"
        "mul	v27.8h, v28.8h, v2.h[3]\n\t"
        "sqrdmulh	v14.8h, v26.8h, v0.h[2]\n\t"
        "sqrdmulh	v16.8h, v28.8h, v0.h[3]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v14.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v16.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v14.8h, v14.8h, v25.8h\n\t"
        "sub	v16.8h, v16.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v14.8h, v14.8h, #1\n\t"
        "sshr	v16.8h, v16.8h, #1\n\t"
        "mov	v25.16b, v17.16b\n\t"
        "mov	v26.16b, v19.16b\n\t"
        "trn1	v17.2d, v17.2d, v18.2d\n\t"
        "trn1	v19.2d, v19.2d, v20.2d\n\t"
        "trn2	v18.2d, v25.2d, v18.2d\n\t"
        "trn2	v20.2d, v26.2d, v20.2d\n\t"
        "sub	v26.8h, v17.8h, v18.8h\n\t"
        "sub	v28.8h, v19.8h, v20.8h\n\t"
        "add	v17.8h, v17.8h, v18.8h\n\t"
        "add	v19.8h, v19.8h, v20.8h\n\t"
        "mul	v25.8h, v26.8h, v2.h[4]\n\t"
        "mul	v27.8h, v28.8h, v2.h[5]\n\t"
        "sqrdmulh	v18.8h, v26.8h, v0.h[4]\n\t"
        "sqrdmulh	v20.8h, v28.8h, v0.h[5]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v18.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v20.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v18.8h, v18.8h, v25.8h\n\t"
        "sub	v20.8h, v20.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v18.8h, v18.8h, #1\n\t"
        "sshr	v20.8h, v20.8h, #1\n\t"
        "mov	v25.16b, v21.16b\n\t"
        "mov	v26.16b, v23.16b\n\t"
        "trn1	v21.2d, v21.2d, v22.2d\n\t"
        "trn1	v23.2d, v23.2d, v24.2d\n\t"
        "trn2	v22.2d, v25.2d, v22.2d\n\t"
        "trn2	v24.2d, v26.2d, v24.2d\n\t"
        "sub	v26.8h, v21.8h, v22.8h\n\t"
        "sub	v28.8h, v23.8h, v24.8h\n\t"
        "add	v21.8h, v21.8h, v22.8h\n\t"
        "add	v23.8h, v23.8h, v24.8h\n\t"
        "mul	v25.8h, v26.8h, v2.h[6]\n\t"
        "mul	v27.8h, v28.8h, v2.h[7]\n\t"
        "sqrdmulh	v22.8h, v26.8h, v0.h[6]\n\t"
        "sqrdmulh	v24.8h, v28.8h, v0.h[7]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v22.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v24.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v22.8h, v22.8h, v25.8h\n\t"
        "sub	v24.8h, v24.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v22.8h, v22.8h, #1\n\t"
        "sshr	v24.8h, v24.8h, #1\n\t"
        "sqdmulh	v25.8h, v9.8h, v8.h[2]\n\t"
        "sqdmulh	v26.8h, v11.8h, v8.h[2]\n\t"
        "sshr	v25.8h, v25.8h, #11\n\t"
        "sshr	v26.8h, v26.8h, #11\n\t"
        "mls	v9.8h, v25.8h, v8.h[0]\n\t"
        "mls	v11.8h, v26.8h, v8.h[0]\n\t"
        "sqdmulh	v25.8h, v13.8h, v8.h[2]\n\t"
        "sqdmulh	v26.8h, v15.8h, v8.h[2]\n\t"
        "sshr	v25.8h, v25.8h, #11\n\t"
        "sshr	v26.8h, v26.8h, #11\n\t"
        "mls	v13.8h, v25.8h, v8.h[0]\n\t"
        "mls	v15.8h, v26.8h, v8.h[0]\n\t"
        "sqdmulh	v25.8h, v17.8h, v8.h[2]\n\t"
        "sqdmulh	v26.8h, v19.8h, v8.h[2]\n\t"
        "sshr	v25.8h, v25.8h, #11\n\t"
        "sshr	v26.8h, v26.8h, #11\n\t"
        "mls	v17.8h, v25.8h, v8.h[0]\n\t"
        "mls	v19.8h, v26.8h, v8.h[0]\n\t"
        "sqdmulh	v25.8h, v21.8h, v8.h[2]\n\t"
        "sqdmulh	v26.8h, v23.8h, v8.h[2]\n\t"
        "sshr	v25.8h, v25.8h, #11\n\t"
        "sshr	v26.8h, v26.8h, #11\n\t"
        "mls	v21.8h, v25.8h, v8.h[0]\n\t"
        "mls	v23.8h, v26.8h, v8.h[0]\n\t"
        "stp	q9, q10, [x1]\n\t"
        "stp	q11, q12, [x1, #32]\n\t"
        "stp	q13, q14, [x1, #64]\n\t"
        "stp	q15, q16, [x1, #96]\n\t"
        "stp	q17, q18, [x1, #128]\n\t"
        "stp	q19, q20, [x1, #160]\n\t"
        "stp	q21, q22, [x1, #192]\n\t"
        "stp	q23, q24, [x1, #224]\n\t"
        "ldr	q4, [x2, #544]\n\t"
        "ldr	q5, [x2, #560]\n\t"
        "ldr	q6, [x3, #544]\n\t"
        "ldr	q7, [x3, #560]\n\t"
        "ldr	q9, [%x[r]]\n\t"
        "ldr	q10, [%x[r], #32]\n\t"
        "ldr	q11, [%x[r], #64]\n\t"
        "ldr	q12, [%x[r], #96]\n\t"
        "ldr	q13, [%x[r], #128]\n\t"
        "ldr	q14, [%x[r], #160]\n\t"
        "ldr	q15, [%x[r], #192]\n\t"
        "ldr	q16, [%x[r], #224]\n\t"
        "ldr	q17, [x1]\n\t"
        "ldr	q18, [x1, #32]\n\t"
        "ldr	q19, [x1, #64]\n\t"
        "ldr	q20, [x1, #96]\n\t"
        "ldr	q21, [x1, #128]\n\t"
        "ldr	q22, [x1, #160]\n\t"
        "ldr	q23, [x1, #192]\n\t"
        "ldr	q24, [x1, #224]\n\t"
        "sub	v26.8h, v9.8h, v10.8h\n\t"
        "sub	v28.8h, v11.8h, v12.8h\n\t"
        "add	v9.8h, v9.8h, v10.8h\n\t"
        "add	v11.8h, v11.8h, v12.8h\n\t"
        "mul	v25.8h, v26.8h, v6.h[0]\n\t"
        "mul	v27.8h, v28.8h, v6.h[1]\n\t"
        "sqrdmulh	v10.8h, v26.8h, v4.h[0]\n\t"
        "sqrdmulh	v12.8h, v28.8h, v4.h[1]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v10.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v12.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v10.8h, v10.8h, v25.8h\n\t"
        "sub	v12.8h, v12.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v10.8h, v10.8h, #1\n\t"
        "sshr	v12.8h, v12.8h, #1\n\t"
        "sub	v26.8h, v13.8h, v14.8h\n\t"
        "sub	v28.8h, v15.8h, v16.8h\n\t"
        "add	v13.8h, v13.8h, v14.8h\n\t"
        "add	v15.8h, v15.8h, v16.8h\n\t"
        "mul	v25.8h, v26.8h, v6.h[2]\n\t"
        "mul	v27.8h, v28.8h, v6.h[3]\n\t"
        "sqrdmulh	v14.8h, v26.8h, v4.h[2]\n\t"
        "sqrdmulh	v16.8h, v28.8h, v4.h[3]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v14.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v16.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v14.8h, v14.8h, v25.8h\n\t"
        "sub	v16.8h, v16.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v14.8h, v14.8h, #1\n\t"
        "sshr	v16.8h, v16.8h, #1\n\t"
        "sub	v26.8h, v17.8h, v18.8h\n\t"
        "sub	v28.8h, v19.8h, v20.8h\n\t"
        "add	v17.8h, v17.8h, v18.8h\n\t"
        "add	v19.8h, v19.8h, v20.8h\n\t"
        "mul	v25.8h, v26.8h, v6.h[4]\n\t"
        "mul	v27.8h, v28.8h, v6.h[5]\n\t"
        "sqrdmulh	v18.8h, v26.8h, v4.h[4]\n\t"
        "sqrdmulh	v20.8h, v28.8h, v4.h[5]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v18.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v20.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v18.8h, v18.8h, v25.8h\n\t"
        "sub	v20.8h, v20.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v18.8h, v18.8h, #1\n\t"
        "sshr	v20.8h, v20.8h, #1\n\t"
        "sub	v26.8h, v21.8h, v22.8h\n\t"
        "sub	v28.8h, v23.8h, v24.8h\n\t"
        "add	v21.8h, v21.8h, v22.8h\n\t"
        "add	v23.8h, v23.8h, v24.8h\n\t"
        "mul	v25.8h, v26.8h, v6.h[6]\n\t"
        "mul	v27.8h, v28.8h, v6.h[7]\n\t"
        "sqrdmulh	v22.8h, v26.8h, v4.h[6]\n\t"
        "sqrdmulh	v24.8h, v28.8h, v4.h[7]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v22.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v24.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v22.8h, v22.8h, v25.8h\n\t"
        "sub	v24.8h, v24.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v22.8h, v22.8h, #1\n\t"
        "sshr	v24.8h, v24.8h, #1\n\t"
        "sub	v26.8h, v9.8h, v11.8h\n\t"
        "sub	v28.8h, v10.8h, v12.8h\n\t"
        "add	v9.8h, v9.8h, v11.8h\n\t"
        "add	v10.8h, v10.8h, v12.8h\n\t"
        "mul	v25.8h, v26.8h, v7.h[0]\n\t"
        "mul	v27.8h, v28.8h, v7.h[0]\n\t"
        "sqrdmulh	v11.8h, v26.8h, v5.h[0]\n\t"
        "sqrdmulh	v12.8h, v28.8h, v5.h[0]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v11.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v12.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v11.8h, v11.8h, v25.8h\n\t"
        "sub	v12.8h, v12.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v11.8h, v11.8h, #1\n\t"
        "sshr	v12.8h, v12.8h, #1\n\t"
        "sub	v26.8h, v13.8h, v15.8h\n\t"
        "sub	v28.8h, v14.8h, v16.8h\n\t"
        "add	v13.8h, v13.8h, v15.8h\n\t"
        "add	v14.8h, v14.8h, v16.8h\n\t"
        "mul	v25.8h, v26.8h, v7.h[1]\n\t"
        "mul	v27.8h, v28.8h, v7.h[1]\n\t"
        "sqrdmulh	v15.8h, v26.8h, v5.h[1]\n\t"
        "sqrdmulh	v16.8h, v28.8h, v5.h[1]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v15.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v16.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v15.8h, v15.8h, v25.8h\n\t"
        "sub	v16.8h, v16.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v15.8h, v15.8h, #1\n\t"
        "sshr	v16.8h, v16.8h, #1\n\t"
        "sub	v26.8h, v17.8h, v19.8h\n\t"
        "sub	v28.8h, v18.8h, v20.8h\n\t"
        "add	v17.8h, v17.8h, v19.8h\n\t"
        "add	v18.8h, v18.8h, v20.8h\n\t"
        "mul	v25.8h, v26.8h, v7.h[2]\n\t"
        "mul	v27.8h, v28.8h, v7.h[2]\n\t"
        "sqrdmulh	v19.8h, v26.8h, v5.h[2]\n\t"
        "sqrdmulh	v20.8h, v28.8h, v5.h[2]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v19.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v20.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v19.8h, v19.8h, v25.8h\n\t"
        "sub	v20.8h, v20.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v19.8h, v19.8h, #1\n\t"
        "sshr	v20.8h, v20.8h, #1\n\t"
        "sub	v26.8h, v21.8h, v23.8h\n\t"
        "sub	v28.8h, v22.8h, v24.8h\n\t"
        "add	v21.8h, v21.8h, v23.8h\n\t"
        "add	v22.8h, v22.8h, v24.8h\n\t"
        "mul	v25.8h, v26.8h, v7.h[3]\n\t"
        "mul	v27.8h, v28.8h, v7.h[3]\n\t"
        "sqrdmulh	v23.8h, v26.8h, v5.h[3]\n\t"
        "sqrdmulh	v24.8h, v28.8h, v5.h[3]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v23.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v24.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v23.8h, v23.8h, v25.8h\n\t"
        "sub	v24.8h, v24.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v23.8h, v23.8h, #1\n\t"
        "sshr	v24.8h, v24.8h, #1\n\t"
        "sub	v26.8h, v9.8h, v13.8h\n\t"
        "sub	v28.8h, v10.8h, v14.8h\n\t"
        "add	v9.8h, v9.8h, v13.8h\n\t"
        "add	v10.8h, v10.8h, v14.8h\n\t"
        "mul	v25.8h, v26.8h, v7.h[4]\n\t"
        "mul	v27.8h, v28.8h, v7.h[4]\n\t"
        "sqrdmulh	v13.8h, v26.8h, v5.h[4]\n\t"
        "sqrdmulh	v14.8h, v28.8h, v5.h[4]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v13.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v14.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v13.8h, v13.8h, v25.8h\n\t"
        "sub	v14.8h, v14.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v13.8h, v13.8h, #1\n\t"
        "sshr	v14.8h, v14.8h, #1\n\t"
        "sub	v26.8h, v11.8h, v15.8h\n\t"
        "sub	v28.8h, v12.8h, v16.8h\n\t"
        "add	v11.8h, v11.8h, v15.8h\n\t"
        "add	v12.8h, v12.8h, v16.8h\n\t"
        "mul	v25.8h, v26.8h, v7.h[4]\n\t"
        "mul	v27.8h, v28.8h, v7.h[4]\n\t"
        "sqrdmulh	v15.8h, v26.8h, v5.h[4]\n\t"
        "sqrdmulh	v16.8h, v28.8h, v5.h[4]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v15.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v16.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v15.8h, v15.8h, v25.8h\n\t"
        "sub	v16.8h, v16.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v15.8h, v15.8h, #1\n\t"
        "sshr	v16.8h, v16.8h, #1\n\t"
        "sub	v26.8h, v17.8h, v21.8h\n\t"
        "sub	v28.8h, v18.8h, v22.8h\n\t"
        "add	v17.8h, v17.8h, v21.8h\n\t"
        "add	v18.8h, v18.8h, v22.8h\n\t"
        "mul	v25.8h, v26.8h, v7.h[5]\n\t"
        "mul	v27.8h, v28.8h, v7.h[5]\n\t"
        "sqrdmulh	v21.8h, v26.8h, v5.h[5]\n\t"
        "sqrdmulh	v22.8h, v28.8h, v5.h[5]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v21.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v22.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v21.8h, v21.8h, v25.8h\n\t"
        "sub	v22.8h, v22.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v21.8h, v21.8h, #1\n\t"
        "sshr	v22.8h, v22.8h, #1\n\t"
        "sub	v26.8h, v19.8h, v23.8h\n\t"
        "sub	v28.8h, v20.8h, v24.8h\n\t"
        "add	v19.8h, v19.8h, v23.8h\n\t"
        "add	v20.8h, v20.8h, v24.8h\n\t"
        "mul	v25.8h, v26.8h, v7.h[5]\n\t"
        "mul	v27.8h, v28.8h, v7.h[5]\n\t"
        "sqrdmulh	v23.8h, v26.8h, v5.h[5]\n\t"
        "sqrdmulh	v24.8h, v28.8h, v5.h[5]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v23.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v24.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v23.8h, v23.8h, v25.8h\n\t"
        "sub	v24.8h, v24.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v23.8h, v23.8h, #1\n\t"
        "sshr	v24.8h, v24.8h, #1\n\t"
        "sqdmulh	v25.8h, v9.8h, v8.h[2]\n\t"
        "sqdmulh	v26.8h, v10.8h, v8.h[2]\n\t"
        "sshr	v25.8h, v25.8h, #11\n\t"
        "sshr	v26.8h, v26.8h, #11\n\t"
        "mls	v9.8h, v25.8h, v8.h[0]\n\t"
        "mls	v10.8h, v26.8h, v8.h[0]\n\t"
        "sqdmulh	v25.8h, v11.8h, v8.h[2]\n\t"
        "sqdmulh	v26.8h, v12.8h, v8.h[2]\n\t"
        "sshr	v25.8h, v25.8h, #11\n\t"
        "sshr	v26.8h, v26.8h, #11\n\t"
        "mls	v11.8h, v25.8h, v8.h[0]\n\t"
        "mls	v12.8h, v26.8h, v8.h[0]\n\t"
        "sqdmulh	v25.8h, v17.8h, v8.h[2]\n\t"
        "sqdmulh	v26.8h, v18.8h, v8.h[2]\n\t"
        "sshr	v25.8h, v25.8h, #11\n\t"
        "sshr	v26.8h, v26.8h, #11\n\t"
        "mls	v17.8h, v25.8h, v8.h[0]\n\t"
        "mls	v18.8h, v26.8h, v8.h[0]\n\t"
        "sqdmulh	v25.8h, v19.8h, v8.h[2]\n\t"
        "sqdmulh	v26.8h, v20.8h, v8.h[2]\n\t"
        "sshr	v25.8h, v25.8h, #11\n\t"
        "sshr	v26.8h, v26.8h, #11\n\t"
        "mls	v19.8h, v25.8h, v8.h[0]\n\t"
        "mls	v20.8h, v26.8h, v8.h[0]\n\t"
        "sub	v26.8h, v9.8h, v17.8h\n\t"
        "sub	v28.8h, v10.8h, v18.8h\n\t"
        "add	v9.8h, v9.8h, v17.8h\n\t"
        "add	v10.8h, v10.8h, v18.8h\n\t"
        "mul	v25.8h, v26.8h, v7.h[6]\n\t"
        "mul	v27.8h, v28.8h, v7.h[6]\n\t"
        "sqrdmulh	v17.8h, v26.8h, v5.h[6]\n\t"
        "sqrdmulh	v18.8h, v28.8h, v5.h[6]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v17.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v18.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v17.8h, v17.8h, v25.8h\n\t"
        "sub	v18.8h, v18.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v17.8h, v17.8h, #1\n\t"
        "sshr	v18.8h, v18.8h, #1\n\t"
        "sub	v26.8h, v11.8h, v19.8h\n\t"
        "sub	v28.8h, v12.8h, v20.8h\n\t"
        "add	v11.8h, v11.8h, v19.8h\n\t"
        "add	v12.8h, v12.8h, v20.8h\n\t"
        "mul	v25.8h, v26.8h, v7.h[6]\n\t"
        "mul	v27.8h, v28.8h, v7.h[6]\n\t"
        "sqrdmulh	v19.8h, v26.8h, v5.h[6]\n\t"
        "sqrdmulh	v20.8h, v28.8h, v5.h[6]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v19.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v20.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v19.8h, v19.8h, v25.8h\n\t"
        "sub	v20.8h, v20.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v19.8h, v19.8h, #1\n\t"
        "sshr	v20.8h, v20.8h, #1\n\t"
        "sub	v26.8h, v13.8h, v21.8h\n\t"
        "sub	v28.8h, v14.8h, v22.8h\n\t"
        "add	v13.8h, v13.8h, v21.8h\n\t"
        "add	v14.8h, v14.8h, v22.8h\n\t"
        "mul	v25.8h, v26.8h, v7.h[6]\n\t"
        "mul	v27.8h, v28.8h, v7.h[6]\n\t"
        "sqrdmulh	v21.8h, v26.8h, v5.h[6]\n\t"
        "sqrdmulh	v22.8h, v28.8h, v5.h[6]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v21.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v22.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v21.8h, v21.8h, v25.8h\n\t"
        "sub	v22.8h, v22.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v21.8h, v21.8h, #1\n\t"
        "sshr	v22.8h, v22.8h, #1\n\t"
        "sub	v26.8h, v15.8h, v23.8h\n\t"
        "sub	v28.8h, v16.8h, v24.8h\n\t"
        "add	v15.8h, v15.8h, v23.8h\n\t"
        "add	v16.8h, v16.8h, v24.8h\n\t"
        "mul	v25.8h, v26.8h, v7.h[6]\n\t"
        "mul	v27.8h, v28.8h, v7.h[6]\n\t"
        "sqrdmulh	v23.8h, v26.8h, v5.h[6]\n\t"
        "sqrdmulh	v24.8h, v28.8h, v5.h[6]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v23.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v24.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v23.8h, v23.8h, v25.8h\n\t"
        "sub	v24.8h, v24.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v23.8h, v23.8h, #1\n\t"
        "sshr	v24.8h, v24.8h, #1\n\t"
        "mul	v25.8h, v9.8h, v7.h[7]\n\t"
        "mul	v26.8h, v10.8h, v7.h[7]\n\t"
        "sqrdmulh	v9.8h, v9.8h, v5.h[7]\n\t"
        "sqrdmulh	v10.8h, v10.8h, v5.h[7]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v9.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v10.8h, v26.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v26.8h, v26.8h, v8.h[0]\n\t"
        "sub	v9.8h, v9.8h, v25.8h\n\t"
        "sub	v10.8h, v10.8h, v26.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v9.8h, v9.8h, #1\n\t"
        "sshr	v10.8h, v10.8h, #1\n\t"
        "mul	v25.8h, v11.8h, v7.h[7]\n\t"
        "mul	v26.8h, v12.8h, v7.h[7]\n\t"
        "sqrdmulh	v11.8h, v11.8h, v5.h[7]\n\t"
        "sqrdmulh	v12.8h, v12.8h, v5.h[7]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v11.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v12.8h, v26.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v26.8h, v26.8h, v8.h[0]\n\t"
        "sub	v11.8h, v11.8h, v25.8h\n\t"
        "sub	v12.8h, v12.8h, v26.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v11.8h, v11.8h, #1\n\t"
        "sshr	v12.8h, v12.8h, #1\n\t"
        "mul	v25.8h, v13.8h, v7.h[7]\n\t"
        "mul	v26.8h, v14.8h, v7.h[7]\n\t"
        "sqrdmulh	v13.8h, v13.8h, v5.h[7]\n\t"
        "sqrdmulh	v14.8h, v14.8h, v5.h[7]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v13.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v14.8h, v26.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v26.8h, v26.8h, v8.h[0]\n\t"
        "sub	v13.8h, v13.8h, v25.8h\n\t"
        "sub	v14.8h, v14.8h, v26.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v13.8h, v13.8h, #1\n\t"
        "sshr	v14.8h, v14.8h, #1\n\t"
        "mul	v25.8h, v15.8h, v7.h[7]\n\t"
        "mul	v26.8h, v16.8h, v7.h[7]\n\t"
        "sqrdmulh	v15.8h, v15.8h, v5.h[7]\n\t"
        "sqrdmulh	v16.8h, v16.8h, v5.h[7]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v15.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v16.8h, v26.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v26.8h, v26.8h, v8.h[0]\n\t"
        "sub	v15.8h, v15.8h, v25.8h\n\t"
        "sub	v16.8h, v16.8h, v26.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v15.8h, v15.8h, #1\n\t"
        "sshr	v16.8h, v16.8h, #1\n\t"
        "mul	v25.8h, v17.8h, v7.h[7]\n\t"
        "mul	v26.8h, v18.8h, v7.h[7]\n\t"
        "sqrdmulh	v17.8h, v17.8h, v5.h[7]\n\t"
        "sqrdmulh	v18.8h, v18.8h, v5.h[7]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v17.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v18.8h, v26.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v26.8h, v26.8h, v8.h[0]\n\t"
        "sub	v17.8h, v17.8h, v25.8h\n\t"
        "sub	v18.8h, v18.8h, v26.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v17.8h, v17.8h, #1\n\t"
        "sshr	v18.8h, v18.8h, #1\n\t"
        "mul	v25.8h, v19.8h, v7.h[7]\n\t"
        "mul	v26.8h, v20.8h, v7.h[7]\n\t"
        "sqrdmulh	v19.8h, v19.8h, v5.h[7]\n\t"
        "sqrdmulh	v20.8h, v20.8h, v5.h[7]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v19.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v20.8h, v26.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v26.8h, v26.8h, v8.h[0]\n\t"
        "sub	v19.8h, v19.8h, v25.8h\n\t"
        "sub	v20.8h, v20.8h, v26.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v19.8h, v19.8h, #1\n\t"
        "sshr	v20.8h, v20.8h, #1\n\t"
        "mul	v25.8h, v21.8h, v7.h[7]\n\t"
        "mul	v26.8h, v22.8h, v7.h[7]\n\t"
        "sqrdmulh	v21.8h, v21.8h, v5.h[7]\n\t"
        "sqrdmulh	v22.8h, v22.8h, v5.h[7]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v21.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v22.8h, v26.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v26.8h, v26.8h, v8.h[0]\n\t"
        "sub	v21.8h, v21.8h, v25.8h\n\t"
        "sub	v22.8h, v22.8h, v26.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v21.8h, v21.8h, #1\n\t"
        "sshr	v22.8h, v22.8h, #1\n\t"
        "mul	v25.8h, v23.8h, v7.h[7]\n\t"
        "mul	v26.8h, v24.8h, v7.h[7]\n\t"
        "sqrdmulh	v23.8h, v23.8h, v5.h[7]\n\t"
        "sqrdmulh	v24.8h, v24.8h, v5.h[7]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v23.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v24.8h, v26.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v26.8h, v26.8h, v8.h[0]\n\t"
        "sub	v23.8h, v23.8h, v25.8h\n\t"
        "sub	v24.8h, v24.8h, v26.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v23.8h, v23.8h, #1\n\t"
        "sshr	v24.8h, v24.8h, #1\n\t"
        "str	q9, [%x[r]]\n\t"
        "str	q10, [%x[r], #32]\n\t"
        "str	q11, [%x[r], #64]\n\t"
        "str	q12, [%x[r], #96]\n\t"
        "str	q13, [%x[r], #128]\n\t"
        "str	q14, [%x[r], #160]\n\t"
        "str	q15, [%x[r], #192]\n\t"
        "str	q16, [%x[r], #224]\n\t"
        "str	q17, [x1]\n\t"
        "str	q18, [x1, #32]\n\t"
        "str	q19, [x1, #64]\n\t"
        "str	q20, [x1, #96]\n\t"
        "str	q21, [x1, #128]\n\t"
        "str	q22, [x1, #160]\n\t"
        "str	q23, [x1, #192]\n\t"
        "str	q24, [x1, #224]\n\t"
        "ldr	q9, [%x[r], #16]\n\t"
        "ldr	q10, [%x[r], #48]\n\t"
        "ldr	q11, [%x[r], #80]\n\t"
        "ldr	q12, [%x[r], #112]\n\t"
        "ldr	q13, [%x[r], #144]\n\t"
        "ldr	q14, [%x[r], #176]\n\t"
        "ldr	q15, [%x[r], #208]\n\t"
        "ldr	q16, [%x[r], #240]\n\t"
        "ldr	q17, [x1, #16]\n\t"
        "ldr	q18, [x1, #48]\n\t"
        "ldr	q19, [x1, #80]\n\t"
        "ldr	q20, [x1, #112]\n\t"
        "ldr	q21, [x1, #144]\n\t"
        "ldr	q22, [x1, #176]\n\t"
        "ldr	q23, [x1, #208]\n\t"
        "ldr	q24, [x1, #240]\n\t"
        "sub	v26.8h, v9.8h, v10.8h\n\t"
        "sub	v28.8h, v11.8h, v12.8h\n\t"
        "add	v9.8h, v9.8h, v10.8h\n\t"
        "add	v11.8h, v11.8h, v12.8h\n\t"
        "mul	v25.8h, v26.8h, v6.h[0]\n\t"
        "mul	v27.8h, v28.8h, v6.h[1]\n\t"
        "sqrdmulh	v10.8h, v26.8h, v4.h[0]\n\t"
        "sqrdmulh	v12.8h, v28.8h, v4.h[1]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v10.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v12.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v10.8h, v10.8h, v25.8h\n\t"
        "sub	v12.8h, v12.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v10.8h, v10.8h, #1\n\t"
        "sshr	v12.8h, v12.8h, #1\n\t"
        "sub	v26.8h, v13.8h, v14.8h\n\t"
        "sub	v28.8h, v15.8h, v16.8h\n\t"
        "add	v13.8h, v13.8h, v14.8h\n\t"
        "add	v15.8h, v15.8h, v16.8h\n\t"
        "mul	v25.8h, v26.8h, v6.h[2]\n\t"
        "mul	v27.8h, v28.8h, v6.h[3]\n\t"
        "sqrdmulh	v14.8h, v26.8h, v4.h[2]\n\t"
        "sqrdmulh	v16.8h, v28.8h, v4.h[3]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v14.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v16.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v14.8h, v14.8h, v25.8h\n\t"
        "sub	v16.8h, v16.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v14.8h, v14.8h, #1\n\t"
        "sshr	v16.8h, v16.8h, #1\n\t"
        "sub	v26.8h, v17.8h, v18.8h\n\t"
        "sub	v28.8h, v19.8h, v20.8h\n\t"
        "add	v17.8h, v17.8h, v18.8h\n\t"
        "add	v19.8h, v19.8h, v20.8h\n\t"
        "mul	v25.8h, v26.8h, v6.h[4]\n\t"
        "mul	v27.8h, v28.8h, v6.h[5]\n\t"
        "sqrdmulh	v18.8h, v26.8h, v4.h[4]\n\t"
        "sqrdmulh	v20.8h, v28.8h, v4.h[5]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v18.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v20.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v18.8h, v18.8h, v25.8h\n\t"
        "sub	v20.8h, v20.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v18.8h, v18.8h, #1\n\t"
        "sshr	v20.8h, v20.8h, #1\n\t"
        "sub	v26.8h, v21.8h, v22.8h\n\t"
        "sub	v28.8h, v23.8h, v24.8h\n\t"
        "add	v21.8h, v21.8h, v22.8h\n\t"
        "add	v23.8h, v23.8h, v24.8h\n\t"
        "mul	v25.8h, v26.8h, v6.h[6]\n\t"
        "mul	v27.8h, v28.8h, v6.h[7]\n\t"
        "sqrdmulh	v22.8h, v26.8h, v4.h[6]\n\t"
        "sqrdmulh	v24.8h, v28.8h, v4.h[7]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v22.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v24.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v22.8h, v22.8h, v25.8h\n\t"
        "sub	v24.8h, v24.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v22.8h, v22.8h, #1\n\t"
        "sshr	v24.8h, v24.8h, #1\n\t"
        "sub	v26.8h, v9.8h, v11.8h\n\t"
        "sub	v28.8h, v10.8h, v12.8h\n\t"
        "add	v9.8h, v9.8h, v11.8h\n\t"
        "add	v10.8h, v10.8h, v12.8h\n\t"
        "mul	v25.8h, v26.8h, v7.h[0]\n\t"
        "mul	v27.8h, v28.8h, v7.h[0]\n\t"
        "sqrdmulh	v11.8h, v26.8h, v5.h[0]\n\t"
        "sqrdmulh	v12.8h, v28.8h, v5.h[0]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v11.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v12.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v11.8h, v11.8h, v25.8h\n\t"
        "sub	v12.8h, v12.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v11.8h, v11.8h, #1\n\t"
        "sshr	v12.8h, v12.8h, #1\n\t"
        "sub	v26.8h, v13.8h, v15.8h\n\t"
        "sub	v28.8h, v14.8h, v16.8h\n\t"
        "add	v13.8h, v13.8h, v15.8h\n\t"
        "add	v14.8h, v14.8h, v16.8h\n\t"
        "mul	v25.8h, v26.8h, v7.h[1]\n\t"
        "mul	v27.8h, v28.8h, v7.h[1]\n\t"
        "sqrdmulh	v15.8h, v26.8h, v5.h[1]\n\t"
        "sqrdmulh	v16.8h, v28.8h, v5.h[1]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v15.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v16.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v15.8h, v15.8h, v25.8h\n\t"
        "sub	v16.8h, v16.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v15.8h, v15.8h, #1\n\t"
        "sshr	v16.8h, v16.8h, #1\n\t"
        "sub	v26.8h, v17.8h, v19.8h\n\t"
        "sub	v28.8h, v18.8h, v20.8h\n\t"
        "add	v17.8h, v17.8h, v19.8h\n\t"
        "add	v18.8h, v18.8h, v20.8h\n\t"
        "mul	v25.8h, v26.8h, v7.h[2]\n\t"
        "mul	v27.8h, v28.8h, v7.h[2]\n\t"
        "sqrdmulh	v19.8h, v26.8h, v5.h[2]\n\t"
        "sqrdmulh	v20.8h, v28.8h, v5.h[2]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v19.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v20.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v19.8h, v19.8h, v25.8h\n\t"
        "sub	v20.8h, v20.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v19.8h, v19.8h, #1\n\t"
        "sshr	v20.8h, v20.8h, #1\n\t"
        "sub	v26.8h, v21.8h, v23.8h\n\t"
        "sub	v28.8h, v22.8h, v24.8h\n\t"
        "add	v21.8h, v21.8h, v23.8h\n\t"
        "add	v22.8h, v22.8h, v24.8h\n\t"
        "mul	v25.8h, v26.8h, v7.h[3]\n\t"
        "mul	v27.8h, v28.8h, v7.h[3]\n\t"
        "sqrdmulh	v23.8h, v26.8h, v5.h[3]\n\t"
        "sqrdmulh	v24.8h, v28.8h, v5.h[3]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v23.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v24.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v23.8h, v23.8h, v25.8h\n\t"
        "sub	v24.8h, v24.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v23.8h, v23.8h, #1\n\t"
        "sshr	v24.8h, v24.8h, #1\n\t"
        "sub	v26.8h, v9.8h, v13.8h\n\t"
        "sub	v28.8h, v10.8h, v14.8h\n\t"
        "add	v9.8h, v9.8h, v13.8h\n\t"
        "add	v10.8h, v10.8h, v14.8h\n\t"
        "mul	v25.8h, v26.8h, v7.h[4]\n\t"
        "mul	v27.8h, v28.8h, v7.h[4]\n\t"
        "sqrdmulh	v13.8h, v26.8h, v5.h[4]\n\t"
        "sqrdmulh	v14.8h, v28.8h, v5.h[4]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v13.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v14.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v13.8h, v13.8h, v25.8h\n\t"
        "sub	v14.8h, v14.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v13.8h, v13.8h, #1\n\t"
        "sshr	v14.8h, v14.8h, #1\n\t"
        "sub	v26.8h, v11.8h, v15.8h\n\t"
        "sub	v28.8h, v12.8h, v16.8h\n\t"
        "add	v11.8h, v11.8h, v15.8h\n\t"
        "add	v12.8h, v12.8h, v16.8h\n\t"
        "mul	v25.8h, v26.8h, v7.h[4]\n\t"
        "mul	v27.8h, v28.8h, v7.h[4]\n\t"
        "sqrdmulh	v15.8h, v26.8h, v5.h[4]\n\t"
        "sqrdmulh	v16.8h, v28.8h, v5.h[4]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v15.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v16.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v15.8h, v15.8h, v25.8h\n\t"
        "sub	v16.8h, v16.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v15.8h, v15.8h, #1\n\t"
        "sshr	v16.8h, v16.8h, #1\n\t"
        "sub	v26.8h, v17.8h, v21.8h\n\t"
        "sub	v28.8h, v18.8h, v22.8h\n\t"
        "add	v17.8h, v17.8h, v21.8h\n\t"
        "add	v18.8h, v18.8h, v22.8h\n\t"
        "mul	v25.8h, v26.8h, v7.h[5]\n\t"
        "mul	v27.8h, v28.8h, v7.h[5]\n\t"
        "sqrdmulh	v21.8h, v26.8h, v5.h[5]\n\t"
        "sqrdmulh	v22.8h, v28.8h, v5.h[5]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v21.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v22.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v21.8h, v21.8h, v25.8h\n\t"
        "sub	v22.8h, v22.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v21.8h, v21.8h, #1\n\t"
        "sshr	v22.8h, v22.8h, #1\n\t"
        "sub	v26.8h, v19.8h, v23.8h\n\t"
        "sub	v28.8h, v20.8h, v24.8h\n\t"
        "add	v19.8h, v19.8h, v23.8h\n\t"
        "add	v20.8h, v20.8h, v24.8h\n\t"
        "mul	v25.8h, v26.8h, v7.h[5]\n\t"
        "mul	v27.8h, v28.8h, v7.h[5]\n\t"
        "sqrdmulh	v23.8h, v26.8h, v5.h[5]\n\t"
        "sqrdmulh	v24.8h, v28.8h, v5.h[5]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v23.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v24.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v23.8h, v23.8h, v25.8h\n\t"
        "sub	v24.8h, v24.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v23.8h, v23.8h, #1\n\t"
        "sshr	v24.8h, v24.8h, #1\n\t"
        "sqdmulh	v25.8h, v9.8h, v8.h[2]\n\t"
        "sqdmulh	v26.8h, v10.8h, v8.h[2]\n\t"
        "sshr	v25.8h, v25.8h, #11\n\t"
        "sshr	v26.8h, v26.8h, #11\n\t"
        "mls	v9.8h, v25.8h, v8.h[0]\n\t"
        "mls	v10.8h, v26.8h, v8.h[0]\n\t"
        "sqdmulh	v25.8h, v11.8h, v8.h[2]\n\t"
        "sqdmulh	v26.8h, v12.8h, v8.h[2]\n\t"
        "sshr	v25.8h, v25.8h, #11\n\t"
        "sshr	v26.8h, v26.8h, #11\n\t"
        "mls	v11.8h, v25.8h, v8.h[0]\n\t"
        "mls	v12.8h, v26.8h, v8.h[0]\n\t"
        "sqdmulh	v25.8h, v17.8h, v8.h[2]\n\t"
        "sqdmulh	v26.8h, v18.8h, v8.h[2]\n\t"
        "sshr	v25.8h, v25.8h, #11\n\t"
        "sshr	v26.8h, v26.8h, #11\n\t"
        "mls	v17.8h, v25.8h, v8.h[0]\n\t"
        "mls	v18.8h, v26.8h, v8.h[0]\n\t"
        "sqdmulh	v25.8h, v19.8h, v8.h[2]\n\t"
        "sqdmulh	v26.8h, v20.8h, v8.h[2]\n\t"
        "sshr	v25.8h, v25.8h, #11\n\t"
        "sshr	v26.8h, v26.8h, #11\n\t"
        "mls	v19.8h, v25.8h, v8.h[0]\n\t"
        "mls	v20.8h, v26.8h, v8.h[0]\n\t"
        "sub	v26.8h, v9.8h, v17.8h\n\t"
        "sub	v28.8h, v10.8h, v18.8h\n\t"
        "add	v9.8h, v9.8h, v17.8h\n\t"
        "add	v10.8h, v10.8h, v18.8h\n\t"
        "mul	v25.8h, v26.8h, v7.h[6]\n\t"
        "mul	v27.8h, v28.8h, v7.h[6]\n\t"
        "sqrdmulh	v17.8h, v26.8h, v5.h[6]\n\t"
        "sqrdmulh	v18.8h, v28.8h, v5.h[6]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v17.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v18.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v17.8h, v17.8h, v25.8h\n\t"
        "sub	v18.8h, v18.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v17.8h, v17.8h, #1\n\t"
        "sshr	v18.8h, v18.8h, #1\n\t"
        "sub	v26.8h, v11.8h, v19.8h\n\t"
        "sub	v28.8h, v12.8h, v20.8h\n\t"
        "add	v11.8h, v11.8h, v19.8h\n\t"
        "add	v12.8h, v12.8h, v20.8h\n\t"
        "mul	v25.8h, v26.8h, v7.h[6]\n\t"
        "mul	v27.8h, v28.8h, v7.h[6]\n\t"
        "sqrdmulh	v19.8h, v26.8h, v5.h[6]\n\t"
        "sqrdmulh	v20.8h, v28.8h, v5.h[6]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v19.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v20.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v19.8h, v19.8h, v25.8h\n\t"
        "sub	v20.8h, v20.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v19.8h, v19.8h, #1\n\t"
        "sshr	v20.8h, v20.8h, #1\n\t"
        "sub	v26.8h, v13.8h, v21.8h\n\t"
        "sub	v28.8h, v14.8h, v22.8h\n\t"
        "add	v13.8h, v13.8h, v21.8h\n\t"
        "add	v14.8h, v14.8h, v22.8h\n\t"
        "mul	v25.8h, v26.8h, v7.h[6]\n\t"
        "mul	v27.8h, v28.8h, v7.h[6]\n\t"
        "sqrdmulh	v21.8h, v26.8h, v5.h[6]\n\t"
        "sqrdmulh	v22.8h, v28.8h, v5.h[6]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v21.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v22.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v21.8h, v21.8h, v25.8h\n\t"
        "sub	v22.8h, v22.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v21.8h, v21.8h, #1\n\t"
        "sshr	v22.8h, v22.8h, #1\n\t"
        "sub	v26.8h, v15.8h, v23.8h\n\t"
        "sub	v28.8h, v16.8h, v24.8h\n\t"
        "add	v15.8h, v15.8h, v23.8h\n\t"
        "add	v16.8h, v16.8h, v24.8h\n\t"
        "mul	v25.8h, v26.8h, v7.h[6]\n\t"
        "mul	v27.8h, v28.8h, v7.h[6]\n\t"
        "sqrdmulh	v23.8h, v26.8h, v5.h[6]\n\t"
        "sqrdmulh	v24.8h, v28.8h, v5.h[6]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v23.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v24.8h, v27.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v27.8h, v27.8h, v8.h[0]\n\t"
        "sub	v23.8h, v23.8h, v25.8h\n\t"
        "sub	v24.8h, v24.8h, v27.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v23.8h, v23.8h, #1\n\t"
        "sshr	v24.8h, v24.8h, #1\n\t"
        "mul	v25.8h, v9.8h, v7.h[7]\n\t"
        "mul	v26.8h, v10.8h, v7.h[7]\n\t"
        "sqrdmulh	v9.8h, v9.8h, v5.h[7]\n\t"
        "sqrdmulh	v10.8h, v10.8h, v5.h[7]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v9.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v10.8h, v26.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v26.8h, v26.8h, v8.h[0]\n\t"
        "sub	v9.8h, v9.8h, v25.8h\n\t"
        "sub	v10.8h, v10.8h, v26.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v9.8h, v9.8h, #1\n\t"
        "sshr	v10.8h, v10.8h, #1\n\t"
        "mul	v25.8h, v11.8h, v7.h[7]\n\t"
        "mul	v26.8h, v12.8h, v7.h[7]\n\t"
        "sqrdmulh	v11.8h, v11.8h, v5.h[7]\n\t"
        "sqrdmulh	v12.8h, v12.8h, v5.h[7]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v11.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v12.8h, v26.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v26.8h, v26.8h, v8.h[0]\n\t"
        "sub	v11.8h, v11.8h, v25.8h\n\t"
        "sub	v12.8h, v12.8h, v26.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v11.8h, v11.8h, #1\n\t"
        "sshr	v12.8h, v12.8h, #1\n\t"
        "mul	v25.8h, v13.8h, v7.h[7]\n\t"
        "mul	v26.8h, v14.8h, v7.h[7]\n\t"
        "sqrdmulh	v13.8h, v13.8h, v5.h[7]\n\t"
        "sqrdmulh	v14.8h, v14.8h, v5.h[7]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v13.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v14.8h, v26.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v26.8h, v26.8h, v8.h[0]\n\t"
        "sub	v13.8h, v13.8h, v25.8h\n\t"
        "sub	v14.8h, v14.8h, v26.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v13.8h, v13.8h, #1\n\t"
        "sshr	v14.8h, v14.8h, #1\n\t"
        "mul	v25.8h, v15.8h, v7.h[7]\n\t"
        "mul	v26.8h, v16.8h, v7.h[7]\n\t"
        "sqrdmulh	v15.8h, v15.8h, v5.h[7]\n\t"
        "sqrdmulh	v16.8h, v16.8h, v5.h[7]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v15.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v16.8h, v26.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v26.8h, v26.8h, v8.h[0]\n\t"
        "sub	v15.8h, v15.8h, v25.8h\n\t"
        "sub	v16.8h, v16.8h, v26.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v15.8h, v15.8h, #1\n\t"
        "sshr	v16.8h, v16.8h, #1\n\t"
        "mul	v25.8h, v17.8h, v7.h[7]\n\t"
        "mul	v26.8h, v18.8h, v7.h[7]\n\t"
        "sqrdmulh	v17.8h, v17.8h, v5.h[7]\n\t"
        "sqrdmulh	v18.8h, v18.8h, v5.h[7]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v17.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v18.8h, v26.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v26.8h, v26.8h, v8.h[0]\n\t"
        "sub	v17.8h, v17.8h, v25.8h\n\t"
        "sub	v18.8h, v18.8h, v26.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v17.8h, v17.8h, #1\n\t"
        "sshr	v18.8h, v18.8h, #1\n\t"
        "mul	v25.8h, v19.8h, v7.h[7]\n\t"
        "mul	v26.8h, v20.8h, v7.h[7]\n\t"
        "sqrdmulh	v19.8h, v19.8h, v5.h[7]\n\t"
        "sqrdmulh	v20.8h, v20.8h, v5.h[7]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v19.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v20.8h, v26.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v26.8h, v26.8h, v8.h[0]\n\t"
        "sub	v19.8h, v19.8h, v25.8h\n\t"
        "sub	v20.8h, v20.8h, v26.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v19.8h, v19.8h, #1\n\t"
        "sshr	v20.8h, v20.8h, #1\n\t"
        "mul	v25.8h, v21.8h, v7.h[7]\n\t"
        "mul	v26.8h, v22.8h, v7.h[7]\n\t"
        "sqrdmulh	v21.8h, v21.8h, v5.h[7]\n\t"
        "sqrdmulh	v22.8h, v22.8h, v5.h[7]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v21.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v22.8h, v26.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v26.8h, v26.8h, v8.h[0]\n\t"
        "sub	v21.8h, v21.8h, v25.8h\n\t"
        "sub	v22.8h, v22.8h, v26.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v21.8h, v21.8h, #1\n\t"
        "sshr	v22.8h, v22.8h, #1\n\t"
        "mul	v25.8h, v23.8h, v7.h[7]\n\t"
        "mul	v26.8h, v24.8h, v7.h[7]\n\t"
        "sqrdmulh	v23.8h, v23.8h, v5.h[7]\n\t"
        "sqrdmulh	v24.8h, v24.8h, v5.h[7]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v23.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmlsh	v24.8h, v26.8h, v8.h[0]\n\t"
#else
        "sqrdmulh	v25.8h, v25.8h, v8.h[0]\n\t"
        "sqrdmulh	v26.8h, v26.8h, v8.h[0]\n\t"
        "sub	v23.8h, v23.8h, v25.8h\n\t"
        "sub	v24.8h, v24.8h, v26.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v23.8h, v23.8h, #1\n\t"
        "sshr	v24.8h, v24.8h, #1\n\t"
        "str	q9, [%x[r], #16]\n\t"
        "str	q10, [%x[r], #48]\n\t"
        "str	q11, [%x[r], #80]\n\t"
        "str	q12, [%x[r], #112]\n\t"
        "str	q13, [%x[r], #144]\n\t"
        "str	q14, [%x[r], #176]\n\t"
        "str	q15, [%x[r], #208]\n\t"
        "str	q16, [%x[r], #240]\n\t"
        "str	q17, [x1, #16]\n\t"
        "str	q18, [x1, #48]\n\t"
        "str	q19, [x1, #80]\n\t"
        "str	q20, [x1, #112]\n\t"
        "str	q21, [x1, #144]\n\t"
        "str	q22, [x1, #176]\n\t"
        "str	q23, [x1, #208]\n\t"
        "str	q24, [x1, #240]\n\t"
        : [r] "+r" (r)
        : [L_kyber_aarch64_q] "S" (L_kyber_aarch64_q), [L_kyber_aarch64_consts] "S" (L_kyber_aarch64_consts), [L_sha3_aarch64_r] "S" (L_sha3_aarch64_r), [L_kyber_aarch64_zetas] "S" (L_kyber_aarch64_zetas), [L_kyber_aarch64_zetas_qinv] "S" (L_kyber_aarch64_zetas_qinv), [L_kyber_aarch64_zetas_inv] "S" (L_kyber_aarch64_zetas_inv), [L_kyber_aarch64_zetas_inv_qinv] "S" (L_kyber_aarch64_zetas_inv_qinv)
        : "memory", "x1", "x2", "x3", "x4", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15", "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26", "v27", "v28", "cc"
    );
}

static const word16 L_kyber_aarch64_zetas_mul[] = {
    0x8b2,
    0xf74e,
    0x1ae,
    0xfe52,
    0x22b,
    0xfdd5,
    0x34b,
    0xfcb5,
    0x81e,
    0xf7e2,
    0x367,
    0xfc99,
    0x60e,
    0xf9f2,
    0x69,
    0xff97,
    0x1a6,
    0xfe5a,
    0x24b,
    0xfdb5,
    0xb1,
    0xff4f,
    0xc16,
    0xf3ea,
    0xbde,
    0xf422,
    0xb35,
    0xf4cb,
    0x626,
    0xf9da,
    0x675,
    0xf98b,
    0xc0b,
    0xf3f5,
    0x30a,
    0xfcf6,
    0x487,
    0xfb79,
    0xc6e,
    0xf392,
    0x9f8,
    0xf608,
    0x5cb,
    0xfa35,
    0xaa7,
    0xf559,
    0x45f,
    0xfba1,
    0x6cb,
    0xf935,
    0x284,
    0xfd7c,
    0x999,
    0xf667,
    0x15d,
    0xfea3,
    0x1a2,
    0xfe5e,
    0x149,
    0xfeb7,
    0xc65,
    0xf39b,
    0xcb6,
    0xf34a,
    0x331,
    0xfccf,
    0x449,
    0xfbb7,
    0x25b,
    0xfda5,
    0x262,
    0xfd9e,
    0x52a,
    0xfad6,
    0x7fc,
    0xf804,
    0x748,
    0xf8b8,
    0x180,
    0xfe80,
    0x842,
    0xf7be,
    0xc79,
    0xf387,
    0x4c2,
    0xfb3e,
    0x7ca,
    0xf836,
    0x997,
    0xf669,
    0xdc,
    0xff24,
    0x85e,
    0xf7a2,
    0x686,
    0xf97a,
    0x860,
    0xf7a0,
    0x707,
    0xf8f9,
    0x803,
    0xf7fd,
    0x31a,
    0xfce6,
    0x71b,
    0xf8e5,
    0x9ab,
    0xf655,
    0x99b,
    0xf665,
    0x1de,
    0xfe22,
    0xc95,
    0xf36b,
    0xbcd,
    0xf433,
    0x3e4,
    0xfc1c,
    0x3df,
    0xfc21,
    0x3be,
    0xfc42,
    0x74d,
    0xf8b3,
    0x5f2,
    0xfa0e,
    0x65c,
    0xf9a4,
};

void kyber_basemul_mont(sword16* r, const sword16* a, const sword16* b)
{
    __asm__ __volatile__ (
#ifndef __APPLE__
        "adrp x3, %[L_kyber_aarch64_zetas_mul]\n\t"
        "add  x3, x3, :lo12:%[L_kyber_aarch64_zetas_mul]\n\t"
#else
        "adrp x3, %[L_kyber_aarch64_zetas_mul]@PAGE\n\t"
        "add  x3, x3, %[L_kyber_aarch64_zetas_mul]@PAGEOFF\n\t"
#endif /* __APPLE__ */
#ifndef __APPLE__
        "adrp x4, %[L_kyber_aarch64_consts]\n\t"
        "add  x4, x4, :lo12:%[L_kyber_aarch64_consts]\n\t"
#else
        "adrp x4, %[L_kyber_aarch64_consts]@PAGE\n\t"
        "add  x4, x4, %[L_kyber_aarch64_consts]@PAGEOFF\n\t"
#endif /* __APPLE__ */
        "ldr	q1, [x4]\n\t"
        "ldp	q2, q3, [%x[a]]\n\t"
        "ldp	q4, q5, [%x[a], #32]\n\t"
        "ldp	q6, q7, [%x[a], #64]\n\t"
        "ldp	q8, q9, [%x[a], #96]\n\t"
        "ldp	q10, q11, [%x[b]]\n\t"
        "ldp	q12, q13, [%x[b], #32]\n\t"
        "ldp	q14, q15, [%x[b], #64]\n\t"
        "ldp	q16, q17, [%x[b], #96]\n\t"
        "ldr	q0, [x3]\n\t"
        "uzp1	v18.8h, v2.8h, v3.8h\n\t"
        "uzp2	v19.8h, v2.8h, v3.8h\n\t"
        "uzp1	v20.8h, v10.8h, v11.8h\n\t"
        "uzp2	v21.8h, v10.8h, v11.8h\n\t"
        "smull	v26.4s, v18.4h, v20.4h\n\t"
        "smull2	v27.4s, v18.8h, v20.8h\n\t"
        "smull	v23.4s, v19.4h, v21.4h\n\t"
        "smull2	v24.4s, v19.8h, v21.8h\n\t"
        "xtn	v25.4h, v23.4s\n\t"
        "xtn2	v25.8h, v24.4s\n\t"
        "mul	v25.8h, v25.8h, v1.h[1]\n\t"
        "smlsl	v23.4s, v25.4h, v1.h[0]\n\t"
        "smlsl2	v24.4s, v25.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v23.4s, #16\n\t"
        "shrn2	v22.8h, v24.4s, #16\n\t"
        "smlal	v26.4s, v22.4h, v0.4h\n\t"
        "smlal2	v27.4s, v22.8h, v0.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v26.4s, #16\n\t"
        "shrn2	v22.8h, v27.4s, #16\n\t"
        "smull	v26.4s, v18.4h, v21.4h\n\t"
        "smull2	v27.4s, v18.8h, v21.8h\n\t"
        "smlal	v26.4s, v19.4h, v20.4h\n\t"
        "smlal2	v27.4s, v19.8h, v20.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v23.4h, v26.4s, #16\n\t"
        "shrn2	v23.8h, v27.4s, #16\n\t"
        "zip1	v24.8h, v22.8h, v23.8h\n\t"
        "zip2	v25.8h, v22.8h, v23.8h\n\t"
        "stp	q24, q25, [%x[r]]\n\t"
        "ldr	q0, [x3, #16]\n\t"
        "uzp1	v18.8h, v4.8h, v5.8h\n\t"
        "uzp2	v19.8h, v4.8h, v5.8h\n\t"
        "uzp1	v20.8h, v12.8h, v13.8h\n\t"
        "uzp2	v21.8h, v12.8h, v13.8h\n\t"
        "smull	v26.4s, v18.4h, v20.4h\n\t"
        "smull2	v27.4s, v18.8h, v20.8h\n\t"
        "smull	v23.4s, v19.4h, v21.4h\n\t"
        "smull2	v24.4s, v19.8h, v21.8h\n\t"
        "xtn	v25.4h, v23.4s\n\t"
        "xtn2	v25.8h, v24.4s\n\t"
        "mul	v25.8h, v25.8h, v1.h[1]\n\t"
        "smlsl	v23.4s, v25.4h, v1.h[0]\n\t"
        "smlsl2	v24.4s, v25.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v23.4s, #16\n\t"
        "shrn2	v22.8h, v24.4s, #16\n\t"
        "smlal	v26.4s, v22.4h, v0.4h\n\t"
        "smlal2	v27.4s, v22.8h, v0.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v26.4s, #16\n\t"
        "shrn2	v22.8h, v27.4s, #16\n\t"
        "smull	v26.4s, v18.4h, v21.4h\n\t"
        "smull2	v27.4s, v18.8h, v21.8h\n\t"
        "smlal	v26.4s, v19.4h, v20.4h\n\t"
        "smlal2	v27.4s, v19.8h, v20.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v23.4h, v26.4s, #16\n\t"
        "shrn2	v23.8h, v27.4s, #16\n\t"
        "zip1	v24.8h, v22.8h, v23.8h\n\t"
        "zip2	v25.8h, v22.8h, v23.8h\n\t"
        "stp	q24, q25, [%x[r], #32]\n\t"
        "ldr	q0, [x3, #32]\n\t"
        "uzp1	v18.8h, v6.8h, v7.8h\n\t"
        "uzp2	v19.8h, v6.8h, v7.8h\n\t"
        "uzp1	v20.8h, v14.8h, v15.8h\n\t"
        "uzp2	v21.8h, v14.8h, v15.8h\n\t"
        "smull	v26.4s, v18.4h, v20.4h\n\t"
        "smull2	v27.4s, v18.8h, v20.8h\n\t"
        "smull	v23.4s, v19.4h, v21.4h\n\t"
        "smull2	v24.4s, v19.8h, v21.8h\n\t"
        "xtn	v25.4h, v23.4s\n\t"
        "xtn2	v25.8h, v24.4s\n\t"
        "mul	v25.8h, v25.8h, v1.h[1]\n\t"
        "smlsl	v23.4s, v25.4h, v1.h[0]\n\t"
        "smlsl2	v24.4s, v25.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v23.4s, #16\n\t"
        "shrn2	v22.8h, v24.4s, #16\n\t"
        "smlal	v26.4s, v22.4h, v0.4h\n\t"
        "smlal2	v27.4s, v22.8h, v0.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v26.4s, #16\n\t"
        "shrn2	v22.8h, v27.4s, #16\n\t"
        "smull	v26.4s, v18.4h, v21.4h\n\t"
        "smull2	v27.4s, v18.8h, v21.8h\n\t"
        "smlal	v26.4s, v19.4h, v20.4h\n\t"
        "smlal2	v27.4s, v19.8h, v20.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v23.4h, v26.4s, #16\n\t"
        "shrn2	v23.8h, v27.4s, #16\n\t"
        "zip1	v24.8h, v22.8h, v23.8h\n\t"
        "zip2	v25.8h, v22.8h, v23.8h\n\t"
        "stp	q24, q25, [%x[r], #64]\n\t"
        "ldr	q0, [x3, #48]\n\t"
        "uzp1	v18.8h, v8.8h, v9.8h\n\t"
        "uzp2	v19.8h, v8.8h, v9.8h\n\t"
        "uzp1	v20.8h, v16.8h, v17.8h\n\t"
        "uzp2	v21.8h, v16.8h, v17.8h\n\t"
        "smull	v26.4s, v18.4h, v20.4h\n\t"
        "smull2	v27.4s, v18.8h, v20.8h\n\t"
        "smull	v23.4s, v19.4h, v21.4h\n\t"
        "smull2	v24.4s, v19.8h, v21.8h\n\t"
        "xtn	v25.4h, v23.4s\n\t"
        "xtn2	v25.8h, v24.4s\n\t"
        "mul	v25.8h, v25.8h, v1.h[1]\n\t"
        "smlsl	v23.4s, v25.4h, v1.h[0]\n\t"
        "smlsl2	v24.4s, v25.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v23.4s, #16\n\t"
        "shrn2	v22.8h, v24.4s, #16\n\t"
        "smlal	v26.4s, v22.4h, v0.4h\n\t"
        "smlal2	v27.4s, v22.8h, v0.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v26.4s, #16\n\t"
        "shrn2	v22.8h, v27.4s, #16\n\t"
        "smull	v26.4s, v18.4h, v21.4h\n\t"
        "smull2	v27.4s, v18.8h, v21.8h\n\t"
        "smlal	v26.4s, v19.4h, v20.4h\n\t"
        "smlal2	v27.4s, v19.8h, v20.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v23.4h, v26.4s, #16\n\t"
        "shrn2	v23.8h, v27.4s, #16\n\t"
        "zip1	v24.8h, v22.8h, v23.8h\n\t"
        "zip2	v25.8h, v22.8h, v23.8h\n\t"
        "stp	q24, q25, [%x[r], #96]\n\t"
        "ldp	q2, q3, [%x[a], #128]\n\t"
        "ldp	q4, q5, [%x[a], #160]\n\t"
        "ldp	q6, q7, [%x[a], #192]\n\t"
        "ldp	q8, q9, [%x[a], #224]\n\t"
        "ldp	q10, q11, [%x[b], #128]\n\t"
        "ldp	q12, q13, [%x[b], #160]\n\t"
        "ldp	q14, q15, [%x[b], #192]\n\t"
        "ldp	q16, q17, [%x[b], #224]\n\t"
        "ldr	q0, [x3, #64]\n\t"
        "uzp1	v18.8h, v2.8h, v3.8h\n\t"
        "uzp2	v19.8h, v2.8h, v3.8h\n\t"
        "uzp1	v20.8h, v10.8h, v11.8h\n\t"
        "uzp2	v21.8h, v10.8h, v11.8h\n\t"
        "smull	v26.4s, v18.4h, v20.4h\n\t"
        "smull2	v27.4s, v18.8h, v20.8h\n\t"
        "smull	v23.4s, v19.4h, v21.4h\n\t"
        "smull2	v24.4s, v19.8h, v21.8h\n\t"
        "xtn	v25.4h, v23.4s\n\t"
        "xtn2	v25.8h, v24.4s\n\t"
        "mul	v25.8h, v25.8h, v1.h[1]\n\t"
        "smlsl	v23.4s, v25.4h, v1.h[0]\n\t"
        "smlsl2	v24.4s, v25.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v23.4s, #16\n\t"
        "shrn2	v22.8h, v24.4s, #16\n\t"
        "smlal	v26.4s, v22.4h, v0.4h\n\t"
        "smlal2	v27.4s, v22.8h, v0.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v26.4s, #16\n\t"
        "shrn2	v22.8h, v27.4s, #16\n\t"
        "smull	v26.4s, v18.4h, v21.4h\n\t"
        "smull2	v27.4s, v18.8h, v21.8h\n\t"
        "smlal	v26.4s, v19.4h, v20.4h\n\t"
        "smlal2	v27.4s, v19.8h, v20.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v23.4h, v26.4s, #16\n\t"
        "shrn2	v23.8h, v27.4s, #16\n\t"
        "zip1	v24.8h, v22.8h, v23.8h\n\t"
        "zip2	v25.8h, v22.8h, v23.8h\n\t"
        "stp	q24, q25, [%x[r], #128]\n\t"
        "ldr	q0, [x3, #80]\n\t"
        "uzp1	v18.8h, v4.8h, v5.8h\n\t"
        "uzp2	v19.8h, v4.8h, v5.8h\n\t"
        "uzp1	v20.8h, v12.8h, v13.8h\n\t"
        "uzp2	v21.8h, v12.8h, v13.8h\n\t"
        "smull	v26.4s, v18.4h, v20.4h\n\t"
        "smull2	v27.4s, v18.8h, v20.8h\n\t"
        "smull	v23.4s, v19.4h, v21.4h\n\t"
        "smull2	v24.4s, v19.8h, v21.8h\n\t"
        "xtn	v25.4h, v23.4s\n\t"
        "xtn2	v25.8h, v24.4s\n\t"
        "mul	v25.8h, v25.8h, v1.h[1]\n\t"
        "smlsl	v23.4s, v25.4h, v1.h[0]\n\t"
        "smlsl2	v24.4s, v25.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v23.4s, #16\n\t"
        "shrn2	v22.8h, v24.4s, #16\n\t"
        "smlal	v26.4s, v22.4h, v0.4h\n\t"
        "smlal2	v27.4s, v22.8h, v0.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v26.4s, #16\n\t"
        "shrn2	v22.8h, v27.4s, #16\n\t"
        "smull	v26.4s, v18.4h, v21.4h\n\t"
        "smull2	v27.4s, v18.8h, v21.8h\n\t"
        "smlal	v26.4s, v19.4h, v20.4h\n\t"
        "smlal2	v27.4s, v19.8h, v20.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v23.4h, v26.4s, #16\n\t"
        "shrn2	v23.8h, v27.4s, #16\n\t"
        "zip1	v24.8h, v22.8h, v23.8h\n\t"
        "zip2	v25.8h, v22.8h, v23.8h\n\t"
        "stp	q24, q25, [%x[r], #160]\n\t"
        "ldr	q0, [x3, #96]\n\t"
        "uzp1	v18.8h, v6.8h, v7.8h\n\t"
        "uzp2	v19.8h, v6.8h, v7.8h\n\t"
        "uzp1	v20.8h, v14.8h, v15.8h\n\t"
        "uzp2	v21.8h, v14.8h, v15.8h\n\t"
        "smull	v26.4s, v18.4h, v20.4h\n\t"
        "smull2	v27.4s, v18.8h, v20.8h\n\t"
        "smull	v23.4s, v19.4h, v21.4h\n\t"
        "smull2	v24.4s, v19.8h, v21.8h\n\t"
        "xtn	v25.4h, v23.4s\n\t"
        "xtn2	v25.8h, v24.4s\n\t"
        "mul	v25.8h, v25.8h, v1.h[1]\n\t"
        "smlsl	v23.4s, v25.4h, v1.h[0]\n\t"
        "smlsl2	v24.4s, v25.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v23.4s, #16\n\t"
        "shrn2	v22.8h, v24.4s, #16\n\t"
        "smlal	v26.4s, v22.4h, v0.4h\n\t"
        "smlal2	v27.4s, v22.8h, v0.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v26.4s, #16\n\t"
        "shrn2	v22.8h, v27.4s, #16\n\t"
        "smull	v26.4s, v18.4h, v21.4h\n\t"
        "smull2	v27.4s, v18.8h, v21.8h\n\t"
        "smlal	v26.4s, v19.4h, v20.4h\n\t"
        "smlal2	v27.4s, v19.8h, v20.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v23.4h, v26.4s, #16\n\t"
        "shrn2	v23.8h, v27.4s, #16\n\t"
        "zip1	v24.8h, v22.8h, v23.8h\n\t"
        "zip2	v25.8h, v22.8h, v23.8h\n\t"
        "stp	q24, q25, [%x[r], #192]\n\t"
        "ldr	q0, [x3, #112]\n\t"
        "uzp1	v18.8h, v8.8h, v9.8h\n\t"
        "uzp2	v19.8h, v8.8h, v9.8h\n\t"
        "uzp1	v20.8h, v16.8h, v17.8h\n\t"
        "uzp2	v21.8h, v16.8h, v17.8h\n\t"
        "smull	v26.4s, v18.4h, v20.4h\n\t"
        "smull2	v27.4s, v18.8h, v20.8h\n\t"
        "smull	v23.4s, v19.4h, v21.4h\n\t"
        "smull2	v24.4s, v19.8h, v21.8h\n\t"
        "xtn	v25.4h, v23.4s\n\t"
        "xtn2	v25.8h, v24.4s\n\t"
        "mul	v25.8h, v25.8h, v1.h[1]\n\t"
        "smlsl	v23.4s, v25.4h, v1.h[0]\n\t"
        "smlsl2	v24.4s, v25.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v23.4s, #16\n\t"
        "shrn2	v22.8h, v24.4s, #16\n\t"
        "smlal	v26.4s, v22.4h, v0.4h\n\t"
        "smlal2	v27.4s, v22.8h, v0.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v26.4s, #16\n\t"
        "shrn2	v22.8h, v27.4s, #16\n\t"
        "smull	v26.4s, v18.4h, v21.4h\n\t"
        "smull2	v27.4s, v18.8h, v21.8h\n\t"
        "smlal	v26.4s, v19.4h, v20.4h\n\t"
        "smlal2	v27.4s, v19.8h, v20.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v23.4h, v26.4s, #16\n\t"
        "shrn2	v23.8h, v27.4s, #16\n\t"
        "zip1	v24.8h, v22.8h, v23.8h\n\t"
        "zip2	v25.8h, v22.8h, v23.8h\n\t"
        "stp	q24, q25, [%x[r], #224]\n\t"
        "ldp	q2, q3, [%x[a], #256]\n\t"
        "ldp	q4, q5, [%x[a], #288]\n\t"
        "ldp	q6, q7, [%x[a], #320]\n\t"
        "ldp	q8, q9, [%x[a], #352]\n\t"
        "ldp	q10, q11, [%x[b], #256]\n\t"
        "ldp	q12, q13, [%x[b], #288]\n\t"
        "ldp	q14, q15, [%x[b], #320]\n\t"
        "ldp	q16, q17, [%x[b], #352]\n\t"
        "ldr	q0, [x3, #128]\n\t"
        "uzp1	v18.8h, v2.8h, v3.8h\n\t"
        "uzp2	v19.8h, v2.8h, v3.8h\n\t"
        "uzp1	v20.8h, v10.8h, v11.8h\n\t"
        "uzp2	v21.8h, v10.8h, v11.8h\n\t"
        "smull	v26.4s, v18.4h, v20.4h\n\t"
        "smull2	v27.4s, v18.8h, v20.8h\n\t"
        "smull	v23.4s, v19.4h, v21.4h\n\t"
        "smull2	v24.4s, v19.8h, v21.8h\n\t"
        "xtn	v25.4h, v23.4s\n\t"
        "xtn2	v25.8h, v24.4s\n\t"
        "mul	v25.8h, v25.8h, v1.h[1]\n\t"
        "smlsl	v23.4s, v25.4h, v1.h[0]\n\t"
        "smlsl2	v24.4s, v25.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v23.4s, #16\n\t"
        "shrn2	v22.8h, v24.4s, #16\n\t"
        "smlal	v26.4s, v22.4h, v0.4h\n\t"
        "smlal2	v27.4s, v22.8h, v0.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v26.4s, #16\n\t"
        "shrn2	v22.8h, v27.4s, #16\n\t"
        "smull	v26.4s, v18.4h, v21.4h\n\t"
        "smull2	v27.4s, v18.8h, v21.8h\n\t"
        "smlal	v26.4s, v19.4h, v20.4h\n\t"
        "smlal2	v27.4s, v19.8h, v20.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v23.4h, v26.4s, #16\n\t"
        "shrn2	v23.8h, v27.4s, #16\n\t"
        "zip1	v24.8h, v22.8h, v23.8h\n\t"
        "zip2	v25.8h, v22.8h, v23.8h\n\t"
        "stp	q24, q25, [%x[r], #256]\n\t"
        "ldr	q0, [x3, #144]\n\t"
        "uzp1	v18.8h, v4.8h, v5.8h\n\t"
        "uzp2	v19.8h, v4.8h, v5.8h\n\t"
        "uzp1	v20.8h, v12.8h, v13.8h\n\t"
        "uzp2	v21.8h, v12.8h, v13.8h\n\t"
        "smull	v26.4s, v18.4h, v20.4h\n\t"
        "smull2	v27.4s, v18.8h, v20.8h\n\t"
        "smull	v23.4s, v19.4h, v21.4h\n\t"
        "smull2	v24.4s, v19.8h, v21.8h\n\t"
        "xtn	v25.4h, v23.4s\n\t"
        "xtn2	v25.8h, v24.4s\n\t"
        "mul	v25.8h, v25.8h, v1.h[1]\n\t"
        "smlsl	v23.4s, v25.4h, v1.h[0]\n\t"
        "smlsl2	v24.4s, v25.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v23.4s, #16\n\t"
        "shrn2	v22.8h, v24.4s, #16\n\t"
        "smlal	v26.4s, v22.4h, v0.4h\n\t"
        "smlal2	v27.4s, v22.8h, v0.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v26.4s, #16\n\t"
        "shrn2	v22.8h, v27.4s, #16\n\t"
        "smull	v26.4s, v18.4h, v21.4h\n\t"
        "smull2	v27.4s, v18.8h, v21.8h\n\t"
        "smlal	v26.4s, v19.4h, v20.4h\n\t"
        "smlal2	v27.4s, v19.8h, v20.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v23.4h, v26.4s, #16\n\t"
        "shrn2	v23.8h, v27.4s, #16\n\t"
        "zip1	v24.8h, v22.8h, v23.8h\n\t"
        "zip2	v25.8h, v22.8h, v23.8h\n\t"
        "stp	q24, q25, [%x[r], #288]\n\t"
        "ldr	q0, [x3, #160]\n\t"
        "uzp1	v18.8h, v6.8h, v7.8h\n\t"
        "uzp2	v19.8h, v6.8h, v7.8h\n\t"
        "uzp1	v20.8h, v14.8h, v15.8h\n\t"
        "uzp2	v21.8h, v14.8h, v15.8h\n\t"
        "smull	v26.4s, v18.4h, v20.4h\n\t"
        "smull2	v27.4s, v18.8h, v20.8h\n\t"
        "smull	v23.4s, v19.4h, v21.4h\n\t"
        "smull2	v24.4s, v19.8h, v21.8h\n\t"
        "xtn	v25.4h, v23.4s\n\t"
        "xtn2	v25.8h, v24.4s\n\t"
        "mul	v25.8h, v25.8h, v1.h[1]\n\t"
        "smlsl	v23.4s, v25.4h, v1.h[0]\n\t"
        "smlsl2	v24.4s, v25.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v23.4s, #16\n\t"
        "shrn2	v22.8h, v24.4s, #16\n\t"
        "smlal	v26.4s, v22.4h, v0.4h\n\t"
        "smlal2	v27.4s, v22.8h, v0.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v26.4s, #16\n\t"
        "shrn2	v22.8h, v27.4s, #16\n\t"
        "smull	v26.4s, v18.4h, v21.4h\n\t"
        "smull2	v27.4s, v18.8h, v21.8h\n\t"
        "smlal	v26.4s, v19.4h, v20.4h\n\t"
        "smlal2	v27.4s, v19.8h, v20.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v23.4h, v26.4s, #16\n\t"
        "shrn2	v23.8h, v27.4s, #16\n\t"
        "zip1	v24.8h, v22.8h, v23.8h\n\t"
        "zip2	v25.8h, v22.8h, v23.8h\n\t"
        "stp	q24, q25, [%x[r], #320]\n\t"
        "ldr	q0, [x3, #176]\n\t"
        "uzp1	v18.8h, v8.8h, v9.8h\n\t"
        "uzp2	v19.8h, v8.8h, v9.8h\n\t"
        "uzp1	v20.8h, v16.8h, v17.8h\n\t"
        "uzp2	v21.8h, v16.8h, v17.8h\n\t"
        "smull	v26.4s, v18.4h, v20.4h\n\t"
        "smull2	v27.4s, v18.8h, v20.8h\n\t"
        "smull	v23.4s, v19.4h, v21.4h\n\t"
        "smull2	v24.4s, v19.8h, v21.8h\n\t"
        "xtn	v25.4h, v23.4s\n\t"
        "xtn2	v25.8h, v24.4s\n\t"
        "mul	v25.8h, v25.8h, v1.h[1]\n\t"
        "smlsl	v23.4s, v25.4h, v1.h[0]\n\t"
        "smlsl2	v24.4s, v25.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v23.4s, #16\n\t"
        "shrn2	v22.8h, v24.4s, #16\n\t"
        "smlal	v26.4s, v22.4h, v0.4h\n\t"
        "smlal2	v27.4s, v22.8h, v0.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v26.4s, #16\n\t"
        "shrn2	v22.8h, v27.4s, #16\n\t"
        "smull	v26.4s, v18.4h, v21.4h\n\t"
        "smull2	v27.4s, v18.8h, v21.8h\n\t"
        "smlal	v26.4s, v19.4h, v20.4h\n\t"
        "smlal2	v27.4s, v19.8h, v20.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v23.4h, v26.4s, #16\n\t"
        "shrn2	v23.8h, v27.4s, #16\n\t"
        "zip1	v24.8h, v22.8h, v23.8h\n\t"
        "zip2	v25.8h, v22.8h, v23.8h\n\t"
        "stp	q24, q25, [%x[r], #352]\n\t"
        "ldp	q2, q3, [%x[a], #384]\n\t"
        "ldp	q4, q5, [%x[a], #416]\n\t"
        "ldp	q6, q7, [%x[a], #448]\n\t"
        "ldp	q8, q9, [%x[a], #480]\n\t"
        "ldp	q10, q11, [%x[b], #384]\n\t"
        "ldp	q12, q13, [%x[b], #416]\n\t"
        "ldp	q14, q15, [%x[b], #448]\n\t"
        "ldp	q16, q17, [%x[b], #480]\n\t"
        "ldr	q0, [x3, #192]\n\t"
        "uzp1	v18.8h, v2.8h, v3.8h\n\t"
        "uzp2	v19.8h, v2.8h, v3.8h\n\t"
        "uzp1	v20.8h, v10.8h, v11.8h\n\t"
        "uzp2	v21.8h, v10.8h, v11.8h\n\t"
        "smull	v26.4s, v18.4h, v20.4h\n\t"
        "smull2	v27.4s, v18.8h, v20.8h\n\t"
        "smull	v23.4s, v19.4h, v21.4h\n\t"
        "smull2	v24.4s, v19.8h, v21.8h\n\t"
        "xtn	v25.4h, v23.4s\n\t"
        "xtn2	v25.8h, v24.4s\n\t"
        "mul	v25.8h, v25.8h, v1.h[1]\n\t"
        "smlsl	v23.4s, v25.4h, v1.h[0]\n\t"
        "smlsl2	v24.4s, v25.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v23.4s, #16\n\t"
        "shrn2	v22.8h, v24.4s, #16\n\t"
        "smlal	v26.4s, v22.4h, v0.4h\n\t"
        "smlal2	v27.4s, v22.8h, v0.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v26.4s, #16\n\t"
        "shrn2	v22.8h, v27.4s, #16\n\t"
        "smull	v26.4s, v18.4h, v21.4h\n\t"
        "smull2	v27.4s, v18.8h, v21.8h\n\t"
        "smlal	v26.4s, v19.4h, v20.4h\n\t"
        "smlal2	v27.4s, v19.8h, v20.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v23.4h, v26.4s, #16\n\t"
        "shrn2	v23.8h, v27.4s, #16\n\t"
        "zip1	v24.8h, v22.8h, v23.8h\n\t"
        "zip2	v25.8h, v22.8h, v23.8h\n\t"
        "stp	q24, q25, [%x[r], #384]\n\t"
        "ldr	q0, [x3, #208]\n\t"
        "uzp1	v18.8h, v4.8h, v5.8h\n\t"
        "uzp2	v19.8h, v4.8h, v5.8h\n\t"
        "uzp1	v20.8h, v12.8h, v13.8h\n\t"
        "uzp2	v21.8h, v12.8h, v13.8h\n\t"
        "smull	v26.4s, v18.4h, v20.4h\n\t"
        "smull2	v27.4s, v18.8h, v20.8h\n\t"
        "smull	v23.4s, v19.4h, v21.4h\n\t"
        "smull2	v24.4s, v19.8h, v21.8h\n\t"
        "xtn	v25.4h, v23.4s\n\t"
        "xtn2	v25.8h, v24.4s\n\t"
        "mul	v25.8h, v25.8h, v1.h[1]\n\t"
        "smlsl	v23.4s, v25.4h, v1.h[0]\n\t"
        "smlsl2	v24.4s, v25.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v23.4s, #16\n\t"
        "shrn2	v22.8h, v24.4s, #16\n\t"
        "smlal	v26.4s, v22.4h, v0.4h\n\t"
        "smlal2	v27.4s, v22.8h, v0.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v26.4s, #16\n\t"
        "shrn2	v22.8h, v27.4s, #16\n\t"
        "smull	v26.4s, v18.4h, v21.4h\n\t"
        "smull2	v27.4s, v18.8h, v21.8h\n\t"
        "smlal	v26.4s, v19.4h, v20.4h\n\t"
        "smlal2	v27.4s, v19.8h, v20.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v23.4h, v26.4s, #16\n\t"
        "shrn2	v23.8h, v27.4s, #16\n\t"
        "zip1	v24.8h, v22.8h, v23.8h\n\t"
        "zip2	v25.8h, v22.8h, v23.8h\n\t"
        "stp	q24, q25, [%x[r], #416]\n\t"
        "ldr	q0, [x3, #224]\n\t"
        "uzp1	v18.8h, v6.8h, v7.8h\n\t"
        "uzp2	v19.8h, v6.8h, v7.8h\n\t"
        "uzp1	v20.8h, v14.8h, v15.8h\n\t"
        "uzp2	v21.8h, v14.8h, v15.8h\n\t"
        "smull	v26.4s, v18.4h, v20.4h\n\t"
        "smull2	v27.4s, v18.8h, v20.8h\n\t"
        "smull	v23.4s, v19.4h, v21.4h\n\t"
        "smull2	v24.4s, v19.8h, v21.8h\n\t"
        "xtn	v25.4h, v23.4s\n\t"
        "xtn2	v25.8h, v24.4s\n\t"
        "mul	v25.8h, v25.8h, v1.h[1]\n\t"
        "smlsl	v23.4s, v25.4h, v1.h[0]\n\t"
        "smlsl2	v24.4s, v25.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v23.4s, #16\n\t"
        "shrn2	v22.8h, v24.4s, #16\n\t"
        "smlal	v26.4s, v22.4h, v0.4h\n\t"
        "smlal2	v27.4s, v22.8h, v0.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v26.4s, #16\n\t"
        "shrn2	v22.8h, v27.4s, #16\n\t"
        "smull	v26.4s, v18.4h, v21.4h\n\t"
        "smull2	v27.4s, v18.8h, v21.8h\n\t"
        "smlal	v26.4s, v19.4h, v20.4h\n\t"
        "smlal2	v27.4s, v19.8h, v20.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v23.4h, v26.4s, #16\n\t"
        "shrn2	v23.8h, v27.4s, #16\n\t"
        "zip1	v24.8h, v22.8h, v23.8h\n\t"
        "zip2	v25.8h, v22.8h, v23.8h\n\t"
        "stp	q24, q25, [%x[r], #448]\n\t"
        "ldr	q0, [x3, #240]\n\t"
        "uzp1	v18.8h, v8.8h, v9.8h\n\t"
        "uzp2	v19.8h, v8.8h, v9.8h\n\t"
        "uzp1	v20.8h, v16.8h, v17.8h\n\t"
        "uzp2	v21.8h, v16.8h, v17.8h\n\t"
        "smull	v26.4s, v18.4h, v20.4h\n\t"
        "smull2	v27.4s, v18.8h, v20.8h\n\t"
        "smull	v23.4s, v19.4h, v21.4h\n\t"
        "smull2	v24.4s, v19.8h, v21.8h\n\t"
        "xtn	v25.4h, v23.4s\n\t"
        "xtn2	v25.8h, v24.4s\n\t"
        "mul	v25.8h, v25.8h, v1.h[1]\n\t"
        "smlsl	v23.4s, v25.4h, v1.h[0]\n\t"
        "smlsl2	v24.4s, v25.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v23.4s, #16\n\t"
        "shrn2	v22.8h, v24.4s, #16\n\t"
        "smlal	v26.4s, v22.4h, v0.4h\n\t"
        "smlal2	v27.4s, v22.8h, v0.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v26.4s, #16\n\t"
        "shrn2	v22.8h, v27.4s, #16\n\t"
        "smull	v26.4s, v18.4h, v21.4h\n\t"
        "smull2	v27.4s, v18.8h, v21.8h\n\t"
        "smlal	v26.4s, v19.4h, v20.4h\n\t"
        "smlal2	v27.4s, v19.8h, v20.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v23.4h, v26.4s, #16\n\t"
        "shrn2	v23.8h, v27.4s, #16\n\t"
        "zip1	v24.8h, v22.8h, v23.8h\n\t"
        "zip2	v25.8h, v22.8h, v23.8h\n\t"
        "stp	q24, q25, [%x[r], #480]\n\t"
        : [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        : [L_kyber_aarch64_q] "S" (L_kyber_aarch64_q), [L_kyber_aarch64_consts] "S" (L_kyber_aarch64_consts), [L_sha3_aarch64_r] "S" (L_sha3_aarch64_r), [L_kyber_aarch64_zetas] "S" (L_kyber_aarch64_zetas), [L_kyber_aarch64_zetas_qinv] "S" (L_kyber_aarch64_zetas_qinv), [L_kyber_aarch64_zetas_inv] "S" (L_kyber_aarch64_zetas_inv), [L_kyber_aarch64_zetas_inv_qinv] "S" (L_kyber_aarch64_zetas_inv_qinv), [L_kyber_aarch64_zetas_mul] "S" (L_kyber_aarch64_zetas_mul)
        : "memory", "x3", "x4", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15", "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26", "v27", "cc"
    );
}

void kyber_basemul_mont_add(sword16* r, const sword16* a, const sword16* b)
{
    __asm__ __volatile__ (
#ifndef __APPLE__
        "adrp x3, %[L_kyber_aarch64_zetas_mul]\n\t"
        "add  x3, x3, :lo12:%[L_kyber_aarch64_zetas_mul]\n\t"
#else
        "adrp x3, %[L_kyber_aarch64_zetas_mul]@PAGE\n\t"
        "add  x3, x3, %[L_kyber_aarch64_zetas_mul]@PAGEOFF\n\t"
#endif /* __APPLE__ */
#ifndef __APPLE__
        "adrp x4, %[L_kyber_aarch64_consts]\n\t"
        "add  x4, x4, :lo12:%[L_kyber_aarch64_consts]\n\t"
#else
        "adrp x4, %[L_kyber_aarch64_consts]@PAGE\n\t"
        "add  x4, x4, %[L_kyber_aarch64_consts]@PAGEOFF\n\t"
#endif /* __APPLE__ */
        "ldr	q1, [x4]\n\t"
        "ldp	q2, q3, [%x[a]]\n\t"
        "ldp	q4, q5, [%x[a], #32]\n\t"
        "ldp	q6, q7, [%x[a], #64]\n\t"
        "ldp	q8, q9, [%x[a], #96]\n\t"
        "ldp	q10, q11, [%x[b]]\n\t"
        "ldp	q12, q13, [%x[b], #32]\n\t"
        "ldp	q14, q15, [%x[b], #64]\n\t"
        "ldp	q16, q17, [%x[b], #96]\n\t"
        "ldp	q28, q29, [%x[r]]\n\t"
        "ldr	q0, [x3]\n\t"
        "uzp1	v18.8h, v2.8h, v3.8h\n\t"
        "uzp2	v19.8h, v2.8h, v3.8h\n\t"
        "uzp1	v20.8h, v10.8h, v11.8h\n\t"
        "uzp2	v21.8h, v10.8h, v11.8h\n\t"
        "smull	v26.4s, v18.4h, v20.4h\n\t"
        "smull2	v27.4s, v18.8h, v20.8h\n\t"
        "smull	v23.4s, v19.4h, v21.4h\n\t"
        "smull2	v24.4s, v19.8h, v21.8h\n\t"
        "xtn	v25.4h, v23.4s\n\t"
        "xtn2	v25.8h, v24.4s\n\t"
        "mul	v25.8h, v25.8h, v1.h[1]\n\t"
        "smlsl	v23.4s, v25.4h, v1.h[0]\n\t"
        "smlsl2	v24.4s, v25.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v23.4s, #16\n\t"
        "shrn2	v22.8h, v24.4s, #16\n\t"
        "smlal	v26.4s, v22.4h, v0.4h\n\t"
        "smlal2	v27.4s, v22.8h, v0.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v26.4s, #16\n\t"
        "shrn2	v22.8h, v27.4s, #16\n\t"
        "smull	v26.4s, v18.4h, v21.4h\n\t"
        "smull2	v27.4s, v18.8h, v21.8h\n\t"
        "smlal	v26.4s, v19.4h, v20.4h\n\t"
        "smlal2	v27.4s, v19.8h, v20.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v23.4h, v26.4s, #16\n\t"
        "shrn2	v23.8h, v27.4s, #16\n\t"
        "zip1	v24.8h, v22.8h, v23.8h\n\t"
        "zip2	v25.8h, v22.8h, v23.8h\n\t"
        "add	v28.8h, v28.8h, v24.8h\n\t"
        "add	v29.8h, v29.8h, v25.8h\n\t"
        "stp	q28, q29, [%x[r]]\n\t"
        "ldp	q28, q29, [%x[r], #32]\n\t"
        "ldr	q0, [x3, #16]\n\t"
        "uzp1	v18.8h, v4.8h, v5.8h\n\t"
        "uzp2	v19.8h, v4.8h, v5.8h\n\t"
        "uzp1	v20.8h, v12.8h, v13.8h\n\t"
        "uzp2	v21.8h, v12.8h, v13.8h\n\t"
        "smull	v26.4s, v18.4h, v20.4h\n\t"
        "smull2	v27.4s, v18.8h, v20.8h\n\t"
        "smull	v23.4s, v19.4h, v21.4h\n\t"
        "smull2	v24.4s, v19.8h, v21.8h\n\t"
        "xtn	v25.4h, v23.4s\n\t"
        "xtn2	v25.8h, v24.4s\n\t"
        "mul	v25.8h, v25.8h, v1.h[1]\n\t"
        "smlsl	v23.4s, v25.4h, v1.h[0]\n\t"
        "smlsl2	v24.4s, v25.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v23.4s, #16\n\t"
        "shrn2	v22.8h, v24.4s, #16\n\t"
        "smlal	v26.4s, v22.4h, v0.4h\n\t"
        "smlal2	v27.4s, v22.8h, v0.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v26.4s, #16\n\t"
        "shrn2	v22.8h, v27.4s, #16\n\t"
        "smull	v26.4s, v18.4h, v21.4h\n\t"
        "smull2	v27.4s, v18.8h, v21.8h\n\t"
        "smlal	v26.4s, v19.4h, v20.4h\n\t"
        "smlal2	v27.4s, v19.8h, v20.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v23.4h, v26.4s, #16\n\t"
        "shrn2	v23.8h, v27.4s, #16\n\t"
        "zip1	v24.8h, v22.8h, v23.8h\n\t"
        "zip2	v25.8h, v22.8h, v23.8h\n\t"
        "add	v28.8h, v28.8h, v24.8h\n\t"
        "add	v29.8h, v29.8h, v25.8h\n\t"
        "stp	q28, q29, [%x[r], #32]\n\t"
        "ldp	q28, q29, [%x[r], #64]\n\t"
        "ldr	q0, [x3, #32]\n\t"
        "uzp1	v18.8h, v6.8h, v7.8h\n\t"
        "uzp2	v19.8h, v6.8h, v7.8h\n\t"
        "uzp1	v20.8h, v14.8h, v15.8h\n\t"
        "uzp2	v21.8h, v14.8h, v15.8h\n\t"
        "smull	v26.4s, v18.4h, v20.4h\n\t"
        "smull2	v27.4s, v18.8h, v20.8h\n\t"
        "smull	v23.4s, v19.4h, v21.4h\n\t"
        "smull2	v24.4s, v19.8h, v21.8h\n\t"
        "xtn	v25.4h, v23.4s\n\t"
        "xtn2	v25.8h, v24.4s\n\t"
        "mul	v25.8h, v25.8h, v1.h[1]\n\t"
        "smlsl	v23.4s, v25.4h, v1.h[0]\n\t"
        "smlsl2	v24.4s, v25.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v23.4s, #16\n\t"
        "shrn2	v22.8h, v24.4s, #16\n\t"
        "smlal	v26.4s, v22.4h, v0.4h\n\t"
        "smlal2	v27.4s, v22.8h, v0.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v26.4s, #16\n\t"
        "shrn2	v22.8h, v27.4s, #16\n\t"
        "smull	v26.4s, v18.4h, v21.4h\n\t"
        "smull2	v27.4s, v18.8h, v21.8h\n\t"
        "smlal	v26.4s, v19.4h, v20.4h\n\t"
        "smlal2	v27.4s, v19.8h, v20.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v23.4h, v26.4s, #16\n\t"
        "shrn2	v23.8h, v27.4s, #16\n\t"
        "zip1	v24.8h, v22.8h, v23.8h\n\t"
        "zip2	v25.8h, v22.8h, v23.8h\n\t"
        "add	v28.8h, v28.8h, v24.8h\n\t"
        "add	v29.8h, v29.8h, v25.8h\n\t"
        "stp	q28, q29, [%x[r], #64]\n\t"
        "ldp	q28, q29, [%x[r], #96]\n\t"
        "ldr	q0, [x3, #48]\n\t"
        "uzp1	v18.8h, v8.8h, v9.8h\n\t"
        "uzp2	v19.8h, v8.8h, v9.8h\n\t"
        "uzp1	v20.8h, v16.8h, v17.8h\n\t"
        "uzp2	v21.8h, v16.8h, v17.8h\n\t"
        "smull	v26.4s, v18.4h, v20.4h\n\t"
        "smull2	v27.4s, v18.8h, v20.8h\n\t"
        "smull	v23.4s, v19.4h, v21.4h\n\t"
        "smull2	v24.4s, v19.8h, v21.8h\n\t"
        "xtn	v25.4h, v23.4s\n\t"
        "xtn2	v25.8h, v24.4s\n\t"
        "mul	v25.8h, v25.8h, v1.h[1]\n\t"
        "smlsl	v23.4s, v25.4h, v1.h[0]\n\t"
        "smlsl2	v24.4s, v25.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v23.4s, #16\n\t"
        "shrn2	v22.8h, v24.4s, #16\n\t"
        "smlal	v26.4s, v22.4h, v0.4h\n\t"
        "smlal2	v27.4s, v22.8h, v0.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v26.4s, #16\n\t"
        "shrn2	v22.8h, v27.4s, #16\n\t"
        "smull	v26.4s, v18.4h, v21.4h\n\t"
        "smull2	v27.4s, v18.8h, v21.8h\n\t"
        "smlal	v26.4s, v19.4h, v20.4h\n\t"
        "smlal2	v27.4s, v19.8h, v20.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v23.4h, v26.4s, #16\n\t"
        "shrn2	v23.8h, v27.4s, #16\n\t"
        "zip1	v24.8h, v22.8h, v23.8h\n\t"
        "zip2	v25.8h, v22.8h, v23.8h\n\t"
        "add	v28.8h, v28.8h, v24.8h\n\t"
        "add	v29.8h, v29.8h, v25.8h\n\t"
        "stp	q28, q29, [%x[r], #96]\n\t"
        "ldp	q2, q3, [%x[a], #128]\n\t"
        "ldp	q4, q5, [%x[a], #160]\n\t"
        "ldp	q6, q7, [%x[a], #192]\n\t"
        "ldp	q8, q9, [%x[a], #224]\n\t"
        "ldp	q10, q11, [%x[b], #128]\n\t"
        "ldp	q12, q13, [%x[b], #160]\n\t"
        "ldp	q14, q15, [%x[b], #192]\n\t"
        "ldp	q16, q17, [%x[b], #224]\n\t"
        "ldp	q28, q29, [%x[r], #128]\n\t"
        "ldr	q0, [x3, #64]\n\t"
        "uzp1	v18.8h, v2.8h, v3.8h\n\t"
        "uzp2	v19.8h, v2.8h, v3.8h\n\t"
        "uzp1	v20.8h, v10.8h, v11.8h\n\t"
        "uzp2	v21.8h, v10.8h, v11.8h\n\t"
        "smull	v26.4s, v18.4h, v20.4h\n\t"
        "smull2	v27.4s, v18.8h, v20.8h\n\t"
        "smull	v23.4s, v19.4h, v21.4h\n\t"
        "smull2	v24.4s, v19.8h, v21.8h\n\t"
        "xtn	v25.4h, v23.4s\n\t"
        "xtn2	v25.8h, v24.4s\n\t"
        "mul	v25.8h, v25.8h, v1.h[1]\n\t"
        "smlsl	v23.4s, v25.4h, v1.h[0]\n\t"
        "smlsl2	v24.4s, v25.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v23.4s, #16\n\t"
        "shrn2	v22.8h, v24.4s, #16\n\t"
        "smlal	v26.4s, v22.4h, v0.4h\n\t"
        "smlal2	v27.4s, v22.8h, v0.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v26.4s, #16\n\t"
        "shrn2	v22.8h, v27.4s, #16\n\t"
        "smull	v26.4s, v18.4h, v21.4h\n\t"
        "smull2	v27.4s, v18.8h, v21.8h\n\t"
        "smlal	v26.4s, v19.4h, v20.4h\n\t"
        "smlal2	v27.4s, v19.8h, v20.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v23.4h, v26.4s, #16\n\t"
        "shrn2	v23.8h, v27.4s, #16\n\t"
        "zip1	v24.8h, v22.8h, v23.8h\n\t"
        "zip2	v25.8h, v22.8h, v23.8h\n\t"
        "add	v28.8h, v28.8h, v24.8h\n\t"
        "add	v29.8h, v29.8h, v25.8h\n\t"
        "stp	q28, q29, [%x[r], #128]\n\t"
        "ldp	q28, q29, [%x[r], #160]\n\t"
        "ldr	q0, [x3, #80]\n\t"
        "uzp1	v18.8h, v4.8h, v5.8h\n\t"
        "uzp2	v19.8h, v4.8h, v5.8h\n\t"
        "uzp1	v20.8h, v12.8h, v13.8h\n\t"
        "uzp2	v21.8h, v12.8h, v13.8h\n\t"
        "smull	v26.4s, v18.4h, v20.4h\n\t"
        "smull2	v27.4s, v18.8h, v20.8h\n\t"
        "smull	v23.4s, v19.4h, v21.4h\n\t"
        "smull2	v24.4s, v19.8h, v21.8h\n\t"
        "xtn	v25.4h, v23.4s\n\t"
        "xtn2	v25.8h, v24.4s\n\t"
        "mul	v25.8h, v25.8h, v1.h[1]\n\t"
        "smlsl	v23.4s, v25.4h, v1.h[0]\n\t"
        "smlsl2	v24.4s, v25.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v23.4s, #16\n\t"
        "shrn2	v22.8h, v24.4s, #16\n\t"
        "smlal	v26.4s, v22.4h, v0.4h\n\t"
        "smlal2	v27.4s, v22.8h, v0.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v26.4s, #16\n\t"
        "shrn2	v22.8h, v27.4s, #16\n\t"
        "smull	v26.4s, v18.4h, v21.4h\n\t"
        "smull2	v27.4s, v18.8h, v21.8h\n\t"
        "smlal	v26.4s, v19.4h, v20.4h\n\t"
        "smlal2	v27.4s, v19.8h, v20.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v23.4h, v26.4s, #16\n\t"
        "shrn2	v23.8h, v27.4s, #16\n\t"
        "zip1	v24.8h, v22.8h, v23.8h\n\t"
        "zip2	v25.8h, v22.8h, v23.8h\n\t"
        "add	v28.8h, v28.8h, v24.8h\n\t"
        "add	v29.8h, v29.8h, v25.8h\n\t"
        "stp	q28, q29, [%x[r], #160]\n\t"
        "ldp	q28, q29, [%x[r], #192]\n\t"
        "ldr	q0, [x3, #96]\n\t"
        "uzp1	v18.8h, v6.8h, v7.8h\n\t"
        "uzp2	v19.8h, v6.8h, v7.8h\n\t"
        "uzp1	v20.8h, v14.8h, v15.8h\n\t"
        "uzp2	v21.8h, v14.8h, v15.8h\n\t"
        "smull	v26.4s, v18.4h, v20.4h\n\t"
        "smull2	v27.4s, v18.8h, v20.8h\n\t"
        "smull	v23.4s, v19.4h, v21.4h\n\t"
        "smull2	v24.4s, v19.8h, v21.8h\n\t"
        "xtn	v25.4h, v23.4s\n\t"
        "xtn2	v25.8h, v24.4s\n\t"
        "mul	v25.8h, v25.8h, v1.h[1]\n\t"
        "smlsl	v23.4s, v25.4h, v1.h[0]\n\t"
        "smlsl2	v24.4s, v25.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v23.4s, #16\n\t"
        "shrn2	v22.8h, v24.4s, #16\n\t"
        "smlal	v26.4s, v22.4h, v0.4h\n\t"
        "smlal2	v27.4s, v22.8h, v0.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v26.4s, #16\n\t"
        "shrn2	v22.8h, v27.4s, #16\n\t"
        "smull	v26.4s, v18.4h, v21.4h\n\t"
        "smull2	v27.4s, v18.8h, v21.8h\n\t"
        "smlal	v26.4s, v19.4h, v20.4h\n\t"
        "smlal2	v27.4s, v19.8h, v20.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v23.4h, v26.4s, #16\n\t"
        "shrn2	v23.8h, v27.4s, #16\n\t"
        "zip1	v24.8h, v22.8h, v23.8h\n\t"
        "zip2	v25.8h, v22.8h, v23.8h\n\t"
        "add	v28.8h, v28.8h, v24.8h\n\t"
        "add	v29.8h, v29.8h, v25.8h\n\t"
        "stp	q28, q29, [%x[r], #192]\n\t"
        "ldp	q28, q29, [%x[r], #224]\n\t"
        "ldr	q0, [x3, #112]\n\t"
        "uzp1	v18.8h, v8.8h, v9.8h\n\t"
        "uzp2	v19.8h, v8.8h, v9.8h\n\t"
        "uzp1	v20.8h, v16.8h, v17.8h\n\t"
        "uzp2	v21.8h, v16.8h, v17.8h\n\t"
        "smull	v26.4s, v18.4h, v20.4h\n\t"
        "smull2	v27.4s, v18.8h, v20.8h\n\t"
        "smull	v23.4s, v19.4h, v21.4h\n\t"
        "smull2	v24.4s, v19.8h, v21.8h\n\t"
        "xtn	v25.4h, v23.4s\n\t"
        "xtn2	v25.8h, v24.4s\n\t"
        "mul	v25.8h, v25.8h, v1.h[1]\n\t"
        "smlsl	v23.4s, v25.4h, v1.h[0]\n\t"
        "smlsl2	v24.4s, v25.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v23.4s, #16\n\t"
        "shrn2	v22.8h, v24.4s, #16\n\t"
        "smlal	v26.4s, v22.4h, v0.4h\n\t"
        "smlal2	v27.4s, v22.8h, v0.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v26.4s, #16\n\t"
        "shrn2	v22.8h, v27.4s, #16\n\t"
        "smull	v26.4s, v18.4h, v21.4h\n\t"
        "smull2	v27.4s, v18.8h, v21.8h\n\t"
        "smlal	v26.4s, v19.4h, v20.4h\n\t"
        "smlal2	v27.4s, v19.8h, v20.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v23.4h, v26.4s, #16\n\t"
        "shrn2	v23.8h, v27.4s, #16\n\t"
        "zip1	v24.8h, v22.8h, v23.8h\n\t"
        "zip2	v25.8h, v22.8h, v23.8h\n\t"
        "add	v28.8h, v28.8h, v24.8h\n\t"
        "add	v29.8h, v29.8h, v25.8h\n\t"
        "stp	q28, q29, [%x[r], #224]\n\t"
        "ldp	q2, q3, [%x[a], #256]\n\t"
        "ldp	q4, q5, [%x[a], #288]\n\t"
        "ldp	q6, q7, [%x[a], #320]\n\t"
        "ldp	q8, q9, [%x[a], #352]\n\t"
        "ldp	q10, q11, [%x[b], #256]\n\t"
        "ldp	q12, q13, [%x[b], #288]\n\t"
        "ldp	q14, q15, [%x[b], #320]\n\t"
        "ldp	q16, q17, [%x[b], #352]\n\t"
        "ldp	q28, q29, [%x[r], #256]\n\t"
        "ldr	q0, [x3, #128]\n\t"
        "uzp1	v18.8h, v2.8h, v3.8h\n\t"
        "uzp2	v19.8h, v2.8h, v3.8h\n\t"
        "uzp1	v20.8h, v10.8h, v11.8h\n\t"
        "uzp2	v21.8h, v10.8h, v11.8h\n\t"
        "smull	v26.4s, v18.4h, v20.4h\n\t"
        "smull2	v27.4s, v18.8h, v20.8h\n\t"
        "smull	v23.4s, v19.4h, v21.4h\n\t"
        "smull2	v24.4s, v19.8h, v21.8h\n\t"
        "xtn	v25.4h, v23.4s\n\t"
        "xtn2	v25.8h, v24.4s\n\t"
        "mul	v25.8h, v25.8h, v1.h[1]\n\t"
        "smlsl	v23.4s, v25.4h, v1.h[0]\n\t"
        "smlsl2	v24.4s, v25.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v23.4s, #16\n\t"
        "shrn2	v22.8h, v24.4s, #16\n\t"
        "smlal	v26.4s, v22.4h, v0.4h\n\t"
        "smlal2	v27.4s, v22.8h, v0.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v26.4s, #16\n\t"
        "shrn2	v22.8h, v27.4s, #16\n\t"
        "smull	v26.4s, v18.4h, v21.4h\n\t"
        "smull2	v27.4s, v18.8h, v21.8h\n\t"
        "smlal	v26.4s, v19.4h, v20.4h\n\t"
        "smlal2	v27.4s, v19.8h, v20.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v23.4h, v26.4s, #16\n\t"
        "shrn2	v23.8h, v27.4s, #16\n\t"
        "zip1	v24.8h, v22.8h, v23.8h\n\t"
        "zip2	v25.8h, v22.8h, v23.8h\n\t"
        "add	v28.8h, v28.8h, v24.8h\n\t"
        "add	v29.8h, v29.8h, v25.8h\n\t"
        "stp	q28, q29, [%x[r], #256]\n\t"
        "ldp	q28, q29, [%x[r], #288]\n\t"
        "ldr	q0, [x3, #144]\n\t"
        "uzp1	v18.8h, v4.8h, v5.8h\n\t"
        "uzp2	v19.8h, v4.8h, v5.8h\n\t"
        "uzp1	v20.8h, v12.8h, v13.8h\n\t"
        "uzp2	v21.8h, v12.8h, v13.8h\n\t"
        "smull	v26.4s, v18.4h, v20.4h\n\t"
        "smull2	v27.4s, v18.8h, v20.8h\n\t"
        "smull	v23.4s, v19.4h, v21.4h\n\t"
        "smull2	v24.4s, v19.8h, v21.8h\n\t"
        "xtn	v25.4h, v23.4s\n\t"
        "xtn2	v25.8h, v24.4s\n\t"
        "mul	v25.8h, v25.8h, v1.h[1]\n\t"
        "smlsl	v23.4s, v25.4h, v1.h[0]\n\t"
        "smlsl2	v24.4s, v25.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v23.4s, #16\n\t"
        "shrn2	v22.8h, v24.4s, #16\n\t"
        "smlal	v26.4s, v22.4h, v0.4h\n\t"
        "smlal2	v27.4s, v22.8h, v0.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v26.4s, #16\n\t"
        "shrn2	v22.8h, v27.4s, #16\n\t"
        "smull	v26.4s, v18.4h, v21.4h\n\t"
        "smull2	v27.4s, v18.8h, v21.8h\n\t"
        "smlal	v26.4s, v19.4h, v20.4h\n\t"
        "smlal2	v27.4s, v19.8h, v20.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v23.4h, v26.4s, #16\n\t"
        "shrn2	v23.8h, v27.4s, #16\n\t"
        "zip1	v24.8h, v22.8h, v23.8h\n\t"
        "zip2	v25.8h, v22.8h, v23.8h\n\t"
        "add	v28.8h, v28.8h, v24.8h\n\t"
        "add	v29.8h, v29.8h, v25.8h\n\t"
        "stp	q28, q29, [%x[r], #288]\n\t"
        "ldp	q28, q29, [%x[r], #320]\n\t"
        "ldr	q0, [x3, #160]\n\t"
        "uzp1	v18.8h, v6.8h, v7.8h\n\t"
        "uzp2	v19.8h, v6.8h, v7.8h\n\t"
        "uzp1	v20.8h, v14.8h, v15.8h\n\t"
        "uzp2	v21.8h, v14.8h, v15.8h\n\t"
        "smull	v26.4s, v18.4h, v20.4h\n\t"
        "smull2	v27.4s, v18.8h, v20.8h\n\t"
        "smull	v23.4s, v19.4h, v21.4h\n\t"
        "smull2	v24.4s, v19.8h, v21.8h\n\t"
        "xtn	v25.4h, v23.4s\n\t"
        "xtn2	v25.8h, v24.4s\n\t"
        "mul	v25.8h, v25.8h, v1.h[1]\n\t"
        "smlsl	v23.4s, v25.4h, v1.h[0]\n\t"
        "smlsl2	v24.4s, v25.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v23.4s, #16\n\t"
        "shrn2	v22.8h, v24.4s, #16\n\t"
        "smlal	v26.4s, v22.4h, v0.4h\n\t"
        "smlal2	v27.4s, v22.8h, v0.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v26.4s, #16\n\t"
        "shrn2	v22.8h, v27.4s, #16\n\t"
        "smull	v26.4s, v18.4h, v21.4h\n\t"
        "smull2	v27.4s, v18.8h, v21.8h\n\t"
        "smlal	v26.4s, v19.4h, v20.4h\n\t"
        "smlal2	v27.4s, v19.8h, v20.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v23.4h, v26.4s, #16\n\t"
        "shrn2	v23.8h, v27.4s, #16\n\t"
        "zip1	v24.8h, v22.8h, v23.8h\n\t"
        "zip2	v25.8h, v22.8h, v23.8h\n\t"
        "add	v28.8h, v28.8h, v24.8h\n\t"
        "add	v29.8h, v29.8h, v25.8h\n\t"
        "stp	q28, q29, [%x[r], #320]\n\t"
        "ldp	q28, q29, [%x[r], #352]\n\t"
        "ldr	q0, [x3, #176]\n\t"
        "uzp1	v18.8h, v8.8h, v9.8h\n\t"
        "uzp2	v19.8h, v8.8h, v9.8h\n\t"
        "uzp1	v20.8h, v16.8h, v17.8h\n\t"
        "uzp2	v21.8h, v16.8h, v17.8h\n\t"
        "smull	v26.4s, v18.4h, v20.4h\n\t"
        "smull2	v27.4s, v18.8h, v20.8h\n\t"
        "smull	v23.4s, v19.4h, v21.4h\n\t"
        "smull2	v24.4s, v19.8h, v21.8h\n\t"
        "xtn	v25.4h, v23.4s\n\t"
        "xtn2	v25.8h, v24.4s\n\t"
        "mul	v25.8h, v25.8h, v1.h[1]\n\t"
        "smlsl	v23.4s, v25.4h, v1.h[0]\n\t"
        "smlsl2	v24.4s, v25.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v23.4s, #16\n\t"
        "shrn2	v22.8h, v24.4s, #16\n\t"
        "smlal	v26.4s, v22.4h, v0.4h\n\t"
        "smlal2	v27.4s, v22.8h, v0.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v26.4s, #16\n\t"
        "shrn2	v22.8h, v27.4s, #16\n\t"
        "smull	v26.4s, v18.4h, v21.4h\n\t"
        "smull2	v27.4s, v18.8h, v21.8h\n\t"
        "smlal	v26.4s, v19.4h, v20.4h\n\t"
        "smlal2	v27.4s, v19.8h, v20.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v23.4h, v26.4s, #16\n\t"
        "shrn2	v23.8h, v27.4s, #16\n\t"
        "zip1	v24.8h, v22.8h, v23.8h\n\t"
        "zip2	v25.8h, v22.8h, v23.8h\n\t"
        "add	v28.8h, v28.8h, v24.8h\n\t"
        "add	v29.8h, v29.8h, v25.8h\n\t"
        "stp	q28, q29, [%x[r], #352]\n\t"
        "ldp	q2, q3, [%x[a], #384]\n\t"
        "ldp	q4, q5, [%x[a], #416]\n\t"
        "ldp	q6, q7, [%x[a], #448]\n\t"
        "ldp	q8, q9, [%x[a], #480]\n\t"
        "ldp	q10, q11, [%x[b], #384]\n\t"
        "ldp	q12, q13, [%x[b], #416]\n\t"
        "ldp	q14, q15, [%x[b], #448]\n\t"
        "ldp	q16, q17, [%x[b], #480]\n\t"
        "ldp	q28, q29, [%x[r], #384]\n\t"
        "ldr	q0, [x3, #192]\n\t"
        "uzp1	v18.8h, v2.8h, v3.8h\n\t"
        "uzp2	v19.8h, v2.8h, v3.8h\n\t"
        "uzp1	v20.8h, v10.8h, v11.8h\n\t"
        "uzp2	v21.8h, v10.8h, v11.8h\n\t"
        "smull	v26.4s, v18.4h, v20.4h\n\t"
        "smull2	v27.4s, v18.8h, v20.8h\n\t"
        "smull	v23.4s, v19.4h, v21.4h\n\t"
        "smull2	v24.4s, v19.8h, v21.8h\n\t"
        "xtn	v25.4h, v23.4s\n\t"
        "xtn2	v25.8h, v24.4s\n\t"
        "mul	v25.8h, v25.8h, v1.h[1]\n\t"
        "smlsl	v23.4s, v25.4h, v1.h[0]\n\t"
        "smlsl2	v24.4s, v25.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v23.4s, #16\n\t"
        "shrn2	v22.8h, v24.4s, #16\n\t"
        "smlal	v26.4s, v22.4h, v0.4h\n\t"
        "smlal2	v27.4s, v22.8h, v0.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v26.4s, #16\n\t"
        "shrn2	v22.8h, v27.4s, #16\n\t"
        "smull	v26.4s, v18.4h, v21.4h\n\t"
        "smull2	v27.4s, v18.8h, v21.8h\n\t"
        "smlal	v26.4s, v19.4h, v20.4h\n\t"
        "smlal2	v27.4s, v19.8h, v20.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v23.4h, v26.4s, #16\n\t"
        "shrn2	v23.8h, v27.4s, #16\n\t"
        "zip1	v24.8h, v22.8h, v23.8h\n\t"
        "zip2	v25.8h, v22.8h, v23.8h\n\t"
        "add	v28.8h, v28.8h, v24.8h\n\t"
        "add	v29.8h, v29.8h, v25.8h\n\t"
        "stp	q28, q29, [%x[r], #384]\n\t"
        "ldp	q28, q29, [%x[r], #416]\n\t"
        "ldr	q0, [x3, #208]\n\t"
        "uzp1	v18.8h, v4.8h, v5.8h\n\t"
        "uzp2	v19.8h, v4.8h, v5.8h\n\t"
        "uzp1	v20.8h, v12.8h, v13.8h\n\t"
        "uzp2	v21.8h, v12.8h, v13.8h\n\t"
        "smull	v26.4s, v18.4h, v20.4h\n\t"
        "smull2	v27.4s, v18.8h, v20.8h\n\t"
        "smull	v23.4s, v19.4h, v21.4h\n\t"
        "smull2	v24.4s, v19.8h, v21.8h\n\t"
        "xtn	v25.4h, v23.4s\n\t"
        "xtn2	v25.8h, v24.4s\n\t"
        "mul	v25.8h, v25.8h, v1.h[1]\n\t"
        "smlsl	v23.4s, v25.4h, v1.h[0]\n\t"
        "smlsl2	v24.4s, v25.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v23.4s, #16\n\t"
        "shrn2	v22.8h, v24.4s, #16\n\t"
        "smlal	v26.4s, v22.4h, v0.4h\n\t"
        "smlal2	v27.4s, v22.8h, v0.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v26.4s, #16\n\t"
        "shrn2	v22.8h, v27.4s, #16\n\t"
        "smull	v26.4s, v18.4h, v21.4h\n\t"
        "smull2	v27.4s, v18.8h, v21.8h\n\t"
        "smlal	v26.4s, v19.4h, v20.4h\n\t"
        "smlal2	v27.4s, v19.8h, v20.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v23.4h, v26.4s, #16\n\t"
        "shrn2	v23.8h, v27.4s, #16\n\t"
        "zip1	v24.8h, v22.8h, v23.8h\n\t"
        "zip2	v25.8h, v22.8h, v23.8h\n\t"
        "add	v28.8h, v28.8h, v24.8h\n\t"
        "add	v29.8h, v29.8h, v25.8h\n\t"
        "stp	q28, q29, [%x[r], #416]\n\t"
        "ldp	q28, q29, [%x[r], #448]\n\t"
        "ldr	q0, [x3, #224]\n\t"
        "uzp1	v18.8h, v6.8h, v7.8h\n\t"
        "uzp2	v19.8h, v6.8h, v7.8h\n\t"
        "uzp1	v20.8h, v14.8h, v15.8h\n\t"
        "uzp2	v21.8h, v14.8h, v15.8h\n\t"
        "smull	v26.4s, v18.4h, v20.4h\n\t"
        "smull2	v27.4s, v18.8h, v20.8h\n\t"
        "smull	v23.4s, v19.4h, v21.4h\n\t"
        "smull2	v24.4s, v19.8h, v21.8h\n\t"
        "xtn	v25.4h, v23.4s\n\t"
        "xtn2	v25.8h, v24.4s\n\t"
        "mul	v25.8h, v25.8h, v1.h[1]\n\t"
        "smlsl	v23.4s, v25.4h, v1.h[0]\n\t"
        "smlsl2	v24.4s, v25.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v23.4s, #16\n\t"
        "shrn2	v22.8h, v24.4s, #16\n\t"
        "smlal	v26.4s, v22.4h, v0.4h\n\t"
        "smlal2	v27.4s, v22.8h, v0.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v26.4s, #16\n\t"
        "shrn2	v22.8h, v27.4s, #16\n\t"
        "smull	v26.4s, v18.4h, v21.4h\n\t"
        "smull2	v27.4s, v18.8h, v21.8h\n\t"
        "smlal	v26.4s, v19.4h, v20.4h\n\t"
        "smlal2	v27.4s, v19.8h, v20.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v23.4h, v26.4s, #16\n\t"
        "shrn2	v23.8h, v27.4s, #16\n\t"
        "zip1	v24.8h, v22.8h, v23.8h\n\t"
        "zip2	v25.8h, v22.8h, v23.8h\n\t"
        "add	v28.8h, v28.8h, v24.8h\n\t"
        "add	v29.8h, v29.8h, v25.8h\n\t"
        "stp	q28, q29, [%x[r], #448]\n\t"
        "ldp	q28, q29, [%x[r], #480]\n\t"
        "ldr	q0, [x3, #240]\n\t"
        "uzp1	v18.8h, v8.8h, v9.8h\n\t"
        "uzp2	v19.8h, v8.8h, v9.8h\n\t"
        "uzp1	v20.8h, v16.8h, v17.8h\n\t"
        "uzp2	v21.8h, v16.8h, v17.8h\n\t"
        "smull	v26.4s, v18.4h, v20.4h\n\t"
        "smull2	v27.4s, v18.8h, v20.8h\n\t"
        "smull	v23.4s, v19.4h, v21.4h\n\t"
        "smull2	v24.4s, v19.8h, v21.8h\n\t"
        "xtn	v25.4h, v23.4s\n\t"
        "xtn2	v25.8h, v24.4s\n\t"
        "mul	v25.8h, v25.8h, v1.h[1]\n\t"
        "smlsl	v23.4s, v25.4h, v1.h[0]\n\t"
        "smlsl2	v24.4s, v25.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v23.4s, #16\n\t"
        "shrn2	v22.8h, v24.4s, #16\n\t"
        "smlal	v26.4s, v22.4h, v0.4h\n\t"
        "smlal2	v27.4s, v22.8h, v0.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v22.4h, v26.4s, #16\n\t"
        "shrn2	v22.8h, v27.4s, #16\n\t"
        "smull	v26.4s, v18.4h, v21.4h\n\t"
        "smull2	v27.4s, v18.8h, v21.8h\n\t"
        "smlal	v26.4s, v19.4h, v20.4h\n\t"
        "smlal2	v27.4s, v19.8h, v20.8h\n\t"
        "xtn	v24.4h, v26.4s\n\t"
        "xtn2	v24.8h, v27.4s\n\t"
        "mul	v24.8h, v24.8h, v1.h[1]\n\t"
        "smlsl	v26.4s, v24.4h, v1.h[0]\n\t"
        "smlsl2	v27.4s, v24.8h, v1.h[0]\n\t"
        "shrn	v23.4h, v26.4s, #16\n\t"
        "shrn2	v23.8h, v27.4s, #16\n\t"
        "zip1	v24.8h, v22.8h, v23.8h\n\t"
        "zip2	v25.8h, v22.8h, v23.8h\n\t"
        "add	v28.8h, v28.8h, v24.8h\n\t"
        "add	v29.8h, v29.8h, v25.8h\n\t"
        "stp	q28, q29, [%x[r], #480]\n\t"
        : [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        : [L_kyber_aarch64_q] "S" (L_kyber_aarch64_q), [L_kyber_aarch64_consts] "S" (L_kyber_aarch64_consts), [L_sha3_aarch64_r] "S" (L_sha3_aarch64_r), [L_kyber_aarch64_zetas] "S" (L_kyber_aarch64_zetas), [L_kyber_aarch64_zetas_qinv] "S" (L_kyber_aarch64_zetas_qinv), [L_kyber_aarch64_zetas_inv] "S" (L_kyber_aarch64_zetas_inv), [L_kyber_aarch64_zetas_inv_qinv] "S" (L_kyber_aarch64_zetas_inv_qinv), [L_kyber_aarch64_zetas_mul] "S" (L_kyber_aarch64_zetas_mul)
        : "memory", "x3", "x4", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15", "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26", "v27", "v28", "v29", "cc"
    );
}

void kyber_csubq_neon(sword16* p)
{
    __asm__ __volatile__ (
#ifndef __APPLE__
        "adrp x1, %[L_kyber_aarch64_q]\n\t"
        "add  x1, x1, :lo12:%[L_kyber_aarch64_q]\n\t"
#else
        "adrp x1, %[L_kyber_aarch64_q]@PAGE\n\t"
        "add  x1, x1, %[L_kyber_aarch64_q]@PAGEOFF\n\t"
#endif /* __APPLE__ */
        "ldr	q20, [x1]\n\t"
        "ld4	{v0.8h, v1.8h, v2.8h, v3.8h}, [%x[p]], #0x40\n\t"
        "ld4	{v4.8h, v5.8h, v6.8h, v7.8h}, [%x[p]], #0x40\n\t"
        "ld4	{v8.8h, v9.8h, v10.8h, v11.8h}, [%x[p]], #0x40\n\t"
        "ld4	{v12.8h, v13.8h, v14.8h, v15.8h}, [%x[p]], #0x40\n\t"
        "sub	%x[p], %x[p], #0x100\n\t"
        "sub	v0.8h, v0.8h, v20.8h\n\t"
        "sub	v1.8h, v1.8h, v20.8h\n\t"
        "sub	v2.8h, v2.8h, v20.8h\n\t"
        "sub	v3.8h, v3.8h, v20.8h\n\t"
        "sub	v4.8h, v4.8h, v20.8h\n\t"
        "sub	v5.8h, v5.8h, v20.8h\n\t"
        "sub	v6.8h, v6.8h, v20.8h\n\t"
        "sub	v7.8h, v7.8h, v20.8h\n\t"
        "sub	v8.8h, v8.8h, v20.8h\n\t"
        "sub	v9.8h, v9.8h, v20.8h\n\t"
        "sub	v10.8h, v10.8h, v20.8h\n\t"
        "sub	v11.8h, v11.8h, v20.8h\n\t"
        "sub	v12.8h, v12.8h, v20.8h\n\t"
        "sub	v13.8h, v13.8h, v20.8h\n\t"
        "sub	v14.8h, v14.8h, v20.8h\n\t"
        "sub	v15.8h, v15.8h, v20.8h\n\t"
        "sshr	v16.8h, v0.8h, #15\n\t"
        "sshr	v17.8h, v1.8h, #15\n\t"
        "sshr	v18.8h, v2.8h, #15\n\t"
        "sshr	v19.8h, v3.8h, #15\n\t"
        "and	v16.16b, v16.16b, v20.16b\n\t"
        "and	v17.16b, v17.16b, v20.16b\n\t"
        "and	v18.16b, v18.16b, v20.16b\n\t"
        "and	v19.16b, v19.16b, v20.16b\n\t"
        "add	v0.8h, v0.8h, v16.8h\n\t"
        "add	v1.8h, v1.8h, v17.8h\n\t"
        "add	v2.8h, v2.8h, v18.8h\n\t"
        "add	v3.8h, v3.8h, v19.8h\n\t"
        "sshr	v16.8h, v4.8h, #15\n\t"
        "sshr	v17.8h, v5.8h, #15\n\t"
        "sshr	v18.8h, v6.8h, #15\n\t"
        "sshr	v19.8h, v7.8h, #15\n\t"
        "and	v16.16b, v16.16b, v20.16b\n\t"
        "and	v17.16b, v17.16b, v20.16b\n\t"
        "and	v18.16b, v18.16b, v20.16b\n\t"
        "and	v19.16b, v19.16b, v20.16b\n\t"
        "add	v4.8h, v4.8h, v16.8h\n\t"
        "add	v5.8h, v5.8h, v17.8h\n\t"
        "add	v6.8h, v6.8h, v18.8h\n\t"
        "add	v7.8h, v7.8h, v19.8h\n\t"
        "sshr	v16.8h, v8.8h, #15\n\t"
        "sshr	v17.8h, v9.8h, #15\n\t"
        "sshr	v18.8h, v10.8h, #15\n\t"
        "sshr	v19.8h, v11.8h, #15\n\t"
        "and	v16.16b, v16.16b, v20.16b\n\t"
        "and	v17.16b, v17.16b, v20.16b\n\t"
        "and	v18.16b, v18.16b, v20.16b\n\t"
        "and	v19.16b, v19.16b, v20.16b\n\t"
        "add	v8.8h, v8.8h, v16.8h\n\t"
        "add	v9.8h, v9.8h, v17.8h\n\t"
        "add	v10.8h, v10.8h, v18.8h\n\t"
        "add	v11.8h, v11.8h, v19.8h\n\t"
        "sshr	v16.8h, v12.8h, #15\n\t"
        "sshr	v17.8h, v13.8h, #15\n\t"
        "sshr	v18.8h, v14.8h, #15\n\t"
        "sshr	v19.8h, v15.8h, #15\n\t"
        "and	v16.16b, v16.16b, v20.16b\n\t"
        "and	v17.16b, v17.16b, v20.16b\n\t"
        "and	v18.16b, v18.16b, v20.16b\n\t"
        "and	v19.16b, v19.16b, v20.16b\n\t"
        "add	v12.8h, v12.8h, v16.8h\n\t"
        "add	v13.8h, v13.8h, v17.8h\n\t"
        "add	v14.8h, v14.8h, v18.8h\n\t"
        "add	v15.8h, v15.8h, v19.8h\n\t"
        "st4	{v0.8h, v1.8h, v2.8h, v3.8h}, [%x[p]], #0x40\n\t"
        "st4	{v4.8h, v5.8h, v6.8h, v7.8h}, [%x[p]], #0x40\n\t"
        "st4	{v8.8h, v9.8h, v10.8h, v11.8h}, [%x[p]], #0x40\n\t"
        "st4	{v12.8h, v13.8h, v14.8h, v15.8h}, [%x[p]], #0x40\n\t"
        "ld4	{v0.8h, v1.8h, v2.8h, v3.8h}, [%x[p]], #0x40\n\t"
        "ld4	{v4.8h, v5.8h, v6.8h, v7.8h}, [%x[p]], #0x40\n\t"
        "ld4	{v8.8h, v9.8h, v10.8h, v11.8h}, [%x[p]], #0x40\n\t"
        "ld4	{v12.8h, v13.8h, v14.8h, v15.8h}, [%x[p]], #0x40\n\t"
        "sub	%x[p], %x[p], #0x100\n\t"
        "sub	v0.8h, v0.8h, v20.8h\n\t"
        "sub	v1.8h, v1.8h, v20.8h\n\t"
        "sub	v2.8h, v2.8h, v20.8h\n\t"
        "sub	v3.8h, v3.8h, v20.8h\n\t"
        "sub	v4.8h, v4.8h, v20.8h\n\t"
        "sub	v5.8h, v5.8h, v20.8h\n\t"
        "sub	v6.8h, v6.8h, v20.8h\n\t"
        "sub	v7.8h, v7.8h, v20.8h\n\t"
        "sub	v8.8h, v8.8h, v20.8h\n\t"
        "sub	v9.8h, v9.8h, v20.8h\n\t"
        "sub	v10.8h, v10.8h, v20.8h\n\t"
        "sub	v11.8h, v11.8h, v20.8h\n\t"
        "sub	v12.8h, v12.8h, v20.8h\n\t"
        "sub	v13.8h, v13.8h, v20.8h\n\t"
        "sub	v14.8h, v14.8h, v20.8h\n\t"
        "sub	v15.8h, v15.8h, v20.8h\n\t"
        "sshr	v16.8h, v0.8h, #15\n\t"
        "sshr	v17.8h, v1.8h, #15\n\t"
        "sshr	v18.8h, v2.8h, #15\n\t"
        "sshr	v19.8h, v3.8h, #15\n\t"
        "and	v16.16b, v16.16b, v20.16b\n\t"
        "and	v17.16b, v17.16b, v20.16b\n\t"
        "and	v18.16b, v18.16b, v20.16b\n\t"
        "and	v19.16b, v19.16b, v20.16b\n\t"
        "add	v0.8h, v0.8h, v16.8h\n\t"
        "add	v1.8h, v1.8h, v17.8h\n\t"
        "add	v2.8h, v2.8h, v18.8h\n\t"
        "add	v3.8h, v3.8h, v19.8h\n\t"
        "sshr	v16.8h, v4.8h, #15\n\t"
        "sshr	v17.8h, v5.8h, #15\n\t"
        "sshr	v18.8h, v6.8h, #15\n\t"
        "sshr	v19.8h, v7.8h, #15\n\t"
        "and	v16.16b, v16.16b, v20.16b\n\t"
        "and	v17.16b, v17.16b, v20.16b\n\t"
        "and	v18.16b, v18.16b, v20.16b\n\t"
        "and	v19.16b, v19.16b, v20.16b\n\t"
        "add	v4.8h, v4.8h, v16.8h\n\t"
        "add	v5.8h, v5.8h, v17.8h\n\t"
        "add	v6.8h, v6.8h, v18.8h\n\t"
        "add	v7.8h, v7.8h, v19.8h\n\t"
        "sshr	v16.8h, v8.8h, #15\n\t"
        "sshr	v17.8h, v9.8h, #15\n\t"
        "sshr	v18.8h, v10.8h, #15\n\t"
        "sshr	v19.8h, v11.8h, #15\n\t"
        "and	v16.16b, v16.16b, v20.16b\n\t"
        "and	v17.16b, v17.16b, v20.16b\n\t"
        "and	v18.16b, v18.16b, v20.16b\n\t"
        "and	v19.16b, v19.16b, v20.16b\n\t"
        "add	v8.8h, v8.8h, v16.8h\n\t"
        "add	v9.8h, v9.8h, v17.8h\n\t"
        "add	v10.8h, v10.8h, v18.8h\n\t"
        "add	v11.8h, v11.8h, v19.8h\n\t"
        "sshr	v16.8h, v12.8h, #15\n\t"
        "sshr	v17.8h, v13.8h, #15\n\t"
        "sshr	v18.8h, v14.8h, #15\n\t"
        "sshr	v19.8h, v15.8h, #15\n\t"
        "and	v16.16b, v16.16b, v20.16b\n\t"
        "and	v17.16b, v17.16b, v20.16b\n\t"
        "and	v18.16b, v18.16b, v20.16b\n\t"
        "and	v19.16b, v19.16b, v20.16b\n\t"
        "add	v12.8h, v12.8h, v16.8h\n\t"
        "add	v13.8h, v13.8h, v17.8h\n\t"
        "add	v14.8h, v14.8h, v18.8h\n\t"
        "add	v15.8h, v15.8h, v19.8h\n\t"
        "st4	{v0.8h, v1.8h, v2.8h, v3.8h}, [%x[p]], #0x40\n\t"
        "st4	{v4.8h, v5.8h, v6.8h, v7.8h}, [%x[p]], #0x40\n\t"
        "st4	{v8.8h, v9.8h, v10.8h, v11.8h}, [%x[p]], #0x40\n\t"
        "st4	{v12.8h, v13.8h, v14.8h, v15.8h}, [%x[p]], #0x40\n\t"
        : [p] "+r" (p)
        : [L_kyber_aarch64_q] "S" (L_kyber_aarch64_q), [L_kyber_aarch64_consts] "S" (L_kyber_aarch64_consts), [L_sha3_aarch64_r] "S" (L_sha3_aarch64_r), [L_kyber_aarch64_zetas] "S" (L_kyber_aarch64_zetas), [L_kyber_aarch64_zetas_qinv] "S" (L_kyber_aarch64_zetas_qinv), [L_kyber_aarch64_zetas_inv] "S" (L_kyber_aarch64_zetas_inv), [L_kyber_aarch64_zetas_inv_qinv] "S" (L_kyber_aarch64_zetas_inv_qinv), [L_kyber_aarch64_zetas_mul] "S" (L_kyber_aarch64_zetas_mul)
        : "memory", "x1", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15", "v16", "v17", "v18", "v19", "v20", "cc"
    );
}

void kyber_add_reduce(sword16* r, const sword16* a)
{
    __asm__ __volatile__ (
#ifndef __APPLE__
        "adrp x2, %[L_kyber_aarch64_consts]\n\t"
        "add  x2, x2, :lo12:%[L_kyber_aarch64_consts]\n\t"
#else
        "adrp x2, %[L_kyber_aarch64_consts]@PAGE\n\t"
        "add  x2, x2, %[L_kyber_aarch64_consts]@PAGEOFF\n\t"
#endif /* __APPLE__ */
        "ldr	q0, [x2]\n\t"
        "ld4	{v1.8h, v2.8h, v3.8h, v4.8h}, [%x[r]], #0x40\n\t"
        "ld4	{v5.8h, v6.8h, v7.8h, v8.8h}, [%x[r]], #0x40\n\t"
        "ld4	{v9.8h, v10.8h, v11.8h, v12.8h}, [%x[a]], #0x40\n\t"
        "ld4	{v13.8h, v14.8h, v15.8h, v16.8h}, [%x[a]], #0x40\n\t"
        "sub	%x[r], %x[r], #0x80\n\t"
        "add	v1.8h, v1.8h, v9.8h\n\t"
        "add	v2.8h, v2.8h, v10.8h\n\t"
        "add	v3.8h, v3.8h, v11.8h\n\t"
        "add	v4.8h, v4.8h, v12.8h\n\t"
        "add	v5.8h, v5.8h, v13.8h\n\t"
        "add	v6.8h, v6.8h, v14.8h\n\t"
        "add	v7.8h, v7.8h, v15.8h\n\t"
        "add	v8.8h, v8.8h, v16.8h\n\t"
        "sqdmulh	v17.8h, v1.8h, v0.h[2]\n\t"
        "sqdmulh	v18.8h, v2.8h, v0.h[2]\n\t"
        "sshr	v17.8h, v17.8h, #11\n\t"
        "sshr	v18.8h, v18.8h, #11\n\t"
        "mls	v1.8h, v17.8h, v0.h[0]\n\t"
        "mls	v2.8h, v18.8h, v0.h[0]\n\t"
        "sqdmulh	v17.8h, v3.8h, v0.h[2]\n\t"
        "sqdmulh	v18.8h, v4.8h, v0.h[2]\n\t"
        "sshr	v17.8h, v17.8h, #11\n\t"
        "sshr	v18.8h, v18.8h, #11\n\t"
        "mls	v3.8h, v17.8h, v0.h[0]\n\t"
        "mls	v4.8h, v18.8h, v0.h[0]\n\t"
        "sqdmulh	v17.8h, v5.8h, v0.h[2]\n\t"
        "sqdmulh	v18.8h, v6.8h, v0.h[2]\n\t"
        "sshr	v17.8h, v17.8h, #11\n\t"
        "sshr	v18.8h, v18.8h, #11\n\t"
        "mls	v5.8h, v17.8h, v0.h[0]\n\t"
        "mls	v6.8h, v18.8h, v0.h[0]\n\t"
        "sqdmulh	v17.8h, v7.8h, v0.h[2]\n\t"
        "sqdmulh	v18.8h, v8.8h, v0.h[2]\n\t"
        "sshr	v17.8h, v17.8h, #11\n\t"
        "sshr	v18.8h, v18.8h, #11\n\t"
        "mls	v7.8h, v17.8h, v0.h[0]\n\t"
        "mls	v8.8h, v18.8h, v0.h[0]\n\t"
        "st4	{v1.8h, v2.8h, v3.8h, v4.8h}, [%x[r]], #0x40\n\t"
        "st4	{v5.8h, v6.8h, v7.8h, v8.8h}, [%x[r]], #0x40\n\t"
        "ld4	{v1.8h, v2.8h, v3.8h, v4.8h}, [%x[r]], #0x40\n\t"
        "ld4	{v5.8h, v6.8h, v7.8h, v8.8h}, [%x[r]], #0x40\n\t"
        "ld4	{v9.8h, v10.8h, v11.8h, v12.8h}, [%x[a]], #0x40\n\t"
        "ld4	{v13.8h, v14.8h, v15.8h, v16.8h}, [%x[a]], #0x40\n\t"
        "sub	%x[r], %x[r], #0x80\n\t"
        "add	v1.8h, v1.8h, v9.8h\n\t"
        "add	v2.8h, v2.8h, v10.8h\n\t"
        "add	v3.8h, v3.8h, v11.8h\n\t"
        "add	v4.8h, v4.8h, v12.8h\n\t"
        "add	v5.8h, v5.8h, v13.8h\n\t"
        "add	v6.8h, v6.8h, v14.8h\n\t"
        "add	v7.8h, v7.8h, v15.8h\n\t"
        "add	v8.8h, v8.8h, v16.8h\n\t"
        "sqdmulh	v17.8h, v1.8h, v0.h[2]\n\t"
        "sqdmulh	v18.8h, v2.8h, v0.h[2]\n\t"
        "sshr	v17.8h, v17.8h, #11\n\t"
        "sshr	v18.8h, v18.8h, #11\n\t"
        "mls	v1.8h, v17.8h, v0.h[0]\n\t"
        "mls	v2.8h, v18.8h, v0.h[0]\n\t"
        "sqdmulh	v17.8h, v3.8h, v0.h[2]\n\t"
        "sqdmulh	v18.8h, v4.8h, v0.h[2]\n\t"
        "sshr	v17.8h, v17.8h, #11\n\t"
        "sshr	v18.8h, v18.8h, #11\n\t"
        "mls	v3.8h, v17.8h, v0.h[0]\n\t"
        "mls	v4.8h, v18.8h, v0.h[0]\n\t"
        "sqdmulh	v17.8h, v5.8h, v0.h[2]\n\t"
        "sqdmulh	v18.8h, v6.8h, v0.h[2]\n\t"
        "sshr	v17.8h, v17.8h, #11\n\t"
        "sshr	v18.8h, v18.8h, #11\n\t"
        "mls	v5.8h, v17.8h, v0.h[0]\n\t"
        "mls	v6.8h, v18.8h, v0.h[0]\n\t"
        "sqdmulh	v17.8h, v7.8h, v0.h[2]\n\t"
        "sqdmulh	v18.8h, v8.8h, v0.h[2]\n\t"
        "sshr	v17.8h, v17.8h, #11\n\t"
        "sshr	v18.8h, v18.8h, #11\n\t"
        "mls	v7.8h, v17.8h, v0.h[0]\n\t"
        "mls	v8.8h, v18.8h, v0.h[0]\n\t"
        "st4	{v1.8h, v2.8h, v3.8h, v4.8h}, [%x[r]], #0x40\n\t"
        "st4	{v5.8h, v6.8h, v7.8h, v8.8h}, [%x[r]], #0x40\n\t"
        "ld4	{v1.8h, v2.8h, v3.8h, v4.8h}, [%x[r]], #0x40\n\t"
        "ld4	{v5.8h, v6.8h, v7.8h, v8.8h}, [%x[r]], #0x40\n\t"
        "ld4	{v9.8h, v10.8h, v11.8h, v12.8h}, [%x[a]], #0x40\n\t"
        "ld4	{v13.8h, v14.8h, v15.8h, v16.8h}, [%x[a]], #0x40\n\t"
        "sub	%x[r], %x[r], #0x80\n\t"
        "add	v1.8h, v1.8h, v9.8h\n\t"
        "add	v2.8h, v2.8h, v10.8h\n\t"
        "add	v3.8h, v3.8h, v11.8h\n\t"
        "add	v4.8h, v4.8h, v12.8h\n\t"
        "add	v5.8h, v5.8h, v13.8h\n\t"
        "add	v6.8h, v6.8h, v14.8h\n\t"
        "add	v7.8h, v7.8h, v15.8h\n\t"
        "add	v8.8h, v8.8h, v16.8h\n\t"
        "sqdmulh	v17.8h, v1.8h, v0.h[2]\n\t"
        "sqdmulh	v18.8h, v2.8h, v0.h[2]\n\t"
        "sshr	v17.8h, v17.8h, #11\n\t"
        "sshr	v18.8h, v18.8h, #11\n\t"
        "mls	v1.8h, v17.8h, v0.h[0]\n\t"
        "mls	v2.8h, v18.8h, v0.h[0]\n\t"
        "sqdmulh	v17.8h, v3.8h, v0.h[2]\n\t"
        "sqdmulh	v18.8h, v4.8h, v0.h[2]\n\t"
        "sshr	v17.8h, v17.8h, #11\n\t"
        "sshr	v18.8h, v18.8h, #11\n\t"
        "mls	v3.8h, v17.8h, v0.h[0]\n\t"
        "mls	v4.8h, v18.8h, v0.h[0]\n\t"
        "sqdmulh	v17.8h, v5.8h, v0.h[2]\n\t"
        "sqdmulh	v18.8h, v6.8h, v0.h[2]\n\t"
        "sshr	v17.8h, v17.8h, #11\n\t"
        "sshr	v18.8h, v18.8h, #11\n\t"
        "mls	v5.8h, v17.8h, v0.h[0]\n\t"
        "mls	v6.8h, v18.8h, v0.h[0]\n\t"
        "sqdmulh	v17.8h, v7.8h, v0.h[2]\n\t"
        "sqdmulh	v18.8h, v8.8h, v0.h[2]\n\t"
        "sshr	v17.8h, v17.8h, #11\n\t"
        "sshr	v18.8h, v18.8h, #11\n\t"
        "mls	v7.8h, v17.8h, v0.h[0]\n\t"
        "mls	v8.8h, v18.8h, v0.h[0]\n\t"
        "st4	{v1.8h, v2.8h, v3.8h, v4.8h}, [%x[r]], #0x40\n\t"
        "st4	{v5.8h, v6.8h, v7.8h, v8.8h}, [%x[r]], #0x40\n\t"
        "ld4	{v1.8h, v2.8h, v3.8h, v4.8h}, [%x[r]], #0x40\n\t"
        "ld4	{v5.8h, v6.8h, v7.8h, v8.8h}, [%x[r]], #0x40\n\t"
        "ld4	{v9.8h, v10.8h, v11.8h, v12.8h}, [%x[a]], #0x40\n\t"
        "ld4	{v13.8h, v14.8h, v15.8h, v16.8h}, [%x[a]], #0x40\n\t"
        "sub	%x[r], %x[r], #0x80\n\t"
        "add	v1.8h, v1.8h, v9.8h\n\t"
        "add	v2.8h, v2.8h, v10.8h\n\t"
        "add	v3.8h, v3.8h, v11.8h\n\t"
        "add	v4.8h, v4.8h, v12.8h\n\t"
        "add	v5.8h, v5.8h, v13.8h\n\t"
        "add	v6.8h, v6.8h, v14.8h\n\t"
        "add	v7.8h, v7.8h, v15.8h\n\t"
        "add	v8.8h, v8.8h, v16.8h\n\t"
        "sqdmulh	v17.8h, v1.8h, v0.h[2]\n\t"
        "sqdmulh	v18.8h, v2.8h, v0.h[2]\n\t"
        "sshr	v17.8h, v17.8h, #11\n\t"
        "sshr	v18.8h, v18.8h, #11\n\t"
        "mls	v1.8h, v17.8h, v0.h[0]\n\t"
        "mls	v2.8h, v18.8h, v0.h[0]\n\t"
        "sqdmulh	v17.8h, v3.8h, v0.h[2]\n\t"
        "sqdmulh	v18.8h, v4.8h, v0.h[2]\n\t"
        "sshr	v17.8h, v17.8h, #11\n\t"
        "sshr	v18.8h, v18.8h, #11\n\t"
        "mls	v3.8h, v17.8h, v0.h[0]\n\t"
        "mls	v4.8h, v18.8h, v0.h[0]\n\t"
        "sqdmulh	v17.8h, v5.8h, v0.h[2]\n\t"
        "sqdmulh	v18.8h, v6.8h, v0.h[2]\n\t"
        "sshr	v17.8h, v17.8h, #11\n\t"
        "sshr	v18.8h, v18.8h, #11\n\t"
        "mls	v5.8h, v17.8h, v0.h[0]\n\t"
        "mls	v6.8h, v18.8h, v0.h[0]\n\t"
        "sqdmulh	v17.8h, v7.8h, v0.h[2]\n\t"
        "sqdmulh	v18.8h, v8.8h, v0.h[2]\n\t"
        "sshr	v17.8h, v17.8h, #11\n\t"
        "sshr	v18.8h, v18.8h, #11\n\t"
        "mls	v7.8h, v17.8h, v0.h[0]\n\t"
        "mls	v8.8h, v18.8h, v0.h[0]\n\t"
        "st4	{v1.8h, v2.8h, v3.8h, v4.8h}, [%x[r]], #0x40\n\t"
        "st4	{v5.8h, v6.8h, v7.8h, v8.8h}, [%x[r]], #0x40\n\t"
        : [r] "+r" (r), [a] "+r" (a)
        : [L_kyber_aarch64_q] "S" (L_kyber_aarch64_q), [L_kyber_aarch64_consts] "S" (L_kyber_aarch64_consts), [L_sha3_aarch64_r] "S" (L_sha3_aarch64_r), [L_kyber_aarch64_zetas] "S" (L_kyber_aarch64_zetas), [L_kyber_aarch64_zetas_qinv] "S" (L_kyber_aarch64_zetas_qinv), [L_kyber_aarch64_zetas_inv] "S" (L_kyber_aarch64_zetas_inv), [L_kyber_aarch64_zetas_inv_qinv] "S" (L_kyber_aarch64_zetas_inv_qinv), [L_kyber_aarch64_zetas_mul] "S" (L_kyber_aarch64_zetas_mul)
        : "memory", "x2", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15", "v16", "v17", "v18", "cc"
    );
}

void kyber_add3_reduce(sword16* r, const sword16* a, const sword16* b)
{
    __asm__ __volatile__ (
#ifndef __APPLE__
        "adrp x3, %[L_kyber_aarch64_consts]\n\t"
        "add  x3, x3, :lo12:%[L_kyber_aarch64_consts]\n\t"
#else
        "adrp x3, %[L_kyber_aarch64_consts]@PAGE\n\t"
        "add  x3, x3, %[L_kyber_aarch64_consts]@PAGEOFF\n\t"
#endif /* __APPLE__ */
        "ldr	q0, [x3]\n\t"
        "ld4	{v1.8h, v2.8h, v3.8h, v4.8h}, [%x[r]], #0x40\n\t"
        "ld4	{v5.8h, v6.8h, v7.8h, v8.8h}, [%x[r]], #0x40\n\t"
        "ld4	{v9.8h, v10.8h, v11.8h, v12.8h}, [%x[a]], #0x40\n\t"
        "ld4	{v13.8h, v14.8h, v15.8h, v16.8h}, [%x[a]], #0x40\n\t"
        "ld4	{v17.8h, v18.8h, v19.8h, v20.8h}, [%x[b]], #0x40\n\t"
        "ld4	{v21.8h, v22.8h, v23.8h, v24.8h}, [%x[b]], #0x40\n\t"
        "sub	%x[r], %x[r], #0x80\n\t"
        "add	v1.8h, v1.8h, v9.8h\n\t"
        "add	v2.8h, v2.8h, v10.8h\n\t"
        "add	v3.8h, v3.8h, v11.8h\n\t"
        "add	v4.8h, v4.8h, v12.8h\n\t"
        "add	v5.8h, v5.8h, v13.8h\n\t"
        "add	v6.8h, v6.8h, v14.8h\n\t"
        "add	v7.8h, v7.8h, v15.8h\n\t"
        "add	v8.8h, v8.8h, v16.8h\n\t"
        "add	v1.8h, v1.8h, v17.8h\n\t"
        "add	v2.8h, v2.8h, v18.8h\n\t"
        "add	v3.8h, v3.8h, v19.8h\n\t"
        "add	v4.8h, v4.8h, v20.8h\n\t"
        "add	v5.8h, v5.8h, v21.8h\n\t"
        "add	v6.8h, v6.8h, v22.8h\n\t"
        "add	v7.8h, v7.8h, v23.8h\n\t"
        "add	v8.8h, v8.8h, v24.8h\n\t"
        "sqdmulh	v25.8h, v1.8h, v0.h[2]\n\t"
        "sqdmulh	v26.8h, v2.8h, v0.h[2]\n\t"
        "sshr	v25.8h, v25.8h, #11\n\t"
        "sshr	v26.8h, v26.8h, #11\n\t"
        "mls	v1.8h, v25.8h, v0.h[0]\n\t"
        "mls	v2.8h, v26.8h, v0.h[0]\n\t"
        "sqdmulh	v25.8h, v3.8h, v0.h[2]\n\t"
        "sqdmulh	v26.8h, v4.8h, v0.h[2]\n\t"
        "sshr	v25.8h, v25.8h, #11\n\t"
        "sshr	v26.8h, v26.8h, #11\n\t"
        "mls	v3.8h, v25.8h, v0.h[0]\n\t"
        "mls	v4.8h, v26.8h, v0.h[0]\n\t"
        "sqdmulh	v25.8h, v5.8h, v0.h[2]\n\t"
        "sqdmulh	v26.8h, v6.8h, v0.h[2]\n\t"
        "sshr	v25.8h, v25.8h, #11\n\t"
        "sshr	v26.8h, v26.8h, #11\n\t"
        "mls	v5.8h, v25.8h, v0.h[0]\n\t"
        "mls	v6.8h, v26.8h, v0.h[0]\n\t"
        "sqdmulh	v25.8h, v7.8h, v0.h[2]\n\t"
        "sqdmulh	v26.8h, v8.8h, v0.h[2]\n\t"
        "sshr	v25.8h, v25.8h, #11\n\t"
        "sshr	v26.8h, v26.8h, #11\n\t"
        "mls	v7.8h, v25.8h, v0.h[0]\n\t"
        "mls	v8.8h, v26.8h, v0.h[0]\n\t"
        "st4	{v1.8h, v2.8h, v3.8h, v4.8h}, [%x[r]], #0x40\n\t"
        "st4	{v5.8h, v6.8h, v7.8h, v8.8h}, [%x[r]], #0x40\n\t"
        "ld4	{v1.8h, v2.8h, v3.8h, v4.8h}, [%x[r]], #0x40\n\t"
        "ld4	{v5.8h, v6.8h, v7.8h, v8.8h}, [%x[r]], #0x40\n\t"
        "ld4	{v9.8h, v10.8h, v11.8h, v12.8h}, [%x[a]], #0x40\n\t"
        "ld4	{v13.8h, v14.8h, v15.8h, v16.8h}, [%x[a]], #0x40\n\t"
        "ld4	{v17.8h, v18.8h, v19.8h, v20.8h}, [%x[b]], #0x40\n\t"
        "ld4	{v21.8h, v22.8h, v23.8h, v24.8h}, [%x[b]], #0x40\n\t"
        "sub	%x[r], %x[r], #0x80\n\t"
        "add	v1.8h, v1.8h, v9.8h\n\t"
        "add	v2.8h, v2.8h, v10.8h\n\t"
        "add	v3.8h, v3.8h, v11.8h\n\t"
        "add	v4.8h, v4.8h, v12.8h\n\t"
        "add	v5.8h, v5.8h, v13.8h\n\t"
        "add	v6.8h, v6.8h, v14.8h\n\t"
        "add	v7.8h, v7.8h, v15.8h\n\t"
        "add	v8.8h, v8.8h, v16.8h\n\t"
        "add	v1.8h, v1.8h, v17.8h\n\t"
        "add	v2.8h, v2.8h, v18.8h\n\t"
        "add	v3.8h, v3.8h, v19.8h\n\t"
        "add	v4.8h, v4.8h, v20.8h\n\t"
        "add	v5.8h, v5.8h, v21.8h\n\t"
        "add	v6.8h, v6.8h, v22.8h\n\t"
        "add	v7.8h, v7.8h, v23.8h\n\t"
        "add	v8.8h, v8.8h, v24.8h\n\t"
        "sqdmulh	v25.8h, v1.8h, v0.h[2]\n\t"
        "sqdmulh	v26.8h, v2.8h, v0.h[2]\n\t"
        "sshr	v25.8h, v25.8h, #11\n\t"
        "sshr	v26.8h, v26.8h, #11\n\t"
        "mls	v1.8h, v25.8h, v0.h[0]\n\t"
        "mls	v2.8h, v26.8h, v0.h[0]\n\t"
        "sqdmulh	v25.8h, v3.8h, v0.h[2]\n\t"
        "sqdmulh	v26.8h, v4.8h, v0.h[2]\n\t"
        "sshr	v25.8h, v25.8h, #11\n\t"
        "sshr	v26.8h, v26.8h, #11\n\t"
        "mls	v3.8h, v25.8h, v0.h[0]\n\t"
        "mls	v4.8h, v26.8h, v0.h[0]\n\t"
        "sqdmulh	v25.8h, v5.8h, v0.h[2]\n\t"
        "sqdmulh	v26.8h, v6.8h, v0.h[2]\n\t"
        "sshr	v25.8h, v25.8h, #11\n\t"
        "sshr	v26.8h, v26.8h, #11\n\t"
        "mls	v5.8h, v25.8h, v0.h[0]\n\t"
        "mls	v6.8h, v26.8h, v0.h[0]\n\t"
        "sqdmulh	v25.8h, v7.8h, v0.h[2]\n\t"
        "sqdmulh	v26.8h, v8.8h, v0.h[2]\n\t"
        "sshr	v25.8h, v25.8h, #11\n\t"
        "sshr	v26.8h, v26.8h, #11\n\t"
        "mls	v7.8h, v25.8h, v0.h[0]\n\t"
        "mls	v8.8h, v26.8h, v0.h[0]\n\t"
        "st4	{v1.8h, v2.8h, v3.8h, v4.8h}, [%x[r]], #0x40\n\t"
        "st4	{v5.8h, v6.8h, v7.8h, v8.8h}, [%x[r]], #0x40\n\t"
        "ld4	{v1.8h, v2.8h, v3.8h, v4.8h}, [%x[r]], #0x40\n\t"
        "ld4	{v5.8h, v6.8h, v7.8h, v8.8h}, [%x[r]], #0x40\n\t"
        "ld4	{v9.8h, v10.8h, v11.8h, v12.8h}, [%x[a]], #0x40\n\t"
        "ld4	{v13.8h, v14.8h, v15.8h, v16.8h}, [%x[a]], #0x40\n\t"
        "ld4	{v17.8h, v18.8h, v19.8h, v20.8h}, [%x[b]], #0x40\n\t"
        "ld4	{v21.8h, v22.8h, v23.8h, v24.8h}, [%x[b]], #0x40\n\t"
        "sub	%x[r], %x[r], #0x80\n\t"
        "add	v1.8h, v1.8h, v9.8h\n\t"
        "add	v2.8h, v2.8h, v10.8h\n\t"
        "add	v3.8h, v3.8h, v11.8h\n\t"
        "add	v4.8h, v4.8h, v12.8h\n\t"
        "add	v5.8h, v5.8h, v13.8h\n\t"
        "add	v6.8h, v6.8h, v14.8h\n\t"
        "add	v7.8h, v7.8h, v15.8h\n\t"
        "add	v8.8h, v8.8h, v16.8h\n\t"
        "add	v1.8h, v1.8h, v17.8h\n\t"
        "add	v2.8h, v2.8h, v18.8h\n\t"
        "add	v3.8h, v3.8h, v19.8h\n\t"
        "add	v4.8h, v4.8h, v20.8h\n\t"
        "add	v5.8h, v5.8h, v21.8h\n\t"
        "add	v6.8h, v6.8h, v22.8h\n\t"
        "add	v7.8h, v7.8h, v23.8h\n\t"
        "add	v8.8h, v8.8h, v24.8h\n\t"
        "sqdmulh	v25.8h, v1.8h, v0.h[2]\n\t"
        "sqdmulh	v26.8h, v2.8h, v0.h[2]\n\t"
        "sshr	v25.8h, v25.8h, #11\n\t"
        "sshr	v26.8h, v26.8h, #11\n\t"
        "mls	v1.8h, v25.8h, v0.h[0]\n\t"
        "mls	v2.8h, v26.8h, v0.h[0]\n\t"
        "sqdmulh	v25.8h, v3.8h, v0.h[2]\n\t"
        "sqdmulh	v26.8h, v4.8h, v0.h[2]\n\t"
        "sshr	v25.8h, v25.8h, #11\n\t"
        "sshr	v26.8h, v26.8h, #11\n\t"
        "mls	v3.8h, v25.8h, v0.h[0]\n\t"
        "mls	v4.8h, v26.8h, v0.h[0]\n\t"
        "sqdmulh	v25.8h, v5.8h, v0.h[2]\n\t"
        "sqdmulh	v26.8h, v6.8h, v0.h[2]\n\t"
        "sshr	v25.8h, v25.8h, #11\n\t"
        "sshr	v26.8h, v26.8h, #11\n\t"
        "mls	v5.8h, v25.8h, v0.h[0]\n\t"
        "mls	v6.8h, v26.8h, v0.h[0]\n\t"
        "sqdmulh	v25.8h, v7.8h, v0.h[2]\n\t"
        "sqdmulh	v26.8h, v8.8h, v0.h[2]\n\t"
        "sshr	v25.8h, v25.8h, #11\n\t"
        "sshr	v26.8h, v26.8h, #11\n\t"
        "mls	v7.8h, v25.8h, v0.h[0]\n\t"
        "mls	v8.8h, v26.8h, v0.h[0]\n\t"
        "st4	{v1.8h, v2.8h, v3.8h, v4.8h}, [%x[r]], #0x40\n\t"
        "st4	{v5.8h, v6.8h, v7.8h, v8.8h}, [%x[r]], #0x40\n\t"
        "ld4	{v1.8h, v2.8h, v3.8h, v4.8h}, [%x[r]], #0x40\n\t"
        "ld4	{v5.8h, v6.8h, v7.8h, v8.8h}, [%x[r]], #0x40\n\t"
        "ld4	{v9.8h, v10.8h, v11.8h, v12.8h}, [%x[a]], #0x40\n\t"
        "ld4	{v13.8h, v14.8h, v15.8h, v16.8h}, [%x[a]], #0x40\n\t"
        "ld4	{v17.8h, v18.8h, v19.8h, v20.8h}, [%x[b]], #0x40\n\t"
        "ld4	{v21.8h, v22.8h, v23.8h, v24.8h}, [%x[b]], #0x40\n\t"
        "sub	%x[r], %x[r], #0x80\n\t"
        "add	v1.8h, v1.8h, v9.8h\n\t"
        "add	v2.8h, v2.8h, v10.8h\n\t"
        "add	v3.8h, v3.8h, v11.8h\n\t"
        "add	v4.8h, v4.8h, v12.8h\n\t"
        "add	v5.8h, v5.8h, v13.8h\n\t"
        "add	v6.8h, v6.8h, v14.8h\n\t"
        "add	v7.8h, v7.8h, v15.8h\n\t"
        "add	v8.8h, v8.8h, v16.8h\n\t"
        "add	v1.8h, v1.8h, v17.8h\n\t"
        "add	v2.8h, v2.8h, v18.8h\n\t"
        "add	v3.8h, v3.8h, v19.8h\n\t"
        "add	v4.8h, v4.8h, v20.8h\n\t"
        "add	v5.8h, v5.8h, v21.8h\n\t"
        "add	v6.8h, v6.8h, v22.8h\n\t"
        "add	v7.8h, v7.8h, v23.8h\n\t"
        "add	v8.8h, v8.8h, v24.8h\n\t"
        "sqdmulh	v25.8h, v1.8h, v0.h[2]\n\t"
        "sqdmulh	v26.8h, v2.8h, v0.h[2]\n\t"
        "sshr	v25.8h, v25.8h, #11\n\t"
        "sshr	v26.8h, v26.8h, #11\n\t"
        "mls	v1.8h, v25.8h, v0.h[0]\n\t"
        "mls	v2.8h, v26.8h, v0.h[0]\n\t"
        "sqdmulh	v25.8h, v3.8h, v0.h[2]\n\t"
        "sqdmulh	v26.8h, v4.8h, v0.h[2]\n\t"
        "sshr	v25.8h, v25.8h, #11\n\t"
        "sshr	v26.8h, v26.8h, #11\n\t"
        "mls	v3.8h, v25.8h, v0.h[0]\n\t"
        "mls	v4.8h, v26.8h, v0.h[0]\n\t"
        "sqdmulh	v25.8h, v5.8h, v0.h[2]\n\t"
        "sqdmulh	v26.8h, v6.8h, v0.h[2]\n\t"
        "sshr	v25.8h, v25.8h, #11\n\t"
        "sshr	v26.8h, v26.8h, #11\n\t"
        "mls	v5.8h, v25.8h, v0.h[0]\n\t"
        "mls	v6.8h, v26.8h, v0.h[0]\n\t"
        "sqdmulh	v25.8h, v7.8h, v0.h[2]\n\t"
        "sqdmulh	v26.8h, v8.8h, v0.h[2]\n\t"
        "sshr	v25.8h, v25.8h, #11\n\t"
        "sshr	v26.8h, v26.8h, #11\n\t"
        "mls	v7.8h, v25.8h, v0.h[0]\n\t"
        "mls	v8.8h, v26.8h, v0.h[0]\n\t"
        "st4	{v1.8h, v2.8h, v3.8h, v4.8h}, [%x[r]], #0x40\n\t"
        "st4	{v5.8h, v6.8h, v7.8h, v8.8h}, [%x[r]], #0x40\n\t"
        : [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        : [L_kyber_aarch64_q] "S" (L_kyber_aarch64_q), [L_kyber_aarch64_consts] "S" (L_kyber_aarch64_consts), [L_sha3_aarch64_r] "S" (L_sha3_aarch64_r), [L_kyber_aarch64_zetas] "S" (L_kyber_aarch64_zetas), [L_kyber_aarch64_zetas_qinv] "S" (L_kyber_aarch64_zetas_qinv), [L_kyber_aarch64_zetas_inv] "S" (L_kyber_aarch64_zetas_inv), [L_kyber_aarch64_zetas_inv_qinv] "S" (L_kyber_aarch64_zetas_inv_qinv), [L_kyber_aarch64_zetas_mul] "S" (L_kyber_aarch64_zetas_mul)
        : "memory", "x3", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15", "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26", "cc"
    );
}

void kyber_rsub_reduce(sword16* r, const sword16* a)
{
    __asm__ __volatile__ (
#ifndef __APPLE__
        "adrp x2, %[L_kyber_aarch64_consts]\n\t"
        "add  x2, x2, :lo12:%[L_kyber_aarch64_consts]\n\t"
#else
        "adrp x2, %[L_kyber_aarch64_consts]@PAGE\n\t"
        "add  x2, x2, %[L_kyber_aarch64_consts]@PAGEOFF\n\t"
#endif /* __APPLE__ */
        "ldr	q0, [x2]\n\t"
        "ld4	{v1.8h, v2.8h, v3.8h, v4.8h}, [%x[r]], #0x40\n\t"
        "ld4	{v5.8h, v6.8h, v7.8h, v8.8h}, [%x[r]], #0x40\n\t"
        "ld4	{v9.8h, v10.8h, v11.8h, v12.8h}, [%x[a]], #0x40\n\t"
        "ld4	{v13.8h, v14.8h, v15.8h, v16.8h}, [%x[a]], #0x40\n\t"
        "sub	%x[r], %x[r], #0x80\n\t"
        "sub	v1.8h, v9.8h, v1.8h\n\t"
        "sub	v2.8h, v10.8h, v2.8h\n\t"
        "sub	v3.8h, v11.8h, v3.8h\n\t"
        "sub	v4.8h, v12.8h, v4.8h\n\t"
        "sub	v5.8h, v13.8h, v5.8h\n\t"
        "sub	v6.8h, v14.8h, v6.8h\n\t"
        "sub	v7.8h, v15.8h, v7.8h\n\t"
        "sub	v8.8h, v16.8h, v8.8h\n\t"
        "sqdmulh	v17.8h, v1.8h, v0.h[2]\n\t"
        "sqdmulh	v18.8h, v2.8h, v0.h[2]\n\t"
        "sshr	v17.8h, v17.8h, #11\n\t"
        "sshr	v18.8h, v18.8h, #11\n\t"
        "mls	v1.8h, v17.8h, v0.h[0]\n\t"
        "mls	v2.8h, v18.8h, v0.h[0]\n\t"
        "sqdmulh	v17.8h, v3.8h, v0.h[2]\n\t"
        "sqdmulh	v18.8h, v4.8h, v0.h[2]\n\t"
        "sshr	v17.8h, v17.8h, #11\n\t"
        "sshr	v18.8h, v18.8h, #11\n\t"
        "mls	v3.8h, v17.8h, v0.h[0]\n\t"
        "mls	v4.8h, v18.8h, v0.h[0]\n\t"
        "sqdmulh	v17.8h, v5.8h, v0.h[2]\n\t"
        "sqdmulh	v18.8h, v6.8h, v0.h[2]\n\t"
        "sshr	v17.8h, v17.8h, #11\n\t"
        "sshr	v18.8h, v18.8h, #11\n\t"
        "mls	v5.8h, v17.8h, v0.h[0]\n\t"
        "mls	v6.8h, v18.8h, v0.h[0]\n\t"
        "sqdmulh	v17.8h, v7.8h, v0.h[2]\n\t"
        "sqdmulh	v18.8h, v8.8h, v0.h[2]\n\t"
        "sshr	v17.8h, v17.8h, #11\n\t"
        "sshr	v18.8h, v18.8h, #11\n\t"
        "mls	v7.8h, v17.8h, v0.h[0]\n\t"
        "mls	v8.8h, v18.8h, v0.h[0]\n\t"
        "st4	{v1.8h, v2.8h, v3.8h, v4.8h}, [%x[r]], #0x40\n\t"
        "st4	{v5.8h, v6.8h, v7.8h, v8.8h}, [%x[r]], #0x40\n\t"
        "ld4	{v1.8h, v2.8h, v3.8h, v4.8h}, [%x[r]], #0x40\n\t"
        "ld4	{v5.8h, v6.8h, v7.8h, v8.8h}, [%x[r]], #0x40\n\t"
        "ld4	{v9.8h, v10.8h, v11.8h, v12.8h}, [%x[a]], #0x40\n\t"
        "ld4	{v13.8h, v14.8h, v15.8h, v16.8h}, [%x[a]], #0x40\n\t"
        "sub	%x[r], %x[r], #0x80\n\t"
        "sub	v1.8h, v9.8h, v1.8h\n\t"
        "sub	v2.8h, v10.8h, v2.8h\n\t"
        "sub	v3.8h, v11.8h, v3.8h\n\t"
        "sub	v4.8h, v12.8h, v4.8h\n\t"
        "sub	v5.8h, v13.8h, v5.8h\n\t"
        "sub	v6.8h, v14.8h, v6.8h\n\t"
        "sub	v7.8h, v15.8h, v7.8h\n\t"
        "sub	v8.8h, v16.8h, v8.8h\n\t"
        "sqdmulh	v17.8h, v1.8h, v0.h[2]\n\t"
        "sqdmulh	v18.8h, v2.8h, v0.h[2]\n\t"
        "sshr	v17.8h, v17.8h, #11\n\t"
        "sshr	v18.8h, v18.8h, #11\n\t"
        "mls	v1.8h, v17.8h, v0.h[0]\n\t"
        "mls	v2.8h, v18.8h, v0.h[0]\n\t"
        "sqdmulh	v17.8h, v3.8h, v0.h[2]\n\t"
        "sqdmulh	v18.8h, v4.8h, v0.h[2]\n\t"
        "sshr	v17.8h, v17.8h, #11\n\t"
        "sshr	v18.8h, v18.8h, #11\n\t"
        "mls	v3.8h, v17.8h, v0.h[0]\n\t"
        "mls	v4.8h, v18.8h, v0.h[0]\n\t"
        "sqdmulh	v17.8h, v5.8h, v0.h[2]\n\t"
        "sqdmulh	v18.8h, v6.8h, v0.h[2]\n\t"
        "sshr	v17.8h, v17.8h, #11\n\t"
        "sshr	v18.8h, v18.8h, #11\n\t"
        "mls	v5.8h, v17.8h, v0.h[0]\n\t"
        "mls	v6.8h, v18.8h, v0.h[0]\n\t"
        "sqdmulh	v17.8h, v7.8h, v0.h[2]\n\t"
        "sqdmulh	v18.8h, v8.8h, v0.h[2]\n\t"
        "sshr	v17.8h, v17.8h, #11\n\t"
        "sshr	v18.8h, v18.8h, #11\n\t"
        "mls	v7.8h, v17.8h, v0.h[0]\n\t"
        "mls	v8.8h, v18.8h, v0.h[0]\n\t"
        "st4	{v1.8h, v2.8h, v3.8h, v4.8h}, [%x[r]], #0x40\n\t"
        "st4	{v5.8h, v6.8h, v7.8h, v8.8h}, [%x[r]], #0x40\n\t"
        "ld4	{v1.8h, v2.8h, v3.8h, v4.8h}, [%x[r]], #0x40\n\t"
        "ld4	{v5.8h, v6.8h, v7.8h, v8.8h}, [%x[r]], #0x40\n\t"
        "ld4	{v9.8h, v10.8h, v11.8h, v12.8h}, [%x[a]], #0x40\n\t"
        "ld4	{v13.8h, v14.8h, v15.8h, v16.8h}, [%x[a]], #0x40\n\t"
        "sub	%x[r], %x[r], #0x80\n\t"
        "sub	v1.8h, v9.8h, v1.8h\n\t"
        "sub	v2.8h, v10.8h, v2.8h\n\t"
        "sub	v3.8h, v11.8h, v3.8h\n\t"
        "sub	v4.8h, v12.8h, v4.8h\n\t"
        "sub	v5.8h, v13.8h, v5.8h\n\t"
        "sub	v6.8h, v14.8h, v6.8h\n\t"
        "sub	v7.8h, v15.8h, v7.8h\n\t"
        "sub	v8.8h, v16.8h, v8.8h\n\t"
        "sqdmulh	v17.8h, v1.8h, v0.h[2]\n\t"
        "sqdmulh	v18.8h, v2.8h, v0.h[2]\n\t"
        "sshr	v17.8h, v17.8h, #11\n\t"
        "sshr	v18.8h, v18.8h, #11\n\t"
        "mls	v1.8h, v17.8h, v0.h[0]\n\t"
        "mls	v2.8h, v18.8h, v0.h[0]\n\t"
        "sqdmulh	v17.8h, v3.8h, v0.h[2]\n\t"
        "sqdmulh	v18.8h, v4.8h, v0.h[2]\n\t"
        "sshr	v17.8h, v17.8h, #11\n\t"
        "sshr	v18.8h, v18.8h, #11\n\t"
        "mls	v3.8h, v17.8h, v0.h[0]\n\t"
        "mls	v4.8h, v18.8h, v0.h[0]\n\t"
        "sqdmulh	v17.8h, v5.8h, v0.h[2]\n\t"
        "sqdmulh	v18.8h, v6.8h, v0.h[2]\n\t"
        "sshr	v17.8h, v17.8h, #11\n\t"
        "sshr	v18.8h, v18.8h, #11\n\t"
        "mls	v5.8h, v17.8h, v0.h[0]\n\t"
        "mls	v6.8h, v18.8h, v0.h[0]\n\t"
        "sqdmulh	v17.8h, v7.8h, v0.h[2]\n\t"
        "sqdmulh	v18.8h, v8.8h, v0.h[2]\n\t"
        "sshr	v17.8h, v17.8h, #11\n\t"
        "sshr	v18.8h, v18.8h, #11\n\t"
        "mls	v7.8h, v17.8h, v0.h[0]\n\t"
        "mls	v8.8h, v18.8h, v0.h[0]\n\t"
        "st4	{v1.8h, v2.8h, v3.8h, v4.8h}, [%x[r]], #0x40\n\t"
        "st4	{v5.8h, v6.8h, v7.8h, v8.8h}, [%x[r]], #0x40\n\t"
        "ld4	{v1.8h, v2.8h, v3.8h, v4.8h}, [%x[r]], #0x40\n\t"
        "ld4	{v5.8h, v6.8h, v7.8h, v8.8h}, [%x[r]], #0x40\n\t"
        "ld4	{v9.8h, v10.8h, v11.8h, v12.8h}, [%x[a]], #0x40\n\t"
        "ld4	{v13.8h, v14.8h, v15.8h, v16.8h}, [%x[a]], #0x40\n\t"
        "sub	%x[r], %x[r], #0x80\n\t"
        "sub	v1.8h, v9.8h, v1.8h\n\t"
        "sub	v2.8h, v10.8h, v2.8h\n\t"
        "sub	v3.8h, v11.8h, v3.8h\n\t"
        "sub	v4.8h, v12.8h, v4.8h\n\t"
        "sub	v5.8h, v13.8h, v5.8h\n\t"
        "sub	v6.8h, v14.8h, v6.8h\n\t"
        "sub	v7.8h, v15.8h, v7.8h\n\t"
        "sub	v8.8h, v16.8h, v8.8h\n\t"
        "sqdmulh	v17.8h, v1.8h, v0.h[2]\n\t"
        "sqdmulh	v18.8h, v2.8h, v0.h[2]\n\t"
        "sshr	v17.8h, v17.8h, #11\n\t"
        "sshr	v18.8h, v18.8h, #11\n\t"
        "mls	v1.8h, v17.8h, v0.h[0]\n\t"
        "mls	v2.8h, v18.8h, v0.h[0]\n\t"
        "sqdmulh	v17.8h, v3.8h, v0.h[2]\n\t"
        "sqdmulh	v18.8h, v4.8h, v0.h[2]\n\t"
        "sshr	v17.8h, v17.8h, #11\n\t"
        "sshr	v18.8h, v18.8h, #11\n\t"
        "mls	v3.8h, v17.8h, v0.h[0]\n\t"
        "mls	v4.8h, v18.8h, v0.h[0]\n\t"
        "sqdmulh	v17.8h, v5.8h, v0.h[2]\n\t"
        "sqdmulh	v18.8h, v6.8h, v0.h[2]\n\t"
        "sshr	v17.8h, v17.8h, #11\n\t"
        "sshr	v18.8h, v18.8h, #11\n\t"
        "mls	v5.8h, v17.8h, v0.h[0]\n\t"
        "mls	v6.8h, v18.8h, v0.h[0]\n\t"
        "sqdmulh	v17.8h, v7.8h, v0.h[2]\n\t"
        "sqdmulh	v18.8h, v8.8h, v0.h[2]\n\t"
        "sshr	v17.8h, v17.8h, #11\n\t"
        "sshr	v18.8h, v18.8h, #11\n\t"
        "mls	v7.8h, v17.8h, v0.h[0]\n\t"
        "mls	v8.8h, v18.8h, v0.h[0]\n\t"
        "st4	{v1.8h, v2.8h, v3.8h, v4.8h}, [%x[r]], #0x40\n\t"
        "st4	{v5.8h, v6.8h, v7.8h, v8.8h}, [%x[r]], #0x40\n\t"
        : [r] "+r" (r), [a] "+r" (a)
        : [L_kyber_aarch64_q] "S" (L_kyber_aarch64_q), [L_kyber_aarch64_consts] "S" (L_kyber_aarch64_consts), [L_sha3_aarch64_r] "S" (L_sha3_aarch64_r), [L_kyber_aarch64_zetas] "S" (L_kyber_aarch64_zetas), [L_kyber_aarch64_zetas_qinv] "S" (L_kyber_aarch64_zetas_qinv), [L_kyber_aarch64_zetas_inv] "S" (L_kyber_aarch64_zetas_inv), [L_kyber_aarch64_zetas_inv_qinv] "S" (L_kyber_aarch64_zetas_inv_qinv), [L_kyber_aarch64_zetas_mul] "S" (L_kyber_aarch64_zetas_mul)
        : "memory", "x2", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15", "v16", "v17", "v18", "cc"
    );
}

void kyber_to_mont(sword16* p)
{
    __asm__ __volatile__ (
#ifndef __APPLE__
        "adrp x1, %[L_kyber_aarch64_consts]\n\t"
        "add  x1, x1, :lo12:%[L_kyber_aarch64_consts]\n\t"
#else
        "adrp x1, %[L_kyber_aarch64_consts]@PAGE\n\t"
        "add  x1, x1, %[L_kyber_aarch64_consts]@PAGEOFF\n\t"
#endif /* __APPLE__ */
        "ldr	q0, [x1]\n\t"
        "ld4	{v1.8h, v2.8h, v3.8h, v4.8h}, [%x[p]], #0x40\n\t"
        "ld4	{v5.8h, v6.8h, v7.8h, v8.8h}, [%x[p]], #0x40\n\t"
        "ld4	{v9.8h, v10.8h, v11.8h, v12.8h}, [%x[p]], #0x40\n\t"
        "ld4	{v13.8h, v14.8h, v15.8h, v16.8h}, [%x[p]], #0x40\n\t"
        "sub	%x[p], %x[p], #0x100\n\t"
        "mul	v17.8h, v1.8h, v0.h[4]\n\t"
        "mul	v18.8h, v2.8h, v0.h[4]\n\t"
        "sqrdmulh	v1.8h, v1.8h, v0.h[3]\n\t"
        "sqrdmulh	v2.8h, v2.8h, v0.h[3]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v1.8h, v17.8h, v0.h[0]\n\t"
        "sqrdmlsh	v2.8h, v18.8h, v0.h[0]\n\t"
#else
        "sqrdmulh	v17.8h, v17.8h, v0.h[0]\n\t"
        "sqrdmulh	v18.8h, v18.8h, v0.h[0]\n\t"
        "sub	v1.8h, v1.8h, v17.8h\n\t"
        "sub	v2.8h, v2.8h, v18.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v1.8h, v1.8h, #1\n\t"
        "sshr	v2.8h, v2.8h, #1\n\t"
        "mul	v17.8h, v3.8h, v0.h[4]\n\t"
        "mul	v18.8h, v4.8h, v0.h[4]\n\t"
        "sqrdmulh	v3.8h, v3.8h, v0.h[3]\n\t"
        "sqrdmulh	v4.8h, v4.8h, v0.h[3]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v3.8h, v17.8h, v0.h[0]\n\t"
        "sqrdmlsh	v4.8h, v18.8h, v0.h[0]\n\t"
#else
        "sqrdmulh	v17.8h, v17.8h, v0.h[0]\n\t"
        "sqrdmulh	v18.8h, v18.8h, v0.h[0]\n\t"
        "sub	v3.8h, v3.8h, v17.8h\n\t"
        "sub	v4.8h, v4.8h, v18.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v3.8h, v3.8h, #1\n\t"
        "sshr	v4.8h, v4.8h, #1\n\t"
        "mul	v17.8h, v5.8h, v0.h[4]\n\t"
        "mul	v18.8h, v6.8h, v0.h[4]\n\t"
        "sqrdmulh	v5.8h, v5.8h, v0.h[3]\n\t"
        "sqrdmulh	v6.8h, v6.8h, v0.h[3]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v5.8h, v17.8h, v0.h[0]\n\t"
        "sqrdmlsh	v6.8h, v18.8h, v0.h[0]\n\t"
#else
        "sqrdmulh	v17.8h, v17.8h, v0.h[0]\n\t"
        "sqrdmulh	v18.8h, v18.8h, v0.h[0]\n\t"
        "sub	v5.8h, v5.8h, v17.8h\n\t"
        "sub	v6.8h, v6.8h, v18.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v5.8h, v5.8h, #1\n\t"
        "sshr	v6.8h, v6.8h, #1\n\t"
        "mul	v17.8h, v7.8h, v0.h[4]\n\t"
        "mul	v18.8h, v8.8h, v0.h[4]\n\t"
        "sqrdmulh	v7.8h, v7.8h, v0.h[3]\n\t"
        "sqrdmulh	v8.8h, v8.8h, v0.h[3]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v7.8h, v17.8h, v0.h[0]\n\t"
        "sqrdmlsh	v8.8h, v18.8h, v0.h[0]\n\t"
#else
        "sqrdmulh	v17.8h, v17.8h, v0.h[0]\n\t"
        "sqrdmulh	v18.8h, v18.8h, v0.h[0]\n\t"
        "sub	v7.8h, v7.8h, v17.8h\n\t"
        "sub	v8.8h, v8.8h, v18.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v7.8h, v7.8h, #1\n\t"
        "sshr	v8.8h, v8.8h, #1\n\t"
        "mul	v17.8h, v9.8h, v0.h[4]\n\t"
        "mul	v18.8h, v10.8h, v0.h[4]\n\t"
        "sqrdmulh	v9.8h, v9.8h, v0.h[3]\n\t"
        "sqrdmulh	v10.8h, v10.8h, v0.h[3]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v9.8h, v17.8h, v0.h[0]\n\t"
        "sqrdmlsh	v10.8h, v18.8h, v0.h[0]\n\t"
#else
        "sqrdmulh	v17.8h, v17.8h, v0.h[0]\n\t"
        "sqrdmulh	v18.8h, v18.8h, v0.h[0]\n\t"
        "sub	v9.8h, v9.8h, v17.8h\n\t"
        "sub	v10.8h, v10.8h, v18.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v9.8h, v9.8h, #1\n\t"
        "sshr	v10.8h, v10.8h, #1\n\t"
        "mul	v17.8h, v11.8h, v0.h[4]\n\t"
        "mul	v18.8h, v12.8h, v0.h[4]\n\t"
        "sqrdmulh	v11.8h, v11.8h, v0.h[3]\n\t"
        "sqrdmulh	v12.8h, v12.8h, v0.h[3]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v11.8h, v17.8h, v0.h[0]\n\t"
        "sqrdmlsh	v12.8h, v18.8h, v0.h[0]\n\t"
#else
        "sqrdmulh	v17.8h, v17.8h, v0.h[0]\n\t"
        "sqrdmulh	v18.8h, v18.8h, v0.h[0]\n\t"
        "sub	v11.8h, v11.8h, v17.8h\n\t"
        "sub	v12.8h, v12.8h, v18.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v11.8h, v11.8h, #1\n\t"
        "sshr	v12.8h, v12.8h, #1\n\t"
        "mul	v17.8h, v13.8h, v0.h[4]\n\t"
        "mul	v18.8h, v14.8h, v0.h[4]\n\t"
        "sqrdmulh	v13.8h, v13.8h, v0.h[3]\n\t"
        "sqrdmulh	v14.8h, v14.8h, v0.h[3]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v13.8h, v17.8h, v0.h[0]\n\t"
        "sqrdmlsh	v14.8h, v18.8h, v0.h[0]\n\t"
#else
        "sqrdmulh	v17.8h, v17.8h, v0.h[0]\n\t"
        "sqrdmulh	v18.8h, v18.8h, v0.h[0]\n\t"
        "sub	v13.8h, v13.8h, v17.8h\n\t"
        "sub	v14.8h, v14.8h, v18.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v13.8h, v13.8h, #1\n\t"
        "sshr	v14.8h, v14.8h, #1\n\t"
        "mul	v17.8h, v15.8h, v0.h[4]\n\t"
        "mul	v18.8h, v16.8h, v0.h[4]\n\t"
        "sqrdmulh	v15.8h, v15.8h, v0.h[3]\n\t"
        "sqrdmulh	v16.8h, v16.8h, v0.h[3]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v15.8h, v17.8h, v0.h[0]\n\t"
        "sqrdmlsh	v16.8h, v18.8h, v0.h[0]\n\t"
#else
        "sqrdmulh	v17.8h, v17.8h, v0.h[0]\n\t"
        "sqrdmulh	v18.8h, v18.8h, v0.h[0]\n\t"
        "sub	v15.8h, v15.8h, v17.8h\n\t"
        "sub	v16.8h, v16.8h, v18.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v15.8h, v15.8h, #1\n\t"
        "sshr	v16.8h, v16.8h, #1\n\t"
        "st4	{v1.8h, v2.8h, v3.8h, v4.8h}, [%x[p]], #0x40\n\t"
        "st4	{v5.8h, v6.8h, v7.8h, v8.8h}, [%x[p]], #0x40\n\t"
        "st4	{v9.8h, v10.8h, v11.8h, v12.8h}, [%x[p]], #0x40\n\t"
        "st4	{v13.8h, v14.8h, v15.8h, v16.8h}, [%x[p]], #0x40\n\t"
        "ld4	{v1.8h, v2.8h, v3.8h, v4.8h}, [%x[p]], #0x40\n\t"
        "ld4	{v5.8h, v6.8h, v7.8h, v8.8h}, [%x[p]], #0x40\n\t"
        "ld4	{v9.8h, v10.8h, v11.8h, v12.8h}, [%x[p]], #0x40\n\t"
        "ld4	{v13.8h, v14.8h, v15.8h, v16.8h}, [%x[p]], #0x40\n\t"
        "sub	%x[p], %x[p], #0x100\n\t"
        "mul	v17.8h, v1.8h, v0.h[4]\n\t"
        "mul	v18.8h, v2.8h, v0.h[4]\n\t"
        "sqrdmulh	v1.8h, v1.8h, v0.h[3]\n\t"
        "sqrdmulh	v2.8h, v2.8h, v0.h[3]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v1.8h, v17.8h, v0.h[0]\n\t"
        "sqrdmlsh	v2.8h, v18.8h, v0.h[0]\n\t"
#else
        "sqrdmulh	v17.8h, v17.8h, v0.h[0]\n\t"
        "sqrdmulh	v18.8h, v18.8h, v0.h[0]\n\t"
        "sub	v1.8h, v1.8h, v17.8h\n\t"
        "sub	v2.8h, v2.8h, v18.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v1.8h, v1.8h, #1\n\t"
        "sshr	v2.8h, v2.8h, #1\n\t"
        "mul	v17.8h, v3.8h, v0.h[4]\n\t"
        "mul	v18.8h, v4.8h, v0.h[4]\n\t"
        "sqrdmulh	v3.8h, v3.8h, v0.h[3]\n\t"
        "sqrdmulh	v4.8h, v4.8h, v0.h[3]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v3.8h, v17.8h, v0.h[0]\n\t"
        "sqrdmlsh	v4.8h, v18.8h, v0.h[0]\n\t"
#else
        "sqrdmulh	v17.8h, v17.8h, v0.h[0]\n\t"
        "sqrdmulh	v18.8h, v18.8h, v0.h[0]\n\t"
        "sub	v3.8h, v3.8h, v17.8h\n\t"
        "sub	v4.8h, v4.8h, v18.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v3.8h, v3.8h, #1\n\t"
        "sshr	v4.8h, v4.8h, #1\n\t"
        "mul	v17.8h, v5.8h, v0.h[4]\n\t"
        "mul	v18.8h, v6.8h, v0.h[4]\n\t"
        "sqrdmulh	v5.8h, v5.8h, v0.h[3]\n\t"
        "sqrdmulh	v6.8h, v6.8h, v0.h[3]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v5.8h, v17.8h, v0.h[0]\n\t"
        "sqrdmlsh	v6.8h, v18.8h, v0.h[0]\n\t"
#else
        "sqrdmulh	v17.8h, v17.8h, v0.h[0]\n\t"
        "sqrdmulh	v18.8h, v18.8h, v0.h[0]\n\t"
        "sub	v5.8h, v5.8h, v17.8h\n\t"
        "sub	v6.8h, v6.8h, v18.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v5.8h, v5.8h, #1\n\t"
        "sshr	v6.8h, v6.8h, #1\n\t"
        "mul	v17.8h, v7.8h, v0.h[4]\n\t"
        "mul	v18.8h, v8.8h, v0.h[4]\n\t"
        "sqrdmulh	v7.8h, v7.8h, v0.h[3]\n\t"
        "sqrdmulh	v8.8h, v8.8h, v0.h[3]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v7.8h, v17.8h, v0.h[0]\n\t"
        "sqrdmlsh	v8.8h, v18.8h, v0.h[0]\n\t"
#else
        "sqrdmulh	v17.8h, v17.8h, v0.h[0]\n\t"
        "sqrdmulh	v18.8h, v18.8h, v0.h[0]\n\t"
        "sub	v7.8h, v7.8h, v17.8h\n\t"
        "sub	v8.8h, v8.8h, v18.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v7.8h, v7.8h, #1\n\t"
        "sshr	v8.8h, v8.8h, #1\n\t"
        "mul	v17.8h, v9.8h, v0.h[4]\n\t"
        "mul	v18.8h, v10.8h, v0.h[4]\n\t"
        "sqrdmulh	v9.8h, v9.8h, v0.h[3]\n\t"
        "sqrdmulh	v10.8h, v10.8h, v0.h[3]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v9.8h, v17.8h, v0.h[0]\n\t"
        "sqrdmlsh	v10.8h, v18.8h, v0.h[0]\n\t"
#else
        "sqrdmulh	v17.8h, v17.8h, v0.h[0]\n\t"
        "sqrdmulh	v18.8h, v18.8h, v0.h[0]\n\t"
        "sub	v9.8h, v9.8h, v17.8h\n\t"
        "sub	v10.8h, v10.8h, v18.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v9.8h, v9.8h, #1\n\t"
        "sshr	v10.8h, v10.8h, #1\n\t"
        "mul	v17.8h, v11.8h, v0.h[4]\n\t"
        "mul	v18.8h, v12.8h, v0.h[4]\n\t"
        "sqrdmulh	v11.8h, v11.8h, v0.h[3]\n\t"
        "sqrdmulh	v12.8h, v12.8h, v0.h[3]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v11.8h, v17.8h, v0.h[0]\n\t"
        "sqrdmlsh	v12.8h, v18.8h, v0.h[0]\n\t"
#else
        "sqrdmulh	v17.8h, v17.8h, v0.h[0]\n\t"
        "sqrdmulh	v18.8h, v18.8h, v0.h[0]\n\t"
        "sub	v11.8h, v11.8h, v17.8h\n\t"
        "sub	v12.8h, v12.8h, v18.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v11.8h, v11.8h, #1\n\t"
        "sshr	v12.8h, v12.8h, #1\n\t"
        "mul	v17.8h, v13.8h, v0.h[4]\n\t"
        "mul	v18.8h, v14.8h, v0.h[4]\n\t"
        "sqrdmulh	v13.8h, v13.8h, v0.h[3]\n\t"
        "sqrdmulh	v14.8h, v14.8h, v0.h[3]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v13.8h, v17.8h, v0.h[0]\n\t"
        "sqrdmlsh	v14.8h, v18.8h, v0.h[0]\n\t"
#else
        "sqrdmulh	v17.8h, v17.8h, v0.h[0]\n\t"
        "sqrdmulh	v18.8h, v18.8h, v0.h[0]\n\t"
        "sub	v13.8h, v13.8h, v17.8h\n\t"
        "sub	v14.8h, v14.8h, v18.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v13.8h, v13.8h, #1\n\t"
        "sshr	v14.8h, v14.8h, #1\n\t"
        "mul	v17.8h, v15.8h, v0.h[4]\n\t"
        "mul	v18.8h, v16.8h, v0.h[4]\n\t"
        "sqrdmulh	v15.8h, v15.8h, v0.h[3]\n\t"
        "sqrdmulh	v16.8h, v16.8h, v0.h[3]\n\t"
#ifndef WOLFSSL_AARCH64_NO_SQRMLSH
        "sqrdmlsh	v15.8h, v17.8h, v0.h[0]\n\t"
        "sqrdmlsh	v16.8h, v18.8h, v0.h[0]\n\t"
#else
        "sqrdmulh	v17.8h, v17.8h, v0.h[0]\n\t"
        "sqrdmulh	v18.8h, v18.8h, v0.h[0]\n\t"
        "sub	v15.8h, v15.8h, v17.8h\n\t"
        "sub	v16.8h, v16.8h, v18.8h\n\t"
#endif /* !WOLFSSL_AARCH64_NO_SQRMLSH */
        "sshr	v15.8h, v15.8h, #1\n\t"
        "sshr	v16.8h, v16.8h, #1\n\t"
        "st4	{v1.8h, v2.8h, v3.8h, v4.8h}, [%x[p]], #0x40\n\t"
        "st4	{v5.8h, v6.8h, v7.8h, v8.8h}, [%x[p]], #0x40\n\t"
        "st4	{v9.8h, v10.8h, v11.8h, v12.8h}, [%x[p]], #0x40\n\t"
        "st4	{v13.8h, v14.8h, v15.8h, v16.8h}, [%x[p]], #0x40\n\t"
        : [p] "+r" (p)
        : [L_kyber_aarch64_q] "S" (L_kyber_aarch64_q), [L_kyber_aarch64_consts] "S" (L_kyber_aarch64_consts), [L_sha3_aarch64_r] "S" (L_sha3_aarch64_r), [L_kyber_aarch64_zetas] "S" (L_kyber_aarch64_zetas), [L_kyber_aarch64_zetas_qinv] "S" (L_kyber_aarch64_zetas_qinv), [L_kyber_aarch64_zetas_inv] "S" (L_kyber_aarch64_zetas_inv), [L_kyber_aarch64_zetas_inv_qinv] "S" (L_kyber_aarch64_zetas_inv_qinv), [L_kyber_aarch64_zetas_mul] "S" (L_kyber_aarch64_zetas_mul)
        : "memory", "x1", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15", "v16", "v17", "v18", "cc"
    );
}

static const word16 L_kyber_aarch64_to_msg_neon_low[] = {
    0x373,
    0x373,
    0x373,
    0x373,
    0x373,
    0x373,
    0x373,
    0x373,
};

static const word16 L_kyber_aarch64_to_msg_neon_high[] = {
    0x9c0,
    0x9c0,
    0x9c0,
    0x9c0,
    0x9c0,
    0x9c0,
    0x9c0,
    0x9c0,
};

static const word16 L_kyber_aarch64_to_msg_neon_bits[] = {
    0x1,
    0x2,
    0x4,
    0x8,
    0x10,
    0x20,
    0x40,
    0x80,
};

void kyber_to_msg_neon(byte* msg, sword16* p)
{
    __asm__ __volatile__ (
#ifndef __APPLE__
        "adrp x2, %[L_kyber_aarch64_to_msg_neon_low]\n\t"
        "add  x2, x2, :lo12:%[L_kyber_aarch64_to_msg_neon_low]\n\t"
#else
        "adrp x2, %[L_kyber_aarch64_to_msg_neon_low]@PAGE\n\t"
        "add  x2, x2, %[L_kyber_aarch64_to_msg_neon_low]@PAGEOFF\n\t"
#endif /* __APPLE__ */
#ifndef __APPLE__
        "adrp x3, %[L_kyber_aarch64_to_msg_neon_high]\n\t"
        "add  x3, x3, :lo12:%[L_kyber_aarch64_to_msg_neon_high]\n\t"
#else
        "adrp x3, %[L_kyber_aarch64_to_msg_neon_high]@PAGE\n\t"
        "add  x3, x3, %[L_kyber_aarch64_to_msg_neon_high]@PAGEOFF\n\t"
#endif /* __APPLE__ */
#ifndef __APPLE__
        "adrp x4, %[L_kyber_aarch64_to_msg_neon_bits]\n\t"
        "add  x4, x4, :lo12:%[L_kyber_aarch64_to_msg_neon_bits]\n\t"
#else
        "adrp x4, %[L_kyber_aarch64_to_msg_neon_bits]@PAGE\n\t"
        "add  x4, x4, %[L_kyber_aarch64_to_msg_neon_bits]@PAGEOFF\n\t"
#endif /* __APPLE__ */
        "ldr	q0, [x2]\n\t"
        "ldr	q1, [x3]\n\t"
        "ldr	q26, [x4]\n\t"
        "ld1	{v2.8h, v3.8h, v4.8h, v5.8h}, [%x[p]], #0x40\n\t"
        "ld1	{v6.8h, v7.8h, v8.8h, v9.8h}, [%x[p]], #0x40\n\t"
        "cmge	v10.8h, v2.8h, v0.8h\n\t"
        "cmge	v18.8h, v1.8h, v2.8h\n\t"
        "cmge	v11.8h, v3.8h, v0.8h\n\t"
        "cmge	v19.8h, v1.8h, v3.8h\n\t"
        "cmge	v12.8h, v4.8h, v0.8h\n\t"
        "cmge	v20.8h, v1.8h, v4.8h\n\t"
        "cmge	v13.8h, v5.8h, v0.8h\n\t"
        "cmge	v21.8h, v1.8h, v5.8h\n\t"
        "cmge	v14.8h, v6.8h, v0.8h\n\t"
        "cmge	v22.8h, v1.8h, v6.8h\n\t"
        "cmge	v15.8h, v7.8h, v0.8h\n\t"
        "cmge	v23.8h, v1.8h, v7.8h\n\t"
        "cmge	v16.8h, v8.8h, v0.8h\n\t"
        "cmge	v24.8h, v1.8h, v8.8h\n\t"
        "cmge	v17.8h, v9.8h, v0.8h\n\t"
        "cmge	v25.8h, v1.8h, v9.8h\n\t"
        "and	v18.16b, v18.16b, v10.16b\n\t"
        "and	v19.16b, v19.16b, v11.16b\n\t"
        "and	v20.16b, v20.16b, v12.16b\n\t"
        "and	v21.16b, v21.16b, v13.16b\n\t"
        "and	v22.16b, v22.16b, v14.16b\n\t"
        "and	v23.16b, v23.16b, v15.16b\n\t"
        "and	v24.16b, v24.16b, v16.16b\n\t"
        "and	v25.16b, v25.16b, v17.16b\n\t"
        "and	v18.16b, v18.16b, v26.16b\n\t"
        "and	v19.16b, v19.16b, v26.16b\n\t"
        "and	v20.16b, v20.16b, v26.16b\n\t"
        "and	v21.16b, v21.16b, v26.16b\n\t"
        "and	v22.16b, v22.16b, v26.16b\n\t"
        "and	v23.16b, v23.16b, v26.16b\n\t"
        "and	v24.16b, v24.16b, v26.16b\n\t"
        "and	v25.16b, v25.16b, v26.16b\n\t"
        "addv	h18, v18.8h\n\t"
        "addv	h19, v19.8h\n\t"
        "addv	h20, v20.8h\n\t"
        "addv	h21, v21.8h\n\t"
        "addv	h22, v22.8h\n\t"
        "addv	h23, v23.8h\n\t"
        "addv	h24, v24.8h\n\t"
        "addv	h25, v25.8h\n\t"
        "ins	v18.b[1], v19.b[0]\n\t"
        "ins	v18.b[2], v20.b[0]\n\t"
        "ins	v18.b[3], v21.b[0]\n\t"
        "ins	v18.b[4], v22.b[0]\n\t"
        "ins	v18.b[5], v23.b[0]\n\t"
        "ins	v18.b[6], v24.b[0]\n\t"
        "ins	v18.b[7], v25.b[0]\n\t"
        "st1	{v18.8b}, [%x[msg]], #8\n\t"
        "ld1	{v2.8h, v3.8h, v4.8h, v5.8h}, [%x[p]], #0x40\n\t"
        "ld1	{v6.8h, v7.8h, v8.8h, v9.8h}, [%x[p]], #0x40\n\t"
        "cmge	v10.8h, v2.8h, v0.8h\n\t"
        "cmge	v18.8h, v1.8h, v2.8h\n\t"
        "cmge	v11.8h, v3.8h, v0.8h\n\t"
        "cmge	v19.8h, v1.8h, v3.8h\n\t"
        "cmge	v12.8h, v4.8h, v0.8h\n\t"
        "cmge	v20.8h, v1.8h, v4.8h\n\t"
        "cmge	v13.8h, v5.8h, v0.8h\n\t"
        "cmge	v21.8h, v1.8h, v5.8h\n\t"
        "cmge	v14.8h, v6.8h, v0.8h\n\t"
        "cmge	v22.8h, v1.8h, v6.8h\n\t"
        "cmge	v15.8h, v7.8h, v0.8h\n\t"
        "cmge	v23.8h, v1.8h, v7.8h\n\t"
        "cmge	v16.8h, v8.8h, v0.8h\n\t"
        "cmge	v24.8h, v1.8h, v8.8h\n\t"
        "cmge	v17.8h, v9.8h, v0.8h\n\t"
        "cmge	v25.8h, v1.8h, v9.8h\n\t"
        "and	v18.16b, v18.16b, v10.16b\n\t"
        "and	v19.16b, v19.16b, v11.16b\n\t"
        "and	v20.16b, v20.16b, v12.16b\n\t"
        "and	v21.16b, v21.16b, v13.16b\n\t"
        "and	v22.16b, v22.16b, v14.16b\n\t"
        "and	v23.16b, v23.16b, v15.16b\n\t"
        "and	v24.16b, v24.16b, v16.16b\n\t"
        "and	v25.16b, v25.16b, v17.16b\n\t"
        "and	v18.16b, v18.16b, v26.16b\n\t"
        "and	v19.16b, v19.16b, v26.16b\n\t"
        "and	v20.16b, v20.16b, v26.16b\n\t"
        "and	v21.16b, v21.16b, v26.16b\n\t"
        "and	v22.16b, v22.16b, v26.16b\n\t"
        "and	v23.16b, v23.16b, v26.16b\n\t"
        "and	v24.16b, v24.16b, v26.16b\n\t"
        "and	v25.16b, v25.16b, v26.16b\n\t"
        "addv	h18, v18.8h\n\t"
        "addv	h19, v19.8h\n\t"
        "addv	h20, v20.8h\n\t"
        "addv	h21, v21.8h\n\t"
        "addv	h22, v22.8h\n\t"
        "addv	h23, v23.8h\n\t"
        "addv	h24, v24.8h\n\t"
        "addv	h25, v25.8h\n\t"
        "ins	v18.b[1], v19.b[0]\n\t"
        "ins	v18.b[2], v20.b[0]\n\t"
        "ins	v18.b[3], v21.b[0]\n\t"
        "ins	v18.b[4], v22.b[0]\n\t"
        "ins	v18.b[5], v23.b[0]\n\t"
        "ins	v18.b[6], v24.b[0]\n\t"
        "ins	v18.b[7], v25.b[0]\n\t"
        "st1	{v18.8b}, [%x[msg]], #8\n\t"
        "ld1	{v2.8h, v3.8h, v4.8h, v5.8h}, [%x[p]], #0x40\n\t"
        "ld1	{v6.8h, v7.8h, v8.8h, v9.8h}, [%x[p]], #0x40\n\t"
        "cmge	v10.8h, v2.8h, v0.8h\n\t"
        "cmge	v18.8h, v1.8h, v2.8h\n\t"
        "cmge	v11.8h, v3.8h, v0.8h\n\t"
        "cmge	v19.8h, v1.8h, v3.8h\n\t"
        "cmge	v12.8h, v4.8h, v0.8h\n\t"
        "cmge	v20.8h, v1.8h, v4.8h\n\t"
        "cmge	v13.8h, v5.8h, v0.8h\n\t"
        "cmge	v21.8h, v1.8h, v5.8h\n\t"
        "cmge	v14.8h, v6.8h, v0.8h\n\t"
        "cmge	v22.8h, v1.8h, v6.8h\n\t"
        "cmge	v15.8h, v7.8h, v0.8h\n\t"
        "cmge	v23.8h, v1.8h, v7.8h\n\t"
        "cmge	v16.8h, v8.8h, v0.8h\n\t"
        "cmge	v24.8h, v1.8h, v8.8h\n\t"
        "cmge	v17.8h, v9.8h, v0.8h\n\t"
        "cmge	v25.8h, v1.8h, v9.8h\n\t"
        "and	v18.16b, v18.16b, v10.16b\n\t"
        "and	v19.16b, v19.16b, v11.16b\n\t"
        "and	v20.16b, v20.16b, v12.16b\n\t"
        "and	v21.16b, v21.16b, v13.16b\n\t"
        "and	v22.16b, v22.16b, v14.16b\n\t"
        "and	v23.16b, v23.16b, v15.16b\n\t"
        "and	v24.16b, v24.16b, v16.16b\n\t"
        "and	v25.16b, v25.16b, v17.16b\n\t"
        "and	v18.16b, v18.16b, v26.16b\n\t"
        "and	v19.16b, v19.16b, v26.16b\n\t"
        "and	v20.16b, v20.16b, v26.16b\n\t"
        "and	v21.16b, v21.16b, v26.16b\n\t"
        "and	v22.16b, v22.16b, v26.16b\n\t"
        "and	v23.16b, v23.16b, v26.16b\n\t"
        "and	v24.16b, v24.16b, v26.16b\n\t"
        "and	v25.16b, v25.16b, v26.16b\n\t"
        "addv	h18, v18.8h\n\t"
        "addv	h19, v19.8h\n\t"
        "addv	h20, v20.8h\n\t"
        "addv	h21, v21.8h\n\t"
        "addv	h22, v22.8h\n\t"
        "addv	h23, v23.8h\n\t"
        "addv	h24, v24.8h\n\t"
        "addv	h25, v25.8h\n\t"
        "ins	v18.b[1], v19.b[0]\n\t"
        "ins	v18.b[2], v20.b[0]\n\t"
        "ins	v18.b[3], v21.b[0]\n\t"
        "ins	v18.b[4], v22.b[0]\n\t"
        "ins	v18.b[5], v23.b[0]\n\t"
        "ins	v18.b[6], v24.b[0]\n\t"
        "ins	v18.b[7], v25.b[0]\n\t"
        "st1	{v18.8b}, [%x[msg]], #8\n\t"
        "ld1	{v2.8h, v3.8h, v4.8h, v5.8h}, [%x[p]], #0x40\n\t"
        "ld1	{v6.8h, v7.8h, v8.8h, v9.8h}, [%x[p]], #0x40\n\t"
        "cmge	v10.8h, v2.8h, v0.8h\n\t"
        "cmge	v18.8h, v1.8h, v2.8h\n\t"
        "cmge	v11.8h, v3.8h, v0.8h\n\t"
        "cmge	v19.8h, v1.8h, v3.8h\n\t"
        "cmge	v12.8h, v4.8h, v0.8h\n\t"
        "cmge	v20.8h, v1.8h, v4.8h\n\t"
        "cmge	v13.8h, v5.8h, v0.8h\n\t"
        "cmge	v21.8h, v1.8h, v5.8h\n\t"
        "cmge	v14.8h, v6.8h, v0.8h\n\t"
        "cmge	v22.8h, v1.8h, v6.8h\n\t"
        "cmge	v15.8h, v7.8h, v0.8h\n\t"
        "cmge	v23.8h, v1.8h, v7.8h\n\t"
        "cmge	v16.8h, v8.8h, v0.8h\n\t"
        "cmge	v24.8h, v1.8h, v8.8h\n\t"
        "cmge	v17.8h, v9.8h, v0.8h\n\t"
        "cmge	v25.8h, v1.8h, v9.8h\n\t"
        "and	v18.16b, v18.16b, v10.16b\n\t"
        "and	v19.16b, v19.16b, v11.16b\n\t"
        "and	v20.16b, v20.16b, v12.16b\n\t"
        "and	v21.16b, v21.16b, v13.16b\n\t"
        "and	v22.16b, v22.16b, v14.16b\n\t"
        "and	v23.16b, v23.16b, v15.16b\n\t"
        "and	v24.16b, v24.16b, v16.16b\n\t"
        "and	v25.16b, v25.16b, v17.16b\n\t"
        "and	v18.16b, v18.16b, v26.16b\n\t"
        "and	v19.16b, v19.16b, v26.16b\n\t"
        "and	v20.16b, v20.16b, v26.16b\n\t"
        "and	v21.16b, v21.16b, v26.16b\n\t"
        "and	v22.16b, v22.16b, v26.16b\n\t"
        "and	v23.16b, v23.16b, v26.16b\n\t"
        "and	v24.16b, v24.16b, v26.16b\n\t"
        "and	v25.16b, v25.16b, v26.16b\n\t"
        "addv	h18, v18.8h\n\t"
        "addv	h19, v19.8h\n\t"
        "addv	h20, v20.8h\n\t"
        "addv	h21, v21.8h\n\t"
        "addv	h22, v22.8h\n\t"
        "addv	h23, v23.8h\n\t"
        "addv	h24, v24.8h\n\t"
        "addv	h25, v25.8h\n\t"
        "ins	v18.b[1], v19.b[0]\n\t"
        "ins	v18.b[2], v20.b[0]\n\t"
        "ins	v18.b[3], v21.b[0]\n\t"
        "ins	v18.b[4], v22.b[0]\n\t"
        "ins	v18.b[5], v23.b[0]\n\t"
        "ins	v18.b[6], v24.b[0]\n\t"
        "ins	v18.b[7], v25.b[0]\n\t"
        "st1	{v18.8b}, [%x[msg]], #8\n\t"
        : [msg] "+r" (msg), [p] "+r" (p)
        : [L_kyber_aarch64_q] "S" (L_kyber_aarch64_q), [L_kyber_aarch64_consts] "S" (L_kyber_aarch64_consts), [L_sha3_aarch64_r] "S" (L_sha3_aarch64_r), [L_kyber_aarch64_zetas] "S" (L_kyber_aarch64_zetas), [L_kyber_aarch64_zetas_qinv] "S" (L_kyber_aarch64_zetas_qinv), [L_kyber_aarch64_zetas_inv] "S" (L_kyber_aarch64_zetas_inv), [L_kyber_aarch64_zetas_inv_qinv] "S" (L_kyber_aarch64_zetas_inv_qinv), [L_kyber_aarch64_zetas_mul] "S" (L_kyber_aarch64_zetas_mul), [L_kyber_aarch64_to_msg_neon_low] "S" (L_kyber_aarch64_to_msg_neon_low), [L_kyber_aarch64_to_msg_neon_high] "S" (L_kyber_aarch64_to_msg_neon_high), [L_kyber_aarch64_to_msg_neon_bits] "S" (L_kyber_aarch64_to_msg_neon_bits)
        : "memory", "x2", "x3", "x4", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15", "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26", "cc"
    );
}

static const word16 L_kyber_aarch64_from_msg_neon_q1half[] = {
    0x681,
    0x681,
    0x681,
    0x681,
    0x681,
    0x681,
    0x681,
    0x681,
};

static const word8 L_kyber_aarch64_from_msg_neon_bits[] = {
    0x1,
    0x2,
    0x4,
    0x8,
    0x10,
    0x20,
    0x40,
    0x80,
    0x1,
    0x2,
    0x4,
    0x8,
    0x10,
    0x20,
    0x40,
    0x80,
};

void kyber_from_msg_neon(sword16* p, const byte* msg)
{
    __asm__ __volatile__ (
#ifndef __APPLE__
        "adrp x2, %[L_kyber_aarch64_from_msg_neon_q1half]\n\t"
        "add  x2, x2, :lo12:%[L_kyber_aarch64_from_msg_neon_q1half]\n\t"
#else
        "adrp x2, %[L_kyber_aarch64_from_msg_neon_q1half]@PAGE\n\t"
        "add  x2, x2, %[L_kyber_aarch64_from_msg_neon_q1half]@PAGEOFF\n\t"
#endif /* __APPLE__ */
#ifndef __APPLE__
        "adrp x3, %[L_kyber_aarch64_from_msg_neon_bits]\n\t"
        "add  x3, x3, :lo12:%[L_kyber_aarch64_from_msg_neon_bits]\n\t"
#else
        "adrp x3, %[L_kyber_aarch64_from_msg_neon_bits]@PAGE\n\t"
        "add  x3, x3, %[L_kyber_aarch64_from_msg_neon_bits]@PAGEOFF\n\t"
#endif /* __APPLE__ */
        "ld1	{v2.16b, v3.16b}, [%x[msg]]\n\t"
        "ldr	q1, [x2]\n\t"
        "ldr	q0, [x3]\n\t"
        "dup	v4.8b, v2.b[0]\n\t"
        "dup	v5.8b, v2.b[1]\n\t"
        "dup	v6.8b, v2.b[2]\n\t"
        "dup	v7.8b, v2.b[3]\n\t"
        "cmtst	v4.8b, v4.8b, v0.8b\n\t"
        "cmtst	v5.8b, v5.8b, v0.8b\n\t"
        "cmtst	v6.8b, v6.8b, v0.8b\n\t"
        "cmtst	v7.8b, v7.8b, v0.8b\n\t"
        "zip1	v4.16b, v4.16b, v4.16b\n\t"
        "zip1	v5.16b, v5.16b, v5.16b\n\t"
        "zip1	v6.16b, v6.16b, v6.16b\n\t"
        "zip1	v7.16b, v7.16b, v7.16b\n\t"
        "and	v4.16b, v4.16b, v1.16b\n\t"
        "and	v5.16b, v5.16b, v1.16b\n\t"
        "and	v6.16b, v6.16b, v1.16b\n\t"
        "and	v7.16b, v7.16b, v1.16b\n\t"
        "st1	{v4.8h, v5.8h, v6.8h, v7.8h}, [%x[p]], #0x40\n\t"
        "dup	v4.8b, v2.b[4]\n\t"
        "dup	v5.8b, v2.b[5]\n\t"
        "dup	v6.8b, v2.b[6]\n\t"
        "dup	v7.8b, v2.b[7]\n\t"
        "cmtst	v4.8b, v4.8b, v0.8b\n\t"
        "cmtst	v5.8b, v5.8b, v0.8b\n\t"
        "cmtst	v6.8b, v6.8b, v0.8b\n\t"
        "cmtst	v7.8b, v7.8b, v0.8b\n\t"
        "zip1	v4.16b, v4.16b, v4.16b\n\t"
        "zip1	v5.16b, v5.16b, v5.16b\n\t"
        "zip1	v6.16b, v6.16b, v6.16b\n\t"
        "zip1	v7.16b, v7.16b, v7.16b\n\t"
        "and	v4.16b, v4.16b, v1.16b\n\t"
        "and	v5.16b, v5.16b, v1.16b\n\t"
        "and	v6.16b, v6.16b, v1.16b\n\t"
        "and	v7.16b, v7.16b, v1.16b\n\t"
        "st1	{v4.8h, v5.8h, v6.8h, v7.8h}, [%x[p]], #0x40\n\t"
        "dup	v4.8b, v2.b[8]\n\t"
        "dup	v5.8b, v2.b[9]\n\t"
        "dup	v6.8b, v2.b[10]\n\t"
        "dup	v7.8b, v2.b[11]\n\t"
        "cmtst	v4.8b, v4.8b, v0.8b\n\t"
        "cmtst	v5.8b, v5.8b, v0.8b\n\t"
        "cmtst	v6.8b, v6.8b, v0.8b\n\t"
        "cmtst	v7.8b, v7.8b, v0.8b\n\t"
        "zip1	v4.16b, v4.16b, v4.16b\n\t"
        "zip1	v5.16b, v5.16b, v5.16b\n\t"
        "zip1	v6.16b, v6.16b, v6.16b\n\t"
        "zip1	v7.16b, v7.16b, v7.16b\n\t"
        "and	v4.16b, v4.16b, v1.16b\n\t"
        "and	v5.16b, v5.16b, v1.16b\n\t"
        "and	v6.16b, v6.16b, v1.16b\n\t"
        "and	v7.16b, v7.16b, v1.16b\n\t"
        "st1	{v4.8h, v5.8h, v6.8h, v7.8h}, [%x[p]], #0x40\n\t"
        "dup	v4.8b, v2.b[12]\n\t"
        "dup	v5.8b, v2.b[13]\n\t"
        "dup	v6.8b, v2.b[14]\n\t"
        "dup	v7.8b, v2.b[15]\n\t"
        "cmtst	v4.8b, v4.8b, v0.8b\n\t"
        "cmtst	v5.8b, v5.8b, v0.8b\n\t"
        "cmtst	v6.8b, v6.8b, v0.8b\n\t"
        "cmtst	v7.8b, v7.8b, v0.8b\n\t"
        "zip1	v4.16b, v4.16b, v4.16b\n\t"
        "zip1	v5.16b, v5.16b, v5.16b\n\t"
        "zip1	v6.16b, v6.16b, v6.16b\n\t"
        "zip1	v7.16b, v7.16b, v7.16b\n\t"
        "and	v4.16b, v4.16b, v1.16b\n\t"
        "and	v5.16b, v5.16b, v1.16b\n\t"
        "and	v6.16b, v6.16b, v1.16b\n\t"
        "and	v7.16b, v7.16b, v1.16b\n\t"
        "st1	{v4.8h, v5.8h, v6.8h, v7.8h}, [%x[p]], #0x40\n\t"
        "dup	v4.8b, v3.b[0]\n\t"
        "dup	v5.8b, v3.b[1]\n\t"
        "dup	v6.8b, v3.b[2]\n\t"
        "dup	v7.8b, v3.b[3]\n\t"
        "cmtst	v4.8b, v4.8b, v0.8b\n\t"
        "cmtst	v5.8b, v5.8b, v0.8b\n\t"
        "cmtst	v6.8b, v6.8b, v0.8b\n\t"
        "cmtst	v7.8b, v7.8b, v0.8b\n\t"
        "zip1	v4.16b, v4.16b, v4.16b\n\t"
        "zip1	v5.16b, v5.16b, v5.16b\n\t"
        "zip1	v6.16b, v6.16b, v6.16b\n\t"
        "zip1	v7.16b, v7.16b, v7.16b\n\t"
        "and	v4.16b, v4.16b, v1.16b\n\t"
        "and	v5.16b, v5.16b, v1.16b\n\t"
        "and	v6.16b, v6.16b, v1.16b\n\t"
        "and	v7.16b, v7.16b, v1.16b\n\t"
        "st1	{v4.8h, v5.8h, v6.8h, v7.8h}, [%x[p]], #0x40\n\t"
        "dup	v4.8b, v3.b[4]\n\t"
        "dup	v5.8b, v3.b[5]\n\t"
        "dup	v6.8b, v3.b[6]\n\t"
        "dup	v7.8b, v3.b[7]\n\t"
        "cmtst	v4.8b, v4.8b, v0.8b\n\t"
        "cmtst	v5.8b, v5.8b, v0.8b\n\t"
        "cmtst	v6.8b, v6.8b, v0.8b\n\t"
        "cmtst	v7.8b, v7.8b, v0.8b\n\t"
        "zip1	v4.16b, v4.16b, v4.16b\n\t"
        "zip1	v5.16b, v5.16b, v5.16b\n\t"
        "zip1	v6.16b, v6.16b, v6.16b\n\t"
        "zip1	v7.16b, v7.16b, v7.16b\n\t"
        "and	v4.16b, v4.16b, v1.16b\n\t"
        "and	v5.16b, v5.16b, v1.16b\n\t"
        "and	v6.16b, v6.16b, v1.16b\n\t"
        "and	v7.16b, v7.16b, v1.16b\n\t"
        "st1	{v4.8h, v5.8h, v6.8h, v7.8h}, [%x[p]], #0x40\n\t"
        "dup	v4.8b, v3.b[8]\n\t"
        "dup	v5.8b, v3.b[9]\n\t"
        "dup	v6.8b, v3.b[10]\n\t"
        "dup	v7.8b, v3.b[11]\n\t"
        "cmtst	v4.8b, v4.8b, v0.8b\n\t"
        "cmtst	v5.8b, v5.8b, v0.8b\n\t"
        "cmtst	v6.8b, v6.8b, v0.8b\n\t"
        "cmtst	v7.8b, v7.8b, v0.8b\n\t"
        "zip1	v4.16b, v4.16b, v4.16b\n\t"
        "zip1	v5.16b, v5.16b, v5.16b\n\t"
        "zip1	v6.16b, v6.16b, v6.16b\n\t"
        "zip1	v7.16b, v7.16b, v7.16b\n\t"
        "and	v4.16b, v4.16b, v1.16b\n\t"
        "and	v5.16b, v5.16b, v1.16b\n\t"
        "and	v6.16b, v6.16b, v1.16b\n\t"
        "and	v7.16b, v7.16b, v1.16b\n\t"
        "st1	{v4.8h, v5.8h, v6.8h, v7.8h}, [%x[p]], #0x40\n\t"
        "dup	v4.8b, v3.b[12]\n\t"
        "dup	v5.8b, v3.b[13]\n\t"
        "dup	v6.8b, v3.b[14]\n\t"
        "dup	v7.8b, v3.b[15]\n\t"
        "cmtst	v4.8b, v4.8b, v0.8b\n\t"
        "cmtst	v5.8b, v5.8b, v0.8b\n\t"
        "cmtst	v6.8b, v6.8b, v0.8b\n\t"
        "cmtst	v7.8b, v7.8b, v0.8b\n\t"
        "zip1	v4.16b, v4.16b, v4.16b\n\t"
        "zip1	v5.16b, v5.16b, v5.16b\n\t"
        "zip1	v6.16b, v6.16b, v6.16b\n\t"
        "zip1	v7.16b, v7.16b, v7.16b\n\t"
        "and	v4.16b, v4.16b, v1.16b\n\t"
        "and	v5.16b, v5.16b, v1.16b\n\t"
        "and	v6.16b, v6.16b, v1.16b\n\t"
        "and	v7.16b, v7.16b, v1.16b\n\t"
        "st1	{v4.8h, v5.8h, v6.8h, v7.8h}, [%x[p]], #0x40\n\t"
        : [p] "+r" (p), [msg] "+r" (msg)
        : [L_kyber_aarch64_q] "S" (L_kyber_aarch64_q), [L_kyber_aarch64_consts] "S" (L_kyber_aarch64_consts), [L_sha3_aarch64_r] "S" (L_sha3_aarch64_r), [L_kyber_aarch64_zetas] "S" (L_kyber_aarch64_zetas), [L_kyber_aarch64_zetas_qinv] "S" (L_kyber_aarch64_zetas_qinv), [L_kyber_aarch64_zetas_inv] "S" (L_kyber_aarch64_zetas_inv), [L_kyber_aarch64_zetas_inv_qinv] "S" (L_kyber_aarch64_zetas_inv_qinv), [L_kyber_aarch64_zetas_mul] "S" (L_kyber_aarch64_zetas_mul), [L_kyber_aarch64_to_msg_neon_low] "S" (L_kyber_aarch64_to_msg_neon_low), [L_kyber_aarch64_to_msg_neon_high] "S" (L_kyber_aarch64_to_msg_neon_high), [L_kyber_aarch64_to_msg_neon_bits] "S" (L_kyber_aarch64_to_msg_neon_bits), [L_kyber_aarch64_from_msg_neon_q1half] "S" (L_kyber_aarch64_from_msg_neon_q1half), [L_kyber_aarch64_from_msg_neon_bits] "S" (L_kyber_aarch64_from_msg_neon_bits)
        : "memory", "x2", "x3", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "cc"
    );
}

int kyber_cmp_neon(const byte* a, const byte* b, int sz)
{
    __asm__ __volatile__ (
        "ld4	{v0.16b, v1.16b, v2.16b, v3.16b}, [%x[a]], #0x40\n\t"
        "ld4	{v4.16b, v5.16b, v6.16b, v7.16b}, [%x[b]], #0x40\n\t"
        "eor	v8.16b, v0.16b, v4.16b\n\t"
        "eor	v9.16b, v1.16b, v5.16b\n\t"
        "eor	v10.16b, v2.16b, v6.16b\n\t"
        "eor	v11.16b, v3.16b, v7.16b\n\t"
        "ld4	{v0.16b, v1.16b, v2.16b, v3.16b}, [%x[a]], #0x40\n\t"
        "ld4	{v4.16b, v5.16b, v6.16b, v7.16b}, [%x[b]], #0x40\n\t"
        "eor	v0.16b, v0.16b, v4.16b\n\t"
        "eor	v1.16b, v1.16b, v5.16b\n\t"
        "eor	v2.16b, v2.16b, v6.16b\n\t"
        "eor	v3.16b, v3.16b, v7.16b\n\t"
        "orr	v8.16b, v8.16b, v0.16b\n\t"
        "orr	v9.16b, v9.16b, v1.16b\n\t"
        "orr	v10.16b, v10.16b, v2.16b\n\t"
        "orr	v11.16b, v11.16b, v3.16b\n\t"
        "ld4	{v0.16b, v1.16b, v2.16b, v3.16b}, [%x[a]], #0x40\n\t"
        "ld4	{v4.16b, v5.16b, v6.16b, v7.16b}, [%x[b]], #0x40\n\t"
        "eor	v0.16b, v0.16b, v4.16b\n\t"
        "eor	v1.16b, v1.16b, v5.16b\n\t"
        "eor	v2.16b, v2.16b, v6.16b\n\t"
        "eor	v3.16b, v3.16b, v7.16b\n\t"
        "orr	v8.16b, v8.16b, v0.16b\n\t"
        "orr	v9.16b, v9.16b, v1.16b\n\t"
        "orr	v10.16b, v10.16b, v2.16b\n\t"
        "orr	v11.16b, v11.16b, v3.16b\n\t"
        "ld4	{v0.16b, v1.16b, v2.16b, v3.16b}, [%x[a]], #0x40\n\t"
        "ld4	{v4.16b, v5.16b, v6.16b, v7.16b}, [%x[b]], #0x40\n\t"
        "eor	v0.16b, v0.16b, v4.16b\n\t"
        "eor	v1.16b, v1.16b, v5.16b\n\t"
        "eor	v2.16b, v2.16b, v6.16b\n\t"
        "eor	v3.16b, v3.16b, v7.16b\n\t"
        "orr	v8.16b, v8.16b, v0.16b\n\t"
        "orr	v9.16b, v9.16b, v1.16b\n\t"
        "orr	v10.16b, v10.16b, v2.16b\n\t"
        "orr	v11.16b, v11.16b, v3.16b\n\t"
        "ld4	{v0.16b, v1.16b, v2.16b, v3.16b}, [%x[a]], #0x40\n\t"
        "ld4	{v4.16b, v5.16b, v6.16b, v7.16b}, [%x[b]], #0x40\n\t"
        "eor	v0.16b, v0.16b, v4.16b\n\t"
        "eor	v1.16b, v1.16b, v5.16b\n\t"
        "eor	v2.16b, v2.16b, v6.16b\n\t"
        "eor	v3.16b, v3.16b, v7.16b\n\t"
        "orr	v8.16b, v8.16b, v0.16b\n\t"
        "orr	v9.16b, v9.16b, v1.16b\n\t"
        "orr	v10.16b, v10.16b, v2.16b\n\t"
        "orr	v11.16b, v11.16b, v3.16b\n\t"
        "ld4	{v0.16b, v1.16b, v2.16b, v3.16b}, [%x[a]], #0x40\n\t"
        "ld4	{v4.16b, v5.16b, v6.16b, v7.16b}, [%x[b]], #0x40\n\t"
        "eor	v0.16b, v0.16b, v4.16b\n\t"
        "eor	v1.16b, v1.16b, v5.16b\n\t"
        "eor	v2.16b, v2.16b, v6.16b\n\t"
        "eor	v3.16b, v3.16b, v7.16b\n\t"
        "orr	v8.16b, v8.16b, v0.16b\n\t"
        "orr	v9.16b, v9.16b, v1.16b\n\t"
        "orr	v10.16b, v10.16b, v2.16b\n\t"
        "orr	v11.16b, v11.16b, v3.16b\n\t"
        "ld4	{v0.16b, v1.16b, v2.16b, v3.16b}, [%x[a]], #0x40\n\t"
        "ld4	{v4.16b, v5.16b, v6.16b, v7.16b}, [%x[b]], #0x40\n\t"
        "eor	v0.16b, v0.16b, v4.16b\n\t"
        "eor	v1.16b, v1.16b, v5.16b\n\t"
        "eor	v2.16b, v2.16b, v6.16b\n\t"
        "eor	v3.16b, v3.16b, v7.16b\n\t"
        "orr	v8.16b, v8.16b, v0.16b\n\t"
        "orr	v9.16b, v9.16b, v1.16b\n\t"
        "orr	v10.16b, v10.16b, v2.16b\n\t"
        "orr	v11.16b, v11.16b, v3.16b\n\t"
        "ld4	{v0.16b, v1.16b, v2.16b, v3.16b}, [%x[a]], #0x40\n\t"
        "ld4	{v4.16b, v5.16b, v6.16b, v7.16b}, [%x[b]], #0x40\n\t"
        "eor	v0.16b, v0.16b, v4.16b\n\t"
        "eor	v1.16b, v1.16b, v5.16b\n\t"
        "eor	v2.16b, v2.16b, v6.16b\n\t"
        "eor	v3.16b, v3.16b, v7.16b\n\t"
        "orr	v8.16b, v8.16b, v0.16b\n\t"
        "orr	v9.16b, v9.16b, v1.16b\n\t"
        "orr	v10.16b, v10.16b, v2.16b\n\t"
        "orr	v11.16b, v11.16b, v3.16b\n\t"
        "ld4	{v0.16b, v1.16b, v2.16b, v3.16b}, [%x[a]], #0x40\n\t"
        "ld4	{v4.16b, v5.16b, v6.16b, v7.16b}, [%x[b]], #0x40\n\t"
        "eor	v0.16b, v0.16b, v4.16b\n\t"
        "eor	v1.16b, v1.16b, v5.16b\n\t"
        "eor	v2.16b, v2.16b, v6.16b\n\t"
        "eor	v3.16b, v3.16b, v7.16b\n\t"
        "orr	v8.16b, v8.16b, v0.16b\n\t"
        "orr	v9.16b, v9.16b, v1.16b\n\t"
        "orr	v10.16b, v10.16b, v2.16b\n\t"
        "orr	v11.16b, v11.16b, v3.16b\n\t"
        "ld4	{v0.16b, v1.16b, v2.16b, v3.16b}, [%x[a]], #0x40\n\t"
        "ld4	{v4.16b, v5.16b, v6.16b, v7.16b}, [%x[b]], #0x40\n\t"
        "eor	v0.16b, v0.16b, v4.16b\n\t"
        "eor	v1.16b, v1.16b, v5.16b\n\t"
        "eor	v2.16b, v2.16b, v6.16b\n\t"
        "eor	v3.16b, v3.16b, v7.16b\n\t"
        "orr	v8.16b, v8.16b, v0.16b\n\t"
        "orr	v9.16b, v9.16b, v1.16b\n\t"
        "orr	v10.16b, v10.16b, v2.16b\n\t"
        "orr	v11.16b, v11.16b, v3.16b\n\t"
        "ld4	{v0.16b, v1.16b, v2.16b, v3.16b}, [%x[a]], #0x40\n\t"
        "ld4	{v4.16b, v5.16b, v6.16b, v7.16b}, [%x[b]], #0x40\n\t"
        "eor	v0.16b, v0.16b, v4.16b\n\t"
        "eor	v1.16b, v1.16b, v5.16b\n\t"
        "eor	v2.16b, v2.16b, v6.16b\n\t"
        "eor	v3.16b, v3.16b, v7.16b\n\t"
        "orr	v8.16b, v8.16b, v0.16b\n\t"
        "orr	v9.16b, v9.16b, v1.16b\n\t"
        "orr	v10.16b, v10.16b, v2.16b\n\t"
        "orr	v11.16b, v11.16b, v3.16b\n\t"
        "ld4	{v0.16b, v1.16b, v2.16b, v3.16b}, [%x[a]], #0x40\n\t"
        "ld4	{v4.16b, v5.16b, v6.16b, v7.16b}, [%x[b]], #0x40\n\t"
        "eor	v0.16b, v0.16b, v4.16b\n\t"
        "eor	v1.16b, v1.16b, v5.16b\n\t"
        "eor	v2.16b, v2.16b, v6.16b\n\t"
        "eor	v3.16b, v3.16b, v7.16b\n\t"
        "orr	v8.16b, v8.16b, v0.16b\n\t"
        "orr	v9.16b, v9.16b, v1.16b\n\t"
        "orr	v10.16b, v10.16b, v2.16b\n\t"
        "orr	v11.16b, v11.16b, v3.16b\n\t"
        "subs	%w[sz], %w[sz], #0x300\n\t"
        "beq	L_kyber_aarch64_cmp_neon_done_%=\n\t"
        "ld4	{v0.16b, v1.16b, v2.16b, v3.16b}, [%x[a]], #0x40\n\t"
        "ld4	{v4.16b, v5.16b, v6.16b, v7.16b}, [%x[b]], #0x40\n\t"
        "eor	v0.16b, v0.16b, v4.16b\n\t"
        "eor	v1.16b, v1.16b, v5.16b\n\t"
        "eor	v2.16b, v2.16b, v6.16b\n\t"
        "eor	v3.16b, v3.16b, v7.16b\n\t"
        "orr	v8.16b, v8.16b, v0.16b\n\t"
        "orr	v9.16b, v9.16b, v1.16b\n\t"
        "orr	v10.16b, v10.16b, v2.16b\n\t"
        "orr	v11.16b, v11.16b, v3.16b\n\t"
        "ld4	{v0.16b, v1.16b, v2.16b, v3.16b}, [%x[a]], #0x40\n\t"
        "ld4	{v4.16b, v5.16b, v6.16b, v7.16b}, [%x[b]], #0x40\n\t"
        "eor	v0.16b, v0.16b, v4.16b\n\t"
        "eor	v1.16b, v1.16b, v5.16b\n\t"
        "eor	v2.16b, v2.16b, v6.16b\n\t"
        "eor	v3.16b, v3.16b, v7.16b\n\t"
        "orr	v8.16b, v8.16b, v0.16b\n\t"
        "orr	v9.16b, v9.16b, v1.16b\n\t"
        "orr	v10.16b, v10.16b, v2.16b\n\t"
        "orr	v11.16b, v11.16b, v3.16b\n\t"
        "ld4	{v0.16b, v1.16b, v2.16b, v3.16b}, [%x[a]], #0x40\n\t"
        "ld4	{v4.16b, v5.16b, v6.16b, v7.16b}, [%x[b]], #0x40\n\t"
        "eor	v0.16b, v0.16b, v4.16b\n\t"
        "eor	v1.16b, v1.16b, v5.16b\n\t"
        "eor	v2.16b, v2.16b, v6.16b\n\t"
        "eor	v3.16b, v3.16b, v7.16b\n\t"
        "orr	v8.16b, v8.16b, v0.16b\n\t"
        "orr	v9.16b, v9.16b, v1.16b\n\t"
        "orr	v10.16b, v10.16b, v2.16b\n\t"
        "orr	v11.16b, v11.16b, v3.16b\n\t"
        "ld4	{v0.16b, v1.16b, v2.16b, v3.16b}, [%x[a]], #0x40\n\t"
        "ld4	{v4.16b, v5.16b, v6.16b, v7.16b}, [%x[b]], #0x40\n\t"
        "eor	v0.16b, v0.16b, v4.16b\n\t"
        "eor	v1.16b, v1.16b, v5.16b\n\t"
        "eor	v2.16b, v2.16b, v6.16b\n\t"
        "eor	v3.16b, v3.16b, v7.16b\n\t"
        "orr	v8.16b, v8.16b, v0.16b\n\t"
        "orr	v9.16b, v9.16b, v1.16b\n\t"
        "orr	v10.16b, v10.16b, v2.16b\n\t"
        "orr	v11.16b, v11.16b, v3.16b\n\t"
        "ld4	{v0.16b, v1.16b, v2.16b, v3.16b}, [%x[a]], #0x40\n\t"
        "ld4	{v4.16b, v5.16b, v6.16b, v7.16b}, [%x[b]], #0x40\n\t"
        "eor	v0.16b, v0.16b, v4.16b\n\t"
        "eor	v1.16b, v1.16b, v5.16b\n\t"
        "eor	v2.16b, v2.16b, v6.16b\n\t"
        "eor	v3.16b, v3.16b, v7.16b\n\t"
        "orr	v8.16b, v8.16b, v0.16b\n\t"
        "orr	v9.16b, v9.16b, v1.16b\n\t"
        "orr	v10.16b, v10.16b, v2.16b\n\t"
        "orr	v11.16b, v11.16b, v3.16b\n\t"
        "subs	%w[sz], %w[sz], #0x140\n\t"
        "beq	L_kyber_aarch64_cmp_neon_done_%=\n\t"
        "ld4	{v0.16b, v1.16b, v2.16b, v3.16b}, [%x[a]], #0x40\n\t"
        "ld4	{v4.16b, v5.16b, v6.16b, v7.16b}, [%x[b]], #0x40\n\t"
        "eor	v0.16b, v0.16b, v4.16b\n\t"
        "eor	v1.16b, v1.16b, v5.16b\n\t"
        "eor	v2.16b, v2.16b, v6.16b\n\t"
        "eor	v3.16b, v3.16b, v7.16b\n\t"
        "orr	v8.16b, v8.16b, v0.16b\n\t"
        "orr	v9.16b, v9.16b, v1.16b\n\t"
        "orr	v10.16b, v10.16b, v2.16b\n\t"
        "orr	v11.16b, v11.16b, v3.16b\n\t"
        "ld4	{v0.16b, v1.16b, v2.16b, v3.16b}, [%x[a]], #0x40\n\t"
        "ld4	{v4.16b, v5.16b, v6.16b, v7.16b}, [%x[b]], #0x40\n\t"
        "eor	v0.16b, v0.16b, v4.16b\n\t"
        "eor	v1.16b, v1.16b, v5.16b\n\t"
        "eor	v2.16b, v2.16b, v6.16b\n\t"
        "eor	v3.16b, v3.16b, v7.16b\n\t"
        "orr	v8.16b, v8.16b, v0.16b\n\t"
        "orr	v9.16b, v9.16b, v1.16b\n\t"
        "orr	v10.16b, v10.16b, v2.16b\n\t"
        "orr	v11.16b, v11.16b, v3.16b\n\t"
        "ld4	{v0.16b, v1.16b, v2.16b, v3.16b}, [%x[a]], #0x40\n\t"
        "ld4	{v4.16b, v5.16b, v6.16b, v7.16b}, [%x[b]], #0x40\n\t"
        "eor	v0.16b, v0.16b, v4.16b\n\t"
        "eor	v1.16b, v1.16b, v5.16b\n\t"
        "eor	v2.16b, v2.16b, v6.16b\n\t"
        "eor	v3.16b, v3.16b, v7.16b\n\t"
        "orr	v8.16b, v8.16b, v0.16b\n\t"
        "orr	v9.16b, v9.16b, v1.16b\n\t"
        "orr	v10.16b, v10.16b, v2.16b\n\t"
        "orr	v11.16b, v11.16b, v3.16b\n\t"
        "ld4	{v0.16b, v1.16b, v2.16b, v3.16b}, [%x[a]], #0x40\n\t"
        "ld4	{v4.16b, v5.16b, v6.16b, v7.16b}, [%x[b]], #0x40\n\t"
        "eor	v0.16b, v0.16b, v4.16b\n\t"
        "eor	v1.16b, v1.16b, v5.16b\n\t"
        "eor	v2.16b, v2.16b, v6.16b\n\t"
        "eor	v3.16b, v3.16b, v7.16b\n\t"
        "orr	v8.16b, v8.16b, v0.16b\n\t"
        "orr	v9.16b, v9.16b, v1.16b\n\t"
        "orr	v10.16b, v10.16b, v2.16b\n\t"
        "orr	v11.16b, v11.16b, v3.16b\n\t"
        "ld4	{v0.16b, v1.16b, v2.16b, v3.16b}, [%x[a]], #0x40\n\t"
        "ld4	{v4.16b, v5.16b, v6.16b, v7.16b}, [%x[b]], #0x40\n\t"
        "eor	v0.16b, v0.16b, v4.16b\n\t"
        "eor	v1.16b, v1.16b, v5.16b\n\t"
        "eor	v2.16b, v2.16b, v6.16b\n\t"
        "eor	v3.16b, v3.16b, v7.16b\n\t"
        "orr	v8.16b, v8.16b, v0.16b\n\t"
        "orr	v9.16b, v9.16b, v1.16b\n\t"
        "orr	v10.16b, v10.16b, v2.16b\n\t"
        "orr	v11.16b, v11.16b, v3.16b\n\t"
        "ld4	{v0.16b, v1.16b, v2.16b, v3.16b}, [%x[a]], #0x40\n\t"
        "ld4	{v4.16b, v5.16b, v6.16b, v7.16b}, [%x[b]], #0x40\n\t"
        "eor	v0.16b, v0.16b, v4.16b\n\t"
        "eor	v1.16b, v1.16b, v5.16b\n\t"
        "eor	v2.16b, v2.16b, v6.16b\n\t"
        "eor	v3.16b, v3.16b, v7.16b\n\t"
        "orr	v8.16b, v8.16b, v0.16b\n\t"
        "orr	v9.16b, v9.16b, v1.16b\n\t"
        "orr	v10.16b, v10.16b, v2.16b\n\t"
        "orr	v11.16b, v11.16b, v3.16b\n\t"
        "ld4	{v0.16b, v1.16b, v2.16b, v3.16b}, [%x[a]], #0x40\n\t"
        "ld4	{v4.16b, v5.16b, v6.16b, v7.16b}, [%x[b]], #0x40\n\t"
        "eor	v0.16b, v0.16b, v4.16b\n\t"
        "eor	v1.16b, v1.16b, v5.16b\n\t"
        "eor	v2.16b, v2.16b, v6.16b\n\t"
        "eor	v3.16b, v3.16b, v7.16b\n\t"
        "orr	v8.16b, v8.16b, v0.16b\n\t"
        "orr	v9.16b, v9.16b, v1.16b\n\t"
        "orr	v10.16b, v10.16b, v2.16b\n\t"
        "orr	v11.16b, v11.16b, v3.16b\n\t"
        "ld2	{v0.16b, v1.16b}, [%x[a]]\n\t"
        "ld2	{v4.16b, v5.16b}, [%x[b]]\n\t"
        "eor	v0.16b, v0.16b, v4.16b\n\t"
        "eor	v1.16b, v1.16b, v5.16b\n\t"
        "orr	v8.16b, v8.16b, v0.16b\n\t"
        "orr	v9.16b, v9.16b, v1.16b\n\t"
        "\n"
    "L_kyber_aarch64_cmp_neon_done_%=: \n\t"
        "orr	v8.16b, v8.16b, v9.16b\n\t"
        "orr	v10.16b, v10.16b, v11.16b\n\t"
        "orr	v8.16b, v8.16b, v10.16b\n\t"
        "ins	v9.b[0], v8.b[1]\n\t"
        "orr	v8.16b, v8.16b, v9.16b\n\t"
        "mov	x0, v8.d[0]\n\t"
        "subs	x0, x0, xzr\n\t"
        "csetm	w0, ne\n\t"
        : [a] "+r" (a), [b] "+r" (b), [sz] "+r" (sz)
        : [L_kyber_aarch64_q] "S" (L_kyber_aarch64_q), [L_kyber_aarch64_consts] "S" (L_kyber_aarch64_consts), [L_sha3_aarch64_r] "S" (L_sha3_aarch64_r), [L_kyber_aarch64_zetas] "S" (L_kyber_aarch64_zetas), [L_kyber_aarch64_zetas_qinv] "S" (L_kyber_aarch64_zetas_qinv), [L_kyber_aarch64_zetas_inv] "S" (L_kyber_aarch64_zetas_inv), [L_kyber_aarch64_zetas_inv_qinv] "S" (L_kyber_aarch64_zetas_inv_qinv), [L_kyber_aarch64_zetas_mul] "S" (L_kyber_aarch64_zetas_mul), [L_kyber_aarch64_to_msg_neon_low] "S" (L_kyber_aarch64_to_msg_neon_low), [L_kyber_aarch64_to_msg_neon_high] "S" (L_kyber_aarch64_to_msg_neon_high), [L_kyber_aarch64_to_msg_neon_bits] "S" (L_kyber_aarch64_to_msg_neon_bits), [L_kyber_aarch64_from_msg_neon_q1half] "S" (L_kyber_aarch64_from_msg_neon_q1half), [L_kyber_aarch64_from_msg_neon_bits] "S" (L_kyber_aarch64_from_msg_neon_bits)
        : "memory", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "cc"
    );
    return (word32)(size_t)a;
}

static const word16 L_kyber_aarch64_rej_uniform_neon_mask[] = {
    0xfff,
    0xfff,
    0xfff,
    0xfff,
    0xfff,
    0xfff,
    0xfff,
    0xfff,
};

static const word16 L_kyber_aarch64_rej_uniform_neon_bits[] = {
    0x1,
    0x2,
    0x4,
    0x8,
    0x10,
    0x20,
    0x40,
    0x80,
};

static const word8 L_kyber_aarch64_rej_uniform_neon_indices[] = {
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x4,
    0x5,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x4,
    0x5,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x4,
    0x5,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x4,
    0x5,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x6,
    0x7,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x6,
    0x7,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x6,
    0x7,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x6,
    0x7,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x4,
    0x5,
    0x6,
    0x7,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x4,
    0x5,
    0x6,
    0x7,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x4,
    0x5,
    0x6,
    0x7,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x4,
    0x5,
    0x6,
    0x7,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x8,
    0x9,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x8,
    0x9,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x8,
    0x9,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x8,
    0x9,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x4,
    0x5,
    0x8,
    0x9,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x4,
    0x5,
    0x8,
    0x9,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x4,
    0x5,
    0x8,
    0x9,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x4,
    0x5,
    0x8,
    0x9,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x6,
    0x7,
    0x8,
    0x9,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x6,
    0x7,
    0x8,
    0x9,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x6,
    0x7,
    0x8,
    0x9,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x6,
    0x7,
    0x8,
    0x9,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x4,
    0x5,
    0x6,
    0x7,
    0x8,
    0x9,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x4,
    0x5,
    0x6,
    0x7,
    0x8,
    0x9,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x4,
    0x5,
    0x6,
    0x7,
    0x8,
    0x9,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x4,
    0x5,
    0x6,
    0x7,
    0x8,
    0x9,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xa,
    0xb,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0xa,
    0xb,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0xa,
    0xb,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0xa,
    0xb,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x4,
    0x5,
    0xa,
    0xb,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x4,
    0x5,
    0xa,
    0xb,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x4,
    0x5,
    0xa,
    0xb,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x4,
    0x5,
    0xa,
    0xb,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x6,
    0x7,
    0xa,
    0xb,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x6,
    0x7,
    0xa,
    0xb,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x6,
    0x7,
    0xa,
    0xb,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x6,
    0x7,
    0xa,
    0xb,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x4,
    0x5,
    0x6,
    0x7,
    0xa,
    0xb,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x4,
    0x5,
    0x6,
    0x7,
    0xa,
    0xb,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x4,
    0x5,
    0x6,
    0x7,
    0xa,
    0xb,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x4,
    0x5,
    0x6,
    0x7,
    0xa,
    0xb,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x8,
    0x9,
    0xa,
    0xb,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x8,
    0x9,
    0xa,
    0xb,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x8,
    0x9,
    0xa,
    0xb,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x8,
    0x9,
    0xa,
    0xb,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x4,
    0x5,
    0x8,
    0x9,
    0xa,
    0xb,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x4,
    0x5,
    0x8,
    0x9,
    0xa,
    0xb,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x4,
    0x5,
    0x8,
    0x9,
    0xa,
    0xb,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x4,
    0x5,
    0x8,
    0x9,
    0xa,
    0xb,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x6,
    0x7,
    0x8,
    0x9,
    0xa,
    0xb,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x6,
    0x7,
    0x8,
    0x9,
    0xa,
    0xb,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x6,
    0x7,
    0x8,
    0x9,
    0xa,
    0xb,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x6,
    0x7,
    0x8,
    0x9,
    0xa,
    0xb,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x4,
    0x5,
    0x6,
    0x7,
    0x8,
    0x9,
    0xa,
    0xb,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x4,
    0x5,
    0x6,
    0x7,
    0x8,
    0x9,
    0xa,
    0xb,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x4,
    0x5,
    0x6,
    0x7,
    0x8,
    0x9,
    0xa,
    0xb,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x4,
    0x5,
    0x6,
    0x7,
    0x8,
    0x9,
    0xa,
    0xb,
    0xff,
    0xff,
    0xff,
    0xff,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x4,
    0x5,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x4,
    0x5,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x4,
    0x5,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x4,
    0x5,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x6,
    0x7,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x6,
    0x7,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x6,
    0x7,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x6,
    0x7,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x4,
    0x5,
    0x6,
    0x7,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x4,
    0x5,
    0x6,
    0x7,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x4,
    0x5,
    0x6,
    0x7,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x4,
    0x5,
    0x6,
    0x7,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x8,
    0x9,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x8,
    0x9,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x8,
    0x9,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x8,
    0x9,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x4,
    0x5,
    0x8,
    0x9,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x4,
    0x5,
    0x8,
    0x9,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x4,
    0x5,
    0x8,
    0x9,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x4,
    0x5,
    0x8,
    0x9,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x6,
    0x7,
    0x8,
    0x9,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x6,
    0x7,
    0x8,
    0x9,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x6,
    0x7,
    0x8,
    0x9,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x6,
    0x7,
    0x8,
    0x9,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x4,
    0x5,
    0x6,
    0x7,
    0x8,
    0x9,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x4,
    0x5,
    0x6,
    0x7,
    0x8,
    0x9,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x4,
    0x5,
    0x6,
    0x7,
    0x8,
    0x9,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x4,
    0x5,
    0x6,
    0x7,
    0x8,
    0x9,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xa,
    0xb,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0xa,
    0xb,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0xa,
    0xb,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0xa,
    0xb,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x4,
    0x5,
    0xa,
    0xb,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x4,
    0x5,
    0xa,
    0xb,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x4,
    0x5,
    0xa,
    0xb,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x4,
    0x5,
    0xa,
    0xb,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x6,
    0x7,
    0xa,
    0xb,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x6,
    0x7,
    0xa,
    0xb,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x6,
    0x7,
    0xa,
    0xb,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x6,
    0x7,
    0xa,
    0xb,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x4,
    0x5,
    0x6,
    0x7,
    0xa,
    0xb,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x4,
    0x5,
    0x6,
    0x7,
    0xa,
    0xb,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x4,
    0x5,
    0x6,
    0x7,
    0xa,
    0xb,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x4,
    0x5,
    0x6,
    0x7,
    0xa,
    0xb,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0x8,
    0x9,
    0xa,
    0xb,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x8,
    0x9,
    0xa,
    0xb,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x8,
    0x9,
    0xa,
    0xb,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x8,
    0x9,
    0xa,
    0xb,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x4,
    0x5,
    0x8,
    0x9,
    0xa,
    0xb,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x4,
    0x5,
    0x8,
    0x9,
    0xa,
    0xb,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x4,
    0x5,
    0x8,
    0x9,
    0xa,
    0xb,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x4,
    0x5,
    0x8,
    0x9,
    0xa,
    0xb,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0x6,
    0x7,
    0x8,
    0x9,
    0xa,
    0xb,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x6,
    0x7,
    0x8,
    0x9,
    0xa,
    0xb,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x6,
    0x7,
    0x8,
    0x9,
    0xa,
    0xb,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x6,
    0x7,
    0x8,
    0x9,
    0xa,
    0xb,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0x4,
    0x5,
    0x6,
    0x7,
    0x8,
    0x9,
    0xa,
    0xb,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x4,
    0x5,
    0x6,
    0x7,
    0x8,
    0x9,
    0xa,
    0xb,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x4,
    0x5,
    0x6,
    0x7,
    0x8,
    0x9,
    0xa,
    0xb,
    0xc,
    0xd,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x4,
    0x5,
    0x6,
    0x7,
    0x8,
    0x9,
    0xa,
    0xb,
    0xc,
    0xd,
    0xff,
    0xff,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x4,
    0x5,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x4,
    0x5,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x4,
    0x5,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x4,
    0x5,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x6,
    0x7,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x6,
    0x7,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x6,
    0x7,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x6,
    0x7,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x4,
    0x5,
    0x6,
    0x7,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x4,
    0x5,
    0x6,
    0x7,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x4,
    0x5,
    0x6,
    0x7,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x4,
    0x5,
    0x6,
    0x7,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x8,
    0x9,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x8,
    0x9,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x8,
    0x9,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x8,
    0x9,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x4,
    0x5,
    0x8,
    0x9,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x4,
    0x5,
    0x8,
    0x9,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x4,
    0x5,
    0x8,
    0x9,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x4,
    0x5,
    0x8,
    0x9,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x6,
    0x7,
    0x8,
    0x9,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x6,
    0x7,
    0x8,
    0x9,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x6,
    0x7,
    0x8,
    0x9,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x6,
    0x7,
    0x8,
    0x9,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x4,
    0x5,
    0x6,
    0x7,
    0x8,
    0x9,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x4,
    0x5,
    0x6,
    0x7,
    0x8,
    0x9,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x4,
    0x5,
    0x6,
    0x7,
    0x8,
    0x9,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x4,
    0x5,
    0x6,
    0x7,
    0x8,
    0x9,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xa,
    0xb,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0xa,
    0xb,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0xa,
    0xb,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0xa,
    0xb,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x4,
    0x5,
    0xa,
    0xb,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x4,
    0x5,
    0xa,
    0xb,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x4,
    0x5,
    0xa,
    0xb,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x4,
    0x5,
    0xa,
    0xb,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x6,
    0x7,
    0xa,
    0xb,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x6,
    0x7,
    0xa,
    0xb,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x6,
    0x7,
    0xa,
    0xb,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x6,
    0x7,
    0xa,
    0xb,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x4,
    0x5,
    0x6,
    0x7,
    0xa,
    0xb,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x4,
    0x5,
    0x6,
    0x7,
    0xa,
    0xb,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x4,
    0x5,
    0x6,
    0x7,
    0xa,
    0xb,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x4,
    0x5,
    0x6,
    0x7,
    0xa,
    0xb,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0x8,
    0x9,
    0xa,
    0xb,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x8,
    0x9,
    0xa,
    0xb,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x8,
    0x9,
    0xa,
    0xb,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x8,
    0x9,
    0xa,
    0xb,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x4,
    0x5,
    0x8,
    0x9,
    0xa,
    0xb,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x4,
    0x5,
    0x8,
    0x9,
    0xa,
    0xb,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x4,
    0x5,
    0x8,
    0x9,
    0xa,
    0xb,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x4,
    0x5,
    0x8,
    0x9,
    0xa,
    0xb,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0x6,
    0x7,
    0x8,
    0x9,
    0xa,
    0xb,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x6,
    0x7,
    0x8,
    0x9,
    0xa,
    0xb,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x6,
    0x7,
    0x8,
    0x9,
    0xa,
    0xb,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x6,
    0x7,
    0x8,
    0x9,
    0xa,
    0xb,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0x4,
    0x5,
    0x6,
    0x7,
    0x8,
    0x9,
    0xa,
    0xb,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x4,
    0x5,
    0x6,
    0x7,
    0x8,
    0x9,
    0xa,
    0xb,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x4,
    0x5,
    0x6,
    0x7,
    0x8,
    0x9,
    0xa,
    0xb,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x4,
    0x5,
    0x6,
    0x7,
    0x8,
    0x9,
    0xa,
    0xb,
    0xe,
    0xf,
    0xff,
    0xff,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x4,
    0x5,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x4,
    0x5,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x4,
    0x5,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x4,
    0x5,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x6,
    0x7,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x6,
    0x7,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x6,
    0x7,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x6,
    0x7,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x4,
    0x5,
    0x6,
    0x7,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x4,
    0x5,
    0x6,
    0x7,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x4,
    0x5,
    0x6,
    0x7,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x4,
    0x5,
    0x6,
    0x7,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0x8,
    0x9,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x8,
    0x9,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x8,
    0x9,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x8,
    0x9,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x4,
    0x5,
    0x8,
    0x9,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x4,
    0x5,
    0x8,
    0x9,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x4,
    0x5,
    0x8,
    0x9,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x4,
    0x5,
    0x8,
    0x9,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0x6,
    0x7,
    0x8,
    0x9,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x6,
    0x7,
    0x8,
    0x9,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x6,
    0x7,
    0x8,
    0x9,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x6,
    0x7,
    0x8,
    0x9,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0x4,
    0x5,
    0x6,
    0x7,
    0x8,
    0x9,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x4,
    0x5,
    0x6,
    0x7,
    0x8,
    0x9,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x4,
    0x5,
    0x6,
    0x7,
    0x8,
    0x9,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x4,
    0x5,
    0x6,
    0x7,
    0x8,
    0x9,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xa,
    0xb,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0xa,
    0xb,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0xa,
    0xb,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0xa,
    0xb,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x4,
    0x5,
    0xa,
    0xb,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x4,
    0x5,
    0xa,
    0xb,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x4,
    0x5,
    0xa,
    0xb,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x4,
    0x5,
    0xa,
    0xb,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0x6,
    0x7,
    0xa,
    0xb,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x6,
    0x7,
    0xa,
    0xb,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x6,
    0x7,
    0xa,
    0xb,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x6,
    0x7,
    0xa,
    0xb,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0x4,
    0x5,
    0x6,
    0x7,
    0xa,
    0xb,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x4,
    0x5,
    0x6,
    0x7,
    0xa,
    0xb,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x4,
    0x5,
    0x6,
    0x7,
    0xa,
    0xb,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x4,
    0x5,
    0x6,
    0x7,
    0xa,
    0xb,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0x8,
    0x9,
    0xa,
    0xb,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x8,
    0x9,
    0xa,
    0xb,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x8,
    0x9,
    0xa,
    0xb,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x8,
    0x9,
    0xa,
    0xb,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0x4,
    0x5,
    0x8,
    0x9,
    0xa,
    0xb,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x4,
    0x5,
    0x8,
    0x9,
    0xa,
    0xb,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x4,
    0x5,
    0x8,
    0x9,
    0xa,
    0xb,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x4,
    0x5,
    0x8,
    0x9,
    0xa,
    0xb,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0x6,
    0x7,
    0x8,
    0x9,
    0xa,
    0xb,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x6,
    0x7,
    0x8,
    0x9,
    0xa,
    0xb,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0x2,
    0x3,
    0x6,
    0x7,
    0x8,
    0x9,
    0xa,
    0xb,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x6,
    0x7,
    0x8,
    0x9,
    0xa,
    0xb,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0x4,
    0x5,
    0x6,
    0x7,
    0x8,
    0x9,
    0xa,
    0xb,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0xff,
    0xff,
    0x0,
    0x1,
    0x4,
    0x5,
    0x6,
    0x7,
    0x8,
    0x9,
    0xa,
    0xb,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0x2,
    0x3,
    0x4,
    0x5,
    0x6,
    0x7,
    0x8,
    0x9,
    0xa,
    0xb,
    0xc,
    0xd,
    0xe,
    0xf,
    0xff,
    0xff,
    0x0,
    0x1,
    0x2,
    0x3,
    0x4,
    0x5,
    0x6,
    0x7,
    0x8,
    0x9,
    0xa,
    0xb,
    0xc,
    0xd,
    0xe,
    0xf,
};

unsigned int kyber_rej_uniform_neon(sword16* p, unsigned int len, const byte* r, unsigned int rLen)
{
    __asm__ __volatile__ (
#ifndef __APPLE__
        "adrp x4, %[L_kyber_aarch64_rej_uniform_neon_mask]\n\t"
        "add  x4, x4, :lo12:%[L_kyber_aarch64_rej_uniform_neon_mask]\n\t"
#else
        "adrp x4, %[L_kyber_aarch64_rej_uniform_neon_mask]@PAGE\n\t"
        "add  x4, x4, %[L_kyber_aarch64_rej_uniform_neon_mask]@PAGEOFF\n\t"
#endif /* __APPLE__ */
#ifndef __APPLE__
        "adrp x5, %[L_kyber_aarch64_q]\n\t"
        "add  x5, x5, :lo12:%[L_kyber_aarch64_q]\n\t"
#else
        "adrp x5, %[L_kyber_aarch64_q]@PAGE\n\t"
        "add  x5, x5, %[L_kyber_aarch64_q]@PAGEOFF\n\t"
#endif /* __APPLE__ */
#ifndef __APPLE__
        "adrp x6, %[L_kyber_aarch64_rej_uniform_neon_bits]\n\t"
        "add  x6, x6, :lo12:%[L_kyber_aarch64_rej_uniform_neon_bits]\n\t"
#else
        "adrp x6, %[L_kyber_aarch64_rej_uniform_neon_bits]@PAGE\n\t"
        "add  x6, x6, %[L_kyber_aarch64_rej_uniform_neon_bits]@PAGEOFF\n\t"
#endif /* __APPLE__ */
#ifndef __APPLE__
        "adrp x7, %[L_kyber_aarch64_rej_uniform_neon_indices]\n\t"
        "add  x7, x7, :lo12:%[L_kyber_aarch64_rej_uniform_neon_indices]\n\t"
#else
        "adrp x7, %[L_kyber_aarch64_rej_uniform_neon_indices]@PAGE\n\t"
        "add  x7, x7, %[L_kyber_aarch64_rej_uniform_neon_indices]@PAGEOFF\n\t"
#endif /* __APPLE__ */
        "eor	v1.16b, v1.16b, v1.16b\n\t"
        "eor	v12.16b, v12.16b, v12.16b\n\t"
        "eor	v13.16b, v13.16b, v13.16b\n\t"
        "eor	x12, x12, x12\n\t"
        "eor	v10.16b, v10.16b, v10.16b\n\t"
        "eor	v11.16b, v11.16b, v11.16b\n\t"
        "mov	x13, #0xd01\n\t"
        "ldr	q0, [x4]\n\t"
        "ldr	q3, [x5]\n\t"
        "ldr	q2, [x6]\n\t"
        "subs	wzr, %w[len], #0\n\t"
        "beq	L_kyber_aarch64_rej_uniform_neon_done_%=\n\t"
        "subs	wzr, %w[len], #16\n\t"
        "blt	L_kyber_aarch64_rej_uniform_neon_loop_4_%=\n\t"
        "\n"
    "L_kyber_aarch64_rej_uniform_neon_loop_16_%=: \n\t"
        "ld3	{v4.8b, v5.8b, v6.8b}, [%x[r]], #24\n\t"
        "zip1	v4.16b, v4.16b, v1.16b\n\t"
        "zip1	v5.16b, v5.16b, v1.16b\n\t"
        "zip1	v6.16b, v6.16b, v1.16b\n\t"
        "shl	v7.8h, v5.8h, #8\n\t"
        "ushr	v8.8h, v5.8h, #4\n\t"
        "shl	v6.8h, v6.8h, #4\n\t"
        "orr	v4.16b, v4.16b, v7.16b\n\t"
        "orr	v5.16b, v8.16b, v6.16b\n\t"
        "and	v7.16b, v4.16b, v0.16b\n\t"
        "and	v8.16b, v5.16b, v0.16b\n\t"
        "zip1	v4.8h, v7.8h, v8.8h\n\t"
        "zip2	v5.8h, v7.8h, v8.8h\n\t"
        "cmgt	v7.8h, v3.8h, v4.8h\n\t"
        "cmgt	v8.8h, v3.8h, v5.8h\n\t"
        "ushr	v12.8h, v7.8h, #15\n\t"
        "ushr	v13.8h, v8.8h, #15\n\t"
        "addv	h12, v12.8h\n\t"
        "addv	h13, v13.8h\n\t"
        "mov	x10, v12.d[0]\n\t"
        "mov	x11, v13.d[0]\n\t"
        "and	v10.16b, v7.16b, v2.16b\n\t"
        "and	v11.16b, v8.16b, v2.16b\n\t"
        "addv	h10, v10.8h\n\t"
        "addv	h11, v11.8h\n\t"
        "mov	w8, v10.s[0]\n\t"
        "mov	w9, v11.s[0]\n\t"
        "lsl	w8, w8, #4\n\t"
        "lsl	w9, w9, #4\n\t"
        "ldr	q10, [x7, x8]\n\t"
        "ldr	q11, [x7, x9]\n\t"
        "tbl	v7.16b, {v4.16b}, v10.16b\n\t"
        "tbl	v8.16b, {v5.16b}, v11.16b\n\t"
        "str	q7, [%x[p]]\n\t"
        "add	%x[p], %x[p], x10, lsl 1\n\t"
        "add	x12, x12, x10\n\t"
        "str	q8, [%x[p]]\n\t"
        "add	%x[p], %x[p], x11, lsl 1\n\t"
        "add	x12, x12, x11\n\t"
        "subs	%w[rLen], %w[rLen], #24\n\t"
        "beq	L_kyber_aarch64_rej_uniform_neon_done_%=\n\t"
        "sub	w10, %w[len], w12\n\t"
        "subs	x10, x10, #16\n\t"
        "blt	L_kyber_aarch64_rej_uniform_neon_loop_4_%=\n\t"
        "b	L_kyber_aarch64_rej_uniform_neon_loop_16_%=\n\t"
        "\n"
    "L_kyber_aarch64_rej_uniform_neon_loop_4_%=: \n\t"
        "subs	w10, %w[len], w12\n\t"
        "beq	L_kyber_aarch64_rej_uniform_neon_done_%=\n\t"
        "subs	x10, x10, #4\n\t"
        "blt	L_kyber_aarch64_rej_uniform_neon_loop_lt_4_%=\n\t"
        "ldr	x4, [%x[r]], #6\n\t"
        "lsr	x5, x4, #12\n\t"
        "lsr	x6, x4, #24\n\t"
        "lsr	x7, x4, #36\n\t"
        "and	x4, x4, #0xfff\n\t"
        "and	x5, x5, #0xfff\n\t"
        "and	x6, x6, #0xfff\n\t"
        "and	x7, x7, #0xfff\n\t"
        "strh	w4, [%x[p]]\n\t"
        "subs	xzr, x4, x13\n\t"
        "cinc	%x[p], %x[p], lt\n\t"
        "cinc	%x[p], %x[p], lt\n\t"
        "cinc	x12, x12, lt\n\t"
        "strh	w5, [%x[p]]\n\t"
        "subs	xzr, x5, x13\n\t"
        "cinc	%x[p], %x[p], lt\n\t"
        "cinc	%x[p], %x[p], lt\n\t"
        "cinc	x12, x12, lt\n\t"
        "strh	w6, [%x[p]]\n\t"
        "subs	xzr, x6, x13\n\t"
        "cinc	%x[p], %x[p], lt\n\t"
        "cinc	%x[p], %x[p], lt\n\t"
        "cinc	x12, x12, lt\n\t"
        "strh	w7, [%x[p]]\n\t"
        "subs	xzr, x7, x13\n\t"
        "cinc	%x[p], %x[p], lt\n\t"
        "cinc	%x[p], %x[p], lt\n\t"
        "cinc	x12, x12, lt\n\t"
        "subs	%w[rLen], %w[rLen], #6\n\t"
        "beq	L_kyber_aarch64_rej_uniform_neon_done_%=\n\t"
        "b	L_kyber_aarch64_rej_uniform_neon_loop_4_%=\n\t"
        "\n"
    "L_kyber_aarch64_rej_uniform_neon_loop_lt_4_%=: \n\t"
        "ldr	x4, [%x[r]], #6\n\t"
        "lsr	x5, x4, #12\n\t"
        "lsr	x6, x4, #24\n\t"
        "lsr	x7, x4, #36\n\t"
        "and	x4, x4, #0xfff\n\t"
        "and	x5, x5, #0xfff\n\t"
        "and	x6, x6, #0xfff\n\t"
        "and	x7, x7, #0xfff\n\t"
        "strh	w4, [%x[p]]\n\t"
        "subs	xzr, x4, x13\n\t"
        "cinc	%x[p], %x[p], lt\n\t"
        "cinc	%x[p], %x[p], lt\n\t"
        "cinc	x12, x12, lt\n\t"
        "subs	wzr, %w[len], w12\n\t"
        "beq	L_kyber_aarch64_rej_uniform_neon_done_%=\n\t"
        "strh	w5, [%x[p]]\n\t"
        "subs	xzr, x5, x13\n\t"
        "cinc	%x[p], %x[p], lt\n\t"
        "cinc	%x[p], %x[p], lt\n\t"
        "cinc	x12, x12, lt\n\t"
        "subs	wzr, %w[len], w12\n\t"
        "beq	L_kyber_aarch64_rej_uniform_neon_done_%=\n\t"
        "strh	w6, [%x[p]]\n\t"
        "subs	xzr, x6, x13\n\t"
        "cinc	%x[p], %x[p], lt\n\t"
        "cinc	%x[p], %x[p], lt\n\t"
        "cinc	x12, x12, lt\n\t"
        "subs	wzr, %w[len], w12\n\t"
        "beq	L_kyber_aarch64_rej_uniform_neon_done_%=\n\t"
        "strh	w7, [%x[p]]\n\t"
        "subs	xzr, x7, x13\n\t"
        "cinc	%x[p], %x[p], lt\n\t"
        "cinc	%x[p], %x[p], lt\n\t"
        "cinc	x12, x12, lt\n\t"
        "subs	wzr, %w[len], w12\n\t"
        "beq	L_kyber_aarch64_rej_uniform_neon_done_%=\n\t"
        "subs	%w[rLen], %w[rLen], #6\n\t"
        "beq	L_kyber_aarch64_rej_uniform_neon_done_%=\n\t"
        "b	L_kyber_aarch64_rej_uniform_neon_loop_lt_4_%=\n\t"
        "\n"
    "L_kyber_aarch64_rej_uniform_neon_done_%=: \n\t"
        "mov	x0, x12\n\t"
        : [p] "+r" (p), [len] "+r" (len), [r] "+r" (r), [rLen] "+r" (rLen)
        : [L_kyber_aarch64_q] "S" (L_kyber_aarch64_q), [L_kyber_aarch64_consts] "S" (L_kyber_aarch64_consts), [L_sha3_aarch64_r] "S" (L_sha3_aarch64_r), [L_kyber_aarch64_zetas] "S" (L_kyber_aarch64_zetas), [L_kyber_aarch64_zetas_qinv] "S" (L_kyber_aarch64_zetas_qinv), [L_kyber_aarch64_zetas_inv] "S" (L_kyber_aarch64_zetas_inv), [L_kyber_aarch64_zetas_inv_qinv] "S" (L_kyber_aarch64_zetas_inv_qinv), [L_kyber_aarch64_zetas_mul] "S" (L_kyber_aarch64_zetas_mul), [L_kyber_aarch64_to_msg_neon_low] "S" (L_kyber_aarch64_to_msg_neon_low), [L_kyber_aarch64_to_msg_neon_high] "S" (L_kyber_aarch64_to_msg_neon_high), [L_kyber_aarch64_to_msg_neon_bits] "S" (L_kyber_aarch64_to_msg_neon_bits), [L_kyber_aarch64_from_msg_neon_q1half] "S" (L_kyber_aarch64_from_msg_neon_q1half), [L_kyber_aarch64_from_msg_neon_bits] "S" (L_kyber_aarch64_from_msg_neon_bits), [L_kyber_aarch64_rej_uniform_neon_mask] "S" (L_kyber_aarch64_rej_uniform_neon_mask), [L_kyber_aarch64_rej_uniform_neon_bits] "S" (L_kyber_aarch64_rej_uniform_neon_bits), [L_kyber_aarch64_rej_uniform_neon_indices] "S" (L_kyber_aarch64_rej_uniform_neon_indices)
        : "memory", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "cc"
    );
    return (word32)(size_t)p;
}

#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
void kyber_sha3_blocksx3_neon(word64* state)
{
    __asm__ __volatile__ (
        "stp	x29, x30, [sp, #-64]!\n\t"
        "add	x29, sp, #0\n\t"
#ifndef __APPLE__
        "adrp x27, %[L_sha3_aarch64_r]\n\t"
        "add  x27, x27, :lo12:%[L_sha3_aarch64_r]\n\t"
#else
        "adrp x27, %[L_sha3_aarch64_r]@PAGE\n\t"
        "add  x27, x27, %[L_sha3_aarch64_r]@PAGEOFF\n\t"
#endif /* __APPLE__ */
        "str	%x[state], [x29, #40]\n\t"
        "ld4	{v0.d, v1.d, v2.d, v3.d}[0], [%x[state]], #32\n\t"
        "ld4	{v4.d, v5.d, v6.d, v7.d}[0], [%x[state]], #32\n\t"
        "ld4	{v8.d, v9.d, v10.d, v11.d}[0], [%x[state]], #32\n\t"
        "ld4	{v12.d, v13.d, v14.d, v15.d}[0], [%x[state]], #32\n\t"
        "ld4	{v16.d, v17.d, v18.d, v19.d}[0], [%x[state]], #32\n\t"
        "ld4	{v20.d, v21.d, v22.d, v23.d}[0], [%x[state]], #32\n\t"
        "ld1	{v24.d}[0], [%x[state]]\n\t"
        "add	%x[state], %x[state], #8\n\t"
        "ld4	{v0.d, v1.d, v2.d, v3.d}[1], [%x[state]], #32\n\t"
        "ld4	{v4.d, v5.d, v6.d, v7.d}[1], [%x[state]], #32\n\t"
        "ld4	{v8.d, v9.d, v10.d, v11.d}[1], [%x[state]], #32\n\t"
        "ld4	{v12.d, v13.d, v14.d, v15.d}[1], [%x[state]], #32\n\t"
        "ld4	{v16.d, v17.d, v18.d, v19.d}[1], [%x[state]], #32\n\t"
        "ld4	{v20.d, v21.d, v22.d, v23.d}[1], [%x[state]], #32\n\t"
        "ld1	{v24.d}[1], [%x[state]]\n\t"
        "add	%x[state], %x[state], #8\n\t"
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
        "mov	x28, #24\n\t"
        /* Start of 24 rounds */
        "\n"
    "L_SHA3_transform_blocksx3_neon_begin_%=: \n\t"
        "stp	x27, x28, [x29, #48]\n\t"
        /* Col Mix */
        "eor3	v31.16b, v0.16b, v5.16b, v10.16b\n\t"
        "eor	%x[state], x5, x10\n\t"
        "eor3	v27.16b, v1.16b, v6.16b, v11.16b\n\t"
        "eor	x30, x1, x6\n\t"
        "eor3	v28.16b, v2.16b, v7.16b, v12.16b\n\t"
        "eor	x28, x3, x8\n\t"
        "eor3	v29.16b, v3.16b, v8.16b, v13.16b\n\t"
        "eor	%x[state], %x[state], x15\n\t"
        "eor3	v30.16b, v4.16b, v9.16b, v14.16b\n\t"
        "eor	x30, x30, x11\n\t"
        "eor3	v31.16b, v31.16b, v15.16b, v20.16b\n\t"
        "eor	x28, x28, x13\n\t"
        "eor3	v27.16b, v27.16b, v16.16b, v21.16b\n\t"
        "eor	%x[state], %x[state], x21\n\t"
        "eor3	v28.16b, v28.16b, v17.16b, v22.16b\n\t"
        "eor	x30, x30, x16\n\t"
        "eor3	v29.16b, v29.16b, v18.16b, v23.16b\n\t"
        "eor	x28, x28, x19\n\t"
        "eor3	v30.16b, v30.16b, v19.16b, v24.16b\n\t"
        "eor	%x[state], %x[state], x26\n\t"
        "rax1	v25.2d, v30.2d, v27.2d\n\t"
        "eor	x30, x30, x22\n\t"
        "rax1	v26.2d, v31.2d, v28.2d\n\t"
        "eor	x28, x28, x24\n\t"
        "rax1	v27.2d, v27.2d, v29.2d\n\t"
        "str	%x[state], [x29, #32]\n\t"
        "rax1	v28.2d, v28.2d, v30.2d\n\t"
        "str	x28, [x29, #24]\n\t"
        "rax1	v29.2d, v29.2d, v31.2d\n\t"
        "eor	x27, x2, x7\n\t"
        "eor	v0.16b, v0.16b, v25.16b\n\t"
        "xar	v30.2d, v1.2d, v26.2d, #63\n\t"
        "eor	x28, x4, x9\n\t"
        "xar	v1.2d, v6.2d, v26.2d, #20\n\t"
        "eor	x27, x27, x12\n\t"
        "xar	v6.2d, v9.2d, v29.2d, #44\n\t"
        "eor	x28, x28, x14\n\t"
        "xar	v9.2d, v22.2d, v27.2d, #3\n\t"
        "eor	x27, x27, x17\n\t"
        "xar	v22.2d, v14.2d, v29.2d, #25\n\t"
        "eor	x28, x28, x20\n\t"
        "xar	v14.2d, v20.2d, v25.2d, #46\n\t"
        "eor	x27, x27, x23\n\t"
        "xar	v20.2d, v2.2d, v27.2d, #2\n\t"
        "eor	x28, x28, x25\n\t"
        "xar	v2.2d, v12.2d, v27.2d, #21\n\t"
        "eor	%x[state], %x[state], x27, ror 63\n\t"
        "xar	v12.2d, v13.2d, v28.2d, #39\n\t"
        "eor	x27, x27, x28, ror 63\n\t"
        "xar	v13.2d, v19.2d, v29.2d, #56\n\t"
        "eor	x1, x1, %x[state]\n\t"
        "xar	v19.2d, v23.2d, v28.2d, #8\n\t"
        "eor	x6, x6, %x[state]\n\t"
        "xar	v23.2d, v15.2d, v25.2d, #23\n\t"
        "eor	x11, x11, %x[state]\n\t"
        "xar	v15.2d, v4.2d, v29.2d, #37\n\t"
        "eor	x16, x16, %x[state]\n\t"
        "xar	v4.2d, v24.2d, v29.2d, #50\n\t"
        "eor	x22, x22, %x[state]\n\t"
        "xar	v24.2d, v21.2d, v26.2d, #62\n\t"
        "eor	x3, x3, x27\n\t"
        "xar	v21.2d, v8.2d, v28.2d, #9\n\t"
        "eor	x8, x8, x27\n\t"
        "xar	v8.2d, v16.2d, v26.2d, #19\n\t"
        "eor	x13, x13, x27\n\t"
        "xar	v16.2d, v5.2d, v25.2d, #28\n\t"
        "eor	x19, x19, x27\n\t"
        "xar	v5.2d, v3.2d, v28.2d, #36\n\t"
        "eor	x24, x24, x27\n\t"
        "xar	v3.2d, v18.2d, v28.2d, #43\n\t"
        "ldr	%x[state], [x29, #32]\n\t"
        "xar	v18.2d, v17.2d, v27.2d, #49\n\t"
        "ldr	x27, [x29, #24]\n\t"
        "xar	v17.2d, v11.2d, v26.2d, #54\n\t"
        "eor	x28, x28, x30, ror 63\n\t"
        "xar	v11.2d, v7.2d, v27.2d, #58\n\t"
        "eor	x30, x30, x27, ror 63\n\t"
        "xar	v7.2d, v10.2d, v25.2d, #61\n\t"
        "eor	x27, x27, %x[state], ror 63\n\t"
        /* Row Mix */
        "mov	v25.16b, v0.16b\n\t"
        "eor	x5, x5, x28\n\t"
        "mov	v26.16b, v1.16b\n\t"
        "eor	x10, x10, x28\n\t"
        "bcax	v0.16b, v25.16b, v2.16b, v26.16b\n\t"
        "eor	x15, x15, x28\n\t"
        "bcax	v1.16b, v26.16b, v3.16b, v2.16b\n\t"
        "eor	x21, x21, x28\n\t"
        "bcax	v2.16b, v2.16b, v4.16b, v3.16b\n\t"
        "eor	x26, x26, x28\n\t"
        "bcax	v3.16b, v3.16b, v25.16b, v4.16b\n\t"
        "eor	x2, x2, x30\n\t"
        "bcax	v4.16b, v4.16b, v26.16b, v25.16b\n\t"
        "eor	x7, x7, x30\n\t"
        "mov	v25.16b, v5.16b\n\t"
        "eor	x12, x12, x30\n\t"
        "mov	v26.16b, v6.16b\n\t"
        "eor	x17, x17, x30\n\t"
        "bcax	v5.16b, v25.16b, v7.16b, v26.16b\n\t"
        "eor	x23, x23, x30\n\t"
        "bcax	v6.16b, v26.16b, v8.16b, v7.16b\n\t"
        "eor	x4, x4, x27\n\t"
        "bcax	v7.16b, v7.16b, v9.16b, v8.16b\n\t"
        "eor	x9, x9, x27\n\t"
        "bcax	v8.16b, v8.16b, v25.16b, v9.16b\n\t"
        "eor	x14, x14, x27\n\t"
        "bcax	v9.16b, v9.16b, v26.16b, v25.16b\n\t"
        "eor	x20, x20, x27\n\t"
        "mov	v26.16b, v11.16b\n\t"
        "eor	x25, x25, x27\n\t"
        /* Swap Rotate Base */
        "bcax	v10.16b, v30.16b, v12.16b, v26.16b\n\t"
        "ror	%x[state], x2, #63\n\t"
        "bcax	v11.16b, v26.16b, v13.16b, v12.16b\n\t"
        "ror	x2, x7, #20\n\t"
        "bcax	v12.16b, v12.16b, v14.16b, v13.16b\n\t"
        "ror	x7, x10, #44\n\t"
        "bcax	v13.16b, v13.16b, v30.16b, v14.16b\n\t"
        "ror	x10, x24, #3\n\t"
        "bcax	v14.16b, v14.16b, v26.16b, v30.16b\n\t"
        "ror	x24, x15, #25\n\t"
        "mov	v25.16b, v15.16b\n\t"
        "ror	x15, x22, #46\n\t"
        "mov	v26.16b, v16.16b\n\t"
        "ror	x22, x3, #2\n\t"
        "bcax	v15.16b, v25.16b, v17.16b, v26.16b\n\t"
        "ror	x3, x13, #21\n\t"
        "bcax	v16.16b, v26.16b, v18.16b, v17.16b\n\t"
        "ror	x13, x14, #39\n\t"
        "bcax	v17.16b, v17.16b, v19.16b, v18.16b\n\t"
        "ror	x14, x21, #56\n\t"
        "bcax	v18.16b, v18.16b, v25.16b, v19.16b\n\t"
        "ror	x21, x25, #8\n\t"
        "bcax	v19.16b, v19.16b, v26.16b, v25.16b\n\t"
        "ror	x25, x16, #23\n\t"
        "mov	v25.16b, v20.16b\n\t"
        "ror	x16, x5, #37\n\t"
        "mov	v26.16b, v21.16b\n\t"
        "ror	x5, x26, #50\n\t"
        "bcax	v20.16b, v25.16b, v22.16b, v26.16b\n\t"
        "ror	x26, x23, #62\n\t"
        "bcax	v21.16b, v26.16b, v23.16b, v22.16b\n\t"
        "ror	x23, x9, #9\n\t"
        "bcax	v22.16b, v22.16b, v24.16b, v23.16b\n\t"
        "ror	x9, x17, #19\n\t"
        "bcax	v23.16b, v23.16b, v25.16b, v24.16b\n\t"
        "ror	x17, x6, #28\n\t"
        "bcax	v24.16b, v24.16b, v26.16b, v25.16b\n\t"
        "ror	x6, x4, #36\n\t"
        "ror	x4, x20, #43\n\t"
        "ror	x20, x19, #49\n\t"
        "ror	x19, x12, #54\n\t"
        "ror	x12, x8, #58\n\t"
        "ror	x8, x11, #61\n\t"
        /* Row Mix Base */
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
        "mov	v30.d[0], %x[state]\n\t"
        "mov	v30.d[1], %x[state]\n\t"
        "eor	x1, x1, %x[state]\n\t"
        "eor	v0.16b, v0.16b, v30.16b\n\t"
        "bne	L_SHA3_transform_blocksx3_neon_begin_%=\n\t"
        "ldr	%x[state], [x29, #40]\n\t"
        "st4	{v0.d, v1.d, v2.d, v3.d}[0], [%x[state]], #32\n\t"
        "st4	{v4.d, v5.d, v6.d, v7.d}[0], [%x[state]], #32\n\t"
        "st4	{v8.d, v9.d, v10.d, v11.d}[0], [%x[state]], #32\n\t"
        "st4	{v12.d, v13.d, v14.d, v15.d}[0], [%x[state]], #32\n\t"
        "st4	{v16.d, v17.d, v18.d, v19.d}[0], [%x[state]], #32\n\t"
        "st4	{v20.d, v21.d, v22.d, v23.d}[0], [%x[state]], #32\n\t"
        "st1	{v24.d}[0], [%x[state]]\n\t"
        "add	%x[state], %x[state], #8\n\t"
        "st4	{v0.d, v1.d, v2.d, v3.d}[1], [%x[state]], #32\n\t"
        "st4	{v4.d, v5.d, v6.d, v7.d}[1], [%x[state]], #32\n\t"
        "st4	{v8.d, v9.d, v10.d, v11.d}[1], [%x[state]], #32\n\t"
        "st4	{v12.d, v13.d, v14.d, v15.d}[1], [%x[state]], #32\n\t"
        "st4	{v16.d, v17.d, v18.d, v19.d}[1], [%x[state]], #32\n\t"
        "st4	{v20.d, v21.d, v22.d, v23.d}[1], [%x[state]], #32\n\t"
        "st1	{v24.d}[1], [%x[state]]\n\t"
        "add	%x[state], %x[state], #8\n\t"
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
        : [L_kyber_aarch64_q] "S" (L_kyber_aarch64_q), [L_kyber_aarch64_consts] "S" (L_kyber_aarch64_consts), [L_sha3_aarch64_r] "S" (L_sha3_aarch64_r), [L_kyber_aarch64_zetas] "S" (L_kyber_aarch64_zetas), [L_kyber_aarch64_zetas_qinv] "S" (L_kyber_aarch64_zetas_qinv), [L_kyber_aarch64_zetas_inv] "S" (L_kyber_aarch64_zetas_inv), [L_kyber_aarch64_zetas_inv_qinv] "S" (L_kyber_aarch64_zetas_inv_qinv), [L_kyber_aarch64_zetas_mul] "S" (L_kyber_aarch64_zetas_mul), [L_kyber_aarch64_to_msg_neon_low] "S" (L_kyber_aarch64_to_msg_neon_low), [L_kyber_aarch64_to_msg_neon_high] "S" (L_kyber_aarch64_to_msg_neon_high), [L_kyber_aarch64_to_msg_neon_bits] "S" (L_kyber_aarch64_to_msg_neon_bits), [L_kyber_aarch64_from_msg_neon_q1half] "S" (L_kyber_aarch64_from_msg_neon_q1half), [L_kyber_aarch64_from_msg_neon_bits] "S" (L_kyber_aarch64_from_msg_neon_bits), [L_kyber_aarch64_rej_uniform_neon_mask] "S" (L_kyber_aarch64_rej_uniform_neon_mask), [L_kyber_aarch64_rej_uniform_neon_bits] "S" (L_kyber_aarch64_rej_uniform_neon_bits), [L_kyber_aarch64_rej_uniform_neon_indices] "S" (L_kyber_aarch64_rej_uniform_neon_indices)
        : "memory", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15", "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31", "cc"
    );
}

void kyber_shake128_blocksx3_seed_neon(word64* state, byte* seed)
{
    __asm__ __volatile__ (
        "stp	x29, x30, [sp, #-64]!\n\t"
        "add	x29, sp, #0\n\t"
#ifndef __APPLE__
        "adrp x28, %[L_sha3_aarch64_r]\n\t"
        "add  x28, x28, :lo12:%[L_sha3_aarch64_r]\n\t"
#else
        "adrp x28, %[L_sha3_aarch64_r]@PAGE\n\t"
        "add  x28, x28, %[L_sha3_aarch64_r]@PAGEOFF\n\t"
#endif /* __APPLE__ */
        "str	%x[state], [x29, #40]\n\t"
        "add	%x[state], %x[state], #32\n\t"
        "ld1	{v4.d}[0], [%x[state]]\n\t"
        "ldp	x2, x3, [%x[seed]], #16\n\t"
        "add	%x[state], %x[state], #0xc8\n\t"
        "ld1	{v4.d}[1], [%x[state]]\n\t"
        "ldp	x4, x5, [%x[seed]], #16\n\t"
        "ldr	x6, [%x[state], #200]\n\t"
        "eor	v5.16b, v5.16b, v5.16b\n\t"
        "eor	x7, x7, x7\n\t"
        "eor	v6.16b, v6.16b, v6.16b\n\t"
        "eor	x8, x8, x8\n\t"
        "eor	v7.16b, v7.16b, v7.16b\n\t"
        "eor	x9, x9, x9\n\t"
        "eor	v8.16b, v8.16b, v8.16b\n\t"
        "eor	x10, x10, x10\n\t"
        "eor	v9.16b, v9.16b, v9.16b\n\t"
        "eor	x11, x11, x11\n\t"
        "eor	v10.16b, v10.16b, v10.16b\n\t"
        "eor	x12, x12, x12\n\t"
        "eor	v11.16b, v11.16b, v11.16b\n\t"
        "eor	x13, x13, x13\n\t"
        "eor	v12.16b, v12.16b, v12.16b\n\t"
        "eor	x14, x14, x14\n\t"
        "eor	v13.16b, v13.16b, v13.16b\n\t"
        "eor	x15, x15, x15\n\t"
        "eor	v14.16b, v14.16b, v14.16b\n\t"
        "eor	x16, x16, x16\n\t"
        "eor	v15.16b, v15.16b, v15.16b\n\t"
        "eor	x17, x17, x17\n\t"
        "eor	v16.16b, v16.16b, v16.16b\n\t"
        "eor	x19, x19, x19\n\t"
        "eor	v17.16b, v17.16b, v17.16b\n\t"
        "eor	x20, x20, x20\n\t"
        "eor	v18.16b, v18.16b, v18.16b\n\t"
        "eor	x21, x21, x21\n\t"
        "eor	v19.16b, v19.16b, v19.16b\n\t"
        "eor	x22, x22, x22\n\t"
        "movz	x23, #0x8000, lsl 48\n\t"
        "eor	v21.16b, v21.16b, v21.16b\n\t"
        "eor	x24, x24, x24\n\t"
        "eor	v22.16b, v22.16b, v22.16b\n\t"
        "eor	x25, x25, x25\n\t"
        "eor	v23.16b, v23.16b, v23.16b\n\t"
        "eor	x26, x26, x26\n\t"
        "eor	v24.16b, v24.16b, v24.16b\n\t"
        "eor	x27, x27, x27\n\t"
        "dup	v0.2d, x2\n\t"
        "dup	v1.2d, x3\n\t"
        "dup	v2.2d, x4\n\t"
        "dup	v3.2d, x5\n\t"
        "dup	v20.2d, x23\n\t"
        "mov	%x[seed], #24\n\t"
        /* Start of 24 rounds */
        "\n"
    "L_SHA3_shake128_blocksx3_seed_neon_begin_%=: \n\t"
        "stp	x28, %x[seed], [x29, #48]\n\t"
        /* Col Mix */
        "eor3	v31.16b, v0.16b, v5.16b, v10.16b\n\t"
        "eor	%x[state], x6, x11\n\t"
        "eor3	v27.16b, v1.16b, v6.16b, v11.16b\n\t"
        "eor	x30, x2, x7\n\t"
        "eor3	v28.16b, v2.16b, v7.16b, v12.16b\n\t"
        "eor	x28, x4, x9\n\t"
        "eor3	v29.16b, v3.16b, v8.16b, v13.16b\n\t"
        "eor	%x[state], %x[state], x16\n\t"
        "eor3	v30.16b, v4.16b, v9.16b, v14.16b\n\t"
        "eor	x30, x30, x12\n\t"
        "eor3	v31.16b, v31.16b, v15.16b, v20.16b\n\t"
        "eor	x28, x28, x14\n\t"
        "eor3	v27.16b, v27.16b, v16.16b, v21.16b\n\t"
        "eor	%x[state], %x[state], x22\n\t"
        "eor3	v28.16b, v28.16b, v17.16b, v22.16b\n\t"
        "eor	x30, x30, x17\n\t"
        "eor3	v29.16b, v29.16b, v18.16b, v23.16b\n\t"
        "eor	x28, x28, x20\n\t"
        "eor3	v30.16b, v30.16b, v19.16b, v24.16b\n\t"
        "eor	%x[state], %x[state], x27\n\t"
        "rax1	v25.2d, v30.2d, v27.2d\n\t"
        "eor	x30, x30, x23\n\t"
        "rax1	v26.2d, v31.2d, v28.2d\n\t"
        "eor	x28, x28, x25\n\t"
        "rax1	v27.2d, v27.2d, v29.2d\n\t"
        "str	%x[state], [x29, #32]\n\t"
        "rax1	v28.2d, v28.2d, v30.2d\n\t"
        "str	x28, [x29, #24]\n\t"
        "rax1	v29.2d, v29.2d, v31.2d\n\t"
        "eor	%x[seed], x3, x8\n\t"
        "eor	v0.16b, v0.16b, v25.16b\n\t"
        "xar	v30.2d, v1.2d, v26.2d, #63\n\t"
        "eor	x28, x5, x10\n\t"
        "xar	v1.2d, v6.2d, v26.2d, #20\n\t"
        "eor	%x[seed], %x[seed], x13\n\t"
        "xar	v6.2d, v9.2d, v29.2d, #44\n\t"
        "eor	x28, x28, x15\n\t"
        "xar	v9.2d, v22.2d, v27.2d, #3\n\t"
        "eor	%x[seed], %x[seed], x19\n\t"
        "xar	v22.2d, v14.2d, v29.2d, #25\n\t"
        "eor	x28, x28, x21\n\t"
        "xar	v14.2d, v20.2d, v25.2d, #46\n\t"
        "eor	%x[seed], %x[seed], x24\n\t"
        "xar	v20.2d, v2.2d, v27.2d, #2\n\t"
        "eor	x28, x28, x26\n\t"
        "xar	v2.2d, v12.2d, v27.2d, #21\n\t"
        "eor	%x[state], %x[state], %x[seed], ror 63\n\t"
        "xar	v12.2d, v13.2d, v28.2d, #39\n\t"
        "eor	%x[seed], %x[seed], x28, ror 63\n\t"
        "xar	v13.2d, v19.2d, v29.2d, #56\n\t"
        "eor	x2, x2, %x[state]\n\t"
        "xar	v19.2d, v23.2d, v28.2d, #8\n\t"
        "eor	x7, x7, %x[state]\n\t"
        "xar	v23.2d, v15.2d, v25.2d, #23\n\t"
        "eor	x12, x12, %x[state]\n\t"
        "xar	v15.2d, v4.2d, v29.2d, #37\n\t"
        "eor	x17, x17, %x[state]\n\t"
        "xar	v4.2d, v24.2d, v29.2d, #50\n\t"
        "eor	x23, x23, %x[state]\n\t"
        "xar	v24.2d, v21.2d, v26.2d, #62\n\t"
        "eor	x4, x4, %x[seed]\n\t"
        "xar	v21.2d, v8.2d, v28.2d, #9\n\t"
        "eor	x9, x9, %x[seed]\n\t"
        "xar	v8.2d, v16.2d, v26.2d, #19\n\t"
        "eor	x14, x14, %x[seed]\n\t"
        "xar	v16.2d, v5.2d, v25.2d, #28\n\t"
        "eor	x20, x20, %x[seed]\n\t"
        "xar	v5.2d, v3.2d, v28.2d, #36\n\t"
        "eor	x25, x25, %x[seed]\n\t"
        "xar	v3.2d, v18.2d, v28.2d, #43\n\t"
        "ldr	%x[state], [x29, #32]\n\t"
        "xar	v18.2d, v17.2d, v27.2d, #49\n\t"
        "ldr	%x[seed], [x29, #24]\n\t"
        "xar	v17.2d, v11.2d, v26.2d, #54\n\t"
        "eor	x28, x28, x30, ror 63\n\t"
        "xar	v11.2d, v7.2d, v27.2d, #58\n\t"
        "eor	x30, x30, %x[seed], ror 63\n\t"
        "xar	v7.2d, v10.2d, v25.2d, #61\n\t"
        "eor	%x[seed], %x[seed], %x[state], ror 63\n\t"
        /* Row Mix */
        "mov	v25.16b, v0.16b\n\t"
        "eor	x6, x6, x28\n\t"
        "mov	v26.16b, v1.16b\n\t"
        "eor	x11, x11, x28\n\t"
        "bcax	v0.16b, v25.16b, v2.16b, v26.16b\n\t"
        "eor	x16, x16, x28\n\t"
        "bcax	v1.16b, v26.16b, v3.16b, v2.16b\n\t"
        "eor	x22, x22, x28\n\t"
        "bcax	v2.16b, v2.16b, v4.16b, v3.16b\n\t"
        "eor	x27, x27, x28\n\t"
        "bcax	v3.16b, v3.16b, v25.16b, v4.16b\n\t"
        "eor	x3, x3, x30\n\t"
        "bcax	v4.16b, v4.16b, v26.16b, v25.16b\n\t"
        "eor	x8, x8, x30\n\t"
        "mov	v25.16b, v5.16b\n\t"
        "eor	x13, x13, x30\n\t"
        "mov	v26.16b, v6.16b\n\t"
        "eor	x19, x19, x30\n\t"
        "bcax	v5.16b, v25.16b, v7.16b, v26.16b\n\t"
        "eor	x24, x24, x30\n\t"
        "bcax	v6.16b, v26.16b, v8.16b, v7.16b\n\t"
        "eor	x5, x5, %x[seed]\n\t"
        "bcax	v7.16b, v7.16b, v9.16b, v8.16b\n\t"
        "eor	x10, x10, %x[seed]\n\t"
        "bcax	v8.16b, v8.16b, v25.16b, v9.16b\n\t"
        "eor	x15, x15, %x[seed]\n\t"
        "bcax	v9.16b, v9.16b, v26.16b, v25.16b\n\t"
        "eor	x21, x21, %x[seed]\n\t"
        "mov	v26.16b, v11.16b\n\t"
        "eor	x26, x26, %x[seed]\n\t"
        /* Swap Rotate Base */
        "bcax	v10.16b, v30.16b, v12.16b, v26.16b\n\t"
        "ror	%x[state], x3, #63\n\t"
        "bcax	v11.16b, v26.16b, v13.16b, v12.16b\n\t"
        "ror	x3, x8, #20\n\t"
        "bcax	v12.16b, v12.16b, v14.16b, v13.16b\n\t"
        "ror	x8, x11, #44\n\t"
        "bcax	v13.16b, v13.16b, v30.16b, v14.16b\n\t"
        "ror	x11, x25, #3\n\t"
        "bcax	v14.16b, v14.16b, v26.16b, v30.16b\n\t"
        "ror	x25, x16, #25\n\t"
        "mov	v25.16b, v15.16b\n\t"
        "ror	x16, x23, #46\n\t"
        "mov	v26.16b, v16.16b\n\t"
        "ror	x23, x4, #2\n\t"
        "bcax	v15.16b, v25.16b, v17.16b, v26.16b\n\t"
        "ror	x4, x14, #21\n\t"
        "bcax	v16.16b, v26.16b, v18.16b, v17.16b\n\t"
        "ror	x14, x15, #39\n\t"
        "bcax	v17.16b, v17.16b, v19.16b, v18.16b\n\t"
        "ror	x15, x22, #56\n\t"
        "bcax	v18.16b, v18.16b, v25.16b, v19.16b\n\t"
        "ror	x22, x26, #8\n\t"
        "bcax	v19.16b, v19.16b, v26.16b, v25.16b\n\t"
        "ror	x26, x17, #23\n\t"
        "mov	v25.16b, v20.16b\n\t"
        "ror	x17, x6, #37\n\t"
        "mov	v26.16b, v21.16b\n\t"
        "ror	x6, x27, #50\n\t"
        "bcax	v20.16b, v25.16b, v22.16b, v26.16b\n\t"
        "ror	x27, x24, #62\n\t"
        "bcax	v21.16b, v26.16b, v23.16b, v22.16b\n\t"
        "ror	x24, x10, #9\n\t"
        "bcax	v22.16b, v22.16b, v24.16b, v23.16b\n\t"
        "ror	x10, x19, #19\n\t"
        "bcax	v23.16b, v23.16b, v25.16b, v24.16b\n\t"
        "ror	x19, x7, #28\n\t"
        "bcax	v24.16b, v24.16b, v26.16b, v25.16b\n\t"
        "ror	x7, x5, #36\n\t"
        "ror	x5, x21, #43\n\t"
        "ror	x21, x20, #49\n\t"
        "ror	x20, x13, #54\n\t"
        "ror	x13, x9, #58\n\t"
        "ror	x9, x12, #61\n\t"
        /* Row Mix Base */
        "bic	x12, x4, x3\n\t"
        "bic	%x[seed], x5, x4\n\t"
        "bic	x28, x2, x6\n\t"
        "bic	x30, x3, x2\n\t"
        "eor	x2, x2, x12\n\t"
        "eor	x3, x3, %x[seed]\n\t"
        "bic	x12, x6, x5\n\t"
        "eor	x5, x5, x28\n\t"
        "eor	x4, x4, x12\n\t"
        "eor	x6, x6, x30\n\t"
        "bic	x12, x9, x8\n\t"
        "bic	%x[seed], x10, x9\n\t"
        "bic	x28, x7, x11\n\t"
        "bic	x30, x8, x7\n\t"
        "eor	x7, x7, x12\n\t"
        "eor	x8, x8, %x[seed]\n\t"
        "bic	x12, x11, x10\n\t"
        "eor	x10, x10, x28\n\t"
        "eor	x9, x9, x12\n\t"
        "eor	x11, x11, x30\n\t"
        "bic	x12, x14, x13\n\t"
        "bic	%x[seed], x15, x14\n\t"
        "bic	x28, %x[state], x16\n\t"
        "bic	x30, x13, %x[state]\n\t"
        "eor	x12, %x[state], x12\n\t"
        "eor	x13, x13, %x[seed]\n\t"
        "bic	%x[state], x16, x15\n\t"
        "eor	x15, x15, x28\n\t"
        "eor	x14, x14, %x[state]\n\t"
        "eor	x16, x16, x30\n\t"
        "bic	%x[state], x20, x19\n\t"
        "bic	%x[seed], x21, x20\n\t"
        "bic	x28, x17, x22\n\t"
        "bic	x30, x19, x17\n\t"
        "eor	x17, x17, %x[state]\n\t"
        "eor	x19, x19, %x[seed]\n\t"
        "bic	%x[state], x22, x21\n\t"
        "eor	x21, x21, x28\n\t"
        "eor	x20, x20, %x[state]\n\t"
        "eor	x22, x22, x30\n\t"
        "bic	%x[state], x25, x24\n\t"
        "bic	%x[seed], x26, x25\n\t"
        "bic	x28, x23, x27\n\t"
        "bic	x30, x24, x23\n\t"
        "eor	x23, x23, %x[state]\n\t"
        "eor	x24, x24, %x[seed]\n\t"
        "bic	%x[state], x27, x26\n\t"
        "eor	x26, x26, x28\n\t"
        "eor	x25, x25, %x[state]\n\t"
        "eor	x27, x27, x30\n\t"
        /* Done transforming */
        "ldp	x28, %x[seed], [x29, #48]\n\t"
        "ldr	%x[state], [x28], #8\n\t"
        "subs	%x[seed], %x[seed], #1\n\t"
        "mov	v30.d[0], %x[state]\n\t"
        "mov	v30.d[1], %x[state]\n\t"
        "eor	x2, x2, %x[state]\n\t"
        "eor	v0.16b, v0.16b, v30.16b\n\t"
        "bne	L_SHA3_shake128_blocksx3_seed_neon_begin_%=\n\t"
        "ldr	%x[state], [x29, #40]\n\t"
        "st4	{v0.d, v1.d, v2.d, v3.d}[0], [%x[state]], #32\n\t"
        "st4	{v4.d, v5.d, v6.d, v7.d}[0], [%x[state]], #32\n\t"
        "st4	{v8.d, v9.d, v10.d, v11.d}[0], [%x[state]], #32\n\t"
        "st4	{v12.d, v13.d, v14.d, v15.d}[0], [%x[state]], #32\n\t"
        "st4	{v16.d, v17.d, v18.d, v19.d}[0], [%x[state]], #32\n\t"
        "st4	{v20.d, v21.d, v22.d, v23.d}[0], [%x[state]], #32\n\t"
        "st1	{v24.d}[0], [%x[state]]\n\t"
        "add	%x[state], %x[state], #8\n\t"
        "st4	{v0.d, v1.d, v2.d, v3.d}[1], [%x[state]], #32\n\t"
        "st4	{v4.d, v5.d, v6.d, v7.d}[1], [%x[state]], #32\n\t"
        "st4	{v8.d, v9.d, v10.d, v11.d}[1], [%x[state]], #32\n\t"
        "st4	{v12.d, v13.d, v14.d, v15.d}[1], [%x[state]], #32\n\t"
        "st4	{v16.d, v17.d, v18.d, v19.d}[1], [%x[state]], #32\n\t"
        "st4	{v20.d, v21.d, v22.d, v23.d}[1], [%x[state]], #32\n\t"
        "st1	{v24.d}[1], [%x[state]]\n\t"
        "add	%x[state], %x[state], #8\n\t"
        "stp	x2, x3, [%x[state]]\n\t"
        "stp	x4, x5, [%x[state], #16]\n\t"
        "stp	x6, x7, [%x[state], #32]\n\t"
        "stp	x8, x9, [%x[state], #48]\n\t"
        "stp	x10, x11, [%x[state], #64]\n\t"
        "stp	x12, x13, [%x[state], #80]\n\t"
        "stp	x14, x15, [%x[state], #96]\n\t"
        "stp	x16, x17, [%x[state], #112]\n\t"
        "stp	x19, x20, [%x[state], #128]\n\t"
        "stp	x21, x22, [%x[state], #144]\n\t"
        "stp	x23, x24, [%x[state], #160]\n\t"
        "stp	x25, x26, [%x[state], #176]\n\t"
        "str	x27, [%x[state], #192]\n\t"
        "ldp	x29, x30, [sp], #0x40\n\t"
        : [state] "+r" (state), [seed] "+r" (seed)
        : [L_kyber_aarch64_q] "S" (L_kyber_aarch64_q), [L_kyber_aarch64_consts] "S" (L_kyber_aarch64_consts), [L_sha3_aarch64_r] "S" (L_sha3_aarch64_r), [L_kyber_aarch64_zetas] "S" (L_kyber_aarch64_zetas), [L_kyber_aarch64_zetas_qinv] "S" (L_kyber_aarch64_zetas_qinv), [L_kyber_aarch64_zetas_inv] "S" (L_kyber_aarch64_zetas_inv), [L_kyber_aarch64_zetas_inv_qinv] "S" (L_kyber_aarch64_zetas_inv_qinv), [L_kyber_aarch64_zetas_mul] "S" (L_kyber_aarch64_zetas_mul), [L_kyber_aarch64_to_msg_neon_low] "S" (L_kyber_aarch64_to_msg_neon_low), [L_kyber_aarch64_to_msg_neon_high] "S" (L_kyber_aarch64_to_msg_neon_high), [L_kyber_aarch64_to_msg_neon_bits] "S" (L_kyber_aarch64_to_msg_neon_bits), [L_kyber_aarch64_from_msg_neon_q1half] "S" (L_kyber_aarch64_from_msg_neon_q1half), [L_kyber_aarch64_from_msg_neon_bits] "S" (L_kyber_aarch64_from_msg_neon_bits), [L_kyber_aarch64_rej_uniform_neon_mask] "S" (L_kyber_aarch64_rej_uniform_neon_mask), [L_kyber_aarch64_rej_uniform_neon_bits] "S" (L_kyber_aarch64_rej_uniform_neon_bits), [L_kyber_aarch64_rej_uniform_neon_indices] "S" (L_kyber_aarch64_rej_uniform_neon_indices)
        : "memory", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15", "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31", "cc"
    );
}

void kyber_shake256_blocksx3_seed_neon(word64* state, byte* seed)
{
    __asm__ __volatile__ (
        "stp	x29, x30, [sp, #-64]!\n\t"
        "add	x29, sp, #0\n\t"
#ifndef __APPLE__
        "adrp x28, %[L_sha3_aarch64_r]\n\t"
        "add  x28, x28, :lo12:%[L_sha3_aarch64_r]\n\t"
#else
        "adrp x28, %[L_sha3_aarch64_r]@PAGE\n\t"
        "add  x28, x28, %[L_sha3_aarch64_r]@PAGEOFF\n\t"
#endif /* __APPLE__ */
        "str	%x[state], [x29, #40]\n\t"
        "add	%x[state], %x[state], #32\n\t"
        "ld1	{v4.d}[0], [%x[state]]\n\t"
        "ldp	x2, x3, [%x[seed]], #16\n\t"
        "add	%x[state], %x[state], #0xc8\n\t"
        "ld1	{v4.d}[1], [%x[state]]\n\t"
        "ldp	x4, x5, [%x[seed]], #16\n\t"
        "ldr	x6, [%x[state], #200]\n\t"
        "eor	v5.16b, v5.16b, v5.16b\n\t"
        "eor	x7, x7, x7\n\t"
        "eor	v6.16b, v6.16b, v6.16b\n\t"
        "eor	x8, x8, x8\n\t"
        "eor	v7.16b, v7.16b, v7.16b\n\t"
        "eor	x9, x9, x9\n\t"
        "eor	v8.16b, v8.16b, v8.16b\n\t"
        "eor	x10, x10, x10\n\t"
        "eor	v9.16b, v9.16b, v9.16b\n\t"
        "eor	x11, x11, x11\n\t"
        "eor	v10.16b, v10.16b, v10.16b\n\t"
        "eor	x12, x12, x12\n\t"
        "eor	v11.16b, v11.16b, v11.16b\n\t"
        "eor	x13, x13, x13\n\t"
        "eor	v12.16b, v12.16b, v12.16b\n\t"
        "eor	x14, x14, x14\n\t"
        "eor	v13.16b, v13.16b, v13.16b\n\t"
        "eor	x15, x15, x15\n\t"
        "eor	v14.16b, v14.16b, v14.16b\n\t"
        "eor	x16, x16, x16\n\t"
        "eor	v15.16b, v15.16b, v15.16b\n\t"
        "eor	x17, x17, x17\n\t"
        "movz	x19, #0x8000, lsl 48\n\t"
        "eor	v17.16b, v17.16b, v17.16b\n\t"
        "eor	x20, x20, x20\n\t"
        "eor	v18.16b, v18.16b, v18.16b\n\t"
        "eor	x21, x21, x21\n\t"
        "eor	v19.16b, v19.16b, v19.16b\n\t"
        "eor	x22, x22, x22\n\t"
        "eor	v20.16b, v20.16b, v20.16b\n\t"
        "eor	x23, x23, x23\n\t"
        "eor	v21.16b, v21.16b, v21.16b\n\t"
        "eor	x24, x24, x24\n\t"
        "eor	v22.16b, v22.16b, v22.16b\n\t"
        "eor	x25, x25, x25\n\t"
        "eor	v23.16b, v23.16b, v23.16b\n\t"
        "eor	x26, x26, x26\n\t"
        "eor	v24.16b, v24.16b, v24.16b\n\t"
        "eor	x27, x27, x27\n\t"
        "dup	v0.2d, x2\n\t"
        "dup	v1.2d, x3\n\t"
        "dup	v2.2d, x4\n\t"
        "dup	v3.2d, x5\n\t"
        "dup	v16.2d, x19\n\t"
        "mov	%x[seed], #24\n\t"
        /* Start of 24 rounds */
        "\n"
    "L_SHA3_shake256_blocksx3_seed_neon_begin_%=: \n\t"
        "stp	x28, %x[seed], [x29, #48]\n\t"
        /* Col Mix */
        "eor3	v31.16b, v0.16b, v5.16b, v10.16b\n\t"
        "eor	%x[state], x6, x11\n\t"
        "eor3	v27.16b, v1.16b, v6.16b, v11.16b\n\t"
        "eor	x30, x2, x7\n\t"
        "eor3	v28.16b, v2.16b, v7.16b, v12.16b\n\t"
        "eor	x28, x4, x9\n\t"
        "eor3	v29.16b, v3.16b, v8.16b, v13.16b\n\t"
        "eor	%x[state], %x[state], x16\n\t"
        "eor3	v30.16b, v4.16b, v9.16b, v14.16b\n\t"
        "eor	x30, x30, x12\n\t"
        "eor3	v31.16b, v31.16b, v15.16b, v20.16b\n\t"
        "eor	x28, x28, x14\n\t"
        "eor3	v27.16b, v27.16b, v16.16b, v21.16b\n\t"
        "eor	%x[state], %x[state], x22\n\t"
        "eor3	v28.16b, v28.16b, v17.16b, v22.16b\n\t"
        "eor	x30, x30, x17\n\t"
        "eor3	v29.16b, v29.16b, v18.16b, v23.16b\n\t"
        "eor	x28, x28, x20\n\t"
        "eor3	v30.16b, v30.16b, v19.16b, v24.16b\n\t"
        "eor	%x[state], %x[state], x27\n\t"
        "rax1	v25.2d, v30.2d, v27.2d\n\t"
        "eor	x30, x30, x23\n\t"
        "rax1	v26.2d, v31.2d, v28.2d\n\t"
        "eor	x28, x28, x25\n\t"
        "rax1	v27.2d, v27.2d, v29.2d\n\t"
        "str	%x[state], [x29, #32]\n\t"
        "rax1	v28.2d, v28.2d, v30.2d\n\t"
        "str	x28, [x29, #24]\n\t"
        "rax1	v29.2d, v29.2d, v31.2d\n\t"
        "eor	%x[seed], x3, x8\n\t"
        "eor	v0.16b, v0.16b, v25.16b\n\t"
        "xar	v30.2d, v1.2d, v26.2d, #63\n\t"
        "eor	x28, x5, x10\n\t"
        "xar	v1.2d, v6.2d, v26.2d, #20\n\t"
        "eor	%x[seed], %x[seed], x13\n\t"
        "xar	v6.2d, v9.2d, v29.2d, #44\n\t"
        "eor	x28, x28, x15\n\t"
        "xar	v9.2d, v22.2d, v27.2d, #3\n\t"
        "eor	%x[seed], %x[seed], x19\n\t"
        "xar	v22.2d, v14.2d, v29.2d, #25\n\t"
        "eor	x28, x28, x21\n\t"
        "xar	v14.2d, v20.2d, v25.2d, #46\n\t"
        "eor	%x[seed], %x[seed], x24\n\t"
        "xar	v20.2d, v2.2d, v27.2d, #2\n\t"
        "eor	x28, x28, x26\n\t"
        "xar	v2.2d, v12.2d, v27.2d, #21\n\t"
        "eor	%x[state], %x[state], %x[seed], ror 63\n\t"
        "xar	v12.2d, v13.2d, v28.2d, #39\n\t"
        "eor	%x[seed], %x[seed], x28, ror 63\n\t"
        "xar	v13.2d, v19.2d, v29.2d, #56\n\t"
        "eor	x2, x2, %x[state]\n\t"
        "xar	v19.2d, v23.2d, v28.2d, #8\n\t"
        "eor	x7, x7, %x[state]\n\t"
        "xar	v23.2d, v15.2d, v25.2d, #23\n\t"
        "eor	x12, x12, %x[state]\n\t"
        "xar	v15.2d, v4.2d, v29.2d, #37\n\t"
        "eor	x17, x17, %x[state]\n\t"
        "xar	v4.2d, v24.2d, v29.2d, #50\n\t"
        "eor	x23, x23, %x[state]\n\t"
        "xar	v24.2d, v21.2d, v26.2d, #62\n\t"
        "eor	x4, x4, %x[seed]\n\t"
        "xar	v21.2d, v8.2d, v28.2d, #9\n\t"
        "eor	x9, x9, %x[seed]\n\t"
        "xar	v8.2d, v16.2d, v26.2d, #19\n\t"
        "eor	x14, x14, %x[seed]\n\t"
        "xar	v16.2d, v5.2d, v25.2d, #28\n\t"
        "eor	x20, x20, %x[seed]\n\t"
        "xar	v5.2d, v3.2d, v28.2d, #36\n\t"
        "eor	x25, x25, %x[seed]\n\t"
        "xar	v3.2d, v18.2d, v28.2d, #43\n\t"
        "ldr	%x[state], [x29, #32]\n\t"
        "xar	v18.2d, v17.2d, v27.2d, #49\n\t"
        "ldr	%x[seed], [x29, #24]\n\t"
        "xar	v17.2d, v11.2d, v26.2d, #54\n\t"
        "eor	x28, x28, x30, ror 63\n\t"
        "xar	v11.2d, v7.2d, v27.2d, #58\n\t"
        "eor	x30, x30, %x[seed], ror 63\n\t"
        "xar	v7.2d, v10.2d, v25.2d, #61\n\t"
        "eor	%x[seed], %x[seed], %x[state], ror 63\n\t"
        /* Row Mix */
        "mov	v25.16b, v0.16b\n\t"
        "eor	x6, x6, x28\n\t"
        "mov	v26.16b, v1.16b\n\t"
        "eor	x11, x11, x28\n\t"
        "bcax	v0.16b, v25.16b, v2.16b, v26.16b\n\t"
        "eor	x16, x16, x28\n\t"
        "bcax	v1.16b, v26.16b, v3.16b, v2.16b\n\t"
        "eor	x22, x22, x28\n\t"
        "bcax	v2.16b, v2.16b, v4.16b, v3.16b\n\t"
        "eor	x27, x27, x28\n\t"
        "bcax	v3.16b, v3.16b, v25.16b, v4.16b\n\t"
        "eor	x3, x3, x30\n\t"
        "bcax	v4.16b, v4.16b, v26.16b, v25.16b\n\t"
        "eor	x8, x8, x30\n\t"
        "mov	v25.16b, v5.16b\n\t"
        "eor	x13, x13, x30\n\t"
        "mov	v26.16b, v6.16b\n\t"
        "eor	x19, x19, x30\n\t"
        "bcax	v5.16b, v25.16b, v7.16b, v26.16b\n\t"
        "eor	x24, x24, x30\n\t"
        "bcax	v6.16b, v26.16b, v8.16b, v7.16b\n\t"
        "eor	x5, x5, %x[seed]\n\t"
        "bcax	v7.16b, v7.16b, v9.16b, v8.16b\n\t"
        "eor	x10, x10, %x[seed]\n\t"
        "bcax	v8.16b, v8.16b, v25.16b, v9.16b\n\t"
        "eor	x15, x15, %x[seed]\n\t"
        "bcax	v9.16b, v9.16b, v26.16b, v25.16b\n\t"
        "eor	x21, x21, %x[seed]\n\t"
        "mov	v26.16b, v11.16b\n\t"
        "eor	x26, x26, %x[seed]\n\t"
        /* Swap Rotate Base */
        "bcax	v10.16b, v30.16b, v12.16b, v26.16b\n\t"
        "ror	%x[state], x3, #63\n\t"
        "bcax	v11.16b, v26.16b, v13.16b, v12.16b\n\t"
        "ror	x3, x8, #20\n\t"
        "bcax	v12.16b, v12.16b, v14.16b, v13.16b\n\t"
        "ror	x8, x11, #44\n\t"
        "bcax	v13.16b, v13.16b, v30.16b, v14.16b\n\t"
        "ror	x11, x25, #3\n\t"
        "bcax	v14.16b, v14.16b, v26.16b, v30.16b\n\t"
        "ror	x25, x16, #25\n\t"
        "mov	v25.16b, v15.16b\n\t"
        "ror	x16, x23, #46\n\t"
        "mov	v26.16b, v16.16b\n\t"
        "ror	x23, x4, #2\n\t"
        "bcax	v15.16b, v25.16b, v17.16b, v26.16b\n\t"
        "ror	x4, x14, #21\n\t"
        "bcax	v16.16b, v26.16b, v18.16b, v17.16b\n\t"
        "ror	x14, x15, #39\n\t"
        "bcax	v17.16b, v17.16b, v19.16b, v18.16b\n\t"
        "ror	x15, x22, #56\n\t"
        "bcax	v18.16b, v18.16b, v25.16b, v19.16b\n\t"
        "ror	x22, x26, #8\n\t"
        "bcax	v19.16b, v19.16b, v26.16b, v25.16b\n\t"
        "ror	x26, x17, #23\n\t"
        "mov	v25.16b, v20.16b\n\t"
        "ror	x17, x6, #37\n\t"
        "mov	v26.16b, v21.16b\n\t"
        "ror	x6, x27, #50\n\t"
        "bcax	v20.16b, v25.16b, v22.16b, v26.16b\n\t"
        "ror	x27, x24, #62\n\t"
        "bcax	v21.16b, v26.16b, v23.16b, v22.16b\n\t"
        "ror	x24, x10, #9\n\t"
        "bcax	v22.16b, v22.16b, v24.16b, v23.16b\n\t"
        "ror	x10, x19, #19\n\t"
        "bcax	v23.16b, v23.16b, v25.16b, v24.16b\n\t"
        "ror	x19, x7, #28\n\t"
        "bcax	v24.16b, v24.16b, v26.16b, v25.16b\n\t"
        "ror	x7, x5, #36\n\t"
        "ror	x5, x21, #43\n\t"
        "ror	x21, x20, #49\n\t"
        "ror	x20, x13, #54\n\t"
        "ror	x13, x9, #58\n\t"
        "ror	x9, x12, #61\n\t"
        /* Row Mix Base */
        "bic	x12, x4, x3\n\t"
        "bic	%x[seed], x5, x4\n\t"
        "bic	x28, x2, x6\n\t"
        "bic	x30, x3, x2\n\t"
        "eor	x2, x2, x12\n\t"
        "eor	x3, x3, %x[seed]\n\t"
        "bic	x12, x6, x5\n\t"
        "eor	x5, x5, x28\n\t"
        "eor	x4, x4, x12\n\t"
        "eor	x6, x6, x30\n\t"
        "bic	x12, x9, x8\n\t"
        "bic	%x[seed], x10, x9\n\t"
        "bic	x28, x7, x11\n\t"
        "bic	x30, x8, x7\n\t"
        "eor	x7, x7, x12\n\t"
        "eor	x8, x8, %x[seed]\n\t"
        "bic	x12, x11, x10\n\t"
        "eor	x10, x10, x28\n\t"
        "eor	x9, x9, x12\n\t"
        "eor	x11, x11, x30\n\t"
        "bic	x12, x14, x13\n\t"
        "bic	%x[seed], x15, x14\n\t"
        "bic	x28, %x[state], x16\n\t"
        "bic	x30, x13, %x[state]\n\t"
        "eor	x12, %x[state], x12\n\t"
        "eor	x13, x13, %x[seed]\n\t"
        "bic	%x[state], x16, x15\n\t"
        "eor	x15, x15, x28\n\t"
        "eor	x14, x14, %x[state]\n\t"
        "eor	x16, x16, x30\n\t"
        "bic	%x[state], x20, x19\n\t"
        "bic	%x[seed], x21, x20\n\t"
        "bic	x28, x17, x22\n\t"
        "bic	x30, x19, x17\n\t"
        "eor	x17, x17, %x[state]\n\t"
        "eor	x19, x19, %x[seed]\n\t"
        "bic	%x[state], x22, x21\n\t"
        "eor	x21, x21, x28\n\t"
        "eor	x20, x20, %x[state]\n\t"
        "eor	x22, x22, x30\n\t"
        "bic	%x[state], x25, x24\n\t"
        "bic	%x[seed], x26, x25\n\t"
        "bic	x28, x23, x27\n\t"
        "bic	x30, x24, x23\n\t"
        "eor	x23, x23, %x[state]\n\t"
        "eor	x24, x24, %x[seed]\n\t"
        "bic	%x[state], x27, x26\n\t"
        "eor	x26, x26, x28\n\t"
        "eor	x25, x25, %x[state]\n\t"
        "eor	x27, x27, x30\n\t"
        /* Done transforming */
        "ldp	x28, %x[seed], [x29, #48]\n\t"
        "ldr	%x[state], [x28], #8\n\t"
        "subs	%x[seed], %x[seed], #1\n\t"
        "mov	v30.d[0], %x[state]\n\t"
        "mov	v30.d[1], %x[state]\n\t"
        "eor	x2, x2, %x[state]\n\t"
        "eor	v0.16b, v0.16b, v30.16b\n\t"
        "bne	L_SHA3_shake256_blocksx3_seed_neon_begin_%=\n\t"
        "ldr	%x[state], [x29, #40]\n\t"
        "st4	{v0.d, v1.d, v2.d, v3.d}[0], [%x[state]], #32\n\t"
        "st4	{v4.d, v5.d, v6.d, v7.d}[0], [%x[state]], #32\n\t"
        "st4	{v8.d, v9.d, v10.d, v11.d}[0], [%x[state]], #32\n\t"
        "st4	{v12.d, v13.d, v14.d, v15.d}[0], [%x[state]], #32\n\t"
        "st4	{v16.d, v17.d, v18.d, v19.d}[0], [%x[state]], #32\n\t"
        "st4	{v20.d, v21.d, v22.d, v23.d}[0], [%x[state]], #32\n\t"
        "st1	{v24.d}[0], [%x[state]]\n\t"
        "add	%x[state], %x[state], #8\n\t"
        "st4	{v0.d, v1.d, v2.d, v3.d}[1], [%x[state]], #32\n\t"
        "st4	{v4.d, v5.d, v6.d, v7.d}[1], [%x[state]], #32\n\t"
        "st4	{v8.d, v9.d, v10.d, v11.d}[1], [%x[state]], #32\n\t"
        "st4	{v12.d, v13.d, v14.d, v15.d}[1], [%x[state]], #32\n\t"
        "st4	{v16.d, v17.d, v18.d, v19.d}[1], [%x[state]], #32\n\t"
        "st4	{v20.d, v21.d, v22.d, v23.d}[1], [%x[state]], #32\n\t"
        "st1	{v24.d}[1], [%x[state]]\n\t"
        "add	%x[state], %x[state], #8\n\t"
        "stp	x2, x3, [%x[state]]\n\t"
        "stp	x4, x5, [%x[state], #16]\n\t"
        "stp	x6, x7, [%x[state], #32]\n\t"
        "stp	x8, x9, [%x[state], #48]\n\t"
        "stp	x10, x11, [%x[state], #64]\n\t"
        "stp	x12, x13, [%x[state], #80]\n\t"
        "stp	x14, x15, [%x[state], #96]\n\t"
        "stp	x16, x17, [%x[state], #112]\n\t"
        "stp	x19, x20, [%x[state], #128]\n\t"
        "stp	x21, x22, [%x[state], #144]\n\t"
        "stp	x23, x24, [%x[state], #160]\n\t"
        "stp	x25, x26, [%x[state], #176]\n\t"
        "str	x27, [%x[state], #192]\n\t"
        "ldp	x29, x30, [sp], #0x40\n\t"
        : [state] "+r" (state), [seed] "+r" (seed)
        : [L_kyber_aarch64_q] "S" (L_kyber_aarch64_q), [L_kyber_aarch64_consts] "S" (L_kyber_aarch64_consts), [L_sha3_aarch64_r] "S" (L_sha3_aarch64_r), [L_kyber_aarch64_zetas] "S" (L_kyber_aarch64_zetas), [L_kyber_aarch64_zetas_qinv] "S" (L_kyber_aarch64_zetas_qinv), [L_kyber_aarch64_zetas_inv] "S" (L_kyber_aarch64_zetas_inv), [L_kyber_aarch64_zetas_inv_qinv] "S" (L_kyber_aarch64_zetas_inv_qinv), [L_kyber_aarch64_zetas_mul] "S" (L_kyber_aarch64_zetas_mul), [L_kyber_aarch64_to_msg_neon_low] "S" (L_kyber_aarch64_to_msg_neon_low), [L_kyber_aarch64_to_msg_neon_high] "S" (L_kyber_aarch64_to_msg_neon_high), [L_kyber_aarch64_to_msg_neon_bits] "S" (L_kyber_aarch64_to_msg_neon_bits), [L_kyber_aarch64_from_msg_neon_q1half] "S" (L_kyber_aarch64_from_msg_neon_q1half), [L_kyber_aarch64_from_msg_neon_bits] "S" (L_kyber_aarch64_from_msg_neon_bits), [L_kyber_aarch64_rej_uniform_neon_mask] "S" (L_kyber_aarch64_rej_uniform_neon_mask), [L_kyber_aarch64_rej_uniform_neon_bits] "S" (L_kyber_aarch64_rej_uniform_neon_bits), [L_kyber_aarch64_rej_uniform_neon_indices] "S" (L_kyber_aarch64_rej_uniform_neon_indices)
        : "memory", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15", "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31", "cc"
    );
}

#else
void kyber_sha3_blocksx3_neon(word64* state)
{
    __asm__ __volatile__ (
        "stp	x29, x30, [sp, #-64]!\n\t"
        "add	x29, sp, #0\n\t"
#ifndef __APPLE__
        "adrp x27, %[L_sha3_aarch64_r]\n\t"
        "add  x27, x27, :lo12:%[L_sha3_aarch64_r]\n\t"
#else
        "adrp x27, %[L_sha3_aarch64_r]@PAGE\n\t"
        "add  x27, x27, %[L_sha3_aarch64_r]@PAGEOFF\n\t"
#endif /* __APPLE__ */
        "str	%x[state], [x29, #40]\n\t"
        "ld4	{v0.d, v1.d, v2.d, v3.d}[0], [%x[state]], #32\n\t"
        "ld4	{v4.d, v5.d, v6.d, v7.d}[0], [%x[state]], #32\n\t"
        "ld4	{v8.d, v9.d, v10.d, v11.d}[0], [%x[state]], #32\n\t"
        "ld4	{v12.d, v13.d, v14.d, v15.d}[0], [%x[state]], #32\n\t"
        "ld4	{v16.d, v17.d, v18.d, v19.d}[0], [%x[state]], #32\n\t"
        "ld4	{v20.d, v21.d, v22.d, v23.d}[0], [%x[state]], #32\n\t"
        "ld1	{v24.d}[0], [%x[state]]\n\t"
        "add	%x[state], %x[state], #8\n\t"
        "ld4	{v0.d, v1.d, v2.d, v3.d}[1], [%x[state]], #32\n\t"
        "ld4	{v4.d, v5.d, v6.d, v7.d}[1], [%x[state]], #32\n\t"
        "ld4	{v8.d, v9.d, v10.d, v11.d}[1], [%x[state]], #32\n\t"
        "ld4	{v12.d, v13.d, v14.d, v15.d}[1], [%x[state]], #32\n\t"
        "ld4	{v16.d, v17.d, v18.d, v19.d}[1], [%x[state]], #32\n\t"
        "ld4	{v20.d, v21.d, v22.d, v23.d}[1], [%x[state]], #32\n\t"
        "ld1	{v24.d}[1], [%x[state]]\n\t"
        "add	%x[state], %x[state], #8\n\t"
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
        "mov	x28, #24\n\t"
        /* Start of 24 rounds */
        "\n"
    "L_SHA3_transform_blocksx3_neon_begin_%=: \n\t"
        "stp	x27, x28, [x29, #48]\n\t"
        /* Col Mix NEON */
        "eor	v30.16b, v4.16b, v9.16b\n\t"
        "eor	%x[state], x5, x10\n\t"
        "eor	v27.16b, v1.16b, v6.16b\n\t"
        "eor	x30, x1, x6\n\t"
        "eor	v30.16b, v30.16b, v14.16b\n\t"
        "eor	x28, x3, x8\n\t"
        "eor	v27.16b, v27.16b, v11.16b\n\t"
        "eor	%x[state], %x[state], x15\n\t"
        "eor	v30.16b, v30.16b, v19.16b\n\t"
        "eor	x30, x30, x11\n\t"
        "eor	v27.16b, v27.16b, v16.16b\n\t"
        "eor	x28, x28, x13\n\t"
        "eor	v30.16b, v30.16b, v24.16b\n\t"
        "eor	%x[state], %x[state], x21\n\t"
        "eor	v27.16b, v27.16b, v21.16b\n\t"
        "eor	x30, x30, x16\n\t"
        "ushr	v25.2d, v27.2d, #63\n\t"
        "eor	x28, x28, x19\n\t"
        "sli	v25.2d, v27.2d, #1\n\t"
        "eor	%x[state], %x[state], x26\n\t"
        "eor	v25.16b, v25.16b, v30.16b\n\t"
        "eor	x30, x30, x22\n\t"
        "eor	v31.16b, v0.16b, v5.16b\n\t"
        "eor	x28, x28, x24\n\t"
        "eor	v28.16b, v2.16b, v7.16b\n\t"
        "str	%x[state], [x29, #32]\n\t"
        "eor	v31.16b, v31.16b, v10.16b\n\t"
        "str	x28, [x29, #24]\n\t"
        "eor	v28.16b, v28.16b, v12.16b\n\t"
        "eor	x27, x2, x7\n\t"
        "eor	v31.16b, v31.16b, v15.16b\n\t"
        "eor	x28, x4, x9\n\t"
        "eor	v28.16b, v28.16b, v17.16b\n\t"
        "eor	x27, x27, x12\n\t"
        "eor	v31.16b, v31.16b, v20.16b\n\t"
        "eor	x28, x28, x14\n\t"
        "eor	v28.16b, v28.16b, v22.16b\n\t"
        "eor	x27, x27, x17\n\t"
        "ushr	v29.2d, v30.2d, #63\n\t"
        "eor	x28, x28, x20\n\t"
        "ushr	v26.2d, v28.2d, #63\n\t"
        "eor	x27, x27, x23\n\t"
        "sli	v29.2d, v30.2d, #1\n\t"
        "eor	x28, x28, x25\n\t"
        "sli	v26.2d, v28.2d, #1\n\t"
        "eor	%x[state], %x[state], x27, ror 63\n\t"
        "eor	v28.16b, v28.16b, v29.16b\n\t"
        "eor	x27, x27, x28, ror 63\n\t"
        "eor	v29.16b, v3.16b, v8.16b\n\t"
        "eor	x1, x1, %x[state]\n\t"
        "eor	v26.16b, v26.16b, v31.16b\n\t"
        "eor	x6, x6, %x[state]\n\t"
        "eor	v29.16b, v29.16b, v13.16b\n\t"
        "eor	x11, x11, %x[state]\n\t"
        "eor	v29.16b, v29.16b, v18.16b\n\t"
        "eor	x16, x16, %x[state]\n\t"
        "eor	v29.16b, v29.16b, v23.16b\n\t"
        "eor	x22, x22, %x[state]\n\t"
        "ushr	v30.2d, v29.2d, #63\n\t"
        "eor	x3, x3, x27\n\t"
        "sli	v30.2d, v29.2d, #1\n\t"
        "eor	x8, x8, x27\n\t"
        "eor	v27.16b, v27.16b, v30.16b\n\t"
        "eor	x13, x13, x27\n\t"
        "ushr	v30.2d, v31.2d, #63\n\t"
        "eor	x19, x19, x27\n\t"
        "sli	v30.2d, v31.2d, #1\n\t"
        "eor	x24, x24, x27\n\t"
        "eor	v29.16b, v29.16b, v30.16b\n\t"
        "ldr	%x[state], [x29, #32]\n\t"
        /* Swap Rotate NEON */
        "eor	v0.16b, v0.16b, v25.16b\n\t"
        "eor	v31.16b, v1.16b, v26.16b\n\t"
        "ldr	x27, [x29, #24]\n\t"
        "eor	v6.16b, v6.16b, v26.16b\n\t"
        "eor	x28, x28, x30, ror 63\n\t"
        "ushr	v30.2d, v31.2d, #63\n\t"
        "eor	x30, x30, x27, ror 63\n\t"
        "ushr	v1.2d, v6.2d, #20\n\t"
        "eor	x27, x27, %x[state], ror 63\n\t"
        "sli	v30.2d, v31.2d, #1\n\t"
        "eor	x5, x5, x28\n\t"
        "sli	v1.2d, v6.2d, #44\n\t"
        "eor	x10, x10, x28\n\t"
        "eor	v31.16b, v9.16b, v29.16b\n\t"
        "eor	x15, x15, x28\n\t"
        "eor	v22.16b, v22.16b, v27.16b\n\t"
        "eor	x21, x21, x28\n\t"
        "ushr	v6.2d, v31.2d, #44\n\t"
        "eor	x26, x26, x28\n\t"
        "ushr	v9.2d, v22.2d, #3\n\t"
        "eor	x2, x2, x30\n\t"
        "sli	v6.2d, v31.2d, #20\n\t"
        "eor	x7, x7, x30\n\t"
        "sli	v9.2d, v22.2d, #61\n\t"
        "eor	x12, x12, x30\n\t"
        "eor	v31.16b, v14.16b, v29.16b\n\t"
        "eor	x17, x17, x30\n\t"
        "eor	v20.16b, v20.16b, v25.16b\n\t"
        "eor	x23, x23, x30\n\t"
        "ushr	v22.2d, v31.2d, #25\n\t"
        "eor	x4, x4, x27\n\t"
        "ushr	v14.2d, v20.2d, #46\n\t"
        "eor	x9, x9, x27\n\t"
        "sli	v22.2d, v31.2d, #39\n\t"
        "eor	x14, x14, x27\n\t"
        "sli	v14.2d, v20.2d, #18\n\t"
        "eor	x20, x20, x27\n\t"
        "eor	v31.16b, v2.16b, v27.16b\n\t"
        "eor	x25, x25, x27\n\t"
        /* Swap Rotate Base */
        "eor	v12.16b, v12.16b, v27.16b\n\t"
        "ror	%x[state], x2, #63\n\t"
        "ushr	v20.2d, v31.2d, #2\n\t"
        "ror	x2, x7, #20\n\t"
        "ushr	v2.2d, v12.2d, #21\n\t"
        "ror	x7, x10, #44\n\t"
        "sli	v20.2d, v31.2d, #62\n\t"
        "ror	x10, x24, #3\n\t"
        "sli	v2.2d, v12.2d, #43\n\t"
        "ror	x24, x15, #25\n\t"
        "eor	v31.16b, v13.16b, v28.16b\n\t"
        "ror	x15, x22, #46\n\t"
        "eor	v19.16b, v19.16b, v29.16b\n\t"
        "ror	x22, x3, #2\n\t"
        "ushr	v12.2d, v31.2d, #39\n\t"
        "ror	x3, x13, #21\n\t"
        "ushr	v13.2d, v19.2d, #56\n\t"
        "ror	x13, x14, #39\n\t"
        "sli	v12.2d, v31.2d, #25\n\t"
        "ror	x14, x21, #56\n\t"
        "sli	v13.2d, v19.2d, #8\n\t"
        "ror	x21, x25, #8\n\t"
        "eor	v31.16b, v23.16b, v28.16b\n\t"
        "ror	x25, x16, #23\n\t"
        "eor	v15.16b, v15.16b, v25.16b\n\t"
        "ror	x16, x5, #37\n\t"
        "ushr	v19.2d, v31.2d, #8\n\t"
        "ror	x5, x26, #50\n\t"
        "ushr	v23.2d, v15.2d, #23\n\t"
        "ror	x26, x23, #62\n\t"
        "sli	v19.2d, v31.2d, #56\n\t"
        "ror	x23, x9, #9\n\t"
        "sli	v23.2d, v15.2d, #41\n\t"
        "ror	x9, x17, #19\n\t"
        "eor	v31.16b, v4.16b, v29.16b\n\t"
        "ror	x17, x6, #28\n\t"
        "eor	v24.16b, v24.16b, v29.16b\n\t"
        "ror	x6, x4, #36\n\t"
        "ushr	v15.2d, v31.2d, #37\n\t"
        "ror	x4, x20, #43\n\t"
        "ushr	v4.2d, v24.2d, #50\n\t"
        "ror	x20, x19, #49\n\t"
        "sli	v15.2d, v31.2d, #27\n\t"
        "ror	x19, x12, #54\n\t"
        "sli	v4.2d, v24.2d, #14\n\t"
        "ror	x12, x8, #58\n\t"
        "eor	v31.16b, v21.16b, v26.16b\n\t"
        "ror	x8, x11, #61\n\t"
        /* Row Mix Base */
        "eor	v8.16b, v8.16b, v28.16b\n\t"
        "bic	x11, x3, x2\n\t"
        "ushr	v24.2d, v31.2d, #62\n\t"
        "bic	x27, x4, x3\n\t"
        "ushr	v21.2d, v8.2d, #9\n\t"
        "bic	x28, x1, x5\n\t"
        "sli	v24.2d, v31.2d, #2\n\t"
        "bic	x30, x2, x1\n\t"
        "sli	v21.2d, v8.2d, #55\n\t"
        "eor	x1, x1, x11\n\t"
        "eor	v31.16b, v16.16b, v26.16b\n\t"
        "eor	x2, x2, x27\n\t"
        "eor	v5.16b, v5.16b, v25.16b\n\t"
        "bic	x11, x5, x4\n\t"
        "ushr	v8.2d, v31.2d, #19\n\t"
        "eor	x4, x4, x28\n\t"
        "ushr	v16.2d, v5.2d, #28\n\t"
        "eor	x3, x3, x11\n\t"
        "sli	v8.2d, v31.2d, #45\n\t"
        "eor	x5, x5, x30\n\t"
        "sli	v16.2d, v5.2d, #36\n\t"
        "bic	x11, x8, x7\n\t"
        "eor	v31.16b, v3.16b, v28.16b\n\t"
        "bic	x27, x9, x8\n\t"
        "eor	v18.16b, v18.16b, v28.16b\n\t"
        "bic	x28, x6, x10\n\t"
        "ushr	v5.2d, v31.2d, #36\n\t"
        "bic	x30, x7, x6\n\t"
        "ushr	v3.2d, v18.2d, #43\n\t"
        "eor	x6, x6, x11\n\t"
        "sli	v5.2d, v31.2d, #28\n\t"
        "eor	x7, x7, x27\n\t"
        "sli	v3.2d, v18.2d, #21\n\t"
        "bic	x11, x10, x9\n\t"
        "eor	v31.16b, v17.16b, v27.16b\n\t"
        "eor	x9, x9, x28\n\t"
        "eor	v11.16b, v11.16b, v26.16b\n\t"
        "eor	x8, x8, x11\n\t"
        "ushr	v18.2d, v31.2d, #49\n\t"
        "eor	x10, x10, x30\n\t"
        "ushr	v17.2d, v11.2d, #54\n\t"
        "bic	x11, x13, x12\n\t"
        "sli	v18.2d, v31.2d, #15\n\t"
        "bic	x27, x14, x13\n\t"
        "sli	v17.2d, v11.2d, #10\n\t"
        "bic	x28, %x[state], x15\n\t"
        "eor	v31.16b, v7.16b, v27.16b\n\t"
        "bic	x30, x12, %x[state]\n\t"
        "eor	v10.16b, v10.16b, v25.16b\n\t"
        "eor	x11, %x[state], x11\n\t"
        "ushr	v11.2d, v31.2d, #58\n\t"
        "eor	x12, x12, x27\n\t"
        "ushr	v7.2d, v10.2d, #61\n\t"
        "bic	%x[state], x15, x14\n\t"
        "sli	v11.2d, v31.2d, #6\n\t"
        "eor	x14, x14, x28\n\t"
        "sli	v7.2d, v10.2d, #3\n\t"
        "eor	x13, x13, %x[state]\n\t"
        /* Row Mix NEON */
        "bic	v25.16b, v2.16b, v1.16b\n\t"
        "eor	x15, x15, x30\n\t"
        "bic	v26.16b, v3.16b, v2.16b\n\t"
        "bic	%x[state], x19, x17\n\t"
        "bic	v27.16b, v4.16b, v3.16b\n\t"
        "bic	x27, x20, x19\n\t"
        "bic	v28.16b, v0.16b, v4.16b\n\t"
        "bic	x28, x16, x21\n\t"
        "bic	v29.16b, v1.16b, v0.16b\n\t"
        "bic	x30, x17, x16\n\t"
        "eor	v0.16b, v0.16b, v25.16b\n\t"
        "eor	x16, x16, %x[state]\n\t"
        "eor	v1.16b, v1.16b, v26.16b\n\t"
        "eor	x17, x17, x27\n\t"
        "eor	v2.16b, v2.16b, v27.16b\n\t"
        "bic	%x[state], x21, x20\n\t"
        "eor	v3.16b, v3.16b, v28.16b\n\t"
        "eor	x20, x20, x28\n\t"
        "eor	v4.16b, v4.16b, v29.16b\n\t"
        "eor	x19, x19, %x[state]\n\t"
        "bic	v25.16b, v7.16b, v6.16b\n\t"
        "eor	x21, x21, x30\n\t"
        "bic	v26.16b, v8.16b, v7.16b\n\t"
        "bic	%x[state], x24, x23\n\t"
        "bic	v27.16b, v9.16b, v8.16b\n\t"
        "bic	x27, x25, x24\n\t"
        "bic	v28.16b, v5.16b, v9.16b\n\t"
        "bic	x28, x22, x26\n\t"
        "bic	v29.16b, v6.16b, v5.16b\n\t"
        "bic	x30, x23, x22\n\t"
        "eor	v5.16b, v5.16b, v25.16b\n\t"
        "eor	x22, x22, %x[state]\n\t"
        "eor	v6.16b, v6.16b, v26.16b\n\t"
        "eor	x23, x23, x27\n\t"
        "eor	v7.16b, v7.16b, v27.16b\n\t"
        "bic	%x[state], x26, x25\n\t"
        "eor	v8.16b, v8.16b, v28.16b\n\t"
        "eor	x25, x25, x28\n\t"
        "eor	v9.16b, v9.16b, v29.16b\n\t"
        "eor	x24, x24, %x[state]\n\t"
        "bic	v25.16b, v12.16b, v11.16b\n\t"
        "eor	x26, x26, x30\n\t"
        "bic	v26.16b, v13.16b, v12.16b\n\t"
        "bic	v27.16b, v14.16b, v13.16b\n\t"
        "bic	v28.16b, v30.16b, v14.16b\n\t"
        "bic	v29.16b, v11.16b, v30.16b\n\t"
        "eor	v10.16b, v30.16b, v25.16b\n\t"
        "eor	v11.16b, v11.16b, v26.16b\n\t"
        "eor	v12.16b, v12.16b, v27.16b\n\t"
        "eor	v13.16b, v13.16b, v28.16b\n\t"
        "eor	v14.16b, v14.16b, v29.16b\n\t"
        "bic	v25.16b, v17.16b, v16.16b\n\t"
        "bic	v26.16b, v18.16b, v17.16b\n\t"
        "bic	v27.16b, v19.16b, v18.16b\n\t"
        "bic	v28.16b, v15.16b, v19.16b\n\t"
        "bic	v29.16b, v16.16b, v15.16b\n\t"
        "eor	v15.16b, v15.16b, v25.16b\n\t"
        "eor	v16.16b, v16.16b, v26.16b\n\t"
        "eor	v17.16b, v17.16b, v27.16b\n\t"
        "eor	v18.16b, v18.16b, v28.16b\n\t"
        "eor	v19.16b, v19.16b, v29.16b\n\t"
        "bic	v25.16b, v22.16b, v21.16b\n\t"
        "bic	v26.16b, v23.16b, v22.16b\n\t"
        "bic	v27.16b, v24.16b, v23.16b\n\t"
        "bic	v28.16b, v20.16b, v24.16b\n\t"
        "bic	v29.16b, v21.16b, v20.16b\n\t"
        "eor	v20.16b, v20.16b, v25.16b\n\t"
        "eor	v21.16b, v21.16b, v26.16b\n\t"
        "eor	v22.16b, v22.16b, v27.16b\n\t"
        "eor	v23.16b, v23.16b, v28.16b\n\t"
        "eor	v24.16b, v24.16b, v29.16b\n\t"
        /* Done transforming */
        "ldp	x27, x28, [x29, #48]\n\t"
        "ldr	%x[state], [x27], #8\n\t"
        "subs	x28, x28, #1\n\t"
        "mov	v30.d[0], %x[state]\n\t"
        "mov	v30.d[1], %x[state]\n\t"
        "eor	x1, x1, %x[state]\n\t"
        "eor	v0.16b, v0.16b, v30.16b\n\t"
        "bne	L_SHA3_transform_blocksx3_neon_begin_%=\n\t"
        "ldr	%x[state], [x29, #40]\n\t"
        "st4	{v0.d, v1.d, v2.d, v3.d}[0], [%x[state]], #32\n\t"
        "st4	{v4.d, v5.d, v6.d, v7.d}[0], [%x[state]], #32\n\t"
        "st4	{v8.d, v9.d, v10.d, v11.d}[0], [%x[state]], #32\n\t"
        "st4	{v12.d, v13.d, v14.d, v15.d}[0], [%x[state]], #32\n\t"
        "st4	{v16.d, v17.d, v18.d, v19.d}[0], [%x[state]], #32\n\t"
        "st4	{v20.d, v21.d, v22.d, v23.d}[0], [%x[state]], #32\n\t"
        "st1	{v24.d}[0], [%x[state]]\n\t"
        "add	%x[state], %x[state], #8\n\t"
        "st4	{v0.d, v1.d, v2.d, v3.d}[1], [%x[state]], #32\n\t"
        "st4	{v4.d, v5.d, v6.d, v7.d}[1], [%x[state]], #32\n\t"
        "st4	{v8.d, v9.d, v10.d, v11.d}[1], [%x[state]], #32\n\t"
        "st4	{v12.d, v13.d, v14.d, v15.d}[1], [%x[state]], #32\n\t"
        "st4	{v16.d, v17.d, v18.d, v19.d}[1], [%x[state]], #32\n\t"
        "st4	{v20.d, v21.d, v22.d, v23.d}[1], [%x[state]], #32\n\t"
        "st1	{v24.d}[1], [%x[state]]\n\t"
        "add	%x[state], %x[state], #8\n\t"
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
        : [L_kyber_aarch64_q] "S" (L_kyber_aarch64_q), [L_kyber_aarch64_consts] "S" (L_kyber_aarch64_consts), [L_sha3_aarch64_r] "S" (L_sha3_aarch64_r), [L_kyber_aarch64_zetas] "S" (L_kyber_aarch64_zetas), [L_kyber_aarch64_zetas_qinv] "S" (L_kyber_aarch64_zetas_qinv), [L_kyber_aarch64_zetas_inv] "S" (L_kyber_aarch64_zetas_inv), [L_kyber_aarch64_zetas_inv_qinv] "S" (L_kyber_aarch64_zetas_inv_qinv), [L_kyber_aarch64_zetas_mul] "S" (L_kyber_aarch64_zetas_mul), [L_kyber_aarch64_to_msg_neon_low] "S" (L_kyber_aarch64_to_msg_neon_low), [L_kyber_aarch64_to_msg_neon_high] "S" (L_kyber_aarch64_to_msg_neon_high), [L_kyber_aarch64_to_msg_neon_bits] "S" (L_kyber_aarch64_to_msg_neon_bits), [L_kyber_aarch64_from_msg_neon_q1half] "S" (L_kyber_aarch64_from_msg_neon_q1half), [L_kyber_aarch64_from_msg_neon_bits] "S" (L_kyber_aarch64_from_msg_neon_bits), [L_kyber_aarch64_rej_uniform_neon_mask] "S" (L_kyber_aarch64_rej_uniform_neon_mask), [L_kyber_aarch64_rej_uniform_neon_bits] "S" (L_kyber_aarch64_rej_uniform_neon_bits), [L_kyber_aarch64_rej_uniform_neon_indices] "S" (L_kyber_aarch64_rej_uniform_neon_indices)
        : "memory", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15", "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31", "cc"
    );
}

void kyber_shake128_blocksx3_seed_neon(word64* state, byte* seed)
{
    __asm__ __volatile__ (
        "stp	x29, x30, [sp, #-64]!\n\t"
        "add	x29, sp, #0\n\t"
#ifndef __APPLE__
        "adrp x28, %[L_sha3_aarch64_r]\n\t"
        "add  x28, x28, :lo12:%[L_sha3_aarch64_r]\n\t"
#else
        "adrp x28, %[L_sha3_aarch64_r]@PAGE\n\t"
        "add  x28, x28, %[L_sha3_aarch64_r]@PAGEOFF\n\t"
#endif /* __APPLE__ */
        "str	%x[state], [x29, #40]\n\t"
        "add	%x[state], %x[state], #32\n\t"
        "ld1	{v4.d}[0], [%x[state]]\n\t"
        "ldp	x2, x3, [%x[seed]], #16\n\t"
        "add	%x[state], %x[state], #0xc8\n\t"
        "ld1	{v4.d}[1], [%x[state]]\n\t"
        "ldp	x4, x5, [%x[seed]], #16\n\t"
        "ldr	x6, [%x[state], #200]\n\t"
        "eor	v5.16b, v5.16b, v5.16b\n\t"
        "eor	x7, x7, x7\n\t"
        "eor	v6.16b, v6.16b, v6.16b\n\t"
        "eor	x8, x8, x8\n\t"
        "eor	v7.16b, v7.16b, v7.16b\n\t"
        "eor	x9, x9, x9\n\t"
        "eor	v8.16b, v8.16b, v8.16b\n\t"
        "eor	x10, x10, x10\n\t"
        "eor	v9.16b, v9.16b, v9.16b\n\t"
        "eor	x11, x11, x11\n\t"
        "eor	v10.16b, v10.16b, v10.16b\n\t"
        "eor	x12, x12, x12\n\t"
        "eor	v11.16b, v11.16b, v11.16b\n\t"
        "eor	x13, x13, x13\n\t"
        "eor	v12.16b, v12.16b, v12.16b\n\t"
        "eor	x14, x14, x14\n\t"
        "eor	v13.16b, v13.16b, v13.16b\n\t"
        "eor	x15, x15, x15\n\t"
        "eor	v14.16b, v14.16b, v14.16b\n\t"
        "eor	x16, x16, x16\n\t"
        "eor	v15.16b, v15.16b, v15.16b\n\t"
        "eor	x17, x17, x17\n\t"
        "eor	v16.16b, v16.16b, v16.16b\n\t"
        "eor	x19, x19, x19\n\t"
        "eor	v17.16b, v17.16b, v17.16b\n\t"
        "eor	x20, x20, x20\n\t"
        "eor	v18.16b, v18.16b, v18.16b\n\t"
        "eor	x21, x21, x21\n\t"
        "eor	v19.16b, v19.16b, v19.16b\n\t"
        "eor	x22, x22, x22\n\t"
        "movz	x23, #0x8000, lsl 48\n\t"
        "eor	v21.16b, v21.16b, v21.16b\n\t"
        "eor	x24, x24, x24\n\t"
        "eor	v22.16b, v22.16b, v22.16b\n\t"
        "eor	x25, x25, x25\n\t"
        "eor	v23.16b, v23.16b, v23.16b\n\t"
        "eor	x26, x26, x26\n\t"
        "eor	v24.16b, v24.16b, v24.16b\n\t"
        "eor	x27, x27, x27\n\t"
        "dup	v0.2d, x2\n\t"
        "dup	v1.2d, x3\n\t"
        "dup	v2.2d, x4\n\t"
        "dup	v3.2d, x5\n\t"
        "dup	v20.2d, x23\n\t"
        "mov	%x[seed], #24\n\t"
        /* Start of 24 rounds */
        "\n"
    "L_SHA3_shake128_blocksx3_seed_neon_begin_%=: \n\t"
        "stp	x28, %x[seed], [x29, #48]\n\t"
        /* Col Mix NEON */
        "eor	v30.16b, v4.16b, v9.16b\n\t"
        "eor	%x[state], x6, x11\n\t"
        "eor	v27.16b, v1.16b, v6.16b\n\t"
        "eor	x30, x2, x7\n\t"
        "eor	v30.16b, v30.16b, v14.16b\n\t"
        "eor	x28, x4, x9\n\t"
        "eor	v27.16b, v27.16b, v11.16b\n\t"
        "eor	%x[state], %x[state], x16\n\t"
        "eor	v30.16b, v30.16b, v19.16b\n\t"
        "eor	x30, x30, x12\n\t"
        "eor	v27.16b, v27.16b, v16.16b\n\t"
        "eor	x28, x28, x14\n\t"
        "eor	v30.16b, v30.16b, v24.16b\n\t"
        "eor	%x[state], %x[state], x22\n\t"
        "eor	v27.16b, v27.16b, v21.16b\n\t"
        "eor	x30, x30, x17\n\t"
        "ushr	v25.2d, v27.2d, #63\n\t"
        "eor	x28, x28, x20\n\t"
        "sli	v25.2d, v27.2d, #1\n\t"
        "eor	%x[state], %x[state], x27\n\t"
        "eor	v25.16b, v25.16b, v30.16b\n\t"
        "eor	x30, x30, x23\n\t"
        "eor	v31.16b, v0.16b, v5.16b\n\t"
        "eor	x28, x28, x25\n\t"
        "eor	v28.16b, v2.16b, v7.16b\n\t"
        "str	%x[state], [x29, #32]\n\t"
        "eor	v31.16b, v31.16b, v10.16b\n\t"
        "str	x28, [x29, #24]\n\t"
        "eor	v28.16b, v28.16b, v12.16b\n\t"
        "eor	%x[seed], x3, x8\n\t"
        "eor	v31.16b, v31.16b, v15.16b\n\t"
        "eor	x28, x5, x10\n\t"
        "eor	v28.16b, v28.16b, v17.16b\n\t"
        "eor	%x[seed], %x[seed], x13\n\t"
        "eor	v31.16b, v31.16b, v20.16b\n\t"
        "eor	x28, x28, x15\n\t"
        "eor	v28.16b, v28.16b, v22.16b\n\t"
        "eor	%x[seed], %x[seed], x19\n\t"
        "ushr	v29.2d, v30.2d, #63\n\t"
        "eor	x28, x28, x21\n\t"
        "ushr	v26.2d, v28.2d, #63\n\t"
        "eor	%x[seed], %x[seed], x24\n\t"
        "sli	v29.2d, v30.2d, #1\n\t"
        "eor	x28, x28, x26\n\t"
        "sli	v26.2d, v28.2d, #1\n\t"
        "eor	%x[state], %x[state], %x[seed], ror 63\n\t"
        "eor	v28.16b, v28.16b, v29.16b\n\t"
        "eor	%x[seed], %x[seed], x28, ror 63\n\t"
        "eor	v29.16b, v3.16b, v8.16b\n\t"
        "eor	x2, x2, %x[state]\n\t"
        "eor	v26.16b, v26.16b, v31.16b\n\t"
        "eor	x7, x7, %x[state]\n\t"
        "eor	v29.16b, v29.16b, v13.16b\n\t"
        "eor	x12, x12, %x[state]\n\t"
        "eor	v29.16b, v29.16b, v18.16b\n\t"
        "eor	x17, x17, %x[state]\n\t"
        "eor	v29.16b, v29.16b, v23.16b\n\t"
        "eor	x23, x23, %x[state]\n\t"
        "ushr	v30.2d, v29.2d, #63\n\t"
        "eor	x4, x4, %x[seed]\n\t"
        "sli	v30.2d, v29.2d, #1\n\t"
        "eor	x9, x9, %x[seed]\n\t"
        "eor	v27.16b, v27.16b, v30.16b\n\t"
        "eor	x14, x14, %x[seed]\n\t"
        "ushr	v30.2d, v31.2d, #63\n\t"
        "eor	x20, x20, %x[seed]\n\t"
        "sli	v30.2d, v31.2d, #1\n\t"
        "eor	x25, x25, %x[seed]\n\t"
        "eor	v29.16b, v29.16b, v30.16b\n\t"
        "ldr	%x[state], [x29, #32]\n\t"
        /* Swap Rotate NEON */
        "eor	v0.16b, v0.16b, v25.16b\n\t"
        "eor	v31.16b, v1.16b, v26.16b\n\t"
        "ldr	%x[seed], [x29, #24]\n\t"
        "eor	v6.16b, v6.16b, v26.16b\n\t"
        "eor	x28, x28, x30, ror 63\n\t"
        "ushr	v30.2d, v31.2d, #63\n\t"
        "eor	x30, x30, %x[seed], ror 63\n\t"
        "ushr	v1.2d, v6.2d, #20\n\t"
        "eor	%x[seed], %x[seed], %x[state], ror 63\n\t"
        "sli	v30.2d, v31.2d, #1\n\t"
        "eor	x6, x6, x28\n\t"
        "sli	v1.2d, v6.2d, #44\n\t"
        "eor	x11, x11, x28\n\t"
        "eor	v31.16b, v9.16b, v29.16b\n\t"
        "eor	x16, x16, x28\n\t"
        "eor	v22.16b, v22.16b, v27.16b\n\t"
        "eor	x22, x22, x28\n\t"
        "ushr	v6.2d, v31.2d, #44\n\t"
        "eor	x27, x27, x28\n\t"
        "ushr	v9.2d, v22.2d, #3\n\t"
        "eor	x3, x3, x30\n\t"
        "sli	v6.2d, v31.2d, #20\n\t"
        "eor	x8, x8, x30\n\t"
        "sli	v9.2d, v22.2d, #61\n\t"
        "eor	x13, x13, x30\n\t"
        "eor	v31.16b, v14.16b, v29.16b\n\t"
        "eor	x19, x19, x30\n\t"
        "eor	v20.16b, v20.16b, v25.16b\n\t"
        "eor	x24, x24, x30\n\t"
        "ushr	v22.2d, v31.2d, #25\n\t"
        "eor	x5, x5, %x[seed]\n\t"
        "ushr	v14.2d, v20.2d, #46\n\t"
        "eor	x10, x10, %x[seed]\n\t"
        "sli	v22.2d, v31.2d, #39\n\t"
        "eor	x15, x15, %x[seed]\n\t"
        "sli	v14.2d, v20.2d, #18\n\t"
        "eor	x21, x21, %x[seed]\n\t"
        "eor	v31.16b, v2.16b, v27.16b\n\t"
        "eor	x26, x26, %x[seed]\n\t"
        /* Swap Rotate Base */
        "eor	v12.16b, v12.16b, v27.16b\n\t"
        "ror	%x[state], x3, #63\n\t"
        "ushr	v20.2d, v31.2d, #2\n\t"
        "ror	x3, x8, #20\n\t"
        "ushr	v2.2d, v12.2d, #21\n\t"
        "ror	x8, x11, #44\n\t"
        "sli	v20.2d, v31.2d, #62\n\t"
        "ror	x11, x25, #3\n\t"
        "sli	v2.2d, v12.2d, #43\n\t"
        "ror	x25, x16, #25\n\t"
        "eor	v31.16b, v13.16b, v28.16b\n\t"
        "ror	x16, x23, #46\n\t"
        "eor	v19.16b, v19.16b, v29.16b\n\t"
        "ror	x23, x4, #2\n\t"
        "ushr	v12.2d, v31.2d, #39\n\t"
        "ror	x4, x14, #21\n\t"
        "ushr	v13.2d, v19.2d, #56\n\t"
        "ror	x14, x15, #39\n\t"
        "sli	v12.2d, v31.2d, #25\n\t"
        "ror	x15, x22, #56\n\t"
        "sli	v13.2d, v19.2d, #8\n\t"
        "ror	x22, x26, #8\n\t"
        "eor	v31.16b, v23.16b, v28.16b\n\t"
        "ror	x26, x17, #23\n\t"
        "eor	v15.16b, v15.16b, v25.16b\n\t"
        "ror	x17, x6, #37\n\t"
        "ushr	v19.2d, v31.2d, #8\n\t"
        "ror	x6, x27, #50\n\t"
        "ushr	v23.2d, v15.2d, #23\n\t"
        "ror	x27, x24, #62\n\t"
        "sli	v19.2d, v31.2d, #56\n\t"
        "ror	x24, x10, #9\n\t"
        "sli	v23.2d, v15.2d, #41\n\t"
        "ror	x10, x19, #19\n\t"
        "eor	v31.16b, v4.16b, v29.16b\n\t"
        "ror	x19, x7, #28\n\t"
        "eor	v24.16b, v24.16b, v29.16b\n\t"
        "ror	x7, x5, #36\n\t"
        "ushr	v15.2d, v31.2d, #37\n\t"
        "ror	x5, x21, #43\n\t"
        "ushr	v4.2d, v24.2d, #50\n\t"
        "ror	x21, x20, #49\n\t"
        "sli	v15.2d, v31.2d, #27\n\t"
        "ror	x20, x13, #54\n\t"
        "sli	v4.2d, v24.2d, #14\n\t"
        "ror	x13, x9, #58\n\t"
        "eor	v31.16b, v21.16b, v26.16b\n\t"
        "ror	x9, x12, #61\n\t"
        /* Row Mix Base */
        "eor	v8.16b, v8.16b, v28.16b\n\t"
        "bic	x12, x4, x3\n\t"
        "ushr	v24.2d, v31.2d, #62\n\t"
        "bic	%x[seed], x5, x4\n\t"
        "ushr	v21.2d, v8.2d, #9\n\t"
        "bic	x28, x2, x6\n\t"
        "sli	v24.2d, v31.2d, #2\n\t"
        "bic	x30, x3, x2\n\t"
        "sli	v21.2d, v8.2d, #55\n\t"
        "eor	x2, x2, x12\n\t"
        "eor	v31.16b, v16.16b, v26.16b\n\t"
        "eor	x3, x3, %x[seed]\n\t"
        "eor	v5.16b, v5.16b, v25.16b\n\t"
        "bic	x12, x6, x5\n\t"
        "ushr	v8.2d, v31.2d, #19\n\t"
        "eor	x5, x5, x28\n\t"
        "ushr	v16.2d, v5.2d, #28\n\t"
        "eor	x4, x4, x12\n\t"
        "sli	v8.2d, v31.2d, #45\n\t"
        "eor	x6, x6, x30\n\t"
        "sli	v16.2d, v5.2d, #36\n\t"
        "bic	x12, x9, x8\n\t"
        "eor	v31.16b, v3.16b, v28.16b\n\t"
        "bic	%x[seed], x10, x9\n\t"
        "eor	v18.16b, v18.16b, v28.16b\n\t"
        "bic	x28, x7, x11\n\t"
        "ushr	v5.2d, v31.2d, #36\n\t"
        "bic	x30, x8, x7\n\t"
        "ushr	v3.2d, v18.2d, #43\n\t"
        "eor	x7, x7, x12\n\t"
        "sli	v5.2d, v31.2d, #28\n\t"
        "eor	x8, x8, %x[seed]\n\t"
        "sli	v3.2d, v18.2d, #21\n\t"
        "bic	x12, x11, x10\n\t"
        "eor	v31.16b, v17.16b, v27.16b\n\t"
        "eor	x10, x10, x28\n\t"
        "eor	v11.16b, v11.16b, v26.16b\n\t"
        "eor	x9, x9, x12\n\t"
        "ushr	v18.2d, v31.2d, #49\n\t"
        "eor	x11, x11, x30\n\t"
        "ushr	v17.2d, v11.2d, #54\n\t"
        "bic	x12, x14, x13\n\t"
        "sli	v18.2d, v31.2d, #15\n\t"
        "bic	%x[seed], x15, x14\n\t"
        "sli	v17.2d, v11.2d, #10\n\t"
        "bic	x28, %x[state], x16\n\t"
        "eor	v31.16b, v7.16b, v27.16b\n\t"
        "bic	x30, x13, %x[state]\n\t"
        "eor	v10.16b, v10.16b, v25.16b\n\t"
        "eor	x12, %x[state], x12\n\t"
        "ushr	v11.2d, v31.2d, #58\n\t"
        "eor	x13, x13, %x[seed]\n\t"
        "ushr	v7.2d, v10.2d, #61\n\t"
        "bic	%x[state], x16, x15\n\t"
        "sli	v11.2d, v31.2d, #6\n\t"
        "eor	x15, x15, x28\n\t"
        "sli	v7.2d, v10.2d, #3\n\t"
        "eor	x14, x14, %x[state]\n\t"
        /* Row Mix NEON */
        "bic	v25.16b, v2.16b, v1.16b\n\t"
        "eor	x16, x16, x30\n\t"
        "bic	v26.16b, v3.16b, v2.16b\n\t"
        "bic	%x[state], x20, x19\n\t"
        "bic	v27.16b, v4.16b, v3.16b\n\t"
        "bic	%x[seed], x21, x20\n\t"
        "bic	v28.16b, v0.16b, v4.16b\n\t"
        "bic	x28, x17, x22\n\t"
        "bic	v29.16b, v1.16b, v0.16b\n\t"
        "bic	x30, x19, x17\n\t"
        "eor	v0.16b, v0.16b, v25.16b\n\t"
        "eor	x17, x17, %x[state]\n\t"
        "eor	v1.16b, v1.16b, v26.16b\n\t"
        "eor	x19, x19, %x[seed]\n\t"
        "eor	v2.16b, v2.16b, v27.16b\n\t"
        "bic	%x[state], x22, x21\n\t"
        "eor	v3.16b, v3.16b, v28.16b\n\t"
        "eor	x21, x21, x28\n\t"
        "eor	v4.16b, v4.16b, v29.16b\n\t"
        "eor	x20, x20, %x[state]\n\t"
        "bic	v25.16b, v7.16b, v6.16b\n\t"
        "eor	x22, x22, x30\n\t"
        "bic	v26.16b, v8.16b, v7.16b\n\t"
        "bic	%x[state], x25, x24\n\t"
        "bic	v27.16b, v9.16b, v8.16b\n\t"
        "bic	%x[seed], x26, x25\n\t"
        "bic	v28.16b, v5.16b, v9.16b\n\t"
        "bic	x28, x23, x27\n\t"
        "bic	v29.16b, v6.16b, v5.16b\n\t"
        "bic	x30, x24, x23\n\t"
        "eor	v5.16b, v5.16b, v25.16b\n\t"
        "eor	x23, x23, %x[state]\n\t"
        "eor	v6.16b, v6.16b, v26.16b\n\t"
        "eor	x24, x24, %x[seed]\n\t"
        "eor	v7.16b, v7.16b, v27.16b\n\t"
        "bic	%x[state], x27, x26\n\t"
        "eor	v8.16b, v8.16b, v28.16b\n\t"
        "eor	x26, x26, x28\n\t"
        "eor	v9.16b, v9.16b, v29.16b\n\t"
        "eor	x25, x25, %x[state]\n\t"
        "bic	v25.16b, v12.16b, v11.16b\n\t"
        "eor	x27, x27, x30\n\t"
        "bic	v26.16b, v13.16b, v12.16b\n\t"
        "bic	v27.16b, v14.16b, v13.16b\n\t"
        "bic	v28.16b, v30.16b, v14.16b\n\t"
        "bic	v29.16b, v11.16b, v30.16b\n\t"
        "eor	v10.16b, v30.16b, v25.16b\n\t"
        "eor	v11.16b, v11.16b, v26.16b\n\t"
        "eor	v12.16b, v12.16b, v27.16b\n\t"
        "eor	v13.16b, v13.16b, v28.16b\n\t"
        "eor	v14.16b, v14.16b, v29.16b\n\t"
        "bic	v25.16b, v17.16b, v16.16b\n\t"
        "bic	v26.16b, v18.16b, v17.16b\n\t"
        "bic	v27.16b, v19.16b, v18.16b\n\t"
        "bic	v28.16b, v15.16b, v19.16b\n\t"
        "bic	v29.16b, v16.16b, v15.16b\n\t"
        "eor	v15.16b, v15.16b, v25.16b\n\t"
        "eor	v16.16b, v16.16b, v26.16b\n\t"
        "eor	v17.16b, v17.16b, v27.16b\n\t"
        "eor	v18.16b, v18.16b, v28.16b\n\t"
        "eor	v19.16b, v19.16b, v29.16b\n\t"
        "bic	v25.16b, v22.16b, v21.16b\n\t"
        "bic	v26.16b, v23.16b, v22.16b\n\t"
        "bic	v27.16b, v24.16b, v23.16b\n\t"
        "bic	v28.16b, v20.16b, v24.16b\n\t"
        "bic	v29.16b, v21.16b, v20.16b\n\t"
        "eor	v20.16b, v20.16b, v25.16b\n\t"
        "eor	v21.16b, v21.16b, v26.16b\n\t"
        "eor	v22.16b, v22.16b, v27.16b\n\t"
        "eor	v23.16b, v23.16b, v28.16b\n\t"
        "eor	v24.16b, v24.16b, v29.16b\n\t"
        /* Done transforming */
        "ldp	x28, %x[seed], [x29, #48]\n\t"
        "ldr	%x[state], [x28], #8\n\t"
        "subs	%x[seed], %x[seed], #1\n\t"
        "mov	v30.d[0], %x[state]\n\t"
        "mov	v30.d[1], %x[state]\n\t"
        "eor	x2, x2, %x[state]\n\t"
        "eor	v0.16b, v0.16b, v30.16b\n\t"
        "bne	L_SHA3_shake128_blocksx3_seed_neon_begin_%=\n\t"
        "ldr	%x[state], [x29, #40]\n\t"
        "st4	{v0.d, v1.d, v2.d, v3.d}[0], [%x[state]], #32\n\t"
        "st4	{v4.d, v5.d, v6.d, v7.d}[0], [%x[state]], #32\n\t"
        "st4	{v8.d, v9.d, v10.d, v11.d}[0], [%x[state]], #32\n\t"
        "st4	{v12.d, v13.d, v14.d, v15.d}[0], [%x[state]], #32\n\t"
        "st4	{v16.d, v17.d, v18.d, v19.d}[0], [%x[state]], #32\n\t"
        "st4	{v20.d, v21.d, v22.d, v23.d}[0], [%x[state]], #32\n\t"
        "st1	{v24.d}[0], [%x[state]]\n\t"
        "add	%x[state], %x[state], #8\n\t"
        "st4	{v0.d, v1.d, v2.d, v3.d}[1], [%x[state]], #32\n\t"
        "st4	{v4.d, v5.d, v6.d, v7.d}[1], [%x[state]], #32\n\t"
        "st4	{v8.d, v9.d, v10.d, v11.d}[1], [%x[state]], #32\n\t"
        "st4	{v12.d, v13.d, v14.d, v15.d}[1], [%x[state]], #32\n\t"
        "st4	{v16.d, v17.d, v18.d, v19.d}[1], [%x[state]], #32\n\t"
        "st4	{v20.d, v21.d, v22.d, v23.d}[1], [%x[state]], #32\n\t"
        "st1	{v24.d}[1], [%x[state]]\n\t"
        "add	%x[state], %x[state], #8\n\t"
        "stp	x2, x3, [%x[state]]\n\t"
        "stp	x4, x5, [%x[state], #16]\n\t"
        "stp	x6, x7, [%x[state], #32]\n\t"
        "stp	x8, x9, [%x[state], #48]\n\t"
        "stp	x10, x11, [%x[state], #64]\n\t"
        "stp	x12, x13, [%x[state], #80]\n\t"
        "stp	x14, x15, [%x[state], #96]\n\t"
        "stp	x16, x17, [%x[state], #112]\n\t"
        "stp	x19, x20, [%x[state], #128]\n\t"
        "stp	x21, x22, [%x[state], #144]\n\t"
        "stp	x23, x24, [%x[state], #160]\n\t"
        "stp	x25, x26, [%x[state], #176]\n\t"
        "str	x27, [%x[state], #192]\n\t"
        "ldp	x29, x30, [sp], #0x40\n\t"
        : [state] "+r" (state), [seed] "+r" (seed)
        : [L_kyber_aarch64_q] "S" (L_kyber_aarch64_q), [L_kyber_aarch64_consts] "S" (L_kyber_aarch64_consts), [L_sha3_aarch64_r] "S" (L_sha3_aarch64_r), [L_kyber_aarch64_zetas] "S" (L_kyber_aarch64_zetas), [L_kyber_aarch64_zetas_qinv] "S" (L_kyber_aarch64_zetas_qinv), [L_kyber_aarch64_zetas_inv] "S" (L_kyber_aarch64_zetas_inv), [L_kyber_aarch64_zetas_inv_qinv] "S" (L_kyber_aarch64_zetas_inv_qinv), [L_kyber_aarch64_zetas_mul] "S" (L_kyber_aarch64_zetas_mul), [L_kyber_aarch64_to_msg_neon_low] "S" (L_kyber_aarch64_to_msg_neon_low), [L_kyber_aarch64_to_msg_neon_high] "S" (L_kyber_aarch64_to_msg_neon_high), [L_kyber_aarch64_to_msg_neon_bits] "S" (L_kyber_aarch64_to_msg_neon_bits), [L_kyber_aarch64_from_msg_neon_q1half] "S" (L_kyber_aarch64_from_msg_neon_q1half), [L_kyber_aarch64_from_msg_neon_bits] "S" (L_kyber_aarch64_from_msg_neon_bits), [L_kyber_aarch64_rej_uniform_neon_mask] "S" (L_kyber_aarch64_rej_uniform_neon_mask), [L_kyber_aarch64_rej_uniform_neon_bits] "S" (L_kyber_aarch64_rej_uniform_neon_bits), [L_kyber_aarch64_rej_uniform_neon_indices] "S" (L_kyber_aarch64_rej_uniform_neon_indices)
        : "memory", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15", "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31", "cc"
    );
}

void kyber_shake256_blocksx3_seed_neon(word64* state, byte* seed)
{
    __asm__ __volatile__ (
        "stp	x29, x30, [sp, #-64]!\n\t"
        "add	x29, sp, #0\n\t"
#ifndef __APPLE__
        "adrp x28, %[L_sha3_aarch64_r]\n\t"
        "add  x28, x28, :lo12:%[L_sha3_aarch64_r]\n\t"
#else
        "adrp x28, %[L_sha3_aarch64_r]@PAGE\n\t"
        "add  x28, x28, %[L_sha3_aarch64_r]@PAGEOFF\n\t"
#endif /* __APPLE__ */
        "str	%x[state], [x29, #40]\n\t"
        "add	%x[state], %x[state], #32\n\t"
        "ld1	{v4.d}[0], [%x[state]]\n\t"
        "ldp	x2, x3, [%x[seed]], #16\n\t"
        "add	%x[state], %x[state], #0xc8\n\t"
        "ld1	{v4.d}[1], [%x[state]]\n\t"
        "ldp	x4, x5, [%x[seed]], #16\n\t"
        "ldr	x6, [%x[state], #200]\n\t"
        "eor	v5.16b, v5.16b, v5.16b\n\t"
        "eor	x7, x7, x7\n\t"
        "eor	v6.16b, v6.16b, v6.16b\n\t"
        "eor	x8, x8, x8\n\t"
        "eor	v7.16b, v7.16b, v7.16b\n\t"
        "eor	x9, x9, x9\n\t"
        "eor	v8.16b, v8.16b, v8.16b\n\t"
        "eor	x10, x10, x10\n\t"
        "eor	v9.16b, v9.16b, v9.16b\n\t"
        "eor	x11, x11, x11\n\t"
        "eor	v10.16b, v10.16b, v10.16b\n\t"
        "eor	x12, x12, x12\n\t"
        "eor	v11.16b, v11.16b, v11.16b\n\t"
        "eor	x13, x13, x13\n\t"
        "eor	v12.16b, v12.16b, v12.16b\n\t"
        "eor	x14, x14, x14\n\t"
        "eor	v13.16b, v13.16b, v13.16b\n\t"
        "eor	x15, x15, x15\n\t"
        "eor	v14.16b, v14.16b, v14.16b\n\t"
        "eor	x16, x16, x16\n\t"
        "eor	v15.16b, v15.16b, v15.16b\n\t"
        "eor	x17, x17, x17\n\t"
        "movz	x19, #0x8000, lsl 48\n\t"
        "eor	v17.16b, v17.16b, v17.16b\n\t"
        "eor	x20, x20, x20\n\t"
        "eor	v18.16b, v18.16b, v18.16b\n\t"
        "eor	x21, x21, x21\n\t"
        "eor	v19.16b, v19.16b, v19.16b\n\t"
        "eor	x22, x22, x22\n\t"
        "eor	v20.16b, v20.16b, v20.16b\n\t"
        "eor	x23, x23, x23\n\t"
        "eor	v21.16b, v21.16b, v21.16b\n\t"
        "eor	x24, x24, x24\n\t"
        "eor	v22.16b, v22.16b, v22.16b\n\t"
        "eor	x25, x25, x25\n\t"
        "eor	v23.16b, v23.16b, v23.16b\n\t"
        "eor	x26, x26, x26\n\t"
        "eor	v24.16b, v24.16b, v24.16b\n\t"
        "eor	x27, x27, x27\n\t"
        "dup	v0.2d, x2\n\t"
        "dup	v1.2d, x3\n\t"
        "dup	v2.2d, x4\n\t"
        "dup	v3.2d, x5\n\t"
        "dup	v16.2d, x19\n\t"
        "mov	%x[seed], #24\n\t"
        /* Start of 24 rounds */
        "\n"
    "L_SHA3_shake256_blocksx3_seed_neon_begin_%=: \n\t"
        "stp	x28, %x[seed], [x29, #48]\n\t"
        /* Col Mix NEON */
        "eor	v30.16b, v4.16b, v9.16b\n\t"
        "eor	%x[state], x6, x11\n\t"
        "eor	v27.16b, v1.16b, v6.16b\n\t"
        "eor	x30, x2, x7\n\t"
        "eor	v30.16b, v30.16b, v14.16b\n\t"
        "eor	x28, x4, x9\n\t"
        "eor	v27.16b, v27.16b, v11.16b\n\t"
        "eor	%x[state], %x[state], x16\n\t"
        "eor	v30.16b, v30.16b, v19.16b\n\t"
        "eor	x30, x30, x12\n\t"
        "eor	v27.16b, v27.16b, v16.16b\n\t"
        "eor	x28, x28, x14\n\t"
        "eor	v30.16b, v30.16b, v24.16b\n\t"
        "eor	%x[state], %x[state], x22\n\t"
        "eor	v27.16b, v27.16b, v21.16b\n\t"
        "eor	x30, x30, x17\n\t"
        "ushr	v25.2d, v27.2d, #63\n\t"
        "eor	x28, x28, x20\n\t"
        "sli	v25.2d, v27.2d, #1\n\t"
        "eor	%x[state], %x[state], x27\n\t"
        "eor	v25.16b, v25.16b, v30.16b\n\t"
        "eor	x30, x30, x23\n\t"
        "eor	v31.16b, v0.16b, v5.16b\n\t"
        "eor	x28, x28, x25\n\t"
        "eor	v28.16b, v2.16b, v7.16b\n\t"
        "str	%x[state], [x29, #32]\n\t"
        "eor	v31.16b, v31.16b, v10.16b\n\t"
        "str	x28, [x29, #24]\n\t"
        "eor	v28.16b, v28.16b, v12.16b\n\t"
        "eor	%x[seed], x3, x8\n\t"
        "eor	v31.16b, v31.16b, v15.16b\n\t"
        "eor	x28, x5, x10\n\t"
        "eor	v28.16b, v28.16b, v17.16b\n\t"
        "eor	%x[seed], %x[seed], x13\n\t"
        "eor	v31.16b, v31.16b, v20.16b\n\t"
        "eor	x28, x28, x15\n\t"
        "eor	v28.16b, v28.16b, v22.16b\n\t"
        "eor	%x[seed], %x[seed], x19\n\t"
        "ushr	v29.2d, v30.2d, #63\n\t"
        "eor	x28, x28, x21\n\t"
        "ushr	v26.2d, v28.2d, #63\n\t"
        "eor	%x[seed], %x[seed], x24\n\t"
        "sli	v29.2d, v30.2d, #1\n\t"
        "eor	x28, x28, x26\n\t"
        "sli	v26.2d, v28.2d, #1\n\t"
        "eor	%x[state], %x[state], %x[seed], ror 63\n\t"
        "eor	v28.16b, v28.16b, v29.16b\n\t"
        "eor	%x[seed], %x[seed], x28, ror 63\n\t"
        "eor	v29.16b, v3.16b, v8.16b\n\t"
        "eor	x2, x2, %x[state]\n\t"
        "eor	v26.16b, v26.16b, v31.16b\n\t"
        "eor	x7, x7, %x[state]\n\t"
        "eor	v29.16b, v29.16b, v13.16b\n\t"
        "eor	x12, x12, %x[state]\n\t"
        "eor	v29.16b, v29.16b, v18.16b\n\t"
        "eor	x17, x17, %x[state]\n\t"
        "eor	v29.16b, v29.16b, v23.16b\n\t"
        "eor	x23, x23, %x[state]\n\t"
        "ushr	v30.2d, v29.2d, #63\n\t"
        "eor	x4, x4, %x[seed]\n\t"
        "sli	v30.2d, v29.2d, #1\n\t"
        "eor	x9, x9, %x[seed]\n\t"
        "eor	v27.16b, v27.16b, v30.16b\n\t"
        "eor	x14, x14, %x[seed]\n\t"
        "ushr	v30.2d, v31.2d, #63\n\t"
        "eor	x20, x20, %x[seed]\n\t"
        "sli	v30.2d, v31.2d, #1\n\t"
        "eor	x25, x25, %x[seed]\n\t"
        "eor	v29.16b, v29.16b, v30.16b\n\t"
        "ldr	%x[state], [x29, #32]\n\t"
        /* Swap Rotate NEON */
        "eor	v0.16b, v0.16b, v25.16b\n\t"
        "eor	v31.16b, v1.16b, v26.16b\n\t"
        "ldr	%x[seed], [x29, #24]\n\t"
        "eor	v6.16b, v6.16b, v26.16b\n\t"
        "eor	x28, x28, x30, ror 63\n\t"
        "ushr	v30.2d, v31.2d, #63\n\t"
        "eor	x30, x30, %x[seed], ror 63\n\t"
        "ushr	v1.2d, v6.2d, #20\n\t"
        "eor	%x[seed], %x[seed], %x[state], ror 63\n\t"
        "sli	v30.2d, v31.2d, #1\n\t"
        "eor	x6, x6, x28\n\t"
        "sli	v1.2d, v6.2d, #44\n\t"
        "eor	x11, x11, x28\n\t"
        "eor	v31.16b, v9.16b, v29.16b\n\t"
        "eor	x16, x16, x28\n\t"
        "eor	v22.16b, v22.16b, v27.16b\n\t"
        "eor	x22, x22, x28\n\t"
        "ushr	v6.2d, v31.2d, #44\n\t"
        "eor	x27, x27, x28\n\t"
        "ushr	v9.2d, v22.2d, #3\n\t"
        "eor	x3, x3, x30\n\t"
        "sli	v6.2d, v31.2d, #20\n\t"
        "eor	x8, x8, x30\n\t"
        "sli	v9.2d, v22.2d, #61\n\t"
        "eor	x13, x13, x30\n\t"
        "eor	v31.16b, v14.16b, v29.16b\n\t"
        "eor	x19, x19, x30\n\t"
        "eor	v20.16b, v20.16b, v25.16b\n\t"
        "eor	x24, x24, x30\n\t"
        "ushr	v22.2d, v31.2d, #25\n\t"
        "eor	x5, x5, %x[seed]\n\t"
        "ushr	v14.2d, v20.2d, #46\n\t"
        "eor	x10, x10, %x[seed]\n\t"
        "sli	v22.2d, v31.2d, #39\n\t"
        "eor	x15, x15, %x[seed]\n\t"
        "sli	v14.2d, v20.2d, #18\n\t"
        "eor	x21, x21, %x[seed]\n\t"
        "eor	v31.16b, v2.16b, v27.16b\n\t"
        "eor	x26, x26, %x[seed]\n\t"
        /* Swap Rotate Base */
        "eor	v12.16b, v12.16b, v27.16b\n\t"
        "ror	%x[state], x3, #63\n\t"
        "ushr	v20.2d, v31.2d, #2\n\t"
        "ror	x3, x8, #20\n\t"
        "ushr	v2.2d, v12.2d, #21\n\t"
        "ror	x8, x11, #44\n\t"
        "sli	v20.2d, v31.2d, #62\n\t"
        "ror	x11, x25, #3\n\t"
        "sli	v2.2d, v12.2d, #43\n\t"
        "ror	x25, x16, #25\n\t"
        "eor	v31.16b, v13.16b, v28.16b\n\t"
        "ror	x16, x23, #46\n\t"
        "eor	v19.16b, v19.16b, v29.16b\n\t"
        "ror	x23, x4, #2\n\t"
        "ushr	v12.2d, v31.2d, #39\n\t"
        "ror	x4, x14, #21\n\t"
        "ushr	v13.2d, v19.2d, #56\n\t"
        "ror	x14, x15, #39\n\t"
        "sli	v12.2d, v31.2d, #25\n\t"
        "ror	x15, x22, #56\n\t"
        "sli	v13.2d, v19.2d, #8\n\t"
        "ror	x22, x26, #8\n\t"
        "eor	v31.16b, v23.16b, v28.16b\n\t"
        "ror	x26, x17, #23\n\t"
        "eor	v15.16b, v15.16b, v25.16b\n\t"
        "ror	x17, x6, #37\n\t"
        "ushr	v19.2d, v31.2d, #8\n\t"
        "ror	x6, x27, #50\n\t"
        "ushr	v23.2d, v15.2d, #23\n\t"
        "ror	x27, x24, #62\n\t"
        "sli	v19.2d, v31.2d, #56\n\t"
        "ror	x24, x10, #9\n\t"
        "sli	v23.2d, v15.2d, #41\n\t"
        "ror	x10, x19, #19\n\t"
        "eor	v31.16b, v4.16b, v29.16b\n\t"
        "ror	x19, x7, #28\n\t"
        "eor	v24.16b, v24.16b, v29.16b\n\t"
        "ror	x7, x5, #36\n\t"
        "ushr	v15.2d, v31.2d, #37\n\t"
        "ror	x5, x21, #43\n\t"
        "ushr	v4.2d, v24.2d, #50\n\t"
        "ror	x21, x20, #49\n\t"
        "sli	v15.2d, v31.2d, #27\n\t"
        "ror	x20, x13, #54\n\t"
        "sli	v4.2d, v24.2d, #14\n\t"
        "ror	x13, x9, #58\n\t"
        "eor	v31.16b, v21.16b, v26.16b\n\t"
        "ror	x9, x12, #61\n\t"
        /* Row Mix Base */
        "eor	v8.16b, v8.16b, v28.16b\n\t"
        "bic	x12, x4, x3\n\t"
        "ushr	v24.2d, v31.2d, #62\n\t"
        "bic	%x[seed], x5, x4\n\t"
        "ushr	v21.2d, v8.2d, #9\n\t"
        "bic	x28, x2, x6\n\t"
        "sli	v24.2d, v31.2d, #2\n\t"
        "bic	x30, x3, x2\n\t"
        "sli	v21.2d, v8.2d, #55\n\t"
        "eor	x2, x2, x12\n\t"
        "eor	v31.16b, v16.16b, v26.16b\n\t"
        "eor	x3, x3, %x[seed]\n\t"
        "eor	v5.16b, v5.16b, v25.16b\n\t"
        "bic	x12, x6, x5\n\t"
        "ushr	v8.2d, v31.2d, #19\n\t"
        "eor	x5, x5, x28\n\t"
        "ushr	v16.2d, v5.2d, #28\n\t"
        "eor	x4, x4, x12\n\t"
        "sli	v8.2d, v31.2d, #45\n\t"
        "eor	x6, x6, x30\n\t"
        "sli	v16.2d, v5.2d, #36\n\t"
        "bic	x12, x9, x8\n\t"
        "eor	v31.16b, v3.16b, v28.16b\n\t"
        "bic	%x[seed], x10, x9\n\t"
        "eor	v18.16b, v18.16b, v28.16b\n\t"
        "bic	x28, x7, x11\n\t"
        "ushr	v5.2d, v31.2d, #36\n\t"
        "bic	x30, x8, x7\n\t"
        "ushr	v3.2d, v18.2d, #43\n\t"
        "eor	x7, x7, x12\n\t"
        "sli	v5.2d, v31.2d, #28\n\t"
        "eor	x8, x8, %x[seed]\n\t"
        "sli	v3.2d, v18.2d, #21\n\t"
        "bic	x12, x11, x10\n\t"
        "eor	v31.16b, v17.16b, v27.16b\n\t"
        "eor	x10, x10, x28\n\t"
        "eor	v11.16b, v11.16b, v26.16b\n\t"
        "eor	x9, x9, x12\n\t"
        "ushr	v18.2d, v31.2d, #49\n\t"
        "eor	x11, x11, x30\n\t"
        "ushr	v17.2d, v11.2d, #54\n\t"
        "bic	x12, x14, x13\n\t"
        "sli	v18.2d, v31.2d, #15\n\t"
        "bic	%x[seed], x15, x14\n\t"
        "sli	v17.2d, v11.2d, #10\n\t"
        "bic	x28, %x[state], x16\n\t"
        "eor	v31.16b, v7.16b, v27.16b\n\t"
        "bic	x30, x13, %x[state]\n\t"
        "eor	v10.16b, v10.16b, v25.16b\n\t"
        "eor	x12, %x[state], x12\n\t"
        "ushr	v11.2d, v31.2d, #58\n\t"
        "eor	x13, x13, %x[seed]\n\t"
        "ushr	v7.2d, v10.2d, #61\n\t"
        "bic	%x[state], x16, x15\n\t"
        "sli	v11.2d, v31.2d, #6\n\t"
        "eor	x15, x15, x28\n\t"
        "sli	v7.2d, v10.2d, #3\n\t"
        "eor	x14, x14, %x[state]\n\t"
        /* Row Mix NEON */
        "bic	v25.16b, v2.16b, v1.16b\n\t"
        "eor	x16, x16, x30\n\t"
        "bic	v26.16b, v3.16b, v2.16b\n\t"
        "bic	%x[state], x20, x19\n\t"
        "bic	v27.16b, v4.16b, v3.16b\n\t"
        "bic	%x[seed], x21, x20\n\t"
        "bic	v28.16b, v0.16b, v4.16b\n\t"
        "bic	x28, x17, x22\n\t"
        "bic	v29.16b, v1.16b, v0.16b\n\t"
        "bic	x30, x19, x17\n\t"
        "eor	v0.16b, v0.16b, v25.16b\n\t"
        "eor	x17, x17, %x[state]\n\t"
        "eor	v1.16b, v1.16b, v26.16b\n\t"
        "eor	x19, x19, %x[seed]\n\t"
        "eor	v2.16b, v2.16b, v27.16b\n\t"
        "bic	%x[state], x22, x21\n\t"
        "eor	v3.16b, v3.16b, v28.16b\n\t"
        "eor	x21, x21, x28\n\t"
        "eor	v4.16b, v4.16b, v29.16b\n\t"
        "eor	x20, x20, %x[state]\n\t"
        "bic	v25.16b, v7.16b, v6.16b\n\t"
        "eor	x22, x22, x30\n\t"
        "bic	v26.16b, v8.16b, v7.16b\n\t"
        "bic	%x[state], x25, x24\n\t"
        "bic	v27.16b, v9.16b, v8.16b\n\t"
        "bic	%x[seed], x26, x25\n\t"
        "bic	v28.16b, v5.16b, v9.16b\n\t"
        "bic	x28, x23, x27\n\t"
        "bic	v29.16b, v6.16b, v5.16b\n\t"
        "bic	x30, x24, x23\n\t"
        "eor	v5.16b, v5.16b, v25.16b\n\t"
        "eor	x23, x23, %x[state]\n\t"
        "eor	v6.16b, v6.16b, v26.16b\n\t"
        "eor	x24, x24, %x[seed]\n\t"
        "eor	v7.16b, v7.16b, v27.16b\n\t"
        "bic	%x[state], x27, x26\n\t"
        "eor	v8.16b, v8.16b, v28.16b\n\t"
        "eor	x26, x26, x28\n\t"
        "eor	v9.16b, v9.16b, v29.16b\n\t"
        "eor	x25, x25, %x[state]\n\t"
        "bic	v25.16b, v12.16b, v11.16b\n\t"
        "eor	x27, x27, x30\n\t"
        "bic	v26.16b, v13.16b, v12.16b\n\t"
        "bic	v27.16b, v14.16b, v13.16b\n\t"
        "bic	v28.16b, v30.16b, v14.16b\n\t"
        "bic	v29.16b, v11.16b, v30.16b\n\t"
        "eor	v10.16b, v30.16b, v25.16b\n\t"
        "eor	v11.16b, v11.16b, v26.16b\n\t"
        "eor	v12.16b, v12.16b, v27.16b\n\t"
        "eor	v13.16b, v13.16b, v28.16b\n\t"
        "eor	v14.16b, v14.16b, v29.16b\n\t"
        "bic	v25.16b, v17.16b, v16.16b\n\t"
        "bic	v26.16b, v18.16b, v17.16b\n\t"
        "bic	v27.16b, v19.16b, v18.16b\n\t"
        "bic	v28.16b, v15.16b, v19.16b\n\t"
        "bic	v29.16b, v16.16b, v15.16b\n\t"
        "eor	v15.16b, v15.16b, v25.16b\n\t"
        "eor	v16.16b, v16.16b, v26.16b\n\t"
        "eor	v17.16b, v17.16b, v27.16b\n\t"
        "eor	v18.16b, v18.16b, v28.16b\n\t"
        "eor	v19.16b, v19.16b, v29.16b\n\t"
        "bic	v25.16b, v22.16b, v21.16b\n\t"
        "bic	v26.16b, v23.16b, v22.16b\n\t"
        "bic	v27.16b, v24.16b, v23.16b\n\t"
        "bic	v28.16b, v20.16b, v24.16b\n\t"
        "bic	v29.16b, v21.16b, v20.16b\n\t"
        "eor	v20.16b, v20.16b, v25.16b\n\t"
        "eor	v21.16b, v21.16b, v26.16b\n\t"
        "eor	v22.16b, v22.16b, v27.16b\n\t"
        "eor	v23.16b, v23.16b, v28.16b\n\t"
        "eor	v24.16b, v24.16b, v29.16b\n\t"
        /* Done transforming */
        "ldp	x28, %x[seed], [x29, #48]\n\t"
        "ldr	%x[state], [x28], #8\n\t"
        "subs	%x[seed], %x[seed], #1\n\t"
        "mov	v30.d[0], %x[state]\n\t"
        "mov	v30.d[1], %x[state]\n\t"
        "eor	x2, x2, %x[state]\n\t"
        "eor	v0.16b, v0.16b, v30.16b\n\t"
        "bne	L_SHA3_shake256_blocksx3_seed_neon_begin_%=\n\t"
        "ldr	%x[state], [x29, #40]\n\t"
        "st4	{v0.d, v1.d, v2.d, v3.d}[0], [%x[state]], #32\n\t"
        "st4	{v4.d, v5.d, v6.d, v7.d}[0], [%x[state]], #32\n\t"
        "st4	{v8.d, v9.d, v10.d, v11.d}[0], [%x[state]], #32\n\t"
        "st4	{v12.d, v13.d, v14.d, v15.d}[0], [%x[state]], #32\n\t"
        "st4	{v16.d, v17.d, v18.d, v19.d}[0], [%x[state]], #32\n\t"
        "st4	{v20.d, v21.d, v22.d, v23.d}[0], [%x[state]], #32\n\t"
        "st1	{v24.d}[0], [%x[state]]\n\t"
        "add	%x[state], %x[state], #8\n\t"
        "st4	{v0.d, v1.d, v2.d, v3.d}[1], [%x[state]], #32\n\t"
        "st4	{v4.d, v5.d, v6.d, v7.d}[1], [%x[state]], #32\n\t"
        "st4	{v8.d, v9.d, v10.d, v11.d}[1], [%x[state]], #32\n\t"
        "st4	{v12.d, v13.d, v14.d, v15.d}[1], [%x[state]], #32\n\t"
        "st4	{v16.d, v17.d, v18.d, v19.d}[1], [%x[state]], #32\n\t"
        "st4	{v20.d, v21.d, v22.d, v23.d}[1], [%x[state]], #32\n\t"
        "st1	{v24.d}[1], [%x[state]]\n\t"
        "add	%x[state], %x[state], #8\n\t"
        "stp	x2, x3, [%x[state]]\n\t"
        "stp	x4, x5, [%x[state], #16]\n\t"
        "stp	x6, x7, [%x[state], #32]\n\t"
        "stp	x8, x9, [%x[state], #48]\n\t"
        "stp	x10, x11, [%x[state], #64]\n\t"
        "stp	x12, x13, [%x[state], #80]\n\t"
        "stp	x14, x15, [%x[state], #96]\n\t"
        "stp	x16, x17, [%x[state], #112]\n\t"
        "stp	x19, x20, [%x[state], #128]\n\t"
        "stp	x21, x22, [%x[state], #144]\n\t"
        "stp	x23, x24, [%x[state], #160]\n\t"
        "stp	x25, x26, [%x[state], #176]\n\t"
        "str	x27, [%x[state], #192]\n\t"
        "ldp	x29, x30, [sp], #0x40\n\t"
        : [state] "+r" (state), [seed] "+r" (seed)
        : [L_kyber_aarch64_q] "S" (L_kyber_aarch64_q), [L_kyber_aarch64_consts] "S" (L_kyber_aarch64_consts), [L_sha3_aarch64_r] "S" (L_sha3_aarch64_r), [L_kyber_aarch64_zetas] "S" (L_kyber_aarch64_zetas), [L_kyber_aarch64_zetas_qinv] "S" (L_kyber_aarch64_zetas_qinv), [L_kyber_aarch64_zetas_inv] "S" (L_kyber_aarch64_zetas_inv), [L_kyber_aarch64_zetas_inv_qinv] "S" (L_kyber_aarch64_zetas_inv_qinv), [L_kyber_aarch64_zetas_mul] "S" (L_kyber_aarch64_zetas_mul), [L_kyber_aarch64_to_msg_neon_low] "S" (L_kyber_aarch64_to_msg_neon_low), [L_kyber_aarch64_to_msg_neon_high] "S" (L_kyber_aarch64_to_msg_neon_high), [L_kyber_aarch64_to_msg_neon_bits] "S" (L_kyber_aarch64_to_msg_neon_bits), [L_kyber_aarch64_from_msg_neon_q1half] "S" (L_kyber_aarch64_from_msg_neon_q1half), [L_kyber_aarch64_from_msg_neon_bits] "S" (L_kyber_aarch64_from_msg_neon_bits), [L_kyber_aarch64_rej_uniform_neon_mask] "S" (L_kyber_aarch64_rej_uniform_neon_mask), [L_kyber_aarch64_rej_uniform_neon_bits] "S" (L_kyber_aarch64_rej_uniform_neon_bits), [L_kyber_aarch64_rej_uniform_neon_indices] "S" (L_kyber_aarch64_rej_uniform_neon_indices)
        : "memory", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15", "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31", "cc"
    );
}

#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
#endif /* WOLFSSL_WC_KYBER */
#endif /* __aarch64__ */
#endif /* WOLFSSL_ARMASM */
#endif /* WOLFSSL_ARMASM_INLINE */
