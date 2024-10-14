/* riscv-64-chacha.c
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

/* The paper NEON crypto by Daniel J. Bernstein and Peter Schwabe was used to
 * optimize for ARM:
 *   https://cryptojedi.org/papers/veccrypto-20120320.pdf
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/port/riscv/riscv-64-asm.h>

#ifdef WOLFSSL_RISCV_ASM
#ifdef HAVE_CHACHA

#include <wolfssl/wolfcrypt/chacha.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/cpuid.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#ifdef CHACHA_AEAD_TEST
    #include <stdio.h>
#endif

#ifdef CHACHA_TEST
    #include <stdio.h>
#endif

/* Number of rounds */
#define ROUNDS  20

#define U32C(v) (v##U)
#define U32V(v) ((word32)(v) & U32C(0xFFFFFFFF))
#define U8TO32_LITTLE(p) (((word32*)(p))[0])

#define PLUS(v,w)   (U32V((v) + (w)))
#define PLUSONE(v)  (PLUS((v),1))

#define ARM_SIMD_LEN_BYTES 16

/**
 * Set up iv(nonce). Earlier versions used 64 bits instead of 96, this version
 * uses the typical AEAD 96 bit nonce and can do record sizes of 256 GB.
 */
int wc_Chacha_SetIV(ChaCha* ctx, const byte* inIv, word32 counter)
{
    word32 temp[CHACHA_IV_WORDS];/* used for alignment of memory */

    if (ctx == NULL)
        return BAD_FUNC_ARG;

    XMEMCPY(temp, inIv, CHACHA_IV_BYTES);

    ctx->left = 0;
    ctx->X[CHACHA_IV_BYTES+0] = counter;           /* block counter */
    ctx->X[CHACHA_IV_BYTES+1] = temp[0]; /* fixed variable from nonce */
    ctx->X[CHACHA_IV_BYTES+2] = temp[1]; /* counter from nonce */
    ctx->X[CHACHA_IV_BYTES+3] = temp[2]; /* counter from nonce */

    return 0;
}

/* "expand 32-byte k" as unsigned 32 byte */
static const word32 sigma[4] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
/* "expand 16-byte k" as unsigned 16 byte */
static const word32 tau[4] = {0x61707865, 0x3120646e, 0x79622d36, 0x6b206574};

/**
 * Key setup. 8 word iv (nonce)
 */
int wc_Chacha_SetKey(ChaCha* ctx, const byte* key, word32 keySz)
{
    const word32* constants;
    const byte*   k;

#ifdef XSTREAM_ALIGN
    word32 alignKey[8];
#endif

    if (ctx == NULL)
        return BAD_FUNC_ARG;

    if (keySz != (CHACHA_MAX_KEY_SZ/2) && keySz != CHACHA_MAX_KEY_SZ)
        return BAD_FUNC_ARG;

#ifdef XSTREAM_ALIGN
    if ((wc_ptr_t)key % 4) {
        WOLFSSL_MSG("wc_ChachaSetKey unaligned key");
        XMEMCPY(alignKey, key, keySz);
        k = (byte*)alignKey;
    }
    else {
        k = key;
    }
#else
    k = key;
#endif /* XSTREAM_ALIGN */

    ctx->X[4] = U8TO32_LITTLE(k +  0);
    ctx->X[5] = U8TO32_LITTLE(k +  4);
    ctx->X[6] = U8TO32_LITTLE(k +  8);
    ctx->X[7] = U8TO32_LITTLE(k + 12);
    if (keySz == CHACHA_MAX_KEY_SZ) {
        k += 16;
        constants = sigma;
    }
    else {
        constants = tau;
    }
    ctx->X[ 8] = U8TO32_LITTLE(k +  0);
    ctx->X[ 9] = U8TO32_LITTLE(k +  4);
    ctx->X[10] = U8TO32_LITTLE(k +  8);
    ctx->X[11] = U8TO32_LITTLE(k + 12);
    ctx->X[ 0] = constants[0];
    ctx->X[ 1] = constants[1];
    ctx->X[ 2] = constants[2];
    ctx->X[ 3] = constants[3];
    ctx->left = 0;

    return 0;
}


#define CC_A0   "a4"
#define CC_A1   "a5"
#define CC_A2   "a6"
#define CC_A3   "a7"
#define CC_B0   "t3"
#define CC_B1   "t4"
#define CC_B2   "t5"
#define CC_B3   "t6"
#define CC_C0   "s2"
#define CC_C1   "s3"
#define CC_C2   "s4"
#define CC_C3   "s5"
#define CC_D0   "s6"
#define CC_D1   "s7"
#define CC_D2   "s8"
#define CC_D3   "s9"
#define CC_T0   "t0"
#define CC_T1   "t1"
#define CC_T2   "t2"
#define CC_T3   "s1"

#if defined(WOLFSSL_RISCV_VECTOR)

static const word32 L_chacha20_vec_inc_first_word[] = {
    0x1,
    0x0,
    0x0,
    0x0,
};

#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION

#define PART_ROUND_ODD_ABD_5(s, sr)                     \
        VADD_VV(REG_V0, REG_V0, REG_V1)                 \
        "add    " CC_A0 ", " CC_A0 ", " CC_B0 "\n\t"    \
        VADD_VV(REG_V4, REG_V4, REG_V5)                 \
        "add    " CC_A1 ", " CC_A1 ", " CC_B1 "\n\t"    \
        VADD_VV(REG_V8, REG_V8, REG_V9)                 \
        "add    " CC_A2 ", " CC_A2 ", " CC_B2 "\n\t"    \
        VADD_VV(REG_V12, REG_V12, REG_V13)              \
        "add    " CC_A3 ", " CC_A3 ", " CC_B3 "\n\t"    \
        VADD_VV(REG_V16, REG_V16, REG_V17)              \
        VXOR_VV(REG_V3, REG_V3, REG_V0)                 \
        "xor    " CC_D0 ", " CC_D0 ", " CC_A0 "\n\t"    \
        VXOR_VV(REG_V7, REG_V7, REG_V4)                 \
        "xor    " CC_D1 ", " CC_D1 ", " CC_A1 "\n\t"    \
        VXOR_VV(REG_V11, REG_V11, REG_V8)               \
        "xor    " CC_D2 ", " CC_D2 ", " CC_A2 "\n\t"    \
        VXOR_VV(REG_V15, REG_V15, REG_V12)              \
        "xor    " CC_D3 ", " CC_D3 ", " CC_A3 "\n\t"    \
        VXOR_VV(REG_V19, REG_V19, REG_V16)              \
        VSLL_VI(REG_V20, REG_V3, s)                     \
        "slli   " CC_T0 ", " CC_D0 ", " #s "\n\t"       \
        VSLL_VI(REG_V21, REG_V7, s)                     \
        "slli   " CC_T1 ", " CC_D1 ", " #s "\n\t"       \
        VSLL_VI(REG_V22, REG_V11, s)                    \
        "slli   " CC_T2 ", " CC_D2 ", " #s "\n\t"       \
        VSLL_VI(REG_V23, REG_V15, s)                    \
        "slli   " CC_T3 ", " CC_D3 ", " #s "\n\t"       \
        VSLL_VI(REG_V24, REG_V19, s)                    \
        VSRL_VI(REG_V3, REG_V3, sr)                     \
        "srliw  " CC_D0 ", " CC_D0 ", " #sr "\n\t"      \
        VSRL_VI(REG_V7, REG_V7, sr)                     \
        "srliw  " CC_D1 ", " CC_D1 ", " #sr "\n\t"      \
        VSRL_VI(REG_V11, REG_V11, sr)                   \
        "srliw  " CC_D2 ", " CC_D2 ", " #sr "\n\t"      \
        VSRL_VI(REG_V15, REG_V15, sr)                   \
        "srliw  " CC_D3 ", " CC_D3 ", " #sr "\n\t"      \
        VSRL_VI(REG_V19, REG_V19, sr)                   \
        VOR_VV(REG_V3, REG_V3, REG_V20)                 \
        "or     " CC_D0 ", " CC_D0 ", " CC_T0 "\n\t"    \
        VOR_VV(REG_V7, REG_V7, REG_V21)                 \
        "or     " CC_D1 ", " CC_D1 ", " CC_T1 "\n\t"    \
        VOR_VV(REG_V11, REG_V11, REG_V22)               \
        "or     " CC_D2 ", " CC_D2 ", " CC_T2 "\n\t"    \
        VOR_VV(REG_V15, REG_V15, REG_V23)               \
        "or     " CC_D3 ", " CC_D3 ", " CC_T3 "\n\t"    \
        VOR_VV(REG_V19, REG_V19, REG_V24)

#define PART_ROUND_ODD_CDB_5(s, sr)                     \
        VADD_VV(REG_V2, REG_V2, REG_V3)                 \
        "add    " CC_C0 ", " CC_C0 ", " CC_D0 "\n\t"    \
        VADD_VV(REG_V6, REG_V6, REG_V7)                 \
        "add    " CC_C1 ", " CC_C1 ", " CC_D1 "\n\t"    \
        VADD_VV(REG_V10, REG_V10, REG_V11)              \
        "add    " CC_C2 ", " CC_C2 ", " CC_D2 "\n\t"    \
        VADD_VV(REG_V14, REG_V14, REG_V15)              \
        "add    " CC_C3 ", " CC_C3 ", " CC_D3 "\n\t"    \
        VADD_VV(REG_V18, REG_V18, REG_V19)              \
        VXOR_VV(REG_V1, REG_V1, REG_V2)                 \
        "xor    " CC_B0 ", " CC_B0 ", " CC_C0 "\n\t"    \
        VXOR_VV(REG_V5, REG_V5, REG_V6)                 \
        "xor    " CC_B1 ", " CC_B1 ", " CC_C1 "\n\t"    \
        VXOR_VV(REG_V9, REG_V9, REG_V10)                \
        "xor    " CC_B2 ", " CC_B2 ", " CC_C2 "\n\t"    \
        VXOR_VV(REG_V13, REG_V13, REG_V14)              \
        "xor    " CC_B3 ", " CC_B3 ", " CC_C3 "\n\t"    \
        VXOR_VV(REG_V17, REG_V17, REG_V18)              \
        VSLL_VI(REG_V20, REG_V1, s)                     \
        "slli   " CC_T0 ", " CC_B0 ", " #s "\n\t"       \
        VSLL_VI(REG_V21, REG_V5, s)                     \
        "slli   " CC_T1 ", " CC_B1 ", " #s "\n\t"       \
        VSLL_VI(REG_V22, REG_V9, s)                     \
        "slli   " CC_T2 ", " CC_B2 ", " #s "\n\t"       \
        VSLL_VI(REG_V23, REG_V13, s)                    \
        "slli   " CC_T3 ", " CC_B3 ", " #s "\n\t"       \
        VSLL_VI(REG_V24, REG_V17, s)                    \
        VSRL_VI(REG_V1, REG_V1, sr)                     \
        "srliw  " CC_B0 ", " CC_B0 ", " #sr "\n\t"      \
        VSRL_VI(REG_V5, REG_V5, sr)                     \
        "srliw  " CC_B1 ", " CC_B1 ", " #sr "\n\t"      \
        VSRL_VI(REG_V9, REG_V9, sr)                     \
        "srliw  " CC_B2 ", " CC_B2 ", " #sr "\n\t"      \
        VSRL_VI(REG_V13, REG_V13, sr)                   \
        "srliw  " CC_B3 ", " CC_B3 ", " #sr "\n\t"      \
        VSRL_VI(REG_V17, REG_V17, sr)                   \
        VOR_VV(REG_V1, REG_V1, REG_V20)                 \
        "or     " CC_B0 ", " CC_B0 ", " CC_T0 "\n\t"    \
        VOR_VV(REG_V5, REG_V5, REG_V21)                 \
        "or     " CC_B1 ", " CC_B1 ", " CC_T1 "\n\t"    \
        VOR_VV(REG_V9, REG_V9, REG_V22)                 \
        "or     " CC_B2 ", " CC_B2 ", " CC_T2 "\n\t"    \
        VOR_VV(REG_V13, REG_V13, REG_V23)               \
        "or     " CC_B3 ", " CC_B3 ", " CC_T3 "\n\t"    \
        VOR_VV(REG_V17, REG_V17, REG_V24)

#define PART_ROUND_EVEN_ABD_5(s, sr)                    \
        VADD_VV(REG_V0, REG_V0, REG_V1)                 \
        "add    " CC_A0 ", " CC_A0 ", " CC_B1 "\n\t"    \
        VADD_VV(REG_V4, REG_V4, REG_V5)                 \
        "add    " CC_A1 ", " CC_A1 ", " CC_B2 "\n\t"    \
        VADD_VV(REG_V8, REG_V8, REG_V9)                 \
        "add    " CC_A2 ", " CC_A2 ", " CC_B3 "\n\t"    \
        VADD_VV(REG_V12, REG_V12, REG_V13)              \
        "add    " CC_A3 ", " CC_A3 ", " CC_B0 "\n\t"    \
        VADD_VV(REG_V16, REG_V16, REG_V17)              \
        VXOR_VV(REG_V3, REG_V3, REG_V0)                 \
        "xor    " CC_D3 ", " CC_D3 ", " CC_A0 "\n\t"    \
        VXOR_VV(REG_V7, REG_V7, REG_V4)                 \
        "xor    " CC_D0 ", " CC_D0 ", " CC_A1 "\n\t"    \
        VXOR_VV(REG_V11, REG_V11, REG_V8)               \
        "xor    " CC_D1 ", " CC_D1 ", " CC_A2 "\n\t"    \
        VXOR_VV(REG_V15, REG_V15, REG_V12)              \
        "xor    " CC_D2 ", " CC_D2 ", " CC_A3 "\n\t"    \
        VXOR_VV(REG_V19, REG_V19, REG_V16)              \
        VSLL_VI(REG_V20, REG_V3, s)                     \
        "slli   " CC_T0 ", " CC_D3 ", " #s "\n\t"       \
        VSLL_VI(REG_V21, REG_V7, s)                     \
        "slli   " CC_T1 ", " CC_D0 ", " #s "\n\t"       \
        VSLL_VI(REG_V22, REG_V11, s)                    \
        "slli   " CC_T2 ", " CC_D1 ", " #s "\n\t"       \
        VSLL_VI(REG_V23, REG_V15, s)                    \
        "slli   " CC_T3 ", " CC_D2 ", " #s "\n\t"       \
        VSLL_VI(REG_V24, REG_V19, s)                    \
        VSRL_VI(REG_V3, REG_V3, sr)                     \
        "srliw  " CC_D3 ", " CC_D3 ", " #sr "\n\t"      \
        VSRL_VI(REG_V7, REG_V7, sr)                     \
        "srliw  " CC_D0 ", " CC_D0 ", " #sr "\n\t"      \
        VSRL_VI(REG_V11, REG_V11, sr)                   \
        "srliw  " CC_D1 ", " CC_D1 ", " #sr "\n\t"      \
        VSRL_VI(REG_V15, REG_V15, sr)                   \
        "srliw  " CC_D2 ", " CC_D2 ", " #sr "\n\t"      \
        VSRL_VI(REG_V19, REG_V19, sr)                   \
        VOR_VV(REG_V3, REG_V3, REG_V20)                 \
        "or     " CC_D3 ", " CC_D3 ", " CC_T0 "\n\t"    \
        VOR_VV(REG_V7, REG_V7, REG_V21)                 \
        "or     " CC_D0 ", " CC_D0 ", " CC_T1 "\n\t"    \
        VOR_VV(REG_V11, REG_V11, REG_V22)               \
        "or     " CC_D1 ", " CC_D1 ", " CC_T2 "\n\t"    \
        VOR_VV(REG_V15, REG_V15, REG_V23)               \
        "or     " CC_D2 ", " CC_D2 ", " CC_T3 "\n\t"    \
        VOR_VV(REG_V19, REG_V19, REG_V24)

#define PART_ROUND_EVEN_CDB_5(s, sr)                    \
        VADD_VV(REG_V2, REG_V2, REG_V3)                 \
        "add    " CC_C2 ", " CC_C2 ", " CC_D3 "\n\t"    \
        VADD_VV(REG_V6, REG_V6, REG_V7)                 \
        "add    " CC_C3 ", " CC_C3 ", " CC_D0 "\n\t"    \
        VADD_VV(REG_V10, REG_V10, REG_V11)              \
        "add    " CC_C0 ", " CC_C0 ", " CC_D1 "\n\t"    \
        VADD_VV(REG_V14, REG_V14, REG_V15)              \
        "add    " CC_C1 ", " CC_C1 ", " CC_D2 "\n\t"    \
        VADD_VV(REG_V18, REG_V18, REG_V19)              \
        VXOR_VV(REG_V1, REG_V1, REG_V2)                 \
        "xor    " CC_B1 ", " CC_B1 ", " CC_C2 "\n\t"    \
        VXOR_VV(REG_V5, REG_V5, REG_V6)                 \
        "xor    " CC_B2 ", " CC_B2 ", " CC_C3 "\n\t"    \
        VXOR_VV(REG_V9, REG_V9, REG_V10)                \
        "xor    " CC_B3 ", " CC_B3 ", " CC_C0 "\n\t"    \
        VXOR_VV(REG_V13, REG_V13, REG_V14)              \
        "xor    " CC_B0 ", " CC_B0 ", " CC_C1 "\n\t"    \
        VXOR_VV(REG_V17, REG_V17, REG_V18)              \
        VSLL_VI(REG_V20, REG_V1, s)                     \
        "slli   " CC_T0 ", " CC_B1 ", " #s "\n\t"       \
        VSLL_VI(REG_V21, REG_V5, s)                     \
        "slli   " CC_T1 ", " CC_B2 ", " #s "\n\t"       \
        VSLL_VI(REG_V22, REG_V9, s)                     \
        "slli   " CC_T2 ", " CC_B3 ", " #s "\n\t"       \
        VSLL_VI(REG_V23, REG_V13, s)                    \
        "slli   " CC_T3 ", " CC_B0 ", " #s "\n\t"       \
        VSLL_VI(REG_V24, REG_V17, s)                    \
        VSRL_VI(REG_V1, REG_V1, sr)                     \
        "srliw  " CC_B1 ", " CC_B1 ", " #sr "\n\t"      \
        VSRL_VI(REG_V5, REG_V5, sr)                     \
        "srliw  " CC_B2 ", " CC_B2 ", " #sr "\n\t"      \
        VSRL_VI(REG_V9, REG_V9, sr)                     \
        "srliw  " CC_B3 ", " CC_B3 ", " #sr "\n\t"      \
        VSRL_VI(REG_V13, REG_V13, sr)                   \
        "srliw  " CC_B0 ", " CC_B0 ", " #sr "\n\t"      \
        VSRL_VI(REG_V17, REG_V17, sr)                   \
        VOR_VV(REG_V1, REG_V1, REG_V20)                 \
        "or     " CC_B1 ", " CC_B1 ", " CC_T0 "\n\t"    \
        VOR_VV(REG_V5, REG_V5, REG_V21)                 \
        "or     " CC_B2 ", " CC_B2 ", " CC_T1 "\n\t"    \
        VOR_VV(REG_V9, REG_V9, REG_V22)                 \
        "or     " CC_B3 ", " CC_B3 ", " CC_T2 "\n\t"    \
        VOR_VV(REG_V13, REG_V13, REG_V23)               \
        "or     " CC_B0 ", " CC_B0 ", " CC_T3 "\n\t"    \
        VOR_VV(REG_V17, REG_V17, REG_V24)

#elif !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION )

#define PART_ROUND_ODD_ABD_5(s, sr)                     \
        VADD_VV(REG_V0, REG_V0, REG_V1)                 \
        "add    " CC_A0 ", " CC_A0 ", " CC_B0 "\n\t"    \
        VADD_VV(REG_V4, REG_V4, REG_V5)                 \
        "add    " CC_A1 ", " CC_A1 ", " CC_B1 "\n\t"    \
        VADD_VV(REG_V8, REG_V8, REG_V9)                 \
        "add    " CC_A2 ", " CC_A2 ", " CC_B2 "\n\t"    \
        VADD_VV(REG_V12, REG_V12, REG_V13)              \
        "add    " CC_A3 ", " CC_A3 ", " CC_B3 "\n\t"    \
        VADD_VV(REG_V16, REG_V16, REG_V17)              \
        "xor    " CC_D0 ", " CC_D0 ", " CC_A0 "\n\t"    \
        VXOR_VV(REG_V3, REG_V3, REG_V0)                 \
        "xor    " CC_D1 ", " CC_D1 ", " CC_A1 "\n\t"    \
        VXOR_VV(REG_V7, REG_V7, REG_V4)                 \
        "xor    " CC_D2 ", " CC_D2 ", " CC_A2 "\n\t"    \
        VXOR_VV(REG_V11, REG_V11, REG_V8)               \
        "xor    " CC_D3 ", " CC_D3 ", " CC_A3 "\n\t"    \
        VXOR_VV(REG_V15, REG_V15, REG_V12)              \
        "slli   " CC_T0 ", " CC_D0 ", " #s "\n\t"       \
        VXOR_VV(REG_V19, REG_V19, REG_V16)              \
        "slli   " CC_T1 ", " CC_D1 ", " #s "\n\t"       \
        VROR_VI(REG_V3, sr, REG_V3)                     \
        "slli   " CC_T2 ", " CC_D2 ", " #s "\n\t"       \
        VROR_VI(REG_V7, sr, REG_V7)                     \
        "slli   " CC_T3 ", " CC_D3 ", " #s "\n\t"       \
        VROR_VI(REG_V11, sr, REG_V11)                   \
        "srliw  " CC_D0 ", " CC_D0 ", " #sr "\n\t"      \
        VROR_VI(REG_V15, sr, REG_V15)                   \
        "srliw  " CC_D1 ", " CC_D1 ", " #sr "\n\t"      \
        VROR_VI(REG_V19, sr, REG_V19)                   \
        "srliw  " CC_D2 ", " CC_D2 ", " #sr "\n\t"      \
        "srliw  " CC_D3 ", " CC_D3 ", " #sr "\n\t"      \
        "or     " CC_D0 ", " CC_D0 ", " CC_T0 "\n\t"    \
        "or     " CC_D1 ", " CC_D1 ", " CC_T1 "\n\t"    \
        "or     " CC_D2 ", " CC_D2 ", " CC_T2 "\n\t"    \
        "or     " CC_D3 ", " CC_D3 ", " CC_T3 "\n\t"

#define PART_ROUND_ODD_CDB_5(s, sr)                     \
        VADD_VV(REG_V2, REG_V2, REG_V3)                 \
        "add    " CC_C0 ", " CC_C0 ", " CC_D0 "\n\t"    \
        VADD_VV(REG_V6, REG_V6, REG_V7)                 \
        "add    " CC_C1 ", " CC_C1 ", " CC_D1 "\n\t"    \
        VADD_VV(REG_V10, REG_V10, REG_V11)              \
        "add    " CC_C2 ", " CC_C2 ", " CC_D2 "\n\t"    \
        VADD_VV(REG_V14, REG_V14, REG_V15)              \
        "add    " CC_C3 ", " CC_C3 ", " CC_D3 "\n\t"    \
        VADD_VV(REG_V18, REG_V18, REG_V19)              \
        "xor    " CC_B0 ", " CC_B0 ", " CC_C0 "\n\t"    \
        VXOR_VV(REG_V1, REG_V1, REG_V2)                 \
        "xor    " CC_B1 ", " CC_B1 ", " CC_C1 "\n\t"    \
        VXOR_VV(REG_V5, REG_V5, REG_V6)                 \
        "xor    " CC_B2 ", " CC_B2 ", " CC_C2 "\n\t"    \
        VXOR_VV(REG_V9, REG_V9, REG_V10)                \
        "xor    " CC_B3 ", " CC_B3 ", " CC_C3 "\n\t"    \
        VXOR_VV(REG_V13, REG_V13, REG_V14)              \
        "slli   " CC_T0 ", " CC_B0 ", " #s "\n\t"       \
        VXOR_VV(REG_V17, REG_V17, REG_V18)              \
        "slli   " CC_T1 ", " CC_B1 ", " #s "\n\t"       \
        VROR_VI(REG_V1, sr, REG_V1)                     \
        "slli   " CC_T2 ", " CC_B2 ", " #s "\n\t"       \
        VROR_VI(REG_V5, sr, REG_V5)                     \
        "slli   " CC_T3 ", " CC_B3 ", " #s "\n\t"       \
        VROR_VI(REG_V9, sr, REG_V9)                     \
        "srliw  " CC_B0 ", " CC_B0 ", " #sr "\n\t"      \
        VROR_VI(REG_V13, sr, REG_V13)                   \
        "srliw  " CC_B1 ", " CC_B1 ", " #sr "\n\t"      \
        VROR_VI(REG_V17, sr, REG_V17)                   \
        "srliw  " CC_B2 ", " CC_B2 ", " #sr "\n\t"      \
        "srliw  " CC_B3 ", " CC_B3 ", " #sr "\n\t"      \
        "or     " CC_B0 ", " CC_B0 ", " CC_T0 "\n\t"    \
        "or     " CC_B1 ", " CC_B1 ", " CC_T1 "\n\t"    \
        "or     " CC_B2 ", " CC_B2 ", " CC_T2 "\n\t"    \
        "or     " CC_B3 ", " CC_B3 ", " CC_T3 "\n\t"

#define PART_ROUND_EVEN_ABD_5(s, sr)                    \
        VADD_VV(REG_V0, REG_V0, REG_V1)                 \
        "add    " CC_A0 ", " CC_A0 ", " CC_B1 "\n\t"    \
        VADD_VV(REG_V4, REG_V4, REG_V5)                 \
        "add    " CC_A1 ", " CC_A1 ", " CC_B2 "\n\t"    \
        VADD_VV(REG_V8, REG_V8, REG_V9)                 \
        "add    " CC_A2 ", " CC_A2 ", " CC_B3 "\n\t"    \
        VADD_VV(REG_V12, REG_V12, REG_V13)              \
        "add    " CC_A3 ", " CC_A3 ", " CC_B0 "\n\t"    \
        VADD_VV(REG_V16, REG_V16, REG_V17)              \
        "xor    " CC_D3 ", " CC_D3 ", " CC_A0 "\n\t"    \
        VXOR_VV(REG_V3, REG_V3, REG_V0)                 \
        "xor    " CC_D0 ", " CC_D0 ", " CC_A1 "\n\t"    \
        VXOR_VV(REG_V7, REG_V7, REG_V4)                 \
        "xor    " CC_D1 ", " CC_D1 ", " CC_A2 "\n\t"    \
        VXOR_VV(REG_V11, REG_V11, REG_V8)               \
        "xor    " CC_D2 ", " CC_D2 ", " CC_A3 "\n\t"    \
        VXOR_VV(REG_V15, REG_V15, REG_V12)              \
        "slli   " CC_T0 ", " CC_D3 ", " #s "\n\t"       \
        VXOR_VV(REG_V19, REG_V19, REG_V16)              \
        "slli   " CC_T1 ", " CC_D0 ", " #s "\n\t"       \
        VROR_VI(REG_V3, sr, REG_V3)                     \
        "slli   " CC_T2 ", " CC_D1 ", " #s "\n\t"       \
        VROR_VI(REG_V7, sr, REG_V7)                     \
        "slli   " CC_T3 ", " CC_D2 ", " #s "\n\t"       \
        VROR_VI(REG_V11, sr, REG_V11)                   \
        "srliw  " CC_D3 ", " CC_D3 ", " #sr "\n\t"      \
        VROR_VI(REG_V15, sr, REG_V15)                   \
        "srliw  " CC_D0 ", " CC_D0 ", " #sr "\n\t"      \
        VROR_VI(REG_V19, sr, REG_V19)                   \
        "srliw  " CC_D1 ", " CC_D1 ", " #sr "\n\t"      \
        "srliw  " CC_D2 ", " CC_D2 ", " #sr "\n\t"      \
        "or     " CC_D3 ", " CC_D3 ", " CC_T0 "\n\t"    \
        "or     " CC_D0 ", " CC_D0 ", " CC_T1 "\n\t"    \
        "or     " CC_D1 ", " CC_D1 ", " CC_T2 "\n\t"    \
        "or     " CC_D2 ", " CC_D2 ", " CC_T3 "\n\t"

#define PART_ROUND_EVEN_CDB_5(s, sr)                    \
        VADD_VV(REG_V2, REG_V2, REG_V3)                 \
        "add    " CC_C2 ", " CC_C2 ", " CC_D3 "\n\t"    \
        VADD_VV(REG_V6, REG_V6, REG_V7)                 \
        "add    " CC_C3 ", " CC_C3 ", " CC_D0 "\n\t"    \
        VADD_VV(REG_V10, REG_V10, REG_V11)              \
        "add    " CC_C0 ", " CC_C0 ", " CC_D1 "\n\t"    \
        VADD_VV(REG_V14, REG_V14, REG_V15)              \
        "add    " CC_C1 ", " CC_C1 ", " CC_D2 "\n\t"    \
        VADD_VV(REG_V18, REG_V18, REG_V19)              \
        "xor    " CC_B1 ", " CC_B1 ", " CC_C2 "\n\t"    \
        VXOR_VV(REG_V1, REG_V1, REG_V2)                 \
        "xor    " CC_B2 ", " CC_B2 ", " CC_C3 "\n\t"    \
        VXOR_VV(REG_V5, REG_V5, REG_V6)                 \
        "xor    " CC_B3 ", " CC_B3 ", " CC_C0 "\n\t"    \
        VXOR_VV(REG_V9, REG_V9, REG_V10)                \
        "xor    " CC_B0 ", " CC_B0 ", " CC_C1 "\n\t"    \
        VXOR_VV(REG_V13, REG_V13, REG_V14)              \
        "slli   " CC_T0 ", " CC_B1 ", " #s "\n\t"       \
        VXOR_VV(REG_V17, REG_V17, REG_V18)              \
        "slli   " CC_T1 ", " CC_B2 ", " #s "\n\t"       \
        VROR_VI(REG_V1, sr, REG_V1)                     \
        "slli   " CC_T2 ", " CC_B3 ", " #s "\n\t"       \
        VROR_VI(REG_V5, sr, REG_V5)                     \
        "slli   " CC_T3 ", " CC_B0 ", " #s "\n\t"       \
        VROR_VI(REG_V9, sr, REG_V9)                     \
        "srliw  " CC_B1 ", " CC_B1 ", " #sr "\n\t"      \
        VROR_VI(REG_V13, sr, REG_V13)                   \
        "srliw  " CC_B2 ", " CC_B2 ", " #sr "\n\t"      \
        VROR_VI(REG_V17, sr, REG_V17)                   \
        "srliw  " CC_B3 ", " CC_B3 ", " #sr "\n\t"      \
        "srliw  " CC_B0 ", " CC_B0 ", " #sr "\n\t"      \
        "or     " CC_B1 ", " CC_B1 ", " CC_T0 "\n\t"    \
        "or     " CC_B2 ", " CC_B2 ", " CC_T1 "\n\t"    \
        "or     " CC_B3 ", " CC_B3 ", " CC_T2 "\n\t"    \
        "or     " CC_B0 ", " CC_B0 ", " CC_T3 "\n\t"

#else

#define PART_ROUND_ODD_ABD_5(s, sr)                     \
        VADD_VV(REG_V0, REG_V0, REG_V1)                 \
        "add    " CC_A0 ", " CC_A0 ", " CC_B0 "\n\t"    \
        VADD_VV(REG_V4, REG_V4, REG_V5)                 \
        "add    " CC_A1 ", " CC_A1 ", " CC_B1 "\n\t"    \
        VADD_VV(REG_V8, REG_V8, REG_V9)                 \
        "add    " CC_A2 ", " CC_A2 ", " CC_B2 "\n\t"    \
        VADD_VV(REG_V12, REG_V12, REG_V13)              \
        "add    " CC_A3 ", " CC_A3 ", " CC_B3 "\n\t"    \
        VADD_VV(REG_V16, REG_V16, REG_V17)              \
        VXOR_VV(REG_V3, REG_V3, REG_V0)                 \
        "xor    " CC_D0 ", " CC_D0 ", " CC_A0 "\n\t"    \
        VXOR_VV(REG_V7, REG_V7, REG_V4)                 \
        "xor    " CC_D1 ", " CC_D1 ", " CC_A1 "\n\t"    \
        VXOR_VV(REG_V11, REG_V11, REG_V8)               \
        "xor    " CC_D2 ", " CC_D2 ", " CC_A2 "\n\t"    \
        VXOR_VV(REG_V15, REG_V15, REG_V12)              \
        "xor    " CC_D3 ", " CC_D3 ", " CC_A3 "\n\t"    \
        VXOR_VV(REG_V19, REG_V19, REG_V16)              \
        VROR_VI(REG_V3, sr, REG_V3)                     \
        RORIW(REG_S6, REG_S6, sr)                       \
        VROR_VI(REG_V7, sr, REG_V7)                     \
        RORIW(REG_S7, REG_S7, sr)                       \
        VROR_VI(REG_V11, sr, REG_V11)                   \
        RORIW(REG_S8, REG_S8, sr)                       \
        VROR_VI(REG_V15, sr, REG_V15)                   \
        RORIW(REG_S9, REG_S9, sr)                       \
        VROR_VI(REG_V19, sr, REG_V19)

#define PART_ROUND_ODD_CDB_5(s, sr)                     \
        VADD_VV(REG_V2, REG_V2, REG_V3)                 \
        "add    " CC_C0 ", " CC_C0 ", " CC_D0 "\n\t"    \
        VADD_VV(REG_V6, REG_V6, REG_V7)                 \
        "add    " CC_C1 ", " CC_C1 ", " CC_D1 "\n\t"    \
        VADD_VV(REG_V10, REG_V10, REG_V11)              \
        "add    " CC_C2 ", " CC_C2 ", " CC_D2 "\n\t"    \
        VADD_VV(REG_V14, REG_V14, REG_V15)              \
        "add    " CC_C3 ", " CC_C3 ", " CC_D3 "\n\t"    \
        VADD_VV(REG_V18, REG_V18, REG_V19)              \
        VXOR_VV(REG_V1, REG_V1, REG_V2)                 \
        "xor    " CC_B0 ", " CC_B0 ", " CC_C0 "\n\t"    \
        VXOR_VV(REG_V5, REG_V5, REG_V6)                 \
        "xor    " CC_B1 ", " CC_B1 ", " CC_C1 "\n\t"    \
        VXOR_VV(REG_V9, REG_V9, REG_V10)                \
        "xor    " CC_B2 ", " CC_B2 ", " CC_C2 "\n\t"    \
        VXOR_VV(REG_V13, REG_V13, REG_V14)              \
        "xor    " CC_B3 ", " CC_B3 ", " CC_C3 "\n\t"    \
        VXOR_VV(REG_V17, REG_V17, REG_V18)              \
        VROR_VI(REG_V1, sr, REG_V1)                     \
        RORIW(REG_T3, REG_T3, sr)                       \
        VROR_VI(REG_V5, sr, REG_V5)                     \
        RORIW(REG_T4, REG_T4, sr)                       \
        VROR_VI(REG_V9, sr, REG_V9)                     \
        RORIW(REG_T5, REG_T5, sr)                       \
        VROR_VI(REG_V13, sr, REG_V13)                   \
        RORIW(REG_T6, REG_T6, sr)                       \
        VROR_VI(REG_V17, sr, REG_V17)

#define PART_ROUND_EVEN_ABD_5(s, sr)                    \
        VADD_VV(REG_V0, REG_V0, REG_V1)                 \
        "add    " CC_A0 ", " CC_A0 ", " CC_B1 "\n\t"    \
        VADD_VV(REG_V4, REG_V4, REG_V5)                 \
        "add    " CC_A1 ", " CC_A1 ", " CC_B2 "\n\t"    \
        VADD_VV(REG_V8, REG_V8, REG_V9)                 \
        "add    " CC_A2 ", " CC_A2 ", " CC_B3 "\n\t"    \
        VADD_VV(REG_V12, REG_V12, REG_V13)              \
        "add    " CC_A3 ", " CC_A3 ", " CC_B0 "\n\t"    \
        VADD_VV(REG_V16, REG_V16, REG_V17)              \
        VXOR_VV(REG_V3, REG_V3, REG_V0)                 \
        "xor    " CC_D3 ", " CC_D3 ", " CC_A0 "\n\t"    \
        VXOR_VV(REG_V7, REG_V7, REG_V4)                 \
        "xor    " CC_D0 ", " CC_D0 ", " CC_A1 "\n\t"    \
        VXOR_VV(REG_V11, REG_V11, REG_V8)               \
        "xor    " CC_D1 ", " CC_D1 ", " CC_A2 "\n\t"    \
        VXOR_VV(REG_V15, REG_V15, REG_V12)              \
        "xor    " CC_D2 ", " CC_D2 ", " CC_A3 "\n\t"    \
        VXOR_VV(REG_V19, REG_V19, REG_V16)              \
        VROR_VI(REG_V3, sr, REG_V3)                     \
        RORIW(REG_S9, REG_S9, sr)                       \
        VROR_VI(REG_V7, sr, REG_V7)                     \
        RORIW(REG_S6, REG_S6, sr)                       \
        VROR_VI(REG_V11, sr, REG_V11)                   \
        RORIW(REG_S7, REG_S7, sr)                       \
        VROR_VI(REG_V15, sr, REG_V15)                   \
        RORIW(REG_S8, REG_S8, sr)                       \
        VROR_VI(REG_V19, sr, REG_V19)

#define PART_ROUND_EVEN_CDB_5(s, sr)                    \
        VADD_VV(REG_V2, REG_V2, REG_V3)                 \
        "add    " CC_C2 ", " CC_C2 ", " CC_D3 "\n\t"    \
        VADD_VV(REG_V6, REG_V6, REG_V7)                 \
        "add    " CC_C3 ", " CC_C3 ", " CC_D0 "\n\t"    \
        VADD_VV(REG_V10, REG_V10, REG_V11)              \
        "add    " CC_C0 ", " CC_C0 ", " CC_D1 "\n\t"    \
        VADD_VV(REG_V14, REG_V14, REG_V15)              \
        "add    " CC_C1 ", " CC_C1 ", " CC_D2 "\n\t"    \
        VADD_VV(REG_V18, REG_V18, REG_V19)              \
        VXOR_VV(REG_V1, REG_V1, REG_V2)                 \
        "xor    " CC_B1 ", " CC_B1 ", " CC_C2 "\n\t"    \
        VXOR_VV(REG_V5, REG_V5, REG_V6)                 \
        "xor    " CC_B2 ", " CC_B2 ", " CC_C3 "\n\t"    \
        VXOR_VV(REG_V9, REG_V9, REG_V10)                \
        "xor    " CC_B3 ", " CC_B3 ", " CC_C0 "\n\t"    \
        VXOR_VV(REG_V13, REG_V13, REG_V14)              \
        "xor    " CC_B0 ", " CC_B0 ", " CC_C1 "\n\t"    \
        VXOR_VV(REG_V17, REG_V17, REG_V18)              \
        VROR_VI(REG_V1, sr, REG_V1)                     \
        RORIW(REG_T4, REG_T4, sr)                       \
        VROR_VI(REG_V5, sr, REG_V5)                     \
        RORIW(REG_T5, REG_T5, sr)                       \
        VROR_VI(REG_V9, sr, REG_V9)                     \
        RORIW(REG_T6, REG_T6, sr)                       \
        VROR_VI(REG_V13, sr, REG_V13)                   \
        RORIW(REG_T3, REG_T3, sr)                       \
        VROR_VI(REG_V17, sr, REG_V17)

#endif

#define QUARTER_ROUND_ODD_5()               \
        /* a += b; d ^= a; d <<<= 16; */    \
        PART_ROUND_ODD_ABD_5(16, 16)        \
        /* c += d; b ^= c; b <<<= 12; */    \
        PART_ROUND_ODD_CDB_5(12, 20)        \
        /* a += b; d ^= a; d <<<= 8; */     \
        PART_ROUND_ODD_ABD_5( 8, 24)        \
        /* c += d; b ^= c; b <<<= 7; */     \
        PART_ROUND_ODD_CDB_5( 7, 25)

#define QUARTER_ROUND_EVEN_5()              \
        /* a += b; d ^= a; d <<<= 16; */    \
        PART_ROUND_EVEN_ABD_5(16, 16)       \
        /* c += d; b ^= c; b <<<= 12; */    \
        PART_ROUND_EVEN_CDB_5(12, 20)       \
        /* a += b; d ^= a; d <<<= 8; */     \
        PART_ROUND_EVEN_ABD_5( 8, 24)       \
        /* c += d; b ^= c; b <<<= 7; */     \
        PART_ROUND_EVEN_CDB_5( 7, 25)

#define SHUFFLE_5(r, t, i)                  \
        VRGATHER_VV(t + 0, i, r + 0)        \
        VRGATHER_VV(t + 1, i, r + 4)        \
        VRGATHER_VV(t + 2, i, r + 8)        \
        VRGATHER_VV(t + 3, i, r + 12)       \
        VRGATHER_VV(t + 4, i, r + 16)       \
        VMV_V_V(r + 0, t + 0)               \
        VMV_V_V(r + 4, t + 1)               \
        VMV_V_V(r + 8, t + 2)               \
        VMV_V_V(r + 12, t + 3)              \
        VMV_V_V(r + 16, t + 4)

#define ODD_SHUFFLE_5()                                                 \
        /*    a=0,1,2,3; b=4,5,6,7; c=8,9,10,11; d=12,13,14,15          \
         * => a=0,1,2,3; b=5,6,7,4; c=10,11,8,9; d=15,12,13,14 */       \
        SHUFFLE_5(REG_V3, REG_V20, REG_V27)                             \
        SHUFFLE_5(REG_V1, REG_V20, REG_V25)                             \
        SHUFFLE_5(REG_V2, REG_V20, REG_V26)

#define EVEN_SHUFFLE_5()                                                \
        /*    a=0,1,2,3; b=5,6,7,4; c=10,11,8,9; d=15,12,13,14          \
         * => a=0,1,2,3; b=4,5,6,7; c=8,9,10,11; d=12,13,14,15 */       \
        SHUFFLE_5(REG_V3, REG_V20, REG_V25)                             \
        SHUFFLE_5(REG_V1, REG_V20, REG_V27)                             \
        SHUFFLE_5(REG_V2, REG_V20, REG_V26)

static WC_INLINE void wc_chacha_encrypt_384(const word32* input, const byte* m,
    byte* c, word32 bytes)
{
    word64 bytes64 = (word64)bytes;

    __asm__ __volatile__ (
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
        /* The layout of used vector registers is:
         * v0-v3 - first block
         * v4-v7 - second block
         * v8-v11 - third block
         * v12-v15 - fourth block
         * v16-v19 - fifth block
         * v20-v24 - temp/message
         * v25-v27 - indices for rotating words in vector
         * v28-v31 - input
         *
         * v0  0  1  2  3
         * v1  4  5  6  7
         * v2  8  9 10 11
         * v3 12 13 14 15
         * load CHACHA state with indices placed as shown above
         */

        /* Load state to encrypt */
        "mv     t2, %[input]\n\t"
        VL4RE32_V(REG_V28, REG_T2)
        VID_V(REG_V20)
        VSLIDEDOWN_VI(REG_V25, REG_V20, 1)
        VSLIDEUP_VI(REG_V25, REG_V20, 3)
        VSLIDEDOWN_VI(REG_V26, REG_V20, 2)
        VSLIDEUP_VI(REG_V26, REG_V20, 2)
        VSLIDEDOWN_VI(REG_V27, REG_V20, 3)
        VSLIDEUP_VI(REG_V27, REG_V20, 1)
        "\n"
    "L_chacha20_riscv_384_outer:\n\t"
        /* Move state into regular registers */
        "ld     a4,  0(%[input])\n\t"
        "ld     a6,  8(%[input])\n\t"
        "ld     t3, 16(%[input])\n\t"
        "ld     t5, 24(%[input])\n\t"
        "ld     s2, 32(%[input])\n\t"
        "ld     s4, 40(%[input])\n\t"
        "lw     s7, 52(%[input])\n\t"
        "ld     s8, 56(%[input])\n\t"
        "srli   a5, a4, 32\n\t"
        "srli   a7, a6, 32\n\t"
        "srli   t4, t3, 32\n\t"
        "srli   t6, t5, 32\n\t"
        "srli   s3, s2, 32\n\t"
        "srli   s5, s4, 32\n\t"
        "srli   s9, s8, 32\n\t"
        VMV_X_S(REG_S6, REG_V31)
        /* Move state into vector registers */
        VMVR_V(REG_V0, REG_V28, 4)
        VMVR_V(REG_V4, REG_V28, 4)
        VMVR_V(REG_V8, REG_V28, 4)
        VMVR_V(REG_V12, REG_V28, 4)
        VMVR_V(REG_V16, REG_V28, 4)
        /* Set counter word */
        "addi   t1, s6, 1\n\t"
        VMV_S_X(REG_V7, REG_T1)
        "addi   t1, s6, 2\n\t"
        VMV_S_X(REG_V11, REG_T1)
        "addi   t1, s6, 3\n\t"
        VMV_S_X(REG_V15, REG_T1)
        "addi   t1, s6, 4\n\t"
        VMV_S_X(REG_V19, REG_T1)
        "addi   s6, s6, 5\n\t"
        /* Set number of odd+even rounds to perform */
        "li     a3, 10\n\t"
        "\n"
    "L_chacha20_riscv_384_loop:\n\t"
        /* Odd Round */
        QUARTER_ROUND_ODD_5()
        ODD_SHUFFLE_5()
        /* Even Round */
        QUARTER_ROUND_EVEN_5()
        EVEN_SHUFFLE_5()
        "addi   a3, a3, -1\n\t"
        "bnez   a3, L_chacha20_riscv_384_loop\n\t"
        /* Load message */
        "mv     t2, %[m]\n\t"
        VL4RE32_V(REG_V20, REG_T2)
        "addi   %[m], %[m], 64\n\t"
        /* Add back state, XOR in message and store (load next block) */
        /* BLOCK 1 */
        VADD_VV(REG_V0, REG_V0, REG_V28)
        VADD_VV(REG_V1, REG_V1, REG_V29)
        VADD_VV(REG_V2, REG_V2, REG_V30)
        VADD_VV(REG_V3, REG_V3, REG_V31)
        VXOR_VV(REG_V0, REG_V0, REG_V20)
        VXOR_VV(REG_V1, REG_V1, REG_V21)
        VXOR_VV(REG_V2, REG_V2, REG_V22)
        VXOR_VV(REG_V3, REG_V3, REG_V23)
        "mv     t2, %[m]\n\t"
        VL4RE32_V(REG_V20, REG_T2)
        "addi   %[m], %[m], 64\n\t"
        VMV_X_S(REG_T0, REG_V31)
        "mv     t2, %[c]\n\t"
        VS4R_V(REG_V0, REG_T2)
        "addi   %[c], %[c], 64\n\t"
        /* BLOCK 2 */
        "addi   t0, t0, 1\n\t"
        VMV_S_X(REG_V31, REG_T0)
        VADD_VV(REG_V4, REG_V4, REG_V28)
        VADD_VV(REG_V5, REG_V5, REG_V29)
        VADD_VV(REG_V6, REG_V6, REG_V30)
        VADD_VV(REG_V7, REG_V7, REG_V31)
        VXOR_VV(REG_V4, REG_V4, REG_V20)
        VXOR_VV(REG_V5, REG_V5, REG_V21)
        VXOR_VV(REG_V6, REG_V6, REG_V22)
        VXOR_VV(REG_V7, REG_V7, REG_V23)
        "mv     t2, %[m]\n\t"
        VL4RE32_V(REG_V20, REG_T2)
        "addi   %[m], %[m], 64\n\t"
        "mv     t2, %[c]\n\t"
        VS4R_V(REG_V4, REG_T2)
        "addi   %[c], %[c], 64\n\t"
        /* BLOCK 3 */
        "addi   t0, t0, 1\n\t"
        VMV_S_X(REG_V31, REG_T0)
        VADD_VV(REG_V8, REG_V8, REG_V28)
        VADD_VV(REG_V9, REG_V9, REG_V29)
        VADD_VV(REG_V10, REG_V10, REG_V30)
        VADD_VV(REG_V11, REG_V11, REG_V31)
        VXOR_VV(REG_V8, REG_V8, REG_V20)
        VXOR_VV(REG_V9, REG_V9, REG_V21)
        VXOR_VV(REG_V10, REG_V10, REG_V22)
        VXOR_VV(REG_V11, REG_V11, REG_V23)
        "mv     t2, %[m]\n\t"
        VL4RE32_V(REG_V20, REG_T2)
        "addi   %[m], %[m], 64\n\t"
        "mv     t2, %[c]\n\t"
        VS4R_V(REG_V8, REG_T2)
        "addi   %[c], %[c], 64\n\t"
        /* BLOCK 4 */
        "addi   t0, t0, 1\n\t"
        VMV_S_X(REG_V31, REG_T0)
        VADD_VV(REG_V12, REG_V12, REG_V28)
        VADD_VV(REG_V13, REG_V13, REG_V29)
        VADD_VV(REG_V14, REG_V14, REG_V30)
        VADD_VV(REG_V15, REG_V15, REG_V31)
        VXOR_VV(REG_V12, REG_V12, REG_V20)
        VXOR_VV(REG_V13, REG_V13, REG_V21)
        VXOR_VV(REG_V14, REG_V14, REG_V22)
        VXOR_VV(REG_V15, REG_V15, REG_V23)
        "mv     t2, %[m]\n\t"
        VL4RE32_V(REG_V20, REG_T2)
        "addi   %[m], %[m], 64\n\t"
        "mv     t2, %[c]\n\t"
        VS4R_V(REG_V12, REG_T2)
        "addi   %[c], %[c], 64\n\t"
        /* BLOCK 5 */
        "addi   t0, t0, 1\n\t"
        VMV_S_X(REG_V31, REG_T0)
        VADD_VV(REG_V16, REG_V16, REG_V28)
        VADD_VV(REG_V17, REG_V17, REG_V29)
        VADD_VV(REG_V18, REG_V18, REG_V30)
        VADD_VV(REG_V19, REG_V19, REG_V31)
        VXOR_VV(REG_V16, REG_V16, REG_V20)
        VXOR_VV(REG_V17, REG_V17, REG_V21)
        VXOR_VV(REG_V18, REG_V18, REG_V22)
        VXOR_VV(REG_V19, REG_V19, REG_V23)
        "mv     t2, %[m]\n\t"
        VL4RE32_V(REG_V20, REG_T2)
        "addi   %[m], %[m], 64\n\t"
        "mv     t2, %[c]\n\t"
        VS4R_V(REG_V16, REG_T2)
        "addi   %[c], %[c], 64\n\t"
        /* BLOCK 6 */
        /* Move regular registers into vector registers for adding and xor */
        "addi   t0, t0, 1\n\t"
        VMV_S_X(REG_V0, REG_A4)
        VMV_S_X(REG_V1, REG_T3)
        VMV_S_X(REG_V2, REG_S2)
        VMV_S_X(REG_V3, REG_S6)
        VMV_S_X(REG_V4, REG_A5)
        VMV_S_X(REG_V5, REG_T4)
        VMV_S_X(REG_V6, REG_S3)
        VMV_S_X(REG_V7, REG_S7)
        VSLIDEUP_VI(REG_V0, REG_V4, 1)
        VSLIDEUP_VI(REG_V1, REG_V5, 1)
        VSLIDEUP_VI(REG_V2, REG_V6, 1)
        VSLIDEUP_VI(REG_V3, REG_V7, 1)
        VMV_S_X(REG_V4, REG_A6)
        VMV_S_X(REG_V5, REG_T5)
        VMV_S_X(REG_V6, REG_S4)
        VMV_S_X(REG_V7, REG_S8)
        VSLIDEUP_VI(REG_V0, REG_V4, 2)
        VSLIDEUP_VI(REG_V1, REG_V5, 2)
        VSLIDEUP_VI(REG_V2, REG_V6, 2)
        VSLIDEUP_VI(REG_V3, REG_V7, 2)
        VMV_S_X(REG_V4, REG_A7)
        VMV_S_X(REG_V5, REG_T6)
        VMV_S_X(REG_V6, REG_S5)
        VMV_S_X(REG_V7, REG_S9)
        VSLIDEUP_VI(REG_V0, REG_V4, 3)
        VSLIDEUP_VI(REG_V1, REG_V5, 3)
        VSLIDEUP_VI(REG_V2, REG_V6, 3)
        VSLIDEUP_VI(REG_V3, REG_V7, 3)
        VMV_S_X(REG_V31, REG_T0)
        /* Add back state, XOR in message and store */
        VADD_VV(REG_V0, REG_V0, REG_V28)
        VADD_VV(REG_V1, REG_V1, REG_V29)
        VADD_VV(REG_V2, REG_V2, REG_V30)
        VADD_VV(REG_V3, REG_V3, REG_V31)
        VXOR_VV(REG_V0, REG_V0, REG_V20)
        VXOR_VV(REG_V1, REG_V1, REG_V21)
        VXOR_VV(REG_V2, REG_V2, REG_V22)
        VXOR_VV(REG_V3, REG_V3, REG_V23)
        "mv     t2, %[c]\n\t"
        VS4R_V(REG_V0, REG_T2)
        "addi   %[c], %[c], 64\n\t"
        "addi   %[bytes], %[bytes], -384\n\t"
        "addi   t0, t0, 1\n\t"
        VMV_S_X(REG_V31, REG_T0)
        "bnez   %[bytes], L_chacha20_riscv_384_outer\n\t"
        : [m] "+r" (m), [c] "+r" (c), [bytes] "+r" (bytes64)
        : [input] "r" (input)
        : "memory", "t0", "t1", "t2", "s1", "a3",
          "t3", "t4", "t5", "t6",
          "a4", "a5", "a6", "a7",
          "s2", "s3", "s4", "s5",
          "s6", "s7", "s8", "s9"
    );
}

#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION

#define PART_ROUND_ODD_ABD(s, sr)                       \
        "add    " CC_A0 ", " CC_A0 ", " CC_B0 "\n\t"    \
        VADD_VV(REG_V0, REG_V0, REG_V1)                 \
        "add    " CC_A1 ", " CC_A1 ", " CC_B1 "\n\t"    \
        VADD_VV(REG_V4, REG_V4, REG_V5)                 \
        "add    " CC_A2 ", " CC_A2 ", " CC_B2 "\n\t"    \
        VADD_VV(REG_V8, REG_V8, REG_V9)                 \
        "add    " CC_A3 ", " CC_A3 ", " CC_B3 "\n\t"    \
        VXOR_VV(REG_V3, REG_V3, REG_V0)                 \
        "xor    " CC_D0 ", " CC_D0 ", " CC_A0 "\n\t"    \
        VXOR_VV(REG_V7, REG_V7, REG_V4)                 \
        "xor    " CC_D1 ", " CC_D1 ", " CC_A1 "\n\t"    \
        VXOR_VV(REG_V11, REG_V11, REG_V8)               \
        "xor    " CC_D2 ", " CC_D2 ", " CC_A2 "\n\t"    \
        VSLL_VI(REG_V20, REG_V3, s)                     \
        "xor    " CC_D3 ", " CC_D3 ", " CC_A3 "\n\t"    \
        VSLL_VI(REG_V21, REG_V7, s)                     \
        "slli   " CC_T0 ", " CC_D0 ", " #s "\n\t"       \
        VSLL_VI(REG_V22, REG_V11, s)                    \
        "slli   " CC_T1 ", " CC_D1 ", " #s "\n\t"       \
        VSRL_VI(REG_V3, REG_V3, sr)                     \
        "slli   " CC_T2 ", " CC_D2 ", " #s "\n\t"       \
        VSRL_VI(REG_V7, REG_V7, sr)                     \
        "slli   " CC_T3 ", " CC_D3 ", " #s "\n\t"       \
        VSRL_VI(REG_V11, REG_V11, sr)                   \
        "srliw  " CC_D0 ", " CC_D0 ", " #sr "\n\t"      \
        VOR_VV(REG_V3, REG_V3, REG_V20)                 \
        "srliw  " CC_D1 ", " CC_D1 ", " #sr "\n\t"      \
        VOR_VV(REG_V7, REG_V7, REG_V21)                 \
        "srliw  " CC_D2 ", " CC_D2 ", " #sr "\n\t"      \
        VOR_VV(REG_V11, REG_V11, REG_V22)               \
        "srliw  " CC_D3 ", " CC_D3 ", " #sr "\n\t"      \
        "or     " CC_D0 ", " CC_D0 ", " CC_T0 "\n\t"    \
        "or     " CC_D1 ", " CC_D1 ", " CC_T1 "\n\t"    \
        "or     " CC_D2 ", " CC_D2 ", " CC_T2 "\n\t"    \
        "or     " CC_D3 ", " CC_D3 ", " CC_T3 "\n\t"

#define PART_ROUND_ODD_CDB(s, sr)                       \
        "add    " CC_C0 ", " CC_C0 ", " CC_D0 "\n\t"    \
        VADD_VV(REG_V2, REG_V2, REG_V3)                 \
        "add    " CC_C1 ", " CC_C1 ", " CC_D1 "\n\t"    \
        VADD_VV(REG_V6, REG_V6, REG_V7)                 \
        "add    " CC_C2 ", " CC_C2 ", " CC_D2 "\n\t"    \
        VADD_VV(REG_V10, REG_V10, REG_V11)              \
        "add    " CC_C3 ", " CC_C3 ", " CC_D3 "\n\t"    \
        VXOR_VV(REG_V1, REG_V1, REG_V2)                 \
        "xor    " CC_B0 ", " CC_B0 ", " CC_C0 "\n\t"    \
        VXOR_VV(REG_V5, REG_V5, REG_V6)                 \
        "xor    " CC_B1 ", " CC_B1 ", " CC_C1 "\n\t"    \
        VXOR_VV(REG_V9, REG_V9, REG_V10)                \
        "xor    " CC_B2 ", " CC_B2 ", " CC_C2 "\n\t"    \
        VSLL_VI(REG_V20, REG_V1, s)                     \
        "xor    " CC_B3 ", " CC_B3 ", " CC_C3 "\n\t"    \
        VSLL_VI(REG_V21, REG_V5, s)                     \
        "slli   " CC_T0 ", " CC_B0 ", " #s "\n\t"       \
        VSLL_VI(REG_V22, REG_V9, s)                     \
        "slli   " CC_T1 ", " CC_B1 ", " #s "\n\t"       \
        VSRL_VI(REG_V1, REG_V1, sr)                     \
        "slli   " CC_T2 ", " CC_B2 ", " #s "\n\t"       \
        VSRL_VI(REG_V5, REG_V5, sr)                     \
        "slli   " CC_T3 ", " CC_B3 ", " #s "\n\t"       \
        VSRL_VI(REG_V9, REG_V9, sr)                     \
        "srliw  " CC_B0 ", " CC_B0 ", " #sr "\n\t"      \
        VOR_VV(REG_V1, REG_V1, REG_V20)                 \
        "srliw  " CC_B1 ", " CC_B1 ", " #sr "\n\t"      \
        VOR_VV(REG_V5, REG_V5, REG_V21)                 \
        "srliw  " CC_B2 ", " CC_B2 ", " #sr "\n\t"      \
        VOR_VV(REG_V9, REG_V9, REG_V22)                 \
        "srliw  " CC_B3 ", " CC_B3 ", " #sr "\n\t"      \
        "or     " CC_B0 ", " CC_B0 ", " CC_T0 "\n\t"    \
        "or     " CC_B1 ", " CC_B1 ", " CC_T1 "\n\t"    \
        "or     " CC_B2 ", " CC_B2 ", " CC_T2 "\n\t"    \
        "or     " CC_B3 ", " CC_B3 ", " CC_T3 "\n\t"

#define PART_ROUND_EVEN_ABD(s, sr)                      \
        "add    " CC_A0 ", " CC_A0 ", " CC_B1 "\n\t"    \
        VADD_VV(REG_V0, REG_V0, REG_V1)                 \
        "add    " CC_A1 ", " CC_A1 ", " CC_B2 "\n\t"    \
        VADD_VV(REG_V4, REG_V4, REG_V5)                 \
        "add    " CC_A2 ", " CC_A2 ", " CC_B3 "\n\t"    \
        VADD_VV(REG_V8, REG_V8, REG_V9)                 \
        "add    " CC_A3 ", " CC_A3 ", " CC_B0 "\n\t"    \
        VXOR_VV(REG_V3, REG_V3, REG_V0)                 \
        "xor    " CC_D3 ", " CC_D3 ", " CC_A0 "\n\t"    \
        VXOR_VV(REG_V7, REG_V7, REG_V4)                 \
        "xor    " CC_D0 ", " CC_D0 ", " CC_A1 "\n\t"    \
        VXOR_VV(REG_V11, REG_V11, REG_V8)               \
        "xor    " CC_D1 ", " CC_D1 ", " CC_A2 "\n\t"    \
        VSLL_VI(REG_V20, REG_V3, s)                     \
        "xor    " CC_D2 ", " CC_D2 ", " CC_A3 "\n\t"    \
        VSLL_VI(REG_V21, REG_V7, s)                     \
        "slli   " CC_T0 ", " CC_D3 ", " #s "\n\t"       \
        VSLL_VI(REG_V22, REG_V11, s)                    \
        "slli   " CC_T1 ", " CC_D0 ", " #s "\n\t"       \
        VSRL_VI(REG_V3, REG_V3, sr)                     \
        "slli   " CC_T2 ", " CC_D1 ", " #s "\n\t"       \
        VSRL_VI(REG_V7, REG_V7, sr)                     \
        "slli   " CC_T3 ", " CC_D2 ", " #s "\n\t"       \
        VSRL_VI(REG_V11, REG_V11, sr)                   \
        "srliw  " CC_D3 ", " CC_D3 ", " #sr "\n\t"      \
        VOR_VV(REG_V3, REG_V3, REG_V20)                 \
        "srliw  " CC_D0 ", " CC_D0 ", " #sr "\n\t"      \
        VOR_VV(REG_V7, REG_V7, REG_V21)                 \
        "srliw  " CC_D1 ", " CC_D1 ", " #sr "\n\t"      \
        VOR_VV(REG_V11, REG_V11, REG_V22)               \
        "srliw  " CC_D2 ", " CC_D2 ", " #sr "\n\t"      \
        "or     " CC_D3 ", " CC_D3 ", " CC_T0 "\n\t"    \
        "or     " CC_D0 ", " CC_D0 ", " CC_T1 "\n\t"    \
        "or     " CC_D1 ", " CC_D1 ", " CC_T2 "\n\t"    \
        "or     " CC_D2 ", " CC_D2 ", " CC_T3 "\n\t"

#define PART_ROUND_EVEN_CDB(s, sr)                      \
        "add    " CC_C2 ", " CC_C2 ", " CC_D3 "\n\t"    \
        VADD_VV(REG_V2, REG_V2, REG_V3)                 \
        "add    " CC_C3 ", " CC_C3 ", " CC_D0 "\n\t"    \
        VADD_VV(REG_V6, REG_V6, REG_V7)                 \
        "add    " CC_C0 ", " CC_C0 ", " CC_D1 "\n\t"    \
        VADD_VV(REG_V10, REG_V10, REG_V11)              \
        "add    " CC_C1 ", " CC_C1 ", " CC_D2 "\n\t"    \
        VXOR_VV(REG_V1, REG_V1, REG_V2)                 \
        "xor    " CC_B1 ", " CC_B1 ", " CC_C2 "\n\t"    \
        VXOR_VV(REG_V5, REG_V5, REG_V6)                 \
        "xor    " CC_B2 ", " CC_B2 ", " CC_C3 "\n\t"    \
        VXOR_VV(REG_V9, REG_V9, REG_V10)                \
        "xor    " CC_B3 ", " CC_B3 ", " CC_C0 "\n\t"    \
        VSLL_VI(REG_V20, REG_V1, s)                     \
        "xor    " CC_B0 ", " CC_B0 ", " CC_C1 "\n\t"    \
        VSLL_VI(REG_V21, REG_V5, s)                     \
        "slli   " CC_T0 ", " CC_B1 ", " #s "\n\t"       \
        VSLL_VI(REG_V22, REG_V9, s)                     \
        "slli   " CC_T1 ", " CC_B2 ", " #s "\n\t"       \
        VSRL_VI(REG_V1, REG_V1, sr)                     \
        "slli   " CC_T2 ", " CC_B3 ", " #s "\n\t"       \
        VSRL_VI(REG_V5, REG_V5, sr)                     \
        "slli   " CC_T3 ", " CC_B0 ", " #s "\n\t"       \
        VSRL_VI(REG_V9, REG_V9, sr)                     \
        "srliw  " CC_B1 ", " CC_B1 ", " #sr "\n\t"      \
        VOR_VV(REG_V1, REG_V1, REG_V20)                 \
        "srliw  " CC_B2 ", " CC_B2 ", " #sr "\n\t"      \
        VOR_VV(REG_V5, REG_V5, REG_V21)                 \
        "srliw  " CC_B3 ", " CC_B3 ", " #sr "\n\t"      \
        VOR_VV(REG_V9, REG_V9, REG_V22)                 \
        "srliw  " CC_B0 ", " CC_B0 ", " #sr "\n\t"      \
        "or     " CC_B1 ", " CC_B1 ", " CC_T0 "\n\t"    \
        "or     " CC_B2 ", " CC_B2 ", " CC_T1 "\n\t"    \
        "or     " CC_B3 ", " CC_B3 ", " CC_T2 "\n\t"    \
        "or     " CC_B0 ", " CC_B0 ", " CC_T3 "\n\t"

#elif !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION )

#define PART_ROUND_ODD_ABD(s, sr)                       \
        "add    " CC_A0 ", " CC_A0 ", " CC_B0 "\n\t"    \
        VADD_VV(REG_V0, REG_V0, REG_V1)                 \
        "add    " CC_A1 ", " CC_A1 ", " CC_B1 "\n\t"    \
        VADD_VV(REG_V4, REG_V4, REG_V5)                 \
        "add    " CC_A2 ", " CC_A2 ", " CC_B2 "\n\t"    \
        VADD_VV(REG_V8, REG_V8, REG_V9)                 \
        "add    " CC_A3 ", " CC_A3 ", " CC_B3 "\n\t"    \
        VXOR_VV(REG_V3, REG_V3, REG_V0)                 \
        "xor    " CC_D0 ", " CC_D0 ", " CC_A0 "\n\t"    \
        VXOR_VV(REG_V7, REG_V7, REG_V4)                 \
        "xor    " CC_D1 ", " CC_D1 ", " CC_A1 "\n\t"    \
        VXOR_VV(REG_V11, REG_V11, REG_V8)               \
        "xor    " CC_D2 ", " CC_D2 ", " CC_A2 "\n\t"    \
        VROR_VI(REG_V3, sr, REG_V3)                     \
        "xor    " CC_D3 ", " CC_D3 ", " CC_A3 "\n\t"    \
        VROR_VI(REG_V7, sr, REG_V7)                     \
        "slli   " CC_T0 ", " CC_D0 ", " #s "\n\t"       \
        VROR_VI(REG_V11, sr, REG_V11)                   \
        "slli   " CC_T1 ", " CC_D1 ", " #s "\n\t"       \
        "slli   " CC_T2 ", " CC_D2 ", " #s "\n\t"       \
        "slli   " CC_T3 ", " CC_D3 ", " #s "\n\t"       \
        "srliw  " CC_D0 ", " CC_D0 ", " #sr "\n\t"      \
        "srliw  " CC_D1 ", " CC_D1 ", " #sr "\n\t"      \
        "srliw  " CC_D2 ", " CC_D2 ", " #sr "\n\t"      \
        "srliw  " CC_D3 ", " CC_D3 ", " #sr "\n\t"      \
        "or     " CC_D0 ", " CC_D0 ", " CC_T0 "\n\t"    \
        "or     " CC_D1 ", " CC_D1 ", " CC_T1 "\n\t"    \
        "or     " CC_D2 ", " CC_D2 ", " CC_T2 "\n\t"    \
        "or     " CC_D3 ", " CC_D3 ", " CC_T3 "\n\t"

#define PART_ROUND_ODD_CDB(s, sr)                       \
        "add    " CC_C0 ", " CC_C0 ", " CC_D0 "\n\t"    \
        VADD_VV(REG_V2, REG_V2, REG_V3)                 \
        "add    " CC_C1 ", " CC_C1 ", " CC_D1 "\n\t"    \
        VADD_VV(REG_V6, REG_V6, REG_V7)                 \
        "add    " CC_C2 ", " CC_C2 ", " CC_D2 "\n\t"    \
        VADD_VV(REG_V10, REG_V10, REG_V11)              \
        "add    " CC_C3 ", " CC_C3 ", " CC_D3 "\n\t"    \
        VXOR_VV(REG_V1, REG_V1, REG_V2)                 \
        "xor    " CC_B0 ", " CC_B0 ", " CC_C0 "\n\t"    \
        VXOR_VV(REG_V5, REG_V5, REG_V6)                 \
        "xor    " CC_B1 ", " CC_B1 ", " CC_C1 "\n\t"    \
        VXOR_VV(REG_V9, REG_V9, REG_V10)                \
        "xor    " CC_B2 ", " CC_B2 ", " CC_C2 "\n\t"    \
        VROR_VI(REG_V1, sr, REG_V1)                     \
        "xor    " CC_B3 ", " CC_B3 ", " CC_C3 "\n\t"    \
        VROR_VI(REG_V5, sr, REG_V5)                     \
        "slli   " CC_T0 ", " CC_B0 ", " #s "\n\t"       \
        VROR_VI(REG_V9, sr, REG_V9)                     \
        "slli   " CC_T1 ", " CC_B1 ", " #s "\n\t"       \
        "slli   " CC_T2 ", " CC_B2 ", " #s "\n\t"       \
        "slli   " CC_T3 ", " CC_B3 ", " #s "\n\t"       \
        "srliw  " CC_B0 ", " CC_B0 ", " #sr "\n\t"      \
        "srliw  " CC_B1 ", " CC_B1 ", " #sr "\n\t"      \
        "srliw  " CC_B2 ", " CC_B2 ", " #sr "\n\t"      \
        "srliw  " CC_B3 ", " CC_B3 ", " #sr "\n\t"      \
        "or     " CC_B0 ", " CC_B0 ", " CC_T0 "\n\t"    \
        "or     " CC_B1 ", " CC_B1 ", " CC_T1 "\n\t"    \
        "or     " CC_B2 ", " CC_B2 ", " CC_T2 "\n\t"    \
        "or     " CC_B3 ", " CC_B3 ", " CC_T3 "\n\t"

#define PART_ROUND_EVEN_ABD(s, sr)                      \
        "add    " CC_A0 ", " CC_A0 ", " CC_B1 "\n\t"    \
        VADD_VV(REG_V0, REG_V0, REG_V1)                 \
        "add    " CC_A1 ", " CC_A1 ", " CC_B2 "\n\t"    \
        VADD_VV(REG_V4, REG_V4, REG_V5)                 \
        "add    " CC_A2 ", " CC_A2 ", " CC_B3 "\n\t"    \
        VADD_VV(REG_V8, REG_V8, REG_V9)                 \
        "add    " CC_A3 ", " CC_A3 ", " CC_B0 "\n\t"    \
        VXOR_VV(REG_V3, REG_V3, REG_V0)                 \
        "xor    " CC_D3 ", " CC_D3 ", " CC_A0 "\n\t"    \
        VXOR_VV(REG_V7, REG_V7, REG_V4)                 \
        "xor    " CC_D0 ", " CC_D0 ", " CC_A1 "\n\t"    \
        VXOR_VV(REG_V11, REG_V11, REG_V8)               \
        "xor    " CC_D1 ", " CC_D1 ", " CC_A2 "\n\t"    \
        VROR_VI(REG_V3, sr, REG_V3)                     \
        "xor    " CC_D2 ", " CC_D2 ", " CC_A3 "\n\t"    \
        VROR_VI(REG_V7, sr, REG_V7)                     \
        "slli   " CC_T0 ", " CC_D3 ", " #s "\n\t"       \
        VROR_VI(REG_V11, sr, REG_V11)                   \
        "slli   " CC_T1 ", " CC_D0 ", " #s "\n\t"       \
        "slli   " CC_T2 ", " CC_D1 ", " #s "\n\t"       \
        "slli   " CC_T3 ", " CC_D2 ", " #s "\n\t"       \
        "srliw  " CC_D3 ", " CC_D3 ", " #sr "\n\t"      \
        "srliw  " CC_D0 ", " CC_D0 ", " #sr "\n\t"      \
        "srliw  " CC_D1 ", " CC_D1 ", " #sr "\n\t"      \
        "srliw  " CC_D2 ", " CC_D2 ", " #sr "\n\t"      \
        "or     " CC_D3 ", " CC_D3 ", " CC_T0 "\n\t"    \
        "or     " CC_D0 ", " CC_D0 ", " CC_T1 "\n\t"    \
        "or     " CC_D1 ", " CC_D1 ", " CC_T2 "\n\t"    \
        "or     " CC_D2 ", " CC_D2 ", " CC_T3 "\n\t"

#define PART_ROUND_EVEN_CDB(s, sr)                      \
        "add    " CC_C2 ", " CC_C2 ", " CC_D3 "\n\t"    \
        VADD_VV(REG_V2, REG_V2, REG_V3)                 \
        "add    " CC_C3 ", " CC_C3 ", " CC_D0 "\n\t"    \
        VADD_VV(REG_V6, REG_V6, REG_V7)                 \
        "add    " CC_C0 ", " CC_C0 ", " CC_D1 "\n\t"    \
        VADD_VV(REG_V10, REG_V10, REG_V11)              \
        "add    " CC_C1 ", " CC_C1 ", " CC_D2 "\n\t"    \
        VXOR_VV(REG_V1, REG_V1, REG_V2)                 \
        "xor    " CC_B1 ", " CC_B1 ", " CC_C2 "\n\t"    \
        VXOR_VV(REG_V5, REG_V5, REG_V6)                 \
        "xor    " CC_B2 ", " CC_B2 ", " CC_C3 "\n\t"    \
        VXOR_VV(REG_V9, REG_V9, REG_V10)                \
        "xor    " CC_B3 ", " CC_B3 ", " CC_C0 "\n\t"    \
        VROR_VI(REG_V1, sr, REG_V1)                     \
        "xor    " CC_B0 ", " CC_B0 ", " CC_C1 "\n\t"    \
        VROR_VI(REG_V5, sr, REG_V5)                     \
        "slli   " CC_T0 ", " CC_B1 ", " #s "\n\t"       \
        VROR_VI(REG_V9, sr, REG_V9)                     \
        "slli   " CC_T1 ", " CC_B2 ", " #s "\n\t"       \
        "slli   " CC_T2 ", " CC_B3 ", " #s "\n\t"       \
        "slli   " CC_T3 ", " CC_B0 ", " #s "\n\t"       \
        "srliw  " CC_B1 ", " CC_B1 ", " #sr "\n\t"      \
        "srliw  " CC_B2 ", " CC_B2 ", " #sr "\n\t"      \
        "srliw  " CC_B3 ", " CC_B3 ", " #sr "\n\t"      \
        "srliw  " CC_B0 ", " CC_B0 ", " #sr "\n\t"      \
        "or     " CC_B1 ", " CC_B1 ", " CC_T0 "\n\t"    \
        "or     " CC_B2 ", " CC_B2 ", " CC_T1 "\n\t"    \
        "or     " CC_B3 ", " CC_B3 ", " CC_T2 "\n\t"    \
        "or     " CC_B0 ", " CC_B0 ", " CC_T3 "\n\t"

#else

#define PART_ROUND_ODD_ABD(s, sr)                       \
        "add    " CC_A0 ", " CC_A0 ", " CC_B0 "\n\t"    \
        VADD_VV(REG_V0, REG_V0, REG_V1)                 \
        "add    " CC_A1 ", " CC_A1 ", " CC_B1 "\n\t"    \
        VADD_VV(REG_V4, REG_V4, REG_V5)                 \
        "add    " CC_A2 ", " CC_A2 ", " CC_B2 "\n\t"    \
        VADD_VV(REG_V8, REG_V8, REG_V9)                 \
        "add    " CC_A3 ", " CC_A3 ", " CC_B3 "\n\t"    \
        VXOR_VV(REG_V3, REG_V3, REG_V0)                 \
        "xor    " CC_D0 ", " CC_D0 ", " CC_A0 "\n\t"    \
        VXOR_VV(REG_V7, REG_V7, REG_V4)                 \
        "xor    " CC_D1 ", " CC_D1 ", " CC_A1 "\n\t"    \
        VXOR_VV(REG_V11, REG_V11, REG_V8)               \
        "xor    " CC_D2 ", " CC_D2 ", " CC_A2 "\n\t"    \
        VROR_VI(REG_V3, sr, REG_V3)                     \
        "xor    " CC_D3 ", " CC_D3 ", " CC_A3 "\n\t"    \
        VROR_VI(REG_V7, sr, REG_V7)                     \
        RORIW(REG_S6, REG_S6, sr)                       \
        VROR_VI(REG_V11, sr, REG_V11)                   \
        RORIW(REG_S7, REG_S7, sr)                       \
        RORIW(REG_S8, REG_S8, sr)                       \
        RORIW(REG_S9, REG_S9, sr)

#define PART_ROUND_ODD_CDB(s, sr)                       \
        "add    " CC_C0 ", " CC_C0 ", " CC_D0 "\n\t"    \
        VADD_VV(REG_V2, REG_V2, REG_V3)                 \
        "add    " CC_C1 ", " CC_C1 ", " CC_D1 "\n\t"    \
        VADD_VV(REG_V6, REG_V6, REG_V7)                 \
        "add    " CC_C2 ", " CC_C2 ", " CC_D2 "\n\t"    \
        VADD_VV(REG_V10, REG_V10, REG_V11)              \
        "add    " CC_C3 ", " CC_C3 ", " CC_D3 "\n\t"    \
        VXOR_VV(REG_V1, REG_V1, REG_V2)                 \
        "xor    " CC_B0 ", " CC_B0 ", " CC_C0 "\n\t"    \
        VXOR_VV(REG_V5, REG_V5, REG_V6)                 \
        "xor    " CC_B1 ", " CC_B1 ", " CC_C1 "\n\t"    \
        VXOR_VV(REG_V9, REG_V9, REG_V10)                \
        "xor    " CC_B2 ", " CC_B2 ", " CC_C2 "\n\t"    \
        VROR_VI(REG_V1, sr, REG_V1)                     \
        "xor    " CC_B3 ", " CC_B3 ", " CC_C3 "\n\t"    \
        VROR_VI(REG_V5, sr, REG_V5)                     \
        RORIW(REG_T3, REG_T3, sr)                       \
        VROR_VI(REG_V9, sr, REG_V9)                     \
        RORIW(REG_T4, REG_T4, sr)                       \
        RORIW(REG_T5, REG_T5, sr)                       \
        RORIW(REG_T6, REG_T6, sr)

#define PART_ROUND_EVEN_ABD(s, sr)                      \
        "add    " CC_A0 ", " CC_A0 ", " CC_B1 "\n\t"    \
        VADD_VV(REG_V0, REG_V0, REG_V1)                 \
        "add    " CC_A1 ", " CC_A1 ", " CC_B2 "\n\t"    \
        VADD_VV(REG_V4, REG_V4, REG_V5)                 \
        "add    " CC_A2 ", " CC_A2 ", " CC_B3 "\n\t"    \
        VADD_VV(REG_V8, REG_V8, REG_V9)                 \
        "add    " CC_A3 ", " CC_A3 ", " CC_B0 "\n\t"    \
        VXOR_VV(REG_V3, REG_V3, REG_V0)                 \
        "xor    " CC_D3 ", " CC_D3 ", " CC_A0 "\n\t"    \
        VXOR_VV(REG_V7, REG_V7, REG_V4)                 \
        "xor    " CC_D0 ", " CC_D0 ", " CC_A1 "\n\t"    \
        VXOR_VV(REG_V11, REG_V11, REG_V8)               \
        "xor    " CC_D1 ", " CC_D1 ", " CC_A2 "\n\t"    \
        VROR_VI(REG_V3, sr, REG_V3)                     \
        "xor    " CC_D2 ", " CC_D2 ", " CC_A3 "\n\t"    \
        VROR_VI(REG_V7, sr, REG_V7)                     \
        RORIW(REG_S9, REG_S9, sr)                       \
        VROR_VI(REG_V11, sr, REG_V11)                   \
        RORIW(REG_S6, REG_S6, sr)                       \
        RORIW(REG_S7, REG_S7, sr)                       \
        RORIW(REG_S8, REG_S8, sr)

#define PART_ROUND_EVEN_CDB(s, sr)                      \
        "add    " CC_C2 ", " CC_C2 ", " CC_D3 "\n\t"    \
        VADD_VV(REG_V2, REG_V2, REG_V3)                 \
        "add    " CC_C3 ", " CC_C3 ", " CC_D0 "\n\t"    \
        VADD_VV(REG_V6, REG_V6, REG_V7)                 \
        "add    " CC_C0 ", " CC_C0 ", " CC_D1 "\n\t"    \
        VADD_VV(REG_V10, REG_V10, REG_V11)              \
        "add    " CC_C1 ", " CC_C1 ", " CC_D2 "\n\t"    \
        VXOR_VV(REG_V1, REG_V1, REG_V2)                 \
        "xor    " CC_B1 ", " CC_B1 ", " CC_C2 "\n\t"    \
        VXOR_VV(REG_V5, REG_V5, REG_V6)                 \
        "xor    " CC_B2 ", " CC_B2 ", " CC_C3 "\n\t"    \
        VXOR_VV(REG_V9, REG_V9, REG_V10)                \
        "xor    " CC_B3 ", " CC_B3 ", " CC_C0 "\n\t"    \
        VROR_VI(REG_V1, sr, REG_V1)                     \
        "xor    " CC_B0 ", " CC_B0 ", " CC_C1 "\n\t"    \
        VROR_VI(REG_V5, sr, REG_V5)                     \
        "slli   " CC_T0 ", " CC_B1 ", " #s "\n\t"       \
        RORIW(REG_T4, REG_T4, sr)                       \
        VROR_VI(REG_V9, sr, REG_V9)                     \
        RORIW(REG_T5, REG_T5, sr)                       \
        RORIW(REG_T6, REG_T6, sr)                       \
        RORIW(REG_T3, REG_T3, sr)

#endif

#define QUARTER_ROUND_ODD_4()               \
        /* a += b; d ^= a; d <<<= 16; */    \
        PART_ROUND_ODD_ABD(16, 16)          \
        /* c += d; b ^= c; b <<<= 12; */    \
        PART_ROUND_ODD_CDB(12, 20)          \
        /* a += b; d ^= a; d <<<= 8; */     \
        PART_ROUND_ODD_ABD( 8, 24)          \
        /* c += d; b ^= c; b <<<= 7; */     \
        PART_ROUND_ODD_CDB( 7, 25)

#define QUARTER_ROUND_EVEN_4()              \
        /* a += b; d ^= a; d <<<= 16; */    \
        PART_ROUND_EVEN_ABD(16, 16)         \
        /* c += d; b ^= c; b <<<= 12; */    \
        PART_ROUND_EVEN_CDB(12, 20)         \
        /* a += b; d ^= a; d <<<= 8; */     \
        PART_ROUND_EVEN_ABD( 8, 24)         \
        /* c += d; b ^= c; b <<<= 7; */     \
        PART_ROUND_EVEN_CDB( 7, 25)

#define SHUFFLE_4(r, t, i)                  \
        VRGATHER_VV(t + 0, i, r + 0)        \
        VRGATHER_VV(t + 1, i, r + 4)        \
        VRGATHER_VV(t + 2, i, r + 8)        \
        VMV_V_V(r + 0, t + 0)               \
        VMV_V_V(r + 4, t + 1)               \
        VMV_V_V(r + 8, t + 2)

#define ODD_SHUFFLE_4()                                                 \
        /*    a=0,1,2,3; b=4,5,6,7; c=8,9,10,11; d=12,13,14,15          \
         * => a=0,1,2,3; b=5,6,7,4; c=10,11,8,9; d=15,12,13,14 */       \
        SHUFFLE_4(REG_V3, REG_V20, REG_V25)                             \
        SHUFFLE_4(REG_V1, REG_V20, REG_V23)                             \
        SHUFFLE_4(REG_V2, REG_V20, REG_V24)

#define EVEN_SHUFFLE_4()                                                \
        /*    a=0,1,2,3; b=5,6,7,4; c=10,11,8,9; d=15,12,13,14          \
         * => a=0,1,2,3; b=4,5,6,7; c=8,9,10,11; d=12,13,14,15 */       \
        SHUFFLE_4(REG_V3, REG_V20, REG_V23)                             \
        SHUFFLE_4(REG_V1, REG_V20, REG_V25)                             \
        SHUFFLE_4(REG_V2, REG_V20, REG_V24)

/**
  * Converts word into bytes with rotations having been done.
  */
static WC_INLINE int wc_chacha_encrypt_256(const word32* input, const byte* m,
    byte* c)
{
    __asm__ __volatile__ (
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
        /* The layout of used vector registers is:
         * v0-v3 - first block
         * v4-v7 - second block
         * v8-v11 - third block
         * v12-v15 - message
         * v16-v19 - input
         * v20-v22 - temp
         * v23-v25 - indices for rotating words in vector
         *
         * v0  0  1  2  3
         * v1  4  5  6  7
         * v2  8  9 10 11
         * v3 12 13 14 15
         * load CHACHA state with indices placed as shown above
         */

        /* Load state to encrypt */
        "mv     t2, %[input]\n\t"
        VL4RE32_V(REG_V16, REG_T2)
        VID_V(REG_V20)
        VSLIDEDOWN_VI(REG_V23, REG_V20, 1)
        VSLIDEUP_VI(REG_V23, REG_V20, 3)
        VSLIDEDOWN_VI(REG_V24, REG_V20, 2)
        VSLIDEUP_VI(REG_V24, REG_V20, 2)
        VSLIDEDOWN_VI(REG_V25, REG_V20, 3)
        VSLIDEUP_VI(REG_V25, REG_V20, 1)
        /* Move state into regular registers */
        "ld     a4,  0(%[input])\n\t"
        "ld     a6,  8(%[input])\n\t"
        "ld     t3, 16(%[input])\n\t"
        "ld     t5, 24(%[input])\n\t"
        "ld     s2, 32(%[input])\n\t"
        "ld     s4, 40(%[input])\n\t"
        "ld     s6, 48(%[input])\n\t"
        "ld     s8, 56(%[input])\n\t"
        "srli   a5, a4, 32\n\t"
        "srli   a7, a6, 32\n\t"
        "srli   t4, t3, 32\n\t"
        "srli   t6, t5, 32\n\t"
        "srli   s3, s2, 32\n\t"
        "srli   s5, s4, 32\n\t"
        "srli   s7, s6, 32\n\t"
        "srli   s9, s8, 32\n\t"
        /* Move state into vector registers */
        VMVR_V(REG_V0, REG_V16, 4)
        "addi   t0, s6, 1\n\t"
        VMVR_V(REG_V4, REG_V16, 4)
        "addi   t1, s6, 2\n\t"
        VMVR_V(REG_V8, REG_V16, 4)
        "addi   s6, s6, 3\n\t"
        /* Set counter word */
        VMV_S_X(REG_V7, REG_T0)
        VMV_S_X(REG_V11, REG_T1)
        /* Set number of odd+even rounds to perform */
        "li     a3, 10\n\t"
        "\n"
    "L_chacha20_riscv_256_loop:\n\t"
        /* Odd Round */
        QUARTER_ROUND_ODD_4()
        ODD_SHUFFLE_4()
        "addi   a3, a3, -1\n\t"
        /* Even Round */
        QUARTER_ROUND_EVEN_4()
        EVEN_SHUFFLE_4()
        "bnez   a3, L_chacha20_riscv_256_loop\n\t"
        /* Load message */
        "mv     t2, %[m]\n\t"
        VL4RE32_V(REG_V12, REG_T2)
        "addi   %[m], %[m], 64\n\t"
        /* Add back state, XOR in message and store (load next block) */
        /* BLOCK 1 */
        VADD_VV(REG_V0, REG_V0, REG_V16)
        VADD_VV(REG_V1, REG_V1, REG_V17)
        VADD_VV(REG_V2, REG_V2, REG_V18)
        VADD_VV(REG_V3, REG_V3, REG_V19)
        VXOR_VV(REG_V0, REG_V0, REG_V12)
        VXOR_VV(REG_V1, REG_V1, REG_V13)
        VXOR_VV(REG_V2, REG_V2, REG_V14)
        VXOR_VV(REG_V3, REG_V3, REG_V15)
        "mv     t2, %[m]\n\t"
        VL4RE32_V(REG_V12, REG_T2)
        "addi   %[m], %[m], 64\n\t"
        VMV_X_S(REG_T0, REG_V19)
        "mv     t2, %[c]\n\t"
        VS4R_V(REG_V0, REG_T2)
        "addi   %[c], %[c], 64\n\t"
        /* BLOCK 2 */
        "addi   t0, t0, 1\n\t"
        VMV_S_X(REG_V19, REG_T0)
        VADD_VV(REG_V4, REG_V4, REG_V16)
        VADD_VV(REG_V5, REG_V5, REG_V17)
        VADD_VV(REG_V6, REG_V6, REG_V18)
        VADD_VV(REG_V7, REG_V7, REG_V19)
        VXOR_VV(REG_V4, REG_V4, REG_V12)
        VXOR_VV(REG_V5, REG_V5, REG_V13)
        VXOR_VV(REG_V6, REG_V6, REG_V14)
        VXOR_VV(REG_V7, REG_V7, REG_V15)
        "mv     t2, %[m]\n\t"
        VL4RE32_V(REG_V12, REG_T2)
        "addi   %[m], %[m], 64\n\t"
        "mv     t2, %[c]\n\t"
        VS4R_V(REG_V4, REG_T2)
        "addi   %[c], %[c], 64\n\t"
        /* BLOCK 3 */
        "addi   t0, t0, 1\n\t"
        VMV_S_X(REG_V19, REG_T0)
        VADD_VV(REG_V8, REG_V8, REG_V16)
        VADD_VV(REG_V9, REG_V9, REG_V17)
        VADD_VV(REG_V10, REG_V10, REG_V18)
        VADD_VV(REG_V11, REG_V11, REG_V19)
        VXOR_VV(REG_V8, REG_V8, REG_V12)
        VXOR_VV(REG_V9, REG_V9, REG_V13)
        VXOR_VV(REG_V10, REG_V10, REG_V14)
        VXOR_VV(REG_V11, REG_V11, REG_V15)
        "mv     t2, %[m]\n\t"
        VL4RE32_V(REG_V12, REG_T2)
        "mv     t2, %[c]\n\t"
        VS4R_V(REG_V8, REG_T2)
        "addi   %[c], %[c], 64\n\t"
        /* BLOCK 4 */
        /* Move regular registers into vector registers for adding and xor */
        "addi   t0, t0, 1\n\t"
        VMV_S_X(REG_V0, REG_A4)
        VMV_S_X(REG_V1, REG_T3)
        VMV_S_X(REG_V2, REG_S2)
        VMV_S_X(REG_V3, REG_S6)
        VMV_S_X(REG_V4, REG_A5)
        VMV_S_X(REG_V5, REG_T4)
        VMV_S_X(REG_V6, REG_S3)
        VMV_S_X(REG_V7, REG_S7)
        VSLIDEUP_VI(REG_V0, REG_V4, 1)
        VSLIDEUP_VI(REG_V1, REG_V5, 1)
        VSLIDEUP_VI(REG_V2, REG_V6, 1)
        VSLIDEUP_VI(REG_V3, REG_V7, 1)
        VMV_S_X(REG_V4, REG_A6)
        VMV_S_X(REG_V5, REG_T5)
        VMV_S_X(REG_V6, REG_S4)
        VMV_S_X(REG_V7, REG_S8)
        VSLIDEUP_VI(REG_V0, REG_V4, 2)
        VSLIDEUP_VI(REG_V1, REG_V5, 2)
        VSLIDEUP_VI(REG_V2, REG_V6, 2)
        VSLIDEUP_VI(REG_V3, REG_V7, 2)
        VMV_S_X(REG_V4, REG_A7)
        VMV_S_X(REG_V5, REG_T6)
        VMV_S_X(REG_V6, REG_S5)
        VMV_S_X(REG_V7, REG_S9)
        VSLIDEUP_VI(REG_V0, REG_V4, 3)
        VSLIDEUP_VI(REG_V1, REG_V5, 3)
        VSLIDEUP_VI(REG_V2, REG_V6, 3)
        VSLIDEUP_VI(REG_V3, REG_V7, 3)
        VMV_S_X(REG_V19, REG_T0)
        /* Add back state, XOR in message and store */
        VADD_VV(REG_V0, REG_V0, REG_V16)
        VADD_VV(REG_V1, REG_V1, REG_V17)
        VADD_VV(REG_V2, REG_V2, REG_V18)
        VADD_VV(REG_V3, REG_V3, REG_V19)
        VXOR_VV(REG_V0, REG_V0, REG_V12)
        VXOR_VV(REG_V1, REG_V1, REG_V13)
        VXOR_VV(REG_V2, REG_V2, REG_V14)
        VXOR_VV(REG_V3, REG_V3, REG_V15)
        "mv     t2, %[c]\n\t"
        VS4R_V(REG_V0, REG_T2)
        : [m] "+r" (m), [c] "+r" (c)
        : [input] "r" (input)
        : "memory", "t0", "t1", "t2", "s1", "a3",
          "t3", "t4", "t5", "t6",
          "a4", "a5", "a6", "a7",
          "s2", "s3", "s4", "s5",
          "s6", "s7", "s8", "s9"
    );
    return CHACHA_CHUNK_BYTES * 4;
}

#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION

#define PART_ROUND_2(a, b, d, t, a2, b2, d2, t2, sl, sr)    \
        VADD_VV(a, a, b)                                    \
        VADD_VV(a2, a2, b2)                                 \
        VXOR_VV(d, d, a)                                    \
        VXOR_VV(d2, d2, a2)                                 \
        VSLL_VI(t, d, sl)                                   \
        VSLL_VI(t2, d2, sl)                                 \
        VSRL_VI(d, d, sr)                                   \
        VSRL_VI(d2, d2, sr)                                 \
        VOR_VV(d, d, t)                                     \
        VOR_VV(d2, d2, t2)

#else

#define PART_ROUND_2(a, b, d, t, a2, b2, d2, t2, sl, sr)    \
        VADD_VV(a, a, b)                                    \
        VADD_VV(a2, a2, b2)                                 \
        VXOR_VV(d, d, a)                                    \
        VXOR_VV(d2, d2, a2)                                 \
        VROR_VI(d, sr, d)                                   \
        VROR_VI(d2, sr, d2)

#endif

#define QUARTER_ROUND_2(a, b, c, d, t, a2, b2, c2, d2, t2)  \
        /* a += b; d ^= a; d <<<= 16; */                    \
        PART_ROUND_2(a, b, d, t, a2, b2, d2, t2, 16, 16)    \
        /* c += d; b ^= c; b <<<= 12; */                    \
        PART_ROUND_2(c, d, b, t, c2, d2, b2, t2, 12, 20)    \
        /* a += b; d ^= a; d <<<= 8; */     \
        PART_ROUND_2(a, b, d, t, a2, b2, d2, t2,  8, 24)    \
        /* c += d; b ^= c; b <<<= 7; */     \
        PART_ROUND_2(c, d, b, t, c2, d2, b2, t2,  7, 25)

#define ODD_SHUFFLE_2(b, c, d, t, b2, c2, d2, t2)                       \
        /*    a=0,1,2,3; b=4,5,6,7; c=8,9,10,11; d=12,13,14,15          \
         * => a=0,1,2,3; b=5,6,7,4; c=10,11,8,9; d=15,12,13,14 */       \
        VRGATHER_VV(t, REG_V25, d)                                      \
        VRGATHER_VV(t2, REG_V25, d2)                                    \
        VMV_V_V(d, t)                                                   \
        VMV_V_V(d2, t2)                                                 \
        VRGATHER_VV(t, REG_V23, b)                                      \
        VRGATHER_VV(t2, REG_V23, b2)                                    \
        VMV_V_V(b, t)                                                   \
        VMV_V_V(b2, t2)                                                 \
        VRGATHER_VV(t, REG_V24, c)                                      \
        VRGATHER_VV(t2, REG_V24, c2)                                    \
        VMV_V_V(c, t)                                                   \
        VMV_V_V(c2, t2)

#define EVEN_SHUFFLE_2(b, c, d, t, b2, c2, d2, t2)                      \
        /*    a=0,1,2,3; b=5,6,7,4; c=10,11,8,9; d=15,12,13,14          \
         * => a=0,1,2,3; b=4,5,6,7; c=8,9,10,11; d=12,13,14,15 */       \
        VRGATHER_VV(t, REG_V23, d)                                      \
        VRGATHER_VV(t2, REG_V23, d2)                                    \
        VMV_V_V(d, t)                                                   \
        VMV_V_V(d2, t2)                                                 \
        VRGATHER_VV(t, REG_V25, b)                                      \
        VRGATHER_VV(t2, REG_V25, b2)                                    \
        VMV_V_V(b, t)                                                   \
        VMV_V_V(b2, t2)                                                 \
        VRGATHER_VV(t, REG_V24, c)                                      \
        VRGATHER_VV(t2, REG_V24, c2)                                    \
        VMV_V_V(c, t)                                                   \
        VMV_V_V(c2, t2)


static WC_INLINE int wc_chacha_encrypt_128(const word32* input, const byte* m,
     byte* c)
{
    __asm__ __volatile__ (
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
        /* The layout of used vector registers is:
         * v0-v3 - first block
         * v4-v7 - second block
         * v12-v15 - message
         * v16-v19 - input
         * v20-v22 - temp
         * v23-v25 - indices for rotating words in vector
         *
         * v0  0  1  2  3
         * v1  4  5  6  7
         * v2  8  9 10 11
         * v3 12 13 14 15
         * load CHACHA state with indices placed as shown above
         */

        /* Load incrementer register to modify counter */
        "mv     t2, %[L_chacha20_vec_inc_first_word]\n\t"
        VL1RE32_V(REG_V22, REG_T2)
        VID_V(REG_V20)
        VSLIDEDOWN_VI(REG_V23, REG_V20, 1)
        VSLIDEUP_VI(REG_V23, REG_V20, 3)
        VSLIDEDOWN_VI(REG_V24, REG_V20, 2)
        VSLIDEUP_VI(REG_V24, REG_V20, 2)
        VSLIDEDOWN_VI(REG_V25, REG_V20, 3)
        VSLIDEUP_VI(REG_V25, REG_V20, 1)
        /* Load state to encrypt */
        "mv     t2, %[input]\n\t"
        VL4RE32_V(REG_V16, REG_T2)
        /* Load message */
        "mv     t2, %[m]\n\t"
        VL4RE32_V(REG_V12, REG_T2)
        "addi   %[m], %[m], 64\n\t"
        /* Move state into vector registers */
        VMVR_V(REG_V0, REG_V16, 4)
        VMVR_V(REG_V4, REG_V16, 4)
        /* Add counter word */
        VADD_VV(REG_V7, REG_V7, REG_V22)
        /* Set number of odd+even rounds to perform */
        "li     t0, 10\n\t"
        "\n"
    "L_chacha20_riscv_128_loop:\n\t"
        QUARTER_ROUND_2(REG_V0, REG_V1, REG_V2, REG_V3, REG_V20,
                        REG_V4, REG_V5, REG_V6, REG_V7, REG_V21)
        ODD_SHUFFLE_2(REG_V1, REG_V2, REG_V3, REG_V20,
                      REG_V5, REG_V6, REG_V7, REG_V21)
        QUARTER_ROUND_2(REG_V0, REG_V1, REG_V2, REG_V3, REG_V20,
                        REG_V4, REG_V5, REG_V6, REG_V7, REG_V21)
        EVEN_SHUFFLE_2(REG_V1, REG_V2, REG_V3, REG_V20,
                       REG_V5, REG_V6, REG_V7, REG_V21)
        "addi   t0, t0, -1\n\t"
        "bnez   t0, L_chacha20_riscv_128_loop\n\t"
        /* Add back state, XOR in message and store (load next block) */
        VADD_VV(REG_V0, REG_V0, REG_V16)
        VADD_VV(REG_V1, REG_V1, REG_V17)
        VADD_VV(REG_V2, REG_V2, REG_V18)
        VADD_VV(REG_V3, REG_V3, REG_V19)
        VXOR_VV(REG_V0, REG_V0, REG_V12)
        VXOR_VV(REG_V1, REG_V1, REG_V13)
        VXOR_VV(REG_V2, REG_V2, REG_V14)
        VXOR_VV(REG_V3, REG_V3, REG_V15)
        "mv     t2, %[m]\n\t"
        VL4RE32_V(REG_V12, REG_T2)
        "mv     t2, %[c]\n\t"
        VS4R_V(REG_V0, REG_T2)
        "addi   %[c], %[c], 64\n\t"
        VADD_VV(REG_V19, REG_V19, REG_V22)
        VADD_VV(REG_V4, REG_V4, REG_V16)
        VADD_VV(REG_V5, REG_V5, REG_V17)
        VADD_VV(REG_V6, REG_V6, REG_V18)
        VADD_VV(REG_V7, REG_V7, REG_V19)
        VXOR_VV(REG_V4, REG_V4, REG_V12)
        VXOR_VV(REG_V5, REG_V5, REG_V13)
        VXOR_VV(REG_V6, REG_V6, REG_V14)
        VXOR_VV(REG_V7, REG_V7, REG_V15)
        "mv     t2, %[c]\n\t"
        VS4R_V(REG_V4, REG_T2)
        : [m] "+r" (m), [c] "+r" (c)
        : [input] "r" (input),
          [L_chacha20_vec_inc_first_word] "r" (L_chacha20_vec_inc_first_word)
        : "memory", "t0", "t1", "t2"
    );
    return CHACHA_CHUNK_BYTES * 2;
}

#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION

#define PART_ROUND(a, b, d, t, sl, sr)      \
        VADD_VV(a, a, b)                    \
        VXOR_VV(d, d, a)                    \
        VSLL_VI(t, d, sl)                   \
        VSRL_VI(d, d, sr)                   \
        VOR_VV(d, d, t)

#else

#define PART_ROUND(a, b, d, t, sl, sr)      \
        VADD_VV(a, a, b)                    \
        VXOR_VV(d, d, a)                    \
        VROR_VI(d, sr, d)

#endif

#define QUARTER_ROUND(a, b, c, d, t)        \
        /* a += b; d ^= a; d <<<= 16; */    \
        PART_ROUND(a, b, d, t, 16, 16)      \
        /* c += d; b ^= c; b <<<= 12; */    \
        PART_ROUND(c, d, b, t, 12, 20)      \
        /* a += b; d ^= a; d <<<= 8; */     \
        PART_ROUND(a, b, d, t,  8, 24)      \
        /* c += d; b ^= c; b <<<= 7; */     \
        PART_ROUND(c, d, b, t,  7, 25)

#define ODD_SHUFFLE(b, c, d, t)                                         \
        /*    a=0,1,2,3; b=4,5,6,7; c=8,9,10,11; d=12,13,14,15          \
         * => a=0,1,2,3; b=5,6,7,4; c=10,11,8,9; d=15,12,13,14 */       \
        VSLIDEDOWN_VI(t, d, 3)                                          \
        VSLIDEUP_VI(t, d, 1)                                            \
        VMV_V_V(d, t)                                                   \
        VSLIDEDOWN_VI(t, b, 1)                                          \
        VSLIDEUP_VI(t, b, 3)                                            \
        VMV_V_V(b, t)                                                   \
        VSLIDEDOWN_VI(t, c, 2)                                          \
        VSLIDEUP_VI(t, c, 2)                                            \
        VMV_V_V(c, t)

#define EVEN_SHUFFLE(b, c, d, t)                                        \
        /*    a=0,1,2,3; b=5,6,7,4; c=10,11,8,9; d=15,12,13,14          \
         * => a=0,1,2,3; b=4,5,6,7; c=8,9,10,11; d=12,13,14,15 */       \
        VSLIDEDOWN_VI(t, d, 1)                                          \
        VSLIDEUP_VI(t, d, 3)                                            \
        VMV_V_V(d, t)                                                   \
        VSLIDEDOWN_VI(t, b, 3)                                          \
        VSLIDEUP_VI(t, b, 1)                                            \
        VMV_V_V(b, t)                                                   \
        VSLIDEDOWN_VI(t, c, 2)                                          \
        VSLIDEUP_VI(t, c, 2)                                            \
        VMV_V_V(c, t)

#define EIGHT_QUARTER_ROUNDS(a, b, c, d, t) \
        /* Odd Round */                     \
        QUARTER_ROUND(a, b, c, d, t)        \
        ODD_SHUFFLE(b, c, d, t)             \
        /* Even Round */                    \
        QUARTER_ROUND(a, b, c, d, t)        \
        EVEN_SHUFFLE(b, c, d, t)

static WC_INLINE void wc_chacha_encrypt_64(const word32* input, const byte* m,
    byte* c, word32 bytes, byte* over)
{
    word64 bytes64 = (word64)bytes;

    __asm__ __volatile__ (
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
        /* The layout of used vector registers is:
         * v0-v3 - block
         * v4-v7 - message
         * v8-v11 - input
         * v12 - temp
         *
         * v0  0  1  2  3
         * v1  4  5  6  7
         * v2  8  9 10 11
         * v3 12 13 14 15
         * load CHACHA state with indices placed as shown above
         */

        /* Load incrementer register to modify counter */
        "mv     t2, %[L_chacha20_vec_inc_first_word]\n\t"
        VL1RE32_V(REG_V13, REG_T2)
        /* Load state to encrypt */
        "mv     t2, %[input]\n\t"
        VL4RE32_V(REG_V8, REG_T2)
        "\n"
    "L_chacha20_riscv_64_loop:\n\t"
        /* Move state into vector registers */
        VMVR_V(REG_V0, REG_V8, 4)
        /* Add counter word */
        /* Odd Round */
        EIGHT_QUARTER_ROUNDS(REG_V0, REG_V1, REG_V2, REG_V3, REG_V12)
        EIGHT_QUARTER_ROUNDS(REG_V0, REG_V1, REG_V2, REG_V3, REG_V12)
        EIGHT_QUARTER_ROUNDS(REG_V0, REG_V1, REG_V2, REG_V3, REG_V12)
        EIGHT_QUARTER_ROUNDS(REG_V0, REG_V1, REG_V2, REG_V3, REG_V12)
        EIGHT_QUARTER_ROUNDS(REG_V0, REG_V1, REG_V2, REG_V3, REG_V12)
        EIGHT_QUARTER_ROUNDS(REG_V0, REG_V1, REG_V2, REG_V3, REG_V12)
        EIGHT_QUARTER_ROUNDS(REG_V0, REG_V1, REG_V2, REG_V3, REG_V12)
        EIGHT_QUARTER_ROUNDS(REG_V0, REG_V1, REG_V2, REG_V3, REG_V12)
        EIGHT_QUARTER_ROUNDS(REG_V0, REG_V1, REG_V2, REG_V3, REG_V12)
        EIGHT_QUARTER_ROUNDS(REG_V0, REG_V1, REG_V2, REG_V3, REG_V12)
        "addi   t1, %[bytes], -64\n\t"
        /* Add back state */
        VADD_VV(REG_V0, REG_V0, REG_V8)
        VADD_VV(REG_V1, REG_V1, REG_V9)
        VADD_VV(REG_V2, REG_V2, REG_V10)
        VADD_VV(REG_V3, REG_V3, REG_V11)
        "bltz   t1, L_chacha20_riscv_64_lt_64\n\t"
        "mv     t2, %[m]\n\t"
        VL4RE32_V(REG_V4, REG_T2)
        VXOR_VV(REG_V4, REG_V4, REG_V0)
        VXOR_VV(REG_V5, REG_V5, REG_V1)
        VXOR_VV(REG_V6, REG_V6, REG_V2)
        VXOR_VV(REG_V7, REG_V7, REG_V3)
        "mv     t2, %[c]\n\t"
        VS4R_V(REG_V4, REG_T2)
        "addi   %[bytes], %[bytes], -64\n\t"
        "addi   %[c], %[c], 64\n\t"
        "addi   %[m], %[m], 64\n\t"
        VADD_VV(REG_V11, REG_V11, REG_V13)
        "bnez   %[bytes], L_chacha20_riscv_64_loop\n\t"
        "beqz   %[bytes], L_chacha20_riscv_64_done\n\t"
        "\n"
    "L_chacha20_riscv_64_lt_64:\n\t"
        "mv     t2, %[over]\n\t"
        "addi   t1, %[bytes], -32\n\t"
        VS4R_V(REG_V0, REG_T2)

        "bltz   t1, L_chacha20_riscv_64_lt_32\n\t"
        "mv     t2, %[m]\n\t"
        VL2RE32_V(REG_V4, REG_T2)
        VXOR_VV(REG_V4, REG_V4, REG_V0)
        VXOR_VV(REG_V5, REG_V5, REG_V1)
        "mv     t2, %[c]\n\t"
        VS2R_V(REG_V4, REG_T2)
        "addi   %[bytes], %[bytes], -32\n\t"
        "addi   %[c], %[c], 32\n\t"
        "addi   %[m], %[m], 32\n\t"
        "beqz   %[bytes], L_chacha20_riscv_64_done\n\t"
        VMVR_V(REG_V0, REG_V2, 2)
        "\n"
    "L_chacha20_riscv_64_lt_32:\n\t"
        "addi   t1, %[bytes], -16\n\t"
        "bltz   t1, L_chacha20_riscv_64_lt_16\n\t"
        "mv     t2, %[m]\n\t"
        VL1RE32_V(REG_V4, REG_T2)
        VXOR_VV(REG_V4, REG_V4, REG_V0)
        "mv     t2, %[c]\n\t"
        VS1R_V(REG_V4, REG_T2)
        "addi   %[bytes], %[bytes], -16\n\t"
        "addi   %[c], %[c], 16\n\t"
        "addi   %[m], %[m], 16\n\t"
        "beqz   %[bytes], L_chacha20_riscv_64_done\n\t"
        VMV_V_V(REG_V0, REG_V1)
        "\n"
    "L_chacha20_riscv_64_lt_16:\n\t"
        "addi   t1, %[bytes], -8\n\t"
        "bltz   t1, L_chacha20_riscv_64_lt_8\n\t"
        VSETIVLI(REG_X0, 2, 1, 1, 0b011, 0b000)
        VMV_X_S(REG_T0, REG_V0)
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
        "ld     t1, (%[m])\n\t"
        "xor    t1, t1, t0\n\t"
        "sd     t1, (%[c])\n\t"
        "addi   %[bytes], %[bytes], -8\n\t"
        "addi   %[c], %[c], 8\n\t"
        "addi   %[m], %[m], 8\n\t"
        "beqz   %[bytes], L_chacha20_riscv_64_done\n\t"
        VSLIDEDOWN_VI(REG_V0, REG_V0, 2)
        "\n"
    "L_chacha20_riscv_64_lt_8:\n\t"
        "addi   %[bytes], %[bytes], -1\n\t"
        VSETIVLI(REG_X0, 2, 1, 1, 0b011, 0b000)
        VMV_X_S(REG_T0, REG_V0)
        VSETIVLI(REG_X0, 4, 1, 1, 0b010, 0b000)
        "\n"
    "L_chacha20_riscv_64_loop_lt_8:\n\t"
        "addi   %[bytes], %[bytes], -1\n\t"
        "lb     t1, (%[m])\n\t"
        "addi   %[m], %[m], 1\n\t"
        "xor    t1, t1, t0\n\t"
        "sb     t1, (%[c])\n\t"
        "addi   %[c], %[c], 1\n\t"
        "srli   t0, t0, 8\n\t"
        "bgez   %[bytes], L_chacha20_riscv_64_loop_lt_8\n\t"
        "\n"
    "L_chacha20_riscv_64_done:\n\t"
        : [m] "+r" (m), [c] "+r" (c), [bytes] "+r" (bytes64)
        : [input] "r" (input), [over] "r" (over),
          [L_chacha20_vec_inc_first_word] "r" (L_chacha20_vec_inc_first_word)
        : "memory", "t0", "t1", "t2"
    );
}

/**
 * Encrypt a stream of bytes
 */
static void wc_chacha_encrypt_bytes(ChaCha* ctx, const byte* m, byte* c,
    word32 bytes)
{
    int    processed;

    if (bytes >= CHACHA_CHUNK_BYTES * 6) {
        processed = (bytes / (CHACHA_CHUNK_BYTES * 6)) * CHACHA_CHUNK_BYTES * 6;
        wc_chacha_encrypt_384(ctx->X, m, c, processed);

        bytes -= processed;
        c += processed;
        m += processed;
        ctx->X[CHACHA_IV_BYTES] = PLUS(ctx->X[CHACHA_IV_BYTES],
                                       processed / CHACHA_CHUNK_BYTES);
    }
    if (bytes >= CHACHA_CHUNK_BYTES * 4) {
        processed = wc_chacha_encrypt_256(ctx->X, m, c);

        bytes -= processed;
        c += processed;
        m += processed;
        ctx->X[CHACHA_IV_BYTES] = PLUS(ctx->X[CHACHA_IV_BYTES],
                                       processed / CHACHA_CHUNK_BYTES);
    }
    if (bytes >= CHACHA_CHUNK_BYTES * 2) {
        processed = wc_chacha_encrypt_128(ctx->X, m, c);

        bytes -= processed;
        c += processed;
        m += processed;
        ctx->X[CHACHA_IV_BYTES] = PLUS(ctx->X[CHACHA_IV_BYTES],
                                       processed / CHACHA_CHUNK_BYTES);
    }
    if (bytes > 0) {
        wc_chacha_encrypt_64(ctx->X, m, c, bytes, (byte*)ctx->over);
        if (bytes > CHACHA_CHUNK_BYTES)
            ctx->X[CHACHA_IV_BYTES] = PLUSONE(ctx->X[CHACHA_IV_BYTES]);
        ctx->left = CHACHA_CHUNK_BYTES - (bytes & (CHACHA_CHUNK_BYTES - 1));
        ctx->left &= CHACHA_CHUNK_BYTES - 1;
        ctx->X[CHACHA_IV_BYTES] = PLUSONE(ctx->X[CHACHA_IV_BYTES]);
    }
}

#else

#if !defined(WOLFSSL_RISCV_BIT_MANIPULATION)

#define PART_ROUND_ODD_ABD(sl, sr)                      \
        "add    " CC_A0 ", " CC_A0 ", " CC_B0 "\n\t"    \
        "add    " CC_A1 ", " CC_A1 ", " CC_B1 "\n\t"    \
        "add    " CC_A2 ", " CC_A2 ", " CC_B2 "\n\t"    \
        "add    " CC_A3 ", " CC_A3 ", " CC_B3 "\n\t"    \
        "xor    " CC_D0 ", " CC_D0 ", " CC_A0 "\n\t"    \
        "xor    " CC_D1 ", " CC_D1 ", " CC_A1 "\n\t"    \
        "xor    " CC_D2 ", " CC_D2 ", " CC_A2 "\n\t"    \
        "xor    " CC_D3 ", " CC_D3 ", " CC_A3 "\n\t"    \
        "slli   " CC_T0 ", " CC_D0 ", " #sl "\n\t"      \
        "slli   " CC_T1 ", " CC_D1 ", " #sl "\n\t"      \
        "slli   " CC_T2 ", " CC_D2 ", " #sl "\n\t"      \
        "slli   " CC_T3 ", " CC_D3 ", " #sl "\n\t"      \
        "srliw  " CC_D0 ", " CC_D0 ", " #sr "\n\t"      \
        "srliw  " CC_D1 ", " CC_D1 ", " #sr "\n\t"      \
        "srliw  " CC_D2 ", " CC_D2 ", " #sr "\n\t"      \
        "srliw  " CC_D3 ", " CC_D3 ", " #sr "\n\t"      \
        "or     " CC_D0 ", " CC_D0 ", " CC_T0 "\n\t"    \
        "or     " CC_D1 ", " CC_D1 ", " CC_T1 "\n\t"    \
        "or     " CC_D2 ", " CC_D2 ", " CC_T2 "\n\t"    \
        "or     " CC_D3 ", " CC_D3 ", " CC_T3 "\n\t"

#define PART_ROUND_ODD_CDB(sl, sr)                      \
        "add    " CC_C0 ", " CC_C0 ", " CC_D0 "\n\t"    \
        "add    " CC_C1 ", " CC_C1 ", " CC_D1 "\n\t"    \
        "add    " CC_C2 ", " CC_C2 ", " CC_D2 "\n\t"    \
        "add    " CC_C3 ", " CC_C3 ", " CC_D3 "\n\t"    \
        "xor    " CC_B0 ", " CC_B0 ", " CC_C0 "\n\t"    \
        "xor    " CC_B1 ", " CC_B1 ", " CC_C1 "\n\t"    \
        "xor    " CC_B2 ", " CC_B2 ", " CC_C2 "\n\t"    \
        "xor    " CC_B3 ", " CC_B3 ", " CC_C3 "\n\t"    \
        "slli   " CC_T0 ", " CC_B0 ", " #sl "\n\t"      \
        "slli   " CC_T1 ", " CC_B1 ", " #sl "\n\t"      \
        "slli   " CC_T2 ", " CC_B2 ", " #sl "\n\t"      \
        "slli   " CC_T3 ", " CC_B3 ", " #sl "\n\t"      \
        "srliw  " CC_B0 ", " CC_B0 ", " #sr "\n\t"      \
        "srliw  " CC_B1 ", " CC_B1 ", " #sr "\n\t"      \
        "srliw  " CC_B2 ", " CC_B2 ", " #sr "\n\t"      \
        "srliw  " CC_B3 ", " CC_B3 ", " #sr "\n\t"      \
        "or     " CC_B0 ", " CC_B0 ", " CC_T0 "\n\t"    \
        "or     " CC_B1 ", " CC_B1 ", " CC_T1 "\n\t"    \
        "or     " CC_B2 ", " CC_B2 ", " CC_T2 "\n\t"    \
        "or     " CC_B3 ", " CC_B3 ", " CC_T3 "\n\t"

#define PART_ROUND_EVEN_ABD(sl, sr)                     \
        "add    " CC_A0 ", " CC_A0 ", " CC_B1 "\n\t"    \
        "add    " CC_A1 ", " CC_A1 ", " CC_B2 "\n\t"    \
        "add    " CC_A2 ", " CC_A2 ", " CC_B3 "\n\t"    \
        "add    " CC_A3 ", " CC_A3 ", " CC_B0 "\n\t"    \
        "xor    " CC_D3 ", " CC_D3 ", " CC_A0 "\n\t"    \
        "xor    " CC_D0 ", " CC_D0 ", " CC_A1 "\n\t"    \
        "xor    " CC_D1 ", " CC_D1 ", " CC_A2 "\n\t"    \
        "xor    " CC_D2 ", " CC_D2 ", " CC_A3 "\n\t"    \
        "slli   " CC_T0 ", " CC_D3 ", " #sl "\n\t"      \
        "slli   " CC_T1 ", " CC_D0 ", " #sl "\n\t"      \
        "slli   " CC_T2 ", " CC_D1 ", " #sl "\n\t"      \
        "slli   " CC_T3 ", " CC_D2 ", " #sl "\n\t"      \
        "srliw  " CC_D3 ", " CC_D3 ", " #sr "\n\t"      \
        "srliw  " CC_D0 ", " CC_D0 ", " #sr "\n\t"      \
        "srliw  " CC_D1 ", " CC_D1 ", " #sr "\n\t"      \
        "srliw  " CC_D2 ", " CC_D2 ", " #sr "\n\t"      \
        "or     " CC_D3 ", " CC_D3 ", " CC_T0 "\n\t"    \
        "or     " CC_D0 ", " CC_D0 ", " CC_T1 "\n\t"    \
        "or     " CC_D1 ", " CC_D1 ", " CC_T2 "\n\t"    \
        "or     " CC_D2 ", " CC_D2 ", " CC_T3 "\n\t"

#define PART_ROUND_EVEN_CDB(sl, sr)                     \
        "add    " CC_C2 ", " CC_C2 ", " CC_D3 "\n\t"    \
        "add    " CC_C3 ", " CC_C3 ", " CC_D0 "\n\t"    \
        "add    " CC_C0 ", " CC_C0 ", " CC_D1 "\n\t"    \
        "add    " CC_C1 ", " CC_C1 ", " CC_D2 "\n\t"    \
        "xor    " CC_B1 ", " CC_B1 ", " CC_C2 "\n\t"    \
        "xor    " CC_B2 ", " CC_B2 ", " CC_C3 "\n\t"    \
        "xor    " CC_B3 ", " CC_B3 ", " CC_C0 "\n\t"    \
        "xor    " CC_B0 ", " CC_B0 ", " CC_C1 "\n\t"    \
        "slli   " CC_T0 ", " CC_B1 ", " #sl "\n\t"      \
        "slli   " CC_T1 ", " CC_B2 ", " #sl "\n\t"      \
        "slli   " CC_T2 ", " CC_B3 ", " #sl "\n\t"      \
        "slli   " CC_T3 ", " CC_B0 ", " #sl "\n\t"      \
        "srliw  " CC_B1 ", " CC_B1 ", " #sr "\n\t"      \
        "srliw  " CC_B2 ", " CC_B2 ", " #sr "\n\t"      \
        "srliw  " CC_B3 ", " CC_B3 ", " #sr "\n\t"      \
        "srliw  " CC_B0 ", " CC_B0 ", " #sr "\n\t"      \
        "or     " CC_B1 ", " CC_B1 ", " CC_T0 "\n\t"    \
        "or     " CC_B2 ", " CC_B2 ", " CC_T1 "\n\t"    \
        "or     " CC_B3 ", " CC_B3 ", " CC_T2 "\n\t"    \
        "or     " CC_B0 ", " CC_B0 ", " CC_T3 "\n\t"

#else

#define PART_ROUND_ODD_ABD(sl, sr)                      \
        "add    " CC_A0 ", " CC_A0 ", " CC_B0 "\n\t"    \
        "add    " CC_A1 ", " CC_A1 ", " CC_B1 "\n\t"    \
        "add    " CC_A2 ", " CC_A2 ", " CC_B2 "\n\t"    \
        "add    " CC_A3 ", " CC_A3 ", " CC_B3 "\n\t"    \
        "xor    " CC_D0 ", " CC_D0 ", " CC_A0 "\n\t"    \
        "xor    " CC_D1 ", " CC_D1 ", " CC_A1 "\n\t"    \
        "xor    " CC_D2 ", " CC_D2 ", " CC_A2 "\n\t"    \
        "xor    " CC_D3 ", " CC_D3 ", " CC_A3 "\n\t"    \
        RORIW(REG_S6, REG_S6, sr)                       \
        RORIW(REG_S7, REG_S7, sr)                       \
        RORIW(REG_S8, REG_S8, sr)                       \
        RORIW(REG_S9, REG_S9, sr)

#define PART_ROUND_ODD_CDB(sl, sr)                      \
        "add    " CC_C0 ", " CC_C0 ", " CC_D0 "\n\t"    \
        "add    " CC_C1 ", " CC_C1 ", " CC_D1 "\n\t"    \
        "add    " CC_C2 ", " CC_C2 ", " CC_D2 "\n\t"    \
        "add    " CC_C3 ", " CC_C3 ", " CC_D3 "\n\t"    \
        "xor    " CC_B0 ", " CC_B0 ", " CC_C0 "\n\t"    \
        "xor    " CC_B1 ", " CC_B1 ", " CC_C1 "\n\t"    \
        "xor    " CC_B2 ", " CC_B2 ", " CC_C2 "\n\t"    \
        "xor    " CC_B3 ", " CC_B3 ", " CC_C3 "\n\t"    \
        RORIW(REG_T3, REG_T3, sr)                       \
        RORIW(REG_T4, REG_T4, sr)                       \
        RORIW(REG_T5, REG_T5, sr)                       \
        RORIW(REG_T6, REG_T6, sr)

#define PART_ROUND_EVEN_ABD(sl, sr)                     \
        "add    " CC_A0 ", " CC_A0 ", " CC_B1 "\n\t"    \
        "add    " CC_A1 ", " CC_A1 ", " CC_B2 "\n\t"    \
        "add    " CC_A2 ", " CC_A2 ", " CC_B3 "\n\t"    \
        "add    " CC_A3 ", " CC_A3 ", " CC_B0 "\n\t"    \
        "xor    " CC_D3 ", " CC_D3 ", " CC_A0 "\n\t"    \
        "xor    " CC_D0 ", " CC_D0 ", " CC_A1 "\n\t"    \
        "xor    " CC_D1 ", " CC_D1 ", " CC_A2 "\n\t"    \
        "xor    " CC_D2 ", " CC_D2 ", " CC_A3 "\n\t"    \
        RORIW(REG_S9, REG_S9, sr)                       \
        RORIW(REG_S6, REG_S6, sr)                       \
        RORIW(REG_S7, REG_S7, sr)                       \
        RORIW(REG_S8, REG_S8, sr)

#define PART_ROUND_EVEN_CDB(sl, sr)                     \
        "add    " CC_C2 ", " CC_C2 ", " CC_D3 "\n\t"    \
        "add    " CC_C3 ", " CC_C3 ", " CC_D0 "\n\t"    \
        "add    " CC_C0 ", " CC_C0 ", " CC_D1 "\n\t"    \
        "add    " CC_C1 ", " CC_C1 ", " CC_D2 "\n\t"    \
        "xor    " CC_B1 ", " CC_B1 ", " CC_C2 "\n\t"    \
        "xor    " CC_B2 ", " CC_B2 ", " CC_C3 "\n\t"    \
        "xor    " CC_B3 ", " CC_B3 ", " CC_C0 "\n\t"    \
        "xor    " CC_B0 ", " CC_B0 ", " CC_C1 "\n\t"    \
        RORIW(REG_T4, REG_T4, sr)                       \
        RORIW(REG_T5, REG_T5, sr)                       \
        RORIW(REG_T6, REG_T6, sr)                       \
        RORIW(REG_T3, REG_T3, sr)

#endif

#define QUARTER_ROUND_ODD()                 \
        /* a += b; d ^= a; d <<<= 16; */    \
        PART_ROUND_ODD_ABD(16, 16)          \
        /* c += d; b ^= c; b <<<= 12; */    \
        PART_ROUND_ODD_CDB(12, 20)          \
        /* a += b; d ^= a; d <<<= 8; */     \
        PART_ROUND_ODD_ABD( 8, 24)          \
        /* c += d; b ^= c; b <<<= 7; */     \
        PART_ROUND_ODD_CDB( 7, 25)

#define QUARTER_ROUND_EVEN()                \
        /* a += b; d ^= a; d <<<= 16; */    \
        PART_ROUND_EVEN_ABD(16, 16)         \
        /* c += d; b ^= c; b <<<= 12; */    \
        PART_ROUND_EVEN_CDB(12, 20)         \
        /* a += b; d ^= a; d <<<= 8; */     \
        PART_ROUND_EVEN_ABD( 8, 24)         \
        /* c += d; b ^= c; b <<<= 7; */     \
        PART_ROUND_EVEN_CDB( 7, 25)


static WC_INLINE void wc_chacha_encrypt(const word32* input, const byte* m,
    byte* c, word32 bytes, word32* over)
{
    __asm__ __volatile__ (
        /* Ensure 64-bit bytes has top bits clear. */
        "slli   %[bytes], %[bytes], 32\n\t"
        "srli   %[bytes], %[bytes], 32\n\t"

    "L_chacha20_riscv_outer:\n\t"
        /* Move state into regular registers */
        "ld     a4,  0(%[input])\n\t"
        "ld     a6,  8(%[input])\n\t"
        "ld     t3, 16(%[input])\n\t"
        "ld     t5, 24(%[input])\n\t"
        "ld     s2, 32(%[input])\n\t"
        "ld     s4, 40(%[input])\n\t"
        "ld     s6, 48(%[input])\n\t"
        "ld     s8, 56(%[input])\n\t"
        "srli   a5, a4, 32\n\t"
        "srli   a7, a6, 32\n\t"
        "srli   t4, t3, 32\n\t"
        "srli   t6, t5, 32\n\t"
        "srli   s3, s2, 32\n\t"
        "srli   s5, s4, 32\n\t"
        "srli   s7, s6, 32\n\t"
        "srli   s9, s8, 32\n\t"

        /* Set number of odd+even rounds to perform */
        "li     a3, 10\n\t"
        "\n"
    "L_chacha20_riscv_loop:\n\t"
        /* Odd Round */
        QUARTER_ROUND_ODD()
        "addi   a3, a3, -1\n\t"
        /* Even Round */
        QUARTER_ROUND_EVEN()
        "bnez   a3, L_chacha20_riscv_loop\n\t"

        "addi   %[bytes], %[bytes], -64\n\t"

        "ld     t0, 0(%[input])\n\t"
        "ld     t1, 8(%[input])\n\t"
        "ld     t2, 16(%[input])\n\t"
        "ld     s1, 24(%[input])\n\t"
        "add    a4, a4, t0\n\t"
        "add    a6, a6, t1\n\t"
        "add    t3, t3, t2\n\t"
        "add    t5, t5, s1\n\t"
        "srli   t0, t0, 32\n\t"
        "srli   t1, t1, 32\n\t"
        "srli   t2, t2, 32\n\t"
        "srli   s1, s1, 32\n\t"
        "add    a5, a5, t0\n\t"
        "add    a7, a7, t1\n\t"
        "add    t4, t4, t2\n\t"
        "add    t6, t6, s1\n\t"
        "ld     t0, 32(%[input])\n\t"
        "ld     t1, 40(%[input])\n\t"
        "ld     t2, 48(%[input])\n\t"
        "ld     s1, 56(%[input])\n\t"
        "add    s2, s2, t0\n\t"
        "add    s4, s4, t1\n\t"
        "add    s6, s6, t2\n\t"
        "addi   t2, t2, 1\n\t"
        "add    s8, s8, s1\n\t"
        "srli   t0, t0, 32\n\t"
        "srli   t1, t1, 32\n\t"
        "sw     t2, 48(%[input])\n\t"
        "srli   t2, t2, 32\n\t"
        "srli   s1, s1, 32\n\t"
        "add    s3, s3, t0\n\t"
        "add    s5, s5, t1\n\t"
        "add    s7, s7, t2\n\t"
        "add    s9, s9, s1\n\t"

        "bltz   %[bytes], L_chacha20_riscv_over\n\t"

#if !defined(WOLFSSL_RISCV_BIT_MANIPULATION)
        "ld     t0, 0(%[m])\n\t"
        "ld     t1, 8(%[m])\n\t"
        "ld     t2, 16(%[m])\n\t"
        "ld     s1, 24(%[m])\n\t"
        "xor    a4, a4, t0\n\t"
        "xor    a6, a6, t1\n\t"
        "xor    t3, t3, t2\n\t"
        "xor    t5, t5, s1\n\t"
        "srli   t0, t0, 32\n\t"
        "srli   t1, t1, 32\n\t"
        "srli   t2, t2, 32\n\t"
        "srli   s1, s1, 32\n\t"
        "xor    a5, a5, t0\n\t"
        "xor    a7, a7, t1\n\t"
        "xor    t4, t4, t2\n\t"
        "xor    t6, t6, s1\n\t"
        "ld     t0, 32(%[m])\n\t"
        "ld     t1, 40(%[m])\n\t"
        "ld     t2, 48(%[m])\n\t"
        "ld     s1, 56(%[m])\n\t"
        "xor    s2, s2, t0\n\t"
        "xor    s4, s4, t1\n\t"
        "xor    s6, s6, t2\n\t"
        "xor    s8, s8, s1\n\t"
        "srli   t0, t0, 32\n\t"
        "srli   t1, t1, 32\n\t"
        "srli   t2, t2, 32\n\t"
        "srli   s1, s1, 32\n\t"
        "xor    s3, s3, t0\n\t"
        "xor    s5, s5, t1\n\t"
        "xor    s7, s7, t2\n\t"
        "xor    s9, s9, s1\n\t"
        "sw     a4, 0(%[c])\n\t"
        "sw     a5, 4(%[c])\n\t"
        "sw     a6, 8(%[c])\n\t"
        "sw     a7, 12(%[c])\n\t"
        "sw     t3, 16(%[c])\n\t"
        "sw     t4, 20(%[c])\n\t"
        "sw     t5, 24(%[c])\n\t"
        "sw     t6, 28(%[c])\n\t"
        "sw     s2, 32(%[c])\n\t"
        "sw     s3, 36(%[c])\n\t"
        "sw     s4, 40(%[c])\n\t"
        "sw     s5, 44(%[c])\n\t"
        "sw     s6, 48(%[c])\n\t"
        "sw     s7, 52(%[c])\n\t"
        "sw     s8, 56(%[c])\n\t"
        "sw     s9, 60(%[c])\n\t"
#else
        PACK(REG_A4, REG_A4, REG_A5)
        PACK(REG_A6, REG_A6, REG_A7)
        PACK(REG_T3, REG_T3, REG_T4)
        PACK(REG_T5, REG_T5, REG_T6)
        PACK(REG_S2, REG_S2, REG_S3)
        PACK(REG_S4, REG_S4, REG_S5)
        PACK(REG_S6, REG_S6, REG_S7)
        PACK(REG_S8, REG_S8, REG_S9)
        "ld     a5, 0(%[m])\n\t"
        "ld     a7, 8(%[m])\n\t"
        "ld     t4, 16(%[m])\n\t"
        "ld     t6, 24(%[m])\n\t"
        "ld     s3, 32(%[m])\n\t"
        "ld     s5, 40(%[m])\n\t"
        "ld     s7, 48(%[m])\n\t"
        "ld     s9, 56(%[m])\n\t"
        "xor    a4, a4, a5\n\t"
        "xor    a6, a6, a7\n\t"
        "xor    t3, t3, t4\n\t"
        "xor    t5, t5, t6\n\t"
        "xor    s2, s2, s3\n\t"
        "xor    s4, s4, s5\n\t"
        "xor    s6, s6, s7\n\t"
        "xor    s8, s8, s9\n\t"
        "sd     a4, 0(%[c])\n\t"
        "sd     a6, 8(%[c])\n\t"
        "sd     t3, 16(%[c])\n\t"
        "sd     t5, 24(%[c])\n\t"
        "sd     s2, 32(%[c])\n\t"
        "sd     s4, 40(%[c])\n\t"
        "sd     s6, 48(%[c])\n\t"
        "sd     s8, 56(%[c])\n\t"
#endif

        "addi   %[m], %[m], 64\n\t"
        "addi   %[c], %[c], 64\n\t"

        "bnez   %[bytes], L_chacha20_riscv_outer\n\t"
        "beqz   %[bytes], L_chacha20_riscv_done\n\t"

     "L_chacha20_riscv_over:\n\t"
        "addi   a3, %[bytes], 64\n\t"

        "sw     a4,  0(%[over])\n\t"
        "sw     a5,  4(%[over])\n\t"
        "sw     a6,  8(%[over])\n\t"
        "sw     a7, 12(%[over])\n\t"
        "sw     t3, 16(%[over])\n\t"
        "sw     t4, 20(%[over])\n\t"
        "sw     t5, 24(%[over])\n\t"
        "sw     t6, 28(%[over])\n\t"
        "sw     s2, 32(%[over])\n\t"
        "sw     s3, 36(%[over])\n\t"
        "sw     s4, 40(%[over])\n\t"
        "sw     s5, 44(%[over])\n\t"
        "sw     s6, 48(%[over])\n\t"
        "sw     s7, 52(%[over])\n\t"
        "sw     s8, 56(%[over])\n\t"
        "sw     s9, 60(%[over])\n\t"

        "addi   t0, a3, -8\n\t"
        "bltz   t0, L_chacha20_riscv_32bit\n\t"
        "addi   a3, a3, -1\n\t"
     "L_chacha20_riscv_64bit_loop:\n\t"
        "ld     t0, (%[m])\n\t"
        "ld     t1, (%[over])\n\t"
        "xor    t0, t0, t1\n\t"
        "sd     t0, (%[c])\n\t"
        "addi   %[m], %[m], 8\n\t"
        "addi   %[c], %[c], 8\n\t"
        "addi   %[over], %[over], 8\n\t"
        "addi   a3, a3, -8\n\t"
        "bgez   a3, L_chacha20_riscv_64bit_loop\n\t"
        "addi   a3, a3, 1\n\t"

     "L_chacha20_riscv_32bit:\n\t"
        "addi   t0, a3, -4\n\t"
        "bltz   t0, L_chacha20_riscv_16bit\n\t"
        "lw     t0, (%[m])\n\t"
        "lw     t1, (%[over])\n\t"
        "xor    t0, t0, t1\n\t"
        "sw     t0, (%[c])\n\t"
        "addi   %[m], %[m], 4\n\t"
        "addi   %[c], %[c], 4\n\t"
        "addi   %[over], %[over], 4\n\t"

     "L_chacha20_riscv_16bit:\n\t"
        "addi   t0, a3, -2\n\t"
        "bltz   t0, L_chacha20_riscv_8bit\n\t"
        "lh     t0, (%[m])\n\t"
        "lh     t1, (%[over])\n\t"
        "xor    t0, t0, t1\n\t"
        "sh     t0, (%[c])\n\t"
        "addi   %[m], %[m], 2\n\t"
        "addi   %[c], %[c], 2\n\t"
        "addi   %[over], %[over], 2\n\t"

     "L_chacha20_riscv_8bit:\n\t"
        "addi   t0, a3, -1\n\t"
        "bltz   t0, L_chacha20_riscv_done\n\t\n\t"
        "lb     t0, (%[m])\n\t"
        "lb     t1, (%[over])\n\t"
        "xor    t0, t0, t1\n\t"
        "sb     t0, (%[c])\n\t"
        "bltz   %[bytes], L_chacha20_riscv_done\n\t"

     "L_chacha20_riscv_done:\n\t"
        : [m] "+r" (m), [c] "+r" (c), [bytes] "+r" (bytes), [over] "+r" (over)
        : [input] "r" (input)
        : "memory", "t0", "t1", "t2", "s1", "a3",
          "t3", "t4", "t5", "t6",
          "a4", "a5", "a6", "a7",
          "s2", "s3", "s4", "s5",
          "s6", "s7", "s8", "s9"
    );
}

/**
 * Encrypt a stream of bytes
 */
static WC_INLINE void wc_chacha_encrypt_bytes(ChaCha* ctx, const byte* m,
    byte* c, word32 bytes)
{
    wc_chacha_encrypt(ctx->X, m, c, bytes, ctx->over);
    ctx->left = (CHACHA_CHUNK_BYTES - (bytes & (CHACHA_CHUNK_BYTES - 1))) &
                (CHACHA_CHUNK_BYTES - 1);
}
#endif

/**
 * API to encrypt/decrypt a message of any size.
 */
int wc_Chacha_Process(ChaCha* ctx, byte* output, const byte* input,
    word32 msglen)
{
    int ret = 0;

    if ((ctx == NULL) || (output == NULL) || (input == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else if (msglen > 0) {
        if (ctx->left > 0) {
            word32 processed = min(msglen, ctx->left);
            byte*  out = (byte*)ctx->over + CHACHA_CHUNK_BYTES - ctx->left;

            xorbufout(output, input, out, processed);

            ctx->left -= processed;
            msglen -= processed;
            output += processed;
            input += processed;
        }

        if (msglen > 0) {
            wc_chacha_encrypt_bytes(ctx, input, output, msglen);
        }
    }

    return ret;
}

#endif /* HAVE_CHACHA */
#endif /* WOLFSSL_ARMASM && !WOLFSSL_ARMASM_NO_NEON */
