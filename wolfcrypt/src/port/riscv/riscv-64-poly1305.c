/* riscv-64-poly1305.c
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

/*
 * Based off the public domain implementations by Andrew Moon
 * and Daniel J. Bernstein
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/port/riscv/riscv-64-asm.h>

#ifdef WOLFSSL_RISCV_ASM

#ifdef HAVE_POLY1305
#include <wolfssl/wolfcrypt/poly1305.h>
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


#ifndef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY

#define SPLIT_130(r0, r1, r2, a0, a1, a2, t)        \
        "srli   " #r1 ", " #a0 ", (64-12)\n\t"      \
        "and    " #r0 ", " #a0 ", a6\n\t"           \
        "slli   " #t  ", " #a1 ", (2*12)\n\t"       \
        "slli   " #r2 ", " #a2 ", (2*12)\n\t"       \
        "srli   " #a1 ", " #a1 ", (64-2*12)\n\t"    \
        "srli   " #t  ", " #t  ", 12\n\t"           \
        "or     " #r2 ", " #a1 ", " #r2 "\n\t"      \
        "or     " #r1 ", " #r1 ", " #t  "\n\t"

#define SPLIT_128(r0, r1, r2, a0, a1, t)            \
        "slli   " #t  ", " #a1 ", (2*12)\n\t"       \
        "srli   " #r1 ", " #a0 ", (64-12)\n\t"      \
        "and    " #r0 ", " #a0 ", a6\n\t"           \
        "srli   " #t  ", " #t  ", 12\n\t"           \
        "srli   " #r2 ", " #a1 ", (64-2*12)\n\t"    \
        "or     " #r1 ", " #r1 ", " #t  "\n\t"

#define REDIST(l, h, t)                     \
        "srli   " #t ", " #l ", 52\n\t"     \
        "slli   " #h ", " #h ", 12\n\t"     \
        "and    " #l ", " #l ", a6\n\t"     \
        "or     " #h ", " #h ", " #t "\n\t"

#define REDIST_HI(l, h, h2, t)              \
        "srli   " #h2 ", " #h ", 28\n\t"    \
        "slli   " #h ", " #h ", 24\n\t"     \
        "srli   " #t ", " #l ", 40\n\t"     \
        "slli   " #l ", " #l ", 12\n\t"     \
        "and    " #h ", " #h ", a6\n\t"     \
        "and    " #l ", " #l ", a6\n\t"     \
        "or     " #h ", " #h ", " #t "\n\t"

#define REDIST_HI_26(l, h, t)               \
        "srli   " #t ", " #l ", 40\n\t"     \
        "slli   " #l ", " #l ", 12\n\t"     \
        "slli   " #h ", " #h ", 24\n\t"     \
        "and    " #l ", " #l ", a6\n\t"     \
        "or     " #h ", " #h ", " #t "\n\t"

#else

#define SPLIT_130(r0, r1, r2, a0, a1, a2, t)        \
        "and    " #r0 ", " #a0 ", a6\n\t"           \
        FSRI(r1, a1, a0, 52)                        \
        FSRI(r2, a2, a1, 40)                        \
        "and    " #r1 ", " #r1 ", a6\n\t"           \
        "and    " #r2 ", " #r2 ", a6\n\t"

#define SPLIT_128(r0, r1, r2, a0, a1, t)            \
        "srli   " #r2 ", " #a1 ", 40\n\t"           \
        FSRI(r1, a1, a0, 52)                        \
        "and    " #r0 ", " #a0 ", a6\n\t"           \
        "and    " #r1 ", " #r1 ", a6\n\t"

#define REDIST(l, h, t)                     \
        FSRI(h, h, l, 52)                   \
        "and    " #l ", " #l ", a4\n\t"

#define REDIST_HI(l, h, h2, t)              \
        "srli   " #h2 ", " #h ", 28\n\t"    \
        FSRI(h, h, l, 40)                   \
        "slli   " #l ", " #l ", 12\n\t"     \
        "and    " #h ", " #h ", a6\n\t"     \
        "and    " #l ", " #l ", a6\n\t"

#define REDIST_HI_26(l, h, t)               \
        FSRI(h, h, l, 40)                   \
        "slli   " #l ", " #l ", 12\n\t"     \
        "and    " #l ", " #l ", a6\n\t"

#endif

#define RECALC(l, h, t)                     \
        "srli   " #t ", " #l ", 52\n\t"     \
        "and    " #l ", " #l ", a6\n\t"     \
        "add    " #h ", " #h ", " #t "\n\t"

static WC_INLINE void poly1305_blocks_riscv64_16(Poly1305* ctx,
    const unsigned char *m, size_t bytes, int notLast)
{
    __asm__ __volatile__ (
        "addi   %[bytes], %[bytes], -16\n\t"
        "bltz   %[bytes], L_poly1305_riscv64_16_64_done_%=\n\t"

        "li     a4, 0xffffffc000000\n\t"
        "li     a5, 0x3ffffff\n\t"
        "li     a6, 0xfffffffffffff\n\t"

        /* Load r and h */
        "ld     s8, %[ctx_r_0]\n\t"
        "ld     s9, %[ctx_r_1]\n\t"

        "ld     s3, %[ctx_h_0]\n\t"
        "ld     s4, %[ctx_h_1]\n\t"
        "ld     s5, %[ctx_h_2]\n\t"

    "L_poly1305_riscv64_16_64_loop_%=:\n\t"
        /* Load m */
        "ld     t0, (%[m])\n\t"
        "ld     t1, 8(%[m])\n\t"
        /* Split m into 26, 52, 52 */
        SPLIT_130(t2, t3, t4, t0, t1, %[notLast], t5)

        "add    s3, s3, t2\n\t"
        "add    s4, s4, t3\n\t"
        "add    s5, s5, t4\n\t"

        /* r[0] * h[0] = [0, 1] */
        "mul    t0, s8, s3\n\t"
        "mulhu  t1, s8, s3\n\t"
        REDIST(t0, t1, s6)
        /* r[0] * h[1] = [1, 2] */
        "mul    t3, s8, s4\n\t"
        "mulhu  t2, s8, s4\n\t"
        REDIST(t3, t2, s6)
        "add    t1, t1, t3\n\t"
        /* r[1] * h[0] = [1, 2] */
        "mul    t4, s9, s3\n\t"
        "mulhu  t5, s9, s3\n\t"
        REDIST_HI(t4, t5, t3, s6)
        "add    t1, t1, t4\n\t"
        "add    t2, t2, t5\n\t"
        /* r[0] * h[2] = [2, 3] */
        "mul    t4, s8, s5\n\t"
        "mulhu  t5, s8, s5\n\t"
        REDIST(t4, t5, s6)
        "add    t2, t2, t4\n\t"
        "add    t3, t3, t5\n\t"
        /* r[1] * h[1] = [2, 3] */
        "mul    t5, s9, s4\n\t"
        "mulhu  t6, s9, s4\n\t"
        REDIST_HI(t5, t6, t4, s6)
        "add    t2, t2, t5\n\t"
        "add    t3, t3, t6\n\t"
        /* r[1] * h[2] = [3, 4] */
        "mul    t5, s9, s5\n\t"
        "mulhu  t6, s9, s5\n\t"
        REDIST_HI_26(t5, t6, s6)
        "add    t3, t3, t5\n\t"
        "add    t4, t4, t6\n\t"

        RECALC(t1, t2, s6)
        RECALC(t2, t3, s6)
        RECALC(t3, t4, s6)

        /* h[0..4] % (2^130 - 5) */
        "slli   s3, t3, 26\n\t"
        "slli   s4, t4, 26\n\t"
        "and    s3, s3, a4\n\t"
        "and    s4, s4, a4\n\t"
        "srli   t5, t2, 26\n\t"
        "and    t2, t2, a5\n\t"
        "srli   t3, t3, 26\n\t"
        "srli   t4, t4, 26\n\t"
        "add    t5, t5, s3\n\t"
        "add    t3, t3, s4\n\t"

        "slli   s5, t5, 2\n\t"
        "slli   s3, t3, 2\n\t"
        "slli   s4, t4, 2\n\t"
        "add    t5, t5, s5\n\t"
        "add    t3, t3, s3\n\t"
        "add    t4, t4, s4\n\t"

        "add    s3, t0, t5\n\t"
        "add    s4, t1, t3\n\t"
        "add    s5, t2, t4\n\t"

        /* h[0..2] % (2^130 - 5) */
        "and    t5, s5, a4\n\t"
        "and    s5, s5, a5\n\t"
        "srli   t6, t5, 24\n\t"
        "srli   t5, t5, 26\n\t"
        "add    t5, t5, t6\n\t"
        "add    s3, s3, t5\n\t"

        "addi   %[bytes], %[bytes], -16\n\t"
        "addi   %[m], %[m], 16\n\t"
        "bgez   %[bytes], L_poly1305_riscv64_16_64_loop_%=\n\t"

        "sd     s3, %[ctx_h_0]\n\t"
        "sd     s4, %[ctx_h_1]\n\t"
        "sd     s5, %[ctx_h_2]\n\t"
        "\n"
    "L_poly1305_riscv64_16_64_done_%=:\n\t"
        : [bytes] "+r" (bytes), [m] "+r" (m)
        : [ctx_h_0] "m" (ctx->h[0]), [ctx_h_1] "m" (ctx->h[1]),
          [ctx_h_2] "m" (ctx->h[2]), [ctx_r_0] "m" (ctx->r[0]),
          [ctx_r_1] "m" (ctx->r[1]), [notLast] "r" ((word64)notLast)
        : "memory", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "s6",
                    "a4", "a5", "a6", /* Constants */
                    "s3", "s4", "s5", /* h */
                    "s8", "s9" /* r */
    );
}

#ifdef WOLFSSL_RISCV_VECTOR

#define MUL_RES_REDIS(l, h, t)  \
        VSRL_VX(t, l, REG_A7)   \
        VSLL_VI(h, h, 12)       \
        VAND_VX(l, l, REG_A6)   \
        VOR_VV(h, h, t)

#endif

void poly1305_blocks_riscv64(Poly1305* ctx, const unsigned char *m,
    size_t bytes)
{
#ifdef WOLFSSL_RISCV_VECTOR
    __asm__ __volatile__ (
        "addi   %[bytes], %[bytes], -32\n\t"
        "bltz   %[bytes], L_poly1305_riscv64_vec_done_%=\n\t"

        VSETIVLI(REG_ZERO, 2, 1, 1, 0b011, 0b000)

        "li     a4, 0xffffffc000000\n\t"
        "li     a5, 0x3ffffff\n\t"
        "li     a6, 0xfffffffffffff\n\t"
        "li     a7, 52\n\t"

        /* Load r and r^2 */
        "mv     t0, %[r2]\n\t"
        VL2RE64_V(REG_V2, REG_T0)
        "addi   t0, %[r2], 32\n\t"
        VL1RE64_V(REG_V4, REG_T0)

        /* Load h */
        "ld     t0,  0(%[h])\n\t"
        "ld     t1,  8(%[h])\n\t"
        "ld     t2,  16(%[h])\n\t"

        VMV_S_X(REG_V8, REG_T0)
        VMV_S_X(REG_V9, REG_T1)
        VMV_S_X(REG_V10, REG_T2)

    "L_poly1305_riscv64_vec_loop_%=:\n\t"
        /* m0 + nfin */
        "ld     t0, 0(%[m])\n\t"
        "ld     t1, 8(%[m])\n\t"
        "li     t6, 1\n\t"
        /* Split m into 24, 52, 52 */
        SPLIT_130(t2, t3, t4, t0, t1, t6, t5)
        VMV_S_X(REG_V11, REG_T2)
        VMV_S_X(REG_V12, REG_T3)
        VMV_S_X(REG_V13, REG_T4)
        /* m1+ nfin */
        "ld     t0, 16(%[m])\n\t"
        "ld     t1, 24(%[m])\n\t"
        /* Split m into 24, 52, 52 */
        SPLIT_130(t2, t3, t4, t0, t1, t6, t5)
        VMV_S_X(REG_V14, REG_T2)
        VMV_S_X(REG_V15, REG_T3)
        VMV_S_X(REG_V16, REG_T4)
        /* h += m0 + nfin */
        VADD_VV(REG_V8, REG_V8, REG_V11)
        VADD_VV(REG_V9, REG_V9, REG_V12)
        VADD_VV(REG_V10, REG_V10, REG_V13)
        /* h[0]|m1[0], h[1]|m1[1], h[2]|m1[2] */
        VSLIDEUP_VI(REG_V8, REG_V14, 1)
        VSLIDEUP_VI(REG_V9, REG_V15, 1)
        VSLIDEUP_VI(REG_V10, REG_V16, 1)

        /* hm[0] * r2r[0] */
        VMUL_VV(REG_V11, REG_V8, REG_V2)
        VMULHU_VV(REG_V12, REG_V8, REG_V2)
        MUL_RES_REDIS(REG_V11, REG_V12, REG_V18)

        /* + hm[0] * r2r[1] */
        VMUL_VV(REG_V14, REG_V8, REG_V3)
        VMULHU_VV(REG_V13, REG_V8, REG_V3)
        MUL_RES_REDIS(REG_V14, REG_V13, REG_V18)
        VADD_VV(REG_V12, REG_V12, REG_V14)
        /* + hm[1] * r2r[0] */
        VMUL_VV(REG_V14, REG_V9, REG_V2)
        VMULHU_VV(REG_V15, REG_V9, REG_V2)
        MUL_RES_REDIS(REG_V14, REG_V15, REG_V18)
        VADD_VV(REG_V12, REG_V12, REG_V14)
        VADD_VV(REG_V13, REG_V13, REG_V15)

        /* + hm[0] * r2r[2] */
        VMUL_VV(REG_V15, REG_V8, REG_V4)
        VMULHU_VV(REG_V14, REG_V8, REG_V4)
        MUL_RES_REDIS(REG_V15, REG_V14, REG_V18)
        VADD_VV(REG_V13, REG_V13, REG_V15)
        /* + hm[1] * r2r[1] */
        VMUL_VV(REG_V15, REG_V9, REG_V3)
        VMULHU_VV(REG_V16, REG_V9, REG_V3)
        MUL_RES_REDIS(REG_V15, REG_V16, REG_V18)
        VADD_VV(REG_V13, REG_V13, REG_V15)
        VADD_VV(REG_V14, REG_V14, REG_V16)
        /* + hm[2] * r2r[0] */
        VMUL_VV(REG_V15, REG_V10, REG_V2)
        VMULHU_VV(REG_V16, REG_V10, REG_V2)
        MUL_RES_REDIS(REG_V15, REG_V16, REG_V18)
        VADD_VV(REG_V13, REG_V13, REG_V15)
        VADD_VV(REG_V14, REG_V14, REG_V16)

        /* + hm[1] * r2r[2] */
        VMUL_VV(REG_V16, REG_V9, REG_V4)
        VMULHU_VV(REG_V15, REG_V9, REG_V4)
        MUL_RES_REDIS(REG_V16, REG_V15, REG_V18)
        VADD_VV(REG_V14, REG_V14, REG_V16)
        /* + hm[2] * r2r[1] */
        VMUL_VV(REG_V16, REG_V10, REG_V3)
        VMULHU_VV(REG_V17, REG_V10, REG_V3)
        MUL_RES_REDIS(REG_V16, REG_V17, REG_V18)
        VADD_VV(REG_V14, REG_V14, REG_V16)
        VADD_VV(REG_V15, REG_V15, REG_V17)

        /* + hm[2] * r2r[2] */
        VMUL_VV(REG_V17, REG_V10, REG_V4)
        VADD_VV(REG_V15, REG_V15, REG_V17)

        /* Get m1 * r down */
        VSLIDEDOWN_VI(REG_V18, REG_V11, 1)
        VSLIDEDOWN_VI(REG_V19, REG_V12, 1)
        VSLIDEDOWN_VI(REG_V20, REG_V13, 1)
        VSLIDEDOWN_VI(REG_V21, REG_V14, 1)
        VSLIDEDOWN_VI(REG_V22, REG_V15, 1)

        /* Add (h + m0) * r^2 + m1 * r */
        VADD_VV(REG_V11, REG_V11, REG_V18)
        VADD_VV(REG_V12, REG_V12, REG_V19)
        VADD_VV(REG_V13, REG_V13, REG_V20)
        VADD_VV(REG_V14, REG_V14, REG_V21)
        VADD_VV(REG_V15, REG_V15, REG_V22)

        /* h' % 2^130-5 */
        VSLL_VI(REG_V8, REG_V14, 26)
        VSLL_VI(REG_V9, REG_V15, 26)
        VAND_VX(REG_V8, REG_V8, REG_A4)
        VAND_VX(REG_V9, REG_V9, REG_A4)
        VSRL_VI(REG_V10, REG_V13, 26)
        VAND_VX(REG_V13, REG_V13, REG_A5)
        VSRL_VI(REG_V14, REG_V14, 26)
        VSRL_VI(REG_V15, REG_V15, 26)
        VADD_VV(REG_V10, REG_V10, REG_V8)
        VADD_VV(REG_V14, REG_V14, REG_V9)

        VSLL_VI(REG_V16, REG_V10, 2)
        VSLL_VI(REG_V17, REG_V14, 2)
        VSLL_VI(REG_V18, REG_V15, 2)
        VADD_VV(REG_V10, REG_V10, REG_V16)
        VADD_VV(REG_V14, REG_V14, REG_V17)
        VADD_VV(REG_V15, REG_V15, REG_V18)

        VADD_VV(REG_V8, REG_V11, REG_V10)
        VADD_VV(REG_V9, REG_V12, REG_V14)
        VADD_VV(REG_V10, REG_V13, REG_V15)

        /* h'' % 2^130-5 */
        VAND_VX(REG_V11, REG_V10, REG_A4)
        VAND_VX(REG_V10, REG_V10, REG_A5)
        VSRL_VI(REG_V12, REG_V11, 24)
        VSRL_VI(REG_V11, REG_V11, 26)
        VADD_VV(REG_V11, REG_V11, REG_V12)
        VADD_VV(REG_V8, REG_V8, REG_V11)

        "addi   %[bytes], %[bytes], -32\n\t"
        "addi   %[m], %[m], 32\n\t"
        "bgez   %[bytes], L_poly1305_riscv64_vec_loop_%=\n\t"

        VMV_X_S(REG_S3, REG_V8)
        VMV_X_S(REG_S4, REG_V9)
        VMV_X_S(REG_S5, REG_V10)

        "sd     s3, 0(%[h])\n\t"
        "sd     s4, 8(%[h])\n\t"
        "sd     s5, 16(%[h])\n\t"

        "\n"
    "L_poly1305_riscv64_vec_done_%=:\n\t"
        "addi   %[bytes], %[bytes], 32\n\t"
        : [bytes] "+r" (bytes), [m] "+r" (m)
        : [r2] "r" (ctx->r2), [h] "r" (ctx->h)
        : "memory", "t0", "t1", "t2", "t3", "t4", "t5", "t6",
          "s3", "s4", "s5", "a4", "a5", "a6", "a7"
    );
#endif
    poly1305_blocks_riscv64_16(ctx, m, bytes, 1);
}

void poly1305_block_riscv64(Poly1305* ctx, const unsigned char *m)
{
    poly1305_blocks_riscv64_16(ctx, m, POLY1305_BLOCK_SIZE, 1);
}

#if defined(POLY130564)
static word64 clamp[] = {
    0x0ffffffc0fffffff,
    0x0ffffffc0ffffffc,
};
#endif /* POLY130564 */


int wc_Poly1305SetKey(Poly1305* ctx, const byte* key, word32 keySz)
{
    if (key == NULL)
        return BAD_FUNC_ARG;

#ifdef CHACHA_AEAD_TEST
    word32 k;
    printf("Poly key used:\n");
    for (k = 0; k < keySz; k++) {
        printf("%02x", key[k]);
        if ((k+1) % 8 == 0)
            printf("\n");
    }
    printf("\n");
#endif

    if (keySz != 32 || ctx == NULL)
        return BAD_FUNC_ARG;

    __asm__ __volatile__ (
        /* Load key material */
        "ld     t0, 0(%[key])\n\t"
        "ld     t1, 8(%[key])\n\t"
        "ld     t2, 16(%[key])\n\t"
        "ld     t3, 24(%[key])\n\t"
        /* Load clamp */
        "ld     t4, 0(%[clamp])\n\t"
        "ld     t5, 8(%[clamp])\n\t"
        /* Save pad for later */
        "sd     t2, 0(%[ctx_pad])\n\t"
        "sd     t3, 8(%[ctx_pad])\n\t"
        /* Apply clamp */
        /* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
        "and    t0, t0, t4\n\t"
        "and    t1, t1, t5\n\t"
        /* Store r */
        "sd     t0, 0(%[ctx_r])\n\t"
        "sd     t1, 8(%[ctx_r])\n\t"

#ifdef WOLFSSL_RISCV_VECTOR
        "li     a6, 0xfffffffffffff\n\t"
        /* Split r into parts less than 64 */
        SPLIT_128(t2, t3, t4, t0, t1, t5)
        /* Store r */
        "sd     t2, 8(%[ctx_r2])\n\t"
        "sd     t3, 24(%[ctx_r2])\n\t"
        "sd     t4, 40(%[ctx_r2])\n\t"

        /* r * r */
        /*   r[0] * r[0] - 0, 1 */
        "mul    t2, t0, t0\n\t"
        "mulhu  t3, t0, t0\n\t"
        /* + r[0] * r[1] - 1, 2 */
        "mul    t5, t1, t0\n\t"
        "mulhu  t6, t1, t0\n\t"
        "add    t3, t3, t5\n\t"
        "sltu   s1, t3, t5\n\t"
        "add    t4, t6, s1\n\t"
        /* + r[1] * r[0] - 1, 2 */
        "add    t3, t3, t5\n\t"
        "sltu   s1, t3, t5\n\t"
        "add    t4, t4, s1\n\t"
        "add    t4, t4, t6\n\t"
        "sltu   t5, t4, t6\n\t"
        /* + r[1] * r[1] - 2, 3 */
        "mul    s1, t1, t1\n\t"
        "mulhu  t6, t1, t1\n\t"
        "add    t4, t4, s1\n\t"
        "sltu   s1, t4, s1\n\t"
        "add    t5, t5, t6\n\t"
        "add    t5, t5, s1\n\t"
        /* (r * r) % (2 ^ 130 - 5) */
        "andi   t6, t4, -4\n\t"
        "andi   t4, t4, 3\n\t"
        /* r[0..129] + r[130-191] * 4 */
        "add    t2, t2, t6\n\t"
        "sltu   s1, t2, t6\n\t"
        "add    t3, t3, s1\n\t"
        "sltu   s1, t3, s1\n\t"
        "add    t4, t4, s1\n\t"
        /* r[0..129] + r[130-193] */
        "srli   t6, t6, 2\n\t"
        "slli   s1, t5, 62\n\t"
        "or     t6, t6, s1\n\t"
        "add    t2, t2, t6\n\t"
        "sltu   s1, t2, t6\n\t"
        "add    t3, t3, s1\n\t"
        "sltu   s1, t3, s1\n\t"
        "add    t4, t4, s1\n\t"
        /* r[64..129] + r[194-253] * 4 */
        "add    t3, t3, t5\n\t"
        "sltu   s1, t3, t5\n\t"
        "add    t4, t4, s1\n\t"
        /* r[64..129] + r[194-253] */
        "srli   t5, t5, 2\n\t"
        "add    t3, t3, t5\n\t"
        "sltu   s1, t3, t5\n\t"
        "add    t4, t4, s1\n\t"
        /* Split r^2 into parts less than 64 */
        SPLIT_130(t0, t1, t2, t2, t3, t4, t5)
        /* Store r^2 */
        "sd     t0, 0(%[ctx_r2])\n\t"
        "sd     t1, 16(%[ctx_r2])\n\t"
        "sd     t2, 32(%[ctx_r2])\n\t"
#endif

        /* h (accumulator) = 0 */
        "sd     x0, 0(%[ctx_h])\n\t"
        "sd     x0, 8(%[ctx_h])\n\t"
        "sd     x0, 16(%[ctx_h])\n\t"
        /* Zero leftover */
        "sd     x0, (%[ctx_leftover])\n\t"
        :
        : [clamp] "r" (clamp), [key] "r" (key), [ctx_r] "r" (ctx->r),
#ifdef WOLFSSL_RISCV_VECTOR
          [ctx_r2] "r" (ctx->r2),
#endif
          [ctx_h] "r" (ctx->h), [ctx_pad] "r" (ctx->pad),
          [ctx_leftover] "r" (&ctx->leftover)
        : "memory", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "s1"
#ifdef WOLFSSL_RISCV_VECTOR
                  , "a6"
#endif
    );

    return 0;
}


int wc_Poly1305Final(Poly1305* ctx, byte* mac)
{

    if (ctx == NULL)
        return BAD_FUNC_ARG;

    /* process the remaining block */
    if (ctx->leftover) {
        size_t i = ctx->leftover;
        ctx->buffer[i++] = 1;
        for (; i < POLY1305_BLOCK_SIZE; i++)
            ctx->buffer[i] = 0;
        poly1305_blocks_riscv64_16(ctx, ctx->buffer, POLY1305_BLOCK_SIZE, 0);
    }

    __asm__ __volatile__ (
        /* Load raw h and padding. */
        "ld     t0, %[ctx_h_0]\n\t"
        "ld     t1, %[ctx_h_1]\n\t"
        "ld     t2, %[ctx_h_2]\n\t"
        "ld     t3, %[ctx_pad_0]\n\t"
        "ld     t4, %[ctx_pad_1]\n\t"

        /* Shrink h to 2,64,64. */
        "slli   t5, t1, 52\n\t"
        "slli   t6, t2, 40\n\t"
        "srli   t1, t1, 12\n\t"
        "srli   t2, t2, 24\n\t"
        "add    t1, t1, t6\n\t"
        "sltu   t6, t1, t6\n\t"
        "add    t2, t2, t6\n\t"
        "add    t0, t0, t5\n\t"
        "sltu   t5, t0, t5\n\t"
        "add    t1, t1, t5\n\t"
        "sltu   t5, t1, t5\n\t"
        "add    t2, t2, t5\n\t"

        /* Add padding to h */
        "add    t0, t0, t3\n\t"
        "sltu   t3, t0, t3\n\t"
        "add    t1, t1, t3\n\t"
        "sltu   t3, t1, t3\n\t"
        "add    t2, t2, t3\n\t"
        "add    t1, t1, t4\n\t"
        "sltu   t4, t1, t4\n\t"
        "add    t2, t2, t4\n\t"

        /* Check if h is larger than p */
        "addi   t3, t0, 5\n\t"
        "sltiu  t3, t3, 5\n\t"
        "add    t4, t1, t3\n\t"
        "sltu   t3, t4, t3\n\t"
        "add    t4, t2, t3\n\t"
        /* Check if h+5 is larger than 2^130 */
        "addi   t4, t4, -4\n\t"
        "srli   t4, t4, 63\n\t"
        "addi   t4, t4, -1\n\t"
        "andi   t4, t4, 5\n\t"
        "add    t0, t0, t4\n\t"
        "sltu   t3, t0, t4\n\t"
        "add    t1, t1, t3\n\t"
        "sltu   t3, t1, t3\n\t"
        "add    t2, t2, t3\n\t"
        "andi   t2, t2, 3\n\t"
        "sd     t0, 0(%[mac])\n\t"
        "sd     t1, 8(%[mac])\n\t"
        /* Zero out h. */
        "sd     x0, %[ctx_h_0]\n\t"
        "sd     x0, %[ctx_h_1]\n\t"
        "sd     x0, %[ctx_h_2]\n\t"
        /* Zero out r. */
        "sd     x0, %[ctx_r_0]\n\t"
        "sd     x0, %[ctx_r_1]\n\t"
        /* Zero out pad. */
        "ld     t3, %[ctx_pad_0]\n\t"
        "ld     t4, %[ctx_pad_1]\n\t"
        : [mac] "+r" (mac)
        : [ctx_pad_0] "m" (ctx->pad[0]), [ctx_pad_1] "m" (ctx->pad[1]),
          [ctx_h_0] "m" (ctx->h[0]), [ctx_h_1] "m" (ctx->h[1]),
          [ctx_h_2] "m" (ctx->h[2]),
          [ctx_r_0] "m" (ctx->r[0]), [ctx_r_1] "m" (ctx->r[1])
        : "memory", "t0", "t1", "t2", "t3", "t4", "t5", "t6"
    );

    return 0;
}

#endif /* HAVE_POLY1305 */
#endif /* WOLFSSL_RISCV_ASM */
