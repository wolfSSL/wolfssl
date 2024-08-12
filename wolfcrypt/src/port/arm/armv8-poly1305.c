/* armv8-poly1305.c
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

#ifdef WOLFSSL_ARMASM
#ifdef __aarch64__

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

static WC_INLINE void poly1305_blocks_aarch64_16(Poly1305* ctx,
    const unsigned char *m, size_t bytes)
{
    __asm__ __volatile__ (
        /* Check for zero bytes to do. */
        "CMP        %[bytes], %[POLY1305_BLOCK_SIZE] \n\t"
        "BLO        L_poly1305_aarch64_16_done_%= \n\t"

        "MOV        x12, #1               \n\t"
        /* Load h */
        "LDP        w4, w5, [%[ctx_h], #0]   \n\t"
        "LDP        w6, w7, [%[ctx_h], #8]   \n\t"
        "LDR        w8, [%[ctx_h], #16]   \n\t"
        /* Base 26 -> Base 64 */
        "ORR        x4, x4, x5, LSL #26\n\t"
        "ORR        x4, x4, x6, LSL #52\n\t"
        "LSR        x5, x6, #12\n\t"
        "ORR        x5, x5, x7, LSL #14\n\t"
        "ORR        x5, x5, x8, LSL #40\n\t"
        "LSR        x6, x8, #24\n\t"
        /* Load r */
        "LDP        x8, x9, %[ctx_r64]   \n\t"
        "SUB        %[finished], x12, %[finished]\n\t"
        "\n"
        ".align 2 \n\t"
    "L_poly1305_aarch64_16_loop_%=: \n\t"
        /* Load m */
        "LDR        x10, [%[m]]          \n\t"
        "LDR        x11, [%[m], 8]       \n\t"
        /* Add m and !finished at bit 128. */
        "ADDS       x4, x4, x10          \n\t"
        "ADCS       x5, x5, x11          \n\t"
        "ADC        x6, x6, %[finished]  \n\t"

        /* r * h */
        /* r0 * h0 */
        "MUL        x12, x8, x4\n\t"
        "UMULH      x13, x8, x4\n\t"
        /* r0 * h1 */
        "MUL        x16, x8, x5\n\t"
        "UMULH      x14, x8, x5\n\t"
        /* r1 * h0 */
        "MUL        x15, x9, x4\n\t"
        "ADDS       x13, x13, x16\n\t"
        "UMULH      x17, x9, x4\n\t"
        "ADC        x14, x14, xzr\n\t"
        "ADDS       x13, x13, x15\n\t"
        /* r0 * h2 */
        "MUL        x16, x8, x6\n\t"
        "ADCS       x14, x14, x17\n\t"
        "UMULH      x17, x8, x6\n\t"
        "ADC        x15, xzr, xzr\n\t"
        "ADDS       x14, x14, x16\n\t"
        /* r1 * h1 */
        "MUL        x16, x9, x5\n\t"
        "ADC        x15, x15, x17\n\t"
        "UMULH      x19, x9, x5\n\t"
        "ADDS       x14, x14, x16\n\t"
        /* r1 * h2 */
        "MUL        x17, x9, x6\n\t"
        "ADCS       x15, x15, x19\n\t"
        "UMULH      x19, x9, x6\n\t"
        "ADC        x16, xzr, xzr\n\t"
        "ADDS       x15, x15, x17\n\t"
        "ADC        x16, x16, x19\n\t"
        /* h' = x12, x13, x14, x15, x16 */

        /* h' mod 2^130 - 5 */
        /* Get top two bits from h[2]. */
        "AND        x6, x14, 3\n\t"
        /* Get high bits from h[2]. */
        "AND        x14, x14, -4\n\t"
        /* Add top bits * 4. */
        "ADDS       x4, x12, x14\n\t"
        "ADCS       x5, x13, x15\n\t"
        "ADC        x6, x6, x16\n\t"
        /* Move down 2 bits. */
        "EXTR       x14, x15, x14, 2\n\t"
        "EXTR       x15, x16, x15, 2\n\t"
        /* Add top bits. */
        "ADDS       x4, x4, x14\n\t"
        "ADCS       x5, x5, x15\n\t"
        "ADC        x6, x6, xzr\n\t"

        "SUBS       %[bytes], %[bytes], %[POLY1305_BLOCK_SIZE]\n\t"
        "ADD        %[m], %[m], %[POLY1305_BLOCK_SIZE]\n\t"
        "BGT        L_poly1305_aarch64_16_loop_%=\n\t"

        /* Base 64 -> Base 26 */
        "MOV        x10, #0x3ffffff\n\t"
        "EXTR       x8, x6, x5, #40\n\t"
        "AND        x7, x10, x5, LSR #14\n\t"
        "EXTR       x6, x5, x4, #52\n\t"
        "AND        x5, x10, x4, LSR #26\n\t"
        "AND        x4, x4, x10\n\t"
        "AND        x6, x6, x10\n\t"
        "AND        x8, x8, x10\n\t"
        "STP        w4, w5, [%[ctx_h], #0]   \n\t"
        "STP        w6, w7, [%[ctx_h], #8]   \n\t"
        "STR        w8, [%[ctx_h], #16]   \n\t"
        "\n"
        ".align 2 \n\t"
    "L_poly1305_aarch64_16_done_%=: \n\t"
        : [bytes] "+r" (bytes), [m] "+r" (m)
        : [POLY1305_BLOCK_SIZE] "I" (POLY1305_BLOCK_SIZE),
          [ctx_r64] "m" (ctx->r64[0]), [ctx_h] "r" (ctx->h),
          [finished] "r" ((word64)ctx->finished)
        : "memory", "cc",
          "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14",
          "x15", "x16", "x17", "x19"
    );
}

void poly1305_blocks_aarch64(Poly1305* ctx, const unsigned char *m,
    size_t bytes)
{
    __asm__ __volatile__ (
        /* If less than 4 blocks to process then use regular method */
        "CMP        %[bytes], %[POLY1305_BLOCK_SIZE]*4 \n\t"
        "BLO        L_poly1305_aarch64_64_done_%= \n\t"
        "MOV        x9, #0x3ffffff       \n\t"
        /* Load h */
        "LDP        x20, x22, [%[h]]     \n\t"
        "MOV        v27.D[0], x9         \n\t"
        "LDR        w24, [%[h], #16]     \n\t"
        "MOV        v27.D[1], x9         \n\t"
        "LSR        x21, x20, #32        \n\t"
        "DUP        v29.4S, v27.S[0]     \n\t"
        "LSR        x23, x22, #32        \n\t"
        "MOV        x9, #5               \n\t"
        "AND        x20, x20, #0x3ffffff \n\t"
        "MOV        v28.D[0], x9         \n\t"
        "AND        x22, x22, #0x3ffffff \n\t"
        /* Zero accumulator registers */
        "MOVI       v15.16B, #0x0        \n\t"
        "MOVI       v16.16B, #0x0        \n\t"
        "MOVI       v17.16B, #0x0        \n\t"
        "MOVI       v18.16B, #0x0        \n\t"
        "MOVI       v19.16B, #0x0        \n\t"
        /* Set hibit */
        "CMP        %[finished], #0      \n\t"
        "CSET       x9, EQ               \n\t"
        "LSL        x9, x9, #24          \n\t"
        "MOV        v26.D[0], x9         \n\t"
        "MOV        v26.D[1], x9         \n\t"
        "DUP        v30.4S, v26.S[0]     \n\t"
        "CMP        %[bytes], %[POLY1305_BLOCK_SIZE]*6 \n\t"
        "BLO        L_poly1305_aarch64_64_start_block_size_64_%= \n\t"
        /* Load r^2 to NEON v0, v1, v2, v3, v4 */
        "LD4        { v0.S-v3.S }[2], [%[r_2]], #16 \n\t"
        "LD1        { v4.S }[2], [%[r_2]] \n\t"
        "SUB        %[r_2], %[r_2], #16  \n\t"
        /* Load r^4 to NEON v0, v1, v2, v3, v4 */
        "LD4        { v0.S-v3.S }[0], [%[r_4]], #16 \n\t"
        "LD1        { v4.S }[0], [%[r_4]] \n\t"
        "SUB        %[r_4], %[r_4], #16  \n\t"
        "MOV        v0.S[1], v0.S[0]     \n\t"
        "MOV        v0.S[3], v0.S[2]     \n\t"
        "MOV        v1.S[1], v1.S[0]     \n\t"
        "MOV        v1.S[3], v1.S[2]     \n\t"
        "MOV        v2.S[1], v2.S[0]     \n\t"
        "MOV        v2.S[3], v2.S[2]     \n\t"
        "MOV        v3.S[1], v3.S[0]     \n\t"
        "MOV        v3.S[3], v3.S[2]     \n\t"
        "MOV        v4.S[1], v4.S[0]     \n\t"
        "MOV        v4.S[3], v4.S[2]     \n\t"
        /* Store [r^4, r^2] * 5 */
        "MUL        v5.4S, v0.4S, v28.S[0] \n\t"
        "MUL        v6.4S, v1.4S, v28.S[0] \n\t"
        "MUL        v7.4S, v2.4S, v28.S[0] \n\t"
        "MUL        v8.4S, v3.4S, v28.S[0] \n\t"
        "MUL        v9.4S, v4.4S, v28.S[0] \n\t"
        /* Copy r^4 to ARM */
        "MOV        w25, v0.S[0]         \n\t"
        "MOV        w26, v1.S[0]         \n\t"
        "MOV        w27, v2.S[0]         \n\t"
        "MOV        w28, v3.S[0]         \n\t"
        "MOV        w30, v4.S[0]         \n\t"
        /* Copy 5*r^4 to ARM */
        "MOV        w15, v5.S[0]         \n\t"
        "MOV        w16, v6.S[0]         \n\t"
        "MOV        w17, v7.S[0]         \n\t"
        "MOV        w8, v8.S[0]          \n\t"
        "MOV        w19, v9.S[0]         \n\t"
        /* Load m */
        /* Load four message blocks to NEON v10, v11, v12, v13, v14 */
        "LD4        { v10.4S-v13.4S }, [%[m]], #64 \n\t"
        "SUB        %[bytes], %[bytes], %[POLY1305_BLOCK_SIZE]*4 \n\t"
        "USHR       v14.4S, v13.4S, #8   \n\t"
        "ORR        v14.16B, v14.16B, v30.16B \n\t"
        "SHL        v13.4S, v13.4S, #18  \n\t"
        "SRI        v13.4S, v12.4S, #14  \n\t"
        "SHL        v12.4S, v12.4S, #12  \n\t"
        "SRI        v12.4S, v11.4S, #20  \n\t"
        "SHL        v11.4S, v11.4S, #6   \n\t"
        "SRI        v11.4S, v10.4S, #26  \n\t"
        "AND        v10.16B, v10.16B, v29.16B \n\t"
        "AND        v11.16B, v11.16B, v29.16B \n\t"
        "AND        v12.16B, v12.16B, v29.16B \n\t"
        "AND        v13.16B, v13.16B, v29.16B \n\t"
        "AND        v14.16B, v14.16B, v29.16B \n\t"
        /* Four message blocks loaded */
        /* Add messages to accumulator */
        "ADD        v15.2S, v15.2S, v10.2S \n\t"
        "ADD        v16.2S, v16.2S, v11.2S \n\t"
        "ADD        v17.2S, v17.2S, v12.2S \n\t"
        "ADD        v18.2S, v18.2S, v13.2S \n\t"
        "ADD        v19.2S, v19.2S, v14.2S \n\t"
        "\n"
        ".align 2 \n\t"
    "L_poly1305_aarch64_64_loop_128_%=: \n\t"
        /* d0 = h0*r0 + h1*s4 + h2*s3 + h3*s2 + h4*s1 */
        /* d1 = h0*r1 + h1*r0 + h2*s4 + h3*s3 + h4*s2 */
        /* d2 = h0*r2 + h1*r1 + h2*r0 + h3*s4 + h4*s3 */
        /* d3 = h0*r3 + h1*r2 + h2*r1 + h3*r0 + h4*s4 */
        /* d4 = h0*r4 + h1*r3 + h2*r2 + h3*r1 + h4*r0 */
        "UMULL      v21.2D, v15.2S, v0.2S \n\t"
        /* Compute h*r^2 */
        /* d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1 */
        /* d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2 */
        /* d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3 */
        /* d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4 */
        /* d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0 */
        "MUL        x9, x20, x25         \n\t"
        "UMULL      v22.2D, v15.2S, v1.2S \n\t"
        "MUL        x10, x20, x26        \n\t"
        "UMULL      v23.2D, v15.2S, v2.2S \n\t"
        "MUL        x11, x20, x27        \n\t"
        "UMULL      v24.2D, v15.2S, v3.2S \n\t"
        "MUL        x12, x20, x28        \n\t"
        "UMULL      v25.2D, v15.2S, v4.2S \n\t"
        "MUL        x13, x20, x30        \n\t"
        "UMLAL      v21.2D, v16.2S, v9.2S \n\t"
        "MADD       x9, x21, x19, x9     \n\t"
        "UMLAL      v22.2D, v16.2S, v0.2S \n\t"
        "MADD       x10, x21, x25, x10   \n\t"
        "UMLAL      v23.2D, v16.2S, v1.2S \n\t"
        "MADD       x11, x21, x26, x11   \n\t"
        "UMLAL      v24.2D, v16.2S, v2.2S \n\t"
        "MADD       x12, x21, x27, x12   \n\t"
        "UMLAL      v25.2D, v16.2S, v3.2S \n\t"
        "MADD       x13, x21, x28, x13   \n\t"
        "UMLAL      v21.2D, v17.2S, v8.2S \n\t"
        "MADD       x9, x22, x8, x9      \n\t"
        "UMLAL      v22.2D, v17.2S, v9.2S \n\t"
        "MADD       x10, x22, x19, x10   \n\t"
        "UMLAL      v23.2D, v17.2S, v0.2S \n\t"
        "MADD       x11, x22, x25, x11   \n\t"
        "UMLAL      v24.2D, v17.2S, v1.2S \n\t"
        "MADD       x12, x22, x26, x12   \n\t"
        "UMLAL      v25.2D, v17.2S, v2.2S \n\t"
        "MADD       x13, x22, x27, x13   \n\t"
        "UMLAL      v21.2D, v18.2S, v7.2S \n\t"
        "MADD       x9, x23, x17, x9     \n\t"
        "UMLAL      v22.2D, v18.2S, v8.2S \n\t"
        "MADD       x10, x23, x8, x10    \n\t"
        "UMLAL      v23.2D, v18.2S, v9.2S \n\t"
        "MADD       x11, x23, x19, x11   \n\t"
        "UMLAL      v24.2D, v18.2S, v0.2S \n\t"
        "MADD       x12, x23, x25, x12   \n\t"
        "UMLAL      v25.2D, v18.2S, v1.2S \n\t"
        "MADD       x13, x23, x26, x13   \n\t"
        "UMLAL      v21.2D, v19.2S, v6.2S \n\t"
        "MADD       x9, x24, x16, x9     \n\t"
        "UMLAL      v22.2D, v19.2S, v7.2S \n\t"
        "MADD       x10, x24, x17, x10   \n\t"
        "UMLAL      v23.2D, v19.2S, v8.2S \n\t"
        "MADD       x11, x24, x8, x11    \n\t"
        "UMLAL      v24.2D, v19.2S, v9.2S \n\t"
        "MADD       x12, x24, x19, x12   \n\t"
        "UMLAL      v25.2D, v19.2S, v0.2S \n\t"
        "MADD       x13, x24, x25, x13   \n\t"
        /* d0 = h0*r0 + h1*s4 + h2*s3 + h3*s2 + h4*s1 */
        /* d1 = h0*r1 + h1*r0 + h2*s4 + h3*s3 + h4*s2 */
        /* d2 = h0*r2 + h1*r1 + h2*r0 + h3*s4 + h4*s3 */
        /* d3 = h0*r3 + h1*r2 + h2*r1 + h3*r0 + h4*s4 */
        /* d4 = h0*r4 + h1*r3 + h2*r2 + h3*r1 + h4*r0 */
        "UMLAL2     v21.2D, v10.4S, v0.4S \n\t"
        /* Reduce h % P */
        "MOV        x14, #5              \n\t"
        "UMLAL2     v22.2D, v10.4S, v1.4S \n\t"
        "ADD        x10, x10, x9, LSR #26 \n\t"
        "UMLAL2     v23.2D, v10.4S, v2.4S \n\t"
        "ADD        x13, x13, x12, LSR #26 \n\t"
        "UMLAL2     v24.2D, v10.4S, v3.4S \n\t"
        "AND        x9, x9, #0x3ffffff   \n\t"
        "UMLAL2     v25.2D, v10.4S, v4.4S \n\t"
        "LSR        x20, x13, #26        \n\t"
        "UMLAL2     v21.2D, v11.4S, v9.4S \n\t"
        "AND        x12, x12, #0x3ffffff \n\t"
        "UMLAL2     v22.2D, v11.4S, v0.4S \n\t"
        "MADD       x9, x20, x14, x9     \n\t"
        "UMLAL2     v23.2D, v11.4S, v1.4S \n\t"
        "ADD        x11, x11, x10, LSR #26 \n\t"
        "UMLAL2     v24.2D, v11.4S, v2.4S \n\t"
        "AND        x10, x10, #0x3ffffff \n\t"
        "UMLAL2     v25.2D, v11.4S, v3.4S \n\t"
        "AND        x13, x13, #0x3ffffff \n\t"
        "UMLAL2     v21.2D, v12.4S, v8.4S \n\t"
        "ADD        x12, x12, x11, LSR #26 \n\t"
        "UMLAL2     v22.2D, v12.4S, v9.4S \n\t"
        "AND        x22, x11, #0x3ffffff \n\t"
        "UMLAL2     v23.2D, v12.4S, v0.4S \n\t"
        "ADD        x21, x10, x9, LSR #26 \n\t"
        "UMLAL2     v24.2D, v12.4S, v1.4S \n\t"
        "AND        x20, x9, #0x3ffffff  \n\t"
        "UMLAL2     v25.2D, v12.4S, v2.4S \n\t"
        "ADD        x24, x13, x12, LSR #26 \n\t"
        "UMLAL2     v21.2D, v13.4S, v7.4S \n\t"
        "AND        x23, x12, #0x3ffffff \n\t"
        "UMLAL2     v22.2D, v13.4S, v8.4S \n\t"
        "UMLAL2     v23.2D, v13.4S, v9.4S \n\t"
        "UMLAL2     v24.2D, v13.4S, v0.4S \n\t"
        "UMLAL2     v25.2D, v13.4S, v1.4S \n\t"
        "UMLAL2     v21.2D, v14.4S, v6.4S \n\t"
        "UMLAL2     v22.2D, v14.4S, v7.4S \n\t"
        "UMLAL2     v23.2D, v14.4S, v8.4S \n\t"
        "UMLAL2     v24.2D, v14.4S, v9.4S \n\t"
        "UMLAL2     v25.2D, v14.4S, v0.4S \n\t"
        /* If less than six message blocks left then leave loop */
        "CMP        %[bytes], %[POLY1305_BLOCK_SIZE]*6 \n\t"
        "BLS        L_poly1305_aarch64_64_loop_128_final_%= \n\t"
        /* Load m */
        /* Load four message blocks to NEON v10, v11, v12, v13, v14 */
        "LD4        { v10.4S-v13.4S }, [%[m]], #64 \n\t"
        "SUB        %[bytes], %[bytes], %[POLY1305_BLOCK_SIZE]*4 \n\t"
        "USHR       v14.4S, v13.4S, #8   \n\t"
        "ORR        v14.16B, v14.16B, v30.16B \n\t"
        "SHL        v13.4S, v13.4S, #18  \n\t"
        "SRI        v13.4S, v12.4S, #14  \n\t"
        "SHL        v12.4S, v12.4S, #12  \n\t"
        "SRI        v12.4S, v11.4S, #20  \n\t"
        "SHL        v11.4S, v11.4S, #6   \n\t"
        "SRI        v11.4S, v10.4S, #26  \n\t"
        "AND        v10.16B, v10.16B, v29.16B \n\t"
        "AND        v11.16B, v11.16B, v29.16B \n\t"
        "AND        v12.16B, v12.16B, v29.16B \n\t"
        "AND        v13.16B, v13.16B, v29.16B \n\t"
        "AND        v14.16B, v14.16B, v29.16B \n\t"
        /* Four message blocks loaded */
        /* Add new message block to accumulator */
        "UADDW      v21.2D, v21.2D, v10.2S \n\t"
        "UADDW      v22.2D, v22.2D, v11.2S \n\t"
        "UADDW      v23.2D, v23.2D, v12.2S \n\t"
        "UADDW      v24.2D, v24.2D, v13.2S \n\t"
        "UADDW      v25.2D, v25.2D, v14.2S \n\t"
        /* Reduce radix 26 NEON */
        /* Interleave h0 -> h1 -> h2 -> h3 -> h4 */
        /*       with h3 -> h4 -> h0 -> h1 */
        "USRA       v22.2D, v21.2D, #26  \n\t"
        "AND        v21.16B, v21.16B, v27.16B \n\t"
        "USRA       v25.2D, v24.2D, #26  \n\t"
        "AND        v24.16B, v24.16B, v27.16B \n\t"
        "USHR       v15.2D, v25.2D, #26  \n\t"
        "USRA       v23.2D, v22.2D, #26  \n\t"
        /* Simulate multiplying by 5 using adding and shifting */
        "SHL        v18.2D, v15.2D, #2   \n\t"
        "AND        v16.16B, v22.16B, v27.16B \n\t"
        "ADD        v18.2D, v18.2D, v15.2D \n\t"
        "AND        v19.16B, v25.16B, v27.16B \n\t"
        "ADD        v21.2D, v21.2D, v18.2D \n\t"
        "USRA       v24.2D, v23.2D, #26  \n\t"
        "AND        v17.16B, v23.16B, v27.16B \n\t"
        "USRA       v16.2D, v21.2D, #26  \n\t"
        "AND        v15.16B, v21.16B, v27.16B \n\t"
        "USRA       v19.2D, v24.2D, #26  \n\t"
        "AND        v18.16B, v24.16B, v27.16B \n\t"
        /* Copy values to lower halves of result registers */
        "MOV        v15.S[1], v15.S[2]   \n\t"
        "MOV        v16.S[1], v16.S[2]   \n\t"
        "MOV        v17.S[1], v17.S[2]   \n\t"
        "MOV        v18.S[1], v18.S[2]   \n\t"
        "MOV        v19.S[1], v19.S[2]   \n\t"
        "B          L_poly1305_aarch64_64_loop_128_%= \n\t"
        "\n"
        ".align 2 \n\t"
    "L_poly1305_aarch64_64_loop_128_final_%=: \n\t"
        /* Load m */
        /* Load two message blocks to NEON v10, v11, v12, v13, v14 */
        "LD2        { v10.2D-v11.2D }, [%[m]], #32 \n\t"
        /* Copy r^2 to lower half of registers */
        "MOV        v0.D[0], v0.D[1]     \n\t"
        "SUB        %[bytes], %[bytes], %[POLY1305_BLOCK_SIZE]*2 \n\t"
        "MOV        v5.D[0], v5.D[1]     \n\t"
        "USHR       v14.2D, v11.2D, #40  \n\t"
        "MOV        v1.D[0], v1.D[1]     \n\t"
        "ORR        v14.16B, v14.16B, v26.16B \n\t"
        "MOV        v6.D[0], v6.D[1]     \n\t"
        "USHR       v13.2D, v11.2D, #14  \n\t"
        "MOV        v2.D[0], v2.D[1]     \n\t"
        "AND        v13.16B, v13.16B, v27.16B \n\t"
        "MOV        v7.D[0], v7.D[1]     \n\t"
        "SHL        v12.2D, v11.2D, #12  \n\t"
        "MOV        v3.D[0], v3.D[1]     \n\t"
        "SRI        v12.2D, v10.2D, #52  \n\t"
        "MOV        v8.D[0], v8.D[1]     \n\t"
        "AND        v12.16B, v12.16B, v27.16B \n\t"
        "MOV        v4.D[0], v4.D[1]     \n\t"
        "USHR       v11.2D, v10.2D, #26  \n\t"
        "MOV        v9.D[0], v9.D[1]     \n\t"
        "AND        v11.16B, v11.16B, v27.16B \n\t"
        /* Copy r^2 to ARM */
        "MOV        w25, v0.S[2]         \n\t"
        "AND        v10.16B, v10.16B, v27.16B \n\t"
        "MOV        w26, v1.S[2]         \n\t"
        /* Two message blocks loaded */
        /* Add last messages */
        "ADD        v21.2D, v21.2D, v10.2D \n\t"
        "MOV        w27, v2.S[2]         \n\t"
        "ADD        v22.2D, v22.2D, v11.2D \n\t"
        "MOV        w28, v3.S[2]         \n\t"
        "ADD        v23.2D, v23.2D, v12.2D \n\t"
        "MOV        w30, v4.S[2]         \n\t"
        "ADD        v24.2D, v24.2D, v13.2D \n\t"
        /* Copy 5*r^2 to ARM */
        "MOV        w15, v5.S[2]         \n\t"
        "ADD        v25.2D, v25.2D, v14.2D \n\t"
        "MOV        w16, v6.S[2]         \n\t"
        /* Reduce message to be ready for next multiplication */
        /* Reduce radix 26 NEON */
        /* Interleave h0 -> h1 -> h2 -> h3 -> h4 */
        /*       with h3 -> h4 -> h0 -> h1 */
        "USRA       v22.2D, v21.2D, #26  \n\t"
        "MOV        w17, v7.S[2]         \n\t"
        "AND        v21.16B, v21.16B, v27.16B \n\t"
        "MOV        w8, v8.S[2]          \n\t"
        "USRA       v25.2D, v24.2D, #26  \n\t"
        "MOV        w19, v9.S[2]         \n\t"
        "AND        v24.16B, v24.16B, v27.16B \n\t"
        "USHR       v15.2D, v25.2D, #26  \n\t"
        "USRA       v23.2D, v22.2D, #26  \n\t"
        /* Simulate multiplying by 5 using adding and shifting */
        "SHL        v18.2D, v15.2D, #2   \n\t"
        "AND        v16.16B, v22.16B, v27.16B \n\t"
        "ADD        v18.2D, v18.2D, v15.2D \n\t"
        "AND        v19.16B, v25.16B, v27.16B \n\t"
        "ADD        v21.2D, v21.2D, v18.2D \n\t"
        "USRA       v24.2D, v23.2D, #26  \n\t"
        "AND        v17.16B, v23.16B, v27.16B \n\t"
        "USRA       v16.2D, v21.2D, #26  \n\t"
        "AND        v15.16B, v21.16B, v27.16B \n\t"
        "USRA       v19.2D, v24.2D, #26  \n\t"
        "AND        v18.16B, v24.16B, v27.16B \n\t"
        /* Copy values to lower halves of result registers */
        "MOV        v15.S[1], v15.S[2]   \n\t"
        "MOV        v16.S[1], v16.S[2]   \n\t"
        "MOV        v17.S[1], v17.S[2]   \n\t"
        "MOV        v18.S[1], v18.S[2]   \n\t"
        "MOV        v19.S[1], v19.S[2]   \n\t"
        /* If less than 2 blocks left go straight to final multiplication. */
        "CMP        %[bytes], %[POLY1305_BLOCK_SIZE]*2 \n\t"
        "BLO        L_poly1305_aarch64_64_last_mult_%= \n\t"
        /* Else go to one loop of L_poly1305_aarch64_64_loop_64 */
        "B          L_poly1305_aarch64_64_loop_64_%= \n\t"
        "\n"
        ".align 2 \n\t"
    "L_poly1305_aarch64_64_start_block_size_64_%=: \n\t"
        /* Load r^2 to NEON v0, v1, v2, v3, v4 */
        "LD4R       { v0.2S-v3.2S }, [%[r_2]], #16 \n\t"
        "LD1R       { v4.2S }, [%[r_2]]  \n\t"
        "SUB        %[r_2], %[r_2], #16  \n\t"
        /* Store r^2 * 5 */
        "MUL        v5.4S, v0.4S, v28.S[0] \n\t"
        "MUL        v6.4S, v1.4S, v28.S[0] \n\t"
        "MUL        v7.4S, v2.4S, v28.S[0] \n\t"
        "MUL        v8.4S, v3.4S, v28.S[0] \n\t"
        "MUL        v9.4S, v4.4S, v28.S[0] \n\t"
        /* Copy r^2 to ARM */
        "MOV        w25, v0.S[0]         \n\t"
        "MOV        w26, v1.S[0]         \n\t"
        "MOV        w27, v2.S[0]         \n\t"
        "MOV        w28, v3.S[0]         \n\t"
        "MOV        w30, v4.S[0]         \n\t"
        /* Copy 5*r^2 to ARM */
        "MOV        w15, v5.S[0]         \n\t"
        "MOV        w16, v6.S[0]         \n\t"
        "MOV        w17, v7.S[0]         \n\t"
        "MOV        w8, v8.S[0]          \n\t"
        "MOV        w19, v9.S[0]         \n\t"
        /* Load m */
        /* Load two message blocks to NEON v10, v11, v12, v13, v14 */
        "LD2        { v10.2D-v11.2D }, [%[m]], #32 \n\t"
        "SUB        %[bytes], %[bytes], %[POLY1305_BLOCK_SIZE]*2 \n\t"
        "USHR       v14.2D, v11.2D, #40  \n\t"
        "ORR        v14.16B, v14.16B, v26.16B \n\t"
        "USHR       v13.2D, v11.2D, #14  \n\t"
        "AND        v13.16B, v13.16B, v27.16B \n\t"
        "SHL        v12.2D, v11.2D, #12  \n\t"
        "SRI        v12.2D, v10.2D, #52  \n\t"
        "AND        v12.16B, v12.16B, v27.16B \n\t"
        "USHR       v11.2D, v10.2D, #26  \n\t"
        "AND        v11.16B, v11.16B, v27.16B \n\t"
        "AND        v10.16B, v10.16B, v27.16B \n\t"
        "MOV        v10.S[1], v10.S[2]   \n\t"
        "MOV        v11.S[1], v11.S[2]   \n\t"
        "MOV        v12.S[1], v12.S[2]   \n\t"
        "MOV        v13.S[1], v13.S[2]   \n\t"
        "MOV        v14.S[1], v14.S[2]   \n\t"
        /* Two message blocks loaded */
        /* Add messages to accumulator */
        "ADD        v15.2S, v15.2S, v10.2S \n\t"
        "ADD        v16.2S, v16.2S, v11.2S \n\t"
        "ADD        v17.2S, v17.2S, v12.2S \n\t"
        "ADD        v18.2S, v18.2S, v13.2S \n\t"
        "ADD        v19.2S, v19.2S, v14.2S \n\t"
        "\n"
        ".align 2 \n\t"
    "L_poly1305_aarch64_64_loop_64_%=: \n\t"
        /* d0 = h0*r0 + h1*s4 + h2*s3 + h3*s2 + h4*s1 */
        /* d1 = h0*r1 + h1*r0 + h2*s4 + h3*s3 + h4*s2 */
        /* d2 = h0*r2 + h1*r1 + h2*r0 + h3*s4 + h4*s3 */
        /* d3 = h0*r3 + h1*r2 + h2*r1 + h3*r0 + h4*s4 */
        /* d4 = h0*r4 + h1*r3 + h2*r2 + h3*r1 + h4*r0 */
        "UMULL      v21.2D, v15.2S, v0.2S \n\t"
        /* Compute h*r^2 */
        /* d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1 */
        /* d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2 */
        /* d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3 */
        /* d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4 */
        /* d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0 */
        "MUL        x9, x20, x25         \n\t"
        "UMULL      v22.2D, v15.2S, v1.2S \n\t"
        "MUL        x10, x20, x26        \n\t"
        "UMULL      v23.2D, v15.2S, v2.2S \n\t"
        "MUL        x11, x20, x27        \n\t"
        "UMULL      v24.2D, v15.2S, v3.2S \n\t"
        "MUL        x12, x20, x28        \n\t"
        "UMULL      v25.2D, v15.2S, v4.2S \n\t"
        "MUL        x13, x20, x30        \n\t"
        "UMLAL      v21.2D, v16.2S, v9.2S \n\t"
        "MADD       x9, x21, x19, x9     \n\t"
        "UMLAL      v22.2D, v16.2S, v0.2S \n\t"
        "MADD       x10, x21, x25, x10   \n\t"
        "UMLAL      v23.2D, v16.2S, v1.2S \n\t"
        "MADD       x11, x21, x26, x11   \n\t"
        "UMLAL      v24.2D, v16.2S, v2.2S \n\t"
        "MADD       x12, x21, x27, x12   \n\t"
        "UMLAL      v25.2D, v16.2S, v3.2S \n\t"
        "MADD       x13, x21, x28, x13   \n\t"
        "UMLAL      v21.2D, v17.2S, v8.2S \n\t"
        "MADD       x9, x22, x8, x9      \n\t"
        "UMLAL      v22.2D, v17.2S, v9.2S \n\t"
        "MADD       x10, x22, x19, x10   \n\t"
        "UMLAL      v23.2D, v17.2S, v0.2S \n\t"
        "MADD       x11, x22, x25, x11   \n\t"
        "UMLAL      v24.2D, v17.2S, v1.2S \n\t"
        "MADD       x12, x22, x26, x12   \n\t"
        "UMLAL      v25.2D, v17.2S, v2.2S \n\t"
        "MADD       x13, x22, x27, x13   \n\t"
        "UMLAL      v21.2D, v18.2S, v7.2S \n\t"
        "MADD       x9, x23, x17, x9     \n\t"
        "UMLAL      v22.2D, v18.2S, v8.2S \n\t"
        "MADD       x10, x23, x8, x10    \n\t"
        "UMLAL      v23.2D, v18.2S, v9.2S \n\t"
        "MADD       x11, x23, x19, x11   \n\t"
        "UMLAL      v24.2D, v18.2S, v0.2S \n\t"
        "MADD       x12, x23, x25, x12   \n\t"
        "UMLAL      v25.2D, v18.2S, v1.2S \n\t"
        "MADD       x13, x23, x26, x13   \n\t"
        "UMLAL      v21.2D, v19.2S, v6.2S \n\t"
        "MADD       x9, x24, x16, x9     \n\t"
        "UMLAL      v22.2D, v19.2S, v7.2S \n\t"
        "MADD       x10, x24, x17, x10   \n\t"
        "UMLAL      v23.2D, v19.2S, v8.2S \n\t"
        "MADD       x11, x24, x8, x11    \n\t"
        "UMLAL      v24.2D, v19.2S, v9.2S \n\t"
        "MADD       x12, x24, x19, x12   \n\t"
        "UMLAL      v25.2D, v19.2S, v0.2S \n\t"
        "MADD       x13, x24, x25, x13   \n\t"
        /* Load m */
        /* Load two message blocks to NEON v10, v11, v12, v13, v14 */
        "LD2        { v10.2D-v11.2D }, [%[m]], #32 \n\t"
        /* Reduce h % P */
        "MOV        x14, #5              \n\t"
        "SUB        %[bytes], %[bytes], %[POLY1305_BLOCK_SIZE]*2 \n\t"
        "ADD        x10, x10, x9, LSR #26 \n\t"
        "USHR       v14.2D, v11.2D, #40  \n\t"
        "ADD        x13, x13, x12, LSR #26 \n\t"
        "ORR        v14.16B, v14.16B, v26.16B \n\t"
        "AND        x9, x9, #0x3ffffff   \n\t"
        "USHR       v13.2D, v11.2D, #14  \n\t"
        "LSR        x20, x13, #26        \n\t"
        "AND        v13.16B, v13.16B, v27.16B \n\t"
        "AND        x12, x12, #0x3ffffff \n\t"
        "SHL        v12.2D, v11.2D, #12  \n\t"
        "MADD       x9, x20, x14, x9     \n\t"
        "SRI        v12.2D, v10.2D, #52  \n\t"
        "ADD        x11, x11, x10, LSR #26 \n\t"
        "AND        v12.16B, v12.16B, v27.16B \n\t"
        "AND        x10, x10, #0x3ffffff \n\t"
        "USHR       v11.2D, v10.2D, #26  \n\t"
        "AND        x13, x13, #0x3ffffff \n\t"
        "AND        v11.16B, v11.16B, v27.16B \n\t"
        "ADD        x12, x12, x11, LSR #26 \n\t"
        "AND        v10.16B, v10.16B, v27.16B \n\t"
        "AND        x22, x11, #0x3ffffff \n\t"
        /* Two message blocks loaded */
        "ADD        v21.2D, v21.2D, v10.2D \n\t"
        "ADD        x21, x10, x9, LSR #26 \n\t"
        "ADD        v22.2D, v22.2D, v11.2D \n\t"
        "AND        x20, x9, #0x3ffffff  \n\t"
        "ADD        v23.2D, v23.2D, v12.2D \n\t"
        "ADD        x24, x13, x12, LSR #26 \n\t"
        "ADD        v24.2D, v24.2D, v13.2D \n\t"
        "AND        x23, x12, #0x3ffffff \n\t"
        "ADD        v25.2D, v25.2D, v14.2D \n\t"
        /* Reduce radix 26 NEON */
        /* Interleave h0 -> h1 -> h2 -> h3 -> h4 */
        /*       with h3 -> h4 -> h0 -> h1 */
        "USRA       v22.2D, v21.2D, #26  \n\t"
        "AND        v21.16B, v21.16B, v27.16B \n\t"
        "USRA       v25.2D, v24.2D, #26  \n\t"
        "AND        v24.16B, v24.16B, v27.16B \n\t"
        "USHR       v15.2D, v25.2D, #26  \n\t"
        "USRA       v23.2D, v22.2D, #26  \n\t"
        /* Simulate multiplying by 5 using adding and shifting */
        "SHL        v18.2D, v15.2D, #2   \n\t"
        "AND        v16.16B, v22.16B, v27.16B \n\t"
        "ADD        v18.2D, v18.2D, v15.2D \n\t"
        "AND        v19.16B, v25.16B, v27.16B \n\t"
        "ADD        v21.2D, v21.2D, v18.2D \n\t"
        "USRA       v24.2D, v23.2D, #26  \n\t"
        "AND        v17.16B, v23.16B, v27.16B \n\t"
        "USRA       v16.2D, v21.2D, #26  \n\t"
        "AND        v15.16B, v21.16B, v27.16B \n\t"
        "USRA       v19.2D, v24.2D, #26  \n\t"
        "AND        v18.16B, v24.16B, v27.16B \n\t"
        /* Copy values to lower halves of result registers */
        "MOV        v15.S[1], v15.S[2]   \n\t"
        "MOV        v16.S[1], v16.S[2]   \n\t"
        "MOV        v17.S[1], v17.S[2]   \n\t"
        "MOV        v18.S[1], v18.S[2]   \n\t"
        "MOV        v19.S[1], v19.S[2]   \n\t"
        /* If at least two message blocks left then loop_64 */
        "CMP        %[bytes], %[POLY1305_BLOCK_SIZE]*2 \n\t"
        "BHS        L_poly1305_aarch64_64_loop_64_%= \n\t"
        "\n"
        ".align 2 \n\t"
    "L_poly1305_aarch64_64_last_mult_%=: \n\t"
        /* Load r */
        "LD4        { v0.S-v3.S }[1], [%[r]], #16 \n\t"
        /* Compute h*r^2 */
        /* d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1 */
        /* d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2 */
        /* d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3 */
        /* d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4 */
        /* d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0 */
        "MUL        x9, x20, x25         \n\t"
        "LD1        { v4.S }[1], [%[r]]  \n\t"
        "MUL        x10, x20, x26        \n\t"
        "SUB        %[r], %[r], #16      \n\t"
        "MUL        x11, x20, x27        \n\t"
        /* Store [r^2, r] * 5 */
        "MUL        v5.2S, v0.2S, v28.S[0] \n\t"
        "MUL        x12, x20, x28        \n\t"
        "MUL        v6.2S, v1.2S, v28.S[0] \n\t"
        "MUL        x13, x20, x30        \n\t"
        "MUL        v7.2S, v2.2S, v28.S[0] \n\t"
        "MADD       x9, x21, x19, x9     \n\t"
        "MUL        v8.2S, v3.2S, v28.S[0] \n\t"
        "MADD       x10, x21, x25, x10   \n\t"
        "MUL        v9.2S, v4.2S, v28.S[0] \n\t"
        "MADD       x11, x21, x26, x11   \n\t"
        /* Final multiply by [r^2, r] */
        /* d0 = h0*r0 + h1*s4 + h2*s3 + h3*s2 + h4*s1 */
        /* d1 = h0*r1 + h1*r0 + h2*s4 + h3*s3 + h4*s2 */
        /* d2 = h0*r2 + h1*r1 + h2*r0 + h3*s4 + h4*s3 */
        /* d3 = h0*r3 + h1*r2 + h2*r1 + h3*r0 + h4*s4 */
        /* d4 = h0*r4 + h1*r3 + h2*r2 + h3*r1 + h4*r0 */
        "UMULL      v21.2D, v15.2S, v0.2S \n\t"
        "MADD       x12, x21, x27, x12   \n\t"
        "UMULL      v22.2D, v15.2S, v1.2S \n\t"
        "MADD       x13, x21, x28, x13   \n\t"
        "UMULL      v23.2D, v15.2S, v2.2S \n\t"
        "MADD       x9, x22, x8, x9      \n\t"
        "UMULL      v24.2D, v15.2S, v3.2S \n\t"
        "MADD       x10, x22, x19, x10   \n\t"
        "UMULL      v25.2D, v15.2S, v4.2S \n\t"
        "MADD       x11, x22, x25, x11   \n\t"
        "UMLAL      v21.2D, v16.2S, v9.2S \n\t"
        "MADD       x12, x22, x26, x12   \n\t"
        "UMLAL      v22.2D, v16.2S, v0.2S \n\t"
        "MADD       x13, x22, x27, x13   \n\t"
        "UMLAL      v23.2D, v16.2S, v1.2S \n\t"
        "MADD       x9, x23, x17, x9     \n\t"
        "UMLAL      v24.2D, v16.2S, v2.2S \n\t"
        "MADD       x10, x23, x8, x10    \n\t"
        "UMLAL      v25.2D, v16.2S, v3.2S \n\t"
        "MADD       x11, x23, x19, x11   \n\t"
        "UMLAL      v21.2D, v17.2S, v8.2S \n\t"
        "MADD       x12, x23, x25, x12   \n\t"
        "UMLAL      v22.2D, v17.2S, v9.2S \n\t"
        "MADD       x13, x23, x26, x13   \n\t"
        "UMLAL      v23.2D, v17.2S, v0.2S \n\t"
        "MADD       x9, x24, x16, x9     \n\t"
        "UMLAL      v24.2D, v17.2S, v1.2S \n\t"
        "MADD       x10, x24, x17, x10   \n\t"
        "UMLAL      v25.2D, v17.2S, v2.2S \n\t"
        "MADD       x11, x24, x8, x11    \n\t"
        "UMLAL      v21.2D, v18.2S, v7.2S \n\t"
        "MADD       x12, x24, x19, x12   \n\t"
        "UMLAL      v22.2D, v18.2S, v8.2S \n\t"
        "MADD       x13, x24, x25, x13   \n\t"
        "UMLAL      v23.2D, v18.2S, v9.2S \n\t"
        /* Reduce h % P */
        "MOV        x14, #5              \n\t"
        "UMLAL      v24.2D, v18.2S, v0.2S \n\t"
        "ADD        x10, x10, x9, LSR #26 \n\t"
        "UMLAL      v25.2D, v18.2S, v1.2S \n\t"
        "ADD        x13, x13, x12, LSR #26 \n\t"
        "UMLAL      v21.2D, v19.2S, v6.2S \n\t"
        "AND        x9, x9, #0x3ffffff   \n\t"
        "UMLAL      v22.2D, v19.2S, v7.2S \n\t"
        "LSR        x20, x13, #26        \n\t"
        "UMLAL      v23.2D, v19.2S, v8.2S \n\t"
        "AND        x12, x12, #0x3ffffff \n\t"
        "UMLAL      v24.2D, v19.2S, v9.2S \n\t"
        "MADD       x9, x20, x14, x9     \n\t"
        "UMLAL      v25.2D, v19.2S, v0.2S \n\t"
        "ADD        x11, x11, x10, LSR #26 \n\t"
        /* Add even and odd elements */
        "ADDP       d21, v21.2D          \n\t"
        "AND        x10, x10, #0x3ffffff \n\t"
        "ADDP       d22, v22.2D          \n\t"
        "AND        x13, x13, #0x3ffffff \n\t"
        "ADDP       d23, v23.2D          \n\t"
        "ADD        x12, x12, x11, LSR #26 \n\t"
        "ADDP       d24, v24.2D          \n\t"
        "AND        x22, x11, #0x3ffffff \n\t"
        "ADDP       d25, v25.2D          \n\t"
        "ADD        x21, x10, x9, LSR #26 \n\t"
        "AND        x20, x9, #0x3ffffff  \n\t"
        "ADD        x24, x13, x12, LSR #26 \n\t"
        "AND        x23, x12, #0x3ffffff \n\t"
        /* Load h to NEON */
        "MOV        v5.D[0], x20         \n\t"
        "MOV        v6.D[0], x21         \n\t"
        "MOV        v7.D[0], x22         \n\t"
        "MOV        v8.D[0], x23         \n\t"
        "MOV        v9.D[0], x24         \n\t"
        /* Add ctx->h to current accumulator */
        "ADD        v21.2D, v21.2D, v5.2D \n\t"
        "ADD        v22.2D, v22.2D, v6.2D \n\t"
        "ADD        v23.2D, v23.2D, v7.2D \n\t"
        "ADD        v24.2D, v24.2D, v8.2D \n\t"
        "ADD        v25.2D, v25.2D, v9.2D \n\t"
        /* Reduce h (h % P) */
        /* Reduce radix 26 NEON */
        /* Interleave h0 -> h1 -> h2 -> h3 -> h4 */
        /*       with h3 -> h4 -> h0 -> h1 */
        "USRA       v22.2D, v21.2D, #26  \n\t"
        "AND        v21.16B, v21.16B, v27.16B \n\t"
        "USRA       v25.2D, v24.2D, #26  \n\t"
        "AND        v24.16B, v24.16B, v27.16B \n\t"
        "USHR       v5.2D, v25.2D, #26   \n\t"
        "USRA       v23.2D, v22.2D, #26  \n\t"
        /* Simulate multiplying by 5 using adding and shifting */
        "SHL        v8.2D, v5.2D, #2     \n\t"
        "AND        v6.16B, v22.16B, v27.16B \n\t"
        "ADD        v8.2D, v8.2D, v5.2D  \n\t"
        "AND        v9.16B, v25.16B, v27.16B \n\t"
        "ADD        v21.2D, v21.2D, v8.2D \n\t"
        "USRA       v24.2D, v23.2D, #26  \n\t"
        "AND        v7.16B, v23.16B, v27.16B \n\t"
        "USRA       v6.2D, v21.2D, #26   \n\t"
        "AND        v5.16B, v21.16B, v27.16B \n\t"
        "USRA       v9.2D, v24.2D, #26   \n\t"
        "AND        v8.16B, v24.16B, v27.16B \n\t"
        /* Copy values to lower halves of result registers */
        /* Store h */
        "ST4        { v5.S-v8.S }[0], [%[h]], #16 \n\t"
        "ST1        { v9.S }[0], [%[h]]  \n\t"
        "SUB        %[h], %[h], #16      \n\t"
        "\n"
        ".align 2 \n\t"
    "L_poly1305_aarch64_64_done_%=: \n\t"
        : [bytes] "+r" (bytes),
          [m] "+r" (m),
          [ctx] "+m" (ctx)
        : [POLY1305_BLOCK_SIZE] "I" (POLY1305_BLOCK_SIZE),
          [h] "r" (ctx->h),
          [r] "r" (ctx->r),
          [r_2] "r" (ctx->r_2),
          [r_4] "r" (ctx->r_4),
          [finished] "r" ((word64)ctx->finished)
        : "memory", "cc",
          "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9",
          "v10", "v11", "v12", "v13", "v14", "v15", "v16", "v17", "v18", "v19",
          "v21", "v22", "v23", "v24", "v25", "v26", "v27", "v28", "v29", "v30",
          "w8", "w9", "w10", "w11", "w12", "w13", "w14", "w15", "w16", "w17",
          "w19", "w20", "w21", "w22", "w23", "w24", "w25", "w26", "w27", "w28",
          "w30", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16",
          "x17", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27",
          "x28", "x30"
    );
    poly1305_blocks_aarch64_16(ctx, m, bytes);
}

void poly1305_block_aarch64(Poly1305* ctx, const unsigned char *m)
{
    poly1305_blocks_aarch64_16(ctx, m, POLY1305_BLOCK_SIZE);
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
        "LDP        x8, x9, [%[key]]     \n\t"
        "LDP        x10, x11, [%[key], #16] \n\t"
        /* Load clamp */
        "LDP        x12, x13, [%[clamp]] \n\t"
        /* Save pad for later */
        "STP        x10, x11, [%[ctx_pad]] \n\t"
        /* Apply clamp */
        /* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
        "AND        x8, x8, x12          \n\t"
        "AND        x9, x9, x13          \n\t"
        "STP        x8, x9, [%[ctx_r64]] \n\t"
        /* 128-bits: Base 64 -> Base 26 */
        "MOV        x20, #0x3ffffff\n\t"
        "LSR        x15, x9, #40\n\t"
        "AND        x14, x20, x9, LSR #14\n\t"
        "EXTR       x13, x9, x8, #52\n\t"
        "AND        x12, x20, x8, LSR #26\n\t"
        "AND        x11, x8, x20\n\t"
        "AND        x13, x13, x20\n\t"
        "AND        x15, x15, x20\n\t"
        "STP        w11, w12, [%[ctx_r], #0]   \n\t"
        "STP        w13, w14, [%[ctx_r], #8]   \n\t"
        "STR        w15, [%[ctx_r], #16]   \n\t"

        /* Compute r^2 */
        /* r0 * r0 */
        "MUL        x12, x8, x8\n\t"
        "UMULH      x13, x8, x8\n\t"
        /* 2 * r0 * r1 */
        "MUL        x15, x8, x9\n\t"
        "UMULH      x16, x8, x9\n\t"
        "ADDS       x13, x13, x15\n\t"
        "ADC        x14, xzr, x16\n\t"
        "ADDS       x13, x13, x15\n\t"
        "ADCS       x14, x14, x16\n\t"
        "ADC        x15, xzr, xzr\n\t"
        /* r1 * r1 */
        "MUL        x16, x9, x9\n\t"
        "UMULH      x17, x9, x9\n\t"
        "ADDS       x14, x14, x16\n\t"
        "ADC        x15, x15, x17\n\t"
        /* r_2 = r^2 % P */
        /* Get top two bits from r^2[2]. */
        "AND        x10, x14, 3\n\t"
        /* Get high bits from r^2[2]. */
        "AND        x14, x14, -4\n\t"
        /* Add top bits * 4. */
        "ADDS       x8, x12, x14\n\t"
        "ADCS       x9, x13, x15\n\t"
        "ADC        x10, x10, xzr\n\t"
        /* Move down 2 bits. */
        "EXTR       x14, x15, x14, 2\n\t"
        "LSR        x15, x15, 2\n\t"
        /* Add top bits. */
        "ADDS       x8, x8, x14\n\t"
        "ADCS       x9, x9, x15\n\t"
        "ADC        x10, x10, xzr\n\t"
        /* 130-bits: Base 64 -> Base 26 */
        "EXTR       x15, x10, x9, #40\n\t"
        "AND        x14, x20, x9, LSR #14\n\t"
        "EXTR       x13, x9, x8, #52\n\t"
        "AND        x12, x20, x8, LSR #26\n\t"
        "AND        x11, x8, x20\n\t"
        "AND        x13, x13, x20\n\t"
        "AND        x15, x15, x20\n\t"
        /* Store r^2 */
        "STP        w11, w12, [%[ctx_r_2], #0]   \n\t"
        "STP        w13, w14, [%[ctx_r_2], #8]   \n\t"
        "STR        w15, [%[ctx_r_2], #16]   \n\t"

        /* Compute r^4 */
        /* r0 * r0 */
        "MUL        x12, x8, x8\n\t"
        "UMULH      x13, x8, x8\n\t"
        /* 2 * r0 * r1 */
        "MUL        x15, x8, x9\n\t"
        "UMULH      x16, x8, x9\n\t"
        "ADDS       x13, x13, x15\n\t"
        "ADC        x14, xzr, x16\n\t"
        "ADDS       x13, x13, x15\n\t"
        "ADCS       x14, x14, x16\n\t"
        "ADC        x15, xzr, xzr\n\t"
        /* 2 * r0 * r2 */
        "MUL        x16, x8, x10\n\t"
        "UMULH      x17, x8, x10\n\t"
        "ADDS       x14, x14, x16\n\t"
        "ADC        x15, x15, x17\n\t"
        "ADDS       x14, x14, x16\n\t"
        "ADC        x15, x15, x17\n\t"
        /* r1 * r1 */
        "MUL        x16, x9, x9\n\t"
        "UMULH      x17, x9, x9\n\t"
        "ADDS       x14, x14, x16\n\t"
        "ADCS       x15, x15, x17\n\t"
        "ADC        x16, xzr, xzr\n\t"
        /* 2 * r1 * r2 */
        "MUL        x17, x9, x10\n\t"
        "UMULH      x19, x9, x10\n\t"
        "ADDS       x15, x15, x17\n\t"
        "ADC        x16, x16, x19\n\t"
        "ADDS       x15, x15, x17\n\t"
        "ADC        x16, x16, x19\n\t"
        /* r2 * r2 */
        "MUL        x17, x10, x10\n\t"
        "ADD        x16, x16, x17\n\t"
        /* r_4 = r^4 % P */
        /* Get top two bits from r^4[2]. */
        "AND        x10, x14, 3\n\t"
        /* Get high bits from r^4[2]. */
        "AND        x14, x14, -4\n\t"
        /* Add top bits * 4. */
        "ADDS       x8, x12, x14\n\t"
        "ADCS       x9, x13, x15\n\t"
        "ADC        x10, x10, x16\n\t"
        /* Move down 2 bits. */
        "EXTR       x14, x15, x14, 2\n\t"
        "EXTR       x15, x16, x15, 2\n\t"
        "LSR        x16, x16, 2\n\t"
        /* Add top bits. */
        "ADDS       x8, x8, x14\n\t"
        "ADCS       x9, x9, x15\n\t"
        "ADC        x10, x10, x16\n\t"
        /* Top again as it was 260 bits mod less than 130 bits. */
        "AND        x11, x10, -4\n\t"
        "AND        x10, x10, 3\n\t"
        "ADD        x11, x11, x11, LSR #2\n\t"
        "ADDS       x8, x8, x11\n\t"
        "ADCS       x9, x9, xzr\n\t"
        "ADC        x10, x10, xzr\n\t"
        /* 130-bits: Base 64 -> Base 26 */
        "EXTR       x15, x10, x9, #40\n\t"
        "AND        x14, x20, x9, LSR #14\n\t"
        "EXTR       x13, x9, x8, #52\n\t"
        "AND        x12, x20, x8, LSR #26\n\t"
        "AND        x11, x8, x20\n\t"
        "AND        x13, x13, x20\n\t"
        "AND        x15, x15, x20\n\t"
        /* Store r^4 */
        "STP        w11, w12, [%[ctx_r_4], #0]   \n\t"
        "STP        w13, w14, [%[ctx_r_4], #8]   \n\t"
        "STR        w15, [%[ctx_r_4], #16]   \n\t"

        /* h (accumulator) = 0 */
        "STP        xzr, xzr, [%[ctx_h_0]] \n\t"
        "STR        wzr, [%[ctx_h_0], #16] \n\t"
        /* Zero leftover */
        "STR        xzr, [%[ctx_leftover]] \n\t"
        /* Zero finished */
        "STRB       wzr, [%[ctx_finished]] \n\t"
        :
        : [clamp] "r" (clamp),
          [key] "r" (key),
          [ctx_r64] "r" (ctx->r64),
          [ctx_r] "r" (ctx->r),
          [ctx_r_2] "r" (ctx->r_2),
          [ctx_r_4] "r" (ctx->r_4),
          [ctx_h_0] "r" (ctx->h),
          [ctx_pad] "r" (ctx->pad),
          [ctx_leftover] "r" (&ctx->leftover),
          [ctx_finished] "r" (&ctx->finished)
        : "memory", "cc",
          "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17",
          "x19", "x20"
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
        ctx->finished = 1;
        poly1305_block_aarch64(ctx, ctx->buffer);
    }

    __asm__ __volatile__ (
        "LDP        x9, x10, %[ctx_pad] \n\t"
        /* Load h */
        "LDP        w4, w5, [%[ctx_h], #0]   \n\t"
        "LDP        w6, w7, [%[ctx_h], #8]   \n\t"
        "LDR        w8, [%[ctx_h], #16]   \n\t"
        /* Base 26 -> Base 64 */
        "ORR        x4, x4, x5, LSL #26\n\t"
        "ORR        x4, x4, x6, LSL #52\n\t"
        "LSR        x5, x6, #12\n\t"
        "ORR        x5, x5, x7, LSL #14\n\t"
        "ORR        x5, x5, x8, LSL #40\n\t"
        "LSR        x6, x8, #24\n\t"
        /* Check if h is larger than p */
        "ADDS       x1, x4, #5           \n\t"
        "ADCS       x2, x5, xzr          \n\t"
        "ADC        x3, x6, xzr          \n\t"
        /* Check if h+5 is larger than 2^130 */
        "CMP        x3, #3               \n\t"
        "CSEL       x4, x1, x4, HI       \n\t"
        "CSEL       x5, x2, x5, HI       \n\t"
        "ADDS       x4, x4, x9           \n\t"
        "ADC        x5, x5, x10          \n\t"
        "STP        x4, x5, [%[mac]]     \n\t"

        /* Zero out h */
        "STP        xzr, xzr, [%[ctx_h]] \n\t"
        "STR        wzr, [%[ctx_h], #16] \n\t"
        /* Zero out r64 */
        "STP        xzr, xzr, [%[ctx_r64]] \n\t"
        /* Zero out r */
        "STP        xzr, xzr, [%[ctx_r]] \n\t"
        "STR        wzr, [%[ctx_r], #16] \n\t"
        /* Zero out r_2 */
        "STP        xzr, xzr, [%[ctx_r_2]] \n\t"
        "STR        wzr, [%[ctx_r_2], #16] \n\t"
        /* Zero out r_4 */
        "STP        xzr, xzr, [%[ctx_r_4]] \n\t"
        "STR        wzr, [%[ctx_r_4], #16] \n\t"
        /* Zero out pad */
        "STP        xzr, xzr, %[ctx_pad] \n\t"
        :
        : [ctx_pad] "m" (ctx->pad), [ctx_h] "r" (ctx->h), [mac] "r" (mac),
          [ctx_r64] "r" (ctx->r64), [ctx_r] "r" (ctx->r),
          [ctx_r_2] "r" (ctx->r_2), [ctx_r_4] "r" (ctx->r_4)
        : "memory", "cc",
          "w4", "w5", "w6", "w7", "w8",
          "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10"
    );

    return 0;
}

#endif /* HAVE_POLY1305 */
#endif /* __aarch64__ */
#endif /* WOLFSSL_ARMASM */
