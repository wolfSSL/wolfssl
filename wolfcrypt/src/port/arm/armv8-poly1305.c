/* armv8-poly1305.c
 *
 * Copyright (C) 2006-2019 wolfSSL Inc.
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


#ifdef WOLFSSL_ARMASM

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

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

#ifdef _MSC_VER
    /* 4127 warning constant while(1)  */
    #pragma warning(disable: 4127)
#endif

#if defined(POLY130564)
    #if defined(_MSC_VER)
        #define POLY1305_NOINLINE __declspec(noinline)
    #elif defined(__GNUC__)
        #define POLY1305_NOINLINE __attribute__((noinline))
    #else
        #define POLY1305_NOINLINE
    #endif

    #if defined(_MSC_VER)
        #include <intrin.h>

        typedef struct word128 {
            word64 lo;
            word64 hi;
        } word128;

        #define MUL(out, x, y) out.lo = _umul128((x), (y), &out.hi)
        #define ADD(out, in) { word64 t = out.lo; out.lo += in.lo; \
                               out.hi += (out.lo < t) + in.hi; }
        #define ADDLO(out, in) { word64 t = out.lo; out.lo += in; \
                                 out.hi += (out.lo < t); }
        #define SHR(in, shift) (__shiftright128(in.lo, in.hi, (shift)))
        #define LO(in) (in.lo)

    #elif defined(__GNUC__)
        #if defined(__SIZEOF_INT128__)
            typedef unsigned __int128 word128;
        #else
            typedef unsigned word128 __attribute__((mode(TI)));
        #endif

        #define MUL(out, x, y) out = ((word128)x * y)
        #define ADD(out, in) out += in
        #define ADDLO(out, in) out += in
        #define SHR(in, shift) (word64)(in >> (shift))
        #define LO(in) (word64)(in)
    #endif
#endif

//#if !defined(POLY130564)
//
//    static word64 U8TO64(const byte* p)
//    {
//        return
//            (((word64)(p[0] & 0xff)      ) |
//             ((word64)(p[1] & 0xff) <<  8) |
//             ((word64)(p[2] & 0xff) << 16) |
//             ((word64)(p[3] & 0xff) << 24) |
//             ((word64)(p[4] & 0xff) << 32) |
//             ((word64)(p[5] & 0xff) << 40) |
//             ((word64)(p[6] & 0xff) << 48) |
//             ((word64)(p[7] & 0xff) << 56));
//    }
//
//    static void U64TO8(byte* p, word64 v) {
//        p[0] = (v      ) & 0xff;
//        p[1] = (v >>  8) & 0xff;
//        p[2] = (v >> 16) & 0xff;
//        p[3] = (v >> 24) & 0xff;
//        p[4] = (v >> 32) & 0xff;
//        p[5] = (v >> 40) & 0xff;
//        p[6] = (v >> 48) & 0xff;
//        p[7] = (v >> 56) & 0xff;
//    }
//
//#else /* if not 64 bit then use 32 bit */

    static word32 U8TO32(const byte *p)
    {
        return
            (((word32)(p[0] & 0xff)      ) |
             ((word32)(p[1] & 0xff) <<  8) |
             ((word32)(p[2] & 0xff) << 16) |
             ((word32)(p[3] & 0xff) << 24));
    }

    static void U32TO8(byte *p, word32 v) {
        p[0] = (v      ) & 0xff;
        p[1] = (v >>  8) & 0xff;
        p[2] = (v >> 16) & 0xff;
        p[3] = (v >> 24) & 0xff;
    }
//#endif


static void U32TO64(word32 v, byte* p)
{
    XMEMSET(p, 0, 8);
    p[0] = (v & 0xFF);
    p[1] = (v >>  8) & 0xFF;
    p[2] = (v >> 16) & 0xFF;
    p[3] = (v >> 24) & 0xFF;
}

static WC_INLINE void poly1305_blocks_16(Poly1305* ctx, const unsigned char *m,
                               size_t bytes)
{
#if defined(POLY130564)
    __asm__ __volatile__ (
        "CMP        %[bytes], %[POLY1305_BLOCK_SIZE] \n\t"
        "BLO        L_poly1305_16_64_done_%= \n\t"
        /* Load r and h */
        "LDP        x21, x23, %[ctx_r]   \n\t"
        "LDR        w25, %[ctx_r_4]      \n\t"
        "LDP        x2, x4, %[ctx_h]     \n\t"
        "LDR        w6, %[ctx_h_4]       \n\t"
        "LSR        x22, x21, #32        \n\t"
        "LSR        x24, x23, #32        \n\t"
        "LSR        x3, x2, #32          \n\t"
        "LSR        x5, x4, #32          \n\t"
        "AND        x21, x21, #0x3ffffff \n\t"
        "AND        x23, x23, #0x3ffffff \n\t"
        "AND        x2, x2, #0x3ffffff   \n\t"
        "AND        x4, x4, #0x3ffffff   \n\t"
        /* s1 = r1 * 5; */
        /* s2 = r2 * 5; */
        /* s3 = r3 * 5; */
        /* s4 = r4 * 5; */
        "MOV        x15, #5              \n\t"
        "CMP        %[finished], #0      \n\t"
        "MUL        w7, w22, w15         \n\t"
        "CSET       %[finished], EQ      \n\t"
        "MUL        w8, w23, w15         \n\t"
        "LSL        %[finished], %[finished], #24 \n\t"
        "MUL        w9, w24, w15         \n\t"
        "MOV        x14, #0x3ffffff      \n\t"
        "MUL        w10, w25, w15        \n\t"
        "\n"
    "L_poly1305_16_64_loop_%=: \n\t"
        /* t0 = U8TO64(&m[0]); */
        /* t1 = U8TO64(&m[8]); */
        "LDP        x16, x17, [%[m]], #16 \n\t"
        /* h0 += (U8TO32(m + 0)) & 0x3ffffff; */
        "AND        x18, x16, #0x3ffffff \n\t"
        "ADD        x2, x2, x18          \n\t"
        /* h1 += (U8TO32(m + 3) >> 2) & 0x3ffffff; */
        "AND        x18, x14, x16, LSR #26 \n\t"
        "ADD        x3, x3, x18          \n\t"
        /* h2 += (U8TO32(m + 6) >> 4) & 0x3ffffff; */
        "EXTR       x18, x17, x16, #52   \n\t"
        "AND        x18, x18, #0x3ffffff \n\t"
        "ADD        x4, x4, x18          \n\t"
        /* h3 += (U8TO32(m + 9) >> 6) & 0x3ffffff; */
        "AND        x18, x14, x17, LSR #14 \n\t"
        "ADD        x5, x5, x18          \n\t"
        /* h4 += (U8TO32(m + 12) >> 8) | hibit; */
        "ORR        x17, %[finished], x17, LSR #40 \n\t"
        "ADD        x6, x6, x17          \n\t"
        /* d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1 */
        /* d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2 */
        /* d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3 */
        /* d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4 */
        /* d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0 */
        "MUL        x16, x2, x21         \n\t"
        "MUL        x17, x2, x22         \n\t"
        "MUL        x18, x2, x23         \n\t"
        "MUL        x19, x2, x24         \n\t"
        "MUL        x20, x2, x25         \n\t"
        "MADD       x16, x3, x10, x16    \n\t"
        "MADD       x17, x3, x21, x17    \n\t"
        "MADD       x18, x3, x22, x18    \n\t"
        "MADD       x19, x3, x23, x19    \n\t"
        "MADD       x20, x3, x24, x20    \n\t"
        "MADD       x16, x4, x9, x16     \n\t"
        "MADD       x17, x4, x10, x17    \n\t"
        "MADD       x18, x4, x21, x18    \n\t"
        "MADD       x19, x4, x22, x19    \n\t"
        "MADD       x20, x4, x23, x20    \n\t"
        "MADD       x16, x5, x8, x16     \n\t"
        "MADD       x17, x5, x9, x17     \n\t"
        "MADD       x18, x5, x10, x18    \n\t"
        "MADD       x19, x5, x21, x19    \n\t"
        "MADD       x20, x5, x22, x20    \n\t"
        "MADD       x16, x6, x7, x16     \n\t"
        "MADD       x17, x6, x8, x17     \n\t"
        "MADD       x18, x6, x9, x18     \n\t"
        "MADD       x19, x6, x10, x19    \n\t"
        "MADD       x20, x6, x21, x20    \n\t"
        /* d1 = d1 + d0 >> 26 */
        /* d2 = d2 + d1 >> 26 */
        /* d3 = d3 + d2 >> 26 */
        /* d4 = d4 + d3 >> 26 */
        /* h0 = d0 & 0x3ffffff */
        /* h1 = d1 & 0x3ffffff */
        /* h2 = d2 & 0x3ffffff */
        /* h0 = h0 + (d4 >> 26) * 5 */
        /* h1 = h1 + h0 >> 26 */
        /* h3 = d3 & 0x3ffffff */
        /* h4 = d4 & 0x3ffffff */
        /* h0 = h0 & 0x3ffffff */
        "ADD        x17, x17, x16, LSR #26 \n\t"
        "ADD        x20, x20, x19, LSR #26 \n\t"
        "AND        x16, x16, #0x3ffffff \n\t"
        "LSR        x2, x20, #26         \n\t"
        "AND        x19, x19, #0x3ffffff \n\t"
        "MADD       x16, x2, x15, x16    \n\t"
        "ADD        x18, x18, x17, LSR #26 \n\t"
        "AND        x17, x17, #0x3ffffff \n\t"
        "AND        x20, x20, #0x3ffffff \n\t"
        "ADD        x19, x19, x18, LSR #26 \n\t"
        "AND        x4, x18, #0x3ffffff  \n\t"
        "ADD        x3, x17, x16, LSR #26 \n\t"
        "AND        x2, x16, #0x3ffffff  \n\t"
        "ADD        x6, x20, x19, LSR #26 \n\t"
        "AND        x5, x19, #0x3ffffff  \n\t"
        "SUB        %[bytes], %[bytes], %[POLY1305_BLOCK_SIZE] \n\t"
        "CMP        %[bytes], %[POLY1305_BLOCK_SIZE] \n\t"
        "BHS        L_poly1305_16_64_loop_%= \n\t"
        /* Store h */
        "ORR        x2, x2, x3, LSL #32  \n\t"
        "ORR        x4, x4, x5, LSL #32  \n\t"
        "STP        x2, x4, %[ctx_h]     \n\t"
        "STR        w6, %[ctx_h_4]       \n\t"
        "\n"
    "L_poly1305_16_64_done_%=: \n\t"
        : [ctx_h] "+m" (ctx->h[0]),
          [ctx_h_4] "+m" (ctx->h[4]),
          [bytes] "+r" (bytes),
          [m] "+r" (m)
        : [POLY1305_BLOCK_SIZE] "I" (POLY1305_BLOCK_SIZE),
          [ctx_r] "m" (ctx->r[0]),
          [ctx_r_4] "m" (ctx->r[4]),
          [finished] "r" (ctx->finished)
        : "memory", "cc",
          "w2", "w3", "w4", "w5", "w6", "w7", "w8", "w9", "w10", "w15",
          "w21", "w22", "w23", "w24", "w25", "x2", "x3", "x4", "x5", "x6",
          "x7", "x8", "x9", "x10", "x14", "x15", "x16", "x17", "x18", "x19",
          "x20", "x21", "x22", "x23", "x24", "x25"
    );

#else /* if not 64 bit then use 32 bit */
    const word32 hibit = (ctx->finished) ? 0 : ((word32)1 << 24); /* 1 << 128 */
    word32 r0,r1,r2,r3,r4;
    word32 s1,s2,s3,s4;
    word32 h0,h1,h2,h3,h4;
    word64 d0,d1,d2,d3,d4;
    word32 c;


    r0 = ctx->r[0];
    r1 = ctx->r[1];
    r2 = ctx->r[2];
    r3 = ctx->r[3];
    r4 = ctx->r[4];

    s1 = r1 * 5;
    s2 = r2 * 5;
    s3 = r3 * 5;
    s4 = r4 * 5;

    h0 = ctx->h[0];
    h1 = ctx->h[1];
    h2 = ctx->h[2];
    h3 = ctx->h[3];
    h4 = ctx->h[4];

    while (bytes >= POLY1305_BLOCK_SIZE) {
        /* h += m[i] */
        h0 += (U8TO32(m+ 0)     ) & 0x3ffffff;
        h1 += (U8TO32(m+ 3) >> 2) & 0x3ffffff;
        h2 += (U8TO32(m+ 6) >> 4) & 0x3ffffff;
        h3 += (U8TO32(m+ 9) >> 6) & 0x3ffffff;
        h4 += (U8TO32(m+12) >> 8) | hibit;

        /* h *= r */
        d0 = ((word64)h0 * r0) + ((word64)h1 * s4) + ((word64)h2 * s3) +
             ((word64)h3 * s2) + ((word64)h4 * s1);
        d1 = ((word64)h0 * r1) + ((word64)h1 * r0) + ((word64)h2 * s4) +
             ((word64)h3 * s3) + ((word64)h4 * s2);
        d2 = ((word64)h0 * r2) + ((word64)h1 * r1) + ((word64)h2 * r0) +
             ((word64)h3 * s4) + ((word64)h4 * s3);
        d3 = ((word64)h0 * r3) + ((word64)h1 * r2) + ((word64)h2 * r1) +
             ((word64)h3 * r0) + ((word64)h4 * s4);
        d4 = ((word64)h0 * r4) + ((word64)h1 * r3) + ((word64)h2 * r2) +
             ((word64)h3 * r1) + ((word64)h4 * r0);

        /* (partial) h %= p */
                      c = (word32)(d0 >> 26); h0 = (word32)d0 & 0x3ffffff;
        d1 += c;      c = (word32)(d1 >> 26); h1 = (word32)d1 & 0x3ffffff;
        d2 += c;      c = (word32)(d2 >> 26); h2 = (word32)d2 & 0x3ffffff;
        d3 += c;      c = (word32)(d3 >> 26); h3 = (word32)d3 & 0x3ffffff;
        d4 += c;      c = (word32)(d4 >> 26); h4 = (word32)d4 & 0x3ffffff;
        h0 += c * 5;  c =  (h0 >> 26); h0 =                h0 & 0x3ffffff;
        h1 += c;

        m += POLY1305_BLOCK_SIZE;
        bytes -= POLY1305_BLOCK_SIZE;
    }

    ctx->h[0] = h0;
    ctx->h[1] = h1;
    ctx->h[2] = h2;
    ctx->h[3] = h3;
    ctx->h[4] = h4;

#endif /* end of 64 bit cpu blocks or 32 bit cpu */
}

static void poly1305_blocks(Poly1305* ctx, const unsigned char *m,
                            size_t bytes)
{
#if defined(POLY130564)
    __asm__ __volatile__ (
        /* If less than 4 blocks to process then use regular method */
        "CMP        %[bytes], %[POLY1305_BLOCK_SIZE]*4 \n\t"
        "BLO        L_poly1305_64_done_%= \n\t"
        "MOV        x9, #0x3ffffff       \n\t"
        /* Load h */
        "LDP        x20, x22, [%[h]], #16 \n\t"
        "MOV        v27.D[0], x9         \n\t"
        "LDR        w24, [%[h]]          \n\t"
        "MOV        v27.D[1], x9         \n\t"
        "SUB        %[h], %[h], #16      \n\t"
        "MOV        x9, #5               \n\t"
        "LSR        x21, x20, #32        \n\t"
        "MOV        v28.D[0], x9         \n\t"
        "LSR        x23, x22, #32        \n\t"
        /* Zero accumulator registers */
        "MOVI       v15.2D, #0x0         \n\t"
        "AND        x20, x20, #0x3ffffff \n\t"
        "MOVI       v16.2D, #0x0         \n\t"
        "AND        x22, x22, #0x3ffffff \n\t"
        "MOVI       v17.2D, #0x0         \n\t"
        "MOVI       v18.2D, #0x0         \n\t"
        "MOVI       v19.2D, #0x0         \n\t"
        /* Set hibit */
        "CMP        %[finished], #0      \n\t"
        "CSET       x9, EQ               \n\t"
        "LSL        x9, x9, #24          \n\t"
        "MOV        v26.D[0], x9         \n\t"
        "MOV        v26.D[1], x9         \n\t"
        "CMP        %[bytes], %[POLY1305_BLOCK_SIZE]*6 \n\t"
        "BLO        L_poly1305_64_start_block_size_64_%= \n\t"
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
        "MOV        w29, v4.S[0]         \n\t"
        /* Copy 5*r^4 to ARM */
        "MOV        w15, v5.S[0]         \n\t"
        "MOV        w16, v6.S[0]         \n\t"
        "MOV        w17, v7.S[0]         \n\t"
        "MOV        w18, v8.S[0]         \n\t"
        "MOV        w19, v9.S[0]         \n\t"
        /* Load m */
        /* Load four message blocks to NEON v10, v11, v12, v13, v14 */
        "LD4        { v10.S-v13.S }[0], [%[m]], #16 \n\t"
        "LD4        { v10.S-v13.S }[1], [%[m]], #16 \n\t"
        "LD4        { v10.S-v13.S }[2], [%[m]], #16 \n\t"
        "LD4        { v10.S-v13.S }[3], [%[m]], #16 \n\t"
        "SUB        %[bytes], %[bytes], #4*%[POLY1305_BLOCK_SIZE] \n\t"
        "DUP        v27.4S, v27.S[0]     \n\t"
        "DUP        v26.4S, v26.S[0]     \n\t"
        "USHR       v14.4S, v13.4S, #8   \n\t"
        "ORR        v14.16B, v14.16B, v26.16B \n\t"
        "SHL        v13.4S, v13.4S, #18  \n\t"
        "SRI        v13.4S, v12.4S, #14  \n\t"
        "SHL        v12.4S, v12.4S, #12  \n\t"
        "SRI        v12.4S, v11.4S, #20  \n\t"
        "SHL        v11.4S, v11.4S, #6   \n\t"
        "SRI        v11.4S, v10.4S, #26  \n\t"
        "AND        v10.16B, v10.16B, v27.16B \n\t"
        "AND        v11.16B, v11.16B, v27.16B \n\t"
        "AND        v12.16B, v12.16B, v27.16B \n\t"
        "AND        v13.16B, v13.16B, v27.16B \n\t"
        "AND        v14.16B, v14.16B, v27.16B \n\t"
        "MOV        v27.S[1], wzr        \n\t"
        "MOV        v27.S[3], wzr        \n\t"
        "MOV        v26.S[1], wzr        \n\t"
        "MOV        v26.S[3], wzr        \n\t"
        /* Four message blocks loaded */
        /* Add messages to accumulator */
        "ADD        v15.2S, v15.2S, v10.2S \n\t"
        "ADD        v16.2S, v16.2S, v11.2S \n\t"
        "ADD        v17.2S, v17.2S, v12.2S \n\t"
        "ADD        v18.2S, v18.2S, v13.2S \n\t"
        "ADD        v19.2S, v19.2S, v14.2S \n\t"
        "\n"
    "L_poly1305_64_loop_128_%=: \n\t"
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
        "MUL        x13, x20, x29        \n\t"
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
        "MADD       x9, x22, x18, x9     \n\t"
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
        "MADD       x10, x23, x18, x10   \n\t"
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
        "MADD       x11, x24, x18, x11   \n\t"
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
        "BLS        L_poly1305_64_loop_128_final_%= \n\t"
        /* Load m */
        /* Load four message blocks to NEON v10, v11, v12, v13, v14 */
        "LD4        { v10.S-v13.S }[0], [%[m]], #16 \n\t"
        "LD4        { v10.S-v13.S }[1], [%[m]], #16 \n\t"
        "LD4        { v10.S-v13.S }[2], [%[m]], #16 \n\t"
        "LD4        { v10.S-v13.S }[3], [%[m]], #16 \n\t"
        "SUB        %[bytes], %[bytes], #4*%[POLY1305_BLOCK_SIZE] \n\t"
        "DUP        v27.4S, v27.S[0]     \n\t"
        "DUP        v26.4S, v26.S[0]     \n\t"
        "USHR       v14.4S, v13.4S, #8   \n\t"
        "ORR        v14.16B, v14.16B, v26.16B \n\t"
        "SHL        v13.4S, v13.4S, #18  \n\t"
        "SRI        v13.4S, v12.4S, #14  \n\t"
        "SHL        v12.4S, v12.4S, #12  \n\t"
        "SRI        v12.4S, v11.4S, #20  \n\t"
        "SHL        v11.4S, v11.4S, #6   \n\t"
        "SRI        v11.4S, v10.4S, #26  \n\t"
        "AND        v10.16B, v10.16B, v27.16B \n\t"
        "AND        v11.16B, v11.16B, v27.16B \n\t"
        "AND        v12.16B, v12.16B, v27.16B \n\t"
        "AND        v13.16B, v13.16B, v27.16B \n\t"
        "AND        v14.16B, v14.16B, v27.16B \n\t"
        "MOV        v27.S[1], wzr        \n\t"
        "MOV        v27.S[3], wzr        \n\t"
        "MOV        v26.S[1], wzr        \n\t"
        "MOV        v26.S[3], wzr        \n\t"
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
        "B          L_poly1305_64_loop_128_%= \n\t"
        "\n"
    "L_poly1305_64_loop_128_final_%=: \n\t"
        /* Load m */
        /* Load two message blocks to NEON v10, v11, v12, v13, v14 */
        "LD2        { v10.D-v11.D }[0], [%[m]], #16 \n\t"
        /* Copy r^2 to lower half of registers */
        "MOV        v0.D[0], v0.D[1]     \n\t"
        "LD2        { v10.D-v11.D }[1], [%[m]], #16 \n\t"
        "MOV        v5.D[0], v5.D[1]     \n\t"
        "SUB        %[bytes], %[bytes], #2*%[POLY1305_BLOCK_SIZE] \n\t"
        "MOV        v1.D[0], v1.D[1]     \n\t"
        "USHR       v14.2D, v11.2D, #40  \n\t"
        "MOV        v6.D[0], v6.D[1]     \n\t"
        "ORR        v14.16B, v14.16B, v26.16B \n\t"
        "MOV        v2.D[0], v2.D[1]     \n\t"
        "USHR       v13.2D, v11.2D, #14  \n\t"
        "MOV        v7.D[0], v7.D[1]     \n\t"
        "AND        v13.16B, v13.16B, v27.16B \n\t"
        "MOV        v3.D[0], v3.D[1]     \n\t"
        "SHL        v12.2D, v11.2D, #12  \n\t"
        "MOV        v8.D[0], v8.D[1]     \n\t"
        "SRI        v12.2D, v10.2D, #52  \n\t"
        "MOV        v4.D[0], v4.D[1]     \n\t"
        "AND        v12.16B, v12.16B, v27.16B \n\t"
        "MOV        v9.D[0], v9.D[1]     \n\t"
        "USHR       v11.2D, v10.2D, #26  \n\t"
        /* Copy r^2 to ARM */
        "MOV        w25, v0.S[2]         \n\t"
        "AND        v11.16B, v11.16B, v27.16B \n\t"
        "MOV        w26, v1.S[2]         \n\t"
        "AND        v10.16B, v10.16B, v27.16B \n\t"
        "MOV        w27, v2.S[2]         \n\t"
        /* Two message blocks loaded */
        /* Add last messages */
        "ADD        v21.2D, v21.2D, v10.2D \n\t"
        "MOV        w28, v3.S[2]         \n\t"
        "ADD        v22.2D, v22.2D, v11.2D \n\t"
        "MOV        w29, v4.S[2]         \n\t"
        "ADD        v23.2D, v23.2D, v12.2D \n\t"
        /* Copy 5*r^2 to ARM */
        "MOV        w15, v5.S[2]         \n\t"
        "ADD        v24.2D, v24.2D, v13.2D \n\t"
        "MOV        w16, v6.S[2]         \n\t"
        "ADD        v25.2D, v25.2D, v14.2D \n\t"
        "MOV        w17, v7.S[2]         \n\t"
        /* Reduce message to be ready for next multiplication */
        /* Reduce radix 26 NEON */
        /* Interleave h0 -> h1 -> h2 -> h3 -> h4 */
        /*       with h3 -> h4 -> h0 -> h1 */
        "USRA       v22.2D, v21.2D, #26  \n\t"
        "MOV        w18, v8.S[2]         \n\t"
        "AND        v21.16B, v21.16B, v27.16B \n\t"
        "MOV        w19, v9.S[2]         \n\t"
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
        /* If less than 2 blocks left go straight to final multiplication. */
        "CMP        %[bytes], %[POLY1305_BLOCK_SIZE]*2 \n\t"
        "BLO        L_poly1305_64_last_mult_%= \n\t"
        /* Else go to one loop of L_poly1305_64_loop_64 */
        "B          L_poly1305_64_loop_64_%= \n\t"
        "\n"
    "L_poly1305_64_start_block_size_64_%=: \n\t"
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
        "MOV        w29, v4.S[0]         \n\t"
        /* Copy 5*r^2 to ARM */
        "MOV        w15, v5.S[0]         \n\t"
        "MOV        w16, v6.S[0]         \n\t"
        "MOV        w17, v7.S[0]         \n\t"
        "MOV        w18, v8.S[0]         \n\t"
        "MOV        w19, v9.S[0]         \n\t"
        /* Load m */
        /* Load two message blocks to NEON v10, v11, v12, v13, v14 */
        "LD2        { v10.D-v11.D }[0], [%[m]], #16 \n\t"
        "LD2        { v10.D-v11.D }[1], [%[m]], #16 \n\t"
        "SUB        %[bytes], %[bytes], #2*%[POLY1305_BLOCK_SIZE] \n\t"
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
        "MOV        v10.2S[1], v10.2S[2] \n\t"
        "MOV        v11.2S[1], v11.2S[2] \n\t"
        "MOV        v12.2S[1], v12.2S[2] \n\t"
        "MOV        v13.2S[1], v13.2S[2] \n\t"
        "MOV        v14.2S[1], v14.2S[2] \n\t"
        /* Two message blocks loaded */
        /* Add messages to accumulator */
        "ADD        v15.2S, v15.2S, v10.2S \n\t"
        "ADD        v16.2S, v16.2S, v11.2S \n\t"
        "ADD        v17.2S, v17.2S, v12.2S \n\t"
        "ADD        v18.2S, v18.2S, v13.2S \n\t"
        "ADD        v19.2S, v19.2S, v14.2S \n\t"
        "\n"
    "L_poly1305_64_loop_64_%=: \n\t"
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
        "MUL        x13, x20, x29        \n\t"
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
        "MADD       x9, x22, x18, x9     \n\t"
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
        "MADD       x10, x23, x18, x10   \n\t"
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
        "MADD       x11, x24, x18, x11   \n\t"
        "UMLAL      v24.2D, v19.2S, v9.2S \n\t"
        "MADD       x12, x24, x19, x12   \n\t"
        "UMLAL      v25.2D, v19.2S, v0.2S \n\t"
        "MADD       x13, x24, x25, x13   \n\t"
        /* Load m */
        /* Load two message blocks to NEON v10, v11, v12, v13, v14 */
        "LD2        { v10.D-v11.D }[0], [%[m]], #16 \n\t"
        /* Reduce h % P */
        "MOV        x14, #5              \n\t"
        "LD2        { v10.D-v11.D }[1], [%[m]], #16 \n\t"
        "ADD        x10, x10, x9, LSR #26 \n\t"
        "SUB        %[bytes], %[bytes], #2*%[POLY1305_BLOCK_SIZE] \n\t"
        "ADD        x13, x13, x12, LSR #26 \n\t"
        "USHR       v14.2D, v11.2D, #40  \n\t"
        "AND        x9, x9, #0x3ffffff   \n\t"
        "ORR        v14.16B, v14.16B, v26.16B \n\t"
        "LSR        x20, x13, #26        \n\t"
        "USHR       v13.2D, v11.2D, #14  \n\t"
        "AND        x12, x12, #0x3ffffff \n\t"
        "AND        v13.16B, v13.16B, v27.16B \n\t"
        "MADD       x9, x20, x14, x9     \n\t"
        "SHL        v12.2D, v11.2D, #12  \n\t"
        "ADD        x11, x11, x10, LSR #26 \n\t"
        "SRI        v12.2D, v10.2D, #52  \n\t"
        "AND        x10, x10, #0x3ffffff \n\t"
        "AND        v12.16B, v12.16B, v27.16B \n\t"
        "AND        x13, x13, #0x3ffffff \n\t"
        "USHR       v11.2D, v10.2D, #26  \n\t"
        "ADD        x12, x12, x11, LSR #26 \n\t"
        "AND        v11.16B, v11.16B, v27.16B \n\t"
        "AND        x22, x11, #0x3ffffff \n\t"
        "AND        v10.16B, v10.16B, v27.16B \n\t"
        "ADD        x21, x10, x9, LSR #26 \n\t"
        /* Two message blocks loaded */
        "ADD        v21.2D, v21.2D, v10.2D \n\t"
        "AND        x20, x9, #0x3ffffff  \n\t"
        "ADD        v22.2D, v22.2D, v11.2D \n\t"
        "ADD        x24, x13, x12, LSR #26 \n\t"
        "ADD        v23.2D, v23.2D, v12.2D \n\t"
        "AND        x23, x12, #0x3ffffff \n\t"
        "ADD        v24.2D, v24.2D, v13.2D \n\t"
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
        "BHS        L_poly1305_64_loop_64_%= \n\t"
        "\n"
    "L_poly1305_64_last_mult_%=: \n\t"
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
        "MUL        v5.2S, v0.2S, v28.2S[0] \n\t"
        "MUL        x12, x20, x28        \n\t"
        "MUL        v6.2S, v1.2S, v28.2S[0] \n\t"
        "MUL        x13, x20, x29        \n\t"
        "MUL        v7.2S, v2.2S, v28.2S[0] \n\t"
        "MADD       x9, x21, x19, x9     \n\t"
        "MUL        v8.2S, v3.2S, v28.2S[0] \n\t"
        "MADD       x10, x21, x25, x10   \n\t"
        "MUL        v9.2S, v4.2S, v28.2S[0] \n\t"
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
        "MADD       x9, x22, x18, x9     \n\t"
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
        "MADD       x10, x23, x18, x10   \n\t"
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
        "MADD       x11, x24, x18, x11   \n\t"
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
    "L_poly1305_64_done_%=: \n\t"
        : [bytes] "+r" (bytes),
          [m] "+r" (m),
          [ctx] "+m" (ctx)
        : [POLY1305_BLOCK_SIZE] "I" (POLY1305_BLOCK_SIZE),
          [h] "r" (ctx->h),
          [r] "r" (ctx->r),
          [r_2] "r" (ctx->r_2),
          [r_4] "r" (ctx->r_4),
          [finished] "r" (ctx->finished)
        : "memory", "cc",
          "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9",
          "v10", "v11", "v12", "v13", "v14", "v15", "v16", "v17", "v18", "v19",
          "v21", "v22", "v23", "v24", "v25", "v26", "v27", "v28", "w9", "w10",
          "w11", "w12", "w13", "w14", "w15", "w16", "w17", "w18", "w19", "w20",
          "w21", "w22", "w23", "w24", "w25", "w26", "w27", "w28", "w29", "x9",
          "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18", "x19",
          "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29"
    );
    poly1305_blocks_16(ctx, m, bytes);
#else
    poly1305_blocks_16(ctx, m, bytes);
#endif /* POLY130564 */
}

static void poly1305_block(Poly1305* ctx, const unsigned char *m)
{
    poly1305_blocks_16(ctx, m, POLY1305_BLOCK_SIZE);
}

static word64 clamp[] = {
    0x0ffffffc0fffffff,
    0x0ffffffc0ffffffc,
};


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

#if defined(POLY130564)
    __asm__ __volatile__ (
        /* Load key material */
        "LDP        x8, x9, [%[key]]     \n\t"
        "LDP        x10, x11, [%[key], #16] \n\t"
        /* Load clamp */
        "LDP        x12, x13, [%[clamp]] \n\t"
        /* Apply clamp */
        /* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
        "AND        x8, x8, x12          \n\t"
        "AND        x9, x9, x13          \n\t"
        "MOV        x19, xzr             \n\t"
        "MOV        x20, xzr             \n\t"
        "MOV        x21, xzr             \n\t"
        "MOV        x22, xzr             \n\t"
        "MOV        x23, xzr             \n\t"
        "BFI        x19, x8, #0, #26     \n\t"
        "LSR        x8, x8, #26          \n\t"
        "BFI        x20, x8, #0, #26     \n\t"
        "LSR        x8, x8, #26          \n\t"
        "BFI        x21, x8, #0, #12     \n\t"
        "BFI        x21, x9, #12, #14    \n\t"
        "LSR        x9, x9, #14          \n\t"
        "BFI        x22, x9, #0, #26     \n\t"
        "LSR        x9, x9, #26          \n\t"
        "BFI        x23, x9, #0, #24     \n\t"
        /* Compute r^2 */
        /* r*5 */
        "MOV        x8, #5               \n\t"
        "MUL        x24, x20, x8         \n\t"
        "MUL        x25, x21, x8         \n\t"
        "MUL        x26, x22, x8         \n\t"
        "MUL        x27, x23, x8         \n\t"
        /* d = r*r */
        /* d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1 */
        /* d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2 */
        /* d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3 */
        /* d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4 */
        /* d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0 */
        "MUL        x14, x19, x19        \n\t"
        "MUL        x15, x19, x20        \n\t"
        "MUL        x16, x19, x21        \n\t"
        "MUL        x17, x19, x22        \n\t"
        "MUL        x18, x19, x23        \n\t"
        "MADD       x14, x20, x27, x14   \n\t"
        "MADD       x15, x20, x19, x15   \n\t"
        "MADD       x16, x20, x20, x16   \n\t"
        "MADD       x17, x20, x21, x17   \n\t"
        "MADD       x18, x20, x22, x18   \n\t"
        "MADD       x14, x21, x26, x14   \n\t"
        "MADD       x15, x21, x27, x15   \n\t"
        "MADD       x16, x21, x19, x16   \n\t"
        "MADD       x17, x21, x20, x17   \n\t"
        "MADD       x18, x21, x21, x18   \n\t"
        "MADD       x14, x22, x25, x14   \n\t"
        "MADD       x15, x22, x26, x15   \n\t"
        "MADD       x16, x22, x27, x16   \n\t"
        "MADD       x17, x22, x19, x17   \n\t"
        "MADD       x18, x22, x20, x18   \n\t"
        "MADD       x14, x23, x24, x14   \n\t"
        "MADD       x15, x23, x25, x15   \n\t"
        "MADD       x16, x23, x26, x16   \n\t"
        "MADD       x17, x23, x27, x17   \n\t"
        "MADD       x18, x23, x19, x18   \n\t"
        /* r_2 = r^2 % P */
        "ADD        x15, x15, x14, LSR #26 \n\t"
        "ADD        x18, x18, x17, LSR #26 \n\t"
        "AND        x14, x14, #0x3ffffff \n\t"
        "LSR        x9, x18, #26         \n\t"
        "AND        x17, x17, #0x3ffffff \n\t"
        "MADD       x14, x9, x8, x14     \n\t"
        "ADD        x16, x16, x15, LSR #26 \n\t"
        "AND        x15, x15, #0x3ffffff \n\t"
        "AND        x18, x18, #0x3ffffff \n\t"
        "ADD        x17, x17, x16, LSR #26 \n\t"
        "AND        x16, x16, #0x3ffffff \n\t"
        "ADD        x15, x15, x14, LSR #26 \n\t"
        "AND        x14, x14, #0x3ffffff \n\t"
        "ADD        x18, x18, x17, LSR #26 \n\t"
        "AND        x17, x17, #0x3ffffff \n\t"
        /* Store r */
        "ORR        x19, x19, x20, LSL #32 \n\t"
        "ORR        x21, x21, x22, LSL #32 \n\t"
        "STP        x19, x21, [%[ctx_r]] \n\t"
        "STR        w23, [%[ctx_r], ##16] \n\t"
        "MOV        x8, #5               \n\t"
        "MUL        x24, x15, x8         \n\t"
        "MUL        x25, x16, x8         \n\t"
        "MUL        x26, x17, x8         \n\t"
        "MUL        x27, x18, x8         \n\t"
        /* Compute r^4 */
        /* d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1 */
        /* d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2 */
        /* d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3 */
        /* d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4 */
        /* d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0 */
        "MUL        x19, x14, x14        \n\t"
        "MUL        x20, x14, x15        \n\t"
        "MUL        x21, x14, x16        \n\t"
        "MUL        x22, x14, x17        \n\t"
        "MUL        x23, x14, x18        \n\t"
        "MADD       x19, x15, x27, x19   \n\t"
        "MADD       x20, x15, x14, x20   \n\t"
        "MADD       x21, x15, x15, x21   \n\t"
        "MADD       x22, x15, x16, x22   \n\t"
        "MADD       x23, x15, x17, x23   \n\t"
        "MADD       x19, x16, x26, x19   \n\t"
        "MADD       x20, x16, x27, x20   \n\t"
        "MADD       x21, x16, x14, x21   \n\t"
        "MADD       x22, x16, x15, x22   \n\t"
        "MADD       x23, x16, x16, x23   \n\t"
        "MADD       x19, x17, x25, x19   \n\t"
        "MADD       x20, x17, x26, x20   \n\t"
        "MADD       x21, x17, x27, x21   \n\t"
        "MADD       x22, x17, x14, x22   \n\t"
        "MADD       x23, x17, x15, x23   \n\t"
        "MADD       x19, x18, x24, x19   \n\t"
        "MADD       x20, x18, x25, x20   \n\t"
        "MADD       x21, x18, x26, x21   \n\t"
        "MADD       x22, x18, x27, x22   \n\t"
        "MADD       x23, x18, x14, x23   \n\t"
        /* r^4 % P */
        "ADD        x20, x20, x19, LSR #26 \n\t"
        "ADD        x23, x23, x22, LSR #26 \n\t"
        "AND        x19, x19, #0x3ffffff \n\t"
        "LSR        x9, x23, #26         \n\t"
        "AND        x22, x22, #0x3ffffff \n\t"
        "MADD       x19, x9, x8, x19     \n\t"
        "ADD        x21, x21, x20, LSR #26 \n\t"
        "AND        x20, x20, #0x3ffffff \n\t"
        "AND        x23, x23, #0x3ffffff \n\t"
        "ADD        x22, x22, x21, LSR #26 \n\t"
        "AND        x21, x21, #0x3ffffff \n\t"
        "ADD        x20, x20, x19, LSR #26 \n\t"
        "AND        x19, x19, #0x3ffffff \n\t"
        "ADD        x23, x23, x22, LSR #26 \n\t"
        "AND        x22, x22, #0x3ffffff \n\t"
        /* Store r^2 */
        "ORR        x14, x14, x15, LSL #32 \n\t"
        "ORR        x16, x16, x17, LSL #32 \n\t"
        "STP        x14, x16, [%[ctx_r_2]] \n\t"
        "STR        w18, [%[ctx_r_2], ##16] \n\t"
        /* Store r^4 */
        "ORR        x19, x19, x20, LSL #32 \n\t"
        "ORR        x21, x21, x22, LSL #32 \n\t"
        "STP        x19, x21, [%[ctx_r_4]] \n\t"
        "STR        w23, [%[ctx_r_4], ##16] \n\t"
        /* h (accumulator) = 0 */
        "STP        xzr, xzr, [%[ctx_h_0]] \n\t"
        "STR        wzr, [%[ctx_h_0], ##16] \n\t"
        /* Save pad for later */
        "STP        x10, x11, [%[ctx_pad]] \n\t"
        /* Zero leftover */
        "STR        xzr, [%[ctx_leftover]] \n\t"
        /* Zero finished */
        "STRB       wzr, [%[ctx_finished]] \n\t"
        :
        : [clamp] "r" (clamp),
          [key] "r" (key),
          [ctx_r] "r" (ctx->r),
          [ctx_r_2] "r" (ctx->r_2),
          [ctx_r_4] "r" (ctx->r_4),
          [ctx_h_0] "r" (ctx->h),
          [ctx_pad] "r" (ctx->pad),
          [ctx_leftover] "r" (&ctx->leftover),
          [ctx_finished] "r" (&ctx->finished)
        : "memory", "cc",
          "w14", "w15", "w16", "w17", "w18", "w19", "w20", "w21", "w22", "w23",
          "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17",
          "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27"
    );

#else /* if not 64 bit then use 32 bit */

    /* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
    ctx->r[0] = (U8TO32(key +  0)     ) & 0x3ffffff;
    ctx->r[1] = (U8TO32(key +  3) >> 2) & 0x3ffff03;
    ctx->r[2] = (U8TO32(key +  6) >> 4) & 0x3ffc0ff;
    ctx->r[3] = (U8TO32(key +  9) >> 6) & 0x3f03fff;
    ctx->r[4] = (U8TO32(key + 12) >> 8) & 0x00fffff;

    /* h = 0 */
    ctx->h[0] = 0;
    ctx->h[1] = 0;
    ctx->h[2] = 0;
    ctx->h[3] = 0;
    ctx->h[4] = 0;

    /* save pad for later */
    ctx->pad[0] = U8TO32(key + 16);
    ctx->pad[1] = U8TO32(key + 20);
    ctx->pad[2] = U8TO32(key + 24);
    ctx->pad[3] = U8TO32(key + 28);

    ctx->leftover = 0;
    ctx->finished = 0;

#endif

    return 0;
}


int wc_Poly1305Final(Poly1305* ctx, byte* mac)
{
#if !defined(POLY130564)

    word32 h0,h1,h2,h3,h4,c;
    word32 g0,g1,g2,g3,g4;
    word64 f;
    word32 mask;

#endif

    if (ctx == NULL)
        return BAD_FUNC_ARG;

#if defined(POLY130564)
    /* process the remaining block */
    if (ctx->leftover) {
        size_t i = ctx->leftover;
        ctx->buffer[i++] = 1;
        for (; i < POLY1305_BLOCK_SIZE; i++)
            ctx->buffer[i] = 0;
        ctx->finished = 1;
        poly1305_block(ctx, ctx->buffer);
    }

    __asm__ __volatile__ (
        /* Load raw h and zero h registers */
        "LDP        x2, x3, %[h_addr]    \n\t"
        "MOV        x5, xzr              \n\t"
        "LDR        w4, %[h_4_addr]      \n\t"
        "MOV        x6, xzr              \n\t"
        "LDP        x16, x17, %[pad_addr] \n\t"
        /* Base 26 -> Base 64 */
        "MOV        w5, w2               \n\t"
        "LSR        x2, x2, #32          \n\t"
        "ORR        x5, x5, x2, LSL #26  \n\t"
        "ORR        x5, x5, x3, LSL #52  \n\t"
        "LSR        w6, w3, #12          \n\t"
        "LSR        x3, x3, #32          \n\t"
        "ORR        x6, x6, x3, LSL #14  \n\t"
        "ORR        x6, x6, x4, LSL #40  \n\t"
        "LSR        x7, x4, #24          \n\t"
        /* Check if h is larger than p */
        "ADDS       x2, x5, #5           \n\t"
        "ADCS       x3, x6, xzr          \n\t"
        "ADC        x4, x7, xzr          \n\t"
        /* Check if h+5 is larger than 2^130 */
        "CMP        x4, #3               \n\t"
        "CSEL       x5, x2, x5, HI       \n\t"
        "CSEL       x6, x3, x6, HI       \n\t"
        "ADDS       x5, x5, x16          \n\t"
        "ADC        x6, x6, x17          \n\t"
        "STP        x5, x6, [%[mac]]     \n\t"
        : [mac] "+r" (mac)
        : [pad_addr] "m" (ctx->pad),
          [h_addr] "m" (ctx->h),
          [h_4_addr] "m" (ctx->h[4])
        : "memory", "cc",
          "w2", "w3", "w4", "w5", "w6", "w7", "x2", "x3", "x4", "x5",
          "x6", "x7", "x16", "x17"
    );

    /* zero out the state */
    ctx->h[0] = 0;
    ctx->h[1] = 0;
    ctx->h[2] = 0;
    ctx->h[3] = 0;
    ctx->h[4] = 0;
    ctx->r[0] = 0;
    ctx->r[1] = 0;
    ctx->r[2] = 0;
    ctx->r[3] = 0;
    ctx->r[4] = 0;
    ctx->r_2[0] = 0;
    ctx->r_2[1] = 0;
    ctx->r_2[2] = 0;
    ctx->r_2[3] = 0;
    ctx->r_2[4] = 0;
    ctx->r_4[0] = 0;
    ctx->r_4[1] = 0;
    ctx->r_4[2] = 0;
    ctx->r_4[3] = 0;
    ctx->r_4[4] = 0;
    ctx->pad[0] = 0;
    ctx->pad[1] = 0;
    ctx->pad[2] = 0;
    ctx->pad[3] = 0;

#else /* if not 64 bit then use 32 bit */

    /* process the remaining block */
    if (ctx->leftover) {
        size_t i = ctx->leftover;
        ctx->buffer[i++] = 1;
        for (; i < POLY1305_BLOCK_SIZE; i++)
            ctx->buffer[i] = 0;
        ctx->finished = 1;
        poly1305_block(ctx, ctx->buffer);
    }

    /* fully carry h */
    h0 = ctx->h[0];
    h1 = ctx->h[1];
    h2 = ctx->h[2];
    h3 = ctx->h[3];
    h4 = ctx->h[4];

                 c = h1 >> 26; h1 = h1 & 0x3ffffff;
    h2 +=     c; c = h2 >> 26; h2 = h2 & 0x3ffffff;
    h3 +=     c; c = h3 >> 26; h3 = h3 & 0x3ffffff;
    h4 +=     c; c = h4 >> 26; h4 = h4 & 0x3ffffff;
    h0 += c * 5; c = h0 >> 26; h0 = h0 & 0x3ffffff;
    h1 +=     c;

    /* compute h + -p */
    g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    g4 = h4 + c - ((word32)1 << 26);

    /* select h if h < p, or h + -p if h >= p */
    mask = ((word32)g4 >> ((sizeof(word32) * 8) - 1)) - 1;
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    g3 &= mask;
    g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    /* h = h % (2^128) */
    h0 = ((h0      ) | (h1 << 26)) & 0xffffffff;
    h1 = ((h1 >>  6) | (h2 << 20)) & 0xffffffff;
    h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
    h3 = ((h3 >> 18) | (h4 <<  8)) & 0xffffffff;

    /* mac = (h + pad) % (2^128) */
    f = (word64)h0 + ctx->pad[0]            ; h0 = (word32)f;
    f = (word64)h1 + ctx->pad[1] + (f >> 32); h1 = (word32)f;
    f = (word64)h2 + ctx->pad[2] + (f >> 32); h2 = (word32)f;
    f = (word64)h3 + ctx->pad[3] + (f >> 32); h3 = (word32)f;

    U32TO8(mac + 0, h0);
    U32TO8(mac + 4, h1);
    U32TO8(mac + 8, h2);
    U32TO8(mac + 12, h3);

    /* zero out the state */
    ctx->h[0] = 0;
    ctx->h[1] = 0;
    ctx->h[2] = 0;
    ctx->h[3] = 0;
    ctx->h[4] = 0;
    ctx->r[0] = 0;
    ctx->r[1] = 0;
    ctx->r[2] = 0;
    ctx->r[3] = 0;
    ctx->r[4] = 0;
    ctx->pad[0] = 0;
    ctx->pad[1] = 0;
    ctx->pad[2] = 0;
    ctx->pad[3] = 0;

#endif

    return 0;
}


int wc_Poly1305Update(Poly1305* ctx, const byte* m, word32 bytes)
{
    size_t i;

#ifdef CHACHA_AEAD_TEST
    word32 k;
    printf("Raw input to poly:\n");
    for (k = 0; k < bytes; k++) {
        printf("%02x", m[k]);
        if ((k+1) % 16 == 0)
            printf("\n");
    }
    printf("\n");
#endif

    if (ctx == NULL)
        return BAD_FUNC_ARG;

    {
        /* handle leftover */
        if (ctx->leftover) {
            size_t want = (POLY1305_BLOCK_SIZE - ctx->leftover);
            if (want > bytes)
                want = bytes;
            for (i = 0; i < want; i++)
                ctx->buffer[ctx->leftover + i] = m[i];
            bytes -= (word32)want;
            m += want;
            ctx->leftover += want;
            if (ctx->leftover < POLY1305_BLOCK_SIZE)
                return 0;
            poly1305_block(ctx, ctx->buffer);
            ctx->leftover = 0;
        }

        /* process full blocks */
        if (bytes >= POLY1305_BLOCK_SIZE) {
            size_t want = (bytes & ~(POLY1305_BLOCK_SIZE - 1));
            poly1305_blocks(ctx, m, want);
            m += want;
            bytes -= (word32)want;
        }

        /* store leftover */
        if (bytes) {
            for (i = 0; i < bytes; i++)
                ctx->buffer[ctx->leftover + i] = m[i];
            ctx->leftover += bytes;
        }
    }

    return 0;
}


/*  Takes in an initialized Poly1305 struct that has a key loaded and creates
    a MAC (tag) using recent TLS AEAD padding scheme.
    ctx        : Initialized Poly1305 struct to use
    additional : Additional data to use
    addSz      : Size of additional buffer
    input      : Input buffer to create tag from
    sz         : Size of input buffer
    tag        : Buffer to hold created tag
    tagSz      : Size of input tag buffer (must be at least
                 WC_POLY1305_MAC_SZ(16))
 */
int wc_Poly1305_MAC(Poly1305* ctx, byte* additional, word32 addSz,
                    byte* input, word32 sz, byte* tag, word32 tagSz)
{
    int ret;
    byte padding[WC_POLY1305_PAD_SZ - 1];
    word32 paddingLen;
    byte little64[16];

    XMEMSET(padding, 0, sizeof(padding));

    /* sanity check on arguments */
    if (ctx == NULL || input == NULL || tag == NULL ||
                                                   tagSz < WC_POLY1305_MAC_SZ) {
        return BAD_FUNC_ARG;
    }

    /* additional allowed to be 0 */
    if (addSz > 0) {
        if (additional == NULL)
            return BAD_FUNC_ARG;

        /* additional data plus padding */
        if ((ret = wc_Poly1305Update(ctx, additional, addSz)) != 0) {
            return ret;
        }
        paddingLen = -((int)addSz) & (WC_POLY1305_PAD_SZ - 1);
        if (paddingLen) {
            if ((ret = wc_Poly1305Update(ctx, padding, paddingLen)) != 0) {
                return ret;
            }
        }
    }

    /* input plus padding */
    if ((ret = wc_Poly1305Update(ctx, input, sz)) != 0) {
        return ret;
    }
    paddingLen = -((int)sz) & (WC_POLY1305_PAD_SZ - 1);
    if (paddingLen) {
        if ((ret = wc_Poly1305Update(ctx, padding, paddingLen)) != 0) {
            return ret;
        }
    }

    /* size of additional data and input as little endian 64 bit types */
    U32TO64(addSz, little64);
    U32TO64(sz, little64 + 8);
    ret = wc_Poly1305Update(ctx, little64, sizeof(little64));
    if (ret)
    {
        return ret;
    }

    /* Finalize the auth tag */
    ret = wc_Poly1305Final(ctx, tag);

    return ret;

}
#endif /* HAVE_POLY1305 */
#endif /* WOLFSSL_ARMASM */

