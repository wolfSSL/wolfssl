/* armv8-sha256.c
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.
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
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if !defined(NO_SHA256) && defined(WOLFSSL_ARMASM)
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#ifndef WOLFSSL_HAVE_MIN
#define WOLFSSL_HAVE_MIN

    static INLINE word32 min(word32 a, word32 b)
    {
        return a > b ? b : a;
    }

#endif /* WOLFSSL_HAVE_MIN */

#if !defined (ALIGN32)
    #if defined (__GNUC__)
        #define ALIGN32 __attribute__ ( (aligned (32)))
    #elif defined(_MSC_VER)
        /* disable align warning, we want alignment ! */
        #pragma warning(disable: 4324)
        #define ALIGN32 __declspec (align (32))
    #else
        #define ALIGN32
    #endif
#endif

static const ALIGN32 word32 K[64] = {
    0x428A2F98L, 0x71374491L, 0xB5C0FBCFL, 0xE9B5DBA5L, 0x3956C25BL,
    0x59F111F1L, 0x923F82A4L, 0xAB1C5ED5L, 0xD807AA98L, 0x12835B01L,
    0x243185BEL, 0x550C7DC3L, 0x72BE5D74L, 0x80DEB1FEL, 0x9BDC06A7L,
    0xC19BF174L, 0xE49B69C1L, 0xEFBE4786L, 0x0FC19DC6L, 0x240CA1CCL,
    0x2DE92C6FL, 0x4A7484AAL, 0x5CB0A9DCL, 0x76F988DAL, 0x983E5152L,
    0xA831C66DL, 0xB00327C8L, 0xBF597FC7L, 0xC6E00BF3L, 0xD5A79147L,
    0x06CA6351L, 0x14292967L, 0x27B70A85L, 0x2E1B2138L, 0x4D2C6DFCL,
    0x53380D13L, 0x650A7354L, 0x766A0ABBL, 0x81C2C92EL, 0x92722C85L,
    0xA2BFE8A1L, 0xA81A664BL, 0xC24B8B70L, 0xC76C51A3L, 0xD192E819L,
    0xD6990624L, 0xF40E3585L, 0x106AA070L, 0x19A4C116L, 0x1E376C08L,
    0x2748774CL, 0x34B0BCB5L, 0x391C0CB3L, 0x4ED8AA4AL, 0x5B9CCA4FL,
    0x682E6FF3L, 0x748F82EEL, 0x78A5636FL, 0x84C87814L, 0x8CC70208L,
    0x90BEFFFAL, 0xA4506CEBL, 0xBEF9A3F7L, 0xC67178F2L
};

int wc_InitSha256(Sha256* sha256)
{
    int ret = 0;

    if (sha256 == NULL) {
        return BAD_FUNC_ARG;
    }

    sha256->digest[0] = 0x6A09E667L;
    sha256->digest[1] = 0xBB67AE85L;
    sha256->digest[2] = 0x3C6EF372L;
    sha256->digest[3] = 0xA54FF53AL;
    sha256->digest[4] = 0x510E527FL;
    sha256->digest[5] = 0x9B05688CL;
    sha256->digest[6] = 0x1F83D9ABL;
    sha256->digest[7] = 0x5BE0CD19L;

    sha256->buffLen = 0;
    sha256->loLen   = 0;
    sha256->hiLen   = 0;

    return ret;
}


static INLINE void AddLength(Sha256* sha256, word32 len)
{
    word32 tmp = sha256->loLen;
    if ( (sha256->loLen += len) < tmp)
        sha256->hiLen++;                       /* carry low to high */
}


#ifdef __aarch64__
/* ARMv8 hardware accleration */
int wc_Sha256Update(Sha256* sha256, const byte* data, word32 len)
{
    word32 add;
    word32 numBlocks;

    if (sha256 == NULL || (data == NULL && len != 0)) {
        return BAD_FUNC_ARG;
    }

    /* only perform actions if a buffer is passed in */
    if (len > 0) {
        /* fill leftover buffer with data */
        add = min(len, SHA256_BLOCK_SIZE - sha256->buffLen);
        XMEMCPY((byte*)(sha256->buffer) + sha256->buffLen, data, add);
        sha256->buffLen += add;
        data            += add;
        len             -= add;

        /* number of blocks in a row to complete */
        numBlocks = (len + sha256->buffLen)/SHA256_BLOCK_SIZE;

        if (numBlocks > 0) {
            word32* k = (word32*)K;

            /* get leftover amount after blocks */
            add = (len + sha256->buffLen) - numBlocks * SHA256_BLOCK_SIZE;
            __asm__ volatile (
            "#load leftover data\n"
            "LD1 {v0.2d-v3.2d}, %[buffer]   \n"

            "#load current digest\n"
            "LD1 {v12.2d-v13.2d}, %[digest] \n"
            "MOV w8, %w[blocks] \n"
            "REV32 v0.16b, v0.16b \n"
            "REV32 v1.16b, v1.16b \n"
            "REV32 v2.16b, v2.16b \n"
            "REV32 v3.16b, v3.16b \n"

            "#load K values in \n"
            "LD1 {v16.4s-v19.4s}, [%[k]], #64    \n"
            "LD1 {v20.4s-v23.4s}, [%[k]], #64    \n"
            "MOV v14.16b, v12.16b \n" /* store digest for add at the end */
            "MOV v15.16b, v13.16b \n"
            "LD1 {v24.4s-v27.4s}, [%[k]], #64    \n"
            "LD1 {v28.4s-v31.4s}, [%[k]], #64    \n"

            /* begining of SHA256 block operation */
            "1:\n"
            /* Round 1 */
            "MOV v4.16b, v0.16b        \n"
            "ADD v0.4s, v0.4s, v16.4s  \n"
            "MOV v11.16b, v12.16b      \n"
            "SHA256H q12, q13, v0.4s   \n"
            "SHA256H2 q13, q11, v0.4s  \n"

            /* Round 2 */
            "SHA256SU0 v4.4s, v1.4s        \n"
            "ADD v0.4s, v1.4s, v17.4s  \n"
            "MOV v11.16b, v12.16b      \n"
            "SHA256SU1 v4.4s, v2.4s, v3.4s \n"
            "SHA256H q12, q13, v0.4s   \n"
            "SHA256H2 q13, q11, v0.4s  \n"

            /* Round 3 */
            "SHA256SU0 v1.4s, v2.4s        \n"
            "ADD v0.4s, v2.4s, v18.4s  \n"
            "MOV v11.16b, v12.16b      \n"
            "SHA256SU1 v1.4s, v3.4s, v4.4s \n"
            "SHA256H q12, q13, v0.4s   \n"
            "SHA256H2 q13, q11, v0.4s  \n"

            /* Round 4 */
            "SHA256SU0 v2.4s, v3.4s        \n"
            "ADD v0.4s, v3.4s, v19.4s      \n"
            "MOV v11.16b, v12.16b          \n"
            "SHA256SU1 v2.4s, v4.4s, v1.4s \n"
            "SHA256H q12, q13, v0.4s       \n"
            "SHA256H2 q13, q11, v0.4s      \n"

            /* Round 5 */
            "SHA256SU0 v3.4s, v4.4s        \n"
            "ADD v0.4s, v4.4s, v20.4s      \n"
            "MOV v11.16b, v12.16b          \n"
            "SHA256SU1 v3.4s, v1.4s, v2.4s \n"
            "SHA256H q12, q13, v0.4s       \n"
            "SHA256H2 q13, q11, v0.4s      \n"

            /* Round 6 */
            "SHA256SU0 v4.4s, v1.4s        \n"
            "ADD v0.4s, v1.4s, v21.4s      \n"
            "MOV v11.16b, v12.16b          \n"
            "SHA256SU1 v4.4s, v2.4s, v3.4s \n"
            "SHA256H q12, q13, v0.4s       \n"
            "SHA256H2 q13, q11, v0.4s      \n"

            /* Round 7 */
            "SHA256SU0 v1.4s, v2.4s        \n"
            "ADD v0.4s, v2.4s, v22.4s      \n"
            "MOV v11.16b, v12.16b          \n"
            "SHA256SU1 v1.4s, v3.4s, v4.4s \n"
            "SHA256H q12, q13, v0.4s       \n"
            "SHA256H2 q13, q11, v0.4s      \n"

            /* Round 8 */
            "SHA256SU0 v2.4s, v3.4s        \n"
            "ADD v0.4s, v3.4s, v23.4s      \n"
            "MOV v11.16b, v12.16b          \n"
            "SHA256SU1 v2.4s, v4.4s, v1.4s \n"
            "SHA256H q12, q13, v0.4s       \n"
            "SHA256H2 q13, q11, v0.4s      \n"

            /* Round 9 */
            "SHA256SU0 v3.4s, v4.4s        \n"
            "ADD v0.4s, v4.4s, v24.4s      \n"
            "MOV v11.16b, v12.16b          \n"
            "SHA256SU1 v3.4s, v1.4s, v2.4s \n"
            "SHA256H q12, q13, v0.4s       \n"
            "SHA256H2 q13, q11, v0.4s      \n"

            /* Round 10 */
            "SHA256SU0 v4.4s, v1.4s        \n"
            "ADD v0.4s, v1.4s, v25.4s      \n"
            "MOV v11.16b, v12.16b          \n"
            "SHA256SU1 v4.4s, v2.4s, v3.4s \n"
            "SHA256H q12, q13, v0.4s       \n"
            "SHA256H2 q13, q11, v0.4s      \n"

            /* Round 11 */
            "SHA256SU0 v1.4s, v2.4s        \n"
            "ADD v0.4s, v2.4s, v26.4s      \n"
            "MOV v11.16b, v12.16b          \n"
            "SHA256SU1 v1.4s, v3.4s, v4.4s \n"
            "SHA256H q12, q13, v0.4s       \n"
            "SHA256H2 q13, q11, v0.4s      \n"

            /* Round 12 */
            "SHA256SU0 v2.4s, v3.4s        \n"
            "ADD v0.4s, v3.4s, v27.4s      \n"
            "MOV v11.16b, v12.16b          \n"
            "SHA256SU1 v2.4s, v4.4s, v1.4s \n"
            "SHA256H q12, q13, v0.4s       \n"
            "SHA256H2 q13, q11, v0.4s      \n"

            /* Round 13 */
            "SHA256SU0 v3.4s, v4.4s        \n"
            "ADD v0.4s, v4.4s, v28.4s      \n"
            "MOV v11.16b, v12.16b          \n"
            "SHA256SU1 v3.4s, v1.4s, v2.4s \n"
            "SHA256H q12, q13, v0.4s       \n"
            "SHA256H2 q13, q11, v0.4s      \n"

            /* Round 14 */
            "ADD v0.4s, v1.4s, v29.4s      \n"
            "MOV v11.16b, v12.16b          \n"
            "SHA256H q12, q13, v0.4s       \n"
            "SHA256H2 q13, q11, v0.4s      \n"

            /* Round 15 */
            "ADD v0.4s, v2.4s, v30.4s      \n"
            "MOV v11.16b, v12.16b          \n"
            "SHA256H q12, q13, v0.4s       \n"
            "SHA256H2 q13, q11, v0.4s      \n"

            /* Round 16 */
            "ADD v0.4s, v3.4s, v31.4s      \n"
            "MOV v11.16b, v12.16b          \n"
            "SHA256H q12, q13, v0.4s       \n"
            "SHA256H2 q13, q11, v0.4s      \n"

            "#Add working vars back into digest state \n"
            "SUB w8, w8, #1    \n"
            "ADD v12.4s, v12.4s, v14.4s \n"
            "ADD v13.4s, v13.4s, v15.4s \n"

            "#check if more blocks should be done\n"
            "CBZ w8, 2f \n"

            "#load in message and schedual updates \n"
            "LD1 {v0.2d-v3.2d}, [%[dataIn]], #64   \n"
            "MOV v14.16b, v12.16b \n"
            "MOV v15.16b, v13.16b \n"
            "REV32 v0.16b, v0.16b \n"
            "REV32 v1.16b, v1.16b \n"
            "REV32 v2.16b, v2.16b \n"
            "REV32 v3.16b, v3.16b \n"
            "B 1b \n" /* do another block */

            "2:\n"
            "STP q12, q13, %[out] \n"

            : [out] "=m" (sha256->digest), "=m" (sha256->buffer), "=r" (numBlocks),
              "=r" (data), "=r" (k)
            : [k] "4" (k), [digest] "m" (sha256->digest), [buffer] "m" (sha256->buffer),
              [blocks] "2" (numBlocks), [dataIn] "3" (data)
            : "cc", "memory", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7",
                              "v8",  "v9",  "v10", "v11", "v12", "v13", "v14",
                              "v15", "v16", "v17", "v18", "v19", "v20", "v21",
                              "v22", "v23", "v24", "v25", "v26", "v27", "v28",
                              "v29", "v30", "v31", "w8"
            );

            AddLength(sha256, SHA256_BLOCK_SIZE * numBlocks);

            /* copy over any remaining data leftover */
            XMEMCPY(sha256->buffer, data, add);
            sha256->buffLen = add;
        }
    }

    /* account for possiblity of not used if len = 0 */
    (void)add;
    (void)numBlocks;

    return 0;
}


int wc_Sha256Final(Sha256* sha256, byte* hash)
{
    byte* local;

    if (sha256 == NULL || hash == NULL) {
        return BAD_FUNC_ARG;
    }

    local = (byte*)sha256->buffer;
    AddLength(sha256, sha256->buffLen);  /* before adding pads */

    local[sha256->buffLen++] = 0x80;     /* add 1 */

    /* pad with zeros */
    if (sha256->buffLen > SHA256_PAD_SIZE) {

        XMEMSET(&local[sha256->buffLen], 0, SHA256_BLOCK_SIZE - sha256->buffLen);
        sha256->buffLen += SHA256_BLOCK_SIZE - sha256->buffLen;
        __asm__ volatile (
            "LD1 {v4.2d-v7.2d}, %[buffer]          \n"
            "MOV v0.16b, v4.16b                    \n"
            "MOV v1.16b, v5.16b                    \n"
            "REV32 v0.16b, v0.16b                  \n"
            "REV32 v1.16b, v1.16b                  \n"
            "MOV v2.16b, v6.16b                    \n"
            "MOV v3.16b, v7.16b                    \n"
            "REV32 v2.16b, v2.16b                  \n"
            "REV32 v3.16b, v3.16b                  \n"
            "MOV v4.16b, v0.16b                    \n"
            "MOV v5.16b, v1.16b                    \n"
            "LD1 {v20.2d-v21.2d}, %[digest]        \n"

            "#SHA256 operation on updated message  \n"
            "MOV v16.16b, v20.16b \n"
            "MOV v17.16b, v21.16b \n"

            "LD1 {v22.16b-v25.16b}, [%[k]], #64 \n"
            "SHA256SU0 v4.4s, v1.4s        \n"
            "ADD v0.4s, v0.4s, v22.4s      \n"
            "MOV v6.16b, v2.16b            \n"
            "MOV v18.16b, v16.16b          \n"
            "SHA256SU1 v4.4s, v2.4s, v3.4s \n"
            "SHA256H q16, q17, v0.4s       \n"
            "SHA256H2 q17, q18, v0.4s      \n"

            "SHA256SU0 v5.4s, v2.4s        \n"
            "ADD v1.4s, v1.4s, v23.4s      \n"
            "MOV v18.16b, v16.16b          \n"
            "MOV v7.16b, v3.16b            \n"
            "SHA256SU1 v5.4s, v3.4s, v4.4s \n"
            "SHA256H q16, q17, v1.4s       \n"
            "SHA256H2 q17, q18, v1.4s      \n"

            "SHA256SU0 v6.4s, v3.4s        \n"
            "ADD v2.4s, v2.4s, v24.4s      \n"
            "MOV v18.16b, v16.16b          \n"
            "MOV v8.16b, v4.16b            \n"
            "SHA256SU1 v6.4s, v4.4s, v5.4s \n"
            "SHA256H q16, q17, v2.4s       \n"
            "SHA256H2 q17, q18, v2.4s      \n"

            "SHA256SU0 v7.4s, v4.4s        \n"
            "ADD v3.4s, v3.4s, v25.4s      \n"
            "MOV v18.16b, v16.16b          \n"
            "MOV v9.16b, v5.16b            \n"
            "SHA256SU1 v7.4s, v5.4s, v6.4s \n"
            "SHA256H q16, q17, v3.4s       \n"
            "SHA256H2 q17, q18, v3.4s      \n"

            "LD1 {v22.16b-v25.16b}, [%[k]], #64 \n"
            "SHA256SU0 v8.4s, v5.4s        \n"
            "ADD v4.4s, v4.4s, v22.4s      \n"
            "MOV v18.16b, v16.16b          \n"
            "MOV v10.16b, v6.16b           \n"
            "SHA256SU1 v8.4s, v6.4s, v7.4s \n"
            "SHA256H q16, q17, v4.4s       \n"
            "SHA256H2 q17, q18, v4.4s      \n"

            "SHA256SU0 v9.4s, v6.4s        \n"
            "ADD v5.4s, v5.4s, v23.4s      \n"
            "MOV v18.16b, v16.16b          \n"
            "MOV v11.16b, v7.16b           \n"
            "SHA256SU1 v9.4s, v7.4s, v8.4s \n"
            "SHA256H q16, q17, v5.4s       \n"
            "SHA256H2 q17, q18, v5.4s      \n"

            "SHA256SU0 v10.4s, v7.4s        \n"
            "ADD v6.4s, v6.4s, v24.4s       \n"
            "MOV v18.16b, v16.16b           \n"
            "MOV v12.16b, v8.16b            \n"
            "SHA256SU1 v10.4s, v8.4s, v9.4s \n"
            "SHA256H q16, q17, v6.4s        \n"
            "SHA256H2 q17, q18, v6.4s       \n"

            "SHA256SU0 v11.4s, v8.4s         \n"
            "ADD v7.4s, v7.4s, v25.4s        \n"
            "MOV v18.16b, v16.16b            \n"
            "MOV v13.16b, v9.16b             \n"
            "SHA256SU1 v11.4s, v9.4s, v10.4s \n"
            "SHA256H q16, q17, v7.4s         \n"
            "SHA256H2 q17, q18, v7.4s        \n"

            "LD1 {v22.16b-v25.16b}, [%[k]], #64 \n"
            "SHA256SU0 v12.4s, v9.4s            \n"
            "ADD v8.4s, v8.4s, v22.4s           \n"
            "MOV v18.16b, v16.16b               \n"
            "MOV v14.16b, v10.16b               \n"
            "SHA256SU1 v12.4s, v10.4s, v11.4s   \n"
            "SHA256H q16, q17, v8.4s            \n"
            "SHA256H2 q17, q18, v8.4s           \n"

            "SHA256SU0 v13.4s, v10.4s           \n"
            "ADD v9.4s, v9.4s, v23.4s           \n"
            "MOV v18.16b, v16.16b               \n"
            "MOV v15.16b, v11.16b               \n"
            "SHA256SU1 v13.4s, v11.4s, v12.4s   \n"
            "SHA256H q16, q17, v9.4s            \n"
            "SHA256H2 q17, q18, v9.4s           \n"

            "SHA256SU0 v14.4s, v11.4s           \n"
            "ADD v10.4s, v10.4s, v24.4s         \n"
            "MOV v18.16b, v16.16b               \n"
            "SHA256SU1 v14.4s, v12.4s, v13.4s   \n"
            "SHA256H q16, q17, v10.4s           \n"
            "SHA256H2 q17, q18, v10.4s          \n"

            "SHA256SU0 v15.4s, v12.4s           \n"
            "ADD v11.4s, v11.4s, v25.4s         \n"
            "MOV v18.16b, v16.16b               \n"
            "SHA256SU1 v15.4s, v13.4s, v14.4s   \n"
            "SHA256H q16, q17, v11.4s           \n"
            "SHA256H2 q17, q18, v11.4s          \n"

            "LD1 {v22.16b-v25.16b}, [%[k]] \n"
            "ADD v12.4s, v12.4s, v22.4s    \n"
            "MOV v18.16b, v16.16b          \n"
            "SHA256H q16, q17, v12.4s      \n"
            "SHA256H2 q17, q18, v12.4s     \n"

            "ADD v13.4s, v13.4s, v23.4s    \n"
            "MOV v18.16b, v16.16b          \n"
            "SHA256H q16, q17, v13.4s      \n"
            "SHA256H2 q17, q18, v13.4s     \n"

            "ADD v14.4s, v14.4s, v24.4s  \n"
            "MOV v18.16b, v16.16b        \n"
            "SHA256H q16, q17, v14.4s    \n"
            "SHA256H2 q17, q18, v14.4s   \n"

            "ADD v15.4s, v15.4s, v25.4s  \n"
            "MOV v18.16b, v16.16b        \n"
            "SHA256H q16, q17, v15.4s    \n"
            "SHA256H2 q17, q18, v15.4s   \n"

            "#Add working vars back into digest state \n"
            "ADD v16.4s, v16.4s, v20.4s \n"
            "ADD v17.4s, v17.4s, v21.4s \n"
            "STP q16, q17, %[out] \n"

            : [out] "=m" (sha256->digest)
            : [k] "r" (K), [digest] "m" (sha256->digest),
              [buffer] "m" (sha256->buffer)
            : "cc", "memory", "v0", "v1", "v2", "v3", "v8",  "v9",  "v10", "v11"
                            , "v12", "v13", "v14", "v15", "v16", "v17", "v18"
                            , "v19", "v20", "v21", "v22", "v23", "v24", "v25"
        );

        sha256->buffLen = 0;
    }
    XMEMSET(&local[sha256->buffLen], 0, SHA256_PAD_SIZE - sha256->buffLen);

    /* put lengths in bits */
    sha256->hiLen = (sha256->loLen >> (8*sizeof(sha256->loLen) - 3)) +
                 (sha256->hiLen << 3);
    sha256->loLen = sha256->loLen << 3;

    /* store lengths */
    #if defined(LITTLE_ENDIAN_ORDER)
        __asm__ volatile (
            "LD1 {v0.2d-v3.2d}, %[in] \n"
            "REV32 v0.16b, v0.16b \n"
            "REV32 v1.16b, v1.16b \n"
            "REV32 v2.16b, v2.16b \n"
            "REV32 v3.16b, v3.16b \n"
            "ST1 {v0.2d-v3.2d}, %[out] \n"
            : [out] "=m" (sha256->buffer)
            : [in] "m" (sha256->buffer)
            : "cc", "memory", "v0", "v1", "v2", "v3"
        );
    #endif
    /* ! length ordering dependent on digest endian type ! */
    XMEMCPY(&local[SHA256_PAD_SIZE], &sha256->hiLen, sizeof(word32));
    XMEMCPY(&local[SHA256_PAD_SIZE + sizeof(word32)], &sha256->loLen,
            sizeof(word32));

    __asm__ volatile (
        "#load in message and schedual updates \n"
        "LD1 {v4.2d-v7.2d}, %[buffer]        \n"
        "MOV v0.16b, v4.16b \n"
        "MOV v1.16b, v5.16b \n"
        "MOV v2.16b, v6.16b \n"
        "MOV v3.16b, v7.16b \n"
        "LD1 {v20.2d-v21.2d}, %[digest] \n"

        "MOV v16.16b, v20.16b      \n"
        "MOV v17.16b, v21.16b      \n"
        "LD1 {v22.16b-v25.16b}, [%[k]], #64 \n"
        "SHA256SU0 v4.4s, v1.4s          \n"
        "ADD v0.4s, v0.4s, v22.4s        \n"
        "MOV v6.16b, v2.16b              \n"
        "MOV v18.16b, v16.16b            \n"
        "SHA256SU1 v4.4s, v2.4s, v3.4s   \n"
        "SHA256H q16, q17, v0.4s         \n"
        "SHA256H2 q17, q18, v0.4s        \n"

        "SHA256SU0 v5.4s, v2.4s          \n"
        "ADD v1.4s, v1.4s, v23.4s        \n"
        "MOV v7.16b, v3.16b              \n"
        "MOV v18.16b, v16.16b            \n"
        "SHA256SU1 v5.4s, v3.4s, v4.4s   \n"
        "SHA256H q16, q17, v1.4s         \n"
        "SHA256H2 q17, q18, v1.4s        \n"

        "SHA256SU0 v6.4s, v3.4s          \n"
        "ADD v2.4s, v2.4s, v24.4s        \n"
        "MOV v18.16b, v16.16b            \n"
        "MOV v8.16b, v4.16b              \n"
        "SHA256SU1 v6.4s, v4.4s, v5.4s   \n"
        "SHA256H q16, q17, v2.4s         \n"
        "SHA256H2 q17, q18, v2.4s        \n"

        "SHA256SU0 v7.4s, v4.4s          \n"
        "ADD v3.4s, v3.4s, v25.4s        \n"
        "MOV v18.16b, v16.16b            \n"
        "MOV v9.16b, v5.16b              \n"
        "SHA256SU1 v7.4s, v5.4s, v6.4s   \n"
        "SHA256H q16, q17, v3.4s         \n"
        "SHA256H2 q17, q18, v3.4s        \n"

        "LD1 {v22.16b-v25.16b}, [%[k]], #64 \n"
        "SHA256SU0 v8.4s, v5.4s          \n"
        "ADD v4.4s, v4.4s, v22.4s        \n"
        "MOV v18.16b, v16.16b            \n"
        "MOV v10.16b, v6.16b             \n"
        "SHA256SU1 v8.4s, v6.4s, v7.4s   \n"
        "SHA256H q16, q17, v4.4s         \n"
        "SHA256H2 q17, q18, v4.4s        \n"

        "SHA256SU0 v9.4s, v6.4s          \n"
        "ADD v5.4s, v5.4s, v23.4s        \n"
        "MOV v18.16b, v16.16b            \n"
        "MOV v11.16b, v7.16b             \n"
        "SHA256SU1 v9.4s, v7.4s, v8.4s   \n"
        "SHA256H q16, q17, v5.4s         \n"
        "SHA256H2 q17, q18, v5.4s        \n"

        "SHA256SU0 v10.4s, v7.4s         \n"
        "ADD v6.4s, v6.4s, v24.4s        \n"
        "MOV v18.16b, v16.16b            \n"
        "MOV v12.16b, v8.16b             \n"
        "SHA256SU1 v10.4s, v8.4s, v9.4s  \n"
        "SHA256H q16, q17, v6.4s         \n"
        "SHA256H2 q17, q18, v6.4s        \n"

        "SHA256SU0 v11.4s, v8.4s         \n"
        "ADD v7.4s, v7.4s, v25.4s        \n"
        "MOV v18.16b, v16.16b            \n"
        "MOV v13.16b, v9.16b             \n"
        "SHA256SU1 v11.4s, v9.4s, v10.4s \n"
        "SHA256H q16, q17, v7.4s         \n"
        "SHA256H2 q17, q18, v7.4s        \n"

        "LD1 {v22.16b-v25.16b}, [%[k]], #64 \n"
        "SHA256SU0 v12.4s, v9.4s          \n"
        "ADD v8.4s, v8.4s, v22.4s         \n"
        "MOV v18.16b, v16.16b             \n"
        "MOV v14.16b, v10.16b             \n"
        "SHA256SU1 v12.4s, v10.4s, v11.4s \n"
        "SHA256H q16, q17, v8.4s          \n"
        "SHA256H2 q17, q18, v8.4s         \n"

        "SHA256SU0 v13.4s, v10.4s         \n"
        "ADD v9.4s, v9.4s, v23.4s         \n"
        "MOV v18.16b, v16.16b             \n"
        "MOV v15.16b, v11.16b             \n"
        "SHA256SU1 v13.4s, v11.4s, v12.4s \n"
        "SHA256H q16, q17, v9.4s          \n"
        "SHA256H2 q17, q18, v9.4s         \n"

        "SHA256SU0 v14.4s, v11.4s         \n"
        "ADD v10.4s, v10.4s, v24.4s       \n"
        "MOV v18.16b, v16.16b             \n"
        "SHA256SU1 v14.4s, v12.4s, v13.4s \n"
        "SHA256H q16, q17, v10.4s         \n"
        "SHA256H2 q17, q18, v10.4s        \n"

        "SHA256SU0 v15.4s, v12.4s         \n"
        "ADD v11.4s, v11.4s, v25.4s       \n"
        "MOV v18.16b, v16.16b             \n"
        "SHA256SU1 v15.4s, v13.4s, v14.4s \n"
        "SHA256H q16, q17, v11.4s         \n"
        "SHA256H2 q17, q18, v11.4s        \n"

        "LD1 {v22.16b-v25.16b}, [%[k]] \n"
        "ADD v12.4s, v12.4s, v22.4s    \n"
        "MOV v18.16b, v16.16b          \n"
        "SHA256H q16, q17, v12.4s      \n"
        "SHA256H2 q17, q18, v12.4s     \n"

        "ADD v13.4s, v13.4s, v23.4s \n"
        "MOV v18.16b, v16.16b       \n"
        "SHA256H q16, q17, v13.4s   \n"
        "SHA256H2 q17, q18, v13.4s  \n"

        "ADD v14.4s, v14.4s, v24.4s \n"
        "MOV v18.16b, v16.16b       \n"
        "SHA256H q16, q17, v14.4s   \n"
        "SHA256H2 q17, q18, v14.4s  \n"

        "ADD v15.4s, v15.4s, v25.4s \n"
        "MOV v18.16b, v16.16b       \n"
        "SHA256H q16, q17, v15.4s   \n"
        "SHA256H2 q17, q18, v15.4s  \n"

        "#Add working vars back into digest state \n"
        "ADD v16.4s, v16.4s, v20.4s \n"
        "ADD v17.4s, v17.4s, v21.4s \n"

        "#Store value as hash output \n"
    #if defined(LITTLE_ENDIAN_ORDER)
        "REV32 v16.16b, v16.16b \n"
    #endif
        "ST1 {v16.16b}, [%[hashOut]], #16 \n"
    #if defined(LITTLE_ENDIAN_ORDER)
        "REV32 v17.16b, v17.16b \n"
    #endif
        "ST1 {v17.16b}, [%[hashOut]] \n"
        : [hashOut] "=r" (hash)
        : [k] "r" (K), [digest] "m" (sha256->digest),
          [buffer] "m" (sha256->buffer),
          "0" (hash)
            : "cc", "memory", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7",
                              "v8",  "v9",  "v10", "v11", "v12", "v13", "v14",
                              "v15", "v16", "v17", "v18", "v19", "v20", "v21",
                              "v22", "v23", "v24", "v25"
    );

    return wc_InitSha256(sha256);  /* reset state */
}

#else /* not using 64 bit */
/* ARMv8 hardware accleration Aarch32 */
int wc_Sha256Update(Sha256* sha256, const byte* data, word32 len)
{
    word32 add;
    word32 numBlocks;

    if (sha256 == NULL || (data == NULL && len != 0)) {
        return BAD_FUNC_ARG;
    }

    /* only perform actions if a buffer is passed in */
    if (len > 0) {
        /* fill leftover buffer with data */
        add = min(len, SHA256_BLOCK_SIZE - sha256->buffLen);
        XMEMCPY((byte*)(sha256->buffer) + sha256->buffLen, data, add);
        sha256->buffLen += add;
        data            += add;
        len             -= add;

        /* number of blocks in a row to complete */
        numBlocks = (len + sha256->buffLen)/SHA256_BLOCK_SIZE;

        if (numBlocks > 0) {
            word32* bufPt = sha256->buffer;
            word32* digPt = sha256->digest;
            /* get leftover amount after blocks */
            add = (len + sha256->buffLen) - numBlocks * SHA256_BLOCK_SIZE;
            __asm__ volatile (
            "#load leftover data\n"
            "VLDM %[buffer]!, {q0-q3} \n"

            "#load current digest\n"
            "VLDM %[digest], {q12-q13} \n"
            "MOV r8, %[blocks] \n"
            "VREV32.8 q0, q0 \n"
            "VREV32.8 q1, q1 \n"
            "VREV32.8 q2, q2 \n"
            "VREV32.8 q3, q3 \n"
            "VLDM %[k]! ,{q5-q8} \n"
            "VLDM %[k]! ,{q9}\n"

            "VMOV.32 q14, q12 \n" /* store digest for add at the end */
            "VMOV.32 q15, q13 \n"

            /* begining of SHA256 block operation */
            "1:\n"

            /* Round 1 */
            "VMOV.32 q4, q0           \n"
            "VADD.i32 q0, q0, q5      \n"
            "VMOV.32 q11, q12         \n"
            "SHA256H.32 q12, q13, q0  \n"
            "SHA256H2.32 q13, q11, q0 \n"

            /* Round 2 */
            "SHA256SU0.32 q4, q1      \n"
            "VADD.i32 q0, q1, q6      \n"
            "VMOV.32 q11, q12         \n"
            "SHA256SU1.32 q4, q2, q3  \n"
            "SHA256H.32 q12, q13, q0  \n"
            "SHA256H2.32 q13, q11, q0 \n"

            /* Round 3 */
            "SHA256SU0.32 q1, q2      \n"
            "VADD.i32 q0, q2, q7      \n"
            "VMOV.32 q11, q12         \n"
            "SHA256SU1.32 q1, q3, q4  \n"
            "SHA256H.32 q12, q13, q0  \n"
            "SHA256H2.32 q13, q11, q0 \n"

            /* Round 4 */
            "SHA256SU0.32 q2, q3      \n"
            "VADD.i32 q0, q3, q8      \n"
            "VMOV.32 q11, q12         \n"
            "SHA256SU1.32 q2, q4, q1  \n"
            "SHA256H.32 q12, q13, q0  \n"
            "SHA256H2.32 q13, q11, q0 \n"

            /* Round 5 */
            "SHA256SU0.32 q3, q4      \n"
            "VADD.i32 q0, q4, q9      \n"
            "VMOV.32 q11, q12         \n"
            "SHA256SU1.32 q3, q1, q2  \n"
            "SHA256H.32 q12, q13, q0  \n"
            "SHA256H2.32 q13, q11, q0 \n"

            /* Round 6 */
            "VLD1.32 {q10}, [%[k]]!   \n"
            "SHA256SU0.32 q4, q1      \n"
            "VADD.i32 q0, q1, q10     \n"
            "VMOV.32 q11, q12         \n"
            "SHA256SU1.32 q4, q2, q3  \n"
            "SHA256H.32 q12, q13, q0  \n"
            "SHA256H2.32 q13, q11, q0 \n"

            /* Round 7 */
            "VLD1.32 {q10}, [%[k]]!   \n"
            "SHA256SU0.32 q1, q2      \n"
            "VADD.i32 q0, q2, q10     \n"
            "VMOV.32 q11, q12         \n"
            "SHA256SU1.32 q1, q3, q4  \n"
            "SHA256H.32 q12, q13, q0  \n"
            "SHA256H2.32 q13, q11, q0 \n"

            /* Round 8 */
            "VLD1.32 {q10}, [%[k]]!   \n"
            "SHA256SU0.32 q2, q3      \n"
            "VADD.i32 q0, q3, q10     \n"
            "VMOV.32 q11, q12         \n"
            "SHA256SU1.32 q2, q4, q1  \n"
            "SHA256H.32 q12, q13, q0  \n"
            "SHA256H2.32 q13, q11, q0 \n"

            /* Round 9 */
            "VLD1.32 {q10}, [%[k]]!   \n"
            "SHA256SU0.32 q3, q4      \n"
            "VADD.i32 q0, q4, q10     \n"
            "VMOV.32 q11, q12         \n"
            "SHA256SU1.32 q3, q1, q2  \n"
            "SHA256H.32 q12, q13, q0  \n"
            "SHA256H2.32 q13, q11, q0 \n"

            /* Round 10 */
            "VLD1.32 {q10}, [%[k]]!   \n"
            "SHA256SU0.32 q4, q1      \n"
            "VADD.i32 q0, q1, q10     \n"
            "VMOV.32 q11, q12         \n"
            "SHA256SU1.32 q4, q2, q3  \n"
            "SHA256H.32 q12, q13, q0  \n"
            "SHA256H2.32 q13, q11, q0 \n"

            /* Round 11 */
            "VLD1.32 {q10}, [%[k]]!   \n"
            "SHA256SU0.32 q1, q2      \n"
            "VADD.i32 q0, q2, q10     \n"
            "VMOV.32 q11, q12         \n"
            "SHA256SU1.32 q1, q3, q4  \n"
            "SHA256H.32 q12, q13, q0  \n"
            "SHA256H2.32 q13, q11, q0 \n"

            /* Round 12 */
            "VLD1.32 {q10}, [%[k]]!   \n"
            "SHA256SU0.32 q2, q3      \n"
            "VADD.i32 q0, q3, q10     \n"
            "VMOV.32 q11, q12         \n"
            "SHA256SU1.32 q2, q4, q1  \n"
            "SHA256H.32 q12, q13, q0  \n"
            "SHA256H2.32 q13, q11, q0 \n"

            /* Round 13 */
            "VLD1.32 {q10}, [%[k]]!   \n"
            "SHA256SU0.32 q3, q4      \n"
            "VADD.i32 q0, q4, q10     \n"
            "VMOV.32 q11, q12         \n"
            "SHA256SU1.32 q3, q1, q2  \n"
            "SHA256H.32 q12, q13, q0  \n"
            "SHA256H2.32 q13, q11, q0 \n"

            /* Round 14 */
            "VLD1.32 {q10}, [%[k]]!   \n"
            "VADD.i32 q0, q1, q10     \n"
            "VMOV.32 q11, q12         \n"
            "SHA256H.32 q12, q13, q0  \n"
            "SHA256H2.32 q13, q11, q0 \n"

            /* Round 15 */
            "VLD1.32 {q10}, [%[k]]!   \n"
            "VADD.i32 q0, q2, q10     \n"
            "VMOV.32 q11, q12         \n"
            "SHA256H.32 q12, q13, q0  \n"
            "SHA256H2.32 q13, q11, q0 \n"

            /* Round 16 */
            "VLD1.32 {q10}, [%[k]]    \n"
            "SUB r8, r8, #1           \n"
            "VADD.i32 q0, q3, q10     \n"
            "VMOV.32 q11, q12         \n"
            "SHA256H.32 q12, q13, q0  \n"
            "SHA256H2.32 q13, q11, q0 \n"

            "#Add working vars back into digest state \n"
            "VADD.i32 q12, q12, q14 \n"
            "VADD.i32 q13, q13, q15 \n"

            "#check if more blocks should be done\n"
            "CMP r8, #0 \n"
            "BEQ 2f \n"

            "#load in message and schedual updates \n"
            "VLD1.32 {q0}, [%[dataIn]]!   \n"
            "VLD1.32 {q1}, [%[dataIn]]!   \n"
            "VLD1.32 {q2}, [%[dataIn]]!   \n"
            "VLD1.32 {q3}, [%[dataIn]]!   \n"

            /* reset K pointer */
            "SUB %[k], %[k], #160 \n"
            "VREV32.8 q0, q0 \n"
            "VREV32.8 q1, q1 \n"
            "VREV32.8 q2, q2 \n"
            "VREV32.8 q3, q3 \n"
            "VMOV.32 q14, q12 \n"
            "VMOV.32 q15, q13 \n"
            "B 1b \n" /* do another block */

            "2:\n"
            "VST1.32 {q12, q13}, [%[out]] \n"

            : [out] "=r" (digPt), "=r" (bufPt), "=r" (numBlocks),
              "=r" (data)
            : [k] "r" (K), [digest] "0" (digPt), [buffer] "1" (bufPt),
              [blocks] "2" (numBlocks), [dataIn] "3" (data)
            : "cc", "memory", "q0", "q1", "q2", "q3", "q4", "q5", "q6", "q7",
                              "q8",  "q9",  "q10", "q11", "q12", "q13", "q14",
                              "q15", "r8"
            );

            AddLength(sha256, SHA256_BLOCK_SIZE * numBlocks);

            /* copy over any remaining data leftover */
            XMEMCPY(sha256->buffer, data, add);
            sha256->buffLen = add;
        }
    }

    /* account for possiblity of not used if len = 0 */
    (void)add;
    (void)numBlocks;

    return 0;
}


int wc_Sha256Final(Sha256* sha256, byte* hash)
{
    byte* local;

    if (sha256 == NULL || hash == NULL) {
        return BAD_FUNC_ARG;
    }

    local = (byte*)sha256->buffer;
    AddLength(sha256, sha256->buffLen);  /* before adding pads */

    local[sha256->buffLen++] = 0x80;     /* add 1 */

    /* pad with zeros */
    if (sha256->buffLen > SHA256_PAD_SIZE) {
        word32* bufPt = sha256->buffer;
        word32* digPt = sha256->digest;
        XMEMSET(&local[sha256->buffLen], 0, SHA256_BLOCK_SIZE - sha256->buffLen);
        sha256->buffLen += SHA256_BLOCK_SIZE - sha256->buffLen;
        __asm__ volatile (
        "#load leftover data\n"
        "VLDM %[buffer]!, {q0-q3} \n"

        "#load current digest\n"
        "VLDM %[digest], {q12-q13} \n"
        "VREV32.8 q0, q0 \n"
        "VREV32.8 q1, q1 \n"
        "VREV32.8 q2, q2 \n"
        "VREV32.8 q3, q3 \n"

        "#load K values in \n"
        "VMOV.32 q14, q12 \n" /* store digest for add at the end */
        "VMOV.32 q15, q13 \n"

        /* begining of SHA256 block operation */
        /* Round 1 */
        "VLD1.32 {q5}, [%[k]]!    \n"
        "VMOV.32 q4, q0           \n"
        "VADD.i32 q0, q0, q5      \n"
        "VMOV.32 q11, q12         \n"
        "SHA256H.32 q12, q13, q0  \n"
        "SHA256H2.32 q13, q11, q0 \n"

        /* Round 2 */
        "VLD1.32 {q5}, [%[k]]!    \n"
        "SHA256SU0.32 q4, q1      \n"
        "VADD.i32 q0, q1, q5      \n"
        "VMOV.32 q11, q12         \n"
        "SHA256SU1.32 q4, q2, q3  \n"
        "SHA256H.32 q12, q13, q0  \n"
        "SHA256H2.32 q13, q11, q0 \n"

        /* Round 3 */
        "VLD1.32 {q5}, [%[k]]!    \n"
        "SHA256SU0.32 q1, q2      \n"
        "VADD.i32 q0, q2, q5      \n"
        "VMOV.32 q11, q12         \n"
        "SHA256SU1.32 q1, q3, q4  \n"
        "SHA256H.32 q12, q13, q0  \n"
        "SHA256H2.32 q13, q11, q0 \n"

        /* Round 4 */
        "VLD1.32 {q5}, [%[k]]!    \n"
        "SHA256SU0.32 q2, q3      \n"
        "VADD.i32 q0, q3, q5      \n"
        "VMOV.32 q11, q12         \n"
        "SHA256SU1.32 q2, q4, q1  \n"
        "SHA256H.32 q12, q13, q0  \n"
        "SHA256H2.32 q13, q11, q0 \n"

        /* Round 5 */
        "VLD1.32 {q5}, [%[k]]!    \n"
        "SHA256SU0.32 q3, q4      \n"
        "VADD.i32 q0, q4, q5      \n"
        "VMOV.32 q11, q12         \n"
        "SHA256SU1.32 q3, q1, q2  \n"
        "SHA256H.32 q12, q13, q0  \n"
        "SHA256H2.32 q13, q11, q0 \n"

        /* Round 6 */
        "VLD1.32 {q5}, [%[k]]!    \n"
        "SHA256SU0.32 q4, q1      \n"
        "VADD.i32 q0, q1, q5     \n"
        "VMOV.32 q11, q12         \n"
        "SHA256SU1.32 q4, q2, q3  \n"
        "SHA256H.32 q12, q13, q0  \n"
        "SHA256H2.32 q13, q11, q0 \n"

        /* Round 7 */
        "VLD1.32 {q5}, [%[k]]!    \n"
        "SHA256SU0.32 q1, q2      \n"
        "VADD.i32 q0, q2, q5      \n"
        "VMOV.32 q11, q12         \n"
        "SHA256SU1.32 q1, q3, q4  \n"
        "SHA256H.32 q12, q13, q0  \n"
        "SHA256H2.32 q13, q11, q0 \n"

        /* Round 8 */
        "VLD1.32 {q5}, [%[k]]!    \n"
        "SHA256SU0.32 q2, q3      \n"
        "VADD.i32 q0, q3, q5      \n"
        "VMOV.32 q11, q12         \n"
        "SHA256SU1.32 q2, q4, q1  \n"
        "SHA256H.32 q12, q13, q0  \n"
        "SHA256H2.32 q13, q11, q0 \n"

        /* Round 9 */
        "VLD1.32 {q5}, [%[k]]!    \n"
        "SHA256SU0.32 q3, q4      \n"
        "VADD.i32 q0, q4, q5      \n"
        "VMOV.32 q11, q12         \n"
        "SHA256SU1.32 q3, q1, q2  \n"
        "SHA256H.32 q12, q13, q0  \n"
        "SHA256H2.32 q13, q11, q0 \n"

        /* Round 10 */
        "VLD1.32 {q5}, [%[k]]!    \n"
        "SHA256SU0.32 q4, q1      \n"
        "VADD.i32 q0, q1, q5      \n"
        "VMOV.32 q11, q12         \n"
        "SHA256SU1.32 q4, q2, q3  \n"
        "SHA256H.32 q12, q13, q0  \n"
        "SHA256H2.32 q13, q11, q0 \n"

        /* Round 11 */
        "VLD1.32 {q5}, [%[k]]!    \n"
        "SHA256SU0.32 q1, q2      \n"
        "VADD.i32 q0, q2, q5      \n"
        "VMOV.32 q11, q12         \n"
        "SHA256SU1.32 q1, q3, q4  \n"
        "SHA256H.32 q12, q13, q0  \n"
        "SHA256H2.32 q13, q11, q0 \n"

        /* Round 12 */
        "VLD1.32 {q5}, [%[k]]!    \n"
        "SHA256SU0.32 q2, q3      \n"
        "VADD.i32 q0, q3, q5      \n"
        "VMOV.32 q11, q12         \n"
        "SHA256SU1.32 q2, q4, q1  \n"
        "SHA256H.32 q12, q13, q0  \n"
        "SHA256H2.32 q13, q11, q0 \n"

        /* Round 13 */
        "VLD1.32 {q5}, [%[k]]!    \n"
        "SHA256SU0.32 q3, q4      \n"
        "VADD.i32 q0, q4, q5      \n"
        "VMOV.32 q11, q12         \n"
        "SHA256SU1.32 q3, q1, q2  \n"
        "SHA256H.32 q12, q13, q0  \n"
        "SHA256H2.32 q13, q11, q0 \n"

        /* Round 14 */
        "VLD1.32 {q5}, [%[k]]!    \n"
        "VADD.i32 q0, q1, q5      \n"
        "VMOV.32 q11, q12         \n"
        "SHA256H.32 q12, q13, q0  \n"
        "SHA256H2.32 q13, q11, q0 \n"

        /* Round 15 */
        "VLD1.32 {q5}, [%[k]]!    \n"
        "VADD.i32 q0, q2, q5      \n"
        "VMOV.32 q11, q12         \n"
        "SHA256H.32 q12, q13, q0  \n"
        "SHA256H2.32 q13, q11, q0 \n"

        /* Round 16 */
        "VLD1.32 {q5}, [%[k]]!     \n"
        "VADD.i32 q0, q3, q5      \n"
        "VMOV.32 q11, q12         \n"
        "SHA256H.32 q12, q13, q0  \n"
        "SHA256H2.32 q13, q11, q0 \n"

        "#Add working vars back into digest state \n"
        "VADD.i32 q12, q12, q14 \n"
        "VADD.i32 q13, q13, q15 \n"

        /* reset K pointer */
        "SUB %[k], %[k], #256 \n"
        "VST1.32 {q12, q13}, [%[out]] \n"

        : [out] "=r" (digPt), "=r" (bufPt)
        : [k] "r" (K), [digest] "0" (digPt), [buffer] "1" (bufPt)
        : "cc", "memory", "q0", "q1", "q2", "q3", "q4", "q5", "q6", "q7",
                          "q8",  "q9",  "q10", "q11", "q12", "q13", "q14",
                          "q15"
        );

        sha256->buffLen = 0;
    }
    XMEMSET(&local[sha256->buffLen], 0, SHA256_PAD_SIZE - sha256->buffLen);

    /* put lengths in bits */
    sha256->hiLen = (sha256->loLen >> (8*sizeof(sha256->loLen) - 3)) +
                 (sha256->hiLen << 3);
    sha256->loLen = sha256->loLen << 3;

    /* store lengths */
	word32* bufPt = sha256->buffer;
    #if defined(LITTLE_ENDIAN_ORDER)
        __asm__ volatile (
            "VLD1.32 {q0}, [%[in]] \n"
            "VREV32.8 q0, q0 \n"
            "VST1.32 {q0}, [%[out]]!\n"
            "VLD1.32 {q1}, [%[in]] \n"
            "VREV32.8 q1, q1 \n"
            "VST1.32 {q1}, [%[out]]!\n"
            "VLD1.32 {q2}, [%[in]] \n"
            "VREV32.8 q2, q2 \n"
            "VST1.32 {q2}, [%[out]]!\n"
            "VLD1.32 {q3}, [%[in]] \n"
            "VREV32.8 q3, q3 \n"
            "VST1.32 {q3}, [%[out]] \n"
            : [out] "=r" (bufPt)
            : [in] "0" (bufPt)
            : "cc", "memory", "q0", "q1", "q2", "q3"
        );
    #endif
    /* ! length ordering dependent on digest endian type ! */
    XMEMCPY(&local[SHA256_PAD_SIZE], &sha256->hiLen, sizeof(word32));
    XMEMCPY(&local[SHA256_PAD_SIZE + sizeof(word32)], &sha256->loLen,
            sizeof(word32));

    bufPt = sha256->buffer;
    word32* digPt = sha256->digest;
    __asm__ volatile (
        "#load leftover data\n"
        "VLDM %[buffer]!, {q0-q3} \n"

        "#load current digest\n"
        "VLDM %[digest], {q12-q13} \n"

        "VMOV.32 q14, q12 \n" /* store digest for add at the end */
        "VMOV.32 q15, q13 \n"

        /* begining of SHA256 block operation */
        /* Round 1 */
        "VLD1.32 {q5}, [%[k]]!    \n"
        "VMOV.32 q4, q0           \n"
        "VADD.i32 q0, q0, q5      \n"
        "VMOV.32 q11, q12         \n"
        "SHA256H.32 q12, q13, q0  \n"
        "SHA256H2.32 q13, q11, q0 \n"

        /* Round 2 */
        "VLD1.32 {q5}, [%[k]]!    \n"
        "SHA256SU0.32 q4, q1      \n"
        "VADD.i32 q0, q1, q5      \n"
        "VMOV.32 q11, q12         \n"
        "SHA256SU1.32 q4, q2, q3  \n"
        "SHA256H.32 q12, q13, q0  \n"
        "SHA256H2.32 q13, q11, q0 \n"

        /* Round 3 */
        "VLD1.32 {q5}, [%[k]]!    \n"
        "SHA256SU0.32 q1, q2      \n"
        "VADD.i32 q0, q2, q5      \n"
        "VMOV.32 q11, q12         \n"
        "SHA256SU1.32 q1, q3, q4  \n"
        "SHA256H.32 q12, q13, q0  \n"
        "SHA256H2.32 q13, q11, q0 \n"

        /* Round 4 */
        "VLD1.32 {q5}, [%[k]]!    \n"
        "SHA256SU0.32 q2, q3      \n"
        "VADD.i32 q0, q3, q5      \n"
        "VMOV.32 q11, q12         \n"
        "SHA256SU1.32 q2, q4, q1  \n"
        "SHA256H.32 q12, q13, q0  \n"
        "SHA256H2.32 q13, q11, q0 \n"

        /* Round 5 */
        "VLD1.32 {q5}, [%[k]]!    \n"
        "SHA256SU0.32 q3, q4      \n"
        "VADD.i32 q0, q4, q5      \n"
        "VMOV.32 q11, q12         \n"
        "SHA256SU1.32 q3, q1, q2  \n"
        "SHA256H.32 q12, q13, q0  \n"
        "SHA256H2.32 q13, q11, q0 \n"

        /* Round 6 */
        "VLD1.32 {q5}, [%[k]]!    \n"
        "SHA256SU0.32 q4, q1      \n"
        "VADD.i32 q0, q1, q5     \n"
        "VMOV.32 q11, q12         \n"
        "SHA256SU1.32 q4, q2, q3  \n"
        "SHA256H.32 q12, q13, q0  \n"
        "SHA256H2.32 q13, q11, q0 \n"

        /* Round 7 */
        "VLD1.32 {q5}, [%[k]]!    \n"
        "SHA256SU0.32 q1, q2      \n"
        "VADD.i32 q0, q2, q5      \n"
        "VMOV.32 q11, q12         \n"
        "SHA256SU1.32 q1, q3, q4  \n"
        "SHA256H.32 q12, q13, q0  \n"
        "SHA256H2.32 q13, q11, q0 \n"

        /* Round 8 */
        "VLD1.32 {q5}, [%[k]]!    \n"
        "SHA256SU0.32 q2, q3      \n"
        "VADD.i32 q0, q3, q5      \n"
        "VMOV.32 q11, q12         \n"
        "SHA256SU1.32 q2, q4, q1  \n"
        "SHA256H.32 q12, q13, q0  \n"
        "SHA256H2.32 q13, q11, q0 \n"

        /* Round 9 */
        "VLD1.32 {q5}, [%[k]]!    \n"
        "SHA256SU0.32 q3, q4      \n"
        "VADD.i32 q0, q4, q5      \n"
        "VMOV.32 q11, q12         \n"
        "SHA256SU1.32 q3, q1, q2  \n"
        "SHA256H.32 q12, q13, q0  \n"
        "SHA256H2.32 q13, q11, q0 \n"

        /* Round 10 */
        "VLD1.32 {q5}, [%[k]]!    \n"
        "SHA256SU0.32 q4, q1      \n"
        "VADD.i32 q0, q1, q5      \n"
        "VMOV.32 q11, q12         \n"
        "SHA256SU1.32 q4, q2, q3  \n"
        "SHA256H.32 q12, q13, q0  \n"
        "SHA256H2.32 q13, q11, q0 \n"

        /* Round 11 */
        "VLD1.32 {q5}, [%[k]]!    \n"
        "SHA256SU0.32 q1, q2      \n"
        "VADD.i32 q0, q2, q5      \n"
        "VMOV.32 q11, q12         \n"
        "SHA256SU1.32 q1, q3, q4  \n"
        "SHA256H.32 q12, q13, q0  \n"
        "SHA256H2.32 q13, q11, q0 \n"

        /* Round 12 */
        "VLD1.32 {q5}, [%[k]]!    \n"
        "SHA256SU0.32 q2, q3      \n"
        "VADD.i32 q0, q3, q5      \n"
        "VMOV.32 q11, q12         \n"
        "SHA256SU1.32 q2, q4, q1  \n"
        "SHA256H.32 q12, q13, q0  \n"
        "SHA256H2.32 q13, q11, q0 \n"

        /* Round 13 */
        "VLD1.32 {q5}, [%[k]]!    \n"
        "SHA256SU0.32 q3, q4      \n"
        "VADD.i32 q0, q4, q5      \n"
        "VMOV.32 q11, q12         \n"
        "SHA256SU1.32 q3, q1, q2  \n"
        "SHA256H.32 q12, q13, q0  \n"
        "SHA256H2.32 q13, q11, q0 \n"

        /* Round 14 */
        "VLD1.32 {q5}, [%[k]]!    \n"
        "VADD.i32 q0, q1, q5      \n"
        "VMOV.32 q11, q12         \n"
        "SHA256H.32 q12, q13, q0  \n"
        "SHA256H2.32 q13, q11, q0 \n"

        /* Round 15 */
        "VLD1.32 {q5}, [%[k]]!    \n"
        "VADD.i32 q0, q2, q5      \n"
        "VMOV.32 q11, q12         \n"
        "SHA256H.32 q12, q13, q0  \n"
        "SHA256H2.32 q13, q11, q0 \n"

        /* Round 16 */
        "VLD1.32 {q5}, [%[k]]!     \n"
        "VADD.i32 q0, q3, q5      \n"
        "VMOV.32 q11, q12         \n"
        "SHA256H.32 q12, q13, q0  \n"
        "SHA256H2.32 q13, q11, q0 \n"

        "#Add working vars back into digest state \n"
        "VADD.i32 q12, q12, q14 \n"
        "VADD.i32 q13, q13, q15 \n"

        "#Store value as hash output \n"
    #if defined(LITTLE_ENDIAN_ORDER)
        "VREV32.8 q12, q12 \n"
    #endif
        "VST1.32 {q12}, [%[hashOut]]! \n"
    #if defined(LITTLE_ENDIAN_ORDER)
        "VREV32.8 q13, q13 \n"
    #endif
        "VST1.32 {q13}, [%[hashOut]] \n"

        : [out] "=r" (digPt), "=r" (bufPt),
          [hashOut] "=r" (hash)
        : [k] "r" (K), [digest] "0" (digPt), [buffer] "1" (bufPt),
          "2" (hash)
        : "cc", "memory", "q0", "q1", "q2", "q3", "q4", "q5", "q6", "q7",
                          "q8",  "q9",  "q10", "q11", "q12", "q13", "q14",
                          "q15"
    );

    return wc_InitSha256(sha256);  /* reset state */
}
#endif /* __aarch64__ */

#endif /* NO_SHA256 and WOLFSSL_ARMASM */

