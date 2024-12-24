/* armv8-sha256.c
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
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_ARMASM
#if !defined(NO_SHA256) || defined(WOLFSSL_SHA224)

#if FIPS_VERSION3_LT(6,0,0) && defined(HAVE_FIPS)
    #undef HAVE_FIPS
#else
    #if defined(HAVE_FIPS) && FIPS_VERSION3_GE(6,0,0)
    /* set NO_WRAPPERS before headers, use direct internal f()s not wrappers */
        #define FIPS_NO_WRAPPERS
    #endif
#endif

#include <wolfssl/wolfcrypt/sha256.h>
#if FIPS_VERSION3_GE(6,0,0)
    const unsigned int wolfCrypt_FIPS_sha256_ro_sanity[2] =
                                                     { 0x1a2b3c4d, 0x00000014 };
    int wolfCrypt_FIPS_SHA256_sanity(void)
    {
        return 0;
    }
#endif
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/cpuid.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#ifdef WOLF_CRYPTO_CB
    #include <wolfssl/wolfcrypt/cryptocb.h>
#endif

#if defined(FREESCALE_MMCAU_SHA)
    #ifdef FREESCALE_MMCAU_CLASSIC_SHA
        #include "cau_api.h"
    #else
        #include "fsl_mmcau.h"
    #endif
#endif

#if defined(__aarch64__) || !defined(WOLFSSL_ARMASM_NO_HW_CRYPTO)
static const FLASH_QUALIFIER ALIGN32 word32 K[64] = {
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
#endif


#if defined(__aarch64__)
/* Both versions of Ch and Maj are logically the same, but with the second set
    the compilers can recognize them better for optimization */
#ifdef WOLFSSL_SHA256_BY_SPEC
    /* SHA256 math based on specification */
    #define Ch(x,y,z)       ((z) ^ ((x) & ((y) ^ (z))))
    #define Maj(x,y,z)      ((((x) | (y)) & (z)) | ((x) & (y)))
#else
    /* SHA256 math reworked for easier compiler optimization */
    #define Ch(x,y,z)       ((((y) ^ (z)) & (x)) ^ (z))
    #define Maj(x,y,z)      ((((x) ^ (y)) & ((y) ^ (z))) ^ (y))
#endif
    #define R(x, n)         (((x) & 0xFFFFFFFFU) >> (n))

    #define S(x, n)         rotrFixed(x, n)
    #define Sigma0(x)       (S(x, 2)  ^ S(x, 13) ^ S(x, 22))
    #define Sigma1(x)       (S(x, 6)  ^ S(x, 11) ^ S(x, 25))
    #define Gamma0(x)       (S(x, 7)  ^ S(x, 18) ^ R(x, 3))
    #define Gamma1(x)       (S(x, 17) ^ S(x, 19) ^ R(x, 10))

    #define a(i) S[(0-(i)) & 7]
    #define b(i) S[(1-(i)) & 7]
    #define c(i) S[(2-(i)) & 7]
    #define d(i) S[(3-(i)) & 7]
    #define e(i) S[(4-(i)) & 7]
    #define f(i) S[(5-(i)) & 7]
    #define g(i) S[(6-(i)) & 7]
    #define h(i) S[(7-(i)) & 7]

    #ifndef XTRANSFORM
         #define XTRANSFORM(S, D)         Transform_Sha256((S),(D))
    #endif

#ifndef SHA256_MANY_REGISTERS
    #define RND(j) \
         t0 = h(j) + Sigma1(e(j)) + Ch(e(j), f(j), g(j)) + K[i+(j)] + \
              W[i+(j)]; \
         t1 = Sigma0(a(j)) + Maj(a(j), b(j), c(j)); \
         d(j) += t0; \
         h(j)  = t0 + t1

    static void Transform_Sha256(wc_Sha256* sha256, const byte* data)
    {
        word32 S[8], t0, t1;
        int i;

    #ifdef WOLFSSL_SMALL_STACK_CACHE
        word32* W = sha256->W;
        if (W == NULL) {
            W = (word32*)XMALLOC(sizeof(word32) * WC_SHA256_BLOCK_SIZE, NULL,
                                                           DYNAMIC_TYPE_DIGEST);
            if (W == NULL)
                return MEMORY_E;
            sha256->W = W;
        }
    #elif defined(WOLFSSL_SMALL_STACK)
        word32* W;
        W = (word32*)XMALLOC(sizeof(word32) * WC_SHA256_BLOCK_SIZE, NULL,
                                                       DYNAMIC_TYPE_TMP_BUFFER);
        if (W == NULL)
            return MEMORY_E;
    #else
        word32 W[WC_SHA256_BLOCK_SIZE];
    #endif

        /* Copy context->state[] to working vars */
        for (i = 0; i < 8; i++)
            S[i] = sha256->digest[i];

        for (i = 0; i < 16; i++)
            W[i] = *((const word32*)&data[i*(int)sizeof(word32)]);

        for (i = 16; i < WC_SHA256_BLOCK_SIZE; i++)
           W[i] = Gamma1(W[i-2]) + W[i-7] + Gamma0(W[i-15]) + W[i-16];

    #ifdef USE_SLOW_SHA256
        /* not unrolled - ~2k smaller and ~25% slower */
        for (i = 0; i < WC_SHA256_BLOCK_SIZE; i += 8) {
            int j;
            for (j = 0; j < 8; j++) { /* braces needed here for macros {} */
                RND(j);
            }
        }
    #else
        /* partially loop unrolled */
        for (i = 0; i < WC_SHA256_BLOCK_SIZE; i += 8) {
            RND(0); RND(1); RND(2); RND(3);
            RND(4); RND(5); RND(6); RND(7);
        }
    #endif /* USE_SLOW_SHA256 */

        /* Add the working vars back into digest state[] */
        for (i = 0; i < 8; i++) {
            sha256->digest[i] += S[i];
        }

    #if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_SMALL_STACK_CACHE)
        ForceZero(W, sizeof(word32) * WC_SHA256_BLOCK_SIZE);
        XFREE(W, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    #endif
    }
#else
    /* SHA256 version that keeps all data in registers */
    #define SCHED1(j) (W[j] = *((word32*)&data[j*sizeof(word32)]))
    #define SCHED(j) (               \
                   W[ j     & 15] += \
            Gamma1(W[(j-2)  & 15])+  \
                   W[(j-7)  & 15] +  \
            Gamma0(W[(j-15) & 15])   \
        )

    #define RND1(j) \
         t0 = h(j) + Sigma1(e(j)) + Ch(e(j), f(j), g(j)) + K[i+j] + SCHED1(j); \
         t1 = Sigma0(a(j)) + Maj(a(j), b(j), c(j)); \
         d(j) += t0; \
         h(j)  = t0 + t1
    #define RNDN(j) \
         t0 = h(j) + Sigma1(e(j)) + Ch(e(j), f(j), g(j)) + K[i+j] + SCHED(j); \
         t1 = Sigma0(a(j)) + Maj(a(j), b(j), c(j)); \
         d(j) += t0; \
         h(j)  = t0 + t1

    static void Transform_Sha256(wc_Sha256* sha256, const byte* data)
    {
        word32 S[8], t0, t1;
        int i;
    #ifdef USE_SLOW_SHA256
        int j;
    #endif
        word32 W[WC_SHA256_BLOCK_SIZE/sizeof(word32)];

        /* Copy digest to working vars */
        S[0] = sha256->digest[0];
        S[1] = sha256->digest[1];
        S[2] = sha256->digest[2];
        S[3] = sha256->digest[3];
        S[4] = sha256->digest[4];
        S[5] = sha256->digest[5];
        S[6] = sha256->digest[6];
        S[7] = sha256->digest[7];

        i = 0;
    #ifdef USE_SLOW_SHA256
        for (j = 0; j < 16; j++) {
            RND1(j);
        }
        for (i = 16; i < 64; i += 16) {
            for (j = 0; j < 16; j++) {
                RNDN(j);
            }
        }
    #else
        RND1( 0); RND1( 1); RND1( 2); RND1( 3);
        RND1( 4); RND1( 5); RND1( 6); RND1( 7);
        RND1( 8); RND1( 9); RND1(10); RND1(11);
        RND1(12); RND1(13); RND1(14); RND1(15);
        /* 64 operations, partially loop unrolled */
        for (i = 16; i < 64; i += 16) {
            RNDN( 0); RNDN( 1); RNDN( 2); RNDN( 3);
            RNDN( 4); RNDN( 5); RNDN( 6); RNDN( 7);
            RNDN( 8); RNDN( 9); RNDN(10); RNDN(11);
            RNDN(12); RNDN(13); RNDN(14); RNDN(15);
        }
    #endif

        /* Add the working vars back into digest */
        sha256->digest[0] += S[0];
        sha256->digest[1] += S[1];
        sha256->digest[2] += S[2];
        sha256->digest[3] += S[3];
        sha256->digest[4] += S[4];
        sha256->digest[5] += S[5];
        sha256->digest[6] += S[6];
        sha256->digest[7] += S[7];
    }
#endif /* SHA256_MANY_REGISTERS */

static void Transform_Sha256_Len(wc_Sha256* sha256, const byte* data,
    word32 len)
{
    while (len > 0) {
        byte tmp[WC_SHA256_BLOCK_SIZE];
        ByteReverseWords((word32*)tmp, (const word32*)data,
            WC_SHA256_BLOCK_SIZE);
        Transform_Sha256(sha256, tmp);
        data += WC_SHA256_BLOCK_SIZE;
        len  -= WC_SHA256_BLOCK_SIZE;
    }
}
#endif

#if defined(__aarch64__) && !defined(WOLFSSL_ARMASM_NO_HW_CRYPTO)
static word32 cpuid_flags = 0;
static int cpuid_flags_set = 0;
#endif

static int InitSha256(wc_Sha256* sha256)
{
    int ret = 0;

    if (sha256 == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef FREESCALE_MMCAU_SHA
    ret = wolfSSL_CryptHwMutexLock();
    if (ret == 0) {
    #ifdef FREESCALE_MMCAU_CLASSIC_SHA
        cau_sha256_initialize_output(sha256->digest);
    #else
        MMCAU_SHA256_InitializeOutput((uint32_t*)sha256->digest);
    #endif
        wolfSSL_CryptHwMutexUnLock();
    }
#else
    sha256->digest[0] = 0x6A09E667L;
    sha256->digest[1] = 0xBB67AE85L;
    sha256->digest[2] = 0x3C6EF372L;
    sha256->digest[3] = 0xA54FF53AL;
    sha256->digest[4] = 0x510E527FL;
    sha256->digest[5] = 0x9B05688CL;
    sha256->digest[6] = 0x1F83D9ABL;
    sha256->digest[7] = 0x5BE0CD19L;
#endif

    sha256->buffLen = 0;
    sha256->loLen   = 0;
    sha256->hiLen   = 0;

#ifdef WOLFSSL_HASH_FLAGS
    sha256->flags = 0;
#endif

    return ret;
}

static WC_INLINE void AddLength(wc_Sha256* sha256, word32 len)
{
    word32 tmp = sha256->loLen;
    if ((sha256->loLen += len) < tmp)
        sha256->hiLen++;                       /* carry low to high */
}


#ifndef WOLFSSL_ARMASM_NO_HW_CRYPTO

#ifdef __aarch64__

/* First block is in sha256->buffer and rest in data. */
static WC_INLINE void Sha256Transform(wc_Sha256* sha256, const byte* data,
                                      word32 numBlocks)
{
    word32* k = (word32*)K;

    __asm__ volatile (
    "# load first block of data\n"
    "LD1 {v0.16b-v3.16b}, [%[dataIn]], #64   \n"

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

    /* beginning of SHA256 block operation */
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

    "#load in message and schedule updates \n"
    "LD1 {v0.16b-v3.16b}, [%[dataIn]], #64   \n"
    "MOV v14.16b, v12.16b \n"
    "MOV v15.16b, v13.16b \n"
    "REV32 v0.16b, v0.16b \n"
    "REV32 v1.16b, v1.16b \n"
    "REV32 v2.16b, v2.16b \n"
    "REV32 v3.16b, v3.16b \n"
    "B 1b \n" /* do another block */

    "2:\n"
    "ST1 {v12.2d-v13.2d}, %[out] \n"

    : [out] "=m" (sha256->digest), "=r" (numBlocks), "=r" (data), "=r" (k)
    : [k] "3" (k), [digest] "m" (sha256->digest), [blocks] "1" (numBlocks),
      [dataIn] "2" (data)
    : "cc", "memory", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7",
                      "v8",  "v9",  "v10", "v11", "v12", "v13", "v14",
                      "v15", "v16", "v17", "v18", "v19", "v20", "v21",
                      "v22", "v23", "v24", "v25", "v26", "v27", "v28",
                      "v29", "v30", "v31", "w8"
    );
}

/* ARMv8 hardware acceleration */
static WC_INLINE int Sha256Update(wc_Sha256* sha256, const byte* data,
    word32 len)
{
    word32 add;
    word32 numBlocks;

    /* only perform actions if a buffer is passed in */
    if (len > 0) {
        AddLength(sha256, len);

        if (sha256->buffLen > 0) {
            /* fill leftover buffer with data */
            add = min(len, WC_SHA256_BLOCK_SIZE - sha256->buffLen);
            XMEMCPY((byte*)(sha256->buffer) + sha256->buffLen, data, add);
            sha256->buffLen += add;
            data            += add;
            len             -= add;
            if (sha256->buffLen == WC_SHA256_BLOCK_SIZE) {
                if (IS_AARCH64_SHA256(cpuid_flags)) {
                    Sha256Transform(sha256, (byte*)sha256->buffer, 1);
                }
                else {
                    ByteReverseWords(sha256->buffer, sha256->buffer,
                        WC_SHA256_BLOCK_SIZE);
                    Transform_Sha256(sha256, (const byte*)sha256->buffer);
                }

                 sha256->buffLen = 0;
            }
        }

        /* number of blocks in a row to complete */
        numBlocks = (len + sha256->buffLen) / WC_SHA256_BLOCK_SIZE;

        if (numBlocks > 0) {
            if (IS_AARCH64_SHA256(cpuid_flags)) {
                Sha256Transform(sha256, data, numBlocks);
            }
            else {
                Transform_Sha256_Len(sha256, data,
                    numBlocks * WC_SHA256_BLOCK_SIZE);
            }
            data += numBlocks * WC_SHA256_BLOCK_SIZE;
            len  -= numBlocks * WC_SHA256_BLOCK_SIZE;
        }

        if (len > 0) {
            /* copy over any remaining data leftover */
            XMEMCPY(sha256->buffer, data, len);
            sha256->buffLen = len;
        }
    }

    /* account for possibility of not used if len = 0 */
    (void)add;
    (void)numBlocks;

    return 0;
}


static WC_INLINE int Sha256Final(wc_Sha256* sha256, byte* hash)
{
    byte* local;
    const word32* k;

    local = (byte*)sha256->buffer;
    local[sha256->buffLen++] = 0x80;     /* add 1 */

    /* pad with zeros */
    if (sha256->buffLen > WC_SHA256_PAD_SIZE) {
        XMEMSET(&local[sha256->buffLen], 0, WC_SHA256_BLOCK_SIZE -
                                                               sha256->buffLen);
        sha256->buffLen += WC_SHA256_BLOCK_SIZE - sha256->buffLen;
        if (IS_AARCH64_SHA256(cpuid_flags)) {
            k = K;
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

                "LD1 {v22.4s-v25.4s}, [%[k]], #64 \n"
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

                "LD1 {v22.4s-v25.4s}, [%[k]], #64 \n"
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

                "LD1 {v22.4s-v25.4s}, [%[k]], #64 \n"
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

                "LD1 {v22.4s-v25.4s}, [%[k]] \n"
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
                "ST1 {v16.2d-v17.2d}, %[out]        \n"

                : [out] "=m" (sha256->digest), [k] "+r" (k)
                : [digest] "m" (sha256->digest),
                  [buffer] "m" (sha256->buffer)
                : "cc", "memory", "v0", "v1", "v2", "v3", "v8",  "v9",  "v10"
                                , "v11" , "v12", "v13", "v14", "v15", "v16"
                                , "v17", "v18" , "v19", "v20", "v21", "v22"
                                , "v23", "v24", "v25"
            );
        }
        else {
            ByteReverseWords(sha256->buffer, sha256->buffer,
                WC_SHA256_BLOCK_SIZE);
            Transform_Sha256(sha256, (const byte*)sha256->buffer);
        }

        sha256->buffLen = 0;
    }
    XMEMSET(&local[sha256->buffLen], 0, WC_SHA256_PAD_SIZE - sha256->buffLen);

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
        XMEMCPY(&local[WC_SHA256_PAD_SIZE], &sha256->hiLen, sizeof(word32));
        XMEMCPY(&local[WC_SHA256_PAD_SIZE + sizeof(word32)], &sha256->loLen,
                sizeof(word32));

    if (IS_AARCH64_SHA256(cpuid_flags)) {
        k = K;
        __asm__ volatile (
            "#load in message and schedule updates \n"
            "LD1 {v4.2d-v7.2d}, %[buffer]        \n"
            "MOV v0.16b, v4.16b \n"
            "MOV v1.16b, v5.16b \n"
            "MOV v2.16b, v6.16b \n"
            "MOV v3.16b, v7.16b \n"
            "LD1 {v20.2d-v21.2d}, %[digest] \n"

            "MOV v16.16b, v20.16b      \n"
            "MOV v17.16b, v21.16b      \n"
            "LD1 {v22.4s-v25.4s}, [%[k]], #64 \n"
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

            "LD1 {v22.4s-v25.4s}, [%[k]], #64 \n"
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

            "LD1 {v22.4s-v25.4s}, [%[k]], #64 \n"
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

            "LD1 {v22.4s-v25.4s}, [%[k]] \n"
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
            : [hashOut] "=r" (hash), [k] "+r" (k)
            : [digest] "m" (sha256->digest),
              [buffer] "m" (sha256->buffer),
              "0" (hash)
                : "cc", "memory", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7",
                                  "v8",  "v9",  "v10", "v11", "v12", "v13", "v14",
                                  "v15", "v16", "v17", "v18", "v19", "v20", "v21",
                                  "v22", "v23", "v24", "v25"
        );
    }
    else {
        Transform_Sha256(sha256, (const byte*)sha256->buffer);

    #ifdef LITTLE_ENDIAN_ORDER
        ByteReverseWords((word32*)hash, sha256->digest, WC_SHA256_DIGEST_SIZE);
    #else
        XMEMCPY(hash, sha256->digest, WC_SHA256_DIGEST_SIZE);
    #endif
    }

    return 0;
}

#else /* not using 64 bit */

static WC_INLINE void Sha256Transform(wc_Sha256* sha256, const byte* data,
                                      word32 numBlocks)
{
    word32* bufPt = sha256->buffer;
    word32* digPt = sha256->digest;

    __asm__ volatile (
    "# load first block of data\n"
    "VLD1.8 {d0-d3}, [%[dataIn]]! \n"
    "VLD1.8 {d4-d7}, [%[dataIn]]! \n"

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

    /* beginning of SHA256 block operation */
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

    "#load in message and schedule updates \n"
    "VLD1.8 {d0-d3}, [%[dataIn]]! \n"
    "VLD1.8 {d4-d7}, [%[dataIn]]! \n"

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
}

/* ARMv8 hardware acceleration Aarch32 */
static WC_INLINE int Sha256Update(wc_Sha256* sha256, const byte* data,
    word32 len)
{
    word32 add;
    word32 numBlocks;

    /* only perform actions if a buffer is passed in */
    if (len > 0) {
        AddLength(sha256, len);

        if (sha256->buffLen > 0) {
             /* fill leftover buffer with data */
             add = min(len, WC_SHA256_BLOCK_SIZE - sha256->buffLen);
             XMEMCPY((byte*)(sha256->buffer) + sha256->buffLen, data, add);
             sha256->buffLen += add;
             data            += add;
             len             -= add;
             if (sha256->buffLen == WC_SHA256_BLOCK_SIZE) {
                 Sha256Transform(sha256, (byte*)sha256->buffer, 1);
                 sha256->buffLen = 0;
             }
        }

        /* number of blocks in a row to complete */
        numBlocks = (len + sha256->buffLen)/WC_SHA256_BLOCK_SIZE;

        if (numBlocks > 0) {
            Sha256Transform(sha256, data, numBlocks);
            data += numBlocks * WC_SHA256_BLOCK_SIZE;
            len  -= numBlocks * WC_SHA256_BLOCK_SIZE;
        }

        if (len > 0) {
            /* copy over any remaining data leftover */
            XMEMCPY(sha256->buffer, data, len);
            sha256->buffLen = len;
        }
    }

    /* account for possibility of not used if len = 0 */
    (void)add;
    (void)numBlocks;

    return 0;
}


static WC_INLINE int Sha256Final(wc_Sha256* sha256, byte* hash)
{
    byte* local;

    if (sha256 == NULL || hash == NULL) {
        return BAD_FUNC_ARG;
    }

    local = (byte*)sha256->buffer;
    local[sha256->buffLen++] = 0x80;     /* add 1 */

    /* pad with zeros */
    if (sha256->buffLen > WC_SHA256_PAD_SIZE) {
        word32* bufPt = sha256->buffer;
        word32* digPt = sha256->digest;
        XMEMSET(&local[sha256->buffLen], 0, WC_SHA256_BLOCK_SIZE - sha256->buffLen);
        sha256->buffLen += WC_SHA256_BLOCK_SIZE - sha256->buffLen;
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

        /* beginning of SHA256 block operation */
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
    XMEMSET(&local[sha256->buffLen], 0, WC_SHA256_PAD_SIZE - sha256->buffLen);

    /* put lengths in bits */
    sha256->hiLen = (sha256->loLen >> (8*sizeof(sha256->loLen) - 3)) +
                 (sha256->hiLen << 3);
    sha256->loLen = sha256->loLen << 3;

    /* store lengths */
    #if defined(LITTLE_ENDIAN_ORDER)
    {
        word32* bufPt = sha256->buffer;
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
    }
    #endif
    /* ! length ordering dependent on digest endian type ! */
    XMEMCPY(&local[WC_SHA256_PAD_SIZE], &sha256->hiLen, sizeof(word32));
    XMEMCPY(&local[WC_SHA256_PAD_SIZE + sizeof(word32)], &sha256->loLen,
            sizeof(word32));

    word32* bufPt = sha256->buffer;
    word32* digPt = sha256->digest;
    __asm__ volatile (
        "#load leftover data\n"
        "VLDM %[buffer]!, {q0-q3} \n"

        "#load current digest\n"
        "VLDM %[digest], {q12-q13} \n"

        "VMOV.32 q14, q12 \n" /* store digest for add at the end */
        "VMOV.32 q15, q13 \n"

        /* beginning of SHA256 block operation */
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

    return 0;
}

#endif /* __aarch64__ */

#else /* WOLFSSL_ARMASM_NO_HW_CRYPTO */

#if defined(FREESCALE_MMCAU_SHA)

    #ifndef WC_HASH_DATA_ALIGNMENT
        /* these hardware API's require 4 byte (word32) alignment */
        #define WC_HASH_DATA_ALIGNMENT 4
    #endif

    static int Transform_Sha256_Len(wc_Sha256* sha256, const byte* data,
        word32 len)
    {
        int ret = wolfSSL_CryptHwMutexLock();
        if (ret == 0) {
        #if defined(WC_HASH_DATA_ALIGNMENT) && WC_HASH_DATA_ALIGNMENT > 0
            if ((wc_ptr_t)data % WC_HASH_DATA_ALIGNMENT) {
                /* data pointer is NOT aligned,
                 * so copy and perform one block at a time */
                byte* local = (byte*)sha256->buffer;
                while (len >= WC_SHA256_BLOCK_SIZE) {
                    XMEMCPY(local, data, WC_SHA256_BLOCK_SIZE);
                #ifdef FREESCALE_MMCAU_CLASSIC_SHA
                    cau_sha256_hash_n(local, 1, sha256->digest);
                #else
                    MMCAU_SHA256_HashN(local, 1, (uint32_t*)sha256->digest);
                #endif
                    data += WC_SHA256_BLOCK_SIZE;
                    len  -= WC_SHA256_BLOCK_SIZE;
                }
            }
            else
        #endif
            {
    #ifdef FREESCALE_MMCAU_CLASSIC_SHA
            cau_sha256_hash_n((byte*)data, len/WC_SHA256_BLOCK_SIZE,
                sha256->digest);
    #else
            MMCAU_SHA256_HashN((byte*)data, len/WC_SHA256_BLOCK_SIZE,
                (uint32_t*)sha256->digest);
    #endif
            }
            wolfSSL_CryptHwMutexUnLock();
        }
        return ret;
    }

#elif !defined(__aarch64__)

extern void Transform_Sha256_Len(wc_Sha256* sha256, const byte* data,
    word32 len);

#endif

/* ARMv8 hardware acceleration Aarch32 and Thumb2 */
static WC_INLINE int Sha256Update(wc_Sha256* sha256, const byte* data, word32 len)
{
    int ret = 0;
    /* do block size increments */
    byte* local = (byte*)sha256->buffer;
    word32 blocksLen;

    /* check that internal buffLen is valid */
    if (sha256->buffLen >= WC_SHA256_BLOCK_SIZE)
        return BUFFER_E;

    AddLength(sha256, len);

    if (sha256->buffLen > 0) {
        word32 add = min(len, WC_SHA256_BLOCK_SIZE - sha256->buffLen);
        if (add > 0) {
            XMEMCPY(&local[sha256->buffLen], data, add);

            sha256->buffLen += add;
            data            += add;
            len             -= add;
        }

        if (sha256->buffLen == WC_SHA256_BLOCK_SIZE) {
            Transform_Sha256_Len(sha256, (const byte*)sha256->buffer,
                                                          WC_SHA256_BLOCK_SIZE);
            sha256->buffLen = 0;
        }
    }

    blocksLen = len & ~(WC_SHA256_BLOCK_SIZE-1);
    if (blocksLen > 0) {
        /* Byte reversal performed in function if required. */
        Transform_Sha256_Len(sha256, data, blocksLen);
        data += blocksLen;
        len  -= blocksLen;
    }

    if (len > 0) {
        XMEMCPY(local, data, len);
        sha256->buffLen = len;
    }

    return ret;
}

static WC_INLINE int Sha256Final(wc_Sha256* sha256, byte* hash)
{
    byte* local = (byte*)sha256->buffer;

    if (sha256 == NULL) {
        return BAD_FUNC_ARG;
    }

    local[sha256->buffLen++] = 0x80;  /* add 1 */

    /* pad with zeros */
    if (sha256->buffLen > WC_SHA256_PAD_SIZE) {
        XMEMSET(&local[sha256->buffLen], 0, WC_SHA256_BLOCK_SIZE -
                                                               sha256->buffLen);
        sha256->buffLen += WC_SHA256_BLOCK_SIZE - sha256->buffLen;
        Transform_Sha256_Len(sha256, (const byte*)sha256->buffer,
                                                          WC_SHA256_BLOCK_SIZE);

        sha256->buffLen = 0;
    }
    XMEMSET(&local[sha256->buffLen], 0, WC_SHA256_PAD_SIZE - sha256->buffLen);

    /* put lengths in bits */
    sha256->hiLen = (sha256->loLen >> (8 * sizeof(sha256->loLen) - 3)) +
                                                         (sha256->hiLen << 3);
    sha256->loLen = sha256->loLen << 3;

    /* store lengths */
    /* ! length ordering dependent on digest endian type ! */

    sha256->buffer[WC_SHA256_BLOCK_SIZE / sizeof(word32) - 2] = sha256->hiLen;
    sha256->buffer[WC_SHA256_BLOCK_SIZE / sizeof(word32) - 1] = sha256->loLen;

    ByteReverseWords(
                   &(sha256->buffer[WC_SHA256_BLOCK_SIZE / sizeof(word32) - 2]),
                   &(sha256->buffer[WC_SHA256_BLOCK_SIZE / sizeof(word32) - 2]),
                   WC_SHA256_BLOCK_SIZE - WC_SHA256_PAD_SIZE);
    Transform_Sha256_Len(sha256, (const byte*)sha256->buffer,
                                                          WC_SHA256_BLOCK_SIZE);

#ifdef LITTLE_ENDIAN_ORDER
    ByteReverseWords((word32*)hash, sha256->digest, WC_SHA256_DIGEST_SIZE);
#else
    XMEMCPY(hash, sha256->digest, WC_SHA256_DIGEST_SIZE);
#endif

    return 0;
}

#endif /* !WOLFSSL_ARMASM_NO_HW_CRYPTO */


#ifndef NO_SHA256

int wc_InitSha256_ex(wc_Sha256* sha256, void* heap, int devId)
{
    int ret = 0;
    if (sha256 == NULL)
        return BAD_FUNC_ARG;
    ret = InitSha256(sha256);
    if (ret != 0)
        return ret;

    sha256->heap = heap;
#ifdef WOLF_CRYPTO_CB
    sha256->devId = devId;
    sha256->devCtx = NULL;
#endif

#ifdef MAX3266X_SHA_CB
    ret = wc_MXC_TPU_SHA_Init(&(sha256->mxcCtx));
    if (ret != 0) {
        return ret;
    }
#endif

#if defined(__aarch64__) && !defined(WOLFSSL_ARMASM_NO_HW_CRYPTO)
    if (!cpuid_flags_set) {
        cpuid_flags = cpuid_get_flags();
        cpuid_flags_set = 1;
    }
#endif

    (void)devId;

    return ret;
}

int wc_InitSha256(wc_Sha256* sha256)
{
    int devId = INVALID_DEVID;

#ifdef WOLF_CRYPTO_CB
    devId = wc_CryptoCb_DefaultDevID();
#endif
    return wc_InitSha256_ex(sha256, NULL, devId);
}

void wc_Sha256Free(wc_Sha256* sha256)
{
#ifdef MAX3266X_SHA_CB
    wc_MXC_TPU_SHA_Free(&(sha256->mxcCtx));
#endif
    (void)sha256;
}

int wc_Sha256Update(wc_Sha256* sha256, const byte* data, word32 len)
{
    if (sha256 == NULL || (data == NULL && len != 0)) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLF_CRYPTO_CB
    #ifndef WOLF_CRYPTO_CB_FIND
    if (sha256->devId != INVALID_DEVID)
    #endif
    {
        int ret = wc_CryptoCb_Sha256Hash(sha256, data, len, NULL);
        if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
            return ret;
        /* fall-through when unavailable */
    }
#endif

    return Sha256Update(sha256, data, len);
}

int wc_Sha256FinalRaw(wc_Sha256* sha256, byte* hash)
{
#ifdef LITTLE_ENDIAN_ORDER
    word32 digest[WC_SHA256_DIGEST_SIZE / sizeof(word32)];
#endif

    if (sha256 == NULL || hash == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef LITTLE_ENDIAN_ORDER
    ByteReverseWords((word32*)digest, (word32*)sha256->digest,
                                                        WC_SHA256_DIGEST_SIZE);
    XMEMCPY(hash, digest, WC_SHA256_DIGEST_SIZE);
#else
    XMEMCPY(hash, sha256->digest, WC_SHA256_DIGEST_SIZE);
#endif

    return 0;
}

int wc_Sha256Final(wc_Sha256* sha256, byte* hash)
{
    int ret;

    if (sha256 == NULL || hash == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLF_CRYPTO_CB
    #ifndef WOLF_CRYPTO_CB_FIND
    if (sha256->devId != INVALID_DEVID)
    #endif
    {
        ret = wc_CryptoCb_Sha256Hash(sha256, NULL, 0, hash);
        if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
            return ret;
        /* fall-through when unavailable */
    }
#endif

    ret = Sha256Final(sha256, hash);
    if (ret != 0)
        return ret;

    return InitSha256(sha256);  /* reset state */
}

int wc_Sha256GetHash(wc_Sha256* sha256, byte* hash)
{
    int ret;
    wc_Sha256 tmpSha256;

    if (sha256 == NULL || hash == NULL)
        return BAD_FUNC_ARG;

    ret = wc_Sha256Copy(sha256, &tmpSha256);
    if (ret == 0) {
        ret = wc_Sha256Final(&tmpSha256, hash);
    }
    return ret;
}

#ifdef WOLFSSL_HASH_FLAGS
int wc_Sha256SetFlags(wc_Sha256* sha256, word32 flags)
{
    if (sha256) {
        sha256->flags = flags;
    }
    return 0;
}
int wc_Sha256GetFlags(wc_Sha256* sha256, word32* flags)
{
    if (sha256 && flags) {
        *flags = sha256->flags;
    }
    return 0;
}
#endif

int wc_Sha256Copy(wc_Sha256* src, wc_Sha256* dst)
{
    int ret = 0;

    if (src == NULL || dst == NULL)
        return BAD_FUNC_ARG;

    XMEMCPY(dst, src, sizeof(wc_Sha256));

#ifdef MAX3266X_SHA_CB
    ret = wc_MXC_TPU_SHA_Copy(&(src->mxcCtx), &(dst->mxcCtx));
    if (ret != 0) {
        return ret;
    }
#endif

    return ret;
}

#ifdef OPENSSL_EXTRA
int wc_Sha256Transform(wc_Sha256* sha256, const unsigned char* data)
{
    if (sha256 == NULL || data == NULL) {
        return BAD_FUNC_ARG;
    }
#ifdef LITTLE_ENDIAN_ORDER
    ByteReverseWords(sha256->buffer, (word32*)data, WC_SHA256_BLOCK_SIZE);
#else
    XMEMCPY(sha256->buffer, data, WC_SHA256_BLOCK_SIZE);
#endif
#ifndef WOLFSSL_ARMASM_NO_HW_CRYPTO
    Sha256Transform(sha256, (byte*)sha256->buffer, 1);
#else
    Transform_Sha256_Len(sha256, (byte*)sha256->buffer, WC_SHA256_BLOCK_SIZE);
#endif
    return 0;
}
#endif

#if defined(WOLFSSL_HAVE_LMS) && !defined(WOLFSSL_LMS_FULL_HASH)
/* One block will be used from data.
 * hash must be big enough to hold all of digest output.
 */
int wc_Sha256HashBlock(wc_Sha256* sha256, const unsigned char* data,
    unsigned char* hash)
{
    int ret = 0;

    if ((sha256 == NULL) || (data == NULL)) {
        return BAD_FUNC_ARG;
    }

#ifndef WOLFSSL_ARMASM_NO_HW_CRYPTO
    Sha256Transform(sha256, data, 1);
#else
    Transform_Sha256_Len(sha256, data, WC_SHA256_BLOCK_SIZE);
#endif

    if (hash != NULL) {
#ifdef LITTLE_ENDIAN_ORDER
    #ifndef WOLFSSL_ARMASM_NO_HW_CRYPTO
        #ifdef __aarch64__
            __asm__ __volatile__ (
                "LD1 {v0.2d-v1.2d}, [%[digest]]   \n"
                "REV32 v0.16b, v0.16b \n"
                "REV32 v1.16b, v1.16b \n"
                "ST1 {v0.16b-v1.16b}, [%[hash]]  \n"
                :
                : [digest] "r" (sha256->digest), [hash] "r" (hash)
                : "memory", "v0", "v1"
            );
        #else
            __asm__ __volatile__ (
                "VLDM %[digest], {q0-q1} \n"
                "VREV32.8 q0, q0 \n"
                "VREV32.8 q1, q1 \n"
                "VST1.8 {d0-d3}, [%[hash]] \n"
                :
                : [digest] "r" (sha256->digest), [hash] "r" (hash)
                : "memory", "q0", "q1"
            );
        #endif
    #else
        word32* hash32 = (word32*)hash;
        word32* digest = (word32*)sha256->digest;
        hash32[0] = ByteReverseWord32(digest[0]);
        hash32[1] = ByteReverseWord32(digest[1]);
        hash32[2] = ByteReverseWord32(digest[2]);
        hash32[3] = ByteReverseWord32(digest[3]);
        hash32[4] = ByteReverseWord32(digest[4]);
        hash32[5] = ByteReverseWord32(digest[5]);
        hash32[6] = ByteReverseWord32(digest[6]);
        hash32[7] = ByteReverseWord32(digest[7]);
    #endif /* !WOLFSSL_ARMASM_NO_HW_CRYPTO */
#else
        XMEMCPY(hash, sha256->digest, WC_SHA256_DIGEST_SIZE);
#endif
        sha256->digest[0] = 0x6A09E667L;
        sha256->digest[1] = 0xBB67AE85L;
        sha256->digest[2] = 0x3C6EF372L;
        sha256->digest[3] = 0xA54FF53AL;
        sha256->digest[4] = 0x510E527FL;
        sha256->digest[5] = 0x9B05688CL;
        sha256->digest[6] = 0x1F83D9ABL;
        sha256->digest[7] = 0x5BE0CD19L;
    }

    return ret;
}
#endif /* WOLFSSL_HAVE_LMS && !WOLFSSL_LMS_FULL_HASH */

#endif /* !NO_SHA256 */


#ifdef WOLFSSL_SHA224
    static int InitSha224(wc_Sha224* sha224)
    {

        int ret = 0;

        if (sha224 == NULL) {
            return BAD_FUNC_ARG;
        }

        sha224->digest[0] = 0xc1059ed8;
        sha224->digest[1] = 0x367cd507;
        sha224->digest[2] = 0x3070dd17;
        sha224->digest[3] = 0xf70e5939;
        sha224->digest[4] = 0xffc00b31;
        sha224->digest[5] = 0x68581511;
        sha224->digest[6] = 0x64f98fa7;
        sha224->digest[7] = 0xbefa4fa4;

        sha224->buffLen = 0;
        sha224->loLen   = 0;
        sha224->hiLen   = 0;

    #ifdef WOLFSSL_HASH_FLAGS
        sha224->flags = 0;
    #endif
        return ret;
    }

    int wc_InitSha224_ex(wc_Sha224* sha224, void* heap, int devId)
    {
        if (sha224 == NULL)
            return BAD_FUNC_ARG;

        sha224->heap = heap;

    #if defined(__aarch64__) && !defined(WOLFSSL_ARMASM_NO_HW_CRYPTO)
        if (!cpuid_flags_set) {
            cpuid_flags = cpuid_get_flags();
            cpuid_flags_set = 1;
        }
    #endif

        (void)devId;

        return InitSha224(sha224);
    }

    int wc_InitSha224(wc_Sha224* sha224)
    {
        return wc_InitSha224_ex(sha224, NULL, INVALID_DEVID);
    }

    int wc_Sha224Update(wc_Sha224* sha224, const byte* data, word32 len)
    {
        int ret;

        if (sha224 == NULL || (data == NULL && len > 0)) {
            return BAD_FUNC_ARG;
        }

        ret = Sha256Update((wc_Sha256 *)sha224, data, len);

        return ret;
    }

    int wc_Sha224Final(wc_Sha224* sha224, byte* hash)
    {
        int ret;
        word32 hashTmp[WC_SHA256_DIGEST_SIZE/sizeof(word32)];

        if (sha224 == NULL || hash == NULL) {
            return BAD_FUNC_ARG;
        }

        ret = Sha256Final((wc_Sha256*)sha224, (byte*)hashTmp);
        if (ret != 0)
            return ret;

        XMEMCPY(hash, hashTmp, WC_SHA224_DIGEST_SIZE);

        return InitSha224(sha224);  /* reset state */
    }

    void wc_Sha224Free(wc_Sha224* sha224)
    {
        if (sha224 == NULL)
            return;
    }

    int wc_Sha224GetHash(wc_Sha224* sha224, byte* hash)
    {
        int ret;
        wc_Sha224 tmpSha224;

        if (sha224 == NULL || hash == NULL)
            return BAD_FUNC_ARG;

        ret = wc_Sha224Copy(sha224, &tmpSha224);
        if (ret == 0) {
            ret = wc_Sha224Final(&tmpSha224, hash);
        }
        return ret;
    }

#ifdef WOLFSSL_HASH_FLAGS
    int wc_Sha224SetFlags(wc_Sha224* sha224, word32 flags)
    {
        if (sha224) {
            sha224->flags = flags;
        }
        return 0;
    }
    int wc_Sha224GetFlags(wc_Sha224* sha224, word32* flags)
    {
        if (sha224 && flags) {
            *flags = sha224->flags;
        }
        return 0;
    }
#endif

    int wc_Sha224Copy(wc_Sha224* src, wc_Sha224* dst)
    {
        int ret = 0;

        if (src == NULL || dst == NULL)
            return BAD_FUNC_ARG;

        XMEMCPY(dst, src, sizeof(wc_Sha224));

        return ret;
    }

#endif /* WOLFSSL_SHA224 */

#endif /* !NO_SHA256 || WOLFSSL_SHA224 */
#endif /* WOLFSSL_ARMASM */
