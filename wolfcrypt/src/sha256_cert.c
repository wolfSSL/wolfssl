/* sha256_cert.c
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

/* For more info on the algorithm, see https://tools.ietf.org/html/rfc6234 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
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

#define Ch(x,y,z)       ((z) ^ ((x) & ((y) ^ (z))))
#define Maj(x,y,z)      ((((x) | (y)) & (z)) | ((x) & (y)))
#define R(x, n)         (((x) & 0xFFFFFFFFU) >> (n))

#define S(x, n)         rotrFixed(x, n)
#define Sigma0(x)       (S(x, 2)  ^ S(x, 13) ^ S(x, 22))
#define Sigma1(x)       (S(x, 6)  ^ S(x, 11) ^ S(x, 25))
#define Gamma0(x)       (S(x, 7)  ^ S(x, 18) ^ R(x, 3))
#define Gamma1(x)       (S(x, 17) ^ S(x, 19) ^ R(x, 10))

#define a(i) S[(0-i) & 7]
#define b(i) S[(1-i) & 7]
#define c(i) S[(2-i) & 7]
#define d(i) S[(3-i) & 7]
#define e(i) S[(4-i) & 7]
#define f(i) S[(5-i) & 7]
#define g(i) S[(6-i) & 7]
#define h(i) S[(7-i) & 7]

#define RND(j) \
     t0 = h(j) + Sigma1(e(j)) + Ch(e(j), f(j), g(j)) + K[i+j] + W[i+j]; \
     t1 = Sigma0(a(j)) + Maj(a(j), b(j), c(j)); \
     d(j) += t0; \
     h(j)  = t0 + t1

static int Transform_Sha256(wc_Sha256* sha256);
#define XTRANSFORM(S)        Transform_Sha256((S))

static int Transform_Sha256(wc_Sha256* sha256)
{
    word32 S[8], t0, t1;
    int i;
    word32 W[WC_SHA256_BLOCK_SIZE];

    /* Copy context->state[] to working vars */
    for (i = 0; i < 8; i++)
        S[i] = sha256->digest[i];

    for (i = 0; i < 16; i++)
        W[i] = sha256->buffer[i];

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

    return 0;
 }

static int InitSha256(wc_Sha256* sha256)
{
    int ret = 0;

    if (sha256 == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(sha256->digest, 0, sizeof(sha256->digest));
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

int wc_InitSha256_ex(wc_Sha256* sha256, void* heap, int devId)
{
    int ret = 0;
    (void)heap;
    (void)devId;

    if (sha256 == NULL)
        return BAD_FUNC_ARG;

    sha256->heap = heap;

    ret = InitSha256(sha256);
    if (ret != 0)
        return ret;

#ifdef WOLFSSL_SMALL_STACK_CACHE
    sha256->W = NULL;
#endif
    return ret;
 }

static WC_INLINE void AddLength(wc_Sha256* sha256, word32 len)
{
    word32 tmp = sha256->loLen;
    if ((sha256->loLen += len) < tmp)
        sha256->hiLen++;                       /* carry low to high */
}

static WC_INLINE int Sha256Update(wc_Sha256* sha256, const byte* data, word32 len)
{
    int ret = 0;
    byte* local;

    if (sha256 == NULL || (data == NULL && len > 0)) {
        return BAD_FUNC_ARG;
    }

    if (data == NULL && len == 0) {
        /* valid, but do nothing */
        return 0;
    }

    /* do block size increments */
    local = (byte*)sha256->buffer;

    /* check that internal buffLen is valid */
    if (sha256->buffLen >= WC_SHA256_BLOCK_SIZE)
        return BUFFER_E;

    if (sha256->buffLen > 0) {
        word32 add = min(len, WC_SHA256_BLOCK_SIZE - sha256->buffLen);
        XMEMCPY(&local[sha256->buffLen], data, add);

        sha256->buffLen += add;
        data            += add;
        len             -= add;

        if (sha256->buffLen == WC_SHA256_BLOCK_SIZE) {
     #if defined(LITTLE_ENDIAN_ORDER)
            ByteReverseWords(sha256->buffer, sha256->buffer,
                                                       WC_SHA256_BLOCK_SIZE);
     #endif
        ret = XTRANSFORM(sha256);
             if (ret == 0) {
                 AddLength(sha256, WC_SHA256_BLOCK_SIZE);
                 sha256->buffLen = 0;
             }
             else
                 len = 0;
         }
     }

     word32 blocksLen = len & ~(WC_SHA256_BLOCK_SIZE-1);
     AddLength(sha256, blocksLen);
     while (len >= WC_SHA256_BLOCK_SIZE) {
        XMEMCPY(local, data, WC_SHA256_BLOCK_SIZE);

        data += WC_SHA256_BLOCK_SIZE;
        len  -= WC_SHA256_BLOCK_SIZE;

        #if defined(LITTLE_ENDIAN_ORDER)
            ByteReverseWords(sha256->buffer, sha256->buffer,
                                                          WC_SHA256_BLOCK_SIZE);
        #endif
        /* Byte reversal performed in function if required. */
        ret = XTRANSFORM(sha256);
        if (ret != 0)
            break;
        }

     if (len > 0) {
        XMEMCPY(local, data, len);
        sha256->buffLen = len;
     }
     return ret;
 }


int wc_Sha256Update(wc_Sha256* sha256, const byte* data, word32 len)
{
    return Sha256Update(sha256, data, len);
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

int wc_Sha256Copy(wc_Sha256* src, wc_Sha256* dst)
{
    int ret = 0;

    if (src == NULL || dst == NULL)
        return BAD_FUNC_ARG;

    XMEMCPY(dst, src, sizeof(wc_Sha256));
#ifdef WOLFSSL_SMALL_STACK_CACHE
    dst->W = NULL;
#endif

   return ret;
}

static WC_INLINE int Sha256Final(wc_Sha256* sha256)
{
    int ret;
    byte* local = (byte*)sha256->buffer;

    if (sha256 == NULL) {
        return BAD_FUNC_ARG;
    }

    AddLength(sha256, sha256->buffLen);  /* before adding pads */
    local[sha256->buffLen++] = 0x80;     /* add 1 */

    /* pad with zeros */
    if (sha256->buffLen > WC_SHA256_PAD_SIZE) {
        XMEMSET(&local[sha256->buffLen], 0,
            WC_SHA256_BLOCK_SIZE - sha256->buffLen);
        sha256->buffLen += WC_SHA256_BLOCK_SIZE - sha256->buffLen;

        {
    #if defined(LITTLE_ENDIAN_ORDER)
            ByteReverseWords(sha256->buffer, sha256->buffer,
                                                      WC_SHA256_BLOCK_SIZE);
    #endif
        }
        ret = XTRANSFORM(sha256);
        if (ret != 0)
            return ret;

        sha256->buffLen = 0;
    }
     XMEMSET(&local[sha256->buffLen], 0, WC_SHA256_PAD_SIZE - sha256->buffLen);

     /* put lengths in bits */
     sha256->hiLen = (sha256->loLen >> (8 * sizeof(sha256->loLen) - 3)) +
                                                      (sha256->hiLen << 3);
     sha256->loLen = sha256->loLen << 3;

     /* store lengths */
 #if defined(LITTLE_ENDIAN_ORDER)
     ByteReverseWords(sha256->buffer, sha256->buffer,
                 WC_SHA256_BLOCK_SIZE);
 #endif
     /* ! length ordering dependent on digest endian type ! */
     XMEMCPY(&local[WC_SHA256_PAD_SIZE], &sha256->hiLen, sizeof(word32));
     XMEMCPY(&local[WC_SHA256_PAD_SIZE + sizeof(word32)], &sha256->loLen,
             sizeof(word32));

 #if defined(FREESCALE_MMCAU_SHA) || defined(HAVE_INTEL_AVX1) || \
     defined(HAVE_INTEL_AVX2)
     /* Kinetis requires only these bytes reversed */
     #if defined(HAVE_INTEL_AVX1) || defined(HAVE_INTEL_AVX2)
         if (IS_INTEL_AVX1(intel_flags) || IS_INTEL_AVX2(intel_flags))
     #endif
         {
             ByteReverseWords(
                 &sha256->buffer[WC_SHA256_PAD_SIZE / sizeof(word32)],
                 &sha256->buffer[WC_SHA256_PAD_SIZE / sizeof(word32)],
                 2 * sizeof(word32));
         }
 #endif

        return XTRANSFORM(sha256);

}

int wc_Sha256Final(wc_Sha256* sha256, byte* hash)
{
    int ret;

    if (sha256 == NULL || hash == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = Sha256Final(sha256);
    if (ret != 0)
        return ret;

 #if defined(LITTLE_ENDIAN_ORDER)
    ByteReverseWords(sha256->digest, sha256->digest, WC_SHA256_DIGEST_SIZE);
 #endif
    XMEMCPY(hash, sha256->digest, WC_SHA256_DIGEST_SIZE);

    return InitSha256(sha256);  /* reset state */
}
